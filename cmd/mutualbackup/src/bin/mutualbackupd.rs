use std::future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::Multiaddr;
use mb_node::{
    ClaimedTorTransportConfig, LocalControlListener, LocalRequest, LocalResponse, LockedDataDir,
    Node, P2pConfig, P2pStartup, TorShutdownHandle, TorTransport, TorTransportConfig, UnlockSecret,
    WireError, bind_local_control, build_p2p_with_tor, onion_listener_address,
    run_coordinator_jobs, run_dht_publications, run_peer_exchange, run_port_mapping,
    run_relay_membership_sync, run_root_watcher, serve_local_control_on,
    wait_for_onion_service_shutdown,
};
use mutualbackup::{
    DaemonOptions, DaemonOptionsError, IdentityManifest, InitializationIntent, read_daemon_options,
    read_identity_manifest, read_seed,
};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .ok();
    let config = match read_daemon_options(std::env::args_os()) {
        Ok(config) => config,
        Err(DaemonOptionsError::Parse(error)) => error.exit(),
        Err(DaemonOptionsError::Load(error)) => return Err(error),
    };
    let identity = read_identity_manifest(&config.data_dir)?;
    config.validate(&identity)?;
    if identity.intent == InitializationIntent::Recovery && config.failure_domain.is_some() {
        tracing::warn!(
            "ignoring configured failure domain while recovering authenticated guild state"
        );
    }
    let locked_data_dir = Node::lock_data_dir(&config.data_dir)?;
    let listener = bind_local_control(&config.control_socket)?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let (node, p2p_client, mut p2p_task, startup, tor_shutdown) = match &config.seed_file {
        Some(seed_file) => {
            let seed_file = seed_file.clone();
            let open_config = config.clone();
            let open_identity = identity.clone();
            let mut open_task = tokio::task::spawn_blocking(move || {
                let seed =
                    read_seed(&seed_file).context("automatic recovery-string unlock failed")?;
                open_configured_node(&open_config, &open_identity, locked_data_dir, seed)
            });
            let node = tokio::select! {
                result = &mut open_task => {
                    result.context("automatic unlock worker failed")??
                }
                result = shutdown.as_mut() => {
                    // A blocking task may already be running and cannot be
                    // cancelled safely. Wait for it to release the data-dir
                    // lock before allowing process shutdown to complete.
                    open_task.abort();
                    let _ = open_task.await;
                    return result;
                }
            };
            let Some(runtime) =
                start_ready_runtime(&config, &identity, node, shutdown.as_mut()).await?
            else {
                return Ok(());
            };
            runtime
        }
        None => {
            println!("node {} locked", identity.expected_node_id);
            println!("control socket: {}", config.control_socket.display());
            loop {
                let (node, connection) = tokio::select! {
                    result = await_manual_node(
                        &config,
                        &identity,
                        locked_data_dir.clone(),
                        &listener,
                    ) => result?,
                    result = shutdown.as_mut() => return result,
                };
                match start_ready_runtime(&config, &identity, node, shutdown.as_mut()).await {
                    Ok(Some(runtime)) => {
                        if let Err(error) = connection
                            .respond(LocalResponse::Unlocked {
                                node_id: identity.expected_node_id,
                            })
                            .await
                        {
                            tracing::warn!(%error, "unlocking client disconnected before acknowledgement");
                        }
                        break runtime;
                    }
                    Ok(None) => return Ok(()),
                    Err(error) => {
                        tracing::warn!(%error, "manual daemon unlock could not reach network readiness");
                        if let Err(response_error) = connection
                            .respond_error(WireError::operation(format!("{error:#}")))
                            .await
                        {
                            tracing::warn!(%response_error, "failed unlock client disconnected");
                        }
                    }
                }
            }
        }
    };
    let node_id = identity.expected_node_id;
    println!("node {node_id} ready");
    println!(
        "network ingress: direct={} relay={} onion={} degraded={:?}",
        startup.direct_listeners_active,
        startup.relay_reservations_active,
        startup.onion_service_reachable,
        startup.degraded
    );
    println!("libp2p peer id: {}", p2p_client.local_peer_id());
    println!("control socket: {}", config.control_socket.display());

    let (port_mapping_shutdown, mut port_mapping_task) = if config.enable_port_mapping {
        let (shutdown, receiver) = tokio::sync::watch::channel(false);
        let client = p2p_client.clone();
        (
            Some(shutdown),
            Some(tokio::spawn(async move {
                run_port_mapping(client, receiver).await
            })),
        )
    } else {
        (None, None)
    };
    let mut p2p_finished = false;
    let mut port_mapping_finished = false;
    let mut result = tokio::select! {
        result = serve_local_control_on(node.clone(), p2p_client.clone(), listener) => result,
        result = run_coordinator_jobs(node.clone(), p2p_client.clone()) => result,
        result = run_dht_publications(node.clone(), p2p_client.clone()), if config.enable_dht_maintenance => result,
        result = run_peer_exchange(node.clone(), p2p_client.clone()) => result,
        result = await_optional_task(&mut port_mapping_task) => {
            port_mapping_finished = true;
            result.context("port-mapping task failed")
        },
        result = run_relay_membership_sync(node.clone(), p2p_client.clone()) => result,
        result = run_root_watcher(node.clone()) => result,
        result = &mut p2p_task => {
            p2p_finished = true;
            result
                .context("libp2p event-loop task failed")
                .and_then(|result| result)
        },
        result = shutdown.as_mut() => result,
    };

    if let Some(shutdown) = port_mapping_shutdown {
        let _ = shutdown.send(true);
    }
    if !port_mapping_finished && let Some(task) = port_mapping_task {
        absorb_cleanup(
            &mut result,
            task.await
                .context("port-mapping task failed during shutdown")
                .and_then(|result| result),
            "port mapping",
        );
    }
    if !p2p_finished {
        absorb_cleanup(
            &mut result,
            p2p_client.shutdown().await,
            "request libp2p shutdown",
        );
        absorb_cleanup(
            &mut result,
            p2p_task
                .await
                .context("libp2p event-loop task failed during shutdown")
                .and_then(|result| result),
            "join libp2p shutdown",
        );
    }
    if let Some(tor_shutdown) = tor_shutdown {
        absorb_cleanup(
            &mut result,
            tor_shutdown.wait_stopped().await,
            "join Arti onion-service shutdown",
        );
    }
    result
}

async fn await_optional_task(task: &mut Option<tokio::task::JoinHandle<Result<()>>>) -> Result<()> {
    match task {
        Some(task) => task.await.context("background task panicked")?,
        None => future::pending().await,
    }
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install SIGTERM handler")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("listen for SIGINT"),
        signal = terminate.recv() => signal.context("SIGTERM stream ended").map(|_| ()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<()> {
    tokio::signal::ctrl_c()
        .await
        .context("listen for shutdown signal")
}

fn absorb_cleanup(result: &mut Result<()>, cleanup: Result<()>, operation: &'static str) {
    if let Err(error) = cleanup {
        if result.is_ok() {
            *result = Err(error.context(operation));
        } else {
            tracing::warn!(%error, operation, "shutdown cleanup also failed");
        }
    }
}

async fn start_ready_runtime<F>(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    node: Node,
    mut shutdown: Pin<&mut F>,
) -> Result<
    Option<(
        Arc<Mutex<Node>>,
        mb_node::P2pClient,
        tokio::task::JoinHandle<Result<()>>,
        P2pStartup,
        Option<TorShutdownHandle>,
    )>,
>
where
    F: future::Future<Output = Result<()>> + ?Sized,
{
    let claimed_tor = if config.tor_mode.enabled() {
        let prepared = TorTransport::prepare_config(&TorTransportConfig {
            state_dir: config.effective_tor_state_dir(),
            cache_dir: config.effective_tor_cache_dir(),
            arti_config_file: config.arti_config_file.clone(),
            max_inbound_streams: config.max_connections,
        })?;
        Some(TorTransport::claim_prepared(prepared)?)
    } else {
        None
    };
    let claimed_tor_state = claimed_tor
        .as_ref()
        .map(|claimed| claimed.state_dir().to_path_buf());
    let construction_timeout = if config.tor_mode.enabled() {
        Duration::from_secs(180)
    } else {
        Duration::from_secs(30)
    };
    let construction_result = supervise_network_construction(
        start_node_runtime(config, identity, node, claimed_tor),
        shutdown.as_mut(),
        construction_timeout,
        || async {
            if let Some(state_dir) = claimed_tor_state.as_deref() {
                wait_for_onion_service_shutdown(state_dir).await
            } else {
                Ok(())
            }
        },
    )
    .await?;
    let Some((node, client, mut event_loop, tor_shutdown)) = construction_result else {
        return Ok(None);
    };
    let startup_receiver = event_loop.take_startup_receiver()?;
    let task = tokio::spawn(event_loop.run());
    let startup_timeout = if config.tor_mode.enabled() {
        Duration::from_secs(180)
    } else {
        Duration::from_secs(30)
    };
    let startup_result = tokio::select! {
        result = tokio::time::timeout(startup_timeout, startup_receiver) => result,
        signal = shutdown.as_mut() => {
            let mut result = signal;
            absorb_cleanup(
                &mut result,
                client.shutdown().await,
                "request libp2p shutdown during startup",
            );
            absorb_cleanup(
                &mut result,
                task.await
                    .context("libp2p event-loop task failed during startup shutdown")
                    .and_then(|result| result),
                "join libp2p shutdown during startup",
            );
            if let Some(tor_shutdown) = tor_shutdown.as_ref() {
                absorb_cleanup(
                    &mut result,
                    tor_shutdown.wait_stopped().await,
                    "join Arti onion-service shutdown during startup",
                );
            }
            return result.map(|()| None);
        }
    };
    let startup = match startup_result {
        Ok(Ok(Ok(startup))) => startup,
        Ok(Ok(Err(error))) => {
            let mut result = Err(anyhow::anyhow!("libp2p startup failed: {error}"));
            absorb_cleanup(
                &mut result,
                stop_failed_network_runtime(task, tor_shutdown.as_ref()).await,
                "stop failed network startup",
            );
            return result.map(|()| unreachable!());
        }
        Ok(Err(_)) => {
            return finish_failed_network_startup(
                task,
                wait_for_failed_tor_shutdown(tor_shutdown.as_ref()),
            )
            .await
            .map(|()| None);
        }
        Err(_) => {
            let mut result = Err(anyhow::anyhow!(
                "libp2p startup timed out after {} seconds",
                startup_timeout.as_secs()
            ));
            absorb_cleanup(
                &mut result,
                stop_failed_network_runtime(task, tor_shutdown.as_ref()).await,
                "stop timed-out network startup",
            );
            return result.map(|()| unreachable!());
        }
    };
    Ok(Some((node, client, task, startup, tor_shutdown)))
}

async fn finish_failed_network_startup<CleanupFuture>(
    task: tokio::task::JoinHandle<Result<()>>,
    cleanup: CleanupFuture,
) -> Result<()>
where
    CleanupFuture: future::Future<Output = Result<()>>,
{
    let mut result = match task.await {
        Ok(Ok(())) => Err(anyhow::anyhow!("libp2p event loop stopped before startup")),
        Ok(Err(error)) => Err(error),
        Err(error) => {
            Err(anyhow::Error::new(error).context("libp2p event-loop task failed before startup"))
        }
    };
    absorb_cleanup(&mut result, cleanup.await, "drain failed network startup");
    result
}

async fn supervise_network_construction<T, C, S, Cleanup, CleanupFuture>(
    construction: C,
    mut shutdown: Pin<&mut S>,
    timeout: Duration,
    cleanup: Cleanup,
) -> Result<Option<T>>
where
    C: future::Future<Output = Result<T>>,
    S: future::Future<Output = Result<()>> + ?Sized,
    Cleanup: FnOnce() -> CleanupFuture,
    CleanupFuture: future::Future<Output = Result<()>>,
{
    enum Outcome<T> {
        Finished(Result<T>),
        Shutdown(Result<()>),
        TimedOut,
    }

    let mut construction = Box::pin(construction);
    let outcome = tokio::select! {
        result = tokio::time::timeout(timeout, construction.as_mut()) => match result {
            Ok(result) => Outcome::Finished(result),
            Err(_) => Outcome::TimedOut,
        },
        signal = shutdown.as_mut() => Outcome::Shutdown(signal),
    };
    // Drop a cancelled constructor before waiting for any Arti instance lock
    // it may have acquired and then released during destruction.
    drop(construction);
    match outcome {
        Outcome::Finished(Ok(runtime)) => Ok(Some(runtime)),
        Outcome::Finished(Err(error)) => {
            let mut result = Err(error);
            absorb_cleanup(
                &mut result,
                cleanup().await,
                "drain failed network construction",
            );
            result.map(|()| None)
        }
        Outcome::Shutdown(mut result) => {
            absorb_cleanup(
                &mut result,
                cleanup().await,
                "drain interrupted network construction",
            );
            result.map(|()| None)
        }
        Outcome::TimedOut => {
            let mut result = Err(anyhow::anyhow!(
                "network construction timed out after {} seconds",
                timeout.as_secs()
            ));
            absorb_cleanup(
                &mut result,
                cleanup().await,
                "drain timed-out network construction",
            );
            result.map(|()| None)
        }
    }
}

async fn stop_failed_network_runtime(
    task: tokio::task::JoinHandle<Result<()>>,
    tor_shutdown: Option<&TorShutdownHandle>,
) -> Result<()> {
    task.abort();
    let _ = task.await;
    wait_for_failed_tor_shutdown(tor_shutdown).await
}

async fn wait_for_failed_tor_shutdown(tor_shutdown: Option<&TorShutdownHandle>) -> Result<()> {
    if let Some(tor_shutdown) = tor_shutdown {
        tor_shutdown
            .wait_stopped()
            .await
            .context("wait for failed Arti runtime to release its state")?;
    }
    Ok(())
}

async fn start_node_runtime(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    node: Node,
    claimed_tor: Option<ClaimedTorTransportConfig>,
) -> Result<(
    Arc<Mutex<Node>>,
    mb_node::P2pClient,
    mb_node::P2pEventLoop,
    Option<TorShutdownHandle>,
)> {
    // Finish all fallible operator-address parsing and local publication
    // validation before launching Arti.
    let listen_addresses = parse_addresses(&config.p2p_listen_addresses)?;
    let mut external_addresses = parse_addresses(&config.p2p_external_addresses)?;
    let bootstrap_addresses = parse_addresses(&config.p2p_bootstrap_addresses)?;
    let relay_reservation_addresses = parse_addresses(&config.p2p_relay_addresses)?;
    external_addresses = mb_node::validate_local_advertised_endpoints(
        identity.expected_node_id,
        config.tor_mode,
        &listen_addresses,
        &external_addresses,
        &relay_reservation_addresses,
        config.enable_port_mapping,
    )?;
    let onion_endpoint = onion_listener_address(identity.expected_node_id)?;
    let direct_endpoint = external_addresses
        .first()
        .or_else(|| listen_addresses.first())
        .map(ToString::to_string);
    let public_endpoint = match (config.tor_mode.requires_tor(), direct_endpoint) {
        (true, _) => onion_endpoint.to_string(),
        (false, Some(endpoint)) => endpoint,
        (false, None) if config.tor_mode.enabled() => onion_endpoint.to_string(),
        (false, None) => format!(
            "{}/p2p-circuit/p2p/{}",
            config
                .p2p_relay_addresses
                .first()
                .context("validated config has no relay address")?,
            identity.expected_node_id.libp2p_peer_id()?
        ),
    };
    let failure_domain = config.effective_failure_domain(identity);
    let (tor_transport, tor_shutdown) = if let Some(claimed_tor) = claimed_tor {
        let transport = TorTransport::new_claimed(
            claimed_tor,
            node.keys().onion_identity_seed(),
            identity.expected_node_id,
        )
        .await?;
        let shutdown = transport.shutdown_handle();
        (Some(transport), Some(shutdown))
    } else {
        (None, None)
    };
    let node = Arc::new(Mutex::new(node));
    let p2p_config = P2pConfig {
        listen_addresses,
        external_addresses,
        bootstrap_addresses,
        relay_reservation_addresses,
        enable_dht_maintenance: config.enable_dht_maintenance,
        enable_relay_server: config.enable_relay_server,
        enable_hole_punching: config.enable_hole_punching,
        enable_port_mapping: config.enable_port_mapping,
        public_endpoint,
        failure_domain,
        configure_failure_domain: identity.intent == InitializationIntent::New,
        max_connections: config.max_connections,
        tor_mode: config.tor_mode,
    };
    let (p2p_client, p2p_event_loop) = match build_p2p_with_tor(
        node.clone(),
        p2p_config,
        tor_transport,
    ) {
        Ok(runtime) => runtime,
        Err(error) => {
            if let Err(cleanup_error) = wait_for_failed_tor_shutdown(tor_shutdown.as_ref()).await {
                tracing::warn!(%cleanup_error, "Arti cleanup also failed after libp2p construction failure");
            }
            return Err(error);
        }
    };
    Ok((node, p2p_client, p2p_event_loop, tor_shutdown))
}

fn open_configured_node(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    locked_data_dir: LockedDataDir,
    seed: mb_core::Seed,
) -> Result<Node> {
    let actual = mb_core::KeyMaterial::from_seed(&seed).node_id();
    if actual != identity.expected_node_id {
        anyhow::bail!(
            "recovery string derives node {actual}, expected {}",
            identity.expected_node_id
        );
    }
    let mut node = Node::open_locked(locked_data_dir, seed)?;
    if identity.intent == InitializationIntent::New {
        node.configure_failure_domain(&config.effective_failure_domain(identity))?;
    }
    node.configure_parity_budget(config.parity_budget_bytes)?;
    Ok(node)
}

async fn await_manual_node(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    locked_data_dir: LockedDataDir,
    listener: &LocalControlListener,
) -> Result<(Node, mb_node::LocalControlConnection)> {
    loop {
        let mut connection = listener.accept().await?;
        let request = match connection.read_request().await {
            Ok(request) => request,
            Err(error) => {
                tracing::warn!(%error, "invalid locked-daemon control request");
                continue;
            }
        };
        match request {
            LocalRequest::Status => {
                if let Err(error) = connection
                    .respond(LocalResponse::Locked {
                        expected_node_id: identity.expected_node_id,
                    })
                    .await
                {
                    tracing::warn!(%error, "locked status client disconnected");
                }
            }
            LocalRequest::Unlock { secret } => {
                match try_manual_unlock(config, identity, locked_data_dir.clone(), secret).await {
                    Ok(node) => return Ok((node, connection)),
                    Err(error) => {
                        tracing::warn!(%error, "manual daemon unlock rejected");
                        if let Err(response_error) = connection
                            .respond_error(WireError::operation(format!("{error:#}")))
                            .await
                        {
                            tracing::warn!(%response_error, "rejected unlock client disconnected");
                        }
                    }
                }
            }
            _ => {
                if let Err(error) = connection.respond_error(WireError::locked()).await {
                    tracing::warn!(%error, "locked control client disconnected");
                }
            }
        }
    }
}

async fn try_manual_unlock(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    locked_data_dir: LockedDataDir,
    secret: UnlockSecret,
) -> Result<Node> {
    let config = config.clone();
    let identity = identity.clone();
    tokio::task::spawn_blocking(move || {
        open_configured_node(&config, &identity, locked_data_dir, secret.seed())
    })
    .await
    .context("unlock worker failed")?
}

fn parse_addresses(values: &[String]) -> Result<Vec<Multiaddr>> {
    values
        .iter()
        .map(|value| {
            value
                .parse()
                .map_err(anyhow::Error::new)
                .with_context(|| format!("invalid libp2p multiaddress {value}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn signal_during_construction_cancels_owner_before_cleanup() {
        let dropped = Arc::new(AtomicBool::new(false));
        let cleaned = Arc::new(AtomicBool::new(false));
        let marker = DropMarker(Arc::clone(&dropped));
        let construction = async move {
            let _marker = marker;
            future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };
        let shutdown = future::ready(Ok(()));
        tokio::pin!(shutdown);

        let result = supervise_network_construction(
            construction,
            shutdown.as_mut(),
            Duration::from_secs(10),
            || {
                let dropped = Arc::clone(&dropped);
                let cleaned = Arc::clone(&cleaned);
                async move {
                    assert!(dropped.load(Ordering::SeqCst));
                    cleaned.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .unwrap();
        assert!(result.is_none());
        assert!(cleaned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn construction_timeout_cancels_owner_before_cleanup() {
        let dropped = Arc::new(AtomicBool::new(false));
        let cleaned = Arc::new(AtomicBool::new(false));
        let marker = DropMarker(Arc::clone(&dropped));
        let construction = async move {
            let _marker = marker;
            future::pending::<()>().await;
            Ok::<(), anyhow::Error>(())
        };
        let shutdown = future::pending::<Result<()>>();
        tokio::pin!(shutdown);

        let error = supervise_network_construction(
            construction,
            shutdown.as_mut(),
            Duration::from_millis(1),
            || {
                let dropped = Arc::clone(&dropped);
                let cleaned = Arc::clone(&cleaned);
                async move {
                    assert!(dropped.load(Ordering::SeqCst));
                    cleaned.store(true, Ordering::SeqCst);
                    Ok(())
                }
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("construction timed out"));
        assert!(cleaned.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn p2p_startup_panic_still_runs_cleanup() {
        let cleaned = Arc::new(AtomicBool::new(false));
        let task = tokio::spawn(async {
            panic!("synthetic P2P startup panic");
            #[allow(unreachable_code)]
            Ok(())
        });
        let cleanup_marker = Arc::clone(&cleaned);
        let error = finish_failed_network_startup(task, async move {
            cleanup_marker.store(true, Ordering::SeqCst);
            Ok(())
        })
        .await
        .unwrap_err();
        assert!(error.to_string().contains("event-loop task failed"));
        assert!(cleaned.load(Ordering::SeqCst));
    }
}
