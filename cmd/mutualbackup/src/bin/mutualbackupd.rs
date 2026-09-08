use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use libp2p::Multiaddr;
use mb_node::{
    LocalControlListener, LocalRequest, LocalResponse, LockedDataDir, Node, P2pConfig, P2pStartup,
    UnlockSecret, WireError, bind_local_control, build_p2p, run_coordinator_jobs,
    run_dht_publications, run_root_watcher, serve_local_control_on,
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
    let (node, p2p_client, mut p2p_task, startup) = match &config.seed_file {
        Some(seed_file) => {
            let seed_file = seed_file.clone();
            let open_config = config.clone();
            let open_identity = identity.clone();
            let node = tokio::task::spawn_blocking(move || {
                let seed =
                    read_seed(&seed_file).context("automatic recovery-string unlock failed")?;
                open_configured_node(&open_config, &open_identity, locked_data_dir, seed)
            })
            .await
            .context("automatic unlock worker failed")??;
            start_ready_runtime(&config, &identity, node).await?
        }
        None => {
            println!("node {} locked", identity.expected_node_id);
            println!("control socket: {}", config.control_socket.display());
            loop {
                let (node, connection) =
                    await_manual_node(&config, &identity, locked_data_dir.clone(), &listener)
                        .await?;
                match start_ready_runtime(&config, &identity, node).await {
                    Ok(runtime) => {
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
        "network ingress: direct={} relay={} degraded={:?}",
        startup.direct_listeners_active, startup.relay_reservations_active, startup.degraded
    );
    println!("libp2p peer id: {}", p2p_client.local_peer_id());
    println!("control socket: {}", config.control_socket.display());

    tokio::select! {
        result = serve_local_control_on(node.clone(), p2p_client.clone(), listener) => result,
        result = run_coordinator_jobs(node.clone(), p2p_client.clone()) => result,
        result = run_dht_publications(node.clone(), p2p_client.clone()), if config.enable_dht_maintenance => result,
        result = run_root_watcher(node.clone()) => result,
        result = &mut p2p_task => result.context("libp2p event-loop task failed")?,
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok(())
        }
    }
}

async fn start_ready_runtime(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    node: Node,
) -> Result<(
    Arc<Mutex<Node>>,
    mb_node::P2pClient,
    tokio::task::JoinHandle<Result<()>>,
    P2pStartup,
)> {
    let (node, client, mut event_loop) = start_node_runtime(config, identity, node)?;
    let startup_receiver = event_loop.take_startup_receiver()?;
    let task = tokio::spawn(event_loop.run());
    let startup = match tokio::time::timeout(Duration::from_secs(30), startup_receiver).await {
        Ok(Ok(Ok(startup))) => startup,
        Ok(Ok(Err(error))) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("libp2p startup failed: {error}");
        }
        Ok(Err(_)) => {
            let result = task
                .await
                .context("libp2p event-loop task failed before startup")?;
            return Err(result
                .err()
                .unwrap_or_else(|| anyhow::anyhow!("libp2p event loop stopped before startup")));
        }
        Err(_) => {
            task.abort();
            let _ = task.await;
            anyhow::bail!("libp2p startup timed out after 30 seconds");
        }
    };
    Ok((node, client, task, startup))
}

fn start_node_runtime(
    config: &DaemonOptions,
    identity: &IdentityManifest,
    node: Node,
) -> Result<(Arc<Mutex<Node>>, mb_node::P2pClient, mb_node::P2pEventLoop)> {
    let direct_endpoint = config
        .p2p_external_addresses
        .first()
        .or_else(|| config.p2p_listen_addresses.first())
        .cloned();
    let public_endpoint = match direct_endpoint {
        Some(endpoint) => endpoint,
        None => format!(
            "{}/p2p-circuit/p2p/{}",
            config
                .p2p_relay_addresses
                .first()
                .context("validated config has no relay address")?,
            identity.expected_node_id.libp2p_peer_id()?
        ),
    };
    let failure_domain = config.effective_failure_domain(identity);
    let node = Arc::new(Mutex::new(node));
    let p2p_config = P2pConfig {
        listen_addresses: parse_addresses(&config.p2p_listen_addresses)?,
        external_addresses: parse_addresses(&config.p2p_external_addresses)?,
        bootstrap_addresses: parse_addresses(&config.p2p_bootstrap_addresses)?,
        relay_reservation_addresses: parse_addresses(&config.p2p_relay_addresses)?,
        enable_dht_maintenance: config.enable_dht_maintenance,
        enable_relay_server: config.enable_relay_server,
        enable_hole_punching: config.enable_hole_punching,
        public_endpoint,
        failure_domain,
        configure_failure_domain: identity.intent == InitializationIntent::New,
        max_connections: config.max_connections,
    };
    let (p2p_client, p2p_event_loop) = build_p2p(node.clone(), p2p_config)?;
    Ok((node, p2p_client, p2p_event_loop))
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
