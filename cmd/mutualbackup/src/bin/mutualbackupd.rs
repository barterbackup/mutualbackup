use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use libp2p::Multiaddr;
use mb_node::{
    LocalControlListener, LocalRequest, LocalResponse, LockedDataDir, Node, P2pConfig,
    UnlockSecret, WireError, bind_local_control, build_p2p, run_coordinator_jobs,
    run_dht_publications, run_root_watcher, serve_local_control_on,
};
use mutualbackup::{DaemonConfig, read_config, read_seed};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(name = "mutualbackupd", version, about = "MutualBackup node daemon")]
struct Cli {
    #[arg(long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .ok();
    let config = read_config(&Cli::parse().config)?;
    let locked_data_dir = Node::lock_data_dir(&config.data_dir)?;
    let listener = bind_local_control(&config.control_socket)?;
    let (node, p2p_client, p2p_event_loop) = match &config.seed_file {
        Some(seed_file) => {
            let seed_file = seed_file.clone();
            let open_config = config.clone();
            let node = tokio::task::spawn_blocking(move || {
                let seed =
                    read_seed(&seed_file).context("automatic recovery-string unlock failed")?;
                open_configured_node(&open_config, locked_data_dir, seed)
            })
            .await
            .context("automatic unlock worker failed")??;
            start_node_runtime(&config, node)?
        }
        None => {
            println!("node {} locked", config.expected_node_id);
            println!("control socket: {}", config.control_socket.display());
            loop {
                let (node, connection) =
                    await_manual_node(&config, locked_data_dir.clone(), &listener).await?;
                match start_node_runtime(&config, node) {
                    Ok(runtime) => {
                        if let Err(error) = connection
                            .respond(LocalResponse::Unlocked {
                                node_id: config.expected_node_id,
                            })
                            .await
                        {
                            tracing::warn!(%error, "unlocking client disconnected before acknowledgement");
                        }
                        break runtime;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "manual daemon unlock could not start node runtime");
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
    let node_id = config.expected_node_id;
    println!("node {node_id} ready");
    println!("libp2p peer id: {}", p2p_client.local_peer_id());
    println!("control socket: {}", config.control_socket.display());

    tokio::select! {
        result = serve_local_control_on(node.clone(), p2p_client.clone(), listener) => result,
        result = run_coordinator_jobs(node.clone(), p2p_client.clone()) => result,
        result = run_dht_publications(node.clone(), p2p_client.clone()) => result,
        result = run_root_watcher(node.clone()) => result,
        result = p2p_event_loop.run() => result,
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok(())
        }
    }
}

fn start_node_runtime(
    config: &DaemonConfig,
    node: Node,
) -> Result<(Arc<Mutex<Node>>, mb_node::P2pClient, mb_node::P2pEventLoop)> {
    let node = Arc::new(Mutex::new(node));
    let p2p_config = P2pConfig {
        listen_addresses: parse_addresses(&config.p2p_listen_addresses)?,
        external_addresses: parse_addresses(&config.p2p_external_addresses)?,
        bootstrap_addresses: parse_addresses(&config.p2p_bootstrap_addresses)?,
        relay_reservation_addresses: parse_addresses(&config.p2p_relay_addresses)?,
        enable_relay_server: config.enable_relay_server,
        enable_hole_punching: true,
        public_endpoint: config
            .p2p_external_addresses
            .first()
            .or_else(|| config.p2p_listen_addresses.first())
            .cloned()
            .expect("validated config has a listen address"),
        failure_domain: config.failure_domain.clone(),
        configure_failure_domain: !config.recovery_mode,
        max_connections: 32,
    };
    let (p2p_client, p2p_event_loop) = build_p2p(node.clone(), p2p_config)?;
    Ok((node, p2p_client, p2p_event_loop))
}

fn open_configured_node(
    config: &DaemonConfig,
    locked_data_dir: LockedDataDir,
    seed: mb_core::Seed,
) -> Result<Node> {
    let actual = mb_core::KeyMaterial::from_seed(&seed).node_id();
    if actual != config.expected_node_id {
        anyhow::bail!(
            "recovery string derives node {actual}, expected {}",
            config.expected_node_id
        );
    }
    let mut node = Node::open_locked(locked_data_dir, seed)?;
    if !config.recovery_mode {
        node.configure_failure_domain(&config.failure_domain)?;
    }
    node.configure_parity_budget(config.parity_budget_bytes)?;
    Ok(node)
}

async fn await_manual_node(
    config: &DaemonConfig,
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
                        expected_node_id: config.expected_node_id,
                    })
                    .await
                {
                    tracing::warn!(%error, "locked status client disconnected");
                }
            }
            LocalRequest::Unlock { secret } => {
                match try_manual_unlock(config, locked_data_dir.clone(), secret).await {
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
    config: &DaemonConfig,
    locked_data_dir: LockedDataDir,
    secret: UnlockSecret,
) -> Result<Node> {
    let config = config.clone();
    tokio::task::spawn_blocking(move || {
        open_configured_node(&config, locked_data_dir, secret.seed())
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
