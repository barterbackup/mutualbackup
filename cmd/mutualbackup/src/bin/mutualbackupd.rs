use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use clap::Parser;
use libp2p::Multiaddr;
use mb_node::{
    Node, P2pConfig, build_p2p, run_coordinator_jobs, run_dht_publications, run_root_watcher,
    serve_local_control,
};
use mutualbackup::{read_config, read_seed};
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
    let mut node = Node::open(&config.data_dir, read_seed(&config.seed_file)?)?;
    if !config.recovery_mode {
        node.configure_failure_domain(&config.failure_domain)?;
    }
    node.configure_parity_budget(config.parity_budget_bytes)?;
    let node_id = node.keys().node_id();
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
    println!("node {node_id} ready");
    println!("libp2p peer id: {}", p2p_client.local_peer_id());
    println!("control socket: {}", config.control_socket.display());

    tokio::select! {
        result = serve_local_control(node.clone(), p2p_client.clone(), &config.control_socket) => result,
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
