use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;
use mb_node::{Node, serve_local_control};
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
    node.configure_failure_domain(&config.failure_domain)?;
    let node_id = node.keys().node_id();
    let node = Arc::new(Mutex::new(node));
    println!("node {node_id} ready");
    println!("control socket: {}", config.control_socket.display());

    tokio::select! {
        result = serve_local_control(node, &config.control_socket) => result,
        result = tokio::signal::ctrl_c() => {
            result?;
            Ok(())
        }
    }
}
