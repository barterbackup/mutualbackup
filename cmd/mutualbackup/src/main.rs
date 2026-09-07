use std::path::PathBuf;

#[cfg(test)]
use std::fs;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mb_core::{KeyMaterial, Seed};
use mb_node::{LocalRequest, LocalResponse, local_control_call};
use mb_store::probe_reflink;
use mutualbackup::{
    DaemonConfig, default_p2p_listen_addresses, read_seed, write_config, write_seed,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "mutualbackup", version, about = "Mutual P2P backup prototype")]
struct Cli {
    /// Unix socket of the local daemon. Defaults below XDG_RUNTIME_DIR.
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a protected recovery-seed file and show its stable identities.
    Init {
        #[arg(long)]
        seed_file: PathBuf,
        /// Also create a daemon configuration file.
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, requires = "config")]
        data_dir: Option<PathBuf>,
        #[arg(long, requires = "config")]
        failure_domain: Option<String>,
        #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024_u64, requires = "config")]
        parity_budget_bytes: u64,
        #[arg(long = "listen", requires = "config")]
        p2p_listen_addresses: Vec<String>,
        #[arg(long = "external-address", requires = "config")]
        p2p_external_addresses: Vec<String>,
        #[arg(long = "bootstrap", requires = "config")]
        p2p_bootstrap_addresses: Vec<String>,
        #[arg(long = "relay", requires = "config")]
        p2p_relay_addresses: Vec<String>,
        #[arg(long, requires = "config")]
        enable_relay_server: bool,
    },
    /// Derive the public identity for an existing recovery seed.
    Identity {
        #[arg(long)]
        seed_file: PathBuf,
    },
    /// Check whether a directory passes the complete reflink COW probe.
    ReflinkProbe { path: PathBuf },
    /// Show the persistent local daemon state.
    Status,
    /// Manage the single protected root in the prototype.
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    /// Create, join, and inspect the fixed five-member prototype guild.
    Guild {
        #[command(subcommand)]
        command: GuildCommand,
    },
    /// Capture the registered root and submit a durable guild backup job.
    Backup {
        /// Wait until the checkpoint is committed.
        #[arg(long)]
        wait: bool,
    },
    /// Inspect a durable backup job by revision ID.
    BackupStatus { revision_id: Uuid },
    /// Create a blank recovery-mode daemon configuration around an existing seed.
    RecoverInit {
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long, default_value_t = 10 * 1024 * 1024 * 1024_u64)]
        parity_budget_bytes: u64,
        #[arg(long = "listen")]
        p2p_listen_addresses: Vec<String>,
        #[arg(long = "external-address")]
        p2p_external_addresses: Vec<String>,
        #[arg(long = "bootstrap", required = true)]
        p2p_bootstrap_addresses: Vec<String>,
        #[arg(long = "relay")]
        p2p_relay_addresses: Vec<String>,
    },
    /// Restore this seed's latest revision through the recovery-mode daemon.
    Restore { target: PathBuf },
    /// List or restore committed snapshots owned by this node.
    Snapshot {
        #[command(subcommand)]
        command: SnapshotCommand,
    },
}

#[derive(Debug, Subcommand)]
enum RootCommand {
    /// Probe and register a reflink-capable directory.
    Add { path: PathBuf },
}

#[derive(Debug, Subcommand)]
enum GuildCommand {
    /// Create a new local guild draft with this node as coordinator.
    Create,
    /// Issue a signed, single-use invitation valid for seven days.
    Invite,
    /// Join the coordinator's draft using a signed invitation token.
    Join { token: String },
    /// Retry delivery of a durably pending guild join.
    Retry,
    /// Discard a pending guild join so another invitation can be used.
    Cancel,
    /// Collect all five signatures and install the immutable guild genesis.
    Finalize,
    /// Show local guild membership and onboarding phase.
    Status,
}

#[derive(Debug, Subcommand)]
enum SnapshotCommand {
    List,
    Restore {
        target: PathBuf,
        #[arg(long)]
        revision: Option<Uuid>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .ok();
    let cli = Cli::parse();
    let control_socket = cli.socket.clone().unwrap_or_else(default_control_socket);
    match cli.command {
        Command::Init {
            seed_file,
            config,
            data_dir,
            failure_domain,
            parity_budget_bytes,
            p2p_listen_addresses,
            p2p_external_addresses,
            p2p_bootstrap_addresses,
            p2p_relay_addresses,
            enable_relay_server,
        } => {
            let seed = Seed::generate();
            write_seed(&seed_file, &seed)?;
            println!("recovery seed written to: {}", seed_file.display());
            if let Some(config_path) = config {
                let config = DaemonConfig {
                    format_version: 1,
                    data_dir: data_dir.context("--data-dir is required when --config is used")?,
                    seed_file: seed_file.clone(),
                    control_socket: control_socket.clone(),
                    failure_domain: failure_domain
                        .context("--failure-domain is required when --config is used")?,
                    recovery_mode: false,
                    parity_budget_bytes,
                    p2p_listen_addresses: if p2p_listen_addresses.is_empty() {
                        default_p2p_listen_addresses()
                    } else {
                        p2p_listen_addresses
                    },
                    p2p_external_addresses,
                    p2p_bootstrap_addresses,
                    p2p_relay_addresses,
                    enable_relay_server,
                };
                write_config(&config_path, &config)?;
                println!("daemon config written to: {}", config_path.display());
            }
            print_identity(&seed, false);
        }
        Command::Identity { seed_file } => print_identity(&read_seed(&seed_file)?, false),
        Command::ReflinkProbe { path } => {
            probe_reflink(&path)?;
            println!("reflink COW probe passed: {}", path.display());
        }
        Command::Status => {
            let response = local_control_call(&control_socket, &LocalRequest::Status).await?;
            let LocalResponse::Status(status) = response else {
                bail!("daemon returned the wrong response to status request");
            };
            println!("node id:       {}", status.node_id);
            println!("data dir:      {}", status.data_dir.display());
            println!("checkpoints:   {}", status.checkpoint_count);
            println!("recovery ready: {}", status.seed_recovery_ready);
            println!("root dirty:     {}", status.root_dirty);
            match status.protected_root {
                Some(root) => println!("protected root: {}", root.path.display()),
                None => println!("protected root: (not configured)"),
            }
            if let Some(network) = status.network {
                println!("libp2p peer id: {}", network.peer_id);
                for peer in network.peers {
                    println!(
                        "peer connection: {} active={:?} last-application={:?}",
                        peer.peer_id, peer.active_paths, peer.last_application_path
                    );
                }
            }
        }
        Command::Root {
            command: RootCommand::Add { path },
        } => {
            let response =
                local_control_call(&control_socket, &LocalRequest::AddRoot { path }).await?;
            let LocalResponse::RootAdded(root) = response else {
                bail!("daemon returned the wrong response to root-add request");
            };
            println!("protected root registered: {}", root.path.display());
            println!("root id: {}", root.root_id);
        }
        Command::Guild { command } => {
            let request = match command {
                GuildCommand::Create => LocalRequest::GuildCreate,
                GuildCommand::Invite => LocalRequest::GuildInvite,
                GuildCommand::Join { token } => LocalRequest::GuildJoin { token },
                GuildCommand::Retry => LocalRequest::GuildRetry,
                GuildCommand::Cancel => LocalRequest::GuildCancel,
                GuildCommand::Finalize => LocalRequest::GuildFinalize,
                GuildCommand::Status => LocalRequest::GuildStatus,
            };
            match local_control_call(&control_socket, &request).await? {
                LocalResponse::Guild(Some(guild)) => {
                    println!("guild id:    {}", hex::encode(guild.guild_id));
                    println!("coordinator: {}", guild.coordinator);
                    println!("phase:       {:?}", guild.phase);
                    println!("members:     {} of 5", guild.peers.len());
                    for peer in guild.peers {
                        println!(
                            "member:      {} [{}]",
                            peer.member.node_id, peer.member.failure_domain
                        );
                    }
                }
                LocalResponse::Guild(None) => println!("guild: (not configured)"),
                LocalResponse::GuildInvite {
                    token,
                    expires_at_unix_seconds,
                } => {
                    println!("invitation: {token}");
                    println!("expires unix: {expires_at_unix_seconds}");
                }
                _ => bail!("daemon returned the wrong response to guild request"),
            }
        }
        Command::Backup { wait } => {
            let response =
                local_control_call(&control_socket, &LocalRequest::Backup { wait }).await?;
            let LocalResponse::BackupJob(job) = response else {
                bail!("daemon returned the wrong response to backup request");
            };
            print_backup_job(&job);
        }
        Command::BackupStatus { revision_id } => {
            let response =
                local_control_call(&control_socket, &LocalRequest::BackupStatus { revision_id })
                    .await?;
            let LocalResponse::BackupJob(job) = response else {
                bail!("daemon returned the wrong response to backup-status request");
            };
            print_backup_job(&job);
        }
        Command::RecoverInit {
            seed_file,
            config,
            data_dir,
            parity_budget_bytes,
            p2p_listen_addresses,
            p2p_external_addresses,
            p2p_bootstrap_addresses,
            p2p_relay_addresses,
        } => {
            read_seed(&seed_file).context("cannot use the supplied recovery seed")?;
            write_config(
                &config,
                &DaemonConfig {
                    format_version: 1,
                    data_dir,
                    seed_file,
                    control_socket: control_socket.clone(),
                    failure_domain: String::new(),
                    recovery_mode: true,
                    parity_budget_bytes,
                    p2p_listen_addresses: if p2p_listen_addresses.is_empty() {
                        default_p2p_listen_addresses()
                    } else {
                        p2p_listen_addresses
                    },
                    p2p_external_addresses,
                    p2p_bootstrap_addresses,
                    p2p_relay_addresses,
                    enable_relay_server: false,
                },
            )?;
            println!("recovery daemon config written to: {}", config.display());
        }
        Command::Restore { target } => {
            let response = local_control_call(
                &control_socket,
                &LocalRequest::Recover {
                    target: target.clone(),
                },
            )
            .await?;
            let LocalResponse::Recovered(result) = response else {
                bail!("daemon returned the wrong response to restore request");
            };
            println!("guild id:    {}", hex::encode(result.guild_id));
            println!("checkpoint:  {}", hex::encode(result.checkpoint_hash));
            println!("generation:  {}", result.generation);
            if let Some(revision_id) = result.revision_id {
                println!("restore succeeded: {}", target.display());
                println!("revision:    {revision_id}");
            } else {
                println!("recovery succeeded: guild state and assigned shards restored");
                println!("revision:    (this node has no protected-root revision)");
            }
        }
        Command::Snapshot { command } => match command {
            SnapshotCommand::List => {
                let response =
                    local_control_call(&control_socket, &LocalRequest::SnapshotList).await?;
                let LocalResponse::Snapshots(snapshots) = response else {
                    bail!("daemon returned the wrong response to snapshot list");
                };
                for snapshot in snapshots {
                    println!(
                        "{} sequence={} checkpoint-generation={}",
                        snapshot.revision_id, snapshot.sequence, snapshot.checkpoint_generation
                    );
                }
            }
            SnapshotCommand::Restore { target, revision } => {
                let response = local_control_call(
                    &control_socket,
                    &LocalRequest::SnapshotRestore {
                        revision_id: revision,
                        target: target.clone(),
                    },
                )
                .await?;
                let LocalResponse::SnapshotRestored(snapshot) = response else {
                    bail!("daemon returned the wrong response to snapshot restore");
                };
                println!(
                    "restored revision {} to {}",
                    snapshot.revision_id,
                    target.display()
                );
            }
        },
    }
    Ok(())
}

fn default_control_socket() -> PathBuf {
    if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
        PathBuf::from(runtime).join("mutualbackup/control.sock")
    } else {
        std::env::temp_dir()
            .join(format!("mutualbackup-{}", unsafe { libc::geteuid() }))
            .join("control.sock")
    }
}

fn print_identity(seed: &Seed, expose_seed: bool) {
    let keys = KeyMaterial::from_seed(seed);
    if expose_seed {
        println!("recovery seed: {}", seed.encode());
    }
    println!("node id:       {}", keys.node_id());
    println!(
        "libp2p peer id: {}",
        keys.node_id()
            .libp2p_peer_id()
            .expect("seed-derived node ID must map to libp2p")
    );
    println!(
        "recovery key:   {}",
        hex::encode(keys.recovery_public_key().0)
    );
}

fn print_backup_job(job: &mb_node::BackupJob) {
    println!("revision:   {}", job.descriptor.revision_id);
    println!("state:      {:?}", job.state);
    if let Some(hash) = job.checkpoint_hash {
        println!("checkpoint: {}", hex::encode(hash));
    }
    if let Some(error) = &job.error {
        println!("last error: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_install_is_no_replace_and_private() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.seed");
        let first = Seed::from_bytes([31; 32]);
        write_seed(&path, &first).unwrap();
        assert_eq!(read_seed(&path).unwrap().expose(), first.expose());
        assert!(write_seed(&path, &Seed::from_bytes([32; 32])).is_err());
        assert_eq!(read_seed(&path).unwrap().expose(), first.expose());
        assert_eq!(
            fs::read_dir(temp.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .count(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }
}
