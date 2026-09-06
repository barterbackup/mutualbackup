use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mb_core::{KeyMaterial, NodeId, Seed};
use mb_node::{
    DirectoryState, LocalRequest, LocalResponse, Node, NodeServerConfig, PrototypeGuild,
    commit_source_over_network_with_intent, local_control_call, recover_guild_over_network,
    recover_member_and_republish_over_network, recover_over_network, serve_directory, serve_node,
};
use mb_store::probe_reflink;
use mutualbackup::{
    DaemonConfig, default_p2p_listen_addresses, read_seed, write_config, write_seed,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "mutualbackup", version, about = "Mutual P2P backup prototype")]
struct Cli {
    /// Unix socket of the local daemon. Required by routine runtime commands.
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
    /// Run a real five-node, SQLCipher-backed, seed-only recovery demonstration.
    DemoSeedRecovery {
        /// Existing directory on a reflink-capable filesystem. The command
        /// creates one uniquely named demonstration directory below it.
        #[arg(long)]
        work_dir: PathBuf,
    },
    /// Run the temporary signed recovery-record directory service.
    ServeDirectory {
        #[arg(long)]
        listen: SocketAddr,
    },
    /// Run one independently keyed node and its persistent encrypted stores.
    ServeNode {
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        listen: SocketAddr,
        /// Address advertised to other peers, currently tcp://IP:PORT.
        #[arg(long)]
        public_endpoint: String,
        /// A stable physical failure-domain label such as host, disk, or zone.
        #[arg(long)]
        failure_domain: String,
        /// Node ID authorized to coordinate mutations in this prototype guild.
        #[arg(long)]
        trusted_coordinator: NodeId,
    },
    /// Capture a reflink snapshot and distribute its RS groups to five nodes.
    Commit {
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        source: PathBuf,
        #[arg(long)]
        directory: SocketAddr,
        /// Repeat exactly five times; one endpoint must be this seed's node.
        #[arg(long, required = true)]
        peer: Vec<SocketAddr>,
        /// Resume the durable commit with this previously printed intent UUID.
        #[arg(long)]
        resume_intent: Option<Uuid>,
    },
    /// Recover into an empty target using only the seed and public directory.
    Recover {
        #[arg(long)]
        seed_file: PathBuf,
        /// New local state directory rebuilt during recovery.
        #[arg(long)]
        data_dir: PathBuf,
        /// Destination path, which must not already exist.
        #[arg(long)]
        restore: PathBuf,
        #[arg(long)]
        directory: SocketAddr,
        /// Required when this seed owns revisions in more than one guild.
        #[arg(long)]
        guild_id: Option<String>,
    },
    /// Rebuild a storage member, republish its new endpoint, and serve it.
    RecoverMember {
        #[arg(long)]
        seed_file: PathBuf,
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        directory: SocketAddr,
        #[arg(long)]
        listen: SocketAddr,
        #[arg(long)]
        public_endpoint: String,
        #[arg(long)]
        failure_domain: String,
        #[arg(long)]
        trusted_coordinator: NodeId,
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
                let control_socket = cli
                    .socket
                    .as_ref()
                    .context("--socket is required when --config is used")?;
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
            let response =
                local_control_call(required_socket(&cli.socket)?, &LocalRequest::Status).await?;
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
        }
        Command::Root {
            command: RootCommand::Add { path },
        } => {
            let response = local_control_call(
                required_socket(&cli.socket)?,
                &LocalRequest::AddRoot { path },
            )
            .await?;
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
                GuildCommand::Finalize => LocalRequest::GuildFinalize,
                GuildCommand::Status => LocalRequest::GuildStatus,
            };
            match local_control_call(required_socket(&cli.socket)?, &request).await? {
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
            let response = local_control_call(
                required_socket(&cli.socket)?,
                &LocalRequest::Backup { wait },
            )
            .await?;
            let LocalResponse::BackupJob(job) = response else {
                bail!("daemon returned the wrong response to backup request");
            };
            print_backup_job(&job);
        }
        Command::BackupStatus { revision_id } => {
            let response = local_control_call(
                required_socket(&cli.socket)?,
                &LocalRequest::BackupStatus { revision_id },
            )
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
            let control_socket = cli
                .socket
                .as_ref()
                .context("--socket is required for recover-init")?;
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
                required_socket(&cli.socket)?,
                &LocalRequest::Recover {
                    target: target.clone(),
                },
            )
            .await?;
            let LocalResponse::Recovered(result) = response else {
                bail!("daemon returned the wrong response to restore request");
            };
            println!("restore succeeded: {}", target.display());
            println!("guild id:    {}", hex::encode(result.guild_id));
            println!("checkpoint:  {}", hex::encode(result.checkpoint_hash));
            println!("generation:  {}", result.generation);
            println!("revision:    {}", result.revision_id);
        }
        Command::Snapshot { command } => match command {
            SnapshotCommand::List => {
                let response =
                    local_control_call(required_socket(&cli.socket)?, &LocalRequest::SnapshotList)
                        .await?;
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
                    required_socket(&cli.socket)?,
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
        Command::DemoSeedRecovery { work_dir } => demo_seed_recovery(work_dir)?,
        Command::ServeDirectory { listen } => {
            println!("recovery directory listening on {listen}");
            serve_directory(listen, DirectoryState::default()).await?;
        }
        Command::ServeNode {
            seed_file,
            data_dir,
            listen,
            public_endpoint,
            failure_domain,
            trusted_coordinator,
        } => {
            let seed = read_seed(&seed_file)?;
            let node = Node::open(data_dir, seed)?;
            let node_id = node.keys().node_id();
            println!("node {node_id} listening on {listen} as {public_endpoint}");
            serve_node(
                Arc::new(Mutex::new(node)),
                NodeServerConfig {
                    listen,
                    public_endpoint,
                    failure_domain,
                    trusted_coordinator,
                    max_connections: 32,
                },
            )
            .await?;
        }
        Command::Commit {
            seed_file,
            source,
            directory,
            peer,
            resume_intent,
        } => {
            let seed = read_seed(&seed_file)?;
            let keys = KeyMaterial::from_seed(&seed);
            let source = source
                .canonicalize()
                .with_context(|| format!("cannot resolve source {}", source.display()))?;
            let intent_id = resume_intent.unwrap_or_else(Uuid::new_v4);
            println!("commit intent:      {intent_id}");
            let result =
                commit_source_over_network_with_intent(&keys, &source, directory, peer, intent_id)
                    .await?;
            println!("commit succeeded");
            println!("guild id:          {}", hex::encode(result.guild_id));
            println!("checkpoint:        {}", hex::encode(result.checkpoint_hash));
            println!("coding groups:     {}", result.coding_groups);
            println!("recoverable owner: {}", result.owner);
        }
        Command::Recover {
            seed_file,
            data_dir,
            restore,
            directory,
            guild_id,
        } => {
            if restore.exists() {
                bail!("--restore must not already exist");
            }
            let seed = read_seed(&seed_file)?;
            let node = match guild_id {
                Some(guild_id) => {
                    recover_guild_over_network(
                        seed,
                        &data_dir,
                        &restore,
                        directory,
                        parse_hex_32(&guild_id)?,
                    )
                    .await?
                }
                None => recover_over_network(seed, &data_dir, &restore, directory).await?,
            };
            println!("seed-only recovery succeeded");
            println!("node id:            {}", node.keys().node_id());
            println!("rebuilt state:      {}", data_dir.display());
            println!("restored directory: {}", restore.display());
        }
        Command::RecoverMember {
            seed_file,
            data_dir,
            directory,
            listen,
            public_endpoint,
            failure_domain,
            trusted_coordinator,
        } => {
            let recovered = recover_member_and_republish_over_network(
                read_seed(&seed_file)?,
                &data_dir,
                directory,
                public_endpoint.clone(),
            )
            .await?;
            println!(
                "storage member recovered for {} guild(s); serving on {listen}",
                recovered.checkpoints.len()
            );
            serve_node(
                Arc::new(Mutex::new(recovered.node)),
                NodeServerConfig {
                    listen,
                    public_endpoint,
                    failure_domain,
                    trusted_coordinator,
                    max_connections: 32,
                },
            )
            .await?;
        }
    }
    Ok(())
}

fn required_socket(socket: &Option<PathBuf>) -> Result<&Path> {
    socket
        .as_deref()
        .context("this command requires --socket PATH")
}

fn parse_hex_32(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).context("guild ID must be hexadecimal")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("guild ID must contain exactly 32 bytes"))
}

fn demo_seed_recovery(work_dir: PathBuf) -> Result<()> {
    if !work_dir.is_dir() {
        bail!("--work-dir must name an existing directory");
    }
    probe_reflink(&work_dir).context("work directory does not support safe reflink capture")?;
    let run_root = work_dir.join(format!("mutualbackup-demo-{}", Uuid::new_v4()));
    let source = run_root.join("source-that-will-be-deleted");
    fs::create_dir_all(source.join("documents"))?;
    fs::write(
        source.join("documents/hello.txt"),
        b"This tree was recovered from a MutualBackup seed.\n",
    )?;
    let binary = (0..180_000)
        .map(|index| ((index * 17 + 3) % 251) as u8)
        .collect::<Vec<_>>();
    fs::write(source.join("several-sectors.bin"), &binary)?;

    let seeds = (0..5).map(|_| Seed::generate()).collect::<Vec<_>>();
    let recovery_seed = seeds[0].encode();
    let mut guild = PrototypeGuild::create(&run_root.join("nodes"), seeds)?;
    let checkpoint = guild.commit_source(0, &source)?;
    let owner_id = guild.node_id(0);
    let owner_data_dir = guild.lose_node(0)?;
    let second_data_dir = guild.lose_node(1)?;

    // These paths were created under this command's unique run directory. The
    // deletion is the proof that recovery cannot consult an owner-local anchor,
    // database, or plaintext source. A second peer is removed so exactly three
    // distinct failure domains remain.
    fs::remove_dir_all(&owner_data_dir)?;
    fs::remove_dir_all(&second_data_dir)?;
    fs::remove_dir_all(&source)?;
    let restored = run_root.join("restored-from-seed");
    guild.recover(
        Seed::from_str(&recovery_seed)?,
        &run_root.join("blank-recovered-node"),
        &restored,
    )?;
    if fs::read(restored.join("documents/hello.txt"))?
        != b"This tree was recovered from a MutualBackup seed.\n"
        || fs::read(restored.join("several-sectors.bin"))? != binary
    {
        bail!("restored bytes differ from the committed source");
    }

    println!("seed-only recovery succeeded");
    println!("owner node id:      {owner_id}");
    println!("recovery seed:      {recovery_seed}");
    println!("checkpoint:         {}", hex::encode(checkpoint.hash()?));
    println!("surviving peers:    3 of 5 distinct failure domains");
    println!("restored directory: {}", restored.display());
    println!("demo state:         {}", run_root.display());
    Ok(())
}

fn print_identity(seed: &Seed, expose_seed: bool) {
    let keys = KeyMaterial::from_seed(seed);
    if expose_seed {
        println!("recovery seed: {}", seed.encode());
    }
    println!("node id:       {}", keys.node_id());
    println!("onion address: {}", keys.onion_hostname());
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
