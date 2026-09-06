use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mb_core::{KeyMaterial, NodeId, Seed};
use mb_node::{
    DirectoryState, Node, NodeServerConfig, PrototypeGuild, commit_source_over_network,
    recover_over_network, serve_directory, serve_node,
};
use mb_store::probe_reflink;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(name = "mutualbackup", version, about = "Mutual P2P backup prototype")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a protected recovery-seed file and show its stable identities.
    Init {
        #[arg(long)]
        seed_file: PathBuf,
    },
    /// Derive the public identity for an existing recovery seed.
    Identity {
        #[arg(long)]
        seed_file: PathBuf,
    },
    /// Check whether a directory passes the complete reflink COW probe.
    ReflinkProbe { path: PathBuf },
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
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()
        .ok();
    match Cli::parse().command {
        Command::Init { seed_file } => {
            let seed = Seed::generate();
            write_seed(&seed_file, &seed)?;
            println!("recovery seed written to: {}", seed_file.display());
            print_identity(&seed, false);
        }
        Command::Identity { seed_file } => print_identity(&read_seed(&seed_file)?, false),
        Command::ReflinkProbe { path } => {
            probe_reflink(&path)?;
            println!("reflink COW probe passed: {}", path.display());
        }
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
        } => {
            let seed = read_seed(&seed_file)?;
            let keys = KeyMaterial::from_seed(&seed);
            let source = source
                .canonicalize()
                .with_context(|| format!("cannot resolve source {}", source.display()))?;
            let result = commit_source_over_network(&keys, &source, directory, peer).await?;
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
        } => {
            if restore.exists() {
                bail!("--restore must not already exist");
            }
            let seed = read_seed(&seed_file)?;
            let node = recover_over_network(seed, &data_dir, &restore, directory).await?;
            println!("seed-only recovery succeeded");
            println!("node id:            {}", node.keys().node_id());
            println!("rebuilt state:      {}", data_dir.display());
            println!("restored directory: {}", restore.display());
        }
    }
    Ok(())
}

fn write_seed(path: &PathBuf, seed: &Seed) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    if !parent.is_dir() {
        bail!("seed-file parent directory does not exist");
    }
    let temporary = parent.join(format!(".mutualbackup-seed-{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("cannot create temporary seed file in {}", parent.display()))?;
    writeln!(file, "{}", seed.encode())?;
    file.sync_all()?;
    let written = read_seed(&temporary)?;
    if written.expose() != seed.expose() {
        let _ = fs::remove_file(&temporary);
        bail!("temporary recovery seed failed validation");
    }
    if let Err(error) = fs::hard_link(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        sync_directory(parent).ok();
        return Err(error).with_context(|| format!("cannot install seed file {}", path.display()));
    }
    fs::remove_file(&temporary)?;
    sync_directory(parent)?;
    Ok(())
}

fn read_seed(path: &PathBuf) -> Result<Seed> {
    let encoded = fs::read_to_string(path)
        .with_context(|| format!("cannot read seed file {}", path.display()))?;
    Seed::from_str(encoded.trim()).context("invalid recovery seed file")
}

fn sync_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
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
