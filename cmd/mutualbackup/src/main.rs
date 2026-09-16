use std::fs;
use std::io::{BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use mb_core::{KeyMaterial, QuorumPolicy, QuorumRule, Seed};
use mb_node::{LocalRequest, LocalResponse, Node, UnlockSecret, local_control_call};
use mb_store::{DatabaseShellResult, probe_reflink};
#[cfg(test)]
use mutualbackup::read_seed;
use mutualbackup::{
    InitializationIntent, default_control_socket, identity_manifest_path, initialize_identity,
    preflight_identity_initialization, read_recovery_string, validate_initialization_output_paths,
    write_seed,
};
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use zeroize::Zeroizing;

const MAX_CLI_RECOVERY_BYTES: usize = 16 * 1024;

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
    /// Initialize a node from a generated or user-supplied recovery string.
    Init {
        /// New, empty application state directory.
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        seed_file: Option<PathBuf>,
        /// Read a user-supplied recovery string from standard input.
        #[arg(long, conflicts_with = "prompt_recovery")]
        seed_stdin: bool,
        /// Prompt without echo for a user-supplied recovery string.
        #[arg(long, conflicts_with = "seed_stdin")]
        prompt_recovery: bool,
    },
    /// Derive public identity from a recovery string.
    Identity {
        #[arg(long)]
        seed_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "seed_file")]
        seed_stdin: bool,
    },
    /// Check whether a directory passes the complete reflink COW probe.
    ReflinkProbe { path: PathBuf },
    /// Inspect an encrypted application database using the linked SQLCipher build.
    DbShell {
        #[arg(long)]
        data_dir: PathBuf,
        /// Inspect a parity database instead of control.db.
        #[arg(long)]
        volume: Option<Uuid>,
        /// Permit SQL statements that change the selected database.
        #[arg(long)]
        write: bool,
        /// Execute one statement and exit.
        #[arg(long)]
        execute: Option<String>,
        #[arg(long)]
        seed_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "seed_file", requires = "execute")]
        seed_stdin: bool,
    },
    /// Show the persistent local daemon state.
    Status,
    /// Inspect and maintain parity storage volumes.
    Storage {
        #[command(subcommand)]
        command: StorageCommand,
    },
    /// Verify the current guild layout and optionally repair missing shards.
    Audit {
        #[arg(long)]
        repair: bool,
    },
    /// Unlock a running daemon using a recovery string.
    Unlock {
        #[arg(long)]
        seed_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "seed_file")]
        seed_stdin: bool,
    },
    /// Manage the single protected root in the prototype.
    Root {
        #[command(subcommand)]
        command: RootCommand,
    },
    /// Create, join, inspect, and administer a guild.
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
    /// Create blank application identity state from a recovery string.
    RecoverInit {
        /// New, empty application state directory.
        #[arg(long)]
        data_dir: PathBuf,
        #[arg(long)]
        seed_file: Option<PathBuf>,
        #[arg(long, conflicts_with = "seed_file")]
        seed_stdin: bool,
    },
    /// Restore this identity's latest revision through the recovery-mode daemon.
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
    /// Remove an active member through a quorum-signed event.
    Remove { node_id: mb_core::NodeId },
    /// Change an active member's failure-domain claim for future placement.
    Relabel {
        node_id: mb_core::NodeId,
        failure_domain: String,
    },
    /// Change the signature policy for subsequent guild events.
    SetQuorum {
        #[command(subcommand)]
        policy: GuildQuorumCommand,
    },
    /// Create and quorum-authorize the next recovery-key epoch for this node.
    RotateRecoveryKey,
    /// Revoke a recovery-key epoch through a quorum-signed event.
    RevokeRecoveryKey {
        subject: mb_core::NodeId,
        epoch: u64,
    },
}

#[derive(Debug, Subcommand)]
enum GuildQuorumCommand {
    Unanimous,
    Majority,
    Threshold { signatures: u16 },
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

#[derive(Debug, Subcommand)]
enum StorageCommand {
    /// List configured volumes and their durable state.
    List,
    /// Verify SQLCipher pages and every stored parity root.
    Scrub,
    /// Return unused database pages and WAL allocation to the filesystem.
    Reclaim {
        #[arg(long)]
        volume: Option<Uuid>,
    },
    /// Stop new placement on a volume and mark it for evacuation.
    Drain { volume_id: Uuid },
    /// Copy verified objects off every draining volume.
    Migrate,
    /// Explicitly return a completed retired volume to service.
    Reactivate { volume_id: Uuid },
    /// Finish interrupted cross-database writes.
    Reconcile,
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
            data_dir,
            seed_file,
            seed_stdin,
            prompt_recovery,
        } => {
            if let Some(path) = &seed_file {
                validate_initialization_output_paths(&data_dir, path)?;
            }
            let existing_seed = if !seed_stdin && !prompt_recovery {
                match seed_file.as_deref() {
                    Some(path) => match fs::symlink_metadata(path) {
                        Ok(_) => Some(read_recovery_string(path).with_context(|| {
                            format!("cannot resume initialization from {}", path.display())
                        })?),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                        Err(error) => return Err(error.into()),
                    },
                    None => None,
                }
            } else {
                None
            };
            let generated = existing_seed.is_none() && !seed_stdin && !prompt_recovery;
            let recovery = if seed_stdin {
                read_recovery_stdin().await?
            } else if prompt_recovery {
                prompt_recovery_string("Recovery string: ").await?
            } else if let Some(existing_seed) = existing_seed {
                existing_seed
            } else {
                Seed::generate_recovery_string()?
            };
            let seed = derive_seed(&recovery).await?;
            preflight_identity_initialization(&data_dir, &seed, InitializationIntent::New)?;
            if let Some(path) = &seed_file {
                write_seed(path, &recovery)?;
                println!("recovery string written to: {}", path.display());
                #[cfg(debug_assertions)]
                if std::env::var_os("MUTUALBACKUP_TEST_FAIL_AFTER_SEED_INSTALL").is_some() {
                    bail!("test interruption after recovery-string installation");
                }
            } else if generated {
                println!("recovery string (shown once): {}", recovery.as_str());
                let confirmation =
                    prompt_recovery_string("Re-enter the recovery string to confirm: ").await?;
                let confirmed = derive_seed(&confirmation).await?;
                if confirmed.expose() != seed.expose() {
                    bail!("recovery string confirmation did not match");
                }
            }
            initialize_identity(&data_dir, &seed, InitializationIntent::New)?;
            println!(
                "identity manifest written to: {}",
                identity_manifest_path(&data_dir).display()
            );
            print_identity(&seed);
        }
        Command::Identity {
            seed_file,
            seed_stdin,
        } => {
            let recovery = recovery_input(seed_file.as_deref(), seed_stdin).await?;
            print_identity(&derive_seed(&recovery).await?);
        }
        Command::ReflinkProbe { path } => {
            probe_reflink(&path)?;
            println!("reflink COW probe passed: {}", path.display());
        }
        Command::DbShell {
            data_dir,
            volume,
            write,
            execute,
            seed_file,
            seed_stdin,
        } => {
            let recovery = recovery_input(seed_file.as_deref(), seed_stdin).await?;
            let seed = derive_seed(&recovery).await?;
            let mut node = Node::open(&data_dir, seed)
                .with_context(|| format!("cannot open {}", data_dir.display()))?;
            if let Some(sql) = execute {
                let result = node.database_shell_statement(volume, &sql, write)?;
                print_database_result(&result);
            } else {
                run_database_shell(&mut node, volume, write)?;
            }
        }
        Command::Status => {
            let response = local_control_call(&control_socket, &LocalRequest::Status).await?;
            if let LocalResponse::Locked { expected_node_id } = response {
                println!("state:         Locked");
                println!("expected node: {expected_node_id}");
                return Ok(());
            }
            let LocalResponse::Status(status) = response else {
                bail!("daemon returned the wrong response to status request");
            };
            println!("node id:       {}", status.node_id);
            println!("data dir:      {}", status.data_dir.display());
            println!("checkpoints:   {}", status.checkpoint_count);
            println!("recovery ready: {}", status.seed_recovery_ready);
            println!("root dirty:     {}", status.root_dirty);
            println!(
                "automatic backup: enabled={} in-flight={} window={}/{} bytes",
                status.automatic_backup.enabled,
                status
                    .automatic_backup
                    .in_flight_revision
                    .map(|revision| revision.to_string())
                    .unwrap_or_else(|| "none".to_owned()),
                status.automatic_backup.window_backup_count,
                status.automatic_backup.window_bytes,
            );
            if let Some(reason) = &status.automatic_backup.blocked_reason {
                println!("backup blocked: {reason}");
            }
            println!("protection:     {:?}", status.protection_state);
            if let Some(audit) = &status.last_audit {
                println!(
                    "last audit:     generation={} groups={} unavailable={} repaired={} emergency={} removed={}",
                    audit.checkpoint_generation,
                    audit.checked_groups,
                    audit.assigned_shards_unavailable,
                    audit.assigned_shards_repaired,
                    audit.emergency_copies_created,
                    audit.emergency_copies_removed,
                );
            }
            for volume in status.storage_volumes {
                print_storage_volume(&volume);
            }
            match status.protected_root {
                Some(root) => println!("protected root: {}", root.path.display()),
                None => println!("protected root: (not configured)"),
            }
            if let Some(network) = status.network {
                println!("libp2p peer id: {}", network.peer_id);
                println!("network ready:  {}", network.network_ready);
                println!(
                    "direct listeners: {}/{}",
                    network.direct_listeners_active, network.direct_listeners_configured
                );
                println!(
                    "relay reservations: {}/{}",
                    network.relay_reservations_active, network.relay_reservations_configured
                );
                println!("Tor mode:        {}", network.tor_mode);
                println!(
                    "onion service:   configured={} reachable={}",
                    network.onion_service_configured, network.onion_service_reachable
                );
                println!(
                    "gateway mapping: enabled={} external={}",
                    network.port_mapping_enabled,
                    network
                        .port_mapping_external_address
                        .as_deref()
                        .unwrap_or("(none)")
                );
                for reason in network.degraded {
                    println!("network degraded: {reason}");
                }
                for address in network.listen_addresses {
                    println!("listen address: {address}");
                }
                for address in network.advertised_addresses {
                    println!("advertised address: {address}");
                }
                for metrics in network.path_metrics {
                    println!(
                        "path metrics: {:?} sessions={}/{} dial-failures={} requests={}/{} latency-ms-total={} sent={} received={}",
                        metrics.path,
                        metrics.sessions_opened,
                        metrics.sessions_closed,
                        metrics.dial_failures,
                        metrics.requests_succeeded,
                        metrics.requests_failed,
                        metrics.request_latency_millis_total,
                        metrics.application_bytes_sent,
                        metrics.application_bytes_received
                    );
                }
                for session in network.active_sessions {
                    println!(
                        "active session: #{} {} {:?} {:?} opened={}",
                        session.sequence,
                        session.peer_id,
                        session.path,
                        session.direction,
                        session.opened_at_unix_seconds
                    );
                }
                for peer in network.peers {
                    println!(
                        "peer connection: {} active={:?} last-application={:?} sent={} received={}",
                        peer.peer_id,
                        peer.active_paths,
                        peer.last_application_path,
                        peer.application_bytes_sent,
                        peer.application_bytes_received
                    );
                    for transfer in peer.path_transfers {
                        println!(
                            "peer path transfer: {} path={:?} sent={} received={}",
                            peer.peer_id,
                            transfer.path,
                            transfer.application_bytes_sent,
                            transfer.application_bytes_received
                        );
                    }
                }
                let history_skip = network.recent_sessions.len().saturating_sub(20);
                for session in network.recent_sessions.into_iter().skip(history_skip) {
                    println!(
                        "recent session: #{} {} {:?} {:?} outcome={:?} duration-ms={}",
                        session.sequence,
                        session.peer_id,
                        session.path,
                        session.direction,
                        session.outcome,
                        session.duration_millis
                    );
                }
            }
        }
        Command::Storage { command } => {
            let request = match command {
                StorageCommand::List => LocalRequest::StorageStatus,
                StorageCommand::Scrub => LocalRequest::StorageScrub,
                StorageCommand::Reclaim { volume } => {
                    LocalRequest::StorageReclaim { volume_id: volume }
                }
                StorageCommand::Drain { volume_id } => LocalRequest::StorageDrain { volume_id },
                StorageCommand::Migrate => LocalRequest::StorageMigrate,
                StorageCommand::Reactivate { volume_id } => {
                    LocalRequest::StorageReactivate { volume_id }
                }
                StorageCommand::Reconcile => LocalRequest::StorageReconcile,
            };
            match local_control_call(&control_socket, &request).await? {
                LocalResponse::StorageVolumes(volumes) => {
                    for volume in volumes {
                        print_storage_volume(&volume);
                    }
                }
                LocalResponse::StorageScrubbed(reports) => {
                    for report in reports {
                        println!(
                            "volume {}: checked {} objects / {} bytes; corrupt={}",
                            report.volume_id,
                            report.checked_objects,
                            report.checked_bytes,
                            report.corrupt_objects.len()
                        );
                    }
                }
                LocalResponse::StorageReclaimed { bytes } => {
                    println!("reclaimed physical storage bytes: {bytes}");
                }
                LocalResponse::StorageMigrated { objects } => {
                    println!("migrated parity objects: {objects}");
                }
                LocalResponse::StorageReactivated => println!("storage volume reactivated"),
                LocalResponse::StorageReconciled => println!("storage reconciliation complete"),
                _ => bail!("daemon returned the wrong response to storage request"),
            }
        }
        Command::Audit { repair } => {
            let response =
                local_control_call(&control_socket, &LocalRequest::GuildAudit { repair }).await?;
            let LocalResponse::GuildAudited(report) = response else {
                bail!("daemon returned the wrong response to audit request");
            };
            println!("protection: {:?}", report.state);
            println!("groups checked: {}", report.checked_groups);
            println!(
                "assigned shards unavailable: {}",
                report.assigned_shards_unavailable
            );
            println!("assigned repairs: {}", report.assigned_shards_repaired);
            println!("emergency copies: {}", report.emergency_copies_created);
            println!(
                "emergency copies removed: {}",
                report.emergency_copies_removed
            );
            for issue in report.issues {
                println!("issue: {issue}");
            }
        }
        Command::Unlock {
            seed_file,
            seed_stdin,
        } => {
            let recovery = recovery_input(seed_file.as_deref(), seed_stdin).await?;
            let seed = derive_seed(&recovery).await?;
            let request = LocalRequest::Unlock {
                secret: UnlockSecret::new(*seed.expose()),
            };
            let LocalResponse::Unlocked { node_id } =
                local_control_call(&control_socket, &request).await?
            else {
                bail!("daemon returned the wrong response to unlock request");
            };
            println!("daemon unlocked: {node_id}");
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
                GuildCommand::Remove { node_id } => LocalRequest::GuildRemoveMember { node_id },
                GuildCommand::Relabel {
                    node_id,
                    failure_domain,
                } => LocalRequest::GuildRelabelMember {
                    node_id,
                    failure_domain,
                },
                GuildCommand::SetQuorum { policy } => LocalRequest::GuildSetQuorum {
                    policy: QuorumPolicy {
                        format_version: 1,
                        rule: match policy {
                            GuildQuorumCommand::Unanimous => QuorumRule::Unanimous,
                            GuildQuorumCommand::Majority => QuorumRule::Majority,
                            GuildQuorumCommand::Threshold { signatures } => {
                                QuorumRule::Threshold(signatures)
                            }
                        },
                    },
                },
                GuildCommand::RotateRecoveryKey => LocalRequest::GuildRotateRecoveryKey,
                GuildCommand::RevokeRecoveryKey { subject, epoch } => {
                    LocalRequest::GuildRevokeRecoveryKey { subject, epoch }
                }
            };
            match local_control_call(&control_socket, &request).await? {
                LocalResponse::Guild(Some(guild)) => {
                    println!("guild id:    {}", hex::encode(guild.guild_id));
                    println!("coordinator: {}", guild.coordinator);
                    println!("phase:       {:?}", guild.phase);
                    println!("members:     {}", guild.peers.len());
                    if let Some(membership_epoch) = guild.membership_epoch {
                        println!("membership epoch: {membership_epoch}");
                    }
                    if let Some(event_sequence) = guild.event_sequence {
                        println!("event sequence:   {event_sequence}");
                    }
                    if let Some(quorum) = guild.quorum {
                        println!("quorum:           {:?}", quorum.rule);
                    }
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
                LocalResponse::GuildEventCommitted {
                    sequence,
                    event_hash,
                } => {
                    println!("guild event committed: {sequence}");
                    println!("event hash: {}", hex::encode(event_hash));
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
            data_dir,
            seed_file,
            seed_stdin,
        } => {
            let recovery = recovery_input(seed_file.as_deref(), seed_stdin).await?;
            let seed = derive_seed(&recovery)
                .await
                .context("cannot use the supplied recovery string")?;
            initialize_identity(&data_dir, &seed, InitializationIntent::Recovery)?;
            println!(
                "recovery identity manifest written to: {}",
                identity_manifest_path(&data_dir).display()
            );
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

fn print_identity(seed: &Seed) {
    let keys = KeyMaterial::from_seed(seed);
    println!("node id:       {}", keys.node_id());
    println!(
        "libp2p peer id: {}",
        keys.node_id()
            .libp2p_peer_id()
            .expect("recovery-derived node ID must map to libp2p")
    );
    println!(
        "recovery key:   {}",
        hex::encode(keys.recovery_public_key().0)
    );
}

fn print_storage_volume(volume: &mb_node::StorageVolumeStatus) {
    println!(
        "storage volume: {} {:?} used={}/{} allocated={} available={} headroom={} path={}",
        volume.volume_id,
        volume.state,
        volume
            .used_bytes
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        volume.budget_bytes,
        volume
            .allocated_bytes
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        volume
            .available_bytes
            .map(|bytes| bytes.to_string())
            .unwrap_or_else(|| "unknown".to_owned()),
        volume.headroom_bytes,
        volume.path.display()
    );
    if let Some(error) = &volume.last_error {
        println!("storage degraded: {error}");
    }
}

fn run_database_shell(node: &mut Node, volume: Option<Uuid>, writable: bool) -> Result<()> {
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprintln!(
            "MutualBackup SQLCipher shell ({}, {}; one statement per line; .help for commands)",
            volume
                .map(|id| format!("volume {id}"))
                .unwrap_or_else(|| "control.db".to_owned()),
            if writable { "writable" } else { "query-only" },
        );
    }
    let stdin = std::io::stdin();
    let mut lines = stdin.lock().lines();
    loop {
        if interactive {
            eprint!("mbdb> ");
            std::io::stderr().flush()?;
        }
        let Some(line) = lines.next() else {
            break;
        };
        let line = line?;
        match line.trim() {
            "" => continue,
            ".quit" | ".exit" => break,
            ".help" => {
                eprintln!(".tables  list tables");
                eprintln!(".schema  show table definitions");
                eprintln!(".quit    exit");
                eprintln!("Enter one SQL statement per line.");
                continue;
            }
            ".tables" => {
                let result = node.database_shell_statement(
                    volume,
                    "SELECT name FROM sqlite_schema WHERE type = 'table' ORDER BY name",
                    writable,
                )?;
                print_database_result(&result);
                continue;
            }
            ".schema" => {
                let result = node.database_shell_statement(
                    volume,
                    "SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL ORDER BY name",
                    writable,
                )?;
                print_database_result(&result);
                continue;
            }
            command if command.starts_with('.') => {
                eprintln!("unknown shell command: {command}");
                continue;
            }
            sql => match node.database_shell_statement(volume, sql, writable) {
                Ok(result) => print_database_result(&result),
                Err(error) => eprintln!("error: {error:#}"),
            },
        }
    }
    Ok(())
}

fn print_database_result(result: &DatabaseShellResult) {
    if !result.columns.is_empty() {
        println!("{}", result.columns.join("\t"));
    }
    for row in &result.rows {
        println!("{}", row.join("\t"));
    }
    if let Some(affected) = result.affected_rows {
        println!("rows affected: {affected}");
    }
}

async fn recovery_input(
    seed_file: Option<&std::path::Path>,
    seed_stdin: bool,
) -> Result<Zeroizing<String>> {
    match seed_file {
        Some(path) => read_recovery_string(path),
        None if seed_stdin => read_recovery_stdin().await,
        None => prompt_recovery_string("Recovery string: ").await,
    }
}

async fn read_recovery_stdin() -> Result<Zeroizing<String>> {
    tokio::task::spawn_blocking(|| {
        let mut bytes = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take((MAX_CLI_RECOVERY_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_CLI_RECOVERY_BYTES {
            bail!("recovery string on standard input exceeds size limit");
        }
        let value = std::str::from_utf8(&bytes).context("recovery string is not valid UTF-8")?;
        Ok(Zeroizing::new(value.to_owned()))
    })
    .await
    .context("recovery-string input worker failed")?
}

async fn prompt_recovery_string(prompt: &'static str) -> Result<Zeroizing<String>> {
    tokio::task::spawn_blocking(move || {
        rpassword::prompt_password(prompt)
            .map(Zeroizing::new)
            .context("cannot read recovery string without echo")
    })
    .await
    .context("recovery-string prompt worker failed")?
}

async fn derive_seed(recovery: &Zeroizing<String>) -> Result<Seed> {
    let recovery = recovery.clone();
    tokio::task::spawn_blocking(move || {
        Seed::from_recovery_string(&recovery).context("invalid recovery string")
    })
    .await
    .context("recovery-string derivation worker failed")?
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
    fn parses_dynamic_guild_administration_commands() {
        let node_id = "0707070707070707070707070707070707070707070707070707070707070707";
        let parsed =
            Cli::try_parse_from(["mutualbackup", "guild", "set-quorum", "threshold", "3"]).unwrap();
        assert!(matches!(
            parsed.command,
            Command::Guild {
                command: GuildCommand::SetQuorum {
                    policy: GuildQuorumCommand::Threshold { signatures: 3 }
                }
            }
        ));

        let parsed =
            Cli::try_parse_from(["mutualbackup", "guild", "relabel", node_id, "new-domain"])
                .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Guild {
                command: GuildCommand::Relabel {
                    failure_domain,
                    ..
                }
            } if failure_domain == "new-domain"
        ));
    }

    #[test]
    fn seed_install_is_no_replace_and_private() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("recovery.seed");
        let first_text = "correct-horse-battery-staple-2026!";
        let second_text = "another-long-recovery-string-for-testing-2027!";
        let first = Seed::from_recovery_string(first_text).unwrap();
        write_seed(&path, first_text).unwrap();
        assert_eq!(read_seed(&path).unwrap().expose(), first.expose());
        assert!(write_seed(&path, second_text).is_err());
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
