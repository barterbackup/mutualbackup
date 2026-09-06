use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as SyncUnixStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, bail};
use libp2p::multiaddr::Protocol;
use libp2p::{Multiaddr, PeerId};
use mb_core::{GuildInvite, NodeId, canonical_bytes};
use mb_core::{QuorumGuildGenesis, SignedRecord, decode_canonical};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

use crate::{
    BackupJob, BackupJobState, DhtRecoveryResult, GuildSummary, Node, P2pClient, P2pStatus,
    SnapshotInfo, recover_from_dht,
};

const MAX_LOCAL_FRAME_BYTES: usize = 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtectedRoot {
    pub format_version: u16,
    pub root_id: Uuid,
    pub path: PathBuf,
    pub filesystem_device: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    pub format_version: u16,
    pub node_id: NodeId,
    pub data_dir: PathBuf,
    pub protected_root: Option<ProtectedRoot>,
    pub checkpoint_count: u64,
    pub seed_recovery_ready: bool,
    pub root_dirty: bool,
    pub network: Option<P2pStatus>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LocalRequest {
    Status,
    AddRoot {
        path: PathBuf,
    },
    GuildStatus,
    GuildCreate,
    GuildInvite,
    GuildJoin {
        token: String,
    },
    GuildFinalize,
    Backup {
        wait: bool,
    },
    BackupStatus {
        revision_id: Uuid,
    },
    Recover {
        target: PathBuf,
    },
    SnapshotList,
    SnapshotRestore {
        revision_id: Option<Uuid>,
        target: PathBuf,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LocalResponse {
    Status(NodeStatus),
    RootAdded(ProtectedRoot),
    Guild(Option<GuildSummary>),
    GuildInvite {
        token: String,
        expires_at_unix_seconds: u64,
    },
    BackupJob(BackupJob),
    Recovered(DhtRecoveryResult),
    Snapshots(Vec<SnapshotInfo>),
    SnapshotRestored(SnapshotInfo),
    Error(String),
}

pub async fn serve_local_control(
    node: Arc<Mutex<Node>>,
    p2p: P2pClient,
    socket_path: &Path,
) -> Result<()> {
    let parent = socket_path
        .parent()
        .context("control socket must have a parent directory")?;
    let parent_existed = parent.exists();
    fs::create_dir_all(parent).with_context(|| {
        format!(
            "cannot create control socket directory {}",
            parent.display()
        )
    })?;
    if !parent_existed {
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    }
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.permissions().mode() & 0o077 != 0
    {
        bail!("control socket directory must be private and owned by the daemon user");
    }
    if let Ok(metadata) = fs::symlink_metadata(socket_path) {
        if !metadata.file_type().is_socket() {
            bail!(
                "refusing to replace non-socket control path {}",
                socket_path.display()
            );
        }
        match SyncUnixStream::connect(socket_path) {
            Ok(_) => bail!("another daemon is already listening on the control socket"),
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::ConnectionRefused | ErrorKind::NotFound
                ) =>
            {
                fs::remove_file(socket_path).with_context(|| {
                    format!("cannot remove stale socket {}", socket_path.display())
                })?;
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot verify stale socket {}", socket_path.display())
                });
            }
        }
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("cannot bind control socket {}", socket_path.display()))?;
    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600))?;
    let metadata = fs::symlink_metadata(socket_path)?;
    let _cleanup = SocketCleanup {
        path: socket_path.to_path_buf(),
        device: metadata.dev(),
        inode: metadata.ino(),
    };

    loop {
        let (stream, _) = listener.accept().await?;
        let credentials = stream
            .peer_cred()
            .context("cannot read local control peer credentials")?;
        if credentials.uid() != unsafe { libc::geteuid() } {
            tracing::warn!(
                peer_uid = credentials.uid(),
                "rejected local control client owned by another user"
            );
            continue;
        }
        let node = node.clone();
        let p2p = p2p.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_connection(node, p2p, stream).await {
                tracing::warn!(%error, "local control request failed");
            }
        });
    }
}

pub async fn local_control_call(
    socket_path: &Path,
    request: &LocalRequest,
) -> Result<LocalResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("cannot connect to daemon at {}", socket_path.display()))?;
    write_frame(&mut stream, request).await?;
    let response: LocalResponse = read_frame(&mut stream).await?;
    if let LocalResponse::Error(message) = &response {
        bail!("daemon rejected request: {message}");
    }
    Ok(response)
}

async fn handle_connection(
    node: Arc<Mutex<Node>>,
    p2p: P2pClient,
    mut stream: UnixStream,
) -> Result<()> {
    let request: LocalRequest = read_frame(&mut stream).await?;
    let response = handle_request(node, p2p, request)
        .await
        .unwrap_or_else(|error| LocalResponse::Error(format!("{error:#}")));
    write_frame(&mut stream, &response).await
}

async fn handle_request(
    node: Arc<Mutex<Node>>,
    p2p: P2pClient,
    request: LocalRequest,
) -> Result<LocalResponse> {
    match request {
        LocalRequest::Status => {
            let mut status = blocking_node(node, |node| node.status()).await?;
            status.network = Some(p2p.status().await?);
            Ok(LocalResponse::Status(status))
        }
        LocalRequest::AddRoot { path } => {
            blocking_node(node, move |node| {
                node.add_protected_root(&path).map(LocalResponse::RootAdded)
            })
            .await
        }
        LocalRequest::GuildStatus => {
            blocking_node(node, |node| node.guild_summary().map(LocalResponse::Guild)).await
        }
        LocalRequest::GuildCreate => {
            let endpoints = local_endpoints(&p2p).await?;
            blocking_node(node, move |node| {
                node.create_guild(endpoints)
                    .map(|guild| LocalResponse::Guild(Some(guild)))
            })
            .await
        }
        LocalRequest::GuildInvite => {
            let endpoints = local_endpoints(&p2p).await?;
            let expires_at_unix_seconds = unix_seconds()
                .checked_add(7 * 24 * 60 * 60)
                .context("clock overflow while creating invitation")?;
            let invite = blocking_node(node, move |node| {
                node.issue_guild_invite(endpoints, expires_at_unix_seconds)
            })
            .await?;
            Ok(LocalResponse::GuildInvite {
                token: hex::encode(canonical_bytes(&invite)?),
                expires_at_unix_seconds,
            })
        }
        LocalRequest::GuildJoin { token } => {
            let bytes = hex::decode(token).context("guild invitation must be hexadecimal")?;
            let invite: SignedRecord<GuildInvite> =
                decode_canonical(&bytes).context("guild invitation has invalid encoding")?;
            let coordinator = invite.value.coordinator.clone();
            let endpoints = local_endpoints(&p2p).await?;
            let local_peer = blocking_node(node.clone(), {
                let invite = invite.clone();
                move |node| node.begin_join_guild(invite, endpoints)
            })
            .await?;
            add_peer_endpoints(
                &p2p,
                coordinator.node_id,
                &invite.value.coordinator_endpoints,
            )
            .await?;
            let profile = p2p.profile(coordinator.node_id).await?;
            if profile.member != coordinator {
                bail!("connected coordinator profile differs from the signed invitation");
            }
            p2p.join_guild(coordinator.node_id, invite, local_peer)
                .await?;
            let guild = blocking_node(node, |node| node.guild_summary()).await?;
            Ok(LocalResponse::Guild(guild))
        }
        LocalRequest::GuildFinalize => {
            let (genesis, peers, local_signature, local_node) =
                blocking_node(node.clone(), |node| {
                    let (genesis, peers) = node.proposed_guild_genesis()?;
                    let signature = node.sign_guild_genesis(&genesis)?;
                    let local_node = node.keys().node_id();
                    Ok((genesis, peers, signature, local_node))
                })
                .await?;
            let mut signatures = vec![local_signature];
            for peer in peers
                .iter()
                .filter(|peer| peer.member.node_id != local_node)
            {
                add_peer_endpoints(&p2p, peer.member.node_id, &peer.endpoints).await?;
                signatures.push(
                    p2p.propose_guild_genesis(peer.member.node_id, genesis.clone())
                        .await?,
                );
            }
            signatures.sort_by_key(|signature| signature.signer);
            let certificate = QuorumGuildGenesis {
                genesis,
                signatures,
            };
            certificate.verify()?;
            for peer in peers
                .iter()
                .filter(|peer| peer.member.node_id != local_node)
            {
                p2p.install_guild_genesis(peer.member.node_id, certificate.clone(), peers.clone())
                    .await?;
            }
            blocking_node(node, move |node| {
                node.install_guild_genesis(certificate, peers)?;
                node.guild_summary().map(LocalResponse::Guild)
            })
            .await
        }
        LocalRequest::Backup { wait } => {
            let (descriptor, guild, local_id) = blocking_node(node.clone(), |node| {
                let descriptor = node.prepare_protected_backup()?;
                let guild = node
                    .guild_summary()?
                    .context("this node has no active guild")?;
                Ok((descriptor, guild, node.keys().node_id()))
            })
            .await?;
            let coordinator = guild
                .peers
                .iter()
                .find(|peer| peer.member.node_id == guild.coordinator)
                .context("guild endpoint roster omits the coordinator")?;
            let mut job = if guild.coordinator == local_id {
                let descriptor = descriptor.clone();
                blocking_node(node.clone(), move |node| {
                    node.enqueue_backup(local_id, descriptor)
                })
                .await?
            } else {
                add_peer_endpoints(&p2p, guild.coordinator, &coordinator.endpoints).await?;
                p2p.submit_backup(guild.coordinator, descriptor.clone())
                    .await?
            };
            while wait
                && !matches!(
                    job.state,
                    BackupJobState::Committed | BackupJobState::Failed
                )
            {
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                job = query_backup_job(
                    node.clone(),
                    &p2p,
                    local_id,
                    guild.coordinator,
                    descriptor.guild_id,
                    descriptor.revision_id,
                )
                .await?;
            }
            Ok(LocalResponse::BackupJob(job))
        }
        LocalRequest::BackupStatus { revision_id } => {
            let (guild, local_id) = blocking_node(node.clone(), |node| {
                Ok((
                    node.guild_summary()?
                        .context("this node has no active guild")?,
                    node.keys().node_id(),
                ))
            })
            .await?;
            let coordinator = guild
                .peers
                .iter()
                .find(|peer| peer.member.node_id == guild.coordinator)
                .context("guild endpoint roster omits the coordinator")?;
            if guild.coordinator != local_id {
                add_peer_endpoints(&p2p, guild.coordinator, &coordinator.endpoints).await?;
            }
            let job = query_backup_job(
                node,
                &p2p,
                local_id,
                guild.coordinator,
                guild.guild_id,
                revision_id,
            )
            .await?;
            Ok(LocalResponse::BackupJob(job))
        }
        LocalRequest::Recover { target } => {
            let result = recover_from_dht(node, &p2p, &target).await?;
            Ok(LocalResponse::Recovered(result))
        }
        LocalRequest::SnapshotList => {
            blocking_node(node, |node| {
                node.list_snapshots().map(LocalResponse::Snapshots)
            })
            .await
        }
        LocalRequest::SnapshotRestore {
            revision_id,
            target,
        } => {
            blocking_node(node, move |node| {
                node.restore_snapshot(revision_id, &target)
                    .map(LocalResponse::SnapshotRestored)
            })
            .await
        }
    }
}

async fn query_backup_job(
    node: Arc<Mutex<Node>>,
    p2p: &P2pClient,
    local_id: NodeId,
    coordinator: NodeId,
    guild_id: [u8; 32],
    revision_id: Uuid,
) -> Result<BackupJob> {
    if coordinator == local_id {
        blocking_node(node, move |node| node.backup_job(guild_id, revision_id)).await
    } else {
        p2p.backup_status(coordinator, guild_id, revision_id).await
    }
}

async fn blocking_node<T, F>(node: Arc<Mutex<Node>>, operation: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut Node) -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut node = node
            .lock()
            .map_err(|_| anyhow::anyhow!("node state lock is poisoned"))?;
        operation(&mut node)
    })
    .await
    .context("local control worker failed")?
}

async fn local_endpoints(p2p: &P2pClient) -> Result<Vec<String>> {
    let status = p2p.status().await?;
    let peer_id: PeerId = status
        .peer_id
        .parse()
        .context("daemon has an invalid local libp2p peer ID")?;
    let mut endpoints = Vec::new();
    for value in status.advertised_addresses {
        let mut address: Multiaddr = value
            .parse()
            .with_context(|| format!("invalid local advertised address {value}"))?;
        if address.iter().any(|protocol| match protocol {
            Protocol::Ip4(address) => address.is_unspecified(),
            Protocol::Ip6(address) => address.is_unspecified(),
            _ => false,
        }) {
            continue;
        }
        match address.iter().last() {
            Some(Protocol::P2p(actual)) if actual == peer_id => {}
            Some(Protocol::P2p(_)) => {
                bail!("local advertised address contains another peer identity")
            }
            _ => address.push(Protocol::P2p(peer_id)),
        }
        endpoints.push(address.to_string());
    }
    endpoints.sort();
    endpoints.dedup();
    if endpoints.is_empty() {
        bail!("daemon has no usable advertised endpoint; configure a concrete --external-address");
    }
    Ok(endpoints)
}

async fn add_peer_endpoints(p2p: &P2pClient, peer: NodeId, endpoints: &[String]) -> Result<()> {
    for endpoint in endpoints {
        let address: Multiaddr = endpoint
            .parse()
            .with_context(|| format!("invalid peer endpoint {endpoint}"))?;
        p2p.add_peer_address(peer, address).await?;
    }
    Ok(())
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_LOCAL_FRAME_BYTES {
        bail!("local control frame exceeds size limit");
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_LOCAL_FRAME_BYTES {
        bail!("local control frame exceeds size limit");
    }
    let mut bytes = vec![0_u8; length];
    stream.read_exact(&mut bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

struct SocketCleanup {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_protocol_round_trips() {
        let request = LocalRequest::AddRoot {
            path: PathBuf::from("/var/lib/data"),
        };
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: LocalRequest = serde_json::from_slice(&bytes).unwrap();
        assert!(matches!(
            decoded,
            LocalRequest::AddRoot { path } if path == Path::new("/var/lib/data")
        ));
    }
}
