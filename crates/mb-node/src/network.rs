use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use mb_core::{
    CodingGroup, GuildCheckpoint, InformationRole, KeyMaterial, Member, MemberSignature, NodeId,
    ParityRole, QuorumCheckpoint, RecoveryLocator, SealedRecoveryRecord, SectorId, SectorRef, Seed,
    ShardRole, SignedRecord, UserRevision, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS, V1_SECTOR_SIZE,
    canonical_bytes, decode_canonical, encode_3_2, open_recovery_record, reconstruct_3_2,
    sector_root,
};
use mb_store::ParityObject;
use rand::RngCore;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{Node, RecoveredShards, restore_revision};

const MAX_PEER_FRAME_BYTES: usize = 8 * 1024 * 1024;
const MAX_DIRECTORY_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIRECTORY_RECORD_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_SUBJECTS: usize = 100_000;
const MAX_PUBLISHERS_PER_SUBJECT: usize = 64;
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
const PEER_REQUEST_DOMAIN: &[u8] = b"mutualbackup/direct-request/v2";
const PEER_RESPONSE_DOMAIN: &[u8] = b"mutualbackup/direct-response/v2";
const DIRECTORY_RECORD_DOMAIN: &[u8] = b"mutualbackup/directory-record/v1";

#[derive(Clone, Debug)]
pub struct NodeServerConfig {
    pub listen: SocketAddr,
    pub public_endpoint: String,
    pub failure_domain: String,
    pub trusted_coordinator: NodeId,
    pub max_connections: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PeerProfile {
    member: Member,
    endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerRequest {
    Profile,
    PrepareSource {
        guild_id: [u8; 32],
        source: String,
        sequence: u64,
    },
    EnsureFiller {
        guild_id: [u8; 32],
        revision_id: Uuid,
        ordinal: u64,
    },
    GetSector {
        guild_id: [u8; 32],
        sector_id: SectorId,
    },
    PublishParity {
        object: ParityObject,
    },
    GetParity {
        guild_id: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
    },
    SignCheckpoint {
        checkpoint: GuildCheckpoint,
    },
    StoreCheckpoint {
        checkpoint: QuorumCheckpoint,
    },
    GetCheckpoint {
        guild_id: [u8; 32],
        hash: [u8; 32],
    },
    BuildRecoveryRecord {
        subject: Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        expires_at_unix_seconds: u64,
    },
}

impl PeerRequest {
    fn mutation_kind(&self) -> Option<&'static str> {
        match self {
            Self::Profile
            | Self::GetSector { .. }
            | Self::GetParity { .. }
            | Self::GetCheckpoint { .. } => None,
            Self::PrepareSource { .. } => Some("prepare-source"),
            Self::EnsureFiller { .. } => Some("ensure-filler"),
            Self::PublishParity { .. } => Some("publish-parity"),
            Self::SignCheckpoint { .. } => Some("sign-checkpoint"),
            Self::StoreCheckpoint { .. } => Some("store-checkpoint"),
            Self::BuildRecoveryRecord { .. } => Some("build-recovery-record"),
        }
    }

    fn guild_scope(&self) -> Option<[u8; 32]> {
        match self {
            Self::Profile => None,
            Self::PrepareSource { guild_id, .. }
            | Self::EnsureFiller { guild_id, .. }
            | Self::GetSector { guild_id, .. }
            | Self::GetParity { guild_id, .. }
            | Self::GetCheckpoint { guild_id, .. }
            | Self::BuildRecoveryRecord { guild_id, .. } => Some(*guild_id),
            Self::PublishParity { object } => Some(object.guild_id),
            Self::SignCheckpoint { checkpoint } => Some(checkpoint.guild_id),
            Self::StoreCheckpoint { checkpoint } => Some(checkpoint.checkpoint.guild_id),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerRequestEnvelope {
    format_version: u16,
    request_id: [u8; 16],
    caller: NodeId,
    recipient: Option<NodeId>,
    guild_scope: Option<[u8; 32]>,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    request: PeerRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PeerResponse {
    Profile(PeerProfile),
    Prepared(SignedRecord<UserRevision>),
    Filler {
        reference: SectorRef,
        bytes: Vec<u8>,
    },
    Bytes(Vec<u8>),
    CheckpointSignature(MemberSignature),
    Checkpoint(QuorumCheckpoint),
    RecoveryRecord(SignedRecord<PublishedRecoveryRecord>),
    Ack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerResponseEnvelope {
    format_version: u16,
    request_id: [u8; 16],
    recipient: NodeId,
    request_hash: [u8; 32],
    result: std::result::Result<PeerResponse, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CachedOperation {
    request_hash: [u8; 32],
    response: PeerResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PublishedRecoveryRecord {
    format_version: u16,
    subject: NodeId,
    publisher: NodeId,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    checkpoint_generation: u64,
    expires_at_unix_seconds: u64,
    sealed: SealedRecoveryRecord,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DirectoryRequest {
    Publish(Box<SignedRecord<PublishedRecoveryRecord>>),
    Lookup { subject: NodeId },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum DirectoryResponse {
    Records(Vec<SignedRecord<PublishedRecoveryRecord>>),
    Ack,
    Error(String),
}

type PublisherRecords = BTreeMap<NodeId, SignedRecord<PublishedRecoveryRecord>>;
type RecoveryDirectoryRecords = BTreeMap<NodeId, PublisherRecords>;

#[derive(Clone, Default)]
pub struct DirectoryState {
    records: Arc<Mutex<RecoveryDirectoryRecords>>,
}

pub async fn serve_node(node: Arc<Mutex<Node>>, config: NodeServerConfig) -> Result<()> {
    if config.failure_domain.is_empty() || config.max_connections == 0 {
        bail!("invalid node server configuration");
    }
    validate_advertised_endpoint(&config.public_endpoint)?;
    let listener = TcpListener::bind(config.listen).await?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = permits.clone().acquire_owned().await?;
        let node = node.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_peer_connection(stream, node, config).await {
                tracing::warn!(%error, "peer request failed");
            }
        });
    }
}

pub async fn serve_directory(listen: SocketAddr, state: DirectoryState) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let permits = Arc::new(Semaphore::new(128));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let permit = permits.clone().acquire_owned().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let response = match read_frame_timed::<_, DirectoryRequest>(
                &mut stream,
                MAX_DIRECTORY_FRAME_BYTES,
            )
            .await
            {
                Ok(DirectoryRequest::Publish(record)) => {
                    let record = *record;
                    if record.verify(DIRECTORY_RECORD_DOMAIN).is_err()
                        || record.signer != record.value.publisher
                        || record.value.format_version != 1
                        || record.value.expires_at_unix_seconds != u64::MAX
                        || canonical_bytes(&record)
                            .map_or(true, |bytes| bytes.len() > MAX_DIRECTORY_RECORD_BYTES)
                    {
                        DirectoryResponse::Error("invalid publisher signature".to_owned())
                    } else {
                        match state.records.lock() {
                            Ok(mut records) => {
                                if !records.contains_key(&record.value.subject)
                                    && records.len() >= MAX_DIRECTORY_SUBJECTS
                                {
                                    DirectoryResponse::Error(
                                        "recovery directory subject limit reached".to_owned(),
                                    )
                                } else {
                                    let publishers =
                                        records.entry(record.value.subject).or_default();
                                    if !publishers.contains_key(&record.value.publisher)
                                        && publishers.len() >= MAX_PUBLISHERS_PER_SUBJECT
                                    {
                                        DirectoryResponse::Error(
                                            "recovery publisher limit reached".to_owned(),
                                        )
                                    } else {
                                        let accepted = match publishers.get(&record.value.publisher)
                                        {
                                            Some(current)
                                                if current.value.checkpoint_generation
                                                    > record.value.checkpoint_generation =>
                                            {
                                                false
                                            }
                                            Some(current)
                                                if current.value.checkpoint_generation
                                                    == record.value.checkpoint_generation
                                                    && current.value.checkpoint_hash
                                                        != record.value.checkpoint_hash =>
                                            {
                                                false
                                            }
                                            _ => true,
                                        };
                                        if accepted {
                                            publishers.insert(record.value.publisher, record);
                                            DirectoryResponse::Ack
                                        } else {
                                            DirectoryResponse::Error(
                                                "recovery record would roll back or fork publisher state"
                                                    .to_owned(),
                                            )
                                        }
                                    }
                                }
                            }
                            Err(_) => {
                                DirectoryResponse::Error("directory lock poisoned".to_owned())
                            }
                        }
                    }
                }
                Ok(DirectoryRequest::Lookup { subject }) => match state.records.lock() {
                    Ok(records) => DirectoryResponse::Records(
                        records
                            .get(&subject)
                            .map(|entries| entries.values().cloned().collect())
                            .unwrap_or_default(),
                    ),
                    Err(_) => DirectoryResponse::Error("directory lock poisoned".to_owned()),
                },
                Err(error) => DirectoryResponse::Error(error.to_string()),
            };
            if let Err(error) =
                write_frame_limited(&mut stream, &response, MAX_DIRECTORY_FRAME_BYTES).await
            {
                tracing::warn!(%error, "directory response failed");
            }
        });
    }
}

async fn handle_peer_connection(
    mut stream: TcpStream,
    node: Arc<Mutex<Node>>,
    config: NodeServerConfig,
) -> Result<()> {
    let signed =
        read_frame_timed::<_, SignedRecord<PeerRequestEnvelope>>(&mut stream, MAX_PEER_FRAME_BYTES)
            .await?;
    let signed_response =
        tokio::task::spawn_blocking(move || process_peer_request(node, &config, signed))
            .await
            .context("peer request worker panicked")??;
    write_frame_limited(&mut stream, &signed_response, MAX_PEER_FRAME_BYTES).await?;
    Ok(())
}

fn process_peer_request(
    node: Arc<Mutex<Node>>,
    config: &NodeServerConfig,
    signed: SignedRecord<PeerRequestEnvelope>,
) -> Result<SignedRecord<PeerResponseEnvelope>> {
    let request_id = signed.value.request_id;
    let caller = signed.signer;
    let wire_request_hash = *blake3::hash(&canonical_bytes(&signed.value)?).as_bytes();
    let operation_hash = peer_operation_hash(&signed.value)?;
    let mut node_guard = node.lock().map_err(lock_error)?;
    let response = (|| {
        signed.verify(PEER_REQUEST_DOMAIN)?;
        validate_request_envelope(&signed.value, caller, node_guard.keys().node_id())?;
        let request = signed.value.request;
        let mutation_kind = request.mutation_kind();
        let local_node_id = node_guard.keys().node_id();
        if mutation_kind.is_some() && caller != config.trusted_coordinator {
            bail!("caller is not the configured guild coordinator");
        }
        if matches!(&request, PeerRequest::PrepareSource { .. }) && caller != local_node_id {
            bail!("only the source node itself may request source capture");
        }
        if mutation_kind.is_none()
            && !matches!(&request, PeerRequest::Profile)
            && !(matches!(&request, PeerRequest::GetSector { .. })
                && caller == config.trusted_coordinator)
        {
            node_guard.authorize_member(
                &request
                    .guild_scope()
                    .context("guild-scoped request has no scope")?,
                caller,
            )?;
        }
        if let Some(kind) = mutation_kind {
            if let Some(cached_bytes) =
                node_guard.cached_operation(&request_id, kind, caller, &operation_hash)?
            {
                let cached: CachedOperation = decode_canonical(&cached_bytes)?;
                if cached.request_hash != operation_hash {
                    bail!("cached operation hash is inconsistent");
                }
                return Ok(cached.response);
            }
            let response = execute_peer_request(&mut node_guard, config, request_id, request)?;
            let cached = CachedOperation {
                request_hash: operation_hash,
                response: response.clone(),
            };
            node_guard.commit_operation(
                &request_id,
                kind,
                caller,
                &operation_hash,
                &canonical_bytes(&cached)?,
            )?;
            Ok(response)
        } else {
            execute_peer_request(&mut node_guard, config, request_id, request)
        }
    })();
    let error = response.map_err(|error| {
        let mut message = format!("{error:#}");
        message.truncate(4096);
        message
    });
    Ok(SignedRecord::sign(
        PEER_RESPONSE_DOMAIN,
        PeerResponseEnvelope {
            format_version: 1,
            request_id,
            recipient: caller,
            request_hash: wire_request_hash,
            result: error,
        },
        node_guard.keys(),
    )?)
}

fn validate_request_envelope(
    envelope: &PeerRequestEnvelope,
    signer: NodeId,
    local_node: NodeId,
) -> Result<()> {
    let now = unix_seconds();
    if envelope.format_version != 1
        || envelope.caller != signer
        || envelope.guild_scope != envelope.request.guild_scope()
        || envelope.expires_at_unix_seconds < envelope.issued_at_unix_seconds
        || envelope.expires_at_unix_seconds - envelope.issued_at_unix_seconds > 120
        || envelope.expires_at_unix_seconds < now
        || envelope.issued_at_unix_seconds > now.saturating_add(30)
    {
        bail!("invalid request protocol or freshness context");
    }
    match &envelope.request {
        PeerRequest::Profile if envelope.recipient.is_none() => {}
        PeerRequest::Profile => bail!("profile request must not claim a recipient"),
        _ if envelope.recipient == Some(local_node) => {}
        _ => bail!("request is not addressed to this node"),
    }
    if let PeerRequest::PrepareSource { ref source, .. } = envelope.request
        && source.len() > 4096
    {
        bail!("source path exceeds the protocol limit");
    }
    Ok(())
}

fn peer_operation_hash(envelope: &PeerRequestEnvelope) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&canonical_bytes(&(
        envelope.format_version,
        envelope.caller,
        envelope.recipient,
        envelope.guild_scope,
        &envelope.request,
    ))?)
    .as_bytes())
}

fn execute_peer_request(
    node: &mut Node,
    config: &NodeServerConfig,
    request_id: [u8; 16],
    request: PeerRequest,
) -> Result<PeerResponse> {
    match request {
        PeerRequest::Profile => Ok(PeerResponse::Profile(PeerProfile {
            member: node.member(config.failure_domain.clone()),
            endpoint: config.public_endpoint.clone(),
        })),
        PeerRequest::PrepareSource {
            guild_id,
            source,
            sequence,
        } => Ok(PeerResponse::Prepared(node.prepare_revision(
            guild_id,
            Path::new(&source),
            sequence,
            Some(request_id),
        )?)),
        PeerRequest::EnsureFiller {
            guild_id,
            revision_id,
            ordinal,
        } => {
            let (reference, bytes) = node.ensure_filler(guild_id, revision_id, ordinal)?;
            Ok(PeerResponse::Filler { reference, bytes })
        }
        PeerRequest::GetSector {
            guild_id,
            sector_id,
        } => Ok(PeerResponse::Bytes(
            node.sector_for_guild(&guild_id, &sector_id)?,
        )),
        PeerRequest::PublishParity { object } => {
            node.publish_parity(&object)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::GetParity {
            guild_id,
            group_id,
            shard_index,
        } => Ok(PeerResponse::Bytes(node.parity_for_guild(
            &guild_id,
            &group_id,
            shard_index,
        )?)),
        PeerRequest::SignCheckpoint { checkpoint } => Ok(PeerResponse::CheckpointSignature(
            node.sign_checkpoint(&checkpoint)?,
        )),
        PeerRequest::StoreCheckpoint { checkpoint } => {
            node.store_checkpoint(&checkpoint)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::GetCheckpoint { guild_id, hash } => {
            let checkpoint = node.checkpoint(&hash)?;
            if checkpoint.checkpoint.guild_id != guild_id {
                bail!("checkpoint does not belong to the requested guild");
            }
            Ok(PeerResponse::Checkpoint(checkpoint))
        }
        PeerRequest::BuildRecoveryRecord {
            subject,
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            expires_at_unix_seconds,
        } => {
            if expires_at_unix_seconds != u64::MAX {
                bail!("prototype recovery records must not expire");
            }
            let checkpoint = node.checkpoint(&checkpoint_hash)?;
            if checkpoint.checkpoint.guild_id != guild_id
                || checkpoint.checkpoint.generation != checkpoint_generation
                || !checkpoint
                    .checkpoint
                    .members
                    .iter()
                    .any(|member| member == &subject)
            {
                bail!("recovery locator does not match the stored checkpoint");
            }
            let sealed = node.recovery_record(
                &subject,
                guild_id,
                checkpoint_hash,
                checkpoint_generation,
                config.public_endpoint.clone(),
                expires_at_unix_seconds,
            )?;
            Ok(PeerResponse::RecoveryRecord(SignedRecord::sign(
                DIRECTORY_RECORD_DOMAIN,
                PublishedRecoveryRecord {
                    format_version: 1,
                    subject: subject.node_id,
                    publisher: node.keys().node_id(),
                    guild_id,
                    checkpoint_hash,
                    checkpoint_generation,
                    expires_at_unix_seconds,
                    sealed,
                },
                node.keys(),
            )?))
        }
    }
}

#[derive(Clone, Debug)]
struct RemotePeer {
    endpoint: SocketAddr,
    profile: PeerProfile,
}

#[derive(Clone, Debug)]
pub struct NetworkCommitResult {
    pub guild_id: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub owner: NodeId,
    pub coding_groups: usize,
}

pub async fn commit_source_over_network(
    coordinator_keys: &KeyMaterial,
    source: &Path,
    directory: SocketAddr,
    peer_endpoints: Vec<SocketAddr>,
) -> Result<NetworkCommitResult> {
    if peer_endpoints.len() != 5 {
        bail!("the first network profile requires exactly five peer endpoints");
    }
    let mut peers = Vec::new();
    for endpoint in peer_endpoints {
        let (signer, response) =
            peer_call(endpoint, coordinator_keys, PeerRequest::Profile).await?;
        let PeerResponse::Profile(profile) = response else {
            bail!("peer returned the wrong response to profile request");
        };
        if signer != profile.member.node_id {
            bail!("profile signer does not match its member identity");
        }
        peers.push(RemotePeer { endpoint, profile });
    }
    let mut unique_nodes = BTreeSet::new();
    let mut unique_domains = BTreeSet::new();
    if peers.iter().any(|peer| {
        !unique_nodes.insert(peer.profile.member.node_id)
            || !unique_domains.insert(peer.profile.member.failure_domain.clone())
    }) {
        bail!("peer identities and physical failure domains must be unique");
    }
    for peer in &peers {
        let advertised = validate_advertised_endpoint(&peer.profile.endpoint)?;
        let (signer, response) =
            peer_call(advertised, coordinator_keys, PeerRequest::Profile).await?;
        let PeerResponse::Profile(advertised_profile) = response else {
            bail!("advertised peer returned the wrong profile response");
        };
        if signer != peer.profile.member.node_id
            || advertised_profile.member.node_id != peer.profile.member.node_id
        {
            bail!("advertised endpoint does not authenticate as the expected node");
        }
    }
    let owner_position = peers
        .iter()
        .position(|peer| peer.profile.member.node_id == coordinator_keys.node_id())
        .context("coordinator identity is not one of the five peers")?;
    peers.swap(0, owner_position);
    peers[1..].sort_by_key(|peer| peer.profile.member.node_id);

    let mut guild_id = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut guild_id);
    let source = source
        .to_str()
        .context("source path is not valid UTF-8")?
        .to_owned();
    let prepared = peer_call_expected(
        peers[0].endpoint,
        peers[0].profile.member.node_id,
        coordinator_keys,
        PeerRequest::PrepareSource {
            guild_id,
            source,
            sequence: 1,
        },
    )
    .await?;
    let PeerResponse::Prepared(revision) = prepared else {
        bail!("owner returned the wrong response to source preparation");
    };
    revision.verify(b"mutualbackup/user-revision/v1")?;
    if revision.value.owner != coordinator_keys.node_id() {
        bail!("prepared revision owner does not match coordinator");
    }

    let mut target_sectors = revision.value.metadata_sectors.clone();
    target_sectors.extend(revision.value.data_sectors.clone());
    let mut groups = Vec::with_capacity(target_sectors.len());
    for (ordinal, target_reference) in target_sectors.iter().enumerate() {
        let owner_response = peer_call_expected(
            peers[0].endpoint,
            peers[0].profile.member.node_id,
            coordinator_keys,
            PeerRequest::GetSector {
                guild_id,
                sector_id: target_reference.id,
            },
        )
        .await?;
        let PeerResponse::Bytes(owner_bytes) = owner_response else {
            bail!("owner returned the wrong sector response");
        };
        if sector_root(&owner_bytes) != target_reference.root {
            bail!("owner sector failed its committed root");
        }
        let helper_a = request_filler(
            &peers[1],
            coordinator_keys,
            guild_id,
            revision.value.revision_id,
            ordinal as u64 * 2,
        )
        .await?;
        let helper_b = request_filler(
            &peers[2],
            coordinator_keys,
            guild_id,
            revision.value.revision_id,
            ordinal as u64 * 2 + 1,
        )
        .await?;
        let shards = encode_3_2([owner_bytes, helper_a.1, helper_b.1])?;
        let roles = [
            ShardRole::Information(InformationRole {
                owner: peers[0].profile.member.node_id,
                sector: target_reference.clone(),
            }),
            ShardRole::Information(InformationRole {
                owner: peers[1].profile.member.node_id,
                sector: helper_a.0,
            }),
            ShardRole::Information(InformationRole {
                owner: peers[2].profile.member.node_id,
                sector: helper_b.0,
            }),
            ShardRole::Parity(ParityRole {
                holder: peers[3].profile.member.node_id,
                row: 0,
                root: sector_root(&shards[3]),
            }),
            ShardRole::Parity(ParityRole {
                holder: peers[4].profile.member.node_id,
                row: 1,
                root: sector_root(&shards[4]),
            }),
        ];
        let mut group = CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id,
            data_shards: V1_RS_DATA_SHARDS,
            parity_shards: V1_RS_PARITY_SHARDS,
            shard_size: V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id()?;
        let group_id = group.id;
        let parity_a = ParityObject {
            format_version: 1,
            guild_id,
            group_id,
            shard_index: 3,
            root: sector_root(&shards[3]),
            bytes: shards[3].clone(),
        };
        let parity_b = ParityObject {
            format_version: 1,
            guild_id,
            group_id,
            shard_index: 4,
            root: sector_root(&shards[4]),
            bytes: shards[4].clone(),
        };
        expect_ack(
            peer_call_expected(
                peers[3].endpoint,
                peers[3].profile.member.node_id,
                coordinator_keys,
                PeerRequest::PublishParity {
                    object: parity_a.clone(),
                },
            )
            .await?,
        )?;
        expect_ack(
            peer_call_expected(
                peers[4].endpoint,
                peers[4].profile.member.node_id,
                coordinator_keys,
                PeerRequest::PublishParity {
                    object: parity_b.clone(),
                },
            )
            .await?,
        )?;
        groups.push(group);
    }

    groups.sort_by_key(|group| group.id);
    let mut checkpoint_members = peers
        .iter()
        .map(|peer| peer.profile.member.clone())
        .collect::<Vec<_>>();
    checkpoint_members.sort_by_key(|member| member.node_id);

    let checkpoint_body = GuildCheckpoint {
        format_version: 1,
        guild_id,
        generation: 1,
        parent: None,
        members: checkpoint_members,
        revisions: vec![revision],
        coding_groups: groups,
    };
    checkpoint_body.validate()?;
    let mut signatures = Vec::new();
    for peer in &peers {
        let response = peer_call_expected(
            peer.endpoint,
            peer.profile.member.node_id,
            coordinator_keys,
            PeerRequest::SignCheckpoint {
                checkpoint: checkpoint_body.clone(),
            },
        )
        .await?;
        let PeerResponse::CheckpointSignature(signature) = response else {
            bail!("peer returned the wrong checkpoint-signature response");
        };
        signatures.push(signature);
    }
    signatures.sort_by_key(|signature| signature.signer);
    let checkpoint = QuorumCheckpoint {
        checkpoint: checkpoint_body,
        signatures,
    };
    checkpoint.verify()?;
    let checkpoint_hash = checkpoint.hash()?;
    for peer in &peers {
        expect_ack(
            peer_call_expected(
                peer.endpoint,
                peer.profile.member.node_id,
                coordinator_keys,
                PeerRequest::StoreCheckpoint {
                    checkpoint: checkpoint.clone(),
                },
            )
            .await?,
        )?;
    }

    for subject in &checkpoint.checkpoint.members {
        for peer in &peers {
            if peer.profile.member.node_id == subject.node_id {
                continue;
            }
            let response = peer_call_expected(
                peer.endpoint,
                peer.profile.member.node_id,
                coordinator_keys,
                PeerRequest::BuildRecoveryRecord {
                    subject: subject.clone(),
                    guild_id,
                    checkpoint_hash,
                    checkpoint_generation: checkpoint.checkpoint.generation,
                    expires_at_unix_seconds: u64::MAX,
                },
            )
            .await?;
            let PeerResponse::RecoveryRecord(record) = response else {
                bail!("peer returned the wrong recovery-record response");
            };
            directory_publish(directory, record).await?;
        }
    }
    Ok(NetworkCommitResult {
        guild_id,
        checkpoint_hash,
        owner: peers[0].profile.member.node_id,
        coding_groups: checkpoint.checkpoint.coding_groups.len(),
    })
}

pub async fn recover_over_network(
    seed: Seed,
    data_dir: &Path,
    restore_target: &Path,
    directory: SocketAddr,
) -> Result<Node> {
    let mut recovered_node = Node::open(data_dir, seed)?;
    let local_node_id = recovered_node.keys().node_id();
    let sealed_records = directory_lookup(directory, local_node_id).await?;
    let mut candidates = Vec::new();
    for published in sealed_records {
        if published.verify(DIRECTORY_RECORD_DOMAIN).is_err()
            || published.signer != published.value.publisher
            || published.value.subject != local_node_id
            || published.value.format_version != 1
            || published.value.expires_at_unix_seconds != u64::MAX
        {
            continue;
        }
        let plaintext = match open_recovery_record(recovered_node.keys(), &published.value.sealed) {
            Ok(plaintext) => plaintext,
            Err(_) => continue,
        };
        let signed: SignedRecord<RecoveryLocator> = match decode_canonical(&plaintext) {
            Ok(signed) => signed,
            Err(_) => continue,
        };
        if signed.verify(b"mutualbackup/recovery-locator/v1").is_err()
            || signed.signer != signed.value.publisher
            || signed.value.subject != local_node_id
            || signed.value.format_version != 1
            || signed.value.expires_at_unix_seconds != u64::MAX
            || signed.value.publisher != published.value.publisher
            || signed.value.guild_id != published.value.guild_id
            || signed.value.checkpoint_hash != published.value.checkpoint_hash
            || signed.value.checkpoint_generation != published.value.checkpoint_generation
            || signed.value.expires_at_unix_seconds != published.value.expires_at_unix_seconds
        {
            continue;
        }
        let Some(endpoint) = signed
            .value
            .endpoints
            .iter()
            .find_map(|endpoint| parse_tcp_endpoint(endpoint).ok())
        else {
            continue;
        };
        let response = match peer_call_expected(
            endpoint,
            signed.value.publisher,
            recovered_node.keys(),
            PeerRequest::GetCheckpoint {
                guild_id: signed.value.guild_id,
                hash: signed.value.checkpoint_hash,
            },
        )
        .await
        {
            Ok(PeerResponse::Checkpoint(checkpoint)) => checkpoint,
            _ => continue,
        };
        if response
            .validate_recovery_authority(
                recovered_node.keys(),
                &signed.value,
                published.value.publisher,
            )
            .is_err()
        {
            continue;
        }
        candidates.push((response, signed.value.publisher, endpoint));
    }
    let checkpoint = candidates
        .iter()
        .map(|(checkpoint, _, _)| checkpoint)
        .max_by_key(|candidate| candidate.checkpoint.generation)
        .cloned()
        .context("no reachable recovery locator led to a valid quorum checkpoint")?;
    let checkpoint_hash = checkpoint.hash()?;
    let peer_endpoints = candidates
        .into_iter()
        .filter(|(candidate, _, _)| candidate.hash().ok() == Some(checkpoint_hash))
        .map(|(_, publisher, endpoint)| (publisher, endpoint))
        .collect::<BTreeMap<_, _>>();
    let recovered_shards = recover_network_local_shards(
        local_node_id,
        recovered_node.keys(),
        &checkpoint,
        &peer_endpoints,
    )
    .await?;
    recovered_node.install_recovered_checkpoint(&checkpoint, &recovered_shards)?;
    let revision = checkpoint
        .checkpoint
        .revisions
        .iter()
        .filter(|revision| revision.value.owner == local_node_id)
        .max_by_key(|revision| revision.value.sequence);
    if let Some(revision) = revision {
        let ciphertexts = local_revision_ciphertexts(revision, &checkpoint, &recovered_shards)?;
        restore_revision(
            recovered_node.keys(),
            checkpoint.checkpoint.guild_id,
            revision,
            &ciphertexts,
            restore_target,
        )?;
    }
    Ok(recovered_node)
}

async fn recover_network_local_shards(
    recovering: NodeId,
    keys: &KeyMaterial,
    checkpoint: &QuorumCheckpoint,
    peer_endpoints: &BTreeMap<NodeId, SocketAddr>,
) -> Result<RecoveredShards> {
    let mut recovered = BTreeMap::new();
    let mut unhealthy = BTreeSet::new();
    for group in &checkpoint.checkpoint.coding_groups {
        let target = group
            .roles
            .iter()
            .enumerate()
            .find_map(|(index, role)| match role {
                ShardRole::Information(information) if information.owner == recovering => {
                    Some((index, information.sector.root))
                }
                ShardRole::Parity(parity) if parity.holder == recovering => {
                    Some((index, parity.root))
                }
                _ => None,
            });
        let Some((target_index, target_root)) = target else {
            continue;
        };
        let mut shards = vec![None; 5];
        let mut attempts = FuturesUnordered::new();
        for (index, role) in group.roles.iter().enumerate() {
            if index == target_index {
                continue;
            }
            let (holder, root, request) = match role {
                ShardRole::Information(information) => (
                    information.owner,
                    information.sector.root,
                    PeerRequest::GetSector {
                        guild_id: checkpoint.checkpoint.guild_id,
                        sector_id: information.sector.id,
                    },
                ),
                ShardRole::Parity(parity) => (
                    parity.holder,
                    parity.root,
                    PeerRequest::GetParity {
                        guild_id: checkpoint.checkpoint.guild_id,
                        group_id: group.id,
                        shard_index: index as u8,
                    },
                ),
            };
            let Some(endpoint) = peer_endpoints.get(&holder) else {
                continue;
            };
            if unhealthy.contains(&holder) {
                continue;
            }
            attempts.push(async move {
                (
                    holder,
                    index,
                    root,
                    peer_call_expected(*endpoint, holder, keys, request).await,
                )
            });
        }
        while let Some((holder, index, root, response)) = attempts.next().await {
            match response {
                Ok(PeerResponse::Bytes(bytes))
                    if bytes.len() == group.shard_size as usize && sector_root(&bytes) == root =>
                {
                    shards[index] = Some(bytes);
                }
                _ => {
                    unhealthy.insert(holder);
                }
            }
            if shards.iter().filter(|shard| shard.is_some()).count() == 3 {
                break;
            }
        }
        if shards.iter().filter(|shard| shard.is_some()).count() < 3 {
            bail!("coding group has fewer than three valid reachable shards");
        }
        reconstruct_3_2(&mut shards)?;
        let bytes = shards[target_index]
            .take()
            .context("local shard was not reconstructed")?;
        if sector_root(&bytes) != target_root {
            bail!("reconstructed local shard failed its signed root");
        }
        recovered.insert((group.id, target_index as u8), bytes);
    }
    Ok(recovered)
}

fn local_revision_ciphertexts(
    revision: &SignedRecord<UserRevision>,
    checkpoint: &QuorumCheckpoint,
    recovered_shards: &RecoveredShards,
) -> Result<BTreeMap<SectorId, Vec<u8>>> {
    let wanted = revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .map(|reference| reference.id)
        .collect::<BTreeSet<_>>();
    let mut ciphertexts = BTreeMap::new();
    for group in &checkpoint.checkpoint.coding_groups {
        for (index, role) in group.roles.iter().enumerate() {
            if let ShardRole::Information(information) = role
                && wanted.contains(&information.sector.id)
            {
                let bytes = recovered_shards
                    .get(&(group.id, index as u8))
                    .context("missing recovered revision shard")?;
                ciphertexts.insert(information.sector.id, bytes.clone());
            }
        }
    }
    if ciphertexts.len() != wanted.len() {
        bail!("not all revision sectors were recovered");
    }
    Ok(ciphertexts)
}

async fn request_filler(
    peer: &RemotePeer,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision_id: Uuid,
    ordinal: u64,
) -> Result<(SectorRef, Vec<u8>)> {
    let response = peer_call_expected(
        peer.endpoint,
        peer.profile.member.node_id,
        keys,
        PeerRequest::EnsureFiller {
            guild_id,
            revision_id,
            ordinal,
        },
    )
    .await?;
    let PeerResponse::Filler { reference, bytes } = response else {
        bail!("peer returned the wrong filler response");
    };
    if bytes.len() != V1_SECTOR_SIZE || sector_root(&bytes) != reference.root {
        bail!("helper filler failed its root");
    }
    Ok((reference, bytes))
}

async fn peer_call(
    endpoint: SocketAddr,
    keys: &KeyMaterial,
    request: PeerRequest,
) -> Result<(NodeId, PeerResponse)> {
    let signed_request = make_peer_request(keys, None, request)?;
    send_peer_request(endpoint, keys, &signed_request).await
}

fn make_peer_request(
    keys: &KeyMaterial,
    recipient: Option<NodeId>,
    request: PeerRequest,
) -> Result<SignedRecord<PeerRequestEnvelope>> {
    let issued_at_unix_seconds = unix_seconds();
    let guild_scope = request.guild_scope();
    let request_id = if request.mutation_kind().is_some() {
        let bytes = canonical_bytes(&(1_u16, keys.node_id(), recipient, guild_scope, &request))?;
        let mut id = [0_u8; 16];
        id.copy_from_slice(&blake3::hash(&bytes).as_bytes()[..16]);
        id
    } else {
        *Uuid::new_v4().as_bytes()
    };
    Ok(SignedRecord::sign(
        PEER_REQUEST_DOMAIN,
        PeerRequestEnvelope {
            format_version: 1,
            request_id,
            caller: keys.node_id(),
            recipient,
            guild_scope,
            issued_at_unix_seconds,
            expires_at_unix_seconds: issued_at_unix_seconds.saturating_add(60),
            request,
        },
        keys,
    )?)
}

async fn send_peer_request(
    endpoint: SocketAddr,
    keys: &KeyMaterial,
    signed_request: &SignedRecord<PeerRequestEnvelope>,
) -> Result<(NodeId, PeerResponse)> {
    let request_hash = *blake3::hash(&canonical_bytes(&signed_request.value)?).as_bytes();
    let request_id = signed_request.value.request_id;
    let call = async {
        let mut stream = TcpStream::connect(endpoint).await?;
        write_frame_limited(&mut stream, signed_request, MAX_PEER_FRAME_BYTES).await?;
        let response: SignedRecord<PeerResponseEnvelope> =
            read_frame_timed(&mut stream, MAX_PEER_FRAME_BYTES).await?;
        response.verify(PEER_RESPONSE_DOMAIN)?;
        if response.value.format_version != 1
            || response.value.request_id != request_id
            || response.value.recipient != keys.node_id()
            || response.value.request_hash != request_hash
        {
            bail!("peer response context mismatch");
        }
        let body = response.value.result.map_err(anyhow::Error::msg)?;
        Ok((response.signer, body))
    };
    tokio::time::timeout(Duration::from_secs(5), call)
        .await
        .context("peer request timed out")?
}

async fn peer_call_expected(
    endpoint: SocketAddr,
    expected_signer: NodeId,
    keys: &KeyMaterial,
    request: PeerRequest,
) -> Result<PeerResponse> {
    let signed_request = make_peer_request(keys, Some(expected_signer), request)?;
    let mut last_error = None;
    for _ in 0..2 {
        match send_peer_request(endpoint, keys, &signed_request).await {
            Ok((signer, response)) if signer == expected_signer => return Ok(response),
            Ok(_) => last_error = Some(anyhow::anyhow!("unexpected peer response identity")),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.context("peer request was not attempted")?)
}

fn expect_ack(response: PeerResponse) -> Result<()> {
    if matches!(response, PeerResponse::Ack) {
        Ok(())
    } else {
        bail!("peer returned the wrong acknowledgement response")
    }
}

async fn directory_publish(
    endpoint: SocketAddr,
    record: SignedRecord<PublishedRecoveryRecord>,
) -> Result<()> {
    match directory_call(endpoint, DirectoryRequest::Publish(Box::new(record))).await? {
        DirectoryResponse::Ack => Ok(()),
        DirectoryResponse::Error(error) => bail!(error),
        DirectoryResponse::Records(_) => bail!("directory returned records to publish request"),
    }
}

async fn directory_lookup(
    endpoint: SocketAddr,
    subject: NodeId,
) -> Result<Vec<SignedRecord<PublishedRecoveryRecord>>> {
    match directory_call(endpoint, DirectoryRequest::Lookup { subject }).await? {
        DirectoryResponse::Records(records) => Ok(records),
        DirectoryResponse::Error(error) => bail!(error),
        DirectoryResponse::Ack => bail!("directory returned acknowledgement to lookup request"),
    }
}

async fn directory_call(
    endpoint: SocketAddr,
    request: DirectoryRequest,
) -> Result<DirectoryResponse> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(endpoint).await?;
        write_frame_limited(&mut stream, &request, MAX_DIRECTORY_FRAME_BYTES).await?;
        read_frame_timed(&mut stream, MAX_DIRECTORY_FRAME_BYTES).await
    })
    .await
    .context("directory request timed out")?
}

async fn write_frame_limited<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<()> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > limit {
        bail!("outgoing protocol frame exceeds the fixed limit");
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame_timed<R: AsyncRead + Unpin, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
) -> Result<T> {
    let length = tokio::time::timeout(HEADER_TIMEOUT, reader.read_u32())
        .await
        .context("protocol frame header timed out")?? as usize;
    if length == 0 || length > limit {
        bail!("incoming protocol frame has an invalid length");
    }
    let mut bytes = vec![0_u8; length];
    tokio::time::timeout(BODY_TIMEOUT, reader.read_exact(&mut bytes))
        .await
        .context("protocol frame body timed out")??;
    Ok(decode_canonical(&bytes)?)
}

fn parse_tcp_endpoint(endpoint: &str) -> Result<SocketAddr> {
    endpoint
        .strip_prefix("tcp://")
        .context("endpoint is not a direct TCP endpoint")?
        .parse()
        .context("invalid direct TCP endpoint")
}

fn validate_advertised_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let address = parse_tcp_endpoint(endpoint)?;
    if address.port() == 0 || address.ip().is_unspecified() || address.ip().is_multicast() {
        bail!("advertised endpoint is not remotely usable");
    }
    Ok(address)
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("node state lock was poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn free_address() -> SocketAddr {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    }

    async fn wait_until_listening(address: SocketAddr) {
        for _ in 0..100 {
            if TcpStream::connect(address).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("server did not start listening");
    }

    #[test]
    fn endpoint_parser_is_strict() {
        assert_eq!(
            parse_tcp_endpoint("tcp://127.0.0.1:1234").unwrap(),
            "127.0.0.1:1234".parse().unwrap()
        );
        assert!(parse_tcp_endpoint("http://127.0.0.1:1234").is_err());
        assert!(validate_advertised_endpoint("tcp://0.0.0.0:1234").is_err());
        assert!(validate_advertised_endpoint("tcp://127.0.0.1:0").is_err());
    }

    #[test]
    fn signed_request_context_is_destination_bound_and_fresh() {
        let caller = KeyMaterial::from_seed(&Seed::from_bytes([51; 32]));
        let recipient = KeyMaterial::from_seed(&Seed::from_bytes([52; 32])).node_id();
        let guild_id = [7; 32];
        let request = PeerRequest::EnsureFiller {
            guild_id,
            revision_id: Uuid::from_bytes([8; 16]),
            ordinal: 9,
        };
        let first = make_peer_request(&caller, Some(recipient), request.clone()).unwrap();
        let second = make_peer_request(&caller, Some(recipient), request).unwrap();
        assert_eq!(first.value.request_id, second.value.request_id);
        validate_request_envelope(&first.value, caller.node_id(), recipient).unwrap();
        assert!(
            validate_request_envelope(
                &first.value,
                caller.node_id(),
                KeyMaterial::from_seed(&Seed::from_bytes([53; 32])).node_id(),
            )
            .is_err()
        );
        let mut stale = first.value;
        stale.issued_at_unix_seconds = 1;
        stale.expires_at_unix_seconds = 2;
        assert!(validate_request_envelope(&stale, caller.node_id(), recipient).is_err());
    }

    #[tokio::test]
    async fn directory_rejects_signed_rollback() {
        let address = free_address();
        let task = tokio::spawn(serve_directory(address, DirectoryState::default()));
        wait_until_listening(address).await;
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([61; 32]));
        let subject = KeyMaterial::from_seed(&Seed::from_bytes([62; 32])).node_id();
        let record = |generation, hash| {
            SignedRecord::sign(
                DIRECTORY_RECORD_DOMAIN,
                PublishedRecoveryRecord {
                    format_version: 1,
                    subject,
                    publisher: keys.node_id(),
                    guild_id: [4; 32],
                    checkpoint_hash: hash,
                    checkpoint_generation: generation,
                    expires_at_unix_seconds: u64::MAX,
                    sealed: SealedRecoveryRecord {
                        format_version: 1,
                        ephemeral_public_key: [5; 32],
                        nonce: [6; 24],
                        ciphertext: vec![7; 32],
                    },
                },
                &keys,
            )
            .unwrap()
        };
        directory_publish(address, record(2, [2; 32]))
            .await
            .unwrap();
        assert!(
            directory_publish(address, record(1, [1; 32]))
                .await
                .is_err()
        );
        assert!(
            directory_publish(address, record(2, [3; 32]))
                .await
                .is_err()
        );
        let records = directory_lookup(address, subject).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value.checkpoint_generation, 2);
        assert_eq!(records[0].value.checkpoint_hash, [2; 32]);
        task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn signed_network_commit_and_seed_recovery() {
        let Some(test_root) = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") else {
            eprintln!("skipped: MUTUALBACKUP_REFLINK_TEST_ROOT is not set");
            return;
        };
        let root = PathBuf::from(test_root).join(format!("network-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), vec![0x5a; 150_000]).unwrap();

        let coordinator_seed = Seed::from_bytes([100; 32]);
        let coordinator_keys = KeyMaterial::from_seed(&coordinator_seed);
        let directory_address = free_address();
        let directory_task = tokio::spawn(serve_directory(
            directory_address,
            DirectoryState::default(),
        ));
        wait_until_listening(directory_address).await;

        let mut peer_addresses = Vec::new();
        let mut peer_tasks = Vec::new();
        for index in 0_u8..5 {
            let address = free_address();
            let node = Node::open(
                root.join(format!("node-{index}")),
                Seed::from_bytes([100 + index; 32]),
            )
            .unwrap();
            let task = tokio::spawn(serve_node(
                Arc::new(Mutex::new(node)),
                NodeServerConfig {
                    listen: address,
                    public_endpoint: format!("tcp://{address}"),
                    failure_domain: format!("host-{index}"),
                    trusted_coordinator: coordinator_keys.node_id(),
                    max_connections: 8,
                },
            ));
            wait_until_listening(address).await;
            peer_addresses.push(address);
            peer_tasks.push(task);
        }

        commit_source_over_network(
            &coordinator_keys,
            &source,
            directory_address,
            peer_addresses,
        )
        .await
        .unwrap();
        peer_tasks.remove(0).abort();
        tokio::task::yield_now().await;
        fs::remove_dir_all(root.join("node-0")).unwrap();
        fs::remove_dir_all(&source).unwrap();

        let restored = root.join("restored");
        let recovered = recover_over_network(
            Seed::from_bytes([100; 32]),
            &root.join("recovered-node"),
            &restored,
            directory_address,
        )
        .await
        .unwrap();
        assert_eq!(recovered.keys().node_id(), coordinator_keys.node_id());
        assert_eq!(
            fs::read(restored.join("payload")).unwrap(),
            vec![0x5a; 150_000]
        );

        for task in peer_tasks {
            task.abort();
        }
        directory_task.abort();
        drop(recovered);
        fs::remove_dir_all(&root).unwrap();
    }
}
