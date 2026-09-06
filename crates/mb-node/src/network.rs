use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

use crate::{Node, restore_revision};

const MAX_FRAME_BYTES: usize = 32 * 1024 * 1024;
const PEER_REQUEST_DOMAIN: &[u8] = b"mutualbackup/direct-request/v1";
const PEER_RESPONSE_DOMAIN: &[u8] = b"mutualbackup/direct-response/v1";
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
        sector_id: SectorId,
    },
    PublishParity {
        object: ParityObject,
    },
    GetParity {
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PeerRequestEnvelope {
    request_id: [u8; 16],
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
    request_id: [u8; 16],
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
    Publish(SignedRecord<PublishedRecoveryRecord>),
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
            let response = match read_frame::<_, DirectoryRequest>(&mut stream).await {
                Ok(DirectoryRequest::Publish(record)) => {
                    if record.verify(DIRECTORY_RECORD_DOMAIN).is_err()
                        || record.signer != record.value.publisher
                        || record.value.format_version != 1
                        || record.value.expires_at_unix_seconds != u64::MAX
                    {
                        DirectoryResponse::Error("invalid publisher signature".to_owned())
                    } else {
                        match state.records.lock() {
                            Ok(mut records) => {
                                let publishers = records.entry(record.value.subject).or_default();
                                let accepted = match publishers.get(&record.value.publisher) {
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
            let _ = write_frame(&mut stream, &response).await;
        });
    }
}

async fn handle_peer_connection(
    mut stream: TcpStream,
    node: Arc<Mutex<Node>>,
    config: NodeServerConfig,
) -> Result<()> {
    let signed = read_frame::<_, SignedRecord<PeerRequestEnvelope>>(&mut stream).await?;
    let request_id = signed.value.request_id;
    let result = tokio::task::spawn_blocking(move || process_peer_request(node, &config, signed))
        .await
        .context("peer request worker panicked")?;
    let signed_response = {
        let node = result.node.lock().map_err(lock_error)?;
        SignedRecord::sign(
            PEER_RESPONSE_DOMAIN,
            PeerResponseEnvelope {
                request_id,
                result: result.response.map_err(|error| format!("{error:#}")),
            },
            node.keys(),
        )?
    };
    write_frame(&mut stream, &signed_response).await?;
    Ok(())
}

struct ProcessedRequest {
    node: Arc<Mutex<Node>>,
    response: Result<PeerResponse>,
}

fn process_peer_request(
    node: Arc<Mutex<Node>>,
    config: &NodeServerConfig,
    signed: SignedRecord<PeerRequestEnvelope>,
) -> ProcessedRequest {
    let response = (|| {
        signed.verify(PEER_REQUEST_DOMAIN)?;
        let caller = signed.signer;
        let request_id = signed.value.request_id;
        let request = signed.value.request;
        let request_bytes = canonical_bytes(&request)?;
        let request_hash = *blake3::hash(&request_bytes).as_bytes();
        let mutation_kind = request.mutation_kind();
        let mut node_guard = node.lock().map_err(lock_error)?;
        let local_node_id = node_guard.keys().node_id();
        if mutation_kind.is_some() && caller != config.trusted_coordinator {
            bail!("caller is not the configured guild coordinator");
        }
        if matches!(&request, PeerRequest::PrepareSource { .. }) && caller != local_node_id {
            bail!("only the source node itself may request source capture");
        }
        if let Some(kind) = mutation_kind {
            if let Some(cached_bytes) =
                node_guard.cached_operation(&request_id, kind, caller, &request_hash)?
            {
                let cached: CachedOperation = decode_canonical(&cached_bytes)?;
                return Ok(cached.response);
            }
            let response = execute_peer_request(&mut node_guard, config, request)?;
            let cached = CachedOperation {
                request_hash,
                response: response.clone(),
            };
            node_guard.commit_operation(
                &request_id,
                kind,
                caller,
                &request_hash,
                &canonical_bytes(&cached)?,
            )?;
            Ok(response)
        } else {
            execute_peer_request(&mut node_guard, config, request)
        }
    })();
    ProcessedRequest { node, response }
}

fn execute_peer_request(
    node: &mut Node,
    config: &NodeServerConfig,
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
        )?)),
        PeerRequest::EnsureFiller {
            guild_id,
            revision_id,
            ordinal,
        } => {
            let (reference, bytes) = node.ensure_filler(guild_id, revision_id, ordinal)?;
            Ok(PeerResponse::Filler { reference, bytes })
        }
        PeerRequest::GetSector { sector_id } => Ok(PeerResponse::Bytes(node.sector(&sector_id)?)),
        PeerRequest::PublishParity { object } => {
            node.publish_parity(&object)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::GetParity {
            group_id,
            shard_index,
        } => Ok(PeerResponse::Bytes(node.parity(&group_id, shard_index)?)),
        PeerRequest::SignCheckpoint { checkpoint } => Ok(PeerResponse::CheckpointSignature(
            node.sign_checkpoint(&checkpoint)?,
        )),
        PeerRequest::StoreCheckpoint { checkpoint } => {
            node.store_checkpoint(&checkpoint)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::GetCheckpoint { hash } => {
            Ok(PeerResponse::Checkpoint(node.checkpoint(&hash)?))
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
) -> Result<BTreeMap<([u8; 32], u8), Vec<u8>>> {
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
                        sector_id: information.sector.id,
                    },
                ),
                ShardRole::Parity(parity) => (
                    parity.holder,
                    parity.root,
                    PeerRequest::GetParity {
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
    recovered_shards: &BTreeMap<([u8; 32], u8), Vec<u8>>,
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
    let request_id = *Uuid::new_v4().as_bytes();
    let signed_request = SignedRecord::sign(
        PEER_REQUEST_DOMAIN,
        PeerRequestEnvelope {
            request_id,
            request,
        },
        keys,
    )?;
    let call = async {
        let mut stream = TcpStream::connect(endpoint).await?;
        write_frame(&mut stream, &signed_request).await?;
        let response: SignedRecord<PeerResponseEnvelope> = read_frame(&mut stream).await?;
        response.verify(PEER_RESPONSE_DOMAIN)?;
        if response.value.request_id != request_id {
            bail!("peer response request ID mismatch");
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
    let (signer, response) = peer_call(endpoint, keys, request).await?;
    if signer != expected_signer {
        bail!("peer response was signed by an unexpected identity");
    }
    Ok(response)
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
    match directory_call(endpoint, DirectoryRequest::Publish(record)).await? {
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
        write_frame(&mut stream, &request).await?;
        read_frame(&mut stream).await
    })
    .await
    .context("directory request timed out")?
}

async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(writer: &mut W, value: &T) -> Result<()> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("outgoing protocol frame exceeds the fixed limit");
    }
    writer.write_u32(bytes.len() as u32).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin, T: DeserializeOwned>(reader: &mut R) -> Result<T> {
    let length = reader.read_u32().await? as usize;
    if length == 0 || length > MAX_FRAME_BYTES {
        bail!("incoming protocol frame has an invalid length");
    }
    let mut bytes = vec![0_u8; length];
    reader.read_exact(&mut bytes).await?;
    Ok(decode_canonical(&bytes)?)
}

fn parse_tcp_endpoint(endpoint: &str) -> Result<SocketAddr> {
    endpoint
        .strip_prefix("tcp://")
        .context("endpoint is not a direct TCP endpoint")?
        .parse()
        .context("invalid direct TCP endpoint")
}

fn lock_error<T>(_: std::sync::PoisonError<T>) -> anyhow::Error {
    anyhow::anyhow!("node state lock was poisoned")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_parser_is_strict() {
        assert_eq!(
            parse_tcp_endpoint("tcp://127.0.0.1:1234").unwrap(),
            "127.0.0.1:1234".parse().unwrap()
        );
        assert!(parse_tcp_endpoint("http://127.0.0.1:1234").is_err());
    }
}
