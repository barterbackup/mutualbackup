use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use futures::{StreamExt, stream::FuturesUnordered};
use mb_core::{
    CodingGroup, GuildCheckpoint, GuildGenesis, GuildInvite, InformationRole, KeyMaterial, Member,
    MemberSignature, NodeId, ParityRole, QuorumCheckpoint, QuorumGuildGenesis, RecoveryLocator,
    SealedRecoveryRecord, SectorId, SectorRef, Seed, ShardRole, SignedRecord,
    StorageAcknowledgement, UserRevision, V1_CATALOG_PAGE_BYTES, V1_MAX_CATALOG_BYTES,
    V1_MAX_CATALOG_PAGES, V1_MAX_CODING_GROUPS, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS,
    V1_SECTOR_SIZE, canonical_bytes, decode_canonical, encode_3_2, open_recovery_record,
    reconstruct_3_2, sector_root,
};
use mb_store::ParityObject;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use uuid::Uuid;

use crate::{
    BackupDescriptor, BackupJob, GuildPeer, Node,
    node::{NodeReader, NodeReaderConfig},
};

mod p2p;
pub use p2p::{
    DhtRecord, DhtRecoveryResult, P2pClient, P2pConfig, P2pEventLoop, P2pPeerProfile, P2pStatus,
    build_p2p, endpoint_record_key, recover_from_dht, recovery_bundle_key, recovery_mailbox_key,
    run_coordinator_jobs, run_dht_publications,
};

const MAX_PEER_FRAME_BYTES: usize = 600 * 1024;
const MAX_DIRECTORY_FRAME_BYTES: usize = 4 * 1024 * 1024;
const MAX_DIRECTORY_REQUEST_BYTES: usize = 72 * 1024;
const MAX_DIRECTORY_RECORD_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_TOTAL_BYTES: usize = 64 * 1024 * 1024;
const MAX_DIRECTORY_PUBLISHES_PER_MINUTE: u32 = 512;
const MAX_DIRECTORY_WORKING_BYTES: usize = 32 * 1024 * 1024;
const MAX_RECOVERY_SLOTS_PER_SUBJECT: usize = 64;
const HEADER_TIMEOUT: Duration = Duration::from_secs(2);
const BODY_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);
const PEER_REQUEST_DOMAIN: &[u8] = b"mutualbackup/direct-request/v2";
const PEER_RESPONSE_DOMAIN: &[u8] = b"mutualbackup/direct-response/v2";
const DIRECTORY_RECORD_DOMAIN: &[u8] = b"mutualbackup/directory-record/v1";
const DIRECTORY_ADMISSION_DOMAIN: &[u8] = b"mutualbackup/directory-admission/v1";
const RECOVERY_POW_ZERO_BYTES: usize = 2;
const RECOVERY_READ_ATTEMPTS: usize = 3;

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
    JoinGuild {
        invite: Box<SignedRecord<GuildInvite>>,
        peer: GuildPeer,
    },
    ProposeGuildGenesis {
        genesis: Box<GuildGenesis>,
    },
    InstallGuildGenesis {
        certificate: Box<QuorumGuildGenesis>,
        peers: Vec<GuildPeer>,
    },
    SubmitBackup {
        descriptor: BackupDescriptor,
    },
    BackupStatus {
        guild_id: [u8; 32],
        revision_id: Uuid,
    },
    GetGuildGenesis {
        guild_id: [u8; 32],
    },
    BeginCommit {
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
    },
    PrepareSource {
        guild_id: [u8; 32],
        source: String,
        sequence: u64,
    },
    GetPreparedRevisionPage {
        guild_id: [u8; 32],
        revision_id: Uuid,
        page_index: u32,
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
        operation_id: [u8; 16],
        group: Box<CodingGroup>,
        information: [Vec<u8>; 3],
        object: ParityObject,
    },
    GetParity {
        guild_id: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
    },
    PutCheckpointPage {
        object_kind: CheckpointObjectKind,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        page_index: u32,
        total_pages: u32,
        page_hash: [u8; 32],
        bytes: Vec<u8>,
    },
    SignCheckpoint {
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    },
    FinalizeCheckpoint {
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    },
    GetCheckpointPage {
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        page_index: u32,
    },
    BuildRecoveryRecord {
        publication_id: [u8; 16],
        subject: Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        expires_at_unix_seconds: u64,
        admission: Box<SignedRecord<RecoveryPublisherAdmission>>,
    },
    AuthorizeRecoveryPublisher {
        guild_id: [u8; 32],
        publisher: NodeId,
        expires_at_unix_seconds: u64,
    },
    CompleteCommit {
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) enum CheckpointObjectKind {
    Body,
    Certificate,
}

impl CheckpointObjectKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Certificate => "certificate",
        }
    }
}

impl PeerRequest {
    fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::Profile
                | Self::GetSector { .. }
                | Self::GetParity { .. }
                | Self::GetPreparedRevisionPage { .. }
                | Self::GetCheckpointPage { .. }
                | Self::BackupStatus { .. }
                | Self::GetGuildGenesis { .. }
        )
    }

    fn mutation_kind(&self) -> Option<&'static str> {
        match self {
            Self::Profile
            | Self::GetSector { .. }
            | Self::GetParity { .. }
            | Self::GetPreparedRevisionPage { .. }
            | Self::GetCheckpointPage { .. }
            | Self::BackupStatus { .. } => None,
            Self::GetGuildGenesis { .. } => None,
            Self::BeginCommit { .. } => Some("begin-commit"),
            Self::JoinGuild { .. } => Some("join-guild"),
            Self::ProposeGuildGenesis { .. } => Some("propose-guild-genesis"),
            Self::InstallGuildGenesis { .. } => Some("install-guild-genesis"),
            Self::SubmitBackup { .. } => Some("submit-backup"),
            Self::PrepareSource { .. } => Some("prepare-source"),
            Self::EnsureFiller { .. } => Some("ensure-filler"),
            Self::PublishParity { .. } => Some("publish-parity"),
            Self::PutCheckpointPage { .. } => Some("put-checkpoint-page"),
            Self::SignCheckpoint { .. } => Some("sign-checkpoint"),
            Self::FinalizeCheckpoint { .. } => Some("finalize-checkpoint"),
            Self::BuildRecoveryRecord { .. } => Some("build-recovery-record"),
            Self::AuthorizeRecoveryPublisher { .. } => Some("authorize-recovery-publisher"),
            Self::CompleteCommit { .. } => Some("complete-commit"),
        }
    }

    fn guild_scope(&self) -> Option<[u8; 32]> {
        match self {
            Self::Profile | Self::BeginCommit { .. } => None,
            Self::JoinGuild { invite, .. } => Some(invite.value.guild_id),
            Self::ProposeGuildGenesis { genesis } => Some(genesis.guild_id),
            Self::InstallGuildGenesis { certificate, .. } => Some(certificate.genesis.guild_id),
            Self::SubmitBackup { descriptor } => Some(descriptor.guild_id),
            Self::PrepareSource { guild_id, .. }
            | Self::GetPreparedRevisionPage { guild_id, .. }
            | Self::EnsureFiller { guild_id, .. }
            | Self::GetSector { guild_id, .. }
            | Self::GetParity { guild_id, .. }
            | Self::PutCheckpointPage { guild_id, .. }
            | Self::SignCheckpoint { guild_id, .. }
            | Self::FinalizeCheckpoint { guild_id, .. }
            | Self::GetCheckpointPage { guild_id, .. }
            | Self::BuildRecoveryRecord { guild_id, .. }
            | Self::AuthorizeRecoveryPublisher { guild_id, .. }
            | Self::CompleteCommit { guild_id, .. }
            | Self::BackupStatus { guild_id, .. } => Some(*guild_id),
            Self::GetGuildGenesis { guild_id } => Some(*guild_id),
            Self::PublishParity { object, .. } => Some(object.guild_id),
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
    CommitStarted {
        guild_id: [u8; 32],
    },
    PreparedRevision {
        revision_id: Uuid,
        total_pages: u32,
        object_hash: [u8; 32],
    },
    PreparedRevisionPage {
        total_pages: u32,
        page_hash: [u8; 32],
        bytes: Vec<u8>,
    },
    Filler {
        reference: SectorRef,
        bytes: Vec<u8>,
    },
    Bytes(Vec<u8>),
    CheckpointSignature(MemberSignature),
    GuildGenesisSignature(MemberSignature),
    BackupJob(BackupJob),
    StorageAcknowledgement(SignedRecord<StorageAcknowledgement>),
    GuildGenesis(Box<QuorumGuildGenesis>),
    CheckpointPage {
        total_pages: u32,
        page_hash: [u8; 32],
        bytes: Vec<u8>,
    },
    RecoveryRecord(Box<SignedRecord<PublishedRecoveryRecord>>),
    RecoveryAdmission(SignedRecord<RecoveryPublisherAdmission>),
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PublishedRecoveryRecord {
    format_version: u16,
    subject: NodeId,
    publisher: NodeId,
    slot: [u8; 32],
    slot_sequence: u64,
    expires_at_unix_seconds: u64,
    admission: SignedRecord<RecoveryPublisherAdmission>,
    sealed: SealedRecoveryRecord,
    pow_nonce: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RecoveryPublisherAdmission {
    format_version: u16,
    subject: NodeId,
    publisher: NodeId,
    slot: [u8; 32],
    expires_at_unix_seconds: u64,
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

type RecoverySlotKey = ([u8; 32], NodeId);
struct StoredRecoveryRecord {
    record: SignedRecord<PublishedRecoveryRecord>,
    byte_len: usize,
    admission_order: u64,
}
type PublisherRecords = BTreeMap<RecoverySlotKey, StoredRecoveryRecord>;
type RecoveryDirectoryRecords = BTreeMap<NodeId, PublisherRecords>;

#[derive(Default)]
struct RecoveryDirectoryState {
    records: RecoveryDirectoryRecords,
    total_bytes: usize,
    next_admission_order: u64,
    rate_window_started: u64,
    rate_window_publishes: u32,
}

#[derive(Clone, Default)]
pub struct DirectoryState {
    inner: Arc<Mutex<RecoveryDirectoryState>>,
}

struct NodeService {
    writer: Arc<Mutex<Node>>,
    reader_config: NodeReaderConfig,
    readers: Mutex<Vec<NodeReader>>,
    max_readers: usize,
}

impl NodeService {
    fn checkout_reader(&self) -> Result<NodeReader> {
        if let Some(reader) = self.readers.lock().map_err(lock_error)?.pop() {
            Ok(reader)
        } else {
            self.reader_config.open()
        }
    }

    fn return_reader(&self, reader: NodeReader) -> Result<()> {
        let mut readers = self.readers.lock().map_err(lock_error)?;
        if readers.len() < self.max_readers {
            readers.push(reader);
        }
        Ok(())
    }
}

fn directory_records_fit(
    publishers: &PublisherRecords,
    candidate: &SignedRecord<PublishedRecoveryRecord>,
) -> Result<bool> {
    let candidate_key = (candidate.value.slot, candidate.value.publisher);
    let mut records = publishers
        .iter()
        .filter(|(key, _)| **key != candidate_key)
        .map(|(_, stored)| stored.record.clone())
        .collect::<Vec<_>>();
    records.push(candidate.clone());
    Ok(canonical_bytes(&DirectoryResponse::Records(records))?.len() <= MAX_DIRECTORY_FRAME_BYTES)
}

impl RecoveryDirectoryState {
    fn publish(&mut self, record: SignedRecord<PublishedRecoveryRecord>) -> Result<()> {
        let now = unix_seconds();
        if now.saturating_sub(self.rate_window_started) >= 60 {
            self.rate_window_started = now;
            self.rate_window_publishes = 0;
        }
        if self.rate_window_publishes >= MAX_DIRECTORY_PUBLISHES_PER_MINUTE {
            bail!("recovery directory publish rate limit reached");
        }
        self.rate_window_publishes += 1;

        let subject = record.value.subject;
        let slot_key = (record.value.slot, record.value.publisher);
        if let Some(current) = self
            .records
            .get(&subject)
            .and_then(|publishers| publishers.get(&slot_key))
        {
            if current.record.value.slot_sequence > record.value.slot_sequence {
                bail!("recovery record would roll back publisher state");
            }
            if current.record.value.slot_sequence == record.value.slot_sequence {
                if current.record == record {
                    return Ok(());
                }
                bail!("recovery record would fork publisher state");
            }
        }

        let byte_len = canonical_bytes(&record)?.len();
        if byte_len > MAX_DIRECTORY_RECORD_BYTES {
            bail!("recovery record exceeds its byte limit");
        }
        let replaced_len = self
            .records
            .get(&subject)
            .and_then(|publishers| publishers.get(&slot_key))
            .map_or(0, |stored| stored.byte_len);
        while self
            .total_bytes
            .saturating_sub(replaced_len)
            .saturating_add(byte_len)
            > MAX_DIRECTORY_TOTAL_BYTES
        {
            self.evict_oldest(Some((subject, slot_key)))?;
        }
        let publishers = self.records.entry(subject).or_default();
        if !publishers.contains_key(&slot_key) && publishers.len() >= MAX_RECOVERY_SLOTS_PER_SUBJECT
        {
            bail!("recovery slot limit reached");
        }
        if !directory_records_fit(publishers, &record)? {
            bail!("recovery records exceed the lookup response limit");
        }
        self.next_admission_order = self
            .next_admission_order
            .checked_add(1)
            .context("recovery directory admission order exhausted")?;
        if let Some(previous) = publishers.insert(
            slot_key,
            StoredRecoveryRecord {
                record,
                byte_len,
                admission_order: self.next_admission_order,
            },
        ) {
            self.total_bytes = self.total_bytes.saturating_sub(previous.byte_len);
        }
        self.total_bytes = self
            .total_bytes
            .checked_add(byte_len)
            .context("recovery directory byte accounting overflow")?;
        Ok(())
    }

    fn evict_oldest(&mut self, protected: Option<(NodeId, RecoverySlotKey)>) -> Result<()> {
        let victim = self
            .records
            .iter()
            .flat_map(|(subject, publishers)| {
                publishers.iter().filter_map(move |(key, stored)| {
                    if protected == Some((*subject, *key)) {
                        None
                    } else {
                        Some((stored.admission_order, *subject, *key))
                    }
                })
            })
            .min();
        let Some((_, subject, key)) = victim else {
            bail!("recovery directory global byte limit reached");
        };
        let publishers = self
            .records
            .get_mut(&subject)
            .context("recovery directory eviction subject disappeared")?;
        let removed = publishers
            .remove(&key)
            .context("recovery directory eviction record disappeared")?;
        self.total_bytes = self.total_bytes.saturating_sub(removed.byte_len);
        if publishers.is_empty() {
            self.records.remove(&subject);
        }
        Ok(())
    }

    fn lookup(&self, subject: NodeId) -> Vec<SignedRecord<PublishedRecoveryRecord>> {
        self.records
            .get(&subject)
            .map(|entries| {
                entries
                    .values()
                    .map(|stored| stored.record.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn recovery_slot(subject: NodeId, publisher: NodeId, guild_id: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup recovery directory slot v1");
    hasher.update(&subject.0);
    hasher.update(&publisher.0);
    hasher.update(&guild_id);
    *hasher.finalize().as_bytes()
}

pub(super) fn storage_operation_id(group_id: &[u8; 32], shard_index: u8) -> [u8; 16] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup parity operation v1");
    hasher.update(group_id);
    hasher.update(&[shard_index]);
    let mut id = [0_u8; 16];
    id.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    if id == [0; 16] {
        id[0] = 1;
    }
    id
}

fn validate_recovery_admission(
    admission: &SignedRecord<RecoveryPublisherAdmission>,
    subject: NodeId,
    publisher: NodeId,
    slot: [u8; 32],
    expires_at_unix_seconds: u64,
) -> Result<()> {
    admission.verify(DIRECTORY_ADMISSION_DOMAIN)?;
    if admission.signer != subject
        || admission.value.format_version != 1
        || admission.value.subject != subject
        || admission.value.publisher != publisher
        || admission.value.slot != slot
        || admission.value.expires_at_unix_seconds != expires_at_unix_seconds
        || expires_at_unix_seconds != u64::MAX
    {
        bail!("invalid recovery-directory admission");
    }
    Ok(())
}

fn validate_published_recovery_record(
    record: &SignedRecord<PublishedRecoveryRecord>,
) -> Result<()> {
    record.verify(DIRECTORY_RECORD_DOMAIN)?;
    if record.signer != record.value.publisher
        || record.value.format_version != 3
        || record.value.expires_at_unix_seconds != u64::MAX
    {
        bail!("invalid published recovery record");
    }
    validate_recovery_admission(
        &record.value.admission,
        record.value.subject,
        record.value.publisher,
        record.value.slot,
        record.value.expires_at_unix_seconds,
    )?;
    if !valid_recovery_pow(&record.value)? {
        bail!("published recovery record has insufficient proof of work");
    }
    Ok(())
}

fn recovery_pow_commitment(record: &PublishedRecoveryRecord) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup recovery directory work v1");
    hasher.update(&canonical_bytes(&(
        record.format_version,
        record.subject,
        record.publisher,
        record.slot,
        record.slot_sequence,
        record.expires_at_unix_seconds,
        &record.admission,
        &record.sealed,
    ))?);
    Ok(*hasher.finalize().as_bytes())
}

fn recovery_pow_digest(commitment: [u8; 32], nonce: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup recovery directory nonce v1");
    hasher.update(&commitment);
    hasher.update(&nonce.to_le_bytes());
    *hasher.finalize().as_bytes()
}

fn valid_recovery_pow(record: &PublishedRecoveryRecord) -> Result<bool> {
    let digest = recovery_pow_digest(recovery_pow_commitment(record)?, record.pow_nonce);
    Ok(digest[..RECOVERY_POW_ZERO_BYTES]
        .iter()
        .all(|byte| *byte == 0))
}

fn solve_recovery_pow(record: &mut PublishedRecoveryRecord) -> Result<()> {
    let commitment = recovery_pow_commitment(record)?;
    for nonce in 0..=u64::MAX {
        if recovery_pow_digest(commitment, nonce)[..RECOVERY_POW_ZERO_BYTES]
            .iter()
            .all(|byte| *byte == 0)
        {
            record.pow_nonce = nonce;
            return Ok(());
        }
    }
    bail!("recovery-directory proof-of-work nonce space was exhausted")
}

pub async fn serve_node(node: Arc<Mutex<Node>>, config: NodeServerConfig) -> Result<()> {
    if config.failure_domain.is_empty() || config.max_connections == 0 {
        bail!("invalid node server configuration");
    }
    validate_advertised_endpoint(&config.public_endpoint)?;
    let reader_config = {
        let mut node = node.lock().map_err(lock_error)?;
        node.configure_failure_domain(&config.failure_domain)?;
        node.reader_config()
    };
    let service = Arc::new(NodeService {
        writer: node,
        reader_config,
        readers: Mutex::new(Vec::new()),
        max_readers: config.max_connections,
    });
    let listener = TcpListener::bind(config.listen).await?;
    let permits = Arc::new(Semaphore::new(config.max_connections));
    loop {
        let (stream, _) = listener.accept().await?;
        let permit = permits.clone().acquire_owned().await?;
        let service = service.clone();
        let config = config.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_peer_connection(stream, service, config).await {
                tracing::warn!(%error, "peer request failed");
            }
        });
    }
}

pub async fn serve_directory(listen: SocketAddr, state: DirectoryState) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    let permits = Arc::new(Semaphore::new(128));
    let working_bytes = Arc::new(Semaphore::new(MAX_DIRECTORY_WORKING_BYTES));
    loop {
        let (mut stream, _) = listener.accept().await?;
        let permit = permits.clone().acquire_owned().await?;
        let state = state.clone();
        let working_bytes = working_bytes.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let Ok(inbound_permit) = working_bytes
                .clone()
                .acquire_many_owned(MAX_DIRECTORY_REQUEST_BYTES as u32)
                .await
            else {
                return;
            };
            let mut inbound_permit = Some(inbound_permit);
            let mut response_permit = None;
            let response = match read_frame_timed::<_, DirectoryRequest>(
                &mut stream,
                MAX_DIRECTORY_REQUEST_BYTES,
            )
            .await
            {
                Ok(DirectoryRequest::Publish(record)) => {
                    let record = *record;
                    if validate_published_recovery_record(&record).is_err()
                        || canonical_bytes(&record)
                            .map_or(true, |bytes| bytes.len() > MAX_DIRECTORY_RECORD_BYTES)
                    {
                        DirectoryResponse::Error("invalid recovery record or admission".to_owned())
                    } else {
                        match state.inner.lock() {
                            Ok(mut state) => match state.publish(record) {
                                Ok(()) => DirectoryResponse::Ack,
                                Err(error) => DirectoryResponse::Error(error.to_string()),
                            },
                            Err(_) => {
                                DirectoryResponse::Error("directory lock poisoned".to_owned())
                            }
                        }
                    }
                }
                Ok(DirectoryRequest::Lookup { subject }) => {
                    drop(inbound_permit.take());
                    match working_bytes
                        .clone()
                        .acquire_many_owned((2 * MAX_DIRECTORY_FRAME_BYTES) as u32)
                        .await
                    {
                        Ok(permit) => {
                            response_permit = Some(permit);
                            match state.inner.lock() {
                                Ok(state) => DirectoryResponse::Records(state.lookup(subject)),
                                Err(_) => {
                                    DirectoryResponse::Error("directory lock poisoned".to_owned())
                                }
                            }
                        }
                        Err(_) => DirectoryResponse::Error(
                            "directory working-memory limiter closed".to_owned(),
                        ),
                    }
                }
                Err(error) => DirectoryResponse::Error(error.to_string()),
            };
            drop(inbound_permit);
            if let Err(error) =
                write_frame_timed(&mut stream, &response, MAX_DIRECTORY_FRAME_BYTES).await
            {
                tracing::warn!(%error, "directory response failed");
            }
            drop(response_permit);
        });
    }
}

async fn handle_peer_connection(
    mut stream: TcpStream,
    service: Arc<NodeService>,
    config: NodeServerConfig,
) -> Result<()> {
    let signed =
        read_frame_timed::<_, SignedRecord<PeerRequestEnvelope>>(&mut stream, MAX_PEER_FRAME_BYTES)
            .await?;
    let signed_response =
        tokio::task::spawn_blocking(move || process_peer_request(service, &config, signed))
            .await
            .context("peer request worker panicked")??;
    write_frame_timed(&mut stream, &signed_response, MAX_PEER_FRAME_BYTES).await?;
    Ok(())
}

fn process_peer_request(
    service: Arc<NodeService>,
    config: &NodeServerConfig,
    signed: SignedRecord<PeerRequestEnvelope>,
) -> Result<SignedRecord<PeerResponseEnvelope>> {
    let request_id = signed.value.request_id;
    let caller = signed.signer;
    let wire_request_hash = *blake3::hash(&canonical_bytes(&signed.value)?).as_bytes();
    let operation_hash = peer_operation_hash(&signed.value)?;
    let response = (|| {
        signed.verify(PEER_REQUEST_DOMAIN)?;
        validate_request_envelope(
            &signed.value,
            caller,
            service.reader_config.keys().node_id(),
        )?;
        let request = signed.value.request;
        if request.is_read_only() {
            let reader = service.checkout_reader()?;
            let result = (|| {
                if !matches!(&request, PeerRequest::Profile)
                    && !(matches!(
                        &request,
                        PeerRequest::GetSector { .. } | PeerRequest::GetPreparedRevisionPage { .. }
                    ) && caller == config.trusted_coordinator)
                {
                    reader.authorize_member(
                        &request
                            .guild_scope()
                            .context("guild-scoped request has no scope")?,
                        caller,
                    )?;
                }
                execute_read_request(&reader, config, request)
            })();
            service.return_reader(reader)?;
            return result;
        }

        let mutation_kind = request.mutation_kind();
        let mut node_guard = service.writer.lock().map_err(lock_error)?;
        let local_node_id = node_guard.keys().node_id();
        let self_authorized_admission = matches!(
            &request,
            PeerRequest::AuthorizeRecoveryPublisher { publisher, .. } if *publisher == caller
        );
        let guild_onboarding = match &request {
            PeerRequest::JoinGuild { peer, .. } => peer.member.node_id == caller,
            PeerRequest::ProposeGuildGenesis { genesis } => genesis.coordinator == caller,
            PeerRequest::InstallGuildGenesis { certificate, .. } => {
                certificate.genesis.coordinator == caller
            }
            _ => false,
        };
        let certified_coordinator = request
            .guild_scope()
            .map(|guild_id| node_guard.guild_coordinator(&guild_id))
            .transpose()?
            .flatten()
            == Some(caller);
        let member_submission = matches!(&request, PeerRequest::SubmitBackup { .. })
            && request
                .guild_scope()
                .is_some_and(|guild_id| node_guard.authorize_member(&guild_id, caller).is_ok());
        if mutation_kind.is_some()
            && caller != config.trusted_coordinator
            && !certified_coordinator
            && !self_authorized_admission
            && !guild_onboarding
            && !member_submission
        {
            bail!("caller is not the configured guild coordinator");
        }
        if matches!(
            &request,
            PeerRequest::BeginCommit { .. }
                | PeerRequest::PrepareSource { .. }
                | PeerRequest::CompleteCommit { .. }
        ) && caller != local_node_id
        {
            bail!("only the source node itself may manage its coordinator commit");
        }
        if let Some(kind) = mutation_kind {
            if kind == "ensure-filler" {
                // Filler bytes are deterministic and installation is
                // idempotent. Recompute them instead of retaining a 64 KiB
                // response for every coding group in the operation journal.
                return execute_peer_request(&mut node_guard, config, request_id, caller, request);
            }
            if let Some(cached_bytes) =
                node_guard.cached_operation(&request_id, kind, caller, &operation_hash)?
            {
                let cached: CachedOperation = decode_canonical(&cached_bytes)?;
                if cached.request_hash != operation_hash {
                    bail!("cached operation hash is inconsistent");
                }
                return Ok(cached.response);
            }
            let response =
                execute_peer_request(&mut node_guard, config, request_id, caller, request)?;
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
            bail!("request was not classified as a read or mutation")
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
        service.reader_config.keys(),
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

fn execute_read_request(
    node: &NodeReader,
    config: &NodeServerConfig,
    request: PeerRequest,
) -> Result<PeerResponse> {
    match request {
        PeerRequest::Profile => Ok(PeerResponse::Profile(PeerProfile {
            member: node.advertised_member(&config.failure_domain)?,
            endpoint: config.public_endpoint.clone(),
        })),
        PeerRequest::GetSector {
            guild_id,
            sector_id,
        } => Ok(PeerResponse::Bytes(
            node.sector_for_guild(&guild_id, &sector_id)?,
        )),
        PeerRequest::GetPreparedRevisionPage {
            guild_id,
            revision_id,
            page_index,
        } => {
            let (total_pages, bytes) =
                node.prepared_revision_page(&guild_id, revision_id, page_index)?;
            Ok(PeerResponse::PreparedRevisionPage {
                total_pages,
                page_hash: *blake3::hash(&bytes).as_bytes(),
                bytes,
            })
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
        PeerRequest::GetCheckpointPage {
            guild_id,
            checkpoint_hash,
            page_index,
        } => {
            let (total_pages, bytes) =
                node.checkpoint_page(&guild_id, &checkpoint_hash, page_index)?;
            Ok(PeerResponse::CheckpointPage {
                total_pages,
                page_hash: *blake3::hash(&bytes).as_bytes(),
                bytes,
            })
        }
        PeerRequest::BackupStatus {
            guild_id,
            revision_id,
        } => Ok(PeerResponse::BackupJob(
            node.backup_job(guild_id, revision_id)?,
        )),
        PeerRequest::GetGuildGenesis { guild_id } => Ok(PeerResponse::GuildGenesis(Box::new(
            node.installed_guild_certificate(guild_id)?,
        ))),
        _ => bail!("mutation was sent to a read-only node worker"),
    }
}

fn execute_peer_request(
    node: &mut Node,
    config: &NodeServerConfig,
    request_id: [u8; 16],
    caller: NodeId,
    request: PeerRequest,
) -> Result<PeerResponse> {
    match request {
        PeerRequest::Profile => Ok(PeerResponse::Profile(PeerProfile {
            member: node.advertised_member(&config.failure_domain)?,
            endpoint: config.public_endpoint.clone(),
        })),
        PeerRequest::JoinGuild { invite, peer } => {
            node.accept_guild_join(caller, &invite, peer)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::ProposeGuildGenesis { genesis } => Ok(PeerResponse::GuildGenesisSignature(
            node.sign_guild_genesis(&genesis)?,
        )),
        PeerRequest::InstallGuildGenesis { certificate, peers } => {
            node.install_guild_genesis(*certificate, peers)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::SubmitBackup { descriptor } => Ok(PeerResponse::BackupJob(
            node.enqueue_backup(caller, descriptor)?,
        )),
        PeerRequest::BeginCommit {
            intent_id,
            plan_hash,
        } => Ok(PeerResponse::CommitStarted {
            guild_id: node.begin_coordinator_commit(intent_id, plan_hash)?,
        }),
        PeerRequest::PrepareSource {
            guild_id,
            source,
            sequence,
        } => {
            let revision =
                node.prepare_revision(guild_id, Path::new(&source), sequence, Some(request_id))?;
            let bytes = canonical_bytes(&revision)?;
            let total_pages = checked_catalog_page_count(bytes.len())?;
            Ok(PeerResponse::PreparedRevision {
                revision_id: revision.value.revision_id,
                total_pages,
                object_hash: *blake3::hash(&bytes).as_bytes(),
            })
        }
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
        PeerRequest::PublishParity {
            operation_id,
            group,
            information,
            object,
        } => Ok(PeerResponse::StorageAcknowledgement(
            node.publish_verified_parity_with_operation(
                &operation_id,
                &group,
                &information,
                &object,
            )?,
        )),
        PeerRequest::GetParity {
            guild_id,
            group_id,
            shard_index,
        } => Ok(PeerResponse::Bytes(node.parity_for_guild(
            &guild_id,
            &group_id,
            shard_index,
        )?)),
        PeerRequest::PutCheckpointPage {
            object_kind,
            guild_id,
            checkpoint_hash,
            page_index,
            total_pages,
            page_hash,
            bytes,
        } => {
            node.stage_checkpoint_page(
                object_kind.as_str(),
                &guild_id,
                &checkpoint_hash,
                page_index,
                total_pages,
                &page_hash,
                &bytes,
            )?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::SignCheckpoint {
            guild_id,
            checkpoint_hash,
        } => Ok(PeerResponse::CheckpointSignature(
            node.sign_staged_checkpoint(&guild_id, &checkpoint_hash)?,
        )),
        PeerRequest::FinalizeCheckpoint {
            guild_id,
            checkpoint_hash,
        } => {
            node.finalize_staged_checkpoint(&guild_id, &checkpoint_hash)?;
            Ok(PeerResponse::Ack)
        }
        PeerRequest::GetCheckpointPage {
            guild_id,
            checkpoint_hash,
            page_index,
        } => {
            let (total_pages, bytes) =
                node.checkpoint_page(&guild_id, &checkpoint_hash, page_index)?;
            Ok(PeerResponse::CheckpointPage {
                total_pages,
                page_hash: *blake3::hash(&bytes).as_bytes(),
                bytes,
            })
        }
        PeerRequest::GetPreparedRevisionPage { .. } => {
            bail!("revision-page read was sent to a mutation worker")
        }
        PeerRequest::BackupStatus { .. } => {
            bail!("backup status read was sent to a mutation worker")
        }
        PeerRequest::GetGuildGenesis { .. } => {
            bail!("guild genesis read was sent to a mutation worker")
        }
        PeerRequest::BuildRecoveryRecord {
            publication_id: _,
            subject,
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            expires_at_unix_seconds,
            admission,
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
            let publisher = node.keys().node_id();
            let slot = recovery_slot(subject.node_id, publisher, guild_id);
            validate_recovery_admission(
                &admission,
                subject.node_id,
                publisher,
                slot,
                expires_at_unix_seconds,
            )?;
            let sealed = node.recovery_record(
                &subject,
                guild_id,
                checkpoint_hash,
                checkpoint_generation,
                config.public_endpoint.clone(),
                expires_at_unix_seconds,
            )?;
            let slot_sequence = node.next_recovery_publication_sequence(&slot, 1)?;
            let mut published = PublishedRecoveryRecord {
                format_version: 3,
                subject: subject.node_id,
                publisher,
                slot,
                slot_sequence,
                expires_at_unix_seconds,
                admission: *admission,
                sealed,
                pow_nonce: 0,
            };
            solve_recovery_pow(&mut published)?;
            Ok(PeerResponse::RecoveryRecord(Box::new(SignedRecord::sign(
                DIRECTORY_RECORD_DOMAIN,
                published,
                node.keys(),
            )?)))
        }
        PeerRequest::AuthorizeRecoveryPublisher {
            guild_id,
            publisher,
            expires_at_unix_seconds,
        } => {
            if expires_at_unix_seconds != u64::MAX {
                bail!("prototype recovery admissions must not expire");
            }
            node.authorize_member(&guild_id, publisher)?;
            let subject = node.keys().node_id();
            Ok(PeerResponse::RecoveryAdmission(SignedRecord::sign(
                DIRECTORY_ADMISSION_DOMAIN,
                RecoveryPublisherAdmission {
                    format_version: 1,
                    subject,
                    publisher,
                    slot: recovery_slot(subject, publisher, guild_id),
                    expires_at_unix_seconds,
                },
                node.keys(),
            )?))
        }
        PeerRequest::CompleteCommit {
            intent_id,
            plan_hash,
            guild_id,
            checkpoint_hash,
        } => {
            node.complete_coordinator_commit(intent_id, plan_hash, guild_id, checkpoint_hash)?;
            Ok(PeerResponse::Ack)
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

pub struct NetworkMemberRecovery {
    pub node: Node,
    pub checkpoints: Vec<QuorumCheckpoint>,
}

struct RecoveredGuild {
    checkpoint: QuorumCheckpoint,
    peer_endpoints: BTreeMap<NodeId, SocketAddr>,
}

pub async fn commit_source_over_network(
    coordinator_keys: &KeyMaterial,
    source: &Path,
    directory: SocketAddr,
    peer_endpoints: Vec<SocketAddr>,
) -> Result<NetworkCommitResult> {
    commit_source_over_network_with_intent(
        coordinator_keys,
        source,
        directory,
        peer_endpoints,
        Uuid::new_v4(),
    )
    .await
}

pub async fn commit_source_over_network_with_intent(
    coordinator_keys: &KeyMaterial,
    source: &Path,
    directory: SocketAddr,
    peer_endpoints: Vec<SocketAddr>,
    intent_id: Uuid,
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

    let source = source
        .to_str()
        .context("source path is not valid UTF-8")?
        .to_owned();
    let plan_peers = peers
        .iter()
        .map(|peer| peer.profile.clone())
        .collect::<Vec<_>>();
    let mut plan_hasher = blake3::Hasher::new_derive_key("mutualbackup coordinator commit v1");
    plan_hasher.update(&canonical_bytes(&(
        source.as_str(),
        directory.to_string(),
        plan_peers,
    ))?);
    let plan_hash = *plan_hasher.finalize().as_bytes();
    let started = peer_call_expected(
        peers[0].endpoint,
        peers[0].profile.member.node_id,
        coordinator_keys,
        PeerRequest::BeginCommit {
            intent_id: *intent_id.as_bytes(),
            plan_hash,
        },
    )
    .await?;
    let PeerResponse::CommitStarted { guild_id } = started else {
        bail!("owner returned the wrong response to commit initialization");
    };
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
    let PeerResponse::PreparedRevision {
        revision_id,
        total_pages,
        object_hash,
    } = prepared
    else {
        bail!("owner returned the wrong response to source preparation");
    };
    let revision = fetch_prepared_revision(
        &peers[0],
        coordinator_keys,
        guild_id,
        revision_id,
        total_pages,
        object_hash,
    )
    .await?;
    revision.verify(b"mutualbackup/user-revision/v1")?;
    if revision.value.owner != coordinator_keys.node_id() {
        bail!("prepared revision owner does not match coordinator");
    }

    let mut target_sectors = revision.value.metadata_sectors.clone();
    target_sectors.extend(revision.value.data_sectors.clone());
    if target_sectors.is_empty() || target_sectors.len() > V1_MAX_CODING_GROUPS {
        bail!("prepared revision exceeds the bounded v1 coding catalog");
    }
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
        let information = [shards[0].clone(), shards[1].clone(), shards[2].clone()];
        expect_storage_ack(
            peer_call_expected(
                peers[3].endpoint,
                peers[3].profile.member.node_id,
                coordinator_keys,
                PeerRequest::PublishParity {
                    operation_id: storage_operation_id(&group.id, parity_a.shard_index),
                    group: Box::new(group.clone()),
                    information: information.clone(),
                    object: parity_a.clone(),
                },
            )
            .await?,
            peers[3].profile.member.node_id,
            &parity_a,
        )?;
        expect_storage_ack(
            peer_call_expected(
                peers[4].endpoint,
                peers[4].profile.member.node_id,
                coordinator_keys,
                PeerRequest::PublishParity {
                    operation_id: storage_operation_id(&group.id, parity_b.shard_index),
                    group: Box::new(group.clone()),
                    information,
                    object: parity_b.clone(),
                },
            )
            .await?,
            peers[4].profile.member.node_id,
            &parity_b,
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
        genesis_hash: *blake3::hash(&canonical_bytes(&checkpoint_members)?).as_bytes(),
        generation: 1,
        parent: None,
        members: checkpoint_members,
        revisions: vec![revision],
        coding_groups: groups,
    };
    checkpoint_body.validate()?;
    let checkpoint_hash = checkpoint_body.hash()?;
    let checkpoint_body_bytes = canonical_bytes(&checkpoint_body)?;
    for peer in &peers {
        publish_checkpoint_pages(
            peer,
            coordinator_keys,
            CheckpointObjectKind::Body,
            guild_id,
            checkpoint_hash,
            &checkpoint_body_bytes,
        )
        .await?;
    }
    let mut signatures = Vec::new();
    for peer in &peers {
        let response = peer_call_expected(
            peer.endpoint,
            peer.profile.member.node_id,
            coordinator_keys,
            PeerRequest::SignCheckpoint {
                guild_id,
                checkpoint_hash,
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
    if checkpoint.hash()? != checkpoint_hash {
        bail!("quorum certificate changed the checkpoint state identity");
    }
    let certificate_bytes = canonical_bytes(&checkpoint)?;
    for peer in &peers {
        publish_checkpoint_pages(
            peer,
            coordinator_keys,
            CheckpointObjectKind::Certificate,
            guild_id,
            checkpoint_hash,
            &certificate_bytes,
        )
        .await?;
        expect_ack(
            peer_call_expected(
                peer.endpoint,
                peer.profile.member.node_id,
                coordinator_keys,
                PeerRequest::FinalizeCheckpoint {
                    guild_id,
                    checkpoint_hash,
                },
            )
            .await?,
        )?;
    }

    for subject in &checkpoint.checkpoint.members {
        let subject_peer = peers
            .iter()
            .find(|peer| peer.profile.member.node_id == subject.node_id)
            .context("checkpoint subject has no connected peer")?;
        for peer in &peers {
            if peer.profile.member.node_id == subject.node_id {
                continue;
            }
            let admission_response = peer_call_expected(
                subject_peer.endpoint,
                subject.node_id,
                coordinator_keys,
                PeerRequest::AuthorizeRecoveryPublisher {
                    guild_id,
                    publisher: peer.profile.member.node_id,
                    expires_at_unix_seconds: u64::MAX,
                },
            )
            .await?;
            let PeerResponse::RecoveryAdmission(admission) = admission_response else {
                bail!("peer returned the wrong recovery-admission response");
            };
            validate_recovery_admission(
                &admission,
                subject.node_id,
                peer.profile.member.node_id,
                recovery_slot(subject.node_id, peer.profile.member.node_id, guild_id),
                u64::MAX,
            )?;
            let response = peer_call_expected(
                peer.endpoint,
                peer.profile.member.node_id,
                coordinator_keys,
                PeerRequest::BuildRecoveryRecord {
                    publication_id: *Uuid::new_v4().as_bytes(),
                    subject: subject.clone(),
                    guild_id,
                    checkpoint_hash,
                    checkpoint_generation: checkpoint.checkpoint.generation,
                    expires_at_unix_seconds: u64::MAX,
                    admission: Box::new(admission),
                },
            )
            .await?;
            let PeerResponse::RecoveryRecord(record) = response else {
                bail!("peer returned the wrong recovery-record response");
            };
            directory_publish(directory, *record).await?;
        }
    }
    expect_ack(
        peer_call_expected(
            peers[0].endpoint,
            peers[0].profile.member.node_id,
            coordinator_keys,
            PeerRequest::CompleteCommit {
                intent_id: *intent_id.as_bytes(),
                plan_hash,
                guild_id,
                checkpoint_hash,
            },
        )
        .await?,
    )?;
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
    recover_selected_guild_over_network(seed, data_dir, restore_target, directory, None).await
}

pub async fn recover_guild_over_network(
    seed: Seed,
    data_dir: &Path,
    restore_target: &Path,
    directory: SocketAddr,
    guild_id: [u8; 32],
) -> Result<Node> {
    recover_selected_guild_over_network(seed, data_dir, restore_target, directory, Some(guild_id))
        .await
}

async fn recover_selected_guild_over_network(
    seed: Seed,
    data_dir: &Path,
    restore_target: &Path,
    directory: SocketAddr,
    selected_guild: Option<[u8; 32]>,
) -> Result<Node> {
    let NetworkMemberRecovery {
        mut node,
        checkpoints,
    } = recover_member_over_network(seed, data_dir, directory).await?;
    let local_node_id = node.keys().node_id();
    let mut owned = checkpoints
        .into_iter()
        .filter_map(|checkpoint| {
            let revision = checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == local_node_id)
                .max_by_key(|revision| revision.value.sequence)
                .cloned()?;
            Some((checkpoint, revision))
        })
        .filter(|(checkpoint, _)| {
            selected_guild.is_none_or(|guild_id| checkpoint.checkpoint.guild_id == guild_id)
        })
        .collect::<Vec<_>>();
    if owned.len() != 1 {
        bail!(
            "recovery found {} owned guilds; select exactly one guild for this restore target",
            owned.len()
        );
    }
    let (checkpoint, revision) = owned.pop().expect("checked one owned guild");
    let checkpoint_hash = checkpoint.hash()?;
    let checkpoint_for_worker = checkpoint.clone();
    let restore_target = restore_target.to_path_buf();
    node = run_node_blocking(node, move |node| {
        node.restore_recovered_revision(
            &checkpoint_hash,
            checkpoint_for_worker.checkpoint.guild_id,
            &revision,
            &restore_target,
        )?;
        Ok(())
    })
    .await?;
    Ok(node)
}

pub async fn recover_member_over_network(
    seed: Seed,
    data_dir: &Path,
    directory: SocketAddr,
) -> Result<NetworkMemberRecovery> {
    let (node, guilds) = recover_member_state(seed, data_dir, directory).await?;
    Ok(NetworkMemberRecovery {
        node,
        checkpoints: guilds.into_iter().map(|guild| guild.checkpoint).collect(),
    })
}

pub async fn recover_member_and_republish_over_network(
    seed: Seed,
    data_dir: &Path,
    directory: SocketAddr,
    public_endpoint: String,
) -> Result<NetworkMemberRecovery> {
    validate_advertised_endpoint(&public_endpoint)?;
    let (mut node, guilds) = recover_member_state(seed, data_dir, directory).await?;
    let local_node = node.keys().node_id();
    for guild in &guilds {
        let checkpoint_hash = guild.checkpoint.hash()?;
        for subject in &guild.checkpoint.checkpoint.members {
            if subject.node_id == local_node {
                continue;
            }
            let slot = recovery_slot(
                subject.node_id,
                local_node,
                guild.checkpoint.checkpoint.guild_id,
            );
            let published_records = directory_lookup(directory, subject.node_id).await?;
            let previous = published_records
                .iter()
                .filter(|record| {
                    record.value.publisher == local_node
                        && record.value.slot == slot
                        && validate_published_recovery_record(record).is_ok()
                })
                .max_by_key(|record| record.value.slot_sequence);
            let admission = match previous {
                Some(record) => record.value.admission.clone(),
                None => {
                    let Some(endpoint) = guild.peer_endpoints.get(&subject.node_id) else {
                        continue;
                    };
                    let response = peer_call_expected(
                        *endpoint,
                        subject.node_id,
                        node.keys(),
                        PeerRequest::AuthorizeRecoveryPublisher {
                            guild_id: guild.checkpoint.checkpoint.guild_id,
                            publisher: local_node,
                            expires_at_unix_seconds: u64::MAX,
                        },
                    )
                    .await?;
                    let PeerResponse::RecoveryAdmission(admission) = response else {
                        bail!("peer returned the wrong recovery-admission response");
                    };
                    admission
                }
            };
            validate_recovery_admission(&admission, subject.node_id, local_node, slot, u64::MAX)?;
            let minimum_sequence = previous
                .map(|record| record.value.slot_sequence)
                .map(|sequence| {
                    sequence
                        .checked_add(1)
                        .context("directory publication sequence exhausted")
                })
                .transpose()?
                .unwrap_or(1);
            let sealed = node.recovery_record(
                subject,
                guild.checkpoint.checkpoint.guild_id,
                checkpoint_hash,
                guild.checkpoint.checkpoint.generation,
                public_endpoint.clone(),
                u64::MAX,
            )?;
            let slot_sequence = node.next_recovery_publication_sequence(&slot, minimum_sequence)?;
            let mut published = PublishedRecoveryRecord {
                format_version: 3,
                subject: subject.node_id,
                publisher: local_node,
                slot,
                slot_sequence,
                expires_at_unix_seconds: u64::MAX,
                admission,
                sealed,
                pow_nonce: 0,
            };
            solve_recovery_pow(&mut published)?;
            let signed = SignedRecord::sign(DIRECTORY_RECORD_DOMAIN, published, node.keys())?;
            directory_publish(directory, signed).await?;
        }
    }
    Ok(NetworkMemberRecovery {
        node,
        checkpoints: guilds.into_iter().map(|guild| guild.checkpoint).collect(),
    })
}

async fn recover_member_state(
    seed: Seed,
    data_dir: &Path,
    directory: SocketAddr,
) -> Result<(Node, Vec<RecoveredGuild>)> {
    let data_dir = data_dir.to_path_buf();
    let mut recovered_node = tokio::task::spawn_blocking(move || Node::open(data_dir, seed))
        .await
        .context("node-open worker panicked")??;
    let local_node_id = recovered_node.keys().node_id();
    let sealed_records = directory_lookup(directory, local_node_id).await?;
    let mut candidates = Vec::new();
    for published in sealed_records {
        if validate_published_recovery_record(&published).is_err()
            || published.value.subject != local_node_id
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
            || recovery_slot(
                local_node_id,
                published.value.publisher,
                signed.value.guild_id,
            ) != published.value.slot
            || published.value.slot_sequence == 0
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
        let response = match fetch_checkpoint(
            endpoint,
            signed.value.publisher,
            recovered_node.keys(),
            signed.value.guild_id,
            signed.value.checkpoint_hash,
        )
        .await
        {
            Ok(checkpoint) => checkpoint,
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
    let mut candidates_by_guild = BTreeMap::<[u8; 32], Vec<_>>::new();
    for candidate in candidates {
        candidates_by_guild
            .entry(candidate.0.checkpoint.guild_id)
            .or_default()
            .push(candidate);
    }
    if candidates_by_guild.is_empty() {
        bail!("no reachable recovery locator led to a valid quorum checkpoint");
    }

    let mut recovered_guilds = Vec::with_capacity(candidates_by_guild.len());
    for (guild_id, guild_candidates) in candidates_by_guild {
        let generation = guild_candidates
            .iter()
            .map(|(checkpoint, _, _)| checkpoint.checkpoint.generation)
            .max()
            .context("recovery guild has no checkpoint candidates")?;
        let mut head_hashes = guild_candidates
            .iter()
            .filter(|(checkpoint, _, _)| checkpoint.checkpoint.generation == generation)
            .map(|(checkpoint, _, _)| Ok::<_, anyhow::Error>(checkpoint.hash()?))
            .collect::<Result<BTreeSet<_>>>()?;
        if head_hashes.len() != 1 {
            bail!("recovery directory contains conflicting heads for one guild");
        }
        let checkpoint_hash = head_hashes.pop_first().expect("checked one guild head");
        let checkpoint = guild_candidates
            .iter()
            .find(|(checkpoint, _, _)| checkpoint.hash().ok() == Some(checkpoint_hash))
            .map(|(checkpoint, _, _)| checkpoint.clone())
            .context("selected guild head disappeared")?;
        if checkpoint.checkpoint.guild_id != guild_id {
            bail!("recovery guild candidate changed identity");
        }
        let peer_endpoints = guild_candidates
            .into_iter()
            .filter(|(candidate, _, _)| candidate.hash().ok() == Some(checkpoint_hash))
            .map(|(_, publisher, endpoint)| (publisher, endpoint))
            .collect::<BTreeMap<_, _>>();
        recovered_node =
            recover_network_local_shards(recovered_node, &checkpoint, &peer_endpoints).await?;
        let checkpoint_for_worker = checkpoint.clone();
        recovered_node = run_node_blocking(recovered_node, move |node| {
            node.install_recovered_checkpoint(&checkpoint_for_worker)?;
            Ok(())
        })
        .await?;
        recovered_guilds.push(RecoveredGuild {
            checkpoint,
            peer_endpoints,
        });
    }
    Ok((recovered_node, recovered_guilds))
}

async fn recover_network_local_shards(
    mut recovered_node: Node,
    checkpoint: &QuorumCheckpoint,
    peer_endpoints: &BTreeMap<NodeId, SocketAddr>,
) -> Result<Node> {
    let recovering = recovered_node.keys().node_id();
    let checkpoint_hash = checkpoint.hash()?;
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
            let signed_request = make_peer_request(recovered_node.keys(), Some(holder), request)?;
            attempts.push(async move {
                let mut last_transport_error = None;
                for _ in 0..RECOVERY_READ_ATTEMPTS {
                    match send_peer_request(*endpoint, recovering, &signed_request).await {
                        Ok((signer, response)) if signer == holder => {
                            return (holder, index, root, Ok(response));
                        }
                        Ok(_) => {
                            return (
                                holder,
                                index,
                                root,
                                Err(anyhow::anyhow!(
                                    "authenticated response came from an unexpected identity"
                                )),
                            );
                        }
                        Err(error) => last_transport_error = Some(error),
                    }
                }
                (
                    holder,
                    index,
                    root,
                    Err(last_transport_error
                        .unwrap_or_else(|| anyhow::anyhow!("recovery read was not attempted"))),
                )
            });
        }
        while let Some((_holder, index, root, response)) = attempts.next().await {
            match response {
                Ok(PeerResponse::Bytes(bytes))
                    if bytes.len() == group.shard_size as usize && sector_root(&bytes) == root =>
                {
                    shards[index] = Some(bytes);
                }
                // An authenticated malformed response is corrupt data for
                // this shard; transport failures have already exhausted their
                // bounded retry budget. Neither poisons later coding groups.
                _ => {}
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
        drop(attempts);
        let group = group.clone();
        let guild_id = checkpoint.checkpoint.guild_id;
        recovered_node = run_node_blocking(recovered_node, move |node| {
            node.stage_recovered_shard(
                &checkpoint_hash,
                &guild_id,
                &group,
                target_index as u8,
                &bytes,
            )
        })
        .await?;
    }
    Ok(recovered_node)
}

async fn run_node_blocking<F>(mut node: Node, operation: F) -> Result<Node>
where
    F: FnOnce(&mut Node) -> Result<()> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        operation(&mut node)?;
        Ok(node)
    })
    .await
    .context("node storage worker panicked")?
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

fn checked_catalog_page_count(byte_length: usize) -> Result<u32> {
    if byte_length == 0 || byte_length > V1_MAX_CATALOG_BYTES {
        bail!("catalog object exceeds the bounded protocol limit");
    }
    let total_pages = byte_length.div_ceil(V1_CATALOG_PAGE_BYTES);
    if total_pages == 0 || total_pages > V1_MAX_CATALOG_PAGES as usize {
        bail!("catalog object has an invalid page count");
    }
    Ok(total_pages as u32)
}

async fn fetch_prepared_revision(
    peer: &RemotePeer,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision_id: Uuid,
    expected_pages: u32,
    expected_hash: [u8; 32],
) -> Result<SignedRecord<UserRevision>> {
    if expected_pages == 0 || expected_pages > V1_MAX_CATALOG_PAGES {
        bail!("prepared revision has an invalid page count");
    }
    let mut assembled = Vec::new();
    for page_index in 0..expected_pages {
        let response = peer_call_expected(
            peer.endpoint,
            peer.profile.member.node_id,
            keys,
            PeerRequest::GetPreparedRevisionPage {
                guild_id,
                revision_id,
                page_index,
            },
        )
        .await?;
        let PeerResponse::PreparedRevisionPage {
            total_pages,
            page_hash,
            bytes,
        } = response
        else {
            bail!("owner returned the wrong prepared-revision page response");
        };
        if total_pages != expected_pages
            || bytes.is_empty()
            || bytes.len() > V1_CATALOG_PAGE_BYTES
            || page_index + 1 < expected_pages && bytes.len() != V1_CATALOG_PAGE_BYTES
            || blake3::hash(&bytes).as_bytes() != &page_hash
            || assembled.len().saturating_add(bytes.len()) > V1_MAX_CATALOG_BYTES
        {
            bail!("prepared revision page failed bounded assembly checks");
        }
        assembled.extend_from_slice(&bytes);
    }
    if blake3::hash(&assembled).as_bytes() != &expected_hash {
        bail!("prepared revision object hash mismatch");
    }
    let revision: SignedRecord<UserRevision> = decode_canonical(&assembled)?;
    if revision.value.revision_id != revision_id || revision.value.guild_id != guild_id {
        bail!("prepared revision descriptor does not match its object");
    }
    Ok(revision)
}

async fn publish_checkpoint_pages(
    peer: &RemotePeer,
    keys: &KeyMaterial,
    object_kind: CheckpointObjectKind,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    bytes: &[u8],
) -> Result<()> {
    let total_pages = checked_catalog_page_count(bytes.len())?;
    for (page_index, page) in bytes.chunks(V1_CATALOG_PAGE_BYTES).enumerate() {
        expect_ack(
            peer_call_expected(
                peer.endpoint,
                peer.profile.member.node_id,
                keys,
                PeerRequest::PutCheckpointPage {
                    object_kind,
                    guild_id,
                    checkpoint_hash,
                    page_index: page_index as u32,
                    total_pages,
                    page_hash: *blake3::hash(page).as_bytes(),
                    bytes: page.to_vec(),
                },
            )
            .await?,
        )?;
    }
    Ok(())
}

async fn fetch_checkpoint(
    endpoint: SocketAddr,
    publisher: NodeId,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
) -> Result<QuorumCheckpoint> {
    let mut assembled = Vec::new();
    let mut expected_total = None;
    for page_index in 0..V1_MAX_CATALOG_PAGES {
        let response = peer_call_expected(
            endpoint,
            publisher,
            keys,
            PeerRequest::GetCheckpointPage {
                guild_id,
                checkpoint_hash,
                page_index,
            },
        )
        .await?;
        let PeerResponse::CheckpointPage {
            total_pages,
            page_hash,
            bytes,
        } = response
        else {
            bail!("peer returned the wrong checkpoint-page response");
        };
        if total_pages == 0
            || total_pages > V1_MAX_CATALOG_PAGES
            || expected_total.is_some_and(|expected| expected != total_pages)
            || page_index >= total_pages
            || bytes.is_empty()
            || bytes.len() > V1_CATALOG_PAGE_BYTES
            || assembled.len().saturating_add(bytes.len()) > V1_MAX_CATALOG_BYTES
            || blake3::hash(&bytes).as_bytes() != &page_hash
        {
            bail!("peer returned an invalid checkpoint page");
        }
        expected_total = Some(total_pages);
        assembled.extend_from_slice(&bytes);
        if page_index + 1 == total_pages {
            let checkpoint: QuorumCheckpoint = decode_canonical(&assembled)?;
            if checkpoint.hash()? != checkpoint_hash || checkpoint.checkpoint.guild_id != guild_id {
                bail!("paged checkpoint has the wrong state identity");
            }
            return Ok(checkpoint);
        }
    }
    bail!("checkpoint page count exceeds the protocol limit")
}

async fn peer_call(
    endpoint: SocketAddr,
    keys: &KeyMaterial,
    request: PeerRequest,
) -> Result<(NodeId, PeerResponse)> {
    let signed_request = make_peer_request(keys, None, request)?;
    send_peer_request(endpoint, keys.node_id(), &signed_request).await
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
    response_recipient: NodeId,
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
            || response.value.recipient != response_recipient
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
        match send_peer_request(endpoint, keys.node_id(), &signed_request).await {
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

fn expect_storage_ack(response: PeerResponse, holder: NodeId, object: &ParityObject) -> Result<()> {
    let PeerResponse::StorageAcknowledgement(acknowledgement) = response else {
        bail!("peer returned the wrong storage acknowledgement response");
    };
    acknowledgement.verify(b"mutualbackup/storage-acknowledgement/v1")?;
    acknowledgement.value.validate()?;
    if acknowledgement.signer != holder
        || acknowledgement.value.holder != holder
        || acknowledgement.value.operation_id
            != storage_operation_id(&object.group_id, object.shard_index)
        || acknowledgement.value.guild_id != object.guild_id
        || acknowledgement.value.group_id != object.group_id
        || acknowledgement.value.shard_index != object.shard_index
        || acknowledgement.value.root != object.root
    {
        bail!("peer storage acknowledgement does not match the parity object");
    }
    Ok(())
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

async fn write_frame_timed<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
    limit: usize,
) -> Result<()> {
    tokio::time::timeout(WRITE_TIMEOUT, write_frame_limited(writer, value, limit))
        .await
        .context("protocol frame write timed out")?
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
    use std::io::{Read, Seek, SeekFrom, Write};
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
    fn catalog_paging_uses_one_shared_end_to_end_bound() {
        assert_eq!(checked_catalog_page_count(1).unwrap(), 1);
        assert_eq!(
            checked_catalog_page_count(V1_CATALOG_PAGE_BYTES + 1).unwrap(),
            2
        );
        assert_eq!(
            checked_catalog_page_count(V1_MAX_CATALOG_BYTES).unwrap(),
            V1_MAX_CATALOG_PAGES
        );
        assert!(checked_catalog_page_count(0).is_err());
        assert!(checked_catalog_page_count(V1_MAX_CATALOG_BYTES + 1).is_err());
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

    #[test]
    fn read_workers_do_not_wait_for_the_mutation_lock() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([54; 32]);
        let node = Arc::new(Mutex::new(Node::open(temp.path(), local_seed).unwrap()));
        let reader_config = node.lock().unwrap().reader_config();
        let service = Arc::new(NodeService {
            writer: node.clone(),
            reader_config,
            readers: Mutex::new(Vec::new()),
            max_readers: 2,
        });
        let config = NodeServerConfig {
            listen: free_address(),
            public_endpoint: "tcp://127.0.0.1:1".to_owned(),
            failure_domain: "test-host".to_owned(),
            trusted_coordinator: KeyMaterial::from_seed(&Seed::from_bytes([55; 32])).node_id(),
            max_connections: 2,
        };
        let caller = KeyMaterial::from_seed(&Seed::from_bytes([56; 32]));
        let request = make_peer_request(&caller, None, PeerRequest::Profile).unwrap();
        let writer_guard = node.lock().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            sender
                .send(process_peer_request(service, &config, request))
                .unwrap();
        });
        let response = receiver
            .recv_timeout(Duration::from_secs(3))
            .expect("a profile read waited for the held mutation lock")
            .unwrap();
        assert!(matches!(
            response.value.result,
            Ok(PeerResponse::Profile(_))
        ));
        drop(writer_guard);
    }

    #[tokio::test]
    async fn directory_rejects_signed_rollback() {
        let address = free_address();
        let task = tokio::spawn(serve_directory(address, DirectoryState::default()));
        wait_until_listening(address).await;
        let publisher_keys = KeyMaterial::from_seed(&Seed::from_bytes([61; 32]));
        let subject_keys = KeyMaterial::from_seed(&Seed::from_bytes([62; 32]));
        let subject = subject_keys.node_id();
        let guild_id = [4; 32];
        let slot = recovery_slot(subject, publisher_keys.node_id(), guild_id);
        let admission = SignedRecord::sign(
            DIRECTORY_ADMISSION_DOMAIN,
            RecoveryPublisherAdmission {
                format_version: 1,
                subject,
                publisher: publisher_keys.node_id(),
                slot,
                expires_at_unix_seconds: u64::MAX,
            },
            &subject_keys,
        )
        .unwrap();
        let record = |generation, payload| {
            let mut published = PublishedRecoveryRecord {
                format_version: 3,
                subject,
                publisher: publisher_keys.node_id(),
                slot,
                slot_sequence: generation,
                expires_at_unix_seconds: u64::MAX,
                admission: admission.clone(),
                sealed: SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [5; 32],
                    nonce: [6; 24],
                    ciphertext: vec![payload; 32],
                },
                pow_nonce: 0,
            };
            solve_recovery_pow(&mut published).unwrap();
            SignedRecord::sign(DIRECTORY_RECORD_DOMAIN, published, &publisher_keys).unwrap()
        };
        directory_publish(address, record(2, 2)).await.unwrap();
        assert!(directory_publish(address, record(1, 1)).await.is_err());
        assert!(directory_publish(address, record(2, 3)).await.is_err());
        let records = directory_lookup(address, subject).await.unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].value.slot_sequence, 2);
        assert_eq!(records[0].value.sealed.ciphertext, vec![2; 32]);
        task.abort();
    }

    #[tokio::test]
    async fn directory_requires_subject_admission_and_separates_guild_slots() {
        let address = free_address();
        let task = tokio::spawn(serve_directory(address, DirectoryState::default()));
        wait_until_listening(address).await;
        let publisher_keys = KeyMaterial::from_seed(&Seed::from_bytes([70; 32]));
        let subject_keys = KeyMaterial::from_seed(&Seed::from_bytes([71; 32]));
        let attacker_keys = KeyMaterial::from_seed(&Seed::from_bytes([72; 32]));
        let make_record = |guild_id: [u8; 32], admission_keys: &KeyMaterial| {
            let subject = subject_keys.node_id();
            let publisher = publisher_keys.node_id();
            let slot = recovery_slot(subject, publisher, guild_id);
            let admission = SignedRecord::sign(
                DIRECTORY_ADMISSION_DOMAIN,
                RecoveryPublisherAdmission {
                    format_version: 1,
                    subject,
                    publisher,
                    slot,
                    expires_at_unix_seconds: u64::MAX,
                },
                admission_keys,
            )
            .unwrap();
            let mut published = PublishedRecoveryRecord {
                format_version: 3,
                subject,
                publisher,
                slot,
                slot_sequence: 1,
                expires_at_unix_seconds: u64::MAX,
                admission,
                sealed: SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [73; 32],
                    nonce: [74; 24],
                    ciphertext: vec![75; 32],
                },
                pow_nonce: 0,
            };
            solve_recovery_pow(&mut published).unwrap();
            SignedRecord::sign(DIRECTORY_RECORD_DOMAIN, published, &publisher_keys).unwrap()
        };
        assert!(
            directory_publish(address, make_record([1; 32], &attacker_keys))
                .await
                .is_err()
        );
        let mut insufficient_work = make_record([3; 32], &subject_keys);
        insufficient_work.value.pow_nonce = 0;
        while valid_recovery_pow(&insufficient_work.value).unwrap() {
            insufficient_work.value.pow_nonce += 1;
        }
        insufficient_work = SignedRecord::sign(
            DIRECTORY_RECORD_DOMAIN,
            insufficient_work.value,
            &publisher_keys,
        )
        .unwrap();
        assert!(directory_publish(address, insufficient_work).await.is_err());
        directory_publish(address, make_record([1; 32], &subject_keys))
            .await
            .unwrap();
        directory_publish(address, make_record([2; 32], &subject_keys))
            .await
            .unwrap();
        let records = directory_lookup(address, subject_keys.node_id())
            .await
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_ne!(records[0].value.slot, records[1].value.slot);
        task.abort();
    }

    #[test]
    fn directory_admission_keeps_every_lookup_frame_encodable() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([63; 32]));
        let subject_keys = KeyMaterial::from_seed(&Seed::from_bytes([64; 32]));
        let subject = subject_keys.node_id();
        let make_record = |ciphertext_len| {
            let slot = recovery_slot(subject, keys.node_id(), [65; 32]);
            let admission = SignedRecord::sign(
                DIRECTORY_ADMISSION_DOMAIN,
                RecoveryPublisherAdmission {
                    format_version: 1,
                    subject,
                    publisher: keys.node_id(),
                    slot,
                    expires_at_unix_seconds: u64::MAX,
                },
                &subject_keys,
            )
            .unwrap();
            let published = PublishedRecoveryRecord {
                format_version: 3,
                subject,
                publisher: keys.node_id(),
                slot,
                slot_sequence: 1,
                expires_at_unix_seconds: u64::MAX,
                admission,
                sealed: SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [67; 32],
                    nonce: [68; 24],
                    ciphertext: vec![69; ciphertext_len],
                },
                pow_nonce: 0,
            };
            SignedRecord::sign(DIRECTORY_RECORD_DOMAIN, published, &keys).unwrap()
        };
        let mut low = 0_usize;
        let mut high = MAX_DIRECTORY_RECORD_BYTES;
        while low < high {
            let midpoint = (low + high).div_ceil(2);
            if canonical_bytes(&make_record(midpoint)).unwrap().len() <= MAX_DIRECTORY_RECORD_BYTES
            {
                low = midpoint;
            } else {
                high = midpoint - 1;
            }
        }
        let base = make_record(low);
        let mut publishers = PublisherRecords::new();
        for value in 0_u8..63 {
            let mut record = base.clone();
            record.signer = NodeId([value; 32]);
            record.value.publisher = record.signer;
            record.value.slot = [value; 32];
            assert!(directory_records_fit(&publishers, &record).unwrap());
            publishers.insert(
                (record.value.slot, record.signer),
                StoredRecoveryRecord {
                    byte_len: canonical_bytes(&record).unwrap().len(),
                    admission_order: u64::from(value) + 1,
                    record,
                },
            );
        }
        let mut last = base;
        last.signer = NodeId([255; 32]);
        last.value.publisher = last.signer;
        last.value.slot = [255; 32];
        assert!(!directory_records_fit(&publishers, &last).unwrap());
        assert!(
            canonical_bytes(&DirectoryResponse::Records(
                publishers
                    .into_values()
                    .map(|stored| stored.record)
                    .collect()
            ))
            .unwrap()
            .len()
                <= MAX_DIRECTORY_FRAME_BYTES
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "requires an explicitly provisioned reflink test filesystem"]
    async fn signed_network_commit_and_seed_recovery() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
        let root = PathBuf::from(test_root).join(format!("network-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let source = root.join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("payload"), vec![0x5a; 150_000]).unwrap();
        fs::hard_link(source.join("payload"), source.join("payload-alias")).unwrap();
        let mut sparse = fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(source.join("sparse"))
            .unwrap();
        sparse.set_len(128 * 1024 * 1024).unwrap();
        sparse.seek(SeekFrom::Start(64 * 1024 * 1024)).unwrap();
        sparse.write_all(b"allocated island").unwrap();
        sparse.sync_all().unwrap();

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

        let commit_intent = Uuid::new_v4();
        let first_commit = commit_source_over_network_with_intent(
            &coordinator_keys,
            &source,
            directory_address,
            peer_addresses.clone(),
            commit_intent,
        )
        .await
        .unwrap();
        let retried_commit = commit_source_over_network_with_intent(
            &coordinator_keys,
            &source,
            directory_address,
            peer_addresses.clone(),
            commit_intent,
        )
        .await
        .unwrap();
        assert_eq!(first_commit.guild_id, retried_commit.guild_id);
        assert_eq!(first_commit.checkpoint_hash, retried_commit.checkpoint_hash);
        peer_tasks[0].abort();
        peer_tasks[1].abort();
        let _ = (&mut peer_tasks[0]).await;
        let _ = (&mut peer_tasks[1]).await;
        fs::remove_dir_all(root.join("node-0")).unwrap();
        fs::remove_dir_all(root.join("node-1")).unwrap();
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
        let recovered_checkpoint = recovered.checkpoint(&first_commit.checkpoint_hash).unwrap();
        let recovered_revision = recovered_checkpoint
            .checkpoint
            .revisions
            .iter()
            .find(|revision| revision.value.owner == recovered.keys().node_id())
            .unwrap();
        assert!(
            recovered_revision
                .value
                .data_sectors
                .iter()
                .all(|sector| !recovered.local_sector_is_inline(&sector.id).unwrap())
        );
        assert_eq!(
            fs::read(restored.join("payload")).unwrap(),
            vec![0x5a; 150_000]
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;

            let payload = fs::metadata(restored.join("payload")).unwrap();
            let alias = fs::metadata(restored.join("payload-alias")).unwrap();
            assert_eq!(payload.ino(), alias.ino());
            assert_eq!(payload.nlink(), 2);

            let sparse_metadata = fs::metadata(restored.join("sparse")).unwrap();
            assert_eq!(sparse_metadata.len(), 128 * 1024 * 1024);
            assert!(sparse_metadata.blocks() * 512 < sparse_metadata.len() / 4);
            let mut restored_sparse = fs::File::open(restored.join("sparse")).unwrap();
            restored_sparse
                .seek(SeekFrom::Start(64 * 1024 * 1024))
                .unwrap();
            let mut island = [0_u8; 16];
            restored_sparse.read_exact(&mut island).unwrap();
            assert_eq!(&island, b"allocated island");
        }
        drop(recovered);
        let recovered = recover_over_network(
            Seed::from_bytes([100; 32]),
            &root.join("recovered-node"),
            &restored,
            directory_address,
        )
        .await
        .unwrap();
        assert!(
            recovered_revision
                .value
                .data_sectors
                .iter()
                .all(|sector| !recovered.local_sector_is_inline(&sector.id).unwrap())
        );
        assert_eq!(
            fs::read(restored.join("payload")).unwrap(),
            vec![0x5a; 150_000]
        );

        drop(recovered);
        let recovered_zero_address = free_address();
        let recovered_zero_endpoint = format!("tcp://{recovered_zero_address}");
        let recovered_zero = recover_member_and_republish_over_network(
            Seed::from_bytes([100; 32]),
            &root.join("recovered-node"),
            directory_address,
            recovered_zero_endpoint.clone(),
        )
        .await
        .unwrap();
        let recovered_zero_task = tokio::spawn(serve_node(
            Arc::new(Mutex::new(recovered_zero.node)),
            NodeServerConfig {
                listen: recovered_zero_address,
                public_endpoint: recovered_zero_endpoint,
                failure_domain: "host-0".to_owned(),
                trusted_coordinator: coordinator_keys.node_id(),
                max_connections: 8,
            },
        ));
        wait_until_listening(recovered_zero_address).await;

        peer_tasks[2].abort();
        let _ = (&mut peer_tasks[2]).await;
        fs::remove_dir_all(root.join("node-2")).unwrap();
        let recovered_one_address = free_address();
        let recovered_one_endpoint = format!("tcp://{recovered_one_address}");
        let recovered_one = recover_member_and_republish_over_network(
            Seed::from_bytes([101; 32]),
            &root.join("recovered-node-1"),
            directory_address,
            recovered_one_endpoint.clone(),
        )
        .await
        .unwrap();
        let recovered_one_checkpoint = &recovered_one.checkpoints[0];
        assert_eq!(
            recovered_one.node.keys().node_id(),
            KeyMaterial::from_seed(&Seed::from_bytes([101; 32])).node_id()
        );
        assert_eq!(
            recovered_one_checkpoint.hash().unwrap(),
            first_commit.checkpoint_hash
        );
        let recovered_one_task = tokio::spawn(serve_node(
            Arc::new(Mutex::new(recovered_one.node)),
            NodeServerConfig {
                listen: recovered_one_address,
                public_endpoint: recovered_one_endpoint,
                failure_domain: "host-1".to_owned(),
                trusted_coordinator: coordinator_keys.node_id(),
                max_connections: 8,
            },
        ));
        wait_until_listening(recovered_one_address).await;

        peer_tasks[3].abort();
        let _ = (&mut peer_tasks[3]).await;
        fs::remove_dir_all(root.join("node-3")).unwrap();
        let recovered_two = recover_member_over_network(
            Seed::from_bytes([102; 32]),
            &root.join("recovered-node-2"),
            directory_address,
        )
        .await
        .unwrap();
        let recovered_two_checkpoint = &recovered_two.checkpoints[0];
        assert_eq!(
            recovered_two.node.keys().node_id(),
            KeyMaterial::from_seed(&Seed::from_bytes([102; 32])).node_id()
        );
        assert_eq!(
            recovered_two_checkpoint.hash().unwrap(),
            first_commit.checkpoint_hash
        );

        peer_tasks[4].abort();
        let _ = (&mut peer_tasks[4]).await;
        recovered_zero_task.abort();
        let _ = recovered_zero_task.await;
        recovered_one_task.abort();
        let _ = recovered_one_task.await;
        directory_task.abort();
        let _ = directory_task.await;
        drop(recovered_two);
        fs::remove_dir_all(&root).unwrap();
    }
}
