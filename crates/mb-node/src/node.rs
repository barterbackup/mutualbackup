use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use mb_core::{
    CODING_ATTEMPT_PLAN_DOMAIN, CODING_CHALLENGE_COMMITMENT_DOMAIN, CODING_CHALLENGE_REVEAL_DOMAIN,
    CODING_FAILURE_REPORT_DOMAIN, CODING_ROOT_MANIFEST_DOMAIN, CODING_SHARD_OPENING_DOMAIN,
    CODING_TRANSCRIPT_DOMAIN, CodingAttemptPlan, CodingChallengeCommitment, CodingChallengeReveal,
    CodingFailureReport, CodingGroupV2, CodingReplayFinding, CodingRootManifest,
    CodingShardOpening, CodingVerificationTranscript, DynamicGuildState, EndpointRecord,
    GuildCheckpoint, GuildEvent, GuildEventTail, GuildGenesis, GuildInvite, KeyMaterial,
    MAX_GUILD_EVENT_TAIL, Member, MemberSignature, NodeId, PackedSector, PackingProfile,
    PackingResult, QuorumCheckpoint, QuorumGuildEvent, QuorumGuildGenesis, QuorumPolicy,
    QuorumRule, RECOVERY_LOCATOR_DOMAIN, RecoveryBundle, RecoveryLocator,
    STAGED_STORAGE_RECEIPT_DOMAIN, STORAGE_ACKNOWLEDGEMENT_DOMAIN, SectorId, SectorRef, Seed,
    ShardRole, ShardRoleV2, SignedRecord, StagedStorageReceipt, StorageAcknowledgement,
    USER_REVISION_DOMAIN, UserRevision, V1_CATALOG_PAGE_BYTES, V1_MAX_CATALOG_PAGES,
    V1_MAX_ENDPOINTS_PER_PEER, canonical_bytes, challenged_leaf, coding_challenge_commitment,
    coding_evidence_hash, decode_canonical, encode_coding_attempt, merkle_commit,
    merkle_open_range, merkle_open_zero_range, open_recovery_key_envelope, open_recovery_record,
    replay_coding_transcript, seal_recovery_record, sector_root, sign_guild_event,
    synthetic_filler_sector,
};
use mb_store::{
    ControlStore, DatabaseError, NativeFileId, ParityObject, ParityStore, PinnedDirectory,
    VariableParityObject, filesystem_identity, probe_reflink,
};
use rand::RngCore;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::control::{NodeStatus, ProtectedRoot};
use crate::snapshot::{
    WriterCredentials, abandon_recovered_anchor_capture, build_revision_restore,
    install_inline_recipe, install_recovered_sector_recipe, make_restore_root_private_at,
    prepare_revision, publish_owned_restore, reanchor_recovered_revision,
    reconcile_pending_captures, recovered_recipe_is_stable, render_sector,
    restore_revision_from_source, restore_signed_root_metadata_at, resume_restore_publication,
    retire_revision_anchor, revision_head_id,
};
use crate::volume::{StorageScrubReport, StorageVolumes, VolumeReaderConfig, open_control_store};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
enum RecoveryJobState {
    Building,
    Ready,
    Complete,
    Published,
    Anchoring,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RecoveryJob {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target: PathBuf,
    staging: PathBuf,
    staged_native_id: Option<(u64, u64)>,
    state: RecoveryJobState,
    #[serde(default)]
    parent_native_id: Option<(u64, u64)>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RecoveryAttempt {
    format_version: u16,
    guild_id: [u8; 32],
    checkpoint_hash: [u8; 32],
    generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct PackedSectorRecord {
    format_version: u16,
    guild_id: [u8; 32],
    sector: PackedSector,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct LocalRecoveryResume {
    pub guild_id: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub generation: u64,
    pub revision_id: Option<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct CoordinatorCommitJournal {
    format_version: u16,
    intent_id: [u8; 16],
    plan_hash: [u8; 32],
    guild_id: [u8; 32],
    checkpoint_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct VerifierChallengeState {
    format_version: u16,
    attempt_id: [u8; 16],
    plan_hash: [u8; 32],
    nonce: [u8; 32],
    commitment: SignedRecord<CodingChallengeCommitment>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) enum DelegatedCodingJobState {
    Pending,
    Running,
    Cleanup,
    Submitting,
    Complete,
    Failed,
    ReportingFailure,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DelegatedCodingJob {
    pub format_version: u16,
    pub plan: SignedRecord<CodingAttemptPlan>,
    pub state: DelegatedCodingJobState,
    pub transcript: Option<SignedRecord<CodingVerificationTranscript>>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CodingActivationJob {
    pub format_version: u16,
    pub transcript: SignedRecord<CodingVerificationTranscript>,
    pub complete: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CodingRetryJob {
    pub format_version: u16,
    pub failure: SignedRecord<CodingFailureReport>,
    pub retry_plan: Option<SignedRecord<CodingAttemptPlan>>,
    pub complete: bool,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CodingLaunchJob {
    pub format_version: u16,
    pub plan: SignedRecord<CodingAttemptPlan>,
    pub dispatched: bool,
    pub error: Option<String>,
}

const GUILD_INVITE_DOMAIN: &[u8] = b"mutualbackup/guild-invite/v1";

#[cfg(test)]
thread_local! {
    static INTERRUPT_AFTER_RECOVERY_STAGING_CREATE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GuildPeer {
    pub member: Member,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum GuildPhase {
    Draft,
    Joining,
    Active,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GuildSummary {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub coordinator: NodeId,
    pub phase: GuildPhase,
    pub peers: Vec<GuildPeer>,
    pub membership_epoch: Option<u64>,
    pub event_sequence: Option<u64>,
    pub quorum: Option<QuorumPolicy>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BackupDescriptor {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub owner: NodeId,
    pub protected_root_id: Uuid,
    pub revision_id: Uuid,
    pub total_pages: u32,
    pub object_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum BackupJobState {
    Pending,
    Running,
    Committed,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct BackupJob {
    pub format_version: u16,
    pub descriptor: BackupDescriptor,
    pub state: BackupJobState,
    pub checkpoint_hash: Option<[u8; 32]>,
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct DhtPublicationSet {
    pub checkpoint_hash: [u8; 32],
    pub endpoint: SignedRecord<EndpointRecord>,
    pub recovery: Vec<SignedRecord<RecoveryBundle>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DhtSequenceFloors {
    pub endpoint: u64,
    pub recovery: BTreeMap<NodeId, u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct DhtPublicationState {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    endpoints: Vec<String>,
    expires_at_unix_seconds: u64,
    recovery_epochs: Vec<(NodeId, u64)>,
}

const MAX_DHT_OBSERVED_SEQUENCES: usize = 64;
const MAX_DHT_OBSERVED_RECORD_BYTES: usize = 16 * 1024;
const MAX_DHT_OBSERVED_ENDPOINT_SCOPES: usize = 1_024;
const MAX_DHT_OBSERVED_RECOVERY_SCOPES: usize = 64;
const DHT_OBSERVATION_FORMAT_UNCERTIFIED: u16 = 1;
const DHT_OBSERVATION_FORMAT_CERTIFIED: u16 = 2;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DhtRecordObservation {
    pub sequence: u64,
    pub expires_at_unix_seconds: u64,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct CheckpointRecoveryObservation {
    pub provider_peer_id: String,
    pub selected: SignedRecord<RecoveryBundle>,
    pub observations: Vec<DhtRecordObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct DhtObservationState {
    format_version: u16,
    highest_sequence: u64,
    hashes: Vec<DhtObservedHash>,
    current: DhtObservedRecord,
}

struct DhtRecordReconciliation {
    delete_record_ids: Vec<Vec<u8>>,
    replacements: Vec<(Vec<u8>, Vec<u8>)>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct DhtObservedHash {
    sequence: u64,
    hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct DhtObservedRecord {
    sequence: u64,
    hash: [u8; 32],
    expires_at_unix_seconds: u64,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SnapshotInfo {
    pub protected_root_id: Uuid,
    pub revision_id: Uuid,
    pub sequence: u64,
    pub checkpoint_generation: u64,
    pub checkpoint_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuildDraft {
    format_version: u16,
    guild_id: [u8; 32],
    coordinator: NodeId,
    peers: Vec<GuildPeer>,
    issued_invites: Vec<SignedRecord<GuildInvite>>,
    used_invites: Vec<[u8; 16]>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct PendingGuild {
    format_version: u16,
    invite: SignedRecord<GuildInvite>,
    local_peer: GuildPeer,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GenesisSignatureLock {
    format_version: u16,
    genesis_hash: [u8; 32],
    genesis: GuildGenesis,
    signature: MemberSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuildEventSignatureLock {
    format_version: u16,
    event_hash: [u8; 32],
    event: GuildEvent,
    signature: MemberSignature,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct InstalledGuild {
    format_version: u16,
    certificate: QuorumGuildGenesis,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GuildEndpointCache {
    format_version: u16,
    guild_id: [u8; 32],
    endpoints: Vec<(NodeId, Vec<String>)>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RootDirtyState {
    format_version: u16,
    protected_root_id: Uuid,
    dirty: bool,
    reason: String,
    change_sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct RetentionPolicy {
    format_version: u16,
    revisions_per_root: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct GarbageCandidate {
    format_version: u16,
    first_unreachable_generation: u64,
    checkpoint_hash: [u8; 32],
    parity_root: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AutomaticBackupPolicy {
    pub enabled: bool,
    pub quiet_period_seconds: u64,
    pub minimum_interval_seconds: u64,
    pub full_reconcile_interval_seconds: u64,
    pub daily_backup_limit: u32,
    pub daily_byte_limit: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AutomaticBackupStatus {
    pub enabled: bool,
    pub dirty_since_unix_seconds: Option<u64>,
    pub last_attempt_unix_seconds: Option<u64>,
    pub last_success_unix_seconds: Option<u64>,
    pub in_flight_revision: Option<Uuid>,
    pub window_backup_count: u32,
    pub window_bytes: u64,
    pub retry_at_unix_seconds: Option<u64>,
    pub blocked_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionState {
    Unknown,
    Healthy,
    Degraded,
    Emergency,
    Unrecoverable,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct GuildAuditReport {
    pub format_version: u16,
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_generation: u64,
    pub audited_at_unix_seconds: u64,
    pub state: ProtectionState,
    pub checked_groups: u64,
    pub assigned_shards_unavailable: u64,
    pub assigned_shards_repaired: u64,
    pub emergency_copies_created: u64,
    pub emergency_copies_removed: u64,
    pub issues: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct EmergencyShardRecord {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    group_id: [u8; 32],
    shard_index: u8,
    root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct VariableEmergencyShardRecord {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    group_id: [u8; 32],
    shard_index: u16,
    commitment: mb_core::MerkleCommitment,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct VariableRepairRecord {
    format_version: u16,
    repair_id: [u8; 16],
    group_id: [u8; 32],
    shard_index: u16,
    emergency: bool,
    commitment: mb_core::MerkleCommitment,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutomaticBackupState {
    format_version: u16,
    dirty_since_unix_seconds: Option<u64>,
    last_full_reconcile_unix_seconds: Option<u64>,
    last_attempt_unix_seconds: Option<u64>,
    last_success_unix_seconds: Option<u64>,
    window_started_unix_seconds: u64,
    window_backup_count: u32,
    window_bytes: u64,
    in_flight_revision: Option<Uuid>,
    retry_at_unix_seconds: Option<u64>,
    blocked_reason: Option<String>,
}

pub(crate) enum AutomaticBackupPoll {
    Idle,
    InFlight(Uuid),
    Start { estimated_bytes: u64 },
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize, Zeroize, ZeroizeOnDrop)]
struct LocalWriterIncarnation {
    format_version: u16,
    epoch: u64,
    public_key: [u8; 32],
    secret_key: [u8; 32],
    base_checkpoint: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct SeedRecoveryReadiness {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    confirmed_until_unix_seconds: u64,
    publishers: Vec<NodeId>,
}

pub type RecoveredShards = BTreeMap<([u8; 32], u8), Vec<u8>>;

/// An exclusive, process-lifetime claim on one initialized data directory.
///
/// The daemon acquires this before accepting an unlock secret, then moves a
/// clone into `Node` after the secret has been verified.
#[derive(Clone)]
pub struct LockedDataDir {
    path: PathBuf,
    _lock: Arc<File>,
}

pub struct Node {
    data_dir: PathBuf,
    _data_dir_lock: LockedDataDir,
    keys: Arc<KeyMaterial>,
    control: ControlStore,
    control_database_key: [u8; 32],
    volumes: StorageVolumes,
    volume_readers: Arc<RwLock<Vec<VolumeReaderConfig>>>,
}

#[derive(Clone)]
pub(crate) struct NodeReaderConfig {
    keys: Arc<KeyMaterial>,
    control_path: PathBuf,
    control_database_key: [u8; 32],
    volume_readers: Arc<RwLock<Vec<VolumeReaderConfig>>>,
}

pub(crate) struct NodeReader {
    keys: Arc<KeyMaterial>,
    control: ControlStore,
    volume_readers: Arc<RwLock<Vec<VolumeReaderConfig>>>,
}

impl NodeReaderConfig {
    pub(crate) fn open(&self) -> Result<NodeReader> {
        Ok(NodeReader {
            keys: self.keys.clone(),
            control: ControlStore::open_with_key(&self.control_path, &self.control_database_key)?,
            volume_readers: self.volume_readers.clone(),
        })
    }

    pub(crate) fn keys(&self) -> &KeyMaterial {
        &self.keys
    }
}

impl NodeReader {
    pub(crate) fn advertised_member(&self, fallback_failure_domain: &str) -> Result<Member> {
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            return decode_canonical(&bytes).map_err(Into::into);
        }
        Ok(Member {
            node_id: self.keys.node_id(),
            recovery_public_key: self.keys.recovery_public_key(),
            failure_domain: fallback_failure_domain.to_owned(),
        })
    }

    pub(crate) fn authorize_member(&self, guild_id: &[u8; 32], caller: NodeId) -> Result<()> {
        authorize_member(&self.control, guild_id, caller)
    }

    pub(crate) fn authorize_historical_member(
        &self,
        guild_id: &[u8; 32],
        caller: NodeId,
    ) -> Result<()> {
        authorize_historical_member(&self.control, guild_id, caller)
    }

    pub(crate) fn coding_capacity(&self, shard_size: u32) -> Result<u64> {
        let readers = self
            .volume_readers
            .read()
            .map_err(|_| anyhow::anyhow!("volume reader configuration lock was poisoned"))?;
        crate::volume::reader_coding_capacity(&self.control, &readers, shard_size)
    }

    pub(crate) fn backup_job(&self, guild_id: [u8; 32], revision_id: Uuid) -> Result<BackupJob> {
        backup_job(&self.control, guild_id, revision_id)
    }

    pub(crate) fn installed_guild_certificate(
        &self,
        guild_id: [u8; 32],
    ) -> Result<QuorumGuildGenesis> {
        let installed = decode_installed_guild(
            &self
                .control
                .get_record("guild-installed", b"primary")?
                .context("this node has no installed guild")?,
        )?;
        if installed.certificate.genesis.guild_id != guild_id {
            anyhow::bail!("requested guild differs from installed guild");
        }
        Ok(installed.certificate)
    }

    pub(crate) fn guild_event_tail(
        &self,
        base_sequence: u64,
        base_head: [u8; 32],
    ) -> Result<GuildEventTail> {
        guild_event_tail_from_store(&self.control, base_sequence, base_head)
    }

    pub(crate) fn coding_transcript_for_group(
        &self,
        guild_id: [u8; 32],
        group_id: [u8; 32],
    ) -> Result<SignedRecord<CodingVerificationTranscript>> {
        let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(
            &self
                .control
                .get_record("coding-group-transcript", &group_id)?
                .context("coding-group verifier transcript is unavailable")?,
        )?;
        if transcript.value.manifest.value.group.guild_id != guild_id
            || transcript.value.manifest.value.group.id != group_id
            || replay_coding_transcript(&transcript)? != CodingReplayFinding::Verified
        {
            anyhow::bail!("stored coding-group verifier transcript is invalid");
        }
        Ok(transcript)
    }

    pub(crate) fn peer_exchange_endpoints(
        &self,
        guild_id: [u8; 32],
    ) -> Result<Vec<SignedRecord<EndpointRecord>>> {
        let certificate = self.installed_guild_certificate(guild_id)?;
        let allowed = match self.control.get_record("guild-dynamic-state", b"primary")? {
            Some(bytes) => {
                let state: DynamicGuildState = decode_canonical(&bytes)?;
                state.validate()?;
                if state.guild_id != certificate.genesis.guild_id {
                    anyhow::bail!("dynamic membership belongs to another guild");
                }
                state
                    .active_members()
                    .map(|member| member.node_id)
                    .collect::<BTreeSet<_>>()
            }
            None => certificate
                .genesis
                .members
                .iter()
                .map(|member| member.node_id)
                .collect::<BTreeSet<_>>(),
        };
        let now = unix_seconds();
        let mut records = BTreeMap::<NodeId, SignedRecord<EndpointRecord>>::new();
        if let Some(bytes) = self.control.get_record("dht-endpoint", b"primary")? {
            retain_exchange_endpoint(&mut records, &allowed, now, &bytes)?;
        }
        for (_, bytes) in self.control.records("dht-observed-endpoint")? {
            let state: DhtObservationState = decode_canonical(&bytes)?;
            validate_dht_observation_state(&state)?;
            if state.current.expires_at_unix_seconds > now {
                retain_exchange_endpoint(&mut records, &allowed, now, &state.current.bytes)?;
            }
        }
        Ok(records.into_values().collect())
    }

    pub(crate) fn sector_for_guild(
        &self,
        guild_id: &[u8; 32],
        sector_id: &SectorId,
    ) -> Result<Vec<u8>> {
        render_sector(&self.control, &self.keys, sector_id, Some(guild_id))
            .or_else(|_| load_packed_sector(&self.control, guild_id, sector_id))
    }

    pub(crate) fn parity_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>> {
        let volumes = self
            .volume_readers
            .read()
            .map_err(|_| anyhow::anyhow!("volume reader configuration lock was poisoned"))?;
        let mut first_error = None;
        let mut object = None;
        for volume in volumes.iter() {
            let store = match ParityStore::open_existing_with_key(
                &volume.path,
                volume.volume_id.as_bytes(),
                &volume.database_key,
            ) {
                Ok(store) => store,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            match store.load_ready(group_id, shard_index) {
                Ok(found) => {
                    object = Some(found);
                    break;
                }
                Err(DatabaseError::NotReady) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        let object = match object {
            Some(object) => object,
            None => return Err(first_error.unwrap_or(DatabaseError::NotReady).into()),
        };
        if object.guild_id != *guild_id {
            anyhow::bail!("parity object does not belong to the requested guild");
        }
        Ok(object.bytes)
    }

    pub(crate) fn variable_shard_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<Vec<u8>> {
        let state: DynamicGuildState = decode_canonical(
            &self
                .control
                .get_record("guild-dynamic-state", b"primary")?
                .context("node has no dynamic guild state")?,
        )?;
        state.validate()?;
        if state.guild_id != *guild_id {
            anyhow::bail!("variable coding group belongs to another guild");
        }
        let group = &state
            .coding_groups
            .iter()
            .find(|retained| retained.group.id == *group_id)
            .context("variable coding group is unavailable")?
            .group;
        let role = group
            .roles
            .get(usize::from(shard_index))
            .context("variable shard index is outside its group")?;
        let (holder, commitment, storage_group) = match role {
            ShardRoleV2::Information(information) => {
                if information.sector.virtual_zero {
                    return Ok(vec![0; group.profile.shard_size as usize]);
                }
                (
                    information.owner,
                    &information.sector.commitment,
                    information.sector.id,
                )
            }
            ShardRoleV2::Parity(parity) => (parity.holder, &parity.commitment, group.id),
        };
        if holder != self.keys.node_id() {
            anyhow::bail!("variable shard is assigned to another holder");
        }
        let bytes = match role {
            ShardRoleV2::Information(information) => self
                .sector_for_guild(guild_id, &information.sector.id)
                .or_else(|_| {
                    self.ready_variable_object(&storage_group, shard_index)
                        .map(|object| object.bytes)
                })?,
            ShardRoleV2::Parity(_) => {
                self.ready_variable_object(&storage_group, shard_index)?
                    .bytes
            }
        };
        if merkle_commit(&bytes)? != *commitment {
            anyhow::bail!("variable shard conflicts with its committed Merkle root");
        }
        Ok(bytes)
    }

    pub(crate) fn variable_emergency_shard_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<Vec<u8>> {
        let marker_id = variable_emergency_id(group_id, shard_index);
        let marker: VariableEmergencyShardRecord = decode_canonical(
            &self
                .control
                .get_record("variable-emergency-shard", &marker_id)?
                .context("variable emergency shard is unavailable")?,
        )?;
        let (_, head_hash, _) = self
            .control
            .checkpoint_head(guild_id)?
            .context("variable emergency shard checkpoint is unavailable")?;
        let state: DynamicGuildState = decode_canonical(
            &self
                .control
                .get_record("guild-dynamic-state", b"primary")?
                .context("node has no dynamic guild state")?,
        )?;
        state.validate()?;
        let group = &state
            .coding_groups
            .iter()
            .find(|retained| retained.group.id == *group_id)
            .context("variable coding group is unavailable")?
            .group;
        let commitment = match group.roles.get(usize::from(shard_index)) {
            Some(ShardRoleV2::Information(information)) => &information.sector.commitment,
            Some(ShardRoleV2::Parity(parity)) => &parity.commitment,
            None => anyhow::bail!("variable emergency shard index is outside its group"),
        };
        if state.guild_id != *guild_id
            || marker.format_version != 1
            || marker.checkpoint_hash != head_hash
            || marker.group_id != *group_id
            || marker.shard_index != shard_index
            || marker.commitment != *commitment
        {
            anyhow::bail!("variable emergency shard has invalid durable metadata");
        }
        let object = self.ready_variable_object(group_id, shard_index)?;
        if object.guild_id != *guild_id || object.commitment != *commitment {
            anyhow::bail!("variable emergency shard payload is invalid");
        }
        Ok(object.bytes)
    }

    fn ready_variable_object(
        &self,
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<VariableParityObject> {
        let volumes = self
            .volume_readers
            .read()
            .map_err(|_| anyhow::anyhow!("volume reader configuration lock was poisoned"))?;
        let mut first_error = None;
        for volume in volumes.iter() {
            let store = match ParityStore::open_existing_with_key(
                &volume.path,
                volume.volume_id.as_bytes(),
                &volume.database_key,
            ) {
                Ok(store) => store,
                Err(error) => {
                    first_error.get_or_insert(error);
                    continue;
                }
            };
            match store.load_ready_variable(group_id, shard_index) {
                Ok(found) => return Ok(found),
                Err(DatabaseError::NotReady) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        Err(first_error.unwrap_or(DatabaseError::NotReady).into())
    }

    pub(crate) fn checkpoint_page(
        &self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
        page_index: u32,
    ) -> Result<(u32, Vec<u8>)> {
        checkpoint_page(&self.control, guild_id, checkpoint_hash, page_index)
    }

    pub(crate) fn prepared_revision_page(
        &self,
        guild_id: &[u8; 32],
        revision_id: Uuid,
        page_index: u32,
    ) -> Result<(u32, Vec<u8>)> {
        let bytes = self
            .control
            .get_record("user-revision", revision_id.as_bytes())?
            .context("prepared revision is unavailable")?;
        let revision: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        revision.verify(USER_REVISION_DOMAIN)?;
        revision.value.verify_writer()?;
        if revision.value.guild_id != *guild_id || revision.value.revision_id != revision_id {
            anyhow::bail!("prepared revision does not belong to the authorized guild");
        }
        Ok(self.control.protocol_record_page(
            "user-revision",
            revision_id.as_bytes(),
            page_index,
        )?)
    }
}

impl Node {
    pub fn lock_data_dir(data_dir: impl AsRef<Path>) -> Result<LockedDataDir> {
        let data_dir = data_dir.as_ref();
        fs::create_dir_all(data_dir)?;
        let data_dir = data_dir
            .canonicalize()
            .with_context(|| format!("cannot resolve data directory {}", data_dir.display()))?;
        set_private_directory(&data_dir)?;
        let lock = Arc::new(open_data_dir_lock(&data_dir)?);
        Ok(LockedDataDir {
            path: data_dir,
            _lock: lock,
        })
    }

    pub fn open(data_dir: impl AsRef<Path>, seed: Seed) -> Result<Self> {
        let locked = Self::lock_data_dir(data_dir)?;
        Self::open_locked(locked, seed)
    }

    pub fn open_locked(locked: LockedDataDir, seed: Seed) -> Result<Self> {
        let data_dir = locked.path.clone();
        let keys = Arc::new(KeyMaterial::from_seed(&seed));
        let (mut control, control_database_key) = open_control_store(&data_dir, &keys)?;
        control.clear_recomputable_operations()?;
        reconcile_pending_captures(&control)?;
        let mut volumes = StorageVolumes::open(&data_dir, keys.clone(), &control)?;
        volumes.reconcile(&control)?;
        let volume_readers = Arc::new(RwLock::new(volumes.reader_configs()));
        let mut node = Self {
            data_dir,
            _data_dir_lock: locked,
            keys,
            control,
            control_database_key,
            volumes,
            volume_readers,
        };
        node.reconcile_certified_writer_head()?;
        node.reconcile_garbage_collection()?;
        Ok(node)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn keys(&self) -> &KeyMaterial {
        &self.keys
    }

    pub fn status(&self) -> Result<NodeStatus> {
        let last_audit = self.last_guild_audit()?;
        let storage_volumes = self.volumes.statuses()?;
        let storage_degraded = self.volumes.protection_degraded(&self.control)?;
        let current_checkpoint_hash = match self.installed_guild()? {
            Some(guild) => self
                .current_checkpoint(guild.certificate.genesis.guild_id)?
                .map(|checkpoint| checkpoint.hash())
                .transpose()?,
            None => None,
        };
        let protection_state = match &last_audit {
            Some(audit) if Some(audit.checkpoint_hash) == current_checkpoint_hash => audit.state,
            _ if storage_degraded => ProtectionState::Degraded,
            _ => ProtectionState::Unknown,
        };
        Ok(NodeStatus {
            format_version: 2,
            node_id: self.keys.node_id(),
            data_dir: self.data_dir.clone(),
            protected_roots: self.protected_roots()?,
            checkpoint_count: self.control.checkpoint_head_certificates()?.len() as u64,
            seed_recovery_ready: self.seed_recovery_ready()?,
            root_dirty: self.root_dirty()?,
            automatic_backup: self.automatic_backup_status()?,
            protection_state,
            last_audit,
            storage_volumes,
            network: None,
        })
    }

    pub fn protected_roots(&self) -> Result<Vec<ProtectedRoot>> {
        let mut roots = Vec::new();
        for (record_id, bytes) in self.control.records("protected-root")? {
            let root: ProtectedRoot = decode_canonical(&bytes)?;
            if root.format_version != 3
                || root.root_id.is_nil()
                || record_id != root.root_id.as_bytes()
                || root.filesystem_id == 0
                || root.root_inode == 0
            {
                anyhow::bail!("invalid protected-root record");
            }
            roots.push(root);
        }
        roots.sort_by_key(|root| root.root_id);
        if roots.len() > 256 {
            anyhow::bail!("too many protected roots");
        }
        for (index, root) in roots.iter().enumerate() {
            if roots[..index].iter().any(|configured| {
                configured.path.starts_with(&root.path) || root.path.starts_with(&configured.path)
            }) {
                anyhow::bail!("protected roots must not overlap");
            }
        }
        Ok(roots)
    }

    fn protected_root_by_id(&self, root_id: Uuid) -> Result<ProtectedRoot> {
        self.protected_roots()?
            .into_iter()
            .find(|root| root.root_id == root_id)
            .context("protected root is not registered")
    }

    pub fn add_protected_root(&mut self, source_root: &Path) -> Result<ProtectedRoot> {
        self.register_protected_root(source_root, None, true, true)
    }

    fn register_protected_root(
        &mut self,
        source_root: &Path,
        requested_root_id: Option<Uuid>,
        initially_dirty: bool,
        probe_source: bool,
    ) -> Result<ProtectedRoot> {
        if requested_root_id.is_some_and(|root_id| root_id.is_nil()) {
            anyhow::bail!("protected root ID must not be nil");
        }
        let source_root = source_root
            .canonicalize()
            .with_context(|| format!("cannot resolve protected root {}", source_root.display()))?;
        if !source_root.is_dir() {
            anyhow::bail!("protected root must be a directory");
        }
        if source_root.starts_with(&self.data_dir) || self.data_dir.starts_with(&source_root) {
            anyhow::bail!("protected root and daemon data directory must not overlap");
        }
        let filesystem = filesystem_identity(&source_root)?;
        let root_metadata = fs::symlink_metadata(&source_root)?;
        #[cfg(unix)]
        let root_inode = {
            use std::os::unix::fs::MetadataExt;
            root_metadata.ino()
        };
        #[cfg(not(unix))]
        let root_inode = 0;

        let configured = self.protected_roots()?;
        if let Some(configured) = configured.iter().find(|root| root.path == source_root) {
            if configured.format_version == 3
                && requested_root_id.is_none_or(|root_id| configured.root_id == root_id)
                && configured.filesystem_id == filesystem.stable_id
                && configured.root_inode == root_inode
            {
                return Ok(configured.clone());
            }
            anyhow::bail!("protected root identity conflicts with an existing root");
        }
        let root_id = requested_root_id.unwrap_or_else(Uuid::new_v4);
        if configured.iter().any(|root| root.root_id == root_id) {
            anyhow::bail!("protected root identity conflicts with an existing root");
        }

        if probe_source {
            probe_reflink(&source_root).context("protected root failed the reflink COW probe")?;
        }
        if configured
            .iter()
            .any(|root| root.path.starts_with(&source_root) || source_root.starts_with(&root.path))
        {
            anyhow::bail!("protected roots must not overlap");
        }
        if configured.len() == 256 {
            anyhow::bail!("at most 256 protected roots may be registered");
        }
        let root = ProtectedRoot {
            format_version: 3,
            root_id,
            path: source_root,
            filesystem_id: filesystem.stable_id,
            root_inode,
        };
        self.control.put_record(
            "protected-root",
            root.root_id.as_bytes(),
            &canonical_bytes(&root)?,
        )?;
        if initially_dirty {
            self.mark_root_dirty(root.root_id, "protected root has not been backed up")?;
        } else {
            self.control.put_record(
                "root-dirty",
                root.root_id.as_bytes(),
                &canonical_bytes(&RootDirtyState {
                    format_version: 3,
                    protected_root_id: root.root_id,
                    dirty: false,
                    reason: "protected root was restored from its committed revision".to_owned(),
                    change_sequence: 0,
                })?,
            )?;
        }
        Ok(root)
    }

    pub fn mark_root_dirty(&mut self, root_id: Uuid, reason: &str) -> Result<()> {
        self.mark_root_dirty_at(root_id, reason, false, unix_seconds())
    }

    pub fn mark_root_changed(&mut self, root_id: Uuid, reason: &str) -> Result<()> {
        self.mark_root_dirty_at(root_id, reason, true, unix_seconds())
    }

    fn mark_root_dirty_at(
        &mut self,
        root_id: Uuid,
        reason: &str,
        changed: bool,
        now: u64,
    ) -> Result<()> {
        self.protected_root_by_id(root_id)?;
        let mut reason = reason.to_owned();
        truncate_utf8(&mut reason, 512);
        let previous = self.root_dirty_state(root_id)?;
        let change_sequence = previous
            .as_ref()
            .map(|state| state.change_sequence)
            .unwrap_or(0)
            .checked_add(1)
            .context("protected-root change sequence exhausted")?;
        self.control.put_record(
            "root-dirty",
            root_id.as_bytes(),
            &canonical_bytes(&RootDirtyState {
                format_version: 3,
                protected_root_id: root_id,
                dirty: true,
                reason,
                change_sequence,
            })?,
        )?;
        let mut automation = self.automatic_backup_state(now)?;
        if changed || automation.dirty_since_unix_seconds.is_none() {
            automation.dirty_since_unix_seconds = Some(now);
        }
        self.store_automatic_backup_state(&automation)?;
        Ok(())
    }

    pub fn root_dirty(&self) -> Result<bool> {
        for root in self.protected_roots()? {
            if self
                .root_dirty_state(root.root_id)?
                .is_none_or(|state| state.dirty)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn root_dirty_state(&self, root_id: Uuid) -> Result<Option<RootDirtyState>> {
        let state = self
            .control
            .get_record("root-dirty", root_id.as_bytes())?
            .map(|bytes| decode_canonical::<RootDirtyState>(&bytes))
            .transpose()?;
        if state
            .as_ref()
            .is_some_and(|state| state.format_version != 3 || state.protected_root_id != root_id)
        {
            anyhow::bail!("unsupported root dirty-state version");
        }
        Ok(state)
    }

    pub fn configure_automatic_backup(&self, policy: &AutomaticBackupPolicy) -> Result<()> {
        validate_automatic_backup_policy(policy)?;
        self.control.put_record(
            "node-config",
            b"automatic-backup",
            &canonical_bytes(policy)?,
        )?;
        Ok(())
    }

    fn automatic_backup_policy(&self) -> Result<AutomaticBackupPolicy> {
        let policy = self
            .control
            .get_record("node-config", b"automatic-backup")?
            .map(|bytes| decode_canonical::<AutomaticBackupPolicy>(&bytes))
            .transpose()?
            .unwrap_or(AutomaticBackupPolicy {
                enabled: false,
                quiet_period_seconds: 300,
                minimum_interval_seconds: 3_600,
                full_reconcile_interval_seconds: 86_400,
                daily_backup_limit: 24,
                daily_byte_limit: 100 * 1024 * 1024 * 1024,
            });
        validate_automatic_backup_policy(&policy)?;
        Ok(policy)
    }

    fn automatic_backup_state(&self, now: u64) -> Result<AutomaticBackupState> {
        let state = self
            .control
            .get_record("node-state", b"automatic-backup")?
            .map(|bytes| decode_canonical::<AutomaticBackupState>(&bytes))
            .transpose()?
            .unwrap_or(AutomaticBackupState {
                format_version: 1,
                dirty_since_unix_seconds: None,
                last_full_reconcile_unix_seconds: None,
                last_attempt_unix_seconds: None,
                last_success_unix_seconds: None,
                window_started_unix_seconds: now,
                window_backup_count: 0,
                window_bytes: 0,
                in_flight_revision: None,
                retry_at_unix_seconds: None,
                blocked_reason: None,
            });
        if state.format_version != 1 {
            anyhow::bail!("unsupported automatic-backup state version");
        }
        Ok(state)
    }

    fn store_automatic_backup_state(&self, state: &AutomaticBackupState) -> Result<()> {
        self.control
            .put_record("node-state", b"automatic-backup", &canonical_bytes(state)?)?;
        Ok(())
    }

    pub fn automatic_backup_status(&self) -> Result<AutomaticBackupStatus> {
        let policy = self.automatic_backup_policy()?;
        let state = self.automatic_backup_state(unix_seconds())?;
        Ok(AutomaticBackupStatus {
            enabled: policy.enabled,
            dirty_since_unix_seconds: state.dirty_since_unix_seconds,
            last_attempt_unix_seconds: state.last_attempt_unix_seconds,
            last_success_unix_seconds: state.last_success_unix_seconds,
            in_flight_revision: state.in_flight_revision,
            window_backup_count: state.window_backup_count,
            window_bytes: state.window_bytes,
            retry_at_unix_seconds: state.retry_at_unix_seconds,
            blocked_reason: state.blocked_reason,
        })
    }

    pub(crate) fn poll_automatic_backup(&mut self, now: u64) -> Result<AutomaticBackupPoll> {
        let policy = self.automatic_backup_policy()?;
        if !policy.enabled {
            return Ok(AutomaticBackupPoll::Idle);
        }
        let mut state = self.automatic_backup_state(now)?;
        if now.saturating_sub(state.window_started_unix_seconds) >= 24 * 60 * 60 {
            state.window_started_unix_seconds = now;
            state.window_backup_count = 0;
            state.window_bytes = 0;
            state.retry_at_unix_seconds = None;
            state.blocked_reason = None;
        }
        let reconciliation_due = state
            .last_full_reconcile_unix_seconds
            .is_none_or(|last| now.saturating_sub(last) >= policy.full_reconcile_interval_seconds);
        if reconciliation_due {
            state.last_full_reconcile_unix_seconds = Some(now);
            self.store_automatic_backup_state(&state)?;
            for root in self.protected_roots()? {
                self.mark_root_dirty_at(root.root_id, "scheduled full reconciliation", false, now)?;
            }
            state = self.automatic_backup_state(now)?;
        }
        if let Some(revision_id) = state.in_flight_revision {
            return Ok(AutomaticBackupPoll::InFlight(revision_id));
        }
        if !self.root_dirty()? {
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        if state.retry_at_unix_seconds.is_some_and(|retry| retry > now)
            || state.blocked_reason.is_some() && state.retry_at_unix_seconds.is_none()
        {
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        let quiet_until = state
            .dirty_since_unix_seconds
            .unwrap_or(now)
            .saturating_add(policy.quiet_period_seconds);
        let interval_until = state
            .last_attempt_unix_seconds
            .unwrap_or(0)
            .saturating_add(policy.minimum_interval_seconds);
        if now < quiet_until || now < interval_until {
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        if self.protected_roots()?.is_empty() || self.installed_guild()?.is_none() {
            state.blocked_reason = Some("automatic backup needs a protected root and guild".into());
            state.retry_at_unix_seconds = None;
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        let root = self
            .next_dirty_root()?
            .context("automatic backup has no dirty protected root")?;
        let estimated_bytes = match self.protected_root_logical_bytes(&root) {
            Ok(estimated_bytes) => estimated_bytes,
            Err(error) => {
                let mut message = format!("automatic full reconciliation failed: {error:#}");
                truncate_utf8(&mut message, 512);
                state.blocked_reason = Some(message);
                state.retry_at_unix_seconds =
                    Some(now.saturating_add(policy.minimum_interval_seconds));
                self.store_automatic_backup_state(&state)?;
                return Ok(AutomaticBackupPoll::Idle);
            }
        };
        if state.window_backup_count >= policy.daily_backup_limit {
            state.blocked_reason = Some("daily automatic-backup count limit reached".into());
            state.retry_at_unix_seconds = Some(
                state
                    .window_started_unix_seconds
                    .saturating_add(24 * 60 * 60),
            );
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        if estimated_bytes > policy.daily_byte_limit.saturating_sub(state.window_bytes) {
            state.blocked_reason = Some("daily automatic-backup byte limit reached".into());
            state.retry_at_unix_seconds = Some(
                state
                    .window_started_unix_seconds
                    .saturating_add(24 * 60 * 60),
            );
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        state.last_attempt_unix_seconds = Some(now);
        state.window_backup_count += 1;
        state.window_bytes = state.window_bytes.saturating_add(estimated_bytes);
        state.retry_at_unix_seconds = None;
        state.blocked_reason = None;
        self.store_automatic_backup_state(&state)?;
        Ok(AutomaticBackupPoll::Start { estimated_bytes })
    }

    pub(crate) fn automatic_backup_submitted(&self, revision_id: Uuid) -> Result<()> {
        let mut state = self.automatic_backup_state(unix_seconds())?;
        state.in_flight_revision = Some(revision_id);
        state.blocked_reason = None;
        state.retry_at_unix_seconds = None;
        self.store_automatic_backup_state(&state)
    }

    pub(crate) fn automatic_backup_finished(
        &self,
        revision_id: Option<Uuid>,
        succeeded: bool,
        error: Option<&str>,
    ) -> Result<()> {
        let now = unix_seconds();
        let mut state = self.automatic_backup_state(now)?;
        if revision_id.is_some() && state.in_flight_revision != revision_id {
            anyhow::bail!("automatic-backup completion conflicts with its durable revision");
        }
        state.in_flight_revision = None;
        if succeeded {
            state.last_success_unix_seconds = Some(now);
            state.blocked_reason = None;
            state.retry_at_unix_seconds = None;
        } else {
            let mut message = error.unwrap_or("automatic backup failed").to_owned();
            truncate_utf8(&mut message, 512);
            let hard = message.contains("budget")
                || message.contains("capacity")
                || message.contains("space");
            state.blocked_reason = Some(message);
            state.retry_at_unix_seconds = (!hard).then(|| {
                now.saturating_add(
                    self.automatic_backup_policy()
                        .map(|policy| policy.minimum_interval_seconds)
                        .unwrap_or(60),
                )
            });
        }
        self.store_automatic_backup_state(&state)
    }

    pub fn clear_automatic_backup_block(&self) -> Result<()> {
        let mut state = self.automatic_backup_state(unix_seconds())?;
        state.blocked_reason = None;
        state.retry_at_unix_seconds = None;
        self.store_automatic_backup_state(&state)
    }

    fn next_dirty_root(&self) -> Result<Option<ProtectedRoot>> {
        for root in self.protected_roots()? {
            if self
                .root_dirty_state(root.root_id)?
                .is_none_or(|state| state.dirty)
            {
                return Ok(Some(root));
            }
        }
        Ok(None)
    }

    fn protected_root_logical_bytes(&self, root: &ProtectedRoot) -> Result<u64> {
        let mut total = 0_u64;
        for entry in walkdir::WalkDir::new(&root.path).follow_links(false) {
            let entry = entry.context("automatic full reconciliation could not enumerate root")?;
            let metadata = entry
                .metadata()
                .context("automatic full reconciliation could not inspect an entry")?;
            if metadata.is_file() {
                total = total
                    .checked_add(metadata.len())
                    .context("protected-root logical size overflow")?;
            }
        }
        Ok(total)
    }

    pub(crate) fn reader_config(&self) -> NodeReaderConfig {
        NodeReaderConfig {
            keys: self.keys.clone(),
            control_path: self.control.path().to_path_buf(),
            control_database_key: self.control_database_key,
            volume_readers: self.volume_readers.clone(),
        }
    }

    fn refresh_volume_readers(&self) -> Result<()> {
        *self
            .volume_readers
            .write()
            .map_err(|_| anyhow::anyhow!("volume reader configuration lock was poisoned"))? =
            self.volumes.reader_configs();
        Ok(())
    }

    pub fn member(&self, failure_domain: impl Into<String>) -> Member {
        Member {
            node_id: self.keys.node_id(),
            recovery_public_key: self.keys.recovery_public_key(),
            failure_domain: failure_domain.into(),
        }
    }

    pub fn advertised_member(&self, fallback_failure_domain: &str) -> Result<Member> {
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            return decode_canonical(&bytes).map_err(Into::into);
        }
        Ok(self.member(fallback_failure_domain))
    }

    pub fn configure_failure_domain(&mut self, failure_domain: &str) -> Result<()> {
        if failure_domain.is_empty() {
            anyhow::bail!("failure domain must not be empty");
        }
        let expected = self.member(failure_domain);
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            let configured: Member = decode_canonical(&bytes)?;
            if configured != expected {
                anyhow::bail!("configured failure domain conflicts with durable node identity");
            }
        }
        for bytes in self.control.checkpoint_head_certificates()? {
            let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
            checkpoint.verify()?;
            let committed = checkpoint
                .checkpoint
                .members
                .iter()
                .find(|member| member.node_id == self.keys.node_id())
                .context("committed checkpoint does not contain the local node")?;
            if committed != &expected {
                anyhow::bail!("configured failure domain conflicts with committed membership");
            }
        }
        self.control
            .put_record("node-config", b"member", &canonical_bytes(&expected)?)?;
        Ok(())
    }

    pub fn configure_parity_budget(&mut self, budget_bytes: u64) -> Result<()> {
        self.volumes.set_uniform_budget(&self.control, budget_bytes)
    }

    pub fn configure_storage_volumes(
        &mut self,
        paths: &[PathBuf],
        budget_bytes: u64,
        headroom_bytes: u64,
    ) -> Result<()> {
        self.volumes
            .configure(&self.control, paths, budget_bytes, headroom_bytes)?;
        self.refresh_volume_readers()
    }

    pub fn configure_retention(&self, revisions_per_root: u32) -> Result<()> {
        if revisions_per_root == 0 || revisions_per_root > 1_024 {
            anyhow::bail!("retention must keep between 1 and 1024 revisions per root");
        }
        self.control.put_record(
            "node-config",
            b"retention",
            &canonical_bytes(&RetentionPolicy {
                format_version: 2,
                revisions_per_root,
            })?,
        )?;
        Ok(())
    }

    pub(crate) fn retention_revisions(&self) -> Result<usize> {
        let Some(bytes) = self.control.get_record("node-config", b"retention")? else {
            return Ok(30);
        };
        let policy: RetentionPolicy = decode_canonical(&bytes)?;
        if policy.format_version != 2
            || policy.revisions_per_root == 0
            || policy.revisions_per_root > 1_024
        {
            anyhow::bail!("durable retention policy is invalid");
        }
        Ok(policy.revisions_per_root as usize)
    }

    pub fn storage_status(&self) -> Result<Vec<crate::StorageVolumeStatus>> {
        self.volumes.statuses()
    }

    pub(crate) fn coding_capacity(&self, shard_size: u32) -> Result<u64> {
        self.volumes.coding_capacity(&self.control, shard_size)
    }

    pub fn database_shell_statement(
        &self,
        volume_id: Option<Uuid>,
        sql: &str,
        writable: bool,
    ) -> Result<mb_store::DatabaseShellResult> {
        if sql.trim().is_empty() {
            anyhow::bail!("database statement is empty");
        }
        match volume_id {
            Some(volume_id) => self
                .volumes
                .database_shell_statement(volume_id, sql, !writable),
            None => Ok(self.control.database_shell_statement(sql, !writable)?),
        }
    }

    pub fn scrub_storage(&mut self) -> Result<Vec<StorageScrubReport>> {
        let reports = self.volumes.scrub(&self.control)?;
        self.refresh_volume_readers()?;
        Ok(reports)
    }

    pub fn reclaim_storage(&mut self, volume_id: Option<Uuid>) -> Result<u64> {
        let _readers = self
            .volume_readers
            .write()
            .map_err(|_| anyhow::anyhow!("volume reader configuration lock was poisoned"))?;
        self.volumes.reclaim(volume_id)
    }

    pub fn last_guild_audit(&self) -> Result<Option<GuildAuditReport>> {
        let report = self
            .control
            .get_record("node-state", b"guild-audit")?
            .map(|bytes| decode_canonical::<GuildAuditReport>(&bytes))
            .transpose()?;
        if report
            .as_ref()
            .is_some_and(|report| report.format_version != 1)
        {
            anyhow::bail!("unsupported guild-audit report version");
        }
        Ok(report)
    }

    pub(crate) fn guild_audit_due(&self, now: u64, interval_seconds: u64) -> Result<bool> {
        let Some(guild) = self.installed_guild()? else {
            return Ok(false);
        };
        let Some(checkpoint) = self.current_checkpoint(guild.certificate.genesis.guild_id)? else {
            return Ok(false);
        };
        let checkpoint_hash = checkpoint.hash()?;
        let last = self.last_guild_audit()?;
        let storage_degraded = self.volumes.protection_degraded(&self.control)?;
        Ok(last.as_ref().is_none_or(|report| {
            report.checkpoint_hash != checkpoint_hash
                || now.saturating_sub(report.audited_at_unix_seconds) >= interval_seconds
                || storage_degraded && report.state == ProtectionState::Healthy
        }))
    }

    pub(crate) fn record_guild_audit(&self, report: &GuildAuditReport) -> Result<()> {
        if report.format_version != 1 || report.issues.len() > 256 {
            anyhow::bail!("invalid guild-audit report");
        }
        self.control
            .put_record("node-state", b"guild-audit", &canonical_bytes(report)?)?;
        Ok(())
    }

    pub fn drain_storage_volume(&mut self, volume_id: Uuid) -> Result<()> {
        self.volumes.mark_draining(&self.control, volume_id)
    }

    pub fn migrate_draining_volumes(&mut self) -> Result<u64> {
        let migrated = self.volumes.migrate_draining(&self.control)?;
        self.refresh_volume_readers()?;
        self.clear_automatic_backup_block()?;
        Ok(migrated)
    }

    pub fn reactivate_storage_volume(&mut self, volume_id: Uuid) -> Result<()> {
        self.volumes.reactivate(&self.control, volume_id)?;
        self.refresh_volume_readers()?;
        self.clear_automatic_backup_block()
    }

    pub fn reconcile_storage(&mut self) -> Result<()> {
        self.volumes.reconcile(&self.control)?;
        self.refresh_volume_readers()?;
        self.clear_automatic_backup_block()
    }

    pub fn create_guild(&mut self, endpoints: Vec<String>) -> Result<GuildSummary> {
        self.ensure_no_guild_state()?;
        let member = self.configured_member()?;
        validate_endpoint_set(member.node_id, &endpoints)?;
        let mut guild_id = [0_u8; 32];
        while guild_id == [0; 32] {
            rand::rngs::OsRng.fill_bytes(&mut guild_id);
        }
        let draft = GuildDraft {
            format_version: 1,
            guild_id,
            coordinator: member.node_id,
            peers: vec![GuildPeer { member, endpoints }],
            issued_invites: Vec::new(),
            used_invites: Vec::new(),
        };
        self.control
            .put_record("guild-draft", b"primary", &canonical_bytes(&draft)?)?;
        Ok(summary_from_draft(&draft))
    }

    pub fn issue_guild_invite(
        &mut self,
        coordinator_endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<SignedRecord<GuildInvite>> {
        let mut draft = self
            .guild_draft()?
            .context("this node has no guild draft")?;
        if draft.coordinator != self.keys.node_id() || draft.peers.len() >= 5 {
            anyhow::bail!("only an incomplete guild coordinator can issue invitations");
        }
        validate_endpoint_set(self.keys.node_id(), &coordinator_endpoints)?;
        if expires_at_unix_seconds <= unix_seconds() {
            anyhow::bail!("guild invitation expiry must be in the future");
        }
        let mut nonce = [0_u8; 16];
        while nonce == [0; 16]
            || draft
                .issued_invites
                .iter()
                .any(|invite| invite.value.nonce == nonce)
        {
            rand::rngs::OsRng.fill_bytes(&mut nonce);
        }
        let invite = SignedRecord::sign(
            GUILD_INVITE_DOMAIN,
            GuildInvite {
                format_version: 1,
                guild_id: draft.guild_id,
                coordinator: self.configured_member()?,
                coordinator_endpoints,
                nonce,
                expires_at_unix_seconds,
            },
            &self.keys,
        )?;
        invite.value.validate()?;
        draft.issued_invites.push(invite.clone());
        draft
            .issued_invites
            .sort_by_key(|invite| invite.value.nonce);
        self.control
            .put_record("guild-draft", b"primary", &canonical_bytes(&draft)?)?;
        Ok(invite)
    }

    pub fn begin_join_guild(
        &mut self,
        invite: SignedRecord<GuildInvite>,
        endpoints: Vec<String>,
    ) -> Result<GuildPeer> {
        invite.verify(GUILD_INVITE_DOMAIN)?;
        invite.value.validate()?;
        if invite.signer != invite.value.coordinator.node_id
            || invite.value.expires_at_unix_seconds <= unix_seconds()
        {
            anyhow::bail!("guild invitation is not authentic or has expired");
        }
        let local_peer = GuildPeer {
            member: self.configured_member()?,
            endpoints,
        };
        validate_endpoint_set(local_peer.member.node_id, &local_peer.endpoints)?;
        if local_peer.member.node_id == invite.value.coordinator.node_id {
            anyhow::bail!("guild coordinator cannot join its own invitation");
        }
        if let Some(installed) = self.installed_guild()? {
            if installed.certificate.genesis.guild_id == invite.value.guild_id {
                return self
                    .guild_peers(&installed)?
                    .into_iter()
                    .find(|peer| peer.member.node_id == self.keys.node_id())
                    .context("installed guild omits the local peer");
            }
            anyhow::bail!("this node already belongs to another guild");
        }
        if self.guild_draft()?.is_some() {
            anyhow::bail!("a guild coordinator cannot join another guild");
        }
        let pending = PendingGuild {
            format_version: 1,
            invite,
            local_peer: local_peer.clone(),
        };
        if let Some(bytes) = self.control.get_record("guild-pending", b"primary")? {
            let existing: PendingGuild = decode_canonical(&bytes)?;
            if existing != pending {
                anyhow::bail!("this node already has a different pending guild invitation");
            }
            return Ok(local_peer);
        }
        self.control
            .put_record("guild-pending", b"primary", &canonical_bytes(&pending)?)?;
        Ok(local_peer)
    }

    pub fn accept_guild_join(
        &mut self,
        caller: NodeId,
        invite: &SignedRecord<GuildInvite>,
        peer: GuildPeer,
    ) -> Result<()> {
        invite.verify(GUILD_INVITE_DOMAIN)?;
        invite.value.validate()?;
        validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
        let mut draft = self
            .guild_draft()?
            .context("this node has no guild draft")?;
        if caller != peer.member.node_id
            || invite.signer != self.keys.node_id()
            || invite.value.coordinator.node_id != self.keys.node_id()
            || invite.value.guild_id != draft.guild_id
            || invite.value.expires_at_unix_seconds <= unix_seconds()
            || !draft.issued_invites.iter().any(|issued| issued == invite)
        {
            anyhow::bail!("guild join is not authorized by an issued invitation");
        }
        if draft.used_invites.contains(&invite.value.nonce) {
            if draft.peers.iter().any(|existing| existing == &peer) {
                return Ok(());
            }
            anyhow::bail!("guild invitation has already been used");
        }
        if draft.peers.len() >= 5
            || draft
                .peers
                .iter()
                .any(|existing| existing.member.node_id == peer.member.node_id)
            || draft
                .peers
                .iter()
                .any(|existing| existing.member.failure_domain == peer.member.failure_domain)
        {
            anyhow::bail!("guild member or failure domain is duplicated, or guild is full");
        }
        draft.peers.push(peer);
        draft.peers.sort_by_key(|entry| entry.member.node_id);
        draft.used_invites.push(invite.value.nonce);
        draft.used_invites.sort();
        self.control
            .put_record("guild-draft", b"primary", &canonical_bytes(&draft)?)?;
        Ok(())
    }

    pub fn proposed_guild_genesis(&self) -> Result<(GuildGenesis, Vec<GuildPeer>)> {
        let draft = self
            .guild_draft()?
            .context("this node has no guild draft")?;
        if draft.coordinator != self.keys.node_id() || draft.peers.len() != 5 {
            anyhow::bail!("guild finalization requires exactly five accepted members");
        }
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: draft.guild_id,
            coordinator: draft.coordinator,
            members: draft.peers.iter().map(|peer| peer.member.clone()).collect(),
        };
        genesis.validate()?;
        Ok((genesis, draft.peers))
    }

    pub fn sign_guild_genesis(&mut self, genesis: &GuildGenesis) -> Result<MemberSignature> {
        genesis.validate()?;
        let local_member = genesis
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("guild genesis omits the local node")?;
        if local_member != &self.configured_member()? {
            anyhow::bail!("guild genesis conflicts with the durable local member identity");
        }
        if genesis.coordinator == self.keys.node_id() {
            let (expected, _) = self.proposed_guild_genesis()?;
            if &expected != genesis {
                anyhow::bail!("guild genesis differs from the coordinator draft");
            }
        } else {
            let pending = self
                .pending_guild()?
                .context("no pending invitation authorizes this guild")?;
            if pending.invite.value.guild_id != genesis.guild_id
                || pending.invite.value.coordinator.node_id != genesis.coordinator
                || !genesis
                    .members
                    .iter()
                    .any(|member| member == &pending.invite.value.coordinator)
            {
                anyhow::bail!("guild genesis differs from the accepted invitation");
            }
        }
        let genesis_hash = genesis.hash()?;
        if let Some(bytes) = self
            .control
            .get_record("guild-genesis-signature-lock", b"primary")?
        {
            let lock: GenesisSignatureLock = decode_canonical(&bytes)?;
            if lock.format_version != 1
                || lock.genesis_hash != genesis_hash
                || lock.genesis != *genesis
            {
                anyhow::bail!("local seed has already signed a conflicting guild genesis");
            }
            return Ok(lock.signature);
        }
        let signature = genesis.member_signature(&self.keys)?;
        let lock = GenesisSignatureLock {
            format_version: 1,
            genesis_hash,
            genesis: genesis.clone(),
            signature: signature.clone(),
        };
        self.control.put_record(
            "guild-genesis-signature-lock",
            b"primary",
            &canonical_bytes(&lock)?,
        )?;
        Ok(signature)
    }

    pub fn install_guild_genesis(
        &mut self,
        certificate: QuorumGuildGenesis,
        mut peers: Vec<GuildPeer>,
    ) -> Result<()> {
        certificate.verify()?;
        peers.sort_by_key(|peer| peer.member.node_id);
        if peers.len() != 5
            || peers
                .iter()
                .map(|peer| &peer.member)
                .ne(certificate.genesis.members.iter())
        {
            anyhow::bail!("guild endpoint roster does not match certified membership");
        }
        for peer in &peers {
            validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
        }
        let lock: GenesisSignatureLock = decode_canonical(
            &self
                .control
                .get_record("guild-genesis-signature-lock", b"primary")?
                .context("local node did not sign this guild genesis")?,
        )?;
        if lock.genesis_hash != certificate.hash()?
            || !certificate
                .signatures
                .iter()
                .any(|signature| signature == &lock.signature)
        {
            anyhow::bail!("guild certificate does not contain the locked local signature");
        }
        let installed = InstalledGuild {
            format_version: 2,
            certificate,
        };
        let initial_dynamic = initial_dynamic_guild_state(&installed)?;
        if let Some(existing) = self.installed_guild()? {
            if existing != installed {
                anyhow::bail!("this node already has a different installed guild");
            }
            let endpoint_cache = self.merged_guild_endpoint_cache(&installed, peers)?;
            let mut records = vec![(
                "guild-endpoints".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&endpoint_cache)?,
            )];
            match self.dynamic_guild_state()? {
                Some(state) => validate_dynamic_state_origin(&state, &initial_dynamic)?,
                None => records.push((
                    "guild-dynamic-state".to_owned(),
                    b"primary".to_vec(),
                    canonical_bytes(&initial_dynamic)?,
                )),
            }
            self.control.put_records(&records)?;
            return Ok(());
        }
        let endpoint_cache = self.merged_guild_endpoint_cache(&installed, peers)?;
        self.control.put_records(&[
            (
                "guild-installed".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&installed)?,
            ),
            (
                "guild-endpoints".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&endpoint_cache)?,
            ),
            (
                "guild-dynamic-state".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&initial_dynamic)?,
            ),
        ])?;
        Ok(())
    }

    pub fn adopt_recovered_guild(
        &mut self,
        certificate: QuorumGuildGenesis,
        mut peers: Vec<GuildPeer>,
    ) -> Result<()> {
        certificate.verify()?;
        let local_member = certificate
            .genesis
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("recovered guild does not contain this seed identity")?
            .clone();
        if local_member.recovery_public_key != self.keys.recovery_public_key() {
            anyhow::bail!("recovered guild has the wrong recovery key for this seed");
        }
        let local_signature = certificate
            .signatures
            .iter()
            .find(|signature| signature.signer == self.keys.node_id())
            .cloned()
            .context("recovered guild certificate omits this seed's signature")?;
        peers.sort_by_key(|peer| peer.member.node_id);
        if peers.len() != 5
            || peers
                .iter()
                .map(|peer| &peer.member)
                .ne(certificate.genesis.members.iter())
        {
            anyhow::bail!("recovered endpoint roster does not match guild membership");
        }
        for peer in &peers {
            if !peer.endpoints.is_empty() {
                validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
            }
        }
        let lock = GenesisSignatureLock {
            format_version: 1,
            genesis_hash: certificate.hash()?,
            genesis: certificate.genesis.clone(),
            signature: local_signature,
        };
        let installed = InstalledGuild {
            format_version: 2,
            certificate,
        };
        let initial_dynamic = initial_dynamic_guild_state(&installed)?;
        if let Some(existing) = self.installed_guild()?
            && existing != installed
        {
            anyhow::bail!("this node already has different guild state");
        }
        let dynamic_state = self.dynamic_guild_state()?;
        if let Some(state) = &dynamic_state {
            validate_dynamic_state_origin(state, &initial_dynamic)?;
        }
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            let configured: Member = decode_canonical(&bytes)?;
            if configured != local_member {
                anyhow::bail!("configured member conflicts with recovered guild membership");
            }
        }
        let endpoint_cache = self.merged_guild_endpoint_cache(&installed, peers)?;
        let mut records = vec![
            (
                "node-config".to_owned(),
                b"member".to_vec(),
                canonical_bytes(&local_member)?,
            ),
            (
                "guild-genesis-signature-lock".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&lock)?,
            ),
            (
                "guild-installed".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&installed)?,
            ),
            (
                "guild-endpoints".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&endpoint_cache)?,
            ),
            (
                "dht-recovery-sequence-probe".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&true)?,
            ),
        ];
        if dynamic_state.is_none() {
            records.push((
                "guild-dynamic-state".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&initial_dynamic)?,
            ));
        }
        self.control.put_records(&records)?;
        Ok(())
    }

    pub fn adopt_recovered_dynamic_guild(
        &mut self,
        certificate: QuorumGuildGenesis,
        checkpoint: &QuorumCheckpoint,
        events: Vec<QuorumGuildEvent>,
        mut peers: Vec<GuildPeer>,
        transcripts: Vec<SignedRecord<CodingVerificationTranscript>>,
    ) -> Result<()> {
        certificate.verify()?;
        checkpoint.verify()?;
        let installed = InstalledGuild {
            format_version: 2,
            certificate,
        };
        let guild_id = installed.certificate.genesis.guild_id;
        if !matches!(checkpoint.checkpoint.format_version, 4..=7)
            || checkpoint.checkpoint.guild_id != guild_id
            || checkpoint.checkpoint.genesis_hash != installed.certificate.hash()?
        {
            anyhow::bail!("dynamic recovery checkpoint is not bound to its guild genesis");
        }
        let mut state = initial_dynamic_guild_state(&installed)?;
        let mut authority_states = BTreeMap::from([(state.membership_epoch, state.clone())]);
        let mut checkpoint_membership =
            checkpoint_matches_dynamic_authority(&checkpoint.checkpoint, &state);
        let mut event_records = Vec::with_capacity(events.len());
        for event in events {
            let record_id = event.event.sequence.to_be_bytes().to_vec();
            state.apply_event(&event)?;
            authority_states
                .entry(state.membership_epoch)
                .or_insert_with(|| state.clone());
            checkpoint_membership |=
                checkpoint_matches_dynamic_authority(&checkpoint.checkpoint, &state);
            event_records.push((
                "guild-event".to_owned(),
                record_id,
                canonical_bytes(&event)?,
            ));
        }
        if !checkpoint_membership {
            anyhow::bail!("dynamic recovery checkpoint membership is absent from event history");
        }
        let local_id = self.keys.node_id();
        let local_member = state
            .members
            .iter()
            .find(|member| member.member.node_id == local_id && member.is_active())
            .map(|member| member.member.clone())
            .context("recovered dynamic guild does not authorize this seed identity")?;
        if local_member.recovery_public_key != self.keys.recovery_public_key()
            || checkpoint.checkpoint.format_version < 5 && !checkpoint.has_signature(local_id)
            || !checkpoint.checkpoint.members.iter().any(|member| {
                member.node_id == local_id
                    && member.recovery_public_key == self.keys.recovery_public_key()
            })
        {
            anyhow::bail!("dynamic recovery authority does not match this seed");
        }
        peers.sort_by_key(|peer| peer.member.node_id);
        if peers
            .iter()
            .map(|peer| &peer.member)
            .ne(state.members.iter().map(|member| &member.member))
        {
            anyhow::bail!("recovered endpoint roster does not match dynamic membership");
        }
        for peer in &peers {
            if !peer.endpoints.is_empty() {
                validate_endpoint_set(peer.member.node_id, &peer.endpoints)?;
            }
        }
        let transcript_by_group = transcripts
            .into_iter()
            .map(|transcript| (transcript.value.manifest.value.group.id, transcript))
            .collect::<BTreeMap<_, _>>();
        if transcript_by_group.len() != state.coding_groups.len() {
            anyhow::bail!("dynamic recovery has incomplete or extra coding evidence");
        }
        let mut transcript_records = Vec::with_capacity(transcript_by_group.len() * 2);
        for retained in &state.coding_groups {
            let transcript = transcript_by_group
                .get(&retained.group.id)
                .context("dynamic recovery coding transcript is unavailable")?;
            let authority = authority_states
                .get(&transcript.value.plan.value.membership_epoch)
                .context("coding transcript membership epoch is absent from event history")?;
            authority.validate_attempt_authority(&transcript.value.plan.value)?;
            if transcript.value.manifest.value.group != retained.group
                || replay_coding_transcript(transcript)? != CodingReplayFinding::Verified
            {
                anyhow::bail!("dynamic recovery coding transcript is invalid");
            }
            let bytes = canonical_bytes(transcript)?;
            transcript_records.push((
                "coding-transcript".to_owned(),
                transcript.value.plan.value.attempt_id.to_vec(),
                bytes.clone(),
            ));
            transcript_records.push((
                "coding-group-transcript".to_owned(),
                retained.group.id.to_vec(),
                bytes,
            ));
        }
        if let Some(existing) = self.installed_guild()?
            && existing != installed
        {
            anyhow::bail!("this node already has different guild state");
        }
        if let Some(existing) = self.dynamic_guild_state()?
            && existing != state
        {
            anyhow::bail!("this node already has a different dynamic guild history");
        }
        if let Some(bytes) = self.control.get_record("node-config", b"member")? {
            let configured: Member = decode_canonical(&bytes)?;
            if configured != local_member {
                anyhow::bail!("configured member conflicts with recovered dynamic membership");
            }
        }
        for (kind, record_id, bytes) in event_records.iter().chain(&transcript_records) {
            if self
                .control
                .get_record(kind, record_id)?
                .is_some_and(|existing| existing.as_slice() != bytes.as_slice())
            {
                anyhow::bail!("dynamic recovery conflicts with durable guild history");
            }
        }
        let mut endpoint_map = match self.guild_endpoint_cache()? {
            Some(cache) => {
                if cache.format_version != 1 || cache.guild_id != guild_id {
                    anyhow::bail!("cached guild endpoints belong to different guild state");
                }
                cache.endpoints.into_iter().collect::<BTreeMap<_, _>>()
            }
            None => BTreeMap::new(),
        };
        for peer in peers {
            if !peer.endpoints.is_empty() {
                endpoint_map.insert(peer.member.node_id, peer.endpoints);
            } else {
                endpoint_map.entry(peer.member.node_id).or_default();
            }
        }
        let endpoint_cache = GuildEndpointCache {
            format_version: 1,
            guild_id,
            endpoints: state
                .members
                .iter()
                .map(|member| {
                    (
                        member.member.node_id,
                        endpoint_map
                            .remove(&member.member.node_id)
                            .unwrap_or_default(),
                    )
                })
                .collect(),
        };
        let mut records = vec![
            (
                "node-config".to_owned(),
                b"member".to_vec(),
                canonical_bytes(&local_member)?,
            ),
            (
                "guild-installed".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&installed)?,
            ),
            (
                "guild-endpoints".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&endpoint_cache)?,
            ),
            (
                "guild-dynamic-state".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&state)?,
            ),
            (
                "dht-recovery-sequence-probe".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&true)?,
            ),
        ];
        if let Some(signature) = installed
            .certificate
            .signatures
            .iter()
            .find(|signature| signature.signer == local_id)
        {
            records.push((
                "guild-genesis-signature-lock".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&GenesisSignatureLock {
                    format_version: 1,
                    genesis_hash: installed.certificate.hash()?,
                    genesis: installed.certificate.genesis.clone(),
                    signature: signature.clone(),
                })?,
            ));
        }
        records.extend(event_records);
        records.extend(transcript_records);
        self.control.put_records(&records)?;
        Ok(())
    }

    pub fn guild_summary(&self) -> Result<Option<GuildSummary>> {
        if let Some(installed) = self.installed_guild()? {
            let dynamic = self.dynamic_guild_state()?;
            let (coordinator, peers, membership_epoch, event_sequence, quorum) = match dynamic {
                Some(state) => (
                    dynamic_guild_coordinator(&installed, &state)?,
                    self.dynamic_guild_peers(&installed, &state)?,
                    Some(state.membership_epoch),
                    Some(state.event_sequence),
                    Some(state.quorum),
                ),
                None => (
                    installed.certificate.genesis.coordinator,
                    self.guild_peers(&installed)?,
                    None,
                    None,
                    None,
                ),
            };
            return Ok(Some(GuildSummary {
                format_version: 2,
                guild_id: installed.certificate.genesis.guild_id,
                coordinator,
                phase: GuildPhase::Active,
                peers,
                membership_epoch,
                event_sequence,
                quorum,
            }));
        }
        if let Some(draft) = self.guild_draft()? {
            return Ok(Some(summary_from_draft(&draft)));
        }
        if let Some(pending) = self.pending_guild()? {
            return Ok(Some(GuildSummary {
                format_version: 2,
                guild_id: pending.invite.value.guild_id,
                coordinator: pending.invite.value.coordinator.node_id,
                phase: GuildPhase::Joining,
                peers: vec![
                    GuildPeer {
                        member: pending.invite.value.coordinator,
                        endpoints: pending.invite.value.coordinator_endpoints,
                    },
                    pending.local_peer,
                ],
                membership_epoch: None,
                event_sequence: None,
                quorum: None,
            }));
        }
        Ok(None)
    }

    pub fn dynamic_guild_state(&self) -> Result<Option<DynamicGuildState>> {
        let state = self
            .control
            .get_record("guild-dynamic-state", b"primary")?
            .map(|bytes| decode_canonical::<DynamicGuildState>(&bytes))
            .transpose()?;
        if let Some(state) = &state {
            state.validate()?;
        }
        Ok(state)
    }

    pub fn sign_guild_event_proposal(&self, event: &GuildEvent) -> Result<MemberSignature> {
        if matches!(event.kind, mb_core::GuildEventKind::AddCodingGroup { .. }) {
            anyhow::bail!("coding-group events require replayable verifier evidence");
        }
        self.sign_guild_event_proposal_inner(event)
    }

    pub fn sign_coding_group_event_proposal(
        &self,
        event: &GuildEvent,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<MemberSignature> {
        self.validate_coding_group_event_evidence(event, transcript)?;
        self.sign_guild_event_proposal_inner(event)
    }

    fn sign_guild_event_proposal_inner(&self, event: &GuildEvent) -> Result<MemberSignature> {
        let event_hash = event.hash()?;
        let record_id = event.sequence.to_be_bytes();
        if let Some(bytes) = self
            .control
            .get_record("guild-event-signature-lock", &record_id)?
        {
            let lock: GuildEventSignatureLock = decode_canonical(&bytes)?;
            if lock.format_version != 1 || lock.event_hash != event_hash || lock.event != *event {
                anyhow::bail!("local seed has already signed a conflicting guild event");
            }
            return Ok(lock.signature);
        }
        let state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        state.validate_event_proposal(event)?;
        if !state
            .active_members()
            .any(|member| member.node_id == self.keys.node_id())
        {
            anyhow::bail!("local node is not an active guild member");
        }
        let signature = sign_guild_event(event, &self.keys)?;
        let lock = GuildEventSignatureLock {
            format_version: 1,
            event_hash,
            event: event.clone(),
            signature: signature.clone(),
        };
        if !self.control.put_record_if_absent(
            "guild-event-signature-lock",
            &record_id,
            &canonical_bytes(&lock)?,
        )? {
            anyhow::bail!("local seed has already signed a guild event at this sequence");
        }
        Ok(signature)
    }

    pub fn install_guild_event(&mut self, certified: QuorumGuildEvent) -> Result<()> {
        if matches!(
            certified.event.kind,
            mb_core::GuildEventKind::AddCodingGroup { .. }
        ) {
            anyhow::bail!("coding-group events require replayable verifier evidence");
        }
        self.install_guild_event_inner(certified, None)
    }

    pub fn install_coding_group_event(
        &mut self,
        certified: QuorumGuildEvent,
        transcript: SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        self.validate_coding_group_event_evidence(&certified.event, &transcript)?;
        self.install_guild_event_inner(certified, Some(transcript))
    }

    fn install_guild_event_inner(
        &mut self,
        certified: QuorumGuildEvent,
        transcript: Option<SignedRecord<CodingVerificationTranscript>>,
    ) -> Result<()> {
        let mut state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        let sequence = certified.event.sequence;
        let record_id = sequence.to_be_bytes();
        let encoded = canonical_bytes(&certified)?;
        if sequence <= state.event_sequence {
            let existing = self
                .control
                .get_record("guild-event", &record_id)?
                .context("dynamic guild state omits a historical event")?;
            if existing != encoded {
                anyhow::bail!("guild event conflicts with installed history");
            }
            if let Some(transcript) = transcript {
                let attempt_id = transcript.value.plan.value.attempt_id;
                self.persist_coding_group_transcript(&transcript)?;
                self.volumes.finalize_attempt(&self.control, &attempt_id)?;
            }
            return Ok(());
        }
        if let Some(existing) = self.control.get_record("guild-event", &record_id)?
            && existing != encoded
        {
            anyhow::bail!("guild event conflicts with durable history");
        }
        let invalidates_placement_audit = matches!(
            &certified.event.kind,
            mb_core::GuildEventKind::RemoveMember { .. }
                | mb_core::GuildEventKind::RelabelMember { .. }
        );
        state.apply_event(&certified)?;
        if invalidates_placement_audit {
            // Invalidate before committing the valid event so an interruption
            // cannot leave a pre-change Healthy report attached to the
            // unchanged checkpoint hash.
            self.control.delete_record("node-state", b"guild-audit")?;
        }
        let mut records = vec![
            ("guild-event".to_owned(), record_id.to_vec(), encoded),
            (
                "guild-dynamic-state".to_owned(),
                b"primary".to_vec(),
                canonical_bytes(&state)?,
            ),
        ];
        let attempt_id = transcript
            .as_ref()
            .map(|transcript| transcript.value.plan.value.attempt_id);
        if let Some(transcript) = transcript {
            self.validate_coding_transcript_storage_conflicts(&transcript)?;
            let bytes = canonical_bytes(&transcript)?;
            records.push((
                "coding-transcript".to_owned(),
                transcript.value.plan.value.attempt_id.to_vec(),
                bytes.clone(),
            ));
            records.push((
                "coding-group-transcript".to_owned(),
                transcript.value.manifest.value.group.id.to_vec(),
                bytes,
            ));
        }
        self.control.put_records(&records)?;
        if let Some(attempt_id) = attempt_id {
            self.volumes.finalize_attempt(&self.control, &attempt_id)?;
        }
        Ok(())
    }

    fn validate_coding_group_event_evidence(
        &self,
        event: &GuildEvent,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let mb_core::GuildEventKind::AddCodingGroup { group } = &event.kind else {
            anyhow::bail!("coding evidence was supplied for another guild event kind");
        };
        self.validate_coding_attempt_authority(&transcript.value.plan)?;
        if replay_coding_transcript(transcript)? != CodingReplayFinding::Verified
            || transcript.value.manifest.value.group != *group
        {
            anyhow::bail!("guild coding-group event has invalid verifier evidence");
        }
        Ok(())
    }

    fn validate_coding_transcript_storage_conflicts(
        &self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let bytes = canonical_bytes(transcript)?;
        for (kind, id) in [
            (
                "coding-transcript",
                transcript.value.plan.value.attempt_id.as_slice(),
            ),
            (
                "coding-group-transcript",
                transcript.value.manifest.value.group.id.as_slice(),
            ),
        ] {
            if self
                .control
                .get_record(kind, id)?
                .is_some_and(|existing| existing != bytes)
            {
                anyhow::bail!("coding group already has conflicting verifier evidence");
            }
        }
        Ok(())
    }

    fn persist_coding_group_transcript(
        &mut self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        self.validate_coding_transcript_storage_conflicts(transcript)?;
        let bytes = canonical_bytes(transcript)?;
        self.control.put_records(&[
            (
                "coding-transcript".to_owned(),
                transcript.value.plan.value.attempt_id.to_vec(),
                bytes.clone(),
            ),
            (
                "coding-group-transcript".to_owned(),
                transcript.value.manifest.value.group.id.to_vec(),
                bytes,
            ),
        ])?;
        Ok(())
    }

    pub fn guild_event_tail(
        &self,
        base_sequence: u64,
        base_head: [u8; 32],
    ) -> Result<GuildEventTail> {
        guild_event_tail_from_store(&self.control, base_sequence, base_head)
    }

    pub(crate) fn coding_transcript_for_group(
        &self,
        guild_id: [u8; 32],
        group_id: [u8; 32],
    ) -> Result<SignedRecord<CodingVerificationTranscript>> {
        let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(
            &self
                .control
                .get_record("coding-group-transcript", &group_id)?
                .context("coding-group verifier transcript is unavailable")?,
        )?;
        if transcript.value.manifest.value.group.guild_id != guild_id
            || transcript.value.manifest.value.group.id != group_id
            || replay_coding_transcript(&transcript)? != CodingReplayFinding::Verified
        {
            anyhow::bail!("stored coding-group verifier transcript is invalid");
        }
        Ok(transcript)
    }

    pub fn pending_guild_join(&self) -> Result<Option<(SignedRecord<GuildInvite>, GuildPeer)>> {
        Ok(self
            .pending_guild()?
            .map(|pending| (pending.invite, pending.local_peer)))
    }

    pub fn cancel_pending_guild_join(&mut self) -> Result<()> {
        if !self.control.delete_record("guild-pending", b"primary")? {
            anyhow::bail!("this node has no pending guild join to cancel");
        }
        Ok(())
    }

    pub fn installed_guild_certificate(&self) -> Result<Option<QuorumGuildGenesis>> {
        Ok(self.installed_guild()?.map(|guild| guild.certificate))
    }

    pub fn guild_coordinator(&self, guild_id: &[u8; 32]) -> Result<Option<NodeId>> {
        guild_coordinator(&self.control, guild_id)
    }

    pub fn prepare_protected_backup(
        &mut self,
        requested_root_id: Option<Uuid>,
    ) -> Result<BackupDescriptor> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let guild_id = installed.certificate.genesis.guild_id;
        let root = match requested_root_id {
            Some(root_id) => self.protected_root_by_id(root_id)?,
            None => match self.next_dirty_root()? {
                Some(root) => root,
                None => self
                    .protected_roots()?
                    .into_iter()
                    .next()
                    .context("this node has no protected root")?,
            },
        };
        let current_filesystem = filesystem_identity(&root.path)?;
        let root_metadata = fs::symlink_metadata(&root.path)?;
        #[cfg(unix)]
        let root_inode = {
            use std::os::unix::fs::MetadataExt;
            root_metadata.ino()
        };
        #[cfg(not(unix))]
        let root_inode = 0;
        if !root_metadata.is_dir()
            || root_metadata.file_type().is_symlink()
            || !root.matches_identity(current_filesystem, root_inode)
        {
            anyhow::bail!("protected root identity changed");
        }
        let local_head = self
            .control
            .get_record(
                "user-revision-head",
                &revision_head_id(guild_id, root.root_id),
            )?
            .map(|bytes| decode_canonical::<SignedRecord<UserRevision>>(&bytes))
            .transpose()?;
        let committed_sequence = self
            .control
            .checkpoint_head(&guild_id)?
            .map(|(_, _, bytes)| decode_canonical::<QuorumCheckpoint>(&bytes))
            .transpose()?
            .and_then(|checkpoint| {
                checkpoint
                    .checkpoint
                    .revisions
                    .into_iter()
                    .filter(|revision| {
                        revision.value.owner == self.keys.node_id()
                            && revision.value.protected_root_id == root.root_id
                    })
                    .map(|revision| revision.value.sequence)
                    .max()
            })
            .unwrap_or(0);
        let sequence = match &local_head {
            Some(revision)
                if revision.value.sequence.checked_sub(1) == Some(committed_sequence) =>
            {
                revision.value.sequence
            }
            Some(revision) if revision.value.sequence == committed_sequence => committed_sequence
                .checked_add(1)
                .context("revision sequence exhausted")?,
            None if committed_sequence == 0 => 1,
            _ => anyhow::bail!("local revision head is inconsistent with the guild checkpoint"),
        };
        let revision_id = local_head
            .filter(|revision| revision.value.sequence == sequence)
            .map(|revision| revision.value.revision_id)
            .unwrap_or_else(|| {
                deterministic_revision_id(guild_id, self.keys.node_id(), root.root_id, sequence)
            });
        let revision = self.prepare_revision(
            guild_id,
            root.root_id,
            &root.path,
            sequence,
            Some(*revision_id.as_bytes()),
        )?;
        let bytes = canonical_bytes(&revision)?;
        let total_pages = bytes.len().div_ceil(V1_CATALOG_PAGE_BYTES);
        if total_pages == 0 || total_pages > V1_MAX_CATALOG_PAGES as usize {
            anyhow::bail!("prepared revision exceeds the catalog paging limit");
        }
        Ok(BackupDescriptor {
            format_version: 2,
            guild_id,
            owner: self.keys.node_id(),
            protected_root_id: root.root_id,
            revision_id,
            total_pages: total_pages as u32,
            object_hash: *blake3::hash(&bytes).as_bytes(),
        })
    }

    pub fn enqueue_backup(
        &mut self,
        caller: NodeId,
        descriptor: BackupDescriptor,
    ) -> Result<BackupJob> {
        validate_backup_descriptor(&descriptor)?;
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let state = self
            .dynamic_guild_state()?
            .context("this node has no dynamic guild state")?;
        if dynamic_guild_coordinator(&installed, &state)? != self.keys.node_id()
            || installed.certificate.genesis.guild_id != descriptor.guild_id
            || descriptor.owner != caller
            || !state
                .active_members()
                .any(|member| member.node_id == caller)
        {
            anyhow::bail!("backup submission is not authorized for this coordinator");
        }
        if let Some(bytes) = self
            .control
            .get_record("backup-job", descriptor.revision_id.as_bytes())?
        {
            let mut existing: BackupJob = decode_canonical(&bytes)?;
            if existing.descriptor != descriptor {
                anyhow::bail!("backup job identity conflicts with a prior submission");
            }
            if existing.state == BackupJobState::Failed {
                existing.state = BackupJobState::Pending;
                existing.error = None;
                self.put_backup_job(&existing)?;
            }
            return Ok(existing);
        }
        let job = BackupJob {
            format_version: 1,
            descriptor,
            state: BackupJobState::Pending,
            checkpoint_hash: None,
            error: None,
        };
        self.put_backup_job(&job)?;
        Ok(job)
    }

    pub fn backup_job(&self, guild_id: [u8; 32], revision_id: Uuid) -> Result<BackupJob> {
        backup_job(&self.control, guild_id, revision_id)
    }

    pub fn claim_backup_job(&mut self) -> Result<Option<BackupJob>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let state = self
            .dynamic_guild_state()?
            .context("this node has no dynamic guild state")?;
        if dynamic_guild_coordinator(&installed, &state)? != self.keys.node_id() {
            return Ok(None);
        }
        for (_, bytes) in self.control.records("backup-job")? {
            let mut job: BackupJob = decode_canonical(&bytes)?;
            if matches!(job.state, BackupJobState::Pending | BackupJobState::Running) {
                job.state = BackupJobState::Running;
                job.error = None;
                self.put_backup_job(&job)?;
                return Ok(Some(job));
            }
        }
        Ok(None)
    }

    pub fn complete_backup_job(
        &mut self,
        descriptor: &BackupDescriptor,
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup completion conflicts with the durable job");
        }
        job.state = BackupJobState::Committed;
        job.checkpoint_hash = Some(checkpoint_hash);
        job.error = None;
        self.put_backup_job(&job)
    }

    pub fn fail_backup_job(&mut self, descriptor: &BackupDescriptor, error: &str) -> Result<()> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup failure conflicts with the durable job");
        }
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        job.state = BackupJobState::Failed;
        job.error = Some(error);
        self.put_backup_job(&job)
    }

    pub fn retry_failed_backup_job(&mut self, descriptor: &BackupDescriptor) -> Result<BackupJob> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup retry conflicts with the durable job");
        }
        if job.state == BackupJobState::Failed {
            job.state = BackupJobState::Pending;
            job.error = None;
            self.put_backup_job(&job)?;
        }
        Ok(job)
    }

    pub fn current_checkpoint(&self, guild_id: [u8; 32]) -> Result<Option<QuorumCheckpoint>> {
        self.control
            .checkpoint_head(&guild_id)?
            .map(|(_, _, bytes)| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn prepared_revision_bytes(
        &self,
        guild_id: [u8; 32],
        revision_id: Uuid,
    ) -> Result<Vec<u8>> {
        let bytes = self
            .control
            .get_record("user-revision", revision_id.as_bytes())?
            .context("prepared revision is unavailable")?;
        let revision: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        revision.verify(USER_REVISION_DOMAIN)?;
        revision.value.verify_writer()?;
        if revision.value.guild_id != guild_id || revision.value.revision_id != revision_id {
            anyhow::bail!("prepared revision has the wrong guild or revision identity");
        }
        Ok(bytes)
    }

    pub fn defer_backup_job(&mut self, descriptor: &BackupDescriptor, error: &str) -> Result<()> {
        let mut job = self.backup_job(descriptor.guild_id, descriptor.revision_id)?;
        if job.descriptor != *descriptor {
            anyhow::bail!("backup retry conflicts with the durable job");
        }
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        job.state = BackupJobState::Pending;
        job.error = Some(error);
        self.put_backup_job(&job)
    }

    fn put_backup_job(&self, job: &BackupJob) -> Result<()> {
        self.control.put_record(
            "backup-job",
            job.descriptor.revision_id.as_bytes(),
            &canonical_bytes(job)?,
        )?;
        Ok(())
    }

    fn configured_member(&self) -> Result<Member> {
        decode_canonical(
            &self
                .control
                .get_record("node-config", b"member")?
                .context("node failure domain has not been configured")?,
        )
        .map_err(Into::into)
    }

    fn guild_draft(&self) -> Result<Option<GuildDraft>> {
        self.control
            .get_record("guild-draft", b"primary")?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn pending_guild(&self) -> Result<Option<PendingGuild>> {
        self.control
            .get_record("guild-pending", b"primary")?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn installed_guild(&self) -> Result<Option<InstalledGuild>> {
        self.control
            .get_record("guild-installed", b"primary")?
            .map(|bytes| decode_installed_guild(&bytes))
            .transpose()
    }

    fn guild_endpoint_cache(&self) -> Result<Option<GuildEndpointCache>> {
        self.control
            .get_record("guild-endpoints", b"primary")?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    fn merged_guild_endpoint_cache(
        &self,
        installed: &InstalledGuild,
        peers: Vec<GuildPeer>,
    ) -> Result<GuildEndpointCache> {
        let guild_id = installed.certificate.genesis.guild_id;
        let mut endpoints = match self.guild_endpoint_cache()? {
            Some(cache) => {
                if cache.format_version != 1 || cache.guild_id != guild_id {
                    anyhow::bail!("cached guild endpoints belong to different guild state");
                }
                cache.endpoints.into_iter().collect::<BTreeMap<_, _>>()
            }
            None => BTreeMap::new(),
        };
        for peer in peers {
            if !installed
                .certificate
                .genesis
                .members
                .iter()
                .any(|member| member.node_id == peer.member.node_id)
            {
                anyhow::bail!("endpoint cache contains a nonmember");
            }
            if !peer.endpoints.is_empty() {
                endpoints.insert(peer.member.node_id, peer.endpoints);
            } else {
                endpoints.entry(peer.member.node_id).or_default();
            }
        }
        Ok(GuildEndpointCache {
            format_version: 1,
            guild_id,
            endpoints: installed
                .certificate
                .genesis
                .members
                .iter()
                .map(|member| {
                    (
                        member.node_id,
                        endpoints.remove(&member.node_id).unwrap_or_default(),
                    )
                })
                .collect(),
        })
    }

    fn guild_peers(&self, installed: &InstalledGuild) -> Result<Vec<GuildPeer>> {
        if installed.format_version != 2 {
            anyhow::bail!("unsupported installed guild format version");
        }
        let cache = self
            .guild_endpoint_cache()?
            .context("installed guild has no endpoint cache")?;
        if cache.format_version != 1
            || cache.guild_id != installed.certificate.genesis.guild_id
            || cache.endpoints.len() != installed.certificate.genesis.members.len()
        {
            anyhow::bail!("installed guild endpoint cache is inconsistent");
        }
        let mut endpoints = cache.endpoints.into_iter().collect::<BTreeMap<_, _>>();
        if endpoints.len() != installed.certificate.genesis.members.len() {
            anyhow::bail!("installed guild endpoint cache contains duplicate members");
        }
        installed
            .certificate
            .genesis
            .members
            .iter()
            .map(|member| {
                let endpoints = endpoints
                    .remove(&member.node_id)
                    .context("installed guild endpoint cache omits a member")?;
                if !endpoints.is_empty() {
                    validate_endpoint_set(member.node_id, &endpoints)?;
                }
                Ok(GuildPeer {
                    member: member.clone(),
                    endpoints,
                })
            })
            .collect()
    }

    fn dynamic_guild_peers(
        &self,
        installed: &InstalledGuild,
        state: &DynamicGuildState,
    ) -> Result<Vec<GuildPeer>> {
        if state.guild_id != installed.certificate.genesis.guild_id {
            anyhow::bail!("dynamic membership belongs to another guild");
        }
        let cache = self
            .guild_endpoint_cache()?
            .context("installed guild has no endpoint cache")?;
        if cache.format_version != 1 || cache.guild_id != state.guild_id {
            anyhow::bail!("installed guild endpoint cache is inconsistent");
        }
        let mut endpoints = cache.endpoints.into_iter().collect::<BTreeMap<_, _>>();
        state
            .active_members()
            .map(|member| {
                let endpoints = endpoints.remove(&member.node_id).unwrap_or_default();
                if !endpoints.is_empty() {
                    validate_endpoint_set(member.node_id, &endpoints)?;
                }
                Ok(GuildPeer {
                    member: member.clone(),
                    endpoints,
                })
            })
            .collect()
    }

    fn ensure_no_guild_state(&self) -> Result<()> {
        if self.guild_draft()?.is_some()
            || self.pending_guild()?.is_some()
            || self.installed_guild()?.is_some()
        {
            anyhow::bail!("this node already has guild state");
        }
        Ok(())
    }

    pub fn begin_coordinator_commit(
        &mut self,
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
    ) -> Result<[u8; 32]> {
        if let Some(bytes) = self
            .control
            .get_record("coordinator-commit-intent", &intent_id)?
        {
            let journal: CoordinatorCommitJournal = decode_canonical(&bytes)?;
            if journal.format_version != 2
                || journal.intent_id != intent_id
                || journal.plan_hash != plan_hash
            {
                anyhow::bail!("coordinator commit journal is inconsistent");
            }
            return Ok(journal.guild_id);
        }
        let mut guild_id = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut guild_id);
        let journal = CoordinatorCommitJournal {
            format_version: 2,
            intent_id,
            plan_hash,
            guild_id,
            checkpoint_hash: None,
        };
        self.control.put_record(
            "coordinator-commit-intent",
            &intent_id,
            &canonical_bytes(&journal)?,
        )?;
        Ok(guild_id)
    }

    pub fn complete_coordinator_commit(
        &mut self,
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("coordinator-commit-intent", &intent_id)?
            .context("coordinator commit journal is unavailable")?;
        let mut journal: CoordinatorCommitJournal = decode_canonical(&bytes)?;
        if journal.format_version != 2
            || journal.intent_id != intent_id
            || journal.plan_hash != plan_hash
            || journal.guild_id != guild_id
            || journal
                .checkpoint_hash
                .is_some_and(|stored| stored != checkpoint_hash)
        {
            anyhow::bail!("coordinator commit completion conflicts with durable state");
        }
        let checkpoint = self.checkpoint(&checkpoint_hash)?;
        if checkpoint.checkpoint.guild_id != guild_id {
            anyhow::bail!("coordinator commit checkpoint belongs to another guild");
        }
        journal.checkpoint_hash = Some(checkpoint_hash);
        self.control.put_record(
            "coordinator-commit-intent",
            &intent_id,
            &canonical_bytes(&journal)?,
        )?;
        Ok(())
    }

    pub fn prepare_revision(
        &mut self,
        guild_id: [u8; 32],
        protected_root_id: Uuid,
        source_root: &Path,
        sequence: u64,
        operation_id: Option<[u8; 16]>,
    ) -> Result<SignedRecord<UserRevision>> {
        let captured_change_sequence = self
            .root_dirty_state(protected_root_id)?
            .filter(|state| state.dirty)
            .map(|state| state.change_sequence);
        let writer = self.writer_incarnation(guild_id)?;
        prepare_revision(
            &mut self.control,
            &self.keys,
            guild_id,
            protected_root_id,
            source_root,
            sequence,
            operation_id.map(Uuid::from_bytes),
            WriterCredentials {
                epoch: writer.epoch,
                secret: &writer.secret_key,
                captured_change_sequence,
            },
        )
    }

    fn writer_incarnation(&mut self, guild_id: [u8; 32]) -> Result<LocalWriterIncarnation> {
        let current = self.current_checkpoint(guild_id)?;
        let current_hash = current.as_ref().map(QuorumCheckpoint::hash).transpose()?;
        let latest = current
            .as_ref()
            .and_then(|checkpoint| {
                checkpoint
                    .checkpoint
                    .writer_fences
                    .iter()
                    .filter(|fence| fence.owner == self.keys.node_id())
                    .max_by_key(|fence| fence.epoch)
            })
            .cloned();
        if let Some(bytes) = self.control.get_record("writer-incarnation", &guild_id)? {
            let writer: LocalWriterIncarnation = decode_canonical(&bytes)?;
            let derived = ed25519_dalek::SigningKey::from_bytes(&writer.secret_key)
                .verifying_key()
                .to_bytes();
            if writer.format_version != 1 || writer.epoch == 0 || writer.public_key != derived {
                anyhow::bail!("durable writer incarnation is invalid");
            }
            let is_current = latest.as_ref().is_some_and(|fence| {
                fence.epoch == writer.epoch && fence.public_key == writer.public_key
            });
            let is_pending = latest.as_ref().map_or(writer.epoch == 1, |fence| {
                fence.epoch.checked_add(1) == Some(writer.epoch)
            });
            if is_current || is_pending {
                return Ok(writer);
            }
            anyhow::bail!(
                "local writer incarnation is fenced; recover into fresh state before taking over"
            );
        }

        let epoch = latest
            .as_ref()
            .map(|fence| fence.epoch)
            .unwrap_or(0)
            .checked_add(1)
            .context("writer incarnation epoch exhausted")?;
        let mut secret_key = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret_key);
        let public_key = ed25519_dalek::SigningKey::from_bytes(&secret_key)
            .verifying_key()
            .to_bytes();
        let writer = LocalWriterIncarnation {
            format_version: 1,
            epoch,
            public_key,
            secret_key,
            base_checkpoint: current_hash,
        };
        self.control
            .put_record("writer-incarnation", &guild_id, &canonical_bytes(&writer)?)?;
        Ok(writer)
    }

    pub fn ensure_filler(
        &mut self,
        guild_id: [u8; 32],
        revision_id: Uuid,
        ordinal: u64,
    ) -> Result<(SectorRef, Vec<u8>)> {
        let (reference, bytes) = synthetic_filler_sector(
            &self.keys.guild_data_key(&guild_id),
            self.keys.node_id(),
            revision_id,
            ordinal,
        )?;
        install_inline_recipe(&mut self.control, guild_id, reference.clone(), Vec::new())?;
        Ok((reference, bytes))
    }

    pub fn sector(&self, sector_id: &SectorId) -> Result<Vec<u8>> {
        render_sector(&self.control, &self.keys, sector_id, None)
    }

    pub fn sector_for_guild(&self, guild_id: &[u8; 32], sector_id: &SectorId) -> Result<Vec<u8>> {
        render_sector(&self.control, &self.keys, sector_id, Some(guild_id))
            .or_else(|_| load_packed_sector(&self.control, guild_id, sector_id))
    }

    pub(crate) fn store_packing_result(
        &mut self,
        guild_id: [u8; 32],
        result: &PackingResult,
    ) -> Result<()> {
        result.validate()?;
        let mut records = Vec::with_capacity(result.sectors.len());
        for sector in &result.sectors {
            records.push((
                "packed-sector".to_owned(),
                packed_record_id(&guild_id, &sector.descriptor.id),
                canonical_bytes(&PackedSectorRecord {
                    format_version: 1,
                    guild_id,
                    sector: sector.clone(),
                })?,
            ));
        }
        self.control.put_records(&records)?;
        Ok(())
    }

    pub(crate) fn store_packed_sector(
        &mut self,
        guild_id: [u8; 32],
        profile: PackingProfile,
        sector: PackedSector,
    ) -> Result<()> {
        validate_packed_sector(profile, &sector)?;
        self.control.put_record(
            "packed-sector",
            &packed_record_id(&guild_id, &sector.descriptor.id),
            &canonical_bytes(&PackedSectorRecord {
                format_version: 1,
                guild_id,
                sector,
            })?,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn local_sector_is_inline(&self, sector_id: &SectorId) -> Result<bool> {
        crate::snapshot::local_recipe_is_inline(&self.control, sector_id)
    }

    #[cfg(test)]
    pub(crate) fn make_control_query_only(&self) -> Result<()> {
        self.control.make_query_only()?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn forget_local_sector(&self, sector_id: &SectorId) -> Result<()> {
        if !self.control.delete_record("local-sector", sector_id)? {
            anyhow::bail!("local sector recipe is unavailable");
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn forget_local_parity(
        &mut self,
        group: &mb_core::CodingGroup,
        shard_index: u8,
    ) -> Result<()> {
        let role = group
            .roles
            .get(shard_index as usize)
            .context("test parity index is outside its group")?;
        let ShardRole::Parity(parity) = role else {
            anyhow::bail!("test parity removal requires a parity role");
        };
        if parity.holder != self.keys.node_id() {
            anyhow::bail!("test parity removal is not assigned to the local node");
        }
        if !self
            .volumes
            .remove_unreachable(&self.control, &group.id, shard_index, &parity.root)?
        {
            anyhow::bail!("test parity volume is offline");
        }
        self.control.delete_record(
            "local-parity-proof",
            &parity_proof_id(&group.id, shard_index),
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn restore_job_count(&self) -> Result<usize> {
        Ok(self.control.records("restore-job")?.len())
    }

    #[cfg(test)]
    pub(crate) fn emergency_shard_count(&self) -> Result<usize> {
        Ok(self.control.records("emergency-shard")?.len())
    }

    pub fn sign_coding_attempt_plan(
        &self,
        plan: CodingAttemptPlan,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        if plan.delegator != self.keys.node_id() {
            anyhow::bail!("only the named delegator may sign a coding attempt");
        }
        let signed = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, &self.keys)?;
        self.validate_coding_attempt_plan(&signed)?;
        Ok(signed)
    }

    pub(crate) fn enqueue_coding_launch(
        &self,
        plan: SignedRecord<CodingAttemptPlan>,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        self.validate_coding_attempt_plan(&plan)?;
        if plan.value.delegator != self.keys.node_id() {
            anyhow::bail!("only the coding delegator may queue its launch");
        }
        let attempt_id = plan.value.attempt_id;
        if let Some(bytes) = self.control.get_record("coding-launch-job", &attempt_id)? {
            let mut existing: CodingLaunchJob = decode_canonical(&bytes)?;
            if existing.format_version != 1
                || existing.plan.value.attempt_id != attempt_id
                || existing.plan.value.checkpoint_hash != plan.value.checkpoint_hash
                || existing.plan.value.geometry != plan.value.geometry
                || existing.plan.value.delegator != plan.value.delegator
                || existing.plan.value.coding_coordinator != plan.value.coding_coordinator
                || existing.plan.value.verification_coordinator
                    != plan.value.verification_coordinator
            {
                anyhow::bail!("coding launch conflicts with a durable attempt");
            }
            existing.dispatched = false;
            existing.error = None;
            self.put_coding_launch_job(&existing)?;
            return Ok(existing.plan);
        }
        self.put_coding_launch_job(&CodingLaunchJob {
            format_version: 1,
            plan: plan.clone(),
            dispatched: false,
            error: None,
        })?;
        Ok(plan)
    }

    pub(crate) fn claim_coding_launch(&self) -> Result<Option<CodingLaunchJob>> {
        let records = self.control.records("coding-launch-job")?;
        if records.is_empty() {
            return Ok(None);
        }
        let current_membership_epoch = self
            .dynamic_guild_state()?
            .context("coding launch requires dynamic guild state")?
            .membership_epoch;
        let mut stale = None;
        for (_, bytes) in records {
            let job: CodingLaunchJob = decode_canonical(&bytes)?;
            if job.format_version != 1
                || job.plan.value.delegator != self.keys.node_id()
                || job.plan.value.attempt_id == [0; 16]
            {
                anyhow::bail!("durable coding launch job is invalid");
            }
            self.validate_coding_attempt_authority(&job.plan)?;
            if job.plan.value.membership_epoch != current_membership_epoch {
                stale.get_or_insert(job);
            } else if !job.dispatched {
                return Ok(Some(job));
            }
        }
        Ok(stale)
    }

    pub(crate) fn coding_checkpoint_has_pending(&self, checkpoint_hash: [u8; 32]) -> Result<bool> {
        for (_, bytes) in self.control.records("coding-launch-job")? {
            let job: CodingLaunchJob = decode_canonical(&bytes)?;
            if job.format_version != 1 {
                anyhow::bail!("durable coding launch job is invalid");
            }
            if job.plan.value.checkpoint_hash == checkpoint_hash {
                return Ok(true);
            }
        }
        for (_, bytes) in self.control.records("coding-activation-job")? {
            let job: CodingActivationJob = decode_canonical(&bytes)?;
            if job.format_version != 1 {
                anyhow::bail!("durable coding activation job is invalid");
            }
            if !job.complete && job.transcript.value.plan.value.checkpoint_hash == checkpoint_hash {
                return Ok(true);
            }
        }
        for (_, bytes) in self.control.records("coding-retry-job")? {
            let job: CodingRetryJob = decode_canonical(&bytes)?;
            if job.format_version != 1 {
                anyhow::bail!("durable coding retry job is invalid");
            }
            if !job.complete && job.failure.value.plan.value.checkpoint_hash == checkpoint_hash {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn backup_commit_in_progress(&self, guild_id: [u8; 32]) -> Result<bool> {
        for (_, bytes) in self.control.records("backup-job")? {
            let job: BackupJob = decode_canonical(&bytes)?;
            validate_backup_descriptor(&job.descriptor)?;
            if job.format_version != 1 {
                anyhow::bail!("durable backup job is invalid");
            }
            if job.descriptor.guild_id == guild_id && job.state == BackupJobState::Running {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn complete_coding_launch(&self, attempt_id: [u8; 16]) -> Result<()> {
        self.update_coding_launch(attempt_id, true, None)
    }

    pub(crate) fn abandon_coding_launch(&self, attempt_id: [u8; 16]) -> Result<()> {
        self.control
            .delete_record("coding-launch-job", &attempt_id)?;
        Ok(())
    }

    pub(crate) fn defer_coding_launch(&self, attempt_id: [u8; 16], error: &str) -> Result<()> {
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        self.update_coding_launch(attempt_id, false, Some(error))
    }

    fn update_coding_launch(
        &self,
        attempt_id: [u8; 16],
        dispatched: bool,
        error: Option<String>,
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("coding-launch-job", &attempt_id)?
            .context("coding launch job is unavailable")?;
        let mut job: CodingLaunchJob = decode_canonical(&bytes)?;
        if job.format_version != 1 || job.plan.value.attempt_id != attempt_id {
            anyhow::bail!("durable coding launch job is invalid");
        }
        job.dispatched = dispatched;
        job.error = error;
        self.put_coding_launch_job(&job)
    }

    fn put_coding_launch_job(&self, job: &CodingLaunchJob) -> Result<()> {
        self.control.put_record(
            "coding-launch-job",
            &job.plan.value.attempt_id,
            &canonical_bytes(job)?,
        )?;
        Ok(())
    }

    pub fn enqueue_delegated_coding(
        &self,
        caller: NodeId,
        plan: SignedRecord<CodingAttemptPlan>,
    ) -> Result<()> {
        self.validate_coding_attempt_plan(&plan)?;
        if caller != plan.value.delegator || plan.value.coding_coordinator != self.keys.node_id() {
            anyhow::bail!("coding attempt was not delegated to this node");
        }
        let id = plan.value.attempt_id;
        if let Some(bytes) = self.control.get_record("delegated-coding-job", &id)? {
            let existing: DelegatedCodingJob = decode_canonical(&bytes)?;
            if existing.format_version != 1 || existing.plan != plan {
                anyhow::bail!("coding attempt ID conflicts with a prior delegation");
            }
            return Ok(());
        }
        self.put_delegated_coding_job(&DelegatedCodingJob {
            format_version: 1,
            plan,
            state: DelegatedCodingJobState::Pending,
            transcript: None,
            error: None,
        })
    }

    pub(crate) fn claim_delegated_coding(&self) -> Result<Option<DelegatedCodingJob>> {
        let records = self.control.records("delegated-coding-job")?;
        if records.is_empty() {
            return Ok(None);
        }
        let current_membership_epoch = self
            .dynamic_guild_state()?
            .context("delegated coding requires dynamic guild state")?
            .membership_epoch;
        let mut stale = None;
        for (_, bytes) in records {
            let mut job: DelegatedCodingJob = decode_canonical(&bytes)?;
            if job.format_version != 1 || job.plan.value.coding_coordinator != self.keys.node_id() {
                anyhow::bail!("durable delegated coding job is invalid");
            }
            if job.plan.value.membership_epoch != current_membership_epoch {
                self.validate_coding_attempt_authority(&job.plan)?;
                stale.get_or_insert(job);
                continue;
            }
            if job.state == DelegatedCodingJobState::Cleanup {
                return Ok(Some(job));
            }
            if job.state == DelegatedCodingJobState::Submitting {
                if job.transcript.is_none() {
                    anyhow::bail!("coding submission job has no verifier transcript");
                }
                return Ok(Some(job));
            }
            if job.state == DelegatedCodingJobState::ReportingFailure {
                return Ok(Some(job));
            }
            if job.state == DelegatedCodingJobState::Running {
                self.validate_coding_attempt_authority(&job.plan)?;
                job.state = DelegatedCodingJobState::Cleanup;
                job.error = Some("coding attempt was interrupted before verification".to_owned());
                self.put_delegated_coding_job(&job)?;
                return Ok(Some(job));
            }
            if job.state == DelegatedCodingJobState::Pending {
                if let Err(error) = self.validate_coding_attempt_plan(&job.plan) {
                    job.state = DelegatedCodingJobState::Cleanup;
                    job.error = Some(format!(
                        "coding attempt became ineligible before verification: {error:#}"
                    ));
                    self.put_delegated_coding_job(&job)?;
                    return Ok(Some(job));
                }
                job.state = DelegatedCodingJobState::Running;
                job.error = None;
                self.put_delegated_coding_job(&job)?;
                return Ok(Some(job));
            }
        }
        Ok(stale)
    }

    pub(crate) fn encode_delegated_coding(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        information: Vec<Option<Vec<u8>>>,
    ) -> Result<(SignedRecord<CodingRootManifest>, Vec<Vec<u8>>)> {
        self.validate_coding_attempt_plan(plan)?;
        if plan.value.coding_coordinator != self.keys.node_id() {
            anyhow::bail!("coding attempt is assigned to another coordinator");
        }
        encode_coding_attempt(plan, information, &self.keys).map_err(Into::into)
    }

    pub(crate) fn complete_delegated_coding(&self, attempt_id: [u8; 16]) -> Result<()> {
        self.update_delegated_coding_job(attempt_id, DelegatedCodingJobState::Complete, None)
    }

    pub(crate) fn record_delegated_coding_result(
        &self,
        attempt_id: [u8; 16],
        transcript: SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("delegated-coding-job", &attempt_id)?
            .context("delegated coding job is unavailable")?;
        let mut job: DelegatedCodingJob = decode_canonical(&bytes)?;
        if job.plan != transcript.value.plan || transcript.value.plan.value.attempt_id != attempt_id
        {
            anyhow::bail!("coding result conflicts with its durable job");
        }
        replay_coding_transcript(&transcript)?;
        job.state = DelegatedCodingJobState::Submitting;
        job.transcript = Some(transcript);
        job.error = None;
        self.put_delegated_coding_job(&job)
    }

    pub(crate) fn record_delegated_coding_failure(
        &mut self,
        attempt_id: [u8; 16],
        error: &str,
    ) -> Result<SignedRecord<CodingFailureReport>> {
        let bytes = self
            .control
            .get_record("delegated-coding-job", &attempt_id)?
            .context("delegated coding job is unavailable")?;
        let mut job: DelegatedCodingJob = decode_canonical(&bytes)?;
        if job.format_version != 1
            || job.plan.value.attempt_id != attempt_id
            || job.plan.value.coding_coordinator != self.keys.node_id()
        {
            anyhow::bail!("delegated coding job cannot report this failure");
        }
        self.validate_coding_attempt_authority(&job.plan)?;
        let mut error_hash = *blake3::hash(error.as_bytes()).as_bytes();
        if error_hash == [0; 32] {
            error_hash[0] = 1;
        }
        let report = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: job.plan.clone(),
                error_hash,
            },
            &self.keys,
        )?;
        report.value.validate()?;
        job.state = DelegatedCodingJobState::ReportingFailure;
        job.error = Some({
            let mut error = error.to_owned();
            truncate_utf8(&mut error, 4096);
            error
        });
        self.control.put_records(&[
            (
                "delegated-coding-failure".to_owned(),
                attempt_id.to_vec(),
                canonical_bytes(&report)?,
            ),
            (
                "delegated-coding-job".to_owned(),
                attempt_id.to_vec(),
                canonical_bytes(&job)?,
            ),
        ])?;
        Ok(report)
    }

    pub(crate) fn delegated_coding_failure(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<SignedRecord<CodingFailureReport>> {
        let report: SignedRecord<CodingFailureReport> = decode_canonical(
            &self
                .control
                .get_record("delegated-coding-failure", &attempt_id)?
                .context("delegated coding failure report is unavailable")?,
        )?;
        report.verify(CODING_FAILURE_REPORT_DOMAIN)?;
        report.value.validate()?;
        if report.value.plan.value.attempt_id != attempt_id
            || report.signer != report.value.plan.value.coding_coordinator
        {
            anyhow::bail!("delegated coding failure report conflicts with its attempt");
        }
        Ok(report)
    }

    pub(crate) fn cleanup_delegated_coding(&self, attempt_id: [u8; 16], error: &str) -> Result<()> {
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        self.update_delegated_coding_job(attempt_id, DelegatedCodingJobState::Cleanup, Some(error))
    }

    fn update_delegated_coding_job(
        &self,
        attempt_id: [u8; 16],
        state: DelegatedCodingJobState,
        error: Option<String>,
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("delegated-coding-job", &attempt_id)?
            .context("delegated coding job is unavailable")?;
        let mut job: DelegatedCodingJob = decode_canonical(&bytes)?;
        job.state = state;
        job.error = error;
        self.put_delegated_coding_job(&job)
    }

    fn put_delegated_coding_job(&self, job: &DelegatedCodingJob) -> Result<()> {
        self.control.put_record(
            "delegated-coding-job",
            &job.plan.value.attempt_id,
            &canonical_bytes(job)?,
        )?;
        Ok(())
    }

    pub fn commit_coding_challenge(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<SignedRecord<CodingChallengeCommitment>> {
        self.validate_coding_attempt_plan(plan)?;
        if plan.value.verification_coordinator != self.keys.node_id() {
            anyhow::bail!("coding challenge is assigned to another verifier");
        }
        let plan_hash = plan.value.hash()?;
        if let Some(bytes) = self
            .control
            .get_record("coding-verifier-challenge", &plan.value.attempt_id)?
        {
            let state: VerifierChallengeState = decode_canonical(&bytes)?;
            if state.format_version != 1
                || state.attempt_id != plan.value.attempt_id
                || state.plan_hash != plan_hash
            {
                anyhow::bail!("coding attempt already has a conflicting hidden challenge");
            }
            state
                .commitment
                .verify(CODING_CHALLENGE_COMMITMENT_DOMAIN)?;
            return Ok(state.commitment);
        }
        let mut nonce = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let commitment = SignedRecord::sign(
            CODING_CHALLENGE_COMMITMENT_DOMAIN,
            CodingChallengeCommitment {
                format_version: 1,
                attempt_id: plan.value.attempt_id,
                plan_hash,
                commitment: coding_challenge_commitment(plan_hash, nonce),
            },
            &self.keys,
        )?;
        self.control.put_record_if_absent(
            "coding-verifier-challenge",
            &plan.value.attempt_id,
            &canonical_bytes(&VerifierChallengeState {
                format_version: 1,
                attempt_id: plan.value.attempt_id,
                plan_hash,
                nonce,
                commitment: commitment.clone(),
            })?,
        )?;
        Ok(commitment)
    }

    pub fn reveal_coding_challenge(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        manifest: &SignedRecord<CodingRootManifest>,
        receipts: &[SignedRecord<StagedStorageReceipt>],
    ) -> Result<SignedRecord<CodingChallengeReveal>> {
        self.validate_coding_attempt_plan(plan)?;
        if plan.value.verification_coordinator != self.keys.node_id() {
            anyhow::bail!("coding challenge is assigned to another verifier");
        }
        let plan_hash = plan.value.hash()?;
        manifest.verify(CODING_ROOT_MANIFEST_DOMAIN)?;
        if manifest.signer != plan.value.coding_coordinator
            || manifest.value.format_version != 1
            || manifest.value.attempt_id != plan.value.attempt_id
            || manifest.value.plan_hash != plan_hash
        {
            anyhow::bail!("coding root manifest or staged receipt set is invalid");
        }
        plan.value.geometry.validate_group(&manifest.value.group)?;
        let group = &manifest.value.group;
        if receipts.len() != usize::from(group.profile.parity_shards) {
            anyhow::bail!("coding root manifest or staged receipt set is invalid");
        }
        let parity_start = usize::from(group.profile.data_shards);
        for (offset, receipt) in receipts.iter().enumerate() {
            receipt.verify(STAGED_STORAGE_RECEIPT_DOMAIN)?;
            let index = parity_start + offset;
            let ShardRoleV2::Parity(parity) = &group.roles[index] else {
                anyhow::bail!("coding plan parity layout is invalid");
            };
            if receipt.signer != parity.holder
                || receipt.value.format_version != 1
                || receipt.value.attempt_id != plan.value.attempt_id
                || receipt.value.plan_hash != plan_hash
                || receipt.value.guild_id != group.guild_id
                || receipt.value.group_id != group.id
                || usize::from(receipt.value.shard_index) != index
                || receipt.value.holder != parity.holder
                || receipt.value.commitment != parity.commitment
            {
                anyhow::bail!("staged receipt set does not cover the delegated parity rows");
            }
        }
        let bytes = self
            .control
            .get_record("coding-verifier-challenge", &plan.value.attempt_id)?
            .context("verifier did not durably precommit this coding challenge")?;
        let state: VerifierChallengeState = decode_canonical(&bytes)?;
        if state.format_version != 1
            || state.attempt_id != plan.value.attempt_id
            || state.plan_hash != plan_hash
            || state.commitment.signer != self.keys.node_id()
        {
            anyhow::bail!("durable verifier challenge conflicts with the coding plan");
        }
        state
            .commitment
            .verify(CODING_CHALLENGE_COMMITMENT_DOMAIN)?;
        let evidence_hash = coding_evidence_hash(manifest, receipts)?;
        SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            CodingChallengeReveal {
                format_version: 1,
                attempt_id: plan.value.attempt_id,
                plan_hash,
                nonce: state.nonce,
                evidence_hash,
            },
            &self.keys,
        )
        .map_err(Into::into)
    }

    pub fn stage_coding_parity(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        manifest: &SignedRecord<CodingRootManifest>,
        object: &VariableParityObject,
    ) -> Result<SignedRecord<StagedStorageReceipt>> {
        self.validate_coding_attempt_plan(plan)?;
        let plan_hash = plan.value.hash()?;
        manifest.verify(CODING_ROOT_MANIFEST_DOMAIN)?;
        if manifest.signer != plan.value.coding_coordinator
            || manifest.value.attempt_id != plan.value.attempt_id
            || manifest.value.plan_hash != plan_hash
        {
            anyhow::bail!("coding root manifest conflicts with the delegated plan");
        }
        plan.value.geometry.validate_group(&manifest.value.group)?;
        let group = &manifest.value.group;
        let index = usize::from(object.shard_index);
        let Some(ShardRoleV2::Parity(role)) = group.roles.get(index) else {
            anyhow::bail!("coding attempt object is not a declared parity shard");
        };
        if role.holder != self.keys.node_id()
            || object.format_version != 2
            || object.guild_id != group.guild_id
            || object.group_id != group.id
            || object.commitment != role.commitment
            || merkle_commit(&object.bytes)? != role.commitment
        {
            anyhow::bail!("coding attempt parity object conflicts with its delegated plan");
        }
        let receipt = StagedStorageReceipt {
            format_version: 1,
            attempt_id: plan.value.attempt_id,
            plan_hash,
            guild_id: object.guild_id,
            group_id: object.group_id,
            shard_index: object.shard_index,
            holder: self.keys.node_id(),
            commitment: object.commitment.clone(),
        };
        let receipt = SignedRecord::sign(STAGED_STORAGE_RECEIPT_DOMAIN, receipt, &self.keys)?;
        self.volumes.stage_attempt(
            &self.control,
            &plan.value.attempt_id,
            object,
            &canonical_bytes(&receipt)?,
        )?;
        Ok(receipt)
    }

    pub fn reserve_coding_parity(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
    ) -> Result<u32> {
        self.validate_coding_attempt_plan(plan)?;
        let parity_start = usize::from(plan.value.geometry.profile.data_shards);
        let offset = usize::from(shard_index)
            .checked_sub(parity_start)
            .context("coding reservation is not a parity position")?;
        let placement = plan
            .value
            .geometry
            .parity
            .get(offset)
            .context("coding reservation is outside the delegated layout")?;
        if placement.holder != self.keys.node_id() {
            anyhow::bail!("coding reservation is assigned to another holder");
        }
        self.volumes.reserve_attempt(
            &self.control,
            &plan.value.attempt_id,
            plan.value.geometry.guild_id,
            shard_index,
            plan.value.geometry.profile.shard_size,
        )
    }

    pub fn reserve_coding_information(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
    ) -> Result<u32> {
        let role = self.validate_local_coding_information(plan, shard_index)?;
        if role.sector.virtual_zero {
            anyhow::bail!("virtual-zero information requires no storage reservation");
        }
        self.volumes.reserve_attempt(
            &self.control,
            &plan.value.attempt_id,
            plan.value.geometry.guild_id,
            shard_index,
            plan.value.geometry.profile.shard_size,
        )
    }

    pub fn write_coding_information_range(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
        offset: u32,
        bytes: &[u8],
    ) -> Result<u32> {
        let role = self.validate_local_coding_information(plan, shard_index)?;
        if role.sector.virtual_zero {
            anyhow::bail!("virtual-zero information requires no payload upload");
        }
        let end = u64::from(offset)
            .checked_add(bytes.len() as u64)
            .context("coding information range overflows")?;
        if end > u64::from(role.sector.commitment.byte_len) {
            anyhow::bail!("coding information range exceeds its committed shard");
        }
        self.volumes.write_attempt_range(
            &self.control,
            &plan.value.attempt_id,
            shard_index,
            offset,
            bytes,
        )
    }

    pub fn finish_coding_information_upload(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
    ) -> Result<()> {
        let role = self.validate_local_coding_information(plan, shard_index)?;
        if role.sector.virtual_zero {
            anyhow::bail!("virtual-zero information requires no payload upload");
        }
        self.volumes.finish_attempt_upload(
            &self.control,
            &plan.value.attempt_id,
            role.sector.id,
            shard_index,
            &role.sector.commitment,
        )?;
        Ok(())
    }

    pub fn coding_information_range(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
        start_leaf: u32,
        leaf_count: u32,
    ) -> Result<mb_core::MerkleRangeProof> {
        let role = self.validate_local_coding_information(plan, shard_index)?;
        if role.sector.virtual_zero {
            return Ok(merkle_open_zero_range(
                role.sector.commitment.byte_len,
                start_leaf,
                leaf_count,
            )?);
        }
        if let Ok(bytes) = self.sector_for_guild(&plan.value.geometry.guild_id, &role.sector.id) {
            if merkle_commit(&bytes)? != role.sector.commitment {
                anyhow::bail!("local information bytes conflict with the coding plan");
            }
            return Ok(merkle_open_range(&bytes, start_leaf, leaf_count)?);
        }
        self.volumes.open_attempt_range(
            &self.control,
            &plan.value.attempt_id,
            &role.sector.id,
            shard_index,
            start_leaf,
            leaf_count,
        )
    }

    fn validate_local_coding_information<'a>(
        &self,
        plan: &'a SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
    ) -> Result<&'a mb_core::InformationRoleV2> {
        self.validate_coding_attempt_plan(plan)?;
        if usize::from(shard_index) >= usize::from(plan.value.geometry.profile.data_shards) {
            anyhow::bail!("coding information index is outside the delegated layout");
        }
        let role = plan
            .value
            .geometry
            .information
            .get(usize::from(shard_index))
            .context("coding information index is outside the delegated layout")?;
        if role.owner != self.keys.node_id() {
            anyhow::bail!("coding information is assigned to another holder");
        }
        Ok(role)
    }

    pub fn write_coding_parity_range(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        manifest: &SignedRecord<CodingRootManifest>,
        shard_index: u16,
        offset: u32,
        bytes: &[u8],
    ) -> Result<u32> {
        let role = self.validate_local_coding_output(plan, manifest, shard_index)?;
        let end = u64::from(offset)
            .checked_add(bytes.len() as u64)
            .context("coding upload range overflows")?;
        if end > u64::from(role.commitment.byte_len) {
            anyhow::bail!("coding upload range exceeds its committed parity row");
        }
        self.volumes.write_attempt_range(
            &self.control,
            &plan.value.attempt_id,
            shard_index,
            offset,
            bytes,
        )
    }

    pub fn finish_coding_parity_upload(
        &mut self,
        plan: &SignedRecord<CodingAttemptPlan>,
        manifest: &SignedRecord<CodingRootManifest>,
        shard_index: u16,
    ) -> Result<SignedRecord<StagedStorageReceipt>> {
        let role = self.validate_local_coding_output(plan, manifest, shard_index)?;
        let plan_hash = plan.value.hash()?;
        let volume_receipt = self.volumes.finish_attempt_upload(
            &self.control,
            &plan.value.attempt_id,
            manifest.value.group.id,
            shard_index,
            &role.commitment,
        )?;
        if volume_receipt.guild_id != manifest.value.group.guild_id {
            anyhow::bail!("coding upload volume belongs to another guild");
        }
        let receipt = SignedRecord::sign(
            STAGED_STORAGE_RECEIPT_DOMAIN,
            StagedStorageReceipt {
                format_version: 1,
                attempt_id: plan.value.attempt_id,
                plan_hash,
                guild_id: manifest.value.group.guild_id,
                group_id: manifest.value.group.id,
                shard_index,
                holder: self.keys.node_id(),
                commitment: role.commitment.clone(),
            },
            &self.keys,
        )?;
        self.volumes.attach_attempt_receipt(
            &self.control,
            &plan.value.attempt_id,
            &manifest.value.group.id,
            shard_index,
            &canonical_bytes(&receipt)?,
        )?;
        Ok(receipt)
    }

    fn validate_local_coding_output<'a>(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        manifest: &'a SignedRecord<CodingRootManifest>,
        shard_index: u16,
    ) -> Result<&'a mb_core::ParityRoleV2> {
        self.validate_coding_attempt_plan(plan)?;
        let plan_hash = plan.value.hash()?;
        manifest.verify(CODING_ROOT_MANIFEST_DOMAIN)?;
        if manifest.signer != plan.value.coding_coordinator
            || manifest.value.format_version != 1
            || manifest.value.attempt_id != plan.value.attempt_id
            || manifest.value.plan_hash != plan_hash
        {
            anyhow::bail!("coding root manifest conflicts with the delegated plan");
        }
        plan.value.geometry.validate_group(&manifest.value.group)?;
        let Some(ShardRoleV2::Parity(role)) =
            manifest.value.group.roles.get(usize::from(shard_index))
        else {
            anyhow::bail!("coding upload is not a declared parity shard");
        };
        if role.holder != self.keys.node_id() {
            anyhow::bail!("coding upload is assigned to another holder");
        }
        Ok(role)
    }

    pub fn coding_shard_opening(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        manifest: &SignedRecord<CodingRootManifest>,
        challenge: [u8; 32],
        shard_index: u16,
    ) -> Result<SignedRecord<CodingShardOpening>> {
        self.validate_coding_attempt_plan(plan)?;
        let plan_hash = plan.value.hash()?;
        manifest.verify(CODING_ROOT_MANIFEST_DOMAIN)?;
        if manifest.signer != plan.value.coding_coordinator
            || manifest.value.attempt_id != plan.value.attempt_id
            || manifest.value.plan_hash != plan_hash
        {
            anyhow::bail!("coding root manifest conflicts with the delegated plan");
        }
        plan.value.geometry.validate_group(&manifest.value.group)?;
        let group = &manifest.value.group;
        let role = group
            .roles
            .get(usize::from(shard_index))
            .context("coding opening shard index is outside its group")?;
        let (holder, commitment) = match role {
            ShardRoleV2::Information(information) => {
                (information.owner, &information.sector.commitment)
            }
            ShardRoleV2::Parity(parity) => (parity.holder, &parity.commitment),
        };
        if holder != self.keys.node_id() {
            anyhow::bail!("coding opening is assigned to another holder");
        }
        let leaf = challenged_leaf(&challenge, commitment)?;
        let proof = match role {
            ShardRoleV2::Information(information) => {
                if information.sector.virtual_zero {
                    merkle_open_zero_range(information.sector.commitment.byte_len, leaf, 1)?
                } else {
                    match self.sector_for_guild(&group.guild_id, &information.sector.id) {
                        Ok(bytes) => {
                            if merkle_commit(&bytes)? != *commitment {
                                anyhow::bail!(
                                    "local information bytes conflict with the coding plan"
                                );
                            }
                            merkle_open_range(&bytes, leaf, 1)?
                        }
                        Err(_) => self.volumes.open_attempt_range(
                            &self.control,
                            &plan.value.attempt_id,
                            &information.sector.id,
                            shard_index,
                            leaf,
                            1,
                        )?,
                    }
                }
            }
            ShardRoleV2::Parity(_) => self.volumes.open_attempt_range(
                &self.control,
                &plan.value.attempt_id,
                &group.id,
                shard_index,
                leaf,
                1,
            )?,
        };
        SignedRecord::sign(
            CODING_SHARD_OPENING_DOMAIN,
            CodingShardOpening {
                format_version: 1,
                attempt_id: plan.value.attempt_id,
                plan_hash,
                verifier: plan.value.verification_coordinator,
                challenge,
                shard_index,
                commitment: commitment.clone(),
                proof,
            },
            &self.keys,
        )
        .map_err(Into::into)
    }

    pub fn sign_coding_transcript(
        &self,
        mut transcript: CodingVerificationTranscript,
    ) -> Result<SignedRecord<CodingVerificationTranscript>> {
        self.validate_coding_attempt_plan(&transcript.plan)?;
        let plan = &transcript.plan.value;
        let attempt_id = plan.attempt_id;
        let expires_at_unix_seconds = plan.expires_at_unix_seconds;
        if plan.verification_coordinator != self.keys.node_id()
            || transcript.challenge_commitment.signer != self.keys.node_id()
            || transcript.challenge_reveal.signer != self.keys.node_id()
        {
            anyhow::bail!("coding transcript is assigned to another verifier");
        }
        let state: VerifierChallengeState = decode_canonical(
            &self
                .control
                .get_record("coding-verifier-challenge", &attempt_id)?
                .context("verifier challenge state is unavailable")?,
        )?;
        if state.commitment != transcript.challenge_commitment
            || state.nonce != transcript.challenge_reveal.value.nonce
        {
            anyhow::bail!("coding transcript conflicts with the hidden challenge");
        }
        transcript.verified_at_unix_seconds = unix_seconds();
        if transcript.verified_at_unix_seconds > expires_at_unix_seconds {
            anyhow::bail!("coding attempt expired before verification completed");
        }
        let signed = SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, transcript, &self.keys)?;
        replay_coding_transcript(&signed)?;
        let bytes = canonical_bytes(&signed)?;
        if !self
            .control
            .put_record_if_absent("coding-verifier-transcript", &attempt_id, &bytes)?
            && self
                .control
                .get_record("coding-verifier-transcript", &attempt_id)?
                .as_deref()
                != Some(bytes.as_slice())
        {
            anyhow::bail!("verifier already signed different evidence for this attempt");
        }
        Ok(signed)
    }

    pub fn accept_coding_transcript(
        &self,
        caller: NodeId,
        transcript: SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let plan = &transcript.value.plan.value;
        self.validate_coding_attempt_authority(&transcript.value.plan)?;
        if plan.delegator != self.keys.node_id() || caller != plan.coding_coordinator {
            anyhow::bail!("coding result was not submitted to its delegator by its coordinator");
        }
        let id = plan.attempt_id;
        replay_coding_transcript(&transcript)?;
        if let Some(bytes) = self.control.get_record("coding-activation-job", &id)? {
            let existing: CodingActivationJob = decode_canonical(&bytes)?;
            if existing.format_version != 1 || existing.transcript != transcript {
                anyhow::bail!("coding attempt already has a different submitted result");
            }
            return Ok(());
        }
        self.put_coding_activation_job(&CodingActivationJob {
            format_version: 1,
            transcript,
            complete: false,
            error: None,
        })
    }

    pub fn accept_coding_failure(
        &self,
        caller: NodeId,
        failure: SignedRecord<CodingFailureReport>,
    ) -> Result<()> {
        failure.verify(CODING_FAILURE_REPORT_DOMAIN)?;
        failure.value.validate()?;
        let plan = &failure.value.plan;
        self.validate_coding_attempt_authority(plan)?;
        if failure.signer != plan.value.coding_coordinator
            || caller != failure.signer
            || plan.value.delegator != self.keys.node_id()
        {
            anyhow::bail!("coding failure was not submitted by its assigned coordinator");
        }
        let attempt_id = plan.value.attempt_id;
        if self
            .control
            .get_record("coding-activation-job", &attempt_id)?
            .is_some()
        {
            anyhow::bail!("verified coding evidence already exists for this attempt");
        }
        if let Some(bytes) = self.control.get_record("coding-retry-job", &attempt_id)? {
            let existing: CodingRetryJob = decode_canonical(&bytes)?;
            if existing.format_version != 1 || existing.failure != failure {
                anyhow::bail!("coding attempt already has a different failure report");
            }
            return Ok(());
        }
        self.put_coding_retry_job(&CodingRetryJob {
            format_version: 1,
            failure,
            retry_plan: None,
            complete: false,
            error: None,
        })?;
        self.control
            .delete_record("coding-launch-job", &attempt_id)?;
        Ok(())
    }

    pub(crate) fn claim_coding_retry(&self) -> Result<Option<CodingRetryJob>> {
        for (_, bytes) in self.control.records("coding-retry-job")? {
            let job: CodingRetryJob = decode_canonical(&bytes)?;
            if job.format_version != 1 {
                anyhow::bail!("durable coding retry job is invalid");
            }
            job.failure.verify(CODING_FAILURE_REPORT_DOMAIN)?;
            job.failure.value.validate()?;
            if job.failure.value.plan.value.delegator != self.keys.node_id()
                || job.failure.signer != job.failure.value.plan.value.coding_coordinator
            {
                anyhow::bail!("durable coding retry job belongs to another delegator");
            }
            if !job.complete {
                return Ok(Some(job));
            }
        }
        Ok(None)
    }

    pub(crate) fn prepare_coding_retry(
        &self,
        failed_attempt_id: [u8; 16],
        coding_coordinator: NodeId,
        verification_coordinator: NodeId,
        expires_at_unix_seconds: u64,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        let bytes = self
            .control
            .get_record("coding-retry-job", &failed_attempt_id)?
            .context("coding retry job is unavailable")?;
        let mut job: CodingRetryJob = decode_canonical(&bytes)?;
        if let Some(plan) = &job.retry_plan {
            return Ok(plan.clone());
        }
        let prior = &job.failure.value.plan.value;
        let state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        let mut attempt_id = [0_u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut attempt_id);
        if attempt_id == [0; 16] || attempt_id == prior.attempt_id {
            attempt_id[0] ^= 1;
        }
        let plan = SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            CodingAttemptPlan {
                format_version: prior.format_version,
                attempt_id,
                checkpoint_hash: prior.checkpoint_hash,
                membership_epoch: state.membership_epoch,
                geometry: prior.geometry.clone(),
                delegator: self.keys.node_id(),
                coding_coordinator,
                verification_coordinator,
                expires_at_unix_seconds,
                information_roots: prior.information_roots.clone(),
            },
            &self.keys,
        )?;
        self.validate_coding_attempt_plan(&plan)?;
        job.retry_plan = Some(plan.clone());
        job.error = None;
        self.put_coding_retry_job(&job)?;
        Ok(plan)
    }

    pub(crate) fn complete_coding_retry(&self, failed_attempt_id: [u8; 16]) -> Result<()> {
        self.update_coding_retry_job(failed_attempt_id, true, None)
    }

    pub(crate) fn defer_coding_retry(
        &self,
        failed_attempt_id: [u8; 16],
        error: &str,
    ) -> Result<()> {
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        self.update_coding_retry_job(failed_attempt_id, false, Some(error))
    }

    fn update_coding_retry_job(
        &self,
        failed_attempt_id: [u8; 16],
        complete: bool,
        error: Option<String>,
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("coding-retry-job", &failed_attempt_id)?
            .context("coding retry job is unavailable")?;
        let mut job: CodingRetryJob = decode_canonical(&bytes)?;
        job.complete = complete;
        job.error = error;
        self.put_coding_retry_job(&job)
    }

    fn put_coding_retry_job(&self, job: &CodingRetryJob) -> Result<()> {
        self.control.put_record(
            "coding-retry-job",
            &job.failure.value.plan.value.attempt_id,
            &canonical_bytes(job)?,
        )?;
        Ok(())
    }

    pub(crate) fn claim_coding_activation(&self) -> Result<Option<CodingActivationJob>> {
        let records = self.control.records("coding-activation-job")?;
        if records.is_empty() {
            return Ok(None);
        }
        let current_membership_epoch = self
            .dynamic_guild_state()?
            .context("coding activation requires dynamic guild state")?
            .membership_epoch;
        let mut stale = None;
        for (_, bytes) in records {
            let mut job: CodingActivationJob = decode_canonical(&bytes)?;
            if job.format_version != 1
                || job.transcript.value.plan.value.delegator != self.keys.node_id()
            {
                anyhow::bail!("durable coding activation job is invalid");
            }
            if !job.complete {
                self.validate_coding_attempt_authority(&job.transcript.value.plan)?;
                if job.transcript.value.plan.value.membership_epoch != current_membership_epoch {
                    stale.get_or_insert(job);
                    continue;
                }
                job.error = None;
                self.put_coding_activation_job(&job)?;
                return Ok(Some(job));
            }
        }
        Ok(stale)
    }

    pub(crate) fn complete_coding_activation(&self, attempt_id: [u8; 16]) -> Result<()> {
        self.update_coding_activation_job(attempt_id, true, None)?;
        self.control
            .delete_record("coding-launch-job", &attempt_id)?;
        Ok(())
    }

    pub(crate) fn defer_coding_activation(&self, attempt_id: [u8; 16], error: &str) -> Result<()> {
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        self.update_coding_activation_job(attempt_id, false, Some(error))
    }

    fn update_coding_activation_job(
        &self,
        attempt_id: [u8; 16],
        complete: bool,
        error: Option<String>,
    ) -> Result<()> {
        let bytes = self
            .control
            .get_record("coding-activation-job", &attempt_id)?
            .context("coding activation job is unavailable")?;
        let mut job: CodingActivationJob = decode_canonical(&bytes)?;
        job.complete = complete;
        job.error = error;
        self.put_coding_activation_job(&job)
    }

    fn put_coding_activation_job(&self, job: &CodingActivationJob) -> Result<()> {
        self.control.put_record(
            "coding-activation-job",
            &job.transcript.value.plan.value.attempt_id,
            &canonical_bytes(job)?,
        )?;
        Ok(())
    }

    pub fn activate_coding_attempt(
        &mut self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        if replay_coding_transcript(transcript)? != CodingReplayFinding::Verified {
            anyhow::bail!("coding transcript does not verify the delegated codeword");
        }
        let plan = &transcript.value.plan.value;
        let group = &transcript.value.manifest.value.group;
        self.validate_coding_attempt_authority(&transcript.value.plan)?;
        let group_committed = self.dynamic_guild_state()?.is_some_and(|state| {
            state
                .coding_groups
                .iter()
                .any(|retained| retained.group == *group)
        });
        let transcript_hash = *blake3::hash(&canonical_bytes(transcript)?).as_bytes();
        let mut activated = false;
        for (index, role) in group.roles.iter().enumerate() {
            match role {
                ShardRoleV2::Information(information)
                    if information.owner == self.keys.node_id() =>
                {
                    activated = true;
                    if information.sector.virtual_zero {
                        continue;
                    }
                    if group_committed
                        && self
                            .volumes
                            .load_ready_variable(
                                &self.control,
                                &information.sector.id,
                                index as u16,
                            )
                            .is_ok_and(|object| {
                                object.guild_id == group.guild_id
                                    && object.commitment == information.sector.commitment
                            })
                    {
                        continue;
                    }
                    if self
                        .sector_for_guild(&group.guild_id, &information.sector.id)
                        .is_ok_and(|bytes| {
                            merkle_commit(&bytes).ok().as_ref()
                                == Some(&information.sector.commitment)
                        })
                    {
                        continue;
                    }
                    self.volumes.activate_attempt_object(
                        &self.control,
                        &plan.attempt_id,
                        &information.sector.id,
                        index as u16,
                        &information.sector.commitment,
                        &transcript_hash,
                    )?;
                }
                ShardRoleV2::Parity(parity) if parity.holder == self.keys.node_id() => {
                    if group_committed
                        && self
                            .volumes
                            .load_ready_variable(&self.control, &group.id, index as u16)
                            .is_ok_and(|object| {
                                object.guild_id == group.guild_id
                                    && object.commitment == parity.commitment
                            })
                    {
                        activated = true;
                        continue;
                    }
                    self.volumes.activate_attempt_object(
                        &self.control,
                        &plan.attempt_id,
                        &group.id,
                        index as u16,
                        &parity.commitment,
                        &transcript_hash,
                    )?;
                    activated = true;
                }
                _ => {}
            }
        }
        if !activated {
            anyhow::bail!("coding attempt assigns no shard to the local node");
        }
        self.persist_coding_group_transcript(transcript)?;
        Ok(())
    }

    pub fn discard_coding_attempt(&mut self, attempt_id: &[u8; 16]) -> Result<bool> {
        if let Some(bytes) = self.control.get_record("coding-transcript", attempt_id)? {
            let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
            let group_id = transcript.value.manifest.value.group.id;
            if self.dynamic_guild_state()?.is_some_and(|state| {
                state
                    .coding_groups
                    .iter()
                    .any(|retained| retained.group.id == group_id)
            }) {
                self.volumes.finalize_attempt(&self.control, attempt_id)?;
                return Ok(true);
            }
        }
        self.volumes.discard_attempt(&self.control, attempt_id)
    }

    pub(crate) fn validate_coding_attempt_for_cleanup(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<()> {
        self.validate_coding_attempt_authority(plan)
    }

    pub fn variable_parity_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<VariableParityObject> {
        let object = self
            .volumes
            .load_ready_variable(&self.control, group_id, shard_index)?;
        if object.guild_id != *guild_id {
            anyhow::bail!("variable parity object belongs to another guild");
        }
        Ok(object)
    }

    pub fn variable_information_for_guild(
        &self,
        guild_id: &[u8; 32],
        sector_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<VariableParityObject> {
        let object = self
            .volumes
            .load_ready_variable(&self.control, sector_id, shard_index)?;
        if object.guild_id != *guild_id || object.group_id != *sector_id {
            anyhow::bail!("variable information object belongs to another guild or sector");
        }
        Ok(object)
    }

    pub fn variable_shard_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<Vec<u8>> {
        let state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        if state.guild_id != *guild_id {
            anyhow::bail!("variable coding group belongs to another guild");
        }
        let retained = state
            .coding_groups
            .iter()
            .find(|retained| retained.group.id == *group_id)
            .context("variable coding group is unavailable")?;
        let role = retained
            .group
            .roles
            .get(usize::from(shard_index))
            .context("variable shard index is outside its group")?;
        let (holder, commitment, storage_group) = match role {
            ShardRoleV2::Information(information) => {
                if information.sector.virtual_zero {
                    return Ok(vec![0; retained.group.profile.shard_size as usize]);
                }
                (
                    information.owner,
                    &information.sector.commitment,
                    information.sector.id,
                )
            }
            ShardRoleV2::Parity(parity) => (parity.holder, &parity.commitment, retained.group.id),
        };
        if holder != self.keys.node_id() {
            anyhow::bail!("variable shard is assigned to another holder");
        }
        let bytes = if let ShardRoleV2::Information(information) = role {
            match self.sector_for_guild(guild_id, &information.sector.id) {
                Ok(bytes) => bytes,
                Err(_) => {
                    self.volumes
                        .load_ready_variable(&self.control, &storage_group, shard_index)?
                        .bytes
                }
            }
        } else {
            self.volumes
                .load_ready_variable(&self.control, &storage_group, shard_index)?
                .bytes
        };
        if merkle_commit(&bytes)? != *commitment {
            anyhow::bail!("variable shard conflicts with its committed Merkle root");
        }
        Ok(bytes)
    }

    fn validate_coding_attempt_plan(&self, plan: &SignedRecord<CodingAttemptPlan>) -> Result<()> {
        self.validate_signed_coding_attempt(plan)?;
        let state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        state.validate_attempt(&plan.value, unix_seconds())?;
        Ok(())
    }

    fn validate_coding_attempt_authority(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<()> {
        self.validate_signed_coding_attempt(plan)?;
        let state = self.dynamic_guild_state_for_membership_epoch(plan.value.membership_epoch)?;
        state.validate_attempt_authority(&plan.value)?;
        Ok(())
    }

    fn dynamic_guild_state_for_membership_epoch(
        &self,
        membership_epoch: u64,
    ) -> Result<DynamicGuildState> {
        let installed = self
            .installed_guild()?
            .context("node has no installed guild")?;
        let durable = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        let mut replay = initial_dynamic_guild_state(&installed)?;
        let mut selected = (replay.membership_epoch == membership_epoch).then(|| replay.clone());
        for (record_id, bytes) in self.control.records("guild-event")? {
            let event: QuorumGuildEvent = decode_canonical(&bytes)?;
            if record_id != event.event.sequence.to_be_bytes() {
                anyhow::bail!("guild event history has an invalid record ID");
            }
            replay.apply_event(&event)?;
            if selected.is_none() && replay.membership_epoch == membership_epoch {
                selected = Some(replay.clone());
            }
        }
        if replay != durable {
            anyhow::bail!("dynamic guild state conflicts with its event history");
        }
        selected.context("coding attempt membership epoch is absent from guild history")
    }

    fn validate_signed_coding_attempt(&self, plan: &SignedRecord<CodingAttemptPlan>) -> Result<()> {
        plan.verify(CODING_ATTEMPT_PLAN_DOMAIN)?;
        plan.value.validate()?;
        if plan.signer != plan.value.delegator {
            anyhow::bail!("coding attempt delegation is invalid");
        }
        Ok(())
    }

    pub fn publish_verified_parity(
        &mut self,
        group: &mb_core::CodingGroup,
        information: &[Vec<u8>; 3],
        object: &ParityObject,
    ) -> Result<SignedRecord<StorageAcknowledgement>> {
        self.publish_verified_parity_with_operation(
            &parity_operation_id(&group.id, object.shard_index),
            group,
            information,
            object,
        )
    }

    pub fn publish_verified_parity_with_operation(
        &mut self,
        operation_id: &[u8; 16],
        group: &mb_core::CodingGroup,
        information: &[Vec<u8>; 3],
        object: &ParityObject,
    ) -> Result<SignedRecord<StorageAcknowledgement>> {
        self.validate_parity_assignment(group, object)?;
        group.verify_parity_shard(information, object.shard_index as usize, &object.bytes)?;
        let acknowledgement = StorageAcknowledgement {
            format_version: 1,
            operation_id: *operation_id,
            guild_id: object.guild_id,
            group_id: object.group_id,
            shard_index: object.shard_index,
            row: u16::from(object.shard_index - 3),
            root: object.root,
            holder: self.keys.node_id(),
        };
        acknowledgement.validate()?;
        let acknowledgement =
            SignedRecord::sign(STORAGE_ACKNOWLEDGEMENT_DOMAIN, acknowledgement, &self.keys)?;
        self.volumes
            .store(&self.control, object, &canonical_bytes(&acknowledgement)?)?;
        self.control.put_record(
            "local-parity-proof",
            &parity_proof_id(&group.id, object.shard_index),
            &canonical_bytes(group)?,
        )?;
        Ok(acknowledgement)
    }

    fn publish_validated_parity(
        &mut self,
        group: &mb_core::CodingGroup,
        object: &ParityObject,
    ) -> Result<()> {
        self.volumes.store(&self.control, object, &[])?;
        self.control.put_record(
            "local-parity-proof",
            &parity_proof_id(&group.id, object.shard_index),
            &canonical_bytes(group)?,
        )?;
        Ok(())
    }

    fn validate_parity_assignment(
        &self,
        group: &mb_core::CodingGroup,
        object: &ParityObject,
    ) -> Result<()> {
        let ShardRole::Parity(role) = group
            .roles
            .get(object.shard_index as usize)
            .context("parity shard index is out of range")?
        else {
            anyhow::bail!("parity object is assigned to an information role");
        };
        if group.calculate_id()? != group.id
            || group.guild_id != object.guild_id
            || group.format_version != object.format_version
            || group.id != object.group_id
            || role.holder != self.keys.node_id()
            || role.root != object.root
        {
            anyhow::bail!("parity object does not match its local coding-group assignment");
        }
        Ok(())
    }

    pub fn parity(&self, group_id: &[u8; 32], shard_index: u8) -> Result<Vec<u8>> {
        Ok(self.volumes.load_ready(group_id, shard_index)?.bytes)
    }

    pub fn parity_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>> {
        let object = self.volumes.load_ready(group_id, shard_index)?;
        if object.guild_id != *guild_id {
            anyhow::bail!("parity object does not belong to the requested guild");
        }
        Ok(object.bytes)
    }

    pub(crate) fn local_assigned_shard(
        &self,
        group: &mb_core::CodingGroup,
        shard_index: usize,
    ) -> Result<Vec<u8>> {
        let role = group
            .roles
            .get(shard_index)
            .context("audit shard index is outside its group")?;
        match role {
            ShardRole::Information(information) if information.owner == self.keys.node_id() => {
                self.sector_for_guild(&group.guild_id, &information.sector.id)
            }
            ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                self.parity_for_guild(&group.guild_id, &group.id, shard_index as u8)
            }
            _ => anyhow::bail!("audit shard is not assigned to the local node"),
        }
    }

    pub(crate) fn install_repaired_shard(
        &mut self,
        checkpoint_hash: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
        bytes: &[u8],
        emergency: bool,
    ) -> Result<()> {
        let checkpoint = self
            .current_checkpoint_from_hash(checkpoint_hash)?
            .context("repair checkpoint is unavailable")?;
        let group = checkpoint
            .checkpoint
            .coding_groups
            .iter()
            .find(|group| group.id == group_id)
            .context("repair group is not active in the current checkpoint")?;
        let role = group
            .roles
            .get(shard_index as usize)
            .context("repair shard index is outside its group")?;
        let expected_root = match role {
            ShardRole::Information(information) => information.sector.root,
            ShardRole::Parity(parity) => parity.root,
        };
        if bytes.len() != group.shard_size as usize || sector_root(bytes) != expected_root {
            anyhow::bail!("repaired shard failed its certified size or root");
        }
        let assigned_locally = match role {
            ShardRole::Information(information) => information.owner == self.keys.node_id(),
            ShardRole::Parity(parity) => parity.holder == self.keys.node_id(),
        };
        if !emergency && !assigned_locally {
            anyhow::bail!("ordinary repair is not assigned to the local node");
        }
        if emergency && assigned_locally {
            anyhow::bail!("an assigned holder cannot store its own emergency copy");
        }
        if !emergency && let ShardRole::Information(information) = role {
            return self.install_repaired_information_sector(
                group.guild_id,
                information.sector.clone(),
                bytes,
            );
        }
        let object = ParityObject {
            format_version: group.format_version,
            guild_id: group.guild_id,
            group_id,
            shard_index,
            root: expected_root,
            bytes: bytes.to_vec(),
        };
        let record_id = parity_proof_id(&group_id, shard_index).to_vec();
        let mut records = vec![(
            "local-parity-proof".to_owned(),
            record_id.clone(),
            canonical_bytes(group)?,
        )];
        if emergency {
            records.push((
                "emergency-shard".to_owned(),
                record_id,
                canonical_bytes(&EmergencyShardRecord {
                    format_version: 1,
                    checkpoint_hash,
                    group_id,
                    shard_index,
                    root: expected_root,
                })?,
            ));
        }
        // Persist the role classification first. If storage is interrupted, the
        // marker makes the partial repair discoverable and safe to retry or GC.
        self.control.put_records(&records)?;
        self.volumes.store_repair(&self.control, &object)?;
        Ok(())
    }

    pub(crate) fn remove_local_emergency_shards(
        &mut self,
        checkpoint_hash: [u8; 32],
        group: &mb_core::CodingGroup,
    ) -> Result<u64> {
        let current = self
            .current_checkpoint_from_hash(checkpoint_hash)?
            .context("emergency cleanup checkpoint is unavailable")?;
        if !current
            .checkpoint
            .coding_groups
            .iter()
            .any(|candidate| candidate == group)
        {
            anyhow::bail!("emergency cleanup group is not active");
        }
        let mut removed = 0_u64;
        for (record_id, bytes) in self.control.records("emergency-shard")? {
            let marker: EmergencyShardRecord = decode_canonical(&bytes)?;
            if marker.format_version != 1 || marker.group_id != group.id {
                continue;
            }
            let role = group
                .roles
                .get(marker.shard_index as usize)
                .context("emergency marker shard index is invalid")?;
            let expected_root = match role {
                ShardRole::Information(information) => information.sector.root,
                ShardRole::Parity(parity) => parity.root,
            };
            if marker.root != expected_root
                || record_id != parity_proof_id(&group.id, marker.shard_index)
            {
                anyhow::bail!("emergency marker conflicts with its certified group");
            }
            if !self.volumes.remove_unreachable(
                &self.control,
                &group.id,
                marker.shard_index,
                &marker.root,
            )? {
                continue;
            }
            self.control
                .delete_record("local-parity-proof", &record_id)?;
            self.control.delete_record("emergency-shard", &record_id)?;
            removed += 1;
        }
        Ok(removed)
    }

    pub(crate) fn install_repaired_variable_shard(
        &mut self,
        repair_id: [u8; 16],
        checkpoint_hash: [u8; 32],
        group_id: [u8; 32],
        shard_index: u16,
        bytes: &[u8],
        emergency: bool,
    ) -> Result<()> {
        if repair_id == [0; 16] {
            anyhow::bail!("repair operation ID must not be zero");
        }
        let (checkpoint, group, transcript) =
            self.current_variable_group(checkpoint_hash, group_id)?;
        let role = group
            .roles
            .get(usize::from(shard_index))
            .context("variable repair shard index is outside its group")?;
        let (assigned_holder, commitment) = match role {
            ShardRoleV2::Information(information) => {
                (information.owner, &information.sector.commitment)
            }
            ShardRoleV2::Parity(parity) => (parity.holder, &parity.commitment),
        };
        let assigned_locally = assigned_holder == self.keys.node_id();
        if emergency == assigned_locally {
            anyhow::bail!("variable repair role does not match the local assignment");
        }
        if bytes.len() != commitment.byte_len as usize || merkle_commit(bytes)? != *commitment {
            anyhow::bail!("variable repair shard conflicts with its certified commitment");
        }
        if !emergency && let ShardRoleV2::Information(information) = role {
            if information.sector.virtual_zero {
                anyhow::bail!("virtual-zero information requires no repair payload");
            }
            if let Some(catalog) = &checkpoint.checkpoint.packing_catalog {
                let descriptor = catalog
                    .sectors
                    .iter()
                    .find(|descriptor| {
                        descriptor.id == information.sector.id
                            && descriptor.commitment == information.sector.commitment
                    })
                    .context("packed information repair is not live in the checkpoint")?
                    .clone();
                return self.store_packed_sector(
                    group.guild_id,
                    catalog.profile,
                    PackedSector {
                        descriptor,
                        bytes: bytes.to_vec(),
                    },
                );
            }
            let reference = checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == information.owner)
                .flat_map(|revision| {
                    revision
                        .value
                        .metadata_sectors
                        .iter()
                        .chain(&revision.value.data_sectors)
                })
                .find(|reference| {
                    reference.id == information.sector.id
                        && reference.logical_len == information.sector.logical_len
                })
                .context("variable information repair is not live in the checkpoint")?
                .clone();
            if sector_root(bytes) != reference.root {
                anyhow::bail!("variable information repair conflicts with its signed revision");
            }
            return self.install_repaired_information_sector(group.guild_id, reference, bytes);
        }

        let marker_id = variable_emergency_id(&group.id, shard_index);
        let repair_id = match self.control.get_record("variable-repair", &marker_id)? {
            Some(bytes) => {
                let existing: VariableRepairRecord = decode_canonical(&bytes)?;
                if existing.format_version != 1
                    || existing.repair_id == [0; 16]
                    || existing.group_id != group.id
                    || existing.shard_index != shard_index
                    || existing.emergency != emergency
                    || existing.commitment != *commitment
                {
                    anyhow::bail!("variable repair conflicts with durable in-flight work");
                }
                existing.repair_id
            }
            None => {
                self.control.put_record(
                    "variable-repair",
                    &marker_id,
                    &canonical_bytes(&VariableRepairRecord {
                        format_version: 1,
                        repair_id,
                        group_id: group.id,
                        shard_index,
                        emergency,
                        commitment: commitment.clone(),
                    })?,
                )?;
                repair_id
            }
        };
        if emergency {
            self.control.put_record(
                "variable-emergency-shard",
                &marker_id,
                &canonical_bytes(&VariableEmergencyShardRecord {
                    format_version: 1,
                    checkpoint_hash,
                    group_id: group.id,
                    shard_index,
                    commitment: commitment.clone(),
                })?,
            )?;
        }
        let object = VariableParityObject {
            format_version: 2,
            guild_id: group.guild_id,
            group_id: group.id,
            shard_index,
            commitment: commitment.clone(),
            bytes: bytes.to_vec(),
        };
        if self
            .volumes
            .prepare_variable_repair(&self.control, &object)?
        {
            self.control.delete_record("variable-repair", &marker_id)?;
            return Ok(());
        }
        self.volumes.reserve_attempt(
            &self.control,
            &repair_id,
            group.guild_id,
            shard_index,
            commitment.byte_len,
        )?;
        let mut offset = 0_u32;
        for chunk in bytes.chunks(1024 * 1024) {
            offset = self.volumes.write_attempt_range(
                &self.control,
                &repair_id,
                shard_index,
                offset,
                chunk,
            )?;
        }
        if offset != commitment.byte_len {
            anyhow::bail!("variable repair upload is incomplete");
        }
        self.volumes.finish_attempt_upload(
            &self.control,
            &repair_id,
            group.id,
            shard_index,
            commitment,
        )?;
        let transcript_hash = blake3::hash(&canonical_bytes(&transcript)?);
        self.volumes.attach_attempt_receipt(
            &self.control,
            &repair_id,
            &group.id,
            shard_index,
            transcript_hash.as_bytes(),
        )?;
        self.volumes.activate_attempt_object(
            &self.control,
            &repair_id,
            &group.id,
            shard_index,
            commitment,
            transcript_hash.as_bytes(),
        )?;
        self.control.delete_record("variable-repair", &marker_id)?;
        Ok(())
    }

    pub(crate) fn variable_emergency_shard_for_guild(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<Vec<u8>> {
        let marker_id = variable_emergency_id(group_id, shard_index);
        let marker: VariableEmergencyShardRecord = decode_canonical(
            &self
                .control
                .get_record("variable-emergency-shard", &marker_id)?
                .context("variable emergency shard is unavailable")?,
        )?;
        let current = self
            .current_checkpoint_from_hash(marker.checkpoint_hash)?
            .context("variable emergency shard checkpoint is no longer current")?;
        if current.checkpoint.guild_id != *guild_id
            || marker.format_version != 1
            || marker.group_id != *group_id
            || marker.shard_index != shard_index
        {
            anyhow::bail!("variable emergency shard has invalid durable metadata");
        }
        let (_, group, _) = self.current_variable_group(marker.checkpoint_hash, *group_id)?;
        let commitment = match group.roles.get(usize::from(shard_index)) {
            Some(ShardRoleV2::Information(information)) => &information.sector.commitment,
            Some(ShardRoleV2::Parity(parity)) => &parity.commitment,
            None => anyhow::bail!("variable emergency shard index is outside its group"),
        };
        if marker.commitment != *commitment {
            anyhow::bail!("variable emergency shard conflicts with its certified group");
        }
        let object = self
            .volumes
            .load_ready_variable(&self.control, group_id, shard_index)?;
        if object.guild_id != *guild_id || object.commitment != *commitment {
            anyhow::bail!("variable emergency shard payload is invalid");
        }
        Ok(object.bytes)
    }

    pub(crate) fn remove_local_variable_emergency_shards(
        &mut self,
        checkpoint_hash: [u8; 32],
        group: &CodingGroupV2,
    ) -> Result<u64> {
        let (_, active, _) = self.current_variable_group(checkpoint_hash, group.id)?;
        if active != *group {
            anyhow::bail!("variable emergency cleanup group is not active");
        }
        let mut removed = 0_u64;
        for (record_id, bytes) in self.control.records("variable-emergency-shard")? {
            let marker: VariableEmergencyShardRecord = decode_canonical(&bytes)?;
            if marker.group_id != group.id {
                continue;
            }
            let commitment = match group.roles.get(usize::from(marker.shard_index)) {
                Some(ShardRoleV2::Information(information)) => &information.sector.commitment,
                Some(ShardRoleV2::Parity(parity)) => &parity.commitment,
                None => anyhow::bail!("variable emergency marker shard index is invalid"),
            };
            if marker.format_version != 1
                || marker.checkpoint_hash != checkpoint_hash
                || marker.commitment != *commitment
                || record_id != variable_emergency_id(&group.id, marker.shard_index)
            {
                anyhow::bail!("variable emergency marker conflicts with its certified group");
            }
            let index = u8::try_from(marker.shard_index)
                .context("variable emergency shard index exceeds local storage format")?;
            if !self.volumes.remove_unreachable(
                &self.control,
                &group.id,
                index,
                &marker.commitment.root,
            )? {
                continue;
            }
            self.control
                .delete_record("variable-emergency-shard", &record_id)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn current_variable_group(
        &self,
        checkpoint_hash: [u8; 32],
        group_id: [u8; 32],
    ) -> Result<(
        QuorumCheckpoint,
        CodingGroupV2,
        SignedRecord<CodingVerificationTranscript>,
    )> {
        let checkpoint = self
            .current_checkpoint_from_hash(checkpoint_hash)?
            .context("variable repair checkpoint is unavailable")?;
        let state = self
            .dynamic_guild_state()?
            .context("variable repair requires dynamic guild state")?;
        let group = state
            .coding_groups
            .iter()
            .find(|retained| retained.group.id == group_id)
            .context("variable repair group is not retained")?
            .group
            .clone();
        if !variable_group_protects_checkpoint(&checkpoint.checkpoint, &group) {
            anyhow::bail!("variable repair group protects no live checkpoint sector");
        }
        let transcript = self.coding_transcript_for_group(group.guild_id, group.id)?;
        Ok((checkpoint, group, transcript))
    }

    fn current_checkpoint_from_hash(
        &self,
        checkpoint_hash: [u8; 32],
    ) -> Result<Option<QuorumCheckpoint>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let checkpoint = self.current_checkpoint(installed.certificate.genesis.guild_id)?;
        if checkpoint
            .as_ref()
            .map(QuorumCheckpoint::hash)
            .transpose()?
            != Some(checkpoint_hash)
        {
            return Ok(None);
        }
        Ok(checkpoint)
    }

    pub fn store_checkpoint(&mut self, checkpoint: &QuorumCheckpoint) -> Result<[u8; 32]> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint, true)?;
        self.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, false)?;
        if !checkpoint.has_signature(self.keys.node_id()) {
            anyhow::bail!("local node did not authorize this checkpoint");
        }
        let hash = checkpoint.hash()?;
        let body = canonical_bytes(&checkpoint.checkpoint)?;
        let certificate = canonical_bytes(checkpoint)?;
        self.control.commit_checkpoint(
            &checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.generation,
            checkpoint.checkpoint.parent.as_ref(),
            &hash,
            &body,
            &certificate,
            true,
        )?;
        self.clear_root_dirty_if_committed(checkpoint)?;
        for root_id in self.reconcile_local_revision_head(checkpoint)? {
            self.mark_root_dirty(
                root_id,
                "a recovered writer incarnation replaced a local draft",
            )?;
        }
        self.reconcile_garbage_collection()?;
        Ok(hash)
    }

    pub fn sign_checkpoint(&mut self, checkpoint: &GuildCheckpoint) -> Result<MemberSignature> {
        checkpoint.validate()?;
        self.validate_local_member(checkpoint, true)?;
        self.validate_variable_checkpoint_coverage(checkpoint, false)?;
        let configured: Member = decode_canonical(
            &self
                .control
                .get_record("node-config", b"member")?
                .context("node failure domain has not been configured")?,
        )?;
        let committed = checkpoint
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("checkpoint does not contain the local node")?;
        if committed != &configured {
            anyhow::bail!("checkpoint local membership conflicts with node configuration");
        }
        self.validate_checkpoint_transition(checkpoint)?;
        self.validate_local_roles(checkpoint)?;
        let hash = checkpoint.hash()?;
        let body = canonical_bytes(checkpoint)?;
        self.control.lock_checkpoint_signature(
            &checkpoint.guild_id,
            checkpoint.generation,
            checkpoint.parent.as_ref(),
            &hash,
            &body,
        )?;
        Ok(checkpoint.member_signature(&self.keys)?)
    }

    pub(crate) fn validate_variable_checkpoint_coverage(
        &self,
        checkpoint: &GuildCheckpoint,
        recovered_head: bool,
    ) -> Result<()> {
        if !matches!(checkpoint.format_version, 4..=7) {
            return Ok(());
        }
        let checkpoint_hash = checkpoint.hash()?;
        let state = self
            .dynamic_guild_state()?
            .context("dynamic checkpoint requires dynamic guild state")?;
        if state.guild_id != checkpoint.guild_id {
            anyhow::bail!("checkpoint and dynamic guild state differ");
        }
        let previous_revisions = if recovered_head {
            None
        } else {
            self.control
                .checkpoint_head(&checkpoint.guild_id)?
                .filter(|(generation, hash, _)| {
                    (*generation == checkpoint.generation && *hash == checkpoint_hash)
                        || (generation.checked_add(1) == Some(checkpoint.generation)
                            && checkpoint.parent == Some(*hash))
                })
                .map(|(_, _, bytes)| decode_canonical::<QuorumCheckpoint>(&bytes))
                .transpose()?
                .map(|previous| previous.checkpoint.revisions)
        };
        let legacy_coverage = checkpoint
            .coding_groups
            .iter()
            .flat_map(|group| &group.roles)
            .filter_map(|role| match role {
                ShardRole::Information(information) => Some(information.sector.id),
                ShardRole::Parity(_) => None,
            })
            .collect::<BTreeSet<_>>();
        for revision in &checkpoint.revisions {
            let retained_revision = previous_revisions
                .as_ref()
                .is_some_and(|previous| previous.contains(revision));
            let authenticated_writer_key = state.writer_key_for_retained_revision(
                revision.value.owner,
                revision.value.writer_epoch,
            );
            if authenticated_writer_key != Some(revision.value.writer_public_key) {
                anyhow::bail!(
                    "checkpoint revision writer is absent from the authenticated guild history"
                );
            }
            if !recovered_head
                && !retained_revision
                && !state.writer_epoch_is_current(revision.value.owner, revision.value.writer_epoch)
            {
                anyhow::bail!("checkpoint revision was signed by a superseded writer epoch");
            }
            for reference in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
            {
                if checkpoint.format_version == 7 {
                    continue;
                }
                if legacy_coverage.contains(&reference.id) {
                    continue;
                }
                if !self.verified_variable_sector_coverage(
                    &state,
                    revision.value.owner,
                    reference,
                    recovered_head || retained_revision,
                )? {
                    anyhow::bail!(
                        "checkpoint sector has no verified variable coding group bound to its revision"
                    );
                }
            }
        }
        if let Some(catalog) = &checkpoint.packing_catalog {
            for descriptor in &catalog.sectors {
                if !self.verified_packed_sector_coverage(&state, descriptor, recovered_head)? {
                    anyhow::bail!("checkpoint packed sector has no verified variable coding group");
                }
            }
        }
        Ok(())
    }

    fn verified_packed_sector_coverage(
        &self,
        state: &DynamicGuildState,
        descriptor: &mb_core::PackedSectorDescriptor,
        allow_legacy_placement: bool,
    ) -> Result<bool> {
        for retained in state
            .coding_groups
            .iter()
            .filter(|retained| retained.retired_at_event.is_none())
        {
            if !allow_legacy_placement
                && state
                    .validate_current_group_placement(&retained.group)
                    .is_err()
            {
                continue;
            }
            let Some(information_index) = retained.group.roles.iter().position(|role| {
                matches!(role, ShardRoleV2::Information(information)
                    if !information.sector.virtual_zero
                        && information.sector.id == descriptor.id
                        && information.sector.logical_len == descriptor.commitment.byte_len
                        && information.sector.commitment == descriptor.commitment)
            }) else {
                continue;
            };
            let Some(bytes) = self
                .control
                .get_record("coding-group-transcript", &retained.group.id)?
            else {
                continue;
            };
            let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
            if transcript.value.manifest.value.group == retained.group
                && replay_coding_transcript(&transcript)? == CodingReplayFinding::Verified
                && transcript
                    .value
                    .plan
                    .value
                    .information_root(information_index)
                    == Some(descriptor.flat_root)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn uncovered_variable_sectors(
        &self,
        owner: NodeId,
        sectors: &[SectorRef],
    ) -> Result<Vec<SectorRef>> {
        let state = self
            .dynamic_guild_state()?
            .context("variable coverage requires dynamic guild state")?;
        let mut uncovered = Vec::new();
        for sector in sectors {
            if !self.verified_variable_sector_coverage(&state, owner, sector, false)? {
                uncovered.push(sector.clone());
            }
        }
        Ok(uncovered)
    }

    fn verified_variable_sector_coverage(
        &self,
        state: &DynamicGuildState,
        owner: NodeId,
        reference: &SectorRef,
        allow_legacy_root: bool,
    ) -> Result<bool> {
        for retained in state
            .coding_groups
            .iter()
            .filter(|retained| retained.retired_at_event.is_none())
        {
            if !allow_legacy_root
                && state
                    .validate_current_group_placement(&retained.group)
                    .is_err()
            {
                continue;
            }
            let Some(information_index) = retained.group.roles.iter().position(|role| {
                matches!(role, ShardRoleV2::Information(information)
                    if !information.sector.virtual_zero
                        && information.owner == owner
                        && information.sector.id == reference.id
                        && information.sector.logical_len == reference.logical_len)
            }) else {
                continue;
            };
            let Some(bytes) = self
                .control
                .get_record("coding-group-transcript", &retained.group.id)?
            else {
                continue;
            };
            let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
            if transcript.value.manifest.value.group == retained.group
                && replay_coding_transcript(&transcript)? == CodingReplayFinding::Verified
                && (transcript
                    .value
                    .plan
                    .value
                    .information_root(information_index)
                    == Some(reference.root)
                    || allow_legacy_root && transcript.value.plan.value.format_version == 1)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stage_checkpoint_page(
        &mut self,
        object_kind: &str,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
        page_index: u32,
        total_pages: u32,
        page_hash: &[u8; 32],
        bytes: &[u8],
    ) -> Result<()> {
        self.control.stage_checkpoint_page(
            object_kind,
            guild_id,
            checkpoint_hash,
            page_index,
            total_pages,
            page_hash,
            bytes,
        )?;
        Ok(())
    }

    pub fn sign_staged_checkpoint(
        &mut self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
    ) -> Result<MemberSignature> {
        let bytes = self
            .control
            .assembled_checkpoint_object("body", guild_id, checkpoint_hash)?;
        let checkpoint: GuildCheckpoint = decode_canonical(&bytes)?;
        if checkpoint.guild_id != *guild_id || checkpoint.hash()? != *checkpoint_hash {
            anyhow::bail!("staged checkpoint body has the wrong identity");
        }
        self.sign_checkpoint(&checkpoint)
    }

    pub fn finalize_staged_checkpoint(
        &mut self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
    ) -> Result<[u8; 32]> {
        if let Ok(existing) = self.checkpoint(checkpoint_hash)
            && existing.checkpoint.guild_id == *guild_id
        {
            self.control.clear_checkpoint_pages(checkpoint_hash)?;
            return Ok(*checkpoint_hash);
        }
        let bytes =
            self.control
                .assembled_checkpoint_object("certificate", guild_id, checkpoint_hash)?;
        let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
        if checkpoint.checkpoint.guild_id != *guild_id || checkpoint.hash()? != *checkpoint_hash {
            anyhow::bail!("staged checkpoint certificate has the wrong identity");
        }
        let hash = self.store_checkpoint(&checkpoint)?;
        self.control.clear_checkpoint_pages(checkpoint_hash)?;
        Ok(hash)
    }

    pub fn checkpoint_page(
        &self,
        guild_id: &[u8; 32],
        checkpoint_hash: &[u8; 32],
        page_index: u32,
    ) -> Result<(u32, Vec<u8>)> {
        checkpoint_page(&self.control, guild_id, checkpoint_hash, page_index)
    }

    fn validate_local_member(
        &self,
        checkpoint: &GuildCheckpoint,
        require_current_membership: bool,
    ) -> Result<()> {
        if let Some(installed) = self.installed_guild()? {
            if checkpoint.guild_id != installed.certificate.genesis.guild_id
                || checkpoint.genesis_hash != installed.certificate.hash()?
            {
                anyhow::bail!("checkpoint is not bound to the installed guild genesis");
            }
            if checkpoint.format_version == 3 {
                if checkpoint.members != installed.certificate.genesis.members {
                    anyhow::bail!("legacy checkpoint changes its genesis membership");
                }
            } else {
                let durable = self
                    .dynamic_guild_state()?
                    .context("dynamic checkpoint requires dynamic guild state")?;
                let mut replay = initial_dynamic_guild_state(&installed)?;
                let mut historical_membership =
                    checkpoint_matches_dynamic_authority(checkpoint, &replay);
                for (record_id, bytes) in self.control.records("guild-event")? {
                    let event: QuorumGuildEvent = decode_canonical(&bytes)?;
                    if record_id != event.event.sequence.to_be_bytes() {
                        anyhow::bail!("guild event history has an invalid record ID");
                    }
                    replay.apply_event(&event)?;
                    historical_membership |=
                        checkpoint_matches_dynamic_authority(checkpoint, &replay);
                }
                if replay != durable || !historical_membership {
                    anyhow::bail!("checkpoint membership is absent from guild event history");
                }
                if require_current_membership
                    && !checkpoint_matches_dynamic_authority(checkpoint, &durable)
                {
                    anyhow::bail!("checkpoint does not use the current guild authority");
                }
                let historical = durable
                    .members
                    .iter()
                    .map(|member| member.member.node_id)
                    .collect::<BTreeSet<_>>();
                if checkpoint
                    .writer_fences
                    .iter()
                    .map(|fence| fence.owner)
                    .chain(
                        checkpoint
                            .revision_tombstones
                            .iter()
                            .map(|tombstone| tombstone.owner),
                    )
                    .chain(
                        checkpoint
                            .revisions
                            .iter()
                            .map(|revision| revision.value.owner),
                    )
                    .any(|owner| !historical.contains(&owner))
                {
                    anyhow::bail!("checkpoint refers to a node outside guild history");
                }
            }
        }
        let member = checkpoint
            .members
            .iter()
            .find(|member| member.node_id == self.keys.node_id())
            .context("checkpoint does not contain the local node")?;
        if member.recovery_public_key != self.keys.recovery_public_key() {
            anyhow::bail!("checkpoint recovery key does not match the local seed");
        }
        Ok(())
    }

    fn validate_checkpoint_transition(&self, checkpoint: &GuildCheckpoint) -> Result<()> {
        let locked = self.control.locked_checkpoint(&checkpoint.guild_id)?;
        let head = self.control.checkpoint_head(&checkpoint.guild_id)?;
        let previous = match (locked, head) {
            (Some(locked), Some(head)) if locked.0 >= head.0 => {
                Some((locked.0, locked.1, locked.2, true))
            }
            (Some(_), Some(head)) => Some((head.0, head.1, head.2, false)),
            (Some(locked), None) => Some((locked.0, locked.1, locked.2, true)),
            (None, Some(head)) => Some((head.0, head.1, head.2, false)),
            (None, None) => None,
        };
        let Some((generation, hash, bytes, is_body)) = previous else {
            if checkpoint.generation != 1 || checkpoint.parent.is_some() {
                anyhow::bail!("first checkpoint must be generation one");
            }
            return Ok(());
        };
        if generation == checkpoint.generation && hash == checkpoint.hash()? {
            return Ok(());
        }
        if generation.checked_add(1) != Some(checkpoint.generation)
            || checkpoint.parent != Some(hash)
        {
            anyhow::bail!("checkpoint does not extend the locally accepted head");
        }
        let previous = if is_body {
            decode_canonical::<GuildCheckpoint>(&bytes)?
        } else {
            decode_canonical::<QuorumCheckpoint>(&bytes)?.checkpoint
        };
        match (
            previous.packing_catalog.as_ref(),
            checkpoint.packing_catalog.as_ref(),
        ) {
            (Some(previous), Some(current))
                if previous.revision.checked_add(1) == Some(current.revision)
                    && current.parent == Some(previous.id) => {}
            (None, Some(current)) if current.revision == 1 && current.parent.is_none() => {}
            (None, None) => {}
            _ => anyhow::bail!("checkpoint packing catalog does not extend its parent"),
        }
        if !previous
            .writer_fences
            .iter()
            .all(|fence| checkpoint.writer_fences.contains(fence))
        {
            anyhow::bail!("checkpoint transition drops or changes a writer fence");
        }
        for member in &checkpoint.members {
            let previous_epoch = previous
                .writer_fences
                .iter()
                .filter(|fence| fence.owner == member.node_id)
                .map(|fence| fence.epoch)
                .max()
                .unwrap_or(0);
            let current_epoch = checkpoint
                .writer_fences
                .iter()
                .filter(|fence| fence.owner == member.node_id)
                .map(|fence| fence.epoch)
                .max()
                .unwrap_or(0);
            if current_epoch > previous_epoch
                && (previous_epoch.checked_add(1) != Some(current_epoch)
                    || !checkpoint.revisions.iter().any(|revision| {
                        revision.value.owner == member.node_id
                            && revision.value.writer_epoch == current_epoch
                            && !previous.revisions.contains(revision)
                    }))
            {
                anyhow::bail!("checkpoint advances a writer fence without its next revision");
            }
            if checkpoint.revisions.iter().any(|revision| {
                revision.value.owner == member.node_id
                    && !previous.revisions.contains(revision)
                    && revision.value.writer_epoch != current_epoch
            }) {
                anyhow::bail!("checkpoint adds a revision from a superseded writer incarnation");
            }
        }
        for old in &previous.revision_tombstones {
            let Some(current) = checkpoint.revision_tombstones.iter().find(|current| {
                (current.owner, current.protected_root_id) == (old.owner, old.protected_root_id)
            }) else {
                anyhow::bail!("checkpoint transition drops a revision tombstone");
            };
            if current.through_sequence < old.through_sequence
                || current.through_sequence == old.through_sequence && current != old
            {
                anyhow::bail!("checkpoint transition changes a revision tombstone");
            }
        }
        for current in &checkpoint.revision_tombstones {
            let previous_floor = previous
                .revision_tombstones
                .iter()
                .find(|old| {
                    (old.owner, old.protected_root_id) == (current.owner, current.protected_root_id)
                })
                .map(|old| old.through_sequence)
                .unwrap_or(0);
            if current.through_sequence > previous_floor {
                let retired = previous.revisions.iter().find(|revision| {
                    revision.value.owner == current.owner
                        && revision.value.protected_root_id == current.protected_root_id
                        && revision.value.sequence == current.through_sequence
                });
                if current.retired_at_generation != checkpoint.generation
                    || retired.is_none_or(|revision| {
                        revision.value.revision_id != current.last_revision_id
                            || revision.value.hash().ok() != Some(current.last_revision_hash)
                    })
                {
                    anyhow::bail!("checkpoint tombstone does not match retired signed history");
                }
            }
        }
        let current_revision_sectors = checkpoint
            .revisions
            .iter()
            .flat_map(|revision| {
                revision
                    .value
                    .metadata_sectors
                    .iter()
                    .chain(&revision.value.data_sectors)
            })
            .map(|reference| reference.id)
            .collect::<BTreeSet<_>>();
        if checkpoint.format_version == 3 && !previous.members.iter().all(|item| {
            checkpoint
                .members
                .binary_search_by_key(&item.node_id, |entry| entry.node_id)
                .is_ok_and(|index| checkpoint.members[index] == *item)
        }) || !previous.revisions.iter().all(|item| {
            checkpoint.revisions.contains(item)
                || checkpoint.revision_tombstones.iter().any(|tombstone| {
                    tombstone.owner == item.value.owner
                        && tombstone.protected_root_id == item.value.protected_root_id
                        && tombstone.through_sequence >= item.value.sequence
                })
        }) || checkpoint.format_version == 3 && !previous.coding_groups.iter().all(|item| {
            checkpoint
                .coding_groups
                .binary_search_by_key(&item.id, |entry| entry.id)
                .is_ok_and(|index| checkpoint.coding_groups[index] == *item)
                || !item.roles.iter().any(|role| {
                    matches!(role, ShardRole::Information(information) if current_revision_sectors.contains(&information.sector.id))
                })
        })
        {
            anyhow::bail!("checkpoint transition drops or changes active state");
        }
        Ok(())
    }

    fn validate_local_roles(&self, checkpoint: &GuildCheckpoint) -> Result<()> {
        for group in &checkpoint.coding_groups {
            for (index, role) in group.roles.iter().enumerate() {
                match role {
                    ShardRole::Information(information)
                        if information.owner == self.keys.node_id() =>
                    {
                        let bytes =
                            self.sector_for_guild(&checkpoint.guild_id, &information.sector.id)?;
                        if bytes.len() != group.shard_size as usize
                            || sector_root(&bytes) != information.sector.root
                        {
                            anyhow::bail!("local information shard is not durable");
                        }
                    }
                    ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                        let object = self.volumes.load_ready(&group.id, index as u8)?;
                        let proof = self
                            .control
                            .get_record(
                                "local-parity-proof",
                                &parity_proof_id(&group.id, index as u8),
                            )?
                            .context("local parity coding proof is unavailable")?;
                        if object.format_version != group.format_version
                            || object.guild_id != checkpoint.guild_id
                            || object.root != parity.root
                            || proof != canonical_bytes(group)?
                        {
                            anyhow::bail!("local parity shard is not durable");
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn clear_root_dirty_if_committed(&mut self, checkpoint: &QuorumCheckpoint) -> Result<()> {
        for root in self.protected_roots()? {
            let Some(bytes) = self.control.get_record(
                "user-revision-head",
                &revision_head_id(checkpoint.checkpoint.guild_id, root.root_id),
            )?
            else {
                continue;
            };
            let local_head: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
            if !checkpoint.checkpoint.revisions.contains(&local_head) {
                continue;
            }
            let state = self.root_dirty_state(root.root_id)?;
            let captured_change_sequence = self
                .control
                .get_record(
                    "revision-root-change",
                    local_head.value.revision_id.as_bytes(),
                )?
                .map(|bytes| decode_canonical::<u64>(&bytes))
                .transpose()?;
            if state.as_ref().is_some_and(|state| {
                state.dirty && captured_change_sequence != Some(state.change_sequence)
            }) {
                continue;
            }
            let change_sequence = state.map(|state| state.change_sequence).unwrap_or(0);
            self.control.put_record(
                "root-dirty",
                root.root_id.as_bytes(),
                &canonical_bytes(&RootDirtyState {
                    format_version: 3,
                    protected_root_id: root.root_id,
                    dirty: false,
                    reason: "latest local revision is committed".to_owned(),
                    change_sequence,
                })?,
            )?;
        }
        if !self.root_dirty()? {
            let mut automation = self.automatic_backup_state(unix_seconds())?;
            automation.dirty_since_unix_seconds = None;
            self.store_automatic_backup_state(&automation)?;
        }
        Ok(())
    }

    fn reconcile_certified_writer_head(&mut self) -> Result<()> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(());
        };
        let Some(checkpoint) = self.current_checkpoint(installed.certificate.genesis.guild_id)?
        else {
            return Ok(());
        };
        checkpoint.verify()?;
        for root_id in self.reconcile_local_revision_head(&checkpoint)? {
            self.mark_root_dirty(
                root_id,
                "a recovered writer incarnation replaced a local draft",
            )?;
        }
        Ok(())
    }

    fn reconcile_local_revision_head(
        &mut self,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<Vec<Uuid>> {
        let local_id = self.keys.node_id();
        let Some(fence) = checkpoint
            .checkpoint
            .writer_fences
            .iter()
            .filter(|fence| fence.owner == local_id)
            .max_by_key(|fence| fence.epoch)
        else {
            return Ok(Vec::new());
        };
        let mut replaced = Vec::new();
        for root in self.protected_roots()? {
            let head_id = revision_head_id(checkpoint.checkpoint.guild_id, root.root_id);
            let local_head = self
                .control
                .get_record("user-revision-head", &head_id)?
                .map(|bytes| decode_canonical::<SignedRecord<UserRevision>>(&bytes))
                .transpose()?;
            if local_head.as_ref().is_some_and(|revision| {
                checkpoint.checkpoint.revisions.contains(revision)
                    || revision.value.writer_epoch == fence.epoch
                        && revision.value.writer_public_key == fence.public_key
            }) {
                continue;
            }
            let Some(certified) = checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| {
                    revision.value.owner == local_id
                        && revision.value.protected_root_id == root.root_id
                })
                .max_by_key(|revision| revision.value.sequence)
            else {
                continue;
            };
            let bytes = canonical_bytes(certified)?;
            self.control.put_records(&[
                (
                    "user-revision".to_owned(),
                    certified.value.revision_id.as_bytes().to_vec(),
                    bytes.clone(),
                ),
                ("user-revision-head".to_owned(), head_id, bytes),
            ])?;
            if local_head.as_ref() != Some(certified) {
                replaced.push(root.root_id);
            }
        }
        Ok(replaced)
    }

    fn reconcile_garbage_collection(&mut self) -> Result<()> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(());
        };
        let Some(current) = self.current_checkpoint(installed.certificate.genesis.guild_id)? else {
            return Ok(());
        };
        current.verify()?;
        let generation = current.checkpoint.generation;
        let checkpoint_hash = current.hash()?;
        let live_revisions = current
            .checkpoint
            .revisions
            .iter()
            .map(|revision| revision.value.revision_id)
            .collect::<BTreeSet<_>>();
        let live_sectors = current
            .checkpoint
            .revisions
            .iter()
            .flat_map(|revision| {
                revision
                    .value
                    .metadata_sectors
                    .iter()
                    .chain(&revision.value.data_sectors)
            })
            .map(|reference| reference.id)
            .chain(
                current
                    .checkpoint
                    .coding_groups
                    .iter()
                    .flat_map(|group| &group.roles)
                    .filter_map(|role| match role {
                        ShardRole::Information(information) => Some(information.sector.id),
                        ShardRole::Parity(_) => None,
                    }),
            )
            .chain(
                current
                    .checkpoint
                    .packing_catalog
                    .iter()
                    .flat_map(|catalog| catalog.sectors.iter().map(|sector| sector.id)),
            )
            .collect::<BTreeSet<_>>();
        let mut live_groups = current
            .checkpoint
            .coding_groups
            .iter()
            .map(|group| group.id)
            .collect::<BTreeSet<_>>();
        let dynamic_groups = self
            .dynamic_guild_state()?
            .map(|state| state.coding_groups)
            .unwrap_or_default();
        live_groups.extend(dynamic_groups.iter().filter_map(|retained| {
            retained
                .group
                .roles
                .iter()
                .any(|role| {
                    matches!(role, ShardRoleV2::Information(information)
                        if !information.sector.virtual_zero
                            && live_sectors.contains(&information.sector.id))
                })
                .then_some(retained.group.id)
        }));

        self.collect_mature_garbage(generation, &live_revisions, &live_sectors, &live_groups)?;

        for (record_id, _) in self.control.records("packed-sector")? {
            if record_id.len() != 64 {
                anyhow::bail!("packed sector record key has the wrong length");
            }
            if record_id[..32] != current.checkpoint.guild_id {
                continue;
            }
            let sector_id: [u8; 32] = record_id[32..].try_into()?;
            if !live_sectors.contains(&sector_id) {
                self.schedule_garbage(
                    "gc-packed-sector",
                    &record_id,
                    generation,
                    checkpoint_hash,
                    None,
                )?;
            }
        }

        let Some(parent_hash) = current.checkpoint.parent else {
            return Ok(());
        };
        let Some(previous_bytes) = self.control.get_record("guild-checkpoint", &parent_hash)?
        else {
            // Seed recovery installs a certified head without requiring its full
            // history. Missing history cannot prove anything unreachable, so GC
            // must wait rather than blocking recovery or later startup.
            return Ok(());
        };
        let previous: QuorumCheckpoint = decode_canonical(&previous_bytes)?;
        previous.verify()?;
        if previous.hash()? != parent_hash {
            anyhow::bail!("checkpoint hash mismatch");
        }
        for revision in &previous.checkpoint.revisions {
            if live_revisions.contains(&revision.value.revision_id) {
                continue;
            }
            self.schedule_garbage(
                "gc-anchor",
                revision.value.revision_id.as_bytes(),
                generation,
                checkpoint_hash,
                None,
            )?;
            self.schedule_garbage(
                "gc-revision",
                revision.value.revision_id.as_bytes(),
                generation,
                checkpoint_hash,
                None,
            )?;
            for reference in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
            {
                self.schedule_garbage(
                    "gc-sector",
                    &reference.id,
                    generation,
                    checkpoint_hash,
                    None,
                )?;
            }
        }
        let current_packed = current
            .checkpoint
            .packing_catalog
            .iter()
            .flat_map(|catalog| catalog.sectors.iter().map(|sector| sector.id))
            .collect::<BTreeSet<_>>();
        for sector in previous
            .checkpoint
            .packing_catalog
            .iter()
            .flat_map(|catalog| &catalog.sectors)
        {
            if !current_packed.contains(&sector.id) {
                self.schedule_garbage(
                    "gc-packed-sector",
                    &packed_record_id(&current.checkpoint.guild_id, &sector.id),
                    generation,
                    checkpoint_hash,
                    None,
                )?;
            }
        }
        for group in &previous.checkpoint.coding_groups {
            if live_groups.contains(&group.id) {
                continue;
            }
            for (index, role) in group.roles.iter().enumerate() {
                match role {
                    ShardRole::Information(information) => {
                        self.schedule_garbage(
                            "gc-sector",
                            &information.sector.id,
                            generation,
                            checkpoint_hash,
                            None,
                        )?;
                        let emergency_id = parity_proof_id(&group.id, index as u8);
                        if self
                            .control
                            .get_record("emergency-shard", &emergency_id)?
                            .is_some()
                        {
                            self.schedule_garbage(
                                "gc-parity",
                                &emergency_id,
                                generation,
                                checkpoint_hash,
                                Some(information.sector.root),
                            )?;
                        }
                    }
                    ShardRole::Parity(parity) => self.schedule_garbage(
                        "gc-parity",
                        &parity_proof_id(&group.id, index as u8),
                        generation,
                        checkpoint_hash,
                        Some(parity.root),
                    )?,
                }
            }
        }
        let previous_sectors = previous
            .checkpoint
            .packing_catalog
            .as_ref()
            .map(|catalog| {
                catalog
                    .sectors
                    .iter()
                    .map(|sector| sector.id)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_else(|| {
                previous
                    .checkpoint
                    .revisions
                    .iter()
                    .flat_map(|revision| {
                        revision
                            .value
                            .metadata_sectors
                            .iter()
                            .chain(&revision.value.data_sectors)
                    })
                    .map(|reference| reference.id)
                    .collect()
            });
        for retained in &dynamic_groups {
            let group = &retained.group;
            if live_groups.contains(&group.id)
                || !group.roles.iter().any(|role| {
                    matches!(role, ShardRoleV2::Information(information)
                        if !information.sector.virtual_zero
                            && previous_sectors.contains(&information.sector.id))
                })
            {
                continue;
            }
            for (index, role) in group.roles.iter().enumerate() {
                match role {
                    ShardRoleV2::Information(information)
                        if information.owner == self.keys.node_id()
                            && !information.sector.virtual_zero =>
                    {
                        self.schedule_garbage(
                            "gc-variable-sector",
                            &variable_emergency_id(&information.sector.id, index as u16),
                            generation,
                            checkpoint_hash,
                            Some(information.sector.commitment.root),
                        )?;
                    }
                    ShardRoleV2::Parity(parity) if parity.holder == self.keys.node_id() => {
                        self.schedule_garbage(
                            "gc-variable-parity",
                            &variable_emergency_id(&group.id, index as u16),
                            generation,
                            checkpoint_hash,
                            Some(parity.commitment.root),
                        )?;
                    }
                    _ => {}
                }
                let emergency_id = variable_emergency_id(&group.id, index as u16);
                if self
                    .control
                    .get_record("variable-emergency-shard", &emergency_id)?
                    .is_some()
                {
                    self.schedule_garbage(
                        "gc-variable-parity",
                        &variable_emergency_id(&group.id, index as u16),
                        generation,
                        checkpoint_hash,
                        Some(match role {
                            ShardRoleV2::Information(information) => {
                                information.sector.commitment.root
                            }
                            ShardRoleV2::Parity(parity) => parity.commitment.root,
                        }),
                    )?;
                }
            }
        }
        Ok(())
    }

    fn schedule_garbage(
        &self,
        kind: &str,
        record_id: &[u8],
        generation: u64,
        checkpoint_hash: [u8; 32],
        parity_root: Option<[u8; 32]>,
    ) -> Result<()> {
        if self.control.get_record(kind, record_id)?.is_none() {
            self.control.put_record(
                kind,
                record_id,
                &canonical_bytes(&GarbageCandidate {
                    format_version: 1,
                    first_unreachable_generation: generation,
                    checkpoint_hash,
                    parity_root,
                })?,
            )?;
        }
        Ok(())
    }

    fn collect_mature_garbage(
        &mut self,
        generation: u64,
        live_revisions: &BTreeSet<Uuid>,
        live_sectors: &BTreeSet<SectorId>,
        live_groups: &BTreeSet<[u8; 32]>,
    ) -> Result<()> {
        for kind in [
            "gc-anchor",
            "gc-revision",
            "gc-sector",
            "gc-parity",
            "gc-variable-sector",
            "gc-variable-parity",
            "gc-packed-sector",
        ] {
            for (record_id, bytes) in self.control.records(kind)? {
                let candidate: GarbageCandidate = decode_canonical(&bytes)?;
                if candidate.format_version != 1
                    || candidate.first_unreachable_generation == 0
                    || candidate.first_unreachable_generation > generation
                    || candidate.checkpoint_hash == [0; 32]
                {
                    anyhow::bail!("durable garbage-collection candidate is invalid");
                }
                let live = match kind {
                    "gc-anchor" | "gc-revision" => Uuid::from_slice(&record_id)
                        .ok()
                        .is_some_and(|revision_id| live_revisions.contains(&revision_id)),
                    "gc-sector" => record_id
                        .as_slice()
                        .try_into()
                        .ok()
                        .is_some_and(|sector_id: [u8; 32]| live_sectors.contains(&sector_id)),
                    "gc-parity" => record_id
                        .get(..32)
                        .and_then(|id| id.try_into().ok())
                        .is_some_and(|group_id: [u8; 32]| live_groups.contains(&group_id)),
                    "gc-variable-sector" => record_id
                        .get(..32)
                        .and_then(|id| id.try_into().ok())
                        .is_some_and(|sector_id: [u8; 32]| live_sectors.contains(&sector_id)),
                    "gc-variable-parity" => record_id
                        .get(..32)
                        .and_then(|id| id.try_into().ok())
                        .is_some_and(|group_id: [u8; 32]| live_groups.contains(&group_id)),
                    "gc-packed-sector" => record_id
                        .get(32..64)
                        .and_then(|id| id.try_into().ok())
                        .is_some_and(|sector_id: [u8; 32]| live_sectors.contains(&sector_id)),
                    _ => unreachable!(),
                };
                if live {
                    self.control.delete_record(kind, &record_id)?;
                    continue;
                }
                if generation == candidate.first_unreachable_generation {
                    continue;
                }
                let collected = match kind {
                    "gc-anchor" => {
                        retire_revision_anchor(&mut self.control, Uuid::from_slice(&record_id)?)?;
                        true
                    }
                    "gc-revision" => {
                        self.control.delete_record("user-revision", &record_id)?;
                        true
                    }
                    "gc-sector" => {
                        self.control.delete_record("local-sector", &record_id)?;
                        true
                    }
                    "gc-parity" => {
                        let group_id: [u8; 32] = record_id
                            .get(..32)
                            .context("parity garbage key is truncated")?
                            .try_into()?;
                        let shard_index = *record_id
                            .get(32)
                            .context("parity garbage key is truncated")?;
                        let root = candidate
                            .parity_root
                            .context("parity garbage candidate has no root")?;
                        let removed = self.volumes.remove_unreachable(
                            &self.control,
                            &group_id,
                            shard_index,
                            &root,
                        )?;
                        if removed {
                            self.control.delete_record(
                                "local-parity-proof",
                                &parity_proof_id(&group_id, shard_index),
                            )?;
                            self.control.delete_record(
                                "emergency-shard",
                                &parity_proof_id(&group_id, shard_index),
                            )?;
                        }
                        removed
                    }
                    "gc-variable-sector" | "gc-variable-parity" => {
                        let storage_id: [u8; 32] = record_id
                            .get(..32)
                            .context("variable garbage key is truncated")?
                            .try_into()?;
                        let shard_index = u16::from_be_bytes(
                            record_id
                                .get(32..34)
                                .context("variable garbage key is truncated")?
                                .try_into()?,
                        );
                        let local_index = u8::try_from(shard_index)
                            .context("variable garbage shard index exceeds storage format")?;
                        let root = candidate
                            .parity_root
                            .context("variable garbage candidate has no root")?;
                        let removed = self.volumes.remove_unreachable(
                            &self.control,
                            &storage_id,
                            local_index,
                            &root,
                        )?;
                        if removed && kind == "gc-variable-parity" {
                            let emergency_id = variable_emergency_id(&storage_id, shard_index);
                            self.control
                                .delete_record("variable-emergency-shard", &emergency_id)?;
                            self.control
                                .delete_record("variable-repair", &emergency_id)?;
                        }
                        removed
                    }
                    "gc-packed-sector" => {
                        self.control.delete_record("packed-sector", &record_id)?;
                        true
                    }
                    _ => unreachable!(),
                };
                if collected {
                    self.control.delete_record(kind, &record_id)?;
                }
            }
        }
        Ok(())
    }

    pub fn recovery_record(
        &self,
        subject: &Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        endpoint: String,
        expires_at_unix_seconds: u64,
    ) -> Result<mb_core::SealedRecoveryRecord> {
        self.recovery_record_for_endpoints(
            subject,
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            vec![endpoint],
            expires_at_unix_seconds,
        )
    }

    pub fn recovery_record_for_endpoints(
        &self,
        subject: &Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<mb_core::SealedRecoveryRecord> {
        let signed = self.recovery_locator_for_endpoints(
            subject,
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            endpoints,
            expires_at_unix_seconds,
        )?;
        Ok(seal_recovery_record(
            subject.recovery_public_key,
            &canonical_bytes(&signed)?,
        )?)
    }

    fn recovery_locator_for_endpoints(
        &self,
        subject: &Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<SignedRecord<RecoveryLocator>> {
        let locator = RecoveryLocator {
            format_version: 1,
            subject: subject.node_id,
            publisher: self.keys.node_id(),
            guild_id,
            checkpoint_hash,
            checkpoint_generation,
            subject_endpoint_sequence_floor: self
                .observed_endpoint_sequence_floor(subject.node_id)?,
            endpoints,
            expires_at_unix_seconds,
        };
        Ok(SignedRecord::sign(
            RECOVERY_LOCATOR_DOMAIN,
            locator,
            &self.keys,
        )?)
    }

    pub fn build_dht_publications(
        &mut self,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
        sequence_floors: DhtSequenceFloors,
    ) -> Result<Option<DhtPublicationSet>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let guild_id = installed.certificate.genesis.guild_id;
        let Some(checkpoint) = self.current_checkpoint(guild_id)? else {
            return Ok(None);
        };
        checkpoint.verify()?;
        let checkpoint_hash = checkpoint.hash()?;
        let local_id = self.keys.node_id();
        let (publication_members, recovery_envelopes) =
            if matches!(checkpoint.checkpoint.format_version, 4..=7) {
                let state = self
                    .dynamic_guild_state()?
                    .context("dynamic DHT publication requires dynamic guild state")?;
                let active = state.active_members().cloned().collect::<Vec<_>>();
                if active != checkpoint.checkpoint.members {
                    return Ok(None);
                }
                let mut envelopes = BTreeMap::new();
                for member in &active {
                    if member.node_id == local_id {
                        continue;
                    }
                    let Some(epoch) = state.current_recovery_key(member.node_id) else {
                        return Ok(None);
                    };
                    envelopes.insert(member.node_id, epoch.envelope.clone());
                }
                (active, envelopes)
            } else {
                (checkpoint.checkpoint.members.clone(), BTreeMap::new())
            };
        let recovery_epochs = recovery_envelopes
            .iter()
            .map(|(subject, envelope)| (*subject, envelope.epoch))
            .collect::<Vec<_>>();
        if !checkpoint.has_signature(local_id)
            || !publication_members
                .iter()
                .any(|member| member.node_id == local_id)
        {
            return Ok(None);
        }
        validate_endpoint_set(local_id, &endpoints)?;
        if expires_at_unix_seconds <= unix_seconds() {
            anyhow::bail!("DHT publication expiry must be in the future");
        }
        if let Some(bytes) = self.control.get_record("dht-publication", b"primary")? {
            let state = decode_canonical::<DhtPublicationState>(&bytes);
            if state.as_ref().is_ok_and(|state| {
                state.format_version == 2
                    && state.checkpoint_hash == checkpoint_hash
                    && state.endpoints == endpoints
                    && state.recovery_epochs == recovery_epochs
                    && state.expires_at_unix_seconds.saturating_add(5 * 60)
                        >= expires_at_unix_seconds
            }) {
                let endpoint = self
                    .control
                    .get_record("dht-endpoint", b"primary")?
                    .context("DHT publication state has no endpoint record")?;
                let endpoint: SignedRecord<EndpointRecord> = decode_canonical(&endpoint)?;
                let mut recovery = Vec::new();
                for subject in publication_members
                    .iter()
                    .filter(|member| member.node_id != local_id)
                {
                    let bundle = self
                        .control
                        .get_record("dht-recovery-bundle", &subject.node_id.0)?
                        .context("DHT publication state has no recovery bundle")?;
                    recovery.push(decode_canonical(&bundle)?);
                }
                return Ok(Some(DhtPublicationSet {
                    checkpoint_hash,
                    endpoint,
                    recovery,
                }));
            }
        }
        let endpoint = self.build_endpoint_publication(
            guild_id,
            endpoints.clone(),
            expires_at_unix_seconds,
            sequence_floors.endpoint,
        )?;
        let mut recovery = Vec::new();
        for subject in publication_members
            .iter()
            .filter(|member| member.node_id != local_id)
        {
            let slot = publication_slot(b"recovery", subject.node_id, local_id, guild_id);
            let sequence = self.next_recovery_publication_sequence(
                &slot,
                sequence_floors
                    .recovery
                    .get(&subject.node_id)
                    .copied()
                    .unwrap_or(1)
                    .max(1),
            )?;
            let key_envelope = recovery_envelopes.get(&subject.node_id).cloned();
            let recipient = key_envelope
                .as_ref()
                .map_or(subject.recovery_public_key, |envelope| envelope.public_key);
            let locator = self.recovery_locator_for_endpoints(
                subject,
                guild_id,
                checkpoint_hash,
                checkpoint.checkpoint.generation,
                endpoints.clone(),
                expires_at_unix_seconds,
            )?;
            let sealed = seal_recovery_record(recipient, &canonical_bytes(&locator)?)?;
            let bundle = SignedRecord::sign(
                b"mutualbackup/recovery-bundle/v1",
                RecoveryBundle {
                    format_version: if key_envelope.is_some() { 2 } else { 1 },
                    subject: subject.node_id,
                    publisher: local_id,
                    sequence,
                    expires_at_unix_seconds,
                    key_envelope,
                    sealed,
                },
                &self.keys,
            )?;
            self.control.put_record(
                "dht-recovery-bundle",
                &subject.node_id.0,
                &canonical_bytes(&bundle)?,
            )?;
            recovery.push(bundle);
        }
        self.control.put_record(
            "dht-publication",
            b"primary",
            &canonical_bytes(&DhtPublicationState {
                format_version: 2,
                checkpoint_hash,
                endpoints,
                expires_at_unix_seconds,
                recovery_epochs,
            })?,
        )?;
        self.control.put_record(
            "dht-recovery-sequence-probe",
            b"primary",
            &canonical_bytes(&false)?,
        )?;
        Ok(Some(DhtPublicationSet {
            checkpoint_hash,
            endpoint,
            recovery,
        }))
    }

    pub(crate) fn dht_readiness_checkpoint_hash(&self) -> Result<Option<[u8; 32]>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let Some(checkpoint) = self.current_checkpoint(installed.certificate.genesis.guild_id)?
        else {
            return Ok(None);
        };
        checkpoint.verify()?;
        Ok(Some(checkpoint.hash()?))
    }

    pub(crate) fn refresh_peer_exchange_endpoint(
        &mut self,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
    ) -> Result<Option<SignedRecord<EndpointRecord>>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        installed.certificate.verify()?;
        if self.dynamic_guild_state()?.is_some_and(|state| {
            !state
                .active_members()
                .any(|member| member.node_id == self.keys.node_id())
        }) {
            return Ok(None);
        }
        Ok(Some(self.build_endpoint_publication(
            installed.certificate.genesis.guild_id,
            endpoints,
            expires_at_unix_seconds,
            1,
        )?))
    }

    fn build_endpoint_publication(
        &mut self,
        guild_id: [u8; 32],
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
        sequence_floor: u64,
    ) -> Result<SignedRecord<EndpointRecord>> {
        let local_id = self.keys.node_id();
        validate_endpoint_set(local_id, &endpoints)?;
        if expires_at_unix_seconds <= unix_seconds() {
            anyhow::bail!("endpoint publication expiry must be in the future");
        }
        if let Some(bytes) = self.control.get_record("dht-endpoint", b"primary")? {
            let current: SignedRecord<EndpointRecord> = decode_canonical(&bytes)?;
            current.verify(b"mutualbackup/endpoint-record/v1")?;
            if current.signer != local_id
                || current.value.publisher != local_id
                || current.value.format_version != 1
            {
                anyhow::bail!("stored endpoint publication belongs to another identity");
            }
            if current.value.endpoints == endpoints
                && current.value.sequence >= sequence_floor
                && current.value.expires_at_unix_seconds.saturating_add(5 * 60)
                    >= expires_at_unix_seconds
            {
                return Ok(current);
            }
        }
        let endpoint_slot = publication_slot(b"endpoint", local_id, local_id, guild_id);
        let endpoint = SignedRecord::sign(
            b"mutualbackup/endpoint-record/v1",
            EndpointRecord {
                format_version: 1,
                publisher: local_id,
                sequence: self
                    .next_recovery_publication_sequence(&endpoint_slot, sequence_floor.max(1))?,
                expires_at_unix_seconds,
                endpoints,
            },
            &self.keys,
        )?;
        self.control
            .put_record("dht-endpoint", b"primary", &canonical_bytes(&endpoint)?)?;
        Ok(endpoint)
    }

    pub fn dht_recovery_sequence_probe_subjects(&self) -> Result<Vec<NodeId>> {
        let required = self
            .control
            .get_record("dht-recovery-sequence-probe", b"primary")?
            .map(|bytes| decode_canonical::<bool>(&bytes))
            .transpose()?
            .unwrap_or(false);
        if !required {
            return Ok(Vec::new());
        }
        if let Some(state) = self.dynamic_guild_state()? {
            return Ok(state
                .active_members()
                .filter(|member| member.node_id != self.keys.node_id())
                .map(|member| member.node_id)
                .collect());
        }
        Ok(self
            .installed_guild()?
            .into_iter()
            .flat_map(|guild| guild.certificate.genesis.members)
            .filter(|member| member.node_id != self.keys.node_id())
            .map(|member| member.node_id)
            .collect())
    }

    pub(crate) fn observe_dht_records(
        &mut self,
        kind: &str,
        record_id: &[u8],
        incoming: Vec<DhtRecordObservation>,
    ) -> Result<Option<Vec<u8>>> {
        if kind != "dht-observed-endpoint"
            || record_id.is_empty()
            || record_id.len() > 64
            || incoming.len() > MAX_DHT_OBSERVED_SEQUENCES
        {
            anyhow::bail!("invalid durable DHT observation scope");
        }
        let now = unix_seconds();
        let stored = self.control.get_record(kind, record_id)?;
        if stored.is_none()
            && !incoming.is_empty()
            && self.control.records(kind)?.len() >= MAX_DHT_OBSERVED_ENDPOINT_SCOPES
        {
            anyhow::bail!("durable DHT observation scope limit reached");
        }
        let active_stored = match stored.as_deref() {
            Some(bytes) => {
                let state: DhtObservationState = decode_canonical(bytes)?;
                validate_dht_observation_state(&state)?;
                (state.current.expires_at_unix_seconds > now).then_some(bytes)
            }
            None => None,
        };
        let Some(state) = merge_dht_observation_state(
            if incoming.is_empty() {
                stored.as_deref()
            } else {
                active_stored
            },
            incoming,
            now,
            DHT_OBSERVATION_FORMAT_UNCERTIFIED,
        )?
        else {
            if stored.is_some() {
                self.control.delete_record(kind, record_id)?;
            }
            return Ok(None);
        };
        let selected =
            (state.current.expires_at_unix_seconds > now).then(|| state.current.bytes.clone());
        self.control
            .put_record(kind, record_id, &canonical_bytes(&state)?)?;
        Ok(selected)
    }

    pub(crate) fn select_recovery_dht_records(
        &self,
        record_id: &[u8],
        incoming: Vec<DhtRecordObservation>,
    ) -> Result<Option<Vec<u8>>> {
        if record_id.len() != 64
            || record_id[..32] != self.keys.node_id().0
            || incoming.len() > MAX_DHT_OBSERVED_SEQUENCES
        {
            anyhow::bail!("invalid recovery DHT observation scope");
        }
        let now = unix_seconds();
        let stored = self
            .control
            .get_record("dht-observed-recovery", record_id)?;
        let active_stored = match stored.as_deref() {
            Some(bytes) => {
                let state: DhtObservationState = decode_canonical(bytes)?;
                validate_dht_observation_state(&state)?;
                (state.format_version == DHT_OBSERVATION_FORMAT_CERTIFIED
                    && state.current.expires_at_unix_seconds > now)
                    .then_some(bytes)
            }
            None => None,
        };
        Ok(merge_dht_observation_state(
            active_stored,
            incoming,
            now,
            DHT_OBSERVATION_FORMAT_UNCERTIFIED,
        )?
        .map(|state| state.current.bytes))
    }

    pub(crate) fn retain_checkpoint_recovery_records(
        &mut self,
        checkpoint: &QuorumCheckpoint,
        observations: Vec<CheckpointRecoveryObservation>,
    ) -> Result<()> {
        let reconciliation =
            self.checkpoint_recovery_record_reconciliation(checkpoint, observations, None)?;
        self.control.reconcile_records(
            "dht-observed-recovery",
            &reconciliation.delete_record_ids,
            &reconciliation.replacements,
        )?;
        Ok(())
    }

    fn checkpoint_recovery_record_reconciliation(
        &self,
        checkpoint: &QuorumCheckpoint,
        observations: Vec<CheckpointRecoveryObservation>,
        recovered_dynamic_state: Option<&DynamicGuildState>,
    ) -> Result<DhtRecordReconciliation> {
        checkpoint.verify()?;
        let subject = self.keys.node_id();
        if !checkpoint
            .checkpoint
            .members
            .iter()
            .any(|member| member.node_id == subject)
        {
            anyhow::bail!("recovery checkpoint does not contain this node");
        }

        let mut allowed = BTreeMap::new();
        for member in &checkpoint.checkpoint.members {
            let peer_id = member.node_id.libp2p_peer_id()?.to_string();
            allowed.insert(
                recovery_observation_record_id(subject, &peer_id).to_vec(),
                (member.node_id, peer_id),
            );
        }

        let now = unix_seconds();
        let records = self.control.records("dht-observed-recovery")?;
        let mut retained = BTreeMap::<Vec<u8>, Vec<u8>>::new();
        let mut delete_record_ids = Vec::new();
        let mut replacements = Vec::new();
        for (record_id, bytes) in records {
            if record_id.len() != 64 {
                anyhow::bail!("invalid durable recovery observation scope");
            }
            let mut state: DhtObservationState = decode_canonical(&bytes)?;
            validate_dht_observation_state(&state)?;
            let Some((publisher, provider_peer_id)) = allowed.get(&record_id) else {
                delete_record_ids.push(record_id);
                continue;
            };
            if record_id[..32] != subject.0 || state.current.expires_at_unix_seconds <= now {
                delete_record_ids.push(record_id);
                continue;
            }
            let Ok(selected) =
                decode_canonical::<SignedRecord<RecoveryBundle>>(&state.current.bytes)
            else {
                delete_record_ids.push(record_id);
                continue;
            };
            let candidate = CheckpointRecoveryObservation {
                provider_peer_id: provider_peer_id.clone(),
                selected,
                observations: Vec::new(),
            };
            if candidate.selected.value.publisher != *publisher
                || candidate.selected.value.sequence != state.current.sequence
                || candidate.selected.value.expires_at_unix_seconds
                    != state.current.expires_at_unix_seconds
                || self
                    .validate_checkpoint_recovery_observation(
                        checkpoint,
                        &candidate,
                        now,
                        recovered_dynamic_state,
                    )
                    .is_err()
            {
                delete_record_ids.push(record_id);
                continue;
            }
            let certified_bytes = if state.format_version == DHT_OBSERVATION_FORMAT_CERTIFIED {
                bytes
            } else {
                state.format_version = DHT_OBSERVATION_FORMAT_CERTIFIED;
                let certified = canonical_bytes(&state)?;
                replacements.push((record_id.clone(), certified.clone()));
                certified
            };
            retained.insert(record_id, certified_bytes);
        }

        let mut seen_publishers = BTreeMap::new();
        for observation in observations {
            let publisher = self.validate_checkpoint_recovery_observation(
                checkpoint,
                &observation,
                now,
                recovered_dynamic_state,
            )?;
            if seen_publishers.insert(publisher, ()).is_some() {
                anyhow::bail!("duplicate certified recovery publisher");
            }
            if observation.observations.is_empty() {
                continue;
            }
            let record_id =
                recovery_observation_record_id(subject, &observation.provider_peer_id).to_vec();
            let state = merge_dht_observation_state(
                retained.get(&record_id).map(Vec::as_slice),
                observation.observations,
                now,
                DHT_OBSERVATION_FORMAT_CERTIFIED,
            )?
            .context("certified recovery observation has no current record")?;
            let bytes = canonical_bytes(&state)?;
            retained.insert(record_id.clone(), bytes.clone());
            replacements.push((record_id, bytes));
        }
        if retained.len() > MAX_DHT_OBSERVED_RECOVERY_SCOPES {
            anyhow::bail!("durable recovery observation scope limit reached");
        }
        Ok(DhtRecordReconciliation {
            delete_record_ids,
            replacements,
        })
    }

    fn validate_checkpoint_recovery_observation(
        &self,
        checkpoint: &QuorumCheckpoint,
        observation: &CheckpointRecoveryObservation,
        now: u64,
        recovered_dynamic_state: Option<&DynamicGuildState>,
    ) -> Result<NodeId> {
        let bundle = &observation.selected;
        bundle.verify(b"mutualbackup/recovery-bundle/v1")?;
        if bundle.value.format_version != 1 && bundle.value.format_version != 2
            || bundle.value.subject != self.keys.node_id()
            || bundle.value.publisher != bundle.signer
            || bundle.value.sequence == 0
            || bundle.value.expires_at_unix_seconds <= now
            || bundle.value.publisher.libp2p_peer_id()?.to_string() != observation.provider_peer_id
        {
            anyhow::bail!("invalid certified recovery bundle");
        }
        self.validate_recovery_bundle_key_with_state(
            checkpoint,
            &bundle.value,
            recovered_dynamic_state,
        )?;
        let plaintext = self.open_recovery_bundle_record(&bundle.value)?;
        let locator: SignedRecord<RecoveryLocator> = decode_canonical(&plaintext)?;
        locator.verify(RECOVERY_LOCATOR_DOMAIN)?;
        if locator.signer != bundle.value.publisher
            || locator.value.format_version != 1
            || locator.value.subject != bundle.value.subject
            || locator.value.publisher != bundle.value.publisher
            || locator.value.expires_at_unix_seconds != bundle.value.expires_at_unix_seconds
            || locator.value.expires_at_unix_seconds <= now
        {
            anyhow::bail!("certified recovery locator differs from its bundle");
        }
        validate_endpoint_set(locator.value.publisher, &locator.value.endpoints)?;
        checkpoint.validate_recovery_authority(
            self.keys(),
            &locator.value,
            bundle.value.publisher,
        )?;
        for record in &observation.observations {
            let observed: SignedRecord<RecoveryBundle> = decode_canonical(&record.bytes)?;
            observed.verify(b"mutualbackup/recovery-bundle/v1")?;
            if record.sequence != observed.value.sequence
                || record.expires_at_unix_seconds != observed.value.expires_at_unix_seconds
                || !matches!(
                    (&observed.value.format_version, &observed.value.key_envelope),
                    (1, None) | (2, Some(_))
                )
                || observed.value.subject != bundle.value.subject
                || observed.value.publisher != bundle.value.publisher
                || observed.value.publisher != observed.signer
                || observed.value.publisher.libp2p_peer_id()?.to_string()
                    != observation.provider_peer_id
            {
                anyhow::bail!("invalid certified recovery observation history");
            }
        }
        Ok(bundle.value.publisher)
    }

    pub(crate) fn open_recovery_bundle_record(&self, bundle: &RecoveryBundle) -> Result<Vec<u8>> {
        match (bundle.format_version, &bundle.key_envelope) {
            (1, None) => Ok(open_recovery_record(self.keys(), &bundle.sealed)?),
            (2, Some(envelope)) if envelope.subject == bundle.subject => {
                let secret = open_recovery_key_envelope(self.keys(), envelope)?;
                Ok(secret.open_record(&bundle.sealed)?)
            }
            _ => anyhow::bail!("recovery bundle has an invalid key envelope"),
        }
    }

    pub(crate) fn validate_recovery_bundle_key(
        &self,
        checkpoint: &QuorumCheckpoint,
        bundle: &RecoveryBundle,
    ) -> Result<()> {
        self.validate_recovery_bundle_key_with_state(checkpoint, bundle, None)
    }

    fn validate_recovery_bundle_key_with_state(
        &self,
        checkpoint: &QuorumCheckpoint,
        bundle: &RecoveryBundle,
        recovered_dynamic_state: Option<&DynamicGuildState>,
    ) -> Result<()> {
        match checkpoint.checkpoint.format_version {
            3 if bundle.format_version == 1 && bundle.key_envelope.is_none() => Ok(()),
            4..=7 => {
                let local_dynamic_state = if recovered_dynamic_state.is_none() {
                    self.dynamic_guild_state()?
                } else {
                    None
                };
                let state = recovered_dynamic_state
                    .or(local_dynamic_state.as_ref())
                    .context("dynamic recovery requires dynamic guild state")?;
                state.validate()?;
                if state.guild_id != checkpoint.checkpoint.guild_id {
                    anyhow::bail!("dynamic recovery state belongs to another guild");
                }
                let current = state
                    .current_recovery_key(bundle.subject)
                    .context("recovery key epoch is unavailable or revoked")?;
                if bundle.format_version != 2
                    || bundle.key_envelope.as_ref() != Some(&current.envelope)
                {
                    anyhow::bail!("recovery bundle does not use the current key epoch");
                }
                Ok(())
            }
            _ => anyhow::bail!("recovery bundle format does not match its checkpoint"),
        }
    }

    pub(crate) fn observed_recovery_records(
        &mut self,
        subject: NodeId,
    ) -> Result<Vec<([u8; 32], Vec<u8>)>> {
        let records = self.control.records("dht-observed-recovery")?;
        let mut selected = Vec::new();
        let now = unix_seconds();
        let mut delete_record_ids = Vec::new();
        for (record_id, bytes) in records {
            if record_id.len() != 64 {
                anyhow::bail!("invalid durable recovery observation scope");
            }
            let state: DhtObservationState = decode_canonical(&bytes)?;
            validate_dht_observation_state(&state)?;
            if record_id[..32] != subject.0 || state.current.expires_at_unix_seconds <= now {
                delete_record_ids.push(record_id);
                continue;
            }
            let mut provider_hash = [0_u8; 32];
            provider_hash.copy_from_slice(&record_id[32..]);
            selected.push((provider_hash, state.current.bytes));
        }
        self.control
            .reconcile_records("dht-observed-recovery", &delete_record_ids, &[])?;
        Ok(selected)
    }

    pub fn update_seed_recovery_readiness(
        &mut self,
        checkpoint_hash: [u8; 32],
        confirmations: Vec<(NodeId, u64)>,
    ) -> Result<()> {
        let checkpoint = self.checkpoint(&checkpoint_hash)?;
        if checkpoint.checkpoint.guild_id
            != self
                .installed_guild()?
                .context("this node has no active guild")?
                .certificate
                .genesis
                .guild_id
        {
            anyhow::bail!("recovery readiness checkpoint belongs to another guild");
        }
        let (allowed_publishers, required_publishers) =
            self.recovery_readiness_publishers(&checkpoint)?;
        let now = unix_seconds();
        let mut by_publisher = BTreeMap::new();
        for (publisher, expires_at) in confirmations {
            if expires_at > now && allowed_publishers.contains(&publisher) {
                by_publisher
                    .entry(publisher)
                    .and_modify(|current: &mut u64| *current = (*current).max(expires_at))
                    .or_insert(expires_at);
            }
        }
        let mut expiries = by_publisher.values().copied().collect::<Vec<_>>();
        expiries.sort_unstable_by(|left, right| right.cmp(left));
        let confirmed_until_unix_seconds =
            expiries.get(required_publishers - 1).copied().unwrap_or(0);
        self.control.put_record(
            "seed-recovery-ready",
            b"primary",
            &canonical_bytes(&SeedRecoveryReadiness {
                format_version: 1,
                checkpoint_hash,
                confirmed_until_unix_seconds,
                publishers: by_publisher.into_keys().collect(),
            })?,
        )?;
        Ok(())
    }

    pub fn seed_recovery_ready(&self) -> Result<bool> {
        let Some(bytes) = self.control.get_record("seed-recovery-ready", b"primary")? else {
            return Ok(false);
        };
        let ready: SeedRecoveryReadiness = decode_canonical(&bytes)?;
        if ready.format_version != 1 || ready.confirmed_until_unix_seconds <= unix_seconds() {
            return Ok(false);
        }
        let Some(installed) = self.installed_guild()? else {
            return Ok(false);
        };
        let Some(checkpoint) = self.current_checkpoint(installed.certificate.genesis.guild_id)?
        else {
            return Ok(false);
        };
        if checkpoint.hash()? != ready.checkpoint_hash {
            return Ok(false);
        }
        let (allowed_publishers, required_publishers) =
            self.recovery_readiness_publishers(&checkpoint)?;
        Ok(ready
            .publishers
            .iter()
            .filter(|publisher| allowed_publishers.contains(publisher))
            .count()
            >= required_publishers)
    }

    fn recovery_readiness_publishers(
        &self,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<(BTreeSet<NodeId>, usize)> {
        let local_id = self.keys.node_id();
        let members = if matches!(checkpoint.checkpoint.format_version, 4..=7) {
            let state = self
                .dynamic_guild_state()?
                .context("dynamic recovery readiness requires dynamic guild state")?;
            let active = state.active_members().cloned().collect::<Vec<_>>();
            if active != checkpoint.checkpoint.members {
                anyhow::bail!("recovery readiness checkpoint has a stale membership roster");
            }
            active
        } else {
            checkpoint.checkpoint.members.clone()
        };
        let publishers = members
            .iter()
            .map(|member| member.node_id)
            .filter(|member| *member != local_id)
            .collect::<BTreeSet<_>>();
        if publishers.is_empty() {
            anyhow::bail!("seed recovery requires another active guild member");
        }
        let required = publishers.len().min(3);
        Ok((publishers, required))
    }

    pub fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let checkpoint = self
            .current_checkpoint(installed.certificate.genesis.guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let checkpoint_hash = checkpoint.hash()?;
        Ok(checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == self.keys.node_id())
            .map(|revision| SnapshotInfo {
                protected_root_id: revision.value.protected_root_id,
                revision_id: revision.value.revision_id,
                sequence: revision.value.sequence,
                checkpoint_generation: checkpoint.checkpoint.generation,
                checkpoint_hash,
            })
            .collect())
    }

    pub fn restore_snapshot(
        &self,
        revision_id: Option<Uuid>,
        target: &Path,
    ) -> Result<SnapshotInfo> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let guild_id = installed.certificate.genesis.guild_id;
        let checkpoint = self
            .current_checkpoint(guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let revision = match revision_id {
            Some(revision_id) => checkpoint.checkpoint.revisions.iter().find(|revision| {
                revision.value.owner == self.keys.node_id()
                    && revision.value.revision_id == revision_id
            }),
            None => checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == self.keys.node_id())
                .max_by_key(|revision| {
                    (
                        revision.value.sequence,
                        revision.value.protected_root_id,
                        revision.value.revision_id,
                    )
                }),
        }
        .context("requested snapshot is unavailable for this node")?;
        restore_revision_from_source(
            &self.control,
            &self.keys,
            guild_id,
            revision,
            target,
            |sector_id| self.sector_for_guild(&guild_id, sector_id),
        )?;
        Ok(SnapshotInfo {
            protected_root_id: revision.value.protected_root_id,
            revision_id: revision.value.revision_id,
            sequence: revision.value.sequence,
            checkpoint_generation: checkpoint.checkpoint.generation,
            checkpoint_hash: checkpoint.hash()?,
        })
    }

    pub(crate) fn resume_snapshot_publication(
        &self,
        revision_id: Option<Uuid>,
        target: &Path,
    ) -> Result<Option<SnapshotInfo>> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let guild_id = installed.certificate.genesis.guild_id;
        let checkpoint = self
            .current_checkpoint(guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let revision = match revision_id {
            Some(revision_id) => checkpoint.checkpoint.revisions.iter().find(|revision| {
                revision.value.owner == self.keys.node_id()
                    && revision.value.revision_id == revision_id
            }),
            None => checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == self.keys.node_id())
                .max_by_key(|revision| {
                    (
                        revision.value.sequence,
                        revision.value.protected_root_id,
                        revision.value.revision_id,
                    )
                }),
        }
        .context("requested snapshot is unavailable for this node")?;
        if !resume_restore_publication(&self.control, &self.keys, guild_id, revision, target)? {
            return Ok(None);
        }
        Ok(Some(SnapshotInfo {
            protected_root_id: revision.value.protected_root_id,
            revision_id: revision.value.revision_id,
            sequence: revision.value.sequence,
            checkpoint_generation: checkpoint.checkpoint.generation,
            checkpoint_hash: checkpoint.hash()?,
        }))
    }

    pub(crate) fn snapshot_repair_plan(
        &self,
        revision_id: Option<Uuid>,
    ) -> Result<(QuorumCheckpoint, SignedRecord<UserRevision>, Vec<GuildPeer>)> {
        let installed = self
            .installed_guild()?
            .context("this node has no active guild")?;
        let checkpoint = self
            .current_checkpoint(installed.certificate.genesis.guild_id)?
            .context("guild has no committed snapshots")?;
        checkpoint.verify()?;
        let revision = match revision_id {
            Some(revision_id) => checkpoint.checkpoint.revisions.iter().find(|revision| {
                revision.value.owner == self.keys.node_id()
                    && revision.value.revision_id == revision_id
            }),
            None => checkpoint
                .checkpoint
                .revisions
                .iter()
                .filter(|revision| revision.value.owner == self.keys.node_id())
                .max_by_key(|revision| {
                    (
                        revision.value.sequence,
                        revision.value.protected_root_id,
                        revision.value.revision_id,
                    )
                }),
        }
        .cloned()
        .context("requested snapshot is unavailable for this node")?;
        Ok((checkpoint, revision, self.guild_peers(&installed)?))
    }

    pub(crate) fn install_repaired_information_sector(
        &mut self,
        guild_id: [u8; 32],
        reference: SectorRef,
        ciphertext: &[u8],
    ) -> Result<()> {
        install_recovered_sector_recipe(
            &mut self.control,
            &self.keys,
            guild_id,
            reference,
            ciphertext,
        )
    }

    pub fn next_recovery_publication_sequence(
        &mut self,
        slot: &[u8; 32],
        minimum: u64,
    ) -> Result<u64> {
        if minimum == 0 {
            anyhow::bail!("recovery publication sequence must be positive");
        }
        let current = self
            .control
            .get_record("recovery-publication-sequence", slot)?
            .map(|bytes| decode_canonical::<u64>(&bytes))
            .transpose()?
            .unwrap_or(0);
        let next = current
            .checked_add(1)
            .context("recovery publication sequence exhausted")?
            .max(minimum);
        self.control.put_record(
            "recovery-publication-sequence",
            slot,
            &canonical_bytes(&next)?,
        )?;
        Ok(next)
    }

    pub(crate) fn recover_endpoint_publication_sequence_floor(
        &mut self,
        guild_id: [u8; 32],
        recovered_floor: u64,
    ) -> Result<()> {
        if recovered_floor == u64::MAX {
            anyhow::bail!("recovered endpoint publication sequence is exhausted");
        }
        let local_id = self.keys.node_id();
        let slot = publication_slot(b"endpoint", local_id, local_id, guild_id);
        let current = self
            .control
            .get_record("recovery-publication-sequence", &slot)?
            .map(|bytes| decode_canonical::<u64>(&bytes))
            .transpose()?
            .unwrap_or(0);
        if recovered_floor > current {
            self.control.put_record(
                "recovery-publication-sequence",
                &slot,
                &canonical_bytes(&recovered_floor)?,
            )?;
        }
        Ok(())
    }

    fn observed_endpoint_sequence_floor(&self, subject: NodeId) -> Result<u64> {
        let Some(bytes) = self
            .control
            .get_record("dht-observed-endpoint", &subject.0)?
        else {
            return Ok(0);
        };
        let state: DhtObservationState = decode_canonical(&bytes)?;
        validate_dht_observation_state(&state)?;
        if state.highest_sequence == u64::MAX {
            anyhow::bail!("observed endpoint publication sequence is exhausted");
        }
        Ok(state.highest_sequence)
    }

    pub fn checkpoint(&self, hash: &[u8; 32]) -> Result<QuorumCheckpoint> {
        let bytes = self
            .control
            .get_record("guild-checkpoint", hash)?
            .context("checkpoint is unavailable")?;
        let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
        checkpoint.verify()?;
        if checkpoint.hash()? != *hash {
            anyhow::bail!("checkpoint hash mismatch");
        }
        Ok(checkpoint)
    }

    pub fn authorize_member(&self, guild_id: &[u8; 32], caller: NodeId) -> Result<()> {
        authorize_member(&self.control, guild_id, caller)
    }

    pub fn install_recovered_checkpoint(
        &mut self,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<[u8; 32]> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint, false)?;
        self.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, true)?;
        if !checkpoint.has_signature(self.keys.node_id()) {
            anyhow::bail!("checkpoint is not authorized by the recovering seed");
        }
        let checkpoint_hash = checkpoint.hash()?;
        self.require_active_recovery_attempt(checkpoint.checkpoint.guild_id, checkpoint_hash)?;
        for group in &checkpoint.checkpoint.coding_groups {
            for (index, role) in group.roles.iter().enumerate() {
                match role {
                    ShardRole::Information(information)
                        if information.owner == self.keys.node_id() =>
                    {
                        let bytes = self.control.recovery_shard(
                            &checkpoint_hash,
                            &checkpoint.checkpoint.guild_id,
                            &group.id,
                            index as u8,
                            &information.sector.root,
                        )?;
                        install_recovered_sector_recipe(
                            &mut self.control,
                            &self.keys,
                            checkpoint.checkpoint.guild_id,
                            information.sector.clone(),
                            &bytes,
                        )?;
                    }
                    ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => {
                        let bytes = self.control.recovery_shard(
                            &checkpoint_hash,
                            &checkpoint.checkpoint.guild_id,
                            &group.id,
                            index as u8,
                            &parity.root,
                        )?;
                        let object = ParityObject {
                            format_version: group.format_version,
                            guild_id: checkpoint.checkpoint.guild_id,
                            group_id: group.id,
                            shard_index: index as u8,
                            root: parity.root,
                            bytes,
                        };
                        self.validate_parity_assignment(group, &object)?;
                        self.publish_validated_parity(group, &object)?;
                    }
                    _ => {}
                }
            }
        }
        self.validate_local_roles(&checkpoint.checkpoint)?;
        let mut local_heads = BTreeMap::<Uuid, &SignedRecord<UserRevision>>::new();
        for revision in checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == self.keys.node_id())
        {
            let head = local_heads
                .entry(revision.value.protected_root_id)
                .or_insert(revision);
            if revision.value.sequence > head.value.sequence {
                *head = revision;
            }
        }
        let local_heads = local_heads
            .into_iter()
            .map(|(root_id, revision)| {
                Ok((
                    revision_head_id(checkpoint.checkpoint.guild_id, root_id),
                    canonical_bytes(revision)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        self.control.commit_recovered_checkpoint(
            &checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.generation,
            checkpoint.checkpoint.parent.as_ref(),
            &checkpoint_hash,
            &canonical_bytes(&checkpoint.checkpoint)?,
            &canonical_bytes(checkpoint)?,
            &local_heads,
            local_heads.is_empty(),
        )?;
        self.reconcile_garbage_collection()?;
        Ok(checkpoint_hash)
    }

    pub(crate) fn resume_local_recovery(
        &mut self,
        target: &Path,
    ) -> Result<Option<LocalRecoveryResume>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        let guild_id = installed.certificate.genesis.guild_id;
        let Some(checkpoint) = self.current_checkpoint(guild_id)? else {
            return Ok(None);
        };
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint, false)?;
        let checkpoint_hash = checkpoint.hash()?;
        let revision = checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| revision.value.owner == self.keys.node_id())
            .max_by_key(|revision| {
                (
                    revision.value.sequence,
                    revision.value.protected_root_id,
                    revision.value.revision_id,
                )
            })
            .cloned();
        let revision_id = revision.as_ref().map(|revision| revision.value.revision_id);
        if let Some(revision) = revision {
            self.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, target)?;
        }
        Ok(Some(LocalRecoveryResume {
            guild_id,
            checkpoint_hash,
            generation: checkpoint.checkpoint.generation,
            revision_id,
        }))
    }

    pub(crate) fn pin_recovery_attempt(
        &mut self,
        checkpoint: &QuorumCheckpoint,
        observations: Vec<CheckpointRecoveryObservation>,
        recovered_dynamic_state: Option<&DynamicGuildState>,
    ) -> Result<()> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint, false)?;
        let checkpoint_hash = checkpoint.hash()?;
        if let Some(active) = self.active_recovery_attempt()?
            && (active.guild_id != checkpoint.checkpoint.guild_id
                || active.generation != checkpoint.checkpoint.generation
                || active.checkpoint_hash != checkpoint_hash)
        {
            anyhow::bail!("recovery attempt would roll back or fork durable recovery state");
        }
        let reconciliation = self.checkpoint_recovery_record_reconciliation(
            checkpoint,
            observations,
            recovered_dynamic_state,
        )?;
        for (record_id, bytes) in self.control.records("recovery-job")? {
            if record_id.as_slice() == checkpoint_hash {
                continue;
            }
            if record_id.len() != checkpoint_hash.len() {
                anyhow::bail!("durable recovery job has an invalid checkpoint key");
            }
            let job: RecoveryJob = decode_canonical(&bytes)?;
            self.remove_superseded_recovery_job(&job)?;
        }
        let attempt = RecoveryAttempt {
            format_version: 1,
            guild_id: checkpoint.checkpoint.guild_id,
            checkpoint_hash,
            generation: checkpoint.checkpoint.generation,
        };
        self.control.pin_recovery_attempt_and_reconcile_records(
            &checkpoint_hash,
            &canonical_bytes(&attempt)?,
            "dht-observed-recovery",
            &reconciliation.delete_record_ids,
            &reconciliation.replacements,
        )?;
        Ok(())
    }

    fn active_recovery_attempt(&self) -> Result<Option<RecoveryAttempt>> {
        let attempt = self
            .control
            .get_record("recovery-attempt", b"active")?
            .map(|bytes| decode_canonical::<RecoveryAttempt>(&bytes))
            .transpose()?;
        if let Some(attempt) = &attempt
            && (attempt.format_version != 1
                || attempt.guild_id == [0; 32]
                || attempt.checkpoint_hash == [0; 32]
                || attempt.generation == 0)
        {
            anyhow::bail!("invalid durable recovery attempt");
        }
        Ok(attempt)
    }

    fn require_active_recovery_attempt(
        &self,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    ) -> Result<()> {
        if let Some(active) = self.active_recovery_attempt()?
            && (active.guild_id != guild_id || active.checkpoint_hash != checkpoint_hash)
        {
            anyhow::bail!("operation belongs to a superseded recovery attempt");
        }
        Ok(())
    }

    fn remove_superseded_recovery_job(&mut self, job: &RecoveryJob) -> Result<()> {
        if job.format_version != 7 {
            anyhow::bail!("unsupported durable recovery job version");
        }
        let parent_path = containing_directory(&job.target);
        if job.staging.parent() != Some(parent_path)
            || !job
                .staging
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(".mutualbackup-restore-"))
        {
            anyhow::bail!("durable recovery job contains an unsafe staging path");
        }
        let parent = PinnedDirectory::open(parent_path)?;
        if job.parent_native_id != Some(native_id_tuple(parent.identity()?)) {
            anyhow::bail!("durable recovery parent directory changed unexpectedly");
        }
        let target_name = job
            .target
            .file_name()
            .and_then(|name| name.to_str())
            .context("durable recovery target has no UTF-8 file name")?;
        if parent.entry_identity(target_name, true)?.is_some()
            && job.state != RecoveryJobState::Complete
        {
            anyhow::bail!("superseded recovery still owns an unfinished published target");
        }
        let staging_name = job
            .staging
            .file_name()
            .and_then(|name| name.to_str())
            .context("durable recovery staging has no UTF-8 file name")?;
        if let Some(actual) = parent.entry_identity(staging_name, true)? {
            match job.staged_native_id.map(tuple_native_id) {
                Some(expected) if actual == expected => {
                    parent.remove_child_directory(staging_name, actual)?;
                    parent.sync_all()?;
                }
                Some(_) => anyhow::bail!("durable recovery staging directory was replaced"),
                None => {}
            }
        }
        Ok(())
    }

    pub fn stage_recovered_shard(
        &mut self,
        checkpoint_hash: &[u8; 32],
        guild_id: &[u8; 32],
        group: &mb_core::CodingGroup,
        shard_index: u8,
        bytes: &[u8],
    ) -> Result<()> {
        self.require_active_recovery_attempt(*guild_id, *checkpoint_hash)?;
        let role = group
            .roles
            .get(shard_index as usize)
            .context("recovered shard index is out of range")?;
        let root = match role {
            ShardRole::Information(information) if information.owner == self.keys.node_id() => {
                information.sector.root
            }
            ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => parity.root,
            _ => anyhow::bail!("recovered shard is not assigned to the local node"),
        };
        if group.guild_id != *guild_id {
            anyhow::bail!("recovered shard has the wrong guild context");
        }
        self.control.stage_recovery_shard(
            checkpoint_hash,
            guild_id,
            &group.id,
            shard_index,
            &root,
            bytes,
        )?;
        Ok(())
    }

    pub(crate) fn stage_recovered_variable_shard(
        &mut self,
        checkpoint_hash: &[u8; 32],
        transcript: &SignedRecord<CodingVerificationTranscript>,
        shard_index: u16,
        bytes: &[u8],
    ) -> Result<()> {
        let plan = &transcript.value.plan;
        let group = &transcript.value.manifest.value.group;
        self.require_active_recovery_attempt(group.guild_id, *checkpoint_hash)?;
        self.validate_coding_attempt_authority(plan)?;
        if replay_coding_transcript(transcript)? != CodingReplayFinding::Verified
            || !self
                .dynamic_guild_state()?
                .context("node has no dynamic guild state")?
                .coding_groups
                .iter()
                .any(|retained| retained.group == *group)
        {
            anyhow::bail!("recovered variable shard has no certified coding group");
        }
        let (storage_group, commitment) = match group.roles.get(usize::from(shard_index)) {
            Some(ShardRoleV2::Information(information))
                if information.owner == self.keys.node_id() && !information.sector.virtual_zero =>
            {
                (information.sector.id, &information.sector.commitment)
            }
            Some(ShardRoleV2::Parity(parity)) if parity.holder == self.keys.node_id() => {
                (group.id, &parity.commitment)
            }
            _ => anyhow::bail!("recovered variable shard is not assigned to the local node"),
        };
        if bytes.len() != commitment.byte_len as usize || merkle_commit(bytes)? != *commitment {
            anyhow::bail!("recovered variable shard conflicts with its commitment");
        }
        self.volumes.reserve_attempt(
            &self.control,
            &plan.value.attempt_id,
            group.guild_id,
            shard_index,
            commitment.byte_len,
        )?;
        let mut offset = 0_u32;
        for chunk in bytes.chunks(1024 * 1024) {
            offset = self.volumes.write_attempt_range(
                &self.control,
                &plan.value.attempt_id,
                shard_index,
                offset,
                chunk,
            )?;
        }
        if offset != commitment.byte_len {
            anyhow::bail!("recovered variable shard upload is incomplete");
        }
        self.volumes.finish_attempt_upload(
            &self.control,
            &plan.value.attempt_id,
            storage_group,
            shard_index,
            commitment,
        )?;
        let transcript_hash = blake3::hash(&canonical_bytes(transcript)?);
        self.volumes.attach_attempt_receipt(
            &self.control,
            &plan.value.attempt_id,
            &storage_group,
            shard_index,
            transcript_hash.as_bytes(),
        )?;
        Ok(())
    }

    pub fn recovered_shard_is_staged(
        &self,
        checkpoint_hash: &[u8; 32],
        guild_id: &[u8; 32],
        group: &mb_core::CodingGroup,
        shard_index: u8,
    ) -> Result<bool> {
        self.require_active_recovery_attempt(*guild_id, *checkpoint_hash)?;
        let role = group
            .roles
            .get(shard_index as usize)
            .context("recovered shard index is out of range")?;
        let root = match role {
            ShardRole::Information(information) if information.owner == self.keys.node_id() => {
                information.sector.root
            }
            ShardRole::Parity(parity) if parity.holder == self.keys.node_id() => parity.root,
            _ => anyhow::bail!("recovered shard is not assigned to the local node"),
        };
        if group.guild_id != *guild_id {
            anyhow::bail!("recovered shard has the wrong guild context");
        }
        match self
            .control
            .recovery_shard(checkpoint_hash, guild_id, &group.id, shard_index, &root)
        {
            Ok(_) => Ok(true),
            Err(DatabaseError::NotReady) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn restore_recovered_revision(
        &mut self,
        checkpoint_hash: &[u8; 32],
        guild_id: [u8; 32],
        revision: &SignedRecord<UserRevision>,
        target: &Path,
    ) -> Result<()> {
        self.require_active_recovery_attempt(guild_id, *checkpoint_hash)?;
        let (target, target_name, parent_path, parent) = pinned_recovery_target(target)?;
        let parent_identity = native_id_tuple(parent.identity()?);
        let existing = self.control.get_record("recovery-job", checkpoint_hash)?;
        let is_new_job = existing.is_none();
        let mut job = match existing {
            Some(bytes) => {
                let job: RecoveryJob = decode_canonical(&bytes)?;
                if job.format_version != 7
                    || job.guild_id != guild_id
                    || job.revision_id != revision.value.revision_id
                    || job.target != target
                    || job.staging.parent() != Some(parent_path.as_path())
                    || job.parent_native_id != Some(parent_identity)
                {
                    anyhow::bail!("recovery job conflicts with durable local state");
                }
                job
            }
            None => RecoveryJob {
                format_version: 7,
                guild_id,
                revision_id: revision.value.revision_id,
                target: target.clone(),
                staging: parent_path.join(format!(".mutualbackup-restore-{}", Uuid::new_v4())),
                staged_native_id: None,
                state: RecoveryJobState::Building,
                parent_native_id: Some(parent_identity),
            },
        };
        if is_new_job {
            self.control
                .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        }

        let mut staging_name = job
            .staging
            .file_name()
            .and_then(|name| name.to_str())
            .context("durable recovery staging path has no UTF-8 file name")?
            .to_owned();
        let expected = job.staged_native_id.map(tuple_native_id);
        let target_identity = parent.entry_identity(&target_name, true)?;

        if let Some(actual) = target_identity {
            let expected =
                expected.context("existing restore target is not owned by this recovery job")?;
            if actual != expected {
                anyhow::bail!("existing restore target was created by another actor");
            }
            match job.state {
                RecoveryJobState::Complete => {
                    let mut needs_reanchor = false;
                    for reference in &revision.value.data_sectors {
                        if !recovered_recipe_is_stable(
                            &self.control,
                            &self.keys,
                            guild_id,
                            reference,
                        )? {
                            needs_reanchor = true;
                            break;
                        }
                    }
                    if needs_reanchor {
                        let restored = open_expected_recovery_directory(
                            &parent,
                            &target_name,
                            Some(expected),
                        )?;
                        reanchor_recovered_revision(
                            &mut self.control,
                            &self.keys,
                            guild_id,
                            revision,
                            &restored.descriptor_path(),
                        )?;
                    }
                    verify_pinned_parent_path(&parent, &parent_path)?;
                    return Ok(());
                }
                RecoveryJobState::Ready => {
                    publish_owned_restore(&parent, &staging_name, &target_name, expected)?;
                    verify_pinned_parent_path(&parent, &parent_path)?;
                    job.state = RecoveryJobState::Published;
                    self.control.put_record(
                        "recovery-job",
                        checkpoint_hash,
                        &canonical_bytes(&job)?,
                    )?;
                }
                RecoveryJobState::Published => {}
                RecoveryJobState::Building | RecoveryJobState::Anchoring => {
                    anyhow::bail!(
                        "existing restore target is not owned by a publishable recovery job"
                    );
                }
            }
            return self.finish_recovery(
                &mut job,
                checkpoint_hash,
                revision,
                &parent,
                &target_name,
            );
        }

        if job.state == RecoveryJobState::Anchoring {
            let staging = open_expected_recovery_directory(&parent, &staging_name, expected)?;
            reanchor_recovered_revision(
                &mut self.control,
                &self.keys,
                guild_id,
                revision,
                &staging.descriptor_path(),
            )?;
            if parent.entry_identity(&staging_name, true)? != expected {
                anyhow::bail!("recovery staging directory changed while it was anchored");
            }
            make_restore_root_private_at(&staging)?;
            job.state = RecoveryJobState::Ready;
            self.control
                .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        }

        if job.state == RecoveryJobState::Ready {
            let expected = job
                .staged_native_id
                .map(tuple_native_id)
                .context("ready recovery job has no staged native identity")?;
            publish_owned_restore(&parent, &staging_name, &target_name, expected)?;
            verify_pinned_parent_path(&parent, &parent_path)?;
            job.state = RecoveryJobState::Published;
            self.control
                .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
            return self.finish_recovery(
                &mut job,
                checkpoint_hash,
                revision,
                &parent,
                &target_name,
            );
        }

        if matches!(
            job.state,
            RecoveryJobState::Published | RecoveryJobState::Complete
        ) {
            anyhow::bail!("published recovery target disappeared");
        }

        if job.state == RecoveryJobState::Anchoring {
            abandon_recovered_anchor_capture(&self.control, guild_id, revision.value.revision_id)?;
        }

        if let Some(actual) = parent.entry_identity(&staging_name, true)? {
            match expected {
                Some(expected) if actual == expected => {
                    parent.remove_child_directory(&staging_name, actual)?;
                    parent.sync_all()?;
                }
                Some(_) => anyhow::bail!("recovery staging directory was replaced"),
                None => {
                    // The process may have stopped between creating the
                    // directory and recording its inode. The name is not an
                    // ownership proof, so leave this entry untouched and
                    // continue under a fresh random name.
                }
            }
        }
        staging_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        job.staging = parent_path.join(&staging_name);
        job.state = RecoveryJobState::Building;
        job.staged_native_id = None;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        let staging = parent.create_child_directory(&staging_name)?;
        run_after_recovery_staging_create_hook()?;
        parent.sync_all()?;
        let staged_identity = staging.identity()?;
        job.staged_native_id = Some(native_id_tuple(staged_identity));
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        build_revision_restore(
            &self.keys,
            guild_id,
            revision,
            &staging,
            &mut |sector_id| self.sector(sector_id),
            false,
        )?;
        restore_signed_root_metadata_at(&self.control, &self.keys, guild_id, revision, &staging)?;
        if parent.entry_identity(&staging_name, true)? != Some(staged_identity) {
            anyhow::bail!("recovery staging directory changed during construction");
        }
        job.state = RecoveryJobState::Anchoring;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        reanchor_recovered_revision(
            &mut self.control,
            &self.keys,
            guild_id,
            revision,
            &staging.descriptor_path(),
        )?;
        if parent.entry_identity(&staging_name, true)? != Some(staged_identity) {
            anyhow::bail!("recovery staging directory changed while it was anchored");
        }
        make_restore_root_private_at(&staging)?;
        job.state = RecoveryJobState::Ready;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        publish_owned_restore(&parent, &staging_name, &target_name, staged_identity)?;
        verify_pinned_parent_path(&parent, &parent_path)?;
        job.state = RecoveryJobState::Published;
        self.control
            .put_record("recovery-job", checkpoint_hash, &canonical_bytes(&job)?)?;
        self.finish_recovery(&mut job, checkpoint_hash, revision, &parent, &target_name)
    }

    fn finish_recovery(
        &mut self,
        job: &mut RecoveryJob,
        checkpoint_hash: &[u8; 32],
        revision: &SignedRecord<UserRevision>,
        parent: &PinnedDirectory,
        target_name: &str,
    ) -> Result<()> {
        let expected = job
            .staged_native_id
            .map(tuple_native_id)
            .context("published recovery job has no native identity")?;
        let target = open_expected_recovery_directory(parent, target_name, Some(expected))?;
        make_restore_root_private_at(&target)?;
        if !revision.value.metadata_sectors.is_empty() {
            restore_signed_root_metadata_at(
                &self.control,
                &self.keys,
                job.guild_id,
                revision,
                &target,
            )?;
        }
        verify_pinned_parent_path(parent, containing_directory(&job.target))?;
        self.register_protected_root(
            &job.target,
            Some(revision.value.protected_root_id),
            false,
            false,
        )?;
        job.state = RecoveryJobState::Complete;
        self.control
            .complete_recovery_attempt(checkpoint_hash, &canonical_bytes(job)?)?;
        Ok(())
    }

    pub fn cached_operation(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: NodeId,
        request_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>> {
        Ok(self
            .control
            .begin_operation(operation_id, kind, &caller.0, request_hash)?)
    }

    pub fn commit_operation(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: NodeId,
        request_hash: &[u8; 32],
        result: &[u8],
    ) -> Result<()> {
        self.control
            .put_operation_result(operation_id, kind, &caller.0, request_hash, result)?;
        Ok(())
    }
}

fn packed_record_id(guild_id: &[u8; 32], object_id: &[u8; 32]) -> Vec<u8> {
    let mut record_id = Vec::with_capacity(64);
    record_id.extend_from_slice(guild_id);
    record_id.extend_from_slice(object_id);
    record_id
}

fn validate_packed_sector(profile: PackingProfile, sector: &PackedSector) -> Result<()> {
    profile.validate()?;
    if sector.descriptor.calculate_id(profile)? != sector.descriptor.id
        || sector.descriptor.commitment.byte_len != profile.sector_size
        || sector.bytes.len() != profile.sector_size as usize
        || *blake3::hash(&sector.bytes).as_bytes() != sector.descriptor.flat_root
        || merkle_commit(&sector.bytes)? != sector.descriptor.commitment
    {
        anyhow::bail!("packed sector conflicts with its authenticated descriptor");
    }
    Ok(())
}

fn load_packed_sector(
    control: &ControlStore,
    guild_id: &[u8; 32],
    sector_id: &SectorId,
) -> Result<Vec<u8>> {
    let record: PackedSectorRecord = decode_canonical(
        &control
            .get_record("packed-sector", &packed_record_id(guild_id, sector_id))?
            .context("packed sector is unavailable")?,
    )?;
    if record.format_version != 1
        || record.guild_id != *guild_id
        || record.sector.descriptor.id != *sector_id
        || record.sector.bytes.len()
            != usize::try_from(record.sector.descriptor.commitment.byte_len)?
        || *blake3::hash(&record.sector.bytes).as_bytes() != record.sector.descriptor.flat_root
        || merkle_commit(&record.sector.bytes)? != record.sector.descriptor.commitment
    {
        anyhow::bail!("packed sector record is invalid");
    }
    Ok(record.sector.bytes)
}

fn truncate_utf8(value: &mut String, maximum_bytes: usize) {
    if value.len() <= maximum_bytes {
        return;
    }
    let mut boundary = maximum_bytes;
    while !value.is_char_boundary(boundary) {
        boundary -= 1;
    }
    value.truncate(boundary);
}

fn decode_installed_guild(bytes: &[u8]) -> Result<InstalledGuild> {
    let installed: InstalledGuild = decode_canonical(bytes)?;
    if installed.format_version != 2 {
        anyhow::bail!("unsupported installed guild format version");
    }
    installed.certificate.verify()?;
    Ok(installed)
}

fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn pinned_recovery_target(target: &Path) -> Result<(PathBuf, String, PathBuf, PinnedDirectory)> {
    let parent_hint = containing_directory(target);
    fs::create_dir_all(parent_hint)?;
    let parent_path = parent_hint.canonicalize()?;
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("recovery target needs one UTF-8 file name")?
        .to_owned();
    let relative = Path::new(&target_name);
    if relative.components().count() != 1
        || !matches!(
            relative.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        anyhow::bail!("recovery target needs one safe file name");
    }
    let parent = PinnedDirectory::open(&parent_path)?;
    Ok((
        parent_path.join(&target_name),
        target_name,
        parent_path,
        parent,
    ))
}

fn native_id_tuple(identity: NativeFileId) -> (u64, u64) {
    (identity.filesystem_id, identity.inode)
}

fn tuple_native_id(identity: (u64, u64)) -> NativeFileId {
    NativeFileId {
        filesystem_id: identity.0,
        inode: identity.1,
    }
}

fn open_expected_recovery_directory(
    parent: &PinnedDirectory,
    name: &str,
    expected: Option<NativeFileId>,
) -> Result<PinnedDirectory> {
    let expected = expected.context("durable recovery staging has no native identity")?;
    let directory = parent
        .open_child_directory(name)?
        .context("durable recovery directory disappeared")?;
    if directory.identity()? != expected {
        anyhow::bail!("durable recovery directory was replaced");
    }
    Ok(directory)
}

fn verify_pinned_parent_path(parent: &PinnedDirectory, expected: &Path) -> Result<()> {
    if parent.descriptor_path().canonicalize()? != expected {
        anyhow::bail!("recovery parent directory was renamed during publication");
    }
    Ok(())
}

#[cfg(test)]
fn run_after_recovery_staging_create_hook() -> Result<()> {
    INTERRUPT_AFTER_RECOVERY_STAGING_CREATE.with(|interrupt| {
        if interrupt.replace(false) {
            anyhow::bail!("injected interruption after recovery staging creation");
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn run_after_recovery_staging_create_hook() -> Result<()> {
    Ok(())
}

fn authorize_member(control: &ControlStore, guild_id: &[u8; 32], caller: NodeId) -> Result<()> {
    if let Some(bytes) = control.get_record("guild-dynamic-state", b"primary")? {
        let state: DynamicGuildState = decode_canonical(&bytes)?;
        state.validate()?;
        if state.guild_id != *guild_id
            || !state
                .active_members()
                .any(|member| member.node_id == caller)
        {
            anyhow::bail!("caller is not an authorized guild member");
        }
        return Ok(());
    }
    if let Some(bytes) = control.get_record("guild-installed", b"primary")? {
        let installed = decode_installed_guild(&bytes)?;
        if installed.certificate.genesis.guild_id != *guild_id
            || !installed
                .certificate
                .genesis
                .members
                .iter()
                .any(|member| member.node_id == caller)
        {
            anyhow::bail!("caller is not an authorized guild member");
        }
        return Ok(());
    }
    let (_, _, bytes) = control
        .checkpoint_head(guild_id)?
        .context("guild has no locally committed checkpoint")?;
    let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
    checkpoint.verify()?;
    if checkpoint.checkpoint.guild_id != *guild_id
        || !checkpoint
            .checkpoint
            .members
            .iter()
            .any(|member| member.node_id == caller)
    {
        anyhow::bail!("caller is not an authorized guild member");
    }
    Ok(())
}

fn authorize_historical_member(
    control: &ControlStore,
    guild_id: &[u8; 32],
    caller: NodeId,
) -> Result<()> {
    if let Some(bytes) = control.get_record("guild-dynamic-state", b"primary")? {
        let state: DynamicGuildState = decode_canonical(&bytes)?;
        state.validate()?;
        if state.guild_id == *guild_id
            && state
                .members
                .iter()
                .any(|member| member.member.node_id == caller)
        {
            return Ok(());
        }
        anyhow::bail!("caller is not a historical guild member");
    }
    authorize_member(control, guild_id, caller)
}

fn guild_coordinator(control: &ControlStore, guild_id: &[u8; 32]) -> Result<Option<NodeId>> {
    let Some(bytes) = control.get_record("guild-installed", b"primary")? else {
        return Ok(None);
    };
    let installed = decode_installed_guild(&bytes)?;
    if installed.certificate.genesis.guild_id != *guild_id {
        anyhow::bail!("requested guild differs from installed guild");
    }
    if let Some(bytes) = control.get_record("guild-dynamic-state", b"primary")? {
        let state: DynamicGuildState = decode_canonical(&bytes)?;
        state.validate()?;
        if state.guild_id != *guild_id {
            anyhow::bail!("dynamic membership belongs to another guild");
        }
        return dynamic_guild_coordinator(&installed, &state).map(Some);
    }
    Ok(Some(installed.certificate.genesis.coordinator))
}

fn dynamic_guild_coordinator(
    installed: &InstalledGuild,
    state: &DynamicGuildState,
) -> Result<NodeId> {
    if state.guild_id != installed.certificate.genesis.guild_id {
        anyhow::bail!("dynamic membership belongs to another guild");
    }
    let genesis_coordinator = installed.certificate.genesis.coordinator;
    state
        .active_members()
        .map(|member| member.node_id)
        .find(|node_id| *node_id == genesis_coordinator)
        .or_else(|| state.active_members().next().map(|member| member.node_id))
        .context("dynamic guild has no active coordinator")
}

fn initial_dynamic_guild_state(installed: &InstalledGuild) -> Result<DynamicGuildState> {
    installed.certificate.verify()?;
    Ok(DynamicGuildState::new(
        installed.certificate.genesis.guild_id,
        installed.certificate.genesis.hash()?,
        QuorumPolicy {
            format_version: 1,
            rule: QuorumRule::Unanimous,
        },
        installed.certificate.genesis.members.clone(),
    )?)
}

pub(crate) fn checkpoint_matches_dynamic_authority(
    checkpoint: &GuildCheckpoint,
    state: &DynamicGuildState,
) -> bool {
    if checkpoint.guild_id != state.guild_id
        || !state.active_members().eq(checkpoint.members.iter())
    {
        return false;
    }
    match checkpoint.format_version {
        4 => checkpoint.authority.is_none(),
        5..=7 => checkpoint.authority.is_some_and(|authority| {
            authority.format_version == 1
                && authority.membership_epoch == state.membership_epoch
                && authority.quorum == state.quorum
        }),
        _ => false,
    }
}

pub(crate) fn variable_group_protects_checkpoint(
    checkpoint: &GuildCheckpoint,
    group: &CodingGroupV2,
) -> bool {
    checkpoint
        .packing_catalog
        .as_ref()
        .map(|catalog| {
            group.roles.iter().any(|role| {
                matches!(role, ShardRoleV2::Information(information)
                if !information.sector.virtual_zero
                    && catalog.sectors.iter().any(|descriptor| {
                        descriptor.id == information.sector.id
                            && descriptor.commitment == information.sector.commitment
                    }))
            })
        })
        .unwrap_or_else(|| {
            checkpoint.revisions.iter().any(|revision| {
                group.roles.iter().any(|role| {
                    matches!(role, ShardRoleV2::Information(information)
                        if !information.sector.virtual_zero
                            && information.owner == revision.value.owner
                            && revision.value.metadata_sectors.iter()
                                .chain(&revision.value.data_sectors)
                                .any(|reference| reference.id == information.sector.id
                                    && reference.logical_len == information.sector.logical_len))
                })
            })
        })
}

fn validate_dynamic_state_origin(
    state: &DynamicGuildState,
    initial: &DynamicGuildState,
) -> Result<()> {
    state.validate()?;
    if state.guild_id != initial.guild_id
        || (state.event_sequence == 0 && state != initial)
        || initial.members.iter().any(|genesis_member| {
            !state.members.iter().any(|member| {
                member.joined_at_event == 0
                    && member.member.node_id == genesis_member.member.node_id
                    && member.member.recovery_public_key
                        == genesis_member.member.recovery_public_key
            })
        })
    {
        anyhow::bail!("dynamic guild state has a different genesis");
    }
    Ok(())
}

fn guild_event_tail_from_store(
    control: &ControlStore,
    base_sequence: u64,
    base_head: [u8; 32],
) -> Result<GuildEventTail> {
    let installed = decode_installed_guild(
        &control
            .get_record("guild-installed", b"primary")?
            .context("node has no installed guild")?,
    )?;
    let durable: DynamicGuildState = decode_canonical(
        &control
            .get_record("guild-dynamic-state", b"primary")?
            .context("node has no dynamic guild state")?,
    )?;
    durable.validate()?;
    if base_sequence > durable.event_sequence {
        anyhow::bail!("guild event-tail base is ahead of local state");
    }
    let mut replay = initial_dynamic_guild_state(&installed)?;
    let mut base_found = base_sequence == 0 && replay.event_head == base_head;
    let mut events = Vec::new();
    for (record_id, bytes) in control.records("guild-event")? {
        let event: QuorumGuildEvent = decode_canonical(&bytes)?;
        let expected_id = event.event.sequence.to_be_bytes();
        if record_id != expected_id {
            anyhow::bail!("guild event history has an invalid record ID");
        }
        replay.apply_event(&event)?;
        if replay.event_sequence == base_sequence {
            base_found = replay.event_head == base_head;
        } else if replay.event_sequence > base_sequence && events.len() < MAX_GUILD_EVENT_TAIL {
            events.push(event);
        }
    }
    if replay != durable {
        anyhow::bail!("dynamic guild state conflicts with its event history");
    }
    if !base_found {
        anyhow::bail!("guild event-tail base is not on local history");
    }
    Ok(GuildEventTail {
        format_version: 1,
        base_sequence,
        base_head,
        events,
    })
}

fn backup_job(control: &ControlStore, guild_id: [u8; 32], revision_id: Uuid) -> Result<BackupJob> {
    let job: BackupJob = decode_canonical(
        &control
            .get_record("backup-job", revision_id.as_bytes())?
            .context("backup job is unavailable")?,
    )?;
    if job.format_version != 1 || job.descriptor.guild_id != guild_id {
        anyhow::bail!("backup job belongs to another guild");
    }
    Ok(job)
}

fn summary_from_draft(draft: &GuildDraft) -> GuildSummary {
    GuildSummary {
        format_version: 2,
        guild_id: draft.guild_id,
        coordinator: draft.coordinator,
        phase: GuildPhase::Draft,
        peers: draft.peers.clone(),
        membership_epoch: None,
        event_sequence: None,
        quorum: None,
    }
}

fn validate_endpoint_set(node_id: NodeId, endpoints: &[String]) -> Result<()> {
    if endpoints.is_empty() || endpoints.len() > V1_MAX_ENDPOINTS_PER_PEER {
        anyhow::bail!("a guild peer must advertise between one and eight endpoints");
    }
    let mut unique = std::collections::BTreeSet::new();
    for endpoint in endpoints {
        if !unique.insert(endpoint) {
            anyhow::bail!("guild endpoint is duplicated");
        }
        crate::network::validate_published_endpoint(node_id, endpoint)?;
    }
    Ok(())
}

fn retain_exchange_endpoint(
    records: &mut BTreeMap<NodeId, SignedRecord<EndpointRecord>>,
    allowed: &BTreeSet<NodeId>,
    now: u64,
    bytes: &[u8],
) -> Result<()> {
    let endpoint: SignedRecord<EndpointRecord> = decode_canonical(bytes)?;
    endpoint.verify(b"mutualbackup/endpoint-record/v1")?;
    if endpoint.value.format_version != 1
        || endpoint.signer != endpoint.value.publisher
        || !allowed.contains(&endpoint.value.publisher)
        || endpoint.value.sequence == 0
        || endpoint.value.expires_at_unix_seconds <= now
    {
        anyhow::bail!("stored endpoint record is not eligible for peer exchange");
    }
    validate_endpoint_set(endpoint.value.publisher, &endpoint.value.endpoints)?;
    match records.get(&endpoint.value.publisher) {
        Some(current) if current.value.sequence == endpoint.value.sequence => {
            if canonical_bytes(current)? != canonical_bytes(&endpoint)? {
                anyhow::bail!("stored endpoint publisher forked one sequence");
            }
        }
        Some(current) if current.value.sequence > endpoint.value.sequence => {}
        _ => {
            records.insert(endpoint.value.publisher, endpoint);
        }
    }
    Ok(())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn validate_automatic_backup_policy(policy: &AutomaticBackupPolicy) -> Result<()> {
    if policy.quiet_period_seconds == 0
        || policy.minimum_interval_seconds == 0
        || policy.full_reconcile_interval_seconds == 0
        || policy.daily_backup_limit == 0
        || policy.daily_byte_limit == 0
    {
        anyhow::bail!("automatic-backup intervals and budgets must be greater than zero");
    }
    if policy.quiet_period_seconds > 24 * 60 * 60
        || policy.minimum_interval_seconds > 30 * 24 * 60 * 60
        || policy.full_reconcile_interval_seconds > 30 * 24 * 60 * 60
        || policy.daily_backup_limit > 10_000
    {
        anyhow::bail!("automatic-backup policy exceeds its supported bounds");
    }
    Ok(())
}

fn recovery_observation_record_id(subject: NodeId, provider_peer_id: &str) -> [u8; 64] {
    let mut record_id = [0_u8; 64];
    record_id[..32].copy_from_slice(&subject.0);
    record_id[32..].copy_from_slice(blake3::hash(provider_peer_id.as_bytes()).as_bytes());
    record_id
}

fn merge_dht_observation_state(
    stored: Option<&[u8]>,
    incoming: Vec<DhtRecordObservation>,
    now: u64,
    output_format_version: u16,
) -> Result<Option<DhtObservationState>> {
    if !matches!(
        output_format_version,
        DHT_OBSERVATION_FORMAT_UNCERTIFIED | DHT_OBSERVATION_FORMAT_CERTIFIED
    ) {
        anyhow::bail!("invalid DHT observation output format");
    }
    let mut hashes = BTreeMap::<u64, [u8; 32]>::new();
    let mut current = None;
    if let Some(bytes) = stored {
        let state: DhtObservationState = decode_canonical(bytes)?;
        validate_dht_observation_state(&state)?;
        for observed in state.hashes {
            hashes.insert(observed.sequence, observed.hash);
        }
        current = Some(state.current);
    }

    let mut incoming_by_sequence = BTreeMap::<u64, DhtObservedRecord>::new();
    for record in incoming {
        if record.sequence == 0
            || record.expires_at_unix_seconds <= now
            || record.bytes.is_empty()
            || record.bytes.len() > MAX_DHT_OBSERVED_RECORD_BYTES
        {
            anyhow::bail!("invalid accepted DHT observation");
        }
        let observed = DhtObservedRecord {
            sequence: record.sequence,
            hash: *blake3::hash(&record.bytes).as_bytes(),
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            bytes: record.bytes,
        };
        if let Some(existing) = incoming_by_sequence.get(&observed.sequence) {
            if existing.hash != observed.hash {
                anyhow::bail!("DHT publisher forked an observed sequence");
            }
        } else {
            incoming_by_sequence.insert(observed.sequence, observed);
        }
    }

    for observed in incoming_by_sequence.into_values() {
        if let Some(existing_hash) = hashes.get(&observed.sequence) {
            if *existing_hash != observed.hash {
                anyhow::bail!("DHT publisher forked an observed sequence");
            }
            continue;
        }
        if hashes
            .last_key_value()
            .is_some_and(|(highest, _)| observed.sequence < *highest)
        {
            continue;
        }
        hashes.insert(observed.sequence, observed.hash);
        current = Some(observed);
    }

    while hashes.len() > MAX_DHT_OBSERVED_SEQUENCES {
        let oldest = *hashes
            .keys()
            .next()
            .context("nonempty DHT observation set has no first key")?;
        hashes.remove(&oldest);
    }
    let Some((highest_sequence, _)) = hashes.last_key_value() else {
        return Ok(None);
    };
    let current = current.context("durable DHT high-water mark has no current record")?;
    if current.sequence != *highest_sequence {
        anyhow::bail!("durable DHT current record is not the high-water mark");
    }
    Ok(Some(DhtObservationState {
        format_version: output_format_version,
        highest_sequence: *highest_sequence,
        hashes: hashes
            .into_iter()
            .map(|(sequence, hash)| DhtObservedHash { sequence, hash })
            .collect(),
        current,
    }))
}

fn validate_dht_observation(record: &DhtObservedRecord) -> Result<()> {
    if record.sequence == 0
        || record.bytes.is_empty()
        || record.bytes.len() > MAX_DHT_OBSERVED_RECORD_BYTES
        || blake3::hash(&record.bytes).as_bytes() != &record.hash
    {
        anyhow::bail!("invalid durable DHT observation");
    }
    Ok(())
}

fn validate_dht_observation_state(state: &DhtObservationState) -> Result<()> {
    if !matches!(
        state.format_version,
        DHT_OBSERVATION_FORMAT_UNCERTIFIED | DHT_OBSERVATION_FORMAT_CERTIFIED
    ) || state.highest_sequence == 0
        || state.hashes.is_empty()
        || state.hashes.len() > MAX_DHT_OBSERVED_SEQUENCES
    {
        anyhow::bail!("invalid durable DHT observation state");
    }
    validate_dht_observation(&state.current)?;
    let mut previous = 0;
    for observed in &state.hashes {
        if observed.sequence <= previous {
            anyhow::bail!("invalid durable DHT observation ordering");
        }
        previous = observed.sequence;
    }
    if previous != state.highest_sequence
        || state.current.sequence != state.highest_sequence
        || state
            .hashes
            .last()
            .is_none_or(|observed| observed.hash != state.current.hash)
    {
        anyhow::bail!("invalid durable DHT observation high-water mark");
    }
    Ok(())
}

fn deterministic_revision_id(
    guild_id: [u8; 32],
    owner: NodeId,
    protected_root_id: Uuid,
    sequence: u64,
) -> Uuid {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup revision operation v2");
    hasher.update(&guild_id);
    hasher.update(&owner.0);
    hasher.update(protected_root_id.as_bytes());
    hasher.update(&sequence.to_le_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
    Uuid::from_bytes(bytes)
}

fn validate_backup_descriptor(descriptor: &BackupDescriptor) -> Result<()> {
    if descriptor.format_version != 2
        || descriptor.guild_id == [0; 32]
        || descriptor.protected_root_id.is_nil()
        || descriptor.total_pages == 0
        || descriptor.total_pages > V1_MAX_CATALOG_PAGES
        || descriptor.object_hash == [0; 32]
    {
        anyhow::bail!("invalid backup descriptor");
    }
    Ok(())
}

fn checkpoint_page(
    control: &ControlStore,
    guild_id: &[u8; 32],
    checkpoint_hash: &[u8; 32],
    page_index: u32,
) -> Result<(u32, Vec<u8>)> {
    let (_, head_hash, _) = control
        .checkpoint_head(guild_id)?
        .context("guild checkpoint is unavailable")?;
    if head_hash != *checkpoint_hash {
        anyhow::bail!("only the current checkpoint is page-readable");
    }
    Ok(control.protocol_record_page("guild-checkpoint", checkpoint_hash, page_index)?)
}

fn parity_proof_id(group_id: &[u8; 32], shard_index: u8) -> [u8; 33] {
    let mut id = [0_u8; 33];
    id[..32].copy_from_slice(group_id);
    id[32] = shard_index;
    id
}

fn variable_emergency_id(group_id: &[u8; 32], shard_index: u16) -> [u8; 34] {
    let mut id = [0_u8; 34];
    id[..32].copy_from_slice(group_id);
    id[32..].copy_from_slice(&shard_index.to_be_bytes());
    id
}

fn parity_operation_id(group_id: &[u8; 32], shard_index: u8) -> [u8; 16] {
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

fn publication_slot(
    kind: &[u8],
    subject: NodeId,
    publisher: NodeId,
    guild_id: [u8; 32],
) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup dht publication slot v1");
    hasher.update(kind);
    hasher.update(&subject.0);
    hasher.update(&publisher.0);
    hasher.update(&guild_id);
    *hasher.finalize().as_bytes()
}

fn open_data_dir_lock(data_dir: &Path) -> Result<File> {
    use fs2::FileExt;

    let path = data_dir.join(".node.lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    FileExt::try_lock_exclusive(&file).context("node data directory is already in use")?;
    Ok(file)
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn install_empty_recovery_revision(
        node: &mut Node,
        guild_id: [u8; 32],
        revision_id: Uuid,
    ) -> SignedRecord<UserRevision> {
        let metadata = crate::snapshot::PrivateMetadata {
            format_version: 3,
            root_mode: 0o755,
            root_modified_secs: 1_700_000_000,
            root_modified_nanos: 0,
            entries: Vec::new(),
        };
        let plaintext = canonical_bytes(&metadata).unwrap();
        let id = mb_core::make_sector_id(
            node.keys().node_id(),
            revision_id,
            mb_core::SectorPurpose::Metadata,
            0,
        );
        let (reference, _) =
            mb_core::encrypted_sector(&node.keys().guild_data_key(&guild_id), id, &plaintext)
                .unwrap();
        install_inline_recipe(&mut node.control, guild_id, reference.clone(), plaintext).unwrap();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        let mut revision = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id,
            owner: node.keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![reference],
            data_sectors: Vec::new(),
        };
        revision.sign_writer(&writer).unwrap();
        SignedRecord::sign(USER_REVISION_DOMAIN, revision, node.keys()).unwrap()
    }

    fn signed_recovery_checkpoint_fixture() -> (Vec<Seed>, QuorumCheckpoint) {
        let seeds = (0_u8..5)
            .map(|index| Seed::from_bytes([index + 130; 32]))
            .collect::<Vec<_>>();
        let keys = seeds.iter().map(KeyMaterial::from_seed).collect::<Vec<_>>();
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, keys)| Member {
                node_id: keys.node_id(),
                recovery_public_key: keys.recovery_public_key(),
                failure_domain: format!("checkpoint-domain-{index}"),
            })
            .collect::<Vec<_>>();
        let target = SectorRef {
            id: [131; 32],
            root: [132; 32],
            logical_len: 1,
        };
        let guild_id = [133; 32];
        let roles = [
            ShardRole::Information(mb_core::InformationRole {
                owner: keys[0].node_id(),
                sector: target.clone(),
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: keys[1].node_id(),
                sector: SectorRef {
                    id: [134; 32],
                    root: [135; 32],
                    logical_len: 0,
                },
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: keys[2].node_id(),
                sector: SectorRef {
                    id: [136; 32],
                    root: [137; 32],
                    logical_len: 0,
                },
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: keys[3].node_id(),
                row: 0,
                root: [138; 32],
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: keys[4].node_id(),
                row: 1,
                root: [139; 32],
            }),
        ];
        let mut group = mb_core::CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id,
            data_shards: mb_core::V1_RS_DATA_SHARDS,
            parity_shards: mb_core::V1_RS_PARITY_SHARDS,
            shard_size: mb_core::V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
        let mut revision_body = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([140; 16]),
            owner: keys[0].node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![target],
            data_sectors: Vec::new(),
        };
        revision_body.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision_body, &keys[0]).unwrap();
        members.sort_by_key(|member| member.node_id);
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 3,
                guild_id,
                genesis_hash: [141; 32],
                generation: 1,
                parent: None,
                members,
                writer_fences: vec![mb_core::WriterFence {
                    owner: keys[0].node_id(),
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }],
                revision_tombstones: Vec::new(),
                revisions: vec![revision],
                coding_groups: vec![group],
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for keys in &keys {
            checkpoint.add_signature(keys).unwrap();
        }
        checkpoint.verify().unwrap();
        (seeds, checkpoint)
    }

    fn recovery_guild_fixture() -> (Seed, QuorumGuildGenesis, Vec<GuildPeer>) {
        let mut identities = (0_u8..5)
            .map(|index| {
                let seed = Seed::from_bytes([index + 120; 32]);
                let keys = KeyMaterial::from_seed(&seed);
                (keys.node_id(), seed, keys.recovery_public_key())
            })
            .collect::<Vec<_>>();
        identities.sort_by_key(|(node_id, _, _)| *node_id);
        let members = identities
            .iter()
            .enumerate()
            .map(|(index, (node_id, _, recovery_public_key))| Member {
                node_id: *node_id,
                recovery_public_key: *recovery_public_key,
                failure_domain: format!("recovery-domain-{index}"),
            })
            .collect::<Vec<_>>();
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: [121; 32],
            coordinator: members[0].node_id,
            members: members.clone(),
        };
        let signatures = identities
            .iter()
            .map(|(_, seed, _)| {
                genesis
                    .member_signature(&KeyMaterial::from_seed(seed))
                    .unwrap()
            })
            .collect();
        let certificate = QuorumGuildGenesis {
            genesis,
            signatures,
        };
        certificate.verify().unwrap();
        let peers = members
            .into_iter()
            .enumerate()
            .map(|(index, member)| GuildPeer {
                endpoints: vec![format!(
                    "/ip4/127.0.0.1/udp/{}/quic-v1/p2p/{}",
                    41_000 + index,
                    member.node_id.libp2p_peer_id().unwrap()
                )],
                member,
            })
            .collect();
        (identities[2].1.clone(), certificate, peers)
    }

    fn install_public_restore_fixture(
        node: &mut Node,
        local_seed: &Seed,
    ) -> SignedRecord<UserRevision> {
        let mut seeds = vec![local_seed.clone()];
        seeds.extend((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])));
        let keys = seeds.iter().map(KeyMaterial::from_seed).collect::<Vec<_>>();
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, keys)| Member {
                node_id: keys.node_id(),
                recovery_public_key: keys.recovery_public_key(),
                failure_domain: format!("public-restore-domain-{index}"),
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.node_id);
        let guild_id = [233; 32];
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id,
            coordinator: members[0].node_id,
            members: members.clone(),
        };
        let mut genesis_signatures = keys
            .iter()
            .map(|keys| genesis.member_signature(keys).unwrap())
            .collect::<Vec<_>>();
        genesis_signatures.sort_by_key(|signature| signature.signer);
        let certificate = QuorumGuildGenesis {
            genesis,
            signatures: genesis_signatures,
        };
        certificate.verify().unwrap();

        let revision = install_empty_recovery_revision(node, guild_id, Uuid::from_bytes([234; 16]));
        let local_id = node.keys().node_id();
        let other_ids = members
            .iter()
            .map(|member| member.node_id)
            .filter(|node_id| *node_id != local_id)
            .collect::<Vec<_>>();
        let roles = [
            ShardRole::Information(mb_core::InformationRole {
                owner: local_id,
                sector: revision.value.metadata_sectors[0].clone(),
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: other_ids[0],
                sector: SectorRef {
                    id: [235; 32],
                    root: [236; 32],
                    logical_len: 0,
                },
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: other_ids[1],
                sector: SectorRef {
                    id: [237; 32],
                    root: [238; 32],
                    logical_len: 0,
                },
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: other_ids[2],
                row: 0,
                root: [239; 32],
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: other_ids[3],
                row: 1,
                root: [240; 32],
            }),
        ];
        let mut group = mb_core::CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id,
            data_shards: mb_core::V1_RS_DATA_SHARDS,
            parity_shards: mb_core::V1_RS_PARITY_SHARDS,
            shard_size: mb_core::V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 3,
                guild_id,
                genesis_hash: certificate.hash().unwrap(),
                generation: 1,
                parent: None,
                members,
                writer_fences: vec![mb_core::WriterFence {
                    owner: revision.value.owner,
                    epoch: revision.value.writer_epoch,
                    public_key: revision.value.writer_public_key,
                }],
                revision_tombstones: Vec::new(),
                revisions: vec![revision.clone()],
                coding_groups: vec![group],
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for keys in &keys {
            checkpoint.add_signature(keys).unwrap();
        }
        let installed = InstalledGuild {
            format_version: 2,
            certificate,
        };
        node.control
            .put_record(
                "guild-installed",
                b"primary",
                &canonical_bytes(&installed).unwrap(),
            )
            .unwrap();
        let checkpoint_hash = checkpoint.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                1,
                None,
                &checkpoint_hash,
                &canonical_bytes(&checkpoint.checkpoint).unwrap(),
                &canonical_bytes(&checkpoint).unwrap(),
                false,
            )
            .unwrap();
        revision
    }

    #[test]
    fn data_directory_has_one_live_owner() {
        let temp = tempfile::tempdir().unwrap();
        let first = Node::open(temp.path(), Seed::from_bytes([91; 32])).unwrap();
        assert!(Node::open(temp.path(), Seed::from_bytes([91; 32])).is_err());
        drop(first);
        Node::open(temp.path(), Seed::from_bytes([91; 32])).unwrap();
    }

    #[test]
    fn recovery_creates_and_reuses_the_next_writer_incarnation() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([226; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let prior = install_public_restore_fixture(&mut node, &seed);
        let guild_id = prior.value.guild_id;
        let writer = node.writer_incarnation(guild_id).unwrap();
        assert_eq!(writer.epoch, 2);
        assert_ne!(writer.public_key, prior.value.writer_public_key);
        drop(node);

        let mut reopened = Node::open(temp.path(), seed).unwrap();
        assert!(reopened.writer_incarnation(guild_id).unwrap() == writer);
    }

    #[test]
    fn pending_writer_survives_checkpoint_advance_without_a_new_fence() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([226; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let prior = install_public_restore_fixture(&mut node, &seed);
        let guild_id = prior.value.guild_id;
        let writer = node.writer_incarnation(guild_id).unwrap();
        assert_eq!(writer.epoch, 2);

        let first = node.current_checkpoint(guild_id).unwrap().unwrap();
        let first_hash = first.hash().unwrap();
        let mut second = QuorumCheckpoint {
            checkpoint: first.checkpoint.clone(),
            signatures: Vec::new(),
        };
        second.checkpoint.generation = 2;
        second.checkpoint.parent = Some(first_hash);
        let signing_seeds = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])));
        for signing_seed in signing_seeds {
            second
                .add_signature(&KeyMaterial::from_seed(&signing_seed))
                .unwrap();
        }
        second.verify().unwrap();
        let second_hash = second.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                2,
                Some(&first_hash),
                &second_hash,
                &canonical_bytes(&second.checkpoint).unwrap(),
                &canonical_bytes(&second).unwrap(),
                false,
            )
            .unwrap();

        assert!(node.writer_incarnation(guild_id).unwrap() == writer);
        drop(node);
        let mut reopened = Node::open(temp.path(), seed).unwrap();
        assert!(reopened.writer_incarnation(guild_id).unwrap() == writer);
    }

    #[test]
    fn superseded_local_writer_cannot_rotate_itself_back_into_authority() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([225; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let guild_id = [233; 32];
        let stale = node.writer_incarnation(guild_id).unwrap();
        assert_eq!(stale.epoch, 1);

        let recovered = install_public_restore_fixture(&mut node, &seed);
        assert_eq!(recovered.value.guild_id, guild_id);
        let error = match node.writer_incarnation(guild_id) {
            Err(error) => error,
            Ok(_) => panic!("superseded writer unexpectedly regained authority"),
        };
        assert!(error.to_string().contains("writer incarnation is fenced"));
        drop(node);

        let mut reopened = Node::open(temp.path(), seed).unwrap();
        let error = match reopened.writer_incarnation(guild_id) {
            Err(error) => error,
            Ok(_) => panic!("superseded writer unexpectedly regained authority after restart"),
        };
        assert!(error.to_string().contains("writer incarnation is fenced"));
    }

    #[test]
    fn automatic_backup_schedule_is_quiet_bounded_and_durable() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload"), b"four").unwrap();
        let state = temp.path().join("state");
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(&state, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let filesystem = filesystem_identity(&root).unwrap();
        let root_id = Uuid::new_v4();
        let protected_root = ProtectedRoot {
            format_version: 3,
            root_id,
            path: root,
            filesystem_id: filesystem.stable_id,
            root_inode: fs::metadata(temp.path().join("root")).unwrap().ino(),
        };
        node.control
            .put_record(
                "protected-root",
                root_id.as_bytes(),
                &canonical_bytes(&protected_root).unwrap(),
            )
            .unwrap();
        let mut policy = AutomaticBackupPolicy {
            enabled: true,
            quiet_period_seconds: 10,
            minimum_interval_seconds: 100,
            full_reconcile_interval_seconds: 60,
            daily_backup_limit: 1,
            daily_byte_limit: 3,
        };
        node.configure_automatic_backup(&policy).unwrap();
        node.mark_root_dirty_at(root_id, "changed", true, 100)
            .unwrap();
        assert!(matches!(
            node.poll_automatic_backup(109).unwrap(),
            AutomaticBackupPoll::Idle
        ));
        assert!(matches!(
            node.poll_automatic_backup(110).unwrap(),
            AutomaticBackupPoll::Idle
        ));
        assert!(
            node.automatic_backup_status()
                .unwrap()
                .blocked_reason
                .unwrap()
                .contains("byte limit")
        );

        policy.daily_byte_limit = 100;
        node.configure_automatic_backup(&policy).unwrap();
        node.clear_automatic_backup_block().unwrap();
        assert!(matches!(
            node.poll_automatic_backup(110).unwrap(),
            AutomaticBackupPoll::Start { estimated_bytes: 4 }
        ));
        let revision_id = Uuid::new_v4();
        node.automatic_backup_submitted(revision_id).unwrap();
        drop(node);

        let mut reopened = Node::open(&state, seed).unwrap();
        assert!(matches!(
            reopened.poll_automatic_backup(111).unwrap(),
            AutomaticBackupPoll::InFlight(actual) if actual == revision_id
        ));
        reopened
            .automatic_backup_finished(Some(revision_id), false, Some("capacity exhausted"))
            .unwrap();
        let status = reopened.automatic_backup_status().unwrap();
        assert!(status.blocked_reason.unwrap().contains("capacity"));
        assert!(status.retry_at_unix_seconds.is_none());
    }

    #[test]
    fn protected_root_configuration_and_dirty_state_are_independent() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([219; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let first_id = Uuid::from_bytes([1; 16]);
        let second_id = Uuid::from_bytes([2; 16]);
        for (root_id, path, identity) in [
            (first_id, "/root-one", 1_u64),
            (second_id, "/root-two", 2_u64),
        ] {
            let root = ProtectedRoot {
                format_version: 3,
                root_id,
                path: PathBuf::from(path),
                filesystem_id: identity,
                root_inode: identity,
            };
            node.control
                .put_record(
                    "protected-root",
                    root_id.as_bytes(),
                    &canonical_bytes(&root).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(
            node.protected_roots()
                .unwrap()
                .into_iter()
                .map(|root| root.root_id)
                .collect::<Vec<_>>(),
            vec![first_id, second_id]
        );
        node.mark_root_dirty_at(first_id, "first changed", true, 100)
            .unwrap();
        node.mark_root_dirty_at(second_id, "second changed", true, 101)
            .unwrap();
        let first_state = node.root_dirty_state(first_id).unwrap().unwrap();
        node.control
            .put_record(
                "root-dirty",
                first_id.as_bytes(),
                &canonical_bytes(&RootDirtyState {
                    format_version: 3,
                    protected_root_id: first_id,
                    dirty: false,
                    reason: "first committed".to_owned(),
                    change_sequence: first_state.change_sequence,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(!node.root_dirty_state(first_id).unwrap().unwrap().dirty);
        assert!(node.root_dirty_state(second_id).unwrap().unwrap().dirty);
        assert!(node.root_dirty().unwrap());
        drop(node);

        let reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(reopened.protected_roots().unwrap().len(), 2);
        assert!(reopened.root_dirty_state(second_id).unwrap().unwrap().dirty);
        let nested_id = Uuid::from_bytes([3; 16]);
        reopened
            .control
            .put_record(
                "protected-root",
                nested_id.as_bytes(),
                &canonical_bytes(&ProtectedRoot {
                    format_version: 3,
                    root_id: nested_id,
                    path: PathBuf::from("/root-one/nested"),
                    filesystem_id: 3,
                    root_inode: 3,
                })
                .unwrap(),
            )
            .unwrap();
        assert!(reopened.protected_roots().is_err());
    }

    #[test]
    fn packed_sectors_are_durable_and_guild_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([218; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let guild_id = [217; 32];
        let packed = mb_core::pack_incremental(
            mb_core::PackingProfile {
                format_version: 1,
                sector_size: 64,
                slot_size: 16,
            },
            None,
            vec![mb_core::PackingInput {
                owner: node.keys().node_id(),
                protected_root: [1; 32],
                object_id: [2; 32],
                bytes: (0_u8..48).collect(),
            }],
        )
        .unwrap();
        node.store_packing_result(guild_id, &packed).unwrap();
        for sector in &packed.sectors {
            assert_eq!(
                node.sector_for_guild(&guild_id, &sector.descriptor.id)
                    .unwrap(),
                sector.bytes
            );
            assert!(
                node.sector_for_guild(&[216; 32], &sector.descriptor.id)
                    .is_err()
            );
        }
        drop(node);

        let reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened
                .sector_for_guild(&guild_id, &packed.sectors[0].descriptor.id)
                .unwrap(),
            packed.sectors[0].bytes
        );
    }

    #[test]
    fn packed_catalog_sectors_are_live_variable_information() {
        let owner = KeyMaterial::from_seed(&Seed::from_bytes([215; 32])).node_id();
        let guild_id = [214; 32];
        let packed = mb_core::pack_incremental(
            mb_core::PackingProfile {
                format_version: 1,
                sector_size: 64,
                slot_size: 16,
            },
            None,
            vec![mb_core::PackingInput {
                owner,
                protected_root: [1; 32],
                object_id: [2; 32],
                bytes: vec![3; 64],
            }],
        )
        .unwrap();
        let descriptor = &packed.catalog.sectors[0];
        let mut group = CodingGroupV2 {
            id: [4; 32],
            format_version: 2,
            guild_id,
            profile: mb_core::CodingProfile::new(3, 2, 64),
            roles: vec![ShardRoleV2::Information(mb_core::InformationRoleV2 {
                owner,
                failure_domain: "packed-owner".to_owned(),
                sector: mb_core::RangeSectorRef {
                    id: descriptor.id,
                    commitment: descriptor.commitment.clone(),
                    logical_len: 64,
                    virtual_zero: false,
                },
            })],
        };
        let checkpoint = GuildCheckpoint {
            format_version: 7,
            guild_id,
            genesis_hash: [5; 32],
            generation: 1,
            parent: None,
            members: Vec::new(),
            writer_fences: Vec::new(),
            revision_tombstones: Vec::new(),
            revisions: Vec::new(),
            coding_groups: Vec::new(),
            authority: None,
            packing_catalog: Some(packed.catalog),
        };
        assert!(variable_group_protects_checkpoint(&checkpoint, &group));
        match &mut group.roles[0] {
            ShardRoleV2::Information(information) => information.sector.commitment.root[0] ^= 1,
            ShardRoleV2::Parity(_) => unreachable!(),
        }
        assert!(!variable_group_protects_checkpoint(&checkpoint, &group));
    }

    #[test]
    fn automatic_backup_errors_are_bounded_at_utf8_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([227; 32])).unwrap();
        let unicode_error = "é".repeat(300);

        node.automatic_backup_finished(None, false, Some(&unicode_error))
            .unwrap();

        let state = node.automatic_backup_state(0).unwrap();
        let message = state.blocked_reason.unwrap();
        assert!(message.len() <= 512);
        assert!(message.chars().all(|character| character == 'é'));
    }

    #[test]
    fn running_backup_job_durably_fences_group_lifecycle() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([215; 32]);
        let guild_id = [216; 32];
        let descriptor = BackupDescriptor {
            format_version: 2,
            guild_id,
            owner: KeyMaterial::from_seed(&seed).node_id(),
            protected_root_id: Uuid::from_bytes([217; 16]),
            revision_id: Uuid::from_bytes([218; 16]),
            total_pages: 1,
            object_hash: [219; 32],
        };
        let node = Node::open(temp.path(), seed.clone()).unwrap();
        node.put_backup_job(&BackupJob {
            format_version: 1,
            descriptor: descriptor.clone(),
            state: BackupJobState::Running,
            checkpoint_hash: None,
            error: None,
        })
        .unwrap();
        assert!(node.backup_commit_in_progress(guild_id).unwrap());
        drop(node);

        let node = Node::open(temp.path(), seed).unwrap();
        assert!(node.backup_commit_in_progress(guild_id).unwrap());
        node.put_backup_job(&BackupJob {
            format_version: 1,
            descriptor,
            state: BackupJobState::Committed,
            checkpoint_hash: Some([220; 32]),
            error: None,
        })
        .unwrap();
        assert!(!node.backup_commit_in_progress(guild_id).unwrap());
    }

    #[test]
    fn automatic_backup_scan_failure_is_blocked_and_retryable() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload"), b"available later").unwrap();
        let state = temp.path().join("state");
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(&state, seed).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let filesystem = filesystem_identity(&root).unwrap();
        let root_id = Uuid::new_v4();
        let protected_root = ProtectedRoot {
            format_version: 3,
            root_id,
            path: root.clone(),
            filesystem_id: filesystem.stable_id,
            root_inode: fs::metadata(&root).unwrap().ino(),
        };
        node.control
            .put_record(
                "protected-root",
                root_id.as_bytes(),
                &canonical_bytes(&protected_root).unwrap(),
            )
            .unwrap();
        node.configure_automatic_backup(&AutomaticBackupPolicy {
            enabled: true,
            quiet_period_seconds: 1,
            minimum_interval_seconds: 10,
            full_reconcile_interval_seconds: 60,
            daily_backup_limit: 10,
            daily_byte_limit: 1024,
        })
        .unwrap();
        node.mark_root_dirty_at(root_id, "changed", true, 100)
            .unwrap();
        fs::remove_dir_all(&root).unwrap();

        assert!(matches!(
            node.poll_automatic_backup(101).unwrap(),
            AutomaticBackupPoll::Idle
        ));
        let blocked = node.automatic_backup_state(101).unwrap();
        assert!(
            blocked
                .blocked_reason
                .as_deref()
                .unwrap()
                .contains("full reconciliation failed")
        );
        assert_eq!(blocked.retry_at_unix_seconds, Some(111));
        assert!(node.root_dirty().unwrap());

        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload"), b"available later").unwrap();
        assert!(matches!(
            node.poll_automatic_backup(110).unwrap(),
            AutomaticBackupPoll::Idle
        ));
        assert!(matches!(
            node.poll_automatic_backup(111).unwrap(),
            AutomaticBackupPoll::Start { .. }
        ));
    }

    #[test]
    fn missing_capture_generation_never_clears_a_dirty_root() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([224; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let guild_id = revision.value.guild_id;
        let protected_root = ProtectedRoot {
            format_version: 3,
            root_id: revision.value.protected_root_id,
            path: PathBuf::from("/missing-test-root"),
            filesystem_id: 1,
            root_inode: 1,
        };
        node.control
            .put_record(
                "protected-root",
                protected_root.root_id.as_bytes(),
                &canonical_bytes(&protected_root).unwrap(),
            )
            .unwrap();
        node.control
            .put_record(
                "user-revision-head",
                &revision_head_id(guild_id, revision.value.protected_root_id),
                &canonical_bytes(&revision).unwrap(),
            )
            .unwrap();
        node.mark_root_dirty_at(
            revision.value.protected_root_id,
            "changed after capture",
            true,
            100,
        )
        .unwrap();
        let checkpoint = node.current_checkpoint(guild_id).unwrap().unwrap();

        node.clear_root_dirty_if_committed(&checkpoint).unwrap();

        assert!(node.root_dirty().unwrap());
    }

    #[test]
    fn garbage_collection_waits_when_recovered_history_is_unavailable() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([223; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let guild_id = revision.value.guild_id;
        let first = node.current_checkpoint(guild_id).unwrap().unwrap();
        let first_hash = first.hash().unwrap();
        let signing_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        let mut second = QuorumCheckpoint {
            checkpoint: first.checkpoint.clone(),
            signatures: Vec::new(),
        };
        second.checkpoint.generation = 2;
        second.checkpoint.parent = Some(first_hash);
        for keys in &signing_keys {
            second.add_signature(keys).unwrap();
        }
        second.verify().unwrap();
        let second_hash = second.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                2,
                Some(&first_hash),
                &second_hash,
                &canonical_bytes(&second.checkpoint).unwrap(),
                &canonical_bytes(&second).unwrap(),
                false,
            )
            .unwrap();
        assert!(
            node.control
                .delete_record("guild-checkpoint", &first_hash)
                .unwrap()
        );

        node.reconcile_garbage_collection().unwrap();
        drop(node);
        let reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened.current_checkpoint(guild_id).unwrap().unwrap(),
            second
        );
    }

    #[test]
    fn guild_audit_schedule_is_checkpoint_bound_and_durable() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([242; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let checkpoint = node
            .current_checkpoint(revision.value.guild_id)
            .unwrap()
            .unwrap();
        let checkpoint_hash = checkpoint.hash().unwrap();
        assert!(node.guild_audit_due(1_000, 600).unwrap());
        node.record_guild_audit(&GuildAuditReport {
            format_version: 1,
            checkpoint_hash,
            checkpoint_generation: checkpoint.checkpoint.generation,
            audited_at_unix_seconds: 1_000,
            state: ProtectionState::Healthy,
            checked_groups: checkpoint.checkpoint.coding_groups.len() as u64,
            assigned_shards_unavailable: 0,
            assigned_shards_repaired: 0,
            emergency_copies_created: 0,
            emergency_copies_removed: 0,
            issues: Vec::new(),
        })
        .unwrap();
        assert!(!node.guild_audit_due(1_599, 600).unwrap());
        assert!(node.guild_audit_due(1_600, 600).unwrap());
        drop(node);

        let reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened
                .last_guild_audit()
                .unwrap()
                .unwrap()
                .checkpoint_hash,
            checkpoint_hash
        );
        assert!(!reopened.guild_audit_due(1_599, 600).unwrap());
    }

    #[test]
    fn emergency_marker_survives_interruption_before_payload_commit() {
        let temp = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([226; 32]);
        let mut node = Node::open(temp.path(), local_seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &local_seed);
        let first = node
            .current_checkpoint(revision.value.guild_id)
            .unwrap()
            .unwrap();
        let first_hash = first.hash().unwrap();
        let local_id = node.keys().node_id();
        let bytes = vec![243; mb_core::V1_SECTOR_SIZE];
        let mut group = first.checkpoint.coding_groups[0].clone();
        let shard_index = group
            .roles
            .iter()
            .enumerate()
            .find_map(|(index, role)| match role {
                ShardRole::Information(information)
                    if index > 0 && information.owner != local_id =>
                {
                    Some(index)
                }
                ShardRole::Parity(parity) if parity.holder != local_id => Some(index),
                _ => None,
            })
            .unwrap();
        match &mut group.roles[shard_index] {
            ShardRole::Information(information) => information.sector.root = sector_root(&bytes),
            ShardRole::Parity(parity) => parity.root = sector_root(&bytes),
        }
        group.id = group.calculate_id().unwrap();
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: first.checkpoint.clone(),
            signatures: Vec::new(),
        };
        checkpoint.checkpoint.generation = 2;
        checkpoint.checkpoint.parent = Some(first_hash);
        checkpoint.checkpoint.coding_groups = vec![group.clone()];
        let signing_seeds = std::iter::once(local_seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])));
        for seed in signing_seeds {
            checkpoint
                .add_signature(&KeyMaterial::from_seed(&seed))
                .unwrap();
        }
        checkpoint.verify().unwrap();
        let checkpoint_hash = checkpoint.hash().unwrap();
        node.control
            .commit_checkpoint(
                &checkpoint.checkpoint.guild_id,
                checkpoint.checkpoint.generation,
                Some(&first_hash),
                &checkpoint_hash,
                &canonical_bytes(&checkpoint.checkpoint).unwrap(),
                &canonical_bytes(&checkpoint).unwrap(),
                false,
            )
            .unwrap();
        node.configure_storage_volumes(
            &[storage.path().to_path_buf()],
            (mb_core::V1_SECTOR_SIZE * 2) as u64,
            0,
        )
        .unwrap();
        crate::volume::interrupt_next_volume_transition(
            crate::volume::VolumeInterruption::WriteIntentStored,
        );

        let error = node
            .install_repaired_shard(checkpoint_hash, group.id, shard_index as u8, &bytes, true)
            .unwrap_err();
        assert!(
            error.to_string().contains("injected interruption"),
            "{error:#}"
        );
        let record_id = parity_proof_id(&group.id, shard_index as u8);
        assert!(
            node.control
                .get_record("emergency-shard", &record_id)
                .unwrap()
                .is_some()
        );
        drop(node);

        let mut reopened = Node::open(temp.path(), local_seed.clone()).unwrap();
        let storage_id = reopened
            .status()
            .unwrap()
            .storage_volumes
            .into_iter()
            .find(|status| status.path == storage.path().canonicalize().unwrap())
            .unwrap()
            .volume_id;
        reopened.drain_storage_volume(storage_id).unwrap();
        assert_eq!(reopened.migrate_draining_volumes().unwrap(), 0);
        fs::remove_dir_all(storage.path()).unwrap();
        assert_eq!(
            reopened
                .remove_local_emergency_shards(checkpoint_hash, &group)
                .unwrap(),
            1
        );
        assert!(
            reopened
                .control
                .get_record("emergency-shard", &record_id)
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .control
                .get_record("local-parity-proof", &record_id)
                .unwrap()
                .is_none()
        );
        for kind in [
            "volume-write-intent",
            "volume-receipt",
            "volume-copy-cleanup",
            "gc-parity",
        ] {
            assert!(
                reopened
                    .control
                    .get_record(kind, &record_id)
                    .unwrap()
                    .is_none(),
                "{kind}"
            );
        }
        drop(reopened);

        let reopened = Node::open(temp.path(), local_seed).unwrap();
        assert!(
            reopened
                .control
                .get_record("emergency-shard", &record_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            reopened
                .status()
                .unwrap()
                .storage_volumes
                .into_iter()
                .find(|status| status.volume_id == storage_id)
                .unwrap()
                .state,
            crate::StorageVolumeState::Retired
        );
    }

    #[test]
    fn retained_prefix_is_collected_only_after_a_later_checkpoint() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([226; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let retired = install_public_restore_fixture(&mut node, &seed);
        node.control
            .put_record(
                "user-revision",
                retired.value.revision_id.as_bytes(),
                &canonical_bytes(&retired).unwrap(),
            )
            .unwrap();
        let guild_id = retired.value.guild_id;
        let first = node.current_checkpoint(guild_id).unwrap().unwrap();
        let first_hash = first.hash().unwrap();
        let retired_group = first.checkpoint.coding_groups[0].clone();
        let (retired_information_index, retired_information) = retired_group
            .roles
            .iter()
            .enumerate()
            .find_map(|(index, role)| match role {
                ShardRole::Information(information)
                    if information.owner == node.keys().node_id() =>
                {
                    Some((index as u8, information.clone()))
                }
                _ => None,
            })
            .unwrap();
        let retired_information_bytes = node.sector(&retired_information.sector.id).unwrap();
        let retired_receipt = node
            .volumes
            .store_repair(
                &node.control,
                &ParityObject {
                    format_version: retired_group.format_version,
                    guild_id,
                    group_id: retired_group.id,
                    shard_index: retired_information_index,
                    root: retired_information.sector.root,
                    bytes: retired_information_bytes,
                },
            )
            .unwrap();
        let retired_information_record =
            parity_proof_id(&retired_group.id, retired_information_index);
        node.control
            .put_record(
                "local-parity-proof",
                &retired_information_record,
                &canonical_bytes(&retired_group).unwrap(),
            )
            .unwrap();
        node.database_shell_statement(
            Some(retired_receipt.volume_id),
            "UPDATE parity_objects SET bytes = zeroblob(65536)",
            true,
        )
        .unwrap();
        assert_eq!(
            node.scrub_storage()
                .unwrap()
                .into_iter()
                .find(|report| report.volume_id == retired_receipt.volume_id)
                .unwrap()
                .corrupt_objects,
            vec![(retired_group.id, retired_information_index)]
        );
        node.control
            .put_record(
                "emergency-shard",
                &retired_information_record,
                &canonical_bytes(&EmergencyShardRecord {
                    format_version: 1,
                    checkpoint_hash: first_hash,
                    group_id: retired_group.id,
                    shard_index: retired_information_index,
                    root: retired_information.sector.root,
                })
                .unwrap(),
            )
            .unwrap();
        let mut group = first.checkpoint.coding_groups[0].clone();
        let target_id = [196; 32];
        let plaintext = vec![42];
        let (target, _) = mb_core::encrypted_sector(
            &node.keys().guild_data_key(&guild_id),
            target_id,
            &plaintext,
        )
        .unwrap();
        install_inline_recipe(&mut node.control, guild_id, target.clone(), plaintext).unwrap();
        for (index, role) in group.roles.iter_mut().enumerate() {
            match role {
                ShardRole::Information(information)
                    if information.owner == node.keys().node_id() =>
                {
                    information.sector = target.clone();
                }
                ShardRole::Information(information) => {
                    information.sector.id = [197 + index as u8; 32];
                    information.sector.root = [207 + index as u8; 32];
                }
                ShardRole::Parity(parity) => parity.root = [217 + index as u8; 32],
            }
        }
        group.id = group.calculate_id().unwrap();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
        let mut revision = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([195; 16]),
            owner: node.keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 2,
            parent: Some(retired.value.hash().unwrap()),
            metadata_sectors: vec![target],
            data_sectors: Vec::new(),
        };
        revision.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, node.keys()).unwrap();
        let mut second = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 3,
                guild_id,
                genesis_hash: first.checkpoint.genesis_hash,
                generation: 2,
                parent: Some(first.hash().unwrap()),
                members: first.checkpoint.members.clone(),
                writer_fences: first.checkpoint.writer_fences.clone(),
                revision_tombstones: vec![mb_core::RevisionTombstone {
                    owner: retired.value.owner,
                    protected_root_id: retired.value.protected_root_id,
                    through_sequence: 1,
                    last_revision_id: retired.value.revision_id,
                    last_revision_hash: retired.value.hash().unwrap(),
                    retired_at_generation: 2,
                }],
                revisions: vec![revision],
                coding_groups: vec![group],
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        let signing_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        for keys in &signing_keys {
            second.add_signature(keys).unwrap();
        }
        second.verify().unwrap();
        let second_hash = second.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                2,
                second.checkpoint.parent.as_ref(),
                &second_hash,
                &canonical_bytes(&second.checkpoint).unwrap(),
                &canonical_bytes(&second).unwrap(),
                false,
            )
            .unwrap();
        node.reconcile_garbage_collection().unwrap();
        assert!(node.sector(&retired.value.metadata_sectors[0].id).is_ok());

        let mut third = QuorumCheckpoint {
            checkpoint: second.checkpoint.clone(),
            signatures: Vec::new(),
        };
        third.checkpoint.generation = 3;
        third.checkpoint.parent = Some(second.hash().unwrap());
        for keys in &signing_keys {
            third.add_signature(keys).unwrap();
        }
        third.verify().unwrap();
        let third_hash = third.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                3,
                third.checkpoint.parent.as_ref(),
                &third_hash,
                &canonical_bytes(&third.checkpoint).unwrap(),
                &canonical_bytes(&third).unwrap(),
                false,
            )
            .unwrap();
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        assert!(node.sector(&retired.value.metadata_sectors[0].id).is_err());
        assert!(
            node.control
                .get_record("user-revision", retired.value.revision_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(node.control.records("gc-sector").unwrap().is_empty());
        assert!(
            node.parity_for_guild(&guild_id, &retired_group.id, retired_information_index,)
                .is_err()
        );
        assert!(
            node.control
                .get_record("emergency-shard", &retired_information_record)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn public_restore_retry_finishes_a_renamed_publishing_job() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([227; 32]);
        let mut node = Node::open(temp.path().join("node"), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let target = temp.path().join("restored");

        crate::snapshot::interrupt_next_restore_after_rename();
        assert!(
            node.restore_snapshot(Some(revision.value.revision_id), &target)
                .is_err()
        );
        assert!(target.is_dir());

        node.restore_snapshot(Some(revision.value.revision_id), &target)
            .unwrap();
        assert!(node.control.records("restore-job").unwrap().is_empty());
    }

    #[test]
    fn coordinator_commit_retries_are_explicitly_bound_to_an_intent() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), Seed::from_bytes([90; 32])).unwrap();
        let first = node.begin_coordinator_commit([1; 16], [2; 32]).unwrap();
        assert_eq!(
            node.begin_coordinator_commit([1; 16], [2; 32]).unwrap(),
            first
        );
        assert!(node.begin_coordinator_commit([1; 16], [3; 32]).is_err());
        let second = node.begin_coordinator_commit([4; 16], [2; 32]).unwrap();
        assert_ne!(second, first);
    }

    #[test]
    fn failure_domain_is_a_durable_part_of_local_identity() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), Seed::from_bytes([89; 32])).unwrap();
        node.configure_failure_domain("host-a").unwrap();
        node.configure_failure_domain("host-a").unwrap();
        assert!(node.configure_failure_domain("host-b").is_err());
    }

    #[test]
    fn recovered_guild_retry_merges_endpoint_churn() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, first_peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path(), local_seed).unwrap();
        node.adopt_recovered_guild(certificate.clone(), first_peers.clone())
            .unwrap();

        let mut changed_peers = first_peers.clone();
        let changed_member = changed_peers[0].member.node_id;
        let changed_endpoint = format!(
            "/ip4/127.0.0.1/udp/42000/quic-v1/p2p/{}",
            changed_member.libp2p_peer_id().unwrap()
        );
        changed_peers[0].endpoints = vec![changed_endpoint.clone()];
        node.adopt_recovered_guild(certificate.clone(), changed_peers)
            .unwrap();
        let changed_summary = node.guild_summary().unwrap().unwrap();
        assert_eq!(
            changed_summary
                .peers
                .iter()
                .find(|peer| peer.member.node_id == changed_member)
                .unwrap()
                .endpoints
                .as_slice(),
            std::slice::from_ref(&changed_endpoint)
        );

        let unavailable_peers = first_peers
            .into_iter()
            .map(|mut peer| {
                peer.endpoints.clear();
                peer
            })
            .collect();
        node.adopt_recovered_guild(certificate, unavailable_peers)
            .unwrap();
        let resumed_summary = node.guild_summary().unwrap().unwrap();
        assert_eq!(
            resumed_summary
                .peers
                .iter()
                .find(|peer| peer.member.node_id == changed_member)
                .unwrap()
                .endpoints
                .as_slice(),
            std::slice::from_ref(&changed_endpoint)
        );
    }

    #[test]
    fn dynamic_membership_is_durable_authoritative_and_replayable() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, peers) = recovery_guild_fixture();
        let mut signer_keys = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 120; 32])))
            .collect::<Vec<_>>();
        signer_keys.sort_by_key(KeyMaterial::node_id);
        let added_seed = Seed::from_bytes([199; 32]);
        let added_keys = KeyMaterial::from_seed(&added_seed);
        let removed = certificate
            .genesis
            .members
            .iter()
            .map(|member| member.node_id)
            .find(|node_id| {
                *node_id != certificate.genesis.coordinator
                    && *node_id != KeyMaterial::from_seed(&local_seed).node_id()
            })
            .unwrap();
        let guild_id = certificate.genesis.guild_id;
        let genesis_hash = certificate.genesis.hash().unwrap();
        let mut node = Node::open(temp.path(), local_seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let add = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddMember {
                member: Member {
                    node_id: added_keys.node_id(),
                    recovery_public_key: added_keys.recovery_public_key(),
                    failure_domain: "added-domain".to_owned(),
                },
            },
        };
        let local_signature = node.sign_guild_event_proposal(&add).unwrap();
        assert_eq!(local_signature.signer, node.keys().node_id());
        let conflicting = GuildEvent {
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: certificate.genesis.coordinator,
                failure_domain: "conflict".to_owned(),
            },
            ..add.clone()
        };
        assert!(node.sign_guild_event_proposal(&conflicting).is_err());
        let mut add_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&add, keys).unwrap())
            .collect::<Vec<_>>();
        add_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: add,
            signatures: add_signatures,
        })
        .unwrap();

        signer_keys.push(KeyMaterial::from_seed(&added_seed));
        signer_keys.sort_by_key(KeyMaterial::node_id);
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let relabel = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: added_keys.node_id(),
                failure_domain: "relabeled-domain".to_owned(),
            },
        };
        let mut relabel_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&relabel, keys).unwrap())
            .collect::<Vec<_>>();
        relabel_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: relabel,
            signatures: relabel_signatures,
        })
        .unwrap();

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let remove = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RemoveMember { node_id: removed },
        };
        let mut remove_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&remove, keys).unwrap())
            .collect::<Vec<_>>();
        remove_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: remove,
            signatures: remove_signatures,
        })
        .unwrap();

        node.authorize_member(&guild_id, added_keys.node_id())
            .unwrap();
        assert!(node.authorize_member(&guild_id, removed).is_err());
        let reader = node.reader_config().open().unwrap();
        reader
            .authorize_historical_member(&guild_id, removed)
            .unwrap();
        assert!(reader.authorize_member(&guild_id, removed).is_err());
        let summary = node.guild_summary().unwrap().unwrap();
        assert_eq!(summary.peers.len(), 5);
        assert!(
            summary
                .peers
                .iter()
                .all(|peer| peer.member.node_id != removed)
        );
        assert_eq!(
            summary
                .peers
                .iter()
                .find(|peer| peer.member.node_id == added_keys.node_id())
                .unwrap()
                .member
                .failure_domain,
            "relabeled-domain"
        );
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let remove_coordinator = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RemoveMember {
                node_id: certificate.genesis.coordinator,
            },
        };
        let active = state
            .active_members()
            .map(|member| member.node_id)
            .collect::<BTreeSet<_>>();
        let mut coordinator_signatures = signer_keys
            .iter()
            .filter(|keys| active.contains(&keys.node_id()))
            .map(|keys| sign_guild_event(&remove_coordinator, keys).unwrap())
            .collect::<Vec<_>>();
        coordinator_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: remove_coordinator,
            signatures: coordinator_signatures,
        })
        .unwrap();
        let summary = node.guild_summary().unwrap().unwrap();
        assert_ne!(summary.coordinator, certificate.genesis.coordinator);
        assert_eq!(
            summary.coordinator,
            summary
                .peers
                .iter()
                .map(|peer| peer.member.node_id)
                .min()
                .unwrap()
        );
        let tail = node.guild_event_tail(0, genesis_hash).unwrap();
        assert_eq!(tail.events.len(), 4);

        drop(node);
        let node = Node::open(temp.path(), local_seed).unwrap();
        let reopened = node.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(reopened.event_sequence, 4);
        assert!(reopened.active_members().any(|member| {
            member.node_id == added_keys.node_id() && member.failure_domain == "relabeled-domain"
        }));
        assert!(node.authorize_member(&guild_id, removed).is_err());
        assert_eq!(node.guild_event_tail(0, genesis_hash).unwrap(), tail);
    }

    #[test]
    fn added_member_can_adopt_a_recovered_dynamic_guild() {
        let temp = tempfile::tempdir().unwrap();
        let (_, certificate, mut peers) = recovery_guild_fixture();
        let mut signer_keys = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 120; 32])))
            .collect::<Vec<_>>();
        signer_keys.sort_by_key(KeyMaterial::node_id);
        let added_seed = Seed::from_bytes([199; 32]);
        let added_keys = KeyMaterial::from_seed(&added_seed);
        let added_member = Member {
            node_id: added_keys.node_id(),
            recovery_public_key: added_keys.recovery_public_key(),
            failure_domain: "recovered-added-domain".to_owned(),
        };
        let mut state = DynamicGuildState::new(
            certificate.genesis.guild_id,
            certificate.hash().unwrap(),
            QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Unanimous,
            },
            certificate.genesis.members.clone(),
        )
        .unwrap();
        let add = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddMember {
                member: added_member.clone(),
            },
        };
        let mut add_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&add, keys).unwrap())
            .collect::<Vec<_>>();
        add_signatures.sort_by_key(|signature| signature.signer);
        let add = QuorumGuildEvent {
            event: add,
            signatures: add_signatures,
        };
        state.apply_event(&add).unwrap();

        signer_keys.push(KeyMaterial::from_seed(&added_seed));
        signer_keys.sort_by_key(KeyMaterial::node_id);
        let writer = ed25519_dalek::SigningKey::from_bytes(&[198; 32]);
        let rotate_writer = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: 2,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: added_member.node_id,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            },
        };
        let mut writer_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&rotate_writer, keys).unwrap())
            .collect::<Vec<_>>();
        writer_signatures.sort_by_key(|signature| signature.signer);
        let rotate_writer = QuorumGuildEvent {
            event: rotate_writer,
            signatures: writer_signatures,
        };
        state.apply_event(&rotate_writer).unwrap();

        let mut revision = UserRevision {
            format_version: 3,
            guild_id: state.guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([197; 16]),
            owner: added_member.node_id,
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![SectorRef {
                id: [196; 32],
                root: [195; 32],
                logical_len: 1,
            }],
            data_sectors: Vec::new(),
        };
        revision.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, &added_keys).unwrap();
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 4,
                guild_id: state.guild_id,
                genesis_hash: certificate.hash().unwrap(),
                generation: 1,
                parent: None,
                members: state.active_members().cloned().collect(),
                writer_fences: vec![mb_core::WriterFence {
                    owner: added_member.node_id,
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }],
                revision_tombstones: Vec::new(),
                revisions: vec![revision],
                coding_groups: Vec::new(),
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for keys in &signer_keys {
            checkpoint.add_signature(keys).unwrap();
        }
        checkpoint.verify().unwrap();
        peers.push(GuildPeer {
            member: added_member.clone(),
            endpoints: Vec::new(),
        });

        let mut node = Node::open(temp.path(), added_seed.clone()).unwrap();
        node.adopt_recovered_dynamic_guild(
            certificate.clone(),
            &checkpoint,
            vec![add.clone(), rotate_writer.clone()],
            peers,
            Vec::new(),
        )
        .unwrap();
        assert_eq!(node.dynamic_guild_state().unwrap().unwrap(), state);
        assert!(
            node.control
                .get_record("guild-genesis-signature-lock", b"primary")
                .unwrap()
                .is_none()
        );
        assert!(
            node.guild_summary()
                .unwrap()
                .unwrap()
                .peers
                .iter()
                .any(|peer| peer.member == added_member)
        );
        drop(node);

        let reopened = Node::open(temp.path(), added_seed).unwrap();
        assert_eq!(reopened.dynamic_guild_state().unwrap().unwrap(), state);
        assert_eq!(
            reopened
                .guild_event_tail(0, certificate.hash().unwrap())
                .unwrap()
                .events,
            vec![add, rotate_writer]
        );
    }

    #[test]
    fn empty_coding_queues_do_not_require_a_guild() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([210; 32])).unwrap();
        assert!(node.claim_coding_launch().unwrap().is_none());
        assert!(node.claim_delegated_coding().unwrap().is_none());
        assert!(node.claim_coding_activation().unwrap().is_none());
    }

    #[test]
    fn coding_failure_creates_one_durable_fresh_attempt() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, peers) = recovery_guild_fixture();
        let mut keys = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 120; 32])))
            .collect::<Vec<_>>();
        keys.sort_by_key(KeyMaterial::node_id);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let local_index = keys
            .iter()
            .position(|keys| keys.node_id() == local_id)
            .unwrap();
        let remote = (0..keys.len())
            .filter(|index| *index != local_index)
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), local_seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let profile = mb_core::CodingProfile::new(1, 1, 16);
        let geometry = mb_core::CodingPlanGeometry {
            format_version: 1,
            guild_id: certificate.genesis.guild_id,
            profile,
            information: vec![mb_core::InformationRoleV2 {
                owner: certificate.genesis.members[remote[0]].node_id,
                failure_domain: certificate.genesis.members[remote[0]]
                    .failure_domain
                    .clone(),
                sector: mb_core::RangeSectorRef {
                    id: [211; 32],
                    commitment: merkle_commit(&[7; 16]).unwrap(),
                    logical_len: 16,
                    virtual_zero: false,
                },
            }],
            parity: vec![mb_core::ParityPlacementV2 {
                holder: certificate.genesis.members[remote[1]].node_id,
                failure_domain: certificate.genesis.members[remote[1]]
                    .failure_domain
                    .clone(),
                row: 0,
            }],
        };
        let failed = node
            .sign_coding_attempt_plan(CodingAttemptPlan {
                format_version: 1,
                attempt_id: [212; 16],
                checkpoint_hash: [213; 32],
                membership_epoch: 1,
                geometry,
                delegator: local_id,
                coding_coordinator: keys[remote[0]].node_id(),
                verification_coordinator: keys[remote[1]].node_id(),
                expires_at_unix_seconds: unix_seconds() + 600,
                information_roots: None,
            })
            .unwrap();
        let failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: failed.clone(),
                error_hash: [214; 32],
            },
            &keys[remote[0]],
        )
        .unwrap();
        assert_eq!(node.enqueue_coding_launch(failed.clone()).unwrap(), failed);
        drop(node);
        let node = Node::open(temp.path(), local_seed.clone()).unwrap();
        assert_eq!(node.claim_coding_launch().unwrap().unwrap().plan, failed);
        node.complete_coding_launch([212; 16]).unwrap();
        assert!(node.claim_coding_launch().unwrap().is_none());
        node.accept_coding_failure(keys[remote[0]].node_id(), failure.clone())
            .unwrap();
        node.accept_coding_failure(keys[remote[0]].node_id(), failure)
            .unwrap();
        assert!(node.coding_checkpoint_has_pending([213; 32]).unwrap());

        drop(node);
        let mut node = Node::open(temp.path(), local_seed).unwrap();
        assert!(node.claim_coding_launch().unwrap().is_none());
        let retry = node.claim_coding_retry().unwrap().unwrap();
        assert!(retry.retry_plan.is_none());
        let fresh = node
            .prepare_coding_retry(
                [212; 16],
                keys[remote[2]].node_id(),
                keys[remote[3]].node_id(),
                unix_seconds() + 600,
            )
            .unwrap();
        assert_ne!(fresh.value.attempt_id, failed.value.attempt_id);
        assert_ne!(
            fresh.value.coding_coordinator,
            failed.value.coding_coordinator
        );
        assert_ne!(
            fresh.value.verification_coordinator,
            failed.value.verification_coordinator
        );
        assert_eq!(fresh.value.geometry, failed.value.geometry);
        assert_eq!(
            node.prepare_coding_retry(
                [212; 16],
                keys[remote[3]].node_id(),
                keys[remote[2]].node_id(),
                unix_seconds() + 900,
            )
            .unwrap(),
            fresh
        );
        node.complete_coding_retry([212; 16]).unwrap();
        assert!(node.claim_coding_retry().unwrap().is_none());
        assert!(!node.coding_checkpoint_has_pending([213; 32]).unwrap());
        node.enqueue_coding_launch(failed.clone()).unwrap();

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let relabel = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: certificate.genesis.members[remote[0]].node_id,
                failure_domain: "changed-after-attempt".to_owned(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|keys| sign_guild_event(&relabel, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: relabel,
            signatures,
        })
        .unwrap();
        assert!(node.validate_coding_attempt_plan(&failed).is_err());
        node.validate_coding_attempt_for_cleanup(&failed).unwrap();
        let mut current = failed.value.clone();
        current.attempt_id = [215; 16];
        current.membership_epoch = 2;
        current.geometry.information[0].failure_domain = "changed-after-attempt".to_owned();
        let current = node.sign_coding_attempt_plan(current).unwrap();
        node.enqueue_coding_launch(current.clone()).unwrap();
        assert_eq!(node.claim_coding_launch().unwrap().unwrap().plan, current);
        node.complete_coding_launch([215; 16]).unwrap();
        assert_eq!(node.claim_coding_launch().unwrap().unwrap().plan, failed);
        node.abandon_coding_launch([212; 16]).unwrap();
        assert!(node.claim_coding_launch().unwrap().is_none());
    }

    #[test]
    fn peer_exchange_endpoint_exists_before_a_checkpoint_and_reuses_its_sequence() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path(), local_seed).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let local_id = node.keys().node_id();
        let peer_id = local_id.libp2p_peer_id().unwrap();
        let onion = crate::network::onion_listener_address(local_id).unwrap();
        let endpoints = vec![
            format!("/ip4/198.51.100.8/udp/44000/quic-v1/p2p/{peer_id}"),
            format!("{onion}/p2p/{peer_id}"),
        ];
        let expires = unix_seconds() + 15 * 60;
        let first = node
            .refresh_peer_exchange_endpoint(endpoints.clone(), expires)
            .unwrap()
            .unwrap();
        let reused = node
            .refresh_peer_exchange_endpoint(endpoints, expires + 30)
            .unwrap()
            .unwrap();
        assert_eq!(first, reused);
        assert_eq!(first.value.sequence, 1);

        let reader = node.reader_config().open().unwrap();
        assert_eq!(
            reader
                .peer_exchange_endpoints(certificate.genesis.guild_id)
                .unwrap(),
            vec![first]
        );
        assert!(
            node.current_checkpoint(certificate.genesis.guild_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn prepared_revision_pages_are_bound_to_the_requested_guild() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([88; 32])).unwrap();
        let guild_id = [87; 32];
        let revision_id = Uuid::from_bytes([86; 16]);
        let writer = ed25519_dalek::SigningKey::from_bytes(&[73; 32]);
        let mut revision_body = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id,
            owner: node.keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: Vec::new(),
            data_sectors: Vec::new(),
        };
        revision_body.sign_writer(&writer).unwrap();
        let revision =
            SignedRecord::sign(USER_REVISION_DOMAIN, revision_body, node.keys()).unwrap();
        node.control
            .put_record(
                "user-revision",
                revision_id.as_bytes(),
                &canonical_bytes(&revision).unwrap(),
            )
            .unwrap();
        let reader = node.reader_config().open().unwrap();
        assert!(
            reader
                .prepared_revision_page(&guild_id, revision_id, 0)
                .is_ok()
        );
        assert!(
            reader
                .prepared_revision_page(&[85; 32], revision_id, 0)
                .is_err()
        );
    }

    #[test]
    fn live_reader_releases_a_retired_volume_before_detach() {
        let temp = tempfile::tempdir().unwrap();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), Seed::from_bytes([225; 32])).unwrap();
        node.configure_storage_volumes(
            &[first.path().to_path_buf(), second.path().to_path_buf()],
            (mb_core::V1_SECTOR_SIZE * 2) as u64,
            0,
        )
        .unwrap();
        let bytes = vec![226; mb_core::V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [227; 32],
            group_id: [228; 32],
            shard_index: 4,
            root: sector_root(&bytes),
            bytes: bytes.clone(),
        };
        let receipt = node.volumes.store(&node.control, &object, b"ack").unwrap();
        let source_path = node
            .storage_status()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == receipt.volume_id)
            .unwrap()
            .path;
        let reader = node.reader_config().open().unwrap();
        assert_eq!(
            reader
                .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
                .unwrap(),
            bytes
        );

        node.drain_storage_volume(receipt.volume_id).unwrap();
        assert_eq!(node.migrate_draining_volumes().unwrap(), 1);
        fs::remove_dir_all(&source_path).unwrap();

        assert_eq!(
            reader
                .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
                .unwrap(),
            object.bytes
        );
        assert_eq!(
            reader.advertised_member("fallback").unwrap().node_id,
            node.keys().node_id()
        );
        let fresh_reader = node.reader_config().open().unwrap();
        assert_eq!(
            fresh_reader
                .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
                .unwrap(),
            object.bytes
        );
        assert!(!source_path.exists());
    }

    #[test]
    fn variable_coding_attempt_stages_opens_and_activates_after_replay() {
        let data_dir = tempfile::tempdir().unwrap();
        let storage = tempfile::tempdir().unwrap();
        let information_data_dir = tempfile::tempdir().unwrap();
        let information_storage = tempfile::tempdir().unwrap();
        let mut identities = (0_u8..5)
            .map(|index| {
                let seed = Seed::from_bytes([index + 180; 32]);
                let keys = KeyMaterial::from_seed(&seed);
                (keys.node_id(), seed, keys.recovery_public_key())
            })
            .collect::<Vec<_>>();
        identities.sort_by_key(|(node_id, _, _)| *node_id);
        let keys = identities
            .iter()
            .map(|(_, seed, _)| KeyMaterial::from_seed(seed))
            .collect::<Vec<_>>();
        let members = identities
            .iter()
            .enumerate()
            .map(|(index, (node_id, _, recovery_public_key))| Member {
                node_id: *node_id,
                recovery_public_key: *recovery_public_key,
                failure_domain: format!("attempt-domain-{index}"),
            })
            .collect::<Vec<_>>();
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: [181; 32],
            coordinator: members[0].node_id,
            members: members.clone(),
        };
        let certificate = QuorumGuildGenesis {
            signatures: keys
                .iter()
                .map(|keys| genesis.member_signature(keys).unwrap())
                .collect(),
            genesis,
        };
        let peers = members
            .iter()
            .map(|member| GuildPeer {
                member: member.clone(),
                endpoints: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut node = Node::open(data_dir.path(), identities[4].1.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers.clone())
            .unwrap();
        node.configure_storage_volumes(&[storage.path().to_path_buf()], 4096, 0)
            .unwrap();
        let mut information_node =
            Node::open(information_data_dir.path(), identities[2].1.clone()).unwrap();
        information_node
            .adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        information_node
            .configure_storage_volumes(&[information_storage.path().to_path_buf()], 4096, 0)
            .unwrap();

        let profile = mb_core::CodingProfile::new(3, 2, 64);
        let information = vec![vec![7; 64], vec![19; 64], vec![31; 64]];
        let shards = mb_core::encode(profile, information).unwrap();
        let mut roles = shards[..3]
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                ShardRoleV2::Information(mb_core::InformationRoleV2 {
                    owner: members[index].node_id,
                    failure_domain: members[index].failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: [index as u8 + 1; 32],
                        commitment: merkle_commit(bytes).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                })
            })
            .collect::<Vec<_>>();
        roles.extend(shards[3..].iter().enumerate().map(|(row, bytes)| {
            let member = &members[3 + row];
            ShardRoleV2::Parity(mb_core::ParityRoleV2 {
                holder: member.node_id,
                failure_domain: member.failure_domain.clone(),
                row: row as u16,
                commitment: merkle_commit(bytes).unwrap(),
            })
        }));
        let mut group = mb_core::CodingGroupV2 {
            id: [0; 32],
            format_version: 2,
            guild_id: [181; 32],
            profile,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let plan = CodingAttemptPlan {
            format_version: 2,
            attempt_id: [182; 16],
            checkpoint_hash: [183; 32],
            membership_epoch: 1,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id: group.guild_id,
                profile,
                information: group.roles[..3]
                    .iter()
                    .map(|role| match role {
                        ShardRoleV2::Information(information) => information.clone(),
                        ShardRoleV2::Parity(_) => unreachable!(),
                    })
                    .collect(),
                parity: group.roles[3..]
                    .iter()
                    .map(|role| match role {
                        ShardRoleV2::Parity(parity) => mb_core::ParityPlacementV2 {
                            holder: parity.holder,
                            failure_domain: parity.failure_domain.clone(),
                            row: parity.row,
                        },
                        ShardRoleV2::Information(_) => unreachable!(),
                    })
                    .collect(),
            },
            delegator: members[0].node_id,
            coding_coordinator: members[1].node_id,
            verification_coordinator: members[4].node_id,
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(shards[..3].iter().map(|bytes| sector_root(bytes)).collect()),
        };
        let plan_hash = plan.hash().unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, &keys[0]).unwrap();
        assert_eq!(
            information_node
                .reserve_coding_information(&plan, 2)
                .unwrap(),
            0
        );
        assert_eq!(
            information_node
                .write_coding_information_range(&plan, 2, 0, &shards[2][..32])
                .unwrap(),
            32
        );
        assert_eq!(
            information_node
                .reserve_coding_information(&plan, 2)
                .unwrap(),
            32
        );
        assert_eq!(
            information_node
                .write_coding_information_range(&plan, 2, 32, &shards[2][32..])
                .unwrap(),
            64
        );
        information_node
            .finish_coding_information_upload(&plan, 2)
            .unwrap();
        let challenge_commitment = node.commit_coding_challenge(&plan).unwrap();
        let manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            CodingRootManifest {
                format_version: 1,
                attempt_id: [182; 16],
                plan_hash,
                group,
            },
            &keys[1],
        )
        .unwrap();
        let local_object = VariableParityObject {
            format_version: 2,
            guild_id: [181; 32],
            group_id: manifest.value.group.id,
            shard_index: 4,
            commitment: merkle_commit(&shards[4]).unwrap(),
            bytes: shards[4].clone(),
        };
        assert_eq!(node.reserve_coding_parity(&plan, 4).unwrap(), 0);
        assert_eq!(
            node.write_coding_parity_range(&plan, &manifest, 4, 0, &local_object.bytes[..32])
                .unwrap(),
            32
        );
        assert_eq!(node.reserve_coding_parity(&plan, 4).unwrap(), 32);
        assert_eq!(
            node.write_coding_parity_range(&plan, &manifest, 4, 32, &local_object.bytes[32..])
                .unwrap(),
            64
        );
        let local_receipt = node
            .finish_coding_parity_upload(&plan, &manifest, 4)
            .unwrap();
        assert_eq!(
            node.finish_coding_parity_upload(&plan, &manifest, 4)
                .unwrap(),
            local_receipt
        );
        assert!(
            node.variable_parity_for_guild(&[181; 32], &manifest.value.group.id, 4)
                .is_err()
        );
        let other_receipt = SignedRecord::sign(
            STAGED_STORAGE_RECEIPT_DOMAIN,
            StagedStorageReceipt {
                format_version: 1,
                attempt_id: [182; 16],
                plan_hash,
                guild_id: [181; 32],
                group_id: manifest.value.group.id,
                shard_index: 3,
                holder: members[3].node_id,
                commitment: merkle_commit(&shards[3]).unwrap(),
            },
            &keys[3],
        )
        .unwrap();
        let receipts = vec![other_receipt, local_receipt];
        let reveal = node
            .reveal_coding_challenge(&plan, &manifest, &receipts)
            .unwrap();
        let challenge =
            mb_core::coding_challenge(plan_hash, reveal.value.nonce, reveal.value.evidence_hash);
        let mut openings = Vec::new();
        for (index, bytes) in shards.iter().enumerate() {
            if index == 4 {
                openings.push(
                    node.coding_shard_opening(&plan, &manifest, challenge, index as u16)
                        .unwrap(),
                );
                continue;
            }
            if index == 2 {
                openings.push(
                    information_node
                        .coding_shard_opening(&plan, &manifest, challenge, index as u16)
                        .unwrap(),
                );
                continue;
            }
            let commitment = match &manifest.value.group.roles[index] {
                ShardRoleV2::Information(information) => &information.sector.commitment,
                ShardRoleV2::Parity(parity) => &parity.commitment,
            };
            let leaf = challenged_leaf(&challenge, commitment).unwrap();
            openings.push(
                SignedRecord::sign(
                    CODING_SHARD_OPENING_DOMAIN,
                    CodingShardOpening {
                        format_version: 1,
                        attempt_id: [182; 16],
                        plan_hash,
                        verifier: members[4].node_id,
                        challenge,
                        shard_index: index as u16,
                        commitment: commitment.clone(),
                        proof: merkle_open_range(bytes, leaf, 1).unwrap(),
                    },
                    &keys[index],
                )
                .unwrap(),
            );
        }
        let transcript = SignedRecord::sign(
            mb_core::CODING_TRANSCRIPT_DOMAIN,
            CodingVerificationTranscript {
                format_version: 1,
                verified_at_unix_seconds: unix_seconds(),
                plan,
                manifest,
                challenge_commitment,
                staged_receipts: receipts,
                challenge_reveal: reveal,
                openings,
            },
            node.keys(),
        )
        .unwrap();
        node.activate_coding_attempt(&transcript).unwrap();
        information_node
            .activate_coding_attempt(&transcript)
            .unwrap();
        assert_eq!(
            information_node
                .variable_information_for_guild(
                    &[181; 32],
                    &transcript.value.plan.value.geometry.information[2]
                        .sector
                        .id,
                    2,
                )
                .unwrap()
                .bytes,
            shards[2]
        );
        assert_eq!(
            node.variable_parity_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .unwrap(),
            local_object
        );
        assert_eq!(
            node.reader_config()
                .open()
                .unwrap()
                .coding_transcript_for_group([181; 32], transcript.value.manifest.value.group.id,)
                .unwrap(),
            transcript
        );
        assert!(
            node.discard_coding_attempt(&transcript.value.plan.value.attempt_id)
                .unwrap()
        );
        assert!(
            node.variable_parity_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .is_err()
        );
        assert_eq!(
            node.reserve_coding_parity(&transcript.value.plan, 4)
                .unwrap(),
            0
        );
        assert_eq!(
            node.write_coding_parity_range(
                &transcript.value.plan,
                &transcript.value.manifest,
                4,
                0,
                &local_object.bytes,
            )
            .unwrap(),
            64
        );
        assert_eq!(
            node.finish_coding_parity_upload(
                &transcript.value.plan,
                &transcript.value.manifest,
                4,
            )
            .unwrap(),
            transcript.value.staged_receipts[1]
        );
        node.activate_coding_attempt(&transcript).unwrap();

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let event = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroup {
                group: transcript.value.manifest.value.group.clone(),
            },
        };
        assert!(node.sign_guild_event_proposal(&event).is_err());
        assert_eq!(
            node.sign_coding_group_event_proposal(&event, &transcript)
                .unwrap()
                .signer,
            node.keys().node_id()
        );
        let mut signatures = keys
            .iter()
            .map(|keys| sign_guild_event(&event, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let certified = QuorumGuildEvent { event, signatures };
        assert!(node.install_guild_event(certified.clone()).is_err());
        node.install_coding_group_event(certified.clone(), transcript.clone())
            .unwrap();
        information_node
            .install_coding_group_event(certified, transcript.clone())
            .unwrap();
        node.activate_coding_attempt(&transcript).unwrap();
        information_node
            .activate_coding_attempt(&transcript)
            .unwrap();
        assert_eq!(
            node.dynamic_guild_state().unwrap().unwrap().coding_groups[0].group,
            transcript.value.manifest.value.group
        );
        assert_eq!(
            information_node
                .variable_shard_for_guild(&[181; 32], &transcript.value.manifest.value.group.id, 2,)
                .unwrap(),
            shards[2]
        );
        assert_eq!(
            node.variable_shard_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .unwrap(),
            shards[4]
        );

        let writer = ed25519_dalek::SigningKey::from_bytes(&[184; 32]);
        let target = SectorRef {
            id: transcript.value.plan.value.geometry.information[2]
                .sector
                .id,
            root: sector_root(&shards[2]),
            logical_len: 64,
        };
        let mut revision = UserRevision {
            format_version: 3,
            guild_id: [181; 32],
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([185; 16]),
            owner: members[2].node_id,
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![target.clone()],
            data_sectors: Vec::new(),
        };
        revision.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, &keys[2]).unwrap();
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 4,
                guild_id: [181; 32],
                genesis_hash: certificate.hash().unwrap(),
                generation: 1,
                parent: None,
                members: members.clone(),
                writer_fences: vec![mb_core::WriterFence {
                    owner: members[2].node_id,
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }],
                revision_tombstones: Vec::new(),
                revisions: vec![revision],
                coding_groups: Vec::new(),
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for key in &keys {
            checkpoint.add_signature(key).unwrap();
        }
        assert!(
            node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, true)
                .is_err()
        );
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let writer_event = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: members[2].node_id,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|keys| sign_guild_event(&writer_event, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let certified_writer_event = QuorumGuildEvent {
            event: writer_event,
            signatures,
        };
        node.install_guild_event(certified_writer_event.clone())
            .unwrap();
        information_node
            .install_guild_event(certified_writer_event)
            .unwrap();
        assert!(
            node.uncovered_variable_sectors(members[2].node_id, std::slice::from_ref(&target))
                .unwrap()
                .is_empty()
        );
        let mut changed = target.clone();
        changed.root[0] ^= 1;
        assert_eq!(
            node.uncovered_variable_sectors(members[2].node_id, &[changed.clone()])
                .unwrap(),
            vec![changed]
        );
        node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, false)
            .unwrap();
        node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, true)
            .unwrap();
        let checkpoint_hash = checkpoint.hash().unwrap();
        node.pin_recovery_attempt(&checkpoint, Vec::new(), None)
            .unwrap();
        node.install_recovered_checkpoint(&checkpoint).unwrap();
        let parity_root = match &transcript.value.manifest.value.group.roles[4] {
            ShardRoleV2::Parity(parity) => parity.commitment.root,
            ShardRoleV2::Information(_) => unreachable!(),
        };
        node.volumes
            .remove_unreachable(
                &node.control,
                &transcript.value.manifest.value.group.id,
                4,
                &parity_root,
            )
            .unwrap();
        assert!(
            node.variable_shard_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .is_err()
        );
        node.install_repaired_variable_shard(
            [186; 16],
            checkpoint_hash,
            transcript.value.manifest.value.group.id,
            4,
            &shards[4],
            false,
        )
        .unwrap();
        assert_eq!(
            node.variable_shard_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .unwrap(),
            shards[4]
        );
        node.install_repaired_variable_shard(
            [187; 16],
            checkpoint_hash,
            transcript.value.manifest.value.group.id,
            2,
            &shards[2],
            true,
        )
        .unwrap();
        assert_eq!(
            node.variable_emergency_shard_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                2,
            )
            .unwrap(),
            shards[2]
        );
        assert_eq!(
            node.remove_local_variable_emergency_shards(
                checkpoint_hash,
                &transcript.value.manifest.value.group,
            )
            .unwrap(),
            1
        );
        assert!(
            node.variable_emergency_shard_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                2,
            )
            .is_err()
        );
        assert_eq!(
            node.reader_config()
                .open()
                .unwrap()
                .variable_shard_for_guild(&[181; 32], &transcript.value.manifest.value.group.id, 4,)
                .unwrap(),
            shards[4]
        );
        node.record_guild_audit(&GuildAuditReport {
            format_version: 1,
            checkpoint_hash,
            checkpoint_generation: checkpoint.checkpoint.generation,
            audited_at_unix_seconds: 1,
            state: ProtectionState::Healthy,
            checked_groups: 1,
            assigned_shards_unavailable: 0,
            assigned_shards_repaired: 0,
            emergency_copies_created: 0,
            emergency_copies_removed: 0,
            issues: Vec::new(),
        })
        .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let relabel = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: members[2].node_id,
                failure_domain: "replacement-domain".to_owned(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|keys| sign_guild_event(&relabel, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let certified_relabel = QuorumGuildEvent {
            event: relabel,
            signatures,
        };
        node.install_guild_event(certified_relabel.clone()).unwrap();
        information_node
            .install_guild_event(certified_relabel)
            .unwrap();
        assert!(node.last_guild_audit().unwrap().is_none());
        assert_eq!(
            node.uncovered_variable_sectors(members[2].node_id, std::slice::from_ref(&target))
                .unwrap(),
            vec![target.clone()]
        );
        // A retained checkpoint remains valid while replacement work is
        // queued; only fresh placement decisions exclude the stale layout.
        node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, false)
            .unwrap();
        node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, true)
            .unwrap();
        assert_eq!(
            information_node
                .variable_shard_for_guild(&[181; 32], &transcript.value.manifest.value.group.id, 2,)
                .unwrap(),
            shards[2]
        );
        assert!(
            node.discard_coding_attempt(&transcript.value.plan.value.attempt_id)
                .unwrap()
        );
        assert!(
            node.variable_parity_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .is_ok()
        );
        node.schedule_garbage(
            "gc-variable-parity",
            &variable_emergency_id(&transcript.value.manifest.value.group.id, 4),
            1,
            checkpoint_hash,
            Some(parity_root),
        )
        .unwrap();
        node.collect_mature_garbage(2, &BTreeSet::new(), &BTreeSet::new(), &BTreeSet::new())
            .unwrap();
        assert!(
            node.variable_shard_for_guild(
                &[181; 32],
                &transcript.value.manifest.value.group.id,
                4,
            )
            .is_err()
        );
    }

    #[test]
    fn pooled_reader_skips_a_corrupt_copy_in_either_volume_order() {
        let temp = tempfile::tempdir().unwrap();
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([229; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        node.configure_storage_volumes(
            &[first.path().to_path_buf(), second.path().to_path_buf()],
            (mb_core::V1_SECTOR_SIZE * 2) as u64,
            0,
        )
        .unwrap();
        let bytes = vec![230; mb_core::V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [231; 32],
            group_id: [232; 32],
            shard_index: 3,
            root: sector_root(&bytes),
            bytes: bytes.clone(),
        };
        let receipt = node.volumes.store(&node.control, &object, b"ack").unwrap();
        let mut configs = node.volumes.reader_configs();
        let source_index = configs
            .iter()
            .position(|config| config.volume_id == receipt.volume_id)
            .unwrap();
        let source = configs.remove(source_index);
        let destination = configs.pop().unwrap();
        ParityStore::open_existing_with_key(
            &destination.path,
            destination.volume_id.as_bytes(),
            &destination.database_key,
        )
        .unwrap()
        .stage_and_publish(&object)
        .unwrap();
        node.database_shell_statement(
            Some(source.volume_id),
            "UPDATE parity_objects SET bytes = zeroblob(65536)",
            true,
        )
        .unwrap();
        *node.volume_readers.write().unwrap() = vec![source, destination];
        let reader = node.reader_config().open().unwrap();

        assert_eq!(
            reader
                .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
                .unwrap(),
            bytes
        );
        assert!(node.storage_status().is_ok());
        drop(reader);
        drop(node);

        let node = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            node.reader_config()
                .open()
                .unwrap()
                .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
                .unwrap(),
            object.bytes
        );
        assert!(node.storage_status().is_ok());
    }

    #[test]
    fn recovery_publication_sequence_is_durable_and_not_a_checkpoint_generation() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([84; 32]);
        let slot = [83; 32];
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.next_recovery_publication_sequence(&slot, 1).unwrap(),
            1
        );
        assert_eq!(
            node.next_recovery_publication_sequence(&slot, 1).unwrap(),
            2
        );
        drop(node);
        let mut reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened
                .next_recovery_publication_sequence(&slot, 9)
                .unwrap(),
            9
        );
    }

    #[test]
    fn dht_recovery_publication_tracks_rotated_and_revoked_key_epochs() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, peers) = recovery_guild_fixture();
        let mut signer_keys = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 120; 32])))
            .collect::<Vec<_>>();
        signer_keys.sort_by_key(KeyMaterial::node_id);
        let mut node = Node::open(temp.path(), local_seed).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let guild_id = certificate.genesis.guild_id;
        let local_id = node.keys().node_id();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[194; 32]);
        let mut revision = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([193; 16]),
            owner: local_id,
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![SectorRef {
                id: [192; 32],
                root: [191; 32],
                logical_len: 1,
            }],
            data_sectors: Vec::new(),
        };
        revision.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, node.keys()).unwrap();
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 4,
                guild_id,
                genesis_hash: certificate.hash().unwrap(),
                generation: 1,
                parent: None,
                members: certificate.genesis.members.clone(),
                writer_fences: vec![mb_core::WriterFence {
                    owner: local_id,
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }],
                revision_tombstones: Vec::new(),
                revisions: vec![revision],
                coding_groups: Vec::new(),
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for keys in &signer_keys {
            checkpoint.add_signature(keys).unwrap();
        }
        let checkpoint_hash = checkpoint.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                1,
                None,
                &checkpoint_hash,
                &canonical_bytes(&checkpoint.checkpoint).unwrap(),
                &canonical_bytes(&checkpoint).unwrap(),
                false,
            )
            .unwrap();

        let mut current_envelopes = BTreeMap::new();
        for keys in &signer_keys {
            let state = node.dynamic_guild_state().unwrap().unwrap();
            let (envelope, _) = mb_core::create_recovery_key_envelope(keys, guild_id, 1).unwrap();
            let event = GuildEvent {
                format_version: 1,
                guild_id,
                sequence: state.event_sequence + 1,
                parent: state.event_head,
                kind: mb_core::GuildEventKind::RotateRecoveryKey {
                    envelope: envelope.clone(),
                },
            };
            let mut signatures = signer_keys
                .iter()
                .map(|signer| sign_guild_event(&event, signer).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            node.install_guild_event(QuorumGuildEvent { event, signatures })
                .unwrap();
            current_envelopes.insert(keys.node_id(), envelope);
        }
        let endpoint = format!(
            "/ip4/127.0.0.1/udp/44000/quic-v1/p2p/{}",
            local_id.libp2p_peer_id().unwrap()
        );
        let expires = unix_seconds() + 15 * 60;
        let first = node
            .build_dht_publications(
                vec![endpoint.clone()],
                expires,
                DhtSequenceFloors::default(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(first.recovery.len(), 4);
        for bundle in &first.recovery {
            assert_eq!(bundle.value.format_version, 2);
            let envelope = bundle.value.key_envelope.as_ref().unwrap();
            assert_eq!(Some(envelope), current_envelopes.get(&bundle.value.subject));
            let subject_keys = signer_keys
                .iter()
                .find(|keys| keys.node_id() == bundle.value.subject)
                .unwrap();
            let secret = open_recovery_key_envelope(subject_keys, envelope).unwrap();
            let plaintext = secret.open_record(&bundle.value.sealed).unwrap();
            let locator: SignedRecord<RecoveryLocator> = decode_canonical(&plaintext).unwrap();
            locator.verify(RECOVERY_LOCATOR_DOMAIN).unwrap();
            assert_eq!(locator.value.checkpoint_hash, checkpoint_hash);
        }
        for format_version in 4..=7 {
            let mut compatible = checkpoint.clone();
            compatible.checkpoint.format_version = format_version;
            for bundle in &first.recovery {
                node.validate_recovery_bundle_key(&compatible, &bundle.value)
                    .unwrap();
            }
        }

        let target = first.recovery[0].value.subject;
        let target_keys = signer_keys
            .iter()
            .find(|keys| keys.node_id() == target)
            .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let (rotated, _) = mb_core::create_recovery_key_envelope(target_keys, guild_id, 2).unwrap();
        let rotate = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RotateRecoveryKey {
                envelope: rotated.clone(),
            },
        };
        let mut signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&rotate, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: rotate,
            signatures,
        })
        .unwrap();
        let rotated_publications = node
            .build_dht_publications(
                vec![endpoint.clone()],
                expires,
                DhtSequenceFloors::default(),
            )
            .unwrap()
            .unwrap();
        let rotated_bundle = rotated_publications
            .recovery
            .iter()
            .find(|bundle| bundle.value.subject == target)
            .unwrap();
        assert_eq!(rotated_bundle.value.key_envelope.as_ref(), Some(&rotated));
        assert!(
            rotated_bundle.value.sequence
                > first
                    .recovery
                    .iter()
                    .find(|bundle| bundle.value.subject == target)
                    .unwrap()
                    .value
                    .sequence
        );

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let revoke = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RevokeRecoveryKey {
                subject: target,
                epoch: 2,
            },
        };
        let mut signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&revoke, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: revoke,
            signatures,
        })
        .unwrap();
        assert!(
            node.build_dht_publications(vec![endpoint], expires, DhtSequenceFloors::default(),)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn recovered_parity_respects_the_configured_budget() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path(), Seed::from_bytes([83; 32])).unwrap();
        node.configure_parity_budget((mb_core::V1_SECTOR_SIZE - 1) as u64)
            .unwrap();
        let (_, checkpoint) = signed_recovery_checkpoint_fixture();
        let group = &checkpoint.checkpoint.coding_groups[0];
        let bytes = vec![82; mb_core::V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: group.guild_id,
            group_id: group.id,
            shard_index: 3,
            root: sector_root(&bytes),
            bytes,
        };

        let error = node.publish_validated_parity(group, &object).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<DatabaseError>(),
            Some(DatabaseError::CapacityExceeded)
        ));
        assert!(node.volumes.load_ready(&group.id, 3).is_err());
    }

    #[test]
    fn accepted_dht_sequences_reject_rollback_and_forks_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([82; 32]);
        let record_id = [81; 32];
        let expires = unix_seconds() + 300;
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.observe_dht_records(
                "dht-observed-endpoint",
                &record_id,
                vec![
                    DhtRecordObservation {
                        sequence: 1,
                        expires_at_unix_seconds: expires,
                        bytes: b"first".to_vec(),
                    },
                    DhtRecordObservation {
                        sequence: 2,
                        expires_at_unix_seconds: expires,
                        bytes: b"second".to_vec(),
                    },
                ],
            )
            .unwrap(),
            Some(b"second".to_vec())
        );
        assert_eq!(
            node.observe_dht_records("dht-observed-endpoint", &record_id, Vec::new())
                .unwrap(),
            Some(b"second".to_vec())
        );
        drop(node);

        let mut reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened
                .observe_dht_records(
                    "dht-observed-endpoint",
                    &record_id,
                    vec![DhtRecordObservation {
                        sequence: 1,
                        expires_at_unix_seconds: expires,
                        bytes: b"first".to_vec(),
                    }],
                )
                .unwrap(),
            Some(b"second".to_vec())
        );
        assert!(
            reopened
                .observe_dht_records(
                    "dht-observed-endpoint",
                    &record_id,
                    vec![DhtRecordObservation {
                        sequence: 1,
                        expires_at_unix_seconds: expires,
                        bytes: b"fork".to_vec(),
                    }],
                )
                .is_err()
        );

        let mut state: DhtObservationState = decode_canonical(
            &reopened
                .control
                .get_record("dht-observed-endpoint", &record_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        state.current.expires_at_unix_seconds = unix_seconds().saturating_sub(1);
        reopened
            .control
            .put_record(
                "dht-observed-endpoint",
                &record_id,
                &canonical_bytes(&state).unwrap(),
            )
            .unwrap();
        assert_eq!(
            reopened
                .observe_dht_records("dht-observed-endpoint", &record_id, Vec::new())
                .unwrap(),
            None
        );
        assert_eq!(
            reopened
                .observe_dht_records(
                    "dht-observed-endpoint",
                    &record_id,
                    vec![DhtRecordObservation {
                        sequence: 1,
                        expires_at_unix_seconds: expires,
                        bytes: b"first".to_vec(),
                    }],
                )
                .unwrap(),
            Some(b"first".to_vec())
        );
        assert_eq!(
            reopened
                .observe_dht_records(
                    "dht-observed-endpoint",
                    &record_id,
                    vec![DhtRecordObservation {
                        sequence: 3,
                        expires_at_unix_seconds: expires,
                        bytes: b"third".to_vec(),
                    }],
                )
                .unwrap(),
            Some(b"third".to_vec())
        );
    }

    #[test]
    fn recovery_locators_carry_and_restore_the_subject_endpoint_floor() {
        let publisher_dir = tempfile::tempdir().unwrap();
        let recovered_dir = tempfile::tempdir().unwrap();
        let publisher_seed = Seed::from_bytes([80; 32]);
        let subject_seed = Seed::from_bytes([79; 32]);
        let subject_keys = KeyMaterial::from_seed(&subject_seed);
        let subject = Member {
            node_id: subject_keys.node_id(),
            recovery_public_key: subject_keys.recovery_public_key(),
            failure_domain: "subject-domain".to_owned(),
        };
        let publisher = Node::open(publisher_dir.path(), publisher_seed).unwrap();
        let observed_bytes = b"last subject endpoint".to_vec();
        let observed_hash = *blake3::hash(&observed_bytes).as_bytes();
        let observed_sequence = 73;
        let state = DhtObservationState {
            format_version: DHT_OBSERVATION_FORMAT_UNCERTIFIED,
            highest_sequence: observed_sequence,
            hashes: vec![DhtObservedHash {
                sequence: observed_sequence,
                hash: observed_hash,
            }],
            current: DhtObservedRecord {
                sequence: observed_sequence,
                hash: observed_hash,
                expires_at_unix_seconds: unix_seconds().saturating_sub(1),
                bytes: observed_bytes,
            },
        };
        publisher
            .control
            .put_record(
                "dht-observed-endpoint",
                &subject.node_id.0,
                &canonical_bytes(&state).unwrap(),
            )
            .unwrap();
        let sealed = publisher
            .recovery_record_for_endpoints(
                &subject,
                [78; 32],
                [77; 32],
                4,
                vec!["memory://publisher".to_owned()],
                unix_seconds() + 300,
            )
            .unwrap();
        let plaintext = open_recovery_record(&subject_keys, &sealed).unwrap();
        let locator: SignedRecord<RecoveryLocator> = decode_canonical(&plaintext).unwrap();
        locator.verify(RECOVERY_LOCATOR_DOMAIN).unwrap();
        assert_eq!(
            locator.value.subject_endpoint_sequence_floor,
            observed_sequence
        );

        let mut recovered = Node::open(recovered_dir.path(), subject_seed).unwrap();
        recovered
            .recover_endpoint_publication_sequence_floor(
                locator.value.guild_id,
                locator.value.subject_endpoint_sequence_floor,
            )
            .unwrap();
        let slot = publication_slot(
            b"endpoint",
            subject.node_id,
            subject.node_id,
            locator.value.guild_id,
        );
        assert_eq!(
            recovered
                .next_recovery_publication_sequence(&slot, 1)
                .unwrap(),
            observed_sequence + 1
        );
    }

    #[test]
    fn legacy_recovery_high_water_does_not_shadow_a_fresh_observation() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([81; 32]);
        let node = Node::open(temp.path(), seed).unwrap();
        let subject = node.keys().node_id();
        let provider = "legacy-poison-provider";
        let record_id = recovery_observation_record_id(subject, provider);
        let expires_at_unix_seconds = unix_seconds() + 300;
        let poison = b"uncertified high-water".to_vec();
        let poison_hash = *blake3::hash(&poison).as_bytes();
        let legacy = DhtObservationState {
            format_version: DHT_OBSERVATION_FORMAT_UNCERTIFIED,
            highest_sequence: u64::MAX - 1,
            hashes: vec![DhtObservedHash {
                sequence: u64::MAX - 1,
                hash: poison_hash,
            }],
            current: DhtObservedRecord {
                sequence: u64::MAX - 1,
                hash: poison_hash,
                expires_at_unix_seconds,
                bytes: poison,
            },
        };
        node.control
            .put_record(
                "dht-observed-recovery",
                &record_id,
                &canonical_bytes(&legacy).unwrap(),
            )
            .unwrap();

        let fresh = b"fresh candidate awaiting checkpoint validation".to_vec();
        assert_eq!(
            node.select_recovery_dht_records(
                &record_id,
                vec![DhtRecordObservation {
                    sequence: 1,
                    expires_at_unix_seconds,
                    bytes: fresh.clone(),
                }],
            )
            .unwrap(),
            Some(fresh)
        );
        assert_eq!(
            node.control
                .get_record("dht-observed-recovery", &record_id)
                .unwrap()
                .unwrap(),
            canonical_bytes(&legacy).unwrap()
        );
    }

    #[test]
    fn expired_recovery_observation_scopes_are_reclaimed_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([80; 32]);
        let node = Node::open(temp.path(), seed.clone()).unwrap();
        let subject = node.keys().node_id();
        let expires_at_unix_seconds = unix_seconds().saturating_sub(1);
        for index in 0_u8..64 {
            let bytes = vec![index; 8];
            let hash = *blake3::hash(&bytes).as_bytes();
            let state = DhtObservationState {
                format_version: 1,
                highest_sequence: 1,
                hashes: vec![DhtObservedHash { sequence: 1, hash }],
                current: DhtObservedRecord {
                    sequence: 1,
                    hash,
                    expires_at_unix_seconds,
                    bytes,
                },
            };
            let mut record_id = [0_u8; 64];
            record_id[..32].copy_from_slice(&subject.0);
            record_id[32] = index;
            record_id[63] = !index;
            node.control
                .put_record(
                    "dht-observed-recovery",
                    &record_id,
                    &canonical_bytes(&state).unwrap(),
                )
                .unwrap();
        }
        drop(node);

        let mut reopened = Node::open(temp.path(), seed).unwrap();
        assert!(
            reopened
                .observed_recovery_records(subject)
                .unwrap()
                .is_empty()
        );
        assert!(
            reopened
                .control
                .records("dht-observed-recovery")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn parity_publication_requires_the_declared_rs_equation() {
        let temp = tempfile::tempdir().unwrap();
        let identities = (0_u8..5)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 92; 32])).node_id())
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), Seed::from_bytes([95; 32])).unwrap();
        assert_eq!(node.keys().node_id(), identities[3]);
        let information = [
            vec![1; mb_core::V1_SECTOR_SIZE],
            vec![2; mb_core::V1_SECTOR_SIZE],
            vec![3; mb_core::V1_SECTOR_SIZE],
        ];
        let encoded = mb_core::encode_3_2(information.clone()).unwrap();
        let mut invalid_parity = encoded[3].clone();
        invalid_parity[0] ^= 1;
        let roles = [
            ShardRole::Information(mb_core::InformationRole {
                owner: identities[0],
                sector: SectorRef {
                    id: [1; 32],
                    root: sector_root(&information[0]),
                    logical_len: 1,
                },
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: identities[1],
                sector: SectorRef {
                    id: [2; 32],
                    root: sector_root(&information[1]),
                    logical_len: 1,
                },
            }),
            ShardRole::Information(mb_core::InformationRole {
                owner: identities[2],
                sector: SectorRef {
                    id: [3; 32],
                    root: sector_root(&information[2]),
                    logical_len: 1,
                },
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: identities[3],
                row: 0,
                root: sector_root(&invalid_parity),
            }),
            ShardRole::Parity(mb_core::ParityRole {
                holder: identities[4],
                row: 1,
                root: sector_root(&encoded[4]),
            }),
        ];
        let mut group = mb_core::CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id: [7; 32],
            data_shards: mb_core::V1_RS_DATA_SHARDS,
            parity_shards: mb_core::V1_RS_PARITY_SHARDS,
            shard_size: mb_core::V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let object = ParityObject {
            format_version: 1,
            guild_id: group.guild_id,
            group_id: group.id,
            shard_index: 3,
            root: sector_root(&invalid_parity),
            bytes: invalid_parity,
        };
        let checkpoint_hash = [8; 32];
        assert!(
            !node
                .recovered_shard_is_staged(
                    &checkpoint_hash,
                    &group.guild_id,
                    &group,
                    object.shard_index,
                )
                .unwrap()
        );
        node.stage_recovered_shard(
            &checkpoint_hash,
            &group.guild_id,
            &group,
            object.shard_index,
            &object.bytes,
        )
        .unwrap();
        assert!(
            node.recovered_shard_is_staged(
                &checkpoint_hash,
                &group.guild_id,
                &group,
                object.shard_index,
            )
            .unwrap()
        );
        let mut conflicting_group = group.clone();
        let mut conflicting_bytes = object.bytes.clone();
        conflicting_bytes[0] ^= 2;
        let ShardRole::Parity(conflicting_role) = &mut conflicting_group.roles[3] else {
            unreachable!();
        };
        conflicting_role.root = sector_root(&conflicting_bytes);
        assert!(
            node.stage_recovered_shard(
                &checkpoint_hash,
                &group.guild_id,
                &conflicting_group,
                object.shard_index,
                &conflicting_bytes,
            )
            .is_err()
        );
        assert!(
            node.publish_verified_parity(&group, &information, &object)
                .is_err()
        );
        assert!(node.parity(&group.id, 3).is_err());
    }

    #[test]
    fn published_restore_resumes_from_its_durable_native_identity() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([111; 32]);
        let mut node = Node::open(temp.path().join("node"), seed.clone()).unwrap();
        let target = temp.path().join("restored");
        fs::create_dir(&target).unwrap();
        let checkpoint_hash = [112; 32];
        let guild_id = [113; 32];
        let revision_id = Uuid::from_bytes([114; 16]);
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let job = RecoveryJob {
            format_version: 7,
            guild_id,
            revision_id,
            target: target.canonicalize().unwrap(),
            staging: temp.path().join(format!(
                ".mutualbackup-restore-{}",
                Uuid::from_bytes([115; 16])
            )),
            staged_native_id: Some(native_id_tuple(
                parent
                    .open_child_directory("restored")
                    .unwrap()
                    .unwrap()
                    .identity()
                    .unwrap(),
            )),
            state: RecoveryJobState::Published,
            parent_native_id: Some(native_id_tuple(parent.identity().unwrap())),
        };
        node.control
            .put_record(
                "recovery-job",
                &checkpoint_hash,
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
        let mut revision_body = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_bytes([1; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id,
            owner: node.keys().node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: Vec::new(),
            data_sectors: Vec::new(),
        };
        revision_body.sign_writer(&writer).unwrap();
        let revision =
            SignedRecord::sign(USER_REVISION_DOMAIN, revision_body, node.keys()).unwrap();

        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();
        let bytes = node
            .control
            .get_record("recovery-job", &checkpoint_hash)
            .unwrap()
            .unwrap();
        let completed: RecoveryJob = decode_canonical(&bytes).unwrap();
        assert_eq!(completed.state, RecoveryJobState::Complete);

        let mut interrupted_finalization = completed;
        interrupted_finalization.state = RecoveryJobState::Published;
        node.control
            .put_record(
                "recovery-job",
                &checkpoint_hash,
                &canonical_bytes(&interrupted_finalization).unwrap(),
            )
            .unwrap();
        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();
        let bytes = node
            .control
            .get_record("recovery-job", &checkpoint_hash)
            .unwrap()
            .unwrap();
        let completed_again: RecoveryJob = decode_canonical(&bytes).unwrap();
        assert_eq!(completed_again.state, RecoveryJobState::Complete);

        node.control.make_query_only().unwrap();
        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn complete_recovery_verifies_a_relocated_anchor_without_writing() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("complete-recovery-query-only-{}", Uuid::new_v4()));
        let original_parent = run_root.join("original");
        let moved_parent = run_root.join("moved");
        let source = original_parent.join("source");
        let restore_parent = run_root.join("restore-parent");
        let target = restore_parent.join("restored");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(source.join("payload"), b"relocated stable anchor").unwrap();

        let mut node = Node::open(run_root.join("node"), Seed::from_bytes([220; 32])).unwrap();
        let guild_id = [221; 32];
        let checkpoint_hash = [222; 32];
        let revision = node
            .prepare_revision(guild_id, Uuid::from_bytes([1; 16]), &source, 1, None)
            .unwrap();
        assert!(!revision.value.data_sectors.is_empty());
        let manifest: mb_store::StableAnchorManifest = decode_canonical(
            &node
                .control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let parent = PinnedDirectory::open(&restore_parent).unwrap();
        let target_identity = parent
            .open_child_directory("restored")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap();
        let job = RecoveryJob {
            format_version: 7,
            guild_id,
            revision_id: revision.value.revision_id,
            target: target.canonicalize().unwrap(),
            staging: restore_parent.join(format!(".mutualbackup-restore-{}", Uuid::new_v4())),
            staged_native_id: Some(native_id_tuple(target_identity)),
            state: RecoveryJobState::Complete,
            parent_native_id: Some(native_id_tuple(parent.identity().unwrap())),
        };
        let job_bytes = canonical_bytes(&job).unwrap();
        node.control
            .put_record("recovery-job", &checkpoint_hash, &job_bytes)
            .unwrap();
        let location_hints = node.control.records("anchor-area-location").unwrap();

        fs::rename(&original_parent, &moved_parent).unwrap();
        node.control.make_query_only().unwrap();
        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();

        assert_eq!(
            node.control
                .get_record("recovery-job", &checkpoint_hash)
                .unwrap(),
            Some(job_bytes)
        );
        assert_eq!(
            node.control.records("anchor-area-location").unwrap(),
            location_hints
        );
        drop(node);
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_never_adopts_a_replaced_staging_identity() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path().join("node"), Seed::from_bytes([211; 32])).unwrap();
        let guild_id = [212; 32];
        let checkpoint_hash = [213; 32];
        let revision_id = Uuid::from_bytes([214; 16]);
        let revision = install_empty_recovery_revision(&mut node, guild_id, revision_id);
        let target = temp.path().join("restored");
        let staging = temp.path().join(format!(
            ".mutualbackup-restore-{}",
            Uuid::from_bytes([215; 16])
        ));
        fs::create_dir(&staging).unwrap();
        let original = PinnedDirectory::open(&staging).unwrap().identity().unwrap();
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let job = RecoveryJob {
            format_version: 7,
            guild_id,
            revision_id,
            target: temp.path().canonicalize().unwrap().join("restored"),
            staging: staging.clone(),
            staged_native_id: Some(native_id_tuple(original)),
            state: RecoveryJobState::Building,
            parent_native_id: Some(native_id_tuple(parent.identity().unwrap())),
        };
        node.control
            .put_record(
                "recovery-job",
                &checkpoint_hash,
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();
        let moved = temp.path().join("moved-staging");
        fs::rename(&staging, &moved).unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"must survive").unwrap();
        symlink(&external, &staging).unwrap();

        assert!(
            node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
                .is_err()
        );
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"must survive"
        );
        assert!(moved.is_dir());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_leaves_unbound_stage_after_pre_identity_interruption() {
        let temp = tempfile::tempdir().unwrap();
        let run_root = temp.path();
        let mut node = Node::open(run_root.join("node"), Seed::from_bytes([216; 32])).unwrap();
        let guild_id = [217; 32];
        let checkpoint_hash = [218; 32];
        let revision_id = Uuid::from_bytes([219; 16]);
        let revision = install_empty_recovery_revision(&mut node, guild_id, revision_id);
        let target = run_root.join("restored");

        INTERRUPT_AFTER_RECOVERY_STAGING_CREATE.with(|interrupt| interrupt.set(true));
        assert!(
            node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
                .is_err()
        );
        let bytes = node
            .control
            .get_record("recovery-job", &checkpoint_hash)
            .unwrap()
            .unwrap();
        let interrupted: RecoveryJob = decode_canonical(&bytes).unwrap();
        assert_eq!(interrupted.state, RecoveryJobState::Building);
        assert!(interrupted.staged_native_id.is_none());
        assert!(interrupted.staging.is_dir());
        fs::write(interrupted.staging.join("must-survive"), b"unbound staging").unwrap();

        node.restore_recovered_revision(&checkpoint_hash, guild_id, &revision, &target)
            .unwrap();
        assert!(target.is_dir());
        assert_eq!(
            fs::read(interrupted.staging.join("must-survive")).unwrap(),
            b"unbound staging"
        );
        let completed: RecoveryJob = decode_canonical(
            &node
                .control
                .get_record("recovery-job", &checkpoint_hash)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_ne!(completed.staging, interrupted.staging);
    }

    #[test]
    fn superseded_recovery_removes_only_its_owned_hidden_tree() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path().join("node"), Seed::from_bytes([117; 32])).unwrap();
        let target = temp.path().join("restored");
        let staging = temp.path().join(format!(
            ".mutualbackup-restore-{}",
            Uuid::from_bytes([118; 16])
        ));
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("partial"), b"partial restore").unwrap();
        let job = RecoveryJob {
            format_version: 7,
            guild_id: [121; 32],
            revision_id: Uuid::from_bytes([122; 16]),
            target: temp.path().canonicalize().unwrap().join("restored"),
            staging: staging.clone(),
            staged_native_id: Some(native_id_tuple(
                PinnedDirectory::open(&staging).unwrap().identity().unwrap(),
            )),
            state: RecoveryJobState::Building,
            parent_native_id: Some(native_id_tuple(
                PinnedDirectory::open(temp.path())
                    .unwrap()
                    .identity()
                    .unwrap(),
            )),
        };

        node.remove_superseded_recovery_job(&job).unwrap();

        assert!(!staging.exists());
        assert!(!target.exists());
    }

    #[test]
    fn superseded_recovery_leaves_an_unbound_hidden_tree() {
        let temp = tempfile::tempdir().unwrap();
        let mut node = Node::open(temp.path().join("node"), Seed::from_bytes([223; 32])).unwrap();
        let target = temp.path().join("restored");
        let staging = temp.path().join(format!(
            ".mutualbackup-restore-{}",
            Uuid::from_bytes([224; 16])
        ));
        fs::create_dir(&staging).unwrap();
        fs::write(staging.join("must-survive"), b"unbound staging").unwrap();
        let job = RecoveryJob {
            format_version: 7,
            guild_id: [225; 32],
            revision_id: Uuid::from_bytes([226; 16]),
            target: temp.path().canonicalize().unwrap().join("restored"),
            staging: staging.clone(),
            staged_native_id: None,
            state: RecoveryJobState::Building,
            parent_native_id: Some(native_id_tuple(
                PinnedDirectory::open(temp.path())
                    .unwrap()
                    .identity()
                    .unwrap(),
            )),
        };

        node.remove_superseded_recovery_job(&job).unwrap();

        assert_eq!(
            fs::read(staging.join("must-survive")).unwrap(),
            b"unbound staging"
        );
        assert!(!target.exists());
    }

    #[test]
    fn durable_recovery_attempt_rejects_superseded_work() {
        let temp = tempfile::tempdir().unwrap();
        let node = Node::open(temp.path(), Seed::from_bytes([123; 32])).unwrap();
        let guild_id = [124; 32];
        let checkpoint_hash = [125; 32];
        node.control
            .put_record(
                "recovery-attempt",
                b"active",
                &canonical_bytes(&RecoveryAttempt {
                    format_version: 1,
                    guild_id,
                    checkpoint_hash,
                    generation: 7,
                })
                .unwrap(),
            )
            .unwrap();

        node.require_active_recovery_attempt(guild_id, checkpoint_hash)
            .unwrap();
        assert!(
            node.require_active_recovery_attempt(guild_id, [126; 32])
                .is_err()
        );
        assert!(
            node.require_active_recovery_attempt([127; 32], checkpoint_hash)
                .is_err()
        );
    }

    #[test]
    fn checkpoint_reconciliation_prunes_invalid_existing_member_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let (seeds, checkpoint) = signed_recovery_checkpoint_fixture();
        let subject_seed = seeds[0].clone();
        let publisher_seed = seeds[1].clone();
        let mut node = Node::open(temp.path(), subject_seed).unwrap();
        let publisher_keys = KeyMaterial::from_seed(&publisher_seed);
        let publisher = publisher_keys.node_id();
        let provider = publisher.libp2p_peer_id().unwrap().to_string();
        let expires_at_unix_seconds = unix_seconds() + 300;
        let sequence = u64::MAX - 1;
        let bundle = SignedRecord::sign(
            b"mutualbackup/recovery-bundle/v1",
            RecoveryBundle {
                format_version: 1,
                subject: node.keys().node_id(),
                publisher,
                sequence,
                expires_at_unix_seconds,
                key_envelope: None,
                sealed: mb_core::SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [0; 32],
                    nonce: [0; 24],
                    ciphertext: vec![0; 64],
                },
            },
            &publisher_keys,
        )
        .unwrap();
        let bytes = canonical_bytes(&bundle).unwrap();
        let hash = *blake3::hash(&bytes).as_bytes();
        let state = DhtObservationState {
            format_version: 1,
            highest_sequence: sequence,
            hashes: vec![DhtObservedHash { sequence, hash }],
            current: DhtObservedRecord {
                sequence,
                hash,
                expires_at_unix_seconds,
                bytes,
            },
        };
        let record_id = recovery_observation_record_id(node.keys().node_id(), &provider);
        node.control
            .put_record(
                "dht-observed-recovery",
                &record_id,
                &canonical_bytes(&state).unwrap(),
            )
            .unwrap();

        node.retain_checkpoint_recovery_records(&checkpoint, Vec::new())
            .unwrap();

        assert!(
            node.control
                .get_record("dht-observed-recovery", &record_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn cold_recovery_pins_observations_against_the_certified_dynamic_state() {
        let temp = tempfile::tempdir().unwrap();
        let (seeds, mut checkpoint) = signed_recovery_checkpoint_fixture();
        let keys = seeds.iter().map(KeyMaterial::from_seed).collect::<Vec<_>>();
        checkpoint.checkpoint.format_version = 4;
        checkpoint.signatures.clear();
        for signer in &keys {
            checkpoint.add_signature(signer).unwrap();
        }
        checkpoint.verify().unwrap();

        let mut recovered_state = DynamicGuildState::new(
            checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.genesis_hash,
            QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Unanimous,
            },
            checkpoint.checkpoint.members.clone(),
        )
        .unwrap();
        let subject_keys = &keys[0];
        let publisher_keys = &keys[1];
        let (envelope, _) =
            mb_core::create_recovery_key_envelope(subject_keys, checkpoint.checkpoint.guild_id, 1)
                .unwrap();
        let event = GuildEvent {
            format_version: 1,
            guild_id: checkpoint.checkpoint.guild_id,
            sequence: 1,
            parent: recovered_state.event_head,
            kind: mb_core::GuildEventKind::RotateRecoveryKey {
                envelope: envelope.clone(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|signer| sign_guild_event(&event, signer).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        recovered_state
            .apply_event(&QuorumGuildEvent { event, signatures })
            .unwrap();

        let mut node = Node::open(temp.path(), seeds[0].clone()).unwrap();
        assert!(node.dynamic_guild_state().unwrap().is_none());
        let publisher = publisher_keys.node_id();
        let provider_peer_id = publisher.libp2p_peer_id().unwrap().to_string();
        let endpoint = format!("/ip4/127.0.0.1/udp/44000/quic-v1/p2p/{provider_peer_id}");
        let expires_at_unix_seconds = unix_seconds() + 300;
        let locator = SignedRecord::sign(
            RECOVERY_LOCATOR_DOMAIN,
            RecoveryLocator {
                format_version: 1,
                subject: subject_keys.node_id(),
                publisher,
                guild_id: checkpoint.checkpoint.guild_id,
                checkpoint_hash: checkpoint.hash().unwrap(),
                checkpoint_generation: checkpoint.checkpoint.generation,
                subject_endpoint_sequence_floor: 0,
                endpoints: vec![endpoint],
                expires_at_unix_seconds,
            },
            publisher_keys,
        )
        .unwrap();
        let bundle = SignedRecord::sign(
            b"mutualbackup/recovery-bundle/v1",
            RecoveryBundle {
                format_version: 2,
                subject: subject_keys.node_id(),
                publisher,
                sequence: 1,
                expires_at_unix_seconds,
                key_envelope: Some(envelope),
                sealed: seal_recovery_record(
                    recovered_state
                        .current_recovery_key(subject_keys.node_id())
                        .unwrap()
                        .envelope
                        .public_key,
                    &canonical_bytes(&locator).unwrap(),
                )
                .unwrap(),
            },
            publisher_keys,
        )
        .unwrap();
        let observation = CheckpointRecoveryObservation {
            provider_peer_id: provider_peer_id.clone(),
            selected: bundle,
            observations: Vec::new(),
        };

        assert!(
            node.pin_recovery_attempt(&checkpoint, vec![observation.clone()], None)
                .is_err()
        );
        node.pin_recovery_attempt(&checkpoint, vec![observation], Some(&recovered_state))
            .unwrap();
        assert!(node.active_recovery_attempt().unwrap().is_some());
        assert!(node.dynamic_guild_state().unwrap().is_none());
    }

    #[test]
    fn pinned_recovery_attempt_rejects_a_higher_signed_fork() {
        let temp = tempfile::tempdir().unwrap();
        let (seeds, checkpoint) = signed_recovery_checkpoint_fixture();
        let mut node = Node::open(temp.path(), seeds[0].clone()).unwrap();
        node.pin_recovery_attempt(&checkpoint, Vec::new(), None)
            .unwrap();

        let mut fork = checkpoint.checkpoint.clone();
        fork.generation = checkpoint.checkpoint.generation + 1;
        fork.parent = Some([201; 32]);
        let mut fork = QuorumCheckpoint {
            checkpoint: fork,
            signatures: Vec::new(),
        };
        for seed in &seeds {
            fork.add_signature(&KeyMaterial::from_seed(seed)).unwrap();
        }
        fork.verify().unwrap();
        assert!(node.pin_recovery_attempt(&fork, Vec::new(), None).is_err());
        assert_eq!(
            node.active_recovery_attempt().unwrap(),
            Some(RecoveryAttempt {
                format_version: 1,
                guild_id: checkpoint.checkpoint.guild_id,
                checkpoint_hash: checkpoint.hash().unwrap(),
                generation: checkpoint.checkpoint.generation,
            })
        );
    }

    #[test]
    fn rejected_recovery_attempt_does_not_reconcile_dht_observations() {
        let temp = tempfile::tempdir().unwrap();
        let (seeds, checkpoint) = signed_recovery_checkpoint_fixture();
        let mut node = Node::open(temp.path(), seeds[0].clone()).unwrap();
        let active = RecoveryAttempt {
            format_version: 1,
            guild_id: checkpoint.checkpoint.guild_id,
            checkpoint_hash: [142; 32],
            generation: checkpoint.checkpoint.generation + 1,
        };
        node.control
            .put_record(
                "recovery-attempt",
                b"active",
                &canonical_bytes(&active).unwrap(),
            )
            .unwrap();
        let stale_record_id = vec![143; 64];
        let stale_record = b"must survive rejected transition".to_vec();
        node.control
            .put_record("dht-observed-recovery", &stale_record_id, &stale_record)
            .unwrap();

        assert!(
            node.pin_recovery_attempt(&checkpoint, Vec::new(), None)
                .is_err()
        );

        assert_eq!(
            node.control
                .get_record("dht-observed-recovery", &stale_record_id)
                .unwrap(),
            Some(stale_record)
        );
        assert_eq!(node.active_recovery_attempt().unwrap(), Some(active));
    }
}
