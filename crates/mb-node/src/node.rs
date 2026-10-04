use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};

use mb_core::{
    CODING_ATTEMPT_PLAN_DOMAIN, CODING_CHALLENGE_COMMITMENT_DOMAIN, CODING_CHALLENGE_REVEAL_DOMAIN,
    CODING_FAILURE_REPORT_DOMAIN, CODING_ROOT_MANIFEST_DOMAIN, CODING_SHARD_OPENING_DOMAIN,
    CODING_TRANSCRIPT_DOMAIN, CodingAttemptPlan, CodingChallengeCommitment, CodingChallengeReveal,
    CodingFailureReport, CodingGroupV2, CodingReplayFinding, CodingRootManifest,
    CodingShardOpening, CodingVerificationTranscript, DynamicGuildState, EndpointRecord,
    GuildCheckpoint, GuildEvent, GuildEventTail, GuildGenesis, GuildInvite, KeyMaterial,
    LegacyCodingAddStatement, MAX_GUILD_EVENT_TAIL, Member, MemberSignature, NodeId, PackedCatalog,
    PackedSector, PackedSectorDescriptor, PackingProfile, PackingResult, PackingUpdate,
    QuorumCheckpoint, QuorumGuildEvent, QuorumGuildGenesis, QuorumLegacyCodingAddBinding,
    QuorumPolicy, QuorumRule, RECOVERY_LOCATOR_DOMAIN, RecoveryBundle, RecoveryLocator,
    STAGED_STORAGE_RECEIPT_DOMAIN, STORAGE_ACKNOWLEDGEMENT_DOMAIN, SectorId, SectorRef, Seed,
    ShardRole, ShardRoleV2, SignedRecord, StagedStorageReceipt, StorageAcknowledgement,
    USER_REVISION_DOMAIN, UserRevision, V1_CATALOG_PAGE_BYTES, V1_MAX_CATALOG_PAGES,
    V1_MAX_ENDPOINTS_PER_PEER, V1_SECTOR_SIZE, canonical_bytes, challenged_leaf,
    coding_challenge_commitment, coding_evidence_hash, decode_canonical, encode_coding_attempt,
    merkle_commit, merkle_open_range, merkle_open_zero_range, open_recovery_key_envelope,
    open_recovery_record, packing_protected_root, replay_coding_transcript, seal_recovery_record,
    sector_root, sign_guild_event, sign_legacy_coding_add_binding, synthetic_filler_sector,
    verify_guild_event_signature,
};
use mb_git::{
    GitBranchInfo, GitCommitInfo, GitDiff, GitLogEntry, GitPruneReport, GitPruneRoots,
    GitRemoteBranchInfo, GitRepository, GitStatus, GitTagInfo, GitWorktreeInfo,
};
use mb_store::{
    ControlStore, DatabaseError, NativeFileId, ParityObject, ParityStore, PinnedDirectory,
    SourceBackendBinding, SourceBackendKind, VariableParityObject, filesystem_identity,
};
#[cfg(target_os = "linux")]
use mb_store::{GuardedStoppedCaptureV1, GuardedViewMount};
use rand::RngCore;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::control::{GitRepositoryInfo, GitStagedFile, NodeStatus, ProtectedRoot};
use crate::snapshot::{
    WriterCredentials, abandon_recovered_anchor_capture, build_revision_restore,
    git_prune_capture_pending, git_prune_recipe_anchor_ids, install_inline_recipe,
    install_recovered_sector_recipe, make_restore_root_private_at, prepare_revision,
    publish_owned_restore, reanchor_recovered_revision, reconcile_pending_captures,
    recovered_recipe_is_stable, render_sector, restore_revision_from_source,
    restore_signed_root_metadata_at, resume_restore_publication, retire_revision_anchor,
    revision_git_backup, revision_head_id,
};
use crate::volume::{StorageScrubReport, StorageVolumes, VolumeReaderConfig, open_control_store};

type ControlRecord = (String, Vec<u8>, Vec<u8>);

type LegacyPackingAttestationEntries =
    BTreeMap<(NodeId, [u8; 32], SectorId), Vec<SignedRecord<mb_core::LegacyPackingAttestation>>>;

#[derive(Default)]
pub(crate) struct LegacyPackingAttestationIndex {
    entries: LegacyPackingAttestationEntries,
    pub(crate) scan: LegacyPackingAttestationScan,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct LegacyPackingAttestationScan {
    pub(crate) rows_read: usize,
    pub(crate) signatures_verified: usize,
    pub(crate) retained_records: usize,
    pub(crate) retained_encoded_bytes: usize,
    pub(crate) largest_row_bytes: usize,
    pub(crate) peak_journal_payload_bytes: usize,
}

impl std::ops::Deref for LegacyPackingAttestationIndex {
    type Target = LegacyPackingAttestationEntries;

    fn deref(&self) -> &Self::Target {
        &self.entries
    }
}

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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CodingHolderCleanupObligation {
    pub format_version: u16,
    pub plan: SignedRecord<CodingAttemptPlan>,
    pub holder: NodeId,
}

fn coding_holder_cleanup_id(obligation: &CodingHolderCleanupObligation) -> Vec<u8> {
    let mut id = Vec::with_capacity(48);
    id.extend_from_slice(&obligation.plan.value.attempt_id);
    id.extend_from_slice(&obligation.holder.0);
    id
}

enum CodingLaunchRenewalCandidate {
    Launch(CodingLaunchJob),
    Retry(SignedRecord<CodingAttemptPlan>),
    Activation {
        plan: SignedRecord<CodingAttemptPlan>,
        pending: bool,
    },
}

impl CodingLaunchRenewalCandidate {
    fn plan(&self) -> &SignedRecord<CodingAttemptPlan> {
        match self {
            Self::Launch(job) => &job.plan,
            Self::Retry(plan) | Self::Activation { plan, .. } => plan,
        }
    }

    fn needs_input_intent(&self) -> bool {
        !matches!(self, Self::Activation { pending: false, .. })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct VerifiedCodingTranscript(SignedRecord<CodingVerificationTranscript>);

impl VerifiedCodingTranscript {
    pub(crate) fn verify(transcript: SignedRecord<CodingVerificationTranscript>) -> Result<Self> {
        if replay_coding_transcript(&transcript)? != CodingReplayFinding::Verified {
            anyhow::bail!("coding transcript does not verify the delegated codeword");
        }
        Ok(Self(transcript))
    }

    pub(crate) fn into_inner(self) -> SignedRecord<CodingVerificationTranscript> {
        self.0
    }

    pub(crate) fn canonical_hash(&self) -> Result<[u8; 32]> {
        Ok(*blake3::hash(&canonical_bytes(&self.0)?).as_bytes())
    }
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

fn same_coding_lane_attempt(left: &CodingAttemptPlan, right: &CodingAttemptPlan) -> bool {
    left.attempt_id == right.attempt_id && same_coding_lane(left, right)
}

fn same_coding_lane(left: &CodingAttemptPlan, right: &CodingAttemptPlan) -> bool {
    left.membership_epoch == right.membership_epoch && same_coding_lane_geometry(left, right)
}

fn same_coding_lane_geometry(left: &CodingAttemptPlan, right: &CodingAttemptPlan) -> bool {
    left.format_version == right.format_version
        && left.checkpoint_hash == right.checkpoint_hash
        && left.geometry == right.geometry
        && left.delegator == right.delegator
        && left.information_roots == right.information_roots
}

fn coding_renewal_can_follow(prior: &CodingAttemptPlan, candidate: &CodingAttemptPlan) -> bool {
    prior.membership_epoch == candidate.membership_epoch
        && (prior.format_version == candidate.format_version
            || prior.format_version == 2 && candidate.format_version == 3)
        && prior.checkpoint_hash == candidate.checkpoint_hash
        && prior.geometry == candidate.geometry
        && prior.delegator == candidate.delegator
        && prior.information_roots == candidate.information_roots
}

fn coding_renewal_can_follow_with_new_parity(
    prior: &CodingAttemptPlan,
    candidate: &CodingAttemptPlan,
) -> bool {
    coding_renewal_can_follow(prior, candidate)
        || prior.membership_epoch == candidate.membership_epoch
            && (prior.format_version == candidate.format_version
                || prior.format_version == 2 && candidate.format_version == 3)
            && prior.checkpoint_hash == candidate.checkpoint_hash
            && prior.delegator == candidate.delegator
            && prior.information_roots == candidate.information_roots
            && prior.geometry.format_version == candidate.geometry.format_version
            && prior.geometry.guild_id == candidate.geometry.guild_id
            && prior.geometry.profile == candidate.geometry.profile
            && prior.geometry.information == candidate.geometry.information
            && prior.geometry.parity != candidate.geometry.parity
}

fn same_coding_source_lane(left: &CodingAttemptPlan, right: &CodingAttemptPlan) -> bool {
    left.checkpoint_hash == right.checkpoint_hash
        && left.membership_epoch == right.membership_epoch
        && left.delegator == right.delegator
        && left.information_roots == right.information_roots
        && left.geometry.format_version == right.geometry.format_version
        && left.geometry.guild_id == right.geometry.guild_id
        && left.geometry.profile == right.geometry.profile
        && left.geometry.information == right.geometry.information
}

fn choose_usable_parity_geometry(
    original: &mb_core::CodingPlanGeometry,
    eligible: &[&Member],
    mut accepts: impl FnMut(&mb_core::CodingPlanGeometry) -> Result<bool>,
) -> Result<Option<mb_core::CodingPlanGeometry>> {
    const MAX_PARITY_REPLAN_CANDIDATES: usize = 131_072;
    let mut pending = vec![(0, original.clone())];
    let mut best: Option<(usize, Vec<NodeId>, mb_core::CodingPlanGeometry)> = None;
    let mut visited = 0;
    while let Some((row, geometry)) = pending.pop() {
        if row == original.parity.len() {
            visited += 1;
            if visited > MAX_PARITY_REPLAN_CANDIDATES {
                break;
            }
            if geometry.validate().is_err() || !accepts(&geometry)? {
                continue;
            }
            let changed = geometry
                .parity
                .iter()
                .zip(&original.parity)
                .filter(|(new, old)| *new != *old)
                .count();
            if changed == 0 {
                return Ok(Some(geometry));
            }
            let holders = geometry.parity.iter().map(|role| role.holder).collect();
            if best
                .as_ref()
                .is_none_or(|(prior_changed, prior_holders, _)| {
                    (changed, &holders) < (*prior_changed, prior_holders)
                })
            {
                best = Some((changed, holders, geometry));
            }
            continue;
        }
        for member in eligible {
            if original
                .information
                .iter()
                .any(|role| role.failure_domain == member.failure_domain)
                || geometry.parity[..row]
                    .iter()
                    .any(|role| role.failure_domain == member.failure_domain)
            {
                continue;
            }
            let mut candidate = geometry.clone();
            candidate.parity[row].holder = member.node_id;
            candidate.parity[row].failure_domain = member.failure_domain.clone();
            pending.push((row + 1, candidate));
        }
    }
    Ok(best.map(|(_, _, geometry)| geometry))
}

fn validate_checkpoint_for_signature(checkpoint: &GuildCheckpoint) -> Result<()> {
    if checkpoint.format_version == 7
        && checkpoint
            .packing_catalog
            .as_ref()
            .is_none_or(|catalog| !matches!(catalog.format_version, 3..=5))
    {
        anyhow::bail!("new format-seven checkpoints require root-bound authenticated catalogs");
    }
    Ok(())
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

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub(crate) struct CheckpointCatchupState {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub base_generation: u64,
    pub base_hash: [u8; 32],
    pub target_generation: u64,
    pub target_hash: [u8; 32],
    pub cursor_generation: u64,
    pub cursor_hash: [u8; 32],
    pub ready_to_install: bool,
}

const CHECKPOINT_CATCHUP_STATE_KIND: &str = "checkpoint-catchup-state";
const CHECKPOINT_CATCHUP_GENERATION_KIND: &str = "checkpoint-catchup-generation";
const CHECKPOINT_CATCHUP_SOURCE_KIND: &str = "checkpoint-catchup-source";
const CHECKPOINT_LEGACY_EPOCH_KIND: &str = "guild-checkpoint-legacy-epoch";

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
struct PendingGuildEventSignatures {
    format_version: u16,
    event: GuildEvent,
    signatures: Vec<MemberSignature>,
}

fn pending_guild_event_signatures_id(event: &GuildEvent) -> [u8; 40] {
    let mut id = [0_u8; 40];
    id[..32].copy_from_slice(&event.guild_id);
    id[32..].copy_from_slice(&event.sequence.to_be_bytes());
    id
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct LegacyCodingAddSignatureLock {
    format_version: u16,
    statement: LegacyCodingAddStatement,
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
    #[serde(default)]
    in_flight_root_id: Option<Uuid>,
    retry_at_unix_seconds: Option<u64>,
    blocked_reason: Option<String>,
    #[serde(default)]
    root_retries: Vec<AutomaticRootRetry>,
    #[serde(default)]
    root_schedules: Vec<AutomaticRootSchedule>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutomaticRootRetry {
    protected_root_id: Uuid,
    retry_at_unix_seconds: u64,
    reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct AutomaticRootSchedule {
    protected_root_id: Uuid,
    dirty_since_unix_seconds: u64,
    last_attempt_unix_seconds: Option<u64>,
}

pub(crate) enum AutomaticBackupPoll {
    Idle,
    InFlight(Uuid),
    Start {
        protected_root_id: Uuid,
        estimated_bytes: u64,
    },
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
    #[cfg(target_os = "linux")]
    guarded_mounts: Vec<GuardedViewMount>,
    control: ControlStore,
    control_database_key: [u8; 32],
    volumes: StorageVolumes,
    volume_readers: Arc<RwLock<Vec<VolumeReaderConfig>>>,
    membership_history_cache: Mutex<Option<MembershipHistoryCache>>,
}

struct MembershipHistoryCache {
    durable: DynamicGuildState,
    by_epoch: BTreeMap<u64, DynamicGuildState>,
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

    pub(crate) fn legacy_coding_add_binding(
        &self,
        guild_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
    ) -> Result<Option<QuorumLegacyCodingAddBinding>> {
        legacy_coding_add_binding_from_store(&self.control, guild_id, event_sequence, event_hash)
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

    pub(crate) fn coding_transcript_for_event(
        &self,
        guild_id: [u8; 32],
        group_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
    ) -> Result<SignedRecord<CodingVerificationTranscript>> {
        coding_transcript_for_event_from_store(
            &self.control,
            guild_id,
            group_id,
            event_sequence,
            event_hash,
        )
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

    pub(crate) fn sign_legacy_packing_binding(
        &self,
        guild_id: &[u8; 32],
        protected_root_id: Uuid,
        reference: &SectorRef,
    ) -> Result<SignedRecord<mb_core::LegacyPackingBinding>> {
        let bytes = self.sector_for_guild(guild_id, &reference.id)?;
        sign_legacy_packing_binding(&self.keys, protected_root_id, reference, &bytes)
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

    pub(crate) fn checkpoint_head(&self, guild_id: &[u8; 32]) -> Result<Option<(u64, [u8; 32])>> {
        Ok(self
            .control
            .checkpoint_head(guild_id)?
            .map(|(generation, hash, _)| (generation, hash)))
    }

    pub(crate) fn checkpoint_at_generation(
        &self,
        guild_id: &[u8; 32],
        generation: u64,
    ) -> Result<Option<[u8; 32]>> {
        checkpoint_at_generation(&self.control, guild_id, generation)
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
        #[cfg(target_os = "linux")]
        let guarded_mounts = if GuardedViewMount::has_claims(&control)? {
            GuardedViewMount::recover_all_claimed(Arc::new(Mutex::new(
                ControlStore::open_with_key(data_dir.join("control.db"), &control_database_key)?,
            )))?
        } else {
            Vec::new()
        };
        let mut node = Self {
            data_dir,
            _data_dir_lock: locked,
            keys,
            #[cfg(target_os = "linux")]
            guarded_mounts,
            control,
            control_database_key,
            volumes,
            volume_readers,
            membership_history_cache: Mutex::new(None),
        };
        node.backfill_checkpoint_generation_index()?;
        node.reconcile_certified_writer_head()?;
        node.reconcile_garbage_collection()?;
        Ok(node)
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// A failed guarded worker or missing mount is fatal for a protected
    /// worktree: the private lower root must never become its fallback path.
    pub fn check_guarded_mounts(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            let claimed = GuardedViewMount::claimed_anchor_ids(&self.control)?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let mounted = self
                .guarded_mounts
                .iter()
                .map(GuardedViewMount::anchor_id)
                .collect::<BTreeSet<_>>();
            if claimed != mounted || mounted.len() != self.guarded_mounts.len() {
                anyhow::bail!("daemon is not supervising every claimed guarded view");
            }
            for mount in &self.guarded_mounts {
                mount.check_health()?;
            }
        }
        Ok(())
    }

    /// Stop the owned FUSE view, freeze a durable revision attempt, and only
    /// then remount it. Any failure leaves the claim unsupervised and the
    /// daemon health check fails closed; startup finishes a prepared attempt
    /// before recovering that mount.
    #[cfg(target_os = "linux")]
    #[allow(dead_code)] // Called by the guarded signed-revision path once its private format lands.
    pub(crate) fn capture_claimed_guarded_view_for_revision(
        &mut self,
        anchor_id: Uuid,
        revision_id: Uuid,
    ) -> Result<GuardedStoppedCaptureV1> {
        self.check_guarded_mounts()?;
        let index = self
            .guarded_mounts
            .iter()
            .position(|mount| mount.anchor_id() == anchor_id)
            .context("daemon does not own the requested guarded view")?;
        let mount = self.guarded_mounts.swap_remove(index);
        mount
            .stop()
            .context("stop guarded view before revision capture")?;
        let control = Arc::new(Mutex::new(ControlStore::open_with_key(
            self.data_dir.join("control.db"),
            &self.control_database_key,
        )?));
        let capture = GuardedViewMount::capture_stopped_view_for_attempt(
            anchor_id,
            revision_id,
            Arc::clone(&control),
        )?;
        let mount = GuardedViewMount::recover_claimed(anchor_id, control)?;
        mount.check_health()?;
        self.guarded_mounts.push(mount);
        Ok(capture)
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

    fn source_backend_for_root(
        &self,
        root: &ProtectedRoot,
        filesystem: mb_store::FilesystemIdentity,
    ) -> Result<SourceBackendBinding> {
        let expected = SourceBackendBinding::reflink_v1(
            root.root_id,
            filesystem.stable_id,
            root.root_inode,
            filesystem.mount_id,
        );
        let existing = self
            .control
            .get_record("source-backend", root.root_id.as_bytes())?
            .map(|bytes| decode_canonical::<SourceBackendBinding>(&bytes))
            .transpose()?;
        if let Some(binding) = &existing {
            if !binding.is_supported_for(root.root_id, filesystem.stable_id, root.root_inode) {
                anyhow::bail!("protected root has an incompatible source backend binding");
            }
            if binding.mount_id == filesystem.mount_id {
                return Ok(binding.clone());
            }
        }
        SourceBackendKind::ReflinkV1
            .probe(&root.path)
            .context("protected root failed the reflink COW probe")?;
        if filesystem_identity(&root.path)? != filesystem {
            anyhow::bail!("protected root mount changed during backend probe");
        }
        let encoded = canonical_bytes(&expected)?;
        if existing.is_some() {
            self.control
                .put_record("source-backend", root.root_id.as_bytes(), &encoded)?;
        } else if !self.control.put_record_if_absent(
            "source-backend",
            root.root_id.as_bytes(),
            &encoded,
        )? {
            anyhow::bail!("protected root backend binding changed concurrently");
        }
        Ok(expected)
    }

    pub fn add_protected_root(&mut self, source_root: &Path) -> Result<ProtectedRoot> {
        self.register_protected_root(source_root, None, true, true)
    }

    fn git_catalog_key(&self, repository_id: Uuid) -> [u8; 32] {
        mb_git::catalog_key(&self.keys, repository_id)
    }

    pub fn git_init(&mut self, source_root: &Path) -> Result<GitRepositoryInfo> {
        let source_root = source_root
            .canonicalize()
            .with_context(|| format!("cannot resolve Git root {}", source_root.display()))?;
        if fs::symlink_metadata(source_root.join(".git")).is_ok() {
            anyhow::bail!("ordinary .git storage already exists; use an explicit import path");
        }
        let root = self.add_protected_root(&source_root)?;
        let backend = self.source_backend_for_root(&root, filesystem_identity(&root.path)?)?;
        let key = self.git_catalog_key(root.root_id);
        let repository =
            GitRepository::init_with_backend(&root.path, root.root_id, &key, backend.backend)?;
        if repository.id() != root.root_id {
            anyhow::bail!("Git catalog does not match the protected root");
        }
        let info = GitRepositoryInfo {
            format_version: 1,
            repository_id: root.root_id,
            path: root.path,
        };
        if let Some(encoded) = self
            .control
            .get_record("git-repository", info.repository_id.as_bytes())?
        {
            let existing: GitRepositoryInfo = decode_canonical(&encoded)?;
            if existing != info {
                anyhow::bail!("Git repository registration conflicts with its protected root");
            }
        } else {
            self.control.put_record_if_absent(
                "git-repository",
                info.repository_id.as_bytes(),
                &canonical_bytes(&info)?,
            )?;
        }
        Ok(info)
    }

    fn open_git_repository(&self, repository_id: Uuid) -> Result<GitRepository> {
        self.open_git_repository_with_policy(repository_id, None)
    }

    fn open_git_repository_with_policy(
        &self,
        repository_id: Uuid,
        prune_missing: Option<(Uuid, bool)>,
    ) -> Result<GitRepository> {
        let encoded = self
            .control
            .get_record("git-repository", repository_id.as_bytes())?
            .context("Git repository is not registered with this daemon")?;
        let info: GitRepositoryInfo = decode_canonical(&encoded)?;
        let root = self.protected_root_by_id(repository_id)?;
        if info.format_version != 1 || info.repository_id != repository_id || info.path != root.path
        {
            anyhow::bail!("Git repository registration is invalid");
        }
        let metadata = fs::symlink_metadata(&root.path)?;
        #[cfg(unix)]
        let root_inode = {
            use std::os::unix::fs::MetadataExt;
            metadata.ino()
        };
        #[cfg(not(unix))]
        let root_inode = 0;
        let filesystem = filesystem_identity(&root.path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !root.matches_identity(filesystem, root_inode)
        {
            anyhow::bail!("protected Git root identity changed");
        }
        let backend = self.source_backend_for_root(&root, filesystem)?;
        let key = self.git_catalog_key(repository_id);
        let repository = if let Some((worktree_id, force)) = prune_missing {
            GitRepository::open_with_backend_for_missing_worktree_prune(
                &root.path,
                repository_id,
                &key,
                backend.backend,
                worktree_id,
                force,
            )?
        } else {
            GitRepository::open_with_backend(&root.path, repository_id, &key, backend.backend)?
        };
        Ok(repository)
    }

    pub fn git_add_worktree(
        &self,
        repository_id: Uuid,
        path: &Path,
        branch: &str,
    ) -> Result<GitWorktreeInfo> {
        self.open_git_repository(repository_id)?
            .add_linked_worktree(path, branch)
            .map_err(Into::into)
    }

    pub fn git_worktrees(&self, repository_id: Uuid) -> Result<Vec<GitWorktreeInfo>> {
        self.open_git_repository(repository_id)?
            .linked_worktrees()
            .map_err(Into::into)
    }

    pub fn git_resume_worktree(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
    ) -> Result<GitWorktreeInfo> {
        self.open_git_repository(repository_id)?
            .resume_linked_worktree(worktree_id)
            .map_err(Into::into)
    }

    pub fn git_prune_missing_worktree(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        force: bool,
    ) -> Result<GitWorktreeInfo> {
        self.open_git_repository_with_policy(repository_id, Some((worktree_id, force)))?
            .prune_missing_linked_worktree(worktree_id, force)
            .map_err(Into::into)
    }

    pub fn git_remove_worktree(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
    ) -> Result<GitWorktreeInfo> {
        self.open_git_repository(repository_id)?
            .remove_linked_worktree(worktree_id)
            .map_err(Into::into)
    }

    pub fn git_worktree_status(&self, repository_id: Uuid, worktree_id: Uuid) -> Result<GitStatus> {
        let repository = self.open_git_repository(repository_id)?;
        let mut status = repository.linked_status(worktree_id)?;
        status.history_backed_up = self.git_history_backed_up(repository_id, &repository)?;
        Ok(status)
    }

    pub fn git_worktree_add_path(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        path: &Path,
    ) -> Result<Option<GitStagedFile>> {
        let repository = self.open_git_repository(repository_id)?;
        Ok(repository
            .linked_add_path(worktree_id, path)?
            .map(|entry| GitStagedFile {
                format_version: 1,
                repository_id,
                path: path.to_path_buf(),
                oid: hex::encode(entry.oid),
                mode: entry.mode,
            }))
    }

    pub fn git_worktree_remove_cached(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        path: &Path,
    ) -> Result<bool> {
        self.open_git_repository(repository_id)?
            .linked_remove_cached(worktree_id, path)
            .map_err(Into::into)
    }

    pub fn git_worktree_remove_tracked(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        path: &Path,
    ) -> Result<bool> {
        self.open_git_repository(repository_id)?
            .linked_remove_tracked(worktree_id, path)
            .map_err(Into::into)
    }

    pub fn git_worktree_abandon_pending_add(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        path: &Path,
    ) -> Result<bool> {
        self.open_git_repository(repository_id)?
            .linked_abandon_pending_stage(worktree_id, path)
            .map_err(Into::into)
    }

    pub fn git_worktree_commit(
        &mut self,
        repository_id: Uuid,
        worktree_id: Uuid,
        author_name: &str,
        author_email: &str,
        message: &str,
    ) -> Result<GitCommitInfo> {
        self.mark_root_dirty(repository_id, "linked Git history changed")?;
        self.open_git_repository(repository_id)?
            .linked_commit(worktree_id, author_name, author_email, message)
            .map_err(Into::into)
    }

    pub fn git_worktree_log(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        limit: usize,
    ) -> Result<Vec<GitLogEntry>> {
        self.open_git_repository(repository_id)?
            .linked_log(worktree_id, limit)
            .map_err(Into::into)
    }

    pub fn git_worktree_branches(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
    ) -> Result<Vec<GitBranchInfo>> {
        self.open_git_repository(repository_id)?
            .linked_branches(worktree_id)
            .map_err(Into::into)
    }

    pub fn git_worktree_reset_index(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        paths: &[PathBuf],
    ) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .linked_reset_index(worktree_id, paths)
            .map_err(Into::into)
    }

    pub fn git_worktree_restore(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        paths: &[PathBuf],
    ) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .linked_restore_worktree(worktree_id, paths)
            .map_err(Into::into)
    }

    pub fn git_worktree_restore_both(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        paths: &[PathBuf],
    ) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .linked_restore_both(worktree_id, paths)
            .map_err(Into::into)
    }

    pub fn git_worktree_hard_reset(&self, repository_id: Uuid, worktree_id: Uuid) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .linked_hard_reset(worktree_id)
            .map_err(Into::into)
    }

    pub fn git_worktree_create_branch(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        name: &str,
    ) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .linked_create_branch(worktree_id, name)
            .map_err(Into::into)
    }

    pub fn git_worktree_create_branch_from(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        name: &str,
        start_point: &str,
    ) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .linked_create_branch_from(worktree_id, name, start_point)
            .map_err(Into::into)
    }

    pub fn git_worktree_delete_branch(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        name: &str,
        force: bool,
    ) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .linked_delete_branch(worktree_id, name, force)
            .map_err(Into::into)
    }

    pub fn git_worktree_diff(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        cached: bool,
    ) -> Result<GitDiff> {
        self.open_git_repository(repository_id)?
            .linked_diff(worktree_id, cached)
            .map_err(Into::into)
    }

    pub fn git_worktree_switch_branch(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        name: &str,
    ) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .linked_switch_branch(worktree_id, name)
            .map_err(Into::into)
    }

    pub fn git_add(&mut self, repository_id: Uuid, path: &Path) -> Result<GitStagedFile> {
        let repository = self.open_git_repository(repository_id)?;
        repository.resume_pending_stages()?;
        let entry = repository.stage_file(path)?;
        Ok(GitStagedFile {
            format_version: 1,
            repository_id,
            path: path.to_path_buf(),
            oid: hex::encode(entry.oid),
            mode: entry.mode,
        })
    }

    pub fn git_add_path(
        &mut self,
        repository_id: Uuid,
        path: &Path,
    ) -> Result<Option<GitStagedFile>> {
        let repository = self.open_git_repository(repository_id)?;
        repository.resume_pending_stages()?;
        Ok(repository.add_path(path)?.map(|entry| GitStagedFile {
            format_version: 1,
            repository_id,
            path: path.to_path_buf(),
            oid: hex::encode(entry.oid),
            mode: entry.mode,
        }))
    }

    pub fn git_remove_cached(&self, repository_id: Uuid, path: &Path) -> Result<bool> {
        Ok(self
            .open_git_repository(repository_id)?
            .remove_cached(path)?)
    }

    pub fn git_remove_tracked(&self, repository_id: Uuid, path: &Path) -> Result<bool> {
        Ok(self
            .open_git_repository(repository_id)?
            .remove_tracked(path)?)
    }

    pub fn git_abandon_pending_add(&self, repository_id: Uuid, path: &Path) -> Result<bool> {
        Ok(self
            .open_git_repository(repository_id)?
            .abandon_pending_stage(path)?)
    }

    pub fn git_commit(
        &mut self,
        repository_id: Uuid,
        author_name: &str,
        author_email: &str,
        message: &str,
    ) -> Result<GitCommitInfo> {
        self.mark_root_dirty(repository_id, "Git history changed")?;
        let repository = self.open_git_repository(repository_id)?;
        repository.resume_pending_stages()?;
        Ok(repository.commit(author_name, author_email, message)?)
    }

    pub fn git_log(&self, repository_id: Uuid, limit: usize) -> Result<Vec<GitLogEntry>> {
        self.open_git_repository(repository_id)?
            .log(limit)
            .map_err(Into::into)
    }

    pub fn git_branches(&self, repository_id: Uuid) -> Result<Vec<GitBranchInfo>> {
        self.open_git_repository(repository_id)?
            .branches()
            .map_err(Into::into)
    }

    pub fn git_tags(&self, repository_id: Uuid) -> Result<Vec<GitTagInfo>> {
        self.open_git_repository(repository_id)?
            .tags()
            .map_err(Into::into)
    }

    pub fn git_create_tag(
        &mut self,
        repository_id: Uuid,
        worktree_id: Option<Uuid>,
        name: &str,
        start_point: Option<&str>,
    ) -> Result<GitTagInfo> {
        self.mark_root_dirty(repository_id, "Git tag changed")?;
        let repository = self.open_git_repository(repository_id)?;
        match worktree_id {
            Some(worktree_id) => repository
                .linked_create_tag(worktree_id, name, start_point)
                .map_err(Into::into),
            None => repository.create_tag(name, start_point).map_err(Into::into),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn git_create_annotated_tag(
        &mut self,
        repository_id: Uuid,
        worktree_id: Option<Uuid>,
        name: &str,
        start_point: Option<&str>,
        tagger_name: &str,
        tagger_email: &str,
        message: &str,
    ) -> Result<GitTagInfo> {
        self.mark_root_dirty(repository_id, "Git tag changed")?;
        let repository = self.open_git_repository(repository_id)?;
        match worktree_id {
            Some(worktree_id) => repository
                .linked_create_annotated_tag(
                    worktree_id,
                    name,
                    start_point,
                    tagger_name,
                    tagger_email,
                    message,
                )
                .map_err(Into::into),
            None => repository
                .create_annotated_tag(name, start_point, tagger_name, tagger_email, message)
                .map_err(Into::into),
        }
    }

    pub fn git_delete_tag(&mut self, repository_id: Uuid, name: &str) -> Result<GitTagInfo> {
        self.mark_root_dirty(repository_id, "Git tag changed")?;
        self.open_git_repository(repository_id)?
            .delete_tag(name)
            .map_err(Into::into)
    }

    pub fn git_export_to_git_repository(
        &self,
        repository_id: Uuid,
        source_root: &Path,
        destination: &Path,
        advertised: &[GitBranchInfo],
    ) -> Result<u32> {
        let repository = self.open_git_repository(repository_id)?;
        if repository.root() != source_root {
            anyhow::bail!("Git remote root differs from its enrolled repository");
        }
        repository
            .export_to_git_repository(destination, advertised)
            .map_err(Into::into)
    }

    pub fn git_export_to_git_repository_with_tags(
        &self,
        repository_id: Uuid,
        source_root: &Path,
        destination: &Path,
        advertised_branches: &[GitBranchInfo],
        advertised_tags: &[GitTagInfo],
    ) -> Result<u32> {
        let repository = self.open_git_repository(repository_id)?;
        if repository.root() != source_root {
            anyhow::bail!("Git remote root differs from its enrolled repository");
        }
        repository
            .export_to_git_repository_with_tags(destination, advertised_branches, advertised_tags)
            .map_err(Into::into)
    }

    pub fn git_receive_pushed_branch(
        &mut self,
        repository_id: Uuid,
        source_root: &Path,
        source_git_directory: &Path,
        target_branch: &str,
        target_oid: [u8; 20],
        expected_old: Option<[u8; 20]>,
    ) -> Result<()> {
        let repository = self.open_git_repository(repository_id)?;
        if repository.root() != source_root {
            anyhow::bail!("Git remote root differs from its enrolled repository");
        }
        self.mark_root_dirty(repository_id, "Git history changed by stock Git push")?;
        repository
            .receive_pushed_branch(
                source_git_directory,
                target_branch,
                target_oid,
                expected_old,
            )
            .map_err(Into::into)
    }

    pub fn git_receive_pushed_tag(
        &mut self,
        repository_id: Uuid,
        source_root: &Path,
        source_git_directory: &Path,
        target_tag: &str,
        target_oid: [u8; 20],
        expected_old: Option<[u8; 20]>,
    ) -> Result<()> {
        let repository = self.open_git_repository(repository_id)?;
        if repository.root() != source_root {
            anyhow::bail!("Git remote root differs from its enrolled repository");
        }
        self.mark_root_dirty(repository_id, "Git tag changed by stock Git push")?;
        repository
            .receive_pushed_tag(source_git_directory, target_tag, target_oid, expected_old)
            .map_err(Into::into)
    }

    pub fn git_remote_branches(&self, repository_id: Uuid) -> Result<Vec<GitRemoteBranchInfo>> {
        self.open_git_repository(repository_id)?
            .remote_branches()
            .map_err(Into::into)
    }

    pub fn git_commit_pins(&self, repository_id: Uuid) -> Result<Vec<[u8; 20]>> {
        self.open_git_repository(repository_id)?
            .commit_pins()
            .map_err(Into::into)
    }

    pub fn git_pin_commit(&self, repository_id: Uuid, oid: [u8; 20]) -> Result<()> {
        self.open_git_repository(repository_id)?
            .pin_commit(git2::Oid::from_bytes(&oid)?)
            .map_err(Into::into)
    }

    pub fn git_unpin_commit(&self, repository_id: Uuid, oid: [u8; 20]) -> Result<()> {
        self.open_git_repository(repository_id)?
            .unpin_commit(git2::Oid::from_bytes(&oid)?)
            .map_err(Into::into)
    }

    pub fn git_prune(&mut self, repository_id: Uuid) -> Result<GitPruneReport> {
        self.reconcile_garbage_collection()?;
        for kind in ["gc-anchor", "gc-revision", "gc-sector"] {
            if !self.control.records(kind)?.is_empty() {
                anyhow::bail!("retained revision cleanup is unfinished; Git prune must wait");
            }
        }
        let root = self.protected_root_by_id(repository_id)?;
        if git_prune_capture_pending(&self.control, repository_id, &root.path)?
            || !self.control.records("restore-job")?.is_empty()
        {
            anyhow::bail!("a source capture or restore is in progress; Git prune must wait");
        }
        for (_, bytes) in self.control.records("backup-job")? {
            let job: BackupJob = decode_canonical(&bytes)?;
            validate_backup_descriptor(&job.descriptor)?;
            if job.format_version != 1 {
                anyhow::bail!("durable backup job is invalid");
            }
            if job.descriptor.protected_root_id == repository_id
                && job.state != BackupJobState::Committed
            {
                anyhow::bail!("a Git backup job is unfinished; prune must wait");
            }
        }
        let mut protected = GitPruneRoots::default();
        let mut include_revision = |revision: &SignedRecord<UserRevision>| -> Result<()> {
            if revision.value.protected_root_id != repository_id
                || revision.value.owner != self.keys.node_id()
            {
                return Ok(());
            }
            revision.verify(USER_REVISION_DOMAIN)?;
            revision.value.verify_writer()?;
            if let Some(graph) =
                revision_git_backup(&self.control, &self.keys, revision.value.guild_id, revision)?
            {
                if graph.repository_id != repository_id {
                    anyhow::bail!("retained Git backup belongs to another repository");
                }
                protected
                    .metadata_oids
                    .extend(graph.objects.iter().map(|object| object.oid));
                protected
                    .blob_oids
                    .extend(graph.blobs.iter().map(|blob| blob.oid));
            }
            Ok(())
        };
        for (id, bytes) in self.control.records("user-revision")? {
            let revision: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
            if id != revision.value.revision_id.as_bytes() {
                anyhow::bail!("durable user revision ID is invalid");
            }
            include_revision(&revision)?;
        }
        if let Some(installed) = self.installed_guild()?
            && let Some(checkpoint) =
                self.current_checkpoint(installed.certificate.genesis.guild_id)?
        {
            checkpoint.verify()?;
            if let Some(parent) = checkpoint.checkpoint.parent
                && self
                    .control
                    .get_record("guild-checkpoint", &parent)?
                    .is_none()
            {
                anyhow::bail!("checkpoint history is incomplete; Git prune must wait");
            }
            for revision in &checkpoint.checkpoint.revisions {
                include_revision(revision)?;
            }
        }
        protected
            .anchor_ids
            .extend(git_prune_recipe_anchor_ids(&self.control)?);
        self.open_git_repository(repository_id)?
            .prune_unreachable(&protected)
            .map_err(Into::into)
    }

    pub fn git_create_branch(&self, repository_id: Uuid, name: &str) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .create_branch(name)
            .map_err(Into::into)
    }

    pub fn git_reset_index(&self, repository_id: Uuid, paths: &[PathBuf]) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .reset_index(paths)
            .map_err(Into::into)
    }

    pub fn git_restore_worktree(&self, repository_id: Uuid, paths: &[PathBuf]) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .restore_worktree(paths)
            .map_err(Into::into)
    }

    pub fn git_restore_both(&self, repository_id: Uuid, paths: &[PathBuf]) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .restore_both(paths)
            .map_err(Into::into)
    }

    pub fn git_hard_reset(&self, repository_id: Uuid) -> Result<u32> {
        self.open_git_repository(repository_id)?
            .hard_reset()
            .map_err(Into::into)
    }

    pub fn git_create_branch_from(
        &self,
        repository_id: Uuid,
        name: &str,
        start_point: &str,
    ) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .create_branch_from(name, start_point)
            .map_err(Into::into)
    }

    pub fn git_delete_branch(
        &self,
        repository_id: Uuid,
        name: &str,
        force: bool,
    ) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .delete_branch(name, force)
            .map_err(Into::into)
    }

    pub fn git_switch_branch(&self, repository_id: Uuid, name: &str) -> Result<GitBranchInfo> {
        self.open_git_repository(repository_id)?
            .switch_branch(name)
            .map_err(Into::into)
    }

    pub fn git_push_bare(&self, repository_id: Uuid, path: &Path) -> Result<[u8; 20]> {
        let oid = self
            .open_git_repository(repository_id)?
            .push_current_branch_to_bare(path)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_push_branch_bare(
        &self,
        repository_id: Uuid,
        path: &Path,
        source_branch: &str,
        target_branch: &str,
    ) -> Result<[u8; 20]> {
        let oid = self
            .open_git_repository(repository_id)?
            .push_branch_to_bare(path, source_branch, target_branch)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_worktree_push_bare(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        path: &Path,
    ) -> Result<[u8; 20]> {
        let oid = self
            .open_git_repository(repository_id)?
            .push_linked_current_branch_to_bare(worktree_id, path)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_push_tag_bare(
        &self,
        repository_id: Uuid,
        path: &Path,
        name: &str,
    ) -> Result<[u8; 20]> {
        let oid = self
            .open_git_repository(repository_id)?
            .push_tag_to_bare(path, name)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_fetch_bare(&self, repository_id: Uuid, path: &Path) -> Result<u32> {
        let count = self.open_git_repository(repository_id)?.fetch_bare(path)?;
        Ok(u32::try_from(count).expect("bounded Git ref count"))
    }

    pub fn git_pull_bare(
        &self,
        repository_id: Uuid,
        path: &Path,
        author_name: &str,
        author_email: &str,
    ) -> Result<[u8; 20]> {
        let oid =
            self.open_git_repository(repository_id)?
                .pull_bare(path, author_name, author_email)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_worktree_pull_bare(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        path: &Path,
        author_name: &str,
        author_email: &str,
    ) -> Result<[u8; 20]> {
        let oid = self.open_git_repository(repository_id)?.linked_pull_bare(
            worktree_id,
            path,
            author_name,
            author_email,
        )?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_merge_branch(
        &self,
        repository_id: Uuid,
        branch: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<[u8; 20]> {
        let oid = self.open_git_repository(repository_id)?.merge_branch(
            branch,
            author_name,
            author_email,
        )?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_worktree_merge_branch(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
        branch: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<[u8; 20]> {
        let oid = self
            .open_git_repository(repository_id)?
            .linked_merge_branch(worktree_id, branch, author_name, author_email)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_merge_continue(&self, repository_id: Uuid) -> Result<[u8; 20]> {
        let oid = self.open_git_repository(repository_id)?.merge_continue()?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_worktree_merge_continue(
        &self,
        repository_id: Uuid,
        worktree_id: Uuid,
    ) -> Result<[u8; 20]> {
        let oid = self
            .open_git_repository(repository_id)?
            .linked_merge_continue(worktree_id)?;
        Ok(oid.as_bytes().try_into().expect("SHA-1 OID"))
    }

    pub fn git_merge_abort(&self, repository_id: Uuid) -> Result<()> {
        self.open_git_repository(repository_id)?.merge_abort()?;
        Ok(())
    }

    pub fn git_worktree_merge_abort(&self, repository_id: Uuid, worktree_id: Uuid) -> Result<()> {
        self.open_git_repository(repository_id)?
            .linked_merge_abort(worktree_id)?;
        Ok(())
    }

    pub fn git_diff(&self, repository_id: Uuid, cached: bool) -> Result<GitDiff> {
        self.open_git_repository(repository_id)?
            .diff(cached)
            .map_err(Into::into)
    }

    pub fn git_status(&self, repository_id: Uuid) -> Result<GitStatus> {
        let repository = self.open_git_repository(repository_id)?;
        let mut status = repository.status()?;
        status.history_backed_up = self.git_history_backed_up(repository_id, &repository)?;
        Ok(status)
    }

    fn git_history_backed_up(
        &self,
        repository_id: Uuid,
        repository: &GitRepository,
    ) -> Result<bool> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(false);
        };
        let guild_id = installed.certificate.genesis.guild_id;
        let Some(checkpoint) = self.current_checkpoint(guild_id)? else {
            return Ok(false);
        };
        checkpoint.verify()?;
        if checkpoint.checkpoint.guild_id != guild_id
            || checkpoint.checkpoint.genesis_hash != installed.certificate.hash()?
        {
            anyhow::bail!("Git backup status checkpoint belongs to another guild");
        }
        if checkpoint.checkpoint.format_version != 7 {
            // Older checkpoints may certify a revision without a complete
            // root-bound packing catalog for every Git history sector.
            return Ok(false);
        }
        let Some(revision) = checkpoint
            .checkpoint
            .revisions
            .iter()
            .filter(|revision| {
                revision.value.owner == self.keys.node_id()
                    && revision.value.protected_root_id == repository_id
            })
            .max_by_key(|revision| revision.value.sequence)
        else {
            return Ok(false);
        };
        if revision.value.metadata_sectors.is_empty() {
            return Ok(false);
        }
        let Some(backup) = revision_git_backup(&self.control, &self.keys, guild_id, revision)?
        else {
            return Ok(false);
        };
        let graph = repository.export_graph_source()?;
        Ok(backup.repository_id == repository_id
            && backup.refs == graph.refs
            && backup.objects == graph.objects
            && backup.blobs.len() == graph.blobs.len()
            && backup
                .blobs
                .iter()
                .zip(graph.blobs.iter())
                .all(|(backed_up, local)| {
                    backed_up.oid == local.oid && backed_up.logical_len == local.anchor.logical_len
                }))
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
                if probe_source {
                    self.source_backend_for_root(configured, filesystem)?;
                }
                return Ok(configured.clone());
            }
            anyhow::bail!("protected root identity conflicts with an existing root");
        }
        let root_id = requested_root_id.unwrap_or_else(Uuid::new_v4);
        if configured.iter().any(|root| root.root_id == root_id) {
            anyhow::bail!("protected root identity conflicts with an existing root");
        }

        if probe_source {
            SourceBackendKind::ReflinkV1
                .probe(&source_root)
                .context("protected root failed the reflink COW probe")?;
            if filesystem_identity(&source_root)? != filesystem {
                anyhow::bail!("protected root mount changed during backend probe");
            }
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
        let mut records = vec![(
            "protected-root".to_owned(),
            root.root_id.as_bytes().to_vec(),
            canonical_bytes(&root)?,
        )];
        if probe_source {
            let backend = SourceBackendBinding::reflink_v1(
                root.root_id,
                filesystem.stable_id,
                root.root_inode,
                filesystem.mount_id,
            );
            records.push((
                "source-backend".to_owned(),
                root.root_id.as_bytes().to_vec(),
                canonical_bytes(&backend)?,
            ));
        }
        self.control.put_records_and_delete(&records, &[])?;
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
        let schedule = match automation
            .root_schedules
            .binary_search_by_key(&root_id, |schedule| schedule.protected_root_id)
        {
            Ok(index) => &mut automation.root_schedules[index],
            Err(index) => {
                automation.root_schedules.insert(
                    index,
                    AutomaticRootSchedule {
                        protected_root_id: root_id,
                        dirty_since_unix_seconds: now,
                        last_attempt_unix_seconds: None,
                    },
                );
                &mut automation.root_schedules[index]
            }
        };
        if changed {
            schedule.dirty_since_unix_seconds = now;
        }
        automation.dirty_since_unix_seconds = automation
            .root_schedules
            .iter()
            .map(|schedule| schedule.dirty_since_unix_seconds)
            .min();
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

    #[cfg(test)]
    pub(crate) fn install_test_protected_root(&mut self, root: ProtectedRoot) -> Result<()> {
        self.control.put_record(
            "protected-root",
            root.root_id.as_bytes(),
            &canonical_bytes(&root)?,
        )?;
        self.control.put_record(
            "root-dirty",
            root.root_id.as_bytes(),
            &canonical_bytes(&RootDirtyState {
                format_version: 3,
                protected_root_id: root.root_id,
                dirty: false,
                reason: "test root starts clean".to_owned(),
                change_sequence: 0,
            })?,
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_root_change_sequence(&self, root_id: Uuid) -> Result<u64> {
        Ok(self
            .root_dirty_state(root_id)?
            .map(|state| state.change_sequence)
            .unwrap_or(0))
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
                in_flight_root_id: None,
                retry_at_unix_seconds: None,
                blocked_reason: None,
                root_retries: Vec::new(),
                root_schedules: Vec::new(),
            });
        if state.format_version != 1
            || state.in_flight_root_id.is_some() && state.in_flight_revision.is_none()
            || state
                .root_retries
                .iter()
                .any(|retry| retry.protected_root_id.is_nil() || retry.reason.is_empty())
            || state
                .root_retries
                .windows(2)
                .any(|retries| retries[0].protected_root_id >= retries[1].protected_root_id)
            || state
                .root_schedules
                .iter()
                .any(|schedule| schedule.protected_root_id.is_nil())
            || state
                .root_schedules
                .windows(2)
                .any(|schedules| schedules[0].protected_root_id >= schedules[1].protected_root_id)
        {
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
        let root_retry = state
            .root_retries
            .iter()
            .min_by_key(|retry| retry.retry_at_unix_seconds);
        Ok(AutomaticBackupStatus {
            enabled: policy.enabled,
            dirty_since_unix_seconds: state.dirty_since_unix_seconds,
            last_attempt_unix_seconds: state.last_attempt_unix_seconds,
            last_success_unix_seconds: state.last_success_unix_seconds,
            in_flight_revision: state.in_flight_revision,
            window_backup_count: state.window_backup_count,
            window_bytes: state.window_bytes,
            retry_at_unix_seconds: state
                .retry_at_unix_seconds
                .or_else(|| root_retry.map(|retry| retry.retry_at_unix_seconds)),
            blocked_reason: state
                .blocked_reason
                .or_else(|| root_retry.map(|retry| retry.reason.clone())),
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
            state.root_retries.clear();
            state.root_schedules.clear();
            state.dirty_since_unix_seconds = None;
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        if state.retry_at_unix_seconds.is_some_and(|retry| retry > now)
            || state.blocked_reason.is_some() && state.retry_at_unix_seconds.is_none()
        {
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        if self.protected_roots()?.is_empty() || self.installed_guild()?.is_none() {
            state.blocked_reason = Some("automatic backup needs a protected root and guild".into());
            state.retry_at_unix_seconds = None;
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        }
        let roots = self.protected_roots()?;
        let configured = roots
            .iter()
            .map(|root| root.root_id)
            .collect::<BTreeSet<_>>();
        let mut dirty_roots = BTreeSet::new();
        for root in &roots {
            if self
                .root_dirty_state(root.root_id)?
                .is_none_or(|dirty| dirty.dirty)
            {
                dirty_roots.insert(root.root_id);
            }
        }
        state
            .root_retries
            .retain(|retry| configured.contains(&retry.protected_root_id));
        state
            .root_schedules
            .retain(|schedule| dirty_roots.contains(&schedule.protected_root_id));
        for root in &roots {
            if dirty_roots.contains(&root.root_id)
                && state
                    .root_schedules
                    .binary_search_by_key(&root.root_id, |schedule| schedule.protected_root_id)
                    .is_err()
            {
                let index = state
                    .root_schedules
                    .partition_point(|schedule| schedule.protected_root_id < root.root_id);
                state.root_schedules.insert(
                    index,
                    AutomaticRootSchedule {
                        protected_root_id: root.root_id,
                        dirty_since_unix_seconds: state.dirty_since_unix_seconds.unwrap_or(now),
                        last_attempt_unix_seconds: None,
                    },
                );
            }
        }
        state.dirty_since_unix_seconds = state
            .root_schedules
            .iter()
            .map(|schedule| schedule.dirty_since_unix_seconds)
            .min();
        let schedules = state
            .root_schedules
            .iter()
            .map(|schedule| (schedule.protected_root_id, schedule.clone()))
            .collect::<BTreeMap<_, _>>();
        let mut roots = roots
            .into_iter()
            .filter(|root| {
                schedules.get(&root.root_id).is_some_and(|schedule| {
                    now >= schedule
                        .dirty_since_unix_seconds
                        .saturating_add(policy.quiet_period_seconds)
                        && now
                            >= schedule
                                .last_attempt_unix_seconds
                                .unwrap_or(0)
                                .saturating_add(policy.minimum_interval_seconds)
                })
            })
            .collect::<Vec<_>>();
        roots.sort_by_key(|root| {
            let schedule = &schedules[&root.root_id];
            (
                schedule.dirty_since_unix_seconds,
                schedule.last_attempt_unix_seconds.unwrap_or(0),
                root.root_id,
            )
        });
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
        let remaining_bytes = policy.daily_byte_limit.saturating_sub(state.window_bytes);
        let next_window = state
            .window_started_unix_seconds
            .saturating_add(24 * 60 * 60);
        let mut selected = None;
        for root in roots {
            if !self
                .root_dirty_state(root.root_id)?
                .is_none_or(|dirty| dirty.dirty)
                || state.root_retries.iter().any(|retry| {
                    retry.protected_root_id == root.root_id && retry.retry_at_unix_seconds > now
                })
            {
                continue;
            }
            match self.protected_root_logical_bytes(&root) {
                Ok(estimated_bytes) => {
                    state
                        .root_retries
                        .retain(|retry| retry.protected_root_id != root.root_id);
                    if estimated_bytes > remaining_bytes {
                        state.root_retries.push(AutomaticRootRetry {
                            protected_root_id: root.root_id,
                            retry_at_unix_seconds: next_window,
                            reason: format!(
                                "daily automatic-backup byte limit reached for root {}",
                                root.root_id
                            ),
                        });
                        state
                            .root_retries
                            .sort_by_key(|retry| retry.protected_root_id);
                        continue;
                    }
                    selected = Some((root.root_id, estimated_bytes));
                    break;
                }
                Err(error) => {
                    let mut reason = format!(
                        "automatic full reconciliation failed for root {}: {error:#}",
                        root.root_id
                    );
                    truncate_utf8(&mut reason, 512);
                    state
                        .root_retries
                        .retain(|retry| retry.protected_root_id != root.root_id);
                    state.root_retries.push(AutomaticRootRetry {
                        protected_root_id: root.root_id,
                        retry_at_unix_seconds: now.saturating_add(policy.minimum_interval_seconds),
                        reason,
                    });
                    state
                        .root_retries
                        .sort_by_key(|retry| retry.protected_root_id);
                }
            }
        }
        let Some((protected_root_id, estimated_bytes)) = selected else {
            self.store_automatic_backup_state(&state)?;
            return Ok(AutomaticBackupPoll::Idle);
        };
        state.last_attempt_unix_seconds = Some(now);
        let schedule = state
            .root_schedules
            .iter_mut()
            .find(|schedule| schedule.protected_root_id == protected_root_id)
            .context("selected automatic-backup root has no schedule")?;
        schedule.last_attempt_unix_seconds = Some(now);
        state.window_backup_count += 1;
        state.window_bytes = state.window_bytes.saturating_add(estimated_bytes);
        state.retry_at_unix_seconds = None;
        state.blocked_reason = None;
        self.store_automatic_backup_state(&state)?;
        Ok(AutomaticBackupPoll::Start {
            protected_root_id,
            estimated_bytes,
        })
    }

    pub(crate) fn automatic_backup_submitted(
        &self,
        revision_id: Uuid,
        protected_root_id: Uuid,
    ) -> Result<()> {
        let mut state = self.automatic_backup_state(unix_seconds())?;
        state.in_flight_revision = Some(revision_id);
        state.in_flight_root_id = Some(protected_root_id);
        state.blocked_reason = None;
        state.retry_at_unix_seconds = None;
        self.store_automatic_backup_state(&state)
    }

    pub(crate) fn automatic_backup_finished(
        &self,
        revision_id: Option<Uuid>,
        protected_root_id: Option<Uuid>,
        succeeded: bool,
        error: Option<&str>,
    ) -> Result<()> {
        let now = unix_seconds();
        let mut state = self.automatic_backup_state(now)?;
        if revision_id.is_some() && state.in_flight_revision != revision_id {
            anyhow::bail!("automatic-backup completion conflicts with its durable revision");
        }
        let affected_root = protected_root_id.or(state.in_flight_root_id);
        state.in_flight_revision = None;
        state.in_flight_root_id = None;
        if succeeded {
            state.last_success_unix_seconds = Some(now);
            state.blocked_reason = None;
            state.retry_at_unix_seconds = None;
            if let Some(root_id) = affected_root {
                state
                    .root_retries
                    .retain(|retry| retry.protected_root_id != root_id);
            }
        } else {
            let mut message = error.unwrap_or("automatic backup failed").to_owned();
            truncate_utf8(&mut message, 512);
            let hard = message.contains("budget")
                || message.contains("capacity")
                || message.contains("space");
            if !hard && let Some(root_id) = affected_root {
                state
                    .root_retries
                    .retain(|retry| retry.protected_root_id != root_id);
                state.root_retries.push(AutomaticRootRetry {
                    protected_root_id: root_id,
                    retry_at_unix_seconds: now.saturating_add(
                        self.automatic_backup_policy()
                            .map(|policy| policy.minimum_interval_seconds)
                            .unwrap_or(60),
                    ),
                    reason: message,
                });
                state
                    .root_retries
                    .sort_by_key(|retry| retry.protected_root_id);
                state.blocked_reason = None;
                state.retry_at_unix_seconds = None;
            } else {
                state.blocked_reason = Some(message);
                state.retry_at_unix_seconds = (!hard).then(|| {
                    now.saturating_add(
                        self.automatic_backup_policy()
                            .map(|policy| policy.minimum_interval_seconds)
                            .unwrap_or(60),
                    )
                });
            }
        }
        self.store_automatic_backup_state(&state)
    }

    pub fn clear_automatic_backup_block(&self) -> Result<()> {
        let mut state = self.automatic_backup_state(unix_seconds())?;
        state.blocked_reason = None;
        state.retry_at_unix_seconds = None;
        state.root_retries.clear();
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

    pub(crate) fn adopt_recovered_dynamic_guild(
        &mut self,
        certificate: QuorumGuildGenesis,
        checkpoint: &QuorumCheckpoint,
        events: Vec<QuorumGuildEvent>,
        mut peers: Vec<GuildPeer>,
        transcripts: Vec<([u8; 32], VerifiedCodingTranscript)>,
        bindings: Vec<QuorumLegacyCodingAddBinding>,
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
        let mut add_events = Vec::new();
        let binding_count = bindings.len();
        let mut binding_by_event = bindings
            .into_iter()
            .map(|binding| (binding.statement.event_hash, binding))
            .collect::<BTreeMap<_, _>>();
        if binding_by_event.len() != binding_count {
            anyhow::bail!("dynamic recovery has duplicate historical Add bindings");
        }
        let mut binding_records = Vec::new();
        for event in events {
            let record_id = event.event.sequence.to_be_bytes().to_vec();
            if let Some((group, transcript_hash)) = event.event.kind.coding_group_add() {
                let mut expected_hash = transcript_hash;
                if transcript_hash.is_none() {
                    let add_hash = event.event.hash()?;
                    let binding = binding_by_event
                        .remove(&add_hash)
                        .context("dynamic recovery historical Add lacks quorum evidence")?;
                    binding.verify(&state, &event)?;
                    expected_hash = Some(binding.statement.transcript_hash);
                    binding_records.push((
                        "coding-legacy-add-binding".to_owned(),
                        add_hash.to_vec(),
                        canonical_bytes(&binding)?,
                    ));
                }
                add_events.push((
                    event.event.sequence,
                    group.clone(),
                    event.event.hash()?,
                    expected_hash,
                ));
            }
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
        if !binding_by_event.is_empty() {
            anyhow::bail!("dynamic recovery has extra historical Add bindings");
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
            || !checkpoint.authorizes_member_recovery(local_id)
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
        let transcript_by_event = transcripts
            .into_iter()
            .map(|(hash, transcript)| (hash, transcript.into_inner()))
            .collect::<BTreeMap<_, _>>();
        if transcript_by_event.len() != add_events.len() {
            anyhow::bail!("dynamic recovery has incomplete or extra coding evidence");
        }
        let mut transcript_records =
            Vec::with_capacity(add_events.len() + 2 * state.coding_groups.len());
        let mut retained_evidence = 0;
        for (sequence, group, add_hash, expected_hash) in add_events {
            let transcript = transcript_by_event
                .get(&add_hash)
                .context("dynamic recovery historical Add transcript is unavailable")?;
            let authority = authority_states
                .get(&transcript.value.plan.value.membership_epoch)
                .context("coding transcript membership epoch is absent from event history")?;
            authority.validate_attempt_authority(&transcript.value.plan.value)?;
            if transcript.value.manifest.value.group != group {
                anyhow::bail!("dynamic recovery coding transcript is invalid");
            }
            let bytes = canonical_bytes(transcript)?;
            if expected_hash.is_some_and(|expected| *blake3::hash(&bytes).as_bytes() != expected) {
                anyhow::bail!("dynamic recovery Add names different verifier evidence");
            }
            transcript_records.push((
                "coding-event-transcript".to_owned(),
                add_hash.to_vec(),
                bytes.clone(),
            ));
            if state
                .coding_groups
                .iter()
                .any(|retained| retained.added_at_event == sequence && retained.group == group)
            {
                retained_evidence += 1;
                transcript_records.push((
                    "coding-transcript".to_owned(),
                    transcript.value.plan.value.attempt_id.to_vec(),
                    bytes.clone(),
                ));
                transcript_records.push((
                    "coding-group-transcript".to_owned(),
                    group.id.to_vec(),
                    bytes,
                ));
            }
        }
        if retained_evidence != state.coding_groups.len() {
            anyhow::bail!("dynamic recovery has incomplete retained coding evidence");
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
        for (kind, record_id, bytes) in event_records
            .iter()
            .chain(&transcript_records)
            .chain(&binding_records)
        {
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
        records.extend(binding_records);
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
        if event.kind.coding_group_add().is_some() {
            anyhow::bail!("coding-group events require replayable verifier evidence");
        }
        self.sign_guild_event_proposal_inner(event)
    }

    pub(crate) fn locked_guild_event_proposal(&self, sequence: u64) -> Result<Option<GuildEvent>> {
        let record_id = sequence.to_be_bytes();
        let Some(bytes) = self
            .control
            .get_record("guild-event-signature-lock", &record_id)?
        else {
            return Ok(None);
        };
        let lock: GuildEventSignatureLock = decode_canonical(&bytes)?;
        let expected_signature = sign_guild_event(&lock.event, &self.keys)?;
        if lock.format_version != 1
            || lock.event.sequence != sequence
            || lock.event_hash != lock.event.hash()?
            || lock.signature != expected_signature
        {
            anyhow::bail!("local guild event signature lock is invalid");
        }
        Ok(Some(lock.event))
    }

    pub fn sign_coding_group_event_proposal(
        &self,
        event: &GuildEvent,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<MemberSignature> {
        if !matches!(
            event.kind,
            mb_core::GuildEventKind::AddCodingGroupBound { .. }
        ) {
            anyhow::bail!("new coding Add proposals must bind verifier evidence");
        }
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

    /// Retain exact, individually verified signatures across coordinator retry
    /// passes. A unanimous event need not reach every signer in one pass.
    pub(crate) fn collect_guild_event_signature(
        &self,
        event: &GuildEvent,
        candidate: MemberSignature,
    ) -> Result<Vec<MemberSignature>> {
        let state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        state.validate_event_proposal(event)?;
        if self.locked_guild_event_proposal(event.sequence)?.as_ref() != Some(event) {
            anyhow::bail!("local guild proposal lock does not match the event");
        }
        let id = pending_guild_event_signatures_id(event);
        let mut pending = self
            .control
            .get_record("guild-event-partial-signatures", &id)?
            .map(|bytes| decode_canonical::<PendingGuildEventSignatures>(&bytes))
            .transpose()?
            .unwrap_or(PendingGuildEventSignatures {
                format_version: 1,
                event: event.clone(),
                signatures: Vec::new(),
            });
        if pending.format_version != 1 || pending.event != *event {
            anyhow::bail!("pending guild signatures name another proposal");
        }
        let active = state
            .active_members()
            .map(|member| member.node_id)
            .collect::<BTreeSet<_>>();
        let mut previous = None;
        for signature in &pending.signatures {
            if !active.contains(&signature.signer)
                || previous.is_some_and(|signer| signer >= signature.signer)
            {
                anyhow::bail!("pending guild signatures contain an invalid signer");
            }
            verify_guild_event_signature(event, signature)?;
            previous = Some(signature.signer);
        }
        if !active.contains(&candidate.signer) {
            anyhow::bail!("guild signature came from a nonmember");
        }
        verify_guild_event_signature(event, &candidate)?;
        match pending
            .signatures
            .binary_search_by_key(&candidate.signer, |signature| signature.signer)
        {
            Ok(index) if pending.signatures[index] != candidate => {
                anyhow::bail!("guild member returned a conflicting signature");
            }
            Ok(_) => return Ok(pending.signatures),
            Err(index) => pending.signatures.insert(index, candidate),
        }
        self.control.put_record(
            "guild-event-partial-signatures",
            &id,
            &canonical_bytes(&pending)?,
        )?;
        Ok(pending.signatures)
    }

    pub fn install_guild_event(&mut self, certified: QuorumGuildEvent) -> Result<()> {
        if certified.event.kind.coding_group_add().is_some() {
            anyhow::bail!("coding-group events require replayable verifier evidence");
        }
        self.install_guild_event_inner(certified, None, None)
    }

    pub fn install_coding_group_event(
        &mut self,
        certified: QuorumGuildEvent,
        transcript: SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        if matches!(
            certified.event.kind,
            mb_core::GuildEventKind::AddCodingGroup { .. }
        ) {
            anyhow::bail!("historical coding Add requires quorum-bound verifier evidence");
        }
        self.validate_coding_group_event_evidence(&certified.event, &transcript)?;
        self.install_guild_event_inner(certified, Some(transcript), None)
    }

    #[cfg(test)]
    pub(crate) fn install_legacy_coding_group_event(
        &mut self,
        certified: QuorumGuildEvent,
        transcript: SignedRecord<CodingVerificationTranscript>,
        binding: QuorumLegacyCodingAddBinding,
    ) -> Result<()> {
        let state = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        let state_before = if state.event_sequence.checked_add(1) == Some(certified.event.sequence)
        {
            state
        } else {
            self.dynamic_guild_state_before_event(certified.event.sequence)?
        };
        binding.verify(&state_before, &certified)?;
        if binding.statement.transcript_hash
            != *blake3::hash(&canonical_bytes(&transcript)?).as_bytes()
        {
            anyhow::bail!("historical Add binding names different verifier evidence");
        }
        self.validate_coding_group_event_evidence(&certified.event, &transcript)?;
        self.install_guild_event_inner(certified, Some(transcript), Some(binding))
    }

    fn dynamic_guild_state_before_event(&self, sequence: u64) -> Result<DynamicGuildState> {
        let installed = decode_installed_guild(
            &self
                .control
                .get_record("guild-installed", b"primary")?
                .context("node has no installed guild")?,
        )?;
        let mut state = initial_dynamic_guild_state(&installed)?;
        for (record_id, bytes) in self.control.records("guild-event")? {
            let event: QuorumGuildEvent = decode_canonical(&bytes)?;
            if event.event.sequence >= sequence {
                break;
            }
            if record_id != event.event.sequence.to_be_bytes() {
                anyhow::bail!("guild event history has an invalid record ID");
            }
            state.apply_event(&event)?;
        }
        if state.event_sequence.checked_add(1) != Some(sequence) {
            anyhow::bail!("historical Add predecessor is unavailable");
        }
        Ok(state)
    }

    pub(crate) fn next_unbound_legacy_coding_add(
        &self,
    ) -> Result<Option<(QuorumGuildEvent, DynamicGuildState, [u8; 32])>> {
        let installed = match self.control.get_record("guild-installed", b"primary")? {
            Some(bytes) => decode_installed_guild(&bytes)?,
            None => return Ok(None),
        };
        let mut state = initial_dynamic_guild_state(&installed)?;
        for (record_id, bytes) in self.control.records("guild-event")? {
            let event: QuorumGuildEvent = decode_canonical(&bytes)?;
            if record_id != event.event.sequence.to_be_bytes() {
                anyhow::bail!("guild event history has an invalid record ID");
            }
            if let mb_core::GuildEventKind::AddCodingGroup { group } = &event.event.kind {
                let hash = event.event.hash()?;
                if self
                    .control
                    .get_record("coding-legacy-add-binding", &hash)?
                    .is_none()
                {
                    let transcript = self.coding_transcript_for_event(
                        state.guild_id,
                        group.id,
                        event.event.sequence,
                        hash,
                    )?;
                    state.verify_event(&event)?;
                    return Ok(Some((
                        event,
                        state,
                        *blake3::hash(&canonical_bytes(&transcript)?).as_bytes(),
                    )));
                }
            }
            state.apply_event(&event)?;
        }
        Ok(None)
    }

    pub(crate) fn persist_legacy_coding_add_binding(
        &self,
        certified: &QuorumGuildEvent,
        binding: &QuorumLegacyCodingAddBinding,
    ) -> Result<()> {
        let state_before = self.dynamic_guild_state_before_event(certified.event.sequence)?;
        binding.verify(&state_before, certified)?;
        let mb_core::GuildEventKind::AddCodingGroup { group } = &certified.event.kind else {
            anyhow::bail!("legacy binding requires a historical coding Add");
        };
        let hash = certified.event.hash()?;
        let stored: QuorumGuildEvent = decode_canonical(
            &self
                .control
                .get_record("guild-event", &certified.event.sequence.to_be_bytes())?
                .context("historical coding Add is unavailable")?,
        )?;
        if stored != *certified {
            anyhow::bail!("legacy binding conflicts with installed guild history");
        }
        let transcript = self.coding_transcript_for_event(
            state_before.guild_id,
            group.id,
            certified.event.sequence,
            hash,
        )?;
        if binding.statement.transcript_hash
            != *blake3::hash(&canonical_bytes(&transcript)?).as_bytes()
        {
            anyhow::bail!("legacy binding names different local verifier evidence");
        }
        let bytes = canonical_bytes(binding)?;
        if let Some(existing) = self
            .control
            .get_record("coding-legacy-add-binding", &hash)?
        {
            if existing != bytes {
                anyhow::bail!("historical Add conflicts with its persisted binding");
            }
            return Ok(());
        }
        if !self
            .control
            .put_record_if_absent("coding-legacy-add-binding", &hash, &bytes)?
        {
            anyhow::bail!("historical Add binding raced another certificate");
        }
        Ok(())
    }

    fn install_guild_event_inner(
        &mut self,
        certified: QuorumGuildEvent,
        transcript: Option<SignedRecord<CodingVerificationTranscript>>,
        binding: Option<QuorumLegacyCodingAddBinding>,
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
            let binding_record = if let Some(binding) = &binding {
                let event_hash = certified.event.hash()?;
                let bytes = canonical_bytes(binding)?;
                if self
                    .control
                    .get_record("coding-legacy-add-binding", &event_hash)?
                    .is_some_and(|existing| existing != bytes)
                {
                    anyhow::bail!("historical Add conflicts with its quorum binding");
                }
                Some((event_hash, bytes))
            } else {
                None
            };
            if let Some(transcript) = transcript {
                let attempt_id = transcript.value.plan.value.attempt_id;
                let group = &transcript.value.manifest.value.group;
                let event_hash = certified.event.hash()?;
                if let Some(existing) = self
                    .control
                    .get_record("coding-event-transcript", &event_hash)?
                    && existing != canonical_bytes(&transcript)?
                {
                    anyhow::bail!("historical Add conflicts with its bound verifier evidence");
                }
                let current_add = state.coding_groups.iter().any(|retained| {
                    retained.group == *group && retained.added_at_event == sequence
                });
                if current_add {
                    self.persist_coding_group_transcript(&transcript)?;
                    self.control.put_record(
                        "coding-event-transcript",
                        &event_hash,
                        &canonical_bytes(&transcript)?,
                    )?;
                } else if self
                    .control
                    .get_record("coding-event-transcript", &event_hash)?
                    .is_none()
                {
                    anyhow::bail!("historical Add has no event-bound verifier evidence");
                }
                self.volumes.finalize_attempt(&self.control, &attempt_id)?;
                self.control
                    .delete_record("coding-pending-activation", &attempt_id)?;
            }
            if let Some((event_hash, bytes)) = binding_record {
                self.control
                    .put_record("coding-legacy-add-binding", &event_hash, &bytes)?;
            }
            if matches!(
                certified.event.kind,
                mb_core::GuildEventKind::ForgetCodingGroup { .. }
            ) {
                self.reconcile_garbage_collection()?;
            }
            self.control.delete_record(
                "guild-event-partial-signatures",
                &pending_guild_event_signatures_id(&certified.event),
            )?;
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
        let forgotten_group = if let mb_core::GuildEventKind::ForgetCodingGroup { group_id } =
            &certified.event.kind
        {
            let retained = state
                .coding_groups
                .iter()
                .find(|retained| retained.group.id == *group_id)
                .context("forgotten coding group is absent from guild history")?;
            let add_event: QuorumGuildEvent = decode_canonical(
                &self
                    .control
                    .get_record("guild-event", &retained.added_at_event.to_be_bytes())?
                    .context("forgotten coding group has no historical Add event")?,
            )?;
            let transcript = self.coding_transcript_for_event(
                state.guild_id,
                *group_id,
                retained.added_at_event,
                add_event.event.hash()?,
            )?;
            if transcript.value.manifest.value.group != retained.group {
                anyhow::bail!("forgotten coding group has conflicting verifier evidence");
            }
            Some((add_event.event.hash()?, transcript))
        } else {
            None
        };
        let is_forget = forgotten_group.is_some();
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
        if let Some(binding) = binding {
            let event_hash = certified.event.hash()?;
            let bytes = canonical_bytes(&binding)?;
            if self
                .control
                .get_record("coding-legacy-add-binding", &event_hash)?
                .is_some_and(|existing| existing != bytes)
            {
                anyhow::bail!("coding Add conflicts with its quorum binding");
            }
            records.push((
                "coding-legacy-add-binding".to_owned(),
                event_hash.to_vec(),
                bytes,
            ));
        }
        if let Some((add_hash, transcript)) = forgotten_group {
            let bytes = canonical_bytes(&transcript)?;
            if self
                .control
                .get_record("coding-event-transcript", &add_hash)?
                .is_some_and(|existing| existing != bytes)
            {
                anyhow::bail!("forgotten coding Add conflicts with its verifier evidence");
            }
            // Legacy stores can reach Forget using their retained group-key
            // transcript. Preserve that unambiguous Add binding atomically
            // with the event that makes the retained fallback unavailable.
            records.push((
                "coding-event-transcript".to_owned(),
                add_hash.to_vec(),
                bytes,
            ));
            let plan = transcript.value.plan.clone();
            self.validate_coding_attempt_authority(&plan)?;
            let parity_holders = transcript
                .value
                .manifest
                .value
                .group
                .roles
                .iter()
                .filter_map(|role| match role {
                    ShardRoleV2::Parity(parity) => Some(parity.holder),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            for holder in parity_holders {
                // Only the original delegator/coder can ask another holder
                // to abort a historical attempt. Every holder also keeps its
                // own obligation once it installs Forget.
                if holder != self.keys.node_id()
                    && self.keys.node_id() != plan.value.delegator
                    && self.keys.node_id() != plan.value.coding_coordinator
                {
                    continue;
                }
                let obligation = CodingHolderCleanupObligation {
                    format_version: 1,
                    plan: plan.clone(),
                    holder,
                };
                let id = coding_holder_cleanup_id(&obligation);
                let bytes = canonical_bytes(&obligation)?;
                if self
                    .control
                    .get_record("coding-holder-cleanup", &id)?
                    .is_some_and(|existing| existing != bytes)
                {
                    anyhow::bail!("forgotten coding group has conflicting cleanup ownership");
                }
                records.push(("coding-holder-cleanup".to_owned(), id, bytes));
            }
        }
        let attempt_id = transcript
            .as_ref()
            .map(|transcript| transcript.value.plan.value.attempt_id);
        if let Some(transcript) = transcript {
            self.validate_coding_transcript_storage_conflicts(&transcript)?;
            let bytes = canonical_bytes(&transcript)?;
            let event_hash = certified.event.hash()?;
            if self
                .control
                .get_record("coding-event-transcript", &event_hash)?
                .is_some_and(|existing| existing != bytes)
            {
                anyhow::bail!("coding Add conflicts with its bound verifier evidence");
            }
            records.push((
                "coding-transcript".to_owned(),
                transcript.value.plan.value.attempt_id.to_vec(),
                bytes.clone(),
            ));
            records.push((
                "coding-group-transcript".to_owned(),
                transcript.value.manifest.value.group.id.to_vec(),
                bytes.clone(),
            ));
            records.push((
                "coding-event-transcript".to_owned(),
                event_hash.to_vec(),
                bytes,
            ));
        }
        let mut deletions = attempt_id
            .map(|attempt_id| vec![("coding-pending-activation".to_owned(), attempt_id.to_vec())])
            .unwrap_or_default();
        deletions.push((
            "guild-event-partial-signatures".to_owned(),
            pending_guild_event_signatures_id(&certified.event).to_vec(),
        ));
        self.control.put_records_and_delete(&records, &deletions)?;
        if let Some(attempt_id) = attempt_id {
            self.volumes.finalize_attempt(&self.control, &attempt_id)?;
        }
        if is_forget {
            self.reconcile_garbage_collection()?;
        }
        Ok(())
    }

    fn validate_coding_group_event_evidence(
        &self,
        event: &GuildEvent,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let Some((group, transcript_hash)) = event.kind.coding_group_add() else {
            anyhow::bail!("coding evidence was supplied for another guild event kind");
        };
        self.validate_coding_attempt_authority(&transcript.value.plan)?;
        let evidence_hash = *blake3::hash(&canonical_bytes(transcript)?).as_bytes();
        if replay_coding_transcript(transcript)? != CodingReplayFinding::Verified
            || transcript.value.manifest.value.group != *group
            || transcript_hash.is_some_and(|expected| expected != evidence_hash)
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
        if self
            .control
            .get_record("coding-transcript", &transcript.value.plan.value.attempt_id)?
            .is_some_and(|existing| existing != bytes)
        {
            anyhow::bail!("coding attempt already has conflicting verifier evidence");
        }
        let group_id = transcript.value.manifest.value.group.id;
        if self
            .control
            .get_record("coding-group-transcript", &group_id)?
            .is_some_and(|existing| existing != bytes)
            && self.dynamic_guild_state()?.is_some_and(|state| {
                state
                    .coding_groups
                    .iter()
                    .any(|retained| retained.group.id == group_id)
            })
        {
            anyhow::bail!("retained coding group already has conflicting verifier evidence");
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

    pub(crate) fn coding_transcript_for_event(
        &self,
        guild_id: [u8; 32],
        group_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
    ) -> Result<SignedRecord<CodingVerificationTranscript>> {
        coding_transcript_for_event_from_store(
            &self.control,
            guild_id,
            group_id,
            event_sequence,
            event_hash,
        )
    }

    pub(crate) fn attest_legacy_coding_add(
        &self,
        guild_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
        transcript_hash: [u8; 32],
    ) -> Result<MemberSignature> {
        let certified: QuorumGuildEvent = decode_canonical(
            &self
                .control
                .get_record("guild-event", &event_sequence.to_be_bytes())?
                .context("historical coding Add is unavailable")?,
        )?;
        let mb_core::GuildEventKind::AddCodingGroup { group } = &certified.event.kind else {
            anyhow::bail!("historical Add attestation requires an unbound event");
        };
        if certified.event.guild_id != guild_id
            || certified.event.hash()? != event_hash
            || !certified
                .signatures
                .iter()
                .any(|signature| signature.signer == self.keys.node_id())
            || !self.dynamic_guild_state()?.is_some_and(|state| {
                state
                    .active_members()
                    .any(|member| member.node_id == self.keys.node_id())
            })
        {
            anyhow::bail!("local node is not an authorized historical Add witness");
        }
        let transcript =
            self.coding_transcript_for_event(guild_id, group.id, event_sequence, event_hash)?;
        if *blake3::hash(&canonical_bytes(&transcript)?).as_bytes() != transcript_hash {
            anyhow::bail!("historical Add witness has different verifier evidence");
        }
        let statement = LegacyCodingAddStatement::for_event(&certified, transcript_hash)?;
        let signature = sign_legacy_coding_add_binding(&statement, &self.keys)?;
        if let Some(bytes) = self
            .control
            .get_record("coding-legacy-add-signature-lock", &event_hash)?
        {
            let lock: LegacyCodingAddSignatureLock = decode_canonical(&bytes)?;
            if lock.format_version != 1
                || lock.statement != statement
                || lock.signature != signature
            {
                anyhow::bail!("local node already attested different historical Add evidence");
            }
            return Ok(signature);
        }
        let lock = LegacyCodingAddSignatureLock {
            format_version: 1,
            statement,
            signature: signature.clone(),
        };
        if !self.control.put_record_if_absent(
            "coding-legacy-add-signature-lock",
            &event_hash,
            &canonical_bytes(&lock)?,
        )? {
            anyhow::bail!("historical Add attestation raced another local signature");
        }
        Ok(signature)
    }

    pub(crate) fn recovery_coding_transcript_for_group(
        &self,
        checkpoint_hash: [u8; 32],
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
        {
            anyhow::bail!("stored coding-group verifier transcript has the wrong group");
        }
        self.validate_certified_recovery_transcript(checkpoint_hash, &transcript)?;
        Ok(transcript)
    }

    fn validate_certified_recovery_transcript(
        &self,
        checkpoint_hash: [u8; 32],
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let plan = &transcript.value.plan.value;
        let group = &transcript.value.manifest.value.group;
        self.require_active_recovery_attempt(group.guild_id, checkpoint_hash)?;
        if !self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?
            .coding_groups
            .iter()
            .any(|retained| retained.group == *group)
        {
            anyhow::bail!("recovery transcript is absent from certified guild state");
        }
        let bytes = canonical_bytes(transcript)?;
        for (kind, record_id) in [
            ("coding-transcript", plan.attempt_id.as_slice()),
            ("coding-group-transcript", group.id.as_slice()),
        ] {
            if self.control.get_record(kind, record_id)?.as_deref() != Some(bytes.as_slice()) {
                anyhow::bail!("recovery transcript differs from certified durable evidence");
            }
        }
        Ok(())
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
        self.source_backend_for_root(&root, current_filesystem)?;
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
        if state
            .active_members()
            .any(|member| state.current_recovery_key(member.node_id).is_none())
        {
            return Ok(None);
        }
        let next_event_sequence = state
            .event_sequence
            .checked_add(1)
            .context("guild event sequence exhausted")?;
        let locked_event = self.locked_guild_event_proposal(next_event_sequence)?;
        for (_, bytes) in self.control.records("backup-job")? {
            let mut job: BackupJob = decode_canonical(&bytes)?;
            if matches!(job.state, BackupJobState::Pending | BackupJobState::Running) {
                if locked_event.as_ref().is_some_and(|event| {
                    !matches!(
                        &event.kind,
                        mb_core::GuildEventKind::RotateWriterKey { owner, .. }
                            if *owner == job.descriptor.owner
                    )
                }) {
                    continue;
                }
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
        let root = self.protected_root_by_id(protected_root_id)?;
        if source_root.canonicalize()? != root.path {
            anyhow::bail!("source path does not match the protected root");
        }
        let metadata = fs::symlink_metadata(&root.path)?;
        let filesystem = filesystem_identity(&root.path)?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || !root.matches_identity(filesystem, metadata.ino())
        {
            anyhow::bail!("protected root identity changed");
        }
        let backend = self.source_backend_for_root(&root, filesystem)?;
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
            backend.backend,
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

    pub(crate) fn sign_legacy_packing_binding(
        &self,
        guild_id: &[u8; 32],
        protected_root_id: Uuid,
        reference: &SectorRef,
    ) -> Result<SignedRecord<mb_core::LegacyPackingBinding>> {
        let bytes = self.sector_for_guild(guild_id, &reference.id)?;
        sign_legacy_packing_binding(&self.keys, protected_root_id, reference, &bytes)
    }

    pub(crate) fn sign_legacy_packing_attestation(
        &mut self,
        value: mb_core::LegacyPackingAttestation,
        bytes: &[u8],
    ) -> Result<SignedRecord<mb_core::LegacyPackingAttestation>> {
        let state = self
            .dynamic_guild_state()?
            .context("legacy packing attestation requires dynamic guild state")?;
        if value.format_version != 1
            || value.guild_id != state.guild_id
            || value.membership_epoch != state.membership_epoch
            || !state
                .active_members()
                .any(|member| member.node_id == self.keys.node_id())
            || bytes.len() != V1_SECTOR_SIZE
            || sector_root(bytes) != value.flat_root
            || merkle_commit(bytes)? != value.source_commitment
        {
            anyhow::bail!("legacy packing attestation conflicts with recovered source bytes");
        }
        let attestation = SignedRecord::sign(
            mb_core::LEGACY_PACKING_ATTESTATION_DOMAIN,
            value,
            &self.keys,
        )?;
        self.store_legacy_packing_attestation(&attestation)?;
        Ok(attestation)
    }

    pub(crate) fn store_legacy_packing_attestation(
        &mut self,
        attestation: &SignedRecord<mb_core::LegacyPackingAttestation>,
    ) -> Result<()> {
        attestation.verify(mb_core::LEGACY_PACKING_ATTESTATION_DOMAIN)?;
        let state = self
            .dynamic_guild_state()?
            .context("legacy packing attestation requires dynamic guild state")?;
        if attestation.value.guild_id != state.guild_id
            || attestation.value.membership_epoch != state.membership_epoch
            || !state
                .active_members()
                .any(|member| member.node_id == attestation.signer)
        {
            anyhow::bail!("legacy packing attestation signer is not currently authorized");
        }
        let bytes = canonical_bytes(attestation)?;
        self.control.put_record(
            "legacy-packing-attestation",
            blake3::hash(&bytes).as_bytes(),
            &bytes,
        )?;
        Ok(())
    }

    pub(crate) fn legacy_packing_attestation_index(
        &self,
        guild_id: [u8; 32],
    ) -> Result<LegacyPackingAttestationIndex> {
        let mut attestations = LegacyPackingAttestationIndex::default();
        self.control
            .for_each_record_value("legacy-packing-attestation", |bytes| {
                attestations.scan.rows_read += 1;
                attestations.scan.largest_row_bytes =
                    attestations.scan.largest_row_bytes.max(bytes.len());
                let attestation: SignedRecord<mb_core::LegacyPackingAttestation> =
                    decode_canonical(bytes)?;
                attestation.verify(mb_core::LEGACY_PACKING_ATTESTATION_DOMAIN)?;
                attestations.scan.signatures_verified += 1;
                if attestation.value.guild_id == guild_id {
                    attestations.scan.retained_records += 1;
                    attestations.scan.retained_encoded_bytes += bytes.len();
                    attestations.scan.peak_journal_payload_bytes = attestations
                        .scan
                        .peak_journal_payload_bytes
                        .max(attestations.scan.retained_encoded_bytes + bytes.len());
                    attestations
                        .entries
                        .entry((
                            attestation.value.owner,
                            attestation.value.protected_root,
                            attestation.value.object_id,
                        ))
                        .or_default()
                        .push(attestation);
                }
                Ok(())
            })?;
        for entries in attestations.entries.values_mut() {
            entries.sort_by_key(|attestation| attestation.signer);
        }
        Ok(attestations)
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

    pub(crate) fn store_packing_update(
        &mut self,
        guild_id: [u8; 32],
        update: &PackingUpdate,
    ) -> Result<()> {
        update.catalog.validate()?;
        let mut records = Vec::with_capacity(update.changed_sectors.len());
        for sector in &update.changed_sectors {
            validate_packed_sector(update.catalog.profile, sector)?;
            if update
                .catalog
                .sectors
                .get(sector.descriptor.sector_index as usize)
                != Some(&sector.descriptor)
            {
                anyhow::bail!("packed update sector is absent from its catalog");
            }
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

    pub(crate) fn release_distributed_packed_sectors(
        &mut self,
        guild_id: [u8; 32],
        catalog: &PackedCatalog,
    ) -> Result<u64> {
        catalog.validate()?;
        let state = self
            .dynamic_guild_state()?
            .context("packed release requires dynamic guild state")?;
        let mut released = 0_u64;
        for descriptor in &catalog.sectors {
            let (shard_index, owner) = state
                .coding_groups
                .iter()
                .filter(|retained| retained.retired_at_event.is_none())
                .find_map(|retained| {
                    retained
                        .group
                        .roles
                        .iter()
                        .enumerate()
                        .find_map(|(index, role)| match role {
                            ShardRoleV2::Information(information)
                                if !information.sector.virtual_zero
                                    && information.sector.id == descriptor.id
                                    && information.sector.commitment == descriptor.commitment =>
                            {
                                Some((index as u16, information.owner))
                            }
                            _ => None,
                        })
                })
                .context("packed sector has no active distributed placement")?;
            if owner == self.keys.node_id() {
                let object =
                    self.volumes
                        .load_ready_variable(&self.control, &descriptor.id, shard_index)?;
                if object.guild_id != guild_id
                    || object.group_id != descriptor.id
                    || object.commitment != descriptor.commitment
                {
                    anyhow::bail!("local packed placement conflicts with its coding group");
                }
            }
            if self.control.delete_record(
                "packed-sector",
                &packed_record_id(&guild_id, &descriptor.id),
            )? {
                released += 1;
            }
        }
        Ok(released)
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

    #[cfg(test)]
    pub(crate) fn enqueue_coding_launch(
        &mut self,
        plan: SignedRecord<CodingAttemptPlan>,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        self.enqueue_coding_launch_with_information(plan, None)
    }

    pub(crate) fn enqueue_coding_launch_with_information(
        &mut self,
        mut plan: SignedRecord<CodingAttemptPlan>,
        information_to_stage: Option<BTreeMap<SectorId, PackedSectorDescriptor>>,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        self.validate_coding_attempt_plan(&plan)?;
        if plan.value.delegator != self.keys.node_id() {
            anyhow::bail!("only the coding delegator may queue its launch");
        }
        if let Some(bytes) = self
            .control
            .get_record("coding-retired-attempt", &plan.value.attempt_id)?
        {
            let retired: SignedRecord<CodingAttemptPlan> = decode_canonical(&bytes)?;
            self.validate_coding_attempt_authority(&retired)?;
            if !same_coding_lane_attempt(&retired.value, &plan.value) {
                anyhow::bail!("coding launch conflicts with a retired attempt");
            }
            if let Some(bytes) = self
                .control
                .get_record("coding-launch-job", &plan.value.attempt_id)?
            {
                let cleanup: CodingLaunchJob = decode_canonical(&bytes)?;
                if cleanup.plan != retired {
                    anyhow::bail!("retired launch cleanup conflicts with its signed plan");
                }
                // This durable cleanup still owns the renewal transition.
                return Ok(cleanup.plan);
            }
            // The deterministic initial ID can be proposed again after its
            // successor fails. Never allocate or sign new bytes under that ID.
            let mut value = plan.value.clone();
            loop {
                rand::rngs::OsRng.fill_bytes(&mut value.attempt_id);
                if value.attempt_id != [0; 16] && value.attempt_id != retired.value.attempt_id {
                    break;
                }
            }
            plan = self.sign_coding_attempt_plan(value)?;
        }
        // Prefer verified evidence, then a live retry successor. Completed
        // parents retain their signed children forever, including failed and
        // retired children; historical authority alone does not make them work.
        if matches!(plan.value.format_version, 2 | 3) {
            let state = self
                .dynamic_guild_state()?
                .context("coding launch requires dynamic guild state")?;
            for (_, bytes) in self.control.records("coding-activation-job")? {
                let activation: CodingActivationJob = decode_canonical(&bytes)?;
                let prior = &activation.transcript.value.plan;
                if same_coding_lane_geometry(&prior.value, &plan.value) {
                    self.validate_coding_attempt_authority(prior)?;
                    if replay_coding_transcript(&activation.transcript)?
                        != CodingReplayFinding::Verified
                    {
                        // Negative evidence owns holder cleanup, but never
                        // covers this lane. Wait for that cleanup before a
                        // fresh launch; its deterministic ID may be the same
                        // as the completed negative attempt.
                        if !activation.complete {
                            return Ok(prior.clone());
                        }
                        if plan.value.attempt_id == prior.value.attempt_id {
                            let mut value = plan.value.clone();
                            loop {
                                rand::rngs::OsRng.fill_bytes(&mut value.attempt_id);
                                if value.attempt_id != [0; 16]
                                    && value.attempt_id != prior.value.attempt_id
                                {
                                    break;
                                }
                            }
                            plan = self.sign_coding_attempt_plan(value)?;
                        }
                        continue;
                    }
                    let group = &activation.transcript.value.manifest.value.group;
                    if state.validate_current_group_placement(group).is_ok()
                        && (!activation.complete
                            || state.coding_groups.iter().any(|retained| {
                                retained.retired_at_event.is_none() && retained.group == *group
                            }))
                    {
                        return Ok(prior.clone());
                    }
                    if !activation.complete {
                        return Ok(prior.clone());
                    }
                    if plan.value.attempt_id == prior.value.attempt_id {
                        let mut value = plan.value.clone();
                        loop {
                            rand::rngs::OsRng.fill_bytes(&mut value.attempt_id);
                            if value.attempt_id != [0; 16]
                                && value.attempt_id != prior.value.attempt_id
                            {
                                break;
                            }
                        }
                        plan = self.sign_coding_attempt_plan(value)?;
                    }
                }
            }
            for (_, bytes) in self.control.records("coding-retry-job")? {
                let retry: CodingRetryJob = decode_canonical(&bytes)?;
                if let Some(prior) = retry.retry_plan
                    && same_coding_lane(&prior.value, &plan.value)
                {
                    self.validate_coding_attempt_authority(&prior)?;
                    let id = prior.value.attempt_id;
                    if self.validate_coding_attempt_plan(&prior).is_ok()
                        && self.control.get_record("coding-retry-job", &id)?.is_none()
                        && self
                            .control
                            .get_record("coding-retired-attempt", &id)?
                            .is_none()
                        && (!retry.complete
                            || self
                                .control
                                .get_record("delegated-coding-job", &id)?
                                .map(|bytes| decode_canonical::<DelegatedCodingJob>(&bytes))
                                .transpose()?
                                .is_none_or(|delegated| {
                                    !matches!(
                                        delegated.state,
                                        DelegatedCodingJobState::Complete
                                            | DelegatedCodingJobState::Failed
                                    )
                                }))
                    {
                        return Ok(prior);
                    }
                }
            }
            // Reuse an in-flight pre-epoch-binding launch as well. Its signed
            // ID stays immutable when the planner begins generating newer IDs.
            for (_, bytes) in self.control.records("coding-launch-job")? {
                let launch: CodingLaunchJob = decode_canonical(&bytes)?;
                if launch.plan.value.attempt_id != plan.value.attempt_id
                    && same_coding_lane(&launch.plan.value, &plan.value)
                    && self.validate_coding_attempt_plan(&launch.plan).is_ok()
                    && self
                        .control
                        .get_record("coding-retry-job", &launch.plan.value.attempt_id)?
                        .is_none()
                    && self
                        .control
                        .get_record("coding-retired-attempt", &launch.plan.value.attempt_id)?
                        .is_none()
                {
                    return Ok(launch.plan);
                }
            }
        }
        let excluded = self.coding_lane_retry_excluded_coordinators(
            plan.value.checkpoint_hash,
            plan.value.membership_epoch,
            &plan.value.geometry,
            plan.value.information_roots.as_deref().unwrap_or_default(),
        )?;
        if plan.value.format_version == 3
            && (excluded.contains(&plan.value.coding_coordinator)
                || excluded.contains(&plan.value.verification_coordinator))
        {
            anyhow::bail!("coding replacement requires fresh coordinators after failure");
        }
        let attempt_id = plan.value.attempt_id;
        if let Some(bytes) = self.control.get_record("coding-retry-job", &attempt_id)? {
            let existing: CodingRetryJob = decode_canonical(&bytes)?;
            existing.failure.verify(CODING_FAILURE_REPORT_DOMAIN)?;
            existing.failure.value.validate()?;
            let prior = &existing.failure.value.plan;
            if existing.format_version != 1 || !same_coding_lane_attempt(&prior.value, &plan.value)
            {
                anyhow::bail!("coding launch conflicts with a durable retry");
            }
            self.control
                .delete_record("coding-launch-job", &attempt_id)?;
            return Ok(prior.clone());
        }
        if let Some(bytes) = self
            .control
            .get_record("coding-activation-job", &attempt_id)?
        {
            let existing: CodingActivationJob = decode_canonical(&bytes)?;
            let prior = &existing.transcript.value.plan;
            if existing.format_version != 1 || !same_coding_lane_attempt(&prior.value, &plan.value)
            {
                anyhow::bail!("coding launch conflicts with durable verifier evidence");
            }
            return Ok(prior.clone());
        }
        if let Some(bytes) = self.control.get_record("coding-launch-job", &attempt_id)? {
            let existing: CodingLaunchJob = decode_canonical(&bytes)?;
            if existing.format_version != 1
                || !same_coding_lane_attempt(&existing.plan.value, &plan.value)
            {
                anyhow::bail!("coding launch conflicts with a durable attempt");
            }
            // Replanning coalesces with the durable owner. Do not revoke its
            // acknowledgement or erase a cleanup deferral; expiry recovery
            // still needs to distinguish an acknowledged silent attempt.
            return Ok(existing.plan);
        }
        let job = CodingLaunchJob {
            format_version: 1,
            plan: plan.clone(),
            dispatched: false,
            error: None,
        };
        let mut records = vec![(
            "coding-launch-job".to_owned(),
            attempt_id.to_vec(),
            canonical_bytes(&job)?,
        )];
        if let Some(information) = information_to_stage {
            records.push((
                "coding-launch-information".to_owned(),
                attempt_id.to_vec(),
                canonical_bytes(&information)?,
            ));
        }
        self.control.put_records(&records)?;
        Ok(plan)
    }

    pub(crate) fn coding_lane_retry_excluded_coordinators(
        &self,
        checkpoint_hash: [u8; 32],
        membership_epoch: u64,
        geometry: &mb_core::CodingPlanGeometry,
        information_roots: &[[u8; 32]],
    ) -> Result<BTreeSet<NodeId>> {
        let mut excluded = BTreeSet::new();
        for (_, bytes) in self.control.records("coding-retry-job")? {
            let job: CodingRetryJob = decode_canonical(&bytes)?;
            let failed = &job.failure.value.plan.value;
            if job.complete
                || failed.format_version != 3
                || failed.checkpoint_hash != checkpoint_hash
                || failed.membership_epoch != membership_epoch
                || failed.geometry != *geometry
                || failed.delegator != self.keys.node_id()
                || failed.information_roots.as_deref() != Some(information_roots)
            {
                continue;
            }
            if let Some(child) = &job.retry_plan
                && self
                    .control
                    .get_record("coding-retry-job", &child.value.attempt_id)?
                    .is_some()
            {
                continue; // The failed child owns the next generation's exclusions.
            }
            let previous = self.coding_retry_previous_plan(&job)?;
            let prior = if let Some(child) = &job.retry_plan
                && (child.value.expires_at_unix_seconds < unix_seconds()
                    || self
                        .control
                        .get_record("coding-retired-attempt", &child.value.attempt_id)?
                        .is_some())
            {
                child
            } else {
                &previous
            };
            self.validate_coding_attempt_authority(prior)?;
            excluded.insert(prior.value.coding_coordinator);
            excluded.insert(prior.value.verification_coordinator);
        }
        Ok(excluded)
    }

    pub(crate) fn coding_invalid_coordinators_for_source(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<BTreeSet<NodeId>> {
        self.validate_coding_attempt_authority(plan)?;
        let mut excluded = BTreeSet::new();
        for (_, bytes) in self.control.records("coding-activation-job")? {
            let activation: CodingActivationJob = decode_canonical(&bytes)?;
            if same_coding_source_lane(&activation.transcript.value.plan.value, &plan.value)
                && let CodingReplayFinding::InvalidCoding { coordinator } =
                    replay_coding_transcript(&activation.transcript)?
            {
                excluded.insert(coordinator);
            }
        }
        Ok(excluded)
    }

    #[cfg(test)]
    pub(crate) fn claim_coding_launch(&self) -> Result<Option<CodingLaunchJob>> {
        self.claim_coding_launch_after(None)
    }

    pub(crate) fn claim_coding_launch_after(
        &self,
        after: Option<[u8; 16]>,
    ) -> Result<Option<CodingLaunchJob>> {
        let records = self.control.records("coding-launch-job")?;
        if records.is_empty() {
            return Ok(None);
        }
        let current_membership_epoch = self
            .dynamic_guild_state()?
            .context("coding launch requires dynamic guild state")?
            .membership_epoch;
        let mut stale = None;
        let mut first = None;
        for (_, bytes) in records {
            let job: CodingLaunchJob = decode_canonical(&bytes)?;
            if job.format_version != 1
                || job.plan.value.delegator != self.keys.node_id()
                || job.plan.value.attempt_id == [0; 16]
            {
                anyhow::bail!("durable coding launch job is invalid");
            }
            self.validate_coding_attempt_authority(&job.plan)?;
            let current = job.plan.value.membership_epoch == current_membership_epoch;
            if current && job.dispatched && job.plan.value.expires_at_unix_seconds >= unix_seconds()
            {
                continue;
            }
            if let Some(cursor) = after {
                if job.plan.value.attempt_id > cursor {
                    return Ok(Some(job));
                }
                first.get_or_insert(job);
            } else if current {
                return Ok(Some(job));
            } else {
                stale.get_or_insert(job);
            }
        }
        Ok(first.or(stale))
    }

    pub(crate) fn coding_launch_has_verified_result(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        let Some(bytes) = self
            .control
            .get_record("coding-activation-job", &plan.value.attempt_id)?
        else {
            return Ok(false);
        };
        let activation: CodingActivationJob = decode_canonical(&bytes)?;
        if activation.format_version != 1 || activation.transcript.value.plan != *plan {
            anyhow::bail!("coding launch conflicts with its verifier result");
        }
        Ok(replay_coding_transcript(&activation.transcript)? == CodingReplayFinding::Verified)
    }

    fn coding_activation_has_coverage(&self, activation: &CodingActivationJob) -> Result<bool> {
        if replay_coding_transcript(&activation.transcript)? != CodingReplayFinding::Verified {
            return Ok(false);
        }
        let group = &activation.transcript.value.manifest.value.group;
        let state = self
            .dynamic_guild_state()?
            .context("coding activation requires dynamic guild state")?;
        Ok(state
            .coding_groups
            .iter()
            .any(|retained| retained.retired_at_event.is_none() && retained.group == *group))
    }

    fn coding_launch_submission_plan(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<Option<SignedRecord<CodingAttemptPlan>>> {
        let plan = if let Some(bytes) = self
            .control
            .get_record("coding-activation-job", &attempt_id)?
        {
            let job: CodingActivationJob = decode_canonical(&bytes)?;
            if job.format_version != 1 {
                anyhow::bail!("coding activation owner has an invalid format");
            }
            replay_coding_transcript(&job.transcript)?;
            job.transcript.value.plan
        } else if let Some(bytes) = self.control.get_record("coding-retry-job", &attempt_id)? {
            let job: CodingRetryJob = decode_canonical(&bytes)?;
            job.failure.verify(CODING_FAILURE_REPORT_DOMAIN)?;
            job.failure.value.validate()?;
            if job.format_version != 1
                || job.failure.signer != job.failure.value.plan.value.coding_coordinator
            {
                anyhow::bail!("coding retry owner has an invalid failure report");
            }
            job.failure.value.plan
        } else {
            return Ok(None);
        };
        self.validate_coding_attempt_authority(&plan)?;
        if plan.value.attempt_id != attempt_id || plan.value.delegator != self.keys.node_id() {
            anyhow::bail!("coding submission owner conflicts with its launch ID");
        }
        Ok(Some(plan))
    }

    pub(crate) fn coding_launch_submission_is_failure(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<Option<bool>> {
        let Some(owner) = self.coding_launch_submission_plan(plan.value.attempt_id)? else {
            return Ok(None);
        };
        if owner != *plan {
            anyhow::bail!("coding launch conflicts with its submitted owner");
        }
        Ok(Some(
            self.control
                .get_record("coding-retry-job", &plan.value.attempt_id)?
                .is_some(),
        ))
    }

    pub(crate) fn retire_coding_launch_for_cleanup(&self, job: &CodingLaunchJob) -> Result<bool> {
        let plan = &job.plan;
        self.validate_coding_attempt_authority(plan)?;
        if let Some(submitted) = self.coding_launch_submission_plan(plan.value.attempt_id)? {
            if submitted != *plan {
                anyhow::bail!("coding launch conflicts with its submitted owner");
            }
            // Recover a crash after durable submission ownership was written
            // but before its redundant launch was removed. Keep retry inputs.
            self.abandon_coding_launch(plan.value.attempt_id)?;
            return Ok(false);
        }
        if self
            .control
            .get_record("coding-launch-job", &plan.value.attempt_id)?
            != Some(canonical_bytes(job)?)
        {
            anyhow::bail!("coding launch changed before cleanup retirement");
        }
        // Failure acceptance and retirement share the writer lock. A failure
        // accepted first owns a retry; one arriving later is archived without
        // deleting the launch that still owns cleanup and renewal.
        self.retire_coding_retry_plan(plan)
    }

    fn coding_launch_waits_for_negative_cleanup(
        &self,
        prior: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        for (_, bytes) in self.control.records("coding-activation-job")? {
            let activation: CodingActivationJob = decode_canonical(&bytes)?;
            let candidate = &activation.transcript.value.plan;
            if !activation.complete
                && candidate.value.attempt_id != prior.value.attempt_id
                && coding_renewal_can_follow(&prior.value, &candidate.value)
            {
                self.validate_coding_attempt_authority(candidate)?;
                if replay_coding_transcript(&activation.transcript)?
                    != CodingReplayFinding::Verified
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn coding_launch_renewal_candidate(
        &self,
        prior: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<Option<CodingLaunchRenewalCandidate>> {
        let state = self
            .dynamic_guild_state()?
            .context("coding renewal requires a guild")?;
        for (_, bytes) in self.control.records("coding-activation-job")? {
            let activation: CodingActivationJob = decode_canonical(&bytes)?;
            let candidate = &activation.transcript.value.plan;
            if candidate.value.attempt_id != prior.value.attempt_id
                && coding_renewal_can_follow(&prior.value, &candidate.value)
            {
                self.validate_coding_attempt_authority(candidate)?;
                let group = &activation.transcript.value.manifest.value.group;
                if replay_coding_transcript(&activation.transcript)?
                    == CodingReplayFinding::Verified
                    && state.validate_current_group_placement(group).is_ok()
                    && (!activation.complete
                        || state.coding_groups.iter().any(|retained| {
                            retained.retired_at_event.is_none() && retained.group == *group
                        }))
                {
                    return Ok(Some(CodingLaunchRenewalCandidate::Activation {
                        plan: candidate.clone(),
                        pending: !activation.complete,
                    }));
                }
            }
        }
        for (_, bytes) in self.control.records("coding-retry-job")? {
            let retry: CodingRetryJob = decode_canonical(&bytes)?;
            if let Some(candidate) = &retry.retry_plan
                && candidate.value.attempt_id != prior.value.attempt_id
                && coding_renewal_can_follow(&prior.value, &candidate.value)
            {
                self.validate_coding_attempt_authority(candidate)?;
                let id = candidate.value.attempt_id;
                if self.validate_coding_attempt_plan(candidate).is_ok()
                    && self
                        .control
                        .get_record("coding-retired-attempt", &id)?
                        .is_none()
                    && self.control.get_record("coding-retry-job", &id)?.is_none()
                    && (!retry.complete
                        || self
                            .control
                            .get_record("delegated-coding-job", &id)?
                            .map(|bytes| decode_canonical::<DelegatedCodingJob>(&bytes))
                            .transpose()?
                            .is_none_or(|delegated| {
                                !matches!(
                                    delegated.state,
                                    DelegatedCodingJobState::Complete
                                        | DelegatedCodingJobState::Failed
                                )
                            }))
                {
                    return Ok(Some(CodingLaunchRenewalCandidate::Retry(candidate.clone())));
                }
            }
        }
        for (_, bytes) in self.control.records("coding-launch-job")? {
            let existing: CodingLaunchJob = decode_canonical(&bytes)?;
            let candidate = &existing.plan;
            if candidate.value.attempt_id != prior.value.attempt_id
                && coding_renewal_can_follow(&prior.value, &candidate.value)
                && self.validate_coding_attempt_plan(candidate).is_ok()
                && self
                    .control
                    .get_record("coding-retired-attempt", &candidate.value.attempt_id)?
                    .is_none()
                && self
                    .control
                    .get_record("coding-retry-job", &candidate.value.attempt_id)?
                    .is_none()
            {
                return Ok(Some(CodingLaunchRenewalCandidate::Launch(existing)));
            }
        }
        Ok(None)
    }

    pub(crate) fn coding_launch_has_renewal(
        &self,
        prior: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        Ok(self
            .control
            .get_record("coding-launch-successor", &prior.value.attempt_id)?
            .is_some()
            || self.coding_launch_waits_for_negative_cleanup(prior)?
            || self.coding_launch_renewal_candidate(prior)?.is_some())
    }

    pub(crate) fn renew_coding_launch_after_cleanup(
        &mut self,
        job: &CodingLaunchJob,
        coordinators: Option<(NodeId, NodeId)>,
        eligible_parity_holders: Option<BTreeSet<NodeId>>,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        let prior = &job.plan;
        let id = prior.value.attempt_id;
        self.validate_coding_attempt_authority(prior)?;
        if prior.value.expires_at_unix_seconds >= unix_seconds()
            || self.control.get_record("coding-retired-attempt", &id)?
                != Some(canonical_bytes(prior)?)
            || self.control.get_record("coding-launch-job", &id)? != Some(canonical_bytes(job)?)
        {
            anyhow::bail!("expired coding launch changed or was not fenced before cleanup");
        }
        // The successor, staging intent, and lineage are one transaction. If a
        // crash precedes removing the parent, repeating cleanup reuses this ID.
        let successor =
            if let Some(bytes) = self.control.get_record("coding-launch-successor", &id)? {
                decode_canonical(&bytes)?
            } else {
                if self.coding_launch_waits_for_negative_cleanup(prior)? {
                    anyhow::bail!("coding launch renewal waits for negative activation cleanup");
                }
                let replacement = self.coding_launch_renewal_candidate(prior)?;
                let new_launch = replacement.is_none();
                let owner = match replacement {
                    Some(existing) => existing,
                    None => {
                        let (coding_coordinator, verification_coordinator) = coordinators
                            .context("coding launch renewal requires reachable coordinators")?;
                        let invalid = self.coding_invalid_coordinators_for_source(prior)?;
                        if invalid.contains(&coding_coordinator)
                            || invalid.contains(&verification_coordinator)
                        {
                            anyhow::bail!("coding launch renewal selected an invalid coder");
                        }
                        let mut value = prior.value.clone();
                        if value.format_version == 2
                            && value.information_roots.as_ref().is_some_and(|roots| {
                                roots
                                    .iter()
                                    .zip(&value.geometry.information)
                                    .any(|(root, role)| {
                                        !role.sector.virtual_zero
                                            && *root != role.sector.commitment.root
                                    })
                            })
                        {
                            value.format_version = 3;
                        }
                        if let Some(eligible_holders) = &eligible_parity_holders
                            && value
                                .geometry
                                .parity
                                .iter()
                                .any(|placement| !eligible_holders.contains(&placement.holder))
                        {
                            let state = self
                                .dynamic_guild_state()?
                                .context("coding launch renewal requires dynamic guild state")?;
                            let eligible = state
                                .active_members()
                                .filter(|member| eligible_holders.contains(&member.node_id))
                                .collect::<Vec<_>>();
                            value.geometry = choose_usable_parity_geometry(
                                &value.geometry,
                                &eligible,
                                |geometry| Ok(*geometry != prior.value.geometry),
                            )?
                            .context("coding launch renewal has no usable parity placement")?;
                        }
                        value.coding_coordinator = coding_coordinator;
                        value.verification_coordinator = verification_coordinator;
                        loop {
                            rand::rngs::OsRng.fill_bytes(&mut value.attempt_id);
                            if value.attempt_id != [0; 16] && value.attempt_id != id {
                                break;
                            }
                        }
                        value.expires_at_unix_seconds = unix_seconds()
                            .checked_add(24 * 60 * 60)
                            .context("coding launch renewal expiry overflow")?;
                        CodingLaunchRenewalCandidate::Launch(CodingLaunchJob {
                            format_version: 1,
                            plan: self.sign_coding_attempt_plan(value)?,
                            dispatched: false,
                            error: None,
                        })
                    }
                };
                let successor = owner.plan().clone();
                let mut records = vec![(
                    "coding-launch-successor".to_owned(),
                    id.to_vec(),
                    canonical_bytes(&successor)?,
                )];
                if new_launch {
                    let CodingLaunchRenewalCandidate::Launch(launch) = &owner else {
                        anyhow::bail!("new coding renewal has no launch owner");
                    };
                    records.push((
                        "coding-launch-job".to_owned(),
                        successor.value.attempt_id.to_vec(),
                        canonical_bytes(&launch)?,
                    ));
                }
                if owner.needs_input_intent()
                    && self
                        .coding_launch_information_to_stage(successor.value.attempt_id)?
                        .is_none()
                    && let Some(information) = self.coding_launch_information_to_stage(id)?
                {
                    records.push((
                        "coding-launch-information".to_owned(),
                        successor.value.attempt_id.to_vec(),
                        canonical_bytes(&information)?,
                    ));
                }
                self.control.put_records(&records)?;
                successor
            };
        self.validate_coding_attempt_authority(&successor)?;
        if !coding_renewal_can_follow_with_new_parity(&prior.value, &successor.value)
            || successor.value.attempt_id == id
        {
            anyhow::bail!("coding launch successor conflicts with its retired parent");
        }
        self.abandon_coding_launch(id)?;
        Ok(successor)
    }

    #[cfg(test)]
    pub(crate) fn coding_launch_successor_for_test(
        &self,
        id: [u8; 16],
    ) -> Result<Option<SignedRecord<CodingAttemptPlan>>> {
        self.control
            .get_record("coding-launch-successor", &id)?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    #[cfg(test)]
    pub(crate) fn retired_coding_plan_for_test(
        &self,
        id: [u8; 16],
    ) -> Result<Option<SignedRecord<CodingAttemptPlan>>> {
        self.control
            .get_record("coding-retired-attempt", &id)?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
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

    pub(crate) fn coding_launch_information_to_stage(
        &self,
        attempt_id: [u8; 16],
    ) -> Result<Option<BTreeMap<SectorId, PackedSectorDescriptor>>> {
        self.control
            .get_record("coding-launch-information", &attempt_id)?
            .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
            .transpose()
    }

    pub(crate) fn complete_coding_launch_information(&self, attempt_id: [u8; 16]) -> Result<()> {
        self.control
            .delete_record("coding-launch-staged", &attempt_id)?;
        self.control
            .delete_record("coding-launch-information", &attempt_id)?;
        Ok(())
    }

    pub(crate) fn pending_coding_launch_information(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<Option<BTreeMap<SectorId, PackedSectorDescriptor>>> {
        if let Some(bytes) = self
            .control
            .get_record("coding-launch-staged", &plan.value.attempt_id)?
        {
            if decode_canonical::<[u8; 32]>(&bytes)? != plan.value.hash()? {
                anyhow::bail!("staging completion conflicts with its signed launch");
            }
            return Ok(None);
        }
        self.coding_launch_information_to_stage(plan.value.attempt_id)
    }

    pub(crate) fn mark_coding_launch_staged(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<()> {
        self.control.put_record(
            "coding-launch-staged",
            &plan.value.attempt_id,
            &canonical_bytes(&plan.value.hash()?)?,
        )?;
        Ok(())
    }

    pub(crate) fn abandon_coding_launch(&self, attempt_id: [u8; 16]) -> Result<()> {
        let pending_activation = self
            .control
            .get_record("coding-activation-job", &attempt_id)?
            .map(|bytes| decode_canonical::<CodingActivationJob>(&bytes))
            .transpose()?
            .is_some_and(|activation| !activation.complete);
        if pending_activation
            || self
                .control
                .get_record("coding-retry-job", &attempt_id)?
                .is_some()
        {
            self.control
                .delete_record("coding-launch-staged", &attempt_id)?;
        } else {
            self.complete_coding_launch_information(attempt_id)?;
        }
        self.control
            .delete_record("coding-launch-job", &attempt_id)?;
        Ok(())
    }

    pub(crate) fn defer_coding_launch(&self, attempt_id: [u8; 16], error: &str) -> Result<()> {
        let mut error = error.to_owned();
        truncate_utf8(&mut error, 4096);
        let bytes = self.control.get_record("coding-launch-job", &attempt_id)?;
        if bytes.is_none() && self.coding_launch_submission_plan(attempt_id)?.is_some() {
            return Ok(());
        }
        let bytes = bytes.context("coding launch job is unavailable")?;
        let job: CodingLaunchJob = decode_canonical(&bytes)?;
        // Expiry cleanup can defer an acknowledged launch. Retain that state
        // so a later renewal still avoids its silent coordinator pair.
        self.update_coding_launch(attempt_id, job.dispatched, Some(error))
    }

    fn update_coding_launch(
        &self,
        attempt_id: [u8; 16],
        dispatched: bool,
        error: Option<String>,
    ) -> Result<()> {
        let bytes = self.control.get_record("coding-launch-job", &attempt_id)?;
        if bytes.is_none() && self.coding_launch_submission_plan(attempt_id)?.is_some() {
            return Ok(());
        }
        let bytes = bytes.context("coding launch job is unavailable")?;
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

    #[cfg(test)]
    pub(crate) fn install_coding_launch_for_test(&self, job: &CodingLaunchJob) -> Result<()> {
        self.validate_coding_attempt_plan(&job.plan)?;
        self.put_coding_launch_job(job)
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
            if job.state == DelegatedCodingJobState::Complete {
                continue;
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
            || manifest.value.attempt_id != plan.value.attempt_id
            || manifest.value.plan_hash != plan_hash
        {
            anyhow::bail!("coding root manifest or staged receipt set is invalid");
        }
        manifest.value.validate_for_plan(&plan.value)?;
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
        manifest.value.validate_for_plan(&plan.value)?;
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
        if self.ready_coding_information(plan, shard_index)?.is_some() {
            return Ok(role.sector.commitment.byte_len);
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
        if self.ready_coding_information(plan, shard_index)?.is_some() {
            return Ok(());
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
        if let Some(bytes) = self.ready_coding_information(plan, shard_index)? {
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

    /// Reuse an authenticated READY input without taking ownership of its old
    /// attempt record. Upgrading evidence must not rewrite historical storage.
    fn ready_coding_information(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
    ) -> Result<Option<Vec<u8>>> {
        let role = self.validate_local_coding_information(plan, shard_index)?;
        Ok(self
            .volumes
            .load_ready_variable(&self.control, &role.sector.id, shard_index)
            .ok()
            .filter(|object| {
                object.guild_id == plan.value.geometry.guild_id
                    && object.commitment == role.sector.commitment
            })
            .map(|object| object.bytes))
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
            || manifest.value.attempt_id != plan.value.attempt_id
            || manifest.value.plan_hash != plan_hash
        {
            anyhow::bail!("coding root manifest conflicts with the delegated plan");
        }
        manifest.value.validate_for_plan(&plan.value)?;
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
        manifest.value.validate_for_plan(&plan.value)?;
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
            ShardRoleV2::Information(_) => {
                self.coding_information_range(plan, shard_index, leaf, 1)?
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
        if self
            .control
            .get_record("coding-retired-attempt", &id)?
            .is_some()
            || self.control.get_record("coding-retry-job", &id)?.is_some()
        {
            anyhow::bail!("coding attempt was failed or retired before result submission");
        }
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
        if let Some(bytes) = self
            .control
            .get_record("coding-retired-attempt", &attempt_id)?
        {
            let retired: SignedRecord<CodingAttemptPlan> = decode_canonical(&bytes)?;
            if retired != *plan {
                anyhow::bail!("late coding failure conflicts with retired plan");
            }
            let bytes = canonical_bytes(&failure)?;
            if self
                .control
                .get_record("coding-retired-failure", &attempt_id)?
                .is_some_and(|existing| existing != bytes)
            {
                anyhow::bail!("retired coding attempt has a different failure report");
            }
            self.control
                .put_record("coding-retired-failure", &attempt_id, &bytes)?;
            return Ok(());
        }
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
        // Keep input intent under this failed ID until a successor has taken
        // durable ownership. Parent receipts are gone, so every successor must
        // stage its own information before delegation.
        let mut records = Vec::new();
        let mut deletions = self.coding_retry_parent_input_deletions(plan, &mut records)?;
        deletions.extend([
            ("coding-launch-job".to_owned(), attempt_id.to_vec()),
            ("coding-launch-staged".to_owned(), attempt_id.to_vec()),
        ]);
        let input = self.coding_retry_information(plan)?;
        records.push((
            "coding-retry-job".to_owned(),
            attempt_id.to_vec(),
            canonical_bytes(&CodingRetryJob {
                format_version: 1,
                failure,
                retry_plan: None,
                complete: false,
                error: None,
            })?,
        ));
        if let Some(input) = input {
            records.push((
                "coding-launch-information".to_owned(),
                attempt_id.to_vec(),
                canonical_bytes(&input)?,
            ));
        }
        self.control.put_records_and_delete(&records, &deletions)?;
        Ok(())
    }

    pub(crate) fn claim_coding_retry(
        &self,
        after: Option<[u8; 16]>,
    ) -> Result<Option<CodingRetryJob>> {
        self.claim_coding_retry_at(after, unix_seconds())
    }

    fn claim_coding_retry_at(
        &self,
        after: Option<[u8; 16]>,
        now: u64,
    ) -> Result<Option<CodingRetryJob>> {
        let mut first = None;
        for (_, bytes) in self.control.records("coding-retry-job")? {
            let mut job: CodingRetryJob = decode_canonical(&bytes)?;
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
            if job.complete && self.coding_retry_needs_recovery(&job, now)? {
                // Acknowledgement is quiescent ownership, not terminal evidence.
                // Reclaim expired, stale or retired successors lacking submission.
                job.complete = false;
                job.error = None;
                self.put_coding_retry_job(&job)?;
            }
            if !job.complete {
                if after.is_none_or(|cursor| job.failure.value.plan.value.attempt_id > cursor) {
                    return Ok(Some(job));
                }
                first.get_or_insert(job);
            }
        }
        Ok(first)
    }

    fn coding_retry_needs_recovery(&self, job: &CodingRetryJob, now: u64) -> Result<bool> {
        let Some(child) = &job.retry_plan else {
            return Ok(false);
        };
        let terminal_hash = *blake3::hash(&canonical_bytes(child)?).as_bytes();
        if let Some(bytes) = self.control.get_record(
            "coding-retry-terminal",
            &job.failure.value.plan.value.attempt_id,
        )? {
            if decode_canonical::<[u8; 32]>(&bytes)? != terminal_hash {
                anyhow::bail!("terminal retry history conflicts with its signed child");
            }
            return Ok(false);
        }
        let epoch = self
            .dynamic_guild_state()?
            .context("coding retry requires dynamic guild state")?
            .membership_epoch;
        let retired = self
            .control
            .get_record("coding-retired-attempt", &child.value.attempt_id)?;
        if job.failure.value.plan.value.membership_epoch == epoch
            && child.value.expires_at_unix_seconds >= now
            && retired.is_none()
        {
            return Ok(false);
        }
        self.validate_coding_attempt_authority(child)?;
        let parent = &job.failure.value.plan.value;
        if child.value.checkpoint_hash != parent.checkpoint_hash
            || child.value.geometry != parent.geometry
            || child.value.delegator != parent.delegator
            || child.value.information_roots != parent.information_roots
        {
            anyhow::bail!("retry successor conflicts with its failed lane");
        }
        if let Some(owner) = self.coding_launch_submission_plan(child.value.attempt_id)? {
            if owner != *child {
                anyhow::bail!("retry successor conflicts with its submitted owner");
            }
            // A negative verifier transcript is a cleanup owner, not
            // successful protection. Activation completion will requeue this
            // parent after holder cleanup, keeping its input intent alive.
            let terminal = match self
                .control
                .get_record("coding-activation-job", &child.value.attempt_id)?
            {
                Some(bytes) => {
                    let activation: CodingActivationJob = decode_canonical(&bytes)?;
                    self.coding_activation_has_coverage(&activation)?
                }
                None => true, // A signed failure owns its own retry chain.
            };
            if terminal {
                self.control.put_record(
                    "coding-retry-terminal",
                    &job.failure.value.plan.value.attempt_id,
                    &canonical_bytes(&terminal_hash)?,
                )?;
            }
            return Ok(false);
        }
        let signed = canonical_bytes(child)?;
        if retired.as_ref().is_some_and(|bytes| bytes != &signed) {
            anyhow::bail!("retry successor conflicts with its retirement fence");
        }
        // Retirement authorizes deletion; it never proves deletion finished.
        // Descriptor-less jobs can still own remote staged parity/reservations.
        // Only explicit terminal metadata or a submitted owner makes this
        // parent quiescent after its child becomes stale or expires.
        Ok(true)
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
        if job.complete {
            anyhow::bail!("completed coding retry cannot prepare another attempt");
        }
        if self.coding_retry_has_replacement(&job)? {
            anyhow::bail!("coding retry was superseded before preparing its successor");
        }
        if let Some(plan) = &job.retry_plan {
            // Also repair intent for a successor prepared by an earlier build.
            let records = self.coding_retry_successor_input_records(&job, plan)?;
            self.control.put_records_and_delete(&records, &[])?;
            return Ok(plan.clone());
        }
        let previous = self.coding_retry_previous_plan(&job)?;
        let prior = &previous.value;
        let invalid = self.coding_invalid_coordinators_for_source(&previous)?;
        if invalid.contains(&coding_coordinator) || invalid.contains(&verification_coordinator) {
            anyhow::bail!("coding retry selected an invalid coder");
        }
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
                format_version: if prior.format_version == 2
                    && prior.information_roots.as_ref().is_some_and(|roots| {
                        roots
                            .iter()
                            .zip(&prior.geometry.information)
                            .any(|(root, role)| {
                                !role.sector.virtual_zero && *root != role.sector.commitment.root
                            })
                    }) {
                    3
                } else {
                    prior.format_version
                },
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
        let mut records = self.coding_retry_successor_input_records(&job, &plan)?;
        job.retry_plan = Some(plan.clone());
        job.error = None;
        records.push((
            "coding-retry-job".to_owned(),
            failed_attempt_id.to_vec(),
            canonical_bytes(&job)?,
        ));
        self.control.put_records_and_delete(&records, &[])?;
        Ok(plan)
    }

    fn coding_retry_information(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<Option<BTreeMap<SectorId, PackedSectorDescriptor>>> {
        if let Some(input) = self.coding_launch_information_to_stage(plan.value.attempt_id)? {
            return Ok(Some(input));
        }
        // Recover older failed jobs whose descriptor record was deleted while
        // their authenticated packed cache remained available at the delegator.
        let mut input = BTreeMap::new();
        for (index, role) in plan.value.geometry.information.iter().enumerate() {
            if role.sector.virtual_zero {
                continue;
            }
            if let Some(bytes) = self.control.get_record(
                "packed-sector",
                &packed_record_id(&plan.value.geometry.guild_id, &role.sector.id),
            )? {
                let record: PackedSectorRecord = decode_canonical(&bytes)?;
                load_packed_sector(
                    &self.control,
                    &plan.value.geometry.guild_id,
                    &role.sector.id,
                )?;
                if record.sector.descriptor.id != role.sector.id
                    || record.sector.descriptor.commitment != role.sector.commitment
                    || plan
                        .value
                        .information_roots
                        .as_ref()
                        .and_then(|roots| roots.get(index))
                        != Some(&record.sector.descriptor.flat_root)
                {
                    anyhow::bail!("cached retry input conflicts with its signed role");
                }
                input.insert(role.sector.id, record.sector.descriptor);
            }
        }
        Ok((!input.is_empty()).then_some(input))
    }

    fn coding_retry_successor_input_records(
        &self,
        job: &CodingRetryJob,
        successor: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<Vec<ControlRecord>> {
        let mut records = Vec::new();
        if self
            .coding_launch_information_to_stage(successor.value.attempt_id)?
            .is_none()
            && let Some(input) = self.coding_retry_information(&job.failure.value.plan)?
        {
            records.push((
                "coding-launch-information".to_owned(),
                successor.value.attempt_id.to_vec(),
                canonical_bytes(&input)?,
            ));
        }
        Ok(records)
    }

    fn coding_retry_parent_input_deletions(
        &self,
        child: &SignedRecord<CodingAttemptPlan>,
        records: &mut Vec<ControlRecord>,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        let mut deletions = Vec::new();
        for (id, bytes) in self.control.records("coding-retry-job")? {
            let parent: CodingRetryJob = decode_canonical(&bytes)?;
            if parent.retry_plan.as_ref() == Some(child) {
                records.push((
                    "coding-retry-terminal".to_owned(),
                    id.clone(),
                    canonical_bytes(blake3::hash(&canonical_bytes(child)?).as_bytes())?,
                ));
                deletions.extend([
                    ("coding-launch-information".to_owned(), id.clone()),
                    ("coding-launch-staged".to_owned(), id),
                ]);
            }
        }
        Ok(deletions)
    }

    pub(crate) fn coding_retry_previous_plan(
        &self,
        job: &CodingRetryJob,
    ) -> Result<SignedRecord<CodingAttemptPlan>> {
        let Some(bytes) = self.control.get_record(
            "coding-retry-parent",
            &job.failure.value.plan.value.attempt_id,
        )?
        else {
            return Ok(job.failure.value.plan.clone());
        };
        let previous: SignedRecord<CodingAttemptPlan> = decode_canonical(&bytes)?;
        self.validate_coding_attempt_authority(&previous)?;
        let prior = &job.failure.value.plan.value;
        if previous.value.checkpoint_hash != prior.checkpoint_hash
            || previous.value.membership_epoch != prior.membership_epoch
            || previous.value.geometry != prior.geometry
            || previous.value.delegator != prior.delegator
            || previous.value.information_roots != prior.information_roots
        {
            anyhow::bail!("expired retry parent conflicts with its coding lane");
        }
        Ok(previous)
    }

    pub(crate) fn coding_retry_has_replacement(&self, job: &CodingRetryJob) -> Result<bool> {
        let prior = &job.failure.value.plan.value;
        let excluded = self.coding_lane_retry_excluded_coordinators(
            prior.checkpoint_hash,
            prior.membership_epoch,
            &prior.geometry,
            prior.information_roots.as_deref().unwrap_or_default(),
        )?;
        let replaces = |plan: &CodingAttemptPlan| {
            matches!(prior.format_version, 2 | 3)
                && plan.format_version == 3
                && plan.attempt_id != prior.attempt_id
                && plan.checkpoint_hash == prior.checkpoint_hash
                && plan.membership_epoch == prior.membership_epoch
                && plan.delegator == prior.delegator
                && plan.geometry == prior.geometry
                && plan.information_roots == prior.information_roots
                && (prior.format_version == 2
                    || !excluded.contains(&plan.coding_coordinator)
                        && !excluded.contains(&plan.verification_coordinator))
        };
        for (_, bytes) in self.control.records("coding-launch-job")? {
            let launch: CodingLaunchJob = decode_canonical(&bytes)?;
            if replaces(&launch.plan.value)
                && self.validate_coding_attempt_authority(&launch.plan).is_ok()
            {
                // An expired or fenced launch still owns cleanup and renewal.
                // Yield to that durable owner before creating a competing retry.
                return Ok(true);
            }
        }
        for (_, bytes) in self.control.records("coding-activation-job")? {
            let activation: CodingActivationJob = decode_canonical(&bytes)?;
            if replaces(&activation.transcript.value.plan.value) {
                self.validate_coding_attempt_authority(&activation.transcript.value.plan)?;
                let finding = replay_coding_transcript(&activation.transcript)?;
                let state = self
                    .dynamic_guild_state()?
                    .context("coding replacement requires dynamic guild state")?;
                let group = &activation.transcript.value.manifest.value.group;
                if finding == CodingReplayFinding::Verified
                    && (self.coding_activation_has_coverage(&activation)?
                        || !activation.complete
                            && state.validate_current_group_placement(group).is_ok())
                {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    pub(crate) fn coding_attempt_is_retired(
        &self,
        caller: NodeId,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        self.validate_coding_attempt_authority(plan)?;
        if caller != plan.value.coding_coordinator || plan.value.delegator != self.keys.node_id() {
            anyhow::bail!("only the assigned coder may query its delegator's retirement");
        }
        let Some(bytes) = self
            .control
            .get_record("coding-retired-attempt", &plan.value.attempt_id)?
        else {
            return Ok(false);
        };
        if decode_canonical::<SignedRecord<CodingAttemptPlan>>(&bytes)? != *plan {
            anyhow::bail!("retired attempt conflicts with its signed plan");
        }
        Ok(true)
    }

    pub(crate) fn retire_delegated_coding_attempt(
        &self,
        caller: NodeId,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        if caller != plan.value.coding_coordinator {
            anyhow::bail!("only the assigned coder may request attempt retirement");
        }
        self.retire_coding_retry_plan(plan)
    }

    // Fence late submissions before remote cleanup. Keep this signed plan even
    // if cleanup or the process is interrupted; a retry never mutates its bytes.
    pub(crate) fn retire_coding_retry_plan(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        self.validate_coding_attempt_authority(plan)?;
        if plan.value.delegator != self.keys.node_id() {
            anyhow::bail!("only the delegator may retire a coding retry");
        }
        if self.coding_launch_has_verified_result(plan)? {
            return Ok(false);
        }
        let bytes = canonical_bytes(plan)?;
        if self
            .control
            .get_record("coding-retired-attempt", &plan.value.attempt_id)?
            .is_some_and(|existing| existing != bytes)
        {
            anyhow::bail!("retired attempt conflicts with its durable signed plan");
        }
        self.control
            .put_record("coding-retired-attempt", &plan.value.attempt_id, &bytes)?;
        Ok(true)
    }

    pub(crate) fn retire_coding_retry_successor(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        if let Some(owner) = self.coding_launch_submission_plan(plan.value.attempt_id)? {
            if owner != *plan {
                anyhow::bail!("retry successor conflicts with its submitted owner");
            }
            return Ok(false);
        }
        self.retire_coding_retry_plan(plan)
    }

    pub(crate) fn renew_coding_retry_after_cleanup(&mut self, job: &CodingRetryJob) -> Result<()> {
        let plan = job
            .retry_plan
            .as_ref()
            .context("coding retry has no successor plan")?;
        if job.complete
            || self
                .control
                .get_record("coding-retry-job", &job.failure.value.plan.value.attempt_id)?
                != Some(canonical_bytes(job)?)
        {
            anyhow::bail!("coding retry changed before renewal");
        }
        if self
            .control
            .get_record("coding-retired-attempt", &plan.value.attempt_id)?
            != Some(canonical_bytes(plan)?)
        {
            anyhow::bail!("coding retry successor was not fenced before cleanup");
        }
        let mut updated = job.clone();
        updated.retry_plan = None;
        updated.error = None;
        self.control.put_records_and_delete(
            &[
                (
                    "coding-retry-parent".to_owned(),
                    job.failure.value.plan.value.attempt_id.to_vec(),
                    canonical_bytes(plan)?,
                ),
                (
                    "coding-retry-job".to_owned(),
                    job.failure.value.plan.value.attempt_id.to_vec(),
                    canonical_bytes(&updated)?,
                ),
            ],
            &[
                (
                    "coding-launch-information".to_owned(),
                    plan.value.attempt_id.to_vec(),
                ),
                (
                    "coding-launch-staged".to_owned(),
                    plan.value.attempt_id.to_vec(),
                ),
            ],
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn install_historical_coding_retry_for_test(
        &self,
        job: &CodingRetryJob,
    ) -> Result<()> {
        self.accept_coding_failure(job.failure.signer, job.failure.clone())?;
        if let Some(plan) = &job.retry_plan {
            self.validate_coding_attempt_authority(plan)?;
        }
        self.put_coding_retry_job(job)
    }

    #[cfg(test)]
    pub(crate) fn coding_retry_evidence_for_test(&self, id: [u8; 16]) -> Result<CodingRetryJob> {
        decode_canonical(
            &self
                .control
                .get_record("coding-retry-job", &id)?
                .context("missing retry")?,
        )
        .map_err(Into::into)
    }

    #[cfg(test)]
    pub(crate) fn coding_launch_jobs_for_test(&self) -> Result<Vec<CodingLaunchJob>> {
        self.control
            .records("coding-launch-job")?
            .into_iter()
            .map(|(_, bytes)| decode_canonical(&bytes).map_err(Into::into))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn delegated_coding_jobs_for_test(&self) -> Result<Vec<DelegatedCodingJob>> {
        self.control
            .records("delegated-coding-job")?
            .into_iter()
            .map(|(_, bytes)| decode_canonical(&bytes).map_err(Into::into))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn coding_activation_jobs_for_test(&self) -> Result<Vec<CodingActivationJob>> {
        self.control
            .records("coding-activation-job")?
            .into_iter()
            .map(|(_, bytes)| decode_canonical(&bytes).map_err(Into::into))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn coding_reservation_count_for_test(&self) -> Result<usize> {
        Ok(self.control.records("volume-attempt-reservation")?.len())
    }

    #[cfg(test)]
    pub(crate) fn coding_staged_receipt_count_for_test(&self) -> Result<usize> {
        Ok(self.control.records("volume-attempt-receipt")?.len())
    }

    #[cfg(test)]
    pub(crate) fn coding_used_bytes_for_test(&self) -> Result<u64> {
        Ok(self
            .storage_status()?
            .iter()
            .filter_map(|volume| volume.used_bytes)
            .sum())
    }

    #[cfg(test)]
    pub(crate) fn complete_coding_retry(&self, failed_attempt_id: [u8; 16]) -> Result<()> {
        self.finish_coding_retry(failed_attempt_id, false)
    }

    #[cfg(test)]
    pub(crate) fn complete_coding_retry_after_cleanup(
        &self,
        failed_attempt_id: [u8; 16],
    ) -> Result<()> {
        self.finish_coding_retry(failed_attempt_id, true)
    }

    pub(crate) fn complete_claimed_coding_retry(
        &self,
        failed_attempt_id: [u8; 16],
        claimed_child: Option<[u8; 16]>,
        cleaned: bool,
    ) -> Result<()> {
        if claimed_child.is_some() {
            let bytes = self
                .control
                .get_record("coding-retry-job", &failed_attempt_id)?
                .context("coding retry job is unavailable")?;
            let current: CodingRetryJob = decode_canonical(&bytes)?;
            if current.retry_plan.is_none() {
                // Activation cleanup requeued this parent after the worker
                // claimed its old child. Do not complete that fresh retry.
                return Ok(());
            }
        }
        self.finish_coding_retry(failed_attempt_id, cleaned)
    }

    fn finish_coding_retry(&self, failed_attempt_id: [u8; 16], cleaned: bool) -> Result<()> {
        let bytes = self
            .control
            .get_record("coding-retry-job", &failed_attempt_id)?
            .context("coding retry job is unavailable")?;
        let mut job: CodingRetryJob = decode_canonical(&bytes)?;
        let (child_owner, child_terminal) = match &job.retry_plan {
            None => (false, false),
            Some(child) => match self.coding_launch_submission_plan(child.value.attempt_id)? {
                None => (false, false),
                Some(owner) if owner == *child => {
                    let terminal = match self
                        .control
                        .get_record("coding-activation-job", &child.value.attempt_id)?
                    {
                        Some(bytes) => {
                            let activation: CodingActivationJob = decode_canonical(&bytes)?;
                            self.coding_activation_has_coverage(&activation)?
                        }
                        None => true, // The child submitted a signed failure.
                    };
                    (true, terminal)
                }
                Some(_) => anyhow::bail!("retry completion conflicts with its child owner"),
            },
        };
        if cleaned
            && !child_owner
            && let Some(child) = &job.retry_plan
            && self
                .control
                .get_record("coding-retired-attempt", &child.value.attempt_id)?
                != Some(canonical_bytes(child)?)
        {
            anyhow::bail!("cleaned retry successor has no matching retirement fence");
        }
        let terminal = job.retry_plan.is_none() || child_terminal || cleaned;
        // Dispatch acknowledgement is not terminal activation. Retain input
        // intent while the successor can still need restaging after expiry.
        let mut deletions = Vec::new();
        if terminal {
            deletions.extend([
                (
                    "coding-launch-information".to_owned(),
                    failed_attempt_id.to_vec(),
                ),
                (
                    "coding-launch-staged".to_owned(),
                    failed_attempt_id.to_vec(),
                ),
            ]);
            if !child_owner && let Some(plan) = &job.retry_plan {
                deletions.extend([
                    (
                        "coding-launch-information".to_owned(),
                        plan.value.attempt_id.to_vec(),
                    ),
                    (
                        "coding-launch-staged".to_owned(),
                        plan.value.attempt_id.to_vec(),
                    ),
                ]);
            }
        }
        job.complete = true;
        job.error = None;
        let mut records = vec![(
            "coding-retry-job".to_owned(),
            failed_attempt_id.to_vec(),
            canonical_bytes(&job)?,
        )];
        if terminal && let Some(child) = &job.retry_plan {
            records.push((
                "coding-retry-terminal".to_owned(),
                failed_attempt_id.to_vec(),
                canonical_bytes(blake3::hash(&canonical_bytes(child)?).as_bytes())?,
            ));
        }
        self.control.put_records_and_delete(&records, &deletions)?;
        Ok(())
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
        let state = self
            .dynamic_guild_state()?
            .context("coding activation requires dynamic guild state")?;
        let current_membership_epoch = state.membership_epoch;
        let next_event_sequence = state
            .event_sequence
            .checked_add(1)
            .context("guild event sequence exhausted")?;
        let locked_group = match self.locked_guild_event_proposal(next_event_sequence)? {
            Some(event) => match event.kind.coding_group_add() {
                Some((group, transcript_hash)) => Some((group.clone(), transcript_hash)),
                None => return Ok(None),
            },
            None => None,
        };
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
                if job.transcript.value.plan.value.membership_epoch != current_membership_epoch
                    && state
                        .validate_current_group_placement(
                            &job.transcript.value.manifest.value.group,
                        )
                        .is_err()
                {
                    stale.get_or_insert(job);
                    continue;
                }
                if let Some((group, transcript_hash)) = &locked_group {
                    let wrong_attempt = match transcript_hash {
                        Some(expected) => {
                            *blake3::hash(&canonical_bytes(&job.transcript)?).as_bytes()
                                != *expected
                        }
                        None => false,
                    };
                    if job.transcript.value.manifest.value.group != *group || wrong_attempt {
                        continue;
                    }
                }
                job.error = None;
                self.put_coding_activation_job(&job)?;
                return Ok(Some(job));
            }
        }
        if locked_group.is_some() {
            Ok(None)
        } else {
            Ok(stale)
        }
    }

    pub(crate) fn mark_retired_coding_activation_for_replan(
        &self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let id = transcript.value.plan.value.attempt_id;
        let bytes = self
            .control
            .get_record("coding-activation-job", &id)?
            .context("coding activation job is unavailable")?;
        let job: CodingActivationJob = decode_canonical(&bytes)?;
        if job.complete || job.transcript != *transcript {
            anyhow::bail!("retired coding activation changed before replanning");
        }
        let state = self
            .dynamic_guild_state()?
            .context("coding activation requires dynamic guild state")?;
        if !state.coding_groups.iter().any(|retained| {
            retained.group == transcript.value.manifest.value.group
                && retained.retired_at_event.is_some()
        }) {
            anyhow::bail!("coding activation group is not retired");
        }
        let hash = *blake3::hash(&canonical_bytes(transcript)?).as_bytes();
        let value = canonical_bytes(&hash)?;
        if let Some(existing) = self.control.get_record("coding-activation-replan", &id)?
            && existing != value
        {
            anyhow::bail!("retired coding activation replan marker conflicts");
        }
        self.control
            .put_record("coding-activation-replan", &id, &value)?;
        Ok(())
    }

    pub(crate) fn coding_activation_needs_replan(
        &self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<bool> {
        let id = transcript.value.plan.value.attempt_id;
        if let Some(value) = self.control.get_record("coding-activation-replan", &id)? {
            let hash: [u8; 32] = decode_canonical(&value)?;
            if hash != *blake3::hash(&canonical_bytes(transcript)?).as_bytes() {
                anyhow::bail!("retired coding activation replan marker conflicts");
            }
            return Ok(true);
        }
        // Retirement and forgetting can both commit before this worker first
        // claims an already verified activation. The exact old transcript is
        // still durable, while the group is absent from current guild state.
        let group_id = transcript.value.manifest.value.group.id;
        let forgotten = self.dynamic_guild_state()?.is_some_and(|state| {
            !state
                .coding_groups
                .iter()
                .any(|retained| retained.group.id == group_id)
        });
        Ok(forgotten
            && self
                .control
                .get_record("coding-group-transcript", &group_id)?
                == Some(canonical_bytes(transcript)?))
    }

    #[cfg(test)]
    pub(crate) fn complete_coding_activation(
        &self,
        attempt_id: [u8; 16],
        covered: bool,
    ) -> Result<bool> {
        let fresh_coordinators = if covered {
            None
        } else {
            let bytes = self
                .control
                .get_record("coding-activation-job", &attempt_id)?
                .context("coding activation job is unavailable")?;
            let job: CodingActivationJob = decode_canonical(&bytes)?;
            let prior = &job.transcript.value.plan.value;
            let fresh = self
                .dynamic_guild_state()?
                .context("coding activation requires dynamic guild state")?
                .active_members()
                .map(|member| member.node_id)
                .filter(|id| {
                    *id != prior.coding_coordinator && *id != prior.verification_coordinator
                })
                .take(2)
                .collect::<Vec<_>>();
            fresh.first().copied().zip(fresh.get(1).copied())
        };
        let eligible = self
            .dynamic_guild_state()?
            .map(|state| {
                state
                    .active_members()
                    .map(|member| member.node_id)
                    .collect()
            })
            .unwrap_or_default();
        self.complete_coding_activation_with_coordinators(
            attempt_id,
            covered,
            fresh_coordinators,
            eligible,
        )
    }

    pub(crate) fn complete_coding_activation_with_coordinators(
        &self,
        attempt_id: [u8; 16],
        covered: bool,
        fresh_coordinators: Option<(NodeId, NodeId)>,
        eligible_parity_holders: BTreeSet<NodeId>,
    ) -> Result<bool> {
        let bytes = self
            .control
            .get_record("coding-activation-job", &attempt_id)?
            .context("coding activation job is unavailable")?;
        let mut job: CodingActivationJob = decode_canonical(&bytes)?;
        if job.complete {
            return Ok(true);
        }
        if covered && !self.coding_activation_has_coverage(&job)? {
            // The group may have retired after the worker installed it. Keep
            // the job and its retry parent until holder cleanup has run.
            return Ok(false);
        }
        let mut records = Vec::new();
        let mut deletions = if covered {
            self.coding_retry_parent_input_deletions(&job.transcript.value.plan, &mut records)?
        } else {
            let mut deletions = Vec::new();
            let mut has_retry_parent = false;
            for (id, bytes) in self.control.records("coding-retry-job")? {
                let mut parent: CodingRetryJob = decode_canonical(&bytes)?;
                if parent.retry_plan.as_ref() != Some(&job.transcript.value.plan) {
                    continue;
                }
                has_retry_parent = true;
                if self
                    .coding_launch_information_to_stage(parent.failure.value.plan.value.attempt_id)?
                    .is_none()
                    && let Some(input) =
                        self.coding_retry_information(&job.transcript.value.plan)?
                {
                    records.push((
                        "coding-launch-information".to_owned(),
                        id.clone(),
                        canonical_bytes(&input)?,
                    ));
                }
                parent.retry_plan = None;
                parent.complete = false;
                parent.error = None;
                records.extend([
                    (
                        "coding-retry-parent".to_owned(),
                        id.clone(),
                        canonical_bytes(&job.transcript.value.plan)?,
                    ),
                    (
                        "coding-retry-job".to_owned(),
                        id.clone(),
                        canonical_bytes(&parent)?,
                    ),
                ]);
                deletions.push(("coding-retry-terminal".to_owned(), id));
            }
            if !has_retry_parent
                && self
                    .dynamic_guild_state()?
                    .context("coding activation requires dynamic guild state")?
                    .membership_epoch
                    == job.transcript.value.plan.value.membership_epoch
            {
                let Some((coding_coordinator, verification_coordinator)) = fresh_coordinators
                else {
                    // A negative initial result or uncovered verified result
                    // retains its activation and input until a fresh pair is
                    // reachable. Cleanup may be repeated safely after reopen.
                    return Ok(false);
                };
                // An initial result, or an activation selected by an older
                // launch, has no retry parent to reclaim the lane. Handoff
                // its packed input and exact lineage in the same transaction
                // that marks holder cleanup complete.
                let prior = &job.transcript.value.plan;
                let invalid = self.coding_invalid_coordinators_for_source(prior)?;
                if invalid.contains(&coding_coordinator)
                    || invalid.contains(&verification_coordinator)
                {
                    return Ok(false);
                }
                if coding_coordinator == prior.value.coding_coordinator
                    || verification_coordinator == prior.value.coding_coordinator
                    || verification_coordinator == prior.value.verification_coordinator
                    || coding_coordinator == verification_coordinator
                {
                    anyhow::bail!("coding activation renewal did not select fresh coordinators");
                }
                let mut value = prior.value.clone();
                value.coding_coordinator = coding_coordinator;
                value.verification_coordinator = verification_coordinator;
                if value.format_version == 2
                    && value.information_roots.as_ref().is_some_and(|roots| {
                        roots
                            .iter()
                            .zip(&value.geometry.information)
                            .any(|(root, role)| {
                                !role.sector.virtual_zero && *root != role.sector.commitment.root
                            })
                    })
                {
                    value.format_version = 3;
                }
                let state = self
                    .dynamic_guild_state()?
                    .context("coding activation requires dynamic guild state")?;
                let group = &job.transcript.value.manifest.value.group;
                let eligible = state
                    .active_members()
                    .filter(|member| eligible_parity_holders.contains(&member.node_id))
                    .collect::<Vec<_>>();
                let original = value.geometry.clone();
                let replacement =
                    choose_usable_parity_geometry(&original, &eligible, |geometry| {
                        let mut candidate = group.clone();
                        candidate.format_version = value.format_version;
                        for (index, placement) in geometry.parity.iter().enumerate() {
                            let role_index = geometry.information.len() + index;
                            let mb_core::ShardRoleV2::Parity(role) =
                                &mut candidate.roles[role_index]
                            else {
                                anyhow::bail!("verified coding group has an invalid parity role");
                            };
                            role.holder = placement.holder;
                            role.failure_domain = placement.failure_domain.clone();
                        }
                        candidate.id = candidate.calculate_id()?;
                        Ok(!state
                            .coding_groups
                            .iter()
                            .any(|retained| retained.group.id == candidate.id))
                    })?;
                let Some(replacement) = replacement else {
                    // Retain activation and input ownership until a usable
                    // placement exists or history can be forgotten.
                    return Ok(false);
                };
                value.geometry = replacement;
                loop {
                    rand::rngs::OsRng.fill_bytes(&mut value.attempt_id);
                    if value.attempt_id != [0; 16] && value.attempt_id != prior.value.attempt_id {
                        break;
                    }
                }
                value.expires_at_unix_seconds = unix_seconds()
                    .checked_add(24 * 60 * 60)
                    .context("coding activation renewal expiry overflow")?;
                let successor = self.sign_coding_attempt_plan(value)?;
                records.extend([
                    (
                        "coding-launch-successor".to_owned(),
                        attempt_id.to_vec(),
                        canonical_bytes(&successor)?,
                    ),
                    (
                        "coding-launch-job".to_owned(),
                        successor.value.attempt_id.to_vec(),
                        canonical_bytes(&CodingLaunchJob {
                            format_version: 1,
                            plan: successor.clone(),
                            dispatched: false,
                            error: None,
                        })?,
                    ),
                ]);
                if let Some(input) = self.coding_retry_information(prior)? {
                    records.push((
                        "coding-launch-information".to_owned(),
                        successor.value.attempt_id.to_vec(),
                        canonical_bytes(&input)?,
                    ));
                }
            }
            deletions
        };
        deletions.extend([
            ("coding-launch-job".to_owned(), attempt_id.to_vec()),
            ("coding-launch-information".to_owned(), attempt_id.to_vec()),
            ("coding-launch-staged".to_owned(), attempt_id.to_vec()),
            ("coding-activation-replan".to_owned(), attempt_id.to_vec()),
        ]);
        job.complete = true;
        job.error = None;
        records.push((
            "coding-activation-job".to_owned(),
            attempt_id.to_vec(),
            canonical_bytes(&job)?,
        ));
        self.control.put_records_and_delete(&records, &deletions)?;
        Ok(true)
    }

    pub(crate) fn replan_coding_retry_after_cleanup(
        &self,
        failed_attempt_id: [u8; 16],
        fresh_coordinators: Option<(NodeId, NodeId)>,
        eligible_parity_holders: BTreeSet<NodeId>,
    ) -> Result<bool> {
        let bytes = self
            .control
            .get_record("coding-retry-job", &failed_attempt_id)?
            .context("coding retry job is unavailable")?;
        let mut job: CodingRetryJob = decode_canonical(&bytes)?;
        if job.complete {
            return Ok(true);
        }
        if job.retry_plan.is_some() {
            anyhow::bail!("coding retry still owns a prepared successor");
        }
        let prior = &job.failure.value.plan;
        if self
            .control
            .get_record("coding-retired-attempt", &failed_attempt_id)?
            != Some(canonical_bytes(prior)?)
        {
            anyhow::bail!("coding retry parent was not fenced before geometry renewal");
        }
        let Some((coding_coordinator, verification_coordinator)) = fresh_coordinators else {
            return Ok(false);
        };
        let invalid = self.coding_invalid_coordinators_for_source(prior)?;
        if invalid.contains(&coding_coordinator) || invalid.contains(&verification_coordinator) {
            return Ok(false);
        }
        if coding_coordinator == prior.value.coding_coordinator
            || verification_coordinator == prior.value.coding_coordinator
            || verification_coordinator == prior.value.verification_coordinator
            || coding_coordinator == verification_coordinator
        {
            anyhow::bail!("coding retry renewal did not select fresh roles");
        }
        let state = self
            .dynamic_guild_state()?
            .context("coding retry requires dynamic guild state")?;
        let eligible = state
            .active_members()
            .filter(|member| eligible_parity_holders.contains(&member.node_id))
            .collect::<Vec<_>>();
        let Some(geometry) =
            choose_usable_parity_geometry(&prior.value.geometry, &eligible, |geometry| {
                Ok(*geometry != prior.value.geometry)
            })?
        else {
            return Ok(false);
        };
        let Some(input) = self.coding_retry_information(prior)? else {
            // The old retry remains the durable owner until packed input can
            // be recovered; a new geometry may require new holder uploads.
            return Ok(false);
        };
        if self
            .control
            .get_record("coding-launch-successor", &failed_attempt_id)?
            .is_some()
        {
            return Ok(false);
        }
        let mut value = prior.value.clone();
        if value.format_version == 2
            && value.information_roots.as_ref().is_some_and(|roots| {
                roots
                    .iter()
                    .zip(&value.geometry.information)
                    .any(|(root, role)| {
                        !role.sector.virtual_zero && *root != role.sector.commitment.root
                    })
            })
        {
            value.format_version = 3;
        }
        value.geometry = geometry;
        value.membership_epoch = state.membership_epoch;
        value.coding_coordinator = coding_coordinator;
        value.verification_coordinator = verification_coordinator;
        loop {
            rand::rngs::OsRng.fill_bytes(&mut value.attempt_id);
            if value.attempt_id != [0; 16] && value.attempt_id != failed_attempt_id {
                break;
            }
        }
        value.expires_at_unix_seconds = unix_seconds()
            .checked_add(24 * 60 * 60)
            .context("coding retry geometry renewal expiry overflow")?;
        let successor = self.sign_coding_attempt_plan(value)?;
        job.complete = true;
        job.error = None;
        self.control.put_records_and_delete(
            &[
                (
                    "coding-retry-job".to_owned(),
                    failed_attempt_id.to_vec(),
                    canonical_bytes(&job)?,
                ),
                (
                    "coding-launch-successor".to_owned(),
                    failed_attempt_id.to_vec(),
                    canonical_bytes(&successor)?,
                ),
                (
                    "coding-launch-job".to_owned(),
                    successor.value.attempt_id.to_vec(),
                    canonical_bytes(&CodingLaunchJob {
                        format_version: 1,
                        plan: successor.clone(),
                        dispatched: false,
                        error: None,
                    })?,
                ),
                (
                    "coding-launch-information".to_owned(),
                    successor.value.attempt_id.to_vec(),
                    canonical_bytes(&input)?,
                ),
            ],
            &[
                (
                    "coding-launch-information".to_owned(),
                    failed_attempt_id.to_vec(),
                ),
                (
                    "coding-launch-staged".to_owned(),
                    failed_attempt_id.to_vec(),
                ),
            ],
        )?;
        Ok(true)
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
        self.validate_coding_attempt_authority(&transcript.value.plan)?;
        self.activate_verified_coding_attempt(transcript)
    }

    pub(crate) fn activate_recovered_coding_attempt(
        &mut self,
        checkpoint_hash: [u8; 32],
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        self.validate_certified_recovery_transcript(checkpoint_hash, transcript)?;
        self.activate_verified_coding_attempt(transcript)
    }

    fn activate_verified_coding_attempt(
        &mut self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        let plan = &transcript.value.plan.value;
        let group = &transcript.value.manifest.value.group;
        let group_committed = self.dynamic_guild_state()?.is_some_and(|state| {
            state
                .coding_groups
                .iter()
                .any(|retained| retained.group == *group)
        });
        let local_id = self.keys.node_id();
        let assigned = group.roles.iter().any(|role| match role {
            ShardRoleV2::Information(information) => information.owner == local_id,
            ShardRoleV2::Parity(parity) => parity.holder == local_id,
        });
        if !assigned {
            anyhow::bail!("coding attempt assigns no shard to the local node");
        }
        let physical_shard = group.roles.iter().any(|role| match role {
            ShardRoleV2::Information(information) => {
                information.owner == local_id && !information.sector.virtual_zero
            }
            ShardRoleV2::Parity(parity) => parity.holder == local_id,
        });
        if !group_committed && physical_shard {
            // The holder can activate before receiving Add and has no local
            // launch job to pin reused READY information during checkpoint GC.
            // Publish the pin before making any shard READY in another DB.
            self.validate_coding_transcript_storage_conflicts(transcript)?;
            let record_id = plan.attempt_id;
            let bytes = canonical_bytes(&transcript.value.plan)?;
            if self
                .control
                .get_record("coding-pending-activation", &record_id)?
                .is_some_and(|existing| existing != bytes)
            {
                anyhow::bail!("pending coding activation conflicts with its signed plan");
            }
            self.control
                .put_record("coding-pending-activation", &record_id, &bytes)?;
        }
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
                    if self
                        .volumes
                        .load_ready_variable(&self.control, &information.sector.id, index as u16)
                        .is_ok_and(|object| {
                            object.guild_id == group.guild_id
                                && object.commitment == information.sector.commitment
                        })
                    {
                        continue;
                    }
                    if self.volumes.has_staged_attempt_object(
                        &self.control,
                        &plan.attempt_id,
                        &information.sector.id,
                        index as u16,
                    )? {
                        self.volumes.activate_attempt_object(
                            &self.control,
                            &plan.attempt_id,
                            &information.sector.id,
                            index as u16,
                            &information.sector.commitment,
                            &transcript_hash,
                        )?;
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
        let transcript = self
            .control
            .get_record("coding-transcript", attempt_id)?
            .map(|bytes| decode_canonical::<SignedRecord<CodingVerificationTranscript>>(&bytes))
            .transpose()?;
        if let Some(transcript) = &transcript {
            let group_id = transcript.value.manifest.value.group.id;
            let retained = self.dynamic_guild_state()?.is_some_and(|state| {
                state
                    .coding_groups
                    .iter()
                    .any(|retained| retained.group.id == group_id)
            });
            if retained {
                // The delegator may have retired this group even if this
                // holder has not received Retire yet. Acknowledgement cannot
                // remove READY parity until this holder installs Forget, so
                // retain the second phase before finalizing rollback receipts.
                self.record_coding_holder_cleanup(&transcript.value.plan, self.keys.node_id())?;
                self.volumes.finalize_attempt(&self.control, attempt_id)?;
                self.control
                    .delete_record("coding-pending-activation", attempt_id)?;
                return Ok(true);
            }
        }
        let preserve_ready = transcript
            .as_ref()
            .map(|transcript| {
                transcript
                    .value
                    .manifest
                    .value
                    .group
                    .roles
                    .iter()
                    .enumerate()
                    .filter_map(|(index, role)| match role {
                        ShardRoleV2::Information(information)
                            if !information.sector.virtual_zero =>
                        {
                            Some((information.sector.id, index as u16))
                        }
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let mut complete =
            self.volumes
                .discard_attempt(&self.control, attempt_id, &preserve_ready)?;
        if let Some(transcript) = &transcript {
            let group = &transcript.value.manifest.value.group;
            let verification_hash = *blake3::hash(&canonical_bytes(transcript)?).as_bytes();
            for (index, role) in group.roles.iter().enumerate() {
                if let ShardRoleV2::Parity(parity) = role
                    && parity.holder == self.keys.node_id()
                {
                    complete &= self.volumes.remove_unreachable_for_attempt(
                        &self.control,
                        attempt_id,
                        &verification_hash,
                        &group.id,
                        u8::try_from(index)
                            .context("coding parity index exceeds storage format")?,
                        &parity.commitment.root,
                    )?;
                }
            }
            if complete {
                self.clear_coding_holder_cleanup(&transcript.value.plan, self.keys.node_id())?;
            }
        }
        if complete {
            self.control
                .delete_record("coding-pending-activation", attempt_id)?;
        }
        Ok(complete)
    }

    pub(crate) fn coding_holder_cleanup_waits_for_forget(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
    ) -> Result<bool> {
        let Some(bytes) = self
            .control
            .get_record("coding-transcript", &plan.value.attempt_id)?
        else {
            return Ok(false);
        };
        let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
        if transcript.value.plan != *plan {
            anyhow::bail!("coding cleanup transcript conflicts with its signed plan");
        }
        let group_id = transcript.value.manifest.value.group.id;
        Ok(self.dynamic_guild_state()?.is_some_and(|state| {
            state
                .coding_groups
                .iter()
                .any(|retained| retained.group.id == group_id)
        }))
    }

    pub(crate) fn record_coding_holder_cleanup(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        holder: NodeId,
    ) -> Result<()> {
        self.validate_coding_attempt_authority(plan)?;
        if !plan
            .value
            .geometry
            .information
            .iter()
            .any(|role| !role.sector.virtual_zero && role.owner == holder)
            && !plan
                .value
                .geometry
                .parity
                .iter()
                .any(|role| role.holder == holder)
        {
            anyhow::bail!("coding cleanup holder is absent from the signed plan");
        }
        let obligation = CodingHolderCleanupObligation {
            format_version: 1,
            plan: plan.clone(),
            holder,
        };
        let id = coding_holder_cleanup_id(&obligation);
        let bytes = canonical_bytes(&obligation)?;
        if let Some(existing) = self.control.get_record("coding-holder-cleanup", &id)?
            && existing != bytes
        {
            anyhow::bail!("coding holder cleanup conflicts with its durable obligation");
        }
        self.control
            .put_record("coding-holder-cleanup", &id, &bytes)?;
        Ok(())
    }

    pub(crate) fn claim_coding_holder_cleanup_after(
        &self,
        after: Option<Vec<u8>>,
    ) -> Result<Option<(Vec<u8>, CodingHolderCleanupObligation)>> {
        let mut first = None;
        for (id, bytes) in self.control.records("coding-holder-cleanup")? {
            let obligation: CodingHolderCleanupObligation = decode_canonical(&bytes)?;
            if obligation.format_version != 1 || id != coding_holder_cleanup_id(&obligation) {
                anyhow::bail!("durable coding holder cleanup is invalid");
            }
            self.validate_coding_attempt_authority(&obligation.plan)?;
            if after.as_ref().is_none_or(|cursor| id > *cursor) {
                return Ok(Some((id, obligation)));
            }
            first.get_or_insert((id, obligation));
        }
        Ok(first)
    }

    pub(crate) fn complete_coding_holder_cleanup(
        &self,
        obligation: &CodingHolderCleanupObligation,
    ) -> Result<()> {
        let id = coding_holder_cleanup_id(obligation);
        if let Some(existing) = self.control.get_record("coding-holder-cleanup", &id)? {
            if existing != canonical_bytes(obligation)? {
                anyhow::bail!("coding holder cleanup changed before acknowledgement");
            }
            self.control.delete_record("coding-holder-cleanup", &id)?;
        }
        Ok(())
    }

    pub(crate) fn clear_coding_holder_cleanup(
        &self,
        plan: &SignedRecord<CodingAttemptPlan>,
        holder: NodeId,
    ) -> Result<()> {
        self.complete_coding_holder_cleanup(&CodingHolderCleanupObligation {
            format_version: 1,
            plan: plan.clone(),
            holder,
        })
    }

    pub(crate) fn coding_holder_cleanup_endpoints(
        &self,
        guild_id: [u8; 32],
        holder: NodeId,
    ) -> Result<Vec<String>> {
        let Some(cache) = self.guild_endpoint_cache()? else {
            return Ok(Vec::new());
        };
        if cache.format_version != 1 || cache.guild_id != guild_id {
            anyhow::bail!("coding cleanup endpoint cache belongs to another guild");
        }
        Ok(cache
            .endpoints
            .into_iter()
            .find(|(member, _)| *member == holder)
            .map(|(_, endpoints)| endpoints)
            .unwrap_or_default())
    }

    #[cfg(test)]
    pub(crate) fn coding_holder_cleanup_count_for_test(&self) -> Result<usize> {
        Ok(self.control.records("coding-holder-cleanup")?.len())
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
        crate::network::validate_root_binding_frame_budget(
            &plan.value,
            state.active_members().count(),
        )?;
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
        let durable = self
            .dynamic_guild_state()?
            .context("node has no dynamic guild state")?;
        {
            let cache = self
                .membership_history_cache
                .lock()
                .map_err(|_| anyhow::anyhow!("membership history cache is poisoned"))?;
            if let Some(cache) = cache.as_ref()
                && cache.durable == durable
            {
                return cache
                    .by_epoch
                    .get(&membership_epoch)
                    .cloned()
                    .context("coding attempt membership epoch is absent from guild history");
            }
        }
        // Event installation changes the durable state. Rebuild the snapshot
        // index only then, verifying every signed event and its final state.
        // A new Node starts without a cache, so reopen also verifies history.
        let installed = self
            .installed_guild()?
            .context("node has no installed guild")?;
        let mut replay = initial_dynamic_guild_state(&installed)?;
        let mut by_epoch = BTreeMap::new();
        by_epoch.insert(replay.membership_epoch, replay.clone());
        for (record_id, bytes) in self.control.records("guild-event")? {
            let event: QuorumGuildEvent = decode_canonical(&bytes)?;
            if record_id != event.event.sequence.to_be_bytes() {
                anyhow::bail!("guild event history has an invalid record ID");
            }
            replay.apply_event(&event)?;
            by_epoch
                .entry(replay.membership_epoch)
                .or_insert_with(|| replay.clone());
        }
        if replay != durable {
            anyhow::bail!("dynamic guild state conflicts with its event history");
        }
        let selected = by_epoch.get(&membership_epoch).cloned();
        *self
            .membership_history_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("membership history cache is poisoned"))? =
            Some(MembershipHistoryCache { durable, by_epoch });
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
        self.store_checkpoint_with_authority(checkpoint, true, false)
    }

    fn backfill_checkpoint_generation_index(&mut self) -> Result<()> {
        for head_bytes in self.control.checkpoint_head_certificates()? {
            let mut checkpoint: QuorumCheckpoint = decode_canonical(&head_bytes)?;
            checkpoint.verify()?;
            let guild_id = checkpoint.checkpoint.guild_id;
            let mut history = Vec::new();
            loop {
                let generation = checkpoint.checkpoint.generation;
                let hash = checkpoint.hash()?;
                if let Some(indexed) = self
                    .control
                    .checkpoint_at_generation(&guild_id, generation)?
                {
                    if indexed != hash {
                        anyhow::bail!(
                            "committed checkpoint generation index conflicts with its certificate"
                        );
                    }
                    break;
                }
                history.push((generation, hash));
                let Some(parent) = checkpoint.checkpoint.parent else {
                    break;
                };
                let Some(bytes) = self.control.get_record("guild-checkpoint", &parent)? else {
                    break;
                };
                let ancestor: QuorumCheckpoint = decode_canonical(&bytes)?;
                ancestor.verify()?;
                if ancestor.hash()? != parent
                    || ancestor.checkpoint.guild_id != guild_id
                    || ancestor.checkpoint.generation.checked_add(1) != Some(generation)
                {
                    anyhow::bail!("committed checkpoint ancestry is invalid");
                }
                checkpoint = ancestor;
            }
            history.reverse();
            self.control
                .backfill_checkpoint_generations(&guild_id, &history)?;
        }
        Ok(())
    }

    fn store_checkpoint_with_authority(
        &mut self,
        checkpoint: &QuorumCheckpoint,
        require_current_authority: bool,
        historical_coverage: bool,
    ) -> Result<[u8; 32]> {
        checkpoint.verify()?;
        self.validate_local_member(&checkpoint.checkpoint, require_current_authority)?;
        self.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, historical_coverage)?;
        self.validate_checkpoint_transition(&checkpoint.checkpoint, historical_coverage)?;
        let hash = checkpoint.hash()?;
        let body = canonical_bytes(&checkpoint.checkpoint)?;
        let certificate = canonical_bytes(checkpoint)?;
        let legacy_epoch = if checkpoint.checkpoint.format_version == 4
            && self
                .checkpoint_catchup_state(&checkpoint.checkpoint.guild_id)?
                .is_none()
        {
            Some(self.latest_checkpoint_member_epoch(&checkpoint.checkpoint)?)
        } else {
            None
        };
        self.control.commit_checkpoint_with_legacy_epoch(
            &checkpoint.checkpoint.guild_id,
            checkpoint.checkpoint.generation,
            checkpoint.checkpoint.parent.as_ref(),
            &hash,
            &body,
            &certificate,
            false,
            legacy_epoch,
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
        validate_checkpoint_for_signature(checkpoint)?;
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
        self.validate_checkpoint_transition(checkpoint, false)?;
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
        if recovered_head {
            let installed = self
                .installed_guild()?
                .context("historical checkpoint requires an installed guild")?;
            let durable = self
                .dynamic_guild_state()?
                .context("historical checkpoint requires dynamic guild state")?;
            let mut replay = initial_dynamic_guild_state(&installed)?;
            let mut matching = Vec::new();
            if checkpoint_matches_dynamic_authority(checkpoint, &replay) {
                matching.push(replay.clone());
            }
            for (record_id, bytes) in self.control.records("guild-event")? {
                let event: QuorumGuildEvent = decode_canonical(&bytes)?;
                if record_id != event.event.sequence.to_be_bytes() {
                    anyhow::bail!("guild event history has an invalid record ID");
                }
                replay.apply_event(&event)?;
                if checkpoint_matches_dynamic_authority(checkpoint, &replay) {
                    matching.push(replay.clone());
                }
            }
            if replay != durable {
                anyhow::bail!("dynamic guild state conflicts with its event history");
            }
            if matching.is_empty() {
                anyhow::bail!("checkpoint authority is absent from guild event history");
            }
            for state in matching {
                if self
                    .validate_variable_checkpoint_coverage_in_state(checkpoint, &state, true)
                    .is_ok()
                {
                    return Ok(());
                }
            }
            anyhow::bail!("checkpoint contents are invalid in their historical guild epoch");
        }
        let state = self
            .dynamic_guild_state()?
            .context("dynamic checkpoint requires dynamic guild state")?;
        if state.guild_id != checkpoint.guild_id {
            anyhow::bail!("checkpoint and dynamic guild state differ");
        }
        self.validate_variable_checkpoint_coverage_in_state(checkpoint, &state, false)?;
        Ok(())
    }

    fn validate_variable_checkpoint_coverage_in_state(
        &self,
        checkpoint: &GuildCheckpoint,
        state: &DynamicGuildState,
        historical: bool,
    ) -> Result<()> {
        if state.guild_id != checkpoint.guild_id {
            anyhow::bail!("checkpoint and dynamic guild state differ");
        }
        let checkpoint_hash = checkpoint.hash()?;
        let previous_checkpoint = if historical {
            None
        } else {
            self.control
                .checkpoint_head(&checkpoint.guild_id)?
                .filter(|(generation, hash, _)| {
                    (*generation == checkpoint.generation && *hash == checkpoint_hash)
                        || (generation.checked_add(1) == Some(checkpoint.generation)
                            && checkpoint.parent == Some(*hash))
                })
        };
        let exact_committed_head =
            previous_checkpoint
                .as_ref()
                .is_some_and(|(generation, hash, _)| {
                    *generation == checkpoint.generation && *hash == checkpoint_hash
                });
        let previous_revisions = previous_checkpoint
            .map(|(_, _, bytes)| decode_canonical::<QuorumCheckpoint>(&bytes))
            .transpose()?
            .map(|previous| previous.checkpoint.revisions);
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
            if !historical
                && !retained_revision
                && !state.writer_epoch_is_current(revision.value.owner, revision.value.writer_epoch)
            {
                anyhow::bail!("checkpoint revision was signed by a superseded writer epoch");
            }
            for (index, reference) in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
                .enumerate()
            {
                if checkpoint.format_version == 7 {
                    continue;
                }
                if legacy_coverage.contains(&reference.id) {
                    continue;
                }
                if !self.verified_variable_sector_coverage(
                    state,
                    revision.value.owner,
                    reference,
                    revision
                        .value
                        .sector_commitments
                        .as_ref()
                        .and_then(|commitments| commitments.get(index)),
                    historical || exact_committed_head,
                    !historical && !exact_committed_head,
                )? {
                    anyhow::bail!(
                        "checkpoint sector has no verified variable coding group bound to its revision"
                    );
                }
            }
        }
        if let Some(catalog) = &checkpoint.packing_catalog {
            for descriptor in &catalog.sectors {
                if !self.verified_packed_sector_coverage(state, descriptor, historical)? {
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
                && (allow_legacy_placement
                    || descriptor.flat_root == descriptor.commitment.root
                    || transcript.value.plan.value.format_version == 3)
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
        commitments: Option<&[mb_core::MerkleCommitment]>,
    ) -> Result<Vec<SectorRef>> {
        if commitments.is_some_and(|commitments| commitments.len() != sectors.len()) {
            anyhow::bail!("revision sector commitments do not align with its sectors");
        }
        let state = self
            .dynamic_guild_state()?
            .context("variable coverage requires dynamic guild state")?;
        let mut uncovered = Vec::new();
        for (index, sector) in sectors.iter().enumerate() {
            let expected_commitment = commitments.and_then(|commitments| commitments.get(index));
            if !self.verified_variable_sector_coverage(
                &state,
                owner,
                sector,
                expected_commitment,
                false,
                true,
            )? {
                uncovered.push(sector.clone());
            }
        }
        Ok(uncovered)
    }

    pub(crate) fn uncovered_packed_sectors(
        &self,
        descriptors: &[PackedSectorDescriptor],
    ) -> Result<Vec<PackedSectorDescriptor>> {
        let state = self
            .dynamic_guild_state()?
            .context("packed coverage requires dynamic guild state")?;
        descriptors
            .iter()
            .filter_map(|descriptor| {
                match self.verified_packed_sector_coverage(&state, descriptor, false) {
                    Ok(true) => None,
                    Ok(false) => Some(Ok(descriptor.clone())),
                    Err(error) => Some(Err(error)),
                }
            })
            .collect()
    }

    fn verified_variable_sector_coverage(
        &self,
        state: &DynamicGuildState,
        owner: NodeId,
        reference: &SectorRef,
        expected_commitment: Option<&mb_core::MerkleCommitment>,
        allow_legacy_root: bool,
        require_full_root_binding: bool,
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
                        && information.sector.logical_len == reference.logical_len
                        && information.sector.commitment.byte_len == V1_SECTOR_SIZE as u32)
            }) else {
                continue;
            };
            let ShardRoleV2::Information(information) = &retained.group.roles[information_index]
            else {
                unreachable!("selected coding role must be information");
            };
            let commitment_matches = expected_commitment
                .is_some_and(|expected| information.sector.commitment == *expected);
            if require_full_root_binding && expected_commitment.is_some() && !commitment_matches {
                continue;
            }
            let Some(bytes) = self
                .control
                .get_record("coding-group-transcript", &retained.group.id)?
            else {
                continue;
            };
            let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
            let plan = &transcript.value.plan.value;
            let root_matches = plan.information_root(information_index) == Some(reference.root);
            let accepted_root = if require_full_root_binding {
                plan.format_version == 3 && root_matches
            } else {
                root_matches
                    || plan.format_version == 1 && (allow_legacy_root || commitment_matches)
            };
            if transcript.value.manifest.value.group == retained.group
                && replay_coding_transcript(&transcript)? == CodingReplayFinding::Verified
                && accepted_root
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
            let certificate = canonical_bytes(&existing)?;
            let body = canonical_bytes(&existing.checkpoint)?;
            let committed = self.control.checkpoint_head(guild_id)?.is_some_and(
                |(generation, hash, stored)| {
                    generation == existing.checkpoint.generation
                        && hash == *checkpoint_hash
                        && stored == certificate
                },
            );
            let locked = self.control.locked_checkpoint(guild_id)?.is_some_and(
                |(generation, hash, stored)| {
                    generation == existing.checkpoint.generation
                        && hash == *checkpoint_hash
                        && stored == body
                },
            );
            if committed && locked {
                self.control.clear_checkpoint_pages(checkpoint_hash)?;
                return Ok(*checkpoint_hash);
            }
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

    pub(crate) fn checkpoint_catchup_state(
        &self,
        guild_id: &[u8; 32],
    ) -> Result<Option<CheckpointCatchupState>> {
        let Some(bytes) = self
            .control
            .get_record(CHECKPOINT_CATCHUP_STATE_KIND, guild_id)?
        else {
            return Ok(None);
        };
        let state: CheckpointCatchupState = decode_canonical(&bytes)?;
        validate_checkpoint_catchup_state(&state, guild_id)?;
        Ok(Some(state))
    }

    pub(crate) fn begin_checkpoint_catchup(
        &mut self,
        source: NodeId,
        target: &QuorumCheckpoint,
    ) -> Result<CheckpointCatchupState> {
        target.verify()?;
        self.validate_local_member(&target.checkpoint, true)?;
        let target_hash = target.hash()?;
        let guild_id = target.checkpoint.guild_id;
        let (base_generation, base_hash) = self.checkpoint_head(&guild_id)?.unwrap_or((0, [0; 32]));
        if target.checkpoint.generation <= base_generation {
            anyhow::bail!("checkpoint catch-up target is not ahead of the local head");
        }
        let state = CheckpointCatchupState {
            format_version: 2,
            guild_id,
            base_generation,
            base_hash,
            target_generation: target.checkpoint.generation,
            target_hash,
            cursor_generation: base_generation
                .checked_add(1)
                .context("checkpoint catch-up generation exhausted")?,
            cursor_hash: base_hash,
            ready_to_install: false,
        };
        validate_checkpoint_catchup_state(&state, &state.guild_id)?;
        self.control.put_records(&[
            (
                CHECKPOINT_CATCHUP_STATE_KIND.to_owned(),
                state.guild_id.to_vec(),
                canonical_bytes(&state)?,
            ),
            (
                CHECKPOINT_CATCHUP_SOURCE_KIND.to_owned(),
                state.guild_id.to_vec(),
                source.0.to_vec(),
            ),
        ])?;
        Ok(state)
    }

    pub(crate) fn resume_checkpoint_catchup(
        &mut self,
        guild_id: &[u8; 32],
    ) -> Result<Option<(CheckpointCatchupState, NodeId)>> {
        let Some(mut state) = self.checkpoint_catchup_state(guild_id)? else {
            return Ok(None);
        };
        if state.format_version != 2 {
            self.clear_checkpoint_catchup(guild_id)?;
            return Ok(None);
        }
        let Some(source) = self
            .control
            .get_record(CHECKPOINT_CATCHUP_SOURCE_KIND, guild_id)?
        else {
            self.clear_checkpoint_catchup(guild_id)?;
            return Ok(None);
        };
        let Ok(source) = <Vec<u8> as TryInto<[u8; 32]>>::try_into(source) else {
            self.clear_checkpoint_catchup(guild_id)?;
            return Ok(None);
        };
        let source = NodeId(source);
        let (head_generation, head_hash) = self.checkpoint_head(guild_id)?.unwrap_or((0, [0; 32]));
        if head_generation == state.target_generation && head_hash == state.target_hash {
            self.clear_checkpoint_catchup(guild_id)?;
            return Ok(None);
        }
        if head_generation >= state.target_generation {
            self.clear_checkpoint_catchup(guild_id)?;
            return Ok(None);
        }
        let next_generation = head_generation
            .checked_add(1)
            .context("checkpoint catch-up generation exhausted")?;
        if state.cursor_generation != next_generation || state.cursor_hash != head_hash {
            state.base_generation = head_generation;
            state.base_hash = head_hash;
            state.cursor_generation = next_generation;
            state.cursor_hash = head_hash;
            validate_checkpoint_catchup_state(&state, guild_id)?;
            self.control.put_record(
                CHECKPOINT_CATCHUP_STATE_KIND,
                guild_id,
                &canonical_bytes(&state)?,
            )?;
        }
        Ok(Some((state, source)))
    }

    pub(crate) fn install_checkpoint_catchup_link(
        &mut self,
        mut state: CheckpointCatchupState,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<(CheckpointCatchupState, bool)> {
        validate_checkpoint_catchup_state(&state, &state.guild_id)?;
        if state.format_version != 2
            || self.checkpoint_catchup_state(&state.guild_id)? != Some(state.clone())
        {
            anyhow::bail!("checkpoint catch-up state changed while fetching a link");
        }
        let checkpoint_hash = checkpoint.hash()?;
        let expected_parent = (state.cursor_generation != 1).then_some(state.cursor_hash);
        if checkpoint.checkpoint.guild_id != state.guild_id
            || checkpoint.checkpoint.generation != state.cursor_generation
            || checkpoint.checkpoint.parent != expected_parent
            || (state.cursor_generation == state.target_generation
                && checkpoint_hash != state.target_hash)
        {
            anyhow::bail!("checkpoint catch-up received an unexpected certified link");
        }
        let final_target = state.cursor_generation == state.target_generation;
        let committed =
            self.store_checkpoint_with_authority(checkpoint, final_target, !final_target)?;
        if committed != checkpoint_hash {
            anyhow::bail!("checkpoint catch-up installed another certificate");
        }
        if final_target {
            self.clear_checkpoint_catchup(&state.guild_id)?;
            return Ok((state, true));
        }
        state.base_generation = checkpoint.checkpoint.generation;
        state.base_hash = checkpoint_hash;
        state.cursor_generation = checkpoint
            .checkpoint
            .generation
            .checked_add(1)
            .context("checkpoint catch-up generation exhausted")?;
        state.cursor_hash = checkpoint_hash;
        validate_checkpoint_catchup_state(&state, &state.guild_id)?;
        self.control.put_record(
            CHECKPOINT_CATCHUP_STATE_KIND,
            &state.guild_id,
            &canonical_bytes(&state)?,
        )?;
        Ok((state, false))
    }

    pub(crate) fn clear_checkpoint_catchup(&mut self, guild_id: &[u8; 32]) -> Result<()> {
        self.control
            .delete_record(CHECKPOINT_CATCHUP_STATE_KIND, guild_id)?;
        self.control
            .delete_record(CHECKPOINT_CATCHUP_SOURCE_KIND, guild_id)?;
        let head_generation = self
            .checkpoint_head(guild_id)?
            .map(|(generation, _)| generation)
            .unwrap_or(0);
        for (record_id, hash) in self.control.records(CHECKPOINT_CATCHUP_GENERATION_KIND)? {
            if record_id.starts_with(guild_id) {
                let generation = record_id
                    .get(32..40)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u64::from_be_bytes)
                    .unwrap_or(u64::MAX);
                if generation > head_generation && hash.len() == 32 {
                    self.control.delete_record("guild-checkpoint", &hash)?;
                }
                self.control
                    .delete_record(CHECKPOINT_CATCHUP_GENERATION_KIND, &record_id)?;
            }
        }
        Ok(())
    }

    pub(crate) fn checkpoint_head(&self, guild_id: &[u8; 32]) -> Result<Option<(u64, [u8; 32])>> {
        Ok(self
            .control
            .checkpoint_head(guild_id)?
            .map(|(generation, hash, _)| (generation, hash)))
    }

    pub(crate) fn checkpoint_at_generation(
        &self,
        guild_id: &[u8; 32],
        generation: u64,
    ) -> Result<Option<[u8; 32]>> {
        checkpoint_at_generation(&self.control, guild_id, generation)
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
                if require_current_membership {
                    let durable = self
                        .dynamic_guild_state()?
                        .context("dynamic checkpoint requires dynamic guild state")?;
                    if durable.membership_epoch != 1
                        || durable.quorum
                            != (QuorumPolicy {
                                format_version: 1,
                                rule: QuorumRule::Unanimous,
                            })
                        || !durable.active_members().eq(checkpoint.members.iter())
                    {
                        anyhow::bail!("legacy checkpoint does not use the current guild authority");
                    }
                }
            } else {
                let durable = self
                    .dynamic_guild_state()?
                    .context("dynamic checkpoint requires dynamic guild state")?;
                let mut replay = initial_dynamic_guild_state(&installed)?;
                let mut historical_membership =
                    checkpoint_matches_dynamic_authority(checkpoint, &replay);
                let mut historical = replay
                    .members
                    .iter()
                    .map(|member| member.member.node_id)
                    .collect::<BTreeSet<_>>();
                for (record_id, bytes) in self.control.records("guild-event")? {
                    let event: QuorumGuildEvent = decode_canonical(&bytes)?;
                    if record_id != event.event.sequence.to_be_bytes() {
                        anyhow::bail!("guild event history has an invalid record ID");
                    }
                    replay.apply_event(&event)?;
                    historical.extend(replay.members.iter().map(|member| member.member.node_id));
                    historical_membership |=
                        checkpoint_matches_dynamic_authority(checkpoint, &replay);
                }
                if replay != durable || !historical_membership {
                    anyhow::bail!("checkpoint membership is absent from guild event history");
                }
                if require_current_membership
                    && !checkpoint_matches_current_dynamic_authority(checkpoint, &durable)
                {
                    anyhow::bail!("checkpoint does not use the current guild authority");
                }
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

    fn validate_checkpoint_transition(
        &self,
        checkpoint: &GuildCheckpoint,
        historical_catchup: bool,
    ) -> Result<()> {
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
        let next_epoch = checkpoint
            .authority
            .map(|authority| authority.membership_epoch)
            .unwrap_or(0);
        let previous_epoch = match previous.authority {
            Some(authority) => authority.membership_epoch,
            None if checkpoint.authority.is_some() => {
                let witnessed = self
                    .control
                    .get_record(CHECKPOINT_LEGACY_EPOCH_KIND, &hash)?
                    .map(|bytes| -> Result<u64> {
                        let bytes: [u8; 8] = bytes
                            .try_into()
                            .map_err(|_| anyhow::anyhow!("invalid legacy checkpoint epoch"))?;
                        Ok(u64::from_be_bytes(bytes))
                    })
                    .transpose()?;
                if let Some(epoch) = witnessed {
                    epoch
                } else if historical_catchup {
                    self.latest_checkpoint_member_epoch_through(&previous, next_epoch)?
                } else {
                    self.latest_checkpoint_member_epoch(&previous)?
                }
            }
            None => 0,
        };
        if next_epoch < previous_epoch {
            anyhow::bail!("checkpoint authority epoch moves backward");
        }
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

    // Format-4 checkpoints do not record their epoch. Use the latest possible
    // matching epoch so a repeated member roster cannot conceal a rollback.
    fn latest_checkpoint_member_epoch(&self, checkpoint: &GuildCheckpoint) -> Result<u64> {
        self.latest_checkpoint_member_epoch_through(checkpoint, u64::MAX)
    }

    // A historical successor bounds its predecessor's possible epoch even
    // when later events repeat the legacy checkpoint's member roster.
    fn latest_checkpoint_member_epoch_through(
        &self,
        checkpoint: &GuildCheckpoint,
        max_epoch: u64,
    ) -> Result<u64> {
        let installed = self
            .installed_guild()?
            .context("legacy checkpoint transition requires an installed guild")?;
        let mut replay = initial_dynamic_guild_state(&installed)?;
        let mut latest = replay
            .active_members()
            .eq(checkpoint.members.iter())
            .then_some(replay.membership_epoch)
            .filter(|epoch| *epoch <= max_epoch);
        for (record_id, bytes) in self.control.records("guild-event")? {
            let event: QuorumGuildEvent = decode_canonical(&bytes)?;
            if record_id != event.event.sequence.to_be_bytes() {
                anyhow::bail!("guild event history has an invalid record ID");
            }
            replay.apply_event(&event)?;
            if replay.membership_epoch <= max_epoch
                && replay.active_members().eq(checkpoint.members.iter())
            {
                latest = Some(replay.membership_epoch);
            }
        }
        latest.context("legacy checkpoint membership is absent from guild event history")
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
        let mut automation = self.automatic_backup_state(unix_seconds())?;
        let mut dirty_roots = BTreeSet::new();
        for root in self.protected_roots()? {
            if self
                .root_dirty_state(root.root_id)?
                .is_none_or(|state| state.dirty)
            {
                dirty_roots.insert(root.root_id);
            }
        }
        automation
            .root_schedules
            .retain(|schedule| dirty_roots.contains(&schedule.protected_root_id));
        automation.dirty_since_unix_seconds = automation
            .root_schedules
            .iter()
            .map(|schedule| schedule.dirty_since_unix_seconds)
            .min();
        self.store_automatic_backup_state(&automation)?;
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
        let mut live_sectors = current
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
        // Pending launch/retry intent pins the delegator's only packed copy
        // even while unrelated checkpoints advance and parent staging is gone.
        for (_, bytes) in self.control.records("coding-launch-information")? {
            let input: BTreeMap<SectorId, PackedSectorDescriptor> = decode_canonical(&bytes)?;
            live_sectors.extend(input.keys().copied());
        }
        // A pending successor may reuse READY information before its Add
        // event is installed. Keep those sectors pinned across an unrelated
        // checkpoint generation while cleanup of an older group is pending.
        {
            let mut pin_plan = |plan: &SignedRecord<CodingAttemptPlan>| {
                if plan.value.geometry.guild_id == current.checkpoint.guild_id {
                    live_sectors.extend(
                        plan.value
                            .geometry
                            .information
                            .iter()
                            .filter(|role| !role.sector.virtual_zero)
                            .map(|role| role.sector.id),
                    );
                }
            };
            for (_, bytes) in self.control.records("coding-launch-job")? {
                let job: CodingLaunchJob = decode_canonical(&bytes)?;
                pin_plan(&job.plan);
            }
            for (_, bytes) in self.control.records("coding-activation-job")? {
                let job: CodingActivationJob = decode_canonical(&bytes)?;
                if !job.complete {
                    pin_plan(&job.transcript.value.plan);
                }
            }
            for (_, bytes) in self.control.records("coding-retry-job")? {
                let job: CodingRetryJob = decode_canonical(&bytes)?;
                if !job.complete {
                    pin_plan(&job.failure.value.plan);
                    if let Some(retry_plan) = &job.retry_plan {
                        pin_plan(retry_plan);
                    }
                }
            }
            for (_, bytes) in self.control.records("delegated-coding-job")? {
                let job: DelegatedCodingJob = decode_canonical(&bytes)?;
                if !matches!(
                    job.state,
                    DelegatedCodingJobState::Complete | DelegatedCodingJobState::Failed
                ) {
                    pin_plan(&job.plan);
                }
            }
            // Remote holders have no delegator job, and activation can reuse
            // an old READY information object before its Add reaches them.
            for (id, bytes) in self.control.records("coding-pending-activation")? {
                let plan: SignedRecord<CodingAttemptPlan> = decode_canonical(&bytes)?;
                let local_id = self.keys.node_id();
                let physical_shard = plan
                    .value
                    .geometry
                    .information
                    .iter()
                    .any(|role| role.owner == local_id && !role.sector.virtual_zero)
                    || plan
                        .value
                        .geometry
                        .parity
                        .iter()
                        .any(|role| role.holder == local_id);
                if !physical_shard {
                    self.control
                        .delete_record("coding-pending-activation", &id)?;
                    continue;
                }
                pin_plan(&plan);
            }
        }
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
        let retained_group_ids = dynamic_groups
            .iter()
            .map(|retained| retained.group.id)
            .collect::<BTreeSet<_>>();
        // A retained group keeps its shards until Forget. A source sector may
        // also be shared by another group even when no checkpoint names it.
        live_groups.extend(retained_group_ids.iter().copied());
        live_sectors.extend(dynamic_groups.iter().flat_map(|retained| {
            retained.group.roles.iter().filter_map(|role| match role {
                ShardRoleV2::Information(information) if !information.sector.virtual_zero => {
                    Some(information.sector.id)
                }
                _ => None,
            })
        }));

        self.collect_mature_garbage(generation, &live_revisions, &live_sectors, &live_groups)?;

        // Information READY objects can outlive the attempt that first
        // activated them. Their historical transcript remains after Forget,
        // so schedule removal only once no checkpoint or retained group uses
        // the sector; the candidate still needs a later generation to mature.
        for (_, bytes) in self.control.records("coding-group-transcript")? {
            let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
            let group = &transcript.value.manifest.value.group;
            if group.guild_id != current.checkpoint.guild_id
                || retained_group_ids.contains(&group.id)
            {
                continue;
            }
            for (index, role) in group.roles.iter().enumerate() {
                if let ShardRoleV2::Information(information) = role
                    && information.owner == self.keys.node_id()
                    && !information.sector.virtual_zero
                    && !live_sectors.contains(&information.sector.id)
                {
                    self.schedule_garbage(
                        "gc-variable-sector",
                        &variable_emergency_id(&information.sector.id, index as u16),
                        generation,
                        checkpoint_hash,
                        Some(information.sector.commitment.root),
                    )?;
                }
            }
        }

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
            "gc-revision",
            "gc-sector",
            "gc-parity",
            "gc-variable-sector",
            "gc-variable-parity",
            "gc-packed-sector",
            "gc-anchor",
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
                        retire_revision_anchor(&mut self.control, Uuid::from_slice(&record_id)?)?
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
        if !checkpoint.authorizes_member_recovery(local_id)
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

    pub(crate) fn build_removed_holder_endpoint_publication(
        &mut self,
        endpoints: Vec<String>,
        expires_at_unix_seconds: u64,
        sequence_floor: u64,
    ) -> Result<Option<SignedRecord<EndpointRecord>>> {
        let Some(installed) = self.installed_guild()? else {
            return Ok(None);
        };
        installed.certificate.verify()?;
        let Some(state) = self.dynamic_guild_state()? else {
            return Ok(None);
        };
        if state
            .active_members()
            .any(|member| member.node_id == self.keys.node_id())
        {
            return Ok(None);
        }
        Ok(Some(self.build_endpoint_publication(
            installed.certificate.genesis.guild_id,
            endpoints,
            expires_at_unix_seconds,
            sequence_floor,
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
        if !checkpoint.authorizes_member_recovery(self.keys.node_id()) {
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
        self.validate_local_recovery_resume(&installed, &checkpoint)?;
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

    fn validate_local_recovery_resume(
        &self,
        installed: &InstalledGuild,
        checkpoint: &QuorumCheckpoint,
    ) -> Result<()> {
        checkpoint.checkpoint.validate()?;
        let local_id = self.keys.node_id();
        let local_checkpoint_member = checkpoint
            .checkpoint
            .members
            .iter()
            .find(|member| member.node_id == local_id)
            .context("installed recovery checkpoint excludes the local seed identity")?;
        if checkpoint.checkpoint.guild_id != installed.certificate.genesis.guild_id
            || checkpoint.checkpoint.genesis_hash != installed.certificate.genesis.hash()?
            || local_checkpoint_member.recovery_public_key != self.keys.recovery_public_key()
            || !checkpoint.authorizes_member_recovery(local_id)
        {
            anyhow::bail!("installed recovery checkpoint is not bound to the local seed");
        }
        if let Some(state) = self.dynamic_guild_state()? {
            let local_state_member = state
                .active_members()
                .find(|member| member.node_id == local_id)
                .context("installed recovery guild no longer authorizes the local seed")?;
            if state.guild_id != checkpoint.checkpoint.guild_id
                || local_state_member.recovery_public_key != self.keys.recovery_public_key()
            {
                anyhow::bail!("installed recovery state is not bound to the local seed");
            }
        }
        Ok(())
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
        self.validate_certified_recovery_transcript(*checkpoint_hash, transcript)?;
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
        let git_backup = if revision.value.metadata_sectors.is_empty() {
            None
        } else {
            revision_git_backup(&self.control, &self.keys, job.guild_id, revision)?
        };
        let marker = mb_store::git_catalog_marker(&job.target)?;
        match (git_backup, marker) {
            (Some(descriptor), Some(repository_id))
                if repository_id == revision.value.protected_root_id
                    && descriptor.repository_id == repository_id =>
            {
                let key = self.git_catalog_key(repository_id);
                let protected_root = self.protected_root_by_id(repository_id)?;
                let repository = GitRepository::open(&protected_root.path, repository_id, &key)?;
                if repository.id() != repository_id {
                    anyhow::bail!("recovered Git catalog identity changed");
                }
                let info = GitRepositoryInfo {
                    format_version: 1,
                    repository_id,
                    path: protected_root.path,
                };
                let encoded = canonical_bytes(&info)?;
                if let Some(existing) = self
                    .control
                    .get_record("git-repository", repository_id.as_bytes())?
                {
                    if existing != encoded {
                        anyhow::bail!("recovered Git registration conflicts with local state");
                    }
                } else {
                    self.control.put_record_if_absent(
                        "git-repository",
                        repository_id.as_bytes(),
                        &encoded,
                    )?;
                }
            }
            (None, None) => {}
            _ => anyhow::bail!("recovered Git catalog does not match signed history metadata"),
        }
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

fn sign_legacy_packing_binding(
    keys: &KeyMaterial,
    protected_root_id: Uuid,
    reference: &SectorRef,
    bytes: &[u8],
) -> Result<SignedRecord<mb_core::LegacyPackingBinding>> {
    if bytes.len() != V1_SECTOR_SIZE || sector_root(bytes) != reference.root {
        anyhow::bail!("legacy packing source conflicts with its signed revision root");
    }
    Ok(SignedRecord::sign(
        mb_core::LEGACY_PACKING_BINDING_DOMAIN,
        mb_core::LegacyPackingBinding {
            format_version: 1,
            owner: keys.node_id(),
            protected_root: packing_protected_root(protected_root_id),
            object_id: reference.id,
            flat_root: reference.root,
            source_commitment: merkle_commit(bytes)?,
        },
        keys,
    )?)
}

fn validate_packed_sector(profile: PackingProfile, sector: &PackedSector) -> Result<()> {
    profile.validate()?;
    if sector.descriptor.calculate_id(profile)? != sector.descriptor.id
        || sector.descriptor.commitment.byte_len != profile.sector_size
        || sector.bytes.len() != profile.sector_size as usize
        || sector.descriptor.flat_root != sector.descriptor.commitment.root
            && *blake3::hash(&sector.bytes).as_bytes() != sector.descriptor.flat_root
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
        || record.sector.descriptor.flat_root != record.sector.descriptor.commitment.root
            && *blake3::hash(&record.sector.bytes).as_bytes() != record.sector.descriptor.flat_root
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

fn checkpoint_matches_current_dynamic_authority(
    checkpoint: &GuildCheckpoint,
    state: &DynamicGuildState,
) -> bool {
    checkpoint_matches_dynamic_authority(checkpoint, state)
        && (checkpoint.format_version != 4
            || state.membership_epoch == 1
                && state.quorum
                    == QuorumPolicy {
                        format_version: 1,
                        rule: QuorumRule::Unanimous,
                    })
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
                            && information.sector.commitment.byte_len == V1_SECTOR_SIZE as u32
                            && revision.value.metadata_sectors.iter()
                                .chain(&revision.value.data_sectors)
                                .enumerate()
                                .any(|(index, reference)| reference.id == information.sector.id
                                    && reference.logical_len == information.sector.logical_len
                                    && revision.value.sector_commitments.as_ref()
                                        .and_then(|commitments| commitments.get(index))
                                        .is_none_or(|commitment| *commitment == information.sector.commitment)))
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

fn legacy_coding_add_binding_from_store(
    control: &ControlStore,
    guild_id: [u8; 32],
    event_sequence: u64,
    event_hash: [u8; 32],
) -> Result<Option<QuorumLegacyCodingAddBinding>> {
    let certified: QuorumGuildEvent = decode_canonical(
        &control
            .get_record("guild-event", &event_sequence.to_be_bytes())?
            .context("historical coding Add is unavailable")?,
    )?;
    if certified.event.guild_id != guild_id
        || certified.event.hash()? != event_hash
        || !matches!(
            certified.event.kind,
            mb_core::GuildEventKind::AddCodingGroup { .. }
        )
    {
        anyhow::bail!("requested legacy Add binding has a different event");
    }
    control
        .get_record("coding-legacy-add-binding", &event_hash)?
        .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
        .transpose()
}

fn coding_transcript_for_event_from_store(
    control: &ControlStore,
    guild_id: [u8; 32],
    group_id: [u8; 32],
    event_sequence: u64,
    event_hash: [u8; 32],
) -> Result<SignedRecord<CodingVerificationTranscript>> {
    let certified: QuorumGuildEvent = decode_canonical(
        &control
            .get_record("guild-event", &event_sequence.to_be_bytes())?
            .context("coding Add event is unavailable")?,
    )?;
    if certified.event.guild_id != guild_id
        || certified.event.sequence != event_sequence
        || certified.event.hash()? != event_hash
    {
        anyhow::bail!("requested coding transcript has the wrong Add event");
    }
    let Some((group, transcript_hash)) = certified.event.kind.coding_group_add() else {
        anyhow::bail!("requested event is not a coding Add");
    };
    if group.id != group_id {
        anyhow::bail!("requested coding transcript has the wrong group");
    }
    let bytes = if let Some(bytes) = control.get_record("coding-event-transcript", &event_hash)? {
        bytes
    } else {
        // Pre-binding stores can safely supply the current retained Add:
        // another transcript cannot overwrite its group key while retained.
        let retained: DynamicGuildState = decode_canonical(
            &control
                .get_record("guild-dynamic-state", b"primary")?
                .context("node has no dynamic guild state")?,
        )?;
        if !retained.coding_groups.iter().any(|retained| {
            retained.group.id == group_id && retained.added_at_event == event_sequence
        }) {
            anyhow::bail!("historical coding Add has no event-bound verifier evidence");
        }
        control
            .get_record("coding-group-transcript", &group_id)?
            .context("retained coding-group verifier transcript is unavailable")?
    };
    let transcript: SignedRecord<CodingVerificationTranscript> = decode_canonical(&bytes)?;
    if transcript.value.manifest.value.group != *group
        || transcript_hash.is_some_and(|expected| *blake3::hash(&bytes).as_bytes() != expected)
        || replay_coding_transcript(&transcript)? != CodingReplayFinding::Verified
    {
        anyhow::bail!("event-bound coding transcript is invalid");
    }
    Ok(transcript)
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
    let bytes = control
        .get_record("guild-checkpoint", checkpoint_hash)?
        .context("guild checkpoint is unavailable")?;
    let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
    checkpoint.verify()?;
    if checkpoint.checkpoint.guild_id != *guild_id || checkpoint.hash()? != *checkpoint_hash {
        anyhow::bail!("checkpoint page request has the wrong identity");
    }
    Ok(control.protocol_record_page("guild-checkpoint", checkpoint_hash, page_index)?)
}

fn checkpoint_at_generation(
    control: &ControlStore,
    guild_id: &[u8; 32],
    generation: u64,
) -> Result<Option<[u8; 32]>> {
    if generation == 0 {
        anyhow::bail!("checkpoint generation must be positive");
    }
    let Some(hash) = control.checkpoint_at_generation(guild_id, generation)? else {
        return Ok(None);
    };
    let bytes = control
        .get_record("guild-checkpoint", &hash)?
        .context("committed checkpoint generation has no certificate")?;
    let checkpoint: QuorumCheckpoint = decode_canonical(&bytes)?;
    checkpoint.verify()?;
    if checkpoint.hash()? != hash
        || checkpoint.checkpoint.guild_id != *guild_id
        || checkpoint.checkpoint.generation != generation
    {
        anyhow::bail!("committed checkpoint generation has an invalid certificate");
    }
    Ok(Some(hash))
}

fn validate_checkpoint_catchup_state(
    state: &CheckpointCatchupState,
    guild_id: &[u8; 32],
) -> Result<()> {
    let base_hash_valid = if state.base_generation == 0 {
        state.base_hash == [0; 32]
    } else {
        state.base_hash != [0; 32]
    };
    let valid_progress = match state.format_version {
        1 => {
            state.cursor_generation >= state.base_generation
                && state.cursor_generation <= state.target_generation
                && (state.cursor_generation != state.target_generation
                    || state.cursor_hash == state.target_hash)
                && state.ready_to_install == (state.cursor_generation == state.base_generation)
                && (!state.ready_to_install || state.cursor_hash == state.base_hash)
        }
        2 => {
            state.cursor_generation == state.base_generation.saturating_add(1)
                && state.cursor_generation <= state.target_generation
                && state.cursor_hash == state.base_hash
                && !state.ready_to_install
        }
        _ => false,
    };
    if state.guild_id != *guild_id
        || state.guild_id == [0; 32]
        || !base_hash_valid
        || state.target_generation <= state.base_generation
        || state.target_hash == [0; 32]
        || !valid_progress
    {
        anyhow::bail!("invalid checkpoint catch-up state");
    }
    Ok(())
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
pub(crate) mod tests {
    use super::*;

    #[test]
    fn membership_history_cache_rebuilds_after_event_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("node");
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(&path, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let initial = node.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(
            node.dynamic_guild_state_for_membership_epoch(1).unwrap(),
            initial
        );
        assert_eq!(
            node.dynamic_guild_state_for_membership_epoch(1).unwrap(),
            initial
        );

        let event = GuildEvent {
            format_version: 1,
            guild_id: initial.guild_id,
            sequence: initial.event_sequence + 1,
            parent: initial.event_head,
            kind: mb_core::GuildEventKind::SetQuorum {
                policy: QuorumPolicy {
                    format_version: 1,
                    rule: QuorumRule::Majority,
                },
            },
        };
        let mut signatures = (120_u8..125)
            .map(|byte| {
                sign_guild_event(
                    &event,
                    &KeyMaterial::from_seed(&Seed::from_bytes([byte; 32])),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent { event, signatures })
            .unwrap();
        let updated = node.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(updated.membership_epoch, 2);
        assert_eq!(
            node.dynamic_guild_state_for_membership_epoch(1).unwrap(),
            initial
        );
        assert_eq!(
            node.dynamic_guild_state_for_membership_epoch(2).unwrap(),
            updated
        );

        drop(node);
        let node = Node::open(&path, seed).unwrap();
        assert!(node.membership_history_cache.lock().unwrap().is_none());
        assert_eq!(
            node.dynamic_guild_state_for_membership_epoch(1).unwrap(),
            initial
        );
        let mut conflicting = updated;
        conflicting.event_head = [77; 32];
        node.control
            .put_record(
                "guild-dynamic-state",
                b"primary",
                &canonical_bytes(&conflicting).unwrap(),
            )
            .unwrap();
        assert!(node.dynamic_guild_state_for_membership_epoch(2).is_err());
    }

    #[test]
    fn legacy_packing_attestation_survives_restart_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let path = temp.path().join("node");
        let mut node = Node::open(&path, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let bytes = vec![37; V1_SECTOR_SIZE];
        let value = mb_core::LegacyPackingAttestation {
            format_version: 1,
            guild_id: state.guild_id,
            membership_epoch: state.membership_epoch,
            owner: certificate.genesis.members[1].node_id,
            protected_root: [41; 32],
            object_id: [42; 32],
            flat_root: sector_root(&bytes),
            source_commitment: merkle_commit(&bytes).unwrap(),
        };
        let signed = node
            .sign_legacy_packing_attestation(value.clone(), &bytes)
            .unwrap();
        for index in 0..128_u8 {
            let mut other = value.clone();
            other.object_id = [index + 100; 32];
            let attestation = SignedRecord::sign(
                mb_core::LEGACY_PACKING_ATTESTATION_DOMAIN,
                other,
                &node.keys,
            )
            .unwrap();
            node.store_legacy_packing_attestation(&attestation).unwrap();
        }
        drop(node);

        let node = Node::open(&path, seed).unwrap();
        let index = node
            .legacy_packing_attestation_index(value.guild_id)
            .unwrap();
        assert_eq!(index.len(), 129);
        assert_eq!(
            index.get(&(value.owner, value.protected_root, value.object_id)),
            Some(&vec![signed.clone()])
        );
    }

    #[test]
    fn checkpoint_catchup_is_resumable_across_authority_epochs_and_adopts_certificates() {
        let temp = tempfile::tempdir().unwrap();
        let local_seed = Seed::from_bytes([226; 32]);
        let mut source = Node::open(temp.path().join("source"), local_seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut source, &local_seed);
        let certificate = source.installed_guild_certificate().unwrap().unwrap();
        let mut first = source
            .current_checkpoint(revision.value.guild_id)
            .unwrap()
            .unwrap();
        let peers = certificate
            .genesis
            .members
            .iter()
            .cloned()
            .map(|member| GuildPeer {
                member,
                endpoints: Vec::new(),
            })
            .collect::<Vec<_>>();
        let mut signer_keys = std::iter::once(local_seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        signer_keys.sort_by_key(KeyMaterial::node_id);
        let local_id = KeyMaterial::from_seed(&local_seed).node_id();
        let guild_id = certificate.genesis.guild_id;
        drop(source);
        let node_path = temp.path().join("target");
        let mut node = Node::open(&node_path, local_seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers.clone())
            .unwrap();
        let initial = node.dynamic_guild_state().unwrap().unwrap();
        let writer_fence = first.checkpoint.writer_fences[0].clone();
        let rotate_writer = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: 1,
            parent: initial.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: writer_fence.owner,
                epoch: writer_fence.epoch,
                public_key: writer_fence.public_key,
            },
        };
        let mut writer_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&rotate_writer, keys).unwrap())
            .collect::<Vec<_>>();
        writer_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: rotate_writer,
            signatures: writer_signatures,
        })
        .unwrap();
        let writer_state = node.dynamic_guild_state().unwrap().unwrap();
        let set_majority = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: 2,
            parent: writer_state.event_head,
            kind: mb_core::GuildEventKind::SetQuorum {
                policy: QuorumPolicy {
                    format_version: 1,
                    rule: QuorumRule::Majority,
                },
            },
        };
        let mut event_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&set_majority, keys).unwrap())
            .collect::<Vec<_>>();
        event_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: set_majority,
            signatures: event_signatures,
        })
        .unwrap();
        let current = node.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(current.quorum.rule, QuorumRule::Majority);
        let replacement_writer = ed25519_dalek::SigningKey::from_bytes(&[227; 32]);
        let rotate_again = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: current.event_sequence + 1,
            parent: current.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: writer_fence.owner,
                epoch: 2,
                public_key: replacement_writer.verifying_key().to_bytes(),
            },
        };
        let mut rotate_signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&rotate_again, keys).unwrap())
            .collect::<Vec<_>>();
        rotate_signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: rotate_again,
            signatures: rotate_signatures,
        })
        .unwrap();
        let current = node.dynamic_guild_state().unwrap().unwrap();
        assert!(!current.writer_epoch_is_current(writer_fence.owner, writer_fence.epoch));
        let source_id = signer_keys
            .iter()
            .find(|keys| keys.node_id() != local_id)
            .unwrap()
            .node_id();
        let mut late_legacy = first.clone();
        late_legacy.checkpoint.generation = 2;
        late_legacy.checkpoint.parent = Some(first.hash().unwrap());
        late_legacy.signatures.clear();
        for keys in &signer_keys {
            late_legacy.add_signature(keys).unwrap();
        }
        late_legacy.verify().unwrap();
        assert!(
            node.begin_checkpoint_catchup(source_id, &late_legacy)
                .is_err()
        );

        first.checkpoint.format_version = 4;
        first.checkpoint.authority = None;
        first.signatures.clear();
        for keys in &signer_keys {
            first.add_signature(keys).unwrap();
        }
        first.verify().unwrap();

        let nonsigners = signer_keys
            .iter()
            .filter(|keys| keys.node_id() != local_id)
            .take(
                current
                    .quorum
                    .required(current.active_members().count())
                    .unwrap(),
            )
            .collect::<Vec<_>>();
        let mut second = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 5,
                guild_id,
                genesis_hash: certificate.hash().unwrap(),
                generation: 2,
                parent: Some(first.hash().unwrap()),
                members: current.active_members().cloned().collect(),
                writer_fences: first.checkpoint.writer_fences.clone(),
                revision_tombstones: first.checkpoint.revision_tombstones.clone(),
                revisions: first.checkpoint.revisions.clone(),
                coding_groups: first.checkpoint.coding_groups.clone(),
                authority: Some(mb_core::CheckpointAuthority {
                    format_version: 1,
                    membership_epoch: current.membership_epoch,
                    quorum: current.quorum,
                }),
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for keys in &nonsigners {
            second.add_signature(keys).unwrap();
        }
        second.verify().unwrap();
        let mut third = QuorumCheckpoint {
            checkpoint: second.checkpoint.clone(),
            signatures: Vec::new(),
        };
        third.checkpoint.generation = 3;
        third.checkpoint.parent = Some(second.hash().unwrap());
        for keys in &nonsigners {
            third.add_signature(keys).unwrap();
        }
        third.verify().unwrap();

        let mut late_historical = first.clone();
        late_historical.checkpoint.generation = 2;
        late_historical.checkpoint.parent = Some(first.hash().unwrap());
        late_historical.signatures.clear();
        for keys in &signer_keys {
            late_historical.add_signature(keys).unwrap();
        }
        late_historical.verify().unwrap();
        assert!(
            node.begin_checkpoint_catchup(source_id, &late_historical)
                .is_err()
        );
        assert!(node.checkpoint_catchup_state(&guild_id).unwrap().is_none());

        let state = node.begin_checkpoint_catchup(source_id, &third).unwrap();
        assert_eq!(state.cursor_generation, 1);
        assert!(node.checkpoint(&third.hash().unwrap()).is_err());
        node.control
            .put_record(
                "guild-checkpoint",
                &third.hash().unwrap(),
                &canonical_bytes(&third).unwrap(),
            )
            .unwrap();
        assert!(
            node.finalize_staged_checkpoint(&guild_id, &third.hash().unwrap())
                .is_err()
        );
        node.control
            .delete_record("guild-checkpoint", &third.hash().unwrap())
            .unwrap();
        let (state, complete) = node.install_checkpoint_catchup_link(state, &first).unwrap();
        assert!(!complete);
        assert_eq!(state.cursor_generation, 2);
        assert_eq!(
            node.checkpoint_head(&guild_id).unwrap(),
            Some((1, first.hash().unwrap()))
        );
        assert_eq!(
            node.checkpoint_at_generation(&guild_id, 1).unwrap(),
            Some(first.hash().unwrap())
        );
        let generation_key = [guild_id.as_slice(), &1_u64.to_be_bytes()].concat();
        assert!(
            node.control
                .delete_record("guild-checkpoint-generation", &generation_key)
                .unwrap()
        );
        drop(node);

        let mut node = Node::open(&node_path, local_seed.clone()).unwrap();
        assert_eq!(
            node.checkpoint_at_generation(&guild_id, 1).unwrap(),
            Some(first.hash().unwrap())
        );
        let (state, resumed_source) = node.resume_checkpoint_catchup(&guild_id).unwrap().unwrap();
        assert_eq!(resumed_source, source_id);
        let (state, complete) = node
            .install_checkpoint_catchup_link(state, &second)
            .unwrap();
        assert!(!complete);
        assert_eq!(
            node.checkpoint_head(&guild_id).unwrap(),
            Some((2, second.hash().unwrap()))
        );
        let mut regressed = second.clone();
        regressed.checkpoint.generation = 3;
        regressed.checkpoint.parent = Some(second.hash().unwrap());
        regressed.checkpoint.authority = Some(mb_core::CheckpointAuthority {
            format_version: 1,
            membership_epoch: initial.membership_epoch,
            quorum: initial.quorum,
        });
        regressed.signatures.clear();
        for keys in &signer_keys {
            regressed.add_signature(keys).unwrap();
        }
        regressed.verify().unwrap();
        assert!(
            node.validate_checkpoint_transition(&regressed.checkpoint, false)
                .is_err()
        );

        let mut legacy_regression = regressed.clone();
        legacy_regression.checkpoint.format_version = 4;
        legacy_regression.checkpoint.authority = None;
        legacy_regression.signatures.clear();
        for keys in &signer_keys {
            legacy_regression.add_signature(keys).unwrap();
        }
        legacy_regression.verify().unwrap();
        assert!(
            node.validate_checkpoint_transition(&legacy_regression.checkpoint, false)
                .is_err()
        );
        let mut fourth = second.clone();
        fourth.checkpoint.generation = 4;
        fourth.checkpoint.parent = Some(regressed.hash().unwrap());
        fourth.signatures.clear();
        for keys in &nonsigners {
            fourth.add_signature(keys).unwrap();
        }
        fourth.verify().unwrap();
        let rollback_path = temp.path().join("rollback-target");
        let mut rollback = Node::open(&rollback_path, local_seed.clone()).unwrap();
        rollback
            .adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        for (_, bytes) in node.control.records("guild-event").unwrap() {
            rollback
                .install_guild_event(decode_canonical(&bytes).unwrap())
                .unwrap();
        }
        let rollback_state = rollback
            .begin_checkpoint_catchup(source_id, &fourth)
            .unwrap();
        let (rollback_state, complete) = rollback
            .install_checkpoint_catchup_link(rollback_state, &first)
            .unwrap();
        assert!(!complete);
        let (_, complete) = rollback
            .install_checkpoint_catchup_link(rollback_state, &second)
            .unwrap();
        assert!(!complete);
        drop(rollback);
        let mut rollback = Node::open(&rollback_path, local_seed.clone()).unwrap();
        let (rollback_state, _) = rollback
            .resume_checkpoint_catchup(&guild_id)
            .unwrap()
            .unwrap();
        assert!(
            rollback
                .install_checkpoint_catchup_link(rollback_state, &regressed)
                .is_err()
        );
        assert_eq!(
            rollback.checkpoint_head(&guild_id).unwrap(),
            Some((2, second.hash().unwrap()))
        );
        let lock = node.control.locked_checkpoint(&guild_id).unwrap().unwrap();
        assert_eq!((lock.0, lock.1), (2, second.hash().unwrap()));
        let (total_pages, first_page) = node
            .checkpoint_page(&guild_id, &first.hash().unwrap(), 0)
            .unwrap();
        assert!(total_pages >= 1);
        assert!(!first_page.is_empty());
        drop(node);

        let mut node = Node::open(&node_path, local_seed).unwrap();
        let (resumed, resumed_source) = node.resume_checkpoint_catchup(&guild_id).unwrap().unwrap();
        assert_eq!(resumed, state);
        assert_eq!(resumed_source, source_id);
        assert!(
            node.install_checkpoint_catchup_link(resumed, &third)
                .unwrap()
                .1
        );
        assert_eq!(
            node.checkpoint_head(&guild_id).unwrap(),
            Some((3, third.hash().unwrap()))
        );
        assert!(node.checkpoint_catchup_state(&guild_id).unwrap().is_none());
    }

    pub(crate) fn install_long_committed_checkpoint_history(
        node: &mut Node,
        seed: &Seed,
    ) -> ([u8; 32], Vec<[u8; 32]>) {
        let revision = install_public_restore_fixture(node, seed);
        let guild_id = revision.value.guild_id;
        let mut previous = node.current_checkpoint(guild_id).unwrap().unwrap();
        let signer_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        let mut hashes = vec![previous.hash().unwrap()];
        for generation in 2..=1_024 {
            let parent = previous.hash().unwrap();
            let mut next = previous.clone();
            next.checkpoint.generation = generation;
            next.checkpoint.parent = Some(parent);
            next.signatures.clear();
            for keys in &signer_keys {
                next.add_signature(keys).unwrap();
            }
            let hash = next.hash().unwrap();
            node.control
                .commit_checkpoint(
                    &guild_id,
                    generation,
                    Some(&parent),
                    &hash,
                    &canonical_bytes(&next.checkpoint).unwrap(),
                    &canonical_bytes(&next).unwrap(),
                    false,
                )
                .unwrap();
            hashes.push(hash);
            previous = next;
        }
        (guild_id, hashes)
    }

    #[test]
    fn legacy_checkpoint_transition_uses_latest_matching_membership_epoch() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let guild_id = certificate.genesis.guild_id;
        let genesis_hash = certificate.hash().unwrap();
        let path = temp.path().join("node");
        let mut node = Node::open(&path, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let initial = node.dynamic_guild_state().unwrap().unwrap();
        let mut checkpoint = GuildCheckpoint {
            format_version: 4,
            guild_id,
            genesis_hash,
            generation: 1,
            parent: None,
            members: initial.active_members().cloned().collect(),
            writer_fences: Vec::new(),
            revision_tombstones: Vec::new(),
            revisions: Vec::new(),
            coding_groups: Vec::new(),
            authority: None,
            packing_catalog: None,
        };
        assert_eq!(node.latest_checkpoint_member_epoch(&checkpoint).unwrap(), 1);
        let event = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: 1,
            parent: initial.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: initial.members[0].member.node_id,
                failure_domain: "new-distinct-domain".into(),
            },
        };
        let mut signatures = (120_u8..125)
            .map(|index| {
                sign_guild_event(
                    &event,
                    &KeyMaterial::from_seed(&Seed::from_bytes([index; 32])),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent { event, signatures })
            .unwrap();
        let relabeled = node.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(relabeled.membership_epoch, 2);
        checkpoint.members = relabeled.active_members().cloned().collect();
        assert_eq!(node.latest_checkpoint_member_epoch(&checkpoint).unwrap(), 2);
        let restore = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: 2,
            parent: relabeled.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: initial.members[0].member.node_id,
                failure_domain: initial.members[0].member.failure_domain.clone(),
            },
        };
        let mut signatures = (120_u8..125)
            .map(|index| {
                sign_guild_event(
                    &restore,
                    &KeyMaterial::from_seed(&Seed::from_bytes([index; 32])),
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: restore,
            signatures,
        })
        .unwrap();
        checkpoint.members = initial.active_members().cloned().collect();
        assert_eq!(node.latest_checkpoint_member_epoch(&checkpoint).unwrap(), 3);
        drop(node);

        let node = Node::open(&path, seed).unwrap();
        assert_eq!(node.latest_checkpoint_member_epoch(&checkpoint).unwrap(), 3);
    }

    #[test]
    fn historical_legacy_checkpoint_catches_up_after_later_quorum_change() {
        fn next_event(
            node: &Node,
            signing_keys: &[KeyMaterial],
            kind: mb_core::GuildEventKind,
        ) -> QuorumGuildEvent {
            let state = node.dynamic_guild_state().unwrap().unwrap();
            let event = GuildEvent {
                format_version: 1,
                guild_id: state.guild_id,
                sequence: state.event_sequence + 1,
                parent: state.event_head,
                kind,
            };
            let mut signatures = signing_keys
                .iter()
                .map(|keys| sign_guild_event(&event, keys).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            QuorumGuildEvent { event, signatures }
        }

        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([226; 32]);
        let mut source = Node::open(temp.path().join("source"), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut source, &seed);
        let guild_id = revision.value.guild_id;
        let mut first = source.current_checkpoint(guild_id).unwrap().unwrap();
        let certificate = source.installed_guild_certificate().unwrap().unwrap();
        let peers = certificate
            .genesis
            .members
            .iter()
            .cloned()
            .map(|member| GuildPeer {
                member,
                endpoints: Vec::new(),
            })
            .collect::<Vec<_>>();
        drop(source);
        let signing_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        first.checkpoint.format_version = 4;
        first.signatures.clear();
        for keys in &signing_keys {
            first.add_signature(keys).unwrap();
        }
        first.verify().unwrap();

        let target_path = temp.path().join("late-target");
        let mut target = Node::open(&target_path, seed.clone()).unwrap();
        target
            .adopt_recovered_guild(certificate.clone(), peers.clone())
            .unwrap();
        let fence = &first.checkpoint.writer_fences[0];
        let writer_event = next_event(
            &target,
            &signing_keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner: fence.owner,
                epoch: fence.epoch,
                public_key: fence.public_key,
            },
        );
        target.install_guild_event(writer_event.clone()).unwrap();
        let majority_event = next_event(
            &target,
            &signing_keys,
            mb_core::GuildEventKind::SetQuorum {
                policy: QuorumPolicy {
                    format_version: 1,
                    rule: QuorumRule::Majority,
                },
            },
        );
        target.install_guild_event(majority_event.clone()).unwrap();
        let majority = target.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(majority.membership_epoch, 2);
        let mut second = first.clone();
        second.checkpoint.format_version = 5;
        second.checkpoint.generation = 2;
        second.checkpoint.parent = Some(first.hash().unwrap());
        second.checkpoint.authority = Some(mb_core::CheckpointAuthority {
            format_version: 1,
            membership_epoch: majority.membership_epoch,
            quorum: majority.quorum,
        });
        second.signatures.clear();
        for keys in &signing_keys {
            second.add_signature(keys).unwrap();
        }
        second.verify().unwrap();

        let unanimous_event = next_event(
            &target,
            &signing_keys,
            mb_core::GuildEventKind::SetQuorum {
                policy: QuorumPolicy {
                    format_version: 1,
                    rule: QuorumRule::Unanimous,
                },
            },
        );
        target.install_guild_event(unanimous_event.clone()).unwrap();
        let unanimous = target.dynamic_guild_state().unwrap().unwrap();
        assert_eq!(unanimous.membership_epoch, 3);
        let mut third = second.clone();
        third.checkpoint.generation = 3;
        third.checkpoint.parent = Some(second.hash().unwrap());
        third.checkpoint.authority = Some(mb_core::CheckpointAuthority {
            format_version: 1,
            membership_epoch: unanimous.membership_epoch,
            quorum: unanimous.quorum,
        });
        third.signatures.clear();
        for keys in &signing_keys {
            third.add_signature(keys).unwrap();
        }
        third.verify().unwrap();

        let source_id = signing_keys
            .iter()
            .map(KeyMaterial::node_id)
            .find(|id| *id != target.keys().node_id())
            .unwrap();
        let state = target.begin_checkpoint_catchup(source_id, &third).unwrap();
        let (state, complete) = target
            .install_checkpoint_catchup_link(state, &first)
            .unwrap();
        assert!(!complete);
        assert_eq!(state.cursor_generation, 2);
        drop(target);
        let mut target = Node::open(&target_path, seed.clone()).unwrap();
        let (state, _) = target
            .resume_checkpoint_catchup(&guild_id)
            .unwrap()
            .unwrap();
        let (state, complete) = target
            .install_checkpoint_catchup_link(state, &second)
            .unwrap();
        assert!(!complete);
        assert!(
            target
                .install_checkpoint_catchup_link(state, &third)
                .unwrap()
                .1
        );
        assert_eq!(
            target.checkpoint_head(&guild_id).unwrap(),
            Some((3, third.hash().unwrap()))
        );

        let mut known = Node::open(temp.path().join("known-target"), seed).unwrap();
        known.adopt_recovered_guild(certificate, peers).unwrap();
        known.install_guild_event(writer_event).unwrap();
        known
            .store_checkpoint_with_authority(&first, false, true)
            .unwrap();
        assert_eq!(
            known
                .control
                .get_record(CHECKPOINT_LEGACY_EPOCH_KIND, &first.hash().unwrap())
                .unwrap(),
            Some(1_u64.to_be_bytes().to_vec())
        );
        known.install_guild_event(majority_event).unwrap();
        known.install_guild_event(unanimous_event).unwrap();
        let state = known.begin_checkpoint_catchup(source_id, &third).unwrap();
        let (state, complete) = known
            .install_checkpoint_catchup_link(state, &second)
            .unwrap();
        assert!(!complete);
        assert!(
            known
                .install_checkpoint_catchup_link(state, &third)
                .unwrap()
                .1
        );
        assert_eq!(
            known.checkpoint_head(&guild_id).unwrap(),
            Some((3, third.hash().unwrap()))
        );
    }

    #[test]
    fn repeated_legacy_roster_cannot_hide_checkpoint_epoch_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([226; 32]);
        let mut source = Node::open(temp.path().join("source"), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut source, &seed);
        let guild_id = revision.value.guild_id;
        let first = source.current_checkpoint(guild_id).unwrap().unwrap();
        let certificate = source.installed_guild_certificate().unwrap().unwrap();
        let peers = certificate
            .genesis
            .members
            .iter()
            .cloned()
            .map(|member| GuildPeer {
                member,
                endpoints: Vec::new(),
            })
            .collect();
        drop(source);
        let target_path = temp.path().join("target");
        let mut node = Node::open(&target_path, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let initial = node.dynamic_guild_state().unwrap().unwrap();
        node.store_checkpoint_with_authority(&first, false, true)
            .unwrap();
        let signer_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        let writer_fence = &first.checkpoint.writer_fences[0];
        let rotate_writer = GuildEvent {
            format_version: 1,
            guild_id,
            sequence: 1,
            parent: initial.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: writer_fence.owner,
                epoch: writer_fence.epoch,
                public_key: writer_fence.public_key,
            },
        };
        let mut signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&rotate_writer, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: rotate_writer,
            signatures,
        })
        .unwrap();
        let original = initial.members[0].member.clone();
        let mut historical_middle = None;
        for (sequence, domain) in [
            (2, "repeated-roster-middle".to_owned()),
            (3, original.failure_domain.clone()),
        ] {
            let state = node.dynamic_guild_state().unwrap().unwrap();
            let event = GuildEvent {
                format_version: 1,
                guild_id,
                sequence,
                parent: state.event_head,
                kind: mb_core::GuildEventKind::RelabelMember {
                    node_id: original.node_id,
                    failure_domain: domain,
                },
            };
            let mut signatures = signer_keys
                .iter()
                .map(|keys| sign_guild_event(&event, keys).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            node.install_guild_event(QuorumGuildEvent { event, signatures })
                .unwrap();
            if sequence == 2 {
                historical_middle = node.dynamic_guild_state().unwrap();
            }
        }
        let middle = historical_middle.unwrap();
        assert_eq!(middle.membership_epoch, 2);
        assert_eq!(
            node.dynamic_guild_state()
                .unwrap()
                .unwrap()
                .membership_epoch,
            3
        );

        let mut legacy = first.clone();
        legacy.checkpoint.format_version = 4;
        legacy.checkpoint.generation = 2;
        legacy.checkpoint.parent = Some(first.hash().unwrap());
        legacy.signatures.clear();
        for keys in &signer_keys {
            legacy.add_signature(keys).unwrap();
        }
        legacy.verify().unwrap();
        node.store_checkpoint_with_authority(&legacy, false, true)
            .unwrap();
        drop(node);
        let node = Node::open(&target_path, seed).unwrap();
        assert_eq!(
            node.latest_checkpoint_member_epoch(&legacy.checkpoint)
                .unwrap(),
            3
        );

        let mut backward = legacy.checkpoint.clone();
        backward.format_version = 5;
        backward.generation = 3;
        backward.parent = Some(legacy.hash().unwrap());
        backward.members = middle.active_members().cloned().collect();
        backward.authority = Some(mb_core::CheckpointAuthority {
            format_version: 1,
            membership_epoch: middle.membership_epoch,
            quorum: middle.quorum,
        });
        backward.validate().unwrap();
        assert!(
            node.validate_checkpoint_transition(&backward, false)
                .unwrap_err()
                .to_string()
                .contains("epoch moves backward")
        );
    }

    #[test]
    fn new_format_seven_signature_requires_authenticated_packing() {
        let mut checkpoint = GuildCheckpoint {
            format_version: 7,
            guild_id: [1; 32],
            genesis_hash: [2; 32],
            generation: 1,
            parent: None,
            members: Vec::new(),
            writer_fences: Vec::new(),
            revision_tombstones: Vec::new(),
            revisions: Vec::new(),
            coding_groups: Vec::new(),
            authority: None,
            packing_catalog: Some(PackedCatalog {
                id: [3; 32],
                format_version: 1,
                revision: 1,
                parent: None,
                profile: PackingProfile {
                    format_version: 1,
                    sector_size: 64,
                    slot_size: 16,
                },
                sectors: Vec::new(),
                source_authentication: None,
                legacy_bindings: None,
                legacy_attestations: None,
            }),
        };
        assert!(validate_checkpoint_for_signature(&checkpoint).is_err());

        checkpoint.packing_catalog.as_mut().unwrap().format_version = 3;
        checkpoint
            .packing_catalog
            .as_mut()
            .unwrap()
            .source_authentication = Some(Vec::new());
        assert!(validate_checkpoint_for_signature(&checkpoint).is_ok());

        let catalog = checkpoint.packing_catalog.as_mut().unwrap();
        catalog.format_version = 4;
        catalog.legacy_bindings = Some(Vec::new());
        assert!(validate_checkpoint_for_signature(&checkpoint).is_ok());
    }

    #[test]
    fn legacy_packing_binding_authenticates_the_signed_flat_root() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([92; 32]));
        let bytes = vec![17; V1_SECTOR_SIZE];
        let reference = SectorRef {
            id: [31; 32],
            root: sector_root(&bytes),
            logical_len: V1_SECTOR_SIZE as u32,
        };
        let binding =
            sign_legacy_packing_binding(&keys, Uuid::from_u128(44), &reference, &bytes).unwrap();
        binding
            .verify(mb_core::LEGACY_PACKING_BINDING_DOMAIN)
            .unwrap();
        assert_eq!(binding.signer, keys.node_id());
        assert_eq!(binding.value.flat_root, reference.root);
        assert_eq!(
            binding.value.source_commitment,
            merkle_commit(&bytes).unwrap()
        );

        let mut wrong_reference = reference;
        wrong_reference.root[0] ^= 1;
        assert!(
            sign_legacy_packing_binding(&keys, Uuid::from_u128(44), &wrong_reference, &bytes,)
                .is_err()
        );
    }

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
            sector_commitments: None,
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
            sector_commitments: None,
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

    pub(crate) fn recovery_guild_fixture() -> (Seed, QuorumGuildGenesis, Vec<GuildPeer>) {
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

    pub(crate) fn install_public_restore_fixture(
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

    pub(crate) fn install_test_checkpoint_and_dynamic_state(
        node: &mut Node,
        checkpoint: &QuorumCheckpoint,
        state: &DynamicGuildState,
    ) {
        checkpoint.verify().unwrap();
        state.validate().unwrap();
        let guild_id = checkpoint.checkpoint.guild_id;
        let parent_hash = node
            .current_checkpoint(guild_id)
            .unwrap()
            .map(|parent| parent.hash().unwrap());
        assert_eq!(checkpoint.checkpoint.parent, parent_hash);
        node.control
            .put_record(
                "guild-dynamic-state",
                b"primary",
                &canonical_bytes(state).unwrap(),
            )
            .unwrap();
        let hash = checkpoint.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                checkpoint.checkpoint.generation,
                parent_hash.as_ref(),
                &hash,
                &canonical_bytes(&checkpoint.checkpoint).unwrap(),
                &canonical_bytes(checkpoint).unwrap(),
                false,
            )
            .unwrap();
    }

    pub(crate) fn install_test_recovery_transcript(
        node: &mut Node,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) {
        assert_eq!(
            replay_coding_transcript(transcript).unwrap(),
            CodingReplayFinding::Verified
        );
        let bytes = canonical_bytes(transcript).unwrap();
        node.control
            .put_records(&[
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
            ])
            .unwrap();
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
            AutomaticBackupPoll::Start {
                protected_root_id,
                estimated_bytes: 4
            } if protected_root_id == root_id
        ));
        let revision_id = Uuid::new_v4();
        node.automatic_backup_submitted(revision_id, root_id)
            .unwrap();
        drop(node);

        let mut reopened = Node::open(&state, seed).unwrap();
        assert!(matches!(
            reopened.poll_automatic_backup(111).unwrap(),
            AutomaticBackupPoll::InFlight(actual) if actual == revision_id
        ));
        reopened
            .automatic_backup_finished(Some(revision_id), None, false, Some("capacity exhausted"))
            .unwrap();
        let status = reopened.automatic_backup_status().unwrap();
        assert!(status.blocked_reason.unwrap().contains("capacity"));
        assert!(status.retry_at_unix_seconds.is_none());
    }

    #[test]
    fn automatic_backup_noisy_root_cannot_starve_quiet_sibling() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let state_path = temp.path().join("state");
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(&state_path, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let noisy_id = Uuid::from_bytes([1; 16]);
        let quiet_id = Uuid::from_bytes([2; 16]);
        for (root_id, name) in [(noisy_id, "noisy"), (quiet_id, "quiet")] {
            let path = temp.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("payload"), name.as_bytes()).unwrap();
            let filesystem = filesystem_identity(&path).unwrap();
            node.control
                .put_record(
                    "protected-root",
                    root_id.as_bytes(),
                    &canonical_bytes(&ProtectedRoot {
                        format_version: 3,
                        root_id,
                        root_inode: fs::metadata(&path).unwrap().ino(),
                        path,
                        filesystem_id: filesystem.stable_id,
                    })
                    .unwrap(),
                )
                .unwrap();
        }
        node.configure_automatic_backup(&AutomaticBackupPolicy {
            enabled: true,
            quiet_period_seconds: 10,
            minimum_interval_seconds: 1,
            full_reconcile_interval_seconds: 60,
            daily_backup_limit: 10,
            daily_byte_limit: 1024,
        })
        .unwrap();
        node.mark_root_dirty_at(noisy_id, "initial noisy change", true, 100)
            .unwrap();
        node.mark_root_dirty_at(quiet_id, "quiet change", true, 100)
            .unwrap();
        node.mark_root_dirty_at(noisy_id, "more noise", true, 105)
            .unwrap();
        node.mark_root_dirty_at(noisy_id, "still noisy", true, 109)
            .unwrap();
        drop(node);

        let mut reopened = Node::open(&state_path, seed).unwrap();
        assert!(matches!(
            reopened.poll_automatic_backup(110).unwrap(),
            AutomaticBackupPoll::Start {
                protected_root_id,
                ..
            } if protected_root_id == quiet_id
        ));
        let state = reopened.automatic_backup_state(110).unwrap();
        assert_eq!(state.root_schedules.len(), 2);
        assert_eq!(state.root_schedules[0].dirty_since_unix_seconds, 109);
        assert_eq!(state.root_schedules[1].dirty_since_unix_seconds, 100);
    }

    #[test]
    fn automatic_backup_ignores_clean_roots_without_schedules() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path().join("state"), seed).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let clean_id = Uuid::from_bytes([1; 16]);
        let dirty_id = Uuid::from_bytes([2; 16]);
        for (root_id, name) in [(clean_id, "clean"), (dirty_id, "dirty")] {
            let path = temp.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("payload"), name.as_bytes()).unwrap();
            let filesystem = filesystem_identity(&path).unwrap();
            node.install_test_protected_root(ProtectedRoot {
                format_version: 3,
                root_id,
                root_inode: fs::metadata(&path).unwrap().ino(),
                path,
                filesystem_id: filesystem.stable_id,
            })
            .unwrap();
        }
        node.configure_automatic_backup(&AutomaticBackupPolicy {
            enabled: true,
            quiet_period_seconds: 1,
            minimum_interval_seconds: 1,
            full_reconcile_interval_seconds: 60,
            daily_backup_limit: 10,
            daily_byte_limit: 1_024,
        })
        .unwrap();
        let mut state = node.automatic_backup_state(100).unwrap();
        state.last_full_reconcile_unix_seconds = Some(100);
        node.store_automatic_backup_state(&state).unwrap();
        node.mark_root_dirty_at(dirty_id, "changed", true, 100)
            .unwrap();

        assert!(matches!(
            node.poll_automatic_backup(101).unwrap(),
            AutomaticBackupPoll::Start {
                protected_root_id,
                ..
            } if protected_root_id == dirty_id
        ));
        let state = node.automatic_backup_state(101).unwrap();
        assert_eq!(state.root_schedules.len(), 1);
        assert_eq!(state.root_schedules[0].protected_root_id, dirty_id);
    }

    #[test]
    fn automatic_backup_byte_budget_skips_oversized_oldest_root() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path().join("state"), seed).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let oversized_id = Uuid::from_bytes([1; 16]);
        let fitting_id = Uuid::from_bytes([2; 16]);
        for (root_id, name, bytes) in [
            (oversized_id, "oversized", vec![1; 10]),
            (fitting_id, "fitting", vec![2; 3]),
        ] {
            let path = temp.path().join(name);
            fs::create_dir(&path).unwrap();
            fs::write(path.join("payload"), bytes).unwrap();
            let filesystem = filesystem_identity(&path).unwrap();
            node.install_test_protected_root(ProtectedRoot {
                format_version: 3,
                root_id,
                root_inode: fs::metadata(&path).unwrap().ino(),
                path,
                filesystem_id: filesystem.stable_id,
            })
            .unwrap();
            node.mark_root_dirty_at(root_id, "changed", true, 100)
                .unwrap();
        }
        node.configure_automatic_backup(&AutomaticBackupPolicy {
            enabled: true,
            quiet_period_seconds: 1,
            minimum_interval_seconds: 1,
            full_reconcile_interval_seconds: 60,
            daily_backup_limit: 10,
            daily_byte_limit: 5,
        })
        .unwrap();
        let mut state = node.automatic_backup_state(100).unwrap();
        state.last_full_reconcile_unix_seconds = Some(100);
        node.store_automatic_backup_state(&state).unwrap();

        assert!(matches!(
            node.poll_automatic_backup(101).unwrap(),
            AutomaticBackupPoll::Start {
                protected_root_id,
                estimated_bytes: 3,
            } if protected_root_id == fitting_id
        ));
        let state = node.automatic_backup_state(101).unwrap();
        assert_eq!(state.root_retries.len(), 1);
        assert_eq!(state.root_retries[0].protected_root_id, oversized_id);
        assert_eq!(state.root_retries[0].retry_at_unix_seconds, 86_500);
        assert!(state.root_retries[0].reason.contains("byte limit"));
        assert!(state.blocked_reason.is_none());
        assert!(state.retry_at_unix_seconds.is_none());

        assert!(matches!(
            node.poll_automatic_backup(86_500).unwrap(),
            AutomaticBackupPoll::Start {
                protected_root_id,
                estimated_bytes: 3,
            } if protected_root_id == fitting_id
        ));
        let state = node.automatic_backup_state(86_500).unwrap();
        assert_eq!(state.root_retries.len(), 1);
        assert_eq!(state.root_retries[0].protected_root_id, oversized_id);
        assert_eq!(state.root_retries[0].retry_at_unix_seconds, 172_900);
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
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn git_repository_init_and_add_survive_daemon_reopen() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-node-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"first\r\nbytes\0").unwrap();
        let data = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([243; 32]);
        let mut node = Node::open(data.path(), seed.clone()).unwrap();
        let info = node.git_init(&source_root).unwrap();
        assert_eq!(info.path, source_root);
        assert_eq!(
            info.repository_id,
            node.git_init(&source_root).unwrap().repository_id
        );
        let first = node
            .git_add_path(info.repository_id, Path::new("tracked"))
            .unwrap()
            .unwrap();
        assert_eq!(first.mode, 0o100644);
        assert!(
            !node
                .git_abandon_pending_add(info.repository_id, Path::new("tracked"))
                .unwrap()
        );
        let first_commit = node
            .git_commit(
                info.repository_id,
                "Test Author",
                "author@example.test",
                "first",
            )
            .unwrap();
        assert_eq!(first_commit.parent_oid, None);
        node.git_pin_commit(info.repository_id, first_commit.oid)
            .unwrap();
        assert_eq!(
            node.git_commit_pins(info.repository_id).unwrap(),
            vec![first_commit.oid]
        );
        node.git_unpin_commit(info.repository_id, first_commit.oid)
            .unwrap();
        assert!(node.git_commit_pins(info.repository_id).unwrap().is_empty());
        let older = node.git_create_branch(info.repository_id, "older").unwrap();
        assert_eq!(older.oid, first_commit.oid);
        assert!(!older.current);
        assert!(
            node.git_switch_branch(info.repository_id, "older")
                .unwrap()
                .current
        );
        assert_eq!(node.git_status(info.repository_id).unwrap().branch, "older");
        node.git_switch_branch(info.repository_id, "main").unwrap();
        assert!(
            node.git_create_branch(info.repository_id, "older/nested")
                .is_err()
        );
        drop(node);

        let mut reopened = Node::open(data.path(), seed).unwrap();
        fs::write(source_root.join("tracked"), b"second\nbytes").unwrap();
        let unstaged = reopened.git_diff(info.repository_id, false).unwrap();
        assert!(!unstaged.patch.is_empty());
        assert!(
            unstaged
                .patch
                .windows(b"Binary files".len())
                .any(|part| part == b"Binary files")
        );
        assert!(
            reopened
                .git_diff(info.repository_id, true)
                .unwrap()
                .patch
                .is_empty()
        );
        let second = reopened
            .git_add(info.repository_id, Path::new("tracked"))
            .unwrap();
        assert_ne!(first.oid, second.oid);
        assert_eq!(second.repository_id, info.repository_id);
        assert!(
            reopened
                .git_diff(info.repository_id, false)
                .unwrap()
                .patch
                .is_empty()
        );
        assert!(
            !reopened
                .git_diff(info.repository_id, true)
                .unwrap()
                .patch
                .is_empty()
        );
        let second_commit = reopened
            .git_commit(
                info.repository_id,
                "Test Author",
                "author@example.test",
                "second",
            )
            .unwrap();
        assert_eq!(second_commit.parent_oid, Some(first_commit.oid));
        assert!(
            reopened
                .git_diff(info.repository_id, true)
                .unwrap()
                .patch
                .is_empty()
        );
        let status = reopened.git_status(info.repository_id).unwrap();
        assert_eq!(status.head_oid, Some(second_commit.oid));
        assert!(!status.history_backed_up);
        assert!(status.changes.is_empty());
        let bare_root = run_root.join("remote.git");
        git2::Repository::init_bare(&bare_root).unwrap();
        assert_eq!(
            reopened
                .git_push_bare(info.repository_id, &bare_root)
                .unwrap(),
            second_commit.oid
        );
        assert_eq!(
            git2::Repository::open_bare(&bare_root)
                .unwrap()
                .find_reference("refs/heads/main")
                .unwrap()
                .target()
                .unwrap()
                .as_bytes(),
            second_commit.oid
        );
        assert_eq!(
            reopened
                .git_fetch_bare(info.repository_id, &bare_root)
                .unwrap(),
            1
        );
        assert_eq!(
            reopened
                .git_pull_bare(info.repository_id, &bare_root, "", "")
                .unwrap(),
            second_commit.oid
        );
        assert_eq!(
            reopened.git_status(info.repository_id).unwrap().head_oid,
            Some(second_commit.oid)
        );
        let branches = reopened.git_branches(info.repository_id).unwrap();
        assert_eq!(branches.len(), 2);
        assert_eq!(branches[0].name, "main");
        assert!(branches[0].current);
        assert_eq!(branches[1], older);
        let remote_branches = reopened.git_remote_branches(info.repository_id).unwrap();
        assert_eq!(remote_branches.len(), 1);
        assert_eq!(remote_branches[0].name, "origin/main");
        assert_eq!(remote_branches[0].oid, second_commit.oid);
        assert_eq!(
            reopened
                .git_create_branch_from(info.repository_id, "from-origin", "origin/main")
                .unwrap()
                .oid,
            second_commit.oid
        );
        assert_eq!(
            reopened
                .git_delete_branch(info.repository_id, "from-origin", false)
                .unwrap()
                .oid,
            second_commit.oid
        );
        reopened
            .git_switch_branch(info.repository_id, "older")
            .unwrap();
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"first\r\nbytes\0"
        );
        assert_eq!(
            reopened.git_status(info.repository_id).unwrap().branch,
            "older"
        );
        assert_eq!(
            reopened
                .git_merge_branch(info.repository_id, "main", "Author", "a@example.test")
                .unwrap(),
            second_commit.oid
        );
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"second\nbytes"
        );
        reopened
            .git_switch_branch(info.repository_id, "main")
            .unwrap();
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"second\nbytes"
        );
        let history = reopened.git_log(info.repository_id, 10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].oid, second_commit.oid);
        assert_eq!(history[1].oid, first_commit.oid);
        fs::write(source_root.join("text"), b"alpha\r\n").unwrap();
        reopened
            .git_add(info.repository_id, Path::new("text"))
            .unwrap();
        let added_text = reopened.git_diff(info.repository_id, true).unwrap();
        assert!(
            added_text
                .patch
                .windows(b"+alpha\r\n".len())
                .any(|part| part == b"+alpha\r\n")
        );
        assert!(
            reopened
                .git_diff(info.repository_id, false)
                .unwrap()
                .patch
                .is_empty()
        );
        let large_path = source_root.join("large");
        File::create(&large_path)
            .unwrap()
            .set_len(17 * 1024 * 1024)
            .unwrap();
        reopened
            .git_add(info.repository_id, Path::new("large"))
            .unwrap();
        reopened
            .git_commit(
                info.repository_id,
                "Test Author",
                "author@example.test",
                "large",
            )
            .unwrap();
        assert!(
            reopened
                .git_diff(info.repository_id, false)
                .unwrap()
                .patch
                .is_empty()
        );
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&large_path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let mode_only = reopened.git_diff(info.repository_id, false).unwrap();
        assert!(
            mode_only
                .patch
                .windows(b"old mode 100644\nnew mode 100755\n".len())
                .any(|part| { part == b"old mode 100644\nnew mode 100755\n" })
        );
        fs::remove_file(source_root.join("text")).unwrap();
        assert!(
            reopened
                .git_add_path(info.repository_id, Path::new("text"))
                .unwrap()
                .is_none()
        );
        assert!(
            reopened
                .git_status(info.repository_id)
                .unwrap()
                .changes
                .iter()
                .any(|change| change.path == b"text"
                    && change.staged == Some(mb_git::GitChange::Deleted))
        );
        assert!(source_root.join(".mutualbackup/catalog.db").exists());
        let prune = reopened.git_prune(info.repository_id).unwrap();
        assert_eq!(prune.repository_id, info.repository_id);
        assert_eq!(prune.format_version, 1);
        assert_eq!(prune.physical_bytes_reclaimed, None);
        drop(reopened);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn git_linked_worktree_registration_survives_daemon_reopen() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-node-worktree-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::write(primary_root.join("tracked"), b"exact\r\n\0bytes").unwrap();
        let data = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([232; 32]);
        let mut node = Node::open(data.path(), seed.clone()).unwrap();
        let repository = node.git_init(&primary_root).unwrap();
        node.git_add(repository.repository_id, Path::new("tracked"))
            .unwrap();
        node.git_commit(
            repository.repository_id,
            "Test Author",
            "author@example.test",
            "base",
        )
        .unwrap();
        node.git_create_branch(repository.repository_id, "topic")
            .unwrap();
        let linked = node
            .git_add_worktree(repository.repository_id, &linked_root, "topic")
            .unwrap();
        assert_eq!(
            node.git_worktrees(repository.repository_id).unwrap(),
            vec![linked.clone()]
        );
        drop(node);

        let mut reopened = Node::open(data.path(), seed).unwrap();
        assert_eq!(
            reopened
                .git_resume_worktree(repository.repository_id, linked.worktree_id)
                .unwrap(),
            linked
        );
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"exact\r\n\0bytes"
        );
        let status = reopened
            .git_worktree_status(repository.repository_id, linked.worktree_id)
            .unwrap();
        assert_eq!(status.branch, "topic");
        assert!(status.changes.is_empty());
        fs::write(linked_root.join("tracked"), b"linked\nchange").unwrap();
        assert!(
            reopened
                .git_worktree_add_path(
                    repository.repository_id,
                    linked.worktree_id,
                    Path::new("tracked")
                )
                .unwrap()
                .is_some()
        );
        assert!(
            !reopened
                .git_worktree_diff(repository.repository_id, linked.worktree_id, true)
                .unwrap()
                .patch
                .is_empty()
        );
        let dirty_sequence = reopened
            .root_dirty_state(repository.repository_id)
            .unwrap()
            .unwrap()
            .change_sequence;
        let committed = reopened
            .git_worktree_commit(
                repository.repository_id,
                linked.worktree_id,
                "Test Author",
                "author@example.test",
                "linked",
            )
            .unwrap();
        assert!(
            reopened
                .root_dirty_state(repository.repository_id)
                .unwrap()
                .unwrap()
                .change_sequence
                > dirty_sequence
        );
        assert_eq!(
            reopened
                .git_worktree_log(repository.repository_id, linked.worktree_id, 1)
                .unwrap()[0]
                .oid,
            committed.oid
        );
        assert!(
            reopened
                .git_worktree_branches(repository.repository_id, linked.worktree_id)
                .unwrap()
                .iter()
                .any(|branch| branch.name == "topic" && branch.current)
        );
        reopened
            .git_create_branch_from(repository.repository_id, "base-copy", "main")
            .unwrap();
        reopened
            .git_worktree_switch_branch(repository.repository_id, linked.worktree_id, "base-copy")
            .unwrap();
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"exact\r\n\0bytes"
        );
        let graph = reopened
            .open_git_repository(repository.repository_id)
            .unwrap()
            .export_graph_source()
            .unwrap();
        drop(reopened);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn git_prune_keeps_signed_revision_history_until_its_retirement() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-prune-revision-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"base\r\n").unwrap();
        let data = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([83; 32]);
        let mut node = Node::open(data.path(), seed.clone()).unwrap();
        let info = node.git_init(&source_root).unwrap();
        node.git_add(info.repository_id, Path::new("tracked"))
            .unwrap();
        node.git_commit(info.repository_id, "Author", "a@example.test", "base")
            .unwrap();
        node.git_create_branch(info.repository_id, "topic").unwrap();
        node.git_switch_branch(info.repository_id, "topic").unwrap();
        fs::write(source_root.join("tracked"), b"topic\nbytes\0").unwrap();
        node.git_add(info.repository_id, Path::new("tracked"))
            .unwrap();
        let topic = node
            .git_commit(info.repository_id, "Author", "a@example.test", "topic")
            .unwrap();
        // The index is replaced twice with identical bytes. Only the anchor
        // selected by the backup recipe must survive after this branch dies.
        node.git_add(info.repository_id, Path::new("tracked"))
            .unwrap();
        node.git_add(info.repository_id, Path::new("tracked"))
            .unwrap();
        node.git_switch_branch(info.repository_id, "main").unwrap();
        let before = node
            .open_git_repository(info.repository_id)
            .unwrap()
            .export_graph_source()
            .unwrap();
        let guild_id = [84; 32];
        let revision = prepare_revision(
            &mut node.control,
            &node.keys,
            guild_id,
            info.repository_id,
            &source_root,
            1,
            None,
            SourceBackendKind::ReflinkV1,
            WriterCredentials {
                epoch: 1,
                secret: &[85; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        let protected_sectors = revision
            .value
            .data_sectors
            .iter()
            .map(|reference| {
                (
                    reference.id,
                    node.sector_for_guild(&guild_id, &reference.id).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        assert!(!protected_sectors.is_empty());
        node.git_delete_branch(info.repository_id, "topic", true)
            .unwrap();
        let retained = node.git_prune(info.repository_id).unwrap();
        assert_eq!(retained.native_anchors_removed, 2);
        assert_eq!(retained.metadata_objects_removed, 0);
        assert!(before.objects.iter().any(|object| object.oid == topic.oid));
        let current = node
            .open_git_repository(info.repository_id)
            .unwrap()
            .export_graph_source()
            .unwrap();
        let orphan = before
            .blobs
            .iter()
            .find(|blob| !current.blobs.iter().any(|live| live.oid == blob.oid))
            .unwrap()
            .anchor
            .clone();
        assert!(orphan.open_verified().is_ok());
        assert!(
            git_prune_recipe_anchor_ids(&node.control)
                .unwrap()
                .contains(&orphan.anchor_id)
        );
        for (sector_id, expected) in &protected_sectors {
            assert_eq!(
                node.sector_for_guild(&guild_id, sector_id).unwrap(),
                *expected
            );
        }

        drop(node);
        let mut node = Node::open(data.path(), seed).unwrap();
        for (sector_id, expected) in &protected_sectors {
            assert_eq!(
                node.sector_for_guild(&guild_id, sector_id).unwrap(),
                *expected
            );
        }
        fs::write(source_root.join("tracked"), b"changed outside Git").unwrap();
        node.git_restore_worktree(info.repository_id, &[PathBuf::from("tracked")])
            .unwrap();
        assert_eq!(fs::read(source_root.join("tracked")).unwrap(), b"base\r\n");

        node.control
            .delete_record("user-revision", revision.value.revision_id.as_bytes())
            .unwrap();
        let still_serving = node.git_prune(info.repository_id).unwrap();
        assert_eq!(still_serving.native_anchors_removed, 0);
        assert!(still_serving.metadata_objects_removed > 0);
        assert!(orphan.open_verified().is_ok());
        for (sector_id, expected) in &protected_sectors {
            assert_eq!(
                node.sector_for_guild(&guild_id, sector_id).unwrap(),
                *expected
            );
        }
        for reference in revision
            .value
            .metadata_sectors
            .iter()
            .chain(&revision.value.data_sectors)
        {
            node.control
                .delete_record("local-sector", &reference.id)
                .unwrap();
        }
        retire_revision_anchor(&mut node.control, revision.value.revision_id).unwrap();
        let removed = node.git_prune(info.repository_id).unwrap();
        assert!(removed.native_anchors_removed > 0);
        assert_eq!(removed.metadata_objects_removed, 0);
        assert!(orphan.open_verified().is_err());
        assert_eq!(
            node.open_git_repository(info.repository_id)
                .unwrap()
                .export_graph_source()
                .unwrap(),
            current
        );
        drop(node);
        for blob in before.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    fn packed_sectors_are_durable_and_guild_scoped() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([218; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let guild_id = [217; 32];
        let source_bytes = (0_u8..64).collect::<Vec<_>>();
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
                source_commitment: Some(mb_core::merkle_commit(&source_bytes).unwrap()),
                bytes: source_bytes,
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
        let source_bytes = vec![3; 64];
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
                source_commitment: Some(mb_core::merkle_commit(&source_bytes).unwrap()),
                bytes: source_bytes,
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

        node.automatic_backup_finished(None, None, false, Some(&unicode_error))
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
        let blocked = node.automatic_backup_status().unwrap();
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
            AutomaticBackupPoll::Start {
                protected_root_id,
                ..
            } if protected_root_id == root_id
        ));
    }

    #[test]
    fn automatic_backup_skips_unavailable_dirty_root() {
        use std::os::unix::fs::MetadataExt;

        let temp = tempfile::tempdir().unwrap();
        let missing = temp.path().join("missing-root");
        let healthy = temp.path().join("healthy-root");
        fs::create_dir(&missing).unwrap();
        fs::create_dir(&healthy).unwrap();
        fs::write(healthy.join("payload"), b"healthy").unwrap();
        let missing_filesystem = filesystem_identity(&missing).unwrap();
        let healthy_filesystem = filesystem_identity(&healthy).unwrap();
        let missing_inode = fs::metadata(&missing).unwrap().ino();
        let healthy_inode = fs::metadata(&healthy).unwrap().ino();
        let missing_id = Uuid::from_bytes([1; 16]);
        let healthy_id = Uuid::from_bytes([2; 16]);
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path().join("state"), seed).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        for root in [
            ProtectedRoot {
                format_version: 3,
                root_id: missing_id,
                path: missing.clone(),
                filesystem_id: missing_filesystem.stable_id,
                root_inode: missing_inode,
            },
            ProtectedRoot {
                format_version: 3,
                root_id: healthy_id,
                path: healthy,
                filesystem_id: healthy_filesystem.stable_id,
                root_inode: healthy_inode,
            },
        ] {
            node.control
                .put_record(
                    "protected-root",
                    root.root_id.as_bytes(),
                    &canonical_bytes(&root).unwrap(),
                )
                .unwrap();
            node.mark_root_dirty_at(root.root_id, "changed", true, 100)
                .unwrap();
        }
        node.configure_automatic_backup(&AutomaticBackupPolicy {
            enabled: true,
            quiet_period_seconds: 1,
            minimum_interval_seconds: 10,
            full_reconcile_interval_seconds: 60,
            daily_backup_limit: 10,
            daily_byte_limit: 1024,
        })
        .unwrap();
        fs::remove_dir_all(&missing).unwrap();

        assert!(matches!(
            node.poll_automatic_backup(101).unwrap(),
            AutomaticBackupPoll::Start {
                protected_root_id,
                estimated_bytes: 7,
            } if protected_root_id == healthy_id
        ));
        let state = node.automatic_backup_state(101).unwrap();
        assert_eq!(state.root_retries.len(), 1);
        assert_eq!(state.root_retries[0].protected_root_id, missing_id);
        assert_eq!(state.root_retries[0].retry_at_unix_seconds, 111);
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
    fn retry_input_intent_pins_packed_cache_until_terminal_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([223; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let guild_id = revision.value.guild_id;
        let signing_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        let certificate = node.installed_guild_certificate().unwrap().unwrap();
        let members = certificate.genesis.members.clone();
        node.adopt_recovered_guild(
            certificate,
            members
                .iter()
                .cloned()
                .map(|member| crate::GuildPeer {
                    member,
                    endpoints: Vec::new(),
                })
                .collect(),
        )
        .unwrap();
        let local_id = node.keys().node_id();
        let local = members
            .iter()
            .find(|member| member.node_id == local_id)
            .unwrap();
        let remotes = members
            .iter()
            .filter(|member| member.node_id != local_id)
            .collect::<Vec<_>>();
        let profile = PackingProfile {
            format_version: 1,
            sector_size: V1_SECTOR_SIZE as u32,
            slot_size: mb_core::MERKLE_LEAF_SIZE as u32,
        };
        let source = vec![84; V1_SECTOR_SIZE];
        let packed = mb_core::pack_incremental(
            profile,
            None,
            vec![mb_core::PackingInput {
                owner: local_id,
                protected_root: [221; 32],
                object_id: [220; 32],
                source_commitment: Some(merkle_commit(&source).unwrap()),
                bytes: source,
            }],
        )
        .unwrap();
        let sector = packed.sectors[0].clone();
        node.store_packed_sector(guild_id, profile, sector.clone())
            .unwrap();
        let initial = node
            .sign_coding_attempt_plan(CodingAttemptPlan {
                format_version: 2,
                attempt_id: [219; 16],
                checkpoint_hash: [218; 32],
                membership_epoch: 1,
                geometry: mb_core::CodingPlanGeometry {
                    format_version: 1,
                    guild_id,
                    profile: mb_core::CodingProfile::new(1, 1, V1_SECTOR_SIZE as u32),
                    information: vec![mb_core::InformationRoleV2 {
                        owner: local_id,
                        failure_domain: local.failure_domain.clone(),
                        sector: mb_core::RangeSectorRef {
                            id: sector.descriptor.id,
                            commitment: sector.descriptor.commitment.clone(),
                            logical_len: V1_SECTOR_SIZE as u32,
                            virtual_zero: false,
                        },
                    }],
                    parity: vec![mb_core::ParityPlacementV2 {
                        holder: remotes[0].node_id,
                        failure_domain: remotes[0].failure_domain.clone(),
                        row: 0,
                    }],
                },
                delegator: local_id,
                coding_coordinator: local_id,
                verification_coordinator: remotes[0].node_id,
                expires_at_unix_seconds: unix_seconds() + 600,
                information_roots: Some(vec![sector.descriptor.flat_root]),
            })
            .unwrap();
        node.enqueue_coding_launch_with_information(
            initial.clone(),
            Some(BTreeMap::from([(
                sector.descriptor.id,
                sector.descriptor.clone(),
            )])),
        )
        .unwrap();
        let failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: initial.clone(),
                error_hash: [217; 32],
            },
            node.keys(),
        )
        .unwrap();
        node.accept_coding_failure(local_id, failure).unwrap();
        let successor = node
            .prepare_coding_retry(
                initial.value.attempt_id,
                remotes[1].node_id,
                remotes[2].node_id,
                unix_seconds() + 600,
            )
            .unwrap();
        node.complete_coding_retry(initial.value.attempt_id)
            .unwrap();
        let advance = |node: &mut Node, head: &QuorumCheckpoint| {
            let previous = head.hash().unwrap();
            let mut next = QuorumCheckpoint {
                checkpoint: head.checkpoint.clone(),
                signatures: Vec::new(),
            };
            next.checkpoint.generation += 1;
            next.checkpoint.parent = Some(previous);
            for keys in &signing_keys {
                next.add_signature(keys).unwrap();
            }
            next.verify().unwrap();
            let hash = next.hash().unwrap();
            node.control
                .commit_checkpoint(
                    &guild_id,
                    next.checkpoint.generation,
                    Some(&previous),
                    &hash,
                    &canonical_bytes(&next.checkpoint).unwrap(),
                    &canonical_bytes(&next).unwrap(),
                    false,
                )
                .unwrap();
            node.reconcile_garbage_collection().unwrap();
            next
        };
        let mut head = node.current_checkpoint(guild_id).unwrap().unwrap();
        for _ in 0..2 {
            head = advance(&mut node, &head);
            assert_eq!(
                node.sector_for_guild(&guild_id, &sector.descriptor.id)
                    .unwrap(),
                sector.bytes
            );
            assert!(
                node.control
                    .get_record(
                        "gc-packed-sector",
                        &packed_record_id(&guild_id, &sector.descriptor.id)
                    )
                    .unwrap()
                    .is_none()
            );
        }
        drop(node);
        node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.sector_for_guild(&guild_id, &sector.descriptor.id)
                .unwrap(),
            sector.bytes
        );
        assert!(node.retire_coding_retry_plan(&successor).unwrap());
        node.complete_coding_retry_after_cleanup(initial.value.attempt_id)
            .unwrap();
        node.reconcile_garbage_collection().unwrap();
        head = advance(&mut node, &head);
        assert!(
            node.sector_for_guild(&guild_id, &sector.descriptor.id)
                .is_err()
        );
        drop(node);
        let reopened = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            reopened.current_checkpoint(guild_id).unwrap().unwrap(),
            head
        );
        assert!(
            reopened
                .sector_for_guild(&guild_id, &sector.descriptor.id)
                .is_err()
        );
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
    fn recovered_dynamic_node_serves_forgotten_add_evidence() {
        recovered_dynamic_node_serves_forgotten_add_evidence_case(false);
    }

    #[test]
    fn recovered_legacy_add_uses_preissued_certificate_after_signer_loss() {
        recovered_dynamic_node_serves_forgotten_add_evidence_case(true);
    }

    fn recovered_dynamic_node_serves_forgotten_add_evidence_case(legacy: bool) {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([223; 32]);
        let mut source = Node::open(temp.path().join("source"), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut source, &seed);
        let guild_id = revision.value.guild_id;
        let certificate = source.installed_guild_certificate().unwrap().unwrap();
        let peers = certificate
            .genesis
            .members
            .iter()
            .cloned()
            .map(|member| GuildPeer {
                member,
                endpoints: Vec::new(),
            })
            .collect::<Vec<_>>();
        let keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        source
            .adopt_recovered_guild(certificate.clone(), peers.clone())
            .unwrap();
        let mut checkpoint = source.current_checkpoint(guild_id).unwrap().unwrap();
        checkpoint.checkpoint.format_version = 4;
        checkpoint.signatures.clear();
        for key in &keys {
            checkpoint.add_signature(key).unwrap();
        }
        checkpoint.verify().unwrap();

        let members = certificate.genesis.members.clone();
        let local = members
            .iter()
            .find(|member| member.node_id == source.keys().node_id())
            .unwrap();
        let remotes = members
            .iter()
            .filter(|member| member.node_id != local.node_id)
            .collect::<Vec<_>>();
        let shards =
            mb_core::encode(mb_core::CodingProfile::new(1, 1, 64), vec![vec![91; 64]]).unwrap();
        let plan = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [192; 16],
            checkpoint_hash: checkpoint.hash().unwrap(),
            membership_epoch: 1,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id,
                profile: mb_core::CodingProfile::new(1, 1, 64),
                information: vec![mb_core::InformationRoleV2 {
                    owner: local.node_id,
                    failure_domain: local.failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: [193; 32],
                        commitment: merkle_commit(&shards[0]).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: remotes[0].node_id,
                    failure_domain: remotes[0].failure_domain.clone(),
                    row: 0,
                }],
            },
            delegator: remotes[1].node_id,
            coding_coordinator: remotes[2].node_id,
            verification_coordinator: remotes[3].node_id,
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![sector_root(&shards[0])]),
        };
        let delegator = keys
            .iter()
            .find(|key| key.node_id() == plan.delegator)
            .unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, delegator).unwrap();
        let transcript = test_coding_transcript(plan.clone(), &shards, &keys);
        let mut wrong_plan = plan.value.clone();
        wrong_plan.attempt_id = [194; 16];
        let wrong_plan =
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, wrong_plan, delegator).unwrap();
        let wrong_transcript = test_coding_transcript(wrong_plan, &shards, &keys);
        assert_eq!(
            wrong_transcript.value.manifest.value.group.id,
            transcript.value.manifest.value.group.id
        );
        let certify = |source: &Node, kind| {
            let state = source.dynamic_guild_state().unwrap().unwrap();
            let event = GuildEvent {
                format_version: if matches!(
                    kind,
                    mb_core::GuildEventKind::AddCodingGroupBound { .. }
                ) {
                    2
                } else {
                    1
                },
                guild_id,
                sequence: state.event_sequence + 1,
                parent: state.event_head,
                kind,
            };
            let mut signatures = keys
                .iter()
                .map(|key| sign_guild_event(&event, key).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            QuorumGuildEvent { event, signatures }
        };
        let group = transcript.value.manifest.value.group.clone();
        let add = certify(
            &source,
            if legacy {
                mb_core::GuildEventKind::AddCodingGroup {
                    group: group.clone(),
                }
            } else {
                mb_core::GuildEventKind::AddCodingGroupBound {
                    group: group.clone(),
                    transcript_hash: *blake3::hash(&canonical_bytes(&transcript).unwrap())
                        .as_bytes(),
                }
            },
        );
        let binding = if legacy {
            let statement = LegacyCodingAddStatement::for_event(
                &add,
                *blake3::hash(&canonical_bytes(&transcript).unwrap()).as_bytes(),
            )
            .unwrap();
            let mut signatures = keys
                .iter()
                .map(|key| sign_legacy_coding_add_binding(&statement, key).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            Some(QuorumLegacyCodingAddBinding {
                statement,
                signatures,
            })
        } else {
            None
        };
        let group_id = transcript.value.manifest.value.group.id;
        let add_hash = add.event.hash().unwrap();
        if let Some(binding) = &binding {
            source
                .install_legacy_coding_group_event(add.clone(), transcript.clone(), binding.clone())
                .unwrap();
        } else {
            source
                .install_coding_group_event(add.clone(), transcript.clone())
                .unwrap();
        }
        let state = source.dynamic_guild_state().unwrap().unwrap();
        let retire = certify(
            &source,
            mb_core::GuildEventKind::RetireCodingGroup {
                group_id,
                retain_through_event: state.event_sequence + 1,
            },
        );
        source.install_guild_event(retire).unwrap();
        let forget = certify(
            &source,
            mb_core::GuildEventKind::ForgetCodingGroup { group_id },
        );
        source.install_guild_event(forget).unwrap();
        let events = source
            .guild_event_tail(0, certificate.hash().unwrap())
            .unwrap()
            .events;
        assert_eq!(events.len(), 3);
        let evidence = source
            .coding_transcript_for_event(guild_id, group_id, add.event.sequence, add_hash)
            .unwrap();
        let mut poisoned = Node::open(temp.path().join("poisoned"), seed.clone()).unwrap();
        poisoned
            .adopt_recovered_guild(certificate.clone(), peers.clone())
            .unwrap();
        let wrong_install = if let Some(binding) = &binding {
            poisoned.install_legacy_coding_group_event(
                add.clone(),
                wrong_transcript.clone(),
                binding.clone(),
            )
        } else {
            poisoned.install_coding_group_event(add.clone(), wrong_transcript.clone())
        };
        assert!(wrong_install.is_err());
        assert_eq!(
            poisoned
                .dynamic_guild_state()
                .unwrap()
                .unwrap()
                .event_sequence,
            0
        );
        if let Some(binding) = &binding {
            poisoned
                .install_legacy_coding_group_event(add.clone(), transcript.clone(), binding.clone())
                .unwrap();
        } else {
            poisoned
                .install_coding_group_event(add.clone(), transcript.clone())
                .unwrap();
        }
        if legacy {
            let mut no_certificate =
                Node::open(temp.path().join("no-certificate"), seed.clone()).unwrap();
            assert!(
                no_certificate
                    .adopt_recovered_dynamic_guild(
                        certificate.clone(),
                        &checkpoint,
                        events.clone(),
                        peers.clone(),
                        vec![(
                            add_hash,
                            VerifiedCodingTranscript::verify(evidence.clone()).unwrap(),
                        )],
                        Vec::new(),
                    )
                    .is_err()
            );
            assert!(no_certificate.installed_guild().unwrap().is_none());
        }
        let mut rejected_recovery = Node::open(temp.path().join("rejected"), seed.clone()).unwrap();
        assert!(
            rejected_recovery
                .adopt_recovered_dynamic_guild(
                    certificate.clone(),
                    &checkpoint,
                    events.clone(),
                    peers.clone(),
                    vec![(
                        add_hash,
                        VerifiedCodingTranscript::verify(wrong_transcript).unwrap(),
                    )],
                    binding.clone().into_iter().collect(),
                )
                .is_err()
        );

        let recovered_path = temp.path().join("recovered");
        let mut recovered = Node::open(&recovered_path, seed.clone()).unwrap();
        recovered
            .adopt_recovered_dynamic_guild(
                certificate.clone(),
                &checkpoint,
                events,
                peers.clone(),
                vec![(
                    add_hash,
                    VerifiedCodingTranscript::verify(evidence).unwrap(),
                )],
                binding.clone().into_iter().collect(),
            )
            .unwrap();
        assert!(
            recovered
                .dynamic_guild_state()
                .unwrap()
                .unwrap()
                .coding_groups
                .is_empty()
        );
        assert_eq!(
            recovered
                .coding_transcript_for_event(guild_id, group_id, add.event.sequence, add_hash)
                .unwrap(),
            transcript
        );
        drop(recovered);
        let recovered = Node::open(&recovered_path, seed.clone()).unwrap();
        assert_eq!(
            recovered
                .coding_transcript_for_event(guild_id, group_id, add.event.sequence, add_hash)
                .unwrap(),
            transcript
        );
        if legacy {
            assert_eq!(
                legacy_coding_add_binding_from_store(
                    &recovered.control,
                    guild_id,
                    add.event.sequence,
                    add_hash,
                )
                .unwrap(),
                binding,
            );
        }
        let mut lagging = Node::open(temp.path().join("lagging"), seed).unwrap();
        lagging
            .adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let tail = recovered
            .guild_event_tail(0, certificate.hash().unwrap())
            .unwrap();
        for event in tail.events {
            if let Some((group, _)) = event.event.kind.coding_group_add() {
                let transcript = recovered
                    .coding_transcript_for_event(
                        guild_id,
                        group.id,
                        event.event.sequence,
                        event.event.hash().unwrap(),
                    )
                    .unwrap();
                if legacy {
                    assert!(
                        lagging
                            .install_coding_group_event(event, transcript)
                            .is_err()
                    );
                    assert_eq!(
                        lagging
                            .dynamic_guild_state()
                            .unwrap()
                            .unwrap()
                            .event_sequence,
                        0
                    );
                    return;
                }
                lagging
                    .install_coding_group_event(event, transcript)
                    .unwrap();
            } else {
                lagging.install_guild_event(event).unwrap();
            }
        }
        assert_eq!(
            lagging
                .dynamic_guild_state()
                .unwrap()
                .unwrap()
                .event_sequence,
            3
        );
    }

    #[test]
    fn zero_only_and_unassigned_activation_leave_no_pending_pin() {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([222; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        let certificate = node.installed_guild_certificate().unwrap().unwrap();
        let members = certificate.genesis.members.clone();
        node.adopt_recovered_guild(
            certificate,
            members
                .iter()
                .cloned()
                .map(|member| GuildPeer {
                    member,
                    endpoints: Vec::new(),
                })
                .collect(),
        )
        .unwrap();
        let local = members
            .iter()
            .find(|member| member.node_id == node.keys().node_id())
            .unwrap();
        let remotes = members
            .iter()
            .filter(|member| member.node_id != local.node_id)
            .collect::<Vec<_>>();
        let shards =
            mb_core::encode(mb_core::CodingProfile::new(1, 1, 64), vec![vec![0; 64]]).unwrap();
        let plan = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [181; 16],
            checkpoint_hash: [182; 32],
            membership_epoch: 1,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id: revision.value.guild_id,
                profile: mb_core::CodingProfile::new(1, 1, 64),
                information: vec![mb_core::InformationRoleV2 {
                    owner: local.node_id,
                    failure_domain: local.failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: [183; 32],
                        commitment: merkle_commit(&shards[0]).unwrap(),
                        logical_len: 64,
                        virtual_zero: true,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: remotes[0].node_id,
                    failure_domain: remotes[0].failure_domain.clone(),
                    row: 0,
                }],
            },
            delegator: remotes[1].node_id,
            coding_coordinator: remotes[2].node_id,
            verification_coordinator: remotes[3].node_id,
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![[0; 32]]),
        };
        let delegator = keys
            .iter()
            .find(|key| key.node_id() == plan.delegator)
            .unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, delegator).unwrap();
        let transcript = test_coding_transcript(plan.clone(), &shards, &keys);
        node.activate_coding_attempt(&transcript).unwrap();
        assert!(
            node.control
                .get_record("coding-pending-activation", &plan.value.attempt_id)
                .unwrap()
                .is_none()
        );

        let mut unassigned = plan.value.clone();
        unassigned.attempt_id = [184; 16];
        unassigned.geometry.information[0].owner = remotes[1].node_id;
        unassigned.geometry.information[0].failure_domain = remotes[1].failure_domain.clone();
        let unassigned =
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, unassigned, delegator).unwrap();
        let unassigned_transcript = test_coding_transcript(unassigned.clone(), &shards, &keys);
        assert!(
            node.activate_coding_attempt(&unassigned_transcript)
                .is_err()
        );
        assert!(
            node.control
                .get_record("coding-pending-activation", &unassigned.value.attempt_id)
                .unwrap()
                .is_none()
        );

        // Opening an older store may encounter pins written for attempts that
        // never had a physical shard on this node. Reconciliation retires them.
        node.control
            .put_record(
                "coding-pending-activation",
                &plan.value.attempt_id,
                &canonical_bytes(&plan).unwrap(),
            )
            .unwrap();
        node.reconcile_garbage_collection().unwrap();
        assert!(
            node.control
                .get_record("coding-pending-activation", &plan.value.attempt_id)
                .unwrap()
                .is_none()
        );
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        assert!(
            node.control
                .records("coding-pending-activation")
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn remote_information_activation_pins_ready_shard_until_add() {
        let temp = tempfile::tempdir().unwrap();
        let volume = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([223; 32]);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let revision = install_public_restore_fixture(&mut node, &seed);
        let guild_id = revision.value.guild_id;
        let signing_keys = std::iter::once(seed.clone())
            .chain((0_u8..4).map(|index| Seed::from_bytes([index + 228; 32])))
            .map(|seed| KeyMaterial::from_seed(&seed))
            .collect::<Vec<_>>();
        let certificate = node.installed_guild_certificate().unwrap().unwrap();
        let members = certificate.genesis.members.clone();
        node.adopt_recovered_guild(
            certificate,
            members
                .iter()
                .cloned()
                .map(|member| GuildPeer {
                    member,
                    endpoints: Vec::new(),
                })
                .collect(),
        )
        .unwrap();
        node.configure_storage_volumes(&[volume.path().to_path_buf()], 1024 * 1024, 0)
            .unwrap();
        let local = members
            .iter()
            .find(|member| member.node_id == node.keys().node_id())
            .unwrap();
        let remotes = members
            .iter()
            .filter(|member| member.node_id != local.node_id)
            .collect::<Vec<_>>();
        let information = vec![177; 64];
        let shards =
            mb_core::encode(mb_core::CodingProfile::new(1, 1, 64), vec![information]).unwrap();
        let sector_id = [178; 32];
        let plan = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [179; 16],
            checkpoint_hash: [180; 32],
            membership_epoch: 1,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id,
                profile: mb_core::CodingProfile::new(1, 1, 64),
                information: vec![mb_core::InformationRoleV2 {
                    owner: local.node_id,
                    failure_domain: local.failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: sector_id,
                        commitment: merkle_commit(&shards[0]).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: remotes[0].node_id,
                    failure_domain: remotes[0].failure_domain.clone(),
                    row: 0,
                }],
            },
            delegator: remotes[1].node_id,
            coding_coordinator: remotes[2].node_id,
            verification_coordinator: remotes[3].node_id,
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![sector_root(&shards[0])]),
        };
        let delegator = signing_keys
            .iter()
            .find(|key| key.node_id() == plan.delegator)
            .unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, delegator).unwrap();
        let transcript = test_coding_transcript(plan.clone(), &shards, &signing_keys);
        node.reserve_coding_information(&plan, 0).unwrap();
        node.write_coding_information_range(&plan, 0, 0, &shards[0])
            .unwrap();
        node.finish_coding_information_upload(&plan, 0).unwrap();
        node.activate_coding_attempt(&transcript).unwrap();
        assert!(
            node.control
                .records("coding-activation-job")
                .unwrap()
                .is_empty()
        );
        assert!(
            node.control
                .records("coding-launch-job")
                .unwrap()
                .is_empty()
        );
        assert!(
            node.control
                .get_record("coding-pending-activation", &plan.value.attempt_id)
                .unwrap()
                .is_some()
        );

        let first = node.current_checkpoint(guild_id).unwrap().unwrap();
        let first_hash = first.hash().unwrap();
        let candidate_id = variable_emergency_id(&sector_id, 0);
        node.control
            .put_record(
                "gc-variable-sector",
                &candidate_id,
                &canonical_bytes(&GarbageCandidate {
                    format_version: 1,
                    first_unreachable_generation: first.checkpoint.generation,
                    checkpoint_hash: first_hash,
                    parity_root: Some(merkle_commit(&shards[0]).unwrap().root),
                })
                .unwrap(),
            )
            .unwrap();
        drop(node);

        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let mut second = QuorumCheckpoint {
            checkpoint: first.checkpoint.clone(),
            signatures: Vec::new(),
        };
        second.checkpoint.generation += 1;
        second.checkpoint.parent = Some(first_hash);
        for key in &signing_keys {
            second.add_signature(key).unwrap();
        }
        second.verify().unwrap();
        let second_hash = second.hash().unwrap();
        node.control
            .commit_checkpoint(
                &guild_id,
                second.checkpoint.generation,
                Some(&first_hash),
                &second_hash,
                &canonical_bytes(&second.checkpoint).unwrap(),
                &canonical_bytes(&second).unwrap(),
                false,
            )
            .unwrap();
        node.reconcile_garbage_collection().unwrap();
        assert!(
            node.control
                .get_record("gc-variable-sector", &candidate_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            node.variable_information_for_guild(&guild_id, &sector_id, 0)
                .unwrap()
                .bytes,
            shards[0]
        );

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let event = GuildEvent {
            format_version: 2,
            guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: transcript.value.manifest.value.group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&transcript).unwrap()).as_bytes(),
            },
        };
        let mut signatures = signing_keys
            .iter()
            .map(|key| sign_guild_event(&event, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_coding_group_event(QuorumGuildEvent { event, signatures }, transcript.clone())
            .unwrap();
        assert!(
            node.control
                .get_record("coding-pending-activation", &plan.value.attempt_id)
                .unwrap()
                .is_none()
        );
        drop(node);

        let node = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            node.variable_shard_for_guild(&guild_id, &transcript.value.manifest.value.group.id, 0,)
                .unwrap(),
            shards[0]
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
            sector_commitments: None,
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
    fn guild_signatures_accumulate_across_reopen_without_mixing_proposals() {
        let temp = tempfile::tempdir().unwrap();
        let (local_seed, certificate, peers) = recovery_guild_fixture();
        let mut signers = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 120; 32])))
            .collect::<Vec<_>>();
        signers.sort_by_key(KeyMaterial::node_id);
        let mut node = Node::open(temp.path(), local_seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let event = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: certificate.genesis.coordinator,
                failure_domain: "signature-retry-domain".to_owned(),
            },
        };
        let local = node.sign_guild_event_proposal(&event).unwrap();
        let remote = signers
            .iter()
            .filter(|keys| keys.node_id() != local.signer)
            .collect::<Vec<_>>();
        assert_eq!(
            node.collect_guild_event_signature(&event, local.clone())
                .unwrap()
                .len(),
            1
        );
        let second = sign_guild_event(&event, remote[0]).unwrap();
        assert_eq!(
            node.collect_guild_event_signature(&event, second.clone())
                .unwrap()
                .len(),
            2
        );
        let mut invalid = sign_guild_event(&event, remote[1]).unwrap();
        invalid.signature[0] ^= 1;
        assert!(node.collect_guild_event_signature(&event, invalid).is_err());
        let conflicting = GuildEvent {
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: certificate.genesis.coordinator,
                failure_domain: "another-domain".to_owned(),
            },
            ..event.clone()
        };
        assert!(
            node.collect_guild_event_signature(
                &conflicting,
                sign_guild_event(&conflicting, remote[1]).unwrap()
            )
            .is_err()
        );
        drop(node);

        let mut reopened = Node::open(temp.path(), local_seed).unwrap();
        assert_eq!(
            reopened
                .collect_guild_event_signature(&event, local)
                .unwrap()
                .len(),
            2
        );
        let mut collected = Vec::new();
        for keys in remote.iter().skip(1) {
            collected = reopened
                .collect_guild_event_signature(&event, sign_guild_event(&event, keys).unwrap())
                .unwrap();
        }
        assert_eq!(collected.len(), 5);
        state
            .verify_event(&QuorumGuildEvent {
                event: event.clone(),
                signatures: collected.clone(),
            })
            .unwrap();
        reopened
            .install_guild_event(QuorumGuildEvent {
                event: event.clone(),
                signatures: collected,
            })
            .unwrap();
        assert!(
            reopened
                .control
                .get_record(
                    "guild-event-partial-signatures",
                    &pending_guild_event_signatures_id(&event)
                )
                .unwrap()
                .is_none()
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
        assert_eq!(
            node.locked_guild_event_proposal(add.sequence).unwrap(),
            Some(add.clone())
        );
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
    fn backup_claim_waits_for_every_current_recovery_epoch() {
        let temp = tempfile::tempdir().unwrap();
        let (_, certificate, peers) = recovery_guild_fixture();
        let mut signer_seeds = (0_u8..5)
            .map(|index| Seed::from_bytes([index + 120; 32]))
            .collect::<Vec<_>>();
        signer_seeds.sort_by_key(|seed| KeyMaterial::from_seed(seed).node_id());
        let signer_keys = signer_seeds
            .iter()
            .map(KeyMaterial::from_seed)
            .collect::<Vec<_>>();
        let coordinator_seed = signer_seeds
            .iter()
            .find(|seed| KeyMaterial::from_seed(seed).node_id() == certificate.genesis.coordinator)
            .unwrap()
            .clone();
        let mut node = Node::open(temp.path(), coordinator_seed).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        let job = BackupJob {
            format_version: 1,
            descriptor: BackupDescriptor {
                format_version: 1,
                guild_id: certificate.genesis.guild_id,
                owner: signer_keys[1].node_id(),
                protected_root_id: Uuid::from_bytes([210; 16]),
                revision_id: Uuid::from_bytes([211; 16]),
                total_pages: 1,
                object_hash: [212; 32],
            },
            state: BackupJobState::Pending,
            checkpoint_hash: None,
            error: None,
        };
        node.put_backup_job(&job).unwrap();
        assert!(node.claim_backup_job().unwrap().is_none());

        for subject in &signer_keys {
            let state = node.dynamic_guild_state().unwrap().unwrap();
            let (envelope, _) =
                mb_core::create_recovery_key_envelope(subject, certificate.genesis.guild_id, 1)
                    .unwrap();
            let event = GuildEvent {
                format_version: 1,
                guild_id: certificate.genesis.guild_id,
                sequence: state.event_sequence + 1,
                parent: state.event_head,
                kind: mb_core::GuildEventKind::RotateRecoveryKey { envelope },
            };
            let signatures = signer_keys
                .iter()
                .map(|keys| sign_guild_event(&event, keys).unwrap())
                .collect();
            node.install_guild_event(QuorumGuildEvent { event, signatures })
                .unwrap();
        }

        let state = node.dynamic_guild_state().unwrap().unwrap();
        let relabel = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RelabelMember {
                node_id: certificate.genesis.coordinator,
                failure_domain: "coordinator-after-recovery-keys".to_owned(),
            },
        };
        node.sign_guild_event_proposal(&relabel).unwrap();
        assert!(node.claim_backup_job().unwrap().is_none());
        let signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&relabel, keys).unwrap())
            .collect();
        node.install_guild_event(QuorumGuildEvent {
            event: relabel,
            signatures,
        })
        .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[213; 32]);
        let rotate_writer = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: job.descriptor.owner,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            },
        };
        node.sign_guild_event_proposal(&rotate_writer).unwrap();
        let claimed = node.claim_backup_job().unwrap().unwrap();
        assert_eq!(claimed.descriptor, job.descriptor);
        assert_eq!(claimed.state, BackupJobState::Running);
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
            sector_commitments: None,
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

        let mut reopened = Node::open(temp.path(), added_seed.clone()).unwrap();
        assert_eq!(reopened.dynamic_guild_state().unwrap().unwrap(), state);
        assert_eq!(
            reopened
                .guild_event_tail(0, certificate.hash().unwrap())
                .unwrap()
                .events,
            vec![add, rotate_writer]
        );
        let remove = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RemoveMember {
                node_id: added_member.node_id,
            },
        };
        let mut signatures = signer_keys
            .iter()
            .map(|keys| sign_guild_event(&remove, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let remove = QuorumGuildEvent {
            event: remove,
            signatures,
        };
        reopened.install_guild_event(remove.clone()).unwrap();
        assert!(
            reopened
                .coding_holder_cleanup_endpoints(state.guild_id, added_member.node_id)
                .unwrap()
                .is_empty()
        );
        let endpoint = format!(
            "/ip4/127.0.0.1/udp/44001/quic-v1/p2p/{}",
            added_member.node_id.libp2p_peer_id().unwrap()
        );
        let signed = reopened
            .build_removed_holder_endpoint_publication(
                vec![endpoint.clone()],
                unix_seconds() + 600,
                1,
            )
            .unwrap()
            .unwrap();
        signed.verify(b"mutualbackup/endpoint-record/v1").unwrap();
        assert_eq!(signed.signer, added_member.node_id);
        assert_eq!(signed.value.endpoints, vec![endpoint]);
        drop(reopened);
        let mut reopened = Node::open(temp.path(), added_seed).unwrap();
        assert_eq!(
            reopened
                .build_removed_holder_endpoint_publication(
                    signed.value.endpoints.clone(),
                    unix_seconds() + 300,
                    signed.value.sequence,
                )
                .unwrap(),
            Some(signed)
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
        let retry = node.claim_coding_retry(None).unwrap().unwrap();
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
        let mut other = failed.value.clone();
        other.attempt_id = [1; 16];
        let other = node.sign_coding_attempt_plan(other).unwrap();
        let other_failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: other,
                error_hash: [2; 32],
            },
            &keys[remote[0]],
        )
        .unwrap();
        node.accept_coding_failure(other_failure.signer, other_failure)
            .unwrap();
        node.defer_coding_retry([1; 16], "no fresh reachable coordinators")
            .unwrap();
        assert_eq!(
            node.claim_coding_retry(None)
                .unwrap()
                .unwrap()
                .failure
                .value
                .plan
                .value
                .attempt_id,
            [1; 16]
        );
        assert_eq!(
            node.claim_coding_retry(Some([1; 16]))
                .unwrap()
                .unwrap()
                .failure
                .value
                .plan
                .value
                .attempt_id,
            [212; 16]
        );
        assert_eq!(
            node.claim_coding_retry(Some([212; 16]))
                .unwrap()
                .unwrap()
                .failure
                .value
                .plan
                .value
                .attempt_id,
            [1; 16]
        );
        node.complete_coding_retry([1; 16]).unwrap();
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
        assert!(node.claim_coding_retry(None).unwrap().is_none());
        assert!(!node.coding_checkpoint_has_pending([213; 32]).unwrap());
        assert_eq!(node.enqueue_coding_launch(failed.clone()).unwrap(), failed);
        assert!(node.claim_coding_launch().unwrap().is_none());
        let mut stale = failed.value.clone();
        stale.attempt_id = [216; 16];
        let stale = node.sign_coding_attempt_plan(stale).unwrap();
        node.enqueue_coding_launch(stale.clone()).unwrap();

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
        assert_eq!(node.claim_coding_launch().unwrap().unwrap().plan, stale);
        node.abandon_coding_launch([216; 16]).unwrap();
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
            sector_commitments: None,
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

    pub(crate) fn test_coding_transcript(
        plan: SignedRecord<CodingAttemptPlan>,
        shards: &[Vec<u8>],
        keys: &[KeyMaterial],
    ) -> SignedRecord<CodingVerificationTranscript> {
        let key = |id| keys.iter().find(|key| key.node_id() == id).unwrap();
        let value = &plan.value;
        let attempt_id = value.attempt_id;
        let plan_hash = value.hash().unwrap();
        let verifier = value.verification_coordinator;
        let (manifest, _) = mb_core::encode_coding_attempt(
            &plan,
            shards[..usize::from(value.geometry.profile.data_shards)]
                .iter()
                .zip(&value.geometry.information)
                .map(|(bytes, role)| (!role.sector.virtual_zero).then(|| bytes.clone()))
                .collect(),
            key(value.coding_coordinator),
        )
        .unwrap();
        let receipts = manifest
            .value
            .group
            .roles
            .iter()
            .enumerate()
            .filter_map(|(index, role)| {
                let ShardRoleV2::Parity(parity) = role else {
                    return None;
                };
                Some(
                    SignedRecord::sign(
                        STAGED_STORAGE_RECEIPT_DOMAIN,
                        StagedStorageReceipt {
                            format_version: 1,
                            attempt_id,
                            plan_hash,
                            guild_id: manifest.value.group.guild_id,
                            group_id: manifest.value.group.id,
                            shard_index: index as u16,
                            holder: parity.holder,
                            commitment: parity.commitment.clone(),
                        },
                        key(parity.holder),
                    )
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        let nonce = [42; 32];
        let challenge_commitment = SignedRecord::sign(
            CODING_CHALLENGE_COMMITMENT_DOMAIN,
            CodingChallengeCommitment {
                format_version: 1,
                attempt_id,
                plan_hash,
                commitment: mb_core::coding_challenge_commitment(plan_hash, nonce),
            },
            key(verifier),
        )
        .unwrap();
        let evidence_hash = mb_core::coding_evidence_hash(&manifest, &receipts).unwrap();
        let challenge_reveal = SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            CodingChallengeReveal {
                format_version: 1,
                attempt_id,
                plan_hash,
                nonce,
                evidence_hash,
            },
            key(verifier),
        )
        .unwrap();
        let challenge = mb_core::coding_challenge(plan_hash, nonce, evidence_hash);
        let openings = manifest
            .value
            .group
            .roles
            .iter()
            .enumerate()
            .map(|(index, role)| {
                let (holder, commitment) = match role {
                    ShardRoleV2::Information(info) => (info.owner, &info.sector.commitment),
                    ShardRoleV2::Parity(parity) => (parity.holder, &parity.commitment),
                };
                let leaf = challenged_leaf(&challenge, commitment).unwrap();
                SignedRecord::sign(
                    CODING_SHARD_OPENING_DOMAIN,
                    CodingShardOpening {
                        format_version: 1,
                        attempt_id,
                        plan_hash,
                        verifier,
                        challenge,
                        shard_index: index as u16,
                        commitment: commitment.clone(),
                        proof: merkle_open_range(&shards[index], leaf, 1).unwrap(),
                    },
                    key(holder),
                )
                .unwrap()
            })
            .collect();
        let transcript = SignedRecord::sign(
            mb_core::CODING_TRANSCRIPT_DOMAIN,
            CodingVerificationTranscript {
                format_version: 1,
                verified_at_unix_seconds: unix_seconds().min(plan.value.expires_at_unix_seconds),
                plan,
                manifest,
                challenge_commitment,
                staged_receipts: receipts,
                challenge_reveal,
                openings,
            },
            key(verifier),
        )
        .unwrap();
        assert_eq!(
            replay_coding_transcript(&transcript).unwrap(),
            CodingReplayFinding::Verified
        );
        transcript
    }

    pub(crate) fn test_invalid_coding_transcript(
        plan: SignedRecord<CodingAttemptPlan>,
        shards: &[Vec<u8>],
        keys: &[KeyMaterial],
    ) -> SignedRecord<CodingVerificationTranscript> {
        let mut transcript = test_coding_transcript(plan.clone(), shards, keys);
        let mut corrupt_shards = shards.to_vec();
        let parity_index = usize::from(plan.value.geometry.profile.data_shards);
        for byte in &mut corrupt_shards[parity_index] {
            *byte ^= 1;
        }
        let commitment = merkle_commit(&corrupt_shards[parity_index]).unwrap();
        let ShardRoleV2::Parity(parity) =
            &mut transcript.value.manifest.value.group.roles[parity_index]
        else {
            unreachable!();
        };
        parity.commitment = commitment.clone();
        transcript.value.manifest.value.group.id = transcript
            .value
            .manifest
            .value
            .group
            .calculate_id()
            .unwrap();
        let key = |id| keys.iter().find(|key| key.node_id() == id).unwrap();
        let coder = key(plan.value.coding_coordinator);
        let verifier = key(plan.value.verification_coordinator);
        transcript.value.manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            transcript.value.manifest.value.clone(),
            coder,
        )
        .unwrap();
        let receipt = transcript
            .value
            .staged_receipts
            .iter_mut()
            .find(|receipt| receipt.value.shard_index as usize == parity_index)
            .unwrap();
        receipt.value.group_id = transcript.value.manifest.value.group.id;
        receipt.value.commitment = commitment;
        *receipt = SignedRecord::sign(
            STAGED_STORAGE_RECEIPT_DOMAIN,
            receipt.value.clone(),
            key(receipt.signer),
        )
        .unwrap();
        let evidence_hash = mb_core::coding_evidence_hash(
            &transcript.value.manifest,
            &transcript.value.staged_receipts,
        )
        .unwrap();
        transcript.value.challenge_reveal.value.evidence_hash = evidence_hash;
        transcript.value.challenge_reveal = SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            transcript.value.challenge_reveal.value.clone(),
            verifier,
        )
        .unwrap();
        let challenge = mb_core::coding_challenge(
            plan.value.hash().unwrap(),
            transcript.value.challenge_reveal.value.nonce,
            evidence_hash,
        );
        for (index, opening) in transcript.value.openings.iter_mut().enumerate() {
            let role = &transcript.value.manifest.value.group.roles[index];
            let commitment = match role {
                ShardRoleV2::Information(info) => &info.sector.commitment,
                ShardRoleV2::Parity(parity) => &parity.commitment,
            };
            let leaf = challenged_leaf(&challenge, commitment).unwrap();
            opening.value.challenge = challenge;
            opening.value.commitment = commitment.clone();
            opening.value.proof = merkle_open_range(&corrupt_shards[index], leaf, 1).unwrap();
            *opening = SignedRecord::sign(
                CODING_SHARD_OPENING_DOMAIN,
                opening.value.clone(),
                key(opening.signer),
            )
            .unwrap();
        }
        let transcript =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, transcript.value, verifier).unwrap();
        assert_eq!(
            replay_coding_transcript(&transcript).unwrap(),
            CodingReplayFinding::InvalidCoding {
                coordinator: plan.value.coding_coordinator
            }
        );
        transcript
    }

    #[test]
    fn negative_activation_requeues_retry_and_allows_fresh_launch_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let keys = (0_u8..5)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([120 + i; 32])))
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers.clone())
            .unwrap();
        let owner = node.keys().node_id();
        let remotes = keys
            .iter()
            .filter(|key| key.node_id() != owner)
            .collect::<Vec<_>>();
        let shards =
            mb_core::encode(mb_core::CodingProfile::new(1, 1, 64), vec![vec![67; 64]]).unwrap();
        let domain = |id| {
            peers
                .iter()
                .find(|peer| peer.member.node_id == id)
                .unwrap()
                .member
                .failure_domain
                .clone()
        };
        let value = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [1; 16],
            checkpoint_hash: [72; 32],
            membership_epoch: 1,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id: node.dynamic_guild_state().unwrap().unwrap().guild_id,
                profile: mb_core::CodingProfile::new(1, 1, 64),
                information: vec![mb_core::InformationRoleV2 {
                    owner,
                    failure_domain: domain(owner),
                    sector: mb_core::RangeSectorRef {
                        id: [71; 32],
                        commitment: merkle_commit(&shards[0]).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: remotes[0].node_id(),
                    failure_domain: domain(remotes[0].node_id()),
                    row: 0,
                }],
            },
            delegator: owner,
            coding_coordinator: remotes[1].node_id(),
            verification_coordinator: remotes[2].node_id(),
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![sector_root(&shards[0])]),
        };
        let negative_for = |plan: SignedRecord<CodingAttemptPlan>| {
            let verifier = plan.value.verification_coordinator;
            let mut transcript = test_coding_transcript(plan, &shards, &keys);
            let holder = transcript.value.openings[1].signer;
            transcript.value.openings[1].value.proof.leaves[0][0] ^= 1;
            transcript.value.openings[1] = SignedRecord::sign(
                CODING_SHARD_OPENING_DOMAIN,
                transcript.value.openings[1].value.clone(),
                keys.iter().find(|key| key.node_id() == holder).unwrap(),
            )
            .unwrap();
            let transcript = SignedRecord::sign(
                mb_core::CODING_TRANSCRIPT_DOMAIN,
                transcript.value,
                keys.iter().find(|key| key.node_id() == verifier).unwrap(),
            )
            .unwrap();
            assert_eq!(
                replay_coding_transcript(&transcript).unwrap(),
                CodingReplayFinding::InvalidOpening {
                    holder,
                    shard_index: 1
                }
            );
            transcript
        };
        let initial = node.sign_coding_attempt_plan(value.clone()).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &initial.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        let failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: initial.clone(),
                error_hash: [73; 32],
            },
            keys.iter()
                .find(|key| key.node_id() == initial.value.coding_coordinator)
                .unwrap(),
        )
        .unwrap();
        node.accept_coding_failure(initial.value.coding_coordinator, failure)
            .unwrap();
        let child = node
            .prepare_coding_retry(
                initial.value.attempt_id,
                remotes[0].node_id(),
                remotes[3].node_id(),
                unix_seconds() + 600,
            )
            .unwrap();
        node.complete_coding_retry(initial.value.attempt_id)
            .unwrap();
        let negative = negative_for(child.clone());
        node.accept_coding_transcript(child.value.coding_coordinator, negative.clone())
            .unwrap();
        node.complete_coding_retry(initial.value.attempt_id)
            .unwrap();
        assert!(
            node.control
                .get_record("coding-retry-terminal", &initial.value.attempt_id)
                .unwrap()
                .is_none()
        );
        assert!(
            node.coding_launch_information_to_stage(initial.value.attempt_id)
                .unwrap()
                .is_some()
        );
        assert!(node.claim_coding_retry(None).unwrap().is_none());

        // The worker calls this only after every holder abort succeeds.
        node.complete_coding_activation(child.value.attempt_id, false)
            .unwrap();
        node.complete_claimed_coding_retry(
            initial.value.attempt_id,
            Some(child.value.attempt_id),
            false,
        )
        .unwrap();
        let parent = node
            .coding_retry_evidence_for_test(initial.value.attempt_id)
            .unwrap();
        assert!(!parent.complete);
        assert!(parent.retry_plan.is_none());
        assert!(!node.coding_retry_has_replacement(&parent).unwrap());
        assert!(
            node.coding_checkpoint_has_pending(value.checkpoint_hash)
                .unwrap()
        );
        assert!(
            node.coding_launch_information_to_stage(initial.value.attempt_id)
                .unwrap()
                .is_some()
        );
        drop(node);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        let parent = node.claim_coding_retry(None).unwrap().unwrap();
        assert_eq!(parent.failure.value.plan, initial);
        assert_eq!(node.coding_retry_previous_plan(&parent).unwrap(), child);
        assert!(
            node.coding_launch_information_to_stage(initial.value.attempt_id)
                .unwrap()
                .is_some()
        );
        let next = node
            .prepare_coding_retry(
                initial.value.attempt_id,
                owner,
                remotes[2].node_id(),
                unix_seconds() + 600,
            )
            .unwrap();
        assert_ne!(next.value.attempt_id, child.value.attempt_id);
        assert_eq!(
            node.coding_activation_jobs_for_test().unwrap()[0].transcript,
            negative
        );

        // A completed negative initial attempt must not capture its old
        // deterministic launch ID when the planner runs again.
        let mut separate = value.clone();
        separate.checkpoint_hash = [74; 32];
        separate.attempt_id = [90; 16];
        let separate = node.sign_coding_attempt_plan(separate).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &separate.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        let negative = negative_for(separate.clone());
        node.accept_coding_transcript(separate.value.coding_coordinator, negative)
            .unwrap();
        assert!(
            !node
                .complete_coding_activation_with_coordinators(
                    separate.value.attempt_id,
                    false,
                    None,
                    BTreeSet::new(),
                )
                .unwrap()
        );
        assert!(
            node.coding_launch_information_to_stage(separate.value.attempt_id)
                .unwrap()
                .is_some()
        );
        node.complete_coding_activation(separate.value.attempt_id, false)
            .unwrap();
        let renewed = node
            .coding_launch_successor_for_test(separate.value.attempt_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            node.coding_launch_information_to_stage(renewed.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );
        assert!(
            node.coding_launch_information_to_stage(separate.value.attempt_id)
                .unwrap()
                .is_none()
        );
        let fresh = node.enqueue_coding_launch(separate.clone()).unwrap();
        assert_eq!(fresh, renewed);
        assert_eq!(fresh.value.checkpoint_hash, separate.value.checkpoint_hash);
        drop(node);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.coding_launch_successor_for_test(separate.value.attempt_id)
                .unwrap(),
            Some(renewed.clone())
        );
        assert_eq!(
            node.coding_launch_information_to_stage(renewed.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );

        // A verified transcript alone is not installed coverage. If group
        // retirement races completion, the job must remain for holder cleanup.
        let mut uninstalled_value = value.clone();
        uninstalled_value.checkpoint_hash = [76; 32];
        uninstalled_value.attempt_id = [92; 16];
        let uninstalled = node.sign_coding_attempt_plan(uninstalled_value).unwrap();
        let verified = test_coding_transcript(uninstalled.clone(), &shards, &keys);
        assert_eq!(
            replay_coding_transcript(&verified).unwrap(),
            CodingReplayFinding::Verified
        );
        node.accept_coding_transcript(uninstalled.value.coding_coordinator, verified)
            .unwrap();
        assert!(
            !node
                .complete_coding_activation(uninstalled.value.attempt_id, true)
                .unwrap()
        );
        assert!(
            node.coding_activation_jobs_for_test()
                .unwrap()
                .iter()
                .any(|job| job.transcript.value.plan == uninstalled && !job.complete)
        );
        assert!(
            node.complete_coding_activation(uninstalled.value.attempt_id, false)
                .unwrap()
        );

        // A legacy expiry cannot launch across a pending negative format-3
        // activation. Once its abort is complete, both lineages use one job.
        let mut legacy_value = value.clone();
        legacy_value.format_version = 2;
        legacy_value.attempt_id = [93; 16];
        legacy_value.checkpoint_hash = [77; 32];
        legacy_value.expires_at_unix_seconds = unix_seconds() - 1;
        let legacy =
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, legacy_value, node.keys()).unwrap();
        let legacy_job = CodingLaunchJob {
            format_version: 1,
            plan: legacy.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&legacy_job).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &legacy.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        assert!(node.retire_coding_retry_plan(&legacy).unwrap());
        let mut newer_value = legacy.value.clone();
        newer_value.format_version = 3;
        newer_value.attempt_id = [94; 16];
        newer_value.expires_at_unix_seconds = unix_seconds() + 600;
        let newer = node.sign_coding_attempt_plan(newer_value).unwrap();
        let negative = negative_for(newer.clone());
        node.accept_coding_transcript(newer.value.coding_coordinator, negative)
            .unwrap();
        assert!(node.coding_launch_has_renewal(&legacy).unwrap());
        assert!(
            node.renew_coding_launch_after_cleanup(&legacy_job, None, None)
                .unwrap_err()
                .to_string()
                .contains("negative activation cleanup")
        );
        assert!(
            node.coding_launch_successor_for_test(legacy.value.attempt_id)
                .unwrap()
                .is_none()
        );
        drop(node);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        assert!(
            node.renew_coding_launch_after_cleanup(&legacy_job, None, None)
                .is_err()
        );
        node.complete_coding_activation(newer.value.attempt_id, false)
            .unwrap();
        let renewed = node
            .coding_launch_successor_for_test(newer.value.attempt_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            node.renew_coding_launch_after_cleanup(&legacy_job, None, None)
                .unwrap(),
            renewed
        );
        assert_eq!(
            node.coding_launch_information_to_stage(renewed.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );

        let mut coding_value = value;
        coding_value.checkpoint_hash = [75; 32];
        coding_value.attempt_id = [91; 16];
        let coding = node.sign_coding_attempt_plan(coding_value).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &coding.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        let mut invalid_coding = test_coding_transcript(coding.clone(), &shards, &keys);
        let mut corrupt_shards = shards.clone();
        for byte in &mut corrupt_shards[1] {
            *byte ^= 1;
        }
        let commitment = merkle_commit(&corrupt_shards[1]).unwrap();
        let ShardRoleV2::Parity(parity) = &mut invalid_coding.value.manifest.value.group.roles[1]
        else {
            unreachable!();
        };
        parity.commitment = commitment.clone();
        invalid_coding.value.manifest.value.group.id = invalid_coding
            .value
            .manifest
            .value
            .group
            .calculate_id()
            .unwrap();
        let coder = keys
            .iter()
            .find(|key| key.node_id() == coding.value.coding_coordinator)
            .unwrap();
        let verifier = keys
            .iter()
            .find(|key| key.node_id() == coding.value.verification_coordinator)
            .unwrap();
        invalid_coding.value.manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            invalid_coding.value.manifest.value.clone(),
            coder,
        )
        .unwrap();
        let receipt = &mut invalid_coding.value.staged_receipts[0];
        receipt.value.group_id = invalid_coding.value.manifest.value.group.id;
        receipt.value.commitment = commitment;
        *receipt = SignedRecord::sign(
            STAGED_STORAGE_RECEIPT_DOMAIN,
            receipt.value.clone(),
            keys.iter()
                .find(|key| key.node_id() == receipt.signer)
                .unwrap(),
        )
        .unwrap();
        let evidence_hash = mb_core::coding_evidence_hash(
            &invalid_coding.value.manifest,
            &invalid_coding.value.staged_receipts,
        )
        .unwrap();
        invalid_coding.value.challenge_reveal.value.evidence_hash = evidence_hash;
        invalid_coding.value.challenge_reveal = SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            invalid_coding.value.challenge_reveal.value.clone(),
            verifier,
        )
        .unwrap();
        let challenge = mb_core::coding_challenge(
            coding.value.hash().unwrap(),
            invalid_coding.value.challenge_reveal.value.nonce,
            evidence_hash,
        );
        for (index, opening) in invalid_coding.value.openings.iter_mut().enumerate() {
            let role = &invalid_coding.value.manifest.value.group.roles[index];
            let commitment = match role {
                ShardRoleV2::Information(info) => &info.sector.commitment,
                ShardRoleV2::Parity(parity) => &parity.commitment,
            };
            let leaf = challenged_leaf(&challenge, commitment).unwrap();
            opening.value.challenge = challenge;
            opening.value.commitment = commitment.clone();
            opening.value.proof = merkle_open_range(&corrupt_shards[index], leaf, 1).unwrap();
            *opening = SignedRecord::sign(
                CODING_SHARD_OPENING_DOMAIN,
                opening.value.clone(),
                keys.iter()
                    .find(|key| key.node_id() == opening.signer)
                    .unwrap(),
            )
            .unwrap();
        }
        invalid_coding =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, invalid_coding.value, verifier).unwrap();
        assert_eq!(
            replay_coding_transcript(&invalid_coding).unwrap(),
            CodingReplayFinding::InvalidCoding {
                coordinator: coding.value.coding_coordinator
            }
        );
        node.accept_coding_transcript(coding.value.coding_coordinator, invalid_coding)
            .unwrap();
        node.complete_coding_activation(coding.value.attempt_id, false)
            .unwrap();
        let fresh = node.enqueue_coding_launch(coding.clone()).unwrap();
        assert_ne!(fresh.value.attempt_id, coding.value.attempt_id);
        assert_eq!(fresh.value.checkpoint_hash, coding.value.checkpoint_hash);
        assert_ne!(
            fresh.value.coding_coordinator,
            coding.value.coding_coordinator
        );
        assert_ne!(
            fresh.value.coding_coordinator,
            coding.value.verification_coordinator
        );
        assert_ne!(
            fresh.value.verification_coordinator,
            coding.value.coding_coordinator
        );
        assert_ne!(
            fresh.value.verification_coordinator,
            coding.value.verification_coordinator
        );
        assert_eq!(
            node.coding_invalid_coordinators_for_source(&fresh).unwrap(),
            [coding.value.coding_coordinator].into()
        );
        let second_invalid = test_invalid_coding_transcript(fresh.clone(), &shards, &keys);
        node.accept_coding_transcript(fresh.value.coding_coordinator, second_invalid)
            .unwrap();
        let invalid = node.coding_invalid_coordinators_for_source(&fresh).unwrap();
        assert_eq!(invalid.len(), 2);
        assert!(invalid.contains(&coding.value.coding_coordinator));
        assert!(invalid.contains(&fresh.value.coding_coordinator));
        let next_coder = fresh.value.verification_coordinator;
        let next_verifier = node
            .dynamic_guild_state()
            .unwrap()
            .unwrap()
            .active_members()
            .map(|member| member.node_id)
            .find(|id| !invalid.contains(id) && *id != next_coder)
            .unwrap();
        let eligible = node
            .dynamic_guild_state()
            .unwrap()
            .unwrap()
            .active_members()
            .map(|member| member.node_id)
            .collect::<BTreeSet<_>>();
        assert!(
            !node
                .complete_coding_activation_with_coordinators(
                    fresh.value.attempt_id,
                    false,
                    Some((next_coder, coding.value.coding_coordinator)),
                    eligible.clone(),
                )
                .unwrap()
        );
        assert!(
            node.complete_coding_activation_with_coordinators(
                fresh.value.attempt_id,
                false,
                Some((next_coder, next_verifier)),
                eligible,
            )
            .unwrap()
        );
        let healthy = node
            .coding_launch_successor_for_test(fresh.value.attempt_id)
            .unwrap()
            .unwrap();
        assert!(!invalid.contains(&healthy.value.coding_coordinator));
        assert!(!invalid.contains(&healthy.value.verification_coordinator));
        assert_eq!(
            node.coding_launch_information_to_stage(healthy.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );
        let verified = test_coding_transcript(healthy.clone(), &shards, &keys);
        node.accept_coding_transcript(healthy.value.coding_coordinator, verified.clone())
            .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let event = GuildEvent {
            format_version: 2,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: verified.value.manifest.value.group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&verified).unwrap()).as_bytes(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|key| sign_guild_event(&event, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_coding_group_event(QuorumGuildEvent { event, signatures }, verified.clone())
            .unwrap();
        assert!(
            node.complete_coding_activation_with_coordinators(
                healthy.value.attempt_id,
                true,
                None,
                BTreeSet::new(),
            )
            .unwrap()
        );
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            node.coding_transcript_for_group(
                state.guild_id,
                verified.value.manifest.value.group.id,
            )
            .unwrap(),
            verified
        );
        assert_eq!(
            node.coding_launch_successor_for_test(fresh.value.attempt_id)
                .unwrap(),
            Some(healthy)
        );
    }

    fn forgotten_full_width_group_replans_after_retired_activation_cleanup(active_count: usize) {
        let temp = tempfile::tempdir().unwrap();
        let volume = temp.path().join("volume");
        std::fs::create_dir(&volume).unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let catchup_certificate = certificate.clone();
        let catchup_peers = peers.clone();
        let keys = (0_u8..5)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([120 + i; 32])))
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path().join("node"), seed.clone()).unwrap();
        node.configure_storage_volumes(std::slice::from_ref(&volume), 4 * 1024 * 1024, 0)
            .unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let sign_event = |state: &DynamicGuildState, kind| {
            let event = GuildEvent {
                format_version: if matches!(
                    kind,
                    mb_core::GuildEventKind::AddCodingGroupBound { .. }
                ) {
                    2
                } else {
                    1
                },
                guild_id: state.guild_id,
                sequence: state.event_sequence + 1,
                parent: state.event_head,
                kind,
            };
            let active = state
                .active_members()
                .map(|member| member.node_id)
                .collect::<BTreeSet<_>>();
            let mut signatures = keys
                .iter()
                .filter(|key| active.contains(&key.node_id()))
                .map(|key| sign_guild_event(&event, key).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            QuorumGuildEvent { event, signatures }
        };
        for index in (active_count..5).rev() {
            let state = node.dynamic_guild_state().unwrap().unwrap();
            let removed = state.active_members().nth(index).unwrap().node_id;
            node.install_guild_event(sign_event(
                &state,
                mb_core::GuildEventKind::RemoveMember { node_id: removed },
            ))
            .unwrap();
        }
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let members = state.active_members().cloned().collect::<Vec<_>>();
        assert_eq!(members.len(), active_count);
        assert_eq!(members[2].node_id, node.keys().node_id());
        let information_indices = if active_count == 3 {
            vec![0, 1]
        } else {
            vec![0, 1, 3]
        };
        let parity_indices = if active_count == 3 {
            vec![2]
        } else {
            vec![2, 4]
        };
        let profile = mb_core::CodingProfile::new(
            information_indices.len() as u16,
            parity_indices.len() as u16,
            64,
        );
        let data = (0..information_indices.len())
            .map(|index| vec![21 + index as u8; 64])
            .collect::<Vec<_>>();
        let shards = mb_core::encode(profile, data.clone()).unwrap();
        let information = information_indices
            .iter()
            .copied()
            .enumerate()
            .map(|(index, member)| mb_core::InformationRoleV2 {
                owner: members[member].node_id,
                failure_domain: members[member].failure_domain.clone(),
                sector: mb_core::RangeSectorRef {
                    id: [index as u8 + 1; 32],
                    commitment: merkle_commit(&data[index]).unwrap(),
                    logical_len: 64,
                    virtual_zero: false,
                },
            })
            .collect::<Vec<_>>();
        let parity = parity_indices
            .iter()
            .copied()
            .enumerate()
            .map(|(row, member)| mb_core::ParityPlacementV2 {
                holder: members[member].node_id,
                failure_domain: members[member].failure_domain.clone(),
                row: row as u16,
            })
            .collect::<Vec<_>>();
        let plan = node
            .sign_coding_attempt_plan(CodingAttemptPlan {
                format_version: 3,
                attempt_id: [211; 16],
                checkpoint_hash: [212; 32],
                membership_epoch: state.membership_epoch,
                geometry: mb_core::CodingPlanGeometry {
                    format_version: 1,
                    guild_id: state.guild_id,
                    profile,
                    information,
                    parity,
                },
                delegator: node.keys().node_id(),
                coding_coordinator: members[0].node_id,
                verification_coordinator: members[1].node_id,
                expires_at_unix_seconds: unix_seconds() + 600,
                information_roots: Some(data.iter().map(|bytes| sector_root(bytes)).collect()),
            })
            .unwrap();
        let transcript = test_coding_transcript(plan.clone(), &shards, &keys);
        let group = transcript.value.manifest.value.group.clone();
        let local_parity_index = information_indices.len();
        let local_parity = VariableParityObject {
            format_version: 2,
            guild_id: state.guild_id,
            group_id: group.id,
            shard_index: local_parity_index as u16,
            commitment: merkle_commit(&shards[local_parity_index]).unwrap(),
            bytes: shards[local_parity_index].clone(),
        };
        node.stage_coding_parity(&plan, &transcript.value.manifest, &local_parity)
            .unwrap();
        node.activate_coding_attempt(&transcript).unwrap();
        let add = sign_event(
            &state,
            mb_core::GuildEventKind::AddCodingGroup {
                group: group.clone(),
            },
        );
        let statement = LegacyCodingAddStatement::for_event(
            &add,
            *blake3::hash(&canonical_bytes(&transcript).unwrap()).as_bytes(),
        )
        .unwrap();
        let mut signatures = keys
            .iter()
            .filter(|key| {
                state
                    .active_members()
                    .any(|member| member.node_id == key.node_id())
            })
            .map(|key| sign_legacy_coding_add_binding(&statement, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let binding = QuorumLegacyCodingAddBinding {
            statement,
            signatures,
        };
        assert!(
            node.install_coding_group_event(add.clone(), transcript.clone())
                .is_err()
        );
        node.install_legacy_coding_group_event(add.clone(), transcript.clone(), binding.clone())
            .unwrap();
        let old_add_hash = add.event.hash().unwrap();
        let transcript_hash = binding.statement.transcript_hash;
        assert_eq!(
            node.attest_legacy_coding_add(
                state.guild_id,
                add.event.sequence,
                old_add_hash,
                transcript_hash,
            )
            .unwrap(),
            sign_legacy_coding_add_binding(&binding.statement, node.keys()).unwrap(),
        );
        assert!(
            node.attest_legacy_coding_add(
                state.guild_id,
                add.event.sequence,
                old_add_hash,
                [197; 32],
            )
            .is_err()
        );
        assert!(
            node.control
                .delete_record("coding-event-transcript", &old_add_hash)
                .unwrap(),
            "simulate an upgraded store with a retained pre-binding Add"
        );
        assert!(
            node.control
                .delete_record("coding-legacy-add-binding", &old_add_hash)
                .unwrap()
        );
        let (pending, before, pending_hash) =
            node.next_unbound_legacy_coding_add().unwrap().unwrap();
        assert_eq!(pending, add);
        assert_eq!(before, state);
        assert_eq!(pending_hash, transcript_hash);
        let mut wrong_binding = binding.clone();
        wrong_binding.statement.transcript_hash = [198; 32];
        assert!(
            node.persist_legacy_coding_add_binding(&add, &wrong_binding)
                .is_err()
        );
        node.persist_legacy_coding_add_binding(&add, &binding)
            .unwrap();
        assert_eq!(
            legacy_coding_add_binding_from_store(
                &node.control,
                state.guild_id,
                add.event.sequence,
                old_add_hash,
            )
            .unwrap(),
            Some(binding.clone()),
        );
        assert!(node.next_unbound_legacy_coding_add().unwrap().is_none());
        assert!(
            node.control
                .delete_record("coding-legacy-add-binding", &old_add_hash)
                .unwrap()
        );
        assert!(
            node.control
                .delete_record("coding-legacy-add-signature-lock", &old_add_hash)
                .unwrap()
        );
        // The delegator can have retired the group while this holder has only
        // installed Add. Its early abort must still leave a durable cleanup
        // owner for the later Forget.
        assert!(node.discard_coding_attempt(&plan.value.attempt_id).unwrap());
        assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 1);
        node.accept_coding_transcript(plan.value.coding_coordinator, transcript.clone())
            .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let retire = sign_event(
            &state,
            mb_core::GuildEventKind::RetireCodingGroup {
                group_id: group.id,
                retain_through_event: state.event_sequence + 1,
            },
        );
        node.install_guild_event(retire.clone()).unwrap();
        node.mark_retired_coding_activation_for_replan(&transcript)
            .unwrap();
        assert!(node.discard_coding_attempt(&plan.value.attempt_id).unwrap());
        assert_eq!(
            node.variable_parity_for_guild(&state.guild_id, &group.id, local_parity_index as u16)
                .unwrap(),
            local_parity
        );
        let fresh = if active_count == 3 {
            Some((members[1].node_id, members[2].node_id))
        } else {
            Some((members[2].node_id, members[3].node_id))
        };
        assert!(
            !node
                .complete_coding_activation_with_coordinators(
                    plan.value.attempt_id,
                    false,
                    fresh,
                    BTreeSet::new(),
                )
                .unwrap()
        );
        drop(node);
        let mut node = Node::open(temp.path().join("node"), seed.clone()).unwrap();
        assert!(node.coding_activation_needs_replan(&transcript).unwrap());
        assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 1);
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let forget = sign_event(
            &state,
            mb_core::GuildEventKind::ForgetCodingGroup { group_id: group.id },
        );
        assert_eq!(
            node.coding_transcript_for_event(
                state.guild_id,
                group.id,
                add.event.sequence,
                old_add_hash,
            )
            .unwrap(),
            transcript
        );
        node.install_guild_event(forget.clone()).unwrap();
        assert_eq!(
            node.coding_transcript_for_event(
                state.guild_id,
                group.id,
                add.event.sequence,
                old_add_hash,
            )
            .unwrap(),
            transcript
        );
        drop(node);
        let mut node = Node::open(temp.path().join("node"), seed.clone()).unwrap();
        assert_eq!(
            node.coding_transcript_for_event(
                state.guild_id,
                group.id,
                add.event.sequence,
                old_add_hash,
            )
            .unwrap(),
            transcript
        );
        assert!(
            node.attest_legacy_coding_add(
                state.guild_id,
                add.event.sequence,
                old_add_hash,
                transcript_hash,
            )
            .is_ok()
        );
        assert!(node.discard_coding_attempt(&plan.value.attempt_id).unwrap());
        assert_eq!(
            node.coding_holder_cleanup_count_for_test().unwrap(),
            usize::from(active_count == 5),
            "local cleanup must finish while any remote parity cleanup stays durable"
        );
        if active_count == 5 {
            let (_, remote) = node
                .claim_coding_holder_cleanup_after(None)
                .unwrap()
                .unwrap();
            assert_ne!(remote.holder, node.keys().node_id());
        }
        assert!(
            node.variable_parity_for_guild(&state.guild_id, &group.id, local_parity_index as u16)
                .is_err()
        );
        assert!(
            node.complete_coding_activation_with_coordinators(
                plan.value.attempt_id,
                false,
                fresh,
                members.iter().map(|member| member.node_id).collect(),
            )
            .unwrap()
        );
        let successor = node
            .coding_launch_successor_for_test(plan.value.attempt_id)
            .unwrap()
            .unwrap();
        assert_eq!(successor.value.geometry, plan.value.geometry);
        let next = test_coding_transcript(successor.clone(), &shards, &keys);
        assert_eq!(next.value.manifest.value.group.id, group.id);
        node.stage_coding_parity(&successor, &next.value.manifest, &local_parity)
            .unwrap();
        node.activate_coding_attempt(&next).unwrap();
        // An old delegator may send its delayed abort after the successor
        // activates the same group ID but before its Add event reaches us.
        assert!(node.discard_coding_attempt(&plan.value.attempt_id).unwrap());
        assert_eq!(
            node.variable_parity_for_guild(&state.guild_id, &group.id, local_parity_index as u16)
                .unwrap(),
            local_parity
        );
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let successor_add = sign_event(
            &state,
            mb_core::GuildEventKind::AddCodingGroupBound {
                group: group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&next).unwrap()).as_bytes(),
            },
        );
        node.install_coding_group_event(successor_add.clone(), next.clone())
            .unwrap();
        assert_eq!(
            node.coding_transcript_for_group(state.guild_id, group.id)
                .unwrap(),
            next
        );
        if active_count == 5 {
            let old_hash = add.event.hash().unwrap();
            let new_hash = successor_add.event.hash().unwrap();
            assert_eq!(
                node.coding_transcript_for_event(
                    state.guild_id,
                    group.id,
                    add.event.sequence,
                    old_hash,
                )
                .unwrap(),
                transcript
            );
            assert_eq!(
                node.reader_config()
                    .open()
                    .unwrap()
                    .coding_transcript_for_event(
                        state.guild_id,
                        group.id,
                        successor_add.event.sequence,
                        new_hash,
                    )
                    .unwrap(),
                next
            );
            assert!(
                node.install_legacy_coding_group_event(add.clone(), next.clone(), binding.clone())
                    .is_err()
            );

            let mut lagging = Node::open(temp.path().join("lagging"), seed).unwrap();
            lagging
                .adopt_recovered_guild(catchup_certificate, catchup_peers)
                .unwrap();
            let old_evidence = node
                .coding_transcript_for_event(state.guild_id, group.id, add.event.sequence, old_hash)
                .unwrap();
            assert!(
                lagging
                    .install_legacy_coding_group_event(add.clone(), next.clone(), binding.clone())
                    .is_err()
            );
            lagging
                .install_legacy_coding_group_event(add, old_evidence, binding)
                .unwrap();
            lagging.install_guild_event(retire).unwrap();
            lagging.install_guild_event(forget).unwrap();
            let obligations = lagging.control.records("coding-holder-cleanup").unwrap();
            assert!(!obligations.is_empty());
            for (_, bytes) in obligations {
                let obligation: CodingHolderCleanupObligation = decode_canonical(&bytes).unwrap();
                assert_eq!(obligation.plan.value.attempt_id, plan.value.attempt_id);
                assert_ne!(obligation.plan.value.attempt_id, successor.value.attempt_id);
            }
        }
    }

    #[test]
    fn forgotten_three_domain_group_replans_after_retired_activation_cleanup() {
        forgotten_full_width_group_replans_after_retired_activation_cleanup(3);
    }

    #[test]
    fn forgotten_five_domain_group_replans_after_retired_activation_cleanup() {
        forgotten_full_width_group_replans_after_retired_activation_cleanup(5);
    }

    #[test]
    fn failed_retry_moves_unusable_parity_and_input_to_new_launch_after_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let keys = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([120 + index; 32])))
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let members = state.active_members().cloned().collect::<Vec<_>>();
        let bytes = vec![17; 64];
        let plan = node
            .sign_coding_attempt_plan(CodingAttemptPlan {
                format_version: 3,
                attempt_id: [171; 16],
                checkpoint_hash: [172; 32],
                membership_epoch: state.membership_epoch,
                geometry: mb_core::CodingPlanGeometry {
                    format_version: 1,
                    guild_id: state.guild_id,
                    profile: mb_core::CodingProfile::new(1, 1, 64),
                    information: vec![mb_core::InformationRoleV2 {
                        owner: members[2].node_id,
                        failure_domain: members[2].failure_domain.clone(),
                        sector: mb_core::RangeSectorRef {
                            id: [173; 32],
                            commitment: merkle_commit(&bytes).unwrap(),
                            logical_len: 64,
                            virtual_zero: false,
                        },
                    }],
                    parity: vec![mb_core::ParityPlacementV2 {
                        holder: members[0].node_id,
                        failure_domain: members[0].failure_domain.clone(),
                        row: 0,
                    }],
                },
                delegator: members[2].node_id,
                coding_coordinator: members[3].node_id,
                verification_coordinator: members[4].node_id,
                expires_at_unix_seconds: unix_seconds() + 600,
                information_roots: Some(vec![sector_root(&bytes)]),
            })
            .unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &plan.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        let failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: plan.clone(),
                error_hash: [174; 32],
            },
            keys.iter()
                .find(|key| key.node_id() == plan.value.coding_coordinator)
                .unwrap(),
        )
        .unwrap();
        node.accept_coding_failure(plan.value.coding_coordinator, failure)
            .unwrap();
        assert!(node.retire_coding_retry_plan(&plan).unwrap());
        assert!(node.discard_coding_attempt(&plan.value.attempt_id).unwrap());
        assert!(
            node.replan_coding_retry_after_cleanup(
                plan.value.attempt_id,
                Some((members[4].node_id, members[1].node_id)),
                [members[1].node_id].into(),
            )
            .unwrap()
        );
        let successor = node
            .coding_launch_successor_for_test(plan.value.attempt_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            successor.value.geometry.parity[0].holder,
            members[1].node_id
        );
        assert_eq!(successor.value.coding_coordinator, members[4].node_id);
        assert_eq!(successor.value.verification_coordinator, members[1].node_id);
        assert_eq!(
            node.coding_launch_information_to_stage(successor.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );
        assert!(node.claim_coding_retry(None).unwrap().is_none());
        let mut expired_value = plan.value.clone();
        expired_value.attempt_id = [175; 16];
        expired_value.checkpoint_hash = [176; 32];
        expired_value.expires_at_unix_seconds = unix_seconds() - 1;
        let expired =
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, expired_value, node.keys()).unwrap();
        let expired_job = CodingLaunchJob {
            format_version: 1,
            plan: expired.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&expired_job).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &expired.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        assert!(node.retire_coding_retry_plan(&expired).unwrap());
        let rotated = node
            .renew_coding_launch_after_cleanup(
                &expired_job,
                Some((members[4].node_id, members[1].node_id)),
                Some([members[1].node_id].into()),
            )
            .unwrap();
        assert_eq!(rotated.value.geometry.parity[0].holder, members[1].node_id);
        assert_eq!(
            node.coding_launch_information_to_stage(rotated.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );
        node.put_coding_launch_job(&expired_job).unwrap();
        drop(node);
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.renew_coding_launch_after_cleanup(&expired_job, None, None)
                .unwrap(),
            rotated
        );
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            node.coding_launch_successor_for_test(plan.value.attempt_id)
                .unwrap(),
            Some(successor.clone())
        );
        assert_eq!(
            node.coding_launch_information_to_stage(successor.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );
        assert!(node.claim_coding_retry(None).unwrap().is_none());
    }

    #[test]
    fn retry_lane_coalescing_follows_live_successors_and_preserves_history() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let keys = (0_u8..5)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([120 + i; 32])))
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers.clone())
            .unwrap();
        let owner = node.keys().node_id();
        let remotes = keys
            .iter()
            .filter(|key| key.node_id() != owner)
            .collect::<Vec<_>>();
        let shards =
            mb_core::encode(mb_core::CodingProfile::new(1, 1, 64), vec![vec![67; 64]]).unwrap();
        let domain = |id| {
            peers
                .iter()
                .find(|peer| peer.member.node_id == id)
                .unwrap()
                .member
                .failure_domain
                .clone()
        };
        let value = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [1; 16],
            checkpoint_hash: [72; 32],
            membership_epoch: 1,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id: node.dynamic_guild_state().unwrap().unwrap().guild_id,
                profile: mb_core::CodingProfile::new(1, 1, 64),
                information: vec![mb_core::InformationRoleV2 {
                    owner,
                    failure_domain: domain(owner),
                    sector: mb_core::RangeSectorRef {
                        id: [71; 32],
                        commitment: merkle_commit(&shards[0]).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: remotes[0].node_id(),
                    failure_domain: domain(remotes[0].node_id()),
                    row: 0,
                }],
            },
            delegator: owner,
            coding_coordinator: remotes[1].node_id(),
            verification_coordinator: remotes[2].node_id(),
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![sector_root(&shards[0])]),
        };
        let sign = |id, version, deadline| {
            let mut plan = value.clone();
            plan.attempt_id = [id; 16];
            plan.format_version = version;
            plan.expires_at_unix_seconds = deadline;
            SignedRecord::sign(
                CODING_ATTEMPT_PLAN_DOMAIN,
                plan,
                keys.iter().find(|key| key.node_id() == owner).unwrap(),
            )
            .unwrap()
        };
        let failure = |plan: SignedRecord<CodingAttemptPlan>| {
            SignedRecord::sign(
                CODING_FAILURE_REPORT_DOMAIN,
                CodingFailureReport {
                    format_version: 1,
                    failed_at_unix_seconds: unix_seconds(),
                    plan,
                    error_hash: [73; 32],
                },
                remotes[1],
            )
            .unwrap()
        };
        let a = sign(1, 2, value.expires_at_unix_seconds);
        let b = sign(2, 3, value.expires_at_unix_seconds);
        let expired = sign(3, 3, unix_seconds() - 1);
        let live = sign(254, 3, value.expires_at_unix_seconds);
        let reused_roles = sign(200, 3, value.expires_at_unix_seconds);
        let mut initial = reused_roles.value.clone();
        initial.coding_coordinator = owner;
        initial.verification_coordinator = remotes[3].node_id();
        let initial = node.sign_coding_attempt_plan(initial).unwrap();
        let parent = CodingRetryJob {
            format_version: 1,
            failure: failure(a),
            retry_plan: Some(b.clone()),
            complete: true,
            error: None,
        };
        node.install_historical_coding_retry_for_test(&parent)
            .unwrap();
        let mut child = CodingRetryJob {
            format_version: 1,
            failure: failure(b),
            retry_plan: Some(expired.clone()),
            complete: false,
            error: Some("expired child after reopen".to_owned()),
        };
        node.install_historical_coding_retry_for_test(&child)
            .unwrap();
        assert!(node.enqueue_coding_launch(reused_roles.clone()).is_err());
        assert_eq!(
            node.enqueue_coding_launch(initial.clone()).unwrap(),
            initial
        );
        node.abandon_coding_launch(initial.value.attempt_id)
            .unwrap();
        assert!(node.retire_coding_retry_plan(&expired).unwrap());
        child.retry_plan = Some(live.clone());
        node.put_coding_retry_job(&child).unwrap();
        for _ in 0..2 {
            drop(node);
            node = Node::open(temp.path(), seed.clone()).unwrap();
            assert_eq!(node.enqueue_coding_launch(initial.clone()).unwrap(), live);
            assert!(node.claim_coding_launch().unwrap().is_none());
            assert_eq!(
                node.coding_retry_evidence_for_test([1; 16]).unwrap(),
                parent
            );
            assert_eq!(node.coding_retry_evidence_for_test([2; 16]).unwrap(), child);
        }
        // The retry child owns this lane even when an expired launch is
        // renewed after the child was acknowledged and the delegator reopened.
        let retry_first = sign(252, 3, unix_seconds() - 1);
        let retry_first_job = CodingLaunchJob {
            format_version: 1,
            plan: retry_first.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&retry_first_job).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &retry_first.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        assert!(node.retire_coding_retry_plan(&retry_first).unwrap());
        assert_eq!(
            node.renew_coding_launch_after_cleanup(&retry_first_job, None, None)
                .unwrap(),
            live
        );
        assert!(
            node.control
                .records("coding-launch-job")
                .unwrap()
                .is_empty()
        );
        for _ in 0..2 {
            drop(node);
            node = Node::open(temp.path(), seed.clone()).unwrap();
            assert_eq!(
                node.coding_launch_successor_for_test(retry_first.value.attempt_id)
                    .unwrap(),
                Some(live.clone())
            );
            assert_eq!(
                node.coding_launch_information_to_stage(live.value.attempt_id)
                    .unwrap(),
                Some(BTreeMap::new())
            );
            assert_eq!(node.coding_retry_evidence_for_test([2; 16]).unwrap(), child);
            assert!(
                node.control
                    .records("coding-launch-job")
                    .unwrap()
                    .is_empty()
            );
        }
        node.complete_coding_retry([2; 16]).unwrap();
        node.accept_coding_failure(live.value.coding_coordinator, failure(live.clone()))
            .unwrap();
        node.defer_coding_retry(
            live.value.attempt_id,
            "fewer than two fresh reachable coordinators",
        )
        .unwrap();
        assert!(node.enqueue_coding_launch(reused_roles).is_err());
        assert_eq!(
            node.enqueue_coding_launch(initial.clone()).unwrap(),
            initial
        );
        assert_eq!(node.claim_coding_launch().unwrap().unwrap().plan, initial);
        node.abandon_coding_launch(initial.value.attempt_id)
            .unwrap();
        let verified = sign(253, 3, value.expires_at_unix_seconds);
        let transcript = test_coding_transcript(verified.clone(), &shards, &keys);
        node.accept_coding_transcript(verified.value.coding_coordinator, transcript)
            .unwrap();
        assert_eq!(
            node.enqueue_coding_launch(initial.clone()).unwrap(),
            verified
        );
        assert!(node.claim_coding_launch().unwrap().is_none());
        // A pending verified result is stronger than a fresh launch. Keep its
        // input pinned until the activation actually retains coverage.
        let activation_first = sign(248, 3, unix_seconds() - 1);
        let activation_first_job = CodingLaunchJob {
            format_version: 1,
            plan: activation_first.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&activation_first_job).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &activation_first.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        assert!(node.retire_coding_retry_plan(&activation_first).unwrap());
        assert_eq!(
            node.renew_coding_launch_after_cleanup(&activation_first_job, None, None)
                .unwrap(),
            verified
        );
        for _ in 0..2 {
            drop(node);
            node = Node::open(temp.path(), seed.clone()).unwrap();
            assert_eq!(
                node.coding_launch_successor_for_test(activation_first.value.attempt_id)
                    .unwrap(),
                Some(verified.clone())
            );
            assert_eq!(
                node.coding_launch_information_to_stage(verified.value.attempt_id)
                    .unwrap(),
                Some(BTreeMap::new())
            );
            assert!(
                node.control
                    .records("coding-launch-job")
                    .unwrap()
                    .is_empty()
            );
        }
        // Simulate a crash after the successor transaction but before parent
        // removal. Reopening and repeating renewal must reuse the signed ID.
        let mut value = initial.value.clone();
        value.checkpoint_hash = [74; 32];
        value.expires_at_unix_seconds = unix_seconds() - 1;
        let expired = SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            value,
            keys.iter().find(|key| key.node_id() == owner).unwrap(),
        )
        .unwrap();
        let job = CodingLaunchJob {
            format_version: 1,
            plan: expired.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&job).unwrap();
        assert_eq!(node.claim_coding_launch().unwrap(), Some(job.clone()));
        node.defer_coding_launch(expired.value.attempt_id, "cleanup destination offline")
            .unwrap();
        let job = node.claim_coding_launch().unwrap().unwrap();
        assert!(job.dispatched);
        assert!(job.error.is_some());
        // Replanning can run before the worker persists the retirement fence.
        // A fresh proposal under the deterministic ID must preserve the old
        // signed plan, acknowledgement, and explicit deferral after reopen.
        let mut proposed = expired.value.clone();
        proposed.expires_at_unix_seconds = unix_seconds() + 600;
        let proposed = node.sign_coding_attempt_plan(proposed).unwrap();
        assert_eq!(node.enqueue_coding_launch(proposed).unwrap(), expired);
        drop(node);
        node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(node.claim_coding_launch().unwrap(), Some(job.clone()));
        node.control
            .put_record(
                "coding-launch-information",
                &expired.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        assert!(node.retire_coding_retry_plan(&expired).unwrap());
        let late_result = test_coding_transcript(expired.clone(), &shards, &keys);
        assert!(
            node.accept_coding_transcript(expired.value.coding_coordinator, late_result)
                .is_err()
        );
        let successor = node
            .renew_coding_launch_after_cleanup(
                &job,
                Some((remotes[0].node_id(), remotes[1].node_id())),
                None,
            )
            .unwrap();
        assert_ne!(successor.value.attempt_id, expired.value.attempt_id);
        assert!(successor.value.expires_at_unix_seconds > unix_seconds());
        node.put_coding_launch_job(&job).unwrap();
        drop(node);
        node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.renew_coding_launch_after_cleanup(&job, None, None)
                .unwrap(),
            successor
        );
        assert_eq!(node.control.records("coding-launch-job").unwrap().len(), 1);
        assert_eq!(
            node.control
                .get_record("coding-retired-attempt", &expired.value.attempt_id)
                .unwrap(),
            Some(canonical_bytes(&expired).unwrap())
        );
        assert!(
            node.coding_launch_information_to_stage(expired.value.attempt_id)
                .unwrap()
                .is_none()
        );
        assert!(
            node.coding_launch_information_to_stage(successor.value.attempt_id)
                .unwrap()
                .is_some()
        );
        // A deferred lower-ID launch gets one turn, followed by another lane.
        let mut other = initial.value.clone();
        other.attempt_id = [255; 16];
        other.checkpoint_hash = [75; 32];
        let other = node.sign_coding_attempt_plan(other).unwrap();
        node.enqueue_coding_launch(other.clone()).unwrap();
        node.defer_coding_launch(successor.value.attempt_id, "input disk offline")
            .unwrap();
        assert_eq!(
            node.claim_coding_launch_after(Some(successor.value.attempt_id))
                .unwrap()
                .unwrap()
                .plan,
            other
        );
        assert_eq!(
            node.claim_coding_launch_after(Some(other.value.attempt_id))
                .unwrap()
                .unwrap()
                .plan,
            successor
        );
        node.abandon_coding_launch(successor.value.attempt_id)
            .unwrap();
        let mut replacement = expired.value.clone();
        replacement.expires_at_unix_seconds = unix_seconds() + 600;
        let replacement = node.sign_coding_attempt_plan(replacement).unwrap();
        let replacement = node.enqueue_coding_launch(replacement).unwrap();
        assert_ne!(replacement.value.attempt_id, expired.value.attempt_id);
        assert_eq!(
            node.retired_coding_plan_for_test(expired.value.attempt_id)
                .unwrap(),
            Some(expired)
        );

        // A signed failure can arrive after an acknowledged expired claim but
        // before the writer lock is reacquired for retirement. Its retry owns
        // all subsequent work, including delayed acknowledgement/deferral.
        for (id, retire_first) in [(250, false), (251, true)] {
            let mut plan = initial.value.clone();
            plan.coding_coordinator = remotes[1].node_id();
            plan.verification_coordinator = remotes[2].node_id();
            plan.attempt_id = [id; 16];
            plan.checkpoint_hash = [76; 32];
            plan.expires_at_unix_seconds = unix_seconds() - 1;
            let plan = SignedRecord::sign(
                CODING_ATTEMPT_PLAN_DOMAIN,
                plan,
                keys.iter().find(|key| key.node_id() == owner).unwrap(),
            )
            .unwrap();
            let claimed = CodingLaunchJob {
                format_version: 1,
                plan: plan.clone(),
                dispatched: true,
                error: None,
            };
            node.put_coding_launch_job(&claimed).unwrap();
            if retire_first {
                assert!(node.retire_coding_launch_for_cleanup(&claimed).unwrap());
            }
            let report = failure(plan.clone());
            node.accept_coding_failure(report.signer, report.clone())
                .unwrap();
            if retire_first {
                assert_eq!(
                    node.control
                        .get_record("coding-launch-job", &plan.value.attempt_id)
                        .unwrap(),
                    Some(canonical_bytes(&claimed).unwrap())
                );
                assert_eq!(
                    node.control
                        .get_record("coding-retired-failure", &plan.value.attempt_id)
                        .unwrap(),
                    Some(canonical_bytes(&report).unwrap())
                );
                assert!(
                    node.control
                        .get_record("coding-retry-job", &plan.value.attempt_id)
                        .unwrap()
                        .is_none()
                );
            } else {
                for reopen in 0..2 {
                    if reopen == 0 {
                        // A crash can leave this redundant launch beside its
                        // already durable retry owner. Reconcile it as well.
                        node.put_coding_launch_job(&claimed).unwrap();
                    }
                    assert!(!node.retire_coding_launch_for_cleanup(&claimed).unwrap());
                    node.defer_coding_launch(
                        plan.value.attempt_id,
                        "selection completed after failure",
                    )
                    .unwrap();
                    node.complete_coding_launch(plan.value.attempt_id).unwrap();
                    assert!(
                        node.control
                            .get_record("coding-launch-job", &plan.value.attempt_id)
                            .unwrap()
                            .is_none()
                    );
                    assert!(
                        node.retired_coding_plan_for_test(plan.value.attempt_id)
                            .unwrap()
                            .is_none()
                    );
                    assert_eq!(
                        node.coding_retry_evidence_for_test(plan.value.attempt_id)
                            .unwrap()
                            .failure,
                        report
                    );
                    drop(node);
                    node = Node::open(temp.path(), seed.clone()).unwrap();
                }
            }
        }
        assert!(
            node.defer_coding_launch([249; 16], "unexpected missing owner")
                .is_err()
        );
        // If the group retires before completion, the activation owns an
        // atomic input handoff to a fresh signed launch, even after reopen.
        node.complete_coding_activation(verified.value.attempt_id, false)
            .unwrap();
        let after_activation = node
            .coding_launch_successor_for_test(verified.value.attempt_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            node.coding_launch_information_to_stage(after_activation.value.attempt_id)
                .unwrap(),
            Some(BTreeMap::new())
        );
        assert!(
            node.coding_launch_information_to_stage(verified.value.attempt_id)
                .unwrap()
                .is_none()
        );
        drop(node);
        node = Node::open(temp.path(), seed.clone()).unwrap();
        assert_eq!(
            node.coding_launch_successor_for_test(verified.value.attempt_id)
                .unwrap(),
            Some(after_activation)
        );
    }

    #[test]
    fn acknowledged_retry_reclaims_expiry_and_stale_cleanup_but_preserves_accepted_evidence() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let keys = (0_u8..5)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index + 120; 32])))
            .collect::<Vec<_>>();
        let local_id = KeyMaterial::from_seed(&seed).node_id();
        let remotes = keys
            .iter()
            .filter(|key| key.node_id() != local_id)
            .collect::<Vec<_>>();
        let member = |id| {
            peers
                .iter()
                .find(|peer| peer.member.node_id == id)
                .unwrap()
                .member
                .clone()
        };
        let profile = mb_core::CodingProfile::new(1, 1, V1_SECTOR_SIZE as u32);
        let shards = mb_core::encode(profile, vec![vec![96; V1_SECTOR_SIZE]]).unwrap();
        for case in 0..6 {
            let dir = temp.path().join(format!("case-{case}"));
            let mut node = Node::open(&dir, seed.clone()).unwrap();
            node.adopt_recovered_guild(certificate.clone(), peers.clone())
                .unwrap();
            let initial = node
                .sign_coding_attempt_plan(CodingAttemptPlan {
                    format_version: 2,
                    attempt_id: [97; 16],
                    checkpoint_hash: [98; 32],
                    membership_epoch: 1,
                    geometry: mb_core::CodingPlanGeometry {
                        format_version: 1,
                        guild_id: certificate.genesis.guild_id,
                        profile,
                        information: vec![mb_core::InformationRoleV2 {
                            owner: local_id,
                            failure_domain: member(local_id).failure_domain,
                            sector: mb_core::RangeSectorRef {
                                id: [99; 32],
                                commitment: merkle_commit(&shards[0]).unwrap(),
                                logical_len: V1_SECTOR_SIZE as u32,
                                virtual_zero: false,
                            },
                        }],
                        parity: vec![mb_core::ParityPlacementV2 {
                            holder: remotes[0].node_id(),
                            failure_domain: member(remotes[0].node_id()).failure_domain,
                            row: 0,
                        }],
                    },
                    delegator: local_id,
                    coding_coordinator: remotes[1].node_id(),
                    verification_coordinator: remotes[2].node_id(),
                    expires_at_unix_seconds: unix_seconds() + 600,
                    information_roots: Some(vec![sector_root(&shards[0])]),
                })
                .unwrap();
            node.enqueue_coding_launch_with_information(
                initial.clone(),
                (case != 4).then(BTreeMap::new),
            )
            .unwrap();
            let failure = SignedRecord::sign(
                CODING_FAILURE_REPORT_DOMAIN,
                CodingFailureReport {
                    format_version: 1,
                    failed_at_unix_seconds: unix_seconds(),
                    plan: initial.clone(),
                    error_hash: [100; 32],
                },
                remotes[1],
            )
            .unwrap();
            node.accept_coding_failure(failure.signer, failure.clone())
                .unwrap();
            let child = node
                .prepare_coding_retry(
                    initial.value.attempt_id,
                    remotes[0].node_id(),
                    remotes[3].node_id(),
                    unix_seconds() + 600,
                )
                .unwrap();
            assert_eq!(child.value.format_version, 3);
            node.complete_coding_retry(initial.value.attempt_id)
                .unwrap();
            assert!(node.claim_coding_retry(None).unwrap().is_none());
            if case == 2 {
                let result = test_coding_transcript(child.clone(), &shards, &keys);
                node.accept_coding_transcript(child.value.coding_coordinator, result)
                    .unwrap();
            }
            let child_failure = if case == 3 {
                let failure = SignedRecord::sign(
                    CODING_FAILURE_REPORT_DOMAIN,
                    CodingFailureReport {
                        format_version: 1,
                        failed_at_unix_seconds: unix_seconds(),
                        plan: child.clone(),
                        error_hash: [101; 32],
                    },
                    remotes[0],
                )
                .unwrap();
                node.accept_coding_failure(failure.signer, failure.clone())
                    .unwrap();
                assert!(!node.retire_coding_retry_successor(&child).unwrap());
                assert!(node.retire_coding_retry_plan(&child).unwrap());
                // A late parent acknowledgement meets a child failure owner
                // and a retirement fence. The child's retry still needs input.
                node.complete_coding_retry(initial.value.attempt_id)
                    .unwrap();
                assert_eq!(
                    node.coding_launch_information_to_stage(child.value.attempt_id)
                        .unwrap(),
                    Some(BTreeMap::new())
                );
                Some(failure)
            } else {
                None
            };
            if case >= 4 {
                assert!(
                    node.retire_delegated_coding_attempt(child.value.coding_coordinator, &child)
                        .unwrap()
                );
                node.complete_coding_retry(initial.value.attempt_id)
                    .unwrap();
                for id in [initial.value.attempt_id, child.value.attempt_id] {
                    assert_eq!(
                        node.coding_launch_information_to_stage(id).unwrap(),
                        (case != 4).then(BTreeMap::new),
                    );
                }
            }
            if case == 1 || case == 4 {
                let state = node.dynamic_guild_state().unwrap().unwrap();
                let event = GuildEvent {
                    format_version: 1,
                    guild_id: state.guild_id,
                    sequence: state.event_sequence + 1,
                    parent: state.event_head,
                    kind: mb_core::GuildEventKind::RelabelMember {
                        node_id: remotes[2].node_id(),
                        failure_domain: "acknowledged-retry-unrelated-change".to_owned(),
                    },
                };
                let mut signatures = keys
                    .iter()
                    .map(|key| sign_guild_event(&event, key).unwrap())
                    .collect::<Vec<_>>();
                signatures.sort_by_key(|signature| signature.signer);
                node.install_guild_event(QuorumGuildEvent { event, signatures })
                    .unwrap();
            }
            drop(node);
            node = Node::open(&dir, seed.clone()).unwrap();
            let now = if case == 1 || case >= 4 {
                unix_seconds()
            } else {
                child.value.expires_at_unix_seconds + 1
            };
            let claimed = node.claim_coding_retry_at(None, now).unwrap();
            if case == 3 {
                assert_eq!(claimed.unwrap().failure, *child_failure.as_ref().unwrap());
            } else if case == 2 {
                assert!(claimed.is_none());
                assert!(
                    node.retired_coding_plan_for_test(child.value.attempt_id)
                        .unwrap()
                        .is_none()
                );
                assert!(!node.retire_coding_retry_successor(&child).unwrap());
            } else {
                let claimed = claimed.unwrap();
                assert!(!claimed.complete);
                assert_eq!(claimed.failure, failure);
                assert_eq!(claimed.retry_plan, Some(child.clone()));
                // The controlled gate has no holder staging. Only explicit
                // completion after cleanup makes this exact fence terminal.
                assert!(node.retire_coding_retry_plan(&child).unwrap());
                node.complete_coding_retry_after_cleanup(initial.value.attempt_id)
                    .unwrap();
            }
            for _ in 0..2 {
                drop(node);
                node = Node::open(&dir, seed.clone()).unwrap();
                let claimed = node.claim_coding_retry_at(None, now).unwrap();
                if case == 3 {
                    assert_eq!(claimed.unwrap().failure, *child_failure.as_ref().unwrap());
                    assert_eq!(
                        node.coding_launch_information_to_stage(child.value.attempt_id)
                            .unwrap(),
                        Some(BTreeMap::new())
                    );
                } else {
                    assert!(claimed.is_none());
                }
                let retained = node
                    .coding_retry_evidence_for_test(initial.value.attempt_id)
                    .unwrap();
                assert!(retained.complete);
                assert_eq!(retained.failure, failure);
                assert_eq!(retained.retry_plan, Some(child.clone()));
                if case == 2 {
                    assert!(!node.retire_coding_retry_plan(&child).unwrap());
                } else if case != 3 {
                    for id in [initial.value.attempt_id, child.value.attempt_id] {
                        assert!(
                            node.coding_launch_information_to_stage(id)
                                .unwrap()
                                .is_none()
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn legacy_proof_upgrade_preserves_durable_jobs_and_certified_groups() {
        legacy_proof_upgrade_fixture(V1_SECTOR_SIZE as u32, true);
    }

    #[test]
    fn legacy_launch_renewal_yields_to_format_three_retry_and_upgrades_when_alone() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let keys = (0_u8..5)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([120 + i; 32])))
            .collect::<Vec<_>>();
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers.clone())
            .unwrap();
        let owner = node.keys().node_id();
        let remotes = keys
            .iter()
            .filter(|key| key.node_id() != owner)
            .collect::<Vec<_>>();
        let member = |id| {
            peers
                .iter()
                .find(|peer| peer.member.node_id == id)
                .unwrap()
                .member
                .clone()
        };
        let shards =
            mb_core::encode(mb_core::CodingProfile::new(1, 1, 64), vec![vec![67; 64]]).unwrap();
        let geometry = mb_core::CodingPlanGeometry {
            format_version: 1,
            guild_id: node.dynamic_guild_state().unwrap().unwrap().guild_id,
            profile: mb_core::CodingProfile::new(1, 1, 64),
            information: vec![mb_core::InformationRoleV2 {
                owner,
                failure_domain: member(owner).failure_domain,
                sector: mb_core::RangeSectorRef {
                    id: [71; 32],
                    commitment: merkle_commit(&shards[0]).unwrap(),
                    logical_len: 64,
                    virtual_zero: false,
                },
            }],
            parity: vec![mb_core::ParityPlacementV2 {
                holder: remotes[0].node_id(),
                failure_domain: member(remotes[0].node_id()).failure_domain,
                row: 0,
            }],
        };
        let roots = vec![sector_root(&shards[0])];
        assert_ne!(roots[0], geometry.information[0].sector.commitment.root);
        let old = SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            CodingAttemptPlan {
                format_version: 2,
                attempt_id: [11; 16],
                checkpoint_hash: [72; 32],
                membership_epoch: 1,
                geometry,
                delegator: owner,
                coding_coordinator: remotes[1].node_id(),
                verification_coordinator: remotes[2].node_id(),
                expires_at_unix_seconds: unix_seconds() - 1,
                information_roots: Some(roots),
            },
            node.keys(),
        )
        .unwrap();
        let old_job = CodingLaunchJob {
            format_version: 1,
            plan: old.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&old_job).unwrap();
        node.control
            .put_record(
                "coding-launch-information",
                &old.value.attempt_id,
                &canonical_bytes(&BTreeMap::<SectorId, PackedSectorDescriptor>::new()).unwrap(),
            )
            .unwrap();
        let mut new_value = old.value.clone();
        new_value.format_version = 3;
        new_value.attempt_id = [12; 16];
        new_value.expires_at_unix_seconds = unix_seconds() + 600;
        let new = node.sign_coding_attempt_plan(new_value).unwrap();
        assert_eq!(node.enqueue_coding_launch(new.clone()).unwrap(), new);
        let failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: new.clone(),
                error_hash: [73; 32],
            },
            keys.iter()
                .find(|key| key.node_id() == new.value.coding_coordinator)
                .unwrap(),
        )
        .unwrap();
        node.accept_coding_failure(new.value.coding_coordinator, failure)
            .unwrap();
        let retry = node
            .prepare_coding_retry(
                new.value.attempt_id,
                remotes[0].node_id(),
                remotes[3].node_id(),
                unix_seconds() + 600,
            )
            .unwrap();
        node.complete_coding_retry(new.value.attempt_id).unwrap();
        assert!(node.retire_coding_retry_plan(&old).unwrap());
        assert!(node.coding_launch_has_renewal(&old).unwrap());
        assert_eq!(
            node.renew_coding_launch_after_cleanup(&old_job, None, None)
                .unwrap(),
            retry
        );
        assert!(node.coding_launch_jobs_for_test().unwrap().is_empty());
        assert!(
            node.coding_launch_information_to_stage(retry.value.attempt_id)
                .unwrap()
                .is_some()
        );
        for _ in 0..2 {
            drop(node);
            node = Node::open(temp.path(), seed.clone()).unwrap();
            assert_eq!(
                node.coding_launch_successor_for_test(old.value.attempt_id)
                    .unwrap(),
                Some(retry.clone())
            );
            assert!(node.coding_launch_jobs_for_test().unwrap().is_empty());
            assert!(
                node.coding_launch_information_to_stage(retry.value.attempt_id)
                    .unwrap()
                    .is_some()
            );
        }

        let mut isolated_value = old.value.clone();
        isolated_value.checkpoint_hash = [74; 32];
        isolated_value.attempt_id = [14; 16];
        let isolated = SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            isolated_value.clone(),
            node.keys(),
        )
        .unwrap();
        let isolated_job = CodingLaunchJob {
            format_version: 1,
            plan: isolated.clone(),
            dispatched: true,
            error: None,
        };
        node.put_coding_launch_job(&isolated_job).unwrap();
        isolated_value.format_version = 3;
        isolated_value.attempt_id = [15; 16];
        isolated_value.expires_at_unix_seconds = unix_seconds() + 600;
        let stronger = node.sign_coding_attempt_plan(isolated_value).unwrap();
        assert!(!node.coding_launch_has_renewal(&stronger).unwrap());
        assert!(node.retire_coding_retry_plan(&isolated).unwrap());
        let upgraded = node
            .renew_coding_launch_after_cleanup(
                &isolated_job,
                Some((remotes[0].node_id(), remotes[3].node_id())),
                None,
            )
            .unwrap();
        assert_eq!(upgraded.value.format_version, 3);
        assert_eq!(
            upgraded.value.information_roots,
            stronger.value.information_roots
        );
        assert_eq!(node.enqueue_coding_launch(stronger).unwrap(), upgraded);
    }

    #[test]
    fn short_information_proof_cannot_protect_legacy_checkpoint() {
        legacy_proof_upgrade_fixture(64, false);
    }

    fn legacy_proof_upgrade_fixture(shard_size: u32, legacy_coverage_expected: bool) {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let keys = (0_u8..5)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([120 + i; 32])))
            .collect::<Vec<_>>();
        let local_id = KeyMaterial::from_seed(&seed).node_id();
        let remotes = keys
            .iter()
            .filter(|key| key.node_id() != local_id)
            .collect::<Vec<_>>();
        let member = |id| {
            peers
                .iter()
                .find(|peer| peer.member.node_id == id)
                .unwrap()
                .member
                .clone()
        };
        let profile = mb_core::CodingProfile::new(1, 1, shard_size);
        let shards = mb_core::encode(profile, vec![vec![67; shard_size as usize]]).unwrap();
        let geometry = mb_core::CodingPlanGeometry {
            format_version: 1,
            guild_id: certificate.genesis.guild_id,
            profile,
            information: vec![mb_core::InformationRoleV2 {
                owner: local_id,
                failure_domain: member(local_id).failure_domain,
                sector: mb_core::RangeSectorRef {
                    id: [71; 32],
                    commitment: merkle_commit(&shards[0]).unwrap(),
                    logical_len: 64,
                    virtual_zero: false,
                },
            }],
            parity: vec![mb_core::ParityPlacementV2 {
                holder: remotes[0].node_id(),
                failure_domain: member(remotes[0].node_id()).failure_domain,
                row: 0,
            }],
        };
        let roots = vec![sector_root(&shards[0])];
        let old = CodingAttemptPlan {
            format_version: 2,
            attempt_id: CodingAttemptPlan::initial_attempt_id(2, [72; 32], &geometry, &roots)
                .unwrap(),
            checkpoint_hash: [72; 32],
            membership_epoch: 1,
            geometry,
            delegator: local_id,
            coding_coordinator: remotes[1].node_id(),
            verification_coordinator: remotes[2].node_id(),
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(roots),
        };
        let mut new = old.clone();
        new.format_version = 3;
        new.attempt_id = CodingAttemptPlan::initial_attempt_id(
            3,
            new.checkpoint_hash,
            &new.geometry,
            new.information_roots.as_ref().unwrap(),
        )
        .unwrap();
        let signer = keys.iter().find(|key| key.node_id() == local_id).unwrap();
        let old = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, old, signer).unwrap();
        let new = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, new, signer).unwrap();
        let old_transcript = test_coding_transcript(old.clone(), &shards, &keys);
        let new_transcript = test_coding_transcript(new.clone(), &shards, &keys);
        assert_ne!(old.value.attempt_id, new.value.attempt_id);
        assert_ne!(
            old_transcript.value.manifest.value.group.id,
            new_transcript.value.manifest.value.group.id
        );
        let failure = SignedRecord::sign(
            CODING_FAILURE_REPORT_DOMAIN,
            CodingFailureReport {
                format_version: 1,
                failed_at_unix_seconds: unix_seconds(),
                plan: old.clone(),
                error_hash: [73; 32],
            },
            remotes[1],
        )
        .unwrap();
        for (kind, bytes) in [
            (
                "coding-launch-job",
                canonical_bytes(&CodingLaunchJob {
                    format_version: 1,
                    plan: old.clone(),
                    dispatched: true,
                    error: None,
                })
                .unwrap(),
            ),
            (
                "coding-retry-job",
                canonical_bytes(&CodingRetryJob {
                    format_version: 1,
                    failure: failure.clone(),
                    retry_plan: None,
                    complete: false,
                    error: None,
                })
                .unwrap(),
            ),
            (
                "coding-activation-job",
                canonical_bytes(&CodingActivationJob {
                    format_version: 1,
                    transcript: old_transcript.clone(),
                    complete: false,
                    error: None,
                })
                .unwrap(),
            ),
        ] {
            let dir = temp.path().join(kind);
            let mut node = Node::open(&dir, seed.clone()).unwrap();
            node.adopt_recovered_guild(certificate.clone(), peers.clone())
                .unwrap();
            node.control
                .put_record(kind, &old.value.attempt_id, &bytes)
                .unwrap();
            drop(node);
            let mut node = Node::open(&dir, seed.clone()).unwrap();
            assert_eq!(node.enqueue_coding_launch(new.clone()).unwrap(), new);
            assert_eq!(
                node.control
                    .get_record(kind, &old.value.attempt_id)
                    .unwrap()
                    .unwrap(),
                bytes
            );
            assert_eq!(node.claim_coding_launch().unwrap().unwrap().plan, new);
            if kind == "coding-launch-job" {
                let volume = temp.path().join("stale-delegated-volume");
                std::fs::create_dir(&volume).unwrap();
                node.configure_storage_volumes(&[volume], 4 * 1024 * 1024, 0)
                    .unwrap();
                let delegated = |attempt_id| {
                    let mut plan = old.value.clone();
                    plan.attempt_id = attempt_id;
                    plan.delegator = remotes[0].node_id();
                    plan.coding_coordinator = local_id;
                    plan.verification_coordinator = remotes[1].node_id();
                    SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, remotes[0]).unwrap()
                };
                let complete = delegated([82; 16]);
                let pending = delegated([83; 16]);
                node.enqueue_delegated_coding(complete.value.delegator, complete.clone())
                    .unwrap();
                node.complete_delegated_coding(complete.value.attempt_id)
                    .unwrap();
                node.enqueue_delegated_coding(pending.value.delegator, pending.clone())
                    .unwrap();
                node.reserve_coding_information(&pending, 0).unwrap();
                node.write_coding_information_range(&pending, 0, 0, &shards[0])
                    .unwrap();
                node.finish_coding_information_upload(&pending, 0).unwrap();
                assert_eq!(
                    node.coding_used_bytes_for_test().unwrap(),
                    u64::from(shard_size)
                );
                let state = node.dynamic_guild_state().unwrap().unwrap();
                let event = GuildEvent {
                    format_version: 1,
                    guild_id: state.guild_id,
                    sequence: state.event_sequence + 1,
                    parent: state.event_head,
                    kind: mb_core::GuildEventKind::RelabelMember {
                        node_id: remotes[2].node_id(),
                        failure_domain: "epoch-change-for-cleanup".to_owned(),
                    },
                };
                let mut signatures = keys
                    .iter()
                    .map(|key| sign_guild_event(&event, key).unwrap())
                    .collect::<Vec<_>>();
                signatures.sort_by_key(|signature| signature.signer);
                node.install_guild_event(QuorumGuildEvent { event, signatures })
                    .unwrap();
                drop(node);
                let mut node = Node::open(&dir, seed.clone()).unwrap();
                assert_eq!(
                    node.claim_delegated_coding().unwrap().unwrap().plan,
                    pending
                );
                assert!(
                    node.discard_coding_attempt(&pending.value.attempt_id)
                        .unwrap()
                );
                node.complete_delegated_coding(pending.value.attempt_id)
                    .unwrap();
                assert_eq!(node.coding_reservation_count_for_test().unwrap(), 0);
                assert_eq!(node.coding_used_bytes_for_test().unwrap(), 0);
                assert!(node.claim_delegated_coding().unwrap().is_none());
                drop(node);
                let node = Node::open(&dir, seed.clone()).unwrap();
                assert!(node.claim_delegated_coding().unwrap().is_none());
            } else if kind == "coding-retry-job" {
                let mut prepared = old.value.clone();
                prepared.attempt_id = [79; 16];
                let prepared =
                    SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, prepared, signer).unwrap();
                let late_result = test_coding_transcript(prepared.clone(), &shards, &keys);
                assert!(node.coding_attempt_is_retired(local_id, &prepared).is_err());
                assert!(
                    !node
                        .coding_attempt_is_retired(prepared.value.coding_coordinator, &prepared)
                        .unwrap()
                );
                assert!(
                    node.retire_delegated_coding_attempt(local_id, &prepared)
                        .is_err()
                );
                assert!(
                    node.retire_delegated_coding_attempt(
                        prepared.value.coding_coordinator,
                        &prepared
                    )
                    .unwrap()
                );
                assert!(
                    node.coding_attempt_is_retired(prepared.value.coding_coordinator, &prepared)
                        .unwrap()
                );
                let mut conflicting = prepared.value.clone();
                conflicting.expires_at_unix_seconds += 1;
                let conflicting =
                    SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, conflicting, signer).unwrap();
                assert!(
                    node.coding_attempt_is_retired(prepared.value.coding_coordinator, &conflicting)
                        .is_err()
                );
                assert!(
                    node.accept_coding_transcript(prepared.value.coding_coordinator, late_result)
                        .is_err()
                );
                let late_failure = SignedRecord::sign(
                    CODING_FAILURE_REPORT_DOMAIN,
                    CodingFailureReport {
                        format_version: 1,
                        failed_at_unix_seconds: unix_seconds(),
                        plan: prepared.clone(),
                        error_hash: [80; 32],
                    },
                    remotes[1],
                )
                .unwrap();
                node.accept_coding_failure(late_failure.signer, late_failure.clone())
                    .unwrap();
                node.accept_coding_failure(late_failure.signer, late_failure.clone())
                    .unwrap();
                assert!(
                    node.control
                        .get_record("coding-retry-job", &prepared.value.attempt_id)
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    node.control
                        .get_record("coding-retired-failure", &prepared.value.attempt_id)
                        .unwrap(),
                    Some(canonical_bytes(&late_failure).unwrap())
                );
                assert_eq!(
                    node.claim_coding_retry(Some(old.value.attempt_id))
                        .unwrap()
                        .unwrap()
                        .failure,
                    failure
                );
                let mut verified = prepared.value.clone();
                verified.attempt_id = [81; 16];
                let verified =
                    SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, verified, signer).unwrap();
                let result = test_coding_transcript(verified.clone(), &shards, &keys);
                node.accept_coding_transcript(verified.value.coding_coordinator, result.clone())
                    .unwrap();
                assert!(!node.retire_coding_retry_plan(&verified).unwrap());
                assert!(
                    !node
                        .retire_delegated_coding_attempt(
                            verified.value.coding_coordinator,
                            &verified
                        )
                        .unwrap()
                );
                assert_eq!(
                    node.claim_coding_activation().unwrap().unwrap().transcript,
                    result
                );
                drop(node);
                let node = Node::open(&dir, seed.clone()).unwrap();
                assert!(
                    node.coding_attempt_is_retired(prepared.value.coding_coordinator, &prepared)
                        .unwrap()
                );
                assert!(
                    !node
                        .coding_attempt_is_retired(verified.value.coding_coordinator, &verified)
                        .unwrap()
                );
                assert_eq!(
                    node.control
                        .get_record("coding-retired-attempt", &prepared.value.attempt_id)
                        .unwrap(),
                    Some(canonical_bytes(&prepared).unwrap())
                );
                assert_eq!(
                    node.claim_coding_activation().unwrap().unwrap().transcript,
                    result
                );
            }
        }
        let dir = temp.path().join("groups");
        let volume = temp.path().join("volume");
        std::fs::create_dir(&volume).unwrap();
        let mut node = Node::open(&dir, seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate.clone(), peers.clone())
            .unwrap();
        node.configure_storage_volumes(std::slice::from_ref(&volume), 1024 * 1024, 0)
            .unwrap();
        node.configure_failure_domain(&member(local_id).failure_domain)
            .unwrap();
        let writer = ed25519_dalek::SigningKey::from_bytes(&[74; 32]);
        let mut revision = UserRevision {
            format_version: 3,
            guild_id: certificate.genesis.guild_id,
            protected_root_id: Uuid::from_bytes([75; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([76; 16]),
            owner: local_id,
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![SectorRef {
                id: [71; 32],
                root: sector_root(&shards[0]),
                logical_len: 64,
            }],
            data_sectors: Vec::new(),
            sector_commitments: None,
        };
        revision.sign_writer(&writer).unwrap();
        let checkpoint = GuildCheckpoint {
            format_version: 4,
            guild_id: certificate.genesis.guild_id,
            genesis_hash: certificate.hash().unwrap(),
            generation: 1,
            parent: None,
            members: peers.iter().map(|peer| peer.member.clone()).collect(),
            writer_fences: vec![mb_core::WriterFence {
                owner: local_id,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            }],
            revision_tombstones: Vec::new(),
            revisions: vec![SignedRecord::sign(USER_REVISION_DOMAIN, revision, signer).unwrap()],
            coding_groups: Vec::new(),
            authority: None,
            packing_catalog: None,
        };
        checkpoint.validate().unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let event = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RotateWriterKey {
                owner: local_id,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|key| sign_guild_event(&event, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent { event, signatures })
            .unwrap();
        for transcript in [&old_transcript, &new_transcript] {
            let plan = &transcript.value.plan;
            if node.reserve_coding_information(plan, 0).unwrap() == 0 {
                node.write_coding_information_range(plan, 0, 0, &shards[0])
                    .unwrap();
            }
            node.finish_coding_information_upload(plan, 0).unwrap();
            assert_eq!(
                node.coding_information_range(plan, 0, 0, 1).unwrap(),
                merkle_open_range(&shards[0], 0, 1).unwrap()
            );
            node.activate_coding_attempt(transcript).unwrap();
            let state = node.dynamic_guild_state().unwrap().unwrap();
            let event = GuildEvent {
                format_version: 2,
                guild_id: state.guild_id,
                sequence: state.event_sequence + 1,
                parent: state.event_head,
                kind: mb_core::GuildEventKind::AddCodingGroupBound {
                    group: transcript.value.manifest.value.group.clone(),
                    transcript_hash: *blake3::hash(&canonical_bytes(transcript).unwrap())
                        .as_bytes(),
                },
            };
            node.sign_coding_group_event_proposal(&event, transcript)
                .unwrap();
            let mut signatures = keys
                .iter()
                .map(|key| sign_guild_event(&event, key).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            node.install_coding_group_event(
                QuorumGuildEvent { event, signatures },
                transcript.clone(),
            )
            .unwrap();
            if transcript.value.plan.value.format_version == 2 {
                assert!(
                    node.validate_variable_checkpoint_coverage(&checkpoint, false)
                        .is_err()
                );
                assert_eq!(
                    node.validate_variable_checkpoint_coverage(&checkpoint, true)
                        .is_ok(),
                    legacy_coverage_expected
                );
            } else {
                assert_eq!(
                    node.validate_variable_checkpoint_coverage(&checkpoint, false)
                        .is_ok(),
                    legacy_coverage_expected
                );
            }
        }
        drop(node);
        let mut node = Node::open(&dir, seed).unwrap();
        node.configure_storage_volumes(&[volume], 1024 * 1024, 0)
            .unwrap();
        assert_eq!(
            node.dynamic_guild_state()
                .unwrap()
                .unwrap()
                .coding_groups
                .len(),
            2
        );
        for transcript in [&old_transcript, &new_transcript] {
            assert_eq!(
                node.coding_transcript_for_group(
                    certificate.genesis.guild_id,
                    transcript.value.manifest.value.group.id
                )
                .unwrap(),
                *transcript
            );
            assert_eq!(
                node.variable_shard_for_guild(
                    &certificate.genesis.guild_id,
                    &transcript.value.manifest.value.group.id,
                    0
                )
                .unwrap(),
                shards[0]
            );
        }
        assert_eq!(
            node.verified_variable_sector_coverage(
                &node.dynamic_guild_state().unwrap().unwrap(),
                local_id,
                &SectorRef {
                    id: [71; 32],
                    root: sector_root(&shards[0]),
                    logical_len: 64
                },
                None,
                false,
                true
            )
            .unwrap(),
            legacy_coverage_expected
        );
        assert_eq!(
            node.validate_variable_checkpoint_coverage(&checkpoint, false)
                .is_ok(),
            legacy_coverage_expected
        );
        assert_eq!(
            node.sign_checkpoint(&checkpoint).is_ok(),
            legacy_coverage_expected
        );
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
        node.configure_storage_volumes(&[storage.path().to_path_buf()], 8 * 1024 * 1024, 0)
            .unwrap();
        let mut information_node =
            Node::open(information_data_dir.path(), identities[2].1.clone()).unwrap();
        information_node
            .adopt_recovered_guild(certificate.clone(), peers)
            .unwrap();
        information_node
            .configure_storage_volumes(
                &[information_storage.path().to_path_buf()],
                8 * 1024 * 1024,
                0,
            )
            .unwrap();

        let profile = mb_core::CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32);
        let information = vec![
            vec![7; V1_SECTOR_SIZE],
            vec![19; V1_SECTOR_SIZE],
            vec![31; V1_SECTOR_SIZE],
        ];
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
            format_version: 3,
            guild_id: [181; 32],
            profile,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let plan = CodingAttemptPlan {
            format_version: 3,
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
            V1_SECTOR_SIZE as u32
        );
        information_node
            .finish_coding_information_upload(&plan, 2)
            .unwrap();
        let challenge_commitment = node.commit_coding_challenge(&plan).unwrap();
        let manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            CodingRootManifest {
                format_version: 2,
                attempt_id: [182; 16],
                plan_hash,
                group,
                information_bytes: Some(shards[..3].iter().cloned().map(Some).collect()),
            },
            &keys[1],
        )
        .unwrap();
        #[derive(serde::Serialize)]
        struct LegacyManifest<'a> {
            format_version: u16,
            attempt_id: [u8; 16],
            plan_hash: [u8; 32],
            group: &'a mb_core::CodingGroupV2,
        }
        let legacy_manifest = CodingRootManifest {
            format_version: 1,
            attempt_id: manifest.value.attempt_id,
            plan_hash: manifest.value.plan_hash,
            group: manifest.value.group.clone(),
            information_bytes: None,
        };
        let legacy_layout = LegacyManifest {
            format_version: 1,
            attempt_id: legacy_manifest.attempt_id,
            plan_hash: legacy_manifest.plan_hash,
            group: &legacy_manifest.group,
        };
        let legacy_cbor = cbor4ii::serde::to_vec(Vec::new(), &legacy_layout).unwrap();
        assert_eq!(
            cbor4ii::serde::to_vec(Vec::new(), &legacy_manifest).unwrap(),
            legacy_cbor
        );
        assert_eq!(
            canonical_bytes(&legacy_manifest).unwrap(),
            canonical_bytes(&legacy_layout).unwrap(),
        );
        assert_eq!(
            cbor4ii::serde::from_slice::<CodingRootManifest>(&legacy_cbor).unwrap(),
            legacy_manifest,
        );
        assert_eq!(
            cbor4ii::serde::from_slice::<SignedRecord<CodingRootManifest>>(
                &cbor4ii::serde::to_vec(Vec::new(), &manifest).unwrap()
            )
            .unwrap(),
            manifest,
        );
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
            V1_SECTOR_SIZE as u32
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
            node.control
                .get_record(
                    "coding-pending-activation",
                    &transcript.value.plan.value.attempt_id,
                )
                .unwrap()
                .is_some()
        );
        assert!(
            node.discard_coding_attempt(&transcript.value.plan.value.attempt_id)
                .unwrap()
        );
        assert!(
            node.control
                .get_record(
                    "coding-pending-activation",
                    &transcript.value.plan.value.attempt_id,
                )
                .unwrap()
                .is_none()
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
            V1_SECTOR_SIZE as u32
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
            format_version: 2,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: transcript.value.manifest.value.group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&transcript).unwrap()).as_bytes(),
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
        assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 0);
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
            sector_commitments: None,
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
            node.uncovered_variable_sectors(
                members[2].node_id,
                std::slice::from_ref(&target),
                None
            )
            .unwrap()
            .is_empty()
        );
        let mut changed = target.clone();
        changed.root[0] ^= 1;
        assert_eq!(
            node.uncovered_variable_sectors(members[2].node_id, &[changed.clone()], None)
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
            node.uncovered_variable_sectors(
                members[2].node_id,
                std::slice::from_ref(&target),
                None
            )
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
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let retire = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::RetireCodingGroup {
                group_id: transcript.value.manifest.value.group.id,
                retain_through_event: state.event_sequence + 1,
            },
        };
        let mut signatures = keys
            .iter()
            .map(|keys| sign_guild_event(&retire, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: retire,
            signatures,
        })
        .unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let forget = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::ForgetCodingGroup {
                group_id: transcript.value.manifest.value.group.id,
            },
        };
        let mut signatures = keys
            .iter()
            .map(|keys| sign_guild_event(&forget, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_guild_event(QuorumGuildEvent {
            event: forget,
            signatures,
        })
        .unwrap();
        // This completed group was forgotten by the ordinary lifecycle: no
        // attempt abort was needed to give its parity holder durable cleanup.
        assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 1);
        assert!(
            node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, false)
                .is_err()
        );
        node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, true)
            .unwrap();
        drop(node);
        let mut node = Node::open(data_dir.path(), identities[4].1.clone()).unwrap();
        assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 1);
        node.validate_variable_checkpoint_coverage(&checkpoint.checkpoint, true)
            .unwrap();
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
            .is_err(),
            "Forget cleanup must remove parity installed by a later repair of the old group"
        );
        let mut active_receipt_id = transcript.value.manifest.value.group.id.to_vec();
        active_receipt_id.push(4);
        assert!(
            node.control
                .get_record("volume-receipt", &active_receipt_id)
                .unwrap()
                .is_none()
        );
        let mut repair_receipt_id = [186; 16].to_vec();
        repair_receipt_id.extend_from_slice(&active_receipt_id);
        assert!(
            node.control
                .get_record("volume-attempt-receipt", &repair_receipt_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 0);
        for _ in 0..2 {
            drop(node);
            node = Node::open(data_dir.path(), identities[4].1.clone()).unwrap();
            assert_eq!(node.coding_holder_cleanup_count_for_test().unwrap(), 0);
            assert!(
                node.variable_shard_for_guild(
                    &[181; 32],
                    &transcript.value.manifest.value.group.id,
                    4,
                )
                .is_err()
            );
        }
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
            sector_commitments: None,
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
            sector_commitments: None,
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
        let root_id = Uuid::from_bytes([1; 16]);
        node.register_protected_root(&source, Some(root_id), true, true)
            .unwrap();
        let revision = node
            .prepare_revision(guild_id, root_id, &source, 1, None)
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

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn source_backend_binding_reprobes_and_migrates() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("source-binding-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        fs::create_dir_all(&source).unwrap();
        let mut node = Node::open(run_root.join("node"), Seed::from_bytes([240; 32])).unwrap();
        let info = node.git_init(&source).unwrap();
        let key = info.repository_id.as_bytes();
        let decode_binding = |node: &Node| -> SourceBackendBinding {
            decode_canonical(
                &node
                    .control
                    .get_record("source-backend", key)
                    .unwrap()
                    .unwrap(),
            )
            .unwrap()
        };
        let initial = decode_binding(&node);
        let filesystem = filesystem_identity(&source).unwrap();
        assert!(initial.is_supported_for(
            info.repository_id,
            filesystem.stable_id,
            fs::metadata(&source).unwrap().ino(),
        ));
        assert_eq!(initial.mount_id, filesystem.mount_id);

        let mut remounted = initial.clone();
        remounted.mount_id = if initial.mount_id == u64::MAX {
            initial.mount_id - 1
        } else {
            initial.mount_id + 1
        };
        node.control
            .put_record("source-backend", key, &canonical_bytes(&remounted).unwrap())
            .unwrap();
        node.git_status(info.repository_id).unwrap();
        assert_eq!(decode_binding(&node), initial);

        node.control.delete_record("source-backend", key).unwrap();
        node.git_status(info.repository_id).unwrap();
        assert_eq!(decode_binding(&node), initial);

        let mut incompatible = initial.clone();
        incompatible.contract_version = 2;
        let bytes = canonical_bytes(&incompatible).unwrap();
        node.control
            .put_record("source-backend", key, &bytes)
            .unwrap();
        assert!(node.git_status(info.repository_id).is_err());
        assert_eq!(
            node.control.get_record("source-backend", key).unwrap(),
            Some(bytes)
        );
        node.control
            .put_record("source-backend", key, &canonical_bytes(&initial).unwrap())
            .unwrap();
        fs::write(source.join("tracked"), b"backend-routed Git bytes\r\n").unwrap();
        let staged = node.git_add_path(info.repository_id, Path::new("tracked"));
        assert!(staged.unwrap().is_some());
        node.git_commit(
            info.repository_id,
            "Source Test",
            "source@test.invalid",
            "first",
        )
        .unwrap();
        node.git_create_branch(info.repository_id, "saved").unwrap();
        fs::write(source.join("tracked"), b"edited bytes\n").unwrap();
        node.git_add_path(info.repository_id, Path::new("tracked"))
            .unwrap();
        node.git_commit(
            info.repository_id,
            "Source Test",
            "source@test.invalid",
            "second",
        )
        .unwrap();
        node.git_switch_branch(info.repository_id, "saved").unwrap();
        assert_eq!(
            fs::read(source.join("tracked")).unwrap(),
            b"backend-routed Git bytes\r\n"
        );

        let recovered_source = run_root.join("recovered-source");
        fs::create_dir(&recovered_source).unwrap();
        let recovered = node
            .register_protected_root(&recovered_source, None, false, false)
            .unwrap();
        let recovered_key = recovered.root_id.as_bytes();
        assert_eq!(
            node.control
                .get_record("source-backend", recovered_key)
                .unwrap(),
            None
        );
        let recovered_filesystem = filesystem_identity(&recovered_source).unwrap();
        let binding = node
            .source_backend_for_root(&recovered, recovered_filesystem)
            .unwrap();
        assert_eq!(
            node.control
                .get_record("source-backend", recovered_key)
                .unwrap(),
            Some(canonical_bytes(&binding).unwrap())
        );
        drop(node);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn node_owns_claimed_guarded_mount_across_reopen() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/tmp"));
        let area = tempfile::Builder::new()
            .prefix("mb-node-guarded-mount-")
            .tempdir_in(test_root)
            .unwrap();
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let view = area.path().join("view");
        let data_dir = area.path().join("node");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&view).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&view, fs::Permissions::from_mode(0o755)).unwrap();
        let original = b"guarded\r\n\0source\n";
        fs::write(lower.join("sample"), original).unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();

        let seed = Seed::from_bytes([241; 32]);
        let node = Node::open(&data_dir, seed.clone()).unwrap();
        let database_key = node.control_database_key;
        let plan = mb_store::GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&node.control).unwrap();
        let guarded_control = Arc::new(Mutex::new(
            ControlStore::open_with_key(data_dir.join("control.db"), &node.control_database_key)
                .unwrap(),
        ));
        let mounted = mb_store::GuardedViewMount::start(
            &manifest,
            Arc::clone(&guarded_control),
            &view,
            65534,
            65534,
        )
        .unwrap();
        mounted.stop().unwrap();
        drop(guarded_control);
        drop(node);

        let reopened = Node::open(&data_dir, seed.clone()).unwrap();
        reopened.check_guarded_mounts().unwrap();
        let visible = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(view.join("sample"))
            .output()
            .unwrap();
        assert!(visible.status.success(), "{visible:?}");
        assert_eq!(visible.stdout, original);
        let private = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(lower.join("sample"))
            .output()
            .unwrap();
        assert!(!private.status.success());

        let mount_path = CString::new(view.as_os_str().as_bytes()).unwrap();
        // SAFETY: the private test mountpoint is NUL-free and this test owns it.
        assert_eq!(
            unsafe { libc::umount2(mount_path.as_ptr(), libc::MNT_DETACH) },
            0
        );
        assert!(reopened.check_guarded_mounts().is_err());
        assert!(fs::read(view.join("sample")).is_err());
        drop(reopened);

        let mut recovered = Node::open(&data_dir, seed).unwrap();
        recovered.check_guarded_mounts().unwrap();
        let write = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.pwrite(fd,b'EDIT',0); os.fsync(fd); os.close(fd)")
            .arg(view.join("sample"))
            .output()
            .unwrap();
        assert!(write.status.success(), "{write:?}");
        assert!(fs::read(lower.join("sample")).unwrap().starts_with(b"EDIT"));
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut protected = Vec::new();
        use std::io::Read;
        anchor.read_to_end(&mut protected).unwrap();
        assert_eq!(protected, original);
        let unsupervised = recovered.guarded_mounts.pop().unwrap();
        assert!(recovered.check_guarded_mounts().is_err());
        recovered.guarded_mounts.push(unsupervised);
        let revision_id = Uuid::new_v4();
        let capture = recovered
            .capture_claimed_guarded_view_for_revision(manifest.anchor_id, revision_id)
            .unwrap();
        capture.verify().unwrap();
        let private = crate::GuardedPrivateMetadataV6::from_capture(&capture, |file| {
            Ok(file
                .data_extents
                .iter()
                .map(|extent| crate::PrivateDataExtent {
                    offset: extent.offset,
                    logical_len: extent.logical_len,
                    sectors: vec![SectorRef {
                        id: [7; 32],
                        root: [8; 32],
                        logical_len: u32::try_from(extent.logical_len).unwrap(),
                    }],
                })
                .collect())
        })
        .unwrap();
        assert_eq!(private.format_version, 6);
        assert_eq!(private.root.uid, 65534);
        assert!(matches!(
            private.entries.as_slice(),
            [crate::GuardedPrivateEntryV6::File { path, .. }] if path == b"sample"
        ));
        assert_eq!(capture.files.len(), 1);
        assert_eq!(capture.files[0].path, b"sample");
        let mut captured_bytes = Vec::new();
        capture.files[0]
            .locator
            .open()
            .unwrap()
            .read_to_end(&mut captured_bytes)
            .unwrap();
        assert_eq!(captured_bytes, fs::read(lower.join("sample")).unwrap());
        let guild_id = [223; 32];
        let protected_root_id = Uuid::new_v4();
        let writer_secret = [224; 32];
        let keys = Arc::clone(&recovered.keys);
        let sign = |control: &mut ControlStore| {
            crate::snapshot::prepare_guarded_revision(
                control,
                &keys,
                guild_id,
                protected_root_id,
                manifest.anchor_id,
                1,
                revision_id,
                WriterCredentials {
                    epoch: 1,
                    secret: &writer_secret,
                    captured_change_sequence: None,
                },
            )
        };
        let signed = sign(&mut recovered.control).unwrap();
        assert_eq!(sign(&mut recovered.control).unwrap(), signed);
        assert!(
            GuardedViewMount::published_stopped_capture_attempt(
                manifest.anchor_id,
                revision_id,
                &recovered.control,
            )
            .is_err()
        );
        assert_eq!(
            GuardedViewMount::load_revision_capture(revision_id, &recovered.control)
                .unwrap()
                .unwrap()
                .capture,
            capture
        );
        let restored = area.path().join("restored");
        crate::snapshot::restore_revision_from_source(
            &recovered.control,
            &keys,
            guild_id,
            &signed,
            &restored,
            |id| crate::snapshot::render_sector(&recovered.control, &keys, id, Some(&guild_id)),
        )
        .unwrap();
        assert_eq!(fs::read(restored.join("sample")).unwrap(), captured_bytes);
        if std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").is_some() {
            let ciphertexts = signed
                .value
                .metadata_sectors
                .iter()
                .chain(&signed.value.data_sectors)
                .map(|reference| {
                    (
                        reference.clone(),
                        crate::snapshot::render_sector(
                            &recovered.control,
                            &keys,
                            &reference.id,
                            Some(&guild_id),
                        )
                        .unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            let mut seed_only = Node::open(
                area.path().join("seed-only-node"),
                Seed::from_bytes([241; 32]),
            )
            .unwrap();
            for (reference, ciphertext) in ciphertexts {
                crate::snapshot::install_recovered_sector_recipe(
                    &mut seed_only.control,
                    &keys,
                    guild_id,
                    reference,
                    &ciphertext,
                )
                .unwrap();
            }
            let checkpoint_hash = [242; 32];
            let seed_target = area.path().join("seed-recovered");
            seed_only
                .restore_recovered_revision(&checkpoint_hash, guild_id, &signed, &seed_target)
                .unwrap();
            assert_eq!(
                fs::read(seed_target.join("sample")).unwrap(),
                captured_bytes
            );
            for reference in &signed.value.data_sectors {
                assert!(
                    crate::snapshot::recovered_recipe_is_stable(
                        &seed_only.control,
                        &keys,
                        guild_id,
                        reference,
                    )
                    .unwrap()
                );
            }
            assert_eq!(
                seed_only
                    .protected_root_by_id(protected_root_id)
                    .unwrap()
                    .path,
                seed_target
            );
            drop(seed_only);
            let mut seed_only = Node::open(
                area.path().join("seed-only-node"),
                Seed::from_bytes([241; 32]),
            )
            .unwrap();
            seed_only
                .restore_recovered_revision(&checkpoint_hash, guild_id, &signed, &seed_target)
                .unwrap();
        }
        recovered.check_guarded_mounts().unwrap();
        assert!(fs::read(view.join("sample")).unwrap().starts_with(b"EDIT"));
        recovered.guarded_mounts.pop().unwrap().stop().unwrap();
        let guarded_control = Arc::new(Mutex::new(
            ControlStore::open_with_key(data_dir.join("control.db"), &database_key).unwrap(),
        ));
        let captured_file = GuardedViewMount::capture_stopped_file(
            manifest.anchor_id,
            Arc::clone(&guarded_control),
            "sample",
        )
        .unwrap();
        drop(guarded_control);
        drop(recovered);

        let mut control =
            ControlStore::open_with_key(data_dir.join("control.db"), &database_key).unwrap();
        assert!(GuardedViewMount::retire_claim(manifest.anchor_id, &control).is_err());
        let file_plan =
            mb_store::GuardedFileCapturePlan::load_for_manifest(&control, &captured_file)
                .unwrap()
                .unwrap();
        assert!(file_plan.discard_unreferenced(&control).is_err());
        assert!(!retire_revision_anchor(&mut control, revision_id).unwrap());
        control
            .delete_record("user-revision", revision_id.as_bytes())
            .unwrap();
        assert!(!retire_revision_anchor(&mut control, revision_id).unwrap());
        let retained_recipe_id = signed.value.data_sectors[0].id;
        let retained_recipe = control
            .get_record("local-sector", &retained_recipe_id)
            .unwrap()
            .unwrap();
        for reference in signed
            .value
            .metadata_sectors
            .iter()
            .chain(&signed.value.data_sectors)
        {
            control
                .delete_record("local-sector", &reference.id)
                .unwrap();
        }
        assert!(retire_revision_anchor(&mut control, revision_id).unwrap());
        assert!(
            GuardedViewMount::load_revision_capture(revision_id, &control)
                .unwrap()
                .is_none()
        );
        assert!(file_plan.discard_unreferenced(&control).is_err());
        control
            .delete_record(
                "user-revision-head",
                &crate::snapshot::revision_head_id(guild_id, protected_root_id),
            )
            .unwrap();
        drop(control);
        let control =
            ControlStore::open_with_key(data_dir.join("control.db"), &database_key).unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &control).unwrap();
        control
            .put_record("local-sector", &retained_recipe_id, &retained_recipe)
            .unwrap();
        let pinned = git_prune_recipe_anchor_ids(&control).unwrap();
        assert!(pinned.contains(&file_plan.anchor_id()));
        reconcile_pending_captures(&control).unwrap();
        assert!(
            control
                .get_record("guarded-file-plan-v1", file_plan.anchor_id().as_bytes())
                .unwrap()
                .is_some()
        );
        control
            .delete_record("local-sector", &retained_recipe_id)
            .unwrap();
        reconcile_pending_captures(&control).unwrap();
        assert!(
            control
                .get_record("guarded-file-plan-v1", file_plan.anchor_id().as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            control
                .get_record("guarded-root-plan-v1", plan.anchor_id().as_bytes())
                .unwrap()
                .is_none()
        );
    }
}
