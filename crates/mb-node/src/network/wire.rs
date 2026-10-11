use mb_core::{
    CodingAttemptPlan, CodingChallengeCommitment, CodingChallengeReveal, CodingFailureReport,
    CodingGroup, CodingRootManifest, CodingShardOpening, CodingVerificationTranscript,
    EndpointRecord, GuildEvent, GuildEventTail, GuildGenesis, GuildInvite,
    LegacyPackingAttestation, LegacyPackingBinding, Member, MemberSignature, MerkleCommitment,
    MerkleRangeProof, NodeId, QuorumGuildEvent, QuorumGuildGenesis, QuorumLegacyCodingAddBinding,
    SectorId, SectorRef, SignedRecord, StagedStorageReceipt, StorageAcknowledgement,
};
use mb_store::{ParityObject, VariableParityObject};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{BackupDescriptor, BackupJob, GuildPeer};
#[cfg(test)]
use super::{PublishedRecoveryRecord, RecoveryPublisherAdmission};
use crate::WireError;

pub(super) const PEER_WIRE_FORMAT_VERSION: u16 = 2;
pub(super) const MAX_CODING_PATH_TARGETS: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PeerProfile {
    pub(super) member: Member,
    pub(super) endpoint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct CheckpointHead {
    pub(super) generation: u64,
    pub(super) hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub(super) enum CodingPathClass {
    Direct,
    Relay,
    Tor,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct CodingPathEntry {
    pub(super) target: NodeId,
    pub(super) path: Option<CodingPathClass>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct CodingPathObservation {
    pub(super) observed_at_unix_seconds: u64,
    pub(super) paths: Vec<CodingPathEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum PeerRequest {
    Profile,
    CodingPathObservation {
        guild_id: [u8; 32],
        targets: Vec<NodeId>,
    },
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
    GetGuildEventTail {
        guild_id: [u8; 32],
        base_sequence: u64,
        base_head: [u8; 32],
    },
    SignGuildEvent {
        event: Box<GuildEvent>,
    },
    InstallGuildEvent {
        certified: Box<QuorumGuildEvent>,
    },
    SignCodingGroupEvent {
        event: Box<GuildEvent>,
        transcript: Box<SignedRecord<CodingVerificationTranscript>>,
    },
    InstallCodingGroupEvent {
        certified: Box<QuorumGuildEvent>,
        transcript: Box<SignedRecord<CodingVerificationTranscript>>,
    },
    GetCodingTranscript {
        guild_id: [u8; 32],
        group_id: [u8; 32],
    },
    GetCodingTranscriptForEvent {
        guild_id: [u8; 32],
        group_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
    },
    ExchangeEndpoints {
        guild_id: [u8; 32],
    },
    #[cfg(test)]
    BeginCommit {
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
    },
    #[cfg(test)]
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
    GetSectorRange {
        guild_id: [u8; 32],
        sector_id: SectorId,
        start_leaf: u32,
        leaf_count: u32,
    },
    PublishParity {
        operation_id: [u8; 16],
        group: Box<CodingGroup>,
        information: [Vec<u8>; 3],
        object: ParityObject,
    },
    StageCodingParity {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        manifest: Box<SignedRecord<CodingRootManifest>>,
        object: VariableParityObject,
    },
    ReserveCodingInformation {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        shard_index: u16,
    },
    UploadCodingInformationRange {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        shard_index: u16,
        offset: u32,
        bytes: Vec<u8>,
    },
    FinalizeCodingInformation {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        shard_index: u16,
    },
    GetCodingInformationRange {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        shard_index: u16,
        start_leaf: u32,
        leaf_count: u32,
    },
    ReserveCodingParity {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        shard_index: u16,
    },
    UploadCodingParityRange {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        manifest: Box<SignedRecord<CodingRootManifest>>,
        shard_index: u16,
        offset: u32,
        bytes: Vec<u8>,
    },
    FinalizeCodingParity {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        manifest: Box<SignedRecord<CodingRootManifest>>,
        shard_index: u16,
    },
    DelegateCodingAttempt {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
    },
    CommitCodingChallenge {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
    },
    RevealCodingChallenge {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        manifest: Box<SignedRecord<CodingRootManifest>>,
        receipts: Vec<SignedRecord<StagedStorageReceipt>>,
    },
    GetCodingOpening {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
        manifest: Box<SignedRecord<CodingRootManifest>>,
        challenge: [u8; 32],
        shard_index: u16,
    },
    FinalizeCodingVerification {
        transcript: Box<CodingVerificationTranscript>,
    },
    SubmitCodingTranscript {
        transcript: Box<SignedRecord<CodingVerificationTranscript>>,
    },
    SubmitCodingFailure {
        failure: Box<SignedRecord<CodingFailureReport>>,
    },
    ActivateCodingParity {
        transcript: Box<SignedRecord<CodingVerificationTranscript>>,
    },
    AbortCodingAttempt {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
    },
    GetParity {
        guild_id: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
    },
    GetVariableShard {
        guild_id: [u8; 32],
        group_id: [u8; 32],
        shard_index: u16,
    },
    GetVariableEmergencyShard {
        guild_id: [u8; 32],
        group_id: [u8; 32],
        shard_index: u16,
    },
    StoreRepairShard {
        repair_id: [u8; 16],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
        emergency: bool,
        bytes: Vec<u8>,
    },
    StoreVariableRepairShard {
        repair_id: [u8; 16],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        group_id: [u8; 32],
        shard_index: u16,
        emergency: bool,
        bytes: Vec<u8>,
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
    GetCheckpointHead {
        guild_id: [u8; 32],
    },
    SignLegacyPackingBinding {
        guild_id: [u8; 32],
        protected_root_id: Uuid,
        reference: SectorRef,
    },
    #[cfg(test)]
    BuildRecoveryRecord {
        publication_id: [u8; 16],
        subject: Member,
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        checkpoint_generation: u64,
        expires_at_unix_seconds: u64,
        admission: Box<SignedRecord<RecoveryPublisherAdmission>>,
    },
    #[cfg(test)]
    AuthorizeRecoveryPublisher {
        guild_id: [u8; 32],
        publisher: NodeId,
        expires_at_unix_seconds: u64,
    },
    #[cfg(test)]
    CompleteCommit {
        intent_id: [u8; 16],
        plan_hash: [u8; 32],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
    },
    GetSectorCommitment {
        guild_id: [u8; 32],
        sector_id: SectorId,
    },
    CodingCapacity {
        guild_id: [u8; 32],
        shard_size: u32,
    },
    AttestLegacyPackingSource {
        attestation: LegacyPackingAttestation,
        bytes: Vec<u8>,
    },
    GetCheckpointAtGeneration {
        guild_id: [u8; 32],
        generation: u64,
    },
    RetireCodingAttempt {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
    },
    GetCodingAttemptRetirement {
        plan: Box<SignedRecord<CodingAttemptPlan>>,
    },
    AttestLegacyCodingAdd {
        guild_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
        transcript_hash: [u8; 32],
    },
    GetLegacyCodingAddBinding {
        guild_id: [u8; 32],
        event_sequence: u64,
        event_hash: [u8; 32],
    },
    GetRetainedPagedCheckpointCertificate {
        guild_id: [u8; 32],
        layout: mb_core::PagedCheckpointLayout,
        owner_id: Uuid,
        checkpoint_hash: [u8; 32],
    },
    GetRetainedPagedCheckpointPage {
        guild_id: [u8; 32],
        layout: mb_core::PagedCheckpointLayout,
        owner_id: Uuid,
        checkpoint_hash: [u8; 32],
        path: mb_core::CatalogPagePath,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub(crate) enum CheckpointObjectKind {
    Body,
    Certificate,
}

impl CheckpointObjectKind {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Body => "body",
            Self::Certificate => "certificate",
        }
    }
}

impl PeerRequest {
    pub(super) fn is_writer_read(&self) -> bool {
        matches!(self, Self::GetCodingAttemptRetirement { .. })
    }

    pub(super) fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::Profile
                | Self::CodingPathObservation { .. }
                | Self::GetSector { .. }
                | Self::GetSectorRange { .. }
                | Self::GetSectorCommitment { .. }
                | Self::GetParity { .. }
                | Self::GetVariableShard { .. }
                | Self::GetVariableEmergencyShard { .. }
                | Self::GetPreparedRevisionPage { .. }
                | Self::GetCheckpointPage { .. }
                | Self::GetCheckpointHead { .. }
                | Self::GetCheckpointAtGeneration { .. }
                | Self::SignLegacyPackingBinding { .. }
                | Self::BackupStatus { .. }
                | Self::GetGuildGenesis { .. }
                | Self::GetGuildEventTail { .. }
                | Self::GetCodingTranscript { .. }
                | Self::GetCodingTranscriptForEvent { .. }
                | Self::GetLegacyCodingAddBinding { .. }
                | Self::GetRetainedPagedCheckpointCertificate { .. }
                | Self::GetRetainedPagedCheckpointPage { .. }
                | Self::ExchangeEndpoints { .. }
                | Self::CodingCapacity { .. }
        )
    }

    pub(super) fn mutation_kind(&self) -> Option<&'static str> {
        match self {
            Self::GetCodingAttemptRetirement { .. }
            | Self::Profile
            | Self::CodingPathObservation { .. }
            | Self::GetSector { .. }
            | Self::GetSectorRange { .. }
            | Self::GetSectorCommitment { .. }
            | Self::GetParity { .. }
            | Self::GetVariableShard { .. }
            | Self::GetVariableEmergencyShard { .. }
            | Self::GetPreparedRevisionPage { .. }
            | Self::GetCheckpointPage { .. }
            | Self::GetCheckpointAtGeneration { .. }
            | Self::BackupStatus { .. }
            | Self::GetGuildGenesis { .. }
            | Self::GetGuildEventTail { .. }
            | Self::GetCodingTranscript { .. }
            | Self::GetCodingTranscriptForEvent { .. }
            | Self::GetLegacyCodingAddBinding { .. }
            | Self::GetRetainedPagedCheckpointCertificate { .. }
            | Self::GetRetainedPagedCheckpointPage { .. }
            | Self::ExchangeEndpoints { .. }
            | Self::CodingCapacity { .. } => None,
            #[cfg(test)]
            Self::BeginCommit { .. } => Some("begin-commit"),
            Self::JoinGuild { .. } => Some("join-guild"),
            Self::ProposeGuildGenesis { .. } => Some("propose-guild-genesis"),
            Self::InstallGuildGenesis { .. } => Some("install-guild-genesis"),
            Self::SignGuildEvent { .. } => Some("sign-guild-event"),
            Self::InstallGuildEvent { .. } => Some("install-guild-event"),
            Self::SignCodingGroupEvent { .. } => Some("sign-coding-group-event"),
            Self::InstallCodingGroupEvent { .. } => Some("install-coding-group-event"),
            Self::AttestLegacyCodingAdd { .. } => Some("attest-legacy-coding-add"),
            Self::SubmitBackup { .. } => Some("submit-backup"),
            #[cfg(test)]
            Self::PrepareSource { .. } => Some("prepare-source"),
            Self::EnsureFiller { .. } => Some("ensure-filler"),
            Self::PublishParity { .. } => Some("publish-parity"),
            Self::StageCodingParity { .. } => Some("stage-coding-parity"),
            Self::ReserveCodingInformation { .. } => Some("reserve-coding-information"),
            Self::UploadCodingInformationRange { .. } => Some("upload-coding-information-range"),
            Self::FinalizeCodingInformation { .. } => Some("finalize-coding-information"),
            Self::GetCodingInformationRange { .. } => Some("get-coding-information-range"),
            Self::ReserveCodingParity { .. } => Some("reserve-coding-parity"),
            Self::UploadCodingParityRange { .. } => Some("upload-coding-parity-range"),
            Self::FinalizeCodingParity { .. } => Some("finalize-coding-parity"),
            Self::DelegateCodingAttempt { .. } => Some("delegate-coding-attempt"),
            Self::CommitCodingChallenge { .. } => Some("commit-coding-challenge"),
            Self::RevealCodingChallenge { .. } => Some("reveal-coding-challenge"),
            Self::GetCodingOpening { .. } => Some("get-coding-opening"),
            Self::FinalizeCodingVerification { .. } => Some("finalize-coding-verification"),
            Self::SubmitCodingTranscript { .. } => Some("submit-coding-transcript"),
            Self::SubmitCodingFailure { .. } => Some("submit-coding-failure"),
            Self::ActivateCodingParity { .. } => Some("activate-coding-parity"),
            Self::AbortCodingAttempt { .. } => Some("abort-coding-attempt"),
            Self::RetireCodingAttempt { .. } => Some("retire-coding-attempt"),
            Self::StoreRepairShard { .. } => Some("store-repair-shard"),
            Self::StoreVariableRepairShard { .. } => Some("store-variable-repair-shard"),
            Self::PutCheckpointPage { .. } => Some("put-checkpoint-page"),
            Self::SignCheckpoint { .. } => Some("sign-checkpoint"),
            Self::FinalizeCheckpoint { .. } => Some("finalize-checkpoint"),
            Self::GetCheckpointHead { .. } => Some("get-checkpoint-head"),
            Self::SignLegacyPackingBinding { .. } => Some("sign-legacy-packing-binding"),
            Self::AttestLegacyPackingSource { .. } => Some("attest-legacy-packing-source"),
            #[cfg(test)]
            Self::BuildRecoveryRecord { .. } => Some("build-recovery-record"),
            #[cfg(test)]
            Self::AuthorizeRecoveryPublisher { .. } => Some("authorize-recovery-publisher"),
            #[cfg(test)]
            Self::CompleteCommit { .. } => Some("complete-commit"),
        }
    }

    pub(super) fn guild_scope(&self) -> Option<[u8; 32]> {
        match self {
            Self::Profile => None,
            Self::CodingPathObservation { guild_id, .. } => Some(*guild_id),
            #[cfg(test)]
            Self::BeginCommit { .. } => None,
            Self::JoinGuild { invite, .. } => Some(invite.value.guild_id),
            Self::ProposeGuildGenesis { genesis } => Some(genesis.guild_id),
            Self::InstallGuildGenesis { certificate, .. } => Some(certificate.genesis.guild_id),
            Self::SubmitBackup { descriptor } => Some(descriptor.guild_id),
            Self::GetPreparedRevisionPage { guild_id, .. }
            | Self::EnsureFiller { guild_id, .. }
            | Self::GetSector { guild_id, .. }
            | Self::GetSectorRange { guild_id, .. }
            | Self::GetSectorCommitment { guild_id, .. }
            | Self::GetParity { guild_id, .. }
            | Self::GetVariableShard { guild_id, .. }
            | Self::GetVariableEmergencyShard { guild_id, .. }
            | Self::StoreRepairShard { guild_id, .. }
            | Self::StoreVariableRepairShard { guild_id, .. }
            | Self::PutCheckpointPage { guild_id, .. }
            | Self::SignCheckpoint { guild_id, .. }
            | Self::FinalizeCheckpoint { guild_id, .. }
            | Self::GetCheckpointPage { guild_id, .. }
            | Self::GetCheckpointHead { guild_id }
            | Self::GetCheckpointAtGeneration { guild_id, .. }
            | Self::GetRetainedPagedCheckpointCertificate { guild_id, .. }
            | Self::GetRetainedPagedCheckpointPage { guild_id, .. }
            | Self::SignLegacyPackingBinding { guild_id, .. }
            | Self::BackupStatus { guild_id, .. } => Some(*guild_id),
            Self::AttestLegacyPackingSource { attestation, .. } => Some(attestation.guild_id),
            Self::AbortCodingAttempt { plan }
            | Self::RetireCodingAttempt { plan }
            | Self::GetCodingAttemptRetirement { plan } => Some(plan.value.geometry.guild_id),
            Self::ExchangeEndpoints { guild_id } | Self::CodingCapacity { guild_id, .. } => {
                Some(*guild_id)
            }
            #[cfg(test)]
            Self::PrepareSource { guild_id, .. }
            | Self::CompleteCommit { guild_id, .. }
            | Self::BuildRecoveryRecord { guild_id, .. }
            | Self::AuthorizeRecoveryPublisher { guild_id, .. } => Some(*guild_id),
            Self::GetGuildGenesis { guild_id } => Some(*guild_id),
            Self::GetGuildEventTail { guild_id, .. } => Some(*guild_id),
            Self::SignGuildEvent { event } => Some(event.guild_id),
            Self::InstallGuildEvent { certified } => Some(certified.event.guild_id),
            Self::SignCodingGroupEvent { event, .. } => Some(event.guild_id),
            Self::InstallCodingGroupEvent { certified, .. } => Some(certified.event.guild_id),
            Self::GetCodingTranscript { guild_id, .. }
            | Self::GetCodingTranscriptForEvent { guild_id, .. }
            | Self::GetLegacyCodingAddBinding { guild_id, .. }
            | Self::AttestLegacyCodingAdd { guild_id, .. } => Some(*guild_id),
            Self::PublishParity { object, .. } => Some(object.guild_id),
            Self::StageCodingParity { plan, .. }
            | Self::ReserveCodingInformation { plan, .. }
            | Self::UploadCodingInformationRange { plan, .. }
            | Self::FinalizeCodingInformation { plan, .. }
            | Self::GetCodingInformationRange { plan, .. }
            | Self::ReserveCodingParity { plan, .. }
            | Self::UploadCodingParityRange { plan, .. }
            | Self::FinalizeCodingParity { plan, .. }
            | Self::DelegateCodingAttempt { plan }
            | Self::GetCodingOpening { plan, .. }
            | Self::CommitCodingChallenge { plan }
            | Self::RevealCodingChallenge { plan, .. } => Some(plan.value.geometry.guild_id),
            Self::ActivateCodingParity { transcript } => {
                Some(transcript.value.plan.value.geometry.guild_id)
            }
            Self::FinalizeCodingVerification { transcript } => {
                Some(transcript.plan.value.geometry.guild_id)
            }
            Self::SubmitCodingTranscript { transcript } => {
                Some(transcript.value.plan.value.geometry.guild_id)
            }
            Self::SubmitCodingFailure { failure } => {
                Some(failure.value.plan.value.geometry.guild_id)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PeerRequestEnvelope {
    pub(super) format_version: u16,
    pub(super) request_id: [u8; 16],
    pub(super) caller: NodeId,
    pub(super) recipient: Option<NodeId>,
    pub(super) guild_scope: Option<[u8; 32]>,
    pub(super) issued_at_unix_seconds: u64,
    pub(super) expires_at_unix_seconds: u64,
    pub(super) request: PeerRequest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum PeerResponse {
    Profile(PeerProfile),
    CodingPathObservation(CodingPathObservation),
    #[cfg(test)]
    CommitStarted {
        guild_id: [u8; 32],
    },
    #[cfg(test)]
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
    MerkleRange(MerkleRangeProof),
    CheckpointSignature(MemberSignature),
    GuildGenesisSignature(MemberSignature),
    GuildEventSignature(MemberSignature),
    BackupJob(BackupJob),
    StorageAcknowledgement(SignedRecord<StorageAcknowledgement>),
    StagedStorageReceipt(SignedRecord<StagedStorageReceipt>),
    CodingRangeProgress {
        written_until: u32,
    },
    CodingChallengeCommitment(SignedRecord<CodingChallengeCommitment>),
    CodingChallengeReveal(SignedRecord<CodingChallengeReveal>),
    CodingShardOpening(SignedRecord<CodingShardOpening>),
    CodingVerificationTranscript(Box<SignedRecord<CodingVerificationTranscript>>),
    GuildGenesis(Box<QuorumGuildGenesis>),
    GuildEventTail(Box<GuildEventTail>),
    EndpointRecords(Vec<SignedRecord<EndpointRecord>>),
    CheckpointPage {
        total_pages: u32,
        page_hash: [u8; 32],
        bytes: Vec<u8>,
    },
    CheckpointHead(Option<CheckpointHead>),
    LegacyPackingBinding(SignedRecord<LegacyPackingBinding>),
    #[cfg(test)]
    RecoveryRecord(Box<SignedRecord<PublishedRecoveryRecord>>),
    #[cfg(test)]
    RecoveryAdmission(SignedRecord<RecoveryPublisherAdmission>),
    Ack,
    MerkleCommitment(MerkleCommitment),
    CodingCapacity {
        available_shards: u64,
    },
    LegacyPackingAttestation(SignedRecord<LegacyPackingAttestation>),
    CodingAttemptRetired {
        retired: bool,
    },
    LegacyCodingAddAttestation(MemberSignature),
    LegacyCodingAddBinding(Option<QuorumLegacyCodingAddBinding>),
    RetainedPagedCheckpointCertificate {
        #[serde(deserialize_with = "certificate_bytes")]
        bytes: Vec<u8>,
    },
    RetainedPagedCheckpointPage {
        #[serde(deserialize_with = "page_bytes")]
        bytes: Vec<u8>,
    },
}

fn certificate_bytes<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    bounded_bytes::<D, { mb_core::PAGED_QUORUM_CHECKPOINT_BYTES }>(decoder)
}

fn page_bytes<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    bounded_bytes::<D, { mb_core::CATALOG_PAGE_BYTES }>(decoder)
}

fn bounded_bytes<'de, D: serde::Deserializer<'de>, const LIMIT: usize>(
    decoder: D,
) -> Result<Vec<u8>, D::Error> {
    use serde::de::{Error, SeqAccess, Visitor};
    struct Bytes<const LIMIT: usize>;
    impl<'de, const LIMIT: usize> Visitor<'de> for Bytes<LIMIT> {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {LIMIT} bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            if seq.size_hint().is_some_and(|size| size > LIMIT) {
                return Err(A::Error::custom("oversized paged checkpoint response"));
            }
            let mut bytes = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(64));
            while bytes.len() < LIMIT {
                match seq.next_element()? {
                    Some(byte) => bytes.push(byte),
                    None => return Ok(bytes),
                }
            }
            struct Extra;
            impl<'de> serde::de::DeserializeSeed<'de> for Extra {
                type Value = ();
                fn deserialize<E: serde::Deserializer<'de>>(self, _: E) -> Result<(), E::Error> {
                    Err(E::Error::custom("oversized paged checkpoint response"))
                }
            }
            seq.next_element_seed(Extra)?;
            Ok(bytes)
        }
    }
    decoder.deserialize_seq(Bytes::<LIMIT>)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PeerResponseEnvelope {
    pub(super) format_version: u16,
    pub(super) request_id: [u8; 16],
    pub(super) recipient: NodeId,
    pub(super) request_hash: [u8; 32],
    pub(super) result: Result<PeerResponse, WireError>,
}

fn budget_signed<T>(value: T) -> SignedRecord<T> {
    SignedRecord {
        signer: NodeId([255; 32]),
        value,
        signature: vec![255; 64],
    }
}

fn budget_request(request: PeerRequest) -> SignedRecord<PeerRequestEnvelope> {
    budget_signed(PeerRequestEnvelope {
        format_version: PEER_WIRE_FORMAT_VERSION,
        request_id: [255; 16],
        caller: NodeId([255; 32]),
        recipient: Some(NodeId([255; 32])),
        guild_scope: Some([255; 32]),
        issued_at_unix_seconds: u64::MAX,
        expires_at_unix_seconds: u64::MAX,
        request,
    })
}

fn budget_response(response: PeerResponse) -> SignedRecord<PeerResponseEnvelope> {
    budget_signed(PeerResponseEnvelope {
        format_version: PEER_WIRE_FORMAT_VERSION,
        request_id: [255; 16],
        recipient: NodeId([255; 32]),
        request_hash: [255; 32],
        result: Ok(response),
    })
}

fn frame_sizes<T: Serialize>(value: &T) -> anyhow::Result<(usize, usize)> {
    Ok((
        mb_core::canonical_bytes(value)?.len(),
        cbor4ii::serde::to_vec(Vec::new(), value)
            .map_err(|error| anyhow::anyhow!("CBOR frame accounting failed: {error}"))?
            .len(),
    ))
}

/// A u8 sequence uses at most two CBOR bytes per element. Include the largest
/// signed envelope and reserve length-prefix growth before choosing a range.
pub(super) fn coding_parity_range_bytes(
    plan: &SignedRecord<CodingAttemptPlan>,
    manifest: &SignedRecord<CodingRootManifest>,
) -> anyhow::Result<usize> {
    let (tcp, cbor) = frame_sizes(&budget_request(PeerRequest::UploadCodingParityRange {
        plan: Box::new(plan.clone()),
        manifest: Box::new(manifest.clone()),
        shard_index: u16::MAX,
        offset: u32::MAX,
        bytes: Vec::new(),
    }))?;
    let limit = super::MAX_PEER_FRAME_BYTES;
    let bytes = limit
        .saturating_sub(tcp.saturating_add(8))
        .min(limit.saturating_sub(cbor.saturating_add(8)) / 2)
        .min(256 * 1024);
    let bytes = bytes / mb_core::MERKLE_LEAF_SIZE * mb_core::MERKLE_LEAF_SIZE;
    if bytes < mb_core::MERKLE_LEAF_SIZE {
        anyhow::bail!("coding evidence leaves no peer-frame space for a parity range");
    }
    Ok(bytes)
}

/// Verify the worst serialized control evidence before accepting new flat-root
/// work. Empty byte strings stand in for the witness: add its known byte count
/// and conservative length-prefix growth without allocating ciphertext here.
pub(crate) fn validate_root_binding_frame_budget(
    plan: &CodingAttemptPlan,
    member_count: usize,
) -> anyhow::Result<()> {
    if plan.format_version != 3 {
        return Ok(());
    }
    use mb_core::{CodingGroupV2, MERKLE_LEAF_SIZE, ParityRoleV2, ShardRoleV2};
    let profile = plan.geometry.profile;
    let mut plan = plan.clone();
    plan.attempt_id = [255; 16];
    plan.checkpoint_hash = [255; 32];
    plan.membership_epoch = u64::MAX;
    plan.expires_at_unix_seconds = u64::MAX;
    plan.delegator = NodeId([255; 32]);
    plan.coding_coordinator = NodeId([255; 32]);
    plan.verification_coordinator = NodeId([255; 32]);
    for info in &mut plan.geometry.information {
        info.owner = NodeId([255; 32]);
        info.sector.id = [255; 32];
        info.sector.commitment.root = [255; 32];
    }
    for parity in &mut plan.geometry.parity {
        parity.holder = NodeId([255; 32]);
    }
    plan.information_roots = Some(vec![[255; 32]; usize::from(profile.data_shards)]);
    let mut roles = plan
        .geometry
        .information
        .iter()
        .cloned()
        .map(ShardRoleV2::Information)
        .collect::<Vec<_>>();
    let commitment = MerkleCommitment {
        format_version: 1,
        leaf_size: MERKLE_LEAF_SIZE as u16,
        byte_len: profile.shard_size,
        root: [255; 32],
    };
    roles.extend(plan.geometry.parity.iter().map(|parity| {
        ShardRoleV2::Parity(ParityRoleV2 {
            holder: parity.holder,
            failure_domain: parity.failure_domain.clone(),
            row: parity.row,
            commitment: commitment.clone(),
        })
    }));
    let group = CodingGroupV2 {
        id: [255; 32],
        format_version: 3,
        guild_id: [255; 32],
        profile,
        roles,
    };
    let information_bytes = plan
        .geometry
        .information
        .iter()
        .map(|info| (!info.sector.virtual_zero).then(Vec::new))
        .collect::<Vec<_>>();
    let witness = information_bytes
        .iter()
        .filter(|bytes| bytes.is_some())
        .count()
        * (profile.shard_size as usize + 8);
    let manifest = budget_signed(CodingRootManifest {
        format_version: 3,
        attempt_id: [255; 16],
        plan_hash: [255; 32],
        group,
        information_bytes: Some(information_bytes),
    });
    let plan = budget_signed(plan);
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
            Some(budget_signed(StagedStorageReceipt {
                format_version: 1,
                attempt_id: [255; 16],
                plan_hash: [255; 32],
                guild_id: [255; 32],
                group_id: [255; 32],
                shard_index: index as u16,
                holder: parity.holder,
                commitment: parity.commitment.clone(),
            }))
        })
        .collect::<Vec<_>>();
    let openings = manifest
        .value
        .group
        .roles
        .iter()
        .enumerate()
        .map(|(index, _)| {
            budget_signed(CodingShardOpening {
                format_version: 1,
                attempt_id: [255; 16],
                plan_hash: [255; 32],
                verifier: NodeId([255; 32]),
                challenge: [255; 32],
                shard_index: index as u16,
                commitment: commitment.clone(),
                proof: MerkleRangeProof {
                    format_version: 1,
                    start_leaf: u32::MAX,
                    leaves: vec![[255; MERKLE_LEAF_SIZE]],
                    siblings: vec![
                        [255; 32];
                        (profile.shard_size as usize / MERKLE_LEAF_SIZE).ilog2() as usize
                    ],
                },
            })
        })
        .collect();
    let transcript = budget_signed(CodingVerificationTranscript {
        format_version: 1,
        verified_at_unix_seconds: u64::MAX,
        plan: plan.clone(),
        manifest: manifest.clone(),
        challenge_commitment: budget_signed(CodingChallengeCommitment {
            format_version: 1,
            attempt_id: [255; 16],
            plan_hash: [255; 32],
            commitment: [255; 32],
        }),
        staged_receipts: receipts.clone(),
        challenge_reveal: budget_signed(CodingChallengeReveal {
            format_version: 1,
            attempt_id: [255; 16],
            plan_hash: [255; 32],
            nonce: [255; 32],
            evidence_hash: [255; 32],
        }),
        openings,
    });
    let event = GuildEvent {
        format_version: 2,
        guild_id: [255; 32],
        sequence: u64::MAX,
        parent: [255; 32],
        kind: mb_core::GuildEventKind::AddCodingGroupBound {
            group: manifest.value.group.clone(),
            transcript_hash: [255; 32],
        },
    };
    for request in [
        PeerRequest::UploadCodingParityRange {
            plan: Box::new(plan.clone()),
            manifest: Box::new(manifest.clone()),
            shard_index: u16::MAX,
            offset: u32::MAX,
            bytes: vec![255; MERKLE_LEAF_SIZE],
        },
        PeerRequest::RevealCodingChallenge {
            plan: Box::new(plan.clone()),
            manifest: Box::new(manifest.clone()),
            receipts,
        },
        PeerRequest::SubmitCodingTranscript {
            transcript: Box::new(transcript.clone()),
        },
        PeerRequest::ActivateCodingParity {
            transcript: Box::new(transcript.clone()),
        },
        PeerRequest::FinalizeCodingVerification {
            transcript: Box::new(transcript.value.clone()),
        },
        PeerRequest::SignCodingGroupEvent {
            event: Box::new(event.clone()),
            transcript: Box::new(transcript.clone()),
        },
        PeerRequest::InstallCodingGroupEvent {
            certified: Box::new(QuorumGuildEvent {
                event,
                signatures: vec![
                    MemberSignature {
                        signer: NodeId([255; 32]),
                        signature: vec![255; 64]
                    };
                    member_count
                ],
            }),
            transcript: Box::new(transcript.clone()),
        },
    ] {
        let (tcp, cbor) = frame_sizes(&budget_request(request))?;
        if tcp.max(cbor).saturating_add(witness) > super::MAX_PEER_FRAME_BYTES {
            anyhow::bail!("full-byte coding evidence exceeds a containing peer frame");
        }
    }
    let (tcp, cbor) = frame_sizes(&budget_response(
        PeerResponse::CodingVerificationTranscript(Box::new(transcript)),
    ))?;
    if tcp.max(cbor).saturating_add(witness) > super::MAX_PEER_FRAME_BYTES {
        anyhow::bail!("full-byte coding transcript exceeds the peer response frame");
    }
    Ok(())
}

pub(super) fn bound_peer_event_tail(mut tail: GuildEventTail) -> anyhow::Result<GuildEventTail> {
    let mut low = 0;
    let mut high = tail.events.len();
    while low < high {
        let count = low + (high - low).div_ceil(2);
        let mut prefix = tail.clone();
        prefix.events.truncate(count);
        let (tcp, cbor) = frame_sizes(&budget_response(PeerResponse::GuildEventTail(Box::new(
            prefix,
        ))))?;
        if tcp.max(cbor) <= super::MAX_PEER_FRAME_BYTES {
            low = count;
        } else {
            high = count - 1;
        }
    }
    if low == 0 && !tail.events.is_empty() {
        anyhow::bail!("one guild event exceeds a peer response frame");
    }
    tail.events.truncate(low);
    Ok(tail)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct CachedOperation {
    pub(super) request_hash: [u8; 32],
    pub(super) response: PeerResponse,
}

#[cfg(test)]
mod tests {
    use mb_core::{
        EndpointRecord, KeyMaterial, RECOVERY_LOCATOR_DOMAIN, RecoveryLocator,
        STORAGE_ACKNOWLEDGEMENT_DOMAIN, Seed, StorageAcknowledgement, canonical_bytes,
    };

    use super::*;
    use crate::network::{PEER_REQUEST_DOMAIN, PEER_RESPONSE_DOMAIN};

    const SCHEMA: &str = include_str!("../../../../protocol/peer.cddl");
    const PROFILE_REQUEST: &str =
        include_str!("../../../../protocol/vectors/peer-profile-request.cbor.hex");
    const INVALID_VERSION: &str =
        include_str!("../../../../protocol/vectors/peer-invalid-version.cbor.hex");
    const ENDPOINT_RECORD: &str =
        include_str!("../../../../protocol/vectors/endpoint-record.postcard.hex");
    const STORAGE_ACKNOWLEDGEMENT: &str =
        include_str!("../../../../protocol/vectors/storage-acknowledgement.postcard.hex");
    const RECOVERY_LOCATOR: &str =
        include_str!("../../../../protocol/vectors/recovery-locator.postcard.hex");

    #[test]
    fn retained_paged_checkpoint_frames_bound_paths_and_payloads_on_both_transports() {
        let mut path = mb_core::CatalogPagePath {
            scope: mb_core::CatalogScope::Guild {
                guild_id: [255; 32],
            },
            section: mb_core::CatalogSection::Checkpoint,
            pages: (0..=mb_core::CATALOG_MAX_HEIGHT)
                .rev()
                .map(|height| mb_core::CatalogPageRef {
                    hash: [255; 32],
                    encoded_len: mb_core::CATALOG_PAGE_BYTES as u32,
                    height,
                    byte_len: if height == 0 {
                        mb_core::CATALOG_LEAF_BYTES as u64
                    } else {
                        mb_core::CATALOG_MAX_STREAM_BYTES
                    },
                    page_occurrences: if height == 0 {
                        1
                    } else {
                        mb_core::CATALOG_MAX_PAGE_OCCURRENCES
                    },
                })
                .collect(),
        };
        path.validate().unwrap();
        for layout in [
            mb_core::PagedCheckpointLayout::Individual,
            mb_core::PagedCheckpointLayout::Directory,
        ] {
            let mut dataset_path = path.clone();
            dataset_path.scope = mb_core::CatalogScope::Dataset {
                guild_id: [255; 32],
                owner: NodeId([255; 32]),
                protected_root_id: Uuid::from_bytes([255; 16]),
            };
            dataset_path.section = mb_core::CatalogSection::SectorReferences;
            for request in [
                PeerRequest::GetRetainedPagedCheckpointCertificate {
                    guild_id: [255; 32],
                    layout,
                    owner_id: Uuid::from_bytes([255; 16]),
                    checkpoint_hash: [255; 32],
                },
                PeerRequest::GetRetainedPagedCheckpointPage {
                    guild_id: [255; 32],
                    layout,
                    owner_id: Uuid::from_bytes([255; 16]),
                    checkpoint_hash: [255; 32],
                    path: path.clone(),
                },
                PeerRequest::GetRetainedPagedCheckpointPage {
                    guild_id: [255; 32],
                    layout,
                    owner_id: Uuid::from_bytes([255; 16]),
                    checkpoint_hash: [255; 32],
                    path: dataset_path,
                },
            ] {
                assert!(request.is_read_only());
                assert!(!request.is_writer_read());
                assert!(request.mutation_kind().is_none());
                assert_eq!(request.guild_scope(), Some([255; 32]));
                let signed = budget_request(request);
                let cbor = cbor4ii::serde::to_vec(Vec::new(), &signed).unwrap();
                cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &cbor).unwrap();
                cbor4ii::serde::from_slice::<SignedRecord<PeerRequestEnvelope>>(&cbor).unwrap();
                mb_core::decode_canonical::<SignedRecord<PeerRequestEnvelope>>(
                    &canonical_bytes(&signed).unwrap(),
                )
                .unwrap();
                let (tcp, cbor) = frame_sizes(&signed).unwrap();
                assert!(tcp.max(cbor) <= super::super::MAX_PEER_FRAME_BYTES);
            }
        }
        path.pages.push(path.pages[3]);
        let signed = budget_request(PeerRequest::GetRetainedPagedCheckpointPage {
            guild_id: [255; 32],
            layout: mb_core::PagedCheckpointLayout::Individual,
            owner_id: Uuid::from_bytes([255; 16]),
            checkpoint_hash: [255; 32],
            path,
        });
        assert!(
            mb_core::decode_canonical::<SignedRecord<PeerRequestEnvelope>>(
                &canonical_bytes(&signed).unwrap()
            )
            .is_err()
        );
        assert!(
            cbor4ii::serde::from_slice::<SignedRecord<PeerRequestEnvelope>>(
                &cbor4ii::serde::to_vec(Vec::new(), &signed).unwrap()
            )
            .is_err()
        );
        for (limit, certificate) in [
            (mb_core::PAGED_QUORUM_CHECKPOINT_BYTES, true),
            (mb_core::CATALOG_PAGE_BYTES, false),
        ] {
            for length in [limit, limit + 1] {
                let response = if certificate {
                    PeerResponse::RetainedPagedCheckpointCertificate {
                        bytes: vec![255; length],
                    }
                } else {
                    PeerResponse::RetainedPagedCheckpointPage {
                        bytes: vec![255; length],
                    }
                };
                let signed = budget_response(response);
                let tcp = canonical_bytes(&signed).unwrap();
                let cbor = cbor4ii::serde::to_vec(Vec::new(), &signed).unwrap();
                assert_eq!(
                    mb_core::decode_canonical::<SignedRecord<PeerResponseEnvelope>>(&tcp).is_ok(),
                    length == limit
                );
                assert_eq!(
                    cbor4ii::serde::from_slice::<SignedRecord<PeerResponseEnvelope>>(&cbor).is_ok(),
                    length == limit
                );
                if length == limit {
                    cddl_cat::validate_cbor_bytes("signed-peer-response", SCHEMA, &cbor).unwrap();
                    assert!(tcp.len().max(cbor.len()) <= super::super::MAX_PEER_FRAME_BYTES);
                }
            }
        }
    }

    #[tokio::test]
    async fn versioned_coding_plan_tuples_preserve_both_transports_and_reject_extra_fields() {
        use libp2p::request_response::Codec;
        let keys: Vec<_> = (0..4)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([90 + i; 32])))
            .collect();
        let shards = mb_core::encode(
            mb_core::CodingProfile::new(2, 2, 64),
            vec![vec![1; 64], vec![2; 64]],
        )
        .unwrap();
        let protocol = libp2p::StreamProtocol::new("/mutualbackup/peer/2");
        let mut codec = libp2p::request_response::cbor::codec::Codec::<
            SignedRecord<PeerRequestEnvelope>,
            SignedRecord<PeerResponseEnvelope>,
        >::default()
        .set_request_size_maximum(super::super::MAX_PEER_FRAME_BYTES as u64)
        .set_response_size_maximum(super::super::MAX_PEER_FRAME_BYTES as u64);
        for version in [1, 2, 3] {
            let plan = CodingAttemptPlan {
                format_version: version,
                attempt_id: [1; 16],
                checkpoint_hash: [2; 32],
                membership_epoch: 1,
                geometry: mb_core::CodingPlanGeometry {
                    format_version: 1,
                    guild_id: [3; 32],
                    profile: mb_core::CodingProfile::new(2, 2, 64),
                    information: (0..2)
                        .map(|i| mb_core::InformationRoleV2 {
                            owner: keys[i].node_id(),
                            failure_domain: format!("site-{i}"),
                            sector: mb_core::RangeSectorRef {
                                id: [i as u8 + 1; 32],
                                commitment: mb_core::merkle_commit(&shards[i]).unwrap(),
                                logical_len: 64,
                                virtual_zero: false,
                            },
                        })
                        .collect(),
                    parity: (0..2)
                        .map(|i| mb_core::ParityPlacementV2 {
                            holder: keys[i + 2].node_id(),
                            failure_domain: format!("site-{}", i + 2),
                            row: i as u16,
                        })
                        .collect(),
                },
                delegator: keys[0].node_id(),
                coding_coordinator: keys[1].node_id(),
                verification_coordinator: keys[3].node_id(),
                expires_at_unix_seconds: u64::MAX,
                information_roots: (version != 1).then(|| {
                    shards[..2]
                        .iter()
                        .map(|bytes| mb_core::sector_root(bytes))
                        .collect()
                }),
            };
            plan.validate().unwrap();
            let old_layout = (
                plan.format_version,
                plan.attempt_id,
                plan.checkpoint_hash,
                plan.membership_epoch,
                &plan.geometry,
                plan.delegator,
                plan.coding_coordinator,
                plan.verification_coordinator,
                plan.expires_at_unix_seconds,
            );
            if version == 1 {
                assert_eq!(
                    mb_core::canonical_bytes(&plan).unwrap(),
                    mb_core::canonical_bytes(&old_layout).unwrap()
                );
                let mut extra = cbor4ii::serde::to_vec(Vec::new(), &plan).unwrap();
                assert_eq!(extra[0], 0x89);
                extra[0] = 0x8a;
                extra.push(0);
                assert!(cbor4ii::serde::from_slice::<CodingAttemptPlan>(&extra).is_err());
            } else {
                let missing = cbor4ii::serde::to_vec(Vec::new(), &old_layout).unwrap();
                assert!(cbor4ii::serde::from_slice::<CodingAttemptPlan>(&missing).is_err());
            }
            let signed =
                SignedRecord::sign(mb_core::CODING_ATTEMPT_PLAN_DOMAIN, plan, &keys[0]).unwrap();
            let transcript =
                crate::node::tests::test_coding_transcript(signed.clone(), &shards, &keys);
            let request = budget_request(PeerRequest::SubmitCodingTranscript {
                transcript: Box::new(transcript.clone()),
            });
            let canonical = mb_core::canonical_bytes(&request).unwrap();
            let restored: SignedRecord<PeerRequestEnvelope> =
                mb_core::decode_canonical(&canonical).unwrap();
            assert_eq!(mb_core::canonical_bytes(&restored).unwrap(), canonical);
            let mut cursor = futures::io::Cursor::new(Vec::new());
            codec
                .write_request(&protocol, &mut cursor, request)
                .await
                .unwrap();
            cursor.set_position(0);
            let decoded = codec.read_request(&protocol, &mut cursor).await.unwrap();
            assert_eq!(mb_core::canonical_bytes(&decoded).unwrap(), canonical);
            let response = budget_response(PeerResponse::CodingVerificationTranscript(Box::new(
                transcript.clone(),
            )));
            let canonical = mb_core::canonical_bytes(&response).unwrap();
            let mut cursor = futures::io::Cursor::new(Vec::new());
            codec
                .write_response(&protocol, &mut cursor, response)
                .await
                .unwrap();
            cursor.set_position(0);
            let decoded = codec.read_response(&protocol, &mut cursor).await.unwrap();
            assert_eq!(mb_core::canonical_bytes(&decoded).unwrap(), canonical);
            let Ok(PeerResponse::CodingVerificationTranscript(decoded)) = decoded.value.result
            else {
                panic!("wrong response");
            };
            assert_eq!(*decoded, transcript);
            assert_eq!(
                mb_core::replay_coding_transcript(&decoded).unwrap(),
                mb_core::CodingReplayFinding::Verified
            );
        }
        assert!(cbor4ii::serde::from_slice::<[u8; 2]>(&[0x81, 1]).is_err());
        assert!(cbor4ii::serde::from_slice::<[u8; 2]>(&[0x83, 1, 2, 3]).is_err());
    }

    #[tokio::test]
    async fn full_byte_proof_frames_fit_both_transports_and_keep_old_layouts() {
        use libp2p::request_response::Codec;
        use mb_core::{
            CODING_ATTEMPT_PLAN_DOMAIN, CodingPlanGeometry, CodingProfile, InformationRoleV2,
            ParityPlacementV2, RangeSectorRef,
        };
        let keys = (0_u8..6)
            .map(|i| KeyMaterial::from_seed(&Seed::from_bytes([90 + i; 32])))
            .collect::<Vec<_>>();
        let profile = CodingProfile::new(4, 2, 128 * 1024);
        let shards = mb_core::encode(profile, vec![vec![255; 128 * 1024]; 4]).unwrap();
        let domain = |i| format!("{i:03}{}", "x".repeat(253));
        let plan = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [1; 16],
            checkpoint_hash: [2; 32],
            membership_epoch: 1,
            geometry: CodingPlanGeometry {
                format_version: 1,
                guild_id: [3; 32],
                profile,
                information: (0..4)
                    .map(|i| InformationRoleV2 {
                        owner: keys[i].node_id(),
                        failure_domain: domain(i),
                        sector: RangeSectorRef {
                            id: [i as u8 + 1; 32],
                            commitment: mb_core::merkle_commit(&shards[i]).unwrap(),
                            logical_len: profile.shard_size,
                            virtual_zero: false,
                        },
                    })
                    .collect(),
                parity: (0..2)
                    .map(|i| ParityPlacementV2 {
                        holder: keys[4 + i].node_id(),
                        failure_domain: domain(4 + i),
                        row: i as u16,
                    })
                    .collect(),
            },
            delegator: keys[0].node_id(),
            coding_coordinator: keys[1].node_id(),
            verification_coordinator: keys[2].node_id(),
            expires_at_unix_seconds: u64::MAX,
            information_roots: Some(
                shards[..4]
                    .iter()
                    .map(|bytes| mb_core::sector_root(bytes))
                    .collect(),
            ),
        };
        plan.validate().unwrap();
        validate_root_binding_frame_budget(&plan, 256).unwrap();
        let signed_plan =
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan.clone(), &keys[0]).unwrap();
        let transcript =
            crate::node::tests::test_coding_transcript(signed_plan.clone(), &shards, &keys);
        let manifest = transcript.value.manifest.clone();
        let mut legacy = manifest.value.clone();
        legacy.format_version = 2;
        #[derive(Serialize)]
        struct LegacyFullManifest<'a> {
            format_version: u16,
            attempt_id: [u8; 16],
            plan_hash: [u8; 32],
            group: &'a mb_core::CodingGroupV2,
            information_bytes: &'a Vec<Option<Vec<u8>>>,
        }
        let layout = LegacyFullManifest {
            format_version: 2,
            attempt_id: legacy.attempt_id,
            plan_hash: legacy.plan_hash,
            group: &legacy.group,
            information_bytes: legacy.information_bytes.as_ref().unwrap(),
        };
        let legacy_cbor = cbor4ii::serde::to_vec(Vec::new(), &layout).unwrap();
        assert!(legacy_cbor.len() > super::super::MAX_PEER_FRAME_BYTES);
        assert_eq!(
            mb_core::canonical_bytes(&layout).unwrap(),
            mb_core::canonical_bytes(&legacy).unwrap()
        );
        assert_eq!(
            cbor4ii::serde::to_vec(Vec::new(), &legacy).unwrap(),
            legacy_cbor
        );
        assert_eq!(
            cbor4ii::serde::from_slice::<CodingRootManifest>(&legacy_cbor).unwrap(),
            legacy
        );
        assert_eq!(
            mb_core::decode_canonical::<CodingRootManifest>(
                &mb_core::canonical_bytes(&legacy).unwrap()
            )
            .unwrap(),
            legacy
        );
        // Both historical array witnesses and compact byte strings apply one
        // aggregate budget before accepting a map-shaped CBOR manifest.
        for version in [2, 3] {
            let mut oversized = manifest.value.clone();
            oversized.format_version = version;
            oversized.information_bytes.as_mut().unwrap()[0]
                .as_mut()
                .unwrap()
                .push(0);
            let cbor = cbor4ii::serde::to_vec(Vec::new(), &oversized).unwrap();
            assert!(cbor4ii::serde::from_slice::<CodingRootManifest>(&cbor).is_err());
        }
        let mut compact = manifest.value.clone();
        compact.format_version = 1;
        compact.information_bytes = None;
        let encoded = cbor4ii::serde::to_vec(Vec::new(), &compact).unwrap();
        assert_eq!(
            cbor4ii::serde::from_slice::<CodingRootManifest>(&encoded).unwrap(),
            compact
        );
        let range_bytes = coding_parity_range_bytes(&signed_plan, &manifest).unwrap();
        assert!(range_bytes < profile.shard_size as usize);
        // Exercise the holder's actual durable range preconditions, including
        // restart after the first frame-limited chunk. Envelope sizes vary with
        // domain length; fitting a frame alone does not imply leaf alignment.
        let mut raw_unaligned_budget_seen = false;
        for variation in 0..4 {
            let mut varied_plan = plan.clone();
            varied_plan.geometry.information[0]
                .failure_domain
                .truncate(256 - variation);
            let varied_plan =
                SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, varied_plan, &keys[0]).unwrap();
            let varied_manifest =
                crate::node::tests::test_coding_transcript(varied_plan.clone(), &shards, &keys)
                    .value
                    .manifest;
            let range_bytes = coding_parity_range_bytes(&varied_plan, &varied_manifest).unwrap();
            let empty_request = PeerRequest::UploadCodingParityRange {
                plan: Box::new(varied_plan.clone()),
                manifest: Box::new(varied_manifest.clone()),
                shard_index: u16::MAX,
                offset: u32::MAX,
                bytes: Vec::new(),
            };
            let (tcp, cbor) = frame_sizes(&budget_request(empty_request)).unwrap();
            let raw_budget = super::super::MAX_PEER_FRAME_BYTES
                .saturating_sub(tcp + 8)
                .min(super::super::MAX_PEER_FRAME_BYTES.saturating_sub(cbor + 8) / 2)
                .min(256 * 1024);
            raw_unaligned_budget_seen |= !raw_budget.is_multiple_of(mb_core::MERKLE_LEAF_SIZE);
            assert!(range_bytes < shards[4].len());
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("parity.db");
            let volume_id = [1; 16];
            let attempt_id = varied_plan.value.attempt_id;
            let guild_id = varied_plan.value.geometry.guild_id;
            let mut store = mb_store::ParityStore::open(&path, &volume_id, &keys[4]).unwrap();
            let mut offset = store
                .reserve_coding_attempt(
                    &attempt_id,
                    &guild_id,
                    4,
                    profile.shard_size,
                    8 * 1024 * 1024,
                )
                .unwrap() as usize;
            while offset < shards[4].len() {
                let end = (offset + range_bytes).min(shards[4].len());
                let chunk = &shards[4][offset..end];
                let request = budget_request(PeerRequest::UploadCodingParityRange {
                    plan: Box::new(varied_plan.clone()),
                    manifest: Box::new(varied_manifest.clone()),
                    shard_index: 4,
                    offset: offset as u32,
                    bytes: chunk.to_vec(),
                });
                let (tcp, cbor) = frame_sizes(&request).unwrap();
                assert!(tcp.max(cbor) <= super::super::MAX_PEER_FRAME_BYTES);
                offset = store
                    .write_coding_attempt_range(&attempt_id, 4, offset as u32, chunk)
                    .unwrap() as usize;
                if offset == range_bytes {
                    drop(store);
                    store = mb_store::ParityStore::open(&path, &volume_id, &keys[4]).unwrap();
                    assert_eq!(
                        store
                            .reserve_coding_attempt(
                                &attempt_id,
                                &guild_id,
                                4,
                                profile.shard_size,
                                8 * 1024 * 1024,
                            )
                            .unwrap() as usize,
                        offset
                    );
                }
            }
            let commitment = mb_core::merkle_commit(&shards[4]).unwrap();
            let group_id = varied_manifest.value.group.id;
            store
                .finish_coding_attempt_upload(&attempt_id, &group_id, 4, &commitment)
                .unwrap();
            let proof = store
                .open_attempt_range(&attempt_id, &group_id, 4, 0, 1)
                .unwrap();
            mb_core::merkle_verify_range(&commitment, &proof).unwrap();
        }
        assert!(
            raw_unaligned_budget_seen,
            "exercise a budget rejected before leaf rounding"
        );
        let event = GuildEvent {
            format_version: 2,
            guild_id: plan.geometry.guild_id,
            sequence: 1,
            parent: [4; 32],
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: manifest.value.group.clone(),
                transcript_hash: [1; 32],
            },
        };
        let certified = QuorumGuildEvent {
            event: event.clone(),
            signatures: keys
                .iter()
                .map(|key| mb_core::sign_guild_event(&event, key).unwrap())
                .collect(),
        };
        let requests = vec![
            PeerRequest::GetCodingAttemptRetirement {
                plan: Box::new(signed_plan.clone()),
            },
            PeerRequest::RetireCodingAttempt {
                plan: Box::new(signed_plan.clone()),
            },
            PeerRequest::UploadCodingParityRange {
                plan: Box::new(signed_plan.clone()),
                manifest: Box::new(manifest.clone()),
                shard_index: 4,
                offset: u32::MAX,
                bytes: vec![255; range_bytes],
            },
            PeerRequest::FinalizeCodingParity {
                plan: Box::new(signed_plan.clone()),
                manifest: Box::new(manifest.clone()),
                shard_index: 4,
            },
            PeerRequest::RevealCodingChallenge {
                plan: Box::new(signed_plan.clone()),
                manifest: Box::new(manifest.clone()),
                receipts: transcript.value.staged_receipts.clone(),
            },
            PeerRequest::GetCodingOpening {
                plan: Box::new(signed_plan.clone()),
                manifest: Box::new(manifest.clone()),
                challenge: [255; 32],
                shard_index: 4,
            },
            PeerRequest::FinalizeCodingVerification {
                transcript: Box::new(transcript.value.clone()),
            },
            PeerRequest::SubmitCodingTranscript {
                transcript: Box::new(transcript.clone()),
            },
            PeerRequest::ActivateCodingParity {
                transcript: Box::new(transcript.clone()),
            },
            PeerRequest::SignCodingGroupEvent {
                event: Box::new(event.clone()),
                transcript: Box::new(transcript.clone()),
            },
            PeerRequest::InstallCodingGroupEvent {
                certified: Box::new(certified.clone()),
                transcript: Box::new(transcript.clone()),
            },
            PeerRequest::GetCodingTranscriptForEvent {
                guild_id: event.guild_id,
                group_id: manifest.value.group.id,
                event_sequence: event.sequence,
                event_hash: event.hash().unwrap(),
            },
        ];
        let mut codec = libp2p::request_response::cbor::codec::Codec::<
            SignedRecord<PeerRequestEnvelope>,
            SignedRecord<PeerResponseEnvelope>,
        >::default()
        .set_request_size_maximum(super::super::MAX_PEER_FRAME_BYTES as u64)
        .set_response_size_maximum(super::super::MAX_PEER_FRAME_BYTES as u64);
        let protocol = libp2p::StreamProtocol::new("/mutualbackup/peer/2");
        for request in requests {
            let request = budget_request(request);
            if matches!(
                request.value.request,
                PeerRequest::RetireCodingAttempt { .. }
                    | PeerRequest::GetCodingAttemptRetirement { .. }
                    | PeerRequest::GetCodingTranscriptForEvent { .. }
            ) {
                let bytes = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
                cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &bytes).unwrap();
            }
            let (tcp, cbor) = frame_sizes(&request).unwrap();
            assert!(tcp.max(cbor) <= super::super::MAX_PEER_FRAME_BYTES);
            let canonical = mb_core::canonical_bytes(&request).unwrap();
            mb_core::decode_canonical::<SignedRecord<PeerRequestEnvelope>>(&canonical).unwrap();
            let mut cursor = futures::io::Cursor::new(Vec::new());
            codec
                .write_request(&protocol, &mut cursor, request)
                .await
                .unwrap();
            cursor.set_position(0);
            let decoded = codec.read_request(&protocol, &mut cursor).await.unwrap();
            if let PeerRequest::SubmitCodingTranscript {
                transcript: decoded,
            } = decoded.value.request
            {
                assert_eq!(*decoded, transcript);
                assert_eq!(
                    mb_core::replay_coding_transcript(&decoded).unwrap(),
                    mb_core::CodingReplayFinding::Verified
                );
            }
        }
        let tail = GuildEventTail {
            format_version: 1,
            base_sequence: 0,
            base_head: [4; 32],
            events: vec![certified; 512],
        };
        let bounded = bound_peer_event_tail(tail.clone()).unwrap();
        assert!(!bounded.events.is_empty() && bounded.events.len() < tail.events.len());
        assert_eq!(bounded.events, tail.events[..bounded.events.len()]);
        for response in [
            PeerResponse::CodingAttemptRetired { retired: false },
            PeerResponse::CodingAttemptRetired { retired: true },
            PeerResponse::CodingVerificationTranscript(Box::new(transcript)),
            PeerResponse::GuildEventTail(Box::new(bounded)),
        ] {
            let response = budget_response(response);
            if matches!(
                response.value.result,
                Ok(PeerResponse::CodingAttemptRetired { .. })
            ) {
                let bytes = cbor4ii::serde::to_vec(Vec::new(), &response).unwrap();
                cddl_cat::validate_cbor_bytes("signed-peer-response", SCHEMA, &bytes).unwrap();
            }
            let (tcp, cbor) = frame_sizes(&response).unwrap();
            assert!(tcp.max(cbor) <= super::super::MAX_PEER_FRAME_BYTES);
            mb_core::decode_canonical::<SignedRecord<PeerResponseEnvelope>>(
                &mb_core::canonical_bytes(&response).unwrap(),
            )
            .unwrap();
            let mut cursor = futures::io::Cursor::new(Vec::new());
            codec
                .write_response(&protocol, &mut cursor, response)
                .await
                .unwrap();
            cursor.set_position(0);
            codec.read_response(&protocol, &mut cursor).await.unwrap();
        }
        // Raw size alone fits, but dense roles/proofs and a large certificate
        // do not. Reject new work before staging, while core replay stays able
        // to decode historical evidence independent of current transport limits.
        let mut dense = plan;
        dense.geometry.profile = CodingProfile::new(32, 32, 16 * 1024);
        dense.geometry.information = (0..32)
            .map(|i| {
                let mut info = dense.geometry.information[0].clone();
                info.sector.commitment.byte_len = 16 * 1024;
                info.sector.logical_len = 16 * 1024;
                info.failure_domain = domain(i);
                info
            })
            .collect();
        dense.geometry.parity = (0..32)
            .map(|i| ParityPlacementV2 {
                holder: keys[4].node_id(),
                failure_domain: domain(32 + i),
                row: i as u16,
            })
            .collect();
        dense.information_roots = Some(vec![[1; 32]; 32]);
        dense.validate().unwrap();
        assert!(validate_root_binding_frame_budget(&dense, 256).is_err());
    }

    fn profile_request(format_version: u16) -> SignedRecord<PeerRequestEnvelope> {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([7; 32]));
        SignedRecord::sign(
            PEER_REQUEST_DOMAIN,
            PeerRequestEnvelope {
                format_version,
                request_id: [9; 16],
                caller: keys.node_id(),
                recipient: None,
                guild_scope: None,
                issued_at_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_700_000_060,
                request: PeerRequest::Profile,
            },
            &keys,
        )
        .unwrap()
    }

    fn decode_hex_fixture(value: &str) -> Vec<u8> {
        hex::decode(value.trim()).unwrap()
    }

    #[test]
    fn peer_cbor_vectors_match_cddl_and_round_trip() {
        let expected = decode_hex_fixture(PROFILE_REQUEST);
        let actual =
            cbor4ii::serde::to_vec(Vec::new(), &profile_request(PEER_WIRE_FORMAT_VERSION)).unwrap();
        assert_eq!(actual, expected);
        cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &actual).unwrap();
        let decoded: SignedRecord<PeerRequestEnvelope> =
            cbor4ii::serde::from_slice(&actual).unwrap();
        assert_eq!(
            cbor4ii::serde::to_vec(Vec::new(), &decoded).unwrap(),
            actual
        );

        let invalid = decode_hex_fixture(INVALID_VERSION);
        assert_eq!(
            cbor4ii::serde::to_vec(Vec::new(), &profile_request(1)).unwrap(),
            invalid
        );
        assert!(cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &invalid).is_err());
    }

    #[test]
    fn coding_path_observation_matches_cddl() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([7; 32]));
        let recipient = KeyMaterial::from_seed(&Seed::from_bytes([8; 32])).node_id();
        let request = SignedRecord::sign(
            PEER_REQUEST_DOMAIN,
            PeerRequestEnvelope {
                format_version: PEER_WIRE_FORMAT_VERSION,
                request_id: [9; 16],
                caller: keys.node_id(),
                recipient: Some(recipient),
                guild_scope: Some([3; 32]),
                issued_at_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_700_000_060,
                request: PeerRequest::CodingPathObservation {
                    guild_id: [3; 32],
                    targets: vec![keys.node_id(), recipient],
                },
            },
            &keys,
        )
        .unwrap();
        let request_bytes = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
        cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &request_bytes).unwrap();

        let response = SignedRecord::sign(
            PEER_RESPONSE_DOMAIN,
            PeerResponseEnvelope {
                format_version: PEER_WIRE_FORMAT_VERSION,
                request_id: [9; 16],
                recipient: keys.node_id(),
                request_hash: [4; 32],
                result: Ok(PeerResponse::CodingPathObservation(CodingPathObservation {
                    observed_at_unix_seconds: 1_700_000_001,
                    paths: vec![
                        CodingPathEntry {
                            target: keys.node_id(),
                            path: Some(CodingPathClass::Direct),
                        },
                        CodingPathEntry {
                            target: recipient,
                            path: None,
                        },
                    ],
                })),
            },
            &keys,
        )
        .unwrap();
        let response_bytes = cbor4ii::serde::to_vec(Vec::new(), &response).unwrap();
        cddl_cat::validate_cbor_bytes("signed-peer-response", SCHEMA, &response_bytes).unwrap();
    }

    #[test]
    fn legacy_add_attestation_frames_match_cddl() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([21; 32]));
        let recipient = KeyMaterial::from_seed(&Seed::from_bytes([22; 32])).node_id();
        let request = SignedRecord::sign(
            PEER_REQUEST_DOMAIN,
            PeerRequestEnvelope {
                format_version: PEER_WIRE_FORMAT_VERSION,
                request_id: [23; 16],
                caller: keys.node_id(),
                recipient: Some(recipient),
                guild_scope: Some([24; 32]),
                issued_at_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_700_000_060,
                request: PeerRequest::AttestLegacyCodingAdd {
                    guild_id: [24; 32],
                    event_sequence: 7,
                    event_hash: [25; 32],
                    transcript_hash: [26; 32],
                },
            },
            &keys,
        )
        .unwrap();
        let request_bytes = cbor4ii::serde::to_vec(Vec::new(), &request).unwrap();
        cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &request_bytes).unwrap();
        let response = SignedRecord::sign(
            PEER_RESPONSE_DOMAIN,
            PeerResponseEnvelope {
                format_version: PEER_WIRE_FORMAT_VERSION,
                request_id: [23; 16],
                recipient: keys.node_id(),
                request_hash: [27; 32],
                result: Ok(PeerResponse::LegacyCodingAddAttestation(MemberSignature {
                    signer: recipient,
                    signature: vec![28; 64],
                })),
            },
            &keys,
        )
        .unwrap();
        let response_bytes = cbor4ii::serde::to_vec(Vec::new(), &response).unwrap();
        cddl_cat::validate_cbor_bytes("signed-peer-response", SCHEMA, &response_bytes).unwrap();

        let lookup = SignedRecord::sign(
            PEER_REQUEST_DOMAIN,
            PeerRequestEnvelope {
                format_version: PEER_WIRE_FORMAT_VERSION,
                request_id: [29; 16],
                caller: keys.node_id(),
                recipient: Some(recipient),
                guild_scope: Some([24; 32]),
                issued_at_unix_seconds: 1_700_000_000,
                expires_at_unix_seconds: 1_700_000_060,
                request: PeerRequest::GetLegacyCodingAddBinding {
                    guild_id: [24; 32],
                    event_sequence: 7,
                    event_hash: [25; 32],
                },
            },
            &keys,
        )
        .unwrap();
        cddl_cat::validate_cbor_bytes(
            "signed-peer-request",
            SCHEMA,
            &cbor4ii::serde::to_vec(Vec::new(), &lookup).unwrap(),
        )
        .unwrap();
        let binding = QuorumLegacyCodingAddBinding {
            statement: mb_core::LegacyCodingAddStatement {
                format_version: 1,
                guild_id: [24; 32],
                event_sequence: 7,
                event_hash: [25; 32],
                transcript_hash: [26; 32],
            },
            signatures: vec![MemberSignature {
                signer: recipient,
                signature: vec![28; 64],
            }],
        };
        let response = SignedRecord::sign(
            PEER_RESPONSE_DOMAIN,
            PeerResponseEnvelope {
                format_version: PEER_WIRE_FORMAT_VERSION,
                request_id: [29; 16],
                recipient: keys.node_id(),
                request_hash: [27; 32],
                result: Ok(PeerResponse::LegacyCodingAddBinding(Some(binding))),
            },
            &keys,
        )
        .unwrap();
        cddl_cat::validate_cbor_bytes(
            "signed-peer-response",
            SCHEMA,
            &cbor4ii::serde::to_vec(Vec::new(), &response).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn signed_postcard_vector_is_byte_exact_and_verifies() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([7; 32]));
        let record = SignedRecord::sign(
            b"mutualbackup/endpoint-record/v1",
            EndpointRecord {
                format_version: 1,
                publisher: keys.node_id(),
                sequence: 42,
                expires_at_unix_seconds: 1_700_000_000,
                endpoints: vec![
                    "/ip4/192.0.2.7/udp/4400/quic-v1".to_owned(),
                    "exampleexampleexampleexampleexampleexampleexampleexample.onion".to_owned(),
                ],
            },
            &keys,
        )
        .unwrap();
        record.verify(b"mutualbackup/endpoint-record/v1").unwrap();
        let actual = canonical_bytes(&record).unwrap();
        assert_eq!(actual, decode_hex_fixture(ENDPOINT_RECORD));
    }

    #[test]
    fn storage_acknowledgement_domain_and_vector_are_byte_exact() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([7; 32]));
        let record = SignedRecord::sign(
            STORAGE_ACKNOWLEDGEMENT_DOMAIN,
            StorageAcknowledgement {
                format_version: 1,
                operation_id: [1; 16],
                guild_id: [2; 32],
                group_id: [3; 32],
                shard_index: 3,
                row: 0,
                root: [4; 32],
                holder: keys.node_id(),
            },
            &keys,
        )
        .unwrap();
        record.verify(STORAGE_ACKNOWLEDGEMENT_DOMAIN).unwrap();
        assert!(record.verify(b"mutualbackup/storage-ack/v1").is_err());
        assert_eq!(
            hex::encode(canonical_bytes(&record).unwrap()),
            STORAGE_ACKNOWLEDGEMENT.trim()
        );
    }

    #[test]
    fn recovery_locator_domain_and_vector_are_byte_exact() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([7; 32]));
        let peer_id = keys.node_id().libp2p_peer_id().unwrap();
        let record = SignedRecord::sign(
            RECOVERY_LOCATOR_DOMAIN,
            RecoveryLocator {
                format_version: 1,
                subject: keys.node_id(),
                publisher: keys.node_id(),
                guild_id: [5; 32],
                checkpoint_hash: [6; 32],
                checkpoint_generation: 7,
                subject_endpoint_sequence_floor: 41,
                endpoints: vec![format!("/ip4/192.0.2.7/udp/4400/quic-v1/p2p/{peer_id}")],
                expires_at_unix_seconds: 1_700_000_000,
            },
            &keys,
        )
        .unwrap();
        record.verify(RECOVERY_LOCATOR_DOMAIN).unwrap();
        assert!(record.verify(b"mutualbackup/recovery-location/v1").is_err());
        assert_eq!(
            hex::encode(canonical_bytes(&record).unwrap()),
            RECOVERY_LOCATOR.trim()
        );
    }
}
