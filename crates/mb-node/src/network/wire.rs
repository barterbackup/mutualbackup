use mb_core::{
    CodingAttemptPlan, CodingChallengeCommitment, CodingChallengeReveal, CodingFailureReport,
    CodingGroup, CodingRootManifest, CodingShardOpening, CodingVerificationTranscript,
    EndpointRecord, GuildEvent, GuildEventTail, GuildGenesis, GuildInvite, Member, MemberSignature,
    MerkleRangeProof, NodeId, QuorumGuildEvent, QuorumGuildGenesis, SectorId, SectorRef,
    SignedRecord, StagedStorageReceipt, StorageAcknowledgement,
};
use mb_store::{ParityObject, VariableParityObject};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{BackupDescriptor, BackupJob, GuildPeer};
#[cfg(test)]
use super::{PublishedRecoveryRecord, RecoveryPublisherAdmission};
use crate::WireError;

pub(super) const PEER_WIRE_FORMAT_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct PeerProfile {
    pub(super) member: Member,
    pub(super) endpoint: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum PeerRequest {
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
    StoreRepairShard {
        repair_id: [u8; 16],
        guild_id: [u8; 32],
        checkpoint_hash: [u8; 32],
        group_id: [u8; 32],
        shard_index: u8,
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
    pub(super) fn is_read_only(&self) -> bool {
        matches!(
            self,
            Self::Profile
                | Self::GetSector { .. }
                | Self::GetSectorRange { .. }
                | Self::GetParity { .. }
                | Self::GetPreparedRevisionPage { .. }
                | Self::GetCheckpointPage { .. }
                | Self::BackupStatus { .. }
                | Self::GetGuildGenesis { .. }
                | Self::GetGuildEventTail { .. }
                | Self::ExchangeEndpoints { .. }
        )
    }

    pub(super) fn mutation_kind(&self) -> Option<&'static str> {
        match self {
            Self::Profile
            | Self::GetSector { .. }
            | Self::GetSectorRange { .. }
            | Self::GetParity { .. }
            | Self::GetPreparedRevisionPage { .. }
            | Self::GetCheckpointPage { .. }
            | Self::BackupStatus { .. }
            | Self::GetGuildGenesis { .. }
            | Self::GetGuildEventTail { .. }
            | Self::ExchangeEndpoints { .. } => None,
            #[cfg(test)]
            Self::BeginCommit { .. } => Some("begin-commit"),
            Self::JoinGuild { .. } => Some("join-guild"),
            Self::ProposeGuildGenesis { .. } => Some("propose-guild-genesis"),
            Self::InstallGuildGenesis { .. } => Some("install-guild-genesis"),
            Self::SignGuildEvent { .. } => Some("sign-guild-event"),
            Self::InstallGuildEvent { .. } => Some("install-guild-event"),
            Self::SubmitBackup { .. } => Some("submit-backup"),
            #[cfg(test)]
            Self::PrepareSource { .. } => Some("prepare-source"),
            Self::EnsureFiller { .. } => Some("ensure-filler"),
            Self::PublishParity { .. } => Some("publish-parity"),
            Self::StageCodingParity { .. } => Some("stage-coding-parity"),
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
            Self::StoreRepairShard { .. } => Some("store-repair-shard"),
            Self::PutCheckpointPage { .. } => Some("put-checkpoint-page"),
            Self::SignCheckpoint { .. } => Some("sign-checkpoint"),
            Self::FinalizeCheckpoint { .. } => Some("finalize-checkpoint"),
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
            | Self::GetParity { guild_id, .. }
            | Self::StoreRepairShard { guild_id, .. }
            | Self::PutCheckpointPage { guild_id, .. }
            | Self::SignCheckpoint { guild_id, .. }
            | Self::FinalizeCheckpoint { guild_id, .. }
            | Self::GetCheckpointPage { guild_id, .. }
            | Self::BackupStatus { guild_id, .. } => Some(*guild_id),
            Self::AbortCodingAttempt { plan } => Some(plan.value.geometry.guild_id),
            Self::ExchangeEndpoints { guild_id } => Some(*guild_id),
            #[cfg(test)]
            Self::PrepareSource { guild_id, .. }
            | Self::CompleteCommit { guild_id, .. }
            | Self::BuildRecoveryRecord { guild_id, .. }
            | Self::AuthorizeRecoveryPublisher { guild_id, .. } => Some(*guild_id),
            Self::GetGuildGenesis { guild_id } => Some(*guild_id),
            Self::GetGuildEventTail { guild_id, .. } => Some(*guild_id),
            Self::SignGuildEvent { event } => Some(event.guild_id),
            Self::InstallGuildEvent { certified } => Some(certified.event.guild_id),
            Self::PublishParity { object, .. } => Some(object.guild_id),
            Self::StageCodingParity { plan, .. }
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
    #[cfg(test)]
    RecoveryRecord(Box<SignedRecord<PublishedRecoveryRecord>>),
    #[cfg(test)]
    RecoveryAdmission(SignedRecord<RecoveryPublisherAdmission>),
    Ack,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct PeerResponseEnvelope {
    pub(super) format_version: u16,
    pub(super) request_id: [u8; 16],
    pub(super) recipient: NodeId,
    pub(super) request_hash: [u8; 32],
    pub(super) result: Result<PeerResponse, WireError>,
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
    use crate::network::PEER_REQUEST_DOMAIN;

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
        let actual = cbor4ii::serde::to_vec(Vec::new(), &profile_request(1)).unwrap();
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
            cbor4ii::serde::to_vec(Vec::new(), &profile_request(2)).unwrap(),
            invalid
        );
        assert!(cddl_cat::validate_cbor_bytes("signed-peer-request", SCHEMA, &invalid).is_err());
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
