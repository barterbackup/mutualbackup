//! Deterministic protocol primitives for MutualBackup.
//!
//! This crate deliberately performs no network I/O, filesystem I/O, clock, or
//! database work. The async runtime surrounds these synchronous state and
//! cryptographic operations.

mod attempt;
mod coding;
mod content;
mod guild;
mod keys;
mod model;
mod packing;
mod range;
mod recovery;

pub use attempt::{
    CODING_ATTEMPT_PLAN_DOMAIN, CODING_CHALLENGE_COMMITMENT_DOMAIN, CODING_CHALLENGE_REVEAL_DOMAIN,
    CODING_ROOT_MANIFEST_DOMAIN, CODING_SHARD_OPENING_DOMAIN, CODING_TRANSCRIPT_DOMAIN,
    CodingAttemptError, CodingAttemptPlan, CodingChallengeCommitment, CodingChallengeReveal,
    CodingReplayFinding, CodingRootManifest, CodingShardOpening, CodingVerificationTranscript,
    STAGED_STORAGE_RECEIPT_DOMAIN, StagedStorageReceipt, coding_challenge,
    coding_challenge_commitment, coding_evidence_hash, replay_coding_transcript,
};
pub use coding::{
    CodingError, CodingProfile, MAX_CODING_SHARDS, MAX_PROFILE_SHARD_SIZE, MIN_PROFILE_SHARD_SIZE,
    ReedSolomonConstruction, encode, encode_3_2, reconstruct, reconstruct_3_2, verify_codeword,
    verify_sampled_codeword,
};
pub use content::{
    ContentError, SectorPurpose, crypt_sector, encrypted_sector, make_sector_id,
    synthetic_filler_sector,
};
pub use guild::{
    DynamicGuildState, DynamicMember, GUILD_EVENT_DOMAIN, GuildEvent, GuildEventKind,
    GuildEventTail, GuildStateError, QuorumGuildEvent, QuorumPolicy, QuorumRule,
    RecoveryEpochSecret, RecoveryKeyEnvelope, RecoveryKeyEpoch, RetainedCodingGroup,
    WriterKeyEpoch, create_recovery_key_envelope, open_recovery_key_envelope, sign_guild_event,
};
pub use keys::{
    DatabaseKeyError, KeyIdentityError, KeyMaterial, NodeId, RecoveryPublicKey, Seed,
    SeedParseError, WrappedDatabaseKey,
};
pub use model::{
    CodingGroup, CodingGroupId, CodingGroupV2, EndpointRecord, GuildCheckpoint, GuildGenesis,
    GuildInvite, InformationRole, InformationRoleV2, Member, MemberSignature, ModelError,
    ParityRole, ParityRoleV2, QuorumCheckpoint, QuorumGuildGenesis, RangeSectorRef, RecoveryBundle,
    RevisionTombstone, SectorId, SectorRef, ShardRole, ShardRoleV2, SignedRecord,
    StorageAcknowledgement, USER_REVISION_DOMAIN, UserRevision, WriterFence, canonical_bytes,
    coding_group_id, coding_group_v2_id, decode_canonical,
};
pub use packing::{
    PackedCatalog, PackedSector, PackedSectorDescriptor, PackedSlot, PackedSourceChunk,
    PackingError, PackingInput, PackingMetrics, PackingProfile, PackingResult, SourceChunkId,
    pack_incremental, unpack_object,
};
pub use range::{
    MERKLE_LEAF_SIZE, MERKLE_SUITE_V1, MerkleCommitment, MerkleError, MerkleRangeProof,
    challenged_leaf, merkle_commit, merkle_open_range, merkle_verify_range, merkle_zero_commitment,
};
pub use recovery::{
    RecoveryCryptoError, RecoveryLocator, SealedRecoveryRecord, open_recovery_record,
    seal_recovery_record,
};

/// The only sector size accepted by the first protocol profile.
pub const V1_SECTOR_SIZE: usize = 64 * 1024;
pub const V1_CIPHER_PROFILE: u16 = 1;
pub const V1_RS_DATA_SHARDS: u16 = 3;
pub const V1_RS_PARITY_SHARDS: u16 = 2;
/// Maximum number of dial locations carried for one peer by the v1 protocol.
pub const V1_MAX_ENDPOINTS_PER_PEER: usize = 8;
/// Maximum UTF-8 byte length of one canonical, peer-qualified v1 endpoint.
pub const V1_MAX_ENDPOINT_BYTES: usize = 512;
pub const STORAGE_ACKNOWLEDGEMENT_DOMAIN: &[u8] = b"mutualbackup/storage-acknowledgement/v1";
pub const RECOVERY_LOCATOR_DOMAIN: &[u8] = b"mutualbackup/recovery-locator/v1";

/// Maximum encoded size of a v1 control-plane catalog object.
///
/// Bulk file bytes are sectorized and are not counted here. Keeping this
/// bound shared prevents any transport or persistence path from silently
/// accepting a catalog that another path cannot process with bounded memory.
pub const V1_MAX_CATALOG_BYTES: usize = 32 * 1024 * 1024;
pub const V1_CATALOG_PAGE_BYTES: usize = 512 * 1024;
pub const V1_MAX_CATALOG_PAGES: u32 = (V1_MAX_CATALOG_BYTES / V1_CATALOG_PAGE_BYTES) as u32;
/// A v1 checkpoint keeps coding descriptors inline; this bound keeps the
/// resulting signed catalog below `V1_MAX_CATALOG_BYTES` with ample overhead.
pub const V1_MAX_CODING_GROUPS: usize = 40_000;

/// Hash bytes exactly as they are consumed by Reed--Solomon.
pub fn sector_root(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
