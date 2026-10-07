//! Deterministic protocol primitives for MutualBackup.
//!
//! This crate deliberately performs no network I/O, filesystem I/O, clock, or
//! database work. The async runtime surrounds these synchronous state and
//! cryptographic operations.

mod attempt;
mod bounded;
mod canonical;
mod catalog;
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
    CODING_FAILURE_REPORT_DOMAIN, CODING_ROOT_MANIFEST_DOMAIN, CODING_SHARD_OPENING_DOMAIN,
    CODING_TRANSCRIPT_DOMAIN, CodingAttemptError, CodingAttemptPlan, CodingChallengeCommitment,
    CodingChallengeReveal, CodingFailureReport, CodingPlanGeometry, CodingReplayFinding,
    CodingRootManifest, CodingSampleGuarantee, CodingShardOpening, CodingTransferEstimate,
    CodingVerificationTranscript, ParityPlacementV2, STAGED_STORAGE_RECEIPT_DOMAIN,
    StagedStorageReceipt, coding_challenge, coding_challenge_commitment, coding_evidence_hash,
    coding_sample_guarantee, coding_transfer_estimate, encode_coding_attempt,
    replay_coding_transcript,
};
pub use canonical::{canonical_bytes_bounded, canonical_size_bounded};
pub use catalog::{
    CATALOG_FANOUT, CATALOG_FILE_PATH_BYTES, CATALOG_FILE_RECORD_BYTES, CATALOG_FILE_SECTOR_REFS,
    CATALOG_LEAF_BYTES, CATALOG_MAX_HEIGHT, CATALOG_MAX_PAGE_OCCURRENCES, CATALOG_MAX_RECORDS,
    CATALOG_MAX_STREAM_BYTES, CATALOG_NATIVE_FILE_ROOT_BYTES, CATALOG_PACKED_RECORD_BYTES,
    CATALOG_PACKED_ROOT_BYTES, CATALOG_PACKED_SLOTS, CATALOG_PAGE_BYTES, CATALOG_RECORD_BYTES,
    CATALOG_SECTOR_RECORD_BYTES, CatalogBuilder, CatalogError, CatalogFileBuilder,
    CatalogFileEvent, CatalogFileExtent, CatalogFileKind, CatalogFileReader,
    CatalogFileRecipeBuilder, CatalogFileRecipeReader, CatalogFileRecipeRecord,
    CatalogFileRecipeRoot, CatalogFileRecord, CatalogFileRoot, CatalogFileStat,
    CatalogNativeFileReader, CatalogNativeFileRoot, CatalogPackedSectorBuilder,
    CatalogPackedSectorReader, CatalogPackedSectorRecord, CatalogPackedSectorRoot,
    CatalogPageContents, CatalogPageRef, CatalogRangeReader, CatalogReader, CatalogRecordBuilder,
    CatalogRecordReader, CatalogRecordRoot, CatalogScope, CatalogSection, CatalogSectorBuilder,
    CatalogSectorReader, CatalogSectorRecord, CatalogSectorRoot, CatalogStreamError,
    PAGED_PRIVATE_METADATA_BYTES, PAGED_USER_REVISION_BYTES, PAGED_USER_REVISION_DOMAIN,
    PAGED_USER_REVISION_VERSION, PagedRevisionSourceReader, PagedUserRevision,
    catalog_file_path_order,
};
pub use coding::{
    CodingError, CodingProfile, MAX_CODING_SHARDS, MAX_PROFILE_SHARD_SIZE, MIN_PROFILE_SHARD_SIZE,
    ReedSolomonConstruction, encode, encode_3_2, reconstruct, reconstruct_3_2, verify_codeword,
    verify_sampled_codeword,
};
pub use content::{
    ContentError, SectorPurpose, crypt_sector, encrypted_sector, make_content_sector_id,
    make_sector_id, synthetic_filler_sector,
};
pub use guild::{
    DynamicGuildState, DynamicMember, GUILD_EVENT_DOMAIN, GuildEvent, GuildEventKind,
    GuildEventTail, GuildStateError, LEGACY_CODING_ADD_BINDING_DOMAIN, LegacyCodingAddStatement,
    MAX_GUILD_EVENT_TAIL, QuorumGuildEvent, QuorumLegacyCodingAddBinding, QuorumPolicy, QuorumRule,
    RecoveryEpochSecret, RecoveryKeyEnvelope, RecoveryKeyEpoch, RetainedCodingGroup,
    WriterKeyEpoch, create_recovery_key_envelope, open_recovery_key_envelope, sign_guild_event,
    sign_legacy_coding_add_binding, verify_guild_event_signature,
    verify_legacy_coding_add_signature,
};
pub use keys::{
    DatabaseKeyError, KeyIdentityError, KeyMaterial, NodeId, RecoveryPublicKey, Seed,
    SeedParseError, WrappedDatabaseKey,
};
pub use model::{
    CheckpointAuthority, CodingGroup, CodingGroupId, CodingGroupV2, EndpointRecord,
    GuildCheckpoint, GuildGenesis, GuildInvite, InformationRole, InformationRoleV2, Member,
    MemberSignature, ModelError, ParityRole, ParityRoleV2, QuorumCheckpoint, QuorumGuildGenesis,
    RangeSectorRef, RecoveryBundle, RevisionTombstone, SectorId, SectorRef, ShardRole, ShardRoleV2,
    SignedRecord, StorageAcknowledgement, USER_REVISION_DOMAIN, UserRevision, WriterFence,
    canonical_bytes, coding_group_id, coding_group_v2_id, decode_canonical,
};
pub use packing::{
    AuthenticatedPackingSource, LEGACY_PACKING_ATTESTATION_DOMAIN, LEGACY_PACKING_BINDING_DOMAIN,
    LegacyPackingAttestation, LegacyPackingBinding, PackedCatalog, PackedSector,
    PackedSectorDescriptor, PackedSlot, PackedSourceAuthentication, PackedSourceChunk,
    PackingError, PackingInput, PackingMetrics, PackingProfile, PackingResult, PackingUpdate,
    SourceChunkId, attach_legacy_packing_bindings, attach_legacy_packing_evidence,
    pack_incremental, pack_incremental_authenticated, packing_protected_root, unpack_object,
    unpack_object_from_sectors,
};
pub use range::{
    MERKLE_LEAF_SIZE, MERKLE_SUITE_V1, MerkleCommitment, MerkleError, MerkleRangeProof,
    MerkleSubtreeProof, challenged_leaf, merkle_commit, merkle_commit_subtrees, merkle_open_range,
    merkle_open_subtree, merkle_open_zero_range, merkle_verify_range, merkle_verify_subtree,
    merkle_zero_commitment,
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
/// Current flat capture reserves room for the largest metadata vector. These
/// limits describe the prototype format, not the paged 1 TiB release target.
pub const V1_MAX_CAPTURE_METADATA_SECTORS: usize = V1_MAX_CATALOG_BYTES.div_ceil(V1_SECTOR_SIZE);
pub const V1_MAX_CAPTURE_DATA_SECTORS: usize =
    V1_MAX_CODING_GROUPS - V1_MAX_CAPTURE_METADATA_SECTORS;

/// Hash bytes exactly as they are consumed by Reed--Solomon.
pub fn sector_root(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
