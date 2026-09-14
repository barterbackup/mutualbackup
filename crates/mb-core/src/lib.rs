//! Deterministic protocol primitives for MutualBackup.
//!
//! This crate deliberately performs no network I/O, filesystem I/O, clock, or
//! database work. The async runtime surrounds these synchronous state and
//! cryptographic operations.

mod coding;
mod content;
mod keys;
mod model;
mod recovery;

pub use coding::{CodingError, encode_3_2, reconstruct_3_2};
pub use content::{
    ContentError, SectorPurpose, crypt_sector, encrypted_sector, make_sector_id,
    synthetic_filler_sector,
};
pub use keys::{
    DatabaseKeyError, KeyIdentityError, KeyMaterial, NodeId, RecoveryPublicKey, Seed,
    SeedParseError, WrappedDatabaseKey,
};
pub use model::{
    CodingGroup, CodingGroupId, EndpointRecord, GuildCheckpoint, GuildGenesis, GuildInvite,
    InformationRole, Member, MemberSignature, ModelError, ParityRole, QuorumCheckpoint,
    QuorumGuildGenesis, RecoveryBundle, RevisionTombstone, SectorId, SectorRef, ShardRole,
    SignedRecord, StorageAcknowledgement, USER_REVISION_DOMAIN, UserRevision, WriterFence,
    canonical_bytes, coding_group_id, decode_canonical,
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
