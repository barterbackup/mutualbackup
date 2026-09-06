//! Deterministic protocol primitives for MutualBackup.
//!
//! This crate deliberately has no network, filesystem, clock, or database
//! dependencies. The async runtime surrounds these synchronous state and
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
pub use keys::{KeyMaterial, NodeId, RecoveryPublicKey, Seed, SeedParseError};
pub use model::{
    CodingGroup, CodingGroupId, GuildCheckpoint, InformationRole, Member, MemberSignature,
    ModelError, ParityRole, QuorumCheckpoint, SectorId, SectorRef, ShardRole, SignedRecord,
    UserRevision, canonical_bytes, decode_canonical,
};
pub use recovery::{
    RecoveryCryptoError, RecoveryLocator, SealedRecoveryRecord, open_recovery_record,
    seal_recovery_record,
};

/// The only sector size accepted by the first protocol profile.
pub const V1_SECTOR_SIZE: usize = 64 * 1024;

/// Hash bytes exactly as they are consumed by Reed--Solomon.
pub fn sector_root(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}
