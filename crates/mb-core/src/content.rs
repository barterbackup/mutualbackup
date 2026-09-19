use blake3::Hasher;
use chacha20::XChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{NodeId, SectorId, SectorRef, V1_SECTOR_SIZE, sector_root};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SectorPurpose {
    Data,
    Metadata,
    SyntheticFiller,
}

impl SectorPurpose {
    fn tag(self) -> u8 {
        match self {
            Self::Data => 1,
            Self::Metadata => 2,
            Self::SyntheticFiller => 3,
        }
    }
}

#[derive(Debug, Error)]
pub enum ContentError {
    #[error("plaintext exceeds the v1 sector size")]
    TooLarge,
    #[error("ciphertext must have exactly the v1 sector size")]
    InvalidCiphertextLength,
    #[error("logical length exceeds the ciphertext length")]
    InvalidLogicalLength,
}

pub fn make_sector_id(
    owner: NodeId,
    revision_id: Uuid,
    purpose: SectorPurpose,
    ordinal: u64,
) -> SectorId {
    let mut hasher = Hasher::new_derive_key("mutualbackup sector id v1");
    hasher.update(&owner.0);
    hasher.update(revision_id.as_bytes());
    hasher.update(&[purpose.tag()]);
    hasher.update(&ordinal.to_be_bytes());
    *hasher.finalize().as_bytes()
}

/// Stable encrypted-sector identity for content-preserving revisions. The
/// guild scope separates encryption keys, and the logical length prevents two
/// differently truncated plaintexts with identical zero padding from sharing
/// a nonce. Equal IDs therefore imply equal plaintext under the same key.
pub fn make_content_sector_id(
    owner: NodeId,
    guild_id: [u8; 32],
    purpose: SectorPurpose,
    plaintext: &[u8],
) -> Result<SectorId, ContentError> {
    if plaintext.len() > V1_SECTOR_SIZE {
        return Err(ContentError::TooLarge);
    }
    let mut hasher = Hasher::new_derive_key("mutualbackup content sector id v1");
    hasher.update(&owner.0);
    hasher.update(&guild_id);
    hasher.update(&[purpose.tag()]);
    hasher.update(&(plaintext.len() as u64).to_be_bytes());
    hasher.update(plaintext);
    Ok(*hasher.finalize().as_bytes())
}

/// Pad and encrypt one protocol sector. Integrity is supplied by the signed
/// sector root, so this representation intentionally has no per-sector tag.
pub fn encrypted_sector(
    key: &[u8; 32],
    id: SectorId,
    plaintext: &[u8],
) -> Result<(SectorRef, Vec<u8>), ContentError> {
    if plaintext.len() > V1_SECTOR_SIZE {
        return Err(ContentError::TooLarge);
    }
    let mut bytes = vec![0_u8; V1_SECTOR_SIZE];
    bytes[..plaintext.len()].copy_from_slice(plaintext);
    crypt_sector(key, id, &mut bytes)?;
    let reference = SectorRef {
        id,
        root: sector_root(&bytes),
        logical_len: plaintext.len() as u32,
    };
    Ok((reference, bytes))
}

pub fn crypt_sector(key: &[u8; 32], id: SectorId, bytes: &mut [u8]) -> Result<(), ContentError> {
    if bytes.len() != V1_SECTOR_SIZE {
        return Err(ContentError::InvalidCiphertextLength);
    }
    let nonce_material = blake3::derive_key("mutualbackup sector nonce v1", &id);
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&nonce_material[..24]);
    XChaCha20::new(key.into(), (&nonce).into()).apply_keystream(bytes);
    Ok(())
}

/// Deterministic, storage-free helper shard used by the first prototype when
/// only one guild member has pending user data. It is replaced by another
/// member's real information sector whenever one is available.
pub fn synthetic_filler_sector(
    key: &[u8; 32],
    owner: NodeId,
    revision_id: Uuid,
    ordinal: u64,
) -> Result<(SectorRef, Vec<u8>), ContentError> {
    let id = make_sector_id(owner, revision_id, SectorPurpose::SyntheticFiller, ordinal);
    encrypted_sector(key, id, &[])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_encryption_round_trips_and_is_root_bound() {
        let owner = NodeId([5; 32]);
        let id = make_sector_id(owner, Uuid::from_u128(12), SectorPurpose::Data, 7);
        let (reference, mut encrypted) = encrypted_sector(&[9; 32], id, b"hello").unwrap();
        assert_eq!(encrypted.len(), V1_SECTOR_SIZE);
        assert_eq!(sector_root(&encrypted), reference.root);
        assert!(!encrypted.starts_with(b"hello"));
        crypt_sector(&[9; 32], id, &mut encrypted).unwrap();
        assert_eq!(&encrypted[..5], b"hello");
        assert!(encrypted[5..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn guild_keys_produce_distinct_ciphertext() {
        let id = [4; 32];
        let (_, first) = encrypted_sector(&[1; 32], id, b"same").unwrap();
        let (_, second) = encrypted_sector(&[2; 32], id, b"same").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn content_sector_ids_reuse_nonces_only_for_identical_plaintext() {
        let owner = NodeId([8; 32]);
        let guild = [7; 32];
        let first = make_content_sector_id(owner, guild, SectorPurpose::Data, b"same").unwrap();
        assert_eq!(
            first,
            make_content_sector_id(owner, guild, SectorPurpose::Data, b"same").unwrap()
        );
        assert_ne!(
            first,
            make_content_sector_id(owner, guild, SectorPurpose::Data, b"same\0").unwrap()
        );
        assert_ne!(
            first,
            make_content_sector_id(owner, guild, SectorPurpose::Metadata, b"same").unwrap()
        );
        assert_ne!(
            first,
            make_content_sector_id(owner, [6; 32], SectorPurpose::Data, b"same").unwrap()
        );
    }
}
