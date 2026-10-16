//! Authenticated local native-I/O policy metadata. Decoding this record does
//! not enroll writers, reserve space, or authorize an existing catalog upgrade.
use super::{DatabaseKeyError, KeyMaterial, WrappedDatabaseKey, derive_with_context};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const CHUNK: u64 = 64 * 1024;
const POLICY_BYTES: usize = 70;
const PLAINTEXT_BYTES: usize = 32 + POLICY_BYTES;
const CIPHERTEXT_BYTES: usize = PLAINTEXT_BYTES + 16;
const CONTEXT: &[u8] = b"local/database-key-wrap/native-io/v2";

/// Immutable runtime native SQL file ceilings carried with a database key.
/// The nonzero policy identity binds subsequent ownership/enrollment records.
/// These ceilings do not establish persistent birth, old-writer quiescence,
/// aggregate/enclosing reservations or filesystem capability by themselves.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeDatabaseIoPolicy {
    pub format_version: u16,
    pub policy_id: [u8; 16],
    pub main_bytes: u64,
    pub journal_bytes: u64,
    pub shm_bytes: u64,
    pub temporary_bytes: u64,
    pub total_bytes: u64,
    pub headroom_bytes: u64,
    pub files: u32,
}

impl NativeDatabaseIoPolicy {
    pub fn validate(&self) -> Result<(), DatabaseKeyError> {
        if self.format_version != 1
            || self.policy_id == [0; 16]
            || self.files == 0
            || self.files > 64
            || self.total_bytes > i64::MAX as u64
            || !self.total_bytes.is_multiple_of(CHUNK)
            || [
                self.main_bytes,
                self.journal_bytes,
                self.shm_bytes,
                self.temporary_bytes,
            ]
            .into_iter()
            .any(|n| n < CHUNK || !n.is_multiple_of(CHUNK) || n > self.total_bytes)
        {
            return Err(DatabaseKeyError::InvalidEnvelope);
        }
        Ok(())
    }

    fn encode(&self, bytes: &mut [u8]) -> Result<(), DatabaseKeyError> {
        self.validate()?;
        if bytes.len() != POLICY_BYTES {
            return Err(DatabaseKeyError::InvalidEnvelope);
        }
        bytes[..2].copy_from_slice(&self.format_version.to_be_bytes());
        bytes[2..18].copy_from_slice(&self.policy_id);
        for (chunk, value) in bytes[18..66].as_chunks_mut::<8>().0.iter_mut().zip([
            self.main_bytes,
            self.journal_bytes,
            self.shm_bytes,
            self.temporary_bytes,
            self.total_bytes,
            self.headroom_bytes,
        ]) {
            chunk.copy_from_slice(&value.to_be_bytes());
        }
        bytes[66..].copy_from_slice(&self.files.to_be_bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, DatabaseKeyError> {
        if bytes.len() != POLICY_BYTES {
            return Err(DatabaseKeyError::InvalidEnvelope);
        }
        let word =
            |start| u64::from_be_bytes(bytes[start..start + 8].try_into().expect("fixed field"));
        let policy = Self {
            format_version: u16::from_be_bytes(bytes[..2].try_into().expect("fixed field")),
            policy_id: bytes[2..18].try_into().expect("fixed field"),
            main_bytes: word(18),
            journal_bytes: word(26),
            shm_bytes: word(34),
            temporary_bytes: word(42),
            total_bytes: word(50),
            headroom_bytes: word(58),
            files: u32::from_be_bytes(bytes[66..].try_into().expect("fixed field")),
        };
        policy.validate()?;
        Ok(policy)
    }
}

impl KeyMaterial {
    /// Seal a key and its native I/O policy in local envelope version 2.
    /// Existing generic unwrap deliberately rejects this format. Callers must
    /// explicitly retain and enforce the authenticated policy before SQL opens.
    pub fn wrap_native_database_key(
        &self,
        database_id: &[u8],
        database_key: &[u8; 32],
        policy: &NativeDatabaseIoPolicy,
    ) -> Result<WrappedDatabaseKey, DatabaseKeyError> {
        let mut plaintext = Zeroizing::new([0u8; PLAINTEXT_BYTES]);
        plaintext[..32].copy_from_slice(database_key);
        policy.encode(&mut plaintext[32..])?;
        let wrapping_key =
            Zeroizing::new(derive_with_context(&self.storage_key, CONTEXT, database_id));
        let cipher = ChaCha20Poly1305::new((&*wrapping_key).into());
        let mut nonce = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext[..],
                    aad: database_id,
                },
            )
            .map_err(|_| DatabaseKeyError::Encryption)?;
        Ok(WrappedDatabaseKey {
            format_version: 2,
            nonce,
            ciphertext,
        })
    }

    /// Decode exactly the authenticated native format, returning both values.
    /// Plaintext and temporary wrapping-key storage are cleared on return.
    pub fn unwrap_native_database_key(
        &self,
        database_id: &[u8],
        envelope: &WrappedDatabaseKey,
    ) -> Result<([u8; 32], NativeDatabaseIoPolicy), DatabaseKeyError> {
        if envelope.format_version != 2 || envelope.ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(DatabaseKeyError::InvalidEnvelope);
        }
        let wrapping_key =
            Zeroizing::new(derive_with_context(&self.storage_key, CONTEXT, database_id));
        let cipher = ChaCha20Poly1305::new((&*wrapping_key).into());
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    Nonce::from_slice(&envelope.nonce),
                    Payload {
                        msg: &envelope.ciphertext,
                        aad: database_id,
                    },
                )
                .map_err(|_| DatabaseKeyError::InvalidEnvelope)?,
        );
        if plaintext.len() != PLAINTEXT_BYTES {
            return Err(DatabaseKeyError::InvalidEnvelope);
        }
        let policy = NativeDatabaseIoPolicy::decode(&plaintext[32..])?;
        let key = plaintext[..32]
            .try_into()
            .map_err(|_| DatabaseKeyError::InvalidEnvelope)?;
        Ok((key, policy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Seed, canonical_bytes_bounded};

    fn policy() -> NativeDatabaseIoPolicy {
        NativeDatabaseIoPolicy {
            format_version: 1,
            policy_id: [4; 16],
            main_bytes: 16 * CHUNK,
            journal_bytes: 32 * CHUNK,
            shm_bytes: CHUNK,
            temporary_bytes: 8 * CHUNK,
            total_bytes: 64 * CHUNK,
            headroom_bytes: 19 * CHUNK,
            files: 16,
        }
    }

    #[test]
    fn native_policy_key_round_trip_requires_explicit_dispatch_and_original_context() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let policy = policy();
        let envelope = keys
            .wrap_native_database_key(b"parity/volume-a", &[91; 32], &policy)
            .unwrap();
        assert_eq!(envelope.format_version, 2);
        assert_eq!(envelope.ciphertext.len(), 118);
        assert_eq!(
            keys.unwrap_native_database_key(b"parity/volume-a", &envelope)
                .unwrap(),
            ([91; 32], policy)
        );
        assert!(
            keys.unwrap_database_key(b"parity/volume-a", &envelope)
                .is_err()
        );
        assert!(
            keys.unwrap_native_database_key(b"parity/volume-b", &envelope)
                .is_err()
        );
        assert!(
            KeyMaterial::from_seed(&Seed::from_bytes([74; 32]))
                .unwrap_native_database_key(b"parity/volume-a", &envelope)
                .is_err()
        );
        for index in 0..envelope.ciphertext.len() {
            let mut changed = envelope.clone();
            changed.ciphertext[index] ^= 1;
            assert!(
                keys.unwrap_native_database_key(b"parity/volume-a", &changed)
                    .is_err(),
                "byte {index}"
            );
        }
        let mut changed = envelope.clone();
        changed.nonce[0] ^= 1;
        assert!(
            keys.unwrap_native_database_key(b"parity/volume-a", &changed)
                .is_err()
        );
        for version in [0, 1, 3, u16::MAX] {
            let mut changed = envelope.clone();
            changed.format_version = version;
            assert!(
                keys.unwrap_native_database_key(b"parity/volume-a", &changed)
                    .is_err()
            );
            assert!(
                keys.unwrap_database_key(b"parity/volume-a", &changed)
                    .is_err()
            );
        }
        for length in [0, 48, 117, 119, 1024] {
            let mut changed = envelope.clone();
            changed.ciphertext.resize(length, 0);
            assert!(
                keys.unwrap_native_database_key(b"parity/volume-a", &changed)
                    .is_err()
            );
        }
    }

    #[test]
    fn native_policy_rejects_invalid_limits_and_retains_full_width_capacity_fields() {
        let invalid: &[fn(&mut NativeDatabaseIoPolicy)] = &[
            |p| p.format_version = 2,
            |p| p.policy_id = [0; 16],
            |p| p.files = 0,
            |p| p.files = 65,
            |p| p.main_bytes = 0,
            |p| p.journal_bytes = CHUNK - 1,
            |p| p.shm_bytes = 0,
            |p| p.temporary_bytes = p.total_bytes + CHUNK,
            |p| p.total_bytes = 0,
            |p| p.total_bytes += 1,
            |p| p.total_bytes = i64::MAX as u64 + 1,
        ];
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        for change in invalid {
            let mut p = policy();
            change(&mut p);
            assert!(p.validate().is_err());
            assert!(
                keys.wrap_native_database_key(b"control.db/v2", &[91; 32], &p)
                    .is_err()
            );
        }
        let mut p = policy();
        p.total_bytes = (i64::MAX as u64) / CHUNK * CHUNK;
        p.main_bytes = p.total_bytes;
        p.journal_bytes = p.total_bytes;
        p.shm_bytes = p.total_bytes;
        p.temporary_bytes = p.total_bytes;
        p.files = 64;
        p.headroom_bytes = u64::MAX;
        let envelope = keys
            .wrap_native_database_key(b"control.db/v2", &[91; 32], &p)
            .unwrap();
        assert_eq!(
            keys.unwrap_native_database_key(b"control.db/v2", &envelope)
                .unwrap(),
            ([91; 32], p)
        );
    }

    #[test]
    fn authenticated_malformed_native_policy_never_returns_a_database_key() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let database_id = b"control.db/v2";
        let mut valid = [0u8; PLAINTEXT_BYTES];
        valid[..32].copy_from_slice(&[91; 32]);
        policy().encode(&mut valid[32..]).unwrap();
        let cipher = ChaCha20Poly1305::new(
            (&derive_with_context(&keys.storage_key, CONTEXT, database_id)).into(),
        );
        for field in [0usize, 2, 18, 50, 66] {
            let nonce = [field as u8 + 1; 12];
            let mut bytes = valid;
            match field {
                0 => bytes[32..34].copy_from_slice(&2u16.to_be_bytes()),
                2 => bytes[34..50].fill(0),
                18 => bytes[50..58].copy_from_slice(&1u64.to_be_bytes()),
                50 => bytes[82..90].copy_from_slice(&u64::MAX.to_be_bytes()),
                66 => bytes[98..102].fill(0),
                _ => unreachable!(),
            }
            let ciphertext = cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &bytes,
                        aad: database_id,
                    },
                )
                .unwrap();
            let envelope = WrappedDatabaseKey {
                format_version: 2,
                nonce,
                ciphertext,
            };
            assert!(
                keys.unwrap_native_database_key(database_id, &envelope)
                    .is_err(),
                "field {field}"
            );
        }
    }

    #[test]
    fn original_v1_envelope_and_canonical_bytes_remain_readable() {
        // Generated by the already-qualified pre-policy Core library. The
        // exact probe/source/library hashes remain in its external evidence.
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let envelope = WrappedDatabaseKey {
            format_version: 1,
            nonce: [209, 45, 24, 85, 127, 90, 86, 238, 128, 232, 251, 4],
            ciphertext: vec![
                164, 233, 243, 53, 56, 51, 132, 153, 244, 54, 163, 36, 52, 208, 16, 55, 68, 67,
                102, 35, 174, 72, 248, 4, 135, 228, 224, 207, 34, 156, 178, 176, 75, 99, 104, 17,
                77, 116, 48, 76, 134, 81, 205, 204, 249, 230, 13, 24,
            ],
        };
        assert_eq!(
            keys.unwrap_database_key(b"parity/volume-a", &envelope)
                .unwrap(),
            [91; 32]
        );
        assert!(
            keys.unwrap_native_database_key(b"parity/volume-a", &envelope)
                .is_err()
        );
        assert_eq!(canonical_bytes_bounded(&envelope,256).unwrap(),hex::decode("01d12d18557f5a56ee80e8fb0430a4e9f33538338499f436a32434d0103744436623ae48f80487e4e0cf229cb2b04b6368114d74304c8651cdccf9e60d18").unwrap());
    }
}
