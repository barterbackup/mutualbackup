use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

use crate::{KeyMaterial, NodeId, RecoveryPublicKey};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryLocator {
    pub format_version: u16,
    pub subject: NodeId,
    pub publisher: NodeId,
    pub guild_id: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_generation: u64,
    pub endpoints: Vec<String>,
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SealedRecoveryRecord {
    pub format_version: u16,
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Error)]
pub enum RecoveryCryptoError {
    #[error("unsupported recovery-record format")]
    Version,
    #[error("recovery-record encryption failed")]
    Encrypt,
    #[error("recovery-record authentication failed")]
    Authentication,
}

pub fn seal_recovery_record(
    recipient: RecoveryPublicKey,
    plaintext: &[u8],
) -> Result<SealedRecoveryRecord, RecoveryCryptoError> {
    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
    let recipient_public = X25519PublicKey::from(recipient.0);
    let shared_secret = ephemeral_secret.diffie_hellman(&recipient_public);
    if !shared_secret.was_contributory() {
        return Err(RecoveryCryptoError::Authentication);
    }
    let key = recovery_aead_key(
        shared_secret.as_bytes(),
        &ephemeral_public.to_bytes(),
        &recipient.0,
    );
    let cipher = XChaCha20Poly1305::new((&key).into());
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let associated = associated_data(&ephemeral_public.to_bytes(), &recipient.0);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &associated,
            },
        )
        .map_err(|_| RecoveryCryptoError::Encrypt)?;
    Ok(SealedRecoveryRecord {
        format_version: 1,
        ephemeral_public_key: ephemeral_public.to_bytes(),
        nonce,
        ciphertext,
    })
}

pub fn open_recovery_record(
    keys: &KeyMaterial,
    record: &SealedRecoveryRecord,
) -> Result<Vec<u8>, RecoveryCryptoError> {
    if record.format_version != 1 {
        return Err(RecoveryCryptoError::Version);
    }
    let ephemeral_public = X25519PublicKey::from(record.ephemeral_public_key);
    let recipient_public = keys.recovery_public_key();
    let shared_secret = keys.recovery_secret().diffie_hellman(&ephemeral_public);
    if !shared_secret.was_contributory() {
        return Err(RecoveryCryptoError::Authentication);
    }
    let key = recovery_aead_key(
        shared_secret.as_bytes(),
        &record.ephemeral_public_key,
        &recipient_public.0,
    );
    let cipher = XChaCha20Poly1305::new((&key).into());
    let associated = associated_data(&record.ephemeral_public_key, &recipient_public.0);
    cipher
        .decrypt(
            XNonce::from_slice(&record.nonce),
            Payload {
                msg: &record.ciphertext,
                aad: &associated,
            },
        )
        .map_err(|_| RecoveryCryptoError::Authentication)
}

fn recovery_aead_key(
    shared_secret: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &[u8; 32],
) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(b"mutualbackup recovery record v1"), shared_secret);
    let associated = associated_data(ephemeral, recipient);
    let mut key = [0_u8; 32];
    hkdf.expand(&associated, &mut key)
        .expect("32-byte HKDF output is always valid");
    key
}

fn associated_data(ephemeral: &[u8; 32], recipient: &[u8; 32]) -> Vec<u8> {
    let mut associated = b"mutualbackup/recovery-record/v1".to_vec();
    associated.extend_from_slice(ephemeral);
    associated.extend_from_slice(recipient);
    associated
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed;

    #[test]
    fn only_the_recipient_seed_opens_a_locator() {
        let recipient = KeyMaterial::from_seed(&Seed::from_bytes([1; 32]));
        let other = KeyMaterial::from_seed(&Seed::from_bytes([2; 32]));
        let sealed =
            seal_recovery_record(recipient.recovery_public_key(), b"guild locator").unwrap();
        assert_eq!(
            open_recovery_record(&recipient, &sealed).unwrap(),
            b"guild locator"
        );
        assert!(open_recovery_record(&other, &sealed).is_err());

        let mut tampered = sealed;
        tampered.ciphertext[0] ^= 1;
        assert!(open_recovery_record(&recipient, &tampered).is_err());
    }

    #[test]
    fn rejects_non_contributory_x25519_inputs() {
        let recipient = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        assert!(seal_recovery_record(RecoveryPublicKey([0; 32]), b"payload").is_err());
        let invalid = SealedRecoveryRecord {
            format_version: 1,
            ephemeral_public_key: [0; 32],
            nonce: [0; 24],
            ciphertext: vec![0; 16],
        };
        assert!(matches!(
            open_recovery_record(&recipient, &invalid),
            Err(RecoveryCryptoError::Authentication)
        ));
    }
}
