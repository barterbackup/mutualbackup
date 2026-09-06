use std::fmt;
use std::str::FromStr;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SEED_PREFIX: &str = "mbseed1";

/// Stable public node identity used by every transport.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for NodeId {
    type Err = hex::FromHexError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(value, &mut bytes)?;
        Ok(Self(bytes))
    }
}

/// Public key used to encrypt cold-recovery locators and key envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPublicKey(pub [u8; 32]);

/// High-entropy recovery seed. Its textual form is versioned and checksummed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

impl Seed {
    pub fn generate() -> Self {
        let mut bytes = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn encode(&self) -> String {
        let payload = hex::encode(self.0);
        let checksum = blake3::derive_key("mutualbackup seed checksum v1", &self.0);
        format!("{SEED_PREFIX}-{payload}-{}", hex::encode(&checksum[..4]))
    }
}

impl fmt::Debug for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Seed(REDACTED)")
    }
}

impl FromStr for Seed {
    type Err = SeedParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let mut fields = value.split('-');
        if fields.next() != Some(SEED_PREFIX) {
            return Err(SeedParseError::Version);
        }
        let payload = fields.next().ok_or(SeedParseError::Shape)?;
        let checksum = fields.next().ok_or(SeedParseError::Shape)?;
        if fields.next().is_some() || checksum.len() != 8 {
            return Err(SeedParseError::Shape);
        }
        let mut bytes = [0_u8; 32];
        hex::decode_to_slice(payload, &mut bytes).map_err(|_| SeedParseError::Encoding)?;
        let expected = blake3::derive_key("mutualbackup seed checksum v1", &bytes);
        if !constant_time_eq(checksum.as_bytes(), hex::encode(&expected[..4]).as_bytes()) {
            return Err(SeedParseError::Checksum);
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SeedParseError {
    #[error("unsupported recovery-seed version")]
    Version,
    #[error("invalid recovery-seed shape")]
    Shape,
    #[error("invalid recovery-seed encoding")]
    Encoding,
    #[error("recovery-seed checksum mismatch")]
    Checksum,
}

/// Domain-separated keys deterministically recoverable from one seed.
pub struct KeyMaterial {
    signing: SigningKey,
    recovery_secret: StaticSecret,
    storage_key: [u8; 32],
}

impl KeyMaterial {
    pub fn from_seed(seed: &Seed) -> Self {
        let signing = SigningKey::from_bytes(&derive(seed.expose(), b"identity/ed25519"));
        let recovery_secret = StaticSecret::from(derive(seed.expose(), b"recovery/x25519"));
        let storage_key = derive(seed.expose(), b"local/storage-root");
        Self {
            signing,
            recovery_secret,
            storage_key,
        }
    }

    pub fn node_id(&self) -> NodeId {
        NodeId(self.signing.verifying_key().to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing.verifying_key()
    }

    pub fn recovery_public_key(&self) -> RecoveryPublicKey {
        RecoveryPublicKey(X25519PublicKey::from(&self.recovery_secret).to_bytes())
    }

    pub fn recovery_secret(&self) -> &StaticSecret {
        &self.recovery_secret
    }

    pub fn storage_key(&self) -> &[u8; 32] {
        &self.storage_key
    }

    pub fn database_key(&self, database_id: &[u8]) -> [u8; 32] {
        derive_with_context(&self.storage_key, b"local/database/v1", database_id)
    }

    pub fn guild_data_key(&self, guild_id: &[u8; 32]) -> [u8; 32] {
        derive_with_context(self.signing.as_bytes(), b"guild/data/v1", guild_id)
    }

    pub fn sign(&self, domain: &'static [u8], bytes: &[u8]) -> [u8; 64] {
        self.signing
            .sign(&signing_payload(domain, bytes))
            .to_bytes()
    }

    pub fn onion_hostname(&self) -> String {
        onion_hostname_from_public_key(&self.signing.verifying_key().to_bytes())
    }
}

impl Drop for KeyMaterial {
    fn drop(&mut self) {
        self.storage_key.zeroize();
    }
}

pub(crate) fn signing_payload(domain: &'static [u8], bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(4 + domain.len() + bytes.len());
    payload.extend_from_slice(&(domain.len() as u32).to_be_bytes());
    payload.extend_from_slice(domain);
    payload.extend_from_slice(bytes);
    payload
}

fn derive(seed: &[u8; 32], purpose: &[u8]) -> [u8; 32] {
    derive_with_context(seed, b"mutualbackup/v1", purpose)
}

fn derive_with_context(key: &[u8], salt: &[u8], context: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), key);
    let mut output = [0_u8; 32];
    hkdf.expand(context, &mut output)
        .expect("32-byte HKDF output is always valid");
    output
}

fn onion_hostname_from_public_key(public_key: &[u8; 32]) -> String {
    const VERSION: u8 = 3;
    let mut checksum_input = Vec::with_capacity(15 + 32 + 1);
    checksum_input.extend_from_slice(b".onion checksum");
    checksum_input.extend_from_slice(public_key);
    checksum_input.push(VERSION);
    let checksum = Sha3_256::digest(&checksum_input);

    let mut address = [0_u8; 35];
    address[..32].copy_from_slice(public_key);
    address[32..34].copy_from_slice(&checksum[..2]);
    address[34] = VERSION;
    format!(
        "{}.onion",
        BASE32_NOPAD.encode(&address).to_ascii_lowercase()
    )
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trip_and_checksum() {
        let seed = Seed::from_bytes([7; 32]);
        let encoded = seed.encode();
        assert_eq!(encoded.parse::<Seed>().unwrap().expose(), seed.expose());

        let mut damaged = encoded.into_bytes();
        *damaged.last_mut().unwrap() ^= 1;
        assert_eq!(
            String::from_utf8(damaged)
                .unwrap()
                .parse::<Seed>()
                .unwrap_err(),
            SeedParseError::Checksum
        );
    }

    #[test]
    fn identities_are_stable_and_domain_separated() {
        let seed = Seed::from_bytes([3; 32]);
        let first = KeyMaterial::from_seed(&seed);
        let second = KeyMaterial::from_seed(&seed);
        assert_eq!(first.node_id(), second.node_id());
        assert_eq!(first.recovery_public_key(), second.recovery_public_key());
        assert_ne!(first.node_id().0, first.recovery_public_key().0);
        assert_eq!(first.onion_hostname(), second.onion_hostname());
        assert!(first.onion_hostname().ends_with(".onion"));
    }
}
