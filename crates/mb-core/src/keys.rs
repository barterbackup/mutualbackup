use std::fmt;
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Params, Version};
use bip39::{Language, Mnemonic};
use data_encoding::BASE32_NOPAD;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const RECOVERY_STRING_MIN_CHARS: usize = 8;
const RECOVERY_STRING_MAX_CHARS: usize = 1024;
const RECOVERY_STRING_MIN_BITS: f64 = 64.0;
const RECOVERY_ARGON_MEMORY_KIB: u32 = 64 * 1024;
const RECOVERY_ARGON_PASSES: u32 = 3;
const RECOVERY_ARGON_LANES: u32 = 4;
const LOG2_10: f64 = std::f64::consts::LOG2_10;

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

impl NodeId {
    pub fn libp2p_peer_id(&self) -> Result<libp2p_identity::PeerId, KeyIdentityError> {
        let public = libp2p_identity::ed25519::PublicKey::try_from_bytes(&self.0)?;
        Ok(libp2p_identity::PublicKey::from(public).to_peer_id())
    }

    /// Return the v3 onion hostname whose identity key is this Node ID.
    pub fn onion_hostname(&self) -> String {
        onion_hostname_from_public_key(&self.0)
    }
}

/// Public key used to encrypt cold-recovery locators and key envelopes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryPublicKey(pub [u8; 32]);

impl RecoveryPublicKey {
    pub fn is_contributory(&self) -> bool {
        let probe = StaticSecret::from([0x5a; 32]);
        probe
            .diffie_hellman(&X25519PublicKey::from(self.0))
            .was_contributory()
    }
}

/// Derived high-entropy root secret used by the deterministic key hierarchy.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Seed([u8; 32]);

impl Seed {
    /// Generate a 24-word English phrase. BIP39 is used only as a well-reviewed
    /// word generator; parsing and checksum semantics are deliberately not part
    /// of MutualBackup's recovery-string contract.
    pub fn generate_recovery_string() -> Result<Zeroizing<String>, SeedParseError> {
        let mnemonic =
            Mnemonic::generate_in(Language::English, 24).map_err(|_| SeedParseError::Generation)?;
        let phrase = Zeroizing::new(mnemonic.to_string());
        // Keep generation subject to the exact same policy as user input.
        Self::from_recovery_string(&phrase)?;
        Ok(phrase)
    }

    /// Construct a raw derived root. This is for deterministic protocol tests
    /// and for the already-derived local unlock wire value.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_recovery_bytes(value: &[u8]) -> Result<Self, SeedParseError> {
        let value = std::str::from_utf8(value).map_err(|_| SeedParseError::InvalidUtf8)?;
        Self::from_recovery_string(value)
    }

    pub fn from_recovery_string(value: &str) -> Result<Self, SeedParseError> {
        let normalized = normalize_recovery_string(value)?;
        if !recovery_strength_is_acceptable(&normalized) {
            return Err(SeedParseError::TooWeak);
        }

        let salt_material = Zeroizing::new(blake3::derive_key(
            "mutualbackup recovery string argon2 salt v1",
            normalized.as_bytes(),
        ));
        let params = Params::new(
            RECOVERY_ARGON_MEMORY_KIB,
            RECOVERY_ARGON_PASSES,
            RECOVERY_ARGON_LANES,
            Some(32),
        )
        .expect("fixed recovery Argon2 parameters are valid");
        let mut root = [0_u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
            .hash_password_into(normalized.as_bytes(), &salt_material[..16], &mut root)
            .expect("fixed recovery Argon2 output and salt lengths are valid");
        Ok(Self(root))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
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
        Self::from_recovery_string(value)
    }
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SeedParseError {
    #[error("recovery string is not valid UTF-8")]
    InvalidUtf8,
    #[error("recovery string must contain 8 to 1024 non-whitespace characters")]
    Length,
    #[error("recovery string may contain only printable ASCII characters and whitespace")]
    NonPrintable,
    #[error("recovery string has less than 64 bits of estimated guessing resistance")]
    TooWeak,
    #[error("could not generate a recovery string")]
    Generation,
}

fn normalize_recovery_string(value: &str) -> Result<Zeroizing<String>, SeedParseError> {
    let normalized = Zeroizing::new(
        value
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect::<String>(),
    );
    let length = normalized.chars().count();
    if !(RECOVERY_STRING_MIN_CHARS..=RECOVERY_STRING_MAX_CHARS).contains(&length) {
        return Err(SeedParseError::Length);
    }
    if !normalized
        .chars()
        .all(|character| character.is_ascii_graphic())
    {
        return Err(SeedParseError::NonPrintable);
    }
    Ok(normalized)
}

fn recovery_strength_is_acceptable(normalized: &str) -> bool {
    strength_log10_is_acceptable(zxcvbn::zxcvbn(normalized, &[]).guesses_log10())
}

fn strength_log10_is_acceptable(guesses_log10: f64) -> bool {
    let estimated_bits = guesses_log10 * LOG2_10;
    estimated_bits.is_finite() && estimated_bits >= RECOVERY_STRING_MIN_BITS
}

#[derive(Debug, Error)]
pub enum KeyIdentityError {
    #[error("invalid libp2p identity key: {0}")]
    Libp2p(#[from] libp2p_identity::DecodingError),
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

    pub fn libp2p_keypair(&self) -> libp2p_identity::Keypair {
        libp2p_identity::Keypair::ed25519_from_bytes(self.signing.to_bytes())
            .expect("an Ed25519 signing key is always a valid libp2p identity key")
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
        self.node_id().onion_hostname()
    }

    /// Copy the common Ed25519 identity seed into a short-lived zeroizing
    /// buffer for Arti's in-memory hidden-service key injection.
    pub fn onion_identity_seed(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.signing.to_bytes())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_string_policy_and_derivation_are_stable() {
        let compact = "correct-horse-battery-staple-2026!";
        let spaced = "correct-\u{a0}horse-\tbattery-\nstaple-2026!";
        let vector = include_str!("../../../protocol/vectors/recovery-string-kdf.txt");
        let vector_value = |name: &str| {
            vector
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap()
        };
        assert_eq!(vector_value("input"), compact);
        assert_eq!(vector_value("normalized"), compact);
        assert_eq!(vector_value("argon2id_version"), "19");
        assert_eq!(
            vector_value("memory_kib"),
            RECOVERY_ARGON_MEMORY_KIB.to_string()
        );
        assert_eq!(vector_value("passes"), RECOVERY_ARGON_PASSES.to_string());
        assert_eq!(vector_value("lanes"), RECOVERY_ARGON_LANES.to_string());
        let compact_seed = Seed::from_recovery_string(compact).unwrap();
        assert_eq!(
            compact_seed.expose(),
            Seed::from_recovery_string(spaced).unwrap().expose()
        );
        assert_eq!(hex::encode(compact_seed.expose()), vector_value("root"));
        let keys = KeyMaterial::from_seed(&compact_seed);
        assert_eq!(keys.node_id().to_string(), vector_value("node_id"));
        assert_eq!(
            keys.node_id().libp2p_peer_id().unwrap().to_string(),
            vector_value("libp2p_peer_id")
        );
        assert_eq!(
            hex::encode(keys.recovery_public_key().0),
            vector_value("recovery_public_key")
        );
        assert_eq!(
            Seed::from_recovery_bytes(b"not-utf8-\xff").unwrap_err(),
            SeedParseError::InvalidUtf8
        );
        assert_eq!(
            Seed::from_recovery_string("short").unwrap_err(),
            SeedParseError::Length
        );
        assert_eq!(
            Seed::from_recovery_string("printable-but-emoji-\u{1f512}-and-long").unwrap_err(),
            SeedParseError::NonPrintable
        );
        assert_eq!(
            Seed::from_recovery_string("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap_err(),
            SeedParseError::TooWeak
        );
    }

    #[test]
    fn generated_recovery_strings_pass_the_common_policy() {
        let phrase = Seed::generate_recovery_string().unwrap();
        assert_eq!(phrase.split_ascii_whitespace().count(), 24);
        Seed::from_recovery_string(&phrase).unwrap();
    }

    #[test]
    fn normalization_removes_every_rust_unicode_whitespace_class() {
        let whitespace = [
            '\u{0009}', '\u{000a}', '\u{000b}', '\u{000c}', '\u{000d}', '\u{0020}', '\u{0085}',
            '\u{00a0}', '\u{1680}', '\u{2000}', '\u{2001}', '\u{2002}', '\u{2003}', '\u{2004}',
            '\u{2005}', '\u{2006}', '\u{2007}', '\u{2008}', '\u{2009}', '\u{200a}', '\u{2028}',
            '\u{2029}', '\u{202f}', '\u{205f}', '\u{3000}',
        ];
        let mut value = String::from("abcd");
        value.extend(whitespace);
        value.push_str("EFGH");
        assert_eq!(
            normalize_recovery_string(&value).unwrap().as_str(),
            "abcdEFGH"
        );
        assert_eq!(
            normalize_recovery_string("1234567").unwrap_err(),
            SeedParseError::Length
        );
        assert_eq!(
            normalize_recovery_string(&"a".repeat(1025)).unwrap_err(),
            SeedParseError::Length
        );
        assert_eq!(
            normalize_recovery_string("abcdefgh\u{200b}").unwrap_err(),
            SeedParseError::NonPrintable
        );
    }

    #[test]
    fn strength_threshold_is_exactly_sixty_four_bits() {
        let boundary = RECOVERY_STRING_MIN_BITS / LOG2_10;
        assert!(strength_log10_is_acceptable(boundary));
        assert!(!strength_log10_is_acceptable(f64::from_bits(
            boundary.to_bits() - 1
        )));
        assert!(!strength_log10_is_acceptable(f64::NAN));
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
        let libp2p_keypair = first.libp2p_keypair();
        assert_eq!(
            first.node_id().libp2p_peer_id().unwrap(),
            libp2p_keypair.public().to_peer_id()
        );
    }
}
