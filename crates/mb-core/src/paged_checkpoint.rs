//! Fixed public checkpoint envelopes. Header/quorum verification does not
//! establish body EOF, state transition, private authority or payload custody.
//! The store bridge requires the completed public join before signing/binding.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    CATALOG_CODING_DIRECTORY_ROOT_BYTES, CatalogCheckpointAuthorityRoot,
    CatalogCodingDirectoryRoot, CatalogCodingTraversalBudget, CatalogError,
    CatalogPackedSectorRoot, CatalogPackedSourceRoot, CatalogScope, CatalogSection,
    CheckpointAuthority, Member, MemberSignature, ModelError, canonical_bytes_bounded,
    decode_canonical, keys::signing_payload,
};

pub const PAGED_GUILD_CHECKPOINT_VERSION: u16 = 8;
/// Budgeted retained authority across independently bounded revision trees.
pub const PAGED_GUILD_CHECKPOINT_BUDGETED_VERSION: u16 = 9;
pub const PAGED_GUILD_CHECKPOINT_BYTES: usize = 4096;
pub const PAGED_QUORUM_CHECKPOINT_BYTES: usize = 32768;
pub const PAGED_GUILD_CHECKPOINT_DOMAIN: &[u8] = b"mutualbackup/paged-guild-checkpoint/v1";
const HASH_DOMAIN: &str = "mutualbackup paged guild checkpoint body v1";
const MEMBERS: usize = 256;

/// Independently trusted previous state identity. It can refer to a legacy or
/// paged checkpoint; the original hash is preserved across migration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagedCheckpointParent {
    pub generation: u64,
    pub hash: [u8; 32],
}

/// Obtain this bounded snapshot from independently certified guild history and
/// the trusted previous checkpoint, never from the proposed certificate. This
/// type deliberately has no wire decoder. A live signer must reread it; equality
/// here is not an atomic publication guard or proof of a legal state transition.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedCheckpointTrust {
    pub guild_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub event_sequence: u64,
    pub event_head: [u8; 32],
    pub authority: CheckpointAuthority,
    pub members: Vec<Member>,
    pub previous: Option<PagedCheckpointParent>,
}

impl PagedCheckpointTrust {
    pub fn validate(&self) -> Result<(), CatalogError> {
        CatalogScope::Guild {
            guild_id: self.guild_id,
        }
        .validate(CatalogSection::Checkpoint)?;
        if self.genesis_hash == [0; 32]
            || self.event_head == [0; 32]
            || self.event_sequence > i64::MAX as u64
            || self.authority.format_version != 1
            || self.authority.membership_epoch == 0
            || self.members.is_empty()
            || self.members.len() > MEMBERS
            || self.authority.quorum.required(self.members.len()).is_err()
            || self.previous.is_some_and(|parent| {
                parent.generation == 0
                    || parent.generation >= i64::MAX as u64
                    || parent.hash == [0; 32]
            })
        {
            return Err(CatalogError::InvalidPage);
        }
        let mut previous = None;
        for member in &self.members {
            if previous.is_some_and(|node| node >= member.node_id)
                || member.failure_domain.is_empty()
                || member.failure_domain.len() > 256
                || !member.recovery_public_key.is_contributory()
            {
                return Err(CatalogError::InvalidPage);
            }
            let key = VerifyingKey::from_bytes(&member.node_id.0).map_err(ModelError::from)?;
            if key.is_weak() {
                return Err(ModelError::WeakPublicKey.into());
            }
            previous = Some(member.node_id);
        }
        Ok(())
    }

    pub fn next_generation(&self) -> Result<u64, CatalogError> {
        self.validate()?;
        Ok(self.previous.map_or(1, |parent| parent.generation + 1))
    }
}

/// All hashes refer to public control/source ciphertext authority. Owner-private
/// plaintext root hashes stay inside their encrypted metadata sectors. Members
/// and original evidence stay behind the authenticated authority root.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PagedGuildCheckpoint {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub generation: u64,
    pub parent: Option<[u8; 32]>,
    pub event_sequence: u64,
    pub event_head: [u8; 32],
    pub authority: CheckpointAuthority,
    pub authority_root: CatalogCheckpointAuthorityRoot,
    /// Exact completed authority ledger, including nested source frames and
    /// flat legacy source entries. Header validation checks its lower bound;
    /// the completed store proof must establish exact equality before signing.
    pub authority_records: u64,
    pub packed_sectors: CatalogPackedSectorRoot,
    pub packed_sources: CatalogPackedSourceRoot,
    pub coding: CatalogCodingDirectoryRoot,
}

impl PagedGuildCheckpoint {
    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > PAGED_GUILD_CHECKPOINT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let value: Self = decode_canonical(bytes)?;
        value.validate_header(budget)?;
        if canonical_bytes_bounded(&value, PAGED_GUILD_CHECKPOINT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(value)
    }

    /// Shape and complete declared admission only. This does not fetch or
    /// authenticate any body, derive membership or grant a signing capability.
    pub fn validate_header(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogError> {
        CatalogScope::Guild {
            guild_id: self.guild_id,
        }
        .validate(CatalogSection::Checkpoint)?;
        self.authority_root.validate_with_budget(budget)?;
        self.packed_sectors.validate()?;
        self.packed_sources.validate()?;
        if !matches!(
            (self.format_version, self.authority_root.format_version),
            (PAGED_GUILD_CHECKPOINT_VERSION, 1) | (PAGED_GUILD_CHECKPOINT_BUDGETED_VERSION, 2)
        ) || self.genesis_hash == [0; 32]
            || self.event_head == [0; 32]
            || self.event_sequence > i64::MAX as u64
            || self.generation != self.authority_root.generation
            || (self.generation == 1) != self.parent.is_none()
            || self.parent == Some([0; 32])
            || self.authority.format_version != 1
            || self.authority.membership_epoch != self.authority_root.membership_epoch
            || self
                .authority
                .quorum
                .required(self.authority_root.summary.members as usize)
                .is_err()
            || self.authority_records
                < self
                    .authority_root
                    .records
                    .records
                    .checked_add(self.authority_root.summary.legacy_revisions)
                    .ok_or(CatalogError::Bounds)?
            || self.authority_records
                > self
                    .authority_root
                    .records
                    .page
                    .byte_len
                    .checked_add(self.authority_root.summary.legacy_bytes)
                    .and_then(|bytes| bytes.checked_add(self.authority_root.summary.source_bytes))
                    .ok_or(CatalogError::Bounds)?
            || self.packed_sectors.packing_version < 2
            || self.packed_sectors.profile != self.packed_sources.profile
            || self.packed_sectors.source_chunks != self.packed_sources.chunks
            || self.packed_sectors.source_bytes != self.packed_sources.ciphertext_bytes
            || self.coding.guild_event_sequence != self.event_sequence
        {
            return Err(CatalogError::InvalidPage);
        }
        // Preserve existing aggregate packing limits, including its local root
        // envelope, rather than admitting a larger pair through the new header.
        let packing_bytes = self
            .packed_sectors
            .records
            .page
            .byte_len
            .checked_add(self.packed_sources.records.page.byte_len)
            .and_then(|bytes| bytes.checked_add(2048))
            .ok_or(CatalogError::Bounds)?;
        let packing_pages = self
            .packed_sectors
            .records
            .page
            .page_occurrences
            .checked_add(self.packed_sources.records.page.page_occurrences)
            .ok_or(CatalogError::Bounds)?;
        if packing_bytes > crate::CATALOG_MAX_STREAM_BYTES
            || packing_pages > crate::CATALOG_MAX_PAGE_OCCURRENCES
        {
            return Err(CatalogError::Bounds);
        }
        self.coding.validate(budget)?;
        canonical_bytes_bounded(&self, PAGED_GUILD_CHECKPOINT_BYTES)?;
        budget.remaining_after(self.represented_work()?)?;
        Ok(())
    }

    /// One fixed certificate envelope plus every logical page/record occurrence
    /// in all public sections. Embedded root/local descriptor envelopes are not
    /// charged again. Private/payload work must be admitted separately.
    pub fn represented_work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        let mut work = CatalogCodingTraversalBudget {
            bytes: (PAGED_QUORUM_CHECKPOINT_BYTES as u64)
                .checked_add(self.authority_root.records.page.byte_len)
                .and_then(|bytes| bytes.checked_add(self.authority_root.summary.legacy_bytes))
                .and_then(|bytes| bytes.checked_add(self.authority_root.summary.source_bytes))
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self.authority_root.page_occurrences()?,
            records: self.authority_records,
        };
        for root in [self.packed_sectors.records, self.packed_sources.records] {
            work = work.checked_add(CatalogCodingTraversalBudget {
                bytes: root.page.byte_len,
                page_occurrences: root.page.page_occurrences,
                records: root.records,
            })?;
        }
        let mut coding = self.coding.work()?;
        coding.bytes = coding
            .bytes
            .checked_sub(CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64)
            .ok_or(CatalogError::Bounds)?;
        work.checked_add(coding)
    }

    pub fn validate_trust(
        self,
        trust: &PagedCheckpointTrust,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<(), CatalogError> {
        self.validate_header(budget)?;
        if self.generation != trust.next_generation()?
            || self.parent != trust.previous.map(|parent| parent.hash)
            || self.guild_id != trust.guild_id
            || self.genesis_hash != trust.genesis_hash
            || self.event_sequence != trust.event_sequence
            || self.event_head != trust.event_head
            || self.authority != trust.authority
            || self.authority_root.summary.members as usize != trust.members.len()
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    /// State identity excludes the collected signer subset. Admission and body
    /// validation remain separate; even an untrusted proposal has an identity.
    pub fn hash(self) -> Result<[u8; 32], ModelError> {
        let mut hash = blake3::Hasher::new_derive_key(HASH_DOMAIN);
        hash.update(&canonical_bytes_bounded(
            &self,
            PAGED_GUILD_CHECKPOINT_BYTES,
        )?);
        Ok(*hash.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumPagedCheckpoint {
    pub checkpoint: PagedGuildCheckpoint,
    #[serde(deserialize_with = "signatures")]
    pub signatures: Vec<MemberSignature>,
}

fn signatures<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<MemberSignature>, D::Error> {
    #[derive(Deserialize)]
    struct BoundedSignature {
        signer: crate::NodeId,
        #[serde(deserialize_with = "crate::bounded::signature")]
        signature: Vec<u8>,
    }
    Ok(crate::bounded::VecSeed::<BoundedSignature>::new(MEMBERS)
        .deserialize(decoder)?
        .into_iter()
        .map(|signature| MemberSignature {
            signer: signature.signer,
            signature: signature.signature,
        })
        .collect())
}

impl QuorumPagedCheckpoint {
    pub fn decode_header(
        bytes: &[u8],
        trust: &PagedCheckpointTrust,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > PAGED_QUORUM_CHECKPOINT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let value: Self = decode_canonical(bytes)?;
        value.verify_header(trust, budget)?;
        if canonical_bytes_bounded(&value, PAGED_QUORUM_CHECKPOINT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(value)
    }

    /// Verify the bounded quorum against independently trusted current members.
    /// A certificate alone cannot prove body EOF, exact member records, source
    /// coverage, a legal previous-state transition or durable payload ownership.
    pub fn verify_header(
        &self,
        trust: &PagedCheckpointTrust,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<(), CatalogError> {
        self.checkpoint.validate_trust(trust, budget)?;
        if self.signatures.len() > MEMBERS {
            return Err(CatalogError::Bounds);
        }
        canonical_bytes_bounded(self, PAGED_QUORUM_CHECKPOINT_BYTES)?;
        let encoded = canonical_bytes_bounded(&self.checkpoint, PAGED_GUILD_CHECKPOINT_BYTES)?;
        let payload = signing_payload(PAGED_GUILD_CHECKPOINT_DOMAIN, &encoded);
        let mut previous = None;
        for signature in &self.signatures {
            if previous.is_some_and(|signer| signer >= signature.signer)
                || trust
                    .members
                    .binary_search_by_key(&signature.signer, |member| member.node_id)
                    .is_err()
                || signature.signature.len() != 64
            {
                return Err(CatalogError::InvalidPage);
            }
            let key = VerifyingKey::from_bytes(&signature.signer.0).map_err(ModelError::from)?;
            if key.is_weak() {
                return Err(ModelError::WeakPublicKey.into());
            }
            key.verify_strict(
                &payload,
                &Signature::from_slice(&signature.signature).map_err(ModelError::from)?,
            )
            .map_err(ModelError::from)?;
            previous = Some(signature.signer);
        }
        let required = trust
            .authority
            .quorum
            .required(trust.members.len())
            .map_err(|_| CatalogError::InvalidPage)?;
        if self.signatures.len() < required {
            return Err(ModelError::InsufficientQuorum {
                actual: self.signatures.len(),
                required,
            }
            .into());
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        self.checkpoint.hash()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CatalogCodingDirectoryBuilder, CatalogPackedSectorBuilder, CatalogPackedSourceBuilder,
        KeyMaterial, PackingProfile, QuorumPolicy, QuorumRule, Seed, canonical_bytes,
    };

    fn fixture() -> (PagedGuildCheckpoint, PagedCheckpointTrust, Vec<KeyMaterial>) {
        let keys = [11, 12]
            .into_iter()
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value; 32])))
            .collect::<Vec<_>>();
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, keys)| Member {
                node_id: keys.node_id(),
                recovery_public_key: keys.recovery_public_key(),
                failure_domain: format!("domain-{index}"),
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.node_id);
        let authority_root = CatalogCheckpointAuthorityRoot::decode(
            &hex::decode(
                include_str!("../../../protocol/vectors/checkpoint-authority-v1.postcard.hex")
                    .trim(),
            )
            .unwrap(),
        )
        .unwrap();
        let trust = PagedCheckpointTrust {
            guild_id: [16; 32],
            genesis_hash: [21; 32],
            event_sequence: 100,
            event_head: [22; 32],
            authority: CheckpointAuthority {
                format_version: 1,
                membership_epoch: 2,
                quorum: QuorumPolicy {
                    format_version: 1,
                    rule: QuorumRule::Majority,
                },
            },
            members,
            previous: Some(PagedCheckpointParent {
                generation: 2,
                hash: [23; 32],
            }),
        };
        let scope = CatalogScope::Guild {
            guild_id: trust.guild_id,
        };
        let mut sink = |_: crate::CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
        let profile = PackingProfile {
            format_version: 1,
            sector_size: 65536,
            slot_size: 16384,
        };
        // Header tests intentionally do not claim a complete body/coverage join.
        // The store tests build and require the real mixed-source proof.
        let packed_sectors = CatalogPackedSectorBuilder::new_compact(scope, 5, profile)
            .unwrap()
            .finish(&mut sink)
            .unwrap();
        let packed_sources = CatalogPackedSourceBuilder::new_compact(scope, profile)
            .unwrap()
            .finish(&mut sink)
            .unwrap();
        let coding = CatalogCodingDirectoryBuilder::new(scope, 100, unlimited())
            .unwrap()
            .finish(&mut sink)
            .unwrap();
        let checkpoint = PagedGuildCheckpoint {
            format_version: 8,
            guild_id: trust.guild_id,
            genesis_hash: trust.genesis_hash,
            generation: 3,
            parent: Some([23; 32]),
            event_sequence: 100,
            event_head: trust.event_head,
            authority: trust.authority,
            authority_records: authority_root.records.records + 4,
            authority_root,
            packed_sectors,
            packed_sources,
            coding,
        };
        (checkpoint, trust, keys)
    }

    fn unlimited() -> CatalogCodingTraversalBudget {
        CatalogCodingTraversalBudget {
            bytes: u64::MAX,
            page_occurrences: u64::MAX,
            records: u64::MAX,
        }
    }
    fn certificate(
        checkpoint: PagedGuildCheckpoint,
        keys: &[KeyMaterial],
    ) -> QuorumPagedCheckpoint {
        let bytes = canonical_bytes(&checkpoint).unwrap();
        let mut signatures = keys
            .iter()
            .map(|keys| MemberSignature {
                signer: keys.node_id(),
                signature: keys.sign(PAGED_GUILD_CHECKPOINT_DOMAIN, &bytes).to_vec(),
            })
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        QuorumPagedCheckpoint {
            checkpoint,
            signatures,
        }
    }

    #[test]
    fn budgeted_checkpoint_headers_admit_history_only_under_the_supplied_full_budget() {
        let (old, trust, keys) = fixture();
        let mut checkpoint = old;
        checkpoint.format_version = PAGED_GUILD_CHECKPOINT_BUDGETED_VERSION;
        checkpoint.authority_root.format_version = 2;
        // Header admission only; the complete store proof must authenticate
        // these claimed referenced roots/EOFs before signing or retention.
        checkpoint.authority_root.summary.revisions = 33;
        checkpoint.authority_root.summary.source_bytes = 32 * (2 << 30);
        checkpoint.authority_root.summary.source_pages = 32 * 36_000;
        checkpoint.authority_root.records.records += 31;
        checkpoint.authority_records += 31;
        let root = &mut checkpoint.authority_root.records.page;
        root.byte_len += 31 * 512;
        let budget = checkpoint.represented_work().unwrap();
        let quorum = certificate(checkpoint, &keys);
        quorum.verify_header(&trust, budget).unwrap();
        assert_eq!(
            QuorumPagedCheckpoint::decode_header(
                &canonical_bytes(&quorum).unwrap(),
                &trust,
                budget
            )
            .unwrap(),
            quorum
        );
        for dimension in 0..3 {
            let mut short = budget;
            match dimension {
                0 => short.bytes -= 1,
                1 => short.page_occurrences -= 1,
                _ => short.records -= 1,
            }
            assert!(quorum.verify_header(&trust, short).is_err());
        }
        for (version, authority_version) in [(8, 2), (9, 1), (10, 2)] {
            let mut changed = checkpoint;
            changed.format_version = version;
            changed.authority_root.format_version = authority_version;
            assert!(changed.validate_header(unlimited()).is_err());
        }
        let mut changed = old;
        changed.format_version = 9;
        changed.authority_root.format_version = 2;
        assert_ne!(changed.hash().unwrap(), old.hash().unwrap());
        assert!(
            certificate(old, &keys)
                .verify_header(&trust, old.represented_work().unwrap())
                .is_ok()
        );
    }

    #[test]
    fn paged_checkpoint_header_roundtrip_identity_and_distinct_signing_domain() {
        let (checkpoint, trust, keys) = fixture();
        let budget = checkpoint.represented_work().unwrap();
        let mut quorum = certificate(checkpoint, &keys);
        quorum.verify_header(&trust, budget).unwrap();
        let bytes = canonical_bytes(&quorum).unwrap();
        assert_eq!(
            QuorumPagedCheckpoint::decode_header(&bytes, &trust, budget).unwrap(),
            quorum
        );
        assert_eq!(
            PagedGuildCheckpoint::decode(&canonical_bytes(&checkpoint).unwrap(), budget).unwrap(),
            checkpoint
        );
        assert!(decode_canonical::<crate::QuorumCheckpoint>(&bytes).is_err());
        let identity = quorum.hash().unwrap();
        quorum.signatures.pop();
        assert_eq!(quorum.hash().unwrap(), identity);
        assert!(quorum.verify_header(&trust, budget).is_err());
        let mut substituted = checkpoint;
        substituted.packed_sectors.records.page.hash[0] ^= 1;
        assert_ne!(substituted.hash().unwrap(), identity);
        let mut wrong_domain = certificate(checkpoint, &keys);
        wrong_domain.signatures[0].signature = keys
            .iter()
            .find(|keys| keys.node_id() == wrong_domain.signatures[0].signer)
            .unwrap()
            .sign(
                b"mutualbackup/guild-checkpoint/v1",
                &canonical_bytes(&checkpoint).unwrap(),
            )
            .to_vec();
        assert!(wrong_domain.verify_header(&trust, budget).is_err());
        let vector = hex::encode(bytes);
        assert_eq!(
            vector,
            include_str!("../../../protocol/vectors/paged-checkpoint-v1.postcard.hex").trim()
        );
    }

    #[test]
    fn paged_checkpoint_requires_independent_exact_event_base_and_policy() {
        let (checkpoint, trust, keys) = fixture();
        let quorum = certificate(checkpoint, &keys);
        let changes: Vec<fn(&mut PagedCheckpointTrust)> = vec![
            |trust| trust.guild_id[0] ^= 1,
            |trust| trust.genesis_hash[0] ^= 1,
            |trust| trust.event_sequence -= 1,
            |trust| trust.event_head[0] ^= 1,
            |trust| trust.authority.membership_epoch += 1,
            |trust| trust.authority.quorum.rule = QuorumRule::Unanimous,
            |trust| trust.previous.as_mut().unwrap().generation -= 1,
            |trust| trust.previous.as_mut().unwrap().hash[0] ^= 1,
            |trust| trust.previous = None,
            |trust| {
                trust.members.pop();
            },
            |trust| trust.authority.format_version = 2,
        ];
        for change in changes {
            let mut other = trust.clone();
            change(&mut other);
            assert!(quorum.verify_header(&other, unlimited()).is_err());
        }
        let mut first = checkpoint;
        first.generation = 1;
        first.authority_root.generation = 1;
        first.parent = None;
        let mut first_trust = trust.clone();
        first_trust.previous = None;
        certificate(first, &keys)
            .verify_header(&first_trust, unlimited())
            .unwrap();
        first.parent = Some([23; 32]);
        assert!(first.validate_header(unlimited()).is_err());
    }

    #[test]
    fn paged_checkpoint_admits_every_dimension_and_rejects_overflow_and_bad_roots() {
        let (checkpoint, trust, keys) = fixture();
        let budget = checkpoint.represented_work().unwrap();
        for dimension in 0..3 {
            let mut limit = budget;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                certificate(checkpoint, &keys)
                    .verify_header(&trust, limit)
                    .is_err()
            );
        }
        let changes: Vec<fn(&mut PagedGuildCheckpoint)> = vec![
            |value| value.format_version = 7,
            |value| value.authority_records = 0,
            |value| value.authority_records = u64::MAX,
            |value| value.authority_root.generation += 1,
            |value| value.authority_root.membership_epoch += 1,
            |value| value.coding.guild_event_sequence += 1,
            |value| value.packed_sources.profile.slot_size /= 2,
            |value| value.packed_sectors.packing_version = 1,
            |value| value.genesis_hash = [0; 32],
            |value| value.parent = Some([0; 32]),
        ];
        for change in changes {
            let mut value = checkpoint;
            change(&mut value);
            assert!(value.validate_header(unlimited()).is_err());
        }
    }

    #[test]
    fn paged_checkpoint_quorum_rejects_bad_signers_and_signatures() {
        let (checkpoint, trust, keys) = fixture();
        let good = certificate(checkpoint, &keys);
        for length in [0, 63, 65, 4096] {
            let mut bad = good.clone();
            bad.signatures[0].signature.resize(length, 0);
            assert!(bad.verify_header(&trust, unlimited()).is_err());
        }
        let mut bad = good.clone();
        bad.signatures[0].signature[0] ^= 1;
        assert!(bad.verify_header(&trust, unlimited()).is_err());
        let mut bad = good.clone();
        bad.signatures.reverse();
        assert!(bad.verify_header(&trust, unlimited()).is_err());
        let mut bad = good.clone();
        bad.signatures[1] = bad.signatures[0].clone();
        assert!(bad.verify_header(&trust, unlimited()).is_err());
        let outsider = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let mut bad = certificate(checkpoint, &[outsider]);
        assert!(bad.verify_header(&trust, unlimited()).is_err());
        bad.signatures[0].signer = crate::NodeId([0; 32]);
        assert!(bad.verify_header(&trust, unlimited()).is_err());
        let mut too_many = good.clone();
        too_many.signatures.resize(257, good.signatures[0].clone());
        assert!(too_many.verify_header(&trust, unlimited()).is_err());
    }

    #[test]
    fn paged_checkpoint_bounded_decoder_rejects_before_nested_payload_allocation() {
        let (checkpoint, trust, keys) = fixture();
        let mut count = canonical_bytes(&checkpoint).unwrap();
        count.extend(canonical_bytes(&257_usize).unwrap());
        count.resize(count.len() + 257, 0);
        assert!(matches!(
            decode_canonical::<QuorumPagedCheckpoint>(&count),
            Err(ModelError::Decode(postcard::Error::SerdeDeCustom))
        ));
        let mut signature = canonical_bytes(&checkpoint).unwrap();
        signature.extend(canonical_bytes(&1_usize).unwrap());
        signature.extend(canonical_bytes(&keys[0].node_id()).unwrap());
        signature.extend(canonical_bytes(&65_usize).unwrap());
        signature.resize(signature.len() + 65, 0);
        assert!(matches!(
            decode_canonical::<QuorumPagedCheckpoint>(&signature),
            Err(ModelError::Decode(postcard::Error::SerdeDeCustom))
        ));
        let mut encoded = canonical_bytes(&certificate(checkpoint, &keys)).unwrap();
        encoded[0] = 0x88;
        encoded.insert(1, 0);
        assert!(QuorumPagedCheckpoint::decode_header(&encoded, &trust, unlimited()).is_err());
        let mut encoded = canonical_bytes(&certificate(checkpoint, &keys)).unwrap();
        encoded.push(0);
        assert!(QuorumPagedCheckpoint::decode_header(&encoded, &trust, unlimited()).is_err());
        assert!(
            PagedGuildCheckpoint::decode(&vec![0; PAGED_GUILD_CHECKPOINT_BYTES + 1], unlimited())
                .is_err()
        );
        assert!(
            QuorumPagedCheckpoint::decode_header(
                &vec![0; PAGED_QUORUM_CHECKPOINT_BYTES + 1],
                &trust,
                unlimited()
            )
            .is_err()
        );
    }

    #[test]
    fn paged_checkpoint_rejects_unbounded_or_invalid_trusted_snapshots() {
        let (_, trust, _) = fixture();
        let changes: Vec<fn(&mut PagedCheckpointTrust)> = vec![
            |trust| trust.members.reverse(),
            |trust| trust.members[1] = trust.members[0].clone(),
            |trust| trust.members.resize(257, trust.members[0].clone()),
            |trust| trust.members.clear(),
            |trust| trust.members[0].failure_domain = "x".repeat(257),
            |trust| trust.members[0].failure_domain.clear(),
            |trust| trust.members[0].node_id = crate::NodeId([0; 32]),
            |trust| trust.genesis_hash = [0; 32],
            |trust| trust.event_head = [0; 32],
            |trust| trust.event_sequence = u64::MAX,
            |trust| trust.previous.as_mut().unwrap().generation = i64::MAX as u64,
            |trust| trust.previous.as_mut().unwrap().hash = [0; 32],
            |trust| trust.authority.membership_epoch = 0,
            |trust| trust.authority.quorum.rule = QuorumRule::Threshold(1),
        ];
        for change in changes {
            let mut bad = trust.clone();
            change(&mut bad);
            assert!(bad.validate().is_err());
        }
    }

    #[test]
    fn paged_checkpoint_trust_allows_certified_shared_failure_domains() {
        let (header, mut trust, keys) = fixture();
        trust.members[1].failure_domain = trust.members[0].failure_domain.clone();
        trust.validate().unwrap();
        certificate(header, &keys)
            .verify_header(&trust, unlimited())
            .unwrap();
        // Placement must still enforce distinct domains within each coding
        // group; roster validation must not reject a legitimate cohosted peer.
        trust.members[1].node_id = trust.members[0].node_id;
        assert!(trust.validate().is_err());
    }

    #[test]
    fn paged_checkpoint_fits_full_256_member_quorum_without_unbounded_rosters() {
        use crate::{
            CatalogBuilder, CatalogCheckpointAuthorityBuilder,
            CatalogCheckpointAuthorityRecord as R, CatalogLegacyRevisionRef, SectorRef,
            SignedRecord, UserRevision, WriterFence,
        };
        use ed25519_dalek::SigningKey;
        let (mut header, mut trust, _) = fixture();
        let keys = (0..256)
            .map(|index| KeyMaterial::from_seed(&Seed::from_bytes([index as u8; 32])))
            .collect::<Vec<_>>();
        trust.members = keys
            .iter()
            .enumerate()
            .map(|(index, keys)| Member {
                node_id: keys.node_id(),
                recovery_public_key: keys.recovery_public_key(),
                failure_domain: format!("domain-{index:03}-{}", "x".repeat(245)),
            })
            .collect();
        trust.members.sort_by_key(|member| member.node_id);
        trust.authority.quorum.rule = QuorumRule::Unanimous;
        header.authority = trust.authority;
        let writer = SigningKey::from_bytes(&[201; 32]);
        let mut revision = UserRevision {
            format_version: 3,
            guild_id: trust.guild_id,
            protected_root_id: uuid::Uuid::from_u128(17),
            cipher_profile: 1,
            revision_id: uuid::Uuid::from_u128(18),
            owner: keys[0].node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![SectorRef {
                id: [31; 32],
                root: [32; 32],
                logical_len: 17,
            }],
            data_sectors: Vec::new(),
            sector_commitments: None,
        };
        revision.sign_writer(&writer).unwrap();
        let signed = SignedRecord::sign(crate::USER_REVISION_DOMAIN, revision, &keys[0]).unwrap();
        let scope = CatalogScope::Guild {
            guild_id: trust.guild_id,
        };
        let mut sink = |_: crate::CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
        let mut body = CatalogBuilder::new(scope, CatalogSection::Checkpoint).unwrap();
        body.push(&canonical_bytes(&signed).unwrap(), &mut sink)
            .unwrap();
        let reference = CatalogLegacyRevisionRef::from_signed(
            trust.guild_id,
            &signed,
            body.finish(&mut sink).unwrap(),
        )
        .unwrap();
        let mut authority = CatalogCheckpointAuthorityBuilder::new(scope, 3, 2).unwrap();
        for member in &trust.members {
            authority
                .push(&R::Member(member.clone()), &mut sink)
                .unwrap();
        }
        authority
            .push(
                &R::WriterFence(WriterFence {
                    owner: keys[0].node_id(),
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }),
                &mut sink,
            )
            .unwrap();
        authority
            .push(&R::LegacyRevision(reference), &mut sink)
            .unwrap();
        header.authority_root = authority.finish(&mut sink).unwrap();
        header.authority_records = header.authority_root.records.records + 2;
        let certificate = certificate(header, &keys);
        let encoded = canonical_bytes(&certificate).unwrap();
        assert!(encoded.len() <= PAGED_QUORUM_CHECKPOINT_BYTES);
        assert!(canonical_bytes(&header).unwrap().len() <= PAGED_GUILD_CHECKPOINT_BYTES);
        assert_eq!(
            QuorumPagedCheckpoint::decode_header(
                &encoded,
                &trust,
                header.represented_work().unwrap()
            )
            .unwrap(),
            certificate
        );
    }
}
