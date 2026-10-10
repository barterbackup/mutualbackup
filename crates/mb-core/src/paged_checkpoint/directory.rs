//! Version ten header for sharded original packing streams. All body,
//! transition, private/payload and durable activation guards remain required.
use super::*;
pub const PAGED_GUILD_CHECKPOINT_DIRECTORY_VERSION: u16 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PagedGuildCheckpointDirectory {
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
    pub packing: crate::CatalogPackingDirectoryRoot,
    pub coding: CatalogCodingDirectoryRoot,
}

impl PagedGuildCheckpointDirectory {
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
        self.packing.validate(budget)?;
        if self.format_version != PAGED_GUILD_CHECKPOINT_DIRECTORY_VERSION
            || self.authority_root.format_version != 2
            || self.genesis_hash == [0; 32]
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
            || self.coding.guild_event_sequence != self.event_sequence
        {
            return Err(CatalogError::InvalidPage);
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
        let mut packing = self.packing.work()?;
        packing.bytes = packing
            .bytes
            .checked_sub(crate::CATALOG_PACKING_DIRECTORY_ROOT_BYTES as u64)
            .ok_or(CatalogError::Bounds)?;
        work = work.checked_add(packing)?;
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
pub struct QuorumPagedCheckpointDirectory {
    pub checkpoint: PagedGuildCheckpointDirectory,
    #[serde(deserialize_with = "super::signatures")]
    pub signatures: Vec<MemberSignature>,
}

impl QuorumPagedCheckpointDirectory {
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
        verify_signatures(&self.signatures, trust, &encoded)
    }

    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        self.checkpoint.hash()
    }
}

#[cfg(test)]
mod tests;
