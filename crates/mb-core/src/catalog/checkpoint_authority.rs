//! Ordered checkpoint authority records. The enclosing certificate must sign
//! the root; consumers still join membership/writer history, tombstones, global
//! revision IDs, every referenced source/body and migration evidence before
//! publication. These codecs do not activate a checkpoint or protect data.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use super::*;
use crate::{
    LEGACY_PACKING_ATTESTATION_DOMAIN, LEGACY_PACKING_BINDING_DOMAIN, LegacyPackingAttestation,
    LegacyPackingBinding, Member, RevisionTombstone, SignedRecord, USER_REVISION_DOMAIN,
    UserRevision, V1_CIPHER_PROFILE, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, WriterFence,
    canonical_bytes_bounded, canonical_size_bounded,
};

pub const CATALOG_CHECKPOINT_RECORD_BYTES: usize = 4096;
pub const CATALOG_CHECKPOINT_ROOT_BYTES: usize = 1024;

fn decode_member<'de, D: Deserializer<'de>>(decoder: D) -> Result<Member, D::Error> {
    #[derive(Deserialize)]
    struct BoundedMember {
        node_id: NodeId,
        recovery_public_key: crate::RecoveryPublicKey,
        #[serde(deserialize_with = "crate::bounded::failure_domain")]
        failure_domain: String,
    }
    let member = BoundedMember::deserialize(decoder)?;
    Ok(Member {
        node_id: member.node_id,
        recovery_public_key: member.recovery_public_key,
        failure_domain: member.failure_domain,
    })
}

fn public_key(bytes: [u8; 32]) -> Result<(), CatalogError> {
    let key = VerifyingKey::from_bytes(&bytes).map_err(ModelError::from)?;
    if key.is_weak() {
        return Err(ModelError::WeakPublicKey.into());
    }
    Ok(())
}

/// Preserve the original owner/writer signatures and body identity. Legacy
/// envelopes stay individually bounded by their original 32 MiB cap; the new
/// control stream contains only this fixed reference. Its summary is not
/// authority until the complete referenced envelope has been authenticated.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogLegacyRevisionRef {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub owner: NodeId,
    pub protected_root_id: Uuid,
    pub revision_id: Uuid,
    pub sequence: u64,
    pub parent: Option<[u8; 32]>,
    pub writer_epoch: u64,
    pub writer_public_key: [u8; 32],
    pub revision_hash: [u8; 32],
    pub body: CatalogPageRef,
}

impl CatalogLegacyRevisionRef {
    pub fn from_signed(
        guild_id: [u8; 32],
        signed: &SignedRecord<UserRevision>,
        body: CatalogPageRef,
    ) -> Result<Self, CatalogError> {
        let revision = &signed.value;
        let reference = Self {
            format_version: 1,
            guild_id,
            owner: revision.owner,
            protected_root_id: revision.protected_root_id,
            revision_id: revision.revision_id,
            sequence: revision.sequence,
            parent: revision.parent,
            writer_epoch: revision.writer_epoch,
            writer_public_key: revision.writer_public_key,
            revision_hash: {
                canonical_size_bounded(signed, V1_MAX_CATALOG_BYTES)?;
                revision.hash()?
            },
            body,
        };
        reference.verify_signed(signed)?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        self.body.validate()?;
        if self.format_version != 1
            || self.protected_root_id.is_nil()
            || self.revision_id.is_nil()
            || self.sequence == 0
            || (self.sequence == 1) != self.parent.is_none()
            || self.writer_epoch == 0
            || self.revision_hash == [0; 32]
            || self.body.byte_len == 0
            || self.body.byte_len > V1_MAX_CATALOG_BYTES as u64
        {
            return Err(CatalogError::InvalidPage);
        }
        public_key(self.owner.0)?;
        public_key(self.writer_public_key)
    }

    pub fn verify_signed(&self, signed: &SignedRecord<UserRevision>) -> Result<(), CatalogError> {
        self.validate()?;
        if canonical_size_bounded(signed, V1_MAX_CATALOG_BYTES)? as u64 != self.body.byte_len {
            return Err(CatalogError::InvalidPage);
        }
        signed.verify(USER_REVISION_DOMAIN)?;
        signed.value.verify_writer()?;
        let body = &signed.value;
        if signed.signer != self.owner
            || body.owner != self.owner
            || body.guild_id != self.guild_id
            || body.protected_root_id != self.protected_root_id
            || body.revision_id != self.revision_id
            || body.sequence != self.sequence
            || body.parent != self.parent
            || body.writer_epoch != self.writer_epoch
            || body.writer_public_key != self.writer_public_key
            || body.hash()? != self.revision_hash
            || body.cipher_profile != V1_CIPHER_PROFILE
            || body.metadata_sectors.is_empty()
        {
            return Err(CatalogError::InvalidPage);
        }
        let count = body
            .metadata_sectors
            .len()
            .checked_add(body.data_sectors.len())
            .ok_or(CatalogError::Bounds)?;
        if !matches!(
            (body.format_version, &body.sector_commitments),
            (3, None) | (4 | 5, Some(_))
        ) || body
            .metadata_sectors
            .iter()
            .chain(&body.data_sectors)
            .any(|reference| {
                reference.logical_len == 0 || reference.logical_len as usize > V1_SECTOR_SIZE
            })
            || body.sector_commitments.as_ref().is_some_and(|values| {
                values.len() != count
                    || values.iter().any(|commitment| {
                        commitment.byte_len as usize != V1_SECTOR_SIZE
                            || commitment.validate().is_err()
                    })
            })
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    /// Authenticate every byte page before decoding a single legacy envelope.
    /// The old per-object cap is a fixed migration memory bound, independent of
    /// the number/size of new paged revisions and the full retained dataset.
    pub fn read_signed<E>(
        &self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<SignedRecord<UserRevision>, CatalogStreamError<E>> {
        self.validate()?;
        let mut reader = CatalogReader::new(
            CatalogScope::Guild {
                guild_id: self.guild_id,
            },
            CatalogSection::Checkpoint,
            self.body,
        )?;
        let mut bytes = Vec::new();
        while let Some(leaf) = reader.next_leaf(fetch)? {
            bytes.extend(leaf);
        }
        #[derive(Deserialize)]
        struct BoundedLegacy(
            #[serde(deserialize_with = "crate::bounded::signed_record")] SignedRecord<UserRevision>,
        );
        let BoundedLegacy(signed) = decode_canonical(&bytes).map_err(CatalogError::from)?;
        self.verify_signed(&signed)?;
        if canonical_bytes_bounded(&signed, V1_MAX_CATALOG_BYTES).map_err(CatalogError::from)?
            != bytes
        {
            return Err(CatalogError::InvalidPage.into());
        }
        Ok(signed)
    }
}

/// Positional variants are append-only. Members/fences/tombstones precede
/// revisions; legacy and paged revisions share one owner/root/sequence order.
/// Migration evidence follows revisions in source/signer order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogCheckpointAuthorityRecord {
    Member(#[serde(deserialize_with = "decode_member")] Member),
    WriterFence(WriterFence),
    Tombstone(RevisionTombstone),
    LegacyRevision(CatalogLegacyRevisionRef),
    PagedRevision(
        #[serde(deserialize_with = "crate::bounded::signed_record")]
        SignedRecord<PagedUserRevision>,
    ),
    LegacyBinding(
        #[serde(deserialize_with = "crate::bounded::signed_record")]
        SignedRecord<LegacyPackingBinding>,
    ),
    LegacyAttestation(
        #[serde(deserialize_with = "crate::bounded::signed_record")]
        SignedRecord<LegacyPackingAttestation>,
    ),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointAuthoritySummary {
    pub members: u16,
    pub writer_fences: u64,
    pub tombstones: u64,
    pub revisions: u64,
    pub legacy_revisions: u64,
    pub legacy_bytes: u64,
    pub legacy_pages: u64,
    pub source_bytes: u64,
    pub source_pages: u64,
    pub bindings: u64,
    pub attestations: u64,
}

impl CatalogCheckpointAuthoritySummary {
    fn within(self, maximum: Self) -> bool {
        let values = |summary: Self| {
            [
                u64::from(summary.members),
                summary.writer_fences,
                summary.tombstones,
                summary.revisions,
                summary.legacy_revisions,
                summary.legacy_bytes,
                summary.legacy_pages,
                summary.source_bytes,
                summary.source_pages,
                summary.bindings,
                summary.attestations,
            ]
        };
        values(self)
            .into_iter()
            .zip(values(maximum))
            .all(|(actual, limit)| actual <= limit)
    }
    fn records(self) -> Result<u64, CatalogError> {
        [
            u64::from(self.members),
            self.writer_fences,
            self.tombstones,
            self.revisions,
            self.bindings,
            self.attestations,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, count| {
            sum.checked_add(count).ok_or(CatalogError::Bounds)
        })
    }
    fn validate_shape(self, complete: bool) -> Result<(), CatalogError> {
        let paged = self
            .revisions
            .checked_sub(self.legacy_revisions)
            .ok_or(CatalogError::Bounds)?;
        if self.members > 256
            || self.records()? > CATALOG_MAX_RECORDS
            || complete && (self.members == 0 || self.revisions == 0 || self.writer_fences == 0)
            || self.legacy_bytes < self.legacy_revisions
            || self.legacy_pages < self.legacy_revisions
            || self.legacy_bytes
                > self
                    .legacy_revisions
                    .checked_mul(V1_MAX_CATALOG_BYTES as u64)
                    .ok_or(CatalogError::Bounds)?
            || self.legacy_pages
                > self
                    .legacy_revisions
                    .checked_mul(CATALOG_MAX_PAGE_OCCURRENCES)
                    .ok_or(CatalogError::Bounds)?
            || self.source_bytes < paged * 8
            || self.source_pages < paged
            || self.source_bytes
                > paged
                    .checked_mul(CATALOG_MAX_STREAM_BYTES)
                    .ok_or(CatalogError::Bounds)?
            || self.source_pages
                > paged
                    .checked_mul(CATALOG_MAX_PAGE_OCCURRENCES)
                    .ok_or(CatalogError::Bounds)?
            || self.legacy_revisions == 0 && (self.legacy_bytes != 0 || self.legacy_pages != 0)
            || paged == 0 && (self.source_bytes != 0 || self.source_pages != 0)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    fn validate(self, complete: bool) -> Result<(), CatalogError> {
        self.validate_shape(complete)?;
        if self
            .legacy_bytes
            .checked_add(self.source_bytes)
            .is_none_or(|bytes| bytes > CATALOG_MAX_STREAM_BYTES)
            || self
                .legacy_pages
                .checked_add(self.source_pages)
                .is_none_or(|pages| pages > CATALOG_MAX_PAGE_OCCURRENCES)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointAuthorityRoot {
    pub format_version: u16,
    pub generation: u64,
    pub membership_epoch: u64,
    pub records: CatalogRecordRoot,
    pub summary: CatalogCheckpointAuthoritySummary,
}

impl CatalogCheckpointAuthorityRoot {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        let root = Self::decode_inner(bytes)?;
        root.validate()?;
        Ok(root)
    }

    /// The budget comes from the enclosing trusted policy. Format two counts
    /// all retained body/source occurrences across individually bounded trees;
    /// it cannot be decoded through the original format-one entry point.
    pub fn decode_with_budget(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        let root = Self::decode_inner(bytes)?;
        root.validate_with_budget(budget)?;
        Ok(root)
    }

    fn decode_inner(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_CHECKPOINT_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        if canonical_bytes_bounded(&root, CATALOG_CHECKPOINT_ROOT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }
    pub fn validate(self) -> Result<(), CatalogError> {
        self.validate_shape()?;
        self.summary.validate(true)?;
        if self.format_version != 1
            || self.represented_bytes()? > CATALOG_MAX_STREAM_BYTES
            || self.page_occurrences()? > CATALOG_MAX_PAGE_OCCURRENCES
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    pub fn validate_with_budget(
        self,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<(), CatalogError> {
        match self.format_version {
            1 => self.validate()?,
            2 => self.validate_shape()?,
            _ => return Err(CatalogError::Bounds),
        }
        budget.remaining_after(self.minimum_work()?)?;
        Ok(())
    }

    fn validate_shape(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        self.summary.validate_shape(true)?;
        if self.generation == 0
            || self.generation > i64::MAX as u64
            || self.membership_epoch == 0
            || self.records.records != self.summary.records()?
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    /// Nested source frame counts are checked before each revision is returned
    /// by the reader. Flat legacy source entries require the full store join.
    pub fn minimum_work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        Ok(CatalogCodingTraversalBudget {
            bytes: self.represented_bytes()?,
            page_occurrences: self.page_occurrences()?,
            records: self
                .summary
                .records()?
                .checked_add(self.summary.legacy_revisions)
                .ok_or(CatalogError::Bounds)?,
        })
    }

    pub fn represented_bytes(self) -> Result<u64, CatalogError> {
        let envelope = match self.format_version {
            1 => canonical_size_bounded(&self, CATALOG_CHECKPOINT_ROOT_BYTES)? as u64,
            2 => CATALOG_CHECKPOINT_ROOT_BYTES as u64,
            _ => return Err(CatalogError::Bounds),
        };
        [
            self.records.page.byte_len,
            self.summary.legacy_bytes,
            self.summary.source_bytes,
            envelope,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, bytes| {
            sum.checked_add(bytes).ok_or(CatalogError::Bounds)
        })
    }
    pub fn page_occurrences(self) -> Result<u64, CatalogError> {
        [
            self.records.page.page_occurrences,
            self.summary.legacy_pages,
            self.summary.source_pages,
        ]
        .into_iter()
        .try_fold(0_u64, |sum, pages| {
            sum.checked_add(pages).ok_or(CatalogError::Bounds)
        })
    }
}

/// Canonical mixed-revision order. The fixed database key uses a big-endian
/// sequence, so indexed traversal agrees with numeric order across varint
/// boundaries and does not need to sort a whole retained catalog.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct CatalogCheckpointRevisionKey {
    pub owner: NodeId,
    pub protected_root_id: Uuid,
    pub sequence: u64,
    pub revision_id: Uuid,
}

impl CatalogCheckpointRevisionKey {
    pub fn index_key(self) -> [u8; 72] {
        let mut key = [0; 72];
        key[..32].copy_from_slice(&self.owner.0);
        key[32..48].copy_from_slice(self.protected_root_id.as_bytes());
        key[48..56].copy_from_slice(&self.sequence.to_be_bytes());
        key[56..].copy_from_slice(self.revision_id.as_bytes());
        key
    }
}

impl From<&PagedUserRevision> for CatalogCheckpointRevisionKey {
    fn from(revision: &PagedUserRevision) -> Self {
        Self {
            owner: revision.owner,
            protected_root_id: revision.protected_root_id,
            sequence: revision.sequence,
            revision_id: revision.revision_id,
        }
    }
}
impl From<&CatalogLegacyRevisionRef> for CatalogCheckpointRevisionKey {
    fn from(revision: &CatalogLegacyRevisionRef) -> Self {
        Self {
            owner: revision.owner,
            protected_root_id: revision.protected_root_id,
            sequence: revision.sequence,
            revision_id: revision.revision_id,
        }
    }
}

impl CatalogCheckpointAuthorityRecord {
    pub fn revision_key(&self) -> Option<CatalogCheckpointRevisionKey> {
        match self {
            Self::LegacyRevision(revision) => Some(revision.into()),
            Self::PagedRevision(revision) => Some((&revision.value).into()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Order {
    Member(NodeId),
    Fence(NodeId, u64),
    Tombstone(NodeId, Uuid),
    Revision(CatalogCheckpointRevisionKey),
    Binding(CatalogPackedSourceId),
    Attestation(CatalogPackedSourceId, NodeId),
}

struct State {
    guild_id: [u8; 32],
    generation: u64,
    epoch: u64,
    format_version: u16,
    budget: CatalogCodingTraversalBudget,
    record_bytes: u64,
    nested_records: u64,
    summary: CatalogCheckpointAuthoritySummary,
    previous: Option<Order>,
    previous_revision: Option<([u8; 32], u64)>,
}

impl State {
    fn new(
        scope: CatalogScope,
        generation: u64,
        epoch: u64,
        format_version: u16,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        scope.validate(CatalogSection::Checkpoint)?;
        let CatalogScope::Guild { guild_id } = scope else {
            return Err(CatalogError::InvalidPage);
        };
        if generation == 0
            || generation > i64::MAX as u64
            || epoch == 0
            || !matches!(format_version, 1 | 2)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(Self {
            guild_id,
            generation,
            epoch,
            format_version,
            budget,
            record_bytes: 8,
            nested_records: 0,
            summary: Default::default(),
            previous: None,
            previous_revision: None,
        })
    }

    fn revision(
        &mut self,
        key: CatalogCheckpointRevisionKey,
        parent: Option<[u8; 32]>,
        hash: [u8; 32],
        epoch: u64,
    ) -> Result<Order, CatalogError> {
        if let Some(Order::Revision(previous)) = &self.previous
            && previous.owner == key.owner
            && previous.protected_root_id == key.protected_root_id
        {
            let (previous_hash, previous_epoch) =
                self.previous_revision.ok_or(CatalogError::InvalidPage)?;
            if previous.sequence.checked_add(1) != Some(key.sequence)
                || parent != Some(previous_hash)
                || epoch < previous_epoch
            {
                return Err(CatalogError::InvalidPage);
            }
        }
        self.previous_revision = Some((hash, epoch));
        self.summary.revisions += 1;
        Ok(Order::Revision(key))
    }

    fn accept(
        &mut self,
        record: &CatalogCheckpointAuthorityRecord,
        encoded_len: usize,
    ) -> Result<(), CatalogError> {
        use CatalogCheckpointAuthorityRecord as R;
        let order = match record {
            R::Member(member) => {
                public_key(member.node_id.0)?;
                if member.failure_domain.is_empty()
                    || member.failure_domain.len() > 256
                    || !member.recovery_public_key.is_contributory()
                {
                    return Err(CatalogError::InvalidPage);
                }
                if self.summary.members == 256 {
                    return Err(CatalogError::Bounds);
                }
                self.summary.members += 1;
                Order::Member(member.node_id)
            }
            R::WriterFence(fence) => {
                public_key(fence.owner.0)?;
                public_key(fence.public_key)?;
                match &self.previous {
                    Some(Order::Fence(owner, epoch))
                        if *owner == fence.owner && epoch.checked_add(1) == Some(fence.epoch) => {}
                    Some(Order::Fence(owner, _)) if *owner == fence.owner => {
                        return Err(CatalogError::InvalidPage);
                    }
                    _ if fence.epoch == 1 => {}
                    _ => return Err(CatalogError::InvalidPage),
                }
                self.summary.writer_fences += 1;
                Order::Fence(fence.owner, fence.epoch)
            }
            R::Tombstone(tombstone) => {
                public_key(tombstone.owner.0)?;
                if tombstone.protected_root_id.is_nil()
                    || tombstone.through_sequence == 0
                    || tombstone.last_revision_id.is_nil()
                    || tombstone.last_revision_hash == [0; 32]
                    || tombstone.retired_at_generation < 2
                    || tombstone.retired_at_generation > self.generation
                {
                    return Err(CatalogError::InvalidPage);
                }
                self.summary.tombstones += 1;
                Order::Tombstone(tombstone.owner, tombstone.protected_root_id)
            }
            R::LegacyRevision(reference) => {
                reference.validate()?;
                if reference.guild_id != self.guild_id {
                    return Err(CatalogError::InvalidPage);
                }
                self.summary.legacy_revisions += 1;
                self.summary.legacy_bytes += reference.body.byte_len;
                self.summary.legacy_pages += reference.body.page_occurrences;
                self.nested_records = self
                    .nested_records
                    .checked_add(1)
                    .ok_or(CatalogError::Bounds)?;
                self.revision(
                    reference.into(),
                    reference.parent,
                    reference.revision_hash,
                    reference.writer_epoch,
                )?
            }
            R::PagedRevision(signed) => {
                PagedUserRevision::verify_signed(signed)?;
                let revision = &signed.value;
                if revision.guild_id != self.guild_id {
                    return Err(CatalogError::InvalidPage);
                }
                self.summary.source_bytes += revision.sources.records.page.byte_len;
                self.summary.source_pages += revision.sources.records.page.page_occurrences;
                self.nested_records = self
                    .nested_records
                    .checked_add(revision.sources.records.records)
                    .ok_or(CatalogError::Bounds)?;
                self.revision(
                    revision.into(),
                    revision.parent,
                    revision.hash()?,
                    revision.writer_epoch,
                )?
            }
            R::LegacyBinding(signed) => {
                signed.verify(LEGACY_PACKING_BINDING_DOMAIN)?;
                let binding = &signed.value;
                if signed.signer != binding.owner
                    || binding.format_version != 1
                    || binding.flat_root == [0; 32]
                    || binding.source_commitment.byte_len as usize != V1_SECTOR_SIZE
                    || binding.source_commitment.validate().is_err()
                {
                    return Err(CatalogError::InvalidPage);
                }
                let source = CatalogPackedSourceId {
                    owner: binding.owner,
                    protected_root: binding.protected_root,
                    object_id: binding.object_id,
                };
                source.validate()?;
                self.summary.bindings += 1;
                Order::Binding(source)
            }
            R::LegacyAttestation(signed) => {
                signed.verify(LEGACY_PACKING_ATTESTATION_DOMAIN)?;
                let attestation = &signed.value;
                if attestation.format_version != 1
                    || attestation.guild_id != self.guild_id
                    || attestation.membership_epoch != self.epoch
                    || attestation.flat_root == [0; 32]
                    || attestation.source_commitment.byte_len as usize != V1_SECTOR_SIZE
                    || attestation.source_commitment.validate().is_err()
                {
                    return Err(CatalogError::InvalidPage);
                }
                let source = CatalogPackedSourceId {
                    owner: attestation.owner,
                    protected_root: attestation.protected_root,
                    object_id: attestation.object_id,
                };
                source.validate()?;
                self.summary.attestations += 1;
                Order::Attestation(source, signed.signer)
            }
        };
        if self
            .previous
            .as_ref()
            .is_some_and(|previous| previous >= &order)
        {
            return Err(CatalogError::InvalidPage);
        }
        self.previous = Some(order);
        if self.format_version == 1 {
            self.summary.validate(false)
        } else {
            self.summary.validate_shape(false)?;
            self.record_bytes = self
                .record_bytes
                .checked_add(4 + encoded_len as u64)
                .ok_or(CatalogError::Bounds)?;
            if self.record_bytes > CATALOG_MAX_STREAM_BYTES {
                return Err(CatalogError::Bounds);
            }
            // The record builder packs a dense stream. Include its future
            // index pages before writing a frame or exposing a nested root.
            let mut nodes = self.record_bytes.div_ceil(CATALOG_LEAF_BYTES as u64);
            let mut pages = nodes;
            while nodes > 1 {
                nodes = nodes.div_ceil(CATALOG_FANOUT as u64);
                pages = pages.checked_add(nodes).ok_or(CatalogError::Bounds)?;
            }
            self.budget.remaining_after(CatalogCodingTraversalBudget {
                bytes: self
                    .record_bytes
                    .checked_add(CATALOG_CHECKPOINT_ROOT_BYTES as u64)
                    .and_then(|bytes| bytes.checked_add(self.summary.legacy_bytes))
                    .and_then(|bytes| bytes.checked_add(self.summary.source_bytes))
                    .ok_or(CatalogError::Bounds)?,
                page_occurrences: pages
                    .checked_add(self.summary.legacy_pages)
                    .and_then(|pages| pages.checked_add(self.summary.source_pages))
                    .ok_or(CatalogError::Bounds)?,
                records: self
                    .summary
                    .records()?
                    .checked_add(self.nested_records)
                    .ok_or(CatalogError::Bounds)?,
            })?;
            Ok(())
        }
    }
}

pub struct CatalogCheckpointAuthorityBuilder {
    records: CatalogRecordBuilder,
    state: State,
    failed: bool,
}
impl CatalogCheckpointAuthorityBuilder {
    pub fn new(
        scope: CatalogScope,
        generation: u64,
        membership_epoch: u64,
    ) -> Result<Self, CatalogError> {
        Self::new_inner(
            scope,
            generation,
            membership_epoch,
            1,
            CatalogCodingTraversalBudget::default(),
        )
    }

    pub fn new_with_budget(
        scope: CatalogScope,
        generation: u64,
        membership_epoch: u64,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        budget.remaining_after(CatalogCodingTraversalBudget {
            bytes: 8 + CATALOG_CHECKPOINT_ROOT_BYTES as u64,
            page_occurrences: 1,
            records: 0,
        })?;
        Self::new_inner(scope, generation, membership_epoch, 2, budget)
    }

    fn new_inner(
        scope: CatalogScope,
        generation: u64,
        membership_epoch: u64,
        format_version: u16,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::Checkpoint)?,
            state: State::new(scope, generation, membership_epoch, format_version, budget)?,
            failed: false,
        })
    }
    pub fn push<E>(
        &mut self,
        record: &CatalogCheckpointAuthorityRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            let bytes = canonical_bytes_bounded(record, CATALOG_CHECKPOINT_RECORD_BYTES)
                .map_err(CatalogError::from)?;
            self.state.accept(record, bytes.len())?;
            self.records.push_encoded(&bytes, sink)
        })();
        self.failed = result.is_err();
        result
    }
    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogCheckpointAuthorityRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let root = CatalogCheckpointAuthorityRoot {
            format_version: self.state.format_version,
            generation: self.state.generation,
            membership_epoch: self.state.epoch,
            records: self.records.finish(sink)?,
            summary: self.state.summary,
        };
        if root.format_version == 1 {
            root.validate()?;
        } else {
            root.validate_with_budget(self.state.budget)?;
        }
        Ok(root)
    }
}

/// This verifies ordered records and their summaries through EOF. All bodies,
/// sources and authority cross-joins remain required before signing/activation.
pub struct CatalogCheckpointAuthorityReader {
    records: CatalogRecordReader,
    root: CatalogCheckpointAuthorityRoot,
    state: State,
    failed: bool,
}
impl CatalogCheckpointAuthorityReader {
    pub fn new(
        scope: CatalogScope,
        root: CatalogCheckpointAuthorityRoot,
    ) -> Result<Self, CatalogError> {
        root.validate()?;
        Self::new_inner(scope, root, CatalogCodingTraversalBudget::default())
    }

    pub fn new_with_budget(
        scope: CatalogScope,
        root: CatalogCheckpointAuthorityRoot,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        root.validate_with_budget(budget)?;
        Self::new_inner(scope, root, budget)
    }

    fn new_inner(
        scope: CatalogScope,
        root: CatalogCheckpointAuthorityRoot,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::Checkpoint, root.records)?,
            state: State::new(
                scope,
                root.generation,
                root.membership_epoch,
                root.format_version,
                budget,
            )?,
            root,
            failed: false,
        })
    }
    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogCheckpointAuthorityRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            let Some(bytes) = self.records.next_record(fetch)? else {
                if self.state.summary != self.root.summary {
                    return Err(CatalogError::InvalidPage.into());
                }
                return Ok(None);
            };
            if bytes.len() > CATALOG_CHECKPOINT_RECORD_BYTES {
                return Err(CatalogError::Bounds.into());
            }
            let record = decode_canonical(&bytes).map_err(CatalogError::from)?;
            if canonical_bytes_bounded(&record, CATALOG_CHECKPOINT_RECORD_BYTES)
                .map_err(CatalogError::from)?
                != bytes
            {
                return Err(CatalogError::InvalidPage.into());
            }
            self.state.accept(&record, bytes.len())?;
            // Nested closures are consumed by callers after this record is
            // returned. Reject understated counts/work before exposing the
            // offending reference, not only at the final authority EOF.
            if !self.state.summary.within(self.root.summary) {
                return Err(CatalogError::InvalidPage.into());
            }
            if self.root.format_version == 2 {
                // Reserve the entire authenticated control stream and every
                // legacy envelope up front. A trailing authority phase must
                // not lend its record credits to an exposed source closure.
                let source_records = self
                    .state
                    .nested_records
                    .checked_sub(self.state.summary.legacy_revisions)
                    .ok_or(CatalogError::Bounds)?;
                self.state
                    .budget
                    .remaining_after(self.root.minimum_work()?.checked_add(
                        CatalogCodingTraversalBudget {
                            bytes: 0,
                            page_occurrences: 0,
                            records: source_records,
                        },
                    )?)?;
            }
            Ok(Some(record))
        })();
        self.failed = result.is_err();
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyMaterial, SectorRef, Seed, canonical_bytes, merkle_zero_commitment};
    use ed25519_dalek::SigningKey;
    use std::collections::HashMap;

    type Pages = HashMap<[u8; 32], Vec<u8>>;
    struct Fixture {
        owner: KeyMaterial,
        attester: KeyMaterial,
        writer: SigningKey,
        legacy: SignedRecord<UserRevision>,
        paged: SignedRecord<PagedUserRevision>,
        records: Vec<CatalogCheckpointAuthorityRecord>,
        pages: Pages,
    }
    fn fetch(pages: &Pages, page: CatalogPageRef) -> Result<Vec<u8>, &'static str> {
        pages.get(&page.hash).cloned().ok_or("missing page")
    }
    fn byte_root(scope: CatalogScope, bytes: &[u8], pages: &mut Pages) -> CatalogPageRef {
        let mut builder = CatalogBuilder::new(scope, CatalogSection::Checkpoint).unwrap();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, &'static str>(())
        };
        builder.push(bytes, &mut sink).unwrap();
        builder.finish(&mut sink).unwrap()
    }
    impl Fixture {
        fn new(version: u16) -> Self {
            let owner = KeyMaterial::from_seed(&Seed::from_bytes([11; 32]));
            let attester = KeyMaterial::from_seed(&Seed::from_bytes([12; 32]));
            let writer = SigningKey::from_bytes(&[13; 32]);
            let sector = CatalogSectorRecord {
                format_version: 1,
                sector: SectorRef {
                    id: [14; 32],
                    root: [15; 32],
                    logical_len: 12,
                },
                commitment: merkle_zero_commitment(V1_SECTOR_SIZE as u32).unwrap(),
            };
            let mut body = UserRevision {
                format_version: version,
                guild_id: [16; 32],
                protected_root_id: Uuid::from_u128(17),
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::from_u128(18),
                owner: owner.node_id(),
                writer_epoch: 1,
                writer_public_key: writer.verifying_key().to_bytes(),
                writer_signature: Vec::new(),
                sequence: 1,
                parent: None,
                metadata_sectors: vec![sector.sector.clone()],
                data_sectors: Vec::new(),
                sector_commitments: (version != 3).then(|| vec![sector.commitment.clone()]),
            };
            body.sign_writer(&writer).unwrap();
            let legacy = SignedRecord::sign(USER_REVISION_DOMAIN, body, &owner).unwrap();
            let mut pages = Pages::new();
            let scope = CatalogScope::Guild { guild_id: [16; 32] };
            let body_root = byte_root(scope, &canonical_bytes(&legacy).unwrap(), &mut pages);
            let legacy_ref =
                CatalogLegacyRevisionRef::from_signed([16; 32], &legacy, body_root).unwrap();
            let mut sources = CatalogSectorBuilder::new(CatalogScope::Dataset {
                guild_id: [16; 32],
                owner: owner.node_id(),
                protected_root_id: Uuid::from_u128(17),
            })
            .unwrap();
            let sources = {
                let mut sink = |page: CatalogPageRef, bytes| {
                    pages.insert(page.hash, bytes);
                    Ok::<_, &'static str>(())
                };
                sources.push(&sector, &mut sink).unwrap();
                sources.finish(&mut sink).unwrap()
            };
            let paged = PagedUserRevision {
                format_version: 8,
                guild_id: [16; 32],
                protected_root_id: Uuid::from_u128(17),
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::from_u128(19),
                owner: owner.node_id(),
                writer_epoch: 1,
                writer_public_key: writer.verifying_key().to_bytes(),
                writer_signature: Vec::new(),
                sequence: 2,
                parent: Some(legacy.value.hash().unwrap()),
                metadata: sector.clone(),
                sources,
            }
            .sign(&writer, &owner)
            .unwrap();
            let mut members = [&owner, &attester]
                .iter()
                .enumerate()
                .map(|(index, key)| Member {
                    node_id: key.node_id(),
                    recovery_public_key: key.recovery_public_key(),
                    failure_domain: format!("domain-{index}"),
                })
                .collect::<Vec<_>>();
            members.sort_by_key(|member| member.node_id);
            let mut records = members
                .into_iter()
                .map(CatalogCheckpointAuthorityRecord::Member)
                .collect::<Vec<_>>();
            records.push(CatalogCheckpointAuthorityRecord::WriterFence(WriterFence {
                owner: owner.node_id(),
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            }));
            records.push(CatalogCheckpointAuthorityRecord::LegacyRevision(legacy_ref));
            records.push(CatalogCheckpointAuthorityRecord::PagedRevision(
                paged.clone(),
            ));
            records.push(CatalogCheckpointAuthorityRecord::LegacyBinding(
                SignedRecord::sign(
                    LEGACY_PACKING_BINDING_DOMAIN,
                    LegacyPackingBinding {
                        format_version: 1,
                        owner: owner.node_id(),
                        protected_root: crate::packing_protected_root(Uuid::from_u128(17)),
                        object_id: sector.sector.id,
                        flat_root: sector.sector.root,
                        source_commitment: sector.commitment.clone(),
                    },
                    &owner,
                )
                .unwrap(),
            ));
            records.push(CatalogCheckpointAuthorityRecord::LegacyAttestation(
                SignedRecord::sign(
                    LEGACY_PACKING_ATTESTATION_DOMAIN,
                    LegacyPackingAttestation {
                        format_version: 1,
                        guild_id: [16; 32],
                        membership_epoch: 2,
                        owner: owner.node_id(),
                        protected_root: crate::packing_protected_root(Uuid::from_u128(17)),
                        object_id: sector.sector.id,
                        flat_root: sector.sector.root,
                        source_commitment: sector.commitment,
                    },
                    &attester,
                )
                .unwrap(),
            ));
            Self {
                owner,
                attester,
                writer,
                legacy,
                paged,
                records,
                pages,
            }
        }
        fn scope(&self) -> CatalogScope {
            CatalogScope::Guild {
                guild_id: self.legacy.value.guild_id,
            }
        }
        fn build(
            &self,
            records: &[CatalogCheckpointAuthorityRecord],
        ) -> (CatalogCheckpointAuthorityRoot, Pages, Vec<CatalogPageRef>) {
            let mut pages = self.pages.clone();
            let mut roles = Vec::new();
            let mut builder = CatalogCheckpointAuthorityBuilder::new(self.scope(), 3, 2).unwrap();
            let mut sink = |page: CatalogPageRef, bytes| {
                roles.push(page);
                pages.insert(page.hash, bytes);
                Ok::<_, &'static str>(())
            };
            for record in records {
                builder.push(record, &mut sink).unwrap();
            }
            (builder.finish(&mut sink).unwrap(), pages, roles)
        }
    }
    fn read(
        scope: CatalogScope,
        root: CatalogCheckpointAuthorityRoot,
        pages: &Pages,
    ) -> Result<Vec<CatalogCheckpointAuthorityRecord>, CatalogStreamError<&'static str>> {
        let mut reader = CatalogCheckpointAuthorityReader::new(scope, root)?;
        let mut records = Vec::new();
        while let Some(record) = reader.next_record(&mut |page| fetch(pages, page))? {
            records.push(record);
        }
        Ok(records)
    }

    #[test]
    fn budgeted_authority_admits_cumulative_history_without_resetting_source_work() {
        let fixture = Fixture::new(3);
        // Claimed dense 1 TiB source geometry, signed and repeated in history.
        // No source bytes are fabricated or counted as a recovery qualification.
        let sources = (1_u64 << 24) + 1;
        let source_bytes = 8 + sources * (4 + CATALOG_SECTOR_RECORD_BYTES as u64);
        let mut nodes = source_bytes.div_ceil(CATALOG_LEAF_BYTES as u64);
        let mut source_pages = nodes;
        while nodes > 1 {
            nodes = nodes.div_ceil(CATALOG_FANOUT as u64);
            source_pages += nodes;
        }
        let mut records = fixture.records[..4].to_vec();
        let mut parent = fixture.legacy.value.hash().unwrap();
        for sequence in 2..=33 {
            let mut body = fixture.paged.value.clone();
            body.sequence = sequence;
            body.revision_id = Uuid::from_u128(sequence as u128 + 100);
            body.parent = Some(parent);
            body.sources.records.records = sources;
            body.sources.logical_bytes =
                (1_u64 << 40) + u64::from(body.metadata.sector.logical_len);
            body.sources.records.page = CatalogPageRef {
                hash: [99; 32],
                encoded_len: 512,
                height: 3,
                byte_len: source_bytes,
                page_occurrences: source_pages,
            };
            let signed = body.sign(&fixture.writer, &fixture.owner).unwrap();
            parent = signed.value.hash().unwrap();
            records.push(CatalogCheckpointAuthorityRecord::PagedRevision(signed));
        }
        let generous = CatalogCodingTraversalBudget {
            bytes: 128 << 30,
            page_occurrences: 2_000_000,
            records: 1 << 30,
        };
        let build = |budget| {
            let mut pages = fixture.pages.clone();
            let mut builder =
                CatalogCheckpointAuthorityBuilder::new_with_budget(fixture.scope(), 3, 2, budget)?;
            let mut sink = |page: CatalogPageRef, bytes| {
                pages.insert(page.hash, bytes);
                Ok::<_, &'static str>(())
            };
            for record in &records {
                builder.push(record, &mut sink)?;
            }
            Ok::<_, CatalogStreamError<&'static str>>((builder.finish(&mut sink)?, pages))
        };
        let (root, pages) = build(generous).unwrap();
        assert_eq!(root.format_version, 2);
        assert_eq!(root.summary.source_bytes, source_bytes * 32);
        assert_eq!(root.summary.source_pages, source_pages * 32);
        assert!(root.summary.source_bytes > CATALOG_MAX_STREAM_BYTES);
        assert!(root.summary.source_pages > CATALOG_MAX_PAGE_OCCURRENCES);
        assert!(root.validate().is_err());
        assert!(CatalogCheckpointAuthorityRoot::decode(&canonical_bytes(&root).unwrap()).is_err());
        assert!(CatalogCheckpointAuthorityReader::new(fixture.scope(), root).is_err());
        let mut exact = root.minimum_work().unwrap();
        exact.records += sources * 32;
        assert_eq!(build(exact).unwrap().0, root);
        assert_eq!(
            CatalogCheckpointAuthorityRoot::decode_with_budget(
                &canonical_bytes(&root).unwrap(),
                exact
            )
            .unwrap(),
            root
        );
        let mut reader =
            CatalogCheckpointAuthorityReader::new_with_budget(fixture.scope(), root, exact)
                .unwrap();
        let mut observed = Vec::new();
        while let Some(record) = reader.next_record(&mut |page| fetch(&pages, page)).unwrap() {
            observed.push(record);
        }
        assert_eq!(observed, records);
        for dimension in 0..3 {
            let mut short = exact;
            match dimension {
                0 => short.bytes -= 1,
                1 => short.page_occurrences -= 1,
                _ => short.records -= 1,
            }
            assert!(build(short).is_err());
            let reader =
                CatalogCheckpointAuthorityReader::new_with_budget(fixture.scope(), root, short);
            if dimension < 2 {
                assert!(reader.is_err());
                continue;
            }
            let mut reader = reader.unwrap();
            for expected in &records[..records.len() - 1] {
                assert_eq!(
                    reader
                        .next_record(&mut |page| fetch(&pages, page))
                        .unwrap()
                        .as_ref(),
                    Some(expected)
                );
            }
            assert!(matches!(
                reader.next_record(&mut |page| fetch(&pages, page)),
                Err(CatalogStreamError::Catalog(CatalogError::Bounds))
            ));
            assert!(matches!(
                reader.next_record::<&str>(&mut |_| panic!("failed reader fetched")),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
        let mut old = root;
        old.format_version = 1;
        assert!(old.validate_with_budget(generous).is_err());
        let mut understated = root;
        understated.summary.source_bytes -= 1;
        let mut reader = CatalogCheckpointAuthorityReader::new_with_budget(
            fixture.scope(),
            understated,
            generous,
        )
        .unwrap();
        for _ in 0..records.len() - 1 {
            assert!(
                reader
                    .next_record(&mut |page| fetch(&pages, page))
                    .unwrap()
                    .is_some()
            );
        }
        assert!(matches!(
            reader.next_record(&mut |page| fetch(&pages, page)),
            Err(CatalogStreamError::Catalog(CatalogError::InvalidPage))
        ));
    }

    #[test]
    fn budgeted_authority_preserves_original_layout_and_rejects_untrusted_shapes() {
        let fixture = Fixture::new(3);
        let (old, pages, _) = fixture.build(&fixture.records);
        let mut root = old;
        root.format_version = 2;
        let mut expected = canonical_bytes(&old).unwrap();
        expected[0] = 2;
        assert_eq!(canonical_bytes(&root).unwrap(), expected);
        let mut budget = root.minimum_work().unwrap();
        budget.records += fixture.paged.value.sources.records.records;
        let mut reader =
            CatalogCheckpointAuthorityReader::new_with_budget(fixture.scope(), root, budget)
                .unwrap();
        for record in &fixture.records {
            assert_eq!(
                reader
                    .next_record(&mut |page| fetch(&pages, page))
                    .unwrap()
                    .as_ref(),
                Some(record)
            );
        }
        assert!(
            reader
                .next_record(&mut |page| fetch(&pages, page))
                .unwrap()
                .is_none()
        );
        let mut short = budget;
        short.records -= 1;
        let mut reader =
            CatalogCheckpointAuthorityReader::new_with_budget(fixture.scope(), root, short)
                .unwrap();
        for expected in &fixture.records[..4] {
            assert_eq!(
                reader
                    .next_record(&mut |page| fetch(&pages, page))
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
        }
        // The later binding/attestation frames already own their credits.
        assert!(matches!(
            reader.next_record(&mut |page| fetch(&pages, page)),
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
        let unlimited = CatalogCodingTraversalBudget {
            bytes: u64::MAX,
            page_occurrences: u64::MAX,
            records: u64::MAX,
        };
        for case in 0..7 {
            let mut changed = root;
            match case {
                0 => changed.summary.source_bytes = CATALOG_MAX_STREAM_BYTES + 1,
                1 => changed.summary.source_pages = CATALOG_MAX_PAGE_OCCURRENCES + 1,
                2 => changed.summary.legacy_pages = CATALOG_MAX_PAGE_OCCURRENCES + 1,
                3 => changed.summary.revisions = u64::MAX,
                4 => changed.records.page.byte_len = CATALOG_MAX_STREAM_BYTES + 1,
                5 => changed.format_version = 3,
                _ => changed.summary.legacy_revisions = u64::MAX,
            }
            assert!(
                changed.validate_with_budget(unlimited).is_err(),
                "case {case}"
            );
        }
        for end in 0..expected.len() {
            assert!(
                CatalogCheckpointAuthorityRoot::decode_with_budget(&expected[..end], budget)
                    .is_err()
            );
        }
        expected.push(0);
        assert!(CatalogCheckpointAuthorityRoot::decode_with_budget(&expected, budget).is_err());
        assert!(
            CatalogCheckpointAuthorityBuilder::new_with_budget(
                fixture.scope(),
                3,
                2,
                CatalogCodingTraversalBudget::default()
            )
            .is_err()
        );
        let mut builder =
            CatalogCheckpointAuthorityBuilder::new_with_budget(fixture.scope(), 3, 2, budget)
                .unwrap();
        for record in &fixture.records {
            builder.push(record, &mut |_, _| Ok::<_, &str>(())).unwrap();
        }
        assert!(
            builder
                .finish(&mut |_, _| Err::<(), _>("sink failed"))
                .is_err()
        );
    }

    #[test]
    fn checkpoint_authority_roundtrips_mixed_revisions_and_original_legacy_signatures() {
        assert_eq!(canonical_bytes(&CatalogSection::Checkpoint).unwrap(), [5]);
        let fixture = Fixture::new(3);
        let mut previous = None;
        for sequence in [1, 127, 128, 255, 256, 16383, 16384, u64::MAX] {
            let mut key = CatalogCheckpointRevisionKey::from(&fixture.paged.value);
            key.sequence = sequence;
            if let Some(previous) = previous {
                assert!(key.index_key() > previous);
            }
            previous = Some(key.index_key());
        }
        for version in [3, 4, 5] {
            let fixture = Fixture::new(version);
            let (root, pages, _) = fixture.build(&fixture.records);
            if version == 3 {
                assert_eq!(
                    hex::encode(canonical_bytes(&root).unwrap()),
                    include_str!(
                        "../../../../protocol/vectors/checkpoint-authority-v1.postcard.hex"
                    )
                    .trim()
                );
            }
            assert_eq!(
                read(fixture.scope(), root, &pages).unwrap(),
                fixture.records
            );
            assert_eq!(
                CatalogCheckpointAuthorityRoot::decode(&canonical_bytes(&root).unwrap()).unwrap(),
                root
            );
            assert_eq!(root.summary.members, 2);
            assert_eq!(root.summary.writer_fences, 1);
            assert_eq!(root.summary.revisions, 2);
            assert_eq!(root.summary.legacy_revisions, 1);
            assert_eq!(root.summary.bindings, 1);
            assert_eq!(root.summary.attestations, 1);
            let CatalogCheckpointAuthorityRecord::LegacyRevision(reference) = &fixture.records[3]
            else {
                panic!()
            };
            let signed = reference
                .read_signed(&mut |page| fetch(&pages, page))
                .unwrap();
            assert_eq!(
                canonical_bytes(&signed).unwrap(),
                canonical_bytes(&fixture.legacy).unwrap()
            );
            assert_eq!(signed.value.hash().unwrap(), reference.revision_hash);
            assert!(
                root.represented_bytes().unwrap()
                    > root.records.page.byte_len + reference.body.byte_len
            );
        }
    }

    #[test]
    fn checkpoint_authority_rejects_understated_nested_work_before_exposing_references() {
        let mut fixture = Fixture::new(5);
        let mut builder = CatalogSectorBuilder::new(fixture.paged.value.scope()).unwrap();
        let mut sink = |page: CatalogPageRef, bytes| {
            fixture.pages.insert(page.hash, bytes);
            Ok::<_, &'static str>(())
        };
        for index in 0..640_u32 {
            let mut record = fixture.paged.value.metadata.clone();
            record.sector.id = [0; 32];
            record.sector.id[..4].copy_from_slice(&index.to_be_bytes());
            builder.push(&record, &mut sink).unwrap();
        }
        builder
            .push(&fixture.paged.value.metadata, &mut sink)
            .unwrap();
        let mut value = fixture.paged.value.clone();
        value.sources = builder.finish(&mut sink).unwrap();
        fixture.paged = value.sign(&fixture.writer, &fixture.owner).unwrap();
        fixture.records[4] = CatalogCheckpointAuthorityRecord::PagedRevision(fixture.paged.clone());
        let (root, pages, control_pages) = fixture.build(&fixture.records);
        assert!(root.summary.source_pages > 1);
        for dimension in 0..3 {
            let mut bad = root;
            match dimension {
                0 => bad.summary.legacy_bytes -= 1,
                1 => bad.summary.source_bytes -= 1,
                _ => bad.summary.source_pages -= 1,
            }
            bad.validate().unwrap();
            let mut reader = CatalogCheckpointAuthorityReader::new(fixture.scope(), bad).unwrap();
            let mut fetch = |page| {
                assert!(control_pages.contains(&page));
                self::fetch(&pages, page)
            };
            for _ in 0..if dimension == 0 { 3 } else { 4 } {
                assert!(reader.next_record(&mut fetch).unwrap().is_some());
            }
            assert!(reader.next_record(&mut fetch).is_err());
            assert!(
                reader
                    .next_record(&mut |_| -> Result<Vec<u8>, &'static str> {
                        panic!("failed reader fetched another page")
                    })
                    .is_err()
            );
        }
    }

    #[test]
    fn checkpoint_authority_rejects_bad_order_chains_fences_and_evidence() {
        let fixture = Fixture::new(3);
        for case in 0..8 {
            let mut records = fixture.records.clone();
            match case {
                0 => records.swap(0, 1),
                1 => records[1] = records[0].clone(),
                2 => {
                    let CatalogCheckpointAuthorityRecord::WriterFence(fence) = &mut records[2]
                    else {
                        panic!()
                    };
                    fence.epoch = 2;
                }
                3 | 4 => {
                    let mut revision = fixture.paged.value.clone();
                    if case == 3 {
                        revision.parent = Some([99; 32]);
                    } else {
                        revision.sequence = 4;
                    }
                    records[4] = CatalogCheckpointAuthorityRecord::PagedRevision(
                        revision.sign(&fixture.writer, &fixture.owner).unwrap(),
                    );
                }
                5 => {
                    let CatalogCheckpointAuthorityRecord::PagedRevision(revision) = &mut records[4]
                    else {
                        panic!()
                    };
                    revision.signature[0] ^= 1;
                }
                6 => {
                    let CatalogCheckpointAuthorityRecord::LegacyAttestation(signed) = &records[6]
                    else {
                        panic!()
                    };
                    let mut value = signed.value.clone();
                    value.membership_epoch += 1;
                    records[6] = CatalogCheckpointAuthorityRecord::LegacyAttestation(
                        SignedRecord::sign(
                            LEGACY_PACKING_ATTESTATION_DOMAIN,
                            value,
                            &fixture.attester,
                        )
                        .unwrap(),
                    );
                }
                _ => {
                    let CatalogCheckpointAuthorityRecord::LegacyBinding(signed) = &records[5]
                    else {
                        panic!()
                    };
                    records[5] = CatalogCheckpointAuthorityRecord::LegacyBinding(
                        SignedRecord::sign(
                            LEGACY_PACKING_BINDING_DOMAIN,
                            signed.value.clone(),
                            &fixture.attester,
                        )
                        .unwrap(),
                    );
                }
            }
            let mut builder =
                CatalogCheckpointAuthorityBuilder::new(fixture.scope(), 3, 2).unwrap();
            let mut rejected = false;
            for record in records {
                if builder.push(&record, &mut |_, _| Ok::<_, ()>(())).is_err() {
                    rejected = true;
                    break;
                }
            }
            assert!(rejected, "case {case}");
            assert!(
                builder
                    .push(&fixture.records[0], &mut |_, _| Ok::<_, ()>(()))
                    .is_err()
            );
            assert!(builder.finish(&mut |_, _| Ok::<_, ()>(())).is_err());
        }
        for tombstone in [RevisionTombstone {
            owner: fixture.owner.node_id(),
            protected_root_id: Uuid::from_u128(17),
            through_sequence: 2,
            last_revision_id: Uuid::from_u128(98),
            last_revision_hash: [98; 32],
            retired_at_generation: 4,
        }] {
            let mut builder =
                CatalogCheckpointAuthorityBuilder::new(fixture.scope(), 3, 2).unwrap();
            for record in &fixture.records[..3] {
                builder.push(record, &mut |_, _| Ok::<_, ()>(())).unwrap();
            }
            assert!(
                builder
                    .push(
                        &CatalogCheckpointAuthorityRecord::Tombstone(tombstone),
                        &mut |_, _| Ok::<_, ()>(())
                    )
                    .is_err()
            );
        }
    }

    #[test]
    fn checkpoint_authority_rejects_bounded_nested_signature_lengths_and_aggregate_summaries() {
        let fixture = Fixture::new(3);
        for variant in [4_u32, 5, 6] {
            let mut bytes = match variant {
                4 => {
                    canonical_bytes(&(variant, fixture.paged.signer, &fixture.paged.value)).unwrap()
                }
                5 => {
                    let CatalogCheckpointAuthorityRecord::LegacyBinding(signed) =
                        &fixture.records[5]
                    else {
                        panic!()
                    };
                    canonical_bytes(&(variant, signed.signer, &signed.value)).unwrap()
                }
                _ => {
                    let CatalogCheckpointAuthorityRecord::LegacyAttestation(signed) =
                        &fixture.records[6]
                    else {
                        panic!()
                    };
                    canonical_bytes(&(variant, signed.signer, &signed.value)).unwrap()
                }
            };
            bytes.extend(canonical_bytes(&65_usize).unwrap());
            bytes.extend([0; 65]);
            assert!(decode_canonical::<CatalogCheckpointAuthorityRecord>(&bytes).is_err());
        }
        let (root, pages, _) = fixture.build(&fixture.records);
        let mut changed = root;
        changed.summary.source_bytes += 1;
        changed.validate().unwrap();
        assert!(read(fixture.scope(), changed, &pages).is_err());
        let mut reader = CatalogCheckpointAuthorityReader::new(fixture.scope(), changed).unwrap();
        while reader
            .next_record(&mut |page| fetch(&pages, page))
            .is_ok_and(|value| value.is_some())
        {}
        assert!(matches!(
            reader.next_record::<&'static str>(&mut |_| panic!()),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        let mut changed = root;
        changed.summary.legacy_revisions = u64::MAX;
        assert!(changed.validate().is_err());
        let mut changed = root;
        changed.summary.source_bytes = CATALOG_MAX_STREAM_BYTES;
        assert!(changed.validate().is_err());
        let mut changed = root;
        changed.summary.source_pages = CATALOG_MAX_PAGE_OCCURRENCES;
        assert!(changed.validate().is_err());
        let bytes = canonical_bytes(&root).unwrap();
        for end in 0..bytes.len() {
            assert!(CatalogCheckpointAuthorityRoot::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CatalogCheckpointAuthorityRoot::decode(&trailing).is_err());
        assert!(
            CatalogCheckpointAuthorityRoot::decode(&vec![0; CATALOG_CHECKPOINT_ROOT_BYTES + 1])
                .is_err()
        );
        assert!(CatalogCheckpointAuthorityBuilder::new(fixture.paged.value.scope(), 3, 2).is_err());
    }

    #[test]
    fn checkpoint_authority_streams_many_revisions_and_fences_corrupt_tail_or_sink_failure() {
        let fixture = Fixture::new(3);
        let mut records = fixture.records[..4].to_vec();
        let mut previous = fixture.legacy.value.hash().unwrap();
        for sequence in 2..=1001_u64 {
            let mut body = fixture.paged.value.clone();
            body.sequence = sequence;
            body.revision_id = Uuid::from_u128(100 + sequence as u128);
            body.parent = Some(previous);
            let signed = body.sign(&fixture.writer, &fixture.owner).unwrap();
            previous = signed.value.hash().unwrap();
            records.push(CatalogCheckpointAuthorityRecord::PagedRevision(signed));
        }
        let (root, mut pages, roles) = fixture.build(&records);
        assert_eq!(root.summary.source_pages, 1000);
        assert!(root.records.page.page_occurrences > 2);
        assert_eq!(read(fixture.scope(), root, &pages).unwrap(), records);
        let tail = roles.iter().rfind(|page| page.height == 0).unwrap().hash;
        pages.get_mut(&tail).unwrap()[0] ^= 1;
        assert!(read(fixture.scope(), root, &pages).is_err());
        let mut builder = CatalogCheckpointAuthorityBuilder::new(fixture.scope(), 3, 2).unwrap();
        let mut rejected = false;
        for record in &records {
            if builder
                .push(record, &mut |_, _| Err::<(), _>("sink failed"))
                .is_err()
            {
                rejected = true;
                break;
            }
        }
        assert!(rejected);
        assert!(builder.finish(&mut |_, _| Ok::<_, &str>(())).is_err());
    }

    #[test]
    fn checkpoint_authority_handles_retained_tombstones_and_member_domain_boundaries() {
        let mut fixture = Fixture::new(3);
        let mut legacy = fixture.legacy.value.clone();
        legacy.sequence = 3;
        legacy.parent = Some([77; 32]);
        legacy.sign_writer(&fixture.writer).unwrap();
        let legacy = SignedRecord::sign(USER_REVISION_DOMAIN, legacy, &fixture.owner).unwrap();
        let body = byte_root(
            fixture.scope(),
            &canonical_bytes(&legacy).unwrap(),
            &mut fixture.pages,
        );
        let reference = CatalogLegacyRevisionRef::from_signed([16; 32], &legacy, body).unwrap();
        let mut paged = fixture.paged.value.clone();
        paged.sequence = 4;
        paged.parent = Some(legacy.value.hash().unwrap());
        let paged = paged.sign(&fixture.writer, &fixture.owner).unwrap();
        let mut records = fixture.records[..3].to_vec();
        records.push(CatalogCheckpointAuthorityRecord::Tombstone(
            RevisionTombstone {
                owner: fixture.owner.node_id(),
                protected_root_id: Uuid::from_u128(17),
                through_sequence: 2,
                last_revision_id: Uuid::from_u128(77),
                last_revision_hash: [77; 32],
                retired_at_generation: 2,
            },
        ));
        records.push(CatalogCheckpointAuthorityRecord::LegacyRevision(reference));
        records.push(CatalogCheckpointAuthorityRecord::PagedRevision(paged));
        let (root, pages, _) = fixture.build(&records);
        assert_eq!(root.summary.tombstones, 1);
        assert_eq!(read(fixture.scope(), root, &pages).unwrap(), records);

        let mut members = (0..=255_u8)
            .map(|seed| {
                let keys = KeyMaterial::from_seed(&Seed::from_bytes([seed; 32]));
                Member {
                    node_id: keys.node_id(),
                    recovery_public_key: keys.recovery_public_key(),
                    failure_domain: "é".repeat(128),
                }
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.node_id);
        let mut records = members
            .iter()
            .cloned()
            .map(CatalogCheckpointAuthorityRecord::Member)
            .collect::<Vec<_>>();
        records.extend(fixture.records[2..].iter().cloned());
        let (root, pages, _) = fixture.build(&records);
        assert_eq!(root.summary.members, 256);
        assert_eq!(read(fixture.scope(), root, &pages).unwrap(), records);
        let mut builder = CatalogCheckpointAuthorityBuilder::new(fixture.scope(), 3, 2).unwrap();
        for member in &members {
            builder
                .push(
                    &CatalogCheckpointAuthorityRecord::Member(member.clone()),
                    &mut |_, _| Ok::<_, ()>(()),
                )
                .unwrap();
        }
        assert!(matches!(
            builder.push(&fixture.records[0], &mut |_, _| Ok::<_, ()>(())),
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
        let mut member = members[0].clone();
        member.failure_domain = "é".repeat(129);
        let bytes = canonical_bytes(&CatalogCheckpointAuthorityRecord::Member(member)).unwrap();
        assert!(decode_canonical::<CatalogCheckpointAuthorityRecord>(&bytes).is_err());
    }

    #[test]
    fn checkpoint_legacy_reference_authenticates_full_body_and_exact_summary() {
        let mut fixture = Fixture::new(3);
        let mut body = fixture.legacy.value.clone();
        body.data_sectors = (0..2000_u32)
            .map(|index| {
                let mut sector = body.metadata_sectors[0].clone();
                sector.id = [0; 32];
                sector.id[..4].copy_from_slice(&index.to_be_bytes());
                sector.id[31] = 1;
                sector
            })
            .collect();
        body.sign_writer(&fixture.writer).unwrap();
        let signed = SignedRecord::sign(USER_REVISION_DOMAIN, body, &fixture.owner).unwrap();
        let bytes = canonical_bytes(&signed).unwrap();
        let body_root = byte_root(fixture.scope(), &bytes, &mut fixture.pages);
        assert!(body_root.page_occurrences > 2);
        let reference =
            CatalogLegacyRevisionRef::from_signed([16; 32], &signed, body_root).unwrap();
        assert_eq!(
            reference
                .read_signed(&mut |page| fetch(&fixture.pages, page))
                .unwrap(),
            signed
        );
        let mut changed = reference.clone();
        changed.revision_id = Uuid::from_u128(99);
        assert!(
            changed
                .read_signed(&mut |page| fetch(&fixture.pages, page))
                .is_err()
        );
        let mut bad = signed.clone();
        bad.signature[0] ^= 1;
        let bad_root = byte_root(
            fixture.scope(),
            &canonical_bytes(&bad).unwrap(),
            &mut fixture.pages,
        );
        changed = reference.clone();
        changed.body = bad_root;
        assert!(
            changed
                .read_signed(&mut |page| fetch(&fixture.pages, page))
                .is_err()
        );
        let mut visits = 0;
        assert!(
            reference
                .read_signed(&mut |page| {
                    visits += 1;
                    if visits == reference.body.page_occurrences {
                        return Err("last page unavailable");
                    }
                    fetch(&fixture.pages, page)
                })
                .is_err()
        );
        assert_eq!(visits, reference.body.page_occurrences);
        assert!(CatalogLegacyRevisionRef::from_signed([99; 32], &signed, body_root).is_err());
    }
}
