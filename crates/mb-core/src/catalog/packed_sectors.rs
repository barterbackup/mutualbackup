//! Bounded packed-sector descriptors. This stream verifies descriptor identity
//! and geometry; full packing admission must also join unique source chunks,
//! complete source coverage, authentication proofs and signed revision authority.

use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    CATALOG_MAX_RECORDS, CatalogError, CatalogPageRef, CatalogRecordBuilder, CatalogRecordReader,
    CatalogRecordRoot, CatalogScope, CatalogSection, CatalogStreamError,
};
use crate::{
    CatalogPackedSourceId, MerkleCommitment, NodeId, PackedCatalog, PackedSectorDescriptor,
    PackedSlot, PackingProfile, canonical_bytes_bounded, decode_canonical,
};

pub const CATALOG_PACKED_SLOTS: usize = 128;
pub const CATALOG_PACKED_RECORD_BYTES: usize = CATALOG_PACKED_SLOTS * 192 + 256;
pub const CATALOG_PACKED_ROOT_BYTES: usize = 512;

/// Full lengths and source offsets derive from the profile and chunk index.
/// The stable source key resolves to the original owner/root/object identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackedChunkReference {
    pub source_key: [u8; 32],
    pub chunk_index: u32,
    pub content_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackedSlotReference {
    Data(CatalogPackedChunkReference),
    VirtualZero {
        source: Option<CatalogPackedChunkReference>,
    },
}

impl CatalogPackedSlotReference {
    fn from_slot(slot: &PackedSlot) -> Self {
        let reference = slot.source().map(|source| CatalogPackedChunkReference {
            source_key: CatalogPackedSourceId {
                owner: source.id.owner,
                protected_root: source.id.protected_root,
                object_id: source.id.object_id,
            }
            .key(),
            chunk_index: source.id.chunk_index,
            content_hash: source.content_hash,
        });
        match slot {
            PackedSlot::Data(_) => Self::Data(reference.expect("data source")),
            PackedSlot::VirtualZero { .. } => Self::VirtualZero { source: reference },
        }
    }

    fn expand<E>(
        &self,
        profile: PackingProfile,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, E>,
    ) -> Result<PackedSlot, CatalogStreamError<E>> {
        let reference = match self {
            Self::Data(source) => Some(source),
            Self::VirtualZero { source } => source.as_ref(),
        };
        let source = reference
            .map(|reference| -> Result<_, CatalogStreamError<E>> {
                let id = resolve(reference.source_key).map_err(CatalogStreamError::Storage)?;
                if id.key() != reference.source_key {
                    return Err(CatalogError::InvalidPage.into());
                }
                Ok(crate::PackedSourceChunk {
                    id: id.chunk(reference.chunk_index),
                    source_offset: u64::from(reference.chunk_index) * u64::from(profile.slot_size),
                    logical_len: profile.slot_size,
                    content_hash: reference.content_hash,
                })
            })
            .transpose()?;
        Ok(match self {
            Self::Data(_) => PackedSlot::Data(source.expect("data source")),
            Self::VirtualZero { .. } => PackedSlot::VirtualZero { source },
        })
    }
}

/// Discriminants are append-only within record version one. Sector headers
/// occur in contiguous sector-index order, followed by exact-size fragments.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackedSectorRecord {
    Header {
        format_version: u16,
        id: [u8; 32],
        sector_index: u32,
        flat_root: [u8; 32],
        commitment: MerkleCommitment,
    },
    Slots {
        offset: u32,
        #[serde(deserialize_with = "decode_slots")]
        slots: Vec<PackedSlot>,
    },
    CompactSlots {
        offset: u32,
        #[serde(deserialize_with = "decode_references")]
        slots: Vec<CatalogPackedSlotReference>,
    },
}

fn decode_references<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<CatalogPackedSlotReference>, D::Error> {
    crate::bounded::VecSeed::new(CATALOG_PACKED_SLOTS).deserialize(decoder)
}

fn decode_slots<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<PackedSlot>, D::Error> {
    crate::bounded::VecSeed::new(CATALOG_PACKED_SLOTS).deserialize(decoder)
}

impl CatalogPackedSectorRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_PACKED_RECORD_BYTES {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        match &record {
            Self::Header {
                format_version,
                commitment,
                ..
            } if *format_version != 1 || commitment.validate().is_err() => {
                return Err(CatalogError::InvalidPage);
            }
            Self::Slots { slots, .. } if slots.is_empty() || slots.len() > CATALOG_PACKED_SLOTS => {
                return Err(CatalogError::Bounds);
            }
            Self::CompactSlots { slots, .. }
                if slots.is_empty() || slots.len() > CATALOG_PACKED_SLOTS =>
            {
                return Err(CatalogError::Bounds);
            }
            _ => {}
        }
        if canonical_bytes_bounded(&record, CATALOG_PACKED_RECORD_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

/// Authenticate all fields together in the enclosing packing/checkpoint root.
/// `packing_version` preserves versions 1/2's flat-hash semantics and versions
/// 3/4/5's Merkle-root semantics. This descriptor summary alone supplies no
/// source authorization, proof coverage, quota or protection claim.
/// Source counts/bytes count slot occurrences; the complete packing join must
/// additionally reject duplicate source chunks and incomplete source coverage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackedSectorRoot {
    pub format_version: u16,
    pub packing_version: u16,
    pub profile: PackingProfile,
    pub records: CatalogRecordRoot,
    pub sectors: u64,
    pub slots: u64,
    pub source_chunks: u64,
    pub source_bytes: u64,
}

impl CatalogPackedSectorRoot {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_PACKED_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate()?;
        if canonical_bytes_bounded(&root, CATALOG_PACKED_ROOT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }

    pub fn validate(self) -> Result<(), CatalogError> {
        self.validate_geometry(false)
    }

    pub(super) fn validate_part(self) -> Result<(), CatalogError> {
        self.validate_geometry(true)
    }

    fn validate_geometry(self, part: bool) -> Result<(), CatalogError> {
        self.records.validate()?;
        let width = self
            .profile
            .slots_per_sector()
            .map_err(|_| CatalogError::InvalidPage)?;
        let fragments = u64::from(width).div_ceil(CATALOG_PACKED_SLOTS as u64);
        if !matches!(self.format_version, 1 | 2)
            || !matches!(self.packing_version, 1..=5)
            || self.format_version == 2 && self.packing_version < 2
            || self.sectors > CATALOG_MAX_RECORDS
            || self.sectors.checked_mul(1 + fragments) != Some(self.records.records)
            || self.sectors.checked_mul(u64::from(width)) != Some(self.slots)
            || self.source_chunks > self.slots
            || !part && (self.sectors == 0) != (self.source_chunks == 0)
            || self.source_bytes < self.source_chunks
            || self
                .source_chunks
                .checked_mul(u64::from(self.profile.slot_size))
                .is_none_or(|maximum| self.source_bytes > maximum)
            || self.packing_version >= 2
                && self
                    .source_chunks
                    .checked_mul(u64::from(self.profile.slot_size))
                    != Some(self.source_bytes)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    /// Convert only the descriptor stream of an already validated legacy
    /// catalog. Proofs/bindings/attestations remain separate required streams;
    /// their original signed encoding and catalog ID are never rewritten here.
    pub fn from_legacy<E>(
        scope: CatalogScope,
        catalog: &PackedCatalog,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<Self, CatalogStreamError<E>> {
        catalog.validate().map_err(|_| CatalogError::InvalidPage)?;
        if let CatalogScope::Guild { guild_id } = scope
            && catalog
                .legacy_attestations
                .as_ref()
                .is_some_and(|entries| entries.iter().any(|entry| entry.value.guild_id != guild_id))
        {
            return Err(CatalogError::InvalidPage.into());
        }
        let mut builder =
            CatalogPackedSectorBuilder::new(scope, catalog.format_version, catalog.profile)?;
        for sector in &catalog.sectors {
            builder.push_sector(sector, sink)?;
        }
        builder.finish(sink)
    }
}

struct ActiveSector {
    id: [u8; 32],
    hash: crate::packing::PackedSectorIdHasher,
    consumed: u32,
    has_source: bool,
}

struct SectorState {
    first_sector: u32,
    packing_version: u16,
    profile: PackingProfile,
    active: Option<ActiveSector>,
    sectors: u64,
    slots: u64,
    source_chunks: u64,
    source_bytes: u64,
    last_has_source: bool,
}

impl SectorState {
    fn new(packing_version: u16, profile: PackingProfile) -> Result<Self, CatalogError> {
        profile.validate().map_err(|_| CatalogError::InvalidPage)?;
        if !matches!(packing_version, 1..=5) {
            return Err(CatalogError::InvalidPage);
        }
        Ok(Self {
            first_sector: 0,
            packing_version,
            profile,
            active: None,
            sectors: 0,
            slots: 0,
            source_chunks: 0,
            source_bytes: 0,
            last_has_source: false,
        })
    }

    fn accept(&mut self, record: &CatalogPackedSectorRecord) -> Result<(), CatalogError> {
        let width = self.profile.sector_size / self.profile.slot_size;
        match record {
            CatalogPackedSectorRecord::Header {
                format_version,
                id,
                sector_index,
                flat_root,
                commitment,
            } => {
                if *format_version != 1
                    || self.active.is_some()
                    || u64::from(*sector_index) != u64::from(self.first_sector) + self.sectors
                    || *flat_root == [0; 32]
                    || commitment.byte_len != self.profile.sector_size
                    || commitment.validate().is_err()
                    || self.packing_version >= 3 && *flat_root != commitment.root
                {
                    return Err(CatalogError::InvalidPage);
                }
                let hash = crate::packing::PackedSectorIdHasher::new(
                    self.profile,
                    *sector_index,
                    *flat_root,
                    commitment,
                    width as usize,
                )?;
                self.active = Some(ActiveSector {
                    id: *id,
                    hash,
                    consumed: 0,
                    has_source: false,
                });
                self.sectors += 1;
            }
            CatalogPackedSectorRecord::Slots { offset, slots } => {
                let active = self.active.as_mut().ok_or(CatalogError::InvalidPage)?;
                let expected = (width - active.consumed).min(CATALOG_PACKED_SLOTS as u32);
                if *offset != active.consumed
                    || slots.is_empty()
                    || slots.len() != expected as usize
                {
                    return Err(CatalogError::InvalidPage);
                }
                for slot in slots {
                    if let Some(source) = slot.source() {
                        if source.id.owner == NodeId([0; 32])
                            || source.id.protected_root == [0; 32]
                            || source.id.object_id == [0; 32]
                            || source.logical_len == 0
                            || source.logical_len > self.profile.slot_size
                            || self.packing_version >= 2
                                && source.logical_len != self.profile.slot_size
                            || source.source_offset
                                != u64::from(source.id.chunk_index)
                                    * u64::from(self.profile.slot_size)
                        {
                            return Err(CatalogError::InvalidPage);
                        }
                        self.source_chunks += 1;
                        self.source_bytes = self
                            .source_bytes
                            .checked_add(u64::from(source.logical_len))
                            .ok_or(CatalogError::Bounds)?;
                        active.has_source = true;
                    }
                    active.hash.push(slot)?;
                }
                active.consumed += slots.len() as u32;
                self.slots += slots.len() as u64;
                if active.consumed == width {
                    let active = self.active.take().expect("completed sector exists");
                    if active.hash.finish() != active.id {
                        return Err(CatalogError::InvalidPage);
                    }
                    self.last_has_source = active.has_source;
                }
            }
            CatalogPackedSectorRecord::CompactSlots { .. } => {
                return Err(CatalogError::InvalidPage);
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), CatalogError> {
        self.finish_part(false)
    }

    fn finish_part(&self, part: bool) -> Result<(), CatalogError> {
        if self.active.is_some() || !part && self.sectors != 0 && !self.last_has_source {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

/// Construct sectors directly from bounded records. The convenience bridge
/// borrows existing slot vectors without making another whole descriptor copy.
/// Any encoding/storage/schema failure permanently fences this builder.
pub struct CatalogPackedSectorBuilder {
    records: CatalogRecordBuilder,
    state: SectorState,
    failed: bool,
    format_version: u16,
}

impl CatalogPackedSectorBuilder {
    pub fn new(
        scope: CatalogScope,
        packing_version: u16,
        profile: PackingProfile,
    ) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::Packing)?,
            state: SectorState::new(packing_version, profile)?,
            failed: false,
            format_version: 1,
        })
    }

    /// Encode bounded full slots as compact references while hashing exactly
    /// their original representation. Signed legacy sector IDs stay unchanged.
    pub fn new_compact(
        scope: CatalogScope,
        packing_version: u16,
        profile: PackingProfile,
    ) -> Result<Self, CatalogError> {
        if packing_version < 2 {
            return Err(CatalogError::InvalidPage);
        }
        let mut builder = Self::new(scope, packing_version, profile)?;
        builder.format_version = 2;
        Ok(builder)
    }

    /// Build one nonempty directory part at its original global sector index.
    /// The range envelope must be authenticated with the root; never renumber
    /// descriptors or rewrite their original sector identities at a boundary.
    pub fn new_part(
        scope: CatalogScope,
        packing_version: u16,
        profile: PackingProfile,
        first_sector: u32,
    ) -> Result<Self, CatalogError> {
        let mut builder = Self::new_compact(scope, packing_version, profile)?;
        builder.state.first_sector = first_sector;
        Ok(builder)
    }

    pub fn push<E>(
        &mut self,
        record: &CatalogPackedSectorRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            self.state.accept(record)?;
            if self.format_version == 2
                && let CatalogPackedSectorRecord::Slots { offset, slots } = record
            {
                self.records.push(
                    &CatalogPackedSectorRecord::CompactSlots {
                        offset: *offset,
                        slots: slots
                            .iter()
                            .map(CatalogPackedSlotReference::from_slot)
                            .collect(),
                    },
                    sink,
                )
            } else {
                self.records.push(record, sink)
            }
        })();
        self.failed = result.is_err();
        result
    }

    pub fn push_sector<E>(
        &mut self,
        sector: &PackedSectorDescriptor,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if sector.slots.len()
            != (self.state.profile.sector_size / self.state.profile.slot_size) as usize
        {
            self.failed = true;
            return Err(CatalogError::InvalidPage.into());
        }
        self.push(
            &CatalogPackedSectorRecord::Header {
                format_version: 1,
                id: sector.id,
                sector_index: sector.sector_index,
                flat_root: sector.flat_root,
                commitment: sector.commitment.clone(),
            },
            sink,
        )?;
        for (index, slots) in sector.slots.chunks(CATALOG_PACKED_SLOTS).enumerate() {
            self.push(
                &CatalogPackedSectorRecord::Slots {
                    offset: (index * CATALOG_PACKED_SLOTS) as u32,
                    slots: slots.to_vec(),
                },
                sink,
            )?;
        }
        Ok(())
    }

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPackedSectorRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if self.state.first_sector != 0 {
            return Err(CatalogError::InvalidPage.into());
        }
        self.finish_root(sink, false)
    }

    pub fn finish_part<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<super::CatalogPackedSectorPart, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if self.state.sectors == 0 {
            return Err(CatalogError::Bounds.into());
        }
        let first_sector = self.state.first_sector;
        let part = super::CatalogPackedSectorPart {
            format_version: 1,
            first_sector,
            root: self.finish_root(sink, true)?,
        };
        part.validate()?;
        Ok(part)
    }

    fn finish_root<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
        part: bool,
    ) -> Result<CatalogPackedSectorRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.state.finish_part(part)?;
        let root = CatalogPackedSectorRoot {
            format_version: self.format_version,
            packing_version: self.state.packing_version,
            profile: self.state.profile,
            records: self.records.finish(sink)?,
            sectors: self.state.sectors,
            slots: self.state.slots,
            source_chunks: self.state.source_chunks,
            source_bytes: self.state.source_bytes,
        };
        root.validate_geometry(part)?;
        Ok(root)
    }
}

/// Yield one fragment while checking the original sector ID incrementally.
/// Full authenticated EOF and the enclosing source/proof joins are required
/// before any staged packing/checkpoint state can become authoritative.
pub struct CatalogPackedSectorReader {
    records: CatalogRecordReader,
    root: CatalogPackedSectorRoot,
    state: SectorState,
    consumed: u64,
    failed: bool,
    part: bool,
}

impl CatalogPackedSectorReader {
    pub fn new(scope: CatalogScope, root: CatalogPackedSectorRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::Packing, root.records)?,
            root,
            state: SectorState::new(root.packing_version, root.profile)?,
            consumed: 0,
            failed: false,
            part: false,
        })
    }

    pub fn for_part(
        scope: CatalogScope,
        part: super::CatalogPackedSectorPart,
    ) -> Result<Self, CatalogError> {
        part.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::Packing, part.root.records)?,
            root: part.root,
            state: SectorState {
                first_sector: part.first_sector,
                ..SectorState::new(part.root.packing_version, part.root.profile)?
            },
            consumed: 0,
            failed: false,
            part: true,
        })
    }

    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if self.root.format_version != 1 {
            self.failed = true;
            return Err(CatalogError::InvalidPage.into());
        }
        self.next_record_with_sources(fetch, &mut |_| {
            unreachable!("full descriptors do not resolve compact keys")
        })
    }

    /// Compact records resolve through an authenticated source index. Every
    /// returned slot uses its original identity, with checked key binding and
    /// incremental verification of the unchanged legacy sector ID.
    pub fn next_record_with_sources<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, E>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.next_inner(fetch, resolve);
        self.failed = result.is_err();
        result
    }

    fn next_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, E>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            self.verify_totals()?;
            return Ok(None);
        };
        let record = match (
            self.root.format_version,
            CatalogPackedSectorRecord::decode(&bytes)?,
        ) {
            (2, CatalogPackedSectorRecord::CompactSlots { offset, slots }) => {
                CatalogPackedSectorRecord::Slots {
                    offset,
                    slots: slots
                        .iter()
                        .map(|slot| slot.expand(self.root.profile, resolve))
                        .collect::<Result<_, _>>()?,
                }
            }
            (1, CatalogPackedSectorRecord::Slots { offset, slots }) => {
                CatalogPackedSectorRecord::Slots { offset, slots }
            }
            (_, header @ CatalogPackedSectorRecord::Header { .. }) => header,
            _ => return Err(CatalogError::InvalidPage.into()),
        };
        self.state.accept(&record)?;
        self.consumed += 1;
        if self.state.sectors > self.root.sectors
            || self.state.slots > self.root.slots
            || self.state.source_chunks > self.root.source_chunks
            || self.state.source_bytes > self.root.source_bytes
        {
            return Err(CatalogError::InvalidPage.into());
        }
        if self.consumed == self.root.records.records {
            self.verify_totals()?;
        }
        Ok(Some(record))
    }

    fn verify_totals(&self) -> Result<(), CatalogError> {
        if self.part {
            self.state.finish_part(true)?;
        } else {
            self.state.finish()?;
        }
        if self.state.sectors != self.root.sectors
            || self.state.slots != self.root.slots
            || self.state.source_chunks != self.root.source_chunks
            || self.state.source_bytes != self.root.source_bytes
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    pub(super) fn last_sector_has_source(&self) -> bool {
        self.state.last_has_source
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        CATALOG_LEAF_BYTES, KeyMaterial, LEGACY_PACKING_ATTESTATION_DOMAIN,
        LEGACY_PACKING_BINDING_DOMAIN, LegacyPackingAttestation, LegacyPackingBinding,
        MERKLE_LEAF_SIZE, PackedSourceChunk, PackingInput, Seed, SignedRecord, SourceChunkId,
        attach_legacy_packing_bindings, attach_legacy_packing_evidence, canonical_bytes,
        merkle_commit, merkle_zero_commitment, pack_incremental,
    };

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    #[test]
    fn compact_descriptors_resolve_stable_keys_and_preserve_original_sector_ids() {
        let profile = profile();
        let sectors = (0..256)
            .map(|index| descriptor(index, profile))
            .collect::<Vec<_>>();
        let (full, _) = build(&sectors, profile);
        let mut sources = HashMap::new();
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogPackedSectorBuilder::new_compact(scope(), 3, profile).unwrap();
        for sector in &sectors {
            for source in sector.slots.iter().filter_map(PackedSlot::source) {
                let id = CatalogPackedSourceId {
                    owner: source.id.owner,
                    protected_root: source.id.protected_root,
                    object_id: source.id.object_id,
                };
                sources.insert(id.key(), id);
                let mut original = id.owner.0.to_vec();
                original.extend(id.protected_root);
                original.extend(id.object_id);
                assert_eq!(
                    id.key(),
                    blake3::derive_key("mutualbackup packed source identity v1", &original)
                );
            }
            builder.push_sector(sector, &mut sink).unwrap();
        }
        let root = builder.finish(&mut sink).unwrap();
        assert_eq!(root.format_version, 2);
        assert_eq!(root.source_chunks, full.source_chunks);
        assert!(root.records.page.byte_len < full.records.page.byte_len);
        let mut reader = CatalogPackedSectorReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        let mut resolve = |key| sources.get(&key).copied().ok_or("missing source");
        for expected in sectors.iter().flat_map(records) {
            assert_eq!(
                reader
                    .next_record_with_sources(&mut fetch, &mut resolve)
                    .unwrap(),
                Some(expected)
            );
        }
        assert_eq!(
            reader
                .next_record_with_sources(&mut fetch, &mut resolve)
                .unwrap(),
            None
        );
        for failed_resolver in [false, true] {
            let mut reader = CatalogPackedSectorReader::new(scope(), root).unwrap();
            let mut resolve = |_| {
                if failed_resolver {
                    Err("resolve failure")
                } else {
                    Ok(CatalogPackedSourceId {
                        owner: NodeId([8; 32]),
                        protected_root: [3; 32],
                        object_id: [4; 32],
                    })
                }
            };
            assert!(
                reader
                    .next_record_with_sources(&mut fetch, &mut resolve)
                    .unwrap()
                    .is_some()
            );
            assert!(
                reader
                    .next_record_with_sources(&mut fetch, &mut resolve)
                    .is_err()
            );
            assert!(matches!(
                reader.next_record_with_sources(&mut fetch, &mut resolve),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
        let mut reader = CatalogPackedSectorReader::new(scope(), root).unwrap();
        assert!(reader.next_record(&mut fetch).is_err());
        assert!(
            reader
                .next_record_with_sources(&mut fetch, &mut resolve)
                .is_err()
        );
        assert!(CatalogPackedSectorBuilder::new_compact(scope(), 1, profile).is_err());
        let mut oversized = vec![2, 0];
        oversized.extend(canonical_bytes(&129_usize).unwrap());
        assert!(CatalogPackedSectorRecord::decode(&oversized).is_err());
        // Adding a source changes neither an existing stable key nor its slot.
        let slot = &sectors[0].slots[0];
        let before = canonical_bytes(&CatalogPackedSlotReference::from_slot(slot)).unwrap();
        let id = CatalogPackedSourceId {
            owner: NodeId([2; 32]),
            protected_root: [3; 32],
            object_id: [1; 32],
        };
        sources.insert(id.key(), id);
        assert_eq!(
            canonical_bytes(&CatalogPackedSlotReference::from_slot(slot)).unwrap(),
            before
        );
    }

    #[test]
    fn compact_packing_metadata_bound_fits_dense_one_tib_geometry() {
        let profile = PackingProfile {
            format_version: 1,
            sector_size: 65536,
            slot_size: 16384,
        };
        let source_count = (1_u64 << 40) / u64::from(profile.sector_size);
        let sector = descriptor(u32::MAX, profile);
        let header_bytes = canonical_bytes(&records(&sector)[0]).unwrap().len() as u64;
        let compact = CatalogPackedSectorRecord::CompactSlots {
            offset: 0,
            slots: sector
                .slots
                .iter()
                .map(CatalogPackedSlotReference::from_slot)
                .collect(),
        };
        let slot_bytes = canonical_bytes(&compact).unwrap().len() as u64;
        let source_header = crate::CatalogPackedSourceRecord::Source {
            format_version: 1,
            id: CatalogPackedSourceId {
                owner: NodeId([2; 32]),
                protected_root: [3; 32],
                object_id: [4; 32],
            },
            commitment: sector.commitment.clone(),
        };
        let subtrees = crate::CatalogPackedSourceRecord::Subtrees {
            first_chunk: 0,
            roots: vec![[5; 32]; 4],
        };
        let proof_bytes = canonical_bytes(&source_header).unwrap().len() as u64
            + canonical_bytes(&subtrees).unwrap().len() as u64;
        let stream_bytes = [
            8 + source_count * (8 + header_bytes + slot_bytes),
            8 + source_count * (8 + proof_bytes),
        ];
        let mut encoded_upper_bound = 0_u64;
        let mut occurrences = 0_u64;
        for bytes in stream_bytes {
            assert!(bytes < super::super::CATALOG_MAX_STREAM_BYTES);
            let mut nodes = bytes.div_ceil(CATALOG_LEAF_BYTES as u64);
            occurrences += nodes;
            encoded_upper_bound += nodes * crate::CATALOG_PAGE_BYTES as u64;
            let mut height = 0;
            while nodes > 1 {
                nodes = nodes.div_ceil(crate::CATALOG_FANOUT as u64);
                occurrences += nodes;
                encoded_upper_bound += nodes * crate::CATALOG_PAGE_BYTES as u64;
                height += 1;
            }
            assert!(height <= crate::CATALOG_MAX_HEIGHT);
        }
        assert!(encoded_upper_bound + 4096 < crate::CATALOG_MAX_STREAM_BYTES);
        assert!(occurrences < crate::CATALOG_MAX_PAGE_OCCURRENCES);
        assert!(source_count * 2 < crate::CATALOG_MAX_RECORDS);
        // This is a conservative codec-size calculation, not a real-data gate.
    }

    fn scope() -> CatalogScope {
        CatalogScope::Guild { guild_id: [9; 32] }
    }

    fn profile() -> PackingProfile {
        PackingProfile {
            format_version: 1,
            sector_size: 64,
            slot_size: 16,
        }
    }

    fn descriptor(index: u32, profile: PackingProfile) -> PackedSectorDescriptor {
        let mut object_id = [4; 32];
        object_id[..4].copy_from_slice(&index.to_be_bytes());
        let commitment = merkle_zero_commitment(profile.sector_size).unwrap();
        let mut descriptor = PackedSectorDescriptor {
            id: [0; 32],
            sector_index: index,
            flat_root: commitment.root,
            commitment,
            slots: (0..profile.sector_size / profile.slot_size)
                .map(|chunk_index| {
                    PackedSlot::Data(PackedSourceChunk {
                        id: SourceChunkId {
                            owner: NodeId([2; 32]),
                            protected_root: [3; 32],
                            object_id,
                            chunk_index,
                        },
                        source_offset: u64::from(chunk_index) * u64::from(profile.slot_size),
                        logical_len: profile.slot_size,
                        content_hash: [5; 32],
                    })
                })
                .collect(),
        };
        descriptor.id = descriptor.calculate_id(profile).unwrap();
        descriptor
    }

    fn records(sector: &PackedSectorDescriptor) -> Vec<CatalogPackedSectorRecord> {
        let mut records = vec![CatalogPackedSectorRecord::Header {
            format_version: 1,
            id: sector.id,
            sector_index: sector.sector_index,
            flat_root: sector.flat_root,
            commitment: sector.commitment.clone(),
        }];
        records.extend(sector.slots.chunks(CATALOG_PACKED_SLOTS).enumerate().map(
            |(index, slots)| CatalogPackedSectorRecord::Slots {
                offset: (index * CATALOG_PACKED_SLOTS) as u32,
                slots: slots.to_vec(),
            },
        ));
        records
    }

    fn build(
        sectors: &[PackedSectorDescriptor],
        profile: PackingProfile,
    ) -> (CatalogPackedSectorRoot, Pages) {
        let mut pages = Pages::new();
        let mut builder = CatalogPackedSectorBuilder::new(scope(), 3, profile).unwrap();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for sector in sectors {
            builder.push_sector(sector, &mut sink).unwrap();
        }
        let root = builder.finish(&mut sink).unwrap();
        (root, pages)
    }

    fn raw_records(
        mut root: CatalogPackedSectorRoot,
        records: &[CatalogPackedSectorRecord],
    ) -> (CatalogPackedSectorRoot, Pages) {
        let mut pages = Pages::new();
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::Packing).unwrap();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        root.records = builder.finish(&mut sink).unwrap();
        (root, pages)
    }

    fn read(root: CatalogPackedSectorRoot, pages: &Pages) -> Vec<CatalogPackedSectorRecord> {
        let mut reader = CatalogPackedSectorReader::new(scope(), root).unwrap();
        let mut result = Vec::new();
        let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone());
        while let Some(record) = reader.next_record(&mut fetch).unwrap() {
            result.push(record);
        }
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
        result
    }

    fn assert_rejected(root: CatalogPackedSectorRoot, pages: &Pages) {
        let Ok(mut reader) = CatalogPackedSectorReader::new(scope(), root) else {
            return;
        };
        let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone());
        let mut yielded = 0;
        loop {
            match reader.next_record(&mut fetch) {
                Err(_) => break,
                Ok(Some(_)) => yielded += 1,
                Ok(None) => panic!("malformed descriptor stream accepted"),
            }
        }
        assert!(yielded < root.records.records);
        assert!(matches!(
            reader.next_record(&mut fetch),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }

    fn reference_catalog_id(catalog: &PackedCatalog) -> [u8; 32] {
        let version = catalog.format_version;
        let domain = format!("mutualbackup packed catalog v{version}");
        let bytes = match version {
            1 => canonical_bytes(&(
                version,
                catalog.revision,
                catalog.parent,
                catalog.profile,
                &catalog.sectors,
            )),
            2 | 3 => canonical_bytes(&(
                version,
                catalog.revision,
                catalog.parent,
                catalog.profile,
                &catalog.sectors,
                catalog.source_authentication.as_ref().unwrap(),
            )),
            4 => canonical_bytes(&(
                version,
                catalog.revision,
                catalog.parent,
                catalog.profile,
                &catalog.sectors,
                catalog.source_authentication.as_ref().unwrap(),
                catalog.legacy_bindings.as_ref().unwrap(),
            )),
            5 => canonical_bytes(&(
                version,
                catalog.revision,
                catalog.parent,
                catalog.profile,
                &catalog.sectors,
                catalog.source_authentication.as_ref().unwrap(),
                catalog.legacy_bindings.as_ref().unwrap(),
                catalog.legacy_attestations.as_ref().unwrap(),
            )),
            _ => unreachable!(),
        }
        .unwrap();
        let mut hash = blake3::Hasher::new_derive_key(&domain);
        hash.update(&bytes);
        *hash.finalize().as_bytes()
    }

    #[test]
    fn packed_sector_stream_round_trips_many_pages_and_exact_summaries() {
        let sectors = (0..1_024)
            .map(|index| descriptor(index, profile()))
            .collect::<Vec<_>>();
        let (root, pages) = build(&sectors, profile());
        assert!(pages.len() > 8);
        assert_eq!(root.sectors, 1_024);
        assert_eq!(root.slots, 4_096);
        assert_eq!(root.source_chunks, 4_096);
        assert_eq!(root.source_bytes, 1_024 * 64);
        let expected = sectors.iter().flat_map(records).collect::<Vec<_>>();
        assert_eq!(read(root, &pages), expected);
        assert!(expected.iter().all(|record| canonical_bytes(record).unwrap().len() <= CATALOG_PACKED_RECORD_BYTES));
        let other = CatalogScope::Guild { guild_id: [8; 32] };
        let mut reader = CatalogPackedSectorReader::new(other, root).unwrap();
        assert!(
            reader
                .next_record(&mut |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone()))
                .is_err()
        );
    }

    #[test]
    fn packed_sector_stream_fragments_a_descriptor_larger_than_one_page() {
        let profile = PackingProfile {
            format_version: 1,
            sector_size: crate::V1_SECTOR_SIZE as u32,
            slot_size: MERKLE_LEAF_SIZE as u32,
        };
        let sector = descriptor(0, profile);
        let mut old_hash = blake3::Hasher::new_derive_key("mutualbackup packed sector v1");
        let old_bytes = canonical_bytes(&(
            profile,
            sector.sector_index,
            sector.flat_root,
            &sector.commitment,
            &sector.slots,
        ))
        .unwrap();
        assert!(old_bytes.len() > CATALOG_LEAF_BYTES);
        old_hash.update(&old_bytes);
        assert_eq!(sector.id, *old_hash.finalize().as_bytes());
        let (root, pages) = build(std::slice::from_ref(&sector), profile);
        assert_eq!(
            root.records.records,
            1 + 4_096 / CATALOG_PACKED_SLOTS as u64
        );
        assert_eq!(read(root, &pages), records(&sector));
        // A maximum-profile declaration cannot substitute for the actual
        // descriptor geometry, even if its record/page bounds permit it.
        let maximum = PackingProfile {
            sector_size: crate::MAX_PROFILE_SHARD_SIZE,
            ..profile
        };
        let mut maximum_root = root;
        maximum_root.profile = maximum;
        maximum_root.slots = u64::from(maximum.sector_size / maximum.slot_size);
        maximum_root.records.records = 1 + maximum_root.slots.div_ceil(CATALOG_PACKED_SLOTS as u64);
        assert_rejected(maximum_root, &pages);
    }

    #[test]
    fn packed_sector_legacy_adapter_preserves_all_five_layouts_and_rejects_before_writes() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([51; 32]));
        let bytes = (0..64_u8).rev().collect::<Vec<_>>();
        let input = |authenticated: bool| PackingInput {
            owner: keys.node_id(),
            protected_root: [3; 32],
            object_id: [4; 32],
            source_commitment: authenticated.then(|| merkle_commit(&bytes).unwrap()),
            bytes: bytes.clone(),
        };
        let legacy = pack_incremental(profile(), None, vec![input(false)])
            .unwrap()
            .catalog;
        let authenticated = pack_incremental(profile(), None, vec![input(true)]).unwrap();
        assert_eq!(legacy.format_version, 1);
        assert_eq!(authenticated.catalog.format_version, 3);
        let mut version_two = authenticated.catalog.clone();
        version_two.format_version = 2;
        for (sector, packed) in version_two.sectors.iter_mut().zip(&authenticated.sectors) {
            sector.flat_root = crate::sector_root(&packed.bytes);
            sector.id = sector.calculate_id(profile()).unwrap();
        }
        version_two.id = version_two.calculate_id().unwrap();
        let binding = SignedRecord::sign(
            LEGACY_PACKING_BINDING_DOMAIN,
            LegacyPackingBinding {
                format_version: 1,
                owner: keys.node_id(),
                protected_root: [3; 32],
                object_id: [4; 32],
                flat_root: crate::sector_root(&bytes),
                source_commitment: merkle_commit(&bytes).unwrap(),
            },
            &keys,
        )
        .unwrap();
        let version_four =
            attach_legacy_packing_bindings(authenticated.catalog.clone(), vec![binding]).unwrap();
        let attestation = SignedRecord::sign(
            LEGACY_PACKING_ATTESTATION_DOMAIN,
            LegacyPackingAttestation {
                format_version: 1,
                guild_id: [9; 32],
                membership_epoch: 2,
                owner: keys.node_id(),
                protected_root: [3; 32],
                object_id: [4; 32],
                flat_root: crate::sector_root(&bytes),
                source_commitment: merkle_commit(&bytes).unwrap(),
            },
            &keys,
        )
        .unwrap();
        let version_five = attach_legacy_packing_evidence(
            authenticated.catalog.clone(),
            Vec::new(),
            vec![attestation],
        )
        .unwrap();
        for catalog in [
            legacy,
            version_two,
            authenticated.catalog,
            version_four,
            version_five,
        ] {
            assert_eq!(catalog.id, reference_catalog_id(&catalog));
            for sector in &catalog.sectors {
                let mut hash = blake3::Hasher::new_derive_key("mutualbackup packed sector v1");
                hash.update(
                    &canonical_bytes(&(
                        catalog.profile,
                        sector.sector_index,
                        sector.flat_root,
                        &sector.commitment,
                        &sector.slots,
                    ))
                    .unwrap(),
                );
                assert_eq!(sector.id, *hash.finalize().as_bytes());
            }
            let original = canonical_bytes(&catalog).unwrap();
            let mut pages = Pages::new();
            let root = CatalogPackedSectorRoot::from_legacy(
                scope(),
                &catalog,
                &mut |page: CatalogPageRef, bytes| {
                    pages.insert(page.hash, bytes);
                    Ok::<_, ()>(())
                },
            )
            .unwrap();
            assert_eq!(root.packing_version, catalog.format_version);
            assert_eq!(
                read(root, &pages),
                catalog.sectors.iter().flat_map(records).collect::<Vec<_>>()
            );
            assert_eq!(canonical_bytes(&catalog).unwrap(), original);
            let mut corrupt = catalog.clone();
            corrupt.id[0] ^= 1;
            let mut writes = 0;
            assert!(
                CatalogPackedSectorRoot::from_legacy(scope(), &corrupt, &mut |_, _| {
                    writes += 1;
                    Ok::<_, ()>(())
                })
                .is_err()
            );
            assert_eq!(writes, 0);
            if catalog.format_version == 5 {
                assert!(
                    CatalogPackedSectorRoot::from_legacy(
                        CatalogScope::Guild { guild_id: [8; 32] },
                        &catalog,
                        &mut |_, _| {
                            writes += 1;
                            Ok::<_, ()>(())
                        }
                    )
                    .is_err()
                );
                assert_eq!(writes, 0);
            }
        }
    }

    #[test]
    fn packed_sector_stream_rejects_semantic_substitution_before_final_record() {
        let sector = descriptor(0, profile());
        let good = records(&sector);
        let (root, _) = build(std::slice::from_ref(&sector), profile());
        let mut cases = Vec::new();
        for field in 0..5 {
            let mut bad = good.clone();
            let CatalogPackedSectorRecord::Header {
                id,
                sector_index,
                flat_root,
                commitment,
                format_version,
            } = &mut bad[0]
            else {
                unreachable!()
            };
            match field {
                0 => id[0] ^= 1,
                1 => *sector_index = 1,
                2 => flat_root[0] ^= 1,
                3 => *commitment = merkle_zero_commitment(128).unwrap(),
                4 => *format_version = 2,
                _ => unreachable!(),
            }
            cases.push(bad);
        }
        for field in 0..6 {
            let mut bad = good.clone();
            let CatalogPackedSectorRecord::Slots { offset, slots } = &mut bad[1] else {
                unreachable!()
            };
            let PackedSlot::Data(source) = &mut slots[0] else {
                unreachable!()
            };
            match field {
                0 => *offset = 1,
                1 => source.content_hash[0] ^= 1,
                2 => source.source_offset = 1,
                3 => source.logical_len = 0,
                4 => source.id.owner = NodeId([0; 32]),
                5 => source.logical_len -= 1,
                _ => unreachable!(),
            }
            cases.push(bad);
        }
        cases.push(vec![good[1].clone(), good[0].clone()]);
        cases.push(vec![good[0].clone()]);
        for case in cases {
            let (root, pages) = raw_records(root, &case);
            assert_rejected(root, &pages);
        }
        let (_, pages) = build(std::slice::from_ref(&sector), profile());
        for field in 0..4 {
            let mut substituted = root;
            match field {
                0 => substituted.source_bytes += 16,
                1 => {
                    substituted.source_bytes -= 16;
                    substituted.source_chunks -= 1;
                }
                2 => substituted.packing_version = 8,
                3 => substituted.slots += 1,
                _ => unreachable!(),
            }
            assert_rejected(substituted, &pages);
        }
    }

    #[test]
    fn packed_sector_stream_rejects_incomplete_fragments_and_preserves_legacy_tail_geometry() {
        let mut sector = descriptor(0, profile());
        let PackedSlot::Data(source) = &mut sector.slots[3] else {
            unreachable!()
        };
        source.logical_len = 7;
        sector.flat_root = [6; 32];
        sector.id = sector.calculate_id(profile()).unwrap();
        let mut pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder = CatalogPackedSectorBuilder::new(scope(), 1, profile()).unwrap();
        builder.push_sector(&sector, &mut sink).unwrap();
        let root = builder.finish(&mut sink).unwrap();
        assert_eq!(root.source_bytes, 3 * 16 + 7);
        assert_eq!(read(root, &pages), records(&sector));
        let mut builder = CatalogPackedSectorBuilder::new(scope(), 2, profile()).unwrap();
        assert!(
            builder
                .push_sector(&sector, &mut |_, _| Ok::<_, ()>(()))
                .is_err()
        );
        assert!(builder.finish(&mut |_, _| Ok::<_, ()>(())).is_err());
        for count in [0, 3, 5] {
            let mut malformed = descriptor(0, profile());
            malformed
                .slots
                .resize(count, PackedSlot::VirtualZero { source: None });
            let mut builder = CatalogPackedSectorBuilder::new(scope(), 3, profile()).unwrap();
            assert!(
                builder
                    .push_sector(&malformed, &mut |_, _| Ok::<_, ()>(()))
                    .is_err()
            );
            assert!(matches!(
                builder.push(&records(&descriptor(0, profile()))[0], &mut |_, _| Ok::<
                    _,
                    (),
                >(
                    ()
                )),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
    }

    #[test]
    fn packed_sector_record_decoder_bounds_nested_declarations_and_canonical_encoding() {
        let records = records(&descriptor(0, profile()));
        for record in &records {
            let bytes = canonical_bytes(record).unwrap();
            assert_eq!(CatalogPackedSectorRecord::decode(&bytes).unwrap(), *record);
            for end in 0..bytes.len() {
                assert!(CatalogPackedSectorRecord::decode(&bytes[..end]).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(CatalogPackedSectorRecord::decode(&trailing).is_err());
        }
        let mut oversized = vec![1, 0]; // Slots discriminant, offset zero.
        oversized.extend(canonical_bytes(&(CATALOG_PACKED_SLOTS + 1)).unwrap());
        oversized.resize(oversized.len() + CATALOG_PACKED_SLOTS + 1, 0);
        assert!(matches!(
            CatalogPackedSectorRecord::decode(&oversized),
            Err(CatalogError::Model(crate::ModelError::Decode(
                postcard::Error::SerdeDeCustom
            )))
        ));
        let mut truncated_huge = vec![1, 0];
        truncated_huge.extend(canonical_bytes(&u64::MAX).unwrap());
        assert!(CatalogPackedSectorRecord::decode(&truncated_huge).is_err());
        let mut overlong = vec![0x80, 0]; // Noncanonical Header discriminant.
        overlong.extend_from_slice(&canonical_bytes(&records[0]).unwrap()[1..]);
        assert!(CatalogPackedSectorRecord::decode(&overlong).is_err());
        assert!(
            CatalogPackedSectorRecord::decode(&vec![0; CATALOG_PACKED_RECORD_BYTES + 1]).is_err()
        );
        let (root, _) = build(&[descriptor(0, profile())], profile());
        let bytes = canonical_bytes(&root).unwrap();
        assert_eq!(CatalogPackedSectorRoot::decode(&bytes).unwrap(), root);
        for end in 0..bytes.len() {
            assert!(CatalogPackedSectorRoot::decode(&bytes[..end]).is_err());
        }
        assert!(CatalogPackedSectorRoot::decode(&vec![0; CATALOG_PACKED_ROOT_BYTES + 1]).is_err());
        let mut noncanonical = vec![0x81, 0];
        noncanonical.extend_from_slice(&bytes[1..]);
        assert!(CatalogPackedSectorRoot::decode(&noncanonical).is_err());
    }

    #[test]
    fn packed_sector_stream_fences_storage_fetch_and_identity_failures() {
        let profile = PackingProfile {
            sector_size: crate::V1_SECTOR_SIZE as u32,
            slot_size: 16,
            ..profile()
        };
        let sector = descriptor(0, profile);
        let mut writes = 0;
        let mut builder = CatalogPackedSectorBuilder::new(scope(), 3, profile).unwrap();
        let result = builder.push_sector(&sector, &mut |_, _| {
            writes += 1;
            if writes == 2 {
                Err("injected storage failure")
            } else {
                Ok(())
            }
        });
        assert!(matches!(
            result,
            Err(CatalogStreamError::Storage("injected storage failure"))
        ));
        assert!(writes >= 2);
        assert!(matches!(
            builder.finish(&mut |_, _| Ok::<_, &str>(())),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        let (root, pages) = build(std::slice::from_ref(&sector), profile);
        let mut reader = CatalogPackedSectorReader::new(scope(), root).unwrap();
        assert!(matches!(
            reader.next_record(&mut |_| Err::<Vec<u8>, _>("injected fetch failure")),
            Err(CatalogStreamError::Storage("injected fetch failure"))
        ));
        assert!(matches!(
            reader
                .next_record(&mut |page: CatalogPageRef| Ok::<_, &str>(pages[&page.hash].clone())),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        let mut corrupt = pages.clone();
        corrupt.get_mut(&root.records.page.hash).unwrap()[0] ^= 1;
        assert_rejected(root, &corrupt);
    }

    #[test]
    fn packed_sector_stream_empty_and_hole_sectors_keep_exact_final_sector_rule() {
        let (root, pages) = build(&[], profile());
        assert_eq!(root.sectors, 0);
        assert!(read(root, &pages).is_empty());
        let mut empty = descriptor(0, profile());
        empty.slots.fill(PackedSlot::VirtualZero { source: None });
        empty.id = empty.calculate_id(profile()).unwrap();
        let mut builder = CatalogPackedSectorBuilder::new(scope(), 3, profile()).unwrap();
        builder
            .push_sector(&empty, &mut |_, _| Ok::<_, ()>(()))
            .unwrap();
        assert!(builder.finish(&mut |_, _| Ok::<_, ()>(())).is_err());
        let (root, pages) = build(&[empty, descriptor(1, profile())], profile());
        assert_eq!(root.source_chunks, 4);
        assert_eq!(read(root, &pages).len(), 4);
        let invalid_scope = CatalogScope::Dataset {
            guild_id: [9; 32],
            owner: NodeId([2; 32]),
            protected_root_id: uuid::Uuid::from_bytes([3; 16]),
        };
        assert!(CatalogPackedSectorBuilder::new(invalid_scope, 3, profile()).is_err());
        let mut invalid = root;
        invalid.source_chunks = u64::MAX;
        invalid.source_bytes = u64::MAX;
        assert!(invalid.validate().is_err());
    }
}
