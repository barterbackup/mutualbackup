//! Ordered bounded records, automatically sharded only between whole sources
//! or sectors. Global sector indices and original descriptor hashes survive.

use super::*;
use capacity::{FRAGMENT_BYTES, HEADER_BYTES, SLOT_BYTES};

pub struct CatalogPackingDirectoryStreamBuilder {
    scope: CatalogScope,
    profile: PackingProfile,
    version: u16,
    capacity: CatalogPackingDirectoryCapacity,
    directory: CatalogPackingDirectoryBuilder,
    source: Option<CatalogPackedSourceBuilder>,
    sector: Option<CatalogPackedSectorBuilder>,
    sources: u64,
    sectors: u64,
    part_sources: u64,
    part_sectors: u64,
    previous_source: Option<CatalogPackedSourceId>,
    last_sector_has_source: bool,
    descriptors: bool,
    failed: bool,
}

impl CatalogPackingDirectoryStreamBuilder {
    /// Reserve full compact source and descriptor construction before staging.
    /// The supplied credits must be the remaining independently trusted policy
    /// after every other section. Original proof openings are checked before
    /// compaction; source authority and exact placement joins remain required.
    pub fn new(
        scope: CatalogScope,
        version: u16,
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        Self::with_part_bytes(
            scope,
            version,
            profile,
            sources,
            sectors,
            budget,
            CATALOG_MAX_STREAM_BYTES,
        )
    }

    pub fn with_part_bytes(
        scope: CatalogScope,
        version: u16,
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
        budget: CatalogCodingTraversalBudget,
        part_limit: u64,
    ) -> Result<Self, CatalogError> {
        let capacity = CatalogPackingDirectoryCapacity::with_part_bytes(
            profile, sources, sectors, part_limit,
        )?;
        budget.check(capacity.work)?;
        Ok(Self {
            scope,
            profile,
            version,
            capacity,
            directory: CatalogPackingDirectoryBuilder::new(scope, version, profile, capacity.work)?,
            source: None,
            sector: None,
            sources: 0,
            sectors: 0,
            part_sources: 0,
            part_sectors: 0,
            previous_source: None,
            last_sector_has_source: false,
            descriptors: false,
            failed: false,
        })
    }

    fn finish_sources<E>(
        &mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if let Some(source) = self.source.take() {
            self.directory.push(
                CatalogPackingDirectoryRecord::Sources(source.finish_part(sink)?),
                sink,
            )?;
            self.part_sources = 0;
        }
        Ok(())
    }

    fn finish_sectors<E>(
        &mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if let Some(sector) = self.sector.take() {
            self.directory.push(
                CatalogPackingDirectoryRecord::Sectors(sector.finish_part(sink)?),
                sink,
            )?;
            self.part_sectors = 0;
        }
        Ok(())
    }

    pub fn push_source<E>(
        &mut self,
        record: &CatalogPackedSourceRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.push_source_inner(record, sink);
        self.failed = result.is_err();
        result
    }

    fn push_source_inner<E>(
        &mut self,
        record: &CatalogPackedSourceRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.descriptors {
            return Err(CatalogError::InvalidPage.into());
        }
        if let CatalogPackedSourceRecord::Source { id, .. } = record {
            if self.sources >= self.capacity.sources {
                return Err(CatalogError::Bounds.into());
            }
            if self.previous_source.is_some_and(|last| last >= *id) {
                return Err(CatalogError::InvalidPage.into());
            }
            canonical_size_bounded(record, HEADER_BYTES as usize).map_err(CatalogError::from)?;
            if self.part_sources == self.capacity.sources_per_part {
                self.finish_sources(sink)?;
            }
            if self.source.is_none() {
                self.source = Some(CatalogPackedSourceBuilder::new_compact(
                    self.scope,
                    self.profile,
                )?);
            }
            self.source
                .as_mut()
                .ok_or(CatalogError::InvalidPage)?
                .push(record, sink)?;
            self.sources += 1;
            self.part_sources += 1;
            self.previous_source = Some(*id);
        } else {
            // Only compact output is charged. The inner builder validates full
            // proof geometry/openings before emitting these original subtrees.
            let (first_chunk, roots) = match record {
                CatalogPackedSourceRecord::Subtrees { first_chunk, roots }
                    if !roots.is_empty() && roots.len() <= CATALOG_PACKED_SOURCE_PROOFS =>
                {
                    (*first_chunk, roots.clone())
                }
                CatalogPackedSourceRecord::Proofs {
                    first_chunk,
                    proofs,
                } if !proofs.is_empty() && proofs.len() <= CATALOG_PACKED_SOURCE_PROOFS => (
                    *first_chunk,
                    proofs.iter().map(|proof| proof.subtree_root).collect(),
                ),
                _ => return Err(CatalogError::Bounds.into()),
            };
            let limit = FRAGMENT_BYTES + 32 * roots.len() as u64;
            canonical_size_bounded(
                &CatalogPackedSourceRecord::Subtrees { first_chunk, roots },
                limit as usize,
            )
            .map_err(CatalogError::from)?;
            self.source
                .as_mut()
                .ok_or(CatalogError::InvalidPage)?
                .push(record, sink)?;
        }
        Ok(())
    }

    /// Consume bounded full slots; their compact representation is emitted
    /// only after checking the unchanged original sector identity.
    pub fn push_sector<E>(
        &mut self,
        record: &CatalogPackedSectorRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.push_sector_inner(record, sink);
        self.failed = result.is_err();
        result
    }

    fn push_sector_inner<E>(
        &mut self,
        record: &CatalogPackedSectorRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        match record {
            CatalogPackedSectorRecord::Header { sector_index, .. } => {
                if self.sectors >= self.capacity.sectors {
                    return Err(CatalogError::Bounds.into());
                }
                if u64::from(*sector_index) != self.sectors {
                    return Err(CatalogError::InvalidPage.into());
                }
                canonical_size_bounded(record, HEADER_BYTES as usize)
                    .map_err(CatalogError::from)?;
                self.finish_sources(sink)?;
                self.descriptors = true;
                if self.part_sectors == self.capacity.sectors_per_part {
                    self.finish_sectors(sink)?;
                }
                if self.sector.is_none() {
                    self.sector = Some(CatalogPackedSectorBuilder::new_part(
                        self.scope,
                        self.version,
                        self.profile,
                        *sector_index,
                    )?);
                }
                self.sector
                    .as_mut()
                    .ok_or(CatalogError::InvalidPage)?
                    .push(record, sink)?;
                self.sectors += 1;
                self.part_sectors += 1;
                self.last_sector_has_source = false;
            }
            CatalogPackedSectorRecord::Slots { offset, slots } => {
                if slots.is_empty() || slots.len() > CATALOG_PACKED_SLOTS {
                    return Err(CatalogError::Bounds.into());
                }
                let compact = CatalogPackedSectorRecord::CompactSlots {
                    offset: *offset,
                    slots: slots
                        .iter()
                        .map(CatalogPackedSlotReference::from_slot)
                        .collect(),
                };
                canonical_size_bounded(
                    &compact,
                    (FRAGMENT_BYTES + SLOT_BYTES * slots.len() as u64) as usize,
                )
                .map_err(CatalogError::from)?;
                self.sector
                    .as_mut()
                    .ok_or(CatalogError::InvalidPage)?
                    .push(record, sink)?;
                self.last_sector_has_source |= slots.iter().any(|slot| slot.source().is_some());
            }
            CatalogPackedSectorRecord::CompactSlots { .. } => {
                return Err(CatalogError::InvalidPage.into());
            }
        }
        Ok(())
    }

    pub fn finish<E>(
        mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPackingDirectoryRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if self.sectors != 0 && !self.last_sector_has_source {
            return Err(CatalogError::InvalidPage.into());
        }
        self.finish_sources(sink)?;
        self.finish_sectors(sink)?;
        self.directory.finish(sink)
    }
}
