//! One construction reservation for complete packing streams and full original
//! coding witnesses. This stages roots; enclosing authority, ownership and
//! database/payload/physical admission still precede protection publication.

use super::*;
use crate::PackingProfile;

/// Derived local credits, with no wire decoder or source authority. Counts
/// include all live/candidate/retired occurrences that will be emitted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogPackingCodingCapacity {
    pub packing: CatalogPackingDirectoryCapacity,
    pub coding: CatalogCodingDirectoryCapacity,
    pub work: CatalogCodingTraversalBudget,
    pub encoded_page_bytes: u64,
    profile: PackingProfile,
    packing_part_bytes: u64,
}

impl CatalogPackingCodingCapacity {
    pub fn for_counts(
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
        groups: u64,
    ) -> Result<Self, CatalogError> {
        Self::with_packing_part_bytes(profile, sources, sectors, groups, CATALOG_MAX_STREAM_BYTES)
    }

    pub fn with_packing_part_bytes(
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
        groups: u64,
        packing_part_bytes: u64,
    ) -> Result<Self, CatalogError> {
        let packing = CatalogPackingDirectoryCapacity::with_part_bytes(
            profile,
            sources,
            sectors,
            packing_part_bytes,
        )?;
        let coding = CatalogCodingDirectoryCapacity::for_groups(groups)?;
        Ok(Self {
            packing,
            coding,
            work: packing.work.checked_add(coding.work)?,
            encoded_page_bytes: packing
                .encoded_page_bytes
                .checked_add(coding.encoded_page_bytes)
                .ok_or(CatalogError::Bounds)?,
            profile,
            packing_part_bytes,
        })
    }

    fn validate(self) -> Result<(), CatalogError> {
        if self
            != Self::with_packing_part_bytes(
                self.profile,
                self.packing.sources,
                self.packing.sectors,
                self.coding.groups,
                self.packing_part_bytes,
            )?
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

/// Both staged directory roots. Exact complete-source, placement, coding and
/// signed-history joins remain mandatory; a builder does not grant authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogPackingCodingRoots {
    pub packing: CatalogPackingDirectoryRoot,
    pub coding: CatalogCodingDirectoryRoot,
}

impl CatalogPackingCodingRoots {
    pub fn work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        self.packing.work()?.checked_add(self.coding.work()?)
    }
}

/// Streams sources, then sectors, then ordered original coding witnesses.
/// Each section owns separate credits inside the combined reservation, so a
/// smaller encoding in one section cannot fund excess occurrences in another.
pub struct CatalogPackingCodingBuilder {
    packing: Option<CatalogPackingDirectoryStreamBuilder>,
    packing_root: Option<CatalogPackingDirectoryRoot>,
    coding: CatalogCodingDirectoryBuilder,
    capacity: CatalogPackingCodingCapacity,
    groups: u64,
    failed: bool,
}

impl CatalogPackingCodingBuilder {
    /// Reserve the complete declared retained data/private/bootstrap geometry
    /// before the first sink call. Original witness and count fences still apply.
    pub fn with_capacity_policy(
        scope: CatalogScope,
        packing_version: u16,
        event_sequence: u64,
        policy: CatalogCapacityPolicy,
        remaining_budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        Self::new(
            scope,
            packing_version,
            event_sequence,
            policy.plan()?.packing_coding,
            remaining_budget,
        )
    }

    pub fn new(
        scope: CatalogScope,
        packing_version: u16,
        event_sequence: u64,
        capacity: CatalogPackingCodingCapacity,
        remaining_budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        capacity.validate()?;
        remaining_budget.check(capacity.work)?;
        Ok(Self {
            packing: Some(CatalogPackingDirectoryStreamBuilder::with_part_bytes(
                scope,
                packing_version,
                capacity.profile,
                capacity.packing.sources,
                capacity.packing.sectors,
                capacity.packing.work,
                capacity.packing_part_bytes,
            )?),
            packing_root: None,
            coding: CatalogCodingDirectoryBuilder::for_group_capacity(
                scope,
                event_sequence,
                capacity.coding.groups,
                capacity.coding.work,
            )?,
            capacity,
            groups: 0,
            failed: false,
        })
    }

    pub fn push_source<E>(
        &mut self,
        record: &CatalogPackedSourceRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = match self.packing.as_mut() {
            Some(packing) => packing.push_source(record, sink),
            None => Err(CatalogError::InvalidPage.into()),
        };
        self.failed = result.is_err();
        result
    }

    pub fn push_sector<E>(
        &mut self,
        record: &CatalogPackedSectorRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = match self.packing.as_mut() {
            Some(packing) => packing.push_sector(record, sink),
            None => Err(CatalogError::InvalidPage.into()),
        };
        self.failed = result.is_err();
        result
    }

    pub fn push_group<E>(
        &mut self,
        entry: &CatalogCodingEntry,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            if self.groups >= self.capacity.coding.groups {
                return Err(CatalogError::Bounds.into());
            }
            if let Some(packing) = self.packing.take() {
                self.packing_root = Some(packing.finish(sink)?);
            }
            self.coding.push_group(entry, sink)?;
            self.groups += 1;
            Ok(())
        })();
        self.failed = result.is_err();
        result
    }

    pub fn finish<E>(
        mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPackingCodingRoots, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if let Some(packing) = self.packing.take() {
            self.packing_root = Some(packing.finish(sink)?);
        }
        let roots = CatalogPackingCodingRoots {
            packing: self.packing_root.ok_or(CatalogError::InvalidPage)?,
            coding: self.coding.finish(sink)?,
        };
        self.capacity.work.check(roots.work()?)?;
        Ok(roots)
    }
}

#[cfg(test)]
mod tests;
