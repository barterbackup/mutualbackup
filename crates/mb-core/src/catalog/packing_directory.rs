//! Bounded directories of original packing streams. Global descriptor indices,
//! ordered source ranges and cumulative work survive every part boundary.
//! Complete source/descriptor/authority joins remain required for admission.

use serde::{Deserialize, Serialize};

use super::*;
use crate::{PackingProfile, canonical_bytes_bounded, canonical_size_bounded};

pub const CATALOG_PACKING_DIRECTORY_ROOT_BYTES: usize = 512;
pub const CATALOG_PACKING_DIRECTORY_RECORD_BYTES: usize = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackedSectorPart {
    pub format_version: u16,
    pub first_sector: u32,
    pub root: CatalogPackedSectorRoot,
}

impl CatalogPackedSectorPart {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.root.validate_part()?;
        if self.format_version != 1
            || self.root.sectors == 0
            || u64::from(self.first_sector) + self.root.sectors > u64::from(u32::MAX) + 1
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackedSourcePart {
    pub format_version: u16,
    pub first: CatalogPackedSourceId,
    pub last: CatalogPackedSourceId,
    pub root: CatalogPackedSourceRoot,
}

impl CatalogPackedSourcePart {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.root.validate()?;
        self.first.validate()?;
        self.last.validate()?;
        if self.format_version != 1
            || self.root.sources == 0
            || self.first > self.last
            || (self.root.sources == 1) != (self.first == self.last)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

/// Complete ordered source parts precede contiguous global descriptor parts.
/// The first/last source bounds are verified against actual headers at EOF.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackingDirectoryRecord {
    Sources(CatalogPackedSourcePart),
    Sectors(CatalogPackedSectorPart),
}

impl CatalogPackingDirectoryRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_PACKING_DIRECTORY_RECORD_BYTES {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        record.validate()?;
        if canonical_bytes_bounded(&record, CATALOG_PACKING_DIRECTORY_RECORD_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }

    fn validate(self) -> Result<(), CatalogError> {
        match self {
            Self::Sources(part) => part.validate(),
            Self::Sectors(part) => part.validate(),
        }
    }

    fn records(self) -> CatalogRecordRoot {
        match self {
            Self::Sources(part) => part.root.records,
            Self::Sectors(part) => part.root.records,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingDirectorySummary {
    pub source_parts: u64,
    pub sector_parts: u64,
    pub sources: u64,
    pub source_chunks: u64,
    pub source_bytes: u64,
    pub sectors: u64,
    pub slots: u64,
    pub packed_chunks: u64,
    pub packed_bytes: u64,
    pub evidence_bytes: u64,
    pub evidence_pages: u64,
    pub evidence_records: u64,
}

impl CatalogPackingDirectorySummary {
    fn values(self) -> [u64; 12] {
        [
            self.source_parts,
            self.sector_parts,
            self.sources,
            self.source_chunks,
            self.source_bytes,
            self.sectors,
            self.slots,
            self.packed_chunks,
            self.packed_bytes,
            self.evidence_bytes,
            self.evidence_pages,
            self.evidence_records,
        ]
    }

    fn validate(self, profile: PackingProfile) -> Result<(), CatalogError> {
        let width = u64::from(
            profile
                .slots_per_sector()
                .map_err(|_| CatalogError::InvalidPage)?,
        );
        let parts = self
            .source_parts
            .checked_add(self.sector_parts)
            .ok_or(CatalogError::Bounds)?;
        let records = self
            .sources
            .checked_mul(1 + width.div_ceil(CATALOG_PACKED_SOURCE_PROOFS as u64))
            .and_then(|count| {
                self.sectors
                    .checked_mul(1 + width.div_ceil(CATALOG_PACKED_SLOTS as u64))
                    .and_then(|sectors| count.checked_add(sectors))
            })
            .ok_or(CatalogError::Bounds)?;
        if parts > CATALOG_MAX_RECORDS
            || self.sectors > u64::from(u32::MAX) + 1
            || self.sources < self.source_parts
            || self.sectors < self.sector_parts
            || (self.sources == 0) != (self.source_parts == 0)
            || (self.sectors == 0) != (self.sector_parts == 0)
            || (self.sources == 0) != (self.sectors == 0)
            || self.sources.checked_mul(width) != Some(self.source_chunks)
            || self.sources.checked_mul(u64::from(profile.sector_size)) != Some(self.source_bytes)
            || self.sectors.checked_mul(width) != Some(self.slots)
            || self.source_chunks != self.packed_chunks
            || self.source_bytes != self.packed_bytes
            || self.packed_chunks > self.slots
            || self.evidence_records != records
            || self.evidence_bytes < records * 5 + parts * 8
            || self.evidence_bytes > parts * CATALOG_MAX_STREAM_BYTES
            || self.evidence_pages < parts
            || self.evidence_pages > parts * CATALOG_MAX_PAGE_OCCURRENCES
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingDirectoryRoot {
    pub format_version: u16,
    pub packing_version: u16,
    pub profile: PackingProfile,
    pub records: CatalogRecordRoot,
    pub summary: CatalogPackingDirectorySummary,
}

impl CatalogPackingDirectoryRoot {
    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_PACKING_DIRECTORY_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate(budget)?;
        if canonical_bytes_bounded(&root, CATALOG_PACKING_DIRECTORY_ROOT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }

    pub fn validate(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogError> {
        self.records.validate()?;
        self.summary.validate(self.profile)?;
        if self.format_version != 1
            || !matches!(self.packing_version, 2..=5)
            || self.summary.source_parts + self.summary.sector_parts != self.records.records
        {
            return Err(CatalogError::Bounds);
        }
        budget.remaining_after(self.work()?)?;
        Ok(())
    }

    /// Referenced parts count once per occurrence. Their envelopes already
    /// appear in directory frames; the fixed root envelope is charged once.
    pub fn work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        Ok(CatalogCodingTraversalBudget {
            bytes: self
                .summary
                .evidence_bytes
                .checked_add(self.records.page.byte_len)
                .and_then(|bytes| bytes.checked_add(CATALOG_PACKING_DIRECTORY_ROOT_BYTES as u64))
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self
                .summary
                .evidence_pages
                .checked_add(self.records.page.page_occurrences)
                .ok_or(CatalogError::Bounds)?,
            records: self
                .summary
                .evidence_records
                .checked_add(self.records.records)
                .ok_or(CatalogError::Bounds)?,
        })
    }
}

#[derive(Default)]
struct DirectoryState {
    summary: CatalogPackingDirectorySummary,
    previous_source: Option<CatalogPackedSourceId>,
    descriptors: bool,
}

fn add(value: &mut u64, increment: u64) -> Result<(), CatalogError> {
    *value = value.checked_add(increment).ok_or(CatalogError::Bounds)?;
    Ok(())
}

impl DirectoryState {
    fn accept(
        &mut self,
        record: CatalogPackingDirectoryRecord,
        profile: PackingProfile,
        version: u16,
    ) -> Result<(), CatalogError> {
        record.validate()?;
        match record {
            CatalogPackingDirectoryRecord::Sources(part) => {
                if self.descriptors
                    || part.root.profile != profile
                    || self.previous_source.is_some_and(|last| last >= part.first)
                {
                    return Err(CatalogError::InvalidPage);
                }
                self.previous_source = Some(part.last);
                add(&mut self.summary.source_parts, 1)?;
                add(&mut self.summary.sources, part.root.sources)?;
                add(&mut self.summary.source_chunks, part.root.chunks)?;
                add(&mut self.summary.source_bytes, part.root.ciphertext_bytes)?;
            }
            CatalogPackingDirectoryRecord::Sectors(part) => {
                if part.root.profile != profile
                    || part.root.packing_version != version
                    || u64::from(part.first_sector) != self.summary.sectors
                {
                    return Err(CatalogError::InvalidPage);
                }
                self.descriptors = true;
                add(&mut self.summary.sector_parts, 1)?;
                add(&mut self.summary.sectors, part.root.sectors)?;
                add(&mut self.summary.slots, part.root.slots)?;
                add(&mut self.summary.packed_chunks, part.root.source_chunks)?;
                add(&mut self.summary.packed_bytes, part.root.source_bytes)?;
            }
        }
        let records = record.records();
        add(&mut self.summary.evidence_bytes, records.page.byte_len)?;
        add(
            &mut self.summary.evidence_pages,
            records.page.page_occurrences,
        )?;
        add(&mut self.summary.evidence_records, records.records)?;
        Ok(())
    }
}

fn dense_pages(bytes: u64) -> u64 {
    let mut nodes = bytes.div_ceil(CATALOG_LEAF_BYTES as u64).max(1);
    let mut pages = nodes;
    while nodes > 1 {
        nodes = nodes.div_ceil(CATALOG_FANOUT as u64);
        pages += nodes;
    }
    pages
}

pub struct CatalogPackingDirectoryBuilder {
    records: CatalogRecordBuilder,
    profile: PackingProfile,
    version: u16,
    budget: CatalogCodingTraversalBudget,
    state: DirectoryState,
    directory_bytes: u64,
    failed: bool,
}

impl CatalogPackingDirectoryBuilder {
    pub fn new(
        scope: CatalogScope,
        version: u16,
        profile: PackingProfile,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        profile.validate().map_err(|_| CatalogError::InvalidPage)?;
        if !matches!(version, 2..=5) {
            return Err(CatalogError::InvalidPage);
        }
        budget.remaining_after(CatalogCodingTraversalBudget {
            bytes: 8 + CATALOG_PACKING_DIRECTORY_ROOT_BYTES as u64,
            page_occurrences: 1,
            records: 0,
        })?;
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::Packing)?,
            profile,
            version,
            budget,
            state: DirectoryState::default(),
            directory_bytes: 8,
            failed: false,
        })
    }

    pub fn push<E>(
        &mut self,
        record: CatalogPackingDirectoryRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            self.state.accept(record, self.profile, self.version)?;
            let framed = canonical_size_bounded(&record, CATALOG_PACKING_DIRECTORY_RECORD_BYTES)
                .map_err(CatalogError::from)? as u64
                + 4;
            self.directory_bytes = self
                .directory_bytes
                .checked_add(framed)
                .ok_or(CatalogError::Bounds)?;
            let summary = self.state.summary;
            self.budget.remaining_after(CatalogCodingTraversalBudget {
                bytes: summary
                    .evidence_bytes
                    .checked_add(self.directory_bytes)
                    .and_then(|bytes| {
                        bytes.checked_add(CATALOG_PACKING_DIRECTORY_ROOT_BYTES as u64)
                    })
                    .ok_or(CatalogError::Bounds)?,
                page_occurrences: summary
                    .evidence_pages
                    .checked_add(dense_pages(self.directory_bytes))
                    .ok_or(CatalogError::Bounds)?,
                records: summary
                    .evidence_records
                    .checked_add(summary.source_parts)
                    .and_then(|records| records.checked_add(summary.sector_parts))
                    .ok_or(CatalogError::Bounds)?,
            })?;
            self.records.push(&record, sink)
        })();
        self.failed = result.is_err();
        result
    }

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPackingDirectoryRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.state.summary.validate(self.profile)?;
        let root = CatalogPackingDirectoryRoot {
            format_version: 1,
            packing_version: self.version,
            profile: self.profile,
            records: self.records.finish(sink)?,
            summary: self.state.summary,
        };
        root.validate(self.budget)?;
        Ok(root)
    }
}

struct ActiveSourcePart {
    part: CatalogPackedSourcePart,
    reader: CatalogPackedSourceReader,
    last: Option<CatalogPackedSourceId>,
}

/// Streaming complete EOF of the directory and all parts, with one active
/// nested reader. No directory-sized collection or budget reset is allowed.
pub struct CatalogPackingDirectoryReader {
    scope: CatalogScope,
    root: CatalogPackingDirectoryRoot,
    directory: CatalogRecordReader,
    state: DirectoryState,
    source: Option<ActiveSourcePart>,
    sector: Option<CatalogPackedSectorReader>,
    pending: Option<CatalogPackedSectorPart>,
    sources_done: bool,
    complete: bool,
    failed: bool,
    last_sector_has_source: bool,
}

impl CatalogPackingDirectoryReader {
    pub fn new(
        scope: CatalogScope,
        root: CatalogPackingDirectoryRoot,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogError> {
        root.validate(budget)?;
        Ok(Self {
            scope,
            root,
            directory: CatalogRecordReader::new(scope, CatalogSection::Packing, root.records)?,
            state: DirectoryState::default(),
            source: None,
            sector: None,
            pending: None,
            sources_done: false,
            complete: false,
            failed: false,
            last_sector_has_source: false,
        })
    }

    fn next_part<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        visit: &mut impl FnMut(CatalogPackingDirectoryRecord) -> Result<(), E>,
    ) -> Result<Option<CatalogPackingDirectoryRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.directory.next_record(fetch)? else {
            if self.state.summary != self.root.summary {
                return Err(CatalogError::InvalidPage.into());
            }
            self.complete = true;
            return Ok(None);
        };
        let record = CatalogPackingDirectoryRecord::decode(&bytes)?;
        self.state
            .accept(record, self.root.profile, self.root.packing_version)?;
        if self
            .state
            .summary
            .values()
            .into_iter()
            .zip(self.root.summary.values())
            .any(|(actual, expected)| actual > expected)
        {
            return Err(CatalogError::InvalidPage.into());
        }
        visit(record).map_err(CatalogStreamError::Storage)?;
        Ok(Some(record))
    }

    pub fn next_source<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogPackedSourceRecord>, CatalogStreamError<E>> {
        self.next_source_with_part(fetch, &mut |_| Ok(()))
    }

    /// Visit each admitted part before reading its referenced pages. Durable
    /// ownership walkers pin that exact root here; failures fence the reader.
    pub fn next_source_with_part<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        visit: &mut impl FnMut(CatalogPackingDirectoryRecord) -> Result<(), E>,
    ) -> Result<Option<CatalogPackedSourceRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.source_inner(fetch, visit);
        self.failed = result.is_err();
        result
    }

    fn source_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        visit: &mut impl FnMut(CatalogPackingDirectoryRecord) -> Result<(), E>,
    ) -> Result<Option<CatalogPackedSourceRecord>, CatalogStreamError<E>> {
        if self.sources_done {
            return Ok(None);
        }
        loop {
            if let Some(active) = &mut self.source {
                if let Some(record) = active.reader.next_record(fetch)? {
                    if let CatalogPackedSourceRecord::Source { id, .. } = &record {
                        if active.last.is_none() && *id != active.part.first
                            || *id > active.part.last
                        {
                            return Err(CatalogError::InvalidPage.into());
                        }
                        active.last = Some(*id);
                    }
                    return Ok(Some(record));
                }
                if active.last != Some(active.part.last) {
                    return Err(CatalogError::InvalidPage.into());
                }
                self.source = None;
            }
            match self.next_part(fetch, visit)? {
                Some(CatalogPackingDirectoryRecord::Sources(part)) => {
                    self.source = Some(ActiveSourcePart {
                        part,
                        reader: CatalogPackedSourceReader::new(self.scope, part.root)?,
                        last: None,
                    });
                }
                Some(CatalogPackingDirectoryRecord::Sectors(part)) => {
                    let actual = self.state.summary;
                    let expected = self.root.summary;
                    if actual.source_parts != expected.source_parts
                        || actual.sources != expected.sources
                        || actual.source_chunks != expected.source_chunks
                        || actual.source_bytes != expected.source_bytes
                    {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    self.pending = Some(part);
                    self.sources_done = true;
                    return Ok(None);
                }
                None => {
                    self.sources_done = true;
                    return Ok(None);
                }
            }
        }
    }

    pub fn next_sector<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, E>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStreamError<E>> {
        self.next_sector_with_part(fetch, resolve, &mut |_| Ok(()))
    }

    pub fn next_sector_with_part<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, E>,
        visit: &mut impl FnMut(CatalogPackingDirectoryRecord) -> Result<(), E>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.sector_inner(fetch, resolve, visit);
        self.failed = result.is_err();
        result
    }

    fn sector_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, E>,
        visit: &mut impl FnMut(CatalogPackingDirectoryRecord) -> Result<(), E>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStreamError<E>> {
        if !self.sources_done {
            return Err(CatalogError::InvalidPage.into());
        }
        loop {
            if let Some(reader) = &mut self.sector {
                if let Some(record) = reader.next_record_with_sources(fetch, resolve)? {
                    return Ok(Some(record));
                }
                self.last_sector_has_source = reader.last_sector_has_source();
                self.sector = None;
            }
            let part = if let Some(part) = self.pending.take() {
                Some(part)
            } else {
                match self.next_part(fetch, visit)? {
                    Some(CatalogPackingDirectoryRecord::Sectors(part)) => Some(part),
                    Some(CatalogPackingDirectoryRecord::Sources(_)) => {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    None => None,
                }
            };
            let Some(part) = part else {
                if self.root.summary.sectors != 0 && !self.last_sector_has_source {
                    return Err(CatalogError::InvalidPage.into());
                }
                return Ok(None);
            };
            self.sector = Some(CatalogPackedSectorReader::for_part(self.scope, part)?);
        }
    }

    pub fn is_complete(&self) -> bool {
        self.complete
            && self.sources_done
            && self.source.is_none()
            && self.sector.is_none()
            && self.pending.is_none()
            && !self.failed
    }
}

#[cfg(test)]
mod tests;
