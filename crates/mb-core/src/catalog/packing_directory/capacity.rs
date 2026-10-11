//! Credits for compact source and descriptor construction. They preserve full
//! identities and source subtrees; they do not budget original coding witnesses.

use super::*;

// Postcard's fixed byte arrays are encoded without length prefixes. Reserve
// all header fields at their maximum scalar widths and the full commitment.
pub(in crate::catalog) const HEADER_BYTES: u64 = 256;
pub(in crate::catalog) const FRAGMENT_BYTES: u64 = 16;
// A virtual-zero reference includes both enum and Option tags, a 32-byte key,
// a five-byte u32 and a 32-byte hash. This also covers a data reference.
pub(in crate::catalog) const SLOT_BYTES: u64 = 72;

/// Local construction credits for the automatic dense part builder. Counts
/// include every source/sector occurrence, without assuming page sharing.
/// These bounds do not authorize sources or establish complete packing joins.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogPackingDirectoryCapacity {
    pub sources: u64,
    pub sectors: u64,
    pub source_parts: u64,
    pub sector_parts: u64,
    pub source_bytes: u64,
    pub sector_bytes: u64,
    pub directory_bytes: u64,
    pub work: CatalogCodingTraversalBudget,
    pub encoded_page_bytes: u64,
    pub(super) sources_per_part: u64,
    pub(super) sectors_per_part: u64,
}

impl CatalogPackingDirectoryCapacity {
    pub fn for_counts(
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
    ) -> Result<Self, CatalogError> {
        Self::with_part_bytes(profile, sources, sectors, CATALOG_MAX_STREAM_BYTES)
    }

    /// Choose a smaller part target for bounded updates without changing any
    /// record/page format. Each part still counts its own rounding and header.
    pub fn with_part_bytes(
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
        part_limit: u64,
    ) -> Result<Self, CatalogError> {
        let width = u64::from(
            profile
                .slots_per_sector()
                .map_err(|_| CatalogError::InvalidPage)?,
        );
        if sectors > u64::from(u32::MAX) + 1 || part_limit > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds);
        }
        let source_records = 1 + width.div_ceil(CATALOG_PACKED_SOURCE_PROOFS as u64);
        let sector_records = 1 + width.div_ceil(CATALOG_PACKED_SLOTS as u64);
        let unit = |records: u64, item_bytes: u64| {
            (records - 1)
                .checked_mul(4 + FRAGMENT_BYTES)
                .and_then(|bytes| bytes.checked_add(4 + HEADER_BYTES))
                .and_then(|bytes| bytes.checked_add(width * item_bytes))
                .ok_or(CatalogError::Bounds)
        };
        let source_unit = unit(source_records, 32)?;
        let sector_unit = unit(sector_records, SLOT_BYTES)?;
        let per_part = |unit: u64, records: u64| {
            let count = part_limit.checked_sub(8).ok_or(CatalogError::Bounds)? / unit;
            let count = count.min(CATALOG_MAX_RECORDS / records);
            if count == 0 {
                Err(CatalogError::Bounds)
            } else {
                Ok(count)
            }
        };
        let sources_per_part = per_part(source_unit, source_records)?;
        let sectors_per_part = per_part(sector_unit, sector_records)?;
        let source_parts = sources.div_ceil(sources_per_part);
        let sector_parts = sectors.div_ceil(sectors_per_part);
        let parts = source_parts
            .checked_add(sector_parts)
            .ok_or(CatalogError::Bounds)?;
        if parts > CATALOG_MAX_RECORDS {
            return Err(CatalogError::Bounds);
        }
        let stream_bytes = |count: u64, unit: u64, parts: u64| {
            count
                .checked_mul(unit)
                .and_then(|bytes| {
                    parts
                        .checked_mul(8)
                        .and_then(|headers| bytes.checked_add(headers))
                })
                .ok_or(CatalogError::Bounds)
        };
        let source_bytes = stream_bytes(sources, source_unit, source_parts)?;
        let sector_bytes = stream_bytes(sectors, sector_unit, sector_parts)?;
        let directory_bytes = parts
            .checked_mul(4 + CATALOG_PACKING_DIRECTORY_RECORD_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(8))
            .ok_or(CatalogError::Bounds)?;
        if directory_bytes > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds);
        }
        let directory_pages = dense_pages(directory_bytes);
        if directory_pages > CATALOG_MAX_PAGE_OCCURRENCES {
            return Err(CatalogError::Bounds);
        }
        let page_occurrences =
            super::super::coding_directory::dense_forest_pages(source_bytes, source_parts)?
                .checked_add(super::super::coding_directory::dense_forest_pages(
                    sector_bytes,
                    sector_parts,
                )?)
                .and_then(|pages| pages.checked_add(directory_pages))
                .ok_or(CatalogError::Bounds)?;
        let records = sources
            .checked_mul(source_records)
            .and_then(|records| {
                sectors
                    .checked_mul(sector_records)
                    .and_then(|more| records.checked_add(more))
            })
            .and_then(|records| records.checked_add(parts))
            .ok_or(CatalogError::Bounds)?;
        Ok(Self {
            sources,
            sectors,
            source_parts,
            sector_parts,
            source_bytes,
            sector_bytes,
            directory_bytes,
            work: CatalogCodingTraversalBudget {
                bytes: source_bytes
                    .checked_add(sector_bytes)
                    .and_then(|bytes| bytes.checked_add(directory_bytes))
                    .and_then(|bytes| {
                        bytes.checked_add(CATALOG_PACKING_DIRECTORY_ROOT_BYTES as u64)
                    })
                    .ok_or(CatalogError::Bounds)?,
                page_occurrences,
                records,
            },
            encoded_page_bytes: page_occurrences
                .checked_mul(CATALOG_PAGE_BYTES as u64)
                .ok_or(CatalogError::Bounds)?,
            sources_per_part,
            sectors_per_part,
        })
    }
}
