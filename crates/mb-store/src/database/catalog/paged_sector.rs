//! Sector-address lookup of existing revision-owned source rows. The partial
//! database index also covers old bindings, without a second ownership journal.

use super::*;

const DATA_PREFIX: &str = "catalog-paged-data-source-v1/";
const PAGE_PREFIX: &str = "catalog-paged-page-source-v1/";
const SOURCE_OWNERS_PER_LOOKUP: usize = 64;
const NEXT_SOURCE: &str = "SELECT CASE WHEN length(kind) <= ?3 THEN kind END
    FROM protocol_records INDEXED BY protocol_records_paged_sector_sources
    WHERE record_id = ?1 AND kind > ?2
      AND (kind GLOB 'catalog-paged-data-source-v1/*'
        OR kind GLOB 'catalog-paged-page-source-v1/*')
    ORDER BY kind LIMIT 1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PagedCatalogSectorSource {
    Page(PagedCatalogPageSource),
    Data(PagedCatalogDataSource),
}

impl PagedCatalogSectorSource {
    pub fn catalog(&self) -> &PagedCatalogSnapshot {
        match self {
            Self::Page(source) => &source.catalog,
            Self::Data(source) => &source.catalog,
        }
    }

    pub fn source(&self) -> &mb_core::CatalogSectorRecord {
        match self {
            Self::Page(source) => &source.source,
            Self::Data(source) => &source.source,
        }
    }
}

impl ControlStore {
    /// Select a live source without collecting revision history. Each candidate
    /// and its root/source/pin state are checked in one read snapshot. Retired
    /// rows remain until bounded cleanup, with a fixed per-call work budget.
    /// Read-only pre-index catalogs retain their old explicit-revision APIs;
    /// writable schema migration installs the index over all existing bindings.
    pub fn paged_sector_source(
        &self,
        sector: [u8; 32],
    ) -> Result<Option<PagedCatalogSectorSource>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let version = super::super::stored_schema_version(&tx)?;
        if matches!(version, 1..=3 | 5..=9) {
            tx.commit()?;
            return Ok(None);
        }
        if version != crate::SCHEMA_VERSION {
            return Err(DatabaseError::IncompatibleSchema.into());
        }
        // INDEXED BY makes a lost current-schema index an error, rather than
        // silently treating retained ownership as absent or scanning history.
        let mut cursor = String::new();
        for visited in 0..=SOURCE_OWNERS_PER_LOOKUP {
            let kind: Option<Option<String>> = tx
                .query_row(
                    NEXT_SOURCE,
                    params![sector, cursor, PAGE_PREFIX.len() + 32],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(kind) = kind else {
                tx.commit()?;
                return Ok(None);
            };
            let kind = kind.ok_or(DatabaseError::Integrity)?;
            if visited == SOURCE_OWNERS_PER_LOOKUP {
                return Err(CatalogStoreError::PagedSourceLookupLimit);
            }
            let (is_page, suffix) = if let Some(suffix) = kind.strip_prefix(PAGE_PREFIX) {
                (true, suffix)
            } else {
                (
                    false,
                    kind.strip_prefix(DATA_PREFIX)
                        .ok_or(DatabaseError::Integrity)?,
                )
            };
            let id = Uuid::parse_str(suffix).map_err(|_| DatabaseError::Integrity)?;
            if id.is_nil() || id.simple().to_string() != suffix {
                return Err(DatabaseError::Integrity.into());
            }
            let source = if is_page {
                paged_revision::page_source(&tx, id, sector)?.map(PagedCatalogSectorSource::Page)
            } else {
                paged_data::read_source(&tx, id, sector)?.map(PagedCatalogSectorSource::Data)
            };
            if let Some(source) = source {
                tx.commit()?;
                return Ok(Some(source));
            }
            // Only a valid cancellation journal can explain a skipped row.
            if paged_revision::snapshot(&tx, id)?
                .ok_or(DatabaseError::Integrity)?
                .state
                != CatalogBundleState::Cancelled
            {
                return Err(DatabaseError::Integrity.into());
            }
            cursor = kind;
        }
        unreachable!("the lookup either exhausts its candidates or its explicit budget")
    }
}
