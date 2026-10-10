//! Revision-owned stable data recipes and physical anchor retention.

use mb_core::{CatalogSectorRecord, PagedUserRevision};

use super::*;

pub const PAGED_DATA_RECIPE_BYTES: usize = 8192;
const RECORD_LIMIT: usize = PAGED_DATA_RECIPE_BYTES + 1024;
pub(super) const ANCHOR: &str = "catalog-paged-data-anchor-v1";

fn sources(id: Uuid) -> String {
    format!("catalog-paged-data-source-v1/{}", id.simple())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DataSourceRecord {
    version: u16,
    source: CatalogSectorRecord,
    anchor: Uuid,
    recipe: Vec<u8>,
    generation: u64,
}

#[derive(Serialize, Deserialize)]
struct LegacyDataSourceRecord {
    version: u16,
    source: CatalogSectorRecord,
    anchor: Uuid,
    recipe: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedCatalogDataSource {
    pub catalog: PagedCatalogSnapshot,
    pub source: CatalogSectorRecord,
    pub anchor: Uuid,
    pub recipe: Vec<u8>,
    /// Monotonic local source identity; zero for version-1 bindings.
    pub generation: u64,
}

pub(super) fn anchor_count(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<u64>, CatalogStoreError> {
    bounded_record(connection, ANCHOR, id.as_bytes(), 10)?
        .map(|bytes| {
            let count: u64 = decode_canonical(&bytes)?;
            if count == 0 || canonical_bytes(&count)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(count)
        })
        .transpose()
}

pub(super) fn change_anchor_count(
    connection: &Connection,
    id: Uuid,
    previous: Option<u64>,
    next: u64,
) -> Result<(), CatalogStoreError> {
    match previous {
        None => insert_exact(connection, ANCHOR, id.as_bytes(), &canonical_bytes(&next)?),
        Some(previous) => {
            let old = canonical_bytes(&previous)?;
            let changed = if next == 0 {
                connection.execute("DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                    params![ANCHOR, id.as_bytes(), old])?
            } else {
                connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                    params![ANCHOR, id.as_bytes(), old, canonical_bytes(&next)?])?
            };
            if changed != 1 {
                return Err(DatabaseError::Conflict.into());
            }
            Ok(())
        }
    }?;
    if anchor_count(connection, id)? != (next != 0).then_some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

/// Find a retained physical binding without opening a nested read transaction.
/// Cancelled bindings remain usable for a dependency hold until their cleanup.
pub(super) fn retained_anchor(
    connection: &Connection,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<Option<Uuid>, CatalogStoreError> {
    let prefix = "catalog-paged-data-source-v1/";
    let mut cursor = String::new();
    loop {
        let kind: Option<Option<String>> = connection
            .query_row(
                "SELECT CASE WHEN length(kind) <= ?3 THEN kind END
             FROM protocol_records INDEXED BY protocol_records_paged_sector_sources
             WHERE record_id = ?1 AND kind > ?2 AND kind GLOB 'catalog-paged-data-source-v1/*'
             ORDER BY kind LIMIT 1",
                params![source.sector.id, cursor, prefix.len() + 32],
                |row| row.get(0),
            )
            .optional()?;
        let Some(kind) = kind else { return Ok(None) };
        let kind = kind.ok_or(DatabaseError::Integrity)?;
        let suffix = kind.strip_prefix(prefix).ok_or(DatabaseError::Integrity)?;
        let id = Uuid::parse_str(suffix).map_err(|_| DatabaseError::Integrity)?;
        if id.is_nil() || id.simple().to_string() != suffix {
            return Err(DatabaseError::Integrity.into());
        }
        let (bundle, state) =
            bundle::bundle_snapshot(connection, id)?.ok_or(DatabaseError::Integrity)?;
        if bundle.scope == scope {
            let bytes = bounded_record(connection, &kind, &source.sector.id, RECORD_LIMIT)?
                .ok_or(DatabaseError::Integrity)?;
            let record = decode_record(&bytes, source.sector.id)?;
            if record.source != *source
                || native_validation::retained_source_record(
                    connection,
                    id,
                    source.sector.id,
                    state == CatalogBundleState::Cancelled,
                )?
                .as_ref()
                    != Some(source)
                || anchor_count(connection, record.anchor)?.is_none()
            {
                return Err(DatabaseError::Integrity.into());
            }
            retained_source_quota::require_charge(
                connection,
                id,
                scope,
                source,
                state == CatalogBundleState::Cancelled,
            )?;
            return Ok(Some(record.anchor));
        }
        cursor = kind;
    }
}

fn decode_record(bytes: &[u8], sector: [u8; 32]) -> Result<DataSourceRecord, CatalogStoreError> {
    let record: DataSourceRecord = match bytes.first() {
        Some(1) => {
            let old: LegacyDataSourceRecord = decode_canonical(bytes)?;
            if canonical_bytes(&old)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            DataSourceRecord {
                version: 2,
                source: old.source,
                anchor: old.anchor,
                recipe: old.recipe,
                generation: 0,
            }
        }
        Some(2) => {
            let record: DataSourceRecord = decode_canonical(bytes)?;
            if canonical_bytes(&record)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            record
        }
        _ => return Err(DatabaseError::Integrity.into()),
    };
    if record.version != 2
        || record.source.sector.id != sector
        || record.anchor.is_nil()
        || record.recipe.is_empty()
        || record.recipe.len() > PAGED_DATA_RECIPE_BYTES
    {
        return Err(DatabaseError::Integrity.into());
    }
    record.source.validate()?;
    Ok(record)
}

pub(super) fn bind(
    connection: &Connection,
    bundle: &CatalogBundle,
    source: &CatalogSectorRecord,
    anchor: Uuid,
    recipe: &[u8],
) -> Result<(), CatalogStoreError> {
    if anchor.is_nil()
        || recipe.is_empty()
        || recipe.len() > PAGED_DATA_RECIPE_BYTES
        || native_validation::source_record(connection, bundle.id, source.sector.id)?.as_ref()
            != Some(source)
        || PagedUserRevision::decode_signed(&bundle.descriptor)?
            .value
            .metadata
            .sector
            .id
            == source.sector.id
    {
        return Err(DatabaseError::Conflict.into());
    }
    let kind = sources(bundle.id);
    let record = DataSourceRecord {
        version: 2,
        source: source.clone(),
        anchor,
        recipe: recipe.to_vec(),
        generation: 0,
    };
    let encoded = canonical_bytes(&record)?;
    if let Some(existing) = bounded_record(connection, &kind, &source.sector.id, RECORD_LIMIT)? {
        if decode_record(&existing, source.sector.id)? != record
            || anchor_count(connection, anchor)?.is_none()
        {
            return Err(DatabaseError::Conflict.into());
        }
        retained_source_quota::require_binding(connection, bundle.id, bundle.scope, source)?;
        return Ok(());
    }
    let previous = anchor_count(connection, anchor)?;
    let next = previous
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    retained_source_quota::bind(connection, bundle.id, bundle.scope, source)?;
    insert_exact(connection, &kind, &source.sector.id, &encoded)?;
    if bounded_record(connection, &kind, &source.sector.id, RECORD_LIMIT)?.as_deref()
        != Some(encoded.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    change_anchor_count(connection, anchor, previous, next)?;
    retained_source_quota::admission::consume(connection, bundle.id, bundle.scope, source)
}

pub(super) fn read_source(
    connection: &Connection,
    id: Uuid,
    sector: [u8; 32],
) -> Result<Option<PagedCatalogDataSource>, CatalogStoreError> {
    let Some(catalog) = paged_revision::snapshot(connection, id)? else {
        return Ok(None);
    };
    if catalog.state == CatalogBundleState::Cancelled {
        return Ok(None);
    }
    let Some(bytes) = bounded_record(connection, &sources(id), &sector, RECORD_LIMIT)? else {
        return Ok(None);
    };
    let record = decode_record(&bytes, sector)?;
    if native_validation::source_record(connection, id, sector)?.as_ref() != Some(&record.source)
        || anchor_count(connection, record.anchor)?.is_none()
    {
        return Err(DatabaseError::Integrity.into());
    }
    retained_source_quota::require_charge(
        connection,
        id,
        catalog.bundle.scope,
        &record.source,
        false,
    )?;
    Ok(Some(PagedCatalogDataSource {
        catalog,
        source: record.source,
        anchor: record.anchor,
        recipe: record.recipe,
        generation: record.generation,
    }))
}

impl ControlStore {
    /// Visit one indexed owner of a data sector, including cancelled owners
    /// whose pins await cleanup. The cursor advances over tombstones without
    /// materializing history or imposing a total owner-count limit.
    pub fn next_paged_revision_data_source(
        &self,
        sector: [u8; 32],
        after: Option<Uuid>,
    ) -> Result<Option<(Uuid, Option<PagedCatalogDataSource>)>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let prefix = "catalog-paged-data-source-v1/";
        let cursor = after.map(sources).unwrap_or_default();
        let kind: Option<Option<String>> = tx
            .query_row(
                "SELECT CASE WHEN length(kind) <= ?3 THEN kind END
             FROM protocol_records INDEXED BY protocol_records_paged_sector_sources
             WHERE record_id = ?1 AND kind > ?2
               AND kind GLOB 'catalog-paged-data-source-v1/*'
             ORDER BY kind LIMIT 1",
                params![sector, cursor, prefix.len() + 32],
                |row| row.get(0),
            )
            .optional()?;
        let result = if let Some(kind) = kind {
            let kind = kind.ok_or(DatabaseError::Integrity)?;
            let suffix = kind.strip_prefix(prefix).ok_or(DatabaseError::Integrity)?;
            let id = Uuid::parse_str(suffix).map_err(|_| DatabaseError::Integrity)?;
            if id.is_nil() || id.simple().to_string() != suffix {
                return Err(DatabaseError::Integrity.into());
            }
            let source = read_source(&tx, id, sector)?;
            if source.is_none()
                && paged_revision::snapshot(&tx, id)?
                    .ok_or(DatabaseError::Integrity)?
                    .state
                    != CatalogBundleState::Cancelled
            {
                return Err(DatabaseError::Integrity.into());
            }
            Some((id, source))
        } else {
            None
        };
        tx.commit()?;
        Ok(result)
    }

    /// Replace one authenticated source under an exact ownership/generation
    /// fence, transferring physical pins in the same writer transaction.
    /// The callback verifies replacement bytes using this current snapshot.
    /// One-generation exact retries are idempotent; intervening changes fail.
    pub fn replace_paged_revision_data_source_checked<E: From<CatalogStoreError>>(
        &self,
        expected: &PagedCatalogDataSource,
        anchor: Uuid,
        recipe: &[u8],
        check: impl FnOnce(&PagedCatalogDataSource) -> Result<(), E>,
    ) -> Result<PagedCatalogDataSource, E> {
        if anchor.is_nil() || recipe.is_empty() || recipe.len() > PAGED_DATA_RECIPE_BYTES {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let id = expected.catalog.bundle.id;
        let sector = expected.source.sector.id;
        let mut current = read_source(&tx, id, sector)?
            .ok_or_else(|| CatalogStoreError::from(DatabaseError::Conflict))?;
        if current.catalog != expected.catalog || current.source != expected.source {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let identical = current.anchor == anchor && current.recipe == recipe;
        let retry = identical && expected.generation.checked_add(1) == Some(current.generation);
        if &current != expected && !retry {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        check(&current)?;
        if identical {
            tx.commit().map_err(CatalogStoreError::from)?;
            return Ok(current);
        }
        let generation = current
            .generation
            .checked_add(1)
            .ok_or_else(|| CatalogStoreError::from(DatabaseError::CapacityExceeded))?;
        let old_bytes = bounded_record(&tx, &sources(id), &sector, RECORD_LIMIT)?
            .ok_or_else(|| CatalogStoreError::from(DatabaseError::Integrity))?;
        let encoded = canonical_bytes(&DataSourceRecord {
            version: 2,
            source: current.source.clone(),
            anchor,
            recipe: recipe.to_vec(),
            generation,
        })
        .map_err(CatalogStoreError::from)?;
        if tx.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![sources(id), sector, old_bytes, encoded]).map_err(CatalogStoreError::from)? != 1 {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        if current.anchor != anchor {
            let next_count = anchor_count(&tx, anchor)?;
            let next = next_count
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(|| CatalogStoreError::from(DatabaseError::CapacityExceeded))?;
            let old = anchor_count(&tx, current.anchor)?
                .ok_or_else(|| CatalogStoreError::from(DatabaseError::Integrity))?;
            change_anchor_count(&tx, anchor, next_count, next)?;
            change_anchor_count(&tx, current.anchor, Some(old), old - 1)?;
        }
        current.anchor = anchor;
        current.recipe = recipe.to_vec();
        current.generation = generation;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(current)
    }

    /// Read one bounded recipe and its signed/root ownership in one snapshot.
    /// Cancelled revisions are unavailable even while physical pins await GC.
    pub fn paged_revision_data_source(
        &self,
        id: Uuid,
        sector: [u8; 32],
    ) -> Result<Option<PagedCatalogDataSource>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let result = read_source(&tx, id, sector)?;
        tx.commit()?;
        Ok(result)
    }

    pub fn paged_data_anchor_is_pinned(&self, anchor: Uuid) -> Result<bool, CatalogStoreError> {
        Ok(anchor_count(&self.connection, anchor)?.is_some())
    }

    /// Compatibility index for existing native Git prune. Only identities are
    /// materialized; paged data reads and retirement remain indexed/bounded.
    pub fn paged_data_anchor_ids(&self) -> Result<Vec<Uuid>, CatalogStoreError> {
        let mut statement = self.connection.prepare("SELECT CASE WHEN length(record_id) = 16 THEN record_id END,
            CASE WHEN length(bytes) <= 10 THEN bytes END FROM protocol_records WHERE kind = ?1 ORDER BY record_id")?;
        let mut rows = statement.query(params![ANCHOR])?;
        let mut anchors = Vec::new();
        while let Some(row) = rows.next()? {
            let key: Option<Vec<u8>> = row.get(0)?;
            let bytes: Option<Vec<u8>> = row.get(1)?;
            let id = Uuid::from_slice(&key.ok_or(DatabaseError::Integrity)?)
                .map_err(|_| DatabaseError::Integrity)?;
            let bytes = bytes.ok_or(DatabaseError::Integrity)?;
            let count: u64 = decode_canonical(&bytes)?;
            if id.is_nil() || count == 0 || canonical_bytes(&count)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            anchors.push(id);
        }
        Ok(anchors)
    }

    /// Release one cancelled recipe and its exact physical anchor count in one
    /// writer transaction. Shared revisions and other sectors retain their pins.
    pub fn release_paged_revision_data_source(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let catalog = paged_revision::snapshot(&tx, id)?.ok_or(DatabaseError::NotReady)?;
        if catalog.state != CatalogBundleState::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let kind = sources(id);
        let key: Option<Option<Vec<u8>>> = tx
            .query_row(
                "SELECT CASE WHEN length(record_id) = 32 THEN record_id END
            FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
                params![kind],
                |row| row.get(0),
            )
            .optional()?;
        let removed = if let Some(key) = key {
            let key: [u8; 32] = key
                .ok_or(DatabaseError::Integrity)?
                .try_into()
                .map_err(|_| DatabaseError::Integrity)?;
            let record = decode_record(
                &bounded_record(&tx, &kind, &key, RECORD_LIMIT)?.ok_or(DatabaseError::Integrity)?,
                key,
            )?;
            let count = anchor_count(&tx, record.anchor)?.ok_or(DatabaseError::Integrity)?;
            if tx.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![kind, key],
            )? != 1
                || bounded_record(&tx, &kind, &key, RECORD_LIMIT)?.is_some()
            {
                return Err(DatabaseError::Conflict.into());
            }
            retained_source_quota::release(&tx, id, catalog.bundle.scope, &record.source)?;
            change_anchor_count(&tx, record.anchor, Some(count), count - 1)?;
            true
        } else {
            false
        };
        tx.commit()?;
        Ok(removed)
    }
}
