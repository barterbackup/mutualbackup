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
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PagedCatalogDataSource {
    pub catalog: PagedCatalogSnapshot,
    pub source: CatalogSectorRecord,
    pub anchor: Uuid,
    pub recipe: Vec<u8>,
}

fn anchor_count(connection: &Connection, id: Uuid) -> Result<Option<u64>, CatalogStoreError> {
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

fn change_anchor_count(
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
    }
}

fn decode_record(bytes: &[u8], sector: [u8; 32]) -> Result<DataSourceRecord, CatalogStoreError> {
    let record: DataSourceRecord = decode_canonical(bytes)?;
    if record.version != 1
        || record.source.sector.id != sector
        || record.anchor.is_nil()
        || record.recipe.is_empty()
        || record.recipe.len() > PAGED_DATA_RECIPE_BYTES
        || canonical_bytes(&record)? != bytes
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
    let encoded = canonical_bytes(&DataSourceRecord {
        version: 1,
        source: source.clone(),
        anchor,
        recipe: recipe.to_vec(),
    })?;
    if let Some(existing) = bounded_record(connection, &kind, &source.sector.id, RECORD_LIMIT)? {
        if existing != encoded || anchor_count(connection, anchor)?.is_none() {
            return Err(DatabaseError::Conflict.into());
        }
        return Ok(());
    }
    let previous = anchor_count(connection, anchor)?;
    let next = previous
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    insert_exact(connection, &kind, &source.sector.id, &encoded)?;
    change_anchor_count(connection, anchor, previous, next)
}

impl ControlStore {
    /// Read one bounded recipe and its signed/root ownership in one snapshot.
    /// Cancelled revisions are unavailable even while physical pins await GC.
    pub fn paged_revision_data_source(
        &self,
        id: Uuid,
        sector: [u8; 32],
    ) -> Result<Option<PagedCatalogDataSource>, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let result = if let Some(catalog) = paged_revision::snapshot(&tx, id)? {
            if catalog.state == CatalogBundleState::Cancelled {
                None
            } else if let Some(bytes) = bounded_record(&tx, &sources(id), &sector, RECORD_LIMIT)? {
                let record = decode_record(&bytes, sector)?;
                if native_validation::source_record(&tx, id, sector)?.as_ref()
                    != Some(&record.source)
                    || anchor_count(&tx, record.anchor)?.is_none()
                {
                    return Err(DatabaseError::Integrity.into());
                }
                Some(PagedCatalogDataSource {
                    catalog,
                    source: record.source,
                    anchor: record.anchor,
                    recipe: record.recipe,
                })
            } else {
                None
            }
        } else {
            None
        };
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
        if paged_revision::snapshot(&tx, id)?
            .ok_or(DatabaseError::NotReady)?
            .state
            != CatalogBundleState::Cancelled
        {
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
            {
                return Err(DatabaseError::Conflict.into());
            }
            change_anchor_count(&tx, record.anchor, Some(count), count - 1)?;
            true
        } else {
            false
        };
        tx.commit()?;
        Ok(removed)
    }
}
