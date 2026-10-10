//! Immutable shared recipe bytes. Owner backlinks retain one independent
//! binding/generation per revision without copying its opaque recipe body.

use super::*;

#[cfg(test)]
mod tests;

pub(super) const RECIPE: &str = "catalog-paged-data-recipe-v1";

fn owners(key: [u8; 32]) -> String {
    format!("catalog-paged-data-recipe-owner-v1/{}", hex::encode(key))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Recipe {
    version: u16,
    scope: CatalogScope,
    source: CatalogSectorRecord,
    anchor: Uuid,
    #[serde(deserialize_with = "bounded_recipe")]
    bytes: Vec<u8>,
    references: u64,
}

fn key(scope: CatalogScope, record: &DataSourceRecord) -> Result<[u8; 32], CatalogStoreError> {
    scope.validate(CatalogSection::SectorReferences)?;
    if !matches!(scope, CatalogScope::Dataset { .. }) {
        return Err(DatabaseError::Conflict.into());
    }
    let bytes = mb_core::canonical_bytes_bounded(
        &(1_u16, scope, &record.source, record.anchor, &record.recipe),
        RECORD_LIMIT,
    )?;
    let mut hash = blake3::Hasher::new_derive_key("mutualbackup shared paged data recipe v1");
    hash.update(&bytes);
    Ok(*hash.finalize().as_bytes())
}

fn load(connection: &Connection, key: [u8; 32]) -> Result<Option<Recipe>, CatalogStoreError> {
    let Some(bytes) = bounded_record(connection, RECIPE, &key, RECORD_LIMIT)? else {
        return Ok(None);
    };
    let record: Recipe = decode_canonical(&bytes)?;
    let identity = DataSourceRecord {
        version: 2,
        source: record.source.clone(),
        anchor: record.anchor,
        recipe: record.bytes.clone(),
        generation: 0,
    };
    if record.version != 1
        || record.references == 0
        || record.references > i64::MAX as u64
        || record.anchor.is_nil()
        || record.bytes.is_empty()
        || record.bytes.len() > PAGED_DATA_RECIPE_BYTES
        || canonical_bytes(&record)? != bytes
        || self::key(record.scope, &identity)? != key
    {
        return Err(DatabaseError::Integrity.into());
    }
    record.source.validate()?;
    let count: u64 = connection.query_row(
        "SELECT count(*) FROM protocol_records WHERE kind = ?1",
        [owners(key)],
        |row| row.get(0),
    )?;
    if count != record.references {
        return Err(DatabaseError::Integrity.into());
    }
    let malformed: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1
         AND (length(record_id) != 16 OR record_id = zeroblob(16) OR length(bytes) != 0))",
        [owners(key)],
        |row| row.get(0),
    )?;
    if malformed {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

fn require_owner(
    connection: &Connection,
    key: [u8; 32],
    id: Uuid,
) -> Result<(), CatalogStoreError> {
    if id.is_nil()
        || bounded_record(connection, &owners(key), id.as_bytes(), 0)?.as_deref() != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn read(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    binding: &SharedDataSourceRecord,
) -> Result<Vec<u8>, CatalogStoreError> {
    let record = load(connection, binding.recipe)?.ok_or(DatabaseError::Integrity)?;
    require_owner(connection, binding.recipe, id)?;
    if record.scope != scope || record.source != binding.source || record.anchor != binding.anchor {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(record.bytes)
}

pub(super) fn acquire(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    binding: &DataSourceRecord,
) -> Result<SharedDataSourceRecord, CatalogStoreError> {
    if connection.is_autocommit()
        || id.is_nil()
        || binding.anchor.is_nil()
        || binding.recipe.is_empty()
        || binding.recipe.len() > PAGED_DATA_RECIPE_BYTES
    {
        return Err(DatabaseError::Conflict.into());
    }
    binding.source.validate()?;
    let key = key(scope, binding)?;
    let old = load(connection, key)?;
    if old.is_none() {
        let orphan: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
            [owners(key)],
            |row| row.get(0),
        )?;
        if orphan {
            return Err(DatabaseError::Integrity.into());
        }
    }
    if bounded_record(connection, &owners(key), id.as_bytes(), 0)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
    let record = Recipe {
        version: 1,
        scope,
        source: binding.source.clone(),
        anchor: binding.anchor,
        bytes: binding.recipe.clone(),
        references: old
            .as_ref()
            .map(|record| record.references)
            .unwrap_or(0)
            .checked_add(1)
            .filter(|count| *count <= i64::MAX as u64)
            .ok_or(DatabaseError::CapacityExceeded)?,
    };
    let bytes = mb_core::canonical_bytes_bounded(&record, RECORD_LIMIT)?;
    insert_exact(connection, &owners(key), id.as_bytes(), &[])?;
    require_owner(connection, key, id)?;
    if let Some(old) = old {
        let expected = canonical_bytes(&old)?;
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3", params![RECIPE, key, expected, bytes])? != 1 {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        insert_exact(connection, RECIPE, &key, &bytes)?;
    }
    if load(connection, key)? != Some(record) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(SharedDataSourceRecord {
        version: 3,
        source: binding.source.clone(),
        anchor: binding.anchor,
        recipe: key,
        generation: binding.generation,
    })
}

pub(super) fn release(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    binding: &SharedDataSourceRecord,
) -> Result<(), CatalogStoreError> {
    if connection.is_autocommit() {
        return Err(DatabaseError::Conflict.into());
    }
    let mut record = load(connection, binding.recipe)?.ok_or(DatabaseError::Integrity)?;
    read(connection, id, scope, binding)?;
    if connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
        params![owners(binding.recipe), id.as_bytes()],
    )? != 1
        || bounded_record(connection, &owners(binding.recipe), id.as_bytes(), 0)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    let old = canonical_bytes(&record)?;
    if record.references == 1 {
        if connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![RECIPE, binding.recipe, old],
        )? != 1
            || bounded_record(connection, RECIPE, &binding.recipe, RECORD_LIMIT)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    } else {
        record.references -= 1;
        let bytes = canonical_bytes(&record)?;
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3", params![RECIPE, binding.recipe, old, bytes])? != 1
            || load(connection, binding.recipe)? != Some(record)
        { return Err(DatabaseError::Integrity.into()) }
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn make_inline_for_test(store: &ControlStore, source: &PagedCatalogDataSource) {
    store
        .with_record_transaction(|| {
            let id = source.catalog.bundle.id;
            let raw = bounded_record(
                &store.connection,
                &sources(id),
                &source.source.sector.id,
                RECORD_LIMIT,
            )?
            .ok_or(DatabaseError::Integrity)?;
            if let Some(shared) = shared_record(&raw)? {
                release(&store.connection, id, source.catalog.bundle.scope, &shared)?;
                let bytes = canonical_bytes(&DataSourceRecord {
                    version: 2,
                    source: source.source.clone(),
                    anchor: source.anchor,
                    recipe: source.recipe.clone(),
                    generation: source.generation,
                })?;
                if store.connection.execute(
                    "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
                    params![sources(id), source.source.sector.id, bytes],
                )? != 1
                {
                    return Err(DatabaseError::Integrity.into());
                }
            }
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
}
