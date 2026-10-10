//! Aggregate the existing dataset source charges and outstanding credits inside
//! their writer. Shared revisions and dependency holds remain charged once per
//! dataset; a guild limit is never reset at a dataset or owner boundary.

use super::*;

const POLICY: &str = "catalog-retained-source-guild-quota-v1";
const ENABLED: &str = "catalog-retained-source-guild-quota-enabled-v1";
const LEDGER: &str = "catalog-retained-source-guild-usage-v1";
const GUILD: &str = "catalog-retained-source-guild-v1";

fn members(guild_id: [u8; 32]) -> String {
    format!(
        "catalog-retained-source-guild-dataset-v1/{}",
        hex::encode(guild_id)
    )
}

fn register_dataset(connection: &Connection, scope: CatalogScope) -> Result<(), CatalogStoreError> {
    let kind = members(guild_id(scope)?);
    let key = dataset_key(scope)?;
    insert_exact(connection, &kind, &key, &[1])?;
    if bounded_record(connection, &kind, &key, 1)?.as_deref() != Some(&[1]) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;

fn guild_id(scope: CatalogScope) -> Result<[u8; 32], CatalogStoreError> {
    dataset_key(scope)?;
    let CatalogScope::Dataset { guild_id, .. } = scope else {
        unreachable!("dataset scope checked")
    };
    Ok(guild_id)
}

pub(super) fn policy(
    connection: &Connection,
) -> Result<Option<CatalogRetainedSourceQuota>, CatalogStoreError> {
    match (
        bounded_record(connection, ENABLED, KEY, 1)?.as_deref(),
        bounded_record(connection, POLICY, KEY, RECORD_BYTES)?,
    ) {
        (None, None) => {
            let existing: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1, ?2)
                 OR kind GLOB 'catalog-retained-source-guild-dataset-v1/*')",
                params![LEDGER, GUILD],
                |row| row.get(0),
            )?;
            if existing {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(None)
        }
        (Some([1]), Some(bytes)) => {
            let (version, quota): (u16, CatalogRetainedSourceQuota) = decode(&bytes)?;
            if version != 1 {
                return Err(DatabaseError::Integrity.into());
            }
            quota.validate()?;
            Ok(Some(quota))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn ledger(
    connection: &Connection,
    guild_id: [u8; 32],
    quota: CatalogRetainedSourceQuota,
) -> Result<Option<CatalogRetainedSourceUsage>, CatalogStoreError> {
    let result = match (
        bounded_record(connection, GUILD, &guild_id, 1)?.as_deref(),
        bounded_record(connection, LEDGER, &guild_id, RECORD_BYTES)?,
    ) {
        (None, None) => {
            let existing: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
                params![members(guild_id)],
                |row| row.get(0),
            )?;
            if existing {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(None);
        }
        (Some([1]), Some(bytes)) => {
            let (version, usage): (u16, CatalogRetainedSourceUsage) = decode(&bytes)?;
            if version != 1 || usage.scope != (CatalogScope::Guild { guild_id }) {
                return Err(DatabaseError::Integrity.into());
            }
            usage
        }
        _ => return Err(DatabaseError::Integrity.into()),
    };
    result.validate_limits(quota)?;
    Ok(Some(result))
}

fn ensure(
    connection: &Connection,
    guild_id: [u8; 32],
    quota: CatalogRetainedSourceQuota,
) -> Result<CatalogRetainedSourceUsage, CatalogStoreError> {
    if let Some(usage) = ledger(connection, guild_id, quota)? {
        return Ok(usage);
    }
    let usage = CatalogRetainedSourceUsage::empty(CatalogScope::Guild { guild_id });
    insert_exact(
        connection,
        LEDGER,
        &guild_id,
        &canonical_bytes(&(1_u16, usage))?,
    )?;
    insert_exact(connection, GUILD, &guild_id, &[1])?;
    if ledger(connection, guild_id, quota)? != Some(usage) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(usage)
}

pub(super) fn ensure_ledger(
    connection: &Connection,
    scope: CatalogScope,
) -> Result<(), CatalogStoreError> {
    if let Some(quota) = policy(connection)? {
        ensure(connection, guild_id(scope)?, quota)?;
        register_dataset(connection, scope)?;
    }
    Ok(())
}

pub(super) fn require_dataset_usage(
    connection: &Connection,
    dataset: CatalogRetainedSourceUsage,
    known_dataset: bool,
) -> Result<(), CatalogStoreError> {
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    let total = ledger(connection, guild_id(dataset.scope)?, quota)?;
    if known_dataset
        && (total.is_none()
            || bounded_record(
                connection,
                &members(guild_id(dataset.scope)?),
                &dataset_key(dataset.scope)?,
                1,
            )?
            .as_deref()
                != Some(&[1]))
    {
        return Err(DatabaseError::Integrity.into());
    }
    if let Some(total) = total
        && (total.stored_logical_bytes < dataset.stored_logical_bytes
            || total.stored_sources < dataset.stored_sources
            || total.reserved_logical_bytes < dataset.reserved_logical_bytes
            || total.reserved_sources < dataset.reserved_sources
            || total.open_reservations < dataset.open_reservations)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn changed(
    mut total: CatalogRetainedSourceUsage,
    before: CatalogRetainedSourceUsage,
    after: CatalogRetainedSourceUsage,
) -> Result<CatalogRetainedSourceUsage, CatalogStoreError> {
    if before.scope != after.scope
        || total.scope
            != (CatalogScope::Guild {
                guild_id: guild_id(after.scope)?,
            })
    {
        return Err(DatabaseError::Conflict.into());
    }
    for (value, old, new) in [
        (
            &mut total.stored_logical_bytes,
            before.stored_logical_bytes,
            after.stored_logical_bytes,
        ),
        (
            &mut total.stored_sources,
            before.stored_sources,
            after.stored_sources,
        ),
        (
            &mut total.reserved_logical_bytes,
            before.reserved_logical_bytes,
            after.reserved_logical_bytes,
        ),
        (
            &mut total.reserved_sources,
            before.reserved_sources,
            after.reserved_sources,
        ),
    ] {
        *value = value
            .checked_sub(old)
            .ok_or(DatabaseError::Integrity)?
            .checked_add(new)
            .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    }
    total.open_reservations = total
        .open_reservations
        .checked_sub(before.open_reservations)
        .ok_or(DatabaseError::Integrity)?
        .checked_add(after.open_reservations)
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    Ok(total)
}

pub(super) fn update_dataset_usage(
    connection: &Connection,
    before: CatalogRetainedSourceUsage,
    after: CatalogRetainedSourceUsage,
) -> Result<(), CatalogStoreError> {
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    let id = guild_id(after.scope)?;
    let total = ledger(connection, id, quota)?.ok_or(DatabaseError::Integrity)?;
    let total = changed(total, before, after)?;
    total.validate_limits(quota)?;
    replace(connection, LEDGER, &id, &(1_u16, total))
}

fn adopt(
    connection: &Connection,
    dataset_quota: CatalogRetainedSourceQuota,
    guild_quota: CatalogRetainedSourceQuota,
) -> Result<(), CatalogStoreError> {
    // A missing dataset ledger cannot be interpreted as zero during adoption.
    let missing: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records AS marker WHERE marker.kind = ?1
         AND NOT EXISTS(SELECT 1 FROM protocol_records AS usage WHERE usage.kind = ?2
         AND usage.record_id = marker.record_id))",
        params![DATASET, super::LEDGER],
        |row| row.get(0),
    )?;
    if missing {
        return Err(DatabaseError::Integrity.into());
    }
    // Bound both columns in SQL before allocating a single row. The covering
    // kind/key index and one-row decoding keep memory independent of datasets,
    // revisions, sources and page counts. Adoption shares the immediate writer
    // with every reservation, so no new dataset can escape this snapshot.
    let mut statement = connection.prepare(
        "SELECT CASE WHEN length(record_id) = 32 THEN record_id END,
         CASE WHEN length(bytes) BETWEEN 1 AND ?2 THEN bytes END
         FROM protocol_records WHERE kind = ?1 ORDER BY record_id",
    )?;
    let mut rows = statement.query(params![super::LEDGER, RECORD_BYTES])?;
    while let Some(row) = rows.next()? {
        let key: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(0)?
            .ok_or(DatabaseError::Integrity)?;
        let bytes: Vec<u8> = row
            .get::<_, Option<Vec<u8>>>(1)?
            .ok_or(DatabaseError::Integrity)?;
        let (version, dataset): (u16, CatalogRetainedSourceUsage) = decode(&bytes)?;
        dataset.validate(dataset_quota)?;
        if version != 1
            || key != dataset_key(dataset.scope)?
            || bounded_record(connection, DATASET, &key, 1)?.as_deref() != Some(&[1])
        {
            return Err(DatabaseError::Integrity.into());
        }
        let id = guild_id(dataset.scope)?;
        let total = ensure(connection, id, guild_quota)?;
        let total = changed(
            total,
            CatalogRetainedSourceUsage::empty(dataset.scope),
            dataset,
        )?;
        total.validate_limits(guild_quota)?;
        replace(connection, LEDGER, &id, &(1_u16, total))?;
        register_dataset(connection, dataset.scope)?;
    }
    Ok(())
}

impl ControlStore {
    /// Enforce one aggregate retained logical source limit per guild, across
    /// all owners/datasets and outstanding jobs. Dataset accounting must already
    /// be enabled. Initial adoption streams existing ledgers under the immediate
    /// writer and rejects an over-limit guild without changing its data or jobs.
    /// Grow-only changes preserve admission without rescanning retained history.
    /// Private/bootstrap metadata, physical payload/coding and SQL/WAL usage
    /// still require their own enclosing resource policy.
    pub fn configure_catalog_retained_source_guild_quota(
        &self,
        quota: CatalogRetainedSourceQuota,
    ) -> Result<(), CatalogStoreError> {
        quota.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let dataset_quota = super::policy(&tx)?.ok_or(DatabaseError::NotReady)?;
        if let Some(previous) = policy(&tx)? {
            if quota.logical_bytes < previous.logical_bytes
                || quota.sources < previous.sources
                || quota.open_reservations < previous.open_reservations
            {
                return Err(CatalogStoreError::RetainedSourceQuotaExceeded);
            }
            replace(&tx, POLICY, KEY, &(1_u16, quota))?;
        } else {
            adopt(&tx, dataset_quota, quota)?;
            insert_exact(&tx, POLICY, KEY, &canonical_bytes(&(1_u16, quota))?)?;
            insert_exact(&tx, ENABLED, KEY, &[1])?;
        }
        if policy(&tx)? != Some(quota) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(())
    }

    /// Aggregate unique per-dataset data charges and credits. Returned scope is
    /// Guild; repeated retained owners/holds within a dataset do not add bytes.
    pub fn catalog_retained_source_guild_usage(
        &self,
        guild_id: [u8; 32],
    ) -> Result<Option<CatalogRetainedSourceUsage>, CatalogStoreError> {
        let snapshot = self.read_snapshot()?;
        super::policy(&snapshot)?;
        let usage = policy(&snapshot)?
            .map(|quota| -> Result<_, CatalogStoreError> {
                Ok(ledger(&snapshot, guild_id, quota)?.unwrap_or_else(|| {
                    CatalogRetainedSourceUsage::empty(CatalogScope::Guild { guild_id })
                }))
            })
            .transpose()?;
        snapshot.commit()?;
        Ok(usage)
    }
}
