//! Incremental admission holds shared source identities and their physical
//! anchors until publication or bounded cancellation cleanup transfers them.

use super::*;

#[cfg(test)]
mod tests;

pub(super) const PLAN: &str = "catalog-retained-source-admission-v1";
pub(super) const HOLD: &str = "catalog-retained-source-hold-v1";

fn owners(id: Uuid) -> String {
    format!("catalog-retained-source-hold-owner-v1/{}", id.simple())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Plan {
    version: u16,
    id: Uuid,
    scope: CatalogScope,
    digest: [u8; 32],
    requested: CatalogRetainedSourceReservation,
    held: CatalogRetainedSourceReservation,
    conservative: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Hold {
    version: u16,
    id: Uuid,
    scope: CatalogScope,
    source: CatalogSectorRecord,
    anchor: Uuid,
}

fn hold_key(
    scope: CatalogScope,
    source: [u8; 32],
    id: Uuid,
) -> Result<[u8; 80], CatalogStoreError> {
    let mut key = [0; 80];
    key[..64].copy_from_slice(&source_key(scope, source)?);
    key[64..].copy_from_slice(id.as_bytes());
    Ok(key)
}

fn checked_hold(connection: &Connection, key: &[u8]) -> Result<Hold, CatalogStoreError> {
    let bytes =
        bounded_record(connection, HOLD, key, RECORD_BYTES)?.ok_or(DatabaseError::Integrity)?;
    let hold: Hold = decode(&bytes)?;
    if hold.version != 1
        || hold.id.is_nil()
        || hold.anchor.is_nil()
        || key != hold_key(hold.scope, hold.source.sector.id, hold.id)?
        || bounded_record(connection, &owners(hold.id), &hold.source.sector.id, 80)?.as_deref()
            != Some(key)
        || charge(connection, hold.scope, &hold.source)?.is_none()
        || paged_data::anchor_count(connection, hold.anchor)?.is_none()
    {
        return Err(DatabaseError::Integrity.into());
    }
    let reservation =
        reservation(connection, hold.id, hold.scope)?.ok_or(DatabaseError::Integrity)?;
    let quota = policy(connection)?.ok_or(DatabaseError::Integrity)?;
    let usage = usage(connection, hold.scope, quota)?;
    if usage.stored_sources == 0
        || usage.stored_logical_bytes < u64::from(hold.source.sector.logical_len)
    {
        return Err(DatabaseError::Integrity.into());
    }
    if reservation.state == State::Published {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(hold)
}

fn own_hold(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<Option<Hold>, CatalogStoreError> {
    let key = hold_key(scope, source.sector.id, id)?;
    let backlink = bounded_record(connection, &owners(id), &source.sector.id, 80)?;
    if backlink.as_deref().is_some_and(|bytes| bytes != key) {
        return Err(DatabaseError::Integrity.into());
    }
    if bounded_record(connection, HOLD, &key, RECORD_BYTES)?.is_none() {
        if backlink.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    }
    let hold = checked_hold(connection, &key)?;
    if hold.source != *source {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(hold))
}

fn shared_anchor(
    connection: &Connection,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<Uuid, CatalogStoreError> {
    // Existing holds also work after the original revision's final binding is
    // cleaned. This point/range lookup does not materialize retained history.
    let prefix = source_key(scope, source.sector.id)?;
    let key: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(record_id) = 80 THEN record_id END
         FROM protocol_records WHERE kind = ?1 AND record_id >= ?2 ORDER BY record_id LIMIT 1",
            params![HOLD, prefix.as_slice()],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(key) = key {
        let key = key.ok_or(DatabaseError::Integrity)?;
        if key.starts_with(&prefix) {
            let hold = checked_hold(connection, &key)?;
            if hold.scope != scope || hold.source != *source {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(hold.anchor);
        }
    }
    paged_data::retained_anchor(connection, scope, source)?
        .ok_or_else(|| DatabaseError::Integrity.into())
}

fn add_hold(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    let mut charge = charge(connection, scope, source)?.ok_or(DatabaseError::Integrity)?;
    let anchor = shared_anchor(connection, scope, source)?;
    let old = paged_data::anchor_count(connection, anchor)?.ok_or(DatabaseError::Integrity)?;
    let next = old.checked_add(1).ok_or(DatabaseError::CapacityExceeded)?;
    charge.owners = charge
        .owners
        .checked_add(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    let hold = Hold {
        version: 1,
        id,
        scope,
        source: source.clone(),
        anchor,
    };
    let key = hold_key(scope, source.sector.id, id)?;
    insert_exact(
        connection,
        HOLD,
        &key,
        &mb_core::canonical_bytes_bounded(&hold, RECORD_BYTES)?,
    )?;
    insert_exact(connection, &owners(id), &source.sector.id, &key)?;
    replace(
        connection,
        SOURCE,
        &source_key(scope, source.sector.id)?,
        &charge,
    )?;
    paged_data::change_anchor_count(connection, anchor, Some(old), next)?;
    if checked_hold(connection, &key)? != hold {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn remove_hold(connection: &Connection, hold: &Hold) -> Result<(), CatalogStoreError> {
    let quota = policy(connection)?.ok_or(DatabaseError::Integrity)?;
    let old = paged_data::anchor_count(connection, hold.anchor)?.ok_or(DatabaseError::Integrity)?;
    let key = hold_key(hold.scope, hold.source.sector.id, hold.id)?;
    for (kind, key) in [
        (HOLD.to_owned(), key.as_slice()),
        (owners(hold.id), hold.source.sector.id.as_slice()),
    ] {
        if connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![kind, key],
        )? != 1
            || bounded_record(connection, &kind, key, RECORD_BYTES)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    release_owner(connection, hold.scope, &hold.source, quota)?;
    paged_data::change_anchor_count(connection, hold.anchor, Some(old), old - 1)
}

pub(in crate::database::catalog) fn consume(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    if let Some(hold) = own_hold(connection, id, scope, source)? {
        let reservation = reservation(connection, id, scope)?.ok_or(DatabaseError::Integrity)?;
        if reservation.state != State::Building {
            return Err(DatabaseError::Conflict.into());
        }
        remove_hold(connection, &hold)?;
    }
    Ok(())
}

pub(super) fn require_no_holds(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    let exists: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        [owners(id)],
        |row| row.get(0),
    )?;
    if exists {
        return Err(DatabaseError::NotReady.into());
    }
    Ok(())
}

#[derive(Eq, PartialEq)]
struct Scan {
    digest: [u8; 32],
    requested: CatalogRetainedSourceReservation,
    needed: CatalogRetainedSourceReservation,
    held: CatalogRetainedSourceReservation,
}

fn count(
    capacity: &mut CatalogRetainedSourceReservation,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    capacity.logical_bytes = capacity
        .logical_bytes
        .checked_add(u64::from(source.sector.logical_len))
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    capacity.sources = capacity
        .sources
        .checked_add(1)
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    capacity.validate()
}

fn scan<I: Iterator<Item = Result<CatalogSectorRecord, CatalogStoreError>>>(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    sources: I,
    configured: bool,
    mut visit: impl FnMut(&CatalogSectorRecord, bool) -> Result<(), CatalogStoreError>,
) -> Result<Scan, CatalogStoreError> {
    let mut hash = blake3::Hasher::new_derive_key("mutualbackup retained source admission v1");
    let mut result = Scan {
        digest: [0; 32],
        requested: Default::default(),
        needed: Default::default(),
        held: Default::default(),
    };
    let mut previous = None;
    for source in sources {
        let source = source?;
        source.validate()?;
        if previous.is_some_and(|previous| previous >= source.sector.id) {
            return Err(DatabaseError::Conflict.into());
        }
        previous = Some(source.sector.id);
        count(&mut result.requested, &source)?;
        if result.requested.sources > mb_core::CATALOG_MAX_RECORDS {
            return Err(CatalogError::Bounds.into());
        }
        hash.update(&mb_core::canonical_bytes_bounded(&source, RECORD_BYTES)?);
        let shared = configured && charge(connection, scope, &source)?.is_some();
        if !shared {
            count(&mut result.needed, &source)?
        }
        if own_hold(connection, id, scope, &source)?.is_some() {
            count(&mut result.held, &source)?
        }
        visit(&source, shared)?;
    }
    result.digest = *hash.finalize().as_bytes();
    Ok(result)
}

impl ControlStore {
    /// Reserve only new authenticated identities, holding shared identities and
    /// native anchor pins in the caller's existing writer. The sorted, unique
    /// iterator factory must be repeatable and perform no external I/O. Propagate
    /// any error to roll back the entire writer, including the owner journal.
    /// Stores without a configured quota retain their existing admission policy.
    pub fn reserve_catalog_retained_sources_with_dependencies_in_transaction<F, I>(
        &self,
        id: Uuid,
        scope: CatalogScope,
        mut sources: F,
    ) -> Result<(), CatalogStoreError>
    where
        F: FnMut() -> I,
        I: Iterator<Item = Result<CatalogSectorRecord, CatalogStoreError>>,
    {
        if self.connection.is_autocommit() || id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        dataset_key(scope)?;
        let quota = policy(&self.connection)?;
        // Enforce the operation limit before walking a potentially large input.
        if let Some(quota) = quota
            && reservation(&self.connection, id, scope)?.is_none()
            && usage(&self.connection, scope, quota)?.open_reservations >= quota.open_reservations
        {
            return Err(CatalogStoreError::RetainedSourceQuotaExceeded);
        }
        let first = scan(
            &self.connection,
            id,
            scope,
            sources(),
            quota.is_some(),
            |_, _| Ok(()),
        )?;
        let Some(quota) = quota else { return Ok(()) };
        let existing = reservation(&self.connection, id, scope)?;
        if let Some(bytes) = bounded_record(&self.connection, PLAN, id.as_bytes(), RECORD_BYTES)? {
            let plan: Plan = decode(&bytes)?;
            if plan.version != 1
                || plan.id != id
                || plan.scope != scope
                || plan.digest != first.digest
                || plan.requested != first.requested
                || plan.held != first.held
            {
                return Err(DatabaseError::Conflict.into());
            }
            check_remaining(
                existing.ok_or(DatabaseError::Integrity)?,
                usage(&self.connection, scope, quota)?,
            )?;
            return Ok(());
        }
        // Resume pre-existing conservative reservations without changing their
        // immutable loans. Their newly authenticated shared inputs acquire the
        // same durable dependency holds as a new incremental reservation.
        let conservative = existing.is_some();
        if let Some(existing) = existing {
            check_remaining(existing, usage(&self.connection, scope, quota)?)?;
            if existing.original.logical_bytes < first.requested.logical_bytes
                || existing.original.sources < first.requested.sources
            {
                return Err(DatabaseError::Conflict.into());
            }
        } else {
            self.reserve_catalog_retained_sources_in_transaction(id, scope, first.needed)?;
        }
        if first.held != CatalogRetainedSourceReservation::default() {
            return Err(DatabaseError::Integrity.into());
        }
        let mut held = CatalogRetainedSourceReservation::default();
        let second = scan(
            &self.connection,
            id,
            scope,
            sources(),
            true,
            |source, shared| {
                if shared {
                    add_hold(&self.connection, id, scope, source)?;
                    count(&mut held, source)?
                }
                Ok(())
            },
        )?;
        if second != first {
            return Err(DatabaseError::Conflict.into());
        }
        let plan = Plan {
            version: 1,
            id,
            scope,
            digest: first.digest,
            requested: first.requested,
            held,
            conservative,
        };
        insert_exact(
            &self.connection,
            PLAN,
            id.as_bytes(),
            &mb_core::canonical_bytes_bounded(&plan, RECORD_BYTES)?,
        )?;
        if decode::<Plan>(
            &bounded_record(&self.connection, PLAN, id.as_bytes(), RECORD_BYTES)?
                .ok_or(DatabaseError::Integrity)?,
        )? != plan
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }

    /// Release one dependency hold after durable cancellation, even if the
    /// operation never published a bundle. Shared storage remains charged until
    /// its final binding/hold is actually removed.
    pub fn release_catalog_retained_source_dependency(
        &self,
        id: Uuid,
        scope: CatalogScope,
    ) -> Result<bool, CatalogStoreError> {
        if id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        dataset_key(scope)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some((bundle, state)) = bundle::bundle_snapshot(&tx, id)?
            && (bundle.scope != scope || state != CatalogBundleState::Cancelled)
        {
            return Err(DatabaseError::Conflict.into());
        }
        let key: Option<Option<Vec<u8>>> = tx.query_row(
            "SELECT CASE WHEN length(record_id) = 32 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
            [owners(id)], |row| row.get(0),
        ).optional()?;
        let Some(key) = key else {
            tx.commit()?;
            return Ok(false);
        };
        let key = key.ok_or(DatabaseError::Integrity)?;
        let source: [u8; 32] = key.try_into().map_err(|_| DatabaseError::Integrity)?;
        let reservation = reservation(&tx, id, scope)?.ok_or(DatabaseError::Integrity)?;
        if reservation.state != State::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let hold = checked_hold(&tx, &hold_key(scope, source, id)?)?;
        remove_hold(&tx, &hold)?;
        tx.commit()?;
        Ok(true)
    }
}
