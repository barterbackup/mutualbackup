//! Initial accounting of already published paged ownership. All source facts
//! and physical pins remain unchanged; the policy and counters commit together.

use super::*;

#[cfg(test)]
mod tests;

pub(super) fn adopt(
    connection: &Connection,
    quota: CatalogRetainedSourceQuota,
) -> Result<(), CatalogStoreError> {
    if connection.is_autocommit() {
        return Err(DatabaseError::Conflict.into());
    }
    paged_data::for_each_retained_source(connection, |id, scope, state, source| {
        let key = dataset_key(scope)?;
        let mut usage = self::usage(connection, scope, quota)?;
        if bounded_record(connection, DATASET, &key, 1)?.is_none() {
            insert_exact(connection, LEDGER, &key, &canonical_bytes(&(1_u16, usage))?)?;
            insert_exact(connection, DATASET, &key, &[1])?;
            if self::usage(connection, scope, quota)? != usage
                || bounded_record(connection, DATASET, &key, 1)?.as_deref() != Some(&[1])
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        let reservation = Reservation {
            version: 1,
            id,
            scope,
            original: CatalogRetainedSourceReservation::default(),
            remaining: CatalogRetainedSourceReservation::default(),
            state: match state {
                CatalogBundleState::Published => State::Published,
                CatalogBundleState::Cancelled => State::Cancelled,
            },
        };
        insert_exact(
            connection,
            RESERVATION,
            id.as_bytes(),
            &canonical_bytes(&reservation)?,
        )?;
        if self::reservation(connection, id, scope)? != Some(reservation) {
            return Err(DatabaseError::Integrity.into());
        }
        let key = source_key(scope, source.sector.id)?;
        if let Some(mut charge) = charge(connection, scope, source)? {
            charge.owners = charge
                .owners
                .checked_add(1)
                .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
            replace(connection, SOURCE, &key, &charge)?;
        } else {
            usage.stored_logical_bytes = usage
                .stored_logical_bytes
                .checked_add(u64::from(source.sector.logical_len))
                .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
            usage.stored_sources = usage
                .stored_sources
                .checked_add(1)
                .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
            usage.validate(quota)?;
            let charge = Charge {
                version: 1,
                scope,
                source: source.clone(),
                owners: 1,
            };
            insert_exact(connection, SOURCE, &key, &canonical_bytes(&charge)?)?;
            if self::charge(connection, scope, source)? != Some(charge) {
                return Err(DatabaseError::Integrity.into());
            }
            write_usage(connection, usage, quota)?;
        }
        require_charge(
            connection,
            id,
            scope,
            source,
            state == CatalogBundleState::Cancelled,
        )
    })
}
