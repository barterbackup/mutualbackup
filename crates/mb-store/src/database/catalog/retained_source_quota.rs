//! Dataset-wide admission for unique retained authenticated data sources.
//! Logical source bytes exclude holes, aliases, private pages and bootstrap
//! metadata. Physical payload/coding allocation needs a separate quota.

use mb_core::{CatalogSectorRecord, V1_SECTOR_SIZE};

use super::*;

pub(super) mod admission;
mod guild;

const POLICY: &str = "catalog-retained-source-quota-v1";
const ENABLED: &str = "catalog-retained-source-quota-enabled-v1";
const LEDGER: &str = "catalog-retained-source-usage-v1";
const DATASET: &str = "catalog-retained-source-dataset-v1";
const RESERVATION: &str = "catalog-retained-source-reservation-v1";
const SOURCE: &str = "catalog-retained-source-charge-v1";
const KEY: &[u8] = b"store";

/// Local byte/source/job limits for retained revisions. Dataset and aggregate
/// guild policies are configured separately; neither authorizes a source or
/// certifies release capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogRetainedSourceQuota {
    pub logical_bytes: u64,
    pub sources: u64,
    pub open_reservations: u32,
}

impl CatalogRetainedSourceQuota {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.logical_bytes > i64::MAX as u64
            || self.sources > i64::MAX as u64
            || self.open_reservations == 0
        {
            return Err(CatalogStoreError::RetainedSourceQuotaExceeded);
        }
        Ok(())
    }
}

/// Conservative new-source credits for one immutable revision operation.
/// Identical retained sources use no credits; unused credits close atomically
/// with publication/cancellation. Changed capacities cannot replay the ID.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogRetainedSourceReservation {
    pub logical_bytes: u64,
    pub sources: u64,
}

impl CatalogRetainedSourceReservation {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.logical_bytes > i64::MAX as u64 || self.sources > i64::MAX as u64 {
            return Err(CatalogStoreError::RetainedSourceQuotaExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogRetainedSourceUsage {
    pub scope: CatalogScope,
    pub stored_logical_bytes: u64,
    pub stored_sources: u64,
    pub reserved_logical_bytes: u64,
    pub reserved_sources: u64,
    pub open_reservations: u32,
}

impl CatalogRetainedSourceUsage {
    fn empty(scope: CatalogScope) -> Self {
        Self {
            scope,
            stored_logical_bytes: 0,
            stored_sources: 0,
            reserved_logical_bytes: 0,
            reserved_sources: 0,
            open_reservations: 0,
        }
    }

    fn validate(self, quota: CatalogRetainedSourceQuota) -> Result<(), CatalogStoreError> {
        dataset_key(self.scope)?;
        self.validate_limits(quota)
    }

    fn validate_limits(self, quota: CatalogRetainedSourceQuota) -> Result<(), CatalogStoreError> {
        quota.validate()?;
        if self
            .stored_logical_bytes
            .checked_add(self.reserved_logical_bytes)
            .is_none_or(|bytes| bytes > quota.logical_bytes)
            || self
                .stored_sources
                .checked_add(self.reserved_sources)
                .is_none_or(|sources| sources > quota.sources)
            || self.open_reservations > quota.open_reservations
            || self.stored_logical_bytes < self.stored_sources
            || u128::from(self.stored_logical_bytes)
                > u128::from(self.stored_sources) * V1_SECTOR_SIZE as u128
            || self.open_reservations == 0
                && (self.reserved_logical_bytes != 0 || self.reserved_sources != 0)
        {
            return Err(CatalogStoreError::RetainedSourceQuotaExceeded);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum State {
    Building,
    Published,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Reservation {
    version: u16,
    id: Uuid,
    scope: CatalogScope,
    original: CatalogRetainedSourceReservation,
    remaining: CatalogRetainedSourceReservation,
    state: State,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Charge {
    version: u16,
    scope: CatalogScope,
    source: CatalogSectorRecord,
    owners: u64,
}

fn dataset_key(scope: CatalogScope) -> Result<[u8; 32], CatalogStoreError> {
    if !matches!(scope, CatalogScope::Dataset { .. }) {
        return Err(DatabaseError::Conflict.into());
    }
    scope.validate(CatalogSection::SectorReferences)?;
    let bytes = canonical_bytes(&scope)?;
    let mut hash = blake3::Hasher::new_derive_key("mutualbackup retained source dataset v1");
    hash.update(&bytes);
    Ok(*hash.finalize().as_bytes())
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let record = decode_canonical(bytes)?;
    if mb_core::canonical_bytes_bounded(&record, RECORD_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(record)
}

fn policy(
    connection: &Connection,
) -> Result<Option<CatalogRetainedSourceQuota>, CatalogStoreError> {
    let enabled = bounded_record(connection, ENABLED, KEY, 1)?;
    let bytes = bounded_record(connection, POLICY, KEY, RECORD_BYTES)?;
    match (enabled.as_deref(), bytes) {
        (None, None) => {
            if guild::policy(connection)?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
            let existing: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1, ?2, ?3, ?4, ?5, ?6)
                 OR kind GLOB 'catalog-retained-source-hold-owner-v1/*')",
                params![LEDGER, DATASET, RESERVATION, SOURCE, admission::PLAN, admission::HOLD],
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
            guild::policy(connection)?;
            Ok(Some(quota))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn usage(
    connection: &Connection,
    scope: CatalogScope,
    quota: CatalogRetainedSourceQuota,
) -> Result<CatalogRetainedSourceUsage, CatalogStoreError> {
    let key = dataset_key(scope)?;
    let enabled = bounded_record(connection, DATASET, &key, 1)?;
    let result = match (
        enabled.as_deref(),
        bounded_record(connection, LEDGER, &key, RECORD_BYTES)?,
    ) {
        (None, None) => CatalogRetainedSourceUsage::empty(scope),
        (Some([1]), Some(bytes)) => {
            let (version, usage): (u16, CatalogRetainedSourceUsage) = decode(&bytes)?;
            if version != 1 || usage.scope != scope {
                return Err(DatabaseError::Integrity.into());
            }
            usage
        }
        _ => return Err(DatabaseError::Integrity.into()),
    };
    result.validate(quota)?;
    guild::require_dataset_usage(connection, result, enabled.is_some())?;
    Ok(result)
}

fn replace<T: Serialize>(
    connection: &Connection,
    kind: &str,
    key: &[u8],
    value: &T,
) -> Result<(), CatalogStoreError> {
    let bytes = mb_core::canonical_bytes_bounded(value, RECORD_BYTES)?;
    if connection.execute(
        "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
        params![kind, key, bytes],
    )? != 1
        || bounded_record(connection, kind, key, RECORD_BYTES)?.as_deref() != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn write_usage(
    connection: &Connection,
    usage: CatalogRetainedSourceUsage,
    quota: CatalogRetainedSourceQuota,
) -> Result<(), CatalogStoreError> {
    usage.validate(quota)?;
    let previous = self::usage(connection, usage.scope, quota)?;
    guild::update_dataset_usage(connection, previous, usage)?;
    replace(
        connection,
        LEDGER,
        &dataset_key(usage.scope)?,
        &(1_u16, usage),
    )
}

fn reservation(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
) -> Result<Option<Reservation>, CatalogStoreError> {
    dataset_key(scope)?;
    let Some(bytes) = bounded_record(connection, RESERVATION, id.as_bytes(), RECORD_BYTES)? else {
        return Ok(None);
    };
    let record: Reservation = decode(&bytes)?;
    record.original.validate()?;
    record.remaining.validate()?;
    if record.version != 1
        || record.id != id
        || id.is_nil()
        || record.scope != scope
        || record.remaining.logical_bytes > record.original.logical_bytes
        || record.remaining.sources > record.original.sources
        || record.state != State::Building
            && record.remaining != CatalogRetainedSourceReservation::default()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

fn check_remaining(
    record: Reservation,
    usage: CatalogRetainedSourceUsage,
) -> Result<(), CatalogStoreError> {
    if record.state != State::Building
        || usage.open_reservations == 0
        || record.remaining.logical_bytes > usage.reserved_logical_bytes
        || record.remaining.sources > usage.reserved_sources
    {
        return Err(DatabaseError::NotReady.into());
    }
    Ok(())
}

fn source_key(scope: CatalogScope, sector: [u8; 32]) -> Result<[u8; 64], CatalogStoreError> {
    let mut key = [0; 64];
    key[..32].copy_from_slice(&dataset_key(scope)?);
    key[32..].copy_from_slice(&sector);
    Ok(key)
}

fn charge(
    connection: &Connection,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<Option<Charge>, CatalogStoreError> {
    let Some(bytes) = bounded_record(
        connection,
        SOURCE,
        &source_key(scope, source.sector.id)?,
        RECORD_BYTES,
    )?
    else {
        return Ok(None);
    };
    let record: Charge = decode(&bytes)?;
    if record.version != 1
        || record.scope != scope
        || record.source != *source
        || record.owners == 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    record.source.validate()?;
    Ok(Some(record))
}

/// Called with the data binding and its anchor pin in the same writer.
pub(super) fn bind(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    source.validate()?;
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    let mut usage = usage(connection, scope, quota)?;
    let mut reservation = reservation(connection, id, scope)?.ok_or(DatabaseError::NotReady)?;
    check_remaining(reservation, usage)?;
    let key = source_key(scope, source.sector.id)?;
    if let Some(mut charge) = charge(connection, scope, source)? {
        if usage.stored_sources == 0
            || usage.stored_logical_bytes < u64::from(source.sector.logical_len)
        {
            return Err(DatabaseError::Integrity.into());
        }
        charge.owners = charge
            .owners
            .checked_add(1)
            .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
        return replace(connection, SOURCE, &key, &charge);
    }
    let bytes = u64::from(source.sector.logical_len);
    reservation.remaining.logical_bytes = reservation
        .remaining
        .logical_bytes
        .checked_sub(bytes)
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    reservation.remaining.sources = reservation
        .remaining
        .sources
        .checked_sub(1)
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    usage.reserved_logical_bytes -= bytes;
    usage.reserved_sources -= 1;
    usage.stored_logical_bytes = usage
        .stored_logical_bytes
        .checked_add(bytes)
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    usage.stored_sources = usage
        .stored_sources
        .checked_add(1)
        .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
    let charge = Charge {
        version: 1,
        scope,
        source: source.clone(),
        owners: 1,
    };
    insert_exact(
        connection,
        SOURCE,
        &key,
        &mb_core::canonical_bytes_bounded(&charge, RECORD_BYTES)?,
    )?;
    if self::charge(connection, scope, source)? != Some(charge) {
        return Err(DatabaseError::Integrity.into());
    }
    replace(connection, RESERVATION, id.as_bytes(), &reservation)?;
    write_usage(connection, usage, quota)
}

pub(super) fn require_charge(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
    cancelled: bool,
) -> Result<(), CatalogStoreError> {
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    let usage = usage(connection, scope, quota)?;
    let reservation = reservation(connection, id, scope)?.ok_or(DatabaseError::Integrity)?;
    if reservation.state
        != (if cancelled {
            State::Cancelled
        } else {
            State::Published
        })
        || usage.stored_sources == 0
        || usage.stored_logical_bytes < u64::from(source.sector.logical_len)
        || charge(connection, scope, source)?.is_none()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn require_binding(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    let usage = usage(connection, scope, quota)?;
    let reservation = reservation(connection, id, scope)?.ok_or(DatabaseError::Integrity)?;
    if reservation.state == State::Cancelled
        || usage.stored_sources == 0
        || usage.stored_logical_bytes < u64::from(source.sector.logical_len)
        || charge(connection, scope, source)?.is_none()
    {
        return Err(DatabaseError::Integrity.into());
    }
    if reservation.state == State::Building {
        check_remaining(reservation, usage)?;
    }
    Ok(())
}

pub(super) fn release(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    require_charge(connection, id, scope, source, true)?;
    release_owner(connection, scope, source, quota)
}

fn release_owner(
    connection: &Connection,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
    quota: CatalogRetainedSourceQuota,
) -> Result<(), CatalogStoreError> {
    let mut usage = usage(connection, scope, quota)?;
    let mut charge = charge(connection, scope, source)?.ok_or(DatabaseError::Integrity)?;
    if usage.stored_sources == 0
        || usage.stored_logical_bytes < u64::from(source.sector.logical_len)
    {
        return Err(DatabaseError::Integrity.into());
    }
    let key = source_key(scope, source.sector.id)?;
    if charge.owners > 1 {
        charge.owners -= 1;
        return replace(connection, SOURCE, &key, &charge);
    }
    if connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
        params![SOURCE, key.as_slice()],
    )? != 1
        || bounded_record(connection, SOURCE, &key, RECORD_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    usage.stored_logical_bytes = usage
        .stored_logical_bytes
        .checked_sub(u64::from(source.sector.logical_len))
        .ok_or(DatabaseError::Integrity)?;
    usage.stored_sources = usage
        .stored_sources
        .checked_sub(1)
        .ok_or(DatabaseError::Integrity)?;
    write_usage(connection, usage, quota)
}

pub(super) fn close(
    connection: &Connection,
    id: Uuid,
    scope: CatalogScope,
    cancelled: bool,
) -> Result<(), CatalogStoreError> {
    if !cancelled {
        admission::require_no_holds(connection, id)?;
    }
    let Some(quota) = policy(connection)? else {
        return Ok(());
    };
    let Some(mut record) = reservation(connection, id, scope)? else {
        if cancelled {
            let record = Reservation {
                version: 1,
                id,
                scope,
                original: CatalogRetainedSourceReservation::default(),
                remaining: CatalogRetainedSourceReservation::default(),
                state: State::Cancelled,
            };
            insert_exact(
                connection,
                RESERVATION,
                id.as_bytes(),
                &canonical_bytes(&record)?,
            )?;
            if reservation(connection, id, scope)? != Some(record) {
                return Err(DatabaseError::Integrity.into());
            }
        }
        return Ok(());
    };
    let next = if cancelled {
        State::Cancelled
    } else {
        State::Published
    };
    if record.state == State::Cancelled && !cancelled {
        return Err(DatabaseError::Conflict.into());
    }
    let mut usage = usage(connection, scope, quota)?;
    if record.state == State::Building {
        check_remaining(record, usage)?;
        usage.reserved_logical_bytes -= record.remaining.logical_bytes;
        usage.reserved_sources -= record.remaining.sources;
        usage.open_reservations -= 1;
        write_usage(connection, usage, quota)?;
    }
    record.remaining = CatalogRetainedSourceReservation::default();
    record.state = next;
    replace(connection, RESERVATION, id.as_bytes(), &record)
}

impl ControlStore {
    /// Enable only before any paged data binding exists. Existing flat data is
    /// charged by explicit authenticated migration, not this configuration.
    /// Grow-only resizing preserves every dataset's outstanding reservations
    /// without a catalog/history scan. Rebuilding existing paged usage remains
    /// a separate bounded adoption gate.
    pub fn configure_catalog_retained_source_quota(
        &self,
        quota: CatalogRetainedSourceQuota,
    ) -> Result<(), CatalogStoreError> {
        quota.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some(previous) = policy(&tx)? {
            if quota.logical_bytes < previous.logical_bytes
                || quota.sources < previous.sources
                || quota.open_reservations < previous.open_reservations
            {
                return Err(CatalogStoreError::RetainedSourceQuotaExceeded);
            }
            replace(&tx, POLICY, KEY, &(1_u16, quota))?;
        } else {
            let existing: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE
                kind GLOB 'catalog-paged-data-source-v1/*'
                OR kind GLOB 'catalog-retained-source-hold-owner-v1/*'
                OR kind IN (?1, ?2, ?3, ?4, ?5, ?6))",
                params![
                    LEDGER,
                    RESERVATION,
                    SOURCE,
                    DATASET,
                    admission::PLAN,
                    admission::HOLD
                ],
                |row| row.get(0),
            )?;
            if existing {
                return Err(DatabaseError::NotReady.into());
            }
            insert_exact(&tx, POLICY, KEY, &canonical_bytes(&(1_u16, quota))?)?;
            insert_exact(&tx, ENABLED, KEY, &[1])?;
            if policy(&tx)? != Some(quota) {
                return Err(DatabaseError::Integrity.into());
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn catalog_retained_source_usage(
        &self,
        scope: CatalogScope,
    ) -> Result<Option<CatalogRetainedSourceUsage>, CatalogStoreError> {
        dataset_key(scope)?;
        let snapshot = self.read_snapshot()?;
        let usage = policy(&snapshot)?
            .map(|quota| usage(&snapshot, scope, quota))
            .transpose()?;
        snapshot.commit()?;
        Ok(usage)
    }

    /// Compose admission with page reservations and an immutable owner journal
    /// in the caller's existing writer transaction. No nested transaction or
    /// external I/O is allowed. An error must propagate to roll back the writer.
    /// Unconfigured stores preserve their existing behavior.
    pub fn reserve_catalog_retained_sources_in_transaction(
        &self,
        id: Uuid,
        scope: CatalogScope,
        capacity: CatalogRetainedSourceReservation,
    ) -> Result<(), CatalogStoreError> {
        if self.connection.is_autocommit() || id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        capacity.validate()?;
        let key = dataset_key(scope)?;
        let Some(quota) = policy(&self.connection)? else {
            return Ok(());
        };
        let mut usage = usage(&self.connection, scope, quota)?;
        if let Some(existing) = reservation(&self.connection, id, scope)? {
            if existing.original != capacity {
                return Err(DatabaseError::Conflict.into());
            }
            check_remaining(existing, usage)?;
            return Ok(());
        }
        if bundle::bundle_snapshot(&self.connection, id)?.is_some() {
            return Err(DatabaseError::Conflict.into());
        }
        guild::ensure_ledger(&self.connection, scope)?;
        insert_exact(
            &self.connection,
            LEDGER,
            &key,
            &canonical_bytes(&(1_u16, usage))?,
        )?;
        insert_exact(&self.connection, DATASET, &key, &[1])?;
        if self::usage(&self.connection, scope, quota)? != usage {
            return Err(DatabaseError::Integrity.into());
        }
        usage.reserved_logical_bytes = usage
            .reserved_logical_bytes
            .checked_add(capacity.logical_bytes)
            .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
        usage.reserved_sources = usage
            .reserved_sources
            .checked_add(capacity.sources)
            .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
        usage.open_reservations = usage
            .open_reservations
            .checked_add(1)
            .ok_or(CatalogStoreError::RetainedSourceQuotaExceeded)?;
        write_usage(&self.connection, usage, quota)?;
        let record = Reservation {
            version: 1,
            id,
            scope,
            original: capacity,
            remaining: capacity,
            state: State::Building,
        };
        insert_exact(
            &self.connection,
            RESERVATION,
            id.as_bytes(),
            &canonical_bytes(&record)?,
        )?;
        if reservation(&self.connection, id, scope)? != Some(record) {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }

    /// Fence an admitted but unpublished operation after the caller's durable
    /// owner cancellation. Published bundles must be cancelled first; shared
    /// sources remain charged until their existing bounded binding cleanup.
    pub fn cancel_catalog_retained_source_reservation(
        &self,
        id: Uuid,
        scope: CatalogScope,
    ) -> Result<(), CatalogStoreError> {
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
        close(&tx, id, scope, true)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{NodeId, SectorRef, merkle_commit, sector_root};
    use std::sync::{Arc, Barrier};

    fn scope(marker: u8) -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([marker; 16]),
        }
    }
    fn id(marker: u8) -> Uuid {
        Uuid::from_bytes([marker; 16])
    }
    fn capacity(bytes: u64, sources: u64) -> CatalogRetainedSourceReservation {
        CatalogRetainedSourceReservation {
            logical_bytes: bytes,
            sources,
        }
    }
    fn source(marker: u8, len: u32) -> CatalogSectorRecord {
        let bytes = vec![marker; V1_SECTOR_SIZE];
        CatalogSectorRecord {
            format_version: 1,
            sector: SectorRef {
                id: [marker; 32],
                root: sector_root(&bytes),
                logical_len: len,
            },
            commitment: merkle_commit(&bytes).unwrap(),
        }
    }
    fn reserve(
        store: &ControlStore,
        marker: u8,
        scope: CatalogScope,
        capacity: CatalogRetainedSourceReservation,
    ) -> Result<(), CatalogStoreError> {
        store.with_record_transaction(|| {
            store.reserve_catalog_retained_sources_in_transaction(id(marker), scope, capacity)
        })
    }
    fn publish(
        store: &ControlStore,
        marker: u8,
        scope: CatalogScope,
        source: &CatalogSectorRecord,
    ) -> Result<(), CatalogStoreError> {
        store.with_record_transaction(|| {
            bind(&store.connection, id(marker), scope, source)?;
            close(&store.connection, id(marker), scope, false)
        })
    }
    fn remove(
        store: &ControlStore,
        marker: u8,
        scope: CatalogScope,
        source: &CatalogSectorRecord,
    ) -> Result<(), CatalogStoreError> {
        store.with_record_transaction(|| {
            close(&store.connection, id(marker), scope, true)?;
            release(&store.connection, id(marker), scope, source)
        })
    }
    fn quota(bytes: u64, sources: u64) -> CatalogRetainedSourceQuota {
        CatalogRetainedSourceQuota {
            logical_bytes: bytes,
            sources,
            open_reservations: 2,
        }
    }

    #[test]
    fn retained_sources_are_shared_per_dataset_until_last_owner_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[84; 32]).unwrap();
        store
            .configure_catalog_retained_source_quota(quota(200, 2))
            .unwrap();
        let source = source(7, 100);
        let empty = store
            .catalog_retained_source_usage(scope(3))
            .unwrap()
            .unwrap();
        reserve(&store, 4, scope(3), capacity(100, 1)).unwrap();
        publish(&store, 4, scope(3), &source).unwrap();
        let used = store
            .catalog_retained_source_usage(scope(3))
            .unwrap()
            .unwrap();
        assert_eq!(used.stored_logical_bytes, 100);
        assert_eq!(used.stored_sources, 1);
        assert_eq!(used.open_reservations, 0);
        reserve(&store, 5, scope(3), capacity(100, 1)).unwrap();
        publish(&store, 5, scope(3), &source).unwrap();
        assert_eq!(
            store.catalog_retained_source_usage(scope(3)).unwrap(),
            Some(used)
        );
        // Zero new-storage credits can share exact already retained sources.
        reserve(&store, 6, scope(3), capacity(0, 0)).unwrap();
        publish(&store, 6, scope(3), &source).unwrap();
        assert_eq!(
            store.catalog_retained_source_usage(scope(3)).unwrap(),
            Some(used)
        );
        // The same identity in a separate protected root is independently billed.
        reserve(&store, 8, scope(9), capacity(100, 1)).unwrap();
        publish(&store, 8, scope(9), &source).unwrap();
        assert_eq!(
            store
                .catalog_retained_source_usage(scope(9))
                .unwrap()
                .unwrap()
                .stored_logical_bytes,
            100
        );
        assert!(reserve(&store, 5, scope(3), capacity(100, 1)).is_err());
        drop(store);
        let store = ControlStore::open_with_key(&path, &[84; 32]).unwrap();
        for marker in [4, 5] {
            remove(&store, marker, scope(3), &source).unwrap();
            assert_eq!(
                store.catalog_retained_source_usage(scope(3)).unwrap(),
                Some(used)
            );
        }
        remove(&store, 6, scope(3), &source).unwrap();
        assert_eq!(
            store.catalog_retained_source_usage(scope(3)).unwrap(),
            Some(empty)
        );
        require_charge(&store.connection, id(8), scope(9), &source, false).unwrap();
        let ro = ControlStore::open_existing_read_only_with_key(&path, &[84; 32]).unwrap();
        assert_eq!(
            ro.catalog_retained_source_usage(scope(3)).unwrap(),
            Some(empty)
        );
        assert!(
            ro.configure_catalog_retained_source_quota(quota(300, 3))
                .is_err()
        );
    }

    #[test]
    fn retained_source_capacity_is_atomic_across_connections_and_dimensions() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[85; 32]).unwrap();
        store
            .configure_catalog_retained_source_quota(quota(100, 1))
            .unwrap();
        let gate = Arc::new(Barrier::new(3));
        let threads = [4, 5].map(|marker| {
            let path = path.clone();
            let gate = Arc::clone(&gate);
            std::thread::spawn(move || {
                let store = ControlStore::open_with_key(path, &[85; 32]).unwrap();
                gate.wait();
                (
                    marker,
                    reserve(&store, marker, scope(3), capacity(100, 1)).is_ok(),
                )
            })
        });
        gate.wait();
        let attempts = threads.map(|thread| thread.join().unwrap());
        assert_eq!(attempts.iter().filter(|(_, passed)| *passed).count(), 1);
        let winner = attempts.into_iter().find(|(_, passed)| *passed).unwrap().0;
        let reserved = store
            .catalog_retained_source_usage(scope(3))
            .unwrap()
            .unwrap();
        assert_eq!(reserved.reserved_logical_bytes, 100);
        assert_eq!(reserved.reserved_sources, 1);
        reserve(&store, winner, scope(3), capacity(100, 1)).unwrap();
        assert!(reserve(&store, winner, scope(3), capacity(99, 1)).is_err());
        assert_eq!(
            store.catalog_retained_source_usage(scope(3)).unwrap(),
            Some(reserved)
        );
        store
            .cancel_catalog_retained_source_reservation(id(winner), scope(3))
            .unwrap();
        for request in [capacity(101, 0), capacity(0, 2), capacity(u64::MAX, 1)] {
            assert!(reserve(&store, 6, scope(3), request).is_err());
        }
        assert_eq!(
            store
                .catalog_retained_source_usage(scope(3))
                .unwrap()
                .unwrap()
                .open_reservations,
            0
        );
        assert!(reserve(&store, winner, scope(3), capacity(100, 1)).is_err());
        store
            .cancel_catalog_retained_source_reservation(id(7), scope(3))
            .unwrap();
        store
            .cancel_catalog_retained_source_reservation(id(7), scope(3))
            .unwrap();
        assert!(reserve(&store, 7, scope(3), capacity(0, 0)).is_err());
        assert!(
            store
                .configure_catalog_retained_source_quota(quota(99, 1))
                .is_err()
        );
        store
            .configure_catalog_retained_source_quota(quota(200, 2))
            .unwrap();
        reserve(&store, 8, scope(3), capacity(200, 2)).unwrap();
        assert!(
            store
                .reserve_catalog_retained_sources_in_transaction(id(9), scope(3), capacity(0, 0))
                .is_err()
        );
        assert!(
            reserve(
                &store,
                9,
                CatalogScope::Guild { guild_id: [1; 32] },
                capacity(0, 0)
            )
            .is_err()
        );
        assert!(reserve(&store, 0, scope(3), capacity(0, 0)).is_err());
    }

    #[test]
    fn retained_source_faults_roll_back_credits_charges_and_owner_journals() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[86; 32]).unwrap();
        store
            .configure_catalog_retained_source_quota(quota(200, 2))
            .unwrap();
        let empty = store.catalog_retained_source_usage(scope(3)).unwrap();
        for kind in [LEDGER, DATASET, RESERVATION] {
            store.connection.execute_batch(&format!(
                "CREATE TEMP TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END"
            )).unwrap();
            assert!(reserve(&store, 4, scope(3), capacity(100, 1)).is_err());
            assert_eq!(
                store.catalog_retained_source_usage(scope(3)).unwrap(),
                empty
            );
            assert!(store.records(RESERVATION).unwrap().is_empty());
            store
                .connection
                .execute_batch("DROP TRIGGER fault")
                .unwrap();
        }
        let denied: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
            store.reserve_catalog_retained_sources_in_transaction(
                id(4),
                scope(3),
                capacity(100, 1),
            )?;
            store.put_record("owner", b"id", b"immutable journal")?;
            Err(DatabaseError::Conflict.into())
        });
        assert!(denied.is_err());
        assert_eq!(
            store.catalog_retained_source_usage(scope(3)).unwrap(),
            empty
        );
        assert!(store.get_record("owner", b"id").unwrap().is_none());
        reserve(&store, 4, scope(3), capacity(100, 1)).unwrap();
        let pending = store.catalog_retained_source_usage(scope(3)).unwrap();
        let source = source(7, 100);
        for (kind, action) in [
            (SOURCE, "INSERT"),
            (RESERVATION, "UPDATE"),
            (LEDGER, "UPDATE"),
        ] {
            store.connection.execute_batch(&format!(
                "CREATE TEMP TRIGGER fault BEFORE {action} ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END"
            )).unwrap();
            assert!(publish(&store, 4, scope(3), &source).is_err());
            assert_eq!(
                store.catalog_retained_source_usage(scope(3)).unwrap(),
                pending
            );
            assert!(store.records(SOURCE).unwrap().is_empty());
            store
                .connection
                .execute_batch("DROP TRIGGER fault")
                .unwrap();
        }
        publish(&store, 4, scope(3), &source).unwrap();
        let used = store.catalog_retained_source_usage(scope(3)).unwrap();
        store.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER fault AFTER DELETE ON protocol_records WHEN OLD.kind = '{SOURCE}' BEGIN INSERT INTO protocol_records(kind, record_id, bytes) VALUES(OLD.kind, OLD.record_id, OLD.bytes); END"
        )).unwrap();
        assert!(remove(&store, 4, scope(3), &source).is_err());
        assert_eq!(store.catalog_retained_source_usage(scope(3)).unwrap(), used);
        require_charge(&store.connection, id(4), scope(3), &source, false).unwrap();
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
        remove(&store, 4, scope(3), &source).unwrap();
        assert_eq!(
            store.catalog_retained_source_usage(scope(3)).unwrap(),
            empty
        );
    }

    #[test]
    fn retained_source_policy_and_missing_corrupt_usage_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[87; 32]).unwrap();
        // Existing paged bindings cannot be silently adopted as zero usage.
        store
            .put_record("catalog-paged-data-source-v1/existing", &[7; 32], b"old")
            .unwrap();
        assert!(
            store
                .configure_catalog_retained_source_quota(quota(100, 1))
                .is_err()
        );
        assert!(store.get_record(POLICY, KEY).unwrap().is_none());
        store
            .delete_record("catalog-paged-data-source-v1/existing", &[7; 32])
            .unwrap();
        let one_tib = CatalogRetainedSourceQuota {
            logical_bytes: 1_u64 << 40,
            sources: mb_core::CATALOG_MAX_RECORDS,
            open_reservations: 8,
        };
        store
            .configure_catalog_retained_source_quota(one_tib)
            .unwrap();
        reserve(&store, 4, scope(3), capacity(1_u64 << 40, 16_777_216)).unwrap();
        assert!(reserve(&store, 5, scope(3), capacity(1, 0)).is_err());
        store
            .cancel_catalog_retained_source_reservation(id(4), scope(3))
            .unwrap();
        reserve(&store, 5, scope(3), capacity(100, 1)).unwrap();
        publish(&store, 5, scope(3), &source(7, 100)).unwrap();
        for (kind, key) in [
            (POLICY, KEY.to_vec()),
            (ENABLED, KEY.to_vec()),
            (LEDGER, dataset_key(scope(3)).unwrap().to_vec()),
            (DATASET, dataset_key(scope(3)).unwrap().to_vec()),
        ] {
            let original = store.get_record(kind, &key).unwrap().unwrap();
            store.delete_record(kind, &key).unwrap();
            assert!(store.catalog_retained_source_usage(scope(3)).is_err());
            assert!(reserve(&store, 6, scope(3), capacity(0, 0)).is_err());
            store.put_record(kind, &key, &original).unwrap();
            store.put_record(kind, &key, b"invalid").unwrap();
            assert!(store.catalog_retained_source_usage(scope(3)).is_err());
            store.put_record(kind, &key, &original).unwrap();
        }
        for (kind, key) in [
            (RESERVATION, id(5).as_bytes().to_vec()),
            (SOURCE, source_key(scope(3), [7; 32]).unwrap().to_vec()),
        ] {
            let original = store.get_record(kind, &key).unwrap().unwrap();
            store.delete_record(kind, &key).unwrap();
            assert!(
                require_charge(&store.connection, id(5), scope(3), &source(7, 100), false).is_err()
            );
            store.put_record(kind, &key, &original).unwrap();
        }
        let original_policy = store.get_record(POLICY, KEY).unwrap().unwrap();
        store.delete_record(POLICY, KEY).unwrap();
        store.delete_record(ENABLED, KEY).unwrap();
        assert!(store.catalog_retained_source_usage(scope(3)).is_err());
        assert!(reserve(&store, 6, scope(3), capacity(0, 0)).is_err());
        assert!(
            store
                .configure_catalog_retained_source_quota(one_tib)
                .is_err()
        );
        assert!(
            require_charge(&store.connection, id(5), scope(3), &source(7, 100), false).is_err()
        );
        store.put_record(POLICY, KEY, &original_policy).unwrap();
        store.put_record(ENABLED, KEY, &[1]).unwrap();
    }
}
