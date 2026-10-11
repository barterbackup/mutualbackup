//! Durable reservations for encoded immutable page storage. These counters
//! exclude SQL/WAL overhead, source payloads and traversal work; the enclosing
//! production policy must reserve those resources separately.

use super::*;

mod scoped;

const QUOTA: &str = "catalog-storage-quota-v1";
const ENABLED: &str = "catalog-storage-quota-enabled-v1";
const RESERVATION: &str = "catalog-page-reservation-v1";
const KEY: &[u8] = b"store";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogStorageQuota {
    pub page_bytes: u64,
    pub pages: u64,
    pub open_reservations: u32,
}

impl CatalogStorageQuota {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.page_bytes > i64::MAX as u64
            || self.pages > i64::MAX as u64
            || self.open_reservations == 0
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }
}

/// Maximum new encoded bytes/pages for one immutable intent. Existing shared
/// pages do not consume credits. The original reservation cannot be changed
/// on replay; unused credits close with publication or cancellation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPageReservation {
    pub page_bytes: u64,
    pub pages: u64,
}

impl CatalogPageReservation {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.page_bytes > i64::MAX as u64 || self.pages > i64::MAX as u64 {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogStorageUsage {
    pub quota: CatalogStorageQuota,
    pub stored_page_bytes: u64,
    pub stored_pages: u64,
    pub reserved_page_bytes: u64,
    pub reserved_pages: u64,
    pub open_reservations: u32,
}

impl CatalogStorageUsage {
    fn validate(self) -> Result<(), CatalogStoreError> {
        self.quota.validate()?;
        let bytes = self.stored_page_bytes.checked_add(self.reserved_page_bytes);
        let pages = self.stored_pages.checked_add(self.reserved_pages);
        if bytes.is_none_or(|value| value > self.quota.page_bytes)
            || pages.is_none_or(|value| value > self.quota.pages)
            || self.open_reservations > self.quota.open_reservations
            || self.stored_page_bytes < self.stored_pages
            || u128::from(self.stored_page_bytes)
                > u128::from(self.stored_pages) * CATALOG_PAGE_BYTES as u128
            || self.open_reservations == 0
                && (self.reserved_page_bytes != 0 || self.reserved_pages != 0)
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Ledger {
    version: u8,
    usage: CatalogStorageUsage,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Reservation {
    version: u8,
    intent: CatalogIntent,
    original: CatalogPageReservation,
    remaining: CatalogPageReservation,
    closed: bool,
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value = decode_canonical(bytes)?;
    if mb_core::canonical_bytes_bounded(&value, RECORD_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

fn ledger(connection: &Connection) -> Result<Option<Ledger>, CatalogStoreError> {
    let enabled = bounded_record(connection, ENABLED, KEY, 1)?;
    let bytes = bounded_record(connection, QUOTA, KEY, RECORD_BYTES)?;
    scoped::require_global_policy(connection, enabled.is_some() || bytes.is_some())?;
    match (enabled.as_deref(), bytes) {
        (None, None) => Ok(None),
        (Some([1]), Some(bytes)) => {
            let ledger: Ledger = decode(&bytes)?;
            if ledger.version != 1 {
                return Err(DatabaseError::Integrity.into());
            }
            ledger.usage.validate()?;
            Ok(Some(ledger))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn reservation(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<Option<Reservation>, CatalogStoreError> {
    let Some(bytes) = bounded_record(connection, RESERVATION, intent.id.as_bytes(), RECORD_BYTES)?
    else {
        return Ok(None);
    };
    let record: Reservation = decode(&bytes)?;
    record.original.validate()?;
    record.remaining.validate()?;
    if record.version != 1
        || record.intent != intent
        || intent.id.is_nil()
        || record.remaining.page_bytes > record.original.page_bytes
        || record.remaining.pages > record.original.pages
        || record.closed && record.remaining != CatalogPageReservation::default()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
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
        params![kind, key, &bytes],
    )? != 1
        || bounded_record(connection, kind, key, RECORD_BYTES)?.as_deref() != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn write_ledger(connection: &Connection, record: Ledger) -> Result<(), CatalogStoreError> {
    record.usage.validate()?;
    replace(connection, QUOTA, KEY, &record)
}

pub(super) fn require_reservation(
    connection: &Connection,
    intent: CatalogIntent,
    state: CatalogIntentState,
) -> Result<(), CatalogStoreError> {
    scoped::require_reservation(connection, intent)?;
    let record = reservation(connection, intent)?;
    match (ledger(connection)?, record, state) {
        (None, None, _) => Ok(()),
        (Some(ledger), Some(record), CatalogIntentState::Building)
            if !record.closed
                && ledger.usage.open_reservations != 0
                && record.remaining.page_bytes <= ledger.usage.reserved_page_bytes
                && record.remaining.pages <= ledger.usage.reserved_pages =>
        {
            Ok(())
        }
        (Some(_), None, CatalogIntentState::Published(_)) => Ok(()),
        (Some(_), Some(record), CatalogIntentState::Published(_)) if record.closed => Ok(()),
        _ => Err(DatabaseError::NotReady.into()),
    }
}

pub(super) fn stage(
    connection: &Connection,
    intent: CatalogIntent,
    reference: CatalogPageRef,
    bytes: &[u8],
) -> Result<(), CatalogStoreError> {
    let mut record = reservation(connection, intent)?;
    let Some(mut ledger) = ledger(connection)? else {
        if record.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(());
    };
    let record = record.as_mut().ok_or(DatabaseError::NotReady)?;
    if record.closed
        || ledger.usage.open_reservations == 0
        || record.remaining.page_bytes > ledger.usage.reserved_page_bytes
        || record.remaining.pages > ledger.usage.reserved_pages
    {
        return Err(DatabaseError::Conflict.into());
    }
    scoped::stage(connection, *record, reference, bytes.len() as u64)?;
    if bounded_record(connection, PAGE, &reference.hash, CATALOG_PAGE_BYTES)?.is_some() {
        return Ok(());
    }
    let count = bytes.len() as u64;
    record.remaining.page_bytes = record
        .remaining
        .page_bytes
        .checked_sub(count)
        .ok_or(DatabaseError::CapacityExceeded)?;
    record.remaining.pages = record
        .remaining
        .pages
        .checked_sub(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    ledger.usage.reserved_page_bytes = ledger
        .usage
        .reserved_page_bytes
        .checked_sub(count)
        .ok_or(DatabaseError::Integrity)?;
    ledger.usage.reserved_pages = ledger
        .usage
        .reserved_pages
        .checked_sub(1)
        .ok_or(DatabaseError::Integrity)?;
    ledger.usage.stored_page_bytes = ledger
        .usage
        .stored_page_bytes
        .checked_add(count)
        .ok_or(DatabaseError::CapacityExceeded)?;
    ledger.usage.stored_pages = ledger
        .usage
        .stored_pages
        .checked_add(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    replace(connection, RESERVATION, intent.id.as_bytes(), record)?;
    write_ledger(connection, ledger)
}

pub(super) fn close(
    connection: &Connection,
    intent: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    scoped::close(connection, intent)?;
    let Some(mut record) = reservation(connection, intent)? else {
        return Ok(());
    };
    let mut ledger = ledger(connection)?.ok_or(DatabaseError::Integrity)?;
    if record.closed {
        return Ok(());
    }
    ledger.usage.reserved_page_bytes = ledger
        .usage
        .reserved_page_bytes
        .checked_sub(record.remaining.page_bytes)
        .ok_or(DatabaseError::Integrity)?;
    ledger.usage.reserved_pages = ledger
        .usage
        .reserved_pages
        .checked_sub(record.remaining.pages)
        .ok_or(DatabaseError::Integrity)?;
    ledger.usage.open_reservations = ledger
        .usage
        .open_reservations
        .checked_sub(1)
        .ok_or(DatabaseError::Integrity)?;
    record.closed = true;
    record.remaining = CatalogPageReservation::default();
    replace(connection, RESERVATION, intent.id.as_bytes(), &record)?;
    write_ledger(connection, ledger)
}

pub(super) fn collect(
    connection: &Connection,
    page: PageMetadata,
    page_bytes: u64,
) -> Result<(), CatalogStoreError> {
    scoped::collect(connection, page, page_bytes)?;
    let Some(mut record) = ledger(connection)? else {
        return Ok(());
    };
    record.usage.stored_page_bytes = record
        .usage
        .stored_page_bytes
        .checked_sub(page_bytes)
        .ok_or(DatabaseError::Integrity)?;
    record.usage.stored_pages = record
        .usage
        .stored_pages
        .checked_sub(1)
        .ok_or(DatabaseError::Integrity)?;
    write_ledger(connection, record)
}

fn reserve_intent(
    connection: &Connection,
    intent: CatalogIntent,
    capacity: CatalogPageReservation,
) -> Result<CatalogIntentState, CatalogStoreError> {
    capacity.validate()?;
    let state = begin_intent(connection, intent)?;
    let mut ledger = ledger(connection)?.ok_or(DatabaseError::NotReady)?;
    if let Some(existing) = reservation(connection, intent)? {
        if existing.original != capacity
            || existing.closed == (state == CatalogIntentState::Building)
        {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        if state != CatalogIntentState::Building {
            return Err(DatabaseError::Conflict.into());
        }
        ledger.usage.reserved_page_bytes = ledger
            .usage
            .reserved_page_bytes
            .checked_add(capacity.page_bytes)
            .ok_or(DatabaseError::CapacityExceeded)?;
        ledger.usage.reserved_pages = ledger
            .usage
            .reserved_pages
            .checked_add(capacity.pages)
            .ok_or(DatabaseError::CapacityExceeded)?;
        ledger.usage.open_reservations = ledger
            .usage
            .open_reservations
            .checked_add(1)
            .ok_or(DatabaseError::CapacityExceeded)?;
        ledger.usage.validate()?;
        let record = Reservation {
            version: 1,
            intent,
            original: capacity,
            remaining: capacity,
            closed: false,
        };
        insert_exact(
            connection,
            RESERVATION,
            intent.id.as_bytes(),
            &canonical_bytes(&record)?,
        )?;
        if reservation(connection, intent)? != Some(record) {
            return Err(DatabaseError::Integrity.into());
        }
        write_ledger(connection, ledger)?;
        scoped::reserve(connection, record)?;
    }
    require_reservation(connection, intent, state)?;
    Ok(state)
}

impl ControlStore {
    /// Enable or resize encoded-page quotas. Initial adoption counts existing
    /// physical page rows without loading their blobs. It supplies no source,
    /// signature, history or ownership authority. A lower limit must fit all
    /// stored pages and outstanding reservations before it is installed.
    pub fn configure_catalog_storage_quota(
        &self,
        quota: CatalogStorageQuota,
    ) -> Result<CatalogStorageUsage, CatalogStoreError> {
        quota.validate()?;
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let mut record = if let Some(record) = ledger(&transaction)? {
            record
        } else {
            let stale: bool = transaction.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
                [RESERVATION],
                |row| row.get(0),
            )?;
            if stale {
                return Err(DatabaseError::Integrity.into());
            }
            let (pages, bytes, invalid): (u64, u64, u64) = transaction.query_row(
                "SELECT count(*), coalesce(sum(length(bytes)), 0),
                 coalesce(sum(CASE WHEN length(record_id) != 32 OR length(bytes) = 0 OR length(bytes) > ?2 THEN 1 ELSE 0 END), 0)
                 FROM protocol_records WHERE kind = ?1",
                params![PAGE, CATALOG_PAGE_BYTES as u64],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            if invalid != 0 {
                return Err(DatabaseError::Integrity.into());
            }
            Ledger {
                version: 1,
                usage: CatalogStorageUsage {
                    quota,
                    stored_page_bytes: bytes,
                    stored_pages: pages,
                    reserved_page_bytes: 0,
                    reserved_pages: 0,
                    open_reservations: 0,
                },
            }
        };
        record.usage.quota = quota;
        record.usage.validate()?;
        if ledger(&transaction)?.is_none() {
            insert_exact(&transaction, ENABLED, KEY, &[1])?;
            insert_exact(&transaction, QUOTA, KEY, &canonical_bytes(&record)?)?;
            if ledger(&transaction)? != Some(record) {
                return Err(DatabaseError::Integrity.into());
            }
        } else {
            write_ledger(&transaction, record)?;
        }
        transaction.commit()?;
        Ok(record.usage)
    }

    pub fn catalog_storage_usage(&self) -> Result<Option<CatalogStorageUsage>, CatalogStoreError> {
        let snapshot = self.read_snapshot()?;
        let usage = ledger(&snapshot)?.map(|record| record.usage);
        snapshot.commit()?;
        Ok(usage)
    }

    /// Reserve before an intent can stage pages. Concurrent writers share one
    /// immediate transaction and ledger. Replay requires the exact same intent
    /// and limits; cancelled IDs cannot regain credits or become writable.
    pub fn begin_catalog_with_page_reservation(
        &self,
        intent: CatalogIntent,
        capacity: CatalogPageReservation,
    ) -> Result<CatalogIntentState, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let state = reserve_intent(&transaction, intent, capacity)?;
        transaction.commit()?;
        Ok(state)
    }

    /// Reserve all roles of one bounded local bundle atomically. Replay binds
    /// each original intent/capacity; the caller separately binds the complete
    /// role manifest to its capture/migration identity.
    pub fn begin_catalog_with_page_reservations(
        &self,
        requests: &[(CatalogIntent, CatalogPageReservation)],
    ) -> Result<Vec<CatalogIntentState>, CatalogStoreError> {
        self.with_catalog_page_reservations(requests, |states| Ok(states.to_vec()))
    }

    /// Reserve a bounded set of same-scope roles and persist its caller-checked
    /// owner journal in one immediate transaction. The callback may use record
    /// reads/CAS/writes on this store; it must verify write outcomes and avoid
    /// nested transactions or external I/O. Any error rolls back every role,
    /// credit and callback write, including failures after a valid prefix.
    pub fn with_catalog_page_reservations<T, E: From<CatalogStoreError>>(
        &self,
        requests: &[(CatalogIntent, CatalogPageReservation)],
        operation: impl FnOnce(&[CatalogIntentState]) -> Result<T, E>,
    ) -> Result<T, E> {
        if requests.is_empty() || requests.len() > CATALOG_BUNDLE_ROOTS {
            return Err(CatalogStoreError::from(DatabaseError::CapacityExceeded).into());
        }
        for (index, (intent, capacity)) in requests.iter().enumerate() {
            capacity.validate()?;
            if intent.scope != requests[0].0.scope
                || requests[..index]
                    .iter()
                    .any(|(previous, _)| previous.id == intent.id)
            {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
        }
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
                .map_err(CatalogStoreError::from)?;
        let mut states = Vec::with_capacity(requests.len());
        for &(intent, capacity) in requests {
            states.push(reserve_intent(&transaction, intent, capacity)?);
        }
        let result = operation(&states)?;
        transaction.commit().map_err(CatalogStoreError::from)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use mb_core::{CATALOG_LEAF_BYTES, CatalogBuilder};

    use super::*;

    fn intent(id: u128) -> CatalogIntent {
        CatalogIntent {
            id: Uuid::from_u128(id),
            scope: CatalogScope::Guild { guild_id: [61; 32] },
            section: CatalogSection::Coding,
        }
    }

    fn pages(data: &[u8]) -> (CatalogPageRef, Vec<(CatalogPageRef, Vec<u8>)>) {
        let mut pages = Vec::new();
        let mut builder = CatalogBuilder::new(intent(1).scope, intent(1).section).unwrap();
        let mut sink = |reference, bytes| {
            pages.push((reference, bytes));
            Ok::<_, ()>(())
        };
        builder.push(data, &mut sink).unwrap();
        let root = builder.finish(&mut sink).unwrap();
        (root, pages)
    }

    fn capacity(pages: &[(CatalogPageRef, Vec<u8>)]) -> CatalogPageReservation {
        CatalogPageReservation {
            page_bytes: pages.iter().map(|(_, bytes)| bytes.len() as u64).sum(),
            pages: pages.len() as u64,
        }
    }

    #[test]
    fn reservation_replay_and_competing_connections_cannot_overbook_storage() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let first = ControlStore::open_with_key(&path, &[62; 32]).unwrap();
        let (_, data) = pages(b"reserved page");
        let planned = capacity(&data);
        let quota = CatalogStorageQuota {
            page_bytes: planned.page_bytes,
            pages: planned.pages,
            open_reservations: 1,
        };
        let initial = first.configure_catalog_storage_quota(quota).unwrap();
        assert!(first.begin_catalog(intent(1)).is_err());
        assert!(
            first
                .get_record(INTENT, intent(1).id.as_bytes())
                .unwrap()
                .is_none()
        );
        first
            .begin_catalog_with_page_reservation(intent(1), planned)
            .unwrap();
        let admitted = first.catalog_storage_usage().unwrap().unwrap();
        assert_eq!(admitted.reserved_page_bytes, planned.page_bytes);
        assert_eq!(admitted.reserved_pages, planned.pages);
        assert_eq!(admitted.open_reservations, 1);
        let second = ControlStore::open_with_key(&path, &[62; 32]).unwrap();
        second
            .begin_catalog_with_page_reservation(intent(1), planned)
            .unwrap();
        assert_eq!(second.catalog_storage_usage().unwrap(), Some(admitted));
        assert!(
            second
                .begin_catalog_with_page_reservation(intent(2), planned)
                .is_err()
        );
        assert!(
            second
                .begin_catalog_with_page_reservation(intent(1), CatalogPageReservation::default())
                .is_err()
        );
        let mut wrong = intent(1);
        wrong.scope = CatalogScope::Guild { guild_id: [63; 32] };
        assert!(
            second
                .begin_catalog_with_page_reservation(wrong, planned)
                .is_err()
        );
        assert_eq!(first.catalog_storage_usage().unwrap(), Some(admitted));
        second.cancel_catalog(intent(1)).unwrap();
        assert_eq!(first.catalog_storage_usage().unwrap(), Some(initial));
        assert!(
            first
                .begin_catalog_with_page_reservation(intent(1), planned)
                .is_err()
        );
        first
            .begin_catalog_with_page_reservation(intent(2), planned)
            .unwrap();
        drop(second);
        drop(first);
        let reopened = ControlStore::open_with_key(&path, &[62; 32]).unwrap();
        assert_eq!(reopened.catalog_storage_usage().unwrap(), Some(admitted));
        assert!(
            reopened
                .begin_catalog_with_page_reservation(intent(3), planned)
                .is_err()
        );
    }

    #[test]
    fn simultaneous_reservations_share_the_same_durable_limit() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[70; 32]).unwrap();
        let capacity = CatalogPageReservation {
            page_bytes: 1024,
            pages: 1,
        };
        store
            .configure_catalog_storage_quota(CatalogStorageQuota {
                page_bytes: capacity.page_bytes,
                pages: capacity.pages,
                open_reservations: 2,
            })
            .unwrap();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let connections = [
            ControlStore::open_with_key(&path, &[70; 32]).unwrap(),
            ControlStore::open_with_key(&path, &[70; 32]).unwrap(),
        ];
        let workers = connections
            .into_iter()
            .enumerate()
            .map(|(index, store)| {
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store
                        .begin_catalog_with_page_reservation(intent(index as u128 + 1), capacity)
                        .is_ok()
                })
            })
            .collect::<Vec<_>>();
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|success| *success)
            .count();
        assert_eq!(admitted, 1);
        let usage = store.catalog_storage_usage().unwrap().unwrap();
        assert_eq!(usage.reserved_page_bytes, capacity.page_bytes);
        assert_eq!(usage.reserved_pages, capacity.pages);
        assert_eq!(usage.open_reservations, 1);
    }

    #[test]
    fn bundle_admission_and_owner_journal_roll_back_every_partial_prefix() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[71; 32]).unwrap();
        let capacity = CatalogPageReservation {
            page_bytes: 1024,
            pages: 1,
        };
        let requests = [(intent(1), capacity), (intent(2), capacity)];
        let quota = CatalogStorageQuota {
            page_bytes: 2047,
            pages: 2,
            open_reservations: 2,
        };
        let initial = store.configure_catalog_storage_quota(quota).unwrap();
        assert!(
            store
                .begin_catalog_with_page_reservations(&requests)
                .is_err()
        );
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
        assert!(store.records(INTENT).unwrap().is_empty());
        assert!(store.records(RESERVATION).unwrap().is_empty());
        let initial = store
            .configure_catalog_storage_quota(CatalogStorageQuota {
                page_bytes: 2048,
                ..quota
            })
            .unwrap();
        store.connection.execute_batch(&format!(
            "CREATE TRIGGER batch_fault BEFORE INSERT ON protocol_records WHEN NEW.kind = '{RESERVATION}' AND NEW.record_id = X'{}' BEGIN SELECT RAISE(IGNORE); END",
            hex::encode(intent(2).id.as_bytes())
        )).unwrap();
        assert!(
            store
                .begin_catalog_with_page_reservations(&requests)
                .is_err()
        );
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
        assert!(store.records(INTENT).unwrap().is_empty());
        assert!(store.records(RESERVATION).unwrap().is_empty());
        store
            .connection
            .execute_batch("DROP TRIGGER batch_fault")
            .unwrap();
        let rejected: Result<(), CatalogStoreError> =
            store.with_catalog_page_reservations(&requests, |_| {
                store.put_record("test-owner", b"job", b"journal")?;
                Err(DatabaseError::Conflict.into())
            });
        assert!(rejected.is_err());
        assert!(store.get_record("test-owner", b"job").unwrap().is_none());
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
        assert!(store.records(INTENT).unwrap().is_empty());
        assert!(store.records(RESERVATION).unwrap().is_empty());
        let admitted: Result<(), CatalogStoreError> =
            store.with_catalog_page_reservations(&requests, |states| {
                assert_eq!(states, [CatalogIntentState::Building; 2]);
                assert!(store.put_record_if_absent("test-owner", b"job", b"journal")?);
                Ok(())
            });
        admitted.unwrap();
        let reserved = store.catalog_storage_usage().unwrap();
        assert_eq!(
            store
                .begin_catalog_with_page_reservations(&requests)
                .unwrap(),
            [CatalogIntentState::Building; 2]
        );
        assert_eq!(store.catalog_storage_usage().unwrap(), reserved);
        for invalid in [
            Vec::new(),
            vec![requests[0]; 2],
            vec![requests[0]; CATALOG_BUNDLE_ROOTS + 1],
        ] {
            assert!(
                store
                    .begin_catalog_with_page_reservations(&invalid)
                    .is_err()
            );
        }
        let mut different = intent(3);
        different.scope = CatalogScope::Guild { guild_id: [72; 32] };
        assert!(
            store
                .begin_catalog_with_page_reservations(&[requests[0], (different, capacity)])
                .is_err()
        );
        assert_eq!(store.catalog_storage_usage().unwrap(), reserved);
        for (intent, _) in requests {
            store.fence_catalog(intent).unwrap();
        }
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
    }

    #[test]
    fn cancellation_fences_unreached_and_prequota_intents_without_acquiring_credits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[72; 32]).unwrap();
        let (root, pages) = pages(b"existing unreserved pending page");
        store.begin_catalog(intent(1)).unwrap();
        store
            .stage_catalog_page(intent(1), root, &pages[0].1)
            .unwrap();
        let initial = store
            .configure_catalog_storage_quota(CatalogStorageQuota {
                page_bytes: pages[0].1.len() as u64,
                pages: 1,
                open_reservations: 1,
            })
            .unwrap();
        for id in [1, 2] {
            store.fence_catalog(intent(id)).unwrap();
            store.fence_catalog(intent(id)).unwrap();
            assert_eq!(
                store.catalog_intent_state(intent(id)).unwrap(),
                CatalogIntentState::Cancelled
            );
            assert!(store.begin_catalog(intent(id)).is_err());
            assert!(
                store
                    .begin_catalog_with_page_reservation(
                        intent(id),
                        CatalogPageReservation::default()
                    )
                    .is_err()
            );
        }
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
        drop(store);
        let store = ControlStore::open_with_key(&path, &[72; 32]).unwrap();
        assert_eq!(
            store.catalog_intent_state(intent(2)).unwrap(),
            CatalogIntentState::Cancelled
        );
        assert_eq!(
            store
                .catalog_page(intent(1).scope, intent(1).section, root)
                .unwrap(),
            pages[0].1
        );
        while store.release_catalog_pin(intent(1)).unwrap() {}
        assert!(store.collect_catalog_page().unwrap());
        assert_eq!(
            store.catalog_storage_usage().unwrap().unwrap().stored_pages,
            0
        );
        assert!(store.records(RESERVATION).unwrap().is_empty());
    }

    #[test]
    fn shared_parent_closures_keep_storage_charged_until_actual_page_collection() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[64; 32]).unwrap();
        let (root, data) = pages(&vec![65; CATALOG_LEAF_BYTES + 1]);
        assert_eq!(data.len(), 3);
        let planned = capacity(&data);
        let quota = CatalogStorageQuota {
            page_bytes: planned.page_bytes + 123,
            pages: planned.pages + 1,
            open_reservations: 2,
        };
        store.configure_catalog_storage_quota(quota).unwrap();
        let oversized = CatalogPageReservation {
            page_bytes: quota.page_bytes,
            pages: quota.pages,
        };
        store
            .begin_catalog_with_page_reservation(intent(1), oversized)
            .unwrap();
        for (reference, bytes) in &data {
            store
                .stage_catalog_page(intent(1), *reference, bytes)
                .unwrap();
        }
        let usage = store.catalog_storage_usage().unwrap().unwrap();
        assert_eq!(usage.stored_page_bytes, planned.page_bytes);
        assert_eq!(usage.stored_pages, planned.pages);
        assert_eq!(usage.reserved_page_bytes, 123);
        assert_eq!(usage.reserved_pages, 1);
        store.publish_catalog(intent(1), root).unwrap();
        let published = store.catalog_storage_usage().unwrap().unwrap();
        assert_eq!(published.reserved_page_bytes, 0);
        assert_eq!(published.open_reservations, 0);
        while store.release_catalog_pin(intent(1)).unwrap() {}
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(published));
        assert!(!store.collect_catalog_page().unwrap());
        assert!(
            store
                .configure_catalog_storage_quota(CatalogStorageQuota {
                    page_bytes: planned.page_bytes - 1,
                    ..quota
                })
                .is_err()
        );
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(published));
        store
            .begin_catalog_with_page_reservation(intent(2), CatalogPageReservation::default())
            .unwrap();
        let bytes = store
            .catalog_page(intent(2).scope, intent(2).section, root)
            .unwrap();
        store.stage_catalog_page(intent(2), root, &bytes).unwrap();
        store.publish_catalog(intent(2), root).unwrap();
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(published));
        assert_eq!(
            store
                .begin_catalog_with_page_reservation(intent(2), CatalogPageReservation::default())
                .unwrap(),
            CatalogIntentState::Published(root)
        );
        store.cancel_catalog(intent(1)).unwrap();
        while store.release_catalog_pin(intent(1)).unwrap() {}
        assert!(!store.collect_catalog_page().unwrap());
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(published));
        store.cancel_catalog(intent(2)).unwrap();
        while store.release_catalog_pin(intent(2)).unwrap() {}
        for remaining in [2, 1, 0] {
            assert!(store.collect_catalog_page().unwrap());
            assert_eq!(
                store.catalog_storage_usage().unwrap().unwrap().stored_pages,
                remaining
            );
        }
        assert_eq!(
            store
                .catalog_storage_usage()
                .unwrap()
                .unwrap()
                .stored_page_bytes,
            0
        );
    }

    #[test]
    fn exhausted_credit_and_initial_adoption_preserve_existing_pages() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[66; 32]).unwrap();
        let (root, data) = pages(b"original catalog page");
        let planned = capacity(&data);
        store.begin_catalog(intent(1)).unwrap();
        store
            .stage_catalog_page(intent(1), root, &data[0].1)
            .unwrap();
        let usage = store
            .configure_catalog_storage_quota(CatalogStorageQuota {
                page_bytes: planned.page_bytes * 3,
                pages: 2,
                open_reservations: 2,
            })
            .unwrap();
        assert_eq!(usage.stored_page_bytes, planned.page_bytes);
        assert_eq!(usage.stored_pages, 1);
        assert!(
            store
                .stage_catalog_page(intent(1), root, &data[0].1)
                .is_err()
        );
        store
            .begin_catalog_with_page_reservation(intent(1), CatalogPageReservation::default())
            .unwrap();
        store.publish_catalog(intent(1), root).unwrap();
        let (new_root, new_data) = pages(b"replacement catalog page");
        let short = CatalogPageReservation {
            page_bytes: new_data[0].1.len() as u64 - 1,
            pages: 1,
        };
        store
            .begin_catalog_with_page_reservation(intent(2), short)
            .unwrap();
        let reserved = store.catalog_storage_usage().unwrap();
        assert!(
            store
                .stage_catalog_page(intent(2), new_root, &new_data[0].1)
                .is_err()
        );
        assert!(store.get_record(PAGE, &new_root.hash).unwrap().is_none());
        assert_eq!(store.catalog_storage_usage().unwrap(), reserved);
        assert_eq!(
            store
                .catalog_page(intent(1).scope, intent(1).section, root)
                .unwrap(),
            data[0].1
        );
        store.cancel_catalog(intent(2)).unwrap();
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(usage));
        store
            .begin_catalog_with_page_reservation(
                intent(3),
                CatalogPageReservation {
                    page_bytes: new_data[0].1.len() as u64,
                    pages: 0,
                },
            )
            .unwrap();
        let reserved = store.catalog_storage_usage().unwrap();
        assert!(
            store
                .stage_catalog_page(intent(3), new_root, &new_data[0].1)
                .is_err()
        );
        assert!(store.get_record(PAGE, &new_root.hash).unwrap().is_none());
        assert_eq!(store.catalog_storage_usage().unwrap(), reserved);
        store.cancel_catalog(intent(3)).unwrap();
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(usage));
    }

    #[test]
    fn ignored_or_reverted_writes_roll_back_reservations_pages_and_collection() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[67; 32]).unwrap();
        let (root, data) = pages(b"atomic quota page");
        let planned = capacity(&data);
        let initial = store
            .configure_catalog_storage_quota(CatalogStorageQuota {
                page_bytes: planned.page_bytes,
                pages: 1,
                open_reservations: 1,
            })
            .unwrap();
        for trigger in [
            format!(
                "CREATE TRIGGER quota_fault BEFORE INSERT ON protocol_records WHEN NEW.kind = '{RESERVATION}' BEGIN SELECT RAISE(IGNORE); END"
            ),
            format!(
                "CREATE TRIGGER quota_fault AFTER UPDATE ON protocol_records WHEN NEW.kind = '{QUOTA}' BEGIN UPDATE protocol_records SET bytes = OLD.bytes WHERE kind = OLD.kind AND record_id = OLD.record_id; END"
            ),
            format!(
                "CREATE TRIGGER quota_fault AFTER INSERT ON protocol_records WHEN NEW.kind = '{INTENT}' BEGIN DELETE FROM protocol_records WHERE kind = NEW.kind AND record_id = NEW.record_id; END"
            ),
        ] {
            store.connection.execute_batch(&trigger).unwrap();
            assert!(
                store
                    .begin_catalog_with_page_reservation(intent(1), planned)
                    .is_err()
            );
            assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
            assert!(
                store
                    .get_record(INTENT, intent(1).id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(
                store
                    .get_record(RESERVATION, intent(1).id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            store
                .connection
                .execute_batch("DROP TRIGGER quota_fault")
                .unwrap();
        }
        store
            .begin_catalog_with_page_reservation(intent(1), planned)
            .unwrap();
        let reserved = store.catalog_storage_usage().unwrap();
        store.connection.execute_batch(&format!("CREATE TRIGGER quota_fault AFTER INSERT ON protocol_records WHEN NEW.kind = '{PAGE}' BEGIN DELETE FROM protocol_records WHERE kind = NEW.kind AND record_id = NEW.record_id; END")).unwrap();
        assert!(
            store
                .stage_catalog_page(intent(1), root, &data[0].1)
                .is_err()
        );
        assert_eq!(store.catalog_storage_usage().unwrap(), reserved);
        assert!(store.get_record(PAGE, &root.hash).unwrap().is_none());
        store
            .connection
            .execute_batch("DROP TRIGGER quota_fault")
            .unwrap();
        store
            .stage_catalog_page(intent(1), root, &data[0].1)
            .unwrap();
        store.publish_catalog(intent(1), root).unwrap();
        store.cancel_catalog(intent(1)).unwrap();
        store.release_catalog_pin(intent(1)).unwrap();
        let stored = store.catalog_storage_usage().unwrap();
        store.connection.execute_batch(&format!("CREATE TRIGGER quota_fault BEFORE DELETE ON protocol_records WHEN OLD.kind = '{PAGE}' BEGIN SELECT RAISE(IGNORE); END")).unwrap();
        assert!(store.collect_catalog_page().is_err());
        assert_eq!(store.catalog_storage_usage().unwrap(), stored);
        assert_eq!(
            store
                .catalog_page(intent(1).scope, intent(1).section, root)
                .unwrap(),
            data[0].1
        );
        store
            .connection
            .execute_batch("DROP TRIGGER quota_fault")
            .unwrap();
        assert!(store.collect_catalog_page().unwrap());
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
    }

    #[test]
    fn bundle_publication_and_cancellation_close_credits_in_the_same_transaction() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[68; 32]).unwrap();
        let (first, first_pages) = pages(b"first bundle member");
        let (second, second_pages) = pages(b"second bundle member");
        let capacity = |bytes: &[u8]| CatalogPageReservation {
            page_bytes: bytes.len() as u64 + 128,
            pages: 2,
        };
        let first_credit = capacity(&first_pages[0].1);
        let second_credit = capacity(&second_pages[0].1);
        let quota = CatalogStorageQuota {
            page_bytes: first_credit.page_bytes + second_credit.page_bytes,
            pages: 4,
            open_reservations: 2,
        };
        let initial = store.configure_catalog_storage_quota(quota).unwrap();
        for (intent, root, bytes, credits) in [
            (intent(1), first, &first_pages[0].1, first_credit),
            (intent(2), second, &second_pages[0].1, second_credit),
        ] {
            store
                .begin_catalog_with_page_reservation(intent, credits)
                .unwrap();
            store.stage_catalog_page(intent, root, bytes).unwrap();
        }
        let before = store.catalog_storage_usage().unwrap();
        let bundle = CatalogBundle {
            id: Uuid::from_u128(100),
            scope: intent(1).scope,
            roots: vec![
                CatalogBundleRoot {
                    intent: intent(1),
                    root: first,
                },
                CatalogBundleRoot {
                    intent: intent(2),
                    root: second,
                },
            ],
            descriptor: b"quota bundle".to_vec(),
        };
        store.connection.execute_batch(&format!(
            "CREATE TRIGGER quota_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind = '{INTENT}' AND NEW.record_id = X'{}' BEGIN SELECT RAISE(IGNORE); END",
            hex::encode(intent(2).id.as_bytes())
        )).unwrap();
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        assert_eq!(store.catalog_storage_usage().unwrap(), before);
        for (intent, credits) in [(intent(1), first_credit), (intent(2), second_credit)] {
            assert_eq!(
                store.catalog_intent_state(intent).unwrap(),
                CatalogIntentState::Building
            );
            store
                .begin_catalog_with_page_reservation(intent, credits)
                .unwrap();
        }
        store
            .connection
            .execute_batch("DROP TRIGGER quota_fault")
            .unwrap();
        store.publish_catalog_bundle(&bundle).unwrap();
        let published = store.catalog_storage_usage().unwrap().unwrap();
        assert_eq!(published.open_reservations, 0);
        assert_eq!(published.reserved_page_bytes, 0);
        assert_eq!(published.reserved_pages, 0);
        assert_eq!(published.stored_pages, 2);
        store.cancel_catalog_bundle(bundle.id).unwrap();
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(published));
        for intent in [intent(1), intent(2)] {
            while store.release_catalog_pin(intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        assert_eq!(store.catalog_storage_usage().unwrap(), Some(initial));
    }

    #[test]
    fn missing_and_corrupt_quota_records_cannot_make_reserved_writes_unlimited() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[69; 32]).unwrap();
        let (root, data) = pages(b"bounded stored page");
        let capacity = capacity(&data);
        store
            .configure_catalog_storage_quota(CatalogStorageQuota {
                page_bytes: capacity.page_bytes,
                pages: capacity.pages,
                open_reservations: 1,
            })
            .unwrap();
        store
            .begin_catalog_with_page_reservation(intent(1), capacity)
            .unwrap();
        let ledger_bytes = store.get_record(QUOTA, KEY).unwrap().unwrap();
        let reservation_bytes = store
            .get_record(RESERVATION, intent(1).id.as_bytes())
            .unwrap()
            .unwrap();
        let original = store.catalog_storage_usage().unwrap();
        for fault in 0..7 {
            match fault {
                0 => {
                    store.delete_record(QUOTA, KEY).unwrap();
                }
                1 => {
                    store.delete_record(ENABLED, KEY).unwrap();
                }
                2 => store.put_record(ENABLED, KEY, &[2]).unwrap(),
                3 => store
                    .put_record(QUOTA, KEY, &vec![0; RECORD_BYTES + 1])
                    .unwrap(),
                4 => {
                    store
                        .delete_record(RESERVATION, intent(1).id.as_bytes())
                        .unwrap();
                }
                5 => {
                    let mut record: Reservation = decode(&reservation_bytes).unwrap();
                    record.remaining.pages += 1;
                    store
                        .put_record(
                            RESERVATION,
                            intent(1).id.as_bytes(),
                            &canonical_bytes(&record).unwrap(),
                        )
                        .unwrap();
                }
                _ => {
                    let mut record: Ledger = decode(&ledger_bytes).unwrap();
                    record.usage.open_reservations = 0;
                    record.usage.reserved_page_bytes = 0;
                    record.usage.reserved_pages = 0;
                    store
                        .put_record(QUOTA, KEY, &canonical_bytes(&record).unwrap())
                        .unwrap();
                }
            }
            assert!(
                store
                    .stage_catalog_page(intent(1), root, &data[0].1)
                    .is_err(),
                "fault {fault}"
            );
            assert!(store.get_record(PAGE, &root.hash).unwrap().is_none());
            store.put_record(QUOTA, KEY, &ledger_bytes).unwrap();
            store.put_record(ENABLED, KEY, &[1]).unwrap();
            store
                .put_record(RESERVATION, intent(1).id.as_bytes(), &reservation_bytes)
                .unwrap();
            assert_eq!(store.catalog_storage_usage().unwrap(), original);
        }
    }
}
