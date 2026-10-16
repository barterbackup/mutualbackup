//! Shared traversal admission for durable acquisition jobs and live recovery. Encoded pages,
//! SQL/WAL, payloads and physical scratch keep their separate backing ledgers.
use super::*;

mod live;
pub(in crate::database::catalog) mod live_lock;
mod live_owner;
mod pool;
pub use live::CatalogCheckpointRecoveryWork;
pub use pool::CatalogTraversalPoolPolicy;

const LEDGER: &str = "catalog-acquisition-work-v1";
const GUARD: &str = "catalog-acquisition-work-guard-v1";
const LEASE: &str = "catalog-acquisition-work-lease-v1";
const LEASE_GUARD: &str = "catalog-acquisition-work-lease-guard-v1";
const HELD: &str = "catalog-acquisition-work-held-v1";
const HELD_GUARD: &str = "catalog-acquisition-work-held-guard-v1";
const META: &str = "catalog_acquisition_work_version";
const READY: &str = "catalog_acquisition_work_ready";
const TRIGGER: &str = "catalog_acquisition_work_insert";
const KEY: &[u8] = b"store";
const RECORD: usize = 4096;
/// Bound every admission-integrity scan independently of retained history.
pub const CATALOG_ACQUISITION_WORK_JOBS: u32 = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogAcquisitionWorkState {
    Adopting,
    Active,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogAcquisitionWorkUsage {
    pub state: CatalogAcquisitionWorkState,
    pub limit: Work,
    pub reserved: Work,
    /// Shared slots held by durable acquisitions and disposable proof traversals.
    pub open_jobs: u32,
    pub max_jobs: u32,
    pub scanned_jobs: u64,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Ledger {
    version: u16,
    policy: CatalogResourcePolicy,
    state: CatalogAcquisitionWorkState,
    after: Option<[u8; 16]>,
    scanned: u64,
    reserved: Work,
    open: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Lease {
    version: u16,
    spec_hash: [u8; 32],
    budget: Work,
    held: bool,
}
fn canonical<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value = decode_canonical(bytes)?;
    if mb_core::canonical_bytes_bounded(&value, RECORD)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}
fn paired(
    cx: &Connection,
    a: &str,
    b: &str,
    key: &[u8],
) -> Result<Option<Vec<u8>>, CatalogStoreError> {
    let bytes = bounded_record(cx, a, key, RECORD)?;
    if bytes != bounded_record(cx, b, key, RECORD)? {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(bytes)
}
fn max_jobs(p: CatalogResourcePolicy) -> u32 {
    p.open_page_reservations.min(CATALOG_ACQUISITION_WORK_JOBS)
}
fn trigger_sql() -> String {
    format!(
        "CREATE TRIGGER {TRIGGER} BEFORE INSERT ON protocol_records WHEN NEW.kind IN ('{}','{}') BEGIN SELECT CASE WHEN COALESCE((SELECT value=x'01' FROM meta WHERE key='{READY}'),0)=0 OR NOT EXISTS(SELECT 1 FROM protocol_records h JOIN protocol_records g ON g.kind='{HELD_GUARD}' AND g.record_id=h.record_id AND g.bytes=h.bytes JOIN protocol_records l ON l.kind='{LEASE}' AND l.record_id=h.record_id AND l.bytes=h.bytes JOIN protocol_records f ON f.kind='{LEASE_GUARD}' AND f.record_id=h.record_id AND f.bytes=h.bytes WHERE h.kind='{HELD}' AND h.record_id=NEW.record_id) THEN RAISE(ABORT,'acquisition work admission is required') END; END",
        JOB,
        super::GUARD
    )
}
fn validate_trigger(cx: &Connection) -> Result<(), CatalogStoreError> {
    let sql:Option<Option<String>>=cx.query_row("SELECT CASE WHEN length(sql)<=4096 THEN sql END FROM sqlite_schema WHERE type='trigger' AND name=?1",[TRIGGER],|r|r.get(0)).optional()?;
    if sql
        .flatten()
        .as_deref()
        .map(crate::database::normalize_schema_sql)
        != Some(crate::database::normalize_schema_sql(&trigger_sql()))
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn read(cx: &Connection) -> Result<Option<Ledger>, CatalogStoreError> {
    let marker: Option<Option<Vec<u8>>> = cx
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            [META],
            |r| r.get(0),
        )
        .optional()?;
    let ready: Option<Option<Vec<u8>>> = cx
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            [READY],
            |r| r.get(0),
        )
        .optional()?;
    let bytes = paired(cx, LEDGER, GUARD, KEY)?;
    let Some(bytes) = bytes else {
        pool::require_unconfigured(cx)?;
        let orphan: bool = cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10))",
            params![
                LEASE,
                LEASE_GUARD,
                HELD,
                HELD_GUARD,
                live::SCOPE,
                live::SCOPE_GUARD,
                live::LEGACY_SCOPE,
                live::LEGACY_GUARD,
                live_lock::KINDS[0],
                live_lock::KINDS[1]
            ],
            |r| r.get(0),
        )?;
        let trigger: bool = cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='trigger' AND name=?1)",
            [TRIGGER],
            |r| r.get(0),
        )?;
        if marker.is_some() || ready.is_some() || orphan || trigger {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let l: Ledger = canonical(&bytes)?;
    validate_trigger(cx)?;
    if (l.state == CatalogAcquisitionWorkState::Active && ready != Some(Some(vec![1])))
        || (l.state == CatalogAcquisitionWorkState::Adopting && ready.is_some())
    {
        return Err(DatabaseError::Integrity.into());
    }

    if marker != Some(Some(vec![1]))
        || l.version != 1
        || capacity_policy::resource_policy(cx)? != Some(l.policy)
        || capacity_policy::read(cx)? != Some(l.policy.capacity)
        || l.open > max_jobs(l.policy)
        || (l.open == 0) != (l.reserved == Work::default())
        || l.after.is_none() && l.scanned != 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    pool::limit(cx, l.policy)?.remaining_after(l.reserved)?;
    let mut query=cx.prepare("SELECT CASE WHEN length(record_id)=16 THEN record_id END,CASE WHEN length(bytes)<=?2 THEN bytes END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT ?3")?;
    let mut rows = query.query(params![
        HELD,
        RECORD,
        u64::from(CATALOG_ACQUISITION_WORK_JOBS) + 1
    ])?;
    let mut count = 0u32;
    let mut sum = Work::default();
    while let Some(row) = rows.next()? {
        let key: Option<Vec<u8>> = row.get(0)?;
        let key = key.ok_or(DatabaseError::Integrity)?;
        let bytes: Option<Vec<u8>> = row.get(1)?;
        let bytes = bytes.ok_or(DatabaseError::Integrity)?;
        let lease: Lease = canonical(&bytes)?;
        if lease.version != 1
            || !lease.held
            || lease.spec_hash == [0; 32]
            || bounded_record(cx, HELD_GUARD, &key, RECORD)?.as_deref() != Some(bytes.as_slice())
        {
            return Err(DatabaseError::Integrity.into());
        }
        sum = sum.checked_add(lease.budget)?;
        count = count.checked_add(1).ok_or(DatabaseError::Integrity)?;
        if count > CATALOG_ACQUISITION_WORK_JOBS {
            return Err(DatabaseError::Integrity.into());
        }
    }
    let guards: u64 = cx.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM protocol_records WHERE kind=?1 LIMIT ?2)",
        params![HELD_GUARD, u64::from(CATALOG_ACQUISITION_WORK_JOBS) + 1],
        |r| r.get(0),
    )?;
    if count != l.open || guards != u64::from(count) || sum != l.reserved {
        return Err(DatabaseError::Integrity.into());
    }
    live::validate(cx)?;
    Ok(Some(l))
}
fn write(cx: &Connection, old: Ledger, next: Ledger) -> Result<(), CatalogStoreError> {
    if old.state == CatalogAcquisitionWorkState::Adopting
        && next.state == CatalogAcquisitionWorkState::Active
        && cx.execute(
            "INSERT INTO meta(key,value) VALUES (?1,?2)",
            params![READY, &[1u8][..]],
        )? != 1
    {
        return Err(DatabaseError::Integrity.into());
    }
    let bytes = canonical_bytes(&next)?;
    for kind in [LEDGER, GUARD] {
        if cx.execute(
            "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
            params![kind, KEY, bytes, canonical_bytes(&old)?],
        )? != 1
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    if read(cx)? != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn expected(spec: &CatalogCheckpointAcquisition) -> Result<Lease, CatalogStoreError> {
    Ok(Lease {
        version: 1,
        spec_hash: mb_core::canonical_hash_bounded(spec, BYTES)?,
        budget: spec.budget,
        held: true,
    })
}
fn lease(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
) -> Result<Option<Lease>, CatalogStoreError> {
    let bytes = paired(cx, LEASE, LEASE_GUARD, spec.id.as_bytes())?;
    let held = paired(cx, HELD, HELD_GUARD, spec.id.as_bytes())?;
    let Some(bytes) = bytes else {
        if held.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let l: Lease = canonical(&bytes)?;
    let e = expected(spec)?;
    if l.version != 1
        || l.spec_hash != e.spec_hash
        || l.budget != e.budget
        || (if l.held {
            held.as_deref() != Some(bytes.as_slice())
        } else {
            held.is_some()
        })
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(l))
}
pub(in crate::database::catalog) fn enroll(
    cx: &Connection,
    policy: CatalogResourcePolicy,
) -> Result<(), CatalogStoreError> {
    if let Some(l) = read(cx)? {
        if l.policy != policy {
            return Err(DatabaseError::Conflict.into());
        }
        return Ok(());
    }
    let l = Ledger {
        version: 1,
        policy,
        state: CatalogAcquisitionWorkState::Adopting,
        after: None,
        scanned: 0,
        reserved: Work::default(),
        open: 0,
    };
    cx.execute_batch(&trigger_sql())?;
    let bytes = canonical_bytes(&l)?;
    for kind in [LEDGER, GUARD] {
        insert_exact(cx, kind, KEY, &bytes)?;
    }
    if cx.execute(
        "INSERT INTO meta(key,value) VALUES (?1,?2)",
        params![META, &[1u8][..]],
    )? != 1
        || read(cx)? != Some(l)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn reserve_inner(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
    old: Ledger,
) -> Result<(), CatalogStoreError> {
    old.policy
        .capacity
        .plan()?
        .job_work
        .remaining_after(spec.budget)?;
    if let Some(l) = lease(cx, spec)? {
        if !l.held {
            return Err(DatabaseError::Conflict.into());
        }
        return Ok(());
    }
    let next = Ledger {
        reserved: old.reserved.checked_add(spec.budget)?,
        open: old
            .open
            .checked_add(1)
            .ok_or(DatabaseError::CapacityExceeded)?,
        ..old
    };
    pool::limit(cx, old.policy)?.remaining_after(next.reserved)?;
    if next.open > max_jobs(old.policy) {
        return Err(DatabaseError::CapacityExceeded.into());
    }
    let bytes = canonical_bytes(&expected(spec)?)?;
    for kind in [LEASE, LEASE_GUARD, HELD, HELD_GUARD] {
        insert_exact(cx, kind, spec.id.as_bytes(), &bytes)?;
    }
    write(cx, old, next)?;
    if lease(cx, spec)? != Some(expected(spec)?) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
pub(super) fn reserve(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
) -> Result<(), CatalogStoreError> {
    match read(cx)? {
        None => {
            if capacity_policy::resource_policy(cx)?.is_some() {
                return Err(DatabaseError::NotReady.into());
            }
            Ok(())
        }
        Some(l) => {
            if l.state != CatalogAcquisitionWorkState::Active {
                return Err(DatabaseError::NotReady.into());
            }
            reserve_inner(cx, spec, l)
        }
    }
}
pub(super) fn require(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
) -> Result<(), CatalogStoreError> {
    match read(cx)? {
        None => {
            if capacity_policy::resource_policy(cx)?.is_some() {
                return Err(DatabaseError::NotReady.into());
            }
            Ok(())
        }
        Some(l) => {
            l.policy
                .capacity
                .plan()?
                .job_work
                .remaining_after(spec.budget)?;
            if l.state != CatalogAcquisitionWorkState::Active
                || lease(cx, spec)? != Some(expected(spec)?)
            {
                return Err(DatabaseError::NotReady.into());
            }
            Ok(())
        }
    }
}
pub(super) fn release(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
) -> Result<(), CatalogStoreError> {
    let Some(old) = read(cx)? else { return Ok(()) };
    let Some(l) = lease(cx, spec)? else {
        if old.state == CatalogAcquisitionWorkState::Active
            && super::read(cx, spec.id)?
                .is_some_and(|job| job.state == CatalogCheckpointAcquisitionState::Building)
        {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(());
    };
    if !l.held {
        return Ok(());
    }
    let next = Ledger {
        reserved: Work {
            bytes: old
                .reserved
                .bytes
                .checked_sub(l.budget.bytes)
                .ok_or(DatabaseError::Integrity)?,
            records: old
                .reserved
                .records
                .checked_sub(l.budget.records)
                .ok_or(DatabaseError::Integrity)?,
            page_occurrences: old
                .reserved
                .page_occurrences
                .checked_sub(l.budget.page_occurrences)
                .ok_or(DatabaseError::Integrity)?,
        },
        open: old.open.checked_sub(1).ok_or(DatabaseError::Integrity)?,
        ..old
    };
    let bytes = canonical_bytes(&Lease { held: false, ..l })?;
    let before = canonical_bytes(&l)?;
    for kind in [LEASE, LEASE_GUARD] {
        if cx.execute(
            "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
            params![kind, spec.id.as_bytes(), bytes, before],
        )? != 1
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    for kind in [HELD, HELD_GUARD] {
        if cx.execute(
            "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
            params![kind, spec.id.as_bytes(), before],
        )? != 1
            || bounded_record(cx, kind, spec.id.as_bytes(), RECORD)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    write(cx, old, next)?;
    if lease(cx, spec)?.is_none_or(|l| l.held) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
pub(in crate::database::catalog) fn schema(
    cx: &Connection,
) -> Result<Vec<(String, String)>, DatabaseError> {
    let enrolled: Option<Option<Vec<u8>>> = cx
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            [META],
            |r| r.get(0),
        )
        .optional()?;
    match enrolled {
        None => Ok(Vec::new()),
        Some(Some(v)) if v == [1] => Ok(vec![(TRIGGER.to_owned(), trigger_sql())]),
        _ => Err(DatabaseError::Integrity),
    }
}
pub(in crate::database::catalog) fn validate_open(cx: &Connection) -> Result<(), DatabaseError> {
    read(cx).map(|_| ()).map_err(|e| match e {
        CatalogStoreError::Database(e) => e,
        _ => DatabaseError::Integrity,
    })
}
impl ControlStore {
    /// Adopt at most one pre-existing job in a short writer. Admission remains
    /// frozen until authenticated EOF; cancellation can reduce excessive debt.
    /// Returns true while another bounded adoption step is needed.
    pub fn advance_checkpoint_acquisition_work_admission(&self) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(p) = capacity_policy::resource_policy(&tx)? else {
            read(&tx)?;
            tx.commit()?;
            return Ok(false);
        };
        enroll(&tx, p)?;
        let old = read(&tx)?.ok_or(DatabaseError::Integrity)?;
        if old.state == CatalogAcquisitionWorkState::Active {
            tx.commit()?;
            return Ok(false);
        }
        let key:Option<Option<Vec<u8>>>=tx.query_row("SELECT CASE WHEN length(record_id)=16 THEN record_id END FROM protocol_records WHERE kind=?1 AND (?2 IS NULL OR record_id>?2) ORDER BY record_id LIMIT 1",params![JOB,old.after.map(|a|a.to_vec())],|r|r.get(0)).optional()?;
        let mut next = old;
        if let Some(key) = key {
            let key: [u8; 16] = key
                .ok_or(DatabaseError::Integrity)?
                .try_into()
                .map_err(|_| DatabaseError::Integrity)?;
            let job = super::read(&tx, Uuid::from_bytes(key))?.ok_or(DatabaseError::Integrity)?;
            if job.state == CatalogCheckpointAcquisitionState::Building {
                reserve_inner(&tx, &job.spec, old)?;
                next = read(&tx)?.ok_or(DatabaseError::Integrity)?;
            }
            next.after = Some(key);
            next.scanned = old
                .scanned
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?;
        } else {
            next.state = CatalogAcquisitionWorkState::Active;
        }
        let previous = read(&tx)?.ok_or(DatabaseError::Integrity)?;
        write(&tx, previous, next)?;
        tx.commit()?;
        Ok(next.state != CatalogAcquisitionWorkState::Active)
    }
    pub fn checkpoint_acquisition_work_usage(
        &self,
    ) -> Result<Option<CatalogAcquisitionWorkUsage>, CatalogStoreError> {
        let value = |cx: &Connection| -> Result<_, CatalogStoreError> {
            read(cx)?
                .map(|l| {
                    Ok(CatalogAcquisitionWorkUsage {
                        state: l.state,
                        limit: pool::limit(cx, l.policy)?,
                        reserved: l.reserved,
                        open_jobs: l.open,
                        max_jobs: max_jobs(l.policy),
                        scanned_jobs: l.scanned,
                    })
                })
                .transpose()
        };
        if !self.connection.is_autocommit() {
            return value(&self.connection);
        }
        let tx = self.read_snapshot()?;
        let result = value(&tx)?;
        tx.commit()?;
        Ok(result)
    }
}
