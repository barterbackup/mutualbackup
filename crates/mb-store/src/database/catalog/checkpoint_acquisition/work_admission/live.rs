//! Disposable complete-proof traversal reservations. A permit accounts work;
//! it grants no certificate, history, page, payload or publication authority.
use super::live_owner::Owner;
use super::*;
use std::sync::Arc;

pub(super) const SCOPE: &str = "catalog-live-recovery-work-v1";
pub(super) const SCOPE_GUARD: &str = "catalog-live-recovery-work-guard-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Spec {
    version: u16,
    id: Uuid,
    selected: CatalogCheckpointRecoveryTip,
    budget: Work,
    owner: Owner,
}

impl Spec {
    fn lease(self) -> Result<Lease, CatalogStoreError> {
        Ok(Lease {
            version: 1,
            spec_hash: mb_core::canonical_hash_bounded(&self, RECORD)?,
            budget: self.budget,
            held: true,
        })
    }
}

fn scope(cx: &Connection, id: Uuid) -> Result<Option<Spec>, CatalogStoreError> {
    let Some(bytes) = paired(cx, SCOPE, SCOPE_GUARD, id.as_bytes())? else {
        return Ok(None);
    };
    let spec: Spec = canonical(&bytes)?;
    spec.owner.validate()?;
    if spec.version != 1 || spec.id != id || id.is_nil() || spec.budget == Work::default() {
        return Err(DatabaseError::Integrity.into());
    }
    let expected = canonical_bytes(&spec.lease()?)?;
    for (a, b) in [(LEASE, LEASE_GUARD), (HELD, HELD_GUARD)] {
        if paired(cx, a, b, id.as_bytes())?.as_deref() != Some(expected.as_slice()) {
            return Err(DatabaseError::Integrity.into());
        }
    }
    Ok(Some(spec))
}

fn scopes(cx: &Connection) -> Result<Vec<Spec>, CatalogStoreError> {
    let mut query = cx.prepare("SELECT CASE WHEN length(record_id)=16 THEN record_id END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT ?2")?;
    let mut rows = query.query(params![SCOPE, u64::from(CATALOG_ACQUISITION_WORK_JOBS) + 1])?;
    let mut specs = Vec::new();
    while let Some(row) = rows.next()? {
        let id: Option<Vec<u8>> = row.get(0)?;
        let id = Uuid::from_slice(&id.ok_or(DatabaseError::Integrity)?)
            .map_err(|_| DatabaseError::Integrity)?;
        specs.push(scope(cx, id)?.ok_or(DatabaseError::Integrity)?);
        if specs.len() > CATALOG_ACQUISITION_WORK_JOBS as usize {
            return Err(DatabaseError::Integrity.into());
        }
    }
    let guards: u64 = cx.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM protocol_records WHERE kind=?1 LIMIT ?2)",
        params![SCOPE_GUARD, u64::from(CATALOG_ACQUISITION_WORK_JOBS) + 1],
        |row| row.get(0),
    )?;
    if guards != specs.len() as u64 {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(specs)
}

pub(super) fn validate(cx: &Connection) -> Result<(), CatalogStoreError> {
    scopes(cx).map(|_| ())
}

fn release(cx: &Connection, old: Ledger, spec: Spec) -> Result<(), CatalogStoreError> {
    if scope(cx, spec.id)? != Some(spec) {
        return Err(DatabaseError::Integrity.into());
    }
    let next = Ledger {
        reserved: old.reserved.remaining_after(spec.budget)?,
        open: old.open.checked_sub(1).ok_or(DatabaseError::Integrity)?,
        ..old
    };
    for (kind, bytes) in [
        (SCOPE, canonical_bytes(&spec)?),
        (SCOPE_GUARD, canonical_bytes(&spec)?),
        (LEASE, canonical_bytes(&spec.lease()?)?),
        (LEASE_GUARD, canonical_bytes(&spec.lease()?)?),
        (HELD, canonical_bytes(&spec.lease()?)?),
        (HELD_GUARD, canonical_bytes(&spec.lease()?)?),
    ] {
        if cx.execute(
            "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
            params![kind, spec.id.as_bytes(), bytes],
        )? != 1
            || bounded_record(cx, kind, spec.id.as_bytes(), RECORD)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    write(cx, old, next)?;
    Ok(())
}

/// A process-owned declaration for one complete recovery proof traversal.
/// Durable acquisition jobs and these scopes share the same cumulative credits
/// and bounded slots. Drop releases credits only after the traversal stops;
/// failed cleanup leaves visible debt for bounded abandoned-scope reclamation.
pub struct CatalogCheckpointRecoveryWork<'a> {
    store: &'a ControlStore,
    spec: Option<Spec>,
    token: Option<Arc<()>>,
    closed: bool,
}

impl CatalogCheckpointRecoveryWork<'_> {
    /// Recheck custody before every bounded unit of expensive validation.
    pub fn check(&self) -> Result<(), CatalogStoreError> {
        if self.closed {
            return Err(DatabaseError::NotReady.into());
        }
        let value = |cx: &Connection| {
            let ledger = read(cx)?;
            match self.spec {
                None if ledger.is_none() && capacity_policy::resource_policy(cx)?.is_none() => {
                    Ok(())
                }
                Some(spec)
                    if ledger.is_some_and(|l| l.state == CatalogAcquisitionWorkState::Active)
                        && scope(cx, spec.id)? == Some(spec) =>
                {
                    spec.owner.require_current(self.store)
                }
                _ => Err(DatabaseError::NotReady.into()),
            }
        };
        if !self.store.connection.is_autocommit() {
            return value(&self.store.connection);
        }
        let tx = self.store.read_snapshot()?;
        value(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// End the traversal and atomically release its declaration. Failed writes
    /// keep the permit live and all credits held, so callers may retry cleanup.
    pub fn finish(&mut self) -> Result<(), CatalogStoreError> {
        if self.closed {
            return Ok(());
        }
        if !self.store.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        if self.spec.is_none() {
            self.check()?;
        }
        if let Some(spec) = self.spec {
            spec.owner.require_current(self.store)?;
            let tx =
                Transaction::new_unchecked(&self.store.connection, TransactionBehavior::Immediate)?;
            let old = read(&tx)?.ok_or(DatabaseError::Integrity)?;
            release(&tx, old, spec)?;
            tx.commit()?;
            spec.owner.unregister(spec.id);
        }
        self.token.take();
        self.closed = true;
        Ok(())
    }
}

impl Drop for CatalogCheckpointRecoveryWork<'_> {
    fn drop(&mut self) {
        let _ = self.finish();
        if let Some(spec) = self.spec {
            spec.owner.unregister(spec.id);
        }
    }
}

impl ControlStore {
    /// Reserve a whole-chain proof declaration before scratch or ancestry
    /// traversal. The selected identity is a work label; the caller must still
    /// authenticate its recovery tip and all original proof authority.
    pub fn begin_checkpoint_recovery_work(
        &self,
        selected: CatalogCheckpointRecoveryTip,
        budget: Work,
    ) -> Result<CatalogCheckpointRecoveryWork<'_>, CatalogStoreError> {
        if !self.connection.is_autocommit() || budget == Work::default() {
            return Err(DatabaseError::NotReady.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(old) = read(&tx)? else {
            if capacity_policy::resource_policy(&tx)?.is_some() {
                return Err(DatabaseError::NotReady.into());
            }
            tx.commit()?;
            return Ok(CatalogCheckpointRecoveryWork {
                store: self,
                spec: None,
                token: None,
                closed: false,
            });
        };
        if old.state != CatalogAcquisitionWorkState::Active {
            return Err(DatabaseError::NotReady.into());
        }
        let next = Ledger {
            reserved: old.reserved.checked_add(budget)?,
            open: old
                .open
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?,
            ..old
        };
        pool::limit(&tx, old.policy)?.remaining_after(next.reserved)?;
        if next.open > max_jobs(old.policy) {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        let spec = Spec {
            version: 1,
            id: Uuid::new_v4(),
            selected,
            budget,
            owner: Owner::current(self)?,
        };
        // Register before commit: another connection must never mistake a newly
        // visible scope for abandoned work between publication and token setup.
        let token = spec.owner.register(spec.id)?;
        let bytes = canonical_bytes(&spec)?;
        for kind in [SCOPE, SCOPE_GUARD] {
            insert_exact(&tx, kind, spec.id.as_bytes(), &bytes)?;
        }
        let bytes = canonical_bytes(&spec.lease()?)?;
        for kind in [LEASE, LEASE_GUARD, HELD, HELD_GUARD] {
            insert_exact(&tx, kind, spec.id.as_bytes(), &bytes)?;
        }
        write(&tx, old, next)?;
        if scope(&tx, spec.id)? != Some(spec) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(CatalogCheckpointRecoveryWork {
            store: self,
            spec: Some(spec),
            token: Some(token),
            closed: false,
        })
    }

    /// Reclaim at most one abandoned process scope in one short writer. A live
    /// process/start identity is never treated as stale by age or timeout.
    /// Acquisition jobs remain durable resumable debt and are never reclaimed.
    pub fn reclaim_abandoned_checkpoint_recovery_work(&self) -> Result<bool, CatalogStoreError> {
        if !self.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(old) = read(&tx)? else {
            tx.commit()?;
            return Ok(false);
        };
        let current = Owner::current(self)?;
        for spec in scopes(&tx)? {
            if spec.owner.abandoned(spec.id, current)? {
                release(&tx, old, spec)?;
                tx.commit()?;
                return Ok(true);
            }
        }
        tx.commit()?;
        Ok(false)
    }
}
