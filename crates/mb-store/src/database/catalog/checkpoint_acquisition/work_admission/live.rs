//! Disposable complete-proof traversal reservations. A permit accounts work;
//! it grants no certificate, history, page, payload or publication authority.
use super::live_lock::{self, FileLock, Identity};
use super::live_owner::Owner;
use super::*;

pub(super) const SCOPE: &str = "catalog-live-recovery-work-v2";
pub(super) const SCOPE_GUARD: &str = "catalog-live-recovery-work-guard-v2";
pub(super) const LEGACY_SCOPE: &str = "catalog-live-recovery-work-v1";
pub(super) const LEGACY_GUARD: &str = "catalog-live-recovery-work-guard-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Spec {
    version: u16,
    id: Uuid,
    selected: CatalogCheckpointRecoveryTip,
    budget: Work,
    domain: Uuid,
    slot: u8,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacySpec {
    version: u16,
    id: Uuid,
    selected: CatalogCheckpointRecoveryTip,
    budget: Work,
    owner: Owner,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Entry {
    Current(Spec),
    Legacy(LegacySpec),
}
impl Entry {
    fn id(self) -> Uuid {
        match self {
            Self::Current(s) => s.id,
            Self::Legacy(s) => s.id,
        }
    }
    fn budget(self) -> Work {
        match self {
            Self::Current(s) => s.budget,
            Self::Legacy(s) => s.budget,
        }
    }
    fn kinds(self) -> (&'static str, &'static str) {
        match self {
            Self::Current(_) => (SCOPE, SCOPE_GUARD),
            Self::Legacy(_) => (LEGACY_SCOPE, LEGACY_GUARD),
        }
    }
    fn bytes(self) -> Result<Vec<u8>, CatalogStoreError> {
        Ok(match self {
            Self::Current(s) => canonical_bytes(&s)?,
            Self::Legacy(s) => canonical_bytes(&s)?,
        })
    }
    fn lease(self) -> Result<Lease, CatalogStoreError> {
        Ok(Lease {
            version: 1,
            spec_hash: match self {
                Self::Current(s) => mb_core::canonical_hash_bounded(&s, RECORD)?,
                Self::Legacy(s) => mb_core::canonical_hash_bounded(&s, RECORD)?,
            },
            budget: self.budget(),
            held: true,
        })
    }
}

fn entry(
    cx: &Connection,
    id: Uuid,
    legacy: bool,
    domain: Option<live_lock::Domain>,
) -> Result<Option<Entry>, CatalogStoreError> {
    let (kind, guard) = if legacy {
        (LEGACY_SCOPE, LEGACY_GUARD)
    } else {
        (SCOPE, SCOPE_GUARD)
    };
    let Some(bytes) = paired(cx, kind, guard, id.as_bytes())? else {
        return Ok(None);
    };
    let result = if legacy {
        let spec: LegacySpec = canonical(&bytes)?;
        spec.owner.validate()?;
        if spec.version != 1 {
            return Err(DatabaseError::Integrity.into());
        }
        Entry::Legacy(spec)
    } else {
        let spec: Spec = canonical(&bytes)?;
        if spec.version != 2
            || u32::from(spec.slot) >= CATALOG_ACQUISITION_WORK_JOBS
            || domain.is_none_or(|d| d.id != spec.domain)
        {
            return Err(DatabaseError::Integrity.into());
        }
        Entry::Current(spec)
    };
    if result.id() != id || id.is_nil() || result.budget() == Work::default() {
        return Err(DatabaseError::Integrity.into());
    }
    let expected = canonical_bytes(&result.lease()?)?;
    for (a, b) in [(LEASE, LEASE_GUARD), (HELD, HELD_GUARD)] {
        if paired(cx, a, b, id.as_bytes())?.as_deref() != Some(expected.as_slice()) {
            return Err(DatabaseError::Integrity.into());
        }
    }
    Ok(Some(result))
}
fn scope(cx: &Connection, id: Uuid) -> Result<Option<Spec>, CatalogStoreError> {
    match entry(cx, id, false, live_lock::read(cx)?)? {
        Some(Entry::Current(s)) => Ok(Some(s)),
        None => Ok(None),
        _ => Err(DatabaseError::Integrity.into()),
    }
}
fn scopes(cx: &Connection) -> Result<Vec<Entry>, CatalogStoreError> {
    let domain = live_lock::read(cx)?;
    let mut query=cx.prepare("SELECT CASE WHEN length(record_id)=16 THEN record_id END,kind FROM protocol_records WHERE kind IN (?1,?2) ORDER BY record_id,kind LIMIT ?3")?;
    let mut rows = query.query(params![
        SCOPE,
        LEGACY_SCOPE,
        u64::from(CATALOG_ACQUISITION_WORK_JOBS) + 1
    ])?;
    let mut values = Vec::new();
    let mut slots = [false; CATALOG_ACQUISITION_WORK_JOBS as usize];
    while let Some(row) = rows.next()? {
        let id: Option<Vec<u8>> = row.get(0)?;
        let kind: String = row.get(1)?;
        let id = Uuid::from_slice(&id.ok_or(DatabaseError::Integrity)?)
            .map_err(|_| DatabaseError::Integrity)?;
        let e = entry(cx, id, kind == LEGACY_SCOPE, domain)?.ok_or(DatabaseError::Integrity)?;
        if let Entry::Current(s) = e
            && std::mem::replace(&mut slots[s.slot as usize], true)
        {
            return Err(DatabaseError::Integrity.into());
        }
        values.push(e);
        if values.len() > CATALOG_ACQUISITION_WORK_JOBS as usize {
            return Err(DatabaseError::Integrity.into());
        }
    }
    let guards: u64 = cx.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM protocol_records WHERE kind IN (?1,?2) LIMIT ?3)",
        params![
            SCOPE_GUARD,
            LEGACY_GUARD,
            u64::from(CATALOG_ACQUISITION_WORK_JOBS) + 1
        ],
        |r| r.get(0),
    )?;
    if guards != values.len() as u64 {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(values)
}
pub(super) fn validate(cx: &Connection) -> Result<(), CatalogStoreError> {
    scopes(cx).map(|_| ())
}
fn release(cx: &Connection, old: Ledger, e: Entry) -> Result<(), CatalogStoreError> {
    let (kind, guard) = e.kinds();
    if entry(
        cx,
        e.id(),
        matches!(e, Entry::Legacy(_)),
        live_lock::read(cx)?,
    )? != Some(e)
    {
        return Err(DatabaseError::Integrity.into());
    }
    let next = Ledger {
        reserved: old.reserved.remaining_after(e.budget())?,
        open: old.open.checked_sub(1).ok_or(DatabaseError::Integrity)?,
        ..old
    };
    let before = canonical_bytes(&e.lease()?)?;
    for (kind, bytes) in [
        (kind, e.bytes()?),
        (guard, e.bytes()?),
        (LEASE, before.clone()),
        (LEASE_GUARD, before.clone()),
        (HELD, before.clone()),
        (HELD_GUARD, before),
    ] {
        if cx.execute(
            "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
            params![kind, e.id().as_bytes(), bytes],
        )? != 1
            || bounded_record(cx, kind, e.id().as_bytes(), RECORD)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    write(cx, old, next)?;
    Ok(())
}

/// One complete recovery traversal, sharing cumulative credits and bounded
/// slots with durable acquisitions. A kernel-held slot remains owned across
/// process/module/PID-namespace boundaries. Failed cleanup leaves visible debt.
pub struct CatalogCheckpointRecoveryWork<'a> {
    store: &'a ControlStore,
    spec: Option<Spec>,
    token: Option<FileLock>,
    closed: bool,
}
impl CatalogCheckpointRecoveryWork<'_> {
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
                Some(s)
                    if ledger.is_some_and(|l| l.state == CatalogAcquisitionWorkState::Active)
                        && scope(cx, s.id)? == Some(s) =>
                {
                    let token = self.token.as_ref().ok_or(DatabaseError::Integrity)?;
                    if live_lock::read(cx)? != Some(token.domain) {
                        return Err(DatabaseError::Integrity.into());
                    }
                    token.check(self.store)
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
    /// Release only after work stops. A failed explicit finish keeps the slot
    /// locked; Drop closes its descriptor even if SQL cleanup still fails.
    pub fn finish(&mut self) -> Result<(), CatalogStoreError> {
        if self.closed {
            return Ok(());
        }
        if !self.store.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        if let Some(s) = self.spec {
            let token = self.token.as_ref().ok_or(DatabaseError::Integrity)?;
            token.check(self.store)?;
            let tx =
                Transaction::new_unchecked(&self.store.connection, TransactionBehavior::Immediate)?;
            let old = read(&tx)?.ok_or(DatabaseError::Integrity)?;
            if live_lock::read(&tx)? != Some(token.domain) {
                return Err(DatabaseError::Integrity.into());
            }
            release(&tx, old, Entry::Current(s))?;
            tx.commit()?;
        } else {
            self.check()?;
        }
        self.token.take();
        self.closed = true;
        Ok(())
    }
}
impl Drop for CatalogCheckpointRecoveryWork<'_> {
    fn drop(&mut self) {
        let _ = self.finish();
    }
}
impl ControlStore {
    /// Reserve before scratch or ancestry traversal. The selected identity is
    /// only a work label; all original recovery/proof authority stays required.
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
        let entries = scopes(&tx)?;
        let mut used = [false; CATALOG_ACQUISITION_WORK_JOBS as usize];
        let mut has_scopes = false;
        for e in entries {
            if let Entry::Current(s) = e {
                used[s.slot as usize] = true;
                has_scopes = true;
            }
        }
        let token = FileLock::admit(&tx, self, has_scopes)?;
        let mut slot = None;
        for index in 0..CATALOG_ACQUISITION_WORK_JOBS {
            if !used[index as usize] && token.try_slot(index as u8)? {
                slot = Some(index as u8);
                break;
            }
        }
        let s = Spec {
            version: 2,
            id: Uuid::new_v4(),
            selected,
            budget,
            domain: token.domain.id,
            slot: slot.ok_or(DatabaseError::CapacityExceeded)?,
        };
        let bytes = canonical_bytes(&s)?;
        for kind in [SCOPE, SCOPE_GUARD] {
            insert_exact(&tx, kind, s.id.as_bytes(), &bytes)?;
        }
        let bytes = canonical_bytes(&Entry::Current(s).lease()?)?;
        for kind in [LEASE, LEASE_GUARD, HELD, HELD_GUARD] {
            insert_exact(&tx, kind, s.id.as_bytes(), &bytes)?;
        }
        write(&tx, old, next)?;
        if scope(&tx, s.id)? != Some(s) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(CatalogCheckpointRecoveryWork {
            store: self,
            spec: Some(s),
            token: Some(token),
            closed: false,
        })
    }
    /// Probe at most 64 slots and release at most one abandoned declaration.
    /// A PID/age/nonce never authorizes release. Durable acquisitions retain
    /// their resumable debt. Unproven legacy domains/scopes remain debt even
    /// through another pathname; an alias is not evidence of an independent copy.
    pub fn reclaim_abandoned_checkpoint_recovery_work(&self) -> Result<bool, CatalogStoreError> {
        if !self.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(old) = read(&tx)? else {
            tx.commit()?;
            return Ok(false);
        };
        let database = Identity::database(self)?;
        let domain = live_lock::read(&tx)?;
        let mut token = None;
        for e in scopes(&tx)? {
            let abandoned = match e {
                Entry::Legacy(_) => false,
                Entry::Current(s) => {
                    let domain = domain.ok_or(DatabaseError::Integrity)?;
                    if domain.database != database {
                        domain.permits_copy_reclamation()
                    } else {
                        if token.is_none() {
                            token = Some(FileLock::existing(self, domain)?);
                        }
                        token
                            .as_ref()
                            .ok_or(DatabaseError::Integrity)?
                            .try_slot(s.slot)?
                    }
                }
            };
            if abandoned {
                release(&tx, old, e)?;
                tx.commit()?;
                return Ok(true);
            }
        }
        tx.commit()?;
        Ok(false)
    }
}
