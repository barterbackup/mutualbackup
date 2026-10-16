//! Aggregate admission for anonymous catalog scratch. A declaration reserves
//! its complete physical ceiling before creating files; the scratch VFS still
//! allocates actual extents and protects filesystem headroom on every growth.
use super::checkpoint_acquisition::work_admission::live_lock::{
    self, FileLock, Identity, SlotOwner,
};
use super::*;

const LEDGER: &str = "catalog-scratch-pool-v1";
const GUARD: &str = "catalog-scratch-pool-guard-v1";
const LEASE: &str = "catalog-scratch-lease-v1";
const LEASE_GUARD: &str = "catalog-scratch-lease-guard-v1";
const MARKER: &str = "catalog_scratch_pool_version";
const KEY: &[u8] = b"store";
const BYTES: usize = 1024;
const SLOTS: u32 = 64;

/// Separate from traversal work credits and durable SQL/page quotas. These
/// limits govern the sum of complete scratch declarations, including debt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogScratchPoolPolicy {
    pub format_version: u16,
    pub physical_bytes: u64,
    pub jobs: u32,
}
impl CatalogScratchPoolPolicy {
    pub fn validate(self) -> Result<(), CatalogStoreError> {
        if self.format_version != 1
            || self.physical_bytes == 0
            || self.physical_bytes > i64::MAX as u64
            || !(1..=SLOTS).contains(&self.jobs)
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogScratchPoolUsage {
    pub policy: CatalogScratchPoolPolicy,
    pub reserved_physical_bytes: u64,
    pub open_jobs: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Ledger {
    version: u16,
    policy: CatalogScratchPoolPolicy,
    resource: [u8; 32],
    reserved: u64,
    jobs: u32,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Spec {
    version: u16,
    id: Uuid,
    physical_bytes: u64,
    domain: Uuid,
    slot: u8,
    owner: Option<Identity>,
}
impl Serialize for Spec {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.owner {
            Some(owner) => (
                self.version,
                self.id,
                self.physical_bytes,
                self.domain,
                self.slot,
                owner,
            )
                .serialize(serializer),
            None => (
                self.version,
                self.id,
                self.physical_bytes,
                self.domain,
                self.slot,
            )
                .serialize(serializer),
        }
    }
}
impl Spec {
    fn decode(bytes: &[u8]) -> Result<Self, CatalogStoreError> {
        type Owned = (u16, Uuid, u64, Uuid, u8, Identity);
        if let Ok((2, id, physical_bytes, domain, slot, owner)) = decode::<Owned>(bytes) {
            if owner.inode == 0 {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(Self {
                version: 2,
                id,
                physical_bytes,
                domain,
                slot,
                owner: Some(owner),
            });
        }
        let (version, id, physical_bytes, domain, slot): (u16, Uuid, u64, Uuid, u8) =
            decode(bytes)?;
        if version != 1 {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Self {
            version,
            id,
            physical_bytes,
            domain,
            slot,
            owner: None,
        })
    }
}
fn encoded<T: Serialize>(value: &T) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(mb_core::canonical_bytes_bounded(value, BYTES)?)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value = decode_canonical(bytes)?;
    if encoded(&value)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}
fn pair(
    cx: &Connection,
    kind: &str,
    guard: &str,
    key: &[u8],
) -> Result<Option<Vec<u8>>, CatalogStoreError> {
    let bytes = bounded_record(cx, kind, key, BYTES)?;
    if bounded_record(cx, guard, key, BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(bytes)
}
fn entries(cx: &Connection) -> Result<Vec<Spec>, CatalogStoreError> {
    let domain = live_lock::read(cx, live_lock::SCRATCH)?;
    let mut query = cx.prepare("SELECT CASE WHEN length(record_id)=16 THEN record_id END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT ?2")?;
    let mut rows = query.query(params![LEASE, SLOTS + 1])?;
    let mut values = Vec::new();
    let mut used = [false; SLOTS as usize];
    while let Some(row) = rows.next()? {
        let key: Option<Vec<u8>> = row.get(0)?;
        let key = key.ok_or(DatabaseError::Integrity)?;
        let bytes = pair(cx, LEASE, LEASE_GUARD, &key)?.ok_or(DatabaseError::Integrity)?;
        let spec = Spec::decode(&bytes)?;
        if spec.id.is_nil()
            || spec.id.as_bytes().as_slice() != key
            || spec.physical_bytes == 0
            || u32::from(spec.slot) >= SLOTS
            || domain.is_none_or(|d| d.id != spec.domain)
            || std::mem::replace(&mut used[spec.slot as usize], true)
        {
            return Err(DatabaseError::Integrity.into());
        }
        values.push(spec);
        if values.len() > SLOTS as usize {
            return Err(DatabaseError::Integrity.into());
        }
    }
    let guards: u64 = cx.query_row(
        "SELECT count(*) FROM (SELECT 1 FROM protocol_records WHERE kind=?1 LIMIT ?2)",
        params![LEASE_GUARD, SLOTS + 1],
        |r| r.get(0),
    )?;
    if guards != values.len() as u64 {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(values)
}
fn resource(cx: &Connection) -> Result<Option<[u8; 32]>, CatalogStoreError> {
    let Some(resource) = capacity_policy::resource_policy(cx)? else {
        return Ok(None);
    };
    // Recheck actual backing, not merely the saved resource envelope.
    if capacity_policy::read(cx)? != Some(resource.capacity) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(mb_core::canonical_hash_bounded(&resource, BYTES)?))
}
fn snapshot<T>(
    store: &ControlStore,
    operation: impl FnOnce(&Connection) -> Result<T, CatalogStoreError>,
) -> Result<T, CatalogStoreError> {
    if !store.connection.is_autocommit() {
        return operation(&store.connection);
    }
    let tx = store.read_snapshot()?;
    let value = operation(&tx)?;
    tx.commit()?;
    Ok(value)
}

fn read(cx: &Connection) -> Result<Option<Ledger>, CatalogStoreError> {
    let marker: Option<Option<Vec<u8>>> = cx
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            [MARKER],
            |r| r.get(0),
        )
        .optional()?;
    let Some(bytes) = pair(cx, LEDGER, GUARD, KEY)? else {
        let orphan: bool = cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1,?2,?3,?4))",
            params![
                LEASE,
                LEASE_GUARD,
                live_lock::SCRATCH.kinds[0],
                live_lock::SCRATCH.kinds[1]
            ],
            |r| r.get(0),
        )?;
        if marker.is_some() || orphan {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let ledger: Ledger = decode(&bytes)?;
    ledger.policy.validate()?;
    if !matches!(ledger.version, 1 | 2)
        || marker != Some(Some(vec![ledger.version as u8]))
        || (ledger.version == 2 && live_lock::read(cx, live_lock::SCRATCH)?.is_none())
        || resource(cx)? != Some(ledger.resource)
        || ledger.reserved > ledger.policy.physical_bytes
        || ledger.jobs > ledger.policy.jobs
    {
        return Err(DatabaseError::Integrity.into());
    }
    let mut bytes = 0_u64;
    let mut jobs = 0_u32;
    for spec in entries(cx)? {
        bytes = bytes
            .checked_add(spec.physical_bytes)
            .ok_or(DatabaseError::Integrity)?;
        jobs = jobs.checked_add(1).ok_or(DatabaseError::Integrity)?;
    }
    if (bytes, jobs) != (ledger.reserved, ledger.jobs) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(ledger))
}
fn write(cx: &Connection, old: Ledger, next: Ledger) -> Result<(), CatalogStoreError> {
    let old = encoded(&old)?;
    let bytes = encoded(&next)?;
    for kind in [LEDGER, GUARD] {
        if cx.execute(
            "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
            params![kind, KEY, bytes, old],
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
fn release(cx: &Connection, ledger: Ledger, spec: Spec) -> Result<(), CatalogStoreError> {
    let bytes = encoded(&spec)?;
    for kind in [LEASE, LEASE_GUARD] {
        if cx.execute(
            "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
            params![kind, spec.id.as_bytes(), bytes],
        )? != 1
            || bounded_record(cx, kind, spec.id.as_bytes(), BYTES)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    write(
        cx,
        ledger,
        Ledger {
            reserved: ledger
                .reserved
                .checked_sub(spec.physical_bytes)
                .ok_or(DatabaseError::Integrity)?,
            jobs: ledger.jobs.checked_sub(1).ok_or(DatabaseError::Integrity)?,
            ..ledger
        },
    )
}

/// Owned solely by a scratch VFS. It retains no SQLite connection or borrowed
/// store. The VFS closes its anonymous files before releasing the kernel slot.
/// After normal drop or process death, explicit/bounded admission reclamation
/// can return the declaration. Live slots cannot be cancelled or reclaimed.
pub struct CatalogScratchLease {
    spec: Spec,
    #[cfg(target_os = "linux")]
    _database_identity: std::fs::File,
    owner: SlotOwner,
    token: FileLock,
}
impl CatalogScratchLease {
    pub(crate) fn check_domain(
        &self,
        expected: [u8; 32],
        maximum: u64,
    ) -> Result<(), CatalogStoreError> {
        self.check(maximum)?;
        if self.token.allocation_domain()? != expected {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    pub(crate) fn check(&self, maximum_physical_bytes: u64) -> Result<(), CatalogStoreError> {
        if maximum_physical_bytes > self.spec.physical_bytes {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        self.token.check_owned()?;
        self.owner.check()
    }
}

impl ControlStore {
    /// Enroll only after the immutable resource policy and its backing exist.
    /// Record the local ownership domain in the same writer as the policy,
    /// before even the first declaration can outlive this connection. Moving
    /// only the main file cannot then detach an enrolled snapshot from its
    /// original lock rendezvous. Preserve the directory and ownership files
    /// when relocating an enrolled catalog.
    ///
    /// Older pools without a recorded domain remain readable but cannot be
    /// automatically upgraded: their live ownership may be at an unknown old
    /// location. Existing catalogs without a pool remain readable too.
    pub fn configure_catalog_scratch_pool_policy(
        &self,
        policy: CatalogScratchPoolPolicy,
    ) -> Result<(), CatalogStoreError> {
        policy.validate()?;
        if !self.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some(old) = read(&tx)? {
            if old.policy != policy {
                return Err(DatabaseError::Conflict.into());
            }
            live_lock::read(&tx, live_lock::SCRATCH)?
                .ok_or(CatalogStoreError::UnanchoredScratchPool)?;
        } else {
            let token = FileLock::admit(&tx, self, false, live_lock::SCRATCH)?;
            let ledger = Ledger {
                version: 2,
                policy,
                resource: resource(&tx)?.ok_or(DatabaseError::NotReady)?,
                reserved: 0,
                jobs: 0,
            };
            for kind in [LEDGER, GUARD] {
                insert_exact(&tx, kind, KEY, &encoded(&ledger)?)?;
            }
            if tx.execute(
                "INSERT INTO meta(key,value) VALUES (?1,?2)",
                params![MARKER, &[2_u8][..]],
            )? != 1
                || read(&tx)? != Some(ledger)
            {
                return Err(DatabaseError::Integrity.into());
            }
            token.check(self)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn catalog_scratch_pool_usage(
        &self,
    ) -> Result<Option<CatalogScratchPoolUsage>, CatalogStoreError> {
        let get = |cx: &Connection| -> Result<_, CatalogStoreError> {
            Ok(read(cx)?.map(|l| CatalogScratchPoolUsage {
                policy: l.policy,
                reserved_physical_bytes: l.reserved,
                open_jobs: l.jobs,
            }))
        };
        if !self.connection.is_autocommit() {
            return get(&self.connection);
        }
        let tx = self.read_snapshot()?;
        let value = get(&tx)?;
        tx.commit()?;
        Ok(value)
    }

    /// Reserve the full VFS physical ceiling, not its initial/observed size.
    /// One prior dead declaration may be reclaimed in its own short writer;
    /// that progress remains committed even if new admission is exhausted.
    pub fn reserve_catalog_scratch(
        &self,
        physical_bytes: u64,
    ) -> Result<Option<CatalogScratchLease>, CatalogStoreError> {
        if physical_bytes == 0 {
            return Err(DatabaseError::NotReady.into());
        }
        // Unconfigured legacy/read-only consumers need no writer or token.
        // Compose this probe with a caller's existing read/write snapshot.
        let configured = snapshot(self, |cx| {
            if read(cx)?.is_some() {
                live_lock::read(cx, live_lock::SCRATCH)?
                    .ok_or(CatalogStoreError::UnanchoredScratchPool)?;
                return Ok(true);
            }
            if capacity_policy::resource_policy(cx)?.is_some() {
                return Err(CatalogStoreError::ScratchPoolRequired);
            }
            Ok(false)
        })?;
        if !configured {
            return Ok(None);
        }
        if !self.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        self.reclaim_abandoned_catalog_scratch()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(old) = read(&tx)? else {
            if resource(&tx)?.is_some() {
                return Err(CatalogStoreError::ScratchPoolRequired);
            }
            tx.commit()?;
            return Ok(None);
        };
        live_lock::read(&tx, live_lock::SCRATCH)?
            .ok_or(CatalogStoreError::UnanchoredScratchPool)?;
        let next = Ledger {
            reserved: old
                .reserved
                .checked_add(physical_bytes)
                .ok_or(DatabaseError::CapacityExceeded)?,
            jobs: old
                .jobs
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?,
            ..old
        };
        if next.reserved > next.policy.physical_bytes || next.jobs > next.policy.jobs {
            return Err(CatalogStoreError::ScratchPoolExhausted);
        }
        let scopes = entries(&tx)?;
        if scopes.iter().any(|spec| spec.owner.is_none()) {
            return Err(DatabaseError::NotReady.into());
        }
        let token = FileLock::admit(&tx, self, !scopes.is_empty(), live_lock::SCRATCH)?;
        let mut used = [false; SLOTS as usize];
        let mut expected = [None; SLOTS as usize];
        for spec in scopes {
            used[spec.slot as usize] = true;
            expected[spec.slot as usize] =
                Some((spec.id, spec.owner.ok_or(DatabaseError::Integrity)?));
        }
        token.validate_owners(&expected)?;
        let slot = token.claim_slot(&used)?;
        #[cfg(target_os = "linux")]
        let database_identity = token.pin_database()?;
        let id = Uuid::new_v4();
        let owner = token.create_owner(slot, id)?;
        let spec = Spec {
            version: 2,
            id,
            physical_bytes,
            domain: token.domain.id,
            slot,
            owner: Some(owner.identity),
        };
        for kind in [LEASE, LEASE_GUARD] {
            insert_exact(&tx, kind, spec.id.as_bytes(), &encoded(&spec)?)?;
        }
        write(&tx, old, next)?;
        token.check(self)?;
        owner.check()?;
        tx.commit()?;
        Ok(Some(CatalogScratchLease {
            spec,
            #[cfg(target_os = "linux")]
            _database_identity: database_identity,
            owner,
            token,
        }))
    }

    /// Reclaim at most one stopped VFS declaration. Process IDs and ages grant
    /// no authority. Copies require the same proven v2 filesystem semantics as
    /// traversal scopes; unproven/live domains retain debt.
    pub fn reclaim_abandoned_catalog_scratch(&self) -> Result<bool, CatalogStoreError> {
        if !snapshot(self, |cx| Ok(read(cx)?.is_some()))? {
            return Ok(false);
        }
        if !self.connection.is_autocommit() {
            return Err(DatabaseError::NotReady.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(ledger) = read(&tx)? else {
            tx.commit()?;
            return Ok(false);
        };
        let database = Identity::database(self)?;
        let domain = live_lock::read(&tx, live_lock::SCRATCH)?;
        let mut token = None;
        for spec in entries(&tx)? {
            let domain = domain.ok_or(DatabaseError::Integrity)?;
            let abandoned = if domain.database != database {
                domain.permits_copy_reclamation()
            } else {
                if token.is_none() {
                    token = Some(FileLock::existing(self, domain, live_lock::SCRATCH)?);
                }
                token
                    .as_ref()
                    .ok_or(DatabaseError::Integrity)?
                    .try_slot(spec.slot)?
            };
            if abandoned {
                release(&tx, ledger, spec)?;
                tx.commit()?;
                return Ok(true);
            }
        }
        tx.commit()?;
        Ok(false)
    }
}

pub(super) fn validate_open(cx: &Connection) -> Result<(), DatabaseError> {
    read(cx).map(|_| ()).map_err(|error| match error {
        CatalogStoreError::Database(error) => error,
        _ => DatabaseError::Integrity,
    })
}
