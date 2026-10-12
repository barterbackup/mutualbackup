//! Published revision occurrences, not unique physical pages or data sources.
//! Cancellation frees this exposure budget atomically; pending cleanup remains
//! charged by the independent page, data-source and all-table record ledgers.

use mb_core::{
    CATALOG_MAX_RECORDS, CatalogCodingTraversalBudget as Work, PAGED_USER_REVISION_BYTES,
    V1_SECTOR_SIZE,
};

use super::*;

const POLICY: &str = "catalog-published-revision-policy-v1";
const ENABLED: &str = "catalog-published-revision-enabled-v1";
const TOTALS: &str = "catalog-published-revision-totals-v1";
const SCOPE_ENABLED: &str = "catalog-published-revision-scope-v1";
const CHARGE: &str = "catalog-published-revision-charge-v1";
const ROW_BYTES: usize = 1024;
const KEY: &[u8] = b"store";

/// Independently declared limits on published retained revisions and their
/// represented metadata work. Every repeated root/source occurrence is charged.
/// This does not bound SQL/WAL, scratch, filesystem allocation or CPU replays.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPublishedRevisionQuota {
    pub revisions: u64,
    pub work: Work,
}

impl CatalogPublishedRevisionQuota {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if [
            self.revisions,
            self.work.bytes,
            self.work.page_occurrences,
            self.work.records,
        ]
        .iter()
        .any(|n| *n > i64::MAX as u64)
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }

    fn covers(self, used: Self) -> Result<(), CatalogStoreError> {
        self.validate()?;
        if used.revisions > self.revisions
            || used.work.bytes > self.work.bytes
            || used.work.page_occurrences > self.work.page_occurrences
            || used.work.records > self.work.records
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }

    fn add(self, amount: Self) -> Result<Self, CatalogStoreError> {
        Ok(Self {
            revisions: self
                .revisions
                .checked_add(amount.revisions)
                .ok_or(DatabaseError::CapacityExceeded)?,
            work: self.work.checked_add(amount.work)?,
        })
    }

    fn subtract(self, amount: Self) -> Result<Self, CatalogStoreError> {
        Ok(Self {
            revisions: self
                .revisions
                .checked_sub(amount.revisions)
                .ok_or(DatabaseError::Integrity)?,
            work: self.work.remaining_after(amount.work)?,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPublishedRevisionQuotaState {
    Adopting,
    Active,
    Aborting,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPublishedRevisionQuotas {
    pub global: CatalogPublishedRevisionQuota,
    pub dataset: CatalogPublishedRevisionQuota,
    pub guild: CatalogPublishedRevisionQuota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPublishedRevisionQuotaScope {
    Global,
    Dataset(CatalogScope),
    Guild([u8; 32]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogPublishedRevisionQuotaUsage {
    pub state: CatalogPublishedRevisionQuotaState,
    pub quota: CatalogPublishedRevisionQuota,
    pub used: CatalogPublishedRevisionQuota,
    pub cursor: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Policy {
    version: u16,
    quotas: CatalogPublishedRevisionQuotas,
    state: CatalogPublishedRevisionQuotaState,
    cursor: Option<Uuid>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Total {
    version: u16,
    scope: CatalogPublishedRevisionQuotaScope,
    used: CatalogPublishedRevisionQuota,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Charge {
    version: u16,
    id: Uuid,
    scope: CatalogScope,
    bundle_hash: [u8; 32],
    amount: CatalogPublishedRevisionQuota,
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value = decode_canonical(bytes)?;
    if mb_core::canonical_bytes_bounded(&value, ROW_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

fn exact<T: Serialize>(
    connection: &Connection,
    kind: &str,
    key: &[u8],
    previous: Option<&[u8]>,
    value: &T,
) -> Result<(), CatalogStoreError> {
    let bytes = mb_core::canonical_bytes_bounded(value, ROW_BYTES)?;
    if let Some(previous) = previous {
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3", params![kind, key, previous, bytes])? != 1 {
            return Err(DatabaseError::Integrity.into());
        }
    } else {
        insert_exact(connection, kind, key, &bytes)?;
    }
    if bounded_record(connection, kind, key, ROW_BYTES)?.as_deref() != Some(bytes.as_slice()) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn erase(
    connection: &Connection,
    kind: &str,
    key: &[u8],
    bytes: &[u8],
) -> Result<(), CatalogStoreError> {
    if connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
        params![kind, key, bytes],
    )? != 1
        || bounded_record(connection, kind, key, ROW_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn policy(connection: &Connection) -> Result<Option<Policy>, CatalogStoreError> {
    let enabled = bounded_record(connection, ENABLED, KEY, 1)?;
    let bytes = bounded_record(connection, POLICY, KEY, ROW_BYTES)?;
    match (enabled.as_deref(), bytes) {
        (None, None) => {
            let orphan: bool = connection.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (?1, ?2, ?3))",
                params![TOTALS, CHARGE, SCOPE_ENABLED],
                |row| row.get(0),
            )?;
            if orphan {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(None)
        }
        (Some([1]), Some(bytes)) => {
            let policy: Policy = decode(&bytes)?;
            if policy.version != 1 || policy.cursor.is_some_and(|id| id.is_nil()) {
                return Err(DatabaseError::Integrity.into());
            }
            for limit in [
                policy.quotas.global,
                policy.quotas.dataset,
                policy.quotas.guild,
            ] {
                limit.validate()?;
            }
            Ok(Some(policy))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn scope_key(scope: CatalogPublishedRevisionQuotaScope) -> Result<[u8; 32], CatalogStoreError> {
    if let CatalogPublishedRevisionQuotaScope::Dataset(dataset) = scope {
        dataset.validate(CatalogSection::SectorReferences)?;
    }
    let mut hash = blake3::Hasher::new_derive_key("mutualbackup published revision quota scope v1");
    hash.update(&canonical_bytes(&scope)?);
    Ok(*hash.finalize().as_bytes())
}

fn scopes(
    dataset: CatalogScope,
) -> Result<[CatalogPublishedRevisionQuotaScope; 3], CatalogStoreError> {
    let CatalogScope::Dataset { guild_id, .. } = dataset else {
        return Err(DatabaseError::Integrity.into());
    };
    Ok([
        CatalogPublishedRevisionQuotaScope::Global,
        CatalogPublishedRevisionQuotaScope::Dataset(dataset),
        CatalogPublishedRevisionQuotaScope::Guild(guild_id),
    ])
}

fn limit(
    policy: Policy,
    scope: CatalogPublishedRevisionQuotaScope,
) -> CatalogPublishedRevisionQuota {
    match scope {
        CatalogPublishedRevisionQuotaScope::Global => policy.quotas.global,
        CatalogPublishedRevisionQuotaScope::Dataset(_) => policy.quotas.dataset,
        CatalogPublishedRevisionQuotaScope::Guild(_) => policy.quotas.guild,
    }
}

fn total(
    connection: &Connection,
    policy: Policy,
    scope: CatalogPublishedRevisionQuotaScope,
) -> Result<CatalogPublishedRevisionQuota, CatalogStoreError> {
    let key = scope_key(scope)?;
    let enabled = bounded_record(connection, SCOPE_ENABLED, &key, 1)?;
    let bytes = match (
        enabled.as_deref(),
        bounded_record(connection, TOTALS, &key, ROW_BYTES)?,
    ) {
        (None, None) if scope != CatalogPublishedRevisionQuotaScope::Global => {
            return Ok(CatalogPublishedRevisionQuota::default());
        }
        (Some([1]), Some(bytes)) => bytes,
        _ => return Err(DatabaseError::Integrity.into()),
    };
    let value: Total = decode(&bytes)?;
    if value.version != 1
        || value.scope != scope
        || (value.used.revisions == 0 && value.used.work != Work::default())
    {
        return Err(DatabaseError::Integrity.into());
    }
    limit(policy, scope).covers(value.used)?;
    Ok(value.used)
}

/// Count known source records exactly; private record framing supplies a
/// conservative count without decrypting or reading a payload. Private record
/// streams have an eight-byte header, four-byte length and nonempty record.
fn charge(bundle: &CatalogBundle) -> Result<Charge, CatalogStoreError> {
    let signed = paged_revision::revision(bundle)?;
    let mut work = Work {
        bytes: (PAGED_USER_REVISION_BYTES + V1_SECTOR_SIZE + 8 * 1024) as u64,
        page_occurrences: 0,
        records: 1,
    };
    for member in &bundle.roots {
        let records = if member.intent.section == CatalogSection::SectorReferences {
            signed.value.sources.records.records
        } else {
            member
                .root
                .byte_len
                .checked_sub(8)
                .ok_or(DatabaseError::Integrity)?
                / 5
        }
        .min(CATALOG_MAX_RECORDS);
        work = work.checked_add(Work {
            bytes: member.root.byte_len,
            page_occurrences: member.root.page_occurrences,
            records,
        })?;
    }
    Ok(Charge {
        version: 1,
        id: bundle.id,
        scope: bundle.scope,
        bundle_hash: mb_core::canonical_hash_bounded(bundle, 8 * 1024)?,
        amount: CatalogPublishedRevisionQuota { revisions: 1, work },
    })
}

fn read_charge(connection: &Connection, id: Uuid) -> Result<Option<Charge>, CatalogStoreError> {
    let Some(bytes) = bounded_record(connection, CHARGE, id.as_bytes(), ROW_BYTES)? else {
        return Ok(None);
    };
    let value: Charge = decode(&bytes)?;
    scopes(value.scope)?;
    if value.version != 1
        || value.id != id
        || id.is_nil()
        || value.bundle_hash == [0; 32]
        || value.amount.revisions != 1
        || value.amount.work.bytes == 0
        || value.amount.work.page_occurrences == 0
        || value.amount.work.records == 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(value))
}

fn totals(
    connection: &Connection,
    policy: Policy,
    value: Charge,
) -> Result<[CatalogPublishedRevisionQuota; 3], CatalogStoreError> {
    let scopes = scopes(value.scope)?;
    Ok([
        total(connection, policy, scopes[0])?,
        total(connection, policy, scopes[1])?,
        total(connection, policy, scopes[2])?,
    ])
}

fn require_totals(
    connection: &Connection,
    policy: Policy,
    value: Charge,
    expected: [CatalogPublishedRevisionQuota; 3],
) -> Result<(), CatalogStoreError> {
    if totals(connection, policy, value)? != expected || self::policy(connection)? != Some(policy) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn change(
    connection: &Connection,
    expected_policy: Policy,
    value: Charge,
    add: bool,
) -> Result<[CatalogPublishedRevisionQuota; 3], CatalogStoreError> {
    let mut planned = Vec::with_capacity(3);
    for scope in scopes(value.scope)? {
        let key = scope_key(scope)?;
        let previous = bounded_record(connection, TOTALS, &key, ROW_BYTES)?;
        let old = total(connection, expected_policy, scope)?;
        let used = if add {
            old.add(value.amount)?
        } else {
            old.subtract(value.amount)?
        };
        limit(expected_policy, scope).covers(used)?;
        planned.push((scope, key, previous, used));
    }
    let expected = [planned[0].3, planned[1].3, planned[2].3];
    for (scope, key, previous, used) in planned {
        exact(
            connection,
            TOTALS,
            &key,
            previous.as_deref(),
            &Total {
                version: 1,
                scope,
                used,
            },
        )?;
        if previous.is_none() {
            insert_exact(connection, SCOPE_ENABLED, &key, &[1])?;
        }
    }
    require_totals(connection, expected_policy, value, expected)?;
    Ok(expected)
}

pub(super) struct Guard {
    policy: Option<Policy>,
    value: Option<Charge>,
    id: Uuid,
    expected: Option<[CatalogPublishedRevisionQuota; 3]>,
    published: bool,
}

impl Guard {
    pub(super) fn recheck(&self, connection: &Connection) -> Result<(), CatalogStoreError> {
        if policy(connection)? != self.policy {
            return Err(DatabaseError::Integrity.into());
        }
        if let (Some(policy), Some(value), Some(expected)) =
            (self.policy, self.value, self.expected)
        {
            require_totals(connection, policy, value, expected)?;
            if read_charge(connection, self.id)? != self.published.then_some(value) {
                return Err(DatabaseError::Integrity.into());
            }
        }
        Ok(())
    }
}

fn acquire(
    connection: &Connection,
    policy: Policy,
    bundle: &CatalogBundle,
) -> Result<Guard, CatalogStoreError> {
    let value = charge(bundle)?;
    if let Some(old) = read_charge(connection, bundle.id)? {
        if old != value {
            return Err(DatabaseError::Integrity.into());
        }
        for scope in scopes(value.scope)? {
            total(connection, policy, scope)?.subtract(value.amount)?;
        }
        return Ok(Guard {
            policy: Some(policy),
            value: Some(value),
            id: bundle.id,
            expected: Some(totals(connection, policy, value)?),
            published: true,
        });
    }
    let expected = change(connection, policy, value, true)?;
    exact(connection, CHARGE, bundle.id.as_bytes(), None, &value)?;
    let guard = Guard {
        policy: Some(policy),
        value: Some(value),
        id: bundle.id,
        expected: Some(expected),
        published: true,
    };
    guard.recheck(connection)?;
    Ok(guard)
}

pub(super) fn check(
    connection: &Connection,
    bundle: &CatalogBundle,
) -> Result<(), CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(());
    };
    if policy.state != CatalogPublishedRevisionQuotaState::Active {
        return Err(DatabaseError::Conflict.into());
    }
    let value = charge(bundle)?;
    if let Some(old) = read_charge(connection, bundle.id)? {
        if old != value {
            return Err(DatabaseError::Integrity.into());
        }
        for scope in scopes(value.scope)? {
            total(connection, policy, scope)?.subtract(value.amount)?;
        }
    } else {
        for scope in scopes(value.scope)? {
            limit(policy, scope).covers(total(connection, policy, scope)?.add(value.amount)?)?;
        }
    }
    Ok(())
}

pub(super) fn publish(
    connection: &Connection,
    bundle: &CatalogBundle,
) -> Result<Guard, CatalogStoreError> {
    check(connection, bundle)?;
    if let Some(policy) = policy(connection)? {
        acquire(connection, policy, bundle)
    } else {
        Ok(Guard {
            policy: None,
            value: None,
            id: bundle.id,
            expected: None,
            published: true,
        })
    }
}

pub(super) fn cancel(
    connection: &Connection,
    bundle: &CatalogBundle,
) -> Result<Guard, CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(Guard {
            policy: None,
            value: None,
            id: bundle.id,
            expected: None,
            published: false,
        });
    };
    if policy.state != CatalogPublishedRevisionQuotaState::Active {
        return Err(DatabaseError::Conflict.into());
    }
    let value = read_charge(connection, bundle.id)?.ok_or(DatabaseError::Integrity)?;
    if value != charge(bundle)? {
        return Err(DatabaseError::Integrity.into());
    }
    let expected = change(connection, policy, value, false)?;
    erase(
        connection,
        CHARGE,
        bundle.id.as_bytes(),
        &canonical_bytes(&value)?,
    )?;
    let guard = Guard {
        policy: Some(policy),
        value: Some(value),
        id: bundle.id,
        expected: Some(expected),
        published: false,
    };
    guard.recheck(connection)?;
    Ok(guard)
}

pub(super) fn validate_publication(
    connection: &Connection,
    bundle: &CatalogBundle,
    state: CatalogBundleState,
) -> Result<(), CatalogStoreError> {
    let Some(policy) = policy(connection)? else {
        return Ok(());
    };
    if policy.state != CatalogPublishedRevisionQuotaState::Active {
        return Ok(());
    }
    match (state, read_charge(connection, bundle.id)?) {
        (CatalogBundleState::Published, Some(value)) if value == charge(bundle)? => {
            for scope in scopes(value.scope)? {
                total(connection, policy, scope)?.subtract(value.amount)?;
            }
            Ok(())
        }
        (CatalogBundleState::Cancelled, None) => Ok(()),
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn usage(
    connection: &Connection,
    policy: Policy,
    scope: CatalogPublishedRevisionQuotaScope,
) -> Result<CatalogPublishedRevisionQuotaUsage, CatalogStoreError> {
    // Aborting dismantles only these derived rows, one per transaction. Its
    // partial totals are not an admitted exposure ledger.
    let used = if policy.state == CatalogPublishedRevisionQuotaState::Aborting {
        CatalogPublishedRevisionQuota::default()
    } else {
        total(connection, policy, scope)?
    };
    Ok(CatalogPublishedRevisionQuotaUsage {
        state: policy.state,
        quota: limit(policy, scope),
        used,
        cursor: policy.cursor,
    })
}

impl ControlStore {
    pub fn catalog_published_revision_quota_usage(
        &self,
        scope: CatalogPublishedRevisionQuotaScope,
    ) -> Result<Option<CatalogPublishedRevisionQuotaUsage>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let value = policy(&tx)?
            .map(|policy| usage(&tx, policy, scope))
            .transpose()?;
        tx.commit()?;
        Ok(value)
    }

    /// Read-only early preflight. Publication repeats this check under its
    /// Immediate writer; another publisher cannot overbook between the checks.
    pub fn check_catalog_published_revision_capacity(
        &self,
        bundle: &CatalogBundle,
    ) -> Result<(), CatalogStoreError> {
        let tx = self.read_snapshot()?;
        check(&tx, bundle)?;
        tx.commit()?;
        Ok(())
    }

    pub fn begin_catalog_published_revision_quota_adoption(
        &self,
        quotas: CatalogPublishedRevisionQuotas,
    ) -> Result<CatalogPublishedRevisionQuotaUsage, CatalogStoreError> {
        for value in [quotas.global, quotas.dataset, quotas.guild] {
            value.validate()?;
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let next = if let Some(previous) = policy(&tx)? {
            if previous.state == CatalogPublishedRevisionQuotaState::Aborting {
                return Err(DatabaseError::Conflict.into());
            }
            for (new, old) in [
                (quotas.global, previous.quotas.global),
                (quotas.dataset, previous.quotas.dataset),
                (quotas.guild, previous.quotas.guild),
            ] {
                new.covers(old)?;
            }
            let next = Policy { quotas, ..previous };
            exact(&tx, POLICY, KEY, Some(&canonical_bytes(&previous)?), &next)?;
            next
        } else {
            let next = Policy {
                version: 1,
                quotas,
                state: CatalogPublishedRevisionQuotaState::Adopting,
                cursor: None,
            };
            exact(&tx, POLICY, KEY, None, &next)?;
            insert_exact(&tx, ENABLED, KEY, &[1])?;
            let scope = CatalogPublishedRevisionQuotaScope::Global;
            let key = scope_key(scope)?;
            exact(
                &tx,
                TOTALS,
                &key,
                None,
                &Total {
                    version: 1,
                    scope,
                    used: CatalogPublishedRevisionQuota::default(),
                },
            )?;
            insert_exact(&tx, SCOPE_ENABLED, &key, &[1])?;
            next
        };
        if policy(&tx)? != Some(next) {
            return Err(DatabaseError::Integrity.into());
        }
        let value = usage(&tx, next, CatalogPublishedRevisionQuotaScope::Global)?;
        tx.commit()?;
        Ok(value)
    }

    /// One bounded publication locator and one original root manifest per
    /// transaction. Reads the bounded root/64 KiB bootstrap but no catalog page
    /// or data payload. Cancellation/publication remain frozen until indexed EOF.
    pub fn resume_catalog_published_revision_quota_adoption(
        &self,
    ) -> Result<CatalogPublishedRevisionQuotaUsage, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous = policy(&tx)?.ok_or(DatabaseError::NotReady)?;
        if previous.state != CatalogPublishedRevisionQuotaState::Adopting {
            return Err(DatabaseError::Conflict.into());
        }
        let after = previous.cursor.map(|id| id.as_bytes().to_vec());
        let key: Option<Option<Vec<u8>>> = tx.query_row(
            "SELECT CASE WHEN length(record_id) = 16 THEN record_id END FROM protocol_records WHERE kind = ?1 AND (?2 IS NULL OR record_id > ?2) ORDER BY record_id LIMIT 1",
            params![paged_revision::PUBLICATION, after], |row| row.get(0),
        ).optional()?;
        let mut guard = None;
        let next = if let Some(key) = key {
            let id = Uuid::from_slice(&key.ok_or(DatabaseError::Integrity)?)
                .map_err(|_| DatabaseError::Integrity)?;
            if id.is_nil() {
                return Err(DatabaseError::Integrity.into());
            }
            let catalog = paged_revision::snapshot(&tx, id)?.ok_or(DatabaseError::Integrity)?;
            if catalog.state == CatalogBundleState::Published {
                guard = Some(acquire(&tx, previous, &catalog.bundle)?);
            }
            Policy {
                cursor: Some(id),
                ..previous
            }
        } else {
            Policy {
                state: CatalogPublishedRevisionQuotaState::Active,
                ..previous
            }
        };
        exact(&tx, POLICY, KEY, Some(&canonical_bytes(&previous)?), &next)?;
        if policy(&tx)? != Some(next) {
            return Err(DatabaseError::Integrity.into());
        }
        if let Some(mut guard) = guard {
            guard.policy = Some(next);
            guard.recheck(&tx)?;
        }
        let value = usage(&tx, next, CatalogPublishedRevisionQuotaScope::Global)?;
        tx.commit()?;
        Ok(value)
    }

    /// Abort only incomplete adoption. Each call removes at most one quota
    /// charge or total; original publication/bundle/source rows are untouched.
    /// Returns true while cleanup remains, false after removing the policy.
    pub fn abort_catalog_published_revision_quota_adoption(
        &self,
    ) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let Some(previous) = policy(&tx)? else {
            return Ok(false);
        };
        if previous.state == CatalogPublishedRevisionQuotaState::Active {
            return Err(DatabaseError::Conflict.into());
        }
        let aborting = Policy {
            state: CatalogPublishedRevisionQuotaState::Aborting,
            ..previous
        };
        if previous != aborting {
            exact(
                &tx,
                POLICY,
                KEY,
                Some(&canonical_bytes(&previous)?),
                &aborting,
            )?;
        }
        let mut removed = false;
        for kind in [CHARGE, TOTALS, SCOPE_ENABLED] {
            let key: Option<Option<Vec<u8>>> = tx.query_row("SELECT CASE WHEN length(record_id) <= 32 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1", params![kind], |row| row.get(0)).optional()?;
            if let Some(key) = key {
                let key = key.ok_or(DatabaseError::Integrity)?;
                let bytes =
                    bounded_record(&tx, kind, &key, ROW_BYTES)?.ok_or(DatabaseError::Integrity)?;
                erase(&tx, kind, &key, &bytes)?;
                removed = true;
                break;
            }
        }
        if !removed {
            erase(&tx, POLICY, KEY, &canonical_bytes(&aborting)?)?;
            erase(&tx, ENABLED, KEY, &[1])?;
            if policy(&tx)?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
        } else if policy(&tx)? != Some(aborting) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(removed)
    }
}

#[cfg(test)]
mod tests;
