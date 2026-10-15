//! Explicit cumulative traversal credits. Per-checkpoint declarations retain
//! their original limits; complete multi-stage/recovery work shares this pool.
//! These are work credits, not SQL, payload or physical-space reservations.
use super::*;
use mb_core::CatalogCapacityPolicy;

const POLICY: &str = "catalog-traversal-pool-v1";
const POLICY_GUARD: &str = "catalog-traversal-pool-guard-v1";
const VERSION: &str = "catalog_traversal_pool_version";

/// Optional expansion of the original resource-backed acquisition work pool.
/// It never shrinks the old limit: older writers therefore retain a stricter
/// admission rule, and existing job/lease encodings are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogTraversalPoolPolicy {
    pub format_version: u16,
    pub capacity: CatalogCapacityPolicy,
    pub limit: Work,
}

impl CatalogTraversalPoolPolicy {
    pub fn validate(self) -> Result<(), CatalogStoreError> {
        if self.format_version != 1 {
            return Err(DatabaseError::Integrity.into());
        }
        self.limit.remaining_after(self.capacity.plan()?.job_work)?;
        Ok(())
    }
}

fn read(cx: &Connection) -> Result<Option<CatalogTraversalPoolPolicy>, CatalogStoreError> {
    let marker: Option<Option<Vec<u8>>> = cx
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            [VERSION],
            |row| row.get(0),
        )
        .optional()?;
    let bytes = paired(cx, POLICY, POLICY_GUARD, KEY)?;
    match (marker, bytes) {
        (None, None) => Ok(None),
        (Some(Some(marker)), Some(bytes)) if marker == [1] => {
            let policy: CatalogTraversalPoolPolicy = canonical(&bytes)?;
            policy.validate()?;
            if capacity_policy::resource_policy(cx)?.map(|value| value.capacity)
                != Some(policy.capacity)
            {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(Some(policy))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

pub(super) fn require_unconfigured(cx: &Connection) -> Result<(), CatalogStoreError> {
    if read(cx)?.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn limit(
    cx: &Connection,
    backing: CatalogResourcePolicy,
) -> Result<Work, CatalogStoreError> {
    match read(cx)? {
        Some(policy) if policy.capacity == backing.capacity => Ok(policy.limit),
        Some(_) => Err(DatabaseError::Integrity.into()),
        None => Ok(backing.capacity.plan()?.job_work),
    }
}

impl ControlStore {
    /// Install an immutable cumulative work ceiling only after existing
    /// acquisition debt has been adopted. No job, certificate or signed head is
    /// rewritten. Declared per-checkpoint and database backing limits remain.
    pub fn configure_catalog_traversal_pool_policy(
        &self,
        policy: CatalogTraversalPoolPolicy,
    ) -> Result<(), CatalogStoreError> {
        policy.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let ledger = super::read(&tx)?.ok_or(DatabaseError::NotReady)?;
        if ledger.state != CatalogAcquisitionWorkState::Active
            || policy.capacity != ledger.policy.capacity
        {
            return Err(DatabaseError::NotReady.into());
        }
        match read(&tx)? {
            Some(previous) if previous == policy => {}
            Some(_) => return Err(DatabaseError::Conflict.into()),
            None => {
                let bytes = canonical_bytes(&policy)?;
                for kind in [POLICY, POLICY_GUARD] {
                    insert_exact(&tx, kind, KEY, &bytes)?;
                }
                if tx.execute(
                    "INSERT INTO meta(key,value) VALUES (?1,?2)",
                    params![VERSION, &[1u8][..]],
                )? != 1
                {
                    return Err(DatabaseError::Integrity.into());
                }
            }
        }
        if read(&tx)? != Some(policy) || super::read(&tx)? != Some(ledger) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(())
    }

    pub fn catalog_traversal_pool_policy(
        &self,
    ) -> Result<Option<CatalogTraversalPoolPolicy>, CatalogStoreError> {
        let value = |cx: &Connection| {
            super::read(cx)?;
            read(cx)
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
