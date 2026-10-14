//! Durable enclosing contract. Existing ledgers retain their original identities
//! and atomic counters; this policy adds limits rather than replacing them.

use super::*;
use mb_core::{CatalogCapacityPolicy, CatalogCodingTraversalBudget as Work};

const POLICY: &str = "catalog-capacity-policy-v1";
const GUARD: &str = "catalog-capacity-policy-guard-v1";
const ENABLED: &str = "catalog-capacity-policy-enabled-v1";
const META: &str = "catalog_capacity_policy_version";
const KEY: &[u8] = b"store";
const ROW_BYTES: usize = 4096;
mod resources;
pub use resources::CatalogResourcePolicy;

pub(super) fn resource_policy(
    connection: &Connection,
) -> Result<Option<CatalogResourcePolicy>, CatalogStoreError> {
    resources::read(connection)
}

pub(super) fn read(
    connection: &Connection,
) -> Result<Option<CatalogCapacityPolicy>, CatalogStoreError> {
    let enabled = bounded_record(connection, ENABLED, KEY, 1)?;
    let policy = bounded_record(connection, POLICY, KEY, ROW_BYTES)?;
    let guard = bounded_record(connection, GUARD, KEY, ROW_BYTES)?;
    let enrolled: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            params![META],
            |row| row.get(0),
        )
        .optional()?;
    match (
        enrolled.as_ref().and_then(|value| value.as_deref()),
        enrolled.is_some(),
        enabled.as_deref(),
        policy,
        guard,
    ) {
        (None, false, None, None, None) => {
            resources::require_unconfigured(connection)?;
            Ok(None)
        }
        (Some([1]), true, Some([1]), Some(bytes), Some(guard)) if bytes == guard => {
            let value: CatalogCapacityPolicy = decode_canonical(&bytes)?;
            if mb_core::canonical_bytes_bounded(&value, ROW_BYTES)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            value.plan()?;
            resources::check(connection, value)?;
            Ok(Some(value))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

pub(super) fn revision_limit(
    connection: &Connection,
    scope: CatalogPublishedRevisionQuotaScope,
) -> Result<Option<CatalogPublishedRevisionQuota>, CatalogStoreError> {
    read(connection)?
        .map(|policy| {
            let plan = policy.plan()?;
            let count = if matches!(scope, CatalogPublishedRevisionQuotaScope::Dataset(_)) {
                policy.revisions_per_dataset
            } else {
                plan.revision_occurrences
            };
            Ok(CatalogPublishedRevisionQuota {
                revisions: count,
                work: Work {
                    bytes: plan
                        .revision_work
                        .bytes
                        .checked_mul(count)
                        .ok_or(DatabaseError::CapacityExceeded)?,
                    page_occurrences: plan
                        .revision_work
                        .page_occurrences
                        .checked_mul(count)
                        .ok_or(DatabaseError::CapacityExceeded)?,
                    records: plan
                        .revision_work
                        .records
                        .checked_mul(count)
                        .ok_or(DatabaseError::CapacityExceeded)?,
                },
            })
        })
        .transpose()
}

pub(super) fn data_limit(
    connection: &Connection,
    scope: CatalogScope,
) -> Result<Option<CatalogRetainedSourceQuota>, CatalogStoreError> {
    read(connection)?
        .map(|policy| {
            let count = if matches!(scope, CatalogScope::Dataset { .. }) {
                1
            } else {
                u64::from(policy.datasets)
            };
            Ok(CatalogRetainedSourceQuota {
                logical_bytes: policy
                    .data_bytes_per_dataset
                    .checked_mul(count)
                    .ok_or(DatabaseError::CapacityExceeded)?,
                sources: policy
                    .data_sources_per_dataset
                    .checked_mul(count)
                    .ok_or(DatabaseError::CapacityExceeded)?,
                open_reservations: u32::MAX,
            })
        })
        .transpose()
}

fn private_work(bundle: &CatalogBundle) -> Result<Work, CatalogStoreError> {
    let mut result = Work::default();
    for member in bundle
        .roots
        .iter()
        .filter(|root| root.intent.section.is_private())
    {
        result = result.checked_add(Work {
            bytes: member.root.byte_len,
            page_occurrences: member.root.page_occurrences,
            records: (member
                .root
                .byte_len
                .checked_sub(8)
                .ok_or(DatabaseError::Integrity)?
                / 5)
            .min(mb_core::CATALOG_MAX_RECORDS),
        })?;
    }
    Ok(result)
}

pub(super) struct PublicationGuard(Option<CatalogCapacityPolicy>);
pub(super) struct Guard(Option<CatalogCapacityPolicy>);
pub(super) fn guard(connection: &Connection) -> Result<Guard, CatalogStoreError> {
    Ok(Guard(read(connection)?))
}
impl Guard {
    pub(super) fn policy(&self) -> Option<CatalogCapacityPolicy> {
        self.0
    }
    pub(super) fn recheck(&self, connection: &Connection) -> Result<(), CatalogStoreError> {
        if read(connection)? != self.0 {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }
}
impl PublicationGuard {
    pub(super) fn recheck(
        &self,
        connection: &Connection,
        bundle: &CatalogBundle,
    ) -> Result<(), CatalogStoreError> {
        if read(connection)? != self.0 {
            return Err(DatabaseError::Conflict.into());
        }
        if let Some(policy) = self.0 {
            policy.admit_revision(
                &paged_revision::revision(bundle)?.value,
                private_work(bundle)?,
            )?;
            // Both bounded ledgers are required. Reads reapply the enclosing
            // limits, including changes attempted by a later trigger/callback.
            revision_quota::require_capacity_backing(connection)?;
            retained_source_quota::require_capacity_backing(connection)?;
            retained_source_quota::check_capacity_usage(connection, bundle.scope)?;
        }
        Ok(())
    }
}
pub(super) fn publication(
    connection: &Connection,
    bundle: &CatalogBundle,
) -> Result<PublicationGuard, CatalogStoreError> {
    let guard = PublicationGuard(read(connection)?);
    guard.recheck(connection, bundle)?;
    Ok(guard)
}

impl ControlStore {
    /// Recheck an immutable enclosing contract in the caller's current writer,
    /// or a fresh read snapshot when no transaction is held. This never commits
    /// or rolls back the caller's writer and keeps backing-ledger checks intact.
    pub fn check_catalog_capacity_policy(
        &self,
        expected: CatalogCapacityPolicy,
    ) -> Result<(), CatalogStoreError> {
        let check = |connection: &Connection| {
            if read(connection)? != Some(expected) {
                return Err(DatabaseError::Conflict.into());
            }
            revision_quota::require_capacity_backing(connection)?;
            retained_source_quota::require_capacity_backing(connection)?;
            Ok(())
        };
        if !self.connection.is_autocommit() {
            check(&self.connection)
        } else {
            let tx = self.read_snapshot()?;
            check(&tx)?;
            tx.commit()?;
            Ok(())
        }
    }

    pub fn catalog_capacity_policy(
        &self,
    ) -> Result<Option<CatalogCapacityPolicy>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let value = read(&tx)?;
        if value.is_some() {
            revision_quota::require_capacity_backing(&tx)?;
            retained_source_quota::require_capacity_backing(&tx)?;
        }
        tx.commit()?;
        Ok(value)
    }

    /// Establish an immutable contract on an empty retained catalog. Existing
    /// owners need explicit adoption; refusal performs no history/payload scan.
    /// The independent revision and unique-data ledgers must already be active.
    pub fn configure_catalog_capacity_policy(
        &self,
        policy: CatalogCapacityPolicy,
    ) -> Result<(), CatalogStoreError> {
        policy.plan()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if let Some(old) = read(&tx)? {
            if old != policy {
                return Err(DatabaseError::Conflict.into());
            }
            tx.commit()?;
            return Ok(());
        }
        revision_quota::require_capacity_backing(&tx)?;
        retained_source_quota::require_capacity_backing(&tx)?;
        revision_quota::require_capacity_backing_for(&tx, policy)?;
        retained_source_quota::require_capacity_backing_for(&tx, policy)?;
        let existing: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind IN (
             'catalog-paged-publication-v1', 'catalog-paged-checkpoint-retention-v1',
             'catalog-directory-checkpoint-retention-v1', 'catalog-retained-source-charge-v1',
             'catalog-retained-source-reservation-v1'))",
            [],
            |row| row.get(0),
        )?;
        if existing {
            return Err(DatabaseError::NotReady.into());
        }
        let bytes = mb_core::canonical_bytes_bounded(&policy, ROW_BYTES)?;
        insert_exact(&tx, POLICY, KEY, &bytes)?;
        insert_exact(&tx, GUARD, KEY, &bytes)?;
        insert_exact(&tx, ENABLED, KEY, &[1])?;
        if tx.execute(
            "INSERT INTO meta(key,value) VALUES (?1,?2)",
            params![META, &[1_u8][..]],
        )? != 1
        {
            return Err(DatabaseError::Integrity.into());
        }
        if read(&tx)? != Some(policy) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
