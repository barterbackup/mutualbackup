//! Explicit backing for represented catalog admission. These ceilings bind
//! actual database ledgers; they do not reserve filesystem or scratch space.

use super::*;
use crate::database::{journal_quota, page_quota, record_quota};

const POLICY: &str = "catalog-resource-policy-v1";
const GUARD: &str = "catalog-resource-policy-guard-v1";
const META: &str = "catalog_resource_policy_version";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogResourcePolicy {
    pub format_version: u16,
    pub capacity: CatalogCapacityPolicy,
    pub control_rows: u64,
    pub control_accounted_bytes: u64,
    pub control_pages: u64,
    pub control_journal_bytes: u64,
    pub immutable_page_bytes: u64,
    pub immutable_pages: u64,
    pub open_page_reservations: u32,
}

impl CatalogResourcePolicy {
    pub fn minimum_database_extents(
        capacity: CatalogCapacityPolicy,
    ) -> Result<(u64, u64), CatalogStoreError> {
        let (_, bytes) = Self::minimum_control_credits(capacity)?;
        let pages = bytes
            .checked_add(1024 * 1024)
            .ok_or(DatabaseError::CapacityExceeded)?
            .div_ceil(4096);
        let journal = pages
            .checked_mul(4096 + 24)
            .and_then(|n| n.checked_add(32))
            .ok_or(DatabaseError::CapacityExceeded)?;
        Ok((pages, journal))
    }
    /// Conservative live-cell credits for public/private metadata and durable
    /// recovery/custody indexes. Full history replay and SQL schema/index/WAL
    /// allocation keep the separately configured pager and journal ceilings.
    pub fn minimum_control_credits(
        capacity: CatalogCapacityPolicy,
    ) -> Result<(u64, u64), CatalogStoreError> {
        let plan = capacity.plan()?;
        let checked = |a: u64, b: u64| a.checked_mul(b).ok_or(DatabaseError::CapacityExceeded);
        let source_rows = checked(plan.sources_per_revision, plan.revision_occurrences)?;
        // Framed coding transcript records live inside immutable page BLOBs,
        // rather than each becoming a persistent SQL row. Charge the page row
        // and its bounded ownership/index keys independently of stream records.
        let page_rows = checked(plan.metadata_work.page_occurrences, 8)?;
        let source_index_rows = checked(source_rows, 3)?;
        let chunk_rows = checked(capacity.packed_sectors, 128)?;
        let custody_rows = checked(capacity.coding_groups, 64 * 3 + 4)?;
        let revision_rows = checked(plan.revision_occurrences, 16)?;
        let rows = page_rows
            .checked_add(source_index_rows)
            .and_then(|n| n.checked_add(chunk_rows))
            .and_then(|n| n.checked_add(custody_rows))
            .and_then(|n| n.checked_add(revision_rows))
            .and_then(|n| n.checked_add(1024))
            .ok_or(DatabaseError::CapacityExceeded)?;
        let bytes = plan
            .encoded_metadata_page_bytes
            .checked_add(plan.metadata_work.bytes)
            .and_then(|n| n.checked_add(page_rows.checked_mul(1024)?))
            .and_then(|n| n.checked_add(source_index_rows.checked_mul(1024)?))
            .and_then(|n| n.checked_add(chunk_rows.checked_mul(1024)?))
            .and_then(|n| n.checked_add(custody_rows.checked_mul(1024)?))
            .and_then(|n| n.checked_add(revision_rows.checked_mul(8192)?))
            .and_then(|n| n.checked_add(4096))
            .ok_or(DatabaseError::CapacityExceeded)?;
        Ok((rows, bytes))
    }

    pub fn validate(self) -> Result<(), CatalogStoreError> {
        let plan = self.capacity.plan()?;
        let (rows, bytes) = Self::minimum_control_credits(self.capacity)?;
        let (pages, journal_bytes) = Self::minimum_database_extents(self.capacity)?;
        if self.format_version != 1
            || self.control_rows < rows
            || self.control_accounted_bytes < bytes
            || self.control_rows > i64::MAX as u64
            || self.control_accounted_bytes > i64::MAX as u64
            || self.control_pages == 0
            || self.control_pages > u32::MAX as u64 - 1
            || self.control_pages < pages
            || self.control_journal_bytes < journal_bytes
            || self.control_journal_bytes > i64::MAX as u64
            || self.immutable_page_bytes < plan.encoded_metadata_page_bytes
            || self.immutable_page_bytes > i64::MAX as u64
            || self.immutable_pages < plan.metadata_work.page_occurrences
            || self.immutable_pages > i64::MAX as u64
            || self.open_page_reservations == 0
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        Ok(())
    }
}

pub(super) fn require_unconfigured(cx: &Connection) -> Result<(), CatalogStoreError> {
    if bounded_record(cx, POLICY, KEY, ROW_BYTES)?.is_some()
        || bounded_record(cx, GUARD, KEY, ROW_BYTES)?.is_some()
        || cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM meta WHERE key=?1)",
            [META],
            |r| r.get::<_, bool>(0),
        )?
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn read(cx: &Connection) -> Result<Option<CatalogResourcePolicy>, CatalogStoreError> {
    let enrolled: Option<Option<Vec<u8>>> = cx
        .query_row(
            "SELECT CASE WHEN length(value)=1 THEN value END FROM meta WHERE key=?1",
            [META],
            |r| r.get(0),
        )
        .optional()?;
    let a = bounded_record(cx, POLICY, KEY, ROW_BYTES)?;
    let b = bounded_record(cx, GUARD, KEY, ROW_BYTES)?;
    match (enrolled, a, b) {
        (None, None, None) => Ok(None),
        (Some(Some(marker)), Some(a), Some(b)) if marker == [1] && a == b => {
            let value: CatalogResourcePolicy = decode_canonical(&a)?;
            if canonical_bytes(&value)? != a {
                return Err(DatabaseError::Integrity.into());
            }
            value.validate()?;
            Ok(Some(value))
        }
        _ => Err(DatabaseError::Integrity.into()),
    }
}

fn backing(cx: &Connection, p: CatalogResourcePolicy) -> Result<(), CatalogStoreError> {
    record_quota::validate(cx)?;
    let records = record_quota::usage(cx)?.ok_or(DatabaseError::NotReady)?;
    let pages = page_quota::usage(cx)?.ok_or(DatabaseError::NotReady)?;
    let journal = journal_quota::usage(cx)?.ok_or(DatabaseError::NotReady)?;
    let immutable = storage_quota::usage(cx)?.ok_or(DatabaseError::NotReady)?;
    if records.state != crate::database::DatabaseRecordQuotaState::Active
        || records.quota.max_rows != p.control_rows
        || records.quota.max_accounted_bytes != p.control_accounted_bytes
        || pages.quota.max_pages != p.control_pages
        || journal.quota.max_bytes != p.control_journal_bytes
        || immutable.quota.page_bytes != p.immutable_page_bytes
        || immutable.quota.pages != p.immutable_pages
        || immutable.quota.open_reservations != p.open_page_reservations
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

pub(super) fn check(
    cx: &Connection,
    capacity: CatalogCapacityPolicy,
) -> Result<(), CatalogStoreError> {
    if let Some(policy) = read(cx)? {
        if policy.capacity != capacity {
            return Err(DatabaseError::Integrity.into());
        }
        backing(cx, policy)?;
    }
    Ok(())
}

impl ControlStore {
    /// Bind active backing ledgers in one writer without resizing them or
    /// scanning payloads. Installation preserves existing signed identities.
    pub fn configure_catalog_resource_policy(
        &self,
        policy: CatalogResourcePolicy,
    ) -> Result<(), CatalogStoreError> {
        self.configure_catalog_resource_policy_inner(policy, false)
    }

    /// Atomically bind native traversal ownership with initial resource
    /// enrollment, before any live recovery scope can outlive that state.
    /// Preserve the catalog's whole directory and ownership files on relocation.
    /// Existing unanchored enrollment cannot establish offline quiescence and
    /// cannot be automatically upgraded. Generic logical resource configuration
    /// remains available independently of native filesystem/platform support.
    pub fn configure_catalog_resource_policy_with_native_work(
        &self,
        policy: CatalogResourcePolicy,
    ) -> Result<(), CatalogStoreError> {
        self.configure_catalog_resource_policy_inner(policy, true)
    }

    fn configure_catalog_resource_policy_inner(
        &self,
        policy: CatalogResourcePolicy,
        native_work: bool,
    ) -> Result<(), CatalogStoreError> {
        policy.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if super::read(&tx)? != Some(policy.capacity) {
            return Err(DatabaseError::Conflict.into());
        }
        backing(&tx, policy)?;
        if let Some(existing) = read(&tx)? {
            if existing != policy {
                return Err(DatabaseError::Conflict.into());
            }
        } else {
            let bytes = canonical_bytes(&policy)?;
            insert_exact(&tx, POLICY, KEY, &bytes)?;
            insert_exact(&tx, GUARD, KEY, &bytes)?;
            if tx.execute(
                "INSERT INTO meta(key,value) VALUES (?1,?2)",
                params![META, &[1_u8][..]],
            )? != 1
                || read(&tx)? != Some(policy)
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        check(&tx, policy.capacity)?;
        super::super::checkpoint_acquisition::work_admission::enroll(
            &tx,
            policy,
            native_work.then_some(self),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn catalog_resource_policy(
        &self,
    ) -> Result<Option<CatalogResourcePolicy>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let value = read(&tx)?;
        if let Some(value) = value {
            if super::read(&tx)? != Some(value.capacity) {
                return Err(DatabaseError::Integrity.into());
            }
            backing(&tx, value)?;
        }
        tx.commit()?;
        Ok(value)
    }
}
