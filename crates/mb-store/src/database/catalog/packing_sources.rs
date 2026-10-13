//! Durable loans of published revision custody to pending packing operations.
//! Source authority and current-base checks remain with the enclosing operation.

use mb_core::{CatalogCodingTraversalBudget as Work, PagedUserRevision, SignedRecord};

use super::*;

const JOURNAL: &str = "catalog-packing-source-retention-v1";
const OWNER_COUNT: &str = "catalog-packing-source-owner-count-v1";
const ROW_BYTES: usize = 512;

fn revisions(id: Uuid) -> String {
    format!("catalog-packing-source-revision-v1/{}", id.simple())
}

fn owners(id: Uuid) -> String {
    format!("catalog-revision-packing-owner-v1/{}", id.simple())
}

/// Immutable local admission for a packing operation. The original base must
/// come from the independently established checkpoint chain. The budget is
/// supplied after enclosing admission, never learned from peer metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingSourceRetention {
    pub id: Uuid,
    pub base: CatalogPackingAuthorityBase,
    pub budget: Work,
}

impl CatalogPackingSourceRetention {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil()
            || self.base.guild_id == [0; 32]
            || self.base.checkpoint_hash == [0; 32]
            || self.base.generation == 0
            || self.base.membership_epoch == Some(0)
        {
            return Err(DatabaseError::Conflict.into());
        }
        self.budget.remaining_after(journal_work())?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackingSourceRetentionState {
    Building,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Journal {
    version: u16,
    retention: CatalogPackingSourceRetention,
    state: CatalogPackingSourceRetentionState,
    dependencies: u64,
    work: Work,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Dependency {
    version: u16,
    bundle_hash: [u8; 32],
    work: Work,
}

fn journal_work() -> Work {
    Work {
        bytes: ROW_BYTES as u64,
        page_occurrences: 0,
        records: 1,
    }
}

fn dependency(catalog: &PagedCatalogSnapshot) -> Result<Dependency, CatalogStoreError> {
    catalog.bundle.validate()?;
    if catalog.state != CatalogBundleState::Published {
        return Err(DatabaseError::Conflict.into());
    }
    let bootstrap = catalog.bootstrap.as_ref().ok_or(DatabaseError::Integrity)?;
    let mut work = Work {
        bytes: bootstrap.len() as u64 + 3 * ROW_BYTES as u64,
        page_occurrences: 0,
        records: 3,
    };
    // Every root remains owned by the original bundle. A loan neither copies
    // trees nor takes over their source/quota/physical-anchor charges.
    for member in &catalog.bundle.roots {
        work = work.checked_add(Work {
            bytes: member.root.byte_len,
            page_occurrences: member.root.page_occurrences,
            records: 0,
        })?;
    }
    Ok(Dependency {
        version: 1,
        bundle_hash: mb_core::canonical_hash_bounded(&catalog.bundle, 8192)?,
        work,
    })
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(mb_core::canonical_bytes_bounded(value, ROW_BYTES)?)
}

fn decode<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value = decode_canonical(bytes)?;
    if encode(&value)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

fn has_dependencies(connection: &Connection, id: Uuid) -> Result<bool, CatalogStoreError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        [revisions(id)],
        |row| row.get(0),
    )?)
}

fn read_journal(connection: &Connection, id: Uuid) -> Result<Option<Journal>, CatalogStoreError> {
    if id.is_nil() {
        return Err(DatabaseError::Conflict.into());
    }
    let Some(bytes) = bounded_record(connection, JOURNAL, id.as_bytes(), ROW_BYTES)? else {
        if has_dependencies(connection, id)? {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let journal: Journal = decode(&bytes)?;
    journal.retention.validate()?;
    let remaining = journal.work.remaining_after(journal_work())?;
    let dependencies = u128::from(journal.dependencies);
    let fixed = (3 * ROW_BYTES + mb_core::V1_SECTOR_SIZE) as u128;
    if journal.version != 1
        || journal.retention.id != id
        || remaining.records
            != journal
                .dependencies
                .checked_mul(3)
                .ok_or(DatabaseError::Integrity)?
        || (journal.dependencies == 0) != (remaining.bytes == 0)
        || (journal.dependencies == 0) != (remaining.page_occurrences == 0)
        || u128::from(remaining.bytes) < dependencies * fixed
        || u128::from(remaining.bytes)
            > dependencies * (fixed + mb_core::CATALOG_MAX_STREAM_BYTES as u128)
        || u128::from(remaining.page_occurrences) < dependencies * 3
        || u128::from(remaining.page_occurrences)
            > dependencies * u128::from(CATALOG_MAX_PAGE_OCCURRENCES)
        || has_dependencies(connection, id)? != (journal.dependencies != 0)
    {
        return Err(DatabaseError::Integrity.into());
    }
    journal.retention.budget.remaining_after(journal.work)?;
    Ok(Some(journal))
}

fn require(
    connection: &Connection,
    retention: CatalogPackingSourceRetention,
) -> Result<Journal, CatalogStoreError> {
    let journal = read_journal(connection, retention.id)?.ok_or(DatabaseError::NotReady)?;
    if journal.retention != retention {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(journal)
}

fn change(
    connection: &Connection,
    previous: Journal,
    next: Journal,
) -> Result<(), CatalogStoreError> {
    next.retention.budget.remaining_after(next.work)?;
    if connection.execute(
        "UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
        params![
            JOURNAL,
            previous.retention.id.as_bytes(),
            encode(&previous)?,
            encode(&next)?
        ],
    )? != 1
        || read_journal(connection, next.retention.id)? != Some(next)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn read(
    connection: &Connection,
    owner: Uuid,
    revision: Uuid,
) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
    let forward = bounded_record(
        connection,
        &revisions(owner),
        revision.as_bytes(),
        ROW_BYTES,
    )?;
    let reverse = bounded_record(connection, &owners(revision), owner.as_bytes(), ROW_BYTES)?;
    let Some(bytes) = forward else {
        if reverse.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    if reverse.as_deref() != Some(bytes.as_slice())
        || owner_count(connection, revision)?.unwrap_or(0) == 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    let expected: Dependency = decode(&bytes)?;
    let catalog =
        paged_revision::snapshot(connection, revision)?.ok_or(DatabaseError::Integrity)?;
    if expected != dependency(&catalog)? {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(catalog))
}

pub(super) fn require_unretained(
    connection: &Connection,
    revision: Uuid,
) -> Result<(), CatalogStoreError> {
    if owner_count(connection, revision)?.unwrap_or(0) != 0 {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn owner_count(connection: &Connection, revision: Uuid) -> Result<Option<u64>, CatalogStoreError> {
    let stored = bounded_record(connection, OWNER_COUNT, revision.as_bytes(), ROW_BYTES)?;
    let count: Option<u64> = stored.as_deref().map(decode).transpose()?;
    let retained: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        [owners(revision)],
        |row| row.get(0),
    )?;
    if retained != count.is_some_and(|count| count != 0) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(count)
}

fn change_owner_count(
    connection: &Connection,
    revision: Uuid,
    previous: Option<u64>,
    next: u64,
) -> Result<(), CatalogStoreError> {
    let bytes = encode(&next)?;
    if let Some(previous) = previous {
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3", params![OWNER_COUNT, revision.as_bytes(), encode(&previous)?, bytes])? != 1 {
            return Err(DatabaseError::Integrity.into());
        }
    } else {
        insert_exact(connection, OWNER_COUNT, revision.as_bytes(), &bytes)?;
    }
    if owner_count(connection, revision)? != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

/// Reads inside the loan's writer snapshot. Callbacks must authenticate private
/// descriptors and check the actual current base/events through this view;
/// they must not start a nested store transaction.
pub struct CatalogPackingSourceView<'a> {
    connection: &'a Connection,
}

impl CatalogPackingSourceView<'_> {
    pub fn record(
        &self,
        kind: &str,
        key: &[u8],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        bounded_record(self.connection, kind, key, limit)
    }

    pub fn catalog_page(
        &self,
        scope: CatalogScope,
        section: CatalogSection,
        page: CatalogPageRef,
    ) -> Result<Vec<u8>, CatalogStoreError> {
        read_page(
            self.connection,
            PageMetadata {
                format_version: 1,
                scope,
                section,
                reference: page,
            },
        )
    }

    pub fn data_source(
        &self,
        revision: Uuid,
        sector: [u8; 32],
    ) -> Result<Option<PagedCatalogDataSource>, CatalogStoreError> {
        paged_data::read_source(self.connection, revision, sector)
    }
}

impl ControlStore {
    pub fn begin_catalog_packing_source_retention<E: From<CatalogStoreError>>(
        &self,
        retention: CatalogPackingSourceRetention,
        mut guard: impl FnMut(&CatalogPackingSourceView<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        retention.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingSourceView { connection: &tx };
        guard(&view)?;
        match read_journal(&tx, retention.id)? {
            Some(journal)
                if journal.retention != retention
                    || journal.state == CatalogPackingSourceRetentionState::Cancelled =>
            {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            Some(_) => {}
            None => {
                let journal = Journal {
                    version: 1,
                    retention,
                    state: CatalogPackingSourceRetentionState::Building,
                    dependencies: 0,
                    work: journal_work(),
                };
                insert_exact(&tx, JOURNAL, retention.id.as_bytes(), &encode(&journal)?)?;
                if require(&tx, retention)? != journal {
                    return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
                }
            }
        }
        guard(&view)?;
        if require(&tx, retention)?.state != CatalogPackingSourceRetentionState::Building {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    /// Borrow one exact independently authorized signed catalog before payload
    /// reads. Authenticate its private roots/bootstrap in the second callback;
    /// check current base/event authority in the first callback at both ends.
    /// Retries reauthenticate. Physical source replacement may still install
    /// verified equivalent bytes under the original source commitments.
    pub fn retain_catalog_packing_source_checked<E: From<CatalogStoreError>>(
        &self,
        retention: CatalogPackingSourceRetention,
        signed: &SignedRecord<PagedUserRevision>,
        (mut guard, authenticate): (
            impl FnMut(&CatalogPackingSourceView<'_>) -> Result<(), E>,
            impl FnOnce(&CatalogPackingSourceView<'_>, &PagedCatalogSnapshot) -> Result<(), E>,
        ),
    ) -> Result<PagedCatalogSnapshot, E> {
        retention.validate()?;
        let signed_bytes =
            mb_core::canonical_bytes_bounded(signed, mb_core::PAGED_USER_REVISION_BYTES)
                .map_err(CatalogStoreError::from)?;
        if signed.value.guild_id != retention.base.guild_id {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingSourceView { connection: &tx };
        let previous = require(&tx, retention)?;
        if previous.state != CatalogPackingSourceRetentionState::Building {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        guard(&view)?;
        let catalog = paged_revision::snapshot(&tx, signed.value.revision_id)?
            .ok_or(CatalogStoreError::from(DatabaseError::NotReady))?;
        if catalog.bundle.descriptor != signed_bytes {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let expected = dependency(&catalog)?;
        let count = owner_count(&tx, catalog.bundle.id)?;
        let next = if read(&tx, retention.id, catalog.bundle.id)?.is_none() {
            let next = Journal {
                dependencies: previous
                    .dependencies
                    .checked_add(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                work: previous
                    .work
                    .checked_add(expected.work)
                    .map_err(CatalogStoreError::from)?,
                ..previous
            };
            retention
                .budget
                .remaining_after(next.work)
                .map_err(CatalogStoreError::from)?;
            Some(next)
        } else {
            None
        };
        authenticate(&view, &catalog)?;
        if let Some(next) = next {
            let bytes = encode(&expected)?;
            insert_exact(
                &tx,
                &revisions(retention.id),
                catalog.bundle.id.as_bytes(),
                &bytes,
            )?;
            insert_exact(
                &tx,
                &owners(catalog.bundle.id),
                retention.id.as_bytes(),
                &bytes,
            )?;
            change_owner_count(
                &tx,
                catalog.bundle.id,
                count,
                count
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
            )?;
            change(&tx, previous, next)?;
        }
        if read(&tx, retention.id, catalog.bundle.id)?.as_ref() != Some(&catalog)
            || require(&tx, retention)?.state != CatalogPackingSourceRetentionState::Building
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        guard(&view)?;
        if require(&tx, retention)? != next.unwrap_or(previous)
            || read(&tx, retention.id, catalog.bundle.id)?.as_ref() != Some(&catalog)
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(catalog)
    }

    /// A cancelled job keeps every loan until bounded release. Its identity
    /// remains fenced permanently and cannot resume with another base/budget.
    pub fn cancel_catalog_packing_source_retention(
        &self,
        retention: CatalogPackingSourceRetention,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous = require(&tx, retention)?;
        if previous.state != CatalogPackingSourceRetentionState::Cancelled {
            change(
                &tx,
                previous,
                Journal {
                    state: CatalogPackingSourceRetentionState::Cancelled,
                    ..previous
                },
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn catalog_packing_source_retention(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(
            CatalogPackingSourceRetention,
            CatalogPackingSourceRetentionState,
            Work,
        )>,
        CatalogStoreError,
    > {
        let tx = self.read_snapshot()?;
        let journal = read_journal(&tx, id)?;
        tx.commit()?;
        Ok(journal.map(|j| (j.retention, j.state, j.work)))
    }

    /// Read an exact loan, including a cancelled job before its release step.
    /// The caller must recheck its operation/base authority before packing I/O.
    pub fn catalog_packing_source(
        &self,
        retention: CatalogPackingSourceRetention,
        revision: Uuid,
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        let catalog = read(&tx, retention.id, revision)?;
        tx.commit()?;
        Ok(catalog)
    }

    /// Release at most one exact loan after cancellation. This transfers no
    /// underlying source pins; other jobs/checkpoints and the original bundle
    /// continue owning their bytes until their separate cancellation succeeds.
    pub fn release_catalog_packing_source(
        &self,
        retention: CatalogPackingSourceRetention,
    ) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous = require(&tx, retention)?;
        if previous.state != CatalogPackingSourceRetentionState::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let key: Option<Option<Vec<u8>>> = tx.query_row(
            "SELECT CASE WHEN length(record_id) = 16 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
            [revisions(retention.id)], |row| row.get(0),
        ).optional()?;
        let Some(key) = key else { return Ok(false) };
        let revision = Uuid::from_slice(&key.ok_or(DatabaseError::Integrity)?)
            .map_err(|_| DatabaseError::Integrity)?;
        let catalog = read(&tx, retention.id, revision)?.ok_or(DatabaseError::Integrity)?;
        let expected = dependency(&catalog)?;
        let count = owner_count(&tx, revision)?.ok_or(DatabaseError::Integrity)?;
        let bytes = encode(&expected)?;
        for (kind, key) in [
            (revisions(retention.id), revision),
            (owners(revision), retention.id),
        ] {
            if tx.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![kind, key.as_bytes(), bytes],
            )? != 1
                || bounded_record(&tx, &kind, key.as_bytes(), ROW_BYTES)?.is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        change_owner_count(
            &tx,
            revision,
            Some(count),
            count.checked_sub(1).ok_or(DatabaseError::Integrity)?,
        )?;
        change(
            &tx,
            previous,
            Journal {
                dependencies: previous
                    .dependencies
                    .checked_sub(1)
                    .ok_or(DatabaseError::Integrity)?,
                work: previous.work.remaining_after(expected.work)?,
                ..previous
            },
        )?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
