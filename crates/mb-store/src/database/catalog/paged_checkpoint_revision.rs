//! Checkpoint dependencies on existing published private revision custody.
//! A dependency keeps the bundle, bootstrap and its native/source pins live;
//! it does not certify complete payload availability or activate a checkpoint.

use mb_core::{
    CatalogCheckpointAuthorityRecord, CatalogCheckpointRevisionKey,
    CatalogCodingTraversalBudget as Work, PagedCheckpointTrust,
};

use super::paged_checkpoint_retention::owned_certificate;
use super::retention_journal as journal;
use super::*;

const ROW_BYTES: usize = 128;
const TOTALS: &str = "catalog-checkpoint-private-work-v1";

fn revisions(owner: Uuid) -> String {
    format!("catalog-checkpoint-private-revision-v1/{}", owner.simple())
}

fn owners(revision: Uuid) -> String {
    format!(
        "catalog-private-revision-checkpoint-v1/{}",
        revision.simple()
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Dependency {
    version: u16,
    bundle_hash: [u8; 32],
    work: Work,
}

fn dependency(catalog: &PagedCatalogSnapshot) -> Result<Dependency, CatalogStoreError> {
    catalog.bundle.validate()?;
    if catalog.state != CatalogBundleState::Published || catalog.bootstrap.is_none() {
        return Err(DatabaseError::Conflict.into());
    }
    let mut work = Work {
        bytes: catalog
            .bootstrap
            .as_ref()
            .ok_or(DatabaseError::Integrity)?
            .len() as u64
            + 3 * ROW_BYTES as u64,
        page_occurrences: 0,
        records: 3,
    };
    for member in &catalog.bundle.roots {
        if member.intent.section.is_private() {
            work = work.checked_add(Work {
                bytes: member.root.byte_len,
                page_occurrences: member.root.page_occurrences,
                records: 0,
            })?;
        }
    }
    Ok(Dependency {
        version: 1,
        bundle_hash: mb_core::canonical_hash_bounded(&catalog.bundle, 8192)?,
        work,
    })
}

pub(super) fn admitted_work(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention,
) -> Result<Option<Work>, CatalogStoreError> {
    let stored = bounded_record(connection, TOTALS, retention.id.as_bytes(), ROW_BYTES)?;
    let work: Option<Work> = stored
        .as_ref()
        .map(|bytes| decode_canonical(bytes))
        .transpose()?;
    if let Some(work) = work {
        if canonical_bytes(&work)? != *stored.as_ref().ok_or(DatabaseError::Integrity)?
            || work.records % 3 != 0
            || work.records / 3 > retention.checkpoint.authority_root.summary.revisions
            || (work.records == 0) != (work.bytes == 0)
            || (work.records == 0) != (work.page_occurrences == 0)
        {
            return Err(DatabaseError::Integrity.into());
        }
        check_work(retention, work)?;
    }
    if has_dependencies(connection, retention.id)? != work.is_some_and(|work| work.records != 0) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(work)
}

fn check_work(
    retention: CatalogPagedCheckpointRetention,
    work: Work,
) -> Result<(), CatalogStoreError> {
    retention.budget.remaining_after(
        retention
            .proof_work
            .checked_add(retention.checkpoint.represented_work()?)?
            .checked_add(work)?,
    )?;
    Ok(())
}

pub(super) fn require_unowned(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    if has_dependencies(connection, id)?
        || bounded_record(connection, TOTALS, id.as_bytes(), ROW_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn change_work(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention,
    previous: Option<Work>,
    next: Work,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    if let Some(previous) = previous {
        if connection.execute(
            "UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![TOTALS, retention.id.as_bytes(), canonical_bytes(&previous)?, bytes],
        )? != 1 {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        insert_exact(connection, TOTALS, retention.id.as_bytes(), &bytes)?;
    }
    if admitted_work(connection, retention)? != Some(next) {
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
    if reverse.as_deref() != Some(bytes.as_slice()) {
        return Err(DatabaseError::Integrity.into());
    }
    let expected: Dependency = decode_canonical(&bytes)?;
    let catalog =
        paged_revision::snapshot(connection, revision)?.ok_or(DatabaseError::Integrity)?;
    if expected != dependency(&catalog)? || canonical_bytes(&expected)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(catalog))
}

pub(super) fn require_unretained(
    connection: &Connection,
    revision: Uuid,
) -> Result<(), CatalogStoreError> {
    let retained: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        params![owners(revision)],
        |row| row.get(0),
    )?;
    if retained {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

pub(super) fn has_dependencies(
    connection: &Connection,
    owner: Uuid,
) -> Result<bool, CatalogStoreError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        params![revisions(owner)],
        |row| row.get(0),
    )?)
}

// The enclosing caller supplies an Immediate writer and checks the actual
// current checkpoint before and after this one bounded dependency transfer.
pub(super) fn release(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention,
) -> Result<bool, CatalogStoreError> {
    if journal::require(connection, retention)?.state
        != CatalogPagedCheckpointRetentionState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    let previous_work = admitted_work(connection, retention)?;
    let revision: Option<Option<Vec<u8>>> = connection
        .query_row(
            "SELECT CASE WHEN length(record_id) = 16 THEN record_id END
         FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
            params![revisions(retention.id)],
            |row| row.get(0),
        )
        .optional()?;
    let Some(revision) = revision else {
        return Ok(false);
    };
    let revision = Uuid::from_slice(&revision.ok_or(DatabaseError::Integrity)?)
        .map_err(|_| DatabaseError::Integrity)?;
    if revision.is_nil() {
        return Err(DatabaseError::Integrity.into());
    }
    owned_certificate(connection, retention)?;
    let catalog = read(connection, retention.id, revision)?.ok_or(DatabaseError::Integrity)?;
    let dependency = dependency(&catalog)?;
    let bytes = canonical_bytes(&dependency)?;
    for (kind, key) in [
        (revisions(retention.id), revision),
        (owners(revision), retention.id),
    ] {
        if connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, key.as_bytes(), bytes],
        )? != 1
            || bounded_record(connection, &kind, key.as_bytes(), ROW_BYTES)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    let next = previous_work
        .ok_or(DatabaseError::Integrity)?
        .remaining_after(dependency.work)?;
    change_work(connection, retention, previous_work, next)?;
    owned_certificate(connection, retention)?;
    if journal::require(connection, retention)?.state
        != CatalogPagedCheckpointRetentionState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(true)
}

impl ControlStore {
    /// Retain one existing private revision bundle, its bootstrap and native/
    /// source pins for an exact revision in the completed original-history
    /// proof. Authenticate the encrypted private descriptor in `check` using
    /// this writer's snapshot. This dependency is not full payload readiness.
    pub fn retain_catalog_paged_checkpoint_revision_checked<E: From<CatalogStoreError>>(
        &self,
        id: Uuid,
        proof: &CatalogQuorumPagedCheckpointIndex,
        key: CatalogCheckpointRevisionKey,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
        check: impl FnOnce(&PagedCatalogSnapshot) -> Result<(), E>,
    ) -> Result<PagedCatalogSnapshot, E> {
        let mut acquire = || -> Result<_, CatalogStoreError> {
            if id.is_nil() || !proof.transition().has_certified_history_transition() {
                return Err(DatabaseError::Conflict.into());
            }
            proof.recheck_header(&mut read_trust)?;
            let Some(CatalogCheckpointAuthorityRecord::PagedRevision(signed)) =
                proof.index().revision(key)?
            else {
                return Err(DatabaseError::Conflict.into());
            };
            let retention = CatalogPagedCheckpointRetention {
                id,
                checkpoint: proof.certificate().checkpoint,
                certificate_hash: mb_core::canonical_hash_bounded(
                    proof.certificate(),
                    mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
                )?,
                trust_hash: super::checkpoint_transition::snapshot_hash(proof.trust())?,
                proof_work: proof.transition().represented_work(),
                budget: proof.transition().budget(),
            };
            Ok((retention, signed))
        };
        let (retention, signed) = acquire()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        owned_certificate(&tx, retention)?;
        let catalog = paged_revision::snapshot(&tx, signed.value.revision_id)?
            .ok_or_else(|| CatalogStoreError::from(DatabaseError::NotReady))?;
        let expected = dependency(&catalog)?;
        if catalog.bundle.descriptor
            != mb_core::canonical_bytes_bounded(&signed, mb_core::PAGED_USER_REVISION_BYTES)
                .map_err(CatalogStoreError::from)?
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        check(&catalog)?;
        let previous_work = admitted_work(&tx, retention)?;
        let bytes = canonical_bytes(&expected).map_err(CatalogStoreError::from)?;
        // Reject one-sided damage rather than silently repairing a lost pin.
        if read(&tx, id, catalog.bundle.id)?.is_none() {
            let next = previous_work
                .unwrap_or_default()
                .checked_add(expected.work)
                .map_err(CatalogStoreError::from)?;
            check_work(retention, next)?;
            insert_exact(&tx, &revisions(id), catalog.bundle.id.as_bytes(), &bytes)?;
            insert_exact(&tx, &owners(catalog.bundle.id), id.as_bytes(), &bytes)?;
            change_work(&tx, retention, previous_work, next)?;
        }
        if read(&tx, id, catalog.bundle.id)?.as_ref() != Some(&catalog) {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        owned_certificate(&tx, retention)?;
        admitted_work(&tx, retention)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(catalog)
    }

    /// Read one retained private dependency, including a cancelled owner's
    /// dependency until its bounded retirement step has committed.
    pub fn catalog_paged_checkpoint_revision(
        &self,
        id: Uuid,
        revision: Uuid,
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        if id.is_nil() || revision.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Deferred)?;
        let catalog = read(&tx, id, revision)?;
        if catalog.is_some() {
            let record = journal::read::<CatalogPagedCheckpointRetention>(&tx, id)?
                .ok_or(DatabaseError::Integrity)?;
            if record.state == CatalogPagedCheckpointRetentionState::Building || record.roots == 0 {
                return Err(DatabaseError::Integrity.into());
            }
            owned_certificate(&tx, record.retention)?;
            admitted_work(&tx, record.retention)?;
        }
        tx.commit()?;
        Ok(catalog)
    }
}
