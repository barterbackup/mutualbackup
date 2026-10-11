//! Preserve a legacy revision's identity while borrowing its separately
//! published local conversion. The original public body remains owned by the
//! enclosing checkpoint; this bridge keeps the converted private roots live.

use mb_core::{
    CatalogCheckpointAuthorityRecord as R, CatalogCheckpointRevisionKey as Key,
    CatalogCodingTraversalBudget as Work, CatalogLegacyRevisionRef, PagedCheckpointTrust,
    PagedUserRevision, SignedRecord, UserRevision,
};

use super::packing_validation::unwrap_stream;
use super::paged_checkpoint_retention::{Layout, Proof, owned_certificate, validate_owner};
use super::retention_journal as journal;
use super::*;

const ROW_BYTES: usize = 1024;
const TOTALS: &str = "catalog-checkpoint-legacy-private-work-v1";
// This is an existing local migration owner, not new signed authority.
const MIGRATION: &str = "paged-legacy-migration-v1";
const MIGRATION_BYTES: usize = 512;
const PIN_COUNT: &str = "catalog-legacy-private-checkpoint-count-v1";
const COUNT_BYTES: usize = 32;

fn revisions(owner: Uuid) -> String {
    format!("catalog-checkpoint-legacy-private-v1/{}", owner.simple())
}
fn owners(bundle: Uuid) -> String {
    format!("catalog-legacy-private-checkpoint-v1/{}", bundle.simple())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Dependency {
    version: u16,
    reference: CatalogLegacyRevisionRef,
    bundle: Uuid,
    bundle_hash: [u8; 32],
    migration_hash: [u8; 32],
    work: Work,
}

fn legacy(
    connection: &Connection,
    reference: &CatalogLegacyRevisionRef,
) -> Result<SignedRecord<UserRevision>, CatalogStoreError> {
    unwrap_stream(reference.read_signed(&mut |page| {
        read_page(
            connection,
            PageMetadata {
                format_version: 1,
                scope: CatalogScope::Guild {
                    guild_id: reference.guild_id,
                },
                section: CatalogSection::Checkpoint,
                reference: page,
            },
        )
    }))
}

fn dependency(
    connection: &Connection,
    reference: CatalogLegacyRevisionRef,
    snapshot: &PagedCatalogSnapshot,
) -> Result<Dependency, CatalogStoreError> {
    reference.validate()?;
    let signed = PagedUserRevision::decode_signed(&snapshot.bundle.descriptor)?;
    let value = &signed.value;
    if snapshot.state != CatalogBundleState::Published
        || snapshot.bootstrap.is_none()
        || value.revision_id != snapshot.bundle.id
        || value.revision_id == reference.revision_id
        || value.guild_id != reference.guild_id
        || value.owner != reference.owner
        || value.protected_root_id != reference.protected_root_id
        || value.parent != Some(reference.revision_hash)
        || value.sequence
            != reference
                .sequence
                .checked_add(1)
                .ok_or(CatalogError::Bounds)?
    {
        return Err(DatabaseError::Conflict.into());
    }
    let migration = bounded_record(
        connection,
        MIGRATION,
        snapshot.bundle.id.as_bytes(),
        MIGRATION_BYTES,
    )?
    .ok_or(DatabaseError::NotReady)?;
    let mut work = Work {
        bytes: snapshot
            .bootstrap
            .as_ref()
            .ok_or(DatabaseError::Integrity)?
            .len() as u64
            + reference.body.byte_len
            + MIGRATION_BYTES as u64
            + 4 * ROW_BYTES as u64,
        page_occurrences: reference.body.page_occurrences,
        records: 4,
    };
    for member in &snapshot.bundle.roots {
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
        reference,
        bundle: snapshot.bundle.id,
        bundle_hash: mb_core::canonical_hash_bounded(&snapshot.bundle, 8192)?,
        migration_hash: *blake3::hash(&migration).as_bytes(),
        work,
    })
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

fn pin_count(connection: &Connection, bundle: Uuid) -> Result<Option<u64>, CatalogStoreError> {
    let bytes = bounded_record(connection, PIN_COUNT, bundle.as_bytes(), COUNT_BYTES)?;
    let count: Option<u64> = bytes
        .as_ref()
        .map(|bytes| decode_canonical(bytes))
        .transpose()?;
    if let Some(count) = count
        && (count == 0
            || canonical_bytes(&count)? != *bytes.as_ref().ok_or(DatabaseError::Integrity)?)
    {
        return Err(DatabaseError::Integrity.into());
    }
    let retained: bool = connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        params![owners(bundle)],
        |row| row.get(0),
    )?;
    if retained != count.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    // The separate count makes a missing last backlink fail closed instead
    // of allowing cancellation to discard another owner's private custody.
    Ok(count)
}

fn change_pin_count(
    connection: &Connection,
    bundle: Uuid,
    previous: Option<u64>,
    next: u64,
) -> Result<(), CatalogStoreError> {
    if let Some(previous) = previous {
        let changed = if next == 0 {
            connection.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![PIN_COUNT, bundle.as_bytes(), canonical_bytes(&previous)?],
            )?
        } else {
            connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![PIN_COUNT, bundle.as_bytes(), canonical_bytes(&previous)?, canonical_bytes(&next)?])?
        };
        if changed != 1 {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        if next != 1 {
            return Err(DatabaseError::Integrity.into());
        }
        insert_exact(
            connection,
            PIN_COUNT,
            bundle.as_bytes(),
            &canonical_bytes(&next)?,
        )?;
    }
    if pin_count(connection, bundle)? != (next != 0).then_some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn require_unretained(
    connection: &Connection,
    bundle: Uuid,
) -> Result<(), CatalogStoreError> {
    if pin_count(connection, bundle)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
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

pub(super) fn owned_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Work>, CatalogStoreError> {
    let bytes = bounded_record(connection, TOTALS, retention.id.as_bytes(), ROW_BYTES)?;
    let work: Option<Work> = bytes
        .as_ref()
        .map(|bytes| decode_canonical(bytes))
        .transpose()?;
    if let Some(work) = work
        && (canonical_bytes(&work)? != *bytes.as_ref().ok_or(DatabaseError::Integrity)?
            || work.records % 4 != 0
            || work.records / 3
                > retention
                    .checkpoint
                    .authority_root()
                    .summary
                    .legacy_revisions
            || (work.records == 0) != (work.bytes == 0)
            || (work.records == 0) != (work.page_occurrences == 0))
    {
        return Err(DatabaseError::Integrity.into());
    }
    if has_dependencies(connection, retention.id)? != work.is_some_and(|work| work.records != 0) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(work)
}

fn check_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    work: Work,
) -> Result<(), CatalogStoreError> {
    retention.budget.remaining_after(
        retention
            .proof_work
            .checked_add(retention.checkpoint.work()?)?
            .checked_add(work)?
            .checked_add(
                paged_checkpoint_revision::owned_work(connection, retention)?.unwrap_or_default(),
            )?
            .checked_add(
                paged_checkpoint_payload::owned_work(connection, retention)?.unwrap_or_default(),
            )?
            .checked_add(paged_checkpoint_custody::owned_work(connection, retention)?)?,
    )?;
    Ok(())
}

fn change_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    previous: Option<Work>,
    next: Work,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    if let Some(previous) = previous {
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![TOTALS, retention.id.as_bytes(), canonical_bytes(&previous)?, bytes])? != 1 {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        insert_exact(connection, TOTALS, retention.id.as_bytes(), &bytes)?;
    }
    if owned_work(connection, retention)? != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    check_work(connection, retention, next)
}

fn read(
    connection: &Connection,
    owner: Uuid,
    revision: Uuid,
) -> Result<Option<(Dependency, PagedCatalogSnapshot)>, CatalogStoreError> {
    let Some(bytes) = bounded_record(
        connection,
        &revisions(owner),
        revision.as_bytes(),
        ROW_BYTES,
    )?
    else {
        return Ok(None);
    };
    let expected: Dependency = decode_canonical(&bytes)?;
    if expected.version != 1
        || expected.reference.revision_id != revision
        || expected.bundle.is_nil()
        || canonical_bytes(&expected)? != bytes
        || bounded_record(
            connection,
            &owners(expected.bundle),
            owner.as_bytes(),
            ROW_BYTES,
        )?
        .as_deref()
            != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    let snapshot =
        paged_revision::snapshot(connection, expected.bundle)?.ok_or(DatabaseError::Integrity)?;
    if dependency(connection, expected.reference.clone(), &snapshot)? != expected {
        return Err(DatabaseError::Integrity.into());
    }
    // Public body bytes are retained by the enclosing owner, including after cancellation.
    legacy(connection, &expected.reference)?;
    Ok(Some((expected, snapshot)))
}

pub(super) fn release<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<bool, CatalogStoreError> {
    if journal::require(connection, retention)?.state
        != CatalogPagedCheckpointRetentionState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    let row: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN length(record_id) = 16 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
        params![revisions(retention.id)], |row| row.get(0)).optional()?;
    let Some(row) = row else {
        return Ok(false);
    };
    let revision = Uuid::from_slice(&row.ok_or(DatabaseError::Integrity)?)
        .map_err(|_| DatabaseError::Integrity)?;
    let (dependency, _) =
        read(connection, retention.id, revision)?.ok_or(DatabaseError::Integrity)?;
    let count = pin_count(connection, dependency.bundle)?.ok_or(DatabaseError::Integrity)?;
    let previous = owned_work(connection, retention)?.ok_or(DatabaseError::Integrity)?;
    check_work(connection, retention, previous)?;
    owned_certificate(connection, retention)?;
    for (kind, key) in [
        (revisions(retention.id), revision),
        (owners(dependency.bundle), retention.id),
    ] {
        if connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, key.as_bytes(), canonical_bytes(&dependency)?],
        )? != 1
            || bounded_record(connection, &kind, key.as_bytes(), ROW_BYTES)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    change_pin_count(
        connection,
        dependency.bundle,
        Some(count),
        count.checked_sub(1).ok_or(DatabaseError::Integrity)?,
    )?;
    change_work(
        connection,
        retention,
        Some(previous),
        previous.remaining_after(dependency.work)?,
    )?;
    Ok(true)
}

impl ControlStore {
    /// Read a retained conversion by its original legacy revision ID. A
    /// cancelled checkpoint keeps it pinned until bounded dependency retirement.
    pub fn catalog_paged_checkpoint_legacy_revision(
        &self,
        id: Uuid,
        revision: Uuid,
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        if id.is_nil() || revision.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        let tx = self.read_snapshot()?;
        let snapshot = read(&tx, id, revision)?.map(|(_, snapshot)| snapshot);
        if snapshot.is_some() {
            validate_owner(&tx, id)?;
        }
        tx.commit()?;
        Ok(snapshot)
    }

    pub(super) fn retain_checkpoint_legacy_revision_checked<
        P: Proof,
        E: From<CatalogStoreError>,
    >(
        &self,
        id: Uuid,
        proof: &P,
        key: Key,
        bundle: Option<Uuid>,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
        check: impl FnOnce(&PagedCatalogSnapshot, &SignedRecord<UserRevision>) -> Result<(), E>,
    ) -> Result<PagedCatalogSnapshot, E> {
        proof.recheck(&mut read_trust)?;
        let retention = proof.retention(id)?;
        let Some(R::LegacyRevision(reference)) = proof.revision(key)? else {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        };
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        owned_certificate(&tx, retention)?;
        let previous = read(&tx, id, key.revision_id)?;
        let bundle = bundle
            .or_else(|| previous.as_ref().map(|(dep, _)| dep.bundle))
            .ok_or_else(|| CatalogStoreError::from(DatabaseError::NotReady))?;
        let snapshot = paged_revision::snapshot(&tx, bundle)?
            .ok_or_else(|| CatalogStoreError::from(DatabaseError::NotReady))?;
        let expected = dependency(&tx, reference.clone(), &snapshot)?;
        if previous.as_ref().is_some_and(|(dep, _)| dep != &expected) {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        // A missing forward row cannot silently replace an existing reverse pin.
        if previous.is_none()
            && bounded_record(&tx, &owners(bundle), id.as_bytes(), ROW_BYTES)?.is_some()
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        let old_work = owned_work(&tx, retention)?;
        let next = old_work
            .unwrap_or_default()
            .checked_add(if previous.is_none() {
                expected.work
            } else {
                Work::default()
            })
            .map_err(CatalogStoreError::from)?;
        check_work(&tx, retention, next)?;
        let original = legacy(&tx, &reference)?;
        check(&snapshot, &original)?;
        if previous.is_none() {
            let bytes = canonical_bytes(&expected).map_err(CatalogStoreError::from)?;
            insert_exact(&tx, &revisions(id), key.revision_id.as_bytes(), &bytes)?;
            let count = pin_count(&tx, bundle)?;
            insert_exact(&tx, &owners(bundle), id.as_bytes(), &bytes)?;
            change_pin_count(
                &tx,
                bundle,
                count,
                count
                    .unwrap_or_default()
                    .checked_add(1)
                    .ok_or_else(|| CatalogStoreError::from(CatalogError::Bounds))?,
            )?;
            change_work(&tx, retention, old_work, next)?;
        }
        if read(&tx, id, key.revision_id)?.as_ref() != Some(&(expected, snapshot.clone())) {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        owned_certificate(&tx, retention)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(snapshot)
    }

    /// Check checkpoint pins and fence an existing migration journal in one
    /// immediate writer. The callback must use record operations without
    /// starting nested transactions. Subsequent typed cancellation may resume.
    pub fn with_unretained_paged_revision_record_transaction<T, E: From<CatalogStoreError>>(
        &self,
        bundle: Uuid,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        paged_checkpoint_revision::require_unretained(&tx, bundle)?;
        let result = operation()?;
        paged_checkpoint_revision::require_unretained(&tx, bundle)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(result)
    }
}

macro_rules! legacy_api {
    ($proof:ty, $retain:ident) => {
        impl ControlStore {
            /// Borrow one published, authenticated local legacy conversion
            /// under the exact original checkpoint revision identity. The
            /// callback must authenticate the private conversion and its active
            /// original migration journal in this writer snapshot.
            pub fn $retain<E: From<CatalogStoreError>>(
                &self, id: Uuid, proof: &$proof, key: Key, migration: Uuid,
                read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
                check: impl FnOnce(&PagedCatalogSnapshot, &SignedRecord<UserRevision>) -> Result<(), E>,
            ) -> Result<PagedCatalogSnapshot, E> {
                self.retain_checkpoint_legacy_revision_checked(id, proof, key, Some(migration), read_trust, check)
            }
        }
    };
}
legacy_api!(
    CatalogQuorumPagedCheckpointIndex,
    retain_catalog_paged_checkpoint_legacy_revision_checked
);
legacy_api!(
    CatalogQuorumPagedCheckpointDirectoryIndex,
    retain_catalog_paged_checkpoint_directory_legacy_revision_checked
);
