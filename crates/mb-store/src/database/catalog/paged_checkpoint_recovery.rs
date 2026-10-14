//! Pending private recovery debt under the exact original public checkpoint.
//! Publication transfers the reservation to ordinary retained private custody.

use super::paged_checkpoint_retention::{Layout, owned_certificate};
use super::retention_journal as journal;
use super::*;
use mb_core::{CatalogCheckpointAuthorityRecord as R, CatalogCodingTraversalBudget as Work};

const TOTALS: &str = "catalog-checkpoint-recovery-work-v1";
const ROW_BYTES: usize = 8192;
const JOURNAL_WORK: Work = Work {
    bytes: 2 * ROW_BYTES as u64,
    records: 2,
    page_occurrences: 0,
};
fn jobs(owner: Uuid) -> String {
    format!("catalog-checkpoint-recovery-v1/{}", owner.simple())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Job {
    version: u16,
    owner: Uuid,
    checkpoint_hash: [u8; 32],
    bundle: CatalogBundle,
    work: Work,
    complete: bool,
}

fn work(bundle: &CatalogBundle) -> Result<Work, CatalogStoreError> {
    bundle.validate()?;
    let mut work = Work {
        bytes: 2 * ROW_BYTES as u64 + mb_core::V1_SECTOR_SIZE as u64,
        records: 2,
        page_occurrences: 0,
    };
    for root in &bundle.roots {
        work = work.checked_add(Work {
            bytes: root
                .root
                .page_occurrences
                .checked_mul(mb_core::CATALOG_PAGE_BYTES as u64)
                .ok_or(DatabaseError::CapacityExceeded)?,
            records: root.root.page_occurrences,
            page_occurrences: root.root.page_occurrences,
        })?;
    }
    Ok(work)
}

impl ControlStore {
    fn reserve_checkpoint_bootstrap<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        signed: &mb_core::SignedRecord<mb_core::PagedUserRevision>,
    ) -> Result<(), CatalogStoreError> {
        if self
            .paged_revision_catalog(signed.value.revision_id)?
            .is_none()
            && self.catalog_storage_usage()?.is_none()
        {
            return Err(DatabaseError::NotReady.into());
        }
        let mut hash =
            blake3::Hasher::new_derive_key("mutualbackup checkpoint bootstrap reservation v1");
        hash.update(&canonical_bytes(&(retention.id, signed.value.hash()?))?);
        let mut id = [0; 16];
        id.copy_from_slice(&hash.finalize().as_bytes()[..16]);
        let intent = CatalogIntent {
            id: Uuid::from_bytes(id),
            scope: signed.value.scope(),
            section: CatalogSection::SectorReferences,
        };
        let bundle = CatalogBundle {
            id: signed.value.revision_id,
            scope: signed.value.scope(),
            roots: vec![CatalogBundleRoot {
                intent,
                root: signed.value.sources.records.page,
            }],
            descriptor: canonical_bytes(signed)?,
        };
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(DatabaseError::Conflict.into());
        }
        owned_certificate(&tx, retention)?;
        if self.lookup_recovery_revision(retention, signed.value.revision_id)?
            != R::PagedRevision(signed.clone())
        {
            return Err(DatabaseError::Integrity.into());
        }
        if let Some(existing) = read(&tx, retention, signed.value.revision_id)? {
            if existing.bundle.descriptor != canonical_bytes(signed)? {
                return Err(DatabaseError::Integrity.into());
            }
        } else {
            let job = Job {
                version: 1,
                owner: retention.id,
                checkpoint_hash: retention.checkpoint.hash()?,
                work: work(&bundle)?,
                bundle,
                complete: false,
            };
            let previous = owned_work(&tx, retention)?;
            begin_intent(&tx, intent)?;
            insert_exact(
                &tx,
                &jobs(retention.id),
                signed.value.revision_id.as_bytes(),
                &canonical_bytes(&job)?,
            )?;
            totals(&tx, retention.id, previous, previous.checked_add(job.work)?)?;
        }
        paged_checkpoint_revision::admitted_work(&tx, retention)?;
        tx.commit()?;
        Ok(())
    }
}
pub(super) fn owned_work<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    let saved = bounded_record(cx, TOTALS, retention.id.as_bytes(), 128)?;
    if saved.is_none()
        && cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
            [jobs(retention.id)],
            |r| r.get::<_, bool>(0),
        )?
    {
        return Err(DatabaseError::Integrity.into());
    }
    let value = saved
        .map(|bytes| -> Result<_, CatalogStoreError> {
            let value: Work = decode_canonical(&bytes)?;
            if canonical_bytes(&value)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(value)
        })
        .transpose()?;
    let value = value.unwrap_or_default();
    let count: u64 = cx.query_row(
        "SELECT count(*) FROM protocol_records WHERE kind=?1",
        [jobs(retention.id)],
        |r| r.get(0),
    )?;
    if count > retention.checkpoint.authority_root().summary.revisions
        || (count == 0) != (value == Work::default())
        || value.records
            < count
                .checked_mul(JOURNAL_WORK.records)
                .ok_or(DatabaseError::Integrity)?
        || value.bytes
            < count
                .checked_mul(JOURNAL_WORK.bytes)
                .ok_or(DatabaseError::Integrity)?
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}
fn read<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    revision: Uuid,
) -> Result<Option<Job>, CatalogStoreError> {
    let Some(bytes) = bounded_record(cx, &jobs(retention.id), revision.as_bytes(), ROW_BYTES)?
    else {
        return Ok(None);
    };
    let job: Job = decode_canonical(&bytes)?;
    if job.version != 1
        || job.owner != retention.id
        || job.checkpoint_hash != retention.checkpoint.hash()?
        || job.bundle.id != revision
        || job.work != work(&job.bundle)?
        || canonical_bytes(&job)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(job))
}
fn totals(
    cx: &Connection,
    owner: Uuid,
    previous: Work,
    next: Work,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    match bounded_record(cx, TOTALS, owner.as_bytes(), 128)? {
        None if previous == Work::default() => {
            insert_exact(cx, TOTALS, owner.as_bytes(), &bytes)?;
        }
        Some(old) if old == canonical_bytes(&previous)? => {
            if cx.execute(
                "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
                params![TOTALS, owner.as_bytes(), bytes, old],
            )? != 1
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        _ => return Err(DatabaseError::Integrity.into()),
    }
    if bounded_record(cx, TOTALS, owner.as_bytes(), 128)?.as_deref() != Some(bytes.as_slice()) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn check<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    bundle: &CatalogBundle,
) -> Result<mb_core::SignedRecord<mb_core::PagedUserRevision>, CatalogStoreError> {
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Published {
        return Err(DatabaseError::Conflict.into());
    }
    owned_certificate(cx, retention)?;
    let signed = paged_revision::revision(bundle)?;
    if let Some(job) = read(cx, retention, bundle.id)? {
        owned_work(cx, retention)?.remaining_after(if job.complete {
            JOURNAL_WORK
        } else {
            job.work
        })?;
    }
    let control_record = bounded_record(
        cx,
        &paged_checkpoint_lookup::kind(retention.id, "revision"),
        bundle.id.as_bytes(),
        1024,
    )?
    .ok_or(DatabaseError::NotReady)?;
    let row: paged_checkpoint_lookup::Revision = decode_canonical(&control_record)?;
    if row.key != mb_core::CatalogCheckpointRevisionKey::from(&signed.value) {
        return Err(DatabaseError::Integrity.into());
    }
    paged_checkpoint_revision::admitted_work(cx, retention)?;
    Ok(signed)
}

impl ControlStore {
    fn begin_checkpoint_private_recovery<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        bundle: &CatalogBundle,
    ) -> Result<(), CatalogStoreError> {
        let signed = paged_revision::revision(bundle)?;
        let job = Job {
            version: 1,
            owner: retention.id,
            checkpoint_hash: retention.checkpoint.hash()?,
            bundle: bundle.clone(),
            work: work(bundle)?,
            complete: false,
        };
        let requests: Vec<_> = bundle
            .roots
            .iter()
            .map(|root| {
                Ok((
                    root.intent,
                    CatalogPageReservation {
                        page_bytes: root
                            .root
                            .page_occurrences
                            .checked_mul(mb_core::CATALOG_PAGE_BYTES as u64)
                            .ok_or(DatabaseError::CapacityExceeded)?,
                        pages: root.root.page_occurrences,
                    },
                ))
            })
            .collect::<Result<_, CatalogStoreError>>()?;
        self.with_catalog_page_reservations(&requests, |_| -> Result<(), CatalogStoreError> {
            self.check_checkpoint_private_recovery(retention, bundle)?;
            let previous = owned_work(&self.connection, retention)?;
            if let Some(existing) = read(&self.connection, retention, bundle.id)? {
                if existing.bundle != *bundle {
                    if existing.complete || existing.bundle.roots.len() != 1 || existing.bundle.descriptor != bundle.descriptor {
                        return Err(DatabaseError::Conflict.into());
                    }
                    let bytes = canonical_bytes(&job)?;
                    if self.connection.execute("UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4", params![jobs(retention.id),bundle.id.as_bytes(),bytes,canonical_bytes(&existing)?])? != 1
                        || read(&self.connection, retention, bundle.id)?.as_ref() != Some(&job) { return Err(DatabaseError::Integrity.into()); }
                    totals(&self.connection, retention.id, previous, previous.remaining_after(existing.work)?.checked_add(job.work)?)?;
                    let old = &existing.bundle.roots[0];
                    let mut record = read_intent(&self.connection, old.intent)?;
                    record.state = CatalogIntentState::Cancelled;
                    write_intent(&self.connection, &record)?;
                }
            } else {
                if paged_revision::snapshot(&self.connection, bundle.id)?.is_some() {
                    return Err(DatabaseError::Conflict.into());
                }
                insert_exact(
                    &self.connection,
                    &jobs(retention.id),
                    bundle.id.as_bytes(),
                    &canonical_bytes(&job)?,
                )?;
                totals(
                    &self.connection,
                    retention.id,
                    previous,
                    previous.checked_add(job.work)?,
                )?;
            }
            paged_checkpoint_revision::admitted_work(&self.connection, retention)?;
            if signed.value.guild_id != retention.checkpoint.guild_id() {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(())
        })
    }
    fn check_checkpoint_private_recovery<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        bundle: &CatalogBundle,
    ) -> Result<(), CatalogStoreError> {
        let signed = check(&self.connection, retention, bundle)?;
        let record = self.lookup_recovery_revision(retention, bundle.id)?;
        if record != R::PagedRevision(signed) {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }
    fn finish_checkpoint_private_recovery<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        bundle: &CatalogBundle,
    ) -> Result<(), CatalogStoreError> {
        self.check_checkpoint_private_recovery(retention, bundle)?;
        let Some(job) = read(&self.connection, retention, bundle.id)? else {
            if !self.connection.is_autocommit() {
                let signed = paged_revision::revision(bundle)?;
                return paged_checkpoint_revision::retain_recovered(
                    &self.connection,
                    retention,
                    &signed,
                );
            }
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            self.check_checkpoint_private_recovery(retention, bundle)?;
            let signed = paged_revision::revision(bundle)?;
            paged_checkpoint_revision::retain_recovered(&tx, retention, &signed)?;
            self.check_checkpoint_private_recovery(retention, bundle)?;
            tx.commit()?;
            return Ok(());
        };
        if self.connection.is_autocommit() {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            self.finish_checkpoint_private_recovery(retention, bundle)?;
            tx.commit()?;
            return Ok(());
        }
        if job.bundle != *bundle {
            // Another owner may have published this original revision while
            // this owner's recovery was pending. Keep its reservation until
            // its own staging intents are retired; borrow the published bundle.
            if job.complete
                || job.bundle.descriptor != bundle.descriptor
                || paged_revision::snapshot(&self.connection, bundle.id)?
                    .is_none_or(|published| published.bundle != *bundle)
            {
                return Err(DatabaseError::Integrity.into());
            }
            let signed = paged_revision::revision(bundle)?;
            paged_checkpoint_revision::retain_recovered(&self.connection, retention, &signed)?;
            return self.check_checkpoint_private_recovery(retention, bundle);
        }
        if !job.complete {
            let next = Job {
                complete: true,
                ..job.clone()
            };
            let bytes = canonical_bytes(&next)?;
            if self.connection.execute(
                "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
                params![
                    jobs(retention.id),
                    bundle.id.as_bytes(),
                    bytes,
                    canonical_bytes(&job)?
                ],
            )? != 1
                || bounded_record(
                    &self.connection,
                    &jobs(retention.id),
                    bundle.id.as_bytes(),
                    ROW_BYTES,
                )?
                .as_deref()
                    != Some(bytes.as_slice())
            {
                return Err(DatabaseError::Integrity.into());
            }
            let previous = owned_work(&self.connection, retention)?;
            totals(
                &self.connection,
                retention.id,
                previous,
                previous
                    .remaining_after(job.work)?
                    .checked_add(JOURNAL_WORK)?,
            )?;
        }
        let signed = paged_revision::revision(bundle)?;
        paged_checkpoint_revision::retain_recovered(&self.connection, retention, &signed)?;
        self.check_checkpoint_private_recovery(retention, bundle)
    }
}

pub(super) fn release<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<bool, CatalogStoreError> {
    let row:Option<Option<Vec<u8>>>=cx.query_row("SELECT CASE WHEN length(record_id)=16 THEN record_id END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT 1",[jobs(retention.id)],|r|r.get(0)).optional()?;
    let Some(key) = row else {
        if let Some(bytes) = bounded_record(cx, TOTALS, retention.id.as_bytes(), 128)? {
            if journal::require(cx, retention)?.state
                != CatalogPagedCheckpointRetentionState::Cancelled
            {
                return Err(DatabaseError::Conflict.into());
            }
            if decode_canonical::<Work>(&bytes)? != Work::default() {
                return Err(DatabaseError::Integrity.into());
            }
            if cx.execute(
                "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
                params![TOTALS, retention.id.as_bytes(), bytes],
            )? != 1
                || bounded_record(cx, TOTALS, retention.id.as_bytes(), 128)?.is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(true);
        }
        return Ok(false);
    };
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Cancelled {
        return Err(DatabaseError::Conflict.into());
    }
    let key = key.ok_or(DatabaseError::Integrity)?;
    let revision = Uuid::from_slice(&key).map_err(|_| DatabaseError::Integrity)?;
    let job = read(cx, retention, revision)?.ok_or(DatabaseError::Integrity)?;
    let previous = owned_work(cx, retention)?;
    let published = paged_revision::snapshot(cx, revision)?.is_some();
    if !job.complete {
        let other_pending: bool = cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind LIKE 'catalog-checkpoint-recovery-v1/%' AND kind<>?1 AND record_id=?2)",
            params![jobs(retention.id), revision.as_bytes()],
            |r| r.get(0),
        )?;
        if !published
            && !other_pending
            && native_validation::retire_unpublished_recovery_record(cx, revision)?
        {
            return Ok(true);
        }
        for root in &job.bundle.roots {
            let mut intent = read_intent(cx, root.intent)?;
            bundle::require_unbundled(cx, root.intent)?;
            if intent.state != CatalogIntentState::Cancelled {
                intent.state = CatalogIntentState::Cancelled;
                write_intent(cx, &intent)?;
                return Ok(true);
            }
            let owner_kind = owners(root.intent);
            if let Some(hash) = candidate_hash(cx, &owner_kind, &[])? {
                let page = metadata(cx, hash)?;
                intent.owned_pages = intent
                    .owned_pages
                    .checked_sub(1)
                    .ok_or(DatabaseError::Integrity)?;
                intent.owned_bytes = intent
                    .owned_bytes
                    .checked_sub(u64::from(page.reference.encoded_len))
                    .ok_or(DatabaseError::Integrity)?;
                if cx.execute(
                    "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2",
                    params![owner_kind, hash],
                )? != 1
                    || cx.execute(
                        "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2",
                        params![pins(hash), root.intent.id.as_bytes()],
                    )? != 1
                    || bounded_record(cx, &owner_kind, &hash, RECORD_BYTES)?.is_some()
                    || bounded_record(cx, &pins(hash), root.intent.id.as_bytes(), RECORD_BYTES)?
                        .is_some()
                {
                    return Err(DatabaseError::Integrity.into());
                }
                write_intent(cx, &intent)?;
                queue_unreferenced(cx, hash)?;
                return Ok(true);
            }
        }
    }
    if cx.execute(
        "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
        params![
            jobs(retention.id),
            revision.as_bytes(),
            canonical_bytes(&job)?
        ],
    )? != 1
        || read(cx, retention, revision)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    totals(
        cx,
        retention.id,
        previous,
        previous.remaining_after(if job.complete { JOURNAL_WORK } else { job.work })?,
    )?;
    Ok(true)
}

macro_rules! api {
    ($header:ty,$begin:ident,$check:ident,$finish:ident,$reserve:ident) => {
        impl ControlStore {
            pub fn $reserve(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                signed: &mb_core::SignedRecord<mb_core::PagedUserRevision>,
            ) -> Result<(), CatalogStoreError> {
                self.reserve_checkpoint_bootstrap(retention, signed)
            }
            pub fn $begin(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                bundle: &CatalogBundle,
            ) -> Result<(), CatalogStoreError> {
                self.begin_checkpoint_private_recovery(retention, bundle)
            }
            pub fn $check(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                bundle: &CatalogBundle,
            ) -> Result<(), CatalogStoreError> {
                self.check_checkpoint_private_recovery(retention, bundle)
            }
            /// Called by the private publication callback in its existing writer.
            pub fn $finish(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                bundle: &CatalogBundle,
            ) -> Result<(), CatalogStoreError> {
                self.finish_checkpoint_private_recovery(retention, bundle)
            }
        }
    };
}
api!(
    mb_core::PagedGuildCheckpoint,
    begin_catalog_paged_checkpoint_private_recovery,
    check_catalog_paged_checkpoint_private_recovery,
    finish_catalog_paged_checkpoint_private_recovery,
    reserve_catalog_paged_checkpoint_bootstrap
);
api!(
    mb_core::PagedGuildCheckpointDirectory,
    begin_catalog_paged_checkpoint_directory_private_recovery,
    check_catalog_paged_checkpoint_directory_private_recovery,
    finish_catalog_paged_checkpoint_directory_private_recovery,
    reserve_catalog_paged_checkpoint_directory_bootstrap
);
