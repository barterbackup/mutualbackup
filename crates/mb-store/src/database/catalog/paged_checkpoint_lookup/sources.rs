//! Original signed source-root locators for private bootstrap/page recovery.
//! Rows never authenticate a source; every point read replays its original frame.

use super::*;
use mb_core::{CatalogSectorRecord, PagedRevisionSourceReader, SectorId, WriterFence};

const TOTALS: &str = "catalog-checkpoint-source-lookup-work-v1";
const INDEX: &str = "catalog-checkpoint-source-lookup-index-v1";

fn indexes(owner: Uuid) -> String {
    format!("{INDEX}/{}", owner.simple())
}
fn rows(owner: Uuid, revision: Uuid) -> String {
    format!(
        "catalog-checkpoint-source-frame-v1/{}/{}",
        owner.simple(),
        revision.simple()
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Entry {
    version: u16,
    owner: Uuid,
    revision: Uuid,
    checkpoint_hash: [u8; 32],
    signed_hash: [u8; 32],
    work: Work,
}

fn reservation(
    signed: &mb_core::SignedRecord<mb_core::PagedUserRevision>,
) -> Result<Work, CatalogStoreError> {
    let root = signed.value.sources.records;
    Ok(Work {
        bytes: root
            .records
            .checked_mul(32 + ROW_BYTES as u64)
            .and_then(|n| n.checked_add(ROW_BYTES as u64))
            .ok_or(DatabaseError::CapacityExceeded)?,
        records: root
            .records
            .checked_add(1)
            .ok_or(DatabaseError::CapacityExceeded)?,
        page_occurrences: 0,
    }
    .checked_add(Work {
        bytes: root
            .page
            .page_occurrences
            .checked_mul(mb_core::CATALOG_PAGE_BYTES as u64)
            .ok_or(DatabaseError::CapacityExceeded)?,
        records: root.records,
        page_occurrences: root.page.page_occurrences,
    })?)
}

pub(super) fn owned_work<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    let value = bounded_record(cx, TOTALS, retention.id.as_bytes(), ROW_BYTES)?
        .map(|bytes| decode_row::<Work>(&bytes))
        .transpose()?;
    if value.is_none()
        && cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
            [indexes(retention.id)],
            |r| r.get::<_, bool>(0),
        )?
    {
        return Err(DatabaseError::Integrity.into());
    }
    let value = value.unwrap_or_default();
    let count: u64 = cx.query_row(
        "SELECT count(*) FROM protocol_records WHERE kind=?1",
        [indexes(retention.id)],
        |r| r.get(0),
    )?;
    if count > retention.checkpoint.authority_root().summary.revisions
        || (count == 0) != (value == Work::default())
        || value.records < count
        || !(value.records - count).is_multiple_of(2)
        || value.bytes
            < count
                .checked_mul(ROW_BYTES as u64)
                .ok_or(DatabaseError::Integrity)?
        || (count != 0 && value.page_occurrences == 0)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

pub(super) fn release<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<bool, CatalogStoreError> {
    let index: Option<BoundedRow> = cx.query_row("SELECT CASE WHEN length(record_id)=16 THEN record_id END,CASE WHEN length(bytes)<=?2 THEN bytes END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT 1",params![indexes(retention.id),ROW_BYTES],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    let Some((key, bytes)) = index else {
        if let Some(bytes) = bounded_record(cx, TOTALS, retention.id.as_bytes(), ROW_BYTES)? {
            if journal::require(cx, retention)?.state
                != CatalogPagedCheckpointRetentionState::Cancelled
            {
                return Err(DatabaseError::Conflict.into());
            }
            if decode_row::<Work>(&bytes)? != Work::default() {
                return Err(DatabaseError::Integrity.into());
            }
            exact_delete(cx, TOTALS, retention.id.as_bytes(), &bytes)?;
            return Ok(true);
        }
        return Ok(false);
    };
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Cancelled {
        return Err(DatabaseError::Conflict.into());
    }
    let key = key.ok_or(DatabaseError::Integrity)?;
    let bytes = bytes.ok_or(DatabaseError::Integrity)?;
    let index: Entry = decode_row(&bytes)?;
    if index.owner != retention.id
        || index.version != 1
        || index.revision.as_bytes().as_slice() != key
        || index.checkpoint_hash != retention.checkpoint.hash()?
    {
        return Err(DatabaseError::Integrity.into());
    }
    let name = rows(retention.id, index.revision);
    let row: Option<BoundedRow> = cx.query_row("SELECT CASE WHEN length(record_id)=32 THEN record_id END,CASE WHEN length(bytes)<=?2 THEN bytes END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT 1",params![name,ROW_BYTES],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
    if let Some((key, bytes)) = row {
        exact_delete(
            cx,
            &name,
            &key.ok_or(DatabaseError::Integrity)?,
            &bytes.ok_or(DatabaseError::Integrity)?,
        )?;
    } else {
        let previous = owned_work(cx, retention)?;
        let next = previous.remaining_after(index.work)?;
        exact_delete(cx, &indexes(retention.id), &key, &bytes)?;
        replace_totals(cx, retention.id, previous, next)?;
    }
    Ok(true)
}

fn exact_delete(
    cx: &Connection,
    name: &str,
    key: &[u8],
    bytes: &[u8],
) -> Result<(), CatalogStoreError> {
    if cx.execute(
        "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
        params![name, key, bytes],
    )? != 1
        || bounded_record(cx, name, key, ROW_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn replace_totals(
    cx: &Connection,
    owner: Uuid,
    previous: Work,
    next: Work,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    if cx.execute(
        "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
        params![TOTALS, owner.as_bytes(), bytes, canonical_bytes(&previous)?],
    )? != 1
        || bounded_record(cx, TOTALS, owner.as_bytes(), ROW_BYTES)?.as_deref()
            != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

impl ControlStore {
    fn build_checkpoint_source_lookup<P: Proof>(
        &self,
        owner: Uuid,
        proof: &P,
        revision: Uuid,
        mut trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let retention = proof.retention(owner)?;
        proof.recheck(&mut trust)?;
        let Some(R::PagedRevision(signed)) =
            self.lookup_revision(retention, revision, retention.budget)?
        else {
            return Err(DatabaseError::Conflict.into());
        };
        let entry = Entry {
            version: 1,
            owner,
            revision,
            checkpoint_hash: retention.checkpoint.hash()?,
            signed_hash: signed.value.hash()?,
            work: reservation(&signed)?,
        };
        // Source traversal reads only already-retained public metadata. One
        // serialized writer makes locator EOF and aggregate debt atomic.
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        guard(self, &tx, retention, &mut trust)?;
        require(&tx, retention)?;
        let prior = bounded_record(&tx, &indexes(owner), revision.as_bytes(), ROW_BYTES)?;
        let previous = owned_work(&tx, retention)?;
        if let Some(bytes) = &prior {
            if decode_row::<Entry>(bytes)? != entry {
                return Err(DatabaseError::Integrity.into());
            }
        } else {
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
                [rows(owner, revision)],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(DatabaseError::Integrity.into());
            }
            let next = previous.checked_add(entry.work)?;
            if bounded_record(&tx, TOTALS, owner.as_bytes(), ROW_BYTES)?.is_none() {
                put(&tx, TOTALS, owner.as_bytes(), &Work::default())?;
            }
            put(&tx, &indexes(owner), revision.as_bytes(), &entry)?;
            replace_totals(&tx, owner, previous, next)?;
        }
        paged_checkpoint_revision::admitted_work(&tx, retention)?;
        let fence = WriterFence {
            owner: signed.value.owner,
            epoch: signed.value.writer_epoch,
            public_key: signed.value.writer_public_key,
        };
        let mut reader = PagedRevisionSourceReader::new(
            &signed,
            signed.value.guild_id,
            signed.value.owner,
            &fence,
        )?;
        let mut count = 0_u64;
        while let Some(source) = unwrap_stream(reader.next_sector(&mut |page| {
            read_page(
                &tx,
                PageMetadata {
                    format_version: 1,
                    scope: signed.value.scope(),
                    section: CatalogSection::SectorReferences,
                    reference: page,
                },
            )
        }))? {
            let location = Frame::new(reader.last_record_range().ok_or(DatabaseError::Integrity)?)?;
            if prior.is_some()
                && bounded_record(&tx, &rows(owner, revision), &source.sector.id, ROW_BYTES)?
                    .is_none()
            {
                return Err(DatabaseError::Integrity.into());
            }
            put(&tx, &rows(owner, revision), &source.sector.id, &location)?;
            count = count.checked_add(1).ok_or(DatabaseError::Integrity)?;
        }
        let actual: u64 = tx.query_row(
            "SELECT count(*) FROM protocol_records WHERE kind=?1",
            [rows(owner, revision)],
            |r| r.get(0),
        )?;
        if !reader.is_complete() || count != signed.value.sources.records.records || actual != count
        {
            return Err(DatabaseError::Integrity.into());
        }
        proof.recheck(&mut trust)?;
        guard(self, &tx, retention, &mut trust)?;
        paged_checkpoint_revision::admitted_work(&tx, retention)?;
        tx.commit()?;
        Ok(())
    }

    fn checkpoint_source<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        revision: Uuid,
        sector: SectorId,
        budget: Work,
    ) -> Result<Option<CatalogSectorRecord>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        let piece = Work {
            bytes: budget.bytes / 2,
            records: budget.records / 2,
            page_occurrences: budget.page_occurrences / 2,
        };
        let Some(R::PagedRevision(signed)) =
            self.read_lookup_revision(&tx, retention, revision, piece)?
        else {
            return Err(DatabaseError::Conflict.into());
        };
        let bytes = bounded_record(&tx, &indexes(retention.id), revision.as_bytes(), ROW_BYTES)?
            .ok_or(DatabaseError::NotReady)?;
        let entry: Entry = decode_row(&bytes)?;
        owned_work(&tx, retention)?.remaining_after(entry.work)?;
        if entry
            != (Entry {
                version: 1,
                owner: retention.id,
                revision,
                checkpoint_hash: retention.checkpoint.hash()?,
                signed_hash: signed.value.hash()?,
                work: reservation(&signed)?,
            })
        {
            return Err(DatabaseError::Integrity.into());
        }
        let Some(bytes) = bounded_record(&tx, &rows(retention.id, revision), &sector, ROW_BYTES)?
        else {
            tx.commit()?;
            return Ok(None);
        };
        let location: Frame = decode_row(&bytes)?;
        let (bytes, _) = frame(
            &tx,
            signed.value.scope(),
            CatalogSection::SectorReferences,
            signed.value.sources.records.page,
            location,
            piece,
        )?;
        let record = CatalogSectorRecord::decode(&bytes)?;
        if record.sector.id != sector {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(Some(record))
    }
}

macro_rules! api {
    ($header:ty,$proof:ty,$build:ident,$point:ident) => {
        impl ControlStore {
            pub fn $build(
                &self,
                owner: Uuid,
                proof: &$proof,
                revision: Uuid,
                trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
            ) -> Result<(), CatalogStoreError> {
                self.build_checkpoint_source_lookup(owner, proof, revision, trust)
            }
            pub fn $point(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                revision: Uuid,
                sector: SectorId,
                budget: Work,
            ) -> Result<Option<CatalogSectorRecord>, CatalogStoreError> {
                self.checkpoint_source(retention, revision, sector, budget)
            }
        }
    };
}
api!(
    mb_core::PagedGuildCheckpoint,
    CatalogQuorumPagedCheckpointIndex,
    build_catalog_paged_checkpoint_source_lookup,
    catalog_paged_checkpoint_indexed_source
);
api!(
    mb_core::PagedGuildCheckpointDirectory,
    CatalogQuorumPagedCheckpointDirectoryIndex,
    build_catalog_paged_checkpoint_directory_source_lookup,
    catalog_paged_checkpoint_directory_indexed_source
);
