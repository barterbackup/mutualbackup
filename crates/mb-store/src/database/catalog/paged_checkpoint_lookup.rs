//! Durable, root-authenticated point lookups under one retained checkpoint.
//! Index rows are locators; every returned record is read from signed roots.

use super::checkpoint_body::Header;
use super::packing_validation::unwrap_stream;
use super::paged_checkpoint_retention::{Layout, Proof, owned_certificate};
use super::retention_journal as journal;
use super::*;
use mb_core::{
    CatalogCheckpointAuthorityReader, CatalogCheckpointAuthorityRecord as R,
    CatalogCheckpointRevisionKey as Key, CatalogCodingDirectoryReader, CatalogCodingGroupLocation,
    CatalogCodingTraversalBudget as Work, CatalogRangeReader, PagedCheckpointTrust,
};

const JOURNAL: &str = "catalog-checkpoint-lookup-v1";
const ROW_BYTES: usize = 1024;
type BoundedRow = (Option<Vec<u8>>, Option<Vec<u8>>);

pub(super) fn kind(id: Uuid, suffix: &str) -> String {
    format!("catalog-checkpoint-lookup-{suffix}-v1/{}", id.simple())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Frame {
    pub(super) offset: u64,
    pub(super) len: u32,
}
impl Frame {
    fn new(range: std::ops::Range<u64>) -> Result<Self, CatalogStoreError> {
        Ok(Self {
            offset: range.start,
            len: u32::try_from(
                range
                    .end
                    .checked_sub(range.start)
                    .ok_or(DatabaseError::Integrity)?,
            )
            .map_err(|_| DatabaseError::Integrity)?,
        })
    }
    fn range(self, root: CatalogPageRef) -> Result<std::ops::Range<u64>, CatalogStoreError> {
        let end = self
            .offset
            .checked_add(u64::from(self.len))
            .ok_or(DatabaseError::Integrity)?;
        if self.offset < 8
            || self.len < 5
            || self.len as usize > 4 + mb_core::CATALOG_CODING_ROOT_BYTES
            || end > root.byte_len
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(self.offset..end)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Revision {
    pub(super) key: Key,
    pub(super) frame: Frame,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Group {
    pub(super) forest: Frame,
    pub(super) location: CatalogCodingGroupLocation,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Index {
    version: u16,
    id: Uuid,
    checkpoint_hash: [u8; 32],
    certificate_hash: [u8; 32],
    trust_hash: [u8; 32],
    revisions: u64,
    groups: u64,
    complete: bool,
    work: Work,
}

fn reservation<H: Layout>(
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    let rows = retention
        .checkpoint
        .authority_root()
        .summary
        .revisions
        .checked_mul(2)
        .and_then(|n| n.checked_add(retention.checkpoint.coding().groups))
        .and_then(|n| n.checked_add(1))
        .ok_or(DatabaseError::CapacityExceeded)?;
    // Reserve locator rows and a complete independent traversal before I/O.
    let declared = retention.checkpoint.work()?;
    Ok(Work {
        bytes: rows
            .checked_mul(ROW_BYTES as u64)
            .ok_or(DatabaseError::CapacityExceeded)?,
        records: rows,
        page_occurrences: 0,
    }
    .checked_add(Work {
        bytes: declared
            .page_occurrences
            .checked_mul(mb_core::CATALOG_PAGE_BYTES as u64)
            .ok_or(DatabaseError::CapacityExceeded)?,
        page_occurrences: declared.page_occurrences,
        records: declared.records,
    })?)
}
fn read<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Index>, CatalogStoreError> {
    let Some(bytes) = bounded_record(cx, JOURNAL, retention.id.as_bytes(), ROW_BYTES)? else {
        for suffix in ["revision", "ordered", "group"] {
            if cx.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
                [kind(retention.id, suffix)],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(DatabaseError::Integrity.into());
            }
        }
        return Ok(None);
    };
    let value: Index = decode_canonical(&bytes)?;
    if value.version != 1
        || value.id != retention.id
        || value.checkpoint_hash != retention.checkpoint.hash()?
        || value.certificate_hash != retention.certificate_hash
        || value.trust_hash != retention.trust_hash
        || value.work != reservation(retention)?
        || value.revisions > retention.checkpoint.authority_root().summary.revisions
        || value.groups > retention.checkpoint.coding().groups
        || value.complete
            && (value.revisions != retention.checkpoint.authority_root().summary.revisions
                || value.groups != retention.checkpoint.coding().groups)
        || canonical_bytes(&value)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(value))
}
pub(super) fn owned_work<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    Ok(read(cx, retention)?.map_or(Work::default(), |v| v.work))
}
fn require<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Index, CatalogStoreError> {
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Published {
        return Err(DatabaseError::NotReady.into());
    }
    owned_certificate(cx, retention)?;
    let value = read(cx, retention)?.ok_or(DatabaseError::NotReady)?;
    if !value.complete {
        return Err(DatabaseError::NotReady.into());
    }
    Ok(value)
}
fn guard<H: Layout>(
    control: &ControlStore,
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    trust: &mut impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    control.guard_paged_candidate(retention, trust)?;
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Published {
        return Err(DatabaseError::Conflict.into());
    }
    owned_certificate(cx, retention)?;
    Ok(())
}

pub(super) fn release<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<bool, CatalogStoreError> {
    let Some(index) = read(cx, retention)? else {
        return Ok(false);
    };
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Cancelled {
        return Err(DatabaseError::Conflict.into());
    }
    for (suffix, key_len) in [("revision", 16), ("ordered", 72), ("group", 32)] {
        let name = kind(retention.id, suffix);
        let row: Option<BoundedRow> = cx.query_row("SELECT CASE WHEN length(record_id)=?2 THEN record_id END,CASE WHEN length(bytes)<=?3 THEN bytes END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT 1",params![name,key_len,ROW_BYTES],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        if let Some((key, bytes)) = row {
            let key = key.ok_or(DatabaseError::Integrity)?;
            let bytes = bytes.ok_or(DatabaseError::Integrity)?;
            if cx.execute(
                "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
                params![name, key, bytes],
            )? != 1
            {
                return Err(DatabaseError::Integrity.into());
            }
            if bounded_record(cx, &name, &key, ROW_BYTES)?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(true);
        }
    }
    if cx.execute(
        "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
        params![JOURNAL, index.id.as_bytes(), canonical_bytes(&index)?],
    )? != 1
        || read(cx, retention)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(true)
}
fn change(cx: &Connection, old: Index, next: Index) -> Result<(), CatalogStoreError> {
    if cx.execute(
        "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
        params![
            JOURNAL,
            old.id.as_bytes(),
            canonical_bytes(&next)?,
            canonical_bytes(&old)?
        ],
    )? != 1
        || bounded_record(cx, JOURNAL, old.id.as_bytes(), ROW_BYTES)?.as_deref()
            != Some(canonical_bytes(&next)?.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn put(
    cx: &Connection,
    kind: &str,
    key: &[u8],
    value: &impl Serialize,
) -> Result<(), CatalogStoreError> {
    let bytes = mb_core::canonical_bytes_bounded(value, ROW_BYTES)?;
    match bounded_record(cx, kind, key, ROW_BYTES)? {
        Some(existing) if existing == bytes => {}
        None => {
            insert_exact(cx, kind, key, &bytes)?;
        }
        _ => return Err(DatabaseError::Integrity.into()),
    }
    if bounded_record(cx, kind, key, ROW_BYTES)?.as_deref() != Some(bytes.as_slice()) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn decode_row<T: serde::de::DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, CatalogStoreError> {
    let value: T = decode_canonical(bytes)?;
    if mb_core::canonical_bytes_bounded(&value, ROW_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

fn frame(
    cx: &Connection,
    scope: CatalogScope,
    section: CatalogSection,
    root: CatalogPageRef,
    location: Frame,
    budget: Work,
) -> Result<(Vec<u8>, Work), CatalogStoreError> {
    let range = location.range(root)?;
    budget.remaining_after(Work {
        bytes: u64::from(location.len),
        page_occurrences: 1,
        records: 1,
    })?;
    let mut used = Work {
        bytes: u64::from(location.len),
        records: 1,
        ..Work::default()
    };
    let mut reader = CatalogRangeReader::new(scope, section, root, range)?;
    let mut bytes = Vec::with_capacity(location.len as usize);
    while let Some(chunk) = unwrap_stream(reader.next_chunk(&mut |reference: CatalogPageRef| {
        used = used.checked_add(Work {
            bytes: u64::from(reference.encoded_len),
            page_occurrences: 1,
            records: 0,
        })?;
        budget.remaining_after(used)?;
        read_page(
            cx,
            PageMetadata {
                format_version: 1,
                scope,
                section,
                reference,
            },
        )
    }))? {
        bytes.extend(chunk);
    }
    if bytes.len() != location.len as usize || bytes.len() < 4 {
        return Err(DatabaseError::Integrity.into());
    }
    let length = u32::from_be_bytes(
        bytes[..4]
            .try_into()
            .map_err(|_| DatabaseError::Integrity)?,
    ) as usize;
    if length == 0 || length.checked_add(4) != Some(bytes.len()) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok((bytes[4..].to_vec(), used))
}

impl ControlStore {
    fn build_checkpoint_lookup<P: Proof>(
        &self,
        id: Uuid,
        proof: &P,
        mut trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let retention = proof.retention(id)?;
        proof.recheck(&mut trust)?;
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            guard(self, &tx, retention, &mut trust)?;
            if journal::require(&tx, retention)?.state
                != CatalogPagedCheckpointRetentionState::Published
            {
                return Err(DatabaseError::NotReady.into());
            }
            owned_certificate(&tx, retention)?;
            if read(&tx, retention)?.is_none() {
                let index = Index {
                    version: 1,
                    id,
                    checkpoint_hash: retention.checkpoint.hash()?,
                    certificate_hash: retention.certificate_hash,
                    trust_hash: retention.trust_hash,
                    revisions: 0,
                    groups: 0,
                    complete: false,
                    work: reservation(retention)?,
                };
                put(&tx, JOURNAL, id.as_bytes(), &index)?;
            }
            paged_checkpoint_revision::admitted_work(&tx, retention)?;
            guard(self, &tx, retention, &mut trust)?;
            tx.commit()?;
        }
        let scope = CatalogScope::Guild {
            guild_id: retention.checkpoint.guild_id(),
        };
        let declared = retention.checkpoint.work()?;
        let scan_budget = Work {
            bytes: declared
                .page_occurrences
                .checked_mul(mb_core::CATALOG_PAGE_BYTES as u64)
                .ok_or(DatabaseError::CapacityExceeded)?,
            page_occurrences: declared.page_occurrences,
            records: declared.records,
        };
        let mut scan = Work::default();
        let mut authority = CatalogCheckpointAuthorityReader::new_with_budget(
            scope,
            retention.checkpoint.authority_root(),
            retention.budget,
        )?;
        let mut revisions = 0_u64;
        while let Some(record) = unwrap_stream(authority.next_record(&mut |page| {
            guard(self, &self.connection, retention, &mut trust)?;
            scan = scan.checked_add(Work {
                bytes: u64::from(page.encoded_len),
                page_occurrences: 1,
                records: 0,
            })?;
            scan_budget.remaining_after(scan)?;
            self.catalog_page(scope, CatalogSection::Checkpoint, page)
        }))? {
            scan = scan.checked_add(Work {
                records: 1,
                ..Work::default()
            })?;
            scan_budget.remaining_after(scan)?;
            let Some(key) = record.revision_key() else {
                continue;
            };
            let row = Revision {
                key,
                frame: Frame::new(
                    authority
                        .last_record_range()
                        .ok_or(DatabaseError::Integrity)?,
                )?,
            };
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            guard(self, &tx, retention, &mut trust)?;
            put(&tx, &kind(id, "revision"), key.revision_id.as_bytes(), &row)?;
            put(
                &tx,
                &kind(id, "ordered"),
                &key.index_key(),
                &key.revision_id,
            )?;
            guard(self, &tx, retention, &mut trust)?;
            tx.commit()?;
            revisions = revisions.checked_add(1).ok_or(DatabaseError::Integrity)?;
        }
        let mut coding = CatalogCodingDirectoryReader::new(
            scope,
            retention.checkpoint.coding_root(),
            retention.budget,
        )?;
        let mut groups = 0_u64;
        while let Some(entry) = unwrap_stream(coding.next_group(&mut |page| {
            guard(self, &self.connection, retention, &mut trust)?;
            scan = scan.checked_add(Work {
                bytes: u64::from(page.encoded_len),
                page_occurrences: 1,
                records: 0,
            })?;
            scan_budget.remaining_after(scan)?;
            self.catalog_page(scope, CatalogSection::Coding, page)
        }))? {
            scan = scan.checked_add(Work {
                records: 1
                    + (mb_core::canonical_bytes_bounded(
                        &entry.transcript,
                        mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
                    )?
                    .len() as u64)
                        .div_ceil(mb_core::CATALOG_CODING_FRAGMENT_BYTES as u64),
                ..Work::default()
            })?;
            scan_budget.remaining_after(scan)?;
            let row = Group {
                forest: Frame::new(
                    coding
                        .last_group_forest_range()
                        .ok_or(DatabaseError::Integrity)?,
                )?,
                location: coding
                    .last_group_location()
                    .ok_or(DatabaseError::Integrity)?,
            };
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            guard(self, &tx, retention, &mut trust)?;
            put(&tx, &kind(id, "group"), &entry.retained.group.id, &row)?;
            guard(self, &tx, retention, &mut trust)?;
            tx.commit()?;
            groups = groups.checked_add(1).ok_or(DatabaseError::Integrity)?;
        }
        proof.recheck(&mut trust)?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        guard(self, &tx, retention, &mut trust)?;
        let old = read(&tx, retention)?.ok_or(DatabaseError::Integrity)?;
        if revisions != retention.checkpoint.authority_root().summary.revisions
            || groups != retention.checkpoint.coding().groups
        {
            return Err(DatabaseError::Integrity.into());
        }
        for (suffix, count) in [
            ("revision", revisions),
            ("ordered", revisions),
            ("group", groups),
        ] {
            let actual: u64 = tx.query_row(
                "SELECT count(*) FROM protocol_records WHERE kind=?1",
                [kind(id, suffix)],
                |r| r.get(0),
            )?;
            if actual != count {
                return Err(DatabaseError::Integrity.into());
            }
        }
        change(
            &tx,
            old,
            Index {
                revisions,
                groups,
                complete: true,
                ..old
            },
        )?;
        paged_checkpoint_revision::admitted_work(&tx, retention)?;
        guard(self, &tx, retention, &mut trust)?;
        tx.commit()?;
        Ok(())
    }

    fn read_lookup_revision<H: Layout>(
        &self,
        tx: &Connection,
        retention: CatalogPagedCheckpointRetention<H>,
        revision: Uuid,
        budget: Work,
    ) -> Result<Option<R>, CatalogStoreError> {
        let Some(bytes) = bounded_record(
            tx,
            &kind(retention.id, "revision"),
            revision.as_bytes(),
            ROW_BYTES,
        )?
        else {
            return Ok(None);
        };
        let row: Revision = decode_row(&bytes)?;
        if row.key.revision_id != revision {
            return Err(DatabaseError::Integrity.into());
        }
        let ordered = bounded_record(
            tx,
            &kind(retention.id, "ordered"),
            &row.key.index_key(),
            ROW_BYTES,
        )?
        .ok_or(DatabaseError::Integrity)?;
        if decode_row::<Uuid>(&ordered)? != revision {
            return Err(DatabaseError::Integrity.into());
        }
        let scope = CatalogScope::Guild {
            guild_id: retention.checkpoint.guild_id(),
        };
        let (bytes, _) = frame(
            tx,
            scope,
            CatalogSection::Checkpoint,
            retention.checkpoint.authority_root().records.page,
            row.frame,
            budget,
        )?;
        let record: R = decode_canonical(&bytes)?;
        if record.revision_key() != Some(row.key)
            || mb_core::canonical_bytes_bounded(&record, mb_core::CATALOG_CHECKPOINT_RECORD_BYTES)?
                != bytes
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(record))
    }
    fn lookup_revision<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        revision: Uuid,
        budget: Work,
    ) -> Result<Option<R>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        let record = self.read_lookup_revision(&tx, retention, revision, budget)?;
        tx.commit()?;
        Ok(record)
    }
    fn lookup_next_revision<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        after: Option<Key>,
        budget: Work,
    ) -> Result<Option<R>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        let row: Option<BoundedRow> = tx.query_row("SELECT CASE WHEN length(record_id)=72 THEN record_id END,CASE WHEN length(bytes)<=?3 THEN bytes END FROM protocol_records WHERE kind=?1 AND (?2 IS NULL OR record_id>?2) ORDER BY record_id LIMIT 1",params![kind(retention.id,"ordered"),after.map(|k|k.index_key().to_vec()),ROW_BYTES],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
        let Some((key, bytes)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        let key = key.ok_or(DatabaseError::Integrity)?;
        let revision: Uuid = decode_row(&bytes.ok_or(DatabaseError::Integrity)?)?;
        let record = self
            .read_lookup_revision(&tx, retention, revision, budget)?
            .ok_or(DatabaseError::Integrity)?;
        let actual = record.revision_key().ok_or(DatabaseError::Integrity)?;
        if actual.index_key().as_slice() != key || after.is_some_and(|previous| actual <= previous)
        {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(Some(record))
    }

    fn lookup_group<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        group: [u8; 32],
        budget: Work,
    ) -> Result<Option<mb_core::CatalogCodingEntry>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        let Some(bytes) = bounded_record(&tx, &kind(retention.id, "group"), &group, ROW_BYTES)?
        else {
            tx.commit()?;
            return Ok(None);
        };
        let row: Group = decode_row(&bytes)?;
        if row.location.range.group_id != group {
            return Err(DatabaseError::Integrity.into());
        }
        let scope = CatalogScope::Guild {
            guild_id: retention.checkpoint.guild_id(),
        };
        let coding = retention.checkpoint.coding_root();
        let (bytes, used) = frame(
            &tx,
            scope,
            CatalogSection::Coding,
            coding.records.page,
            row.forest,
            budget,
        )?;
        let forest = mb_core::CatalogCodingRoot::decode(&bytes)?;
        if forest.guild_event_sequence != coding.guild_event_sequence
            || forest
                .parts
                .get(usize::from(row.location.range.part))
                .is_none_or(|part| part.page != row.location.page)
        {
            return Err(DatabaseError::Integrity.into());
        }
        let (entry, _) = unwrap_stream(coding.read_group_with_work_budget(
            scope,
            retention.budget,
            row.location,
            budget.remaining_after(used)?,
            &mut |reference| {
                read_page(
                    &tx,
                    PageMetadata {
                        format_version: 1,
                        scope,
                        section: CatalogSection::Coding,
                        reference,
                    },
                )
            },
        ))?;
        tx.commit()?;
        Ok(Some(entry))
    }
}

macro_rules! api {
    ($header:ty,$proof:ty,$build:ident,$revision:ident,$next:ident,$group:ident) => {
        impl ControlStore {
            pub fn $build(
                &self,
                id: Uuid,
                proof: &$proof,
                trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
            ) -> Result<(), CatalogStoreError> {
                self.build_checkpoint_lookup(id, proof, trust)
            }
            pub fn $revision(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                revision: Uuid,
                budget: Work,
            ) -> Result<Option<R>, CatalogStoreError> {
                self.lookup_revision(retention, revision, budget)
            }
            pub fn $next(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                after: Option<Key>,
                budget: Work,
            ) -> Result<Option<R>, CatalogStoreError> {
                self.lookup_next_revision(retention, after, budget)
            }
            pub fn $group(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                group: [u8; 32],
                budget: Work,
            ) -> Result<Option<mb_core::CatalogCodingEntry>, CatalogStoreError> {
                self.lookup_group(retention, group, budget)
            }
        }
    };
}
api!(
    mb_core::PagedGuildCheckpoint,
    CatalogQuorumPagedCheckpointIndex,
    build_catalog_paged_checkpoint_lookup,
    catalog_paged_checkpoint_indexed_revision,
    next_catalog_paged_checkpoint_indexed_revision,
    catalog_paged_checkpoint_indexed_group
);
api!(
    mb_core::PagedGuildCheckpointDirectory,
    CatalogQuorumPagedCheckpointDirectoryIndex,
    build_catalog_paged_checkpoint_directory_lookup,
    catalog_paged_checkpoint_directory_indexed_revision,
    next_catalog_paged_checkpoint_directory_indexed_revision,
    catalog_paged_checkpoint_directory_indexed_group
);
