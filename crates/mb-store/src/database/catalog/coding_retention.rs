//! Durable local ownership of coding-directory and referenced forest roots.
//! This is a retention journal, not a checkpoint certificate or activation.

use mb_core::{
    CatalogCodingDirectoryReader, CatalogCodingDirectoryRoot, CatalogCodingTraversalBudget,
    CatalogStreamError,
};

use super::*;

const JOURNAL: &str = "catalog-coding-retention-v1";
const JOURNAL_BYTES: usize = 2048;

/// The immutable descriptor for a local retention job. IDs never resume after
/// cancellation. All referenced public roots must already be staged locally;
/// their original intents may be retired after retention finishes successfully.
/// The budget is a trusted local admission decision, never copied from peers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCodingRetention {
    pub id: Uuid,
    pub guild_id: [u8; 32],
    pub coding: CatalogCodingDirectoryRoot,
    pub budget: CatalogCodingTraversalBudget,
}

impl CatalogCodingRetention {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        self.scope().validate(CatalogSection::Coding)?;
        self.coding.validate(self.budget)?;
        Ok(())
    }

    fn scope(self) -> CatalogScope {
        CatalogScope::Guild {
            guild_id: self.guild_id,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogCodingRetentionState {
    Building,
    Published,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct JournalRecord {
    format_version: u16,
    retention: CatalogCodingRetention,
    state: CatalogCodingRetentionState,
    roots: u64,
    bytes: u64,
    pages: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Dependency {
    scope: CatalogScope,
    section: CatalogSection,
    root: CatalogPageRef,
}

impl Dependency {
    fn validate(self, retention: CatalogCodingRetention) -> Result<(), CatalogStoreError> {
        self.scope.validate(self.section)?;
        self.root.validate()?;
        if self.scope != retention.scope() || self.section != CatalogSection::Coding {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    fn page(self) -> PageMetadata {
        PageMetadata {
            format_version: 1,
            scope: self.scope,
            section: self.section,
            reference: self.root,
        }
    }
}

fn dependencies(id: Uuid) -> String {
    format!("catalog-coding-dependency-v1/{}", id.simple())
}

fn pin_id(id: Uuid) -> [u8; 17] {
    // Capture pins are 16 bytes; authority-retention pins use prefix one.
    // Prefix two separates coding ownership even when local job IDs coincide.
    let mut key = [0; 17];
    key[0] = 2;
    key[1..].copy_from_slice(id.as_bytes());
    key
}

fn read_journal(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<JournalRecord>, CatalogStoreError> {
    if id.is_nil() {
        return Err(DatabaseError::Conflict.into());
    }
    let Some(bytes) = bounded_record(connection, JOURNAL, id.as_bytes(), JOURNAL_BYTES)? else {
        return Ok(None);
    };
    let record: JournalRecord = decode_canonical(&bytes)?;
    record.retention.validate()?;
    if record.format_version != 1
        || record.retention.id != id
        || record.roots > record.pages
        || record.pages > record.retention.coding.work()?.page_occurrences
        || record.bytes > record.retention.coding.work()?.bytes
        || (record.roots == 0) != (record.pages == 0)
        || (record.roots == 0) != (record.bytes == 0)
        || (record.state == CatalogCodingRetentionState::Published && record.roots == 0)
        || canonical_bytes(&record)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(record))
}

fn require_journal(
    connection: &Connection,
    retention: CatalogCodingRetention,
) -> Result<JournalRecord, CatalogStoreError> {
    let record = read_journal(connection, retention.id)?.ok_or(DatabaseError::NotReady)?;
    if record.retention != retention {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(record)
}

fn write_journal(
    connection: &Connection,
    previous: JournalRecord,
    next: JournalRecord,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    if bytes.len() > JOURNAL_BYTES {
        return Err(DatabaseError::Integrity.into());
    }
    let written = connection.execute(
        "UPDATE protocol_records SET bytes = ?3
         WHERE kind = ?1 AND record_id = ?2 AND bytes = ?4",
        params![
            JOURNAL,
            previous.retention.id.as_bytes(),
            bytes,
            canonical_bytes(&previous)?
        ],
    )?;
    if written != 1 || read_journal(connection, previous.retention.id)? != Some(next) {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn retain_root(
    connection: &Connection,
    retention: CatalogCodingRetention,
    dependency: Dependency,
) -> Result<(), CatalogStoreError> {
    dependency.validate(retention)?;
    let previous = require_journal(connection, retention)?;
    if previous.state != CatalogCodingRetentionState::Building {
        return Err(DatabaseError::Conflict.into());
    }
    read_page(connection, dependency.page())?;
    let kind = dependencies(retention.id);
    let bytes = canonical_bytes(&dependency)?;
    let existing = bounded_record(connection, &kind, &dependency.root.hash, RECORD_BYTES)?;
    if let Some(existing) = existing {
        if existing != bytes
            || bounded_record(
                connection,
                &pins(dependency.root.hash),
                &pin_id(retention.id),
                0,
            )?
            .as_deref()
                != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(());
    }
    let mut next = previous;
    next.roots = next
        .roots
        .checked_add(1)
        .ok_or(DatabaseError::CapacityExceeded)?;
    next.bytes = next
        .bytes
        .checked_add(dependency.root.byte_len)
        .ok_or(DatabaseError::CapacityExceeded)?;
    next.pages = next
        .pages
        .checked_add(dependency.root.page_occurrences)
        .ok_or(DatabaseError::CapacityExceeded)?;
    if next.pages > retention.coding.work()?.page_occurrences
        || next.bytes > retention.coding.work()?.bytes
    {
        return Err(DatabaseError::CapacityExceeded.into());
    }
    insert_exact(connection, &kind, &dependency.root.hash, &bytes)?;
    insert_exact(
        connection,
        &pins(dependency.root.hash),
        &pin_id(retention.id),
        &[],
    )?;
    if bounded_record(connection, &kind, &dependency.root.hash, RECORD_BYTES)?.as_deref()
        != Some(&bytes)
        || bounded_record(
            connection,
            &pins(dependency.root.hash),
            &pin_id(retention.id),
            0,
        )?
        .as_deref()
            != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    connection.execute(
        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
        params![GC, dependency.root.hash],
    )?;
    write_journal(connection, previous, next)
}

fn stream_error(error: CatalogStreamError<CatalogStoreError>) -> CatalogStoreError {
    match error {
        CatalogStreamError::Catalog(error) => error.into(),
        CatalogStreamError::Storage(error) => error,
    }
}

impl ControlStore {
    /// Pin the directory and each referenced forest part, replaying every
    /// original witness in global order through complete authenticated EOF.
    /// Each bounded forest callback uses short per-root writer transactions;
    /// evidence traversal holds no writer. Building jobs replay after a crash.
    /// Failed jobs are fenced and release at most one root per cleanup step.
    ///
    /// The budget must come from trusted enclosing admission after charging
    /// other sections. This local metadata journal certifies neither current
    /// delegation/membership/lifecycle nor packing coverage. It owns no native,
    /// information, bootstrap or parity payload and activates no checkpoint.
    pub fn retain_catalog_coding_directory(
        &self,
        retention: CatalogCodingRetention,
    ) -> Result<(), CatalogStoreError> {
        retention.validate()?;
        let control = Dependency {
            scope: retention.scope(),
            section: CatalogSection::Coding,
            root: retention.coding.records.page,
        };
        {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            match read_journal(&transaction, retention.id)? {
                Some(record)
                    if record.retention != retention
                        || record.state == CatalogCodingRetentionState::Cancelled =>
                {
                    return Err(DatabaseError::Conflict.into());
                }
                Some(record) if record.state == CatalogCodingRetentionState::Published => {
                    return Ok(());
                }
                Some(_) => {}
                None => {
                    let orphan: bool = transaction.query_row(
                        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
                        [dependencies(retention.id)],
                        |row| row.get(0),
                    )?;
                    if orphan {
                        return Err(DatabaseError::Integrity.into());
                    }
                    insert_exact(
                        &transaction,
                        JOURNAL,
                        retention.id.as_bytes(),
                        &canonical_bytes(&JournalRecord {
                            format_version: 1,
                            retention,
                            state: CatalogCodingRetentionState::Building,
                            roots: 0,
                            bytes: 0,
                            pages: 0,
                        })?,
                    )?;
                }
            }
            retain_root(&transaction, retention, control)?;
            transaction.commit()?;
        }
        let result = (|| {
            let mut reader = CatalogCodingDirectoryReader::new(
                retention.scope(),
                retention.coding,
                retention.budget,
            )?;
            let mut fetch =
                |page| self.catalog_page(retention.scope(), CatalogSection::Coding, page);
            let mut forest = |root: &mb_core::CatalogCodingRoot| {
                for part in &root.parts {
                    let transaction = Transaction::new_unchecked(
                        &self.connection,
                        TransactionBehavior::Immediate,
                    )?;
                    retain_root(
                        &transaction,
                        retention,
                        Dependency {
                            scope: retention.scope(),
                            section: CatalogSection::Coding,
                            root: part.page,
                        },
                    )?;
                    transaction.commit()?;
                }
                Ok::<_, CatalogStoreError>(())
            };
            while reader
                .next_group_with_forest(&mut fetch, &mut forest)
                .map_err(stream_error)?
                .is_some()
            {}
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            let previous = require_journal(&transaction, retention)?;
            if previous.state != CatalogCodingRetentionState::Building {
                return Err(DatabaseError::Conflict.into());
            }
            let mut next = previous;
            next.state = CatalogCodingRetentionState::Published;
            write_journal(&transaction, previous, next)?;
            transaction.commit()?;
            Ok(())
        })();
        if result.is_err() {
            // A concurrent successful replay must not be retired by a failed
            // worker. Only fence a job that is still Building.
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            let previous = require_journal(&transaction, retention)?;
            if previous.state == CatalogCodingRetentionState::Building {
                let mut next = previous;
                next.state = CatalogCodingRetentionState::Cancelled;
                write_journal(&transaction, previous, next)?;
            }
            transaction.commit()?;
        }
        result
    }

    pub fn catalog_coding_retention(
        &self,
        id: Uuid,
    ) -> Result<Option<(CatalogCodingRetention, CatalogCodingRetentionState)>, CatalogStoreError>
    {
        Ok(read_journal(&self.connection, id)?.map(|record| (record.retention, record.state)))
    }

    /// Fence further acquisition/publication before releasing any root. This
    /// local API must be guarded by current checkpoint ownership at activation.
    pub fn cancel_catalog_coding_retention(&self, id: Uuid) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous = read_journal(&transaction, id)?.ok_or(DatabaseError::NotReady)?;
        if previous.state != CatalogCodingRetentionState::Cancelled {
            let mut next = previous;
            next.state = CatalogCodingRetentionState::Cancelled;
            write_journal(&transaction, previous, next)?;
        }
        transaction.commit()?;
        Ok(())
    }

    /// Release at most one cancelled journal root. Parent links preserve each
    /// immutable byte-tree closure; ordinary bounded page GC reclaims it only
    /// after every other capture/checkpoint/coding owner has released its references.
    pub fn release_catalog_coding_root(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let previous = read_journal(&transaction, id)?.ok_or(DatabaseError::NotReady)?;
        if previous.state != CatalogCodingRetentionState::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let kind = dependencies(id);
        let Some(hash) = candidate_hash(&transaction, &kind, &[])? else {
            if previous.roots != 0 {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(false);
        };
        let bytes = bounded_record(&transaction, &kind, &hash, RECORD_BYTES)?
            .ok_or(DatabaseError::Integrity)?;
        let dependency: Dependency = decode_canonical(&bytes)?;
        dependency.validate(previous.retention)?;
        if dependency.root.hash != hash
            || canonical_bytes(&dependency)? != bytes
            || metadata(&transaction, hash)? != dependency.page()
            || bounded_record(&transaction, &pins(hash), &pin_id(id), 0)?.as_deref() != Some(&[])
        {
            return Err(DatabaseError::Integrity.into());
        }
        let mut next = previous;
        next.roots = next.roots.checked_sub(1).ok_or(DatabaseError::Integrity)?;
        next.bytes = next
            .bytes
            .checked_sub(dependency.root.byte_len)
            .ok_or(DatabaseError::Integrity)?;
        next.pages = next
            .pages
            .checked_sub(dependency.root.page_occurrences)
            .ok_or(DatabaseError::Integrity)?;
        let removed = transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, hash, bytes],
        )?;
        let unpinned = transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![pins(hash), pin_id(id), &[] as &[u8]],
        )?;
        if removed != 1 || unpinned != 1 {
            return Err(DatabaseError::Conflict.into());
        }
        write_journal(&transaction, previous, next)?;
        queue_unreferenced(&transaction, hash)?;
        transaction.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{
        CatalogCodingBuilder, CatalogCodingDirectorySummary, CatalogCodingEntry,
        CatalogRecordBuilder, KeyMaterial, Seed,
    };

    struct Fixture {
        retention: CatalogCodingRetention,
        intents: Vec<CatalogIntent>,
        roots: Vec<Dependency>,
        entries: Vec<CatalogCodingEntry>,
    }

    fn keys() -> KeyMaterial {
        KeyMaterial::from_seed(&Seed::from_bytes([181; 32]))
    }

    fn fixture(store: &ControlStore, count: u64, duplicate: bool) -> Fixture {
        let packing = super::super::packing_validation::tests::fixture(3, true);
        let mut entries = (1..=count)
            .map(|id| super::super::coding_coverage::tests::entry(&packing, [0, 1, 2], id, 2, None))
            .collect::<Vec<_>>();
        entries.sort_by_key(|entry| entry.retained.group.id);
        if duplicate {
            entries.push(entries.last().unwrap().clone());
        }
        let scope = packing.manifest.scope;
        let mut intents = Vec::new();
        let mut roots = Vec::new();
        let mut forests = Vec::new();
        let mut summary = CatalogCodingDirectorySummary::default();
        for (index, entry) in entries.iter().enumerate() {
            let intent = CatalogIntent {
                id: Uuid::from_u128(index as u128 + 10),
                scope,
                section: CatalogSection::Coding,
            };
            store.begin_catalog(intent).unwrap();
            let mut sink = |page, bytes: Vec<u8>| store.stage_catalog_page(intent, page, &bytes);
            let mut builder = CatalogCodingBuilder::new(scope, 100).unwrap();
            builder.push_group(entry, &mut sink).unwrap();
            let root = builder.finish(&mut sink).unwrap();
            summary.forests += 1;
            summary.coding.groups += root.summary.groups;
            summary.coding.retired_groups += root.summary.retired_groups;
            summary.coding.information_roles += root.summary.information_roles;
            summary.coding.parity_roles += root.summary.parity_roles;
            summary.coding.transcript_bytes += root.summary.transcript_bytes;
            summary.coding.fragments += root.summary.fragments;
            for part in &root.parts {
                roots.push(Dependency {
                    scope,
                    section: CatalogSection::Coding,
                    root: part.page,
                });
                summary.evidence_bytes += part.page.byte_len;
                summary.evidence_pages += part.page.page_occurrences;
            }
            intents.push(intent);
            forests.push(root);
        }
        let control = CatalogIntent {
            id: Uuid::from_u128(1),
            scope,
            section: CatalogSection::Coding,
        };
        store.begin_catalog(control).unwrap();
        let mut builder = CatalogRecordBuilder::new(scope, CatalogSection::Coding).unwrap();
        let mut sink = |page, bytes: Vec<u8>| store.stage_catalog_page(control, page, &bytes);
        for root in &forests {
            builder.push(root, &mut sink).unwrap();
        }
        let records = builder.finish(&mut sink).unwrap();
        intents.push(control);
        roots.push(Dependency {
            scope,
            section: CatalogSection::Coding,
            root: records.page,
        });
        let coding = CatalogCodingDirectoryRoot {
            format_version: 1,
            guild_event_sequence: 100,
            records,
            summary,
        };
        let retention = CatalogCodingRetention {
            id: control.id,
            guild_id: [7; 32],
            coding,
            budget: coding.work().unwrap(),
        };
        retention.validate().unwrap();
        Fixture {
            retention,
            intents,
            roots,
            entries,
        }
    }

    fn release_originals(store: &ControlStore, fixture: &Fixture) {
        for intent in &fixture.intents {
            store.cancel_catalog(*intent).unwrap();
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
    }

    fn assert_roots(store: &ControlStore, fixture: &Fixture, present: bool) {
        for dependency in &fixture.roots {
            assert_eq!(
                store
                    .catalog_page(dependency.scope, dependency.section, dependency.root)
                    .is_ok(),
                present
            );
        }
    }

    fn replay(store: &ControlStore, fixture: &Fixture) {
        let mut reader = CatalogCodingDirectoryReader::new(
            fixture.retention.scope(),
            fixture.retention.coding,
            fixture.retention.budget,
        )
        .unwrap();
        let mut fetch =
            |page| store.catalog_page(fixture.retention.scope(), CatalogSection::Coding, page);
        for expected in &fixture.entries {
            assert_eq!(
                reader.next_group(&mut fetch).unwrap().as_ref(),
                Some(expected)
            );
            assert_eq!(
                fixture
                    .retention
                    .coding
                    .read_group(
                        fixture.retention.scope(),
                        fixture.retention.budget,
                        reader.last_group_location().unwrap(),
                        &mut fetch
                    )
                    .unwrap(),
                *expected
            );
        }
        assert!(reader.next_group(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn coding_directory_roots_survive_reopen_share_and_retire_beyond_fixed_bundles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = fixture(&store, 20, false);
        assert!(fixture.roots.len() > CATALOG_BUNDLE_ROOTS);
        store
            .retain_catalog_coding_directory(fixture.retention)
            .unwrap();
        store
            .retain_catalog_coding_directory(fixture.retention)
            .unwrap();
        let successor = CatalogCodingRetention {
            id: Uuid::from_u128(2),
            ..fixture.retention
        };
        store.retain_catalog_coding_directory(successor).unwrap();
        assert_eq!(
            read_journal(&store.connection, fixture.retention.id)
                .unwrap()
                .unwrap()
                .roots,
            21
        );
        release_originals(&store, &fixture);
        assert_roots(&store, &fixture, true);
        drop(store);
        let mut store = ControlStore::open(&path, &keys()).unwrap();
        assert_eq!(
            store
                .catalog_coding_retention(fixture.retention.id)
                .unwrap(),
            Some((fixture.retention, CatalogCodingRetentionState::Published))
        );
        replay(&store, &fixture);
        assert!(
            store
                .release_catalog_coding_root(fixture.retention.id)
                .is_err()
        );
        store
            .cancel_catalog_coding_retention(fixture.retention.id)
            .unwrap();
        for remaining in (0..21).rev() {
            assert!(
                store
                    .release_catalog_coding_root(fixture.retention.id)
                    .unwrap()
            );
            assert_eq!(
                read_journal(&store.connection, fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .roots,
                remaining
            );
            if remaining == 10 {
                drop(store);
                store = ControlStore::open(&path, &keys()).unwrap();
            }
        }
        assert!(
            !store
                .release_catalog_coding_root(fixture.retention.id)
                .unwrap()
        );
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, true);
        assert!(
            store
                .retain_catalog_coding_directory(fixture.retention)
                .is_err()
        );
        store.cancel_catalog_coding_retention(successor.id).unwrap();
        while store.release_catalog_coding_root(successor.id).unwrap() {}
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn interrupted_coding_retention_replays_after_reopen_and_rejects_substitution() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = fixture(&store, 3, false);
        let transaction =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        insert_exact(
            &transaction,
            JOURNAL,
            fixture.retention.id.as_bytes(),
            &canonical_bytes(&JournalRecord {
                format_version: 1,
                retention: fixture.retention,
                state: CatalogCodingRetentionState::Building,
                roots: 0,
                bytes: 0,
                pages: 0,
            })
            .unwrap(),
        )
        .unwrap();
        retain_root(
            &transaction,
            fixture.retention,
            *fixture.roots.last().unwrap(),
        )
        .unwrap();
        retain_root(&transaction, fixture.retention, fixture.roots[0]).unwrap();
        transaction.commit().unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys()).unwrap();
        assert_eq!(
            store
                .catalog_coding_retention(fixture.retention.id)
                .unwrap()
                .unwrap()
                .1,
            CatalogCodingRetentionState::Building
        );
        let mut bad = fixture.retention;
        bad.budget.bytes += 1;
        assert!(store.retain_catalog_coding_directory(bad).is_err());
        store
            .retain_catalog_coding_directory(fixture.retention)
            .unwrap();
        assert_eq!(
            read_journal(&store.connection, fixture.retention.id)
                .unwrap()
                .unwrap()
                .roots,
            4
        );
        release_originals(&store, &fixture);
        replay(&store, &fixture);
    }

    #[test]
    fn late_coding_order_and_page_failures_fence_jobs_without_publishing_prefixes() {
        for duplicate in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("control.db");
            let store = ControlStore::open(&path, &keys()).unwrap();
            let fixture = fixture(&store, 3, duplicate);
            let mut damaged = None;
            if !duplicate {
                let last = fixture.roots[2].root;
                damaged = Some((
                    last.hash,
                    store
                        .catalog_page(fixture.retention.scope(), CatalogSection::Coding, last)
                        .unwrap(),
                ));
                store.connection.execute("UPDATE protocol_records SET bytes=zeroblob(length(bytes)) WHERE kind=?1 AND record_id=?2",
                    params![PAGE, last.hash]).unwrap();
            }
            assert!(
                store
                    .retain_catalog_coding_directory(fixture.retention)
                    .is_err()
            );
            assert_eq!(
                store
                    .catalog_coding_retention(fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .1,
                CatalogCodingRetentionState::Cancelled
            );
            assert!(
                read_journal(&store.connection, fixture.retention.id)
                    .unwrap()
                    .unwrap()
                    .roots
                    >= 3
            );
            assert!(
                store
                    .retain_catalog_coding_directory(fixture.retention)
                    .is_err()
            );
            // GC authenticates page contents before discovering their children.
            // Repair this deliberately damaged fixture before testing cleanup;
            // a cancelled job must never turn corruption into an unsafe delete.
            if let Some((hash, bytes)) = damaged {
                store
                    .connection
                    .execute(
                        "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2",
                        params![PAGE, hash, bytes],
                    )
                    .unwrap();
            }
            drop(store);
            let store = ControlStore::open(&path, &keys()).unwrap();
            while store
                .release_catalog_coding_root(fixture.retention.id)
                .unwrap()
            {}
            release_originals(&store, &fixture);
            assert_roots(&store, &fixture, false);
        }
    }

    #[test]
    fn coding_retention_ignored_writes_preserve_atomic_pins_counters_and_completion() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 2, false);
        store.connection.execute_batch("CREATE TEMP TRIGGER ignore_coding_counts BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-coding-retention-v1' BEGIN SELECT RAISE(IGNORE); END").unwrap();
        assert!(
            store
                .retain_catalog_coding_directory(fixture.retention)
                .is_err()
        );
        assert!(
            store
                .catalog_coding_retention(fixture.retention.id)
                .unwrap()
                .is_none()
        );
        assert!(
            candidate_hash(&store.connection, &dependencies(fixture.retention.id), &[])
                .unwrap()
                .is_none()
        );
        assert!(
            bounded_record(
                &store.connection,
                &pins(fixture.retention.coding.records.page.hash),
                &pin_id(fixture.retention.id),
                0
            )
            .unwrap()
            .is_none()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_coding_counts")
            .unwrap();
        let published = JournalRecord {
            format_version: 1,
            retention: fixture.retention,
            state: CatalogCodingRetentionState::Published,
            roots: fixture.roots.len() as u64,
            bytes: fixture
                .roots
                .iter()
                .map(|dependency| dependency.root.byte_len)
                .sum(),
            pages: fixture
                .roots
                .iter()
                .map(|dependency| dependency.root.page_occurrences)
                .sum(),
        };
        store.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER ignore_coding_completion BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-coding-retention-v1' AND NEW.bytes=X'{}' BEGIN SELECT RAISE(IGNORE); END",
            hex::encode(canonical_bytes(&published).unwrap()))).unwrap();
        assert!(
            store
                .retain_catalog_coding_directory(fixture.retention)
                .is_err()
        );
        assert_eq!(
            store
                .catalog_coding_retention(fixture.retention.id)
                .unwrap()
                .unwrap()
                .1,
            CatalogCodingRetentionState::Cancelled
        );
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_coding_completion")
            .unwrap();
        let before = read_journal(&store.connection, fixture.retention.id)
            .unwrap()
            .unwrap();
        store.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER ignore_coding_release BEFORE DELETE ON protocol_records WHEN OLD.kind='{}' BEGIN SELECT RAISE(IGNORE); END", dependencies(fixture.retention.id))).unwrap();
        assert!(
            store
                .release_catalog_coding_root(fixture.retention.id)
                .is_err()
        );
        assert_eq!(
            read_journal(&store.connection, fixture.retention.id).unwrap(),
            Some(before)
        );
        for dependency in &fixture.roots {
            assert_eq!(
                bounded_record(
                    &store.connection,
                    &pins(dependency.root.hash),
                    &pin_id(fixture.retention.id),
                    0
                )
                .unwrap()
                .as_deref(),
                Some(&[] as &[u8])
            );
        }
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_coding_release")
            .unwrap();
        while store
            .release_catalog_coding_root(fixture.retention.id)
            .unwrap()
        {}
        release_originals(&store, &fixture);
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn coding_retention_admission_orphans_scopes_and_pin_namespaces_fail_closed() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 1, false);
        for dimension in 0..5 {
            let mut bad = fixture.retention;
            match dimension {
                0 => bad.budget.bytes -= 1,
                1 => bad.budget.page_occurrences -= 1,
                2 => bad.budget.records -= 1,
                3 => bad.id = Uuid::nil(),
                _ => bad.guild_id = [0; 32],
            }
            assert!(store.retain_catalog_coding_directory(bad).is_err());
            assert!(
                read_journal(&store.connection, fixture.retention.id)
                    .unwrap()
                    .is_none()
            );
        }
        let hash = fixture.roots[0].root.hash;
        insert_exact(
            &store.connection,
            &dependencies(fixture.retention.id),
            &hash,
            &[],
        )
        .unwrap();
        assert!(
            store
                .retain_catalog_coding_directory(fixture.retention)
                .is_err()
        );
        store
            .connection
            .execute(
                "DELETE FROM protocol_records WHERE kind=?1",
                [dependencies(fixture.retention.id)],
            )
            .unwrap();
        let mut wrong = fixture.retention;
        wrong.guild_id = [8; 32];
        assert!(store.retain_catalog_coding_directory(wrong).is_err());
        assert!(read_journal(&store.connection, wrong.id).unwrap().is_none());
        store
            .retain_catalog_coding_directory(fixture.retention)
            .unwrap();
        let mut authority_pin = pin_id(fixture.retention.id);
        authority_pin[0] = 1;
        insert_exact(&store.connection, &pins(hash), &authority_pin, &[]).unwrap();
        assert_ne!(
            pin_id(fixture.retention.id).as_slice(),
            fixture.retention.id.as_bytes()
        );
        store
            .cancel_catalog_coding_retention(fixture.retention.id)
            .unwrap();
        while store
            .release_catalog_coding_root(fixture.retention.id)
            .unwrap()
        {}
        assert_eq!(
            bounded_record(&store.connection, &pins(hash), &authority_pin, 0)
                .unwrap()
                .as_deref(),
            Some(&[] as &[u8])
        );
        release_originals(&store, &fixture);
        assert!(
            store
                .catalog_page(
                    fixture.roots[0].scope,
                    CatalogSection::Coding,
                    fixture.roots[0].root
                )
                .is_ok()
        );
        store
            .connection
            .execute(
                "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2",
                params![pins(hash), authority_pin],
            )
            .unwrap();
        queue_unreferenced(&store.connection, hash).unwrap();
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn empty_coding_directory_retains_its_authenticated_stream() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 0, false);
        store
            .retain_catalog_coding_directory(fixture.retention)
            .unwrap();
        release_originals(&store, &fixture);
        replay(&store, &fixture);
        assert_eq!(
            read_journal(&store.connection, fixture.retention.id)
                .unwrap()
                .unwrap()
                .roots,
            1
        );
        store
            .cancel_catalog_coding_retention(fixture.retention.id)
            .unwrap();
        assert!(
            store
                .release_catalog_coding_root(fixture.retention.id)
                .unwrap()
        );
        assert!(
            !store
                .release_catalog_coding_root(fixture.retention.id)
                .unwrap()
        );
        while store.collect_catalog_page().unwrap() {}
        assert_roots(&store, &fixture, false);
    }
}
