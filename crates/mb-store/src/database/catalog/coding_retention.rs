//! Durable local ownership of coding-directory and referenced forest roots.
//! This is a retention journal, not a checkpoint certificate or activation.

use mb_core::{
    CatalogCodingDirectoryReader, CatalogCodingDirectoryRoot, CatalogCodingTraversalBudget,
    CatalogStreamError,
};

use super::retention_journal::{self as journal, Dependency};
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

pub use journal::CatalogRetentionState as CatalogCodingRetentionState;

#[cfg(test)]
type JournalRecord = journal::JournalRecord<CatalogCodingRetention>;

impl journal::Retention for CatalogCodingRetention {
    const JOURNAL: &'static str = JOURNAL;
    const JOURNAL_BYTES: usize = JOURNAL_BYTES;
    const DEPENDENCIES: &'static str = "catalog-coding-dependency-v1";
    const PIN_PREFIX: u8 = 2;

    fn id(self) -> Uuid {
        self.id
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        CatalogCodingRetention::validate(self)
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        let work = self.coding.work()?;
        Ok((work.bytes, work.page_occurrences))
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        scope == self.scope() && section == CatalogSection::Coding
    }
}

#[cfg(test)]
fn dependencies(id: Uuid) -> String {
    journal::dependencies::<CatalogCodingRetention>(id)
}
#[cfg(test)]
fn pin_id(id: Uuid) -> [u8; 17] {
    journal::pin_id::<CatalogCodingRetention>(id)
}
fn read_journal(
    connection: &Connection,
    id: Uuid,
) -> Result<Option<journal::JournalRecord<CatalogCodingRetention>>, CatalogStoreError> {
    journal::read(connection, id)
}
#[cfg(test)]
fn retain_root(
    connection: &Connection,
    retention: CatalogCodingRetention,
    dependency: Dependency,
) -> Result<(), CatalogStoreError> {
    journal::retain(connection, retention, dependency)
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
            if journal::begin(&transaction, retention)? == CatalogCodingRetentionState::Published {
                return Ok(());
            }
            journal::retain(&transaction, retention, control)?;
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
                    journal::retain(
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
            journal::publish(&transaction, retention)?;
            transaction.commit()?;
            Ok(())
        })();
        if result.is_err() {
            // A concurrent successful replay must not be retired by a failed
            // worker. Only fence a job that is still Building.
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::cancel_building(&transaction, retention)?;
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
        journal::cancel::<CatalogCodingRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }

    /// Release at most one cancelled journal root. Parent links preserve each
    /// immutable byte-tree closure; ordinary bounded page GC reclaims it only
    /// after every other capture/checkpoint/coding owner has released its references.
    pub fn release_catalog_coding_root(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let released = journal::release::<CatalogCodingRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(released)
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

    #[test]
    fn coding_retention_v1_journal_and_pin_layout_remain_unchanged() {
        use CatalogCodingRetentionState::*;
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = fixture(&store, 1, false);
        journal::assert_v1_layout(
            &store.connection,
            fixture.retention,
            fixture.retention.coding.records.page,
        );
        assert_eq!(
            store
                .catalog_coding_retention(fixture.retention.id)
                .unwrap()
                .unwrap()
                .1,
            Cancelled
        );
        let pin = pin_id(fixture.retention.id);
        assert_eq!(pin[0], 2);
        assert_eq!(&pin[1..], fixture.retention.id.as_bytes());
        assert_eq!(
            dependencies(fixture.retention.id),
            format!(
                "catalog-coding-dependency-v1/{}",
                fixture.retention.id.simple()
            )
        );
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
