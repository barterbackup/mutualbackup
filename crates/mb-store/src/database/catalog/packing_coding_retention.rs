//! One durable local owner for a completed packing/coding directory proof.
//! Current certified checkpoint guards and payload ownership remain external.

use mb_core::{
    CatalogCodingDirectoryReader, CatalogCodingTraversalBudget, CatalogPackedSectorReader,
    CatalogPackedSourceReader,
};

use super::packing_validation::unwrap_stream;
use super::retention_journal::{self as journal, Dependency, Retention};
use super::*;

/// Immutable local job identity. Only a completed admitted coverage index can
/// start or resume acquisition. Original staging intents must remain owned
/// until this job publishes successfully. Cancellation permanently fences IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingCodingRetention {
    pub id: Uuid,
    pub manifest: CatalogPackingCodingDirectoryValidation,
    pub budget: CatalogCodingTraversalBudget,
}

pub use journal::CatalogRetentionState as CatalogPackingCodingRetentionState;

impl CatalogPackingCodingRetention {
    fn scope(self) -> CatalogScope {
        self.manifest.packing.scope
    }

    fn initial(self) -> [Dependency; 3] {
        [
            Dependency {
                scope: self.scope(),
                section: CatalogSection::Packing,
                root: self.manifest.packing.descriptors.records.page,
            },
            Dependency {
                scope: self.scope(),
                section: CatalogSection::Packing,
                root: self.manifest.packing.sources.records.page,
            },
            Dependency {
                scope: self.scope(),
                section: CatalogSection::Coding,
                root: self.manifest.coding.records.page,
            },
        ]
    }
}

impl Retention for CatalogPackingCodingRetention {
    const JOURNAL: &'static str = "catalog-packing-coding-retention-v1";
    const JOURNAL_BYTES: usize = 8192;
    const DEPENDENCIES: &'static str = "catalog-packing-coding-dependency-v1";
    const PIN_PREFIX: u8 = 3;

    fn id(self) -> Uuid {
        self.id
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        self.manifest.validate(self.budget)
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        // This owner retains packing/coding metadata, not the authority prefix.
        // Traversal continues to charge all logical occurrences; distinct root
        // pins/counters may be smaller when roles or forests share closures.
        let work = self
            .manifest
            .represented_work()?
            .remaining_after(self.manifest.prior_work)?;
        Ok((work.bytes, work.page_occurrences))
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        scope == self.scope() && matches!(section, CatalogSection::Packing | CatalogSection::Coding)
    }
}

impl ControlStore {
    /// Acquire one local owner for both packing roots, the directory and every
    /// logical forest part. Initial roots are pinned atomically; bounded forest
    /// callbacks pin parts before evidence reads. Publish only after full local
    /// source/descriptor/coding EOF and original witness replay. Traversal holds
    /// no production writer. Crash-interrupted jobs replay with the same proof.
    ///
    /// This binds immutable completed coverage to durable metadata. It does not
    /// certify current guild events, own authority/private/native/bootstrap or
    /// information/parity payloads, or activate a checkpoint. The enclosing
    /// certified-current checkpoint must guard publication and retirement.
    pub fn retain_catalog_packing_coding(
        &self,
        id: Uuid,
        proof: &CatalogPackingCodingDirectoryIndex,
    ) -> Result<CatalogPackingCodingRetention, CatalogStoreError> {
        proof.require_complete()?;
        let retention = CatalogPackingCodingRetention {
            id,
            manifest: proof.manifest(),
            budget: proof.budget(),
        };
        retention.validate()?;
        {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            if journal::begin(&transaction, retention)?
                == CatalogPackingCodingRetentionState::Published
            {
                return Ok(retention);
            }
            for dependency in retention.initial() {
                journal::retain(&transaction, retention, dependency)?;
            }
            transaction.commit()?;
        }
        let result = (|| {
            let mut fetch_packing =
                |page| self.catalog_page(retention.scope(), CatalogSection::Packing, page);
            let mut sources = CatalogPackedSourceReader::new(
                retention.scope(),
                retention.manifest.packing.sources,
            )?;
            while unwrap_stream(sources.next_record(&mut fetch_packing))?.is_some() {}
            let mut descriptors = CatalogPackedSectorReader::new(
                retention.scope(),
                retention.manifest.packing.descriptors,
            )?;
            while unwrap_stream(
                descriptors.next_record_with_sources(&mut fetch_packing, &mut |key| {
                    proof.packing().source_id(key)
                }),
            )?
            .is_some()
            {}

            let mut reader = CatalogCodingDirectoryReader::new(
                retention.scope(),
                retention.manifest.coding,
                retention.manifest.coding_budget(retention.budget)?,
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
            while unwrap_stream(reader.next_group_with_forest(&mut fetch, &mut forest))?.is_some() {
            }
            proof.require_complete()?;
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::publish(&transaction, retention)?;
            transaction.commit()?;
            Ok(retention)
        })();
        if result.is_err() {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::cancel_building(&transaction, retention)?;
            transaction.commit()?;
        }
        result
    }

    pub fn catalog_packing_coding_retention(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(
            CatalogPackingCodingRetention,
            CatalogPackingCodingRetentionState,
        )>,
        CatalogStoreError,
    > {
        Ok(
            journal::read::<CatalogPackingCodingRetention>(&self.connection, id)?
                .map(|record| (record.retention, record.state)),
        )
    }

    /// Local metadata retirement only. Activation must guard this operation
    /// against the certified current checkpoint and every retained successor.
    pub fn cancel_catalog_packing_coding_retention(
        &self,
        id: Uuid,
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        journal::cancel::<CatalogPackingCodingRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(())
    }

    /// Release at most one cancelled root closure, atomically with its pin and
    /// counters. Other capture/retention owners continue to preserve shared pages.
    pub fn release_catalog_packing_coding_root(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let released = journal::release::<CatalogPackingCodingRetention>(&transaction, id)?;
        transaction.commit()?;
        Ok(released)
    }
}

#[cfg(test)]
mod tests {
    use super::super::coding_directory_coverage::tests::Fixture;
    use super::*;
    use mb_core::{CatalogPageContents, KeyMaterial, Seed};
    use std::collections::HashMap;

    type Record = journal::JournalRecord<CatalogPackingCodingRetention>;

    fn keys() -> KeyMaterial {
        KeyMaterial::from_seed(&Seed::from_bytes([183; 32]))
    }

    fn job(id: u128, proof: &CatalogPackingCodingDirectoryIndex) -> CatalogPackingCodingRetention {
        CatalogPackingCodingRetention {
            id: Uuid::from_u128(id),
            manifest: proof.manifest(),
            budget: proof.budget(),
        }
    }

    fn record(store: &ControlStore, id: Uuid) -> Record {
        journal::read(&store.connection, id).unwrap().unwrap()
    }

    fn roots(fixture: &Fixture) -> Vec<Dependency> {
        let scope = fixture.packing.manifest.scope;
        let mut roots = vec![
            Dependency {
                scope,
                section: CatalogSection::Packing,
                root: fixture.packing.manifest.descriptors.records.page,
            },
            Dependency {
                scope,
                section: CatalogSection::Packing,
                root: fixture.packing.manifest.sources.records.page,
            },
            Dependency {
                scope,
                section: CatalogSection::Coding,
                root: fixture.root.records.page,
            },
        ];
        for forest in &fixture.forests {
            for part in &forest.parts {
                roots.push(Dependency {
                    scope,
                    section: CatalogSection::Coding,
                    root: part.page,
                });
            }
        }
        roots.sort_by_key(|dependency| dependency.root.hash);
        roots.dedup_by_key(|dependency| dependency.root.hash);
        roots
    }

    // Fixture trees are small and depth-bounded. Stage children before parents
    // exactly as a producer would, with independent bounded capture intents.
    fn stage_tree(
        store: &ControlStore,
        intent: CatalogIntent,
        root: CatalogPageRef,
        pages: &HashMap<[u8; 32], Vec<u8>>,
    ) {
        let bytes = &pages[&root.hash];
        if let CatalogPageContents::Index(children) = root
            .verify_page(intent.scope, intent.section, bytes)
            .unwrap()
        {
            for child in children {
                stage_tree(store, intent, child, pages);
            }
        }
        store.stage_catalog_page(intent, root, bytes).unwrap();
    }

    fn stage(store: &ControlStore, fixture: &Fixture) -> Vec<CatalogIntent> {
        let scope = fixture.packing.manifest.scope;
        let mut intents = Vec::new();
        for (index, role) in fixture.packing.roles.iter().enumerate() {
            let intent = CatalogIntent {
                id: Uuid::from_u128(index as u128 + 10),
                scope,
                section: CatalogSection::Packing,
            };
            store.begin_catalog(intent).unwrap();
            for (page, bytes) in role {
                store.stage_catalog_page(intent, *page, bytes).unwrap();
            }
            intents.push(intent);
        }
        for (index, forest) in fixture.forests.iter().enumerate() {
            let intent = CatalogIntent {
                id: Uuid::from_u128(index as u128 + 100),
                scope,
                section: CatalogSection::Coding,
            };
            store.begin_catalog(intent).unwrap();
            for part in &forest.parts {
                stage_tree(store, intent, part.page, &fixture.pages);
            }
            intents.push(intent);
        }
        let intent = CatalogIntent {
            id: Uuid::from_u128(1),
            scope,
            section: CatalogSection::Coding,
        };
        store.begin_catalog(intent).unwrap();
        stage_tree(store, intent, fixture.root.records.page, &fixture.pages);
        intents.push(intent);
        intents
    }

    fn collect(store: &ControlStore) {
        while store.collect_catalog_page().unwrap() {}
    }

    fn release_originals(store: &ControlStore, intents: &[CatalogIntent]) {
        for intent in intents {
            store.cancel_catalog(*intent).unwrap();
            while store.release_catalog_pin(*intent).unwrap() {}
        }
        collect(store);
    }

    fn assert_roots(store: &ControlStore, fixture: &Fixture, present: bool) {
        for dependency in roots(fixture) {
            assert_eq!(
                store
                    .catalog_page(dependency.scope, dependency.section, dependency.root)
                    .is_ok(),
                present
            );
        }
    }

    fn replay(store: &ControlStore, fixture: &Fixture, proof: &CatalogPackingCodingDirectoryIndex) {
        let scope = fixture.packing.manifest.scope;
        let mut fetch = |page| store.catalog_page(scope, CatalogSection::Packing, page);
        let mut sources =
            CatalogPackedSourceReader::new(scope, fixture.packing.manifest.sources).unwrap();
        while sources.next_record(&mut fetch).unwrap().is_some() {}
        let mut descriptors =
            CatalogPackedSectorReader::new(scope, fixture.packing.manifest.descriptors).unwrap();
        while descriptors
            .next_record_with_sources(&mut fetch, &mut |key| proof.packing().source_id(key))
            .unwrap()
            .is_some()
        {}
        for expected in &fixture.entries {
            assert_eq!(
                proof
                    .read_group(expected.retained.group.id, |page| store.catalog_page(
                        scope,
                        CatalogSection::Coding,
                        page
                    ))
                    .unwrap()
                    .as_ref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn combined_owner_survives_reopen_and_shared_successor_retirement_beyond_bundles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = Fixture::new(60);
        let intents = stage(&store, &fixture);
        let proof = fixture.build(4 * 1024 * 1024).unwrap();
        let retention = store
            .retain_catalog_packing_coding(Uuid::from_u128(1), &proof)
            .unwrap();
        assert_eq!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .unwrap(),
            retention
        );
        let successor = store
            .retain_catalog_packing_coding(Uuid::from_u128(2), &proof)
            .unwrap();
        let count = roots(&fixture).len() as u64;
        assert_eq!(count, 23);
        assert!(count as usize > CATALOG_BUNDLE_ROOTS);
        assert_eq!(record(&store, retention.id).roots, count);
        // A late failed worker cannot cancel a concurrently completed replay.
        let transaction =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        journal::cancel_building(&transaction, retention).unwrap();
        transaction.commit().unwrap();
        release_originals(&store, &intents);
        assert_roots(&store, &fixture, true);
        drop(store);
        let mut store = ControlStore::open(&path, &keys()).unwrap();
        assert_eq!(
            store
                .catalog_packing_coding_retention(retention.id)
                .unwrap(),
            Some((retention, CatalogPackingCodingRetentionState::Published))
        );
        replay(&store, &fixture, &proof);
        assert!(
            store
                .release_catalog_packing_coding_root(retention.id)
                .is_err()
        );
        store
            .cancel_catalog_packing_coding_retention(retention.id)
            .unwrap();
        for remaining in (0..count).rev() {
            assert!(
                store
                    .release_catalog_packing_coding_root(retention.id)
                    .unwrap()
            );
            assert_eq!(record(&store, retention.id).roots, remaining);
            if remaining == 10 {
                drop(store);
                store = ControlStore::open(&path, &keys()).unwrap();
            }
        }
        assert!(
            !store
                .release_catalog_packing_coding_root(retention.id)
                .unwrap()
        );
        collect(&store);
        replay(&store, &fixture, &proof);
        assert!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .is_err()
        );
        store
            .cancel_catalog_packing_coding_retention(successor.id)
            .unwrap();
        while store
            .release_catalog_packing_coding_root(successor.id)
            .unwrap()
        {}
        collect(&store);
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn combined_owner_resumes_interrupted_acquisition_with_exact_proof_and_budget() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = Fixture::new(12);
        let intents = stage(&store, &fixture);
        // The enclosing join carries authority work, but this local owner must
        // neither acquire those roots nor spend their reserved ownership work.
        let prior = CatalogCodingTraversalBudget {
            bytes: 8192,
            page_occurrences: 17,
            records: 23,
        };
        let manifest = CatalogPackingCodingDirectoryValidation {
            format_version: 1,
            packing: fixture.packing.manifest,
            coding: fixture.root,
            policy: CatalogCodingCoveragePolicy::Current,
            prior_work: prior,
        };
        let budget = manifest.represented_work().unwrap();
        let build = || {
            fixture
                .packing
                .build(4 * 1024 * 1024)
                .unwrap()
                .validate_directory_with_prior(
                    fixture.root,
                    manifest.policy,
                    budget,
                    prior,
                    |page| fixture.fetch(page),
                    |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
                )
                .unwrap()
        };
        let proof = build();
        let retention = job(1, &proof);
        let owned_work = budget.remaining_after(prior).unwrap();
        assert_eq!(
            retention.work().unwrap(),
            (owned_work.bytes, owned_work.page_occurrences)
        );
        let transaction =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        journal::begin(&transaction, retention).unwrap();
        for dependency in retention.initial() {
            journal::retain(&transaction, retention, dependency).unwrap();
        }
        journal::retain(
            &transaction,
            retention,
            Dependency {
                scope: retention.scope(),
                section: CatalogSection::Coding,
                root: fixture.forests[0].parts[0].page,
            },
        )
        .unwrap();
        transaction.commit().unwrap();
        drop(proof);
        drop(store);
        let store = ControlStore::open(&path, &keys()).unwrap();
        let proof = build();
        let before = record(&store, retention.id);
        assert_eq!(before.state, CatalogPackingCodingRetentionState::Building);
        assert_eq!(before.roots, 4);
        let mut changed_budget = proof.budget();
        changed_budget.bytes += 1;
        let changed = fixture
            .packing
            .build(4 * 1024 * 1024)
            .unwrap()
            .validate_directory_with_prior(
                fixture.root,
                CatalogCodingCoveragePolicy::Current,
                changed_budget,
                prior,
                |page| fixture.fetch(page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap();
        assert!(
            store
                .retain_catalog_packing_coding(retention.id, &changed)
                .is_err()
        );
        assert_eq!(record(&store, retention.id), before);
        assert_eq!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .unwrap(),
            retention
        );
        assert_eq!(record(&store, retention.id).roots, 7);
        release_originals(&store, &intents);
        replay(&store, &fixture, &proof);
    }

    #[test]
    fn combined_owner_rejects_local_packing_and_coding_tail_corruption() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = Fixture::new(384);
        let intents = stage(&store, &fixture);
        let proof = fixture.build(8 * 1024 * 1024).unwrap();
        let tails = fixture
            .packing
            .roles
            .iter()
            .map(|role| role.iter().rfind(|(page, _)| page.height == 0).unwrap().0)
            .chain([fixture.forests.last().unwrap().parts.last().unwrap().page])
            .collect::<Vec<_>>();
        for root in [
            fixture.packing.manifest.sources.records.page,
            fixture.packing.manifest.descriptors.records.page,
        ] {
            assert!(
                root.height > 0,
                "packing faults must occur beyond the pinned top page"
            );
        }
        for (index, tail) in tails.into_iter().enumerate() {
            let id = Uuid::from_u128(index as u128 + 1);
            let section = if index == 2 {
                CatalogSection::Coding
            } else {
                CatalogSection::Packing
            };
            let bytes = store
                .catalog_page(fixture.packing.manifest.scope, section, tail)
                .unwrap();
            store.connection.execute("UPDATE protocol_records SET bytes=zeroblob(length(bytes)) WHERE kind=?1 AND record_id=?2", params![PAGE, tail.hash]).unwrap();
            assert!(store.retain_catalog_packing_coding(id, &proof).is_err());
            let failed = record(&store, id);
            assert_eq!(failed.state, CatalogPackingCodingRetentionState::Cancelled);
            assert!(failed.roots >= 3);
            if index == 2 {
                assert!(failed.roots > 100);
            }
            assert!(store.retain_catalog_packing_coding(id, &proof).is_err());
            // GC also authenticates bytes. Repair the injected corruption
            // before checking safe reclamation, rather than bypassing GC.
            store
                .connection
                .execute(
                    "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2",
                    params![PAGE, tail.hash, bytes],
                )
                .unwrap();
            while store.release_catalog_packing_coding_root(id).unwrap() {}
        }
        drop(store);
        let store = ControlStore::open(&path, &keys()).unwrap();
        release_originals(&store, &intents);
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn combined_owner_ignored_writes_preserve_atomic_acquisition_publication_and_cleanup() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = Fixture::new(6);
        let intents = stage(&store, &fixture);
        let proof = fixture.build(4 * 1024 * 1024).unwrap();
        let retention = job(1, &proof);
        let kind = journal::dependencies::<CatalogPackingCodingRetention>(retention.id);
        let pin = journal::pin_id::<CatalogPackingCodingRetention>(retention.id);
        let dir_pin = pins(fixture.root.records.page.hash);
        for trigger in [
            "CREATE TEMP TRIGGER ignore_acquisition BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-packing-coding-retention-v1' BEGIN SELECT RAISE(IGNORE); END".to_owned(),
            format!("CREATE TEMP TRIGGER ignore_acquisition BEFORE INSERT ON protocol_records WHEN NEW.kind='{dir_pin}' AND NEW.record_id=X'{}' BEGIN SELECT RAISE(IGNORE); END", hex::encode(pin)),
            format!("CREATE TEMP TRIGGER ignore_acquisition BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' AND NEW.record_id=X'{}' BEGIN SELECT RAISE(IGNORE); END", hex::encode(fixture.root.records.page.hash)),
        ] {
            store.connection.execute_batch(&trigger).unwrap();
            assert!(store.retain_catalog_packing_coding(retention.id, &proof).is_err());
            assert!(store.catalog_packing_coding_retention(retention.id).unwrap().is_none());
            assert!(candidate_hash(&store.connection, &kind, &[]).unwrap().is_none());
            for dependency in retention.initial() {
                assert!(bounded_record(&store.connection, &pins(dependency.root.hash), &pin, 0).unwrap().is_none());
            }
            store.connection.execute_batch("DROP TRIGGER ignore_acquisition").unwrap();
        }
        let dependencies = roots(&fixture);
        let published = Record {
            format_version: 1,
            retention,
            state: CatalogPackingCodingRetentionState::Published,
            roots: dependencies.len() as u64,
            bytes: dependencies
                .iter()
                .map(|dependency| dependency.root.byte_len)
                .sum(),
            pages: dependencies
                .iter()
                .map(|dependency| dependency.root.page_occurrences)
                .sum(),
        };
        store.connection.execute_batch(&format!("CREATE TEMP TRIGGER ignore_completion BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-packing-coding-retention-v1' AND NEW.bytes=X'{}' BEGIN SELECT RAISE(IGNORE); END", hex::encode(canonical_bytes(&published).unwrap()))).unwrap();
        assert!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .is_err()
        );
        assert_eq!(
            record(&store, retention.id).state,
            CatalogPackingCodingRetentionState::Cancelled
        );
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_completion")
            .unwrap();
        let before = record(&store, retention.id);
        assert_eq!(before.roots, published.roots);
        for trigger in [
            format!("CREATE TEMP TRIGGER ignore_release BEFORE DELETE ON protocol_records WHEN OLD.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"),
            "CREATE TEMP TRIGGER ignore_release BEFORE UPDATE ON protocol_records WHEN OLD.kind='catalog-packing-coding-retention-v1' BEGIN SELECT RAISE(IGNORE); END".to_owned(),
        ] {
            store.connection.execute_batch(&trigger).unwrap();
            assert!(store.release_catalog_packing_coding_root(retention.id).is_err());
            assert_eq!(record(&store, retention.id), before);
            for dependency in &dependencies {
                assert_eq!(bounded_record(&store.connection, &pins(dependency.root.hash), &pin, 0).unwrap().as_deref(), Some(&[] as &[u8]));
            }
            store.connection.execute_batch("DROP TRIGGER ignore_release").unwrap();
        }
        while store
            .release_catalog_packing_coding_root(retention.id)
            .unwrap()
        {}
        release_originals(&store, &intents);
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn combined_owner_requires_completion_rejects_orphans_and_separates_all_pin_namespaces() {
        let directory = tempfile::tempdir().unwrap();
        let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
        let fixture = Fixture::new(3);
        let intents = stage(&store, &fixture);
        let proof = fixture.build(4 * 1024 * 1024).unwrap();
        let retention = job(1, &proof);
        let marker = canonical_bytes(&proof.manifest()).unwrap();
        let complete = "packing-coding-directory-complete";
        proof
            .packing()
            .store
            .delete_record_if_value(complete, b"root", &marker)
            .unwrap();
        assert!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .is_err()
        );
        assert!(
            store
                .catalog_packing_coding_retention(retention.id)
                .unwrap()
                .is_none()
        );
        proof
            .packing()
            .store
            .put_record_if_absent(complete, b"root", &marker)
            .unwrap();
        let root = fixture.root.records.page;
        let bytes = store
            .catalog_page(retention.scope(), CatalogSection::Coding, root)
            .unwrap();
        store.connection.execute("UPDATE protocol_records SET bytes=zeroblob(length(bytes)) WHERE kind=?1 AND record_id=?2", params![PAGE, root.hash]).unwrap();
        assert!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .is_err()
        );
        assert!(
            store
                .catalog_packing_coding_retention(retention.id)
                .unwrap()
                .is_none()
        );
        for dependency in retention.initial() {
            assert!(
                bounded_record(
                    &store.connection,
                    &pins(dependency.root.hash),
                    &journal::pin_id::<CatalogPackingCodingRetention>(retention.id),
                    0
                )
                .unwrap()
                .is_none()
            );
        }
        store
            .connection
            .execute(
                "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2",
                params![PAGE, root.hash, bytes],
            )
            .unwrap();
        assert!(
            store
                .retain_catalog_packing_coding(Uuid::nil(), &proof)
                .is_err()
        );
        let kind = journal::dependencies::<CatalogPackingCodingRetention>(retention.id);
        let dependency = Dependency {
            scope: retention.scope(),
            section: CatalogSection::Coding,
            root: fixture.forests[0].parts[0].page,
        };
        insert_exact(&store.connection, &kind, &dependency.root.hash, &[]).unwrap();
        assert!(
            store
                .retain_catalog_packing_coding(retention.id, &proof)
                .is_err()
        );
        assert!(
            store
                .catalog_packing_coding_retention(retention.id)
                .unwrap()
                .is_none()
        );
        store
            .connection
            .execute("DELETE FROM protocol_records WHERE kind=?1", [&kind])
            .unwrap();
        {
            let transaction =
                Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate)
                    .unwrap();
            journal::begin(&transaction, retention).unwrap();
            for wrong in [
                Dependency {
                    scope: CatalogScope::Guild { guild_id: [8; 32] },
                    ..dependency
                },
                Dependency {
                    section: CatalogSection::Checkpoint,
                    ..dependency
                },
            ] {
                assert!(journal::retain(&transaction, retention, wrong).is_err());
            }
            // Dropping this uncommitted attempt leaves no usable journal.
        }
        store
            .retain_catalog_packing_coding(retention.id, &proof)
            .unwrap();
        let mut foreign_pins = Vec::new();
        let pin = journal::pin_id::<CatalogPackingCodingRetention>(retention.id);
        assert_eq!(pin[0], 3);
        assert_ne!(pin.as_slice(), retention.id.as_bytes());
        for prefix in [1, 2] {
            let mut foreign = pin;
            foreign[0] = prefix;
            insert_exact(
                &store.connection,
                &pins(dependency.root.hash),
                &foreign,
                &[],
            )
            .unwrap();
            foreign_pins.push(foreign);
        }
        store
            .cancel_catalog_packing_coding_retention(retention.id)
            .unwrap();
        while store
            .release_catalog_packing_coding_root(retention.id)
            .unwrap()
        {}
        release_originals(&store, &intents);
        assert!(
            store
                .catalog_page(dependency.scope, dependency.section, dependency.root)
                .is_ok()
        );
        for pin in foreign_pins {
            assert_eq!(
                bounded_record(&store.connection, &pins(dependency.root.hash), &pin, 0)
                    .unwrap()
                    .as_deref(),
                Some(&[] as &[u8])
            );
            store
                .connection
                .execute(
                    "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2",
                    params![pins(dependency.root.hash), pin],
                )
                .unwrap();
        }
        queue_unreferenced(&store.connection, dependency.root.hash).unwrap();
        collect(&store);
        assert_roots(&store, &fixture, false);
    }

    #[test]
    fn empty_combined_owner_deduplicates_physical_packing_roots_but_charges_logical_occurrences() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let store = ControlStore::open(&path, &keys()).unwrap();
        let fixture = Fixture::new(0);
        let intents = stage(&store, &fixture);
        let proof = fixture.build(4 * 1024 * 1024).unwrap();
        assert_eq!(
            fixture.packing.manifest.sources.records.page,
            fixture.packing.manifest.descriptors.records.page
        );
        assert_eq!(
            proof
                .manifest()
                .represented_work()
                .unwrap()
                .page_occurrences,
            3
        );
        let retention = store
            .retain_catalog_packing_coding(Uuid::from_u128(1), &proof)
            .unwrap();
        assert_eq!(record(&store, retention.id).roots, 2);
        assert_eq!(record(&store, retention.id).pages, 2);
        release_originals(&store, &intents);
        drop(store);
        let store = ControlStore::open(&path, &keys()).unwrap();
        replay(&store, &fixture, &proof);
        assert_roots(&store, &fixture, true);
        store
            .cancel_catalog_packing_coding_retention(retention.id)
            .unwrap();
        assert!(
            store
                .release_catalog_packing_coding_root(retention.id)
                .unwrap()
        );
        assert!(
            store
                .release_catalog_packing_coding_root(retention.id)
                .unwrap()
        );
        assert!(
            !store
                .release_catalog_packing_coding_root(retention.id)
                .unwrap()
        );
        collect(&store);
        assert_roots(&store, &fixture, false);
    }
}
