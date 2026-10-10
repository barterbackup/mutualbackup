use super::*;
use crate::database::catalog::packing_directories_coverage::tests::Fixture;
use mb_core::{CatalogPageContents, KeyMaterial, Seed};
use std::collections::HashMap;

type Record = journal::JournalRecord<CatalogPackingCodingDirectoriesRetention>;
fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([193; 32]))
}
fn job(
    id: u128,
    proof: &CatalogPackingCodingDirectoriesIndex,
) -> CatalogPackingCodingDirectoriesRetention {
    CatalogPackingCodingDirectoriesRetention {
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
            root: fixture.packing.manifest.directory.records.page,
        },
        Dependency {
            scope,
            section: CatalogSection::Coding,
            root: fixture.coding.root.records.page,
        },
    ];
    for root in fixture
        .packing
        .sources
        .iter()
        .map(|part| part.root.records.page)
        .chain(
            fixture
                .packing
                .sectors
                .iter()
                .map(|part| part.root.records.page),
        )
    {
        roots.push(Dependency {
            scope,
            section: CatalogSection::Packing,
            root,
        });
    }
    for forest in &fixture.coding.forests {
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
    roots(fixture)
        .into_iter()
        .enumerate()
        .map(|(index, dependency)| {
            let intent = CatalogIntent {
                id: Uuid::from_u128(index as u128 + 100),
                scope: dependency.scope,
                section: dependency.section,
            };
            store.begin_catalog(intent).unwrap();
            stage_tree(
                store,
                intent,
                dependency.root,
                if dependency.section == CatalogSection::Packing {
                    &fixture.packing.pages
                } else {
                    &fixture.coding.pages
                },
            );
            intent
        })
        .collect()
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
fn replay(store: &ControlStore, fixture: &Fixture, proof: &CatalogPackingCodingDirectoriesIndex) {
    let scope = fixture.packing.manifest.scope;
    let mut reader = CatalogPackingDirectoryReader::new(
        scope,
        fixture.packing.manifest.directory,
        proof.manifest().packing_budget(proof.budget()).unwrap(),
    )
    .unwrap();
    let mut fetch = |page| store.catalog_page(scope, CatalogSection::Packing, page);
    while reader.next_source(&mut fetch).unwrap().is_some() {}
    while reader
        .next_sector(&mut fetch, &mut |key| proof.packing().source_id(key))
        .unwrap()
        .is_some()
    {}
    assert!(reader.is_complete());
    for entry in &fixture.coding.entries {
        assert_eq!(
            proof
                .read_group(entry.retained.group.id, |page| store.catalog_page(
                    scope,
                    CatalogSection::Coding,
                    page
                ))
                .unwrap()
                .as_ref(),
            Some(entry)
        );
    }
}

#[test]
fn packing_directories_owner_preserves_all_nested_roots_across_reopen_and_shared_retirement() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.db");
    let store = ControlStore::open(&path, &keys()).unwrap();
    let fixture = Fixture::new(12);
    let intents = stage(&store, &fixture);
    let proof = fixture.build();
    let owner = store
        .retain_catalog_packing_directories(Uuid::from_u128(1), &proof)
        .unwrap();
    let successor = store
        .retain_catalog_packing_directories(Uuid::from_u128(2), &proof)
        .unwrap();
    let count = roots(&fixture).len() as u64;
    assert!(count as usize > CATALOG_BUNDLE_ROOTS);
    assert_eq!(record(&store, owner.id).roots, count);
    assert_eq!(
        journal::pin_id::<CatalogPackingCodingDirectoriesRetention>(owner.id)[0],
        5
    );
    assert_eq!(
        store
            .retain_catalog_packing_directories(owner.id, &proof)
            .unwrap(),
        owner
    );
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
    journal::cancel_building(&transaction, owner).unwrap();
    transaction.commit().unwrap();
    assert_eq!(
        record(&store, owner.id).state,
        CatalogPackingCodingDirectoriesRetentionState::Published
    );
    release_originals(&store, &intents);
    drop(store);
    let store = ControlStore::open(&path, &keys()).unwrap();
    assert_eq!(
        store
            .catalog_packing_directories_retention(owner.id)
            .unwrap(),
        Some((
            owner,
            CatalogPackingCodingDirectoriesRetentionState::Published
        ))
    );
    replay(&store, &fixture, &proof);
    assert!(
        store
            .release_catalog_packing_directories_root(owner.id)
            .is_err()
    );
    store
        .cancel_catalog_packing_directories_retention(owner.id)
        .unwrap();
    assert!(
        store
            .retain_catalog_packing_directories(owner.id, &proof)
            .is_err()
    );
    for remaining in (0..count).rev() {
        assert!(
            store
                .release_catalog_packing_directories_root(owner.id)
                .unwrap()
        );
        assert_eq!(record(&store, owner.id).roots, remaining);
    }
    assert!(
        !store
            .release_catalog_packing_directories_root(owner.id)
            .unwrap()
    );
    collect(&store);
    assert_roots(&store, &fixture, true);
    replay(&store, &fixture, &proof);
    store
        .cancel_catalog_packing_directories_retention(successor.id)
        .unwrap();
    while store
        .release_catalog_packing_directories_root(successor.id)
        .unwrap()
    {}
    collect(&store);
    assert_roots(&store, &fixture, false);
}

#[test]
fn packing_directories_owner_resumes_interrupted_parts_and_fences_changed_jobs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("control.db");
    let store = ControlStore::open(&path, &keys()).unwrap();
    let fixture = Fixture::new(9);
    let intents = stage(&store, &fixture);
    let proof = fixture.build();
    let owner = job(1, &proof);
    let transaction =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
    journal::begin(&transaction, owner).unwrap();
    for dependency in owner.initial() {
        journal::retain(&transaction, owner, dependency).unwrap();
    }
    journal::retain(
        &transaction,
        owner,
        Dependency {
            scope: owner.scope(),
            section: CatalogSection::Packing,
            root: fixture.packing.sources[0].root.records.page,
        },
    )
    .unwrap();
    transaction.commit().unwrap();
    assert_eq!(record(&store, owner.id).roots, 3);
    drop(store);
    let store = ControlStore::open(&path, &keys()).unwrap();
    let prior = CatalogCodingTraversalBudget {
        bytes: 1,
        ..Default::default()
    };
    let manifest = fixture.manifest(prior);
    let changed = fixture
        .packing()
        .validate_directory_with_prior(
            manifest.coding,
            manifest.policy,
            manifest.represented_work().unwrap(),
            prior,
            |page| fixture.coding.fetch(page),
            |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
        )
        .unwrap();
    assert!(
        store
            .retain_catalog_packing_directories(owner.id, &changed)
            .is_err()
    );
    assert_eq!(record(&store, owner.id).roots, 3);
    assert_eq!(
        store
            .retain_catalog_packing_directories(owner.id, &proof)
            .unwrap(),
        owner
    );
    assert_eq!(record(&store, owner.id).roots, roots(&fixture).len() as u64);
    release_originals(&store, &intents);
    replay(&store, &fixture, &proof);
    store
        .cancel_catalog_packing_directories_retention(owner.id)
        .unwrap();
    drop(store);
    let store = ControlStore::open(&path, &keys()).unwrap();
    while store
        .release_catalog_packing_directories_root(owner.id)
        .unwrap()
    {}
    collect(&store);
    assert_roots(&store, &fixture, false);
}

#[test]
fn packing_directories_owner_rejects_source_descriptor_and_coding_tail_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
    let fixture = Fixture::new(12);
    let intents = stage(&store, &fixture);
    let proof = fixture.build();
    let tails = [
        (
            CatalogSection::Packing,
            fixture.packing.sources.last().unwrap().root.records.page,
        ),
        (
            CatalogSection::Packing,
            fixture.packing.sectors.last().unwrap().root.records.page,
        ),
        (
            CatalogSection::Coding,
            fixture
                .coding
                .forests
                .last()
                .unwrap()
                .parts
                .last()
                .unwrap()
                .page,
        ),
    ];
    for (index, (section, tail)) in tails.into_iter().enumerate() {
        let bytes = store
            .catalog_page(fixture.packing.manifest.scope, section, tail)
            .unwrap();
        store.connection.execute("UPDATE protocol_records SET bytes=zeroblob(length(bytes)) WHERE kind=?1 AND record_id=?2", params![PAGE, tail.hash]).unwrap();
        let id = Uuid::from_u128(index as u128 + 1);
        assert!(
            store
                .retain_catalog_packing_directories(id, &proof)
                .is_err()
        );
        let failed = record(&store, id);
        assert_eq!(
            failed.state,
            CatalogPackingCodingDirectoriesRetentionState::Cancelled
        );
        assert!(failed.roots > 2);
        assert!(
            store
                .retain_catalog_packing_directories(id, &proof)
                .is_err()
        );
        store
            .connection
            .execute(
                "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2",
                params![PAGE, tail.hash, bytes],
            )
            .unwrap();
        while store.release_catalog_packing_directories_root(id).unwrap() {}
        assert_eq!(record(&store, id).roots, 0);
    }
    release_originals(&store, &intents);
    assert_roots(&store, &fixture, false);
}

#[test]
fn packing_directories_owner_sql_faults_roll_back_pins_counts_publication_and_release() {
    let directory = tempfile::tempdir().unwrap();
    let store = ControlStore::open(directory.path().join("control.db"), &keys()).unwrap();
    let fixture = Fixture::new(9);
    let intents = stage(&store, &fixture);
    let proof = fixture.build();
    let dependencies = roots(&fixture);
    for mode in 0..3 {
        let owner = job(mode as u128 + 1, &proof);
        let final_record = Record {
            format_version: 1,
            retention: owner,
            state: CatalogPackingCodingDirectoriesRetentionState::Published,
            roots: dependencies.len() as u64,
            bytes: dependencies.iter().map(|d| d.root.byte_len).sum(),
            pages: dependencies.iter().map(|d| d.root.page_occurrences).sum(),
        };
        let trigger = match mode {
            0 => format!(
                "CREATE TEMP TRIGGER skip_change BEFORE INSERT ON protocol_records WHEN NEW.kind='{}' BEGIN SELECT RAISE(IGNORE); END",
                journal::dependencies::<CatalogPackingCodingDirectoriesRetention>(owner.id)
            ),
            1 => format!(
                "CREATE TEMP TRIGGER skip_change BEFORE INSERT ON protocol_records WHEN NEW.kind='{}' BEGIN SELECT RAISE(IGNORE); END",
                pins(fixture.packing.sources[0].root.records.page.hash)
            ),
            _ => format!(
                "CREATE TEMP TRIGGER skip_change BEFORE UPDATE ON protocol_records WHEN NEW.kind='{}' AND NEW.bytes=X'{}' BEGIN SELECT RAISE(IGNORE); END",
                CatalogPackingCodingDirectoriesRetention::JOURNAL,
                hex::encode(canonical_bytes(&final_record).unwrap())
            ),
        };
        store.connection.execute_batch(&trigger).unwrap();
        assert!(
            store
                .retain_catalog_packing_directories(owner.id, &proof)
                .is_err()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER skip_change")
            .unwrap();
        if mode == 0 {
            assert!(
                store
                    .catalog_packing_directories_retention(owner.id)
                    .unwrap()
                    .is_none()
            );
            assert!(
                bounded_record(
                    &store.connection,
                    &pins(owner.initial()[0].root.hash),
                    &journal::pin_id::<CatalogPackingCodingDirectoriesRetention>(owner.id),
                    0
                )
                .unwrap()
                .is_none()
            );
        } else {
            let failed = record(&store, owner.id);
            assert_eq!(
                failed.state,
                CatalogPackingCodingDirectoriesRetentionState::Cancelled
            );
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER skip_release BEFORE DELETE ON protocol_records WHEN OLD.kind='{}' BEGIN SELECT RAISE(IGNORE); END", journal::dependencies::<CatalogPackingCodingDirectoriesRetention>(owner.id))).unwrap();
            assert!(
                store
                    .release_catalog_packing_directories_root(owner.id)
                    .is_err()
            );
            assert_eq!(record(&store, owner.id), failed);
            store
                .connection
                .execute_batch("DROP TRIGGER skip_release")
                .unwrap();
            while store
                .release_catalog_packing_directories_root(owner.id)
                .unwrap()
            {}
            assert_eq!(record(&store, owner.id).roots, 0);
        }
    }
    let owner = store
        .retain_catalog_packing_directories(Uuid::from_u128(4), &proof)
        .unwrap();
    release_originals(&store, &intents);
    replay(&store, &fixture, &proof);
    store
        .cancel_catalog_packing_directories_retention(owner.id)
        .unwrap();
    while store
        .release_catalog_packing_directories_root(owner.id)
        .unwrap()
    {}
    collect(&store);
    assert_roots(&store, &fixture, false);
}
