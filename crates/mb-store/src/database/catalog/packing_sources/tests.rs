use super::super::paged_revision::tests::{data_fixture, fixture, publish};
use super::*;

fn retention() -> CatalogPackingSourceRetention {
    CatalogPackingSourceRetention {
        id: Uuid::new_v4(),
        base: CatalogPackingAuthorityBase {
            guild_id: [73; 32],
            checkpoint_hash: [9; 32],
            generation: 1,
            membership_epoch: Some(1),
        },
        budget: Work {
            bytes: 1024 * 1024,
            page_occurrences: 100,
            records: 100,
        },
    }
}

fn begin(
    store: &ControlStore,
    retention: CatalogPackingSourceRetention,
) -> Result<(), CatalogStoreError> {
    store.begin_catalog_packing_source_retention(retention, |_| Ok(()))
}

fn retain(
    store: &ControlStore,
    retention: CatalogPackingSourceRetention,
    bundle: &CatalogBundle,
) -> Result<PagedCatalogSnapshot, CatalogStoreError> {
    store.retain_catalog_packing_source_checked(
        retention,
        &paged_revision::revision(bundle)?,
        (|_| Ok(()), |_, _| Ok(())),
    )
}

#[test]
fn packing_source_loans_reopen_keep_shared_bootstrap_and_fence_capture_cancellation() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (first, bytes) = fixture(&store, 1, None);
    publish(&store, &first, &bytes).unwrap();
    let (next, next_bytes) = fixture(
        &store,
        2,
        Some(
            paged_revision::revision(&first)
                .unwrap()
                .value
                .hash()
                .unwrap(),
        ),
    );
    publish(&store, &next, &next_bytes).unwrap();
    let a = retention();
    let b = retention();
    for job in [a, b] {
        begin(&store, job).unwrap();
        retain(&store, job, &first).unwrap();
        retain(&store, job, &next).unwrap();
        let before = store.catalog_packing_source_retention(job.id).unwrap();
        retain(&store, job, &first).unwrap();
        assert_eq!(
            store.catalog_packing_source_retention(job.id).unwrap(),
            before
        );
    }
    drop(store);
    let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    for job in [a, b] {
        assert_eq!(
            store
                .catalog_packing_source(job, first.id)
                .unwrap()
                .unwrap()
                .bootstrap,
            Some(bytes.clone())
        );
        assert!(store.release_catalog_packing_source(job).is_err());
    }
    assert!(store.cancel_paged_revision_catalog(first.id).is_err());
    assert!(store.cancel_catalog_bundle(first.id).is_err());
    let fenced: Result<(), CatalogStoreError> = store
        .with_unretained_paged_revision_record_transaction(first.id, || {
            panic!("capture cancellation must be excluded before fencing its journal")
        });
    assert!(fenced.is_err());
    store.cancel_catalog_packing_source_retention(a).unwrap();
    assert!(begin(&store, a).is_err());
    assert!(retain(&store, a, &first).is_err());
    assert!(store.release_catalog_packing_source(a).unwrap());
    assert!(store.release_catalog_packing_source(a).unwrap());
    assert!(!store.release_catalog_packing_source(a).unwrap());
    assert!(store.cancel_paged_revision_catalog(first.id).is_err());
    store.cancel_catalog_packing_source_retention(b).unwrap();
    while store.release_catalog_packing_source(b).unwrap() {}
    store.cancel_paged_revision_catalog(first.id).unwrap();
    assert_eq!(
        store
            .paged_revision_catalog(next.id)
            .unwrap()
            .unwrap()
            .bootstrap,
        Some(next_bytes)
    );
    assert!(begin(&store, a).is_err());
}

#[test]
fn packing_source_loans_admit_all_dimensions_before_authentication_and_preserve_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    publish(&store, &bundle, &bytes).unwrap();
    let snapshot = store.paged_revision_catalog(bundle.id).unwrap().unwrap();
    let minimum = journal_work()
        .checked_add(dependency(&snapshot).unwrap().work)
        .unwrap();
    let signed = paged_revision::revision(&bundle).unwrap();
    for dimension in 0..3 {
        let mut job = retention();
        job.budget = minimum;
        match dimension {
            0 => job.budget.bytes -= 1,
            1 => job.budget.page_occurrences -= 1,
            _ => job.budget.records -= 1,
        }
        begin(&store, job).unwrap();
        let result: Result<_, CatalogStoreError> = store.retain_catalog_packing_source_checked(
            job,
            &signed,
            (
                |_| Ok(()),
                |_, _| panic!("admit before private/payload reads"),
            ),
        );
        assert!(result.is_err());
        assert_eq!(store.catalog_packing_source(job, bundle.id).unwrap(), None);
    }
    let mut job = retention();
    job.budget = minimum;
    begin(&store, job).unwrap();
    retain(&store, job, &bundle).unwrap();
    let mut changed = job;
    changed.base.checkpoint_hash = [8; 32];
    assert!(begin(&store, changed).is_err());
    changed = job;
    changed.budget.records += 1;
    assert!(begin(&store, changed).is_err());
    let mut wrong = signed.clone();
    wrong.value.sequence += 1;
    let result: Result<_, CatalogStoreError> = store.retain_catalog_packing_source_checked(
        job,
        &wrong,
        (
            |_| Ok(()),
            |_, _| panic!("reject substituted signed identity"),
        ),
    );
    assert!(result.is_err());
    assert_eq!(
        store.catalog_packing_source(job, bundle.id).unwrap(),
        Some(snapshot)
    );
}

#[test]
fn packing_source_loans_roll_back_authentication_and_late_base_guard_failures() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    publish(&store, &bundle, &bytes).unwrap();
    let job = retention();
    begin(&store, job).unwrap();
    let before = store.catalog_packing_source_retention(job.id).unwrap();
    let signed = paged_revision::revision(&bundle).unwrap();
    let rejected: Result<_, CatalogStoreError> = store.retain_catalog_packing_source_checked(
        job,
        &signed,
        (|_| Ok(()), |_, _| Err(DatabaseError::Integrity.into())),
    );
    assert!(rejected.is_err());
    let mut calls = 0;
    let rejected: Result<_, CatalogStoreError> = store.retain_catalog_packing_source_checked(
        job,
        &signed,
        (
            |view| {
                calls += 1;
                assert!(
                    view.record(JOURNAL, job.id.as_bytes(), ROW_BYTES)?
                        .is_some()
                );
                if calls == 2 {
                    Err(DatabaseError::Conflict.into())
                } else {
                    Ok(())
                }
            },
            |view, catalog| {
                for member in &catalog.bundle.roots {
                    view.catalog_page(catalog.bundle.scope, member.intent.section, member.root)?;
                }
                Ok(())
            },
        ),
    );
    assert!(rejected.is_err());
    assert_eq!(calls, 2);
    assert_eq!(
        store.catalog_packing_source_retention(job.id).unwrap(),
        before
    );
    assert_eq!(store.catalog_packing_source(job, bundle.id).unwrap(), None);
    store.cancel_paged_revision_catalog(bundle.id).unwrap();
}

#[test]
fn packing_source_loans_roll_back_every_acquire_and_release_sql_boundary() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    publish(&store, &bundle, &bytes).unwrap();
    for fault in ["ABORT", "IGNORE"] {
        for boundary in 0..8 {
            let job = retention();
            begin(&store, job).unwrap();
            if boundary >= 4 {
                retain(&store, job, &bundle).unwrap();
                store.cancel_catalog_packing_source_retention(job).unwrap();
            }
            let before = store.catalog_packing_source_retention(job.id).unwrap();
            let (operation, kind) = match boundary {
                0 => ("INSERT", revisions(job.id)),
                1 => ("INSERT", owners(bundle.id)),
                2 => ("UPDATE", JOURNAL.into()),
                3 => ("UPDATE", OWNER_COUNT.into()),
                4 => ("DELETE", revisions(job.id)),
                5 => ("DELETE", owners(bundle.id)),
                6 => ("UPDATE", JOURNAL.into()),
                _ => ("UPDATE", OWNER_COUNT.into()),
            };
            let expression = if fault == "ABORT" {
                "RAISE(ABORT, 'injected')"
            } else {
                "RAISE(IGNORE)"
            };
            let row = if operation == "DELETE" { "OLD" } else { "NEW" };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER loan_fault BEFORE {operation} ON protocol_records WHEN {row}.kind = '{kind}' BEGIN SELECT {expression}; END;")).unwrap();
            if boundary < 4 {
                assert!(retain(&store, job, &bundle).is_err());
            } else {
                assert!(store.release_catalog_packing_source(job).is_err());
            }
            assert_eq!(
                store.catalog_packing_source_retention(job.id).unwrap(),
                before
            );
            assert_eq!(
                store
                    .catalog_packing_source(job, bundle.id)
                    .unwrap()
                    .is_some(),
                boundary >= 4
            );
            store
                .connection
                .execute_batch("DROP TRIGGER loan_fault")
                .unwrap();
            if boundary < 4 {
                retain(&store, job, &bundle).unwrap();
                store.cancel_catalog_packing_source_retention(job).unwrap();
            }
            assert!(store.release_catalog_packing_source(job).unwrap());
            assert!(!store.release_catalog_packing_source(job).unwrap());
        }
    }
    store.cancel_paged_revision_catalog(bundle.id).unwrap();
}

#[test]
fn packing_source_loans_owner_count_fences_missing_reverse_pins_and_ignored_initial_charge() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
    for fault in ["ABORT", "IGNORE"] {
        let (bundle, bytes) = fixture(&store, 1, None);
        publish(&store, &bundle, &bytes).unwrap();
        let job = retention();
        begin(&store, job).unwrap();
        let expression = if fault == "ABORT" {
            "RAISE(ABORT, 'injected')"
        } else {
            "RAISE(IGNORE)"
        };
        store.connection.execute_batch(&format!("CREATE TEMP TRIGGER loan_fault BEFORE INSERT ON protocol_records WHEN NEW.kind = '{OWNER_COUNT}' BEGIN SELECT {expression}; END;")).unwrap();
        assert!(retain(&store, job, &bundle).is_err());
        assert_eq!(store.catalog_packing_source(job, bundle.id).unwrap(), None);
        assert_eq!(
            store.get_record(OWNER_COUNT, bundle.id.as_bytes()).unwrap(),
            None
        );
        store
            .connection
            .execute_batch("DROP TRIGGER loan_fault")
            .unwrap();
        retain(&store, job, &bundle).unwrap();
        let kind = owners(bundle.id);
        let reverse = store.get_record(&kind, job.id.as_bytes()).unwrap().unwrap();
        store.delete_record(&kind, job.id.as_bytes()).unwrap();
        assert!(store.cancel_paged_revision_catalog(bundle.id).is_err());
        assert!(
            store
                .with_unretained_paged_revision_record_transaction(bundle.id, || Ok::<
                    _,
                    CatalogStoreError,
                >(
                    ()
                ))
                .is_err()
        );
        assert!(store.catalog_packing_source(job, bundle.id).is_err());
        store
            .put_record(&kind, job.id.as_bytes(), &reverse)
            .unwrap();
        let count = store
            .get_record(OWNER_COUNT, bundle.id.as_bytes())
            .unwrap()
            .unwrap();
        store
            .delete_record(OWNER_COUNT, bundle.id.as_bytes())
            .unwrap();
        assert!(store.cancel_paged_revision_catalog(bundle.id).is_err());
        store
            .put_record(OWNER_COUNT, bundle.id.as_bytes(), &count)
            .unwrap();
        store.cancel_catalog_packing_source_retention(job).unwrap();
        assert!(store.release_catalog_packing_source(job).unwrap());
        store.cancel_paged_revision_catalog(bundle.id).unwrap();
    }
}

#[test]
fn packing_source_loans_reject_impossible_journal_work_before_authentication() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    publish(&store, &bundle, &bytes).unwrap();
    let mut job = retention();
    job.budget = Work {
        bytes: u64::MAX,
        page_occurrences: u64::MAX,
        records: u64::MAX,
    };
    begin(&store, job).unwrap();
    retain(&store, job, &bundle).unwrap();
    let original = store
        .get_record(JOURNAL, job.id.as_bytes())
        .unwrap()
        .unwrap();
    let journal: Journal = decode(&original).unwrap();
    let fixed = (3 * ROW_BYTES + mb_core::V1_SECTOR_SIZE) as u64;
    let signed = paged_revision::revision(&bundle).unwrap();
    for dimension in 0..4 {
        let mut damaged = journal;
        match dimension {
            0 => damaged.work.bytes = journal_work().bytes + fixed - 1,
            1 => damaged.work.page_occurrences = 2,
            2 => {
                damaged.work.bytes =
                    journal_work().bytes + fixed + mb_core::CATALOG_MAX_STREAM_BYTES + 1
            }
            _ => damaged.work.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES + 1,
        }
        store
            .put_record(JOURNAL, job.id.as_bytes(), &encode(&damaged).unwrap())
            .unwrap();
        let result: Result<_, CatalogStoreError> = store.retain_catalog_packing_source_checked(
            job,
            &signed,
            (
                |_| Ok(()),
                |_, _| panic!("reject damaged admission before reads"),
            ),
        );
        assert!(result.is_err());
        assert!(store.catalog_packing_source_retention(job.id).is_err());
        assert!(store.cancel_paged_revision_catalog(bundle.id).is_err());
        store
            .put_record(JOURNAL, job.id.as_bytes(), &original)
            .unwrap();
    }
    retain(&store, job, &bundle).unwrap();
}

#[test]
fn packing_source_loans_reject_one_sided_and_damaged_dependencies_without_repair() {
    let tmp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    publish(&store, &bundle, &bytes).unwrap();
    let job = retention();
    begin(&store, job).unwrap();
    retain(&store, job, &bundle).unwrap();
    for (kind, key) in [(revisions(job.id), bundle.id), (owners(bundle.id), job.id)] {
        let original = store.get_record(&kind, key.as_bytes()).unwrap().unwrap();
        for damage in [None, Some(vec![0; ROW_BYTES + 1]), Some(b"bad".to_vec())] {
            if let Some(bytes) = &damage {
                store.put_record(&kind, key.as_bytes(), bytes).unwrap();
            } else {
                store.delete_record(&kind, key.as_bytes()).unwrap();
            }
            assert!(retain(&store, job, &bundle).is_err());
            assert!(store.catalog_packing_source(job, bundle.id).is_err());
            assert_eq!(store.get_record(&kind, key.as_bytes()).unwrap(), damage);
            store.put_record(&kind, key.as_bytes(), &original).unwrap();
        }
    }
    store.cancel_catalog_packing_source_retention(job).unwrap();
    assert!(store.release_catalog_packing_source(job).unwrap());
}

#[test]
fn packing_source_loans_keep_native_binding_live_and_allow_authenticated_replacement() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let a = Uuid::new_v4();
    let b = Uuid::new_v4();
    let original = data_fixture(&store, a);
    let job = retention();
    begin(&store, job).unwrap();
    let signed = paged_revision::revision(&original.catalog.bundle).unwrap();
    let retained: Result<_, CatalogStoreError> = store.retain_catalog_packing_source_checked(
        job,
        &signed,
        (
            |_| Ok(()),
            |view, catalog| {
                assert_eq!(
                    view.data_source(catalog.bundle.id, original.source.sector.id)?
                        .unwrap(),
                    original
                );
                Ok(())
            },
        ),
    );
    retained.unwrap();
    drop(store);
    let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    assert!(
        store
            .cancel_paged_revision_catalog(original.catalog.bundle.id)
            .is_err()
    );
    assert!(
        store
            .release_paged_revision_data_source(original.catalog.bundle.id)
            .is_err()
    );
    assert!(store.paged_data_anchor_is_pinned(a).unwrap());
    let replacement = store
        .replace_paged_revision_data_source_checked(&original, b, b"source-b", |_| {
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
    assert!(!store.paged_data_anchor_is_pinned(a).unwrap());
    assert!(store.paged_data_anchor_is_pinned(b).unwrap());
    assert_eq!(
        store
            .catalog_packing_source(job, original.catalog.bundle.id)
            .unwrap(),
        Some(original.catalog.clone())
    );
    assert_eq!(
        store
            .paged_revision_data_source(original.catalog.bundle.id, original.source.sector.id)
            .unwrap(),
        Some(replacement)
    );
    store.cancel_catalog_packing_source_retention(job).unwrap();
    assert!(store.release_catalog_packing_source(job).unwrap());
    store
        .cancel_paged_revision_catalog(original.catalog.bundle.id)
        .unwrap();
    assert!(
        store
            .release_paged_revision_data_source(original.catalog.bundle.id)
            .unwrap()
    );
    assert!(!store.paged_data_anchor_is_pinned(b).unwrap());
}

fn authorised(
    bundle: &CatalogBundle,
    record: &mb_core::CatalogSectorRecord,
) -> CatalogPackingAuthorizedSource {
    let CatalogScope::Dataset {
        owner,
        protected_root_id,
        ..
    } = bundle.scope
    else {
        panic!("dataset fixture")
    };
    CatalogPackingAuthorizedSource {
        id: mb_core::CatalogPackedSourceId {
            owner,
            protected_root: mb_core::packing_protected_root(protected_root_id),
            object_id: record.sector.id,
        },
        flat_root: record.sector.root,
        commitment: record.commitment.clone(),
    }
}

#[test]
fn packing_input_join_requires_the_exact_borrowed_catalog_and_original_source_identity() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let (first, bytes) = fixture(&s, 1, None);
    publish(&s, &first, &bytes).unwrap();
    let (second, bytes) = fixture(
        &s,
        2,
        Some(
            paged_revision::revision(&first)
                .unwrap()
                .value
                .hash()
                .unwrap(),
        ),
    );
    publish(&s, &second, &bytes).unwrap();
    let job = retention();
    begin(&s, job).unwrap();
    retain(&s, job, &second).unwrap();
    let first_source = authorised(
        &first,
        &paged_revision::revision(&first).unwrap().value.metadata,
    );
    assert!(retained_source(&s.connection, job, first.id, &first_source).is_err());
    let record = paged_revision::revision(&second).unwrap().value.metadata;
    let input = authorised(&second, &record);
    assert_eq!(
        retained_source(&s.connection, job, second.id, &input)
            .unwrap()
            .bundle,
        second
    );
    for damage in 0..5 {
        let mut wrong = input.clone();
        match damage {
            0 => wrong.id.owner = mb_core::NodeId([94; 32]),
            1 => wrong.id.protected_root = [95; 32],
            2 => wrong.id.object_id = [96; 32],
            3 => wrong.flat_root = [97; 32],
            _ => wrong.commitment.root = [98; 32],
        }
        assert!(retained_source(&s.connection, job, second.id, &wrong).is_err());
    }
    s.cancel_catalog_packing_source_retention(job).unwrap();
    assert!(retained_source(&s.connection, job, second.id, &input).is_ok());
    while s.release_catalog_packing_source(job).unwrap() {}
    assert!(retained_source(&s.connection, job, second.id, &input).is_err());
}

#[test]
fn packing_input_join_validates_data_and_page_bindings_and_reopens_shared_owners() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let s = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let data = data_fixture(&s, Uuid::new_v4());
    let data_input = authorised(&data.catalog.bundle, &data.source);
    let job = retention();
    begin(&s, job).unwrap();
    retain(&s, job, &data.catalog.bundle).unwrap();
    assert!(retained_source(&s.connection, job, data.catalog.bundle.id, &data_input).is_ok());
    let signed = paged_revision::revision(&data.catalog.bundle).unwrap();
    let (next, bytes) = fixture(&s, 2, Some(signed.value.hash().unwrap()));
    publish(&s, &next, &bytes).unwrap();
    retain(&s, job, &next).unwrap();
    let page = s
        .paged_revision_page_source(next.id, data.source.sector.id)
        .unwrap()
        .unwrap();
    let input = authorised(&next, &page.source);
    assert!(retained_source(&s.connection, job, next.id, &input).is_ok());
    drop(s);
    let s = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    assert!(retained_source(&s.connection, job, next.id, &input).is_ok());
    let kind = format!("catalog-paged-page-source-v1/{}", next.id.simple());
    s.put_record(&kind, &input.id.object_id, &[0; 8193])
        .unwrap();
    assert!(retained_source(&s.connection, job, next.id, &input).is_err());
    assert!(retained_source(&s.connection, job, data.catalog.bundle.id, &data_input).is_ok());
}
