use super::*;
use std::sync::{Arc, Barrier};

#[test]
fn source_dependency_competing_connections_publish_and_cancel_after_original_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (original, source, anchor) = setup(&store);
    let used = store.catalog_retained_source_usage(original.scope).unwrap();
    let admitted = Arc::new(Barrier::new(3));
    let proceed = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for publishes in [false, true] {
        let path = path.clone();
        let source = source.clone();
        let admitted = admitted.clone();
        let proceed = proceed.clone();
        tasks.push(std::thread::spawn(move || {
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (bundle, bytes, _) = fixture(&store);
            admit(
                &store,
                bundle.id,
                bundle.scope,
                std::slice::from_ref(&source),
            )
            .unwrap();
            admitted.wait();
            proceed.wait();
            if publishes {
                let new_anchor = Uuid::new_v4();
                publish(&store, &bundle, &bytes, &source, new_anchor);
                Some((bundle.id, new_anchor))
            } else {
                store
                    .cancel_catalog_retained_source_reservation(bundle.id, bundle.scope)
                    .unwrap();
                assert!(
                    store
                        .release_catalog_retained_source_dependency(bundle.id, bundle.scope)
                        .unwrap()
                );
                None
            }
        }));
    }
    admitted.wait();
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(3)
    );
    store.cancel_paged_revision_catalog(original.id).unwrap();
    assert!(
        store
            .release_paged_revision_data_source(original.id)
            .unwrap()
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(2)
    );
    proceed.wait();
    let survivor = tasks
        .into_iter()
        .filter_map(|task| task.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(survivor.len(), 1);
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        used
    );
    assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
    let (id, new_anchor) = survivor[0];
    assert!(
        store
            .paged_revision_data_source(id, source.sector.id)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, new_anchor).unwrap(),
        Some(1)
    );
    store.cancel_paged_revision_catalog(id).unwrap();
    assert!(store.release_paged_revision_data_source(id).unwrap());
    assert!(!store.paged_data_anchor_is_pinned(new_anchor).unwrap());
    assert_eq!(
        store
            .catalog_retained_source_usage(original.scope)
            .unwrap()
            .unwrap()
            .stored_sources,
        0
    );
}

fn fixture(store: &ControlStore) -> (CatalogBundle, Vec<u8>, CatalogSectorRecord) {
    let (bundle, bytes) = paged_revision::tests::fixture(store, 1, None);
    let signed = mb_core::PagedUserRevision::decode_signed(&bundle.descriptor).unwrap();
    let mut reader = mb_core::CatalogSectorReader::new(bundle.scope, signed.value.sources).unwrap();
    let mut source = None;
    while let Some(record) = reader
        .next_sector(&mut |page| {
            store.catalog_page(bundle.scope, CatalogSection::SectorReferences, page)
        })
        .unwrap()
    {
        if record.sector.id != signed.value.metadata.sector.id {
            source = Some(record)
        }
    }
    (bundle, bytes, source.unwrap())
}

fn admit(
    store: &ControlStore,
    id: Uuid,
    scope: CatalogScope,
    sources: &[CatalogSectorRecord],
) -> Result<(), CatalogStoreError> {
    store.with_record_transaction(|| {
        store.reserve_catalog_retained_sources_with_dependencies_in_transaction(id, scope, || {
            sources.iter().cloned().map(Ok)
        })
    })
}

fn publish(
    store: &ControlStore,
    bundle: &CatalogBundle,
    bytes: &[u8],
    source: &CatalogSectorRecord,
    anchor: Uuid,
) {
    store
        .publish_paged_revision_catalog_checked(bundle, bytes, |view| {
            view.bind_data_source(source, anchor, b"authenticated-source")
        })
        .unwrap();
}

fn setup(store: &ControlStore) -> (CatalogBundle, CatalogSectorRecord, Uuid) {
    let (bundle, bytes, source) = fixture(store);
    store
        .configure_catalog_retained_source_quota(CatalogRetainedSourceQuota {
            logical_bytes: source.sector.logical_len.into(),
            sources: 1,
            open_reservations: 2,
        })
        .unwrap();
    admit(
        store,
        bundle.id,
        bundle.scope,
        std::slice::from_ref(&source),
    )
    .unwrap();
    let anchor = Uuid::new_v4();
    publish(store, &bundle, &bytes, &source, anchor);
    (bundle, source, anchor)
}

#[test]
fn source_dependency_cancelled_binding_can_be_held_until_its_actual_cleanup() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (original, source, anchor) = setup(&store);
    let (next, bytes, _) = fixture(&store);
    let used = store.catalog_retained_source_usage(original.scope).unwrap();
    store.cancel_paged_revision_catalog(original.id).unwrap();
    assert!(
        store
            .paged_revision_data_source(original.id, source.sector.id)
            .unwrap()
            .is_none()
    );
    admit(&store, next.id, next.scope, std::slice::from_ref(&source)).unwrap();
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(2)
    );
    assert!(
        store
            .release_paged_revision_data_source(original.id)
            .unwrap()
    );
    assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
    publish(&store, &next, &bytes, &source, anchor);
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        used
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(1)
    );
    store.cancel_paged_revision_catalog(next.id).unwrap();
    assert!(store.release_paged_revision_data_source(next.id).unwrap());
    assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
}

#[test]
fn source_dependency_holds_admit_at_capacity_and_survive_final_owner_cleanup_and_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (original, source, old_anchor) = setup(&store);
    let id = Uuid::new_v4();
    let list = std::slice::from_ref(&source);
    let used = store
        .catalog_retained_source_usage(original.scope)
        .unwrap()
        .unwrap();
    admit(&store, id, original.scope, list).unwrap();
    admit(&store, id, original.scope, list).unwrap();
    assert!(
        store
            .release_catalog_retained_source_dependency(id, original.scope)
            .is_err()
    );
    assert!(
        store
            .with_record_transaction(|| close(&store.connection, id, original.scope, false))
            .is_err()
    );
    let held = store
        .catalog_retained_source_usage(original.scope)
        .unwrap()
        .unwrap();
    assert_eq!(held.stored_logical_bytes, used.stored_logical_bytes);
    assert_eq!(held.reserved_logical_bytes, 0);
    assert_eq!(held.reserved_sources, 0);
    assert_eq!(held.open_reservations, 1);
    store.cancel_paged_revision_catalog(original.id).unwrap();
    assert!(
        store
            .release_paged_revision_data_source(original.id)
            .unwrap()
    );
    assert!(
        !store
            .release_paged_revision_data_source(original.id)
            .unwrap()
    );
    assert!(store.paged_data_anchor_is_pinned(old_anchor).unwrap());
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        Some(held)
    );
    drop(store);
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    admit(&store, id, original.scope, list).unwrap();
    let (next, bytes, next_source) = fixture(&store);
    assert_eq!(source, next_source);
    admit(&store, next.id, next.scope, list).unwrap();
    // The original binding is gone: the second hold borrows the first hold.
    let new_anchor = Uuid::new_v4();
    publish(&store, &next, &bytes, &source, new_anchor);
    assert!(store.paged_data_anchor_is_pinned(old_anchor).unwrap());
    assert!(store.paged_data_anchor_is_pinned(new_anchor).unwrap());
    store
        .cancel_catalog_retained_source_reservation(id, original.scope)
        .unwrap();
    assert!(
        store
            .release_catalog_retained_source_dependency(id, original.scope)
            .unwrap()
    );
    assert!(
        !store
            .release_catalog_retained_source_dependency(id, original.scope)
            .unwrap()
    );
    assert!(!store.paged_data_anchor_is_pinned(old_anchor).unwrap());
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        Some(used)
    );
    assert!(
        store
            .paged_revision_data_source(next.id, source.sector.id)
            .unwrap()
            .is_some()
    );
    store.cancel_paged_revision_catalog(next.id).unwrap();
    assert!(store.release_paged_revision_data_source(next.id).unwrap());
    let empty = store
        .catalog_retained_source_usage(original.scope)
        .unwrap()
        .unwrap();
    assert_eq!(empty.stored_sources, 0);
    assert_eq!(empty.stored_logical_bytes, 0);
    assert!(!store.paged_data_anchor_is_pinned(new_anchor).unwrap());
}

#[test]
fn source_dependency_admission_rejects_changed_inputs_unfunded_additions_and_nonrepeatable_streams_atomically()
 {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (original, source, anchor) = setup(&store);
    let used = store.catalog_retained_source_usage(original.scope).unwrap();
    let other = CatalogSectorRecord {
        sector: mb_core::SectorRef {
            id: [255; 32],
            ..source.sector.clone()
        },
        ..source.clone()
    };
    let mut inputs = vec![source.clone(), other.clone()];
    inputs.sort_by_key(|record| record.sector.id);
    let id = Uuid::new_v4();
    assert!(matches!(
        admit(&store, id, original.scope, &inputs),
        Err(CatalogStoreError::RetainedSourceQuotaExceeded)
    ));
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        used
    );
    assert!(
        reservation(&store.connection, id, original.scope)
            .unwrap()
            .is_none()
    );
    let list = std::slice::from_ref(&source);
    let mut pass = 0;
    assert!(
        store
            .with_record_transaction(|| store
                .reserve_catalog_retained_sources_with_dependencies_in_transaction(
                    id,
                    original.scope,
                    || {
                        pass += 1;
                        if pass == 1 {
                            vec![Ok(source.clone())]
                        } else {
                            vec![Ok(other.clone())]
                        }
                        .into_iter()
                    }
                ))
            .is_err()
    );
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        used
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(1)
    );
    admit(&store, id, original.scope, list).unwrap();
    let held = store.catalog_retained_source_usage(original.scope).unwrap();
    for changed in [vec![], vec![other], vec![source.clone(), source.clone()]] {
        assert!(admit(&store, id, original.scope, &changed).is_err());
        assert_eq!(
            store.catalog_retained_source_usage(original.scope).unwrap(),
            held
        );
    }
    store
        .cancel_catalog_retained_source_reservation(id, original.scope)
        .unwrap();
    assert!(admit(&store, id, original.scope, list).is_err());
    assert!(
        store
            .release_catalog_retained_source_dependency(id, original.scope)
            .unwrap()
    );
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        used
    );
    // Old conservative reservations keep their original loans on resume.
    store
        .configure_catalog_retained_source_quota(CatalogRetainedSourceQuota {
            logical_bytes: u64::from(source.sector.logical_len) * 2,
            sources: 2,
            open_reservations: 2,
        })
        .unwrap();
    let old = Uuid::new_v4();
    let capacity = CatalogRetainedSourceReservation {
        logical_bytes: source.sector.logical_len.into(),
        sources: 1,
    };
    store
        .with_record_transaction(|| {
            store.reserve_catalog_retained_sources_in_transaction(old, original.scope, capacity)
        })
        .unwrap();
    admit(&store, old, original.scope, list).unwrap();
    admit(&store, old, original.scope, list).unwrap();
    assert!(
        own_hold(&store.connection, old, original.scope, &source)
            .unwrap()
            .is_some()
    );
    assert_eq!(
        reservation(&store.connection, old, original.scope)
            .unwrap()
            .unwrap()
            .original,
        capacity
    );
    store.cancel_paged_revision_catalog(original.id).unwrap();
    assert!(
        store
            .release_paged_revision_data_source(original.id)
            .unwrap()
    );
    assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
    store
        .cancel_catalog_retained_source_reservation(old, original.scope)
        .unwrap();
    assert!(
        store
            .release_catalog_retained_source_dependency(old, original.scope)
            .unwrap()
    );
    assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
    assert_eq!(
        store
            .catalog_retained_source_usage(original.scope)
            .unwrap()
            .unwrap()
            .stored_sources,
        0
    );
}

#[test]
fn source_dependency_holds_roll_back_ignored_and_reverted_writes_with_owner_journal() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (original, source, anchor) = setup(&store);
    let used = store.catalog_retained_source_usage(original.scope).unwrap();
    for trigger in [
        "CREATE TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-retained-source-hold-v1' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind GLOB 'catalog-retained-source-hold-owner-v1/*' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER fault AFTER UPDATE ON protocol_records WHEN NEW.kind = 'catalog-paged-data-anchor-v1' BEGIN UPDATE protocol_records SET bytes = OLD.bytes WHERE kind = NEW.kind AND record_id = NEW.record_id; END",
        "CREATE TRIGGER fault BEFORE UPDATE ON protocol_records WHEN NEW.kind = 'catalog-retained-source-charge-v1' BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-retained-source-admission-v1' BEGIN SELECT RAISE(IGNORE); END",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        let id = Uuid::new_v4();
        assert!(
            store
                .with_record_transaction(|| {
                    store.put_record_if_absent(
                        "test-source-admission-owner",
                        id.as_bytes(),
                        b"immutable",
                    )?;
                    store.reserve_catalog_retained_sources_with_dependencies_in_transaction(
                        id,
                        original.scope,
                        || std::iter::once(Ok(source.clone())),
                    )
                })
                .is_err()
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
        assert_eq!(
            store.catalog_retained_source_usage(original.scope).unwrap(),
            used
        );
        assert_eq!(
            paged_data::anchor_count(&store.connection, anchor).unwrap(),
            Some(1)
        );
        assert!(
            reservation(&store.connection, id, original.scope)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_record_bounded("test-source-admission-owner", id.as_bytes(), 32)
                .unwrap()
                .is_none()
        );
        require_no_holds(&store.connection, id).unwrap();
    }
    let id = Uuid::new_v4();
    assert!(
        store
            .with_record_transaction(|| {
                store.reserve_catalog_retained_sources_with_dependencies_in_transaction(
                    id,
                    original.scope,
                    || std::iter::once(Ok(source.clone())),
                )?;
                Err::<(), CatalogStoreError>(DatabaseError::Conflict.into())
            })
            .is_err()
    );
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        used
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(1)
    );
}

#[test]
fn source_dependency_publication_and_cancel_cleanup_roll_back_failed_pin_transfers() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (original, source, anchor) = setup(&store);
    let (next, bytes, _) = fixture(&store);
    admit(&store, next.id, next.scope, std::slice::from_ref(&source)).unwrap();
    let held = store.catalog_retained_source_usage(original.scope).unwrap();
    store.connection.execute_batch("CREATE TRIGGER fault BEFORE DELETE ON protocol_records WHEN OLD.kind = 'catalog-retained-source-hold-v1' BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(
        store
            .publish_paged_revision_catalog_checked(&next, &bytes, |view| view.bind_data_source(
                &source,
                anchor,
                b"new-source"
            ))
            .is_err()
    );
    assert!(store.catalog_bundle(next.id).unwrap().is_none());
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        held
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(2)
    );
    store
        .cancel_catalog_retained_source_reservation(next.id, next.scope)
        .unwrap();
    let cancelled = store.catalog_retained_source_usage(original.scope).unwrap();
    assert!(
        store
            .release_catalog_retained_source_dependency(next.id, next.scope)
            .is_err()
    );
    assert_eq!(
        store.catalog_retained_source_usage(original.scope).unwrap(),
        cancelled
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(2)
    );
    store
        .connection
        .execute_batch("DROP TRIGGER fault")
        .unwrap();
    assert!(
        store
            .release_catalog_retained_source_dependency(next.id, next.scope)
            .unwrap()
    );
    assert_eq!(
        paged_data::anchor_count(&store.connection, anchor).unwrap(),
        Some(1)
    );
}
