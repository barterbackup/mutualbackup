use super::*;
use mb_core::{KeyMaterial, PagedUserRevision, Seed, merkle_commit};

fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([71; 32]))
}

fn fixture(
    store: &ControlStore,
    sequence: u64,
    parent: Option<[u8; 32]>,
) -> (CatalogBundle, Vec<u8>, CatalogSectorRecord) {
    let (bundle, bootstrap) = paged_revision::tests::fixture(store, sequence, parent);
    let source = source_for(store, &bundle);
    (bundle, bootstrap, source)
}

fn source_for(store: &ControlStore, bundle: &CatalogBundle) -> CatalogSectorRecord {
    let CatalogScope::Dataset { guild_id, .. } = bundle.scope else {
        unreachable!()
    };
    let page = bundle.roots[0];
    let encoded = store
        .catalog_page(bundle.scope, page.intent.section, page.root)
        .unwrap();
    let (sector, ciphertext) = page
        .root
        .seal_private_page(
            &keys().guild_content_id_key(&guild_id),
            &keys().guild_data_key(&guild_id),
            bundle.scope,
            page.intent.section,
            &encoded,
        )
        .unwrap();
    CatalogSectorRecord {
        format_version: 1,
        sector,
        commitment: merkle_commit(&ciphertext).unwrap(),
    }
}

fn publish(
    store: &ControlStore,
    bundle: &CatalogBundle,
    bootstrap: &[u8],
    source: &CatalogSectorRecord,
    anchor: Uuid,
) {
    store
        .publish_paged_revision_catalog_checked(bundle, bootstrap, |view| {
            view.bind_data_source(source, anchor, b"original authenticated recipe")
        })
        .unwrap();
}

fn quota(source: &CatalogSectorRecord) -> CatalogRetainedSourceQuota {
    CatalogRetainedSourceQuota {
        logical_bytes: u64::from(source.sector.logical_len),
        sources: 1,
        open_reservations: 2,
    }
}

fn rows(store: &ControlStore) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    store
        .connection
        .prepare("SELECT kind, record_id, bytes FROM protocol_records ORDER BY kind, record_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap()
}

#[test]
fn source_quota_adopts_shared_and_cancelled_owners_without_changing_original_custody() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (first, bootstrap, source) = fixture(&store, 1, None);
    let (next, next_bootstrap, next_source) = fixture(
        &store,
        2,
        Some(
            PagedUserRevision::decode_signed(&first.descriptor)
                .unwrap()
                .value
                .hash()
                .unwrap(),
        ),
    );
    assert_eq!(source, next_source);
    let anchor = Uuid::new_v4();
    publish(&store, &first, &bootstrap, &source, anchor);
    publish(&store, &next, &next_bootstrap, &source, anchor);
    store.cancel_paged_revision_catalog(first.id).unwrap();
    let original = rows(&store);
    let expected = store
        .paged_revision_data_source(next.id, source.sector.id)
        .unwrap();
    let quota = quota(&source);
    for too_small in [
        CatalogRetainedSourceQuota {
            logical_bytes: quota.logical_bytes - 1,
            ..quota
        },
        CatalogRetainedSourceQuota {
            sources: 0,
            ..quota
        },
    ] {
        assert!(
            store
                .configure_catalog_retained_source_quota(too_small)
                .is_err()
        );
        assert_eq!(rows(&store), original);
        assert!(
            store
                .catalog_retained_source_usage(first.scope)
                .unwrap()
                .is_none()
        );
    }
    store
        .configure_catalog_retained_source_quota(quota)
        .unwrap();
    store
        .configure_catalog_retained_source_guild_quota(quota)
        .unwrap();
    let used = store
        .catalog_retained_source_usage(first.scope)
        .unwrap()
        .unwrap();
    assert_eq!(
        (used.stored_logical_bytes, used.stored_sources),
        (quota.logical_bytes, 1)
    );
    assert_eq!(
        (
            used.reserved_logical_bytes,
            used.reserved_sources,
            used.open_reservations
        ),
        (0, 0, 0)
    );
    let current = rows(&store);
    assert!(original.iter().all(|row| current.contains(row)));
    assert_eq!(
        store
            .paged_revision_data_source(next.id, source.sector.id)
            .unwrap(),
        expected
    );
    assert_eq!(
        charge(&store.connection, first.scope, &source)
            .unwrap()
            .unwrap()
            .owners,
        2
    );
    drop(store);
    let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    assert!(store.release_paged_revision_data_source(first.id).unwrap());
    assert_eq!(
        store.catalog_retained_source_usage(first.scope).unwrap(),
        Some(used)
    );
    assert!(store.paged_data_anchor_is_pinned(anchor).unwrap());
    // A new revision borrows the adopted identity at the exact dataset/guild limit.
    let (third, third_bootstrap, third_source) = fixture(
        &store,
        3,
        Some(
            PagedUserRevision::decode_signed(&next.descriptor)
                .unwrap()
                .value
                .hash()
                .unwrap(),
        ),
    );
    assert_eq!(source, third_source);
    store
        .with_record_transaction(|| {
            store.reserve_catalog_retained_sources_with_dependencies_in_transaction(
                third.id,
                third.scope,
                || std::iter::once(Ok(source.clone())),
            )
        })
        .unwrap();
    publish(&store, &third, &third_bootstrap, &source, anchor);
    for bundle in [&next, &third] {
        store.cancel_paged_revision_catalog(bundle.id).unwrap();
        assert!(store.release_paged_revision_data_source(bundle.id).unwrap());
    }
    assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
    assert_eq!(
        store.catalog_retained_source_usage(first.scope).unwrap(),
        Some(CatalogRetainedSourceUsage::empty(first.scope))
    );
    assert_eq!(
        store.catalog_retained_source_guild_usage([73; 32]).unwrap(),
        Some(CatalogRetainedSourceUsage::empty(CatalogScope::Guild {
            guild_id: [73; 32]
        }))
    );
}

#[test]
fn source_quota_adopts_each_original_binding_format_and_reopens_read_only() {
    for version in [1_u16, 2, 3] {
        for cancelled in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (bundle, bootstrap, source) = fixture(&store, 1, None);
            let anchor = Uuid::new_v4();
            publish(&store, &bundle, &bootstrap, &source, anchor);
            let kind = format!("catalog-paged-data-source-v1/{}", bundle.id.simple());
            if version != 3 {
                let original = store.get_record(&kind, &source.sector.id).unwrap().unwrap();
                let (_, _, _, recipe_key, _): (u16, CatalogSectorRecord, Uuid, [u8; 32], u64) =
                    decode_canonical(&original).unwrap();
                store
                    .delete_record("catalog-paged-data-recipe-v1", &recipe_key)
                    .unwrap();
                store
                    .delete_record(
                        &format!(
                            "catalog-paged-data-recipe-owner-v1/{}",
                            hex::encode(recipe_key)
                        ),
                        bundle.id.as_bytes(),
                    )
                    .unwrap();
                let bytes = if version == 1 {
                    canonical_bytes(&(
                        version,
                        &source,
                        anchor,
                        b"original authenticated recipe".to_vec(),
                    ))
                    .unwrap()
                } else {
                    canonical_bytes(&(
                        version,
                        &source,
                        anchor,
                        b"original authenticated recipe".to_vec(),
                        7_u64,
                    ))
                    .unwrap()
                };
                store.put_record(&kind, &source.sector.id, &bytes).unwrap();
            }
            if cancelled {
                store.cancel_paged_revision_catalog(bundle.id).unwrap();
            }
            let original = rows(&store);
            store
                .configure_catalog_retained_source_quota(quota(&source))
                .unwrap();
            assert!(original.iter().all(|row| rows(&store).contains(row)));
            let used = store.catalog_retained_source_usage(bundle.scope).unwrap();
            drop(store);
            let ro = ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(
                ro.catalog_retained_source_usage(bundle.scope).unwrap(),
                used
            );
            assert!(
                ro.configure_catalog_retained_source_quota(quota(&source))
                    .is_err()
            );
            drop(ro);
            let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            store
                .configure_catalog_retained_source_quota(CatalogRetainedSourceQuota {
                    logical_bytes: quota(&source).logical_bytes + 1,
                    ..quota(&source)
                })
                .unwrap();
            assert_eq!(
                store.catalog_retained_source_usage(bundle.scope).unwrap(),
                used
            );
            if !cancelled {
                assert_eq!(
                    store
                        .paged_revision_data_source(bundle.id, source.sector.id)
                        .unwrap()
                        .unwrap()
                        .generation,
                    if version == 2 { 7 } else { 0 }
                );
                store.cancel_paged_revision_catalog(bundle.id).unwrap();
            }
            assert!(store.release_paged_revision_data_source(bundle.id).unwrap());
            assert!(!store.paged_data_anchor_is_pinned(anchor).unwrap());
        }
    }
}

#[test]
fn source_quota_adoption_rejects_damaged_rows_and_authentication_without_a_valid_prefix() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let (bundle, bootstrap, source) = fixture(&store, 1, None);
    let anchor = Uuid::new_v4();
    publish(&store, &bundle, &bootstrap, &source, anchor);
    let kind = format!("catalog-paged-data-source-v1/{}", bundle.id.simple());
    let binding = store.get_record(&kind, &source.sector.id).unwrap().unwrap();
    let (_, _, _, recipe, _): (u16, CatalogSectorRecord, Uuid, [u8; 32], u64) =
        decode_canonical(&binding).unwrap();
    let mut changed_bundle = bundle.clone();
    *changed_bundle.descriptor.last_mut().unwrap() ^= 1;
    let mut changed_source = source.clone();
    changed_source.sector.logical_len += 1;
    for (kind, key, replacement) in [
        (
            kind.clone(),
            source.sector.id.to_vec(),
            Some(vec![0; paged_data::PAGED_DATA_RECIPE_BYTES + 1025]),
        ),
        (
            format!(
                "catalog-paged-data-source-v1/{}",
                Uuid::from_bytes([1; 16]).simple()
            ),
            source.sector.id.to_vec(),
            Some(binding.clone()),
        ),
        (
            format!("catalog-paged-data-source-v1/{}", Uuid::nil().simple()),
            source.sector.id.to_vec(),
            Some(binding.clone()),
        ),
        (
            format!(
                "catalog-paged-data-source-v1/{}",
                Uuid::from_bytes([255; 16]).simple()
            ),
            source.sector.id.to_vec(),
            Some(binding.clone()),
        ),
        (kind.clone(), Vec::new(), Some(binding.clone())),
        (
            format!("catalog-paged-data-source-v1/{}", "x".repeat(513)),
            source.sector.id.to_vec(),
            Some(binding),
        ),
        (
            paged_data::ANCHOR.to_owned(),
            anchor.as_bytes().to_vec(),
            None,
        ),
        (
            "catalog-paged-publication-v1".to_owned(),
            bundle.id.as_bytes().to_vec(),
            Some(vec![0]),
        ),
        (
            format!("catalog-paged-data-recipe-owner-v1/{}", hex::encode(recipe)),
            bundle.id.as_bytes().to_vec(),
            None,
        ),
        (
            "catalog-paged-data-recipe-v1".to_owned(),
            recipe.to_vec(),
            Some(vec![0]),
        ),
        (
            "paged-user-revision-v1".to_owned(),
            bundle.id.as_bytes().to_vec(),
            Some(vec![0]),
        ),
        (
            "catalog-bundle-v1".to_owned(),
            bundle.id.as_bytes().to_vec(),
            Some(canonical_bytes(&(1_u16, changed_bundle, CatalogBundleState::Published)).unwrap()),
        ),
        (
            format!("catalog-validation-source-v1/{}", bundle.id.simple()),
            source.sector.id.to_vec(),
            Some(canonical_bytes(&changed_source).unwrap()),
        ),
    ] {
        let previous = store.get_record(&kind, &key).unwrap();
        if let Some(bytes) = replacement {
            store.put_record(&kind, &key, &bytes).unwrap();
        } else {
            store.delete_record(&kind, &key).unwrap();
        }
        let damaged = rows(&store);
        assert!(
            store
                .configure_catalog_retained_source_quota(quota(&source))
                .is_err(),
            "{kind}"
        );
        assert_eq!(rows(&store), damaged, "{kind}");
        if let Some(bytes) = previous {
            store.put_record(&kind, &key, &bytes).unwrap();
        } else {
            store.delete_record(&kind, &key).unwrap();
        }
    }
    store
        .configure_catalog_retained_source_quota(quota(&source))
        .unwrap();
}

#[test]
fn source_quota_adoption_rolls_back_ignored_and_aborted_accounting_writes() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let anchor = Uuid::new_v4();
    let (first, bootstrap, source) = fixture(&store, 1, None);
    publish(&store, &first, &bootstrap, &source, anchor);
    let (next, next_bootstrap, _) = fixture(
        &store,
        2,
        Some(
            PagedUserRevision::decode_signed(&first.descriptor)
                .unwrap()
                .value
                .hash()
                .unwrap(),
        ),
    );
    publish(&store, &next, &next_bootstrap, &source, anchor);
    let original = rows(&store);
    for (operation, kinds) in [
        (
            "INSERT",
            &[POLICY, ENABLED, LEDGER, DATASET, RESERVATION, SOURCE][..],
        ),
        ("UPDATE", &[LEDGER, SOURCE][..]),
    ] {
        for kind in kinds {
            for fault in ["RAISE(IGNORE)", "RAISE(ABORT, 'injected')"] {
                store.connection.execute_batch(&format!("CREATE TEMP TRIGGER reject_adoption BEFORE {operation} ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT {fault}; END;")).unwrap();
                assert!(
                    store
                        .configure_catalog_retained_source_quota(quota(&source))
                        .is_err(),
                    "{operation} {kind} {fault}"
                );
                assert_eq!(rows(&store), original);
                store
                    .connection
                    .execute_batch("DROP TRIGGER reject_adoption")
                    .unwrap();
            }
        }
    }
    store
        .configure_catalog_retained_source_quota(quota(&source))
        .unwrap();
    assert_eq!(
        charge(&store.connection, first.scope, &source)
            .unwrap()
            .unwrap()
            .owners,
        2
    );
}

#[test]
fn source_quota_concurrent_adoption_counts_all_datasets_before_guild_enablement() {
    use std::sync::{Arc, Barrier};
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let mut bundles = Vec::new();
    let mut data_quota = None;
    for (guild_id, root) in [([73; 32], 74), ([73; 32], 75), ([77; 32], 76)] {
        let scope = CatalogScope::Dataset {
            guild_id,
            owner: keys().node_id(),
            protected_root_id: Uuid::from_bytes([root; 16]),
        };
        let (bundle, bootstrap) = paged_revision::tests::fixture_with_context(
            &store,
            1,
            None,
            &keys(),
            &ed25519_dalek::SigningKey::from_bytes(&[72; 32]),
            scope,
        );
        let source = source_for(&store, &bundle);
        assert_eq!(data_quota.get_or_insert(quota(&source)), &quota(&source));
        publish(&store, &bundle, &bootstrap, &source, Uuid::new_v4());
        bundles.push(bundle);
    }
    store.cancel_paged_revision_catalog(bundles[1].id).unwrap();
    let data_quota = data_quota.unwrap();
    drop(store);
    let ready = Arc::new(Barrier::new(3));
    let mut tasks = Vec::new();
    for _ in 0..2 {
        let path = path.clone();
        let ready = ready.clone();
        tasks.push(std::thread::spawn(move || {
            let store = ControlStore::open_existing_with_key(path, &[7; 32]).unwrap();
            ready.wait();
            store
                .configure_catalog_retained_source_quota(data_quota)
                .unwrap();
        }));
    }
    ready.wait();
    for task in tasks {
        task.join().unwrap();
    }
    let store = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    for bundle in &bundles {
        let used = store
            .catalog_retained_source_usage(bundle.scope)
            .unwrap()
            .unwrap();
        assert_eq!(
            (used.stored_logical_bytes, used.stored_sources),
            (data_quota.logical_bytes, 1)
        );
        assert_eq!(used.open_reservations, 0);
    }
    let original = rows(&store);
    assert!(
        store
            .configure_catalog_retained_source_guild_quota(data_quota)
            .is_err()
    );
    assert_eq!(rows(&store), original);
    let guild_quota = CatalogRetainedSourceQuota {
        logical_bytes: data_quota.logical_bytes * 2,
        sources: 2,
        ..data_quota
    };
    store
        .configure_catalog_retained_source_guild_quota(guild_quota)
        .unwrap();
    assert_eq!(
        store
            .catalog_retained_source_guild_usage([73; 32])
            .unwrap()
            .unwrap()
            .stored_sources,
        2
    );
    assert_eq!(
        store
            .catalog_retained_source_guild_usage([77; 32])
            .unwrap()
            .unwrap()
            .stored_sources,
        1
    );
    assert!(
        store
            .release_paged_revision_data_source(bundles[1].id)
            .unwrap()
    );
    assert_eq!(
        store
            .catalog_retained_source_guild_usage([73; 32])
            .unwrap()
            .unwrap()
            .stored_sources,
        1
    );
}
