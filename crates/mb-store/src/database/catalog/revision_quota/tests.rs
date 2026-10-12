use super::super::paged_revision::tests::{fixture, fixture_with_context, publish};
use super::*;
use ed25519_dalek::SigningKey;
use mb_core::{KeyMaterial, Seed};

fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([71; 32]))
}
fn generous() -> CatalogPublishedRevisionQuota {
    CatalogPublishedRevisionQuota {
        revisions: 100,
        work: Work {
            bytes: 1 << 30,
            page_occurrences: 1_000_000,
            records: 10_000_000,
        },
    }
}
fn quotas(quota: CatalogPublishedRevisionQuota) -> CatalogPublishedRevisionQuotas {
    CatalogPublishedRevisionQuotas {
        global: quota,
        dataset: quota,
        guild: quota,
    }
}
fn configure(store: &ControlStore, quotas: CatalogPublishedRevisionQuotas) {
    let mut usage = store
        .begin_catalog_published_revision_quota_adoption(quotas)
        .unwrap();
    while usage.state == CatalogPublishedRevisionQuotaState::Adopting {
        usage = store
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
}
fn used(
    store: &ControlStore,
    scope: CatalogPublishedRevisionQuotaScope,
) -> CatalogPublishedRevisionQuota {
    store
        .catalog_published_revision_quota_usage(scope)
        .unwrap()
        .unwrap()
        .used
}
fn global(store: &ControlStore) -> CatalogPublishedRevisionQuota {
    used(store, CatalogPublishedRevisionQuotaScope::Global)
}

#[test]
fn published_revision_work_charges_shared_roots_per_occurrence_and_reopens_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &keys()).unwrap();
    configure(
        &store,
        quotas(CatalogPublishedRevisionQuota {
            revisions: 2,
            ..generous()
        }),
    );
    let (first, bootstrap) = fixture(&store, 1, None);
    let value = charge(&first).unwrap().amount;
    publish(&store, &first, &bootstrap).unwrap();
    assert_eq!(global(&store), value);
    publish(&store, &first, &bootstrap).unwrap();
    assert_eq!(global(&store), value);
    let (second, bytes) = fixture(
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
    assert_eq!(
        first.roots.iter().map(|v| v.root).collect::<Vec<_>>(),
        second.roots.iter().map(|v| v.root).collect::<Vec<_>>()
    );
    publish(&store, &second, &bytes).unwrap();
    assert_eq!(
        global(&store),
        value.add(charge(&second).unwrap().amount).unwrap()
    );
    let (third, bytes) = fixture(&store, 3, Some([7; 32]));
    assert!(
        store
            .publish_paged_revision_catalog_checked(
                &third,
                &bytes,
                |_| -> Result<(), CatalogStoreError> { panic!("exhausted quota reached callback") }
            )
            .is_err()
    );
    assert!(store.catalog_bundle(third.id).unwrap().is_none());
    drop(store);
    store = ControlStore::open(&path, &keys()).unwrap();
    store.cancel_paged_revision_catalog(first.id).unwrap();
    store.cancel_paged_revision_catalog(first.id).unwrap();
    assert_eq!(global(&store), charge(&second).unwrap().amount);
    assert!(
        store
            .paged_revision_catalog(second.id)
            .unwrap()
            .unwrap()
            .bootstrap
            .is_some()
    );
    // Pending pins and source cleanup still exist after exposure is withdrawn.
    assert!(store.release_paged_revision_page_source(first.id).unwrap());
    assert_eq!(global(&store), charge(&second).unwrap().amount);
    publish(&store, &third, &bytes).unwrap();
    assert_eq!(global(&store).revisions, 2);
}

#[test]
fn published_revision_quota_enforces_every_dimension_before_callback() {
    for dimension in 0..4 {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
        let (bundle, bytes) = fixture(&store, 1, None);
        let mut limit = charge(&bundle).unwrap().amount;
        match dimension {
            0 => limit.revisions -= 1,
            1 => limit.work.bytes -= 1,
            2 => limit.work.page_occurrences -= 1,
            _ => limit.work.records -= 1,
        }
        configure(&store, quotas(limit));
        assert!(
            store
                .check_catalog_published_revision_capacity(&bundle)
                .is_err()
        );
        assert!(
            store
                .publish_paged_revision_catalog_checked(
                    &bundle,
                    &bytes,
                    |_| -> Result<(), CatalogStoreError> {
                        panic!("quota refusal reached callback")
                    }
                )
                .is_err()
        );
        assert_eq!(global(&store), CatalogPublishedRevisionQuota::default());
        assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
    }
}

#[test]
fn published_revision_quotas_isolate_datasets_and_guilds_under_one_global_ledger() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    configure(
        &store,
        CatalogPublishedRevisionQuotas {
            global: CatalogPublishedRevisionQuota {
                revisions: 3,
                ..generous()
            },
            dataset: CatalogPublishedRevisionQuota {
                revisions: 1,
                ..generous()
            },
            guild: CatalogPublishedRevisionQuota {
                revisions: 2,
                ..generous()
            },
        },
    );
    let make = |guild: u8, root: u8| {
        fixture_with_context(
            &store,
            1,
            None,
            &keys(),
            &SigningKey::from_bytes(&[72; 32]),
            CatalogScope::Dataset {
                guild_id: [guild; 32],
                owner: keys().node_id(),
                protected_root_id: Uuid::from_bytes([root; 16]),
            },
        )
    };
    let (first, bytes) = make(73, 1);
    publish(&store, &first, &bytes).unwrap();
    let (same, bytes) = make(73, 1);
    assert!(publish(&store, &same, &bytes).is_err());
    let (second, bytes) = make(73, 2);
    publish(&store, &second, &bytes).unwrap();
    let (guild_full, bytes) = make(73, 3);
    assert!(publish(&store, &guild_full, &bytes).is_err());
    let (third, bytes) = make(74, 1);
    publish(&store, &third, &bytes).unwrap();
    let (global_full, bytes) = make(75, 1);
    assert!(publish(&store, &global_full, &bytes).is_err());
    assert_eq!(global(&store).revisions, 3);
    assert_eq!(
        used(&store, CatalogPublishedRevisionQuotaScope::Guild([73; 32])).revisions,
        2
    );
    assert_eq!(
        used(
            &store,
            CatalogPublishedRevisionQuotaScope::Dataset(first.scope)
        )
        .revisions,
        1
    );
}

#[test]
fn published_revision_adoption_is_bounded_freezes_writers_reopens_and_preserves_originals() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &keys()).unwrap();
    let mut originals = Vec::new();
    for _ in 0..3 {
        let (bundle, bytes) = fixture(&store, 1, None);
        publish(&store, &bundle, &bytes).unwrap();
        originals.push(bundle);
    }
    store
        .cancel_paged_revision_catalog(originals[1].id)
        .unwrap();
    let other = ControlStore::open(&path, &keys()).unwrap();
    let start = store
        .begin_catalog_published_revision_quota_adoption(quotas(generous()))
        .unwrap();
    assert_eq!(start.state, CatalogPublishedRevisionQuotaState::Adopting);
    assert!(
        other
            .cancel_paged_revision_catalog(originals[0].id)
            .is_err()
    );
    let (new, bytes) = fixture(&other, 1, None);
    assert!(publish(&other, &new, &bytes).is_err());
    originals.sort_by_key(|v| v.id);
    let partial = store
        .resume_catalog_published_revision_quota_adoption()
        .unwrap();
    assert_eq!(partial.cursor, Some(originals[0].id));
    assert!(partial.used.revisions <= 1);
    drop(other);
    drop(store);
    store = ControlStore::open(&path, &keys()).unwrap();
    let second = store
        .resume_catalog_published_revision_quota_adoption()
        .unwrap();
    assert_eq!(second.cursor, Some(originals[1].id));
    let third = store
        .resume_catalog_published_revision_quota_adoption()
        .unwrap();
    assert_eq!(third.cursor, Some(originals[2].id));
    assert_eq!(third.state, CatalogPublishedRevisionQuotaState::Adopting);
    let final_usage = store
        .resume_catalog_published_revision_quota_adoption()
        .unwrap();
    assert_eq!(
        final_usage.state,
        CatalogPublishedRevisionQuotaState::Active
    );
    assert_eq!(final_usage.used.revisions, 2);
    for original in &originals {
        assert_eq!(
            store
                .paged_revision_catalog(original.id)
                .unwrap()
                .unwrap()
                .bundle,
            *original
        );
    }
    assert!(
        store
            .abort_catalog_published_revision_quota_adoption()
            .is_err()
    );
}

#[test]
fn published_revision_refused_adoption_grows_or_aborts_without_changing_original_data() {
    for abort in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
        let (first, bytes) = fixture(&store, 1, None);
        publish(&store, &first, &bytes).unwrap();
        let (second, bytes) = fixture(&store, 1, None);
        publish(&store, &second, &bytes).unwrap();
        store
            .begin_catalog_published_revision_quota_adoption(quotas(
                CatalogPublishedRevisionQuota {
                    revisions: 1,
                    ..generous()
                },
            ))
            .unwrap();
        store
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
        let partial = store
            .catalog_published_revision_quota_usage(CatalogPublishedRevisionQuotaScope::Global)
            .unwrap()
            .unwrap();
        assert!(
            store
                .resume_catalog_published_revision_quota_adoption()
                .is_err()
        );
        assert_eq!(
            store
                .catalog_published_revision_quota_usage(CatalogPublishedRevisionQuotaScope::Global)
                .unwrap(),
            Some(partial)
        );
        if abort {
            let mut calls = 0;
            while store
                .abort_catalog_published_revision_quota_adoption()
                .unwrap()
            {
                calls += 1;
                assert!(calls <= 8);
            }
            assert!(
                store
                    .catalog_published_revision_quota_usage(
                        CatalogPublishedRevisionQuotaScope::Global
                    )
                    .unwrap()
                    .is_none()
            );
            let (third, bytes) = fixture(&store, 1, None);
            publish(&store, &third, &bytes).unwrap();
        } else {
            store
                .begin_catalog_published_revision_quota_adoption(quotas(generous()))
                .unwrap();
            store
                .resume_catalog_published_revision_quota_adoption()
                .unwrap();
            assert_eq!(
                store
                    .resume_catalog_published_revision_quota_adoption()
                    .unwrap()
                    .used
                    .revisions,
                2
            );
            assert!(
                store
                    .begin_catalog_published_revision_quota_adoption(quotas(
                        CatalogPublishedRevisionQuota {
                            revisions: 1,
                            ..generous()
                        }
                    ))
                    .is_err()
            );
        }
        assert_eq!(
            store
                .paged_revision_catalog(first.id)
                .unwrap()
                .unwrap()
                .bundle,
            first
        );
        assert_eq!(
            store
                .paged_revision_catalog(second.id)
                .unwrap()
                .unwrap()
                .bundle,
            second
        );
    }
}

#[test]
fn published_revision_quota_sql_faults_roll_back_all_scopes_and_enclosing_publication() {
    for kind in [TOTALS, SCOPE_ENABLED, CHARGE] {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
        configure(&store, quotas(generous()));
        let (bundle, bytes) = fixture(&store, 1, None);
        store.connection.execute_batch(&format!("CREATE TEMP TRIGGER ignore_quota BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END")).unwrap();
        assert!(publish(&store, &bundle, &bytes).is_err());
        assert_eq!(global(&store), CatalogPublishedRevisionQuota::default());
        assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
    }
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    configure(&store, quotas(generous()));
    let (bundle, bytes) = fixture(&store, 1, None);
    let global_key = hex::encode(scope_key(CatalogPublishedRevisionQuotaScope::Global).unwrap());
    let old = store
        .get_record(
            TOTALS,
            &scope_key(CatalogPublishedRevisionQuotaScope::Global).unwrap(),
        )
        .unwrap()
        .unwrap();
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER revert_late AFTER INSERT ON protocol_records WHEN NEW.kind='{}' BEGIN UPDATE protocol_records SET bytes=x'{}' WHERE kind='{TOTALS}' AND record_id=x'{global_key}'; END", paged_revision::PUBLICATION, hex::encode(&old))).unwrap();
    assert!(publish(&store, &bundle, &bytes).is_err());
    assert_eq!(global(&store), CatalogPublishedRevisionQuota::default());
    assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
    store
        .connection
        .execute_batch("DROP TRIGGER revert_late")
        .unwrap();
    publish(&store, &bundle, &bytes).unwrap();
    let full = global(&store);
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_cancel BEFORE DELETE ON protocol_records WHEN OLD.kind='{CHARGE}' BEGIN SELECT RAISE(IGNORE); END")).unwrap();
    assert!(store.cancel_paged_revision_catalog(bundle.id).is_err());
    assert_eq!(global(&store), full);
    assert_eq!(
        store
            .paged_revision_catalog(bundle.id)
            .unwrap()
            .unwrap()
            .state,
        CatalogBundleState::Published
    );
}

#[test]
fn published_revision_quota_missing_or_malformed_owned_rows_fail_closed() {
    for kind in [POLICY, ENABLED, TOTALS, SCOPE_ENABLED, CHARGE] {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
        configure(&store, quotas(generous()));
        let (bundle, bytes) = fixture(&store, 1, None);
        publish(&store, &bundle, &bytes).unwrap();
        store
            .connection
            .execute("DELETE FROM protocol_records WHERE kind=?1", params![kind])
            .unwrap();
        assert!(store.paged_revision_catalog(bundle.id).is_err(), "{kind}");
        assert!(
            store.cancel_paged_revision_catalog(bundle.id).is_err(),
            "{kind}"
        );
    }
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    configure(&store, quotas(generous()));
    store
        .put_record(POLICY, KEY, &vec![1; ROW_BYTES + 1])
        .unwrap();
    assert!(
        store
            .catalog_published_revision_quota_usage(CatalogPublishedRevisionQuotaScope::Global)
            .is_err()
    );
}
