use super::super::paged_revision::tests::{fixture, publish};
use super::*;
use mb_core::{
    CatalogCapacityPolicy, CodingProfile, KeyMaterial, PackingProfile, Seed, V1_SECTOR_SIZE,
};

fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([71; 32]))
}
fn policy() -> CatalogCapacityPolicy {
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 1,
        legacy_revisions: 0,
        legacy_source_occurrences: 0,
        data_bytes_per_dataset: 1,
        data_sources_per_dataset: 1,
        private_work_per_revision: Work {
            bytes: 16,
            page_occurrences: 2,
            records: 0,
        },
        source_pages_per_revision: 1,
        authority_control_records: 257,
        packing_profile: PackingProfile {
            format_version: 1,
            sector_size: V1_SECTOR_SIZE as u32,
            slot_size: (V1_SECTOR_SIZE / 4) as u32,
        },
        coding_profile: CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32),
        packed_sectors: 6,
        coding_groups: 2,
        replay_work: Work::default(),
    }
}
fn backing(store: &ControlStore) {
    let quota = CatalogPublishedRevisionQuota {
        revisions: 100,
        work: Work {
            bytes: 1 << 30,
            page_occurrences: 1_000_000,
            records: 10_000_000,
        },
    };
    let mut usage = store
        .begin_catalog_published_revision_quota_adoption(CatalogPublishedRevisionQuotas {
            global: quota,
            dataset: quota,
            guild: quota,
        })
        .unwrap();
    while usage.state == CatalogPublishedRevisionQuotaState::Adopting {
        usage = store
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
    let data = CatalogRetainedSourceQuota {
        logical_bytes: 1 << 30,
        sources: 1_000_000,
        open_reservations: 100,
    };
    store.configure_catalog_retained_source_quota(data).unwrap();
    store
        .configure_catalog_retained_source_guild_quota(data)
        .unwrap();
}

fn resource_policy() -> CatalogResourcePolicy {
    let capacity = policy();
    let plan = capacity.plan().unwrap();
    let (control_rows, control_accounted_bytes) =
        CatalogResourcePolicy::minimum_control_credits(capacity).unwrap();
    let (control_pages, control_journal_bytes) =
        CatalogResourcePolicy::minimum_database_extents(capacity).unwrap();
    CatalogResourcePolicy {
        format_version: 1,
        capacity,
        control_rows,
        control_accounted_bytes,
        control_pages,
        control_journal_bytes,
        immutable_page_bytes: plan.encoded_metadata_page_bytes,
        immutable_pages: plan.metadata_work.page_occurrences,
        open_page_reservations: 16,
    }
}

#[test]
fn resource_contract_reports_complete_dense_one_tib_database_geometry() {
    let mut capacity = policy();
    capacity.data_bytes_per_dataset = 1 << 40;
    capacity.data_sources_per_dataset = (1 << 40) / V1_SECTOR_SIZE as u64;
    capacity.private_work_per_revision = Work {
        bytes: 2 << 30,
        page_occurrences: 40_000,
        records: 5 * mb_core::CATALOG_MAX_RECORDS,
    };
    capacity.source_pages_per_revision = mb_core::CATALOG_MAX_PAGE_OCCURRENCES - 40_000;
    capacity.packed_sectors = 22_422_956;
    capacity.coding_groups = 7_474_319;
    let (rows, bytes) = CatalogResourcePolicy::minimum_control_credits(capacity).unwrap();
    let (pages, journal) = CatalogResourcePolicy::minimum_database_extents(capacity).unwrap();
    println!(
        "complete dense one TiB database credits: rows={rows}, bytes={bytes}, pages={pages}, journal={journal}"
    );
    assert!(rows > capacity.coding_groups * 64);
    assert!(bytes > capacity.plan().unwrap().encoded_metadata_page_bytes);
    assert!(journal > bytes);
    let plan = capacity.plan().unwrap();
    CatalogResourcePolicy {
        format_version: 1,
        capacity,
        control_rows: rows,
        control_accounted_bytes: bytes,
        control_pages: pages,
        control_journal_bytes: journal,
        immutable_page_bytes: plan.encoded_metadata_page_bytes,
        immutable_pages: plan.metadata_work.page_occurrences,
        open_page_reservations: 16,
    }
    .validate()
    .unwrap();
}

fn resource_backing(store: &mut ControlStore, p: CatalogResourcePolicy) {
    store
        .begin_record_quota_adoption(crate::database::DatabaseRecordQuota {
            max_rows: p.control_rows,
            max_accounted_bytes: p.control_accounted_bytes,
        })
        .unwrap();
    while store.record_quota_usage().unwrap().unwrap().state
        == crate::database::DatabaseRecordQuotaState::Adopting
    {
        store.resume_record_quota_adoption().unwrap();
    }
    store
        .configure_page_quota(crate::database::DatabasePageQuota {
            max_pages: p.control_pages,
        })
        .unwrap();
    store
        .configure_journal_quota(crate::database::DatabaseJournalQuota {
            max_bytes: p.control_journal_bytes,
        })
        .unwrap();
    store
        .configure_catalog_storage_quota(CatalogStorageQuota {
            page_bytes: p.immutable_page_bytes,
            pages: p.immutable_pages,
            open_reservations: p.open_page_reservations,
        })
        .unwrap();
}

#[test]
fn resource_contract_requires_all_backing_ledgers_rechecks_existing_writers_and_reopens() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let p = resource_policy();
    p.validate().unwrap();
    assert!(store.configure_catalog_resource_policy(p).is_err());
    assert_eq!(store.catalog_resource_policy().unwrap(), None);
    resource_backing(&mut store, p);
    store.configure_catalog_resource_policy(p).unwrap();
    store.configure_catalog_resource_policy(p).unwrap();
    assert_eq!(store.catalog_resource_policy().unwrap(), Some(p));
    let result: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        store.put_record("resource-prefix", b"rollback", b"new")?;
        store.put_record("catalog-storage-quota-v1", b"store", b"damaged")?;
        store.check_catalog_capacity_policy(policy())
    });
    assert!(result.is_err());
    assert!(
        store
            .get_record("resource-prefix", b"rollback")
            .unwrap()
            .is_none()
    );
    drop(store);
    let store = ControlStore::open(&path, &keys()).unwrap();
    assert_eq!(store.catalog_resource_policy().unwrap(), Some(p));
    store
        .delete_record("catalog-resource-policy-v1", b"store")
        .unwrap();
    store
        .delete_record("catalog-resource-policy-guard-v1", b"store")
        .unwrap();
    assert!(store.catalog_capacity_policy().is_err());
    assert!(store.catalog_resource_policy().is_err());
}

#[test]
fn resource_contract_installation_faults_preserve_original_policy_and_do_not_enroll() {
    for action in ["ABORT", "IGNORE"] {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
        backing(&store);
        store.configure_catalog_capacity_policy(policy()).unwrap();
        let p = resource_policy();
        resource_backing(&mut store, p);
        store.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_resources BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-resource-policy-guard-v1' BEGIN SELECT RAISE({action}{}); END",if action=="ABORT"{",'test'"}else{""})).unwrap();
        assert!(store.configure_catalog_resource_policy(p).is_err());
        assert_eq!(store.catalog_capacity_policy().unwrap(), Some(policy()));
        assert_eq!(store.catalog_resource_policy().unwrap(), None);
        store
            .connection
            .execute_batch("DROP TRIGGER refuse_resources")
            .unwrap();
        store.configure_catalog_resource_policy(p).unwrap();
        let mut changed = p;
        changed.control_rows += 1;
        assert!(store.configure_catalog_resource_policy(changed).is_err());
        assert!(
            store
                .configure_page_quota(crate::database::DatabasePageQuota {
                    max_pages: p.control_pages + 1,
                })
                .is_err()
        );
        assert_eq!(store.catalog_resource_policy().unwrap(), Some(p));
    }
}

#[test]
fn resource_contract_late_private_publication_backing_fault_rolls_back_and_retries() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let (bundle, bootstrap) = fixture(&store, 1, None);
    let p = resource_policy();
    resource_backing(&mut store, p);
    store.configure_catalog_resource_policy(p).unwrap();
    let requests: Vec<_> = bundle
        .roots
        .iter()
        .map(|root| {
            (
                root.intent,
                CatalogPageReservation {
                    page_bytes: root.root.page_occurrences * mb_core::CATALOG_PAGE_BYTES as u64,
                    pages: root.root.page_occurrences,
                },
            )
        })
        .collect();
    store
        .begin_catalog_with_page_reservations(&requests)
        .unwrap();
    let finalized = std::cell::Cell::new(false);
    let failed = store.publish_paged_revision_catalog_with_guards(
        &bundle,
        &bootstrap,
        |_| Ok::<_, CatalogStoreError>(()),
        || {
            finalized.set(true);
            store.put_record("resource-prefix", b"publication", b"new")?;
            store.put_record("catalog-storage-quota-v1", b"store", b"broken")?;
            Ok::<_, CatalogStoreError>(())
        },
        || Ok::<_, CatalogStoreError>(()),
    );
    assert!(failed.is_err());
    assert!(finalized.get());
    assert!(store.paged_revision_catalog(bundle.id).unwrap().is_none());
    assert!(
        store
            .get_record("resource-prefix", b"publication")
            .unwrap()
            .is_none()
    );
    assert_eq!(store.catalog_resource_policy().unwrap(), Some(p));
    publish(&store, &bundle, &bootstrap).unwrap();
    assert!(store.paged_revision_catalog(bundle.id).unwrap().is_some());
}

#[test]
fn capacity_policy_checked_writer_read_preserves_enclosing_rollback_and_guard_faults() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    store.check_catalog_capacity_policy(policy()).unwrap();
    let result: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        store.put_record("policy-writer-prefix", b"rollback", b"new")?;
        store.check_catalog_capacity_policy(policy())?;
        Err(DatabaseError::Conflict.into())
    });
    assert!(matches!(
        result,
        Err(CatalogStoreError::Database(DatabaseError::Conflict))
    ));
    assert!(
        store
            .get_record("policy-writer-prefix", b"rollback")
            .unwrap()
            .is_none()
    );
    let mut wrong = policy();
    wrong.revisions_per_dataset = 2;
    assert!(store.check_catalog_capacity_policy(wrong).is_err());
    let result: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        store.put_record("policy-writer-prefix", b"fault", b"new")?;
        store.put_record(POLICY, KEY, b"broken")?;
        store.check_catalog_capacity_policy(policy())
    });
    assert!(result.is_err());
    assert!(
        store
            .get_record("policy-writer-prefix", b"fault")
            .unwrap()
            .is_none()
    );
    assert_eq!(store.catalog_capacity_policy().unwrap(), Some(policy()));
    store
        .with_record_transaction(|| -> Result<(), CatalogStoreError> {
            store.put_record("policy-writer-prefix", b"committed", b"new")?;
            store.check_catalog_capacity_policy(policy())
        })
        .unwrap();
    assert_eq!(
        store
            .get_record("policy-writer-prefix", b"committed")
            .unwrap(),
        Some(b"new".to_vec())
    );
}

#[test]
fn capacity_policy_charges_shared_revision_occurrences_and_preserves_reopen_and_cancellation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open(&path, &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let (first, bytes) = fixture(&store, 1, None);
    publish(&store, &first, &bytes).unwrap();
    let (second, next) = fixture(&store, 2, Some([7; 32]));
    assert_eq!(
        first.roots.iter().map(|r| r.root).collect::<Vec<_>>(),
        second.roots.iter().map(|r| r.root).collect::<Vec<_>>()
    );
    assert!(
        store
            .check_catalog_published_revision_capacity(&second)
            .is_err()
    );
    assert!(
        store
            .publish_paged_revision_catalog_checked(
                &second,
                &next,
                |_| -> Result<(), CatalogStoreError> {
                    panic!("enclosing revision exhaustion reached callback")
                }
            )
            .is_err()
    );
    assert!(store.catalog_bundle(second.id).unwrap().is_none());
    let original = store.paged_revision_catalog(first.id).unwrap().unwrap();
    drop(store);
    let store = ControlStore::open(&path, &keys()).unwrap();
    assert_eq!(store.catalog_capacity_policy().unwrap(), Some(policy()));
    assert_eq!(
        store.paged_revision_catalog(first.id).unwrap().unwrap(),
        original
    );
    store.cancel_paged_revision_catalog(first.id).unwrap();
    publish(&store, &second, &next).unwrap();
    assert!(
        store
            .paged_revision_catalog(second.id)
            .unwrap()
            .unwrap()
            .bootstrap
            .is_some()
    );
}

#[test]
fn capacity_policy_limits_data_and_guild_reservations_even_with_larger_backing_quotas() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let (bundle, _) = fixture(&store, 1, None);
    let id = Uuid::new_v4();
    {
        let tx =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        assert!(
            store
                .reserve_catalog_retained_sources_in_transaction(
                    id,
                    bundle.scope,
                    CatalogRetainedSourceReservation {
                        logical_bytes: 2,
                        sources: 1
                    }
                )
                .is_err()
        );
        tx.rollback().unwrap();
    }
    assert_eq!(
        store
            .catalog_retained_source_usage(bundle.scope)
            .unwrap()
            .unwrap()
            .reserved_logical_bytes,
        0
    );
    {
        let tx =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        store
            .reserve_catalog_retained_sources_in_transaction(
                id,
                bundle.scope,
                CatalogRetainedSourceReservation {
                    logical_bytes: 1,
                    sources: 1,
                },
            )
            .unwrap();
        tx.commit().unwrap();
    }
    let CatalogScope::Dataset {
        guild_id, owner, ..
    } = bundle.scope
    else {
        unreachable!()
    };
    let other = CatalogScope::Dataset {
        guild_id,
        owner,
        protected_root_id: Uuid::new_v4(),
    };
    {
        let tx =
            Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
        assert!(
            store
                .reserve_catalog_retained_sources_in_transaction(
                    Uuid::new_v4(),
                    other,
                    CatalogRetainedSourceReservation {
                        logical_bytes: 1,
                        sources: 1
                    }
                )
                .is_err()
        );
        tx.rollback().unwrap();
    }
    assert_eq!(
        store
            .catalog_retained_source_guild_usage(guild_id)
            .unwrap()
            .unwrap()
            .reserved_logical_bytes,
        1
    );
}

#[test]
fn capacity_policy_refused_installation_preserves_existing_published_owners_and_backing_ledgers() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    assert!(store.configure_catalog_capacity_policy(policy()).is_err());
    assert!(store.catalog_capacity_policy().unwrap().is_none());
    backing(&store);
    let (bundle, bytes) = fixture(&store, 1, None);
    publish(&store, &bundle, &bytes).unwrap();
    let before = store.paged_revision_catalog(bundle.id).unwrap();
    assert!(store.configure_catalog_capacity_policy(policy()).is_err());
    assert!(store.catalog_capacity_policy().unwrap().is_none());
    assert_eq!(store.paged_revision_catalog(bundle.id).unwrap(), before);
}

#[test]
fn capacity_policy_pair_faults_and_late_replacement_roll_back_publication() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.connection.execute_batch("CREATE TEMP TRIGGER ignore_capacity_guard BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-capacity-policy-guard-v1' BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(store.configure_catalog_capacity_policy(policy()).is_err());
    assert!(store.catalog_capacity_policy().unwrap().is_none());
    store
        .connection
        .execute_batch("DROP TRIGGER ignore_capacity_guard")
        .unwrap();
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    let mut next = policy();
    next.coding_groups += 1;
    let encoded = hex::encode(mb_core::canonical_bytes_bounded(&next, ROW_BYTES).unwrap());
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER replace_capacity AFTER INSERT ON protocol_records WHEN NEW.kind='catalog-paged-publication-v1' BEGIN UPDATE protocol_records SET bytes=x'{encoded}' WHERE kind IN ('catalog-capacity-policy-v1','catalog-capacity-policy-guard-v1'); END")).unwrap();
    assert!(publish(&store, &bundle, &bytes).is_err());
    assert_eq!(store.catalog_capacity_policy().unwrap(), Some(policy()));
    assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
    assert_eq!(
        store
            .catalog_published_revision_quota_usage(CatalogPublishedRevisionQuotaScope::Global)
            .unwrap()
            .unwrap()
            .used
            .revisions,
        0
    );
    store
        .connection
        .execute_batch("DROP TRIGGER replace_capacity")
        .unwrap();
    publish(&store, &bundle, &bytes).unwrap();
    assert!(store.configure_catalog_capacity_policy(next).is_err());
}

#[test]
fn capacity_policy_corruption_refuses_before_publication_callback_and_preserves_pages() {
    for damage in ["missing", "changed", "oversized", "all"] {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
        backing(&store);
        store.configure_catalog_capacity_policy(policy()).unwrap();
        let (bundle, bytes) = fixture(&store, 1, None);
        let original = store
            .catalog_page(
                bundle.scope,
                bundle.roots[0].intent.section,
                bundle.roots[0].root,
            )
            .unwrap();
        let sql = match damage {
            "all" => {
                "DELETE FROM protocol_records WHERE kind IN ('catalog-capacity-policy-v1','catalog-capacity-policy-guard-v1','catalog-capacity-policy-enabled-v1')"
            }
            "missing" => {
                "DELETE FROM protocol_records WHERE kind='catalog-capacity-policy-guard-v1'"
            }
            "changed" => {
                "UPDATE protocol_records SET bytes=x'01' WHERE kind='catalog-capacity-policy-guard-v1'"
            }
            _ => {
                "UPDATE protocol_records SET bytes=zeroblob(65536) WHERE kind='catalog-capacity-policy-v1'"
            }
        };
        store.connection.execute_batch(sql).unwrap();
        assert!(store.catalog_capacity_policy().is_err());
        assert!(
            store
                .publish_paged_revision_catalog_checked(
                    &bundle,
                    &bytes,
                    |_| -> Result<(), CatalogStoreError> {
                        panic!("damaged contract reached publication callback")
                    }
                )
                .is_err()
        );
        assert!(
            store
                .get_record(PUBLICATION_KIND, bundle.id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .catalog_page(
                    bundle.scope,
                    bundle.roots[0].intent.section,
                    bundle.roots[0].root
                )
                .unwrap(),
            original
        );
    }
}

#[test]
fn capacity_policy_checks_private_dimensions_before_any_publication_callback() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let (bundle, bytes) = fixture(&store, 1, None);
    let mut changed = bundle.clone();
    changed.roots[0].root.byte_len += 5;
    assert!(
        store
            .check_catalog_published_revision_capacity(&changed)
            .is_err()
    );
    let mut changed = bundle.clone();
    changed.roots[0].root.height = 1;
    changed.roots[0].root.page_occurrences = 2;
    assert!(
        store
            .check_catalog_published_revision_capacity(&changed)
            .is_err()
    );
    publish(&store, &bundle, &bytes).unwrap();
}
const PUBLICATION_KIND: &str = "catalog-paged-publication-v1";

#[test]
fn capacity_policy_late_reservation_replacement_rolls_back_all_credits() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let (bundle, _) = fixture(&store, 1, None);
    let mut next = policy();
    next.data_bytes_per_dataset = 2;
    next.data_sources_per_dataset = 2;
    next.packed_sectors = 7;
    next.coding_groups = 3;
    let encoded = hex::encode(mb_core::canonical_bytes_bounded(&next, ROW_BYTES).unwrap());
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER replace_reservation_capacity AFTER INSERT ON protocol_records WHEN NEW.kind='catalog-retained-source-reservation-v1' BEGIN UPDATE protocol_records SET bytes=x'{encoded}' WHERE kind IN ('catalog-capacity-policy-v1','catalog-capacity-policy-guard-v1'); END")).unwrap();
    let id = Uuid::new_v4();
    let tx = Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
    assert!(
        store
            .reserve_catalog_retained_sources_in_transaction(
                id,
                bundle.scope,
                CatalogRetainedSourceReservation {
                    logical_bytes: 1,
                    sources: 1
                }
            )
            .is_err()
    );
    tx.rollback().unwrap();
    assert_eq!(store.catalog_capacity_policy().unwrap(), Some(policy()));
    assert_eq!(
        store
            .catalog_retained_source_usage(bundle.scope)
            .unwrap()
            .unwrap()
            .reserved_logical_bytes,
        0
    );
    assert!(
        store
            .get_record("catalog-retained-source-reservation-v1", id.as_bytes())
            .unwrap()
            .is_none()
    );
}

#[test]
fn capacity_policy_refuses_declared_geometry_without_sufficient_backing_limits() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    let mut large = policy();
    large.data_bytes_per_dataset = 1 << 40;
    large.data_sources_per_dataset = (1 << 40) / V1_SECTOR_SIZE as u64;
    large.private_work_per_revision = Work {
        bytes: 2 << 30,
        page_occurrences: 40_000,
        records: 5 * mb_core::CATALOG_MAX_RECORDS,
    };
    large.source_pages_per_revision = mb_core::CATALOG_MAX_PAGE_OCCURRENCES - 40_000;
    large.packed_sectors = 22_422_956;
    large.coding_groups = 7_474_319;
    assert!(large.plan().is_ok());
    assert!(store.configure_catalog_capacity_policy(large).is_err());
    assert!(store.catalog_capacity_policy().unwrap().is_none());
    assert_eq!(
        store
            .catalog_published_revision_quota_usage(CatalogPublishedRevisionQuotaScope::Global)
            .unwrap()
            .unwrap()
            .used
            .revisions,
        0
    );
    store.configure_catalog_capacity_policy(policy()).unwrap();
}

#[test]
fn capacity_policy_reads_inside_writer_keep_backing_checks_and_outer_rollback() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    let abort: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        assert_eq!(store.catalog_capacity_policy()?, None);
        store.put_record("probe", b"writer", b"rollback")?;
        Err(DatabaseError::Conflict.into())
    });
    assert!(abort.is_err());
    assert!(store.get_record("probe", b"writer").unwrap().is_none());
    backing(&store);
    let policy = policy();
    store.configure_catalog_capacity_policy(policy).unwrap();
    let abort: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        assert_eq!(store.catalog_capacity_policy()?, Some(policy));
        store.put_record("probe", b"writer", b"rollback")?;
        Err(DatabaseError::Conflict.into())
    });
    assert!(abort.is_err());
    assert!(store.get_record("probe", b"writer").unwrap().is_none());
    store
        .database_shell_statement(
            "DELETE FROM protocol_records WHERE kind='catalog-capacity-policy-guard-v1'",
            false,
        )
        .unwrap();
    let refusal: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        store.catalog_capacity_policy()?;
        Ok(())
    });
    assert!(refusal.is_err());
}
