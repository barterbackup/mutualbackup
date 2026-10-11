use mb_core::{CatalogBuilder, NodeId};

use super::*;

fn dataset(owner: u8, guild: u8) -> CatalogScope {
    CatalogScope::Dataset {
        guild_id: [guild; 32],
        owner: NodeId([owner; 32]),
        protected_root_id: Uuid::from_u128(u128::from(owner)),
    }
}

fn intent(id: u128, scope: CatalogScope, section: CatalogSection) -> CatalogIntent {
    CatalogIntent {
        id: Uuid::from_u128(id),
        scope,
        section,
    }
}

fn wide() -> CatalogStorageQuota {
    CatalogStorageQuota {
        page_bytes: 1024 * 1024,
        pages: 64,
        open_reservations: 16,
    }
}

fn page(intent: CatalogIntent, value: &[u8]) -> (CatalogPageRef, Vec<u8>) {
    let mut result = None;
    let mut sink = |reference, bytes| {
        result = Some((reference, bytes));
        Ok::<_, ()>(())
    };
    let mut builder = CatalogBuilder::new(intent.scope, intent.section).unwrap();
    builder.push(value, &mut sink).unwrap();
    let root = builder.finish(&mut sink).unwrap();
    let result = result.unwrap();
    assert_eq!(root, result.0);
    result
}

fn capacity(bytes: &[u8]) -> CatalogPageReservation {
    CatalogPageReservation {
        page_bytes: bytes.len() as u64,
        pages: 1,
    }
}

fn records(store: &ControlStore) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    let mut statement = store
        .connection
        .prepare("SELECT kind, record_id, bytes FROM protocol_records ORDER BY kind, record_id")
        .unwrap();
    statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn publish(
    store: &ControlStore,
    intent: CatalogIntent,
    page: &(CatalogPageRef, Vec<u8>),
    credit: CatalogPageReservation,
) {
    store
        .begin_catalog_with_page_reservation(intent, credit)
        .unwrap();
    store.stage_catalog_page(intent, page.0, &page.1).unwrap();
    store.publish_catalog(intent, page.0).unwrap();
}

fn retire(store: &ControlStore, intent: CatalogIntent) {
    store.cancel_catalog(intent).unwrap();
    while store.release_catalog_pin(intent).unwrap() {}
}

#[test]
fn scoped_page_reservations_enforce_dataset_guild_and_global_limits_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[71; 32]).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    let quota = CatalogStorageQuota {
        page_bytes: 100,
        pages: 2,
        open_reservations: 1,
    };
    let guild = CatalogStorageQuota {
        page_bytes: 150,
        pages: 2,
        open_reservations: 2,
    };
    store
        .configure_catalog_scoped_storage_quotas(quota, guild)
        .unwrap();
    let first = intent(1, dataset(1, 61), CatalogSection::FileMetadata);
    let second = intent(2, dataset(2, 61), CatalogSection::GitGraph);
    let other = intent(3, dataset(3, 62), CatalogSection::SectorReferences);
    let loan = CatalogPageReservation {
        page_bytes: 100,
        pages: 1,
    };
    store
        .begin_catalog_with_page_reservation(first, loan)
        .unwrap();
    let saved = records(&store);
    for (candidate, credit) in [
        (
            intent(4, first.scope, first.section),
            CatalogPageReservation::default(),
        ),
        (second, loan),
        (
            second,
            CatalogPageReservation {
                page_bytes: 49,
                pages: 2,
            },
        ),
        (
            first,
            CatalogPageReservation {
                page_bytes: 99,
                ..loan
            },
        ),
    ] {
        assert!(
            store
                .begin_catalog_with_page_reservation(candidate, credit)
                .is_err()
        );
        assert_eq!(records(&store), saved);
    }
    store
        .begin_catalog_with_page_reservation(first, loan)
        .unwrap();
    assert_eq!(records(&store), saved);
    store
        .begin_catalog_with_page_reservation(other, loan)
        .unwrap();
    assert_eq!(
        store
            .catalog_guild_storage_usage([61; 32])
            .unwrap()
            .unwrap()
            .reserved_page_bytes,
        100
    );
    assert_eq!(
        store
            .catalog_guild_storage_usage([62; 32])
            .unwrap()
            .unwrap()
            .reserved_page_bytes,
        100
    );
    store.cancel_catalog(first).unwrap();
    store
        .begin_catalog_with_page_reservation(second, loan)
        .unwrap();
    assert_eq!(
        store
            .catalog_dataset_storage_usage(first.scope)
            .unwrap()
            .unwrap()
            .open_reservations,
        0
    );
    let saved = records(&store);
    for (dataset_quota, guild_quota) in [
        (
            CatalogStorageQuota {
                page_bytes: 99,
                ..quota
            },
            guild,
        ),
        (quota, CatalogStorageQuota { pages: 1, ..guild }),
    ] {
        assert!(
            store
                .configure_catalog_scoped_storage_quotas(dataset_quota, guild_quota)
                .is_err()
        );
        assert_eq!(records(&store), saved);
    }
    store
        .configure_catalog_scoped_storage_quotas(wide(), wide())
        .unwrap();
    assert_eq!(
        store
            .catalog_dataset_storage_usage(second.scope)
            .unwrap()
            .unwrap()
            .reserved_page_bytes,
        100
    );
    assert!(
        store
            .catalog_dataset_storage_usage(guild_scope(first.scope))
            .is_err()
    );
}

#[test]
fn concurrent_datasets_cannot_overbook_their_shared_guild_page_credits() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[72; 32]).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    let quota = CatalogStorageQuota {
        page_bytes: 1024,
        pages: 1,
        open_reservations: 2,
    };
    store
        .configure_catalog_scoped_storage_quotas(quota, quota)
        .unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let connections = [
        ControlStore::open_with_key(&path, &[72; 32]).unwrap(),
        ControlStore::open_with_key(&path, &[72; 32]).unwrap(),
    ];
    let workers = connections
        .into_iter()
        .enumerate()
        .map(|(index, store)| {
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .begin_catalog_with_page_reservation(
                        intent(
                            index as u128 + 1,
                            dataset(index as u8 + 1, 63),
                            CatalogSection::FileMetadata,
                        ),
                        CatalogPageReservation {
                            page_bytes: 1024,
                            pages: 1,
                        },
                    )
                    .is_ok()
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|success| *success)
            .count(),
        1
    );
    let usage = store
        .catalog_guild_storage_usage([63; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            usage.reserved_page_bytes,
            usage.reserved_pages,
            usage.open_reservations
        ),
        (1024, 1, 1)
    );
}

#[test]
fn private_and_public_pages_share_guild_admission_and_remain_charged_until_final_gc() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[73; 32]).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    let native = intent(1, dataset(1, 64), CatalogSection::FileMetadata);
    let shared = intent(2, native.scope, native.section);
    let git = intent(3, native.scope, CatalogSection::GitGraph);
    let public = intent(4, guild_scope(native.scope), CatalogSection::Coding);
    let native_page = page(native, b"native private metadata");
    let git_page = page(git, b"Git private metadata");
    let public_page = page(public, b"public coding metadata");
    let private_bytes = (native_page.1.len() + git_page.1.len()) as u64;
    let all_bytes = private_bytes + public_page.1.len() as u64;
    let dataset_quota = CatalogStorageQuota {
        page_bytes: private_bytes,
        pages: 2,
        open_reservations: 4,
    };
    let guild_quota = CatalogStorageQuota {
        page_bytes: all_bytes,
        pages: 3,
        open_reservations: 4,
    };
    store
        .configure_catalog_scoped_storage_quotas(dataset_quota, guild_quota)
        .unwrap();
    publish(&store, native, &native_page, capacity(&native_page.1));
    publish(
        &store,
        shared,
        &native_page,
        CatalogPageReservation::default(),
    );
    publish(&store, git, &git_page, capacity(&git_page.1));
    publish(&store, public, &public_page, capacity(&public_page.1));
    let dataset = store
        .catalog_dataset_storage_usage(native.scope)
        .unwrap()
        .unwrap();
    let guild = store
        .catalog_guild_storage_usage([64; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (dataset.stored_page_bytes, dataset.stored_pages),
        (private_bytes, 2)
    );
    assert_eq!(
        (
            guild.stored_page_bytes,
            guild.stored_pages,
            guild.open_reservations
        ),
        (all_bytes, 3, 0)
    );
    retire(&store, native);
    while store.collect_catalog_page().unwrap() {}
    assert_eq!(
        store.catalog_guild_storage_usage([64; 32]).unwrap(),
        Some(guild)
    );
    drop(store);
    let store = ControlStore::open_with_key(&path, &[73; 32]).unwrap();
    assert_eq!(
        store.catalog_guild_storage_usage([64; 32]).unwrap(),
        Some(guild)
    );
    let reader = ControlStore::open_existing_read_only_with_key(&path, &[73; 32]).unwrap();
    let original = records(&store);
    assert_eq!(
        reader.catalog_dataset_storage_usage(native.scope).unwrap(),
        Some(dataset)
    );
    assert_eq!(
        reader.catalog_guild_storage_usage([64; 32]).unwrap(),
        Some(guild)
    );
    assert!(
        reader
            .configure_catalog_scoped_storage_quotas(wide(), wide())
            .is_err()
    );
    assert_eq!(records(&store), original);
    drop(reader);
    for owner in [shared, git, public] {
        retire(&store, owner);
    }
    while store.collect_catalog_page().unwrap() {}
    let guild = store
        .catalog_guild_storage_usage([64; 32])
        .unwrap()
        .unwrap();
    assert_eq!(
        (
            guild.stored_page_bytes,
            guild.stored_pages,
            guild.open_reservations
        ),
        (0, 0, 0)
    );
    assert!(store.records(PAGE_CHARGE).unwrap().is_empty());
}

#[test]
fn initial_scoped_adoption_preserves_shared_cancelled_pages_and_pending_global_loans() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[74; 32]).unwrap();
    let old = intent(1, dataset(1, 65), CatalogSection::FileMetadata);
    let shared = intent(2, old.scope, old.section);
    let pending = intent(3, dataset(2, 65), CatalogSection::SectorReferences);
    let old_page = page(old, b"existing shared private page");
    for owner in [old, shared] {
        store.begin_catalog(owner).unwrap();
        store
            .stage_catalog_page(owner, old_page.0, &old_page.1)
            .unwrap();
        store.publish_catalog(owner, old_page.0).unwrap();
    }
    store.cancel_catalog(old).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    let pending_page = page(pending, b"pending public source page");
    let credits = CatalogPageReservation {
        page_bytes: pending_page.1.len() as u64 + 100,
        pages: 2,
    };
    store
        .begin_catalog_with_page_reservation(pending, credits)
        .unwrap();
    store
        .stage_catalog_page(pending, pending_page.0, &pending_page.1)
        .unwrap();
    let global = store.catalog_storage_usage().unwrap().unwrap();
    let guild_quota = CatalogStorageQuota {
        page_bytes: global.stored_page_bytes + global.reserved_page_bytes,
        pages: global.stored_pages + global.reserved_pages,
        open_reservations: 1,
    };
    let original = records(&store);
    assert!(
        store
            .configure_catalog_scoped_storage_quotas(
                wide(),
                CatalogStorageQuota {
                    page_bytes: guild_quota.page_bytes - 1,
                    ..guild_quota
                }
            )
            .is_err()
    );
    assert_eq!(records(&store), original);
    store
        .configure_catalog_scoped_storage_quotas(wide(), guild_quota)
        .unwrap();
    let guild = store
        .catalog_guild_storage_usage([65; 32])
        .unwrap()
        .unwrap();
    assert_eq!(Counts::from_usage(guild), Counts::from_usage(global));
    for (kind, key, bytes) in original {
        assert_eq!(store.get_record(&kind, &key).unwrap(), Some(bytes));
    }
    store.begin_catalog(shared).unwrap();
    store
        .begin_catalog_with_page_reservation(pending, credits)
        .unwrap();
    store.publish_catalog(pending, pending_page.0).unwrap();
    assert_eq!(
        store
            .catalog_guild_storage_usage([65; 32])
            .unwrap()
            .unwrap()
            .reserved_page_bytes,
        0
    );
    for owner in [old, shared, pending] {
        retire(&store, owner);
    }
    while store.collect_catalog_page().unwrap() {}
    assert_eq!(
        store
            .catalog_guild_storage_usage([65; 32])
            .unwrap()
            .unwrap()
            .stored_pages,
        0
    );
}

#[test]
fn scoped_reservation_staging_publication_and_gc_sql_faults_roll_back_all_counters() {
    for operation in ["IGNORE", "ABORT, 'fault'"] {
        for kind in [SCOPE, USAGE, LOAN, "catalog-page-quota-member-v1/*"] {
            let temp = tempfile::tempdir().unwrap();
            let store =
                ControlStore::open_with_key(temp.path().join("control.db"), &[75; 32]).unwrap();
            store.configure_catalog_storage_quota(wide()).unwrap();
            store
                .configure_catalog_scoped_storage_quotas(wide(), wide())
                .unwrap();
            store.connection.execute_batch(&format!(
                "CREATE TEMP TRIGGER scoped_fault BEFORE INSERT ON protocol_records WHEN NEW.kind GLOB '{kind}' BEGIN SELECT RAISE({operation}); END"
            )).unwrap();
            let original = records(&store);
            assert!(
                store
                    .begin_catalog_with_page_reservation(
                        intent(1, dataset(1, 66), CatalogSection::FileMetadata),
                        CatalogPageReservation {
                            page_bytes: 1024,
                            pages: 1
                        },
                    )
                    .is_err()
            );
            assert_eq!(records(&store), original);
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[75; 32]).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    store
        .configure_catalog_scoped_storage_quotas(wide(), wide())
        .unwrap();
    let owner = intent(1, dataset(1, 66), CatalogSection::GitGraph);
    let value = page(owner, b"verified private page");
    store
        .begin_catalog_with_page_reservation(owner, capacity(&value.1))
        .unwrap();
    for (event, kind) in [("UPDATE", USAGE), ("INSERT", PAGE_CHARGE), ("INSERT", META)] {
        let original = records(&store);
        store.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER scoped_fault BEFORE {event} ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END"
        )).unwrap();
        assert!(store.stage_catalog_page(owner, value.0, &value.1).is_err());
        assert_eq!(records(&store), original);
        store
            .connection
            .execute_batch("DROP TRIGGER scoped_fault")
            .unwrap();
    }
    store.stage_catalog_page(owner, value.0, &value.1).unwrap();
    let original = records(&store);
    store.connection.execute_batch(&format!(
        "CREATE TEMP TRIGGER scoped_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind = '{USAGE}' BEGIN SELECT RAISE(IGNORE); END"
    )).unwrap();
    assert!(store.publish_catalog(owner, value.0).is_err());
    assert_eq!(records(&store), original);
    store
        .connection
        .execute_batch("DROP TRIGGER scoped_fault")
        .unwrap();
    store.publish_catalog(owner, value.0).unwrap();
    retire(&store, owner);
    for kind in [PAGE_CHARGE, META, "catalog-page-quota-member-v1/*"] {
        let original = records(&store);
        store.connection.execute_batch(&format!(
            "CREATE TEMP TRIGGER scoped_fault BEFORE DELETE ON protocol_records WHEN OLD.kind GLOB '{kind}' BEGIN SELECT RAISE(IGNORE); END"
        )).unwrap();
        assert!(store.collect_catalog_page().is_err());
        assert_eq!(records(&store), original);
        store
            .connection
            .execute_batch("DROP TRIGGER scoped_fault")
            .unwrap();
    }
    while store.collect_catalog_page().unwrap() {}
    assert_eq!(
        store
            .catalog_guild_storage_usage([66; 32])
            .unwrap()
            .unwrap()
            .stored_pages,
        0
    );
}

#[test]
fn missing_scoped_policies_ledgers_charges_and_members_cannot_reset_page_admission() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[76; 32]).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    store
        .configure_catalog_scoped_storage_quotas(wide(), wide())
        .unwrap();
    let owner = intent(1, dataset(1, 67), CatalogSection::FileMetadata);
    let value = page(owner, b"retained private page");
    store
        .begin_catalog_with_page_reservation(owner, capacity(&value.1))
        .unwrap();
    store.stage_catalog_page(owner, value.0, &value.1).unwrap();
    let key = scope_key(owner.scope).unwrap();
    let members = members(owner.scope).unwrap();
    for (kind, key) in [
        (POLICY, KEY.to_vec()),
        (ENABLED, KEY.to_vec()),
        (USAGE, key.to_vec()),
        (SCOPE, key.to_vec()),
        (PAGE_CHARGE, value.0.hash.to_vec()),
        (LOAN, owner.id.as_bytes().to_vec()),
        (RESERVATION, owner.id.as_bytes().to_vec()),
        (members.as_str(), member_key(1, owner.id.as_bytes())),
    ] {
        let bytes = store.get_record(kind, &key).unwrap().unwrap();
        store.delete_record(kind, &key).unwrap();
        let original = records(&store);
        assert!(
            store.stage_catalog_page(owner, value.0, &value.1).is_err(),
            "{kind}"
        );
        assert_eq!(records(&store), original);
        if kind == RESERVATION {
            assert!(
                store
                    .begin_catalog_with_page_reservation(owner, capacity(&value.1))
                    .is_err()
            );
            assert_eq!(records(&store), original);
        }
        store.put_record(kind, &key, &bytes).unwrap();
        // Membership markers deliberately have an empty body; any nonempty
        // replacement is invalid. The other records require nonempty bodies.
        let malformed = if kind == members { vec![0] } else { Vec::new() };
        for invalid in [malformed, vec![0; RECORD_BYTES + 1]] {
            store.put_record(kind, &key, &invalid).unwrap();
            let original = records(&store);
            assert!(
                store.stage_catalog_page(owner, value.0, &value.1).is_err(),
                "{kind}"
            );
            assert_eq!(records(&store), original);
            store.put_record(kind, &key, &bytes).unwrap();
        }
    }
    for kinds in [
        [POLICY, ENABLED],
        [USAGE, SCOPE],
        [super::super::QUOTA, super::super::ENABLED],
    ] {
        let key = if kinds[0] == USAGE {
            key.as_slice()
        } else {
            KEY
        };
        let saved = kinds.map(|kind| store.get_record(kind, key).unwrap().unwrap());
        for kind in kinds {
            store.delete_record(kind, key).unwrap();
        }
        let original = records(&store);
        assert!(
            store
                .begin_catalog_with_page_reservation(
                    intent(2, owner.scope, owner.section),
                    CatalogPageReservation::default()
                )
                .is_err()
        );
        assert_eq!(records(&store), original);
        for (kind, bytes) in kinds.into_iter().zip(saved) {
            store.put_record(kind, key, &bytes).unwrap();
        }
    }
    store.publish_catalog(owner, value.0).unwrap();
}

#[test]
fn scoped_loan_identity_and_aggregate_debt_substitutions_reject_before_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[78; 32]).unwrap();
    store.configure_catalog_storage_quota(wide()).unwrap();
    store
        .configure_catalog_scoped_storage_quotas(wide(), wide())
        .unwrap();
    let owner = intent(1, dataset(1, 69), CatalogSection::FileMetadata);
    let value = page(owner, b"authentic private metadata");
    let planned = capacity(&value.1);
    store
        .begin_catalog_with_page_reservation(owner, planned)
        .unwrap();
    let original_loan = store
        .get_record(RESERVATION, owner.id.as_bytes())
        .unwrap()
        .unwrap();
    let mut loan: Reservation = decode(&original_loan).unwrap();
    loan.original.page_bytes += 1;
    store
        .put_record(
            RESERVATION,
            owner.id.as_bytes(),
            &canonical_bytes(&loan).unwrap(),
        )
        .unwrap();
    let original = records(&store);
    assert!(
        store
            .begin_catalog_with_page_reservation(owner, loan.original)
            .is_err()
    );
    assert!(store.stage_catalog_page(owner, value.0, &value.1).is_err());
    assert_eq!(records(&store), original);
    store
        .put_record(RESERVATION, owner.id.as_bytes(), &original_loan)
        .unwrap();
    for scope in [owner.scope, guild_scope(owner.scope)] {
        let key = scope_key(scope).unwrap();
        let bytes = store.get_record(USAGE, &key).unwrap().unwrap();
        let mut changed: Usage = decode(&bytes).unwrap();
        changed.counts.reserved_page_bytes -= 1;
        store
            .put_record(USAGE, &key, &canonical_bytes(&changed).unwrap())
            .unwrap();
        let original = records(&store);
        assert!(store.stage_catalog_page(owner, value.0, &value.1).is_err());
        assert_eq!(records(&store), original);
        store.put_record(USAGE, &key, &bytes).unwrap();
    }
    store.stage_catalog_page(owner, value.0, &value.1).unwrap();
    store.publish_catalog(owner, value.0).unwrap();
}

#[test]
fn scoped_adoption_authenticates_bounds_metadata_pages_and_original_global_totals() {
    for fault in 0..10 {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[77; 32]).unwrap();
        let owner = intent(1, dataset(1, 68), CatalogSection::FileMetadata);
        let value = page(owner, b"original metadata");
        store.begin_catalog(owner).unwrap();
        store.stage_catalog_page(owner, value.0, &value.1).unwrap();
        store.publish_catalog(owner, value.0).unwrap();
        store.configure_catalog_storage_quota(wide()).unwrap();
        match fault {
            0 => {
                store
                    .put_record(PAGE, &value.0.hash, &vec![0; CATALOG_PAGE_BYTES + 1])
                    .unwrap();
            }
            1 => {
                let mut bytes = value.1.clone();
                bytes[0] ^= 1;
                store.put_record(PAGE, &value.0.hash, &bytes).unwrap();
            }
            2 => {
                store.delete_record(META, &value.0.hash).unwrap();
            }
            3 => {
                let mut meta = metadata(&store.connection, value.0.hash).unwrap();
                meta.scope = dataset(2, 68);
                store
                    .put_record(META, &value.0.hash, &canonical_bytes(&meta).unwrap())
                    .unwrap();
            }
            4 => {
                let meta = store.get_record(META, &value.0.hash).unwrap().unwrap();
                store.put_record(META, &[0; 32], &meta).unwrap();
            }
            5 => {
                let mut ledger = ledger(&store.connection).unwrap().unwrap();
                ledger.usage.stored_page_bytes += 1;
                store
                    .put_record(super::super::QUOTA, KEY, &canonical_bytes(&ledger).unwrap())
                    .unwrap();
            }
            6 => {
                store.put_record(PAGE, &[0; 33], b"unbounded key").unwrap();
            }
            7 => {
                let loan = Reservation {
                    version: 1,
                    intent: owner,
                    original: CatalogPageReservation::default(),
                    remaining: CatalogPageReservation::default(),
                    closed: false,
                };
                store
                    .put_record(
                        RESERVATION,
                        owner.id.as_bytes(),
                        &canonical_bytes(&loan).unwrap(),
                    )
                    .unwrap();
            }
            8 => {
                store
                    .put_record(RESERVATION, &[0; 17], b"unbounded loan key")
                    .unwrap();
            }
            9 => {
                store
                    .put_record(RESERVATION, owner.id.as_bytes(), &vec![0; RECORD_BYTES + 1])
                    .unwrap();
            }
            _ => unreachable!(),
        }
        let original = records(&store);
        assert!(
            store
                .configure_catalog_scoped_storage_quotas(wide(), wide())
                .is_err(),
            "fault {fault}"
        );
        assert_eq!(records(&store), original);
        assert!(store.records(POLICY).unwrap().is_empty());
    }
}
