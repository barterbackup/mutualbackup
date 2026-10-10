use super::*;
use mb_core::{NodeId, SectorRef, merkle_commit, sector_root};
use std::sync::{Arc, Barrier};

fn scope(guild: u8, dataset: u8) -> CatalogScope {
    CatalogScope::Dataset {
        guild_id: [guild; 32],
        owner: NodeId([dataset; 32]),
        protected_root_id: Uuid::from_bytes([dataset; 16]),
    }
}

fn quota(bytes: u64, sources: u64, jobs: u32) -> CatalogRetainedSourceQuota {
    CatalogRetainedSourceQuota {
        logical_bytes: bytes,
        sources,
        open_reservations: jobs,
    }
}

fn id(marker: u8) -> Uuid {
    Uuid::from_bytes([marker; 16])
}

fn reserve(
    store: &ControlStore,
    marker: u8,
    scope: CatalogScope,
    bytes: u64,
    sources: u64,
) -> Result<(), CatalogStoreError> {
    store.with_record_transaction(|| {
        store.reserve_catalog_retained_sources_in_transaction(
            id(marker),
            scope,
            CatalogRetainedSourceReservation {
                logical_bytes: bytes,
                sources,
            },
        )
    })
}

fn source(marker: u8) -> CatalogSectorRecord {
    let bytes = vec![marker; V1_SECTOR_SIZE];
    CatalogSectorRecord {
        format_version: 1,
        sector: SectorRef {
            id: [marker; 32],
            root: sector_root(&bytes),
            logical_len: 100,
        },
        commitment: merkle_commit(&bytes).unwrap(),
    }
}

fn publish(
    store: &ControlStore,
    marker: u8,
    scope: CatalogScope,
    source: &CatalogSectorRecord,
) -> Result<(), CatalogStoreError> {
    store.with_record_transaction(|| {
        bind(&store.connection, id(marker), scope, source)?;
        close(&store.connection, id(marker), scope, false)
    })
}

fn state(store: &ControlStore) -> Vec<(String, Vec<u8>, Vec<u8>)> {
    store
        .connection
        .prepare("SELECT kind, record_id, bytes FROM protocol_records ORDER BY kind, record_id")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn usage(store: &ControlStore, guild: u8) -> CatalogRetainedSourceUsage {
    store
        .catalog_retained_source_guild_usage([guild; 32])
        .unwrap()
        .unwrap()
}

#[test]
fn guild_source_admission_is_atomic_across_datasets_owners_connections_and_dimensions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[98; 32]).unwrap();
    assert!(
        store
            .configure_catalog_retained_source_guild_quota(quota(100, 1, 1))
            .is_err()
    );
    store
        .configure_catalog_retained_source_quota(quota(400, 4, 4))
        .unwrap();
    store
        .configure_catalog_retained_source_guild_quota(quota(100, 1, 1))
        .unwrap();
    let empty = usage(&store, 1);
    let gate = Arc::new(Barrier::new(3));
    let threads = [3, 4].map(|marker| {
        let path = path.clone();
        let gate = Arc::clone(&gate);
        std::thread::spawn(move || {
            let store = ControlStore::open_with_key(&path, &[98; 32]).unwrap();
            gate.wait();
            (
                marker,
                reserve(&store, marker, scope(1, marker), 100, 1).is_ok(),
            )
        })
    });
    gate.wait();
    let attempts = threads.map(|thread| thread.join().unwrap());
    assert_eq!(attempts.iter().filter(|(_, passed)| *passed).count(), 1);
    let winner = attempts.into_iter().find(|(_, passed)| *passed).unwrap().0;
    let reserved = usage(&store, 1);
    assert_eq!(reserved.reserved_logical_bytes, 100);
    assert_eq!(reserved.reserved_sources, 1);
    assert_eq!(reserved.open_reservations, 1);
    reserve(&store, winner, scope(1, winner), 100, 1).unwrap();
    assert_eq!(usage(&store, 1), reserved);
    assert!(reserve(&store, winner, scope(1, winner), 99, 1).is_err());
    assert!(reserve(&store, 5, scope(1, 5), 0, 0).is_err());
    // Other guilds use independent totals, even with the same owner/root.
    reserve(&store, 6, scope(2, winner), 100, 1).unwrap();
    let other = usage(&store, 2);
    store
        .cancel_catalog_retained_source_reservation(id(winner), scope(1, winner))
        .unwrap();
    assert_eq!(usage(&store, 1), empty);
    assert_eq!(usage(&store, 2), other);
    for (bytes, sources) in [(101, 1), (100, 2), (u64::MAX, 1)] {
        let before = state(&store);
        assert!(reserve(&store, 7, scope(1, 7), bytes, sources).is_err());
        assert_eq!(state(&store), before);
    }
    reserve(&store, 7, scope(1, 7), 0, 0).unwrap();
    assert!(reserve(&store, 8, scope(1, 8), 0, 0).is_err());
}

#[test]
fn guild_source_adoption_includes_stored_cancelled_and_outstanding_dataset_usage() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[99; 32]).unwrap();
    store
        .configure_catalog_retained_source_quota(quota(400, 4, 4))
        .unwrap();
    reserve(&store, 4, scope(1, 3), 100, 1).unwrap();
    let source = source(7);
    publish(&store, 4, scope(1, 3), &source).unwrap();
    store
        .cancel_catalog_retained_source_reservation(id(4), scope(1, 3))
        .unwrap();
    reserve(&store, 5, scope(1, 4), 200, 2).unwrap();
    reserve(&store, 6, scope(1, 5), 0, 0).unwrap();
    reserve(&store, 8, scope(2, 3), 100, 1).unwrap();
    let before = state(&store);
    for limit in [quota(299, 4, 2), quota(350, 2, 2), quota(350, 4, 1)] {
        assert!(
            store
                .configure_catalog_retained_source_guild_quota(limit)
                .is_err()
        );
        assert_eq!(state(&store), before);
        assert_eq!(
            store.catalog_retained_source_guild_usage([1; 32]).unwrap(),
            None
        );
    }
    store
        .configure_catalog_retained_source_guild_quota(quota(350, 4, 2))
        .unwrap();
    let adopted = usage(&store, 1);
    assert_eq!(adopted.stored_logical_bytes, 100);
    assert_eq!(adopted.stored_sources, 1);
    assert_eq!(adopted.reserved_logical_bytes, 200);
    assert_eq!(adopted.reserved_sources, 2);
    assert_eq!(adopted.open_reservations, 2);
    assert_eq!(usage(&store, 2).reserved_logical_bytes, 100);
    // Adoption does not replay, alter or close an immutable existing job.
    reserve(&store, 5, scope(1, 4), 200, 2).unwrap();
    assert_eq!(usage(&store, 1), adopted);
    drop(store);
    let store = ControlStore::open_with_key(&path, &[99; 32]).unwrap();
    assert_eq!(usage(&store, 1), adopted);
    store
        .with_record_transaction(|| release(&store.connection, id(4), scope(1, 3), &source))
        .unwrap();
    assert_eq!(usage(&store, 1).stored_sources, 0);
    assert_eq!(usage(&store, 1).reserved_logical_bytes, 200);
    let readonly = ControlStore::open_existing_read_only_with_key(&path, &[99; 32]).unwrap();
    assert_eq!(usage(&readonly, 1), usage(&store, 1));
    assert!(
        readonly
            .configure_catalog_retained_source_guild_quota(quota(400, 5, 3))
            .is_err()
    );
    for limit in [quota(349, 4, 2), quota(350, 3, 2), quota(350, 4, 1)] {
        assert!(
            store
                .configure_catalog_retained_source_guild_quota(limit)
                .is_err()
        );
    }
    let existing = usage(&store, 1);
    store
        .configure_catalog_retained_source_guild_quota(quota(
            1 << 40,
            (1 << 40) / V1_SECTOR_SIZE as u64,
            32,
        ))
        .unwrap();
    assert_eq!(usage(&store, 1), existing);
}

#[test]
fn guild_source_policy_and_initial_adoption_roll_back_ignored_and_reverted_sql() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[100; 32]).unwrap();
    store
        .configure_catalog_retained_source_quota(quota(400, 4, 4))
        .unwrap();
    reserve(&store, 4, scope(1, 3), 100, 1).unwrap();
    let before = state(&store);
    for kind in [
        POLICY.to_string(),
        ENABLED.to_string(),
        LEDGER.to_string(),
        GUILD.to_string(),
        members([1; 32]),
    ] {
        for action in ["ignore", "delete"] {
            let body = if action == "ignore" {
                "SELECT RAISE(IGNORE);".to_string()
            } else {
                "DELETE FROM protocol_records WHERE kind = NEW.kind AND record_id = NEW.record_id;"
                    .to_string()
            };
            let timing = if action == "ignore" {
                "BEFORE"
            } else {
                "AFTER"
            };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER fault {timing} INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN {body} END")).unwrap();
            assert!(
                store
                    .configure_catalog_retained_source_guild_quota(quota(400, 4, 4))
                    .is_err()
            );
            assert_eq!(state(&store), before);
            store
                .connection
                .execute_batch("DROP TRIGGER fault")
                .unwrap();
        }
    }
    store
        .configure_catalog_retained_source_guild_quota(quota(400, 4, 4))
        .unwrap();
    let before = state(&store);
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER fault AFTER UPDATE ON protocol_records WHEN NEW.kind = '{POLICY}' BEGIN UPDATE protocol_records SET bytes = OLD.bytes WHERE kind = NEW.kind AND record_id = NEW.record_id; END")).unwrap();
    assert!(
        store
            .configure_catalog_retained_source_guild_quota(quota(500, 5, 5))
            .is_err()
    );
    assert_eq!(state(&store), before);
}

#[test]
fn guild_source_credit_publication_cancel_and_final_cleanup_share_the_owner_writer() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[101; 32]).unwrap();
    store
        .configure_catalog_retained_source_quota(quota(400, 4, 4))
        .unwrap();
    store
        .configure_catalog_retained_source_guild_quota(quota(400, 4, 4))
        .unwrap();
    let empty = state(&store);
    for kind in [LEDGER.to_string(), GUILD.to_string(), members([1; 32])] {
        store.connection.execute_batch(&format!("CREATE TEMP TRIGGER fault BEFORE INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END")).unwrap();
        assert!(reserve(&store, 4, scope(1, 3), 100, 1).is_err());
        assert_eq!(state(&store), empty);
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
    }
    for reverts in [false, true] {
        let timing = if reverts { "AFTER" } else { "BEFORE" };
        let body = if reverts {
            "UPDATE protocol_records SET bytes = OLD.bytes WHERE kind = NEW.kind AND record_id = NEW.record_id;"
        } else {
            "SELECT RAISE(IGNORE);"
        };
        let fault = format!(
            "CREATE TEMP TRIGGER fault {timing} UPDATE ON protocol_records WHEN NEW.kind = '{LEDGER}' BEGIN {body} END"
        );
        store.connection.execute_batch(&fault).unwrap();
        assert!(reserve(&store, 4, scope(1, 3), 100, 1).is_err());
        assert_eq!(state(&store), empty);
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
    }
    reserve(&store, 4, scope(1, 3), 100, 1).unwrap();
    let reserved = state(&store);
    let source = source(7);
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER fault BEFORE UPDATE ON protocol_records WHEN NEW.kind = '{LEDGER}' BEGIN SELECT RAISE(IGNORE); END")).unwrap();
    assert!(publish(&store, 4, scope(1, 3), &source).is_err());
    assert_eq!(state(&store), reserved);
    assert!(
        store
            .cancel_catalog_retained_source_reservation(id(4), scope(1, 3))
            .is_err()
    );
    assert_eq!(state(&store), reserved);
    store
        .connection
        .execute_batch("DROP TRIGGER fault")
        .unwrap();
    publish(&store, 4, scope(1, 3), &source).unwrap();
    let used = usage(&store, 1);
    // Revisions share the same dataset charge; conservative unused credits close.
    reserve(&store, 5, scope(1, 3), 100, 1).unwrap();
    publish(&store, 5, scope(1, 3), &source).unwrap();
    assert_eq!(usage(&store, 1), used);
    store
        .cancel_catalog_retained_source_reservation(id(4), scope(1, 3))
        .unwrap();
    store
        .with_record_transaction(|| release(&store.connection, id(4), scope(1, 3), &source))
        .unwrap();
    assert_eq!(usage(&store, 1), used);
    store
        .cancel_catalog_retained_source_reservation(id(5), scope(1, 3))
        .unwrap();
    let cancelled = state(&store);
    store.connection.execute_batch(&format!("CREATE TEMP TRIGGER fault BEFORE UPDATE ON protocol_records WHEN NEW.kind = '{LEDGER}' BEGIN SELECT RAISE(IGNORE); END")).unwrap();
    assert!(
        store
            .with_record_transaction(|| release(&store.connection, id(5), scope(1, 3), &source))
            .is_err()
    );
    assert_eq!(state(&store), cancelled);
    store
        .connection
        .execute_batch("DROP TRIGGER fault")
        .unwrap();
    store
        .with_record_transaction(|| release(&store.connection, id(5), scope(1, 3), &source))
        .unwrap();
    assert_eq!(usage(&store, 1).stored_sources, 0);
    let before = state(&store);
    let failed: Result<(), CatalogStoreError> = store.with_record_transaction(|| {
        store.reserve_catalog_retained_sources_in_transaction(
            id(6),
            scope(1, 4),
            CatalogRetainedSourceReservation {
                logical_bytes: 100,
                sources: 1,
            },
        )?;
        store.put_record("test-owner", b"id", b"journal")?;
        Err(DatabaseError::Conflict.into())
    });
    assert!(failed.is_err());
    assert_eq!(state(&store), before);
}

#[test]
fn guild_source_missing_corrupt_or_oversized_accounting_cannot_reset_admission() {
    for fault in [
        "policy",
        "enabled",
        "ledger",
        "guild",
        "member",
        "pair",
        "scope",
        "oversized",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let store =
            ControlStore::open_with_key(temp.path().join("control.db"), &[102; 32]).unwrap();
        store
            .configure_catalog_retained_source_quota(quota(400, 4, 4))
            .unwrap();
        store
            .configure_catalog_retained_source_guild_quota(quota(100, 1, 1))
            .unwrap();
        reserve(&store, 4, scope(1, 3), 100, 1).unwrap();
        let (kind, key) = match fault {
            "policy" => (POLICY.to_string(), KEY.to_vec()),
            "enabled" => (ENABLED.to_string(), KEY.to_vec()),
            "guild" => (GUILD.to_string(), vec![1_u8; 32]),
            "member" => (members([1; 32]), dataset_key(scope(1, 3)).unwrap().to_vec()),
            _ => (LEDGER.to_string(), vec![1_u8; 32]),
        };
        match fault {
            "scope" => {
                let mut bad = usage(&store, 1);
                bad.scope = CatalogScope::Guild { guild_id: [2; 32] };
                replace(&store.connection, LEDGER, &[1; 32], &(1_u16, bad)).unwrap();
            }
            "oversized" => {
                store
                    .connection
                    .execute(
                        "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
                        params![kind, key, vec![0_u8; RECORD_BYTES + 1]],
                    )
                    .unwrap();
            }
            _ => {
                store
                    .connection
                    .execute(
                        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                        params![kind, key],
                    )
                    .unwrap();
                if fault == "pair" {
                    store
                        .connection
                        .execute(
                            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                            params![GUILD, vec![1_u8; 32]],
                        )
                        .unwrap();
                }
            }
        }
        let before = state(&store);
        assert!(
            store.catalog_retained_source_usage(scope(1, 3)).is_err(),
            "{fault}"
        );
        assert!(reserve(&store, 4, scope(1, 3), 100, 1).is_err(), "{fault}");
        assert!(reserve(&store, 5, scope(1, 4), 100, 1).is_err(), "{fault}");
        assert_eq!(state(&store), before);
    }
}

#[test]
fn guild_source_adoption_rejects_missing_and_unbounded_dataset_records_atomically() {
    for fault in ["marker", "ledger", "key", "oversized", "canonical"] {
        let temp = tempfile::tempdir().unwrap();
        let store =
            ControlStore::open_with_key(temp.path().join("control.db"), &[103; 32]).unwrap();
        store
            .configure_catalog_retained_source_quota(quota(400, 4, 4))
            .unwrap();
        reserve(&store, 4, scope(1, 3), 100, 1).unwrap();
        let key = dataset_key(scope(1, 3)).unwrap();
        match fault {
            "marker" | "ledger" => {
                let kind = if fault == "marker" {
                    DATASET
                } else {
                    super::super::LEDGER
                };
                store
                    .connection
                    .execute(
                        "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                        params![kind, key.as_slice()],
                    )
                    .unwrap();
            }
            "key" => {
                store.connection.execute("UPDATE protocol_records SET record_id = ?3 WHERE kind = ?1 AND record_id = ?2", params![super::super::LEDGER, key.as_slice(), vec![0_u8; 33]]).unwrap();
            }
            _ => {
                let bytes = if fault == "oversized" {
                    vec![0_u8; RECORD_BYTES + 1]
                } else {
                    vec![1, 2, 3]
                };
                store
                    .connection
                    .execute(
                        "UPDATE protocol_records SET bytes = ?3 WHERE kind = ?1 AND record_id = ?2",
                        params![super::super::LEDGER, key.as_slice(), bytes],
                    )
                    .unwrap();
            }
        }
        let before = state(&store);
        assert!(
            store
                .configure_catalog_retained_source_guild_quota(quota(400, 4, 4))
                .is_err(),
            "{fault}"
        );
        assert_eq!(state(&store), before);
    }
}
