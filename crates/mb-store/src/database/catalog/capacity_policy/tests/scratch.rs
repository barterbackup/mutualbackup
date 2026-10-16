use super::*;
use crate::{CatalogScratchPoolPolicy, RecordScratchStore, ScratchStorageLimits};

fn setup() -> (tempfile::TempDir, ControlStore) {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    backing(&store);
    store.configure_catalog_capacity_policy(policy()).unwrap();
    let resources = resource_policy();
    resource_backing(&mut store, resources);
    store.configure_catalog_resource_policy(resources).unwrap();
    (temp, store)
}
fn pool(bytes: u64, jobs: u32) -> CatalogScratchPoolPolicy {
    CatalogScratchPoolPolicy {
        format_version: 1,
        physical_bytes: bytes,
        jobs,
    }
}
fn usage(store: &ControlStore) -> (u64, u32) {
    let value = store.catalog_scratch_pool_usage().unwrap().unwrap();
    (value.reserved_physical_bytes, value.open_jobs)
}

#[test]
fn scratch_unconfigured_probes_preserve_read_only_inputs_and_enclosing_transactions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open(&path, &keys()).unwrap();
    let tx = rusqlite::Transaction::new_unchecked(
        &store.connection,
        rusqlite::TransactionBehavior::Immediate,
    )
    .unwrap();
    tx.execute(
        "INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('fixture',x'01',x'02')",
        [],
    )
    .unwrap();
    assert!(store.reserve_catalog_scratch(10).unwrap().is_none());
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    assert!(!store.connection.is_autocommit());
    assert_eq!(store.get_record("fixture", &[1]).unwrap(), Some(vec![2]));
    tx.rollback().unwrap();
    assert_eq!(store.get_record("fixture", &[1]).unwrap(), None);
    drop(store);
    let original = std::fs::read(&path).unwrap();
    let mut before = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    before.sort();
    let database_key = keys().database_key(crate::database::CONTROL_DATABASE_ID);
    let (reader, guard) =
        ControlStore::open_preserved_read_only_with_keys(&path, &[database_key]).unwrap();
    reader
        .with_read_only_snapshot(|| {
            assert!(reader.reserve_catalog_scratch(10)?.is_none());
            assert!(!reader.reclaim_abandoned_catalog_scratch()?);
            assert!(!reader.connection.is_autocommit());
            Ok(())
        })
        .unwrap();
    guard.verify_unchanged().unwrap();
    drop(reader);
    let mut after = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    after.sort();
    assert_eq!(before, after);
    assert_eq!(std::fs::read(&path).unwrap(), original);
}

#[test]
fn scratch_enrollment_is_required_only_for_resource_backed_catalogs() {
    let temp = tempfile::tempdir().unwrap();
    let store = ControlStore::open(temp.path().join("old.db"), &keys()).unwrap();
    assert!(store.reserve_catalog_scratch(10).unwrap().is_none());
    assert!(
        store
            .configure_catalog_scratch_pool_policy(pool(10, 1))
            .is_err()
    );
    assert_eq!(store.catalog_scratch_pool_usage().unwrap(), None);
    let (temp, store) = setup();
    assert!(matches!(
        store.reserve_catalog_scratch(10),
        Err(CatalogStoreError::ScratchPoolRequired)
    ));
    assert_eq!(store.catalog_scratch_pool_usage().unwrap(), None);
    drop(store);
    let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    store
        .configure_catalog_scratch_pool_policy(pool(10, 1))
        .unwrap();
    assert_eq!(usage(&store), (0, 0));
    for invalid in [pool(0, 1), pool(u64::MAX, 1), pool(10, 0), pool(10, 65)] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn scratch_byte_and_job_limits_compete_across_connections_without_stealing_live_work() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let observer = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    let a = store.reserve_catalog_scratch(3).unwrap().unwrap();
    // A second slot is available: only the byte ceiling refuses this request.
    assert!(matches!(
        observer.reserve_catalog_scratch(7),
        Err(CatalogStoreError::ScratchPoolExhausted)
    ));
    assert_eq!(usage(&store), (3, 1));
    let b = observer.reserve_catalog_scratch(6).unwrap().unwrap();
    assert_eq!(usage(&store), (9, 2));
    assert!(matches!(
        store.reserve_catalog_scratch(1),
        Err(CatalogStoreError::ScratchPoolExhausted)
    ));
    assert!(!observer.reclaim_abandoned_catalog_scratch().unwrap());
    a.check(3).unwrap();
    b.check(6).unwrap();
    drop(a);
    // Dead-credit cleanup commits even when the next declaration cannot fit.
    assert!(matches!(
        store.reserve_catalog_scratch(4),
        Err(CatalogStoreError::ScratchPoolExhausted)
    ));
    assert_eq!(usage(&observer), (6, 1));
    let c = store.reserve_catalog_scratch(1).unwrap().unwrap();
    assert_eq!(usage(&observer), (7, 2));
    assert!(matches!(
        observer.reserve_catalog_scratch(1),
        Err(CatalogStoreError::ScratchPoolExhausted)
    ));
    b.check(6).unwrap();
    c.check(1).unwrap();
    drop(c);
    drop(b);
    assert!(observer.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&store).1, 1);
    assert!(observer.reclaim_abandoned_catalog_scratch().unwrap());
    assert!(!observer.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&store), (0, 0));
}

#[test]
fn scratch_policy_enrollment_faults_roll_back_and_exact_replay_is_immutable() {
    for action in ["ABORT,'fixture'", "IGNORE"] {
        for target in ["guard", "marker"] {
            let (temp, store) = setup();
            let trigger = if target == "guard" {
                format!(
                    "CREATE TEMP TRIGGER refuse_scratch BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-scratch-pool-guard-v1' BEGIN SELECT RAISE({action}); END"
                )
            } else {
                format!(
                    "CREATE TEMP TRIGGER refuse_scratch BEFORE INSERT ON meta WHEN NEW.key='catalog_scratch_pool_version' BEGIN SELECT RAISE({action}); END"
                )
            };
            store.connection.execute_batch(&trigger).unwrap();
            assert!(
                store
                    .configure_catalog_scratch_pool_policy(pool(9, 2))
                    .is_err()
            );
            assert_eq!(store.catalog_scratch_pool_usage().unwrap(), None);
            store
                .connection
                .execute_batch("DROP TRIGGER refuse_scratch")
                .unwrap();
            store
                .configure_catalog_scratch_pool_policy(pool(9, 2))
                .unwrap();
            store
                .configure_catalog_scratch_pool_policy(pool(9, 2))
                .unwrap();
            assert!(
                store
                    .configure_catalog_scratch_pool_policy(pool(10, 2))
                    .is_err()
            );
            assert!(
                store
                    .configure_catalog_scratch_pool_policy(pool(9, 3))
                    .is_err()
            );
            drop(store);
            let store = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
            assert_eq!(usage(&store), (0, 0));
            assert_eq!(
                store.catalog_scratch_pool_usage().unwrap().unwrap().policy,
                pool(9, 2)
            );
        }
    }
}

#[test]
fn scratch_reservation_and_reclamation_are_atomic_under_abort_and_ignore_faults() {
    for action in ["ABORT,'fixture'", "IGNORE"] {
        for (verb, kind) in [
            ("INSERT", "catalog-scratch-lease-guard-v1"),
            ("UPDATE", "catalog-scratch-pool-guard-v1"),
        ] {
            let (_temp, store) = setup();
            store
                .configure_catalog_scratch_pool_policy(pool(9, 2))
                .unwrap();
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_scratch BEFORE {verb} ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}); END")).unwrap();
            assert!(store.reserve_catalog_scratch(3).is_err());
            assert_eq!(usage(&store), (0, 0));
            store
                .connection
                .execute_batch("DROP TRIGGER refuse_scratch")
                .unwrap();
            let lease = store.reserve_catalog_scratch(3).unwrap().unwrap();
            drop(lease);
            for (verb, side, kind) in [
                ("DELETE", "OLD", "catalog-scratch-lease-guard-v1"),
                ("UPDATE", "NEW", "catalog-scratch-pool-guard-v1"),
            ] {
                store.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_scratch BEFORE {verb} ON protocol_records WHEN {side}.kind='{kind}' BEGIN SELECT RAISE({action}); END")).unwrap();
                assert!(store.reclaim_abandoned_catalog_scratch().is_err());
                assert_eq!(usage(&store), (3, 1));
                store
                    .connection
                    .execute_batch("DROP TRIGGER refuse_scratch")
                    .unwrap();
            }
            assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
            assert_eq!(usage(&store), (0, 0));
        }
    }
}

#[test]
fn scratch_corrupt_pairs_and_markers_reject_reopen_without_releasing_live_tokens() {
    for (kind, marker) in [
        ("catalog-scratch-pool-guard-v1", false),
        ("catalog-scratch-lease-guard-v1", false),
        ("catalog-scratch-domain-guard-v1", false),
        ("catalog_scratch_pool_version", true),
    ] {
        let (temp, store) = setup();
        store
            .configure_catalog_scratch_pool_policy(pool(9, 2))
            .unwrap();
        let lease = store.reserve_catalog_scratch(3).unwrap().unwrap();
        let bytes: Vec<u8> = if marker {
            store
                .connection
                .query_row("SELECT value FROM meta WHERE key=?1", [kind], |r| r.get(0))
                .unwrap()
        } else {
            store
                .connection
                .query_row(
                    "SELECT bytes FROM protocol_records WHERE kind=?1",
                    [kind],
                    |r| r.get(0),
                )
                .unwrap()
        };
        if marker {
            store
                .connection
                .execute("DELETE FROM meta WHERE key=?1", [kind])
                .unwrap();
        } else {
            store
                .connection
                .execute("DELETE FROM protocol_records WHERE kind=?1", [kind])
                .unwrap();
        }
        assert!(store.catalog_scratch_pool_usage().is_err());
        assert!(store.reclaim_abandoned_catalog_scratch().is_err());
        assert!(ControlStore::open(temp.path().join("control.db"), &keys()).is_err());
        if marker {
            store
                .connection
                .execute(
                    "INSERT INTO meta(key,value) VALUES (?1,?2)",
                    params![kind, bytes],
                )
                .unwrap();
        } else {
            let id = if kind == "catalog-scratch-lease-guard-v1" {
                store.connection.query_row("SELECT record_id FROM protocol_records WHERE kind='catalog-scratch-lease-v1'", [], |r| r.get::<_, Vec<u8>>(0)).unwrap()
            } else {
                b"store".to_vec()
            };
            store
                .connection
                .execute(
                    "INSERT INTO protocol_records(kind,record_id,bytes) VALUES (?1,?2,?3)",
                    params![kind, id, bytes],
                )
                .unwrap();
        }
        assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
        lease.check(3).unwrap();
        assert_eq!(usage(&store), (3, 1));
    }
}

#[test]
fn scratch_copied_catalog_rebinds_without_changing_original_live_credits() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let a = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    let copied_path = temp.path().join("copied.db");
    std::fs::copy(store.path(), &copied_path).unwrap();
    let copied = ControlStore::open(&copied_path, &keys()).unwrap();
    assert_eq!(usage(&copied), (3, 1));
    assert!(copied.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&copied), (0, 0));
    let b = copied.reserve_catalog_scratch(9).unwrap().unwrap();
    b.check(9).unwrap();
    a.check(3).unwrap();
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    assert!(!copied.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&store), (3, 1));
}

#[test]
fn scratch_owned_vfs_outlives_original_connection_and_closes_before_returning_credits() {
    let (temp, store) = setup();
    let limits = ScratchStorageLimits::for_database(2 << 20).unwrap();
    store
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = store
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let records =
        RecordScratchStore::new_in_with_reserved_checkpoint_space(temp.path(), limits, &[], lease)
            .unwrap();
    assert_eq!(usage(&store), (limits.max_physical_bytes, 1));
    drop(store);
    let observer = ControlStore::open(temp.path().join("control.db"), &keys()).unwrap();
    assert!(!observer.reclaim_abandoned_catalog_scratch().unwrap());
    for index in 0_u32..16 {
        records
            .put_record_if_absent(
                "payload",
                &index.to_be_bytes(),
                &vec![index as u8; 64 * 1024],
            )
            .unwrap();
    }
    assert_eq!(
        records
            .get_record_bounded("payload", &15_u32.to_be_bytes(), 64 * 1024)
            .unwrap()
            .unwrap(),
        vec![15; 64 * 1024]
    );
    assert!(matches!(
        observer.reserve_catalog_scratch(1),
        Err(CatalogStoreError::ScratchPoolExhausted)
    ));
    drop(records);
    assert!(observer.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&observer), (0, 0));
    assert!(
        observer
            .reserve_catalog_scratch(limits.max_physical_bytes)
            .unwrap()
            .is_some()
    );
}

#[test]
fn scratch_constructor_failure_keeps_reclaimable_debt_and_cannot_exceed_its_grant() {
    let (temp, store) = setup();
    let limits = ScratchStorageLimits::for_database(2 << 20).unwrap();
    store
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = store.reserve_catalog_scratch(1).unwrap().unwrap();
    assert!(
        RecordScratchStore::new_in_with_reserved_checkpoint_space(temp.path(), limits, &[], lease)
            .is_err()
    );
    assert_eq!(usage(&store), (1, 1));
    assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    let lease = store
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let mut invalid = limits;
    invalid.max_database_bytes = 1;
    assert!(
        RecordScratchStore::new_in_with_reserved_checkpoint_space(temp.path(), invalid, &[], lease)
            .is_err()
    );
    assert_eq!(usage(&store), (limits.max_physical_bytes, 1));
    assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&store), (0, 0));
}

#[test]
fn scratch_sigkill_returns_only_stopped_credits() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    if let Some(directory) = std::env::var_os("MB_SCRATCH_LEASE_CHILD") {
        let directory = std::path::PathBuf::from(directory);
        let store = ControlStore::open(directory.join("control.db"), &keys()).unwrap();
        let _lease = store.reserve_catalog_scratch(3).unwrap().unwrap();
        std::fs::write(directory.join("ready"), b"ready").unwrap();
        loop {
            std::thread::park();
        }
    }
    struct Kill(Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 3))
        .unwrap();
    let own = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let mut child = Kill(Command::new(std::env::current_exe().unwrap())
        .args(["database::catalog::capacity_policy::tests::scratch::scratch_sigkill_returns_only_stopped_credits", "--exact", "--nocapture"])
        .env("MB_SCRATCH_LEASE_CHILD", temp.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !temp.path().join("ready").exists() {
        assert!(child.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(usage(&store), (6, 2));
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    child.0.kill().unwrap();
    child.0.wait().unwrap();
    assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(&store), (3, 1));
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    own.check(3).unwrap();
}

#[test]
fn scratch_lease_rejects_recreated_database_after_original_connection_closes() {
    use std::os::unix::fs::MetadataExt;
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 1))
        .unwrap();
    let lease = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let path = temp.path().join("control.db");
    let original = std::fs::metadata(&path).unwrap().ino();
    drop(store);
    std::fs::remove_file(&path).unwrap();
    // The lease must keep its original file identity alive even after SQLite
    // closes. On the qualified ext4 host the old code recycled it immediately.
    for index in 0..512 {
        std::fs::write(&path, []).unwrap();
        let replacement = std::fs::metadata(&path).unwrap().ino();
        assert!(
            lease.check(3).is_err(),
            "recreated database was accepted: original inode {original}, replacement {replacement}, attempt {index}"
        );
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn scratch_empty_restored_ledger_cannot_rebind_while_original_kernel_slot_is_live() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 1))
        .unwrap();
    let path = temp.path().join("control.db");
    let snapshot = temp.path().join("before-lease.db");
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    std::fs::copy(&path, &snapshot).unwrap();
    let original = store.reserve_catalog_scratch(3).unwrap().unwrap();
    drop(store);
    // Restore an earlier valid same-inode catalog while its old VFS token is
    // still alive. Empty persisted rows must not erase kernel ownership.
    std::fs::copy(&snapshot, &path).unwrap();
    let restored = ControlStore::open(&path, &keys()).unwrap();
    assert_eq!(usage(&restored), (0, 0));
    assert!(
        restored.reserve_catalog_scratch(9).is_err(),
        "restored empty ledger admitted the full pool while an old declaration remained live"
    );
    assert_eq!(usage(&restored), (0, 0));
    original.check(3).unwrap();
    drop(original);
    let next = restored.reserve_catalog_scratch(9).unwrap().unwrap();
    assert_eq!(usage(&restored), (9, 1));
    next.check(9).unwrap();
}

fn restored_prelease_snapshot_cannot_relocate_live_ownership(hard_link: bool) {
    use std::os::unix::fs::MetadataExt;
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let path = temp.path().join("control.db");
    let snapshot = temp.path().join("before-first-lease.db");
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    std::fs::copy(&path, &snapshot).unwrap();
    let original = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let identity = std::fs::metadata(&path).unwrap();
    drop(store);
    // Restore only SQLite to its valid state immediately after enrollment,
    // keeping the same inode and the original lease/lock descriptions alive.
    std::fs::copy(&snapshot, &path).unwrap();
    original.check(3).unwrap();
    let other = temp.path().join("other");
    std::fs::create_dir(&other).unwrap();
    let relocated = other.join("control.db");
    if hard_link {
        std::fs::hard_link(&path, &relocated).unwrap();
    } else {
        std::fs::rename(&path, &relocated).unwrap();
    }
    let named = std::fs::metadata(&relocated).unwrap();
    assert_eq!((identity.dev(), identity.ino()), (named.dev(), named.ino()));
    let alias = ControlStore::open(&relocated, &keys()).unwrap();
    assert_eq!(usage(&alias), (0, 0));
    assert!(
        alias.reserve_catalog_scratch(9).is_err(),
        "relocated pre-lease snapshot admitted 9 bytes while the original 3-byte lease remained live (hard_link={hard_link})"
    );
    assert_eq!(usage(&alias), (0, 0));
    drop(alias);
    if hard_link {
        std::fs::remove_file(&relocated).unwrap();
    } else {
        std::fs::rename(&relocated, &path).unwrap();
    }
    original.check(3).unwrap();
    let restored = ControlStore::open(&path, &keys()).unwrap();
    assert!(restored.reserve_catalog_scratch(9).is_err());
    drop(original);
    let next = restored.reserve_catalog_scratch(9).unwrap().unwrap();
    assert_eq!(usage(&restored), (9, 1));
    next.check(9).unwrap();
}

#[test]
fn scratch_restored_prelease_database_move_cannot_hide_a_live_owner() {
    restored_prelease_snapshot_cannot_relocate_live_ownership(false);
}

#[test]
fn scratch_restored_prelease_database_hard_link_cannot_hide_a_live_owner() {
    restored_prelease_snapshot_cannot_relocate_live_ownership(true);
}

#[test]
fn scratch_partial_restored_ledger_cannot_skip_an_unrecorded_live_slot() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let path = temp.path().join("control.db");
    let snapshot = temp.path().join("one-lease.db");
    let represented = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    std::fs::copy(&path, &snapshot).unwrap();
    let unrecorded = store.reserve_catalog_scratch(3).unwrap().unwrap();
    drop(store);
    std::fs::copy(&snapshot, &path).unwrap();
    let restored = ControlStore::open(&path, &keys()).unwrap();
    assert_eq!(usage(&restored), (3, 1));
    assert!(matches!(
        restored.reserve_catalog_scratch(6),
        Err(CatalogStoreError::UnrecordedLiveCatalogWork)
    ));
    assert_eq!(usage(&restored), (3, 1));
    represented.check(3).unwrap();
    unrecorded.check(3).unwrap();
    drop(unrecorded);
    let next = restored.reserve_catalog_scratch(6).unwrap().unwrap();
    assert_eq!(usage(&restored), (9, 2));
    represented.check(3).unwrap();
    next.check(6).unwrap();
}

#[test]
fn scratch_restored_declaration_cannot_impersonate_a_new_owner_of_the_same_slot() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let path = temp.path().join("control.db");
    let snapshot = temp.path().join("old-owner.db");
    let stopped = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    std::fs::copy(&path, &snapshot).unwrap();
    drop(stopped);
    let actual = store.reserve_catalog_scratch(9).unwrap().unwrap();
    assert_eq!(usage(&store), (9, 1));
    drop(store);
    std::fs::copy(&snapshot, &path).unwrap();
    let restored = ControlStore::open(&path, &keys()).unwrap();
    assert_eq!(usage(&restored), (3, 1));
    assert!(
        restored.reserve_catalog_scratch(6).is_err(),
        "a restored small declaration impersonated the later full-pool owner of its reused kernel slot"
    );
    actual.check(9).unwrap();
    drop(actual);
    let next = restored.reserve_catalog_scratch(9).unwrap().unwrap();
    assert_eq!(usage(&restored), (9, 1));
    next.check(9).unwrap();
}

#[test]
fn scratch_identity_pin_close_preserves_another_sqlite_connections_posix_writer_lock() {
    const CHILD: &str = "MB_SCRATCH_PIN_SQLITE_CHILD";
    const CASE: &str = "database::catalog::capacity_policy::tests::scratch::scratch_identity_pin_close_preserves_another_sqlite_connections_posix_writer_lock";
    if let Some(path) = std::env::var_os(CHILD) {
        // ControlStore::open changes journal_mode to WAL. Use a raw child
        // connection so SHM locks cannot mask loss of the main POSIX lock.
        let connection = Connection::open(path).unwrap();
        connection
            .pragma_update(None, "key", hex::encode(keys().database_key(b"control.db")))
            .unwrap();
        connection
            .execute_batch("PRAGMA cipher_compatibility=4; PRAGMA cipher_page_size=4096;")
            .unwrap();
        connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
                r.get::<_, u64>(0)
            })
            .unwrap();
        connection.busy_timeout(std::time::Duration::ZERO).unwrap();
        let error = connection
            .execute_batch("BEGIN IMMEDIATE")
            .expect_err("original rollback-mode writer lost its main-file POSIX lock");
        assert_eq!(
            error.sqlite_error_code(),
            Some(rusqlite::ErrorCode::DatabaseBusy)
        );
        return;
    }
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 1))
        .unwrap();
    let mut lease = Some(store.reserve_catalog_scratch(3).unwrap().unwrap());
    let mode: String = store
        .connection
        .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let writer =
        Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
    for after_close in [false, true] {
        if after_close {
            drop(lease.take());
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([CASE, "--exact", "--nocapture"])
            .env(CHILD, temp.path().join("control.db"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "child writer exclusion failed after_close={after_close}: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    writer.rollback().unwrap();
}

#[test]
fn scratch_legacy_declarations_keep_original_bytes_and_block_new_grants_until_stopped() {
    let (_temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let lease = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let (key, bytes) = store
        .records("catalog-scratch-lease-v1")
        .unwrap()
        .pop()
        .unwrap();
    type Owned = (u16, Uuid, u64, Uuid, u8, (u64, u64));
    let (version, id, bytes, domain, slot, _): Owned = mb_core::decode_canonical(&bytes).unwrap();
    assert_eq!(version, 2);
    let original = mb_core::canonical_bytes(&(1_u16, id, bytes, domain, slot)).unwrap();
    for kind in ["catalog-scratch-lease-v1", "catalog-scratch-lease-guard-v1"] {
        store
            .connection
            .execute(
                "UPDATE protocol_records SET bytes=?1 WHERE kind=?2 AND record_id=?3",
                params![original, kind, key],
            )
            .unwrap();
    }
    assert_eq!(usage(&store), (3, 1));
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    assert!(store.reserve_catalog_scratch(3).is_err());
    assert_eq!(
        store
            .get_record("catalog-scratch-lease-v1", &key)
            .unwrap()
            .unwrap(),
        original
    );
    drop(lease);
    assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    let next = store.reserve_catalog_scratch(9).unwrap().unwrap();
    assert_eq!(usage(&store), (9, 1));
    next.check(9).unwrap();
}

#[test]
fn scratch_owner_files_are_bounded_and_recycling_preserves_another_live_owner() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let live = store.reserve_catalog_scratch(3).unwrap().unwrap();
    for _ in 0..32 {
        let next = store.reserve_catalog_scratch(3).unwrap().unwrap();
        live.check(3).unwrap();
        let directories: Vec<_> = std::fs::read_dir(temp.path())
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|s| s == "owners"))
            .collect();
        assert_eq!(directories.len(), 1);
        assert_eq!(std::fs::read_dir(&directories[0]).unwrap().count(), 2);
        drop(next);
    }
    live.check(3).unwrap();
}

#[test]
fn scratch_owner_file_replacement_refuses_growth_without_releasing_live_credits() {
    let (temp, store) = setup();
    store
        .configure_catalog_scratch_pool_policy(pool(9, 2))
        .unwrap();
    let live = store.reserve_catalog_scratch(3).unwrap().unwrap();
    let directory = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|s| s == "owners"))
        .unwrap();
    let path = std::fs::read_dir(&directory)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let saved = temp.path().join("saved-owner");
    std::fs::rename(&path, &saved).unwrap();
    std::fs::write(&path, []).unwrap();
    assert!(live.check(3).is_err());
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    assert!(store.reserve_catalog_scratch(3).is_err());
    assert_eq!(usage(&store), (3, 1));
    std::fs::remove_file(&path).unwrap();
    std::fs::rename(saved, path).unwrap();
    live.check(3).unwrap();
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
}
