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
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_scratch BEFORE DELETE ON protocol_records WHEN OLD.kind='catalog-scratch-lease-guard-v1' BEGIN SELECT RAISE({action}); END")).unwrap();
            assert!(store.reclaim_abandoned_catalog_scratch().is_err());
            assert_eq!(usage(&store), (3, 1));
            store
                .connection
                .execute_batch("DROP TRIGGER refuse_scratch")
                .unwrap();
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
