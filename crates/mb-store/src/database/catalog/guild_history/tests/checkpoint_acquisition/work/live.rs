use super::*;

fn selected(cert: &Certificate) -> CatalogCheckpointRecoveryTip {
    CatalogCheckpointRecoveryTip {
        owner: Uuid::from_u128(2200),
        guild_id: cert.guild_id(),
        layout: cert.layout(),
        generation: cert.generation(),
        hash: cert.hash().unwrap(),
    }
}

#[test]
fn live_recovery_competes_with_acquisitions_in_every_work_dimension() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    for dimension in 0..3 {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
        let other = ControlStore::open(&path, &history.keys[0]).unwrap();
        configure(&mut store, &cert, 16);
        activate(&store);
        let limit = store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .limit;
        store
            .configure_catalog_traversal_pool_policy(CatalogTraversalPoolPolicy {
                format_version: 1,
                capacity: capacity(&cert),
                limit: limit.checked_add(limit).unwrap(),
            })
            .unwrap();
        let mut amount = base(&cert);
        let mut whole_chain = amount;
        match dimension {
            0 => {
                amount.bytes = limit.bytes / 2 + limit.bytes / 4 + 1;
                whole_chain.bytes = limit.bytes + 1;
            }
            1 => {
                amount.records = limit.records / 2 + limit.records / 4 + 1;
                whole_chain.records = limit.records + 1;
            }
            _ => {
                amount.page_occurrences =
                    limit.page_occurrences / 2 + limit.page_occurrences / 4 + 1;
                whole_chain.page_occurrences = limit.page_occurrences + 1;
            }
        }
        let job = store
            .begin_checkpoint_acquisition(
                Uuid::from_u128(2201),
                cert.clone(),
                proof.trust().clone(),
                amount,
            )
            .unwrap();
        let mut work = other
            .begin_checkpoint_recovery_work(selected(&cert), amount)
            .unwrap();
        assert_eq!(
            store
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            amount.checked_add(amount).unwrap()
        );
        assert!(
            store
                .begin_checkpoint_recovery_work(selected(&cert), amount)
                .is_err()
        );
        assert!(
            store
                .begin_checkpoint_acquisition(
                    Uuid::from_u128(2202),
                    cert.clone(),
                    proof.trust().clone(),
                    amount
                )
                .is_err()
        );
        assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
        work.check().unwrap();
        store.cancel_checkpoint_acquisition(&job).unwrap();
        let mut larger = store
            .begin_checkpoint_recovery_work(selected(&cert), whole_chain)
            .unwrap();
        larger.check().unwrap();
        assert_eq!(
            store
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            amount.checked_add(whole_chain).unwrap()
        );
        larger.finish().unwrap();
        assert!(larger.check().is_err());
        work.finish().unwrap();
        work.finish().unwrap();
        assert_eq!(
            store
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            Work::default()
        );
        assert_eq!(
            store.checkpoint_acquisition_state(&job).unwrap(),
            State::Cancelled
        );
        drop(larger);
        drop(work);
        drop(store);
        assert_eq!(
            ControlStore::open(&path, &history.keys[0])
                .unwrap()
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .open_jobs,
            0
        );
    }
}

#[test]
fn live_recovery_slots_and_policy_enrollment_fence_unfunded_traversals() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    let other = ControlStore::open(&path, &history.keys[0]).unwrap();
    let mut old = other
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    old.check().unwrap();
    configure(&mut store, &cert, 2);
    assert!(old.check().is_err());
    assert!(old.finish().is_err());
    assert!(
        store
            .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
            .is_err()
    );
    activate(&store);
    drop(old);
    let mut work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let job = other
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2210),
            cert.clone(),
            proof.trust().clone(),
            base(&cert),
        )
        .unwrap();
    let usage = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    usage
        .limit
        .remaining_after(usage.reserved.checked_add(base(&cert)).unwrap())
        .unwrap();
    assert_eq!(usage.open_jobs, 2);
    assert!(
        other
            .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
            .is_err()
    );
    assert!(!other.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    work.finish().unwrap();
    let replacement = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    drop(replacement);
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        1
    );
    other.cancel_checkpoint_acquisition(&job).unwrap();
}

#[test]
fn live_recovery_reservation_and_failed_drop_cleanup_are_atomic_under_write_faults() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let job = store
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2220),
            cert.clone(),
            proof.trust().clone(),
            base(&cert),
        )
        .unwrap();
    let before = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    for action in ["ABORT", "IGNORE"] {
        for kind in [
            "catalog-live-recovery-work-v1",
            "catalog-live-recovery-work-guard-v1",
            "catalog-acquisition-work-lease-v1",
            "catalog-acquisition-work-lease-guard-v1",
            "catalog-acquisition-work-held-v1",
            "catalog-acquisition-work-held-guard-v1",
            "catalog-acquisition-work-v1",
            "catalog-acquisition-work-guard-v1",
        ] {
            let suffix = if action == "ABORT" { ",'test'" } else { "" };
            let counter = matches!(
                kind,
                "catalog-acquisition-work-v1" | "catalog-acquisition-work-guard-v1"
            );
            let operation = if counter { "UPDATE" } else { "INSERT" };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER live_fault BEFORE {operation} ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(
                store
                    .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                    .is_err()
            );
            store
                .connection
                .execute_batch("DROP TRIGGER live_fault")
                .unwrap();
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                before
            );
            assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            let mut work = store
                .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
                .unwrap();
            let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
            let operation = if counter { "UPDATE" } else { "DELETE" };
            let column = if counter { "NEW" } else { "OLD" };
            store.connection.execute_batch(&format!("CREATE TEMP TRIGGER live_fault BEFORE {operation} ON protocol_records WHEN {column}.kind='{kind}' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(work.finish().is_err());
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                held
            );
            work.check().unwrap();
            assert!(
                !ControlStore::open(&path, &history.keys[0])
                    .unwrap()
                    .reclaim_abandoned_checkpoint_recovery_work()
                    .unwrap()
            );
            drop(work);
            store
                .connection
                .execute_batch("DROP TRIGGER live_fault")
                .unwrap();
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                held
            );
            assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
            assert_eq!(
                store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
                before
            );
        }
    }
    assert_eq!(
        store.checkpoint_acquisition_state(&job).unwrap(),
        State::Building
    );
    store.cancel_checkpoint_acquisition(&job).unwrap();
}

#[test]
fn live_recovery_torn_scope_and_copied_catalog_preserve_original_live_credits() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let mut work = store
        .begin_checkpoint_recovery_work(selected(&cert), base(&cert))
        .unwrap();
    let held = store.checkpoint_acquisition_work_usage().unwrap().unwrap();
    let (id, bytes) = store
        .next_record_bounded("catalog-live-recovery-work-guard-v1", None, 16, 4096)
        .unwrap()
        .unwrap();
    store.connection.execute("DELETE FROM protocol_records WHERE kind='catalog-live-recovery-work-guard-v1' AND record_id=?1", [&id]).unwrap();
    assert!(work.check().is_err());
    assert!(work.finish().is_err());
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().is_err());
    assert!(ControlStore::open(&path, &history.keys[0]).is_err());
    store.connection.execute("INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('catalog-live-recovery-work-guard-v1',?1,?2)", params![id, bytes]).unwrap();
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    work.check().unwrap();
    // This fixture has one quiescent SQL connection; the permit keeps only its
    // work token live. Checkpoint WAL before copying the encrypted main file.
    let checkpoint: (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(checkpoint.0, 0);
    let copied_path = temp.path().join("copied.db");
    std::fs::copy(&path, &copied_path).unwrap();
    let copied = ControlStore::open(&copied_path, &history.keys[0]).unwrap();
    assert_eq!(
        copied.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    assert!(copied.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        copied
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
    assert_eq!(
        store.checkpoint_acquisition_work_usage().unwrap().unwrap(),
        held
    );
    work.check().unwrap();
    work.finish().unwrap();
    assert_eq!(
        ControlStore::open(&path, &history.keys[0])
            .unwrap()
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn live_recovery_sigkill_reclaims_one_scope_without_releasing_durable_jobs() {
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};
    if let Some(directory) = std::env::var_os("MB_LIVE_RECOVERY_CHILD") {
        let directory = std::path::PathBuf::from(directory);
        let (key, tip, amount): ([u8; 32], CatalogCheckpointRecoveryTip, Work) =
            mb_core::decode_canonical(&std::fs::read(directory.join("input")).unwrap()).unwrap();
        let store = ControlStore::open_with_key(directory.join("control.db"), &key).unwrap();
        let _first = store.begin_checkpoint_recovery_work(tip, amount).unwrap();
        let _second = store.begin_checkpoint_recovery_work(tip, amount).unwrap();
        std::fs::write(directory.join("ready"), b"two live scopes").unwrap();
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut store, &cert, 16);
    activate(&store);
    let limit = store
        .checkpoint_acquisition_work_usage()
        .unwrap()
        .unwrap()
        .limit;
    store
        .configure_catalog_traversal_pool_policy(CatalogTraversalPoolPolicy {
            format_version: 1,
            capacity: capacity(&cert),
            limit: limit.checked_add(limit).unwrap(),
        })
        .unwrap();
    let amount = base(&cert);
    let job = store
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2230),
            cert.clone(),
            proof.trust().clone(),
            amount,
        )
        .unwrap();
    let key = history.keys[0].database_key(crate::database::CONTROL_DATABASE_ID);
    std::fs::write(
        temp.path().join("input"),
        mb_core::canonical_bytes(&(key, selected(&cert), amount)).unwrap(),
    )
    .unwrap();
    let mut child = ChildGuard(Command::new(std::env::current_exe().unwrap()).args([
        "database::catalog::guild_history::tests::checkpoint_acquisition::work::live::live_recovery_sigkill_reclaims_one_scope_without_releasing_durable_jobs", "--exact", "--nocapture"
    ]).env("MB_LIVE_RECOVERY_CHILD", temp.path()).stdout(Stdio::null()).stderr(Stdio::null()).spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !temp.path().join("ready").exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "child exited before reserving its scopes"
        );
        assert!(Instant::now() < deadline, "child did not reserve scopes");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        3
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    child.0.kill().unwrap();
    assert!(!child.0.wait().unwrap().success());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        3
    );
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        2
    );
    drop(store);
    let store = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert!(store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        amount
    );
    assert!(!store.reclaim_abandoned_checkpoint_recovery_work().unwrap());
    assert_eq!(
        store.checkpoint_acquisition_state(&job).unwrap(),
        State::Building
    );
    store.cancel_checkpoint_acquisition(&job).unwrap();
    assert_eq!(
        store
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        0
    );
}
