use super::*;

struct Fixture {
    directory: Option<tempfile::TempDir>,
    store: Option<ControlStore>,
}
impl Fixture {
    fn new(bytes: u64, jobs: u32) -> Self {
        let (directory, store) = setup();
        let fixture = Self {
            directory: Some(directory),
            store: Some(store),
        };
        fixture
            .store()
            .configure_catalog_scratch_pool_policy(pool(bytes, jobs))
            .unwrap();
        fixture
    }
    fn store(&self) -> &ControlStore {
        self.store.as_ref().unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // Preserve the original named main/WAL/SHM and ownership state;
            // do not run connection cleanup/checkpointing on a failed fixture.
            if let Some(store) = self.store.take() {
                std::mem::forget(store);
            }
            eprintln!(
                "SCRATCH_BATCH_NEGATIVE_FIXTURE {}",
                self.directory.take().unwrap().keep().display()
            );
        }
    }
}

#[test]
fn scratch_batch_checks_complete_bytes_and_slots_without_committing_a_prefix() {
    let fixture = Fixture::new(9, 3);
    let store = fixture.store();
    let observer = ControlStore::open(
        fixture
            .directory
            .as_ref()
            .unwrap()
            .path()
            .join("control.db"),
        &keys(),
    )
    .unwrap();
    let a = store.reserve_catalog_scratch(3).unwrap().unwrap();
    for request in [&[4, 3][..], &[1, 1, 1][..]] {
        assert!(matches!(
            observer.reserve_catalog_scratch_batch(request),
            Err(CatalogStoreError::ScratchPoolExhausted)
        ));
        assert_eq!(usage(store), (3, 1));
        a.check(3).unwrap();
    }
    let mut batch = observer
        .reserve_catalog_scratch_batch(&[2, 4])
        .unwrap()
        .unwrap();
    assert_eq!(usage(store), (9, 3));
    batch[0].check(2).unwrap();
    batch[1].check(4).unwrap();
    drop(batch.pop());
    assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(store), (5, 2));
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    a.check(3).unwrap();
    batch[0].check(2).unwrap();
    let replacement = store.reserve_catalog_scratch_batch(&[4]).unwrap().unwrap();
    assert_eq!(usage(store), (9, 3));
    replacement[0].check(4).unwrap();
    drop(replacement);
    drop(batch);
    drop(a);
    for _ in 0..3 {
        assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    }
    assert_eq!(usage(store), (0, 0));
}

#[test]
fn scratch_batch_all_64_slots_remain_independently_owned_and_reclaimable() {
    let mut fixture = Fixture::new(64, 64);
    let store = fixture.store();
    for invalid in [Vec::new(), vec![0], vec![1; 65], vec![u64::MAX, 1]] {
        assert!(store.reserve_catalog_scratch_batch(&invalid).is_err());
        assert_eq!(usage(store), (0, 0));
    }
    let mut leases = store
        .reserve_catalog_scratch_batch(&[1; 64])
        .unwrap()
        .unwrap();
    assert_eq!(usage(store), (64, 64));
    let path = fixture
        .directory
        .as_ref()
        .unwrap()
        .path()
        .join("control.db");
    drop(fixture.store.take());
    fixture.store = Some(ControlStore::open(path, &keys()).unwrap());
    let store = fixture.store();
    assert_eq!(usage(store), (64, 64));
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    drop(leases.remove(31));
    assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(store), (63, 63));
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    for lease in &leases {
        lease.check(1).unwrap();
    }
    let replacement = store.reserve_catalog_scratch_batch(&[1]).unwrap().unwrap();
    assert_eq!(usage(store), (64, 64));
    replacement[0].check(1).unwrap();
    drop(replacement);
    drop(leases);
    for _ in 0..64 {
        assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    }
    assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(store), (0, 0));
}

#[test]
fn scratch_batch_replacement_reclaims_each_stopped_member_before_admission() {
    let fixture = Fixture::new(6, 2);
    let store = fixture.store();
    let stopped = store
        .reserve_catalog_scratch_batch(&[3, 3])
        .unwrap()
        .unwrap();
    drop(stopped);
    assert_eq!(usage(store), (6, 2));
    let replacement = store
        .reserve_catalog_scratch_batch(&[3, 3])
        .unwrap()
        .unwrap();
    assert_eq!(usage(store), (6, 2));
    for lease in &replacement {
        lease.check(3).unwrap();
    }
    drop(replacement);
    for _ in 0..2 {
        assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
    }
    assert_eq!(usage(store), (0, 0));
}

#[test]
fn scratch_batch_late_abort_and_ignore_roll_back_all_members_and_retry() {
    for action in ["ABORT,'fixture'", "IGNORE"] {
        for late_guard in [false, true] {
            let fixture = Fixture::new(9, 3);
            let store = fixture.store();
            let trigger = if late_guard {
                format!(
                    "CREATE TEMP TRIGGER refuse_batch BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-scratch-pool-guard-v1' BEGIN SELECT RAISE({action}); END"
                )
            } else {
                format!(
                    "CREATE TEMP TRIGGER refuse_batch BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-scratch-lease-guard-v1' AND (SELECT count(*) FROM protocol_records WHERE kind='catalog-scratch-lease-v1')=2 BEGIN SELECT RAISE({action}); END"
                )
            };
            store.connection.execute_batch(&trigger).unwrap();
            assert!(store.reserve_catalog_scratch_batch(&[3, 2, 4]).is_err());
            assert_eq!(usage(store), (0, 0));
            assert!(!store.reclaim_abandoned_catalog_scratch().unwrap());
            store
                .connection
                .execute_batch("DROP TRIGGER refuse_batch")
                .unwrap();
            let leases = store
                .reserve_catalog_scratch_batch(&[3, 2, 4])
                .unwrap()
                .unwrap();
            assert_eq!(usage(store), (9, 3));
            for (lease, bytes) in leases.iter().zip([3, 2, 4]) {
                lease.check(bytes).unwrap();
            }
            drop(leases);
            for _ in 0..3 {
                assert!(store.reclaim_abandoned_catalog_scratch().unwrap());
            }
            assert_eq!(usage(store), (0, 0));
        }
    }
}
