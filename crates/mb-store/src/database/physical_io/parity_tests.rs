use super::*;
use crate::database::{
    ParityObject, ParityStore, VariableParityObject, merkle_commit, sector_root,
};

fn limits() -> DatabasePhysicalIoLimits {
    DatabasePhysicalIoLimits {
        main_bytes: 4 << 20,
        journal_bytes: 8 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 8 << 20,
        total_bytes: 32 << 20,
        headroom_bytes: 0,
        files: 16,
    }
}
fn setup(budget: DatabasePhysicalIoLimits) -> (tempfile::TempDir, ParityStore) {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = ParityStore::create_physical_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("parity.db"),
        &[3; 16],
        &[7; 32],
        budget,
    )
    .unwrap();
    (temp, store)
}
fn fixed() -> ParityObject {
    let bytes = vec![4; 65536];
    ParityObject {
        format_version: 1,
        guild_id: [1; 32],
        group_id: [2; 32],
        shard_index: 1,
        root: sector_root(&bytes),
        bytes,
    }
}
fn variable(bytes: usize) -> VariableParityObject {
    let bytes = vec![8; bytes];
    VariableParityObject {
        format_version: 2,
        guild_id: [1; 32],
        group_id: [5; 32],
        shard_index: 2,
        commitment: merkle_commit(&bytes).unwrap(),
        bytes,
    }
}

#[test]
fn native_parity_connections_share_physical_credits_and_preserve_ready_evidence() {
    let mut budget = limits();
    budget.temporary_bytes = 6 << 20;
    let (temp, mut first) = setup(budget);
    let object = fixed();
    first
        .stage_and_publish_ack(&object, b"shared-pool acknowledgement", 1 << 20)
        .unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let second = ParityStore::open_physical_existing_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("parity.db"),
        &[3; 16],
        &[7; 32],
        budget,
    )
    .unwrap();
    for store in [&first, &second] {
        store
            .connection
            .execute_batch(
                "PRAGMA temp_store=FILE; PRAGMA temp.cache_size=8;
                 CREATE TEMP TABLE shared_spill(bytes BLOB);",
            )
            .unwrap();
    }
    let spill = |store: &ParityStore| -> Result<(), DatabaseError> {
        let tx = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        for _ in 0..128 {
            tx.execute("INSERT INTO temp.shared_spill VALUES (zeroblob(32768))", [])?;
        }
        tx.commit()?;
        Ok(())
    };
    spill(&first).unwrap();
    assert_eq!(
        first.physical_io_allocated_bytes().unwrap(),
        second.physical_io_allocated_bytes().unwrap()
    );
    let error = spill(&second).expect_err("parity temporaries share the complete allowance");
    assert!(
        matches!(error, DatabaseError::Sql(ref e) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::DiskFull)),
        "{error:?}"
    );
    assert!(
        second
            .publication_is_complete(&object, b"shared-pool acknowledgement")
            .unwrap()
    );
    drop(first);
    spill(&second).unwrap();
    assert_eq!(
        second
            .load_ready(&object.group_id, object.shard_index)
            .unwrap(),
        object
    );
    drop(second);
    let reopened = ParityStore::open_physical_existing_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("parity.db"),
        &[3; 16],
        &[7; 32],
        budget,
    )
    .unwrap();
    assert!(
        reopened
            .publication_is_complete(&object, b"shared-pool acknowledgement")
            .unwrap()
    );
}

#[test]
fn native_parity_preserves_fixed_and_variable_ready_evidence_after_reopen() {
    let (temp, mut store) = setup(limits());
    let fixed = fixed();
    let variable = variable(32768);
    store
        .stage_and_publish_ack(&fixed, b"original acknowledgement", 1 << 20)
        .unwrap();
    store
        .stage_attempt(&[9; 16], &variable, b"original staged receipt", 1 << 20)
        .unwrap();
    store
        .activate_attempt_object(
            &[9; 16],
            &variable.group_id,
            variable.shard_index,
            &variable.commitment,
            &[6; 32],
        )
        .unwrap();
    assert_eq!(
        store
            .load_ready(&fixed.group_id, fixed.shard_index)
            .unwrap(),
        fixed
    );
    assert_eq!(
        store
            .load_ready_variable(&variable.group_id, variable.shard_index)
            .unwrap(),
        variable
    );
    let allocated = store.physical_io_allocated_bytes().unwrap().unwrap();
    let visible = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| std::fs::metadata(e.unwrap().path()).unwrap().blocks() * 512)
        .sum::<u64>();
    assert_eq!(allocated, visible);
    assert!(allocated >= 3 * CHUNK && allocated <= limits().total_bytes);
    drop(store);
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = ParityStore::open_physical_existing_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("parity.db"),
        &[3; 16],
        &[7; 32],
        limits(),
    )
    .unwrap();
    assert!(
        store
            .publication_is_complete(&fixed, b"original acknowledgement")
            .unwrap()
    );
    let ready = store
        .load_ready_variable_object(&variable.group_id, variable.shard_index)
        .unwrap();
    assert_eq!(ready.object, variable);
    assert_eq!(ready.attempt_id, [9; 16]);
    assert_eq!(ready.verification_hash, [6; 32]);
    assert_eq!(ready.staged_receipt, b"original staged receipt");
    drop(store);
    let ordinary =
        ParityStore::open_existing_with_key(temp.path().join("parity.db"), &[3; 16], &[7; 32])
            .unwrap();
    assert_eq!(
        ordinary
            .load_ready(&fixed.group_id, fixed.shard_index)
            .unwrap(),
        fixed
    );
    assert_eq!(
        ordinary
            .load_ready_variable(&variable.group_id, variable.shard_index)
            .unwrap(),
        variable
    );
}

#[test]
fn late_native_parity_allocation_failure_preserves_ready_receipts_and_retries() {
    let mut budget = limits();
    budget.main_bytes = 512 << 10;
    budget.journal_bytes = 512 << 10;
    budget.shm_bytes = CHUNK;
    budget.temporary_bytes = 512 << 10;
    budget.total_bytes = 2 << 20;
    let (_temp, mut store) = setup(budget);
    let fixed = fixed();
    store
        .stage_and_publish_ack(&fixed, b"keep acknowledgement", 1 << 20)
        .unwrap();
    let too_large = variable(2 << 20);
    let error = store
        .stage_attempt(&[9; 16], &too_large, b"uncommitted receipt", 8 << 20)
        .unwrap_err();
    assert!(
        matches!(error, DatabaseError::Sql(ref e) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "{error:?}"
    );
    assert_eq!(
        store
            .object_attempt_state(
                &too_large.group_id,
                u8::try_from(too_large.shard_index).unwrap()
            )
            .unwrap(),
        None
    );
    assert!(
        store
            .publication_is_complete(&fixed, b"keep acknowledgement")
            .unwrap()
    );
    assert_eq!(
        store
            .load_ready(&fixed.group_id, fixed.shard_index)
            .unwrap(),
        fixed
    );
    assert!(store.physical_io_allocated_bytes().unwrap().unwrap() <= budget.total_bytes);
    let small = variable(32768);
    store
        .stage_attempt(&[9; 16], &small, b"retry receipt", 8 << 20)
        .unwrap();
    store
        .activate_attempt_object(
            &[9; 16],
            &small.group_id,
            small.shard_index,
            &small.commitment,
            &[6; 32],
        )
        .unwrap();
    assert_eq!(
        store
            .load_ready_variable(&small.group_id, small.shard_index)
            .unwrap(),
        small
    );
}

#[test]
fn native_parity_creation_and_wrong_volume_reopen_preserve_existing_bytes() {
    let (temp, mut store) = setup(limits());
    let fixed = fixed();
    store.stage_and_publish(&fixed).unwrap();
    drop(store);
    let before = std::fs::read(temp.path().join("parity.db")).unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    assert!(
        ParityStore::create_physical_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("parity.db"),
            &[3; 16],
            &[7; 32],
            limits()
        )
        .is_err()
    );
    assert!(
        ParityStore::open_physical_existing_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("parity.db"),
            &[8; 16],
            &[7; 32],
            limits()
        )
        .is_err()
    );
    assert!(
        ParityStore::open_physical_existing_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("missing.db"),
            &[3; 16],
            &[7; 32],
            limits()
        )
        .is_err()
    );
    assert!(!temp.path().join("missing.db").exists());
    assert_eq!(
        std::fs::read(temp.path().join("parity.db")).unwrap(),
        before
    );
    let store =
        ParityStore::open_existing_with_key(temp.path().join("parity.db"), &[3; 16], &[7; 32])
            .unwrap();
    assert_eq!(
        store
            .load_ready(&fixed.group_id, fixed.shard_index)
            .unwrap(),
        fixed
    );
}

#[test]
fn native_parity_retains_original_directory_for_future_publication() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    let moved = temp.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    let directory = DatabaseDirectory::open(&original).unwrap();
    let mut store = ParityStore::create_physical_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("parity.db"),
        &[3; 16],
        &[7; 32],
        limits(),
    )
    .unwrap();
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("sentinel"), b"preserve").unwrap();
    let fixed = fixed();
    store.stage_and_publish(&fixed).unwrap();
    assert_eq!(
        store
            .load_ready(&fixed.group_id, fixed.shard_index)
            .unwrap(),
        fixed
    );
    assert!(store.physical_io_allocated_bytes().unwrap().unwrap() > 0);
    assert_eq!(std::fs::read_dir(original).unwrap().count(), 1);
    assert!(moved.join("parity.db-wal").is_file());
}
