use super::*;
use crate::ScratchWorkspace;
use std::os::unix::fs::FileExt;

fn workspace(
    control: &ControlStore,
    root: &std::path::Path,
) -> (ScratchWorkspace, ScratchStorageLimits) {
    let limits = ScratchStorageLimits::for_database(2 << 20).unwrap();
    control
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = control
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    (
        ScratchWorkspace::new_in_with_reserved_checkpoint_space(root, limits, &[], lease).unwrap(),
        limits,
    )
}

#[test]
fn workspace_reuses_one_funded_backing_with_fresh_indexes_and_thread_handoff() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let (workspace, limits) = workspace(control, root);
    let _snapshot = SnapshotOnPanic(root);
    let files = anonymous(root);
    assert_eq!(files.len(), 1);
    let identity = (files[0].1.dev(), files[0].1.ino(), files[0].1.blocks());
    let owned = blocks(root);
    assert!(owned >= limits.max_physical_bytes - 2 * 65536 && owned <= limits.max_physical_bytes);
    assert!(workspace.open(4096).is_err());
    assert!(workspace.open(limits.max_database_bytes + 4096).is_err());
    let first = workspace.open(limits.max_database_bytes).unwrap();
    let _first_snapshot = SnapshotOnPanic(root);
    assert!(workspace.clone().open(64 << 10).is_err());
    assert!(
        first
            .put_record_if_absent("workspace", b"old", &vec![0x31; 1 << 20])
            .unwrap()
    );
    drop(first);
    assert_eq!(blocks(root), owned);
    assert!(!control.reclaim_abandoned_catalog_scratch().unwrap());
    let next = workspace.clone();
    let path = root.to_path_buf();
    let second = std::thread::spawn(move || {
        let second = next.open(64 << 10).unwrap();
        let _snapshot = SnapshotOnPanic(&path);
        assert_eq!(
            second
                .get_record_bounded("workspace", b"old", 1 << 20)
                .unwrap(),
            None
        );
        assert!(
            second
                .put_record_if_absent("workspace", b"new", b"thread handoff")
                .unwrap()
        );
        second
    })
    .join()
    .unwrap();
    let _second_snapshot = SnapshotOnPanic(root);
    assert_eq!(
        second.get_record_bounded("workspace", b"new", 64).unwrap(),
        Some(b"thread handoff".to_vec())
    );
    let files = anonymous(root);
    assert_eq!(files.len(), 1);
    assert_eq!(
        (files[0].1.dev(), files[0].1.ino(), files[0].1.blocks()),
        identity
    );
    drop(workspace);
    assert_eq!(
        blocks(root),
        owned,
        "the active index retains its funded workspace"
    );
    assert!(!control.reclaim_abandoned_catalog_scratch().unwrap());
    drop(second);
    assert_eq!(blocks(root), 0);
    assert!(control.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(control), (0, 0));
}

#[test]
fn workspace_keeps_checkout_database_ceiling_and_reuses_after_full_rollback() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let (workspace, limits) = workspace(control, root);
    let index = workspace.open(64 << 10).unwrap();
    let _snapshot = SnapshotOnPanic(root);
    let result: Result<(), DatabaseError> = index.with_record_transaction(|| {
        index.put_record_if_absent("workspace", b"too-large", &vec![7; 128 << 10])?;
        Ok(())
    });
    assert!(
        matches!(result, Err(DatabaseError::Sql(ref e)) if e.sqlite_error().is_some_and(|e| e.extended_code==rusqlite::ffi::SQLITE_FULL))
    );
    assert_eq!(
        index
            .get_record_bounded("workspace", b"too-large", 128 << 10)
            .unwrap(),
        None
    );
    assert!(
        index
            .put_record_if_absent("workspace", b"healthy", b"original ceiling")
            .unwrap()
    );
    let owned = blocks(root);
    drop(index);
    for byte in [1u8, 2, 3] {
        let index = workspace.open(limits.max_database_bytes).unwrap();
        let _snapshot = SnapshotOnPanic(root);
        assert_eq!(
            index
                .get_record_bounded("workspace", b"healthy", 64)
                .unwrap(),
            None
        );
        assert!(
            index
                .put_record_if_absent("workspace", &[byte], &vec![byte; 1 << 20])
                .unwrap()
        );
        assert_eq!(blocks(root), owned);
    }
    drop(workspace);
    assert_eq!(blocks(root), 0);
}

#[test]
fn workspace_rejects_inherited_checkout_and_keeps_the_parent_usable() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let (workspace, limits) = workspace(control, root);
    let _snapshot = SnapshotOnPanic(root);
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let refused = workspace.open(limits.max_database_bytes).is_err();
        unsafe { libc::_exit(if refused { 0 } else { 2 }) };
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0);
    let index = workspace.open(limits.max_database_bytes).unwrap();
    let _index_snapshot = SnapshotOnPanic(root);
    assert!(
        index
            .put_record_if_absent("workspace", b"parent", b"parent data")
            .unwrap()
    );
    assert_eq!(
        index
            .get_record_bounded("workspace", b"parent", 64)
            .unwrap(),
        Some(b"parent data".to_vec())
    );
}

#[test]
fn workspace_retires_corrupt_recycled_backing_instead_of_returning_it_again() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let (workspace, limits) = workspace(control, root);
    let index = workspace.open(limits.max_database_bytes).unwrap();
    let _snapshot = SnapshotOnPanic(root);
    assert!(
        index
            .put_record_if_absent("workspace", b"original", &vec![0x71; 1 << 20])
            .unwrap()
    );
    drop(index);
    let files = anonymous(root);
    assert_eq!(files.len(), 1);
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&files[0].0)
        .unwrap();
    let zero = vec![0; 65536];
    let mut offset = 0;
    while offset < files[0].1.len() {
        let count = (files[0].1.len() - offset).min(zero.len() as u64) as usize;
        file.write_all_at(&zero[..count], offset).unwrap();
        offset += count as u64;
    }
    file.sync_all().unwrap();
    drop(file);
    if let Ok(index) = workspace.open(limits.max_database_bytes) {
        let _index_snapshot = SnapshotOnPanic(root);
        assert!(
            index
                .put_record_if_absent("workspace", b"new", &vec![0x72; 1 << 20])
                .is_err()
        );
    }
    assert!(workspace.open(limits.max_database_bytes).is_err());
    assert_eq!(blocks(root), 0);
    assert!(control.reclaim_abandoned_catalog_scratch().unwrap());
}
