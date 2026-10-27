use super::*;
use crate::ControlStore;
use mb_core::{KeyMaterial, NativeDatabaseIoPolicy, Seed};
use std::ffi::OsStr;

struct Fixture {
    directory: Option<tempfile::TempDir>,
    store: Option<ControlStore>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.take();
        if std::thread::panicking() {
            eprintln!(
                "NATIVE_WAL_COMMIT_NEGATIVE_FIXTURE {}",
                self.directory.take().unwrap().keep().display()
            );
        }
    }
}
fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([131; 32]))
}
fn setup(main: u64) -> Fixture {
    let mut fixture = Fixture {
        directory: Some(tempfile::tempdir().unwrap()),
        store: None,
    };
    let directory = DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap();
    fixture.store = Some(
        ControlStore::create_native_in_directory(
            &directory,
            OsStr::new("control.db"),
            &keys(),
            b"control.db/v2",
            NativeDatabaseIoPolicy {
                format_version: 1,
                policy_id: [132; 16],
                main_bytes: main,
                journal_bytes: 8 << 20,
                shm_bytes: 1 << 20,
                temporary_bytes: 8 << 20,
                total_bytes: 24 << 20,
                headroom_bytes: 0,
                files: 16,
            },
        )
        .unwrap(),
    );
    fixture
        .store
        .as_ref()
        .unwrap()
        .connection
        .pragma_update(None, "wal_autocheckpoint", 0)
        .unwrap();
    fixture
        .store
        .as_ref()
        .unwrap()
        .put_record("wal-commit", b"original", b"original data")
        .unwrap();
    fixture
}
fn reopen(fixture: &mut Fixture) -> ControlStore {
    fixture.store.take();
    ControlStore::open_native_existing_in_directory(
        &DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap(),
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap()
}

#[test]
fn native_wal_commit_control_checks_arguments_and_legacy_remains_unmanaged() {
    use rusqlite::ffi;
    let fixture = setup(8 << 20);
    let store = fixture.store.as_ref().unwrap();
    let before = store.physical_io_allocated_bytes().unwrap();
    let control = |argument: *mut std::ffi::c_void| unsafe {
        ffi::sqlite3_file_control(
            store.connection.handle(),
            c"main".as_ptr(),
            ffi::MUTUALBACKUP_SQLITE_FCNTL_WAL_COMMIT_SIZE,
            argument,
        )
    };
    assert_eq!(control(std::ptr::null_mut()), ffi::SQLITE_MISUSE);
    let mut bytes: i64 = -1;
    assert_eq!(control((&mut bytes as *mut i64).cast()), ffi::SQLITE_MISUSE);
    bytes = 9 << 20;
    assert_eq!(control((&mut bytes as *mut i64).cast()), ffi::SQLITE_FULL);
    bytes = 0;
    assert_eq!(control((&mut bytes as *mut i64).cast()), ffi::SQLITE_OK);
    assert_eq!(store.physical_io_allocated_bytes().unwrap(), before);
    let legacy = ControlStore::open_with_key(
        fixture.directory.as_ref().unwrap().path().join("legacy.db"),
        &[135; 32],
    )
    .unwrap();
    assert_eq!(
        unsafe {
            ffi::sqlite3_file_control(
                legacy.connection.handle(),
                c"main".as_ptr(),
                ffi::MUTUALBACKUP_SQLITE_FCNTL_WAL_COMMIT_SIZE,
                std::ptr::null_mut(),
            )
        },
        ffi::SQLITE_NOTFOUND
    );
    legacy
        .put_record("legacy", b"original", b"legacy commit remains writable")
        .unwrap();
    assert_eq!(
        legacy.get_record("legacy", b"original").unwrap(),
        Some(b"legacy commit remains writable".to_vec())
    );
}

#[test]
fn native_wal_admission_yields_to_checkpoint_without_publishing() {
    use rusqlite::{Connection, ffi};
    struct Checkpoint<'a> {
        file: *mut ffi::sqlite3_file,
        _connection: &'a Connection,
        active: bool,
    }
    impl Checkpoint<'_> {
        fn unlock(&mut self) -> i32 {
            let rc = unsafe {
                ((*(*self.file).pMethods).xShmLock.unwrap())(
                    self.file,
                    1,
                    1,
                    ffi::SQLITE_SHM_UNLOCK | ffi::SQLITE_SHM_EXCLUSIVE,
                )
            };
            if rc == ffi::SQLITE_OK {
                self.active = false;
            }
            rc
        }
    }
    impl Drop for Checkpoint<'_> {
        fn drop(&mut self) {
            if self.active && self.unlock() != ffi::SQLITE_OK {
                eprintln!("checkpoint test lock cleanup failed");
            }
        }
    }
    let mut fixture = setup(8 << 20);
    let directory = DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap();
    let peer = ControlStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(
        peer.get_record("wal-commit", b"original").unwrap(),
        Some(b"original data".to_vec())
    );
    let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
    assert_eq!(
        unsafe {
            ffi::sqlite3_file_control(
                peer.connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_FILE_POINTER,
                (&mut file as *mut *mut ffi::sqlite3_file).cast(),
            )
        },
        ffi::SQLITE_OK
    );
    assert!(!file.is_null());
    assert_eq!(
        unsafe {
            ((*(*file).pMethods).xShmLock.unwrap())(
                file,
                1,
                1,
                ffi::SQLITE_SHM_LOCK | ffi::SQLITE_SHM_EXCLUSIVE,
            )
        },
        ffi::SQLITE_OK
    );
    let mut checkpoint = Checkpoint {
        file,
        _connection: &peer.connection,
        active: true,
    };
    let store = fixture.store.as_ref().unwrap();
    let path = fixture
        .directory
        .as_ref()
        .unwrap()
        .path()
        .join("control.db");
    let allocated = std::fs::metadata(&path).unwrap().blocks();
    let payload = vec![136; 1 << 20];
    let result = store.put_record("wal-commit", b"checkpoint-contended", &payload);
    assert!(
        matches!(result, Err(DatabaseError::Sql(ref e)) if e.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy)),
        "commit crossed an active checkpoint: {result:?}"
    );
    assert_eq!(std::fs::metadata(&path).unwrap().blocks(), allocated);
    assert!(
        store
            .get_record("wal-commit", b"checkpoint-contended")
            .unwrap()
            .is_none()
    );
    assert_eq!(checkpoint.unlock(), ffi::SQLITE_OK);
    drop(checkpoint);
    drop(peer);
    store
        .put_record("wal-commit", b"checkpoint-contended", &payload)
        .unwrap();
    let store = reopen(&mut fixture);
    assert_eq!(
        store
            .get_record("wal-commit", b"checkpoint-contended")
            .unwrap(),
        Some(payload)
    );
    assert_eq!(
        store.get_record("wal-commit", b"original").unwrap(),
        Some(b"original data".to_vec())
    );
}

#[test]
fn native_wal_refuses_commit_when_future_main_exceeds_immutable_ceiling() {
    let mut fixture = setup(2 << 20);
    let store = fixture.store.as_ref().unwrap();
    let result: Result<(), DatabaseError> = store.with_record_transaction(|| {
        store.put_record("wal-commit", b"partial", b"must roll back")?;
        store.put_record("wal-commit", b"oversized", &vec![133; 3 << 20])?;
        Ok(())
    });
    assert!(
        matches!(result,Err(DatabaseError::Sql(ref e)) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "WAL committed an unfundable main database: {result:?}"
    );
    for key in [b"partial".as_slice(), b"oversized"] {
        assert!(store.get_record("wal-commit", key).unwrap().is_none());
    }
    store
        .put_record("wal-commit", b"retry", b"ordinary retry remains healthy")
        .unwrap();
    let store = reopen(&mut fixture);
    assert_eq!(
        store.get_record("wal-commit", b"original").unwrap(),
        Some(b"original data".to_vec())
    );
    assert_eq!(
        store.get_record("wal-commit", b"retry").unwrap(),
        Some(b"ordinary retry remains healthy".to_vec())
    );
    for key in [b"partial".as_slice(), b"oversized"] {
        assert!(store.get_record("wal-commit", key).unwrap().is_none());
    }
}

#[test]
fn native_wal_commit_funds_exact_main_extent_before_blocked_checkpoint() {
    let mut fixture = setup(8 << 20);
    let directory = DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap();
    let reader = ControlStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    let snapshot = reader.connection.unchecked_transaction().unwrap();
    let count: u64 = snapshot
        .query_row("SELECT count(*) FROM protocol_records", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert!(count > 0);
    let path = fixture
        .directory
        .as_ref()
        .unwrap()
        .path()
        .join("control.db");
    let before = std::fs::metadata(&path).unwrap();
    let store = fixture.store.as_ref().unwrap();
    let payload = vec![134; 1 << 20];
    store.put_record("wal-commit", b"funded", &payload).unwrap();
    let pages: u64 = store
        .connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap();
    let page_size: String = store
        .connection
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .unwrap();
    let page_size: u64 = page_size.parse().unwrap();
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!(
        after.len(),
        before.len(),
        "WAL commit must not extend the logical main file"
    );
    assert!(
        after.blocks() * 512 >= pages * page_size,
        "committed WAL lacks future main backing: allocated={} required={}",
        after.blocks() * 512,
        pages * page_size
    );
    assert!(
        after.blocks() * 512 < 8 << 20,
        "fund the current main size, not its ceiling"
    );
    let mut descriptor = -1;
    assert_eq!(
        unsafe {
            rusqlite::ffi::sqlite3_file_control(
                store.connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD,
                (&mut descriptor as *mut i32).cast(),
            )
        },
        rusqlite::ffi::SQLITE_OK
    );
    assert_eq!(
        private_missing_bytes(descriptor, 0, pages * page_size).unwrap(),
        0
    );
    assert!(
        reader
            .get_record("wal-commit", b"funded")
            .unwrap()
            .is_none()
    );
    snapshot.rollback().unwrap();
    drop(reader);
    let (busy, _, _): (u32, u32, u32) = store
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .unwrap();
    assert_eq!(busy, 0);
    let store = reopen(&mut fixture);
    assert_eq!(
        store.get_record("wal-commit", b"funded").unwrap(),
        Some(payload)
    );
    assert_eq!(
        store.get_record("wal-commit", b"original").unwrap(),
        Some(b"original data".to_vec())
    );
}
