use super::*;
use crate::ControlStore;
use rusqlite::{Transaction, TransactionBehavior};

fn limits() -> DatabasePhysicalIoLimits {
    DatabasePhysicalIoLimits {
        main_bytes: 2 << 20,
        journal_bytes: 4 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 8 << 20,
        total_bytes: 16 << 20,
        headroom_bytes: 0,
        files: 16,
    }
}
fn setup(limits: DatabasePhysicalIoLimits) -> (tempfile::TempDir, ControlStore) {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = ControlStore::create_physical_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &[7; 32],
        limits,
    )
    .unwrap();
    (temp, store)
}
fn allocated(path: impl AsRef<std::path::Path>) -> u64 {
    std::fs::metadata(path).unwrap().blocks() * 512
}

#[test]
fn native_runtime_allocates_main_wal_and_shm_without_extending_to_their_ceiling() {
    let (temp, store) = setup(limits());
    let payload = vec![9; 32 * 1024];
    store.put_record("physical", b"original", &payload).unwrap();
    assert_eq!(
        store.get_record("physical", b"original").unwrap(),
        Some(payload)
    );
    let total = store.physical_io_allocated_bytes().unwrap().unwrap();
    let visible = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| allocated(e.unwrap().path()))
        .sum::<u64>();
    assert_eq!(total, visible);
    assert!(total >= 3 * CHUNK && total <= limits().total_bytes);
    for (name, ceiling) in [
        ("control.db", limits().main_bytes),
        ("control.db-wal", limits().journal_bytes),
        ("control.db-shm", limits().shm_bytes),
    ] {
        let metadata = std::fs::metadata(temp.path().join(name)).unwrap();
        assert!(metadata.len() > 0 && metadata.len() < ceiling, "{name}");
        assert!(metadata.blocks() * 512 >= metadata.len(), "{name}");
    }
}

#[test]
fn late_native_extent_exhaustion_rolls_back_the_complete_sql_transaction() {
    let mut budget = limits();
    budget.main_bytes = 512 * 1024;
    budget.journal_bytes = 512 * 1024;
    budget.shm_bytes = CHUNK;
    budget.total_bytes = 2 << 20;
    budget.temporary_bytes = 512 * 1024;
    let (_temp, store) = setup(budget);
    store
        .put_record("physical", b"preserve", b"committed")
        .unwrap();
    let result: Result<(), DatabaseError> = store.with_record_transaction(|| {
        store.put_record("physical", b"preserve", b"must roll back")?;
        store.put_record("physical", b"over-limit", &vec![5; 2 << 20])?;
        Ok(())
    });
    let error = result.expect_err("a transaction exceeded the native journal allocation ceiling");
    assert!(
        matches!(error,DatabaseError::Sql(ref e) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "{error:?}"
    );
    assert_eq!(
        store.get_record("physical", b"preserve").unwrap(),
        Some(b"committed".to_vec())
    );
    assert_eq!(store.get_record("physical", b"over-limit").unwrap(), None);
    assert!(store.physical_io_allocated_bytes().unwrap().unwrap() <= budget.total_bytes);
    store
        .put_record("physical", b"retry", b"small successful retry")
        .unwrap();
    assert_eq!(
        store.get_record("physical", b"retry").unwrap(),
        Some(b"small successful retry".to_vec())
    );
}

#[test]
fn closed_persistent_rollback_journal_keeps_its_real_allocation_charged() {
    let (temp, store) = setup(limits());
    let mode: String = store
        .connection
        .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "delete");
    let mode: String = store
        .connection
        .query_row("PRAGMA journal_mode=PERSIST", [], |r| r.get(0))
        .unwrap();
    assert_eq!(mode, "persist");
    store
        .put_record("physical", b"journal", &vec![8; 16 * 1024])
        .unwrap();
    let main = allocated(temp.path().join("control.db"));
    let journal = allocated(temp.path().join("control.db-journal"));
    assert!(journal >= CHUNK);
    assert!(store.physical_io_allocated_bytes().unwrap().unwrap() >= main + journal);
    store
        .put_record("physical", b"again", b"same journal")
        .unwrap();
    assert_eq!(
        store.get_record("physical", b"journal").unwrap(),
        Some(vec![8; 16 * 1024])
    );
}

#[test]
fn native_sql_temporary_spill_uses_admitted_anonymous_extents() {
    let mut budget = limits();
    budget.temporary_bytes = 16 << 20;
    budget.total_bytes = 32 << 20;
    let (temp, store) = setup(budget);
    store.connection.execute_batch("PRAGMA temp_store=FILE; PRAGMA temp.cache_size=8; CREATE TEMP TABLE spill(id INTEGER PRIMARY KEY,bytes BLOB);").unwrap();
    let tx = Transaction::new_unchecked(&store.connection, TransactionBehavior::Immediate).unwrap();
    let payload = vec![3u8; 32768];
    for i in 0..128 {
        tx.execute(
            "INSERT INTO temp.spill VALUES (?1,?2)",
            rusqlite::params![i, payload],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let (rows, bytes): (u64, u64) = store
        .connection
        .query_row(
            "SELECT count(*),sum(length(bytes)) FROM temp.spill",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!((rows, bytes), (128, 128 * 32768));
    let visible = std::fs::read_dir(temp.path())
        .unwrap()
        .map(|e| allocated(e.unwrap().path()))
        .sum::<u64>();
    let total = store.physical_io_allocated_bytes().unwrap().unwrap();
    assert!(
        total >= visible + bytes,
        "temporary spill did not retain anonymous backing: total={total} visible={visible} bytes={bytes}"
    );
    assert!(total <= budget.total_bytes);
    assert!(std::fs::read_dir(temp.path()).unwrap().all(|e| {
        e.unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("control.db")
    }));
}

#[test]
fn runtime_physical_store_retains_its_directory_after_rename() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    let moved = temp.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    let directory = DatabaseDirectory::open(&original).unwrap();
    let store = ControlStore::create_physical_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &[7; 32],
        limits(),
    )
    .unwrap();
    store
        .put_record("physical", b"before", b"original")
        .unwrap();
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("sentinel"), b"preserve").unwrap();
    store
        .put_record("physical", b"after", &vec![5; 64 * 1024])
        .unwrap();
    assert_eq!(
        store.get_record("physical", b"after").unwrap(),
        Some(vec![5; 64 * 1024])
    );
    assert!(store.physical_io_allocated_bytes().unwrap().unwrap() > 0);
    assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
    assert_eq!(
        std::fs::read(original.join("sentinel")).unwrap(),
        b"preserve"
    );
}

#[test]
fn physical_creation_never_replaces_an_existing_generic_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    store
        .put_record("physical", b"preserve", b"generic source")
        .unwrap();
    drop(store);
    let before = std::fs::read(&path).unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    assert!(
        ControlStore::create_physical_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("control.db"),
            &[7; 32],
            limits()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(
        ControlStore::open_with_key(&path, &[7; 32])
            .unwrap()
            .get_record("physical", b"preserve")
            .unwrap(),
        Some(b"generic source".to_vec())
    );
}

#[test]
fn physical_reopen_preserves_native_sql_bytes_and_never_creates_a_missing_main() {
    let (temp, store) = setup(limits());
    store
        .put_record("physical", b"reopen", b"retained bytes")
        .unwrap();
    drop(store);
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = ControlStore::open_physical_existing_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &[7; 32],
        limits(),
    )
    .unwrap();
    assert_eq!(
        store.get_record("physical", b"reopen").unwrap(),
        Some(b"retained bytes".to_vec())
    );
    store
        .put_record("physical", b"after", b"future native write")
        .unwrap();
    drop(store);
    let before = std::fs::read(temp.path().join("control.db")).unwrap();
    assert!(
        ControlStore::open_physical_existing_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("missing.db"),
            &[7; 32],
            limits(),
        )
        .is_err()
    );
    assert!(!temp.path().join("missing.db").exists());
    assert_eq!(
        std::fs::read(temp.path().join("control.db")).unwrap(),
        before
    );
    let ordinary = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    assert_eq!(
        ordinary.get_record("physical", b"after").unwrap(),
        Some(b"future native write".to_vec())
    );
}

#[test]
fn native_journal_recovery_survives_process_exit_with_uncommitted_spill() {
    const CASE: &str = "database::physical_io::tests::native_journal_recovery_survives_process_exit_with_uncommitted_spill";
    if let Some(path) = std::env::var_os("MB_PHYSICAL_RECOVERY_CHILD") {
        let directory = DatabaseDirectory::open(std::path::Path::new(&path)).unwrap();
        let mut budget = limits();
        budget.main_bytes = 8 << 20;
        budget.journal_bytes = 16 << 20;
        budget.total_bytes = 32 << 20;
        let store = ControlStore::create_physical_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("control.db"),
            &[7; 32],
            budget,
        )
        .unwrap();
        store
            .put_record("physical", b"preserve", b"committed before crash")
            .unwrap();
        store
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let mode = std::env::var("MB_PHYSICAL_RECOVERY_MODE").unwrap();
        assert!(["WAL", "DELETE", "PERSIST", "TRUNCATE"].contains(&mode.as_str()));
        store
            .connection
            .pragma_update(None, "journal_mode", &mode)
            .unwrap();
        store
            .connection
            .execute_batch("PRAGMA cache_size=8; BEGIN IMMEDIATE")
            .unwrap();
        store
            .put_record("physical", b"preserve", b"uncommitted change")
            .unwrap();
        for i in 0u32..48 {
            store
                .put_record("physical", &i.to_be_bytes(), &vec![5; 32768])
                .unwrap();
        }
        // Do not run Connection/Transaction destructors: recovery must use the
        // real native WAL or hot rollback journal left by a terminated writer.
        std::process::exit(0);
    }
    for mode in ["WAL", "DELETE", "PERSIST", "TRUNCATE"] {
        let temp = tempfile::tempdir().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([CASE, "--exact", "--nocapture", "--test-threads=1"])
            .env("MB_PHYSICAL_RECOVERY_CHILD", temp.path())
            .env("MB_PHYSICAL_RECOVERY_MODE", mode)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let suffix = if mode == "WAL" { "-wal" } else { "-journal" };
        assert!(
            std::fs::metadata(temp.path().join(format!("control.db{suffix}")))
                .unwrap()
                .len()
                > 4096,
            "{mode}"
        );
        // Recovery uses the ordinary bundled adapter, independently of the
        // physical VFS's EOF/preallocation and SHM admission implementation.
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        assert_eq!(
            store.get_record("physical", b"preserve").unwrap(),
            Some(b"committed before crash".to_vec()),
            "{mode}"
        );
        for i in 0u32..48 {
            assert_eq!(
                store.get_record("physical", &i.to_be_bytes()).unwrap(),
                None,
                "{mode}/{i}"
            );
        }
        store
            .put_record("physical", b"retry", b"recovered writer")
            .unwrap();
    }
}

fn owned_btrfs_test_directory() -> tempfile::TempDir {
    let mount = std::env::var_os("MB_PHYSICAL_OWNED_MOUNT")
        .expect("provision an owned disposable Btrfs mount");
    let mount = std::path::Path::new(&mount);
    let info = std::fs::read_to_string("/proc/self/mountinfo").unwrap();
    assert!(
        info.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields
                .get(4)
                .is_some_and(|p| std::path::Path::new(p) == mount)
                && line.contains(" - btrfs /dev/loop")
        }),
        "the explicitly owned test mount must be a Btrfs loop filesystem"
    );
    let temp = tempfile::tempdir_in(mount).unwrap();
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    assert_eq!(
        unsafe { libc::fstatfs(directory.file().as_raw_fd(), filesystem.as_mut_ptr()) },
        0
    );
    assert_eq!(
        unsafe { filesystem.assume_init() }.f_type as u32,
        libc::BTRFS_SUPER_MAGIC as u32
    );
    temp
}

#[test]
#[ignore = "requires an explicitly owned disposable Btrfs loop mount"]
fn closed_reflinked_native_catalog_refuses_shared_backing_before_main_write() {
    let temp = owned_btrfs_test_directory();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = ControlStore::create_physical_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &[7; 32],
        limits(),
    )
    .unwrap();
    store
        .put_record("physical", b"preserve", b"original closed catalog")
        .unwrap();
    drop(store);
    let original = temp.path().join("control.db");
    let before = std::fs::read(&original).unwrap();
    let source = OpenOptions::new().read(true).open(&original).unwrap();
    let copy = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp.path().join("closed-copy.db"))
        .unwrap();
    initialize_private_file(copy.as_raw_fd(), 0, 0).unwrap();
    // Both SQL connections are closed. This creates known shared extents in
    // a stopped fixture; no live database is reflinked or modified externally.
    assert_eq!(
        unsafe {
            libc::ioctl(
                copy.as_raw_fd(),
                0x4004_9409 as libc::c_ulong,
                source.as_raw_fd(),
            )
        },
        0
    );
    copy.sync_all().unwrap();
    assert!(matches!(
        private_missing_bytes(source.as_raw_fd(), 0, CHUNK),
        Err(DatabaseError::PhysicalIoUnavailable)
    ));
    drop(source);
    drop(copy);
    let store = ControlStore::open_physical_existing_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &[7; 32],
        limits(),
    )
    .unwrap();
    store
        .connection
        .execute_batch("PRAGMA journal_mode=DELETE")
        .unwrap();
    let error = store
        .put_record("physical", b"preserve", b"must not replace shared pages")
        .unwrap_err();
    assert!(
        matches!(error, DatabaseError::Sql(ref e) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "{error:?}"
    );
    assert_eq!(
        store.get_record("physical", b"preserve").unwrap(),
        Some(b"original closed catalog".to_vec())
    );
    drop(store);
    assert_eq!(std::fs::read(original).unwrap(), before);
    assert_eq!(
        std::fs::read(temp.path().join("closed-copy.db")).unwrap(),
        before
    );
}

#[test]
#[ignore = "fills only an explicitly owned disposable Btrfs loop filesystem"]
fn real_native_filesystem_exhaustion_rolls_back_and_retries_after_space_returns() {
    let temp = owned_btrfs_test_directory();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let mut budget = limits();
    budget.main_bytes = 64 << 20;
    budget.journal_bytes = 128 << 20;
    budget.total_bytes = 256 << 20;
    let store = ControlStore::create_physical_in_directory_with_key(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &[7; 32],
        budget,
    )
    .unwrap();
    store
        .put_record("physical", b"preserve", b"committed before exhaustion")
        .unwrap();
    let filler_path = temp.path().join("owned-filler");
    let filler = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&filler_path)
        .unwrap();
    let mut offset = 0i64;
    let mut kernel_enospc = false;
    for chunk in [128 << 20, 8 << 20, 1 << 20, 64 << 10, 4096] {
        loop {
            assert!(
                offset < 8i64 << 30,
                "owned fixture unexpectedly exceeds its 4 GiB bound"
            );
            if unsafe {
                libc::fallocate(filler.as_raw_fd(), libc::FALLOC_FL_KEEP_SIZE, offset, chunk)
            } == 0
            {
                offset += chunk;
                continue;
            }
            let error = io::Error::last_os_error();
            assert_eq!(error.raw_os_error(), Some(libc::ENOSPC), "{error}");
            kernel_enospc = true;
            break;
        }
    }
    assert!(kernel_enospc && offset > 1 << 30);
    let error = store
        .with_record_transaction(|| {
            store.put_record("physical", b"preserve", b"must roll back")?;
            store.put_record("physical", b"too-large", &vec![6; 8 << 20])
        })
        .unwrap_err();
    assert!(
        matches!(error, DatabaseError::Sql(ref e) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "{error:?}"
    );
    assert_eq!(
        store.get_record("physical", b"preserve").unwrap(),
        Some(b"committed before exhaustion".to_vec())
    );
    assert_eq!(store.get_record("physical", b"too-large").unwrap(), None);
    assert!(store.physical_io_allocated_bytes().unwrap().unwrap() < budget.total_bytes);
    drop(filler);
    std::fs::remove_file(filler_path).unwrap();
    store
        .put_record("physical", b"retry", &vec![8; 1 << 20])
        .unwrap();
    assert_eq!(
        store.get_record("physical", b"retry").unwrap(),
        Some(vec![8; 1 << 20])
    );
}
