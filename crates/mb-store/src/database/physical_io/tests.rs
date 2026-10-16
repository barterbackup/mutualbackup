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
