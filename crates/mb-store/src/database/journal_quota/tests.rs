use super::*;

const MIB: u64 = 1024 * 1024;

#[test]
fn journal_quota_unopened_and_closed_native_journal_handles_have_zero_bytes() {
    let temp = tempfile::tempdir().unwrap();
    let connection = super::super::journal_vfs::connect(
        &temp.path().join("native.db"),
        rusqlite::OpenFlags::default(),
    )
    .unwrap();
    assert_eq!(journal(&connection), 0);
    connection
        .execute_batch("PRAGMA journal_mode=DELETE; CREATE TABLE native_probe(value INTEGER)")
        .unwrap();
    assert_eq!(journal(&connection), 0);
    super::super::journal_vfs::set_limit(&connection, 1024 * 1024).unwrap();
    connection
        .execute_batch("PRAGMA journal_mode=WAL; INSERT INTO native_probe VALUES (1)")
        .unwrap();
    assert!(journal(&connection) > 0);
    assert_eq!(
        connection
            .query_row("SELECT value FROM native_probe", [], |row| row
                .get::<_, u64>(0))
            .unwrap(),
        1
    );
}

fn cap(bytes: u64) -> DatabaseJournalQuota {
    DatabaseJournalQuota { max_bytes: bytes }
}
fn journal(connection: &Connection) -> u64 {
    super::super::journal_vfs::journal_bytes(connection).unwrap()
}

#[test]
fn journal_quota_exhaustion_rolls_back_cached_and_streamed_writers_with_a_held_reader() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [194; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    let mut old = ControlStore::open_existing_with_key(&path, &key).unwrap();
    owner
        .put_record("original", b"one", b"exact original")
        .unwrap();
    old.begin_record_quota_adoption(super::super::DatabaseRecordQuota {
        max_rows: 1000,
        max_accounted_bytes: 8 * MIB,
    })
    .unwrap();
    while old.resume_record_quota_adoption().unwrap().state
        != super::super::DatabaseRecordQuotaState::Active
    {}
    let mut cached = old
        .connection
        .prepare_cached("INSERT INTO protocol_records VALUES ('cached', x'01', ?1)")
        .unwrap();
    let limit = journal(&owner.connection) + 256 * 1024;
    owner.configure_journal_quota(cap(limit)).unwrap();
    let before = old.record_quota_usage().unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    assert_eq!(
        reader.get_record("original", b"one").unwrap().unwrap(),
        b"exact original"
    );
    assert!(cached.execute(params![vec![7_u8; MIB as usize]]).is_err());
    drop(cached);
    assert_eq!(
        super::super::journal_vfs::current_limit(&old.connection).unwrap(),
        limit
    );
    assert!(
        old.put_records_iter((0..32_u64).map(|n| -> anyhow::Result<_> {
            Ok(("batch", n.to_be_bytes(), vec![n as u8; 64 * 1024]))
        }))
        .is_err()
    );
    assert!(old.connection.is_autocommit());
    assert_eq!(old.record_quota_usage().unwrap(), before);
    assert!(
        old.get_record("batch", &0_u64.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert!(old.get_record("cached", &[1]).unwrap().is_none());
    assert!(journal(&old.connection) <= limit);
    assert_eq!(
        reader.get_record("original", b"one").unwrap().unwrap(),
        b"exact original"
    );
    owner.configure_journal_quota(cap(8 * MIB)).unwrap();
    old.put_records_iter((0..32_u64).map(|n| -> anyhow::Result<_> {
        Ok(("batch", n.to_be_bytes(), vec![n as u8; 64 * 1024]))
    }))
    .unwrap();
    assert!(journal(&old.connection) <= 8 * MIB);
    reader.connection.execute_batch("COMMIT").unwrap();
    drop(reader);
    drop(old);
    drop(owner);
    let reopened = ControlStore::open_existing_with_key(&path, &key).unwrap();
    assert_eq!(
        reopened.journal_quota_usage().unwrap().unwrap().quota,
        cap(8 * MIB)
    );
    assert_eq!(
        reopened
            .get_record("batch", &31_u64.to_be_bytes())
            .unwrap()
            .unwrap(),
        vec![31; 64 * 1024]
    );
}

#[test]
fn journal_quota_commit_time_exhaustion_preserves_all_records_and_accounting() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [195; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    owner.put_record("original", b"one", b"exact").unwrap();
    owner
        .configure_journal_quota(cap(journal(&owner.connection) + 256 * 1024))
        .unwrap();
    owner
        .connection
        .pragma_update(None, "cache_spill", false)
        .unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    assert_eq!(
        reader.get_record("original", b"one").unwrap().unwrap(),
        b"exact"
    );
    let produced = std::cell::Cell::new(0);
    assert!(
        owner
            .put_records_iter((0..16_u64).map(|n| -> anyhow::Result<_> {
                produced.set(produced.get() + 1);
                Ok(("commit", n.to_be_bytes(), vec![9; 64 * 1024]))
            }))
            .is_err()
    );
    assert_eq!(
        produced.get(),
        16,
        "the declared small batch must reach COMMIT before journal refusal"
    );
    assert!(owner.connection.is_autocommit());
    assert!(
        owner
            .get_record("commit", &0_u64.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        owner.get_record("original", b"one").unwrap().unwrap(),
        b"exact"
    );
    assert_eq!(
        reader.get_record("original", b"one").unwrap().unwrap(),
        b"exact"
    );
}

#[test]
fn journal_quota_admits_shell_schema_writes_and_preserves_explicit_transactions() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [204; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    let old = ControlStore::open_existing_with_key(&path, &key).unwrap();
    let payload = vec![5; 256 * 1024];
    owner.put_record("original", b"one", &payload).unwrap();
    owner
        .configure_journal_quota(cap(journal(&owner.connection) + 128 * 1024))
        .unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    reader.get_record("original", b"one").unwrap();
    assert!(
        old.database_shell_statement(
            "CREATE INDEX no_space_index ON protocol_records(bytes, bytes, bytes)",
            false
        )
        .is_err()
    );
    assert_eq!(
        old.connection
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE name='no_space_index'",
                [],
                |row| row.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
    assert_eq!(
        old.get_record("original", b"one").unwrap().unwrap(),
        payload
    );
    owner.configure_journal_quota(cap(4 * MIB)).unwrap();
    old.database_shell_statement("/* transaction control */ BEGIN IMMEDIATE", false)
        .unwrap();
    old.database_shell_statement(
        "INSERT INTO protocol_records VALUES ('shell',x'01',x'02')",
        false,
    )
    .unwrap();
    old.database_shell_statement("ROLLBACK", false).unwrap();
    assert!(old.get_record("shell", &[1]).unwrap().is_none());
    old.database_shell_statement("PRAGMA wal_autocheckpoint=1", false)
        .unwrap();
    assert!(
        old.database_shell_statement("not valid SQL", false)
            .is_err()
    );
    assert_eq!(
        old.database_shell_statement("SELECT 1", false)
            .unwrap()
            .rows,
        vec![vec!["1"]]
    );
}

#[test]
fn journal_quota_refuses_inherited_wal_shrink_without_truncation_and_restores_sql_faults() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [196; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    owner.put_record("original", b"one", b"old").unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    reader.get_record("original", b"one").unwrap();
    owner
        .put_record("payload", b"one", &vec![4; MIB as usize])
        .unwrap();
    let bytes = journal(&owner.connection);
    assert!(bytes > MIB);
    let unlimited = super::super::journal_vfs::current_limit(&owner.connection).unwrap();
    assert!(owner.configure_journal_quota(cap(bytes - 1)).is_err());
    assert_eq!(journal(&owner.connection), bytes);
    assert!(owner.journal_quota_usage().unwrap().is_none());
    assert_eq!(
        super::super::journal_vfs::current_limit(&owner.connection).unwrap(),
        unlimited
    );
    owner.configure_journal_quota(cap(4 * MIB)).unwrap();
    for table in [POLICY, GUARD] {
        owner.connection.execute_batch(&format!("CREATE TEMP TRIGGER ignore_journal_policy BEFORE UPDATE ON {table} BEGIN SELECT RAISE(IGNORE); END")).unwrap();
        assert!(owner.configure_journal_quota(cap(8 * MIB)).is_err());
        assert_eq!(
            owner.journal_quota_usage().unwrap().unwrap().quota,
            cap(4 * MIB)
        );
        assert_eq!(
            super::super::journal_vfs::current_limit(&owner.connection).unwrap(),
            4 * MIB
        );
        owner
            .connection
            .execute_batch("DROP TRIGGER ignore_journal_policy")
            .unwrap();
    }
    owner.connection.execute_batch("CREATE TEMP TRIGGER revert_journal_policy AFTER UPDATE ON database_journal_quota_guard BEGIN UPDATE database_journal_quota SET max_bytes=4194304; END").unwrap();
    assert!(owner.configure_journal_quota(cap(8 * MIB)).is_err());
    assert_eq!(
        super::super::journal_vfs::current_limit(&owner.connection).unwrap(),
        4 * MIB
    );
    drop(owner);
    let reopened = ControlStore::open_existing_with_key(&path, &key).unwrap();
    assert!(journal(&reopened.connection) >= bytes);
    assert_eq!(
        reopened.get_record("payload", b"one").unwrap().unwrap(),
        vec![4; MIB as usize]
    );
    assert_eq!(
        reader.get_record("original", b"one").unwrap().unwrap(),
        b"old"
    );
}

#[test]
fn journal_quota_missing_or_changed_policy_refuses_writes_and_reopen() {
    for damage in ["policy", "guard", "mismatch", "schema", "oversized"] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let key = [197; 32];
        let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
        owner.configure_journal_quota(cap(4 * MIB)).unwrap();
        owner.put_record("original", b"one", b"exact").unwrap();
        owner.connection.execute_batch(match damage {
            "policy"=>"DELETE FROM database_journal_quota",
            "guard"=>"DELETE FROM database_journal_quota_guard",
            "mismatch"=>"UPDATE database_journal_quota_guard SET max_bytes=4194305",
            "schema"=>"ALTER TABLE database_journal_quota ADD COLUMN unexpected TEXT",
            "oversized"=>"PRAGMA ignore_check_constraints=ON; UPDATE database_journal_quota SET database_kind=printf('%.*c',65536,'x')",
            _=>unreachable!(),
        }).unwrap();
        assert!(owner.put_record("after", b"one", b"refused").is_err());
        assert!(owner.journal_quota_usage().is_err());
        assert_eq!(
            owner.get_record("original", b"one").unwrap().unwrap(),
            b"exact"
        );
        drop(owner);
        assert!(ControlStore::open_existing_with_key(&path, &key).is_err());
    }
}

#[test]
fn journal_quota_rejects_native_hint_truncate_and_write_beyond_admitted_end() {
    let temp = tempfile::tempdir().unwrap();
    let mut owner =
        ControlStore::open_with_key(temp.path().join("control.db"), &[198; 32]).unwrap();
    owner.configure_journal_quota(cap(MIB)).unwrap();
    owner.put_record("original", b"one", b"exact").unwrap();
    let mut file: *mut ffi::sqlite3_file = std::ptr::null_mut();
    // SQLite owns this live journal object. Only refused growth and optional
    // hints are issued: the original encrypted WAL bytes remain untouched.
    unsafe {
        assert_eq!(
            ffi::sqlite3_file_control(
                owner.connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_JOURNAL_POINTER,
                (&mut file as *mut *mut ffi::sqlite3_file).cast()
            ),
            ffi::SQLITE_OK
        );
        assert!(!file.is_null());
        let methods = &*(*file).pMethods;
        let before = journal(&owner.connection);
        let mut hint = i64::MAX;
        assert_eq!(
            methods.xFileControl.unwrap()(
                file,
                ffi::SQLITE_FCNTL_SIZE_HINT,
                (&mut hint as *mut i64).cast()
            ),
            ffi::SQLITE_OK
        );
        assert_eq!(journal(&owner.connection), before);
        assert_eq!(
            methods.xTruncate.unwrap()(file, MIB as i64 + 1),
            ffi::SQLITE_FULL
        );
        assert_eq!(
            methods.xWrite.unwrap()(file, b"x".as_ptr().cast(), 1, MIB as i64),
            ffi::SQLITE_FULL
        );
        assert_eq!(journal(&owner.connection), before);
    }
    assert_eq!(
        owner.get_record("original", b"one").unwrap().unwrap(),
        b"exact"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn journal_quota_directory_writers_remain_bound_after_parent_replacement() {
    use std::ffi::OsStr;
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    let moved = temp.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    let directory = super::super::DatabaseDirectory::open(&original).unwrap();
    let key = [199; 32];
    let mut owner =
        ControlStore::open_in_directory_with_key(&directory, OsStr::new("control.db"), &key)
            .unwrap();
    owner.configure_journal_quota(cap(256 * 1024)).unwrap();
    owner.put_record("original", b"one", b"exact").unwrap();
    std::fs::rename(&original, &moved).unwrap();
    std::fs::create_dir(&original).unwrap();
    std::fs::write(original.join("control.db"), b"replacement").unwrap();
    let reader =
        ControlStore::open_existing_read_only_with_key(directory.leaf("control.db").unwrap(), &key)
            .unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    reader.get_record("original", b"one").unwrap();
    assert!(
        owner
            .put_record("large", b"one", &vec![8; MIB as usize])
            .is_err()
    );
    assert!(journal(&owner.connection) <= 256 * 1024);
    assert_eq!(
        owner.get_record("original", b"one").unwrap().unwrap(),
        b"exact"
    );
    assert_eq!(
        std::fs::read(original.join("control.db")).unwrap(),
        b"replacement"
    );
    drop(reader);
    drop(owner);
    let reopened = ControlStore::open_existing_in_directory_with_key(
        &directory,
        OsStr::new("control.db"),
        &key,
    )
    .unwrap();
    assert_eq!(
        reopened.journal_quota_usage().unwrap().unwrap().quota,
        cap(256 * 1024)
    );
}

#[test]
fn journal_quota_blob_ranges_and_cursor_faults_preserve_the_previous_reservation() {
    use std::io::Read;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("parity.db");
    let key = [200; 32];
    let volume = [201; 16];
    let attempt = [202; 16];
    let mut owner = ParityStore::open_with_key(&path, &volume, &key).unwrap();
    owner.configure_journal_quota(cap(4 * MIB)).unwrap();
    owner
        .reserve_coding_attempt(&attempt, &[203; 32], 5, 512 * 1024, 4 * MIB)
        .unwrap();
    let mut old = ParityStore::open_with_key(&path, &volume, &key).unwrap();
    let rowid: i64 = owner
        .connection
        .query_row("SELECT rowid FROM coding_reservations", [], |row| {
            row.get(0)
        })
        .unwrap();
    owner.connection.execute_batch("CREATE TEMP TRIGGER ignore_cursor BEFORE UPDATE ON coding_reservations BEGIN SELECT RAISE(IGNORE); END").unwrap();
    assert!(
        owner
            .write_coding_attempt_range(&attempt, 5, 0, &[7; 32])
            .is_err()
    );
    let mut blob = owner
        .connection
        .blob_open(
            rusqlite::MAIN_DB,
            "coding_reservations",
            "bytes",
            rowid,
            true,
        )
        .unwrap();
    let mut bytes = [0; 32];
    blob.read_exact(&mut bytes).unwrap();
    drop(blob);
    assert_eq!(bytes, [0; 32]);
    owner
        .connection
        .execute_batch("DROP TRIGGER ignore_cursor")
        .unwrap();
    let reader = ParityStore::open_existing_read_only_with_key(&path, &volume, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    reader
        .connection
        .query_row("SELECT written_until FROM coding_reservations", [], |row| {
            row.get::<_, u32>(0)
        })
        .unwrap();
    let limit = journal(&owner.connection) + 128 * 1024;
    owner.configure_journal_quota(cap(limit)).unwrap();
    old.connection
        .pragma_update(None, "cache_spill", false)
        .unwrap();
    assert!(
        old.write_coding_attempt_range(&attempt, 5, 0, &vec![9; 512 * 1024])
            .is_err()
    );
    assert!(journal(&old.connection) <= limit);
    assert_eq!(
        old.connection
            .query_row("SELECT written_until FROM coding_reservations", [], |row| {
                row.get::<_, u32>(0)
            })
            .unwrap(),
        0
    );
    let mut blob = old
        .connection
        .blob_open(
            rusqlite::MAIN_DB,
            "coding_reservations",
            "bytes",
            rowid,
            true,
        )
        .unwrap();
    blob.read_exact(&mut bytes).unwrap();
    drop(blob);
    assert_eq!(bytes, [0; 32]);
    owner.configure_journal_quota(cap(4 * MIB)).unwrap();
    assert_eq!(
        old.write_coding_attempt_range(&attempt, 5, 0, &vec![9; 512 * 1024])
            .unwrap(),
        512 * 1024
    );
    assert_eq!(
        old.write_coding_attempt_range(&attempt, 5, 0, &[9; 32])
            .unwrap(),
        512 * 1024
    );
}
