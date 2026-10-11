use super::*;

fn generous() -> DatabaseRecordQuota {
    DatabaseRecordQuota {
        max_rows: 100_000,
        max_accounted_bytes: 1024 * 1024 * 1024,
    }
}

fn activate(store: &mut ControlStore) -> DatabaseRecordQuotaUsage {
    store.begin_record_quota_adoption(generous()).unwrap();
    loop {
        let usage = store.resume_record_quota_adoption().unwrap();
        if usage.state == DatabaseRecordQuotaState::Active {
            return usage;
        }
    }
}

fn assert_exact(connection: &Connection) {
    let mut rows = 0_u64;
    let mut bytes = BOOKKEEPING_BYTES;
    for table in tables(connection).unwrap() {
        let sql = format!(
            "SELECT count(*), coalesce(sum({}), 0) FROM {}",
            table.charge(""),
            table.name
        );
        let (count, charge): (u64, u64) = connection
            .query_row(&sql, [], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap();
        rows += count;
        bytes += charge;
    }
    let current = usage(connection).unwrap().unwrap();
    assert_eq!((current.rows, current.accounted_bytes), (rows, bytes));
    assert_eq!(
        connection
            .query_row(
                "SELECT count(*) FROM database_record_quota_guard",
                [],
                |r| r.get::<_, u64>(0)
            )
            .unwrap(),
        0
    );
}

#[test]
fn adoption_length_headers_do_not_materialize_large_text_keys_or_blob_values() {
    use rusqlite::ffi;
    struct LiveStatement(*mut ffi::sqlite3_stmt);
    impl Drop for LiveStatement {
        fn drop(&mut self) {
            // The pointer belongs to this test and is finalized before the
            // owning connection is closed, including on assertion failure.
            unsafe {
                ffi::sqlite3_finalize(self.0);
            }
        }
    }
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [88; 32];
    let store = ControlStore::open_with_key(&path, &key).unwrap();
    let kind = "é".repeat(4 * 1024 * 1024);
    let kind_bytes = kind.len() as u64;
    let body_bytes = 16 * 1024 * 1024_u64;
    store
        .connection
        .execute(
            "INSERT INTO protocol_records VALUES (?1, x'01', zeroblob(?2))",
            params![kind, body_bytes],
        )
        .unwrap();
    drop(kind);
    drop(store);
    let mut store = ControlStore::open_existing_with_key(&path, &key).unwrap();
    let sql = std::ffi::CString::new(format!(
        "SELECT rowid, {} FROM protocol_records ORDER BY rowid LIMIT {ADOPTION_ROWS}",
        CONTROL[1].charge("")
    ))
    .unwrap();
    let mut pointer = std::ptr::null_mut();
    // Preparing/stepping through the linked engine allows us to observe the
    // live statement before reset frees any materialized column registers.
    let prepared = unsafe {
        ffi::sqlite3_prepare_v2(
            store.connection.handle(),
            sql.as_ptr(),
            -1,
            &mut pointer,
            std::ptr::null_mut(),
        )
    };
    let statement = LiveStatement(pointer);
    assert_eq!(prepared, ffi::SQLITE_OK);
    assert_eq!(unsafe { ffi::sqlite3_step(statement.0) }, ffi::SQLITE_ROW);
    let memory =
        unsafe { ffi::sqlite3_stmt_status(statement.0, ffi::SQLITE_STMTSTATUS_MEMUSED, 0) };
    assert!(
        (1..1024 * 1024).contains(&memory),
        "header query materialized a large cell: {memory} bytes"
    );
    let charge = unsafe { ffi::sqlite3_column_int64(statement.0, 1) } as u64;
    assert_eq!(charge, 48 + 3 * (kind_bytes + 1) + body_bytes);
    drop(statement);
    activate(&mut store);
    assert_exact(&store.connection);
}

#[test]
fn preexisting_utf16_database_accounts_stored_text_bytes_consistently_on_writes() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [89; 32];
    let mut connection = super::super::open_encrypted(&path, &key).unwrap();
    connection
        .pragma_update(None, "encoding", "UTF-16le")
        .unwrap();
    super::super::initialize_or_validate_control(&mut connection).unwrap();
    drop(connection);
    let mut store = ControlStore::open_existing_with_key(&path, &key).unwrap();
    let encoding: String = store
        .connection
        .pragma_query_value(None, "encoding", |r| r.get(0))
        .unwrap();
    assert_eq!(encoding, "UTF-16le");
    let baseline = activate(&mut store);
    store.put_record("普通", &[1], &[1, 2, 3]).unwrap();
    assert_exact(&store.connection);
    let after = store.record_quota_usage().unwrap().unwrap();
    assert_eq!(
        after.accounted_bytes - baseline.accounted_bytes,
        48 + 3 * (4 + 1) + 3
    );
    store.put_record("普通", &[1], &[1, 2, 3, 4]).unwrap();
    assert_exact(&store.connection);
    store.delete_record("普通", &[1]).unwrap();
    assert_eq!(store.record_quota_usage().unwrap(), Some(baseline));
}

#[test]
fn adoption_is_bounded_resumable_and_freezes_existing_writers_without_payload_reads() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [81; 32];
    let mut store = ControlStore::open_with_key(&path, &key).unwrap();
    let existing = ControlStore::open_existing_with_key(&path, &key).unwrap();
    for index in 0..300_u64 {
        store
            .put_record("旧", &index.to_be_bytes(), &[index as u8; 4096])
            .unwrap();
    }
    // Implicit rowids need not be positive, including the first cursor.
    store
        .connection
        .execute(
            "UPDATE protocol_records SET rowid = -9 WHERE record_id = ?1",
            [0_u64.to_be_bytes().as_slice()],
        )
        .unwrap();
    store.begin_record_quota_adoption(generous()).unwrap();
    assert!(
        existing
            .put_record("old-writer", b"id", b"must not be added")
            .is_err()
    );
    assert!(
        existing
            .connection
            .execute("DELETE FROM protocol_records", [])
            .is_err()
    );
    let first = store.resume_record_quota_adoption().unwrap();
    assert_eq!(first.scan_table, 1);
    assert_eq!(first.rows, 2);
    let second = store.resume_record_quota_adoption().unwrap();
    assert_eq!(second.rows - first.rows, ADOPTION_ROWS as u64);
    assert_eq!(second.scan_table, 1);
    assert!(second.last_rowid.is_some());
    drop(store);
    let read = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    assert_eq!(read.record_quota_usage().unwrap(), Some(second));
    assert_eq!(
        read.get_record("旧", &0_u64.to_be_bytes())
            .unwrap()
            .unwrap(),
        vec![0; 4096]
    );
    drop(read);
    let mut store = ControlStore::open_existing_with_key(&path, &key).unwrap();
    let mut previous = second;
    loop {
        let next = store.resume_record_quota_adoption().unwrap();
        assert!(next.rows - previous.rows <= ADOPTION_ROWS as u64);
        previous = next;
        if next.state == DatabaseRecordQuotaState::Active {
            break;
        }
    }
    assert_exact(&store.connection);
    existing
        .put_record("old-writer", b"id", b"now accounted")
        .unwrap();
    assert_exact(&store.connection);
    let before = store.record_quota_usage().unwrap().unwrap();
    store
        .begin_record_quota_adoption(DatabaseRecordQuota {
            max_rows: before.rows,
            max_accounted_bytes: before.accounted_bytes,
        })
        .unwrap();
    assert!(
        existing
            .put_record("old-writer", b"other", b"exhausted")
            .is_err()
    );
    assert_eq!(store.get_record("old-writer", b"other").unwrap(), None);
    assert_exact(&store.connection);
}

#[test]
fn every_control_table_utf8_and_secondary_index_is_charged_and_deletion_releases_it() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ControlStore::open_with_key(temp.path().join("control.db"), &[82; 32]).unwrap();
    let baseline = activate(&mut store);
    store.connection.execute_batch("INSERT INTO meta VALUES ('é', x'01');
        INSERT INTO operations VALUES (zeroblob(16), 'op', zeroblob(32), zeroblob(32), 'IN_PROGRESS', zeroblob(1024));
        INSERT INTO checkpoint_signature_locks VALUES (zeroblob(32), 1, zeroblob(32), zeroblob(2048));
        INSERT INTO checkpoint_heads VALUES (zeroblob(32), 1, zeroblob(32), zeroblob(2048));
        INSERT INTO recovery_shards VALUES (zeroblob(32), zeroblob(32), zeroblob(32), 0, zeroblob(32), zeroblob(65536));
        INSERT INTO checkpoint_pages VALUES ('body', zeroblob(32), zeroblob(32), 0, 1, zeroblob(32), zeroblob(4096));").unwrap();
    store
        .put_record("catalog-paged-data-source-v1/é", b"source", &[5; 1024])
        .unwrap();
    assert_exact(&store.connection);
    let charged = store.record_quota_usage().unwrap().unwrap();
    assert_eq!(charged.rows, baseline.rows + 7);
    // Independent hand totals for the seven fixtures, including UTF-8 key
    // bytes, duplicated primary keys and the partial source index entry.
    let source_charge = 40 + 3 * ("catalog-paged-data-source-v1/é".len() + 6) + 1024 + 8;
    assert_eq!(
        charged.accounted_bytes - baseline.accounted_bytes,
        45 + 1173 + 2 * 2192 + 65784 + 4296 + source_charge as u64
    );
    store.connection.execute_batch("UPDATE meta SET key = '长键', value = zeroblob(29) WHERE key = 'é';
        UPDATE checkpoint_pages SET bytes = zeroblob(8192);
        UPDATE protocol_records SET kind = '普通', bytes = x'00';
        INSERT OR REPLACE INTO checkpoint_heads VALUES (zeroblob(32), 2, zeroblob(32), zeroblob(17));").unwrap();
    assert_exact(&store.connection);
    store
        .connection
        .execute_batch(
            "DELETE FROM meta WHERE key = '长键'; DELETE FROM operations;
        DELETE FROM checkpoint_signature_locks; DELETE FROM checkpoint_heads;
        DELETE FROM recovery_shards; DELETE FROM checkpoint_pages; DELETE FROM protocol_records;",
        )
        .unwrap();
    assert_eq!(store.record_quota_usage().unwrap().unwrap(), baseline);
}

#[test]
fn late_capacity_failure_rolls_back_the_entire_existing_streaming_writer() {
    let temp = tempfile::tempdir().unwrap();
    let mut store = ControlStore::open_with_key(temp.path().join("control.db"), &[83; 32]).unwrap();
    store.put_record("stream", b"original", b"keep").unwrap();
    let baseline = activate(&mut store);
    store
        .begin_record_quota_adoption(DatabaseRecordQuota {
            max_rows: baseline.rows + 2,
            ..generous()
        })
        .unwrap();
    let baseline = store.record_quota_usage().unwrap();
    let records = (0..3).map(|i| Ok::<_, DatabaseError>(("stream", [i], [i; 32])));
    assert!(store.put_records_iter(records).is_err());
    assert_eq!(store.record_quota_usage().unwrap(), baseline);
    assert!(store.connection.is_autocommit());
    for i in 0..3 {
        assert_eq!(store.get_record("stream", &[i]).unwrap(), None);
    }
    assert_eq!(
        store.get_record("stream", b"original").unwrap().unwrap(),
        b"keep"
    );
    // Updates that shrink records can proceed even at a full byte budget.
    let baseline = baseline.unwrap();
    store
        .begin_record_quota_adoption(DatabaseRecordQuota {
            max_rows: baseline.rows,
            max_accounted_bytes: baseline.accounted_bytes,
        })
        .unwrap();
    assert!(store.put_record("stream", b"original", &[1; 100]).is_err());
    store.put_record("stream", b"original", b"k").unwrap();
    assert_exact(&store.connection);
}

#[test]
fn ignored_or_reverted_counter_and_guard_writes_fail_closed() {
    for fault in [
        "CREATE TEMP TRIGGER fault BEFORE UPDATE OF used_rows ON main.database_record_quota BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TEMP TRIGGER fault AFTER UPDATE OF used_rows ON main.database_record_quota WHEN NEW.used_rows > OLD.used_rows BEGIN UPDATE database_record_quota SET used_rows = OLD.used_rows, used_bytes = OLD.used_bytes; END",
        "CREATE TEMP TRIGGER fault BEFORE DELETE ON main.database_record_quota_guard BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TEMP TRIGGER fault BEFORE INSERT ON main.database_record_quota_guard BEGIN SELECT RAISE(IGNORE); END",
        "CREATE TEMP TRIGGER fault AFTER INSERT ON main.database_record_quota_guard BEGIN UPDATE database_record_quota_guard SET expected_rows = expected_rows - 1; END",
        "CREATE TEMP TRIGGER fault AFTER UPDATE OF used_rows ON main.database_record_quota WHEN NEW.used_rows > OLD.used_rows BEGIN UPDATE database_record_quota SET max_bytes = max_bytes + 1; END",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut store =
            ControlStore::open_with_key(temp.path().join("control.db"), &[84; 32]).unwrap();
        activate(&mut store);
        let before = store.record_quota_usage().unwrap();
        store.connection.execute_batch(fault).unwrap();
        assert!(
            store.put_record("original", b"id", b"retain").is_err(),
            "{fault}"
        );
        assert_eq!(store.record_quota_usage().unwrap(), before);
        assert_eq!(store.get_record("original", b"id").unwrap(), None);
        store
            .connection
            .execute_batch("DROP TRIGGER temp.fault")
            .unwrap();
        store.put_record("original", b"id", b"retain").unwrap();
        assert_exact(&store.connection);
    }
}

#[test]
fn adoption_exhaustion_and_cursor_faults_preserve_data_and_can_be_aborted() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut store = ControlStore::open_with_key(&path, &[85; 32]).unwrap();
    store.put_record("legacy", b"id", &[7; 65536]).unwrap();
    store
        .begin_record_quota_adoption(DatabaseRecordQuota {
            max_rows: 100,
            max_accounted_bytes: 4096,
        })
        .unwrap();
    store.resume_record_quota_adoption().unwrap();
    let before = store.record_quota_usage().unwrap();
    assert!(matches!(
        store.resume_record_quota_adoption(),
        Err(DatabaseError::RecordCapacityExceeded)
    ));
    assert_eq!(store.record_quota_usage().unwrap(), before);
    assert_eq!(
        store.get_record("legacy", b"id").unwrap().unwrap(),
        vec![7; 65536]
    );
    store.abort_record_quota_adoption().unwrap();
    assert_eq!(store.record_quota_usage().unwrap(), None);
    store
        .put_record("legacy", b"other", b"unconfigured compatibility")
        .unwrap();
    store.begin_record_quota_adoption(generous()).unwrap();
    store.connection.execute_batch("CREATE TEMP TRIGGER fault BEFORE UPDATE ON main.database_record_quota BEGIN SELECT RAISE(IGNORE); END").unwrap();
    let before = store.record_quota_usage().unwrap();
    assert!(store.resume_record_quota_adoption().is_err());
    assert_eq!(store.record_quota_usage().unwrap(), before);
    store
        .connection
        .execute_batch("DROP TRIGGER temp.fault")
        .unwrap();
    activate(&mut store);
    assert!(store.abort_record_quota_adoption().is_err());
    assert_exact(&store.connection);
}

#[test]
fn incomplete_trigger_schema_and_missing_counter_reject_reopen() {
    for corruption in [
        "DROP TRIGGER database_record_quota_protocol_records_insert",
        "DELETE FROM database_record_quota",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let key = [86; 32];
        let mut store = ControlStore::open_with_key(&path, &key).unwrap();
        store.put_record("legacy", b"id", b"preserved").unwrap();
        activate(&mut store);
        store.connection.execute_batch(corruption).unwrap();
        drop(store);
        assert!(ControlStore::open_existing_read_only_with_key(&path, &key).is_err());
        assert!(ControlStore::open_existing_with_key(&path, &key).is_err());
        // Inspect original bytes through an authenticated raw read, without
        // relaxing the store's schema admission policy.
        let raw = super::super::open_encrypted_existing(&path, &key).unwrap();
        assert_eq!(
            raw.query_row(
                "SELECT bytes FROM protocol_records WHERE kind = 'legacy'",
                [],
                |r| r.get::<_, Vec<u8>>(0)
            )
            .unwrap(),
            b"preserved"
        );
    }
}

#[test]
fn parity_reservations_incremental_blob_writes_and_ready_payloads_share_one_quota() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("parity.db");
    let key = [87; 32];
    let volume = [1; 16];
    let mut store = ParityStore::open_with_key(&path, &volume, &key).unwrap();
    store.begin_record_quota_adoption(generous()).unwrap();
    while store.resume_record_quota_adoption().unwrap().state != DatabaseRecordQuotaState::Active {}
    let baseline = store.record_quota_usage().unwrap().unwrap();
    store
        .reserve_coding_attempt(&[2; 16], &[3; 32], 0, 65536, u64::MAX)
        .unwrap();
    assert_exact(&store.connection);
    store.connection.execute_batch("INSERT INTO parity_objects VALUES (2, zeroblob(32), zeroblob(32), 0, zeroblob(32), 65536, 'STAGED', zeroblob(65536), zeroblob(100), NULL, NULL)").unwrap();
    assert_exact(&store.connection);
    let before = store.record_quota_usage().unwrap().unwrap();
    assert_eq!(
        before.accounted_bytes - baseline.accounted_bytes,
        65672 + 65842
    );
    store
        .begin_record_quota_adoption(DatabaseRecordQuota {
            max_rows: before.rows,
            max_accounted_bytes: before.accounted_bytes,
        })
        .unwrap();
    assert!(
        store
            .reserve_coding_attempt(&[4; 16], &[3; 32], 1, 65536, u64::MAX)
            .is_err()
    );
    assert_exact(&store.connection);
    // Incremental BLOB writes cannot change the reserved length; no additional
    // allocation is admitted when the logical quota is already full.
    assert_eq!(
        store
            .write_coding_attempt_range(&[2; 16], 0, 0, &[9; 4096])
            .unwrap(),
        4096
    );
    assert_exact(&store.connection);
    store.connection.execute_batch("UPDATE parity_objects SET state = 'READY'; DELETE FROM coding_reservations; DELETE FROM parity_objects").unwrap();
    let after = store.record_quota_usage().unwrap().unwrap();
    assert_eq!(
        (after.rows, after.accounted_bytes),
        (baseline.rows, baseline.accounted_bytes)
    );
    drop(store);
    let store = ParityStore::open_existing_read_only_with_key(&path, &volume, &key).unwrap();
    assert_eq!(store.record_quota_usage().unwrap(), Some(after));
}
