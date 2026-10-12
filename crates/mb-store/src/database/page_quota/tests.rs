use super::*;

fn pages(connection: &Connection) -> u64 {
    connection
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .unwrap()
}

fn pager_limit(connection: &Connection) -> u64 {
    connection
        .pragma_query_value(None, "max_page_count", |row| row.get(0))
        .unwrap()
}

#[test]
fn page_quota_bounds_atomic_batches_on_old_connections_and_cached_statements() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [186; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    let mut old = ControlStore::open_existing_with_key(&path, &key).unwrap();
    old.put_record("paged", b"original", b"preserved").unwrap();
    old.begin_record_quota_adoption(super::super::DatabaseRecordQuota {
        max_rows: 1000,
        max_accounted_bytes: 16 * 1024 * 1024,
    })
    .unwrap();
    while old.resume_record_quota_adoption().unwrap().state
        != super::super::DatabaseRecordQuotaState::Active
    {}
    let mut cached = old
        .connection
        .prepare_cached("INSERT INTO protocol_records VALUES ('cached', ?1, ?2)")
        .unwrap();
    let quota = DatabasePageQuota {
        max_pages: pages(&owner.connection) + 96,
    };
    owner.configure_page_quota(quota).unwrap();
    let before = old.record_quota_usage().unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    assert_eq!(
        reader.get_record("paged", b"original").unwrap().unwrap(),
        b"preserved"
    );
    // The already prepared statement must observe the newly installed trigger.
    assert!(
        cached
            .execute(params![b"large", vec![9_u8; 1024 * 1024]])
            .is_err()
    );
    assert_eq!(pager_limit(&old.connection), quota.max_pages);
    drop(cached);
    let produced = std::cell::Cell::new(0);
    assert!(
        old.put_records_iter((0..32_u64).map(|n| -> anyhow::Result<_> {
            produced.set(produced.get() + 1);
            Ok(("batch", n.to_be_bytes(), vec![n as u8; 64 * 1024]))
        }))
        .is_err()
    );
    assert!((2..32).contains(&produced.get()));
    assert!(old.connection.is_autocommit());
    assert_eq!(old.record_quota_usage().unwrap(), before);
    assert!(
        old.get_record("batch", &0_u64.to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert!(old.get_record("cached", b"large").unwrap().is_none());
    assert_eq!(
        reader.get_record("paged", b"original").unwrap().unwrap(),
        b"preserved"
    );
    assert!(pages(&old.connection) <= quota.max_pages);
    reader.connection.execute_batch("COMMIT").unwrap();
    drop(reader);
    drop(old);
    drop(owner);
    let reopened = ControlStore::open_existing_with_key(&path, &key).unwrap();
    assert_eq!(reopened.page_quota_usage().unwrap().unwrap().quota, quota);
    assert_eq!(pager_limit(&reopened.connection), quota.max_pages);
    assert_eq!(
        reopened.get_record("paged", b"original").unwrap().unwrap(),
        b"preserved"
    );
}

#[test]
fn page_quota_grows_and_shrinks_across_connections_without_counting_only_live_rows() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [187; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    let old = ControlStore::open_existing_with_key(&path, &key).unwrap();
    owner
        .configure_page_quota(DatabasePageQuota { max_pages: 512 })
        .unwrap();
    old.put_record("payload", b"one", &vec![1; 512 * 1024])
        .unwrap();
    let full_pages = pages(&old.connection);
    assert!(full_pages > 64);
    old.delete_record("payload", b"one").unwrap();
    assert!(pages(&old.connection) >= full_pages);
    let before = owner.page_quota_usage().unwrap();
    assert!(
        owner
            .configure_page_quota(DatabasePageQuota {
                max_pages: full_pages - 1
            })
            .is_err()
    );
    assert_eq!(owner.page_quota_usage().unwrap(), before);
    let small = DatabasePageQuota {
        max_pages: pages(&owner.connection) + 8,
    };
    owner.configure_page_quota(small).unwrap();
    // Raising an old connection's pragma does not bypass the persisted writer fence.
    old.connection
        .pragma_update(None, "max_page_count", 4096)
        .unwrap();
    assert!(
        old.put_record("payload", b"two", &vec![2; 1024 * 1024])
            .is_err()
    );
    assert_eq!(pager_limit(&old.connection), small.max_pages);
    owner
        .configure_page_quota(DatabasePageQuota { max_pages: 1024 })
        .unwrap();
    old.put_record("payload", b"two", &vec![2; 1024 * 1024])
        .unwrap();
    assert_eq!(pager_limit(&old.connection), 1024);
}

#[test]
fn page_quota_refused_installation_and_sql_faults_restore_the_previous_pager_limit() {
    let temp = tempfile::tempdir().unwrap();
    let mut store =
        ControlStore::open_with_key(temp.path().join("control.db"), &[188; 32]).unwrap();
    store
        .put_record("original", b"one", b"exact original")
        .unwrap();
    let original_limit = pager_limit(&store.connection);
    for max_pages in [0, 1, u64::MAX] {
        assert!(
            store
                .configure_page_quota(DatabasePageQuota { max_pages })
                .is_err()
        );
        assert_eq!(store.page_quota_usage().unwrap(), None);
        assert_eq!(pager_limit(&store.connection), original_limit);
        store
            .put_record("still writable", b"one", b"valid")
            .unwrap();
    }
    store
        .configure_page_quota(DatabasePageQuota { max_pages: 256 })
        .unwrap();
    let before = store.page_quota_usage().unwrap();
    for table in [POLICY, GUARD] {
        store.connection.execute_batch(&format!("CREATE TEMP TRIGGER ignore_page_policy BEFORE UPDATE ON {table} BEGIN SELECT RAISE(IGNORE); END")).unwrap();
        assert!(
            store
                .configure_page_quota(DatabasePageQuota { max_pages: 512 })
                .is_err()
        );
        assert_eq!(store.page_quota_usage().unwrap(), before);
        assert_eq!(pager_limit(&store.connection), 256);
        store
            .connection
            .execute_batch("DROP TRIGGER ignore_page_policy")
            .unwrap();
    }
    store.connection.execute_batch("CREATE TEMP TRIGGER revert_page_policy AFTER UPDATE ON database_page_quota_guard BEGIN UPDATE database_page_quota SET max_pages=256; END").unwrap();
    assert!(
        store
            .configure_page_quota(DatabasePageQuota { max_pages: 512 })
            .is_err()
    );
    assert_eq!(store.page_quota_usage().unwrap(), before);
    assert_eq!(pager_limit(&store.connection), 256);
    assert_eq!(
        store.get_record("original", b"one").unwrap().unwrap(),
        b"exact original"
    );
}

#[test]
fn page_quota_missing_rows_and_schema_are_rejected_on_writes_and_reopen() {
    for damage in [
        "policy",
        "guard",
        "mismatch",
        "trigger",
        "oversized",
        "count",
        "schema",
        "meta-schema",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let key = [189; 32];
        let mut store = ControlStore::open_with_key(&path, &key).unwrap();
        store
            .configure_page_quota(DatabasePageQuota { max_pages: 256 })
            .unwrap();
        store.put_record("original", b"one", b"exact").unwrap();
        store
            .connection
            .execute_batch(match damage {
                "policy" => "DELETE FROM database_page_quota",
                "guard" => "DELETE FROM database_page_quota_guard",
                "mismatch" => "UPDATE database_page_quota_guard SET max_pages=257",
            "trigger" => "DROP TRIGGER database_page_quota_protocol_records_insert",
            "oversized" => "PRAGMA ignore_check_constraints=ON; UPDATE database_page_quota SET database_kind=printf('%.*c',65536,'x')",
            "count" => "PRAGMA ignore_check_constraints=ON; INSERT INTO database_page_quota SELECT 2, format_version, database_kind, page_bytes, max_pages FROM database_page_quota",
            "schema" => "ALTER TABLE database_page_quota ADD COLUMN unexpected TEXT",
            "meta-schema" => "ALTER TABLE meta ADD COLUMN unexpected TEXT",
                _ => unreachable!(),
            })
            .unwrap();
        if damage != "trigger" {
            assert!(store.put_record("after", b"one", b"refused").is_err());
            assert!(store.page_quota_usage().is_err());
        }
        assert_eq!(
            store.get_record("original", b"one").unwrap().unwrap(),
            b"exact"
        );
        drop(store);
        assert!(ControlStore::open_existing_with_key(&path, &key).is_err());
    }
}

#[test]
fn page_quota_includes_schema_and_index_growth_in_the_database_shell() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let key = [194; 32];
    let mut owner = ControlStore::open_with_key(&path, &key).unwrap();
    let old = ControlStore::open_existing_with_key(&path, &key).unwrap();
    let payload = vec![5; 192 * 1024];
    owner.put_record("original", b"one", &payload).unwrap();
    owner
        .configure_page_quota(DatabasePageQuota {
            max_pages: pages(&owner.connection) + 64,
        })
        .unwrap();
    let quota = DatabasePageQuota {
        max_pages: pages(&owner.connection) + 2,
    };
    owner.configure_page_quota(quota).unwrap();
    assert!(
        old.database_shell_statement(
            "CREATE INDEX no_space_index ON protocol_records(bytes)",
            false
        )
        .is_err()
    );
    assert_eq!(pager_limit(&old.connection), quota.max_pages);
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
    assert!(pages(&old.connection) <= quota.max_pages);
    super::super::validate_control_schema(&old.connection, crate::SCHEMA_VERSION).unwrap();
}

#[test]
fn page_quota_covers_parity_blob_growth_and_preserved_read_only_inspection() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("parity.db");
    let key = [190; 32];
    let volume = [191; 16];
    let mut store = ParityStore::open_with_key(&path, &volume, &key).unwrap();
    store
        .configure_page_quota(DatabasePageQuota { max_pages: 96 })
        .unwrap();
    let object = super::super::ParityObject {
        format_version: 1,
        guild_id: [192; 32],
        group_id: [193; 32],
        shard_index: 3,
        bytes: vec![7; mb_core::V1_SECTOR_SIZE],
        root: [0; 32],
    };
    let object = super::super::ParityObject {
        root: mb_core::sector_root(&object.bytes),
        ..object
    };
    store.stage_and_publish(&object).unwrap();
    let row_before = store.first_ready_object().unwrap().unwrap();
    // Use the same production table to require overflow pages exceeding the cap.
    assert!(
        store
            .connection
            .execute(
                "UPDATE parity_objects SET bytes=zeroblob(1048576) WHERE group_id=?1",
                params![object.group_id]
            )
            .is_err()
    );
    assert_eq!(store.first_ready_object().unwrap().unwrap(), row_before);
    drop(store);
    let read = ParityStore::open_existing_read_only_with_key(&path, &volume, &key).unwrap();
    assert_eq!(
        read.page_quota_usage().unwrap().unwrap().quota.max_pages,
        96
    );
    assert_eq!(read.first_ready_object().unwrap().unwrap(), row_before);
}
