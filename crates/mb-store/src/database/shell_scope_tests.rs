use super::*;
#[cfg(target_os = "linux")]
use mb_core::NativeDatabaseIoPolicy;
use mb_core::Seed;

#[cfg(target_os = "linux")]
fn native_policy() -> NativeDatabaseIoPolicy {
    NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [63; 16],
        main_bytes: 8 << 20,
        journal_bytes: 8 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 8 << 20,
        total_bytes: 32 << 20,
        headroom_bytes: 0,
        files: 32,
    }
}

fn layouts() -> &'static [bool] {
    #[cfg(target_os = "linux")]
    {
        &[false, true]
    }
    #[cfg(not(target_os = "linux"))]
    {
        &[false]
    }
}

fn control_case(check: impl Fn(&ControlStore) -> bool) {
    let mut failures = Vec::new();
    for &native in layouts() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([64; 32]));
        let path = temp.path().join("control.db");
        #[cfg(target_os = "linux")]
        let store = if native {
            ControlStore::create_native_in_directory(
                &DatabaseDirectory::open(temp.path()).unwrap(),
                std::ffi::OsStr::new("control.db"),
                &keys,
                b"shell/control",
                native_policy(),
            )
            .unwrap()
        } else {
            ControlStore::open(&path, &keys).unwrap()
        };
        #[cfg(not(target_os = "linux"))]
        let store = ControlStore::open(&path, &keys).unwrap();
        store
            .put_record("shell-original", b"one", b"original retained bytes")
            .unwrap();
        let passed = check(&store);
        assert_eq!(
            store.get_record("shell-original", b"one").unwrap().unwrap(),
            b"original retained bytes"
        );
        drop(store);
        if !passed {
            failures.push((native, temp.keep()));
        }
    }
    assert!(
        failures.is_empty(),
        "shell query changed live connection authority; preserved={failures:?}"
    );
}

fn next_write(store: &ControlStore) -> bool {
    store
        .put_record("shell-followup", b"two", b"normal write after inspection")
        .is_ok()
        && store
            .get_record("shell-followup", b"two")
            .unwrap()
            .as_deref()
            == Some(b"normal write after inspection".as_slice())
}

#[test]
fn read_only_shell_success_retains_live_control_writer() {
    control_case(|store| {
        assert_eq!(
            store
                .database_shell_statement(
                    "SELECT bytes FROM protocol_records WHERE kind='shell-original'",
                    true
                )
                .unwrap()
                .rows
                .len(),
            1
        );
        next_write(store)
    });
}

#[test]
fn read_only_shell_refused_write_retains_live_control_writer() {
    control_case(|store| {
        assert!(
            store
                .database_shell_statement(
                    "INSERT INTO protocol_records VALUES ('forbidden', X'01', X'02')",
                    true
                )
                .is_err()
        );
        assert!(store.get_record("forbidden", &[1]).unwrap().is_none());
        next_write(store)
    });
}

#[test]
fn read_only_shell_prepare_error_retains_live_control_writer() {
    control_case(|store| {
        assert!(
            store
                .database_shell_statement("SELECT missing_column FROM missing_table", true)
                .is_err()
        );
        next_write(store)
    });
}

#[test]
fn read_only_shell_step_error_retains_live_control_writer() {
    control_case(|store| {
        assert!(
            store
                .database_shell_statement("SELECT abs(-9223372036854775808)", true)
                .is_err()
        );
        next_write(store)
    });
}

#[test]
fn read_only_shell_preserves_preexisting_query_only_connection() {
    control_case(|store| {
        store
            .connection
            .pragma_update(None, "query_only", true)
            .unwrap();
        store
            .database_shell_statement("PRAGMA query_only=OFF", true)
            .unwrap();
        let retained = store
            .put_record("forbidden", b"two", b"must not be writable")
            .is_err();
        let query_only: bool = store
            .connection
            .pragma_query_value(None, "query_only", |row| row.get(0))
            .unwrap();
        retained && query_only
    });
}

#[test]
fn read_only_shell_preserves_live_parity_publication_and_original_ack() {
    let mut failures = Vec::new();
    for &native in layouts() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([64; 32]));
        #[cfg(target_os = "linux")]
        let mut store = if native {
            ParityStore::create_native_in_directory(
                &DatabaseDirectory::open(temp.path()).unwrap(),
                std::ffi::OsStr::new("parity.db"),
                &[65; 16],
                &keys,
                b"shell/parity",
                native_policy(),
            )
            .unwrap()
        } else {
            ParityStore::open(temp.path().join("parity.db"), &[65; 16], &keys).unwrap()
        };
        #[cfg(not(target_os = "linux"))]
        let mut store = ParityStore::open(temp.path().join("parity.db"), &[65; 16], &keys).unwrap();
        let bytes = vec![66; mb_core::V1_SECTOR_SIZE];
        let first = ParityObject {
            format_version: 1,
            guild_id: [67; 32],
            group_id: [68; 32],
            shard_index: 2,
            root: mb_core::sector_root(&bytes),
            bytes,
        };
        store
            .stage_and_publish_ack(&first, b"original ACK", 4 << 20)
            .unwrap();
        assert_eq!(
            store
                .database_shell_statement("SELECT state FROM parity_objects", true)
                .unwrap()
                .rows,
            vec![vec!["READY".to_owned()]]
        );
        let second = ParityObject {
            group_id: [69; 32],
            ..first.clone()
        };
        let passed = store
            .stage_and_publish_ack(&second, b"followup ACK", 4 << 20)
            .is_ok();
        assert!(
            store
                .publication_is_complete(&first, b"original ACK")
                .unwrap()
        );
        assert_eq!(
            store
                .load_ready(&first.group_id, first.shard_index)
                .unwrap()
                .bytes,
            first.bytes
        );
        drop(store);
        if !passed {
            failures.push((native, temp.keep()));
        }
    }
    assert!(
        failures.is_empty(),
        "shell inspection disabled parity publication; preserved={failures:?}"
    );
}
