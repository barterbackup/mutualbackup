use super::*;
use crate::ParityObject;
use mb_core::{Seed, sector_root};

fn keys() -> KeyMaterial {
    KeyMaterial::from_seed(&Seed::from_bytes([47; 32]))
}
fn policy() -> NativeDatabaseIoPolicy {
    NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [8; 16],
        main_bytes: 4 << 20,
        journal_bytes: 8 << 20,
        shm_bytes: 64 << 10,
        temporary_bytes: 8 << 20,
        total_bytes: 24 << 20,
        headroom_bytes: 0,
        files: 16,
    }
}
fn create(directory: &DatabaseDirectory) -> ControlStore {
    ControlStore::create_native_in_directory(
        directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
        policy(),
    )
    .unwrap()
}
fn reopen(directory: &DatabaseDirectory) -> Result<ControlStore, DatabaseError> {
    ControlStore::open_native_existing_in_directory(
        directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
}

#[test]
fn native_birth_reopens_original_policy_key_and_bytes_through_owner_handles() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"retained")
        .unwrap();
    let owner = store.native_database_owner().unwrap();
    assert_eq!(owner.policy(), policy());
    assert_eq!(owner.wrapped_key().format_version, 2);
    let envelope = owner.wrapped_key().clone();
    drop(store);
    let reader = owner.open_control().unwrap();
    assert_eq!(
        reader.get_record("native-birth", b"keep").unwrap(),
        Some(b"retained".to_vec())
    );
    drop(reader);
    drop(owner);
    let store = reopen(&directory).unwrap();
    assert_eq!(
        store.native_database_owner().unwrap().wrapped_key(),
        &envelope
    );
    assert_eq!(
        store.get_record("native-birth", b"keep").unwrap(),
        Some(b"retained".to_vec())
    );
    let key = NativeDatabaseOwner::recovery_key(
        &directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(key.1, policy());
    let (preserved, guard) =
        ControlStore::open_preserved_read_only_with_keys(temp.path().join("control.db"), &[key.0])
            .unwrap();
    assert_eq!(
        preserved.get_record("native-birth", b"keep").unwrap(),
        Some(b"retained".to_vec())
    );
    guard.verify_unchanged().unwrap();
}

#[test]
fn native_birth_preserves_fixed_parity_and_acknowledgement_across_restart() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let mut store = ParityStore::create_native_in_directory(
        &directory,
        OsStr::new("parity.db"),
        &[3; 16],
        &keys(),
        b"parity/native",
        policy(),
    )
    .unwrap();
    let bytes = vec![7; 65536];
    let object = ParityObject {
        format_version: 1,
        guild_id: [1; 32],
        group_id: [2; 32],
        shard_index: 1,
        root: sector_root(&bytes),
        bytes,
    };
    store
        .stage_and_publish_ack(&object, b"original acknowledgement", 1 << 20)
        .unwrap();
    let owner = store.native_database_owner().unwrap();
    let second = owner.open_parity().unwrap();
    assert!(
        second
            .publication_is_complete(&object, b"original acknowledgement")
            .unwrap()
    );
    drop((owner, store, second));
    let store = ParityStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("parity.db"),
        &[3; 16],
        &keys(),
        b"parity/native",
    )
    .unwrap();
    assert!(
        store
            .publication_is_complete(&object, b"original acknowledgement")
            .unwrap()
    );
    assert!(
        ParityStore::open_native_existing_in_directory(
            &directory,
            OsStr::new("parity.db"),
            &[4; 16],
            &keys(),
            b"parity/native"
        )
        .is_err()
    );
}

#[test]
fn native_birth_resumes_every_partial_publication_with_the_same_envelope() {
    for point in [
        Interruption::Birth,
        Interruption::EmptyMain,
        Interruption::MainBinding,
        Interruption::Schema,
        Interruption::MarkerWrite,
        Interruption::SqlMarker,
        Interruption::Ready,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        INTERRUPT.with(|next| next.set(Some(point)));
        assert!(
            ControlStore::create_native_in_directory(
                &directory,
                OsStr::new("control.db"),
                &keys(),
                b"control.db/v2",
                policy()
            )
            .is_err(),
            "{point:?}"
        );
        let lease = directory
            .leaf(lease_name(OsStr::new("control.db")))
            .unwrap();
        let before = fs::read(lease.join("birth")).unwrap();
        let store = create(&directory);
        assert_eq!(fs::read(lease.join("birth")).unwrap(), before, "{point:?}");
        store
            .put_record("native-birth", b"retry", b"complete")
            .unwrap();
        drop(store);
        assert_eq!(
            reopen(&directory)
                .unwrap()
                .get_record("native-birth", b"retry")
                .unwrap(),
            Some(b"complete".to_vec())
        );
    }
}

fn footprint(root: &Path) -> BTreeMap<std::path::PathBuf, (u64, u32, Vec<u8>)> {
    let mut files = BTreeMap::new();
    for entry in walkdir::WalkDir::new(root).min_depth(1) {
        let entry = entry.unwrap();
        let m = fs::symlink_metadata(entry.path()).unwrap();
        if !m.is_dir() {
            let bytes = if m.file_type().is_symlink() {
                fs::read_link(entry.path())
                    .unwrap()
                    .as_os_str()
                    .as_bytes()
                    .to_vec()
            } else {
                fs::read(entry.path()).unwrap()
            };
            files.insert(
                entry.path().strip_prefix(root).unwrap().to_owned(),
                (m.ino(), m.mode(), bytes),
            );
        }
    }
    files
}

fn copy_directory(source: &Path, destination: &Path) {
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let to = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            fs::create_dir(&to).unwrap();
            fs::set_permissions(&to, entry.metadata().unwrap().permissions()).unwrap();
            copy_directory(&entry.path(), &to);
        } else {
            fs::copy(entry.path(), &to).unwrap();
        }
    }
}

#[test]
fn native_birth_rejects_missing_replaced_and_damaged_ownership_without_mutation() {
    for case in [
        "main-missing",
        "main-replaced",
        "main-linked",
        "birth",
        "main",
        "ready",
        "damaged",
        "lease-replaced",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let store = create(&directory);
        store
            .put_record("native-birth", b"keep", b"retained")
            .unwrap();
        drop(store);
        let lease = directory
            .leaf(lease_name(OsStr::new("control.db")))
            .unwrap();
        match case {
            "main-missing" => {
                fs::remove_file(temp.path().join("control.db")).unwrap();
            }
            "main-replaced" => {
                fs::rename(
                    temp.path().join("control.db"),
                    temp.path().join("original.db"),
                )
                .unwrap();
                fs::copy(
                    temp.path().join("original.db"),
                    temp.path().join("control.db"),
                )
                .unwrap();
            }
            "main-linked" => {
                fs::hard_link(temp.path().join("control.db"), temp.path().join("alias.db"))
                    .unwrap();
            }
            "damaged" => {
                let mut bytes = fs::read(lease.join("birth")).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                fs::write(lease.join("birth"), bytes).unwrap();
            }
            "lease-replaced" => {
                let old = temp.path().join("old-lease");
                fs::rename(&lease, &old).unwrap();
                fs::DirBuilder::new().mode(0o700).create(&lease).unwrap();
                copy_directory(&old, &lease);
            }
            name => {
                fs::remove_file(lease.join(name)).unwrap();
            }
        }
        let before = footprint(temp.path());
        assert!(reopen(&directory).is_err(), "{case}");
        assert_eq!(footprint(temp.path()), before, "{case}");
    }
}

#[test]
fn native_birth_copies_are_recoverable_without_adopting_their_physical_identity() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    let copy = temp.path().join("copy");
    fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&copy).unwrap();
    let directory = DatabaseDirectory::open(&original).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"recover exact bytes")
        .unwrap();
    drop(store);
    copy_directory(&original, &copy);
    let copy_directory = DatabaseDirectory::open(&copy).unwrap();
    let before = footprint(&copy);
    assert!(reopen(&copy_directory).is_err());
    assert!(
        ControlStore::create_native_in_directory(
            &copy_directory,
            OsStr::new("control.db"),
            &keys(),
            b"control.db/v2",
            policy()
        )
        .is_err()
    );
    let (key, p) = NativeDatabaseOwner::recovery_key(
        &copy_directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(p, policy());
    let (reader, guard) =
        ControlStore::open_preserved_read_only_with_keys(copy.join("control.db"), &[key]).unwrap();
    assert_eq!(
        reader.get_record("native-birth", b"keep").unwrap(),
        Some(b"recover exact bytes".to_vec())
    );
    guard.verify_unchanged().unwrap();
    drop(reader);
    assert_eq!(footprint(&copy), before);
    // A bare database copy still carries the policy marker and cannot silently
    // become a generic writer even if all external ownership records are lost.
    let bare = temp.path().join("bare");
    fs::DirBuilder::new().mode(0o700).create(&bare).unwrap();
    fs::copy(copy.join("control.db"), bare.join("control.db")).unwrap();
    let bytes = fs::read(bare.join("control.db")).unwrap();
    assert!(matches!(
        ControlStore::open_with_key(bare.join("control.db"), &key),
        Err(DatabaseError::NativeOwnershipRequired)
    ));
    assert_eq!(fs::read(bare.join("control.db")).unwrap(), bytes);
}

#[test]
fn native_birth_generic_writers_and_unmanaged_rekey_cannot_drop_the_policy() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"retained")
        .unwrap();
    let owner = store.native_database_owner().unwrap();
    let (key, _) = NativeDatabaseOwner::recovery_key(
        &directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    let before = footprint(temp.path());
    assert!(matches!(
        ControlStore::open_with_key(temp.path().join("control.db"), &key),
        Err(DatabaseError::NativeOwnershipRequired)
    ));
    assert!(matches!(
        ControlStore::open_existing_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &key
        ),
        Err(DatabaseError::NativeOwnershipRequired)
    ));
    assert!(matches!(
        ControlStore::open_physical_existing_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &key,
            owner.0.limits()
        ),
        Err(DatabaseError::NativeOwnershipRequired)
    ));
    let mut changed = policy();
    changed.headroom_bytes = 1;
    assert!(
        ControlStore::create_native_in_directory(
            &directory,
            OsStr::new("control.db"),
            &keys(),
            b"control.db/v2",
            changed
        )
        .is_err()
    );
    assert!(
        ControlStore::open_native_existing_in_directory(
            &directory,
            OsStr::new("control.db"),
            &keys(),
            b"wrong-context"
        )
        .is_err()
    );
    assert_eq!(footprint(temp.path()), before);
    assert!(matches!(
        store.rekey(&[99; 32]),
        Err(DatabaseError::NativeOwnershipRequired)
    ));
    assert_eq!(
        owner
            .open_control()
            .unwrap()
            .get_record("native-birth", b"keep")
            .unwrap(),
        Some(b"retained".to_vec())
    );
}

#[test]
fn native_birth_never_enrolls_a_preexisting_generic_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = ControlStore::open_with_key(temp.path().join("control.db"), &[4; 32]).unwrap();
    store.put_record("old", b"keep", b"original").unwrap();
    drop(store);
    let before = footprint(temp.path());
    assert!(
        ControlStore::create_native_in_directory(
            &directory,
            OsStr::new("control.db"),
            &keys(),
            b"control.db/v2",
            policy()
        )
        .is_err()
    );
    assert_eq!(footprint(temp.path()), before);
    assert!(
        !directory
            .leaf(lease_name(OsStr::new("control.db")))
            .unwrap()
            .exists()
    );
}

#[test]
fn native_birth_follows_the_held_parent_after_directory_handoff() {
    let temp = tempfile::tempdir().unwrap();
    let original = temp.path().join("original");
    let moved = temp.path().join("moved");
    fs::DirBuilder::new().mode(0o700).create(&original).unwrap();
    let directory = DatabaseDirectory::open(&original).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"original")
        .unwrap();
    fs::rename(&original, &moved).unwrap();
    fs::create_dir(&original).unwrap();
    fs::write(original.join("sentinel"), b"preserve").unwrap();
    let second = reopen(&DatabaseDirectory::open(&moved).unwrap()).unwrap();
    assert_eq!(
        second.get_record("native-birth", b"keep").unwrap(),
        Some(b"original".to_vec())
    );
    second
        .put_record("native-birth", b"after", b"renamed parent")
        .unwrap();
    assert_eq!(fs::read_dir(&original).unwrap().count(), 1);
    assert_eq!(fs::read(original.join("sentinel")).unwrap(), b"preserve");
}

fn run_child(root: &Path, mode: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "database::native_owner::tests::native_birth_child",
            "--nocapture",
        ])
        .env("MB_NATIVE_BIRTH_ROOT", root)
        .env("MB_NATIVE_BIRTH_MODE", mode)
        .stdout(std::process::Stdio::null());
    command
}

fn child_status(command: &mut std::process::Command) -> std::process::ExitStatus {
    struct Child(std::process::Child);
    impl Drop for Child {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Child(command.spawn().unwrap());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "native ownership child exceeded its deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[test]
fn native_birth_kernel_claim_outlives_stores_until_the_last_owner_handle_closes() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = create(&directory);
    let owner = store.native_database_owner().unwrap();
    assert!(child_status(&mut run_child(temp.path(), "busy")).success());
    drop(store);
    assert!(child_status(&mut run_child(temp.path(), "busy")).success());
    let second = owner.open_control().unwrap();
    drop(owner);
    assert!(child_status(&mut run_child(temp.path(), "busy")).success());
    drop(second);
    assert!(child_status(&mut run_child(temp.path(), "open")).success());
    assert_eq!(
        reopen(&directory)
            .unwrap()
            .get_record("native-birth", b"child")
            .unwrap(),
        Some(b"complete".to_vec())
    );
}

#[test]
fn native_birth_owner_handles_share_actual_temporary_admission_and_release() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let mut p = policy();
    p.temporary_bytes = 6 << 20;
    let first = ControlStore::create_native_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
        p,
    )
    .unwrap();
    let owner = first.native_database_owner().unwrap();
    let second = owner.open_control().unwrap();
    let spill = |store: &ControlStore| -> Result<(), DatabaseError> {
        store.connection.execute_batch("PRAGMA temp_store=FILE; PRAGMA temp.cache_size=8; CREATE TEMP TABLE IF NOT EXISTS spill(bytes BLOB);")?;
        let tx = Transaction::new_unchecked(&store.connection, TransactionBehavior::Deferred)?;
        for _ in 0..128 {
            tx.execute("INSERT INTO temp.spill VALUES (zeroblob(32768))", [])?;
        }
        tx.commit()?;
        Ok(())
    };
    spill(&first).unwrap();
    assert_eq!(
        first.physical_io_allocated_bytes().unwrap(),
        second.physical_io_allocated_bytes().unwrap()
    );
    let error =
        spill(&second).expect_err("managed handles share the authenticated temporary ceiling");
    assert!(
        matches!(error,DatabaseError::Sql(ref e) if e.sqlite_error_code()==Some(rusqlite::ErrorCode::DiskFull)),
        "{error:?}"
    );
    drop(first);
    spill(&second).unwrap();
    drop(second);
    drop(owner);
    let store = reopen(&directory).unwrap();
    assert_eq!(store.native_database_owner().unwrap().policy(), p);
}

#[test]
fn native_birth_reusable_handles_accept_normal_concurrent_data_writes() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"original")
        .unwrap();
    let owner = store.native_database_owner().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    struct Stop(Arc<AtomicBool>);
    impl Drop for Stop {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    std::thread::scope(|scope| {
        let stopped = stop.clone();
        let worker = scope.spawn(move || {
            for n in 0u32..256 {
                if stopped.load(Ordering::Acquire) {
                    break;
                }
                store
                    .put_record("native-birth", b"changing", &vec![(n % 255) as u8; 32768])
                    .unwrap();
            }
        });
        let _stop = Stop(stop.clone());
        let mut opened = 0;
        for _ in 0..4 {
            match owner.open_control() {
                Ok(reader) => {
                    assert_eq!(
                        reader.get_record("native-birth", b"keep").unwrap(),
                        Some(b"original".to_vec())
                    );
                    opened += 1;
                }
                Err(DatabaseError::Sql(error))
                    if error.sqlite_error_code() == Some(rusqlite::ErrorCode::DatabaseBusy) => {}
                Err(error) => {
                    panic!("normal data writes must not invalidate the unchanged owner: {error:?}")
                }
            }
        }
        assert!(opened > 0);
        stop.store(true, Ordering::Release);
        worker.join().unwrap();
    });
}

#[test]
fn native_birth_rechecks_signed_record_mappings_before_more_physical_writes() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"retained")
        .unwrap();
    let owner = store.native_database_owner().unwrap();
    let lease = directory
        .leaf(lease_name(OsStr::new("control.db")))
        .unwrap();
    fs::rename(lease.join("ready"), lease.join("original-ready")).unwrap();
    fs::copy(lease.join("original-ready"), lease.join("ready")).unwrap();
    assert!(owner.verify_current().is_err());
    assert!(
        store
            .put_record("native-birth", b"keep", &vec![5; 65536])
            .is_err()
    );
    fs::remove_file(lease.join("ready")).unwrap();
    fs::rename(lease.join("original-ready"), lease.join("ready")).unwrap();
    drop((owner, store));
    let reopened = reopen(&directory).unwrap();
    assert_eq!(
        reopened.get_record("native-birth", b"keep").unwrap(),
        Some(b"retained".to_vec())
    );
    reopened
        .put_record("native-birth", b"retry", b"new claim")
        .unwrap();
}

#[test]
fn native_birth_rejects_lost_or_damaged_sql_binding_before_writable_open() {
    for damaged in [None, Some(vec![7u8; 32]), Some(vec![4u8; 65536])] {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let store = create(&directory);
        match damaged {
            None => {
                store
                    .connection
                    .execute("DELETE FROM meta WHERE key=?1", [SQL_MARKER])
                    .unwrap();
            }
            Some(bytes) => {
                store
                    .connection
                    .execute(
                        "UPDATE meta SET value=?2 WHERE key=?1",
                        rusqlite::params![SQL_MARKER, bytes],
                    )
                    .unwrap();
            }
        }
        drop(store);
        let before = footprint(temp.path());
        assert!(reopen(&directory).is_err());
        assert_eq!(footprint(temp.path()), before);
    }
}

#[test]
fn native_birth_charges_unopened_retained_journal_allocation_before_sql_work() {
    let temp = tempfile::tempdir().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let store = create(&directory);
    store
        .put_record("native-birth", b"keep", b"retained")
        .unwrap();
    drop(store);
    let tail = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(temp.path().join("control.db-journal"))
        .unwrap();
    assert_eq!(
        unsafe { libc::fallocate(tail.as_raw_fd(), 0, 0, 9 << 20) },
        0
    );
    tail.sync_all().unwrap();
    drop(tail);
    let before = footprint(temp.path());
    assert!(matches!(
        reopen(&directory),
        Err(DatabaseError::CapacityExceeded)
    ));
    assert_eq!(footprint(temp.path()), before);
}

#[test]
fn native_birth_recovers_hot_sql_and_publications_after_actual_process_death() {
    for point in [
        Interruption::Birth,
        Interruption::EmptyMain,
        Interruption::MainBinding,
        Interruption::Schema,
        Interruption::MarkerWrite,
        Interruption::SqlMarker,
        Interruption::Ready,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let status = child_status(
            run_child(temp.path(), "create").env("MB_NATIVE_BIRTH_CRASH", format!("{point:?}")),
        );
        assert_eq!(status.code(), Some(73), "{point:?}");
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let path = directory
            .leaf(lease_name(OsStr::new("control.db")))
            .unwrap();
        let birth = fs::read(path.join("birth")).unwrap();
        let binding = fs::read(path.join("main")).ok();
        let store = create(&directory);
        assert_eq!(fs::read(path.join("birth")).unwrap(), birth);
        if let Some(binding) = binding {
            assert_eq!(fs::read(path.join("main")).unwrap(), binding);
        }
        store
            .put_record("native-birth", b"after-crash", b"complete")
            .unwrap();
        drop(store);
        assert_eq!(
            reopen(&directory)
                .unwrap()
                .get_record("native-birth", b"after-crash")
                .unwrap(),
            Some(b"complete".to_vec())
        );
    }
}

#[test]
fn native_birth_recovers_ready_catalogs_after_hot_transactions_in_all_native_modes() {
    for mode in ["DELETE", "TRUNCATE", "PERSIST", "WAL"] {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let store = create(&directory);
        store
            .put_record("native-birth", b"keep", b"original committed bytes")
            .unwrap();
        drop(store);
        let status = child_status(
            run_child(temp.path(), "transaction").env("MB_NATIVE_TRANSACTION_MODE", mode),
        );
        assert_eq!(status.code(), Some(73), "{mode}");
        let store = reopen(&directory).unwrap();
        assert_eq!(
            store.get_record("native-birth", b"keep").unwrap(),
            Some(b"original committed bytes".to_vec()),
            "{mode}"
        );
        assert_eq!(
            store.get_record("native-birth", b"uncommitted").unwrap(),
            None,
            "{mode}"
        );
        store
            .put_record("native-birth", b"retry", b"after native recovery")
            .unwrap();
    }
}

#[test]
#[ignore = "invoked only by the native ownership/crash parent fixtures"]
fn native_birth_child() {
    let root = std::env::var_os("MB_NATIVE_BIRTH_ROOT").expect("parent-owned root");
    let directory = DatabaseDirectory::open(Path::new(&root)).unwrap();
    match std::env::var("MB_NATIVE_BIRTH_MODE").unwrap().as_str() {
        "create" => {
            drop(create(&directory));
        }
        "busy" => {
            assert!(matches!(
                reopen(&directory),
                Err(DatabaseError::NativeOwnershipBusy)
            ));
        }
        "open" => {
            let store = reopen(&directory).unwrap();
            store
                .put_record("native-birth", b"child", b"complete")
                .unwrap();
        }
        "transaction" => {
            let store = reopen(&directory).unwrap();
            let mode = std::env::var("MB_NATIVE_TRANSACTION_MODE").unwrap();
            assert!(["DELETE", "TRUNCATE", "PERSIST", "WAL"].contains(&mode.as_str()));
            store
                .connection
                .pragma_update(None, "journal_mode", mode)
                .unwrap();
            store
                .connection
                .execute_batch("PRAGMA cache_size=8; BEGIN IMMEDIATE")
                .unwrap();
            store.connection.execute("UPDATE protocol_records SET bytes=zeroblob(524288) WHERE kind='native-birth' AND record_id=?1", [b"keep".as_slice()]).unwrap();
            store.connection.execute("INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('native-birth',?1,zeroblob(524288))", [b"uncommitted".as_slice()]).unwrap();
            unsafe {
                libc::_exit(73);
            }
        }
        other => panic!("unknown child mode {other}"),
    }
}
