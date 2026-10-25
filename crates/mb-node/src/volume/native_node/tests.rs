use super::*;
use crate::{Node, Seed};

pub(crate) fn policy() -> NativeNodeStoragePolicy {
    let control = NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [31; 16],
        main_bytes: 16 << 20,
        journal_bytes: 16 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 16 << 20,
        total_bytes: 64 << 20,
        headroom_bytes: 0,
        files: 32,
    };
    NativeNodeStoragePolicy {
        control,
        default_parity: NativeDatabaseIoPolicy {
            policy_id: [32; 16],
            ..control
        },
        parity_budget_bytes: 8 << 20,
    }
}

#[test]
fn native_node_creates_and_normally_reopens_both_managed_catalogs() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    let node = Node::create_native(temp.path(), seed.clone(), policy()).unwrap();
    assert_eq!(node.storage_status().unwrap().len(), 1);
    assert!(!temp.path().join(CONTROL_KEY_FILE).exists());
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let keys = KeyMaterial::from_seed(&seed);
    let inspection = control_inspection(temp.path(), &keys).unwrap().unwrap();
    assert_eq!(inspection.policy(), policy().control);
    let config = node.reader_config();
    let reader = config.open().unwrap();
    drop((node, reader, config));
    let node = Node::open(temp.path(), seed.clone()).unwrap();
    let manifest = read_volume_manifest(temp.path(), &keys).unwrap().unwrap();
    let parity = ParityStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("parity.db"),
        manifest.volume_id.as_bytes(),
        &keys,
        &volume_database_id(manifest.volume_id),
    )
    .unwrap();
    assert_eq!(
        parity.native_database_owner().unwrap().policy(),
        policy().default_parity
    );
    assert!(node.reader_config().open_for_retained_restore().is_ok());
}

type FileStamp = (u64, u32, i64, i64, i64, i64, [u8; 32]);
pub(crate) type Footprint = BTreeMap<PathBuf, FileStamp>;

// Include inode, modes and timestamps, but never access times changed by reads.
pub(crate) fn footprint(root: &Path) -> Footprint {
    walkdir::WalkDir::new(root)
        .into_iter()
        .map(|entry| {
            let entry = entry.unwrap();
            let m = fs::symlink_metadata(entry.path()).unwrap();
            let bytes = if m.is_file() {
                fs::read(entry.path()).unwrap()
            } else {
                Vec::new()
            };
            (
                entry.path().strip_prefix(root).unwrap().to_owned(),
                (
                    m.ino(),
                    m.mode(),
                    m.mtime(),
                    m.mtime_nsec(),
                    m.ctime(),
                    m.ctime_nsec(),
                    *blake3::hash(&bytes).as_bytes(),
                ),
            )
        })
        .collect()
}

fn assert_original_births(root: &Path, before: &Footprint) {
    let after = footprint(root);
    for (name, original) in before {
        if matches!(
            name.file_name().and_then(OsStr::to_str),
            Some(PROFILE_FILE | "birth" | "main" | "ready" | VOLUME_MANIFEST_FILE)
        ) {
            assert_eq!(after.get(name), Some(original), "{name:?}");
        }
    }
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
            "native Node child exceeded deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn run_child(root: &Path, mode: &str) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "volume::native_node::tests::native_node_child",
            "--nocapture",
        ])
        .env("MB_NATIVE_NODE_ROOT", root)
        .env("MB_NATIVE_NODE_MODE", mode)
        .stdout(std::process::Stdio::null());
    command
}

fn check_resume(root: &Path, seed: Seed, step: Step) {
    let before = footprint(root);
    if step != Step::Ready {
        assert!(Node::open(root, seed.clone()).is_err(), "{step:?}");
        assert_eq!(footprint(root), before);
    }
    let mut wrong = policy();
    wrong.control.headroom_bytes = 1;
    assert!(Node::create_native(root, seed.clone(), wrong).is_err());
    assert!(Node::create_native(root, Seed::from_bytes([89; 32]), policy()).is_err());
    assert_eq!(footprint(root), before);
    let node = Node::create_native(root, seed.clone(), policy()).unwrap();
    assert_eq!(node.storage_status().unwrap().len(), 1);
    assert!(!root.join(CONTROL_KEY_FILE).exists());
    assert_original_births(root, &before);
    let profile_before = fs::read(root.join(PROFILE_FILE)).unwrap();
    drop(node);
    let node = Node::open(root, seed).unwrap();
    assert_eq!(fs::read(root.join(PROFILE_FILE)).unwrap(), profile_before);
    assert_eq!(node.storage_status().unwrap().len(), 1);
}

#[test]
fn native_node_resumes_each_interrupted_publication_with_original_identity_and_policy() {
    for step in [
        Step::Profile,
        Step::Control,
        Step::Parity,
        Step::Manifest,
        Step::Registry,
        Step::Ready,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([88; 32]);
        INTERRUPT.with(|next| next.set(Some(step)));
        assert!(
            Node::create_native(temp.path(), seed.clone(), policy()).is_err(),
            "{step:?}"
        );
        check_resume(temp.path(), seed, step);
    }
}

#[test]
fn native_node_registry_publication_requires_exact_durable_bytes() {
    for action in [
        "SELECT RAISE(IGNORE)",
        "UPDATE protocol_records SET bytes = X'00' WHERE kind = 'node-config' AND record_id = X'73746f726167652d766f6c756d6573'",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([88; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        INTERRUPT.with(|next| next.set(Some(Step::Control)));
        assert!(Node::create_native(temp.path(), seed.clone(), policy()).is_err());
        let before = footprint(temp.path());
        let open_control = || {
            let directory = DatabaseDirectory::open(temp.path()).unwrap();
            ControlStore::open_native_existing_in_directory(
                &directory,
                OsStr::new("control.db"),
                &keys,
                b"control.db/v2",
            )
            .unwrap()
        };
        BEFORE_REGISTRY_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move |control| {
                let timing = if action.starts_with("SELECT") {
                    "BEFORE"
                } else {
                    "AFTER"
                };
                control.database_shell_statement(
                    &format!("CREATE TEMP TRIGGER alter_registry {timing} INSERT ON protocol_records WHEN NEW.kind = 'node-config' AND NEW.record_id = X'73746f726167652d766f6c756d6573' BEGIN {action}; END"),
                    false,
                ).unwrap();
            }));
        });
        let error = Node::create_native(temp.path(), seed.clone(), policy()).err();
        if temp.path().join(READY_FILE).exists() {
            let root = temp.keep();
            panic!(
                "native Node published readiness without its exact registry: {error:?}; preserved={}",
                root.display()
            );
        }
        let error = error.expect("registry fault must fail native creation");
        assert!(
            format!("{error:#}").contains("volume registry publication"),
            "{error:#}"
        );
        let control = open_control();
        assert!(
            control
                .get_record("node-config", b"storage-volumes")
                .unwrap()
                .is_none()
        );
        assert!(
            control
                .get_record(PROFILE_KIND, b"ready")
                .unwrap()
                .is_none()
        );
        drop(control);
        let node = Node::create_native(temp.path(), seed.clone(), policy()).unwrap();
        assert_eq!(node.storage_status().unwrap().len(), 1);
        assert_original_births(temp.path(), &before);
        drop(node);
        assert_eq!(
            Node::open(temp.path(), seed)
                .unwrap()
                .storage_status()
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
fn native_node_resumes_after_actual_process_death_at_every_publication() {
    for step in [
        Step::Profile,
        Step::Control,
        Step::Parity,
        Step::Manifest,
        Step::Registry,
        Step::Ready,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let status = child_status(
            run_child(temp.path(), "create").env("MB_NATIVE_NODE_CRASH", format!("{step:?}")),
        );
        assert_eq!(status.code(), Some(74), "{step:?}");
        check_resume(temp.path(), Seed::from_bytes([88; 32]), step);
    }
}

#[test]
fn native_node_inspector_does_not_hold_process_writer_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    let node = Node::create_native(temp.path(), seed.clone(), policy()).unwrap();
    let keys = KeyMaterial::from_seed(&seed);
    let inspection = control_inspection(temp.path(), &keys).unwrap().unwrap();
    assert!(child_status(&mut run_child(temp.path(), "busy")).success());
    drop(node);
    assert!(child_status(&mut run_child(temp.path(), "open")).success());
    inspection.verify_current().unwrap();
}

#[test]
fn native_node_rejects_withdrawn_sources_before_lock_permissions_or_recovery_writes() {
    for pending in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([88; 32]);
        if pending {
            INTERRUPT.with(|next| next.set(Some(Step::Control)));
            assert!(Node::create_native(temp.path(), seed.clone(), policy()).is_err());
        } else {
            drop(Node::create_native(temp.path(), seed.clone(), policy()).unwrap());
        }
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let control = ControlStore::open_native_existing_in_directory(
            &directory,
            OsStr::new("control.db"),
            &KeyMaterial::from_seed(&seed),
            b"control.db/v2",
        )
        .unwrap();
        control
            .put_record(
                "guarded-unfinished",
                b"intent",
                b"even malformed withdrawn state",
            )
            .unwrap();
        drop(control);
        fs::remove_file(temp.path().join(".node.lock")).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let before = footprint(temp.path());
        let error = Node::create_native(temp.path(), seed.clone(), policy())
            .err()
            .unwrap();
        assert!(format!("{error:#}").contains("withdrawn"), "{error:#}");
        assert!(Node::open(temp.path(), seed).is_err());
        assert_eq!(footprint(temp.path()), before);
    }
}

#[test]
fn native_node_creation_never_enrolls_legacy_or_copied_catalogs() {
    let seed = Seed::from_bytes([88; 32]);
    let legacy = tempfile::tempdir().unwrap();
    drop(Node::open(legacy.path(), seed.clone()).unwrap());
    let before = footprint(legacy.path());
    assert!(Node::create_native(legacy.path(), seed.clone(), policy()).is_err());
    assert_eq!(footprint(legacy.path()), before);
    let original = tempfile::tempdir().unwrap();
    drop(Node::create_native(original.path(), seed.clone(), policy()).unwrap());
    let copy = tempfile::tempdir().unwrap();
    for entry in walkdir::WalkDir::new(original.path()).min_depth(1) {
        let entry = entry.unwrap();
        let destination = copy
            .path()
            .join(entry.path().strip_prefix(original.path()).unwrap());
        if entry.file_type().is_dir() {
            fs::create_dir(&destination).unwrap();
        } else {
            fs::copy(entry.path(), &destination).unwrap();
        }
        fs::set_permissions(&destination, entry.metadata().unwrap().permissions()).unwrap();
    }
    let before = footprint(copy.path());
    assert!(Node::create_native(copy.path(), seed.clone(), policy()).is_err());
    assert!(Node::open(copy.path(), seed.clone()).is_err());
    assert_eq!(footprint(copy.path()), before);
    let directory = DatabaseDirectory::open(copy.path()).unwrap();
    let (key, original_policy) = mb_store::NativeDatabaseOwner::recovery_key(
        &directory,
        OsStr::new("control.db"),
        &KeyMaterial::from_seed(&seed),
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(original_policy, policy().control);
    let (reader, guard) =
        ControlStore::open_preserved_read_only_with_keys(copy.path().join("control.db"), &[key])
            .unwrap();
    assert!(reader.get_record(PROFILE_KIND, b"ready").unwrap().is_some());
    guard.verify_unchanged().unwrap();
    assert_eq!(footprint(copy.path()), before);
}

#[test]
#[ignore = "invoked only by native Node process parents"]
fn native_node_child() {
    let root = std::env::var_os("MB_NATIVE_NODE_ROOT").expect("parent-owned root");
    let root = Path::new(&root);
    let seed = Seed::from_bytes([88; 32]);
    match std::env::var("MB_NATIVE_NODE_MODE").unwrap().as_str() {
        "create" => drop(Node::create_native(root, seed, policy()).unwrap()),
        "open" => drop(Node::open(root, seed).unwrap()),
        "busy" => assert!(Node::open(root, seed).is_err()),
        mode => panic!("unknown native Node child mode {mode}"),
    }
}

#[test]
fn native_node_empty_creation_handoff_rejects_newly_appeared_withdrawn_state_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    INTERRUPT.with(|next| next.set(Some(Step::Control)));
    assert!(Node::create_native(temp.path(), seed.clone(), policy()).is_err());
    // Reconstruct the reachable MainBinding state: authenticated birth/main,
    // a bound empty main inode, and no readiness or SQL initialization yet.
    let lease = format!(
        ".mutualbackup-native-{}",
        blake3::hash(b"control.db").to_hex()
    );
    fs::remove_file(temp.path().join(lease).join("ready")).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(temp.path().join("control.db"))
        .unwrap()
        .sync_all()
        .unwrap();
    let root = temp.path().to_owned();
    let observed = std::rc::Rc::new(std::cell::RefCell::new(None));
    let captured = observed.clone();
    BEFORE_CONTROL_CREATION_WRITER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let directory = DatabaseDirectory::open(&root).unwrap();
            let control = ControlStore::create_native_in_directory(
                &directory,
                OsStr::new("control.db"),
                &KeyMaterial::from_seed(&Seed::from_bytes([88; 32])),
                b"control.db/v2",
                policy().control,
            )
            .unwrap();
            control
                .put_record("guarded-appeared", b"intent", b"unadmitted")
                .unwrap();
            drop(control);
            *captured.borrow_mut() = Some(footprint(&root));
        }))
    });
    assert!(Node::create_native(temp.path(), seed, policy()).is_err());
    assert_eq!(
        footprint(temp.path()),
        observed.borrow_mut().take().unwrap()
    );
}

#[test]
fn native_node_fresh_creation_handoff_rejects_newly_appeared_withdrawn_state_without_writes() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    INTERRUPT.with(|next| next.set(Some(Step::Profile)));
    assert!(Node::create_native(temp.path(), seed.clone(), policy()).is_err());
    let root = temp.path().to_owned();
    let observed = std::rc::Rc::new(std::cell::RefCell::new(None));
    let captured = observed.clone();
    BEFORE_CONTROL_CREATION_WRITER.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move || {
            let directory = DatabaseDirectory::open(&root).unwrap();
            let control = ControlStore::create_native_in_directory(
                &directory,
                OsStr::new("control.db"),
                &KeyMaterial::from_seed(&Seed::from_bytes([88; 32])),
                b"control.db/v2",
                policy().control,
            )
            .unwrap();
            control
                .put_record("guarded-appeared", b"intent", b"unadmitted")
                .unwrap();
            drop(control);
            *captured.borrow_mut() = Some(footprint(&root));
        }))
    });
    assert!(Node::create_native(temp.path(), seed, policy()).is_err());
    assert_eq!(
        footprint(temp.path()),
        observed.borrow_mut().take().unwrap()
    );
}

#[test]
fn native_node_refuses_corrupt_completed_control_in_pending_profile_before_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    INTERRUPT.with(|next| next.set(Some(Step::Control)));
    assert!(Node::create_native(temp.path(), seed.clone(), policy()).is_err());
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(temp.path().join("control.db"))
        .unwrap()
        .sync_all()
        .unwrap();
    fs::remove_file(temp.path().join(".node.lock")).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o750)).unwrap();
    let before = footprint(temp.path());
    assert!(Node::create_native(temp.path(), seed, policy()).is_err());
    assert_eq!(footprint(temp.path()), before);
}
