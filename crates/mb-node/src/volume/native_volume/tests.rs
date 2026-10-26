use super::*;
use crate::volume::native_node::tests::{footprint, policy as node_policy};
use crate::{Node, Seed};

fn policy() -> NativeParityVolumePolicy {
    NativeParityVolumePolicy {
        database: NativeDatabaseIoPolicy {
            policy_id: [47; 16],
            ..node_policy().default_parity
        },
        parity_budget_bytes: 8 << 20,
    }
}

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, Node) {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("node");
    let extra = temp.path().join("extra");
    fs::create_dir(&extra).unwrap();
    let node = Node::create_native(&data, Seed::from_bytes([88; 32]), node_policy()).unwrap();
    (temp, data, extra, node)
}

fn registry(node: &Node) -> DatabaseShellResult {
    node.database_shell_statement(None, "SELECT bytes FROM protocol_records WHERE kind='node-config' AND record_id=X'73746f726167652d766f6c756d6573'", false).unwrap()
}

fn check_original(root: &Path, original: &crate::volume::native_node::tests::Footprint) {
    let after = footprint(root);
    for (name, stamp) in original {
        if matches!(
            name.file_name().and_then(OsStr::to_str),
            Some(PROFILE_FILE | VOLUME_MANIFEST_FILE | "birth" | "main" | "ready")
        ) {
            assert_eq!(after.get(name), Some(stamp), "{name:?}");
        }
    }
}

fn open_parity(root: &Path) -> ParityStore {
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([88; 32]));
    let manifest = read_volume_manifest(root, &keys).unwrap().unwrap();
    ParityStore::open_native_existing_in_directory(
        &DatabaseDirectory::open(root).unwrap(),
        OsStr::new(DATABASE_FILE),
        manifest.volume_id.as_bytes(),
        &keys,
        &volume_database_id(manifest.volume_id),
    )
    .unwrap()
}

#[test]
fn extra_native_volume_preserves_payload_ack_policy_and_live_reader_lifetime() {
    let (_temp, data, extra, mut node) = setup();
    let id = node.create_native_storage_volume(&extra, policy()).unwrap();
    assert_eq!(node.storage_status().unwrap().len(), 2);
    let original = footprint(&extra);
    let bytes = vec![53; mb_core::V1_SECTOR_SIZE];
    let object = ParityObject {
        format_version: 1,
        guild_id: [54; 32],
        group_id: [55; 32],
        shard_index: 2,
        root: mb_core::sector_root(&bytes),
        bytes,
    };
    let mut parity = open_parity(&extra);
    assert_eq!(
        parity.native_database_owner().unwrap().policy(),
        policy().database
    );
    parity
        .stage_and_publish_ack(
            &object,
            b"original extra-volume acknowledgement",
            policy().parity_budget_bytes,
        )
        .unwrap();
    drop(parity);
    let config = node.reader_config();
    let reader = config.open().unwrap();
    assert_eq!(
        reader
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
    drop(node);
    assert!(Node::open(&data, Seed::from_bytes([88; 32])).is_err());
    assert_eq!(
        reader
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
    drop((reader, config));
    let node = Node::open(&data, Seed::from_bytes([88; 32])).unwrap();
    assert!(
        node.storage_status()
            .unwrap()
            .iter()
            .any(|s| s.volume_id == id && s.budget_bytes == policy().parity_budget_bytes)
    );
    let parity = open_parity(&extra);
    assert!(
        parity
            .publication_is_complete(&object, b"original extra-volume acknowledgement")
            .unwrap()
    );
    check_original(&extra, &original);
}

#[test]
fn extra_native_volume_resumes_each_error_without_changing_original_identity_or_policy() {
    for step in [
        Step::Profile,
        Step::Database,
        Step::Manifest,
        Step::Registry,
    ] {
        let (_temp, data, extra, mut node) = setup();
        INTERRUPT.with(|next| next.set(Some(step)));
        assert!(
            node.create_native_storage_volume(&extra, policy()).is_err(),
            "{step:?}"
        );
        let original = footprint(&extra);
        let mut wrong = policy();
        wrong.parity_budget_bytes /= 2;
        assert!(node.create_native_storage_volume(&extra, wrong).is_err());
        assert_eq!(footprint(&extra), original);
        let id = read_profile(
            &DatabaseDirectory::open(&extra).unwrap(),
            &KeyMaterial::from_seed(&Seed::from_bytes([88; 32])),
        )
        .unwrap()
        .unwrap()
        .volume_id;
        drop(node);
        let mut node = Node::open(&data, Seed::from_bytes([88; 32])).unwrap();
        assert_eq!(
            node.storage_status().unwrap().len(),
            if step == Step::Registry { 2 } else { 1 }
        );
        assert_eq!(
            node.create_native_storage_volume(&extra, policy()).unwrap(),
            id
        );
        check_original(&extra, &original);
        drop(node);
        assert_eq!(
            Node::open(&data, Seed::from_bytes([88; 32]))
                .unwrap()
                .storage_status()
                .unwrap()
                .len(),
            2
        );
    }
}

#[test]
fn extra_native_volume_registry_faults_keep_capacity_and_retry_original_birth() {
    for (timing, action) in [
        ("BEFORE", "SELECT RAISE(IGNORE)"),
        ("BEFORE", "SELECT RAISE(ABORT, 'registry fault')"),
        (
            "AFTER",
            "UPDATE protocol_records SET bytes=X'00' WHERE kind='node-config' AND record_id=X'73746f726167652d766f6c756d6573'",
        ),
    ] {
        let (_temp, data, extra, mut node) = setup();
        let before = registry(&node);
        let capacity = node
            .coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
            .unwrap();
        node.database_shell_statement(None, &format!("CREATE TEMP TRIGGER registry_fault {timing} UPDATE ON protocol_records WHEN NEW.kind='node-config' AND NEW.record_id=X'73746f726167652d766f6c756d6573' BEGIN {action}; END"), true).unwrap();
        assert!(node.create_native_storage_volume(&extra, policy()).is_err());
        assert_eq!(registry(&node), before);
        assert_eq!(node.storage_status().unwrap().len(), 1);
        assert_eq!(
            node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
                .unwrap(),
            capacity
        );
        let original = footprint(&extra);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([88; 32]));
        let id = read_volume_manifest(&extra, &keys)
            .unwrap()
            .unwrap()
            .volume_id;
        drop(node);
        let mut node = Node::open(&data, Seed::from_bytes([88; 32])).unwrap();
        assert_eq!(registry(&node), before);
        assert_eq!(
            node.create_native_storage_volume(&extra, policy()).unwrap(),
            id
        );
        check_original(&extra, &original);
        assert_eq!(node.storage_status().unwrap().len(), 2);
    }
}

#[test]
fn extra_native_volume_repeat_preserves_later_budgets_and_retired_state() {
    let (_temp, _data, extra, mut node) = setup();
    let id = node.create_native_storage_volume(&extra, policy()).unwrap();
    node.configure_parity_budget(4 << 20).unwrap();
    node.drain_storage_volume(id).unwrap();
    node.migrate_draining_volumes().unwrap();
    let status = node
        .storage_status()
        .unwrap()
        .into_iter()
        .find(|s| s.volume_id == id)
        .unwrap();
    assert_eq!(status.state, StorageVolumeState::Retired);
    let before = registry(&node);
    assert_eq!(
        node.create_native_storage_volume(&extra, policy()).unwrap(),
        id
    );
    assert_eq!(registry(&node), before);
    let status = node
        .storage_status()
        .unwrap()
        .into_iter()
        .find(|s| s.volume_id == id)
        .unwrap();
    assert_eq!(status.state, StorageVolumeState::Retired);
    assert_eq!(status.budget_bytes, 4 << 20);
}

fn copy_tree(source: &Path, destination: &Path) {
    for entry in walkdir::WalkDir::new(source) {
        let entry = entry.unwrap();
        let target = destination.join(entry.path().strip_prefix(source).unwrap());
        if entry.file_type().is_dir() {
            fs::create_dir_all(&target).unwrap();
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
        fs::set_permissions(&target, fs::metadata(entry.path()).unwrap().permissions()).unwrap();
    }
}

#[test]
fn extra_native_volume_rejects_legacy_copy_wrong_owner_and_damaged_manifest_without_writes() {
    let (temp, _data, extra, mut node) = setup();
    let foreign = temp.path().join("foreign");
    drop(Node::open(&foreign, Seed::from_bytes([88; 32])).unwrap());
    let before = footprint(&foreign);
    assert!(
        node.create_native_storage_volume(&foreign, policy())
            .is_err()
    );
    assert_eq!(footprint(&foreign), before);
    let mut legacy = Node::open(temp.path().join("legacy"), Seed::from_bytes([88; 32])).unwrap();
    let before = footprint(&extra);
    assert!(
        legacy
            .create_native_storage_volume(&extra, policy())
            .is_err()
    );
    assert_eq!(footprint(&extra), before);
    node.create_native_storage_volume(&extra, policy()).unwrap();
    let copy = temp.path().join("copy");
    copy_tree(&extra, &copy);
    let before = footprint(&copy);
    assert!(node.create_native_storage_volume(&copy, policy()).is_err());
    assert_eq!(footprint(&copy), before);
    let mut other = Node::create_native(
        temp.path().join("other"),
        Seed::from_bytes([89; 32]),
        node_policy(),
    )
    .unwrap();
    let before = footprint(&extra);
    assert!(
        other
            .create_native_storage_volume(&extra, policy())
            .is_err()
    );
    assert_eq!(footprint(&extra), before);
    fs::write(
        extra.join(VOLUME_MANIFEST_FILE),
        b"damaged original manifest",
    )
    .unwrap();
    let before = footprint(&extra);
    assert!(node.create_native_storage_volume(&extra, policy()).is_err());
    assert_eq!(footprint(&extra), before);
}

#[test]
fn extra_native_volume_handoff_rejects_profile_main_journal_and_directory_replacement() {
    for substitution in ["profile", "main", "journal", "directory"] {
        let (_temp, _data, extra, mut node) = setup();
        INTERRUPT.with(|next| next.set(Some(Step::Database)));
        assert!(node.create_native_storage_volume(&extra, policy()).is_err());
        let captured = std::rc::Rc::new(std::cell::RefCell::new(None));
        let result = captured.clone();
        let target = extra.clone();
        BEFORE_WRITER.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                match substitution {
                    "profile" | "main" => {
                        let file = target.join(if substitution == "profile" {
                            PROFILE_FILE
                        } else {
                            DATABASE_FILE
                        });
                        let held = target.with_extension(format!("{substitution}.original"));
                        fs::rename(&file, &held).unwrap();
                        fs::copy(&held, &file).unwrap();
                    }
                    "journal" => {
                        fs::write(target.join("parity.db-journal"), b"unadmitted journal").unwrap()
                    }
                    "directory" => {
                        fs::rename(&target, target.with_extension("original")).unwrap();
                        fs::create_dir(&target).unwrap();
                        fs::write(target.join("sentinel"), b"replacement directory").unwrap();
                    }
                    _ => unreachable!(),
                }
                *result.borrow_mut() = Some(footprint(&target));
            }))
        });
        assert!(
            node.create_native_storage_volume(&extra, policy()).is_err(),
            "{substitution}"
        );
        assert_eq!(
            footprint(&extra),
            captured.borrow_mut().take().unwrap(),
            "{substitution}"
        );
        assert_eq!(node.storage_status().unwrap().len(), 1);
    }
}

fn child(root: &Path, extra: &Path) -> std::process::Command {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "volume::native_volume::tests::extra_native_volume_child",
            "--nocapture",
        ])
        .env("MB_NATIVE_VOLUME_ROOT", root)
        .env("MB_NATIVE_VOLUME_EXTRA", extra)
        .stdout(std::process::Stdio::null());
    command
}

#[test]
fn extra_native_volume_resumes_after_process_death_at_each_publication() {
    for step in [
        Step::Profile,
        Step::Database,
        Step::Manifest,
        Step::Registry,
    ] {
        let (_temp, data, extra, node) = setup();
        drop(node);
        let mut process = child(&data, &extra)
            .env("MB_NATIVE_VOLUME_CRASH", format!("{step:?}"))
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(status) = process.try_wait().unwrap() {
                break status;
            }
            if start.elapsed() > std::time::Duration::from_secs(60) {
                process.kill().unwrap();
                process.wait().unwrap();
                panic!("child exceeded 60-second deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        assert_eq!(status.code(), Some(75), "{step:?}");
        let original = footprint(&extra);
        let mut node = Node::open(&data, Seed::from_bytes([88; 32])).unwrap();
        assert_eq!(
            node.storage_status().unwrap().len(),
            if step == Step::Registry { 2 } else { 1 }
        );
        node.create_native_storage_volume(&extra, policy()).unwrap();
        check_original(&extra, &original);
        assert_eq!(node.storage_status().unwrap().len(), 2);
    }
}

#[test]
#[ignore = "child process for explicit native parity crash qualification"]
fn extra_native_volume_child() {
    let root =
        PathBuf::from(std::env::var_os("MB_NATIVE_VOLUME_ROOT").expect("parent fixture required"));
    let extra =
        PathBuf::from(std::env::var_os("MB_NATIVE_VOLUME_EXTRA").expect("parent fixture required"));
    Node::open(root, Seed::from_bytes([88; 32]))
        .unwrap()
        .create_native_storage_volume(extra, policy())
        .unwrap();
}

#[test]
fn extra_native_volume_checks_registry_capacity_before_birth_and_allows_existing_retry() {
    let (temp, data, extra, mut node) = setup();
    let id = node.create_native_storage_volume(&extra, policy()).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([88; 32]));
    let control = ControlStore::open_native_existing_in_directory(
        &DatabaseDirectory::open(&data).unwrap(),
        OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
    )
    .unwrap();
    let mut records = load_volume_records(&control).unwrap();
    let template = records[0].clone();
    for index in 0..MAX_BOUNDED_VOLUME_RECORDS - records.len() {
        let volume_id = Uuid::from_u128(index as u128 + 1);
        records.push(VolumeRecord {
            volume_id,
            path: temp.path().join(format!("unavailable-volume-{index}")),
            wrapped_database_key: keys
                .wrap_native_database_key(
                    &volume_database_id(volume_id),
                    &[77; 32],
                    &policy().database,
                )
                .unwrap(),
            state: StorageVolumeState::Offline,
            configured: false,
            ..template.clone()
        });
    }
    store_volume_records(&control, &records).unwrap();
    drop((control, node));
    let mut node = Node::open(&data, Seed::from_bytes([88; 32])).unwrap();
    assert_eq!(
        node.storage_status().unwrap().len(),
        MAX_BOUNDED_VOLUME_RECORDS
    );
    let fresh = temp.path().join("fresh");
    fs::create_dir(&fresh).unwrap();
    let before = footprint(&fresh);
    let registered = registry(&node);
    assert!(node.create_native_storage_volume(&fresh, policy()).is_err());
    assert_eq!(footprint(&fresh), before);
    assert_eq!(registry(&node), registered);
    assert_eq!(
        node.create_native_storage_volume(&extra, policy()).unwrap(),
        id
    );
    assert_eq!(registry(&node), registered);
}

#[test]
fn extra_native_volume_rejects_empty_registered_replacement_before_publishing_an_identity() {
    let (_temp, _data, extra, mut node) = setup();
    node.create_native_storage_volume(&extra, policy()).unwrap();
    let bytes = vec![81; mb_core::V1_SECTOR_SIZE];
    let object = ParityObject {
        format_version: 1,
        guild_id: [82; 32],
        group_id: [83; 32],
        shard_index: 2,
        root: mb_core::sector_root(&bytes),
        bytes,
    };
    let mut parity = open_parity(&extra);
    parity
        .stage_and_publish_ack(
            &object,
            b"original replacement-path ACK",
            policy().parity_budget_bytes,
        )
        .unwrap();
    drop(parity);
    let config = node.reader_config();
    let original = extra.with_extension("original");
    fs::rename(&extra, &original).unwrap();
    fs::create_dir(&extra).unwrap();
    let before = footprint(&extra);
    let registered = registry(&node);
    assert!(node.create_native_storage_volume(&extra, policy()).is_err());
    assert_eq!(
        footprint(&extra),
        before,
        "failed recreation must not publish a second identity at the registered path"
    );
    assert_eq!(registry(&node), registered);
    assert_eq!(
        config
            .open()
            .unwrap()
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
    assert!(
        open_parity(&original)
            .publication_is_complete(&object, b"original replacement-path ACK")
            .unwrap()
    );
}
