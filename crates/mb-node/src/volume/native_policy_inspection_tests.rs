use super::*;
use mb_core::{NativeDatabaseIoPolicy, Seed};
use tempfile::TempDir;

fn policy() -> NativeDatabaseIoPolicy {
    NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [4; 16],
        main_bytes: 2 << 20,
        journal_bytes: 4 << 20,
        shm_bytes: 64 << 10,
        temporary_bytes: 8 << 20,
        total_bytes: 16 << 20,
        headroom_bytes: 0,
        files: 16,
    }
}

#[cfg(target_os = "linux")]
#[test]
fn native_birth_control_recovers_without_an_external_key_and_rejects_node_startup() {
    let temp = TempDir::new().unwrap();
    let seed = Seed::from_bytes([74; 32]);
    let keys = KeyMaterial::from_seed(&seed);
    let directory = mb_store::DatabaseDirectory::open(temp.path()).unwrap();
    let store = ControlStore::create_native_in_directory(
        &directory,
        std::ffi::OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
        policy(),
    )
    .unwrap();
    store
        .put_record(
            "native-policy-fixture",
            b"retained",
            b"recover from seed and birth",
        )
        .unwrap();
    let before = footprint(temp.path());
    with_inspected_control_snapshot(temp.path(), &keys, |reader| {
        assert_eq!(
            reader.get_record("native-policy-fixture", b"retained")?,
            Some(b"recover from seed and birth".to_vec())
        );
        Ok(())
    })
    .unwrap();
    let error = crate::Node::lock_data_dir_with_seed(temp.path(), &seed)
        .err()
        .expect("normal startup must not grant an unmanaged native writer");
    assert!(
        format!("{error:#}").contains("managed native database opener"),
        "{error:#}"
    );
    assert!(!temp.path().join(CONTROL_KEY_FILE).exists());
    assert!(!temp.path().join(".node.lock").exists());
    assert_eq!(footprint(temp.path()), before);
    drop(store);
    fs::remove_file(temp.path().join("control.db")).unwrap();
    let before = footprint(temp.path());
    assert!(crate::Node::lock_data_dir_with_seed(temp.path(), &seed).is_err());
    assert!(!temp.path().join(CONTROL_KEY_FILE).exists());
    assert!(!temp.path().join(".node.lock").exists());
    assert_eq!(footprint(temp.path()), before);
}
#[derive(Debug, Eq, PartialEq)]
struct FileFootprint {
    inode: u64,
    mode: u32,
    length: u64,
    contents: Option<Vec<u8>>,
}
fn footprint(root: &Path) -> BTreeMap<std::ffi::OsString, FileFootprint> {
    fs::read_dir(root)
        .unwrap()
        .filter_map(|entry| {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if !metadata.is_file() {
                return None;
            }
            let volatile = entry.file_name().as_encoded_bytes().ends_with(b"-shm");
            Some((
                entry.file_name(),
                FileFootprint {
                    inode: metadata.ino(),
                    mode: metadata.mode(),
                    length: metadata.len(),
                    contents: (!volatile).then(|| fs::read(entry.path()).unwrap()),
                },
            ))
        })
        .collect()
}
fn journal_root(temp: &TempDir, database: &str, manifest: &str, state: usize) -> PathBuf {
    if state != 1 {
        return temp.path().to_path_buf();
    }
    let copy = temp.path().join("copy");
    fs::create_dir(&copy).unwrap();
    for name in [
        database.to_owned(),
        format!("{database}-wal"),
        manifest.to_owned(),
    ] {
        if temp.path().join(&name).exists() {
            fs::copy(temp.path().join(&name), copy.join(name)).unwrap();
        }
    }
    copy
}

#[test]
fn native_policy_control_readers_preserve_closed_wal_only_and_live_inputs() {
    for state in 0..if cfg!(target_os = "linux") { 3 } else { 1 } {
        let temp = TempDir::new().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let key = [91; 32];
        let writer = ControlStore::open_with_key(temp.path().join("control.db"), &key).unwrap();
        writer
            .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
            .unwrap();
        writer
            .put_record(
                "native-policy-fixture",
                b"retained",
                b"read without enrollment",
            )
            .unwrap();
        let envelope = keys
            .wrap_native_database_key(b"control.db/v2", &key, &policy())
            .unwrap();
        write_new_private_record(&temp.path().join(CONTROL_KEY_FILE), &envelope).unwrap();
        let root = journal_root(&temp, "control.db", CONTROL_KEY_FILE, state);
        let _writer = if state == 2 {
            Some(writer)
        } else {
            drop(writer);
            None
        };
        let before = footprint(&root);
        #[cfg(target_os = "linux")]
        {
            with_inspected_control_snapshot(&root, &keys, |reader| {
                assert_eq!(
                    reader.get_record("native-policy-fixture", b"retained")?,
                    Some(b"read without enrollment".to_vec())
                );
                Ok(())
            })
            .unwrap();
            with_inspected_control_key_snapshot(&root, &keys, |reader, selected| {
                assert_eq!(selected, key);
                assert_eq!(
                    reader.get_record("native-policy-fixture", b"retained")?,
                    Some(b"read without enrollment".to_vec())
                );
                Ok(())
            })
            .unwrap();
            let (reader, guard) = open_preserved_control_store(&root, &keys).unwrap();
            assert_eq!(
                reader
                    .get_record("native-policy-fixture", b"retained")
                    .unwrap(),
                Some(b"read without enrollment".to_vec())
            );
            guard.verify_unchanged().unwrap();
            drop(reader);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let reader = inspect_control_store(&root, &keys).unwrap().unwrap();
            assert_eq!(
                reader
                    .get_record("native-policy-fixture", b"retained")
                    .unwrap(),
                Some(b"read without enrollment".to_vec())
            );
        }
        assert_eq!(footprint(&root), before, "journal state {state}");
    }
}

#[test]
fn native_policy_preserved_parity_retains_fixed_variable_and_receipt_evidence() {
    for state in 0..if cfg!(target_os = "linux") { 3 } else { 1 } {
        let temp = TempDir::new().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let volume_id = Uuid::new_v4();
        let key = [91; 32];
        let mut writer =
            ParityStore::open_with_key(temp.path().join("parity.db"), volume_id.as_bytes(), &key)
                .unwrap();
        writer
            .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
            .unwrap();
        let bytes = vec![5; 65536];
        let fixed = ParityObject {
            format_version: 1,
            guild_id: [1; 32],
            group_id: [2; 32],
            shard_index: 3,
            root: mb_core::sector_root(&bytes),
            bytes,
        };
        writer
            .stage_and_publish_ack(&fixed, b"original acknowledgement", 1 << 20)
            .unwrap();
        let bytes = vec![8; 4096];
        let variable = VariableParityObject {
            format_version: 2,
            guild_id: [1; 32],
            group_id: [6; 32],
            shard_index: 7,
            commitment: mb_core::merkle_commit(&bytes).unwrap(),
            bytes,
        };
        writer
            .stage_attempt(&[9; 16], &variable, b"original receipt", 1 << 20)
            .unwrap();
        writer
            .activate_attempt_object(
                &[9; 16],
                &variable.group_id,
                variable.shard_index,
                &variable.commitment,
                &[10; 32],
            )
            .unwrap();
        let manifest = VolumeManifest {
            format_version: 1,
            owner: keys.node_id(),
            volume_id,
            database_file: "parity.db".into(),
            wrapped_database_key: keys
                .wrap_native_database_key(&volume_database_id(volume_id), &key, &policy())
                .unwrap(),
        };
        write_new_private_record(
            &temp.path().join(VOLUME_MANIFEST_FILE),
            &SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, &keys).unwrap(),
        )
        .unwrap();
        let root = journal_root(&temp, "parity.db", VOLUME_MANIFEST_FILE, state);
        let _writer = if state == 2 {
            Some(writer)
        } else {
            drop(writer);
            None
        };
        let before = footprint(&root);
        let reader = PreservedParityVolume::open(&root, &keys).unwrap();
        assert_eq!(reader.volume_id(), volume_id);
        assert_eq!(
            reader
                .load_fixed(
                    &fixed.guild_id,
                    &fixed.group_id,
                    fixed.shard_index,
                    &fixed.root
                )
                .unwrap(),
            fixed.bytes
        );
        assert_eq!(
            reader
                .load_variable(
                    &variable.guild_id,
                    &variable.group_id,
                    variable.shard_index,
                    &variable.commitment
                )
                .unwrap(),
            variable.bytes
        );
        assert!(
            reader
                .store
                .publication_is_complete(&fixed, b"original acknowledgement")
                .unwrap()
        );
        let ready = reader
            .store
            .load_ready_variable_object(&variable.group_id, variable.shard_index)
            .unwrap();
        assert_eq!(ready.staged_receipt, b"original receipt");
        assert_eq!(ready.attempt_id, [9; 16]);
        assert_eq!(ready.verification_hash, [10; 32]);
        #[cfg(target_os = "linux")]
        reader.verify_unchanged().unwrap();
        drop(reader);
        assert_eq!(footprint(&root), before, "journal state {state}");
    }
}

#[test]
#[cfg(target_os = "linux")]
fn native_policy_mutable_startup_rejects_before_lock_key_or_permission_changes() {
    use crate::Node;
    for existing in [false, true] {
        let temp = TempDir::new().unwrap();
        let seed = Seed::from_bytes([73; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        let key = [91; 32];
        if existing {
            let writer = ControlStore::open_with_key(temp.path().join("control.db"), &key).unwrap();
            writer
                .put_record("native-policy-fixture", b"retained", b"preserve")
                .unwrap();
            drop(writer);
        }
        let envelope = keys
            .wrap_native_database_key(b"control.db/v2", &key, &policy())
            .unwrap();
        write_new_private_record(&temp.path().join(CONTROL_KEY_FILE), &envelope).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o751)).unwrap();
        let before = footprint(temp.path());
        let metadata = fs::metadata(temp.path()).unwrap();
        let stamp = (
            metadata.ino(),
            metadata.mode(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        );
        let error = Node::open(temp.path(), seed)
            .err()
            .expect("generic startup cannot discard native policy");
        assert!(
            format!("{error:#}").contains("native I/O key policy"),
            "{error:#}"
        );
        assert_eq!(footprint(temp.path()), before);
        let metadata = fs::metadata(temp.path()).unwrap();
        assert_eq!(
            (
                metadata.ino(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec()
            ),
            stamp
        );
        assert!(!temp.path().join(".node.lock").exists());
        assert_eq!(temp.path().join("control.db").exists(), existing);
    }
}

#[test]
#[cfg(target_os = "linux")]
fn native_policy_invalid_key_records_reject_before_any_inspection_callback() {
    for kind in ["tamper", "context", "owner", "length", "version"] {
        let temp = TempDir::new().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let key = [91; 32];
        let writer = ControlStore::open_with_key(temp.path().join("control.db"), &key).unwrap();
        writer
            .put_record("native-policy-fixture", b"retained", b"preserve")
            .unwrap();
        drop(writer);
        let mut envelope = keys
            .wrap_native_database_key(
                if kind == "context" {
                    b"wrong.db"
                } else {
                    b"control.db/v2"
                },
                &key,
                &policy(),
            )
            .unwrap();
        match kind {
            "tamper" => envelope.ciphertext[48] ^= 1,
            "length" => envelope.ciphertext.push(0),
            "version" => envelope.format_version = 3,
            _ => {}
        }
        write_new_private_record(&temp.path().join(CONTROL_KEY_FILE), &envelope).unwrap();
        let before = footprint(temp.path());
        let other = KeyMaterial::from_seed(&Seed::from_bytes([74; 32]));
        let selected = if kind == "owner" { &other } else { &keys };
        let visited = std::cell::Cell::new(false);
        assert!(
            with_inspected_control_snapshot(temp.path(), selected, |_| {
                visited.set(true);
                Ok(())
            })
            .is_err(),
            "{kind}"
        );
        assert!(!visited.get());
        assert_eq!(footprint(temp.path()), before, "{kind}");
    }
}
