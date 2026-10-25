use super::*;
use mb_core::{Seed, V1_SECTOR_SIZE, sector_root};
use std::{cell::RefCell, rc::Rc};

fn object(marker: u8) -> ParityObject {
    let bytes = vec![marker; V1_SECTOR_SIZE];
    ParityObject {
        format_version: 1,
        guild_id: [3; 32],
        group_id: [4; 32],
        shard_index: 3,
        root: sector_root(&bytes),
        bytes,
    }
}

fn files(path: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.file_name().unwrap().into(), fs::read(path).unwrap())
        })
        .collect()
}

#[test]
fn default_volume_startup_keeps_the_control_directory_before_and_after_caller_admission() {
    let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([233; 32])));
    for registered in [false, true] {
        for after_admission in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("node");
            let owned = temp.path().join("owned");
            fs::create_dir(&root).unwrap();
            let directory = DatabaseDirectory::open(&root).unwrap();
            let control = ControlStore::open_in_directory_with_key(
                &directory,
                OsStr::new("control.db"),
                &[33; 32],
            )
            .unwrap();
            if registered {
                drop(StorageVolumes::open(&root, keys.clone(), &control).unwrap());
            }
            let registry = control
                .get_record("node-config", b"storage-volumes")
                .unwrap();
            let observed = Rc::new(RefCell::new(None));
            let captured = observed.clone();
            let visible = root.clone();
            let original = owned.clone();
            let replace = move || {
                fs::rename(&visible, &original).unwrap();
                fs::create_dir(&visible).unwrap();
                fs::write(visible.join("sentinel"), b"preserve replacement").unwrap();
                *captured.borrow_mut() = Some((files(&original), files(&visible)));
            };
            if after_admission {
                BEFORE_DEFAULT_VOLUME_OPEN
                    .with(|hook| *hook.borrow_mut() = Some(Box::new(replace)));
            } else {
                replace();
            }
            assert!(
                StorageVolumes::open(&root, keys.clone(), &control).is_err(),
                "{registered}/{after_admission}"
            );
            let (original, replacement) = observed.borrow_mut().take().unwrap();
            assert_eq!(files(&owned), original, "{registered}/{after_admission}");
            assert_eq!(files(&root), replacement, "{registered}/{after_admission}");
            assert_eq!(
                control
                    .get_record("node-config", b"storage-volumes")
                    .unwrap(),
                registry
            );
        }
    }
}

#[test]
fn default_volume_configuration_and_reactivation_reject_a_replaced_control_directory() {
    let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([232; 32])));
    for operation in ["configure", "reactivate"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("node");
        let owned = temp.path().join("owned");
        fs::create_dir(&root).unwrap();
        let directory = DatabaseDirectory::open(&root).unwrap();
        let control = ControlStore::open_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[34; 32],
        )
        .unwrap();
        let mut volumes = StorageVolumes::open(&root, keys.clone(), &control).unwrap();
        let id = *volumes.volumes.keys().next().unwrap();
        let volume = volumes.volumes.get_mut(&id).unwrap();
        volume.store = None;
        volume.record.state = StorageVolumeState::Retired;
        volumes.persist(&control).unwrap();
        let registry = control
            .get_record("node-config", b"storage-volumes")
            .unwrap();
        fs::rename(&root, &owned).unwrap();
        fs::create_dir(&root).unwrap();
        fs::write(root.join("sentinel"), b"preserve replacement").unwrap();
        let before = (files(&owned), files(&root));
        let result = if operation == "configure" {
            volumes.configure(&control, &[], 1 << 20, 0)
        } else {
            volumes.reactivate(&control, id)
        };
        assert!(result.is_err(), "{operation}");
        assert_eq!((files(&owned), files(&root)), before, "{operation}");
        assert_eq!(
            control
                .get_record("node-config", b"storage-volumes")
                .unwrap(),
            registry
        );
        assert!(volumes.volumes.get(&id).unwrap().store.is_none());
        assert_eq!(
            volumes.volumes.get(&id).unwrap().record.state,
            StorageVolumeState::Retired
        );
    }
}

#[test]
fn volume_admission_migrates_exact_legacy_payloads_and_resumes_interrupted_rekeys() {
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([239; 32]));
    for mode in ["closed", "live-wal", "wal-only", "interrupted"] {
        let temp = tempfile::tempdir().unwrap();
        let id = legacy_default_volume_id(&keys);
        let old_key = keys.database_key(&legacy_volume_database_id(id));
        let mut store =
            ParityStore::open_with_key(temp.path().join("parity.db"), id.as_bytes(), &old_key)
                .unwrap();
        let expected = object(13);
        store
            .stage_and_publish_ack(&expected, b"ack", 1 << 20)
            .unwrap();
        if mode == "wal-only" {
            store
                .database_shell_statement("PRAGMA wal_checkpoint(TRUNCATE)", false)
                .unwrap();
            // Keep a committed frame while preserving main and WAL only.
            store
                .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
                .unwrap();
            let mut additional = object(14);
            additional.group_id = [9; 32];
            store
                .stage_and_publish_ack(&additional, b"ack", 1 << 20)
                .unwrap();
            for name in ["parity.db", "parity.db-wal"] {
                fs::copy(
                    temp.path().join(name),
                    temp.path().join(format!("copy-{name}")),
                )
                .unwrap();
            }
        }
        let mut live = Some(store);
        if mode != "live-wal" {
            drop(live.take());
        }
        if mode == "wal-only" {
            for name in ["parity.db", "parity.db-wal"] {
                fs::rename(
                    temp.path().join(format!("copy-{name}")),
                    temp.path().join(name),
                )
                .unwrap();
            }
        }
        if mode == "interrupted" {
            let manifest = VolumeManifest {
                format_version: 1,
                owner: keys.node_id(),
                volume_id: id,
                database_file: "parity.db".into(),
                wrapped_database_key: keys
                    .wrap_database_key(&volume_database_id(id), &[54; 32])
                    .unwrap(),
            };
            write_new_private_record(
                &temp.path().join(VOLUME_MANIFEST_FILE),
                &SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, &keys).unwrap(),
            )
            .unwrap();
        }
        // A live writer prevents the legacy rekey; dropping it then retrying
        // must authenticate the same original bytes and durable target key.
        if mode == "live-wal" {
            let directory = DatabaseDirectory::open(temp.path()).unwrap();
            let guard =
                DatabaseOpenGuard::capture(&directory.leaf("parity.db").unwrap(), &[]).unwrap();
            assert_eq!(
                admit_key(&directory, "parity.db", id, &guard, &[old_key]).unwrap(),
                Some(old_key)
            );
            drop(live.take());
        }
        let record = initialize_volume(temp.path(), Some("parity.db"), 1 << 20, 0, &keys).unwrap();
        assert_eq!(record.volume_id, id, "{mode}");
        let key = keys
            .unwrap_database_key(&volume_database_id(id), &record.wrapped_database_key)
            .unwrap();
        let opened = open_volume_store(&record, &key, &keys).unwrap();
        assert_eq!(
            opened
                .load_ready(&expected.group_id, expected.shard_index)
                .unwrap(),
            expected
        );
        assert!(opened.directory().is_some());
        drop(opened);
        assert!(open_volume_store(&record, &key, &keys).is_ok());
    }
}

#[test]
fn volume_admission_rejects_damaged_legacy_inputs_before_manifest_or_database_writes() {
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([238; 32]));
    for mode in [
        "empty",
        "corrupt",
        "orphan-wal",
        "orphan-shm",
        "orphan-journal",
        "wrong-id",
        "wrong-key",
    ] {
        let temp = tempfile::tempdir().unwrap();
        match mode {
            "empty" => fs::write(temp.path().join("parity.db"), []).unwrap(),
            "corrupt" => {
                fs::write(temp.path().join("parity.db"), b"preserved broken catalog").unwrap()
            }
            "orphan-wal" | "orphan-shm" | "orphan-journal" => {
                let suffix = mode.strip_prefix("orphan-").unwrap();
                fs::write(
                    temp.path().join(format!("parity.db-{suffix}")),
                    b"preserved orphan",
                )
                .unwrap();
            }
            _ => {
                let id = if mode == "wrong-id" {
                    Uuid::new_v4()
                } else {
                    legacy_default_volume_id(&keys)
                };
                let key = if mode == "wrong-key" {
                    [97; 32]
                } else {
                    keys.database_key(&legacy_volume_database_id(id))
                };
                drop(
                    ParityStore::open_with_key(temp.path().join("parity.db"), id.as_bytes(), &key)
                        .unwrap(),
                );
            }
        }
        let before = files(temp.path());
        assert!(
            initialize_volume(temp.path(), Some("parity.db"), 1 << 20, 0, &keys).is_err(),
            "{mode}"
        );
        assert_eq!(files(temp.path()), before, "{mode}");
        assert!(!temp.path().join(VOLUME_MANIFEST_FILE).exists());
    }
}

#[test]
fn volume_admission_rejects_changed_inputs_before_initial_or_registered_writers() {
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([237; 32]));
    for initial in [true, false] {
        for mode in [
            "database",
            "removed",
            "manifest",
            "wal",
            "directory",
            "directory-mode",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("volume");
            fs::create_dir(&root).unwrap();
            let record = initialize_volume(&root, Some("parity.db"), 1 << 20, 0, &keys).unwrap();
            let key = keys
                .unwrap_database_key(
                    &volume_database_id(record.volume_id),
                    &record.wrapped_database_key,
                )
                .unwrap();
            let before_hook = Rc::new(RefCell::new(None));
            let captured = before_hook.clone();
            let location = root.clone();
            let moved = temp.path().join("original");
            let preserved = moved.clone();
            BEFORE_VOLUME_WRITER.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    match mode {
                        "database" => {
                            fs::rename(location.join("parity.db"), location.join("original.db"))
                                .unwrap();
                            fs::write(location.join("parity.db"), b"preserve replacement").unwrap();
                        }
                        "removed" => {
                            fs::rename(location.join("parity.db"), location.join("original.db"))
                                .unwrap();
                        }
                        "manifest" => {
                            fs::write(
                                location.join(VOLUME_MANIFEST_FILE),
                                b"preserve changed manifest",
                            )
                            .unwrap();
                        }
                        "wal" => {
                            fs::write(location.join("parity.db-wal"), b"preserve new WAL").unwrap();
                        }
                        "directory" => {
                            fs::rename(&location, &moved).unwrap();
                            fs::create_dir(&location).unwrap();
                            fs::write(location.join("sentinel"), b"replacement directory").unwrap();
                        }
                        "directory-mode" => {
                            fs::set_permissions(&location, fs::Permissions::from_mode(0o770))
                                .unwrap();
                        }
                        _ => unreachable!(),
                    }
                    *captured.borrow_mut() = Some(files(&location));
                }))
            });
            let result = if initial {
                initialize_volume(&root, Some("parity.db"), 1 << 20, 0, &keys).map(|_| ())
            } else {
                open_volume_store(&record, &key, &keys).map(|_| ())
            };
            assert!(result.is_err(), "{initial}/{mode}");
            assert_eq!(
                files(&root),
                before_hook.borrow_mut().take().unwrap(),
                "{initial}/{mode}"
            );
            if mode == "directory" {
                assert_eq!(files(&preserved).len(), 2);
            }
        }
    }
}

#[test]
fn volume_admission_resumes_manifest_only_initialization_but_does_not_recreate_registered_data() {
    let temp = tempfile::tempdir().unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([236; 32]));
    let record = initialize_volume(temp.path(), Some("parity.db"), 1 << 20, 0, &keys).unwrap();
    let key = keys
        .unwrap_database_key(
            &volume_database_id(record.volume_id),
            &record.wrapped_database_key,
        )
        .unwrap();
    fs::remove_file(temp.path().join("parity.db")).unwrap();
    let before = files(temp.path());
    assert!(open_volume_store(&record, &key, &keys).is_err());
    assert_eq!(files(temp.path()), before);
    let resumed = initialize_volume(temp.path(), Some("parity.db"), 1 << 20, 0, &keys).unwrap();
    assert_eq!(resumed.volume_id, record.volume_id);
    assert_eq!(resumed.wrapped_database_key, record.wrapped_database_key);
    assert!(open_volume_store(&resumed, &key, &keys).is_ok());
}

#[test]
fn volume_admission_fences_new_manifest_publication_and_preserves_unregistered_legacy_data() {
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([235; 32]));
    for legacy in [false, true] {
        for mode in ["manifest", "main", "directory"] {
            let temp = tempfile::tempdir().unwrap();
            let root = temp.path().join("volume");
            fs::create_dir(&root).unwrap();
            if legacy {
                let id = legacy_default_volume_id(&keys);
                let key = keys.database_key(&legacy_volume_database_id(id));
                let mut store =
                    ParityStore::open_with_key(root.join("parity.db"), id.as_bytes(), &key)
                        .unwrap();
                store.stage_and_publish(&object(19)).unwrap();
            }
            let changed = Rc::new(RefCell::new(None));
            let captured = changed.clone();
            let location = root.clone();
            let moved = temp.path().join("original");
            let original = moved.clone();
            BEFORE_VOLUME_WRITER.with(|hook| {
                *hook.borrow_mut() = Some(Box::new(move || {
                    match mode {
                        "manifest" => {
                            fs::write(location.join(VOLUME_MANIFEST_FILE), b"concurrent manifest")
                                .unwrap()
                        }
                        "main" => {
                            if legacy {
                                fs::rename(
                                    location.join("parity.db"),
                                    location.join("original.db"),
                                )
                                .unwrap();
                            }
                            fs::write(location.join("parity.db"), b"concurrent main").unwrap();
                        }
                        "directory" => {
                            fs::rename(&location, &moved).unwrap();
                            fs::create_dir(&location).unwrap();
                            fs::write(location.join("sentinel"), b"concurrent directory").unwrap();
                        }
                        _ => unreachable!(),
                    }
                    *captured.borrow_mut() = Some(files(&location));
                }))
            });
            assert!(
                initialize_volume(&root, Some("parity.db"), 1 << 20, 0, &keys).is_err(),
                "{legacy}/{mode}"
            );
            assert_eq!(files(&root), changed.borrow_mut().take().unwrap());
            if mode == "directory" {
                assert!(!original.join(VOLUME_MANIFEST_FILE).exists());
                assert_eq!(files(&original).len(), usize::from(legacy));
            }
        }
    }
}

#[test]
fn volume_admission_rechecks_the_published_key_before_creating_a_database() {
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([234; 32]));
    for mode in ["manifest", "wal"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        let other_keys = KeyMaterial::from_seed(&Seed::from_bytes([234; 32]));
        let observed = Rc::new(RefCell::new(None));
        let captured = observed.clone();
        AFTER_MANIFEST_PUBLICATION.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                let mut manifest = read_volume_manifest(&root, &other_keys).unwrap().unwrap();
                if mode == "manifest" {
                    manifest.wrapped_database_key = other_keys
                        .wrap_database_key(&volume_database_id(manifest.volume_id), &[79; 32])
                        .unwrap();
                    fs::remove_file(root.join(VOLUME_MANIFEST_FILE)).unwrap();
                    write_new_private_record(
                        &root.join(VOLUME_MANIFEST_FILE),
                        &SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, &other_keys).unwrap(),
                    )
                    .unwrap();
                } else {
                    fs::write(
                        root.join(format!("{}-wal", manifest.database_file)),
                        b"unadmitted WAL",
                    )
                    .unwrap();
                }
                *captured.borrow_mut() = Some(files(&root));
            }))
        });
        assert!(
            initialize_volume(temp.path(), None, 1 << 20, 0, &keys).is_err(),
            "{mode}"
        );
        assert_eq!(files(temp.path()), observed.borrow_mut().take().unwrap());
    }
}

#[test]
fn managed_parity_handoff_rejects_main_journal_manifest_and_birth_substitution() {
    use crate::volume::native_node::tests::{footprint, policy};
    for substitution in ["main", "wal", "manifest", "birth"] {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([88; 32]);
        drop(crate::Node::create_native(temp.path(), seed.clone(), policy()).unwrap());
        let keys = KeyMaterial::from_seed(&seed);
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let control = ControlStore::open_native_existing_in_directory(
            &directory,
            OsStr::new("control.db"),
            &keys,
            b"control.db/v2",
        )
        .unwrap();
        let record = load_volume_records(&control).unwrap().remove(0);
        drop(control);
        let key = keys
            .unwrap_native_database_key(
                &volume_database_id(record.volume_id),
                &record.wrapped_database_key,
            )
            .unwrap()
            .0;
        let observed = Rc::new(RefCell::new(None));
        let captured = observed.clone();
        let visible = temp.path().to_owned();
        BEFORE_VOLUME_WRITER.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                match substitution {
                    "main" => {
                        fs::rename(visible.join("parity.db"), visible.join("original.db")).unwrap();
                        fs::copy(visible.join("original.db"), visible.join("parity.db")).unwrap();
                    }
                    "wal" => {
                        fs::write(visible.join("parity.db-wal"), b"unadmitted journal").unwrap()
                    }
                    "manifest" => {
                        let file = visible.join(VOLUME_MANIFEST_FILE);
                        fs::rename(&file, visible.join("original-manifest")).unwrap();
                        fs::copy(visible.join("original-manifest"), file).unwrap();
                    }
                    "birth" => {
                        let name = format!(
                            ".mutualbackup-native-{}",
                            blake3::hash(b"parity.db").to_hex()
                        );
                        let file = visible.join(name).join("birth");
                        fs::rename(&file, file.with_file_name("original-birth")).unwrap();
                        fs::copy(file.with_file_name("original-birth"), file).unwrap();
                    }
                    _ => unreachable!(),
                }
                *captured.borrow_mut() = Some(footprint(&visible));
            }))
        });
        assert!(
            open_volume_store_in_directory(&record, &key, &keys, &directory).is_err(),
            "{substitution}"
        );
        assert_eq!(
            footprint(temp.path()),
            observed.borrow_mut().take().unwrap(),
            "{substitution}"
        );
    }
}
