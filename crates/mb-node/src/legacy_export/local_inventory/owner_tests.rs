use super::*;
use git2::{ObjectType, Oid, Repository, Signature, Time};
use mb_core::{KeyMaterial, Seed, canonical_bytes};
use mb_git::{GitGraphBlobSource, GitGraphObject, GitGraphRef, GitGraphSource};
use mb_store::{
    AnchorAreaLocator, AnchorManifest, CapturedEntry, FileAnchorManifest, FileExtent,
    GuardedRootFileBacking, StableAnchorAreaLocator, StableAnchorManifest,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

pub(super) fn blob(source: &Path, area: &Path, index: usize) -> GitGraphBlobSource {
    let anchor_id = Uuid::from_u128(80 + index as u128);
    let bytes = [b"native!".as_slice(), b"guarded", b"import!"][index];
    let version = (
        7_u64,
        if index == 2 { 0_u64 } else { 31_u64 },
        7_u64,
        0_i64,
        0_i64,
        0_i64,
        0_i64,
    );
    let locator = StableAnchorAreaLocator {
        area_id: Uuid::from_u128(83 + index as u128),
        path_hint: area.to_path_buf(),
        filesystem_id: 7,
        volume_root_hint: PathBuf::from("/"),
    };
    let relative = if index == 2 {
        PathBuf::from(format!(".mutualbackup/git-import-{anchor_id}"))
    } else {
        tests::raw_path(Path::new(""), b"file-\xff")
    };
    let wire = if index == 1 {
        canonical_bytes(&(
            2_u16,
            anchor_id,
            locator,
            source.as_os_str().as_bytes().to_vec(),
            relative.as_os_str().as_bytes().to_vec(),
            7_u64,
            *blake3::hash(bytes).as_bytes(),
            version,
            GuardedRootFileBacking {
                root_anchor_id: Uuid::from_u128(86),
                captured_relative_path: tests::raw_path(Path::new("captured"), b"file-\xff"),
                native_id: NativeFileId {
                    filesystem_id: 7,
                    inode: 31,
                },
            },
        ))
        .unwrap()
    } else {
        canonical_bytes(&(
            1_u16,
            anchor_id,
            locator,
            source.as_os_str().as_bytes().to_vec(),
            relative.as_os_str().as_bytes().to_vec(),
            7_u64,
            *blake3::hash(bytes).as_bytes(),
            version,
        ))
        .unwrap()
    };
    GitGraphBlobSource {
        oid: Oid::hash_object(ObjectType::Blob, bytes)
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap(),
        anchor: decode_canonical::<FileAnchorManifest>(&wire).unwrap(),
    }
}

pub(super) fn graph(parent: &Path, repository_id: Uuid, tags: bool) -> GitGraphSource {
    let odb = git2::Odb::new().unwrap();
    odb.add_new_mempack_backend(1000).unwrap();
    let repository = Repository::from_odb(odb).unwrap();
    let blobs: Vec<_> = (0..3)
        .map(|index| {
            blob(
                &tests::raw_path(parent, &[b's', index as u8 + b'0', 0xff]),
                &tests::raw_path(parent, &[b'a', index as u8 + b'0', 0xff]),
                index,
            )
        })
        .collect();
    for (payload, blob) in [b"native!".as_slice(), b"guarded", b"import!"]
        .into_iter()
        .zip(&blobs)
    {
        assert_eq!(
            repository
                .odb()
                .unwrap()
                .write(ObjectType::Blob, payload)
                .unwrap()
                .as_bytes(),
            blob.oid
        );
    }
    let signature = Signature::new("retained", "retained@example.test", &Time::new(1, 0)).unwrap();
    let mut trees = Vec::new();
    let mut commits = Vec::new();
    for count in [1, 3] {
        let mut builder = repository.treebuilder(None).unwrap();
        for (index, blob) in blobs.iter().take(count).enumerate() {
            let path = tests::raw_path(Path::new(""), &[b'f', index as u8 + b'0', 0xff]);
            builder
                .insert(&path, Oid::from_bytes(&blob.oid).unwrap(), 0o100644)
                .unwrap();
        }
        let id = builder.write().unwrap();
        trees.push(id);
        let tree = repository.find_tree(id).unwrap();
        let parents: Vec<_> = commits
            .iter()
            .map(|id| repository.find_commit(*id).unwrap())
            .collect();
        let refs: Vec<_> = parents.iter().collect();
        commits.push(
            repository
                .commit(
                    None,
                    &signature,
                    &signature,
                    "retained history",
                    &tree,
                    &refs,
                )
                .unwrap(),
        );
    }
    let mut objects: Vec<_> = trees
        .into_iter()
        .map(|id| (id, 2))
        .chain(commits.iter().copied().map(|id| (id, 1)))
        .map(|(id, kind)| GitGraphObject {
            kind,
            oid: id.as_bytes().try_into().unwrap(),
            bytes: repository.odb().unwrap().read(id).unwrap().data().to_vec(),
        })
        .collect();
    let mut refs = vec![
        GitGraphRef {
            name: b"refs/heads/main".to_vec(),
            oid: commits[1].as_bytes().try_into().unwrap(),
        },
        GitGraphRef {
            name: b"refs/mutualbackup/pins/retained".to_vec(),
            oid: commits[0].as_bytes().try_into().unwrap(),
        },
    ];
    if tags {
        let target = repository
            .find_object(commits[1], Some(ObjectType::Commit))
            .unwrap();
        let id = repository
            .tag_annotation_create("v1", &target, &signature, "retained tag")
            .unwrap();
        objects.push(GitGraphObject {
            kind: 3,
            oid: id.as_bytes().try_into().unwrap(),
            bytes: repository.odb().unwrap().read(id).unwrap().data().to_vec(),
        });
        refs.push(GitGraphRef {
            name: b"refs/tags/v1".to_vec(),
            oid: id.as_bytes().try_into().unwrap(),
        });
    }
    GitGraphSource {
        format_version: if tags { 2 } else { 1 },
        repository_id,
        refs,
        objects,
        blobs,
    }
}

fn graph_bytes(version: u16, guild: [u8; 32], revision: Uuid, graph: &GitGraphSource) -> Vec<u8> {
    if version == 1 {
        canonical_bytes(&(version, guild, revision, graph.repository_id, graph)).unwrap()
    } else {
        canonical_bytes(&(
            version,
            guild,
            revision,
            graph.repository_id,
            graph,
            "retained-unborn",
        ))
        .unwrap()
    }
}

fn stable(parent: &Path, format: u16, anchor_id: Uuid) -> StableAnchorManifest {
    let path = if format == 3 {
        tests::raw_path(Path::new(""), b"retained-\xff")
    } else {
        PathBuf::from("retained")
    };
    StableAnchorManifest {
        format_version: format,
        anchor_id,
        source_root_hint: parent.join(format!("old-source-{format}")),
        area: StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            path_hint: parent.join(format!("old-area-{format}")),
            filesystem_id: 7,
            volume_root_hint: PathBuf::from("/"),
        },
        root_mode: libc::S_IFDIR | 0o700,
        root_modified_secs: 1,
        root_modified_nanos: 2,
        entries: vec![CapturedEntry::FileV2 {
            path,
            mode: libc::S_IFREG | 0o600,
            logical_len: 7,
            modified_secs: 1,
            modified_nanos: 2,
            native_id: NativeFileId {
                filesystem_id: 7,
                inode: 40,
            },
            data_extents: vec![FileExtent {
                offset: 0,
                logical_len: 7,
            }],
        }],
    }
}

fn legacy(parent: &Path) -> AnchorManifest {
    AnchorManifest {
        format_version: 1,
        anchor_id: Uuid::from_u128(89),
        source_root_hint: parent.join("legacy-source"),
        area: AnchorAreaLocator {
            area_id: Uuid::from_u128(90),
            path_hint: parent.join("legacy-area"),
        },
        root_mode: libc::S_IFDIR | 0o700,
        root_modified_secs: 1,
        root_modified_nanos: 2,
        entries: vec![CapturedEntry::File {
            path: PathBuf::from("old-file"),
            mode: libc::S_IFREG | 0o600,
            logical_len: 7,
            modified_secs: 1,
            modified_nanos: 2,
        }],
    }
}

#[test]
fn pending_git_inventory_preserves_history_raw_pins_imported_streams_and_original_head_layouts() {
    for wrapped in [false, true] {
        let ((keys, revision, _), _, _, _) =
            crate::legacy_export::tests::fixed_checkpoint_fixture(7);
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let current = graph(temp.path(), revision.value.protected_root_id, true);
        let old = graph(temp.path(), revision.value.protected_root_id, false);
        let store = if wrapped {
            crate::volume::open_control_store(&data, &keys).unwrap().0
        } else {
            ControlStore::open(data.join("control.db"), &keys).unwrap()
        };
        store
            .put_record(
                "git-graph-intent-v1",
                Uuid::from_u128(91).as_bytes(),
                &graph_bytes(1, revision.value.guild_id, Uuid::from_u128(91), &old),
            )
            .unwrap();
        store
            .put_record(
                "git-graph-intent-v1",
                revision.value.revision_id.as_bytes(),
                &graph_bytes(
                    2,
                    revision.value.guild_id,
                    revision.value.revision_id,
                    &current,
                ),
            )
            .unwrap();
        store
            .put_record(
                "user-revision",
                revision.value.revision_id.as_bytes(),
                &canonical_bytes(&revision).unwrap(),
            )
            .unwrap();
        if wrapped {
            let root = ProtectedRoot {
                format_version: 3,
                root_id: current.repository_id,
                path: temp.path().join("absent-registered-root"),
                filesystem_id: 7,
                root_inode: 100,
            };
            store
                .put_record(
                    "protected-root",
                    root.root_id.as_bytes(),
                    &canonical_bytes(&root).unwrap(),
                )
                .unwrap();
            let git = GitRepositoryInfo {
                format_version: 1,
                repository_id: current.repository_id,
                path: root.path,
            };
            store
                .put_record(
                    "git-repository",
                    git.repository_id.as_bytes(),
                    &canonical_bytes(&git).unwrap(),
                )
                .unwrap();
        }
        drop(store);
        let before = tests::preserved_files(&data);
        let report =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap();
        assert_eq!(report.format_version, 16);
        assert_eq!(report.local_state.pending_git_graphs.len(), 2);
        for entry in &report.local_state.pending_git_graphs {
            assert!(entry.graph_metadata_validated && !entry.payloads_verified);
            assert_eq!(entry.registered_root, wrapped);
            assert_eq!(entry.registered_repository, wrapped);
            assert_eq!(entry.blobs.len(), 3);
            assert_eq!(entry.head_branch_recorded, entry.record_format == 2);
            assert_eq!(
                entry.head_branch,
                if entry.record_format == 1 {
                    "main"
                } else {
                    "retained-unborn"
                }
            );
            assert_eq!(
                entry.signed_revision_metadata_available,
                entry.record_format == 2
            );
            assert_eq!(
                entry.refs.len(),
                if entry.record_format == 1 { 2 } else { 3 }
            );
            assert_eq!(
                entry.objects.len(),
                if entry.record_format == 1 { 4 } else { 5 }
            );
            for (index, pin) in entry.blobs.iter().enumerate() {
                let anchor = &current.blobs[index].anchor;
                assert_eq!(
                    pin.source_path_hint_hex,
                    hex::encode(anchor.source_root_hint.as_os_str().as_bytes())
                );
                if index == 1 {
                    assert_eq!(pin.locator_anchor_id, Uuid::from_u128(86));
                    assert_ne!(pin.anchor_id, pin.locator_anchor_id);
                    assert_eq!(
                        pin.locator_relative_path_hex,
                        hex::encode(b"captured/file-\xff")
                    );
                    assert_eq!(
                        pin.stable_file_identity,
                        Some(NativeFileId {
                            filesystem_id: 7,
                            inode: 31
                        })
                    );
                } else {
                    assert_eq!(pin.locator_anchor_id, pin.anchor_id);
                    assert!(pin.stable_file_identity.is_none());
                    assert_eq!(pin.locator_relative_path_hex, hex::encode(b"blob"));
                }
                assert_eq!(pin.recorded_file_identity.is_none(), index == 2);
                assert!(!anchor.source_root_hint.exists() && !anchor.area.path_hint.exists());
            }
        }
        crate::volume::with_inspected_control_snapshot(&data, &keys, |store| {
            assert!(collect(store, &mut 0, 64).is_err());
            Ok(())
        })
        .unwrap();
        tests::assert_preserved_files(&data, &before);
    }
}

#[test]
fn retained_anchor_inventory_preserves_legacy_stable_raw_and_retiring_owners() {
    let ((keys, revision, _), _, _, _) = crate::legacy_export::tests::fixed_checkpoint_fixture(6);
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
    let old = legacy(temp.path());
    store
        .put_record(
            "anchor-manifest",
            Uuid::from_u128(92).as_bytes(),
            &canonical_bytes(&old).unwrap(),
        )
        .unwrap();
    for (format, id) in [(2, Uuid::from_u128(93)), (3, revision.value.revision_id)] {
        store
            .put_record(
                "anchor-manifest",
                id.as_bytes(),
                &canonical_bytes(&stable(
                    temp.path(),
                    format,
                    Uuid::from_u128(format as u128 + 94),
                ))
                .unwrap(),
            )
            .unwrap();
    }
    let retiring = stable(temp.path(), 3, revision.value.revision_id);
    store
        .put_record(
            "anchor-retirement",
            retiring.anchor_id.as_bytes(),
            &canonical_bytes(&retiring).unwrap(),
        )
        .unwrap();
    store
        .put_record(
            "user-revision",
            revision.value.revision_id.as_bytes(),
            &canonical_bytes(&revision).unwrap(),
        )
        .unwrap();
    drop(store);
    let before = tests::preserved_files(&data);
    let report =
        super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
    assert_eq!(report.local_state.retained_anchors.len(), 4);
    for entry in &report.local_state.retained_anchors {
        assert!(!entry.payloads_verified);
        assert_eq!(entry.anchor.file_pins.len(), 1);
        if entry.anchor.record_format == 1 {
            assert!(
                entry.anchor.recorded_area_filesystem_id.is_none()
                    && entry.anchor.volume_root_hint_hex.is_none()
            );
        } else {
            assert_eq!(entry.anchor.recorded_area_filesystem_id, Some(7));
        }
        assert!(entry.anchor.stable_root_identity.is_none());
        let signed =
            entry.record_kind == "anchor-manifest" && entry.record_id == revision.value.revision_id;
        assert_eq!(entry.signed_revision_metadata_available, signed);
        assert_eq!(
            entry.protected_root_id,
            signed.then_some(revision.value.protected_root_id)
        );
        assert_eq!(
            entry.revision_id,
            (entry.record_kind == "anchor-manifest").then_some(entry.record_id)
        );
    }
    tests::assert_preserved_files(&data, &before);
    assert!(!old.source_root_hint.exists() && !old.area.path_hint.exists());
}

#[test]
fn graph_and_anchor_only_inputs_exclude_peer_scratch_without_catalog_or_payload_reads() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([98; 32]));
    let graph = graph(temp.path(), Uuid::from_u128(99), true);
    let old = legacy(temp.path());
    let root = stable(temp.path(), 3, Uuid::from_u128(100));
    let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
    let id = Uuid::from_u128(101);
    store
        .put_record(
            "git-graph-intent-v1",
            id.as_bytes(),
            &graph_bytes(2, [102; 32], id, &graph),
        )
        .unwrap();
    store
        .put_record(
            "anchor-manifest",
            Uuid::from_u128(103).as_bytes(),
            &canonical_bytes(&old).unwrap(),
        )
        .unwrap();
    store
        .put_record(
            "anchor-retirement",
            root.anchor_id.as_bytes(),
            &canonical_bytes(&root).unwrap(),
        )
        .unwrap();
    drop(store);
    let before = tests::preserved_files(&data);
    let mut paths = vec![
        old.source_root_hint,
        old.area.path_hint,
        root.source_root_hint,
        root.area.path_hint,
    ];
    for blob in &graph.blobs {
        paths.extend([
            blob.anchor.source_root_hint.clone(),
            blob.anchor.area.path_hint.clone(),
        ]);
    }
    for path in &paths {
        fs::create_dir_all(path.join("scratch")).unwrap();
        fs::write(path.join("witness"), b"preserved source").unwrap();
    }
    for path in &paths {
        assert!(
            super::super::remote::peer_client_preflight(
                &keys,
                &data,
                &path.join("scratch"),
                &[],
                false
            )
            .is_err()
        );
        assert!(
            super::super::remote::export_parent_preflight(&keys, &data, &path.join("scratch"), &[])
                .is_err()
        );
        assert!(fs::read_dir(path.join("scratch")).unwrap().next().is_none());
        assert_eq!(fs::read(path.join("witness")).unwrap(), b"preserved source");
        assert_eq!(fs::read_dir(path).unwrap().count(), 2);
    }
    super::super::remote::peer_client_preflight(&keys, &data, temp.path(), &[], false).unwrap();
    super::super::remote::export_parent_preflight(&keys, &data, temp.path(), &[]).unwrap();
    crate::volume::with_inspected_control_snapshot(&data, &keys, |store| {
        for_each_record(store, |record| {
            record.for_each_input(|input| {
                assert!(
                    matches!(input, PreservedInput::PathHint(_)),
                    "file identities must not be directory roots"
                );
                Ok(())
            })
        })
    })
    .unwrap();
    tests::assert_preserved_files(&data, &before);
}

fn reject_row(
    data: &Path,
    keys: &KeyMaterial,
    kind: &str,
    key: &[u8],
    bytes: &[u8],
    scratch: &Path,
) {
    let store = ControlStore::open(data.join("control.db"), keys).unwrap();
    store.put_record(kind, key, bytes).unwrap();
    drop(store);
    let before = tests::preserved_files(data);
    assert!(
        super::super::inventory::inventory_withdrawn_revisions_from_catalog(keys, data).is_err()
    );
    assert!(super::super::remote::peer_client_preflight(keys, data, scratch, &[], false).is_err());
    assert!(super::super::remote::export_parent_preflight(keys, data, scratch, &[]).is_err());
    tests::assert_preserved_files(data, &before);
    let store = ControlStore::open(data.join("control.db"), keys).unwrap();
    store.delete_record(kind, key).unwrap();
}

#[test]
fn corrupt_graph_intents_reject_original_encoding_identity_dag_and_blob_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([104; 32]));
    let source = graph(temp.path(), Uuid::from_u128(105), true);
    let id = Uuid::from_u128(106);
    let valid = graph_bytes(2, [107; 32], id, &source);
    let mut bad = vec![0x82, 0];
    bad.extend_from_slice(&valid[1..]);
    reject_row(
        &data,
        &keys,
        "git-graph-intent-v1",
        id.as_bytes(),
        &bad,
        temp.path(),
    );
    bad = valid.clone();
    bad.push(0);
    reject_row(
        &data,
        &keys,
        "git-graph-intent-v1",
        id.as_bytes(),
        &bad,
        temp.path(),
    );
    reject_row(
        &data,
        &keys,
        "git-graph-intent-v1",
        &[0; 17],
        &valid,
        temp.path(),
    );
    reject_row(
        &data,
        &keys,
        "git-graph-intent-v1",
        Uuid::from_u128(108).as_bytes(),
        &valid,
        temp.path(),
    );
    for mutation in 0..9 {
        let mut graph = source.clone();
        match mutation {
            0 => graph.objects[0].bytes.push(0),
            1 => {
                graph.objects.remove(0);
            }
            2 => graph.blobs.push(graph.blobs[0].clone()),
            3 => {
                graph.blobs.remove(0);
            }
            4 => graph.refs.push(graph.refs[0].clone()),
            5 => {
                graph.blobs[1]
                    .anchor
                    .guarded_root_file
                    .as_mut()
                    .unwrap()
                    .captured_relative_path = PathBuf::from("../escape")
            }
            6 => {
                graph.blobs[1]
                    .anchor
                    .guarded_root_file
                    .as_mut()
                    .unwrap()
                    .root_anchor_id = graph.blobs[1].anchor.anchor_id
            }
            7 => graph.blobs[2].anchor.logical_len = 8,
            8 => graph.format_version = 1,
            _ => unreachable!(),
        }
        reject_row(
            &data,
            &keys,
            "git-graph-intent-v1",
            id.as_bytes(),
            &graph_bytes(2, [107; 32], id, &graph),
            temp.path(),
        );
    }
}

#[test]
fn corrupt_retained_anchors_reject_unsafe_paths_extents_and_retirement_keys() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([109; 32]));
    let id = Uuid::from_u128(110);
    let root = stable(temp.path(), 3, Uuid::from_u128(111));
    reject_row(
        &data,
        &keys,
        "anchor-retirement",
        id.as_bytes(),
        &canonical_bytes(&root).unwrap(),
        temp.path(),
    );
    let mut old = legacy(temp.path());
    old.source_root_hint = PathBuf::from("relative/source");
    reject_row(
        &data,
        &keys,
        "anchor-manifest",
        id.as_bytes(),
        &canonical_bytes(&old).unwrap(),
        temp.path(),
    );
    for mutation in 0..5 {
        let mut root = root.clone();
        match mutation {
            0 => root.format_version = 2,
            1 => root.area.area_id = Uuid::nil(),
            2 => {
                if let CapturedEntry::FileV2 { path, .. } = &mut root.entries[0] {
                    *path = PathBuf::from("../escape");
                }
            }
            3 => {
                if let CapturedEntry::FileV2 { data_extents, .. } = &mut root.entries[0] {
                    data_extents[0].logical_len = 8;
                }
            }
            4 => root.entries.push(root.entries[0].clone()),
            _ => unreachable!(),
        }
        reject_row(
            &data,
            &keys,
            "anchor-manifest",
            id.as_bytes(),
            &canonical_bytes(&root).unwrap(),
            temp.path(),
        );
    }
}

#[test]
fn preserved_graph_inventory_and_placement_do_not_create_git_scratch() {
    const CHILD_DATA: &str = "MUTUALBACKUP_TEST_PRESERVED_GRAPH_CHILD_DATA";
    const CHILD_SCRATCH: &str = "MUTUALBACKUP_TEST_PRESERVED_GRAPH_CHILD_SCRATCH";
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([112; 32]));
    if let Some(data) = std::env::var_os(CHILD_DATA) {
        let data = PathBuf::from(data);
        let report =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap();
        assert_eq!(report.local_state.pending_git_graphs.len(), 1);
        assert!(report.local_state.pending_git_graphs[0].graph_metadata_validated);
        let scratch = PathBuf::from(std::env::var_os(CHILD_SCRATCH).unwrap());
        super::super::remote::peer_client_preflight(&keys, &data, &scratch, &[], false).unwrap();
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let scratch = temp.path().join("safe");
    fs::create_dir(&scratch).unwrap();
    let source = graph(temp.path(), Uuid::from_u128(113), true);
    let id = Uuid::from_u128(114);
    let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
    store
        .put_record(
            "git-graph-intent-v1",
            id.as_bytes(),
            &graph_bytes(2, [115; 32], id, &source),
        )
        .unwrap();
    drop(store);
    let before = tests::preserved_files(&data);
    let absent = temp.path().join("absent-git-scratch");
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["legacy_export::local_inventory::owner_tests::preserved_graph_inventory_and_placement_do_not_create_git_scratch", "--exact"])
        .env(CHILD_DATA, &data).env(CHILD_SCRATCH, &scratch).env("TMPDIR", &absent).output().unwrap();
    assert!(
        result.status.success(),
        "child graph inspection failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(String::from_utf8_lossy(&result.stdout).contains("1 passed; 0 failed; 0 ignored"));
    assert!(!absent.exists());
    assert!(fs::read_dir(&scratch).unwrap().next().is_none());
    tests::assert_preserved_files(&data, &before);
}

#[test]
fn cached_anchor_locations_preserve_raw_relative_hints_and_exclude_absolute_scratch() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([116; 32]));
    let area = tests::raw_path(temp.path(), b"relocated-\xff");
    let relative = PathBuf::from("relative/historical-cwd");
    let id = Uuid::from_u128(117);
    let relative_id = Uuid::from_u128(118);
    let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
    crate::snapshot::remember_anchor_area_location(&store, id, &area).unwrap();
    crate::snapshot::remember_anchor_area_location(&store, relative_id, &relative).unwrap();
    drop(store);
    let before = tests::preserved_files(&data);
    let report =
        super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
    let locations = &report.local_state.anchor_area_locations;
    assert_eq!(locations.len(), 2);
    assert_eq!(locations[0].area_id, id);
    assert!(locations[0].absolute_path);
    assert_eq!(
        locations[0].path_hint_hex,
        hex::encode(area.as_os_str().as_bytes())
    );
    assert_eq!(locations[1].area_id, relative_id);
    assert!(!locations[1].absolute_path);
    assert_eq!(
        locations[1].path_hint_hex,
        hex::encode(relative.as_os_str().as_bytes())
    );
    assert!(!area.exists());
    fs::create_dir_all(area.join("scratch")).unwrap();
    assert!(
        super::super::remote::peer_client_preflight(
            &keys,
            &data,
            &area.join("scratch"),
            &[],
            false
        )
        .is_err()
    );
    assert!(fs::read_dir(area.join("scratch")).unwrap().next().is_none());
    assert!(
        super::super::remote::export_parent_preflight(&keys, &data, &area.join("scratch"), &[])
            .is_err()
    );
    super::super::remote::peer_client_preflight(&keys, &data, temp.path(), &[], false).unwrap();
    super::super::remote::export_parent_preflight(&keys, &data, temp.path(), &[]).unwrap();
    tests::assert_preserved_files(&data, &before);
    let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
    store
        .delete_record("anchor-area-location", id.as_bytes())
        .unwrap();
    store
        .delete_record("anchor-area-location", relative_id.as_bytes())
        .unwrap();
    drop(store);
    for path in [
        tests::raw_path(Path::new("/"), b"bad-\0"),
        PathBuf::from(format!("/{}", "x".repeat(5000))),
    ] {
        reject_row(
            &data,
            &keys,
            "anchor-area-location",
            id.as_bytes(),
            &canonical_bytes(&path.as_os_str().as_bytes().to_vec()).unwrap(),
            temp.path(),
        );
    }
}
