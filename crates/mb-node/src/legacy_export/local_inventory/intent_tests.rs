use super::*;
use mb_core::{KeyMaterial, Seed, canonical_bytes};
use mb_store::{
    CapturedEntry, FileExtent, SourceCapturePlan, StableAnchorAreaLocator, StableAnchorManifest,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

// Positional historical fixtures deliberately do not use the current envelopes.
fn plan(source: &Path, area: &Path, guarded: bool) -> SourceCapturePlan {
    let locator = StableAnchorAreaLocator {
        area_id: Uuid::from_bytes([61; 16]),
        path_hint: area.to_path_buf(),
        filesystem_id: 2,
        volume_root_hint: PathBuf::from("/"),
    };
    let version = (2_u64, 3_u64, 0_u64, 4_i64, 5_i64, 6_i64, 7_i64);
    let common = (
        1_u16,
        Uuid::from_bytes([62; 16]),
        source.as_os_str().as_bytes().to_vec(),
        locator.clone(),
        version,
        libc::S_IFDIR | 0o700,
        4_i64,
        5_u32,
    );
    if guarded {
        #[derive(Serialize)]
        enum Entry {
            Directory(Vec<u8>, (u64, u64, u64, i64, i64, i64, i64), u32, i64, u32),
            File(
                Vec<u8>,
                Uuid,
                (u64, u64, u64, i64, i64, i64, i64),
                u32,
                i64,
                u32,
            ),
        }
        let entries = vec![
            Entry::Directory(
                b"dir".to_vec(),
                (2, 8, 0, 4, 5, 6, 7),
                libc::S_IFDIR | 0o700,
                4,
                5,
            ),
            Entry::File(
                b"dir/file-\xff".to_vec(),
                Uuid::from_bytes([63; 16]),
                (2, 9, 7, 4, 5, 6, 7),
                libc::S_IFREG | 0o600,
                4,
                5,
            ),
        ];
        let bytes = canonical_bytes(&(
            2_u16, common.1, common.2, locator, version, common.5, common.6, common.7, entries,
        ))
        .unwrap();
        SourceCapturePlan::GuardedLinkFreezeV1(decode_canonical(&bytes).unwrap())
    } else {
        SourceCapturePlan::ReflinkV1(decode_canonical(&canonical_bytes(&common).unwrap()).unwrap())
    }
}

fn capture_bytes(version: u16, revision: Uuid, plan: &SourceCapturePlan) -> Vec<u8> {
    let guild = [64_u8; 32];
    let parent = Some([65_u8; 32]);
    let requested = PathBuf::from("relative/original-request");
    if version == 3 {
        canonical_bytes(&(
            version,
            guild,
            revision,
            10_u64,
            parent,
            Some(11_u64),
            requested,
            plan,
        ))
        .unwrap()
    } else {
        let SourceCapturePlan::ReflinkV1(native) = plan else {
            panic!("old envelope requires native plan")
        };
        if version == 2 {
            canonical_bytes(&(
                version,
                guild,
                revision,
                10_u64,
                parent,
                Some(11_u64),
                requested,
                native,
            ))
            .unwrap()
        } else {
            canonical_bytes(&(version, guild, revision, 10_u64, parent, requested, native)).unwrap()
        }
    }
}

fn replaced(source: &Path, area: &Path) -> StableAnchorManifest {
    StableAnchorManifest {
        format_version: 3,
        anchor_id: Uuid::from_bytes([66; 16]),
        source_root_hint: source.to_path_buf(),
        area: StableAnchorAreaLocator {
            area_id: Uuid::from_bytes([67; 16]),
            path_hint: area.to_path_buf(),
            filesystem_id: 2,
            volume_root_hint: PathBuf::from("/"),
        },
        root_mode: libc::S_IFDIR | 0o700,
        root_modified_secs: 4,
        root_modified_nanos: 5,
        entries: vec![CapturedEntry::FileV2 {
            path: tests::raw_path(Path::new(""), b"old-\xff"),
            mode: libc::S_IFREG | 0o600,
            logical_len: 3,
            modified_secs: 4,
            modified_nanos: 5,
            native_id: NativeFileId {
                filesystem_id: 2,
                inode: 25,
            },
            data_extents: vec![FileExtent {
                offset: 0,
                logical_len: 3,
            }],
        }],
    }
}

fn recovery_bytes(
    version: u16,
    revision: Uuid,
    plan: &SourceCapturePlan,
    old: &StableAnchorManifest,
) -> Vec<u8> {
    let source = PathBuf::from("/absent/requested-recovery");
    if version == 2 {
        canonical_bytes(&(version, [64_u8; 32], revision, source, plan, Some(old))).unwrap()
    } else {
        let SourceCapturePlan::ReflinkV1(native) = plan else {
            panic!("old envelope requires native plan")
        };
        canonical_bytes(&(version, [64_u8; 32], revision, source, native, Some(old))).unwrap()
    }
}

#[test]
fn pending_capture_inventory_preserves_all_envelopes_raw_pins_and_old_identity_ambiguity() {
    for wrapped in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([68; 32]));
        let source = tests::raw_path(temp.path(), b"absent-source-\xff");
        let area = tests::raw_path(temp.path(), b"absent-area-\xff");
        let native = plan(&source, &area, false);
        let guarded = plan(&source, &area, true);
        let old = replaced(
            &temp.path().join("absent-old-source"),
            &temp.path().join("absent-old-area"),
        );
        let store = if wrapped {
            crate::volume::open_control_store(&data, &keys).unwrap().0
        } else {
            ControlStore::open(data.join("control.db"), &keys).unwrap()
        };
        for (index, version) in [1, 2, 3].into_iter().enumerate() {
            let id = Uuid::from_u128(index as u128 + 1);
            store
                .put_record(
                    "capture-intent",
                    id.as_bytes(),
                    &capture_bytes(version, id, &native),
                )
                .unwrap();
        }
        let id = Uuid::from_u128(4);
        store
            .put_record(
                "capture-intent",
                id.as_bytes(),
                &capture_bytes(3, id, &guarded),
            )
            .unwrap();
        for (index, (version, plan)) in [(1, &native), (2, &native), (2, &guarded)]
            .into_iter()
            .enumerate()
        {
            let id = Uuid::from_u128(index as u128 + 5);
            store
                .put_record(
                    "recovery-anchor-intent",
                    id.as_bytes(),
                    &recovery_bytes(version, id, plan, &old),
                )
                .unwrap();
        }
        drop(store);
        let before = tests::preserved_files(&data);
        let report =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap();
        assert_eq!(report.format_version, 6);
        assert!(!report.retained_history_complete);
        let captures = report.local_state.pending_captures;
        assert_eq!(captures.len(), 7);
        for capture in &captures {
            assert!(!capture.payloads_verified && !capture.signed_revision_metadata_available);
            let root = &capture.planned_anchor;
            assert_eq!(
                root.source_path_hint_hex,
                hex::encode(source.as_os_str().as_bytes())
            );
            assert_eq!(
                root.area_path_hint_hex,
                hex::encode(area.as_os_str().as_bytes())
            );
            assert_eq!(
                root.recorded_root_identity,
                Some(NativeFileId {
                    filesystem_id: 2,
                    inode: 3
                })
            );
            if capture.backend == mb_store::SourceBackendKind::GuardedLinkFreezeV1 {
                assert_eq!(root.record_format, 2);
                assert_eq!(root.stable_root_identity, root.recorded_root_identity);
                assert_eq!(root.file_pins.len(), 1);
                assert_eq!(
                    root.file_pins[0].relative_path_hex,
                    hex::encode(b"dir/file-\xff")
                );
                assert_eq!(root.file_pins[0].capture_id, Uuid::from_bytes([63; 16]));
            } else {
                assert!(root.stable_root_identity.is_none());
                assert!(root.file_pins.is_empty());
            }
            if capture.record_kind == "capture-intent" {
                assert_eq!(capture.sequence, Some(10));
                assert_eq!(
                    capture.captured_change_sequence,
                    if capture.record_format == 1 {
                        None
                    } else {
                        Some(11)
                    }
                );
            } else {
                let old = capture.replaced_anchor.as_ref().unwrap();
                assert_eq!(old.anchor_id, Uuid::from_bytes([66; 16]));
                assert_eq!(old.file_pins.len(), 1);
                assert_eq!(old.file_pins[0].relative_path_hex, hex::encode(b"old-\xff"));
                assert!(old.stable_root_identity.is_none());
            }
        }
        crate::volume::with_inspected_control_snapshot(&data, &keys, |store| {
            assert!(collect(store, &mut 0, 64).is_err());
            Ok(())
        })
        .unwrap();
        tests::assert_preserved_files(&data, &before);
        assert!(
            !source.exists()
                && !area.exists()
                && !old.source_root_hint.exists()
                && !old.area.path_hint.exists()
        );
    }
}

#[test]
fn pending_only_owners_exclude_peer_scratch_without_creating_or_replaying_state() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([69; 32]));
    let paths: Vec<_> = [
        b"source-\xff".as_slice(),
        b"area-\xff",
        b"old-source-\xff",
        b"old-area-\xff",
    ]
    .into_iter()
    .map(|name| tests::raw_path(temp.path(), name))
    .collect();
    for path in &paths {
        fs::create_dir(path).unwrap();
    }
    let native = plan(&paths[0], &paths[1], false);
    let old = replaced(&paths[2], &paths[3]);
    let id = Uuid::from_bytes([70; 16]);
    let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
    store
        .put_record(
            "recovery-anchor-intent",
            id.as_bytes(),
            &recovery_bytes(1, id, &native, &old),
        )
        .unwrap();
    drop(store);
    let before = tests::preserved_files(&data);
    for owned in &paths {
        let nested = owned.join("scratch");
        fs::create_dir(&nested).unwrap();
        assert!(
            super::super::remote::peer_client_preflight(&keys, &data, &nested, &[], false).is_err()
        );
        assert!(fs::read_dir(&nested).unwrap().next().is_none());
        fs::remove_dir(nested).unwrap();
    }
    // Discovery's starting point `/` does not reserve the whole filesystem.
    super::super::remote::peer_client_preflight(&keys, &data, temp.path(), &[], false).unwrap();
    tests::assert_preserved_files(&data, &before);
    for path in &paths {
        assert!(fs::read_dir(path).unwrap().next().is_none());
    }
}

#[test]
fn malformed_pending_intents_fail_report_and_peer_preflight_without_mutation() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([71; 32]));
    let native = plan(
        &temp.path().join("absent-source"),
        &temp.path().join("absent-area"),
        false,
    );
    let id = Uuid::from_bytes([72; 16]);
    let valid = capture_bytes(1, id, &native);
    let mut noncanonical = vec![0x81, 0];
    noncanonical.extend_from_slice(&valid[1..]);
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut unsupported = valid.clone();
    unsupported[0] = 4;
    let mut old = replaced(
        &temp.path().join("absent-old-source"),
        &temp.path().join("absent-old-area"),
    );
    let mut rows = vec![
        ("capture-intent", id, noncanonical),
        ("capture-intent", id, trailing),
        ("capture-intent", id, unsupported),
        ("capture-intent", Uuid::from_bytes([73; 16]), valid),
    ];
    if let CapturedEntry::FileV2 { path, .. } = &mut old.entries[0] {
        *path = PathBuf::from("../escape");
    }
    rows.push((
        "recovery-anchor-intent",
        id,
        recovery_bytes(1, id, &native, &old),
    ));
    old.entries = replaced(&old.source_root_hint, &old.area.path_hint).entries;
    if let CapturedEntry::FileV2 { data_extents, .. } = &mut old.entries[0] {
        data_extents[0].logical_len = 4;
    }
    rows.push((
        "recovery-anchor-intent",
        id,
        recovery_bytes(2, id, &native, &old),
    ));
    for (kind, key, bytes) in rows {
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        store.put_record(kind, key.as_bytes(), &bytes).unwrap();
        drop(store);
        let before = tests::preserved_files(&data);
        assert!(
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .is_err()
        );
        assert!(
            super::super::remote::peer_client_preflight(&keys, &data, temp.path(), &[], false)
                .is_err()
        );
        tests::assert_preserved_files(&data, &before);
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        store.delete_record(kind, key.as_bytes()).unwrap();
    }
}

#[test]
fn pending_capture_signed_metadata_link_requires_exact_revision_and_guild() {
    let ((keys, revision, _), _, _, _) = crate::legacy_export::tests::fixed_checkpoint_fixture(6);
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("original");
    fs::create_dir(&data).unwrap();
    let native = plan(
        &temp.path().join("absent-source"),
        &temp.path().join("absent-area"),
        false,
    );
    for matches in [false, true] {
        let guild = if matches {
            revision.value.guild_id
        } else {
            [64; 32]
        };
        assert_eq!(guild == revision.value.guild_id, matches);
        let bytes = canonical_bytes(&(
            3_u16,
            guild,
            revision.value.revision_id,
            revision.value.sequence,
            revision.value.parent,
            None::<u64>,
            PathBuf::from("/absent-request"),
            &native,
        ))
        .unwrap();
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        store
            .put_record(
                "user-revision",
                revision.value.revision_id.as_bytes(),
                &canonical_bytes(&revision).unwrap(),
            )
            .unwrap();
        store
            .put_record(
                "capture-intent",
                revision.value.revision_id.as_bytes(),
                &bytes,
            )
            .unwrap();
        drop(store);
        let before = tests::preserved_files(&data);
        let report =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap();
        assert_eq!(report.revisions.len(), 1);
        assert_eq!(
            report.local_state.pending_captures[0].signed_revision_metadata_available,
            matches
        );
        assert!(!report.local_state.pending_captures[0].payloads_verified);
        tests::assert_preserved_files(&data, &before);
    }
}
