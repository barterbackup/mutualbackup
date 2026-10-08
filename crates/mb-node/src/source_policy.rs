//! Admission policy for source backends withdrawn from the product.
//!
//! Inspect existing records read-only before key/schema migration or replay.
//! Even unfinished or malformed guarded journals must remain untouched.

use anyhow::{Result, bail};
use mb_core::{KeyMaterial, decode_canonical};
use mb_store::{ControlStore, SourceBackendBinding, WITHDRAWN_GUARDED_BACKEND};
use std::path::Path;

#[cfg(target_os = "linux")]
use crate::control::GitRepositoryInfo;
use crate::control::ProtectedRoot;

/// Reject withdrawn state before any catalog writer, migration or replay opens.
/// A fresh installation has no catalog to inspect. Linux inspections forbid
/// journal creation and use one preserved read snapshot for all namespaces.
pub(crate) fn require_native_source_state_from_catalog(
    data_dir: &Path,
    keys: &KeyMaterial,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        match std::fs::symlink_metadata(data_dir.join("control.db")) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error.into()),
            Ok(_) => {}
        }
        crate::volume::with_inspected_control_snapshot(data_dir, keys, |control| {
            require_native_source_state(control, keys)
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        if let Some(control) = crate::volume::inspect_control_store(data_dir, keys)? {
            require_native_source_state(&control, keys)?;
        }
        Ok(())
    }
}

pub(crate) fn require_native_source_state(
    control: &ControlStore,
    keys: &KeyMaterial,
) -> Result<()> {
    for prefix in ["guarded-", "link-freeze-"] {
        if control.has_records_with_kind_prefix(prefix)? {
            bail!("{WITHDRAWN_GUARDED_BACKEND}");
        }
    }
    control.for_each_record_value("protected-root", |bytes| {
        let root: ProtectedRoot = decode_canonical(bytes)?;
        if root.format_version == 4 {
            bail!("{WITHDRAWN_GUARDED_BACKEND}");
        }
        Ok(())
    })?;
    control.for_each_record_value("source-backend", |bytes| {
        let binding: SourceBackendBinding = decode_canonical(bytes)?;
        binding.backend.require_supported()?;
        Ok(())
    })?;
    #[cfg(target_os = "linux")]
    control.for_each_record_value("git-repository", |bytes| {
        let repository: GitRepositoryInfo = decode_canonical(bytes)?;
        anyhow::ensure!(
            repository.format_version == 1,
            "unsupported Git registration"
        );
        mb_git::require_native_catalog_state(
            &repository.path,
            repository.repository_id,
            &mb_git::catalog_key(keys, repository.repository_id),
        )
    })?;
    #[cfg(not(target_os = "linux"))]
    let _ = keys;
    crate::snapshot::require_native_capture_state(control)?;
    crate::snapshot::require_native_signed_history(control, keys)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Node;
    use mb_core::{KeyMaterial, Seed, canonical_bytes};
    use std::fs;
    use uuid::Uuid;

    #[cfg(target_os = "linux")]
    fn directory_bytes(
        path: &Path,
    ) -> std::collections::BTreeMap<std::ffi::OsString, (usize, blake3::Hash)> {
        fs::read_dir(path)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                let bytes = fs::read(entry.path()).unwrap();
                (entry.file_name(), (bytes.len(), blake3::hash(&bytes)))
            })
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn control_with_key_format(data: &Path, keys: &KeyMaterial, format: u8) -> ControlStore {
        if format == 0 {
            return ControlStore::open(data.join("control.db"), keys).unwrap();
        }
        let (control, _) = crate::volume::open_control_store(data, keys).unwrap();
        if format == 1 {
            return control;
        }
        // A durable envelope can precede completion of the legacy rekey.
        control.rekey(&keys.database_key(b"control.db")).unwrap();
        ControlStore::open(data.join("control.db"), keys).unwrap()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_admission_does_not_create_a_missing_installation() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("absent/node");
        require_native_source_state_from_catalog(
            &data,
            &KeyMaterial::from_seed(&Seed::from_bytes([90; 32])),
        )
        .unwrap();
        assert_eq!(fs::read_dir(area.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_admission_preserves_closed_and_live_catalogs_across_key_formats() {
        for format in 0..3 {
            for live in [false, true] {
                for withdrawn in [false, true] {
                    let area = tempfile::tempdir().unwrap();
                    let data = area.path();
                    let seed = Seed::from_bytes([90; 32]);
                    let keys = KeyMaterial::from_seed(&seed);
                    drop(Node::lock_data_dir(data).unwrap());
                    let control = control_with_key_format(data, &keys, format);
                    control
                        .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
                        .unwrap();
                    control
                        .put_record(
                            if withdrawn {
                                "guarded-view-mount-v1"
                            } else {
                                "native-test"
                            },
                            b"id",
                            b"preserved",
                        )
                        .unwrap();
                    let control = if live {
                        Some(control)
                    } else {
                        drop(control);
                        None
                    };
                    let before = directory_bytes(data);
                    let result = require_native_source_state_from_catalog(data, &keys);
                    if withdrawn {
                        assert!(result.unwrap_err().to_string().contains("withdrawn"));
                        let error = Node::open(data, seed).err().unwrap();
                        assert!(error.to_string().contains("withdrawn"), "{error:#}");
                    } else {
                        result.unwrap();
                    }
                    let mut after = directory_bytes(data);
                    let mut before = before;
                    assert_eq!(
                        after.keys().collect::<Vec<_>>(),
                        before.keys().collect::<Vec<_>>()
                    );
                    if live {
                        // SQLite may update read marks in the writer's shared
                        // in-process mapping. Database/WAL bytes stay intact.
                        let name = std::ffi::OsStr::new("control.db-shm");
                        assert_eq!(after[name].0, before[name].0);
                        after.remove(name);
                        before.remove(name);
                    }
                    assert_eq!(after, before, "format={format}, live={live}");
                    drop(control);
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_admission_reads_wal_only_commits_before_migration_or_replay() {
        for format in 0..3 {
            for withdrawn in [false, true] {
                let area = tempfile::tempdir().unwrap();
                let source = area.path().join("source");
                let data = area.path().join("node");
                fs::create_dir(&source).unwrap();
                drop(Node::lock_data_dir(&data).unwrap());
                let seed = Seed::from_bytes([90; 32]);
                let keys = KeyMaterial::from_seed(&seed);
                let mut control = control_with_key_format(&source, &keys, format);
                control
                    .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
                    .unwrap();
                let kind = if withdrawn {
                    "guarded-view-mount-v1"
                } else {
                    "native-test"
                };
                control.put_record(kind, b"id", b"only in WAL").unwrap();
                control
                    .begin_operation(&[7; 16], "ensure-filler", &[8; 32], &[9; 32])
                    .unwrap();
                for name in ["control.db", "control.db-wal", "control.key"] {
                    if source.join(name).exists() {
                        fs::copy(source.join(name), data.join(name)).unwrap();
                    }
                }
                drop(control);
                let before = directory_bytes(&data);
                let result = require_native_source_state_from_catalog(&data, &keys);
                if withdrawn {
                    assert!(result.unwrap_err().to_string().contains("withdrawn"));
                } else {
                    result.unwrap();
                }
                assert_eq!(directory_bytes(&data), before);
                let opened = Node::open(&data, seed);
                if withdrawn {
                    assert!(opened.err().unwrap().to_string().contains("withdrawn"));
                    assert_eq!(directory_bytes(&data), before);
                } else {
                    drop(opened.unwrap());
                    crate::volume::with_inspected_control_snapshot(&data, &keys, |reader| {
                        assert_eq!(reader.get_record(kind, b"id")?.unwrap(), b"only in WAL");
                        Ok(())
                    })
                    .unwrap();
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn startup_admission_rejects_incomplete_or_rollback_journals_without_mutation() {
        for suffix in ["-wal", "-shm", "-journal"] {
            let area = tempfile::tempdir().unwrap();
            let data = area.path();
            drop(Node::lock_data_dir(data).unwrap());
            let seed = Seed::from_bytes([90; 32]);
            let keys = KeyMaterial::from_seed(&seed);
            let mut control = control_with_key_format(data, &keys, 0);
            control
                .begin_operation(&[7; 16], "ensure-filler", &[8; 32], &[9; 32])
                .unwrap();
            drop(control);
            fs::write(
                data.join(format!("control.db{suffix}")),
                b"preserved journal",
            )
            .unwrap();
            let before = directory_bytes(data);
            let error = Node::open(data, seed).err().unwrap();
            assert!(
                error.to_string().contains("incomplete or rollback journal"),
                "{error:#}"
            );
            assert_eq!(directory_bytes(data), before);
        }
    }

    #[test]
    fn retained_signed_history_selects_native_or_withdrawn_startup_without_root_records() {
        use ed25519_dalek::SigningKey;
        use mb_core::{
            GuildCheckpoint, Member, QuorumCheckpoint, SectorPurpose, SignedRecord,
            USER_REVISION_DOMAIN, UserRevision, V1_CIPHER_PROFILE, WriterFence, encrypted_sector,
            make_sector_id,
        };

        for private_format in [1_u16, 6, 7] {
            for kind in ["user-revision", "user-revision-head", "guild-checkpoint"] {
                let area = tempfile::tempdir().unwrap();
                let data = area.path();
                let seed = Seed::from_bytes([96; 32]);
                let keys = KeyMaterial::from_seed(&seed);
                drop(Node::open(data, seed.clone()).unwrap());
                let (mut control, _) = crate::volume::open_control_store(data, &keys).unwrap();
                let guild_id = [97; 32];
                let revision_id = Uuid::new_v4();
                let header = canonical_bytes(&private_format).unwrap();
                let (first, _) = encrypted_sector(
                    &keys.guild_data_key(&guild_id),
                    make_sector_id(keys.node_id(), revision_id, SectorPurpose::Metadata, 0),
                    &header,
                )
                .unwrap();
                let (later, _) = encrypted_sector(
                    &keys.guild_data_key(&guild_id),
                    make_sector_id(keys.node_id(), revision_id, SectorPurpose::Metadata, 1),
                    b"not downloaded yet",
                )
                .unwrap();
                crate::snapshot::install_inline_recipe(
                    &mut control,
                    guild_id,
                    first.clone(),
                    header,
                )
                .unwrap();
                let writer = SigningKey::from_bytes(&[98; 32]);
                let mut revision = UserRevision {
                    format_version: 3,
                    guild_id,
                    protected_root_id: Uuid::new_v4(),
                    cipher_profile: V1_CIPHER_PROFILE,
                    revision_id,
                    owner: keys.node_id(),
                    writer_epoch: 1,
                    writer_public_key: writer.verifying_key().to_bytes(),
                    writer_signature: Vec::new(),
                    sequence: 1,
                    parent: None,
                    metadata_sectors: vec![first, later],
                    data_sectors: Vec::new(),
                    sector_commitments: None,
                };
                revision.sign_writer(&writer).unwrap();
                let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, &keys).unwrap();
                let bytes = if kind == "guild-checkpoint" {
                    // The certified history can survive without user-revision
                    // rows. A single-member v4 fixture needs no storage claims.
                    let mut checkpoint = QuorumCheckpoint {
                        checkpoint: GuildCheckpoint {
                            format_version: 4,
                            guild_id,
                            genesis_hash: [99; 32],
                            generation: 1,
                            parent: None,
                            members: vec![Member {
                                node_id: keys.node_id(),
                                recovery_public_key: keys.recovery_public_key(),
                                failure_domain: "fixture".to_owned(),
                            }],
                            writer_fences: vec![WriterFence {
                                owner: keys.node_id(),
                                epoch: 1,
                                public_key: writer.verifying_key().to_bytes(),
                            }],
                            revision_tombstones: Vec::new(),
                            revisions: vec![revision],
                            coding_groups: Vec::new(),
                            authority: None,
                            packing_catalog: None,
                        },
                        signatures: Vec::new(),
                    };
                    checkpoint.add_signature(&keys).unwrap();
                    checkpoint.verify().unwrap();
                    canonical_bytes(&checkpoint).unwrap()
                } else {
                    canonical_bytes(&revision).unwrap()
                };
                control
                    .put_record(kind, revision_id.as_bytes(), &bytes)
                    .unwrap();
                control
                    .begin_operation(&[7; 16], "ensure-filler", &[8; 32], &[9; 32])
                    .unwrap();
                drop(control);
                let paths = [
                    data.join("control.db"),
                    data.join("control.key"),
                    data.join("parity.db"),
                ];
                let original: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
                if private_format == 1 {
                    require_native_source_state_from_catalog(data, &keys).unwrap();
                    for (path, original) in paths.iter().zip(&original) {
                        assert_eq!(&fs::read(path).unwrap(), original);
                    }
                    drop(Node::open(data, seed).unwrap());
                    continue;
                }
                let error = match Node::open(data, seed) {
                    Err(error) => error,
                    Ok(_) => {
                        panic!("signed guarded format {private_format} in {kind} was reopened")
                    }
                };
                assert!(error.to_string().contains("withdrawn"), "{kind}: {error:#}");
                for (path, original) in paths.iter().zip(original) {
                    assert_eq!(
                        fs::read(path).unwrap(),
                        original,
                        "{} changed",
                        path.display()
                    );
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn history_only_git_catalog_stops_startup_before_node_cleanup() {
        for kind in [
            "git-source-backend-v1",
            "git-guarded-recovery-rebind-v1/legacy",
        ] {
            let area = tempfile::tempdir().unwrap();
            let data = area.path().join("node");
            let source = area.path().join("source");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("file"), b"working\r\n\0bytes").unwrap();
            let seed = Seed::from_bytes([95; 32]);
            let keys = KeyMaterial::from_seed(&seed);
            drop(Node::open(&data, seed.clone()).unwrap());
            let repository_id = Uuid::new_v4();
            let directory = source.join(mb_store::GIT_CATALOG_DIRECTORY);
            fs::create_dir(&directory).unwrap();
            let database = directory.join("catalog.db");
            let catalog =
                ControlStore::open_with_key(&database, &mb_git::catalog_key(&keys, repository_id))
                    .unwrap();
            let record = if kind == "git-source-backend-v1" {
                canonical_bytes(&(
                    1_u16,
                    repository_id,
                    mb_store::SourceBackendKind::GuardedLinkFreezeV1,
                ))
                .unwrap()
            } else {
                b"unfinished recovered history pin".to_vec()
            };
            catalog
                .put_record(kind, repository_id.as_bytes(), &record)
                .unwrap();
            drop(catalog);
            let (mut control, _) = crate::volume::open_control_store(&data, &keys).unwrap();
            // No protected root, mount claim, or node-side guarded prefix.
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: source.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            control
                .begin_operation(&[7; 16], "ensure-filler", &[8; 32], &[9; 32])
                .unwrap();
            drop(control);
            let paths = [
                data.join("control.db"),
                data.join("control.key"),
                data.join("parity.db"),
                database,
                source.join("file"),
            ];
            let original: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
            let error = match Node::open(&data, seed) {
                Err(error) => error,
                Ok(_) => panic!("history-only guarded catalog was reopened"),
            };
            assert!(error.to_string().contains("withdrawn"), "{error:#}");
            for (path, original) in paths.iter().zip(original) {
                assert_eq!(
                    fs::read(path).unwrap(),
                    original,
                    "{} changed",
                    path.display()
                );
            }
        }
    }

    #[test]
    fn guarded_journals_are_rejected_before_replay_or_catalog_mutation() {
        for kind in [
            "guarded-view-mount-v1",
            "guarded-root-enrollment-v1",
            "guarded-git-anchor-pin-v1",
            "link-freeze-capture-v1",
        ] {
            let area = tempfile::tempdir().unwrap();
            let data = area.path().join("node");
            let source = area.path().join("source");
            fs::create_dir(&source).unwrap();
            fs::write(source.join("file"), b"working\r\n\0bytes").unwrap();
            let seed = Seed::from_bytes([91; 32]);
            let node = Node::open(&data, seed.clone()).unwrap();
            drop(node);
            let keys = KeyMaterial::from_seed(&seed);
            let (mut control, _) = crate::volume::open_control_store(&data, &keys).unwrap();
            control
                .put_record(kind, b"id", b"unfinished legacy state")
                .unwrap();
            // Normal startup would clear this before replay. Rejection must
            // happen before even that recomputable operation is discarded.
            control
                .begin_operation(&[7; 16], "ensure-filler", &[8; 32], &[9; 32])
                .unwrap();
            drop(control);
            let database = fs::read(data.join("control.db")).unwrap();
            let envelope = fs::read(data.join("control.key")).unwrap();
            let parity = fs::read(data.join("parity.db")).unwrap();
            let error = match Node::open(&data, seed) {
                Err(error) => error,
                Ok(_) => panic!("withdrawn state was reopened: {kind}"),
            };
            assert!(error.to_string().contains("withdrawn"), "{error:#}");
            assert_eq!(fs::read(data.join("control.db")).unwrap(), database);
            assert_eq!(fs::read(data.join("control.key")).unwrap(), envelope);
            assert_eq!(fs::read(data.join("parity.db")).unwrap(), parity);
            assert_eq!(
                fs::read(source.join("file")).unwrap(),
                b"working\r\n\0bytes"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn guarded_enrollment_rejects_before_creating_or_moving_paths() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("node");
        let source = area.path().join("source");
        let view = area.path().join("view");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"working bytes").unwrap();
        let mut node = Node::open(&data, Seed::from_bytes([90; 32])).unwrap();
        for error in [
            node.add_guarded_protected_root(&source, &view, 1000, 1000)
                .unwrap_err(),
            node.add_guarded_protected_root_in_place(&source)
                .unwrap_err(),
            node.remove_guarded_protected_root(Uuid::new_v4())
                .unwrap_err(),
            node.git_retire_empty_guarded_repository(Uuid::new_v4())
                .unwrap_err(),
        ] {
            assert!(error.to_string().contains("withdrawn"), "{error:#}");
        }
        assert_eq!(fs::read(source.join("file")).unwrap(), b"working bytes");
        assert!(!view.exists());
        assert_eq!(fs::read_dir(source).unwrap().count(), 1);
    }

    #[test]
    fn legacy_unwrapped_keys_are_not_rekeyed_on_withdrawal() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path();
        let seed = Seed::from_bytes([92; 32]);
        let keys = KeyMaterial::from_seed(&seed);
        let database = data.join("control.db");
        {
            let control = ControlStore::open(&database, &keys).unwrap();
            control
                .put_record("guarded-file-plan-v1", b"id", b"legacy")
                .unwrap();
        }
        let original = fs::read(&database).unwrap();
        assert!(Node::open(data, seed).is_err());
        assert_eq!(fs::read(database).unwrap(), original);
        assert!(!data.join("control.key").exists());
        assert!(!data.join("parity.db").exists());
    }

    #[test]
    fn root_records_alone_cannot_reenable_guarded_mounts() {
        let area = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[93; 32]).unwrap();
        let root = ProtectedRoot {
            format_version: 4,
            root_id: Uuid::new_v4(),
            path: area.path().join("old-view"),
            filesystem_id: 11,
            root_inode: 12,
        };
        control
            .put_record(
                "protected-root",
                root.root_id.as_bytes(),
                &canonical_bytes(&root).unwrap(),
            )
            .unwrap();
        control.make_query_only().unwrap();
        assert!(
            require_native_source_state(
                &control,
                &KeyMaterial::from_seed(&Seed::from_bytes([93; 32]))
            )
            .unwrap_err()
            .to_string()
            .contains("withdrawn")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn backend_bindings_alone_cannot_reenable_guarded_capture() {
        let area = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[94; 32]).unwrap();
        let binding = SourceBackendBinding::guarded_link_freeze_v1(Uuid::new_v4(), 11, 12, 13);
        control
            .put_record(
                "source-backend",
                binding.root_id.as_bytes(),
                &canonical_bytes(&binding).unwrap(),
            )
            .unwrap();
        control.make_query_only().unwrap();
        assert!(
            require_native_source_state(
                &control,
                &KeyMaterial::from_seed(&Seed::from_bytes([94; 32]))
            )
            .unwrap_err()
            .to_string()
            .contains("withdrawn")
        );
    }
}
