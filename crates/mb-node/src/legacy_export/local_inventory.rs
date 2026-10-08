//! Preserved local registrations and historical anchor ownership, without
//! opening a source path, Git runtime, anchor payload or withdrawn mount.

use std::{collections::BTreeMap, os::unix::ffi::OsStrExt};

use anyhow::{Context, Result, ensure};
use mb_core::{
    V1_MAX_CATALOG_BYTES, canonical_bytes_bounded, canonical_size_bounded, decode_canonical,
};
use mb_store::{
    ControlStore, GuardedRevisionCaptureV1, GuardedStoppedCaptureV1, NativeFileId,
    SourceBackendBinding,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::inventory::LegacyRevisionInventoryEntry;
use crate::control::{GitRepositoryInfo, ProtectedRoot};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyLocalStateInventory {
    pub protected_roots: Vec<LegacyRootRegistration>,
    pub source_backends: Vec<LegacySourceBinding>,
    pub git_repositories: Vec<LegacyGitRegistration>,
    pub guarded_captures: Vec<LegacyGuardedCapture>,
    /// These rows are preserved and identified, not decoded or certified as
    /// complete ownership. Their presence remains a retained-history gap.
    pub unclassified_guarded_records: Vec<LegacyPreservedRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyRootRegistration {
    pub root_id: Uuid,
    pub record_format: u16,
    pub path_hex: String,
    pub filesystem_id: u64,
    pub root_inode: u64,
    pub signed_revision_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacySourceBinding {
    pub binding: SourceBackendBinding,
    pub registered_root: bool,
    /// Unknown for absent roots and historical registrations whose identity
    /// layout predates stable filesystem/inode identity (formats 1 and 2).
    pub registration_identity_matches: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitRegistration {
    pub repository_id: Uuid,
    pub path_hex: String,
    pub registered_root: bool,
    /// The registration does not establish that an external catalog is present
    /// or that its refs, pins, linked worktrees and pending intents are inventoried.
    pub catalog_inventoried: bool,
    pub signed_revision_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGuardedCapture {
    pub record_kind: String,
    pub revision_id: Uuid,
    pub protected_root_id: Option<Uuid>,
    pub signed_revision_metadata_available: bool,
    pub namespace_anchor_id: Uuid,
    pub anchors: Vec<LegacyGuardedAnchorPin>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGuardedAnchorPin {
    pub namespace_path_hex: String,
    pub area_id: Uuid,
    pub filesystem_id: u64,
    pub area_path_hint_hex: String,
    pub volume_root_hint_hex: String,
    pub anchor_id: Uuid,
    pub relative_path_hex: String,
    pub logical_len: u64,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPreservedRecord {
    pub kind: String,
    pub record_id_hex: String,
    pub payload_bytes: u64,
    pub payload_hash: String,
}

/// A validated local record. The scanner retains at most one decoded row;
/// consumers choose whether to build a bounded report or check locations.
pub(super) enum PreservedLocalRecord<'a> {
    Root(ProtectedRoot),
    Binding(SourceBackendBinding),
    Git(GitRepositoryInfo),
    Capture {
        kind: &'a str,
        revision_id: Uuid,
        capture: GuardedStoppedCaptureV1,
    },
    Unclassified {
        kind: &'a str,
        key: &'a [u8],
        bytes: &'a [u8],
    },
}

pub(super) enum PreservedInput<'a> {
    PathHint(&'a std::path::Path),
    NativeRoot(NativeFileId),
}

impl PreservedLocalRecord<'_> {
    /// Known exclusions only. A path hint is not ownership authority, and
    /// opaque records do not establish a complete retained ownership graph.
    pub(super) fn for_each_input(
        &self,
        mut visit: impl FnMut(PreservedInput<'_>) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Root(root) => {
                visit(PreservedInput::PathHint(&root.path))?;
                if matches!(root.format_version, 3 | 4) {
                    visit(PreservedInput::NativeRoot(NativeFileId {
                        filesystem_id: root.filesystem_id,
                        inode: root.root_inode,
                    }))?;
                }
            }
            Self::Binding(binding) => visit(PreservedInput::NativeRoot(NativeFileId {
                filesystem_id: binding.filesystem_id,
                inode: binding.root_inode,
            }))?,
            Self::Git(registration) => visit(PreservedInput::PathHint(&registration.path))?,
            Self::Capture { capture, .. } => {
                visit(PreservedInput::NativeRoot(capture.metadata.lower_root_id))?;
                for file in &capture.files {
                    // A volume root is a discovery starting point, often `/`,
                    // not ownership of the whole filesystem.
                    visit(PreservedInput::PathHint(&file.locator.area.path_hint))?;
                }
            }
            Self::Unclassified { .. } => {}
        }
        Ok(())
    }
}

fn account<T: Serialize>(item: &T, used: &mut usize, limit: usize) -> Result<()> {
    *used = used
        .checked_add(canonical_size_bounded(item, limit)?)
        .context("local inventory size overflow")?;
    ensure!(
        *used <= limit,
        "local inventory exceeds its bounded metadata budget"
    );
    Ok(())
}

fn canonical_record<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8]) -> Result<T> {
    let record = decode_canonical(bytes)?;
    ensure!(
        canonical_bytes_bounded(&record, V1_MAX_CATALOG_BYTES)? == bytes,
        "local inventory record is not canonical"
    );
    Ok(record)
}

fn validate_capture(capture: &GuardedStoppedCaptureV1) -> Result<()> {
    capture.validate_shape()?;
    for file in &capture.files {
        let locator = &file.locator;
        ensure!(
            !locator.anchor_id.is_nil() && !locator.area.area_id.is_nil(),
            "invalid preserved anchor ownership ID"
        );
        let relative = locator.relative_path.as_os_str().as_bytes();
        let mut normalized = std::path::PathBuf::new();
        for component in locator.relative_path.components() {
            let std::path::Component::Normal(name) = component else {
                anyhow::bail!("unsafe preserved anchor relative path")
            };
            normalized.push(name);
        }
        ensure!(
            !relative.is_empty()
                && !relative.contains(&0)
                && normalized.as_os_str().as_bytes() == relative,
            "unsafe preserved anchor relative path"
        );
        let mut end = 0;
        for extent in &file.data_extents {
            ensure!(
                extent.logical_len != 0 && extent.offset >= end,
                "invalid preserved anchor extent order"
            );
            end = extent
                .offset
                .checked_add(extent.logical_len)
                .context("preserved anchor extent overflow")?;
            ensure!(
                end <= file.logical_len,
                "preserved anchor extent exceeds file"
            );
        }
        ensure!(
            locator.area.path_hint.is_absolute()
                && !locator.area.path_hint.as_os_str().as_bytes().contains(&0),
            "unsafe preserved anchor area path hint"
        );
    }
    Ok(())
}

/// Stream every relevant row with SQL byte limits before materialization.
/// Validation is shared by report and placement consumers; neither may skip
/// canonical/shape checks merely because it does not need a field for output.
pub(super) fn for_each_record(
    control: &ControlStore,
    mut visit: impl FnMut(PreservedLocalRecord<'_>) -> Result<()>,
) -> Result<()> {
    control.for_each_record_bounded("protected-root", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let root: ProtectedRoot = canonical_record(bytes)?;
        ensure!(
            matches!(root.format_version, 1..=4)
                && !root.root_id.is_nil()
                && key == root.root_id.as_bytes()
                && root.filesystem_id != 0
                && root.root_inode != 0
                && root.path.is_absolute()
                && !root.path.as_os_str().as_bytes().contains(&0),
            "invalid preserved protected-root registration"
        );
        visit(PreservedLocalRecord::Root(root))?;
        Ok(true)
    })?;
    control.for_each_record_bounded("source-backend", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let binding: SourceBackendBinding = canonical_record(bytes)?;
        ensure!(
            binding.format_version == 1
                && binding.contract_version == 1
                && !binding.root_id.is_nil()
                && key == binding.root_id.as_bytes()
                && binding.filesystem_id != 0
                && binding.root_inode != 0
                && binding.mount_id != 0,
            "invalid preserved source-backend binding"
        );
        visit(PreservedLocalRecord::Binding(binding))?;
        Ok(true)
    })?;
    control.for_each_record_bounded("git-repository", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let registration: GitRepositoryInfo = canonical_record(bytes)?;
        ensure!(
            registration.format_version == 1
                && !registration.repository_id.is_nil()
                && key == registration.repository_id.as_bytes()
                && registration.path.is_absolute()
                && !registration.path.as_os_str().as_bytes().contains(&0),
            "invalid preserved Git registration"
        );
        visit(PreservedLocalRecord::Git(registration))?;
        Ok(true)
    })?;
    for prefix in ["guarded-", "link-freeze-"] {
        control.for_each_record_with_kind_prefix_bounded(
            prefix,
            512,
            64 * 1024,
            V1_MAX_CATALOG_BYTES,
            |kind, key, bytes| {
                let capture = match kind {
                    mb_store::GUARDED_REVISION_CAPTURE_KIND => {
                        let record: GuardedRevisionCaptureV1 = canonical_record(bytes)?;
                        ensure!(
                            record.format_version == 1
                                && key == record.revision_id.as_bytes()
                                && !record.revision_id.is_nil(),
                            "invalid preserved revision capture"
                        );
                        Some((record.revision_id, record.capture))
                    }
                    "guarded-view-stopped-capture-v1" => {
                        let revision_id = Uuid::from_slice(key)?;
                        ensure!(!revision_id.is_nil(), "invalid stopped capture revision ID");
                        Some((
                            revision_id,
                            canonical_record::<GuardedStoppedCaptureV1>(bytes)?,
                        ))
                    }
                    _ => None,
                };
                if let Some((revision_id, capture)) = capture {
                    validate_capture(&capture)?;
                    visit(PreservedLocalRecord::Capture {
                        kind,
                        revision_id,
                        capture,
                    })?;
                } else {
                    visit(PreservedLocalRecord::Unclassified { kind, key, bytes })?;
                }
                Ok(true)
            },
        )?;
    }
    Ok(())
}

pub(super) fn collect(
    control: &ControlStore,
    used: &mut usize,
    limit: usize,
) -> Result<LegacyLocalStateInventory> {
    let mut report = LegacyLocalStateInventory {
        protected_roots: Vec::new(),
        source_backends: Vec::new(),
        git_repositories: Vec::new(),
        guarded_captures: Vec::new(),
        unclassified_guarded_records: Vec::new(),
    };
    for_each_record(control, |record| {
        match record {
            PreservedLocalRecord::Root(root) => {
                let entry = LegacyRootRegistration {
                    root_id: root.root_id,
                    record_format: root.format_version,
                    path_hex: hex::encode(root.path.as_os_str().as_bytes()),
                    filesystem_id: root.filesystem_id,
                    root_inode: root.root_inode,
                    signed_revision_ids: Vec::new(),
                };
                account(&entry, used, limit)?;
                report.protected_roots.push(entry);
            }
            PreservedLocalRecord::Binding(binding) => {
                let root = report
                    .protected_roots
                    .binary_search_by_key(&binding.root_id, |root| root.root_id)
                    .ok()
                    .map(|index| &report.protected_roots[index]);
                let entry = LegacySourceBinding {
                    registered_root: root.is_some(),
                    registration_identity_matches: root
                        .filter(|root| matches!(root.record_format, 3 | 4))
                        .map(|root| {
                            root.filesystem_id == binding.filesystem_id
                                && root.root_inode == binding.root_inode
                        }),
                    binding,
                };
                account(&entry, used, limit)?;
                report.source_backends.push(entry);
            }
            PreservedLocalRecord::Git(registration) => {
                let entry = LegacyGitRegistration {
                    repository_id: registration.repository_id,
                    path_hex: hex::encode(registration.path.as_os_str().as_bytes()),
                    registered_root: report
                        .protected_roots
                        .binary_search_by_key(&registration.repository_id, |root| root.root_id)
                        .is_ok(),
                    catalog_inventoried: false,
                    signed_revision_ids: Vec::new(),
                };
                account(&entry, used, limit)?;
                report.git_repositories.push(entry);
            }
            PreservedLocalRecord::Capture {
                kind,
                revision_id,
                capture,
            } => {
                let mut entry = LegacyGuardedCapture {
                    record_kind: kind.to_owned(),
                    revision_id,
                    protected_root_id: None,
                    signed_revision_metadata_available: false,
                    namespace_anchor_id: capture.metadata.anchor_id,
                    anchors: Vec::new(),
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                for file in capture.files {
                    let locator = file.locator;
                    let pin = LegacyGuardedAnchorPin {
                        namespace_path_hex: hex::encode(file.path),
                        area_id: locator.area.area_id,
                        filesystem_id: locator.area.filesystem_id,
                        area_path_hint_hex: hex::encode(
                            locator.area.path_hint.as_os_str().as_bytes(),
                        ),
                        volume_root_hint_hex: hex::encode(
                            locator.area.volume_root_hint.as_os_str().as_bytes(),
                        ),
                        anchor_id: locator.anchor_id,
                        relative_path_hex: hex::encode(
                            locator.relative_path.as_os_str().as_bytes(),
                        ),
                        logical_len: file.logical_len,
                        content_hash: hex::encode(file.content_hash),
                    };
                    account(&pin, used, limit)?;
                    entry.anchors.push(pin);
                }
                report.guarded_captures.push(entry);
            }
            PreservedLocalRecord::Unclassified { kind, key, bytes } => {
                let entry = LegacyPreservedRecord {
                    kind: kind.to_owned(),
                    record_id_hex: hex::encode(key),
                    payload_bytes: bytes.len() as u64,
                    payload_hash: hex::encode(blake3::hash(bytes).as_bytes()),
                };
                account(&entry, used, limit)?;
                report.unclassified_guarded_records.push(entry);
            }
        }
        Ok(())
    })?;
    Ok(report)
}

impl LegacyLocalStateInventory {
    pub(super) fn reconcile(
        &mut self,
        revisions: &BTreeMap<Uuid, LegacyRevisionInventoryEntry>,
        used: &mut usize,
        limit: usize,
    ) -> Result<()> {
        for revision in revisions.values() {
            if let Ok(index) = self
                .protected_roots
                .binary_search_by_key(&revision.protected_root_id, |root| root.root_id)
            {
                account(&revision.revision_id, used, limit)?;
                self.protected_roots[index]
                    .signed_revision_ids
                    .push(revision.revision_id);
            }
            if let Ok(index) = self
                .git_repositories
                .binary_search_by_key(&revision.protected_root_id, |git| git.repository_id)
            {
                account(&revision.revision_id, used, limit)?;
                self.git_repositories[index]
                    .signed_revision_ids
                    .push(revision.revision_id);
            }
        }
        for capture in &mut self.guarded_captures {
            if let Some(revision) = revisions.get(&capture.revision_id) {
                capture.signed_revision_metadata_available = true;
                capture.protected_root_id = Some(revision.protected_root_id);
                account(&revision.protected_root_id, used, limit)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{KeyMaterial, SignedRecord, UserRevision, canonical_bytes};
    use mb_store::{
        FileExtent, GuardedStoppedFileV1, GuardedViewEntryKind, GuardedViewMetadataEntry,
        GuardedViewMetadataV1, NativeFileId, StableAnchorAreaLocator, StableAnchorFileLocator,
    };
    use std::{
        collections::BTreeSet,
        ffi::OsString,
        fs,
        os::unix::ffi::OsStringExt,
        path::{Path, PathBuf},
    };

    fn raw_path(parent: &Path, name: &[u8]) -> PathBuf {
        parent.join(OsString::from_vec(name.to_vec()))
    }

    fn stopped_capture(parent: &Path) -> GuardedStoppedCaptureV1 {
        let native_id = NativeFileId {
            filesystem_id: 7,
            inode: 11,
        };
        let path = b"name-\xff".to_vec();
        GuardedStoppedCaptureV1 {
            format_version: 1,
            metadata: GuardedViewMetadataV1 {
                format_version: 1,
                anchor_id: Uuid::from_bytes([40; 16]),
                lower_root_id: NativeFileId {
                    filesystem_id: 7,
                    inode: 10,
                },
                root_mode: 0o700,
                root_uid: 123,
                root_gid: 456,
                root_atime_secs: -1,
                root_atime_nanos: 2,
                root_modified_secs: 3,
                root_modified_nanos: 4,
                entries: vec![GuardedViewMetadataEntry {
                    path: path.clone(),
                    kind: GuardedViewEntryKind::File,
                    native_id,
                    mode: 0o640,
                    uid: 123,
                    gid: 456,
                    logical_len: 3,
                    atime_secs: -1,
                    atime_nanos: 2,
                    modified_secs: 3,
                    modified_nanos: 4,
                }],
            },
            files: vec![GuardedStoppedFileV1 {
                path,
                native_id,
                locator: StableAnchorFileLocator {
                    area: StableAnchorAreaLocator {
                        area_id: Uuid::from_bytes([41; 16]),
                        path_hint: raw_path(parent, b"missing-area-\xfe"),
                        filesystem_id: 7,
                        volume_root_hint: parent.join("missing-volume"),
                    },
                    anchor_id: Uuid::from_bytes([42; 16]),
                    relative_path: raw_path(Path::new("capture"), b"name-\xff"),
                },
                logical_len: 3,
                content_hash: *blake3::hash(b"old").as_bytes(),
                data_extents: vec![FileExtent {
                    offset: 0,
                    logical_len: 3,
                }],
            }],
        }
    }

    fn save<T: Serialize>(store: &ControlStore, kind: &str, id: Uuid, record: &T) {
        store
            .put_record(kind, id.as_bytes(), &canonical_bytes(record).unwrap())
            .unwrap();
    }

    fn save_revision(store: &ControlStore, revision: &SignedRecord<UserRevision>) {
        save(store, "user-revision", revision.value.revision_id, revision);
    }

    fn preserved_files(data: &Path) -> BTreeMap<OsString, Vec<u8>> {
        fs::read_dir(data)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect()
    }

    fn assert_preserved_files(data: &Path, before: &BTreeMap<OsString, Vec<u8>>) {
        let after = preserved_files(data);
        assert_eq!(
            after.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>()
        );
        for (name, bytes) in before {
            assert!(after[name] == *bytes, "preserved file changed: {name:?}");
        }
    }

    #[test]
    fn legacy_peer_preflight_streams_retained_captures_beyond_report_budget() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([50; 32]));
        let mut capture = stopped_capture(temp.path());
        let template_entry = capture.metadata.entries[0].clone();
        let template_file = capture.files[0].clone();
        capture.metadata.entries.clear();
        capture.files.clear();
        for index in 0..128 {
            let mut name = format!("file-{index:04}-").into_bytes();
            name.resize(239, b'x');
            name.push(0xff);
            let native_id = NativeFileId {
                filesystem_id: 7,
                inode: 1000 + index,
            };
            let mut entry = template_entry.clone();
            entry.path = name.clone();
            entry.native_id = native_id;
            let mut file = template_file.clone();
            file.path = name.clone();
            file.native_id = native_id;
            file.locator.relative_path = raw_path(Path::new("capture"), &name);
            capture.metadata.entries.push(entry);
            capture.files.push(file);
        }
        validate_capture(&capture).unwrap();
        let kind = "guarded-view-stopped-capture-v1";
        let payload = canonical_bytes(&capture).unwrap();
        let mut store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        save(&store, kind, Uuid::from_u128(1), &capture);
        let report = collect(&store, &mut 0, V1_MAX_CATALOG_BYTES).unwrap();
        let row_cost =
            canonical_size_bounded(&report.guarded_captures[0], V1_MAX_CATALOG_BYTES).unwrap();
        let count = V1_MAX_CATALOG_BYTES / row_cost + 2;
        assert!(count < 1000);
        store
            .put_records_iter((2..=count).map(|index| {
                Ok::<_, anyhow::Error>((
                    kind,
                    *Uuid::from_u128(index as u128).as_bytes(),
                    payload.as_slice(),
                ))
            }))
            .unwrap();
        drop(store);
        assert!(count * row_cost > V1_MAX_CATALOG_BYTES);
        eprintln!(
            "retained captures={count} pins={} encoded_record_bytes={} report_body_bytes={} catalog_bytes={}",
            count * 128,
            payload.len(),
            count * row_cost,
            data.join("control.db").metadata().unwrap().len(),
        );
        let hashes = || -> BTreeMap<_, _> {
            fs::read_dir(&data)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let file = fs::File::open(entry.path()).unwrap();
                    let len = file.metadata().unwrap().len();
                    let mut hash = blake3::Hasher::new();
                    hash.update_reader(file).unwrap();
                    (entry.file_name(), (len, *hash.finalize().as_bytes()))
                })
                .collect()
        };
        let before = hashes();
        let preflight =
            || super::super::remote::peer_client_preflight(&keys, &data, temp.path(), &[], false);
        assert_eq!(preflight().unwrap().0, temp.path().canonicalize().unwrap());
        let error =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap_err();
        assert!(
            error.to_string().contains("bounded metadata budget"),
            "{error:#}"
        );
        assert_eq!(hashes(), before);

        // A late owner still excludes the candidate after a graph larger than
        // the entire report budget; there is no successful truncated scan.
        capture.files[0].locator.area.path_hint = temp.path().to_path_buf();
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        save(&store, kind, Uuid::from_u128(u128::MAX), &capture);
        drop(store);
        let before = hashes();
        let error = preflight().unwrap_err();
        assert!(
            error.to_string().contains("outside preserved inputs"),
            "{error:#}"
        );
        assert_eq!(hashes(), before);

        // Placement consumes the shared validation, even for a late field
        // which does not itself contain a directory exclusion.
        capture.files[0].locator.area.path_hint = temp.path().join("missing-area");
        capture.files[0].locator.relative_path = "../escape".into();
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        save(&store, kind, Uuid::from_u128(u128::MAX), &capture);
        drop(store);
        let before = hashes();
        let error = preflight().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsafe preserved anchor relative path"),
            "{error:#}"
        );
        assert_eq!(hashes(), before);
    }

    #[test]
    fn offline_inventory_reconciles_registrations_and_anchor_owners_without_payload_reads() {
        for (format, wrapped) in [(6, false), (7, true)] {
            let ((keys, revision, _), _, _, _) =
                super::super::tests::fixed_checkpoint_fixture(format);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = if wrapped {
                crate::volume::open_control_store(&data, &keys).unwrap().0
            } else {
                ControlStore::open(data.join("control.db"), &keys).unwrap()
            };
            save_revision(&store, &revision);
            let root_id = revision.value.protected_root_id;
            let root_path = raw_path(temp.path(), b"offline-view-\xff");
            let root = ProtectedRoot {
                format_version: 4,
                root_id,
                path: root_path.clone(),
                filesystem_id: 7,
                root_inode: 10,
            };
            save(&store, "protected-root", root_id, &root);
            save(
                &store,
                "source-backend",
                root_id,
                &SourceBackendBinding::guarded_link_freeze_v1(root_id, 7, 10, 11),
            );
            let orphan_id = Uuid::from_bytes([66; 16]);
            save(
                &store,
                "source-backend",
                orphan_id,
                &SourceBackendBinding::guarded_link_freeze_v1(orphan_id, 7, 10, 11),
            );
            let mismatch_id = Uuid::from_bytes([67; 16]);
            save(
                &store,
                "protected-root",
                mismatch_id,
                &ProtectedRoot {
                    format_version: 3,
                    root_id: mismatch_id,
                    path: temp.path().join("missing-native"),
                    filesystem_id: 8,
                    root_inode: 12,
                },
            );
            save(
                &store,
                "source-backend",
                mismatch_id,
                &SourceBackendBinding::reflink_v1(mismatch_id, 8, 13, 14),
            );
            let old_id = Uuid::from_bytes([68; 16]);
            save(
                &store,
                "protected-root",
                old_id,
                &ProtectedRoot {
                    format_version: 2,
                    root_id: old_id,
                    path: temp.path().join("missing-older"),
                    filesystem_id: 7,
                    root_inode: 10,
                },
            );
            save(
                &store,
                "source-backend",
                old_id,
                &SourceBackendBinding::guarded_link_freeze_v1(old_id, 7, 10, 11),
            );
            save(
                &store,
                "git-repository",
                root_id,
                &GitRepositoryInfo {
                    format_version: 1,
                    repository_id: root_id,
                    path: root_path.clone(),
                },
            );
            let history_id = Uuid::from_bytes([99; 16]);
            let history_path = raw_path(temp.path(), b"history-only-\xfd");
            save(
                &store,
                "git-repository",
                history_id,
                &GitRepositoryInfo {
                    format_version: 1,
                    repository_id: history_id,
                    path: history_path.clone(),
                },
            );
            let capture = stopped_capture(temp.path());
            save(
                &store,
                mb_store::GUARDED_REVISION_CAPTURE_KIND,
                revision.value.revision_id,
                &GuardedRevisionCaptureV1 {
                    format_version: 1,
                    revision_id: revision.value.revision_id,
                    capture: capture.clone(),
                },
            );
            save(
                &store,
                "guarded-view-stopped-capture-v1",
                Uuid::from_bytes([43; 16]),
                &capture,
            );
            store
                .put_record("guarded-view-mount-v1", b"mount", b"not decoded")
                .unwrap();
            store
                .put_record("link-freeze-pending", b"intent", b"preserved intent")
                .unwrap();
            drop(store);
            let before = preserved_files(&data);
            crate::volume::with_inspected_control_snapshot(&data, &keys, |store| {
                let mut paths = BTreeSet::new();
                let mut roots = BTreeSet::new();
                for_each_record(store, |record| {
                    record.for_each_input(|input| {
                        match input {
                            PreservedInput::PathHint(path) => {
                                paths.insert(path.to_path_buf());
                            }
                            PreservedInput::NativeRoot(root) => {
                                roots.insert(root);
                            }
                        }
                        Ok(())
                    })
                })?;
                ensure!(paths.contains(&root_path) && paths.contains(&history_path));
                ensure!(roots.contains(&capture.metadata.lower_root_id));
                ensure!(paths.contains(&capture.files[0].locator.area.path_hint));
                ensure!(!paths.contains(&capture.files[0].locator.area.volume_root_hint));
                Ok(())
            })
            .unwrap();
            let report =
                super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                    .unwrap();
            assert_eq!(report.format_version, 2);
            assert!(!report.retained_history_complete);
            let local = &report.local_state;
            assert_eq!(local.protected_roots.len(), 3);
            let saved_root = local
                .protected_roots
                .iter()
                .find(|root| root.root_id == root_id)
                .unwrap();
            assert_eq!(
                saved_root.path_hex,
                hex::encode(root_path.as_os_str().as_bytes())
            );
            assert_eq!(saved_root.signed_revision_ids, [revision.value.revision_id]);
            let binding = |id| {
                local
                    .source_backends
                    .iter()
                    .find(|entry| entry.binding.root_id == id)
                    .unwrap()
            };
            assert_eq!(binding(root_id).registration_identity_matches, Some(true));
            assert!(binding(root_id).registered_root);
            assert_eq!(
                binding(mismatch_id).registration_identity_matches,
                Some(false)
            );
            assert!(binding(mismatch_id).registered_root);
            assert_eq!(binding(old_id).registration_identity_matches, None);
            assert!(binding(old_id).registered_root);
            assert_eq!(binding(orphan_id).registration_identity_matches, None);
            assert!(!binding(orphan_id).registered_root);
            assert_eq!(local.git_repositories.len(), 2);
            let git = local
                .git_repositories
                .iter()
                .find(|git| git.repository_id == root_id)
                .unwrap();
            assert!(git.registered_root);
            assert_eq!(git.signed_revision_ids, [revision.value.revision_id]);
            assert!(!git.catalog_inventoried);
            let history = local
                .git_repositories
                .iter()
                .find(|git| git.repository_id == history_id)
                .unwrap();
            assert!(!history.registered_root && !history.catalog_inventoried);
            assert_eq!(
                history.path_hex,
                hex::encode(history_path.as_os_str().as_bytes())
            );
            assert!(history.signed_revision_ids.is_empty());
            assert_eq!(local.guarded_captures.len(), 2);
            for owner in &local.guarded_captures {
                assert_eq!(owner.namespace_anchor_id, capture.metadata.anchor_id);
                assert!(!owner.payloads_verified);
                assert_eq!(owner.anchors.len(), 1);
                let pin = &owner.anchors[0];
                assert_eq!(pin.namespace_path_hex, hex::encode(b"name-\xff"));
                assert_eq!(pin.area_id, capture.files[0].locator.area.area_id);
                assert_eq!(pin.anchor_id, capture.files[0].locator.anchor_id);
                assert_eq!(pin.relative_path_hex, hex::encode(b"capture/name-\xff"));
                assert_eq!(
                    pin.area_path_hint_hex,
                    hex::encode(
                        capture.files[0]
                            .locator
                            .area
                            .path_hint
                            .as_os_str()
                            .as_bytes()
                    )
                );
                assert_eq!(pin.logical_len, 3);
                assert_eq!(
                    pin.content_hash,
                    hex::encode(blake3::hash(b"old").as_bytes())
                );
                if owner.revision_id == revision.value.revision_id {
                    assert!(owner.signed_revision_metadata_available);
                    assert_eq!(owner.protected_root_id, Some(root_id));
                } else {
                    assert!(!owner.signed_revision_metadata_available);
                    assert_eq!(owner.protected_root_id, None);
                }
            }
            assert_eq!(local.unclassified_guarded_records.len(), 2);
            let pending = &local.unclassified_guarded_records[1];
            assert_eq!(pending.kind, "link-freeze-pending");
            assert_eq!(pending.record_id_hex, hex::encode(b"intent"));
            assert_eq!(pending.payload_bytes, 16);
            assert_eq!(
                pending.payload_hash,
                hex::encode(blake3::hash(b"preserved intent").as_bytes())
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            assert_preserved_files(&data, &before);
            assert!(!root_path.exists() && !history_path.exists());
            assert!(!capture.files[0].locator.area.path_hint.exists());
            assert!(!capture.files[0].locator.area.volume_root_hint.exists());
        }
    }

    #[test]
    fn inventory_reads_live_wal_without_checkpointing_or_rewriting_keys() {
        let ((keys, revision, _), _, _, _) = super::super::tests::fixed_checkpoint_fixture(7);
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let (writer, _) = crate::volume::open_control_store(&data, &keys).unwrap();
        writer
            .database_shell_statement("PRAGMA wal_autocheckpoint = 0", false)
            .unwrap();
        save_revision(&writer, &revision);
        let root_id = revision.value.protected_root_id;
        save(
            &writer,
            "protected-root",
            root_id,
            &ProtectedRoot {
                format_version: 4,
                root_id,
                path: temp.path().join("missing-source"),
                filesystem_id: 7,
                root_inode: 10,
            },
        );
        let paths = ["control.db", "control.db-wal", "control.key"];
        let before: Vec<_> = paths
            .iter()
            .map(|name| fs::read(data.join(name)).unwrap())
            .collect();
        let report =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap();
        assert_eq!(report.revisions[0].revision_id, revision.value.revision_id);
        assert_eq!(report.local_state.protected_roots[0].root_id, root_id);
        for (name, expected) in paths.iter().zip(before) {
            assert!(
                fs::read(data.join(name)).unwrap() == expected,
                "{name} changed"
            );
        }
        assert!(!data.join("parity.db").exists());
        assert!(!temp.path().join("missing-source").exists());
    }

    #[test]
    fn local_inventory_rejects_malformed_ownership_and_registration_without_mutation() {
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([49; 32]));
        for case in 0..12 {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
            let id = Uuid::from_bytes([43; 16]);
            let mut capture = stopped_capture(temp.path());
            match case {
                0 => capture.files[0].locator.anchor_id = Uuid::nil(),
                1 => capture.files[0].locator.area.area_id = Uuid::nil(),
                2 => capture.files[0].locator.relative_path = "../escape".into(),
                3 => capture.files[0].logical_len = 4,
                4 => capture.files[0].data_extents[0].logical_len = 4,
                5 => capture.metadata.entries[0].path = b"../escape".to_vec(),
                6 => capture
                    .metadata
                    .entries
                    .push(capture.metadata.entries[0].clone()),
                7 => {
                    save(
                        &store,
                        "protected-root",
                        id,
                        &ProtectedRoot {
                            format_version: 4,
                            root_id: Uuid::from_bytes([44; 16]),
                            path: temp.path().join("missing"),
                            filesystem_id: 7,
                            root_inode: 10,
                        },
                    );
                }
                8 => {
                    let mut binding = SourceBackendBinding::guarded_link_freeze_v1(id, 7, 10, 11);
                    binding.contract_version = 2;
                    save(&store, "source-backend", id, &binding);
                }
                9 => {
                    store
                        .put_record("git-repository", id.as_bytes(), b"invalid canonical record")
                        .unwrap();
                }
                10 => capture.files[0].locator.area.path_hint = "relative-area".into(),
                11 => capture.files[0].locator.area.path_hint = raw_path(temp.path(), b"nul\0area"),
                _ => unreachable!(),
            }
            save(&store, "guarded-view-stopped-capture-v1", id, &capture);
            drop(store);
            let before = preserved_files(&data);
            assert!(
                super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                    .is_err(),
                "case {case}"
            );
            assert_preserved_files(&data, &before);
            assert!(!capture.files[0].locator.area.path_hint.exists());
        }
    }
}
