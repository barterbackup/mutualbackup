//! Durable mount ownership for a guarded FUSE worktree whose private lower
//! root has already been captured. Enrollment still owns the separate,
//! replayable transition from a user's original directory to this layout.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, ensure};
use fuser::{BackgroundSession, Config, MountOption, SessionACL};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::guarded_view_probe::{
    GuardedProbeView, GuardedViewEntryKind, GuardedViewMetadataEntry, GuardedViewMetadataV1,
    GuardedViewTimeBaselineV1, retire_virtual_directory_size_dirty, retire_virtual_time_dirty,
    virtual_directory_size_dirty_ids, virtual_time_dirty_masks,
};
use crate::{
    CapturedEntry, ControlStore, FileAnchorManifest, FileExtent, GuardedFileCapturePlan,
    GuardedRootCapturePlan, NativeFileId, PinnedDirectory, StableAnchorFileLocator,
    StableAnchorManifest, filesystem_identity,
};

const MOUNT_CLAIM_KIND: &str = "guarded-view-mount-v1";
const MOUNT_RETIRE_KIND: &str = "guarded-view-mount-retired-v1";
const VIRTUAL_METADATA_KIND: &str = "guarded-view-virtual-metadata-v1";
const VIRTUAL_TIME_BASELINE_KIND: &str = "guarded-view-virtual-time-baseline-v1";
const STOPPED_CAPTURE_KIND: &str = "guarded-view-stopped-capture-v1";
const STOPPED_FILE_CAPTURE_KIND: &str = "guarded-view-stopped-file-capture-v1";
const GIT_ANCHOR_PIN_KIND: &str = "guarded-git-anchor-pin-v1";
const GIT_ROOT_PIN_KIND: &str = "guarded-git-root-pin-v1";
const GIT_RECOVERY_PIN_KIND: &str = "guarded-git-recovered-root-pin-v1";
pub const GUARDED_REVISION_CAPTURE_KIND: &str = "guarded-view-revision-capture-v1";
const GUARDED_REVISION_RETIREMENT_KIND: &str = "guarded-view-revision-retirement-v1";
const STOPPED_CAPTURE_MAX_BYTES: usize = mb_core::V1_MAX_CATALOG_BYTES * 2 + 4096;
const MOUNT_SUBTYPE: &str = "mutualbackup_guarded";
// The daemon is the sole writer for a root. Serialize local mount lifecycle
// operations so a stopped-view snapshot cannot overlap a remount or stop.
static MOUNT_LIFECYCLE: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MountClaim {
    version: u16,
    anchor_id: Uuid,
    #[serde(with = "crate::raw_path_bytes")]
    lower_root: PathBuf,
    lower_id: NativeFileId,
    #[serde(with = "crate::raw_path_bytes")]
    mountpoint: PathBuf,
    mountpoint_id: NativeFileId,
    view_uid: u32,
    view_gid: u32,
}

#[derive(Debug)]
struct MountedFilesystem {
    filesystem_type: String,
    source: String,
}

/// A mounted guarded view. Keep this with the daemon's root registration;
/// dropping it unmounts the view, while `stop` propagates unmount errors.
pub struct GuardedViewMount {
    anchor_id: Uuid,
    session: Option<BackgroundSession>,
    mountpoint: PathBuf,
    source: String,
    claim: MountClaim,
}

/// The durable claim behind a live, supervised guarded view. The protected
/// root's stable filesystem identity belongs to the private lower directory,
/// not to the FUSE mount that presents its editable namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardedViewBinding {
    pub anchor_id: Uuid,
    pub lower_root: PathBuf,
    pub lower_id: NativeFileId,
    pub mountpoint: PathBuf,
    pub mountpoint_id: NativeFileId,
    pub view_uid: u32,
    pub view_gid: u32,
}

/// One quiescent view with an immutable anchor for every visible file. This
/// local capture is input to a future signed owner revision, not a revision by
/// itself. The revision owner must pin its file locators until retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedStoppedCaptureV1 {
    pub format_version: u16,
    pub metadata: GuardedViewMetadataV1,
    pub files: Vec<GuardedStoppedFileV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedStoppedFileV1 {
    pub path: Vec<u8>,
    pub native_id: NativeFileId,
    pub locator: StableAnchorFileLocator,
    pub logical_len: u64,
    pub content_hash: [u8; 32],
    pub data_extents: Vec<FileExtent>,
}

/// Local anchor ownership after a signed owner revision takes over a stopped
/// capture. The signed private metadata omits these machine-specific IDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedRevisionCaptureV1 {
    pub format_version: u16,
    pub revision_id: Uuid,
    pub capture: GuardedStoppedCaptureV1,
}

impl GuardedRevisionCaptureV1 {
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.format_version == 1 && !self.revision_id.is_nil(),
            "invalid guarded revision capture"
        );
        self.capture.verify()
    }

    fn validate_record(&self, record_id: &[u8]) -> anyhow::Result<()> {
        ensure!(
            self.format_version == 1
                && self.revision_id.as_bytes() == record_id
                && !self.revision_id.is_nil()
                && self.capture.format_version == 1
                && mb_core::canonical_bytes(self)?.len() <= STOPPED_CAPTURE_MAX_BYTES,
            "guarded revision capture key changed"
        );
        self.capture.validate_shape()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoppedCaptureIntent {
    format_version: u16,
    attempt_id: Uuid,
    root_anchor_id: Uuid,
    metadata: GuardedViewMetadataV1,
    published: Option<GuardedStoppedCaptureV1>,
}

/// A single file reserved for a future Git index publication. The node keeps
/// this record until the Git catalog has durably taken over its anchor pin.
/// A prepared record fences remount, so replay observes the same view bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoppedFileCaptureIntent {
    format_version: u16,
    attempt_id: Uuid,
    root_anchor_id: Uuid,
    entry: GuardedViewMetadataEntry,
    published: Option<FileAnchorManifest>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedGitAnchorPin {
    format_version: u16,
    repository_id: Uuid,
    root_anchor_id: Uuid,
    manifest: FileAnchorManifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stage: Option<GuardedGitStageContext>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedGitAnchorPinV1 {
    format_version: u16,
    repository_id: Uuid,
    root_anchor_id: Uuid,
    manifest: FileAnchorManifest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedGitStageContext {
    attempt_id: Uuid,
    worktree_id: Uuid,
    relative_path: Vec<u8>,
    git_mode: u32,
}

/// A durable guarded capture ready for replayable Git catalog publication.
/// A version-1 pin without stage context fails closed during listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardedGitStagePin {
    pub repository_id: Uuid,
    pub root_anchor_id: Uuid,
    pub manifest: FileAnchorManifest,
    pub attempt_id: Uuid,
    pub worktree_id: Uuid,
    pub relative_path: Vec<u8>,
    pub git_mode: u32,
}

/// Node-owned half of an imported Git blob's move onto a recovered guarded
/// root file. The same canonical record is retained as the catalog receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedGitRecoveryPin {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub oid: [u8; 20],
    pub imported: FileAnchorManifest,
    pub root_file: FileAnchorManifest,
}

impl GuardedGitRecoveryPin {
    pub fn root_anchor_id(&self) -> anyhow::Result<Uuid> {
        let backing = self
            .root_file
            .guarded_root_file
            .as_ref()
            .context("recovered Git pin has no root-file backing")?;
        ensure!(
            self.format_version == 1
                && !self.repository_id.is_nil()
                && self.imported.format_version == 1
                && self.imported.guarded_root_file.is_none()
                && self.root_file.format_version == 2
                && !self.imported.anchor_id.is_nil()
                && self.imported.anchor_id == self.root_file.anchor_id
                && !backing.root_anchor_id.is_nil()
                && backing.root_anchor_id != self.imported.anchor_id
                && self.imported.area == self.root_file.area
                && self.imported.logical_len == self.root_file.logical_len
                && self.imported.content_hash == self.root_file.content_hash,
            "invalid recovered Git root pin"
        );
        Ok(backing.root_anchor_id)
    }
}

fn valid_git_stage_path(bytes: &[u8]) -> bool {
    let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    !bytes.is_empty()
        && bytes.len() <= 4096
        && !bytes.contains(&0)
        && path
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && !matches!(
            path.components().next(),
            Some(Component::Normal(name))
                if name == OsStr::new(".git") || name == OsStr::new(".mutualbackup")
        )
        && path.as_os_str().as_bytes() == bytes
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedGitRootPin {
    format_version: u16,
    repository_id: Uuid,
    root_anchor_id: Uuid,
}

fn git_anchor_pin(
    control: &ControlStore,
    anchor_id: Uuid,
) -> anyhow::Result<Option<(Vec<u8>, GuardedGitAnchorPin)>> {
    let Some(bytes) = control.get_record(GIT_ANCHOR_PIN_KIND, anchor_id.as_bytes())? else {
        return Ok(None);
    };
    ensure!(
        bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
        "guarded Git pin is too large"
    );
    // Canonical CBOR structs are positional. A trailing optional field does
    // not make an older four-field pin decode as the new five-field record.
    let pin: GuardedGitAnchorPin = match mb_core::decode_canonical(&bytes) {
        Ok(pin) => pin,
        Err(_) => {
            let old: GuardedGitAnchorPinV1 = mb_core::decode_canonical(&bytes)?;
            GuardedGitAnchorPin {
                format_version: old.format_version,
                repository_id: old.repository_id,
                root_anchor_id: old.root_anchor_id,
                manifest: old.manifest,
                stage: None,
            }
        }
    };
    ensure!(
        matches!(pin.format_version, 1 | 2)
            && !pin.repository_id.is_nil()
            && !pin.root_anchor_id.is_nil()
            && matches!(pin.manifest.format_version, 1 | 2)
            && pin.manifest.anchor_id == anchor_id
            && match (&pin.stage, pin.format_version) {
                (None, 1) => true,
                (Some(stage), 2) => {
                    !stage.attempt_id.is_nil()
                        && !stage.worktree_id.is_nil()
                        && valid_git_stage_path(&stage.relative_path)
                        && matches!(stage.git_mode, 0o100644 | 0o100755)
                }
                _ => false,
            }
            && mb_core::canonical_bytes(&pin)? == bytes,
        "guarded Git anchor pin is invalid"
    );
    Ok(Some((bytes, pin)))
}

fn git_root_pin(
    control: &ControlStore,
    root_anchor_id: Uuid,
) -> anyhow::Result<Option<(Vec<u8>, GuardedGitRootPin)>> {
    let Some(bytes) = control.get_record(GIT_ROOT_PIN_KIND, root_anchor_id.as_bytes())? else {
        return Ok(None);
    };
    ensure!(bytes.len() <= 4096, "guarded Git root pin is too large");
    let pin: GuardedGitRootPin = mb_core::decode_canonical(&bytes)?;
    ensure!(
        pin.format_version == 1
            && !pin.repository_id.is_nil()
            && pin.root_anchor_id == root_anchor_id
            && mb_core::canonical_bytes(&pin)? == bytes,
        "guarded Git root pin is invalid"
    );
    Ok(Some((bytes, pin)))
}

impl StoppedFileCaptureIntent {
    fn validate(&self, record_id: &[u8]) -> anyhow::Result<()> {
        let path = PathBuf::from(OsString::from_vec(self.entry.path.clone()));
        ensure!(
            self.format_version == 1
                && !self.attempt_id.is_nil()
                && self.attempt_id.as_bytes() == record_id
                && !self.root_anchor_id.is_nil()
                && self.entry.kind == GuardedViewEntryKind::File
                && !self.entry.path.is_empty()
                && !self.entry.path.contains(&0)
                && path
                    .components()
                    .all(|part| matches!(part, Component::Normal(_)))
                && path.as_os_str().as_bytes() == self.entry.path
                && self.entry.native_id.inode != 0
                && self.entry.native_id.filesystem_id != 0
                && self.entry.mode & !0o7777 == 0
                && self.entry.atime_nanos < 1_000_000_000
                && self.entry.modified_nanos < 1_000_000_000
                && self.published.as_ref().is_none_or(|manifest| {
                    matches!(manifest.format_version, 1 | 2)
                        && !manifest.anchor_id.is_nil()
                        && manifest.source_file_identity() == self.entry.native_id
                        && manifest.logical_len == self.entry.logical_len
                }),
            "guarded stopped-file capture intent is invalid"
        );
        Ok(())
    }
}

fn verify_published_file_capture_binding(
    control: &ControlStore,
    intent: &StoppedFileCaptureIntent,
    manifest: &FileAnchorManifest,
) -> anyhow::Result<()> {
    let claim_bytes = control
        .get_record(MOUNT_CLAIM_KIND, intent.root_anchor_id.as_bytes())?
        .context("guarded file attempt lost its mount claim")?;
    let claim: MountClaim = mb_core::decode_canonical(&claim_bytes)?;
    ensure!(
        claim.version == 1 && claim.anchor_id == intent.root_anchor_id,
        "guarded file attempt lost its mount claim"
    );
    if let Some(backing) = &manifest.guarded_root_file {
        let original =
            GuardedRootCapturePlan::load_published_manifest(control, intent.root_anchor_id)?;
        let root_plan = GuardedRootCapturePlan::load_active_for_view(control, &original)?;
        let entry = original.entries.iter().find(|entry| {
            matches!(entry, CapturedEntry::FileV2 { path, native_id, .. }
                if path == &backing.captured_relative_path && *native_id == backing.native_id)
        });
        let proof =
            root_plan.captured_file_content_proof(control, &backing.captured_relative_path)?;
        ensure!(
            manifest.format_version == 2
                && entry.is_some()
                && backing.root_anchor_id == intent.root_anchor_id
                && backing.native_id == intent.entry.native_id
                && manifest.area == original.area
                && manifest.source_root_hint == claim.lower_root
                && manifest.source_relative_path.as_os_str().as_bytes() == intent.entry.path
                && manifest.logical_len == proof.logical_len
                && manifest.content_hash == proof.content_hash,
            "guarded root-file Git stage differs from its sealed root proof"
        );
    } else {
        let plan = GuardedFileCapturePlan::load_for_manifest(control, manifest)?
            .context("guarded file attempt lost its source plan")?;
        ensure!(
            plan.source_root() == claim.lower_root
                && plan.source_root_identity() == claim.lower_id
                && plan.source_file_identity() == intent.entry.native_id,
            "guarded file attempt differs from its claimed source"
        );
    }
    manifest.open_verified()?;
    Ok(())
}

type StoppedCaptureRecord = (Vec<u8>, Vec<u8>, StoppedCaptureIntent);

impl StoppedCaptureIntent {
    fn validate(&self, record_id: &[u8]) -> anyhow::Result<()> {
        self.metadata.validate_shape()?;
        ensure!(
            self.format_version == 1
                && !self.attempt_id.is_nil()
                && self.attempt_id.as_bytes() == record_id
                && !self.root_anchor_id.is_nil()
                && self.metadata.format_version == 1
                && self.metadata.anchor_id == self.root_anchor_id
                && self
                    .published
                    .as_ref()
                    .is_none_or(|capture| capture.metadata == self.metadata),
            "guarded stopped-capture intent differs from its metadata"
        );
        Ok(())
    }
}

impl GuardedViewMetadataV1 {
    /// Validate the raw-byte namespace before it is retained by a local
    /// attempt or embedded in encrypted revision metadata. A restored view
    /// must never infer missing parents or normalize a path while decoding.
    pub fn validate_shape(&self) -> anyhow::Result<()> {
        ensure!(
            self.format_version == 1
                && !self.anchor_id.is_nil()
                && self.lower_root_id.filesystem_id != 0
                && self.lower_root_id.inode != 0
                && self.root_mode & !0o7777 == 0
                && self.root_atime_nanos < 1_000_000_000
                && self.root_modified_nanos < 1_000_000_000,
            "invalid guarded view root metadata"
        );
        let mut previous = None::<&[u8]>;
        let mut directories = std::collections::BTreeSet::<&[u8]>::new();
        let mut identities = BTreeMap::<NativeFileId, &GuardedViewMetadataEntry>::new();
        for entry in &self.entries {
            let path = PathBuf::from(OsString::from_vec(entry.path.clone()));
            let mut normalized = PathBuf::new();
            for component in path.components() {
                let Component::Normal(name) = component else {
                    anyhow::bail!("guarded view has an unsafe path")
                };
                normalized.push(name);
            }
            ensure!(
                !entry.path.is_empty()
                    && !entry.path.contains(&0)
                    && normalized.as_os_str().as_bytes() == entry.path
                    && previous.is_none_or(|prior| prior < entry.path.as_slice()),
                "guarded view has an unsafe or unordered path"
            );
            ensure!(
                entry.native_id.filesystem_id == self.lower_root_id.filesystem_id
                    && entry.native_id.inode != 0
                    && entry.native_id != self.lower_root_id
                    && entry.mode & !0o7777 == 0
                    && entry.atime_nanos < 1_000_000_000
                    && entry.modified_nanos < 1_000_000_000,
                "invalid guarded view entry metadata"
            );
            if let Some(first) = identities.insert(entry.native_id, entry) {
                ensure!(
                    entry.kind == GuardedViewEntryKind::File
                        && first.kind == entry.kind
                        && first.mode == entry.mode
                        && first.uid == entry.uid
                        && first.gid == entry.gid
                        && first.logical_len == entry.logical_len
                        && first.modified_secs == entry.modified_secs
                        && first.modified_nanos == entry.modified_nanos,
                    "guarded view inode aliases disagree"
                );
            }
            if let Some(slash) = entry.path.iter().rposition(|byte| *byte == b'/') {
                ensure!(
                    directories.contains(&entry.path[..slash]),
                    "guarded view entry has no recorded parent directory"
                );
            }
            if entry.kind == GuardedViewEntryKind::Directory {
                directories.insert(&entry.path);
            }
            previous = Some(&entry.path);
        }
        Ok(())
    }
}

fn validate_virtual_metadata_binding(
    metadata: &GuardedViewMetadataV1,
    manifest: &StableAnchorManifest,
    plan: &GuardedRootCapturePlan,
) -> anyhow::Result<()> {
    metadata.validate_shape()?;
    ensure!(
        metadata.anchor_id == manifest.anchor_id
            && metadata.lower_root_id == plan.source_root_identity()
            && metadata.entries.len() == manifest.entries.len(),
        "guarded virtual metadata differs from its captured root"
    );
    for (signed, captured) in metadata.entries.iter().zip(&manifest.entries) {
        let (path, kind, mode, logical_len, native_id) = match captured {
            CapturedEntry::Directory { path, mode, .. } => (
                path,
                GuardedViewEntryKind::Directory,
                *mode,
                None,
                plan.captured_entry_identity(path),
            ),
            CapturedEntry::FileV2 {
                path,
                mode,
                logical_len,
                native_id,
                ..
            } => (
                path,
                GuardedViewEntryKind::File,
                *mode,
                Some(*logical_len),
                Some(*native_id),
            ),
            CapturedEntry::File { .. } => {
                anyhow::bail!("guarded virtual metadata needs native file identities")
            }
        };
        ensure!(
            signed.path == path.as_os_str().as_bytes()
                && signed.kind == kind
                && signed.native_id == native_id.context("guarded source plan lacks entry")?
                && signed.mode == (mode & 0o7777) as u16
                && logical_len.is_none_or(|len| signed.logical_len == len),
            "guarded virtual metadata entry differs from captured source"
        );
    }
    Ok(())
}

fn stopped_capture_intents(control: &ControlStore) -> anyhow::Result<Vec<StoppedCaptureRecord>> {
    control
        .records(STOPPED_CAPTURE_KIND)?
        .into_iter()
        .map(|(id, bytes)| {
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded stopped-capture intent exceeds its local bound"
            );
            let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
            intent.validate(&id)?;
            Ok((id, bytes, intent))
        })
        .collect()
}

fn guarded_revision_captures(
    control: &ControlStore,
) -> anyhow::Result<Vec<GuardedRevisionCaptureV1>> {
    control
        .records(GUARDED_REVISION_CAPTURE_KIND)?
        .into_iter()
        .map(|(id, bytes)| {
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded revision capture exceeds its local bound"
            );
            let record: GuardedRevisionCaptureV1 = mb_core::decode_canonical(&bytes)?;
            record.validate_record(&id)?;
            Ok(record)
        })
        .collect()
}

fn pending_stopped_capture_attempts(
    control: &ControlStore,
    root_anchor_id: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(stopped_capture_intents(control)?
        .into_iter()
        .filter_map(|(_, _, intent)| {
            (intent.root_anchor_id == root_anchor_id && intent.published.is_none())
                .then_some(intent.attempt_id)
        })
        .collect())
}

fn stopped_file_capture_intents(
    control: &ControlStore,
) -> anyhow::Result<Vec<StoppedFileCaptureIntent>> {
    let records = control.records(STOPPED_FILE_CAPTURE_KIND)?;
    ensure!(
        records.len() <= 1024,
        "too many guarded file-capture attempts"
    );
    records
        .into_iter()
        .map(|(id, bytes)| {
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded stopped-file intent exceeds its local bound"
            );
            let intent: StoppedFileCaptureIntent = mb_core::decode_canonical(&bytes)?;
            intent.validate(&id)?;
            Ok(intent)
        })
        .collect()
}

fn pending_stopped_file_capture_attempts(
    control: &ControlStore,
    root_anchor_id: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(stopped_file_capture_intents(control)?
        .into_iter()
        .filter_map(|intent| {
            (intent.root_anchor_id == root_anchor_id && intent.published.is_none())
                .then_some(intent.attempt_id)
        })
        .collect())
}

pub(crate) fn guarded_anchor_is_pinned(
    control: &ControlStore,
    anchor_id: Uuid,
) -> anyhow::Result<bool> {
    if git_anchor_pin(control, anchor_id)?.is_some() || git_root_pin(control, anchor_id)?.is_some()
    {
        return Ok(true);
    }
    let pending = stopped_capture_intents(control)?
        .into_iter()
        .any(|(_, _, intent)| {
            intent.root_anchor_id == anchor_id
                || intent.published.as_ref().is_some_and(|capture| {
                    capture
                        .files
                        .iter()
                        .any(|file| file.locator.anchor_id == anchor_id)
                })
        });
    if pending
        || stopped_file_capture_intents(control)?
            .into_iter()
            .any(|intent| {
                intent.root_anchor_id == anchor_id
                    || intent
                        .published
                        .as_ref()
                        .is_some_and(|manifest| manifest.anchor_id == anchor_id)
            })
    {
        return Ok(true);
    }
    Ok(guarded_revision_captures(control)?
        .into_iter()
        .any(|record| {
            record.capture.metadata.anchor_id == anchor_id
                || record
                    .capture
                    .files
                    .iter()
                    .any(|file| file.locator.anchor_id == anchor_id)
        }))
}

impl GuardedStoppedCaptureV1 {
    fn validate_shape(&self) -> anyhow::Result<()> {
        self.metadata.validate_shape()?;
        ensure!(
            self.format_version == 1
                && mb_core::canonical_bytes(self)?.len() <= mb_core::V1_MAX_CATALOG_BYTES,
            "invalid guarded stopped-capture version or size"
        );
        let files: Vec<_> = self
            .metadata
            .entries
            .iter()
            .filter(|entry| entry.kind == GuardedViewEntryKind::File)
            .collect();
        ensure!(
            files.len() == self.files.len(),
            "guarded stopped capture lacks a visible file anchor"
        );
        for (entry, captured) in files.into_iter().zip(&self.files) {
            ensure!(
                captured.path == entry.path
                    && captured.native_id == entry.native_id
                    && captured.logical_len == entry.logical_len
                    && captured.locator.area.filesystem_id
                        == self.metadata.lower_root_id.filesystem_id,
                "guarded stopped file differs from visible metadata"
            );
        }
        Ok(())
    }

    /// Recheck a persisted local capture before building signed sector data.
    /// This proves each locator still supplies the exact captured bytes and
    /// sparse layout, without depending on the mutable lower worktree.
    pub fn verify(&self) -> anyhow::Result<()> {
        self.validate_shape()?;
        for captured in &self.files {
            let mut file = captured.locator.open()?;
            ensure!(
                file.metadata()?.len() == captured.logical_len,
                "guarded stopped anchor has another length"
            );
            let mut hasher = blake3::Hasher::new();
            let mut read_len = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                read_len += read as u64;
            }
            ensure!(
                read_len == captured.logical_len
                    && hasher.finalize().as_bytes() == &captured.content_hash
                    && crate::anchor::file_data_extents(&file, captured.logical_len)?
                        == captured.data_extents,
                "guarded stopped anchor differs from its captured bytes or extents"
            );
        }
        Ok(())
    }
}

impl GuardedViewMount {
    pub fn has_revision_capture_retirements(control: &ControlStore) -> anyhow::Result<bool> {
        Ok(!control
            .records(GUARDED_REVISION_RETIREMENT_KIND)?
            .is_empty())
    }

    pub fn has_claims(control: &ControlStore) -> anyhow::Result<bool> {
        Ok(!control.records(MOUNT_CLAIM_KIND)?.is_empty())
    }

    pub fn claimed_anchor_ids(control: &ControlStore) -> anyhow::Result<Vec<Uuid>> {
        let claims = control.records(MOUNT_CLAIM_KIND)?;
        ensure!(claims.len() <= 256, "too many guarded mount claims");
        let mut ids = Vec::with_capacity(claims.len());
        for (record_id, bytes) in claims {
            let anchor_id = Uuid::from_slice(&record_id)?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount claim record is inconsistent"
            );
            ids.push(anchor_id);
        }
        Ok(ids)
    }

    pub fn anchor_id(&self) -> Uuid {
        self.anchor_id
    }

    pub fn load_revision_capture(
        revision_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<Option<GuardedRevisionCaptureV1>> {
        let Some(bytes) =
            control.get_record(GUARDED_REVISION_CAPTURE_KIND, revision_id.as_bytes())?
        else {
            return Ok(None);
        };
        ensure!(
            bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
            "guarded revision capture exceeds its local bound"
        );
        let record: GuardedRevisionCaptureV1 = mb_core::decode_canonical(&bytes)?;
        record.validate_record(revision_id.as_bytes())?;
        record.verify()?;
        Ok(Some(record))
    }

    /// Transfer an unreachable revision's local anchor map to a replayable
    /// retirement obligation. The node must first prove that the signed
    /// revision and every local sector recipe using these anchors are gone.
    pub fn retire_revision_capture_unreferenced(
        revision_id: Uuid,
        control: &mut ControlStore,
        pinned_anchor_ids: &BTreeSet<Uuid>,
    ) -> anyhow::Result<()> {
        ensure!(
            control
                .get_record("user-revision", revision_id.as_bytes())?
                .is_none(),
            "signed guarded revision still retains its capture"
        );
        if let Some(bytes) =
            control.get_record(GUARDED_REVISION_CAPTURE_KIND, revision_id.as_bytes())?
        {
            Self::load_revision_capture(revision_id, control)?
                .context("guarded revision lost its local capture")?;
            ensure!(
                control
                    .get_record(GUARDED_REVISION_RETIREMENT_KIND, revision_id.as_bytes())?
                    .is_none_or(|existing| existing == bytes),
                "guarded revision retirement conflicts with its capture"
            );
            control.move_protocol_record(
                GUARDED_REVISION_CAPTURE_KIND,
                revision_id.as_bytes(),
                &bytes,
                GUARDED_REVISION_RETIREMENT_KIND,
                revision_id.as_bytes(),
            )?;
        }
        Self::reconcile_revision_capture_retirements(control, pinned_anchor_ids)
    }

    /// Resume physical cleanup after a crash. A still claimed view, another
    /// revision pin, or an unavailable source volume leaves the obligation
    /// durable for a later retry.
    pub fn reconcile_revision_capture_retirements(
        control: &ControlStore,
        pinned_anchor_ids: &BTreeSet<Uuid>,
    ) -> anyhow::Result<()> {
        for (id, bytes) in control.records(GUARDED_REVISION_RETIREMENT_KIND)? {
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded revision retirement exceeds its local bound"
            );
            let record: GuardedRevisionCaptureV1 = mb_core::decode_canonical(&bytes)?;
            record.validate_record(&id)?;
            if control.get_record("user-revision", &id)?.is_some() {
                continue;
            }
            let root_id = record.capture.metadata.anchor_id;
            let mut file_ids = BTreeSet::new();
            for file in &record.capture.files {
                if file.locator.anchor_id != root_id {
                    file_ids.insert(file.locator.anchor_id);
                }
            }
            // An unrelated retained revision can still use an old sector
            // recipe after this revision's map is retired. The node supplies
            // its freshly scanned recipe pins on every replay, not just when
            // it first transfers the capture map.
            if pinned_anchor_ids.contains(&root_id)
                || file_ids.iter().any(|id| pinned_anchor_ids.contains(id))
            {
                continue;
            }
            let mut pending = false;
            for file_id in file_ids {
                match crate::GuardedFileCapturePlan::load_for_retirement(control, file_id) {
                    Ok(Some(plan)) => {
                        if plan.discard_unreferenced(control).is_err() {
                            pending = true;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => pending = true,
                }
            }
            if pending {
                continue;
            }
            match GuardedRootCapturePlan::load_for_retirement(control, root_id) {
                Ok(Some(plan)) => {
                    if plan.discard_unreferenced(control).is_err() {
                        continue;
                    }
                }
                Ok(None) => {}
                Err(_) => continue,
            }
            control.delete_record_if_value(GUARDED_REVISION_RETIREMENT_KIND, &id, &bytes)?;
        }
        Ok(())
    }

    /// Recover every active durable mount claim before the daemon starts
    /// serving requests. A retirement marker wins over an old claim; finish
    /// that retirement instead of remounting a view being released.
    pub fn recover_all_claimed(control: Arc<Mutex<ControlStore>>) -> anyhow::Result<Vec<Self>> {
        Self::recover_all_claimed_except(control, &BTreeSet::new())
    }

    /// Leave a node-owned removal intent stopped while recovering unrelated
    /// views. The node must replay each excluded release before serving work;
    /// skipping a claim alone is not a completed removal.
    pub fn recover_all_claimed_except(
        control: Arc<Mutex<ControlStore>>,
        release_anchors: &BTreeSet<Uuid>,
    ) -> anyhow::Result<Vec<Self>> {
        let active = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let claims = control.records(MOUNT_CLAIM_KIND)?;
            ensure!(claims.len() <= 256, "too many guarded mount claims");
            let mut active = Vec::with_capacity(claims.len());
            for (record_id, bytes) in claims {
                let anchor_id = Uuid::from_slice(&record_id)?;
                let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
                ensure!(
                    claim.version == 1 && claim.anchor_id == anchor_id,
                    "guarded mount claim record is inconsistent"
                );
                if let Some(retired) =
                    control.get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
                {
                    ensure!(retired == bytes, "guarded mount retirement marker changed");
                    Self::retire_claim(anchor_id, &control)?;
                } else if release_anchors.contains(&anchor_id) {
                    ensure!(
                        pending_stopped_capture_attempts(&control, anchor_id)?.is_empty()
                            && pending_stopped_file_capture_attempts(&control, anchor_id)?
                                .is_empty(),
                        "guarded release overlaps a prepared capture"
                    );
                } else {
                    active.push(anchor_id);
                }
            }
            active
        };
        let mut mounts = Vec::with_capacity(active.len());
        for anchor_id in active {
            let pending = {
                let store = control
                    .lock()
                    .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                pending_stopped_capture_attempts(&store, anchor_id)?
            };
            for attempt_id in pending {
                Self::finish_stopped_capture(anchor_id, attempt_id, Arc::clone(&control))?;
            }
            let pending_files = {
                let store = control
                    .lock()
                    .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                pending_stopped_file_capture_attempts(&store, anchor_id)?
            };
            for attempt_id in pending_files {
                Self::finish_stopped_file_capture(anchor_id, attempt_id, Arc::clone(&control))?;
            }
            let mount = Self::recover_claimed(anchor_id, Arc::clone(&control))?;
            mount.check_health()?;
            mounts.push(mount);
        }
        Ok(mounts)
    }

    /// Retire a stopped view before releasing its captured anchors. The caller
    /// must first prove the protected revision and every Git pin are gone.
    /// The retirement marker fences remount even if deletion of the claim is
    /// interrupted; retrying this method finishes that deletion.
    pub fn retire_claim(anchor_id: Uuid, control: &ControlStore) -> anyhow::Result<()> {
        Self::require_release_unpinned(anchor_id, control)?;
        let id = anchor_id.as_bytes();
        let claim_bytes = control.get_record(MOUNT_CLAIM_KIND, id)?;
        let retired = control.get_record(MOUNT_RETIRE_KIND, id)?;
        let Some(claim_bytes) = claim_bytes else {
            let bytes =
                retired.ok_or_else(|| anyhow::anyhow!("guarded mount has no claim to retire"))?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount retirement marker changed"
            );
            ensure!(
                mounted_filesystem(&claim.mountpoint)?.is_none(),
                "guarded view remains mounted during retirement"
            );
            control.delete_record(VIRTUAL_METADATA_KIND, id)?;
            control.delete_record(VIRTUAL_TIME_BASELINE_KIND, id)?;
            retire_virtual_time_dirty(control, anchor_id)?;
            retire_virtual_directory_size_dirty(control, anchor_id)?;
            return Ok(());
        };
        let claim: MountClaim = mb_core::decode_canonical(&claim_bytes)?;
        ensure!(
            claim.version == 1 && claim.anchor_id == anchor_id,
            "guarded mount claim changed before retirement"
        );
        ensure!(
            retired.as_ref().is_none_or(|bytes| bytes == &claim_bytes),
            "guarded mount retirement belongs to another claim"
        );
        ensure!(
            mounted_filesystem(&claim.mountpoint)?.is_none(),
            "guarded view remains mounted during retirement"
        );
        let lower = PinnedDirectory::open(&claim.lower_root)?;
        let placeholder = PinnedDirectory::open(&claim.mountpoint)?;
        ensure!(
            lower.identity()? == claim.lower_id && placeholder.identity()? == claim.mountpoint_id,
            "guarded mount paths changed before retirement"
        );
        if retired.is_none() {
            ensure!(control.put_record_if_absent(MOUNT_RETIRE_KIND, id, &claim_bytes)?);
        }
        control.delete_record_if_value(MOUNT_CLAIM_KIND, id, &claim_bytes)?;
        control.delete_record(VIRTUAL_METADATA_KIND, id)?;
        control.delete_record(VIRTUAL_TIME_BASELINE_KIND, id)?;
        retire_virtual_time_dirty(control, anchor_id)?;
        retire_virtual_directory_size_dirty(control, anchor_id)?;
        Ok(())
    }

    /// Read-only pin check for the node's guarded-root removal preflight.
    /// Retirement repeats it after the view has stopped and files detach.
    pub fn require_release_unpinned(anchor_id: Uuid, control: &ControlStore) -> anyhow::Result<()> {
        ensure!(
            !guarded_anchor_is_pinned(control, anchor_id)?,
            "guarded mount retains a capture, revision, or Git pin"
        );
        Ok(())
    }

    /// Verify the retired claim still binds the exact private lower and
    /// user-facing placeholder before a separate-view name handoff.
    pub fn require_retired_release_binding(
        anchor_id: Uuid,
        control: &ControlStore,
        lower_root: &Path,
        lower_id: NativeFileId,
        mountpoint: &Path,
        mountpoint_id: NativeFileId,
    ) -> anyhow::Result<()> {
        require_retired_claim_for_release(
            control,
            anchor_id,
            lower_root,
            lower_id,
            mountpoint,
            mountpoint_id,
        )
    }

    /// Reopen a claimed view after process loss using only its durable local
    /// claim, capture plan, and sealed manifest. No caller-held manifest is
    /// needed; `start` still verifies the lower and placeholder identities.
    pub fn recover_claimed(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<Self> {
        let (claim, manifest) = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let bytes = control
                .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("guarded view has no durable mount claim"))?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount claim changed"
            );
            let manifest = GuardedRootCapturePlan::load_published_manifest(&control, anchor_id)?;
            (claim, manifest)
        };
        Self::start(
            &manifest,
            control,
            claim.mountpoint,
            claim.view_uid,
            claim.view_gid,
        )
    }

    /// Mount an existing private guarded capture. A durable claim binds the
    /// mountpoint and lower inode before FUSE becomes visible. On restart, only
    /// a dead FUSE mount with this exact source may be detached.
    pub fn start(
        manifest: &StableAnchorManifest,
        control: Arc<Mutex<ControlStore>>,
        mountpoint: impl AsRef<Path>,
        view_uid: u32,
        view_gid: u32,
    ) -> anyhow::Result<Self> {
        Self::start_inner(
            manifest,
            control,
            mountpoint.as_ref(),
            view_uid,
            view_gid,
            None,
        )
    }

    /// Mount a restored guarded capture with signed presentation metadata.
    /// The metadata is bound to the captured source and retained separately
    /// from the original mount claim so a later remount presents it again.
    pub fn start_with_virtual_metadata(
        manifest: &StableAnchorManifest,
        control: Arc<Mutex<ControlStore>>,
        mountpoint: impl AsRef<Path>,
        view_uid: u32,
        view_gid: u32,
        metadata: GuardedViewMetadataV1,
    ) -> anyhow::Result<Self> {
        Self::start_inner(
            manifest,
            control,
            mountpoint.as_ref(),
            view_uid,
            view_gid,
            Some(metadata),
        )
    }

    fn start_inner(
        manifest: &StableAnchorManifest,
        control: Arc<Mutex<ControlStore>>,
        mountpoint: &Path,
        view_uid: u32,
        view_gid: u32,
        requested_metadata: Option<GuardedViewMetadataV1>,
    ) -> anyhow::Result<Self> {
        let _lifecycle = MOUNT_LIFECYCLE
            .lock()
            .map_err(|_| io::Error::other("guarded mount lifecycle lock is poisoned"))?;
        ensure!(view_uid != 0, "guarded view needs an unprivileged owner");
        let mountpoint = canonical_mountpoint(mountpoint)?;
        let plan = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            ensure!(
                control
                    .get_record(MOUNT_RETIRE_KIND, manifest.anchor_id.as_bytes())?
                    .is_none(),
                "guarded mount has been retired"
            );
            ensure!(
                pending_stopped_capture_attempts(&control, manifest.anchor_id)?.is_empty()
                    && pending_stopped_file_capture_attempts(&control, manifest.anchor_id)?
                        .is_empty(),
                "guarded view has a prepared capture to finish before remount"
            );
            ensure!(
                !crate::guarded_recovery_handoff::release_prepared_for_anchor(
                    &control,
                    manifest.anchor_id,
                )?,
                "guarded view has a prepared release and cannot remount"
            );
            GuardedRootCapturePlan::load_active_for_view(&control, manifest)?
        };
        if let Some(metadata) = &requested_metadata {
            validate_virtual_metadata_binding(metadata, manifest, &plan)?;
        }
        let lower_root = PinnedDirectory::open(plan.source_root())?;
        ensure!(
            lower_root.identity()? == plan.source_root_identity(),
            "guarded lower root changed after capture"
        );
        let lower_metadata = lower_root.as_file().metadata()?;
        ensure!(
            lower_metadata.uid() != view_uid && lower_metadata.permissions().mode() & 0o077 == 0,
            "guarded lower root is accessible to the view owner"
        );
        let source = mount_source(manifest.anchor_id);
        let existing = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            control
                .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())?
                .map(|bytes| mb_core::decode_canonical::<MountClaim>(&bytes))
                .transpose()?
        };
        let virtual_metadata = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            control
                .get_record(VIRTUAL_METADATA_KIND, manifest.anchor_id.as_bytes())?
                .map(|bytes| {
                    ensure!(
                        bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                        "guarded virtual metadata exceeds its local bound"
                    );
                    Ok(mb_core::decode_canonical::<GuardedViewMetadataV1>(&bytes)?)
                })
                .transpose()?
        };
        let time_baseline = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            control
                .get_record(VIRTUAL_TIME_BASELINE_KIND, manifest.anchor_id.as_bytes())?
                .map(|bytes| {
                    ensure!(
                        bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                        "guarded virtual time baseline exceeds its local bound"
                    );
                    Ok(mb_core::decode_canonical::<GuardedViewTimeBaselineV1>(
                        &bytes,
                    )?)
                })
                .transpose()?
        };
        let dirty_times = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            virtual_time_dirty_masks(
                &control,
                manifest.anchor_id,
                u64::try_from(manifest.entries.len())?
                    .checked_add(2)
                    .context("guarded virtual inode overflow")?,
            )?
        };
        let dirty_sizes = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            virtual_directory_size_dirty_ids(
                &control,
                manifest.anchor_id,
                u64::try_from(manifest.entries.len())?
                    .checked_add(2)
                    .context("guarded virtual inode overflow")?,
            )?
        };
        if let Some(metadata) = &virtual_metadata {
            validate_virtual_metadata_binding(metadata, manifest, &plan)?;
            ensure!(
                requested_metadata
                    .as_ref()
                    .is_none_or(|requested| requested == metadata),
                "guarded virtual metadata differs from the durable record"
            );
        } else {
            ensure!(
                requested_metadata.is_none() || existing.is_none(),
                "cannot add guarded virtual metadata to an existing mount claim"
            );
        }
        if let Some(baseline) = &time_baseline {
            let metadata = virtual_metadata
                .as_ref()
                .or(requested_metadata.as_ref())
                .context("guarded virtual time baseline has no metadata")?;
            ensure!(
                baseline.format_version == 1
                    && baseline.anchor_id == manifest.anchor_id
                    && baseline.metadata_hash
                        == *blake3::hash(&mb_core::canonical_bytes(metadata)?).as_bytes()
                    && baseline.entries.len() == metadata.entries.len()
                    && baseline.root.valid()
                    && baseline.entries.iter().all(|entry| entry.valid()),
                "guarded virtual time baseline differs from signed metadata"
            );
        } else {
            ensure!(
                dirty_times.is_empty(),
                "guarded virtual time change lacks its baseline"
            );
        }
        if let Some(metadata) = virtual_metadata.as_ref().or(requested_metadata.as_ref()) {
            ensure!(
                dirty_sizes.iter().all(|inode| {
                    usize::try_from(inode - 2)
                        .ok()
                        .and_then(|index| metadata.entries.get(index))
                        .is_some_and(|entry| entry.kind == GuardedViewEntryKind::Directory)
                }),
                "guarded virtual directory size marker aliases a file"
            );
        } else {
            ensure!(
                dirty_sizes.is_empty(),
                "guarded virtual directory size marker has no metadata"
            );
        }
        if let Some(claim) = &existing {
            ensure!(
                claim.version == 1
                    && claim.anchor_id == manifest.anchor_id
                    && claim.lower_root == plan.source_root()
                    && claim.lower_id == plan.source_root_identity()
                    && claim.mountpoint == mountpoint
                    && claim.view_uid == view_uid
                    && claim.view_gid == view_gid,
                "guarded mount claim differs from the requested view"
            );
        }
        if let Some(mounted) = mounted_filesystem(&mountpoint)? {
            ensure!(
                existing.is_some(),
                "unclaimed filesystem occupies guarded mountpoint"
            );
            ensure!(
                mounted.matches_guarded(&source),
                "another filesystem occupies guarded mountpoint"
            );
            match fs::metadata(&mountpoint) {
                Ok(_) => anyhow::bail!("guarded view is already mounted and live"),
                Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => {}
                Err(error) => return Err(error).context("check existing guarded mount"),
            }
            let path = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes())?;
            // SAFETY: the claim and mountinfo identify this exact dead
            // guarded FUSE mount. The path is NUL-free and stays owned by
            // this process through the following identity check.
            if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } < 0 {
                return Err(io::Error::last_os_error()).context("detach dead guarded FUSE mount");
            }
        }
        let placeholder = PinnedDirectory::open(&mountpoint)?;
        let placeholder_id = placeholder.identity()?;
        let placeholder_metadata = placeholder.as_file().metadata()?;
        ensure!(
            placeholder_metadata.uid() != view_uid
                && placeholder_metadata.permissions().mode() & 0o022 == 0,
            "unmounted guarded placeholder is writable by the view owner"
        );
        ensure!(
            filesystem_identity(&mountpoint)?.stable_id == lower_root.identity()?.filesystem_id,
            "guarded view mountpoint is not on the lower filesystem"
        );
        ensure!(
            fs::read_dir(&mountpoint)?.next().is_none(),
            "guarded view mountpoint is not empty"
        );
        if let Some(claim) = &existing {
            ensure!(
                claim.mountpoint_id == placeholder_id,
                "guarded mountpoint changed after the original mount"
            );
        } else {
            // No FUSE operation has yet changed captured paths. Refuse an
            // accessible child before view reconstruction can replay a
            // pending namespace operation against that lower directory.
            plan.verify_initial_lower_namespace(&lower_root)?;
            plan.verify_initial_private_directories(&lower_root, view_uid)?;
        }
        // Build and validate the complete view before publishing a new mount
        // claim. A user-owned frozen anchor can be changed through a descriptor
        // retained before the private lower path was hidden: fchmod restores
        // write permission, then /proc/self/fd reopens the same inode.
        let mut view = GuardedProbeView::from_guarded_capture(
            manifest,
            Arc::clone(&control),
            view_uid,
            view_gid,
        )?;
        view.verify_private_lower_ownership()?;
        view.verify_lower_namespace()?;
        let new_time_baseline = if existing.is_none() && time_baseline.is_none() {
            virtual_metadata
                .as_ref()
                .or(requested_metadata.as_ref())
                .map(|metadata| view.capture_time_baseline(metadata))
                .transpose()?
        } else {
            None
        };
        if let Some(metadata) = virtual_metadata.as_ref().or(requested_metadata.as_ref()) {
            view.apply_virtual_metadata(
                metadata,
                time_baseline.as_ref().or(new_time_baseline.as_ref()),
                &dirty_times,
                &dirty_sizes,
                existing.is_none(),
            )?;
        }
        if existing.is_none() {
            let claim = MountClaim {
                version: 1,
                anchor_id: manifest.anchor_id,
                lower_root: plan.source_root().to_path_buf(),
                lower_id: plan.source_root_identity(),
                mountpoint: mountpoint.clone(),
                mountpoint_id: placeholder_id,
                view_uid,
                view_gid,
            };
            let encoded = mb_core::canonical_bytes(&claim)?;
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            for (other_id, bytes) in control.records(MOUNT_CLAIM_KIND)? {
                let other: MountClaim = mb_core::decode_canonical(&bytes)?;
                ensure!(
                    other.version == 1
                        && (other.mountpoint != mountpoint
                            || other_id == manifest.anchor_id.as_bytes()),
                    "another guarded capture claims this mountpoint"
                );
            }
            if let Some(metadata) = &requested_metadata {
                let encoded_metadata = mb_core::canonical_bytes(metadata)?;
                ensure!(
                    encoded_metadata.len() <= STOPPED_CAPTURE_MAX_BYTES,
                    "guarded virtual metadata exceeds its local bound"
                );
                if virtual_metadata.is_none() {
                    ensure!(
                        control.put_record_if_absent(
                            VIRTUAL_METADATA_KIND,
                            manifest.anchor_id.as_bytes(),
                            &encoded_metadata,
                        )?,
                        "guarded virtual metadata changed concurrently"
                    );
                }
            }
            if let Some(baseline) = &new_time_baseline {
                let encoded_baseline = mb_core::canonical_bytes(baseline)?;
                ensure!(
                    encoded_baseline.len() <= STOPPED_CAPTURE_MAX_BYTES,
                    "guarded virtual time baseline exceeds its local bound"
                );
                ensure!(
                    control.put_record_if_absent(
                        VIRTUAL_TIME_BASELINE_KIND,
                        manifest.anchor_id.as_bytes(),
                        &encoded_baseline,
                    )?,
                    "guarded virtual time baseline changed concurrently"
                );
            }
            ensure!(
                control.put_record_if_absent(
                    MOUNT_CLAIM_KIND,
                    manifest.anchor_id.as_bytes(),
                    &encoded,
                )?,
                "guarded mount claim changed concurrently"
            );
        }
        let mut config = Config::default();
        config.acl = SessionACL::All;
        config.mount_options = vec![
            MountOption::FSName(source.clone()),
            MountOption::Subtype(MOUNT_SUBTYPE.to_owned()),
            // The view advertises the owner's original modes while the
            // private lower inodes remain frozen. Kernel permission checks
            // must enforce those advertised modes for other local users.
            MountOption::DefaultPermissions,
        ];
        let session = fuser::spawn_mount(view, &mountpoint, &config)
            .context("mount guarded worktree view")?;
        let mounted = mounted_filesystem(&mountpoint)?;
        ensure!(
            mounted
                .as_ref()
                .is_some_and(|mounted| mounted.matches_guarded(&source)),
            "guarded mount did not appear with its claimed identity: {mounted:?}"
        );
        let claim = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            ensure!(
                control
                    .get_record(MOUNT_RETIRE_KIND, manifest.anchor_id.as_bytes())?
                    .is_none(),
                "guarded mount was retired while starting"
            );
            let bytes = control
                .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())?
                .context("guarded mount lost its claim while starting")?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1
                    && claim.anchor_id == manifest.anchor_id
                    && claim.lower_root == plan.source_root()
                    && claim.lower_id == plan.source_root_identity()
                    && claim.mountpoint == mountpoint
                    && claim.mountpoint_id == placeholder_id
                    && claim.view_uid == view_uid
                    && claim.view_gid == view_gid,
                "guarded mount claim changed while starting"
            );
            claim
        };
        Ok(Self {
            anchor_id: manifest.anchor_id,
            session: Some(session),
            mountpoint,
            source,
            claim,
        })
    }

    pub fn check_health(&self) -> anyhow::Result<()> {
        ensure!(
            !self
                .session
                .as_ref()
                .context("guarded FUSE worker is stopped")?
                .guard
                .is_finished(),
            "guarded FUSE worker exited"
        );
        ensure!(
            mounted_filesystem(&self.mountpoint)?
                .is_some_and(|mounted| mounted.matches_guarded(&self.source)),
            "guarded FUSE mount disappeared or changed"
        );
        fs::metadata(&self.mountpoint).context("guarded FUSE view is not responding")?;
        Ok(())
    }

    /// Check the live FUSE mount against its durable claim and lower inode.
    /// Callers must use this verified binding when associating a guarded view
    /// with a protected root; FUSE's own filesystem ID is not the source ID.
    pub fn verified_binding(&self, control: &ControlStore) -> anyhow::Result<GuardedViewBinding> {
        self.check_health()?;
        let bytes = control
            .get_record(MOUNT_CLAIM_KIND, self.anchor_id.as_bytes())?
            .context("guarded view lost its durable mount claim")?;
        let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
        ensure!(
            claim == self.claim
                && self.source == mount_source(self.anchor_id)
                && control
                    .get_record(MOUNT_RETIRE_KIND, self.anchor_id.as_bytes())?
                    .is_none(),
            "guarded view differs from its durable mount claim"
        );
        ensure!(
            PinnedDirectory::open(&claim.lower_root)?.identity()? == claim.lower_id,
            "guarded private lower root changed"
        );
        Ok(GuardedViewBinding {
            anchor_id: claim.anchor_id,
            lower_root: claim.lower_root,
            lower_id: claim.lower_id,
            mountpoint: claim.mountpoint,
            mountpoint_id: claim.mountpoint_id,
            view_uid: claim.view_uid,
            view_gid: claim.view_gid,
        })
    }

    pub fn verify_virtual_metadata(
        &self,
        control: &ControlStore,
        expected: &GuardedViewMetadataV1,
    ) -> anyhow::Result<()> {
        self.verified_binding(control)?;
        let expected_bytes = mb_core::canonical_bytes(expected)?;
        ensure!(
            expected.anchor_id == self.anchor_id
                && control.get_record(VIRTUAL_METADATA_KIND, self.anchor_id.as_bytes())?
                    == Some(expected_bytes),
            "guarded mounted view differs from signed recovery metadata"
        );
        Ok(())
    }

    /// Reconstruct the current visible namespace after the view has stopped.
    /// This is local, verified input for a future signed owner revision; it
    /// does not itself make the mutable view seed-recoverable.
    pub fn snapshot_stopped(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedViewMetadataV1> {
        Self::with_stopped_view(anchor_id, control, |view, _, _| {
            let metadata = view.verified_metadata_snapshot(anchor_id)?;
            metadata.validate_shape()?;
            Ok(metadata)
        })
    }

    /// Detach all currently visible lower files from immutable hard-link
    /// anchors while the FUSE view is stopped. This is a replayable prerequisite
    /// for returning the lower tree to ordinary ownership during root removal.
    /// The claim remains active and the caller must still complete removal.
    pub fn detach_stopped_files_for_release(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<()> {
        Self::with_stopped_view(anchor_id, control, |view, _, _| {
            view.detach_live_files_for_release()
        })
    }

    /// Capture a visible file from a stopped view into a second guarded
    /// anchor. Remount replays an interrupted capture and keeps the file's
    /// visible mode while the new anchor is frozen. This does not publish a
    /// signed owner revision or release any historical anchor.
    pub fn capture_stopped_file(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
        relative_path: impl AsRef<Path>,
    ) -> anyhow::Result<FileAnchorManifest> {
        let relative_path = relative_path.as_ref().to_path_buf();
        Self::with_stopped_view(anchor_id, control, |view, claim, _| {
            view.capture_stopped_file(&claim.lower_root, &relative_path)
        })
    }

    /// Reserve one exact visible file before creating its Git-stage anchor.
    /// An unpublished attempt blocks remount and is completed by startup
    /// recovery. A published attempt is immutable even after later edits.
    pub fn prepare_stopped_file_capture(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
        relative_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        ensure!(!attempt_id.is_nil(), "guarded file attempt ID is nil");
        let path = relative_path.as_ref().as_os_str().as_bytes().to_vec();
        {
            let store = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            if let Some(bytes) =
                store.get_record(STOPPED_FILE_CAPTURE_KIND, attempt_id.as_bytes())?
            {
                ensure!(
                    bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                    "guarded file attempt exceeds its local bound"
                );
                let intent: StoppedFileCaptureIntent = mb_core::decode_canonical(&bytes)?;
                intent.validate(attempt_id.as_bytes())?;
                ensure!(
                    intent.root_anchor_id == anchor_id && intent.entry.path == path,
                    "guarded file attempt belongs to another source"
                );
                return Ok(());
            }
        }
        let control_for_prepare = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, _, _| {
            let metadata = view.verified_metadata_snapshot(anchor_id)?;
            let entry = metadata
                .entries
                .into_iter()
                .find(|entry| entry.path == path && entry.kind == GuardedViewEntryKind::File)
                .context("guarded file attempt path is not a visible regular file")?;
            let intent = StoppedFileCaptureIntent {
                format_version: 1,
                attempt_id,
                root_anchor_id: anchor_id,
                entry,
                published: None,
            };
            intent.validate(attempt_id.as_bytes())?;
            let encoded = mb_core::canonical_bytes(&intent)?;
            ensure!(
                encoded.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded file attempt exceeds its local bound"
            );
            let store = control_for_prepare
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            ensure!(
                pending_stopped_capture_attempts(&store, anchor_id)?.is_empty()
                    && pending_stopped_file_capture_attempts(&store, anchor_id)?.is_empty(),
                "another guarded capture attempt is still prepared"
            );
            ensure!(store.put_record_if_absent(
                STOPPED_FILE_CAPTURE_KIND,
                attempt_id.as_bytes(),
                &encoded,
            )?);
            Ok(())
        })
    }

    /// Finish a prepared file while its view is stopped. A retry after
    /// publication verifies and returns the original immutable anchor.
    pub fn finish_stopped_file_capture(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<FileAnchorManifest> {
        let (encoded, intent) = {
            let store = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let encoded = store
                .get_record(STOPPED_FILE_CAPTURE_KIND, attempt_id.as_bytes())?
                .context("guarded file attempt was not prepared")?;
            ensure!(
                encoded.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded file attempt exceeds its local bound"
            );
            let intent: StoppedFileCaptureIntent = mb_core::decode_canonical(&encoded)?;
            intent.validate(attempt_id.as_bytes())?;
            ensure!(
                intent.root_anchor_id == anchor_id,
                "guarded file attempt belongs to another root"
            );
            if let Some(manifest) = intent.published.as_ref() {
                verify_published_file_capture_binding(&store, &intent, manifest)?;
                return Ok(manifest.clone());
            }
            (encoded, intent)
        };
        let control_for_finish = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, claim, _| {
            let metadata = view.verified_metadata_snapshot(anchor_id)?;
            ensure!(
                metadata.entries.iter().any(|entry| entry == &intent.entry),
                "guarded file changed after its stage attempt was prepared"
            );
            let path = PathBuf::from(OsString::from_vec(intent.entry.path.clone()));
            let original_file = {
                let store = control_for_finish
                    .lock()
                    .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                let original = GuardedRootCapturePlan::load_published_manifest(&store, anchor_id)?;
                let root_plan = GuardedRootCapturePlan::load_active_for_view(&store, &original)?;
                let captured = original.entries.iter().find_map(|entry| match entry {
                    CapturedEntry::FileV2 {
                        path,
                        native_id,
                        logical_len,
                        ..
                    } if *native_id == intent.entry.native_id => Some((path, *logical_len)),
                    _ => None,
                });
                if let Some((captured_path, captured_len)) = captured {
                    if root_plan.file_has_editable_inode(&store, captured_path)? {
                        None
                    } else {
                        let proof = root_plan.captured_file_content_proof(&store, captured_path)?;
                        ensure!(
                            captured_len == intent.entry.logical_len
                                && proof.logical_len == intent.entry.logical_len,
                            "original guarded file length changed before Git stage"
                        );
                        Some(FileAnchorManifest::from_guarded_root_file(
                            attempt_id,
                            &original,
                            &claim.lower_root,
                            &path,
                            captured_path,
                            intent.entry.native_id,
                            &proof,
                        )?)
                    }
                } else {
                    None
                }
            };
            let manifest = if let Some(manifest) = original_file {
                manifest
            } else {
                view.capture_stopped_file(&claim.lower_root, &path)?
            };
            let mut published = intent;
            published.published = Some(manifest.clone());
            published.validate(attempt_id.as_bytes())?;
            let published_bytes = mb_core::canonical_bytes(&published)?;
            ensure!(
                published_bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "published guarded file attempt exceeds its local bound"
            );
            let store = control_for_finish
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            store.replace_record_if_value(
                STOPPED_FILE_CAPTURE_KIND,
                attempt_id.as_bytes(),
                &encoded,
                &published_bytes,
            )?;
            Ok(manifest)
        })
    }

    /// Caller must first prove a Git catalog pin has taken over, or that the
    /// attempt is abandoned and no Git catalog references its anchor.
    pub fn release_stopped_file_capture_unreferenced(
        attempt_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<()> {
        let bytes = control
            .get_record(STOPPED_FILE_CAPTURE_KIND, attempt_id.as_bytes())?
            .context("guarded file attempt has no durable record")?;
        ensure!(
            bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
            "guarded file attempt exceeds its local bound"
        );
        let intent: StoppedFileCaptureIntent = mb_core::decode_canonical(&bytes)?;
        intent.validate(attempt_id.as_bytes())?;
        ensure!(
            intent.published.is_some(),
            "prepared guarded file attempt must finish before release"
        );
        let manifest = intent.published.as_ref().expect("checked published file");
        verify_published_file_capture_binding(control, &intent, manifest)?;
        control.delete_record_if_value(STOPPED_FILE_CAPTURE_KIND, attempt_id.as_bytes(), &bytes)?;
        Ok(())
    }

    /// Atomically replace a stopped-file attempt with node-owned Git pins.
    /// The caller publishes the returned exact manifest into the separate Git
    /// catalog only after this transaction commits. A crash on either side
    /// leaves at least the attempt or these pins durably protecting the bytes.
    pub fn transfer_stopped_file_capture_to_git(
        attempt_id: Uuid,
        repository_id: Uuid,
        worktree_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<FileAnchorManifest> {
        ensure!(!repository_id.is_nil(), "guarded Git repository ID is nil");
        ensure!(!worktree_id.is_nil(), "guarded Git worktree ID is nil");
        let attempt_bytes = control
            .get_record(STOPPED_FILE_CAPTURE_KIND, attempt_id.as_bytes())?
            .context("guarded Git file attempt is unavailable")?;
        ensure!(
            attempt_bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
            "guarded Git file attempt exceeds its local bound"
        );
        let attempt: StoppedFileCaptureIntent = mb_core::decode_canonical(&attempt_bytes)?;
        attempt.validate(attempt_id.as_bytes())?;
        let manifest = attempt
            .published
            .as_ref()
            .context("guarded Git file attempt is not published")?;
        ensure!(
            valid_git_stage_path(&attempt.entry.path),
            "guarded Git stage path is unsupported"
        );
        verify_published_file_capture_binding(control, &attempt, manifest)?;
        let file_pin = GuardedGitAnchorPin {
            format_version: 2,
            repository_id,
            root_anchor_id: attempt.root_anchor_id,
            manifest: manifest.clone(),
            stage: Some(GuardedGitStageContext {
                attempt_id,
                worktree_id,
                relative_path: attempt.entry.path.clone(),
                git_mode: if attempt.entry.mode & 0o111 != 0 {
                    0o100755
                } else {
                    0o100644
                },
            }),
        };
        let root_pin = GuardedGitRootPin {
            format_version: 1,
            repository_id,
            root_anchor_id: attempt.root_anchor_id,
        };
        if let Some((_, existing)) = git_anchor_pin(control, manifest.anchor_id)? {
            ensure!(existing == file_pin, "guarded Git anchor has another owner");
        }
        if let Some((_, existing)) = git_root_pin(control, attempt.root_anchor_id)? {
            ensure!(existing == root_pin, "guarded Git root has another owner");
        }
        control.put_records_and_retire_if_value(
            &[
                (
                    GIT_ANCHOR_PIN_KIND.to_owned(),
                    manifest.anchor_id.as_bytes().to_vec(),
                    mb_core::canonical_bytes(&file_pin)?,
                ),
                (
                    GIT_ROOT_PIN_KIND.to_owned(),
                    attempt.root_anchor_id.as_bytes().to_vec(),
                    mb_core::canonical_bytes(&root_pin)?,
                ),
            ],
            STOPPED_FILE_CAPTURE_KIND,
            attempt_id.as_bytes(),
            &attempt_bytes,
        )?;
        Ok(manifest.clone())
    }

    /// Enumerate durable file pins for one repository. The node compares each
    /// pin with the Git catalog before deciding whether to replay publication
    /// or retire an unreferenced anchor. Legacy pins without stage context
    /// require trusted recovery rather than guessing the index path or mode.
    pub fn git_stage_pins(
        repository_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<Vec<GuardedGitStagePin>> {
        ensure!(!repository_id.is_nil(), "guarded Git repository ID is nil");
        Ok(Self::all_git_stage_pins(control)?
            .into_iter()
            .filter(|pin| pin.repository_id == repository_id)
            .collect())
    }

    /// Discover all node-owned guarded Git anchors before reconciling the
    /// separate repository catalogs. A malformed or legacy pin fails closed;
    /// payload verification belongs to catalog publication and object reads.
    pub fn all_git_stage_pins(control: &ControlStore) -> anyhow::Result<Vec<GuardedGitStagePin>> {
        let mut pins = Vec::new();
        let mut attempts = BTreeSet::new();
        for (id, _) in control.records(GIT_ANCHOR_PIN_KIND)? {
            let anchor_id = Uuid::from_slice(&id)?;
            let (_, pin) = git_anchor_pin(control, anchor_id)?
                .context("guarded Git anchor pin vanished during listing")?;
            let (_, root) = git_root_pin(control, pin.root_anchor_id)?
                .context("guarded Git stage pin lost its root pin")?;
            ensure!(
                root.repository_id == pin.repository_id,
                "guarded Git stage pin has another root owner"
            );
            let stage = pin
                .stage
                .context("legacy guarded Git pin lacks stage context")?;
            ensure!(
                attempts.insert((pin.repository_id, stage.attempt_id)),
                "guarded Git stage attempt has duplicate anchor pins"
            );
            pins.push(GuardedGitStagePin {
                repository_id: pin.repository_id,
                root_anchor_id: pin.root_anchor_id,
                manifest: pin.manifest,
                attempt_id: stage.attempt_id,
                worktree_id: stage.worktree_id,
                relative_path: stage.relative_path,
                git_mode: stage.git_mode,
            });
        }
        pins.sort_by_key(|pin| pin.manifest.anchor_id);
        Ok(pins)
    }

    /// Pin a recovered root file before the Git catalog replaces its imported
    /// blob mapping. Replay can finish the catalog transition from this exact
    /// record if the process stops between the two database writes.
    pub fn pin_recovered_git_blob(
        control: &ControlStore,
        pin: &GuardedGitRecoveryPin,
    ) -> anyhow::Result<()> {
        let root_anchor_id = pin.root_anchor_id()?;
        let encoded = mb_core::canonical_bytes(pin)?;
        if let Some(existing) =
            control.get_record(GIT_RECOVERY_PIN_KIND, pin.imported.anchor_id.as_bytes())?
        {
            ensure!(
                existing == encoded,
                "recovered Git anchor has another owner"
            );
            ensure!(
                Self::all_git_recovery_pins(control)?.contains(pin),
                "recovered Git anchor lost its root pin"
            );
            return Ok(());
        }
        let backing = pin
            .root_file
            .guarded_root_file
            .as_ref()
            .expect("validated backing");
        let verified = GuardedRootCapturePlan::verified_git_file_manifest(
            control,
            root_anchor_id,
            pin.imported.anchor_id,
            &backing.captured_relative_path,
        )?;
        ensure!(
            verified == pin.root_file
                && pin.imported.open_verified()?.metadata()?.len() == pin.imported.logical_len
                && git_anchor_pin(control, pin.imported.anchor_id)?.is_none(),
            "recovered Git pin differs from its imported or root file"
        );
        let root_pin = GuardedGitRootPin {
            format_version: 1,
            repository_id: pin.repository_id,
            root_anchor_id,
        };
        if let Some((_, existing)) = git_root_pin(control, root_anchor_id)? {
            ensure!(existing == root_pin, "recovered Git root has another owner");
        }
        control.put_records_and_delete(
            &[
                (
                    GIT_RECOVERY_PIN_KIND.to_owned(),
                    pin.imported.anchor_id.as_bytes().to_vec(),
                    encoded,
                ),
                (
                    GIT_ROOT_PIN_KIND.to_owned(),
                    root_anchor_id.as_bytes().to_vec(),
                    mb_core::canonical_bytes(&root_pin)?,
                ),
            ],
            &[],
        )?;
        Ok(())
    }

    pub fn all_git_recovery_pins(
        control: &ControlStore,
    ) -> anyhow::Result<Vec<GuardedGitRecoveryPin>> {
        let mut pins = Vec::new();
        for (id, bytes) in control.records(GIT_RECOVERY_PIN_KIND)? {
            let pin: GuardedGitRecoveryPin = mb_core::decode_canonical(&bytes)?;
            let root_anchor_id = pin.root_anchor_id()?;
            ensure!(
                id == pin.imported.anchor_id.as_bytes()
                    && mb_core::canonical_bytes(&pin)? == bytes
                    && git_anchor_pin(control, pin.imported.anchor_id)?.is_none()
                    && git_root_pin(control, root_anchor_id)?
                        .is_some_and(|(_, root)| root.repository_id == pin.repository_id),
                "recovered Git pin lost its root ownership"
            );
            pins.push(pin);
        }
        pins.sort_by_key(|pin| pin.imported.anchor_id);
        Ok(pins)
    }

    /// Retire a recovered virtual mapping after the node-fenced catalog batch
    /// has removed its object map and recovery receipt. Keep the root pin while
    /// any other staged or recovered Git mapping still needs that root.
    pub fn retire_git_recovery_pin_with_prune_progress(
        repository_id: Uuid,
        anchor_id: Uuid,
        control: &ControlStore,
        marker_kind: &str,
        marker_value: &[u8],
    ) -> anyhow::Result<()> {
        ensure!(
            !marker_kind.is_empty()
                && !marker_value.is_empty()
                && control
                    .get_record(marker_kind, anchor_id.as_bytes())?
                    .is_none(),
            "recovered Git prune progress already exists"
        );
        let bytes = control
            .get_record(GIT_RECOVERY_PIN_KIND, anchor_id.as_bytes())?
            .context("recovered Git anchor has no node-owned pin")?;
        let pin: GuardedGitRecoveryPin = mb_core::decode_canonical(&bytes)?;
        let root_anchor_id = pin.root_anchor_id()?;
        ensure!(
            pin.repository_id == repository_id
                && pin.imported.anchor_id == anchor_id
                && mb_core::canonical_bytes(&pin)? == bytes
                && git_root_pin(control, root_anchor_id)?
                    .is_some_and(|(_, root)| root.repository_id == repository_id),
            "recovered Git prune pin differs from its root owner"
        );
        let other_recovery = Self::all_git_recovery_pins(control)?.iter().any(|other| {
            other.imported.anchor_id != anchor_id
                && other.root_anchor_id().ok() == Some(root_anchor_id)
        });
        let other_stage = Self::all_git_stage_pins(control)?
            .iter()
            .any(|other| other.root_anchor_id == root_anchor_id);
        let deletions = if other_recovery || other_stage {
            Vec::new()
        } else {
            vec![(
                GIT_ROOT_PIN_KIND.to_owned(),
                root_anchor_id.as_bytes().to_vec(),
            )]
        };
        control.put_records_and_retire_and_delete_if_value(
            &[(
                marker_kind.to_owned(),
                anchor_id.as_bytes().to_vec(),
                marker_value.to_vec(),
            )],
            &deletions,
            GIT_RECOVERY_PIN_KIND,
            anchor_id.as_bytes(),
            &bytes,
        )?;
        Ok(())
    }

    /// Retire a node-owned Git pin only after the caller proves that the Git
    /// catalog no longer maps this anchor and no signed revision or recipe
    /// needs it. The root pin leaves with the last file pin for that root.
    pub fn retire_git_anchor_pin_unreferenced(
        repository_id: Uuid,
        anchor_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<()> {
        Self::retire_git_anchor_pin_with_progress(repository_id, anchor_id, control, None)
    }

    /// Atomically retire a Git pin and publish the node's prune progress
    /// marker. A restart can then distinguish this removal from a lost pin.
    pub fn retire_git_anchor_pin_with_prune_progress(
        repository_id: Uuid,
        anchor_id: Uuid,
        control: &ControlStore,
        marker_kind: &str,
        marker_value: &[u8],
    ) -> anyhow::Result<()> {
        ensure!(
            !marker_kind.is_empty()
                && !marker_value.is_empty()
                && control
                    .get_record(marker_kind, anchor_id.as_bytes())?
                    .is_none(),
            "guarded Git prune progress already exists"
        );
        Self::retire_git_anchor_pin_with_progress(
            repository_id,
            anchor_id,
            control,
            Some((marker_kind, marker_value)),
        )
    }

    fn retire_git_anchor_pin_with_progress(
        repository_id: Uuid,
        anchor_id: Uuid,
        control: &ControlStore,
        progress: Option<(&str, &[u8])>,
    ) -> anyhow::Result<()> {
        let (bytes, pin) = git_anchor_pin(control, anchor_id)?
            .context("guarded Git anchor has no node-owned pin")?;
        ensure!(
            pin.repository_id == repository_id,
            "guarded Git anchor belongs to another repository"
        );
        let (_, root_pin) = git_root_pin(control, pin.root_anchor_id)?
            .context("guarded Git anchor lost its root pin")?;
        ensure!(
            root_pin.repository_id == repository_id,
            "guarded Git root belongs to another repository"
        );
        let mut other_files = false;
        for (id, _) in control.records(GIT_ANCHOR_PIN_KIND)? {
            let other_id = Uuid::from_slice(&id)?;
            if other_id != anchor_id {
                let (_, other) = git_anchor_pin(control, other_id)?
                    .context("guarded Git anchor pin vanished during retirement")?;
                if other.root_anchor_id == pin.root_anchor_id {
                    ensure!(
                        other.repository_id == repository_id,
                        "guarded Git root has conflicting anchor owners"
                    );
                    other_files = true;
                }
            }
        }
        other_files |= Self::all_git_recovery_pins(control)?
            .iter()
            .any(|other| other.root_anchor_id().ok() == Some(pin.root_anchor_id));
        let deletions = if other_files {
            Vec::new()
        } else {
            vec![(
                GIT_ROOT_PIN_KIND.to_owned(),
                pin.root_anchor_id.as_bytes().to_vec(),
            )]
        };
        let records = progress
            .into_iter()
            .map(|(kind, value)| {
                (
                    kind.to_owned(),
                    anchor_id.as_bytes().to_vec(),
                    value.to_vec(),
                )
            })
            .collect::<Vec<_>>();
        control.put_records_and_retire_and_delete_if_value(
            &records,
            &deletions,
            GIT_ANCHOR_PIN_KIND,
            anchor_id.as_bytes(),
            &bytes,
        )?;
        Ok(())
    }

    /// Freeze every visible file under one stopped-mount fence. An unchanged
    /// file may reuse its original root anchor; an edited or newly created
    /// file gets a durable per-inode guard before this method returns.
    pub fn capture_stopped_view(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        let control_for_capture = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, claim, original| {
            Self::capture_stopped_view_inside(view, claim, original, &control_for_capture, None)
        })
    }

    /// Reserve a stopped view's exact visible metadata for a revision attempt.
    /// Remount refuses a prepared attempt until `finish_stopped_capture` has
    /// durably frozen every file, including after a process crash.
    pub fn prepare_stopped_capture(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedViewMetadataV1> {
        ensure!(!attempt_id.is_nil(), "guarded capture attempt ID is nil");
        // A completed attempt is immutable. Revision retries may arrive after
        // the view has remounted and changed, so do not inspect today's view
        // before returning the metadata reserved by that attempt.
        {
            let store = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            if let Some(bytes) = store.get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())? {
                ensure!(
                    bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                    "guarded stopped-capture intent exceeds its local bound"
                );
                let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
                intent.validate(attempt_id.as_bytes())?;
                ensure!(
                    intent.root_anchor_id == anchor_id,
                    "guarded capture attempt belongs to another root"
                );
                if let Some(capture) = intent.published {
                    capture.verify()?;
                    return Ok(intent.metadata);
                }
            }
        }
        let control_for_prepare = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, _, _| {
            let metadata = view.verified_metadata_snapshot(anchor_id)?;
            metadata.validate_shape()?;
            let store = control_for_prepare
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            if let Some(bytes) = store.get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())? {
                ensure!(
                    bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                    "guarded stopped-capture intent exceeds its local bound"
                );
                let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
                intent.validate(attempt_id.as_bytes())?;
                ensure!(
                    intent.root_anchor_id == anchor_id && intent.metadata == metadata,
                    "guarded capture attempt changed its visible metadata"
                );
                return Ok(metadata);
            }
            ensure!(
                pending_stopped_capture_attempts(&store, anchor_id)?.is_empty()
                    && pending_stopped_file_capture_attempts(&store, anchor_id)?.is_empty(),
                "another guarded capture attempt is still prepared"
            );
            let intent = StoppedCaptureIntent {
                format_version: 1,
                attempt_id,
                root_anchor_id: anchor_id,
                metadata: metadata.clone(),
                published: None,
            };
            let bytes = mb_core::canonical_bytes(&intent)?;
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded capture intent exceeds its catalog bound"
            );
            ensure!(store.put_record_if_absent(
                STOPPED_CAPTURE_KIND,
                attempt_id.as_bytes(),
                &bytes,
            )?);
            Ok(metadata)
        })
    }

    /// Complete a prepared attempt under the same stopped-view fence. A
    /// published retry reads only immutable anchors, so later view edits do
    /// not change the attempt's bytes.
    pub fn finish_stopped_capture(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        let prepared_bytes = {
            let store = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let bytes = store
                .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
                .context("guarded capture attempt was not prepared")?;
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded stopped-capture intent exceeds its local bound"
            );
            let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
            intent.validate(attempt_id.as_bytes())?;
            ensure!(
                intent.root_anchor_id == anchor_id,
                "guarded capture attempt belongs to another root"
            );
            if let Some(capture) = intent.published {
                capture.verify()?;
                return Ok(capture);
            }
            bytes
        };
        let control_for_capture = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, claim, original| {
            let intent: StoppedCaptureIntent = mb_core::decode_canonical(&prepared_bytes)?;
            let capture = Self::capture_stopped_view_inside(
                view,
                claim,
                original,
                &control_for_capture,
                Some(&intent.metadata),
            )?;
            let mut published = intent;
            published.published = Some(capture.clone());
            let published_bytes = mb_core::canonical_bytes(&published)?;
            ensure!(
                published_bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "published guarded capture exceeds its local bound"
            );
            let store = control_for_capture
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            store.replace_record_if_value(
                STOPPED_CAPTURE_KIND,
                attempt_id.as_bytes(),
                &prepared_bytes,
                &published_bytes,
            )?;
            Ok(capture)
        })
    }

    /// Return the exact published intent bytes for a database transaction
    /// that transfers its pins to a signed revision capture record.
    pub fn published_stopped_capture_attempt(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<(Vec<u8>, GuardedStoppedCaptureV1)> {
        let bytes = control
            .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
            .context("guarded capture attempt is unavailable")?;
        ensure!(
            bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
            "guarded stopped-capture intent exceeds its local bound"
        );
        let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
        intent.validate(attempt_id.as_bytes())?;
        ensure!(
            intent.root_anchor_id == anchor_id,
            "guarded capture attempt belongs to another root"
        );
        let capture = intent
            .published
            .context("guarded capture attempt is not yet published")?;
        capture.verify()?;
        Ok((bytes, capture))
    }

    pub fn capture_stopped_view_for_attempt(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        if control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
            .is_none()
        {
            Self::prepare_stopped_capture(anchor_id, attempt_id, Arc::clone(&control))?;
        }
        Self::finish_stopped_capture(anchor_id, attempt_id, control)
    }

    /// The revision owner calls this only after its signed revision has taken
    /// over every anchor pin, or after proving the attempt is unreferenced.
    pub fn release_stopped_capture_unreferenced(
        attempt_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<()> {
        let bytes = control
            .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
            .context("guarded stopped capture has no durable intent")?;
        ensure!(
            bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
            "guarded stopped-capture intent exceeds its local bound"
        );
        let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
        intent.validate(attempt_id.as_bytes())?;
        ensure!(
            intent.published.is_some(),
            "prepared guarded capture must finish before release"
        );
        control.delete_record_if_value(STOPPED_CAPTURE_KIND, attempt_id.as_bytes(), &bytes)?;
        Ok(())
    }

    fn capture_stopped_view_inside(
        view: &GuardedProbeView,
        claim: &MountClaim,
        original: &StableAnchorManifest,
        control_for_capture: &Arc<Mutex<ControlStore>>,
        expected_metadata: Option<&GuardedViewMetadataV1>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        let before = view.verified_metadata_snapshot(original.anchor_id)?;
        ensure!(
            expected_metadata.is_none_or(|expected| expected == &before),
            "guarded stopped capture metadata changed before replay"
        );
        let root_plan = {
            let store = control_for_capture
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            GuardedRootCapturePlan::load_active_for_view(&store, original)?
        };
        let mut original_files = BTreeMap::new();
        for entry in &original.entries {
            if let CapturedEntry::FileV2 {
                path,
                logical_len,
                native_id,
                ..
            } = entry
            {
                ensure!(
                    original_files
                        .insert(*native_id, (path, *logical_len))
                        .is_none(),
                    "guarded root has duplicate captured file identity"
                );
            }
        }
        let mut files = Vec::new();
        for entry in before
            .entries
            .iter()
            .filter(|entry| entry.kind == GuardedViewEntryKind::File)
        {
            let path = PathBuf::from(OsString::from_vec(entry.path.clone()));
            let reusable_original =
                if let Some((captured_path, captured_len)) = original_files.get(&entry.native_id) {
                    let proof = {
                        let store = control_for_capture
                            .lock()
                            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                        if root_plan.file_has_editable_inode(&store, captured_path)? {
                            None
                        } else {
                            Some(root_plan.captured_file_content_proof(&store, captured_path)?)
                        }
                    };
                    if let Some(proof) = proof {
                        ensure!(
                            *captured_len == entry.logical_len
                                && proof.logical_len == entry.logical_len,
                            "unchanged guarded file has another length"
                        );
                        Some((original.file_locator_path(captured_path)?, proof))
                    } else {
                        None
                    }
                } else {
                    None
                };
            let (locator, expected_hash, expected_extents) =
                if let Some((locator, proof)) = reusable_original {
                    (locator, proof.content_hash, Some(proof.data_extents))
                } else {
                    let manifest =
                        view.capture_stopped_file_after_full_check(&claim.lower_root, &path)?;
                    ensure!(
                        manifest.logical_len == entry.logical_len,
                        "recaptured guarded file has another length"
                    );
                    (manifest.file_locator(), manifest.content_hash, None)
                };
            let mut file = locator.open()?;
            ensure!(
                file.metadata()?.len() == entry.logical_len,
                "guarded anchor length changed during stopped capture"
            );
            let mut hasher = blake3::Hasher::new();
            let mut read_len = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                read_len += read as u64;
            }
            ensure!(
                read_len == entry.logical_len,
                "guarded anchor length changed while reading"
            );
            let content_hash = *hasher.finalize().as_bytes();
            ensure!(
                expected_hash == content_hash,
                "guarded anchor bytes differ from their capture proof"
            );
            let data_extents = crate::anchor::file_data_extents(&file, entry.logical_len)?;
            ensure!(
                expected_extents.is_none_or(|expected| expected == data_extents),
                "guarded anchor extents differ from their capture proof"
            );
            files.push(GuardedStoppedFileV1 {
                path: entry.path.clone(),
                native_id: entry.native_id,
                locator,
                logical_len: entry.logical_len,
                content_hash,
                data_extents,
            });
        }
        let after = view.verified_metadata_snapshot(original.anchor_id)?;
        ensure!(
            after == before,
            "guarded metadata changed while capturing its files"
        );
        let capture = GuardedStoppedCaptureV1 {
            format_version: 1,
            metadata: before,
            files,
        };
        capture.metadata.validate_shape()?;
        ensure!(
            mb_core::canonical_bytes(&capture)?.len() <= mb_core::V1_MAX_CATALOG_BYTES,
            "guarded stopped capture exceeds its catalog bound"
        );
        Ok(capture)
    }

    fn with_stopped_view<T>(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
        operation: impl FnOnce(
            &GuardedProbeView,
            &MountClaim,
            &StableAnchorManifest,
        ) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let _lifecycle = MOUNT_LIFECYCLE
            .lock()
            .map_err(|_| io::Error::other("guarded mount lifecycle lock is poisoned"))?;
        let (claim_bytes, claim, manifest, plan) = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let bytes = control
                .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
                .context("guarded view has no mount claim")?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount claim changed"
            );
            ensure!(
                control
                    .get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
                    .is_none(),
                "guarded mount has been retired"
            );
            let manifest = GuardedRootCapturePlan::load_published_manifest(&control, anchor_id)?;
            let plan = GuardedRootCapturePlan::load_active_for_view(&control, &manifest)?;
            ensure!(
                claim.lower_root == plan.source_root()
                    && claim.lower_id == plan.source_root_identity(),
                "guarded mount claim differs from its source plan"
            );
            (bytes, claim, manifest, plan)
        };
        if let Some(mounted) = mounted_filesystem(&claim.mountpoint)? {
            ensure!(
                mounted.matches_guarded(&mount_source(anchor_id)),
                "another filesystem occupies the guarded mountpoint"
            );
            match fs::metadata(&claim.mountpoint) {
                Ok(_) => anyhow::bail!("guarded view must stop before inspecting its source"),
                Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => {
                    let path = CString::new(claim.mountpoint.as_os_str().as_bytes())?;
                    if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } < 0 {
                        return Err(io::Error::last_os_error())
                            .context("detach dead guarded mount before stopped capture");
                    }
                }
                Err(error) => return Err(error).context("check claimed guarded mount"),
            }
        }
        let lower = PinnedDirectory::open(&claim.lower_root)?;
        let placeholder = PinnedDirectory::open(&claim.mountpoint)?;
        ensure!(
            lower.identity()? == claim.lower_id && placeholder.identity()? == claim.mountpoint_id,
            "guarded mount paths changed before inspecting its source"
        );
        let mut view = GuardedProbeView::from_guarded_capture(
            &manifest,
            Arc::clone(&control),
            claim.view_uid,
            claim.view_gid,
        )?;
        let virtual_view = {
            let store = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            if let Some(bytes) = store.get_record(VIRTUAL_METADATA_KIND, anchor_id.as_bytes())? {
                ensure!(
                    bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                    "guarded virtual metadata exceeds its local bound"
                );
                let metadata: GuardedViewMetadataV1 = mb_core::decode_canonical(&bytes)?;
                validate_virtual_metadata_binding(&metadata, &manifest, &plan)?;
                let baseline = store
                    .get_record(VIRTUAL_TIME_BASELINE_KIND, anchor_id.as_bytes())?
                    .map(|bytes| {
                        ensure!(
                            bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                            "guarded virtual time baseline exceeds its local bound"
                        );
                        Ok(mb_core::decode_canonical::<GuardedViewTimeBaselineV1>(
                            &bytes,
                        )?)
                    })
                    .transpose()?;
                let max_inode = u64::try_from(manifest.entries.len())?
                    .checked_add(2)
                    .context("guarded virtual inode overflow")?;
                let dirty_times = virtual_time_dirty_masks(&store, anchor_id, max_inode)?;
                let dirty_sizes = virtual_directory_size_dirty_ids(&store, anchor_id, max_inode)?;
                Some((metadata, baseline, dirty_times, dirty_sizes))
            } else {
                None
            }
        };
        if let Some((metadata, baseline, dirty_times, dirty_sizes)) = virtual_view {
            view.apply_virtual_metadata(
                &metadata,
                baseline.as_ref(),
                &dirty_times,
                &dirty_sizes,
                false,
            )?;
        }
        let value = operation(&view, &claim, &manifest)?;
        let control = control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
        ensure!(
            control.get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())? == Some(claim_bytes)
                && control
                    .get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
                    .is_none()
                && mounted_filesystem(&claim.mountpoint)?.is_none(),
            "guarded mount claim changed during stopped-view operation"
        );
        Ok(value)
    }

    pub fn stop(mut self) -> io::Result<()> {
        let lifecycle = MOUNT_LIFECYCLE
            .lock()
            .map_err(|_| io::Error::other("guarded mount lifecycle lock is poisoned"))?;
        let session = self
            .session
            .take()
            .ok_or_else(|| io::Error::other("guarded FUSE worker is already stopped"))?;
        let result = session.umount_and_join();
        drop(lifecycle);
        result
    }
}

impl Drop for GuardedViewMount {
    fn drop(&mut self) {
        if self.session.is_none() {
            return;
        }
        let _lifecycle = MOUNT_LIFECYCLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Join the worker as well as unmounting, so a later snapshot cannot
        // observe a lower-tree mutation from an in-flight FUSE request.
        let _ = self.session.take().unwrap().umount_and_join();
    }
}

pub(crate) fn require_mount_claim_retired(
    control: &ControlStore,
    anchor_id: Uuid,
) -> anyhow::Result<()> {
    ensure!(
        control
            .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
            .is_none(),
        "guarded mount claim must be retired before its anchors"
    );
    if let Some(bytes) = control.get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())? {
        let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
        ensure!(
            claim.version == 1 && claim.anchor_id == anchor_id,
            "guarded mount retirement marker changed"
        );
        ensure!(
            mounted_filesystem(&claim.mountpoint)?.is_none(),
            "guarded view remains mounted during anchor retirement"
        );
    }
    Ok(())
}

/// Bind a reverse name handoff to the exact claim that previously owned the
/// private lower and visible placeholder. The retirement marker survives
/// claim deletion, so replay remains verifiable after the lower name moves.
pub(crate) fn require_retired_claim_for_release(
    control: &ControlStore,
    anchor_id: Uuid,
    lower_root: &Path,
    lower_id: NativeFileId,
    mountpoint: &Path,
    mountpoint_id: NativeFileId,
) -> anyhow::Result<()> {
    require_mount_claim_retired(control, anchor_id)?;
    let bytes = control
        .get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("guarded release has no retired mount claim"))?;
    let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
    ensure!(
        claim.version == 1
            && claim.anchor_id == anchor_id
            && claim.lower_root == lower_root
            && claim.lower_id == lower_id
            && claim.mountpoint == mountpoint
            && claim.mountpoint_id == mountpoint_id,
        "guarded release differs from its retired mount claim"
    );
    Ok(())
}

pub(crate) fn require_active_claim_for_release(
    control: &ControlStore,
    anchor_id: Uuid,
    lower_root: &Path,
    lower_id: NativeFileId,
    mountpoint: &Path,
    mountpoint_id: NativeFileId,
) -> anyhow::Result<()> {
    ensure!(
        control
            .get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
            .is_none(),
        "guarded release mount is already retired"
    );
    let bytes = control
        .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
        .ok_or_else(|| anyhow::anyhow!("guarded release has no active mount claim"))?;
    let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
    ensure!(
        claim.version == 1
            && claim.anchor_id == anchor_id
            && claim.lower_root == lower_root
            && claim.lower_id == lower_id
            && claim.mountpoint == mountpoint
            && claim.mountpoint_id == mountpoint_id,
        "guarded release differs from its active mount claim"
    );
    Ok(())
}

pub(crate) fn mount_claim_exists(control: &ControlStore, anchor_id: Uuid) -> anyhow::Result<bool> {
    Ok(control
        .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
        .is_some())
}

fn mount_source(anchor_id: Uuid) -> String {
    format!("mutualbackup-guarded-{anchor_id}")
}

impl MountedFilesystem {
    fn matches_guarded(&self, source: &str) -> bool {
        // The pure FUSE mount path reports `fuse` even when a subtype was
        // requested; fusermount may report `fuse.<subtype>` instead.
        (self.filesystem_type == "fuse" || self.filesystem_type == format!("fuse.{MOUNT_SUBTYPE}"))
            && self.source == source
    }
}

fn canonical_mountpoint(path: &Path) -> anyhow::Result<PathBuf> {
    let name = path.file_name().context("guarded mountpoint has no name")?;
    ensure!(
        path.components().next_back() == Some(Component::Normal(name)),
        "guarded mountpoint must name a directory"
    );
    Ok(path
        .parent()
        .context("guarded mountpoint has no parent")?
        .canonicalize()?
        .join(name))
}

fn mounted_filesystem(mountpoint: &Path) -> anyhow::Result<Option<MountedFilesystem>> {
    mounted_filesystem_from_bytes(mountpoint, &fs::read("/proc/self/mountinfo")?)
}

fn mounted_filesystem_from_bytes(
    mountpoint: &Path,
    mountinfo: &[u8],
) -> anyhow::Result<Option<MountedFilesystem>> {
    let mut found = None;
    for line in mountinfo
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let separator = line
            .windows(3)
            .position(|bytes| bytes == b" - ")
            .context("invalid Linux mountinfo separator")?;
        let front = &line[..separator];
        let back = &line[separator + 3..];
        let encoded_path = front
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty())
            .nth(4)
            .context("invalid Linux mountinfo mountpoint")?;
        if decode_mountinfo_path(encoded_path)? != mountpoint {
            continue;
        }
        let mut fields = back
            .split(|byte| byte.is_ascii_whitespace())
            .filter(|field| !field.is_empty());
        let filesystem_type =
            std::str::from_utf8(fields.next().context("missing mountinfo filesystem type")?)?;
        let source = std::str::from_utf8(fields.next().context("missing mountinfo source")?)?;
        ensure!(found.is_none(), "guarded mountpoint has stacked mounts");
        found = Some(MountedFilesystem {
            filesystem_type: filesystem_type.to_owned(),
            source: source.to_owned(),
        });
    }
    Ok(found)
}

fn decode_mountinfo_path(bytes: &[u8]) -> anyhow::Result<PathBuf> {
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            ensure!(index + 3 < bytes.len(), "truncated mountinfo path escape");
            let digits = &bytes[index + 1..index + 4];
            ensure!(
                digits.iter().all(|digit| (b'0'..=b'7').contains(digit)),
                "invalid mountinfo path escape"
            );
            decoded.push((digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0'));
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mb_core::{KeyMaterial, Seed};

    use crate::guarded_view_probe::GuardedProbeView;
    use crate::{ControlStore, GuardedRootCapturePlan};

    use super::{
        GuardedStoppedCaptureV1, GuardedViewMount, MOUNT_CLAIM_KIND, MOUNT_RETIRE_KIND,
        StoppedFileCaptureIntent, decode_mountinfo_path, mounted_filesystem_from_bytes,
        valid_git_stage_path,
    };

    #[test]
    fn stopped_file_attempt_keeps_raw_path_and_rejects_changed_record_shape() {
        let attempt_id = uuid::Uuid::new_v4();
        let record = StoppedFileCaptureIntent {
            format_version: 1,
            attempt_id,
            root_anchor_id: uuid::Uuid::new_v4(),
            entry: crate::guarded_view_probe::GuardedViewMetadataEntry {
                path: b"parent/raw-\xff".to_vec(),
                kind: crate::guarded_view_probe::GuardedViewEntryKind::File,
                native_id: crate::NativeFileId {
                    filesystem_id: 5,
                    inode: 9,
                },
                mode: 0o644,
                uid: 1000,
                gid: 1000,
                logical_len: 3,
                atime_secs: 1,
                atime_nanos: 2,
                modified_secs: 3,
                modified_nanos: 4,
            },
            published: None,
        };
        let bytes = mb_core::canonical_bytes(&record).unwrap();
        let decoded: StoppedFileCaptureIntent = mb_core::decode_canonical(&bytes).unwrap();
        assert_eq!(decoded, record);
        decoded.validate(attempt_id.as_bytes()).unwrap();
        assert!(decoded.validate(uuid::Uuid::new_v4().as_bytes()).is_err());
        let mut unsafe_path = decoded.clone();
        unsafe_path.entry.path = b"parent/../raw".to_vec();
        assert!(unsafe_path.validate(attempt_id.as_bytes()).is_err());
        let mut bad_time = decoded;
        bad_time.entry.atime_nanos = 1_000_000_000;
        assert!(bad_time.validate(attempt_id.as_bytes()).is_err());
        assert!(valid_git_stage_path(b"parent/raw-\xff"));
        assert!(!valid_git_stage_path(b".git/config"));
        assert!(!valid_git_stage_path(b".mutualbackup/catalog"));
        assert!(!valid_git_stage_path(b"parent/../raw"));
        assert!(!valid_git_stage_path(&vec![b'x'; 4097]));
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn stopped_release_detaches_renamed_live_files_before_owner_restore() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-release-detach-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let original = b"release\r\nretained\0";
        fs::write(lower.join("sample"), original).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([214; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
            .unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        fs::rename(mountpoint.join("sample"), mountpoint.join("renamed")).unwrap();
        fs::write(mountpoint.join("created"), b"new\nbytes").unwrap();
        mount.stop().unwrap();

        let anchor = manifest.file_locator("sample".to_owned()).unwrap();
        let anchor_file = anchor.open().unwrap();
        assert_eq!(
            fs::metadata(lower.join("renamed")).unwrap().ino(),
            anchor_file.metadata().unwrap().ino()
        );
        drop(anchor_file);
        GuardedViewMount::detach_stopped_files_for_release(
            manifest.anchor_id,
            Arc::clone(&control),
        )
        .unwrap();
        // Detach replay is idempotent before any mount claim or anchor is retired.
        GuardedViewMount::detach_stopped_files_for_release(
            manifest.anchor_id,
            Arc::clone(&control),
        )
        .unwrap();
        let visible =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert!(visible.entries.iter().any(|entry| entry.path == b"renamed"));
        assert!(visible.entries.iter().any(|entry| entry.path == b"created"));
        assert_ne!(
            fs::metadata(lower.join("renamed")).unwrap().ino(),
            anchor.open().unwrap().metadata().unwrap().ino()
        );
        assert_eq!(fs::read(lower.join("renamed")).unwrap(), original);
        fs::write(lower.join("renamed"), b"changed after detach").unwrap();
        let mut retained = Vec::new();
        anchor.open().unwrap().read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        GuardedViewMount::retire_claim(manifest.anchor_id, &control.lock().unwrap()).unwrap();
        plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
    }

    #[test]
    fn mountinfo_paths_decode_spaces_and_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;

        let path = decode_mountinfo_path(b"/one\\040two/odd\\377").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/one two/odd\xff");
        assert!(decode_mountinfo_path(b"/broken\\08").is_err());
        let literal = decode_mountinfo_path(b"/raw-\xfe").unwrap();
        assert_eq!(literal.as_os_str().as_bytes(), b"/raw-\xfe");
    }

    #[test]
    fn mountinfo_scan_ignores_unrelated_raw_byte_paths() {
        let mountinfo = b"1 0 0:1 / /raw-\xfe rw - btrfs /dev/loop0 rw\n\
                          2 1 0:2 / /wanted rw - fuse mutualbackup-guarded-test rw\n";
        let mounted = mounted_filesystem_from_bytes(Path::new("/wanted"), mountinfo)
            .unwrap()
            .unwrap();
        assert_eq!(mounted.filesystem_type, "fuse");
        assert_eq!(mounted.source, "mutualbackup-guarded-test");
    }

    #[test]
    fn guarded_view_metadata_requires_a_complete_raw_byte_namespace() {
        use crate::{
            GuardedViewEntryKind, GuardedViewMetadataEntry, GuardedViewMetadataV1, NativeFileId,
        };

        let root_id = NativeFileId {
            filesystem_id: 23,
            inode: 10,
        };
        let entry = |path: &[u8], kind, inode| GuardedViewMetadataEntry {
            path: path.to_vec(),
            kind,
            native_id: NativeFileId {
                filesystem_id: root_id.filesystem_id,
                inode,
            },
            mode: 0o700,
            uid: 1000,
            gid: 1000,
            logical_len: 0,
            atime_secs: 1,
            atime_nanos: 2,
            modified_secs: 3,
            modified_nanos: 4,
        };
        let valid = GuardedViewMetadataV1 {
            format_version: 1,
            anchor_id: uuid::Uuid::new_v4(),
            lower_root_id: root_id,
            root_mode: 0o700,
            root_uid: 1000,
            root_gid: 1000,
            root_atime_secs: 1,
            root_atime_nanos: 2,
            root_modified_secs: 3,
            root_modified_nanos: 4,
            entries: vec![
                entry(b"nested", GuardedViewEntryKind::Directory, 11),
                entry(b"nested/\xff", GuardedViewEntryKind::File, 12),
            ],
        };
        valid.validate_shape().unwrap();

        let mut invalid = valid.clone();
        invalid.entries.remove(0);
        assert!(invalid.validate_shape().is_err());
        let mut invalid = valid.clone();
        invalid.entries[1].path = b"nested/../escape".to_vec();
        assert!(invalid.validate_shape().is_err());
        let mut invalid = valid.clone();
        invalid.entries[1].native_id.filesystem_id += 1;
        assert!(invalid.validate_shape().is_err());
        let mut invalid = valid.clone();
        invalid.entries[1].atime_nanos = 1_000_000_000;
        assert!(invalid.validate_shape().is_err());
        let mut invalid = valid.clone();
        invalid.entries.push(invalid.entries[1].clone());
        assert!(invalid.validate_shape().is_err());
        let mut aliases = valid.clone();
        let mut alias = aliases.entries[1].clone();
        alias.path = b"nested/\xfe".to_vec();
        aliases.entries.insert(1, alias);
        aliases.validate_shape().unwrap();
        aliases.entries[1].mode = 0o600;
        assert!(aliases.validate_shape().is_err());
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and fanotify permission events"]
    fn guarded_mount_refuses_mutable_private_lower_inodes() {
        for unsafe_case in [
            "file-owner",
            "directory-owner",
            "directory-group-write",
            "directory-world-search",
            "unknown-lower-entry",
        ] {
            let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
                Some(root) => tempfile::Builder::new()
                    .prefix("mb-guarded-owner-")
                    .tempdir_in(root)
                    .unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let lower = area.path().join("lower");
            let mountpoint = area.path().join("view");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(&mountpoint).unwrap();
            fs::create_dir(lower.join("nested")).unwrap();
            fs::write(lower.join("sample"), b"frozen bytes").unwrap();
            fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
            if unsafe_case == "directory-group-write" {
                fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o775))
                    .unwrap();
            } else if unsafe_case == "directory-world-search" {
                fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o711))
                    .unwrap();
            } else if unsafe_case != "unknown-lower-entry" {
                let owned = lower.join(if unsafe_case == "file-owner" {
                    "sample"
                } else {
                    "nested"
                });
                let path = CString::new(owned.as_os_str().as_bytes()).unwrap();
                // SAFETY: this test owns the NUL-free disposable lower path.
                assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, 65534) }, 0);
            }

            let keys = KeyMaterial::from_seed(&Seed::from_bytes([112; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
            ));
            let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
            let manifest = plan.capture(&control.lock().unwrap()).unwrap();
            if unsafe_case == "unknown-lower-entry" {
                fs::write(lower.join("nested/unknown"), b"outside the capture plan").unwrap();
            }
            // A first-mount preflight must reject the unsafe nested directory
            // before it tries to decode or replay any view namespace intent.
            let pending_rename = (unsafe_case == "directory-world-search"
                || unsafe_case == "unknown-lower-entry")
                .then(|| {
                    let mut id = manifest.anchor_id.as_bytes().to_vec();
                    id.extend_from_slice(&2_u64.to_le_bytes());
                    control
                        .lock()
                        .unwrap()
                        .put_record("guarded-view-directory-rename-v1", &id, &[0xff])
                        .unwrap();
                    id
                });
            let error = match GuardedViewMount::start(
                &manifest,
                Arc::clone(&control),
                &mountpoint,
                65534,
                65534,
            ) {
                Ok(mount) => {
                    mount.stop().unwrap();
                    panic!("mutable private lower {unsafe_case} was mounted")
                }
                Err(error) => error,
            };
            let expected = if unsafe_case == "unknown-lower-entry" {
                "unexpected or missing entry"
            } else {
                "view owner"
            };
            assert!(error.to_string().contains(expected), "{error:#}");
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(
                control
                    .lock()
                    .unwrap()
                    .records("guarded-view-namespace-v1")
                    .unwrap()
                    .is_empty(),
                "unsafe lower {unsafe_case} replayed view namespace state"
            );
            if let Some(id) = pending_rename {
                assert_eq!(
                    control
                        .lock()
                        .unwrap()
                        .get_record("guarded-view-directory-rename-v1", &id)
                        .unwrap(),
                    Some(vec![0xff])
                );
                assert!(
                    control
                        .lock()
                        .unwrap()
                        .delete_record("guarded-view-directory-rename-v1", &id)
                        .unwrap()
                );
            }
            if unsafe_case == "unknown-lower-entry" {
                fs::remove_file(lower.join("nested/unknown")).unwrap();
            }
            plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn guarded_mount_isolates_a_preopened_read_only_lower_descriptor() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-held-fd-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        let nested = lower.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("known"), b"nested bytes").unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let original = b"preopened\r\n\0source";
        let source = lower.join("sample");
        fs::write(&source, original).unwrap();
        let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
        // SAFETY: this test owns the NUL-free disposable source path.
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();

        let keys = KeyMaterial::from_seed(&Seed::from_bytes([113; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        assert_eq!(
            fs::metadata(area.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&lower).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let mut child = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-u")
            .arg("-c")
            .arg(
                r#"import errno, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
dirfd = os.open(os.path.dirname(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
nested_fd = os.open(sys.argv[3], os.O_RDONLY | os.O_DIRECTORY)
print('READY', flush=True)
assert sys.stdin.readline() == 'continue\n'
for operation in (
    lambda: os.fchmod(fd, 0o600),
    lambda: os.open('/proc/self/fd/%d' % fd, os.O_WRONLY),
    lambda: os.open(sys.argv[1], os.O_RDONLY),
    lambda: os.fchmod(dirfd, 0o777),
    lambda: os.open('sample', os.O_RDONLY, dir_fd=dirfd),
    lambda: os.open('known', os.O_RDONLY, dir_fd=nested_fd),
):
    try:
        operation()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM), error
    else:
        raise AssertionError('private lower inode remained accessible')
view = os.open(sys.argv[2], os.O_RDWR)
os.pwrite(view, b'EDIT', 0)
os.fsync(view)
os.close(view)
os.close(fd)
os.close(dirfd)
os.close(nested_fd)
print('DONE', flush=True)
"#,
            )
            .arg(&source)
            .arg(mountpoint.join("sample"))
            .arg(&nested)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        if line != "READY\n" {
            let child_output = child.wait_with_output().unwrap();
            panic!(
                "held-descriptor child did not open the lower file: {line:?}, {}",
                String::from_utf8_lossy(&child_output.stderr)
            );
        }

        let manifest = plan.capture(&control.lock().unwrap()).unwrap();
        // This is the isolation state the enrollment transition must reach
        // durably before exposing a view. The test holds an older descriptor
        // across that transition; enrollment itself remains gated.
        assert_eq!(unsafe { libc::chown(source_path.as_ptr(), 0, 0) }, 0);
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        let status = child.wait().unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "held-descriptor child failed: {stderr}");
        assert_eq!(line, "DONE\n");

        let mut changed = original.to_vec();
        changed[..4].copy_from_slice(b"EDIT");
        assert_eq!(fs::read(&source).unwrap(), changed);
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut frozen = Vec::new();
        anchor.read_to_end(&mut frozen).unwrap();
        assert_eq!(frozen, original);
        mount.stop().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &control.lock().unwrap()).unwrap();
        plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn frozen_file_renamed_through_view_retires_at_its_recorded_path() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-renamed-retire-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let public = tempfile::Builder::new()
            .prefix("mb-guarded-renamed-view-")
            .tempdir_in(area.path().parent().unwrap())
            .unwrap();
        fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = public.path().join("view");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let source = lower.join("sample");
        let original = b"frozen\r\n\0bytes";
        fs::write(&source, original).unwrap();
        let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([126; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
            .unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        let rename = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
            .arg(mountpoint.join("sample"))
            .arg(mountpoint.join("renamed"))
            .output()
            .unwrap();
        assert!(rename.status.success(), "{rename:?}");
        assert_eq!(fs::read(lower.join("renamed")).unwrap(), original);
        assert_eq!(fs::metadata(lower.join("renamed")).unwrap().uid(), 0);
        mount.stop().unwrap();
        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(fs::read(mountpoint.join("renamed")).unwrap(), original);
        assert!(!mountpoint.join("sample").exists());
        remounted.stop().unwrap();
        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        let mut namespace_id = manifest.anchor_id.as_bytes().to_vec();
        namespace_id.extend_from_slice(&2_u64.to_le_bytes());
        let namespace = store
            .get_record("guarded-view-namespace-v1", &namespace_id)
            .unwrap()
            .unwrap();
        store
            .put_record("guarded-view-namespace-v1", &namespace_id, &[0xff])
            .unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        store
            .put_record("guarded-view-namespace-v1", &namespace_id, &namespace)
            .unwrap();
        store
            .put_record("guarded-view-create-v1", &namespace_id, &[0xff])
            .unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        store
            .delete_record("guarded-view-create-v1", &namespace_id)
            .unwrap();
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut retained = Vec::new();
        anchor.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(lower.join("renamed")).unwrap(), original);
        let restored = fs::metadata(lower.join("renamed")).unwrap();
        assert_eq!((restored.uid(), restored.gid()), (65534, 65534));
        assert_eq!(restored.permissions().mode() & 0o7777, 0o644);
        assert!(!source.exists());
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn captured_directory_move_restores_nested_owners_at_current_paths() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-directory-retire-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let public = tempfile::Builder::new()
            .prefix("mb-guarded-directory-view-")
            .tempdir_in(area.path().parent().unwrap())
            .unwrap();
        fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let nested = lower.join("nested");
        let mountpoint = public.path().join("view");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o750)).unwrap();
        let nested_path = CString::new(nested.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(nested_path.as_ptr(), 65533, 65533) },
            0
        );
        let source = nested.join("sample");
        let original = b"nested\r\n\0bytes";
        fs::write(&source, original).unwrap();
        let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([127; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
            .unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        let rename = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
            .arg(mountpoint.join("nested"))
            .arg(mountpoint.join("moved"))
            .output()
            .unwrap();
        assert!(rename.status.success(), "{rename:?}");
        assert_eq!(fs::read(lower.join("moved/sample")).unwrap(), original);
        mount.stop().unwrap();
        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(fs::read(mountpoint.join("moved/sample")).unwrap(), original);
        remounted.stop().unwrap();
        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        let mut directory_id = manifest.anchor_id.as_bytes().to_vec();
        directory_id.extend_from_slice(&2_u64.to_le_bytes());
        let directory_record = store
            .get_record("guarded-view-directory-v1", &directory_id)
            .unwrap()
            .unwrap();
        store
            .put_record("guarded-view-directory-v1", &directory_id, &[0xff])
            .unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        store
            .put_record(
                "guarded-view-directory-v1",
                &directory_id,
                &directory_record,
            )
            .unwrap();
        fs::rename(lower.join("moved"), lower.join("held")).unwrap();
        fs::create_dir(lower.join("moved")).unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        fs::remove_dir(lower.join("moved")).unwrap();
        fs::rename(lower.join("held"), lower.join("moved")).unwrap();
        let moved_path = CString::new(lower.join("moved").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(moved_path.as_ptr(), 65533, 65533) }, 0);
        assert_eq!(
            fs::metadata(lower.join("moved"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let mut anchor = manifest
            .file_locator("nested/sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut retained = Vec::new();
        anchor.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(lower.join("moved/sample")).unwrap(), original);
        let restored_file = fs::metadata(lower.join("moved/sample")).unwrap();
        assert_eq!((restored_file.uid(), restored_file.gid()), (65534, 65534));
        assert_eq!(restored_file.permissions().mode() & 0o7777, 0o644);
        let restored_directory = fs::metadata(lower.join("moved")).unwrap();
        assert_eq!(
            (restored_directory.uid(), restored_directory.gid()),
            (65533, 65533)
        );
        assert_eq!(restored_directory.permissions().mode() & 0o7777, 0o750);
        assert!(!nested.exists());
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn removed_or_replaced_captured_directory_retires_without_restoring_old_inode() {
        for replace in [false, true] {
            let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
                Some(root) => tempfile::Builder::new()
                    .prefix("mb-guarded-removed-dir-")
                    .tempdir_in(root)
                    .unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let public = tempfile::Builder::new()
                .prefix("mb-guarded-removed-view-")
                .tempdir_in(area.path().parent().unwrap())
                .unwrap();
            fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let lower = area.path().join("lower");
            let mountpoint = public.path().join("view");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(&mountpoint).unwrap();
            fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
            let target = lower.join("target");
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o750)).unwrap();
            let target_path = CString::new(target.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(target_path.as_ptr(), 65533, 65533) },
                0
            );
            if replace {
                let source = lower.join("source");
                fs::create_dir(&source).unwrap();
                fs::set_permissions(&source, fs::Permissions::from_mode(0o710)).unwrap();
                let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
                assert_eq!(
                    unsafe { libc::chown(source_path.as_ptr(), 65532, 65532) },
                    0
                );
            }
            let kept = lower.join("kept");
            let original = b"retained\r\n\0bytes";
            fs::write(&kept, original).unwrap();
            let kept_path = CString::new(kept.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(kept_path.as_ptr(), 65534, 65534) }, 0);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([128; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
            ));
            let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
            let manifest = plan
                .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
                .unwrap();
            plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
                .unwrap();
            let mount =
                GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                    .unwrap();
            let operation = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg(if replace {
                    "import os,sys; os.rename(sys.argv[1],sys.argv[2])"
                } else {
                    "import os,sys; os.rmdir(sys.argv[2])"
                })
                .arg(mountpoint.join("source"))
                .arg(mountpoint.join("target"))
                .output()
                .unwrap();
            assert!(operation.status.success(), "{operation:?}");
            mount.stop().unwrap();
            let remounted =
                GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control))
                    .unwrap();
            assert_eq!(mountpoint.join("target").exists(), replace);
            remounted.stop().unwrap();
            let store = control.lock().unwrap();
            GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
            plan.discard_unreferenced(&store).unwrap();
            assert_eq!(target.exists(), replace);
            if replace {
                let restored = fs::metadata(&target).unwrap();
                assert_eq!((restored.uid(), restored.gid()), (65532, 65532));
                assert_eq!(restored.permissions().mode() & 0o7777, 0o710);
                assert!(!lower.join("source").exists());
            }
            assert_eq!(fs::read(&kept).unwrap(), original);
            assert_eq!(fs::metadata(&kept).unwrap().uid(), 65534);
        }
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and reflink capture"]
    fn guarded_virtual_metadata_survives_remount_and_retires_with_claim() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-virtual-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        fs::create_dir(lower.join("nested")).unwrap();
        fs::write(lower.join("nested/file"), b"raw\r\nbytes\0").unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([219; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
            .unwrap();
        let view =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let mut metadata = view.verified_metadata_snapshot(manifest.anchor_id).unwrap();
        metadata.root_mode = 0o750;
        metadata.root_uid = 65533;
        metadata.root_gid = 65533;
        metadata.root_atime_secs = 1_700_000_000;
        metadata.root_modified_secs = 1_700_000_000;
        for (entry, captured) in metadata.entries.iter_mut().zip(&manifest.entries) {
            entry.mode = match captured {
                crate::CapturedEntry::Directory { mode, .. }
                | crate::CapturedEntry::FileV2 { mode, .. } => (mode & 0o7777) as u16,
                crate::CapturedEntry::File { .. } => unreachable!(),
            };
            entry.uid = 65533;
            entry.gid = 65533;
            entry.atime_secs = 1_700_000_000;
            entry.modified_secs = 1_700_000_000;
            if entry.path == b"nested" {
                entry.logical_len = 8192;
            }
        }
        let mut invalid = metadata.clone();
        invalid.entries[0].path = b"different".to_vec();
        assert!(
            GuardedViewMount::start_with_virtual_metadata(
                &manifest,
                Arc::clone(&control),
                &mountpoint,
                65534,
                65534,
                invalid,
            )
            .is_err()
        );
        assert!(
            control
                .lock()
                .unwrap()
                .get_record(super::VIRTUAL_METADATA_KIND, manifest.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        let mount = GuardedViewMount::start_with_virtual_metadata(
            &manifest,
            Arc::clone(&control),
            &mountpoint,
            65534,
            65534,
            metadata,
        )
        .unwrap();
        assert_eq!(fs::metadata(&mountpoint).unwrap().uid(), 65533);
        assert_eq!(fs::metadata(&mountpoint).unwrap().mode() & 0o7777, 0o750);
        assert_eq!(fs::metadata(&mountpoint).unwrap().mtime(), 1_700_000_000);
        assert_eq!(fs::metadata(mountpoint.join("nested")).unwrap().len(), 8192);
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().mode() & 0o7777,
            0o755
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested/file")).unwrap().uid(),
            65533
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested/file"))
                .unwrap()
                .atime(),
            1_700_000_000
        );
        assert_eq!(
            fs::read(mountpoint.join("nested/file")).unwrap(),
            b"raw\r\nbytes\0"
        );
        fs::write(mountpoint.join("nested/new"), b"new").unwrap();
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().len(),
            fs::metadata(lower.join("nested")).unwrap().len()
        );
        fs::remove_file(mountpoint.join("nested/new")).unwrap();
        fs::set_permissions(mountpoint.join("nested"), fs::Permissions::from_mode(0o711)).unwrap();
        let lower_nested = fs::metadata(lower.join("nested")).unwrap();
        let baseline_mtime = (lower_nested.mtime(), lower_nested.mtime_nsec());
        let nested_path = CString::new(mountpoint.join("nested").as_os_str().as_bytes()).unwrap();
        let times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: 1_600_000_000,
                tv_nsec: 0,
            },
        ];
        // SAFETY: the path is NUL-free and the two-element timespec array is valid.
        assert_eq!(
            unsafe { libc::utimensat(libc::AT_FDCWD, nested_path.as_ptr(), times.as_ptr(), 0) },
            0
        );
        mount.stop().unwrap();
        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(fs::metadata(&mountpoint).unwrap().uid(), 65533);
        assert_eq!(fs::metadata(&mountpoint).unwrap().mode() & 0o7777, 0o750);
        assert_eq!(fs::metadata(&mountpoint).unwrap().mtime(), 1_700_000_000);
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().len(),
            fs::metadata(lower.join("nested")).unwrap().len()
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().mtime(),
            1_600_000_000
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().mode() & 0o7777,
            0o711
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested/file")).unwrap().uid(),
            65533
        );
        let reset_times = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: baseline_mtime.0,
                tv_nsec: baseline_mtime.1,
            },
        ];
        // SAFETY: the path remains NUL-free and both timespec values are valid.
        assert_eq!(
            unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    nested_path.as_ptr(),
                    reset_times.as_ptr(),
                    0,
                )
            },
            0
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().mtime(),
            baseline_mtime.0
        );
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().len(),
            fs::metadata(lower.join("nested")).unwrap().len()
        );
        remounted.stop().unwrap();
        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(
            fs::metadata(mountpoint.join("nested")).unwrap().mtime(),
            baseline_mtime.0
        );
        remounted.stop().unwrap();
        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        assert!(
            store
                .get_record(super::VIRTUAL_METADATA_KIND, manifest.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_record(
                    super::VIRTUAL_TIME_BASELINE_KIND,
                    manifest.anchor_id.as_bytes()
                )
                .unwrap()
                .is_none()
        );
        assert!(
            super::virtual_time_dirty_masks(
                &store,
                manifest.anchor_id,
                u64::try_from(manifest.entries.len()).unwrap() + 2,
            )
            .unwrap()
            .is_empty()
        );
        assert!(
            super::virtual_directory_size_dirty_ids(
                &store,
                manifest.anchor_id,
                u64::try_from(manifest.entries.len()).unwrap() + 2,
            )
            .unwrap()
            .is_empty()
        );
        plan.discard_unreferenced(&store).unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn guarded_mount_claim_survives_remount_and_rejects_replaced_placeholder() {
        const CHILD_ROOT: &str = "MUTUALBACKUP_GUARDED_MOUNT_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([111; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(root.join("control/control.db"), &keys).unwrap(),
            ));
            let anchor_id: uuid::Uuid = fs::read_to_string(root.join("anchor-id"))
                .unwrap()
                .parse()
                .unwrap();
            let _mount = GuardedViewMount::recover_claimed(anchor_id, control).unwrap();
            fs::write(root.join("ready"), b"mounted").unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        struct DeadMount {
            child: Child,
            mountpoint: PathBuf,
        }
        impl Drop for DeadMount {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let path = CString::new(self.mountpoint.as_os_str().as_bytes()).unwrap();
                // SAFETY: this test's private mountpoint has no embedded NUL.
                let _ = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
            }
        }

        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-mount-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        let control_path = control_dir.join("control.db");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let exact_bytes = b"guarded\r\n\0source\n";
        fs::create_dir(lower.join("captured")).unwrap();
        fs::set_permissions(lower.join("captured"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(lower.join("sample"), exact_bytes).unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();

        let keys = KeyMaterial::from_seed(&Seed::from_bytes([111; 32]));
        let control = ControlStore::open(&control_path, &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control, 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control, &manifest).unwrap();
        let control = Arc::new(Mutex::new(control));
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        mount.check_health().unwrap();
        assert!(
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).is_err()
        );
        {
            let store = control.lock().unwrap();
            assert!(plan.discard_unreferenced(&store).is_err());
            assert!(GuardedViewMount::retire_claim(manifest.anchor_id, &store).is_err());
        }
        assert!(
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534,)
                .is_err()
        );
        let user_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(user_read.status.success(), "{user_read:?}");
        assert_eq!(user_read.stdout, exact_bytes);
        let unrelated_read = Command::new("cat")
            .uid(65533)
            .gid(65533)
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(!unrelated_read.status.success());
        let private_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(lower.join("sample"))
            .output()
            .unwrap();
        assert!(!private_read.status.success());
        let owner_write = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.pwrite(fd,b'EDIT',0); os.fsync(fd); os.close(fd)")
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(owner_write.status.success(), "{owner_write:?}");
        let mut edited = exact_bytes.to_vec();
        edited[..4].copy_from_slice(b"EDIT");
        assert_eq!(fs::read(lower.join("sample")).unwrap(), edited);
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut frozen = Vec::new();
        anchor.read_to_end(&mut frozen).unwrap();
        assert_eq!(frozen, exact_bytes);
        let public_directory = mountpoint.join("public");
        let user_mkdir = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.mkdir(sys.argv[1],0o777); os.chmod(sys.argv[1],0o777)")
            .arg(&public_directory)
            .output()
            .unwrap();
        assert!(user_mkdir.status.success(), "{user_mkdir:?}");
        assert_eq!(
            fs::metadata(&public_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
        assert_eq!(
            fs::metadata(lower.join("public"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let visible_modes = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.chmod(sys.argv[1],0o751); os.chmod(sys.argv[2],0o711); os.chmod(sys.argv[3],0o640)")
            .arg(&mountpoint)
            .arg(mountpoint.join("captured"))
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(visible_modes.status.success(), "{visible_modes:?}");
        mount.stop().unwrap();
        let snapshot =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        let encoded = mb_core::canonical_bytes(&snapshot).unwrap();
        assert_eq!(
            mb_core::decode_canonical::<crate::GuardedViewMetadataV1>(&encoded).unwrap(),
            snapshot
        );
        assert_eq!(snapshot.format_version, 1);
        assert_eq!(snapshot.anchor_id, manifest.anchor_id);
        assert_eq!(snapshot.root_mode, 0o751);
        assert_eq!((snapshot.root_uid, snapshot.root_gid), (65534, 65534));
        assert_eq!(
            snapshot.lower_root_id,
            crate::PinnedDirectory::open(&lower)
                .unwrap()
                .identity()
                .unwrap()
        );
        assert_eq!(snapshot.entries.len(), 3);
        assert_eq!(snapshot.entries[0].path, b"captured");
        assert_eq!(
            snapshot.entries[0].kind,
            crate::GuardedViewEntryKind::Directory
        );
        assert_eq!(snapshot.entries[0].mode, 0o711);
        assert_eq!(
            (snapshot.entries[0].uid, snapshot.entries[0].gid),
            (65534, 65534)
        );
        assert_eq!(snapshot.entries[1].path, b"public");
        assert_eq!(
            snapshot.entries[1].kind,
            crate::GuardedViewEntryKind::Directory
        );
        assert_eq!(snapshot.entries[1].mode, 0o777);
        assert_eq!(
            (snapshot.entries[1].uid, snapshot.entries[1].gid),
            (65534, 65534)
        );
        assert_eq!(snapshot.entries[2].path, b"sample");
        assert_eq!(snapshot.entries[2].kind, crate::GuardedViewEntryKind::File);
        assert_eq!(snapshot.entries[2].mode, 0o640);
        assert_eq!(
            (snapshot.entries[2].uid, snapshot.entries[2].gid),
            (65534, 65534)
        );
        assert_eq!(snapshot.entries[2].logical_len, edited.len() as u64);
        assert_eq!(
            snapshot.entries[2].native_id.inode,
            fs::metadata(lower.join("sample")).unwrap().ino()
        );

        for unexpected in [lower.join("public/unknown"), lower.join("unknown")] {
            fs::write(&unexpected, b"outside the guarded view").unwrap();
            assert!(
                GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control))
                    .is_err()
            );
            let error =
                match GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)) {
                    Ok(mount) => {
                        mount.stop().unwrap();
                        panic!("remount admitted an unrecorded lower entry")
                    }
                    Err(error) => error,
                };
            assert!(
                error.to_string().contains("unrecorded inode before replay"),
                "{error:#}"
            );
            assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
            fs::remove_file(unexpected).unwrap();
        }
        fs::rename(lower.join("sample"), lower.join("wrong-recorded-inode")).unwrap();
        let error =
            match GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)) {
                Ok(mount) => {
                    mount.stop().unwrap();
                    panic!("remount admitted a recorded inode at an unrecorded path")
                }
                Err(error) => error,
            };
        assert!(
            error.to_string().contains("ungranted path before replay"),
            "{error:#}"
        );
        assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
        fs::rename(lower.join("wrong-recorded-inode"), lower.join("sample")).unwrap();

        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let reopened_snapshot =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(reopened_snapshot.root_mode, snapshot.root_mode);
        for (before, after) in snapshot.entries.iter().zip(&reopened_snapshot.entries) {
            assert_eq!(before.path, after.path);
            assert_eq!(before.kind, after.kind);
            assert_eq!(before.native_id, after.native_id);
            assert_eq!(before.mode, after.mode);
            assert_eq!(before.logical_len, after.logical_len);
        }
        assert_eq!(reopened_snapshot.entries.len(), snapshot.entries.len());

        let mut recovered_mounts =
            GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(recovered_mounts.len(), 1);
        let remounted = recovered_mounts.pop().unwrap();
        remounted.check_health().unwrap();
        assert_eq!(fs::read(mountpoint.join("sample")).unwrap(), edited);
        assert_eq!(
            fs::metadata(&public_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
        assert_eq!(
            fs::metadata(lower.join("public"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let user_rmdir = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rmdir(sys.argv[1])")
            .arg(&public_directory)
            .output()
            .unwrap();
        assert!(user_rmdir.status.success(), "{user_rmdir:?}");
        remounted.stop().unwrap();

        fs::write(
            area.path().join("anchor-id"),
            manifest.anchor_id.to_string(),
        )
        .unwrap();
        let mut dead = DeadMount {
            child: Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "guarded_mount::tests::guarded_mount_claim_survives_remount_and_rejects_replaced_placeholder",
                    "--nocapture",
                ])
                .env(CHILD_ROOT, area.path())
                .spawn()
                .unwrap(),
            mountpoint: mountpoint.clone(),
        };
        for _ in 0..200 {
            if area.path().join("ready").exists() {
                break;
            }
            assert!(dead.child.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            area.path().join("ready").exists(),
            "child mount did not become ready"
        );
        dead.child.kill().unwrap();
        assert!(!dead.child.wait().unwrap().success());
        assert!(fs::read(mountpoint.join("sample")).is_err());
        let after_dead =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert!(
            after_dead
                .entries
                .iter()
                .any(|entry| entry.path == b"sample")
        );
        let mut recovered_mounts =
            GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(recovered_mounts.len(), 1);
        let recovered = recovered_mounts.pop().unwrap();
        recovered.check_health().unwrap();
        assert_eq!(fs::read(mountpoint.join("sample")).unwrap(), edited);
        recovered.stop().unwrap();
        drop(dead);

        fs::rename(&mountpoint, area.path().join("old-view")).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).is_err()
        );
        assert!(
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .is_err()
        );
        fs::remove_dir(&mountpoint).unwrap();
        fs::rename(area.path().join("old-view"), &mountpoint).unwrap();
        {
            let store = control.lock().unwrap();
            assert!(plan.discard_unreferenced(&store).is_err());
            let claim = store
                .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())
                .unwrap()
                .unwrap();
            assert!(
                store
                    .put_record_if_absent(MOUNT_RETIRE_KIND, manifest.anchor_id.as_bytes(), &claim)
                    .unwrap()
            );
        }
        assert!(
            GuardedViewMount::recover_all_claimed(Arc::clone(&control))
                .unwrap()
                .is_empty()
        );
        {
            let store = control.lock().unwrap();
            assert!(
                store
                    .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        }
        assert!(
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).is_err()
        );
        plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
        assert!(
            !manifest
                .area
                .path_hint
                .join(manifest.anchor_id.to_string())
                .exists()
        );
        assert_eq!(fs::read(lower.join("sample")).unwrap(), edited);
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn stopped_view_file_recapture_detaches_new_anchor_after_rename_and_remount() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-recapture-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(lower.join("sample"), b"first revision bytes").unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();
        let source_path = CString::new(lower.join("sample").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        let untouched_bytes = b"untouched\r\nsource";
        fs::write(lower.join("untouched"), untouched_bytes).unwrap();
        fs::set_permissions(lower.join("untouched"), fs::Permissions::from_mode(0o644)).unwrap();
        let untouched_path = CString::new(lower.join("untouched").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(untouched_path.as_ptr(), 65534, 65534) },
            0
        );
        fs::create_dir(lower.join("nested")).unwrap();
        fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(lower.join("nested/kept"), b"nested unchanged").unwrap();
        let nested_path = CString::new(lower.join("nested/kept").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(nested_path.as_ptr(), 65534, 65534) },
            0
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([113; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let root_plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let original = root_plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        root_plan
            .isolate_lower_directories(&control.lock().unwrap(), &original)
            .unwrap();
        let first_mount =
            GuardedViewMount::start(&original, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        let edit = |path: &std::path::Path, bytes: &str| {
            let output = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.pwrite(fd,sys.argv[2].encode(),0); os.fsync(fd); os.close(fd)")
                .arg(path)
                .arg(bytes)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        };
        edit(&mountpoint.join("sample"), "EDIT1");
        let first_bytes = fs::read(lower.join("sample")).unwrap();
        first_mount.stop().unwrap();
        let anchor_bytes = |manifest: &crate::FileAnchorManifest| {
            let mut file = manifest.open_verified().unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        };
        let attempt_id = uuid::Uuid::new_v4();
        let prepared = GuardedViewMount::prepare_stopped_capture(
            original.anchor_id,
            attempt_id,
            Arc::clone(&control),
        )
        .unwrap();
        let partial = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "sample",
        )
        .unwrap();
        assert!(
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).is_err()
        );
        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let mut recovered = GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(recovered.len(), 1);
        recovered.pop().unwrap().stop().unwrap();
        let captured_view = GuardedViewMount::finish_stopped_capture(
            original.anchor_id,
            attempt_id,
            Arc::clone(&control),
        )
        .unwrap();
        assert_eq!(captured_view.metadata, prepared);
        assert_eq!(captured_view.format_version, 1);
        assert_eq!(
            mb_core::decode_canonical::<GuardedStoppedCaptureV1>(
                &mb_core::canonical_bytes(&captured_view).unwrap()
            )
            .unwrap(),
            captured_view
        );
        captured_view.verify().unwrap();
        let mut wrong_bytes = captured_view.clone();
        wrong_bytes.files[0].content_hash[0] ^= 1;
        assert!(wrong_bytes.verify().is_err());
        assert_eq!(captured_view.files.len(), 3);
        let sample = captured_view
            .files
            .iter()
            .find(|file| file.path == b"sample")
            .unwrap();
        let untouched = captured_view
            .files
            .iter()
            .find(|file| file.path == b"untouched")
            .unwrap();
        assert_ne!(sample.locator.anchor_id, original.anchor_id);
        assert_eq!(sample.content_hash, *blake3::hash(&first_bytes).as_bytes());
        assert_eq!(untouched.locator.anchor_id, original.anchor_id);
        assert_eq!(
            untouched.content_hash,
            *blake3::hash(untouched_bytes).as_bytes()
        );
        let nested = captured_view
            .files
            .iter()
            .find(|file| file.path == b"nested/kept")
            .unwrap();
        assert_eq!(nested.locator.anchor_id, original.anchor_id);
        assert_eq!(
            nested.content_hash,
            *blake3::hash(b"nested unchanged").as_bytes()
        );

        let first = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "sample",
        )
        .unwrap();
        assert_eq!(first, partial);
        assert_eq!(first.anchor_id, sample.locator.anchor_id);
        assert_eq!(
            GuardedViewMount::capture_stopped_view(original.anchor_id, Arc::clone(&control))
                .unwrap(),
            captured_view
        );
        assert_eq!(anchor_bytes(&first), first_bytes);
        assert_eq!(
            GuardedViewMount::capture_stopped_file(
                original.anchor_id,
                Arc::clone(&control),
                "sample",
            )
            .unwrap(),
            first
        );
        let remounted =
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).unwrap();
        let first_plan = {
            let store = control.lock().unwrap();
            let plan = crate::GuardedFileCapturePlan::load_for_manifest(&store, &first)
                .unwrap()
                .unwrap();
            assert!(plan.discard_unreferenced(&store).is_err());
            plan
        };
        assert_eq!(
            fs::metadata(mountpoint.join("sample"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o666
        );
        let renamed = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
            .arg(mountpoint.join("sample"))
            .arg(mountpoint.join("moved"))
            .output()
            .unwrap();
        assert!(renamed.status.success(), "{renamed:?}");
        edit(&mountpoint.join("moved"), "EDIT2");
        assert_eq!(anchor_bytes(&first), first_bytes);
        assert_eq!(
            GuardedViewMount::prepare_stopped_capture(
                original.anchor_id,
                attempt_id,
                Arc::clone(&control),
            )
            .unwrap(),
            prepared
        );
        assert_eq!(
            GuardedViewMount::finish_stopped_capture(
                original.anchor_id,
                attempt_id,
                Arc::clone(&control),
            )
            .unwrap(),
            captured_view
        );
        let second_bytes = fs::read(lower.join("moved")).unwrap();
        remounted.stop().unwrap();

        let second = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "moved",
        )
        .unwrap();
        assert_ne!(second.anchor_id, first.anchor_id);
        assert_eq!(anchor_bytes(&second), second_bytes);
        assert!(
            first_plan
                .discard_unreferenced(&control.lock().unwrap())
                .is_err()
        );
        assert!(
            GuardedViewMount::retire_claim(original.anchor_id, &control.lock().unwrap()).is_err()
        );
        GuardedViewMount::release_stopped_capture_unreferenced(
            attempt_id,
            &control.lock().unwrap(),
        )
        .unwrap();
        first_plan
            .discard_unreferenced(&control.lock().unwrap())
            .unwrap();
        assert!(first.open_verified().is_err());
        assert!(captured_view.verify().is_err());
        let remounted =
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).unwrap();
        edit(&mountpoint.join("moved"), "EDIT3");
        assert_eq!(anchor_bytes(&second), second_bytes);
        let create = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644); os.write(fd,b'new view file'); os.fsync(fd); os.close(fd)")
            .arg(mountpoint.join("created"))
            .output()
            .unwrap();
        assert!(create.status.success(), "{create:?}");
        remounted.stop().unwrap();
        let created_bytes = fs::read(lower.join("created")).unwrap();
        let git_attempt = uuid::Uuid::new_v4();
        GuardedViewMount::prepare_stopped_file_capture(
            original.anchor_id,
            git_attempt,
            Arc::clone(&control),
            "created",
        )
        .unwrap();
        let before_publication = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "created",
        )
        .unwrap();
        assert_eq!(anchor_bytes(&before_publication), created_bytes);
        assert!(
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).is_err()
        );
        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let mut resumed = GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(resumed.len(), 1);
        resumed.pop().unwrap().stop().unwrap();
        let created = GuardedViewMount::finish_stopped_file_capture(
            original.anchor_id,
            git_attempt,
            Arc::clone(&control),
        )
        .unwrap();
        assert_eq!(created, before_publication);
        assert!(
            GuardedViewMount::require_release_unpinned(
                original.anchor_id,
                &control.lock().unwrap()
            )
            .is_err()
        );
        assert_eq!(anchor_bytes(&created), created_bytes);
        let remounted =
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).unwrap();
        edit(&mountpoint.join("created"), "EDIT4");
        assert_eq!(anchor_bytes(&created), created_bytes);
        assert_eq!(
            GuardedViewMount::finish_stopped_file_capture(
                original.anchor_id,
                git_attempt,
                Arc::clone(&control)
            )
            .unwrap(),
            created
        );
        let repository_id = uuid::Uuid::new_v4();
        assert_eq!(
            GuardedViewMount::transfer_stopped_file_capture_to_git(
                git_attempt,
                repository_id,
                repository_id,
                &control.lock().unwrap(),
            )
            .unwrap(),
            created
        );
        assert!(
            GuardedViewMount::release_stopped_file_capture_unreferenced(
                git_attempt,
                &control.lock().unwrap(),
            )
            .is_err()
        );
        assert!(
            GuardedViewMount::require_release_unpinned(
                original.anchor_id,
                &control.lock().unwrap()
            )
            .is_err()
        );
        remounted.stop().unwrap();
        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        assert!(
            GuardedViewMount::require_release_unpinned(
                original.anchor_id,
                &control.lock().unwrap()
            )
            .is_err()
        );
        let stage_pins =
            GuardedViewMount::git_stage_pins(repository_id, &control.lock().unwrap()).unwrap();
        assert_eq!(stage_pins.len(), 1);
        assert_eq!(stage_pins[0].attempt_id, git_attempt);
        assert_eq!(stage_pins[0].worktree_id, repository_id);
        assert_eq!(stage_pins[0].relative_path, b"created");
        assert_eq!(stage_pins[0].manifest, created);
        assert!(matches!(stage_pins[0].git_mode, 0o100644 | 0o100755));
        {
            let store = control.lock().unwrap();
            let (current_bytes, mut legacy) = super::git_anchor_pin(&store, created.anchor_id)
                .unwrap()
                .unwrap();
            legacy.format_version = 1;
            legacy.stage = None;
            let legacy_bytes = mb_core::canonical_bytes(&legacy).unwrap();
            store
                .replace_record_if_value(
                    super::GIT_ANCHOR_PIN_KIND,
                    created.anchor_id.as_bytes(),
                    &current_bytes,
                    &legacy_bytes,
                )
                .unwrap();
            assert_eq!(
                super::git_anchor_pin(&store, created.anchor_id)
                    .unwrap()
                    .unwrap()
                    .1
                    .format_version,
                1
            );
            assert!(GuardedViewMount::git_stage_pins(repository_id, &store).is_err());
            store
                .replace_record_if_value(
                    super::GIT_ANCHOR_PIN_KIND,
                    created.anchor_id.as_bytes(),
                    &legacy_bytes,
                    &current_bytes,
                )
                .unwrap();
        }
        let created_plan =
            crate::GuardedFileCapturePlan::load_for_manifest(&control.lock().unwrap(), &created)
                .unwrap()
                .unwrap();
        assert!(
            created_plan
                .discard_unreferenced(&control.lock().unwrap())
                .unwrap_err()
                .to_string()
                .contains("Git catalog")
        );
        let moved_attempt = uuid::Uuid::new_v4();
        GuardedViewMount::prepare_stopped_file_capture(
            original.anchor_id,
            moved_attempt,
            Arc::clone(&control),
            "moved",
        )
        .unwrap();
        let moved_git = GuardedViewMount::finish_stopped_file_capture(
            original.anchor_id,
            moved_attempt,
            Arc::clone(&control),
        )
        .unwrap();
        assert!(
            GuardedViewMount::transfer_stopped_file_capture_to_git(
                moved_attempt,
                uuid::Uuid::new_v4(),
                repository_id,
                &control.lock().unwrap(),
            )
            .is_err()
        );
        GuardedViewMount::transfer_stopped_file_capture_to_git(
            moved_attempt,
            repository_id,
            repository_id,
            &control.lock().unwrap(),
        )
        .unwrap();
        assert_eq!(
            GuardedViewMount::git_stage_pins(repository_id, &control.lock().unwrap())
                .unwrap()
                .len(),
            2
        );
        assert!(
            GuardedViewMount::retire_git_anchor_pin_unreferenced(
                uuid::Uuid::new_v4(),
                created.anchor_id,
                &control.lock().unwrap(),
            )
            .is_err()
        );
        GuardedViewMount::retire_git_anchor_pin_unreferenced(
            repository_id,
            created.anchor_id,
            &control.lock().unwrap(),
        )
        .unwrap();
        assert!(
            GuardedViewMount::require_release_unpinned(
                original.anchor_id,
                &control.lock().unwrap()
            )
            .is_err()
        );
        GuardedViewMount::retire_git_anchor_pin_unreferenced(
            repository_id,
            moved_git.anchor_id,
            &control.lock().unwrap(),
        )
        .unwrap();
        GuardedViewMount::require_release_unpinned(original.anchor_id, &control.lock().unwrap())
            .unwrap();

        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(original.anchor_id, &store).unwrap();
        assert!(root_plan.discard_unreferenced(&store).is_err());
        for anchor in [&second, &created, &moved_git] {
            let plan = crate::GuardedFileCapturePlan::load_for_manifest(&store, anchor)
                .unwrap()
                .unwrap();
            plan.discard_unreferenced(&store).unwrap();
        }
        assert!(
            store
                .records(crate::guarded_view_probe::FILE_GUARD_KIND)
                .unwrap()
                .is_empty()
        );
        root_plan.discard_unreferenced(&store).unwrap();
        assert!(fs::read(lower.join("moved")).unwrap().starts_with(b"EDIT3"));
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and a disposable mounted filesystem of at most 512 MiB"]
    fn real_enospc_writable_open_keeps_guarded_mount_recoverable() {
        let mounted_root = std::env::var_os("MUTUALBACKUP_REAL_ENOSPC_TEST_ROOT")
            .expect("set MUTUALBACKUP_REAL_ENOSPC_TEST_ROOT to a disposable mount");
        let mounted_root = PathBuf::from(mounted_root).canonicalize().unwrap();
        assert_eq!(
            fs::read(mounted_root.join(".mutualbackup-disposable-enospc")).unwrap(),
            b"mutualbackup-disposable-enospc-v1\n"
        );
        assert_ne!(
            fs::metadata(&mounted_root).unwrap().dev(),
            fs::metadata(mounted_root.parent().unwrap()).unwrap().dev()
        );
        let mounted = File::open(&mounted_root).unwrap();
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: the mounted descriptor is open and fstatvfs fills stats on success.
        assert_eq!(
            unsafe { libc::fstatvfs(mounted.as_raw_fd(), stats.as_mut_ptr()) },
            0
        );
        // SAFETY: the preceding fstatvfs call succeeded.
        let stats = unsafe { stats.assume_init() };
        assert!(
            stats.f_blocks > 0
                && stats.f_frsize > 0
                && stats.f_blocks.saturating_mul(stats.f_frsize) <= 512 * 1024 * 1024
        );

        let area = tempfile::Builder::new()
            .prefix("mb-guarded-full-view-")
            .tempdir_in(&mounted_root)
            .unwrap();
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let filler_path = area.path().join("filler");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let chunk = [0x5a_u8; 1024 * 1024];
        let source_path = lower.join("source");
        let mut source = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        for _ in 0..32 {
            source.write_all(&chunk).unwrap();
        }
        source.sync_all().unwrap();
        source
            .set_permissions(fs::Permissions::from_mode(0o666))
            .unwrap();
        drop(source);
        let original_hash = blake3::hash(&fs::read(&source_path).unwrap());

        let journal_area = tempfile::tempdir().unwrap();
        assert_ne!(
            fs::metadata(journal_area.path()).unwrap().dev(),
            fs::metadata(area.path()).unwrap().dev()
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([112; 32]));
        let control = ControlStore::open(journal_area.path().join("control.db"), &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&control).unwrap();
        let control = Arc::new(Mutex::new(control));
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        mount.check_health().unwrap();

        let mut filler = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filler_path)
            .unwrap();
        let mut full = false;
        for _ in 0..512 {
            let result = filler.write_all(&chunk).and_then(|()| filler.sync_data());
            if let Err(error) = result {
                assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
                full = true;
                break;
            }
        }
        assert!(full, "the disposable filesystem did not become full");
        filler
            .set_len(
                filler
                    .metadata()
                    .unwrap()
                    .len()
                    .saturating_sub(8 * 1024 * 1024),
            )
            .unwrap();
        filler.sync_all().unwrap();

        let attempted_open = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import errno,os,sys\ntry:\n fd=os.open(sys.argv[1],os.O_WRONLY)\n os.close(fd)\n raise AssertionError('writable open unexpectedly succeeded')\nexcept OSError as error:\n assert error.errno==errno.ENOSPC,error")
            .arg(mountpoint.join("source"))
            .output()
            .unwrap();
        assert!(
            attempted_open.status.success(),
            "ordinary-user disk-full open: {}",
            String::from_utf8_lossy(&attempted_open.stderr)
        );
        let attempted_truncate = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import errno,os,sys\ntry:\n os.truncate(sys.argv[1],1)\n raise AssertionError('pathname truncate unexpectedly succeeded')\nexcept OSError as error:\n assert error.errno==errno.ENOSPC,error")
            .arg(mountpoint.join("source"))
            .output()
            .unwrap();
        assert!(
            attempted_truncate.status.success(),
            "ordinary-user disk-full truncate: {}",
            String::from_utf8_lossy(&attempted_truncate.stderr)
        );
        mount.check_health().unwrap();
        let private_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(&source_path)
            .output()
            .unwrap();
        assert!(!private_read.status.success());
        let anchor_path = manifest.file_locator("source".to_owned()).unwrap();
        let anchor = anchor_path.open().unwrap();
        assert_eq!(
            fs::metadata(&source_path).unwrap().ino(),
            anchor.metadata().unwrap().ino()
        );
        assert_eq!(
            blake3::hash(&fs::read(&source_path).unwrap()),
            original_hash
        );
        drop(anchor);

        drop(filler);
        fs::remove_file(&filler_path).unwrap();
        mount.stop().unwrap();
        let recovered =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        recovered.check_health().unwrap();
        let edited = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.pwrite(fd,b'EDIT',0); os.fsync(fd); os.close(fd)")
            .arg(mountpoint.join("source"))
            .output()
            .unwrap();
        assert!(
            edited.status.success(),
            "ordinary-user retry: {}",
            String::from_utf8_lossy(&edited.stderr)
        );
        assert!(fs::read(&source_path).unwrap().starts_with(b"EDIT"));
        let mut protected = anchor_path.open().unwrap();
        assert_ne!(
            fs::metadata(&source_path).unwrap().ino(),
            protected.metadata().unwrap().ino()
        );
        let mut anchor_bytes = Vec::new();
        protected.read_to_end(&mut anchor_bytes).unwrap();
        assert_eq!(blake3::hash(&anchor_bytes), original_hash);
        recovered.stop().unwrap();
        let control = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &control).unwrap();
        plan.discard_unreferenced(&control).unwrap();
    }
}
