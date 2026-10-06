//! Historical guarded record shapes for read-only admission and export.
//!
//! These types cannot mount a view, capture a source, replay a journal, or retire
//! an anchor. Their field order and enum identities preserve historical bytes.

use super::{
    CaptureVersion, FileExtent, NativeFileId, StableAnchorAreaLocator, StableAnchorFileLocator,
};
use anyhow::ensure;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedRootCapturePlan {
    format_version: u16,
    anchor_id: Uuid,
    #[serde(with = "super::raw_path_bytes")]
    source_root: PathBuf,
    area: StableAnchorAreaLocator,
    root_version: CaptureVersion,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<GuardedRootEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum GuardedRootEntry {
    Directory {
        #[serde(with = "super::raw_path_bytes")]
        path: PathBuf,
        version: CaptureVersion,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        #[serde(with = "super::raw_path_bytes")]
        path: PathBuf,
        capture_id: Uuid,
        version: CaptureVersion,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedFileCapturePlan {
    format_version: u16,
    anchor_id: Uuid,
    #[serde(with = "super::raw_path_bytes")]
    source_root: PathBuf,
    source_root_id: NativeFileId,
    #[serde(with = "super::raw_path_bytes")]
    relative_path: PathBuf,
    source_version: CaptureVersion,
    source_mode: u32,
    area: StableAnchorAreaLocator,
}

/// The visible namespace and metadata of one quiescent guarded view. Paths
/// remain raw Unix bytes until the revision format defines their encoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedViewMetadataV1 {
    pub format_version: u16,
    pub anchor_id: Uuid,
    pub lower_root_id: NativeFileId,
    pub root_mode: u16,
    pub root_uid: u32,
    pub root_gid: u32,
    pub root_atime_secs: i64,
    pub root_atime_nanos: u32,
    pub root_modified_secs: i64,
    pub root_modified_nanos: u32,
    pub entries: Vec<GuardedViewMetadataEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedViewMetadataEntry {
    pub path: Vec<u8>,
    pub kind: GuardedViewEntryKind,
    pub native_id: NativeFileId,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub logical_len: u64,
    pub atime_secs: i64,
    pub atime_nanos: u32,
    pub modified_secs: i64,
    pub modified_nanos: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuardedViewEntryKind {
    File,
    Directory,
}

/// Historical quiescent-view record with an anchor for every visible file.
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

    /// Read-only verification of a persisted historical capture.
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

impl GuardedRootCapturePlan {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}
impl GuardedFileCapturePlan {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }
    pub fn source_root_identity(&self) -> NativeFileId {
        self.source_root_id
    }
    pub fn source_mode(&self) -> u32 {
        self.source_mode
    }
}
impl GuardedRevisionCaptureV1 {
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.format_version == 1 && !self.revision_id.is_nil(),
            "invalid guarded revision capture"
        );
        self.capture.verify()
    }
}

// Generic native removal must continue to preserve marked historical anchors.
pub(super) fn guarded_root_marker_name(anchor_id: Uuid) -> String {
    format!(".mutualbackup-guarded-root-v1-{anchor_id}")
}
pub(super) fn guarded_file_marker_name(anchor_id: Uuid) -> String {
    format!(".mutualbackup-guarded-file-v1-{anchor_id}")
}
