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
    /// Validate the historical namespace and ownership record without opening
    /// an anchor, source tree or mount. This does not verify captured payloads.
    pub fn validate_shape(&self) -> anyhow::Result<()> {
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
    pub fn preserved_ownership(&self) -> anyhow::Result<super::PreservedRootCapture<'_>> {
        super::validate_preserved_capture_root(
            self.format_version,
            self.anchor_id,
            &self.source_root,
            &self.area,
            &self.root_version,
            self.root_modified_nanos,
        )?;
        ensure!(
            self.root_mode & libc::S_IFMT == libc::S_IFDIR
                && self.root_modified_secs == self.root_version.modified_secs
                && i64::from(self.root_modified_nanos) == self.root_version.modified_nanos
                && self.entries.len() <= super::MAX_CAPTURE_ENTRIES,
            "invalid preserved guarded root metadata"
        );
        let root = self.root_version.recorded_identity();
        let mut directories = std::collections::BTreeSet::new();
        let mut captures = std::collections::BTreeSet::from([self.anchor_id]);
        let mut inodes = std::collections::BTreeSet::from([root.inode]);
        let mut previous = None::<&Path>;
        for entry in &self.entries {
            let (path, version, mode, secs, nanos, directory) = match entry {
                GuardedRootEntry::Directory {
                    path,
                    version,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => (path, version, mode, modified_secs, modified_nanos, true),
                GuardedRootEntry::File {
                    path,
                    capture_id,
                    version,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => {
                    ensure!(
                        !capture_id.is_nil() && captures.insert(*capture_id),
                        "invalid preserved file capture ownership"
                    );
                    (path, version, mode, modified_secs, modified_nanos, false)
                }
            };
            super::validate_relative(path)?;
            let normalized: PathBuf = path.components().collect();
            let bytes = path.as_os_str().as_bytes();
            ensure!(
                !bytes.contains(&0)
                    && normalized.as_os_str().as_bytes() == bytes
                    && bytes.len() <= super::MAX_RELATIVE_PATH_BYTES
                    && path.components().count() <= super::MAX_CAPTURE_DEPTH
                    && (self.format_version == 2 || path.to_str().is_some())
                    && previous.is_none_or(|prior| prior < path.as_path())
                    && *nanos < 1_000_000_000
                    && *secs == version.modified_secs
                    && i64::from(*nanos) == version.modified_nanos
                    && *mode & libc::S_IFMT
                        == if directory {
                            libc::S_IFDIR
                        } else {
                            libc::S_IFREG
                        },
                "unsafe preserved capture entry"
            );
            version.validate_preserved()?;
            ensure!(
                version.recorded_identity().filesystem_id == root.filesystem_id
                    && inodes.insert(version.inode),
                "invalid preserved capture entry identity"
            );
            if let Some(parent) = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            {
                ensure!(
                    directories.contains(parent),
                    "preserved capture entry lacks its parent"
                );
            }
            if directory {
                directories.insert(path.as_path());
            }
            previous = Some(path);
        }
        Ok(super::PreservedRootCapture {
            record_format: self.format_version,
            anchor_id: self.anchor_id,
            source_root: &self.source_root,
            area: &self.area,
            recorded_root_identity: root,
            // Guarded root plans were introduced after stable filesystem IDs.
            stable_root_identity: Some(root),
        })
    }

    pub fn for_each_preserved_file_capture(
        &self,
        mut visit: impl FnMut(super::PreservedFileCapture<'_>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        self.preserved_ownership()?;
        for entry in &self.entries {
            if let GuardedRootEntry::File {
                path,
                capture_id,
                version,
                ..
            } = entry
            {
                visit(super::PreservedFileCapture {
                    relative_path: path,
                    capture_id: *capture_id,
                    native_id: version.recorded_identity(),
                    logical_len: version.logical_len,
                })?;
            }
        }
        Ok(())
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}
impl GuardedFileCapturePlan {
    pub fn preserved_ownership(&self) -> anyhow::Result<super::PreservedFileCapturePlan<'_>> {
        ensure!(
            self.format_version == 1
                && !self.anchor_id.is_nil()
                && !self.area.area_id.is_nil()
                && self.source_root_id.filesystem_id == self.area.filesystem_id
                && self.source_root_id.inode != 0
                && self.source_version.filesystem_id == self.area.filesystem_id
                && self.source_mode & libc::S_IFMT == libc::S_IFREG,
            "invalid preserved guarded file capture plan"
        );
        self.source_version.validate_preserved()?;
        for path in [
            &self.source_root,
            &self.area.path_hint,
            &self.area.volume_root_hint,
        ] {
            super::validate_preserved_path_hint(path)?;
        }
        super::validate_preserved_relative(&self.relative_path)?;
        let identity = self.source_version.recorded_identity();
        Ok(super::PreservedFileCapturePlan {
            record_format: self.format_version,
            capture_id: self.anchor_id,
            source_root: &self.source_root,
            relative_path: &self.relative_path,
            area: &self.area,
            logical_len: self.source_version.logical_len,
            recorded_root_identity: self.source_root_id,
            stable_root_identity: Some(self.source_root_id),
            recorded_file_identity: identity,
            stable_file_identity: Some(identity),
        })
    }

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

#[cfg(test)]
mod preserved_tests {
    use super::*;
    use mb_core::{canonical_bytes, decode_canonical};

    #[test]
    fn preserved_guarded_file_plan_keeps_original_wire_and_stable_ownership_without_io() {
        use std::os::unix::ffi::OsStrExt;
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("missing-source");
        let area_path = temporary.path().join("missing-area");
        let root_id = NativeFileId {
            filesystem_id: 7,
            inode: 8,
        };
        let area = StableAnchorAreaLocator {
            area_id: Uuid::from_u128(193),
            path_hint: area_path.clone(),
            filesystem_id: 7,
            volume_root_hint: temporary.path().to_path_buf(),
        };
        let wire = canonical_bytes(&(
            1_u16,
            Uuid::from_u128(192),
            source.as_os_str().as_bytes().to_vec(),
            root_id,
            b"file-\xff".to_vec(),
            (7_u64, 9_u64, 13_u64, 0_i64, 0_i64, 0_i64, 0_i64),
            0o100644_u32,
            &area,
        ))
        .unwrap();
        let plan: GuardedFileCapturePlan = decode_canonical(&wire).unwrap();
        assert_eq!(canonical_bytes(&plan).unwrap(), wire);
        let ownership = plan.preserved_ownership().unwrap();
        assert_eq!(ownership.source_root, source);
        assert_eq!(ownership.relative_path.as_os_str().as_bytes(), b"file-\xff");
        assert_eq!(ownership.area, &area);
        assert_eq!(ownership.logical_len, 13);
        assert_eq!(ownership.recorded_root_identity, root_id);
        assert_eq!(ownership.stable_root_identity, Some(root_id));
        assert_eq!(
            ownership.stable_file_identity,
            Some(NativeFileId {
                filesystem_id: 7,
                inode: 9
            })
        );
        let dispatch = crate::SourceFileCapturePlan::GuardedLinkFreezeV1(plan.clone());
        assert!(dispatch.backend_kind().require_supported().is_err());
        assert_eq!(
            dispatch.preserved_ownership().unwrap().capture_id,
            plan.anchor_id
        );
        for index in 0..14 {
            let mut bad = plan.clone();
            match index {
                0 => bad.format_version = 2,
                1 => bad.anchor_id = Uuid::nil(),
                2 => bad.area.area_id = Uuid::nil(),
                3 => bad.source_root_id.filesystem_id = 8,
                4 => bad.source_root_id.inode = 0,
                5 => bad.source_version.filesystem_id = 8,
                6 => bad.source_version.inode = 0,
                7 => bad.source_version.modified_nanos = 1_000_000_000,
                8 => bad.source_mode = 0o644,
                9 => bad.source_root = PathBuf::from("relative"),
                10 => bad.area.path_hint = PathBuf::from("/bad\0area"),
                11 => bad.area.volume_root_hint = PathBuf::from("relative"),
                12 => bad.relative_path = PathBuf::from("../escape"),
                _ => bad.relative_path = PathBuf::from("a\0b"),
            }
            assert!(bad.preserved_ownership().is_err(), "case {index}");
        }
        assert_eq!(canonical_bytes(&plan).unwrap(), wire);
        assert!(!source.exists());
        assert!(!area_path.exists());
        assert_eq!(std::fs::read_dir(temporary.path()).unwrap().count(), 0);
    }

    fn fixture() -> GuardedRootCapturePlan {
        let version = CaptureVersion {
            filesystem_id: 2,
            inode: 3,
            logical_len: 0,
            modified_secs: 4,
            modified_nanos: 5,
            changed_secs: 6,
            changed_nanos: 7,
        };
        GuardedRootCapturePlan {
            format_version: 2,
            anchor_id: Uuid::from_bytes([1; 16]),
            source_root: PathBuf::from("/absent-preserved-source"),
            area: StableAnchorAreaLocator {
                area_id: Uuid::from_bytes([2; 16]),
                path_hint: PathBuf::from("/absent-preserved-area"),
                filesystem_id: 2,
                volume_root_hint: PathBuf::from("/"),
            },
            root_version: version.clone(),
            root_mode: libc::S_IFDIR | 0o700,
            root_modified_secs: 4,
            root_modified_nanos: 5,
            entries: vec![GuardedRootEntry::File {
                path: PathBuf::from(OsString::from_vec(b"file-\xff".to_vec())),
                capture_id: Uuid::from_bytes([3; 16]),
                version: CaptureVersion {
                    inode: 8,
                    logical_len: 9,
                    ..version
                },
                mode: libc::S_IFREG | 0o600,
                modified_secs: 4,
                modified_nanos: 5,
            }],
        }
    }

    #[test]
    fn preserved_guarded_plan_validates_all_entries_before_visiting_pins() {
        let valid = fixture();
        let wire = mb_core::canonical_bytes(&valid).unwrap();
        let root = valid.preserved_ownership().unwrap();
        assert_eq!(
            root.stable_root_identity,
            Some(NativeFileId {
                filesystem_id: 2,
                inode: 3
            })
        );
        let mut pins = 0;
        valid
            .for_each_preserved_file_capture(|pin| {
                assert_eq!(pin.relative_path.as_os_str().as_bytes(), b"file-\xff");
                assert_eq!(pin.logical_len, 9);
                pins += 1;
                Ok(())
            })
            .unwrap();
        assert_eq!(pins, 1);
        assert_eq!(mb_core::canonical_bytes(&valid).unwrap(), wire);

        let mut utf8 = valid.clone();
        utf8.format_version = 1;
        if let GuardedRootEntry::File { path, .. } = &mut utf8.entries[0] {
            *path = PathBuf::from("file");
        }
        assert!(utf8.preserved_ownership().is_ok());

        let mut invalid = Vec::new();
        let mut value = valid.clone();
        value.format_version = 3;
        invalid.push(value);
        let mut value = valid.clone();
        value.format_version = 1;
        invalid.push(value);
        let mut value = valid.clone();
        value.area.filesystem_id = 42;
        invalid.push(value);
        let mut value = valid.clone();
        value.root_modified_nanos = 6;
        invalid.push(value);
        let mut value = valid.clone();
        value.entries.push(value.entries[0].clone());
        invalid.push(value);
        for mutation in 0..7 {
            let mut value = valid.clone();
            if let GuardedRootEntry::File {
                path,
                capture_id,
                version,
                mode,
                modified_nanos,
                ..
            } = &mut value.entries[0]
            {
                match mutation {
                    0 => *capture_id = value.anchor_id,
                    1 => version.filesystem_id = 42,
                    2 => *path = PathBuf::from("../escape"),
                    3 => *path = PathBuf::from("missing-parent/file"),
                    4 => *mode = libc::S_IFDIR | 0o700,
                    5 => version.inode = 0,
                    6 => *modified_nanos = 1_000_000_000,
                    _ => unreachable!(),
                }
            }
            invalid.push(value);
        }
        for value in invalid {
            let original = mb_core::canonical_bytes(&value).unwrap();
            let mut visits = 0;
            assert!(
                value
                    .for_each_preserved_file_capture(|_| {
                        visits += 1;
                        Ok(())
                    })
                    .is_err()
            );
            assert_eq!(visits, 0);
            assert_eq!(mb_core::canonical_bytes(&value).unwrap(), original);
        }
    }
}
