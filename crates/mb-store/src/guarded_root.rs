//! Bounded, read-only inventory for a future guarded whole-root capture.
//! The node must persist this plan before freezing any listed file. A root is
//! not eligible for enrollment until capture, replay, and retirement consume
//! this inventory through the versioned source-backend boundary.

use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use mb_core::V1_MAX_CATALOG_BYTES;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AnchorError, CaptureVersion, DirectoryStream, FilesystemIdentity, GIT_CATALOG_DIRECTORY,
    MAX_CAPTURE_DEPTH, MAX_CAPTURE_ENTRIES, MAX_RELATIVE_PATH_BYTES, StableAnchorAreaLocator,
    capture_version, filesystem_identity_for_file, git_catalog_marker_from_root, modified_parts,
    open_path_no_xdev_beneath, open_source_beneath, open_source_root, probe_guarded_link_freeze,
    reopen_pinned_file, unix_mode, validate_relative,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedRootCapturePlan {
    format_version: u16,
    anchor_id: Uuid,
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
        path: String,
        version: CaptureVersion,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        version: CaptureVersion,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
}

impl GuardedRootEntry {
    fn path(&self) -> &str {
        match self {
            Self::Directory { path, .. } | Self::File { path, .. } => path,
        }
    }

    fn version(&self) -> &CaptureVersion {
        match self {
            Self::Directory { version, .. } | Self::File { version, .. } => version,
        }
    }

    fn is_directory(&self) -> bool {
        matches!(self, Self::Directory { .. })
    }
}

impl GuardedRootCapturePlan {
    pub fn plan(source_root: impl AsRef<Path>) -> Result<Self, AnchorError> {
        let source_root = source_root
            .as_ref()
            .canonicalize()
            .map_err(|_| AnchorError::InvalidRoot)?;
        probe_guarded_link_freeze(&source_root)?;
        let root = open_source_root(&source_root)?;
        let root_metadata = root.metadata()?;
        if !root_metadata.is_dir() {
            return Err(AnchorError::InvalidRoot);
        }
        let filesystem = filesystem_identity_for_file(&root)?;
        let root_version = capture_version(filesystem.stable_id, &root_metadata);
        let (root_modified_secs, root_modified_nanos) = modified_parts(&root_metadata);
        let entries = scan_root_inventory(&source_root, &root, filesystem, &root_version)?;
        let area = StableAnchorAreaLocator::prepare_for_root(&source_root)?;
        if area.filesystem_id != filesystem.stable_id {
            return Err(AnchorError::FilesystemChanged);
        }
        let plan = Self {
            format_version: 1,
            anchor_id: Uuid::new_v4(),
            source_root,
            area,
            root_version,
            root_mode: unix_mode(&root_metadata),
            root_modified_secs,
            root_modified_nanos,
            entries,
        };
        if mb_core::canonical_bytes(&plan)
            .map_err(|_| AnchorError::CatalogTooLarge)?
            .len()
            > V1_MAX_CATALOG_BYTES / 2
        {
            return Err(AnchorError::CatalogTooLarge);
        }
        Ok(plan)
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub fn anchor_id(&self) -> Uuid {
        self.anchor_id
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

fn scan_root_inventory(
    source_root: &Path,
    root: &File,
    filesystem: FilesystemIdentity,
    root_version: &CaptureVersion,
) -> Result<Vec<GuardedRootEntry>, AnchorError> {
    let mut entries = Vec::new();
    scan_directory(
        source_root,
        root,
        root,
        filesystem,
        Path::new(""),
        0,
        &mut entries,
    )?;
    if filesystem_identity_for_file(root)? != filesystem
        || capture_version(filesystem.stable_id, &root.metadata()?) != *root_version
    {
        return Err(AnchorError::SourceChanged(PathBuf::new()));
    }
    for entry in &entries {
        let path = Path::new(entry.path());
        let file = open_source_beneath(root, path, entry.is_directory())?;
        if filesystem_identity_for_file(&file)? != filesystem
            || capture_version(filesystem.stable_id, &file.metadata()?) != *entry.version()
        {
            return Err(AnchorError::SourceChanged(path.to_path_buf()));
        }
    }
    entries.sort_by(|left, right| left.path().cmp(right.path()));
    Ok(entries)
}

fn scan_directory(
    source_root: &Path,
    root: &File,
    directory: &File,
    filesystem: FilesystemIdentity,
    relative_directory: &Path,
    depth: usize,
    entries: &mut Vec<GuardedRootEntry>,
) -> Result<(), AnchorError> {
    let mut stream = DirectoryStream::open(directory)?;
    while let Some(name) = stream.next_name()? {
        if entries.len() >= MAX_CAPTURE_ENTRIES {
            return Err(AnchorError::CatalogTooLarge);
        }
        let child_depth = depth.checked_add(1).ok_or(AnchorError::CatalogTooLarge)?;
        if child_depth > MAX_CAPTURE_DEPTH {
            return Err(AnchorError::CatalogTooLarge);
        }
        let component = Path::new(std::ffi::OsStr::from_bytes(name.as_bytes()));
        let relative = relative_directory.join(component);
        validate_relative(&relative)?;
        let path = relative
            .to_str()
            .ok_or(AnchorError::NonUtf8Path)?
            .to_owned();
        if path.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(AnchorError::CatalogTooLarge);
        }
        if depth == 0
            && name.as_bytes() == GIT_CATALOG_DIRECTORY.as_bytes()
            && git_catalog_marker_from_root(root)?.is_some()
        {
            continue;
        }
        let pinned = match open_path_no_xdev_beneath(directory, component) {
            Ok(file) => file,
            Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                return Err(AnchorError::NestedFilesystem(source_root.join(relative)));
            }
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Err(AnchorError::Symlink(relative));
            }
            Err(error) => return Err(error.into()),
        };
        let pinned_metadata = pinned.metadata()?;
        if pinned_metadata.file_type().is_symlink() {
            return Err(AnchorError::Symlink(relative));
        }
        let is_directory = pinned_metadata.is_dir();
        if !is_directory && !pinned_metadata.is_file() {
            return Err(AnchorError::UnsupportedObject(relative));
        }
        let file = reopen_pinned_file(&pinned, is_directory, &relative)?;
        if filesystem_identity_for_file(&file)? != filesystem {
            return Err(AnchorError::NestedFilesystem(source_root.join(relative)));
        }
        let metadata = file.metadata()?;
        if !is_directory && metadata.nlink() != 1 {
            return Err(AnchorError::UnsafeHardLink(relative));
        }
        let (modified_secs, modified_nanos) = modified_parts(&metadata);
        let version = capture_version(filesystem.stable_id, &metadata);
        if is_directory {
            entries.push(GuardedRootEntry::Directory {
                path,
                version,
                mode: unix_mode(&metadata),
                modified_secs,
                modified_nanos,
            });
            scan_directory(
                source_root,
                root,
                &file,
                filesystem,
                &relative,
                child_depth,
                entries,
            )?;
        } else {
            entries.push(GuardedRootEntry::File {
                path,
                version,
                mode: unix_mode(&metadata),
                modified_secs,
                modified_nanos,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::{scan_root_inventory, *};

    fn inventory(root: &Path) -> Result<Vec<GuardedRootEntry>, AnchorError> {
        let directory = open_source_root(root)?;
        let filesystem = filesystem_identity_for_file(&directory)?;
        let root_version = capture_version(filesystem.stable_id, &directory.metadata()?);
        scan_root_inventory(root, &directory, filesystem, &root_version)
    }

    #[test]
    fn inventory_is_sorted_and_retains_exact_file_versions() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("nested")).unwrap();
        fs::write(root.join("z"), b"raw\r\nbytes\0").unwrap();
        fs::write(root.join("nested/a"), b"first").unwrap();
        let entries = inventory(&root).unwrap();
        assert_eq!(
            entries
                .iter()
                .map(GuardedRootEntry::path)
                .collect::<Vec<_>>(),
            ["nested", "nested/a", "z"]
        );
        let GuardedRootEntry::File { version, .. } = &entries[2] else {
            panic!("expected regular file");
        };
        assert_eq!(version.logical_len, b"raw\r\nbytes\0".len() as u64);
    }

    #[test]
    fn inventory_rejects_symlinks_and_hard_link_aliases() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"data").unwrap();
        fs::hard_link(root.join("file"), root.join("alias")).unwrap();
        assert!(matches!(
            inventory(&root),
            Err(AnchorError::UnsafeHardLink(_))
        ));
        fs::remove_file(root.join("alias")).unwrap();
        std::os::unix::fs::symlink("file", root.join("link")).unwrap();
        assert!(matches!(inventory(&root), Err(AnchorError::Symlink(_))));
    }

    #[test]
    fn inventory_excludes_only_a_marked_git_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let catalog = root.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir(&root).unwrap();
        fs::create_dir(&catalog).unwrap();
        std::os::unix::fs::symlink("missing", catalog.join("unreadable-link")).unwrap();
        assert!(matches!(inventory(&root), Err(AnchorError::Symlink(_))));
        fs::write(
            catalog.join(super::super::GIT_CATALOG_MARKER_FILE),
            super::super::git_catalog_marker_bytes(Uuid::new_v4()),
        )
        .unwrap();
        assert!(inventory(&root).unwrap().is_empty());
    }
}
