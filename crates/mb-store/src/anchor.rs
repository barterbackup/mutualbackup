use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;

const ANCHOR_DIRECTORY: &str = ".mutualbackup-anchors";

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("source root must be an existing directory")]
    InvalidRoot,
    #[error("non-UTF-8 paths are not supported by the v1 prototype")]
    NonUtf8Path,
    #[error("symlinks are not supported by the v1 reflink prototype: {0}")]
    Symlink(PathBuf),
    #[error("unsafe relative path")]
    UnsafePath,
    #[error("reflink is unavailable for this source filesystem: {0}")]
    ReflinkUnavailable(std::io::Error),
    #[error("filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("directory walk failed: {0}")]
    Walk(#[from] walkdir::Error),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CapturedEntry {
    Directory {
        path: String,
        mode: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorManifest {
    pub anchor_id: Uuid,
    pub source_root: PathBuf,
    pub anchor_root: PathBuf,
    pub entries: Vec<CapturedEntry>,
}

pub struct ReflinkAnchor;

impl ReflinkAnchor {
    pub fn capture(source_root: impl AsRef<Path>) -> Result<AnchorManifest, AnchorError> {
        let source_root = source_root
            .as_ref()
            .canonicalize()
            .map_err(|_| AnchorError::InvalidRoot)?;
        if !source_root.is_dir() {
            return Err(AnchorError::InvalidRoot);
        }
        probe_reflink(&source_root)?;

        let anchor_id = Uuid::new_v4();
        let anchors = source_root.join(ANCHOR_DIRECTORY);
        create_private_dir(&anchors)?;
        let staging = anchors.join(format!(".staging-{anchor_id}"));
        let anchor_root = anchors.join(anchor_id.to_string());
        create_private_dir(&staging)?;

        let capture_result = capture_entries(&source_root, &anchors, &staging);
        let entries = match capture_result {
            Ok(entries) => entries,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        sync_directory(&staging)?;
        fs::rename(&staging, &anchor_root)?;
        sync_directory(&anchors)?;
        Ok(AnchorManifest {
            anchor_id,
            source_root,
            anchor_root,
            entries,
        })
    }
}

pub fn probe_reflink(root: impl AsRef<Path>) -> Result<(), AnchorError> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(AnchorError::InvalidRoot);
    }
    let probe_dir = root.join(format!(".mutualbackup-probe-{}", Uuid::new_v4()));
    create_private_dir(&probe_dir)?;
    let source_path = probe_dir.join("source");
    let clone_path = probe_dir.join("clone");
    let result = (|| {
        let mut source = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&source_path)?;
        source.set_len(1024 * 1024)?;
        source.seek(SeekFrom::Start(4096))?;
        source.write_all(b"source-before-clone")?;
        source.sync_all()?;

        reflink_file(&source_path, &clone_path).map_err(AnchorError::ReflinkUnavailable)?;
        source.seek(SeekFrom::Start(4096))?;
        source.write_all(b"source-after-clone!")?;
        source.sync_all()?;

        let mut cloned = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&clone_path)?;
        cloned.seek(SeekFrom::Start(4096))?;
        let mut bytes = [0_u8; 19];
        cloned.read_exact(&mut bytes)?;
        if &bytes != b"source-before-clone" {
            return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
                "clone changed when source was edited",
            )));
        }
        cloned.seek(SeekFrom::Start(4096))?;
        cloned.write_all(b"clone-independent!!")?;
        cloned.sync_all()?;
        source.seek(SeekFrom::Start(4096))?;
        source.read_exact(&mut bytes)?;
        if &bytes != b"source-after-clone!" {
            return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
                "source changed when clone was edited",
            )));
        }
        Ok(())
    })();
    let cleanup = fs::remove_dir_all(&probe_dir);
    result?;
    cleanup?;
    Ok(())
}

fn capture_entries(
    source_root: &Path,
    anchors: &Path,
    staging: &Path,
) -> Result<Vec<CapturedEntry>, AnchorError> {
    let mut entries = Vec::new();
    let walker = WalkDir::new(source_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| entry.path() != anchors);
    for entry in walker {
        let entry = entry?;
        if entry.path() == source_root {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(source_root)
            .map_err(|_| AnchorError::UnsafePath)?;
        validate_relative(relative)?;
        let relative_string = relative
            .to_str()
            .ok_or(AnchorError::NonUtf8Path)?
            .to_owned();
        let metadata = fs::symlink_metadata(entry.path())?;
        if metadata.file_type().is_symlink() {
            return Err(AnchorError::Symlink(relative.to_path_buf()));
        }
        let destination = staging.join(relative);
        if metadata.is_dir() {
            create_private_dir(&destination)?;
            entries.push(CapturedEntry::Directory {
                path: relative_string,
                mode: unix_mode(&metadata),
            });
        } else if metadata.is_file() {
            if let Some(parent) = destination.parent() {
                create_private_dir(parent)?;
            }
            reflink_file(entry.path(), &destination).map_err(AnchorError::ReflinkUnavailable)?;
            let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
            let since_epoch = modified
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            entries.push(CapturedEntry::File {
                path: relative_string,
                mode: unix_mode(&metadata),
                logical_len: metadata.len(),
                modified_secs: since_epoch.as_secs().min(i64::MAX as u64) as i64,
                modified_nanos: since_epoch.subsec_nanos(),
            });
        }
    }
    entries.sort_by(|left, right| entry_path(left).cmp(entry_path(right)));
    Ok(entries)
}

fn entry_path(entry: &CapturedEntry) -> &str {
    match entry {
        CapturedEntry::Directory { path, .. } | CapturedEntry::File { path, .. } => path,
    }
}

fn validate_relative(path: &Path) -> Result<(), AnchorError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, Component::Normal(value) if value != OsStr::new(ANCHOR_DIRECTORY))
        })
    {
        return Err(AnchorError::UnsafePath);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reflink_file(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;

    // libc exposes ioctl's request as c_ulong on glibc and c_int on musl.
    // This Linux UAPI constant fits both representations.
    const FICLONE: u64 = 0x4004_9409;
    let source = File::open(source)?;
    let destination_file = OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(destination)?;
    let result = unsafe {
        libc::ioctl(
            destination_file.as_raw_fd(),
            FICLONE as _,
            source.as_raw_fd(),
        )
    };
    if result == -1 {
        let error = std::io::Error::last_os_error();
        drop(destination_file);
        let _ = fs::remove_file(destination);
        return Err(error);
    }
    destination_file.sync_all()?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn reflink_file(_source: &Path, _destination: &Path) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "reflink backend is currently implemented only on Linux",
    ))
}

fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    let _ = path;
    Ok(())
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn unix_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unsafe_relative_paths() {
        assert!(validate_relative(Path::new("good/file")).is_ok());
        assert!(validate_relative(Path::new("../escape")).is_err());
        assert!(validate_relative(Path::new(ANCHOR_DIRECTORY)).is_err());
    }
}
