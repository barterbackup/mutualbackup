use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;

const AREA_PREFIX: &str = ".mutualbackup-anchors";
const AREA_MARKER: &str = ".mutualbackup-anchor-area-v1";
const AREA_MAGIC: &str = "mutualbackup-anchor-area-v1";

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("source root must be an existing directory")]
    InvalidRoot,
    #[error("the source root needs a writable parent on the same filesystem")]
    NoExternalAnchorLocation,
    #[error("non-UTF-8 paths are not supported by the v1 prototype")]
    NonUtf8Path,
    #[error("symlinks are not supported by the v1 reflink prototype: {0}")]
    Symlink(PathBuf),
    #[error("unsupported filesystem object in protected tree: {0}")]
    UnsupportedObject(PathBuf),
    #[error("unsafe relative path")]
    UnsafePath,
    #[error("an unrecognized or unsafe source-anchor area already exists: {0}")]
    AnchorAreaCollision(PathBuf),
    #[error("source changed while it was being captured: {0}")]
    SourceChanged(PathBuf),
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
        modified_secs: i64,
        modified_nanos: u32,
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
pub struct AnchorAreaLocator {
    pub area_id: Uuid,
    pub path_hint: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorFileLocator {
    pub area: AnchorAreaLocator,
    pub anchor_id: Uuid,
    pub relative_path: String,
}

impl AnchorFileLocator {
    pub fn open(&self) -> Result<File, AnchorError> {
        validate_relative(Path::new(&self.relative_path))?;
        validate_anchor_area(&self.area)?;
        open_anchor_beneath(
            &self.area.path_hint,
            self.anchor_id,
            Path::new(&self.relative_path),
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AnchorManifest {
    pub format_version: u16,
    pub anchor_id: Uuid,
    pub source_root_hint: PathBuf,
    pub area: AnchorAreaLocator,
    pub root_mode: u32,
    pub root_modified_secs: i64,
    pub root_modified_nanos: u32,
    pub entries: Vec<CapturedEntry>,
}

impl AnchorManifest {
    pub fn file_locator(&self, relative_path: String) -> Result<AnchorFileLocator, AnchorError> {
        validate_relative(Path::new(&relative_path))?;
        Ok(AnchorFileLocator {
            area: self.area.clone(),
            anchor_id: self.anchor_id,
            relative_path,
        })
    }
}

pub struct ReflinkAnchor;

impl ReflinkAnchor {
    pub fn capture(source_root: impl AsRef<Path>) -> Result<AnchorManifest, AnchorError> {
        let source_root = source_root
            .as_ref()
            .canonicalize()
            .map_err(|_| AnchorError::InvalidRoot)?;
        let root_file = open_source_root(&source_root)?;
        let root_metadata = root_file.metadata()?;
        if !root_metadata.is_dir() {
            return Err(AnchorError::InvalidRoot);
        }
        probe_reflink(&source_root)?;

        let area = ensure_anchor_area(&source_root, &root_metadata)?;
        let anchor_id = Uuid::new_v4();
        let staging_name = format!(".staging-{anchor_id}");
        let staging = area.path_hint.join(&staging_name);
        let anchor_root = area.path_hint.join(anchor_id.to_string());
        create_private_dir_new(&staging)?;

        let capture_result = capture_entries(&source_root, &root_file, &root_metadata, &staging);
        let entries = match capture_result {
            Ok(entries) => entries,
            Err(error) => {
                let _ = fs::remove_dir_all(&staging);
                return Err(error);
            }
        };
        sync_tree_bottom_up(&staging)?;
        rename_no_replace(&staging, &anchor_root)?;
        sync_directory(&area.path_hint)?;
        let (root_modified_secs, root_modified_nanos) = modified_parts(&root_metadata);
        Ok(AnchorManifest {
            format_version: 1,
            anchor_id,
            source_root_hint: source_root,
            area,
            root_mode: unix_mode(&root_metadata),
            root_modified_secs,
            root_modified_nanos,
            entries,
        })
    }
}

pub fn probe_reflink(root: impl AsRef<Path>) -> Result<(), AnchorError> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(AnchorError::InvalidRoot);
    }
    let parent = root.parent().ok_or(AnchorError::NoExternalAnchorLocation)?;
    let probe_dir = parent.join(format!(".mutualbackup-probe-{}", Uuid::new_v4()));
    create_private_dir_new(&probe_dir)?;
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

        reflink_open_file(&source, &clone_path).map_err(AnchorError::ReflinkUnavailable)?;
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
    sync_directory(parent)?;
    Ok(())
}

fn capture_entries(
    source_root: &Path,
    root_file: &File,
    root_metadata: &fs::Metadata,
    staging: &Path,
) -> Result<Vec<CapturedEntry>, AnchorError> {
    let mut entries = Vec::new();
    let mut directory_versions = vec![(
        PathBuf::new(),
        root_file.try_clone()?,
        root_metadata.clone(),
    )];
    for entry in WalkDir::new(source_root).follow_links(false) {
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
        let file = open_source_beneath(root_file, relative, entry.file_type().is_dir())?;
        let before = file.metadata()?;
        if before.file_type().is_symlink() {
            return Err(AnchorError::Symlink(relative.to_path_buf()));
        }
        let destination = staging.join(relative);
        if before.is_dir() {
            create_private_dir_new(&destination)?;
            let (modified_secs, modified_nanos) = modified_parts(&before);
            entries.push(CapturedEntry::Directory {
                path: relative_string,
                mode: unix_mode(&before),
                modified_secs,
                modified_nanos,
            });
            directory_versions.push((relative.to_path_buf(), file, before));
        } else if before.is_file() {
            if let Some(parent) = destination.parent() {
                create_private_dir(parent)?;
            }
            reflink_open_file(&file, &destination).map_err(AnchorError::ReflinkUnavailable)?;
            let after = file.metadata()?;
            let captured = fs::symlink_metadata(&destination)?;
            if !same_capture_version(&before, &after)
                || captured.len() != after.len()
                || !captured.is_file()
            {
                let _ = fs::remove_file(&destination);
                return Err(AnchorError::SourceChanged(relative.to_path_buf()));
            }
            seal_anchor_file(&destination)?;
            let (modified_secs, modified_nanos) = modified_parts(&after);
            entries.push(CapturedEntry::File {
                path: relative_string,
                mode: unix_mode(&after),
                logical_len: after.len(),
                modified_secs,
                modified_nanos,
            });
        } else {
            return Err(AnchorError::UnsupportedObject(relative.to_path_buf()));
        }
    }
    for (relative, directory, before) in directory_versions {
        if !same_capture_version(&before, &directory.metadata()?) {
            return Err(AnchorError::SourceChanged(relative));
        }
    }
    entries.sort_by(|left, right| entry_path(left).cmp(entry_path(right)));
    Ok(entries)
}

fn ensure_anchor_area(
    source_root: &Path,
    root_metadata: &fs::Metadata,
) -> Result<AnchorAreaLocator, AnchorError> {
    let parent = source_root
        .parent()
        .ok_or(AnchorError::NoExternalAnchorLocation)?;
    let area_path = parent.join(format!(
        "{AREA_PREFIX}-{}",
        source_identity_name(root_metadata)
    ));
    match fs::create_dir(&area_path) {
        Ok(()) => {
            set_private_directory(&area_path)?;
            let area_id = Uuid::new_v4();
            let marker_path = area_path.join(AREA_MARKER);
            let mut marker = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&marker_path)?;
            writeln!(marker, "{AREA_MAGIC}")?;
            writeln!(marker, "{area_id}")?;
            marker.sync_all()?;
            seal_anchor_file(&marker_path)?;
            sync_directory(&area_path)?;
            sync_directory(parent)?;
            Ok(AnchorAreaLocator {
                area_id,
                path_hint: area_path,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let area_id = read_area_marker(&area_path)
                .map_err(|_| AnchorError::AnchorAreaCollision(area_path.clone()))?;
            let locator = AnchorAreaLocator {
                area_id,
                path_hint: area_path,
            };
            validate_anchor_area(&locator)?;
            Ok(locator)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_anchor_area(area: &AnchorAreaLocator) -> Result<(), AnchorError> {
    let metadata = fs::symlink_metadata(&area.path_hint)
        .map_err(|_| AnchorError::AnchorAreaCollision(area.path_hint.clone()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()));
    }
    let actual = read_area_marker(&area.path_hint)
        .map_err(|_| AnchorError::AnchorAreaCollision(area.path_hint.clone()))?;
    if actual != area.area_id {
        return Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()));
    }
    Ok(())
}

fn read_area_marker(area: &Path) -> Result<Uuid, AnchorError> {
    let marker = area.join(AREA_MARKER);
    let metadata = fs::symlink_metadata(&marker)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 128 {
        return Err(AnchorError::AnchorAreaCollision(area.to_path_buf()));
    }
    let bytes = fs::read_to_string(marker)?;
    let mut lines = bytes.lines();
    if lines.next() != Some(AREA_MAGIC) {
        return Err(AnchorError::AnchorAreaCollision(area.to_path_buf()));
    }
    let id = lines
        .next()
        .ok_or_else(|| AnchorError::AnchorAreaCollision(area.to_path_buf()))?
        .parse()
        .map_err(|_| AnchorError::AnchorAreaCollision(area.to_path_buf()))?;
    if lines.next().is_some() {
        return Err(AnchorError::AnchorAreaCollision(area.to_path_buf()));
    }
    Ok(id)
}

fn entry_path(entry: &CapturedEntry) -> &str {
    match entry {
        CapturedEntry::Directory { path, .. } | CapturedEntry::File { path, .. } => path,
    }
}

fn validate_relative(path: &Path) -> Result<(), AnchorError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(AnchorError::UnsafePath);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_source_root(path: &Path) -> Result<File, AnchorError> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?)
}

#[cfg(not(target_os = "linux"))]
fn open_source_root(_path: &Path) -> Result<File, AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe reflink capture is currently implemented only on Linux",
    )))
}

#[cfg(target_os = "linux")]
fn open_source_beneath(root: &File, relative: &Path, directory: bool) -> Result<File, AnchorError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    let path =
        CString::new(relative.as_os_str().as_bytes()).map_err(|_| AnchorError::UnsafePath)?;
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    if directory {
        flags |= libc::O_DIRECTORY;
    }
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ELOOP) {
            return Err(AnchorError::Symlink(relative.to_path_buf()));
        }
        return Err(error.into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor as i32) })
}

#[cfg(not(target_os = "linux"))]
fn open_source_beneath(
    _root: &File,
    _relative: &Path,
    _directory: bool,
) -> Result<File, AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "descriptor-relative capture is currently implemented only on Linux",
    )))
}

#[cfg(target_os = "linux")]
fn open_anchor_beneath(area: &Path, anchor_id: Uuid, relative: &Path) -> Result<File, AnchorError> {
    let area_file = open_source_root(area)?;
    let relative = PathBuf::from(anchor_id.to_string()).join(relative);
    open_source_beneath(&area_file, &relative, false)
}

#[cfg(not(target_os = "linux"))]
fn open_anchor_beneath(
    _area: &Path,
    _anchor_id: Uuid,
    _relative: &Path,
) -> Result<File, AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "stable anchor access is currently implemented only on Linux",
    )))
}

#[cfg(target_os = "linux")]
fn reflink_open_file(source: &File, destination: &Path) -> Result<(), std::io::Error> {
    use std::os::fd::AsRawFd;

    const FICLONE: u64 = 0x4004_9409;
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
fn reflink_open_file(_source: &File, _destination: &Path) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "reflink backend is currently implemented only on Linux",
    ))
}

#[cfg(target_os = "linux")]
fn rename_no_replace(source: &Path, destination: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes())?;
    let destination = CString::new(destination.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_no_replace(_source: &Path, _destination: &Path) -> Result<(), std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "atomic no-replace directory rename is currently implemented only on Linux",
    ))
}

#[cfg(unix)]
fn same_capture_version(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(not(unix))]
fn same_capture_version(before: &fs::Metadata, after: &fs::Metadata) -> bool {
    before.len() == after.len() && before.modified().ok() == after.modified().ok()
}

#[cfg(unix)]
fn source_identity_name(metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{:x}-{:x}", metadata.dev(), metadata.ino())
}

#[cfg(not(unix))]
fn source_identity_name(metadata: &fs::Metadata) -> String {
    format!("{:x}", metadata.len())
}

fn modified_parts(metadata: &fs::Metadata) -> (i64, u32) {
    let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
    match modified.duration_since(std::time::UNIX_EPOCH) {
        Ok(duration) => (
            duration.as_secs().min(i64::MAX as u64) as i64,
            duration.subsec_nanos(),
        ),
        Err(error) => {
            let duration = error.duration();
            let seconds = duration.as_secs().min(i64::MAX as u64) as i64;
            if duration.subsec_nanos() == 0 {
                (-seconds, 0)
            } else {
                (
                    -seconds.saturating_sub(1),
                    1_000_000_000 - duration.subsec_nanos(),
                )
            }
        }
    }
}

fn create_private_dir_new(path: &Path) -> Result<(), std::io::Error> {
    fs::create_dir(path)?;
    set_private_directory(path)
}

fn create_private_dir(path: &Path) -> Result<(), std::io::Error> {
    match fs::create_dir(path) {
        Ok(()) => set_private_directory(path),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::AlreadyExists,
                    "path component is not a safe directory",
                ))
            }
        }
        Err(error) => Err(error),
    }
}

fn set_private_directory(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let _ = path;
    Ok(())
}

fn seal_anchor_file(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o400))?;
    }
    File::open(path)?.sync_all()
}

fn sync_tree_bottom_up(root: &Path) -> Result<(), std::io::Error> {
    let mut directories = WalkDir::new(root)
        .min_depth(0)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_dir())
        .map(|entry| entry.into_path())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for directory in directories {
        sync_directory(&directory)?;
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
        assert!(validate_relative(Path::new("/absolute")).is_err());
    }
}
