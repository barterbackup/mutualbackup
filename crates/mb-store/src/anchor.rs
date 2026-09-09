use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use mb_core::{canonical_bytes, decode_canonical};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use walkdir::WalkDir;

const AREA_PREFIX: &str = ".mutualbackup-anchors";
const AREA_MARKER: &str = ".mutualbackup-anchor-area-v1";
const AREA_MAGIC: &str = "mutualbackup-anchor-area-v1";
const CAPTURE_MANIFEST_PREFIX: &str = ".mutualbackup-capture-manifest-v1-";
const MAX_CAPTURE_ENTRIES: usize = 8_192;
const MAX_CAPTURE_EXTENTS: usize = 65_536;
const MAX_CAPTURE_DEPTH: usize = 256;
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;
#[cfg(target_os = "linux")]
const CLEANUP_BATCH_ENTRIES: usize = 64;
const FAILED_AREA_SCAN_RETRY: Duration = Duration::from_secs(60);

static ANCHOR_AREA_INDEX: OnceLock<Mutex<BTreeMap<Uuid, AnchorAreaIndexEntry>>> = OnceLock::new();

#[cfg(test)]
type CaptureDirectoryHook = Box<dyn FnMut(&Path)>;

#[cfg(test)]
thread_local! {
    static BEFORE_CAPTURE_WALK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static BEFORE_CAPTURE_DIRECTORY_READ: std::cell::RefCell<Option<CaptureDirectoryHook>> =
        std::cell::RefCell::new(None);
    static AFTER_CAPTURE_DIRECTORY_READ: std::cell::RefCell<Option<CaptureDirectoryHook>> =
        std::cell::RefCell::new(None);
}

#[derive(Clone)]
enum AnchorAreaIndexEntry {
    Resolved(PathBuf),
    MissingUntil(Instant),
}

#[derive(Debug, Error)]
pub enum AnchorError {
    #[error("source root must be an existing directory")]
    InvalidRoot,
    #[error("the source root needs a writable parent on the same filesystem")]
    NoExternalAnchorLocation,
    #[error("the protected root crosses into another filesystem mount at {0}")]
    NestedFilesystem(PathBuf),
    #[error("the protected root filesystem changed while it was being probed")]
    FilesystemChanged,
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
    #[error("owned directory is missing, replaced, mounted, or unsafe to remove: {0}")]
    UnsafeOwnedDirectory(PathBuf),
    #[error("the in-process anchor-area index is unavailable")]
    AnchorAreaIndexUnavailable,
    #[error("source changed while it was being captured: {0}")]
    SourceChanged(PathBuf),
    #[error("source tree exceeds the bounded v1 capture catalog")]
    CatalogTooLarge,
    #[error("reflink is unavailable for this source filesystem: {0}")]
    ReflinkUnavailable(std::io::Error),
    #[error("filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("directory walk failed: {0}")]
    Walk(#[from] walkdir::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FilesystemIdentity {
    /// A domain-separated digest of the filesystem's external UUID and, on
    /// Btrfs, its subvolume tree ID. Unlike `device` and `mount_id`, this
    /// remains stable when the same filesystem is remounted.
    pub stable_id: u64,
    pub device: u64,
    pub mount_id: u64,
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
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        native_id: NativeFileId,
        data_extents: Vec<FileExtent>,
    },
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct NativeFileId {
    pub filesystem_id: u64,
    pub inode: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileExtent {
    pub offset: u64,
    pub logical_len: u64,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StableAnchorAreaLocator {
    pub area_id: Uuid,
    pub path_hint: PathBuf,
    pub filesystem_id: u64,
    pub volume_root_hint: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StableAnchorFileLocator {
    pub area: StableAnchorAreaLocator,
    pub anchor_id: Uuid,
    pub relative_path: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReflinkCapturePlan {
    format_version: u16,
    anchor_id: Uuid,
    source_root: PathBuf,
    area: StableAnchorAreaLocator,
    root_version: CaptureVersion,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
}

impl ReflinkCapturePlan {
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CaptureVersion {
    filesystem_id: u64,
    inode: u64,
    logical_len: u64,
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
}

impl StableAnchorFileLocator {
    pub fn open(&self) -> Result<File, AnchorError> {
        self.open_with_area_hint(None).map(|(file, _)| file)
    }

    pub fn open_with_area_hint(
        &self,
        area_hint: Option<&Path>,
    ) -> Result<(File, PathBuf), AnchorError> {
        validate_relative(Path::new(&self.relative_path))?;
        let area = resolve_anchor_area_with_hint(&self.area, area_hint)?;
        let file = open_anchor_beneath(&area, self.anchor_id, Path::new(&self.relative_path))?;
        Ok((file, area))
    }
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StableAnchorManifest {
    pub format_version: u16,
    pub anchor_id: Uuid,
    pub source_root_hint: PathBuf,
    pub area: StableAnchorAreaLocator,
    pub root_mode: u32,
    pub root_modified_secs: i64,
    pub root_modified_nanos: u32,
    pub entries: Vec<CapturedEntry>,
}

impl StableAnchorManifest {
    pub fn file_locator(
        &self,
        relative_path: String,
    ) -> Result<StableAnchorFileLocator, AnchorError> {
        validate_relative(Path::new(&relative_path))?;
        Ok(StableAnchorFileLocator {
            area: self.area.clone(),
            anchor_id: self.anchor_id,
            relative_path,
        })
    }

    pub fn remove(&self) -> Result<(), AnchorError> {
        let area = resolve_anchor_area(&self.area)?;
        remove_stable_capture_directory(&area, &self.area, &self.anchor_id.to_string())?;
        sync_directory(&area)?;
        Ok(())
    }
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

    pub fn remove(&self) -> Result<(), AnchorError> {
        validate_anchor_area(&self.area)?;
        remove_legacy_capture_directory(
            &self.area.path_hint,
            self.area.area_id,
            &self.anchor_id.to_string(),
        )?;
        sync_directory(&self.area.path_hint)?;
        Ok(())
    }
}

pub struct ReflinkAnchor;

#[cfg(target_os = "linux")]
pub fn directory_identity(path: impl AsRef<Path>) -> Result<NativeFileId, AnchorError> {
    let directory = open_source_root(path.as_ref())?;
    let metadata = directory.metadata()?;
    Ok(native_file_id(
        filesystem_identity_for_file(&directory)?.stable_id,
        &metadata,
    ))
}

#[cfg(not(target_os = "linux"))]
pub fn directory_identity(_path: impl AsRef<Path>) -> Result<NativeFileId, AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe directory identity is currently implemented only on Linux",
    )))
}

#[cfg(target_os = "linux")]
pub fn remove_owned_directory_tree(
    path: impl AsRef<Path>,
    expected: NativeFileId,
) -> Result<(), AnchorError> {
    let path = path.as_ref();
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let relative = path
        .file_name()
        .map(Path::new)
        .ok_or(AnchorError::UnsafePath)?;
    if relative.components().count() != 1 {
        return Err(AnchorError::UnsafePath);
    }
    let parent_file = open_source_root(parent)?;
    remove_directory_at_expected(&parent_file, relative, path, Some(expected)).map_err(
        |error| {
            if let AnchorError::AnchorAreaCollision(path) = error {
                AnchorError::UnsafeOwnedDirectory(path)
            } else {
                error
            }
        },
    )?;
    sync_directory(parent)?;
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn remove_owned_directory_tree(
    _path: impl AsRef<Path>,
    _expected: NativeFileId,
) -> Result<(), AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe directory cleanup is currently implemented only on Linux",
    )))
}

impl ReflinkAnchor {
    pub fn capture(source_root: impl AsRef<Path>) -> Result<StableAnchorManifest, AnchorError> {
        let plan = Self::plan(source_root)?;
        Self::capture_plan(&plan)
    }

    pub fn plan(source_root: impl AsRef<Path>) -> Result<ReflinkCapturePlan, AnchorError> {
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
        #[cfg(target_os = "linux")]
        let filesystem = filesystem_identity_for_file(&root_file)?;
        #[cfg(not(target_os = "linux"))]
        let filesystem = filesystem_identity(&source_root)?;
        let (root_modified_secs, root_modified_nanos) = modified_parts(&root_metadata);
        Ok(ReflinkCapturePlan {
            format_version: 1,
            anchor_id: Uuid::new_v4(),
            source_root,
            area,
            root_version: capture_version(filesystem.stable_id, &root_metadata),
            root_mode: unix_mode(&root_metadata),
            root_modified_secs,
            root_modified_nanos,
        })
    }

    pub fn capture_plan(plan: &ReflinkCapturePlan) -> Result<StableAnchorManifest, AnchorError> {
        if plan.format_version != 1 {
            return Err(AnchorError::InvalidRoot);
        }
        validate_stable_anchor_area(&plan.area.path_hint, plan.area.area_id)?;
        let staging_name = format!(".staging-{}", plan.anchor_id);
        let staging = plan.area.path_hint.join(&staging_name);
        let anchor_root = plan.area.path_hint.join(plan.anchor_id.to_string());
        if anchor_root.exists() {
            match read_planned_manifest(&anchor_root, plan) {
                Ok(manifest) => return Ok(manifest),
                Err(_) => Self::discard_capture(plan)?,
            }
        }
        remove_stable_capture_directory(&plan.area.path_hint, &plan.area, &staging_name)?;
        sync_directory(&plan.area.path_hint)?;

        let source_root = plan
            .source_root
            .canonicalize()
            .map_err(|_| AnchorError::InvalidRoot)?;
        if source_root != plan.source_root {
            return Err(AnchorError::InvalidRoot);
        }
        let root_file = open_source_root(&source_root)?;
        let root_metadata = root_file.metadata()?;
        #[cfg(target_os = "linux")]
        let filesystem = filesystem_identity_for_file(&root_file)?;
        #[cfg(not(target_os = "linux"))]
        let filesystem = filesystem_identity(&source_root)?;
        if !root_metadata.is_dir()
            || capture_version(filesystem.stable_id, &root_metadata) != plan.root_version
        {
            return Err(AnchorError::SourceChanged(PathBuf::new()));
        }
        if filesystem_identity(&plan.area.path_hint)?.stable_id != plan.area.filesystem_id {
            return Err(AnchorError::FilesystemChanged);
        }
        create_private_dir_new(&staging)?;

        let capture_result = (|| {
            let entries = capture_entries(
                &source_root,
                &root_file,
                &root_metadata,
                filesystem,
                &staging,
            )?;
            let manifest = StableAnchorManifest {
                format_version: 2,
                anchor_id: plan.anchor_id,
                source_root_hint: source_root.clone(),
                area: plan.area.clone(),
                root_mode: plan.root_mode,
                root_modified_secs: plan.root_modified_secs,
                root_modified_nanos: plan.root_modified_nanos,
                entries,
            };
            let manifest_path = staging.join(capture_manifest_name(plan.anchor_id));
            let mut manifest_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&manifest_path)?;
            let manifest_bytes = canonical_bytes(&manifest)
                .map_err(|error| std::io::Error::other(error.to_string()))?;
            manifest_file.write_all(&manifest_bytes)?;
            manifest_file.sync_all()?;
            seal_anchor_file(&manifest_path)?;
            sync_tree_bottom_up(&staging)?;
            rename_no_replace(&staging, &anchor_root)?;
            Ok::<_, AnchorError>(manifest)
        })();
        let manifest = match capture_result {
            Ok(manifest) => manifest,
            Err(error) => {
                let _ = remove_stable_capture_directory(
                    &plan.area.path_hint,
                    &plan.area,
                    &staging_name,
                );
                let _ = sync_directory(&plan.area.path_hint);
                return Err(error);
            }
        };
        if let Err(error) = sync_directory(&plan.area.path_hint) {
            let _ = remove_stable_capture_directory(
                &plan.area.path_hint,
                &plan.area,
                &plan.anchor_id.to_string(),
            );
            let _ = sync_directory(&plan.area.path_hint);
            return Err(error.into());
        }
        Ok(manifest)
    }

    pub fn discard_capture(plan: &ReflinkCapturePlan) -> Result<(), AnchorError> {
        if plan.format_version != 1 {
            return Err(AnchorError::InvalidRoot);
        }
        validate_stable_anchor_area(&plan.area.path_hint, plan.area.area_id)?;
        remove_stable_capture_directory(
            &plan.area.path_hint,
            &plan.area,
            &format!(".staging-{}", plan.anchor_id),
        )?;
        remove_stable_capture_directory(
            &plan.area.path_hint,
            &plan.area,
            &plan.anchor_id.to_string(),
        )?;
        sync_directory(&plan.area.path_hint)?;
        Ok(())
    }

    pub fn reconcile_capture(plan: &ReflinkCapturePlan) -> Result<(), AnchorError> {
        if plan.format_version != 1 {
            return Err(AnchorError::InvalidRoot);
        }
        validate_stable_anchor_area(&plan.area.path_hint, plan.area.area_id)?;
        let anchor_root = plan.area.path_hint.join(plan.anchor_id.to_string());
        if anchor_root.exists() {
            read_planned_manifest(&anchor_root, plan)?;
        }
        remove_stable_capture_directory(
            &plan.area.path_hint,
            &plan.area,
            &format!(".staging-{}", plan.anchor_id),
        )?;
        sync_directory(&plan.area.path_hint)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
const fn read_ioctl<T>(kind: u8, number: u8) -> libc::c_ulong {
    const IOC_NRSHIFT: u32 = 0;
    const IOC_TYPESHIFT: u32 = 8;
    const IOC_SIZESHIFT: u32 = 16;
    const IOC_DIRSHIFT: u32 = 30;
    const IOC_READ: u32 = 2;
    ((IOC_READ << IOC_DIRSHIFT)
        | ((kind as u32) << IOC_TYPESHIFT)
        | ((number as u32) << IOC_NRSHIFT)
        | ((std::mem::size_of::<T>() as u32) << IOC_SIZESHIFT)) as libc::c_ulong
}

#[cfg(target_os = "linux")]
const fn read_write_ioctl<T>(kind: u8, number: u8) -> libc::c_ulong {
    const IOC_NRSHIFT: u32 = 0;
    const IOC_TYPESHIFT: u32 = 8;
    const IOC_SIZESHIFT: u32 = 16;
    const IOC_DIRSHIFT: u32 = 30;
    const IOC_WRITE: u32 = 1;
    const IOC_READ: u32 = 2;
    (((IOC_READ | IOC_WRITE) << IOC_DIRSHIFT)
        | ((kind as u32) << IOC_TYPESHIFT)
        | ((number as u32) << IOC_NRSHIFT)
        | ((std::mem::size_of::<T>() as u32) << IOC_SIZESHIFT)) as libc::c_ulong
}

#[cfg(target_os = "linux")]
unsafe fn ioctl_read<T>(file: &File, kind: u8, number: u8, value: *mut T) -> libc::c_long {
    use std::os::fd::AsRawFd;

    // `libc::ioctl` exposes a target-libc-specific request type (`c_ulong` on
    // glibc, `c_int` on musl). The Linux syscall ABI accepts the same unsigned
    // 32-bit encoded request on both, so keep this small UAPI shim portable.
    unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            file.as_raw_fd(),
            read_ioctl::<T>(kind, number),
            value,
        )
    }
}

#[cfg(target_os = "linux")]
unsafe fn ioctl_read_write<T>(file: &File, kind: u8, number: u8, value: *mut T) -> libc::c_long {
    use std::os::fd::AsRawFd;

    unsafe {
        libc::syscall(
            libc::SYS_ioctl,
            file.as_raw_fd(),
            read_write_ioctl::<T>(kind, number),
            value,
        )
    }
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct FsUuid {
    len: u8,
    uuid: [u8; 16],
}
#[cfg(target_os = "linux")]
const _: () = assert!(std::mem::size_of::<FsUuid>() == 17);

#[cfg(target_os = "linux")]
#[repr(C)]
struct BtrfsFsInfo {
    max_id: u64,
    num_devices: u64,
    fsid: [u8; 16],
    nodesize: u32,
    sectorsize: u32,
    clone_alignment: u32,
    csum_type: u16,
    csum_size: u16,
    flags: u64,
    generation: u64,
    metadata_uuid: [u8; 16],
    reserved: [u8; 944],
}
#[cfg(target_os = "linux")]
const _: () = assert!(std::mem::size_of::<BtrfsFsInfo>() == 1024);

#[cfg(target_os = "linux")]
#[repr(C)]
struct BtrfsInodeLookup {
    tree_id: u64,
    object_id: u64,
    name: [u8; 4080],
}
#[cfg(target_os = "linux")]
const _: () = assert!(std::mem::size_of::<BtrfsInodeLookup>() == 4096);

#[cfg(target_os = "linux")]
fn ioctl_external_filesystem_uuid(file: &File) -> Result<Option<(u8, [u8; 16])>, AnchorError> {
    let mut uuid = std::mem::MaybeUninit::<FsUuid>::zeroed();
    let result = unsafe { ioctl_read(file, 0x15, 0, uuid.as_mut_ptr()) };
    if result != 0 {
        let error = std::io::Error::last_os_error();
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOTTY) | Some(libc::EOPNOTSUPP)
        ) {
            return Ok(None);
        }
        return Err(error.into());
    }
    let uuid = unsafe { uuid.assume_init() };
    if uuid.len == 0 || usize::from(uuid.len) > uuid.uuid.len() {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem returned an invalid external UUID",
        )));
    }
    Ok(Some((uuid.len, uuid.uuid)))
}

#[cfg(target_os = "linux")]
fn btrfs_filesystem_uuid(file: &File) -> Result<[u8; 16], AnchorError> {
    let mut info = std::mem::MaybeUninit::<BtrfsFsInfo>::zeroed();
    let result = unsafe { ioctl_read(file, 0x94, 31, info.as_mut_ptr()) };
    if result != 0 {
        return Err(AnchorError::ReflinkUnavailable(
            std::io::Error::last_os_error(),
        ));
    }
    Ok(unsafe { info.assume_init() }.fsid)
}

#[cfg(target_os = "linux")]
fn btrfs_subvolume_tree_id(file: &File) -> Result<u64, AnchorError> {
    // BTRFS_IOC_INO_LOOKUP permits this exact unprivileged query when tree ID
    // is zero and object ID names the subvolume root. Unlike GET_SUBVOL_INFO,
    // it also works on the descriptor returned by openat2 beneath our root.
    const BTRFS_FIRST_FREE_OBJECT_ID: u64 = 256;
    let mut lookup = BtrfsInodeLookup {
        tree_id: 0,
        object_id: BTRFS_FIRST_FREE_OBJECT_ID,
        name: [0; 4080],
    };
    let result = unsafe { ioctl_read_write(file, 0x94, 18, &mut lookup) };
    if result != 0 {
        return Err(AnchorError::ReflinkUnavailable(
            std::io::Error::last_os_error(),
        ));
    }
    if lookup.tree_id == 0 {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "Btrfs returned an invalid subvolume tree ID",
        )));
    }
    Ok(lookup.tree_id)
}

#[cfg(target_os = "linux")]
fn stable_filesystem_id(file: &File, filesystem_type: u32) -> Result<u64, AnchorError> {
    const BTRFS_SUPER_MAGIC: u32 = 0x9123_683e;

    let external = ioctl_external_filesystem_uuid(file)?;
    let (uuid_len, uuid) = match external {
        Some(uuid) => uuid,
        None if filesystem_type == BTRFS_SUPER_MAGIC => (16, btrfs_filesystem_uuid(file)?),
        None => {
            return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "filesystem does not expose a remount-stable external UUID",
            )));
        }
    };
    let subvolume = if filesystem_type == BTRFS_SUPER_MAGIC {
        Some(btrfs_subvolume_tree_id(file)?)
    } else {
        None
    };
    derive_stable_filesystem_id(filesystem_type, uuid_len, &uuid, subvolume)
}

#[cfg(target_os = "linux")]
fn derive_stable_filesystem_id(
    filesystem_type: u32,
    uuid_len: u8,
    uuid: &[u8; 16],
    subvolume: Option<u64>,
) -> Result<u64, AnchorError> {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup stable filesystem identity v1");
    hasher.update(&filesystem_type.to_le_bytes());
    hasher.update(&[uuid_len]);
    hasher.update(&uuid[..usize::from(uuid_len)]);
    if let Some(subvolume) = subvolume {
        hasher.update(&subvolume.to_le_bytes());
    }
    let mut encoded = [0_u8; 8];
    encoded.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    let stable_id = u64::from_le_bytes(encoded);
    if stable_id == 0 {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "derived filesystem identity is invalid",
        )));
    }
    Ok(stable_id)
}

#[cfg(target_os = "linux")]
fn filesystem_type_for_file(file: &File) -> Result<u32, AnchorError> {
    use std::os::fd::AsRawFd;

    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    let result = unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let filesystem = unsafe { filesystem.assume_init() };
    Ok(filesystem.f_type as u32)
}

#[cfg(target_os = "linux")]
fn stable_filesystem_id_for_file(file: &File) -> Result<u64, AnchorError> {
    stable_filesystem_id(file, filesystem_type_for_file(file)?)
}

#[cfg(target_os = "linux")]
fn stable_filesystem_id_for_pinned_path(
    pinned: &File,
    readable_parent: &File,
) -> Result<u64, AnchorError> {
    use std::os::unix::fs::MetadataExt;

    const BTRFS_SUPER_MAGIC: u32 = 0x9123_683e;
    const BTRFS_FIRST_FREE_OBJECT_ID: u64 = 256;

    let filesystem_type = filesystem_type_for_file(pinned)?;
    if filesystem_type != filesystem_type_for_file(readable_parent)? {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "pinned path is on a different filesystem",
        )));
    }
    if filesystem_type == BTRFS_SUPER_MAGIC
        && pinned.metadata()?.ino() == BTRFS_FIRST_FREE_OBJECT_ID
    {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "refuse to treat a Btrfs subvolume root as an owned directory",
        )));
    }
    stable_filesystem_id_for_file(readable_parent)
}

#[cfg(target_os = "linux")]
fn linux_mount_id_at(
    directory: libc::c_int,
    path: &CStr,
    flags: libc::c_int,
) -> Result<u64, AnchorError> {
    // Linux's statx UAPI is a fixed 256-byte record. libc deliberately omits
    // its statx wrapper for musl targets whose configured headers predate musl
    // 1.2.3, even though the kernel syscall and ABI are available. Keep the
    // tiny ABI surface we need local so the packaged static build has the same
    // mount-ID protection as the glibc build.
    const STATX_TYPE: u32 = 0x0001;
    const STATX_MNT_ID: u32 = 0x1000;
    const STATX_BUFFER_BYTES: usize = 256;
    const STATX_MASK_OFFSET: usize = 0;
    const STATX_MNT_ID_OFFSET: usize = 144;
    #[repr(C, align(8))]
    struct StatxBuffer([u8; STATX_BUFFER_BYTES]);

    let mut stat = StatxBuffer([0; STATX_BUFFER_BYTES]);
    let result = unsafe {
        libc::syscall(
            libc::SYS_statx,
            directory,
            path.as_ptr(),
            flags,
            STATX_TYPE | STATX_MNT_ID,
            stat.0.as_mut_ptr(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mask = u32::from_ne_bytes(
        stat.0[STATX_MASK_OFFSET..STATX_MASK_OFFSET + std::mem::size_of::<u32>()]
            .try_into()
            .expect("fixed statx mask range"),
    );
    if mask & STATX_MNT_ID == 0 {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "filesystem mount identity is unavailable",
        )));
    }
    Ok(u64::from_ne_bytes(
        stat.0[STATX_MNT_ID_OFFSET..STATX_MNT_ID_OFFSET + std::mem::size_of::<u64>()]
            .try_into()
            .expect("fixed statx mount-ID range"),
    ))
}

#[cfg(target_os = "linux")]
fn linux_mount_id(path: &Path) -> Result<u64, AnchorError> {
    use std::os::unix::ffi::OsStrExt;

    let encoded =
        CString::new(path.as_os_str().as_bytes()).map_err(|_| AnchorError::InvalidRoot)?;
    linux_mount_id_at(libc::AT_FDCWD, &encoded, libc::AT_NO_AUTOMOUNT)
}

#[cfg(target_os = "linux")]
fn linux_mount_id_for_file(file: &File) -> Result<u64, AnchorError> {
    use std::os::fd::AsRawFd;

    const AT_EMPTY_PATH: libc::c_int = 0x1000;
    let empty = CString::new("").expect("an empty C string is valid");
    linux_mount_id_at(
        file.as_raw_fd(),
        &empty,
        libc::AT_NO_AUTOMOUNT | AT_EMPTY_PATH,
    )
}

#[cfg(target_os = "linux")]
fn filesystem_identity_for_file(file: &File) -> Result<FilesystemIdentity, AnchorError> {
    use std::os::unix::fs::MetadataExt;

    let mount_id = linux_mount_id_for_file(file)?;
    let stable_id = stable_filesystem_id_for_file(file)?;
    Ok(FilesystemIdentity {
        stable_id,
        device: file.metadata()?.dev(),
        mount_id,
    })
}

#[cfg(target_os = "linux")]
pub fn filesystem_identity(path: impl AsRef<Path>) -> Result<FilesystemIdentity, AnchorError> {
    let file = open_source_root(path.as_ref())?;
    filesystem_identity_for_file(&file)
}

#[cfg(not(target_os = "linux"))]
pub fn filesystem_identity(_path: impl AsRef<Path>) -> Result<FilesystemIdentity, AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "filesystem mount identity is currently implemented only on Linux",
    )))
}

pub fn probe_reflink(root: impl AsRef<Path>) -> Result<(), AnchorError> {
    let root = root.as_ref();
    if !root.is_dir() {
        return Err(AnchorError::InvalidRoot);
    }
    let root_identity = filesystem_identity(root)?;
    let parent = root.parent().ok_or(AnchorError::NoExternalAnchorLocation)?;
    if filesystem_identity(parent)? != root_identity {
        return Err(AnchorError::NoExternalAnchorLocation);
    }
    reject_nested_filesystems(root, root_identity)?;
    let probe_name = format!(".mutualbackup-probe-{}", Uuid::new_v4());
    let probe_dir = parent.join(&probe_name);
    create_private_dir_new(&probe_dir)?;
    let source_path = probe_dir.join("source");
    let removed_source_path = probe_dir.join("source-removed");
    let clone_path = probe_dir.join("clone");
    let result = (|| {
        let mut source = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&source_path)?;
        const PROBE_LENGTH: u64 = 4 * 1024 * 1024;
        const PROBE_OFFSET: u64 = 1024 * 1024;
        source.set_len(PROBE_LENGTH)?;
        source.seek(SeekFrom::Start(PROBE_OFFSET))?;
        source.write_all(b"source-before-clone")?;
        source.sync_all()?;
        let source_extents = file_data_extents(&source, PROBE_LENGTH)?;
        validate_sparse_probe_extents(&source_extents, PROBE_LENGTH)?;

        reflink_open_file(&source, &clone_path).map_err(AnchorError::ReflinkUnavailable)?;
        let cloned_read = File::open(&clone_path)?;
        let cloned_extents = file_data_extents(&cloned_read, PROBE_LENGTH)?;
        if cloned_extents != source_extents {
            return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
                "clone did not preserve sparse extents",
            )));
        }
        drop(cloned_read);

        fs::rename(&source_path, &removed_source_path)?;
        fs::remove_file(&removed_source_path)?;
        source.seek(SeekFrom::Start(PROBE_OFFSET))?;
        source.write_all(b"source-after-clone!")?;
        source.sync_all()?;

        let mut cloned = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&clone_path)?;
        cloned.seek(SeekFrom::Start(PROBE_OFFSET))?;
        let mut bytes = [0_u8; 19];
        cloned.read_exact(&mut bytes)?;
        if &bytes != b"source-before-clone" {
            return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
                "clone changed when source was edited",
            )));
        }
        cloned.seek(SeekFrom::Start(PROBE_OFFSET))?;
        cloned.write_all(b"clone-independent!!")?;
        cloned.sync_all()?;
        source.seek(SeekFrom::Start(PROBE_OFFSET))?;
        source.read_exact(&mut bytes)?;
        if &bytes != b"source-after-clone!" {
            return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
                "source changed when clone was edited",
            )));
        }
        validate_sparse_probe_extents(&file_data_extents(&source, PROBE_LENGTH)?, PROBE_LENGTH)?;
        validate_sparse_probe_extents(&file_data_extents(&cloned, PROBE_LENGTH)?, PROBE_LENGTH)?;
        if filesystem_identity(root)? != root_identity
            || filesystem_identity(&probe_dir)? != root_identity
        {
            return Err(AnchorError::FilesystemChanged);
        }
        Ok(())
    })();
    let cleanup = remove_owned_directory(parent, &probe_name);
    cleanup?;
    sync_directory(parent)?;
    result
}

fn validate_sparse_probe_extents(
    extents: &[FileExtent],
    logical_len: u64,
) -> Result<(), AnchorError> {
    let Some(first) = extents.first() else {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
            "SEEK_DATA did not find probe data",
        )));
    };
    let last = extents.last().expect("first extent exists");
    if first.offset == 0
        || last.offset.saturating_add(last.logical_len) >= logical_len
        || extents
            .iter()
            .any(|extent| extent.logical_len == 0 || extent.offset >= logical_len)
    {
        return Err(AnchorError::ReflinkUnavailable(std::io::Error::other(
            "SEEK_DATA/SEEK_HOLE did not preserve the probe holes",
        )));
    }
    Ok(())
}

fn reject_nested_filesystems(
    root: &Path,
    root_identity: FilesystemIdentity,
) -> Result<(), AnchorError> {
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::MetadataExt;
    #[cfg(target_os = "linux")]
    let root_file = open_source_root(root)?;

    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        if entry.file_type().is_symlink() {
            continue;
        }
        #[cfg(target_os = "linux")]
        let same_filesystem = if let Some(file) = open_walk_entry_beneath(root, &root_file, &entry)?
        {
            filesystem_identity_for_file(&file)? == root_identity
        } else {
            linux_mount_id(entry.path())? == root_identity.mount_id
                && fs::metadata(entry.path())?.dev() == root_identity.device
        };
        #[cfg(not(target_os = "linux"))]
        let same_filesystem = filesystem_identity(entry.path())? == root_identity;
        if !same_filesystem {
            return Err(AnchorError::NestedFilesystem(entry.path().to_path_buf()));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_walk_entry_beneath(
    root: &Path,
    root_file: &File,
    entry: &walkdir::DirEntry,
) -> Result<Option<File>, AnchorError> {
    if !entry.file_type().is_dir() && !entry.file_type().is_file() {
        return Ok(None);
    }
    let relative = entry
        .path()
        .strip_prefix(root)
        .map_err(|_| AnchorError::UnsafePath)?;
    if relative.as_os_str().is_empty() {
        Ok(Some(root_file.try_clone()?))
    } else {
        Ok(Some(open_source_beneath(
            root_file,
            relative,
            entry.file_type().is_dir(),
        )?))
    }
}

fn capture_entries(
    source_root: &Path,
    root_file: &File,
    root_metadata: &fs::Metadata,
    filesystem: FilesystemIdentity,
    staging: &Path,
) -> Result<Vec<CapturedEntry>, AnchorError> {
    #[cfg(test)]
    BEFORE_CAPTURE_WALK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });

    #[cfg(target_os = "linux")]
    {
        let mut capture = DescriptorCapture {
            source_root,
            root_file,
            filesystem,
            staging,
            entries: Vec::new(),
            versions: vec![CapturedVersion {
                relative: PathBuf::new(),
                directory: true,
                version: capture_version(filesystem.stable_id, root_metadata),
            }],
            captured_links: BTreeMap::new(),
            captured_extent_count: 0,
        };
        capture.capture_directory(root_file, Path::new(""), 0)?;
        capture.validate_versions()?;
        capture
            .entries
            .sort_by(|left, right| entry_path(left).cmp(entry_path(right)));
        Ok(capture.entries)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (source_root, root_file, root_metadata, filesystem, staging);
        Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "descriptor-relative capture is currently implemented only on Linux",
        )))
    }
}

#[cfg(target_os = "linux")]
struct CapturedVersion {
    relative: PathBuf,
    directory: bool,
    version: CaptureVersion,
}

#[cfg(target_os = "linux")]
struct DescriptorCapture<'a> {
    source_root: &'a Path,
    root_file: &'a File,
    filesystem: FilesystemIdentity,
    staging: &'a Path,
    entries: Vec<CapturedEntry>,
    versions: Vec<CapturedVersion>,
    captured_links: BTreeMap<NativeFileId, PathBuf>,
    captured_extent_count: usize,
}

#[cfg(target_os = "linux")]
impl DescriptorCapture<'_> {
    fn capture_directory(
        &mut self,
        directory: &File,
        relative_directory: &Path,
        depth: usize,
    ) -> Result<(), AnchorError> {
        #[cfg(test)]
        BEFORE_CAPTURE_DIRECTORY_READ.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(relative_directory);
            }
        });
        let mut stream = DirectoryStream::open(directory)?;
        #[cfg(test)]
        AFTER_CAPTURE_DIRECTORY_READ.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook(relative_directory);
            }
        });

        while let Some(name) = stream.next_name()? {
            if self.entries.len() >= MAX_CAPTURE_ENTRIES {
                return Err(AnchorError::CatalogTooLarge);
            }
            let child_depth = depth.checked_add(1).ok_or(AnchorError::CatalogTooLarge)?;
            if child_depth > MAX_CAPTURE_DEPTH {
                return Err(AnchorError::CatalogTooLarge);
            }
            use std::os::unix::ffi::OsStrExt;
            let component = Path::new(std::ffi::OsStr::from_bytes(name.as_bytes()));
            let relative = relative_directory.join(component);
            validate_relative(&relative)?;
            let relative_string = relative
                .to_str()
                .ok_or(AnchorError::NonUtf8Path)?
                .to_owned();
            if relative_string.len() > MAX_RELATIVE_PATH_BYTES {
                return Err(AnchorError::CatalogTooLarge);
            }

            let pinned = match open_path_no_xdev_beneath(directory, component) {
                Ok(file) => file,
                Err(error) if error.raw_os_error() == Some(libc::EXDEV) => {
                    return Err(AnchorError::NestedFilesystem(
                        self.source_root.join(&relative),
                    ));
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
            let directory = pinned_metadata.is_dir();
            if !directory && !pinned_metadata.is_file() {
                return Err(AnchorError::UnsupportedObject(relative));
            }
            let file = reopen_pinned_file(&pinned, directory, &relative)?;
            let before = file.metadata()?;
            if filesystem_identity_for_file(&file)? != self.filesystem {
                return Err(AnchorError::NestedFilesystem(
                    self.source_root.join(&relative),
                ));
            }
            let destination = self.staging.join(&relative);

            if directory {
                create_private_dir_new(&destination)?;
                let (modified_secs, modified_nanos) = modified_parts(&before);
                self.entries.push(CapturedEntry::Directory {
                    path: relative_string,
                    mode: unix_mode(&before),
                    modified_secs,
                    modified_nanos,
                });
                self.versions.push(CapturedVersion {
                    relative: relative.clone(),
                    directory: true,
                    version: capture_version(self.filesystem.stable_id, &before),
                });
                self.capture_directory(&file, &relative, child_depth)?;
            } else {
                if let Some(parent) = destination.parent() {
                    create_private_dir(parent)?;
                }
                let native_id = native_file_id(self.filesystem.stable_id, &before);
                if let Some(first_destination) = self.captured_links.get(&native_id) {
                    fs::hard_link(first_destination, &destination)?;
                } else {
                    reflink_open_file(&file, &destination)
                        .map_err(AnchorError::ReflinkUnavailable)?;
                    self.captured_links.insert(native_id, destination.clone());
                }
                let after = file.metadata()?;
                let captured = fs::symlink_metadata(&destination)?;
                if !same_capture_version(&before, &after)
                    || captured.len() != after.len()
                    || !captured.is_file()
                {
                    let _ = fs::remove_file(&destination);
                    return Err(AnchorError::SourceChanged(relative));
                }
                seal_anchor_file(&destination)?;
                let (modified_secs, modified_nanos) = modified_parts(&after);
                let captured_file = File::open(&destination)?;
                let data_extents = file_data_extents(&captured_file, after.len())?;
                self.captured_extent_count = self
                    .captured_extent_count
                    .checked_add(data_extents.len())
                    .ok_or(AnchorError::CatalogTooLarge)?;
                if self.captured_extent_count > MAX_CAPTURE_EXTENTS {
                    return Err(AnchorError::CatalogTooLarge);
                }
                self.entries.push(CapturedEntry::FileV2 {
                    path: relative_string,
                    mode: unix_mode(&after),
                    logical_len: after.len(),
                    modified_secs,
                    modified_nanos,
                    native_id,
                    data_extents,
                });
                self.versions.push(CapturedVersion {
                    relative,
                    directory: false,
                    version: capture_version(self.filesystem.stable_id, &after),
                });
            }
        }
        Ok(())
    }

    fn validate_versions(&self) -> Result<(), AnchorError> {
        for expected in &self.versions {
            let current = if expected.relative.as_os_str().is_empty() {
                self.root_file.try_clone()?
            } else {
                open_source_beneath(self.root_file, &expected.relative, expected.directory)?
            };
            if filesystem_identity_for_file(&current)? != self.filesystem
                || capture_version(self.filesystem.stable_id, &current.metadata()?)
                    != expected.version
            {
                return Err(AnchorError::SourceChanged(expected.relative.clone()));
            }
        }
        Ok(())
    }
}

fn ensure_anchor_area(
    source_root: &Path,
    root_metadata: &fs::Metadata,
) -> Result<StableAnchorAreaLocator, AnchorError> {
    let parent = source_root
        .parent()
        .ok_or(AnchorError::NoExternalAnchorLocation)?;
    let source_filesystem_id = filesystem_identity(source_root)?.stable_id;
    let (filesystem_id, volume_root_hint) = volume_root(parent)?;
    let area_name = format!(
        "{AREA_PREFIX}-{}",
        source_identity_name(source_filesystem_id, root_metadata)
    );
    let area_path = parent.join(&area_name);
    let area_id = match read_area_marker(&area_path) {
        Ok(area_id) => area_id,
        Err(AnchorError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            if let Some(area_id) = resume_staged_anchor_area(parent, &area_name, &area_path)? {
                area_id
            } else {
                publish_anchor_area(parent, &area_name, &area_path)?
            }
        }
        Err(_) => return Err(AnchorError::AnchorAreaCollision(area_path)),
    };
    let locator = StableAnchorAreaLocator {
        area_id,
        path_hint: area_path,
        filesystem_id,
        volume_root_hint,
    };
    validate_stable_anchor_area(&locator.path_hint, locator.area_id)?;
    Ok(locator)
}

fn publish_anchor_area(
    parent: &Path,
    area_name: &str,
    area_path: &Path,
) -> Result<Uuid, AnchorError> {
    let area_id = Uuid::new_v4();
    let staging_name = format!(".{area_name}.init-{}", Uuid::new_v4());
    let staging = parent.join(&staging_name);
    create_private_dir_new(&staging)?;
    let result = (|| {
        write_anchor_area_marker(&staging, area_id)?;
        sync_directory(&staging)?;
        rename_no_replace(&staging, area_path)?;
        sync_directory(parent)?;
        Ok::<_, AnchorError>(area_id)
    })();
    match result {
        Ok(area_id) => Ok(area_id),
        Err(AnchorError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = remove_owned_directory(parent, &staging_name);
            read_area_marker(area_path)
                .map_err(|_| AnchorError::AnchorAreaCollision(area_path.to_path_buf()))
        }
        Err(error) => {
            let _ = remove_owned_directory(parent, &staging_name);
            Err(error)
        }
    }
}

fn write_anchor_area_marker(area: &Path, area_id: Uuid) -> Result<(), AnchorError> {
    let marker_path = area.join(AREA_MARKER);
    let mut marker = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker_path)?;
    writeln!(marker, "{AREA_MAGIC}")?;
    writeln!(marker, "{area_id}")?;
    marker.sync_all()?;
    seal_anchor_file(&marker_path)?;
    Ok(())
}

fn resume_staged_anchor_area(
    parent: &Path,
    area_name: &str,
    area_path: &Path,
) -> Result<Option<Uuid>, AnchorError> {
    let prefix = format!(".{area_name}.init-");
    let mut candidates = fs::read_dir(parent)?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|entry| entry.file_name());
    for entry in candidates {
        let staging = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&staging) else {
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let Ok(area_id) = read_area_marker(&staging) else {
            continue;
        };
        match rename_no_replace(&staging, area_path) {
            Ok(()) => {
                sync_directory(parent)?;
                return Ok(Some(area_id));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return read_area_marker(area_path)
                    .map(Some)
                    .map_err(|_| AnchorError::AnchorAreaCollision(area_path.to_path_buf()));
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(None)
}

#[cfg(target_os = "linux")]
fn volume_root(source_root: &Path) -> Result<(u64, PathBuf), AnchorError> {
    let identity = filesystem_identity(source_root)?;
    let mut current = source_root.to_path_buf();
    while let Some(parent) = current.parent() {
        if linux_mount_id(parent)? != identity.mount_id {
            break;
        }
        if filesystem_identity(parent)?.stable_id != identity.stable_id {
            break;
        }
        current = parent.to_path_buf();
    }
    Ok((identity.stable_id, current))
}

#[cfg(not(target_os = "linux"))]
fn volume_root(_source_root: &Path) -> Result<(u64, PathBuf), AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "stable volume discovery is currently implemented only on Unix",
    )))
}

fn validate_stable_anchor_area(path: &Path, expected_id: Uuid) -> Result<(), AnchorError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| AnchorError::AnchorAreaCollision(path.to_path_buf()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AnchorError::AnchorAreaCollision(path.to_path_buf()));
    }
    let actual =
        read_area_marker(path).map_err(|_| AnchorError::AnchorAreaCollision(path.to_path_buf()))?;
    if actual != expected_id {
        return Err(AnchorError::AnchorAreaCollision(path.to_path_buf()));
    }
    Ok(())
}

fn resolve_anchor_area(area: &StableAnchorAreaLocator) -> Result<PathBuf, AnchorError> {
    resolve_anchor_area_with_hint(area, None)
}

fn resolve_anchor_area_with_hint(
    area: &StableAnchorAreaLocator,
    catalog_hint: Option<&Path>,
) -> Result<PathBuf, AnchorError> {
    let mut hints = Vec::with_capacity(2);
    if let Some(hint) = catalog_hint {
        hints.push(hint.to_path_buf());
    }
    if !hints.contains(&area.path_hint) {
        hints.push(area.path_hint.clone());
    }
    for hint in hints {
        if validate_stable_anchor_area(&hint, area.area_id).is_ok() {
            return Ok(hint);
        }
    }

    let index = ANCHOR_AREA_INDEX.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut index = index
        .lock()
        .map_err(|_| AnchorError::AnchorAreaIndexUnavailable)?;
    match index.get(&area.area_id).cloned() {
        Some(AnchorAreaIndexEntry::Resolved(path))
            if validate_stable_anchor_area(&path, area.area_id).is_ok() =>
        {
            return Ok(path);
        }
        Some(AnchorAreaIndexEntry::MissingUntil(retry_after)) if Instant::now() < retry_after => {
            return Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()));
        }
        _ => {
            index.remove(&area.area_id);
        }
    }

    match discover_anchor_area(area) {
        Ok(path) => {
            index.insert(area.area_id, AnchorAreaIndexEntry::Resolved(path.clone()));
            Ok(path)
        }
        Err(error) => {
            index.insert(
                area.area_id,
                AnchorAreaIndexEntry::MissingUntil(Instant::now() + FAILED_AREA_SCAN_RETRY),
            );
            Err(error)
        }
    }
}

fn discover_anchor_area(area: &StableAnchorAreaLocator) -> Result<PathBuf, AnchorError> {
    for root in anchor_discovery_roots(area) {
        let Ok(metadata) = fs::symlink_metadata(&root) else {
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let mut matches = BTreeMap::<NativeFileId, PathBuf>::new();
        let mut walker = WalkDir::new(&root)
            .follow_links(false)
            .same_file_system(true)
            .into_iter();
        while let Some(result) = walker.next() {
            let entry = match result {
                Ok(entry) => entry,
                Err(error)
                    if error.io_error().is_some_and(|error| {
                        matches!(
                            error.kind(),
                            std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                        )
                    }) =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if !entry.file_type().is_dir()
                || !entry.file_name().to_string_lossy().starts_with(AREA_PREFIX)
            {
                continue;
            }
            walker.skip_current_dir();
            if validate_stable_anchor_area(entry.path(), area.area_id).is_err() {
                continue;
            }
            let metadata = entry.metadata()?;
            let filesystem_id = filesystem_identity(entry.path())?.stable_id;
            let identity = native_file_id(filesystem_id, &metadata);
            matches
                .entry(identity)
                .or_insert_with(|| entry.path().to_path_buf());
        }
        if matches.len() > 1 {
            return Err(AnchorError::AnchorAreaCollision(
                matches
                    .into_values()
                    .next()
                    .unwrap_or_else(|| area.path_hint.clone()),
            ));
        }
        if let Some(path) = matches.into_values().next() {
            return Ok(path);
        }
    }
    Err(AnchorError::AnchorAreaCollision(area.path_hint.clone()))
}

fn anchor_discovery_roots(area: &StableAnchorAreaLocator) -> Vec<PathBuf> {
    #[allow(unused_mut)]
    let mut roots = Vec::new();
    #[cfg(target_os = "linux")]
    {
        let mut seen = BTreeSet::new();
        for root in std::iter::once(area.volume_root_hint.clone()).chain(linux_data_mount_points())
        {
            if !filesystem_identity(&root)
                .is_ok_and(|identity| identity.stable_id == area.filesystem_id)
            {
                continue;
            }
            if seen.insert(root.clone()) {
                roots.push(root);
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    roots.push(area.volume_root_hint.clone());
    roots
}

#[cfg(target_os = "linux")]
fn linux_data_mount_points() -> Vec<PathBuf> {
    let Ok(contents) = fs::read_to_string("/proc/self/mountinfo") else {
        return Vec::new();
    };
    contents
        .lines()
        .filter_map(|line| {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            let separator = fields.iter().position(|field| *field == "-")?;
            let filesystem = *fields.get(separator + 1)?;
            if !is_data_filesystem(filesystem) {
                return None;
            }
            decode_mount_path(fields.get(4)?)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn is_data_filesystem(filesystem: &str) -> bool {
    matches!(
        filesystem,
        "bcachefs"
            | "btrfs"
            | "ext2"
            | "ext3"
            | "ext4"
            | "f2fs"
            | "fuseblk"
            | "ntfs3"
            | "ocfs2"
            | "overlay"
            | "tmpfs"
            | "virtiofs"
            | "xfs"
            | "zfs"
    ) || filesystem.starts_with("fuse.")
}

#[cfg(target_os = "linux")]
fn decode_mount_path(encoded: &str) -> Option<PathBuf> {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let encoded = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] == b'\\' && index + 3 < encoded.len() {
            let digits = &encoded[index + 1..index + 4];
            if digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) {
                let value = u16::from(digits[0] - b'0') * 64
                    + u16::from(digits[1] - b'0') * 8
                    + u16::from(digits[2] - b'0');
                decoded.push(u8::try_from(value).ok()?);
                index += 4;
                continue;
            }
        }
        decoded.push(encoded[index]);
        index += 1;
    }
    Some(PathBuf::from(OsString::from_vec(decoded)))
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
    read_area_marker_contents(File::open(marker)?, area)
}

fn read_area_marker_contents(mut marker: File, area: &Path) -> Result<Uuid, AnchorError> {
    if marker.metadata()?.len() > 128 {
        return Err(AnchorError::AnchorAreaCollision(area.to_path_buf()));
    }
    let mut bytes = String::new();
    marker.read_to_string(&mut bytes)?;
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
        CapturedEntry::Directory { path, .. }
        | CapturedEntry::File { path, .. }
        | CapturedEntry::FileV2 { path, .. } => path,
    }
}

#[cfg(target_os = "linux")]
fn remove_stable_capture_directory(
    area_path: &Path,
    area: &StableAnchorAreaLocator,
    name: &str,
) -> Result<(), AnchorError> {
    let area_file = open_source_root(area_path)?;
    if filesystem_identity_for_file(&area_file)?.stable_id != area.filesystem_id {
        return Err(AnchorError::AnchorAreaCollision(area_path.to_path_buf()));
    }
    validate_area_marker_file(&area_file, area_path, area.area_id)?;
    remove_directory_at(&area_file, name, &area_path.join(name))
}

#[cfg(not(target_os = "linux"))]
fn remove_stable_capture_directory(
    _area_path: &Path,
    _area: &StableAnchorAreaLocator,
    _name: &str,
) -> Result<(), AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe anchor cleanup is currently implemented only on Linux",
    )))
}

#[cfg(target_os = "linux")]
fn remove_legacy_capture_directory(
    area_path: &Path,
    area_id: Uuid,
    name: &str,
) -> Result<(), AnchorError> {
    let area_file = open_source_root(area_path)?;
    validate_area_marker_file(&area_file, area_path, area_id)?;
    remove_directory_at(&area_file, name, &area_path.join(name))
}

#[cfg(target_os = "linux")]
fn remove_owned_directory(parent: &Path, name: &str) -> Result<(), AnchorError> {
    let parent_file = open_source_root(parent)?;
    remove_directory_at(&parent_file, name, &parent.join(name))
}

#[cfg(not(target_os = "linux"))]
fn remove_owned_directory(_parent: &Path, _name: &str) -> Result<(), AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe directory cleanup is currently implemented only on Linux",
    )))
}

#[cfg(not(target_os = "linux"))]
fn remove_legacy_capture_directory(
    _area_path: &Path,
    _area_id: Uuid,
    _name: &str,
) -> Result<(), AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "safe anchor cleanup is currently implemented only on Linux",
    )))
}

#[cfg(target_os = "linux")]
fn validate_area_marker_file(
    area: &File,
    area_path: &Path,
    expected_id: Uuid,
) -> Result<(), AnchorError> {
    let marker_handle = open_path_no_xdev_beneath(area, Path::new(AREA_MARKER))
        .map_err(|_| AnchorError::AnchorAreaCollision(area_path.to_path_buf()))?;
    let metadata = marker_handle.metadata()?;
    if !metadata.is_file() {
        return Err(AnchorError::AnchorAreaCollision(area_path.to_path_buf()));
    }
    let marker = reopen_pinned_file(&marker_handle, false, Path::new(AREA_MARKER))?;
    let actual = read_area_marker_contents(marker, area_path)?;
    if actual != expected_id {
        return Err(AnchorError::AnchorAreaCollision(area_path.to_path_buf()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_directory_at(parent: &File, name: &str, display: &Path) -> Result<(), AnchorError> {
    let relative = Path::new(name);
    remove_directory_at_expected(parent, relative, display, None)
}

#[cfg(target_os = "linux")]
fn remove_directory_at_expected(
    parent: &File,
    relative: &Path,
    display: &Path,
    expected: Option<NativeFileId>,
) -> Result<(), AnchorError> {
    if relative.components().count() != 1 {
        return Err(AnchorError::UnsafePath);
    }
    let handle = match open_path_no_xdev_beneath(parent, relative) {
        Ok(handle) => handle,
        Err(error) if error.raw_os_error() == Some(libc::ENOENT) => return Ok(()),
        Err(_) => return Err(AnchorError::AnchorAreaCollision(display.to_path_buf())),
    };
    let metadata = handle.metadata()?;
    if !metadata.is_dir() {
        return Err(AnchorError::AnchorAreaCollision(display.to_path_buf()));
    }
    let stable_filesystem_id = stable_filesystem_id_for_pinned_path(&handle, parent)
        .map_err(|_| AnchorError::AnchorAreaCollision(display.to_path_buf()))?;
    if let Some(expected) = expected {
        let actual = native_file_id(stable_filesystem_id, &metadata);
        if actual != expected {
            return Err(AnchorError::AnchorAreaCollision(display.to_path_buf()));
        }
    }
    make_pinned_directory_private(&handle)?;
    let directory = reopen_pinned_file(&handle, true, relative)?;
    let mut remaining = MAX_CAPTURE_ENTRIES + 1;
    remove_directory_contents(&directory, display, 0, &mut remaining, stable_filesystem_id)?;
    unlink_pinned_name(parent, relative, &handle, true, display)
}

#[cfg(target_os = "linux")]
fn remove_directory_contents(
    directory: &File,
    display: &Path,
    depth: usize,
    remaining: &mut usize,
    expected_filesystem_id: u64,
) -> Result<(), AnchorError> {
    use std::os::unix::ffi::OsStrExt;

    if depth > MAX_CAPTURE_DEPTH {
        return Err(AnchorError::AnchorAreaCollision(display.to_path_buf()));
    }
    loop {
        let names = directory_entry_batch(directory, CLEANUP_BATCH_ENTRIES)?;
        if names.is_empty() {
            return Ok(());
        }
        for name in names {
            if *remaining == 0 {
                return Err(AnchorError::AnchorAreaCollision(display.to_path_buf()));
            }
            *remaining -= 1;
            let relative = Path::new(std::ffi::OsStr::from_bytes(name.as_bytes()));
            let child_display = display.join(relative);
            let handle = match open_path_no_xdev_beneath(directory, relative) {
                Ok(handle) => handle,
                Err(error) if error.raw_os_error() == Some(libc::ENOENT) => continue,
                Err(_) => return Err(AnchorError::AnchorAreaCollision(child_display)),
            };
            let child_filesystem_id = stable_filesystem_id_for_pinned_path(&handle, directory)
                .map_err(|_| AnchorError::AnchorAreaCollision(child_display.clone()))?;
            if child_filesystem_id != expected_filesystem_id {
                return Err(AnchorError::AnchorAreaCollision(child_display));
            }
            if handle.metadata()?.is_dir() {
                make_pinned_directory_private(&handle)?;
                let child = reopen_pinned_file(&handle, true, relative)?;
                remove_directory_contents(
                    &child,
                    &child_display,
                    depth + 1,
                    remaining,
                    expected_filesystem_id,
                )?;
                unlink_pinned_name(directory, relative, &handle, true, &child_display)?;
            } else {
                unlink_pinned_name(directory, relative, &handle, false, &child_display)?;
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn make_pinned_directory_private(directory: &File) -> Result<(), AnchorError> {
    use std::os::fd::AsRawFd;

    let path = CString::new(format!("/proc/self/fd/{}", directory.as_raw_fd()))
        .expect("a numeric proc descriptor path has no NUL");
    if unsafe { libc::chmod(path.as_ptr(), 0o700) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn directory_entry_batch(directory: &File, maximum: usize) -> Result<Vec<CString>, AnchorError> {
    let mut stream = DirectoryStream::open(directory)?;
    let mut names = Vec::with_capacity(maximum);
    while names.len() < maximum {
        let Some(name) = stream.next_name()? else {
            break;
        };
        names.push(name);
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
struct DirectoryStream(*mut libc::DIR);

#[cfg(target_os = "linux")]
impl DirectoryStream {
    fn open(directory: &File) -> Result<Self, AnchorError> {
        use std::os::fd::AsRawFd;

        let descriptor = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { libc::lseek(descriptor, 0, libc::SEEK_SET) } < 0 {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(descriptor);
            }
            return Err(error.into());
        }
        let stream = unsafe { libc::fdopendir(descriptor) };
        if stream.is_null() {
            let error = std::io::Error::last_os_error();
            unsafe {
                libc::close(descriptor);
            }
            return Err(error.into());
        }
        Ok(Self(stream))
    }

    fn next_name(&mut self) -> Result<Option<CString>, AnchorError> {
        loop {
            unsafe {
                *libc::__errno_location() = 0;
            }
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error().unwrap_or(0) == 0 {
                    return Ok(None);
                }
                return Err(error.into());
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() == b"." || name.to_bytes() == b".." {
                continue;
            }
            return Ok(Some(name.to_owned()));
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe {
            libc::closedir(self.0);
        }
    }
}

#[cfg(target_os = "linux")]
fn open_path_no_xdev_beneath(parent: &File, relative: &Path) -> std::io::Result<File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    let path = CString::new(relative.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            parent.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(descriptor as i32) })
}

#[cfg(target_os = "linux")]
fn unlink_pinned_name(
    parent: &File,
    relative: &Path,
    pinned: &File,
    directory: bool,
    display: &Path,
) -> Result<(), AnchorError> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let current = open_path_no_xdev_beneath(parent, relative)
        .map_err(|_| AnchorError::AnchorAreaCollision(display.to_path_buf()))?;
    let expected = pinned.metadata()?;
    let current = current.metadata()?;
    if expected.dev() != current.dev()
        || expected.ino() != current.ino()
        || expected.file_type() != current.file_type()
    {
        return Err(AnchorError::AnchorAreaCollision(display.to_path_buf()));
    }
    let path =
        CString::new(relative.as_os_str().as_bytes()).map_err(|_| AnchorError::UnsafePath)?;
    let flags = if directory { libc::AT_REMOVEDIR } else { 0 };
    if unsafe { libc::unlinkat(parent.as_raw_fd(), path.as_ptr(), flags) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn read_planned_manifest(
    anchor_root: &Path,
    plan: &ReflinkCapturePlan,
) -> Result<StableAnchorManifest, AnchorError> {
    let root_metadata = fs::symlink_metadata(anchor_root)?;
    if !root_metadata.is_dir() || root_metadata.file_type().is_symlink() {
        return Err(AnchorError::AnchorAreaCollision(anchor_root.to_path_buf()));
    }
    let path = anchor_root.join(capture_manifest_name(plan.anchor_id));
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 * 1024
    {
        return Err(AnchorError::AnchorAreaCollision(anchor_root.to_path_buf()));
    }
    let manifest: StableAnchorManifest = decode_canonical(&fs::read(path)?)
        .map_err(|_| AnchorError::AnchorAreaCollision(anchor_root.to_path_buf()))?;
    if manifest.format_version != 2
        || manifest.anchor_id != plan.anchor_id
        || manifest.source_root_hint != plan.source_root
        || manifest.area != plan.area
        || manifest.root_mode != plan.root_mode
        || manifest.root_modified_secs != plan.root_modified_secs
        || manifest.root_modified_nanos != plan.root_modified_nanos
    {
        return Err(AnchorError::AnchorAreaCollision(anchor_root.to_path_buf()));
    }
    Ok(manifest)
}

fn capture_manifest_name(anchor_id: Uuid) -> String {
    format!("{CAPTURE_MANIFEST_PREFIX}{anchor_id}")
}

#[cfg(unix)]
fn capture_version(filesystem_id: u64, metadata: &fs::Metadata) -> CaptureVersion {
    use std::os::unix::fs::MetadataExt;
    CaptureVersion {
        filesystem_id,
        inode: metadata.ino(),
        logical_len: metadata.len(),
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    }
}

#[cfg(not(unix))]
fn capture_version(_filesystem_id: u64, metadata: &fs::Metadata) -> CaptureVersion {
    let (modified_secs, modified_nanos) = modified_parts(metadata);
    CaptureVersion {
        filesystem_id: 0,
        inode: 0,
        logical_len: metadata.len(),
        modified_secs,
        modified_nanos: i64::from(modified_nanos),
        changed_secs: modified_secs,
        changed_nanos: i64::from(modified_nanos),
    }
}

#[cfg(unix)]
fn native_file_id(filesystem_id: u64, metadata: &fs::Metadata) -> NativeFileId {
    use std::os::unix::fs::MetadataExt;
    NativeFileId {
        filesystem_id,
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn native_file_id(_filesystem_id: u64, _metadata: &fs::Metadata) -> NativeFileId {
    NativeFileId {
        filesystem_id: 0,
        inode: 0,
    }
}

#[cfg(target_os = "linux")]
fn file_data_extents(file: &File, logical_len: u64) -> Result<Vec<FileExtent>, AnchorError> {
    use std::os::fd::AsRawFd;

    let mut extents = Vec::new();
    let mut cursor = 0_u64;
    while cursor < logical_len {
        let data = unsafe { libc::lseek(file.as_raw_fd(), cursor as libc::off_t, libc::SEEK_DATA) };
        if data < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                break;
            }
            return Err(error.into());
        }
        let data = data as u64;
        if data >= logical_len {
            break;
        }
        let hole = unsafe { libc::lseek(file.as_raw_fd(), data as libc::off_t, libc::SEEK_HOLE) };
        let hole = if hole < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENXIO) {
                logical_len
            } else {
                return Err(error.into());
            }
        } else {
            (hole as u64).min(logical_len)
        };
        if hole <= data {
            return Err(
                std::io::Error::other("filesystem returned an invalid sparse extent").into(),
            );
        }
        extents.push(FileExtent {
            offset: data,
            logical_len: hole - data,
        });
        if extents.len() > MAX_CAPTURE_EXTENTS {
            return Err(AnchorError::CatalogTooLarge);
        }
        cursor = hole;
    }
    Ok(extents)
}

#[cfg(not(target_os = "linux"))]
fn file_data_extents(_file: &File, _logical_len: u64) -> Result<Vec<FileExtent>, AnchorError> {
    Err(AnchorError::ReflinkUnavailable(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "sparse extent discovery is currently implemented only on Linux",
    )))
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
    let pinned = open_path_beneath(root, relative)?;
    let metadata = pinned.metadata()?;
    if metadata.file_type().is_symlink() {
        return Err(AnchorError::Symlink(relative.to_path_buf()));
    }
    if (directory && !metadata.is_dir()) || (!directory && !metadata.is_file()) {
        return Err(AnchorError::UnsupportedObject(relative.to_path_buf()));
    }
    reopen_pinned_file(&pinned, directory, relative)
}

#[cfg(target_os = "linux")]
fn open_path_beneath(root: &File, relative: &Path) -> Result<File, AnchorError> {
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
    let how = OpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
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

#[cfg(target_os = "linux")]
fn reopen_pinned_file(
    pinned: &File,
    directory: bool,
    relative: &Path,
) -> Result<File, AnchorError> {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;

    let path = CString::new(format!("/proc/self/fd/{}", pinned.as_raw_fd()))
        .expect("a numeric proc descriptor path has no NUL");
    let mut flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK;
    if directory {
        flags |= libc::O_DIRECTORY;
        flags &= !libc::O_NONBLOCK;
    }
    let descriptor = unsafe { libc::open(path.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let reopened = unsafe { File::from_raw_fd(descriptor) };
    let pinned_metadata = pinned.metadata()?;
    let reopened_metadata = reopened.metadata()?;
    if pinned_metadata.dev() != reopened_metadata.dev()
        || pinned_metadata.ino() != reopened_metadata.ino()
        || pinned_metadata.file_type() != reopened_metadata.file_type()
    {
        return Err(AnchorError::SourceChanged(relative.to_path_buf()));
    }
    Ok(reopened)
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
fn source_identity_name(filesystem_id: u64, metadata: &fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!("{filesystem_id:x}-{:x}", metadata.ino())
}

#[cfg(not(unix))]
fn source_identity_name(_filesystem_id: u64, metadata: &fs::Metadata) -> String {
    format!("{:x}", metadata.len())
}

fn modified_parts(metadata: &fs::Metadata) -> (i64, u32) {
    let modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
    system_time_parts(modified)
}

fn system_time_parts(modified: std::time::SystemTime) -> (i64, u32) {
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
                    seconds
                        .checked_add(1)
                        .and_then(|value| value.checked_neg())
                        .unwrap_or(i64::MIN),
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

fn sync_tree_bottom_up(root: &Path) -> Result<(), AnchorError> {
    let mut directories = WalkDir::new(root)
        .min_depth(0)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
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

    #[cfg(target_os = "linux")]
    fn bind_mount(source: &Path, target: &Path) {
        let output = std::process::Command::new("sudo")
            .args(["-n", "mount", "--bind"])
            .arg(source)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot create bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    fn unmount(target: &Path) {
        let output = std::process::Command::new("sudo")
            .args(["-n", "umount"])
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot remove bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn rejects_unsafe_relative_paths() {
        assert!(validate_relative(Path::new("good/file")).is_ok());
        assert!(validate_relative(Path::new("../escape")).is_err());
        assert!(validate_relative(Path::new("/absolute")).is_err());
    }

    #[test]
    fn modification_times_are_normalized_across_the_unix_epoch() {
        use std::time::{Duration, UNIX_EPOCH};

        assert_eq!(system_time_parts(UNIX_EPOCH), (0, 0));
        assert_eq!(
            system_time_parts(UNIX_EPOCH + Duration::from_nanos(1)),
            (0, 1)
        );
        assert_eq!(
            system_time_parts(UNIX_EPOCH - Duration::from_nanos(1)),
            (-1, 999_999_999)
        );
        assert_eq!(
            system_time_parts(UNIX_EPOCH - Duration::from_millis(500)),
            (-1, 500_000_000)
        );
        assert_eq!(
            system_time_parts(UNIX_EPOCH - Duration::from_secs(1)),
            (-1, 0)
        );
        assert_eq!(
            system_time_parts(UNIX_EPOCH - Duration::new(1, 1)),
            (-2, 999_999_999)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn filesystem_identity_tracks_the_mount() {
        let temp = tempfile::tempdir().unwrap();
        let child = temp.path().join("child");
        fs::create_dir(&child).unwrap();
        let parent = filesystem_identity(temp.path()).unwrap();
        let child = filesystem_identity(&child).unwrap();
        assert_eq!(parent, child);
        assert_ne!(parent.stable_id, 0);
        assert_ne!(parent.device, 0);
        assert_ne!(parent.mount_id, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reflink_probe_always_removes_its_temporary_area() {
        let parent = tempfile::tempdir().unwrap();
        let protected = parent.path().join("protected");
        fs::create_dir(&protected).unwrap();

        let _ = probe_reflink(&protected);

        let remaining = fs::read_dir(parent.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(remaining, vec![std::ffi::OsString::from("protected")]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn cached_directory_entry_cannot_turn_into_a_blocking_fifo_open() {
        use std::os::unix::ffi::OsStrExt;

        let temp = tempfile::tempdir().unwrap();
        let entry_path = temp.path().join("entry");
        fs::create_dir(&entry_path).unwrap();
        let cached_entry = WalkDir::new(temp.path())
            .min_depth(1)
            .max_depth(1)
            .into_iter()
            .next()
            .unwrap()
            .unwrap();
        assert!(cached_entry.file_type().is_dir());
        fs::remove_dir(&entry_path).unwrap();
        let encoded = CString::new(entry_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);

        let root_file = open_source_root(temp.path()).unwrap();
        let started = Instant::now();
        assert!(open_walk_entry_beneath(temp.path(), &root_file, &cached_entry).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn capture_walk_remains_bound_to_the_open_root() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("root-swap-{}", Uuid::new_v4()));
        let protected = run_root.join("protected");
        let replacement = run_root.join("replacement");
        fs::create_dir_all(&protected).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(protected.join("payload"), b"pinned-root-payload").unwrap();
        let plan = ReflinkAnchor::plan(&protected).unwrap();

        let hook_source = replacement.clone();
        let hook_target = protected.clone();
        BEFORE_CAPTURE_WALK.with(|hook| {
            assert!(
                hook.borrow_mut()
                    .replace(Box::new(move || bind_mount(&hook_source, &hook_target)))
                    .is_none()
            );
        });
        let captured = ReflinkAnchor::capture_plan(&plan);
        unmount(&protected);

        let manifest = captured.unwrap();
        assert!(manifest.entries.iter().any(|entry| {
            matches!(entry, CapturedEntry::FileV2 { path, .. } if path == "payload")
        }));
        let mut payload = String::new();
        manifest
            .file_locator("payload".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_string(&mut payload)
            .unwrap();
        assert_eq!(payload, "pinned-root-payload");
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn capture_walk_enumerates_a_descendant_through_its_pinned_descriptor() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("descendant-swap-{}", Uuid::new_v4()));
        let protected = run_root.join("protected");
        let child = protected.join("child");
        let replacement = run_root.join("replacement");
        fs::create_dir_all(&child).unwrap();
        fs::create_dir(&replacement).unwrap();
        fs::write(child.join("payload"), b"pinned-child-payload").unwrap();
        let plan = ReflinkAnchor::plan(&protected).unwrap();

        let mount_source = replacement.clone();
        let mount_target = child.clone();
        BEFORE_CAPTURE_DIRECTORY_READ.with(|hook| {
            assert!(
                hook.borrow_mut()
                    .replace(Box::new(move |relative| {
                        if relative == Path::new("child") {
                            bind_mount(&mount_source, &mount_target);
                        }
                    }))
                    .is_none()
            );
        });
        let unmount_target = child.clone();
        AFTER_CAPTURE_DIRECTORY_READ.with(|hook| {
            assert!(
                hook.borrow_mut()
                    .replace(Box::new(move |relative| {
                        if relative == Path::new("child") {
                            unmount(&unmount_target);
                        }
                    }))
                    .is_none()
            );
        });

        let manifest = ReflinkAnchor::capture_plan(&plan).unwrap();
        BEFORE_CAPTURE_DIRECTORY_READ.with(|hook| {
            hook.borrow_mut().take();
        });
        AFTER_CAPTURE_DIRECTORY_READ.with(|hook| {
            hook.borrow_mut().take();
        });
        assert!(manifest.entries.iter().any(|entry| {
            matches!(entry, CapturedEntry::FileV2 { path, .. } if path == "child/payload")
        }));
        let mut payload = String::new();
        manifest
            .file_locator("child/payload".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_string(&mut payload)
            .unwrap();
        assert_eq!(payload, "pinned-child-payload");
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn capture_descriptor_use_is_bounded_by_tree_depth() {
        struct OpenFileLimitGuard(libc::rlimit);

        impl Drop for OpenFileLimitGuard {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
            }
        }

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("bounded-fds-{}", Uuid::new_v4()));
        let protected = run_root.join("protected");
        fs::create_dir_all(&protected).unwrap();
        for ordinal in 0..512 {
            fs::write(protected.join(format!("file-{ordinal:04}")), b"payload").unwrap();
        }
        let plan = ReflinkAnchor::plan(&protected).unwrap();

        let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
            0
        );
        let original = unsafe { original.assume_init() };
        assert!(original.rlim_cur >= 96);
        let limited = libc::rlimit {
            rlim_cur: 96,
            rlim_max: original.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        let limit = OpenFileLimitGuard(original);

        let manifest = ReflinkAnchor::capture_plan(&plan).unwrap();
        assert_eq!(manifest.entries.len(), 512);
        drop(limit);
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn anchor_cleanup_refuses_to_cross_a_child_mount() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("cleanup-mount-{}", Uuid::new_v4()));
        let protected = run_root.join("protected");
        let external = run_root.join("external");
        fs::create_dir_all(&protected).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(protected.join("payload"), b"anchor payload").unwrap();
        let sentinel = external.join("must-survive");
        fs::write(&sentinel, b"external bytes").unwrap();
        let manifest = ReflinkAnchor::capture(&protected).unwrap();
        let anchor_root = manifest.area.path_hint.join(manifest.anchor_id.to_string());

        bind_mount(&external, &anchor_root);
        let removal = manifest.remove();
        unmount(&anchor_root);

        assert!(removal.is_err());
        assert_eq!(fs::read(&sentinel).unwrap(), b"external bytes");
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn owned_tree_cleanup_enforces_entry_budget_in_batches() {
        let parent = tempfile::tempdir().unwrap();
        let owned = parent.path().join("owned");
        fs::create_dir(&owned).unwrap();
        for index in 0..=(MAX_CAPTURE_ENTRIES + 1) {
            fs::write(owned.join(format!("entry-{index:05}")), b"").unwrap();
        }
        let identity = directory_identity(&owned).unwrap();

        assert!(remove_owned_directory_tree(&owned, identity).is_err());
        assert!(owned.is_dir());
        fs::remove_dir_all(&owned).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn owned_tree_cleanup_refuses_child_mounts_and_handles_read_only_directories() {
        use std::os::unix::fs::PermissionsExt;
        use std::process::Command;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("owned-cleanup-{}", Uuid::new_v4()));
        let owned = run_root.join("owned");
        let nested = owned.join("nested");
        let external = run_root.join("external");
        fs::create_dir_all(&nested).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(nested.join("payload"), b"owned payload").unwrap();
        let sentinel = external.join("must-survive");
        fs::write(&sentinel, b"external bytes").unwrap();
        let identity = directory_identity(&owned).unwrap();

        bind_mount(&external, &nested);
        assert!(remove_owned_directory_tree(&owned, identity).is_err());
        unmount(&nested);
        assert_eq!(fs::read(&sentinel).unwrap(), b"external bytes");

        fs::remove_file(nested.join("payload")).unwrap();
        fs::remove_dir(&nested).unwrap();
        let output = Command::new("btrfs")
            .args(["subvolume", "create"])
            .arg(&nested)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot create cleanup-test subvolume: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::write(nested.join("must-survive"), b"subvolume bytes").unwrap();
        assert!(remove_owned_directory_tree(&owned, identity).is_err());
        assert_eq!(
            fs::read(nested.join("must-survive")).unwrap(),
            b"subvolume bytes"
        );
        let output = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(&nested)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot delete cleanup-test subvolume: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fs::create_dir(&nested).unwrap();

        fs::set_permissions(&nested, fs::Permissions::from_mode(0o000)).unwrap();
        fs::set_permissions(&owned, fs::Permissions::from_mode(0o000)).unwrap();
        remove_owned_directory_tree(&owned, identity).unwrap();
        assert!(!owned.exists());
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn anchor_area_initialization_recovers_staged_publication() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("area-init-{}", Uuid::new_v4()));
        let complete_source = run_root.join("complete-source");
        fs::create_dir_all(&complete_source).unwrap();
        let complete_metadata = fs::metadata(&complete_source).unwrap();
        let filesystem_id = filesystem_identity(&complete_source).unwrap().stable_id;
        let complete_area_name = format!(
            "{AREA_PREFIX}-{}",
            source_identity_name(filesystem_id, &complete_metadata)
        );
        let complete_staging_name = format!(".{complete_area_name}.init-test");
        let complete_staging = run_root.join(&complete_staging_name);
        create_private_dir_new(&complete_staging).unwrap();
        let expected_id = Uuid::new_v4();
        write_anchor_area_marker(&complete_staging, expected_id).unwrap();
        sync_directory(&complete_staging).unwrap();

        let complete = ensure_anchor_area(&complete_source, &complete_metadata).unwrap();
        assert_eq!(complete.area_id, expected_id);
        assert!(!complete_staging.exists());
        validate_stable_anchor_area(&complete.path_hint, expected_id).unwrap();

        let partial_source = run_root.join("partial-source");
        fs::create_dir(&partial_source).unwrap();
        let partial_metadata = fs::metadata(&partial_source).unwrap();
        let partial_area_name = format!(
            "{AREA_PREFIX}-{}",
            source_identity_name(filesystem_id, &partial_metadata)
        );
        let partial_staging_name = format!(".{partial_area_name}.init-interrupted");
        create_private_dir_new(&run_root.join(&partial_staging_name)).unwrap();

        let partial = ensure_anchor_area(&partial_source, &partial_metadata).unwrap();
        validate_stable_anchor_area(&partial.path_hint, partial.area_id).unwrap();
        assert!(run_root.join(&partial_staging_name).is_dir());

        remove_owned_directory(&run_root, &complete_area_name).unwrap();
        remove_owned_directory(&run_root, &partial_area_name).unwrap();
        remove_owned_directory(&run_root, &partial_staging_name).unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn nested_btrfs_subvolumes_are_rejected_before_and_during_capture() {
        use std::os::unix::fs::MetadataExt;
        use std::process::Command;

        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
        let run_root =
            PathBuf::from(test_root).join(format!("nested-subvolume-{}", Uuid::new_v4()));
        let protected = run_root.join("protected");
        let container = protected.join("container");
        fs::create_dir_all(&container).unwrap();
        fs::write(protected.join("ordinary"), b"ordinary").unwrap();
        let plan = ReflinkAnchor::plan(&protected).unwrap();

        let first = container.join("first");
        let second = container.join("second");
        for subvolume in [&first, &second] {
            let output = Command::new("btrfs")
                .args(["subvolume", "create"])
                .arg(subvolume)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "cannot create Btrfs test subvolume: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        fs::write(first.join("payload"), b"first subvolume").unwrap();
        fs::write(second.join("payload"), b"second subvolume").unwrap();
        assert_eq!(
            fs::metadata(first.join("payload")).unwrap().ino(),
            fs::metadata(second.join("payload")).unwrap().ino(),
            "the regression requires equal inode numbers in distinct subvolumes"
        );
        let probe_error = probe_reflink(&protected).unwrap_err();
        assert!(matches!(
            probe_error,
            AnchorError::NestedFilesystem(path) if path == first || path == second
        ));
        let capture_error = ReflinkAnchor::capture_plan(&plan).unwrap_err();
        assert!(
            matches!(
                &capture_error,
                AnchorError::NestedFilesystem(path) if path == &first || path == &second
            ),
            "unexpected capture error: {capture_error:?}"
        );

        let output = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .args([&first, &second])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot delete Btrfs test subvolumes: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let bind_owner = run_root.join("bind-owner");
        let bind_external = run_root.join("bind-external");
        for subvolume in [&bind_owner, &bind_external] {
            let output = Command::new("btrfs")
                .args(["subvolume", "create"])
                .arg(subvolume)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "cannot create Btrfs bind-mount test subvolume: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let bind_protected = bind_owner.join("protected");
        fs::create_dir(&bind_protected).unwrap();
        let first_file = bind_protected.join("a-first");
        let mount_target = bind_protected.join("z-mounted");
        fs::write(&first_file, b"root-subvolume-bytes").unwrap();
        fs::write(&mount_target, b"original-target-data").unwrap();
        let bind_plan = ReflinkAnchor::plan(&bind_protected).unwrap();

        fs::create_dir(bind_external.join("inode-slot")).unwrap();
        let mounted_file = bind_external.join("payload");
        fs::write(&mounted_file, b"foreign-subvolume!!!").unwrap();
        assert_eq!(
            fs::metadata(&first_file).unwrap().ino(),
            fs::metadata(&mounted_file).unwrap().ino()
        );
        assert_eq!(
            fs::metadata(&first_file).unwrap().len(),
            fs::metadata(&mounted_file).unwrap().len()
        );
        let output = Command::new("sudo")
            .args(["-n", "mount", "--bind"])
            .arg(&mounted_file)
            .arg(&mount_target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot create Btrfs file bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bind_capture_error = ReflinkAnchor::capture_plan(&bind_plan).unwrap_err();
        let output = Command::new("sudo")
            .args(["-n", "umount"])
            .arg(&mount_target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot remove Btrfs file bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .args([&bind_owner, &bind_external])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot delete Btrfs bind-mount test subvolumes: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            matches!(
                &bind_capture_error,
                AnchorError::NestedFilesystem(path) if path == &mount_target
            ),
            "unexpected bind-mount capture error: {bind_capture_error:?}"
        );
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned reflink test filesystem"]
    fn stable_locator_survives_parent_rename() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
        let root = PathBuf::from(test_root).join(format!("anchor-move-{}", Uuid::new_v4()));
        let original_parent = root.join("original");
        let moved_parent = root.join("moved");
        let source = original_parent.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"stable anchor").unwrap();

        let manifest = ReflinkAnchor::capture(&source).unwrap();
        let locator = manifest.file_locator("payload".to_owned()).unwrap();
        let area_name = locator.area.path_hint.file_name().unwrap().to_owned();
        fs::rename(&original_parent, &moved_parent).unwrap();
        sync_directory(&root).unwrap();

        let mut payload = String::new();
        let moved_area = moved_parent.join(area_name);
        let (mut file, resolved_area) = locator.open_with_area_hint(Some(&moved_area)).unwrap();
        file.read_to_string(&mut payload).unwrap();
        assert_eq!(payload, "stable anchor");
        assert_eq!(resolved_area, moved_area);
        manifest.remove().unwrap();
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an externally remounted test filesystem and identity record"]
    fn filesystem_identity_survives_external_remount() {
        let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
        let record = std::env::var_os("MUTUALBACKUP_FILESYSTEM_ID_RECORD")
            .expect("the remount harness must set MUTUALBACKUP_FILESYSTEM_ID_RECORD");
        let identity = filesystem_identity(PathBuf::from(test_root)).unwrap();
        let expected = format!("{:016x}\n", identity.stable_id);
        match fs::read_to_string(&record) {
            Ok(recorded) => assert_eq!(recorded, expected),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(record)
                    .unwrap();
                file.write_all(expected.as_bytes()).unwrap();
                file.sync_all().unwrap();
            }
            Err(error) => panic!("cannot read filesystem identity record: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an externally remounted reflink filesystem"]
    fn moved_anchor_discovery_survives_external_remount() {
        #[derive(Serialize, Deserialize)]
        struct RemountState {
            root: PathBuf,
            moved_parent: PathBuf,
            locator: StableAnchorFileLocator,
        }

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let record = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_ANCHOR_REMOUNT_RECORD")
                .expect("the remount harness must set MUTUALBACKUP_ANCHOR_REMOUNT_RECORD"),
        );
        match fs::read(&record) {
            Ok(bytes) => {
                let state: RemountState = decode_canonical(&bytes).unwrap();
                let (mut file, resolved_area) = state.locator.open_with_area_hint(None).unwrap();
                let mut payload = String::new();
                file.read_to_string(&mut payload).unwrap();
                assert_eq!(payload, "stable anchor across remount");
                assert!(resolved_area.starts_with(&state.moved_parent));
                fs::remove_dir_all(&state.root).unwrap();
                fs::remove_file(record).unwrap();
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let root = test_root.join("anchor-remount-discovery");
                let original_parent = root.join("original");
                let moved_parent = root.join("moved");
                let source = original_parent.join("source");
                fs::create_dir_all(&source).unwrap();
                fs::write(source.join("payload"), b"stable anchor across remount").unwrap();
                let manifest = ReflinkAnchor::capture(&source).unwrap();
                let locator = manifest.file_locator("payload".to_owned()).unwrap();
                fs::rename(&original_parent, &moved_parent).unwrap();
                sync_directory(&root).unwrap();
                let bytes = canonical_bytes(&RemountState {
                    root,
                    moved_parent,
                    locator,
                })
                .unwrap();
                let mut file = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(record)
                    .unwrap();
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
            }
            Err(error) => panic!("cannot read anchor remount record: {error}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mountinfo_paths_are_decoded_without_a_shell() {
        assert_eq!(
            decode_mount_path("/media/a\\040b\\134c").unwrap(),
            PathBuf::from("/media/a b\\c")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn anchor_discovery_never_scans_another_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let filesystem_id = filesystem_identity(temp.path()).unwrap().stable_id;
        let area = StableAnchorAreaLocator {
            area_id: Uuid::new_v4(),
            path_hint: temp.path().join("missing-area"),
            filesystem_id,
            volume_root_hint: temp.path().to_path_buf(),
        };
        let roots = anchor_discovery_roots(&area);
        assert!(roots.contains(&temp.path().to_path_buf()));
        assert!(roots.iter().all(|root| {
            filesystem_identity(root)
                .map(|identity| identity.stable_id == filesystem_id)
                .unwrap_or(false)
        }));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stable_locator_opens_through_an_indexed_area_hint() {
        let temp = tempfile::tempdir().unwrap();
        let area_id = Uuid::new_v4();
        let anchor_id = Uuid::new_v4();
        let area = temp.path().join(format!("{AREA_PREFIX}-indexed-test"));
        fs::create_dir(&area).unwrap();
        fs::write(area.join(AREA_MARKER), format!("{AREA_MAGIC}\n{area_id}\n")).unwrap();
        fs::create_dir(area.join(anchor_id.to_string())).unwrap();
        fs::write(area.join(anchor_id.to_string()).join("payload"), b"indexed").unwrap();
        let locator = StableAnchorFileLocator {
            area: StableAnchorAreaLocator {
                area_id,
                path_hint: temp.path().join("stale-area"),
                filesystem_id: u64::MAX,
                volume_root_hint: temp.path().join("stale-volume"),
            },
            anchor_id,
            relative_path: "payload".to_owned(),
        };

        let (mut file, resolved) = locator.open_with_area_hint(Some(&area)).unwrap();
        let mut payload = String::new();
        file.read_to_string(&mut payload).unwrap();
        assert_eq!(payload, "indexed");
        assert_eq!(resolved, area);
    }
}
