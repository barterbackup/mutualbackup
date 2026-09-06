use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

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
const MAX_RELATIVE_PATH_BYTES: usize = 4_096;

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
    #[error("source tree exceeds the bounded v1 capture catalog")]
    CatalogTooLarge,
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
    pub device: u64,
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
    pub volume_device: u64,
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
    device: u64,
    inode: u64,
    logical_len: u64,
    modified_secs: i64,
    modified_nanos: i64,
    changed_secs: i64,
    changed_nanos: i64,
}

impl StableAnchorFileLocator {
    pub fn open(&self) -> Result<File, AnchorError> {
        validate_relative(Path::new(&self.relative_path))?;
        let area = resolve_anchor_area(&self.area)?;
        open_anchor_beneath(&area, self.anchor_id, Path::new(&self.relative_path))
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
        let anchor_root = area.join(self.anchor_id.to_string());
        let metadata = fs::symlink_metadata(&anchor_root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AnchorError::AnchorAreaCollision(anchor_root));
        }
        fs::remove_dir_all(anchor_root)?;
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
        let anchor_root = self.area.path_hint.join(self.anchor_id.to_string());
        let metadata = fs::symlink_metadata(&anchor_root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(AnchorError::AnchorAreaCollision(anchor_root));
        }
        fs::remove_dir_all(anchor_root)?;
        sync_directory(&self.area.path_hint)?;
        Ok(())
    }
}

pub struct ReflinkAnchor;

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
        let (root_modified_secs, root_modified_nanos) = modified_parts(&root_metadata);
        Ok(ReflinkCapturePlan {
            format_version: 1,
            anchor_id: Uuid::new_v4(),
            source_root,
            area,
            root_version: capture_version(&root_metadata),
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
        remove_capture_directory(&staging)?;
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
        if !root_metadata.is_dir() || capture_version(&root_metadata) != plan.root_version {
            return Err(AnchorError::SourceChanged(PathBuf::new()));
        }
        create_private_dir_new(&staging)?;

        let capture_result = (|| {
            let entries = capture_entries(&source_root, &root_file, &root_metadata, &staging)?;
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
                let _ = fs::remove_dir_all(&staging);
                let _ = sync_directory(&plan.area.path_hint);
                return Err(error);
            }
        };
        if let Err(error) = sync_directory(&plan.area.path_hint) {
            let _ = fs::remove_dir_all(&anchor_root);
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
        remove_capture_directory(
            &plan
                .area
                .path_hint
                .join(format!(".staging-{}", plan.anchor_id)),
        )?;
        remove_capture_directory(&plan.area.path_hint.join(plan.anchor_id.to_string()))?;
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
        remove_capture_directory(
            &plan
                .area
                .path_hint
                .join(format!(".staging-{}", plan.anchor_id)),
        )?;
        sync_directory(&plan.area.path_hint)?;
        Ok(())
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
    let mut file_versions = Vec::new();
    let mut captured_links = BTreeMap::<NativeFileId, PathBuf>::new();
    let mut captured_extent_count = 0_usize;
    for entry in WalkDir::new(source_root).follow_links(false) {
        let entry = entry?;
        if entry.path() == source_root {
            continue;
        }
        if entries.len() >= MAX_CAPTURE_ENTRIES {
            return Err(AnchorError::CatalogTooLarge);
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
        if relative_string.len() > MAX_RELATIVE_PATH_BYTES {
            return Err(AnchorError::CatalogTooLarge);
        }
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
            let native_id = native_file_id(&before);
            if let Some(first_destination) = captured_links.get(&native_id) {
                fs::hard_link(first_destination, &destination)?;
            } else {
                reflink_open_file(&file, &destination).map_err(AnchorError::ReflinkUnavailable)?;
                captured_links.insert(native_id, destination.clone());
            }
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
            let captured_file = File::open(&destination)?;
            let data_extents = file_data_extents(&captured_file, after.len())?;
            captured_extent_count = captured_extent_count
                .checked_add(data_extents.len())
                .ok_or(AnchorError::CatalogTooLarge)?;
            if captured_extent_count > MAX_CAPTURE_EXTENTS {
                return Err(AnchorError::CatalogTooLarge);
            }
            entries.push(CapturedEntry::FileV2 {
                path: relative_string,
                mode: unix_mode(&after),
                logical_len: after.len(),
                modified_secs,
                modified_nanos,
                native_id,
                data_extents,
            });
            file_versions.push((relative.to_path_buf(), file, after));
        } else {
            return Err(AnchorError::UnsupportedObject(relative.to_path_buf()));
        }
    }
    for (relative, directory, before) in directory_versions {
        if !same_capture_version(&before, &directory.metadata()?) {
            return Err(AnchorError::SourceChanged(relative));
        }
    }
    for (relative, file, before) in file_versions {
        if !same_capture_version(&before, &file.metadata()?) {
            return Err(AnchorError::SourceChanged(relative));
        }
    }
    entries.sort_by(|left, right| entry_path(left).cmp(entry_path(right)));
    Ok(entries)
}

fn ensure_anchor_area(
    source_root: &Path,
    root_metadata: &fs::Metadata,
) -> Result<StableAnchorAreaLocator, AnchorError> {
    let parent = source_root
        .parent()
        .ok_or(AnchorError::NoExternalAnchorLocation)?;
    let (volume_device, volume_root_hint) = volume_root(source_root, root_metadata)?;
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
            Ok(StableAnchorAreaLocator {
                area_id,
                path_hint: area_path,
                volume_device,
                volume_root_hint,
            })
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let area_id = read_area_marker(&area_path)
                .map_err(|_| AnchorError::AnchorAreaCollision(area_path.clone()))?;
            let locator = StableAnchorAreaLocator {
                area_id,
                path_hint: area_path,
                volume_device,
                volume_root_hint,
            };
            validate_stable_anchor_area(&locator.path_hint, locator.area_id)?;
            Ok(locator)
        }
        Err(error) => Err(error.into()),
    }
}

#[cfg(unix)]
fn volume_root(
    source_root: &Path,
    root_metadata: &fs::Metadata,
) -> Result<(u64, PathBuf), AnchorError> {
    use std::os::unix::fs::MetadataExt;

    let device = root_metadata.dev();
    let mut current = source_root.to_path_buf();
    while let Some(parent) = current.parent() {
        let metadata = fs::symlink_metadata(parent)?;
        if metadata.dev() != device {
            break;
        }
        current = parent.to_path_buf();
    }
    Ok((device, current))
}

#[cfg(not(unix))]
fn volume_root(
    _source_root: &Path,
    _root_metadata: &fs::Metadata,
) -> Result<(u64, PathBuf), AnchorError> {
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
    if validate_stable_anchor_area(&area.path_hint, area.area_id).is_ok() {
        return Ok(area.path_hint.clone());
    }
    validate_volume_root(area)?;
    let mut resolved = None;
    let walker = WalkDir::new(&area.volume_root_hint)
        .follow_links(false)
        .same_file_system(true)
        .into_iter();
    for result in walker {
        let entry = match result {
            Ok(entry) => entry,
            Err(error)
                if error
                    .io_error()
                    .is_some_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied) =>
            {
                continue;
            }
            Err(error) => return Err(error.into()),
        };
        if !entry.file_type().is_dir()
            || !entry.file_name().to_string_lossy().starts_with(AREA_PREFIX)
            || read_area_marker(entry.path()).ok() != Some(area.area_id)
        {
            continue;
        }
        if resolved.replace(entry.path().to_path_buf()).is_some() {
            return Err(AnchorError::AnchorAreaCollision(entry.path().to_path_buf()));
        }
    }
    resolved.ok_or_else(|| AnchorError::AnchorAreaCollision(area.path_hint.clone()))
}

#[cfg(unix)]
fn validate_volume_root(area: &StableAnchorAreaLocator) -> Result<(), AnchorError> {
    use std::os::unix::fs::MetadataExt;

    let metadata = fs::symlink_metadata(&area.volume_root_hint)
        .map_err(|_| AnchorError::AnchorAreaCollision(area.volume_root_hint.clone()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.dev() != area.volume_device
    {
        return Err(AnchorError::AnchorAreaCollision(
            area.volume_root_hint.clone(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_volume_root(area: &StableAnchorAreaLocator) -> Result<(), AnchorError> {
    Err(AnchorError::AnchorAreaCollision(
        area.volume_root_hint.clone(),
    ))
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
        CapturedEntry::Directory { path, .. }
        | CapturedEntry::File { path, .. }
        | CapturedEntry::FileV2 { path, .. } => path,
    }
}

fn remove_capture_directory(path: &Path) -> Result<(), AnchorError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(AnchorError::AnchorAreaCollision(path.to_path_buf()));
    }
    fs::remove_dir_all(path)?;
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
fn capture_version(metadata: &fs::Metadata) -> CaptureVersion {
    use std::os::unix::fs::MetadataExt;
    CaptureVersion {
        device: metadata.dev(),
        inode: metadata.ino(),
        logical_len: metadata.len(),
        modified_secs: metadata.mtime(),
        modified_nanos: metadata.mtime_nsec(),
        changed_secs: metadata.ctime(),
        changed_nanos: metadata.ctime_nsec(),
    }
}

#[cfg(not(unix))]
fn capture_version(metadata: &fs::Metadata) -> CaptureVersion {
    let (modified_secs, modified_nanos) = modified_parts(metadata);
    CaptureVersion {
        device: 0,
        inode: 0,
        logical_len: metadata.len(),
        modified_secs,
        modified_nanos: i64::from(modified_nanos),
        changed_secs: modified_secs,
        changed_nanos: i64::from(modified_nanos),
    }
}

#[cfg(unix)]
fn native_file_id(metadata: &fs::Metadata) -> NativeFileId {
    use std::os::unix::fs::MetadataExt;
    NativeFileId {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(not(unix))]
fn native_file_id(_metadata: &fs::Metadata) -> NativeFileId {
    NativeFileId {
        device: 0,
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
        fs::rename(&original_parent, &moved_parent).unwrap();
        sync_directory(&root).unwrap();

        let mut payload = String::new();
        locator
            .open()
            .unwrap()
            .read_to_string(&mut payload)
            .unwrap();
        assert_eq!(payload, "stable anchor");
        manifest.remove().unwrap();
        fs::remove_dir_all(&root).unwrap();
    }
}
