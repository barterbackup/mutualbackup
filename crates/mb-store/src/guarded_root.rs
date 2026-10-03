//! Bounded, read-only inventory for a future guarded whole-root capture.
//! The node must persist this plan before freezing any listed file. A root is
//! not eligible for enrollment until capture, replay, and retirement consume
//! this inventory through the versioned source-backend boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use mb_core::V1_MAX_CATALOG_BYTES;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AnchorError, CaptureVersion, CapturedEntry, DirectoryStream, FilesystemIdentity,
    GIT_CATALOG_DIRECTORY, MAX_CAPTURE_DEPTH, MAX_CAPTURE_ENTRIES, MAX_CAPTURE_EXTENTS,
    MAX_RELATIVE_PATH_BYTES, NativeFileId, PinnedDirectory, StableAnchorAreaLocator,
    StableAnchorManifest, capture_manifest_name, capture_version, filesystem_identity_for_file,
    git_catalog_marker_from_root, modified_parts, open_path_no_xdev_beneath, open_source_beneath,
    open_source_root, open_stable_anchor_area, probe_guarded_link_freeze, reopen_pinned_file,
    resolve_anchor_area, unix_mode, validate_relative,
};
use crate::link_freeze::{AccessAclSnapshot, FileOwner, read_access_acl};
use crate::{
    ControlStore, LinkFreezeCaptureIntent, LinkFreezeCapturePhase, LinkFreezeEditIntent,
    LinkFreezeEditPhase,
};

const PLAN_KIND: &str = "guarded-root-plan-v1";
const ROOT_CLAIM_KIND: &str = "guarded-root-claim-v1";
const DIRECTORY_CLAIM_PREFIX: &str = "guarded-root-directory-v1/";
const MANIFEST_CLAIM_KIND: &str = "guarded-root-manifest-v1";
const RETIRE_KIND: &str = "guarded-root-retire-v1";
const LOWER_OWNERSHIP_KIND: &str = "guarded-root-lower-ownership-v1";
const PRIVATE_FILE_CAPTURE_KIND: &str = "guarded-root-private-file-capture-v1";
const DIRECTORY_ISOLATION_KIND: &str = "guarded-root-directory-isolation-v1";
const MARKER_PREFIX: &str = ".mutualbackup-guarded-root-v1-";

pub(super) fn guarded_root_marker_name(anchor_id: Uuid) -> String {
    format!("{MARKER_PREFIX}{anchor_id}")
}

fn reject_directory_xattr(directory: &File, name: &std::ffi::CStr) -> std::io::Result<()> {
    let length = unsafe {
        libc::fgetxattr(
            directory.as_raw_fd(),
            name.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    };
    if length >= 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "guarded directory isolation cannot preserve this xattr",
        ));
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(()),
        _ => Err(error),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RootClaim {
    format_version: u16,
    anchor_id: Uuid,
    root_id: NativeFileId,
    plan_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DirectoryClaim {
    format_version: u16,
    anchor_id: Uuid,
    path: String,
    parent_id: NativeFileId,
    directory_id: NativeFileId,
    plan_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RootManifestClaim {
    format_version: u16,
    anchor_id: Uuid,
    root_id: NativeFileId,
    plan_hash: [u8; 32],
    manifest_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RootRetirement {
    format_version: u16,
    anchor_id: Uuid,
    plan_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LowerOwnershipEntry {
    path: String,
    native_id: NativeFileId,
    uid: u32,
    gid: u32,
    mode: u32,
    access_acl: AccessAclSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LowerOwnershipSnapshot {
    format_version: u16,
    anchor_id: Uuid,
    plan_hash: [u8; 32],
    entries: Vec<LowerOwnershipEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PrivateFileCapture {
    format_version: u16,
    anchor_id: Uuid,
    plan_hash: [u8; 32],
    view_uid: u32,
    private_uid: u32,
    private_gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DirectoryIsolation {
    format_version: u16,
    anchor_id: Uuid,
    plan_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    view_uid: u32,
    private_uid: u32,
    private_gid: u32,
}

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
        capture_id: Uuid,
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

    fn mode_and_modified(&self) -> (u32, i64, u32) {
        match self {
            Self::Directory {
                mode,
                modified_secs,
                modified_nanos,
                ..
            }
            | Self::File {
                mode,
                modified_secs,
                modified_nanos,
                ..
            } => (*mode, *modified_secs, *modified_nanos),
        }
    }
}

fn lexically_normalized(path: &Path) -> bool {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        normalized.push(component.as_os_str());
    }
    normalized.as_os_str() == path.as_os_str()
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
        plan.validate()?;
        Ok(plan)
    }

    /// Validate a decoded durable inventory before using any of its paths or
    /// per-file journal IDs. Planning also calls this before returning it.
    pub fn validate(&self) -> Result<(), AnchorError> {
        if self.format_version != 1
            || self.anchor_id.is_nil()
            || self.area.area_id.is_nil()
            || !self.source_root.is_absolute()
            || !lexically_normalized(&self.source_root)
            || self
                .source_root
                .components()
                .any(|component| matches!(component, std::path::Component::ParentDir))
            || !self.area.path_hint.is_absolute()
            || !lexically_normalized(&self.area.path_hint)
            || !self.area.volume_root_hint.is_absolute()
            || !lexically_normalized(&self.area.volume_root_hint)
            || self.root_version.filesystem_id == 0
            || self.root_version.filesystem_id != self.area.filesystem_id
            || self.root_version.inode == 0
            || self.root_mode & libc::S_IFMT != libc::S_IFDIR
            || self.root_modified_secs != self.root_version.modified_secs
            || i64::from(self.root_modified_nanos) != self.root_version.modified_nanos
            || self.entries.len() > MAX_CAPTURE_ENTRIES
        {
            return Err(AnchorError::InvalidGuardedPlan);
        }
        let mut directories = BTreeSet::new();
        let mut capture_ids = BTreeSet::from([self.anchor_id]);
        let mut inodes = BTreeSet::from([self.root_version.inode]);
        let mut previous = None::<&str>;
        for entry in &self.entries {
            let path = entry.path();
            let relative = Path::new(path);
            let (mode, modified_secs, modified_nanos) = entry.mode_and_modified();
            if validate_relative(relative).is_err()
                || !lexically_normalized(relative)
                || path.len() > MAX_RELATIVE_PATH_BYTES
                || relative.components().count() > MAX_CAPTURE_DEPTH
                || previous.is_some_and(|prior| prior >= path)
                || path == capture_manifest_name(self.anchor_id)
                || entry.version().filesystem_id != self.root_version.filesystem_id
                || entry.version().inode == 0
                || entry.version().modified_secs != modified_secs
                || entry.version().modified_nanos != i64::from(modified_nanos)
                || mode & libc::S_IFMT
                    != if entry.is_directory() {
                        libc::S_IFDIR
                    } else {
                        libc::S_IFREG
                    }
                || !inodes.insert(entry.version().inode)
            {
                return Err(AnchorError::InvalidGuardedPlan);
            }
            if let Some(parent) = relative
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                && !directories.contains(parent.to_str().ok_or(AnchorError::InvalidGuardedPlan)?)
            {
                return Err(AnchorError::InvalidGuardedPlan);
            }
            match entry {
                GuardedRootEntry::Directory { .. } => {
                    directories.insert(path);
                }
                GuardedRootEntry::File { capture_id, .. } => {
                    if capture_id.is_nil() || !capture_ids.insert(*capture_id) {
                        return Err(AnchorError::InvalidGuardedPlan);
                    }
                }
            }
            previous = Some(path);
        }
        if mb_core::canonical_bytes(self)
            .map_err(|_| AnchorError::InvalidGuardedPlan)?
            .len()
            > V1_MAX_CATALOG_BYTES / 2
        {
            return Err(AnchorError::InvalidGuardedPlan);
        }
        Ok(())
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

    pub(crate) fn source_root_identity(&self) -> NativeFileId {
        NativeFileId {
            filesystem_id: self.root_version.filesystem_id,
            inode: self.root_version.inode,
        }
    }

    pub(crate) fn captured_entry_identity(&self, path: &str) -> Option<NativeFileId> {
        self.entries
            .iter()
            .find(|entry| entry.path() == path)
            .map(|entry| NativeFileId {
                filesystem_id: entry.version().filesystem_id,
                inode: entry.version().inode,
            })
    }

    /// Before the first mount, every lower path still has its captured name.
    /// Compare each pinned directory with the complete plan before any view
    /// namespace journal can replay. The marked Git catalog is app metadata,
    /// excluded by the same rule used during inventory planning.
    pub(crate) fn verify_initial_lower_namespace(
        &self,
        lower_root: &PinnedDirectory,
    ) -> anyhow::Result<()> {
        self.validate()?;
        anyhow::ensure!(
            lower_root.identity()? == self.source_root_identity(),
            "guarded lower root changed after capture"
        );
        let mut expected = BTreeMap::<String, BTreeSet<Vec<u8>>>::new();
        expected.insert(String::new(), BTreeSet::new());
        for entry in &self.entries {
            let relative = Path::new(entry.path());
            let parent = relative.parent().ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent = parent.to_str().ok_or(AnchorError::InvalidGuardedPlan)?;
            let name = relative
                .file_name()
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            expected
                .get_mut(parent)
                .ok_or(AnchorError::InvalidGuardedPlan)?
                .insert(name.as_bytes().to_vec());
            if entry.is_directory() {
                expected.insert(entry.path().to_owned(), BTreeSet::new());
            }
            let native_id = NativeFileId {
                filesystem_id: entry.version().filesystem_id,
                inode: entry.version().inode,
            };
            anyhow::ensure!(
                lower_root.entry_identity(relative, entry.is_directory())? == Some(native_id),
                "guarded lower entry identity changed before first mount: {}",
                entry.path()
            );
        }
        let marked_catalog = lower_root.has_marked_git_catalog()?;
        for (parent, names) in expected {
            let directory = if parent.is_empty() {
                lower_root.try_clone()?
            } else {
                lower_root.open_descendant_directory(&parent)?
            };
            let ignored =
                (parent.is_empty() && marked_catalog).then_some(GIT_CATALOG_DIRECTORY.as_bytes());
            anyhow::ensure!(
                directory.child_names_match(&names, ignored)?,
                "guarded lower directory has an unexpected or missing entry: {parent}"
            );
        }
        Ok(())
    }

    /// Before the first view mount, captured paths have not yet been renamed
    /// through FUSE. Check their private lower directories before rebuilding
    /// namespace journals, since replay itself can mutate that lower tree.
    pub(crate) fn verify_initial_private_directories(
        &self,
        lower_root: &PinnedDirectory,
        view_uid: u32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            lower_root.identity()? == self.source_root_identity(),
            "guarded lower root changed after capture"
        );
        for entry in &self.entries {
            let GuardedRootEntry::Directory { path, version, .. } = entry else {
                continue;
            };
            let directory = lower_root.open_descendant_directory(path)?;
            anyhow::ensure!(
                directory.identity()?
                    == (NativeFileId {
                        filesystem_id: version.filesystem_id,
                        inode: version.inode,
                    }),
                "guarded private directory changed before mounting: {path}"
            );
            let metadata = directory.as_file().metadata()?;
            anyhow::ensure!(
                metadata.uid() != view_uid && unix_mode(&metadata) & 0o077 == 0,
                "guarded private directory remains accessible to the view owner: {path}"
            );
        }
        Ok(())
    }

    fn lower_ownership_entry(
        path: String,
        file: &File,
        native_id: NativeFileId,
        directory: bool,
        planned_mode: u32,
    ) -> anyhow::Result<LowerOwnershipEntry> {
        let before = file.metadata()?;
        anyhow::ensure!(
            before.ino() == native_id.inode
                && before.is_dir() == directory
                && (if directory {
                    unix_mode(&before) & 0o7777 == planned_mode & 0o7777
                } else {
                    before.is_file() && unix_mode(&before) & 0o222 == 0
                }),
            "guarded lower entry changed before ownership snapshot: {path}"
        );
        let access_acl = read_access_acl(file)?;
        let after = file.metadata()?;
        anyhow::ensure!(
            (
                before.dev(),
                before.ino(),
                before.uid(),
                before.gid(),
                before.mode(),
                before.ctime(),
                before.ctime_nsec()
            ) == (
                after.dev(),
                after.ino(),
                after.uid(),
                after.gid(),
                after.mode(),
                after.ctime(),
                after.ctime_nsec()
            ),
            "guarded lower metadata changed during ownership snapshot: {path}"
        );
        Ok(LowerOwnershipEntry {
            path,
            native_id,
            uid: before.uid(),
            gid: before.gid(),
            mode: unix_mode(&before) & 0o7777,
            access_acl,
        })
    }

    fn current_lower_ownership(
        &self,
        control: &ControlStore,
        manifest: &StableAnchorManifest,
    ) -> anyhow::Result<LowerOwnershipSnapshot> {
        self.validate()?;
        anyhow::ensure!(
            Self::load_active_for_view(control, manifest)? == *self,
            "guarded lower ownership snapshot has another capture plan"
        );
        anyhow::ensure!(
            self.capture(control)? == *manifest,
            "guarded frozen bytes changed before ownership snapshot"
        );
        let lower = PinnedDirectory::open(&self.source_root)?;
        let root_id = self.source_root_identity();
        anyhow::ensure!(lower.identity()? == root_id, "guarded lower root changed");
        let mut entries = Vec::with_capacity(self.entries.len() + 1);
        entries.push(Self::lower_ownership_entry(
            String::new(),
            lower.as_file(),
            root_id,
            true,
            self.root_mode,
        )?);
        for entry in &self.entries {
            let path = entry.path();
            let native_id = NativeFileId {
                filesystem_id: entry.version().filesystem_id,
                inode: entry.version().inode,
            };
            let (mode, _, _) = entry.mode_and_modified();
            let file = match entry {
                GuardedRootEntry::Directory { .. } => lower
                    .open_descendant_directory(path)?
                    .as_file()
                    .try_clone()?,
                GuardedRootEntry::File { capture_id, .. } => {
                    let intent = LinkFreezeCaptureIntent::load(control, *capture_id)?
                        .ok_or_else(|| anyhow::anyhow!("guarded file capture disappeared"))?;
                    anyhow::ensure!(
                        intent.phase() == LinkFreezeCapturePhase::Frozen,
                        "guarded file was edited before lower isolation"
                    );
                    let relative = Path::new(path);
                    let parent = relative.parent().ok_or(AnchorError::InvalidGuardedPlan)?;
                    let directory = if parent.as_os_str().is_empty() {
                        lower.try_clone()?
                    } else {
                        lower.open_descendant_directory(parent)?
                    };
                    let file = directory
                        .open_child_file(
                            relative
                                .file_name()
                                .ok_or(AnchorError::InvalidGuardedPlan)?,
                        )?
                        .ok_or_else(|| anyhow::anyhow!("guarded lower file disappeared: {path}"))?;
                    let anchor = manifest.file_locator(path.to_owned())?.open()?;
                    anyhow::ensure!(
                        anchor.metadata()?.ino() == native_id.inode
                            && file.metadata()?.nlink() == 2,
                        "guarded lower file no longer shares its frozen anchor: {path}"
                    );
                    file
                }
            };
            let mut ownership = Self::lower_ownership_entry(
                path.to_owned(),
                &file,
                native_id,
                entry.is_directory(),
                mode,
            )?;
            if let GuardedRootEntry::File { capture_id, .. } = entry {
                let intent = LinkFreezeCaptureIntent::load(control, *capture_id)?
                    .ok_or_else(|| anyhow::anyhow!("guarded file capture disappeared"))?;
                if let Some(original) = intent.original_owner_for_snapshot(
                    control,
                    FileOwner {
                        uid: ownership.uid,
                        gid: ownership.gid,
                    },
                    &crate::link_freeze::FileAccessSnapshot {
                        format_version: 1,
                        mode: ownership.mode,
                        access_acl: ownership.access_acl.clone(),
                    },
                )? {
                    ownership.uid = original.uid;
                    ownership.gid = original.gid;
                }
            }
            entries.push(ownership);
        }
        let snapshot = LowerOwnershipSnapshot {
            format_version: 1,
            anchor_id: self.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes(),
            entries,
        };
        anyhow::ensure!(
            mb_core::canonical_bytes(&snapshot)?.len() <= V1_MAX_CATALOG_BYTES / 2,
            AnchorError::CatalogTooLarge
        );
        Ok(snapshot)
    }

    /// Save the lower tree's original owners and modes. The legacy freeze path
    /// records this before owner isolation; an owner-first capture reconstructs
    /// file owners from the journals written before its private transition.
    /// The original file access state is retained by each freeze journal.
    pub fn prepare_private_lower_ownership(
        &self,
        control: &ControlStore,
        manifest: &StableAnchorManifest,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !crate::guarded_mount::mount_claim_exists(control, self.anchor_id)?,
            "guarded view is already claimed"
        );
        let snapshot = self.current_lower_ownership(control, manifest)?;
        let bytes = mb_core::canonical_bytes(&snapshot)?;
        if !control.put_record_if_absent(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes(), &bytes)? {
            anyhow::ensure!(
                control.get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())? == Some(bytes),
                "guarded lower ownership changed after its durable snapshot"
            );
        }
        Ok(())
    }

    fn private_file_capture(
        &self,
        control: &ControlStore,
    ) -> anyhow::Result<Option<PrivateFileCapture>> {
        let Some(bytes) =
            control.get_record(PRIVATE_FILE_CAPTURE_KIND, self.anchor_id.as_bytes())?
        else {
            return Ok(None);
        };
        let record: PrivateFileCapture = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            record.format_version == 1
                && record.anchor_id == self.anchor_id
                && record.plan_hash == *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes()
                && record.private_uid != record.view_uid,
            "guarded private file capture differs from its plan"
        );
        Ok(Some(record))
    }

    /// Select the owner-first file capture path durably before freezing any
    /// file. Reopen uses the same selection even if the first attempt stopped
    /// with a prepared file or a private source that has no anchor yet.
    pub fn capture_private_file_owners(
        &self,
        control: &ControlStore,
        view_uid: u32,
        private_uid: u32,
        private_gid: u32,
    ) -> anyhow::Result<StableAnchorManifest> {
        self.validate()?;
        anyhow::ensure!(private_uid != view_uid, "private owner is the view owner");
        anyhow::ensure!(
            !crate::guarded_mount::mount_claim_exists(control, self.anchor_id)?,
            "guarded view is already claimed"
        );
        let expected = PrivateFileCapture {
            format_version: 1,
            anchor_id: self.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes(),
            view_uid,
            private_uid,
            private_gid,
        };
        match self.private_file_capture(control)? {
            Some(record) => anyhow::ensure!(
                record == expected,
                "guarded private file capture parameters changed"
            ),
            None => {
                anyhow::ensure!(
                    control
                        .get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?
                        .is_none()
                        && control
                            .get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())?
                            .is_none(),
                    "guarded root was already captured before private selection"
                );
                for entry in &self.entries {
                    if let GuardedRootEntry::File { capture_id, .. } = entry {
                        anyhow::ensure!(
                            LinkFreezeCaptureIntent::load(control, *capture_id)?.is_none(),
                            "guarded file was already frozen before private selection"
                        );
                    }
                }
                anyhow::ensure!(control.put_record_if_absent(
                    PRIVATE_FILE_CAPTURE_KIND,
                    self.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(&expected)?,
                )?);
            }
        }
        let manifest = self.capture(control)?;
        self.prepare_private_lower_ownership(control, &manifest)?;
        Ok(manifest)
    }

    fn directory_isolation(
        &self,
        control: &ControlStore,
        snapshot_bytes: &[u8],
    ) -> anyhow::Result<Option<DirectoryIsolation>> {
        let Some(bytes) =
            control.get_record(DIRECTORY_ISOLATION_KIND, self.anchor_id.as_bytes())?
        else {
            return Ok(None);
        };
        let record: DirectoryIsolation = mb_core::decode_canonical(&bytes)?;
        let private = self
            .private_file_capture(control)?
            .ok_or_else(|| anyhow::anyhow!("directory isolation lost private capture policy"))?;
        anyhow::ensure!(
            record.format_version == 1
                && record.anchor_id == self.anchor_id
                && record.plan_hash == private.plan_hash
                && record.snapshot_hash == *blake3::hash(snapshot_bytes).as_bytes()
                && record.view_uid == private.view_uid
                && record.private_uid == private.private_uid
                && record.private_gid == private.private_gid,
            "guarded directory isolation differs from its ownership snapshot"
        );
        Ok(Some(record))
    }

    fn lower_directory_entries<'a>(
        &'a self,
        snapshot: &'a LowerOwnershipSnapshot,
    ) -> Vec<&'a LowerOwnershipEntry> {
        let mut entries = Vec::with_capacity(self.entries.len() + 1);
        entries.push(&snapshot.entries[0]);
        for (planned, recorded) in self.entries.iter().zip(snapshot.entries.iter().skip(1)) {
            if planned.is_directory() {
                entries.push(recorded);
            }
        }
        entries
    }

    fn retirement_directory_paths(
        &self,
        control: &ControlStore,
    ) -> anyhow::Result<BTreeMap<String, Option<PathBuf>>> {
        let mut paths = BTreeMap::from([(String::new(), Some(PathBuf::new()))]);
        let mut occupied = std::collections::BTreeSet::from([PathBuf::new()]);
        for (index, entry) in self.entries.iter().enumerate() {
            let GuardedRootEntry::Directory { path, version, .. } = entry else {
                continue;
            };
            let expected = NativeFileId {
                filesystem_id: version.filesystem_id,
                inode: version.inode,
            };
            let current = crate::guarded_view_probe::captured_directory_path_for_retirement(
                control,
                self.anchor_id,
                u64::try_from(index)? + 2,
                path,
                expected,
            )?;
            anyhow::ensure!(
                current
                    .as_ref()
                    .is_none_or(|current| occupied.insert(current.clone()))
                    && paths.insert(path.clone(), current).is_none(),
                "captured directories alias a retirement path"
            );
        }
        Ok(paths)
    }

    fn open_lower_directory(
        lower: &PinnedDirectory,
        entry: &LowerOwnershipEntry,
    ) -> anyhow::Result<PinnedDirectory> {
        Self::open_lower_directory_at_path(lower, entry, Path::new(&entry.path))
    }

    fn open_lower_directory_at_path(
        lower: &PinnedDirectory,
        entry: &LowerOwnershipEntry,
        path: &Path,
    ) -> anyhow::Result<PinnedDirectory> {
        let directory = if path.as_os_str().is_empty() {
            lower.try_clone()?
        } else {
            lower.open_descendant_directory(path)?
        };
        anyhow::ensure!(
            directory.identity()? == entry.native_id
                && (path.as_os_str().is_empty()
                    || lower.entry_identity(path, true)? == Some(entry.native_id)),
            "guarded lower directory identity changed: {}",
            path.display()
        );
        Ok(directory)
    }

    fn check_directory_isolation_metadata(directory: &File) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(read_access_acl(directory)?, AccessAclSnapshot::Absent),
            "guarded directory isolation cannot preserve an access ACL"
        );
        reject_directory_xattr(directory, c"system.posix_acl_default")?;
        reject_directory_xattr(directory, c"security.capability")?;
        Ok(())
    }

    /// Make every captured lower directory inaccessible to the view user.
    /// The root snapshot and this bound record precede all chmod/chown calls;
    /// replay accepts only original, mode-restricted, or fully private states.
    pub fn isolate_lower_directories(
        &self,
        control: &ControlStore,
        manifest: &StableAnchorManifest,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !crate::guarded_mount::mount_claim_exists(control, self.anchor_id)?,
            "guarded view is already claimed"
        );
        anyhow::ensure!(
            Self::load_active_for_view(control, manifest)? == *self
                && self.capture(control)? == *manifest,
            "guarded directory isolation needs its published private capture"
        );
        let private = self
            .private_file_capture(control)?
            .ok_or_else(|| anyhow::anyhow!("guarded private file capture is missing"))?;
        let snapshot_bytes = control
            .get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("guarded lower ownership snapshot is missing"))?;
        self.reconcile(control)?;
        let snapshot: LowerOwnershipSnapshot = mb_core::decode_canonical(&snapshot_bytes)?;
        let lower = PinnedDirectory::open(&self.source_root)?;
        let expected = DirectoryIsolation {
            format_version: 1,
            anchor_id: self.anchor_id,
            plan_hash: private.plan_hash,
            snapshot_hash: *blake3::hash(&snapshot_bytes).as_bytes(),
            view_uid: private.view_uid,
            private_uid: private.private_uid,
            private_gid: private.private_gid,
        };
        let prior = self.directory_isolation(control, &snapshot_bytes)?;
        anyhow::ensure!(
            prior.as_ref().is_none_or(|record| record == &expected),
            "guarded directory isolation parameters changed"
        );
        self.verify_lower_directories_for_retirement(&snapshot, &lower, prior.as_ref(), None)?;
        self.verify_initial_lower_namespace(&lower)?;
        for entry in self.lower_directory_entries(&snapshot) {
            let directory = Self::open_lower_directory(&lower, entry)?;
            Self::check_directory_isolation_metadata(directory.as_file())?;
        }
        if prior.is_none() {
            anyhow::ensure!(control.put_record_if_absent(
                DIRECTORY_ISOLATION_KIND,
                self.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&expected)?,
            )?);
        }
        for entry in self.lower_directory_entries(&snapshot).into_iter().rev() {
            let directory = Self::open_lower_directory(&lower, entry)?;
            let before = directory.as_file().metadata()?;
            if unix_mode(&before) & 0o7777 != 0o700 {
                directory
                    .as_file()
                    .set_permissions(std::fs::Permissions::from_mode(0o700))?;
                directory.sync_all()?;
            }
            let after_mode = directory.as_file().metadata()?;
            anyhow::ensure!(
                unix_mode(&after_mode) & 0o7777 == 0o700,
                "guarded lower directory mode was not isolated: {}",
                entry.path
            );
            if (after_mode.uid(), after_mode.gid()) != (private.private_uid, private.private_gid) {
                let result = unsafe {
                    libc::fchown(
                        directory.as_file().as_raw_fd(),
                        private.private_uid as libc::uid_t,
                        private.private_gid as libc::gid_t,
                    )
                };
                if result < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                directory.sync_all()?;
            }
            let after = directory.as_file().metadata()?;
            anyhow::ensure!(
                (after.uid(), after.gid()) == (private.private_uid, private.private_gid)
                    && unix_mode(&after) & 0o7777 == 0o700
                    && Self::open_lower_directory(&lower, entry)?.identity()? == entry.native_id,
                "guarded lower directory owner was not isolated: {}",
                entry.path
            );
        }
        self.verify_lower_directories_for_retirement(&snapshot, &lower, Some(&expected), None)?;
        self.verify_initial_lower_namespace(&lower)?;
        let root_metadata = lower.as_file().metadata()?;
        anyhow::ensure!(
            (root_metadata.uid(), root_metadata.gid())
                == (private.private_uid, private.private_gid)
                && unix_mode(&root_metadata) & 0o7777 == 0o700,
            "guarded lower root was not privately isolated"
        );
        self.verify_initial_private_directories(&lower, private.view_uid)?;
        Ok(())
    }

    /// Isolate every frozen file owner using the durable root snapshot. Each
    /// file has its own write exclusion and owner journal; a failed pass can
    /// resume without changing the identity or bytes of an earlier anchor.
    /// Directory isolation and enrollment remain separate gated transitions.
    pub fn isolate_frozen_file_owners(
        &self,
        control: &ControlStore,
        manifest: &StableAnchorManifest,
        view_uid: u32,
        private_uid: u32,
        private_gid: u32,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(private_uid != view_uid, "private owner is the view owner");
        anyhow::ensure!(
            !crate::guarded_mount::mount_claim_exists(control, self.anchor_id)?,
            "guarded view is already claimed"
        );
        anyhow::ensure!(
            Self::load_active_for_view(control, manifest)? == *self,
            "guarded file isolation has another capture plan"
        );
        let bytes = control
            .get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("guarded lower ownership snapshot is missing"))?;
        self.reconcile(control)?;
        let snapshot: LowerOwnershipSnapshot = mb_core::decode_canonical(&bytes)?;
        let source_root = PinnedDirectory::open(&self.source_root)?;
        anyhow::ensure!(source_root.identity()? == self.source_root_identity());
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let anchor_root = area
            .open_child_directory(self.anchor_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("guarded anchor root disappeared"))?;
        for (index, entry) in self.entries.iter().enumerate() {
            let GuardedRootEntry::File {
                path,
                capture_id,
                version,
                ..
            } = entry
            else {
                continue;
            };
            let original = &snapshot.entries[index + 1];
            let relative = Path::new(path);
            let parent = relative.parent().ok_or(AnchorError::InvalidGuardedPlan)?;
            let source_parent = if parent.as_os_str().is_empty() {
                source_root.try_clone()?
            } else {
                source_root.open_descendant_directory(parent)?
            };
            let anchor_parent = if parent.as_os_str().is_empty() {
                anchor_root.try_clone()?
            } else {
                anchor_root.open_descendant_directory(parent)?
            };
            let name = relative
                .file_name()
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let intent = LinkFreezeCaptureIntent::load(control, *capture_id)?
                .ok_or_else(|| anyhow::anyhow!("guarded file capture disappeared: {path}"))?;
            anyhow::ensure!(
                source_parent.entry_identity(name, false)? == Some(original.native_id)
                    && anchor_parent.entry_identity(name, false)? == Some(original.native_id),
                "guarded lower file changed before owner isolation: {path}"
            );
            anyhow::ensure!(intent.matches_root_file_plan(
                *capture_id,
                source_parent.identity()?,
                NativeFileId {
                    filesystem_id: version.filesystem_id,
                    inode: version.inode,
                },
                &anchor_parent,
                Path::new(name),
            )?);
            if original.uid == private_uid {
                let metadata = anchor_parent
                    .open_child_file(name)?
                    .ok_or_else(|| anyhow::anyhow!("guarded anchor disappeared: {path}"))?
                    .metadata()?;
                anyhow::ensure!(
                    metadata.uid() == private_uid
                        && metadata.gid() == original.gid
                        && metadata.nlink() == 2
                        && unix_mode(&metadata) & 0o022 == 0,
                    "guarded file is no longer private: {path}"
                );
                continue;
            }
            intent.isolate_owner(
                control,
                &source_parent,
                &anchor_parent,
                FileOwner {
                    uid: original.uid,
                    gid: original.gid,
                },
                FileOwner {
                    uid: private_uid,
                    gid: private_gid,
                },
            )?;
        }
        anyhow::ensure!(
            self.capture(control)? == *manifest,
            "guarded frozen bytes changed during owner isolation"
        );
        Ok(())
    }

    /// An unstarted isolation may be canceled only while every pinned lower
    /// inode still matches the original snapshot. A changed owner keeps the
    /// recovery obligation durable and blocks ordinary anchor retirement.
    pub fn cancel_private_lower_ownership(
        &self,
        control: &ControlStore,
        manifest: &StableAnchorManifest,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !crate::guarded_mount::mount_claim_exists(control, self.anchor_id)?,
            "guarded view is already claimed"
        );
        anyhow::ensure!(
            self.private_file_capture(control)?.is_none(),
            "private file capture needs journal-aware root retirement"
        );
        anyhow::ensure!(
            control
                .get_record(DIRECTORY_ISOLATION_KIND, self.anchor_id.as_bytes())?
                .is_none(),
            "isolated lower directories need journal-aware retirement"
        );
        for entry in &self.entries {
            if let GuardedRootEntry::File { capture_id, .. } = entry {
                anyhow::ensure!(
                    !LinkFreezeCaptureIntent::owner_isolation_pending(control, *capture_id)?,
                    "isolated file owner needs journal-aware retirement"
                );
            }
        }
        let Some(bytes) = control.get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())?
        else {
            return Ok(());
        };
        let recorded: LowerOwnershipSnapshot = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            recorded == self.current_lower_ownership(control, manifest)?,
            "guarded lower ownership changed before cancellation"
        );
        control.delete_record_if_value(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes(), &bytes)?;
        Ok(())
    }

    fn verify_lower_directories_for_retirement(
        &self,
        snapshot: &LowerOwnershipSnapshot,
        lower: &PinnedDirectory,
        isolation: Option<&DirectoryIsolation>,
        paths: Option<&BTreeMap<String, Option<PathBuf>>>,
    ) -> anyhow::Result<()> {
        for entry in self.lower_directory_entries(snapshot) {
            let current = match paths {
                Some(paths) => paths
                    .get(&entry.path)
                    .ok_or_else(|| {
                        anyhow::anyhow!("captured directory lost its retirement record")
                    })?
                    .as_deref(),
                None => Some(Path::new(&entry.path)),
            };
            let Some(current) = current else {
                anyhow::ensure!(
                    !lower.contains_descendant_id(entry.native_id)?,
                    "removed captured directory still has a lower-tree name: {}",
                    entry.path
                );
                continue;
            };
            let directory = Self::open_lower_directory_at_path(lower, entry, current)?;
            if isolation.is_some() {
                Self::check_directory_isolation_metadata(directory.as_file())?;
            }
            let metadata = directory.as_file().metadata()?;
            let mode = unix_mode(&metadata) & 0o7777;
            let original =
                (metadata.uid(), metadata.gid()) == (entry.uid, entry.gid) && mode == entry.mode;
            let permitted = match isolation {
                Some(record) => {
                    let restricted_original =
                        (metadata.uid(), metadata.gid()) == (entry.uid, entry.gid) && mode == 0o700;
                    let private = (metadata.uid(), metadata.gid())
                        == (record.private_uid, record.private_gid)
                        && mode == 0o700;
                    matches!(entry.access_acl, AccessAclSnapshot::Absent)
                        && (original || restricted_original || private)
                        && matches!(
                            read_access_acl(directory.as_file())?,
                            AccessAclSnapshot::Absent
                        )
                }
                None => original && read_access_acl(directory.as_file())? == entry.access_acl,
            };
            anyhow::ensure!(
                permitted,
                "guarded lower directory changed during retirement: {}",
                entry.path
            );
        }
        Ok(())
    }

    fn source_file_at_recorded_identity(
        lower: &PinnedDirectory,
        entry: &LowerOwnershipEntry,
    ) -> anyhow::Result<Option<File>> {
        let path = Path::new(&entry.path);
        if lower.entry_identity(path, false)? != Some(entry.native_id) {
            return Ok(None);
        }
        let parent = path.parent().ok_or(AnchorError::InvalidGuardedPlan)?;
        let directory = if parent.as_os_str().is_empty() {
            lower.try_clone()?
        } else {
            lower.open_descendant_directory(parent)?
        };
        let name = path.file_name().ok_or(AnchorError::InvalidGuardedPlan)?;
        let file = directory
            .open_child_file(name)?
            .ok_or_else(|| anyhow::anyhow!("guarded lower file disappeared: {}", entry.path))?;
        anyhow::ensure!(
            directory.identity()?.filesystem_id == entry.native_id.filesystem_id
                && file.metadata()?.ino() == entry.native_id.inode
                && directory.entry_identity(name, false)? == Some(entry.native_id),
            "guarded lower file changed during retirement: {}",
            entry.path
        );
        Ok(Some(file))
    }

    fn verify_lower_ownership_before_retirement(
        &self,
        control: &ControlStore,
        snapshot: &LowerOwnershipSnapshot,
        isolation: Option<&DirectoryIsolation>,
        directory_paths: &BTreeMap<String, Option<PathBuf>>,
    ) -> anyhow::Result<()> {
        let lower = PinnedDirectory::open(&self.source_root)?;
        self.verify_lower_directories_for_retirement(
            snapshot,
            &lower,
            isolation,
            Some(directory_paths),
        )?;
        for (planned, recorded) in self.entries.iter().zip(snapshot.entries.iter().skip(1)) {
            let GuardedRootEntry::File { capture_id, .. } = planned else {
                continue;
            };
            let Some(capture) = LinkFreezeCaptureIntent::load(control, *capture_id)? else {
                continue;
            };
            let current = Self::source_file_at_recorded_identity(&lower, recorded)?
                .map(|file| file.metadata())
                .transpose()?;
            capture.verify_lower_owner_before_retirement(
                control,
                FileOwner {
                    uid: recorded.uid,
                    gid: recorded.gid,
                },
                current.map(|metadata| FileOwner {
                    uid: metadata.uid(),
                    gid: metadata.gid(),
                }),
            )?;
        }
        Ok(())
    }

    fn finish_lower_ownership_retirement(
        &self,
        control: &ControlStore,
        snapshot: &LowerOwnershipSnapshot,
        bytes: &[u8],
        isolation: Option<&DirectoryIsolation>,
        directory_paths: &BTreeMap<String, Option<PathBuf>>,
    ) -> anyhow::Result<()> {
        let lower = PinnedDirectory::open(&self.source_root)?;
        self.verify_lower_directories_for_retirement(
            snapshot,
            &lower,
            isolation,
            Some(directory_paths),
        )?;
        for planned in &self.entries {
            let GuardedRootEntry::File { capture_id, .. } = planned else {
                continue;
            };
            anyhow::ensure!(
                LinkFreezeCaptureIntent::load(control, *capture_id)?.is_none()
                    && !LinkFreezeCaptureIntent::owner_isolation_pending(control, *capture_id)?,
                "guarded lower file still has an owner restoration obligation"
            );
        }
        if let Some(record) = isolation {
            let mut entries = self.lower_directory_entries(snapshot);
            entries.sort_by_key(|entry| {
                std::cmp::Reverse(
                    directory_paths[&entry.path]
                        .as_ref()
                        .map(|path| path.components().count())
                        .unwrap_or(usize::MAX),
                )
            });
            for entry in entries {
                let Some(current) = directory_paths[&entry.path].as_deref() else {
                    continue;
                };
                let directory = Self::open_lower_directory_at_path(&lower, entry, current)?;
                Self::check_directory_isolation_metadata(directory.as_file())?;
                let before = directory.as_file().metadata()?;
                if (before.uid(), before.gid()) != (entry.uid, entry.gid) {
                    let result = unsafe {
                        libc::fchown(
                            directory.as_file().as_raw_fd(),
                            entry.uid as libc::uid_t,
                            entry.gid as libc::gid_t,
                        )
                    };
                    if result < 0 {
                        return Err(std::io::Error::last_os_error().into());
                    }
                    directory.sync_all()?;
                }
                if unix_mode(&directory.as_file().metadata()?) & 0o7777 != entry.mode {
                    directory
                        .as_file()
                        .set_permissions(std::fs::Permissions::from_mode(entry.mode))?;
                    directory.sync_all()?;
                }
                let after = directory.as_file().metadata()?;
                anyhow::ensure!(
                    (after.uid(), after.gid()) == (entry.uid, entry.gid)
                        && unix_mode(&after) & 0o7777 == entry.mode
                        && read_access_acl(directory.as_file())? == entry.access_acl
                        && Self::open_lower_directory_at_path(&lower, entry, current)?
                            .identity()?
                            == entry.native_id,
                    "guarded lower directory was not restored: {}",
                    entry.path
                );
            }
            self.verify_lower_directories_for_retirement(
                snapshot,
                &lower,
                None,
                Some(directory_paths),
            )?;
            control.delete_record_if_value(
                DIRECTORY_ISOLATION_KIND,
                self.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(record)?,
            )?;
        }
        control.delete_record_if_value(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes(), bytes)?;
        Ok(())
    }

    /// A frozen inode has guard-restricted lower permissions, so its captured
    /// mode is the visible one. Once the edit journal made that inode
    /// independent, the lower inode's mode includes later owner chmods and is
    /// authoritative even after a view remount.
    pub(crate) fn file_has_editable_inode(
        &self,
        control: &ControlStore,
        captured_path: &str,
    ) -> anyhow::Result<bool> {
        let capture_id = match self
            .entries
            .iter()
            .find(|entry| entry.path() == captured_path)
        {
            Some(GuardedRootEntry::File { capture_id, .. }) => *capture_id,
            _ => anyhow::bail!("guarded file mode has no captured file"),
        };
        let capture = LinkFreezeCaptureIntent::load(control, capture_id)?
            .ok_or_else(|| anyhow::anyhow!("guarded file capture journal disappeared"))?;
        anyhow::ensure!(
            matches!(
                capture.phase(),
                LinkFreezeCapturePhase::Frozen | LinkFreezeCapturePhase::Detached
            ),
            "guarded file capture is not published"
        );
        if capture.phase() == LinkFreezeCapturePhase::Detached {
            return Ok(true);
        }
        Ok(LinkFreezeEditIntent::load(control, capture_id)?
            .is_some_and(|edit| edit.phase() == LinkFreezeEditPhase::Editable))
    }

    pub(crate) fn load_active_for_view(
        control: &ControlStore,
        manifest: &StableAnchorManifest,
    ) -> anyhow::Result<Self> {
        let plan = Self::load_for_manifest(control, manifest)?
            .ok_or_else(|| anyhow::anyhow!("guarded view has no durable capture plan"))?;
        anyhow::ensure!(
            control
                .get_record(RETIRE_KIND, plan.anchor_id.as_bytes())?
                .is_none()
                && control
                    .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())?
                    .is_some(),
            "guarded view capture is not published or is retiring"
        );
        Ok(plan)
    }

    /// Rebuild a published view from the sealed anchor catalog after the
    /// process that held its manifest has exited. The manifest claim and plan
    /// must still identify the exact catalog bytes before a caller remounts.
    pub(crate) fn load_published_manifest(
        control: &ControlStore,
        anchor_id: Uuid,
    ) -> anyhow::Result<StableAnchorManifest> {
        let plan_bytes = control
            .get_record(PLAN_KIND, anchor_id.as_bytes())?
            .ok_or_else(|| anyhow::anyhow!("guarded root has no durable capture plan"))?;
        let plan: Self = mb_core::decode_canonical(&plan_bytes)?;
        plan.validate()?;
        anyhow::ensure!(plan.anchor_id == anchor_id, "guarded plan ID changed");
        let area_path = resolve_anchor_area(&plan.area)?;
        let area_file = open_stable_anchor_area(&area_path, &plan.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: plan.area.filesystem_id,
        };
        let anchor_root = area
            .open_child_directory(anchor_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("guarded anchor root disappeared"))?;
        let catalog = anchor_root
            .open_child_file(capture_manifest_name(anchor_id))?
            .ok_or_else(|| anyhow::anyhow!("guarded sealed manifest disappeared"))?;
        let metadata = catalog.metadata()?;
        anyhow::ensure!(
            metadata.len() <= V1_MAX_CATALOG_BYTES as u64
                && metadata.nlink() == 1
                && unix_mode(&metadata) & 0o222 == 0,
            "guarded sealed manifest metadata changed"
        );
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        catalog
            .take(V1_MAX_CATALOG_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        anyhow::ensure!(
            bytes.len() == metadata.len() as usize,
            "guarded sealed manifest changed"
        );
        let manifest: StableAnchorManifest = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            Self::load_active_for_view(control, &manifest)? == plan,
            "guarded sealed manifest differs from its active plan"
        );
        Ok(manifest)
    }

    /// Decode a pending guarded plan without requiring its source volume to
    /// be online. Capture itself performs the descriptor and journal checks.
    pub fn reconcile(&self, control: &ControlStore) -> anyhow::Result<()> {
        self.validate()?;
        self.private_file_capture(control)?;
        let directory_snapshot =
            control.get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())?;
        if let Some(bytes) = &directory_snapshot {
            self.directory_isolation(control, bytes)?;
        } else {
            anyhow::ensure!(
                control
                    .get_record(DIRECTORY_ISOLATION_KIND, self.anchor_id.as_bytes())?
                    .is_none(),
                "guarded directory isolation lost its ownership snapshot"
            );
        }
        if let Some(recorded) = control.get_record(PLAN_KIND, self.anchor_id.as_bytes())? {
            anyhow::ensure!(
                recorded == mb_core::canonical_bytes(self)?,
                "guarded root plan changed during replay"
            );
        }
        if let Some(bytes) = control.get_record(RETIRE_KIND, self.anchor_id.as_bytes())? {
            let retirement: RootRetirement = mb_core::decode_canonical(&bytes)?;
            anyhow::ensure!(
                retirement.format_version == 1
                    && retirement.anchor_id == self.anchor_id
                    && retirement.plan_hash
                        == *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes(),
                "guarded root retirement belongs to another plan"
            );
        }
        if let Some(bytes) = control.get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())? {
            anyhow::ensure!(
                bytes.len() <= V1_MAX_CATALOG_BYTES / 2,
                "guarded lower ownership snapshot exceeds its bound"
            );
            let snapshot: LowerOwnershipSnapshot = mb_core::decode_canonical(&bytes)?;
            anyhow::ensure!(
                snapshot.format_version == 1
                    && snapshot.anchor_id == self.anchor_id
                    && snapshot.plan_hash
                        == *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes()
                    && snapshot.entries.len() == self.entries.len() + 1,
                "guarded lower ownership snapshot differs from its capture plan"
            );
            for (index, recorded) in snapshot.entries.iter().enumerate() {
                let (path, expected, directory, planned_mode) = if index == 0 {
                    ("", self.source_root_identity(), true, self.root_mode)
                } else {
                    let planned = &self.entries[index - 1];
                    (
                        planned.path(),
                        NativeFileId {
                            filesystem_id: planned.version().filesystem_id,
                            inode: planned.version().inode,
                        },
                        planned.is_directory(),
                        planned.mode_and_modified().0,
                    )
                };
                anyhow::ensure!(
                    recorded.path == path
                        && recorded.native_id == expected
                        && recorded.mode & !0o7777 == 0
                        && if directory {
                            recorded.mode == planned_mode & 0o7777
                        } else {
                            recorded.mode & 0o222 == 0
                        },
                    "guarded lower ownership entry differs from its capture plan: {path}"
                );
            }
        }
        Ok(())
    }

    /// Identify the backend that owns a stored revision manifest before node
    /// cleanup. A manifest claim binds its exact bytes; once retirement has
    /// unlinked that claim, the durable retirement marker continues replay.
    pub fn load_for_manifest(
        control: &ControlStore,
        manifest: &StableAnchorManifest,
    ) -> anyhow::Result<Option<Self>> {
        let Some(bytes) = control.get_record(PLAN_KIND, manifest.anchor_id.as_bytes())? else {
            return Ok(None);
        };
        let plan: Self = mb_core::decode_canonical(&bytes)?;
        plan.validate()?;
        anyhow::ensure!(
            plan.anchor_id == manifest.anchor_id
                && manifest.format_version == 2
                && plan.area == manifest.area
                && plan.source_root == manifest.source_root_hint
                && plan.root_mode == manifest.root_mode
                && plan.root_modified_secs == manifest.root_modified_secs
                && plan.root_modified_nanos == manifest.root_modified_nanos
                && plan.entries.len() == manifest.entries.len(),
            "revision manifest differs from its guarded source plan"
        );
        plan.reconcile(control)?;
        if let Some(claim_bytes) =
            control.get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())?
        {
            let claim: RootManifestClaim = mb_core::decode_canonical(&claim_bytes)?;
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == plan.anchor_id
                    && claim.plan_hash == *blake3::hash(&bytes).as_bytes()
                    && claim.manifest_hash
                        == *blake3::hash(&mb_core::canonical_bytes(manifest)?).as_bytes(),
                "revision manifest differs from its guarded claim"
            );
        } else {
            anyhow::ensure!(
                control
                    .get_record(RETIRE_KIND, plan.anchor_id.as_bytes())?
                    .is_some(),
                "guarded revision manifest has no durable claim"
            );
        }
        Ok(Some(plan))
    }

    /// Claim the empty root directory before a future guarded capture starts.
    /// Reopening a claimed directory is safe even after it gains file anchors.
    /// The sibling sealed marker keeps app metadata out of the captured tree.
    pub fn prepare_anchor_root(&self, control: &ControlStore) -> anyhow::Result<NativeFileId> {
        self.validate()?;
        anyhow::ensure!(
            control
                .get_record(RETIRE_KIND, self.anchor_id.as_bytes())?
                .is_none(),
            "guarded root anchor is being retired"
        );
        let plan_bytes = mb_core::canonical_bytes(self)?;
        let plan_hash = *blake3::hash(&plan_bytes).as_bytes();
        let new_plan =
            control.put_record_if_absent(PLAN_KIND, self.anchor_id.as_bytes(), &plan_bytes)?;
        if !new_plan {
            anyhow::ensure!(
                control.get_record(PLAN_KIND, self.anchor_id.as_bytes())? == Some(plan_bytes),
                "guarded root anchor belongs to another plan"
            );
        }
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let directory_name = self.anchor_id.to_string();
        let marker_name = self.marker_name();
        let marker_bytes = self.marker_bytes(plan_hash);
        let recorded_claim = control.get_record(ROOT_CLAIM_KIND, self.anchor_id.as_bytes())?;
        if new_plan {
            anyhow::ensure!(
                area.entry_identity(&marker_name, false)?.is_none()
                    && area.entry_identity(&directory_name, true)?.is_none()
                    && recorded_claim.is_none(),
                "unowned guarded root anchor namespace collides with a new plan"
            );
        }
        match self.verified_marker(&area, plan_hash)? {
            Some(_) => {}
            None => {
                anyhow::ensure!(
                    recorded_claim.is_none()
                        && area.entry_identity(&directory_name, true)?.is_none(),
                    "guarded root directory exists without its ownership marker"
                );
                area.publish_sealed_bytes_child(&marker_name, &marker_bytes)?;
            }
        }
        if let Some(bytes) = recorded_claim {
            let claim: RootClaim = mb_core::decode_canonical(&bytes)?;
            let root = area
                .open_child_directory(&directory_name)?
                .ok_or_else(|| anyhow::anyhow!("claimed guarded root directory is missing"))?;
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == self.anchor_id
                    && claim.plan_hash == plan_hash
                    && claim.root_id.filesystem_id == self.area.filesystem_id
                    && root.identity()? == claim.root_id
                    && unix_mode(&root.as_file().metadata()?) & 0o777 == 0o700,
                "guarded root directory differs from its durable claim"
            );
            return Ok(claim.root_id);
        }
        // The only reachable pre-claim crash state is an empty directory:
        // child publication cannot start until this method returns its claim.
        if let Some(unclaimed_id) = area.entry_identity(&directory_name, true)? {
            anyhow::ensure!(
                area.remove_empty_child_directory(&directory_name, unclaimed_id)?,
                "unclaimed guarded root directory contains unknown entries"
            );
        }
        let anchor_root = area.create_child_directory(&directory_name)?;
        let root_id = anchor_root.identity()?;
        area.sync_all()?;
        let claim = RootClaim {
            format_version: 1,
            anchor_id: self.anchor_id,
            root_id,
            plan_hash,
        };
        anyhow::ensure!(control.put_record_if_absent(
            ROOT_CLAIM_KIND,
            self.anchor_id.as_bytes(),
            &mb_core::canonical_bytes(&claim)?,
        )?);
        Ok(root_id)
    }

    /// Materialize only the planned directory shape. A directory's parent is
    /// synced and its inode claim recorded before any descendant can be used
    /// by a file freeze. Replays verify each claimed inode and may replace an
    /// empty directory left by a crash before its claim was recorded.
    pub fn prepare_anchor_directories(&self, control: &ControlStore) -> anyhow::Result<()> {
        let root_id = self.prepare_anchor_root(control)?;
        let plan_hash = *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes();
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let root = area
            .open_child_directory(self.anchor_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("claimed guarded root disappeared"))?;
        anyhow::ensure!(root.identity()? == root_id);
        let mut opened = BTreeMap::from([(String::new(), root)]);
        let claim_kind = self.directory_claim_kind();
        for entry in &self.entries {
            let GuardedRootEntry::Directory { path, .. } = entry else {
                continue;
            };
            let relative = Path::new(path);
            let name = relative
                .file_name()
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent_path = relative
                .parent()
                .and_then(|parent| parent.to_str())
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent = opened
                .get(parent_path)
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent_id = parent.identity()?;
            let claimed = control.get_record(&claim_kind, path.as_bytes())?;
            let directory = if let Some(bytes) = claimed {
                let claim: DirectoryClaim = mb_core::decode_canonical(&bytes)?;
                let directory = parent
                    .open_child_directory(Path::new(name))?
                    .ok_or_else(|| anyhow::anyhow!("claimed guarded directory disappeared"))?;
                anyhow::ensure!(
                    claim.format_version == 1
                        && claim.anchor_id == self.anchor_id
                        && claim.path == path.as_str()
                        && claim.parent_id == parent_id
                        && claim.directory_id == directory.identity()?
                        && claim.plan_hash == plan_hash
                        && unix_mode(&directory.as_file().metadata()?) & 0o777 == 0o700,
                    "guarded directory differs from its durable claim"
                );
                directory
            } else {
                if let Some(unclaimed) = parent.open_child_directory(Path::new(name))? {
                    anyhow::ensure!(
                        parent
                            .remove_empty_child_directory(Path::new(name), unclaimed.identity()?)?,
                        "unclaimed guarded directory contains unknown entries"
                    );
                }
                let directory = parent.create_child_directory(Path::new(name))?;
                parent.sync_all()?;
                let claim = DirectoryClaim {
                    format_version: 1,
                    anchor_id: self.anchor_id,
                    path: path.clone(),
                    parent_id,
                    directory_id: directory.identity()?,
                    plan_hash,
                };
                anyhow::ensure!(control.put_record_if_absent(
                    &claim_kind,
                    path.as_bytes(),
                    &mb_core::canonical_bytes(&claim)?,
                )?);
                directory
            };
            opened.insert(path.clone(), directory);
        }
        Ok(())
    }

    /// Freeze every inventoried file into its corresponding claimed anchor
    /// directory. Each file uses its own durable journal, so a retry continues
    /// completed freezes and refuses a changed, not-yet-frozen source. The
    /// returned entries are only a candidate whole-root catalog; callers must
    /// still publish and protect a complete manifest before enrollment.
    pub fn freeze_planned_files(
        &self,
        control: &ControlStore,
    ) -> anyhow::Result<Vec<CapturedEntry>> {
        let private_capture = self.private_file_capture(control)?;
        self.prepare_anchor_directories(control)?;
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let anchor_root = area
            .open_child_directory(self.anchor_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("claimed guarded root disappeared"))?;
        let root_parent_id = NativeFileId {
            filesystem_id: self.root_version.filesystem_id,
            inode: self.root_version.inode,
        };
        let mut source_directories = BTreeMap::from([(String::new(), root_parent_id)]);
        let mut captured = Vec::with_capacity(self.entries.len());
        let mut extent_count = 0usize;
        for entry in &self.entries {
            match entry {
                GuardedRootEntry::Directory {
                    path,
                    version,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => {
                    source_directories.insert(
                        path.clone(),
                        NativeFileId {
                            filesystem_id: version.filesystem_id,
                            inode: version.inode,
                        },
                    );
                    captured.push(CapturedEntry::Directory {
                        path: path.clone(),
                        mode: *mode,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                    });
                }
                GuardedRootEntry::File {
                    path,
                    capture_id,
                    version,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => {
                    let relative = Path::new(path);
                    let name = relative
                        .file_name()
                        .ok_or(AnchorError::InvalidGuardedPlan)?;
                    let name = Path::new(name);
                    let parent_path = relative
                        .parent()
                        .and_then(|parent| parent.to_str())
                        .ok_or(AnchorError::InvalidGuardedPlan)?;
                    let expected_parent = *source_directories
                        .get(parent_path)
                        .ok_or(AnchorError::InvalidGuardedPlan)?;
                    let anchor_parent = if parent_path.is_empty() {
                        anchor_root.try_clone()?
                    } else {
                        anchor_root.open_descendant_directory(parent_path)?
                    };
                    let recorded = LinkFreezeCaptureIntent::load(control, *capture_id)?;
                    let source_parent = PinnedDirectory::open(&self.source_root).and_then(|root| {
                        if root.identity()? != root_parent_id {
                            return Err(AnchorError::SourceChanged(PathBuf::new()));
                        }
                        if parent_path.is_empty() {
                            Ok(root)
                        } else {
                            root.open_descendant_directory(parent_path)
                        }
                    });
                    let source_parent = match source_parent {
                        Ok(parent) if parent.identity()? == expected_parent => parent,
                        _ if recorded.as_ref().is_some_and(|intent| {
                            intent.phase() != LinkFreezeCapturePhase::Prepared
                        }) =>
                        {
                            anchor_parent.try_clone()?
                        }
                        _ => anyhow::bail!("planned guarded source parent changed: {path}"),
                    };
                    let expected_source = NativeFileId {
                        filesystem_id: version.filesystem_id,
                        inode: version.inode,
                    };
                    let intent = match recorded {
                        Some(intent) => intent,
                        None => {
                            anyhow::ensure!(
                                anchor_parent.entry_identity(name, false)?.is_none(),
                                "unowned guarded file anchor blocks first freeze: {path}"
                            );
                            LinkFreezeCaptureIntent::begin_checked(
                                control,
                                *capture_id,
                                &source_parent,
                                name,
                                &anchor_parent,
                                name,
                                version,
                            )?
                        }
                    };
                    // A detached file may have been renamed before its edit;
                    // the immutable anchor still belongs to the planned inode.
                    let matches_plan = if intent.phase() == LinkFreezeCapturePhase::Detached {
                        intent.matches_file_plan(
                            *capture_id,
                            expected_source,
                            &anchor_parent,
                            name,
                        )?
                    } else {
                        intent.matches_root_file_plan(
                            *capture_id,
                            expected_parent,
                            expected_source,
                            &anchor_parent,
                            name,
                        )?
                    };
                    anyhow::ensure!(matches_plan);
                    if let Some(private) = &private_capture
                        && intent.phase() == LinkFreezeCapturePhase::Prepared
                    {
                        intent.isolate_prepared_owner(
                            control,
                            &source_parent,
                            &anchor_parent,
                            FileOwner {
                                uid: private.private_uid,
                                gid: private.private_gid,
                            },
                            version,
                        )?;
                    }
                    let verified = intent
                        .resume(control, &source_parent, &anchor_parent)?
                        .ok_or_else(|| anyhow::anyhow!("planned guarded source changed: {path}"))?;
                    anyhow::ensure!(matches!(
                        verified.phase(),
                        LinkFreezeCapturePhase::Frozen | LinkFreezeCapturePhase::Detached
                    ));
                    if let Some(private) = &private_capture {
                        let metadata = anchor_parent
                            .open_child_file(name)?
                            .ok_or_else(|| anyhow::anyhow!("private frozen anchor disappeared"))?
                            .metadata()?;
                        anyhow::ensure!(
                            metadata.uid() != private.view_uid && unix_mode(&metadata) & 0o022 == 0,
                            "private file capture retained a view-writable anchor"
                        );
                    }
                    let proof = verified.content_proof();
                    anyhow::ensure!(
                        proof.logical_len == version.logical_len,
                        "guarded file proof differs from planned length: {path}"
                    );
                    extent_count = extent_count
                        .checked_add(proof.data_extents.len())
                        .ok_or(AnchorError::CatalogTooLarge)?;
                    anyhow::ensure!(extent_count <= MAX_CAPTURE_EXTENTS);
                    captured.push(CapturedEntry::FileV2 {
                        path: path.clone(),
                        mode: *mode,
                        logical_len: proof.logical_len,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                        native_id: expected_source,
                        data_extents: proof.data_extents.clone(),
                    });
                }
            }
        }
        anchor_root.sync_all()?;
        Ok(captured)
    }

    /// Publish a complete native root manifest only after every planned file
    /// journal has verified its anchor and the anchor tree has no extra names.
    /// The sealed publication is replayable after a crash. A guarded manifest
    /// must be retired through this backend, never by generic anchor removal.
    pub fn capture(&self, control: &ControlStore) -> anyhow::Result<StableAnchorManifest> {
        let entries = self.freeze_planned_files(control)?;
        self.prepare_anchor_directories(control)?;
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let anchor_root = area
            .open_child_directory(self.anchor_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("claimed guarded root disappeared"))?;
        let manifest_name = capture_manifest_name(self.anchor_id);
        let manifest = StableAnchorManifest {
            format_version: 2,
            anchor_id: self.anchor_id,
            source_root_hint: self.source_root.clone(),
            area: self.area.clone(),
            root_mode: self.root_mode,
            root_modified_secs: self.root_modified_secs,
            root_modified_nanos: self.root_modified_nanos,
            entries,
        };
        let manifest_bytes = mb_core::canonical_bytes(&manifest)?;
        anyhow::ensure!(
            manifest_bytes.len() <= V1_MAX_CATALOG_BYTES,
            AnchorError::CatalogTooLarge
        );
        let claim = RootManifestClaim {
            format_version: 1,
            anchor_id: self.anchor_id,
            root_id: anchor_root.identity()?,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes(),
            manifest_hash: *blake3::hash(&manifest_bytes).as_bytes(),
        };
        let claim_bytes = mb_core::canonical_bytes(&claim)?;
        let recorded_claim = control.get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?;
        if let Some(recorded) = recorded_claim.as_ref() {
            anyhow::ensure!(
                recorded == &claim_bytes,
                "guarded root manifest claim changed"
            );
        }
        self.verify_anchor_names(&anchor_root, &manifest_name)?;
        match anchor_root.open_child_file(&manifest_name)? {
            Some(mut file) => {
                let metadata = file.metadata()?;
                anyhow::ensure!(
                    metadata.len() == manifest_bytes.len() as u64
                        && metadata.nlink() == 1
                        && unix_mode(&metadata) & 0o222 == 0,
                    "guarded root manifest metadata changed"
                );
                let mut existing = Vec::new();
                file.read_to_end(&mut existing)?;
                anyhow::ensure!(
                    existing == manifest_bytes,
                    "guarded root manifest differs from its frozen inventory"
                );
            }
            None => {
                anyhow::ensure!(
                    recorded_claim.is_none(),
                    "claimed guarded root manifest disappeared"
                );
                anchor_root.publish_sealed_catalog_child(&manifest_name, &manifest_bytes)?;
            }
        }
        anchor_root.sync_all()?;
        area.sync_all()?;
        if recorded_claim.is_none() {
            anyhow::ensure!(control.put_record_if_absent(
                MANIFEST_CLAIM_KIND,
                self.anchor_id.as_bytes(),
                &claim_bytes,
            )?);
        }
        Ok(manifest)
    }

    /// Make one file from a published root capture editable while retaining
    /// its exact immutable anchor. The current path may differ from its
    /// capture-time path; a pinned inode check binds the edit to the right
    /// file, and the per-file journal resumes an interrupted sparse detach.
    pub fn prepare_file_edit_at(
        &self,
        control: &ControlStore,
        captured_relative_path: impl AsRef<Path>,
        current_relative_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        self.validate()?;
        let captured_relative_path = captured_relative_path.as_ref();
        let current_relative_path = current_relative_path.as_ref();
        validate_relative(captured_relative_path)?;
        validate_relative(current_relative_path)?;
        let captured_path = captured_relative_path
            .to_str()
            .ok_or(AnchorError::NonUtf8Path)?;
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.path() == captured_path)
            .ok_or_else(|| anyhow::anyhow!("file is not in the guarded root capture"))?;
        let GuardedRootEntry::File {
            capture_id,
            version,
            ..
        } = entry
        else {
            anyhow::bail!("guarded root entry is not a file");
        };
        let plan_bytes = mb_core::canonical_bytes(self)?;
        let plan_hash = *blake3::hash(&plan_bytes).as_bytes();
        anyhow::ensure!(
            control.get_record(PLAN_KIND, self.anchor_id.as_bytes())? == Some(plan_bytes)
                && control
                    .get_record(RETIRE_KIND, self.anchor_id.as_bytes())?
                    .is_none()
                && !LinkFreezeCaptureIntent::retirement_pending(control, *capture_id)?,
            "guarded root file is not published or is being retired"
        );
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        anyhow::ensure!(
            self.verified_marker(&area, plan_hash)?.is_some(),
            "guarded root ownership marker disappeared"
        );
        let root_claim: RootClaim = mb_core::decode_canonical(
            &control
                .get_record(ROOT_CLAIM_KIND, self.anchor_id.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("guarded root claim disappeared"))?,
        )?;
        let anchor_root = area
            .open_child_directory(self.anchor_id.to_string())?
            .ok_or_else(|| anyhow::anyhow!("guarded root anchor directory disappeared"))?;
        anyhow::ensure!(
            root_claim.format_version == 1
                && root_claim.anchor_id == self.anchor_id
                && root_claim.plan_hash == plan_hash
                && root_claim.root_id == anchor_root.identity()?
                && unix_mode(&anchor_root.as_file().metadata()?) & 0o777 == 0o700,
            "guarded root anchor differs from its claim"
        );
        anyhow::ensure!(
            self.verify_manifest_for_retirement(control, &anchor_root, plan_hash, false)?
                .is_some_and(|(_, present)| present.is_some()),
            "guarded root has no published manifest"
        );
        self.verify_directory_claims_before_retirement(control, &area, plan_hash)?;
        let anchor_parent =
            self.claimed_file_parent(control, &anchor_root, plan_hash, captured_relative_path)?;
        let anchor_name = captured_relative_path
            .file_name()
            .ok_or(AnchorError::InvalidGuardedPlan)?;
        let intent = LinkFreezeCaptureIntent::load(control, *capture_id)?
            .ok_or_else(|| anyhow::anyhow!("guarded root file capture journal disappeared"))?;
        anyhow::ensure!(intent.matches_file_plan(
            *capture_id,
            NativeFileId {
                filesystem_id: version.filesystem_id,
                inode: version.inode,
            },
            &anchor_parent,
            Path::new(anchor_name),
        )?);
        let source_root = PinnedDirectory::open(&self.source_root)?;
        anyhow::ensure!(
            source_root.identity()?
                == (NativeFileId {
                    filesystem_id: self.root_version.filesystem_id,
                    inode: self.root_version.inode,
                }),
            "guarded source root changed before edit"
        );
        let current_parent = current_relative_path
            .parent()
            .ok_or(AnchorError::UnsafePath)?;
        let source_parent = if current_parent.as_os_str().is_empty() {
            source_root
        } else {
            source_root.open_descendant_directory(current_parent)?
        };
        let source_name = current_relative_path
            .file_name()
            .ok_or(AnchorError::UnsafePath)?;
        let detached = if intent.phase() == LinkFreezeCapturePhase::Detached {
            intent.verify_detached_anchor(control, &anchor_parent)?
        } else {
            anyhow::ensure!(intent.phase() == LinkFreezeCapturePhase::Frozen);
            if LinkFreezeEditIntent::load(control, *capture_id)?
                .as_ref()
                .is_some_and(|edit| edit.phase() == LinkFreezeEditPhase::Editable)
            {
                intent.finish_detached_edit(control, &anchor_parent)?
            } else {
                intent.detach_for_edit_at(control, &source_parent, source_name, &anchor_parent)?
            }
        };
        detached.restore_detached_owner_at(
            control,
            &source_parent,
            Path::new(source_name),
            &anchor_parent,
        )?;
        Ok(())
    }

    fn claimed_file_parent(
        &self,
        control: &ControlStore,
        anchor_root: &PinnedDirectory,
        plan_hash: [u8; 32],
        captured_relative_path: &Path,
    ) -> anyhow::Result<PinnedDirectory> {
        let mut parent = anchor_root.try_clone()?;
        let mut path = PathBuf::new();
        let claim_kind = self.directory_claim_kind();
        for component in captured_relative_path
            .parent()
            .ok_or(AnchorError::InvalidGuardedPlan)?
            .components()
        {
            let std::path::Component::Normal(name) = component else {
                anyhow::bail!("invalid guarded root file parent");
            };
            path.push(name);
            let path_name = path.to_str().ok_or(AnchorError::InvalidGuardedPlan)?;
            let claim: DirectoryClaim = mb_core::decode_canonical(
                &control
                    .get_record(&claim_kind, path_name.as_bytes())?
                    .ok_or_else(|| anyhow::anyhow!("guarded root file parent claim disappeared"))?,
            )?;
            let child = parent
                .open_child_directory(Path::new(name))?
                .ok_or_else(|| anyhow::anyhow!("guarded root file parent disappeared"))?;
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == self.anchor_id
                    && claim.path == path_name
                    && claim.parent_id == parent.identity()?
                    && claim.directory_id == child.identity()?
                    && claim.plan_hash == plan_hash
                    && unix_mode(&child.as_file().metadata()?) & 0o777 == 0o700,
                "guarded root file parent differs from its claim"
            );
            parent = child;
        }
        Ok(parent)
    }

    fn verify_anchor_names(
        &self,
        anchor_root: &PinnedDirectory,
        manifest_name: &str,
    ) -> anyhow::Result<()> {
        let mut expected = BTreeMap::<String, BTreeSet<String>>::new();
        expected.entry(String::new()).or_default();
        for entry in &self.entries {
            let relative = Path::new(entry.path());
            let name = relative
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent = relative
                .parent()
                .and_then(|parent| parent.to_str())
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            expected
                .entry(parent.to_owned())
                .or_default()
                .insert(name.to_owned());
            if entry.is_directory() {
                expected.entry(entry.path().to_owned()).or_default();
            }
        }
        if anchor_root.entry_identity(manifest_name, false)?.is_some() {
            expected
                .get_mut("")
                .ok_or(AnchorError::InvalidGuardedPlan)?
                .insert(manifest_name.to_owned());
        }
        for (path, names) in expected {
            let directory = if path.is_empty() {
                anchor_root.try_clone()?
            } else {
                anchor_root.open_descendant_directory(&path)?
            };
            let mut actual = BTreeSet::new();
            let mut stream = DirectoryStream::open(directory.as_file())?;
            while let Some(name) = stream.next_name()? {
                actual.insert(String::from_utf8(name.as_bytes().to_vec())?);
            }
            anyhow::ensure!(
                actual == names,
                "guarded anchor contains unknown entries: {path}"
            );
        }
        Ok(())
    }

    /// The caller must prove that no signed revision, Git object, or pending
    /// operation still references this root. The root marker fences new
    /// freezes, and each file's own retirement journal restores source access
    /// before its anchor directory is removed. Repeating this call resumes an
    /// interrupted retirement.
    pub fn discard_unreferenced(&self, control: &ControlStore) -> anyhow::Result<()> {
        self.validate()?;
        crate::guarded_mount::require_mount_claim_retired(control, self.anchor_id)?;
        crate::guarded_view_probe::verify_retired_namespace_quiescent(control, self.anchor_id)?;
        let private_capture = self.private_file_capture(control)?;
        let plan_bytes = mb_core::canonical_bytes(self)?;
        let plan_hash = *blake3::hash(&plan_bytes).as_bytes();
        let recorded_plan = control.get_record(PLAN_KIND, self.anchor_id.as_bytes())?;
        anyhow::ensure!(
            recorded_plan
                .as_ref()
                .is_none_or(|bytes| bytes == &plan_bytes),
            "guarded root plan changed before retirement"
        );
        let lower_ownership = control
            .get_record(LOWER_OWNERSHIP_KIND, self.anchor_id.as_bytes())?
            .map(|bytes| {
                let snapshot: LowerOwnershipSnapshot = mb_core::decode_canonical(&bytes)?;
                Ok::<_, anyhow::Error>((bytes, snapshot))
            })
            .transpose()?;
        let directory_isolation = match &lower_ownership {
            Some((bytes, _)) => self.directory_isolation(control, bytes)?,
            None => {
                anyhow::ensure!(
                    control
                        .get_record(DIRECTORY_ISOLATION_KIND, self.anchor_id.as_bytes())?
                        .is_none(),
                    "guarded directory isolation lost its ownership snapshot"
                );
                None
            }
        };
        if recorded_plan.is_none()
            && let Some(private) = &private_capture
        {
            anyhow::ensure!(
                lower_ownership.is_none()
                    && directory_isolation.is_none()
                    && control
                        .get_record(ROOT_CLAIM_KIND, self.anchor_id.as_bytes())?
                        .is_none()
                    && control
                        .get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?
                        .is_none()
                    && control
                        .get_record(RETIRE_KIND, self.anchor_id.as_bytes())?
                        .is_none()
                    && control.records(&self.directory_claim_kind())?.is_empty(),
                "unstarted private capture has a root ownership obligation"
            );
            for entry in &self.entries {
                if let GuardedRootEntry::File { capture_id, .. } = entry {
                    anyhow::ensure!(
                        LinkFreezeCaptureIntent::load(control, *capture_id)?.is_none(),
                        "unstarted private capture has a file ownership obligation"
                    );
                }
            }
            control.delete_record_if_value(
                PRIVATE_FILE_CAPTURE_KIND,
                self.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(private)?,
            )?;
            return Ok(());
        }
        let mut retirement_directory_paths = None;
        if let Some((_, snapshot)) = &lower_ownership {
            anyhow::ensure!(
                recorded_plan.is_some(),
                "guarded lower owner lost its root plan"
            );
            self.reconcile(control)?;
            let paths = self.retirement_directory_paths(control)?;
            self.verify_lower_ownership_before_retirement(
                control,
                snapshot,
                directory_isolation.as_ref(),
                &paths,
            )?;
            retirement_directory_paths = Some(paths);
        }
        let retirement = RootRetirement {
            format_version: 1,
            anchor_id: self.anchor_id,
            plan_hash,
        };
        let retirement_bytes = mb_core::canonical_bytes(&retirement)?;
        let existing_retirement = control.get_record(RETIRE_KIND, self.anchor_id.as_bytes())?;
        anyhow::ensure!(
            existing_retirement
                .as_ref()
                .is_none_or(|bytes| bytes == &retirement_bytes),
            "guarded root retirement belongs to another plan"
        );
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let root_claim_bytes = control.get_record(ROOT_CLAIM_KIND, self.anchor_id.as_bytes())?;
        let root_claim = root_claim_bytes
            .as_deref()
            .map(mb_core::decode_canonical::<RootClaim>)
            .transpose()?;
        let anchor_root = area.open_child_directory(self.anchor_id.to_string())?;
        anyhow::ensure!(
            (lower_ownership.is_none() && private_capture.is_none()) || anchor_root.is_some(),
            "guarded private capture lost its anchor root"
        );
        if recorded_plan.is_none() || anchor_root.is_none() {
            anyhow::ensure!(
                existing_retirement.is_some() || recorded_plan.is_none(),
                "guarded root disappeared before retirement began"
            );
            anyhow::ensure!(
                control
                    .get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?
                    .is_none(),
                "missing guarded root retains a manifest claim"
            );
            for entry in &self.entries {
                if let GuardedRootEntry::File { capture_id, .. } = entry {
                    anyhow::ensure!(
                        LinkFreezeCaptureIntent::load(control, *capture_id)?.is_none(),
                        "missing guarded root retains a file capture"
                    );
                }
            }
            self.discard_empty_anchor_root(control)?;
            self.finish_file_retirement_records(control)?;
            return Ok(());
        }
        let anchor_root = anchor_root.unwrap();
        let root_claim =
            root_claim.ok_or_else(|| anyhow::anyhow!("guarded root lacks its claim"))?;
        anyhow::ensure!(
            root_claim.format_version == 1
                && root_claim.anchor_id == self.anchor_id
                && root_claim.plan_hash == plan_hash
                && root_claim.root_id == anchor_root.identity()?
                && self.verified_marker(&area, plan_hash)?.is_some(),
            "guarded root ownership changed before retirement"
        );
        if existing_retirement.is_none() {
            self.verify_directory_claims_before_retirement(control, &area, plan_hash)?;
        }
        self.verify_manifest_for_retirement(
            control,
            &anchor_root,
            plan_hash,
            existing_retirement.is_some(),
        )?;
        if existing_retirement.is_none() {
            anyhow::ensure!(control.put_record_if_absent(
                RETIRE_KIND,
                self.anchor_id.as_bytes(),
                &retirement_bytes,
            )?);
        }
        let mut source_directories = BTreeMap::from([(
            String::new(),
            NativeFileId {
                filesystem_id: self.root_version.filesystem_id,
                inode: self.root_version.inode,
            },
        )]);
        for entry in &self.entries {
            if let GuardedRootEntry::Directory { path, version, .. } = entry {
                source_directories.insert(
                    path.clone(),
                    NativeFileId {
                        filesystem_id: version.filesystem_id,
                        inode: version.inode,
                    },
                );
            }
        }
        for (index, entry) in self.entries.iter().enumerate() {
            let GuardedRootEntry::File {
                path,
                capture_id,
                version,
                ..
            } = entry
            else {
                continue;
            };
            let relative = Path::new(path);
            let name = relative
                .file_name()
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let name = Path::new(name);
            let parent_path = relative
                .parent()
                .and_then(|parent| parent.to_str())
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let anchor_parent = if parent_path.is_empty() {
                anchor_root.try_clone()?
            } else {
                anchor_root.open_descendant_directory(parent_path)?
            };
            let Some(capture) = LinkFreezeCaptureIntent::load(control, *capture_id)? else {
                anyhow::ensure!(
                    anchor_parent.entry_identity(name, false)?.is_none(),
                    "guarded root has an unjournaled file anchor: {path}"
                );
                LinkFreezeCaptureIntent::finish_completed_retirement(control, *capture_id)?;
                continue;
            };
            let expected_parent = *source_directories
                .get(parent_path)
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let expected_source = NativeFileId {
                filesystem_id: version.filesystem_id,
                inode: version.inode,
            };
            let current_path = crate::guarded_view_probe::captured_file_path_for_retirement(
                control,
                self.anchor_id,
                u64::try_from(index)? + 2,
                path,
                expected_source,
            )?;
            let moved = current_path
                .as_deref()
                .is_some_and(|current| current != relative);
            // Retirement no longer needs the old source pathname after the
            // anchor became a verified private inode.
            let matches_plan = if capture.phase() == LinkFreezeCapturePhase::Detached || moved {
                capture.matches_file_plan(*capture_id, expected_source, &anchor_parent, name)?
            } else {
                capture.matches_root_file_plan(
                    *capture_id,
                    expected_parent,
                    expected_source,
                    &anchor_parent,
                    name,
                )?
            };
            anyhow::ensure!(matches_plan);
            let (source_parent, capture) = if moved {
                anyhow::ensure!(
                    capture.phase() != LinkFreezeCapturePhase::Prepared,
                    "unpublished guarded file has a moved view path"
                );
                let current = current_path.as_deref().unwrap();
                let source_parent = self.open_source_parent_at_retirement_path(current)?;
                let current_name = current.file_name().ok_or(AnchorError::UnsafePath)?;
                anyhow::ensure!(
                    source_parent.entry_identity(current_name, false)? == Some(expected_source),
                    "moved guarded source differs from its namespace record"
                );
                let capture = if capture.phase() == LinkFreezeCapturePhase::Frozen {
                    if capture.matches_source_binding(&source_parent, Path::new(current_name))? {
                        capture
                    } else {
                        capture.rebind_frozen_source(
                            control,
                            &source_parent,
                            Path::new(current_name),
                            &anchor_parent,
                        )?
                    }
                } else {
                    capture
                };
                (source_parent, capture)
            } else {
                let parent =
                    match self.open_source_parent_for_retirement(parent_path, expected_parent) {
                        Ok(parent) => parent,
                        Err(_) => anchor_parent.try_clone()?,
                    };
                (parent, capture)
            };
            if let Some(private) = &private_capture
                && capture.phase() == LinkFreezeCapturePhase::Prepared
            {
                if !LinkFreezeCaptureIntent::owner_isolation_pending(control, *capture_id)? {
                    capture.cancel_prepared_unlinked(control, &source_parent, &anchor_parent)?;
                    continue;
                }
                capture.isolate_prepared_owner(
                    control,
                    &source_parent,
                    &anchor_parent,
                    FileOwner {
                        uid: private.private_uid,
                        gid: private.private_gid,
                    },
                    version,
                )?;
            }
            let capture = if capture.phase() == LinkFreezeCapturePhase::Prepared {
                capture.resume(control, &source_parent, &anchor_parent)?
            } else {
                Some(capture)
            };
            if let Some(capture) = capture {
                if let Some((_, snapshot)) = &lower_ownership {
                    let original = &snapshot.entries[index + 1];
                    capture.retire_unreferenced_with_original_owner(
                        control,
                        &source_parent,
                        &anchor_parent,
                        FileOwner {
                            uid: original.uid,
                            gid: original.gid,
                        },
                    )?;
                } else {
                    capture.retire_unreferenced(control, &source_parent, &anchor_parent)?;
                }
            }
            LinkFreezeCaptureIntent::finish_completed_retirement(control, *capture_id)?;
        }
        if let Some((bytes, snapshot)) = &lower_ownership {
            self.finish_lower_ownership_retirement(
                control,
                snapshot,
                bytes,
                directory_isolation.as_ref(),
                retirement_directory_paths
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("guarded retirement lost directory paths"))?,
            )?;
        }
        if let Some(private) = &private_capture {
            control.delete_record_if_value(
                PRIVATE_FILE_CAPTURE_KIND,
                self.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(private)?,
            )?;
        }
        self.remove_claimed_manifest(control, &anchor_root, plan_hash)?;
        self.discard_empty_anchor_root(control)?;
        self.finish_file_retirement_records(control)?;
        Ok(())
    }

    fn open_source_parent_for_retirement(
        &self,
        parent_path: &str,
        expected: NativeFileId,
    ) -> Result<PinnedDirectory, AnchorError> {
        let root = PinnedDirectory::open(&self.source_root)?;
        if root.identity()?
            != (NativeFileId {
                filesystem_id: self.root_version.filesystem_id,
                inode: self.root_version.inode,
            })
        {
            return Err(AnchorError::SourceChanged(PathBuf::new()));
        }
        let parent = if parent_path.is_empty() {
            root
        } else {
            root.open_descendant_directory(parent_path)?
        };
        if parent.identity()? != expected {
            return Err(AnchorError::SourceChanged(PathBuf::from(parent_path)));
        }
        Ok(parent)
    }

    fn open_source_parent_at_retirement_path(
        &self,
        current: &Path,
    ) -> anyhow::Result<PinnedDirectory> {
        validate_relative(current)?;
        let root = PinnedDirectory::open(&self.source_root)?;
        anyhow::ensure!(
            root.identity()? == self.source_root_identity(),
            "guarded lower root changed before retirement"
        );
        let parent = current.parent().ok_or(AnchorError::UnsafePath)?;
        if parent.as_os_str().is_empty() {
            Ok(root)
        } else {
            Ok(root.open_descendant_directory(parent)?)
        }
    }

    fn finish_file_retirement_records(&self, control: &ControlStore) -> anyhow::Result<()> {
        for entry in &self.entries {
            if let GuardedRootEntry::File { capture_id, .. } = entry {
                LinkFreezeCaptureIntent::finish_completed_retirement(control, *capture_id)?;
            }
        }
        Ok(())
    }

    fn verify_manifest_for_retirement(
        &self,
        control: &ControlStore,
        anchor_root: &PinnedDirectory,
        plan_hash: [u8; 32],
        allow_missing: bool,
    ) -> anyhow::Result<Option<(Vec<u8>, Option<NativeFileId>)>> {
        let name = capture_manifest_name(self.anchor_id);
        let recorded = control.get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?;
        let present = anchor_root.entry_identity(&name, false)?;
        let Some(bytes) = recorded else {
            anyhow::ensure!(
                present.is_none(),
                "unguarded root manifest blocks retirement"
            );
            return Ok(None);
        };
        let claim: RootManifestClaim = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            claim.format_version == 1
                && claim.anchor_id == self.anchor_id
                && claim.root_id == anchor_root.identity()?
                && claim.plan_hash == plan_hash,
            "guarded root manifest claim changed before retirement"
        );
        if present.is_some() {
            let mut file = anchor_root
                .open_child_file(&name)?
                .ok_or_else(|| anyhow::anyhow!("guarded root manifest disappeared"))?;
            let metadata = file.metadata()?;
            anyhow::ensure!(
                metadata.len() <= V1_MAX_CATALOG_BYTES as u64
                    && metadata.nlink() == 1
                    && unix_mode(&metadata) & 0o222 == 0,
                "guarded root manifest metadata changed"
            );
            let mut encoded = Vec::new();
            file.read_to_end(&mut encoded)?;
            anyhow::ensure!(
                *blake3::hash(&encoded).as_bytes() == claim.manifest_hash,
                "guarded root manifest bytes changed"
            );
            let manifest: StableAnchorManifest = mb_core::decode_canonical(&encoded)?;
            anyhow::ensure!(
                manifest.format_version == 2
                    && manifest.anchor_id == self.anchor_id
                    && manifest.area == self.area
                    && manifest.source_root_hint == self.source_root
                    && manifest.root_mode == self.root_mode
                    && manifest.root_modified_secs == self.root_modified_secs
                    && manifest.root_modified_nanos == self.root_modified_nanos
                    && manifest.entries.len() == self.entries.len(),
                "guarded root manifest differs from its source plan"
            );
            for (planned, captured) in self.entries.iter().zip(&manifest.entries) {
                let matches = match (planned, captured) {
                    (
                        GuardedRootEntry::Directory {
                            path,
                            mode,
                            modified_secs,
                            modified_nanos,
                            ..
                        },
                        CapturedEntry::Directory {
                            path: actual_path,
                            mode: actual_mode,
                            modified_secs: actual_secs,
                            modified_nanos: actual_nanos,
                        },
                    ) => {
                        path == actual_path
                            && mode == actual_mode
                            && modified_secs == actual_secs
                            && modified_nanos == actual_nanos
                    }
                    (
                        GuardedRootEntry::File {
                            path,
                            version,
                            mode,
                            modified_secs,
                            modified_nanos,
                            ..
                        },
                        CapturedEntry::FileV2 {
                            path: actual_path,
                            mode: actual_mode,
                            logical_len,
                            modified_secs: actual_secs,
                            modified_nanos: actual_nanos,
                            native_id,
                            ..
                        },
                    ) => {
                        path == actual_path
                            && mode == actual_mode
                            && *logical_len == version.logical_len
                            && modified_secs == actual_secs
                            && modified_nanos == actual_nanos
                            && *native_id
                                == (NativeFileId {
                                    filesystem_id: version.filesystem_id,
                                    inode: version.inode,
                                })
                    }
                    _ => false,
                };
                anyhow::ensure!(matches, "guarded root manifest entry changed");
            }
        } else {
            anyhow::ensure!(allow_missing, "claimed guarded root manifest disappeared");
        }
        Ok(Some((bytes, present)))
    }

    fn remove_claimed_manifest(
        &self,
        control: &ControlStore,
        anchor_root: &PinnedDirectory,
        plan_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        if let Some((claim_bytes, present)) =
            self.verify_manifest_for_retirement(control, anchor_root, plan_hash, true)?
        {
            if let Some(identity) = present {
                anchor_root.remove_child_file_if_identity(
                    capture_manifest_name(self.anchor_id),
                    identity,
                )?;
            }
            control.delete_record_if_value(
                MANIFEST_CLAIM_KIND,
                self.anchor_id.as_bytes(),
                &claim_bytes,
            )?;
        }
        Ok(())
    }

    /// Abandon only a prepared, empty root namespace. A file freeze requires
    /// the later journal-aware retirement path; this method refuses any file
    /// capture intent or child entry rather than unlinking a frozen source.
    pub fn discard_empty_anchor_root(&self, control: &ControlStore) -> anyhow::Result<()> {
        self.validate()?;
        crate::guarded_mount::require_mount_claim_retired(control, self.anchor_id)?;
        anyhow::ensure!(
            self.private_file_capture(control)?.is_none(),
            "private file capture needs journal-aware retirement"
        );
        anyhow::ensure!(
            control
                .get_record(DIRECTORY_ISOLATION_KIND, self.anchor_id.as_bytes())?
                .is_none(),
            "isolated lower directories need journal-aware retirement"
        );
        anyhow::ensure!(
            control
                .get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?
                .is_none(),
            "published guarded root needs journal-aware retirement"
        );
        let plan_bytes = mb_core::canonical_bytes(self)?;
        let plan_hash = *blake3::hash(&plan_bytes).as_bytes();
        let recorded_plan = control.get_record(PLAN_KIND, self.anchor_id.as_bytes())?;
        if let Some(bytes) = recorded_plan.as_ref() {
            anyhow::ensure!(
                bytes == &plan_bytes,
                "guarded root plan changed before retirement"
            );
        }
        for entry in &self.entries {
            if let GuardedRootEntry::File { capture_id, .. } = entry {
                anyhow::ensure!(
                    LinkFreezeCaptureIntent::load(control, *capture_id)?.is_none()
                        && LinkFreezeCaptureIntent::retirement_ready_for_cleanup(
                            control,
                            *capture_id,
                        )?,
                    "guarded root has a live file capture"
                );
            }
        }
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let directory_name = self.anchor_id.to_string();
        let marker_id = self.verified_marker(&area, plan_hash)?;
        let present_root = area.entry_identity(&directory_name, true)?;
        let claim_bytes = control.get_record(ROOT_CLAIM_KIND, self.anchor_id.as_bytes())?;
        let claim = claim_bytes
            .as_deref()
            .map(mb_core::decode_canonical::<RootClaim>)
            .transpose()?;
        if let Some(claim) = claim.as_ref() {
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == self.anchor_id
                    && claim.plan_hash == plan_hash
                    && claim.root_id.filesystem_id == self.area.filesystem_id
                    && present_root.is_none_or(|present| present == claim.root_id),
                "guarded root claim changed before retirement"
            );
        }
        let retirement = RootRetirement {
            format_version: 1,
            anchor_id: self.anchor_id,
            plan_hash,
        };
        let retire_bytes = mb_core::canonical_bytes(&retirement)?;
        let existing_retirement = control.get_record(RETIRE_KIND, self.anchor_id.as_bytes())?;
        anyhow::ensure!(
            existing_retirement
                .as_ref()
                .is_none_or(|bytes| bytes == &retire_bytes),
            "guarded root retirement belongs to another plan"
        );
        if recorded_plan.is_none() {
            anyhow::ensure!(
                marker_id.is_none() && present_root.is_none() && claim_bytes.is_none(),
                "unowned guarded root namespace remains after retirement"
            );
            return Ok(());
        }
        anyhow::ensure!(
            marker_id.is_some() || (present_root.is_none() && claim_bytes.is_none()),
            "guarded root ownership marker disappeared before cleanup"
        );
        anyhow::ensure!(
            present_root.is_some() || claim_bytes.is_none() || existing_retirement.is_some(),
            "claimed guarded root disappeared before retirement began"
        );
        if existing_retirement.is_none() {
            self.verify_directory_claims_before_retirement(control, &area, plan_hash)?;
        }
        if !control.put_record_if_absent(RETIRE_KIND, self.anchor_id.as_bytes(), &retire_bytes)? {
            anyhow::ensure!(
                control.get_record(RETIRE_KIND, self.anchor_id.as_bytes())? == Some(retire_bytes),
                "guarded root retirement belongs to another plan"
            );
        }
        self.remove_empty_directories(
            control,
            &area,
            claim.as_ref().map(|claim| claim.root_id),
            plan_hash,
            existing_retirement.is_some(),
        )?;
        if let Some(present) = present_root {
            anyhow::ensure!(
                area.remove_empty_child_directory(&directory_name, present)?,
                "guarded root directory is nonempty"
            );
        }
        if let Some(bytes) = claim_bytes {
            control.delete_record_if_value(ROOT_CLAIM_KIND, self.anchor_id.as_bytes(), &bytes)?;
        }
        if let Some(marker_id) = marker_id {
            area.remove_child_file_if_identity(self.marker_name(), marker_id)?;
        }
        area.sync_all()?;
        if let Some(bytes) = recorded_plan {
            control.delete_record_if_value(PLAN_KIND, self.anchor_id.as_bytes(), &bytes)?;
        }
        Ok(())
    }

    fn verify_directory_claims_before_retirement(
        &self,
        control: &ControlStore,
        area: &PinnedDirectory,
        plan_hash: [u8; 32],
    ) -> anyhow::Result<()> {
        let claim_kind = self.directory_claim_kind();
        let planned = self
            .entries
            .iter()
            .filter(|entry| entry.is_directory())
            .map(GuardedRootEntry::path)
            .collect::<BTreeSet<_>>();
        for (id, _) in control.records(&claim_kind)? {
            anyhow::ensure!(
                std::str::from_utf8(&id).is_ok_and(|path| planned.contains(path)),
                "guarded root has an unplanned directory claim"
            );
        }
        let Some(root) = area.open_child_directory(self.anchor_id.to_string())? else {
            anyhow::ensure!(
                control.records(&claim_kind)?.is_empty(),
                "missing guarded root retains directory claims"
            );
            return Ok(());
        };
        for entry in &self.entries {
            let GuardedRootEntry::Directory { path, .. } = entry else {
                continue;
            };
            let Some(bytes) = control.get_record(&claim_kind, path.as_bytes())? else {
                continue;
            };
            let claim: DirectoryClaim = mb_core::decode_canonical(&bytes)?;
            let relative = Path::new(path);
            let parent_path = relative
                .parent()
                .and_then(|parent| parent.to_str())
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent = if parent_path.is_empty() {
                root.try_clone()?
            } else {
                root.open_descendant_directory(parent_path)?
            };
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == self.anchor_id
                    && claim.path == path.as_str()
                    && claim.parent_id == parent.identity()?
                    && claim.plan_hash == plan_hash
                    && root.entry_identity(relative, true)? == Some(claim.directory_id),
                "claimed guarded directory changed before retirement"
            );
        }
        Ok(())
    }

    fn remove_empty_directories(
        &self,
        control: &ControlStore,
        area: &PinnedDirectory,
        claimed_root: Option<NativeFileId>,
        plan_hash: [u8; 32],
        retirement_replay: bool,
    ) -> anyhow::Result<()> {
        let claim_kind = self.directory_claim_kind();
        let planned = self
            .entries
            .iter()
            .filter(|entry| entry.is_directory())
            .map(GuardedRootEntry::path)
            .collect::<BTreeSet<_>>();
        for (id, _) in control.records(&claim_kind)? {
            anyhow::ensure!(
                std::str::from_utf8(&id).is_ok_and(|path| planned.contains(path)),
                "guarded root has an unplanned directory claim"
            );
        }
        let Some(root) = area.open_child_directory(self.anchor_id.to_string())? else {
            anyhow::ensure!(
                control.records(&claim_kind)?.is_empty(),
                "missing guarded root retains directory claims"
            );
            return Ok(());
        };
        if let Some(expected) = claimed_root {
            anyhow::ensure!(root.identity()? == expected);
        }
        for entry in self.entries.iter().rev() {
            let GuardedRootEntry::Directory { path, .. } = entry else {
                continue;
            };
            let relative = Path::new(path);
            let name = relative
                .file_name()
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let parent_path = relative
                .parent()
                .and_then(|parent| parent.to_str())
                .ok_or(AnchorError::InvalidGuardedPlan)?;
            let recorded = control.get_record(&claim_kind, path.as_bytes())?;
            let parent = if parent_path.is_empty() {
                Some(root.try_clone()?)
            } else if root.entry_identity(parent_path, true)?.is_some() {
                Some(root.open_descendant_directory(parent_path)?)
            } else {
                None
            };
            let Some(parent) = parent else {
                anyhow::ensure!(recorded.is_none(), "claimed parent directory disappeared");
                continue;
            };
            let expected_parent = if parent_path.is_empty() {
                claimed_root
            } else {
                control
                    .get_record(&claim_kind, parent_path.as_bytes())?
                    .map(|bytes| mb_core::decode_canonical::<DirectoryClaim>(&bytes))
                    .transpose()?
                    .map(|claim| claim.directory_id)
            };
            let present = parent.entry_identity(Path::new(name), true)?;
            if recorded.is_some() || present.is_some() {
                anyhow::ensure!(
                    expected_parent == Some(parent.identity()?),
                    "guarded directory parent lost its durable claim"
                );
            }
            if let Some(bytes) = recorded.as_ref() {
                let claim: DirectoryClaim = mb_core::decode_canonical(bytes)?;
                anyhow::ensure!(
                    claim.format_version == 1
                        && claim.anchor_id == self.anchor_id
                        && claim.path == path.as_str()
                        && claim.plan_hash == plan_hash
                        && claim.parent_id == parent.identity()?
                        && claim.directory_id.filesystem_id == self.area.filesystem_id
                        && present.is_none_or(|id| id == claim.directory_id),
                    "guarded directory claim changed before retirement"
                );
                anyhow::ensure!(
                    present.is_some() || retirement_replay,
                    "claimed guarded directory disappeared before retirement"
                );
            }
            if let Some(present) = present {
                anyhow::ensure!(
                    parent.remove_empty_child_directory(Path::new(name), present)?,
                    "guarded directory is nonempty"
                );
            }
            if let Some(bytes) = recorded {
                control.delete_record_if_value(&claim_kind, path.as_bytes(), &bytes)?;
            }
        }
        anyhow::ensure!(
            control.records(&claim_kind)?.is_empty(),
            "guarded directory claims remain after empty retirement"
        );
        Ok(())
    }

    fn marker_name(&self) -> String {
        guarded_root_marker_name(self.anchor_id)
    }

    fn directory_claim_kind(&self) -> String {
        format!("{DIRECTORY_CLAIM_PREFIX}{}", self.anchor_id)
    }

    fn marker_bytes(&self, plan_hash: [u8; 32]) -> Vec<u8> {
        format!(
            "mutualbackup-guarded-root-v1\n{}\n{}\n",
            self.anchor_id,
            blake3::Hash::from(plan_hash)
        )
        .into_bytes()
    }

    fn verified_marker(
        &self,
        area: &PinnedDirectory,
        plan_hash: [u8; 32],
    ) -> anyhow::Result<Option<NativeFileId>> {
        let name = self.marker_name();
        let Some(mut marker) = area.open_child_file(&name)? else {
            return Ok(None);
        };
        let expected = self.marker_bytes(plan_hash);
        let metadata = marker.metadata()?;
        let marker_id = NativeFileId {
            filesystem_id: self.area.filesystem_id,
            inode: metadata.ino(),
        };
        anyhow::ensure!(
            metadata.len() == expected.len() as u64
                && metadata.nlink() == 1
                && unix_mode(&metadata) & 0o222 == 0,
            "guarded root ownership marker changed"
        );
        let mut actual = Vec::new();
        marker.read_to_end(&mut actual)?;
        anyhow::ensure!(
            actual == expected && area.entry_identity(&name, false)? == Some(marker_id),
            "guarded root ownership marker changed"
        );
        Ok(Some(marker_id))
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
                capture_id: Uuid::new_v4(),
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
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use mb_core::{KeyMaterial, Seed};

    use super::{scan_root_inventory, *};

    fn inventory(root: &Path) -> Result<Vec<GuardedRootEntry>, AnchorError> {
        let directory = open_source_root(root)?;
        let filesystem = filesystem_identity_for_file(&directory)?;
        let root_version = capture_version(filesystem.stable_id, &directory.metadata()?);
        scan_root_inventory(root, &directory, filesystem, &root_version)
    }

    fn planned_without_privileged_probe(root: &Path) -> GuardedRootCapturePlan {
        let directory = open_source_root(root).unwrap();
        let metadata = directory.metadata().unwrap();
        let filesystem = filesystem_identity_for_file(&directory).unwrap();
        let (root_modified_secs, root_modified_nanos) = modified_parts(&metadata);
        let root_version = capture_version(filesystem.stable_id, &metadata);
        GuardedRootCapturePlan {
            format_version: 1,
            anchor_id: Uuid::new_v4(),
            source_root: root.to_path_buf(),
            area: StableAnchorAreaLocator::prepare_for_root(root).unwrap(),
            root_version: root_version.clone(),
            root_mode: unix_mode(&metadata),
            root_modified_secs,
            root_modified_nanos,
            entries: scan_root_inventory(root, &directory, filesystem, &root_version).unwrap(),
        }
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
        let GuardedRootEntry::File {
            capture_id,
            version,
            ..
        } = &entries[2]
        else {
            panic!("expected regular file");
        };
        assert!(!capture_id.is_nil());
        assert_eq!(version.logical_len, b"raw\r\nbytes\0".len() as u64);
        let ids = entries
            .iter()
            .filter_map(|entry| match entry {
                GuardedRootEntry::File { capture_id, .. } => Some(*capture_id),
                GuardedRootEntry::Directory { .. } => None,
            })
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(ids.len(), 2);
        let encoded = mb_core::canonical_bytes(&entries).unwrap();
        let decoded: Vec<GuardedRootEntry> = mb_core::decode_canonical(&encoded).unwrap();
        assert_eq!(decoded, entries);
    }

    #[test]
    fn initial_lower_namespace_rejects_unplanned_names_and_replacements() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("nested/file"), b"captured").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let lower = PinnedDirectory::open(&root).unwrap();
        plan.verify_initial_lower_namespace(&lower).unwrap();

        let extra = root.join("nested/extra");
        fs::write(&extra, b"not captured").unwrap();
        assert!(
            plan.verify_initial_lower_namespace(&lower)
                .unwrap_err()
                .to_string()
                .contains("unexpected or missing entry")
        );
        fs::remove_file(extra).unwrap();
        let extra = root.join("extra");
        fs::create_dir(&extra).unwrap();
        assert!(
            plan.verify_initial_lower_namespace(&lower)
                .unwrap_err()
                .to_string()
                .contains("unexpected or missing entry")
        );
        fs::remove_dir(extra).unwrap();
        fs::rename(root.join("nested/file"), root.join("nested/old")).unwrap();
        fs::write(root.join("nested/file"), b"replacement").unwrap();
        assert!(
            plan.verify_initial_lower_namespace(&lower)
                .unwrap_err()
                .to_string()
                .contains("identity changed")
        );
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
        let plan = planned_without_privileged_probe(&root);
        let lower = PinnedDirectory::open(&root).unwrap();
        plan.verify_initial_lower_namespace(&lower).unwrap();
        fs::remove_file(catalog.join(super::super::GIT_CATALOG_MARKER_FILE)).unwrap();
        assert!(plan.verify_initial_lower_namespace(&lower).is_err());
    }

    #[test]
    fn decoded_inventory_rejects_reordered_paths_and_reused_journal_ids() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("dir")).unwrap();
        fs::write(root.join("dir/first"), b"first").unwrap();
        fs::write(root.join("second"), b"second").unwrap();
        let plan = planned_without_privileged_probe(&root);
        plan.validate().unwrap();
        let decoded: GuardedRootCapturePlan =
            mb_core::decode_canonical(&mb_core::canonical_bytes(&plan).unwrap()).unwrap();
        assert_eq!(decoded, plan);
        decoded.validate().unwrap();

        let mut reordered = decoded.clone();
        reordered.entries.swap(0, 1);
        assert!(matches!(
            reordered.validate(),
            Err(AnchorError::InvalidGuardedPlan)
        ));
        let mut reused_id = decoded.clone();
        let first_id = match &reused_id.entries[1] {
            GuardedRootEntry::File { capture_id, .. } => *capture_id,
            _ => panic!("expected first file"),
        };
        let GuardedRootEntry::File { capture_id, .. } = &mut reused_id.entries[2] else {
            panic!("expected second file");
        };
        *capture_id = first_id;
        assert!(matches!(
            reused_id.validate(),
            Err(AnchorError::InvalidGuardedPlan)
        ));
        let mut wrong_filesystem = decoded;
        wrong_filesystem.area.filesystem_id ^= 1;
        assert!(matches!(
            wrong_filesystem.validate(),
            Err(AnchorError::InvalidGuardedPlan)
        ));
        let mut aliased_path = plan;
        let GuardedRootEntry::File { path, .. } = &mut aliased_path.entries[1] else {
            panic!("expected nested file");
        };
        *path = "dir//first".to_owned();
        assert!(matches!(
            aliased_path.validate(),
            Err(AnchorError::InvalidGuardedPlan)
        ));
    }

    #[test]
    fn guarded_root_claim_reopens_and_replaces_only_an_empty_unclaimed_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload"), b"untouched").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([63; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let claimed = plan.prepare_anchor_root(&store).unwrap();
        assert_eq!(plan.prepare_anchor_root(&store).unwrap(), claimed);
        drop(store);
        let store = ControlStore::open(&database_path, &keys).unwrap();
        assert_eq!(plan.prepare_anchor_root(&store).unwrap(), claimed);

        // Simulate a crash after mkdir/fsync but before the inode claim was
        // persisted. Only an empty directory is safe to replace on replay.
        store
            .delete_record(ROOT_CLAIM_KIND, plan.anchor_id.as_bytes())
            .unwrap();
        let area = PinnedDirectory::open(&plan.area.path_hint).unwrap();
        let unclaimed = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        unclaimed
            .publish_small_bytes_child("foreign", b"keep")
            .unwrap();
        assert!(plan.prepare_anchor_root(&store).is_err());
        assert_eq!(
            fs::read(
                plan.area
                    .path_hint
                    .join(plan.anchor_id.to_string())
                    .join("foreign")
            )
            .unwrap(),
            b"keep"
        );
        unclaimed.remove_child_file("foreign").unwrap();
        assert!(plan.prepare_anchor_root(&store).is_ok());
        assert_eq!(fs::read(root.join("payload")).unwrap(), b"untouched");
    }

    #[test]
    fn guarded_root_claim_rejects_a_changed_marker() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([64; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_root(&store).unwrap();
        let marker = plan.area.path_hint.join(plan.marker_name());
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&marker, b"different owner").unwrap();
        assert!(plan.prepare_anchor_root(&store).is_err());
    }

    #[test]
    fn guarded_root_claim_rejects_a_replaced_directory() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([65; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_root(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        fs::rename(&anchor, plan.area.path_hint.join("old-anchor")).unwrap();
        fs::create_dir(&anchor).unwrap();
        assert!(plan.prepare_anchor_root(&store).is_err());
        assert!(anchor.is_dir());
    }

    #[test]
    fn claimed_directories_reopen_and_retire_from_leaves_upward() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("parent/child")).unwrap();
        fs::write(root.join("parent/child/file"), b"source bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([69; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        assert!(anchor.join("parent/child").is_dir());
        assert!(!anchor.join("parent/child/file").exists());
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
        assert!(!anchor.exists());
        assert!(
            store
                .records(&plan.directory_claim_kind())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fs::read(root.join("parent/child/file")).unwrap(),
            b"source bytes"
        );
    }

    #[test]
    fn freeze_planned_files_returns_only_a_candidate_catalog_for_empty_directories() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("parent/child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let entries = plan.freeze_planned_files(&store).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(matches!(
            &entries[0],
            CapturedEntry::Directory { path, .. } if path == "parent"
        ));
        assert!(matches!(
            &entries[1],
            CapturedEntry::Directory { path, .. } if path == "parent/child"
        ));
        plan.discard_empty_anchor_root(&store).unwrap();
    }

    #[test]
    fn complete_empty_root_manifest_reopens_and_blocks_generic_removal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("parent/child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([75; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        assert_eq!(manifest.entries.len(), 2);
        assert!(manifest.remove().is_err());
        assert!(plan.discard_empty_anchor_root(&store).is_err());
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_some()
        );
        // A crash after the sealed file was published but before its SQL
        // claim must replay by verifying the exact same catalog bytes.
        store
            .delete_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
            .unwrap();
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        plan.discard_unreferenced(&store).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            !plan
                .area
                .path_hint
                .join(plan.anchor_id.to_string())
                .exists()
        );
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(root.join("parent/child").is_dir());
    }

    #[test]
    fn published_manifest_recovery_rejects_changed_sealed_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([112; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        assert_eq!(
            GuardedRootCapturePlan::load_published_manifest(&store, plan.anchor_id).unwrap(),
            manifest
        );
        let catalog = plan
            .area
            .path_hint
            .join(plan.anchor_id.to_string())
            .join(capture_manifest_name(plan.anchor_id));
        let mut bytes = fs::read(&catalog).unwrap();
        bytes[0] ^= 1;
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o644)).unwrap();
        fs::write(&catalog, bytes).unwrap();
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(GuardedRootCapturePlan::load_published_manifest(&store, plan.anchor_id).is_err());
    }

    #[test]
    fn root_retirement_with_an_unstarted_file_preserves_source_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("parent")).unwrap();
        fs::write(root.join("parent/file"), b"raw\r\nbytes\0").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([78; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(
            fs::read(root.join("parent/file")).unwrap(),
            b"raw\r\nbytes\0"
        );
        assert!(plan.prepare_anchor_root(&store).is_err());
    }

    #[test]
    fn published_root_retirement_replays_after_manifest_unlink() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([81; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let stored_manifest = plan.capture(&store).unwrap();
        let retirement = RootRetirement {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes(),
        };
        store
            .put_record(
                RETIRE_KIND,
                plan.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&retirement).unwrap(),
            )
            .unwrap();
        let anchor =
            PinnedDirectory::open(plan.area.path_hint.join(plan.anchor_id.to_string())).unwrap();
        anchor
            .remove_child_file(capture_manifest_name(plan.anchor_id))
            .unwrap();
        assert!(
            GuardedRootCapturePlan::load_for_manifest(&store, &stored_manifest)
                .unwrap()
                .is_some()
        );
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            !plan
                .area
                .path_hint
                .join(plan.anchor_id.to_string())
                .exists()
        );
    }

    #[test]
    fn durable_source_plan_dispatches_guarded_root_capture() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([83; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let source = crate::SourceCapturePlan::GuardedLinkFreezeV1(plan.clone());
        let decoded: crate::SourceCapturePlan =
            mb_core::decode_canonical(&mb_core::canonical_bytes(&source).unwrap()).unwrap();
        assert_eq!(decoded, source);
        assert_eq!(decoded.source_root(), root);
        let manifest = decoded.capture(&store).unwrap();
        assert!(
            GuardedRootCapturePlan::load_for_manifest(&store, &manifest)
                .unwrap()
                .is_some()
        );
        let mut wrong = manifest.clone();
        wrong.root_mode ^= 0o100;
        assert!(GuardedRootCapturePlan::load_for_manifest(&store, &wrong).is_err());
        decoded.discard(&store).unwrap();
        decoded.reconcile(&store).unwrap();
    }

    #[test]
    fn root_edit_requires_a_published_file_capture() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"source bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let capture_id = match &plan.entries[0] {
            GuardedRootEntry::File { capture_id, .. } => *capture_id,
            _ => panic!("expected file entry"),
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([84; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let source = crate::SourceCapturePlan::GuardedLinkFreezeV1(plan);
        assert!(source.prepare_file_edit_at(&store, "file", "file").is_err());
        assert!(
            LinkFreezeCaptureIntent::load(&store, capture_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read(root.join("file")).unwrap(), b"source bytes");
    }

    #[test]
    fn root_retirement_preserves_an_unknown_child_until_replay() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([82; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.capture(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        fs::write(anchor.join("child/foreign"), b"keep").unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        assert_eq!(fs::read(anchor.join("child/foreign")).unwrap(), b"keep");
        assert!(plan.capture(&store).is_err());
        fs::remove_file(anchor.join("child/foreign")).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert!(!anchor.exists());
    }

    #[test]
    fn root_retirement_refuses_a_changed_claimed_manifest() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([79; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.capture(&store).unwrap();
        let manifest_path = plan
            .area
            .path_hint
            .join(plan.anchor_id.to_string())
            .join(capture_manifest_name(plan.anchor_id));
        fs::set_permissions(&manifest_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&manifest_path, b"changed").unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        assert!(
            store
                .get_record(RETIRE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn complete_root_capture_replays_and_restores_access_on_retirement() {
        use std::os::unix::fs::PermissionsExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-root-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        let source = root.join("nested/file");
        fs::write(&source, b"raw\r\nbytes\0").unwrap();
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([80; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        let mut anchored = Vec::new();
        manifest
            .file_locator("nested/file".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_end(&mut anchored)
            .unwrap();
        assert_eq!(anchored, b"raw\r\nbytes\0");
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o222,
            0
        );
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        crate::SourceCapturePlan::GuardedLinkFreezeV1(plan.clone())
            .prepare_file_edit_at(&store, "nested/file", "nested/file")
            .unwrap();
        fs::write(&source, b"later edit").unwrap();
        let mut retained = Vec::new();
        manifest
            .file_locator("nested/file".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_end(&mut retained)
            .unwrap();
        assert_eq!(retained, b"raw\r\nbytes\0");
        plan.discard_unreferenced(&store).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"later edit");
        assert_ne!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o200,
            0
        );
        assert!(
            !plan
                .area
                .path_hint
                .join(plan.anchor_id.to_string())
                .exists()
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events and root for chown"]
    fn lower_ownership_snapshot_survives_reopen_and_fences_retirement() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-lower-owner-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        let source = root.join("nested/file");
        fs::write(&source, b"original\r\n\0bytes").unwrap();
        let encoded = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([115; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        plan.prepare_private_lower_ownership(&store, &manifest)
            .unwrap();
        let bytes = store
            .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
            .unwrap()
            .unwrap();
        let snapshot: LowerOwnershipSnapshot = mb_core::decode_canonical(&bytes).unwrap();
        assert_eq!(
            snapshot
                .entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["", "nested", "nested/file"]
        );
        assert_eq!(snapshot.entries[2].uid, 65534);
        assert_eq!(snapshot.entries[2].gid, 65534);
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        store
            .put_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes(), &[0xff])
            .unwrap();
        assert!(plan.reconcile(&store).is_err());
        store
            .put_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes(), &bytes)
            .unwrap();
        plan.prepare_private_lower_ownership(&store, &manifest)
            .unwrap();
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 0, 0) }, 0);
        assert!(
            plan.cancel_private_lower_ownership(&store, &manifest)
                .is_err()
        );
        assert!(plan.discard_unreferenced(&store).is_err());
        assert_eq!(
            store
                .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
                .unwrap(),
            Some(bytes.clone())
        );
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        plan.cancel_private_lower_ownership(&store, &manifest)
            .unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(&source).unwrap(), b"original\r\n\0bytes");
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded owner isolation"]
    fn root_file_owner_isolation_replays_after_one_file() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-file-owners-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        for path in [root.join("a"), root.join("nested/b")] {
            fs::write(&path, b"raw\r\n\0file").unwrap();
            let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        }
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([117; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        plan.prepare_private_lower_ownership(&store, &manifest)
            .unwrap();
        let GuardedRootEntry::File { capture_id, .. } = &plan.entries[0] else {
            panic!("expected first captured file");
        };
        let first = LinkFreezeCaptureIntent::load(&store, *capture_id)
            .unwrap()
            .unwrap();
        let source_root = PinnedDirectory::open(&root).unwrap();
        let area = PinnedDirectory::open(&plan.area.path_hint).unwrap();
        let anchor_root = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        first
            .isolate_owner(
                &store,
                &source_root,
                &anchor_root,
                FileOwner {
                    uid: 65534,
                    gid: 65534,
                },
                FileOwner { uid: 0, gid: 0 },
            )
            .unwrap();
        assert_eq!(fs::metadata(root.join("a")).unwrap().uid(), 0);
        assert_eq!(fs::metadata(root.join("nested/b")).unwrap().uid(), 65534);
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.isolate_frozen_file_owners(&store, &manifest, 65534, 0, 0)
            .unwrap();
        plan.isolate_frozen_file_owners(&store, &manifest, 65534, 0, 0)
            .unwrap();
        for path in ["a", "nested/b"] {
            assert_eq!(fs::metadata(root.join(path)).unwrap().uid(), 0);
            assert_eq!(fs::read(root.join(path)).unwrap(), b"raw\r\n\0file");
            let mut anchor = manifest
                .file_locator(path.to_owned())
                .unwrap()
                .open()
                .unwrap();
            let mut bytes = Vec::new();
            anchor.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"raw\r\n\0file");
        }
        let nested = root.join("nested");
        let original_mode = fs::metadata(&nested).unwrap().permissions().mode() & 0o7777;
        fs::set_permissions(&nested, fs::Permissions::from_mode(original_mode ^ 0o001)).unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        assert_eq!(fs::metadata(root.join("a")).unwrap().uid(), 0);
        assert!(
            store
                .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_some()
        );
        fs::set_permissions(&nested, fs::Permissions::from_mode(original_mode)).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            store
                .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        for path in ["a", "nested/b"] {
            let file = root.join(path);
            assert_eq!(fs::metadata(&file).unwrap().uid(), 65534);
            assert_eq!(fs::metadata(&file).unwrap().gid(), 65534);
            assert_eq!(fs::read(file).unwrap(), b"raw\r\n\0file");
        }
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded owner isolation"]
    fn root_owner_retirement_replays_after_one_file_completed() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-owner-retire-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        for name in ["a", "b"] {
            let path = root.join(name);
            fs::write(&path, b"exact\r\n\0bytes").unwrap();
            let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        }
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([120; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        plan.prepare_private_lower_ownership(&store, &manifest)
            .unwrap();
        plan.isolate_frozen_file_owners(&store, &manifest, 65534, 0, 0)
            .unwrap();
        let retirement = RootRetirement {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes(),
        };
        assert!(
            store
                .put_record_if_absent(
                    RETIRE_KIND,
                    plan.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(&retirement).unwrap(),
                )
                .unwrap()
        );
        let GuardedRootEntry::File { capture_id, .. } = &plan.entries[0] else {
            panic!("expected first file");
        };
        let source_root = PinnedDirectory::open(&root).unwrap();
        let anchor_area = PinnedDirectory::open(&plan.area.path_hint).unwrap();
        let anchor_root = anchor_area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        LinkFreezeCaptureIntent::load(&store, *capture_id)
            .unwrap()
            .unwrap()
            .retire_unreferenced(&store, &source_root, &anchor_root)
            .unwrap();
        assert!(LinkFreezeCaptureIntent::retirement_pending(&store, *capture_id).unwrap());
        assert_eq!(fs::metadata(root.join("a")).unwrap().uid(), 65534);
        assert_eq!(fs::metadata(root.join("b")).unwrap().uid(), 0);
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            store
                .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(!LinkFreezeCaptureIntent::retirement_pending(&store, *capture_id).unwrap());
        for name in ["a", "b"] {
            let path = root.join(name);
            assert_eq!(fs::metadata(&path).unwrap().uid(), 65534);
            assert_eq!(fs::metadata(&path).unwrap().gid(), 65534);
            assert_eq!(fs::read(path).unwrap(), b"exact\r\n\0bytes");
        }
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded owner-first capture"]
    fn root_private_capture_keeps_anchors_private_through_reopen_and_retirement() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-private-capture-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        for path in [root.join("a"), root.join("nested/b")] {
            fs::write(&path, b"private\r\n\0bytes").unwrap();
            let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        }
        let already_private = root.join("already-private");
        fs::write(&already_private, b"original private owner").unwrap();
        fs::set_permissions(&already_private, fs::Permissions::from_mode(0o666)).unwrap();
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([123; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan
            .capture_private_file_owners(&store, 65534, 0, 0)
            .unwrap();
        assert!(
            plan.cancel_private_lower_ownership(&store, &manifest)
                .is_err()
        );
        let snapshot_bytes = store
            .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
            .unwrap()
            .unwrap();
        let snapshot: LowerOwnershipSnapshot = mb_core::decode_canonical(&snapshot_bytes).unwrap();
        for entry in snapshot
            .entries
            .iter()
            .filter(|entry| entry.path == "a" || entry.path == "nested/b")
        {
            assert_eq!((entry.uid, entry.gid), (65534, 65534));
        }
        for path in ["a", "nested/b"] {
            assert_eq!(fs::metadata(root.join(path)).unwrap().uid(), 0);
            assert_eq!(
                manifest
                    .file_locator(path.to_owned())
                    .unwrap()
                    .open()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .uid(),
                0
            );
        }
        assert_eq!(fs::metadata(&already_private).unwrap().uid(), 0);
        assert_eq!(
            fs::metadata(&already_private).unwrap().permissions().mode() & 0o7777,
            0o444
        );
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        assert_eq!(
            plan.capture_private_file_owners(&store, 65534, 0, 0)
                .unwrap(),
            manifest
        );
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            store
                .get_record(PRIVATE_FILE_CAPTURE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        for path in ["a", "nested/b"] {
            let file = root.join(path);
            assert_eq!(fs::metadata(&file).unwrap().uid(), 65534);
            assert_eq!(fs::metadata(&file).unwrap().gid(), 65534);
            assert_eq!(fs::read(file).unwrap(), b"private\r\n\0bytes");
        }
        assert_eq!(fs::metadata(&already_private).unwrap().uid(), 0);
        assert_eq!(
            fs::metadata(&already_private).unwrap().permissions().mode() & 0o7777,
            0o666
        );
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded owner-first capture"]
    fn private_root_edit_restores_detached_source_owner_before_retirement() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-detached-owner-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let source = root.join("file");
        let original = b"exact\r\n\0source";
        fs::write(&source, original).unwrap();
        let encoded = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([125; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan
            .capture_private_file_owners(&store, 65534, 0, 0)
            .unwrap();
        assert_eq!(fs::metadata(&source).unwrap().uid(), 0);
        let capture_id = match &plan.entries[0] {
            GuardedRootEntry::File { capture_id, .. } => *capture_id,
            _ => panic!("planned file became a directory"),
        };
        let area_path = resolve_anchor_area(&plan.area).unwrap();
        let area = PinnedDirectory {
            file: open_stable_anchor_area(&area_path, &plan.area).unwrap(),
            filesystem_id: plan.area.filesystem_id,
        };
        let anchor_root = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        let plan_hash = *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes();
        let anchor_parent = plan
            .claimed_file_parent(&store, &anchor_root, plan_hash, Path::new("file"))
            .unwrap();
        let source_parent = PinnedDirectory::open(&root).unwrap();
        let intent = LinkFreezeCaptureIntent::load(&store, capture_id)
            .unwrap()
            .unwrap();
        intent
            .detach_for_edit_at(&store, &source_parent, Path::new("file"), &anchor_parent)
            .unwrap();
        assert_eq!(fs::metadata(&source).unwrap().uid(), 0);
        assert!(LinkFreezeCaptureIntent::owner_isolation_pending(&store, capture_id).unwrap());
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.prepare_file_edit_at(&store, "file", "file").unwrap();
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        assert!(!LinkFreezeCaptureIntent::owner_isolation_pending(&store, capture_id).unwrap());
        fs::write(&source, b"edited bytes").unwrap();
        let mut anchor = manifest
            .file_locator("file".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut retained = Vec::new();
        anchor.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        assert_eq!(fs::read(&source).unwrap(), b"edited bytes");
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded owner-first capture"]
    fn root_private_capture_replays_prepared_private_source_without_anchor() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-private-replay-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let source = root.join("file");
        fs::write(&source, b"replay\r\n\0bytes").unwrap();
        let encoded = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let GuardedRootEntry::File {
            capture_id,
            version,
            ..
        } = &plan.entries[0]
        else {
            panic!("expected file");
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([124; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let marker = PrivateFileCapture {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes(),
            view_uid: 65534,
            private_uid: 0,
            private_gid: 0,
        };
        assert!(
            store
                .put_record_if_absent(
                    PRIVATE_FILE_CAPTURE_KIND,
                    plan.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(&marker).unwrap(),
                )
                .unwrap()
        );
        plan.prepare_anchor_directories(&store).unwrap();
        let source_parent = PinnedDirectory::open(&root).unwrap();
        let area = PinnedDirectory::open(&plan.area.path_hint).unwrap();
        let anchor_parent = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        let prepared = LinkFreezeCaptureIntent::begin_checked(
            &store,
            *capture_id,
            &source_parent,
            "file",
            &anchor_parent,
            "file",
            version,
        )
        .unwrap();
        prepared
            .isolate_prepared_owner(
                &store,
                &source_parent,
                &anchor_parent,
                FileOwner { uid: 0, gid: 0 },
                version,
            )
            .unwrap();
        assert_eq!(fs::metadata(&source).unwrap().uid(), 0);
        assert!(
            !plan
                .area
                .path_hint
                .join(plan.anchor_id.to_string())
                .join("file")
                .exists()
        );
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        assert!(
            plan.capture_private_file_owners(&store, 65534, 0, 1)
                .is_err()
        );
        let manifest = plan
            .capture_private_file_owners(&store, 65534, 0, 0)
            .unwrap();
        assert_eq!(
            manifest
                .file_locator("file".to_owned())
                .unwrap()
                .open()
                .unwrap()
                .metadata()
                .unwrap()
                .uid(),
            0
        );
        assert_eq!(fs::read(&source).unwrap(), b"replay\r\n\0bytes");
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        assert_eq!(fs::read(source).unwrap(), b"replay\r\n\0bytes");
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded prepared capture cancellation"]
    fn root_private_capture_abandons_unlinked_prepared_source() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-private-abandon-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let source = root.join("file");
        fs::write(&source, b"unlinked prepared bytes").unwrap();
        let encoded = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let GuardedRootEntry::File {
            capture_id,
            version,
            ..
        } = &plan.entries[0]
        else {
            panic!("expected file");
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([125; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let marker = PrivateFileCapture {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes(),
            view_uid: 65534,
            private_uid: 0,
            private_gid: 0,
        };
        assert!(
            store
                .put_record_if_absent(
                    PRIVATE_FILE_CAPTURE_KIND,
                    plan.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(&marker).unwrap(),
                )
                .unwrap()
        );
        plan.prepare_anchor_directories(&store).unwrap();
        let source_parent = PinnedDirectory::open(&root).unwrap();
        let area = PinnedDirectory::open(&plan.area.path_hint).unwrap();
        let anchor_parent = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        LinkFreezeCaptureIntent::begin_checked(
            &store,
            *capture_id,
            &source_parent,
            "file",
            &anchor_parent,
            "file",
            version,
        )
        .unwrap();
        assert!(
            anchor_parent
                .entry_identity("file", false)
                .unwrap()
                .is_none()
        );
        let moved = root.join("moved");
        fs::rename(&source, &moved).unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        assert!(
            LinkFreezeCaptureIntent::load(&store, *capture_id)
                .unwrap()
                .is_some()
        );
        fs::rename(&moved, &source).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            LinkFreezeCaptureIntent::load(&store, *capture_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_record(PRIVATE_FILE_CAPTURE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        assert_eq!(fs::read(source).unwrap(), b"unlinked prepared bytes");
    }

    #[test]
    fn unstarted_private_capture_marker_can_be_retired() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([126; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let marker = PrivateFileCapture {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes(),
            view_uid: 65534,
            private_uid: 0,
            private_gid: 0,
        };
        assert!(
            store
                .put_record_if_absent(
                    PRIVATE_FILE_CAPTURE_KIND,
                    plan.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(&marker).unwrap(),
                )
                .unwrap()
        );
        plan.discard_unreferenced(&store).unwrap();
        assert!(
            store
                .get_record(PRIVATE_FILE_CAPTURE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires root, POSIX ACLs, and CAP_SYS_ADMIN"]
    fn private_capture_rejects_acl_without_publishing_an_anchor() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-private-acl-refusal-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let source = root.join("file");
        fs::write(&source, b"acl private refusal").unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&source)
            .unwrap();
        if !crate::link_freeze::install_probe_acl(&file).unwrap() {
            return;
        }
        drop(file);
        let encoded = std::ffi::CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([127; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        assert!(
            plan.capture_private_file_owners(&store, 65534, 0, 0)
                .is_err()
        );
        let anchor = plan
            .area
            .path_hint
            .join(plan.anchor_id.to_string())
            .join("file");
        assert!(!anchor.exists());
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        plan.discard_unreferenced(&store).unwrap();
        assert!(!anchor.exists());
        assert_eq!(fs::read(&source).unwrap(), b"acl private refusal");
        assert!(
            store
                .get_record(PRIVATE_FILE_CAPTURE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded directory isolation"]
    fn private_directory_isolation_replays_and_restores_on_root_retirement() {
        use std::os::unix::ffi::OsStrExt;

        // No interruption, after nested chmod, after nested chown/root chmod,
        // and after the first retirement chown are distinct replay states.
        for interruption in 0..4 {
            let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
                Some(root) => tempfile::Builder::new()
                    .prefix("mb-private-directories-")
                    .tempdir_in(root)
                    .unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let root = temp.path().join("root");
            let nested = root.join("nested");
            fs::create_dir_all(&nested).unwrap();
            let source = nested.join("file");
            fs::write(&source, b"exact\r\n\0directory bytes").unwrap();
            for path in [&root, &nested, &source] {
                let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
            }
            let plan = GuardedRootCapturePlan::plan(&root).unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([128; 32]));
            let database_path = temp.path().join("control.db");
            let store = ControlStore::open(&database_path, &keys).unwrap();
            let manifest = plan
                .capture_private_file_owners(&store, 65534, 0, 0)
                .unwrap();
            let snapshot_bytes = store
                .get_record(LOWER_OWNERSHIP_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .unwrap();
            if interruption == 0 {
                let extra = nested.join("uncaptured");
                fs::write(&extra, b"unplanned bytes").unwrap();
                assert!(plan.isolate_lower_directories(&store, &manifest).is_err());
                assert!(
                    store
                        .get_record(DIRECTORY_ISOLATION_KIND, plan.anchor_id.as_bytes())
                        .unwrap()
                        .is_none()
                );
                for directory in [&root, &nested] {
                    let metadata = fs::metadata(directory).unwrap();
                    assert_eq!((metadata.uid(), metadata.gid()), (65534, 65534));
                }
                fs::remove_file(extra).unwrap();
            }
            if interruption == 1 || interruption == 2 {
                let marker = plan.private_file_capture(&store).unwrap().unwrap();
                let record = DirectoryIsolation {
                    format_version: 1,
                    anchor_id: plan.anchor_id,
                    plan_hash: marker.plan_hash,
                    snapshot_hash: *blake3::hash(&snapshot_bytes).as_bytes(),
                    view_uid: marker.view_uid,
                    private_uid: marker.private_uid,
                    private_gid: marker.private_gid,
                };
                assert!(
                    store
                        .put_record_if_absent(
                            DIRECTORY_ISOLATION_KIND,
                            plan.anchor_id.as_bytes(),
                            &mb_core::canonical_bytes(&record).unwrap(),
                        )
                        .unwrap()
                );
                fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
                if interruption == 2 {
                    let encoded = std::ffi::CString::new(nested.as_os_str().as_bytes()).unwrap();
                    assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 0, 0) }, 0);
                    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
                } else {
                    assert_eq!(fs::metadata(&nested).unwrap().uid(), 65534);
                }
            }
            drop(store);

            let store = ControlStore::open(&database_path, &keys).unwrap();
            plan.isolate_lower_directories(&store, &manifest).unwrap();
            plan.isolate_lower_directories(&store, &manifest).unwrap();
            for directory in [&root, &nested] {
                let metadata = fs::metadata(directory).unwrap();
                assert_eq!((metadata.uid(), metadata.gid()), (0, 0));
                assert_eq!(metadata.permissions().mode() & 0o7777, 0o700);
            }
            assert!(
                store
                    .get_record(DIRECTORY_ISOLATION_KIND, plan.anchor_id.as_bytes())
                    .unwrap()
                    .is_some()
            );
            assert_eq!(fs::read(&source).unwrap(), b"exact\r\n\0directory bytes");
            if interruption == 3 {
                let encoded = std::ffi::CString::new(nested.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
                assert_eq!(
                    fs::metadata(&nested).unwrap().permissions().mode() & 0o7777,
                    0o700
                );
            }
            plan.discard_unreferenced(&store).unwrap();
            for directory in [&root, &nested] {
                let metadata = fs::metadata(directory).unwrap();
                assert_eq!((metadata.uid(), metadata.gid()), (65534, 65534));
                assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);
            }
            assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
            assert_eq!(fs::read(source).unwrap(), b"exact\r\n\0directory bytes");
            assert!(
                store
                    .get_record(DIRECTORY_ISOLATION_KIND, plan.anchor_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for retained-directory descriptor probe"]
    fn private_directory_isolation_blocks_retained_user_descriptors() {
        use std::io::{BufRead, BufReader, Write};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-private-directory-fds-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let root = temp.path().join("root");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o755)).unwrap();
        let source = nested.join("file");
        fs::write(&source, b"held directory bytes").unwrap();
        for path in [&root, &nested, &source] {
            let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        }
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([129; 32]));
        let control_dir = tempfile::tempdir().unwrap();
        let store = ControlStore::open(control_dir.path().join("control.db"), &keys).unwrap();
        let manifest = plan
            .capture_private_file_owners(&store, 65534, 0, 0)
            .unwrap();
        let mut child = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-u")
            .arg("-c")
            .arg(
                r#"import errno, os, sys
root = os.open(sys.argv[1], os.O_RDONLY | os.O_DIRECTORY)
nested = os.open(sys.argv[2], os.O_RDONLY | os.O_DIRECTORY)
print('READY', flush=True)
assert sys.stdin.readline() == 'continue\n'
for operation in (
    lambda: os.fchmod(root, 0o777),
    lambda: os.fchmod(nested, 0o777),
    lambda: os.open('nested', os.O_RDONLY | os.O_DIRECTORY, dir_fd=root),
    lambda: os.open('file', os.O_RDONLY, dir_fd=nested),
):
    try:
        operation()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM), error
    else:
        raise AssertionError('retained directory descriptor bypassed private lower mode')
os.close(nested)
os.close(root)
print('DONE', flush=True)
"#,
            )
            .arg(&root)
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
            let status = child.wait().unwrap();
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            panic!("retained-directory child did not start: {status}: {stderr}");
        }
        plan.isolate_lower_directories(&store, &manifest).unwrap();
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
        assert!(
            status.success(),
            "retained-directory child failed: {stderr}"
        );
        assert_eq!(line, "DONE\n");
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(source).unwrap(), b"held directory bytes");
    }

    #[test]
    #[ignore = "requires root and CAP_SYS_ADMIN for guarded directory ACL probe"]
    fn private_directory_isolation_refuses_default_acl_before_mutation() {
        use std::os::unix::ffi::OsStrExt;

        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-private-directory-acl-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let root = temp.path().join("root");
        let nested = root.join("nested");
        fs::create_dir_all(&nested).unwrap();
        let source = nested.join("file");
        fs::write(&source, b"directory ACL refusal").unwrap();
        for path in [&root, &nested, &source] {
            let encoded = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(encoded.as_ptr(), 65534, 65534) }, 0);
        }
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([130; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let manifest = plan
            .capture_private_file_owners(&store, 65534, 0, 0)
            .unwrap();
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permission) in [(1_u16, 7_u16), (4, 5), (32, 5)] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permission.to_le_bytes());
            acl.extend_from_slice(&u32::MAX.to_le_bytes());
        }
        let encoded = std::ffi::CString::new(nested.as_os_str().as_bytes()).unwrap();
        let result = unsafe {
            libc::setxattr(
                encoded.as_ptr(),
                c"system.posix_acl_default".as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        if result < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EOPNOTSUPP)
            );
            plan.discard_unreferenced(&store).unwrap();
            return;
        }
        assert!(plan.isolate_lower_directories(&store, &manifest).is_err());
        assert!(
            store
                .get_record(DIRECTORY_ISOLATION_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        for directory in [&root, &nested] {
            let metadata = fs::metadata(directory).unwrap();
            assert_eq!((metadata.uid(), metadata.gid()), (65534, 65534));
            assert_eq!(metadata.permissions().mode() & 0o7777, 0o755);
        }
        assert_eq!(
            unsafe { libc::removexattr(encoded.as_ptr(), c"system.posix_acl_default".as_ptr()) },
            0
        );
        plan.isolate_lower_directories(&store, &manifest).unwrap();
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(source).unwrap(), b"directory ACL refusal");
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn root_edit_replays_after_source_rename_without_changing_manifest() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("nested")).unwrap();
        let original = root.join("nested/file");
        fs::write(&original, b"original\r\nbytes\0").unwrap();
        let plan = GuardedRootCapturePlan::plan(&root).unwrap();
        let capture_id = plan
            .entries
            .iter()
            .find_map(|entry| match entry {
                GuardedRootEntry::File {
                    path, capture_id, ..
                } if path == "nested/file" => Some(*capture_id),
                _ => None,
            })
            .unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([85; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let manifest = plan.capture(&store).unwrap();
        let source_parent = PinnedDirectory::open(root.join("nested")).unwrap();
        let anchor_parent = PinnedDirectory::open(
            plan.area
                .path_hint
                .join(plan.anchor_id.to_string())
                .join("nested"),
        )
        .unwrap();
        LinkFreezeCaptureIntent::load(&store, capture_id)
            .unwrap()
            .unwrap()
            .begin_edit(&store, &source_parent, &anchor_parent)
            .unwrap();
        fs::create_dir(root.join("moved")).unwrap();
        let renamed = root.join("moved/renamed");
        fs::rename(&original, &renamed).unwrap();
        fs::write(&original, b"unrelated replacement").unwrap();
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        crate::SourceCapturePlan::GuardedLinkFreezeV1(plan.clone())
            .prepare_file_edit_at(&store, "nested/file", "moved/renamed")
            .unwrap();
        fs::write(&renamed, b"new user bytes").unwrap();
        assert_eq!(fs::read(&original).unwrap(), b"unrelated replacement");
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        let mut retained = Vec::new();
        manifest
            .file_locator("nested/file".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_end(&mut retained)
            .unwrap();
        assert_eq!(retained, b"original\r\nbytes\0");
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(&renamed).unwrap(), b"new user bytes");
        assert_eq!(fs::read(&original).unwrap(), b"unrelated replacement");
    }

    #[test]
    fn claimed_manifest_cannot_be_silently_recreated_after_loss() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([77; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.capture(&store).unwrap();
        let anchor =
            PinnedDirectory::open(plan.area.path_hint.join(plan.anchor_id.to_string())).unwrap();
        anchor
            .remove_child_file(capture_manifest_name(plan.anchor_id))
            .unwrap();
        assert!(plan.capture(&store).is_err());
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn complete_manifest_rejects_unknown_anchor_names() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([76; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        fs::write(anchor.join("child/foreign"), b"keep").unwrap();
        assert!(plan.capture(&store).is_err());
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert_eq!(fs::read(anchor.join("child/foreign")).unwrap(), b"keep");
        fs::remove_file(anchor.join("child/foreign")).unwrap();
        assert!(plan.capture(&store).is_ok());
    }

    #[test]
    fn changed_file_does_not_acquire_a_guarded_freeze_journal() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("file"), b"original").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let capture_id = match &plan.entries[0] {
            GuardedRootEntry::File { capture_id, .. } => *capture_id,
            _ => panic!("expected file"),
        };
        fs::write(root.join("file"), b"changed bytes").unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([74; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        assert!(plan.freeze_planned_files(&store).is_err());
        assert!(
            LinkFreezeCaptureIntent::load(&store, capture_id)
                .unwrap()
                .is_none()
        );
        plan.discard_empty_anchor_root(&store).unwrap();
        assert_eq!(fs::read(root.join("file")).unwrap(), b"changed bytes");
    }

    #[test]
    fn unclaimed_nested_directory_must_be_empty_to_replay() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("parent/child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([70; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        let claim_kind = plan.directory_claim_kind();
        store.delete_record(&claim_kind, b"parent/child").unwrap();
        fs::write(anchor.join("parent/child/foreign"), b"keep").unwrap();

        assert!(plan.prepare_anchor_directories(&store).is_err());
        assert_eq!(
            fs::read(anchor.join("parent/child/foreign")).unwrap(),
            b"keep"
        );
        fs::remove_file(anchor.join("parent/child/foreign")).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
    }

    #[test]
    fn claimed_directory_replacement_is_never_adopted() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([71; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        fs::rename(anchor.join("child"), anchor.join("old-child")).unwrap();
        fs::create_dir(anchor.join("child")).unwrap();

        assert!(plan.prepare_anchor_directories(&store).is_err());
        assert!(plan.discard_empty_anchor_root(&store).is_err());
        assert!(anchor.join("child").is_dir());
        assert!(anchor.join("old-child").is_dir());
    }

    #[test]
    fn nested_retirement_replays_after_a_claimed_directory_was_unlinked() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir_all(root.join("parent/child")).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([72; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_directories(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        fs::remove_dir(anchor.join("parent/child")).unwrap();
        assert!(plan.discard_empty_anchor_root(&store).is_err());
        assert!(
            store
                .get_record(RETIRE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );

        let retirement = RootRetirement {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes(),
        };
        store
            .put_record(
                RETIRE_KIND,
                plan.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&retirement).unwrap(),
            )
            .unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
        assert!(!anchor.exists());
    }

    #[test]
    fn empty_root_retirement_replays_without_recreating_the_anchor() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("payload"), b"source bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([66; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.prepare_anchor_root(&store).unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
        assert!(
            !plan
                .area
                .path_hint
                .join(plan.anchor_id.to_string())
                .exists()
        );
        assert!(!plan.area.path_hint.join(plan.marker_name()).exists());
        assert!(
            store
                .get_record(PLAN_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(plan.prepare_anchor_root(&store).is_err());
        drop(store);
        let store = ControlStore::open(&database_path, &keys).unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
        assert!(plan.prepare_anchor_root(&store).is_err());
        assert_eq!(fs::read(root.join("payload")).unwrap(), b"source bytes");
    }

    #[test]
    fn empty_root_retirement_refuses_unknown_child_until_removed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([67; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        plan.prepare_anchor_root(&store).unwrap();
        let anchor = plan.area.path_hint.join(plan.anchor_id.to_string());
        fs::write(anchor.join("foreign"), b"keep").unwrap();
        assert!(plan.discard_empty_anchor_root(&store).is_err());
        assert_eq!(fs::read(anchor.join("foreign")).unwrap(), b"keep");
        assert!(plan.prepare_anchor_root(&store).is_err());
        fs::remove_file(anchor.join("foreign")).unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
    }

    #[test]
    fn empty_root_retirement_requires_a_durable_record_before_replaying_missing_root() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([68; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let root_id = plan.prepare_anchor_root(&store).unwrap();
        let area = PinnedDirectory::open(&plan.area.path_hint).unwrap();
        assert!(
            area.remove_empty_child_directory(plan.anchor_id.to_string(), root_id)
                .unwrap()
        );
        assert!(plan.discard_empty_anchor_root(&store).is_err());
        let plan_hash = *blake3::hash(&mb_core::canonical_bytes(&plan).unwrap()).as_bytes();
        let retirement = RootRetirement {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash,
        };
        store
            .put_record(
                RETIRE_KIND,
                plan.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&retirement).unwrap(),
            )
            .unwrap();
        plan.discard_empty_anchor_root(&store).unwrap();
        assert!(
            store
                .get_record(ROOT_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
    }
}
