//! Bounded, read-only inventory for a future guarded whole-root capture.
//! The node must persist this plan before freezing any listed file. A root is
//! not eligible for enrollment until capture, replay, and retirement consume
//! this inventory through the versioned source-backend boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use mb_core::V1_MAX_CATALOG_BYTES;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AnchorError, CaptureVersion, CapturedEntry, DirectoryStream, FilesystemIdentity,
    GIT_CATALOG_DIRECTORY, MAX_CAPTURE_DEPTH, MAX_CAPTURE_ENTRIES, MAX_CAPTURE_EXTENTS,
    MAX_RELATIVE_PATH_BYTES, NativeFileId, PinnedDirectory, StableAnchorAreaLocator,
    capture_version, filesystem_identity_for_file, git_catalog_marker_from_root, modified_parts,
    open_path_no_xdev_beneath, open_source_beneath, open_source_root, open_stable_anchor_area,
    probe_guarded_link_freeze, reopen_pinned_file, resolve_anchor_area, unix_mode,
    validate_relative,
};
use crate::{ControlStore, LinkFreezeCaptureIntent, LinkFreezeCapturePhase};

const PLAN_KIND: &str = "guarded-root-plan-v1";
const ROOT_CLAIM_KIND: &str = "guarded-root-claim-v1";
const DIRECTORY_CLAIM_PREFIX: &str = "guarded-root-directory-v1/";
const RETIRE_KIND: &str = "guarded-root-retire-v1";
const MARKER_PREFIX: &str = ".mutualbackup-guarded-root-v1-";

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
struct RootRetirement {
    format_version: u16,
    anchor_id: Uuid,
    plan_hash: [u8; 32],
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
                    anyhow::ensure!(intent.matches_root_file_plan(
                        *capture_id,
                        expected_parent,
                        expected_source,
                        &anchor_parent,
                        name,
                    )?);
                    let verified = intent
                        .resume(control, &source_parent, &anchor_parent)?
                        .ok_or_else(|| anyhow::anyhow!("planned guarded source changed: {path}"))?;
                    anyhow::ensure!(matches!(
                        verified.phase(),
                        LinkFreezeCapturePhase::Frozen | LinkFreezeCapturePhase::Detached
                    ));
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

    /// Abandon only a prepared, empty root namespace. A file freeze requires
    /// the later journal-aware retirement path; this method refuses any file
    /// capture intent or child entry rather than unlinking a frozen source.
    pub fn discard_empty_anchor_root(&self, control: &ControlStore) -> anyhow::Result<()> {
        self.validate()?;
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
        format!("{MARKER_PREFIX}{}", self.anchor_id)
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
