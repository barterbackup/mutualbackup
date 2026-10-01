//! Crash-replayable checkout for regular files. The selected HEAD and index
//! change together only after every target file is durably in the worktree.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, Permissions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use git2::{Branch, ObjectType, Oid};
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{AnchorError, ControlStore, DatabaseError, NativeFileId, PinnedDirectory};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::head::{HeadError, selected_branch, selected_branch_record};
use crate::history::{GitBranchInfo, HistoryError, list_branches};
use crate::stage::{
    GitIndexEntry, StageError, anchors_for_oid, has_pending_stages, index_kind, stage_path_key,
    staged_entries,
};
use crate::status::{StatusError, TreeFiles, committed_files, files_for_commit};
use crate::{GitAnchorError, blob_oid_from_anchor};

const INTENT_PREFIX: &str = "git-checkout-intent-v1/";
const INTENT_KEY: &[u8] = b"active";
const MAX_CHECKOUT_FILES: usize = 8_192;

#[cfg(test)]
thread_local! {
    static AFTER_CHECKOUT_FILE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_CHECKOUT_DIRECTORY: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_DIRECTORY_CLEANUP: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_CHECKOUT_COMMIT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_checkout_file_hook(hook: Box<dyn FnOnce()>) {
    AFTER_CHECKOUT_FILE.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(crate) fn set_after_checkout_directory_hook(hook: Box<dyn FnOnce()>) {
    AFTER_CHECKOUT_DIRECTORY.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(crate) fn set_after_directory_cleanup_hook(hook: Box<dyn FnOnce()>) {
    AFTER_DIRECTORY_CLEANUP.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(crate) fn set_after_checkout_commit_hook(hook: Box<dyn FnOnce()>) {
    AFTER_CHECKOUT_COMMIT.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_checkout_file_hook() {
    #[cfg(test)]
    AFTER_CHECKOUT_FILE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_after_checkout_directory_hook() {
    #[cfg(test)]
    AFTER_CHECKOUT_DIRECTORY.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_after_directory_cleanup_hook() {
    #[cfg(test)]
    AFTER_DIRECTORY_CLEANUP.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn run_after_checkout_commit_hook() {
    #[cfg(test)]
    AFTER_CHECKOUT_COMMIT.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[derive(Debug, Error)]
pub enum CheckoutError {
    #[error("native checkout path error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("encrypted Git catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned checkout metadata error: {0}")]
    Model(#[from] ModelError),
    #[error("Git branch or tree error: {0}")]
    History(#[from] HistoryError),
    #[error("Git status or tree read error: {0}")]
    Status(#[from] StatusError),
    #[error("Git index error: {0}")]
    Stage(#[from] StageError),
    #[error("Git HEAD record error: {0}")]
    Head(#[from] HeadError),
    #[error("Git blob verification error: {0}")]
    GitAnchor(#[from] GitAnchorError),
    #[error("Git object error: {0}")]
    Git(#[from] git2::Error),
    #[error("working-tree I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error(
        "the index, tracked files, or a destination contains changes that checkout would overwrite"
    )]
    DirtyWorktree,
    #[error("this checkout needs a file/directory topology transition or an unsupported Git mode")]
    UnsupportedTopology,
    #[error("the checkout intent or its staged files changed unexpectedly")]
    IncompatibleIntent,
    #[error("no same-filesystem verified anchor is available for a target Git blob")]
    MissingAnchor,
    #[error("the checkout contains too many changed files")]
    TooManyFiles,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum Phase {
    Preparing,
    Applying,
    Cleanup,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CheckoutFile {
    oid: [u8; 20],
    mode: u32,
    anchor_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CheckoutEntry {
    path: Vec<u8>,
    old: Option<CheckoutFile>,
    old_id: Option<NativeFileId>,
    new: Option<CheckoutFile>,
    new_id: Option<NativeFileId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CheckoutDirectory {
    path: Vec<u8>,
    staged_id: Option<NativeFileId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CheckoutRemovedDirectory {
    path: Vec<u8>,
    old_id: NativeFileId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CheckoutIntent {
    format_version: u16,
    repository_id: Uuid,
    old_branch: String,
    old_oid: [u8; 20],
    new_branch: String,
    new_oid: [u8; 20],
    staging_name: String,
    staging_id: Option<NativeFileId>,
    phase: Phase,
    entries: Vec<CheckoutEntry>,
    directories: Vec<CheckoutDirectory>,
    removed_directories: Vec<CheckoutRemovedDirectory>,
}

/// Version 1 intents may remain on disk after an interrupted older checkout.
#[derive(Serialize, Deserialize)]
struct LegacyCheckoutIntent {
    format_version: u16,
    repository_id: Uuid,
    old_branch: String,
    old_oid: [u8; 20],
    new_branch: String,
    new_oid: [u8; 20],
    staging_name: String,
    staging_id: Option<NativeFileId>,
    phase: Phase,
    entries: Vec<CheckoutEntry>,
}

impl From<LegacyCheckoutIntent> for CheckoutIntent {
    fn from(legacy: LegacyCheckoutIntent) -> Self {
        Self {
            format_version: legacy.format_version,
            repository_id: legacy.repository_id,
            old_branch: legacy.old_branch,
            old_oid: legacy.old_oid,
            new_branch: legacy.new_branch,
            new_oid: legacy.new_oid,
            staging_name: legacy.staging_name,
            staging_id: legacy.staging_id,
            phase: legacy.phase,
            entries: legacy.entries,
            directories: Vec::new(),
            removed_directories: Vec::new(),
        }
    }
}

fn intent_kind(repository_id: Uuid) -> String {
    format!("{INTENT_PREFIX}{repository_id}")
}

fn stage_name(index: usize) -> String {
    format!("file-{index:08x}")
}

fn directory_stage_name(index: usize) -> String {
    format!("dir-{index:08x}")
}

fn relative_path(bytes: &[u8]) -> Result<PathBuf, CheckoutError> {
    let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    stage_path_key(&path)?;
    Ok(path)
}

fn parent_and_name(
    root: &PinnedDirectory,
    path: &[u8],
) -> Result<(PinnedDirectory, OsString), CheckoutError> {
    let relative = relative_path(path)?;
    let parent = relative
        .parent()
        .ok_or(CheckoutError::UnsupportedTopology)?;
    let directory = if parent.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        root.open_descendant_directory(parent)
            .map_err(|_| CheckoutError::UnsupportedTopology)?
    };
    let name = relative
        .file_name()
        .ok_or(CheckoutError::UnsupportedTopology)?
        .to_os_string();
    Ok((directory, name))
}

fn parent_and_name_if_exists(
    root: &PinnedDirectory,
    path: &[u8],
) -> Result<Option<(PinnedDirectory, OsString)>, CheckoutError> {
    let relative = relative_path(path)?;
    let mut directory = root.try_clone()?;
    for component in relative
        .parent()
        .ok_or(CheckoutError::UnsupportedTopology)?
        .components()
    {
        let Component::Normal(name) = component else {
            return Err(CheckoutError::UnsupportedTopology);
        };
        let Some(next) = directory.open_child_directory(name)? else {
            return Ok(None);
        };
        directory = next;
    }
    let name = relative
        .file_name()
        .ok_or(CheckoutError::UnsupportedTopology)?
        .to_os_string();
    Ok(Some((directory, name)))
}

fn file_fingerprint(metadata: &Metadata) -> (u64, u64, u64, u32, i64, i64, i64, i64) {
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

fn verify_file(
    parent: &PinnedDirectory,
    name: &OsStr,
    identity: NativeFileId,
    expected: &CheckoutFile,
) -> Result<(), CheckoutError> {
    if parent.entry_identity(name, false)? != Some(identity) {
        return Err(CheckoutError::DirtyWorktree);
    }
    let file: File = parent
        .open_child_file(name)?
        .ok_or(CheckoutError::DirtyWorktree)?;
    let before = file.metadata()?;
    let mode = if before.mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    };
    if mode != expected.mode {
        return Err(CheckoutError::DirtyWorktree);
    }
    let descriptor = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let oid = Oid::hash_file(ObjectType::Blob, descriptor)?;
    if oid.as_bytes() != expected.oid
        || file_fingerprint(&before) != file_fingerprint(&file.metadata()?)
        || parent.entry_identity(name, false)? != Some(identity)
    {
        return Err(CheckoutError::DirtyWorktree);
    }
    Ok(())
}

fn verify_staged_directory(
    staging: &PinnedDirectory,
    name: &str,
) -> Result<NativeFileId, CheckoutError> {
    let directory = staging
        .open_child_directory(name)?
        .ok_or(CheckoutError::IncompatibleIntent)?;
    if directory.as_file().metadata()?.mode() & 0o777 != 0o755
        || fs::read_dir(directory.descriptor_path())?.next().is_some()
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    Ok(directory.identity()?)
}

fn validate_intent(intent: &CheckoutIntent, repository_id: Uuid) -> Result<(), CheckoutError> {
    if !matches!(intent.format_version, 1 | 2)
        || intent.repository_id != repository_id
        || intent.entries.len() > MAX_CHECKOUT_FILES
        || intent.directories.len() > MAX_CHECKOUT_FILES
        || intent.removed_directories.len() > MAX_CHECKOUT_FILES
        || intent.format_version == 1
            && (!intent.directories.is_empty() || !intent.removed_directories.is_empty())
        || intent.old_branch.len() > 1024
        || intent.new_branch.len() > 1024
        || !Branch::name_is_valid(&intent.old_branch)?
        || !Branch::name_is_valid(&intent.new_branch)?
        || intent.phase != Phase::Preparing && intent.staging_id.is_none()
        || !intent.staging_name.starts_with("checkout-")
        || Uuid::parse_str(&intent.staging_name["checkout-".len()..]).is_err()
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let mut paths = BTreeSet::new();
    for entry in &intent.entries {
        relative_path(&entry.path)?;
        if !paths.insert(&entry.path)
            || entry.old.is_none() && entry.new.is_none()
            || entry.old.is_some() != entry.old_id.is_some()
            || entry.phase_invalid(intent.phase)
        {
            return Err(CheckoutError::IncompatibleIntent);
        }
    }
    let mut previous = None::<&[u8]>;
    for directory in &intent.directories {
        relative_path(&directory.path)?;
        if previous.is_some_and(|path| path >= directory.path.as_slice())
            || intent.phase != Phase::Preparing && directory.staged_id.is_none()
        {
            return Err(CheckoutError::IncompatibleIntent);
        }
        previous = Some(&directory.path);
    }
    previous = None;
    for directory in &intent.removed_directories {
        relative_path(&directory.path)?;
        if previous.is_some_and(|path| path >= directory.path.as_slice()) {
            return Err(CheckoutError::IncompatibleIntent);
        }
        previous = Some(&directory.path);
    }
    Ok(())
}

impl CheckoutEntry {
    fn phase_invalid(&self, phase: Phase) -> bool {
        self.new.is_none() && self.new_id.is_some()
            || phase != Phase::Preparing && self.new.is_some() && self.new_id.is_none()
    }
}

fn encode_intent(intent: &CheckoutIntent) -> Result<Vec<u8>, CheckoutError> {
    validate_intent(intent, intent.repository_id)?;
    if intent.format_version == 1 {
        canonical_bytes(&LegacyCheckoutIntent {
            format_version: intent.format_version,
            repository_id: intent.repository_id,
            old_branch: intent.old_branch.clone(),
            old_oid: intent.old_oid,
            new_branch: intent.new_branch.clone(),
            new_oid: intent.new_oid,
            staging_name: intent.staging_name.clone(),
            staging_id: intent.staging_id,
            phase: intent.phase,
            entries: intent.entries.clone(),
        })
        .map_err(Into::into)
    } else {
        canonical_bytes(intent).map_err(Into::into)
    }
}

fn save_intent(control: &ControlStore, intent: &CheckoutIntent) -> Result<(), CheckoutError> {
    let encoded = encode_intent(intent)?;
    control.put_record(&intent_kind(intent.repository_id), INTENT_KEY, &encoded)?;
    Ok(())
}

fn load_intent(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Option<CheckoutIntent>, CheckoutError> {
    let Some(bytes) = control.get_record(&intent_kind(repository_id), INTENT_KEY)? else {
        return Ok(None);
    };
    Ok(Some(decode_intent(&bytes, repository_id)?))
}

fn decode_intent(bytes: &[u8], repository_id: Uuid) -> Result<CheckoutIntent, CheckoutError> {
    let intent: CheckoutIntent = match decode_canonical(bytes) {
        Ok(intent) => intent,
        Err(_) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntent>(bytes)?),
    };
    validate_intent(&intent, repository_id)?;
    Ok(intent)
}

fn target_branch_is_current(
    control: &ControlStore,
    intent: &CheckoutIntent,
) -> Result<bool, CheckoutError> {
    Ok(list_branches(control, intent.repository_id)?
        .iter()
        .any(|branch| {
            branch.current && branch.name == intent.new_branch && branch.oid == intent.new_oid
        }))
}

fn index_matches_tree(staged: &BTreeMap<Vec<u8>, GitIndexEntry>, tree: &TreeFiles) -> bool {
    staged.len() == tree.len()
        && tree.iter().all(|(path, (oid, mode))| {
            staged
                .get(path)
                .is_some_and(|entry| entry.oid == *oid && entry.mode == *mode)
        })
}

fn conflicting_topology(old: &TreeFiles, new: &TreeFiles) -> bool {
    fn has_ancestor(path: &[u8], other: &TreeFiles) -> bool {
        path.iter()
            .enumerate()
            .any(|(index, byte)| *byte == b'/' && other.contains_key(&path[..index]))
    }
    old.keys().any(|path| has_ancestor(path, new)) || new.keys().any(|path| has_ancestor(path, old))
}

fn parent_directory_paths(tree: &TreeFiles) -> Result<BTreeSet<Vec<u8>>, CheckoutError> {
    let mut parents = BTreeSet::new();
    for path in tree.keys() {
        let relative = relative_path(path)?;
        let mut prefix = PathBuf::new();
        for component in relative
            .parent()
            .ok_or(CheckoutError::UnsupportedTopology)?
            .components()
        {
            let Component::Normal(name) = component else {
                return Err(CheckoutError::UnsupportedTopology);
            };
            prefix.push(name);
            parents.insert(stage_path_key(&prefix)?);
        }
    }
    Ok(parents)
}

fn obsolete_directories(
    root: &PinnedDirectory,
    old: &TreeFiles,
    new: &TreeFiles,
) -> Result<Vec<CheckoutRemovedDirectory>, CheckoutError> {
    let target = parent_directory_paths(new)?;
    parent_directory_paths(old)?
        .difference(&target)
        .map(|path| {
            let old_id = root
                .entry_identity(relative_path(path)?, true)?
                .ok_or(CheckoutError::DirtyWorktree)?;
            Ok(CheckoutRemovedDirectory {
                path: path.clone(),
                old_id,
            })
        })
        .collect()
}

fn missing_target_directories(
    root: &PinnedDirectory,
    target: &TreeFiles,
) -> Result<Vec<CheckoutDirectory>, CheckoutError> {
    let mut missing = BTreeSet::new();
    for path in target.keys() {
        let relative = relative_path(path)?;
        let mut current = Some(root.try_clone()?);
        let mut prefix = PathBuf::new();
        for component in relative
            .parent()
            .ok_or(CheckoutError::UnsupportedTopology)?
            .components()
        {
            let Component::Normal(name) = component else {
                return Err(CheckoutError::UnsupportedTopology);
            };
            prefix.push(name);
            if let Some(directory) = &current {
                current = directory
                    .open_child_directory(name)
                    .map_err(|_| CheckoutError::DirtyWorktree)?;
            }
            if current.is_none() {
                missing.insert(stage_path_key(&prefix)?);
            }
        }
    }
    Ok(missing
        .into_iter()
        .map(|path| CheckoutDirectory {
            path,
            staged_id: None,
        })
        .collect())
}

fn choose_anchor(
    control: &ControlStore,
    repository_id: Uuid,
    oid: [u8; 20],
    filesystem_id: u64,
) -> Result<Uuid, CheckoutError> {
    let anchor = anchors_for_oid(control, repository_id, Oid::from_bytes(&oid)?)?
        .into_iter()
        .find(|anchor| anchor.area.filesystem_id == filesystem_id)
        .ok_or(CheckoutError::MissingAnchor)?;
    if blob_oid_from_anchor(&anchor)?.as_bytes() != oid {
        return Err(CheckoutError::MissingAnchor);
    }
    Ok(anchor.anchor_id)
}

pub(crate) fn begin_switch(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    name: &str,
) -> Result<GitBranchInfo, CheckoutError> {
    resume_pending_checkout(control, repository_id, root_path, catalog_dir)?;
    if has_pending_stages(control, repository_id)? {
        return Err(CheckoutError::DirtyWorktree);
    }
    let branches = list_branches(control, repository_id)?;
    let current = branches
        .iter()
        .find(|branch| branch.current)
        .ok_or(CheckoutError::IncompatibleIntent)?;
    let target = branches
        .iter()
        .find(|branch| branch.name == name)
        .ok_or(HistoryError::BranchNotFound)?;
    let old_tree = committed_files(control, repository_id)?;
    let new_tree = files_for_commit(control, repository_id, Some(Oid::from_bytes(&target.oid)?))?;
    if conflicting_topology(&old_tree, &new_tree) {
        return Err(CheckoutError::UnsupportedTopology);
    }
    let staged = staged_entries(control, repository_id)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if !index_matches_tree(&staged, &old_tree) {
        return Err(CheckoutError::DirtyWorktree);
    }
    let root = PinnedDirectory::open(root_path)?;
    let directories = missing_target_directories(&root, &new_tree)?;
    let removed_directories = obsolete_directories(&root, &old_tree, &new_tree)?;
    let missing_directory_paths = directories
        .iter()
        .map(|directory| directory.path.as_slice())
        .collect::<BTreeSet<_>>();
    if old_tree.len().max(new_tree.len()) > MAX_CHECKOUT_FILES {
        return Err(CheckoutError::TooManyFiles);
    }
    for (path, (oid, mode)) in &old_tree {
        if !matches!(mode, 0o100644 | 0o100755) {
            return Err(CheckoutError::UnsupportedTopology);
        }
        let (parent, leaf) = parent_and_name(&root, path)?;
        let identity = parent
            .entry_identity(&leaf, false)?
            .ok_or(CheckoutError::DirtyWorktree)?;
        verify_file(
            &parent,
            &leaf,
            identity,
            &CheckoutFile {
                oid: *oid,
                mode: *mode,
                anchor_id: staged[path].anchor_id,
            },
        )?;
    }
    let mut entries = Vec::new();
    for path in old_tree
        .keys()
        .chain(new_tree.keys())
        .cloned()
        .collect::<BTreeSet<_>>()
    {
        let old = old_tree.get(&path);
        let new = new_tree.get(&path);
        if old == new {
            continue;
        }
        let relative = relative_path(&path)?;
        let missing_parent = missing_directory_paths.contains(
            relative
                .parent()
                .ok_or(CheckoutError::UnsupportedTopology)?
                .as_os_str()
                .as_bytes(),
        );
        let existing_parent = if missing_parent {
            None
        } else {
            Some(parent_and_name(&root, &path)?)
        };
        let old_id = if old.is_some() {
            let (parent, leaf) = existing_parent
                .as_ref()
                .ok_or(CheckoutError::IncompatibleIntent)?;
            Some(
                parent
                    .entry_identity(leaf, false)?
                    .ok_or(CheckoutError::DirtyWorktree)?,
            )
        } else {
            if let Some((parent, leaf)) = &existing_parent
                && parent.entry_identity(leaf, false)?.is_some()
            {
                return Err(CheckoutError::DirtyWorktree);
            }
            None
        };
        let old_file = old.map(|(oid, mode)| CheckoutFile {
            oid: *oid,
            mode: *mode,
            anchor_id: staged[&path].anchor_id,
        });
        let new_file = new
            .map(|(oid, mode)| {
                if !matches!(mode, 0o100644 | 0o100755) {
                    return Err(CheckoutError::UnsupportedTopology);
                }
                Ok(CheckoutFile {
                    oid: *oid,
                    mode: *mode,
                    anchor_id: choose_anchor(
                        control,
                        repository_id,
                        *oid,
                        root.identity()?.filesystem_id,
                    )?,
                })
            })
            .transpose()?;
        entries.push(CheckoutEntry {
            path,
            old: old_file,
            old_id,
            new: new_file,
            new_id: None,
        });
    }
    if entries.is_empty() {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let mut intent = CheckoutIntent {
        format_version: 2,
        repository_id,
        old_branch: selected_branch(control, repository_id)?,
        old_oid: current.oid,
        new_branch: name.to_owned(),
        new_oid: target.oid,
        staging_name: format!("checkout-{}", Uuid::new_v4()),
        staging_id: None,
        phase: Phase::Preparing,
        entries,
        directories,
        removed_directories,
    };
    validate_intent(&intent, repository_id)?;
    if !control.put_record_if_absent(
        &intent_kind(repository_id),
        INTENT_KEY,
        &encode_intent(&intent)?,
    )? {
        return Err(CheckoutError::IncompatibleIntent);
    }
    apply_intent(control, &mut intent, &root, catalog_dir)?;
    Ok(GitBranchInfo {
        current: true,
        ..target.clone()
    })
}

pub(crate) fn resume_pending_checkout(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
) -> Result<(), CheckoutError> {
    let Some(mut intent) = load_intent(control, repository_id)? else {
        return Ok(());
    };
    let root = PinnedDirectory::open(root_path)?;
    apply_intent(control, &mut intent, &root, catalog_dir)
}

fn apply_intent(
    control: &ControlStore,
    intent: &mut CheckoutIntent,
    root: &PinnedDirectory,
    catalog: &PinnedDirectory,
) -> Result<(), CheckoutError> {
    let staging = match catalog.open_child_directory(&intent.staging_name)? {
        Some(staging) => staging,
        None if intent.staging_id.is_none() && intent.phase == Phase::Preparing => {
            let staging = catalog.create_child_directory(&intent.staging_name)?;
            catalog.sync_all()?;
            staging
        }
        None if intent.phase == Phase::Cleanup => {
            if !target_branch_is_current(control, intent)? {
                return Err(CheckoutError::IncompatibleIntent);
            }
            control.delete_record(&intent_kind(intent.repository_id), INTENT_KEY)?;
            return Ok(());
        }
        None => return Err(CheckoutError::IncompatibleIntent),
    };
    let staging_id = staging.identity()?;
    if let Some(expected) = intent.staging_id {
        if expected != staging_id {
            return Err(CheckoutError::IncompatibleIntent);
        }
    } else {
        intent.staging_id = Some(staging_id);
        save_intent(control, intent)?;
    }
    if intent.phase == Phase::Preparing {
        for index in 0..intent.entries.len() {
            let entry = &mut intent.entries[index];
            let Some(target) = &entry.new else {
                continue;
            };
            let name = stage_name(index);
            if let Some(identity) = staging.entry_identity(&name, false)? {
                verify_file(&staging, OsStr::new(&name), identity, target)?;
                if entry.new_id.is_some_and(|recorded| recorded != identity) {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                entry.new_id = Some(identity);
            } else {
                if entry.new_id.is_some() {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                let anchor =
                    anchors_for_oid(control, intent.repository_id, Oid::from_bytes(&target.oid)?)?
                        .into_iter()
                        .find(|anchor| anchor.anchor_id == target.anchor_id)
                        .ok_or(CheckoutError::MissingAnchor)?;
                staging.publish_reflink_child(&name, &anchor, target.mode)?;
                let identity = staging
                    .entry_identity(&name, false)?
                    .ok_or(CheckoutError::IncompatibleIntent)?;
                verify_file(&staging, OsStr::new(&name), identity, target)?;
                entry.new_id = Some(identity);
            }
            save_intent(control, intent)?;
        }
        for index in 0..intent.directories.len() {
            let directory = &mut intent.directories[index];
            let name = directory_stage_name(index);
            let staged_directory = match staging.open_child_directory(&name)? {
                Some(existing) => existing,
                None if directory.staged_id.is_none() => staging.create_child_directory(&name)?,
                None => return Err(CheckoutError::IncompatibleIntent),
            };
            if directory.staged_id.is_none() {
                if fs::read_dir(staged_directory.descriptor_path())?
                    .next()
                    .is_some()
                {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                staged_directory
                    .as_file()
                    .set_permissions(Permissions::from_mode(0o755))?;
                staged_directory.sync_all()?;
                staging.sync_all()?;
            }
            let identity = verify_staged_directory(&staging, &name)?;
            if directory
                .staged_id
                .is_some_and(|recorded| recorded != identity)
            {
                return Err(CheckoutError::IncompatibleIntent);
            }
            directory.staged_id = Some(identity);
            save_intent(control, intent)?;
        }
        intent.phase = Phase::Applying;
        save_intent(control, intent)?;
    }
    if intent.phase == Phase::Applying {
        let branches = list_branches(control, intent.repository_id)?;
        if !branches.iter().any(|branch| {
            branch.current && branch.name == intent.old_branch && branch.oid == intent.old_oid
        }) || !branches
            .iter()
            .any(|branch| branch.name == intent.new_branch && branch.oid == intent.new_oid)
        {
            return Err(CheckoutError::IncompatibleIntent);
        }
        for (index, directory) in intent.directories.iter().enumerate() {
            let (parent, leaf) = parent_and_name(root, &directory.path)?;
            let staged = directory_stage_name(index);
            let staged_id = directory
                .staged_id
                .ok_or(CheckoutError::IncompatibleIntent)?;
            let work_id = parent.entry_identity(&leaf, true)?;
            let private_id = staging.entry_identity(&staged, true)?;
            if work_id.is_none() && private_id == Some(staged_id) {
                verify_staged_directory(&staging, &staged)?;
                staging.move_child_directory_no_replace(&staged, staged_id, &parent, &leaf)?;
            } else if work_id != Some(staged_id) || private_id.is_some() {
                return Err(CheckoutError::DirtyWorktree);
            }
            run_after_checkout_directory_hook();
        }
        for (index, entry) in intent.entries.iter().enumerate() {
            let (parent, leaf) = parent_and_name(root, &entry.path)?;
            let staged = stage_name(index);
            let work_id = parent.entry_identity(&leaf, false)?;
            let staged_id = staging.entry_identity(&staged, false)?;
            match (&entry.old, entry.old_id, &entry.new, entry.new_id) {
                (Some(old), Some(old_id), Some(new), Some(new_id)) => {
                    if work_id == Some(old_id) && staged_id == Some(new_id) {
                        verify_file(&parent, &leaf, old_id, old)?;
                        verify_file(&staging, OsStr::new(&staged), new_id, new)?;
                        parent.exchange_child_files(&leaf, old_id, &staging, &staged, new_id)?;
                    } else if work_id != Some(new_id) || staged_id != Some(old_id) {
                        return Err(CheckoutError::DirtyWorktree);
                    }
                    verify_file(&parent, &leaf, new_id, new)?;
                    verify_file(&staging, OsStr::new(&staged), old_id, old)?;
                }
                (Some(old), Some(old_id), None, None) => {
                    if work_id == Some(old_id) && staged_id.is_none() {
                        verify_file(&parent, &leaf, old_id, old)?;
                        parent.move_child_file_no_replace(&leaf, old_id, &staging, &staged)?;
                    } else if work_id.is_some() || staged_id != Some(old_id) {
                        return Err(CheckoutError::DirtyWorktree);
                    }
                    verify_file(&staging, OsStr::new(&staged), old_id, old)?;
                }
                (None, None, Some(new), Some(new_id)) => {
                    if work_id.is_none() && staged_id == Some(new_id) {
                        verify_file(&staging, OsStr::new(&staged), new_id, new)?;
                        staging.move_child_file_no_replace(&staged, new_id, &parent, &leaf)?;
                    } else if work_id != Some(new_id) || staged_id.is_some() {
                        return Err(CheckoutError::DirtyWorktree);
                    }
                    verify_file(&parent, &leaf, new_id, new)?;
                }
                _ => return Err(CheckoutError::IncompatibleIntent),
            }
            run_after_checkout_file_hook();
        }
        // The target refs remain immutable while the daemon owns this intent.
        // Verify every target path once more before changing the visible HEAD.
        let target_files = files_for_commit(
            control,
            intent.repository_id,
            Some(Oid::from_bytes(&intent.new_oid)?),
        )?;
        for (path, (oid, mode)) in &target_files {
            let (parent, leaf) = parent_and_name(root, path)?;
            let identity = parent
                .entry_identity(&leaf, false)?
                .ok_or(CheckoutError::DirtyWorktree)?;
            verify_file(
                &parent,
                &leaf,
                identity,
                &CheckoutFile {
                    oid: *oid,
                    mode: *mode,
                    anchor_id: Uuid::nil(),
                },
            )?;
        }
        let mut records = Vec::new();
        let mut deletions = Vec::new();
        let previous_index = staged_entries(control, intent.repository_id)?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for (path, (oid, mode)) in &target_files {
            let anchor_id = match intent.entries.iter().find(|entry| entry.path == *path) {
                Some(entry) => {
                    entry
                        .new
                        .as_ref()
                        .ok_or(CheckoutError::IncompatibleIntent)?
                        .anchor_id
                }
                None => {
                    previous_index
                        .get(path)
                        .ok_or(CheckoutError::IncompatibleIntent)?
                        .anchor_id
                }
            };
            records.push((
                index_kind(intent.repository_id),
                path.clone(),
                canonical_bytes(&GitIndexEntry {
                    format_version: 1,
                    oid: *oid,
                    mode: *mode,
                    anchor_id,
                })?,
            ));
        }
        for (path, _) in previous_index {
            if !target_files.contains_key(&path) {
                deletions.push((index_kind(intent.repository_id), path));
            }
        }
        records.push(selected_branch_record(
            intent.repository_id,
            &intent.new_branch,
        )?);
        intent.phase = Phase::Cleanup;
        records.push((
            intent_kind(intent.repository_id),
            INTENT_KEY.to_vec(),
            encode_intent(intent)?,
        ));
        control.put_records_and_delete(&records, &deletions)?;
        run_after_checkout_commit_hook();
    }
    if intent.phase == Phase::Cleanup {
        if !target_branch_is_current(control, intent)? {
            return Err(CheckoutError::IncompatibleIntent);
        }
        for (index, _) in intent.directories.iter().enumerate() {
            if staging
                .entry_identity(directory_stage_name(index), true)?
                .is_some()
            {
                return Err(CheckoutError::IncompatibleIntent);
            }
        }
        for (index, entry) in intent.entries.iter().enumerate() {
            let staged = stage_name(index);
            if let Some(identity) = staging.entry_identity(&staged, false)? {
                if Some(identity) != entry.old_id {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                verify_file(
                    &staging,
                    OsStr::new(&staged),
                    identity,
                    entry
                        .old
                        .as_ref()
                        .ok_or(CheckoutError::IncompatibleIntent)?,
                )?;
                staging.remove_child_file(&staged)?;
            }
        }
        for directory in intent.removed_directories.iter().rev() {
            if let Some((parent, leaf)) = parent_and_name_if_exists(root, &directory.path)? {
                parent.remove_empty_child_directory(&leaf, directory.old_id)?;
            }
            run_after_directory_cleanup_hook();
        }
        catalog.remove_child_directory(&intent.staging_name, staging_id)?;
        catalog.sync_all()?;
        control.delete_record(&intent_kind(intent.repository_id), INTENT_KEY)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_checkout_intent_keeps_its_disk_format_during_replay() {
        let repository_id = Uuid::new_v4();
        let legacy = LegacyCheckoutIntent {
            format_version: 1,
            repository_id,
            old_branch: "main".to_owned(),
            old_oid: [1; 20],
            new_branch: "topic".to_owned(),
            new_oid: [2; 20],
            staging_name: format!("checkout-{}", Uuid::new_v4()),
            staging_id: None,
            phase: Phase::Preparing,
            entries: Vec::new(),
        };
        let original = canonical_bytes(&legacy).unwrap();
        let replayed = decode_intent(&original, repository_id).unwrap();
        assert_eq!(replayed.format_version, 1);
        assert!(replayed.directories.is_empty());
        assert!(replayed.removed_directories.is_empty());
        assert_eq!(encode_intent(&replayed).unwrap(), original);
    }
}
