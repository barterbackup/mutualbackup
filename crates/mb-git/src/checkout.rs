//! Crash-replayable checkout for files and symlinks. The selected HEAD and index
//! change together only after every target file is durably in the worktree.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, Permissions};
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use git2::{Branch, ObjectType, Oid};
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, NativeFileId, PinnedDirectory,
    PinnedEntryKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::head::{HeadError, selected_branch, selected_branch_record, selected_ref};
use crate::history::{
    GitBranchInfo, HistoryError, MergeIdentity, commit_descends_from, create_pathwise_merge_commit,
    fetched_ref_record, list_branches, merge_commit_parents, ref_kind, ref_oid,
};
use crate::stage::{
    GitIndexEntry, StageError, anchors_for_oid, has_pending_stages, index_kind, stage_path_key,
    staged_entries,
};
use crate::status::{StatusError, TreeFiles, files_for_commit, repository_status};
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
    #[error("the selected branch has no matching origin branch to pull")]
    MissingRemoteBranch,
    #[error("the selected branch has diverged from origin; pull requires a fast-forward")]
    NonFastForward,
    #[error("the requested merge branch does not exist")]
    MissingMergeBranch,
    #[error("a divergent merge needs an author name and email")]
    MissingMergeIdentity,
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
    advance_ref: bool,
    target_ref: Option<Vec<u8>>,
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

struct CheckoutTarget<'a> {
    old_branch: &'a str,
    old_oid: Option<Oid>,
    new_branch: &'a str,
    new_oid: Oid,
    advance_ref: bool,
    target_ref: Option<&'a [u8]>,
    merge_commit: bool,
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

/// Version 2 appended directory transitions after the version 1 fields.
#[derive(Serialize, Deserialize)]
struct LegacyCheckoutIntentV2 {
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

/// Version 3 added a selected-ref advance for pulls. Version 4 adds the
/// explicit source ref used by local fast-forward merges.
#[derive(Serialize, Deserialize)]
struct LegacyCheckoutIntentV3 {
    format_version: u16,
    advance_ref: bool,
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

impl From<LegacyCheckoutIntent> for CheckoutIntent {
    fn from(legacy: LegacyCheckoutIntent) -> Self {
        Self {
            format_version: legacy.format_version,
            advance_ref: false,
            target_ref: None,
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

impl From<LegacyCheckoutIntentV2> for CheckoutIntent {
    fn from(legacy: LegacyCheckoutIntentV2) -> Self {
        Self {
            format_version: legacy.format_version,
            advance_ref: false,
            target_ref: None,
            repository_id: legacy.repository_id,
            old_branch: legacy.old_branch,
            old_oid: legacy.old_oid,
            new_branch: legacy.new_branch,
            new_oid: legacy.new_oid,
            staging_name: legacy.staging_name,
            staging_id: legacy.staging_id,
            phase: legacy.phase,
            entries: legacy.entries,
            directories: legacy.directories,
            removed_directories: legacy.removed_directories,
        }
    }
}

impl From<LegacyCheckoutIntentV3> for CheckoutIntent {
    fn from(legacy: LegacyCheckoutIntentV3) -> Self {
        Self {
            format_version: legacy.format_version,
            advance_ref: legacy.advance_ref,
            target_ref: None,
            repository_id: legacy.repository_id,
            old_branch: legacy.old_branch,
            old_oid: legacy.old_oid,
            new_branch: legacy.new_branch,
            new_oid: legacy.new_oid,
            staging_name: legacy.staging_name,
            staging_id: legacy.staging_id,
            phase: legacy.phase,
            entries: legacy.entries,
            directories: legacy.directories,
            removed_directories: legacy.removed_directories,
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
        let next = match directory.open_child_directory(name) {
            Ok(Some(next)) => next,
            Ok(None) | Err(AnchorError::UnsupportedObject(_)) => return Ok(None),
            Err(error) => return Err(error.into()),
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

fn entry_kind(mode: u32) -> Result<PinnedEntryKind, CheckoutError> {
    match mode {
        0o100644 | 0o100755 => Ok(PinnedEntryKind::RegularFile),
        0o120000 => Ok(PinnedEntryKind::Symlink),
        _ => Err(CheckoutError::UnsupportedTopology),
    }
}

fn entry_identity_for(
    parent: &PinnedDirectory,
    name: &OsStr,
    mode: u32,
) -> Result<Option<NativeFileId>, CheckoutError> {
    let result = match entry_kind(mode)? {
        PinnedEntryKind::RegularFile => parent.entry_identity(name, false),
        PinnedEntryKind::Symlink => parent.symlink_identity(name),
    };
    match result {
        Ok(identity) => Ok(identity),
        Err(AnchorError::UnsupportedObject(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn entry_exists(parent: &PinnedDirectory, name: &OsStr) -> Result<bool, CheckoutError> {
    match parent.entry_identity(name, false) {
        Ok(Some(_)) | Err(AnchorError::UnsupportedObject(_)) => Ok(true),
        Ok(None) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn move_entry(
    source: &PinnedDirectory,
    source_name: &OsStr,
    identity: NativeFileId,
    destination: &PinnedDirectory,
    destination_name: &OsStr,
    mode: u32,
) -> Result<(), CheckoutError> {
    match entry_kind(mode)? {
        PinnedEntryKind::RegularFile => source.move_child_file_no_replace(
            source_name,
            identity,
            destination,
            destination_name,
        )?,
        PinnedEntryKind::Symlink => source.move_child_symlink_no_replace(
            source_name,
            identity,
            destination,
            destination_name,
        )?,
    }
    Ok(())
}

fn remove_staged_entry(
    staging: &PinnedDirectory,
    name: &OsStr,
    identity: NativeFileId,
    mode: u32,
) -> Result<(), CheckoutError> {
    match entry_kind(mode)? {
        PinnedEntryKind::RegularFile => staging.remove_child_file(name)?,
        PinnedEntryKind::Symlink => staging.remove_child_symlink(name, identity)?,
    }
    Ok(())
}

fn publish_staged_target(
    staging: &PinnedDirectory,
    name: &OsStr,
    anchor: &FileAnchorManifest,
    mode: u32,
) -> Result<(), CheckoutError> {
    match entry_kind(mode)? {
        PinnedEntryKind::RegularFile => staging.publish_reflink_child(name, anchor, mode)?,
        PinnedEntryKind::Symlink => {
            if anchor.logical_len == 0 || anchor.logical_len > 4095 {
                return Err(CheckoutError::UnsupportedTopology);
            }
            let mut bytes = Vec::with_capacity(anchor.logical_len as usize);
            anchor.open_verified()?.take(4096).read_to_end(&mut bytes)?;
            if bytes.len() as u64 != anchor.logical_len || bytes.contains(&0) {
                return Err(CheckoutError::IncompatibleIntent);
            }
            staging.publish_symlink_child(name, &bytes)?;
        }
    }
    Ok(())
}

fn verify_file(
    parent: &PinnedDirectory,
    name: &OsStr,
    identity: NativeFileId,
    expected: &CheckoutFile,
) -> Result<(), CheckoutError> {
    if entry_identity_for(parent, name, expected.mode)? != Some(identity) {
        return Err(CheckoutError::DirtyWorktree);
    }
    if expected.mode == 0o120000 {
        let (target, observed) = parent
            .read_child_symlink(name)?
            .ok_or(CheckoutError::DirtyWorktree)?;
        if observed != identity
            || Oid::hash_object(ObjectType::Blob, &target)?.as_bytes() != expected.oid
            || entry_identity_for(parent, name, expected.mode)? != Some(identity)
        {
            return Err(CheckoutError::DirtyWorktree);
        }
        return Ok(());
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
        || entry_identity_for(parent, name, expected.mode)? != Some(identity)
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

fn apply_old_deletion(
    root: &PinnedDirectory,
    staging: &PinnedDirectory,
    index: usize,
    entry: &CheckoutEntry,
) -> Result<(), CheckoutError> {
    let old = entry
        .old
        .as_ref()
        .ok_or(CheckoutError::IncompatibleIntent)?;
    let old_id = entry.old_id.ok_or(CheckoutError::IncompatibleIntent)?;
    let staged = stage_name(index);
    match entry_identity_for(staging, OsStr::new(&staged), old.mode)? {
        Some(identity) if identity == old_id => {
            verify_file(staging, OsStr::new(&staged), old_id, old)?;
            return Ok(());
        }
        Some(_) => return Err(CheckoutError::IncompatibleIntent),
        None => {}
    }
    let (parent, leaf) = parent_and_name(root, &entry.path)?;
    if entry_identity_for(&parent, &leaf, old.mode)? != Some(old_id) {
        return Err(CheckoutError::DirtyWorktree);
    }
    verify_file(&parent, &leaf, old_id, old)?;
    move_entry(
        &parent,
        &leaf,
        old_id,
        staging,
        OsStr::new(&staged),
        old.mode,
    )?;
    verify_file(staging, OsStr::new(&staged), old_id, old)?;
    Ok(())
}

fn path_at_or_below(path: &[u8], ancestor: &[u8]) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|tail| tail.starts_with(b"/"))
}

fn published_target_file(
    root: &PinnedDirectory,
    entry: &CheckoutEntry,
) -> Result<bool, CheckoutError> {
    let target = entry
        .new
        .as_ref()
        .ok_or(CheckoutError::IncompatibleIntent)?;
    let new_id = entry.new_id.ok_or(CheckoutError::IncompatibleIntent)?;
    let (parent, leaf) = parent_and_name(root, &entry.path)?;
    match entry_identity_for(&parent, &leaf, target.mode)? {
        Some(identity) if identity == new_id => {
            verify_file(&parent, &leaf, new_id, target)?;
            Ok(true)
        }
        None => Ok(false),
        Some(_) => Err(CheckoutError::DirtyWorktree),
    }
}

fn validate_intent(intent: &CheckoutIntent, repository_id: Uuid) -> Result<(), CheckoutError> {
    if !matches!(intent.format_version, 1..=6)
        || matches!(intent.format_version, 3 | 4 | 6) != intent.advance_ref
        || matches!(intent.format_version, 4 | 6) != intent.target_ref.is_some()
        || intent.format_version == 5
            && (intent.old_oid != [0; 20] || intent.old_branch == intent.new_branch)
        || intent.target_ref.as_ref().is_some_and(|reference| {
            let Ok(name) = std::str::from_utf8(reference) else {
                return true;
            };
            reference.len() > "refs/heads/".len() + 1024
                || !name.starts_with("refs/heads/")
                || !git2::Reference::is_valid_name(name)
        })
        || intent.advance_ref
            && (intent.old_branch != intent.new_branch || intent.old_oid == intent.new_oid)
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
    match intent.format_version {
        1 => canonical_bytes(&LegacyCheckoutIntent {
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
        .map_err(Into::into),
        2 => canonical_bytes(&LegacyCheckoutIntentV2 {
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
            directories: intent.directories.clone(),
            removed_directories: intent.removed_directories.clone(),
        })
        .map_err(Into::into),
        3 => canonical_bytes(&LegacyCheckoutIntentV3 {
            format_version: intent.format_version,
            advance_ref: intent.advance_ref,
            repository_id: intent.repository_id,
            old_branch: intent.old_branch.clone(),
            old_oid: intent.old_oid,
            new_branch: intent.new_branch.clone(),
            new_oid: intent.new_oid,
            staging_name: intent.staging_name.clone(),
            staging_id: intent.staging_id,
            phase: intent.phase,
            entries: intent.entries.clone(),
            directories: intent.directories.clone(),
            removed_directories: intent.removed_directories.clone(),
        })
        .map_err(Into::into),
        4..=6 => canonical_bytes(intent).map_err(Into::into),
        _ => Err(CheckoutError::IncompatibleIntent),
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
    // Postcard uses a one-byte varint for these small version numbers. Inspect
    // it before positional decoding; trying newer structs against old bytes
    // can silently shift fields or drop directory transition records.
    let intent = match bytes.first().copied() {
        Some(1) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntent>(bytes)?),
        Some(2) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntentV2>(bytes)?),
        Some(3) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntentV3>(bytes)?),
        Some(4..=6) => decode_canonical::<CheckoutIntent>(bytes)?,
        _ => return Err(CheckoutError::IncompatibleIntent),
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

fn preflight_blocking_directories(
    root: &PinnedDirectory,
    old: &TreeFiles,
    new: &TreeFiles,
    old_directories: &BTreeSet<Vec<u8>>,
) -> Result<(), CheckoutError> {
    for target_path in new.keys().filter(|path| old_directories.contains(*path)) {
        let mut stack = vec![(
            target_path.clone(),
            root.open_descendant_directory(relative_path(target_path)?)?,
        )];
        while let Some((prefix, directory)) = stack.pop() {
            for child in fs::read_dir(directory.descriptor_path())? {
                let name = child?.file_name();
                let mut path = prefix.clone();
                path.push(b'/');
                path.extend_from_slice(name.as_bytes());
                if old.contains_key(&path) {
                    continue;
                }
                if !old_directories.contains(&path) {
                    return Err(CheckoutError::DirtyWorktree);
                }
                let next = directory
                    .open_child_directory(&name)
                    .map_err(|_| CheckoutError::DirtyWorktree)?
                    .ok_or(CheckoutError::DirtyWorktree)?;
                stack.push((path, next));
            }
        }
    }
    Ok(())
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
    old: &TreeFiles,
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
            if old.contains_key(prefix.as_os_str().as_bytes()) {
                current = None;
            }
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
    let branches = list_branches(control, repository_id)?;
    let current = branches.iter().find(|branch| branch.current);
    let old_branch = selected_branch(control, repository_id)?;
    if current.is_none()
        && ref_oid(
            control,
            repository_id,
            &selected_ref(control, repository_id)?,
        )?
        .is_some()
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let target = branches
        .iter()
        .find(|branch| branch.name == name)
        .ok_or(HistoryError::BranchNotFound)?;
    begin_checkout_to(
        control,
        repository_id,
        root_path,
        catalog_dir,
        CheckoutTarget {
            old_branch: &old_branch,
            old_oid: current
                .map(|branch| Oid::from_bytes(&branch.oid))
                .transpose()?,
            new_branch: name,
            new_oid: Oid::from_bytes(&target.oid)?,
            advance_ref: false,
            target_ref: None,
            merge_commit: false,
        },
    )?;
    Ok(GitBranchInfo {
        current: true,
        ..target.clone()
    })
}

/// Advance the selected branch only when origin contains its current commit.
/// The target ref and all blob anchors must already have been fetched.
pub(crate) fn begin_pull(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
) -> Result<Oid, CheckoutError> {
    resume_pending_checkout(control, repository_id, root_path, catalog_dir)?;
    let branch = selected_branch(control, repository_id)?;
    let remote_ref = format!("refs/remotes/origin/{branch}");
    let target = ref_oid(control, repository_id, remote_ref.as_bytes())?
        .ok_or(CheckoutError::MissingRemoteBranch)?;
    let local_ref = selected_ref(control, repository_id)?;
    let old = ref_oid(control, repository_id, &local_ref)?;
    if let Some(old) = old {
        if old == target {
            return Ok(target);
        }
        if !commit_descends_from(control, repository_id, target, old)? {
            return Err(CheckoutError::NonFastForward);
        }
    }
    begin_checkout_to(
        control,
        repository_id,
        root_path,
        catalog_dir,
        CheckoutTarget {
            old_branch: &branch,
            old_oid: old,
            new_branch: &branch,
            new_oid: target,
            advance_ref: true,
            target_ref: None,
            merge_commit: false,
        },
    )?;
    Ok(target)
}

/// Merge a local branch. Existing, disjoint-path blobs can form a two-parent
/// commit without new payloads; checkout publishes it with a replayable intent.
pub(crate) fn begin_merge_branch(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    branch: &str,
    author_name: &str,
    author_email: &str,
) -> Result<Oid, CheckoutError> {
    resume_pending_checkout(control, repository_id, root_path, catalog_dir)?;
    if branch.len() > 1024 || !Branch::name_is_valid(branch)? {
        return Err(HistoryError::InvalidBranch.into());
    }
    let selected = selected_branch(control, repository_id)?;
    let local_ref = selected_ref(control, repository_id)?;
    let source_ref = format!("refs/heads/{branch}");
    let target = ref_oid(control, repository_id, source_ref.as_bytes())?
        .ok_or(CheckoutError::MissingMergeBranch)?;
    let old = ref_oid(control, repository_id, &local_ref)?;
    if let Some(old) = old {
        if old == target {
            return Ok(target);
        }
        if !commit_descends_from(control, repository_id, target, old)? {
            if commit_descends_from(control, repository_id, old, target)? {
                return Ok(old);
            }
            if author_name.is_empty() || author_email.is_empty() {
                return Err(CheckoutError::MissingMergeIdentity);
            }
            let status = repository_status(control, repository_id, root_path)?;
            if !status.changes.is_empty() || !status.pending_adds.is_empty() {
                return Err(CheckoutError::DirtyWorktree);
            }
            let message = format!("Merge branch '{branch}'");
            let merged = create_pathwise_merge_commit(
                control,
                repository_id,
                root_path,
                old,
                target,
                MergeIdentity {
                    name: author_name,
                    email: author_email,
                    message: &message,
                },
            )?;
            begin_checkout_to(
                control,
                repository_id,
                root_path,
                catalog_dir,
                CheckoutTarget {
                    old_branch: &selected,
                    old_oid: Some(old),
                    new_branch: &selected,
                    new_oid: merged,
                    advance_ref: true,
                    target_ref: Some(source_ref.as_bytes()),
                    merge_commit: true,
                },
            )?;
            return Ok(merged);
        }
    }
    begin_checkout_to(
        control,
        repository_id,
        root_path,
        catalog_dir,
        CheckoutTarget {
            old_branch: &selected,
            old_oid: old,
            new_branch: &selected,
            new_oid: target,
            advance_ref: true,
            target_ref: Some(source_ref.as_bytes()),
            merge_commit: false,
        },
    )?;
    Ok(target)
}

fn begin_checkout_to(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    target: CheckoutTarget<'_>,
) -> Result<(), CheckoutError> {
    if target.merge_commit {
        let old = target.old_oid.ok_or(CheckoutError::IncompatibleIntent)?;
        let source_ref = target.target_ref.ok_or(CheckoutError::IncompatibleIntent)?;
        let (first, second) = merge_commit_parents(control, repository_id, target.new_oid)?;
        if first != old || ref_oid(control, repository_id, source_ref)? != Some(second) {
            return Err(CheckoutError::IncompatibleIntent);
        }
    }
    if has_pending_stages(control, repository_id)? {
        return Err(CheckoutError::DirtyWorktree);
    }
    let old_tree = files_for_commit(control, repository_id, target.old_oid)?;
    let new_tree = files_for_commit(control, repository_id, Some(target.new_oid))?;
    let staged = staged_entries(control, repository_id)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if !index_matches_tree(&staged, &old_tree) {
        return Err(CheckoutError::DirtyWorktree);
    }
    let root = PinnedDirectory::open(root_path)?;
    let old_directory_paths = parent_directory_paths(&old_tree)?;
    preflight_blocking_directories(&root, &old_tree, &new_tree, &old_directory_paths)?;
    let directories = missing_target_directories(&root, &old_tree, &new_tree)?;
    let removed_directories = obsolete_directories(&root, &old_tree, &new_tree)?;
    let missing_directory_paths = directories
        .iter()
        .map(|directory| directory.path.as_slice())
        .collect::<BTreeSet<_>>();
    if old_tree.len().max(new_tree.len()) > MAX_CHECKOUT_FILES {
        return Err(CheckoutError::TooManyFiles);
    }
    for (path, (oid, mode)) in &old_tree {
        entry_kind(*mode)?;
        let (parent, leaf) = parent_and_name(&root, path)?;
        let identity =
            entry_identity_for(&parent, &leaf, *mode)?.ok_or(CheckoutError::DirtyWorktree)?;
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
        } else if old_directory_paths.contains(&path) {
            // A tracked directory occupies the destination until its old
            // children have been moved into private staging.
            None
        } else {
            Some(parent_and_name(&root, &path)?)
        };
        let old_id = if old.is_some() {
            let (parent, leaf) = existing_parent
                .as_ref()
                .ok_or(CheckoutError::IncompatibleIntent)?;
            Some(
                entry_identity_for(
                    parent,
                    leaf,
                    old.ok_or(CheckoutError::IncompatibleIntent)?.1,
                )?
                .ok_or(CheckoutError::DirtyWorktree)?,
            )
        } else {
            if let Some((parent, leaf)) = &existing_parent
                && entry_exists(parent, leaf)?
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
                entry_kind(*mode)?;
                Ok::<_, CheckoutError>(CheckoutFile {
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
    if entries.is_empty() && !target.advance_ref && target.old_oid.is_some() {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let mut intent = CheckoutIntent {
        format_version: if target.merge_commit {
            6
        } else if target.target_ref.is_some() {
            4
        } else if target.advance_ref {
            3
        } else if target.old_oid.is_none() {
            5
        } else {
            2
        },
        advance_ref: target.advance_ref,
        target_ref: target.target_ref.map(<[u8]>::to_vec),
        repository_id,
        old_branch: target.old_branch.to_owned(),
        old_oid: target
            .old_oid
            .map(|oid| oid.as_bytes().try_into().expect("SHA-1 OID"))
            .unwrap_or([0; 20]),
        new_branch: target.new_branch.to_owned(),
        new_oid: target.new_oid.as_bytes().try_into().expect("SHA-1 OID"),
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
    Ok(())
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
            if let Some(identity) = entry_identity_for(&staging, OsStr::new(&name), target.mode)? {
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
                publish_staged_target(&staging, OsStr::new(&name), &anchor, target.mode)?;
                let identity = entry_identity_for(&staging, OsStr::new(&name), target.mode)?
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
        let (old_current, target_available) = if intent.advance_ref {
            let local_ref = format!("refs/heads/{}", intent.old_branch);
            let remote_ref = format!("refs/remotes/origin/{}", intent.new_branch);
            let target_ref = intent
                .target_ref
                .as_deref()
                .unwrap_or(remote_ref.as_bytes());
            let old = ref_oid(control, intent.repository_id, local_ref.as_bytes())?;
            let expected_old = if intent.old_oid == [0; 20] {
                None
            } else {
                Some(Oid::from_bytes(&intent.old_oid)?)
            };
            let expected_target = if intent.format_version == 6 {
                let (first, second) = merge_commit_parents(
                    control,
                    intent.repository_id,
                    Oid::from_bytes(&intent.new_oid)?,
                )?;
                if Some(first) != expected_old {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                second
            } else {
                Oid::from_bytes(&intent.new_oid)?
            };
            (
                selected_branch(control, intent.repository_id)? == intent.old_branch
                    && old == expected_old,
                ref_oid(control, intent.repository_id, target_ref)? == Some(expected_target),
            )
        } else if intent.format_version == 5 {
            let old_ref = format!("refs/heads/{}", intent.old_branch);
            (
                selected_branch(control, intent.repository_id)? == intent.old_branch
                    && ref_oid(control, intent.repository_id, old_ref.as_bytes())?.is_none(),
                branches
                    .iter()
                    .any(|branch| branch.name == intent.new_branch && branch.oid == intent.new_oid),
            )
        } else {
            (
                branches.iter().any(|branch| {
                    branch.current
                        && branch.name == intent.old_branch
                        && branch.oid == intent.old_oid
                }),
                branches
                    .iter()
                    .any(|branch| branch.name == intent.new_branch && branch.oid == intent.new_oid),
            )
        };
        if !old_current || !target_available {
            return Err(CheckoutError::IncompatibleIntent);
        }
        let target_files = files_for_commit(
            control,
            intent.repository_id,
            Some(Oid::from_bytes(&intent.new_oid)?),
        )?;
        for (index, entry) in intent.entries.iter().enumerate() {
            if entry.new.is_none() {
                apply_old_deletion(root, &staging, index, entry)?;
                run_after_checkout_file_hook();
            }
        }
        for path in target_files.keys().filter(|path| {
            intent
                .removed_directories
                .iter()
                .any(|dir| dir.path == **path)
        }) {
            let entry = intent
                .entries
                .iter()
                .find(|entry| entry.path == *path)
                .ok_or(CheckoutError::IncompatibleIntent)?;
            if published_target_file(root, entry)? {
                continue;
            }
            for directory in intent
                .removed_directories
                .iter()
                .rev()
                .filter(|directory| path_at_or_below(&directory.path, path))
            {
                if let Some((parent, leaf)) = parent_and_name_if_exists(root, &directory.path)?
                    && !parent.remove_empty_child_directory(&leaf, directory.old_id)?
                {
                    match parent.open_child_directory(&leaf) {
                        Ok(None) => {}
                        _ => return Err(CheckoutError::DirtyWorktree),
                    }
                }
            }
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
            if entry.new.is_none() {
                continue;
            }
            let (parent, leaf) = parent_and_name(root, &entry.path)?;
            let staged = stage_name(index);
            match (&entry.old, entry.old_id, &entry.new, entry.new_id) {
                (Some(old), Some(old_id), Some(new), Some(new_id)) => {
                    let work_old = entry_identity_for(&parent, &leaf, old.mode)?;
                    let work_new = entry_identity_for(&parent, &leaf, new.mode)?;
                    let staged_old = entry_identity_for(&staging, OsStr::new(&staged), old.mode)?;
                    let staged_new = entry_identity_for(&staging, OsStr::new(&staged), new.mode)?;
                    if work_old == Some(old_id) && staged_new == Some(new_id) {
                        verify_file(&parent, &leaf, old_id, old)?;
                        verify_file(&staging, OsStr::new(&staged), new_id, new)?;
                        parent.exchange_child_entries(
                            &leaf,
                            (old_id, entry_kind(old.mode)?),
                            &staging,
                            &staged,
                            (new_id, entry_kind(new.mode)?),
                        )?;
                    } else if work_new != Some(new_id) || staged_old != Some(old_id) {
                        return Err(CheckoutError::DirtyWorktree);
                    }
                    verify_file(&parent, &leaf, new_id, new)?;
                    verify_file(&staging, OsStr::new(&staged), old_id, old)?;
                }
                (None, None, Some(new), Some(new_id)) => {
                    let work_id = entry_identity_for(&parent, &leaf, new.mode)?;
                    let staged_id = entry_identity_for(&staging, OsStr::new(&staged), new.mode)?;
                    if !entry_exists(&parent, &leaf)? && staged_id == Some(new_id) {
                        verify_file(&staging, OsStr::new(&staged), new_id, new)?;
                        move_entry(
                            &staging,
                            OsStr::new(&staged),
                            new_id,
                            &parent,
                            &leaf,
                            new.mode,
                        )?;
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
        for (path, (oid, mode)) in &target_files {
            let (parent, leaf) = parent_and_name(root, path)?;
            let identity =
                entry_identity_for(&parent, &leaf, *mode)?.ok_or(CheckoutError::DirtyWorktree)?;
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
        if intent.advance_ref {
            records.push((
                ref_kind(intent.repository_id),
                format!("refs/heads/{}", intent.new_branch).into_bytes(),
                fetched_ref_record(intent.new_oid)?,
            ));
        }
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
            let Some(old) = &entry.old else {
                if entry_exists(&staging, OsStr::new(&staged))? {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                continue;
            };
            if let Some(identity) = entry_identity_for(&staging, OsStr::new(&staged), old.mode)? {
                if Some(identity) != entry.old_id {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                verify_file(&staging, OsStr::new(&staged), identity, old)?;
                remove_staged_entry(&staging, OsStr::new(&staged), identity, old.mode)?;
            } else if entry_exists(&staging, OsStr::new(&staged))? {
                return Err(CheckoutError::IncompatibleIntent);
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

    #[test]
    fn version_two_checkout_intent_keeps_its_disk_format_during_replay() {
        #[derive(Serialize)]
        struct HistoricalVersionTwo<'a> {
            format_version: u16,
            repository_id: Uuid,
            old_branch: &'a str,
            old_oid: [u8; 20],
            new_branch: &'a str,
            new_oid: [u8; 20],
            staging_name: String,
            staging_id: Option<NativeFileId>,
            phase: Phase,
            entries: Vec<CheckoutEntry>,
            directories: Vec<CheckoutDirectory>,
            removed_directories: Vec<CheckoutRemovedDirectory>,
        }
        let repository_id = Uuid::new_v4();
        let previous = HistoricalVersionTwo {
            format_version: 2,
            repository_id,
            old_branch: "main",
            old_oid: [1; 20],
            new_branch: "topic",
            new_oid: [2; 20],
            staging_name: format!("checkout-{}", Uuid::new_v4()),
            staging_id: None,
            phase: Phase::Preparing,
            entries: Vec::new(),
            directories: vec![CheckoutDirectory {
                path: b"nested".to_vec(),
                staged_id: None,
            }],
            removed_directories: Vec::new(),
        };
        let original = canonical_bytes(&previous).unwrap();
        let replayed = decode_intent(&original, repository_id).unwrap();
        assert!(!replayed.advance_ref);
        assert!(replayed.target_ref.is_none());
        assert_eq!(replayed.directories.len(), 1);
        assert_eq!(encode_intent(&replayed).unwrap(), original);
    }

    #[test]
    fn version_three_pull_intent_keeps_its_disk_format_during_replay() {
        #[derive(Serialize)]
        struct HistoricalVersionThree<'a> {
            format_version: u16,
            advance_ref: bool,
            repository_id: Uuid,
            old_branch: &'a str,
            old_oid: [u8; 20],
            new_branch: &'a str,
            new_oid: [u8; 20],
            staging_name: String,
            staging_id: Option<NativeFileId>,
            phase: Phase,
            entries: Vec<CheckoutEntry>,
            directories: Vec<CheckoutDirectory>,
            removed_directories: Vec<CheckoutRemovedDirectory>,
        }
        let repository_id = Uuid::new_v4();
        let previous = HistoricalVersionThree {
            format_version: 3,
            advance_ref: true,
            repository_id,
            old_branch: "main",
            old_oid: [1; 20],
            new_branch: "main",
            new_oid: [2; 20],
            staging_name: format!("checkout-{}", Uuid::new_v4()),
            staging_id: None,
            phase: Phase::Preparing,
            entries: Vec::new(),
            directories: vec![CheckoutDirectory {
                path: b"nested".to_vec(),
                staged_id: None,
            }],
            removed_directories: Vec::new(),
        };
        let original = canonical_bytes(&previous).unwrap();
        let replayed = decode_intent(&original, repository_id).unwrap();
        assert!(replayed.advance_ref);
        assert!(replayed.target_ref.is_none());
        assert_eq!(replayed.directories.len(), 1);
        assert_eq!(encode_intent(&replayed).unwrap(), original);
    }
}
