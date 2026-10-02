//! Crash-replayable checkout and worktree restore for files and symlinks.
//! Checkout changes the selected HEAD and index together only after every
//! target file is durable; restore changes working files without moving either.

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
    PinnedEntryKind, SourceBackendKind,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::head::{
    HeadError, branch_selected_elsewhere, selected_branch, selected_branch_for_scope,
    selected_branch_record_for_scope, selected_ref, selected_ref_for_scope,
};
use crate::history::{
    GitBranchInfo, HistoryError, MergeIdentity, commit_descends_from, create_pathwise_merge_commit,
    fetched_ref_record, list_branches_for_scope, merge_commit_parents, ref_kind, ref_oid,
};
use crate::merge::{
    MergeBlobError, MergeSession, load_merge_session, session_key, session_kind,
    store_merge_session,
};
use crate::stage::{
    GitIndexEntry, StageError, anchors_for_oid, has_pending_stages_for_scope, index_kind_for_scope,
    indexed_anchor_manifest, stage_path_key, staged_entries, staged_entries_for_scope,
};
use crate::status::{StatusError, TreeFiles, files_for_commit, repository_status};
use crate::{GitAnchorError, GitWorktreeScope, NativeSource, blob_oid_from_anchor};

const INTENT_PREFIX: &str = "git-checkout-intent-v1/";
const WORKTREE_INTENT_PREFIX: &str = "git-worktree-checkout-intent-v1/";
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
    static AFTER_MISSING_CHECKOUT_STAGING_REMOVE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
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

#[cfg(test)]
pub(crate) fn set_after_missing_checkout_staging_remove_hook(hook: Box<dyn FnOnce()>) {
    AFTER_MISSING_CHECKOUT_STAGING_REMOVE.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_missing_checkout_staging_remove_hook() {
    #[cfg(test)]
    AFTER_MISSING_CHECKOUT_STAGING_REMOVE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
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
    #[error("Git merge state error: {0}")]
    MergeState(#[from] MergeBlobError),
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
    #[error("the requested merge branch does not exist")]
    MissingMergeBranch,
    #[error("the Git branch is selected by another worktree")]
    BranchCheckedOutElsewhere,
    #[error("a divergent merge or pull needs an author name and email")]
    MissingMergeIdentity,
    #[error("merge needs resolution for paths: {0:?}")]
    MergeConflicts(Vec<Vec<u8>>),
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

/// Linked worktrees use a separate namespace and bind each replayable intent
/// to its worktree ID. The primary worktree keeps the historical disk format.
#[derive(Serialize, Deserialize)]
struct LinkedCheckoutIntent {
    format_version: u16,
    worktree_id: Uuid,
    root_id: NativeFileId,
    checkout: CheckoutIntent,
}

struct CheckoutTarget<'a> {
    old_branch: &'a str,
    old_oid: Option<Oid>,
    new_branch: &'a str,
    new_oid: Oid,
    advance_ref: bool,
    target_ref: Option<&'a [u8]>,
    merge_commit: bool,
    resolved_paths: Option<&'a BTreeSet<Vec<u8>>>,
}

struct DivergentMerge<'a> {
    selected: &'a str,
    old: Oid,
    target: Oid,
    source_ref: &'a [u8],
    author_name: &'a str,
    author_email: &'a str,
    message: &'a str,
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

fn intent_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(INTENT_PREFIX, WORKTREE_INTENT_PREFIX)
}

pub(crate) fn has_pending_checkout_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<bool, CheckoutError> {
    Ok(control
        .get_record(&intent_kind_for_scope(scope), INTENT_KEY)?
        .is_some())
}

/// Discard only an interrupted initial checkout for a missing linked worktree.
/// Format 5 starts with an unborn HEAD, so its private staging directory holds
/// no pre-existing working bytes. A crash after directory removal can replay
/// this operation because the exact intent remains until the final deletion.
pub(crate) fn abandon_missing_initial_checkout_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_id: NativeFileId,
    target_branch: &str,
    catalog: &PinnedDirectory,
) -> Result<bool, CheckoutError> {
    if scope.worktree_id() == scope.repository_id() {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let kind = intent_kind_for_scope(scope);
    let Some(encoded) = control.get_record(&kind, INTENT_KEY)? else {
        return Ok(false);
    };
    let linked: LinkedCheckoutIntent = decode_canonical(&encoded)?;
    let intent = &linked.checkout;
    let unborn = format!("mutualbackup-init-{}", scope.worktree_id());
    if linked.format_version != 1
        || linked.worktree_id != scope.worktree_id()
        || linked.root_id != root_id
        || validate_intent(intent, scope.repository_id()).is_err()
        || intent.format_version != 5
        || intent.old_branch != unborn
        || intent.new_branch != target_branch
        || intent.old_oid != [0; 20]
        || intent.entries.iter().any(|entry| entry.old.is_some())
        || !intent.removed_directories.is_empty()
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    if let Some(staging) = catalog.open_child_directory(&intent.staging_name)? {
        let actual = staging.identity()?;
        if intent.staging_id.is_some_and(|expected| expected != actual) {
            return Err(CheckoutError::IncompatibleIntent);
        }
        catalog.remove_child_directory(&intent.staging_name, actual)?;
        catalog.sync_all()?;
    }
    run_after_missing_checkout_staging_remove_hook();
    control.delete_record_if_value(&kind, INTENT_KEY, &encoded)?;
    Ok(true)
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

pub(crate) fn parent_and_name_if_exists(
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
    source_backend: SourceBackendKind,
) -> Result<(), CheckoutError> {
    match entry_kind(mode)? {
        PinnedEntryKind::RegularFile => {
            source_backend.publish_checkout_file(staging, name, anchor, mode)?
        }
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

fn verify_file_with_anchor(
    control: &ControlStore,
    repository_id: Uuid,
    parent: &PinnedDirectory,
    name: &OsStr,
    identity: NativeFileId,
    expected: &CheckoutFile,
) -> Result<(), CheckoutError> {
    if expected.anchor_id.is_nil() {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let entry = GitIndexEntry {
        format_version: 1,
        oid: expected.oid,
        mode: expected.mode,
        anchor_id: expected.anchor_id,
    };
    let anchor = indexed_anchor_manifest(control, repository_id, &entry)?;
    verify_tracked_file_for_removal(parent, name, identity, expected.oid, expected.mode, &anchor)
}

fn verify_file_for_intent(
    control: &ControlStore,
    repository_id: Uuid,
    parent: &PinnedDirectory,
    name: &OsStr,
    identity: NativeFileId,
    expected: &CheckoutFile,
) -> Result<(), CheckoutError> {
    if expected.anchor_id.is_nil() {
        // Restore/reset can capture an existing working file that has no
        // native anchor. A future intent version must record its BLAKE3 root.
        verify_file(parent, name, identity, expected)
    } else {
        verify_file_with_anchor(control, repository_id, parent, name, identity, expected)
    }
}

pub(crate) fn verify_tracked_file_for_removal(
    parent: &PinnedDirectory,
    name: &OsStr,
    identity: NativeFileId,
    oid: [u8; 20],
    mode: u32,
    anchor: &FileAnchorManifest,
) -> Result<(), CheckoutError> {
    verify_file(
        parent,
        name,
        identity,
        &CheckoutFile {
            oid,
            mode,
            anchor_id: Uuid::nil(),
        },
    )?;
    if mode == 0o120000 {
        let (target, observed) = parent
            .read_child_symlink(name)?
            .ok_or(CheckoutError::DirtyWorktree)?;
        if observed != identity
            || target.len() as u64 != anchor.logical_len
            || blake3::hash(&target).as_bytes() != &anchor.content_hash
            || entry_identity_for(parent, name, mode)? != Some(identity)
        {
            return Err(CheckoutError::DirtyWorktree);
        }
        return Ok(());
    }
    let mut file = parent
        .open_child_file(name)?
        .ok_or(CheckoutError::DirtyWorktree)?;
    let before = file.metadata()?;
    if before.len() != anchor.logical_len {
        return Err(CheckoutError::DirtyWorktree);
    }
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    if hasher.finalize().as_bytes() != &anchor.content_hash
        || file_fingerprint(&before) != file_fingerprint(&file.metadata()?)
        || entry_identity_for(parent, name, mode)? != Some(identity)
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
    control: &ControlStore,
    repository_id: Uuid,
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
            verify_file_for_intent(
                control,
                repository_id,
                staging,
                OsStr::new(&staged),
                old_id,
                old,
            )?;
            return Ok(());
        }
        Some(_) => return Err(CheckoutError::IncompatibleIntent),
        None => {}
    }
    let (parent, leaf) = parent_and_name(root, &entry.path)?;
    if entry_identity_for(&parent, &leaf, old.mode)? != Some(old_id) {
        return Err(CheckoutError::DirtyWorktree);
    }
    verify_file_for_intent(control, repository_id, &parent, &leaf, old_id, old)?;
    move_entry(
        &parent,
        &leaf,
        old_id,
        staging,
        OsStr::new(&staged),
        old.mode,
    )?;
    verify_file_for_intent(
        control,
        repository_id,
        staging,
        OsStr::new(&staged),
        old_id,
        old,
    )?;
    Ok(())
}

fn path_at_or_below(path: &[u8], ancestor: &[u8]) -> bool {
    path == ancestor
        || path
            .strip_prefix(ancestor)
            .is_some_and(|tail| tail.starts_with(b"/"))
}

fn published_target_file(
    control: &ControlStore,
    repository_id: Uuid,
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
            verify_file_with_anchor(control, repository_id, &parent, &leaf, new_id, target)?;
            Ok(true)
        }
        None => Ok(false),
        Some(_) => Err(CheckoutError::DirtyWorktree),
    }
}

fn validate_intent(intent: &CheckoutIntent, repository_id: Uuid) -> Result<(), CheckoutError> {
    if !matches!(intent.format_version, 1..=8)
        || matches!(intent.format_version, 3 | 4 | 6) != intent.advance_ref
        || matches!(intent.format_version, 4 | 6) != intent.target_ref.is_some()
        || intent.format_version == 5
            && (intent.old_oid != [0; 20] || intent.old_branch == intent.new_branch)
        || matches!(intent.format_version, 7 | 8)
            && (intent.advance_ref
                || intent.target_ref.is_some()
                || intent.old_branch != intent.new_branch
                || intent.old_oid != intent.new_oid)
        || intent.target_ref.as_ref().is_some_and(|reference| {
            let Ok(name) = std::str::from_utf8(reference) else {
                return true;
            };
            let prefix = if intent.format_version == 6 && name.starts_with("refs/remotes/origin/") {
                "refs/remotes/origin/"
            } else {
                "refs/heads/"
            };
            reference.len() > prefix.len() + 1024
                || !name.starts_with(prefix)
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
        4..=8 => canonical_bytes(intent).map_err(Into::into),
        _ => Err(CheckoutError::IncompatibleIntent),
    }
}

fn encode_intent_for_scope(
    scope: GitWorktreeScope,
    root_id: NativeFileId,
    intent: &CheckoutIntent,
) -> Result<Vec<u8>, CheckoutError> {
    if scope.repository_id() != intent.repository_id {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let encoded = encode_intent(intent)?;
    if scope.worktree_id() == scope.repository_id() {
        Ok(encoded)
    } else {
        Ok(canonical_bytes(&LinkedCheckoutIntent {
            format_version: 1,
            worktree_id: scope.worktree_id(),
            root_id,
            checkout: intent.clone(),
        })?)
    }
}

fn save_intent(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_id: NativeFileId,
    intent: &CheckoutIntent,
) -> Result<(), CheckoutError> {
    let encoded = encode_intent_for_scope(scope, root_id, intent)?;
    control.put_record(&intent_kind_for_scope(scope), INTENT_KEY, &encoded)?;
    Ok(())
}

fn load_intent(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_id: NativeFileId,
) -> Result<Option<CheckoutIntent>, CheckoutError> {
    let Some(bytes) = control.get_record(&intent_kind_for_scope(scope), INTENT_KEY)? else {
        return Ok(None);
    };
    if scope.worktree_id() == scope.repository_id() {
        return Ok(Some(decode_intent(&bytes, scope.repository_id())?));
    }
    let linked: LinkedCheckoutIntent = decode_canonical(&bytes)?;
    if linked.format_version != 1
        || linked.worktree_id != scope.worktree_id()
        || linked.root_id != root_id
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    validate_intent(&linked.checkout, scope.repository_id())?;
    Ok(Some(linked.checkout))
}

fn decode_intent(bytes: &[u8], repository_id: Uuid) -> Result<CheckoutIntent, CheckoutError> {
    // Postcard uses a one-byte varint for these small version numbers. Inspect
    // it before positional decoding; trying newer structs against old bytes
    // can silently shift fields or drop directory transition records.
    let intent = match bytes.first().copied() {
        Some(1) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntent>(bytes)?),
        Some(2) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntentV2>(bytes)?),
        Some(3) => CheckoutIntent::from(decode_canonical::<LegacyCheckoutIntentV3>(bytes)?),
        Some(4..=8) => decode_canonical::<CheckoutIntent>(bytes)?,
        _ => return Err(CheckoutError::IncompatibleIntent),
    };
    validate_intent(&intent, repository_id)?;
    Ok(intent)
}

fn target_branch_is_current(
    control: &ControlStore,
    scope: GitWorktreeScope,
    intent: &CheckoutIntent,
) -> Result<bool, CheckoutError> {
    if matches!(intent.format_version, 7 | 8) {
        let selected = selected_branch_for_scope(control, scope)?;
        let current = ref_oid(
            control,
            intent.repository_id,
            format!("refs/heads/{selected}").as_bytes(),
        )?;
        let expected = (intent.new_oid != [0; 20])
            .then(|| Oid::from_bytes(&intent.new_oid))
            .transpose()?;
        return Ok(selected == intent.new_branch && current == expected);
    }
    Ok(list_branches_for_scope(control, scope)?
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

fn index_matches_checkout(
    staged: &BTreeMap<Vec<u8>, GitIndexEntry>,
    old_tree: &TreeFiles,
    new_tree: &TreeFiles,
    resolved: Option<&BTreeSet<Vec<u8>>>,
) -> bool {
    let Some(resolved) = resolved else {
        return index_matches_tree(staged, old_tree);
    };
    let mut expected = old_tree.clone();
    for path in resolved {
        if let Some(file) = new_tree.get(path) {
            expected.insert(path.clone(), *file);
        } else {
            expected.remove(path);
        }
    }
    index_matches_tree(staged, &expected)
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
    source_backend: SourceBackendKind,
) -> Result<GitBranchInfo, CheckoutError> {
    begin_switch_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        root_path,
        catalog_dir,
        name,
        source_backend,
    )
}

pub(crate) fn begin_switch_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    name: &str,
    source_backend: SourceBackendKind,
) -> Result<GitBranchInfo, CheckoutError> {
    let repository_id = scope.repository_id();
    resume_pending_checkout_for_scope(control, scope, root_path, catalog_dir, source_backend)?;
    if branch_selected_elsewhere(control, scope, name)? {
        return Err(CheckoutError::BranchCheckedOutElsewhere);
    }
    let branches = list_branches_for_scope(control, scope)?;
    let current = branches.iter().find(|branch| branch.current);
    let old_branch = selected_branch_for_scope(control, scope)?;
    if current.is_none()
        && ref_oid(
            control,
            repository_id,
            &selected_ref_for_scope(control, scope)?,
        )?
        .is_some()
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let target = branches
        .iter()
        .find(|branch| branch.name == name)
        .ok_or(HistoryError::BranchNotFound)?;
    begin_checkout_to_for_scope(
        control,
        scope,
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
            resolved_paths: None,
        },
        source_backend,
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
    source: NativeSource<'_>,
    catalog_dir: &PinnedDirectory,
    author_name: &str,
    author_email: &str,
) -> Result<Oid, CheckoutError> {
    let root_path = source.root;
    resume_pending_checkout(
        control,
        repository_id,
        root_path,
        catalog_dir,
        source.backend,
    )?;
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
            if commit_descends_from(control, repository_id, old, target)? {
                return Ok(old);
            }
            let message = format!("Merge remote-tracking branch 'origin/{branch}'");
            return begin_divergent_merge(
                control,
                repository_id,
                source,
                catalog_dir,
                DivergentMerge {
                    selected: &branch,
                    old,
                    target,
                    source_ref: remote_ref.as_bytes(),
                    author_name,
                    author_email,
                    message: &message,
                },
            );
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
            resolved_paths: None,
        },
        source.backend,
    )?;
    Ok(target)
}

/// Merge a local branch. Existing, disjoint-path blobs can form a two-parent
/// commit without new payloads; checkout publishes it with a replayable intent.
pub(crate) fn begin_merge_branch(
    control: &ControlStore,
    repository_id: Uuid,
    source: NativeSource<'_>,
    catalog_dir: &PinnedDirectory,
    branch: &str,
    author_name: &str,
    author_email: &str,
) -> Result<Oid, CheckoutError> {
    let root_path = source.root;
    resume_pending_checkout(
        control,
        repository_id,
        root_path,
        catalog_dir,
        source.backend,
    )?;
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
            let message = format!("Merge branch '{branch}'");
            return begin_divergent_merge(
                control,
                repository_id,
                source,
                catalog_dir,
                DivergentMerge {
                    selected: &selected,
                    old,
                    target,
                    source_ref: source_ref.as_bytes(),
                    author_name,
                    author_email,
                    message: &message,
                },
            );
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
            resolved_paths: None,
        },
        source.backend,
    )?;
    Ok(target)
}

fn begin_divergent_merge(
    control: &ControlStore,
    repository_id: Uuid,
    source: NativeSource<'_>,
    catalog_dir: &PinnedDirectory,
    merge: DivergentMerge<'_>,
) -> Result<Oid, CheckoutError> {
    let root_path = source.root;
    if merge.author_name.is_empty() || merge.author_email.is_empty() {
        return Err(CheckoutError::MissingMergeIdentity);
    }
    let status = repository_status(control, repository_id, root_path)?;
    if !status.changes.is_empty() || !status.pending_adds.is_empty() {
        return Err(CheckoutError::DirtyWorktree);
    }
    let merged = match create_pathwise_merge_commit(
        control,
        repository_id,
        source,
        merge.old,
        merge.target,
        MergeIdentity {
            name: merge.author_name,
            email: merge.author_email,
            message: merge.message,
        },
        None,
    ) {
        Ok(merged) => merged,
        Err(HistoryError::MergeConflicts(paths)) => {
            store_merge_session(
                control,
                &MergeSession {
                    format_version: 1,
                    repository_id,
                    branch: merge.selected.to_owned(),
                    ours: merge.old.as_bytes().try_into().expect("SHA-1 OID"),
                    theirs: merge.target.as_bytes().try_into().expect("SHA-1 OID"),
                    source_ref: merge.source_ref.to_vec(),
                    author_name: merge.author_name.to_owned(),
                    author_email: merge.author_email.to_owned(),
                    message: merge.message.to_owned(),
                    conflicts: paths.clone(),
                    resolved: Vec::new(),
                },
            )?;
            return Err(CheckoutError::MergeConflicts(paths));
        }
        Err(error) => return Err(error.into()),
    };
    begin_checkout_to(
        control,
        repository_id,
        root_path,
        catalog_dir,
        CheckoutTarget {
            old_branch: merge.selected,
            old_oid: Some(merge.old),
            new_branch: merge.selected,
            new_oid: merged,
            advance_ref: true,
            target_ref: Some(merge.source_ref),
            merge_commit: true,
            resolved_paths: None,
        },
        source.backend,
    )?;
    Ok(merged)
}

pub(crate) fn continue_merge(
    control: &ControlStore,
    repository_id: Uuid,
    source: NativeSource<'_>,
    catalog_dir: &PinnedDirectory,
) -> Result<Oid, CheckoutError> {
    let root_path = source.root;
    resume_pending_checkout(
        control,
        repository_id,
        root_path,
        catalog_dir,
        source.backend,
    )?;
    let (session, _) =
        load_merge_session(control, repository_id)?.ok_or(MergeBlobError::MissingSession)?;
    let branch = selected_branch(control, repository_id)?;
    let ours = Oid::from_bytes(&session.ours)?;
    let theirs = Oid::from_bytes(&session.theirs)?;
    if branch != session.branch
        || ref_oid(
            control,
            repository_id,
            &selected_ref(control, repository_id)?,
        )? != Some(ours)
        || ref_oid(control, repository_id, &session.source_ref)? != Some(theirs)
    {
        return Err(CheckoutError::IncompatibleIntent);
    }
    if session.conflicts.len() != session.resolved.len() {
        return Err(CheckoutError::MergeConflicts(
            session
                .conflicts
                .iter()
                .filter(|path| session.resolved.binary_search(path).is_err())
                .cloned()
                .collect(),
        ));
    }
    let staged = staged_entries(control, repository_id)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let mut resolutions = BTreeMap::new();
    let mut resolved_paths = BTreeSet::new();
    for path in &session.conflicts {
        resolutions.insert(path.clone(), staged.get(path).cloned());
        resolved_paths.insert(path.clone());
    }
    let merged = create_pathwise_merge_commit(
        control,
        repository_id,
        source,
        ours,
        theirs,
        MergeIdentity {
            name: &session.author_name,
            email: &session.author_email,
            message: &session.message,
        },
        Some(&resolutions),
    )?;
    begin_checkout_to(
        control,
        repository_id,
        root_path,
        catalog_dir,
        CheckoutTarget {
            old_branch: &branch,
            old_oid: Some(ours),
            new_branch: &branch,
            new_oid: merged,
            advance_ref: true,
            target_ref: Some(&session.source_ref),
            merge_commit: true,
            resolved_paths: Some(&resolved_paths),
        },
        source.backend,
    )?;
    Ok(merged)
}

fn begin_checkout_to(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    target: CheckoutTarget<'_>,
    source_backend: SourceBackendKind,
) -> Result<(), CheckoutError> {
    begin_checkout_to_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        root_path,
        catalog_dir,
        target,
        source_backend,
    )
}

fn begin_checkout_to_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    target: CheckoutTarget<'_>,
    source_backend: SourceBackendKind,
) -> Result<(), CheckoutError> {
    let repository_id = scope.repository_id();
    if target.merge_commit {
        let old = target.old_oid.ok_or(CheckoutError::IncompatibleIntent)?;
        let source_ref = target.target_ref.ok_or(CheckoutError::IncompatibleIntent)?;
        let (first, second) = merge_commit_parents(control, repository_id, target.new_oid)?;
        if first != old || ref_oid(control, repository_id, source_ref)? != Some(second) {
            return Err(CheckoutError::IncompatibleIntent);
        }
    }
    if has_pending_stages_for_scope(control, scope)? {
        return Err(CheckoutError::DirtyWorktree);
    }
    let old_tree = files_for_commit(control, repository_id, target.old_oid)?;
    let new_tree = files_for_commit(control, repository_id, Some(target.new_oid))?;
    let staged = staged_entries_for_scope(control, scope)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if !index_matches_checkout(&staged, &old_tree, &new_tree, target.resolved_paths) {
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
    for (path, (old_oid, old_mode)) in &old_tree {
        let resolved = target
            .resolved_paths
            .is_some_and(|paths| paths.contains(path));
        if resolved && !new_tree.contains_key(path) {
            if let Some((parent, leaf)) = parent_and_name_if_exists(&root, path)?
                && entry_exists(&parent, &leaf)?
            {
                return Err(CheckoutError::DirtyWorktree);
            }
            continue;
        }
        let (oid, mode) = if resolved {
            *new_tree
                .get(path)
                .ok_or(CheckoutError::IncompatibleIntent)?
        } else {
            (*old_oid, *old_mode)
        };
        entry_kind(mode)?;
        let (parent, leaf) = parent_and_name(&root, path)?;
        let identity =
            entry_identity_for(&parent, &leaf, mode)?.ok_or(CheckoutError::DirtyWorktree)?;
        verify_file_with_anchor(
            control,
            repository_id,
            &parent,
            &leaf,
            identity,
            &CheckoutFile {
                oid,
                mode,
                anchor_id: staged[path].anchor_id,
            },
        )?;
    }
    if let Some(paths) = target.resolved_paths {
        for path in paths.iter().filter(|path| !old_tree.contains_key(*path)) {
            let Some((oid, mode)) = new_tree.get(path) else {
                if let Some((parent, leaf)) = parent_and_name_if_exists(&root, path)?
                    && entry_exists(&parent, &leaf)?
                {
                    return Err(CheckoutError::DirtyWorktree);
                }
                continue;
            };
            let (parent, leaf) = parent_and_name(&root, path)?;
            let identity =
                entry_identity_for(&parent, &leaf, *mode)?.ok_or(CheckoutError::DirtyWorktree)?;
            verify_file_with_anchor(
                control,
                repository_id,
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
        if target
            .resolved_paths
            .is_some_and(|paths| paths.contains(&path))
        {
            continue;
        }
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
    if !source_backend.supports_git_checkout_file()
        && entries.iter().any(|entry| {
            entry
                .new
                .as_ref()
                .is_some_and(|file| matches!(file.mode, 0o100644 | 0o100755))
        })
    {
        return Err(AnchorError::UnsupportedSourceOperation(
            "Git regular-file checkout with guarded link-freeze",
        )
        .into());
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
        &intent_kind_for_scope(scope),
        INTENT_KEY,
        &encode_intent_for_scope(scope, root.identity()?, &intent)?,
    )? {
        return Err(CheckoutError::IncompatibleIntent);
    }
    apply_intent(
        control,
        scope,
        &mut intent,
        &root,
        catalog_dir,
        source_backend,
    )?;
    Ok(())
}

fn captured_worktree_file(
    root: &PinnedDirectory,
    path: &[u8],
) -> Result<Option<(CheckoutFile, NativeFileId)>, CheckoutError> {
    let Some((parent, leaf)) = parent_and_name_if_exists(root, path)? else {
        return Ok(None);
    };
    if let Some(identity) = entry_identity_for(&parent, &leaf, 0o100644)? {
        let file = parent
            .open_child_file(&leaf)?
            .ok_or(CheckoutError::DirtyWorktree)?;
        let before = file.metadata()?;
        let mode = if before.mode() & 0o111 != 0 {
            0o100755
        } else {
            0o100644
        };
        let oid = Oid::hash_file(
            ObjectType::Blob,
            PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd())),
        )?;
        if file_fingerprint(&before) != file_fingerprint(&file.metadata()?) {
            return Err(CheckoutError::DirtyWorktree);
        }
        let captured = CheckoutFile {
            oid: oid.as_bytes().try_into().expect("SHA-1 OID"),
            mode,
            anchor_id: Uuid::nil(),
        };
        verify_file(&parent, &leaf, identity, &captured)?;
        return Ok(Some((captured, identity)));
    }
    let symlink = match parent.read_child_symlink(&leaf) {
        Ok(symlink) => symlink,
        Err(AnchorError::UnsupportedObject(_)) => None,
        Err(error) => return Err(error.into()),
    };
    if let Some((target, identity)) = symlink {
        let captured = CheckoutFile {
            oid: Oid::hash_object(ObjectType::Blob, &target)?
                .as_bytes()
                .try_into()
                .expect("SHA-1 OID"),
            mode: 0o120000,
            anchor_id: Uuid::nil(),
        };
        verify_file(&parent, &leaf, identity, &captured)?;
        return Ok(Some((captured, identity)));
    }
    Ok(None)
}

/// Restore selected paths from the index without moving HEAD or changing the
/// index. Dirty working bytes are fingerprinted before the replayable intent is
/// installed, then checked again before any replacement is published.
pub(crate) fn begin_restore_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    paths: &[PathBuf],
    source_backend: SourceBackendKind,
) -> Result<u32, CheckoutError> {
    begin_index_or_head_restore(
        control,
        scope,
        root_path,
        catalog_dir,
        paths,
        false,
        source_backend,
    )
}

/// Reset the whole working tree and index to the selected HEAD. One intent
/// publishes the index only after all tracked working bytes have been placed.
pub(crate) fn begin_hard_reset_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    source_backend: SourceBackendKind,
) -> Result<u32, CheckoutError> {
    begin_index_or_head_restore(
        control,
        scope,
        root_path,
        catalog_dir,
        &[],
        true,
        source_backend,
    )
}

fn begin_index_or_head_restore(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    paths: &[PathBuf],
    hard_reset: bool,
    source_backend: SourceBackendKind,
) -> Result<u32, CheckoutError> {
    let repository_id = scope.repository_id();
    resume_pending_checkout_for_scope(control, scope, root_path, catalog_dir, source_backend)?;
    if has_pending_stages_for_scope(control, scope)? {
        return Err(CheckoutError::DirtyWorktree);
    }
    let branch = selected_branch_for_scope(control, scope)?;
    let head = ref_oid(
        control,
        repository_id,
        format!("refs/heads/{branch}").as_bytes(),
    )?;
    let committed = files_for_commit(control, repository_id, head)?;
    let staged = staged_entries_for_scope(control, scope)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    let available = committed
        .keys()
        .chain(staged.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut selected = if hard_reset {
        available.clone()
    } else {
        BTreeSet::new()
    };
    for path in paths {
        let key = stage_path_key(path)?;
        let mut prefix = key.clone();
        prefix.push(b'/');
        let matches = available
            .iter()
            .filter(|candidate| *candidate == &key || candidate.starts_with(&prefix))
            .cloned()
            .collect::<Vec<_>>();
        if matches.is_empty() {
            return Err(StageError::MissingUntrackedPath.into());
        }
        selected.extend(matches);
    }
    if selected.len() > MAX_CHECKOUT_FILES {
        return Err(CheckoutError::TooManyFiles);
    }
    let root = PinnedDirectory::open(root_path)?;
    let mut old_files = BTreeMap::new();
    let mut old_tree = TreeFiles::new();
    let mut target_tree = TreeFiles::new();
    for path in &selected {
        if let Some((file, identity)) = captured_worktree_file(&root, path)? {
            old_tree.insert(path.clone(), (file.oid, file.mode));
            old_files.insert(path.clone(), (file, identity));
        }
        let target = if hard_reset {
            committed.get(path).copied()
        } else {
            staged.get(path).map(|index| (index.oid, index.mode))
        };
        if let Some((oid, mode)) = target {
            entry_kind(mode)?;
            target_tree.insert(path.clone(), (oid, mode));
        }
    }
    let old_directories = parent_directory_paths(&old_tree)?;
    for path in &selected {
        if old_files.contains_key(path) {
            continue;
        }
        if let Some((parent, leaf)) = parent_and_name_if_exists(&root, path)?
            && entry_exists(&parent, &leaf)?
            && !old_directories.contains(path)
        {
            return Err(CheckoutError::DirtyWorktree);
        }
    }
    preflight_blocking_directories(&root, &old_tree, &target_tree, &old_directories)?;
    let directories = missing_target_directories(&root, &old_tree, &target_tree)?;
    let removed_directories = obsolete_directories(&root, &old_tree, &target_tree)?;
    let missing_directories = directories
        .iter()
        .map(|directory| directory.path.as_slice())
        .collect::<BTreeSet<_>>();
    let mut entries = Vec::new();
    for path in selected {
        let old = old_files.get(&path);
        let new = target_tree.get(&path);
        if old.is_some_and(|(file, _)| {
            new.is_some_and(|(oid, mode)| *oid == file.oid && *mode == file.mode)
        }) || old.is_none() && new.is_none()
        {
            continue;
        }
        let relative = relative_path(&path)?;
        let parent = relative
            .parent()
            .ok_or(CheckoutError::UnsupportedTopology)?;
        let new_parent_is_missing = missing_directories.contains(parent.as_os_str().as_bytes());
        if old.is_none()
            && new.is_some()
            && !new_parent_is_missing
            && !old_directories.contains(&path)
            && let Some((directory, leaf)) = parent_and_name_if_exists(&root, &path)?
            && entry_exists(&directory, &leaf)?
        {
            return Err(CheckoutError::DirtyWorktree);
        }
        let new_file = new
            .map(|(oid, mode)| {
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
            old: old.map(|(file, _)| file.clone()),
            old_id: old.map(|(_, identity)| *identity),
            new: new_file,
            new_id: None,
        });
    }
    let index_changes = if hard_reset {
        available
            .iter()
            .filter(|path| {
                committed.get(*path).copied()
                    != staged.get(*path).map(|entry| (entry.oid, entry.mode))
            })
            .cloned()
            .collect::<BTreeSet<_>>()
    } else {
        BTreeSet::new()
    };
    if entries.is_empty() && index_changes.is_empty() {
        return Ok(0);
    }
    let changed = u32::try_from(
        entries
            .iter()
            .map(|entry| &entry.path)
            .chain(index_changes.iter())
            .collect::<BTreeSet<_>>()
            .len(),
    )
    .map_err(|_| CheckoutError::TooManyFiles)?;
    let oid = head
        .map(|oid| oid.as_bytes().try_into().expect("SHA-1 OID"))
        .unwrap_or([0; 20]);
    let mut intent = CheckoutIntent {
        format_version: if hard_reset { 8 } else { 7 },
        advance_ref: false,
        target_ref: None,
        repository_id,
        old_branch: branch.clone(),
        old_oid: oid,
        new_branch: branch,
        new_oid: oid,
        staging_name: format!("checkout-{}", Uuid::new_v4()),
        staging_id: None,
        phase: Phase::Preparing,
        entries,
        directories,
        removed_directories,
    };
    validate_intent(&intent, repository_id)?;
    if !control.put_record_if_absent(
        &intent_kind_for_scope(scope),
        INTENT_KEY,
        &encode_intent_for_scope(scope, root.identity()?, &intent)?,
    )? {
        return Err(CheckoutError::IncompatibleIntent);
    }
    apply_intent(
        control,
        scope,
        &mut intent,
        &root,
        catalog_dir,
        source_backend,
    )?;
    Ok(changed)
}

pub(crate) fn resume_pending_checkout(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    source_backend: SourceBackendKind,
) -> Result<(), CheckoutError> {
    resume_pending_checkout_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        root_path,
        catalog_dir,
        source_backend,
    )
}

pub(crate) fn resume_pending_checkout_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    catalog_dir: &PinnedDirectory,
    source_backend: SourceBackendKind,
) -> Result<(), CheckoutError> {
    let root = PinnedDirectory::open(root_path)?;
    let Some(mut intent) = load_intent(control, scope, root.identity()?)? else {
        return Ok(());
    };
    apply_intent(
        control,
        scope,
        &mut intent,
        &root,
        catalog_dir,
        source_backend,
    )
}

fn apply_intent(
    control: &ControlStore,
    scope: GitWorktreeScope,
    intent: &mut CheckoutIntent,
    root: &PinnedDirectory,
    catalog: &PinnedDirectory,
    source_backend: SourceBackendKind,
) -> Result<(), CheckoutError> {
    if intent.repository_id != scope.repository_id() {
        return Err(CheckoutError::IncompatibleIntent);
    }
    let existing_staging = catalog.open_child_directory(&intent.staging_name)?;
    if intent.phase == Phase::Preparing && !source_backend.supports_git_checkout_file() {
        for (index, entry) in intent.entries.iter().enumerate() {
            let Some(target) = entry.new.as_ref() else {
                continue;
            };
            if !matches!(target.mode, 0o100644 | 0o100755) || entry.new_id.is_some() {
                continue;
            }
            let Some(staging) = existing_staging.as_ref() else {
                return Err(AnchorError::UnsupportedSourceOperation(
                    "Git regular-file checkout with guarded link-freeze",
                )
                .into());
            };
            if entry_identity_for(staging, OsStr::new(&stage_name(index)), target.mode)?.is_none() {
                return Err(AnchorError::UnsupportedSourceOperation(
                    "Git regular-file checkout with guarded link-freeze",
                )
                .into());
            }
        }
    }
    let staging = match existing_staging {
        Some(staging) => staging,
        None if intent.staging_id.is_none() && intent.phase == Phase::Preparing => {
            let staging = catalog.create_child_directory(&intent.staging_name)?;
            catalog.sync_all()?;
            staging
        }
        None if intent.phase == Phase::Cleanup => {
            if !target_branch_is_current(control, scope, intent)? {
                return Err(CheckoutError::IncompatibleIntent);
            }
            control.delete_record(&intent_kind_for_scope(scope), INTENT_KEY)?;
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
        save_intent(control, scope, root.identity()?, intent)?;
    }
    if intent.phase == Phase::Preparing {
        for index in 0..intent.entries.len() {
            let entry = &mut intent.entries[index];
            let Some(target) = &entry.new else {
                continue;
            };
            let name = stage_name(index);
            if let Some(identity) = entry_identity_for(&staging, OsStr::new(&name), target.mode)? {
                verify_file_with_anchor(
                    control,
                    intent.repository_id,
                    &staging,
                    OsStr::new(&name),
                    identity,
                    target,
                )?;
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
                publish_staged_target(
                    &staging,
                    OsStr::new(&name),
                    &anchor,
                    target.mode,
                    source_backend,
                )?;
                let identity = entry_identity_for(&staging, OsStr::new(&name), target.mode)?
                    .ok_or(CheckoutError::IncompatibleIntent)?;
                verify_file_with_anchor(
                    control,
                    intent.repository_id,
                    &staging,
                    OsStr::new(&name),
                    identity,
                    target,
                )?;
                entry.new_id = Some(identity);
            }
            save_intent(control, scope, root.identity()?, intent)?;
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
            save_intent(control, scope, root.identity()?, intent)?;
        }
        intent.phase = Phase::Applying;
        save_intent(control, scope, root.identity()?, intent)?;
    }
    if intent.phase == Phase::Applying {
        if branch_selected_elsewhere(control, scope, &intent.new_branch)? {
            return Err(CheckoutError::BranchCheckedOutElsewhere);
        }
        let branches = list_branches_for_scope(control, scope)?;
        let (old_current, target_available) = if matches!(intent.format_version, 7 | 8) {
            let current = target_branch_is_current(control, scope, intent)?;
            (current, current)
        } else if intent.advance_ref {
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
                selected_branch_for_scope(control, scope)? == intent.old_branch
                    && old == expected_old,
                ref_oid(control, intent.repository_id, target_ref)? == Some(expected_target),
            )
        } else if intent.format_version == 5 {
            let old_ref = format!("refs/heads/{}", intent.old_branch);
            (
                selected_branch_for_scope(control, scope)? == intent.old_branch
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
        let target_files = if intent.format_version == 7 {
            let staged = staged_entries_for_scope(control, scope)?
                .into_iter()
                .collect::<BTreeMap<_, _>>();
            let mut files = TreeFiles::new();
            for entry in &intent.entries {
                match (&entry.new, staged.get(&entry.path)) {
                    (Some(target), Some(index))
                        if target.oid == index.oid && target.mode == index.mode =>
                    {
                        files.insert(entry.path.clone(), (target.oid, target.mode));
                    }
                    (None, None) => {}
                    _ => return Err(CheckoutError::IncompatibleIntent),
                }
            }
            files
        } else if intent.format_version == 8 {
            files_for_commit(
                control,
                intent.repository_id,
                (intent.new_oid != [0; 20])
                    .then(|| Oid::from_bytes(&intent.new_oid))
                    .transpose()?,
            )?
        } else {
            files_for_commit(
                control,
                intent.repository_id,
                Some(Oid::from_bytes(&intent.new_oid)?),
            )?
        };
        for (index, entry) in intent.entries.iter().enumerate() {
            if entry.new.is_none() {
                apply_old_deletion(control, intent.repository_id, root, &staging, index, entry)?;
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
            if published_target_file(control, intent.repository_id, root, entry)? {
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
                        verify_file_for_intent(
                            control,
                            intent.repository_id,
                            &parent,
                            &leaf,
                            old_id,
                            old,
                        )?;
                        verify_file_with_anchor(
                            control,
                            intent.repository_id,
                            &staging,
                            OsStr::new(&staged),
                            new_id,
                            new,
                        )?;
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
                    verify_file_with_anchor(
                        control,
                        intent.repository_id,
                        &parent,
                        &leaf,
                        new_id,
                        new,
                    )?;
                    verify_file_for_intent(
                        control,
                        intent.repository_id,
                        &staging,
                        OsStr::new(&staged),
                        old_id,
                        old,
                    )?;
                }
                (None, None, Some(new), Some(new_id)) => {
                    let work_id = entry_identity_for(&parent, &leaf, new.mode)?;
                    let staged_id = entry_identity_for(&staging, OsStr::new(&staged), new.mode)?;
                    if !entry_exists(&parent, &leaf)? && staged_id == Some(new_id) {
                        verify_file_with_anchor(
                            control,
                            intent.repository_id,
                            &staging,
                            OsStr::new(&staged),
                            new_id,
                            new,
                        )?;
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
                    verify_file_with_anchor(
                        control,
                        intent.repository_id,
                        &parent,
                        &leaf,
                        new_id,
                        new,
                    )?;
                }
                _ => return Err(CheckoutError::IncompatibleIntent),
            }
            run_after_checkout_file_hook();
        }
        // The target refs remain immutable while the daemon owns this intent.
        // Verify every target path once more before changing the visible HEAD.
        let filesystem_id = root.identity()?.filesystem_id;
        for (path, (oid, mode)) in &target_files {
            let (parent, leaf) = parent_and_name(root, path)?;
            let identity =
                entry_identity_for(&parent, &leaf, *mode)?.ok_or(CheckoutError::DirtyWorktree)?;
            verify_file_with_anchor(
                control,
                intent.repository_id,
                &parent,
                &leaf,
                identity,
                &CheckoutFile {
                    oid: *oid,
                    mode: *mode,
                    anchor_id: choose_anchor(control, intent.repository_id, *oid, filesystem_id)?,
                },
            )?;
        }
        if intent.format_version == 7 {
            intent.phase = Phase::Cleanup;
            save_intent(control, scope, root.identity()?, intent)?;
        } else {
            let mut records = Vec::new();
            let mut deletions = Vec::new();
            let previous_index = staged_entries_for_scope(control, scope)?
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
                    None if intent.format_version == 8 => {
                        let anchor =
                            anchors_for_oid(control, intent.repository_id, Oid::from_bytes(oid)?)?
                                .into_iter()
                                .next()
                                .ok_or(CheckoutError::MissingAnchor)?;
                        if blob_oid_from_anchor(&anchor)?.as_bytes() != oid {
                            return Err(CheckoutError::MissingAnchor);
                        }
                        anchor.anchor_id
                    }
                    None => {
                        let staged = previous_index
                            .get(path)
                            .ok_or(CheckoutError::IncompatibleIntent)?;
                        if staged.oid != *oid || staged.mode != *mode {
                            return Err(CheckoutError::IncompatibleIntent);
                        }
                        staged.anchor_id
                    }
                };
                records.push((
                    index_kind_for_scope(scope),
                    path.clone(),
                    canonical_bytes(&GitIndexEntry {
                        format_version: 1,
                        oid: *oid,
                        mode: *mode,
                        anchor_id,
                    })?,
                ));
            }
            for path in previous_index.keys() {
                if !target_files.contains_key(path) {
                    deletions.push((index_kind_for_scope(scope), path.clone()));
                }
            }
            if intent.format_version != 8 {
                records.push(selected_branch_record_for_scope(scope, &intent.new_branch)?);
            }
            if intent.advance_ref {
                records.push((
                    ref_kind(intent.repository_id),
                    format!("refs/heads/{}", intent.new_branch).into_bytes(),
                    fetched_ref_record(intent.new_oid)?,
                ));
            }
            intent.phase = Phase::Cleanup;
            records.push((
                intent_kind_for_scope(scope),
                INTENT_KEY.to_vec(),
                encode_intent_for_scope(scope, root.identity()?, intent)?,
            ));
            let merge_session = if scope.worktree_id() == scope.repository_id() {
                load_merge_session(control, intent.repository_id)?
            } else {
                None
            };
            if let Some((session, encoded)) = merge_session {
                let (first, second) = merge_commit_parents(
                    control,
                    intent.repository_id,
                    Oid::from_bytes(&intent.new_oid)?,
                )?;
                if intent.format_version != 6
                    || session.branch != intent.old_branch
                    || session.ours != intent.old_oid
                    || session.theirs != second.as_bytes()
                    || first.as_bytes() != session.ours
                    || intent.target_ref.as_deref() != Some(session.source_ref.as_slice())
                    || session.conflicts.len() != session.resolved.len()
                    || session.conflicts.iter().any(|path| {
                        match (target_files.get(path), previous_index.get(path)) {
                            (Some((oid, mode)), Some(staged)) => {
                                staged.oid != *oid || staged.mode != *mode
                            }
                            (None, None) => false,
                            _ => true,
                        }
                    })
                {
                    return Err(CheckoutError::IncompatibleIntent);
                }
                control.put_records_and_retire_and_delete_if_value(
                    &records,
                    &deletions,
                    &session_kind(intent.repository_id),
                    session_key(),
                    &encoded,
                )?;
            } else {
                control.put_records_and_delete(&records, &deletions)?;
            }
        }
        run_after_checkout_commit_hook();
    }
    if intent.phase == Phase::Cleanup {
        if !target_branch_is_current(control, scope, intent)? {
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
                verify_file_for_intent(
                    control,
                    intent.repository_id,
                    &staging,
                    OsStr::new(&staged),
                    identity,
                    old,
                )?;
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
        control.delete_record(&intent_kind_for_scope(scope), INTENT_KEY)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn tracked_removal_rechecks_native_bytes_after_matching_git_id() {
        let worktree = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::fs::write(worktree.path().join("tracked"), b"bravo").unwrap();
        let anchor = mb_store::SourceBlobImportPlan::plan_direct(source.path(), 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"alpha"))
            .unwrap();
        let root = PinnedDirectory::open(worktree.path()).unwrap();
        let name = OsStr::new("tracked");
        let identity = entry_identity_for(&root, name, 0o100644).unwrap().unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"bravo")
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        assert!(matches!(
            verify_tracked_file_for_removal(&root, name, identity, oid, 0o100644, &anchor),
            Err(CheckoutError::DirtyWorktree)
        ));
        std::fs::write(worktree.path().join("tracked"), b"alpha").unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"alpha")
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        verify_tracked_file_for_removal(&root, name, identity, oid, 0o100644, &anchor).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn tracked_symlink_removal_rechecks_native_target_after_matching_git_id() {
        let worktree = tempfile::tempdir().unwrap();
        let source = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("bravo", worktree.path().join("tracked")).unwrap();
        let anchor = mb_store::SourceBlobImportPlan::plan_direct(source.path(), 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"alpha"))
            .unwrap();
        let root = PinnedDirectory::open(worktree.path()).unwrap();
        let name = OsStr::new("tracked");
        let identity = entry_identity_for(&root, name, 0o120000).unwrap().unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"bravo")
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        assert!(matches!(
            verify_tracked_file_for_removal(&root, name, identity, oid, 0o120000, &anchor),
            Err(CheckoutError::DirtyWorktree)
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn checkout_replay_keeps_worktree_bytes_on_native_root_conflict() {
        let temporary = tempfile::tempdir().unwrap();
        let worktree_path = temporary.path().join("worktree");
        let staging_path = temporary.path().join("staging");
        std::fs::create_dir_all(&worktree_path).unwrap();
        std::fs::create_dir_all(&staging_path).unwrap();
        std::fs::write(worktree_path.join("tracked"), b"bravo").unwrap();
        let control =
            ControlStore::open_with_key(temporary.path().join("control.db"), &[64; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let anchor = mb_store::SourceBlobImportPlan::plan_direct(temporary.path(), 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"alpha"))
            .unwrap();
        // Model a same-SHA-1/different-native-root conflict without needing
        // to manufacture a cryptographic collision for this replay test.
        let oid = Oid::hash_object(ObjectType::Blob, b"bravo").unwrap();
        control
            .put_record(
                &crate::stage::object_kind(repository_id, oid),
                anchor.anchor_id.as_bytes(),
                &canonical_bytes(&anchor).unwrap(),
            )
            .unwrap();
        let worktree = PinnedDirectory::open(&worktree_path).unwrap();
        let staging = PinnedDirectory::open(&staging_path).unwrap();
        let identity = entry_identity_for(&worktree, OsStr::new("tracked"), 0o100644)
            .unwrap()
            .unwrap();
        let entry = CheckoutEntry {
            path: b"tracked".to_vec(),
            old: Some(CheckoutFile {
                oid: oid.as_bytes().try_into().unwrap(),
                mode: 0o100644,
                anchor_id: anchor.anchor_id,
            }),
            old_id: Some(identity),
            new: None,
            new_id: None,
        };
        assert!(matches!(
            apply_old_deletion(&control, repository_id, &worktree, &staging, 0, &entry),
            Err(CheckoutError::DirtyWorktree)
        ));
        assert_eq!(
            std::fs::read(worktree_path.join("tracked")).unwrap(),
            b"bravo"
        );
        assert!(std::fs::read_dir(staging_path).unwrap().next().is_none());
    }

    #[test]
    fn guarded_checkout_replay_does_not_create_staging_for_a_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let root_path = temp.path().join("work");
        let catalog_path = root_path.join(".mutualbackup");
        std::fs::create_dir_all(&catalog_path).unwrap();
        let root = PinnedDirectory::open(&root_path).unwrap();
        let catalog = PinnedDirectory::open(&catalog_path).unwrap();
        let control =
            ControlStore::open_with_key(catalog_path.join("catalog.db"), &[41; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let mut intent = CheckoutIntent {
            format_version: 8,
            advance_ref: false,
            target_ref: None,
            repository_id,
            old_branch: "main".to_owned(),
            old_oid: [0; 20],
            new_branch: "main".to_owned(),
            new_oid: [1; 20],
            staging_name: format!("checkout-{}", Uuid::new_v4()),
            staging_id: None,
            phase: Phase::Preparing,
            entries: vec![CheckoutEntry {
                path: b"tracked".to_vec(),
                old: None,
                old_id: None,
                new: Some(CheckoutFile {
                    oid: [2; 20],
                    mode: 0o100644,
                    anchor_id: Uuid::new_v4(),
                }),
                new_id: None,
            }],
            directories: Vec::new(),
            removed_directories: Vec::new(),
        };
        assert!(matches!(
            apply_intent(
                &control,
                GitWorktreeScope::primary(repository_id),
                &mut intent,
                &root,
                &catalog,
                SourceBackendKind::GuardedLinkFreezeV1,
            ),
            Err(CheckoutError::Anchor(
                AnchorError::UnsupportedSourceOperation(_)
            ))
        ));
        assert!(
            catalog
                .entry_identity(&intent.staging_name, true)
                .unwrap()
                .is_none()
        );
        assert!(intent.staging_id.is_none());
    }

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
