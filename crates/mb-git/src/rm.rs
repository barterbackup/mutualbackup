//! Replayable removal of a tracked working file and its index entry.
//! The index keeps its anchor pinned until the matching worktree path has been
//! unlinked; a crash between those steps leaves a durable intent to replay.

use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{AnchorError, ControlStore, DatabaseError, NativeFileId, PinnedDirectory};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::GitWorktreeScope;
use crate::checkout::{
    CheckoutError, has_pending_checkout_for_scope, parent_and_name_if_exists,
    verify_tracked_file_for_removal,
};
use crate::stage::{
    GitIndexEntry, StageError, index_kind_for_scope, stage_path_key, staged_entry_for_scope,
};
use crate::status::{StatusError, committed_files_for_scope};

const PRIMARY_PREFIX: &str = "git-rm-intent-v1/";
const LINKED_PREFIX: &str = "git-worktree-rm-intent-v1/";

#[cfg(test)]
thread_local! {
    static AFTER_UNLINK: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_unlink_hook(hook: Box<dyn FnOnce()>) {
    AFTER_UNLINK.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_unlink_hook() {
    #[cfg(test)]
    AFTER_UNLINK.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[derive(Debug, Error)]
pub enum GitRmError {
    #[error("tracked removal path or pinned file failed: {0}")]
    Anchor(#[from] AnchorError),
    #[error("encrypted Git catalog failed: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned tracked-removal intent failed: {0}")]
    Model(#[from] ModelError),
    #[error("Git index failed: {0}")]
    Stage(#[from] StageError),
    #[error("Git HEAD tree failed: {0}")]
    Status(#[from] StatusError),
    #[error("tracked-file verification failed: {0}")]
    Checkout(#[from] CheckoutError),
    #[error("the tracked file differs from the index or changed during removal")]
    DirtyWorktree,
    #[error("the index differs from HEAD; commit, reset, or use rm --cached first")]
    StagedChanges,
    #[error("an add, checkout, or tracked removal is unfinished")]
    PendingOperation,
    #[error("the tracked-removal intent or index record is incompatible")]
    IncompatibleIntent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RmIntent {
    format_version: u16,
    repository_id: Uuid,
    worktree_id: Uuid,
    root_id: NativeFileId,
    path: Vec<u8>,
    entry: GitIndexEntry,
    file_id: NativeFileId,
}

pub(crate) fn intent_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(PRIMARY_PREFIX, LINKED_PREFIX)
}

fn file_identity(
    parent: &PinnedDirectory,
    name: &std::ffi::OsStr,
    mode: u32,
) -> Result<Option<NativeFileId>, GitRmError> {
    Ok(match mode {
        0o100644 | 0o100755 => parent.entry_identity(name, false)?,
        0o120000 => parent.symlink_identity(name)?,
        _ => return Err(GitRmError::IncompatibleIntent),
    })
}

fn decode_intent(
    scope: GitWorktreeScope,
    key: &[u8],
    encoded: &[u8],
) -> Result<RmIntent, GitRmError> {
    let intent: RmIntent = decode_canonical(encoded)?;
    let path = PathBuf::from(OsString::from_vec(intent.path.clone()));
    if intent.format_version != 1
        || intent.repository_id != scope.repository_id()
        || intent.worktree_id != scope.worktree_id()
        || intent.path != key
        || stage_path_key(&path)? != key
        || !matches!(intent.entry.mode, 0o100644 | 0o100755 | 0o120000)
        || intent.entry.format_version != 1
        || intent.file_id.filesystem_id != intent.root_id.filesystem_id
    {
        return Err(GitRmError::IncompatibleIntent);
    }
    Ok(intent)
}

fn resume_one(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    key: &[u8],
    encoded: &[u8],
) -> Result<(), GitRmError> {
    let intent = decode_intent(scope, key, encoded)?;
    let index_kind = index_kind_for_scope(scope);
    let current = control
        .get_record(&index_kind, key)?
        .ok_or(GitRmError::IncompatibleIntent)?;
    if current != canonical_bytes(&intent.entry)? {
        return Err(GitRmError::IncompatibleIntent);
    }
    let root = PinnedDirectory::open(root_path)?;
    if root.identity()? != intent.root_id {
        return Err(GitRmError::IncompatibleIntent);
    }
    if let Some((parent, name)) = parent_and_name_if_exists(&root, key)?
        && let Some(actual) = file_identity(&parent, &name, intent.entry.mode)?
    {
        if actual != intent.file_id {
            return Err(GitRmError::DirtyWorktree);
        }
        verify_tracked_file_for_removal(
            &parent,
            &name,
            actual,
            intent.entry.oid,
            intent.entry.mode,
        )?;
        if intent.entry.mode == 0o120000 {
            parent.remove_child_symlink(&name, actual)?;
        } else {
            parent.remove_child_file_if_identity(&name, actual)?;
        }
        run_after_unlink_hook();
    }
    control.put_records_and_retire_and_delete_if_value(
        &[],
        &[(index_kind, key.to_vec())],
        &intent_kind_for_scope(scope),
        key,
        encoded,
    )?;
    Ok(())
}

/// A missing linked worktree has no path left to unlink. Force prune can
/// discard its exact pending removal after binding the intent to that root;
/// the linked index remains until the registration is retired atomically.
pub(crate) fn abandon_missing_linked_rm(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_id: NativeFileId,
) -> Result<(), GitRmError> {
    if scope.worktree_id() == scope.repository_id() {
        return Err(GitRmError::IncompatibleIntent);
    }
    let kind = intent_kind_for_scope(scope);
    for (key, encoded) in control.records(&kind)? {
        let intent = decode_intent(scope, &key, &encoded)?;
        if intent.root_id != root_id
            || control.get_record(&index_kind_for_scope(scope), &key)?
                != Some(canonical_bytes(&intent.entry)?)
        {
            return Err(GitRmError::IncompatibleIntent);
        }
        control.delete_record_if_value(&kind, &key, &encoded)?;
    }
    Ok(())
}

pub(crate) fn resume_pending_rm_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
) -> Result<(), GitRmError> {
    for (key, encoded) in control.records(&intent_kind_for_scope(scope))? {
        resume_one(control, scope, root_path, &key, &encoded)?;
    }
    Ok(())
}

pub(crate) fn remove_tracked_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
    relative: &Path,
) -> Result<bool, GitRmError> {
    resume_pending_rm_for_scope(control, scope, root_path)?;
    let key = stage_path_key(relative)?;
    let Some(entry) = staged_entry_for_scope(control, scope, relative)? else {
        return Ok(false);
    };
    if crate::stage::has_pending_stages_for_scope(control, scope)?
        || has_pending_checkout_for_scope(control, scope)?
    {
        return Err(GitRmError::PendingOperation);
    }
    if committed_files_for_scope(control, scope)?.get(&key) != Some(&(entry.oid, entry.mode)) {
        return Err(GitRmError::StagedChanges);
    }
    let root = PinnedDirectory::open(root_path)?;
    let (parent, name) =
        parent_and_name_if_exists(&root, &key)?.ok_or(GitRmError::DirtyWorktree)?;
    let file_id = file_identity(&parent, &name, entry.mode)?.ok_or(GitRmError::DirtyWorktree)?;
    verify_tracked_file_for_removal(&parent, &name, file_id, entry.oid, entry.mode)?;
    let intent = RmIntent {
        format_version: 1,
        repository_id: scope.repository_id(),
        worktree_id: scope.worktree_id(),
        root_id: root.identity()?,
        path: key.clone(),
        entry,
        file_id,
    };
    let index_kind = index_kind_for_scope(scope);
    let index_bytes = canonical_bytes(&intent.entry)?;
    control.put_records_and_retire_if_value(
        &[
            (index_kind.clone(), key.clone(), index_bytes.clone()),
            (
                intent_kind_for_scope(scope),
                key.clone(),
                canonical_bytes(&intent)?,
            ),
        ],
        &index_kind,
        &key,
        &index_bytes,
    )?;
    let encoded = control
        .get_record(&intent_kind_for_scope(scope), &key)?
        .ok_or(GitRmError::IncompatibleIntent)?;
    resume_one(control, scope, root_path, &key, &encoded)?;
    Ok(true)
}
