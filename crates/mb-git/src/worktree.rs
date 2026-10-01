//! Durable linked-worktree registration. Refs, Git objects, and anchors remain
//! in the primary repository catalog; only HEAD, index, and checkout are local
//! to each registered worktree.

use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use git2::Branch;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{
    AnchorError, ControlStore, DatabaseError, GIT_CATALOG_DIRECTORY, NativeFileId, PinnedDirectory,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::GitWorktreeScope;
use crate::checkout::{CheckoutError, begin_switch_for_scope, resume_pending_checkout_for_scope};
use crate::head::{
    HeadError, branch_selected_elsewhere, selected_branch_for_scope,
    store_selected_branch_for_scope,
};
use crate::history::{HistoryError, list_branches_for_scope};
use crate::status::{StatusError, repository_status_for_scope};

const RECORD_PREFIX: &str = "git-linked-worktree-v1/";
const MARKER_NAME: &str = "worktree";
const MARKER_MAGIC: &str = "mutualbackup-git-worktree-v1\n";
const MAX_WORKTREES: usize = 256;

#[cfg(test)]
thread_local! {
    static AFTER_REGISTRATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_registration_hook(hook: Box<dyn FnOnce()>) {
    AFTER_REGISTRATION.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_registration_hook() {
    #[cfg(test)]
    AFTER_REGISTRATION.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GitWorktreeState {
    Preparing,
    Ready,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitWorktreeInfo {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub path: PathBuf,
    pub root_id: NativeFileId,
    pub target_branch: String,
    pub state: GitWorktreeState,
}

impl GitWorktreeInfo {
    pub fn scope(&self) -> Option<GitWorktreeScope> {
        GitWorktreeScope::linked(self.repository_id, self.worktree_id)
    }
}

#[derive(Debug, Error)]
pub enum GitWorktreeError {
    #[error("linked worktree I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("linked worktree path failed: {0}")]
    Anchor(#[from] AnchorError),
    #[error("encrypted Git catalog failed: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned linked worktree record failed: {0}")]
    Model(#[from] ModelError),
    #[error("Git HEAD record failed: {0}")]
    Head(#[from] HeadError),
    #[error("Git branch record failed: {0}")]
    History(#[from] HistoryError),
    #[error("Git checkout failed: {0}")]
    Checkout(#[from] CheckoutError),
    #[error("Git worktree status failed: {0}")]
    Status(#[from] StatusError),
    #[error("the linked worktree path, identity, or marker conflicts with its registration")]
    Conflict,
    #[error("a linked worktree must start in an empty directory on the primary filesystem")]
    InvalidDestination,
    #[error("the requested branch is already selected by another worktree")]
    BranchCheckedOutElsewhere,
    #[error("the linked worktree registration does not exist")]
    NotRegistered,
    #[error("too many linked worktrees are registered")]
    TooManyWorktrees,
}

pub(crate) fn record_kind(repository_id: Uuid) -> String {
    format!("{RECORD_PREFIX}{repository_id}")
}

fn validate(
    info: &GitWorktreeInfo,
    repository_id: Uuid,
    key: &[u8],
) -> Result<(), GitWorktreeError> {
    if info.format_version != 1
        || info.repository_id != repository_id
        || GitWorktreeScope::linked(info.repository_id, info.worktree_id).is_none()
        || info.worktree_id.as_bytes() != key
        || !info.path.is_absolute()
        || info.target_branch.len() > 1024
        || !Branch::name_is_valid(&info.target_branch).map_err(HistoryError::from)?
        || info.root_id.filesystem_id == 0
        || info.root_id.inode == 0
    {
        return Err(GitWorktreeError::Conflict);
    }
    Ok(())
}

pub(crate) fn list_worktrees(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<GitWorktreeInfo>, GitWorktreeError> {
    let rows = control.records(&record_kind(repository_id))?;
    if rows.len() > MAX_WORKTREES {
        return Err(GitWorktreeError::TooManyWorktrees);
    }
    rows.into_iter()
        .map(|(key, bytes)| {
            let info: GitWorktreeInfo = decode_canonical(&bytes)?;
            validate(&info, repository_id, &key)?;
            Ok(info)
        })
        .collect()
}

pub(crate) fn get_worktree(
    control: &ControlStore,
    repository_id: Uuid,
    worktree_id: Uuid,
) -> Result<GitWorktreeInfo, GitWorktreeError> {
    let bytes = control
        .get_record(&record_kind(repository_id), worktree_id.as_bytes())?
        .ok_or(GitWorktreeError::NotRegistered)?;
    let info: GitWorktreeInfo = decode_canonical(&bytes)?;
    validate(&info, repository_id, worktree_id.as_bytes())?;
    Ok(info)
}

pub(crate) fn add_worktree(
    control: &ControlStore,
    repository_id: Uuid,
    primary_root: &Path,
    catalog: &PinnedDirectory,
    destination: &Path,
    branch: &str,
) -> Result<GitWorktreeInfo, GitWorktreeError> {
    let path = destination.canonicalize()?;
    let root = PinnedDirectory::open(&path)?;
    let root_id = root.identity()?;
    if path.starts_with(primary_root)
        || primary_root.starts_with(&path)
        || root_id.filesystem_id != catalog.identity()?.filesystem_id
        || fs::read_dir(root.descriptor_path())?.next().is_some()
    {
        return Err(GitWorktreeError::InvalidDestination);
    }
    let existing = list_worktrees(control, repository_id)?;
    if existing.len() >= MAX_WORKTREES {
        return Err(GitWorktreeError::TooManyWorktrees);
    }
    if existing
        .iter()
        .any(|info| path.starts_with(&info.path) || info.path.starts_with(&path))
    {
        return Err(GitWorktreeError::InvalidDestination);
    }
    if existing
        .iter()
        .any(|info| info.state == GitWorktreeState::Preparing && info.target_branch == branch)
    {
        return Err(GitWorktreeError::BranchCheckedOutElsewhere);
    }
    let scope = GitWorktreeScope::linked(repository_id, Uuid::new_v4())
        .ok_or(GitWorktreeError::Conflict)?;
    if !list_branches_for_scope(control, scope)?
        .iter()
        .any(|entry| entry.name == branch)
    {
        return Err(HistoryError::BranchNotFound.into());
    }
    if branch_selected_elsewhere(control, scope, branch)? {
        return Err(GitWorktreeError::BranchCheckedOutElsewhere);
    }
    let info = GitWorktreeInfo {
        format_version: 1,
        repository_id,
        worktree_id: scope.worktree_id(),
        path,
        root_id,
        target_branch: branch.to_owned(),
        state: GitWorktreeState::Preparing,
    };
    if !control.put_record_if_absent(
        &record_kind(repository_id),
        info.worktree_id.as_bytes(),
        &canonical_bytes(&info)?,
    )? {
        return Err(GitWorktreeError::Conflict);
    }
    run_after_registration_hook();
    resume_worktree(control, repository_id, info.worktree_id, catalog)
}

pub(crate) fn resume_worktree(
    control: &ControlStore,
    repository_id: Uuid,
    worktree_id: Uuid,
    catalog: &PinnedDirectory,
) -> Result<GitWorktreeInfo, GitWorktreeError> {
    let info = get_worktree(control, repository_id, worktree_id)?;
    let canonical = info.path.canonicalize()?;
    let root = PinnedDirectory::open(&info.path)?;
    if canonical != info.path || root.identity()? != info.root_id {
        return Err(GitWorktreeError::Conflict);
    }
    if info.state == GitWorktreeState::Ready {
        verify_marker(&root, &info)?;
        return Ok(info);
    }
    let scope = info.scope().ok_or(GitWorktreeError::Conflict)?;
    resume_pending_checkout_for_scope(control, scope, &info.path, catalog)?;
    let selected = selected_branch_for_scope(control, scope)?;
    if selected != info.target_branch {
        let unborn = format!("mutualbackup-init-{}", info.worktree_id);
        if selected == "main"
            && control
                .get_record(&crate::head::head_kind_for_scope(scope), b"branch")?
                .is_none()
        {
            store_selected_branch_for_scope(control, scope, &unborn)?;
        } else if selected != unborn {
            return Err(GitWorktreeError::Conflict);
        }
        if fs::read_dir(root.descriptor_path())?.next().is_some() {
            return Err(GitWorktreeError::InvalidDestination);
        }
        begin_switch_for_scope(control, scope, &info.path, catalog, &info.target_branch)?;
    }
    let status = repository_status_for_scope(control, scope, &info.path)?;
    if status.branch != info.target_branch
        || !status.changes.is_empty()
        || !status.untracked.is_empty()
    {
        return Err(GitWorktreeError::Conflict);
    }
    publish_marker(&root, &info)?;
    let ready = GitWorktreeInfo {
        state: GitWorktreeState::Ready,
        ..info.clone()
    };
    control.replace_record_if_value(
        &record_kind(repository_id),
        worktree_id.as_bytes(),
        &canonical_bytes(&info)?,
        &canonical_bytes(&ready)?,
    )?;
    Ok(ready)
}

fn marker_bytes(info: &GitWorktreeInfo) -> Vec<u8> {
    format!(
        "{MARKER_MAGIC}{}\n{}\n",
        info.repository_id, info.worktree_id
    )
    .into_bytes()
}

fn verify_marker(root: &PinnedDirectory, info: &GitWorktreeInfo) -> Result<(), GitWorktreeError> {
    let directory = root
        .open_child_directory(GIT_CATALOG_DIRECTORY)?
        .ok_or(GitWorktreeError::Conflict)?;
    let metadata = directory.as_file().metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(GitWorktreeError::Conflict);
    }
    let mut file = directory
        .open_child_file(MARKER_NAME)?
        .ok_or(GitWorktreeError::Conflict)?;
    if file.metadata()?.len() > 128 {
        return Err(GitWorktreeError::Conflict);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes != marker_bytes(info) {
        return Err(GitWorktreeError::Conflict);
    }
    Ok(())
}

fn publish_marker(root: &PinnedDirectory, info: &GitWorktreeInfo) -> Result<(), GitWorktreeError> {
    let directory = match root.open_child_directory(GIT_CATALOG_DIRECTORY)? {
        Some(existing) => existing,
        None => {
            let created = root.create_child_directory(GIT_CATALOG_DIRECTORY)?;
            root.sync_all()?;
            created
        }
    };
    if directory.open_child_file(MARKER_NAME)?.is_none() {
        if fs::read_dir(directory.descriptor_path())?.next().is_some() {
            return Err(GitWorktreeError::Conflict);
        }
        directory.publish_small_bytes_child(MARKER_NAME, &marker_bytes(info))?;
    }
    verify_marker(root, info)
}
