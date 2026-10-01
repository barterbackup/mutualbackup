//! App-owned Git repository marker and encrypted local catalog lifecycle.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use git2::Oid;
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, GIT_CATALOG_DIRECTORY,
    GIT_CATALOG_MARKER_FILE, PinnedDirectory, git_catalog_marker_bytes,
};
use thiserror::Error;
use uuid::Uuid;

use crate::checkout::{
    CheckoutError, begin_merge_branch, begin_pull, begin_switch, begin_switch_for_scope,
    continue_merge, resume_pending_checkout, resume_pending_checkout_for_scope,
};
use crate::diff::{DiffError, GitDiff, repository_diff, repository_diff_for_scope};
use crate::fetch::{FetchError, fetch_bare, import_pushed_branch, import_pushed_tag};
use crate::head::{HeadError, selected_branch};
use crate::history::{
    GitBranchInfo, GitCommitInfo, GitGraphSource, GitLogEntry, GitRemoteBranchInfo, GitTagInfo,
    HistoryError, commit_index, commit_index_for_scope, create_annotated_tag_for_scope,
    create_branch, create_branch_for_scope, create_branch_from, create_branch_from_for_scope,
    create_tag_for_scope, delete_branch, delete_branch_for_scope, delete_tag, export_graph_source,
    import_graph_backup, list_branches, list_branches_for_scope, list_commit_pins,
    list_remote_branches, list_tags, log_history, log_history_for_scope, pin_commit,
    reset_index_for_scope, switch_same_tree_branch, switch_same_tree_branch_for_scope,
    unpin_commit,
};
use crate::interop::{
    GitInteropError, export_graph_to_git_repository, push_current_branch_to_bare, push_tag_to_bare,
};
use crate::merge::{
    MergeBlobError, has_merge_session, load_merge_session, mark_merge_resolved,
    resume_pending_merge_blob, session_key, session_kind, unmark_merge_resolved,
};
use crate::prune::{
    GitPruneError, GitPruneReport, GitPruneRoots, prune_unreachable, resume_pending_prune,
};
use crate::stage::{
    GitIndexEntry, StageError, abandon_pending_stage, abandon_pending_stage_for_scope,
    anchors_for_oid, pending_stage_paths, remove_cached, remove_cached_for_scope,
    resume_pending_stages, resume_pending_stages_for_scope, stage_file, stage_file_for_scope,
    stage_path_key, stage_symlink, stage_symlink_for_scope, staged_entry,
};
use crate::status::{GitStatus, StatusError, repository_status, repository_status_for_scope};
use crate::worktree::{
    GitWorktreeError, GitWorktreeInfo, add_worktree, get_worktree, list_worktrees, resume_worktree,
};

const INITIALIZATION_INTENT: &str = "repository-intent";
const INITIALIZATION_MAGIC: &str = "mutualbackup-git-repository-init-v1\n";
const CATALOG_DATABASE: &str = "catalog.db";
const TEMP_MARKER_PREFIX: &str = ".repository-staging-";
const MAX_MARKER_BYTES: u64 = 128;

#[derive(Debug, Error)]
pub enum RepositoryError {
    #[error("repository filesystem error: {0}")]
    Io(#[from] std::io::Error),
    #[error("repository path or anchor error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("encrypted Git catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Git stage error: {0}")]
    Stage(#[from] StageError),
    #[error("Git history error: {0}")]
    History(#[from] HistoryError),
    #[error("Git HEAD record error: {0}")]
    Head(#[from] HeadError),
    #[error("Git status error: {0}")]
    Status(#[from] StatusError),
    #[error("Git diff error: {0}")]
    Diff(#[from] DiffError),
    #[error("Git checkout error: {0}")]
    Checkout(#[from] CheckoutError),
    #[error("Git interoperability error: {0}")]
    Interop(#[from] GitInteropError),
    #[error("Git fetch error: {0}")]
    Fetch(#[from] FetchError),
    #[error("Git merge blob error: {0}")]
    MergeBlob(#[from] MergeBlobError),
    #[error("Git history prune error: {0}")]
    Prune(#[from] GitPruneError),
    #[error("Git linked worktree error: {0}")]
    Worktree(#[from] GitWorktreeError),
    #[error("repository marker or catalog identity conflicts with this root")]
    Conflict,
    #[error("the Git repository is not initialized")]
    NotInitialized,
}

/// The daemon owns this handle while serving an operation. The catalog field
/// drops before the pinned directory, keeping SQLite's `/proc/self/fd` parent
/// valid until its database connection has closed.
pub struct GitRepository {
    catalog: ControlStore,
    directory: PinnedDirectory,
    root: PathBuf,
    repository_id: Uuid,
}

impl GitRepository {
    pub fn init(
        source_root: impl AsRef<Path>,
        repository_id: Uuid,
        catalog_key: &[u8; 32],
    ) -> Result<Self, RepositoryError> {
        if repository_id.is_nil() {
            return Err(RepositoryError::Conflict);
        }
        let root = source_root.as_ref().canonicalize()?;
        let root_dir = PinnedDirectory::open(&root)?;
        let directory = match root_dir.open_child_directory(GIT_CATALOG_DIRECTORY)? {
            Some(existing) => existing,
            None => {
                let created = root_dir.create_child_directory(GIT_CATALOG_DIRECTORY)?;
                root_dir.sync_all()?;
                created
            }
        };
        require_private_catalog(&directory)?;
        let ready = read_marker(&directory, GIT_CATALOG_MARKER_FILE)?;
        let ready_bytes = git_catalog_marker_bytes(repository_id);
        if let Some(existing) = ready {
            if existing != ready_bytes {
                return Err(RepositoryError::Conflict);
            }
            if let Some(intent) = read_marker(&directory, INITIALIZATION_INTENT)? {
                if intent != initialization_intent_bytes(repository_id) {
                    return Err(RepositoryError::Conflict);
                }
                directory.remove_child_file(INITIALIZATION_INTENT)?;
                directory.sync_all()?;
            }
            cleanup_staged_markers(&directory)?;
            return Self::open_from_pinned(root, repository_id, directory, catalog_key);
        }

        let intent_bytes = initialization_intent_bytes(repository_id);
        match read_marker(&directory, INITIALIZATION_INTENT)? {
            Some(existing) if existing == intent_bytes => cleanup_staged_markers(&directory)?,
            Some(_) => return Err(RepositoryError::Conflict),
            None => {
                require_empty_or_staged_marker_directory(&directory)?;
                publish_marker(&directory, INITIALIZATION_INTENT, &intent_bytes)?;
            }
        }

        let path = directory.descriptor_path().join(CATALOG_DATABASE);
        let catalog = ControlStore::open_with_key(&path, catalog_key)?;
        directory.sync_all()?;
        publish_marker(&directory, GIT_CATALOG_MARKER_FILE, &ready_bytes)?;
        directory.remove_child_file(INITIALIZATION_INTENT)?;
        directory.sync_all()?;
        let repository = Self {
            catalog,
            directory,
            root,
            repository_id,
        };
        repository.resume_checkout()?;
        resume_pending_prune(&repository.catalog, repository.repository_id)?;
        Ok(repository)
    }

    pub fn open(
        source_root: impl AsRef<Path>,
        repository_id: Uuid,
        catalog_key: &[u8; 32],
    ) -> Result<Self, RepositoryError> {
        if repository_id.is_nil() {
            return Err(RepositoryError::Conflict);
        }
        let root = source_root.as_ref().canonicalize()?;
        let root_dir = PinnedDirectory::open(&root)?;
        let directory = root_dir
            .open_child_directory(GIT_CATALOG_DIRECTORY)?
            .ok_or(RepositoryError::NotInitialized)?;
        Self::open_from_pinned(root, repository_id, directory, catalog_key)
    }

    fn open_from_pinned(
        root: PathBuf,
        repository_id: Uuid,
        directory: PinnedDirectory,
        catalog_key: &[u8; 32],
    ) -> Result<Self, RepositoryError> {
        require_private_catalog(&directory)?;
        let ready = read_marker(&directory, GIT_CATALOG_MARKER_FILE)?
            .ok_or(RepositoryError::NotInitialized)?;
        if ready != git_catalog_marker_bytes(repository_id) {
            return Err(RepositoryError::Conflict);
        }
        let path = directory.descriptor_path().join(CATALOG_DATABASE);
        let catalog = ControlStore::open_existing_with_key(&path, catalog_key)?;
        let repository = Self {
            catalog,
            directory,
            root,
            repository_id,
        };
        repository.resume_checkout()?;
        resume_pending_prune(&repository.catalog, repository.repository_id)?;
        Ok(repository)
    }

    pub fn id(&self) -> Uuid {
        self.repository_id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn add_linked_worktree(
        &self,
        destination: impl AsRef<Path>,
        branch: &str,
    ) -> Result<GitWorktreeInfo, RepositoryError> {
        self.resume_checkout()?;
        Ok(add_worktree(
            &self.catalog,
            self.repository_id,
            &self.root,
            &self.directory,
            destination.as_ref(),
            branch,
        )?)
    }

    pub fn linked_worktrees(&self) -> Result<Vec<GitWorktreeInfo>, RepositoryError> {
        Ok(list_worktrees(&self.catalog, self.repository_id)?)
    }

    pub fn linked_worktree(&self, worktree_id: Uuid) -> Result<GitWorktreeInfo, RepositoryError> {
        Ok(get_worktree(
            &self.catalog,
            self.repository_id,
            worktree_id,
        )?)
    }

    pub fn resume_linked_worktree(
        &self,
        worktree_id: Uuid,
    ) -> Result<GitWorktreeInfo, RepositoryError> {
        let info = resume_worktree(
            &self.catalog,
            self.repository_id,
            worktree_id,
            &self.root,
            &self.directory,
        )?;
        resume_pending_checkout_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            &info.path,
            &self.directory,
        )?;
        Ok(info)
    }

    pub fn linked_status(&self, worktree_id: Uuid) -> Result<GitStatus, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        let scope = info.scope().ok_or(GitWorktreeError::Conflict)?;
        Ok(repository_status_for_scope(
            &self.catalog,
            scope,
            &info.path,
        )?)
    }

    pub fn linked_add_path(
        &self,
        worktree_id: Uuid,
        relative_path: impl AsRef<Path>,
    ) -> Result<Option<GitIndexEntry>, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        let scope = info.scope().ok_or(GitWorktreeError::Conflict)?;
        resume_pending_stages_for_scope(&self.catalog, scope)?;
        let relative = relative_path.as_ref();
        stage_path_key(relative)?;
        let mut parent = PinnedDirectory::open(&info.path)?;
        for component in relative
            .parent()
            .ok_or(StageError::UnsafePath)?
            .components()
        {
            let Component::Normal(name) = component else {
                return Err(StageError::UnsafePath.into());
            };
            match parent.open_child_directory(name)? {
                Some(next) => parent = next,
                None => return self.linked_missing_path(scope, relative),
            }
        }
        let name = relative.file_name().ok_or(StageError::UnsafePath)?;
        let symlink = match parent.read_child_symlink(name) {
            Ok(found) => found.is_some(),
            Err(AnchorError::UnsupportedObject(_)) => false,
            Err(error) => return Err(error.into()),
        };
        if symlink {
            return Ok(Some(stage_symlink_for_scope(
                &self.catalog,
                scope,
                &info.path,
                &self.root,
                &self.directory,
                relative,
            )?));
        }
        if parent.open_child_file(name)?.is_some() {
            Ok(Some(stage_file_for_scope(
                &self.catalog,
                scope,
                &info.path,
                relative,
            )?))
        } else {
            self.linked_missing_path(scope, relative)
        }
    }

    fn linked_missing_path(
        &self,
        scope: crate::GitWorktreeScope,
        relative: &Path,
    ) -> Result<Option<GitIndexEntry>, RepositoryError> {
        if !remove_cached_for_scope(&self.catalog, scope, relative)? {
            return Err(StageError::MissingUntrackedPath.into());
        }
        Ok(None)
    }

    pub fn linked_remove_cached(
        &self,
        worktree_id: Uuid,
        relative_path: impl AsRef<Path>,
    ) -> Result<bool, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        Ok(remove_cached_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            relative_path,
        )?)
    }

    pub fn linked_abandon_pending_stage(
        &self,
        worktree_id: Uuid,
        relative_path: impl AsRef<Path>,
    ) -> Result<bool, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        Ok(abandon_pending_stage_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            relative_path,
        )?)
    }

    pub fn linked_commit(
        &self,
        worktree_id: Uuid,
        author_name: &str,
        author_email: &str,
        message: &str,
    ) -> Result<GitCommitInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        let scope = info.scope().ok_or(GitWorktreeError::Conflict)?;
        resume_pending_stages_for_scope(&self.catalog, scope)?;
        Ok(commit_index_for_scope(
            &self.catalog,
            scope,
            author_name,
            author_email,
            message,
        )?)
    }

    pub fn linked_log(
        &self,
        worktree_id: Uuid,
        limit: usize,
    ) -> Result<Vec<GitLogEntry>, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        Ok(log_history_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            limit,
        )?)
    }

    pub fn linked_branches(
        &self,
        worktree_id: Uuid,
    ) -> Result<Vec<GitBranchInfo>, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        Ok(list_branches_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
        )?)
    }

    pub fn linked_reset_index(
        &self,
        worktree_id: Uuid,
        paths: &[PathBuf],
    ) -> Result<u32, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        self.ensure_no_merge_session()?;
        Ok(reset_index_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            paths,
        )?)
    }

    pub fn linked_create_branch(
        &self,
        worktree_id: Uuid,
        name: &str,
    ) -> Result<GitBranchInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        self.ensure_no_merge_session()?;
        Ok(create_branch_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            name,
        )?)
    }

    pub fn linked_create_branch_from(
        &self,
        worktree_id: Uuid,
        name: &str,
        start_point: &str,
    ) -> Result<GitBranchInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        self.ensure_no_merge_session()?;
        Ok(create_branch_from_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            name,
            start_point,
        )?)
    }

    pub fn linked_delete_branch(
        &self,
        worktree_id: Uuid,
        name: &str,
        force: bool,
    ) -> Result<GitBranchInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        self.ensure_no_merge_session()?;
        Ok(delete_branch_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            name,
            force,
        )?)
    }

    pub fn linked_create_tag(
        &self,
        worktree_id: Uuid,
        name: &str,
        start_point: Option<&str>,
    ) -> Result<GitTagInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        self.ensure_no_merge_session()?;
        Ok(create_tag_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            name,
            start_point,
        )?)
    }

    pub fn linked_create_annotated_tag(
        &self,
        worktree_id: Uuid,
        name: &str,
        start_point: Option<&str>,
        tagger_name: &str,
        tagger_email: &str,
        message: &str,
    ) -> Result<GitTagInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        self.ensure_no_merge_session()?;
        Ok(create_annotated_tag_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            name,
            start_point,
            tagger_name,
            tagger_email,
            message,
        )?)
    }

    pub fn linked_diff(&self, worktree_id: Uuid, cached: bool) -> Result<GitDiff, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        Ok(repository_diff_for_scope(
            &self.catalog,
            info.scope().ok_or(GitWorktreeError::Conflict)?,
            &info.path,
            cached,
        )?)
    }

    pub fn linked_switch_branch(
        &self,
        worktree_id: Uuid,
        name: &str,
    ) -> Result<GitBranchInfo, RepositoryError> {
        let info = self.resume_linked_worktree(worktree_id)?;
        let scope = info.scope().ok_or(GitWorktreeError::Conflict)?;
        match switch_same_tree_branch_for_scope(&self.catalog, scope, name) {
            Ok(branch) => Ok(branch),
            Err(HistoryError::CheckoutRequired | HistoryError::NoHead) => Ok(
                begin_switch_for_scope(&self.catalog, scope, &info.path, &self.directory, name)?,
            ),
            Err(error) => Err(error.into()),
        }
    }

    pub fn stage_file(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<GitIndexEntry, RepositoryError> {
        self.resume_checkout()?;
        let relative = relative_path.as_ref();
        let entry = stage_file(&self.catalog, self.repository_id, &self.root, relative)?;
        mark_merge_resolved(
            &self.catalog,
            self.repository_id,
            &stage_path_key(relative)?,
        )?;
        Ok(entry)
    }

    /// Like `git add <path>`, capture a present file or symlink, or stage the
    /// deletion of a missing indexed path. Unsupported objects are not deletions.
    pub fn add_path(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<Option<GitIndexEntry>, RepositoryError> {
        self.resume_checkout()?;
        let relative = relative_path.as_ref();
        stage_path_key(relative)?;
        let mut parent = PinnedDirectory::open(&self.root)?;
        for component in relative
            .parent()
            .ok_or(StageError::UnsafePath)?
            .components()
        {
            let Component::Normal(name) = component else {
                return Err(StageError::UnsafePath.into());
            };
            match parent.open_child_directory(name)? {
                Some(next) => parent = next,
                None => return self.stage_missing_path(relative),
            }
        }
        let name = relative.file_name().ok_or(StageError::UnsafePath)?;
        let symlink = match parent.read_child_symlink(name) {
            Ok(found) => found.is_some(),
            Err(AnchorError::UnsupportedObject(_)) => false,
            Err(error) => return Err(error.into()),
        };
        if symlink {
            let entry = stage_symlink(
                &self.catalog,
                self.repository_id,
                &self.root,
                &self.directory,
                relative,
            )?;
            mark_merge_resolved(
                &self.catalog,
                self.repository_id,
                &stage_path_key(relative)?,
            )?;
            return Ok(Some(entry));
        }
        if parent.open_child_file(name)?.is_some() {
            Ok(Some(self.stage_file(relative)?))
        } else {
            self.stage_missing_path(relative)
        }
    }

    fn stage_missing_path(
        &self,
        relative: &Path,
    ) -> Result<Option<GitIndexEntry>, RepositoryError> {
        let path = stage_path_key(relative)?;
        let removed = self.remove_cached(relative)?;
        let conflict = load_merge_session(&self.catalog, self.repository_id)?
            .is_some_and(|(session, _)| session.conflicts.binary_search(&path).is_ok());
        if !removed && !conflict {
            return Err(StageError::MissingUntrackedPath.into());
        }
        if conflict {
            mark_merge_resolved(&self.catalog, self.repository_id, &path)?;
        }
        Ok(None)
    }

    pub fn remove_cached(&self, relative_path: impl AsRef<Path>) -> Result<bool, RepositoryError> {
        self.resume_checkout()?;
        let relative = relative_path.as_ref();
        let removed = remove_cached(&self.catalog, self.repository_id, relative)?;
        if removed {
            unmark_merge_resolved(
                &self.catalog,
                self.repository_id,
                &stage_path_key(relative)?,
            )?;
        }
        Ok(removed)
    }

    pub fn resume_pending_stages(&self) -> Result<Vec<GitIndexEntry>, RepositoryError> {
        self.resume_checkout()?;
        let paths = pending_stage_paths(&self.catalog, self.repository_id)?;
        let entries = resume_pending_stages(&self.catalog, self.repository_id)?;
        for path in paths {
            mark_merge_resolved(&self.catalog, self.repository_id, &path)?;
        }
        Ok(entries)
    }

    pub fn abandon_pending_stage(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<bool, RepositoryError> {
        self.resume_checkout()?;
        Ok(abandon_pending_stage(
            &self.catalog,
            self.repository_id,
            relative_path,
        )?)
    }

    pub fn staged_entry(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<Option<GitIndexEntry>, RepositoryError> {
        self.resume_checkout()?;
        Ok(staged_entry(
            &self.catalog,
            self.repository_id,
            relative_path,
        )?)
    }

    pub fn anchors_for_oid(&self, oid: Oid) -> Result<Vec<FileAnchorManifest>, RepositoryError> {
        self.resume_checkout()?;
        Ok(anchors_for_oid(&self.catalog, self.repository_id, oid)?)
    }

    pub fn commit(
        &self,
        author_name: &str,
        author_email: &str,
        message: &str,
    ) -> Result<GitCommitInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(commit_index(
            &self.catalog,
            self.repository_id,
            author_name,
            author_email,
            message,
        )?)
    }

    pub fn log(&self, limit: usize) -> Result<Vec<GitLogEntry>, RepositoryError> {
        self.resume_checkout()?;
        Ok(log_history(&self.catalog, self.repository_id, limit)?)
    }

    pub fn branches(&self) -> Result<Vec<GitBranchInfo>, RepositoryError> {
        self.resume_checkout()?;
        Ok(list_branches(&self.catalog, self.repository_id)?)
    }

    pub fn remote_branches(&self) -> Result<Vec<GitRemoteBranchInfo>, RepositoryError> {
        self.resume_checkout()?;
        Ok(list_remote_branches(&self.catalog, self.repository_id)?)
    }

    pub fn commit_pins(&self) -> Result<Vec<[u8; 20]>, RepositoryError> {
        self.resume_checkout()?;
        Ok(list_commit_pins(&self.catalog, self.repository_id)?)
    }

    pub fn pin_commit(&self, oid: Oid) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
        Ok(pin_commit(&self.catalog, self.repository_id, oid)?)
    }

    pub fn unpin_commit(&self, oid: Oid) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
        Ok(unpin_commit(&self.catalog, self.repository_id, oid)?)
    }

    pub fn selected_branch(&self) -> Result<String, RepositoryError> {
        self.resume_checkout()?;
        Ok(selected_branch(&self.catalog, self.repository_id)?)
    }

    pub fn reset_index(&self, paths: &[PathBuf]) -> Result<u32, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(reset_index_for_scope(
            &self.catalog,
            crate::GitWorktreeScope::primary(self.repository_id),
            paths,
        )?)
    }

    pub fn create_branch(&self, name: &str) -> Result<GitBranchInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(create_branch(&self.catalog, self.repository_id, name)?)
    }

    pub fn create_branch_from(
        &self,
        name: &str,
        start_point: &str,
    ) -> Result<GitBranchInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(create_branch_from(
            &self.catalog,
            self.repository_id,
            name,
            start_point,
        )?)
    }

    pub fn tags(&self) -> Result<Vec<GitTagInfo>, RepositoryError> {
        self.resume_checkout()?;
        Ok(list_tags(&self.catalog, self.repository_id)?)
    }

    pub fn create_tag(
        &self,
        name: &str,
        start_point: Option<&str>,
    ) -> Result<GitTagInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(create_tag_for_scope(
            &self.catalog,
            crate::GitWorktreeScope::primary(self.repository_id),
            name,
            start_point,
        )?)
    }

    pub fn create_annotated_tag(
        &self,
        name: &str,
        start_point: Option<&str>,
        tagger_name: &str,
        tagger_email: &str,
        message: &str,
    ) -> Result<GitTagInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(create_annotated_tag_for_scope(
            &self.catalog,
            crate::GitWorktreeScope::primary(self.repository_id),
            name,
            start_point,
            tagger_name,
            tagger_email,
            message,
        )?)
    }

    pub fn delete_tag(&self, name: &str) -> Result<GitTagInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(delete_tag(&self.catalog, self.repository_id, name)?)
    }

    pub fn delete_branch(&self, name: &str, force: bool) -> Result<GitBranchInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(delete_branch(
            &self.catalog,
            self.repository_id,
            name,
            force,
        )?)
    }

    pub fn switch_branch(&self, name: &str) -> Result<GitBranchInfo, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        match switch_same_tree_branch(&self.catalog, self.repository_id, name) {
            Ok(info) => Ok(info),
            Err(HistoryError::CheckoutRequired | HistoryError::NoHead) => Ok(begin_switch(
                &self.catalog,
                self.repository_id,
                &self.root,
                &self.directory,
                name,
            )?),
            Err(error) => Err(error.into()),
        }
    }

    fn resume_checkout(&self) -> Result<(), RepositoryError> {
        resume_pending_merge_blob(&self.catalog, self.repository_id, &self.root)?;
        Ok(resume_pending_checkout(
            &self.catalog,
            self.repository_id,
            &self.root,
            &self.directory,
        )?)
    }

    fn ensure_no_merge_session(&self) -> Result<(), RepositoryError> {
        if has_merge_session(&self.catalog, self.repository_id)? {
            return Err(MergeBlobError::PendingSession.into());
        }
        Ok(())
    }

    pub fn status(&self) -> Result<GitStatus, RepositoryError> {
        self.resume_checkout()?;
        Ok(repository_status(
            &self.catalog,
            self.repository_id,
            &self.root,
        )?)
    }

    pub fn diff(&self, cached: bool) -> Result<GitDiff, RepositoryError> {
        self.resume_checkout()?;
        Ok(repository_diff(
            &self.catalog,
            self.repository_id,
            &self.root,
            cached,
        )?)
    }

    pub fn export_graph_source(&self) -> Result<GitGraphSource, RepositoryError> {
        self.resume_checkout()?;
        Ok(export_graph_source(&self.catalog, self.repository_id)?)
    }

    pub fn export_to_git_repository(
        &self,
        destination: impl AsRef<Path>,
        advertised: &[GitBranchInfo],
    ) -> Result<u32, RepositoryError> {
        self.resume_checkout()?;
        Ok(export_graph_to_git_repository(
            &self.catalog,
            self.repository_id,
            &self.root,
            destination.as_ref(),
            advertised,
            None,
        )?)
    }

    pub fn export_to_git_repository_with_tags(
        &self,
        destination: impl AsRef<Path>,
        advertised_branches: &[GitBranchInfo],
        advertised_tags: &[GitTagInfo],
    ) -> Result<u32, RepositoryError> {
        self.resume_checkout()?;
        Ok(export_graph_to_git_repository(
            &self.catalog,
            self.repository_id,
            &self.root,
            destination.as_ref(),
            advertised_branches,
            Some(advertised_tags),
        )?)
    }

    /// The daemon supplies signed-revision pins after checking in-flight work.
    pub fn prune_unreachable(
        &self,
        protected: &GitPruneRoots,
    ) -> Result<GitPruneReport, RepositoryError> {
        self.resume_checkout()?;
        Ok(prune_unreachable(
            &self.catalog,
            self.repository_id,
            protected,
        )?)
    }

    pub fn push_current_branch_to_bare(
        &self,
        destination: impl AsRef<Path>,
    ) -> Result<Oid, RepositoryError> {
        self.resume_checkout()?;
        Ok(push_current_branch_to_bare(
            &self.catalog,
            self.repository_id,
            &self.root,
            destination.as_ref(),
            &self.selected_branch()?,
        )?)
    }

    pub fn push_tag_to_bare(
        &self,
        destination: impl AsRef<Path>,
        name: &str,
    ) -> Result<Oid, RepositoryError> {
        self.resume_checkout()?;
        Ok(push_tag_to_bare(
            &self.catalog,
            self.repository_id,
            &self.root,
            destination.as_ref(),
            name,
        )?)
    }

    /// Import remote branches without changing the selected HEAD, index, or
    /// working tree. Interrupted imports resume from the durable fetch intent.
    pub fn fetch_bare(&self, source: impl AsRef<Path>) -> Result<usize, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(fetch_bare(
            &self.catalog,
            self.repository_id,
            &self.root,
            source.as_ref(),
        )?)
    }

    pub fn receive_pushed_branch(
        &self,
        source_git_directory: impl AsRef<Path>,
        target_branch: &str,
        target_oid: [u8; 20],
        expected_old: Option<[u8; 20]>,
    ) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(import_pushed_branch(
            &self.catalog,
            self.repository_id,
            &self.root,
            source_git_directory.as_ref(),
            target_branch,
            target_oid,
            expected_old,
        )?)
    }

    pub fn receive_pushed_tag(
        &self,
        source_git_directory: impl AsRef<Path>,
        target_tag: &str,
        target_oid: [u8; 20],
        expected_old: Option<[u8; 20]>,
    ) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(import_pushed_tag(
            &self.catalog,
            self.repository_id,
            &self.root,
            source_git_directory.as_ref(),
            target_tag,
            target_oid,
            expected_old,
        )?)
    }

    /// Fetch origin and merge it through the replayable checkout transition.
    pub fn pull_bare(
        &self,
        source: impl AsRef<Path>,
        author_name: &str,
        author_email: &str,
    ) -> Result<Oid, RepositoryError> {
        self.fetch_bare(source)?;
        Ok(begin_pull(
            &self.catalog,
            self.repository_id,
            &self.root,
            &self.directory,
            author_name,
            author_email,
        )?)
    }

    /// Merge a local branch, publishing a two-parent commit for disjoint paths.
    pub fn merge_branch(
        &self,
        branch: &str,
        author_name: &str,
        author_email: &str,
    ) -> Result<Oid, RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(begin_merge_branch(
            &self.catalog,
            self.repository_id,
            &self.root,
            &self.directory,
            branch,
            author_name,
            author_email,
        )?)
    }

    /// Finish a conflicted merge using explicitly staged resolution bytes.
    pub fn merge_continue(&self) -> Result<Oid, RepositoryError> {
        self.resume_checkout()?;
        Ok(continue_merge(
            &self.catalog,
            self.repository_id,
            &self.root,
            &self.directory,
        )?)
    }

    /// A conflict session does not modify the worktree; abort only drops that
    /// pending merge. User edits and staged entries remain untouched.
    pub fn merge_abort(&self) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
        let (_, encoded) = load_merge_session(&self.catalog, self.repository_id)?
            .ok_or(MergeBlobError::MissingSession)?;
        self.catalog.delete_record_if_value(
            &session_kind(self.repository_id),
            session_key(),
            &encoded,
        )?;
        Ok(())
    }

    pub fn import_backup(
        &self,
        descriptor: &crate::GitBackupDescriptor,
        anchors: &[FileAnchorManifest],
    ) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
        self.ensure_no_merge_session()?;
        Ok(import_graph_backup(
            &self.catalog,
            self.repository_id,
            descriptor,
            anchors,
        )?)
    }

    pub fn catalog_directory_identity(&self) -> Result<mb_store::NativeFileId, RepositoryError> {
        Ok(self.directory.identity()?)
    }
}

fn require_private_catalog(directory: &PinnedDirectory) -> Result<(), RepositoryError> {
    let metadata = directory.as_file().metadata()?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o077 != 0 {
        return Err(RepositoryError::Conflict);
    }
    Ok(())
}

fn initialization_intent_bytes(repository_id: Uuid) -> Vec<u8> {
    format!("{INITIALIZATION_MAGIC}{repository_id}\n").into_bytes()
}

fn read_marker(
    directory: &PinnedDirectory,
    name: &str,
) -> Result<Option<Vec<u8>>, RepositoryError> {
    let Some(mut file) = directory.open_child_file(name)? else {
        return Ok(None);
    };
    if file.metadata()?.len() > MAX_MARKER_BYTES {
        return Err(RepositoryError::Conflict);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(bytes))
}

fn cleanup_staged_markers(directory: &PinnedDirectory) -> Result<(), RepositoryError> {
    for entry in fs::read_dir(directory.descriptor_path())? {
        let name = entry?.file_name();
        if name.as_bytes().starts_with(TEMP_MARKER_PREFIX.as_bytes()) {
            directory.remove_child_file(&name)?;
        }
    }
    directory.sync_all()?;
    Ok(())
}

fn require_empty_or_staged_marker_directory(
    directory: &PinnedDirectory,
) -> Result<(), RepositoryError> {
    for entry in fs::read_dir(directory.descriptor_path())? {
        let name = entry?.file_name();
        if name.as_bytes().starts_with(TEMP_MARKER_PREFIX.as_bytes()) {
            directory.remove_child_file(&name)?;
        } else {
            return Err(RepositoryError::Conflict);
        }
    }
    directory.sync_all()?;
    Ok(())
}

fn publish_marker(
    directory: &PinnedDirectory,
    final_name: &str,
    bytes: &[u8],
) -> Result<(), RepositoryError> {
    let temporary_name = format!("{TEMP_MARKER_PREFIX}{}", Uuid::new_v4());
    let mut file = directory.create_child_file(&temporary_name)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    directory.rename_child_no_replace(&temporary_name, final_name)?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use mb_store::{GIT_CATALOG_DIRECTORY, git_catalog_marker};

    use super::*;

    #[test]
    fn repository_init_reopens_and_refuses_missing_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        fs::create_dir(&root).unwrap();
        let repository_id = Uuid::new_v4();
        let key = [9_u8; 32];
        let repo = GitRepository::init(&root, repository_id, &key).unwrap();
        assert_eq!(repo.id(), repository_id);
        assert_eq!(git_catalog_marker(&root).unwrap(), Some(repository_id));
        assert_eq!(
            repo.catalog_directory_identity().unwrap().filesystem_id,
            mb_store::filesystem_identity(&root).unwrap().stable_id
        );
        drop(repo);
        let repo = GitRepository::open(&root, repository_id, &key).unwrap();
        assert_eq!(repo.root(), root);
        drop(repo);
        let catalog = root.join(GIT_CATALOG_DIRECTORY);
        fs::remove_file(catalog.join(CATALOG_DATABASE)).unwrap();
        assert!(GitRepository::open(&root, repository_id, &key).is_err());
        assert!(GitRepository::init(&root, repository_id, &key).is_err());
    }

    #[test]
    fn interrupted_initialization_resumes_only_its_owned_intent() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let catalog = root.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir_all(&catalog).unwrap();
        fs::set_permissions(&catalog, fs::Permissions::from_mode(0o700)).unwrap();
        let repository_id = Uuid::new_v4();
        fs::write(
            catalog.join(INITIALIZATION_INTENT),
            initialization_intent_bytes(repository_id),
        )
        .unwrap();
        let repo = GitRepository::init(&root, repository_id, &[7_u8; 32]).unwrap();
        assert_eq!(repo.id(), repository_id);
        assert!(!catalog.join(INITIALIZATION_INTENT).exists());
        drop(repo);

        let unrelated = temp.path().join("unrelated");
        let unrelated_catalog = unrelated.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir_all(&unrelated_catalog).unwrap();
        fs::set_permissions(&unrelated_catalog, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(unrelated_catalog.join("user-file"), b"must be preserved").unwrap();
        assert!(GitRepository::init(&unrelated, Uuid::new_v4(), &[8_u8; 32]).is_err());
        assert_eq!(
            fs::read(unrelated_catalog.join("user-file")).unwrap(),
            b"must be preserved"
        );
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn fetched_non_main_branch_can_be_created_and_checked_out_from_unborn_head() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-remote-branch-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(source_root.join("dir")).unwrap();
        let remote = git2::Repository::init_bare(&bare_root).unwrap();
        let file = remote.blob(b"raw\r\nbytes\0").unwrap();
        let link = remote.blob(b"dir/tracked").unwrap();
        let mut nested_builder = remote.treebuilder(None).unwrap();
        nested_builder.insert("tracked", file, 0o100644).unwrap();
        let nested_oid = nested_builder.write().unwrap();
        let mut root_builder = remote.treebuilder(None).unwrap();
        root_builder.insert("dir", nested_oid, 0o040000).unwrap();
        root_builder.insert("link", link, 0o120000).unwrap();
        let tree = remote.find_tree(root_builder.write().unwrap()).unwrap();
        let signature = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let commit = remote
            .commit(
                Some("refs/heads/topic"),
                &signature,
                &signature,
                "topic",
                &tree,
                &[],
            )
            .unwrap();

        let repository_id = Uuid::new_v4();
        let key = [93_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.fetch_bare(&bare_root).unwrap(), 1);
        assert!(local.branches().unwrap().is_empty());
        let remotes = local.remote_branches().unwrap();
        assert_eq!(remotes.len(), 1);
        assert_eq!(remotes[0].name, "origin/topic");
        assert_eq!(remotes[0].oid.as_slice(), commit.as_bytes());
        assert!(matches!(
            local.create_branch_from("main", "origin/topic"),
            Err(RepositoryError::History(
                crate::HistoryError::UnbornSelectedBranch
            ))
        ));
        let created = local.create_branch_from("topic", "origin/topic").unwrap();
        assert_eq!(created.oid.as_slice(), commit.as_bytes());
        assert!(!created.current);
        assert_eq!(local.selected_branch().unwrap(), "main");

        fs::write(source_root.join("dir/tracked"), b"untracked collision").unwrap();
        assert!(matches!(
            local.switch_branch("topic"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(
            fs::read(source_root.join("dir/tracked")).unwrap(),
            b"untracked collision"
        );
        assert_eq!(local.selected_branch().unwrap(), "main");
        fs::remove_file(source_root.join("dir/tracked")).unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("unborn switch crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local.switch_branch("topic").unwrap();
        }));
        assert!(interrupted.is_err());
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.selected_branch().unwrap(), "topic");
        assert_eq!(
            local.status().unwrap().head_oid.unwrap().as_slice(),
            commit.as_bytes()
        );
        assert_eq!(
            fs::read(source_root.join("dir/tracked")).unwrap(),
            b"raw\r\nbytes\0"
        );
        assert_eq!(
            fs::read_link(source_root.join("link"))
                .unwrap()
                .as_os_str()
                .as_bytes(),
            b"dir/tracked"
        );
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        drop(tree);
        drop(root_builder);
        drop(nested_builder);
        drop(remote);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn content_merge_captures_raw_result_and_replays_interrupted_blob_publication() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-content-merge-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        let base_bytes = b"first\r\nsecond\nthird\r\nfourth\nfifth\r\n";
        let our_bytes = b"our first\r\nsecond\nthird\r\nfourth\nfifth\r\n";
        let their_bytes = b"first\r\nsecond\nthird\r\nfourth\ntheir fifth\r\n";
        let merged_bytes = b"our first\r\nsecond\nthird\r\nfourth\ntheir fifth\r\n";
        fs::write(source_root.join("tracked"), base_bytes).unwrap();
        let repository_id = Uuid::new_v4();
        let key = [95_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("tracked"), their_bytes).unwrap();
        local.stage_file("tracked").unwrap();
        let topic = local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();
        fs::write(source_root.join("tracked"), our_bytes).unwrap();
        local.stage_file("tracked").unwrap();
        let main = local.commit("Author", "a@example.test", "main").unwrap();

        crate::merge::set_after_merge_blob_capture_hook(Box::new(|| panic!("blob capture crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local
                .merge_branch("topic", "Author", "a@example.test")
                .unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/heads/main").unwrap(),
            Some(Oid::from_bytes(&main.oid).unwrap())
        );
        assert_eq!(fs::read(source_root.join("tracked")).unwrap(), our_bytes);
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        let merged_blob_oid = Oid::hash_object(git2::ObjectType::Blob, merged_bytes).unwrap();
        assert_eq!(local.anchors_for_oid(merged_blob_oid).unwrap().len(), 1);
        assert_eq!(local.status().unwrap().head_oid, Some(main.oid));
        let merged = local
            .merge_branch("topic", "Author", "a@example.test")
            .unwrap();
        assert_eq!(fs::read(source_root.join("tracked")).unwrap(), merged_bytes);
        assert_eq!(local.anchors_for_oid(merged_blob_oid).unwrap().len(), 1);
        assert_eq!(
            local.log(1).unwrap()[0].parent_oids,
            vec![main.oid, topic.oid]
        );
        git2::Repository::init_bare(&bare_root).unwrap();
        local.push_current_branch_to_bare(&bare_root).unwrap();
        let remote = git2::Repository::open_bare(&bare_root).unwrap();
        let remote_commit = remote.find_commit(merged).unwrap();
        assert_eq!(
            remote
                .find_blob(
                    remote_commit
                        .tree()
                        .unwrap()
                        .get_name("tracked")
                        .unwrap()
                        .id()
                )
                .unwrap()
                .content(),
            merged_bytes
        );
        let graph = local.export_graph_source().unwrap();
        drop(local);
        drop(remote_commit);
        drop(remote);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn disjoint_branch_merge_replays_two_parent_commit_without_copying_blobs() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-disjoint-merge-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("left"), b"left\r\nbase\0").unwrap();
        fs::write(source_root.join("right"), b"right\nbase\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [94_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        local.stage_file("left").unwrap();
        local.stage_file("right").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("right"), b"right\r\nnew\0").unwrap();
        local.stage_file("right").unwrap();
        let topic = local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();
        fs::write(source_root.join("left"), b"left\nnew\0").unwrap();
        local.stage_file("left").unwrap();
        let main = local.commit("Author", "a@example.test", "main").unwrap();
        let before = local.export_graph_source().unwrap();
        let blob_count = before.blobs.len();

        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("merge crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local
                .merge_branch("topic", "Author", "a@example.test")
                .unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/heads/main").unwrap(),
            Some(Oid::from_bytes(&main.oid).unwrap())
        );
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        let merged = local.status().unwrap().head_oid.unwrap();
        assert_ne!(merged, main.oid);
        assert_ne!(merged, topic.oid);
        assert_eq!(fs::read(source_root.join("left")).unwrap(), b"left\nnew\0");
        assert_eq!(
            fs::read(source_root.join("right")).unwrap(),
            b"right\r\nnew\0"
        );
        assert_eq!(
            local.log(1).unwrap()[0].parent_oids,
            vec![main.oid, topic.oid]
        );
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/heads/topic").unwrap(),
            Some(Oid::from_bytes(&topic.oid).unwrap())
        );
        assert_eq!(local.export_graph_source().unwrap().blobs.len(), blob_count);
        assert_eq!(
            local
                .merge_branch("topic", "Author", "a@example.test")
                .unwrap()
                .as_bytes(),
            merged
        );
        git2::Repository::init_bare(&bare_root).unwrap();
        local.push_current_branch_to_bare(&bare_root).unwrap();
        let remote = git2::Repository::open_bare(&bare_root).unwrap();
        let remote_commit = remote
            .find_commit(Oid::from_bytes(&merged).unwrap())
            .unwrap();
        assert_eq!(remote_commit.parent_id(0).unwrap().as_bytes(), main.oid);
        assert_eq!(remote_commit.parent_id(1).unwrap().as_bytes(), topic.oid);
        assert_eq!(
            remote
                .find_blob(
                    remote_commit
                        .tree()
                        .unwrap()
                        .get_name("right")
                        .unwrap()
                        .id()
                )
                .unwrap()
                .content(),
            b"right\r\nnew\0"
        );
        let graph = local.export_graph_source().unwrap();
        drop(local);
        drop(remote_commit);
        drop(remote);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn scoped_status_and_diff_keep_linked_changes_out_of_primary() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-scope-status-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::write(primary_root.join("tracked"), b"base\r\n").unwrap();
        fs::write(linked_root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [99_u8; 32];
        let local = GitRepository::init(&primary_root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        let base = local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        let scope = crate::GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        crate::head::store_selected_branch_for_scope(&local.catalog, scope, "topic").unwrap();
        crate::stage::stage_file_for_scope(&local.catalog, scope, &linked_root, "tracked").unwrap();
        let linked_status =
            crate::status::repository_status_for_scope(&local.catalog, scope, &linked_root)
                .unwrap();
        assert_eq!(linked_status.branch, "topic");
        assert!(linked_status.changes.is_empty());
        assert_eq!(local.status().unwrap().branch, "main");
        assert!(local.status().unwrap().changes.is_empty());
        assert!(matches!(
            crate::checkout::begin_switch_for_scope(
                &local.catalog,
                scope,
                &linked_root,
                &local.directory,
                "main",
            ),
            Err(crate::CheckoutError::BranchCheckedOutElsewhere)
        ));

        fs::write(linked_root.join("tracked"), b"linked\nbytes\n").unwrap();
        let linked_status =
            crate::status::repository_status_for_scope(&local.catalog, scope, &linked_root)
                .unwrap();
        assert_eq!(
            linked_status.changes[0].worktree,
            Some(crate::GitChange::Modified)
        );
        assert!(local.status().unwrap().changes.is_empty());
        let linked_staged =
            crate::stage::stage_file_for_scope(&local.catalog, scope, &linked_root, "tracked")
                .unwrap();
        let linked_status =
            crate::status::repository_status_for_scope(&local.catalog, scope, &linked_root)
                .unwrap();
        assert_eq!(
            linked_status.changes[0].staged,
            Some(crate::GitChange::Modified)
        );
        assert_eq!(linked_status.changes[0].worktree, None);
        assert!(local.status().unwrap().changes.is_empty());
        let linked_diff =
            crate::diff::repository_diff_for_scope(&local.catalog, scope, &linked_root, true)
                .unwrap();
        assert!(
            linked_diff
                .patch
                .windows(b"+linked".len())
                .any(|w| w == b"+linked")
        );
        assert!(local.diff(true).unwrap().patch.is_empty());

        let linked_commit = crate::history::commit_index_for_scope(
            &local.catalog,
            scope,
            "Author",
            "a@example.test",
            "linked commit",
        )
        .unwrap();
        assert_eq!(linked_commit.branch, "topic");
        assert_eq!(linked_commit.parent_oid, Some(base.oid));
        assert_eq!(
            crate::status::repository_status_for_scope(&local.catalog, scope, &linked_root)
                .unwrap()
                .head_oid,
            Some(linked_commit.oid)
        );
        assert_eq!(local.status().unwrap().head_oid, Some(base.oid));
        assert!(local.status().unwrap().changes.is_empty());
        assert_eq!(
            crate::history::log_history_for_scope(&local.catalog, scope, 2)
                .unwrap()
                .into_iter()
                .map(|entry| entry.oid)
                .collect::<Vec<_>>(),
            vec![linked_commit.oid, base.oid]
        );
        assert_eq!(local.log(2).unwrap()[0].oid, base.oid);
        assert!(matches!(
            local.delete_branch("topic", true),
            Err(RepositoryError::History(crate::HistoryError::CurrentBranch))
        ));
        local.create_branch_from("base-copy", "main").unwrap();
        crate::checkout::begin_switch_for_scope(
            &local.catalog,
            scope,
            &linked_root,
            &local.directory,
            "base-copy",
        )
        .unwrap();
        assert_eq!(fs::read(linked_root.join("tracked")).unwrap(), b"base\r\n");
        let linked_status =
            crate::status::repository_status_for_scope(&local.catalog, scope, &linked_root)
                .unwrap();
        assert_eq!(linked_status.branch, "base-copy");
        assert_eq!(linked_status.head_oid, Some(base.oid));
        assert!(linked_status.changes.is_empty());
        assert_eq!(local.status().unwrap().branch, "main");
        assert_eq!(fs::read(primary_root.join("tracked")).unwrap(), b"base\r\n");
        assert!(matches!(
            local.switch_branch("base-copy"),
            Err(RepositoryError::History(
                crate::HistoryError::BranchCheckedOutElsewhere
            ))
        ));

        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("linked checkout crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            crate::checkout::begin_switch_for_scope(
                &local.catalog,
                scope,
                &linked_root,
                &local.directory,
                "topic",
            )
            .unwrap();
        }));
        assert!(interrupted.is_err());
        drop(local);
        let local = GitRepository::open(&primary_root, repository_id, &key).unwrap();
        let wrong_root = run_root.join("wrong-linked-root");
        fs::create_dir(&wrong_root).unwrap();
        assert!(matches!(
            crate::checkout::resume_pending_checkout_for_scope(
                &local.catalog,
                scope,
                &wrong_root,
                &local.directory,
            ),
            Err(crate::CheckoutError::IncompatibleIntent)
        ));
        crate::checkout::resume_pending_checkout_for_scope(
            &local.catalog,
            scope,
            &linked_root,
            &local.directory,
        )
        .unwrap();
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"linked\nbytes\n"
        );
        assert_eq!(local.status().unwrap().branch, "main");
        assert_eq!(fs::read(primary_root.join("tracked")).unwrap(), b"base\r\n");

        let primary = local.staged_entry("tracked").unwrap().unwrap();
        let mut anchors = std::collections::BTreeMap::new();
        for oid in [primary.oid, linked_staged.oid] {
            for anchor in crate::stage::anchors_for_oid(
                &local.catalog,
                repository_id,
                Oid::from_bytes(&oid).unwrap(),
            )
            .unwrap()
            {
                anchors.insert(anchor.anchor_id, anchor);
            }
        }
        drop(local);
        for anchor in anchors.into_values() {
            anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn linked_worktree_registration_checkouts_and_reopens_exact_bytes() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-worktree-register-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        let another_root = run_root.join("another");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::create_dir_all(&another_root).unwrap();
        fs::write(primary_root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [73_u8; 32];
        let local = GitRepository::init(&primary_root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        let base = local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(primary_root.join("tracked"), b"topic\n\0bytes\r\n").unwrap();
        local.stage_file("tracked").unwrap();
        let topic = local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();

        let linked = local.add_linked_worktree(&linked_root, "topic").unwrap();
        assert_eq!(linked.state, crate::GitWorktreeState::Ready);
        assert_eq!(
            crate::linked_worktree_marker(&linked_root).unwrap(),
            linked.scope()
        );
        assert_eq!(linked.target_branch, "topic");
        assert_eq!(local.linked_worktrees().unwrap(), vec![linked.clone()]);
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"topic\n\0bytes\r\n"
        );
        assert_eq!(fs::read(primary_root.join("tracked")).unwrap(), b"base\r\n");
        let linked_status = crate::status::repository_status_for_scope(
            &local.catalog,
            linked.scope().unwrap(),
            &linked_root,
        )
        .unwrap();
        assert_eq!(linked_status.head_oid, Some(topic.oid));
        assert!(linked_status.changes.is_empty());
        assert!(linked_status.untracked.is_empty());
        assert!(matches!(
            local.add_linked_worktree(&another_root, "topic"),
            Err(RepositoryError::Worktree(
                crate::GitWorktreeError::BranchCheckedOutElsewhere
            ))
        ));
        drop(local);

        let local = GitRepository::open(&primary_root, repository_id, &key).unwrap();
        assert_eq!(
            local.resume_linked_worktree(linked.worktree_id).unwrap(),
            linked
        );
        assert_eq!(local.status().unwrap().head_oid, Some(base.oid));
        fs::write(linked_root.join("tracked"), b"linked edit\r\n\0").unwrap();
        std::os::unix::fs::symlink("../exact\nlink", linked_root.join("symbolic")).unwrap();
        let symlink_entry = local
            .linked_add_path(linked.worktree_id, "symbolic")
            .unwrap()
            .unwrap();
        assert_eq!(symlink_entry.mode, 0o120000);
        assert!(local.staged_entry("symbolic").unwrap().is_none());
        assert!(
            local
                .linked_add_path(linked.worktree_id, "tracked")
                .unwrap()
                .is_some()
        );
        assert_eq!(
            local
                .linked_reset_index(linked.worktree_id, &[PathBuf::from("tracked")])
                .unwrap(),
            1
        );
        let status = local.linked_status(linked.worktree_id).unwrap();
        assert!(status.changes.iter().any(|change| {
            change.path == b"tracked"
                && change.staged.is_none()
                && change.worktree == Some(crate::GitChange::Modified)
        }));
        assert!(status.changes.iter().any(|change| {
            change.path == b"symbolic" && change.staged == Some(crate::GitChange::Added)
        }));
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"linked edit\r\n\0"
        );
        local
            .linked_add_path(linked.worktree_id, "tracked")
            .unwrap();
        assert!(
            !local
                .linked_diff(linked.worktree_id, true)
                .unwrap()
                .patch
                .is_empty()
        );
        let linked_commit = local
            .linked_commit(
                linked.worktree_id,
                "Author",
                "a@example.test",
                "linked edit",
            )
            .unwrap();
        assert_eq!(linked_commit.parent_oid, Some(topic.oid));
        assert_eq!(
            local.linked_log(linked.worktree_id, 1).unwrap()[0].oid,
            linked_commit.oid
        );
        let linked_tag = local
            .linked_create_tag(linked.worktree_id, "linked-v1", None)
            .unwrap();
        assert_eq!(linked_tag.oid, linked_commit.oid);
        assert_eq!(local.tags().unwrap(), vec![linked_tag]);
        local.delete_tag("linked-v1").unwrap();
        let copy = local
            .linked_create_branch(linked.worktree_id, "linked-copy")
            .unwrap();
        assert_eq!(copy.oid, linked_commit.oid);
        assert!(matches!(
            local.delete_branch("linked-copy", false),
            Err(RepositoryError::History(
                crate::HistoryError::BranchNotMerged
            ))
        ));
        assert_eq!(
            local
                .linked_delete_branch(linked.worktree_id, "linked-copy", false)
                .unwrap()
                .oid,
            linked_commit.oid
        );
        assert!(
            local
                .linked_branches(linked.worktree_id)
                .unwrap()
                .iter()
                .any(|branch| branch.name == "topic" && branch.current)
        );
        local
            .linked_create_branch_from(linked.worktree_id, "base-copy", "main")
            .unwrap();
        local
            .linked_switch_branch(linked.worktree_id, "base-copy")
            .unwrap();
        assert_eq!(fs::read(linked_root.join("tracked")).unwrap(), b"base\r\n");
        assert!(fs::symlink_metadata(linked_root.join("symbolic")).is_err());
        assert_eq!(local.status().unwrap().head_oid, Some(base.oid));
        local
            .linked_switch_branch(linked.worktree_id, "topic")
            .unwrap();
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"linked edit\r\n\0"
        );
        assert_eq!(
            fs::read_link(linked_root.join("symbolic")).unwrap(),
            PathBuf::from("../exact\nlink")
        );
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn pending_linked_worktree_reserves_branch_and_resumes_after_reopen() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-worktree-replay-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::write(primary_root.join("tracked"), b"raw\r\n\0bytes").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [83_u8; 32];
        let local = GitRepository::init(&primary_root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();

        crate::worktree::set_after_registration_hook(Box::new(|| panic!("worktree crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local.add_linked_worktree(&linked_root, "topic").unwrap();
        }));
        assert!(interrupted.is_err());
        let pending = local.linked_worktrees().unwrap().pop().unwrap();
        assert_eq!(pending.state, crate::GitWorktreeState::Preparing);
        assert!(matches!(
            local.delete_branch("topic", true),
            Err(RepositoryError::History(crate::HistoryError::CurrentBranch))
        ));
        assert!(matches!(
            local.switch_branch("topic"),
            Err(RepositoryError::History(
                crate::HistoryError::BranchCheckedOutElsewhere
            ))
        ));
        drop(local);

        let local = GitRepository::open(&primary_root, repository_id, &key).unwrap();
        let ready = local.resume_linked_worktree(pending.worktree_id).unwrap();
        assert_eq!(ready.state, crate::GitWorktreeState::Ready);
        assert_eq!(
            fs::read(linked_root.join("tracked")).unwrap(),
            b"raw\r\n\0bytes"
        );
        assert!(
            crate::status::repository_status_for_scope(
                &local.catalog,
                ready.scope().unwrap(),
                &linked_root,
            )
            .unwrap()
            .changes
            .is_empty()
        );
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn prune_waits_for_linked_stage_and_preserves_its_index_anchor() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-scope-prune-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::write(primary_root.join("tracked"), b"committed").unwrap();
        fs::write(linked_root.join("scratch"), b"linked-only\n").unwrap();
        let repository_id = Uuid::new_v4();
        let scope = crate::GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let local = GitRepository::init(&primary_root, repository_id, &[93; 32]).unwrap();
        local.stage_file("tracked").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        let graph = local.export_graph_source().unwrap();

        let path = b"scratch".to_vec();
        let entry =
            crate::stage::stage_file_for_scope(&local.catalog, scope, &linked_root, "scratch")
                .unwrap();
        let pending_kind =
            scope.local_kind("git-stage-intent-v1/", "git-worktree-stage-intent-v1/");
        local
            .catalog
            .put_record(&pending_kind, b"pending", b"test-only-pending")
            .unwrap();
        assert!(matches!(
            local.prune_unreachable(&crate::GitPruneRoots::default()),
            Err(RepositoryError::Prune(
                crate::GitPruneError::PendingOperation
            ))
        ));
        local
            .catalog
            .delete_record(&pending_kind, b"pending")
            .unwrap();
        let anchor = crate::stage::anchors_for_oid(
            &local.catalog,
            repository_id,
            Oid::from_bytes(&entry.oid).unwrap(),
        )
        .unwrap()
        .into_iter()
        .find(|anchor| anchor.anchor_id == entry.anchor_id)
        .unwrap();
        assert_eq!(
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap()
                .native_anchors_removed,
            0
        );
        assert!(anchor.open_verified().is_ok());
        local
            .catalog
            .delete_record(&crate::stage::index_kind_for_scope(scope), &path)
            .unwrap();
        assert_eq!(
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap()
                .native_anchors_removed,
            1
        );
        assert!(anchor.open_verified().is_err());
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn attributes_reject_conversion_before_stage_and_preserve_raw_checkout_bytes() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-attributes-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join(".gitattributes"), b"*.txt text=auto\n").unwrap();
        fs::write(source_root.join("payload.txt"), b"base\r\nbytes\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [97_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        assert!(matches!(
            local.stage_file("payload.txt"),
            Err(RepositoryError::Stage(StageError::Attributes(
                crate::GitAttributesError::ContentConversion
            )))
        ));
        assert!(local.staged_entry("payload.txt").unwrap().is_none());
        assert!(local.status().unwrap().pending_adds.is_empty());
        assert!(local.export_graph_source().unwrap().blobs.is_empty());

        fs::write(source_root.join(".gitattributes"), b"*.txt -text\n").unwrap();
        local.stage_file(".gitattributes").unwrap();
        local.stage_file("payload.txt").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("payload.txt"), b"topic\nraw\r\n").unwrap();
        local.stage_file("payload.txt").unwrap();
        local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();
        assert_eq!(
            fs::read(source_root.join("payload.txt")).unwrap(),
            b"base\r\nbytes\0"
        );

        fs::write(
            source_root.join(".gitattributes"),
            b"*.txt filter=convert\n",
        )
        .unwrap();
        assert!(matches!(
            local.stage_file(".gitattributes"),
            Err(RepositoryError::Stage(StageError::Attributes(
                crate::GitAttributesError::ContentConversion
            )))
        ));
        assert!(matches!(
            local.stage_file("payload.txt"),
            Err(RepositoryError::Stage(StageError::Attributes(
                crate::GitAttributesError::ContentConversion
            )))
        ));
        assert!(local.status().unwrap().pending_adds.is_empty());
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn bare_fetch_rejects_transforming_attributes_before_import() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-fetch-attributes-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        let filter_marker = run_root.join("filter-executed");
        fs::create_dir_all(&source_root).unwrap();
        let remote = git2::Repository::init_bare(&bare_root).unwrap();
        remote
            .config()
            .unwrap()
            .set_str(
                "filter.convert.smudge",
                &format!("touch {}", filter_marker.display()),
            )
            .unwrap();
        let attributes = remote.blob(b"*.txt filter=convert\n").unwrap();
        let payload = remote.blob(b"raw\r\nbytes\0").unwrap();
        let mut builder = remote.treebuilder(None).unwrap();
        builder
            .insert(".gitattributes", attributes, 0o100644)
            .unwrap();
        builder.insert("payload.txt", payload, 0o100644).unwrap();
        let tree = remote.find_tree(builder.write().unwrap()).unwrap();
        let author = git2::Signature::now("Author", "a@example.test").unwrap();
        remote
            .commit(
                Some("refs/heads/main"),
                &author,
                &author,
                "unsafe",
                &tree,
                &[],
            )
            .unwrap();
        drop(tree);
        drop(builder);
        drop(remote);
        let repository_id = Uuid::new_v4();
        let key = [98_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        assert!(matches!(
            local.fetch_bare(&bare_root),
            Err(RepositoryError::Fetch(crate::FetchError::Attributes(
                crate::GitAttributesError::ContentConversion
            )))
        ));
        assert!(local.remote_branches().unwrap().is_empty());
        assert!(local.export_graph_source().unwrap().blobs.is_empty());
        assert!(!filter_marker.exists());
        drop(local);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn deleted_file_can_resolve_a_modify_delete_merge_conflict() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-delete-conflict-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("conflict"), b"base\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [96_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        local.stage_file("conflict").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("conflict"), b"topic\n").unwrap();
        local.stage_file("conflict").unwrap();
        let topic = local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();
        fs::remove_file(source_root.join("conflict")).unwrap();
        assert!(local.add_path("conflict").unwrap().is_none());
        let main = local.commit("Author", "a@example.test", "delete").unwrap();
        assert!(matches!(
            local.merge_branch("topic", "Author", "a@example.test"),
            Err(RepositoryError::Checkout(crate::CheckoutError::MergeConflicts(paths)))
                if paths == vec![b"conflict".to_vec()]
        ));
        assert_eq!(
            local.status().unwrap().merge.unwrap().unresolved_paths,
            vec![b"conflict".to_vec()]
        );
        assert!(local.add_path("conflict").unwrap().is_none());
        assert!(
            local
                .status()
                .unwrap()
                .merge
                .unwrap()
                .unresolved_paths
                .is_empty()
        );
        fs::write(source_root.join("conflict"), b"stray bytes").unwrap();
        assert!(matches!(
            local.merge_continue(),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(local.status().unwrap().head_oid, Some(main.oid));
        fs::remove_file(source_root.join("conflict")).unwrap();
        let merged = local.merge_continue().unwrap();
        assert_eq!(
            local.status().unwrap().head_oid,
            Some(merged.as_bytes().try_into().unwrap())
        );
        assert!(local.status().unwrap().merge.is_none());
        assert!(!source_root.join("conflict").exists());
        assert_eq!(
            local.log(1).unwrap()[0].parent_oids,
            vec![main.oid, topic.oid]
        );
        assert!(local.status().unwrap().changes.is_empty());
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn conflicted_merge_continues_from_staged_bytes_after_checkout_crash() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-conflict-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("conflict"), b"base\r\n").unwrap();
        fs::write(source_root.join("source-only"), b"base\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [95_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        local.stage_file("conflict").unwrap();
        local.stage_file("source-only").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("conflict"), b"topic\r\n").unwrap();
        fs::write(source_root.join("source-only"), b"topic\n\0").unwrap();
        local.stage_file("conflict").unwrap();
        local.stage_file("source-only").unwrap();
        let topic = local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();
        fs::write(source_root.join("conflict"), b"main\n").unwrap();
        local.stage_file("conflict").unwrap();
        let main = local.commit("Author", "a@example.test", "main").unwrap();
        assert!(matches!(
            local.merge_branch("topic", "Author", "a@example.test"),
            Err(RepositoryError::Checkout(crate::CheckoutError::MergeConflicts(paths)))
                if paths == vec![b"conflict".to_vec()]
        ));
        assert_eq!(local.status().unwrap().head_oid, Some(main.oid));
        assert_eq!(fs::read(source_root.join("conflict")).unwrap(), b"main\n");
        assert!(matches!(
            local.commit("Author", "a@example.test", "blocked"),
            Err(RepositoryError::MergeBlob(MergeBlobError::PendingSession))
        ));
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(
            local.status().unwrap().merge.unwrap().unresolved_paths,
            vec![b"conflict".to_vec()]
        );
        fs::write(source_root.join("conflict"), b"resolved\r\n\0").unwrap();
        let resolution = local.stage_file("conflict").unwrap();
        assert!(
            local
                .status()
                .unwrap()
                .merge
                .unwrap()
                .unresolved_paths
                .is_empty()
        );
        local.merge_abort().unwrap();
        assert!(local.status().unwrap().merge.is_none());
        assert_eq!(local.staged_entry("conflict").unwrap(), Some(resolution));
        assert_eq!(
            fs::read(source_root.join("conflict")).unwrap(),
            b"resolved\r\n\0"
        );
        fs::write(source_root.join("conflict"), b"main\n").unwrap();
        local.stage_file("conflict").unwrap();
        assert!(matches!(
            local.merge_branch("topic", "Author", "a@example.test"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::MergeConflicts(_)
            ))
        ));
        fs::write(source_root.join("conflict"), b"resolved\r\n\0").unwrap();
        local.stage_file("conflict").unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| {
            panic!("merge continuation crash")
        }));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local.merge_continue().unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/heads/main").unwrap(),
            Some(Oid::from_bytes(&main.oid).unwrap())
        );
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        let status = local.status().unwrap();
        assert!(status.merge.is_none());
        assert!(status.changes.is_empty());
        assert_eq!(
            fs::read(source_root.join("conflict")).unwrap(),
            b"resolved\r\n\0"
        );
        assert_eq!(
            fs::read(source_root.join("source-only")).unwrap(),
            b"topic\n\0"
        );
        assert_eq!(
            local.log(1).unwrap()[0].parent_oids,
            vec![main.oid, topic.oid]
        );
        git2::Repository::init_bare(&bare_root).unwrap();
        local.push_current_branch_to_bare(&bare_root).unwrap();
        let remote = git2::Repository::open_bare(&bare_root).unwrap();
        let commit = remote
            .find_commit(Oid::from_bytes(&status.head_oid.unwrap()).unwrap())
            .unwrap();
        assert_eq!(
            remote
                .find_blob(commit.tree().unwrap().get_name("conflict").unwrap().id())
                .unwrap()
                .content(),
            b"resolved\r\n\0"
        );
        let graph = local.export_graph_source().unwrap();
        drop(commit);
        drop(remote);
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn local_branch_merge_fast_forwards_and_replays_without_moving_source_ref() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-local-merge-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [91_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        let base = local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("tracked"), b"topic\nbytes\0").unwrap();
        local.stage_file("tracked").unwrap();
        let topic = local.commit("Author", "a@example.test", "topic").unwrap();
        local.switch_branch("main").unwrap();
        assert_eq!(fs::read(source_root.join("tracked")).unwrap(), b"base\r\n");

        fs::write(source_root.join("tracked"), b"dirty local bytes").unwrap();
        assert!(matches!(
            local.merge_branch("topic", "Author", "a@example.test"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(local.status().unwrap().head_oid, Some(base.oid));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"dirty local bytes"
        );
        fs::write(source_root.join("tracked"), b"base\r\n").unwrap();

        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("merge crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local
                .merge_branch("topic", "Author", "a@example.test")
                .unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/heads/main").unwrap(),
            Some(Oid::from_bytes(&base.oid).unwrap())
        );
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(
            local.status().unwrap().head_oid.unwrap().as_slice(),
            topic.oid
        );
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"topic\nbytes\0"
        );
        assert_eq!(
            local.merge_branch("topic", "", "").unwrap().as_bytes(),
            topic.oid
        );
        let branches = local.branches().unwrap();
        assert_eq!(branches.len(), 2);
        assert!(branches.iter().any(|branch| {
            branch.name == "topic" && branch.oid == topic.oid && !branch.current
        }));
        assert!(
            branches.iter().any(|branch| {
                branch.name == "main" && branch.oid == topic.oid && branch.current
            })
        );

        fs::write(source_root.join("tracked"), b"main divergent").unwrap();
        local.stage_file("tracked").unwrap();
        let main = local
            .commit("Author", "a@example.test", "main divergent")
            .unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(source_root.join("tracked"), b"topic divergent").unwrap();
        local.stage_file("tracked").unwrap();
        let topic_divergent = local
            .commit("Author", "a@example.test", "topic divergent")
            .unwrap();
        local.switch_branch("main").unwrap();
        assert!(matches!(
            local.merge_branch("topic", "", ""),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::MissingMergeIdentity
            ))
        ));
        assert!(matches!(
            local.merge_branch("topic", "Author", "a@example.test"),
            Err(RepositoryError::Checkout(crate::CheckoutError::MergeConflicts(paths)))
                if paths == vec![b"tracked".to_vec()]
        ));
        assert_eq!(
            local.status().unwrap().merge.unwrap().unresolved_paths,
            vec![b"tracked".to_vec()]
        );
        local.merge_abort().unwrap();
        assert!(local.status().unwrap().merge.is_none());
        assert_eq!(local.status().unwrap().head_oid, Some(main.oid));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"main divergent"
        );
        assert!(matches!(
            local.delete_branch("main", true),
            Err(RepositoryError::History(crate::HistoryError::CurrentBranch))
        ));
        assert!(matches!(
            local.delete_branch("topic", false),
            Err(RepositoryError::History(
                crate::HistoryError::BranchNotMerged
            ))
        ));
        assert_eq!(local.branches().unwrap().len(), 2);
        let pin_oid = Oid::from_bytes(&topic_divergent.oid).unwrap();
        local.pin_commit(pin_oid).unwrap();
        local.pin_commit(pin_oid).unwrap();
        assert_eq!(local.commit_pins().unwrap(), vec![topic_divergent.oid]);
        let merged = local.create_branch("merged").unwrap();
        assert_eq!(local.delete_branch("merged", false).unwrap(), merged);
        let deleted = local.delete_branch("topic", true).unwrap();
        assert_eq!(deleted.name, "topic");
        let pinned_graph = local.export_graph_source().unwrap();
        assert_eq!(pinned_graph.refs.len(), 2);
        assert!(pinned_graph.refs.iter().any(|reference| {
            reference.name == format!("refs/mutualbackup/pins/{pin_oid}").as_bytes()
                && reference.oid == topic_divergent.oid
        }));
        assert!(
            pinned_graph
                .objects
                .iter()
                .any(|object| object.oid == topic_divergent.oid)
        );
        assert!(pinned_graph.blobs.len() > 1);
        assert!(matches!(
            local.merge_branch("topic", "Author", "a@example.test"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::MissingMergeBranch
            ))
        ));
        assert_eq!(local.branches().unwrap().len(), 1);
        let protected_prune = local
            .prune_unreachable(&crate::GitPruneRoots::default())
            .unwrap();
        assert_eq!(protected_prune.metadata_objects_removed, 0);
        assert_eq!(protected_prune.native_anchors_removed, 0);
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.commit_pins().unwrap(), vec![topic_divergent.oid]);
        local.unpin_commit(pin_oid).unwrap();
        assert!(local.commit_pins().unwrap().is_empty());
        assert!(matches!(
            local.unpin_commit(pin_oid),
            Err(RepositoryError::History(crate::HistoryError::PinNotFound))
        ));
        assert_eq!(base.parent_oid, None);
        let graph = local.export_graph_source().unwrap();
        assert_eq!(graph.refs.len(), 1);
        let protected = crate::GitPruneRoots {
            metadata_oids: pinned_graph
                .objects
                .iter()
                .map(|object| object.oid)
                .collect(),
            blob_oids: pinned_graph.blobs.iter().map(|blob| blob.oid).collect(),
        };
        let signed_prune = local.prune_unreachable(&protected).unwrap();
        assert_eq!(signed_prune.metadata_objects_removed, 0);
        assert_eq!(signed_prune.native_anchors_removed, 0);
        let orphan_anchors = pinned_graph
            .blobs
            .iter()
            .filter(|blob| !graph.blobs.iter().any(|live| live.oid == blob.oid))
            .map(|blob| blob.anchor.clone())
            .collect::<Vec<_>>();
        assert_eq!(orphan_anchors.len(), 1);
        crate::prune::set_after_catalog_delete_hook(Box::new(|| panic!("prune crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap();
        }));
        assert!(interrupted.is_err());
        assert!(orphan_anchors[0].open_verified().is_ok());
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert!(orphan_anchors[0].open_verified().is_err());
        assert_eq!(local.export_graph_source().unwrap(), graph);
        let report = local
            .prune_unreachable(&crate::GitPruneRoots::default())
            .unwrap();
        assert_eq!(report.native_anchors_removed, 0);
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn divergent_bare_pull_replays_two_parent_merge_without_moving_remote_ref() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-divergent-pull-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        let remote = git2::Repository::init_bare(&bare_root).unwrap();
        let signature = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let left = remote.blob(b"left\r\nbase\0").unwrap();
        let right = remote.blob(b"right\nbase\0").unwrap();
        let mut base_builder = remote.treebuilder(None).unwrap();
        base_builder.insert("left", left, 0o100644).unwrap();
        base_builder.insert("right", right, 0o100644).unwrap();
        let base_tree = remote.find_tree(base_builder.write().unwrap()).unwrap();
        let base = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "base",
                &base_tree,
                &[],
            )
            .unwrap();
        let repository_id = Uuid::new_v4();
        let key = [96_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.pull_bare(&bare_root, "", "").unwrap(), base);
        fs::write(source_root.join("left"), b"left\nlocal\0").unwrap();
        local.stage_file("left").unwrap();
        let ours = local
            .commit("Local", "local@example.invalid", "local")
            .unwrap();

        let new_right = remote.blob(b"right\r\nremote\0").unwrap();
        let mut remote_builder = remote.treebuilder(None).unwrap();
        remote_builder.insert("left", left, 0o100644).unwrap();
        remote_builder.insert("right", new_right, 0o100644).unwrap();
        let remote_tree = remote.find_tree(remote_builder.write().unwrap()).unwrap();
        let base_commit = remote.find_commit(base).unwrap();
        let theirs = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "remote",
                &remote_tree,
                &[&base_commit],
            )
            .unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("divergent pull crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local
                .pull_bare(&bare_root, "Local", "local@example.invalid")
                .unwrap();
        }));
        assert!(interrupted.is_err());
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/heads/main").unwrap(),
            Some(Oid::from_bytes(&ours.oid).unwrap())
        );
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        let merged = Oid::from_bytes(&local.status().unwrap().head_oid.unwrap()).unwrap();
        assert_ne!(merged.as_bytes(), ours.oid);
        assert_ne!(merged, theirs);
        assert_eq!(
            fs::read(source_root.join("left")).unwrap(),
            b"left\nlocal\0"
        );
        assert_eq!(
            fs::read(source_root.join("right")).unwrap(),
            b"right\r\nremote\0"
        );
        assert_eq!(
            local.log(1).unwrap()[0].parent_oids,
            vec![ours.oid, theirs.as_bytes().try_into().unwrap()]
        );
        assert_eq!(
            crate::history::ref_oid(&local.catalog, repository_id, b"refs/remotes/origin/main")
                .unwrap(),
            Some(theirs)
        );
        assert_eq!(remote.refname_to_id("refs/heads/main").unwrap(), theirs);
        assert_eq!(local.pull_bare(&bare_root, "", "").unwrap(), merged);
        local.push_current_branch_to_bare(&bare_root).unwrap();
        let exported = remote.find_commit(merged).unwrap();
        assert_eq!(exported.parent_id(0).unwrap().as_bytes(), ours.oid);
        assert_eq!(exported.parent_id(1).unwrap(), theirs);
        let graph = local.export_graph_source().unwrap();
        drop(local);
        drop(exported);
        drop(base_commit);
        drop(base_tree);
        drop(remote_tree);
        drop(base_builder);
        drop(remote_builder);
        drop(remote);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn bare_git_pull_fast_forwards_exact_bytes_and_replays_checkout() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-bare-pull-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        let remote = git2::Repository::init_bare(&bare_root).unwrap();
        let signature = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let first_blob = remote.blob(b"first\r\nbytes\0").unwrap();
        let mut first_builder = remote.treebuilder(None).unwrap();
        first_builder
            .insert("tracked", first_blob, 0o100644)
            .unwrap();
        let first_tree = remote.find_tree(first_builder.write().unwrap()).unwrap();
        let first = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "first",
                &first_tree,
                &[],
            )
            .unwrap();

        let repository_id = Uuid::new_v4();
        let key = [89_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        fs::write(source_root.join("tracked"), b"untracked collision").unwrap();
        assert!(matches!(
            local.pull_bare(&bare_root, "", ""),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"untracked collision"
        );
        assert!(local.status().unwrap().head_oid.is_none());
        fs::remove_file(source_root.join("tracked")).unwrap();
        assert_eq!(local.pull_bare(&bare_root, "", "").unwrap(), first);
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"first\r\nbytes\0"
        );
        assert_eq!(
            local.status().unwrap().head_oid.unwrap().as_slice(),
            first.as_bytes()
        );
        assert_eq!(local.pull_bare(&bare_root, "", "").unwrap(), first);

        let second_blob = remote.blob(b"second\nbytes\r\n").unwrap();
        let link_blob = remote.blob(b"missing\r\npath").unwrap();
        let mut second_builder = remote.treebuilder(None).unwrap();
        second_builder
            .insert("tracked", second_blob, 0o100755)
            .unwrap();
        second_builder.insert("link", link_blob, 0o120000).unwrap();
        let second_tree = remote.find_tree(second_builder.write().unwrap()).unwrap();
        let first_commit = remote.find_commit(first).unwrap();
        let second = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "second",
                &second_tree,
                &[&first_commit],
            )
            .unwrap();
        fs::write(source_root.join("tracked"), b"dirty local bytes").unwrap();
        assert!(matches!(
            local.pull_bare(&bare_root, "", ""),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"dirty local bytes"
        );
        assert_eq!(
            local.status().unwrap().head_oid.unwrap().as_slice(),
            first.as_bytes()
        );
        fs::write(source_root.join("tracked"), b"first\r\nbytes\0").unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("pull crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local.pull_bare(&bare_root, "", "").unwrap();
        }));
        assert!(interrupted.is_err());
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(
            local.status().unwrap().head_oid.unwrap().as_slice(),
            second.as_bytes()
        );
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"second\nbytes\r\n"
        );
        assert_eq!(
            fs::read_link(source_root.join("link"))
                .unwrap()
                .as_os_str()
                .as_bytes(),
            b"missing\r\npath"
        );

        let second_commit = remote.find_commit(second).unwrap();
        let third = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "same tree",
                &second_tree,
                &[&second_commit],
            )
            .unwrap();
        crate::checkout::set_after_checkout_commit_hook(Box::new(|| panic!("pull commit crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            local.pull_bare(&bare_root, "", "").unwrap();
        }));
        assert!(interrupted.is_err());
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(
            local.status().unwrap().head_oid.unwrap().as_slice(),
            third.as_bytes()
        );
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"second\nbytes\r\n"
        );

        let fourth_blob = remote.blob(b"remote fourth").unwrap();
        let mut fourth_builder = remote.treebuilder(None).unwrap();
        fourth_builder
            .insert("tracked", fourth_blob, 0o100644)
            .unwrap();
        let fourth_tree = remote.find_tree(fourth_builder.write().unwrap()).unwrap();
        let third_commit = remote.find_commit(third).unwrap();
        remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "fourth",
                &fourth_tree,
                &[&third_commit],
            )
            .unwrap();
        fs::write(source_root.join("tracked"), b"local third").unwrap();
        local.stage_file("tracked").unwrap();
        local
            .commit("Local", "local@example.invalid", "local third")
            .unwrap();
        assert!(matches!(
            local.pull_bare(&bare_root, "", ""),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::MissingMergeIdentity
            ))
        ));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"local third"
        );
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        drop(fourth_tree);
        drop(fourth_builder);
        drop(third_commit);
        drop(second_commit);
        drop(second_tree);
        drop(second_builder);
        drop(first_commit);
        drop(first_tree);
        drop(first_builder);
        drop(remote);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn local_bare_git_fetch_imports_packed_objects_without_changing_worktree() {
        use std::process::Command;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-bare-fetch-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        let remote = git2::Repository::init_bare(&bare_root).unwrap();
        let mut payload = vec![0x5a_u8; 2 * 1024 * 1024];
        payload.extend_from_slice(b"\r\n\0tail\n");
        let large = remote.blob(&payload).unwrap();
        let link = remote.blob(b"missing\r\npath").unwrap();
        let mut builder = remote.treebuilder(None).unwrap();
        builder.insert("large", large, 0o100644).unwrap();
        builder.insert("link", link, 0o120000).unwrap();
        let tree_oid = builder.write().unwrap();
        let tree = remote.find_tree(tree_oid).unwrap();
        let author = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let commit = remote
            .commit(
                Some("refs/heads/main"),
                &author,
                &author,
                "first",
                &tree,
                &[],
            )
            .unwrap();
        assert!(
            Command::new("git")
                .arg("--git-dir")
                .arg(&bare_root)
                .arg("gc")
                .status()
                .unwrap()
                .success()
        );

        let repository_id = Uuid::new_v4();
        let key = [83_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.fetch_bare(&bare_root).unwrap(), 1);
        assert_eq!(local.selected_branch().unwrap(), "main");
        assert!(!source_root.join("large").exists());
        let graph = local.export_graph_source().unwrap();
        assert_eq!(graph.refs.len(), 1);
        assert_eq!(graph.refs[0].name, b"refs/remotes/origin/main");
        assert_eq!(graph.refs[0].oid.as_slice(), commit.as_bytes());
        assert_eq!(graph.blobs.len(), 2);
        let large_anchor = graph
            .blobs
            .iter()
            .find(|blob| blob.oid.as_slice() == large.as_bytes())
            .unwrap();
        let link_anchor = graph
            .blobs
            .iter()
            .find(|blob| blob.oid.as_slice() == link.as_bytes())
            .unwrap();
        let mut imported_large = Vec::new();
        large_anchor
            .anchor
            .open_verified()
            .unwrap()
            .read_to_end(&mut imported_large)
            .unwrap();
        assert_eq!(imported_large, payload);
        let mut imported_link = Vec::new();
        link_anchor
            .anchor
            .open_verified()
            .unwrap()
            .read_to_end(&mut imported_link)
            .unwrap();
        assert_eq!(imported_link, b"missing\r\npath");
        assert_eq!(local.fetch_bare(&bare_root).unwrap(), 1);
        drop(local);
        let local = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.export_graph_source().unwrap(), graph);
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        drop(tree);
        drop(builder);
        drop(remote);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn fetches_exact_bytes_from_a_local_nonbare_git_worktree() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-worktree-fetch-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let stock_root = run_root.join("stock");
        fs::create_dir_all(&source_root).unwrap();
        let stock = git2::Repository::init(&stock_root).unwrap();
        let payload = b"from worktree\r\nwith\0raw\xff";
        let blob = stock.blob(payload).unwrap();
        let mut builder = stock.treebuilder(None).unwrap();
        builder.insert("tracked", blob, 0o100644).unwrap();
        let tree = stock.find_tree(builder.write().unwrap()).unwrap();
        let signature = git2::Signature::now("Stock", "stock@example.test").unwrap();
        let commit = stock
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "source",
                &tree,
                &[],
            )
            .unwrap();
        let repository_id = Uuid::new_v4();
        let key = [99_u8; 32];
        let local = GitRepository::init(&source_root, repository_id, &key).unwrap();
        assert_eq!(local.fetch_bare(&stock_root).unwrap(), 1);
        assert!(
            local
                .remote_branches()
                .unwrap()
                .iter()
                .any(|branch| branch.name == "origin/main" && branch.oid == commit.as_bytes())
        );
        assert!(!source_root.join("tracked").exists());
        assert_eq!(local.pull_bare(&stock_root, "", "").unwrap(), commit);
        assert_eq!(fs::read(source_root.join("tracked")).unwrap(), payload);
        let graph = local.export_graph_source().unwrap();
        drop(local);
        drop(tree);
        drop(builder);
        drop(stock);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn lightweight_tag_preserves_unbranched_history_until_deleted() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-tag-retention-{}", Uuid::new_v4()));
        let root = run_root.join("work");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [101_u8; 32];
        let local = GitRepository::init(&root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        let base = local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(root.join("tracked"), b"tagged\nraw\0bytes").unwrap();
        local.stage_file("tracked").unwrap();
        let tagged = local.commit("Author", "a@example.test", "topic").unwrap();
        let tag = local.create_tag("v1", None).unwrap();
        assert_eq!(tag.oid, tagged.oid);
        let alias = local.create_tag("alias", Some("v1")).unwrap();
        assert_eq!(alias.oid, tag.oid);
        local.delete_tag("alias").unwrap();
        assert!(matches!(
            local.create_tag("v1", None),
            Err(RepositoryError::History(crate::HistoryError::TagExists))
        ));
        assert!(matches!(
            local.create_tag("v1/sub", None),
            Err(RepositoryError::History(crate::HistoryError::InvalidTag))
        ));
        local.switch_branch("main").unwrap();
        local.delete_branch("topic", true).unwrap();
        assert_eq!(local.tags().unwrap(), vec![tag.clone()]);
        let graph = local.export_graph_source().unwrap();
        assert!(
            graph
                .refs
                .iter()
                .any(|reference| reference.name == b"refs/tags/v1" && reference.oid == tagged.oid)
        );
        assert!(graph.objects.iter().any(|object| object.oid == tagged.oid));
        let descriptor = crate::GitBackupDescriptor {
            format_version: 2,
            repository_id,
            refs: graph.refs.clone(),
            objects: graph.objects.clone(),
            blobs: graph
                .blobs
                .iter()
                .enumerate()
                .map(|(index, blob)| crate::GitBackupBlob {
                    oid: blob.oid,
                    logical_len: blob.anchor.logical_len,
                    data_extents: vec![crate::GitDataExtent {
                        offset: 0,
                        logical_len: blob.anchor.logical_len,
                        sectors: vec![mb_core::SectorRef {
                            id: [index as u8; 32],
                            root: [index as u8; 32],
                            logical_len: blob.anchor.logical_len as u32,
                        }],
                    }],
                })
                .collect(),
            head_branch: "main".to_owned(),
        };
        descriptor.validate().unwrap();
        let bare_root = run_root.join("stock.git");
        let stock = git2::Repository::init_bare(&bare_root).unwrap();
        assert_eq!(
            local.push_tag_to_bare(&bare_root, "v1").unwrap().as_bytes(),
            tag.oid
        );
        assert_eq!(
            stock
                .find_reference("refs/tags/v1")
                .unwrap()
                .target()
                .unwrap()
                .as_bytes(),
            tag.oid
        );
        assert_eq!(
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap()
                .native_anchors_removed,
            0
        );
        local.delete_tag("v1").unwrap();
        assert!(matches!(
            local.delete_tag("v1"),
            Err(RepositoryError::History(crate::HistoryError::TagNotFound))
        ));
        assert!(
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap()
                .native_anchors_removed
                > 0
        );
        let current = local.export_graph_source().unwrap();
        assert_eq!(current.refs.len(), 1);
        assert_eq!(current.refs[0].oid, base.oid);
        drop(local);
        for blob in current.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn annotated_tag_survives_reopen_and_retains_unbranched_history() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-annotated-tag-{}", Uuid::new_v4()));
        let root = run_root.join("work");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [105_u8; 32];
        let local = GitRepository::init(&root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        local.create_branch("topic").unwrap();
        local.switch_branch("topic").unwrap();
        fs::write(root.join("tracked"), b"tagged\r\nraw\0bytes").unwrap();
        local.stage_file("tracked").unwrap();
        let tagged = local.commit("Author", "a@example.test", "topic").unwrap();
        let tag = local
            .create_annotated_tag(
                "release",
                None,
                "Tagger",
                "tagger@example.test",
                "release notes\r\n",
            )
            .unwrap();
        assert_ne!(tag.oid, tagged.oid);
        local.status().unwrap();
        local.switch_branch("main").unwrap();
        local.delete_branch("topic", true).unwrap();
        drop(local);
        let local = GitRepository::open(&root, repository_id, &key).unwrap();
        assert_eq!(local.tags().unwrap(), vec![tag.clone()]);
        let graph = local.export_graph_source().unwrap();
        assert_eq!(graph.format_version, 2);
        assert!(
            graph
                .objects
                .iter()
                .any(|object| object.kind == 3 && object.oid == tag.oid)
        );
        assert!(graph.objects.iter().any(|object| object.oid == tagged.oid));
        let descriptor = crate::GitBackupDescriptor {
            format_version: 3,
            repository_id,
            refs: graph.refs.clone(),
            objects: graph.objects.clone(),
            blobs: graph
                .blobs
                .iter()
                .enumerate()
                .map(|(index, blob)| crate::GitBackupBlob {
                    oid: blob.oid,
                    logical_len: blob.anchor.logical_len,
                    data_extents: vec![crate::GitDataExtent {
                        offset: 0,
                        logical_len: blob.anchor.logical_len,
                        sectors: vec![mb_core::SectorRef {
                            id: [index as u8; 32],
                            root: [index as u8; 32],
                            logical_len: blob.anchor.logical_len as u32,
                        }],
                    }],
                })
                .collect(),
            head_branch: "main".to_owned(),
        };
        descriptor.validate().unwrap();
        let recovered_root = run_root.join("recovered");
        fs::create_dir_all(&recovered_root).unwrap();
        let recovered = GitRepository::init(&recovered_root, repository_id, &key).unwrap();
        let source_anchors = graph
            .blobs
            .iter()
            .map(|blob| blob.anchor.clone())
            .collect::<Vec<_>>();
        recovered
            .import_backup(&descriptor, &source_anchors)
            .unwrap();
        assert_eq!(recovered.tags().unwrap(), vec![tag.clone()]);
        assert_eq!(
            recovered.export_graph_source().unwrap().objects,
            graph.objects
        );
        drop(recovered);
        let bare_root = run_root.join("stock.git");
        let stock = git2::Repository::init_bare(&bare_root).unwrap();
        local.push_current_branch_to_bare(&bare_root).unwrap();
        assert_eq!(
            stock
                .find_tag(git2::Oid::from_bytes(&tag.oid).unwrap())
                .unwrap()
                .target_id()
                .as_bytes(),
            tagged.oid
        );
        let main_oid = local
            .branches()
            .unwrap()
            .into_iter()
            .find(|branch| branch.name == "main")
            .unwrap()
            .oid;
        let mut conflicting = stock
            .reference(
                "refs/tags/release",
                git2::Oid::from_bytes(&main_oid).unwrap(),
                false,
                "conflicting tag",
            )
            .unwrap();
        assert!(matches!(
            local.push_tag_to_bare(&bare_root, "release"),
            Err(RepositoryError::Interop(crate::GitInteropError::TagExists))
        ));
        assert_eq!(conflicting.target().unwrap().as_bytes(), main_oid);
        conflicting.delete().unwrap();
        assert_eq!(
            local
                .push_tag_to_bare(&bare_root, "release")
                .unwrap()
                .as_bytes(),
            tag.oid
        );
        assert_eq!(
            local
                .push_tag_to_bare(&bare_root, "release")
                .unwrap()
                .as_bytes(),
            tag.oid
        );
        assert_eq!(
            stock
                .find_reference("refs/tags/release")
                .unwrap()
                .target()
                .unwrap()
                .as_bytes(),
            tag.oid
        );
        assert_eq!(
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap()
                .native_anchors_removed,
            0
        );
        local.delete_tag("release").unwrap();
        assert!(
            local
                .prune_unreachable(&crate::GitPruneRoots::default())
                .unwrap()
                .native_anchors_removed
                > 0
        );
        drop(local);
        for blob in graph.blobs {
            if blob.anchor.open_verified().is_ok() {
                blob.anchor.remove().unwrap();
            }
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn exports_advertised_graph_into_stock_git_without_a_local_payload_mirror() {
        use std::process::Command;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-helper-export-{}", Uuid::new_v4()));
        let source_root = run_root.join("source");
        let stock_root = run_root.join("stock");
        fs::create_dir_all(&source_root).unwrap();
        fs::create_dir_all(&stock_root).unwrap();
        let mut bytes = vec![0_u8; 2 * 1024 * 1024 + 17];
        bytes[..7].copy_from_slice(b"raw\r\n\0\xff");
        let tail_start = bytes.len() - 5;
        bytes[tail_start..].copy_from_slice(b"tail\n");
        fs::write(source_root.join("tracked"), &bytes).unwrap();
        let repository_id = Uuid::new_v4();
        let local = GitRepository::init(&source_root, repository_id, &[93_u8; 32]).unwrap();
        let staged = local.stage_file("tracked").unwrap();
        let committed = local.commit("Author", "a@example.test", "initial").unwrap();
        let stock = git2::Repository::init(&stock_root).unwrap();
        let mut stale = local.branches().unwrap();
        stale[0].oid = [0; 20];
        assert!(
            local
                .export_to_git_repository(stock.path(), &stale)
                .is_err()
        );
        assert!(
            !stock
                .odb()
                .unwrap()
                .exists(Oid::from_bytes(&staged.oid).unwrap())
        );
        let advertised = local.branches().unwrap();
        assert_eq!(
            local
                .export_to_git_repository(stock.path(), &advertised)
                .unwrap(),
            3
        );
        let output = Command::new("git")
            .arg("-C")
            .arg(&stock_root)
            .args([
                "cat-file",
                "blob",
                &Oid::from_bytes(&staged.oid).unwrap().to_string(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, bytes);
        let output = Command::new("git")
            .arg("-C")
            .arg(&stock_root)
            .args([
                "update-ref",
                "refs/heads/imported",
                &Oid::from_bytes(&committed.oid).unwrap().to_string(),
            ])
            .output()
            .unwrap();
        assert!(output.status.success());
        let graph = local.export_graph_source().unwrap();
        drop(stock);
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn local_bare_git_push_streams_exact_blobs_and_rejects_divergence() {
        use std::os::unix::fs::symlink;
        use std::process::Command;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-bare-push-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let bare_root = run_root.join("remote.git");
        fs::create_dir_all(&source_root).unwrap();
        git2::Repository::init_bare(&bare_root).unwrap();
        let bytes = vec![0x5a; 2 * 1024 * 1024];
        fs::write(source_root.join("large"), &bytes).unwrap();
        symlink("missing\r\npath", source_root.join("link")).unwrap();
        let repo = GitRepository::init(&source_root, Uuid::new_v4(), &[52_u8; 32]).unwrap();
        let large = repo.add_path("large").unwrap().unwrap();
        let link = repo.add_path("link").unwrap().unwrap();
        let first = repo
            .commit("Test", "test@example.invalid", "first")
            .unwrap();
        let pushed = repo.push_current_branch_to_bare(&bare_root).unwrap();
        assert_eq!(pushed.as_bytes(), first.oid);
        assert_eq!(
            repo.push_current_branch_to_bare(&bare_root).unwrap(),
            pushed
        );
        assert!(
            Command::new("git")
                .arg("--git-dir")
                .arg(&bare_root)
                .arg("gc")
                .status()
                .unwrap()
                .success()
        );
        assert_eq!(
            repo.push_current_branch_to_bare(&bare_root).unwrap(),
            pushed
        );
        let remote = git2::Repository::open_bare(&bare_root).unwrap();
        assert_eq!(
            remote.find_reference("refs/heads/main").unwrap().target(),
            Some(pushed)
        );
        assert_eq!(
            remote
                .find_commit(pushed)
                .unwrap()
                .tree()
                .unwrap()
                .get_name("link")
                .unwrap()
                .filemode(),
            0o120000
        );
        let stock_blob = Command::new("git")
            .arg("--git-dir")
            .arg(&bare_root)
            .arg("cat-file")
            .arg("blob")
            .arg(Oid::from_bytes(&link.oid).unwrap().to_string())
            .output()
            .unwrap();
        assert!(stock_blob.status.success());
        assert_eq!(stock_blob.stdout, b"missing\r\npath");
        let stock_large = Command::new("git")
            .arg("--git-dir")
            .arg(&bare_root)
            .arg("cat-file")
            .arg("-s")
            .arg(Oid::from_bytes(&large.oid).unwrap().to_string())
            .output()
            .unwrap();
        assert!(stock_large.status.success());
        assert_eq!(stock_large.stdout, b"2097152\n");
        fs::write(source_root.join("large"), b"second\r\n").unwrap();
        repo.add_path("large").unwrap();
        let second = repo
            .commit("Test", "test@example.invalid", "second")
            .unwrap();
        assert_eq!(
            repo.push_current_branch_to_bare(&bare_root)
                .unwrap()
                .as_bytes(),
            second.oid
        );

        let signature = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let base = remote.find_commit(pushed).unwrap();
        let tree = base.tree().unwrap();
        let divergent = remote
            .commit(None, &signature, &signature, "diverged", &tree, &[&base])
            .unwrap();
        remote
            .reference("refs/heads/main", divergent, true, "diverge")
            .unwrap();
        assert!(matches!(
            repo.push_current_branch_to_bare(&bare_root),
            Err(RepositoryError::Interop(
                crate::GitInteropError::NonFastForward
            ))
        ));
        assert_eq!(
            remote.find_reference("refs/heads/main").unwrap().target(),
            Some(divergent)
        );
        let graph = repo.export_graph_source().unwrap();
        drop(repo);
        drop(tree);
        drop(base);
        drop(remote);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn symlink_add_preserves_raw_target_bytes_and_commits_git_mode() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-symlink-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        let target = std::ffi::OsStr::from_bytes(b"../outside-\xff\r\n");
        symlink(target, source_root.join("linked")).unwrap();
        let repository_id = Uuid::new_v4();
        let key = [41_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        let entry = repo.add_path("linked").unwrap().unwrap();
        assert_eq!(entry.mode, 0o120000);
        let oid = Oid::from_bytes(&entry.oid).unwrap();
        assert_eq!(
            oid,
            Oid::hash_object(git2::ObjectType::Blob, target.as_bytes()).unwrap()
        );
        let anchors = repo.anchors_for_oid(oid).unwrap();
        assert_eq!(anchors.len(), 1);
        let mut anchor = anchors[0].open_verified().unwrap();
        let mut actual = Vec::new();
        anchor.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, target.as_bytes());
        assert!(
            repo.status()
                .unwrap()
                .changes
                .iter()
                .any(|change| { change.path == b"linked" && change.worktree.is_none() })
        );
        assert!(
            repo.diff(true)
                .unwrap()
                .patch
                .windows(6)
                .any(|part| part == b"120000")
        );
        repo.commit("Test", "test@example.invalid", "add link")
            .unwrap();
        assert!(repo.status().unwrap().changes.is_empty());
        repo.create_branch("topic").unwrap();
        fs::remove_file(source_root.join("linked")).unwrap();
        symlink("replacement", source_root.join("linked")).unwrap();
        assert_eq!(
            repo.status().unwrap().changes[0].worktree,
            Some(crate::GitChange::Modified)
        );
        assert!(
            repo.diff(false)
                .unwrap()
                .patch
                .windows(11)
                .any(|part| part == b"replacement")
        );
        let replacement = repo.add_path("linked").unwrap().unwrap();
        repo.switch_branch("topic").unwrap();
        repo.commit("Test", "test@example.invalid", "change link")
            .unwrap();
        repo.switch_branch("main").unwrap();
        assert_eq!(fs::read_link(source_root.join("linked")).unwrap(), target);
        assert!(repo.status().unwrap().changes.is_empty());
        repo.switch_branch("topic").unwrap();
        assert_eq!(
            fs::read_link(source_root.join("linked")).unwrap(),
            Path::new("replacement")
        );
        assert!(repo.status().unwrap().changes.is_empty());
        fs::remove_file(source_root.join("linked")).unwrap();
        fs::write(source_root.join("linked"), b"plain file\r\n").unwrap();
        symlink("extra target", source_root.join("extra")).unwrap();
        let regular = repo.add_path("linked").unwrap().unwrap();
        let extra = repo.add_path("extra").unwrap().unwrap();
        repo.commit("Test", "test@example.invalid", "change link to file")
            .unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("simulated crash")));
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                repo.switch_branch("main").unwrap();
            }))
            .is_err()
        );
        drop(repo);
        let repo = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(repo.selected_branch().unwrap(), "main");
        assert_eq!(fs::read_link(source_root.join("linked")).unwrap(), target);
        assert!(fs::symlink_metadata(source_root.join("extra")).is_err());
        repo.switch_branch("topic").unwrap();
        assert_eq!(
            fs::read(source_root.join("linked")).unwrap(),
            b"plain file\r\n"
        );
        assert_eq!(
            fs::read_link(source_root.join("extra")).unwrap(),
            Path::new("extra target")
        );
        assert!(repo.status().unwrap().changes.is_empty());
        let replacement_anchors = repo
            .anchors_for_oid(Oid::from_bytes(&replacement.oid).unwrap())
            .unwrap();
        let regular_anchors = repo
            .anchors_for_oid(Oid::from_bytes(&regular.oid).unwrap())
            .unwrap();
        let extra_anchors = repo
            .anchors_for_oid(Oid::from_bytes(&extra.oid).unwrap())
            .unwrap();
        drop(repo);
        anchors[0].remove().unwrap();
        replacement_anchors[0].remove().unwrap();
        regular_anchors[0].remove().unwrap();
        extra_anchors[0].remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn repository_catalog_stays_outside_ordinary_source_capture() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-repository-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"line\r\nbytes\0").unwrap();
        let repository_id = Uuid::new_v4();
        let repo = GitRepository::init(&source_root, repository_id, &[17_u8; 32]).unwrap();
        let entry = repo.stage_file("tracked").unwrap();
        let oid = Oid::from_bytes(&entry.oid).unwrap();
        let anchors = repo.anchors_for_oid(oid).unwrap();
        let backup = mb_store::ReflinkAnchor::capture(&source_root).unwrap();
        let paths = backup
            .entries
            .iter()
            .map(|entry| match entry {
                mb_store::CapturedEntry::Directory { path, .. }
                | mb_store::CapturedEntry::File { path, .. }
                | mb_store::CapturedEntry::FileV2 { path, .. } => path.as_str(),
            })
            .collect::<Vec<_>>();
        assert!(paths.contains(&"tracked"));
        assert!(
            paths
                .iter()
                .all(|path| !path.starts_with(GIT_CATALOG_DIRECTORY))
        );
        backup.remove().unwrap();
        drop(repo);
        anchors[0].remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn local_commits_preserve_exact_staged_blobs_and_parentage() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-history-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(source_root.join("nested")).unwrap();
        fs::write(source_root.join("nested/tracked"), b"first\r\nbytes\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [23_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        let first_blob = repo.stage_file("nested/tracked").unwrap();
        let before_commit = repo.status().unwrap();
        assert_eq!(before_commit.changes.len(), 1);
        assert_eq!(
            before_commit.changes[0].staged,
            Some(crate::GitChange::Added)
        );
        assert_eq!(before_commit.changes[0].worktree, None);
        fs::write(source_root.join("nested/tracked"), b"second\nbytes").unwrap();
        assert_eq!(
            repo.status().unwrap().changes[0].worktree,
            Some(crate::GitChange::Modified)
        );
        let first = repo
            .commit("Test Author", "author@example.test", "first")
            .unwrap();
        assert_eq!(first.parent_oid, None);
        assert_eq!(first.branch, "main");
        assert!(matches!(
            repo.commit("Test Author", "author@example.test", "unchanged"),
            Err(RepositoryError::History(crate::HistoryError::UnchangedTree))
        ));
        drop(repo);

        let repo = GitRepository::open(&source_root, repository_id, &key).unwrap();
        fs::write(source_root.join("untracked"), b"new").unwrap();
        let after_first = repo.status().unwrap();
        assert!(
            after_first
                .changes
                .iter()
                .any(|change| change.worktree == Some(crate::GitChange::Modified))
        );
        assert_eq!(after_first.untracked, vec![b"untracked".to_vec()]);
        assert!(!after_first.history_backed_up);
        assert!(repo.remove_cached("nested/tracked").unwrap());
        assert_eq!(repo.reset_index(&[PathBuf::from("nested")]).unwrap(), 1);
        assert_eq!(
            repo.staged_entry("nested/tracked").unwrap().unwrap().oid,
            first_blob.oid
        );
        assert_eq!(
            fs::read(source_root.join("nested/tracked")).unwrap(),
            b"second\nbytes"
        );
        assert!(repo.remove_cached("nested/tracked").unwrap());
        assert_eq!(repo.reset_index(&[]).unwrap(), 1);
        assert_eq!(repo.reset_index(&[]).unwrap(), 0);
        let second_blob = repo.stage_file("nested/tracked").unwrap();
        assert_ne!(first_blob.oid, second_blob.oid);
        let before_second = repo.status().unwrap();
        assert_eq!(
            before_second.changes[0].staged,
            Some(crate::GitChange::Modified)
        );
        assert_eq!(before_second.changes[0].worktree, None);
        let second = repo
            .commit("Test Author", "author@example.test", "second")
            .unwrap();
        assert_eq!(second.parent_oid, Some(first.oid));
        assert_ne!(second.tree_oid, first.tree_oid);
        let history = repo.log(10).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].oid, second.oid);
        assert_eq!(history[0].parent_oids, vec![first.oid]);
        assert_eq!(history[0].message, b"second");
        assert_eq!(history[1].oid, first.oid);
        let graph = repo.export_graph_source().unwrap();
        assert_eq!(graph.refs.len(), 1);
        assert_eq!(graph.refs[0].name, b"refs/heads/main");
        assert_eq!(graph.refs[0].oid, second.oid);
        assert_eq!(graph.blobs.len(), 2);
        assert!(graph.blobs.iter().any(|blob| blob.oid == first_blob.oid));
        assert!(graph.blobs.iter().any(|blob| blob.oid == second_blob.oid));
        assert!(graph.objects.iter().any(|object| object.oid == first.oid));
        assert!(graph.objects.iter().any(|object| object.oid == second.oid));
        let descriptor = crate::GitBackupDescriptor {
            format_version: 2,
            repository_id,
            refs: graph.refs.clone(),
            objects: graph.objects.clone(),
            blobs: graph
                .blobs
                .iter()
                .enumerate()
                .map(|(index, blob)| crate::GitBackupBlob {
                    oid: blob.oid,
                    logical_len: blob.anchor.logical_len,
                    data_extents: vec![crate::GitDataExtent {
                        offset: 0,
                        logical_len: blob.anchor.logical_len,
                        sectors: vec![mb_core::SectorRef {
                            id: [index as u8; 32],
                            root: [index as u8; 32],
                            logical_len: blob.anchor.logical_len as u32,
                        }],
                    }],
                })
                .collect(),
            head_branch: "main".to_owned(),
        };
        descriptor.validate().unwrap();
        let mut missing_head = descriptor.clone();
        missing_head.head_branch = "missing".to_owned();
        assert!(missing_head.validate().is_err());
        let mut missing_blob = descriptor.clone();
        missing_blob.blobs.pop();
        assert!(missing_blob.validate().is_err());
        let mut wrong_object = descriptor;
        wrong_object.objects[0].bytes.push(0);
        assert!(wrong_object.validate().is_err());
        let first_anchor = repo
            .anchors_for_oid(Oid::from_bytes(&first_blob.oid).unwrap())
            .unwrap();
        assert_eq!(first_anchor.len(), 1);
        let mut bytes = Vec::new();
        use std::io::Read;
        first_anchor[0]
            .open_verified()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, b"first\r\nbytes\0");
        let second_anchor = repo
            .anchors_for_oid(Oid::from_bytes(&second_blob.oid).unwrap())
            .unwrap();
        fs::write(source_root.join("nested/tracked"), b"uncommitted").unwrap();
        let third_blob = repo.stage_file("nested/tracked").unwrap();
        assert_ne!(third_blob.oid, second_blob.oid);
        let after_stage = repo.export_graph_source().unwrap();
        assert_eq!(after_stage.refs, graph.refs);
        assert_eq!(after_stage.objects, graph.objects);
        assert_eq!(after_stage.blobs, graph.blobs);
        let third_anchor = repo
            .anchors_for_oid(Oid::from_bytes(&third_blob.oid).unwrap())
            .unwrap();
        drop(repo);
        first_anchor[0].remove().unwrap();
        second_anchor[0].remove().unwrap();
        third_anchor[0].remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn selected_branch_survives_reopen_and_commits_only_to_its_ref() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-head-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"first\r\nbytes\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [28_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        repo.stage_file("tracked").unwrap();
        let first = repo.commit("Author", "a@example.test", "first").unwrap();
        repo.create_branch("topic").unwrap();
        assert!(matches!(
            repo.switch_branch("missing"),
            Err(RepositoryError::History(
                crate::HistoryError::BranchNotFound
            ))
        ));
        let selected = repo.switch_branch("topic").unwrap();
        assert!(selected.current);
        assert_eq!(repo.status().unwrap().branch, "topic");
        assert!(
            repo.branches()
                .unwrap()
                .iter()
                .any(|branch| { branch.name == "topic" && branch.current })
        );
        drop(repo);

        let repo = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(repo.status().unwrap().head_oid, Some(first.oid));
        assert_eq!(repo.status().unwrap().branch, "topic");
        fs::write(source_root.join("tracked"), b"second\nbytes").unwrap();
        fs::write(source_root.join("added"), b"new\r\nblob\0").unwrap();
        repo.stage_file("tracked").unwrap();
        repo.stage_file("added").unwrap();
        let second = repo.commit("Author", "a@example.test", "second").unwrap();
        assert_eq!(second.branch, "topic");
        assert_eq!(second.parent_oid, Some(first.oid));
        assert_eq!(repo.log(10).unwrap()[0].oid, second.oid);
        assert_eq!(repo.status().unwrap().head_oid, Some(second.oid));
        let graph = repo.export_graph_source().unwrap();
        assert_eq!(graph.refs.len(), 2);
        assert!(graph.refs.iter().any(|reference| {
            reference.name == b"refs/heads/main" && reference.oid == first.oid
        }));
        assert!(graph.refs.iter().any(|reference| {
            reference.name == b"refs/heads/topic" && reference.oid == second.oid
        }));
        fs::write(source_root.join("tracked"), b"dirty worktree").unwrap();
        assert!(matches!(
            repo.switch_branch("main"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"dirty worktree"
        );
        fs::write(source_root.join("tracked"), b"second\nbytes").unwrap();
        repo.switch_branch("main").unwrap();
        assert_eq!(repo.status().unwrap().branch, "main");
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"first\r\nbytes\0"
        );
        assert!(!source_root.join("added").exists());
        fs::write(source_root.join("added"), b"untracked collision").unwrap();
        assert!(repo.switch_branch("topic").is_err());
        assert_eq!(
            fs::read(source_root.join("added")).unwrap(),
            b"untracked collision"
        );
        assert_eq!(repo.status().unwrap().branch, "main");
        fs::remove_file(source_root.join("added")).unwrap();
        repo.switch_branch("topic").unwrap();
        assert_eq!(repo.status().unwrap().branch, "topic");
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"second\nbytes"
        );
        assert_eq!(
            fs::read(source_root.join("added")).unwrap(),
            b"new\r\nblob\0"
        );
        assert!(
            !fs::read_dir(source_root.join(".mutualbackup"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("checkout-"))
        );
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        drop(repo);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn interrupted_checkout_waits_for_dirty_file_then_resumes_on_reopen() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-checkout-replay-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"main bytes\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [29_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        repo.stage_file("tracked").unwrap();
        repo.commit("Author", "a@example.test", "main").unwrap();
        repo.create_branch("topic").unwrap();
        repo.switch_branch("topic").unwrap();
        fs::write(source_root.join("tracked"), b"topic bytes\n").unwrap();
        fs::write(source_root.join("added"), b"branch only\0").unwrap();
        repo.stage_file("tracked").unwrap();
        repo.stage_file("added").unwrap();
        repo.commit("Author", "a@example.test", "topic").unwrap();
        let graph = repo.export_graph_source().unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("checkout crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.switch_branch("main").unwrap();
        }));
        assert!(interrupted.is_err());
        assert!(!source_root.join("added").exists());
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"topic bytes\n"
        );

        fs::write(source_root.join("tracked"), b"post-crash edit").unwrap();
        assert!(matches!(
            repo.stage_file("tracked"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        drop(repo);
        assert!(matches!(
            GitRepository::open(&source_root, repository_id, &key),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"post-crash edit"
        );
        fs::write(source_root.join("tracked"), b"topic bytes\n").unwrap();
        let resumed = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(resumed.status().unwrap().branch, "main");
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"main bytes\r\n"
        );
        assert!(!source_root.join("added").exists());
        assert!(
            !fs::read_dir(source_root.join(".mutualbackup"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("checkout-"))
        );
        drop(resumed);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn committed_checkout_cleans_old_files_after_reopen() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-checkout-cleanup-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("tracked"), b"main\r\nbytes\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [31_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        repo.stage_file("tracked").unwrap();
        repo.commit("Author", "a@example.test", "main").unwrap();
        repo.create_branch("topic").unwrap();
        repo.switch_branch("topic").unwrap();
        fs::write(source_root.join("tracked"), b"topic\nbytes").unwrap();
        repo.stage_file("tracked").unwrap();
        repo.commit("Author", "a@example.test", "topic").unwrap();
        let graph = repo.export_graph_source().unwrap();

        crate::checkout::set_after_checkout_commit_hook(Box::new(|| panic!("checkout crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.switch_branch("main").unwrap();
        }));
        assert!(interrupted.is_err());
        drop(repo);
        assert_eq!(
            fs::read(source_root.join("tracked")).unwrap(),
            b"main\r\nbytes\0"
        );

        let resumed = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(resumed.status().unwrap().branch, "main");
        assert!(
            !fs::read_dir(source_root.join(".mutualbackup"))
                .unwrap()
                .any(|entry| entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with("checkout-"))
        );
        drop(resumed);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn nested_directory_checkout_replays_after_directory_move() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-checkout-nested-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("base"), b"base\r\nbytes").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [32_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        repo.stage_file("base").unwrap();
        repo.commit("Author", "a@example.test", "main").unwrap();
        repo.create_branch("topic").unwrap();
        repo.switch_branch("topic").unwrap();
        fs::create_dir_all(source_root.join("new/deep")).unwrap();
        fs::write(source_root.join("new/deep/file"), b"nested\r\nblob\0").unwrap();
        repo.stage_file("new/deep/file").unwrap();
        repo.commit("Author", "a@example.test", "topic").unwrap();
        let graph = repo.export_graph_source().unwrap();
        crate::checkout::set_after_directory_cleanup_hook(Box::new(|| panic!("cleanup crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.switch_branch("main").unwrap();
        }));
        assert!(interrupted.is_err());
        assert!(!source_root.join("new/deep").exists());
        assert!(source_root.join("new").is_dir());
        drop(repo);
        let repo = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(repo.status().unwrap().branch, "main");
        assert!(!source_root.join("new").exists());

        crate::checkout::set_after_checkout_directory_hook(Box::new(|| panic!("directory crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.switch_branch("topic").unwrap();
        }));
        assert!(interrupted.is_err());
        assert!(source_root.join("new").is_dir());
        assert!(!source_root.join("new/deep").exists());
        drop(repo);

        let resumed = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(resumed.status().unwrap().branch, "topic");
        assert_eq!(
            fs::read(source_root.join("new/deep/file")).unwrap(),
            b"nested\r\nblob\0"
        );
        fs::write(source_root.join("new/deep/keep"), b"untracked keep").unwrap();
        resumed.switch_branch("main").unwrap();
        assert_eq!(
            fs::read(source_root.join("new/deep/keep")).unwrap(),
            b"untracked keep"
        );
        fs::write(source_root.join("new/deep/file"), b"untracked collision").unwrap();
        assert!(resumed.switch_branch("topic").is_err());
        assert_eq!(
            fs::read(source_root.join("new/deep/file")).unwrap(),
            b"untracked collision"
        );
        fs::remove_file(source_root.join("new/deep/file")).unwrap();
        fs::remove_file(source_root.join("new/deep/keep")).unwrap();
        drop(resumed);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn file_directory_checkout_preserves_untracked_children_and_replays() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-checkout-topology-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("shape"), b"flat\r\nbytes\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [33_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        repo.stage_file("shape").unwrap();
        repo.commit("Author", "a@example.test", "flat").unwrap();
        repo.create_branch("topic").unwrap();
        repo.switch_branch("topic").unwrap();
        assert!(repo.remove_cached("shape").unwrap());
        assert!(!repo.remove_cached("shape").unwrap());
        assert_eq!(
            fs::read(source_root.join("shape")).unwrap(),
            b"flat\r\nbytes\0"
        );
        fs::remove_file(source_root.join("shape")).unwrap();
        fs::create_dir_all(source_root.join("shape/nested")).unwrap();
        fs::write(source_root.join("shape/nested/file"), b"deep\nbytes\0").unwrap();
        repo.stage_file("shape/nested/file").unwrap();
        repo.commit("Author", "a@example.test", "nested").unwrap();
        let graph = repo.export_graph_source().unwrap();

        fs::write(source_root.join("shape/nested/keep"), b"untracked").unwrap();
        assert!(matches!(
            repo.switch_branch("main"),
            Err(RepositoryError::Checkout(
                crate::CheckoutError::DirtyWorktree
            ))
        ));
        assert_eq!(repo.status().unwrap().branch, "topic");
        assert_eq!(
            fs::read(source_root.join("shape/nested/keep")).unwrap(),
            b"untracked"
        );
        fs::remove_file(source_root.join("shape/nested/keep")).unwrap();
        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("topology crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.switch_branch("main").unwrap();
        }));
        assert!(interrupted.is_err());
        drop(repo);
        let repo = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(repo.status().unwrap().branch, "main");
        assert_eq!(
            fs::read(source_root.join("shape")).unwrap(),
            b"flat\r\nbytes\0"
        );

        crate::checkout::set_after_checkout_file_hook(Box::new(|| panic!("topology crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.switch_branch("topic").unwrap();
        }));
        assert!(interrupted.is_err());
        drop(repo);
        let resumed = GitRepository::open(&source_root, repository_id, &key).unwrap();
        assert_eq!(resumed.status().unwrap().branch, "topic");
        assert_eq!(
            fs::read(source_root.join("shape/nested/file")).unwrap(),
            b"deep\nbytes\0"
        );
        drop(resumed);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn deleted_path_add_can_commit_an_empty_tree_and_restore_the_old_branch() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-empty-tree-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(source_root.join("nested")).unwrap();
        fs::write(source_root.join("nested/only"), b"only\r\nfile\0").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [34_u8; 32];
        let repo = GitRepository::init(&source_root, repository_id, &key).unwrap();
        repo.stage_file("nested/only").unwrap();
        let first = repo.commit("Author", "a@example.test", "first").unwrap();
        repo.create_branch("empty").unwrap();
        repo.switch_branch("empty").unwrap();
        fs::remove_file(source_root.join("nested/only")).unwrap();
        std::os::unix::fs::symlink("elsewhere", source_root.join("nested/only")).unwrap();
        let symlink_entry = repo.add_path("nested/only").unwrap().unwrap();
        assert_eq!(symlink_entry.mode, 0o120000);
        assert_eq!(
            repo.staged_entry("nested/only").unwrap(),
            Some(symlink_entry.clone())
        );
        let symlink_anchor = repo
            .anchors_for_oid(Oid::from_bytes(&symlink_entry.oid).unwrap())
            .unwrap()
            .into_iter()
            .find(|anchor| anchor.anchor_id == symlink_entry.anchor_id)
            .unwrap();
        fs::remove_file(source_root.join("nested/only")).unwrap();
        fs::remove_dir(source_root.join("nested")).unwrap();
        assert!(repo.add_path("nested/only").unwrap().is_none());
        assert!(repo.add_path("never-tracked").is_err());
        let empty = repo.commit("Author", "a@example.test", "empty").unwrap();
        assert_eq!(empty.parent_oid, Some(first.oid));
        assert!(repo.status().unwrap().changes.is_empty());
        let graph = repo.export_graph_source().unwrap();
        repo.switch_branch("main").unwrap();
        assert_eq!(
            fs::read(source_root.join("nested/only")).unwrap(),
            b"only\r\nfile\0"
        );
        repo.switch_branch("empty").unwrap();
        assert!(!source_root.join("nested").exists());
        drop(repo);
        symlink_anchor.remove().unwrap();
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }
}
