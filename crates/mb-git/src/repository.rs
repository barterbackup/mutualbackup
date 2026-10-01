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

use crate::checkout::{CheckoutError, begin_switch, resume_pending_checkout};
use crate::diff::{DiffError, GitDiff, repository_diff};
use crate::head::{HeadError, selected_branch};
use crate::history::{
    GitBranchInfo, GitCommitInfo, GitGraphSource, GitLogEntry, HistoryError, commit_index,
    create_branch, export_graph_source, import_graph_backup, list_branches, log_history,
    switch_same_tree_branch,
};
use crate::stage::{
    GitIndexEntry, StageError, abandon_pending_stage, anchors_for_oid, remove_cached,
    resume_pending_stages, stage_file, stage_path_key, staged_entry,
};
use crate::status::{GitStatus, StatusError, repository_status};

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
        Ok(repository)
    }

    pub fn id(&self) -> Uuid {
        self.repository_id
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn stage_file(
        &self,
        relative_path: impl AsRef<Path>,
    ) -> Result<GitIndexEntry, RepositoryError> {
        self.resume_checkout()?;
        Ok(stage_file(
            &self.catalog,
            self.repository_id,
            &self.root,
            relative_path,
        )?)
    }

    /// Like `git add <path>`, capture a present regular file or stage the
    /// deletion of a missing indexed path. A symlink or other unsupported
    /// object is never mistaken for a deletion.
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
        if !self.remove_cached(relative)? {
            return Err(StageError::MissingUntrackedPath.into());
        }
        Ok(None)
    }

    pub fn remove_cached(&self, relative_path: impl AsRef<Path>) -> Result<bool, RepositoryError> {
        self.resume_checkout()?;
        Ok(remove_cached(
            &self.catalog,
            self.repository_id,
            relative_path,
        )?)
    }

    pub fn resume_pending_stages(&self) -> Result<Vec<GitIndexEntry>, RepositoryError> {
        self.resume_checkout()?;
        Ok(resume_pending_stages(&self.catalog, self.repository_id)?)
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

    pub fn selected_branch(&self) -> Result<String, RepositoryError> {
        self.resume_checkout()?;
        Ok(selected_branch(&self.catalog, self.repository_id)?)
    }

    pub fn create_branch(&self, name: &str) -> Result<GitBranchInfo, RepositoryError> {
        self.resume_checkout()?;
        Ok(create_branch(&self.catalog, self.repository_id, name)?)
    }

    pub fn switch_branch(&self, name: &str) -> Result<GitBranchInfo, RepositoryError> {
        self.resume_checkout()?;
        match switch_same_tree_branch(&self.catalog, self.repository_id, name) {
            Ok(info) => Ok(info),
            Err(HistoryError::CheckoutRequired) => Ok(begin_switch(
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
        Ok(resume_pending_checkout(
            &self.catalog,
            self.repository_id,
            &self.root,
            &self.directory,
        )?)
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

    pub fn import_backup(
        &self,
        descriptor: &crate::GitBackupDescriptor,
        anchors: &[FileAnchorManifest],
    ) -> Result<(), RepositoryError> {
        self.resume_checkout()?;
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
        assert!(repo.add_path("nested/only").is_err());
        assert!(repo.staged_entry("nested/only").unwrap().is_some());
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
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }
}
