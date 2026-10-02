//! Read-only comparison of HEAD, the staged snapshot, and the working tree.
//! Blob hashes use raw pinned file descriptors; Git text filters never run.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs::{self, Metadata};
use std::io::Read;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid, Repository};
use mb_core::{ModelError, decode_canonical};
use mb_store::{AnchorError, ControlStore, DatabaseError, PinnedDirectory};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::GitWorktreeScope;
use crate::head::{HeadError, selected_branch_for_scope, selected_ref_for_scope};
use crate::merge::{GitMergeState, MergeBlobError, merge_state};
use crate::stage::{
    GitIndexEntry, StageError, indexed_anchor_manifest, pending_stage_paths_for_scope,
    staged_entries_for_scope,
};

const METADATA_PREFIX: &str = "git-metadata-object-v1/";
const REF_PREFIX: &str = "git-ref-v1/";
const MAX_STATUS_FILES: usize = 100_000;
pub(crate) type TreeFiles = BTreeMap<Vec<u8>, ([u8; 20], u32)>;

#[derive(Debug, Error)]
pub enum StatusError {
    #[error("pinned worktree path error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("Git staging error: {0}")]
    Stage(#[from] StageError),
    #[error("encrypted catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned history metadata error: {0}")]
    Model(#[from] ModelError),
    #[error("Git HEAD record error: {0}")]
    Head(#[from] HeadError),
    #[error("Git merge state error: {0}")]
    Merge(#[from] MergeBlobError),
    #[error("Git object error: {0}")]
    Git(#[from] git2::Error),
    #[error("working-tree or temporary repository error: {0}")]
    Io(#[from] std::io::Error),
    #[error("history catalog or index contains an incompatible record")]
    IncompatibleRecord,
    #[error("status exceeds the supported file count")]
    TooManyFiles,
    #[error("the working file changed while status was read")]
    SourceChanged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GitChange {
    Added,
    Modified,
    Deleted,
    TypeChanged,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitStatusChange {
    pub path: Vec<u8>,
    pub staged: Option<GitChange>,
    pub worktree: Option<GitChange>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitStatus {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub branch: String,
    pub head_oid: Option<[u8; 20]>,
    /// A certified checkpoint covers the local reachable graph and refs.
    /// This does not attest uncommitted index entries or worktree selection.
    pub history_backed_up: bool,
    pub changes: Vec<GitStatusChange>,
    pub untracked: Vec<Vec<u8>>,
    pub pending_adds: Vec<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge: Option<GitMergeState>,
}

#[derive(Deserialize)]
struct MetadataObject {
    format_version: u16,
    kind: u8,
    bytes: Vec<u8>,
}

#[derive(Deserialize)]
struct RefRecord {
    format_version: u16,
    oid: [u8; 20],
}

fn head_oid_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Option<Oid>, StatusError> {
    let kind = format!("{REF_PREFIX}{}", scope.repository_id());
    let reference = selected_ref_for_scope(control, scope)?;
    let Some(encoded) = control.get_record(&kind, &reference)? else {
        if reference != b"refs/heads/main" {
            return Err(StatusError::IncompatibleRecord);
        }
        return Ok(None);
    };
    let record: RefRecord = decode_canonical(&encoded)?;
    if record.format_version != 1 {
        return Err(StatusError::IncompatibleRecord);
    }
    Ok(Some(Oid::from_bytes(&record.oid)?))
}

pub(crate) fn files_for_commit(
    control: &ControlStore,
    repository_id: Uuid,
    head: Option<Oid>,
) -> Result<TreeFiles, StatusError> {
    let Some(head) = head else {
        return Ok(BTreeMap::new());
    };
    let temporary = tempfile::tempdir()?;
    let repository = Repository::init_bare(temporary.path())?;
    let odb = git2::Odb::new()?;
    let _pack = odb.add_new_mempack_backend(1000)?;
    repository.set_odb(&odb)?;
    for (key, encoded) in control.records(&format!("{METADATA_PREFIX}{repository_id}"))? {
        let object: MetadataObject = decode_canonical(&encoded)?;
        let kind = match object.kind {
            1 => ObjectType::Commit,
            2 => ObjectType::Tree,
            3 => ObjectType::Tag,
            _ => return Err(StatusError::IncompatibleRecord),
        };
        let oid = Oid::hash_object(kind, &object.bytes)?;
        if object.format_version != 1
            || key != oid.as_bytes()
            || odb.write(kind, &object.bytes)? != oid
        {
            return Err(StatusError::IncompatibleRecord);
        }
    }
    let commit = repository
        .find_commit(head)
        .map_err(|_| StatusError::IncompatibleRecord)?;
    let mut pending = vec![(Vec::<u8>::new(), commit.tree_id())];
    let mut files = BTreeMap::new();
    while let Some((prefix, oid)) = pending.pop() {
        let tree = repository
            .find_tree(oid)
            .map_err(|_| StatusError::IncompatibleRecord)?;
        for entry in tree.iter() {
            let mut path = prefix.clone();
            path.extend_from_slice(entry.name_bytes());
            if entry.kind() == Some(ObjectType::Tree) && entry.filemode() == 0o040000 {
                path.push(b'/');
                pending.push((path, entry.id()));
            } else if entry.kind() == Some(ObjectType::Blob)
                && matches!(entry.filemode(), 0o100644 | 0o100755 | 0o120000)
            {
                files.insert(
                    path,
                    (
                        entry.id().as_bytes().try_into().expect("SHA-1 OID"),
                        entry.filemode() as u32,
                    ),
                );
                if files.len() > MAX_STATUS_FILES {
                    return Err(StatusError::TooManyFiles);
                }
            } else {
                return Err(StatusError::IncompatibleRecord);
            }
        }
    }
    Ok(files)
}

pub(crate) fn committed_files_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<TreeFiles, StatusError> {
    files_for_commit(
        control,
        scope.repository_id(),
        head_oid_for_scope(control, scope)?,
    )
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

fn worktree_change(
    root: &PinnedDirectory,
    path: &[u8],
    staged: &GitIndexEntry,
    expected_hash: [u8; 32],
    expected_len: u64,
) -> Result<Option<GitChange>, StatusError> {
    let relative = PathBuf::from(OsString::from_vec(path.to_vec()));
    let parent_path = relative.parent().ok_or(StatusError::IncompatibleRecord)?;
    let parent = if parent_path.as_os_str().is_empty() {
        None
    } else {
        match root.open_descendant_directory(parent_path) {
            Ok(parent) => Some(parent),
            Err(AnchorError::Io(error)) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Ok(Some(GitChange::Deleted));
            }
            Err(AnchorError::Io(error)) if error.raw_os_error() == Some(libc::ENOTDIR) => {
                return Ok(Some(GitChange::TypeChanged));
            }
            Err(AnchorError::Io(error)) if error.raw_os_error() == Some(libc::ELOOP) => {
                return Ok(Some(GitChange::TypeChanged));
            }
            Err(AnchorError::UnsupportedObject(_)) => {
                return Ok(Some(GitChange::TypeChanged));
            }
            Err(error) => return Err(error.into()),
        }
    };
    let parent = parent.as_ref().unwrap_or(root);
    let name = relative
        .file_name()
        .ok_or(StatusError::IncompatibleRecord)?;
    if staged.mode == 0o120000 {
        let target = match parent.read_child_symlink(name) {
            Ok(Some(target)) => target,
            Ok(None) => return Ok(Some(GitChange::Deleted)),
            Err(AnchorError::UnsupportedObject(_)) => return Ok(Some(GitChange::TypeChanged)),
            Err(error) => return Err(error.into()),
        };
        return Ok((target.0.len() as u64 != expected_len
            || blake3::hash(&target.0).as_bytes() != &expected_hash)
            .then_some(GitChange::Modified));
    }
    let mut file = match parent.open_child_file(name) {
        Ok(Some(file)) => file,
        Ok(None) => return Ok(Some(GitChange::Deleted)),
        Err(AnchorError::UnsupportedObject(_)) => return Ok(Some(GitChange::TypeChanged)),
        Err(AnchorError::Io(error)) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Ok(Some(GitChange::TypeChanged));
        }
        Err(error) => return Err(error.into()),
    };
    let opened_metadata = file.metadata()?;
    if !opened_metadata.is_file() {
        return Ok(Some(GitChange::TypeChanged));
    }
    let mode = if opened_metadata.mode() & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    };
    if mode != staged.mode || opened_metadata.len() != expected_len {
        return Ok(Some(GitChange::Modified));
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
    let after = file.metadata()?;
    if file_fingerprint(&opened_metadata) != file_fingerprint(&after) {
        return Err(StatusError::SourceChanged);
    }
    Ok((hasher.finalize().as_bytes() != &expected_hash).then_some(GitChange::Modified))
}

fn walk_untracked(
    root: &PinnedDirectory,
    tracked: &BTreeSet<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, StatusError> {
    let mut pending = vec![(root.try_clone()?, Vec::<u8>::new())];
    let mut untracked = Vec::new();
    let mut visited = 0;
    while let Some((directory, prefix)) = pending.pop() {
        for item in fs::read_dir(directory.descriptor_path())? {
            let item = item?;
            let name = item.file_name();
            let name_bytes = name.as_bytes();
            if prefix.is_empty() && (name_bytes == b".mutualbackup" || name_bytes == b".git") {
                continue;
            }
            let mut path = prefix.clone();
            path.extend_from_slice(name_bytes);
            visited += 1;
            if visited > MAX_STATUS_FILES {
                return Err(StatusError::TooManyFiles);
            }
            let kind = item.file_type()?;
            if kind.is_dir() {
                path.push(b'/');
                let child = directory
                    .open_child_directory(&name)?
                    .ok_or(AnchorError::PinnedFileChanged)?;
                pending.push((child, path));
            } else if !tracked.contains(&path) {
                untracked.push(path);
            }
        }
    }
    untracked.sort();
    Ok(untracked)
}

pub fn repository_status(
    control: &ControlStore,
    repository_id: Uuid,
    root: &Path,
) -> Result<GitStatus, StatusError> {
    repository_status_for_scope(control, GitWorktreeScope::primary(repository_id), root)
}

pub(crate) fn repository_status_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root: &Path,
) -> Result<GitStatus, StatusError> {
    let repository_id = scope.repository_id();
    let head = head_oid_for_scope(control, scope)?;
    let committed = files_for_commit(control, repository_id, head)?;
    let staged = staged_entries_for_scope(control, scope)?
        .into_iter()
        .collect::<BTreeMap<_, _>>();
    if staged.len() > MAX_STATUS_FILES {
        return Err(StatusError::TooManyFiles);
    }
    let mut all_paths = staged.keys().cloned().collect::<BTreeSet<_>>();
    all_paths.extend(committed.keys().cloned());
    let root = PinnedDirectory::open(root)?;
    let mut changes = Vec::new();
    for path in all_paths {
        let staged_entry = staged.get(&path);
        let committed_entry = committed.get(&path);
        let index_change = match (committed_entry, staged_entry) {
            (None, Some(_)) => Some(GitChange::Added),
            (Some(_), None) => Some(GitChange::Deleted),
            (Some((oid, mode)), Some(index)) if *oid != index.oid || *mode != index.mode => {
                Some(GitChange::Modified)
            }
            _ => None,
        };
        let worktree = match staged_entry {
            Some(index) => {
                let anchor = indexed_anchor_manifest(control, repository_id, index)?;
                worktree_change(&root, &path, index, anchor.content_hash, anchor.logical_len)?
            }
            None => None,
        };
        if index_change.is_some() || worktree.is_some() {
            changes.push(GitStatusChange {
                path,
                staged: index_change,
                worktree,
            });
        }
    }
    let tracked = staged.keys().cloned().collect();
    let untracked = walk_untracked(&root, &tracked)?;
    Ok(GitStatus {
        format_version: 1,
        repository_id,
        branch: selected_branch_for_scope(control, scope)?,
        head_oid: head.map(|oid| oid.as_bytes().try_into().expect("SHA-1 OID")),
        history_backed_up: false,
        changes,
        untracked,
        pending_adds: pending_stage_paths_for_scope(control, scope)?,
        merge: if scope.worktree_id() == repository_id {
            merge_state(control, repository_id)?
        } else {
            None
        },
    })
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    #[test]
    fn tracked_status_does_not_follow_a_replaced_parent_symlink() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), b"same bytes").unwrap();
        symlink(outside.path(), root.path().join("dir")).unwrap();
        let pinned = PinnedDirectory::open(root.path()).unwrap();
        let staged = GitIndexEntry {
            format_version: 1,
            oid: Oid::hash_object(ObjectType::Blob, b"same bytes")
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            mode: 0o100644,
            anchor_id: Uuid::new_v4(),
        };
        assert_eq!(
            worktree_change(&pinned, b"dir/file", &staged, [0; 32], 0).unwrap(),
            Some(GitChange::TypeChanged)
        );
        assert_eq!(
            walk_untracked(&pinned, &BTreeSet::new()).unwrap(),
            vec![b"dir".to_vec()]
        );
    }

    #[test]
    fn tracked_status_reports_a_missing_parent_as_deleted() {
        let root = tempfile::tempdir().unwrap();
        let pinned = PinnedDirectory::open(root.path()).unwrap();
        let staged = GitIndexEntry {
            format_version: 1,
            oid: [1; 20],
            mode: 0o100644,
            anchor_id: Uuid::new_v4(),
        };
        assert_eq!(
            worktree_change(&pinned, b"dir/file", &staged, [0; 32], 0).unwrap(),
            Some(GitChange::Deleted)
        );
    }

    #[test]
    fn tracked_status_reports_a_replaced_file_symlink_as_type_change() {
        let root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join("file"), b"same bytes").unwrap();
        symlink(outside.path().join("file"), root.path().join("file")).unwrap();
        let pinned = PinnedDirectory::open(root.path()).unwrap();
        let staged = GitIndexEntry {
            format_version: 1,
            oid: Oid::hash_object(ObjectType::Blob, b"same bytes")
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            mode: 0o100644,
            anchor_id: Uuid::new_v4(),
        };
        assert_eq!(
            worktree_change(&pinned, b"file", &staged, [0; 32], 0).unwrap(),
            Some(GitChange::TypeChanged)
        );
    }

    #[test]
    fn matching_git_id_does_not_hide_different_worktree_bytes() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("file"), b"bravo").unwrap();
        let pinned = PinnedDirectory::open(root.path()).unwrap();
        let staged = GitIndexEntry {
            format_version: 1,
            oid: Oid::hash_object(ObjectType::Blob, b"bravo")
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            mode: 0o100644,
            anchor_id: Uuid::new_v4(),
        };
        assert_eq!(
            worktree_change(
                &pinned,
                b"file",
                &staged,
                *blake3::hash(b"alpha").as_bytes(),
                5,
            )
            .unwrap(),
            Some(GitChange::Modified)
        );
    }

    #[test]
    fn status_compares_with_the_mapped_native_root_and_requires_its_record() {
        let worktree = tempfile::tempdir().unwrap();
        let anchor_root = tempfile::tempdir().unwrap();
        let database = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(database.path().join("control.db"), &[37; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        fs::write(worktree.path().join("file"), b"alpha").unwrap();
        let anchor = mb_store::SourceBlobImportPlan::plan_direct(anchor_root.path(), 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"alpha"))
            .unwrap();
        let oid = Oid::hash_object(ObjectType::Blob, b"alpha").unwrap();
        let entry = GitIndexEntry {
            format_version: 1,
            oid: oid.as_bytes().try_into().unwrap(),
            mode: 0o100644,
            anchor_id: anchor.anchor_id,
        };
        control
            .put_record(
                &crate::stage::object_kind(repository_id, oid),
                anchor.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&anchor).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                &crate::stage::index_kind(repository_id),
                b"file",
                &mb_core::canonical_bytes(&entry).unwrap(),
            )
            .unwrap();
        let clean = repository_status(&control, repository_id, worktree.path()).unwrap();
        assert_eq!(clean.changes.len(), 1);
        assert_eq!(clean.changes[0].staged, Some(GitChange::Added));
        assert_eq!(clean.changes[0].worktree, None);
        fs::write(worktree.path().join("file"), b"bravo").unwrap();
        assert_eq!(
            repository_status(&control, repository_id, worktree.path())
                .unwrap()
                .changes[0]
                .worktree,
            Some(GitChange::Modified)
        );
        control
            .delete_record(
                &crate::stage::object_kind(repository_id, oid),
                anchor.anchor_id.as_bytes(),
            )
            .unwrap();
        assert!(matches!(
            repository_status(&control, repository_id, worktree.path()),
            Err(StatusError::Stage(StageError::IncompatibleRecord))
        ));
    }
}
