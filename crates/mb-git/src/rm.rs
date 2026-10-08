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
    GitIndexEntry, StageError, index_kind_for_scope, indexed_anchor_manifest, stage_path_key,
    staged_entry_for_scope,
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

/// Original tracked-file removals retain their indexed anchor until replay.
/// Inspect the journal without looking up the index or opening a working file.
#[cfg(target_os = "linux")]
pub(crate) fn for_each_preserved_record(
    control: &ControlStore,
    repository_id: Uuid,
    mut visit: impl FnMut(crate::PreservedGitRecord) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    for prefix in [PRIMARY_PREFIX, LINKED_PREFIX] {
        control.for_each_record_with_kind_prefix_bounded(
            prefix,
            512,
            crate::stage::MAX_STAGE_PATH_BYTES,
            crate::stage::MAX_STAGE_PATH_BYTES + 1024,
            |kind, key, bytes| {
                let scope = GitWorktreeScope::preserved_from_kind(
                    kind,
                    repository_id,
                    PRIMARY_PREFIX,
                    LINKED_PREFIX,
                )?;
                ensure!(!key.contains(&0), "invalid preserved tracked-removal path");
                let intent = decode_intent(scope, key, bytes)?;
                ensure!(
                    mb_core::canonical_bytes_bounded(&intent, bytes.len())? == bytes
                        && !intent.entry.anchor_id.is_nil()
                        && intent.root_id.filesystem_id != 0
                        && intent.root_id.inode != 0
                        && intent.file_id.inode != 0,
                    "invalid preserved tracked-removal ownership or encoding"
                );
                visit(crate::PreservedGitRecord::RemovalIntent {
                    scope,
                    record_format: intent.format_version,
                    recorded_root_identity: intent.root_id,
                    relative_path: intent.path,
                    entry: intent.entry,
                    recorded_file_identity: intent.file_id,
                })?;
                Ok(true)
            },
        )?;
    }
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod preserved_tests {
    use super::*;
    use std::fs;

    #[test]
    fn preserved_git_rm_intents_keep_original_scopes_and_root_ownership_without_unlinking() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("catalog.db");
        let control = ControlStore::open_with_key(&path, &[217; 32]).unwrap();
        let repository_id = Uuid::from_u128(217);
        let linked_id = Uuid::from_u128(218);
        let root = NativeFileId {
            filesystem_id: 7,
            inode: 8,
        };
        let file = NativeFileId {
            filesystem_id: 7,
            inode: 9,
        };
        let entry = GitIndexEntry {
            format_version: 1,
            oid: [19; 20],
            mode: 0o120000,
            anchor_id: Uuid::from_u128(219),
        };
        let primary = intent_kind_for_scope(GitWorktreeScope::primary(repository_id));
        let linked =
            intent_kind_for_scope(GitWorktreeScope::linked(repository_id, linked_id).unwrap());
        let original = |worktree| {
            canonical_bytes(&(
                1_u16,
                repository_id,
                worktree,
                root,
                b"file-\xff".to_vec(),
                &entry,
                file,
            ))
            .unwrap()
        };
        for (kind, worktree) in [(&primary, repository_id), (&linked, linked_id)] {
            control
                .put_record(kind, b"file-\xff", &original(worktree))
                .unwrap();
        }
        let snapshot = || {
            (
                fs::read(&path).unwrap(),
                fs::read(path.with_extension("db-wal")).unwrap(),
            )
        };
        let before = snapshot();
        let mut count = 0;
        for_each_preserved_record(&control, repository_id, |record| {
            let crate::PreservedGitRecord::RemovalIntent {
                scope,
                record_format,
                recorded_root_identity,
                relative_path,
                entry: actual,
                recorded_file_identity,
            } = record
            else {
                panic!("wrong record")
            };
            assert_eq!(record_format, 1);
            assert_eq!(scope.repository_id(), repository_id);
            assert!([repository_id, linked_id].contains(&scope.worktree_id()));
            assert_eq!(recorded_root_identity, root);
            assert_eq!(recorded_file_identity, file);
            assert_eq!(relative_path, b"file-\xff");
            assert_eq!(actual, entry);
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 2);
        assert_eq!(snapshot(), before);
        for kind in [&primary, &linked] {
            control.delete_record(kind, b"file-\xff").unwrap();
        }
        let bytes = original(repository_id);
        let valid: RmIntent = decode_canonical(&bytes).unwrap();
        assert_eq!(canonical_bytes(&valid).unwrap(), bytes);
        let mut boundary = valid.clone();
        boundary.path = vec![b'x'; crate::stage::MAX_STAGE_PATH_BYTES];
        control
            .put_record(
                &primary,
                &boundary.path,
                &canonical_bytes(&boundary).unwrap(),
            )
            .unwrap();
        let before = snapshot();
        let mut visited_boundary = false;
        for_each_preserved_record(&control, repository_id, |record| {
            let crate::PreservedGitRecord::RemovalIntent { relative_path, .. } = record else {
                panic!("wrong record")
            };
            assert_eq!(relative_path.len(), crate::stage::MAX_STAGE_PATH_BYTES);
            visited_boundary = true;
            Ok(())
        })
        .unwrap();
        assert!(visited_boundary);
        assert_eq!(snapshot(), before);
        control.delete_record(&primary, &boundary.path).unwrap();
        let reject = |kind: &str, key: &[u8], bytes: &[u8]| {
            control.put_record(kind, key, bytes).unwrap();
            let before = snapshot();
            assert!(for_each_preserved_record(&control, repository_id, |_| Ok(())).is_err());
            assert_eq!(snapshot(), before);
            control.delete_record(kind, key).unwrap();
        };
        for index in 0..10 {
            let mut bad = valid.clone();
            match index {
                0 => bad.format_version = 2,
                1 => bad.repository_id = linked_id,
                2 => bad.worktree_id = linked_id,
                3 => bad.root_id.filesystem_id = 0,
                4 => bad.root_id.inode = 0,
                5 => bad.file_id.inode = 0,
                6 => bad.file_id.filesystem_id = 8,
                7 => bad.entry.format_version = 2,
                8 => bad.entry.mode = 0,
                _ => bad.entry.anchor_id = Uuid::nil(),
            }
            reject(&primary, b"file-\xff", &canonical_bytes(&bad).unwrap());
        }
        for key in [
            b"".as_slice(),
            b"other",
            b"../escape",
            b"a\0b",
            &vec![b'x'; crate::stage::MAX_STAGE_PATH_BYTES + 1],
        ] {
            reject(&primary, key, &bytes);
        }
        for kind in [
            format!("git-rm-intent-v1/{linked_id}"),
            format!(
                "git-worktree-rm-intent-v1/{repository_id}/{}",
                linked_id.simple()
            ),
            format!("git-worktree-rm-intent-v1/{repository_id}/{repository_id}"),
        ] {
            reject(&kind, b"file-\xff", &bytes);
        }
        reject(&primary, b"file-\xff", &[bytes, vec![0]].concat());
        reject(
            &primary,
            b"file-\xff",
            &vec![0; crate::stage::MAX_STAGE_PATH_BYTES + 1025],
        );
        assert!(
            !temporary
                .path()
                .join(OsString::from_vec(b"file-\xff".to_vec()))
                .exists()
        );
    }
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
            &indexed_anchor_manifest(control, scope.repository_id(), &intent.entry)?,
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
    verify_tracked_file_for_removal(
        &parent,
        &name,
        file_id,
        entry.oid,
        entry.mode,
        &indexed_anchor_manifest(control, scope.repository_id(), &entry)?,
    )?;
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
