//! The selected branch for the first worktree. Old catalogs have no HEAD
//! record and therefore continue to mean `refs/heads/main`.

use git2::Branch;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{ControlStore, DatabaseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::GitWorktreeScope;

const HEAD_PREFIX: &str = "git-head-v1/";
const WORKTREE_HEAD_PREFIX: &str = "git-worktree-head-v1/";
const HEAD_KEY: &[u8] = b"branch";

#[derive(Debug, Error)]
pub enum HeadError {
    #[error("encrypted catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned HEAD record error: {0}")]
    Model(#[from] ModelError),
    #[error("Git branch validation error: {0}")]
    Git(#[from] git2::Error),
    #[error("the selected Git branch record is incompatible or corrupt")]
    IncompatibleRecord,
}

#[derive(Serialize, Deserialize)]
struct HeadRecord {
    format_version: u16,
    branch: String,
}

pub(crate) fn head_kind(repository_id: Uuid) -> String {
    head_kind_for_scope(GitWorktreeScope::primary(repository_id))
}

pub(crate) fn head_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(HEAD_PREFIX, WORKTREE_HEAD_PREFIX)
}

pub(crate) fn selected_branch(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<String, HeadError> {
    selected_branch_for_scope(control, GitWorktreeScope::primary(repository_id))
}

pub(crate) fn selected_branch_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<String, HeadError> {
    let Some(encoded) = control.get_record(&head_kind_for_scope(scope), HEAD_KEY)? else {
        return Ok("main".to_owned());
    };
    let record: HeadRecord = decode_canonical(&encoded)?;
    if record.format_version != 1
        || record.branch.len() > 1024
        || !Branch::name_is_valid(&record.branch)?
    {
        return Err(HeadError::IncompatibleRecord);
    }
    Ok(record.branch)
}

pub(crate) fn selected_ref(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<u8>, HeadError> {
    selected_ref_for_scope(control, GitWorktreeScope::primary(repository_id))
}

pub(crate) fn selected_ref_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Vec<u8>, HeadError> {
    Ok(format!("refs/heads/{}", selected_branch_for_scope(control, scope)?).into_bytes())
}

/// Enumerate linked HEADs for operations that must protect every checked-out
/// branch, including branch deletion before linked worktree routing is exposed.
pub(crate) fn linked_selected_branches(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<String>, HeadError> {
    Ok(linked_selected_branches_with_scope(control, repository_id)?
        .into_iter()
        .map(|(_, branch)| branch)
        .collect())
}

fn linked_selected_branches_with_scope(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<(GitWorktreeScope, String)>, HeadError> {
    let prefix = format!("{WORKTREE_HEAD_PREFIX}{repository_id}/");
    let mut branches = Vec::new();
    for (kind, key, _) in control.records_with_kind_prefix(&prefix)? {
        let suffix = kind
            .strip_prefix(&prefix)
            .ok_or(HeadError::IncompatibleRecord)?;
        let worktree_id = Uuid::parse_str(suffix).map_err(|_| HeadError::IncompatibleRecord)?;
        let scope = GitWorktreeScope::linked(repository_id, worktree_id)
            .ok_or(HeadError::IncompatibleRecord)?;
        if suffix != worktree_id.to_string() || key != HEAD_KEY {
            return Err(HeadError::IncompatibleRecord);
        }
        branches.push((scope, selected_branch_for_scope(control, scope)?));
    }
    Ok(branches)
}

pub(crate) fn branch_selected_elsewhere(
    control: &ControlStore,
    scope: GitWorktreeScope,
    name: &str,
) -> Result<bool, HeadError> {
    if scope.worktree_id() != scope.repository_id()
        && selected_branch(control, scope.repository_id())? == name
    {
        return Ok(true);
    }
    Ok(
        linked_selected_branches_with_scope(control, scope.repository_id())?
            .iter()
            .any(|(other, branch)| *other != scope && branch == name),
    )
}

#[cfg(test)]
pub(crate) fn store_selected_branch(
    control: &ControlStore,
    repository_id: Uuid,
    branch: &str,
) -> Result<(), HeadError> {
    store_selected_branch_for_scope(control, GitWorktreeScope::primary(repository_id), branch)
}

pub(crate) fn store_selected_branch_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    branch: &str,
) -> Result<(), HeadError> {
    let (kind, key, bytes) = selected_branch_record_for_scope(scope, branch)?;
    control.put_record(&kind, &key, &bytes)?;
    Ok(())
}

pub(crate) fn selected_branch_record(
    repository_id: Uuid,
    branch: &str,
) -> Result<(String, Vec<u8>, Vec<u8>), HeadError> {
    selected_branch_record_for_scope(GitWorktreeScope::primary(repository_id), branch)
}

pub(crate) fn selected_branch_record_for_scope(
    scope: GitWorktreeScope,
    branch: &str,
) -> Result<(String, Vec<u8>, Vec<u8>), HeadError> {
    if branch.len() > 1024 || !Branch::name_is_valid(branch)? {
        return Err(HeadError::IncompatibleRecord);
    }
    Ok((
        head_kind_for_scope(scope),
        HEAD_KEY.to_vec(),
        canonical_bytes(&HeadRecord {
            format_version: 1,
            branch: branch.to_owned(),
        })?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linked_head_is_independent_and_primary_key_is_stable() {
        let directory = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(directory.path().join("catalog.db"), &[1; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let linked = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        assert_eq!(
            head_kind(repository_id),
            format!("git-head-v1/{repository_id}")
        );
        assert_ne!(head_kind_for_scope(linked), head_kind(repository_id));
        store_selected_branch(&control, repository_id, "main").unwrap();
        store_selected_branch_for_scope(&control, linked, "topic").unwrap();
        assert_eq!(selected_branch(&control, repository_id).unwrap(), "main");
        assert_eq!(
            selected_branch_for_scope(&control, linked).unwrap(),
            "topic"
        );
        assert_eq!(
            selected_ref_for_scope(&control, linked).unwrap(),
            b"refs/heads/topic"
        );
    }
}
