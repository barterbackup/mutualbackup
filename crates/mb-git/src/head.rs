//! The selected branch for the first worktree. Old catalogs have no HEAD
//! record and therefore continue to mean `refs/heads/main`.

use git2::Branch;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{ControlStore, DatabaseError};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

const HEAD_PREFIX: &str = "git-head-v1/";
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

fn head_kind(repository_id: Uuid) -> String {
    format!("{HEAD_PREFIX}{repository_id}")
}

pub(crate) fn selected_branch(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<String, HeadError> {
    let Some(encoded) = control.get_record(&head_kind(repository_id), HEAD_KEY)? else {
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
    Ok(format!("refs/heads/{}", selected_branch(control, repository_id)?).into_bytes())
}

pub(crate) fn store_selected_branch(
    control: &ControlStore,
    repository_id: Uuid,
    branch: &str,
) -> Result<(), HeadError> {
    if branch.len() > 1024 || !Branch::name_is_valid(branch)? {
        return Err(HeadError::IncompatibleRecord);
    }
    control.put_record(
        &head_kind(repository_id),
        HEAD_KEY,
        &canonical_bytes(&HeadRecord {
            format_version: 1,
            branch: branch.to_owned(),
        })?,
    )?;
    Ok(())
}
