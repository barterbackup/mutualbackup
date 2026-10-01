//! Versioned, source-independent Git graph descriptor for encrypted revision
//! metadata. Blob payloads are referenced by MutualBackup data sectors; raw
//! Git commit and tree objects stay small metadata, never a second blob store.

use std::collections::{HashMap, HashSet};

use git2::{ObjectType, Oid, Repository};
use mb_core::{SectorRef, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{GitGraphObject, GitGraphRef};

const MAX_OBJECTS: usize = 100_000;

#[derive(Debug, Error)]
pub enum GitBackupError {
    #[error("Git backup descriptor is malformed or does not describe one reachable graph")]
    InvalidGraph,
    #[error("Git backup descriptor exceeds the bounded revision metadata limit")]
    TooLarge,
    #[error("libgit2 rejected Git backup metadata: {0}")]
    Git(#[from] git2::Error),
    #[error("temporary Git metadata repository failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Git backup descriptor encoding failed: {0}")]
    Model(#[from] mb_core::ModelError),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitDataExtent {
    pub offset: u64,
    pub logical_len: u64,
    pub sectors: Vec<SectorRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitBackupBlob {
    pub oid: [u8; 20],
    pub logical_len: u64,
    pub data_extents: Vec<GitDataExtent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitBackupDescriptor {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub refs: Vec<GitGraphRef>,
    pub objects: Vec<GitGraphObject>,
    pub blobs: Vec<GitBackupBlob>,
}

impl GitBackupDescriptor {
    /// Validate the full Git DAG and each blob's sector geometry before this
    /// descriptor can be placed in a signed revision or accepted on recovery.
    pub fn validate(&self) -> Result<(), GitBackupError> {
        if self.format_version != 1
            || self.repository_id.is_nil()
            || self.refs.len() > MAX_OBJECTS
            || self.objects.len() > MAX_OBJECTS
            || self.blobs.len() > MAX_OBJECTS
        {
            return Err(GitBackupError::InvalidGraph);
        }
        let encoded = canonical_bytes(self)?;
        if encoded.len() > V1_MAX_CATALOG_BYTES {
            return Err(GitBackupError::TooLarge);
        }
        let temporary = tempfile::tempdir()?;
        let repository = Repository::init_bare(temporary.path())?;
        let odb = git2::Odb::new()?;
        let _pack = odb.add_new_mempack_backend(1000)?;
        repository.set_odb(&odb)?;
        let mut kinds = HashMap::new();
        for object in &self.objects {
            let kind = match object.kind {
                1 => ObjectType::Commit,
                2 => ObjectType::Tree,
                _ => return Err(GitBackupError::InvalidGraph),
            };
            let oid = Oid::hash_object(kind, &object.bytes)?;
            if oid.as_bytes() != object.oid
                || kinds.insert(oid, kind).is_some()
                || odb.write(kind, &object.bytes)? != oid
            {
                return Err(GitBackupError::InvalidGraph);
            }
        }
        let mut blob_ids = HashSet::new();
        for blob in &self.blobs {
            let oid = Oid::from_bytes(&blob.oid)?;
            if !blob_ids.insert(oid) {
                return Err(GitBackupError::InvalidGraph);
            }
            let mut previous_end = 0_u64;
            for extent in &blob.data_extents {
                let end = extent
                    .offset
                    .checked_add(extent.logical_len)
                    .ok_or(GitBackupError::InvalidGraph)?;
                if extent.logical_len == 0 || extent.offset < previous_end || end > blob.logical_len
                {
                    return Err(GitBackupError::InvalidGraph);
                }
                let mut covered = 0_u64;
                for sector in &extent.sectors {
                    if sector.logical_len == 0 || sector.logical_len as usize > V1_SECTOR_SIZE {
                        return Err(GitBackupError::InvalidGraph);
                    }
                    covered = covered
                        .checked_add(sector.logical_len as u64)
                        .ok_or(GitBackupError::InvalidGraph)?;
                }
                if covered != extent.logical_len {
                    return Err(GitBackupError::InvalidGraph);
                }
                previous_end = end;
            }
        }
        let mut ref_names = HashSet::new();
        let mut pending_commits = Vec::new();
        for reference in &self.refs {
            let name =
                std::str::from_utf8(&reference.name).map_err(|_| GitBackupError::InvalidGraph)?;
            if !name.starts_with("refs/")
                || !git2::Reference::is_valid_name(name)
                || !ref_names.insert(reference.name.as_slice())
            {
                return Err(GitBackupError::InvalidGraph);
            }
            pending_commits.push(Oid::from_bytes(&reference.oid)?);
        }
        let mut seen_commits = HashSet::new();
        let mut pending_trees = Vec::new();
        let mut seen_trees = HashSet::new();
        let mut seen_blobs = HashSet::new();
        while let Some(oid) = pending_commits.pop() {
            if !seen_commits.insert(oid) {
                continue;
            }
            if kinds.get(&oid) != Some(&ObjectType::Commit) {
                return Err(GitBackupError::InvalidGraph);
            }
            let commit = repository
                .find_commit(oid)
                .map_err(|_| GitBackupError::InvalidGraph)?;
            pending_trees.push(commit.tree_id());
            pending_commits.extend(commit.parent_ids());
        }
        while let Some(oid) = pending_trees.pop() {
            if !seen_trees.insert(oid) {
                continue;
            }
            if kinds.get(&oid) != Some(&ObjectType::Tree) {
                return Err(GitBackupError::InvalidGraph);
            }
            let tree = repository
                .find_tree(oid)
                .map_err(|_| GitBackupError::InvalidGraph)?;
            for entry in tree.iter() {
                match entry.kind() {
                    Some(ObjectType::Tree) => pending_trees.push(entry.id()),
                    Some(ObjectType::Blob) => {
                        if !blob_ids.contains(&entry.id()) {
                            return Err(GitBackupError::InvalidGraph);
                        }
                        seen_blobs.insert(entry.id());
                    }
                    _ => return Err(GitBackupError::InvalidGraph),
                }
            }
        }
        if seen_commits.len() + seen_trees.len() != kinds.len() || seen_blobs != blob_ids {
            return Err(GitBackupError::InvalidGraph);
        }
        Ok(())
    }
}
