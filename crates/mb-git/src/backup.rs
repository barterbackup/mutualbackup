//! Versioned, source-independent Git graph descriptor for encrypted revision
//! metadata. Blob payloads are referenced by MutualBackup data sectors; raw
//! Git commit and tree objects stay small metadata, never a second blob store.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use git2::{Branch, ObjectType, Oid, Repository};
use mb_core::{SectorRef, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_bytes};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::stage::stage_path_key;
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
    pub head_branch: String,
}

impl GitBackupDescriptor {
    /// Validate the full Git DAG and each blob's sector geometry before this
    /// descriptor can be placed in a signed revision or accepted on recovery.
    pub fn validate(&self) -> Result<(), GitBackupError> {
        if !matches!(self.format_version, 1 | 2)
            || self.repository_id.is_nil()
            || self.refs.len() > MAX_OBJECTS
            || self.objects.len() > MAX_OBJECTS
            || self.blobs.len() > MAX_OBJECTS
            || self.head_branch.len() > 1024
            || !Branch::name_is_valid(&self.head_branch)?
            || (self.format_version == 1 && self.head_branch != "main")
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
            let branch_valid = match name.strip_prefix("refs/heads/") {
                Some(branch) => Branch::name_is_valid(branch)?,
                None => true,
            };
            if !name.starts_with("refs/")
                || !git2::Reference::is_valid_name(name)
                || !branch_valid
                || !ref_names.insert(reference.name.as_slice())
            {
                return Err(GitBackupError::InvalidGraph);
            }
            pending_commits.push(Oid::from_bytes(&reference.oid)?);
        }
        if ref_names.iter().any(|name| {
            name.iter()
                .enumerate()
                .any(|(index, byte)| *byte == b'/' && ref_names.contains(&name[..index]))
        }) {
            return Err(GitBackupError::InvalidGraph);
        }
        if self.format_version == 2
            && !self.refs.is_empty()
            && !ref_names.contains(format!("refs/heads/{}", self.head_branch).as_bytes())
        {
            return Err(GitBackupError::InvalidGraph);
        }
        if self.format_version == 2 && self.refs.is_empty() && self.head_branch != "main" {
            return Err(GitBackupError::InvalidGraph);
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
            pending_trees.push((Vec::<u8>::new(), commit.tree_id()));
            pending_commits.extend(commit.parent_ids());
        }
        let mut tree_visits = 0_usize;
        while let Some((prefix, oid)) = pending_trees.pop() {
            tree_visits += 1;
            if tree_visits > MAX_OBJECTS {
                return Err(GitBackupError::InvalidGraph);
            }
            seen_trees.insert(oid);
            if kinds.get(&oid) != Some(&ObjectType::Tree) {
                return Err(GitBackupError::InvalidGraph);
            }
            let tree = repository
                .find_tree(oid)
                .map_err(|_| GitBackupError::InvalidGraph)?;
            for entry in tree.iter() {
                let mut path = prefix.clone();
                path.extend_from_slice(entry.name_bytes());
                stage_path_key(&PathBuf::from(OsString::from_vec(path.clone())))
                    .map_err(|_| GitBackupError::InvalidGraph)?;
                match entry.kind() {
                    Some(ObjectType::Tree) if entry.filemode() == 0o040000 => {
                        path.push(b'/');
                        pending_trees.push((path, entry.id()));
                    }
                    Some(ObjectType::Blob) => {
                        if !matches!(entry.filemode(), 0o100644 | 0o100755 | 0o120000)
                            || !blob_ids.contains(&entry.id())
                        {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_rejects_unsafe_path_on_another_branch() {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(directory.path()).unwrap();
        let blob = repository.blob(b"").unwrap();
        let mut nested = repository.treebuilder(None).unwrap();
        nested.insert("file", blob, 0o100644).unwrap();
        let nested_oid = nested.write().unwrap();
        let mut main_builder = repository.treebuilder(None).unwrap();
        main_builder.insert("safe", nested_oid, 0o040000).unwrap();
        let main_tree_oid = main_builder.write().unwrap();
        let mut topic_builder = repository.treebuilder(None).unwrap();
        topic_builder
            .insert(".mutualbackup", nested_oid, 0o040000)
            .unwrap();
        let topic_tree_oid = topic_builder.write().unwrap();
        let signature = git2::Signature::now("Author", "a@example.test").unwrap();
        let main_tree = repository.find_tree(main_tree_oid).unwrap();
        let topic_tree = repository.find_tree(topic_tree_oid).unwrap();
        let main_commit = repository
            .commit(None, &signature, &signature, "main", &main_tree, &[])
            .unwrap();
        let topic_commit = repository
            .commit(None, &signature, &signature, "topic", &topic_tree, &[])
            .unwrap();
        let odb = repository.odb().unwrap();
        let graph_object = |kind: u8, oid: Oid| GitGraphObject {
            kind,
            oid: oid.as_bytes().try_into().unwrap(),
            bytes: odb.read(oid).unwrap().data().to_vec(),
        };
        let mut descriptor = GitBackupDescriptor {
            format_version: 2,
            repository_id: Uuid::new_v4(),
            refs: vec![GitGraphRef {
                name: b"refs/heads/main".to_vec(),
                oid: main_commit.as_bytes().try_into().unwrap(),
            }],
            objects: vec![
                graph_object(1, main_commit),
                graph_object(2, main_tree_oid),
                graph_object(2, nested_oid),
            ],
            blobs: vec![GitBackupBlob {
                oid: blob.as_bytes().try_into().unwrap(),
                logical_len: 0,
                data_extents: Vec::new(),
            }],
            head_branch: "main".to_owned(),
        };
        descriptor.validate().unwrap();
        descriptor.refs.push(GitGraphRef {
            name: b"refs/heads/topic".to_vec(),
            oid: topic_commit.as_bytes().try_into().unwrap(),
        });
        descriptor.objects.push(graph_object(1, topic_commit));
        descriptor.objects.push(graph_object(2, topic_tree_oid));
        assert!(matches!(
            descriptor.validate(),
            Err(GitBackupError::InvalidGraph)
        ));
    }
}
