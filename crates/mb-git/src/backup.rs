//! Versioned, source-independent Git graph descriptor for encrypted revision
//! metadata. Blob payloads are referenced by MutualBackup data sectors; raw
//! Git commit, tree, and tag objects stay small metadata, never a second blob store.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use git2::{Branch, ObjectType, Oid, Repository};
use mb_core::{
    ModelError, SectorRef, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_size_bounded,
};
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
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
    #[error("Git backup I/O failed: {0}")]
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

impl GitBackupBlob {
    /// Verify exact raw Git blob bytes with one sector-sized buffer. The
    /// reader must supply logical sparse holes as zero bytes and end at length.
    pub fn verify_plaintext(&self, reader: &mut impl Read) -> Result<(), GitBackupError> {
        let mut hash = Sha1::new();
        hash.update(format!("blob {}\0", self.logical_len).as_bytes());
        let mut remaining = self.logical_len;
        let mut buffer = [0_u8; V1_SECTOR_SIZE];
        while remaining != 0 {
            let count = remaining.min(buffer.len() as u64) as usize;
            reader.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count]);
            remaining -= count as u64;
        }
        let actual: [u8; 20] = hash.finalize().into();
        if reader.read(&mut buffer[..1])? != 0 || actual != self.oid {
            return Err(GitBackupError::InvalidGraph);
        }
        Ok(())
    }
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
        self.symlink_blob_oids().map(|_| ())
    }

    /// Validate the descriptor and identify blobs that must be usable as
    /// symlink targets when native anchors are imported on recovery.
    pub fn symlink_blob_oids(&self) -> Result<HashSet<Oid>, GitBackupError> {
        if !matches!(self.format_version, 1..=4)
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
        match canonical_size_bounded(self, V1_MAX_CATALOG_BYTES) {
            Ok(_) => {}
            Err(ModelError::EncodingTooLarge { .. }) => {
                return Err(GitBackupError::TooLarge);
            }
            Err(error) => return Err(error.into()),
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
                3 if self.format_version >= 3 => ObjectType::Tag,
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
        let mut blob_lengths = HashMap::new();
        for blob in &self.blobs {
            let oid = Oid::from_bytes(&blob.oid)?;
            if blob_lengths.insert(oid, blob.logical_len).is_some() {
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
        let mut seen_tags = HashSet::new();
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
            let mut oid = Oid::from_bytes(&reference.oid)?;
            let mut chain = HashSet::new();
            loop {
                if !chain.insert(oid) || chain.len() > MAX_OBJECTS {
                    return Err(GitBackupError::InvalidGraph);
                }
                match kinds.get(&oid) {
                    Some(ObjectType::Commit) => {
                        pending_commits.push(oid);
                        break;
                    }
                    Some(ObjectType::Tag) if name.starts_with("refs/tags/") => {
                        let tag = repository
                            .find_tag(oid)
                            .map_err(|_| GitBackupError::InvalidGraph)?;
                        if chain.len() == 1
                            && tag.name_bytes() != &name.as_bytes()["refs/tags/".len()..]
                        {
                            return Err(GitBackupError::InvalidGraph);
                        }
                        if !matches!(
                            tag.target_type(),
                            Some(ObjectType::Commit | ObjectType::Tag)
                        ) || kinds.get(&tag.target_id()) != tag.target_type().as_ref()
                        {
                            return Err(GitBackupError::InvalidGraph);
                        }
                        seen_tags.insert(oid);
                        oid = tag.target_id();
                    }
                    _ => return Err(GitBackupError::InvalidGraph),
                }
            }
        }
        if ref_names.iter().any(|name| {
            name.iter()
                .enumerate()
                .any(|(index, byte)| *byte == b'/' && ref_names.contains(&name[..index]))
        }) {
            return Err(GitBackupError::InvalidGraph);
        }
        if matches!(self.format_version, 2 | 3)
            && !self.refs.is_empty()
            && !ref_names.contains(format!("refs/heads/{}", self.head_branch).as_bytes())
        {
            return Err(GitBackupError::InvalidGraph);
        }
        if self.format_version >= 2 && self.refs.is_empty() && self.head_branch != "main" {
            return Err(GitBackupError::InvalidGraph);
        }
        let mut seen_commits = HashSet::new();
        let mut pending_trees = Vec::new();
        let mut seen_trees = HashSet::new();
        let mut seen_blobs = HashSet::new();
        let mut symlink_blobs = HashSet::new();
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
                        // Checkout stores symlinks as exact target bytes and
                        // cannot publish an empty or oversized target.
                        if !matches!(entry.filemode(), 0o100644 | 0o100755 | 0o120000)
                            || !blob_lengths.contains_key(&entry.id())
                            || entry.filemode() == 0o120000
                                && !blob_lengths
                                    .get(&entry.id())
                                    .is_some_and(|length| (1..=4095).contains(length))
                        {
                            return Err(GitBackupError::InvalidGraph);
                        }
                        if entry.filemode() == 0o120000 {
                            symlink_blobs.insert(entry.id());
                        }
                        seen_blobs.insert(entry.id());
                    }
                    _ => return Err(GitBackupError::InvalidGraph),
                }
            }
        }
        if seen_commits.len() + seen_trees.len() + seen_tags.len() != kinds.len()
            || seen_blobs != blob_lengths.into_keys().collect()
        {
            return Err(GitBackupError::InvalidGraph);
        }
        Ok(symlink_blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paged_legacy_blob_verifier_checks_exact_length_oid_and_bounded_reads() {
        struct BoundedReader<'a>(&'a [u8]);
        impl Read for BoundedReader<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                assert!(output.len() <= V1_SECTOR_SIZE);
                self.0.read(output)
            }
        }
        let bytes = vec![0x81; V1_SECTOR_SIZE * 3 + 1];
        let blob = GitBackupBlob {
            oid: Oid::hash_object(ObjectType::Blob, &bytes)
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            logical_len: bytes.len() as u64,
            data_extents: Vec::new(),
        };
        blob.verify_plaintext(&mut BoundedReader(&bytes)).unwrap();
        assert!(
            blob.verify_plaintext(&mut &bytes[..bytes.len() - 1])
                .is_err()
        );
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(blob.verify_plaintext(&mut longer.as_slice()).is_err());
        let mut damaged = bytes.clone();
        damaged[0] ^= 1;
        assert!(blob.verify_plaintext(&mut damaged.as_slice()).is_err());
        struct Offline;
        impl Read for Offline {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("offline"))
            }
        }
        assert!(blob.verify_plaintext(&mut Offline).is_err());
        let empty = GitBackupBlob {
            oid: Oid::hash_object(ObjectType::Blob, &[])
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap(),
            logical_len: 0,
            data_extents: Vec::new(),
        };
        empty.verify_plaintext(&mut [].as_slice()).unwrap();
    }

    #[test]
    fn bounded_backup_admission_counts_full_descriptor_at_the_legacy_limit() {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(directory.path()).unwrap();
        let tree_oid = repository.treebuilder(None).unwrap().write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature =
            git2::Signature::new("Author", "a@example.test", &git2::Time::new(0, 0)).unwrap();
        let mut commit = repository
            .commit_create_buffer(&signature, &signature, "message", &tree, &[])
            .unwrap()
            .to_vec();
        commit.resize(V1_MAX_CATALOG_BYTES, b'x');
        let mut descriptor = GitBackupDescriptor {
            format_version: 4,
            repository_id: Uuid::from_bytes([1; 16]),
            refs: vec![GitGraphRef {
                name: b"refs/heads/main".to_vec(),
                oid: [0; 20],
            }],
            objects: vec![
                GitGraphObject {
                    kind: 1,
                    oid: [0; 20],
                    bytes: commit,
                },
                GitGraphObject {
                    kind: 2,
                    oid: tree_oid.as_bytes().try_into().unwrap(),
                    bytes: vec![],
                },
            ],
            blobs: vec![],
            head_branch: "main".to_owned(),
        };
        let overhead = canonical_size_bounded(&descriptor, usize::MAX).unwrap()
            - descriptor.objects[0].bytes.len();
        assert!(overhead > descriptor.refs[0].name.len());
        let raw_limit = V1_MAX_CATALOG_BYTES - overhead;
        for delta in [-1_isize, 0, 1] {
            descriptor.objects[0]
                .bytes
                .resize(raw_limit.checked_add_signed(delta).unwrap(), b'x');
            let oid = Oid::hash_object(ObjectType::Commit, &descriptor.objects[0].bytes).unwrap();
            descriptor.objects[0].oid = oid.as_bytes().try_into().unwrap();
            descriptor.refs[0].oid = descriptor.objects[0].oid;
            let actual = canonical_size_bounded(&descriptor, usize::MAX).unwrap();
            assert_eq!(
                actual,
                V1_MAX_CATALOG_BYTES.checked_add_signed(delta).unwrap()
            );
            let before_oid = descriptor.refs[0].oid;
            if delta <= 0 {
                descriptor.validate().unwrap();
            } else {
                assert!(matches!(
                    descriptor.validate(),
                    Err(GitBackupError::TooLarge)
                ));
            }
            assert_eq!(descriptor.refs[0].oid, before_oid);
            assert_eq!(
                descriptor.objects[0].bytes.len(),
                raw_limit.checked_add_signed(delta).unwrap()
            );
        }
    }

    #[test]
    fn annotated_tag_is_reachable_metadata_and_must_match_its_ref() {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(directory.path()).unwrap();
        let tree_oid = repository.treebuilder(None).unwrap().write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("Tagger", "tagger@example.test").unwrap();
        let commit_oid = repository
            .commit(None, &signature, &signature, "base", &tree, &[])
            .unwrap();
        let commit = repository
            .find_object(commit_oid, Some(ObjectType::Commit))
            .unwrap();
        let tag_oid = repository
            .tag_annotation_create("release", &commit, &signature, "raw bytes\r\n")
            .unwrap();
        let odb = repository.odb().unwrap();
        let object = |kind, oid: Oid| GitGraphObject {
            kind,
            oid: oid.as_bytes().try_into().unwrap(),
            bytes: odb.read(oid).unwrap().data().to_vec(),
        };
        let descriptor = GitBackupDescriptor {
            format_version: 3,
            repository_id: Uuid::new_v4(),
            refs: vec![
                GitGraphRef {
                    name: b"refs/heads/main".to_vec(),
                    oid: commit_oid.as_bytes().try_into().unwrap(),
                },
                GitGraphRef {
                    name: b"refs/tags/release".to_vec(),
                    oid: tag_oid.as_bytes().try_into().unwrap(),
                },
            ],
            objects: vec![
                object(1, commit_oid),
                object(2, tree_oid),
                object(3, tag_oid),
            ],
            blobs: Vec::new(),
            head_branch: "main".to_owned(),
        };
        descriptor.validate().unwrap();
        let mut old_format = descriptor.clone();
        old_format.format_version = 2;
        assert!(old_format.validate().is_err());
        let mut wrong_name = descriptor.clone();
        wrong_name.refs[1].name = b"refs/tags/other".to_vec();
        assert!(wrong_name.validate().is_err());
        let mut orphan = descriptor.clone();
        orphan.refs.pop();
        assert!(orphan.validate().is_err());
        let mut unborn = descriptor;
        unborn.format_version = 4;
        unborn.refs.remove(0);
        unborn.validate().unwrap();
        unborn.format_version = 3;
        assert!(unborn.validate().is_err());
    }

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

    #[test]
    fn backup_rejects_symlinks_that_checkout_cannot_recreate() {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(directory.path()).unwrap();
        let signature = git2::Signature::now("Author", "a@example.test").unwrap();
        for payload in [Vec::new(), vec![b'a'; 4096]] {
            let blob_oid = repository.blob(&payload).unwrap();
            let mut builder = repository.treebuilder(None).unwrap();
            builder.insert("link", blob_oid, 0o120000).unwrap();
            let tree_oid = builder.write().unwrap();
            let tree = repository.find_tree(tree_oid).unwrap();
            let commit_oid = repository
                .commit(None, &signature, &signature, "symlink", &tree, &[])
                .unwrap();
            let odb = repository.odb().unwrap();
            let object = |kind, oid: Oid| GitGraphObject {
                kind,
                oid: oid.as_bytes().try_into().unwrap(),
                bytes: odb.read(oid).unwrap().data().to_vec(),
            };
            let descriptor = GitBackupDescriptor {
                format_version: 4,
                repository_id: Uuid::new_v4(),
                refs: vec![GitGraphRef {
                    name: b"refs/heads/main".to_vec(),
                    oid: commit_oid.as_bytes().try_into().unwrap(),
                }],
                objects: vec![object(1, commit_oid), object(2, tree_oid)],
                blobs: vec![GitBackupBlob {
                    oid: blob_oid.as_bytes().try_into().unwrap(),
                    logical_len: payload.len() as u64,
                    data_extents: Vec::new(),
                }],
                head_branch: "main".to_owned(),
            };
            assert!(matches!(
                descriptor.validate(),
                Err(GitBackupError::InvalidGraph)
            ));
        }
    }
}
