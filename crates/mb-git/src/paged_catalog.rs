//! One bounded Git container for the paged descriptor migration. Production
//! admission stays on legacy formats until every signed revision/replay/recovery
//! consumer migrates and the shared dataset/history policy is qualified.

use mb_core::{
    CATALOG_MAX_PAGE_OCCURRENCES, CATALOG_MAX_STREAM_BYTES, CatalogError, CatalogStreamError,
    canonical_bytes, decode_canonical,
};
#[cfg(target_os = "linux")]
use mb_core::{CatalogPageRef, CatalogScope};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

#[cfg(target_os = "linux")]
use crate::{
    GitBlobCatalogBuilder, GitObjectCatalogBuilder, GitRefCatalogBuilder, GitRefRecord,
    git_ref_name_order,
};
use crate::{GitBlobCatalogRoot, GitObjectCatalogRoot, GitRefCatalogRoot};

pub const GIT_CATALOG_ROOT_BYTES: usize = 4096;

/// This complete root requires authentication in owner-encrypted metadata.
/// Its three streams share one aggregate metadata/page-occurrence budget.
/// Each stream needs durable ownership; an opaque container leaf alone cannot
/// retain its referenced streams through the page store's index-child GC edges.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitCatalogRoot {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub refs: GitRefCatalogRoot,
    pub objects: GitObjectCatalogRoot,
    pub blobs: GitBlobCatalogRoot,
}

impl GitCatalogRoot {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.format_version != 1 || self.repository_id.is_nil() {
            return Err(CatalogError::InvalidPage);
        }
        self.refs.validate()?;
        self.objects.validate()?;
        self.blobs.validate()?;
        let pages = [
            self.refs.records.page,
            self.objects.records.page,
            self.blobs.records.page,
        ];
        let bytes: u64 = pages.iter().map(|page| page.byte_len).sum();
        let occurrences: u64 = pages.iter().map(|page| page.page_occurrences).sum();
        if bytes > CATALOG_MAX_STREAM_BYTES || occurrences > CATALOG_MAX_PAGE_OCCURRENCES {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > GIT_CATALOG_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate()?;
        if canonical_bytes(&root)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }
}

#[derive(Debug, Error)]
pub enum GitCatalogWriteError<E> {
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Legacy(#[from] crate::GitBackupError),
    #[error(transparent)]
    Catalog(#[from] CatalogStreamError<E>),
}

#[cfg(target_os = "linux")]
impl crate::GitBackupDescriptor {
    /// Validate a supported legacy descriptor before writing any pages, then
    /// emit its exact refs/object bytes/blob recipes through bounded streams.
    /// Sorting retains only borrowed indices into the already bounded legacy
    /// value. New captures must supply ordered streams directly, not assemble
    /// a larger legacy value. Unsupported/oversized history stays untouched.
    pub fn write_paged_catalog<E>(
        &self,
        scope: CatalogScope,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<GitCatalogRoot, GitCatalogWriteError<E>> {
        self.validate()?;
        let mut references: Vec<_> = self.refs.iter().collect();
        references.sort_by(|left, right| git_ref_name_order(&left.name, &right.name));
        // Check the new name geometry before any durable write too.
        for reference in &references {
            if reference.name.len() > crate::GIT_REF_NAME_BYTES {
                return Err(CatalogStreamError::<E>::from(CatalogError::Bounds).into());
            }
            GitRefRecord {
                format_version: 1,
                name: reference.name.clone(),
                oid: reference.oid,
            }
            .validate()
            .map_err(CatalogStreamError::from)?;
        }
        let mut refs = GitRefCatalogBuilder::new(scope, self.head_branch.as_bytes())
            .map_err(CatalogStreamError::from)?;
        for reference in references {
            refs.push_ref(
                &GitRefRecord {
                    format_version: 1,
                    name: reference.name.clone(),
                    oid: reference.oid,
                },
                sink,
            )?;
        }
        let refs = refs.finish(sink)?;
        let mut objects: Vec<_> = self.objects.iter().collect();
        objects.sort_by_key(|object| object.oid);
        let mut object_builder =
            GitObjectCatalogBuilder::new(scope).map_err(CatalogStreamError::from)?;
        for object in objects {
            object_builder.push_object(
                object.oid,
                object.kind,
                object.bytes.len() as u64,
                &mut object.bytes.as_slice(),
                sink,
            )?;
        }
        let objects = object_builder.finish(sink)?;
        let mut blobs: Vec<_> = self.blobs.iter().collect();
        blobs.sort_by_key(|blob| blob.oid);
        let mut blob_builder =
            GitBlobCatalogBuilder::new(scope).map_err(CatalogStreamError::from)?;
        for blob in blobs {
            blob_builder.push_blob(blob, sink)?;
        }
        let root = GitCatalogRoot {
            format_version: 1,
            repository_id: self.repository_id,
            refs,
            objects,
            blobs: blob_builder.finish(sink)?,
        };
        root.validate().map_err(CatalogStreamError::from)?;
        Ok(root)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::{
        GitBackupBlob, GitBackupDescriptor, GitBlobCatalogReader, GitBlobRecord, GitDataExtent,
        GitGraphObject, GitGraphRef, GitObjectCatalogReader, GitObjectRecord, GitRefCatalogReader,
    };
    use git2::{ObjectType, Oid, Repository, Signature};
    use mb_core::{KeyMaterial, NodeId, SectorRef, Seed};
    use mb_store::{CatalogIntent, ControlStore};
    use std::collections::HashMap;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn descriptor() -> GitBackupDescriptor {
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(directory.path()).unwrap();
        let blob_oid = repository.blob(b"exact blob bytes\r\n").unwrap();
        let mut builder = repository.treebuilder(None).unwrap();
        builder.insert("file", blob_oid, 0o100644).unwrap();
        let tree_oid = builder.write().unwrap();
        let tree = repository.find_tree(tree_oid).unwrap();
        let signature =
            Signature::new("Example", "example@example.test", &git2::Time::new(1, 0)).unwrap();
        let commit_oid = repository
            .commit(None, &signature, &signature, "exact commit\r\n", &tree, &[])
            .unwrap();
        let object = repository
            .find_object(commit_oid, Some(ObjectType::Commit))
            .unwrap();
        let tag_oid = repository
            .tag_annotation_create("release", &object, &signature, "exact tag\r\n")
            .unwrap();
        let odb = repository.odb().unwrap();
        let object = |kind, oid: Oid| GitGraphObject {
            kind,
            oid: oid.as_bytes().try_into().unwrap(),
            bytes: odb.read(oid).unwrap().data().to_vec(),
        };
        GitBackupDescriptor {
            format_version: 4,
            repository_id: Uuid::from_bytes([6; 16]),
            refs: vec![
                GitGraphRef {
                    name: b"refs/tags/release".to_vec(),
                    oid: tag_oid.as_bytes().try_into().unwrap(),
                },
                GitGraphRef {
                    name: b"refs/heads/main-other".to_vec(),
                    oid: commit_oid.as_bytes().try_into().unwrap(),
                },
                GitGraphRef {
                    name: b"refs/heads/main".to_vec(),
                    oid: commit_oid.as_bytes().try_into().unwrap(),
                },
            ],
            objects: vec![
                object(3, tag_oid),
                object(2, tree_oid),
                object(1, commit_oid),
            ],
            blobs: vec![GitBackupBlob {
                oid: blob_oid.as_bytes().try_into().unwrap(),
                logical_len: 18,
                data_extents: vec![GitDataExtent {
                    offset: 0,
                    logical_len: 18,
                    sectors: vec![SectorRef {
                        id: [7; 32],
                        root: [8; 32],
                        logical_len: 18,
                    }],
                }],
            }],
            head_branch: "main".to_owned(),
        }
    }

    fn restore_small(
        root: &GitCatalogRoot,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, &'static str>,
    ) -> GitBackupDescriptor {
        // Compatibility fixture only: production recovery must stream into a
        // durable intent rather than collect an unbounded legacy descriptor.
        let mut restored = GitBackupDescriptor {
            format_version: 4,
            repository_id: root.repository_id,
            refs: Vec::new(),
            objects: Vec::new(),
            blobs: Vec::new(),
            head_branch: String::from_utf8(root.refs.head_branch.clone()).unwrap(),
        };
        let mut refs = GitRefCatalogReader::new(scope(), root.refs.clone()).unwrap();
        while let Some(reference) = refs.next_ref(fetch).unwrap() {
            restored.refs.push(GitGraphRef {
                name: reference.name,
                oid: reference.oid,
            });
        }
        let mut objects = GitObjectCatalogReader::new(scope(), root.objects).unwrap();
        while let Some(record) = objects.next_record(fetch).unwrap() {
            match record {
                GitObjectRecord::Header { oid, kind, .. } => {
                    restored.objects.push(GitGraphObject {
                        kind,
                        oid,
                        bytes: Vec::new(),
                    })
                }
                GitObjectRecord::Fragment { offset, bytes } => {
                    let object = restored.objects.last_mut().unwrap();
                    assert_eq!(offset, object.bytes.len() as u64);
                    object.bytes.extend(bytes);
                }
            }
        }
        let mut blobs = GitBlobCatalogReader::new(scope(), root.blobs).unwrap();
        while let Some(record) = blobs.next_record(fetch).unwrap() {
            match record {
                GitBlobRecord::Blob {
                    oid, logical_len, ..
                } => restored.blobs.push(GitBackupBlob {
                    oid,
                    logical_len,
                    data_extents: Vec::new(),
                }),
                GitBlobRecord::Extent {
                    offset,
                    logical_len,
                    ..
                } => restored
                    .blobs
                    .last_mut()
                    .unwrap()
                    .data_extents
                    .push(GitDataExtent {
                        offset,
                        logical_len,
                        sectors: Vec::new(),
                    }),
                GitBlobRecord::Sectors {
                    first_sector,
                    references,
                } => {
                    let extent = restored
                        .blobs
                        .last_mut()
                        .unwrap()
                        .data_extents
                        .last_mut()
                        .unwrap();
                    assert_eq!(first_sector, extent.sectors.len() as u64);
                    extent.sectors.extend(references);
                }
            }
        }
        restored.validate().unwrap();
        restored
    }

    #[test]
    fn paged_git_catalog_preserves_legacy_refs_objects_recipes_and_unborn_selection() {
        for head in ["main", "unborn"] {
            let mut original = descriptor();
            original.head_branch = head.to_owned();
            let before = canonical_bytes(&original).unwrap();
            let mut pages = HashMap::new();
            let mut sink = |reference: CatalogPageRef, bytes| {
                pages.insert(reference.hash, bytes);
                Ok::<_, &'static str>(())
            };
            let root = original.write_paged_catalog(scope(), &mut sink).unwrap();
            assert_eq!(canonical_bytes(&original).unwrap(), before);
            assert_eq!(root.refs.selected_head.is_some(), head == "main");
            let encoded = canonical_bytes(&root).unwrap();
            assert!(encoded.len() <= GIT_CATALOG_ROOT_BYTES);
            assert_eq!(GitCatalogRoot::decode(&encoded).unwrap(), root);
            let restored = restore_small(&root, &mut |reference: CatalogPageRef| {
                Ok(pages[&reference.hash].clone())
            });
            original
                .refs
                .sort_by(|left, right| git_ref_name_order(&left.name, &right.name));
            original.objects.sort_by_key(|object| object.oid);
            original.blobs.sort_by_key(|blob| blob.oid);
            assert_eq!(restored, original);
        }
    }

    #[test]
    fn paged_git_catalog_staged_pages_and_complete_root_reopen_in_control_store() {
        let directory = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([31; 32]));
        let path = directory.path().join("control.db");
        let control = ControlStore::open(&path, &keys).unwrap();
        let intent = CatalogIntent {
            id: Uuid::from_bytes([9; 16]),
            scope: scope(),
            section: mb_core::CatalogSection::GitGraph,
        };
        control.begin_catalog(intent).unwrap();
        let original = descriptor();
        let root = original
            .write_paged_catalog(scope(), &mut |reference: CatalogPageRef, bytes: Vec<u8>| {
                control.stage_catalog_page(intent, reference, &bytes)
            })
            .unwrap();
        control
            .put_record(
                "test-paged-git-root",
                b"root",
                &canonical_bytes(&root).unwrap(),
            )
            .unwrap();
        drop(control);
        let control = ControlStore::open(&path, &keys).unwrap();
        let root = GitCatalogRoot::decode(
            &control
                .get_record("test-paged-git-root", b"root")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let restored = restore_small(&root, &mut |reference| {
            control
                .catalog_page(scope(), intent.section, reference)
                .map_err(|_| "page read failed")
        });
        assert_eq!(restored.repository_id, original.repository_id);
        assert_eq!(restored.blobs, original.blobs);
        assert_eq!(
            control.catalog_intent_state(intent).unwrap(),
            mb_store::CatalogIntentState::Building
        );
        // Keeping the staging intent is deliberate: atomic multi-root/signed
        // publication and authenticated root-set retention are still required.
    }

    #[test]
    fn paged_git_catalog_invalid_legacy_and_sink_failure_cannot_emit_a_root() {
        let mut invalid = descriptor();
        invalid.objects[0].bytes.push(0);
        let mut writes = 0;
        assert!(
            invalid
                .write_paged_catalog(scope(), &mut |_, _| {
                    writes += 1;
                    Ok::<_, &'static str>(())
                })
                .is_err()
        );
        assert_eq!(writes, 0);
        let mut large_name = descriptor();
        let mut name = b"refs/heads/".to_vec();
        name.resize(crate::GIT_REF_NAME_BYTES + 1, b'x');
        large_name.refs[1].name = name;
        large_name.validate().unwrap();
        let before_large = canonical_bytes(&large_name).unwrap();
        assert!(
            large_name
                .write_paged_catalog(scope(), &mut |_, _| {
                    writes += 1;
                    Ok::<_, &'static str>(())
                })
                .is_err()
        );
        assert_eq!(writes, 0);
        assert_eq!(canonical_bytes(&large_name).unwrap(), before_large);
        let mut invalid = descriptor();
        invalid.format_version = 0;
        assert!(
            invalid
                .write_paged_catalog(scope(), &mut |_, _| {
                    writes += 1;
                    Ok::<_, &'static str>(())
                })
                .is_err()
        );
        assert_eq!(writes, 0);
        let original = descriptor();
        let before = canonical_bytes(&original).unwrap();
        assert!(
            original
                .write_paged_catalog(scope(), &mut |_, _| Err::<(), _>("offline"))
                .is_err()
        );
        assert_eq!(canonical_bytes(&original).unwrap(), before);
    }

    #[test]
    fn paged_git_catalog_root_bounds_version_encoding_and_aggregate_geometry() {
        let root = descriptor()
            .write_paged_catalog(scope(), &mut |_, _| Ok::<_, &'static str>(()))
            .unwrap();
        let mut invalid = root.clone();
        invalid.format_version = 2;
        assert!(invalid.validate().is_err());
        let mut invalid = root.clone();
        invalid.repository_id = Uuid::nil();
        assert!(invalid.validate().is_err());
        let mut invalid = root.clone();
        for records in [&mut invalid.refs.records, &mut invalid.objects.records] {
            records.records = 1_000_000;
            records.page.height = 3;
            records.page.byte_len = 9 * 1024 * 1024 * 1024;
            records.page.page_occurrences = 300_000;
        }
        invalid.refs.validate().unwrap();
        invalid.objects.validate().unwrap();
        assert!(invalid.validate().is_err());
        let mut invalid = root.clone();
        for page in [
            &mut invalid.refs.records.page,
            &mut invalid.objects.records.page,
        ] {
            page.height = 3;
            page.page_occurrences = 600_000;
        }
        invalid.refs.validate().unwrap();
        invalid.objects.validate().unwrap();
        assert!(invalid.validate().is_err());
        let encoded = canonical_bytes(&root).unwrap();
        let mut noncanonical = vec![0x81, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(GitCatalogRoot::decode(&noncanonical).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(GitCatalogRoot::decode(&trailing).is_err());
        assert!(GitCatalogRoot::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(GitCatalogRoot::decode(&[0; GIT_CATALOG_ROOT_BYTES + 1]).is_err());
    }
}
