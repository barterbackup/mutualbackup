//! Original paged metadata in bounded immutable local rows. These rows retain
//! object bytes; refs, blobs, complete graph admission and protection are separate.

use anyhow::{Context, Result, ensure};
use mb_core::{
    CatalogPageRef, CatalogScope, CatalogStreamError, canonical_bytes, decode_canonical,
};
use mb_store::ControlStore;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use uuid::Uuid;

use crate::{
    GIT_OBJECT_FRAGMENT_BYTES, GitObjectCatalogReader, GitObjectCatalogRoot, GitObjectRecord,
};

pub(crate) const ROOT: &str = "git-paged-metadata-root-v1";
pub(crate) const HEADERS: &str = "git-metadata-object-v2/";
pub(crate) const FRAGMENTS: &str = "git-metadata-fragment-v2/";
pub(crate) const HEADER_BYTES: usize = 128;

pub(crate) fn kind(prefix: &str, id: Uuid) -> String {
    format!("{prefix}{id}")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Header {
    pub(crate) format_version: u16,
    pub(crate) kind: u8,
    pub(crate) byte_len: u64,
    pub(crate) fragments: u64,
}

impl Header {
    pub(crate) fn validate(self) -> Result<()> {
        ensure!(
            self.format_version == 2
                && matches!(self.kind, 1..=3)
                && self.byte_len <= mb_core::CATALOG_MAX_STREAM_BYTES
                && self.fragments == self.byte_len.div_ceil(GIT_OBJECT_FRAGMENT_BYTES as u64),
            "invalid chunked metadata header"
        );
        Ok(())
    }
    pub(crate) fn hash(self) -> Result<Sha1> {
        self.validate()?;
        let name = match self.kind {
            1 => "commit",
            2 => "tree",
            3 => "tag",
            _ => unreachable!(),
        };
        let mut hash = Sha1::new();
        hash.update(format!("{name} {}\0", self.byte_len).as_bytes());
        Ok(hash)
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct Root {
    format_version: u16,
    pub(crate) scope: CatalogScope,
    pub(crate) objects: GitObjectCatalogRoot,
}

pub(crate) fn root(control: &ControlStore, id: Uuid) -> Result<Option<Root>> {
    let Some(bytes) = control.get_record_bounded(ROOT, id.as_bytes(), 1024)? else {
        ensure!(
            !control.has_records_with_kind_prefix(&kind(HEADERS, id))?
                && !control.has_records_with_kind_prefix(&kind(FRAGMENTS, id))?,
            "chunked metadata has no completed owner"
        );
        return Ok(None);
    };
    let root: Root = decode_canonical(&bytes)?;
    root.objects.validate()?;
    ensure!(
        root.format_version == 1
            && matches!(root.scope, CatalogScope::Dataset{protected_root_id,..} if protected_root_id==id)
            && canonical_bytes(&root)? == bytes,
        "chunked metadata belongs to another repository"
    );
    Ok(Some(root))
}

pub(crate) fn key(oid: [u8; 20], offset: u64) -> [u8; 28] {
    let mut key = [0; 28];
    key[..20].copy_from_slice(&oid);
    key[20..].copy_from_slice(&offset.to_be_bytes());
    key
}

pub(crate) fn header(control: &ControlStore, id: Uuid, oid: [u8; 20]) -> Result<Option<Header>> {
    let Some(bytes) = control.get_record_bounded(&kind(HEADERS, id), &oid, HEADER_BYTES)? else {
        return Ok(None);
    };
    let value: Header = decode_canonical(&bytes)?;
    value.validate()?;
    ensure!(
        canonical_bytes(&value)? == bytes,
        "noncanonical chunked metadata header"
    );
    Ok(Some(value))
}

fn exact(control: &ControlStore, kind: &str, key: &[u8], bytes: &[u8], limit: usize) -> Result<()> {
    ensure!(bytes.len() <= limit, "metadata row exceeds its bound");
    control.put_record_if_absent(kind, key, bytes)?;
    ensure!(
        control.get_record_bounded(kind, key, limit)?.as_deref() == Some(bytes),
        "metadata row write was ignored or conflicts"
    );
    Ok(())
}

pub(crate) fn stream(
    control: &ControlStore,
    id: Uuid,
    oid: [u8; 20],
    value: Header,
    mut visit: impl FnMut(u64, &[u8]) -> Result<()>,
) -> Result<[u8; 32]> {
    let mut hash = value.hash()?;
    let mut content = blake3::Hasher::new();
    let mut offset = 0;
    while offset < value.byte_len {
        let expected = (value.byte_len - offset).min(GIT_OBJECT_FRAGMENT_BYTES as u64) as usize;
        let bytes = control
            .get_record_bounded(
                &kind(FRAGMENTS, id),
                &key(oid, offset),
                GIT_OBJECT_FRAGMENT_BYTES,
            )?
            .context("missing metadata fragment")?;
        ensure!(bytes.len() == expected, "wrong metadata fragment length");
        hash.update(&bytes);
        content.update(&bytes);
        visit(offset, &bytes)?;
        offset += bytes.len() as u64;
    }
    let tail = control.record_at_or_before_bounded(
        &kind(FRAGMENTS, id),
        &key(oid, 0),
        &key(oid, u64::MAX),
        28,
        GIT_OBJECT_FRAGMENT_BYTES,
    )?;
    ensure!(
        tail.as_ref().map(|(key, _)| key.as_slice())
            == (value.fragments > 0)
                .then(|| key(
                    oid,
                    (value.fragments - 1) * GIT_OBJECT_FRAGMENT_BYTES as u64
                ))
                .as_ref()
                .map(|k| k.as_slice()),
        "extra metadata fragment"
    );
    ensure!(
        hash.finalize().as_slice() == oid,
        "chunked metadata differs from original Git OID"
    );
    Ok(*content.finalize().as_bytes())
}

pub(crate) fn validate_all(
    control: &ControlStore,
    id: Uuid,
    mut visit: impl FnMut([u8; 20], Header, [u8; 32]) -> Result<()>,
) -> Result<()> {
    for (prefix, key_bytes, row_bytes) in [
        (HEADERS, 20, HEADER_BYTES),
        (FRAGMENTS, 28, GIT_OBJECT_FRAGMENT_BYTES),
        (ROOT, 16, 1024),
    ] {
        control.for_each_record_with_kind_prefix_bounded(
            prefix,
            512,
            key_bytes,
            row_bytes,
            |name, key, _| {
                ensure!(
                    name == if prefix == ROOT {
                        ROOT.to_string()
                    } else {
                        kind(prefix, id)
                    } && key.len() == key_bytes
                        && (prefix != ROOT || key == id.as_bytes()),
                    "chunked metadata namespace conflicts with repository identity"
                );
                Ok(true)
            },
        )?;
    }
    let Some(root) = root(control, id)? else {
        return Ok(());
    };
    let mut after = None;
    let mut objects = 0u64;
    let mut bytes = 0u64;
    let mut fragments = 0u64;
    while let Some((oid, encoded)) =
        control.next_record_bounded(&kind(HEADERS, id), after.as_deref(), 20, HEADER_BYTES)?
    {
        let oid_array: [u8; 20] = oid
            .as_slice()
            .try_into()
            .context("invalid metadata OID key")?;
        let value: Header = decode_canonical(&encoded)?;
        value.validate()?;
        ensure!(
            canonical_bytes(&value)? == encoded,
            "noncanonical metadata header"
        );
        let content = stream(control, id, oid_array, value, |_, _| Ok(()))?;
        objects = objects
            .checked_add(1)
            .context("metadata object count overflow")?;
        bytes = bytes
            .checked_add(value.byte_len)
            .context("metadata length overflow")?;
        fragments = fragments
            .checked_add(value.fragments)
            .context("metadata fragment count overflow")?;
        ensure!(
            objects <= root.objects.objects && bytes <= root.objects.object_bytes,
            "metadata exceeds original root"
        );
        visit(oid_array, value, content)?;
        after = Some(oid);
    }
    let mut observed = 0u64;
    control.for_each_record_bounded(
        &kind(FRAGMENTS, id),
        28,
        GIT_OBJECT_FRAGMENT_BYTES,
        |key, bytes| {
            ensure!(
                key.len() == 28 && !bytes.is_empty(),
                "invalid metadata fragment row"
            );
            let oid = key[..20].try_into()?;
            let value = header(control, id, oid)?.context("orphaned metadata fragment")?;
            let offset = u64::from_be_bytes(key[20..].try_into()?);
            ensure!(
                offset % GIT_OBJECT_FRAGMENT_BYTES as u64 == 0 && offset < value.byte_len,
                "invalid metadata fragment offset"
            );
            observed = observed.checked_add(1).context("metadata count overflow")?;
            Ok(true)
        },
    )?;
    ensure!(
        objects == root.objects.objects
            && bytes == root.objects.object_bytes
            && observed == fragments
            && objects.checked_add(fragments) == Some(root.objects.records.records),
        "incomplete chunked metadata owner"
    );
    Ok(())
}

pub(crate) fn import(
    control: &ControlStore,
    id: Uuid,
    scope: CatalogScope,
    objects: GitObjectCatalogRoot,
    mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
) -> Result<()> {
    objects.validate()?;
    ensure!(
        matches!(scope,CatalogScope::Dataset{protected_root_id,..} if protected_root_id==id),
        "paged metadata repository differs"
    );
    let expected = Root {
        format_version: 1,
        scope,
        objects,
    };
    control.with_record_transaction(|| -> Result<()> {
        if let Some(previous) = root(control, id)? {
            ensure!(
                previous == expected,
                "metadata retry names another original root"
            )
        } else {
            ensure!(
                control
                    .next_record_metadata_bounded(&crate::history::metadata_kind(id), None, 20)?
                    .is_none(),
                "paged metadata requires an empty metadata destination"
            );
        }
        for_each_import_record(id, scope, objects, &mut fetch, |kind, key, bytes, limit| {
            exact(control, kind, key, bytes, limit)
        })?;
        validate_all(control, id, |_, _, _| Ok(()))?;
        Ok(())
    })
}

/// Stream bounded destination rows into a private staging sink. The completed
/// owner is emitted only after the original reader authenticates typed EOF.
pub(crate) fn for_each_import_record(
    id: Uuid,
    scope: CatalogScope,
    objects: GitObjectCatalogRoot,
    mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
    mut put: impl FnMut(&str, &[u8], &[u8], usize) -> Result<()>,
) -> Result<()> {
    objects.validate()?;
    ensure!(
        matches!(scope, CatalogScope::Dataset { protected_root_id, .. } if protected_root_id == id),
        "paged metadata repository differs"
    );
    let expected = Root {
        format_version: 1,
        scope,
        objects,
    };
    let mut reader = GitObjectCatalogReader::new(scope, objects)?;
    let mut active = None;
    loop {
        let record = reader
            .next_record(&mut fetch)
            .map_err(|error| match error {
                CatalogStreamError::Catalog(error) => anyhow::Error::new(error),
                CatalogStreamError::Storage(error) => error,
            })?;
        match record {
            Some(GitObjectRecord::Header {
                oid,
                kind: code,
                byte_len,
                ..
            }) => {
                let value = Header {
                    format_version: 2,
                    kind: code,
                    byte_len,
                    fragments: byte_len.div_ceil(GIT_OBJECT_FRAGMENT_BYTES as u64),
                };
                value.validate()?;
                put(
                    &kind(HEADERS, id),
                    &oid,
                    &canonical_bytes(&value)?,
                    HEADER_BYTES,
                )?;
                active = Some(oid);
            }
            Some(GitObjectRecord::Fragment { offset, bytes }) => put(
                &kind(FRAGMENTS, id),
                &key(active.context("metadata fragment has no object")?, offset),
                &bytes,
                GIT_OBJECT_FRAGMENT_BYTES,
            )?,
            None => break,
        }
    }
    put(ROOT, id.as_bytes(), &canonical_bytes(&expected)?, 1024)?;
    Ok(())
}

impl crate::GitRepository {
    /// Retain the original paged object stream in an empty or exact-retry local
    /// catalog. The caller authenticates its private descriptor. This does not
    /// install refs/blobs, advance a backup head, or certify complete Git recovery.
    pub fn import_paged_metadata_objects(
        &self,
        scope: CatalogScope,
        objects: GitObjectCatalogRoot,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
    ) -> Result<()> {
        self.with_paged_metadata_catalog(|control| {
            import(control, self.id(), scope, objects, fetch)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{ObjectType, Odb, Oid};
    use std::collections::HashMap;
    use std::io::{Cursor, Read};

    type MetadataFixture = (
        GitObjectCatalogRoot,
        HashMap<[u8; 32], Vec<u8>>,
        Vec<(u8, [u8; 20], Vec<u8>)>,
    );

    fn scope(id: Uuid) -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [223; 32],
            owner: mb_core::NodeId([224; 32]),
            protected_root_id: id,
        }
    }
    fn fixture(id: Uuid, large: usize) -> MetadataFixture {
        let tree = Vec::new();
        let tree_oid = Oid::hash_object(ObjectType::Tree, &tree).unwrap();
        let mut commit = format!(
            "tree {tree_oid}\nauthor A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\noriginal\n"
        )
        .into_bytes();
        commit.resize(commit.len() + large, b'x');
        let commit_oid = Oid::hash_object(ObjectType::Commit, &commit).unwrap();
        let tag=format!("object {commit_oid}\ntype commit\ntag saved\ntagger A <a@test> 1 +0000\n\noriginal tag\n").into_bytes();
        let tag_oid = Oid::hash_object(ObjectType::Tag, &tag).unwrap();
        let mut objects = vec![
            (2, tree_oid.as_bytes().try_into().unwrap(), tree),
            (1, commit_oid.as_bytes().try_into().unwrap(), commit),
            (3, tag_oid.as_bytes().try_into().unwrap(), tag),
        ];
        objects.sort_by_key(|row| row.1);
        let mut pages = HashMap::new();
        let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| {
            pages.insert(page.hash, bytes);
            Ok::<_, anyhow::Error>(())
        };
        let mut builder = crate::GitObjectCatalogBuilder::new(scope(id)).unwrap();
        for (kind, oid, bytes) in &objects {
            builder
                .push_object(
                    *oid,
                    *kind,
                    bytes.len() as u64,
                    &mut bytes.as_slice(),
                    &mut sink,
                )
                .unwrap()
        }
        let root = builder.finish(&mut sink).unwrap();
        (root, pages, objects)
    }

    #[test]
    fn chunked_metadata_original_oid_refs_and_mixed_legacy_overlay_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(223);
        let key = [223; 32];
        let path = temp.path().join("control.db");
        let control = ControlStore::open_with_key(&path, &key).unwrap();
        let (objects, pages, original) = fixture(id, 2 * GIT_OBJECT_FRAGMENT_BYTES + 13);
        import(&control, id, scope(id), objects, |page| {
            Ok(pages[&page.hash].clone())
        })
        .unwrap();
        import(&control, id, scope(id), objects, |page| {
            Ok(pages[&page.hash].clone())
        })
        .unwrap();
        assert!(
            control
                .records(&crate::history::metadata_kind(id))
                .unwrap()
                .is_empty()
        );
        let commit = original.iter().find(|row| row.0 == 1).unwrap();
        control
            .put_record(
                &crate::history::ref_kind(id),
                b"refs/heads/main",
                &crate::history::fetched_ref_record(commit.1).unwrap(),
            )
            .unwrap();
        assert_eq!(
            crate::history::list_branches(&control, id).unwrap()[0].oid,
            commit.1
        );
        assert_eq!(
            crate::history::log_history(&control, id, 1).unwrap()[0].oid,
            commit.1
        );
        let extra = b"different valid raw object";
        let oid = Oid::hash_object(ObjectType::Tag, extra).unwrap();
        control
            .put_record(
                &crate::history::metadata_kind(id),
                oid.as_bytes(),
                &crate::history::object_record(ObjectType::Tag, extra.to_vec()).unwrap(),
            )
            .unwrap();
        drop(control);
        let control = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
        let odb = Odb::new().unwrap();
        let index = crate::metadata_odb::MetadataIndex::load(&control, id, &odb).unwrap();
        assert_eq!(index.ids().unwrap().len(), 4);
        for (kind, oid, bytes) in &original {
            assert_eq!(
                odb.read(Oid::from_bytes(oid).unwrap()).unwrap().data(),
                bytes
            );
            let (mut reader, length, actual) = odb.reader(Oid::from_bytes(oid).unwrap()).unwrap();
            assert_eq!(length, bytes.len());
            assert_eq!(actual, crate::history::object_type(*kind).unwrap());
            let mut output = Vec::new();
            reader.read_to_end(&mut output).unwrap();
            assert_eq!(&output, bytes);
        }
        let mut inventory = Vec::new();
        validate_all(&control, id, |oid, value, hash| {
            inventory.push((oid, value.byte_len, hash));
            Ok(())
        })
        .unwrap();
        assert_eq!(inventory.len(), 3);
        for (_, oid, bytes) in original {
            assert!(inventory.contains(&(
                oid,
                bytes.len() as u64,
                *blake3::hash(&bytes).as_bytes()
            )))
        }
    }

    #[test]
    fn chunked_metadata_preserved_inventory_is_complete_read_only_and_rejects_aliases() {
        use crate::{GitRepository, PreservedGitRecord};
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(223);
        let encryption_key = [223; 32];
        let directory = temp.path().join(mb_store::GIT_CATALOG_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
        std::fs::write(&marker, mb_store::git_catalog_marker_bytes(id)).unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
        let control =
            ControlStore::open_with_key(directory.join("catalog.db"), &encryption_key).unwrap();
        let (objects, pages, original) = fixture(id, GIT_OBJECT_FRAGMENT_BYTES + 1);
        import(&control, id, scope(id), objects, |page| {
            Ok(pages[&page.hash].clone())
        })
        .unwrap();
        let snapshot = || {
            let mut files = std::fs::read_dir(&directory)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    (
                        path.file_name().unwrap().to_owned(),
                        std::fs::read(path).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            files.sort();
            files
        };
        let before = snapshot();
        let mut seen = Vec::new();
        assert!(
            GitRepository::for_each_preserved_record(temp.path(), id, &encryption_key, |record| {
                match record {
                    PreservedGitRecord::ChunkedMetadataObject {
                        repository_id,
                        record_format,
                        kind,
                        oid,
                        byte_len,
                        content_hash,
                    } => {
                        assert_eq!((repository_id, record_format), (id, 2));
                        let source = original.iter().find(|row| row.1 == oid).unwrap();
                        assert_eq!(kind, source.0);
                        assert_eq!(byte_len, source.2.len() as u64);
                        assert_eq!(content_hash, *blake3::hash(&source.2).as_bytes());
                        seen.push(oid);
                    }
                    PreservedGitRecord::Unclassified { .. } => {
                        panic!("valid chunked metadata is unclassified")
                    }
                    _ => {}
                }
                Ok(())
            })
            .unwrap()
        );
        assert_eq!(seen.len(), original.len());
        assert_eq!(snapshot(), before);
        for (name, row_key, bytes) in [
            (kind(HEADERS, Uuid::from_u128(224)), vec![1; 20], vec![0]),
            (
                format!("{}unexpected", kind(FRAGMENTS, id)),
                vec![1; 28],
                vec![0],
            ),
            (
                ROOT.to_string(),
                Uuid::from_u128(224).as_bytes().to_vec(),
                canonical_bytes(&root(&control, id).unwrap().unwrap()).unwrap(),
            ),
        ] {
            control.put_record(&name, &row_key, &bytes).unwrap();
            let before = snapshot();
            assert!(
                GitRepository::for_each_preserved_record(temp.path(), id, &encryption_key, |_| Ok(
                    ()
                ))
                .is_err()
            );
            assert_eq!(snapshot(), before);
            control.delete_record(&name, &row_key).unwrap();
        }
    }

    #[test]
    fn chunked_metadata_failed_import_and_ignored_writes_leave_no_published_owner() {
        for action in ["ABORT", "IGNORE"] {
            let temp = tempfile::tempdir().unwrap();
            let id = Uuid::from_u128(223);
            let control =
                ControlStore::open_with_key(temp.path().join("control.db"), &[223; 32]).unwrap();
            let (objects, pages, _) = fixture(id, GIT_OBJECT_FRAGMENT_BYTES + 1);
            control.database_shell_statement(&format!("CREATE TEMP TRIGGER fail_metadata BEFORE INSERT ON protocol_records WHEN NEW.kind='{}' BEGIN SELECT RAISE({action}{}); END",kind(FRAGMENTS,id),if action=="ABORT"{",'test'"}else{""}),false).unwrap();
            assert!(
                import(&control, id, scope(id), objects, |page| Ok(pages
                    [&page.hash]
                    .clone()))
                .is_err()
            );
            assert!(root(&control, id).unwrap().is_none());
            assert!(
                control
                    .next_record_metadata_bounded(&kind(HEADERS, id), None, 20)
                    .unwrap()
                    .is_none()
            );
            control
                .database_shell_statement("DROP TRIGGER fail_metadata", false)
                .unwrap();
            assert!(
                import(&control, id, scope(id), objects, |_| anyhow::bail!(
                    "lost original page"
                ))
                .is_err()
            );
            assert!(root(&control, id).unwrap().is_none());
            import(&control, id, scope(id), objects, |page| {
                Ok(pages[&page.hash].clone())
            })
            .unwrap();
            let (different, pages, _) = fixture(id, 2 * GIT_OBJECT_FRAGMENT_BYTES + 1);
            assert!(
                import(&control, id, scope(id), different, |page| Ok(pages
                    [&page.hash]
                    .clone()))
                .is_err()
            );
            validate_all(&control, id, |_, _, _| Ok(())).unwrap();
        }
    }

    #[test]
    fn chunked_metadata_damaged_orphaned_extra_and_oversized_rows_never_fall_back() {
        for damage in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let id = Uuid::from_u128(223);
            let control =
                ControlStore::open_with_key(temp.path().join("control.db"), &[223; 32]).unwrap();
            let (objects, pages, original) = fixture(id, GIT_OBJECT_FRAGMENT_BYTES + 1);
            import(&control, id, scope(id), objects, |page| {
                Ok(pages[&page.hash].clone())
            })
            .unwrap();
            let commit = original.iter().find(|row| row.0 == 1).unwrap();
            let first = key(commit.1, 0);
            match damage {
                0 => control
                    .put_record(
                        &kind(FRAGMENTS, id),
                        &first,
                        &[0; GIT_OBJECT_FRAGMENT_BYTES],
                    )
                    .unwrap(),
                1 => {
                    let bytes = control
                        .get_record(&kind(FRAGMENTS, id), &first)
                        .unwrap()
                        .unwrap();
                    control
                        .delete_record_if_value(&kind(FRAGMENTS, id), &first, &bytes)
                        .unwrap();
                }
                2 => control
                    .put_record(&kind(FRAGMENTS, id), &key(commit.1, u64::MAX), b"extra")
                    .unwrap(),
                3 => control
                    .put_record(
                        &kind(FRAGMENTS, id),
                        &first,
                        &vec![0; GIT_OBJECT_FRAGMENT_BYTES + 1],
                    )
                    .unwrap(),
                _ => control
                    .put_record(&kind(FRAGMENTS, id), &key([1; 20], 0), b"orphan")
                    .unwrap(),
            }
            assert!(validate_all(&control, id, |_, _, _| Ok(())).is_err());
            assert!(
                crate::metadata_odb::MetadataIndex::load(&control, id, &Odb::new().unwrap())
                    .is_err()
            );
        }
    }

    #[test]
    fn chunked_metadata_stream_preserves_objects_above_the_legacy_row_bound() {
        let temp = tempfile::tempdir().unwrap();
        let id = Uuid::from_u128(223);
        let control =
            ControlStore::open_with_key(temp.path().join("control.db"), &[223; 32]).unwrap();
        let (objects, pages, original) = fixture(id, crate::history::MAX_GRAPH_METADATA_BYTES + 1);
        import(&control, id, scope(id), objects, |page| {
            Ok(pages[&page.hash].clone())
        })
        .unwrap();
        let object = original.iter().find(|row| row.0 == 1).unwrap();
        let oid = Oid::from_bytes(&object.1).unwrap();
        let odb = Odb::new().unwrap();
        let index = crate::metadata_odb::MetadataIndex::load(&control, id, &odb).unwrap();
        assert!(index.get(oid).is_err());
        assert!(odb.read(oid).is_err());
        assert_eq!(odb.read_header(oid).unwrap().0, object.2.len());
        let (mut stream, length, _) = odb.reader(oid).unwrap();
        assert_eq!(length, object.2.len());
        let mut expected = Cursor::new(&object.2);
        let mut bytes = [0; 8192];
        let mut compare = [0; 8192];
        let mut observed = 0;
        loop {
            let read = stream.read(&mut bytes).unwrap();
            if read == 0 {
                break;
            }
            expected.read_exact(&mut compare[..read]).unwrap();
            assert_eq!(bytes[..read], compare[..read]);
            observed += read
        }
        assert_eq!(observed, object.2.len());
    }
}
