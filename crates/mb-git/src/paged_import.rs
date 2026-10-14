//! Atomic installation of a complete paged Git catalog from independently
//! recovered native blob anchors. Source authority and payload recovery remain
//! with the enclosing checkpoint consumer; this never advances a backup head.

use std::io::Read;

use anyhow::{Context, Result, ensure};
use mb_core::{CatalogPageRef, CatalogScope, canonical_bytes_bounded, decode_canonical};
use mb_store::{ControlStore, FileAnchorManifest, RecordScratchStore};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{GitBlobCatalogReader, GitBlobRecord, GitCatalogRoot, GitRefCatalogReader};

pub(crate) const OWNER: &str = "git-paged-backup-install-v1";
const PENDING: &str = "git-install-pending-row";
const ANCHORS: &str = "git-install-blob-anchor";
const PAYLOAD_BYTES: usize = crate::GIT_OBJECT_FRAGMENT_BYTES;
const ROW_BYTES: usize = PAYLOAD_BYTES + crate::GIT_REF_NAME_BYTES + 1024;

#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
struct Installed {
    format_version: u16,
    scope: CatalogScope,
    git: GitCatalogRoot,
}

impl Installed {
    fn validate(&self, id: Uuid) -> Result<()> {
        self.git.validate()?;
        self.scope.validate(mb_core::CatalogSection::GitGraph)?;
        ensure!(
            self.format_version == 1
                && self.git.repository_id == id
                && matches!(self.scope, CatalogScope::Dataset { protected_root_id, .. } if protected_root_id == id),
            "paged Git installation belongs to another repository"
        );
        Ok(())
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        Ok(canonical_bytes_bounded(
            self,
            crate::GIT_CATALOG_ROOT_BYTES + 128,
        )?)
    }
}

fn installed(control: &ControlStore, id: Uuid) -> Result<Option<Installed>> {
    let Some(bytes) =
        control.get_record_bounded(OWNER, id.as_bytes(), crate::GIT_CATALOG_ROOT_BYTES + 128)?
    else {
        return Ok(None);
    };
    let owner: Installed = decode_canonical(&bytes)?;
    owner.validate(id)?;
    ensure!(
        owner.bytes()? == bytes,
        "noncanonical paged Git installation owner"
    );
    let metadata = crate::metadata_chunks::root(control, id)?
        .context("installed Git has no completed metadata owner")?;
    ensure!(
        metadata.scope == owner.scope && metadata.objects == owner.git.objects,
        "installed Git metadata owner differs"
    );
    Ok(Some(owner))
}

/// The marker retains immutable installation provenance; mutable normal refs
/// and index rows retain their existing validators and meanings.
pub(crate) fn validate_preserved(control: &ControlStore, id: Uuid) -> Result<()> {
    control.for_each_record_with_kind_prefix_bounded(
        OWNER,
        512,
        16,
        crate::GIT_CATALOG_ROOT_BYTES + 128,
        |name, key, _| {
            ensure!(
                name == OWNER && key == id.as_bytes(),
                "paged Git installation namespace conflicts"
            );
            Ok(true)
        },
    )?;
    installed(control, id)?;
    Ok(())
}

fn destination(control: &ControlStore, expected: &Installed) -> Result<bool> {
    let id = expected.git.repository_id;
    if let Some(previous) = installed(control, id)? {
        ensure!(
            previous == *expected,
            "paged Git retry names another original catalog"
        );
        return Ok(true);
    }
    for kind in [
        crate::history::metadata_kind(id),
        crate::history::ref_kind(id),
        crate::stage::index_kind(id),
        crate::head::head_kind(id),
    ] {
        ensure!(
            control
                .next_record_metadata_bounded(&kind, None, crate::GIT_REF_NAME_BYTES)?
                .is_none(),
            "paged Git requires an empty destination"
        );
    }
    ensure!(
        !control.has_records_with_kind_prefix(&crate::stage::object_kind_prefix(id))?,
        "paged Git destination already owns blobs"
    );
    if let Some(metadata) = crate::metadata_chunks::root(control, id)? {
        ensure!(
            metadata.scope == expected.scope && metadata.objects == expected.git.objects,
            "staged metadata belongs to another catalog"
        );
    }
    Ok(false)
}

#[derive(Serialize, Deserialize)]
struct PendingRow {
    kind: String,
    key: Vec<u8>,
    bytes: Vec<u8>,
}

struct Staging<'a> {
    store: &'a RecordScratchStore,
    rows: u64,
    maximum: u64,
}

impl Staging<'_> {
    fn put(&mut self, kind: &str, key: &[u8], bytes: &[u8]) -> Result<()> {
        ensure!(
            kind.len() <= 512
                && key.len() <= crate::GIT_REF_NAME_BYTES
                && bytes.len() <= PAYLOAD_BYTES,
            "oversized Git installation row"
        );
        ensure!(
            self.rows < self.maximum,
            "Git installation row budget exceeded"
        );
        let row = canonical_bytes_bounded(
            &PendingRow {
                kind: kind.to_owned(),
                key: key.to_vec(),
                bytes: bytes.to_vec(),
            },
            ROW_BYTES,
        )?;
        let key = self.rows.to_be_bytes();
        self.store.put_record_if_absent(PENDING, &key, &row)?;
        ensure!(
            self.store
                .get_record_bounded(PENDING, &key, ROW_BYTES)?
                .as_deref()
                == Some(row.as_slice()),
            "staged Git row was ignored or conflicts"
        );
        self.rows += 1;
        Ok(())
    }

    fn install(&self, control: &ControlStore, retry: bool) -> Result<()> {
        for number in 0..self.rows {
            let encoded = self
                .store
                .get_record_bounded(PENDING, &number.to_be_bytes(), ROW_BYTES)?
                .context("missing staged Git row")?;
            let row: PendingRow = decode_canonical(&encoded)?;
            ensure!(
                canonical_bytes_bounded(&row, ROW_BYTES)? == encoded,
                "noncanonical staged Git row"
            );
            if !retry {
                control.put_record_if_absent(&row.kind, &row.key, &row.bytes)?;
            }
            ensure!(
                control
                    .get_record_bounded(&row.kind, &row.key, row.bytes.len())?
                    .as_deref()
                    == Some(row.bytes.as_slice()),
                "Git installation write was ignored, missing or conflicts"
            );
        }
        Ok(())
    }
}

pub(crate) fn import(
    control: &ControlStore,
    id: Uuid,
    scope: CatalogScope,
    git: &GitCatalogRoot,
    mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
    mut anchor: impl FnMut([u8; 20]) -> Result<FileAnchorManifest>,
) -> Result<()> {
    let parent = control
        .path()
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let store = RecordScratchStore::new_in_with_checkpoint_reservations(
        parent,
        mb_store::ScratchStorageLimits::for_database(mb_core::CATALOG_MAX_STREAM_BYTES * 4)?,
        &[control.path().to_path_buf()],
    )?;
    import_with_scratch(control, id, scope, git, &store, &mut fetch, &mut anchor)
}

fn import_with_scratch(
    control: &ControlStore,
    id: Uuid,
    scope: CatalogScope,
    git: &GitCatalogRoot,
    store: &RecordScratchStore,
    mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
    mut anchor: impl FnMut([u8; 20]) -> Result<FileAnchorManifest>,
) -> Result<()> {
    ensure!(
        !control.is_read_only()?,
        "Git installation requires a writable destination"
    );
    let expected = Installed {
        format_version: 1,
        scope,
        git: git.clone(),
    };
    expected.validate(id)?;
    destination(control, &expected)?;
    git.validate_graph_with_scratch(scope, store, &mut fetch)?;
    let maximum = git
        .objects
        .records
        .records
        .checked_add(git.refs.records.records)
        .and_then(|n| {
            git.blobs
                .blobs
                .checked_mul(2)
                .and_then(|blobs| n.checked_add(blobs))
        })
        .and_then(|n| n.checked_add(mb_core::CATALOG_MAX_RECORDS))
        .and_then(|n| n.checked_add(2))
        .context("Git installation row count overflow")?;
    let mut staging = Staging {
        store,
        rows: 0,
        maximum,
    };
    // Only the private disposable writer spans page/native I/O. The destination
    // writer is acquired after every source stream and blob has been verified.
    store.with_record_transaction(|| -> Result<()> {
        let mut blobs = GitBlobCatalogReader::new(scope, git.blobs)?;
        while let Some(record) = blobs.next_record(&mut fetch)? {
            if let GitBlobRecord::Blob {
                oid, logical_len, ..
            } = record
            {
                let manifest = anchor(oid)?;
                let (actual, area) = crate::catalog_anchor::identify(control, &manifest)?;
                ensure!(
                    actual.as_bytes() == oid && manifest.logical_len == logical_len,
                    "recovered blob differs from original Git identity"
                );
                if crate::paged_graph::blob_is_symlink(store, &oid)? {
                    let (mut file, _) = manifest.open_verified_with_area_hint(Some(&area))?;
                    let mut target = Vec::with_capacity(logical_len as usize);
                    file.by_ref().take(4096).read_to_end(&mut target)?;
                    ensure!(
                        target.len() as u64 == logical_len && !target.contains(&0),
                        "Git symlink target cannot be published"
                    );
                }
                let encoded = canonical_bytes_bounded(&manifest, PAYLOAD_BYTES)?;
                staging.put(
                    &crate::stage::object_kind(id, actual),
                    manifest.anchor_id.as_bytes(),
                    &encoded,
                )?;
                store.put_record_if_absent(ANCHORS, &oid, manifest.anchor_id.as_bytes())?;
                ensure!(
                    store.get_record_bounded(ANCHORS, &oid, 16)?.as_deref()
                        == Some(manifest.anchor_id.as_bytes()),
                    "blob anchor join was ignored"
                );
                let (kind, key, bytes) = crate::catalog_anchor::location_record(&manifest, &area)?;
                staging.put(&kind, &key, &bytes)?;
            }
        }
        crate::metadata_chunks::for_each_import_record(
            id,
            scope,
            git.objects,
            &mut fetch,
            |kind, key, bytes, _| staging.put(kind, key, bytes),
        )?;
        let mut refs = GitRefCatalogReader::new(scope, git.refs.clone())?;
        while let Some(reference) = refs.next_ref(&mut fetch)? {
            staging.put(
                &crate::history::ref_kind(id),
                &reference.name,
                &crate::history::fetched_ref_record(reference.oid)?,
            )?;
        }
        let head = std::str::from_utf8(&git.refs.head_branch)?;
        let (kind, key, bytes) = crate::head::selected_branch_record(id, head)?;
        staging.put(&kind, &key, &bytes)?;
        crate::paged_graph::for_each_head_entry(git, store, |path, oid, mode| {
            let anchor = store
                .get_record_bounded(ANCHORS, &oid, 16)?
                .context("HEAD blob has no recovered anchor")?;
            let anchor_id = Uuid::from_slice(&anchor)?;
            ensure!(!anchor_id.is_nil(), "HEAD blob has an invalid anchor");
            staging.put(
                &crate::stage::index_kind(id),
                path,
                &canonical_bytes_bounded(
                    &crate::GitIndexEntry {
                        format_version: 1,
                        oid,
                        mode,
                        anchor_id,
                    },
                    512,
                )?,
            )
        })?;
        Ok(())
    })?;
    control.with_record_transaction(|| -> Result<()> {
        let retry = destination(control, &expected)?;
        staging.install(control, retry)?;
        crate::metadata_chunks::validate_all(control, id, |_, _, _| Ok(()))?;
        let encoded = expected.bytes()?;
        if !retry {
            control.put_record_if_absent(OWNER, id.as_bytes(), &encoded)?;
        }
        ensure!(
            control
                .get_record_bounded(OWNER, id.as_bytes(), encoded.len())?
                .as_deref()
                == Some(encoded.as_slice()),
            "Git installation owner write was ignored"
        );
        validate_preserved(control, id)?;
        Ok(())
    })
}

impl crate::GitRepository {
    /// Install exact paged history and a clean HEAD index from recovered native
    /// blob anchors. The caller authenticates the enclosing private descriptor
    /// and retains those anchors. This never certifies distributed protection.
    pub fn import_paged_backup(
        &self,
        scope: CatalogScope,
        git: &GitCatalogRoot,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
        anchor: impl FnMut([u8; 20]) -> Result<FileAnchorManifest>,
    ) -> Result<()> {
        self.with_paged_metadata_catalog(|control| {
            import(control, self.id(), scope, git, fetch, anchor)
        })
    }

    /// Use the enclosing consumer's private index, placed/admitted alongside
    /// its catalog with configured headroom and checkpoint-copy reservations.
    pub fn import_paged_backup_with_scratch(
        &self,
        scope: CatalogScope,
        git: &GitCatalogRoot,
        scratch: &RecordScratchStore,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>>,
        anchor: impl FnMut([u8; 20]) -> Result<FileAnchorManifest>,
    ) -> Result<()> {
        self.with_paged_metadata_catalog(|control| {
            import_with_scratch(control, self.id(), scope, git, scratch, fetch, anchor)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        GitBlobCatalogBuilder, GitObjectCatalogBuilder, GitRefCatalogBuilder, GitRefRecord,
    };
    use git2::{ObjectType, Oid, Repository};
    use mb_core::{NodeId, SectorRef};
    use mb_store::SourceBlobImportPlan;
    use std::collections::HashMap;

    struct Fixture {
        root: GitCatalogRoot,
        pages: HashMap<[u8; 32], Vec<u8>>,
        anchors: HashMap<[u8; 20], FileAnchorManifest>,
        head: [u8; 20],
        regular: [u8; 20],
        head_bytes: usize,
    }
    type CatalogRows = Vec<(String, Vec<(Vec<u8>, Vec<u8>)>)>;
    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [225; 32],
            owner: NodeId([226; 32]),
            protected_root_id: Uuid::from_u128(225),
        }
    }
    fn fixture(directory: &std::path::Path, symlink: &[u8]) -> Fixture {
        fixture_with_metadata(directory, symlink, 0)
    }
    fn fixture_with_metadata(directory: &std::path::Path, symlink: &[u8], large: usize) -> Fixture {
        let id = Uuid::from_u128(225);
        let native = directory.join("native");
        std::fs::create_dir(&native).unwrap();
        let regular = b"raw\r\n\0original";
        let mut anchors = HashMap::new();
        let mut blob_rows = Vec::new();
        for bytes in [regular.as_slice(), symlink] {
            let oid: [u8; 20] = Oid::hash_object(ObjectType::Blob, bytes)
                .unwrap()
                .as_bytes()
                .try_into()
                .unwrap();
            anchors.insert(
                oid,
                SourceBlobImportPlan::plan_direct(&native, bytes.len() as u64)
                    .unwrap()
                    .capture(bytes)
                    .unwrap(),
            );
            blob_rows.push((oid, bytes.len() as u64));
        }
        blob_rows.sort();
        let regular_oid = Oid::hash_object(ObjectType::Blob, regular).unwrap();
        let symlink_oid = Oid::hash_object(ObjectType::Blob, symlink).unwrap();
        let parser = Repository::init_bare(directory.join("parser")).unwrap();
        assert_eq!(parser.blob(regular).unwrap(), regular_oid);
        assert_eq!(parser.blob(symlink).unwrap(), symlink_oid);
        let mut sub = parser.treebuilder(None).unwrap();
        sub.insert(&b"raw\xff"[..], regular_oid, 0o100755).unwrap();
        let sub = sub.write().unwrap();
        let mut tree = parser.treebuilder(None).unwrap();
        tree.insert("dir", sub, 0o040000).unwrap();
        tree.insert("other", sub, 0o040000).unwrap();
        tree.insert("link", symlink_oid, 0o120000).unwrap();
        let tree = tree.write().unwrap();
        let mut commit = format!(
            "tree {tree}\nauthor A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\noriginal\n"
        )
        .into_bytes();
        commit.resize(commit.len() + large, b'x');
        let head_bytes = commit.len();
        let commit_oid = Oid::hash_object(ObjectType::Commit, &commit).unwrap();
        let tag = format!("object {commit_oid}\ntype commit\ntag saved\ntagger A <a@test> 1 +0000\n\noriginal tag\n").into_bytes();
        let tag_oid = Oid::hash_object(ObjectType::Tag, &tag).unwrap();
        let mut objects = vec![
            (
                2,
                sub,
                parser.odb().unwrap().read(sub).unwrap().data().to_vec(),
            ),
            (
                2,
                tree,
                parser.odb().unwrap().read(tree).unwrap().data().to_vec(),
            ),
            (1, commit_oid, commit),
            (3, tag_oid, tag),
        ];
        objects.sort_by_key(|row| row.1);
        let mut pages = HashMap::new();
        let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| {
            pages.insert(page.hash, bytes);
            Ok::<_, anyhow::Error>(())
        };
        let mut builder = GitObjectCatalogBuilder::new(scope()).unwrap();
        for (kind, oid, bytes) in &objects {
            builder
                .push_object(
                    oid.as_bytes().try_into().unwrap(),
                    *kind,
                    bytes.len() as u64,
                    &mut bytes.as_slice(),
                    &mut sink,
                )
                .unwrap();
        }
        let objects = builder.finish(&mut sink).unwrap();
        let mut refs = GitRefCatalogBuilder::new(scope(), b"main").unwrap();
        for (name, oid) in [
            (
                format!("refs/heads/{}", "a".repeat(6000)).into_bytes(),
                commit_oid,
            ),
            (b"refs/heads/main".to_vec(), commit_oid),
            (b"refs/tags/saved".to_vec(), tag_oid),
        ] {
            refs.push_ref(
                &GitRefRecord {
                    format_version: 1,
                    name,
                    oid: oid.as_bytes().try_into().unwrap(),
                },
                &mut sink,
            )
            .unwrap();
        }
        let refs = refs.finish(&mut sink).unwrap();
        let mut blobs = GitBlobCatalogBuilder::new(scope()).unwrap();
        for (oid, length) in blob_rows {
            for record in [
                GitBlobRecord::Blob {
                    format_version: 1,
                    oid,
                    logical_len: length,
                    extents: 1,
                    sectors: 1,
                },
                GitBlobRecord::Extent {
                    offset: 0,
                    logical_len: length,
                    sectors: 1,
                },
                GitBlobRecord::Sectors {
                    first_sector: 0,
                    references: vec![SectorRef {
                        id: [227; 32],
                        root: [228; 32],
                        logical_len: length as u32,
                    }],
                },
            ] {
                blobs.push_record(&record, &mut sink).unwrap();
            }
        }
        Fixture {
            root: GitCatalogRoot {
                format_version: 1,
                repository_id: id,
                refs,
                objects,
                blobs: blobs.finish(&mut sink).unwrap(),
            },
            pages,
            anchors,
            head: commit_oid.as_bytes().try_into().unwrap(),
            regular: regular_oid.as_bytes().try_into().unwrap(),
            head_bytes,
        }
    }
    fn install(control: &ControlStore, f: &Fixture) -> Result<()> {
        import(
            control,
            f.root.repository_id,
            scope(),
            &f.root,
            |p| Ok(f.pages[&p.hash].clone()),
            |oid| Ok(f.anchors[&oid].clone()),
        )
    }
    fn rows(control: &ControlStore, id: Uuid) -> CatalogRows {
        [
            crate::history::metadata_kind(id),
            crate::history::ref_kind(id),
            crate::stage::index_kind(id),
            crate::head::head_kind(id),
            crate::metadata_chunks::kind(crate::metadata_chunks::HEADERS, id),
            crate::metadata_chunks::kind(crate::metadata_chunks::FRAGMENTS, id),
            crate::metadata_chunks::ROOT.to_owned(),
            OWNER.to_owned(),
        ]
        .into_iter()
        .map(|kind| {
            let values = control.records(&kind).unwrap();
            (kind, values)
        })
        .collect()
    }

    #[test]
    fn paged_import_original_history_refs_modes_and_shared_head_index_survive_reopen() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let f = fixture(temp.path(), b"dir/raw\xff");
        let id = f.root.repository_id;
        let directory = temp.path().join(mb_store::GIT_CATALOG_DIRECTORY);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
        std::fs::write(&marker, mb_store::git_catalog_marker_bytes(id)).unwrap();
        std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
        let path = directory.join("catalog.db");
        let pinned = mb_store::PinnedDirectory::open(&directory).unwrap();
        // An unregistered procfs path is not a database directory capability.
        // Use the same registered store API as an actual GitRepository below.
        let control =
            ControlStore::open_with_key(pinned.descriptor_path().join("catalog.db"), &[225; 32])
                .unwrap();
        assert!(install(&control, &f).is_err());
        assert!(
            rows(&control, id)
                .iter()
                .all(|(_, values)| values.is_empty())
        );
        drop(control);
        let database_directory = mb_store::DatabaseDirectory::from_file(std::sync::Arc::new(
            pinned.as_file().try_clone().unwrap(),
        ))
        .unwrap();
        let control = ControlStore::open_existing_in_directory_with_key(
            &database_directory,
            std::ffi::OsStr::new("catalog.db"),
            &[225; 32],
        )
        .unwrap();
        install(&control, &f).unwrap();
        let original = rows(&control, id);
        install(&control, &f).unwrap();
        assert_eq!(rows(&control, id), original);
        assert!(
            control
                .records(&crate::history::metadata_kind(id))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::history::list_branches(&control, id).unwrap().len(),
            2
        );
        assert_eq!(
            crate::history::log_history(&control, id, 1).unwrap()[0].oid,
            f.head
        );
        assert_eq!(crate::history::list_tags(&control, id).unwrap().len(), 1);
        assert_eq!(crate::head::selected_branch(&control, id).unwrap(), "main");
        let index = control.records(&crate::stage::index_kind(id)).unwrap();
        assert_eq!(index.len(), 3);
        for (path, bytes) in index {
            let entry: crate::GitIndexEntry = decode_canonical(&bytes).unwrap();
            let link = path == b"link";
            assert_eq!(entry.mode, if link { 0o120000 } else { 0o100755 });
            if !link {
                assert_eq!(entry.oid, f.regular);
                assert!(path == b"dir/raw\xff" || path == b"other/raw\xff");
            }
            assert_eq!(entry.anchor_id, f.anchors[&entry.oid].anchor_id);
        }
        drop(control);
        let control = ControlStore::open_existing_read_only_with_key(&path, &[225; 32]).unwrap();
        assert_eq!(rows(&control, id), original);
        validate_preserved(&control, id).unwrap();
        let odb =
            crate::NativeOdb::from_catalog_anchors(&control, f.anchors.values().cloned()).unwrap();
        let _index = crate::metadata_odb::MetadataIndex::load(&control, id, odb.odb()).unwrap();
        assert_eq!(
            odb.odb()
                .read(Oid::from_bytes(&f.regular).unwrap())
                .unwrap()
                .data(),
            b"raw\r\n\0original"
        );
        assert_eq!(
            odb.odb()
                .read(Oid::from_bytes(&f.head).unwrap())
                .unwrap()
                .kind(),
            ObjectType::Commit
        );
        let before = std::fs::read(&path).unwrap();
        let mut counts = [0usize; 4];
        assert!(
            crate::GitRepository::for_each_preserved_record(
                temp.path(),
                id,
                &[225; 32],
                |record| {
                    match record {
                        crate::PreservedGitRecord::Unclassified { .. } => {
                            anyhow::bail!("installed paged history is unclassified")
                        }
                        crate::PreservedGitRecord::Reference { .. } => counts[0] += 1,
                        crate::PreservedGitRecord::ChunkedMetadataObject { .. } => counts[1] += 1,
                        crate::PreservedGitRecord::IndexEntry { .. } => counts[2] += 1,
                        crate::PreservedGitRecord::ObjectAnchor { .. } => counts[3] += 1,
                        _ => {}
                    }
                    Ok(())
                }
            )
            .unwrap()
        );
        assert_eq!(counts, [3, 4, 3, 2]);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn paged_import_aborted_and_ignored_rows_or_owner_never_publish_partial_history() {
        let temp = tempfile::tempdir().unwrap();
        let f = fixture(temp.path(), b"target");
        let id = f.root.repository_id;
        for (number, (kind, action)) in [
            (&crate::history::ref_kind(id), "ABORT"),
            (&crate::stage::index_kind(id), "IGNORE"),
            (&OWNER.to_owned(), "IGNORE"),
            (
                &crate::metadata_chunks::kind(crate::metadata_chunks::FRAGMENTS, id),
                "ABORT",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let control = ControlStore::open_with_key(
                temp.path().join(format!("failure-{number}.db")),
                &[225; 32],
            )
            .unwrap();
            control.database_shell_statement(&format!("CREATE TEMP TRIGGER fail_install BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{}); END", if action == "ABORT" { ",'test'" } else { "" }), false).unwrap();
            assert!(install(&control, &f).is_err());
            assert!(rows(&control, id).iter().all(|(_, rows)| rows.is_empty()));
            assert!(
                !control
                    .has_records_with_kind_prefix(&crate::stage::object_kind_prefix(id))
                    .unwrap()
            );
            control
                .database_shell_statement("DROP TRIGGER fail_install", false)
                .unwrap();
            install(&control, &f).unwrap();
            assert!(installed(&control, id).unwrap().is_some());
        }
    }

    #[test]
    fn paged_import_source_and_symlink_failures_preserve_destination_and_original_anchors() {
        let temp = tempfile::tempdir().unwrap();
        let f = fixture(temp.path(), b"bad\0target");
        let id = f.root.repository_id;
        let control =
            ControlStore::open_with_key(temp.path().join("catalog.db"), &[225; 32]).unwrap();
        let before = rows(&control, id);
        assert!(install(&control, &f).is_err());
        assert_eq!(rows(&control, id), before);
        assert!(
            import(
                &control,
                id,
                scope(),
                &f.root,
                |_| anyhow::bail!("lost page"),
                |oid| Ok(f.anchors[&oid].clone())
            )
            .is_err()
        );
        assert_eq!(rows(&control, id), before);
        assert!(
            import(
                &control,
                id,
                scope(),
                &f.root,
                |p| Ok(f.pages[&p.hash].clone()),
                |_| Ok(f.anchors[&f.regular].clone())
            )
            .is_err()
        );
        assert_eq!(rows(&control, id), before);
        for anchor in f.anchors.values() {
            assert!(anchor.open_verified().is_ok());
        }
    }

    #[test]
    fn paged_import_late_competing_rows_and_damaged_completed_retries_are_preserved() {
        let temp = tempfile::tempdir().unwrap();
        let f = fixture(temp.path(), b"target");
        let id = f.root.repository_id;
        let path = temp.path().join("catalog.db");
        let control = ControlStore::open_with_key(&path, &[225; 32]).unwrap();
        let mut written = false;
        assert!(
            import(
                &control,
                id,
                scope(),
                &f.root,
                |p| {
                    if !written {
                        written = true;
                        let other = ControlStore::open_existing_with_key(&path, &[225; 32])?;
                        other.put_record(
                            &crate::history::ref_kind(id),
                            b"competing",
                            b"original competitor",
                        )?;
                    }
                    Ok(f.pages[&p.hash].clone())
                },
                |oid| Ok(f.anchors[&oid].clone())
            )
            .is_err()
        );
        assert_eq!(
            control.records(&crate::history::ref_kind(id)).unwrap(),
            vec![(b"competing".to_vec(), b"original competitor".to_vec())]
        );
        assert!(installed(&control, id).unwrap().is_none());
        control
            .delete_record(&crate::history::ref_kind(id), b"competing")
            .unwrap();
        install(&control, &f).unwrap();
        let old = control
            .get_record(&crate::history::ref_kind(id), b"refs/heads/main")
            .unwrap()
            .unwrap();
        control
            .delete_record_if_value(&crate::history::ref_kind(id), b"refs/heads/main", &old)
            .unwrap();
        let before = rows(&control, id);
        assert!(install(&control, &f).is_err());
        assert_eq!(rows(&control, id), before);
        assert!(
            control
                .get_record(&crate::history::ref_kind(id), b"refs/heads/main")
                .unwrap()
                .is_none()
        );
        let completed = control.get_record(OWNER, id.as_bytes()).unwrap().unwrap();
        for (kind, key, bytes) in [
            (OWNER.to_owned(), id, b"invalid completed owner".to_vec()),
            (OWNER.to_owned(), Uuid::from_u128(226), completed.clone()),
            (format!("{OWNER}/unexpected"), id, completed.clone()),
        ] {
            control.put_record(&kind, key.as_bytes(), &bytes).unwrap();
            assert!(validate_preserved(&control, id).is_err());
            control.delete_record(&kind, key.as_bytes()).unwrap();
            control
                .put_record(OWNER, id.as_bytes(), &completed)
                .unwrap();
        }
    }

    #[test]
    fn paged_import_streams_large_commit_without_the_legacy_row_or_object_materialization() {
        use sha1::{Digest, Sha1};
        let temp = tempfile::tempdir().unwrap();
        let f = fixture_with_metadata(
            temp.path(),
            b"target",
            crate::history::MAX_GRAPH_METADATA_BYTES + 1,
        );
        let control =
            ControlStore::open_with_key(temp.path().join("catalog.db"), &[225; 32]).unwrap();
        install(&control, &f).unwrap();
        assert_eq!(
            control
                .records(&crate::stage::index_kind(f.root.repository_id))
                .unwrap()
                .len(),
            3
        );
        assert!(
            control
                .records(&crate::history::metadata_kind(f.root.repository_id))
                .unwrap()
                .is_empty()
        );
        let odb = git2::Odb::new().unwrap();
        let _index =
            crate::metadata_odb::MetadataIndex::load(&control, f.root.repository_id, &odb).unwrap();
        let oid = Oid::from_bytes(&f.head).unwrap();
        assert!(odb.read(oid).is_err());
        let (mut reader, length, kind) = odb.reader(oid).unwrap();
        assert_eq!((length, kind), (f.head_bytes, ObjectType::Commit));
        let mut hash = Sha1::new();
        hash.update(format!("commit {length}\0").as_bytes());
        let mut block = [0u8; 8192];
        let mut observed = 0;
        loop {
            let read = reader.read(&mut block).unwrap();
            if read == 0 {
                break;
            }
            hash.update(&block[..read]);
            observed += read;
        }
        assert_eq!(observed, length);
        assert_eq!(hash.finalize().as_slice(), f.head);
    }

    #[test]
    #[ignore = "explicit Linux >512 MiB complete paged Git installation memory qualification"]
    fn paged_import_above_512_mib_keeps_staging_installation_and_history_bounded() {
        let temp = tempfile::tempdir().unwrap();
        let source = RecordScratchStore::new(2 << 30).unwrap();
        const OBJECTS: &str = "source-object";
        const PAGES: &str = "source-page";
        const OBJECT_BYTES: usize = 512 * 1024;
        let tree = Oid::hash_object(ObjectType::Tree, &[]).unwrap();
        let mut head = tree;
        source.with_record_transaction(|| -> Result<()> {
            source.put_record_if_absent(OBJECTS, tree.as_bytes(), &canonical_bytes_bounded(&(2u8, Vec::<u8>::new()), OBJECT_BYTES + 32)?)?;
            for sequence in 0..1025 {
                let parent = if sequence == 0 { String::new() } else { format!("parent {head}\n") };
                let mut bytes = format!("tree {tree}\n{parent}author A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\noriginal {sequence}\n").into_bytes();
                bytes.resize(OBJECT_BYTES, b'x');
                head = Oid::hash_object(ObjectType::Commit, &bytes)?;
                source.put_record_if_absent(OBJECTS, head.as_bytes(), &canonical_bytes_bounded(&(1u8, bytes), OBJECT_BYTES + 32)?)?;
            }
            Ok(())
        }).unwrap();
        let tag = format!(
            "object {head}\ntype commit\ntag saved\ntagger A <a@test> 1 +0000\n\noriginal tag\n"
        )
        .into_bytes();
        let tag_oid = Oid::hash_object(ObjectType::Tag, &tag).unwrap();
        source
            .put_record_if_absent(
                OBJECTS,
                tag_oid.as_bytes(),
                &canonical_bytes_bounded(&(3u8, tag), OBJECT_BYTES + 32).unwrap(),
            )
            .unwrap();
        let mut sink = |page: CatalogPageRef, bytes: Vec<u8>| -> Result<()> {
            ensure!(
                bytes.len() <= mb_core::CATALOG_PAGE_BYTES,
                "oversized source page"
            );
            source.put_record_if_absent(PAGES, &page.hash, &bytes)?;
            ensure!(
                source
                    .get_record_bounded(PAGES, &page.hash, mb_core::CATALOG_PAGE_BYTES)?
                    .as_deref()
                    == Some(bytes.as_slice()),
                "source page write differs"
            );
            Ok(())
        };
        let git = source
            .with_record_transaction(|| -> Result<GitCatalogRoot> {
                let mut objects = GitObjectCatalogBuilder::new(scope())?;
                let mut after = None;
                while let Some((oid, encoded)) =
                    source.next_record_bounded(OBJECTS, after.as_deref(), 20, OBJECT_BYTES + 32)?
                {
                    let (kind, bytes): (u8, Vec<u8>) = decode_canonical(&encoded)?;
                    objects.push_object(
                        oid.as_slice().try_into()?,
                        kind,
                        bytes.len() as u64,
                        &mut bytes.as_slice(),
                        &mut sink,
                    )?;
                    after = Some(oid);
                }
                let mut refs = GitRefCatalogBuilder::new(scope(), b"main")?;
                for (name, oid) in [
                    (b"refs/heads/main".as_slice(), head),
                    (b"refs/tags/saved".as_slice(), tag_oid),
                ] {
                    refs.push_ref(
                        &GitRefRecord {
                            format_version: 1,
                            name: name.to_vec(),
                            oid: oid.as_bytes().try_into()?,
                        },
                        &mut sink,
                    )?;
                }
                Ok(GitCatalogRoot {
                    format_version: 1,
                    repository_id: Uuid::from_u128(225),
                    refs: refs.finish(&mut sink)?,
                    objects: objects.finish(&mut sink)?,
                    blobs: GitBlobCatalogBuilder::new(scope())?.finish(&mut sink)?,
                })
            })
            .unwrap();
        assert_eq!(git.objects.objects, 1027);
        assert!(git.objects.object_bytes > 512 * 1024 * 1024);
        let control =
            ControlStore::open_with_key(temp.path().join("catalog.db"), &[225; 32]).unwrap();
        import(
            &control,
            git.repository_id,
            scope(),
            &git,
            |page| {
                source
                    .get_record_bounded(PAGES, &page.hash, mb_core::CATALOG_PAGE_BYTES)?
                    .context("source page missing")
            },
            |_| anyhow::bail!("empty blob stream requested an anchor"),
        )
        .unwrap();
        assert!(
            control
                .records(&crate::stage::index_kind(git.repository_id))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::history::log_history(&control, git.repository_id, 1).unwrap()[0].oid,
            head.as_bytes()
        );
        assert_eq!(
            crate::history::list_tags(&control, git.repository_id)
                .unwrap()
                .len(),
            1
        );
        validate_preserved(&control, git.repository_id).unwrap();
        println!(
            "paged Git import qualification: objects={}, payload_bytes={}",
            git.objects.objects, git.objects.object_bytes
        );
    }
}
