//! Local Git tree/commit metadata over the encrypted catalog. Libgit2 builds
//! canonical objects in a disposable metadata-only repository; file blobs never
//! enter that repository or a Git object directory.

use std::collections::{HashMap, HashSet};

use git2::{Index, IndexEntry, IndexTime, ObjectType, Oid, Repository, Signature};
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{ControlStore, DatabaseError, FileAnchorManifest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::stage::{StageError, anchors_for_oid, has_pending_stages, staged_entries};
use crate::{GitAnchorError, NativeOdb};

const METADATA_PREFIX: &str = "git-metadata-object-v1/";
const REF_PREFIX: &str = "git-ref-v1/";
const MAIN_REF: &[u8] = b"refs/heads/main";
const MAX_GRAPH_OBJECTS: usize = 100_000;
const MAX_GRAPH_METADATA_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum HistoryError {
    #[error("Git staging error: {0}")]
    Stage(#[from] StageError),
    #[error("encrypted catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned history metadata error: {0}")]
    Model(#[from] ModelError),
    #[error("Git metadata error: {0}")]
    Git(#[from] git2::Error),
    #[error("native Git object backend error: {0}")]
    Anchor(#[from] GitAnchorError),
    #[error("temporary metadata repository error: {0}")]
    Io(#[from] std::io::Error),
    #[error("an unfinished add must be resumed or abandoned before committing")]
    PendingStage,
    #[error("no staged files are available to commit")]
    EmptyIndex,
    #[error("the staged tree is identical to HEAD")]
    UnchangedTree,
    #[error("the history catalog contains an incompatible or corrupt object")]
    IncompatibleRecord,
    #[error("the reachable Git graph exceeds the bounded backup metadata limit")]
    GraphTooLarge,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitCommitInfo {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub oid: [u8; 20],
    pub tree_oid: [u8; 20],
    pub parent_oid: Option<[u8; 20]>,
    pub branch: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitLogEntry {
    pub oid: [u8; 20],
    pub tree_oid: [u8; 20],
    pub parent_oids: Vec<[u8; 20]>,
    pub author_name: Vec<u8>,
    pub author_email: Vec<u8>,
    pub message: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitGraphRef {
    pub name: Vec<u8>,
    pub oid: [u8; 20],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitGraphObject {
    pub kind: u8,
    pub oid: [u8; 20],
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitGraphBlobSource {
    pub oid: [u8; 20],
    pub anchor: FileAnchorManifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitGraphSource {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub refs: Vec<GitGraphRef>,
    pub objects: Vec<GitGraphObject>,
    pub blobs: Vec<GitGraphBlobSource>,
}

#[derive(Clone, Serialize, Deserialize)]
struct MetadataObject {
    format_version: u16,
    kind: u8,
    bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct RefRecord {
    format_version: u16,
    oid: [u8; 20],
}

fn metadata_kind(repository_id: Uuid) -> String {
    format!("{METADATA_PREFIX}{repository_id}")
}

fn ref_kind(repository_id: Uuid) -> String {
    format!("{REF_PREFIX}{repository_id}")
}

fn object_type(code: u8) -> Option<ObjectType> {
    match code {
        1 => Some(ObjectType::Commit),
        2 => Some(ObjectType::Tree),
        _ => None,
    }
}

fn object_code(kind: ObjectType) -> Result<u8, HistoryError> {
    match kind {
        ObjectType::Commit => Ok(1),
        ObjectType::Tree => Ok(2),
        _ => Err(HistoryError::IncompatibleRecord),
    }
}

fn object_record(kind: ObjectType, bytes: Vec<u8>) -> Result<Vec<u8>, HistoryError> {
    Ok(canonical_bytes(&MetadataObject {
        format_version: 1,
        kind: object_code(kind)?,
        bytes,
    })?)
}

fn load_metadata(
    control: &ControlStore,
    repository_id: Uuid,
    repository: &Repository,
) -> Result<HashMap<Oid, MetadataObject>, HistoryError> {
    let odb = repository.odb()?;
    let mut objects = HashMap::new();
    for (key, encoded) in control.records(&metadata_kind(repository_id))? {
        let object: MetadataObject = decode_canonical(&encoded)?;
        let kind = object_type(object.kind).ok_or(HistoryError::IncompatibleRecord)?;
        let oid = Oid::hash_object(kind, &object.bytes)?;
        if object.format_version != 1 || key != oid.as_bytes() {
            return Err(HistoryError::IncompatibleRecord);
        }
        if odb.write(kind, &object.bytes)? != oid {
            return Err(HistoryError::IncompatibleRecord);
        }
        if objects.insert(oid, object).is_some() || objects.len() > MAX_GRAPH_OBJECTS {
            return Err(HistoryError::GraphTooLarge);
        }
    }
    Ok(objects)
}

fn head_oid(control: &ControlStore, repository_id: Uuid) -> Result<Option<Oid>, HistoryError> {
    let Some(encoded) = control.get_record(&ref_kind(repository_id), MAIN_REF)? else {
        return Ok(None);
    };
    let record: RefRecord = decode_canonical(&encoded)?;
    if record.format_version != 1 {
        return Err(HistoryError::IncompatibleRecord);
    }
    Ok(Some(Oid::from_bytes(&record.oid)?))
}

/// Commit the staged snapshot to `main`. This first history path has one
/// worktree and one branch; later branch/worktree commands extend the ref
/// selection without changing the stored Git object bytes.
pub fn commit_index(
    control: &ControlStore,
    repository_id: Uuid,
    author_name: &str,
    author_email: &str,
    message: &str,
) -> Result<GitCommitInfo, HistoryError> {
    if has_pending_stages(control, repository_id)? {
        return Err(HistoryError::PendingStage);
    }
    let staged = staged_entries(control, repository_id)?;
    if staged.is_empty() {
        return Err(HistoryError::EmptyIndex);
    }
    let mut anchors = Vec::new();
    for (_, entry) in &staged {
        let oid = Oid::from_bytes(&entry.oid)?;
        let anchor = anchors_for_oid(control, repository_id, oid)?
            .into_iter()
            .find(|anchor| anchor.anchor_id == entry.anchor_id)
            .ok_or(HistoryError::IncompatibleRecord)?;
        anchors.push(anchor);
    }

    let temporary = tempfile::tempdir()?;
    let repository = Repository::init_bare(temporary.path())?;
    let native_odb = NativeOdb::from_anchors(anchors)?;
    let _metadata_pack = native_odb.odb().add_new_mempack_backend(1000)?;
    repository.set_odb(native_odb.odb())?;
    load_metadata(control, repository_id, &repository)?;
    let previous = head_oid(control, repository_id)?;
    let parent = match previous {
        Some(oid) => Some(
            repository
                .find_commit(oid)
                .map_err(|_| HistoryError::IncompatibleRecord)?,
        ),
        None => None,
    };

    let mut index = Index::new()?;
    for (path, entry) in staged {
        index.add(&IndexEntry {
            ctime: IndexTime::new(0, 0),
            mtime: IndexTime::new(0, 0),
            dev: 0,
            ino: 0,
            mode: entry.mode,
            uid: 0,
            gid: 0,
            file_size: 0,
            id: Oid::from_bytes(&entry.oid)?,
            flags: 0,
            flags_extended: 0,
            path,
        })?;
    }
    let tree_oid = index.write_tree_to(&repository)?;
    if parent
        .as_ref()
        .is_some_and(|commit| commit.tree_id() == tree_oid)
    {
        return Err(HistoryError::UnchangedTree);
    }
    let root_tree = repository.find_tree(tree_oid)?;
    let mut pending = vec![tree_oid];
    let mut seen = HashSet::new();
    let mut published = Vec::new();
    let odb = repository.odb()?;
    while let Some(oid) = pending.pop() {
        if !seen.insert(oid) {
            continue;
        }
        let tree = repository.find_tree(oid)?;
        for entry in tree.iter() {
            if entry.kind() == Some(ObjectType::Tree) {
                pending.push(entry.id());
            }
        }
        let bytes = odb.read(oid)?.data().to_vec();
        published.push((
            metadata_kind(repository_id),
            oid.as_bytes().to_vec(),
            object_record(ObjectType::Tree, bytes)?,
        ));
    }
    let signature = Signature::now(author_name, author_email)?;
    let parents = parent.iter().collect::<Vec<_>>();
    let commit_bytes = repository
        .commit_create_buffer(&signature, &signature, message, &root_tree, &parents)?
        .to_vec();
    let commit_oid = Oid::hash_object(ObjectType::Commit, &commit_bytes)?;
    published.push((
        metadata_kind(repository_id),
        commit_oid.as_bytes().to_vec(),
        object_record(ObjectType::Commit, commit_bytes)?,
    ));
    published.push((
        ref_kind(repository_id),
        MAIN_REF.to_vec(),
        canonical_bytes(&RefRecord {
            format_version: 1,
            oid: commit_oid
                .as_bytes()
                .try_into()
                .expect("SHA-1 Git object IDs contain 20 bytes"),
        })?,
    ));
    control.put_records_and_delete(&published, &[])?;
    Ok(GitCommitInfo {
        format_version: 1,
        repository_id,
        oid: commit_oid
            .as_bytes()
            .try_into()
            .expect("SHA-1 Git object IDs contain 20 bytes"),
        tree_oid: tree_oid
            .as_bytes()
            .try_into()
            .expect("SHA-1 Git object IDs contain 20 bytes"),
        parent_oid: previous.map(|oid| oid.as_bytes().try_into().expect("SHA-1 OID")),
        branch: "main".to_owned(),
    })
}

/// Read reachable commits through libgit2 after verifying the catalog's raw
/// object bytes against their IDs. Parent traversal handles merge commits
/// even though merge creation is not yet exposed by this frontend.
pub fn log_history(
    control: &ControlStore,
    repository_id: Uuid,
    limit: usize,
) -> Result<Vec<GitLogEntry>, HistoryError> {
    if limit == 0 || limit > 1000 {
        return Err(HistoryError::IncompatibleRecord);
    }
    let Some(head) = head_oid(control, repository_id)? else {
        return Ok(Vec::new());
    };
    let temporary = tempfile::tempdir()?;
    let repository = Repository::init_bare(temporary.path())?;
    let odb = git2::Odb::new()?;
    let _pack = odb.add_new_mempack_backend(1000)?;
    repository.set_odb(&odb)?;
    load_metadata(control, repository_id, &repository)?;
    let mut pending = vec![head];
    let mut visited = HashSet::new();
    let mut result = Vec::new();
    while let Some(oid) = pending.pop() {
        if !visited.insert(oid) {
            continue;
        }
        let commit = repository
            .find_commit(oid)
            .map_err(|_| HistoryError::IncompatibleRecord)?;
        let parents = commit
            .parent_ids()
            .map(|parent| {
                parent
                    .as_bytes()
                    .try_into()
                    .expect("SHA-1 Git object IDs contain 20 bytes")
            })
            .collect();
        let author = commit.author();
        result.push(GitLogEntry {
            oid: oid
                .as_bytes()
                .try_into()
                .expect("SHA-1 Git object IDs contain 20 bytes"),
            tree_oid: commit
                .tree_id()
                .as_bytes()
                .try_into()
                .expect("SHA-1 Git object IDs contain 20 bytes"),
            parent_oids: parents,
            author_name: author.name_bytes().to_vec(),
            author_email: author.email_bytes().to_vec(),
            message: commit.message_bytes().to_vec(),
        });
        if result.len() >= limit {
            break;
        }
        for parent in commit.parent_ids().rev() {
            pending.push(parent);
        }
    }
    Ok(result)
}

/// Export only objects reachable from durable refs. Uncommitted staged blobs
/// and unreachable local objects are absent from this backup source.
pub fn export_graph_source(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<GitGraphSource, HistoryError> {
    let mut refs = Vec::new();
    for (name, encoded) in control.records(&ref_kind(repository_id))? {
        let name_text = std::str::from_utf8(&name).map_err(|_| HistoryError::IncompatibleRecord)?;
        if !name_text.starts_with("refs/") || !git2::Reference::is_valid_name(name_text) {
            return Err(HistoryError::IncompatibleRecord);
        }
        let record: RefRecord = decode_canonical(&encoded)?;
        if record.format_version != 1 {
            return Err(HistoryError::IncompatibleRecord);
        }
        refs.push(GitGraphRef {
            name,
            oid: record.oid,
        });
    }
    if refs.len() > MAX_GRAPH_OBJECTS {
        return Err(HistoryError::GraphTooLarge);
    }
    if refs.is_empty() {
        return Ok(GitGraphSource {
            format_version: 1,
            repository_id,
            refs,
            objects: Vec::new(),
            blobs: Vec::new(),
        });
    }

    let temporary = tempfile::tempdir()?;
    let repository = Repository::init_bare(temporary.path())?;
    let odb = git2::Odb::new()?;
    let _pack = odb.add_new_mempack_backend(1000)?;
    repository.set_odb(&odb)?;
    let stored = load_metadata(control, repository_id, &repository)?;
    let mut commits = refs
        .iter()
        .map(|reference| Oid::from_bytes(&reference.oid))
        .collect::<Result<Vec<_>, _>>()?;
    let mut trees = Vec::new();
    let mut seen_commits = HashSet::new();
    let mut seen_trees = HashSet::new();
    let mut blob_ids = HashSet::new();
    while let Some(oid) = commits.pop() {
        if !seen_commits.insert(oid) {
            continue;
        }
        if seen_commits.len() > MAX_GRAPH_OBJECTS {
            return Err(HistoryError::GraphTooLarge);
        }
        let commit = repository
            .find_commit(oid)
            .map_err(|_| HistoryError::IncompatibleRecord)?;
        trees.push(commit.tree_id());
        commits.extend(commit.parent_ids());
    }
    while let Some(oid) = trees.pop() {
        if !seen_trees.insert(oid) {
            continue;
        }
        if seen_trees.len() > MAX_GRAPH_OBJECTS {
            return Err(HistoryError::GraphTooLarge);
        }
        let tree = repository
            .find_tree(oid)
            .map_err(|_| HistoryError::IncompatibleRecord)?;
        for entry in tree.iter() {
            match entry.kind() {
                Some(ObjectType::Tree) => trees.push(entry.id()),
                Some(ObjectType::Blob) => {
                    blob_ids.insert(entry.id());
                    if blob_ids.len() > MAX_GRAPH_OBJECTS {
                        return Err(HistoryError::GraphTooLarge);
                    }
                }
                _ => return Err(HistoryError::IncompatibleRecord),
            }
        }
    }
    let mut reachable = seen_commits
        .into_iter()
        .map(|oid| (oid, ObjectType::Commit))
        .chain(seen_trees.into_iter().map(|oid| (oid, ObjectType::Tree)))
        .collect::<Vec<_>>();
    reachable.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let mut objects = Vec::with_capacity(reachable.len());
    let mut metadata_bytes = refs.iter().map(|item| item.name.len() + 20).sum::<usize>();
    for (oid, kind) in reachable {
        let stored_object = stored.get(&oid).ok_or(HistoryError::IncompatibleRecord)?;
        if object_type(stored_object.kind) != Some(kind) {
            return Err(HistoryError::IncompatibleRecord);
        }
        metadata_bytes = metadata_bytes
            .checked_add(stored_object.bytes.len() + 24)
            .ok_or(HistoryError::GraphTooLarge)?;
        if metadata_bytes > MAX_GRAPH_METADATA_BYTES {
            return Err(HistoryError::GraphTooLarge);
        }
        objects.push(GitGraphObject {
            kind: stored_object.kind,
            oid: oid.as_bytes().try_into().expect("SHA-1 OID"),
            bytes: stored_object.bytes.clone(),
        });
    }
    let mut blob_ids = blob_ids.into_iter().collect::<Vec<_>>();
    blob_ids.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    let mut blobs = Vec::with_capacity(blob_ids.len());
    for oid in blob_ids {
        let anchor = anchors_for_oid(control, repository_id, oid)?
            .into_iter()
            .min_by_key(|anchor| anchor.anchor_id)
            .ok_or(HistoryError::IncompatibleRecord)?;
        blobs.push(GitGraphBlobSource {
            oid: oid.as_bytes().try_into().expect("SHA-1 OID"),
            anchor,
        });
    }
    Ok(GitGraphSource {
        format_version: 1,
        repository_id,
        refs,
        objects,
        blobs,
    })
}
