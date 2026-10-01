//! Crash-replayable import from a local bare Git repository or stock Git push.
//! Commit/tree metadata is bounded in the encrypted catalog. Blob payloads
//! stream from raw Git objects directly into native immutable anchors.

use std::collections::{HashMap, HashSet};
use std::ffi::OsString;
use std::io::{BufReader, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use git2::{ObjectFormat, ObjectType, Oid, Repository};
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, SourceBlobImportPlan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::attributes::{GitAttributesError, MAX_ATTRIBUTES_BYTES, validate_attributes};
use crate::head::{HeadError, linked_selected_branches, selected_branch};
use crate::history::{
    GitGraphObject, GitGraphRef, HistoryError, MAX_GRAPH_METADATA_BYTES, MAX_GRAPH_OBJECTS,
    commit_descends_from, fetched_ref_record, metadata_kind, object_record, ref_kind, ref_oid,
};
use crate::interop::GitInteropError;
use crate::stage::{StageError, anchors_for_oid, object_kind, stage_path_key};
use crate::{GitAnchorError, blob_oid_from_anchor};

const FETCH_PREFIX: &str = "git-bare-fetch-intent-v1/";
const BLOB_PREFIX: &str = "git-bare-fetch-blob-intent-v1/";
const VERIFIED_PREFIX: &str = "git-bare-fetch-verified-v1/";
const PUSH_PREFIX: &str = "git-stock-push-intent-v1/";
const ACTIVE: &[u8] = b"active";

#[derive(Debug, Error)]
pub enum FetchError {
    #[error("Git object or reference error: {0}")]
    Git(#[from] git2::Error),
    #[error("source or Git object stream error: {0}")]
    Io(#[from] std::io::Error),
    #[error("native anchor capture error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("native Git object verification error: {0}")]
    GitAnchor(#[from] GitAnchorError),
    #[error("existing Git object verification error: {0}")]
    Interop(#[from] GitInteropError),
    #[error("Git staging path error: {0}")]
    Stage(#[from] StageError),
    #[error("Git history error: {0}")]
    History(#[from] HistoryError),
    #[error("Git HEAD error: {0}")]
    Head(#[from] HeadError),
    #[error("encrypted catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned fetch intent error: {0}")]
    Model(#[from] ModelError),
    #[error("source must be an existing exact SHA-1 Git directory outside this root")]
    UnsupportedSource,
    #[error("Git attributes policy error: {0}")]
    Attributes(#[from] GitAttributesError),
    #[error("the pending fetch belongs to another source or root")]
    PendingFetch,
    #[error("the Git source changed or contains an unsupported or corrupt object")]
    IncompatibleSource,
    #[error("the fetched Git graph exceeds the bounded metadata or object limit")]
    GraphTooLarge,
    #[error("the requested push branch is selected by a worktree")]
    CheckedOutBranch,
    #[error("the advertised destination ref changed before the push")]
    StalePush,
    #[error("the pushed commit is not a descendant of the destination branch")]
    NonFastForward,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FetchedBlob {
    oid: [u8; 20],
    logical_len: u64,
    symlink: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FetchIntent {
    format_version: u16,
    fetch_id: Uuid,
    repository_id: Uuid,
    source_path: PathBuf,
    source_root: PathBuf,
    refs: Vec<GitGraphRef>,
    objects: Vec<GitGraphObject>,
    blobs: Vec<FetchedBlob>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PushImportIntent {
    format_version: u16,
    target_branch: String,
    expected_old: Option<[u8; 20]>,
    fetch: FetchIntent,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct BlobIntent {
    format_version: u16,
    repository_id: Uuid,
    oid: [u8; 20],
    logical_len: u64,
    plan: SourceBlobImportPlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct VerifiedBlob {
    format_version: u16,
    oid: [u8; 20],
    anchors: Vec<(Uuid, [u8; 32])>,
}

fn fetch_kind(repository_id: Uuid) -> String {
    format!("{FETCH_PREFIX}{repository_id}")
}

fn push_kind(repository_id: Uuid) -> String {
    format!("{PUSH_PREFIX}{repository_id}")
}

pub(crate) fn has_pending_fetch(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<bool, FetchError> {
    Ok(!control.records(&fetch_kind(repository_id))?.is_empty()
        || !control.records(&push_kind(repository_id))?.is_empty()
        || !control.records(&blob_kind(repository_id))?.is_empty()
        || !control
            .records_with_kind_prefix(&format!("{VERIFIED_PREFIX}{repository_id}/"))?
            .is_empty())
}

fn blob_kind(repository_id: Uuid) -> String {
    format!("{BLOB_PREFIX}{repository_id}")
}

fn verified_kind(intent: &FetchIntent) -> String {
    format!(
        "{VERIFIED_PREFIX}{}/{}",
        intent.repository_id, intent.fetch_id
    )
}

fn sha1(oid: Oid) -> [u8; 20] {
    oid.as_bytes().try_into().expect("SHA-1 repository")
}

fn source_repository(
    path: &Path,
    root: &Path,
    format_version: u16,
) -> Result<Repository, FetchError> {
    if path.starts_with(root) || path.canonicalize()? != path {
        return Err(FetchError::UnsupportedSource);
    }
    let repo = match format_version {
        1 => Repository::open_bare(path)?,
        2 => Repository::open(path)?,
        _ => return Err(FetchError::UnsupportedSource),
    };
    if (format_version == 1 && !repo.is_bare())
        || repo.path().canonicalize()? != path
        || repo.object_format() != ObjectFormat::Sha1
    {
        return Err(FetchError::UnsupportedSource);
    }
    Ok(repo)
}

fn metadata_bytes(
    odb: &git2::Odb<'_>,
    oid: Oid,
    kind: ObjectType,
    budget: &mut usize,
) -> Result<Vec<u8>, FetchError> {
    let (size, actual_kind) = odb.read_header(oid)?;
    if actual_kind != kind || size > MAX_GRAPH_METADATA_BYTES.saturating_sub(*budget) {
        return Err(FetchError::GraphTooLarge);
    }
    *budget += size + 24;
    if *budget > MAX_GRAPH_METADATA_BYTES {
        return Err(FetchError::GraphTooLarge);
    }
    let object = odb.read(oid)?;
    if object.kind() != kind || object.data().len() != size {
        return Err(FetchError::IncompatibleSource);
    }
    if Oid::hash_object(kind, object.data())? != oid {
        return Err(FetchError::IncompatibleSource);
    }
    Ok(object.data().to_vec())
}

fn discover(
    repo: &Repository,
    repository_id: Uuid,
    source_path: PathBuf,
    source_root: PathBuf,
) -> Result<FetchIntent, FetchError> {
    let mut refs = Vec::new();
    for reference in repo.references_glob("refs/heads/*")? {
        let reference = reference?;
        let name = reference.name()?;
        let branch = name
            .strip_prefix("refs/heads/")
            .ok_or(FetchError::IncompatibleSource)?;
        if branch.is_empty() || !git2::Branch::name_is_valid(branch)? {
            return Err(FetchError::IncompatibleSource);
        }
        let target = reference.target().ok_or(FetchError::IncompatibleSource)?;
        let remote_name = format!("refs/remotes/origin/{branch}");
        if !git2::Reference::is_valid_name(&remote_name) {
            return Err(FetchError::IncompatibleSource);
        }
        refs.push(GitGraphRef {
            name: remote_name.into_bytes(),
            oid: sha1(target),
        });
        if refs.len() > MAX_GRAPH_OBJECTS {
            return Err(FetchError::GraphTooLarge);
        }
    }
    refs.sort_by(|left, right| left.name.cmp(&right.name));

    discover_from_refs(repo, repository_id, source_path, source_root, refs, 1)
}

fn discover_from_refs(
    repo: &Repository,
    repository_id: Uuid,
    source_path: PathBuf,
    source_root: PathBuf,
    refs: Vec<GitGraphRef>,
    format_version: u16,
) -> Result<FetchIntent, FetchError> {
    let odb = repo.odb()?;

    let mut metadata_budget = refs.iter().map(|reference| reference.name.len() + 20).sum();
    let mut commits = refs
        .iter()
        .map(|reference| Oid::from_bytes(&reference.oid))
        .collect::<Result<Vec<_>, _>>()?;
    let mut trees = Vec::new();
    let mut seen_commits = HashSet::new();
    let mut seen_trees = HashSet::new();
    let mut tree_visits = 0_usize;
    let mut metadata = Vec::new();
    let mut blobs: HashMap<Oid, FetchedBlob> = HashMap::new();
    while let Some(oid) = commits.pop() {
        if !seen_commits.insert(oid) {
            continue;
        }
        if seen_commits.len() + seen_trees.len() + blobs.len() > MAX_GRAPH_OBJECTS {
            return Err(FetchError::GraphTooLarge);
        }
        let bytes = metadata_bytes(&odb, oid, ObjectType::Commit, &mut metadata_budget)?;
        let commit = repo.find_commit(oid)?;
        trees.push((Vec::<u8>::new(), commit.tree_id()));
        commits.extend(commit.parent_ids());
        metadata.push(GitGraphObject {
            kind: 1,
            oid: sha1(oid),
            bytes,
        });
    }
    while let Some((prefix, oid)) = trees.pop() {
        tree_visits += 1;
        if tree_visits > MAX_GRAPH_OBJECTS {
            return Err(FetchError::GraphTooLarge);
        }
        let new_object = seen_trees.insert(oid);
        if seen_commits.len() + seen_trees.len() + blobs.len() > MAX_GRAPH_OBJECTS {
            return Err(FetchError::GraphTooLarge);
        }
        let bytes = if new_object {
            Some(metadata_bytes(
                &odb,
                oid,
                ObjectType::Tree,
                &mut metadata_budget,
            )?)
        } else {
            None
        };
        let tree = repo.find_tree(oid)?;
        for entry in tree.iter() {
            let mut path = prefix.clone();
            path.extend_from_slice(entry.name_bytes());
            stage_path_key(&PathBuf::from(OsString::from_vec(path.clone())))?;
            match entry.filemode() {
                0o040000 if entry.kind() == Some(ObjectType::Tree) => {
                    path.push(b'/');
                    trees.push((path, entry.id()));
                }
                mode @ (0o100644 | 0o100755 | 0o120000)
                    if entry.kind() == Some(ObjectType::Blob) =>
                {
                    let (size, kind) = odb.read_header(entry.id())?;
                    if kind != ObjectType::Blob {
                        return Err(FetchError::IncompatibleSource);
                    }
                    let size = size as u64;
                    if entry.name_bytes() == b".gitattributes"
                        && matches!(mode, 0o100644 | 0o100755)
                    {
                        if size > MAX_ATTRIBUTES_BYTES {
                            return Err(GitAttributesError::TooLarge.into());
                        }
                        validate_attributes(odb.read(entry.id())?.data())?;
                    }
                    let blob = blobs.entry(entry.id()).or_insert_with(|| FetchedBlob {
                        oid: sha1(entry.id()),
                        logical_len: size,
                        symlink: false,
                    });
                    if blob.logical_len != size {
                        return Err(FetchError::IncompatibleSource);
                    }
                    blob.symlink |= mode == 0o120000;
                    if blob.symlink && !(1..=4095).contains(&size) {
                        return Err(FetchError::IncompatibleSource);
                    }
                    if seen_commits.len() + seen_trees.len() + blobs.len() > MAX_GRAPH_OBJECTS {
                        return Err(FetchError::GraphTooLarge);
                    }
                }
                _ => return Err(FetchError::IncompatibleSource),
            }
        }
        if let Some(bytes) = bytes {
            metadata.push(GitGraphObject {
                kind: 2,
                oid: sha1(oid),
                bytes,
            });
        }
    }
    if metadata.len() + blobs.len() + refs.len() > MAX_GRAPH_OBJECTS {
        return Err(FetchError::GraphTooLarge);
    }
    metadata.sort_by_key(|object| object.oid);
    let mut blobs = blobs.into_values().collect::<Vec<_>>();
    blobs.sort_by_key(|blob| blob.oid);
    Ok(FetchIntent {
        format_version,
        fetch_id: Uuid::new_v4(),
        repository_id,
        source_path,
        source_root,
        refs,
        objects: metadata,
        blobs,
    })
}

fn validate_intent(
    intent: &FetchIntent,
    repository_id: Uuid,
    root: &Path,
) -> Result<(), FetchError> {
    if !matches!(intent.format_version, 1 | 2)
        || intent.fetch_id.is_nil()
        || intent.repository_id != repository_id
        || intent.source_root != root
        || !intent.source_path.is_absolute()
        || intent.source_path.starts_with(root)
        || intent.refs.len() + intent.objects.len() + intent.blobs.len() > MAX_GRAPH_OBJECTS
        || intent.format_version == 2 && intent.refs.len() != 1
    {
        return Err(FetchError::IncompatibleSource);
    }
    let mut bytes = 0_usize;
    for reference in &intent.refs {
        let name =
            std::str::from_utf8(&reference.name).map_err(|_| FetchError::IncompatibleSource)?;
        let prefix = if intent.format_version == 1 {
            "refs/remotes/origin/"
        } else {
            "refs/heads/"
        };
        if !name.starts_with(prefix) || !git2::Reference::is_valid_name(name) {
            return Err(FetchError::IncompatibleSource);
        }
        bytes = bytes.saturating_add(reference.name.len() + 20);
    }
    for object in &intent.objects {
        let kind = match object.kind {
            1 => ObjectType::Commit,
            2 => ObjectType::Tree,
            _ => return Err(FetchError::IncompatibleSource),
        };
        if Oid::hash_object(kind, &object.bytes)? != Oid::from_bytes(&object.oid)? {
            return Err(FetchError::IncompatibleSource);
        }
        bytes = bytes.saturating_add(object.bytes.len() + 24);
    }
    if bytes > MAX_GRAPH_METADATA_BYTES {
        return Err(FetchError::GraphTooLarge);
    }
    Ok(())
}

fn validate_symlink(anchor: &FileAnchorManifest) -> Result<(), FetchError> {
    if !(1..=4095).contains(&anchor.logical_len) {
        return Err(FetchError::IncompatibleSource);
    }
    let mut bytes = Vec::with_capacity(anchor.logical_len as usize);
    anchor.open_verified()?.read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.contains(&0) {
        return Err(FetchError::IncompatibleSource);
    }
    Ok(())
}

fn verified_blob(
    blob: &FetchedBlob,
    anchors: &[FileAnchorManifest],
) -> Result<VerifiedBlob, FetchError> {
    if anchors.is_empty() {
        return Err(FetchError::IncompatibleSource);
    }
    let mut verified = Vec::with_capacity(anchors.len());
    for anchor in anchors {
        if anchor.logical_len != blob.logical_len {
            return Err(FetchError::IncompatibleSource);
        }
        if blob.symlink {
            validate_symlink(anchor)?;
        }
        verified.push((anchor.anchor_id, anchor.content_hash));
    }
    verified.sort_by_key(|(anchor_id, _)| *anchor_id);
    Ok(VerifiedBlob {
        format_version: 1,
        oid: blob.oid,
        anchors: verified,
    })
}

fn capture_raw_blob(
    repository_path: &Path,
    oid: Oid,
    len: u64,
    plan: &SourceBlobImportPlan,
) -> Result<FileAnchorManifest, FetchError> {
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(repository_path)
        .arg("cat-file")
        .arg("--batch")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_OBJECT_DIRECTORY")
        .env_remove("GIT_ALTERNATE_OBJECT_DIRECTORIES")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let result = (|| {
        let mut input = child.stdin.take().ok_or(FetchError::IncompatibleSource)?;
        writeln!(input, "{oid}")?;
        drop(input);
        let mut output = BufReader::new(child.stdout.take().ok_or(FetchError::IncompatibleSource)?);
        let mut header = Vec::new();
        for _ in 0..256 {
            let mut byte = [0_u8];
            output.read_exact(&mut byte)?;
            header.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        if header.last() != Some(&b'\n') {
            return Err(FetchError::IncompatibleSource);
        }
        header.pop();
        let header = std::str::from_utf8(&header).map_err(|_| FetchError::IncompatibleSource)?;
        if header != format!("{oid} blob {len}") {
            return Err(FetchError::IncompatibleSource);
        }
        let mut bounded = output.by_ref().take(len);
        let anchor = plan.capture(&mut bounded)?;
        if bounded.limit() != 0 {
            return Err(FetchError::IncompatibleSource);
        }
        let mut delimiter = [0_u8];
        output.read_exact(&mut delimiter)?;
        if delimiter != *b"\n" {
            return Err(FetchError::IncompatibleSource);
        }
        Ok(anchor)
    })();
    if result.is_err() {
        let _ = child.kill();
    }
    let status = child.wait()?;
    if !status.success() {
        return Err(FetchError::IncompatibleSource);
    }
    result
}

fn import_blob(
    control: &ControlStore,
    intent: &FetchIntent,
    blob: &FetchedBlob,
) -> Result<(), FetchError> {
    let oid = Oid::from_bytes(&blob.oid)?;
    let kind = blob_kind(intent.repository_id);
    let verified_kind = verified_kind(intent);
    if let Some(encoded) = control.get_record(&verified_kind, &blob.oid)? {
        let saved: VerifiedBlob = decode_canonical(&encoded)?;
        let anchors = anchors_for_oid(control, intent.repository_id, oid)?;
        if saved.format_version != 1
            || saved != verified_blob(blob, &anchors)?
            || control.get_record(&kind, &blob.oid)?.is_some()
        {
            return Err(FetchError::IncompatibleSource);
        }
        return Ok(());
    }
    let encoded = control.get_record(&kind, &blob.oid)?;
    if encoded.is_none() {
        let existing = anchors_for_oid(control, intent.repository_id, oid)?;
        if !existing.is_empty() {
            let source = source_repository(
                &intent.source_path,
                &intent.source_root,
                intent.format_version,
            )?;
            let verified = verified_blob(blob, &existing)?;
            for anchor in &existing {
                if !super::interop::matches_existing(
                    &source,
                    oid,
                    ObjectType::Blob,
                    blob.logical_len,
                    anchor.open_verified()?,
                )? {
                    return Err(FetchError::IncompatibleSource);
                }
            }
            if !control.put_record_if_absent(
                &verified_kind,
                &blob.oid,
                &canonical_bytes(&verified)?,
            )? {
                return Err(FetchError::PendingFetch);
            }
            return Ok(());
        }
    }
    let (state, encoded) = match encoded {
        Some(bytes) => {
            let state: BlobIntent = decode_canonical(&bytes)?;
            (state, bytes)
        }
        None => {
            let state = BlobIntent {
                format_version: 1,
                repository_id: intent.repository_id,
                oid: blob.oid,
                logical_len: blob.logical_len,
                plan: SourceBlobImportPlan::plan_direct(&intent.source_root, blob.logical_len)?,
            };
            let bytes = canonical_bytes(&state)?;
            if !control.put_record_if_absent(&kind, &blob.oid, &bytes)? {
                return Err(FetchError::PendingFetch);
            }
            (state, bytes)
        }
    };
    if state.format_version != 1
        || state.repository_id != intent.repository_id
        || state.oid != blob.oid
        || state.logical_len != blob.logical_len
        || state.plan.logical_len() != blob.logical_len
        || state.plan.source_root() != intent.source_root
    {
        return Err(FetchError::IncompatibleSource);
    }
    state.plan.reconcile()?;
    let anchor = match state.plan.capture(std::io::empty()) {
        Ok(anchor) => anchor,
        Err(AnchorError::SourceChanged(_)) => {
            source_repository(
                &intent.source_path,
                &intent.source_root,
                intent.format_version,
            )?;
            capture_raw_blob(&intent.source_path, oid, blob.logical_len, &state.plan)?
        }
        Err(error) => return Err(error.into()),
    };
    if blob_oid_from_anchor(&anchor)? != oid {
        return Err(FetchError::IncompatibleSource);
    }
    if blob.symlink {
        validate_symlink(&anchor)?;
    }
    let verified = verified_blob(blob, std::slice::from_ref(&anchor))?;
    control.put_records_and_retire_if_value(
        &[
            (
                object_kind(intent.repository_id, oid),
                anchor.anchor_id.as_bytes().to_vec(),
                canonical_bytes(&anchor)?,
            ),
            (
                verified_kind,
                blob.oid.to_vec(),
                canonical_bytes(&verified)?,
            ),
        ],
        &kind,
        &blob.oid,
        &encoded,
    )?;
    Ok(())
}

/// Fetch every remote branch into `refs/remotes/origin/*`. The selected local
/// branch, index and worktree are unchanged. Blob imports are replayable; refs
/// become visible only when every required native anchor has been published.
pub fn fetch_bare(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    source_path: &Path,
) -> Result<usize, FetchError> {
    if control
        .get_record(&push_kind(repository_id), ACTIVE)?
        .is_some()
    {
        return Err(FetchError::PendingFetch);
    }
    let kind = fetch_kind(repository_id);
    let (intent, encoded) = match control.get_record(&kind, ACTIVE)? {
        Some(bytes) => {
            let intent: FetchIntent = decode_canonical(&bytes)?;
            validate_intent(&intent, repository_id, source_root)?;
            if intent.format_version != 1
                || source_path != intent.source_path
                    && source_path.canonicalize().ok().as_deref()
                        != Some(intent.source_path.as_path())
            {
                return Err(FetchError::PendingFetch);
            }
            (intent, bytes)
        }
        None => {
            let canonical = source_path.canonicalize()?;
            let repository = source_repository(&canonical, source_root, 1)?;
            let intent = discover(
                &repository,
                repository_id,
                canonical,
                source_root.to_owned(),
            )?;
            validate_intent(&intent, repository_id, source_root)?;
            let bytes = canonical_bytes(&intent)?;
            if !control.put_record_if_absent(&kind, ACTIVE, &bytes)? {
                return Err(FetchError::PendingFetch);
            }
            (intent, bytes)
        }
    };
    for blob in &intent.blobs {
        import_blob(control, &intent, blob)?;
    }
    let mut records = Vec::with_capacity(intent.objects.len() + intent.refs.len());
    for object in &intent.objects {
        let kind = match object.kind {
            1 => ObjectType::Commit,
            2 => ObjectType::Tree,
            _ => return Err(FetchError::IncompatibleSource),
        };
        records.push((
            metadata_kind(repository_id),
            object.oid.to_vec(),
            object_record(kind, object.bytes.clone())?,
        ));
    }
    for reference in &intent.refs {
        records.push((
            ref_kind(repository_id),
            reference.name.clone(),
            fetched_ref_record(reference.oid)?,
        ));
    }
    let deletions = intent
        .blobs
        .iter()
        .map(|blob| (verified_kind(&intent), blob.oid.to_vec()))
        .collect::<Vec<_>>();
    control.put_records_and_retire_and_delete_if_value(
        &records, &deletions, &kind, ACTIVE, &encoded,
    )?;
    Ok(intent.refs.len())
}

/// Import one stock Git commit and publish a non-checked-out local branch only
/// after every reachable object and native blob anchor is durable. The
/// expected old ref is bound to the helper's advertisement. A persisted intent
/// replays the same push after a daemon restart.
pub(crate) fn import_pushed_branch(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    source_path: &Path,
    target_branch: &str,
    target_oid: [u8; 20],
    expected_old: Option<[u8; 20]>,
) -> Result<(), FetchError> {
    if target_branch.len() > 1024 || !git2::Branch::name_is_valid(target_branch)? {
        return Err(FetchError::IncompatibleSource);
    }
    if control
        .get_record(&fetch_kind(repository_id), ACTIVE)?
        .is_some()
    {
        return Err(FetchError::PendingFetch);
    }
    let local_ref = format!("refs/heads/{target_branch}");
    let kind = push_kind(repository_id);
    let (intent, encoded) = match control.get_record(&kind, ACTIVE)? {
        Some(bytes) => {
            let pending: PushImportIntent = decode_canonical(&bytes)?;
            validate_intent(&pending.fetch, repository_id, source_root)?;
            if pending.format_version != 1
                || pending.fetch.format_version != 2
                || pending.target_branch != target_branch
                || pending.expected_old != expected_old
                || pending.fetch.refs.len() != 1
                || pending.fetch.refs[0].name != local_ref.as_bytes()
                || pending.fetch.refs[0].oid != target_oid
                || source_path != pending.fetch.source_path
                    && source_path.canonicalize().ok().as_deref()
                        != Some(pending.fetch.source_path.as_path())
            {
                return Err(FetchError::PendingFetch);
            }
            (pending, bytes)
        }
        None => {
            if selected_branch(control, repository_id)? == target_branch
                || linked_selected_branches(control, repository_id)?
                    .iter()
                    .any(|branch| branch == target_branch)
            {
                return Err(FetchError::CheckedOutBranch);
            }
            if ref_oid(control, repository_id, local_ref.as_bytes())?.map(sha1) != expected_old {
                return Err(FetchError::StalePush);
            }
            let canonical = source_path.canonicalize()?;
            let repository = source_repository(&canonical, source_root, 2)?;
            let fetch = discover_from_refs(
                &repository,
                repository_id,
                canonical,
                source_root.to_owned(),
                vec![GitGraphRef {
                    name: local_ref.as_bytes().to_vec(),
                    oid: target_oid,
                }],
                2,
            )?;
            validate_intent(&fetch, repository_id, source_root)?;
            let pending = PushImportIntent {
                format_version: 1,
                target_branch: target_branch.to_owned(),
                expected_old,
                fetch,
            };
            let bytes = canonical_bytes(&pending)?;
            if !control.put_record_if_absent(&kind, ACTIVE, &bytes)? {
                return Err(FetchError::PendingFetch);
            }
            (pending, bytes)
        }
    };
    for blob in &intent.fetch.blobs {
        import_blob(control, &intent.fetch, blob)?;
    }
    let metadata = intent
        .fetch
        .objects
        .iter()
        .map(|object| {
            let kind = match object.kind {
                1 => ObjectType::Commit,
                2 => ObjectType::Tree,
                _ => return Err(FetchError::IncompatibleSource),
            };
            Ok((
                metadata_kind(repository_id),
                object.oid.to_vec(),
                object_record(kind, object.bytes.clone())?,
            ))
        })
        .collect::<Result<Vec<_>, FetchError>>()?;
    control.put_records_and_delete(&metadata, &[])?;
    let new_oid = Oid::from_bytes(&target_oid)?;
    let still_unselected = selected_branch(control, repository_id)? != target_branch
        && !linked_selected_branches(control, repository_id)?
            .iter()
            .any(|branch| branch == target_branch);
    let still_same =
        ref_oid(control, repository_id, local_ref.as_bytes())?.map(sha1) == expected_old;
    let fast_forward = expected_old
        .map(|old| commit_descends_from(control, repository_id, new_oid, Oid::from_bytes(&old)?))
        .transpose()?
        .unwrap_or(true);
    let deletions = intent
        .fetch
        .blobs
        .iter()
        .map(|blob| (verified_kind(&intent.fetch), blob.oid.to_vec()))
        .collect::<Vec<_>>();
    if !still_unselected || !still_same || !fast_forward {
        control.put_records_and_retire_and_delete_if_value(
            &[],
            &deletions,
            &kind,
            ACTIVE,
            &encoded,
        )?;
        return if !still_unselected {
            Err(FetchError::CheckedOutBranch)
        } else if !still_same {
            Err(FetchError::StalePush)
        } else {
            Err(FetchError::NonFastForward)
        };
    }
    control.put_records_and_retire_and_delete_if_value(
        &[(
            ref_kind(repository_id),
            local_ref.into_bytes(),
            fetched_ref_record(target_oid)?,
        )],
        &deletions,
        &kind,
        ACTIVE,
        &encoded,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use mb_store::GIT_CATALOG_DIRECTORY;

    use super::*;
    use crate::GitRepository;

    fn make_remote(path: &Path, bytes: &[u8], mode: i32) -> (Repository, Oid) {
        let remote = Repository::init_bare(path).unwrap();
        let blob = remote.blob(bytes).unwrap();
        let mut builder = remote.treebuilder(None).unwrap();
        builder.insert("tracked", blob, mode).unwrap();
        let tree_oid = builder.write().unwrap();
        let tree = remote.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let commit = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "first",
                &tree,
                &[],
            )
            .unwrap();
        drop(tree);
        drop(builder);
        (remote, commit)
    }

    #[test]
    fn discovery_rejects_gitlinks_before_creating_an_intent() {
        let temp = tempfile::tempdir().unwrap();
        let remote_path = temp.path().join("remote.git");
        let (remote, _) = make_remote(&remote_path, b"ignored", 0o160000);
        assert!(matches!(
            discover(
                &remote,
                Uuid::new_v4(),
                remote_path,
                temp.path().join("work")
            ),
            Err(FetchError::IncompatibleSource)
        ));
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn pushed_branch_replays_after_captured_stock_source_disappears() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-push-replay-{}", Uuid::new_v4()));
        let root = run_root.join("work");
        let stock_root = run_root.join("stock");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [94_u8; 32];
        let local = GitRepository::init(&root, repository_id, &key).unwrap();
        local.stage_file("tracked").unwrap();
        local.commit("Author", "a@example.test", "base").unwrap();
        drop(local);

        let stock = Repository::init(&stock_root).unwrap();
        let payload = b"pushed\r\nraw\0bytes";
        let blob = stock.blob(payload).unwrap();
        let mut builder = stock.treebuilder(None).unwrap();
        builder.insert("tracked", blob, 0o100644).unwrap();
        let tree_oid = builder.write().unwrap();
        let tree = stock.find_tree(tree_oid).unwrap();
        let signature = git2::Signature::now("Stock", "stock@example.test").unwrap();
        let commit = stock
            .commit(None, &signature, &signature, "topic", &tree, &[])
            .unwrap();
        drop(tree);
        drop(builder);
        let git_directory = stock.path().canonicalize().unwrap();
        let fetch = discover_from_refs(
            &stock,
            repository_id,
            git_directory.clone(),
            root.clone(),
            vec![GitGraphRef {
                name: b"refs/heads/topic".to_vec(),
                oid: sha1(commit),
            }],
            2,
        )
        .unwrap();
        assert_eq!(fetch.blobs.len(), 1);
        let pending = PushImportIntent {
            format_version: 1,
            target_branch: "topic".to_owned(),
            expected_old: None,
            fetch,
        };
        let database = root.join(GIT_CATALOG_DIRECTORY).join("catalog.db");
        let control = ControlStore::open_existing_with_key(&database, &key).unwrap();
        control
            .put_record_if_absent(
                &push_kind(repository_id),
                ACTIVE,
                &canonical_bytes(&pending).unwrap(),
            )
            .unwrap();
        import_blob(&control, &pending.fetch, &pending.fetch.blobs[0]).unwrap();
        assert!(has_pending_fetch(&control, repository_id).unwrap());
        drop(control);
        drop(stock);
        fs::remove_dir_all(&stock_root).unwrap();

        let control = ControlStore::open_existing_with_key(&database, &key).unwrap();
        import_pushed_branch(
            &control,
            repository_id,
            &root,
            &git_directory,
            "topic",
            sha1(commit),
            None,
        )
        .unwrap();
        assert!(!has_pending_fetch(&control, repository_id).unwrap());
        drop(control);
        let local = GitRepository::open(&root, repository_id, &key).unwrap();
        local.switch_branch("topic").unwrap();
        assert_eq!(fs::read(root.join("tracked")).unwrap(), payload);
        let graph = local.export_graph_source().unwrap();
        drop(local);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn published_anchor_replays_after_source_disappears() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-fetch-replay-{}", Uuid::new_v4()));
        let root = run_root.join("work");
        let remote_path = run_root.join("remote.git");
        fs::create_dir_all(&root).unwrap();
        let payload = b"raw\r\nblob\0bytes";
        let (remote, first_commit) = make_remote(&remote_path, payload, 0o100644);
        let second_blob = remote.blob(b"another\nblob").unwrap();
        let mut builder = remote.treebuilder(None).unwrap();
        builder.insert("second", second_blob, 0o100644).unwrap();
        let second_tree_oid = builder.write().unwrap();
        let second_tree = remote.find_tree(second_tree_oid).unwrap();
        let parent = remote.find_commit(first_commit).unwrap();
        let signature = git2::Signature::now("Remote", "remote@example.invalid").unwrap();
        let commit = remote
            .commit(
                Some("refs/heads/main"),
                &signature,
                &signature,
                "second",
                &second_tree,
                &[&parent],
            )
            .unwrap();
        drop(second_tree);
        drop(parent);
        drop(builder);
        let repository_id = Uuid::new_v4();
        let key = [87_u8; 32];
        let local = GitRepository::init(&root, repository_id, &key).unwrap();
        drop(local);
        let catalog_path = root.join(GIT_CATALOG_DIRECTORY).join("catalog.db");
        let control = ControlStore::open_existing_with_key(&catalog_path, &key).unwrap();
        let intent = discover(&remote, repository_id, remote_path.clone(), root.clone()).unwrap();
        assert_eq!(intent.blobs.len(), 2);
        control
            .put_record_if_absent(
                &fetch_kind(repository_id),
                ACTIVE,
                &canonical_bytes(&intent).unwrap(),
            )
            .unwrap();
        import_blob(&control, &intent, &intent.blobs[0]).unwrap();
        assert_eq!(control.records(&verified_kind(&intent)).unwrap().len(), 1);
        let blob = &intent.blobs[1];
        let plan = SourceBlobImportPlan::plan_direct(&root, blob.logical_len).unwrap();
        let blob_intent = BlobIntent {
            format_version: 1,
            repository_id,
            oid: blob.oid,
            logical_len: blob.logical_len,
            plan: plan.clone(),
        };
        control
            .put_record_if_absent(
                &blob_kind(repository_id),
                &blob.oid,
                &canonical_bytes(&blob_intent).unwrap(),
            )
            .unwrap();
        let anchor = capture_raw_blob(
            &remote_path,
            Oid::from_bytes(&blob.oid).unwrap(),
            blob.logical_len,
            &plan,
        )
        .unwrap();
        drop(control);
        drop(remote);
        fs::remove_dir_all(&remote_path).unwrap();

        let local = GitRepository::open(&root, repository_id, &key).unwrap();
        assert_eq!(local.fetch_bare(&remote_path).unwrap(), 1);
        let graph = local.export_graph_source().unwrap();
        assert_eq!(graph.refs[0].oid.as_slice(), commit.as_bytes());
        assert_eq!(graph.blobs.len(), 2);
        assert!(
            graph
                .blobs
                .iter()
                .any(|item| item.anchor.anchor_id == anchor.anchor_id)
        );
        drop(local);
        let control = ControlStore::open_existing_with_key(&catalog_path, &key).unwrap();
        assert!(control.records(&verified_kind(&intent)).unwrap().is_empty());
        drop(control);
        for item in graph.blobs {
            item.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }
}
