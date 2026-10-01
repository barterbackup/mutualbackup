//! Local Git interoperability through a standard bare repository. The target
//! Git repository owns its own object storage; this source repository does not
//! create a second persistent blob store.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use git2::{ObjectFormat, ObjectType, Oid, Repository};
use thiserror::Error;

use crate::GitAnchorError;
use crate::history::{
    GitBranchInfo, GitGraphSource, GitTagInfo, HistoryError, export_graph_source,
};
use mb_store::{ControlStore, FileAnchorManifest};
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum GitInteropError {
    #[error("Git history cannot be exported: {0}")]
    History(#[from] HistoryError),
    #[error("native Git blob is unavailable or corrupt: {0}")]
    Anchor(#[from] GitAnchorError),
    #[error("Git library rejected the destination: {0}")]
    Git(#[from] git2::Error),
    #[error("Git object streaming failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("the destination must be an existing SHA-1 Git repository outside this source root")]
    UnsupportedDestination,
    #[error("the current branch has no committed head")]
    NoHead,
    #[error("the destination branch has diverged; a force push is not supported")]
    NonFastForward,
    #[error("the destination tag exists at another object; moving a tag is not supported")]
    TagExists,
    #[error("the requested local tag does not exist")]
    TagNotFound,
    #[error(
        "the destination contains an object ID with different bytes or cannot stream it for verification"
    )]
    ObjectConflict,
    #[error("the exported graph contains an incompatible object or reference")]
    IncompatibleGraph,
    #[error("Git refs changed since the remote helper advertised them")]
    StaleAdvertisement,
}

fn object_type(kind: u8) -> Result<ObjectType, GitInteropError> {
    match kind {
        1 => Ok(ObjectType::Commit),
        2 => Ok(ObjectType::Tree),
        3 => Ok(ObjectType::Tag),
        _ => Err(GitInteropError::IncompatibleGraph),
    }
}

pub(crate) fn matches_existing<R: Read>(
    repository: &Repository,
    oid: Oid,
    kind: ObjectType,
    size: u64,
    mut expected: R,
) -> Result<bool, GitInteropError> {
    let odb = repository.odb()?;
    if let Ok((mut existing, existing_size, existing_kind)) = odb.reader(oid) {
        if existing_kind != kind || existing_size as u64 != size {
            return Ok(false);
        }
        return compare_bytes(&mut existing, &mut expected, size);
    }
    matches_packed_with_stock_git(repository, oid, kind, size, expected)
}

fn compare_bytes(
    actual: &mut impl Read,
    expected: &mut impl Read,
    size: u64,
) -> Result<bool, GitInteropError> {
    let mut left = [0_u8; 64 * 1024];
    let mut right = [0_u8; 64 * 1024];
    let mut remaining = size;
    while remaining != 0 {
        let count = usize::try_from(remaining.min(left.len() as u64))
            .expect("bounded comparison chunk fits usize");
        actual.read_exact(&mut left[..count])?;
        expected.read_exact(&mut right[..count])?;
        if left[..count] != right[..count] {
            return Ok(false);
        }
        remaining -= count as u64;
    }
    Ok(true)
}

fn matches_packed_with_stock_git(
    repository: &Repository,
    oid: Oid,
    kind: ObjectType,
    size: u64,
    mut expected: impl Read,
) -> Result<bool, GitInteropError> {
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(repository.path())
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
        let mut input = child.stdin.take().ok_or(GitInteropError::ObjectConflict)?;
        writeln!(input, "{oid}")?;
        drop(input);
        let mut output =
            std::io::BufReader::new(child.stdout.take().ok_or(GitInteropError::ObjectConflict)?);
        let mut header = Vec::new();
        let mut ended = false;
        for _ in 0..256 {
            let mut byte = [0_u8];
            output.read_exact(&mut byte)?;
            if byte[0] == b'\n' {
                ended = true;
                break;
            }
            header.push(byte[0]);
        }
        if !ended {
            return Err(GitInteropError::ObjectConflict);
        }
        let header = std::str::from_utf8(&header).map_err(|_| GitInteropError::ObjectConflict)?;
        let mut parts = header.split(' ');
        let kind_name = match kind {
            ObjectType::Blob => "blob",
            ObjectType::Tree => "tree",
            ObjectType::Commit => "commit",
            ObjectType::Tag => "tag",
            _ => return Err(GitInteropError::IncompatibleGraph),
        };
        let oid_text = oid.to_string();
        if parts.next() != Some(oid_text.as_str())
            || parts.next() != Some(kind_name)
            || parts.next().and_then(|value| value.parse::<u64>().ok()) != Some(size)
            || parts.next().is_some()
        {
            return Err(GitInteropError::ObjectConflict);
        }
        if !compare_bytes(&mut output, &mut expected, size)? {
            return Ok(false);
        }
        let mut terminator = [0_u8];
        output.read_exact(&mut terminator)?;
        Ok(terminator[0] == b'\n')
    })();
    if !matches!(result, Ok(true)) {
        let _ = child.kill();
    }
    let status = child.wait()?;
    if !status.success() && matches!(result, Ok(true)) {
        return Err(GitInteropError::ObjectConflict);
    }
    result
}

fn publish_object<R: Read>(
    repository: &Repository,
    oid: Oid,
    kind: ObjectType,
    size: u64,
    mut bytes: R,
) -> Result<(), GitInteropError> {
    let odb = repository.odb()?;
    if odb.exists(oid) {
        return if matches_existing(repository, oid, kind, size, bytes)? {
            Ok(())
        } else {
            Err(GitInteropError::ObjectConflict)
        };
    }
    let length = usize::try_from(size).map_err(|_| GitInteropError::IncompatibleGraph)?;
    let mut writer = odb.writer(length, kind)?;
    let copied = std::io::copy(&mut bytes, &mut writer)?;
    if copied != size || writer.finalize()? != oid {
        return Err(GitInteropError::ObjectConflict);
    }
    Ok(())
}

fn export_objects(destination: &Repository, graph: &GitGraphSource) -> Result<(), GitInteropError> {
    for blob in &graph.blobs {
        let oid = Oid::from_bytes(&blob.oid)?;
        let anchor: &FileAnchorManifest = &blob.anchor;
        let source = anchor.open_verified().map_err(GitAnchorError::from)?;
        publish_object(
            destination,
            oid,
            ObjectType::Blob,
            anchor.logical_len,
            source,
        )?;
    }
    for object in &graph.objects {
        let oid = Oid::from_bytes(&object.oid)?;
        publish_object(
            destination,
            oid,
            object_type(object.kind)?,
            object.bytes.len() as u64,
            object.bytes.as_slice(),
        )?;
    }
    Ok(())
}

/// Write the advertised graph into an existing stock Git object database.
/// The stock Git caller owns these objects; this repository keeps only native
/// anchors and does not create a Git-format payload mirror.
pub(crate) fn export_graph_to_git_repository(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    destination_path: &Path,
    advertised: &[GitBranchInfo],
    advertised_tags: Option<&[GitTagInfo]>,
) -> Result<u32, GitInteropError> {
    let destination_path = destination_path.canonicalize()?;
    if destination_path.starts_with(source_root) {
        return Err(GitInteropError::UnsupportedDestination);
    }
    let destination = Repository::open(&destination_path)?;
    if destination.path().canonicalize()? != destination_path
        || destination.object_format() != ObjectFormat::Sha1
    {
        return Err(GitInteropError::UnsupportedDestination);
    }
    let graph = export_graph_source(control, repository_id)?;
    if !matches!(graph.format_version, 1 | 2) || graph.repository_id != repository_id {
        return Err(GitInteropError::IncompatibleGraph);
    }
    let actual = graph
        .refs
        .iter()
        .filter_map(|reference| {
            reference
                .name
                .strip_prefix(b"refs/heads/")
                .map(|name| (name.to_vec(), reference.oid))
        })
        .collect::<BTreeMap<_, _>>();
    let mut expected = BTreeMap::new();
    for branch in advertised {
        if branch.format_version != 1
            || branch.repository_id != repository_id
            || !git2::Branch::name_is_valid(&branch.name)?
            || expected
                .insert(branch.name.as_bytes().to_vec(), branch.oid)
                .is_some()
        {
            return Err(GitInteropError::StaleAdvertisement);
        }
    }
    if actual != expected {
        return Err(GitInteropError::StaleAdvertisement);
    }
    if let Some(advertised_tags) = advertised_tags {
        let actual_tags = graph
            .refs
            .iter()
            .filter_map(|reference| {
                reference
                    .name
                    .strip_prefix(b"refs/tags/")
                    .map(|name| (name.to_vec(), reference.oid))
            })
            .collect::<BTreeMap<_, _>>();
        let mut expected_tags = BTreeMap::new();
        for tag in advertised_tags {
            let reference = format!("refs/tags/{}", tag.name);
            if tag.format_version != 1
                || tag.repository_id != repository_id
                || !git2::Reference::is_valid_name(&reference)
                || expected_tags
                    .insert(tag.name.as_bytes().to_vec(), tag.oid)
                    .is_some()
            {
                return Err(GitInteropError::StaleAdvertisement);
            }
        }
        if actual_tags != expected_tags {
            return Err(GitInteropError::StaleAdvertisement);
        }
    }
    export_objects(&destination, &graph)?;
    u32::try_from(graph.blobs.len() + graph.objects.len())
        .map_err(|_| GitInteropError::IncompatibleGraph)
}

fn source_descends_from(
    graph: &GitGraphSource,
    target: Oid,
    old: Oid,
) -> Result<bool, GitInteropError> {
    let temporary = tempfile::tempdir()?;
    let repository = Repository::init_bare(temporary.path())?;
    let odb = git2::Odb::new()?;
    let _memory = odb.add_new_mempack_backend(1000)?;
    repository.set_odb(&odb)?;
    for object in &graph.objects {
        if object.kind == 1
            && odb.write(ObjectType::Commit, &object.bytes)? != Oid::from_bytes(&object.oid)?
        {
            return Err(GitInteropError::IncompatibleGraph);
        }
    }
    if repository.find_commit(old).is_err() {
        return Ok(false);
    }
    Ok(repository.graph_descendant_of(target, old)?)
}

/// Push the selected branch to an existing bare Git repository. Objects are
/// streamed from native anchors and verified before its ref can advance.
pub fn push_current_branch_to_bare(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    destination_path: &Path,
    branch: &str,
) -> Result<Oid, GitInteropError> {
    let destination_path = destination_path.canonicalize()?;
    if destination_path.starts_with(source_root) {
        return Err(GitInteropError::UnsupportedDestination);
    }
    let destination = Repository::open_bare(&destination_path)?;
    if !destination.is_bare() || destination.object_format() != ObjectFormat::Sha1 {
        return Err(GitInteropError::UnsupportedDestination);
    }
    let graph = export_graph_source(control, repository_id)?;
    if !matches!(graph.format_version, 1 | 2) || graph.repository_id != repository_id {
        return Err(GitInteropError::IncompatibleGraph);
    }
    let reference_name = format!("refs/heads/{branch}");
    let selected = graph
        .refs
        .iter()
        .find(|reference| reference.name == reference_name.as_bytes())
        .ok_or(GitInteropError::NoHead)?;
    let target = Oid::from_bytes(&selected.oid)?;
    let previous = match destination.find_reference(&reference_name) {
        Ok(reference) => Some(
            reference
                .target()
                .ok_or(GitInteropError::IncompatibleGraph)?,
        ),
        Err(error) if error.code() == git2::ErrorCode::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(old) = previous
        && old != target
        && !source_descends_from(&graph, target, old)?
    {
        return Err(GitInteropError::NonFastForward);
    }
    export_objects(&destination, &graph)?;
    if let Some(old) = previous {
        if old == target {
            return Ok(target);
        }
        if !destination.graph_descendant_of(target, old)? {
            return Err(GitInteropError::NonFastForward);
        }
        destination.reference_matching(&reference_name, target, true, old, "mutualgit push")?;
    } else {
        destination.reference(&reference_name, target, false, "mutualgit push")?;
    }
    Ok(target)
}

/// Export a reachable native tag graph and create its stock Git ref. Existing
/// tags may be verified and repeated, but never moved or deleted here.
pub fn push_tag_to_bare(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    destination_path: &Path,
    name: &str,
) -> Result<Oid, GitInteropError> {
    let reference_name = format!("refs/tags/{name}");
    if name.is_empty() || name.len() > 1024 || !git2::Reference::is_valid_name(&reference_name) {
        return Err(GitInteropError::IncompatibleGraph);
    }
    let destination_path = destination_path.canonicalize()?;
    if destination_path.starts_with(source_root) {
        return Err(GitInteropError::UnsupportedDestination);
    }
    let destination = Repository::open_bare(&destination_path)?;
    if !destination.is_bare() || destination.object_format() != ObjectFormat::Sha1 {
        return Err(GitInteropError::UnsupportedDestination);
    }
    let graph = export_graph_source(control, repository_id)?;
    if !matches!(graph.format_version, 1 | 2) || graph.repository_id != repository_id {
        return Err(GitInteropError::IncompatibleGraph);
    }
    let selected = graph
        .refs
        .iter()
        .find(|reference| reference.name == reference_name.as_bytes())
        .ok_or(GitInteropError::TagNotFound)?;
    let target = Oid::from_bytes(&selected.oid)?;
    let previous = match destination.find_reference(&reference_name) {
        Ok(reference) => Some(
            reference
                .target()
                .ok_or(GitInteropError::IncompatibleGraph)?,
        ),
        Err(error) if error.code() == git2::ErrorCode::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if previous.is_some_and(|old| old != target) {
        return Err(GitInteropError::TagExists);
    }
    export_objects(&destination, &graph)?;
    if let Some(old) = previous {
        destination.reference_matching(&reference_name, target, true, old, "mutualgit push tag")?;
    } else {
        destination.reference(&reference_name, target, false, "mutualgit push tag")?;
    }
    Ok(target)
}
