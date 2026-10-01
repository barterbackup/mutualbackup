//! Local Git interoperability through a standard bare repository. The target
//! Git repository owns its own object storage; this source repository does not
//! create a second persistent blob store.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use git2::{ObjectFormat, ObjectType, Oid, Repository};
use thiserror::Error;

use crate::GitAnchorError;
use crate::history::{GitGraphSource, HistoryError, export_graph_source};
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
    #[error(
        "the destination must be an existing SHA-1 bare Git repository outside this source root"
    )]
    UnsupportedDestination,
    #[error("the current branch has no committed head")]
    NoHead,
    #[error("the destination branch has diverged; a force push is not supported")]
    NonFastForward,
    #[error(
        "the destination contains an object ID with different bytes or cannot stream it for verification"
    )]
    ObjectConflict,
    #[error("the exported graph contains an incompatible object or reference")]
    IncompatibleGraph,
}

fn object_type(kind: u8) -> Result<ObjectType, GitInteropError> {
    match kind {
        1 => Ok(ObjectType::Commit),
        2 => Ok(ObjectType::Tree),
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
    if graph.format_version != 1 || graph.repository_id != repository_id {
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
