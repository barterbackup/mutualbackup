//! Crash-replayable Git staging over the daemon's encrypted local catalog.
//!
//! The caller provides a single-writer `ControlStore`, normally opened under
//! the repository's app-owned `.mutualbackup` catalog. Each add first persists
//! a source-capture intent. One SQL transaction then publishes the index entry
//! and object-to-anchor mapping while retiring that intent.

use std::ffi::OsStr;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use git2::Oid;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, SourceFileCapturePlan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{GitAnchorError, blob_oid_from_anchor};

const MAX_STAGE_PATH_BYTES: usize = 4096;
const INTENT_PREFIX: &str = "git-stage-intent-v1/";
const INDEX_PREFIX: &str = "git-index-entry-v1/";
const OBJECT_PREFIX: &str = "git-object-anchor-v1/";

#[derive(Debug, Error)]
pub enum StageError {
    #[error("source anchor error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("encrypted catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("Git object error: {0}")]
    Git(#[from] GitAnchorError),
    #[error("versioned local metadata error: {0}")]
    Model(#[from] ModelError),
    #[error("a pending add already owns this path; replay or abandon it first")]
    PendingStage,
    #[error("the missing path is not staged in the index")]
    MissingUntrackedPath,
    #[error("the staged path is unsafe, reserved, or exceeds the local path bound")]
    UnsafePath,
    #[error("the stage intent or index record is incompatible or corrupt")]
    IncompatibleRecord,
    #[error("Git stage catalog paths currently require Linux byte paths")]
    UnsupportedPlatform,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitIndexEntry {
    pub format_version: u16,
    pub oid: [u8; 20],
    pub mode: u32,
    pub anchor_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StageIntent {
    format_version: u16,
    repository_id: Uuid,
    relative_path: PathBuf,
    git_mode: u32,
    plan: SourceFileCapturePlan,
}

fn intent_kind(repository_id: Uuid) -> String {
    format!("{INTENT_PREFIX}{repository_id}")
}

pub(crate) fn index_kind(repository_id: Uuid) -> String {
    format!("{INDEX_PREFIX}{repository_id}")
}

pub(crate) fn object_kind(repository_id: Uuid, oid: Oid) -> String {
    format!("{OBJECT_PREFIX}{repository_id}/{oid}")
}

pub(crate) fn stage_path_key(path: &Path) -> Result<Vec<u8>, StageError> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        || matches!(
            path.components().next(),
            Some(Component::Normal(name))
                if name == OsStr::new(".mutualbackup") || name == OsStr::new(".git")
        )
    {
        return Err(StageError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let bytes = path.as_os_str().as_bytes();
        let normalized = path.components().collect::<PathBuf>();
        if normalized.as_os_str().as_bytes() != bytes {
            return Err(StageError::UnsafePath);
        }
        if bytes.len() > MAX_STAGE_PATH_BYTES {
            return Err(StageError::UnsafePath);
        }
        Ok(bytes.to_vec())
    }
    #[cfg(not(unix))]
    {
        Err(StageError::UnsupportedPlatform)
    }
}

fn decode_intent(
    encoded: &[u8],
    repository_id: Uuid,
    path_key: &[u8],
) -> Result<StageIntent, StageError> {
    let intent: StageIntent = decode_canonical(encoded)?;
    if intent.format_version != 1
        || intent.repository_id != repository_id
        || stage_path_key(&intent.relative_path)? != path_key
        || intent.plan.relative_path() != intent.relative_path
        || !matches!(intent.git_mode, 0o100644 | 0o100755)
    {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(intent)
}

fn begin_stage(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    relative_path: &Path,
) -> Result<(Vec<u8>, StageIntent), StageError> {
    let path_key = stage_path_key(relative_path)?;
    let kind = intent_kind(repository_id);
    if control.get_record(&kind, &path_key)?.is_some() {
        return Err(StageError::PendingStage);
    }
    let plan = SourceFileCapturePlan::plan_reflink(source_root, relative_path)?;
    let mode = if plan.source_mode()? & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    };
    let intent = StageIntent {
        format_version: 1,
        repository_id,
        relative_path: relative_path.to_path_buf(),
        git_mode: mode,
        plan,
    };
    let encoded = canonical_bytes(&intent)?;
    if !control.put_record_if_absent(&kind, &path_key, &encoded)? {
        return Err(StageError::PendingStage);
    }
    Ok((path_key, intent))
}

fn finish_stage(
    control: &ControlStore,
    repository_id: Uuid,
    path_key: &[u8],
    intent: &StageIntent,
) -> Result<GitIndexEntry, StageError> {
    let kind = intent_kind(repository_id);
    let expected = canonical_bytes(intent)?;
    if control.get_record(&kind, path_key)?.as_deref() != Some(expected.as_slice()) {
        return Err(StageError::IncompatibleRecord);
    }
    let manifest = intent.plan.capture()?;
    let oid = blob_oid_from_anchor(&manifest)?;
    intent.plan.reconcile()?;
    let entry = GitIndexEntry {
        format_version: 1,
        oid: oid.as_bytes().try_into().expect("SHA-1 OID has 20 bytes"),
        mode: intent.git_mode,
        anchor_id: manifest.anchor_id,
    };
    control.put_records_and_retire_if_value(
        &[
            (
                object_kind(repository_id, oid),
                manifest.anchor_id.as_bytes().to_vec(),
                canonical_bytes(&manifest)?,
            ),
            (
                index_kind(repository_id),
                path_key.to_vec(),
                canonical_bytes(&entry)?,
            ),
        ],
        &kind,
        path_key,
        &expected,
    )?;
    Ok(entry)
}

/// Stage an exact regular-file snapshot. The caller must serialize writes to
/// this repository's catalog; a failed add keeps a replayable intent.
pub fn stage_file(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Result<GitIndexEntry, StageError> {
    let (key, intent) = begin_stage(
        control,
        repository_id,
        source_root.as_ref(),
        relative_path.as_ref(),
    )?;
    finish_stage(control, repository_id, &key, &intent)
}

/// Remove a path from the staged index while leaving its working file alone,
/// matching Git's `rm --cached` behavior. The catalog delete is atomic; old
/// immutable anchors stay available to commits on other branches.
pub fn remove_cached(
    control: &ControlStore,
    repository_id: Uuid,
    relative_path: impl AsRef<Path>,
) -> Result<bool, StageError> {
    let key = stage_path_key(relative_path.as_ref())?;
    if control
        .get_record(&intent_kind(repository_id), &key)?
        .is_some()
    {
        return Err(StageError::PendingStage);
    }
    let kind = index_kind(repository_id);
    let Some(encoded) = control.get_record(&kind, &key)? else {
        return Ok(false);
    };
    let entry: GitIndexEntry = decode_canonical(&encoded)?;
    if entry.format_version != 1 || !matches!(entry.mode, 0o100644 | 0o100755) {
        return Err(StageError::IncompatibleRecord);
    }
    control.delete_record_if_value(&kind, &key, &encoded)?;
    Ok(true)
}

/// Finish all pending adds after a daemon restart. A changed source with no
/// captured anchor remains pending for explicit abandonment by the owner.
pub fn resume_pending_stages(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<GitIndexEntry>, StageError> {
    let mut resumed = Vec::new();
    for (key, encoded) in control.records(&intent_kind(repository_id))? {
        let intent = decode_intent(&encoded, repository_id, &key)?;
        resumed.push(finish_stage(control, repository_id, &key, &intent)?);
    }
    Ok(resumed)
}

/// Explicitly discard an unresolved add without changing an existing index.
pub fn abandon_pending_stage(
    control: &ControlStore,
    repository_id: Uuid,
    relative_path: impl AsRef<Path>,
) -> Result<bool, StageError> {
    let key = stage_path_key(relative_path.as_ref())?;
    let kind = intent_kind(repository_id);
    let Some(encoded) = control.get_record(&kind, &key)? else {
        return Ok(false);
    };
    let intent = decode_intent(&encoded, repository_id, &key)?;
    intent.plan.discard()?;
    control.delete_record_if_value(&kind, &key, &encoded)?;
    Ok(true)
}

pub fn staged_entry(
    control: &ControlStore,
    repository_id: Uuid,
    relative_path: impl AsRef<Path>,
) -> Result<Option<GitIndexEntry>, StageError> {
    let key = stage_path_key(relative_path.as_ref())?;
    let Some(encoded) = control.get_record(&index_kind(repository_id), &key)? else {
        return Ok(None);
    };
    let entry: GitIndexEntry = decode_canonical(&encoded)?;
    if entry.format_version != 1 || !matches!(entry.mode, 0o100644 | 0o100755) {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(Some(entry))
}

/// Enumerate the staged snapshot in Git's bytewise path order. These are raw
/// repository-relative path bytes, so a future non-UTF-8 wire encoding need not
/// reinterpret the index keys.
pub fn staged_entries(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<(Vec<u8>, GitIndexEntry)>, StageError> {
    let mut entries = Vec::new();
    for (key, encoded) in control.records(&index_kind(repository_id))? {
        #[cfg(unix)]
        {
            let path = PathBuf::from(std::ffi::OsString::from_vec(key.clone()));
            if stage_path_key(&path)? != key {
                return Err(StageError::IncompatibleRecord);
            }
        }
        #[cfg(not(unix))]
        return Err(StageError::UnsupportedPlatform);
        let entry: GitIndexEntry = decode_canonical(&encoded)?;
        if entry.format_version != 1 || !matches!(entry.mode, 0o100644 | 0o100755) {
            return Err(StageError::IncompatibleRecord);
        }
        entries.push((key, entry));
    }
    Ok(entries)
}

pub fn has_pending_stages(control: &ControlStore, repository_id: Uuid) -> Result<bool, StageError> {
    Ok(!control.records(&intent_kind(repository_id))?.is_empty())
}

pub fn pending_stage_paths(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<Vec<u8>>, StageError> {
    let mut paths = Vec::new();
    for (key, encoded) in control.records(&intent_kind(repository_id))? {
        decode_intent(&encoded, repository_id, &key)?;
        paths.push(key);
    }
    Ok(paths)
}

/// Resolve all physical anchors for a Git blob ID, verifying both the native
/// content root and the Git object ID before the caller reads them.
pub fn anchors_for_oid(
    control: &ControlStore,
    repository_id: Uuid,
    oid: Oid,
) -> Result<Vec<FileAnchorManifest>, StageError> {
    let mut anchors = Vec::new();
    for (key, encoded) in control.records(&object_kind(repository_id, oid))? {
        let manifest: FileAnchorManifest = decode_canonical(&encoded)?;
        if key != manifest.anchor_id.as_bytes()
            || manifest.format_version != 1
            || blob_oid_from_anchor(&manifest)? != oid
        {
            return Err(StageError::IncompatibleRecord);
        }
        anchors.push(manifest);
    }
    Ok(anchors)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::{fs, path::PathBuf};

    use mb_store::{AnchorError, ControlStore};
    use uuid::Uuid;

    use super::{
        StageError, abandon_pending_stage, anchors_for_oid, begin_stage, resume_pending_stages,
        stage_file, staged_entry,
    };

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn stage_index_and_object_map_replay_after_capture_and_reopen() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-stage-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        fs::create_dir_all(&source_root).unwrap();
        let control_path = run_root.join("catalog.db");
        let key = [13_u8; 32];
        let repository_id = Uuid::new_v4();
        let file = source_root.join("tracked");
        fs::write(&file, b"first\r\nbytes\0").unwrap();
        let control = ControlStore::open_with_key(&control_path, &key).unwrap();
        let (path_key, intent) =
            begin_stage(&control, repository_id, &source_root, "tracked".as_ref()).unwrap();
        assert_eq!(path_key, b"tracked");
        let captured = intent.plan.capture().unwrap();
        fs::write(&file, b"second\nbytes").unwrap();
        drop(control);

        let control = ControlStore::open_with_key(&control_path, &key).unwrap();
        let resumed = resume_pending_stages(&control, repository_id).unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].mode, 0o100644);
        assert_eq!(resumed[0].anchor_id, captured.anchor_id);
        assert_eq!(
            staged_entry(&control, repository_id, "tracked")
                .unwrap()
                .unwrap(),
            resumed[0]
        );
        let first_oid = git2::Oid::from_bytes(&resumed[0].oid).unwrap();
        let first_anchors = anchors_for_oid(&control, repository_id, first_oid).unwrap();
        assert_eq!(first_anchors, vec![captured.clone()]);
        assert!(
            resume_pending_stages(&control, repository_id)
                .unwrap()
                .is_empty()
        );

        fs::set_permissions(&file, fs::Permissions::from_mode(0o755)).unwrap();
        let second = stage_file(&control, repository_id, &source_root, "tracked").unwrap();
        assert_eq!(second.mode, 0o100755);
        assert_ne!(second.oid, resumed[0].oid);
        assert_ne!(second.anchor_id, resumed[0].anchor_id);
        assert_eq!(
            anchors_for_oid(&control, repository_id, first_oid)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            staged_entry(&control, repository_id, "tracked")
                .unwrap()
                .unwrap(),
            second
        );
        assert!(!abandon_pending_stage(&control, repository_id, "tracked").unwrap());
        let second_oid = git2::Oid::from_bytes(&second.oid).unwrap();
        let second_anchors = anchors_for_oid(&control, repository_id, second_oid).unwrap();

        fs::write(source_root.join("pending"), b"before edit").unwrap();
        begin_stage(&control, repository_id, &source_root, "pending".as_ref()).unwrap();
        fs::write(source_root.join("pending"), b"after edit").unwrap();
        assert!(matches!(
            resume_pending_stages(&control, repository_id),
            Err(StageError::Anchor(AnchorError::SourceChanged(_)))
        ));
        assert!(abandon_pending_stage(&control, repository_id, "pending").unwrap());
        assert!(
            staged_entry(&control, repository_id, "pending")
                .unwrap()
                .is_none()
        );
        drop(control);
        captured.remove().unwrap();
        second_anchors[0].remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }
}
