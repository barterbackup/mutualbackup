//! Crash-replayable Git staging over the daemon's encrypted local catalog.
//!
//! The caller provides a single-writer `ControlStore`, normally opened under
//! the repository's app-owned `.mutualbackup` catalog. Each add first persists
//! a source-capture intent. One SQL transaction then publishes the index entry
//! and object-to-anchor mapping while retiring that intent.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use git2::Oid;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, GIT_CATALOG_DIRECTORY,
    NativeFileId, PinnedDirectory, SourceBackendKind, SourceFileCapturePlan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::attributes::{is_attributes_path, validate_anchor, validate_worktree_path};
use crate::{GitAnchorError, GitWorktreeScope, blob_oid_from_anchor};

const MAX_STAGE_PATH_BYTES: usize = 4096;
const INTENT_PREFIX: &str = "git-stage-intent-v1/";
const SYMLINK_INTENT_PREFIX: &str = "git-symlink-stage-intent-v1/";
const INDEX_PREFIX: &str = "git-index-entry-v1/";
const WORKTREE_STAGE_INTENT_PREFIX: &str = "git-worktree-stage-intent-v1/";
const WORKTREE_SYMLINK_INTENT_PREFIX: &str = "git-worktree-symlink-stage-intent-v1/";
const WORKTREE_INDEX_PREFIX: &str = "git-worktree-index-entry-v1/";
const OBJECT_PREFIX: &str = "git-object-anchor-v1/";

#[cfg(test)]
thread_local! {
    static AFTER_MISSING_STAGE_DISCARD: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_missing_stage_discard_hook(hook: Box<dyn FnOnce()>) {
    AFTER_MISSING_STAGE_DISCARD.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_missing_stage_discard_hook() {
    #[cfg(test)]
    AFTER_MISSING_STAGE_DISCARD.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

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
    #[error("a pending add or removal already owns this path; resolve it first")]
    PendingStage,
    #[error("the missing path is not staged in the index")]
    MissingUntrackedPath,
    #[error("the staged path is unsafe, reserved, or exceeds the local path bound")]
    UnsafePath,
    #[error("the stage intent or index record is incompatible or corrupt")]
    IncompatibleRecord,
    #[error("Git stage catalog paths currently require Linux byte paths")]
    UnsupportedPlatform,
    #[error("staged symlink temporary file I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Git attributes policy error: {0}")]
    Attributes(#[from] crate::GitAttributesError),
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SymlinkStageIntent {
    format_version: u16,
    repository_id: Uuid,
    source_root: PathBuf,
    root_id: NativeFileId,
    catalog_id: NativeFileId,
    relative_path: PathBuf,
    source_id: NativeFileId,
    target: Vec<u8>,
    temp_name: String,
    temp_id: Option<NativeFileId>,
    plan: Option<SourceFileCapturePlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    catalog_root: Option<PathBuf>,
}

// Canonical CBOR encodes struct fields as a sequence. A new trailing field
// therefore needs an explicit decoder for intents written by older versions.
#[derive(Serialize, Deserialize)]
struct SymlinkStageIntentV1 {
    format_version: u16,
    repository_id: Uuid,
    source_root: PathBuf,
    root_id: NativeFileId,
    catalog_id: NativeFileId,
    relative_path: PathBuf,
    source_id: NativeFileId,
    target: Vec<u8>,
    temp_name: String,
    temp_id: Option<NativeFileId>,
    plan: Option<SourceFileCapturePlan>,
}

impl From<SymlinkStageIntentV1> for SymlinkStageIntent {
    fn from(old: SymlinkStageIntentV1) -> Self {
        Self {
            format_version: old.format_version,
            repository_id: old.repository_id,
            source_root: old.source_root,
            root_id: old.root_id,
            catalog_id: old.catalog_id,
            relative_path: old.relative_path,
            source_id: old.source_id,
            target: old.target,
            temp_name: old.temp_name,
            temp_id: old.temp_id,
            plan: old.plan,
            catalog_root: None,
        }
    }
}

fn intent_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(INTENT_PREFIX, WORKTREE_STAGE_INTENT_PREFIX)
}

fn symlink_intent_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(SYMLINK_INTENT_PREFIX, WORKTREE_SYMLINK_INTENT_PREFIX)
}

pub(crate) fn index_kind(repository_id: Uuid) -> String {
    index_kind_for_scope(GitWorktreeScope::primary(repository_id))
}

pub(crate) fn index_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(INDEX_PREFIX, WORKTREE_INDEX_PREFIX)
}

pub(crate) fn object_kind(repository_id: Uuid, oid: Oid) -> String {
    format!("{OBJECT_PREFIX}{repository_id}/{oid}")
}

pub(crate) fn object_kind_prefix(repository_id: Uuid) -> String {
    format!("{OBJECT_PREFIX}{repository_id}/")
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

fn read_symlink(
    root: &PinnedDirectory,
    relative_path: &Path,
) -> Result<(Vec<u8>, NativeFileId), StageError> {
    let parent_path = relative_path.parent().ok_or(StageError::UnsafePath)?;
    let parent = if parent_path.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        root.open_descendant_directory(parent_path)?
    };
    parent
        .read_child_symlink(relative_path.file_name().ok_or(StageError::UnsafePath)?)?
        .ok_or_else(|| AnchorError::SourceChanged(relative_path.to_path_buf()).into())
}

fn decode_symlink_intent(
    encoded: &[u8],
    repository_id: Uuid,
    path_key: &[u8],
) -> Result<SymlinkStageIntent, StageError> {
    let intent: SymlinkStageIntent = match decode_canonical(encoded) {
        Ok(intent) => intent,
        Err(_) => SymlinkStageIntent::from(decode_canonical::<SymlinkStageIntentV1>(encoded)?),
    };
    let temp_relative = PathBuf::from(GIT_CATALOG_DIRECTORY).join(&intent.temp_name);
    if !matches!(intent.format_version, 1 | 2)
        || intent.repository_id != repository_id
        || (intent.format_version == 1 && intent.catalog_root.is_some())
        || (intent.format_version == 2
            && !intent
                .catalog_root
                .as_ref()
                .is_some_and(|root| root.is_absolute()))
        || stage_path_key(&intent.relative_path)? != path_key
        || !intent.source_root.is_absolute()
        || intent.target.is_empty()
        || intent.target.len() > 4095
        || intent.target.contains(&0)
        || !intent.temp_name.starts_with("symlink-input-")
        || Uuid::parse_str(&intent.temp_name["symlink-input-".len()..]).is_err()
        || intent.plan.is_some() && intent.temp_id.is_none()
        || intent.plan.as_ref().is_some_and(|plan| {
            plan.source_root()
                != intent
                    .catalog_root
                    .as_deref()
                    .unwrap_or(&intent.source_root)
                || plan.relative_path() != temp_relative
        })
    {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(intent)
}

fn symlink_catalog(intent: &SymlinkStageIntent) -> Result<PinnedDirectory, StageError> {
    let root = PinnedDirectory::open(&intent.source_root)?;
    if root.identity()? != intent.root_id {
        return Err(StageError::IncompatibleRecord);
    }
    let catalog_root = if let Some(path) = &intent.catalog_root {
        PinnedDirectory::open(path)?
    } else {
        root
    };
    let catalog = catalog_root
        .open_child_directory(GIT_CATALOG_DIRECTORY)?
        .ok_or(StageError::IncompatibleRecord)?;
    if catalog.identity()? != intent.catalog_id {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(catalog)
}

fn verify_temporary_symlink_bytes(
    catalog: &PinnedDirectory,
    intent: &SymlinkStageIntent,
) -> Result<Option<NativeFileId>, StageError> {
    let Some(mut file) = catalog.open_child_file(&intent.temp_name)? else {
        return Ok(None);
    };
    if file.metadata()?.len() != intent.target.len() as u64 {
        return Err(StageError::IncompatibleRecord);
    }
    let mut bytes = Vec::new();
    file.by_ref().take(4096).read_to_end(&mut bytes)?;
    if bytes != intent.target {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(catalog.entry_identity(&intent.temp_name, false)?)
}

fn save_symlink_intent(
    control: &ControlStore,
    scope: GitWorktreeScope,
    key: &[u8],
    before: &SymlinkStageIntent,
    after: &SymlinkStageIntent,
) -> Result<(), StageError> {
    control.replace_record_if_value(
        &symlink_intent_kind_for_scope(scope),
        key,
        &canonical_bytes(before)?,
        &canonical_bytes(after)?,
    )?;
    Ok(())
}

#[cfg(test)]
fn begin_stage(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    relative_path: &Path,
) -> Result<(Vec<u8>, StageIntent), StageError> {
    begin_stage_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        source_root,
        relative_path,
        SourceBackendKind::ReflinkV1,
    )
}

fn begin_stage_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_root: &Path,
    relative_path: &Path,
    source_backend: SourceBackendKind,
) -> Result<(Vec<u8>, StageIntent), StageError> {
    let path_key = stage_path_key(relative_path)?;
    let kind = intent_kind_for_scope(scope);
    if control.get_record(&kind, &path_key)?.is_some()
        || control
            .get_record(&symlink_intent_kind_for_scope(scope), &path_key)?
            .is_some()
    {
        return Err(StageError::PendingStage);
    }
    validate_worktree_path(source_root, relative_path)?;
    let plan = source_backend.plan_file(source_root, relative_path)?;
    let mode = if plan.source_mode()? & 0o111 != 0 {
        0o100755
    } else {
        0o100644
    };
    let intent = StageIntent {
        format_version: 1,
        repository_id: scope.repository_id(),
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

#[cfg(test)]
fn begin_symlink_stage(
    control: &ControlStore,
    repository_id: Uuid,
    source_root: &Path,
    catalog: &PinnedDirectory,
    relative_path: &Path,
) -> Result<(Vec<u8>, SymlinkStageIntent), StageError> {
    begin_symlink_stage_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        source_root,
        source_root,
        catalog,
        relative_path,
    )
}

fn begin_symlink_stage_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_root: &Path,
    catalog_root: &Path,
    catalog: &PinnedDirectory,
    relative_path: &Path,
) -> Result<(Vec<u8>, SymlinkStageIntent), StageError> {
    let key = stage_path_key(relative_path)?;
    if control
        .get_record(&intent_kind_for_scope(scope), &key)?
        .is_some()
        || control
            .get_record(&symlink_intent_kind_for_scope(scope), &key)?
            .is_some()
        || control
            .get_record(&crate::rm::intent_kind_for_scope(scope), &key)?
            .is_some()
    {
        return Err(StageError::PendingStage);
    }
    validate_worktree_path(source_root, relative_path)?;
    let root = PinnedDirectory::open(source_root)?;
    let catalog_root_pinned = PinnedDirectory::open(catalog_root)?;
    let actual_catalog = catalog_root_pinned
        .open_child_directory(GIT_CATALOG_DIRECTORY)?
        .ok_or(StageError::IncompatibleRecord)?;
    if actual_catalog.identity()? != catalog.identity()? {
        return Err(StageError::IncompatibleRecord);
    }
    let (target, source_id) = read_symlink(&root, relative_path)?;
    let intent = SymlinkStageIntent {
        format_version: if scope.worktree_id() == scope.repository_id() {
            1
        } else {
            2
        },
        repository_id: scope.repository_id(),
        source_root: source_root.to_path_buf(),
        root_id: root.identity()?,
        catalog_id: catalog.identity()?,
        relative_path: relative_path.to_path_buf(),
        source_id,
        target,
        temp_name: format!("symlink-input-{}", Uuid::new_v4()),
        temp_id: None,
        plan: None,
        catalog_root: (scope.worktree_id() != scope.repository_id())
            .then(|| catalog_root.to_path_buf()),
    };
    if !control.put_record_if_absent(
        &symlink_intent_kind_for_scope(scope),
        &key,
        &canonical_bytes(&intent)?,
    )? {
        return Err(StageError::PendingStage);
    }
    Ok((key, intent))
}

fn finish_symlink_stage(
    control: &ControlStore,
    scope: GitWorktreeScope,
    key: &[u8],
    mut intent: SymlinkStageIntent,
    source_backend: SourceBackendKind,
) -> Result<GitIndexEntry, StageError> {
    let kind = symlink_intent_kind_for_scope(scope);
    if control.get_record(&kind, key)?.as_deref() != Some(canonical_bytes(&intent)?.as_slice()) {
        return Err(StageError::IncompatibleRecord);
    }
    validate_worktree_path(&intent.source_root, &intent.relative_path)?;
    let catalog = symlink_catalog(&intent)?;
    let observed_temp = verify_temporary_symlink_bytes(&catalog, &intent)?;
    if let (Some(expected), Some(observed)) = (intent.temp_id, observed_temp)
        && expected != observed
    {
        return Err(StageError::IncompatibleRecord);
    }
    if intent.plan.is_none() {
        let temp_id = match observed_temp {
            Some(existing) => existing,
            None if intent.temp_id.is_none() => {
                catalog.publish_small_bytes_child(&intent.temp_name, &intent.target)?
            }
            None => return Err(StageError::IncompatibleRecord),
        };
        if intent.temp_id.is_none() {
            let mut next = intent.clone();
            next.temp_id = Some(temp_id);
            save_symlink_intent(control, scope, key, &intent, &next)?;
            intent = next;
        }
        let plan = source_backend.plan_file(
            intent
                .catalog_root
                .as_deref()
                .unwrap_or(&intent.source_root),
            PathBuf::from(GIT_CATALOG_DIRECTORY).join(&intent.temp_name),
        )?;
        let mut next = intent.clone();
        next.plan = Some(plan);
        save_symlink_intent(control, scope, key, &intent, &next)?;
        intent = next;
    }
    let plan = intent.plan.as_ref().ok_or(StageError::IncompatibleRecord)?;
    let manifest = plan.capture()?;
    let oid = blob_oid_from_anchor(&manifest)?;
    plan.reconcile()?;
    if let Some(observed) = verify_temporary_symlink_bytes(&catalog, &intent)? {
        if Some(observed) != intent.temp_id {
            return Err(StageError::IncompatibleRecord);
        }
        catalog.remove_child_file(&intent.temp_name)?;
    }
    let entry = GitIndexEntry {
        format_version: 1,
        oid: oid.as_bytes().try_into().expect("SHA-1 OID has 20 bytes"),
        mode: 0o120000,
        anchor_id: manifest.anchor_id,
    };
    control.put_records_and_retire_if_value(
        &[
            (
                object_kind(scope.repository_id(), oid),
                manifest.anchor_id.as_bytes().to_vec(),
                canonical_bytes(&manifest)?,
            ),
            (
                index_kind_for_scope(scope),
                key.to_vec(),
                canonical_bytes(&entry)?,
            ),
        ],
        &kind,
        key,
        &canonical_bytes(&intent)?,
    )?;
    Ok(entry)
}

/// Stage the target bytes of a symlink without following it.
pub(crate) fn stage_symlink_for_scope_with_backend(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_root: &Path,
    catalog_root: &Path,
    catalog: &PinnedDirectory,
    relative_path: &Path,
    source_backend: SourceBackendKind,
) -> Result<GitIndexEntry, StageError> {
    let (key, intent) = begin_symlink_stage_for_scope(
        control,
        scope,
        source_root,
        catalog_root,
        catalog,
        relative_path,
    )?;
    finish_symlink_stage(control, scope, &key, intent, source_backend)
}

fn finish_stage_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    path_key: &[u8],
    intent: &StageIntent,
) -> Result<GitIndexEntry, StageError> {
    let kind = intent_kind_for_scope(scope);
    let expected = canonical_bytes(intent)?;
    if control.get_record(&kind, path_key)?.as_deref() != Some(expected.as_slice()) {
        return Err(StageError::IncompatibleRecord);
    }
    validate_worktree_path(intent.plan.source_root(), &intent.relative_path)?;
    let manifest = intent.plan.capture()?;
    if is_attributes_path(path_key)
        && let Err(error) = validate_anchor(&manifest)
    {
        intent.plan.discard()?;
        control.delete_record_if_value(&kind, path_key, &expected)?;
        return Err(error.into());
    }
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
                object_kind(scope.repository_id(), oid),
                manifest.anchor_id.as_bytes().to_vec(),
                canonical_bytes(&manifest)?,
            ),
            (
                index_kind_for_scope(scope),
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
    stage_file_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        source_root,
        relative_path,
    )
}

/// Capture a regular file for one worktree while publishing its blob anchor
/// into the repository's shared object map.
pub(crate) fn stage_file_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
) -> Result<GitIndexEntry, StageError> {
    stage_file_for_scope_with_backend(
        control,
        scope,
        source_root,
        relative_path,
        SourceBackendKind::ReflinkV1,
    )
}

pub(crate) fn stage_file_for_scope_with_backend(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_root: impl AsRef<Path>,
    relative_path: impl AsRef<Path>,
    source_backend: SourceBackendKind,
) -> Result<GitIndexEntry, StageError> {
    let (key, intent) = begin_stage_for_scope(
        control,
        scope,
        source_root.as_ref(),
        relative_path.as_ref(),
        source_backend,
    )?;
    finish_stage_for_scope(control, scope, &key, &intent)
}

/// Remove a path from the staged index while leaving its working file alone,
/// matching Git's `rm --cached` behavior. The catalog delete is atomic; old
/// immutable anchors stay available to commits on other branches.
pub fn remove_cached(
    control: &ControlStore,
    repository_id: Uuid,
    relative_path: impl AsRef<Path>,
) -> Result<bool, StageError> {
    remove_cached_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        relative_path,
    )
}

pub(crate) fn remove_cached_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    relative_path: impl AsRef<Path>,
) -> Result<bool, StageError> {
    let key = stage_path_key(relative_path.as_ref())?;
    if control
        .get_record(&intent_kind_for_scope(scope), &key)?
        .is_some()
        || control
            .get_record(&symlink_intent_kind_for_scope(scope), &key)?
            .is_some()
    {
        return Err(StageError::PendingStage);
    }
    let kind = index_kind_for_scope(scope);
    let Some(encoded) = control.get_record(&kind, &key)? else {
        return Ok(false);
    };
    let entry: GitIndexEntry = decode_canonical(&encoded)?;
    if entry.format_version != 1 || !matches!(entry.mode, 0o100644 | 0o100755 | 0o120000) {
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
    resume_pending_stages_for_scope(control, GitWorktreeScope::primary(repository_id))
}

pub(crate) fn resume_pending_stages_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Vec<GitIndexEntry>, StageError> {
    resume_pending_stages_for_scope_with_backend(control, scope, SourceBackendKind::ReflinkV1)
}

pub(crate) fn resume_pending_stages_for_scope_with_backend(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_backend: SourceBackendKind,
) -> Result<Vec<GitIndexEntry>, StageError> {
    let mut resumed = Vec::new();
    for (key, encoded) in control.records(&intent_kind_for_scope(scope))? {
        let intent = decode_intent(&encoded, scope.repository_id(), &key)?;
        resumed.push(finish_stage_for_scope(control, scope, &key, &intent)?);
    }
    for (key, encoded) in control.records(&symlink_intent_kind_for_scope(scope))? {
        let intent = decode_symlink_intent(&encoded, scope.repository_id(), &key)?;
        if (intent.format_version == 1) != (scope.worktree_id() == scope.repository_id()) {
            return Err(StageError::IncompatibleRecord);
        }
        resumed.push(finish_symlink_stage(
            control,
            scope,
            &key,
            intent,
            source_backend,
        )?);
    }
    Ok(resumed)
}

/// Explicitly discard an unresolved add without changing an existing index.
pub fn abandon_pending_stage(
    control: &ControlStore,
    repository_id: Uuid,
    relative_path: impl AsRef<Path>,
) -> Result<bool, StageError> {
    abandon_pending_stage_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        relative_path,
    )
}

pub(crate) fn abandon_pending_stage_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    relative_path: impl AsRef<Path>,
) -> Result<bool, StageError> {
    let key = stage_path_key(relative_path.as_ref())?;
    let kind = intent_kind_for_scope(scope);
    if let Some(encoded) = control.get_record(&kind, &key)? {
        let intent = decode_intent(&encoded, scope.repository_id(), &key)?;
        intent.plan.discard()?;
        control.delete_record_if_value(&kind, &key, &encoded)?;
        return Ok(true);
    }
    let kind = symlink_intent_kind_for_scope(scope);
    let Some(encoded) = control.get_record(&kind, &key)? else {
        return Ok(false);
    };
    let intent = decode_symlink_intent(&encoded, scope.repository_id(), &key)?;
    if (intent.format_version == 1) != (scope.worktree_id() == scope.repository_id()) {
        return Err(StageError::IncompatibleRecord);
    }
    let catalog = symlink_catalog(&intent)?;
    if let Some(plan) = &intent.plan {
        plan.discard()?;
    }
    if let Some(observed) = verify_temporary_symlink_bytes(&catalog, &intent)? {
        if intent.temp_id.is_some_and(|expected| expected != observed) {
            return Err(StageError::IncompatibleRecord);
        }
        catalog.remove_child_file(&intent.temp_name)?;
    }
    control.delete_record_if_value(&kind, &key, &encoded)?;
    Ok(true)
}

/// Discard pending adds after their linked worktree directory was removed.
/// Validate every intent against the exact worktree and protected catalog
/// before removing any anchor or temporary input. Each discard is idempotent
/// across a crash before its intent record is retired.
pub(crate) fn abandon_missing_linked_worktree_stages(
    control: &ControlStore,
    scope: GitWorktreeScope,
    source_root: &Path,
    root_id: NativeFileId,
    catalog_root: &Path,
    catalog: &PinnedDirectory,
) -> Result<(), StageError> {
    if scope.worktree_id() == scope.repository_id() {
        return Err(StageError::IncompatibleRecord);
    }
    let file_kind = intent_kind_for_scope(scope);
    let mut files = Vec::new();
    for (key, encoded) in control.records(&file_kind)? {
        let intent = decode_intent(&encoded, scope.repository_id(), &key)?;
        if intent.plan.source_root() != source_root || intent.plan.source_root_identity() != root_id
        {
            return Err(StageError::IncompatibleRecord);
        }
        files.push((key, encoded, intent));
    }
    let symlink_kind = symlink_intent_kind_for_scope(scope);
    let mut symlinks = Vec::new();
    let mut temp_names = BTreeSet::new();
    let catalog_id = catalog.identity()?;
    for (key, encoded) in control.records(&symlink_kind)? {
        let intent = decode_symlink_intent(&encoded, scope.repository_id(), &key)?;
        if intent.format_version != 2
            || intent.source_root != source_root
            || intent.root_id != root_id
            || intent.catalog_root.as_deref() != Some(catalog_root)
            || intent.catalog_id != catalog_id
            || !temp_names.insert(intent.temp_name.clone())
            || verify_temporary_symlink_bytes(catalog, &intent)?
                .is_some_and(|observed| intent.temp_id.is_some_and(|expected| expected != observed))
        {
            return Err(StageError::IncompatibleRecord);
        }
        symlinks.push((key, encoded, intent));
    }
    for (key, encoded, intent) in files {
        intent.plan.discard()?;
        control.delete_record_if_value(&file_kind, &key, &encoded)?;
        run_after_missing_stage_discard_hook();
    }
    for (key, encoded, intent) in symlinks {
        if let Some(plan) = &intent.plan {
            plan.discard()?;
        }
        if let Some(observed) = verify_temporary_symlink_bytes(catalog, &intent)? {
            if intent.temp_id.is_some_and(|expected| expected != observed) {
                return Err(StageError::IncompatibleRecord);
            }
            catalog.remove_child_file(&intent.temp_name)?;
            catalog.sync_all()?;
        }
        control.delete_record_if_value(&symlink_kind, &key, &encoded)?;
        run_after_missing_stage_discard_hook();
    }
    Ok(())
}

pub fn staged_entry(
    control: &ControlStore,
    repository_id: Uuid,
    relative_path: impl AsRef<Path>,
) -> Result<Option<GitIndexEntry>, StageError> {
    staged_entry_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        relative_path,
    )
}

pub(crate) fn staged_entry_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    relative_path: impl AsRef<Path>,
) -> Result<Option<GitIndexEntry>, StageError> {
    let key = stage_path_key(relative_path.as_ref())?;
    let Some(encoded) = control.get_record(&index_kind_for_scope(scope), &key)? else {
        return Ok(None);
    };
    let entry: GitIndexEntry = decode_canonical(&encoded)?;
    if entry.format_version != 1 || !matches!(entry.mode, 0o100644 | 0o100755 | 0o120000) {
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
    staged_entries_for_scope(control, GitWorktreeScope::primary(repository_id))
}

pub(crate) fn staged_entries_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Vec<(Vec<u8>, GitIndexEntry)>, StageError> {
    let mut entries = Vec::new();
    for (key, encoded) in control.records(&index_kind_for_scope(scope))? {
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
        if entry.format_version != 1 || !matches!(entry.mode, 0o100644 | 0o100755 | 0o120000) {
            return Err(StageError::IncompatibleRecord);
        }
        entries.push((key, entry));
    }
    Ok(entries)
}

pub fn has_pending_stages(control: &ControlStore, repository_id: Uuid) -> Result<bool, StageError> {
    has_pending_stages_for_scope(control, GitWorktreeScope::primary(repository_id))
}

pub(crate) fn has_pending_stages_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<bool, StageError> {
    Ok(!control.records(&intent_kind_for_scope(scope))?.is_empty()
        || !control
            .records(&symlink_intent_kind_for_scope(scope))?
            .is_empty()
        || !control
            .records(&crate::rm::intent_kind_for_scope(scope))?
            .is_empty())
}

/// Discover every linked worktree with an index or unfinished add/removal. Prune must
/// treat these namespaces as roots even before worktree registration is wired
/// into the daemon.
pub(crate) fn worktree_scopes_with_stage_state(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<GitWorktreeScope>, StageError> {
    let mut ids = BTreeSet::new();
    for kind_prefix in [
        WORKTREE_INDEX_PREFIX,
        WORKTREE_STAGE_INTENT_PREFIX,
        WORKTREE_SYMLINK_INTENT_PREFIX,
        "git-worktree-rm-intent-v1/",
    ] {
        let prefix = format!("{kind_prefix}{repository_id}/");
        for (kind, _, _) in control.records_with_kind_prefix(&prefix)? {
            let suffix = kind
                .strip_prefix(&prefix)
                .ok_or(StageError::IncompatibleRecord)?;
            let worktree_id =
                Uuid::parse_str(suffix).map_err(|_| StageError::IncompatibleRecord)?;
            if suffix != worktree_id.to_string()
                || GitWorktreeScope::linked(repository_id, worktree_id).is_none()
            {
                return Err(StageError::IncompatibleRecord);
            }
            ids.insert(worktree_id);
        }
    }
    Ok(ids
        .into_iter()
        .map(|id| GitWorktreeScope::linked(repository_id, id).expect("validated linked scope"))
        .collect())
}

pub fn pending_stage_paths(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Vec<Vec<u8>>, StageError> {
    pending_stage_paths_for_scope(control, GitWorktreeScope::primary(repository_id))
}

pub(crate) fn pending_stage_paths_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Vec<Vec<u8>>, StageError> {
    let mut paths = Vec::new();
    for (key, encoded) in control.records(&intent_kind_for_scope(scope))? {
        decode_intent(&encoded, scope.repository_id(), &key)?;
        paths.push(key);
    }
    for (key, encoded) in control.records(&symlink_intent_kind_for_scope(scope))? {
        decode_symlink_intent(&encoded, scope.repository_id(), &key)?;
        paths.push(key);
    }
    paths.sort();
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
    use std::os::unix::fs::symlink;
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use git2::Oid;
    use mb_store::{
        AnchorError, ControlStore, GIT_CATALOG_DIRECTORY, PinnedDirectory, SourceBackendKind,
        SourceFileCapturePlan,
    };
    use uuid::Uuid;

    use super::{
        StageError, abandon_pending_stage, abandon_pending_stage_for_scope, anchors_for_oid,
        begin_stage, begin_stage_for_scope, begin_symlink_stage, begin_symlink_stage_for_scope,
        has_pending_stages, pending_stage_paths_for_scope, resume_pending_stages,
        resume_pending_stages_for_scope, save_symlink_intent, stage_file, staged_entries_for_scope,
        staged_entry, staged_entry_for_scope,
    };
    use crate::GitWorktreeScope;

    #[test]
    fn original_symlink_intent_encoding_remains_replayable() {
        let repository_id = Uuid::new_v4();
        let file_id = mb_store::NativeFileId {
            filesystem_id: 4,
            inode: 12,
        };
        let old = super::SymlinkStageIntentV1 {
            format_version: 1,
            repository_id,
            source_root: PathBuf::from("/source"),
            root_id: file_id,
            catalog_id: file_id,
            relative_path: PathBuf::from("link"),
            source_id: file_id,
            target: b"target".to_vec(),
            temp_name: format!("symlink-input-{}", Uuid::new_v4()),
            temp_id: None,
            plan: None,
        };
        let encoded = mb_core::canonical_bytes(&old).unwrap();
        let decoded = super::decode_symlink_intent(&encoded, repository_id, b"link").unwrap();
        assert_eq!(decoded.format_version, 1);
        assert!(decoded.catalog_root.is_none());
        assert_eq!(mb_core::canonical_bytes(&decoded).unwrap(), encoded);
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn symlink_stage_replays_after_capture_and_temporary_input_removal() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-link-replay-{}", Uuid::new_v4()));
        let source_root = run_root.join("work");
        let catalog_path = source_root.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir_all(&catalog_path).unwrap();
        let catalog = PinnedDirectory::open(&catalog_path).unwrap();
        let database = catalog_path.join("catalog.db");
        let key = [44_u8; 32];
        let repository_id = Uuid::new_v4();
        symlink("old target", source_root.join("linked")).unwrap();
        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let (path_key, initial) = begin_symlink_stage(
            &control,
            repository_id,
            &source_root,
            &catalog,
            "linked".as_ref(),
        )
        .unwrap();
        let temp_id = catalog
            .publish_small_bytes_child(&initial.temp_name, &initial.target)
            .unwrap();
        let mut prepared = initial.clone();
        prepared.temp_id = Some(temp_id);
        save_symlink_intent(
            &control,
            GitWorktreeScope::primary(repository_id),
            &path_key,
            &initial,
            &prepared,
        )
        .unwrap();
        let mut planned = prepared.clone();
        planned.plan = Some(
            SourceFileCapturePlan::plan_reflink(
                &source_root,
                PathBuf::from(GIT_CATALOG_DIRECTORY).join(&planned.temp_name),
            )
            .unwrap(),
        );
        save_symlink_intent(
            &control,
            GitWorktreeScope::primary(repository_id),
            &path_key,
            &prepared,
            &planned,
        )
        .unwrap();
        let manifest = planned.plan.as_ref().unwrap().capture().unwrap();
        catalog.remove_child_file(&planned.temp_name).unwrap();
        fs::remove_file(source_root.join("linked")).unwrap();
        drop(control);

        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let resumed = resume_pending_stages(&control, repository_id).unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].mode, 0o120000);
        assert_eq!(resumed[0].anchor_id, manifest.anchor_id);
        assert!(
            resume_pending_stages(&control, repository_id)
                .unwrap()
                .is_empty()
        );
        drop(control);
        drop(catalog);
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn linked_symlink_stage_replays_into_its_own_index() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-linked-symlink-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        let catalog_path = primary_root.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir_all(&catalog_path).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        let catalog = PinnedDirectory::open(&catalog_path).unwrap();
        let repository_id = Uuid::new_v4();
        let scope = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let key = [84_u8; 32];
        let database = catalog_path.join("catalog.db");
        symlink("../target\nbytes", linked_root.join("link")).unwrap();
        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let (path_key, initial) = begin_symlink_stage_for_scope(
            &control,
            scope,
            &linked_root,
            &primary_root,
            &catalog,
            Path::new("link"),
        )
        .unwrap();
        assert_eq!(initial.format_version, 2);
        assert_eq!(
            initial.catalog_root.as_deref(),
            Some(primary_root.as_path())
        );
        let temp_id = catalog
            .publish_small_bytes_child(&initial.temp_name, &initial.target)
            .unwrap();
        let mut prepared = initial.clone();
        prepared.temp_id = Some(temp_id);
        save_symlink_intent(&control, scope, &path_key, &initial, &prepared).unwrap();
        let mut planned = prepared.clone();
        planned.plan = Some(
            SourceFileCapturePlan::plan_reflink(
                &primary_root,
                PathBuf::from(GIT_CATALOG_DIRECTORY).join(&planned.temp_name),
            )
            .unwrap(),
        );
        save_symlink_intent(&control, scope, &path_key, &prepared, &planned).unwrap();
        let manifest = planned.plan.as_ref().unwrap().capture().unwrap();
        catalog.remove_child_file(&planned.temp_name).unwrap();
        fs::remove_file(linked_root.join("link")).unwrap();
        drop(control);

        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let resumed = resume_pending_stages_for_scope(&control, scope).unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].mode, 0o120000);
        assert_eq!(resumed[0].anchor_id, manifest.anchor_id);
        assert_eq!(
            staged_entry_for_scope(&control, scope, "link").unwrap(),
            Some(resumed[0].clone())
        );
        assert!(
            staged_entry(&control, repository_id, "link")
                .unwrap()
                .is_none()
        );
        assert!(
            resume_pending_stages_for_scope(&control, scope)
                .unwrap()
                .is_empty()
        );
        drop(control);
        drop(catalog);
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn linked_worktree_stage_replays_without_overwriting_primary_index() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-scoped-stage-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::write(primary_root.join("tracked"), b"primary\r\n").unwrap();
        fs::write(linked_root.join("tracked"), b"linked\n\0").unwrap();
        let repository_id = Uuid::new_v4();
        let scope = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let database = run_root.join("catalog.db");
        let key = [62_u8; 32];
        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let primary = stage_file(&control, repository_id, &primary_root, "tracked").unwrap();
        let (path, intent) = begin_stage_for_scope(
            &control,
            scope,
            &linked_root,
            Path::new("tracked"),
            SourceBackendKind::ReflinkV1,
        )
        .unwrap();
        let linked_anchor = intent.plan.capture().unwrap();
        assert_eq!(
            pending_stage_paths_for_scope(&control, scope).unwrap(),
            vec![path]
        );
        assert!(!has_pending_stages(&control, repository_id).unwrap());
        drop(control);

        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let resumed = resume_pending_stages_for_scope(&control, scope).unwrap();
        assert_eq!(resumed.len(), 1);
        assert_eq!(resumed[0].anchor_id, linked_anchor.anchor_id);
        assert_ne!(resumed[0].oid, primary.oid);
        assert_eq!(
            staged_entry(&control, repository_id, "tracked").unwrap(),
            Some(primary.clone())
        );
        assert_eq!(
            staged_entry_for_scope(&control, scope, "tracked").unwrap(),
            Some(resumed[0].clone())
        );
        assert_eq!(staged_entries_for_scope(&control, scope).unwrap().len(), 1);
        assert!(
            resume_pending_stages_for_scope(&control, scope)
                .unwrap()
                .is_empty()
        );
        let primary_anchor = anchors_for_oid(
            &control,
            repository_id,
            Oid::from_bytes(&primary.oid).unwrap(),
        )
        .unwrap();
        assert_eq!(primary_anchor.len(), 1);
        assert_eq!(
            anchors_for_oid(
                &control,
                repository_id,
                Oid::from_bytes(&resumed[0].oid).unwrap()
            )
            .unwrap(),
            vec![linked_anchor.clone()]
        );
        fs::write(linked_root.join("discard"), b"discard me").unwrap();
        let (_, discard_intent) = begin_stage_for_scope(
            &control,
            scope,
            &linked_root,
            Path::new("discard"),
            SourceBackendKind::ReflinkV1,
        )
        .unwrap();
        let discarded_anchor = discard_intent.plan.capture().unwrap();
        assert!(abandon_pending_stage_for_scope(&control, scope, "discard").unwrap());
        assert!(discarded_anchor.open_verified().is_err());
        assert!(
            pending_stage_paths_for_scope(&control, scope)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            staged_entry_for_scope(&control, scope, "tracked").unwrap(),
            Some(resumed[0].clone())
        );
        drop(control);
        primary_anchor[0].remove().unwrap();
        linked_anchor.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }

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

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn missing_linked_worktree_force_prune_replays_pending_file_and_symlink_discards() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-missing-stage-{}", Uuid::new_v4()));
        let primary_root = run_root.join("primary");
        let linked_root = run_root.join("linked");
        let catalog_path = primary_root.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir_all(&primary_root).unwrap();
        fs::create_dir_all(&linked_root).unwrap();
        fs::write(primary_root.join("tracked"), b"base\r\n").unwrap();
        let repository_id = Uuid::new_v4();
        let key = [123; 32];
        let repo = crate::GitRepository::init(&primary_root, repository_id, &key).unwrap();
        repo.stage_file("tracked").unwrap();
        repo.commit("Author", "a@example.test", "base").unwrap();
        repo.create_branch("topic").unwrap();
        let linked = repo.add_linked_worktree(&linked_root, "topic").unwrap();
        let scope = linked.scope().unwrap();
        fs::write(linked_root.join("pending-file"), b"orphaned\n").unwrap();
        symlink("../raw\nlink", linked_root.join("pending-link")).unwrap();

        let control =
            ControlStore::open_existing_with_key(catalog_path.join("catalog.db"), &key).unwrap();
        let catalog = PinnedDirectory::open(&catalog_path).unwrap();
        let (_, file_intent) = begin_stage_for_scope(
            &control,
            scope,
            &linked_root,
            Path::new("pending-file"),
            SourceBackendKind::ReflinkV1,
        )
        .unwrap();
        let file_anchor = file_intent.plan.capture().unwrap();
        let (link_key, initial) = begin_symlink_stage_for_scope(
            &control,
            scope,
            &linked_root,
            &primary_root,
            &catalog,
            Path::new("pending-link"),
        )
        .unwrap();
        let temp_id = catalog
            .publish_small_bytes_child(&initial.temp_name, &initial.target)
            .unwrap();
        let mut prepared = initial.clone();
        prepared.temp_id = Some(temp_id);
        save_symlink_intent(&control, scope, &link_key, &initial, &prepared).unwrap();
        let mut planned = prepared.clone();
        planned.plan = Some(
            SourceFileCapturePlan::plan_reflink(
                &primary_root,
                PathBuf::from(GIT_CATALOG_DIRECTORY).join(&planned.temp_name),
            )
            .unwrap(),
        );
        save_symlink_intent(&control, scope, &link_key, &prepared, &planned).unwrap();
        let link_anchor = planned.plan.as_ref().unwrap().capture().unwrap();
        fs::remove_dir_all(&linked_root).unwrap();
        assert!(matches!(
            repo.prune_missing_linked_worktree(linked.worktree_id, false),
            Err(crate::RepositoryError::Worktree(
                crate::GitWorktreeError::PendingOperation
            ))
        ));
        let mut wrong_catalog = planned.clone();
        wrong_catalog.catalog_id.inode += 1;
        save_symlink_intent(&control, scope, &link_key, &planned, &wrong_catalog).unwrap();
        assert!(matches!(
            repo.prune_missing_linked_worktree(linked.worktree_id, true),
            Err(crate::RepositoryError::Worktree(
                crate::GitWorktreeError::Stage(StageError::IncompatibleRecord)
            ))
        ));
        assert!(file_anchor.open_verified().is_ok());
        assert!(link_anchor.open_verified().is_ok());
        save_symlink_intent(&control, scope, &link_key, &wrong_catalog, &planned).unwrap();
        super::set_after_missing_stage_discard_hook(Box::new(|| panic!("stage discard crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            repo.prune_missing_linked_worktree(linked.worktree_id, true)
                .unwrap();
        }));
        assert!(interrupted.is_err());
        assert!(file_anchor.open_verified().is_err());
        assert!(link_anchor.open_verified().is_ok());
        assert!(super::has_pending_stages_for_scope(&control, scope).unwrap());
        drop(control);
        drop(catalog);
        drop(repo);

        let repo = crate::GitRepository::open(&primary_root, repository_id, &key).unwrap();
        repo.prune_missing_linked_worktree(linked.worktree_id, true)
            .unwrap();
        assert!(link_anchor.open_verified().is_err());
        assert!(fs::symlink_metadata(catalog_path.join(&planned.temp_name)).is_err());
        assert!(repo.linked_worktrees().unwrap().is_empty());
        repo.switch_branch("topic").unwrap();
        assert_eq!(fs::read(primary_root.join("tracked")).unwrap(), b"base\r\n");
        let graph = repo.export_graph_source().unwrap();
        drop(repo);
        for blob in graph.blobs {
            blob.anchor.remove().unwrap();
        }
        fs::remove_dir_all(run_root).unwrap();
    }
}
