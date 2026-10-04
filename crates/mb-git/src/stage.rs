//! Crash-replayable Git staging over the daemon's encrypted local catalog.
//!
//! The caller provides a single-writer `ControlStore`, normally opened under
//! the repository's app-owned `.mutualbackup` catalog. Each add first persists
//! a source-capture intent. One SQL transaction then publishes the index entry
//! and object-to-anchor mapping while retiring that intent.

use std::collections::BTreeSet;
use std::ffi::OsStr;
#[cfg(target_os = "linux")]
use std::ffi::OsString;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::{Component, Path, PathBuf};

use git2::Oid;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
#[cfg(target_os = "linux")]
use mb_store::GuardedGitStagePin;
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, GIT_CATALOG_DIRECTORY,
    NativeFileId, PinnedDirectory, SourceBackendKind, SourceFileCaptureError,
    SourceFileCapturePlan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::merge::{MergeBlobError, SessionRecord, resolution_record_for_scope};
use crate::{GitAnchorError, GitWorktreeScope, blob_oid_from_anchor};

fn resolution_record_for_stage(
    control: &ControlStore,
    scope: GitWorktreeScope,
    path: &[u8],
    resolved: bool,
) -> Result<Option<SessionRecord>, StageError> {
    resolution_record_for_scope(control, scope, path, resolved).map_err(|error| match error {
        MergeBlobError::Database(error) => StageError::Database(error),
        MergeBlobError::Model(error) => StageError::Model(error),
        _ => StageError::IncompatibleRecord,
    })
}

const MAX_STAGE_PATH_BYTES: usize = 4096;
const INTENT_PREFIX: &str = "git-stage-intent-v1/";
const SYMLINK_INTENT_PREFIX: &str = "git-symlink-stage-intent-v1/";
const INDEX_PREFIX: &str = "git-index-entry-v1/";
const WORKTREE_STAGE_INTENT_PREFIX: &str = "git-worktree-stage-intent-v1/";
const WORKTREE_SYMLINK_INTENT_PREFIX: &str = "git-worktree-symlink-stage-intent-v1/";
const WORKTREE_INDEX_PREFIX: &str = "git-worktree-index-entry-v1/";
const OBJECT_PREFIX: &str = "git-object-anchor-v1/";
#[cfg(target_os = "linux")]
const GUARDED_STAGE_RECEIPT_PREFIX: &str = "git-guarded-stage-receipt-v1/";

#[cfg(target_os = "linux")]
pub(crate) fn guarded_stage_receipt_matches(
    control: &ControlStore,
    pin: &GuardedGitStagePin,
) -> Result<bool, StageError> {
    if pin.repository_id.is_nil()
        || pin.worktree_id.is_nil()
        || pin.root_anchor_id.is_nil()
        || pin.attempt_id.is_nil()
        || !matches!(pin.git_mode, 0o100644 | 0o100755)
    {
        return Err(StageError::IncompatibleRecord);
    }
    let path = PathBuf::from(OsString::from_vec(pin.relative_path.clone()));
    if stage_path_key(&path)? != pin.relative_path {
        return Err(StageError::IncompatibleRecord);
    }
    let kind = format!("{GUARDED_STAGE_RECEIPT_PREFIX}{}", pin.repository_id);
    let Some(bytes) = control.get_record(&kind, pin.attempt_id.as_bytes())? else {
        return Ok(false);
    };
    let receipt: GuardedStageReceipt = decode_canonical(&bytes)?;
    if receipt.format_version != 1
        || receipt.repository_id != pin.repository_id
        || receipt.worktree_id != pin.worktree_id
        || receipt.root_anchor_id != pin.root_anchor_id
        || receipt.attempt_id != pin.attempt_id
        || receipt.relative_path != pin.relative_path
        || receipt.manifest != pin.manifest
        || receipt.entry.format_version != 1
        || receipt.entry.mode != pin.git_mode
        || receipt.entry.anchor_id != pin.manifest.anchor_id
        || canonical_bytes(&receipt)? != bytes
    {
        return Err(StageError::IncompatibleRecord);
    }
    let oid = Oid::from_bytes(&receipt.entry.oid).map_err(|_| StageError::IncompatibleRecord)?;
    let mapped = control.get_record(
        &object_kind(pin.repository_id, oid),
        pin.manifest.anchor_id.as_bytes(),
    )?;
    if mapped.as_deref() != Some(canonical_bytes(&pin.manifest)?.as_slice()) {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(true)
}

#[cfg(test)]
thread_local! {
    static AFTER_MISSING_STAGE_DISCARD: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_STAGE_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_missing_stage_discard_hook(hook: Box<dyn FnOnce()>) {
    AFTER_MISSING_STAGE_DISCARD.with(|slot| *slot.borrow_mut() = Some(hook));
}

#[cfg(test)]
pub(crate) fn set_after_stage_publication_hook(hook: Box<dyn FnOnce()>) {
    AFTER_STAGE_PUBLICATION.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_stage_publication_hook() {
    #[cfg(test)]
    AFTER_STAGE_PUBLICATION.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
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
    #[error("guarded source capture error: {0}")]
    Guarded(anyhow::Error),
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
    #[error(
        "pending add belongs to another source backend; restore that backend or abandon the add"
    )]
    BackendMismatch,
    #[error("Git stage catalog paths currently require Linux byte paths")]
    UnsupportedPlatform,
    #[error("staged symlink temporary file I/O failed: {0}")]
    Io(#[from] std::io::Error),
}

impl From<SourceFileCaptureError> for StageError {
    fn from(error: SourceFileCaptureError) -> Self {
        match error {
            SourceFileCaptureError::Anchor(error) => Self::Anchor(error),
            #[cfg(target_os = "linux")]
            SourceFileCaptureError::Guarded(error) => Self::Guarded(error),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitIndexEntry {
    pub format_version: u16,
    pub oid: [u8; 20],
    pub mode: u32,
    pub anchor_id: Uuid,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedStageReceipt {
    format_version: u16,
    repository_id: Uuid,
    worktree_id: Uuid,
    root_anchor_id: Uuid,
    attempt_id: Uuid,
    relative_path: Vec<u8>,
    manifest: FileAnchorManifest,
    entry: GitIndexEntry,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StageIntent {
    format_version: u16,
    repository_id: Uuid,
    #[serde(with = "mb_store::raw_path_bytes")]
    relative_path: PathBuf,
    git_mode: u32,
    plan: SourceFileCapturePlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct SymlinkStageIntent {
    format_version: u16,
    repository_id: Uuid,
    #[serde(with = "mb_store::raw_path_bytes")]
    source_root: PathBuf,
    root_id: NativeFileId,
    catalog_id: NativeFileId,
    #[serde(with = "mb_store::raw_path_bytes")]
    relative_path: PathBuf,
    source_id: NativeFileId,
    target: Vec<u8>,
    temp_name: String,
    temp_id: Option<NativeFileId>,
    plan: Option<SourceFileCapturePlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[serde(with = "mb_store::raw_path_bytes_option")]
    catalog_root: Option<PathBuf>,
}

// Canonical CBOR encodes struct fields as a sequence. A new trailing field
// therefore needs an explicit decoder for intents written by older versions.
#[derive(Serialize, Deserialize)]
struct SymlinkStageIntentV1 {
    format_version: u16,
    repository_id: Uuid,
    #[serde(with = "mb_store::raw_path_bytes")]
    source_root: PathBuf,
    root_id: NativeFileId,
    catalog_id: NativeFileId,
    #[serde(with = "mb_store::raw_path_bytes")]
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
    if let Some(plan) = intent.plan.as_ref() {
        if plan.backend_kind() != source_backend {
            return Err(StageError::BackendMismatch);
        }
    } else if !source_backend.supports_git_file_staging() {
        return Err(AnchorError::UnsupportedSourceOperation(
            "Git file staging with guarded link-freeze",
        )
        .into());
    }
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
    let manifest = plan.capture_with_control(control)?;
    let oid = blob_oid_from_anchor(&manifest)?;
    plan.reconcile_with_control(control)?;
    for existing in anchors_for_oid(control, scope.repository_id(), oid)? {
        require_same_blob_bytes(&existing, &manifest)?;
    }
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
    let mut records = vec![
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
    ];
    if let Some(resolution) = resolution_record_for_stage(control, scope, key, true)? {
        records.push(resolution);
    }
    control.put_records_and_retire_if_value(&records, &kind, key, &canonical_bytes(&intent)?)?;
    run_after_stage_publication_hook();
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
    if !source_backend.supports_git_file_staging() {
        return Err(AnchorError::UnsupportedSourceOperation(
            "Git file staging with guarded link-freeze",
        )
        .into());
    }
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
    source_backend: SourceBackendKind,
) -> Result<GitIndexEntry, StageError> {
    let kind = intent_kind_for_scope(scope);
    let expected = canonical_bytes(intent)?;
    if control.get_record(&kind, path_key)?.as_deref() != Some(expected.as_slice()) {
        return Err(StageError::IncompatibleRecord);
    }
    if intent.plan.backend_kind() != source_backend {
        return Err(StageError::BackendMismatch);
    }
    let manifest = intent.plan.capture_with_control(control)?;
    let oid = blob_oid_from_anchor(&manifest)?;
    intent.plan.reconcile_with_control(control)?;
    for existing in anchors_for_oid(control, scope.repository_id(), oid)? {
        require_same_blob_bytes(&existing, &manifest)?;
    }
    let entry = GitIndexEntry {
        format_version: 1,
        oid: oid.as_bytes().try_into().expect("SHA-1 OID has 20 bytes"),
        mode: intent.git_mode,
        anchor_id: manifest.anchor_id,
    };
    let mut records = vec![
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
    ];
    if let Some(resolution) = resolution_record_for_stage(control, scope, path_key, true)? {
        records.push(resolution);
    }
    control.put_records_and_retire_if_value(&records, &kind, path_key, &expected)?;
    run_after_stage_publication_hook();
    Ok(entry)
}

/// Publish a node-pinned guarded capture into the Git catalog. The node's
/// control database owns the capture before this call; one catalog transaction
/// publishes the object map, index entry, and exact attempt receipt. Replaying
/// a receipt never rewrites a path that was staged again later.
#[cfg(target_os = "linux")]
pub(crate) fn publish_guarded_stage_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    pin: &GuardedGitStagePin,
) -> Result<GitIndexEntry, StageError> {
    if pin.repository_id != scope.repository_id()
        || pin.worktree_id != scope.worktree_id()
        || pin.root_anchor_id.is_nil()
        || pin.attempt_id.is_nil()
        || !matches!(pin.git_mode, 0o100644 | 0o100755)
    {
        return Err(StageError::IncompatibleRecord);
    }
    let path = PathBuf::from(OsString::from_vec(pin.relative_path.clone()));
    let key = stage_path_key(&path)?;
    if key != pin.relative_path {
        return Err(StageError::IncompatibleRecord);
    }
    let oid = blob_oid_from_anchor(&pin.manifest)?;
    let entry = GitIndexEntry {
        format_version: 1,
        oid: oid.as_bytes().try_into().expect("SHA-1 OID has 20 bytes"),
        mode: pin.git_mode,
        anchor_id: pin.manifest.anchor_id,
    };
    let receipt = GuardedStageReceipt {
        format_version: 1,
        repository_id: pin.repository_id,
        worktree_id: pin.worktree_id,
        root_anchor_id: pin.root_anchor_id,
        attempt_id: pin.attempt_id,
        relative_path: key.clone(),
        manifest: pin.manifest.clone(),
        entry: entry.clone(),
    };
    let receipt_kind = format!("{GUARDED_STAGE_RECEIPT_PREFIX}{}", scope.repository_id());
    let receipt_bytes = canonical_bytes(&receipt)?;
    if let Some(existing) = control.get_record(&receipt_kind, pin.attempt_id.as_bytes())? {
        let recorded: GuardedStageReceipt = decode_canonical(&existing)?;
        if existing != receipt_bytes || recorded != receipt {
            return Err(StageError::IncompatibleRecord);
        }
        let mapped = control.get_record(
            &object_kind(scope.repository_id(), oid),
            pin.manifest.anchor_id.as_bytes(),
        )?;
        if mapped.as_deref() != Some(canonical_bytes(&pin.manifest)?.as_slice()) {
            return Err(StageError::IncompatibleRecord);
        }
        return Ok(entry);
    }
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
    for existing in anchors_for_oid(control, scope.repository_id(), oid)? {
        require_same_blob_bytes(&existing, &pin.manifest)?;
    }
    let mut records = vec![
        (
            object_kind(scope.repository_id(), oid),
            pin.manifest.anchor_id.as_bytes().to_vec(),
            canonical_bytes(&pin.manifest)?,
        ),
        (
            index_kind_for_scope(scope),
            key.clone(),
            canonical_bytes(&entry)?,
        ),
        (
            receipt_kind,
            pin.attempt_id.as_bytes().to_vec(),
            receipt_bytes,
        ),
    ];
    if let Some(resolution) = resolution_record_for_stage(control, scope, &key, true)? {
        records.push(resolution);
    }
    control.put_records_and_delete(&records, &[])?;
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
    finish_stage_for_scope(control, scope, &key, &intent, source_backend)
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
    remove_cached_for_scope_with_resolution(control, scope, relative_path, false)
}

pub(crate) fn remove_cached_for_scope_with_resolution(
    control: &ControlStore,
    scope: GitWorktreeScope,
    relative_path: impl AsRef<Path>,
    resolved: bool,
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
    let records = resolution_record_for_stage(control, scope, &key, resolved)?
        .into_iter()
        .collect::<Vec<_>>();
    control.put_records_and_retire_if_value(&records, &kind, &key, &encoded)?;
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
        resumed.push(finish_stage_for_scope(
            control,
            scope,
            &key,
            &intent,
            source_backend,
        )?);
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
        intent.plan.discard_with_control(control)?;
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
        plan.discard_with_control(control)?;
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
        intent.plan.discard_with_control(control)?;
        control.delete_record_if_value(&file_kind, &key, &encoded)?;
        run_after_missing_stage_discard_hook();
    }
    for (key, encoded, intent) in symlinks {
        if let Some(plan) = &intent.plan {
            plan.discard_with_control(control)?;
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

/// Read the catalog root recorded for an index entry without rehashing its
/// payload. Status and diff compare working bytes with this stronger root;
/// operations that consume an anchor still verify the payload and Git ID.
pub(crate) fn indexed_anchor_manifest(
    control: &ControlStore,
    repository_id: Uuid,
    entry: &GitIndexEntry,
) -> Result<FileAnchorManifest, StageError> {
    let oid = Oid::from_bytes(&entry.oid).expect("SHA-1 OID has 20 bytes");
    let encoded = control
        .get_record(&object_kind(repository_id, oid), entry.anchor_id.as_bytes())?
        .ok_or(StageError::IncompatibleRecord)?;
    let manifest: FileAnchorManifest = decode_canonical(&encoded)?;
    if manifest.format_version != 1 || manifest.anchor_id != entry.anchor_id {
        return Err(StageError::IncompatibleRecord);
    }
    Ok(manifest)
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

fn require_same_blob_bytes(
    existing: &FileAnchorManifest,
    candidate: &FileAnchorManifest,
) -> Result<(), StageError> {
    if existing.content_hash != candidate.content_hash
        || existing.logical_len != candidate.logical_len
    {
        return Err(GitAnchorError::OidCollision.into());
    }
    Ok(())
}

/// Resolve usable physical anchors for a Git blob ID, verifying both the
/// native content root and Git object ID. A damaged payload remains mapped for
/// repair/retention, but cannot prevent use of another verified copy. Distinct
/// native content under one Git ID is an ambiguous alias and fails closed.
pub fn anchors_for_oid(
    control: &ControlStore,
    repository_id: Uuid,
    oid: Oid,
) -> Result<Vec<FileAnchorManifest>, StageError> {
    let mut anchors = Vec::new();
    for (key, encoded) in control.records(&object_kind(repository_id, oid))? {
        let manifest: FileAnchorManifest = decode_canonical(&encoded)?;
        if key != manifest.anchor_id.as_bytes() || manifest.format_version != 1 {
            return Err(StageError::IncompatibleRecord);
        }
        match blob_oid_from_anchor(&manifest) {
            Ok(actual) if actual == oid => {
                if let Some(existing) = anchors.first() {
                    require_same_blob_bytes(existing, &manifest)?;
                }
                anchors.push(manifest);
            }
            Ok(_) => return Err(StageError::IncompatibleRecord),
            Err(GitAnchorError::Anchor(_)) => {}
            Err(error) => return Err(error.into()),
        }
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
    use mb_core::canonical_bytes;
    use mb_store::{
        AnchorError, ControlStore, GIT_CATALOG_DIRECTORY, GuardedGitStagePin, PinnedDirectory,
        SourceBackendKind, SourceFileCapturePlan, StableAnchorAreaLocator,
    };
    use serde::Serialize;
    use uuid::Uuid;

    use super::{
        StageError, abandon_pending_stage, abandon_pending_stage_for_scope, anchors_for_oid,
        begin_stage, begin_stage_for_scope, begin_symlink_stage, begin_symlink_stage_for_scope,
        has_pending_stages, pending_stage_paths_for_scope, resume_pending_stages,
        resume_pending_stages_for_scope, save_symlink_intent, stage_file, staged_entries_for_scope,
        staged_entry, staged_entry_for_scope,
    };
    use crate::GitWorktreeScope;
    use crate::merge::{MergeSession, merge_state_for_scope, store_merge_session_for_scope};

    #[test]
    fn guarded_stage_receipt_replays_without_rewriting_a_later_index() {
        let temporary = tempfile::tempdir().unwrap();
        let repository_id = Uuid::new_v4();
        let root_anchor_id = Uuid::new_v4();
        let scope = GitWorktreeScope::primary(repository_id);
        let catalog_path = temporary.path().join("catalog.db");
        let make_pin = |bytes: &'static [u8]| GuardedGitStagePin {
            repository_id,
            root_anchor_id,
            manifest: mb_store::SourceBlobImportPlan::plan_direct(
                temporary.path(),
                bytes.len() as u64,
            )
            .unwrap()
            .capture(std::io::Cursor::new(bytes))
            .unwrap(),
            attempt_id: Uuid::new_v4(),
            worktree_id: repository_id,
            relative_path: b"tracked".to_vec(),
            git_mode: 0o100644,
        };
        let first = make_pin(b"alpha");
        let control = ControlStore::open_with_key(&catalog_path, &[31; 32]).unwrap();
        assert!(!super::guarded_stage_receipt_matches(&control, &first).unwrap());
        let first_entry = super::publish_guarded_stage_for_scope(&control, scope, &first).unwrap();
        assert!(super::guarded_stage_receipt_matches(&control, &first).unwrap());
        assert_eq!(
            staged_entry_for_scope(&control, scope, "tracked").unwrap(),
            Some(first_entry.clone())
        );
        drop(control);
        let control = ControlStore::open_existing_with_key(&catalog_path, &[31; 32]).unwrap();
        assert_eq!(
            super::publish_guarded_stage_for_scope(&control, scope, &first).unwrap(),
            first_entry
        );
        let second = make_pin(b"bravo");
        let second_entry =
            super::publish_guarded_stage_for_scope(&control, scope, &second).unwrap();
        assert_eq!(
            super::publish_guarded_stage_for_scope(&control, scope, &first).unwrap(),
            first_entry
        );
        assert_eq!(
            staged_entry_for_scope(&control, scope, "tracked").unwrap(),
            Some(second_entry.clone())
        );
        let linked_scope = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let mut linked = make_pin(b"linked");
        linked.worktree_id = linked_scope.worktree_id();
        let linked_entry =
            super::publish_guarded_stage_for_scope(&control, linked_scope, &linked).unwrap();
        assert_eq!(
            staged_entry_for_scope(&control, linked_scope, "tracked").unwrap(),
            Some(linked_entry)
        );
        assert_eq!(
            staged_entry_for_scope(&control, scope, "tracked").unwrap(),
            Some(second_entry)
        );
        let mut altered = first.clone();
        altered.git_mode = 0o100755;
        assert!(matches!(
            super::guarded_stage_receipt_matches(&control, &altered),
            Err(StageError::IncompatibleRecord)
        ));
        assert!(matches!(
            super::publish_guarded_stage_for_scope(&control, scope, &altered),
            Err(StageError::IncompatibleRecord)
        ));
    }

    #[test]
    fn index_removal_and_conflict_resolution_share_one_catalog_transition() {
        let database = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(database.path().join("catalog.db"), &[73; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        for scope in [
            GitWorktreeScope::primary(repository_id),
            GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap(),
        ] {
            store_merge_session_for_scope(
                &control,
                scope,
                &MergeSession {
                    format_version: 1,
                    repository_id,
                    branch: "topic".to_owned(),
                    ours: [1; 20],
                    theirs: [2; 20],
                    source_ref: b"refs/heads/source".to_vec(),
                    author_name: "Author".to_owned(),
                    author_email: "a@example.test".to_owned(),
                    message: "merge".to_owned(),
                    conflicts: vec![b"tracked".to_vec()],
                    resolved: Vec::new(),
                },
            )
            .unwrap();
            let index_kind = super::index_kind_for_scope(scope);
            let entry = super::GitIndexEntry {
                format_version: 1,
                oid: [3; 20],
                mode: 0o100644,
                anchor_id: Uuid::new_v4(),
            };
            control
                .put_record(&index_kind, b"tracked", &canonical_bytes(&entry).unwrap())
                .unwrap();
            assert!(
                super::remove_cached_for_scope_with_resolution(&control, scope, "tracked", true)
                    .unwrap()
            );
            assert!(
                control
                    .get_record(&index_kind, b"tracked")
                    .unwrap()
                    .is_none()
            );
            assert!(
                merge_state_for_scope(&control, scope)
                    .unwrap()
                    .unwrap()
                    .unresolved_paths
                    .is_empty()
            );
            control
                .put_record(&index_kind, b"tracked", &canonical_bytes(&entry).unwrap())
                .unwrap();
            assert!(super::remove_cached_for_scope(&control, scope, "tracked").unwrap());
            assert_eq!(
                merge_state_for_scope(&control, scope)
                    .unwrap()
                    .unwrap()
                    .unresolved_paths,
                vec![b"tracked".to_vec()]
            );
        }
    }

    #[derive(Serialize)]
    struct TestCaptureVersion {
        filesystem_id: u64,
        inode: u64,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: i64,
        changed_secs: i64,
        changed_nanos: i64,
    }

    #[derive(Serialize)]
    struct TestFileManifest<'a> {
        format_version: u16,
        anchor_id: Uuid,
        area: &'a StableAnchorAreaLocator,
        source_root_hint: &'a Path,
        source_relative_path: &'a Path,
        logical_len: u64,
        content_hash: [u8; 32],
        source_version: TestCaptureVersion,
    }

    fn test_anchor(
        area: &StableAnchorAreaLocator,
        root: &Path,
        payload: &[u8],
        expected: &[u8],
    ) -> mb_store::FileAnchorManifest {
        let anchor_id = Uuid::new_v4();
        let area_dir = PinnedDirectory::open(&area.path_hint).unwrap();
        let directory = area_dir
            .create_child_directory(anchor_id.to_string())
            .unwrap();
        directory
            .publish_sealed_bytes_child("blob", payload)
            .unwrap();
        let encoded = mb_core::canonical_bytes(&TestFileManifest {
            format_version: 1,
            anchor_id,
            area,
            source_root_hint: root,
            source_relative_path: Path::new("source"),
            logical_len: expected.len() as u64,
            content_hash: mb_core::sector_root(expected),
            source_version: TestCaptureVersion {
                filesystem_id: area.filesystem_id,
                inode: 1,
                logical_len: expected.len() as u64,
                modified_secs: 0,
                modified_nanos: 0,
                changed_secs: 0,
                changed_nanos: 0,
            },
        })
        .unwrap();
        mb_core::decode_canonical(&encoded).unwrap()
    }

    #[test]
    fn damaged_git_anchor_does_not_hide_another_verified_copy() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        fs::create_dir(&root).unwrap();
        let area = StableAnchorAreaLocator::prepare_for_root(&root).unwrap();
        let control =
            ControlStore::open_with_key(temp.path().join("catalog.db"), &[43; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let bytes = b"exact\r\nblob\0";
        let oid = Oid::hash_object(git2::ObjectType::Blob, bytes).unwrap();
        let damaged = test_anchor(&area, &root, b"other\r\nblob\0", bytes);
        let viable = test_anchor(&area, &root, bytes, bytes);
        for anchor in [&damaged, &viable] {
            control
                .put_record(
                    &super::object_kind(repository_id, oid),
                    anchor.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(anchor).unwrap(),
                )
                .unwrap();
        }
        assert_eq!(
            anchors_for_oid(&control, repository_id, oid).unwrap(),
            vec![viable.clone()]
        );
        let wrong_key = Uuid::new_v4();
        control
            .put_record(
                &super::object_kind(repository_id, oid),
                wrong_key.as_bytes(),
                &mb_core::canonical_bytes(&viable).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            anchors_for_oid(&control, repository_id, oid),
            Err(StageError::IncompatibleRecord)
        ));
        let other_oid = Oid::hash_object(git2::ObjectType::Blob, b"different").unwrap();
        control
            .put_record(
                &super::object_kind(repository_id, other_oid),
                viable.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&viable).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            anchors_for_oid(&control, repository_id, other_oid),
            Err(StageError::IncompatibleRecord)
        ));
    }

    #[test]
    fn same_git_id_requires_identical_native_content_roots() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path();
        let capture = |bytes: &'static [u8]| {
            mb_store::SourceBlobImportPlan::plan_direct(root, bytes.len() as u64)
                .unwrap()
                .capture(std::io::Cursor::new(bytes))
                .unwrap()
        };
        let first = capture(b"alpha");
        let duplicate = capture(b"alpha");
        let alias = capture(b"bravo");
        super::require_same_blob_bytes(&first, &duplicate).unwrap();
        assert!(matches!(
            super::require_same_blob_bytes(&first, &alias),
            Err(StageError::Git(crate::GitAnchorError::OidCollision))
        ));
    }

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
    fn guarded_backend_rejects_symlink_stage_before_creating_temporary_input() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("work");
        let catalog_path = root.join(GIT_CATALOG_DIRECTORY);
        fs::create_dir_all(&catalog_path).unwrap();
        symlink("target", root.join("linked")).unwrap();
        let catalog = PinnedDirectory::open(&catalog_path).unwrap();
        let control =
            ControlStore::open_with_key(catalog_path.join("catalog.db"), &[37; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let scope = GitWorktreeScope::primary(repository_id);

        assert!(matches!(
            super::stage_symlink_for_scope_with_backend(
                &control,
                scope,
                &root,
                &root,
                &catalog,
                Path::new("linked"),
                SourceBackendKind::GuardedLinkFreezeV1,
            ),
            Err(StageError::Anchor(AnchorError::UnsupportedSourceOperation(
                _
            )))
        ));
        assert!(
            control
                .get_record(&super::symlink_intent_kind_for_scope(scope), b"linked")
                .unwrap()
                .is_none()
        );

        let (key, intent) = begin_symlink_stage(
            &control,
            repository_id,
            &root,
            &catalog,
            Path::new("linked"),
        )
        .unwrap();
        assert!(matches!(
            super::finish_symlink_stage(
                &control,
                scope,
                &key,
                intent.clone(),
                SourceBackendKind::GuardedLinkFreezeV1,
            ),
            Err(StageError::Anchor(AnchorError::UnsupportedSourceOperation(
                _
            )))
        ));
        assert!(
            catalog
                .entry_identity(&intent.temp_name, false)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            control
                .get_record(&super::symlink_intent_kind_for_scope(scope), &key)
                .unwrap(),
            Some(mb_core::canonical_bytes(&intent).unwrap())
        );
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
