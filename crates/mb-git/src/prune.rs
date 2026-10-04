//! Reachability-based Git catalog collection. A single encrypted intent owns
//! each batch after catalog records are retired, so a crash cannot strand a
//! mapped anchor or leave a physical deletion without a replay path.

use std::collections::{HashMap, HashSet};

use git2::Oid;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{
    AnchorError, ControlStore, DatabaseError, FileAnchorManifest, GuardedFileCapturePlan,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::blob_oid_from_anchor;
use crate::fetch::{FetchError, has_pending_fetch};
use crate::history::{HistoryError, export_graph_source, metadata_kind, verified_metadata_ids};
use crate::merge::{MergeBlobError, has_merge_session, has_pending_merge_blob};
use crate::stage::{
    StageError, guarded_catalog_recovery_rebinds, guarded_catalog_stage_pins,
    guarded_recovery_rebind_kind, guarded_stage_receipt_kind, has_pending_stages,
    has_pending_stages_for_scope, object_kind, object_kind_prefix, staged_entries,
    staged_entries_for_scope, worktree_scopes_with_stage_state,
};

const INTENT_PREFIX: &str = "git-prune-intent-v1/";
const GUARDED_INTENT_PREFIX: &str = "git-guarded-prune-intent-v1/";
const ACTIVE: &[u8] = b"active";
const MAX_BATCH_RECORDS: usize = 1024;

#[derive(Debug, Error)]
pub enum GitPruneError {
    #[error("Git history cannot be traversed: {0}")]
    History(#[from] HistoryError),
    #[error("Git index or anchor mapping is invalid: {0}")]
    Stage(#[from] StageError),
    #[error("a Git fetch is unfinished: {0}")]
    Fetch(#[from] FetchError),
    #[error("a Git content merge is unfinished: {0}")]
    MergeBlob(#[from] MergeBlobError),
    #[error("encrypted catalog failed: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned prune intent failed: {0}")]
    Model(#[from] ModelError),
    #[error("native anchor deletion failed: {0}")]
    Anchor(#[from] AnchorError),
    #[error("guarded native anchor retirement failed: {0}")]
    GuardedAnchor(#[from] anyhow::Error),
    #[error("Git object ID is invalid: {0}")]
    Git(#[from] git2::Error),
    #[error("a stage or fetch is in progress; finish it before pruning")]
    PendingOperation,
    #[error("the protected Git graph is missing local metadata or an anchor")]
    MissingProtectedObject,
    #[error("the Git object map or durable prune intent is incompatible")]
    IncompatibleRecord,
    #[error("Git prune candidates exceed the bounded catalog limit")]
    TooManyObjects,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GitPruneRoots {
    pub metadata_oids: HashSet<[u8; 20]>,
    pub blob_oids: HashSet<[u8; 20]>,
    /// Exact native sources still needed by local sector recipes. These may
    /// outlive the Git ref that originally named their blob.
    pub anchor_ids: HashSet<Uuid>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitPruneReport {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub metadata_objects_removed: u64,
    pub native_anchors_removed: u64,
    pub logical_anchor_bytes_removed: u64,
    /// Shared COW extents make logical bytes an invalid physical-space claim.
    pub physical_bytes_reclaimed: Option<u64>,
}

/// Read-only candidate set for a guarded repository. The node must bind this
/// exact set to a durable cross-catalog retirement before deleting any mapping
/// or releasing any node-owned pin.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitGuardedPrunePreview {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub metadata_oids: Vec<[u8; 20]>,
    pub anchors: Vec<GitGuardedPruneAnchorCandidate>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitGuardedPruneAnchorCandidate {
    pub oid: [u8; 20],
    pub manifest: FileAnchorManifest,
    /// The receipt and its node-owned pin must be retired with this mapping.
    pub attempt_id: Option<Uuid>,
}

impl GitGuardedPrunePreview {
    /// One bounded deterministic batch, with metadata before anchor mappings.
    /// The node fences only this batch, then replans after it completes.
    pub fn first_batch(&self) -> Option<Self> {
        if self.metadata_oids.is_empty() && self.anchors.is_empty() {
            return None;
        }
        let metadata_count = self.metadata_oids.len().min(MAX_BATCH_RECORDS);
        let anchor_count = self.anchors.len().min(MAX_BATCH_RECORDS - metadata_count);
        Some(Self {
            format_version: self.format_version,
            repository_id: self.repository_id,
            metadata_oids: self.metadata_oids[..metadata_count].to_vec(),
            anchors: self.anchors[..anchor_count].to_vec(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct PruneIntent {
    format_version: u16,
    repository_id: Uuid,
    anchors: Vec<FileAnchorManifest>,
}

struct Candidate {
    kind: String,
    key: Vec<u8>,
    anchor: Option<FileAnchorManifest>,
}

fn intent_kind(repository_id: Uuid) -> String {
    format!("{INTENT_PREFIX}{repository_id}")
}

fn guarded_intent_kind(repository_id: Uuid) -> String {
    format!("{GUARDED_INTENT_PREFIX}{repository_id}")
}

pub(crate) fn has_pending_guarded_prune(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<bool, GitPruneError> {
    Ok(control
        .get_record(&guarded_intent_kind(repository_id), ACTIVE)?
        .is_some())
}

fn validate_guarded_batch(batch: &GitGuardedPrunePreview) -> Result<(), GitPruneError> {
    if batch.format_version != 1
        || batch.repository_id.is_nil()
        || batch.metadata_oids.len() + batch.anchors.len() == 0
        || batch.metadata_oids.len() + batch.anchors.len() > MAX_BATCH_RECORDS
    {
        return Err(GitPruneError::IncompatibleRecord);
    }
    let mut metadata = HashSet::new();
    let mut anchors = HashSet::new();
    let mut attempts = HashSet::new();
    for oid in &batch.metadata_oids {
        if !metadata.insert(*oid) {
            return Err(GitPruneError::IncompatibleRecord);
        }
    }
    for candidate in &batch.anchors {
        if !matches!(candidate.manifest.format_version, 1 | 2)
            || candidate.manifest.format_version == 2
                && candidate.manifest.guarded_root_file.is_none()
            || candidate.manifest.format_version == 1
                && candidate.manifest.guarded_root_file.is_some()
            || !anchors.insert(candidate.manifest.anchor_id)
            || candidate
                .attempt_id
                .is_some_and(|attempt| !attempts.insert(attempt))
        {
            return Err(GitPruneError::IncompatibleRecord);
        }
    }
    Ok(())
}

fn guarded_batch_records_absent(
    control: &ControlStore,
    batch: &GitGuardedPrunePreview,
) -> Result<bool, GitPruneError> {
    let mut absent = true;
    for oid in &batch.metadata_oids {
        absent &= control
            .get_record(&metadata_kind(batch.repository_id), oid)?
            .is_none();
    }
    for candidate in &batch.anchors {
        let oid = Oid::from_bytes(&candidate.oid)?;
        absent &= control
            .get_record(
                &object_kind(batch.repository_id, oid),
                candidate.manifest.anchor_id.as_bytes(),
            )?
            .is_none();
        if let Some(attempt) = candidate.attempt_id {
            absent &= control
                .get_record(
                    &guarded_stage_receipt_kind(batch.repository_id),
                    attempt.as_bytes(),
                )?
                .is_none();
        } else if candidate.manifest.format_version == 2 {
            absent &= control
                .get_record(
                    &guarded_recovery_rebind_kind(batch.repository_id),
                    candidate.manifest.anchor_id.as_bytes(),
                )?
                .is_none();
        }
    }
    Ok(absent)
}

/// Atomically retire one node-fenced guarded batch from the Git catalog. The
/// returned `true` means its catalog intent still needs physical cleanup and
/// completion; `false` means a prior completion already removed every record.
/// No caller may invoke this before durably fencing the same batch in node
/// control, because a receipt disappears alongside its object mapping.
pub(crate) fn retire_guarded_prune_catalog(
    control: &ControlStore,
    batch: &GitGuardedPrunePreview,
    protected: &GitPruneRoots,
) -> Result<bool, GitPruneError> {
    validate_guarded_batch(batch)?;
    let intent_kind = guarded_intent_kind(batch.repository_id);
    let encoded = canonical_bytes(batch)?;
    if let Some(existing) = control.get_record(&intent_kind, ACTIVE)? {
        if existing != encoded || !guarded_batch_records_absent(control, batch)? {
            return Err(GitPruneError::IncompatibleRecord);
        }
        return Ok(true);
    }

    if guarded_batch_records_absent(control, batch)? {
        return Ok(false);
    }
    let current = preview_guarded_prune(control, batch.repository_id, protected)?;
    if current.first_batch().as_ref() != Some(batch) {
        return Err(GitPruneError::IncompatibleRecord);
    }

    let receipts = guarded_catalog_stage_pins(control, batch.repository_id)?;
    let recovered = guarded_catalog_recovery_rebinds(control, batch.repository_id)?;
    let recovered_by_anchor = recovered
        .iter()
        .map(|pin| (pin.root_file.anchor_id, pin))
        .collect::<HashMap<_, _>>();
    let by_attempt = receipts
        .iter()
        .map(|pin| (pin.attempt_id, pin))
        .collect::<HashMap<_, _>>();
    let mut deletions = Vec::with_capacity(batch.metadata_oids.len() + batch.anchors.len() * 2);
    let mut present = 0usize;
    for oid in &batch.metadata_oids {
        let kind = metadata_kind(batch.repository_id);
        present += usize::from(control.get_record(&kind, oid)?.is_some());
        deletions.push((kind, oid.to_vec()));
    }
    for candidate in &batch.anchors {
        let oid = Oid::from_bytes(&candidate.oid)?;
        let kind = object_kind(batch.repository_id, oid);
        let mapped = control.get_record(&kind, candidate.manifest.anchor_id.as_bytes())?;
        let expected = canonical_bytes(&candidate.manifest)?;
        if mapped
            .as_deref()
            .is_some_and(|bytes| bytes != expected.as_slice())
        {
            return Err(GitPruneError::IncompatibleRecord);
        }
        present += usize::from(mapped.is_some());
        deletions.push((kind, candidate.manifest.anchor_id.as_bytes().to_vec()));
        if let Some(attempt) = candidate.attempt_id {
            if by_attempt
                .get(&attempt)
                .copied()
                .is_some_and(|pin| pin.manifest != candidate.manifest)
                || mapped.is_some() && !by_attempt.contains_key(&attempt)
            {
                return Err(GitPruneError::IncompatibleRecord);
            }
            let kind = guarded_stage_receipt_kind(batch.repository_id);
            present += usize::from(control.get_record(&kind, attempt.as_bytes())?.is_some());
            deletions.push((kind, attempt.as_bytes().to_vec()));
        } else if candidate.manifest.format_version == 2 {
            let recovered = recovered_by_anchor
                .get(&candidate.manifest.anchor_id)
                .ok_or(GitPruneError::IncompatibleRecord)?;
            if recovered.root_file != candidate.manifest
                || recovered.oid != candidate.oid
                || receipts
                    .iter()
                    .any(|pin| pin.manifest.anchor_id == candidate.manifest.anchor_id)
            {
                return Err(GitPruneError::IncompatibleRecord);
            }
            let kind = guarded_recovery_rebind_kind(batch.repository_id);
            present += usize::from(
                control
                    .get_record(&kind, candidate.manifest.anchor_id.as_bytes())?
                    .is_some(),
            );
            deletions.push((kind, candidate.manifest.anchor_id.as_bytes().to_vec()));
        } else if receipts
            .iter()
            .any(|pin| pin.manifest.anchor_id == candidate.manifest.anchor_id)
        {
            return Err(GitPruneError::IncompatibleRecord);
        }
    }
    if present != deletions.len() {
        return Err(GitPruneError::IncompatibleRecord);
    }
    control.put_records_and_delete(&[(intent_kind, ACTIVE.to_vec(), encoded)], &deletions)?;
    Ok(true)
}

pub(crate) fn complete_guarded_prune_catalog(
    control: &ControlStore,
    batch: &GitGuardedPrunePreview,
) -> Result<(), GitPruneError> {
    validate_guarded_batch(batch)?;
    if !guarded_batch_records_absent(control, batch)? {
        return Err(GitPruneError::IncompatibleRecord);
    }
    let kind = guarded_intent_kind(batch.repository_id);
    let Some(existing) = control.get_record(&kind, ACTIVE)? else {
        return Ok(());
    };
    let encoded = canonical_bytes(batch)?;
    if existing != encoded {
        return Err(GitPruneError::IncompatibleRecord);
    }
    control.delete_record_if_value(&kind, ACTIVE, &encoded)?;
    Ok(())
}

pub(crate) fn has_pending_prune(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<bool, GitPruneError> {
    Ok(control
        .get_record(&intent_kind(repository_id), ACTIVE)?
        .is_some())
}

#[cfg(test)]
thread_local! {
    static AFTER_CATALOG_DELETE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_catalog_delete_hook(hook: Box<dyn FnOnce()>) {
    AFTER_CATALOG_DELETE.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_catalog_delete_hook() {
    #[cfg(test)]
    AFTER_CATALOG_DELETE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

fn retained_physical_ids(
    live_blobs: &HashSet<[u8; 20]>,
    pinned: &HashSet<Uuid>,
    mapped: impl Iterator<Item = ([u8; 20], u64, Uuid)>,
) -> HashSet<Uuid> {
    let mut retained = pinned.clone();
    let mut by_filesystem = HashMap::<([u8; 20], u64), (Uuid, bool)>::new();
    for (oid, filesystem_id, anchor_id) in mapped {
        if !live_blobs.contains(&oid) {
            continue;
        }
        let entry = by_filesystem
            .entry((oid, filesystem_id))
            .or_insert((anchor_id, false));
        entry.0 = entry.0.min(anchor_id);
        entry.1 |= pinned.contains(&anchor_id);
    }
    for (fallback, has_pin) in by_filesystem.into_values() {
        if !has_pin {
            retained.insert(fallback);
        }
    }
    retained
}

/// Finish physical deletion after an atomic catalog retirement. Anchor removal
/// is idempotent, including when a crash occurred between two removals.
pub(crate) fn resume_pending_prune(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<(), GitPruneError> {
    let kind = intent_kind(repository_id);
    let Some(encoded) = control.get_record(&kind, ACTIVE)? else {
        return Ok(());
    };
    let intent: PruneIntent = decode_canonical(&encoded)?;
    if intent.format_version != 1
        || intent.repository_id != repository_id
        || intent.anchors.len() > MAX_BATCH_RECORDS
    {
        return Err(GitPruneError::IncompatibleRecord);
    }
    let mut seen = HashSet::new();
    for anchor in &intent.anchors {
        if anchor.format_version != 1 || !seen.insert(anchor.anchor_id) {
            return Err(GitPruneError::IncompatibleRecord);
        }
        if let Some(plan) = GuardedFileCapturePlan::load_for_manifest(control, anchor)? {
            plan.discard_unreferenced(control)?;
        } else {
            anchor.remove()?;
        }
    }
    control.delete_record_if_value(&kind, ACTIVE, &encoded)?;
    Ok(())
}

/// Remove only objects outside live refs, the staged index, and the supplied
/// signed-revision roots. The daemon must supply every retained signed graph
/// and must reject in-flight backup graph capture before calling this function.
pub(crate) fn prune_unreachable(
    control: &ControlStore,
    repository_id: Uuid,
    protected: &GitPruneRoots,
) -> Result<GitPruneReport, GitPruneError> {
    resume_pending_prune(control, repository_id)?;
    let candidates = collect_candidates(control, repository_id, protected, false)?;

    let mut report = GitPruneReport {
        format_version: 1,
        repository_id,
        ..GitPruneReport::default()
    };
    for batch in candidates.chunks(MAX_BATCH_RECORDS) {
        let mut anchors = Vec::new();
        let mut deletions = Vec::with_capacity(batch.len());
        for candidate in batch {
            deletions.push((candidate.kind.clone(), candidate.key.clone()));
            if let Some(anchor) = &candidate.anchor {
                anchors.push(anchor.clone());
                report.native_anchors_removed += 1;
                report.logical_anchor_bytes_removed = report
                    .logical_anchor_bytes_removed
                    .checked_add(anchor.logical_len)
                    .ok_or(GitPruneError::TooManyObjects)?;
            } else {
                report.metadata_objects_removed += 1;
            }
        }
        let intent = PruneIntent {
            format_version: 1,
            repository_id,
            anchors,
        };
        control.put_records_and_delete(
            &[(
                intent_kind(repository_id),
                ACTIVE.to_vec(),
                canonical_bytes(&intent)?,
            )],
            &deletions,
        )?;
        run_after_catalog_delete_hook();
        resume_pending_prune(control, repository_id)?;
    }
    Ok(report)
}

pub(crate) fn preview_guarded_prune(
    control: &ControlStore,
    repository_id: Uuid,
    protected: &GitPruneRoots,
) -> Result<GitGuardedPrunePreview, GitPruneError> {
    if has_pending_prune(control, repository_id)?
        || has_pending_guarded_prune(control, repository_id)?
    {
        return Err(GitPruneError::IncompatibleRecord);
    }
    let receipts = guarded_catalog_stage_pins(control, repository_id)?;
    let by_anchor = receipts
        .iter()
        .map(|pin| (pin.manifest.anchor_id, pin.attempt_id))
        .collect::<HashMap<_, _>>();
    let mut preview = GitGuardedPrunePreview {
        format_version: 1,
        repository_id,
        metadata_oids: Vec::new(),
        anchors: Vec::new(),
    };
    for candidate in collect_candidates(control, repository_id, protected, true)? {
        if let Some(manifest) = candidate.anchor {
            let oid = candidate
                .kind
                .strip_prefix(&object_kind_prefix(repository_id))
                .ok_or(GitPruneError::IncompatibleRecord)?;
            let oid = Oid::from_str(oid).map_err(|_| GitPruneError::IncompatibleRecord)?;
            preview.anchors.push(GitGuardedPruneAnchorCandidate {
                oid: oid.as_bytes().try_into().expect("SHA-1 OID"),
                attempt_id: by_anchor.get(&manifest.anchor_id).copied(),
                manifest,
            });
        } else {
            preview.metadata_oids.push(
                candidate
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| GitPruneError::IncompatibleRecord)?,
            );
        }
    }
    Ok(preview)
}

fn collect_candidates(
    control: &ControlStore,
    repository_id: Uuid,
    protected: &GitPruneRoots,
    allow_guarded_root_files: bool,
) -> Result<Vec<Candidate>, GitPruneError> {
    let linked_scopes = worktree_scopes_with_stage_state(control, repository_id)?;
    if has_pending_stages(control, repository_id)?
        || linked_scopes.iter().try_fold(false, |pending, scope| {
            Ok::<_, StageError>(pending || has_pending_stages_for_scope(control, *scope)?)
        })?
        || has_pending_fetch(control, repository_id)?
        || has_pending_merge_blob(control, repository_id)?
        || has_merge_session(control, repository_id)?
    {
        return Err(GitPruneError::PendingOperation);
    }
    let graph = export_graph_source(control, repository_id)?;
    let mut live_metadata = graph
        .objects
        .iter()
        .map(|object| object.oid)
        .collect::<HashSet<_>>();
    live_metadata.extend(&protected.metadata_oids);
    let mut live_blobs = graph
        .blobs
        .iter()
        .map(|blob| blob.oid)
        .collect::<HashSet<_>>();
    live_blobs.extend(&protected.blob_oids);
    let index = staged_entries(control, repository_id)?;
    let mut indexed_anchors = HashSet::new();
    for (_, entry) in index {
        live_blobs.insert(entry.oid);
        indexed_anchors.insert((entry.oid, entry.anchor_id));
    }
    for scope in linked_scopes {
        for (_, entry) in staged_entries_for_scope(control, scope)? {
            live_blobs.insert(entry.oid);
            indexed_anchors.insert((entry.oid, entry.anchor_id));
        }
    }
    let mut pinned_anchors = protected.anchor_ids.clone();
    pinned_anchors.extend(indexed_anchors.iter().map(|(_, anchor_id)| *anchor_id));

    let all_metadata = verified_metadata_ids(control, repository_id)?;
    if live_metadata
        .iter()
        .any(|oid| !all_metadata.contains(&Oid::from_bytes(oid).expect("SHA-1 OID")))
    {
        return Err(GitPruneError::MissingProtectedObject);
    }
    let mut candidates = Vec::new();
    for oid in all_metadata {
        let key = oid.as_bytes().to_vec();
        if !live_metadata.contains(key.as_slice()) {
            candidates.push(Candidate {
                kind: metadata_kind(repository_id),
                key,
                anchor: None,
            });
        }
    }

    let prefix = object_kind_prefix(repository_id);
    let mut mapped_anchors = HashMap::new();
    let mut mapped_blobs = HashSet::new();
    let mut native_by_oid = HashMap::new();
    let mut mapped = Vec::new();
    for (kind, key, encoded) in control.records_with_kind_prefix(&prefix)? {
        let suffix = kind
            .strip_prefix(&prefix)
            .ok_or(GitPruneError::IncompatibleRecord)?;
        let oid = Oid::from_str(suffix).map_err(|_| GitPruneError::IncompatibleRecord)?;
        if suffix.len() != 40 || suffix != oid.to_string() {
            return Err(GitPruneError::IncompatibleRecord);
        }
        let anchor: FileAnchorManifest = decode_canonical(&encoded)?;
        if !(anchor.format_version == 1 && anchor.guarded_root_file.is_none()
            || allow_guarded_root_files
                && anchor.format_version == 2
                && anchor.guarded_root_file.is_some())
            || key != anchor.anchor_id.as_bytes()
            || blob_oid_from_anchor(&anchor).map_err(StageError::from)? != oid
            || mapped_anchors.insert(anchor.anchor_id, oid).is_some()
        {
            return Err(GitPruneError::IncompatibleRecord);
        }
        let oid_bytes: [u8; 20] = oid.as_bytes().try_into().expect("SHA-1 OID");
        if native_by_oid
            .insert(oid_bytes, (anchor.content_hash, anchor.logical_len))
            .is_some_and(|previous| previous != (anchor.content_hash, anchor.logical_len))
        {
            return Err(GitPruneError::IncompatibleRecord);
        }
        mapped_blobs.insert(oid_bytes);
        indexed_anchors.remove(&(oid_bytes, anchor.anchor_id));
        mapped.push((oid_bytes, kind, key, anchor));
    }
    if !indexed_anchors.is_empty() || !live_blobs.is_subset(&mapped_blobs) {
        return Err(GitPruneError::MissingProtectedObject);
    }

    // An OID can have many independently captured reflinks. Keep exact index
    // and recipe sources, then one source per filesystem for each live blob.
    // This keeps checkout possible without retaining every redundant capture.
    let retained_anchors = retained_physical_ids(
        &live_blobs,
        &pinned_anchors,
        mapped
            .iter()
            .map(|(oid, _, _, anchor)| (*oid, anchor.area.filesystem_id, anchor.anchor_id)),
    );
    for (_, kind, key, anchor) in mapped {
        if !retained_anchors.contains(&anchor.anchor_id) {
            candidates.push(Candidate {
                kind,
                key,
                anchor: Some(anchor),
            });
        }
    }
    if candidates.len() > crate::history::MAX_GRAPH_OBJECTS * 2 {
        return Err(GitPruneError::TooManyObjects);
    }
    candidates.sort_by(|left, right| (&left.kind, &left.key).cmp(&(&right.kind, &right.key)));
    Ok(candidates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitWorktreeScope;
    use crate::stage::{publish_guarded_stage_for_scope, remove_cached};
    use mb_store::{GuardedGitStagePin, SourceBlobImportPlan};

    #[test]
    fn guarded_preview_names_receipt_and_preserves_catalog_until_retirement() {
        let temporary = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(temporary.path().join("catalog.db"), &[41; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let manifest = SourceBlobImportPlan::plan_direct(temporary.path(), 5)
            .unwrap()
            .capture(std::io::Cursor::new(b"bytes"))
            .unwrap();
        let pin = GuardedGitStagePin {
            repository_id,
            root_anchor_id: Uuid::new_v4(),
            manifest: manifest.clone(),
            attempt_id: Uuid::new_v4(),
            worktree_id: repository_id,
            relative_path: b"tracked".to_vec(),
            git_mode: 0o100644,
        };
        let entry = publish_guarded_stage_for_scope(
            &control,
            GitWorktreeScope::primary(repository_id),
            &pin,
        )
        .unwrap();
        assert!(
            preview_guarded_prune(&control, repository_id, &GitPruneRoots::default())
                .unwrap()
                .anchors
                .is_empty()
        );
        assert!(remove_cached(&control, repository_id, "tracked").unwrap());
        let preview =
            preview_guarded_prune(&control, repository_id, &GitPruneRoots::default()).unwrap();
        assert_eq!(preview.format_version, 1);
        assert!(preview.metadata_oids.is_empty());
        assert_eq!(preview.anchors.len(), 1);
        assert_eq!(preview.anchors[0].oid, entry.oid);
        assert_eq!(preview.anchors[0].manifest, manifest);
        assert_eq!(preview.anchors[0].attempt_id, Some(pin.attempt_id));
        assert_eq!(
            guarded_catalog_stage_pins(&control, repository_id).unwrap(),
            vec![pin.clone()]
        );
        let protected = GitPruneRoots {
            anchor_ids: std::iter::once(manifest.anchor_id).collect(),
            ..GitPruneRoots::default()
        };
        assert!(
            preview_guarded_prune(&control, repository_id, &protected)
                .unwrap()
                .anchors
                .is_empty()
        );
        assert!(matches!(
            retire_guarded_prune_catalog(&control, &preview, &protected),
            Err(GitPruneError::IncompatibleRecord)
        ));
        let mut wrong = preview.clone();
        wrong.anchors[0].attempt_id = Some(Uuid::new_v4());
        assert!(matches!(
            retire_guarded_prune_catalog(&control, &wrong, &GitPruneRoots::default()),
            Err(GitPruneError::IncompatibleRecord)
        ));
        assert_eq!(
            guarded_catalog_stage_pins(&control, repository_id).unwrap(),
            vec![pin]
        );

        assert!(
            retire_guarded_prune_catalog(&control, &preview, &GitPruneRoots::default()).unwrap()
        );
        assert!(matches!(
            preview_guarded_prune(&control, repository_id, &GitPruneRoots::default()),
            Err(GitPruneError::IncompatibleRecord)
        ));
        assert!(matches!(
            retire_guarded_prune_catalog(&control, &wrong, &GitPruneRoots::default()),
            Err(GitPruneError::IncompatibleRecord)
        ));
        assert!(matches!(
            complete_guarded_prune_catalog(&control, &wrong),
            Err(GitPruneError::IncompatibleRecord)
        ));
        assert!(
            control
                .get_record(&guarded_intent_kind(repository_id), ACTIVE)
                .unwrap()
                .is_some()
        );
        assert!(
            guarded_catalog_stage_pins(&control, repository_id)
                .unwrap()
                .is_empty()
        );
        assert!(
            control
                .get_record(
                    &object_kind(repository_id, Oid::from_bytes(&entry.oid).unwrap()),
                    manifest.anchor_id.as_bytes()
                )
                .unwrap()
                .is_none()
        );
        drop(control);
        let reopened =
            ControlStore::open_existing_with_key(temporary.path().join("catalog.db"), &[41; 32])
                .unwrap();
        assert!(
            retire_guarded_prune_catalog(&reopened, &preview, &GitPruneRoots::default()).unwrap()
        );
        complete_guarded_prune_catalog(&reopened, &preview).unwrap();
        assert!(
            !retire_guarded_prune_catalog(&reopened, &preview, &GitPruneRoots::default()).unwrap()
        );
        complete_guarded_prune_catalog(&reopened, &preview).unwrap();
        manifest.remove().unwrap();
    }

    #[test]
    fn physical_prune_pins_recipes_and_index_and_keeps_one_source_per_filesystem() {
        let live = [1; 20];
        let dead = [2; 20];
        let a = Uuid::from_u128(1);
        let b = Uuid::from_u128(2);
        let c = Uuid::from_u128(3);
        let d = Uuid::from_u128(4);
        let e = Uuid::from_u128(5);
        let retained = retained_physical_ids(
            &HashSet::from([live]),
            &HashSet::from([b, d]),
            [
                (live, 1, a),
                (live, 1, b),
                (live, 2, c),
                (dead, 1, d),
                (dead, 1, e),
            ]
            .into_iter(),
        );
        assert_eq!(retained, HashSet::from([b, c, d]));
        let without_pins = retained_physical_ids(
            &HashSet::from([live]),
            &HashSet::new(),
            [(live, 1, b), (live, 1, a), (live, 2, c), (dead, 1, d)].into_iter(),
        );
        assert_eq!(without_pins, HashSet::from([a, c]));
    }
}
