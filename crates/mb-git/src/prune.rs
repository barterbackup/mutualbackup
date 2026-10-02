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
    StageError, has_pending_stages, has_pending_stages_for_scope, object_kind_prefix,
    staged_entries, staged_entries_for_scope, worktree_scopes_with_stage_state,
};

const INTENT_PREFIX: &str = "git-prune-intent-v1/";
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
        if anchor.format_version != 1
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

#[cfg(test)]
mod tests {
    use super::*;

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
