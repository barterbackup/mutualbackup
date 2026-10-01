//! Reachability-based Git catalog collection. A single encrypted intent owns
//! each batch after catalog records are retired, so a crash cannot strand a
//! mapped anchor or leave a physical deletion without a replay path.

use std::collections::{HashMap, HashSet};

use git2::Oid;
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{AnchorError, ControlStore, DatabaseError, FileAnchorManifest};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::blob_oid_from_anchor;
use crate::fetch::{FetchError, has_pending_fetch};
use crate::history::{HistoryError, export_graph_source, metadata_kind, verified_metadata_ids};
use crate::merge::{MergeBlobError, has_pending_merge_blob};
use crate::stage::{StageError, has_pending_stages, object_kind_prefix, staged_entries};

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
        anchor.remove()?;
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
    if has_pending_stages(control, repository_id)?
        || has_pending_fetch(control, repository_id)?
        || has_pending_merge_blob(control, repository_id)?
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
        mapped_blobs.insert(oid_bytes);
        indexed_anchors.remove(&(oid_bytes, anchor.anchor_id));
        if !live_blobs.contains(&oid_bytes) {
            candidates.push(Candidate {
                kind,
                key,
                anchor: Some(anchor),
            });
        }
    }
    if !indexed_anchors.is_empty() || !live_blobs.is_subset(&mapped_blobs) {
        return Err(GitPruneError::MissingProtectedObject);
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
