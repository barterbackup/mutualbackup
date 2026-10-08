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
    #[error("anchor discovery failed: {0}")]
    Discovery(anyhow::Error),
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

/// Inspect original retired-anchor batches, including withdrawn root-backed
/// manifests, without normal prune admission, area discovery or physical removal.
#[cfg(target_os = "linux")]
pub(crate) fn for_each_preserved_record(
    control: &ControlStore,
    repository_id: Uuid,
    mut visit: impl FnMut(crate::PreservedGitRecord) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    let expected = intent_kind(repository_id);
    control.for_each_record_with_kind_prefix_bounded(
        INTENT_PREFIX,
        512,
        ACTIVE.len(),
        mb_core::V1_MAX_CATALOG_BYTES,
        |kind, key, bytes| {
            ensure!(
                kind == expected && key == ACTIVE,
                "invalid preserved Git prune namespace or key"
            );
            let intent: PruneIntent = decode_canonical(bytes)?;
            ensure!(
                intent.format_version == 1
                    && intent.repository_id == repository_id
                    && intent.anchors.len() <= MAX_BATCH_RECORDS
                    && mb_core::canonical_bytes_bounded(&intent, bytes.len())? == bytes,
                "invalid preserved Git prune batch or encoding"
            );
            let mut seen = HashSet::new();
            for anchor in &intent.anchors {
                anchor.preserved_ownership()?;
                ensure!(
                    seen.insert(anchor.anchor_id),
                    "duplicate preserved Git prune anchor"
                );
            }
            visit(crate::PreservedGitRecord::PruneIntent {
                repository_id,
                record_format: intent.format_version,
                anchors: intent.anchors,
            })?;
            Ok(true)
        },
    )?;
    Ok(())
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
        let path = control
            .resolve_anchor_area_location(&anchor.area)
            .map_err(|error| match error.downcast::<AnchorError>() {
                Ok(error) => GitPruneError::Anchor(error),
                Err(error) => GitPruneError::Discovery(error),
            })?;
        anchor.remove_with_area_hint(Some(&path))?;
        control
            .remember_anchor_area_location(anchor.area.area_id, &path)
            .map_err(GitPruneError::Discovery)?;
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
    let candidates = collect_candidates(control, repository_id, protected)?;

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

fn collect_candidates(
    control: &ControlStore,
    repository_id: Uuid,
    protected: &GitPruneRoots,
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
        if anchor.format_version != 1 || anchor.guarded_root_file.is_some() {
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

    #[cfg(target_os = "linux")]
    #[test]
    fn preserved_git_prune_batches_keep_original_retired_anchors_without_deletion_or_discovery() {
        use mb_store::{GuardedRootFileBacking, NativeFileId, StableAnchorAreaLocator};
        use std::{fs, path::PathBuf};
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("catalog.db");
        let control = ControlStore::open_with_key(&path, &[220; 32]).unwrap();
        let repository_id = Uuid::from_u128(220);
        let make_anchor = |index: u128, guarded: bool, imported: bool| {
            let anchor_id = Uuid::from_u128(300 + index);
            let area = StableAnchorAreaLocator {
                area_id: Uuid::from_u128(400 + index),
                path_hint: temporary.path().join("missing-area"),
                filesystem_id: 7,
                volume_root_hint: temporary.path().to_path_buf(),
            };
            let source = temporary
                .path()
                .join("missing-source")
                .as_os_str()
                .as_encoded_bytes()
                .to_vec();
            let relative = if imported {
                format!(".mutualbackup/git-import-{anchor_id}").into_bytes()
            } else {
                b"file-\xff".to_vec()
            };
            let version = (
                7_u64,
                if imported { 0_u64 } else { 9 },
                13_u64,
                0_i64,
                0_i64,
                0_i64,
                0_i64,
            );
            let bytes = if guarded {
                canonical_bytes(&(
                    2_u16,
                    anchor_id,
                    area,
                    source,
                    relative,
                    13_u64,
                    [1_u8; 32],
                    version,
                    GuardedRootFileBacking {
                        root_anchor_id: Uuid::from_u128(500 + index),
                        captured_relative_path: PathBuf::from("captured/file"),
                        native_id: NativeFileId {
                            filesystem_id: 7,
                            inode: 9,
                        },
                    },
                ))
                .unwrap()
            } else {
                canonical_bytes(&(
                    1_u16, anchor_id, area, source, relative, 13_u64, [1_u8; 32], version,
                ))
                .unwrap()
            };
            let anchor: FileAnchorManifest = decode_canonical(&bytes).unwrap();
            assert_eq!(canonical_bytes(&anchor).unwrap(), bytes);
            anchor
        };
        let anchors = vec![
            make_anchor(0, false, false),
            make_anchor(1, true, false),
            make_anchor(2, false, true),
        ];
        let bytes = canonical_bytes(&(1_u16, repository_id, &anchors)).unwrap();
        let kind = intent_kind(repository_id);
        control.put_record(&kind, ACTIVE, &bytes).unwrap();
        let snapshot = || {
            (
                fs::read(&path).unwrap(),
                fs::read(path.with_extension("db-wal")).unwrap(),
            )
        };
        let before = snapshot();
        let mut count = 0;
        for_each_preserved_record(&control, repository_id, |record| {
            let crate::PreservedGitRecord::PruneIntent {
                repository_id: actual,
                record_format,
                anchors: actual_anchors,
            } = record
            else {
                panic!("wrong record")
            };
            assert_eq!(actual, repository_id);
            assert_eq!(record_format, 1);
            assert_eq!(actual_anchors, anchors);
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 1);
        assert_eq!(snapshot(), before);
        control.delete_record(&kind, ACTIVE).unwrap();
        for count in [0, super::MAX_BATCH_RECORDS] {
            let anchors = (0..count)
                .map(|index| make_anchor(index as u128, false, false))
                .collect::<Vec<_>>();
            control
                .put_record(
                    &kind,
                    ACTIVE,
                    &canonical_bytes(&(1_u16, repository_id, anchors)).unwrap(),
                )
                .unwrap();
            assert!(for_each_preserved_record(&control, repository_id, |_| Ok(())).is_ok());
            control.delete_record(&kind, ACTIVE).unwrap();
        }
        let reject = |kind: &str, key: &[u8], bytes: &[u8]| {
            control.put_record(kind, key, bytes).unwrap();
            let before = snapshot();
            assert!(for_each_preserved_record(&control, repository_id, |_| Ok(())).is_err());
            assert_eq!(snapshot(), before);
            control.delete_record(kind, key).unwrap();
        };
        reject(
            &format!("git-prune-intent-v1/{}", Uuid::from_u128(999)),
            ACTIVE,
            &bytes,
        );
        reject(&kind, b"wrong", &bytes);
        reject(&kind, b"active-long", &bytes);
        reject(
            &kind,
            ACTIVE,
            &canonical_bytes(&(2_u16, repository_id, &anchors)).unwrap(),
        );
        reject(
            &kind,
            ACTIVE,
            &canonical_bytes(&(1_u16, Uuid::nil(), &anchors)).unwrap(),
        );
        reject(
            &kind,
            ACTIVE,
            &canonical_bytes(&(1_u16, repository_id, vec![anchors[0].clone(); 2])).unwrap(),
        );
        let too_many = (0..=super::MAX_BATCH_RECORDS)
            .map(|index| make_anchor(index as u128, false, false))
            .collect::<Vec<_>>();
        reject(
            &kind,
            ACTIVE,
            &canonical_bytes(&(1_u16, repository_id, too_many)).unwrap(),
        );
        for index in 0..4 {
            let mut bad = anchors[0].clone();
            match index {
                0 => bad.anchor_id = Uuid::nil(),
                1 => bad.area.area_id = Uuid::nil(),
                2 => bad.logical_len += 1,
                _ => bad.area.path_hint = PathBuf::from("relative"),
            }
            reject(
                &kind,
                ACTIVE,
                &canonical_bytes(&(1_u16, repository_id, vec![bad])).unwrap(),
            );
        }
        reject(&kind, ACTIVE, &[bytes, vec![0]].concat());
        reject(&kind, ACTIVE, &vec![0; mb_core::V1_MAX_CATALOG_BYTES + 1]);
        assert!(!temporary.path().join("missing-area").exists());
        assert!(!temporary.path().join("missing-source").exists());
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
