//! Raw-byte content merges and replayable capture of their generated blobs.
//! Libgit2's file merge consumes verified native anchors; its output is never
//! written to a persistent Git object directory.

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

use git2::{IndexEntry, IndexTime, ObjectType, Oid, Repository};
use mb_core::{ModelError, canonical_bytes, decode_canonical};
use mb_store::{AnchorError, ControlStore, DatabaseError, SourceBlobImportPlan};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::stage::{StageError, anchors_for_oid, object_kind, stage_path_key};
use crate::{GitAnchorError, NativeOdb, blob_oid_from_anchor};

const INTENT_PREFIX: &str = "git-merge-blob-intent-v1/";
const ACTIVE: &[u8] = b"active";
pub(crate) const MAX_AUTOMERGE_FILE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum MergeBlobError {
    #[error("native merge blob capture error: {0}")]
    Anchor(#[from] AnchorError),
    #[error("native Git blob verification error: {0}")]
    GitAnchor(#[from] GitAnchorError),
    #[error("Git content merge error: {0}")]
    Git(#[from] git2::Error),
    #[error("encrypted Git catalog error: {0}")]
    Database(#[from] DatabaseError),
    #[error("versioned merge intent error: {0}")]
    Model(#[from] ModelError),
    #[error("Git merge path error: {0}")]
    Stage(#[from] StageError),
    #[error("merge blob read error: {0}")]
    Io(#[from] std::io::Error),
    #[error("the pending merge blob or an existing Git object is incompatible")]
    IncompatibleRecord,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MergeFileInput {
    pub oid: [u8; 20],
    pub mode: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MergeFileInputs {
    pub base: MergeFileInput,
    pub ours: MergeFileInput,
    pub theirs: MergeFileInput,
}

pub(crate) struct GeneratedBlob {
    pub oid: Oid,
    pub mode: u32,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MergeBlobIntent {
    format_version: u16,
    repository_id: Uuid,
    path: Vec<u8>,
    inputs: MergeFileInputs,
    result_oid: [u8; 20],
    result_mode: u32,
    plan: SourceBlobImportPlan,
}

fn intent_kind(repository_id: Uuid) -> String {
    format!("{INTENT_PREFIX}{repository_id}")
}

fn index_entry(path: &[u8], input: MergeFileInput) -> Result<IndexEntry, MergeBlobError> {
    Ok(IndexEntry {
        ctime: IndexTime::new(0, 0),
        mtime: IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: input.mode,
        uid: 0,
        gid: 0,
        file_size: 0,
        id: Oid::from_bytes(&input.oid)?,
        flags: 0,
        flags_extended: 0,
        path: path.to_vec(),
    })
}

pub(crate) fn merge_file_bytes(
    control: &ControlStore,
    repository_id: Uuid,
    path: &[u8],
    inputs: MergeFileInputs,
) -> Result<Option<GeneratedBlob>, MergeBlobError> {
    let MergeFileInputs { base, ours, theirs } = inputs;
    if !matches!(base.mode, 0o100644 | 0o100755)
        || base.mode != ours.mode
        || base.mode != theirs.mode
    {
        return Ok(None);
    }
    let mut anchors = Vec::new();
    for input in [base, ours, theirs] {
        let anchor = anchors_for_oid(control, repository_id, Oid::from_bytes(&input.oid)?)?
            .into_iter()
            .next()
            .ok_or(MergeBlobError::IncompatibleRecord)?;
        if anchor.logical_len > MAX_AUTOMERGE_FILE_BYTES {
            return Ok(None);
        }
        anchors.push(anchor);
    }
    let temporary = tempfile::tempdir()?;
    let repository = Repository::init_bare(temporary.path())?;
    let native_odb = NativeOdb::from_anchors(anchors)?;
    repository.set_odb(native_odb.odb())?;
    let result = repository.merge_file_from_index(
        &index_entry(path, base)?,
        &index_entry(path, ours)?,
        &index_entry(path, theirs)?,
        None,
    )?;
    if !result.is_automergeable()
        || result.mode() != ours.mode
        || result.content().len() as u64 > MAX_AUTOMERGE_FILE_BYTES
    {
        return Ok(None);
    }
    let bytes = result.content().to_vec();
    let oid = Oid::hash_object(ObjectType::Blob, &bytes)?;
    Ok(Some(GeneratedBlob {
        oid,
        mode: result.mode(),
        bytes,
    }))
}

fn verify_existing_blob(
    control: &ControlStore,
    repository_id: Uuid,
    blob: &GeneratedBlob,
) -> Result<bool, MergeBlobError> {
    let anchors = anchors_for_oid(control, repository_id, blob.oid)?;
    for anchor in &anchors {
        if anchor.logical_len != blob.bytes.len() as u64
            || blob_oid_from_anchor(anchor)? != blob.oid
        {
            return Err(MergeBlobError::IncompatibleRecord);
        }
        let mut bytes = Vec::with_capacity(blob.bytes.len());
        anchor.open_verified()?.read_to_end(&mut bytes)?;
        if bytes != blob.bytes {
            return Err(MergeBlobError::IncompatibleRecord);
        }
    }
    Ok(!anchors.is_empty())
}

#[cfg(test)]
thread_local! {
    static AFTER_MERGE_BLOB_CAPTURE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

#[cfg(test)]
pub(crate) fn set_after_merge_blob_capture_hook(hook: Box<dyn FnOnce()>) {
    AFTER_MERGE_BLOB_CAPTURE.with(|slot| *slot.borrow_mut() = Some(hook));
}

fn run_after_merge_blob_capture_hook() {
    #[cfg(test)]
    AFTER_MERGE_BLOB_CAPTURE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

pub(crate) fn capture_generated_blob(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
    path: &[u8],
    inputs: MergeFileInputs,
    blob: &GeneratedBlob,
) -> Result<(), MergeBlobError> {
    if verify_existing_blob(control, repository_id, blob)? {
        return Ok(());
    }
    let intent = MergeBlobIntent {
        format_version: 1,
        repository_id,
        path: path.to_vec(),
        inputs,
        result_oid: blob.oid.as_bytes().try_into().expect("SHA-1 OID"),
        result_mode: blob.mode,
        plan: SourceBlobImportPlan::plan_direct(root_path, blob.bytes.len() as u64)?,
    };
    if !control.put_record_if_absent(
        &intent_kind(repository_id),
        ACTIVE,
        &canonical_bytes(&intent)?,
    )? {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    resume_pending_merge_blob(control, repository_id, root_path)
}

pub(crate) fn has_pending_merge_blob(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<bool, MergeBlobError> {
    Ok(control
        .get_record(&intent_kind(repository_id), ACTIVE)?
        .is_some())
}

pub(crate) fn resume_pending_merge_blob(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
) -> Result<(), MergeBlobError> {
    let kind = intent_kind(repository_id);
    let Some(encoded) = control.get_record(&kind, ACTIVE)? else {
        return Ok(());
    };
    let intent: MergeBlobIntent = decode_canonical(&encoded)?;
    let relative = PathBuf::from(OsString::from_vec(intent.path.clone()));
    if intent.format_version != 1
        || intent.repository_id != repository_id
        || stage_path_key(&relative)? != intent.path
        || intent.plan.source_root() != root_path
        || intent.plan.logical_len() > MAX_AUTOMERGE_FILE_BYTES
        || !matches!(intent.result_mode, 0o100644 | 0o100755)
    {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    intent.plan.reconcile()?;
    let result = merge_file_bytes(control, repository_id, &intent.path, intent.inputs)?
        .ok_or(MergeBlobError::IncompatibleRecord)?;
    if result.oid.as_bytes() != intent.result_oid
        || result.mode != intent.result_mode
        || result.bytes.len() as u64 != intent.plan.logical_len()
    {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    let anchor = match intent.plan.capture(std::io::empty()) {
        Ok(anchor) => anchor,
        Err(AnchorError::SourceChanged(_)) => intent.plan.capture(result.bytes.as_slice())?,
        Err(error) => return Err(error.into()),
    };
    run_after_merge_blob_capture_hook();
    if anchor.logical_len != intent.plan.logical_len()
        || blob_oid_from_anchor(&anchor)?.as_bytes() != intent.result_oid
    {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    let mut captured = Vec::with_capacity(result.bytes.len());
    anchor.open_verified()?.read_to_end(&mut captured)?;
    if captured != result.bytes {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    control.put_records_and_retire_if_value(
        &[(
            object_kind(repository_id, Oid::from_bytes(&intent.result_oid)?),
            anchor.anchor_id.as_bytes().to_vec(),
            canonical_bytes(&anchor)?,
        )],
        &kind,
        ACTIVE,
        &encoded,
    )?;
    Ok(())
}
