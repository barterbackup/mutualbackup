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
use crate::{GitAnchorError, GitWorktreeScope, NativeOdb, NativeSource, blob_oid_from_anchor};

const INTENT_PREFIX: &str = "git-merge-blob-intent-v1/";
const LINKED_INTENT_PREFIX: &str = "git-worktree-merge-blob-intent-v1/";
const SESSION_PREFIX: &str = "git-merge-session-v1/";
const LINKED_SESSION_PREFIX: &str = "git-worktree-merge-session-v1/";
const ACTIVE: &[u8] = b"active";
pub(crate) type SessionRecord = (String, Vec<u8>, Vec<u8>);
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
    #[error("the pending merge state or an existing Git object is incompatible")]
    IncompatibleRecord,
    #[error("a merge session is already pending")]
    PendingSession,
    #[error("there is no merge session to continue or abort")]
    MissingSession,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitMergeState {
    pub source_ref: Vec<u8>,
    pub ours: [u8; 20],
    pub theirs: [u8; 20],
    pub unresolved_paths: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct MergeSession {
    pub format_version: u16,
    pub repository_id: Uuid,
    pub branch: String,
    pub ours: [u8; 20],
    pub theirs: [u8; 20],
    pub source_ref: Vec<u8>,
    pub author_name: String,
    pub author_email: String,
    pub message: String,
    pub conflicts: Vec<Vec<u8>>,
    pub resolved: Vec<Vec<u8>>,
}

#[derive(Serialize, Deserialize)]
struct LinkedMergeSessionV1 {
    format_version: u16,
    worktree_id: Uuid,
    session: MergeSession,
}

pub(crate) fn session_kind(repository_id: Uuid) -> String {
    format!("{SESSION_PREFIX}{repository_id}")
}

pub(crate) fn session_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(SESSION_PREFIX, LINKED_SESSION_PREFIX)
}

fn encode_session_for_scope(
    scope: GitWorktreeScope,
    session: &MergeSession,
) -> Result<Vec<u8>, MergeBlobError> {
    if scope.worktree_id() == scope.repository_id() {
        Ok(canonical_bytes(session)?)
    } else {
        Ok(canonical_bytes(&LinkedMergeSessionV1 {
            format_version: 1,
            worktree_id: scope.worktree_id(),
            session: session.clone(),
        })?)
    }
}

pub(crate) fn session_key() -> &'static [u8] {
    ACTIVE
}

fn validate_session(session: &MergeSession, repository_id: Uuid) -> Result<(), MergeBlobError> {
    let reference =
        std::str::from_utf8(&session.source_ref).map_err(|_| MergeBlobError::IncompatibleRecord)?;
    let prefix = if reference.starts_with("refs/remotes/origin/") {
        "refs/remotes/origin/"
    } else {
        "refs/heads/"
    };
    if session.format_version != 1
        || session.repository_id != repository_id
        || session.branch.len() > 1024
        || !git2::Branch::name_is_valid(&session.branch)?
        || session.source_ref.len() > prefix.len() + 1024
        || !reference.starts_with(prefix)
        || !git2::Reference::is_valid_name(reference)
        || session.author_name.is_empty()
        || session.author_email.is_empty()
        || session.conflicts.is_empty()
        || session.conflicts.len() > 8_192
        || session.conflicts.windows(2).any(|pair| pair[0] >= pair[1])
        || session.resolved.windows(2).any(|pair| pair[0] >= pair[1])
        || session
            .resolved
            .iter()
            .any(|path| session.conflicts.binary_search(path).is_err())
    {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    for path in &session.conflicts {
        let relative = PathBuf::from(OsString::from_vec(path.clone()));
        if stage_path_key(&relative)? != *path {
            return Err(MergeBlobError::IncompatibleRecord);
        }
    }
    Ok(())
}

#[cfg(test)]
mod scoped_session_tests {
    use super::*;

    #[test]
    fn linked_merge_sessions_bind_worktree_and_keep_primary_record_compatible() {
        let database = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(database.path().join("catalog.db"), &[68; 32]).unwrap();
        let repository_id = Uuid::new_v4();
        let primary = GitWorktreeScope::primary(repository_id);
        let linked = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let other = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let session = MergeSession {
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
        };
        store_merge_session_for_scope(&control, primary, &session).unwrap();
        store_merge_session_for_scope(&control, linked, &session).unwrap();
        assert_eq!(
            control
                .get_record(&session_kind(repository_id), ACTIVE)
                .unwrap(),
            Some(canonical_bytes(&session).unwrap())
        );
        assert_eq!(
            load_merge_session_for_scope(&control, linked)
                .unwrap()
                .unwrap()
                .0,
            session
        );
        assert!(
            load_merge_session_for_scope(&control, other)
                .unwrap()
                .is_none()
        );
        mark_merge_resolved_for_scope(&control, linked, b"tracked").unwrap();
        assert!(
            merge_state_for_scope(&control, linked)
                .unwrap()
                .unwrap()
                .unresolved_paths
                .is_empty()
        );
        assert_eq!(
            merge_state_for_scope(&control, primary)
                .unwrap()
                .unwrap()
                .unresolved_paths,
            vec![b"tracked".to_vec()]
        );
        let (kind, key, bytes) = resolution_record_for_scope(&control, linked, b"tracked", false)
            .unwrap()
            .unwrap();
        control.put_record(&kind, &key, &bytes).unwrap();
        assert_eq!(
            merge_state_for_scope(&control, linked)
                .unwrap()
                .unwrap()
                .unresolved_paths,
            vec![b"tracked".to_vec()]
        );
        assert!(has_merge_session_outside_scope(&control, linked).unwrap());
        control
            .delete_record(&session_kind(repository_id), ACTIVE)
            .unwrap();
        assert!(has_merge_session(&control, repository_id).unwrap());
        assert!(!has_merge_session_outside_scope(&control, linked).unwrap());
        store_merge_session_for_scope(&control, other, &session).unwrap();
        assert!(has_merge_session_outside_scope(&control, linked).unwrap());
        let wrong = canonical_bytes(&LinkedMergeSessionV1 {
            format_version: 1,
            worktree_id: other.worktree_id(),
            session: session.clone(),
        })
        .unwrap();
        control
            .put_record(&session_kind_for_scope(linked), ACTIVE, &wrong)
            .unwrap();
        assert!(matches!(
            load_merge_session_for_scope(&control, linked),
            Err(MergeBlobError::IncompatibleRecord)
        ));
    }
}

pub(crate) fn load_merge_session(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Option<(MergeSession, Vec<u8>)>, MergeBlobError> {
    let Some(encoded) = control.get_record(&session_kind(repository_id), ACTIVE)? else {
        return Ok(None);
    };
    let session: MergeSession = decode_canonical(&encoded)?;
    validate_session(&session, repository_id)?;
    Ok(Some((session, encoded)))
}

pub(crate) fn load_merge_session_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Option<(MergeSession, Vec<u8>)>, MergeBlobError> {
    if scope.worktree_id() == scope.repository_id() {
        return load_merge_session(control, scope.repository_id());
    }
    let Some(encoded) = control.get_record(&session_kind_for_scope(scope), ACTIVE)? else {
        return Ok(None);
    };
    let linked: LinkedMergeSessionV1 = decode_canonical(&encoded)?;
    if linked.format_version != 1 || linked.worktree_id != scope.worktree_id() {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    validate_session(&linked.session, scope.repository_id())?;
    Ok(Some((linked.session, encoded)))
}

pub(crate) fn has_merge_session(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<bool, MergeBlobError> {
    if load_merge_session(control, repository_id)?.is_some() {
        return Ok(true);
    }
    let linked_prefix = format!("{LINKED_SESSION_PREFIX}{repository_id}/");
    Ok(!control.records_with_kind_prefix(&linked_prefix)?.is_empty())
}

pub(crate) fn has_merge_session_outside_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<bool, MergeBlobError> {
    if load_merge_session(control, scope.repository_id())?.is_some() {
        return Ok(true);
    }
    let linked_prefix = format!("{LINKED_SESSION_PREFIX}{}/", scope.repository_id());
    let own_kind = session_kind_for_scope(scope);
    Ok(control
        .records_with_kind_prefix(&linked_prefix)?
        .iter()
        .any(|(kind, key, _)| kind != &own_kind || key.as_slice() != ACTIVE))
}

pub(crate) fn has_merge_session_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<bool, MergeBlobError> {
    Ok(load_merge_session_for_scope(control, scope)?.is_some())
}

pub(crate) fn store_merge_session_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    session: &MergeSession,
) -> Result<(), MergeBlobError> {
    validate_session(session, scope.repository_id())?;
    if !control.put_record_if_absent(
        &session_kind_for_scope(scope),
        ACTIVE,
        &encode_session_for_scope(scope, session)?,
    )? {
        return Err(MergeBlobError::PendingSession);
    }
    Ok(())
}

/// Return the merge-session write to publish in the same catalog transaction
/// as an index change. A staged conflict must never outlive an unresolved
/// session flag (or leave a resolved flag after `rm --cached`).
pub(crate) fn resolution_record_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    path: &[u8],
    resolved: bool,
) -> Result<Option<SessionRecord>, MergeBlobError> {
    let Some((mut session, _)) = load_merge_session_for_scope(control, scope)? else {
        return Ok(None);
    };
    if session
        .conflicts
        .binary_search_by(|candidate| candidate.as_slice().cmp(path))
        .is_err()
    {
        return Ok(None);
    }
    match (
        resolved,
        session
            .resolved
            .binary_search_by(|candidate| candidate.as_slice().cmp(path)),
    ) {
        (true, Err(position)) => session.resolved.insert(position, path.to_vec()),
        (false, Ok(position)) => {
            session.resolved.remove(position);
        }
        _ => return Ok(None),
    }
    Ok(Some((
        session_kind_for_scope(scope),
        ACTIVE.to_vec(),
        encode_session_for_scope(scope, &session)?,
    )))
}

pub(crate) fn mark_merge_resolved(
    control: &ControlStore,
    repository_id: Uuid,
    path: &[u8],
) -> Result<(), MergeBlobError> {
    mark_merge_resolved_for_scope(control, GitWorktreeScope::primary(repository_id), path)
}

pub(crate) fn mark_merge_resolved_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    path: &[u8],
) -> Result<(), MergeBlobError> {
    let Some((mut session, before)) = load_merge_session_for_scope(control, scope)? else {
        return Ok(());
    };
    if session
        .conflicts
        .binary_search_by(|candidate| candidate.as_slice().cmp(path))
        .is_err()
    {
        return Ok(());
    }
    if let Err(position) = session
        .resolved
        .binary_search_by(|candidate| candidate.as_slice().cmp(path))
    {
        session.resolved.insert(position, path.to_vec());
        control.replace_record_if_value(
            &session_kind_for_scope(scope),
            ACTIVE,
            &before,
            &encode_session_for_scope(scope, &session)?,
        )?;
    }
    Ok(())
}

pub(crate) fn merge_state_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<Option<GitMergeState>, MergeBlobError> {
    let Some((session, _)) = load_merge_session_for_scope(control, scope)? else {
        return Ok(None);
    };
    Ok(Some(GitMergeState {
        source_ref: session.source_ref,
        ours: session.ours,
        theirs: session.theirs,
        unresolved_paths: session
            .conflicts
            .into_iter()
            .filter(|path| session.resolved.binary_search(path).is_err())
            .collect(),
    }))
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

#[derive(Serialize, Deserialize)]
struct LinkedMergeBlobIntentV1 {
    format_version: u16,
    worktree_id: Uuid,
    intent: MergeBlobIntent,
}

fn intent_kind(repository_id: Uuid) -> String {
    format!("{INTENT_PREFIX}{repository_id}")
}

fn intent_kind_for_scope(scope: GitWorktreeScope) -> String {
    scope.local_kind(INTENT_PREFIX, LINKED_INTENT_PREFIX)
}

fn encode_blob_intent_for_scope(
    scope: GitWorktreeScope,
    intent: &MergeBlobIntent,
) -> Result<Vec<u8>, MergeBlobError> {
    if scope.worktree_id() == scope.repository_id() {
        Ok(canonical_bytes(intent)?)
    } else {
        Ok(canonical_bytes(&LinkedMergeBlobIntentV1 {
            format_version: 1,
            worktree_id: scope.worktree_id(),
            intent: intent.clone(),
        })?)
    }
}

fn decode_blob_intent_for_scope(
    scope: GitWorktreeScope,
    encoded: &[u8],
) -> Result<MergeBlobIntent, MergeBlobError> {
    if scope.worktree_id() == scope.repository_id() {
        Ok(decode_canonical(encoded)?)
    } else {
        let linked: LinkedMergeBlobIntentV1 = decode_canonical(encoded)?;
        if linked.format_version != 1 || linked.worktree_id != scope.worktree_id() {
            return Err(MergeBlobError::IncompatibleRecord);
        }
        Ok(linked.intent)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod scoped_blob_tests {
    use std::fs;
    use std::io::Read;

    use super::*;
    use mb_store::SourceBackendKind;

    fn replay_after_capture(legacy: bool) {
        let temp = tempfile::tempdir().unwrap();
        let primary_root = temp.path().join("primary");
        let linked_root = temp.path().join("linked");
        fs::create_dir(&primary_root).unwrap();
        fs::create_dir(&linked_root).unwrap();
        let database = temp.path().join("catalog.db");
        let key = [87_u8; 32];
        let control = ControlStore::open_with_key(&database, &key).unwrap();
        let repository_id = Uuid::new_v4();
        let scope = GitWorktreeScope::linked(repository_id, Uuid::new_v4()).unwrap();
        let add_input = |bytes: &[u8]| {
            let plan = SourceBlobImportPlan::plan_direct(&linked_root, bytes.len() as u64).unwrap();
            let anchor = plan.capture(bytes).unwrap();
            let oid = blob_oid_from_anchor(&anchor).unwrap();
            control
                .put_record(
                    &object_kind(repository_id, oid),
                    anchor.anchor_id.as_bytes(),
                    &canonical_bytes(&anchor).unwrap(),
                )
                .unwrap();
            MergeFileInput {
                oid: oid.as_bytes().try_into().unwrap(),
                mode: 0o100644,
            }
        };
        let inputs = MergeFileInputs {
            base: add_input(b"first\r\nsecond\nthird\r\nfourth\nfifth\r\n"),
            ours: add_input(b"our first\r\nsecond\nthird\r\nfourth\nfifth\r\n"),
            theirs: add_input(b"first\r\nsecond\nthird\r\nfourth\ntheir fifth\r\n"),
        };
        let result = merge_file_bytes(&control, repository_id, b"tracked", inputs)
            .unwrap()
            .unwrap();
        assert_eq!(
            result.bytes,
            b"our first\r\nsecond\nthird\r\nfourth\ntheir fifth\r\n"
        );
        set_after_merge_blob_capture_hook(Box::new(|| panic!("merge blob capture crash")));
        let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            capture_generated_blob(
                &control,
                scope,
                NativeSource {
                    root: &linked_root,
                    backend: SourceBackendKind::ReflinkV1,
                },
                b"tracked",
                inputs,
                &result,
            )
            .unwrap();
        }));
        assert!(interrupted.is_err());
        assert!(has_pending_merge_blob_for_scope(&control, scope).unwrap());
        assert!(has_pending_merge_blob(&control, repository_id).unwrap());
        assert!(matches!(
            resume_pending_merge_blob_for_scope(&control, scope, &primary_root),
            Err(MergeBlobError::IncompatibleRecord)
        ));
        if legacy {
            move_linked_blob_intent_to_legacy_primary(&control, scope).unwrap();
            assert_eq!(
                primary_merge_blob_source_root(&control, repository_id).unwrap(),
                Some(linked_root.clone())
            );
        } else {
            assert!(
                primary_merge_blob_source_root(&control, repository_id)
                    .unwrap()
                    .is_none()
            );
        }
        drop(control);

        let control = ControlStore::open_with_key(&database, &key).unwrap();
        if legacy {
            resume_pending_merge_blob(&control, repository_id, &linked_root).unwrap();
        } else {
            resume_pending_merge_blob_for_scope(&control, scope, &linked_root).unwrap();
        }
        assert!(!has_pending_merge_blob(&control, repository_id).unwrap());
        let anchors = anchors_for_oid(&control, repository_id, result.oid).unwrap();
        assert_eq!(anchors.len(), 1);
        let mut bytes = Vec::new();
        anchors[0]
            .open_verified()
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, result.bytes);
        for input in [inputs.base, inputs.ours, inputs.theirs] {
            for anchor in anchors_for_oid(
                &control,
                repository_id,
                Oid::from_bytes(&input.oid).unwrap(),
            )
            .unwrap()
            {
                anchor.remove().unwrap();
            }
        }
        anchors[0].remove().unwrap();
    }

    #[test]
    fn linked_generated_blob_replays_after_interrupted_capture() {
        replay_after_capture(false);
    }

    #[test]
    fn legacy_linked_generated_blob_replays_from_its_recorded_root() {
        replay_after_capture(true);
    }
}

#[cfg(test)]
pub(crate) fn move_linked_blob_intent_to_legacy_primary(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<(), MergeBlobError> {
    let kind = intent_kind_for_scope(scope);
    let encoded = control
        .get_record(&kind, ACTIVE)?
        .ok_or(MergeBlobError::MissingSession)?;
    let intent = decode_blob_intent_for_scope(scope, &encoded)?;
    control.put_records_and_delete(
        &[(
            intent_kind(scope.repository_id()),
            ACTIVE.to_vec(),
            canonical_bytes(&intent)?,
        )],
        &[(kind, ACTIVE.to_vec())],
    )?;
    Ok(())
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
    scope: GitWorktreeScope,
    source: NativeSource<'_>,
    path: &[u8],
    inputs: MergeFileInputs,
    blob: &GeneratedBlob,
) -> Result<(), MergeBlobError> {
    let repository_id = scope.repository_id();
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
        plan: source
            .backend
            .plan_blob_import(source.root, blob.bytes.len() as u64)?,
    };
    if !control.put_record_if_absent(
        &intent_kind_for_scope(scope),
        ACTIVE,
        &encode_blob_intent_for_scope(scope, &intent)?,
    )? {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    resume_pending_merge_blob_for_scope(control, scope, source.root)
}

pub(crate) fn has_pending_merge_blob(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<bool, MergeBlobError> {
    if control
        .get_record(&intent_kind(repository_id), ACTIVE)?
        .is_some()
    {
        return Ok(true);
    }
    Ok(!control
        .records_with_kind_prefix(&format!("{LINKED_INTENT_PREFIX}{repository_id}/"))?
        .is_empty())
}

pub(crate) fn has_pending_merge_blob_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
) -> Result<bool, MergeBlobError> {
    Ok(control
        .get_record(&intent_kind_for_scope(scope), ACTIVE)?
        .is_some())
}

/// A format-1 blob intent predates linked-worktree namespacing. Its capture
/// plan still binds the source root and native identity; callers can locate
/// the exact registered worktree before replaying it.
pub(crate) fn primary_merge_blob_source_root(
    control: &ControlStore,
    repository_id: Uuid,
) -> Result<Option<PathBuf>, MergeBlobError> {
    let Some(encoded) = control.get_record(&intent_kind(repository_id), ACTIVE)? else {
        return Ok(None);
    };
    let intent: MergeBlobIntent = decode_canonical(&encoded)?;
    if intent.format_version != 1 || intent.repository_id != repository_id {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    Ok(Some(intent.plan.source_root().to_path_buf()))
}

pub(crate) fn resume_pending_merge_blob(
    control: &ControlStore,
    repository_id: Uuid,
    root_path: &Path,
) -> Result<(), MergeBlobError> {
    resume_pending_merge_blob_for_scope(
        control,
        GitWorktreeScope::primary(repository_id),
        root_path,
    )
}

pub(crate) fn resume_pending_merge_blob_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
) -> Result<(), MergeBlobError> {
    let repository_id = scope.repository_id();
    let kind = intent_kind_for_scope(scope);
    let Some(encoded) = control.get_record(&kind, ACTIVE)? else {
        return Ok(());
    };
    let intent = decode_blob_intent_for_scope(scope, &encoded)?;
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

/// Force-pruning a missing linked worktree explicitly abandons its unfinished
/// generated blob. The intent still owns the private native anchor until its
/// plan is discarded; a repeated prune can finish after a crash.
pub(crate) fn abandon_pending_merge_blob_for_scope(
    control: &ControlStore,
    scope: GitWorktreeScope,
    root_path: &Path,
) -> Result<(), MergeBlobError> {
    let kind = intent_kind_for_scope(scope);
    let Some(encoded) = control.get_record(&kind, ACTIVE)? else {
        return Ok(());
    };
    let intent = decode_blob_intent_for_scope(scope, &encoded)?;
    if intent.format_version != 1
        || intent.repository_id != scope.repository_id()
        || intent.plan.source_root() != root_path
    {
        return Err(MergeBlobError::IncompatibleRecord);
    }
    intent.plan.discard()?;
    control.delete_record_if_value(&kind, ACTIVE, &encoded)?;
    Ok(())
}
