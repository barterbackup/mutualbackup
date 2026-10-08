//! Validated pending Git graph metadata and its retained file-anchor ownership.
use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitPrivateText {
    pub bytes: u64,
    pub hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitMergeSession {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub envelope_format: Option<u16>,
    pub branch: String,
    pub ours: String,
    pub theirs: String,
    pub source_ref_hex: String,
    pub author_name: LegacyGitPrivateText,
    pub author_email: LegacyGitPrivateText,
    pub message: LegacyGitPrivateText,
    pub conflict_paths_hex: Vec<String>,
    pub resolved_paths_hex: Vec<String>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitMergeInput {
    pub oid: String,
    pub mode: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitMergeBlob {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub envelope_format: Option<u16>,
    pub relative_path_hex: String,
    pub base: LegacyGitMergeInput,
    pub ours: LegacyGitMergeInput,
    pub theirs: LegacyGitMergeInput,
    pub result_oid: String,
    pub result_mode: u32,
    pub plan: LegacyBlobImportPlan,
    pub payloads_verified: bool,
}

pub(super) fn report_merge_session(
    session: mb_git::PreservedMergeSession,
    used: &mut usize,
    limit: usize,
) -> Result<LegacyPendingGitMergeSession> {
    let mut report = LegacyPendingGitMergeSession {
        repository_id: session.scope.repository_id(),
        worktree_id: session.scope.worktree_id(),
        record_format: session.record_format,
        envelope_format: session.envelope_format,
        branch: session.branch,
        ours: hex::encode(session.ours),
        theirs: hex::encode(session.theirs),
        source_ref_hex: hex::encode(session.source_ref),
        author_name: LegacyGitPrivateText {
            bytes: session.author_name_bytes,
            hash: hex::encode(session.author_name_hash),
        },
        author_email: LegacyGitPrivateText {
            bytes: session.author_email_bytes,
            hash: hex::encode(session.author_email_hash),
        },
        message: LegacyGitPrivateText {
            bytes: session.message_bytes,
            hash: hex::encode(session.message_hash),
        },
        conflict_paths_hex: Vec::new(),
        resolved_paths_hex: Vec::new(),
        payloads_verified: false,
    };
    account(&report, used, limit)?;
    for path in session.conflicts {
        let path = hex::encode(path);
        account(&path, used, limit)?;
        report.conflict_paths_hex.push(path);
    }
    for path in session.resolved {
        let path = hex::encode(path);
        account(&path, used, limit)?;
        report.resolved_paths_hex.push(path);
    }
    Ok(report)
}

pub(super) fn report_merge_blob(
    intent: mb_git::PreservedMergeBlob,
) -> Result<LegacyPendingGitMergeBlob> {
    let input = |input: mb_git::PreservedMergeInput| LegacyGitMergeInput {
        oid: hex::encode(input.oid),
        mode: input.mode,
    };
    Ok(LegacyPendingGitMergeBlob {
        repository_id: intent.scope.repository_id(),
        worktree_id: intent.scope.worktree_id(),
        record_format: intent.record_format,
        envelope_format: intent.envelope_format,
        relative_path_hex: hex::encode(intent.path),
        base: input(intent.base),
        ours: input(intent.ours),
        theirs: input(intent.theirs),
        result_oid: hex::encode(intent.result_oid),
        result_mode: intent.result_mode,
        plan: blob_import_plan(&intent.plan)?,
        payloads_verified: false,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitFetch {
    pub repository_id: Uuid,
    pub fetch_id: Uuid,
    pub record_format: u16,
    pub source_path_hint_hex: String,
    pub source_root_hint_hex: String,
    pub push: Option<LegacyPendingGitPush>,
    pub refs: Vec<LegacyGitGraphRef>,
    pub objects: Vec<LegacyGitGraphObject>,
    pub blobs: Vec<LegacyFetchedBlob>,
    pub graph_metadata_validated: bool,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitPush {
    pub record_format: u16,
    pub target_name: String,
    pub expected_old: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyFetchedBlob {
    pub oid: String,
    pub logical_len: u64,
    pub symlink: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitBlobImport {
    pub repository_id: Uuid,
    pub record_format: u16,
    pub oid: String,
    pub logical_len: u64,
    /// The original blob row does not identify a fetch UUID.
    pub plan: LegacyBlobImportPlan,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyBlobImportPlan {
    pub record_format: u16,
    pub anchor_id: Uuid,
    pub source_root_hint_hex: String,
    pub area_id: Uuid,
    pub recorded_area_filesystem_id: u64,
    pub area_path_hint_hex: String,
    pub volume_root_hint_hex: String,
    pub logical_len: u64,
    pub recorded_root_identity: NativeFileId,
    pub stable_root_identity: Option<NativeFileId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyVerifiedFetchBlob {
    pub repository_id: Uuid,
    pub fetch_id: Uuid,
    pub record_format: u16,
    pub oid: String,
    pub anchors: Vec<LegacyVerifiedFetchAnchor>,
    /// Original verification evidence is retained; payloads are not reread.
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyVerifiedFetchAnchor {
    pub anchor_id: Uuid,
    pub content_hash: String,
}

pub(super) fn blob_import_plan(
    plan: &mb_store::SourceBlobImportPlan,
) -> Result<LegacyBlobImportPlan> {
    let ownership = plan.preserved_ownership()?;
    Ok(LegacyBlobImportPlan {
        record_format: ownership.record_format,
        anchor_id: ownership.anchor_id,
        source_root_hint_hex: hex::encode(ownership.source_root.as_os_str().as_bytes()),
        area_id: ownership.area.area_id,
        recorded_area_filesystem_id: ownership.area.filesystem_id,
        area_path_hint_hex: hex::encode(ownership.area.path_hint.as_os_str().as_bytes()),
        volume_root_hint_hex: hex::encode(ownership.area.volume_root_hint.as_os_str().as_bytes()),
        logical_len: plan.logical_len(),
        recorded_root_identity: ownership.recorded_root_identity,
        stable_root_identity: ownership.stable_root_identity,
    })
}

pub(super) fn report_fetch(
    intent: mb_git::PreservedFetchIntent,
    used: &mut usize,
    limit: usize,
) -> Result<LegacyPendingGitFetch> {
    let mut report = LegacyPendingGitFetch {
        repository_id: intent.repository_id,
        fetch_id: intent.fetch_id,
        record_format: intent.record_format,
        source_path_hint_hex: hex::encode(intent.source_path.as_os_str().as_bytes()),
        source_root_hint_hex: hex::encode(intent.source_root.as_os_str().as_bytes()),
        push: intent.push.map(|push| LegacyPendingGitPush {
            record_format: push.record_format,
            target_name: push.target_name,
            expected_old: push.expected_old.map(hex::encode),
        }),
        refs: Vec::new(),
        objects: Vec::new(),
        blobs: Vec::new(),
        graph_metadata_validated: false,
        payloads_verified: false,
    };
    account(&report, used, limit)?;
    for reference in intent.refs {
        let entry = LegacyGitGraphRef {
            name_hex: hex::encode(reference.name),
            oid: hex::encode(reference.oid),
        };
        account(&entry, used, limit)?;
        report.refs.push(entry);
    }
    for object in intent.objects {
        let entry = LegacyGitGraphObject {
            kind: object.kind,
            oid: hex::encode(object.oid),
            payload_bytes: object.bytes.len() as u64,
            payload_hash: hex::encode(blake3::hash(&object.bytes).as_bytes()),
        };
        account(&entry, used, limit)?;
        report.objects.push(entry);
    }
    for blob in intent.blobs {
        let entry = LegacyFetchedBlob {
            oid: hex::encode(blob.oid),
            logical_len: blob.logical_len,
            symlink: blob.symlink,
        };
        account(&entry, used, limit)?;
        report.blobs.push(entry);
    }
    Ok(report)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitGraph {
    pub record_format: u16,
    pub guild_id: String,
    pub revision_id: Uuid,
    pub protected_root_id: Uuid,
    pub graph_format: u16,
    pub repository_id: Uuid,
    /// Version 1 omitted the selection; `main` is the decoder's historical default.
    pub head_branch: String,
    pub head_branch_recorded: bool,
    pub registered_root: bool,
    pub registered_repository: bool,
    pub refs: Vec<LegacyGitGraphRef>,
    pub objects: Vec<LegacyGitGraphObject>,
    pub blobs: Vec<LegacyGitBlobPin>,
    pub graph_metadata_validated: bool,
    pub signed_revision_metadata_available: bool,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitGraphRef {
    pub name_hex: String,
    pub oid: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitGraphObject {
    pub kind: u8,
    pub oid: String,
    pub payload_bytes: u64,
    pub payload_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitBlobPin {
    pub oid: String,
    pub manifest_format: u16,
    pub anchor_id: Uuid,
    pub area_id: Uuid,
    pub recorded_area_filesystem_id: u64,
    pub area_path_hint_hex: String,
    pub volume_root_hint_hex: String,
    pub source_path_hint_hex: String,
    pub source_relative_path_hex: String,
    pub logical_len: u64,
    pub content_hash: String,
    pub recorded_file_identity: Option<NativeFileId>,
    pub stable_file_identity: Option<NativeFileId>,
    /// A guarded virtual mapping locates bytes in its original root anchor.
    pub locator_anchor_id: Uuid,
    pub locator_relative_path_hex: String,
}

pub(super) fn report(
    intent: &PreservedGitGraphIntent,
    used: &mut usize,
    limit: usize,
) -> Result<LegacyPendingGitGraph> {
    let graph = &intent.graph;
    let mut report = LegacyPendingGitGraph {
        record_format: intent.record_format,
        guild_id: hex::encode(intent.guild_id),
        revision_id: intent.revision_id,
        protected_root_id: intent.protected_root_id,
        graph_format: graph.format_version,
        repository_id: graph.repository_id,
        head_branch: intent.head_branch.clone(),
        head_branch_recorded: intent.head_branch_recorded,
        registered_root: false,
        registered_repository: false,
        refs: Vec::new(),
        objects: Vec::new(),
        blobs: Vec::new(),
        graph_metadata_validated: true,
        signed_revision_metadata_available: false,
        payloads_verified: false,
    };
    account(&report, used, limit)?;
    for reference in &graph.refs {
        let entry = LegacyGitGraphRef {
            name_hex: hex::encode(&reference.name),
            oid: hex::encode(reference.oid),
        };
        account(&entry, used, limit)?;
        report.refs.push(entry);
    }
    for object in &graph.objects {
        let entry = LegacyGitGraphObject {
            kind: object.kind,
            oid: hex::encode(object.oid),
            payload_bytes: object.bytes.len() as u64,
            payload_hash: hex::encode(blake3::hash(&object.bytes).as_bytes()),
        };
        account(&entry, used, limit)?;
        report.objects.push(entry);
    }
    for blob in &graph.blobs {
        let pin = file_anchor(blob.oid, &blob.anchor)?;
        account(&pin, used, limit)?;
        report.blobs.push(pin);
    }
    Ok(report)
}

pub(super) fn file_anchor(
    oid: [u8; 20],
    anchor: &mb_store::FileAnchorManifest,
) -> Result<LegacyGitBlobPin> {
    let ownership = anchor.preserved_ownership()?;
    Ok(LegacyGitBlobPin {
        oid: hex::encode(oid),
        manifest_format: anchor.format_version,
        anchor_id: anchor.anchor_id,
        area_id: anchor.area.area_id,
        recorded_area_filesystem_id: anchor.area.filesystem_id,
        area_path_hint_hex: hex::encode(anchor.area.path_hint.as_os_str().as_bytes()),
        volume_root_hint_hex: hex::encode(anchor.area.volume_root_hint.as_os_str().as_bytes()),
        source_path_hint_hex: hex::encode(anchor.source_root_hint.as_os_str().as_bytes()),
        source_relative_path_hex: hex::encode(anchor.source_relative_path.as_os_str().as_bytes()),
        logical_len: anchor.logical_len,
        content_hash: hex::encode(anchor.content_hash),
        recorded_file_identity: ownership.recorded_file_identity,
        stable_file_identity: ownership.stable_file_identity,
        locator_anchor_id: ownership.locator_anchor_id,
        locator_relative_path_hex: hex::encode(
            ownership.locator_relative_path.as_os_str().as_bytes(),
        ),
    })
}
