//! Validated pending Git graph metadata and its retained file-anchor ownership.
use super::*;

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
