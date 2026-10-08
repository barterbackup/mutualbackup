//! Preserved local and external Git ownership through bounded metadata reads.
//! Source/worktree/anchor payloads and withdrawn mount views are not opened.

mod anchors;
mod git_intents;

use std::{collections::BTreeMap, os::unix::ffi::OsStrExt};

use anyhow::{Context, Result, ensure};
use mb_core::{
    V1_MAX_CATALOG_BYTES, canonical_bytes_bounded, canonical_size_bounded, decode_canonical,
};
use mb_store::{
    ControlStore, GuardedRevisionCaptureV1, GuardedStoppedCaptureV1, NativeFileId,
    SourceBackendBinding,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::inventory::LegacyRevisionInventoryEntry;
use crate::control::{GitRepositoryInfo, ProtectedRoot};
pub use crate::snapshot::preserved::{LegacyLocalSectorRecipe, LegacyLocalSectorSource};
use crate::snapshot::preserved::{
    PreservedCaptureIntent, PreservedGitGraphIntent, PreservedLocalSectorRecipe,
};
use anchors::PreservedAnchor;
pub use git_intents::{
    LegacyBlobImportPlan, LegacyFetchedBlob, LegacyGitBlobPin, LegacyGitGraphObject,
    LegacyGitGraphRef, LegacyPendingGitBlobImport, LegacyPendingGitFetch, LegacyPendingGitGraph,
    LegacyPendingGitPush, LegacyVerifiedFetchAnchor, LegacyVerifiedFetchBlob,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyLocalStateInventory {
    pub protected_roots: Vec<LegacyRootRegistration>,
    pub source_backends: Vec<LegacySourceBinding>,
    pub git_repositories: Vec<LegacyGitRegistration>,
    pub git_worktrees: Vec<LegacyGitWorktreeRegistration>,
    pub git_object_anchors: Vec<LegacyGitObjectAnchor>,
    pub git_indexes: Vec<LegacyGitIndexRegistration>,
    pub git_anchor_area_locations: Vec<LegacyGitAnchorAreaLocation>,
    pub git_references: Vec<LegacyGitReference>,
    pub git_metadata_objects: Vec<LegacyGitMetadataObject>,
    pub git_selected_branches: Vec<LegacyGitSelectedBranch>,
    pub pending_git_stages: Vec<LegacyPendingGitStage>,
    pub pending_git_symlinks: Vec<LegacyPendingGitSymlink>,
    pub pending_git_removals: Vec<LegacyPendingGitRemoval>,
    pub pending_git_prunes: Vec<LegacyPendingGitPrune>,
    pub pending_git_worktree_removals: Vec<LegacyPendingGitWorktreeRemoval>,
    pub pending_git_fetches: Vec<LegacyPendingGitFetch>,
    pub pending_git_blob_imports: Vec<LegacyPendingGitBlobImport>,
    pub verified_git_fetch_blobs: Vec<LegacyVerifiedFetchBlob>,
    pub storage_volumes: Vec<LegacyStorageVolumeRegistration>,
    pub volume_ownership: Vec<LegacyVolumeOwnership>,
    pub local_sectors: Vec<LegacyLocalSectorRecipe>,
    pub guarded_captures: Vec<LegacyGuardedCapture>,
    pub pending_captures: Vec<LegacyPendingCapture>,
    pub pending_git_graphs: Vec<LegacyPendingGitGraph>,
    pub retained_anchors: Vec<LegacyRetainedAnchor>,
    pub anchor_area_locations: Vec<LegacyAnchorAreaLocation>,
    /// These rows are preserved and identified, not decoded or certified as
    /// complete ownership. Their presence remains a retained-history gap.
    pub unclassified_guarded_records: Vec<LegacyPreservedRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyRootRegistration {
    pub root_id: Uuid,
    pub record_format: u16,
    pub path_hex: String,
    pub filesystem_id: u64,
    pub root_inode: u64,
    pub signed_revision_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacySourceBinding {
    pub binding: SourceBackendBinding,
    pub registered_root: bool,
    /// Unknown for absent roots and historical registrations whose identity
    /// layout predates stable filesystem/inode identity (formats 1 and 2).
    pub registration_identity_matches: Option<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitRegistration {
    pub repository_id: Uuid,
    pub path_hex: String,
    pub registered_root: bool,
    /// Complete refs, objects, pins and pending-intent reconciliation remains
    /// separate from linked-worktree enumeration and catalog availability.
    pub catalog_inventoried: bool,
    pub external_catalog_available: bool,
    pub linked_worktrees_inventoried: bool,
    pub object_anchors_inventoried: bool,
    pub worktree_indexes_inventoried: bool,
    pub anchor_area_locations_inventoried: bool,
    pub references_inventoried: bool,
    pub metadata_objects_inventoried: bool,
    pub selected_branches_inventoried: bool,
    pub regular_stage_intents_inventoried: bool,
    pub symlink_stage_intents_inventoried: bool,
    pub removal_intents_inventoried: bool,
    pub prune_intents_inventoried: bool,
    pub worktree_removal_intents_inventoried: bool,
    pub fetch_intents_inventoried: bool,
    pub push_intents_inventoried: bool,
    pub blob_import_intents_inventoried: bool,
    pub fetch_verification_records_inventoried: bool,
    pub signed_revision_ids: Vec<Uuid>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitWorktreeRegistration {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub path_hex: String,
    /// Preserve the saved word without asserting its stable-identity era.
    pub recorded_root_identity: NativeFileId,
    pub recorded_target_branch: String,
    pub state: mb_git::GitWorktreeState,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitObjectAnchor {
    pub repository_id: Uuid,
    pub pin: LegacyGitBlobPin,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitIndexRegistration {
    pub repository_id: Uuid,
    /// The primary scope uses the repository ID, as in the original catalog.
    pub worktree_id: Uuid,
    pub relative_path_hex: String,
    pub record_format: u16,
    pub oid: String,
    pub mode: u32,
    pub anchor_id: Uuid,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitAnchorAreaLocation {
    pub repository_id: Uuid,
    pub area_id: Uuid,
    pub path_hex: String,
    pub absolute: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitReference {
    pub repository_id: Uuid,
    pub record_format: u16,
    pub reference: LegacyGitGraphRef,
    pub pin_namespace: bool,
    pub pin_name_matches_target: Option<bool>,
    pub target_graph_reconciled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitMetadataObject {
    pub repository_id: Uuid,
    pub record_format: u16,
    pub object: LegacyGitGraphObject,
    pub content_address_verified: bool,
    pub graph_metadata_validated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGitSelectedBranch {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub branch: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitStage {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub relative_path_hex: String,
    pub git_mode: u32,
    pub plan: LegacyFileCapturePlan,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitSymlink {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub source_root_hint_hex: String,
    pub recorded_root_identity: NativeFileId,
    pub recorded_catalog_identity: NativeFileId,
    pub relative_path_hex: String,
    pub recorded_source_identity: NativeFileId,
    pub target_bytes: u64,
    pub target_hash: String,
    pub temp_name: String,
    pub recorded_temp_identity: Option<NativeFileId>,
    pub plan: Option<LegacyFileCapturePlan>,
    /// None preserves the original primary-worktree implicit catalog root.
    pub catalog_root_hint_hex: Option<String>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitRemoval {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub recorded_root_identity: NativeFileId,
    pub relative_path_hex: String,
    pub entry: mb_git::GitIndexEntry,
    pub recorded_file_identity: NativeFileId,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitPrune {
    pub repository_id: Uuid,
    pub record_format: u16,
    /// The original retirement batch does not retain a Git object ID.
    pub anchors: Vec<LegacyPruneFileAnchor>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingGitWorktreeRemoval {
    pub repository_id: Uuid,
    pub worktree_id: Uuid,
    pub record_format: u16,
    pub recorded_root_identity: NativeFileId,
    /// The containing parent is a location hint, not an owned root.
    pub recorded_parent_identity: NativeFileId,
    pub recorded_marker_directory_identity: NativeFileId,
    pub recorded_marker_identity: NativeFileId,
    pub files: Vec<LegacyWorktreeRemovalFile>,
    pub directories: Vec<LegacyWorktreeRemovalDirectory>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyWorktreeRemovalFile {
    pub relative_path_hex: String,
    pub oid: String,
    pub mode: u32,
    pub recorded_identity: NativeFileId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyWorktreeRemovalDirectory {
    pub relative_path_hex: String,
    pub recorded_identity: NativeFileId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPruneFileAnchor {
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
    pub locator_anchor_id: Uuid,
    pub locator_relative_path_hex: String,
}

fn prune_file_anchor(anchor: &mb_store::FileAnchorManifest) -> Result<LegacyPruneFileAnchor> {
    let ownership = anchor.preserved_ownership()?;
    Ok(LegacyPruneFileAnchor {
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyFileCapturePlan {
    pub backend: mb_store::SourceBackendKind,
    pub record_format: u16,
    pub capture_id: Uuid,
    pub source_root_hint_hex: String,
    pub relative_path_hex: String,
    pub area_id: Uuid,
    pub recorded_area_filesystem_id: u64,
    pub area_path_hint_hex: String,
    /// A discovery hint; this does not claim ownership of the whole volume.
    pub volume_root_hint_hex: String,
    pub logical_len: u64,
    pub recorded_root_identity: NativeFileId,
    pub stable_root_identity: Option<NativeFileId>,
    pub recorded_file_identity: NativeFileId,
    pub stable_file_identity: Option<NativeFileId>,
}

fn file_capture_plan(plan: &mb_store::SourceFileCapturePlan) -> Result<LegacyFileCapturePlan> {
    let ownership = plan.preserved_ownership()?;
    Ok(LegacyFileCapturePlan {
        backend: plan.backend_kind(),
        record_format: ownership.record_format,
        capture_id: ownership.capture_id,
        source_root_hint_hex: hex::encode(ownership.source_root.as_os_str().as_bytes()),
        relative_path_hex: hex::encode(ownership.relative_path.as_os_str().as_bytes()),
        area_id: ownership.area.area_id,
        recorded_area_filesystem_id: ownership.area.filesystem_id,
        area_path_hint_hex: hex::encode(ownership.area.path_hint.as_os_str().as_bytes()),
        volume_root_hint_hex: hex::encode(ownership.area.volume_root_hint.as_os_str().as_bytes()),
        logical_len: ownership.logical_len,
        recorded_root_identity: ownership.recorded_root_identity,
        stable_root_identity: ownership.stable_root_identity,
        recorded_file_identity: ownership.recorded_file_identity,
        stable_file_identity: ownership.stable_file_identity,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyStorageVolumeRegistration {
    pub volume_id: Uuid,
    pub record_format: u16,
    pub path_hex: String,
    pub database_file: String,
    pub state: crate::StorageVolumeState,
    pub configured: bool,
    /// Historical records defaulted to configured without storing this field.
    pub configured_recorded: bool,
    pub budget_bytes: u64,
    pub headroom_bytes: u64,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyVolumeOwnership {
    pub record_kind: String,
    pub record_id_hex: String,
    pub record_bytes: u64,
    pub record_hash: String,
    pub evidence: crate::volume::LegacyVolumeOwnershipEvidence,
    /// Saved references lacking a current registry entry; no payload lookup occurs.
    pub unregistered_volume_ids: Vec<Uuid>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGuardedCapture {
    pub record_kind: String,
    pub revision_id: Uuid,
    pub protected_root_id: Option<Uuid>,
    pub signed_revision_metadata_available: bool,
    pub namespace_anchor_id: Uuid,
    pub anchors: Vec<LegacyGuardedAnchorPin>,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyGuardedAnchorPin {
    pub namespace_path_hex: String,
    pub area_id: Uuid,
    pub filesystem_id: u64,
    pub area_path_hint_hex: String,
    pub volume_root_hint_hex: String,
    pub anchor_id: Uuid,
    pub relative_path_hex: String,
    pub logical_len: u64,
    pub content_hash: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingCapture {
    pub record_kind: String,
    pub record_format: u16,
    pub guild_id: String,
    pub revision_id: Uuid,
    pub sequence: Option<u64>,
    pub parent: Option<String>,
    pub captured_change_sequence: Option<u64>,
    pub requested_source_path_hex: String,
    pub backend: mb_store::SourceBackendKind,
    pub planned_anchor: LegacyCaptureOwnership,
    pub replaced_anchor: Option<LegacyCaptureOwnership>,
    pub signed_revision_metadata_available: bool,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyCaptureOwnership {
    pub record_format: u16,
    pub anchor_id: Uuid,
    pub source_path_hint_hex: String,
    pub area_id: Uuid,
    /// Historical native records do not distinguish st_dev from a stable ID.
    pub recorded_area_filesystem_id: Option<u64>,
    pub area_path_hint_hex: String,
    pub volume_root_hint_hex: Option<String>,
    pub recorded_root_identity: Option<NativeFileId>,
    pub stable_root_identity: Option<NativeFileId>,
    pub file_pins: Vec<LegacyPendingFilePin>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPendingFilePin {
    pub relative_path_hex: String,
    pub capture_id: Uuid,
    pub recorded_file_identity: Option<NativeFileId>,
    pub logical_len: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyAnchorAreaLocation {
    pub area_id: Uuid,
    pub path_hint_hex: String,
    pub absolute_path: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyRetainedAnchor {
    pub record_kind: String,
    pub record_id: Uuid,
    pub revision_id: Option<Uuid>,
    pub protected_root_id: Option<Uuid>,
    pub signed_revision_metadata_available: bool,
    pub anchor: LegacyCaptureOwnership,
    pub payloads_verified: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyPreservedRecord {
    pub kind: String,
    pub record_id_hex: String,
    pub payload_bytes: u64,
    pub payload_hash: String,
}

/// A validated local record. The scanner retains at most one decoded row;
/// consumers choose whether to build a bounded report or check locations.
pub(super) enum PreservedLocalRecord<'a> {
    Root(ProtectedRoot),
    Binding(SourceBackendBinding),
    Git(GitRepositoryInfo),
    Volume(crate::volume::PreservedVolumeRegistration<'a>),
    LocalSector(&'a PreservedLocalSectorRecipe),
    VolumeOwnership {
        kind: &'a str,
        key: &'a [u8],
        bytes: &'a [u8],
        evidence: crate::volume::LegacyVolumeOwnershipEvidence,
    },
    Capture {
        kind: &'a str,
        revision_id: Uuid,
        capture: GuardedStoppedCaptureV1,
    },
    PendingCapture {
        kind: &'a str,
        intent: &'a PreservedCaptureIntent,
    },
    PendingGitGraph(&'a PreservedGitGraphIntent),
    Anchor {
        kind: &'a str,
        record_id: Uuid,
        anchor: &'a PreservedAnchor,
    },
    AreaLocation {
        area_id: Uuid,
        path: std::path::PathBuf,
    },
    Unclassified {
        kind: &'a str,
        key: &'a [u8],
        bytes: &'a [u8],
    },
}

pub(super) enum PreservedInput<'a> {
    PathHint(&'a std::path::Path),
    NativeRoot(NativeFileId),
    /// Either historical st_dev/inode or stable filesystem/inode, never proof
    /// of stable ownership. Placement conservatively excludes both matches.
    RecordedNativeRoot(NativeFileId),
}

impl PreservedLocalRecord<'_> {
    /// Known exclusions only. A path hint is not ownership authority, and
    /// opaque records do not establish a complete retained ownership graph.
    pub(super) fn for_each_input(
        &self,
        mut visit: impl FnMut(PreservedInput<'_>) -> Result<()>,
    ) -> Result<()> {
        match self {
            Self::Root(root) => {
                visit(PreservedInput::PathHint(&root.path))?;
                if matches!(root.format_version, 3 | 4) {
                    visit(PreservedInput::NativeRoot(NativeFileId {
                        filesystem_id: root.filesystem_id,
                        inode: root.root_inode,
                    }))?;
                }
            }
            Self::Binding(binding) => visit(PreservedInput::NativeRoot(NativeFileId {
                filesystem_id: binding.filesystem_id,
                inode: binding.root_inode,
            }))?,
            Self::Git(registration) => visit(PreservedInput::PathHint(&registration.path))?,
            Self::Volume(volume) => visit(PreservedInput::PathHint(volume.path))?,
            Self::VolumeOwnership { .. } => {}
            Self::LocalSector(recipe) => {
                recipe.for_each_path(|path| visit(PreservedInput::PathHint(path)))?
            }
            Self::Capture { capture, .. } => {
                visit(PreservedInput::NativeRoot(capture.metadata.lower_root_id))?;
                for file in &capture.files {
                    // A volume root is a discovery starting point, often `/`,
                    // not ownership of the whole filesystem.
                    visit(PreservedInput::PathHint(&file.locator.area.path_hint))?;
                }
            }
            Self::PendingCapture { intent, .. } => {
                let plan = intent.plan.preserved_ownership()?;
                visit(PreservedInput::PathHint(plan.source_root))?;
                visit(PreservedInput::PathHint(&plan.area.path_hint))?;
                // Requested paths may be relative to a historical process cwd.
                if intent.requested_source.is_absolute() {
                    visit(PreservedInput::PathHint(&intent.requested_source))?;
                }
                if let Some(identity) = plan.stable_root_identity {
                    visit(PreservedInput::NativeRoot(identity))?;
                } else {
                    visit(PreservedInput::RecordedNativeRoot(
                        plan.recorded_root_identity,
                    ))?;
                }
                if let Some(old) = &intent.replaced_anchor {
                    visit(PreservedInput::PathHint(&old.source_root_hint))?;
                    visit(PreservedInput::PathHint(&old.area.path_hint))?;
                }
            }
            Self::PendingGitGraph(intent) => {
                for blob in &intent.graph.blobs {
                    visit(PreservedInput::PathHint(&blob.anchor.source_root_hint))?;
                    visit(PreservedInput::PathHint(&blob.anchor.area.path_hint))?;
                }
            }
            Self::Anchor { anchor, .. } => anchor.for_each_input(&mut visit)?,
            Self::AreaLocation { path, .. } => {
                if path.is_absolute() {
                    visit(PreservedInput::PathHint(path))?;
                }
            }
            Self::Unclassified { .. } => {}
        }
        Ok(())
    }
}

fn account<T: Serialize>(item: &T, used: &mut usize, limit: usize) -> Result<()> {
    *used = used
        .checked_add(canonical_size_bounded(item, limit)?)
        .context("local inventory size overflow")?;
    ensure!(
        *used <= limit,
        "local inventory exceeds its bounded metadata budget"
    );
    Ok(())
}

fn canonical_record<T: for<'de> Deserialize<'de> + Serialize>(bytes: &[u8]) -> Result<T> {
    let record = decode_canonical(bytes)?;
    ensure!(
        canonical_bytes_bounded(&record, V1_MAX_CATALOG_BYTES)? == bytes,
        "local inventory record is not canonical"
    );
    Ok(record)
}

fn validate_capture(capture: &GuardedStoppedCaptureV1) -> Result<()> {
    capture.validate_shape()?;
    for file in &capture.files {
        let locator = &file.locator;
        ensure!(
            !locator.anchor_id.is_nil() && !locator.area.area_id.is_nil(),
            "invalid preserved anchor ownership ID"
        );
        let relative = locator.relative_path.as_os_str().as_bytes();
        let mut normalized = std::path::PathBuf::new();
        for component in locator.relative_path.components() {
            let std::path::Component::Normal(name) = component else {
                anyhow::bail!("unsafe preserved anchor relative path")
            };
            normalized.push(name);
        }
        ensure!(
            !relative.is_empty()
                && !relative.contains(&0)
                && normalized.as_os_str().as_bytes() == relative,
            "unsafe preserved anchor relative path"
        );
        let mut end = 0;
        for extent in &file.data_extents {
            ensure!(
                extent.logical_len != 0 && extent.offset >= end,
                "invalid preserved anchor extent order"
            );
            end = extent
                .offset
                .checked_add(extent.logical_len)
                .context("preserved anchor extent overflow")?;
            ensure!(
                end <= file.logical_len,
                "preserved anchor extent exceeds file"
            );
        }
        ensure!(
            locator.area.path_hint.is_absolute()
                && !locator.area.path_hint.as_os_str().as_bytes().contains(&0),
            "unsafe preserved anchor area path hint"
        );
    }
    Ok(())
}

fn validate_hint(path: &std::path::Path) -> Result<()> {
    ensure!(
        path.is_absolute() && !path.as_os_str().as_bytes().contains(&0),
        "unsafe preserved anchor path hint"
    );
    Ok(())
}

fn validate_pending(intent: &PreservedCaptureIntent) -> Result<()> {
    intent.plan.preserved_ownership()?;
    ensure!(
        !intent.requested_source.as_os_str().is_empty()
            && !intent.requested_source.as_os_str().as_bytes().contains(&0),
        "invalid preserved requested source path"
    );
    if let Some(anchor) = &intent.replaced_anchor {
        anchors::validate_stable(anchor)?;
    }
    Ok(())
}

fn ownership(
    format: u16,
    anchor_id: Uuid,
    source: &std::path::Path,
    area: &mb_store::StableAnchorAreaLocator,
    recorded: Option<NativeFileId>,
    stable: Option<NativeFileId>,
) -> LegacyCaptureOwnership {
    LegacyCaptureOwnership {
        record_format: format,
        anchor_id,
        source_path_hint_hex: hex::encode(source.as_os_str().as_bytes()),
        area_id: area.area_id,
        recorded_area_filesystem_id: Some(area.filesystem_id),
        area_path_hint_hex: hex::encode(area.path_hint.as_os_str().as_bytes()),
        volume_root_hint_hex: Some(hex::encode(area.volume_root_hint.as_os_str().as_bytes())),
        recorded_root_identity: recorded,
        stable_root_identity: stable,
        file_pins: Vec::new(),
    }
}

pub(super) enum PreservedExternalGitRecord {
    Record(mb_git::PreservedGitRecord),
    CatalogStatus {
        repository_id: Uuid,
        available: bool,
    },
}

pub(super) fn for_each_external_git_record(
    control: &ControlStore,
    keys: &mb_core::KeyMaterial,
    mut visit: impl FnMut(PreservedExternalGitRecord) -> Result<()>,
) -> Result<()> {
    control.for_each_record_bounded("git-repository", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let registration: GitRepositoryInfo = canonical_record(bytes)?;
        ensure!(
            registration.format_version == 1
                && !registration.repository_id.is_nil()
                && key == registration.repository_id.as_bytes()
                && registration.path.is_absolute()
                && !registration.path.as_os_str().as_bytes().contains(&0),
            "invalid preserved Git registration"
        );
        let available = mb_git::GitRepository::for_each_preserved_record(
            &registration.path,
            registration.repository_id,
            &mb_git::catalog_key(keys, registration.repository_id),
            |record| visit(PreservedExternalGitRecord::Record(record)),
        )?;
        visit(PreservedExternalGitRecord::CatalogStatus {
            repository_id: registration.repository_id,
            available,
        })?;
        Ok(true)
    })?;
    Ok(())
}

pub(super) fn collect_external_git_records(
    control: &ControlStore,
    keys: &mb_core::KeyMaterial,
    report: &mut LegacyLocalStateInventory,
    used: &mut usize,
    limit: usize,
) -> Result<()> {
    for_each_external_git_record(control, keys, |record| {
        match record {
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::LinkedWorktree(
                info,
            )) => {
                let entry = LegacyGitWorktreeRegistration {
                    repository_id: info.repository_id,
                    worktree_id: info.worktree_id,
                    record_format: info.format_version,
                    path_hex: hex::encode(info.path.as_os_str().as_bytes()),
                    recorded_root_identity: info.root_id,
                    recorded_target_branch: info.target_branch,
                    state: info.state,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.git_worktrees.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::ObjectAnchor {
                repository_id,
                oid,
                anchor,
            }) => {
                let entry = LegacyGitObjectAnchor {
                    repository_id,
                    pin: git_intents::file_anchor(oid, &anchor)?,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.git_object_anchors.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::IndexEntry {
                scope,
                relative_path,
                entry: index,
            }) => {
                let entry = LegacyGitIndexRegistration {
                    repository_id: scope.repository_id(),
                    worktree_id: scope.worktree_id(),
                    relative_path_hex: hex::encode(relative_path),
                    record_format: index.format_version,
                    oid: hex::encode(index.oid),
                    mode: index.mode,
                    anchor_id: index.anchor_id,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.git_indexes.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::StageIntent {
                scope,
                record_format,
                relative_path,
                git_mode,
                plan,
            }) => {
                let entry = LegacyPendingGitStage {
                    repository_id: scope.repository_id(),
                    worktree_id: scope.worktree_id(),
                    record_format,
                    relative_path_hex: hex::encode(relative_path),
                    git_mode,
                    plan: file_capture_plan(&plan)?,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.pending_git_stages.push(entry);
            }
            PreservedExternalGitRecord::Record(
                mb_git::PreservedGitRecord::SymlinkStageIntent { scope, intent },
            ) => {
                let entry = LegacyPendingGitSymlink {
                    repository_id: scope.repository_id(),
                    worktree_id: scope.worktree_id(),
                    record_format: intent.record_format,
                    source_root_hint_hex: hex::encode(intent.source_root.as_os_str().as_bytes()),
                    recorded_root_identity: intent.recorded_root_identity,
                    recorded_catalog_identity: intent.recorded_catalog_identity,
                    relative_path_hex: hex::encode(intent.relative_path),
                    recorded_source_identity: intent.recorded_source_identity,
                    target_bytes: intent.target_bytes,
                    target_hash: hex::encode(intent.target_hash),
                    temp_name: intent.temp_name,
                    recorded_temp_identity: intent.recorded_temp_identity,
                    plan: intent.plan.as_ref().map(file_capture_plan).transpose()?,
                    catalog_root_hint_hex: intent
                        .catalog_root
                        .as_ref()
                        .map(|path| hex::encode(path.as_os_str().as_bytes())),
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.pending_git_symlinks.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::RemovalIntent {
                scope,
                record_format,
                recorded_root_identity,
                relative_path,
                entry,
                recorded_file_identity,
            }) => {
                let entry = LegacyPendingGitRemoval {
                    repository_id: scope.repository_id(),
                    worktree_id: scope.worktree_id(),
                    record_format,
                    recorded_root_identity,
                    relative_path_hex: hex::encode(relative_path),
                    entry,
                    recorded_file_identity,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.pending_git_removals.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::PruneIntent {
                repository_id,
                record_format,
                anchors,
            }) => {
                let mut entry = LegacyPendingGitPrune {
                    repository_id,
                    record_format,
                    anchors: Vec::new(),
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                for anchor in &anchors {
                    let anchor = prune_file_anchor(anchor)?;
                    account(&anchor, used, limit)?;
                    entry.anchors.push(anchor);
                }
                report.pending_git_prunes.push(entry);
            }
            PreservedExternalGitRecord::Record(
                mb_git::PreservedGitRecord::WorktreeRemovalIntent(intent),
            ) => {
                let mut entry = LegacyPendingGitWorktreeRemoval {
                    repository_id: intent.scope.repository_id(),
                    worktree_id: intent.scope.worktree_id(),
                    record_format: intent.format_version,
                    recorded_root_identity: intent.root_id,
                    recorded_parent_identity: intent.parent_id,
                    recorded_marker_directory_identity: intent.marker_directory_id,
                    recorded_marker_identity: intent.marker_id,
                    files: Vec::new(),
                    directories: Vec::new(),
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                for file in intent.files {
                    let file = LegacyWorktreeRemovalFile {
                        relative_path_hex: hex::encode(file.path),
                        oid: hex::encode(file.oid),
                        mode: file.mode,
                        recorded_identity: file.recorded_identity,
                    };
                    account(&file, used, limit)?;
                    entry.files.push(file);
                }
                for directory in intent.directories {
                    let directory = LegacyWorktreeRemovalDirectory {
                        relative_path_hex: hex::encode(directory.path),
                        recorded_identity: directory.recorded_identity,
                    };
                    account(&directory, used, limit)?;
                    entry.directories.push(directory);
                }
                report.pending_git_worktree_removals.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::FetchIntent(intent)) => {
                report
                    .pending_git_fetches
                    .push(git_intents::report_fetch(*intent, used, limit)?);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::BlobImportIntent {
                repository_id,
                record_format,
                oid,
                logical_len,
                plan,
            }) => {
                let entry = LegacyPendingGitBlobImport {
                    repository_id,
                    record_format,
                    oid: hex::encode(oid),
                    logical_len,
                    plan: git_intents::blob_import_plan(&plan)?,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.pending_git_blob_imports.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::VerifiedFetchBlob {
                repository_id,
                fetch_id,
                record_format,
                oid,
                anchors,
            }) => {
                let mut entry = LegacyVerifiedFetchBlob {
                    repository_id,
                    fetch_id,
                    record_format,
                    oid: hex::encode(oid),
                    anchors: Vec::new(),
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                for (anchor_id, hash) in anchors {
                    let anchor = LegacyVerifiedFetchAnchor {
                        anchor_id,
                        content_hash: hex::encode(hash),
                    };
                    account(&anchor, used, limit)?;
                    entry.anchors.push(anchor);
                }
                report.verified_git_fetch_blobs.push(entry);
            }
            PreservedExternalGitRecord::Record(
                mb_git::PreservedGitRecord::AnchorAreaLocation {
                    repository_id,
                    area_id,
                    path,
                },
            ) => {
                let entry = LegacyGitAnchorAreaLocation {
                    repository_id,
                    area_id,
                    path_hex: hex::encode(path.as_os_str().as_bytes()),
                    absolute: path.is_absolute(),
                };
                account(&entry, used, limit)?;
                report.git_anchor_area_locations.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::Reference {
                repository_id,
                record_format,
                name,
                oid,
                pin_namespace,
                pin_name_matches_target,
            }) => {
                let entry = LegacyGitReference {
                    repository_id,
                    record_format,
                    reference: LegacyGitGraphRef {
                        name_hex: hex::encode(name),
                        oid: hex::encode(oid),
                    },
                    pin_namespace,
                    pin_name_matches_target,
                    target_graph_reconciled: false,
                };
                account(&entry, used, limit)?;
                report.git_references.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::MetadataObject {
                repository_id,
                record_format,
                object,
            }) => {
                let entry = LegacyGitMetadataObject {
                    repository_id,
                    record_format,
                    object: LegacyGitGraphObject {
                        kind: object.kind,
                        oid: hex::encode(object.oid),
                        payload_bytes: object.bytes.len() as u64,
                        payload_hash: hex::encode(blake3::hash(&object.bytes).as_bytes()),
                    },
                    content_address_verified: true,
                    graph_metadata_validated: false,
                };
                account(&entry, used, limit)?;
                report.git_metadata_objects.push(entry);
            }
            PreservedExternalGitRecord::Record(mb_git::PreservedGitRecord::SelectedBranch {
                scope,
                record_format,
                branch,
            }) => {
                let entry = LegacyGitSelectedBranch {
                    repository_id: scope.repository_id(),
                    worktree_id: scope.worktree_id(),
                    record_format,
                    branch,
                };
                account(&entry, used, limit)?;
                report.git_selected_branches.push(entry);
            }
            PreservedExternalGitRecord::CatalogStatus {
                repository_id,
                available,
            } => {
                let index = report
                    .git_repositories
                    .binary_search_by_key(&repository_id, |registration| registration.repository_id)
                    .map_err(|_| {
                        anyhow::anyhow!("external Git catalog lost its preserved registration")
                    })?;
                let registration = &mut report.git_repositories[index];
                registration.external_catalog_available = available;
                registration.linked_worktrees_inventoried = available;
                registration.object_anchors_inventoried = available;
                registration.worktree_indexes_inventoried = available;
                registration.anchor_area_locations_inventoried = available;
                registration.references_inventoried = available;
                registration.metadata_objects_inventoried = available;
                registration.selected_branches_inventoried = available;
                registration.regular_stage_intents_inventoried = available;
                registration.symlink_stage_intents_inventoried = available;
                registration.removal_intents_inventoried = available;
                registration.prune_intents_inventoried = available;
                registration.worktree_removal_intents_inventoried = available;
                registration.fetch_intents_inventoried = available;
                registration.push_intents_inventoried = available;
                registration.blob_import_intents_inventoried = available;
                registration.fetch_verification_records_inventoried = available;
            }
        }
        Ok(())
    })
}

/// Stream every relevant row with SQL byte limits before materialization.
/// Validation is shared by report and placement consumers; neither may skip
/// canonical/shape checks merely because it does not need a field for output.
pub(super) fn for_each_record(
    control: &ControlStore,
    mut visit: impl FnMut(PreservedLocalRecord<'_>) -> Result<()>,
) -> Result<()> {
    control.for_each_record_bounded("protected-root", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let root: ProtectedRoot = canonical_record(bytes)?;
        ensure!(
            matches!(root.format_version, 1..=4)
                && !root.root_id.is_nil()
                && key == root.root_id.as_bytes()
                && root.filesystem_id != 0
                && root.root_inode != 0
                && root.path.is_absolute()
                && !root.path.as_os_str().as_bytes().contains(&0),
            "invalid preserved protected-root registration"
        );
        visit(PreservedLocalRecord::Root(root))?;
        Ok(true)
    })?;
    control.for_each_record_bounded("source-backend", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let binding: SourceBackendBinding = canonical_record(bytes)?;
        ensure!(
            binding.format_version == 1
                && binding.contract_version == 1
                && !binding.root_id.is_nil()
                && key == binding.root_id.as_bytes()
                && binding.filesystem_id != 0
                && binding.root_inode != 0
                && binding.mount_id != 0,
            "invalid preserved source-backend binding"
        );
        visit(PreservedLocalRecord::Binding(binding))?;
        Ok(true)
    })?;
    control.for_each_record_bounded("git-repository", 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
        let registration: GitRepositoryInfo = canonical_record(bytes)?;
        ensure!(
            registration.format_version == 1
                && !registration.repository_id.is_nil()
                && key == registration.repository_id.as_bytes()
                && registration.path.is_absolute()
                && !registration.path.as_os_str().as_bytes().contains(&0),
            "invalid preserved Git registration"
        );
        visit(PreservedLocalRecord::Git(registration))?;
        Ok(true)
    })?;
    crate::volume::for_each_preserved_volume_registration(control, |volume| {
        visit(PreservedLocalRecord::Volume(volume))
    })?;
    crate::volume::for_each_preserved_volume_ownership(control, |kind, key, bytes, evidence| {
        visit(PreservedLocalRecord::VolumeOwnership {
            kind,
            key,
            bytes,
            evidence,
        })
    })?;
    control.for_each_record_bounded(
        "local-sector",
        32,
        mb_core::V1_SECTOR_SIZE + 4096,
        |key, bytes| {
            let recipe = crate::snapshot::preserved::decode_local_sector(key, bytes)?;
            visit(PreservedLocalRecord::LocalSector(&recipe))?;
            Ok(true)
        },
    )?;
    for kind in ["capture-intent", "recovery-anchor-intent"] {
        control.for_each_record_bounded(kind, 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
            let intent = crate::snapshot::preserved::decode_capture_intent(kind, key, bytes)?;
            validate_pending(&intent)?;
            visit(PreservedLocalRecord::PendingCapture {
                kind,
                intent: &intent,
            })?;
            Ok(true)
        })?;
    }
    control.for_each_record_bounded(
        "git-graph-intent-v1",
        16,
        V1_MAX_CATALOG_BYTES,
        |key, bytes| {
            let intent = crate::snapshot::preserved::decode_git_graph_intent(key, bytes)?;
            visit(PreservedLocalRecord::PendingGitGraph(&intent))?;
            Ok(true)
        },
    )?;
    for kind in ["anchor-manifest", "anchor-retirement"] {
        control.for_each_record_bounded(kind, 16, V1_MAX_CATALOG_BYTES, |key, bytes| {
            let record_id = Uuid::from_slice(key)?;
            ensure!(!record_id.is_nil(), "invalid preserved anchor record key");
            let anchor = PreservedAnchor::decode(kind, bytes)?;
            ensure!(
                kind == "anchor-manifest" || record_id == anchor.anchor_id(),
                "preserved anchor retirement key differs from anchor ID"
            );
            visit(PreservedLocalRecord::Anchor {
                kind,
                record_id,
                anchor: &anchor,
            })?;
            Ok(true)
        })?;
    }
    control.for_each_record_bounded(
        "anchor-area-location",
        16,
        crate::snapshot::preserved::PRESERVED_AREA_LOCATION_BYTES,
        |key, bytes| {
            let area_id = Uuid::from_slice(key)?;
            ensure!(
                !area_id.is_nil(),
                "invalid preserved anchor area location key"
            );
            let path = crate::snapshot::preserved::decode_area_location(bytes)?;
            visit(PreservedLocalRecord::AreaLocation { area_id, path })?;
            Ok(true)
        },
    )?;
    for prefix in ["guarded-", "link-freeze-"] {
        control.for_each_record_with_kind_prefix_bounded(
            prefix,
            512,
            64 * 1024,
            V1_MAX_CATALOG_BYTES,
            |kind, key, bytes| {
                let capture = match kind {
                    mb_store::GUARDED_REVISION_CAPTURE_KIND => {
                        let record: GuardedRevisionCaptureV1 = canonical_record(bytes)?;
                        ensure!(
                            record.format_version == 1
                                && key == record.revision_id.as_bytes()
                                && !record.revision_id.is_nil(),
                            "invalid preserved revision capture"
                        );
                        Some((record.revision_id, record.capture))
                    }
                    "guarded-view-stopped-capture-v1" => {
                        let revision_id = Uuid::from_slice(key)?;
                        ensure!(!revision_id.is_nil(), "invalid stopped capture revision ID");
                        Some((
                            revision_id,
                            canonical_record::<GuardedStoppedCaptureV1>(bytes)?,
                        ))
                    }
                    _ => None,
                };
                if let Some((revision_id, capture)) = capture {
                    validate_capture(&capture)?;
                    visit(PreservedLocalRecord::Capture {
                        kind,
                        revision_id,
                        capture,
                    })?;
                } else {
                    visit(PreservedLocalRecord::Unclassified { kind, key, bytes })?;
                }
                Ok(true)
            },
        )?;
    }
    Ok(())
}

pub(super) fn collect(
    control: &ControlStore,
    used: &mut usize,
    limit: usize,
) -> Result<LegacyLocalStateInventory> {
    let mut report = LegacyLocalStateInventory {
        protected_roots: Vec::new(),
        source_backends: Vec::new(),
        git_repositories: Vec::new(),
        git_worktrees: Vec::new(),
        git_object_anchors: Vec::new(),
        git_indexes: Vec::new(),
        git_anchor_area_locations: Vec::new(),
        git_references: Vec::new(),
        git_metadata_objects: Vec::new(),
        git_selected_branches: Vec::new(),
        pending_git_stages: Vec::new(),
        pending_git_symlinks: Vec::new(),
        pending_git_removals: Vec::new(),
        pending_git_prunes: Vec::new(),
        pending_git_worktree_removals: Vec::new(),
        pending_git_fetches: Vec::new(),
        pending_git_blob_imports: Vec::new(),
        verified_git_fetch_blobs: Vec::new(),
        storage_volumes: Vec::new(),
        volume_ownership: Vec::new(),
        local_sectors: Vec::new(),
        guarded_captures: Vec::new(),
        pending_captures: Vec::new(),
        pending_git_graphs: Vec::new(),
        retained_anchors: Vec::new(),
        anchor_area_locations: Vec::new(),
        unclassified_guarded_records: Vec::new(),
    };
    for_each_record(control, |record| {
        match record {
            PreservedLocalRecord::Root(root) => {
                let entry = LegacyRootRegistration {
                    root_id: root.root_id,
                    record_format: root.format_version,
                    path_hex: hex::encode(root.path.as_os_str().as_bytes()),
                    filesystem_id: root.filesystem_id,
                    root_inode: root.root_inode,
                    signed_revision_ids: Vec::new(),
                };
                account(&entry, used, limit)?;
                report.protected_roots.push(entry);
            }
            PreservedLocalRecord::Binding(binding) => {
                let root = report
                    .protected_roots
                    .binary_search_by_key(&binding.root_id, |root| root.root_id)
                    .ok()
                    .map(|index| &report.protected_roots[index]);
                let entry = LegacySourceBinding {
                    registered_root: root.is_some(),
                    registration_identity_matches: root
                        .filter(|root| matches!(root.record_format, 3 | 4))
                        .map(|root| {
                            root.filesystem_id == binding.filesystem_id
                                && root.root_inode == binding.root_inode
                        }),
                    binding,
                };
                account(&entry, used, limit)?;
                report.source_backends.push(entry);
            }
            PreservedLocalRecord::Git(registration) => {
                let entry = LegacyGitRegistration {
                    repository_id: registration.repository_id,
                    path_hex: hex::encode(registration.path.as_os_str().as_bytes()),
                    registered_root: report
                        .protected_roots
                        .binary_search_by_key(&registration.repository_id, |root| root.root_id)
                        .is_ok(),
                    catalog_inventoried: false,
                    external_catalog_available: false,
                    linked_worktrees_inventoried: false,
                    object_anchors_inventoried: false,
                    worktree_indexes_inventoried: false,
                    anchor_area_locations_inventoried: false,
                    references_inventoried: false,
                    metadata_objects_inventoried: false,
                    selected_branches_inventoried: false,
                    regular_stage_intents_inventoried: false,
                    symlink_stage_intents_inventoried: false,
                    removal_intents_inventoried: false,
                    prune_intents_inventoried: false,
                    worktree_removal_intents_inventoried: false,
                    fetch_intents_inventoried: false,
                    push_intents_inventoried: false,
                    blob_import_intents_inventoried: false,
                    fetch_verification_records_inventoried: false,
                    signed_revision_ids: Vec::new(),
                };
                account(&entry, used, limit)?;
                report.git_repositories.push(entry);
            }
            PreservedLocalRecord::Volume(volume) => {
                let entry = LegacyStorageVolumeRegistration {
                    volume_id: volume.volume_id,
                    record_format: volume.record_format,
                    path_hex: hex::encode(volume.path.as_os_str().as_bytes()),
                    database_file: volume.database_file.to_owned(),
                    state: volume.state,
                    configured: volume.configured,
                    configured_recorded: volume.configured_recorded,
                    budget_bytes: volume.budget_bytes,
                    headroom_bytes: volume.headroom_bytes,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.storage_volumes.push(entry);
            }
            PreservedLocalRecord::LocalSector(recipe) => {
                let entry = recipe.report();
                account(&entry, used, limit)?;
                report.local_sectors.push(entry);
            }
            PreservedLocalRecord::VolumeOwnership {
                kind,
                key,
                bytes,
                evidence,
            } => {
                let mut unregistered_volume_ids = Vec::new();
                evidence.for_each_volume(|id| {
                    if !report
                        .storage_volumes
                        .iter()
                        .any(|volume| volume.volume_id == id)
                    {
                        unregistered_volume_ids.push(id);
                    }
                });
                unregistered_volume_ids.sort_unstable();
                unregistered_volume_ids.dedup();
                let entry = LegacyVolumeOwnership {
                    record_kind: kind.to_owned(),
                    record_id_hex: hex::encode(key),
                    record_bytes: bytes.len() as u64,
                    record_hash: hex::encode(blake3::hash(bytes).as_bytes()),
                    evidence,
                    unregistered_volume_ids,
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                report.volume_ownership.push(entry);
            }
            PreservedLocalRecord::Capture {
                kind,
                revision_id,
                capture,
            } => {
                let mut entry = LegacyGuardedCapture {
                    record_kind: kind.to_owned(),
                    revision_id,
                    protected_root_id: None,
                    signed_revision_metadata_available: false,
                    namespace_anchor_id: capture.metadata.anchor_id,
                    anchors: Vec::new(),
                    payloads_verified: false,
                };
                account(&entry, used, limit)?;
                for file in capture.files {
                    let locator = file.locator;
                    let pin = LegacyGuardedAnchorPin {
                        namespace_path_hex: hex::encode(file.path),
                        area_id: locator.area.area_id,
                        filesystem_id: locator.area.filesystem_id,
                        area_path_hint_hex: hex::encode(
                            locator.area.path_hint.as_os_str().as_bytes(),
                        ),
                        volume_root_hint_hex: hex::encode(
                            locator.area.volume_root_hint.as_os_str().as_bytes(),
                        ),
                        anchor_id: locator.anchor_id,
                        relative_path_hex: hex::encode(
                            locator.relative_path.as_os_str().as_bytes(),
                        ),
                        logical_len: file.logical_len,
                        content_hash: hex::encode(file.content_hash),
                    };
                    account(&pin, used, limit)?;
                    entry.anchors.push(pin);
                }
                report.guarded_captures.push(entry);
            }
            PreservedLocalRecord::PendingCapture { kind, intent } => {
                let root = intent.plan.preserved_ownership()?;
                let mut planned = ownership(
                    root.record_format,
                    root.anchor_id,
                    root.source_root,
                    root.area,
                    Some(root.recorded_root_identity),
                    root.stable_root_identity,
                );
                account(&planned, used, limit)?;
                intent.plan.for_each_preserved_file_capture(|file| {
                    let pin = LegacyPendingFilePin {
                        relative_path_hex: hex::encode(file.relative_path.as_os_str().as_bytes()),
                        capture_id: file.capture_id,
                        recorded_file_identity: Some(file.native_id),
                        logical_len: file.logical_len,
                    };
                    account(&pin, used, limit)?;
                    planned.file_pins.push(pin);
                    Ok(())
                })?;
                let replaced = intent
                    .replaced_anchor
                    .as_ref()
                    .map(|old| anchors::report_stable(old, used, limit))
                    .transpose()?;
                let entry = LegacyPendingCapture {
                    record_kind: kind.to_owned(),
                    record_format: intent.record_format,
                    guild_id: hex::encode(intent.guild_id),
                    revision_id: intent.revision_id,
                    sequence: intent.sequence,
                    parent: intent.parent.map(hex::encode),
                    captured_change_sequence: intent.captured_change_sequence,
                    requested_source_path_hex: hex::encode(
                        intent.requested_source.as_os_str().as_bytes(),
                    ),
                    backend: match intent.plan {
                        mb_store::SourceCapturePlan::ReflinkV1(_) => {
                            mb_store::SourceBackendKind::ReflinkV1
                        }
                        mb_store::SourceCapturePlan::GuardedLinkFreezeV1(_) => {
                            mb_store::SourceBackendKind::GuardedLinkFreezeV1
                        }
                    },
                    planned_anchor: planned,
                    replaced_anchor: replaced,
                    signed_revision_metadata_available: false,
                    payloads_verified: false,
                };
                // Nested ownership was charged incrementally before allocation.
                // Charge only envelope fields here, without double-counting owners.
                let envelope = (
                    &entry.record_kind,
                    entry.record_format,
                    &entry.guild_id,
                    entry.revision_id,
                    entry.sequence,
                    &entry.parent,
                    entry.captured_change_sequence,
                    &entry.requested_source_path_hex,
                    entry.backend,
                    entry.signed_revision_metadata_available,
                    entry.payloads_verified,
                );
                account(&envelope, used, limit)?;
                report.pending_captures.push(entry);
            }
            PreservedLocalRecord::PendingGitGraph(intent) => {
                let mut entry = git_intents::report(intent, used, limit)?;
                entry.registered_root = report
                    .protected_roots
                    .binary_search_by_key(&intent.protected_root_id, |root| root.root_id)
                    .is_ok();
                entry.registered_repository = report
                    .git_repositories
                    .binary_search_by_key(&intent.graph.repository_id, |repository| {
                        repository.repository_id
                    })
                    .is_ok();
                report.pending_git_graphs.push(entry);
            }
            PreservedLocalRecord::Anchor {
                kind,
                record_id,
                anchor,
            } => {
                let entry = LegacyRetainedAnchor {
                    record_kind: kind.to_owned(),
                    record_id,
                    revision_id: (kind == "anchor-manifest").then_some(record_id),
                    protected_root_id: None,
                    signed_revision_metadata_available: false,
                    anchor: anchor.report(used, limit)?,
                    payloads_verified: false,
                };
                account(
                    &(
                        &entry.record_kind,
                        entry.record_id,
                        entry.revision_id,
                        entry.protected_root_id,
                        entry.signed_revision_metadata_available,
                        entry.payloads_verified,
                    ),
                    used,
                    limit,
                )?;
                report.retained_anchors.push(entry);
            }
            PreservedLocalRecord::AreaLocation { area_id, path } => {
                let entry = LegacyAnchorAreaLocation {
                    area_id,
                    path_hint_hex: hex::encode(path.as_os_str().as_bytes()),
                    absolute_path: path.is_absolute(),
                };
                account(&entry, used, limit)?;
                report.anchor_area_locations.push(entry);
            }
            PreservedLocalRecord::Unclassified { kind, key, bytes } => {
                let entry = LegacyPreservedRecord {
                    kind: kind.to_owned(),
                    record_id_hex: hex::encode(key),
                    payload_bytes: bytes.len() as u64,
                    payload_hash: hex::encode(blake3::hash(bytes).as_bytes()),
                };
                account(&entry, used, limit)?;
                report.unclassified_guarded_records.push(entry);
            }
        }
        Ok(())
    })?;
    Ok(report)
}

impl LegacyLocalStateInventory {
    pub(super) fn reconcile(
        &mut self,
        revisions: &BTreeMap<Uuid, LegacyRevisionInventoryEntry>,
        used: &mut usize,
        limit: usize,
    ) -> Result<()> {
        for revision in revisions.values() {
            if let Ok(index) = self
                .protected_roots
                .binary_search_by_key(&revision.protected_root_id, |root| root.root_id)
            {
                account(&revision.revision_id, used, limit)?;
                self.protected_roots[index]
                    .signed_revision_ids
                    .push(revision.revision_id);
            }
            if let Ok(index) = self
                .git_repositories
                .binary_search_by_key(&revision.protected_root_id, |git| git.repository_id)
            {
                account(&revision.revision_id, used, limit)?;
                self.git_repositories[index]
                    .signed_revision_ids
                    .push(revision.revision_id);
            }
        }
        for intent in &mut self.pending_captures {
            intent.signed_revision_metadata_available = revisions
                .get(&intent.revision_id)
                .is_some_and(|revision| revision.guild_id == intent.guild_id);
        }
        for intent in &mut self.pending_git_graphs {
            intent.signed_revision_metadata_available =
                revisions.get(&intent.revision_id).is_some_and(|revision| {
                    revision.guild_id == intent.guild_id
                        && revision.protected_root_id == intent.protected_root_id
                });
        }
        for anchor in &mut self.retained_anchors {
            if let Some(revision) = anchor.revision_id.and_then(|id| revisions.get(&id)) {
                anchor.signed_revision_metadata_available = true;
                anchor.protected_root_id = Some(revision.protected_root_id);
                account(&revision.protected_root_id, used, limit)?;
            }
        }
        for capture in &mut self.guarded_captures {
            if let Some(revision) = revisions.get(&capture.revision_id) {
                capture.signed_revision_metadata_available = true;
                capture.protected_root_id = Some(revision.protected_root_id);
                account(&revision.protected_root_id, used, limit)?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_export_fetch_and_push_journals_preserve_original_import_owners_without_replay() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        #[derive(Serialize)]
        enum OriginalPlan {
            DirectV1((u16, mb_store::ReflinkCapturePlan, u64)),
        }
        for journal in ["closed", "wal-only", "live"] {
            let temporary = tempfile::tempdir().unwrap();
            let data = temporary.path().join("state");
            let repository = temporary.path().join("repository");
            let safe = temporary.path().join("safe");
            let source = temporary.path().join("stock-git-source");
            let target = temporary.path().join("fetch-target");
            for path in [&data, &repository, &safe, &source, &target] {
                std::fs::create_dir(path).unwrap();
            }
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([239; 32]));
            let repository_id = Uuid::from_u128(239);
            let fetch_id = Uuid::from_u128(240);
            let push_id = Uuid::from_u128(241);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: repository.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let directory = repository.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let tree = mb_git::GitGraphObject {
                kind: 2,
                oid: git2::Oid::hash_object(git2::ObjectType::Tree, b"")
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                bytes: Vec::new(),
            };
            let message = format!("tree {}\nauthor Original <original@example.test> 0 +0000\ncommitter Original <original@example.test> 0 +0000\n\nprivate fetch metadata\n", hex::encode(tree.oid)).into_bytes();
            let commit = mb_git::GitGraphObject {
                kind: 1,
                oid: git2::Oid::hash_object(git2::ObjectType::Commit, &message)
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                bytes: message.clone(),
            };
            let fetch_wire = |format, id, name: &[u8]| {
                canonical_bytes(&(
                    format,
                    id,
                    repository_id,
                    source.as_os_str().as_bytes().to_vec(),
                    target.as_os_str().as_bytes().to_vec(),
                    vec![mb_git::GitGraphRef {
                        name: name.to_vec(),
                        oid: commit.oid,
                    }],
                    vec![tree.clone(), commit.clone()],
                    Vec::<([u8; 20], u64, bool)>::new(),
                ))
                .unwrap()
            };
            let fetch_bytes = fetch_wire(6_u16, fetch_id, b"refs/remotes/origin/main");
            external
                .put_record(
                    &format!("git-bare-fetch-intent-v1/{repository_id}"),
                    b"active",
                    &fetch_bytes,
                )
                .unwrap();
            // The original push envelope embeds the original positional fetch.
            let push_bytes = canonical_bytes(&(
                1_u16,
                "main",
                Some(commit.oid),
                (
                    2_u16,
                    push_id,
                    repository_id,
                    source.as_os_str().as_bytes().to_vec(),
                    target.as_os_str().as_bytes().to_vec(),
                    vec![mb_git::GitGraphRef {
                        name: b"refs/heads/main".to_vec(),
                        oid: commit.oid,
                    }],
                    vec![tree.clone(), commit.clone()],
                    Vec::<([u8; 20], u64, bool)>::new(),
                ),
            ))
            .unwrap();
            external
                .put_record(
                    &format!("git-stock-push-intent-v1/{repository_id}"),
                    b"active",
                    &push_bytes,
                )
                .unwrap();
            let mut excluded = vec![source.clone(), target.clone()];
            let mut originals = Vec::new();
            for era in 0..2 {
                let root = temporary.path().join(format!("import-root-{era}"));
                let area_path = temporary.path().join(format!("import-area-{era}"));
                for path in [&root, &area_path] {
                    std::fs::create_dir(path).unwrap();
                }
                let metadata = std::fs::metadata(&root).unwrap();
                let identity = if era == 0 {
                    NativeFileId {
                        filesystem_id: metadata.dev(),
                        inode: metadata.ino(),
                    }
                } else {
                    mb_store::PinnedDirectory::open(&root)
                        .unwrap()
                        .identity()
                        .unwrap()
                };
                let anchor_id = Uuid::from_u128(242 + era);
                let area = mb_store::StableAnchorAreaLocator {
                    area_id: Uuid::from_u128(244 + era),
                    filesystem_id: identity.filesystem_id,
                    path_hint: area_path.clone(),
                    volume_root_hint: area_path.clone(),
                };
                let root_plan: mb_store::ReflinkCapturePlan = decode_canonical(
                    &canonical_bytes(&(
                        1_u16,
                        anchor_id,
                        root.as_os_str().as_bytes().to_vec(),
                        area.clone(),
                        (
                            identity.filesystem_id,
                            identity.inode,
                            0_u64,
                            0_i64,
                            0_i64,
                            0_i64,
                            0_i64,
                        ),
                        libc::S_IFDIR | 0o700,
                        0_i64,
                        0_u32,
                    ))
                    .unwrap(),
                )
                .unwrap();
                let oid = [50 + era as u8; 20];
                let bytes = canonical_bytes(&(
                    1_u16,
                    repository_id,
                    oid,
                    8_u64,
                    OriginalPlan::DirectV1((1, root_plan, 8)),
                ))
                .unwrap();
                external
                    .put_record(
                        &format!("git-bare-fetch-blob-intent-v1/{repository_id}"),
                        &oid,
                        &bytes,
                    )
                    .unwrap();
                let verified_bytes =
                    canonical_bytes(&(1_u16, oid, vec![(anchor_id, [60 + era as u8; 32])]))
                        .unwrap();
                external
                    .put_record(
                        &format!("git-bare-fetch-verified-v1/{repository_id}/{fetch_id}"),
                        &oid,
                        &verified_bytes,
                    )
                    .unwrap();
                let renamed = temporary.path().join(format!("renamed-import-root-{era}"));
                std::fs::rename(&root, &renamed).unwrap();
                originals.push((oid, anchor_id, area, identity, root));
                excluded.extend([renamed, area_path]);
            }
            let mut aliases = Vec::new();
            for (index, path) in excluded.iter().enumerate() {
                std::fs::create_dir(path.join("child")).unwrap();
                std::fs::write(path.join("original"), b"preserve import owner").unwrap();
                let alias = temporary.path().join(format!("alias-{index}"));
                std::os::unix::fs::symlink(path, &alias).unwrap();
                aliases.push(alias);
            }
            let mut writers = Some((control, external));
            if journal == "closed" {
                drop(writers.take());
            }
            if journal == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let bytes = if entry.file_name().as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (entry.file_name(), bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert_eq!(report.local_state.pending_git_fetches.len(), 2);
            assert_eq!(report.local_state.pending_git_blob_imports.len(), 2);
            assert_eq!(report.local_state.verified_git_fetch_blobs.len(), 2);
            let registration = &report.local_state.git_repositories[0];
            assert!(
                registration.fetch_intents_inventoried
                    && registration.push_intents_inventoried
                    && registration.blob_import_intents_inventoried
                    && registration.fetch_verification_records_inventoried
            );
            assert!(!registration.catalog_inventoried);
            for entry in &report.local_state.pending_git_fetches {
                assert_eq!(entry.repository_id, repository_id);
                assert_eq!(
                    entry.source_path_hint_hex,
                    hex::encode(source.as_os_str().as_bytes())
                );
                assert_eq!(
                    entry.source_root_hint_hex,
                    hex::encode(target.as_os_str().as_bytes())
                );
                assert!(!entry.graph_metadata_validated && !entry.payloads_verified);
                assert_eq!(entry.objects.len(), 2);
                assert_eq!(
                    entry.objects[1].payload_hash,
                    hex::encode(blake3::hash(&message).as_bytes())
                );
                if entry.fetch_id == push_id {
                    assert_eq!(entry.record_format, 2);
                    assert_eq!(
                        entry.push,
                        Some(LegacyPendingGitPush {
                            record_format: 1,
                            target_name: "main".into(),
                            expected_old: Some(hex::encode(commit.oid))
                        })
                    );
                } else {
                    assert_eq!(entry.fetch_id, fetch_id);
                    assert_eq!(entry.record_format, 6);
                    assert!(entry.push.is_none());
                }
            }
            for (oid, anchor_id, area, identity, root) in &originals {
                let entry = report
                    .local_state
                    .pending_git_blob_imports
                    .iter()
                    .find(|entry| entry.oid == hex::encode(oid))
                    .unwrap();
                assert_eq!(entry.plan.anchor_id, *anchor_id);
                assert_eq!(entry.plan.recorded_root_identity, *identity);
                assert_eq!(entry.plan.stable_root_identity, None);
                assert_eq!(
                    entry.plan.area_path_hint_hex,
                    hex::encode(area.path_hint.as_os_str().as_bytes())
                );
                assert_eq!(
                    entry.plan.source_root_hint_hex,
                    hex::encode(root.as_os_str().as_bytes())
                );
                assert_eq!(entry.logical_len, 8);
                assert!(!entry.payloads_verified);
                let verified = report
                    .local_state
                    .verified_git_fetch_blobs
                    .iter()
                    .find(|entry| entry.oid == hex::encode(oid))
                    .unwrap();
                assert_eq!(verified.fetch_id, fetch_id);
                assert_eq!(verified.anchors[0].anchor_id, *anchor_id);
                assert!(!verified.payloads_verified);
            }
            let json = serde_json::to_vec(&report).unwrap();
            assert!(!String::from_utf8_lossy(&json).contains("private fetch metadata"));
            assert_eq!(
                serde_json::from_slice::<super::super::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            for path in excluded.iter().chain(&aliases) {
                for parent in [path.clone(), path.join("child")] {
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err(),
                        "{journal}: {}",
                        parent.display()
                    );
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err()
                    );
                }
                assert_eq!(
                    std::fs::read(path.join("original")).unwrap(),
                    b"preserve import owner"
                );
                assert_eq!(std::fs::read_dir(path.join("child")).unwrap().count(), 0);
            }
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
                let mut local = collect(control, &mut 0, V1_MAX_CATALOG_BYTES)?;
                let mut used = 0;
                collect_external_git_records(
                    control,
                    &keys,
                    &mut local,
                    &mut used,
                    V1_MAX_CATALOG_BYTES,
                )?;
                let mut expected = 0;
                for entry in &local.pending_git_fetches {
                    let mut envelope = entry.clone();
                    envelope.refs.clear();
                    envelope.objects.clear();
                    envelope.blobs.clear();
                    account(&envelope, &mut expected, V1_MAX_CATALOG_BYTES)?;
                    for item in &entry.refs {
                        account(item, &mut expected, V1_MAX_CATALOG_BYTES)?;
                    }
                    for item in &entry.objects {
                        account(item, &mut expected, V1_MAX_CATALOG_BYTES)?;
                    }
                    for item in &entry.blobs {
                        account(item, &mut expected, V1_MAX_CATALOG_BYTES)?;
                    }
                }
                for entry in &local.pending_git_blob_imports {
                    account(entry, &mut expected, V1_MAX_CATALOG_BYTES)?;
                }
                for entry in &local.verified_git_fetch_blobs {
                    let mut envelope = entry.clone();
                    envelope.anchors.clear();
                    account(&envelope, &mut expected, V1_MAX_CATALOG_BYTES)?;
                    for item in &entry.anchors {
                        account(item, &mut expected, V1_MAX_CATALOG_BYTES)?;
                    }
                }
                assert_eq!(used, expected);
                Ok(())
            })
            .unwrap();
            assert_eq!((snapshot(&data), snapshot(&directory)), before);
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            if journal == "closed" {
                let external = ControlStore::open_with_key(
                    &external_path,
                    &mb_git::catalog_key(&keys, repository_id),
                )
                .unwrap();
                external
                    .put_record(
                        &format!("git-bare-fetch-verified-v1/{repository_id}/{fetch_id}"),
                        &[99; 20],
                        b"corrupt late verification",
                    )
                    .unwrap();
                drop(external);
                let corrupted = (snapshot(&data), snapshot(&directory));
                assert!(
                    super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err()
                );
                assert!(
                    super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                        .is_err()
                );
                assert!(
                    super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                        .is_err()
                );
                assert_eq!((snapshot(&data), snapshot(&directory)), corrupted);
            }
            assert!(!source.join(".git").exists() && !target.join(".mutualbackup").exists());
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_worktree_removal_journals_preserve_renamed_and_relocated_directory_owners() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for journal in ["closed", "wal-only", "live"] {
            let temporary = tempfile::tempdir().unwrap();
            let data = temporary.path().join("state");
            let repository = temporary.path().join("repository");
            let safe = temporary.path().join("safe");
            for path in [&data, &repository, &safe] {
                std::fs::create_dir(path).unwrap();
            }
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([227; 32]));
            let repository_id = Uuid::from_u128(227);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: repository.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let directory = repository.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let kind = format!("git-worktree-remove-intent-v1/{repository_id}");
            let mut excluded = Vec::new();
            let mut originals = Vec::new();
            for era in 0..2 {
                let root = temporary.path().join(format!("root-{era}"));
                let marker = root.join(".mutualbackup");
                let nested = root.join("nested");
                for path in [&root, &marker, &nested] {
                    std::fs::create_dir(path).unwrap();
                }
                std::fs::write(marker.join("worktree"), b"original marker bytes").unwrap();
                std::fs::write(nested.join("file"), b"original tracked bytes").unwrap();
                let identity = |path: &Path| {
                    if era == 0 {
                        let metadata = std::fs::symlink_metadata(path).unwrap();
                        NativeFileId {
                            filesystem_id: metadata.dev(),
                            inode: metadata.ino(),
                        }
                    } else {
                        let parent =
                            mb_store::PinnedDirectory::open(path.parent().unwrap()).unwrap();
                        parent
                            .entry_identity(path.file_name().unwrap(), path.is_dir())
                            .unwrap()
                            .unwrap()
                    }
                };
                let worktree_id = Uuid::from_u128(228 + era);
                let root_id = identity(&root);
                let parent_id = identity(root.parent().unwrap());
                let marker_directory_id = identity(&marker);
                let marker_id = identity(&marker.join("worktree"));
                let file_id = identity(&nested.join("file"));
                let nested_id = identity(&nested);
                let bytes = canonical_bytes(&(
                    1_u16,
                    repository_id,
                    worktree_id,
                    root_id,
                    parent_id,
                    marker_directory_id,
                    marker_id,
                    vec![(b"nested/file".to_vec(), [37_u8; 20], 0o100644_u32, file_id)],
                    vec![(b"nested".to_vec(), nested_id)],
                ))
                .unwrap();
                external
                    .put_record(&kind, worktree_id.as_bytes(), &bytes)
                    .unwrap();
                // User relocation after the saved journal must not free ownership.
                let renamed = temporary.path().join(format!("renamed-{era}"));
                std::fs::rename(&root, &renamed).unwrap();
                let moved_marker = temporary.path().join(format!("marker-{era}"));
                let moved_nested = temporary.path().join(format!("nested-{era}"));
                std::fs::rename(renamed.join(".mutualbackup"), &moved_marker).unwrap();
                std::fs::rename(renamed.join("nested"), &moved_nested).unwrap();
                originals.push((
                    worktree_id,
                    root_id,
                    parent_id,
                    marker_directory_id,
                    marker_id,
                    file_id,
                    nested_id,
                    moved_marker.clone(),
                    moved_nested.clone(),
                ));
                for path in [renamed, moved_marker, moved_nested] {
                    std::fs::create_dir(path.join("child")).unwrap();
                    let alias = temporary.path().join(format!("alias-{}", excluded.len()));
                    std::os::unix::fs::symlink(&path, &alias).unwrap();
                    excluded.push((path, alias));
                }
            }
            let mut writers = Some((control, external));
            if journal == "closed" {
                drop(writers.take());
            }
            if journal == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let bytes = if entry.file_name().as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (entry.file_name(), bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert!(
                report.local_state.git_worktrees.is_empty()
                    && report.local_state.git_indexes.is_empty()
            );
            assert_eq!(report.local_state.pending_git_worktree_removals.len(), 2);
            let registration = &report.local_state.git_repositories[0];
            assert!(registration.worktree_removal_intents_inventoried);
            assert!(!registration.catalog_inventoried);
            for (
                worktree,
                root,
                parent,
                marker_dir,
                marker,
                file,
                nested,
                marker_path,
                nested_path,
            ) in &originals
            {
                let entry = report
                    .local_state
                    .pending_git_worktree_removals
                    .iter()
                    .find(|entry| entry.worktree_id == *worktree)
                    .unwrap();
                assert_eq!(entry.repository_id, repository_id);
                assert_eq!(entry.record_format, 1);
                assert_eq!(entry.recorded_root_identity, *root);
                assert_eq!(entry.recorded_parent_identity, *parent);
                assert_eq!(entry.recorded_marker_directory_identity, *marker_dir);
                assert_eq!(entry.recorded_marker_identity, *marker);
                assert!(!entry.payloads_verified);
                assert_eq!(
                    entry.files,
                    vec![LegacyWorktreeRemovalFile {
                        relative_path_hex: hex::encode(b"nested/file"),
                        oid: hex::encode([37; 20]),
                        mode: 0o100644,
                        recorded_identity: *file,
                    }]
                );
                assert_eq!(
                    entry.directories,
                    vec![LegacyWorktreeRemovalDirectory {
                        relative_path_hex: hex::encode(b"nested"),
                        recorded_identity: *nested,
                    }]
                );
                assert_eq!(
                    std::fs::read(marker_path.join("worktree")).unwrap(),
                    b"original marker bytes"
                );
                assert_eq!(
                    std::fs::read(nested_path.join("file")).unwrap(),
                    b"original tracked bytes"
                );
            }
            assert_eq!(
                serde_json::from_slice::<super::super::LegacyRevisionInventory>(
                    &serde_json::to_vec(&report).unwrap()
                )
                .unwrap(),
                report
            );
            for (path, alias) in &excluded {
                for parent in [
                    path.clone(),
                    path.join("child"),
                    alias.clone(),
                    alias.join("child"),
                ] {
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err(),
                        "{journal}: {}",
                        parent.display()
                    );
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err()
                    );
                }
                assert_eq!(std::fs::read_dir(path.join("child")).unwrap().count(), 0);
            }
            // A containing parent is shared location metadata, not owned input.
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            assert!(
                super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                    .is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
                let mut local = collect(control, &mut 0, V1_MAX_CATALOG_BYTES)?;
                let mut used = 0;
                collect_external_git_records(
                    control,
                    &keys,
                    &mut local,
                    &mut used,
                    V1_MAX_CATALOG_BYTES,
                )?;
                let mut expected = 0;
                for entry in &local.pending_git_worktree_removals {
                    account(entry, &mut expected, V1_MAX_CATALOG_BYTES)?;
                }
                assert_eq!(used, expected);
                Ok(())
            })
            .unwrap();
            assert_eq!((snapshot(&data), snapshot(&directory)), before);
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            if journal == "closed" {
                let external = ControlStore::open_with_key(
                    &external_path,
                    &mb_git::catalog_key(&keys, repository_id),
                )
                .unwrap();
                external
                    .put_record(
                        &kind,
                        Uuid::from_u128(999).as_bytes(),
                        b"corrupt late removal",
                    )
                    .unwrap();
                drop(external);
                let corrupted = (snapshot(&data), snapshot(&directory));
                assert!(
                    super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err()
                );
                assert!(
                    super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                        .is_err()
                );
                assert!(
                    super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                        .is_err()
                );
                assert_eq!((snapshot(&data), snapshot(&directory)), corrupted);
            }
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_external_git_prune_and_removal_intents_preserve_retired_and_renamed_owners() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for journal in ["closed", "wal-only", "live"] {
            let temporary = tempfile::tempdir().unwrap();
            let data = temporary.path().join("state");
            let repository = temporary.path().join("repository");
            let safe = temporary.path().join("safe");
            for path in [&data, &repository, &safe] {
                std::fs::create_dir(path).unwrap();
            }
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([221; 32]));
            let repository_id = Uuid::from_u128(221);
            let linked_id = Uuid::from_u128(222);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: repository.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let directory = repository.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let mut excluded = Vec::new();
            let mut anchors = Vec::new();
            for index in 0..3 {
                let source = raw_path(temporary.path(), &[b's', b'0' + index as u8, 255]);
                let area = raw_path(temporary.path(), &[b'a', b'0' + index as u8, 254]);
                for path in [&source, &area] {
                    std::fs::create_dir(path).unwrap();
                    std::fs::create_dir(path.join("nested")).unwrap();
                    std::fs::write(path.join("original"), b"preserved retirement owner").unwrap();
                    let alias = temporary.path().join(format!("alias-{}", excluded.len()));
                    std::os::unix::fs::symlink(path, &alias).unwrap();
                    excluded.push((path.clone(), alias));
                }
                anchors.push(super::owner_tests::blob(&source, &area, index).anchor);
            }
            let prune_kind = format!("git-prune-intent-v1/{repository_id}");
            external
                .put_record(
                    &prune_kind,
                    b"active",
                    &canonical_bytes(&(1_u16, repository_id, &anchors)).unwrap(),
                )
                .unwrap();
            let mut removals = Vec::new();
            for index in 0..2 {
                let root = temporary.path().join(format!("removal-root-{index}"));
                std::fs::create_dir(&root).unwrap();
                std::fs::create_dir(root.join("nested")).unwrap();
                std::fs::write(root.join("original"), b"preserved retirement owner").unwrap();
                let metadata = std::fs::metadata(&root).unwrap();
                let root_id = if index == 0 {
                    NativeFileId {
                        filesystem_id: metadata.dev(),
                        inode: metadata.ino(),
                    }
                } else {
                    mb_store::PinnedDirectory::open(&root)
                        .unwrap()
                        .identity()
                        .unwrap()
                };
                let worktree_id = if index == 0 { repository_id } else { linked_id };
                let kind = if index == 0 {
                    format!("git-rm-intent-v1/{repository_id}")
                } else {
                    format!("git-worktree-rm-intent-v1/{repository_id}/{linked_id}")
                };
                let entry = mb_git::GitIndexEntry {
                    format_version: 1,
                    oid: [33; 20],
                    mode: if index == 0 { 0o100755 } else { 0o120000 },
                    anchor_id: Uuid::from_u128(223 + index),
                };
                let file_id = NativeFileId {
                    filesystem_id: root_id.filesystem_id,
                    inode: 17,
                };
                let relative = b"remove-\xfd".to_vec();
                let original = canonical_bytes(&(
                    1_u16,
                    repository_id,
                    worktree_id,
                    root_id,
                    &relative,
                    &entry,
                    file_id,
                ))
                .unwrap();
                external.put_record(&kind, &relative, &original).unwrap();
                let renamed = temporary.path().join(format!("renamed-removal-{index}"));
                std::fs::rename(&root, &renamed).unwrap();
                let alias = temporary.path().join(format!("alias-{}", excluded.len()));
                std::os::unix::fs::symlink(&renamed, &alias).unwrap();
                excluded.push((renamed, alias));
                removals.push((worktree_id, root_id, relative, entry, file_id));
            }
            let mut writers = Some((control, external));
            if journal == "closed" {
                drop(writers.take());
            }
            if journal == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let bytes = if entry.file_name().as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (entry.file_name(), bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert!(
                report.local_state.git_worktrees.is_empty()
                    && report.local_state.git_indexes.is_empty()
                    && report.local_state.git_object_anchors.is_empty()
            );
            assert_eq!(report.local_state.pending_git_removals.len(), 2);
            assert_eq!(report.local_state.pending_git_prunes.len(), 1);
            let registration = &report.local_state.git_repositories[0];
            assert!(
                registration.prune_intents_inventoried && registration.removal_intents_inventoried
            );
            assert!(!registration.catalog_inventoried);
            let prune = &report.local_state.pending_git_prunes[0];
            assert_eq!(prune.repository_id, repository_id);
            assert_eq!(prune.record_format, 1);
            assert!(!prune.payloads_verified);
            assert_eq!(prune.anchors.len(), 3);
            for anchor in &anchors {
                let projected = prune
                    .anchors
                    .iter()
                    .find(|entry| entry.anchor_id == anchor.anchor_id)
                    .unwrap();
                assert_eq!(*projected, prune_file_anchor(anchor).unwrap());
            }
            for (worktree, root_id, relative, index, file_id) in &removals {
                let removal = report
                    .local_state
                    .pending_git_removals
                    .iter()
                    .find(|entry| entry.worktree_id == *worktree)
                    .unwrap();
                assert_eq!(removal.repository_id, repository_id);
                assert_eq!(removal.record_format, 1);
                assert_eq!(removal.recorded_root_identity, *root_id);
                assert_eq!(removal.recorded_file_identity, *file_id);
                assert_eq!(removal.relative_path_hex, hex::encode(relative));
                assert_eq!(removal.entry, *index);
                assert!(!removal.payloads_verified);
            }
            let json = serde_json::to_vec(&report).unwrap();
            assert_eq!(
                serde_json::from_slice::<super::super::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            for (path, alias) in &excluded {
                for parent in [
                    path.clone(),
                    path.join("nested"),
                    alias.clone(),
                    alias.join("nested"),
                ] {
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err(),
                        "{journal}: {}",
                        parent.display()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err()
                    );
                }
                assert_eq!(
                    std::fs::read(path.join("original")).unwrap(),
                    b"preserved retirement owner"
                );
                assert_eq!(std::fs::read_dir(path).unwrap().count(), 2);
                assert_eq!(std::fs::read_dir(path.join("nested")).unwrap().count(), 0);
            }
            assert!(
                super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                    .is_ok()
            );
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
                let mut report = collect(control, &mut 0, V1_MAX_CATALOG_BYTES)?;
                let mut used = 0;
                collect_external_git_records(
                    control,
                    &keys,
                    &mut report,
                    &mut used,
                    V1_MAX_CATALOG_BYTES,
                )?;
                let mut expected = 0;
                for entry in &report.pending_git_removals {
                    account(entry, &mut expected, V1_MAX_CATALOG_BYTES)?;
                }
                for entry in &report.pending_git_prunes {
                    account(entry, &mut expected, V1_MAX_CATALOG_BYTES)?;
                }
                assert_eq!(used, expected);
                Ok(())
            })
            .unwrap();
            assert_eq!((snapshot(&data), snapshot(&directory)), before, "{journal}");
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            if journal == "closed" {
                for (kind, key) in [
                    (
                        format!(
                            "git-worktree-rm-intent-v1/{repository_id}/{}",
                            Uuid::from_u128(999)
                        ),
                        b"zz-last".as_slice(),
                    ),
                    (prune_kind.clone(), b"wrong".as_slice()),
                ] {
                    let external = ControlStore::open_with_key(
                        &external_path,
                        &mb_git::catalog_key(&keys, repository_id),
                    )
                    .unwrap();
                    external
                        .put_record(&kind, key, b"corrupt retirement")
                        .unwrap();
                    drop(external);
                    let corrupted = (snapshot(&data), snapshot(&directory));
                    assert!(
                        super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                            .is_err()
                    );
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &safe,
                            &[],
                            false
                        )
                        .is_err()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                            .is_err()
                    );
                    assert_eq!((snapshot(&data), snapshot(&directory)), corrupted);
                    let external = ControlStore::open_with_key(
                        &external_path,
                        &mb_git::catalog_key(&keys, repository_id),
                    )
                    .unwrap();
                    external.delete_record(&kind, key).unwrap();
                    drop(external);
                }
            }
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_external_git_symlink_stages_preserve_original_phases_and_target_privacy() {
        use mb_store::{SourceFileCapturePlan, StableAnchorAreaLocator};
        use std::os::unix::fs::PermissionsExt;
        #[derive(Serialize)]
        struct OriginalIntent {
            format_version: u16,
            repository_id: Uuid,
            source_root: Vec<u8>,
            root_id: NativeFileId,
            catalog_id: NativeFileId,
            relative_path: Vec<u8>,
            source_id: NativeFileId,
            target: Vec<u8>,
            temp_name: String,
            temp_id: Option<NativeFileId>,
            plan: Option<SourceFileCapturePlan>,
            #[serde(skip_serializing_if = "Option::is_none")]
            catalog_root: Option<Vec<u8>>,
        }
        for journal in ["closed", "wal-only", "live"] {
            let temporary = tempfile::tempdir().unwrap();
            let data = temporary.path().join("state");
            let repository = temporary.path().join("repository");
            let source = raw_path(temporary.path(), b"symlink-source-\xff");
            let catalog_root = raw_path(temporary.path(), b"symlink-catalog-\xfe");
            let area = raw_path(temporary.path(), b"symlink-area-\xfd");
            let safe = temporary.path().join("safe");
            for path in [&data, &repository, &source, &catalog_root, &area, &safe] {
                std::fs::create_dir(path).unwrap();
            }
            for path in [&source, &catalog_root, &area] {
                std::fs::create_dir(path.join("nested")).unwrap();
                std::fs::write(path.join("original"), b"preserved symlink owner").unwrap();
            }
            for path in [&source, &catalog_root] {
                std::fs::create_dir(path.join(mb_store::GIT_CATALOG_DIRECTORY)).unwrap();
            }
            let source_id = mb_store::PinnedDirectory::open(&source)
                .unwrap()
                .identity()
                .unwrap();
            let catalog_root_id = mb_store::PinnedDirectory::open(&catalog_root)
                .unwrap()
                .identity()
                .unwrap();
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([212; 32]));
            let repository_id = Uuid::from_u128(212);
            let linked_id = Uuid::from_u128(213);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: repository.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let directory = repository.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let target = b"private-symlink-target-\xfc".to_vec();
            let temp_name = format!("symlink-input-{}", Uuid::from_u128(214));
            let mut expected = Vec::new();
            for format in [1_u16, 2] {
                let (root, root_id) = if format == 1 {
                    (&source, source_id)
                } else {
                    (&catalog_root, catalog_root_id)
                };
                let catalog_id =
                    mb_store::PinnedDirectory::open(root.join(mb_store::GIT_CATALOG_DIRECTORY))
                        .unwrap()
                        .identity()
                        .unwrap();
                let kind = if format == 1 {
                    format!("git-symlink-stage-intent-v1/{repository_id}")
                } else {
                    format!("git-worktree-symlink-stage-intent-v1/{repository_id}/{linked_id}")
                };
                let temp_id = NativeFileId {
                    filesystem_id: root_id.filesystem_id,
                    inode: 52,
                };
                let locator = StableAnchorAreaLocator {
                    area_id: Uuid::from_u128(215 + format as u128),
                    path_hint: area.clone(),
                    filesystem_id: root_id.filesystem_id,
                    volume_root_hint: temporary.path().to_path_buf(),
                };
                for phase in 0..5 {
                    let plan = if phase < 2 {
                        None
                    } else {
                        let relative =
                            PathBuf::from(mb_store::GIT_CATALOG_DIRECTORY).join(&temp_name);
                        let capture_id =
                            Uuid::from_u128(220 + u128::from(format) * 10 + phase as u128);
                        let version = (
                            temp_id.filesystem_id,
                            temp_id.inode,
                            target.len() as u64,
                            0_i64,
                            0_i64,
                            0_i64,
                            0_i64,
                        );
                        Some(if phase == 3 {
                            SourceFileCapturePlan::GuardedLinkFreezeV1(
                                decode_canonical(
                                    &canonical_bytes(&(
                                        1_u16,
                                        capture_id,
                                        root.as_os_str().as_bytes().to_vec(),
                                        root_id,
                                        relative.as_os_str().as_bytes().to_vec(),
                                        version,
                                        0o100600_u32,
                                        &locator,
                                    ))
                                    .unwrap(),
                                )
                                .unwrap(),
                            )
                        } else {
                            let root_plan: mb_store::ReflinkCapturePlan = decode_canonical(
                                &canonical_bytes(&(
                                    1_u16,
                                    capture_id,
                                    root.as_os_str().as_bytes().to_vec(),
                                    &locator,
                                    (
                                        root_id.filesystem_id,
                                        root_id.inode,
                                        0_u64,
                                        0_i64,
                                        0_i64,
                                        0_i64,
                                        0_i64,
                                    ),
                                    0o40700_u32,
                                    0_i64,
                                    0_u32,
                                ))
                                .unwrap(),
                            )
                            .unwrap();
                            if phase == 2 {
                                SourceFileCapturePlan::ReflinkV1(
                                    decode_canonical(
                                        &canonical_bytes(&(
                                            1_u16,
                                            root_plan,
                                            relative.to_str().unwrap(),
                                            version,
                                        ))
                                        .unwrap(),
                                    )
                                    .unwrap(),
                                )
                            } else {
                                SourceFileCapturePlan::ReflinkRawV2(
                                    decode_canonical(
                                        &canonical_bytes(&(
                                            2_u16,
                                            root_plan,
                                            relative.as_os_str().as_bytes().to_vec(),
                                            version,
                                        ))
                                        .unwrap(),
                                    )
                                    .unwrap(),
                                )
                            }
                        })
                    };
                    let relative_path = [format!("link-{phase}-").as_bytes(), &[251]].concat();
                    let original = OriginalIntent {
                        format_version: format,
                        repository_id,
                        source_root: source.as_os_str().as_bytes().to_vec(),
                        root_id: source_id,
                        catalog_id,
                        relative_path: relative_path.clone(),
                        source_id: NativeFileId {
                            filesystem_id: source_id.filesystem_id,
                            inode: 51,
                        },
                        target: target.clone(),
                        temp_name: temp_name.clone(),
                        temp_id: (phase > 0).then_some(temp_id),
                        plan,
                        catalog_root: (format == 2)
                            .then(|| catalog_root.as_os_str().as_bytes().to_vec()),
                    };
                    external
                        .put_record(&kind, &relative_path, &canonical_bytes(&original).unwrap())
                        .unwrap();
                    expected.push((format, phase, original));
                }
            }
            let renamed_source = temporary.path().join("renamed-source");
            let renamed_catalog = temporary.path().join("renamed-catalog");
            std::fs::rename(&source, &renamed_source).unwrap();
            std::fs::rename(&catalog_root, &renamed_catalog).unwrap();
            let mut excluded = Vec::new();
            for path in [&renamed_source, &renamed_catalog, &area] {
                let alias = temporary.path().join(format!("alias-{}", excluded.len()));
                std::os::unix::fs::symlink(path, &alias).unwrap();
                excluded.push((path.clone(), alias));
            }
            let mut writers = Some((control, external));
            if journal == "closed" {
                drop(writers.take());
            }
            if journal == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let bytes = if entry.file_name().as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (entry.file_name(), bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert!(
                report.local_state.git_worktrees.is_empty()
                    && report.local_state.git_indexes.is_empty()
                    && report.local_state.pending_git_stages.is_empty()
            );
            assert_eq!(report.local_state.pending_git_symlinks.len(), 10);
            assert!(report.local_state.git_repositories[0].symlink_stage_intents_inventoried);
            assert!(!report.local_state.git_repositories[0].catalog_inventoried);
            for (format, phase, original) in &expected {
                let worktree_id = if *format == 1 {
                    repository_id
                } else {
                    linked_id
                };
                let entry = report
                    .local_state
                    .pending_git_symlinks
                    .iter()
                    .find(|entry| {
                        entry.worktree_id == worktree_id
                            && entry.relative_path_hex == hex::encode(&original.relative_path)
                    })
                    .unwrap();
                assert_eq!(entry.record_format, *format);
                assert_eq!(entry.recorded_root_identity, original.root_id);
                assert_eq!(entry.recorded_catalog_identity, original.catalog_id);
                assert_eq!(entry.recorded_source_identity, original.source_id);
                assert_eq!(entry.recorded_temp_identity, original.temp_id);
                assert_eq!(entry.temp_name, temp_name);
                assert_eq!(
                    entry.catalog_root_hint_hex,
                    original.catalog_root.as_ref().map(hex::encode)
                );
                assert_eq!(entry.target_bytes, target.len() as u64);
                assert_eq!(
                    entry.target_hash,
                    hex::encode(blake3::hash(&target).as_bytes())
                );
                assert_eq!(
                    entry.plan,
                    original
                        .plan
                        .as_ref()
                        .map(file_capture_plan)
                        .transpose()
                        .unwrap()
                );
                assert_eq!(entry.plan.is_some(), *phase >= 2);
                assert!(!entry.payloads_verified);
            }
            let json = serde_json::to_vec(&report).unwrap();
            assert!(!String::from_utf8_lossy(&json).contains("private-symlink-target"));
            assert!(!String::from_utf8_lossy(&json).contains(&hex::encode(&target)));
            assert_eq!(
                serde_json::from_slice::<super::super::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            for (path, alias) in &excluded {
                for parent in [
                    path.clone(),
                    path.join("nested"),
                    alias.clone(),
                    alias.join("nested"),
                ] {
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err(),
                        "{journal}: {}",
                        parent.display()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err()
                    );
                }
                assert_eq!(
                    std::fs::read(path.join("original")).unwrap(),
                    b"preserved symlink owner"
                );
                assert_eq!(std::fs::read_dir(path.join("nested")).unwrap().count(), 0);
            }
            assert!(
                super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                    .is_ok()
            );
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
                let mut report = collect(control, &mut 0, V1_MAX_CATALOG_BYTES)?;
                let mut used = 0;
                collect_external_git_records(
                    control,
                    &keys,
                    &mut report,
                    &mut used,
                    V1_MAX_CATALOG_BYTES,
                )?;
                let mut exact = 0;
                for entry in &report.pending_git_symlinks {
                    account(entry, &mut exact, V1_MAX_CATALOG_BYTES)?;
                }
                assert_eq!(used, exact);
                Ok(())
            })
            .unwrap();
            assert_eq!((snapshot(&data), snapshot(&directory)), before);
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            if journal == "closed" {
                let external = ControlStore::open_with_key(
                    &external_path,
                    &mb_git::catalog_key(&keys, repository_id),
                )
                .unwrap();
                external
                    .put_record(
                        &format!(
                            "git-worktree-symlink-stage-intent-v1/{repository_id}/{}",
                            Uuid::from_u128(999)
                        ),
                        b"zz-last",
                        b"broken symlink",
                    )
                    .unwrap();
                drop(external);
                let corrupted = (snapshot(&data), snapshot(&directory));
                assert!(
                    super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err()
                );
                assert!(
                    super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                        .is_err()
                );
                assert!(
                    super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                        .is_err()
                );
                assert_eq!((snapshot(&data), snapshot(&directory)), corrupted);
            }
            for root in [&renamed_source, &renamed_catalog] {
                assert_eq!(
                    std::fs::read_dir(root.join(mb_store::GIT_CATALOG_DIRECTORY))
                        .unwrap()
                        .count(),
                    0
                );
            }
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_external_git_regular_stage_plans_preserve_original_inputs_and_renamed_roots() {
        use mb_store::{ReflinkCapturePlan, SourceFileCapturePlan, StableAnchorAreaLocator};
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for journal in ["closed", "wal-only", "live"] {
            let temporary = tempfile::tempdir().unwrap();
            let data = temporary.path().join("state");
            let repository = temporary.path().join("repository");
            let safe = temporary.path().join("safe");
            for path in [&data, &repository, &safe] {
                std::fs::create_dir(path).unwrap();
            }
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([198; 32]));
            let repository_id = Uuid::from_u128(198);
            let linked_id = Uuid::from_u128(199);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: repository.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let catalog_directory = repository.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&catalog_directory).unwrap();
            std::fs::set_permissions(&catalog_directory, std::fs::Permissions::from_mode(0o700))
                .unwrap();
            let marker = catalog_directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = catalog_directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let mut expected = Vec::new();
            let mut excluded = Vec::new();
            for index in 0..3 {
                let source = raw_path(temporary.path(), &[b's', b'0' + index as u8, 255]);
                let area = raw_path(temporary.path(), &[b'a', b'0' + index as u8, 254]);
                for path in [&source, &area] {
                    std::fs::create_dir(path).unwrap();
                    std::fs::create_dir(path.join("nested")).unwrap();
                    std::fs::write(path.join("original"), b"preserved staging input").unwrap();
                }
                let metadata = std::fs::metadata(&source).unwrap();
                let stable_id = mb_store::PinnedDirectory::open(&source)
                    .unwrap()
                    .identity()
                    .unwrap();
                let recorded_id = if index == 0 {
                    NativeFileId {
                        filesystem_id: metadata.dev(),
                        inode: metadata.ino(),
                    }
                } else {
                    stable_id
                };
                let capture_id = Uuid::from_u128(200 + index as u128);
                let locator = StableAnchorAreaLocator {
                    area_id: Uuid::from_u128(203 + index as u128),
                    path_hint: area.clone(),
                    filesystem_id: recorded_id.filesystem_id,
                    volume_root_hint: temporary.path().to_path_buf(),
                };
                let relative = if index == 0 {
                    PathBuf::from("file")
                } else {
                    raw_path(Path::new(""), b"file-\xfd")
                };
                let version = (
                    recorded_id.filesystem_id,
                    17_u64,
                    23_u64,
                    0_i64,
                    0_i64,
                    0_i64,
                    0_i64,
                );
                let plan = if index == 1 {
                    let wire = canonical_bytes(&(
                        1_u16,
                        capture_id,
                        source.as_os_str().as_bytes().to_vec(),
                        recorded_id,
                        relative.as_os_str().as_bytes().to_vec(),
                        version,
                        0o100644_u32,
                        &locator,
                    ))
                    .unwrap();
                    let guarded: mb_store::GuardedFileCapturePlan =
                        decode_canonical(&wire).unwrap();
                    assert_eq!(canonical_bytes(&guarded).unwrap(), wire);
                    SourceFileCapturePlan::GuardedLinkFreezeV1(guarded)
                } else {
                    let wire = canonical_bytes(&(
                        1_u16,
                        capture_id,
                        source.as_os_str().as_bytes().to_vec(),
                        &locator,
                        (
                            recorded_id.filesystem_id,
                            recorded_id.inode,
                            0_u64,
                            0_i64,
                            0_i64,
                            0_i64,
                            0_i64,
                        ),
                        0o40700_u32,
                        0_i64,
                        0_u32,
                    ))
                    .unwrap();
                    let root: ReflinkCapturePlan = decode_canonical(&wire).unwrap();
                    assert_eq!(canonical_bytes(&root).unwrap(), wire);
                    if index == 0 {
                        let wire = canonical_bytes(&(1_u16, &root, "file", version)).unwrap();
                        let native: mb_store::ReflinkFileCapturePlan =
                            decode_canonical(&wire).unwrap();
                        assert_eq!(canonical_bytes(&native).unwrap(), wire);
                        SourceFileCapturePlan::ReflinkV1(native)
                    } else {
                        let wire = canonical_bytes(&(
                            2_u16,
                            &root,
                            relative.as_os_str().as_bytes().to_vec(),
                            version,
                        ))
                        .unwrap();
                        let raw: mb_store::RawReflinkFileCapturePlanV2 =
                            decode_canonical(&wire).unwrap();
                        assert_eq!(canonical_bytes(&raw).unwrap(), wire);
                        SourceFileCapturePlan::ReflinkRawV2(raw)
                    }
                };
                let kind = if index == 0 {
                    format!("git-stage-intent-v1/{repository_id}")
                } else {
                    format!("git-worktree-stage-intent-v1/{repository_id}/{linked_id}")
                };
                // A separate scope retains both append-only Linux variants.
                let kind = if index == 2 {
                    format!(
                        "git-worktree-stage-intent-v1/{repository_id}/{}",
                        Uuid::from_u128(206)
                    )
                } else {
                    kind
                };
                external
                    .put_record(
                        &kind,
                        relative.as_os_str().as_bytes(),
                        &canonical_bytes(&(
                            1_u16,
                            repository_id,
                            relative.as_os_str().as_bytes().to_vec(),
                            0o100755_u32,
                            &plan,
                        ))
                        .unwrap(),
                    )
                    .unwrap();
                let renamed = temporary.path().join(format!("renamed-source-{index}"));
                std::fs::rename(&source, &renamed).unwrap();
                for path in [&renamed, &area] {
                    let alias = temporary.path().join(format!("alias-{}", excluded.len()));
                    std::os::unix::fs::symlink(path, &alias).unwrap();
                    excluded.push((path.clone(), alias));
                }
                expected.push((kind, relative, file_capture_plan(&plan).unwrap()));
            }
            let mut writers = Some((control, external));
            if journal == "closed" {
                drop(writers.take());
            }
            if journal == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let bytes = if entry.file_name().as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (entry.file_name(), bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&catalog_directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert!(report.local_state.git_worktrees.is_empty());
            assert!(report.local_state.git_indexes.is_empty());
            assert!(report.local_state.git_object_anchors.is_empty());
            assert_eq!(report.local_state.pending_git_stages.len(), 3);
            let registration = &report.local_state.git_repositories[0];
            assert!(
                registration.external_catalog_available
                    && registration.regular_stage_intents_inventoried
            );
            assert!(!registration.catalog_inventoried);
            for (_, relative, plan) in &expected {
                let entry = report
                    .local_state
                    .pending_git_stages
                    .iter()
                    .find(|entry| entry.plan.capture_id == plan.capture_id)
                    .unwrap();
                assert_eq!(entry.plan, *plan);
                assert_eq!(entry.repository_id, repository_id);
                assert_eq!(entry.record_format, 1);
                assert_eq!(entry.git_mode, 0o100755);
                assert_eq!(
                    entry.relative_path_hex,
                    hex::encode(relative.as_os_str().as_bytes())
                );
                assert!(!entry.payloads_verified);
                assert_eq!(entry.plan.logical_len, 23);
                if entry.plan.backend == mb_store::SourceBackendKind::GuardedLinkFreezeV1 {
                    assert_eq!(
                        entry.plan.stable_root_identity,
                        Some(entry.plan.recorded_root_identity)
                    );
                    assert_eq!(
                        entry.plan.stable_file_identity,
                        Some(entry.plan.recorded_file_identity)
                    );
                } else {
                    assert_eq!(entry.plan.stable_root_identity, None);
                    assert_eq!(entry.plan.stable_file_identity, None);
                }
            }
            let json = serde_json::to_vec(&report).unwrap();
            assert_eq!(
                serde_json::from_slice::<super::super::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            for (path, alias) in &excluded {
                for parent in [
                    path.clone(),
                    path.join("nested"),
                    alias.clone(),
                    alias.join("nested"),
                ] {
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err(),
                        "{journal}: {}",
                        parent.display()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err()
                    );
                }
                assert_eq!(
                    std::fs::read(path.join("original")).unwrap(),
                    b"preserved staging input"
                );
                assert_eq!(std::fs::read_dir(path).unwrap().count(), 2);
                assert_eq!(std::fs::read_dir(path.join("nested")).unwrap().count(), 0);
            }
            assert!(
                super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                    .is_ok()
            );
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            // The nested plan and every outer stage field count toward the report.
            crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
                let mut empty = collect(control, &mut 0, V1_MAX_CATALOG_BYTES)?;
                let mut used = 0;
                collect_external_git_records(
                    control,
                    &keys,
                    &mut empty,
                    &mut used,
                    V1_MAX_CATALOG_BYTES,
                )?;
                let mut exact = 0;
                for entry in &report.local_state.pending_git_stages {
                    account(entry, &mut exact, V1_MAX_CATALOG_BYTES)?;
                }
                assert_eq!(used, exact);
                let mut report = collect(control, &mut 0, V1_MAX_CATALOG_BYTES)?;
                assert!(
                    collect_external_git_records(control, &keys, &mut report, &mut 0, exact - 1)
                        .is_err()
                );
                Ok(())
            })
            .unwrap();
            assert_eq!(
                (snapshot(&data), snapshot(&catalog_directory)),
                before,
                "{journal}"
            );
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            if journal == "closed" {
                let external = ControlStore::open_with_key(
                    &external_path,
                    &mb_git::catalog_key(&keys, repository_id),
                )
                .unwrap();
                let corrupt_kind = format!(
                    "git-worktree-stage-intent-v1/{repository_id}/{}",
                    Uuid::from_u128(999)
                );
                external
                    .put_record(&corrupt_kind, b"zz-last", b"broken stage plan")
                    .unwrap();
                drop(external);
                let corrupted = (snapshot(&data), snapshot(&catalog_directory));
                assert!(
                    super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err()
                );
                assert!(
                    super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                        .is_err()
                );
                assert!(
                    super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                        .is_err()
                );
                assert_eq!((snapshot(&data), snapshot(&catalog_directory)), corrupted);
                assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            }
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_external_git_anchor_index_and_location_ownership_preserves_original_inputs() {
        use std::os::unix::fs::PermissionsExt;
        for mode in ["closed", "wal-only", "live"] {
            let area = tempfile::tempdir().unwrap();
            let data = area.path().join("state");
            let registered = area.path().join("repository");
            std::fs::create_dir(&data).unwrap();
            std::fs::create_dir(&registered).unwrap();
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([150; 32]));
            let repository_id = Uuid::from_u128(150);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: registered.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let directory = registered.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let mut blobs = Vec::new();
            let mut excluded = Vec::new();
            let linked_id = Uuid::from_u128(151);
            for index in 0..3 {
                let source = raw_path(area.path(), &[b's', b'0' + index as u8, 255]);
                let anchor_area = raw_path(area.path(), &[b'a', b'0' + index as u8, 254]);
                for path in [&source, &anchor_area] {
                    std::fs::create_dir(path).unwrap();
                    std::fs::create_dir(path.join("nested")).unwrap();
                    std::fs::write(path.join("original"), b"preserved original data").unwrap();
                    let alias = area.path().join(format!("alias-{}", excluded.len()));
                    std::os::unix::fs::symlink(path, &alias).unwrap();
                    excluded.push((path.clone(), alias));
                }
                let blob = super::owner_tests::blob(&source, &anchor_area, index);
                external
                    .put_record(
                        &format!(
                            "git-object-anchor-v1/{repository_id}/{}",
                            hex::encode(blob.oid)
                        ),
                        blob.anchor.anchor_id.as_bytes(),
                        &canonical_bytes(&blob.anchor).unwrap(),
                    )
                    .unwrap();
                let kind = if index == 0 {
                    format!("git-index-entry-v1/{repository_id}")
                } else {
                    format!("git-worktree-index-entry-v1/{repository_id}/{linked_id}")
                };
                external
                    .put_record(
                        &kind,
                        &[b'f', b'0' + index as u8, 253],
                        &canonical_bytes(&mb_git::GitIndexEntry {
                            format_version: 1,
                            oid: blob.oid,
                            mode: [0o100644, 0o100755, 0o120000][index],
                            anchor_id: blob.anchor.anchor_id,
                        })
                        .unwrap(),
                    )
                    .unwrap();
                blobs.push(blob);
            }
            let mut graph = super::owner_tests::graph(area.path(), repository_id, true);
            let pinned_oid = graph
                .refs
                .iter()
                .find(|reference| reference.name.starts_with(b"refs/mutualbackup/pins/"))
                .unwrap()
                .oid;
            graph.refs.push(mb_git::GitGraphRef {
                name: format!("refs/mutualbackup/pins/{}", hex::encode(pinned_oid)).into_bytes(),
                oid: pinned_oid,
            });
            graph.refs.push(mb_git::GitGraphRef {
                name: b"refs/remotes/origin/main".to_vec(),
                oid: graph.refs[0].oid,
            });
            graph.refs.push(mb_git::GitGraphRef {
                name: b"refs/custom/unresolved".to_vec(),
                oid: [233; 20],
            });
            graph.objects.push(mb_git::GitGraphObject {
                kind: 2,
                oid: git2::Oid::hash_object(git2::ObjectType::Tree, &[])
                    .unwrap()
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                bytes: Vec::new(),
            });
            for reference in &graph.refs {
                external
                    .put_record(
                        &format!("git-ref-v1/{repository_id}"),
                        &reference.name,
                        &canonical_bytes(&(1_u16, reference.oid)).unwrap(),
                    )
                    .unwrap();
            }
            for object in &graph.objects {
                external
                    .put_record(
                        &format!("git-metadata-object-v1/{repository_id}"),
                        &object.oid,
                        &canonical_bytes(&(1_u16, object.kind, &object.bytes)).unwrap(),
                    )
                    .unwrap();
            }
            for (kind, branch) in [
                (format!("git-head-v1/{repository_id}"), "main"),
                (
                    format!("git-worktree-head-v1/{repository_id}/{linked_id}"),
                    "topic",
                ),
            ] {
                external
                    .put_record(
                        &kind,
                        b"branch",
                        &canonical_bytes(&(1_u16, branch)).unwrap(),
                    )
                    .unwrap();
            }
            let cached = raw_path(area.path(), b"cached-\xfc");
            std::fs::create_dir(&cached).unwrap();
            std::fs::create_dir(cached.join("nested")).unwrap();
            std::fs::write(cached.join("original"), b"preserved original data").unwrap();
            let cached_alias = area.path().join("cached-alias");
            std::os::unix::fs::symlink(&cached, &cached_alias).unwrap();
            excluded.push((cached.clone(), cached_alias));
            external
                .put_record(
                    "anchor-area-location",
                    blobs[0].anchor.area.area_id.as_bytes(),
                    &canonical_bytes(&cached.as_os_str().as_bytes().to_vec()).unwrap(),
                )
                .unwrap();
            let relative = b"relative-\xfb";
            external
                .put_record(
                    "anchor-area-location",
                    Uuid::from_u128(152).as_bytes(),
                    &canonical_bytes(&relative.to_vec()).unwrap(),
                )
                .unwrap();
            let mut writers = Some((control, external));
            if mode == "closed" {
                drop(writers.take());
            }
            if mode == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &std::path::Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let bytes = if entry.file_name().as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (entry.file_name(), bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert_eq!(report.local_state.git_object_anchors.len(), 3);
            assert_eq!(report.local_state.git_indexes.len(), 3);
            assert_eq!(report.local_state.git_anchor_area_locations.len(), 2);
            assert_eq!(report.local_state.git_references.len(), graph.refs.len());
            assert_eq!(
                report.local_state.git_metadata_objects.len(),
                graph.objects.len()
            );
            assert_eq!(report.local_state.git_selected_branches.len(), 2);
            for reference in &graph.refs {
                let saved = report
                    .local_state
                    .git_references
                    .iter()
                    .find(|saved| saved.reference.name_hex == hex::encode(&reference.name))
                    .unwrap();
                assert_eq!(saved.repository_id, repository_id);
                assert_eq!(saved.reference.oid, hex::encode(reference.oid));
                assert!(!saved.target_graph_reconciled);
            }
            assert!(report.local_state.git_references.iter().any(|saved| saved.pin_namespace && saved.pin_name_matches_target == Some(true)));
            assert!(
                report.local_state.git_references.iter().any(
                    |saved| saved.pin_namespace && saved.pin_name_matches_target == Some(false)
                )
            );
            for object in &graph.objects {
                let saved = report
                    .local_state
                    .git_metadata_objects
                    .iter()
                    .find(|saved| saved.object.oid == hex::encode(object.oid))
                    .unwrap();
                assert_eq!(saved.object.payload_bytes, object.bytes.len() as u64);
                assert_eq!(
                    saved.object.payload_hash,
                    hex::encode(blake3::hash(&object.bytes).as_bytes())
                );
                assert!(saved.content_address_verified);
                assert!(!saved.graph_metadata_validated);
            }
            assert!(
                report
                    .local_state
                    .git_selected_branches
                    .iter()
                    .any(|saved| saved.worktree_id == linked_id && saved.branch == "topic")
            );
            assert!(report.local_state.git_worktrees.is_empty());
            let registration = &report.local_state.git_repositories[0];
            assert!(
                registration.external_catalog_available
                    && registration.linked_worktrees_inventoried
                    && registration.object_anchors_inventoried
                    && registration.worktree_indexes_inventoried
                    && registration.anchor_area_locations_inventoried
                    && registration.references_inventoried
                    && registration.metadata_objects_inventoried
                    && registration.selected_branches_inventoried
            );
            assert!(!registration.catalog_inventoried);
            for blob in &blobs {
                let anchor = report
                    .local_state
                    .git_object_anchors
                    .iter()
                    .find(|entry| entry.pin.anchor_id == blob.anchor.anchor_id)
                    .unwrap();
                assert_eq!(anchor.repository_id, repository_id);
                assert_eq!(
                    anchor.pin,
                    git_intents::file_anchor(blob.oid, &blob.anchor).unwrap()
                );
                assert!(!anchor.payloads_verified);
                let index = report
                    .local_state
                    .git_indexes
                    .iter()
                    .find(|entry| entry.anchor_id == blob.anchor.anchor_id)
                    .unwrap();
                assert_eq!(index.oid, hex::encode(blob.oid));
                assert_eq!(index.repository_id, repository_id);
                assert_eq!(
                    index.worktree_id,
                    if index.mode == 0o100644 {
                        repository_id
                    } else {
                        linked_id
                    }
                );
                assert!(!index.payloads_verified);
            }
            assert!(
                report
                    .local_state
                    .git_anchor_area_locations
                    .iter()
                    .any(|entry| !entry.absolute && entry.path_hex == hex::encode(relative))
            );
            assert_eq!(
                serde_json::from_slice::<crate::LegacyRevisionInventory>(
                    &serde_json::to_vec(&report).unwrap()
                )
                .unwrap(),
                report
            );
            for (path, alias) in &excluded {
                for parent in [
                    path.clone(),
                    path.join("nested"),
                    alias.clone(),
                    alias.join("nested"),
                ] {
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err()
                    );
                }
                assert_eq!(
                    std::fs::read(path.join("original")).unwrap(),
                    b"preserved original data"
                );
                assert_eq!(std::fs::read_dir(path).unwrap().count(), 2);
                assert_eq!(std::fs::read_dir(path.join("nested")).unwrap().count(), 0);
            }
            let safe = area.path().join("safe");
            std::fs::create_dir(&safe).unwrap();
            assert!(
                super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                    .is_ok()
            );
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            assert_eq!((snapshot(&data), snapshot(&directory)), before, "{mode}");
            if mode == "closed" {
                for (kind, key, bytes) in [
                    (
                        format!("git-ref-v1/{repository_id}"),
                        b"refs/heads/corrupt".to_vec(),
                        b"bad ref".to_vec(),
                    ),
                    (
                        format!("git-metadata-object-v1/{repository_id}"),
                        vec![234; 20],
                        b"bad object".to_vec(),
                    ),
                    (
                        format!(
                            "git-worktree-head-v1/{repository_id}/{}",
                            Uuid::from_u128(999)
                        ),
                        b"wrong".to_vec(),
                        canonical_bytes(&(1_u16, "main")).unwrap(),
                    ),
                ] {
                    let external = ControlStore::open_with_key(
                        &external_path,
                        &mb_git::catalog_key(&keys, repository_id),
                    )
                    .unwrap();
                    external.put_record(&kind, &key, &bytes).unwrap();
                    drop(external);
                    let corrupted = (snapshot(&data), snapshot(&directory));
                    assert!(
                        super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                            .is_err()
                    );
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &safe,
                            &[],
                            false
                        )
                        .is_err()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                            .is_err()
                    );
                    assert_eq!((snapshot(&data), snapshot(&directory)), corrupted);
                    let external = ControlStore::open_with_key(
                        &external_path,
                        &mb_git::catalog_key(&keys, repository_id),
                    )
                    .unwrap();
                    external.delete_record(&kind, &key).unwrap();
                    drop(external);
                }
            }
            if mode == "closed" {
                let external = ControlStore::open_with_key(
                    &external_path,
                    &mb_git::catalog_key(&keys, repository_id),
                )
                .unwrap();
                external
                    .put_record(
                        "anchor-area-location",
                        Uuid::from_u128(999).as_bytes(),
                        b"damaged late location",
                    )
                    .unwrap();
                drop(external);
                let before = (snapshot(&data), snapshot(&directory));
                assert!(
                    super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err()
                );
                assert!(
                    super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                        .is_err()
                );
                assert!(
                    super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                        .is_err()
                );
                assert_eq!((snapshot(&data), snapshot(&directory)), before);
            }
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_external_git_worktrees_inventory_and_placement_preserve_original_inputs() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        for mode in ["closed", "wal-only", "live"] {
            let area = tempfile::tempdir().unwrap();
            let data = area.path().join("state");
            let source = area.path().join("source");
            std::fs::create_dir(&data).unwrap();
            std::fs::create_dir(&source).unwrap();
            let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([130; 32]));
            let repository_id = Uuid::from_u128(130);
            let control_path = data.join("control.db");
            let control = ControlStore::open(&control_path, &keys).unwrap();
            control
                .put_record(
                    "git-repository",
                    repository_id.as_bytes(),
                    &canonical_bytes(&GitRepositoryInfo {
                        format_version: 1,
                        repository_id,
                        path: source.clone(),
                    })
                    .unwrap(),
                )
                .unwrap();
            let directory = source.join(mb_store::GIT_CATALOG_DIRECTORY);
            std::fs::create_dir(&directory).unwrap();
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            let marker = directory.join(mb_store::GIT_CATALOG_MARKER_FILE);
            std::fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
            std::fs::set_permissions(&marker, std::fs::Permissions::from_mode(0o600)).unwrap();
            let external_path = directory.join("catalog.db");
            let external = ControlStore::open_with_key(
                &external_path,
                &mb_git::catalog_key(&keys, repository_id),
            )
            .unwrap();
            let mut locations = Vec::new();
            for (index, state) in [
                mb_git::GitWorktreeState::Preparing,
                mb_git::GitWorktreeState::Ready,
                mb_git::GitWorktreeState::Removing,
            ]
            .into_iter()
            .enumerate()
            {
                let old = area.path().join(std::ffi::OsString::from_vec(vec![
                    b'w',
                    b'0' + index as u8,
                    255,
                ]));
                std::fs::create_dir(&old).unwrap();
                std::fs::create_dir(old.join("nested")).unwrap();
                std::fs::write(old.join("original"), b"retained working data").unwrap();
                let identity = std::fs::metadata(&old).unwrap();
                let info = mb_git::GitWorktreeInfo {
                    format_version: 1,
                    repository_id,
                    worktree_id: Uuid::from_u128(131 + index as u128),
                    path: old.clone(),
                    root_id: NativeFileId {
                        filesystem_id: identity.dev(),
                        inode: identity.ino(),
                    },
                    target_branch: "main".to_owned(),
                    state,
                };
                external
                    .put_record(
                        &format!("git-linked-worktree-v1/{repository_id}"),
                        info.worktree_id.as_bytes(),
                        &canonical_bytes(&info).unwrap(),
                    )
                    .unwrap();
                let moved = area.path().join(format!("moved-{index}"));
                std::fs::rename(&old, &moved).unwrap();
                let alias = area.path().join(format!("alias-{index}"));
                std::os::unix::fs::symlink(&moved, &alias).unwrap();
                locations.push((info, moved, alias));
            }
            external
                .put_record(
                    "git-guarded-stage-receipt-v1/preserved",
                    b"old",
                    b"retained opaque evidence",
                )
                .unwrap();
            let mut writers = Some((control, external));
            if mode == "closed" {
                drop(writers.take());
            }
            if mode == "wal-only" {
                for path in [&control_path, &external_path] {
                    std::fs::remove_file(path.with_extension("db-shm")).unwrap();
                }
            }
            let snapshot = |path: &std::path::Path| {
                let mut files = std::fs::read_dir(path)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        let name = entry.file_name();
                        let bytes = if name.as_bytes().ends_with(b"-shm") {
                            std::fs::metadata(entry.path())
                                .unwrap()
                                .len()
                                .to_le_bytes()
                                .to_vec()
                        } else {
                            std::fs::read(entry.path()).unwrap()
                        };
                        (name, bytes)
                    })
                    .collect::<Vec<_>>();
                files.sort();
                files
            };
            let before = (snapshot(&data), snapshot(&directory));
            let report =
                super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            assert_eq!(report.local_state.git_worktrees.len(), 3);
            let json = serde_json::to_vec(&report).unwrap();
            assert_eq!(
                serde_json::from_slice::<crate::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            let registration = &report.local_state.git_repositories[0];
            assert!(
                registration.external_catalog_available
                    && registration.linked_worktrees_inventoried
            );
            assert!(!registration.catalog_inventoried);
            for (info, moved, alias) in &locations {
                let entry = report
                    .local_state
                    .git_worktrees
                    .iter()
                    .find(|entry| entry.worktree_id == info.worktree_id)
                    .unwrap();
                assert_eq!(
                    entry.path_hex,
                    hex::encode(info.path.as_os_str().as_bytes())
                );
                assert_eq!(entry.state, info.state);
                assert_eq!(entry.recorded_root_identity, info.root_id);
                assert!(!entry.payloads_verified);
                for parent in [
                    moved.clone(),
                    moved.join("nested"),
                    alias.clone(),
                    alias.join("nested"),
                ] {
                    assert!(
                        super::super::remote::peer_client_preflight(
                            &keys,
                            &data,
                            &parent,
                            &[],
                            false
                        )
                        .is_err()
                    );
                    assert!(
                        super::super::remote::export_parent_preflight(&keys, &data, &parent, &[])
                            .is_err()
                    );
                }
                assert_eq!(
                    std::fs::read(moved.join("original")).unwrap(),
                    b"retained working data"
                );
            }
            let safe = area.path().join("safe");
            std::fs::create_dir(&safe).unwrap();
            assert!(
                super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                    .is_ok()
            );
            assert!(
                super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            assert_eq!((snapshot(&data), snapshot(&directory)), before, "{mode}");
            assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            if mode == "closed" {
                let external = ControlStore::open_with_key(
                    &external_path,
                    &mb_git::catalog_key(&keys, repository_id),
                )
                .unwrap();
                external
                    .put_record(
                        &format!("git-linked-worktree-v1/{repository_id}"),
                        Uuid::from_u128(999).as_bytes(),
                        b"damaged late worktree",
                    )
                    .unwrap();
                drop(external);
                let corrupted_before = (snapshot(&data), snapshot(&directory));
                assert!(
                    super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err()
                );
                assert!(
                    super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                        .is_err()
                );
                assert!(
                    super::super::remote::export_parent_preflight(&keys, &data, &safe, &[])
                        .is_err()
                );
                assert_eq!((snapshot(&data), snapshot(&directory)), corrupted_before);
                assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
            }
            drop(writers);
        }
    }

    #[test]
    fn legacy_export_local_sector_inventory_accounts_budget_and_rejects_late_corruption() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("state");
        let safe = area.path().join("safe");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&safe).unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([112; 32]));
        let mut control = ControlStore::open(data.join("control.db"), &keys).unwrap();
        crate::snapshot::install_inline_recipe(
            &mut control,
            [113; 32],
            mb_core::SectorRef {
                id: [114; 32],
                root: [115; 32],
                logical_len: 4,
            },
            b"hide".to_vec(),
        )
        .unwrap();
        drop(control);
        let before = preserved_files(&data);
        let report =
            super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
        assert_eq!(report.format_version, 15);
        assert!(!report.retained_history_complete);
        assert_eq!(report.local_state.local_sectors.len(), 1);
        let entry = &report.local_state.local_sectors[0];
        assert!(!entry.payloads_verified);
        let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
        assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
        assert!(super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err());
        let first = canonical_size_bounded(entry, V1_MAX_CATALOG_BYTES).unwrap();
        crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
            let mut used = 0;
            assert!(collect(control, &mut used, first - 1).is_err());
            assert_eq!(used, 0);
            Ok(())
        })
        .unwrap();
        assert_preserved_files(&data, &before);
        let control = ControlStore::open(data.join("control.db"), &keys).unwrap();
        control
            .put_record("local-sector", &[255; 32], b"damaged late recipe")
            .unwrap();
        drop(control);
        let corrupted_before = preserved_files(&data);
        assert!(super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err());
        assert!(
            super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false).is_err()
        );
        assert!(super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_err());
        assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
        assert_preserved_files(&data, &corrupted_before);
    }

    #[test]
    fn legacy_export_local_sector_placement_excludes_recipe_only_areas_and_aliases() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("state");
        std::fs::create_dir(&data).unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([111; 32]));
        let control = ControlStore::open(data.join("control.db"), &keys).unwrap();
        let fixtures = crate::snapshot::preserved::local_sector_test_records(area.path());
        for (key, bytes) in &fixtures {
            control.put_record("local-sector", key, bytes).unwrap();
        }
        drop(control);
        let safe = area.path().join("safe");
        std::fs::create_dir(&safe).unwrap();
        for (key, bytes) in fixtures {
            let preserved = crate::snapshot::preserved::decode_local_sector(&key, &bytes).unwrap();
            preserved
                .for_each_path(|path| {
                    std::fs::create_dir_all(path.join("nested"))?;
                    std::fs::write(path.join("original"), b"retained payload")?;
                    let alias = area.path().join(format!("alias-{}", key[0]));
                    std::os::unix::fs::symlink(path, &alias)?;
                    for parent in [
                        path.to_path_buf(),
                        path.join("nested"),
                        alias.clone(),
                        alias.join("nested"),
                    ] {
                        assert!(
                            crate::legacy_export::remote::peer_client_preflight(
                                &keys,
                                &data,
                                &parent,
                                &[],
                                false
                            )
                            .is_err()
                        );
                        assert!(
                            crate::legacy_export::remote::export_parent_preflight(
                                &keys,
                                &data,
                                &parent,
                                &[]
                            )
                            .is_err()
                        );
                    }
                    assert_eq!(std::fs::read(path.join("original"))?, b"retained payload");
                    assert_eq!(std::fs::read_dir(path.join("nested"))?.count(), 0);
                    Ok(())
                })
                .unwrap();
        }
        assert!(
            crate::legacy_export::remote::peer_client_preflight(&keys, &data, &safe, &[], false)
                .is_ok()
        );
        assert!(
            crate::legacy_export::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_ok()
        );
        assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
    }

    #[test]
    fn legacy_volume_ownership_accounts_report_and_rejects_late_corruption_before_placement() {
        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("state");
        let safe = area.path().join("safe");
        std::fs::create_dir(&data).unwrap();
        std::fs::create_dir(&safe).unwrap();
        let keys = mb_core::KeyMaterial::from_seed(&mb_core::Seed::from_bytes([96; 32]));
        let control = ControlStore::open(data.join("control.db"), &keys).unwrap();
        let receipt = crate::volume::VolumeReceipt {
            format_version: 1,
            volume_id: Uuid::from_u128(99),
            guild_id: [97; 32],
            group_id: [98; 32],
            shard_index: 4,
            root: [99; 32],
        };
        let mut key = receipt.group_id.to_vec();
        key.push(receipt.shard_index);
        control
            .put_record("volume-receipt", &key, &canonical_bytes(&receipt).unwrap())
            .unwrap();
        drop(control);
        let before = preserved_files(&data);
        let report =
            super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
        assert_eq!(report.format_version, 15);
        assert!(!report.retained_history_complete);
        assert_eq!(report.local_state.volume_ownership.len(), 1);
        let entry = &report.local_state.volume_ownership[0];
        assert_eq!(entry.unregistered_volume_ids, vec![receipt.volume_id]);
        assert!(!entry.payloads_verified);
        let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
        assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
        assert!(super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err());
        let first = canonical_size_bounded(entry, V1_MAX_CATALOG_BYTES).unwrap();
        crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
            let mut used = 0;
            assert!(collect(control, &mut used, first - 1).is_err());
            assert_eq!(used, 0);
            Ok(())
        })
        .unwrap();
        assert_preserved_files(&data, &before);
        let control = ControlStore::open(data.join("control.db"), &keys).unwrap();
        control
            .put_record("volume-write-intent", &key, &[0; 513])
            .unwrap();
        drop(control);
        let corrupted_before = preserved_files(&data);
        assert!(super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).is_err());
        assert!(
            super::super::remote::peer_client_preflight(&keys, &data, &safe, &[], false).is_err()
        );
        assert!(super::super::remote::export_parent_preflight(&keys, &data, &safe, &[]).is_err());
        assert_eq!(std::fs::read_dir(&safe).unwrap().count(), 0);
        assert_preserved_files(&data, &corrupted_before);
    }

    #[test]
    fn legacy_volume_inventory_accounts_registry_entries_without_opening_volumes() {
        use std::os::unix::ffi::OsStringExt;

        let area = tempfile::tempdir().unwrap();
        let data = area.path().join("state");
        let volume = area
            .path()
            .join(std::ffi::OsString::from_vec(b"volume-\xff".to_vec()));
        std::fs::create_dir(&volume).unwrap();
        let seed = mb_core::Seed::from_bytes([86; 32]);
        let keys = mb_core::KeyMaterial::from_seed(&seed);
        let mut node = crate::Node::open(&data, seed).unwrap();
        node.configure_storage_volumes(std::slice::from_ref(&volume), 65536, 0)
            .unwrap();
        drop(node);
        let before_data = preserved_files(&data);
        let before_volume = preserved_files(&volume);
        let report =
            super::super::inventory_withdrawn_revisions_from_catalog(&keys, &data).unwrap();
        assert_eq!(report.format_version, 15);
        assert!(!report.retained_history_complete);
        assert!(report.revisions.is_empty());
        let volumes = &report.local_state.storage_volumes;
        assert_eq!(
            volumes.len(),
            2,
            "retain the unconfigured data-directory volume"
        );
        let selected = volumes
            .iter()
            .find(|record| record.path_hex == hex::encode(volume.as_os_str().as_bytes()))
            .unwrap();
        assert!(selected.configured && selected.configured_recorded);
        assert_eq!(selected.state, crate::StorageVolumeState::Online);
        assert_eq!(selected.budget_bytes, 65536);
        assert_eq!(selected.headroom_bytes, 0);
        assert!(volumes.iter().any(|volume| !volume.configured));
        assert!(volumes.iter().all(|volume| !volume.payloads_verified));
        let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
        assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
        assert!(super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err());
        let first = canonical_size_bounded(&volumes[0], V1_MAX_CATALOG_BYTES).unwrap();
        crate::volume::with_inspected_control_snapshot(&data, &keys, |control| {
            let mut used = 0;
            assert!(collect(control, &mut used, first - 1).is_err());
            assert_eq!(used, 0, "reject before adding the first registry entry");
            Ok(())
        })
        .unwrap();
        assert_preserved_files(&data, &before_data);
        assert_preserved_files(&volume, &before_volume);
    }
    use mb_core::{KeyMaterial, SignedRecord, UserRevision, canonical_bytes};
    use mb_store::{
        FileExtent, GuardedStoppedFileV1, GuardedViewEntryKind, GuardedViewMetadataEntry,
        GuardedViewMetadataV1, NativeFileId, StableAnchorAreaLocator, StableAnchorFileLocator,
    };
    use std::{
        collections::BTreeSet,
        ffi::OsString,
        fs,
        os::unix::ffi::OsStringExt,
        path::{Path, PathBuf},
    };

    pub(super) fn raw_path(parent: &Path, name: &[u8]) -> PathBuf {
        parent.join(OsString::from_vec(name.to_vec()))
    }

    fn stopped_capture(parent: &Path) -> GuardedStoppedCaptureV1 {
        let native_id = NativeFileId {
            filesystem_id: 7,
            inode: 11,
        };
        let path = b"name-\xff".to_vec();
        GuardedStoppedCaptureV1 {
            format_version: 1,
            metadata: GuardedViewMetadataV1 {
                format_version: 1,
                anchor_id: Uuid::from_bytes([40; 16]),
                lower_root_id: NativeFileId {
                    filesystem_id: 7,
                    inode: 10,
                },
                root_mode: 0o700,
                root_uid: 123,
                root_gid: 456,
                root_atime_secs: -1,
                root_atime_nanos: 2,
                root_modified_secs: 3,
                root_modified_nanos: 4,
                entries: vec![GuardedViewMetadataEntry {
                    path: path.clone(),
                    kind: GuardedViewEntryKind::File,
                    native_id,
                    mode: 0o640,
                    uid: 123,
                    gid: 456,
                    logical_len: 3,
                    atime_secs: -1,
                    atime_nanos: 2,
                    modified_secs: 3,
                    modified_nanos: 4,
                }],
            },
            files: vec![GuardedStoppedFileV1 {
                path,
                native_id,
                locator: StableAnchorFileLocator {
                    area: StableAnchorAreaLocator {
                        area_id: Uuid::from_bytes([41; 16]),
                        path_hint: raw_path(parent, b"missing-area-\xfe"),
                        filesystem_id: 7,
                        volume_root_hint: parent.join("missing-volume"),
                    },
                    anchor_id: Uuid::from_bytes([42; 16]),
                    relative_path: raw_path(Path::new("capture"), b"name-\xff"),
                },
                logical_len: 3,
                content_hash: *blake3::hash(b"old").as_bytes(),
                data_extents: vec![FileExtent {
                    offset: 0,
                    logical_len: 3,
                }],
            }],
        }
    }

    fn save<T: Serialize>(store: &ControlStore, kind: &str, id: Uuid, record: &T) {
        store
            .put_record(kind, id.as_bytes(), &canonical_bytes(record).unwrap())
            .unwrap();
    }

    fn save_revision(store: &ControlStore, revision: &SignedRecord<UserRevision>) {
        save(store, "user-revision", revision.value.revision_id, revision);
    }

    pub(super) fn preserved_files(data: &Path) -> BTreeMap<OsString, Vec<u8>> {
        fs::read_dir(data)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect()
    }

    pub(super) fn assert_preserved_files(data: &Path, before: &BTreeMap<OsString, Vec<u8>>) {
        let after = preserved_files(data);
        assert_eq!(
            after.keys().collect::<Vec<_>>(),
            before.keys().collect::<Vec<_>>()
        );
        for (name, bytes) in before {
            assert!(after[name] == *bytes, "preserved file changed: {name:?}");
        }
    }

    #[test]
    fn legacy_peer_preflight_streams_retained_captures_beyond_report_budget() {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([50; 32]));
        let mut capture = stopped_capture(temp.path());
        let template_entry = capture.metadata.entries[0].clone();
        let template_file = capture.files[0].clone();
        capture.metadata.entries.clear();
        capture.files.clear();
        for index in 0..128 {
            let mut name = format!("file-{index:04}-").into_bytes();
            name.resize(239, b'x');
            name.push(0xff);
            let native_id = NativeFileId {
                filesystem_id: 7,
                inode: 1000 + index,
            };
            let mut entry = template_entry.clone();
            entry.path = name.clone();
            entry.native_id = native_id;
            let mut file = template_file.clone();
            file.path = name.clone();
            file.native_id = native_id;
            file.locator.relative_path = raw_path(Path::new("capture"), &name);
            capture.metadata.entries.push(entry);
            capture.files.push(file);
        }
        validate_capture(&capture).unwrap();
        let kind = "guarded-view-stopped-capture-v1";
        let payload = canonical_bytes(&capture).unwrap();
        let mut store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        save(&store, kind, Uuid::from_u128(1), &capture);
        let report = collect(&store, &mut 0, V1_MAX_CATALOG_BYTES).unwrap();
        let row_cost =
            canonical_size_bounded(&report.guarded_captures[0], V1_MAX_CATALOG_BYTES).unwrap();
        let count = V1_MAX_CATALOG_BYTES / row_cost + 2;
        assert!(count < 1000);
        store
            .put_records_iter((2..=count).map(|index| {
                Ok::<_, anyhow::Error>((
                    kind,
                    *Uuid::from_u128(index as u128).as_bytes(),
                    payload.as_slice(),
                ))
            }))
            .unwrap();
        drop(store);
        assert!(count * row_cost > V1_MAX_CATALOG_BYTES);
        eprintln!(
            "retained captures={count} pins={} encoded_record_bytes={} report_body_bytes={} catalog_bytes={}",
            count * 128,
            payload.len(),
            count * row_cost,
            data.join("control.db").metadata().unwrap().len(),
        );
        let hashes = || -> BTreeMap<_, _> {
            fs::read_dir(&data)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    let file = fs::File::open(entry.path()).unwrap();
                    let len = file.metadata().unwrap().len();
                    let mut hash = blake3::Hasher::new();
                    hash.update_reader(file).unwrap();
                    (entry.file_name(), (len, *hash.finalize().as_bytes()))
                })
                .collect()
        };
        let before = hashes();
        let preflight =
            || super::super::remote::peer_client_preflight(&keys, &data, temp.path(), &[], false);
        let export_parent =
            || super::super::remote::export_parent_preflight(&keys, &data, temp.path(), &[]);
        assert_eq!(preflight().unwrap().0, temp.path().canonicalize().unwrap());
        export_parent().unwrap();
        let error =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap_err();
        assert!(
            error.to_string().contains("bounded metadata budget"),
            "{error:#}"
        );
        assert_eq!(hashes(), before);

        // A late owner still excludes the candidate after a graph larger than
        // the entire report budget; there is no successful truncated scan.
        capture.files[0].locator.area.path_hint = temp.path().to_path_buf();
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        save(&store, kind, Uuid::from_u128(u128::MAX), &capture);
        drop(store);
        let before = hashes();
        let error = preflight().unwrap_err();
        assert!(
            error.to_string().contains("outside preserved inputs"),
            "{error:#}"
        );
        let error = export_parent().err().unwrap();
        assert!(
            error
                .to_string()
                .contains("export destination must be outside preserved inputs")
        );
        assert_eq!(hashes(), before);

        // Placement consumes the shared validation, even for a late field
        // which does not itself contain a directory exclusion.
        capture.files[0].locator.area.path_hint = temp.path().join("missing-area");
        capture.files[0].locator.relative_path = "../escape".into();
        let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
        save(&store, kind, Uuid::from_u128(u128::MAX), &capture);
        drop(store);
        let before = hashes();
        let error = preflight().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unsafe preserved anchor relative path"),
            "{error:#}"
        );
        let error = export_parent().err().unwrap();
        assert!(
            error
                .to_string()
                .contains("unsafe preserved anchor relative path")
        );
        assert_eq!(hashes(), before);
    }

    #[test]
    fn offline_inventory_reconciles_registrations_and_anchor_owners_without_payload_reads() {
        for (format, wrapped) in [(6, false), (7, true)] {
            let ((keys, revision, _), _, _, _) =
                super::super::tests::fixed_checkpoint_fixture(format);
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = if wrapped {
                crate::volume::open_control_store(&data, &keys).unwrap().0
            } else {
                ControlStore::open(data.join("control.db"), &keys).unwrap()
            };
            save_revision(&store, &revision);
            let root_id = revision.value.protected_root_id;
            let root_path = raw_path(temp.path(), b"offline-view-\xff");
            let root = ProtectedRoot {
                format_version: 4,
                root_id,
                path: root_path.clone(),
                filesystem_id: 7,
                root_inode: 10,
            };
            save(&store, "protected-root", root_id, &root);
            save(
                &store,
                "source-backend",
                root_id,
                &SourceBackendBinding::guarded_link_freeze_v1(root_id, 7, 10, 11),
            );
            let orphan_id = Uuid::from_bytes([66; 16]);
            save(
                &store,
                "source-backend",
                orphan_id,
                &SourceBackendBinding::guarded_link_freeze_v1(orphan_id, 7, 10, 11),
            );
            let mismatch_id = Uuid::from_bytes([67; 16]);
            save(
                &store,
                "protected-root",
                mismatch_id,
                &ProtectedRoot {
                    format_version: 3,
                    root_id: mismatch_id,
                    path: temp.path().join("missing-native"),
                    filesystem_id: 8,
                    root_inode: 12,
                },
            );
            save(
                &store,
                "source-backend",
                mismatch_id,
                &SourceBackendBinding::reflink_v1(mismatch_id, 8, 13, 14),
            );
            let old_id = Uuid::from_bytes([68; 16]);
            save(
                &store,
                "protected-root",
                old_id,
                &ProtectedRoot {
                    format_version: 2,
                    root_id: old_id,
                    path: temp.path().join("missing-older"),
                    filesystem_id: 7,
                    root_inode: 10,
                },
            );
            save(
                &store,
                "source-backend",
                old_id,
                &SourceBackendBinding::guarded_link_freeze_v1(old_id, 7, 10, 11),
            );
            save(
                &store,
                "git-repository",
                root_id,
                &GitRepositoryInfo {
                    format_version: 1,
                    repository_id: root_id,
                    path: root_path.clone(),
                },
            );
            let history_id = Uuid::from_bytes([99; 16]);
            let history_path = raw_path(temp.path(), b"history-only-\xfd");
            save(
                &store,
                "git-repository",
                history_id,
                &GitRepositoryInfo {
                    format_version: 1,
                    repository_id: history_id,
                    path: history_path.clone(),
                },
            );
            let capture = stopped_capture(temp.path());
            save(
                &store,
                mb_store::GUARDED_REVISION_CAPTURE_KIND,
                revision.value.revision_id,
                &GuardedRevisionCaptureV1 {
                    format_version: 1,
                    revision_id: revision.value.revision_id,
                    capture: capture.clone(),
                },
            );
            save(
                &store,
                "guarded-view-stopped-capture-v1",
                Uuid::from_bytes([43; 16]),
                &capture,
            );
            store
                .put_record("guarded-view-mount-v1", b"mount", b"not decoded")
                .unwrap();
            store
                .put_record("link-freeze-pending", b"intent", b"preserved intent")
                .unwrap();
            drop(store);
            let before = preserved_files(&data);
            crate::volume::with_inspected_control_snapshot(&data, &keys, |store| {
                let mut paths = BTreeSet::new();
                let mut roots = BTreeSet::new();
                for_each_record(store, |record| {
                    record.for_each_input(|input| {
                        match input {
                            PreservedInput::PathHint(path) => {
                                paths.insert(path.to_path_buf());
                            }
                            PreservedInput::NativeRoot(root) => {
                                roots.insert(root);
                            }
                            PreservedInput::RecordedNativeRoot(_) => {}
                        }
                        Ok(())
                    })
                })?;
                ensure!(paths.contains(&root_path) && paths.contains(&history_path));
                ensure!(roots.contains(&capture.metadata.lower_root_id));
                ensure!(paths.contains(&capture.files[0].locator.area.path_hint));
                ensure!(!paths.contains(&capture.files[0].locator.area.volume_root_hint));
                Ok(())
            })
            .unwrap();
            let report =
                super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                    .unwrap();
            assert_eq!(report.format_version, 15);
            assert!(!report.retained_history_complete);
            let local = &report.local_state;
            assert_eq!(local.protected_roots.len(), 3);
            let saved_root = local
                .protected_roots
                .iter()
                .find(|root| root.root_id == root_id)
                .unwrap();
            assert_eq!(
                saved_root.path_hex,
                hex::encode(root_path.as_os_str().as_bytes())
            );
            assert_eq!(saved_root.signed_revision_ids, [revision.value.revision_id]);
            let binding = |id| {
                local
                    .source_backends
                    .iter()
                    .find(|entry| entry.binding.root_id == id)
                    .unwrap()
            };
            assert_eq!(binding(root_id).registration_identity_matches, Some(true));
            assert!(binding(root_id).registered_root);
            assert_eq!(
                binding(mismatch_id).registration_identity_matches,
                Some(false)
            );
            assert!(binding(mismatch_id).registered_root);
            assert_eq!(binding(old_id).registration_identity_matches, None);
            assert!(binding(old_id).registered_root);
            assert_eq!(binding(orphan_id).registration_identity_matches, None);
            assert!(!binding(orphan_id).registered_root);
            assert_eq!(local.git_repositories.len(), 2);
            let git = local
                .git_repositories
                .iter()
                .find(|git| git.repository_id == root_id)
                .unwrap();
            assert!(git.registered_root);
            assert_eq!(git.signed_revision_ids, [revision.value.revision_id]);
            assert!(!git.catalog_inventoried);
            let history = local
                .git_repositories
                .iter()
                .find(|git| git.repository_id == history_id)
                .unwrap();
            assert!(!history.registered_root && !history.catalog_inventoried);
            assert_eq!(
                history.path_hex,
                hex::encode(history_path.as_os_str().as_bytes())
            );
            assert!(history.signed_revision_ids.is_empty());
            assert_eq!(local.guarded_captures.len(), 2);
            for owner in &local.guarded_captures {
                assert_eq!(owner.namespace_anchor_id, capture.metadata.anchor_id);
                assert!(!owner.payloads_verified);
                assert_eq!(owner.anchors.len(), 1);
                let pin = &owner.anchors[0];
                assert_eq!(pin.namespace_path_hex, hex::encode(b"name-\xff"));
                assert_eq!(pin.area_id, capture.files[0].locator.area.area_id);
                assert_eq!(pin.anchor_id, capture.files[0].locator.anchor_id);
                assert_eq!(pin.relative_path_hex, hex::encode(b"capture/name-\xff"));
                assert_eq!(
                    pin.area_path_hint_hex,
                    hex::encode(
                        capture.files[0]
                            .locator
                            .area
                            .path_hint
                            .as_os_str()
                            .as_bytes()
                    )
                );
                assert_eq!(pin.logical_len, 3);
                assert_eq!(
                    pin.content_hash,
                    hex::encode(blake3::hash(b"old").as_bytes())
                );
                if owner.revision_id == revision.value.revision_id {
                    assert!(owner.signed_revision_metadata_available);
                    assert_eq!(owner.protected_root_id, Some(root_id));
                } else {
                    assert!(!owner.signed_revision_metadata_available);
                    assert_eq!(owner.protected_root_id, None);
                }
            }
            assert_eq!(local.unclassified_guarded_records.len(), 2);
            let pending = &local.unclassified_guarded_records[1];
            assert_eq!(pending.kind, "link-freeze-pending");
            assert_eq!(pending.record_id_hex, hex::encode(b"intent"));
            assert_eq!(pending.payload_bytes, 16);
            assert_eq!(
                pending.payload_hash,
                hex::encode(blake3::hash(b"preserved intent").as_bytes())
            );
            let cost = canonical_size_bounded(&report, V1_MAX_CATALOG_BYTES).unwrap();
            assert!(super::super::inventory::inventory_catalog(&keys, &data, cost, None).is_ok());
            assert!(
                super::super::inventory::inventory_catalog(&keys, &data, cost - 1, None).is_err()
            );
            assert_preserved_files(&data, &before);
            assert!(!root_path.exists() && !history_path.exists());
            assert!(!capture.files[0].locator.area.path_hint.exists());
            assert!(!capture.files[0].locator.area.volume_root_hint.exists());
        }
    }

    #[test]
    fn inventory_reads_live_wal_without_checkpointing_or_rewriting_keys() {
        let ((keys, revision, _), _, _, _) = super::super::tests::fixed_checkpoint_fixture(7);
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().join("original");
        fs::create_dir(&data).unwrap();
        let (writer, _) = crate::volume::open_control_store(&data, &keys).unwrap();
        writer
            .database_shell_statement("PRAGMA wal_autocheckpoint = 0", false)
            .unwrap();
        save_revision(&writer, &revision);
        let root_id = revision.value.protected_root_id;
        save(
            &writer,
            "protected-root",
            root_id,
            &ProtectedRoot {
                format_version: 4,
                root_id,
                path: temp.path().join("missing-source"),
                filesystem_id: 7,
                root_inode: 10,
            },
        );
        let paths = ["control.db", "control.db-wal", "control.key"];
        let before: Vec<_> = paths
            .iter()
            .map(|name| fs::read(data.join(name)).unwrap())
            .collect();
        let report =
            super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                .unwrap();
        assert_eq!(report.revisions[0].revision_id, revision.value.revision_id);
        assert_eq!(report.local_state.protected_roots[0].root_id, root_id);
        for (name, expected) in paths.iter().zip(before) {
            assert!(
                fs::read(data.join(name)).unwrap() == expected,
                "{name} changed"
            );
        }
        assert!(!data.join("parity.db").exists());
        assert!(!temp.path().join("missing-source").exists());
    }

    #[test]
    fn local_inventory_rejects_malformed_ownership_and_registration_without_mutation() {
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([49; 32]));
        for case in 0..12 {
            let temp = tempfile::tempdir().unwrap();
            let data = temp.path().join("original");
            fs::create_dir(&data).unwrap();
            let store = ControlStore::open(data.join("control.db"), &keys).unwrap();
            let id = Uuid::from_bytes([43; 16]);
            let mut capture = stopped_capture(temp.path());
            match case {
                0 => capture.files[0].locator.anchor_id = Uuid::nil(),
                1 => capture.files[0].locator.area.area_id = Uuid::nil(),
                2 => capture.files[0].locator.relative_path = "../escape".into(),
                3 => capture.files[0].logical_len = 4,
                4 => capture.files[0].data_extents[0].logical_len = 4,
                5 => capture.metadata.entries[0].path = b"../escape".to_vec(),
                6 => capture
                    .metadata
                    .entries
                    .push(capture.metadata.entries[0].clone()),
                7 => {
                    save(
                        &store,
                        "protected-root",
                        id,
                        &ProtectedRoot {
                            format_version: 4,
                            root_id: Uuid::from_bytes([44; 16]),
                            path: temp.path().join("missing"),
                            filesystem_id: 7,
                            root_inode: 10,
                        },
                    );
                }
                8 => {
                    let mut binding = SourceBackendBinding::guarded_link_freeze_v1(id, 7, 10, 11);
                    binding.contract_version = 2;
                    save(&store, "source-backend", id, &binding);
                }
                9 => {
                    store
                        .put_record("git-repository", id.as_bytes(), b"invalid canonical record")
                        .unwrap();
                }
                10 => capture.files[0].locator.area.path_hint = "relative-area".into(),
                11 => capture.files[0].locator.area.path_hint = raw_path(temp.path(), b"nul\0area"),
                _ => unreachable!(),
            }
            save(&store, "guarded-view-stopped-capture-v1", id, &capture);
            drop(store);
            let before = preserved_files(&data);
            assert!(
                super::super::inventory::inventory_withdrawn_revisions_from_catalog(&keys, &data)
                    .is_err(),
                "case {case}"
            );
            assert_preserved_files(&data, &before);
            assert!(!capture.files[0].locator.area.path_hint.exists());
        }
    }
}

#[cfg(test)]
mod intent_tests;

#[cfg(test)]
mod owner_tests;
