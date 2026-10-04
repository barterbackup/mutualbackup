//! Versioned, durable dispatch for local source capture.
//!
//! The node persists a plan before touching source files. Keep existing enum
//! variants stable: a pending capture must remain replayable after an upgrade.
//! Backends return the same stable anchor manifest consumed by sector encoding;
//! no backend identifier enters signed peer records.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    AnchorError, ControlStore, FileAnchorManifest, ImportedBlobCapturePlan, NativeFileId,
    PinnedDirectory, ReflinkAnchor, ReflinkCapturePlan, ReflinkFileCapturePlan,
    StableAnchorManifest, probe_reflink,
};
#[cfg(target_os = "linux")]
use crate::{
    GuardedFileCapturePlan, GuardedRootCapturePlan, RawReflinkFileCapturePlanV2,
    probe_guarded_link_freeze,
};

/// Local source capabilities never enter a signed peer record. ReflinkV1
/// provides byte-exact sparse reflink capture, raw imports, and reflink
/// checkout. GuardedLinkFreezeV1 provides replayable whole-root capture and
/// retirement plus explicit root-file and Git-file edit detaches. Node enrollment must not
/// select it until a live edit guard invokes that detach for every retained
/// hard link; new Git stage/checkout operations remain unavailable until their
/// separate source-safety gate is implemented.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceBackendKind {
    ReflinkV1,
    #[cfg(target_os = "linux")]
    GuardedLinkFreezeV1,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SourceBackendBinding {
    pub format_version: u16,
    pub contract_version: u16,
    pub root_id: Uuid,
    pub backend: SourceBackendKind,
    pub filesystem_id: u64,
    pub root_inode: u64,
    pub mount_id: u64,
}

impl SourceBackendBinding {
    pub fn reflink_v1(root_id: Uuid, filesystem_id: u64, root_inode: u64, mount_id: u64) -> Self {
        Self {
            format_version: 1,
            contract_version: 1,
            root_id,
            backend: SourceBackendKind::ReflinkV1,
            filesystem_id,
            root_inode,
            mount_id,
        }
    }

    pub fn is_supported_for(&self, root_id: Uuid, filesystem_id: u64, root_inode: u64) -> bool {
        // Existing node enrollment only activates the reflink contract. A
        // guarded binding needs explicit selection and its own reprobe path.
        self.format_version == 1
            && self.contract_version == 1
            && self.root_id == root_id
            && self.backend == SourceBackendKind::ReflinkV1
            && self.filesystem_id == filesystem_id
            && self.root_inode == root_inode
            && self.mount_id != 0
    }
}

impl SourceBackendKind {
    /// The guarded backend cannot retain Git file anchors until its live
    /// edit-detach guard is available to every enrolled worktree.
    pub fn supports_git_file_staging(self) -> bool {
        matches!(self, Self::ReflinkV1)
    }

    /// Guarded checkout needs a protected editable hard-link transition;
    /// publishing a regular file through that backend is still gated.
    pub fn supports_git_checkout_file(self) -> bool {
        matches!(self, Self::ReflinkV1)
    }

    pub fn probe(self, source_root: impl AsRef<Path>) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1 => probe_reflink(source_root),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => probe_guarded_link_freeze(source_root),
        }
    }

    pub fn plan_root(
        self,
        source_root: impl AsRef<Path>,
    ) -> Result<SourceCapturePlan, AnchorError> {
        match self {
            Self::ReflinkV1 => SourceCapturePlan::plan_reflink(source_root),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => GuardedRootCapturePlan::plan(source_root)
                .map(SourceCapturePlan::GuardedLinkFreezeV1),
        }
    }

    pub fn plan_file(
        self,
        source_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<SourceFileCapturePlan, AnchorError> {
        match self {
            Self::ReflinkV1 => SourceFileCapturePlan::plan_reflink(source_root, relative_path),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                "Git file staging with guarded link-freeze",
            )),
        }
    }

    pub fn plan_blob_import(
        self,
        source_root: impl AsRef<Path>,
        logical_len: u64,
    ) -> Result<SourceBlobImportPlan, AnchorError> {
        match self {
            Self::ReflinkV1 => SourceBlobImportPlan::plan_direct(source_root, logical_len),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => {
                SourceBlobImportPlan::plan_direct(source_root, logical_len)
            }
        }
    }

    /// Publish a distinct editable inode from a verified immutable anchor.
    pub fn publish_checkout_file(
        self,
        staging: &PinnedDirectory,
        name: impl AsRef<Path>,
        anchor: &FileAnchorManifest,
        mode: u32,
    ) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1 => staging.publish_reflink_child(name, anchor, mode),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                "Git checkout with guarded link-freeze",
            )),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceCapturePlan {
    ReflinkV1(ReflinkCapturePlan),
    #[cfg(target_os = "linux")]
    GuardedLinkFreezeV1(GuardedRootCapturePlan),
}

impl SourceCapturePlan {
    pub fn plan_reflink(source_root: impl AsRef<Path>) -> Result<Self, AnchorError> {
        ReflinkAnchor::plan(source_root).map(Self::ReflinkV1)
    }

    pub fn source_root(&self) -> &Path {
        match self {
            Self::ReflinkV1(plan) => plan.source_root(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.source_root(),
        }
    }

    pub fn capture(&self, control: &ControlStore) -> anyhow::Result<StableAnchorManifest> {
        match self {
            Self::ReflinkV1(plan) => Ok(ReflinkAnchor::capture_plan(plan)?),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.capture(control),
        }
    }

    /// Detach one file in a published guarded root before an edit. Reflink
    /// roots already keep their anchors on independent COW inodes.
    pub fn prepare_file_edit_at(
        &self,
        control: &ControlStore,
        captured_relative_path: impl AsRef<Path>,
        current_relative_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => {
                plan.prepare_file_edit_at(control, captured_relative_path, current_relative_path)
            }
        }
    }

    pub fn discard(&self, control: &ControlStore) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(plan) => Ok(ReflinkAnchor::discard_capture(plan)?),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.discard_unreferenced(control),
        }
    }

    pub fn reconcile(&self, control: &ControlStore) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(plan) => Ok(ReflinkAnchor::reconcile_capture(plan)?),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.reconcile(control),
        }
    }
}

/// A separate durable operation from whole-root backup capture. Its anchor is
/// pinned by the Git stage/object map, not by a signed source revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceFileCapturePlan {
    ReflinkV1(ReflinkFileCapturePlan),
    #[cfg(target_os = "linux")]
    GuardedLinkFreezeV1(GuardedFileCapturePlan),
    #[cfg(target_os = "linux")]
    ReflinkRawV2(RawReflinkFileCapturePlanV2),
}

#[derive(Debug, Error)]
pub enum SourceFileCaptureError {
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    #[cfg(target_os = "linux")]
    #[error("guarded file capture failed: {0}")]
    Guarded(#[from] anyhow::Error),
}

impl SourceFileCapturePlan {
    pub fn backend_kind(&self) -> SourceBackendKind {
        match self {
            Self::ReflinkV1(_) => SourceBackendKind::ReflinkV1,
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(_) => SourceBackendKind::ReflinkV1,
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => SourceBackendKind::GuardedLinkFreezeV1,
        }
    }

    pub fn plan_reflink(
        source_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<Self, AnchorError> {
        ReflinkAnchor::plan_file(source_root, relative_path).map(Self::ReflinkV1)
    }

    #[cfg(target_os = "linux")]
    pub fn plan_reflink_raw(
        source_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<Self, AnchorError> {
        ReflinkAnchor::plan_file_raw(source_root, relative_path).map(Self::ReflinkRawV2)
    }

    pub fn capture(&self) -> Result<FileAnchorManifest, AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::capture_file_plan(plan),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.capture(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => Err(AnchorError::UnsupportedSourceOperation(
                "guarded file capture needs the control store",
            )),
        }
    }

    /// Replay either backend using the durable control journal. New guarded
    /// plans remain gated by `SourceBackendKind::plan_file` until edit safety
    /// permits retaining a shared hard-link inode.
    pub fn capture_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<FileAnchorManifest, SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(plan) => Ok(ReflinkAnchor::capture_file_plan(plan)?),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => Ok(plan.capture()?),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => Ok(plan.capture(control)?),
        }
    }

    /// Ensure a retained source file can be edited without changing its
    /// immutable anchor. Reflink captures already have independent inodes;
    /// guarded captures must complete their durable sparse detach first.
    pub fn prepare_edit_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        self.prepare_edit_at_with_control(control, self.relative_path())
    }

    /// A guarded source may have moved since capture. The caller supplies its
    /// current path so the backend can prove that inode before replaying the
    /// edit journal; a reflink capture needs no detach at either path.
    pub fn prepare_edit_at_with_control(
        &self,
        control: &ControlStore,
        current_relative_path: impl AsRef<Path>,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => {
                Ok(plan.prepare_edit_at(control, current_relative_path)?)
            }
        }
    }

    pub fn source_mode(&self) -> Result<u32, AnchorError> {
        match self {
            Self::ReflinkV1(plan) => plan.source_mode(),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.source_mode(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => Ok(plan.source_mode()),
        }
    }

    pub fn source_root(&self) -> &Path {
        match self {
            Self::ReflinkV1(plan) => plan.source_root(),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.source_root(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.source_root(),
        }
    }

    pub fn source_root_identity(&self) -> crate::NativeFileId {
        match self {
            Self::ReflinkV1(plan) => plan.source_root_identity(),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.source_root_identity(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.source_root_identity(),
        }
    }

    pub fn relative_path(&self) -> &Path {
        match self {
            Self::ReflinkV1(plan) => plan.relative_path(),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.relative_path(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.relative_path(),
        }
    }

    pub fn reconcile(&self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::reconcile_file_capture(plan),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.reconcile(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => Err(AnchorError::UnsupportedSourceOperation(
                "guarded file reconciliation needs the control store",
            )),
        }
    }

    pub fn reconcile_with_control(
        &self,
        _control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(plan) => Ok(ReflinkAnchor::reconcile_file_capture(plan)?),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => Ok(plan.reconcile()?),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => {
                // capture() verified and synced the guarded manifest before
                // returning; replay calls capture() again before reaching here.
                Ok(())
            }
        }
    }

    pub fn discard(&self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::discard_file_capture(plan),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.discard(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => Err(AnchorError::UnsupportedSourceOperation(
                "guarded file retirement needs the control store",
            )),
        }
    }

    pub fn discard_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(plan) => Ok(ReflinkAnchor::discard_file_capture(plan)?),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => Ok(plan.discard()?),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => Ok(plan.discard_unreferenced(control)?),
        }
    }
}

/// Versioned import of bytes already held by another object store. The
/// producer supplies a bounded stream; the backend writes straight into one
/// immutable native anchor and can replay a completed publication without it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceBlobImportPlan {
    DirectV1(ImportedBlobCapturePlan),
}

impl SourceBlobImportPlan {
    pub fn plan_direct(
        source_root: impl AsRef<Path>,
        logical_len: u64,
    ) -> Result<Self, AnchorError> {
        ImportedBlobCapturePlan::plan(source_root, logical_len).map(Self::DirectV1)
    }

    pub fn source_root(&self) -> &Path {
        match self {
            Self::DirectV1(plan) => plan.source_root(),
        }
    }

    pub fn source_root_identity(&self) -> NativeFileId {
        match self {
            Self::DirectV1(plan) => plan.source_root_identity(),
        }
    }

    pub fn logical_len(&self) -> u64 {
        match self {
            Self::DirectV1(plan) => plan.logical_len(),
        }
    }

    pub fn anchor_id(&self) -> Uuid {
        match self {
            Self::DirectV1(plan) => plan.anchor_id(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn capture(&self, source: impl Read) -> Result<FileAnchorManifest, AnchorError> {
        match self {
            Self::DirectV1(plan) => plan.capture(source),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn reconcile(&self) -> Result<(), AnchorError> {
        match self {
            Self::DirectV1(plan) => plan.reconcile(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn discard(&self) -> Result<(), AnchorError> {
        match self {
            Self::DirectV1(plan) => plan.discard(),
        }
    }
}
