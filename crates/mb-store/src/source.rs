//! Versioned, durable dispatch for local source capture.
//!
//! The node persists a plan before touching source files. Keep existing enum
//! variants stable: withdrawn captures must remain identifiable after an upgrade.
//! Backends return the same stable anchor manifest consumed by sector encoding;
//! no backend identifier enters signed peer records.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

/// User-facing rejection shared by admission, startup, and recovery.
pub const WITHDRAWN_GUARDED_BACKEND: &str = "FUSE-backed guarded capture has been withdrawn; \
     preserve the old data directory, source trees, Git catalogs and anchors. \
     This version cannot migrate, replay or mount guarded state. Follow \
     docs/guarded-withdrawal.md before creating a separate native installation";

use crate::{
    AnchorError, ControlStore, FileAnchorManifest, ImportedBlobCapturePlan, NativeFileId,
    PinnedDirectory, ReflinkAnchor, ReflinkCapturePlan, ReflinkFileCapturePlan,
    StableAnchorManifest, probe_reflink,
};
#[cfg(target_os = "linux")]
use crate::{GuardedFileCapturePlan, GuardedRootCapturePlan, RawReflinkFileCapturePlanV2};

/// The operation validates its own native ownership before assistance is
/// completed. No persisted plan is rewritten with a discovered display path.
fn native_operation<T>(
    control: &ControlStore,
    area: &crate::StableAnchorAreaLocator,
    operation: impl FnOnce(Option<&Path>) -> Result<T, AnchorError>,
) -> anyhow::Result<T> {
    #[cfg(target_os = "linux")]
    {
        let path = control.resolve_anchor_area_location(area)?;
        let result = operation(Some(&path))?;
        control.remember_anchor_area_location(area.area_id, &path)?;
        Ok(result)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (control, area);
        Ok(operation(None)?)
    }
}

/// Local source capabilities never enter a signed peer record. ReflinkV1
/// provides sparse reflink capture, raw imports, and reflink checkout.
/// GuardedLinkFreezeV1 is withdrawn; retain its serialized identity so old
/// bindings and pending captures can be rejected without reinterpretation.
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
        // Enrollment only activates the native reflink contract.
        self.format_version == 1
            && self.contract_version == 1
            && self.root_id == root_id
            && self.backend == SourceBackendKind::ReflinkV1
            && self.filesystem_id == filesystem_id
            && self.root_inode == root_inode
            && self.mount_id != 0
    }

    #[cfg(target_os = "linux")]
    pub fn guarded_link_freeze_v1(
        root_id: Uuid,
        filesystem_id: u64,
        lower_inode: u64,
        mount_id: u64,
    ) -> Self {
        Self {
            format_version: 1,
            contract_version: 1,
            root_id,
            backend: SourceBackendKind::GuardedLinkFreezeV1,
            filesystem_id,
            root_inode: lower_inode,
            mount_id,
        }
    }

    #[cfg(target_os = "linux")]
    pub fn is_supported_guarded_for(
        &self,
        root_id: Uuid,
        filesystem_id: u64,
        lower_inode: u64,
    ) -> bool {
        self.format_version == 1
            && self.contract_version == 1
            && self.root_id == root_id
            && self.backend == SourceBackendKind::GuardedLinkFreezeV1
            && self.filesystem_id == filesystem_id
            && self.root_inode == lower_inode
            && self.mount_id != 0
    }
}

impl SourceBackendKind {
    /// Keep the legacy variant decodable, but never select it for new work.
    pub fn require_supported(self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1 => Ok(()),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }
    /// Only the native backend accepts new Git file anchors.
    pub fn supports_git_file_staging(self) -> bool {
        matches!(self, Self::ReflinkV1)
    }

    /// Only the native backend accepts new Git checkout publication.
    pub fn supports_git_checkout_file(self) -> bool {
        matches!(self, Self::ReflinkV1)
    }

    pub fn probe(self, source_root: impl AsRef<Path>) -> Result<(), AnchorError> {
        self.require_supported()?;
        match self {
            Self::ReflinkV1 => probe_reflink(source_root),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }

    pub fn plan_root(
        self,
        source_root: impl AsRef<Path>,
    ) -> Result<SourceCapturePlan, AnchorError> {
        self.require_supported()?;
        match self {
            Self::ReflinkV1 => SourceCapturePlan::plan_reflink(source_root),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }

    pub fn plan_file(
        self,
        source_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<SourceFileCapturePlan, AnchorError> {
        self.require_supported()?;
        match self {
            Self::ReflinkV1 => {
                #[cfg(target_os = "linux")]
                if relative_path.as_ref().to_str().is_none() {
                    return SourceFileCapturePlan::plan_reflink_raw(source_root, relative_path);
                }
                SourceFileCapturePlan::plan_reflink(source_root, relative_path)
            }
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }

    pub fn plan_blob_import(
        self,
        source_root: impl AsRef<Path>,
        logical_len: u64,
    ) -> Result<SourceBlobImportPlan, AnchorError> {
        self.require_supported()?;
        match self {
            Self::ReflinkV1 => SourceBlobImportPlan::plan_direct(source_root, logical_len),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                WITHDRAWN_GUARDED_BACKEND,
            )),
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
        self.publish_checkout_file_with_area_hint(staging, name, anchor, mode, None)
    }

    pub fn publish_checkout_file_with_area_hint(
        self,
        staging: &PinnedDirectory,
        name: impl AsRef<Path>,
        anchor: &FileAnchorManifest,
        mode: u32,
        hint: Option<&Path>,
    ) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1 => {
                staging.publish_reflink_child_with_area_hint(name, anchor, mode, hint)
            }
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1 => Err(AnchorError::UnsupportedSourceOperation(
                WITHDRAWN_GUARDED_BACKEND,
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
    /// Inspect a retained plan without executing capture, discovery or replay.
    pub fn preserved_ownership(&self) -> anyhow::Result<crate::PreservedRootCapture<'_>> {
        match self {
            Self::ReflinkV1(plan) => plan.preserved_ownership(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.preserved_ownership(),
        }
    }

    pub fn for_each_preserved_file_capture(
        &self,
        visit: impl FnMut(crate::PreservedFileCapture<'_>) -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(plan) => {
                plan.preserved_ownership()?;
                let _ = visit;
                Ok(())
            }
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.for_each_preserved_file_capture(visit),
        }
    }

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
            Self::ReflinkV1(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::capture_plan_with_area_hint(plan, hint)
            }),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => anyhow::bail!("{WITHDRAWN_GUARDED_BACKEND}"),
        }
    }

    /// Native reflink roots keep anchors on independent COW inodes.
    /// A withdrawn plan cannot authorize an edit or journal replay.
    pub fn prepare_file_edit_at(
        &self,
        _control: &ControlStore,
        _captured_relative_path: impl AsRef<Path>,
        _current_relative_path: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => anyhow::bail!("{WITHDRAWN_GUARDED_BACKEND}"),
        }
    }

    pub fn discard(&self, control: &ControlStore) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(plan) => {
                anyhow::ensure!(
                    !control.paged_data_anchor_is_pinned(plan.anchor_id())?,
                    "capture remains owned by a paged data source"
                );
                native_operation(control, plan.area(), |hint| {
                    ReflinkAnchor::discard_capture_with_area_hint(plan, hint)
                })
            }
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => anyhow::bail!("{WITHDRAWN_GUARDED_BACKEND}"),
        }
    }

    /// Read completed ownership without capture replay or source access.
    pub fn captured_manifest(
        &self,
        control: &ControlStore,
    ) -> anyhow::Result<StableAnchorManifest> {
        match self {
            Self::ReflinkV1(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::read_capture_manifest_with_area_hint(plan, hint)
            }),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => anyhow::bail!("{WITHDRAWN_GUARDED_BACKEND}"),
        }
    }

    pub fn reconcile(&self, control: &ControlStore) -> anyhow::Result<()> {
        match self {
            Self::ReflinkV1(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::reconcile_capture_with_area_hint(plan, hint)
            }),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => anyhow::bail!("{WITHDRAWN_GUARDED_BACKEND}"),
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
    #[error("native anchor discovery failed: {0}")]
    Discovery(anyhow::Error),
    #[error(transparent)]
    Anchor(#[from] AnchorError),
    #[cfg(target_os = "linux")]
    #[error("guarded file capture failed: {0}")]
    Guarded(#[from] anyhow::Error),
}

impl SourceFileCaptureError {
    fn discovery(error: anyhow::Error) -> Self {
        match error.downcast::<AnchorError>() {
            Ok(error) => Self::Anchor(error),
            Err(error) => Self::Discovery(error),
        }
    }
}

impl SourceFileCapturePlan {
    /// Inspect the original plan shape without source access, capture or replay.
    pub fn preserved_ownership(&self) -> anyhow::Result<crate::PreservedFileCapturePlan<'_>> {
        match self {
            Self::ReflinkV1(plan) => plan.preserved_ownership(),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(plan) => plan.preserved_ownership(),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => plan.preserved_ownership(),
        }
    }

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
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }

    /// Replay native captures; legacy plans remain decodable for rejection.
    pub fn capture_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<FileAnchorManifest, SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::capture_file_plan_encoding(
                    plan,
                    crate::anchor::FileManifestEncoding::Utf8V1,
                    hint,
                )
            })
            .map_err(SourceFileCaptureError::discovery),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::capture_file_plan_encoding(
                    &plan.as_legacy()?,
                    crate::anchor::FileManifestEncoding::RawV2,
                    hint,
                )
            })
            .map_err(SourceFileCaptureError::discovery),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => {
                Err(AnchorError::UnsupportedSourceOperation(WITHDRAWN_GUARDED_BACKEND).into())
            }
        }
    }

    /// Native captures already have independent inodes. Legacy captures
    /// cannot authorize edits to a previously shared inode.
    pub fn prepare_edit_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        self.prepare_edit_at_with_control(control, self.relative_path())
    }

    /// A native reflink capture needs no detach at either source path.
    pub fn prepare_edit_at_with_control(
        &self,
        _control: &ControlStore,
        _current_relative_path: impl AsRef<Path>,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(_) => Ok(()),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => {
                Err(AnchorError::UnsupportedSourceOperation(WITHDRAWN_GUARDED_BACKEND).into())
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
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }

    pub fn reconcile_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::reconcile_file_capture_encoding(
                    plan,
                    crate::anchor::FileManifestEncoding::Utf8V1,
                    hint,
                )
            })
            .map_err(SourceFileCaptureError::discovery),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::reconcile_file_capture_encoding(
                    &plan.as_legacy()?,
                    crate::anchor::FileManifestEncoding::RawV2,
                    hint,
                )
            })
            .map_err(SourceFileCaptureError::discovery),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => {
                Err(AnchorError::UnsupportedSourceOperation(WITHDRAWN_GUARDED_BACKEND).into())
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
                WITHDRAWN_GUARDED_BACKEND,
            )),
        }
    }

    pub fn discard_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::ReflinkV1(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::discard_file_capture_with_area_hint(plan, hint)
            })
            .map_err(SourceFileCaptureError::discovery),
            #[cfg(target_os = "linux")]
            Self::ReflinkRawV2(plan) => native_operation(control, plan.area(), |hint| {
                ReflinkAnchor::discard_file_capture_with_area_hint(&plan.as_legacy()?, hint)
            })
            .map_err(SourceFileCaptureError::discovery),
            #[cfg(target_os = "linux")]
            Self::GuardedLinkFreezeV1(_) => {
                Err(AnchorError::UnsupportedSourceOperation(WITHDRAWN_GUARDED_BACKEND).into())
            }
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod withdrawal_tests {
    use super::*;
    use mb_core::{canonical_bytes, decode_canonical};
    use std::fmt::Display;
    use std::fs;

    fn withdrawn<T, E: Display>(result: Result<T, E>) {
        match result {
            Err(error) => assert!(error.to_string().contains("withdrawn"), "{error}"),
            Ok(_) => panic!("a withdrawn source operation succeeded"),
        }
    }

    #[test]
    fn legacy_plans_decode_but_cannot_capture_edit_replay_or_discard() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("absent-source");
        let area = crate::StableAnchorAreaLocator {
            area_id: Uuid::from_bytes([1; 16]),
            path_hint: temporary.path().join("absent-anchors"),
            filesystem_id: 2,
            volume_root_hint: temporary.path().to_path_buf(),
        };
        let source_bytes = source.to_str().unwrap().as_bytes().to_vec();
        let version = (2_u64, 3_u64, 0_u64, 0_i64, 0_i64, 0_i64, 0_i64);
        let root_bytes = canonical_bytes(&(
            1_u16,
            Uuid::from_bytes([4; 16]),
            source_bytes.clone(),
            area.clone(),
            version,
            0o755_u32,
            0_i64,
            0_u32,
            Vec::<u8>::new(),
        ))
        .unwrap();
        let root = SourceCapturePlan::GuardedLinkFreezeV1(decode_canonical(&root_bytes).unwrap());
        let file_bytes = canonical_bytes(&(
            1_u16,
            Uuid::from_bytes([5; 16]),
            source_bytes,
            NativeFileId {
                filesystem_id: 2,
                inode: 3,
            },
            b"file".to_vec(),
            version,
            0o644_u32,
            area.clone(),
        ))
        .unwrap();
        let file =
            SourceFileCapturePlan::GuardedLinkFreezeV1(decode_canonical(&file_bytes).unwrap());
        let root_wire = canonical_bytes(&root).unwrap();
        let file_wire = canonical_bytes(&file).unwrap();
        assert_eq!(root_wire[0], 1);
        assert_eq!(file_wire[0], 1);
        let database = temporary.path().join("control.db");
        let control = ControlStore::open_with_key(&database, &[6; 32]).unwrap();
        control.make_query_only().unwrap();
        let original = fs::read(&database).unwrap();
        withdrawn(root.capture(&control));
        withdrawn(root.prepare_file_edit_at(&control, "file", "renamed"));
        withdrawn(root.reconcile(&control));
        withdrawn(root.discard(&control));
        withdrawn(file.capture());
        withdrawn(file.capture_with_control(&control));
        withdrawn(file.prepare_edit_with_control(&control));
        withdrawn(file.prepare_edit_at_with_control(&control, "renamed"));
        withdrawn(file.reconcile());
        withdrawn(file.reconcile_with_control(&control));
        withdrawn(file.discard());
        withdrawn(file.discard_with_control(&control));
        let backend = SourceBackendKind::GuardedLinkFreezeV1;
        withdrawn(backend.probe(&source));
        withdrawn(backend.plan_root(&source));
        withdrawn(backend.plan_file(&source, "file"));
        withdrawn(backend.plan_blob_import(&source, 0));
        assert_eq!(canonical_bytes(&root).unwrap(), root_wire);
        assert_eq!(canonical_bytes(&file).unwrap(), file_wire);
        assert_eq!(fs::read(database).unwrap(), original);
        assert!(!source.exists());
        assert!(!area.path_hint.exists());
        assert!(!control.has_records_with_kind_prefix("").unwrap());
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
    #[cfg(target_os = "linux")]
    pub fn capture_with_control(
        &self,
        control: &ControlStore,
        source: impl Read,
    ) -> Result<FileAnchorManifest, SourceFileCaptureError> {
        match self {
            Self::DirectV1(plan) => native_operation(control, plan.area(), |hint| {
                plan.capture_with_area_hint(source, hint)
            })
            .map_err(SourceFileCaptureError::discovery),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn reconcile_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::DirectV1(plan) => native_operation(control, plan.area(), |hint| {
                plan.reconcile_with_area_hint(hint)
            })
            .map_err(SourceFileCaptureError::discovery),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn discard_with_control(
        &self,
        control: &ControlStore,
    ) -> Result<(), SourceFileCaptureError> {
        match self {
            Self::DirectV1(plan) => native_operation(control, plan.area(), |hint| {
                plan.discard_with_area_hint(hint)
            })
            .map_err(SourceFileCaptureError::discovery),
        }
    }
}
