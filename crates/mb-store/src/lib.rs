//! SQLCipher persistence and source-anchor backends.
//!
//! APIs in this crate are synchronous by design. Node orchestration calls them
//! through bounded blocking workers rather than holding database state across
//! `.await` points.

mod anchor;
mod database;
#[cfg(target_os = "linux")]
mod guarded_mount;
#[cfg(target_os = "linux")]
mod guarded_recovery_handoff;
#[cfg(target_os = "linux")]
mod guarded_view_probe;
#[cfg(target_os = "linux")]
mod link_freeze;
mod source;

#[cfg(target_os = "linux")]
pub use anchor::raw_path_bytes;
#[cfg(target_os = "linux")]
pub use anchor::raw_path_bytes_option;
#[cfg(target_os = "linux")]
pub use anchor::raw_path_bytes_vec;
pub use anchor::{
    AnchorAreaLocator, AnchorError, AnchorFileLocator, AnchorManifest, CapturedEntry,
    FileAnchorManifest, FileExtent, FilesystemIdentity, GIT_CATALOG_DIRECTORY,
    GIT_CATALOG_MARKER_FILE, ImportedBlobCapturePlan, NativeFileId, PinnedDirectory,
    PinnedEntryKind, ReflinkAnchor, ReflinkCapturePlan, ReflinkFileCapturePlan,
    StableAnchorAreaLocator, StableAnchorFileLocator, StableAnchorManifest, directory_identity,
    filesystem_identity, git_catalog_marker, git_catalog_marker_bytes, probe_reflink,
    remove_owned_directory_tree,
};
#[cfg(target_os = "linux")]
pub use anchor::{
    GuardedFileCapturePlan, GuardedRootCapturePlan, RawFileAnchorManifestV2,
    RawReflinkFileCapturePlanV2, probe_guarded_link_freeze,
};
pub use database::{
    CheckpointRow, ControlStore, DatabaseError, DatabaseShellResult, KindedProtocolRecordRow,
    ObjectAttemptState, ParityObject, ParityScrubReport, ParityStore, ProtocolRecordRow,
    VariableParityObject,
};
#[cfg(target_os = "linux")]
pub use guarded_mount::{
    GUARDED_REVISION_CAPTURE_KIND, GuardedRevisionCaptureV1, GuardedStoppedCaptureV1,
    GuardedStoppedFileV1, GuardedViewBinding, GuardedViewMount,
};
#[cfg(target_os = "linux")]
pub use guarded_recovery_handoff::{
    GuardedRecoveryHandoff, restore_visible_release_metadata, verify_visible_release_namespace,
};
#[cfg(target_os = "linux")]
pub use guarded_view_probe::{
    GuardedViewEntryKind, GuardedViewMetadataEntry, GuardedViewMetadataV1,
    probe_guarded_view_passthrough,
};
#[cfg(target_os = "linux")]
pub use link_freeze::{
    AccessAclSnapshot, FileAccessSnapshot, FileWriteExclusion, FrozenAnchorProof,
    IndependentSparseCopy, LinkFreezeCaptureIntent, LinkFreezeCapturePhase, LinkFreezeEditIntent,
    LinkFreezeEditPhase,
};
pub use source::{
    SourceBackendBinding, SourceBackendKind, SourceBlobImportPlan, SourceCapturePlan,
    SourceFileCaptureError, SourceFileCapturePlan,
};

pub const SCHEMA_VERSION: u32 = 9;
