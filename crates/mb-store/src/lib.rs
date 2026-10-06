//! SQLCipher persistence and source-anchor backends.
//!
//! APIs in this crate are synchronous by design. Node orchestration calls them
//! through bounded blocking workers rather than holding database state across
//! `.await` points.

mod anchor;
mod database;
mod source;

#[cfg(target_os = "linux")]
pub use anchor::PreservedAnchorArea;
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
    PinnedEntryKind, PinnedReadDirectory, ReflinkAnchor, ReflinkCapturePlan,
    ReflinkFileCapturePlan, StableAnchorAreaLocator, StableAnchorFileLocator, StableAnchorManifest,
    directory_identity, filesystem_identity, git_catalog_marker, git_catalog_marker_bytes,
    probe_reflink, remove_owned_directory_tree,
};
#[cfg(target_os = "linux")]
pub use anchor::{
    GuardedFileCapturePlan, GuardedRootCapturePlan, GuardedRootFileBacking,
    RawFileAnchorManifestV2, RawReflinkFileCapturePlanV2,
};
#[cfg(target_os = "linux")]
pub use anchor::{
    GuardedRevisionCaptureV1, GuardedStoppedCaptureV1, GuardedStoppedFileV1, GuardedViewEntryKind,
    GuardedViewMetadataEntry, GuardedViewMetadataV1,
};
pub use database::{
    CATALOG_BUNDLE_DESCRIPTOR_BYTES, CATALOG_BUNDLE_ROOTS, CATALOG_SECTOR_RECIPE_BYTES,
    CatalogBundle, CatalogBundleRoot, CatalogBundleState, CatalogIntent, CatalogIntentState,
    CatalogNativeValidation, CatalogNativeValidationState, CatalogPublicationView,
    CatalogSectorSource, CatalogSourceSweep, CatalogStoreError, CatalogValidatedLink,
    CheckpointRow, ControlStore, DatabaseError, DatabaseShellResult, KindedProtocolRecordRow,
    ObjectAttemptState, PAGED_DATA_RECIPE_BYTES, PagedCatalogDataSource, PagedCatalogPageSource,
    PagedCatalogSnapshot, ParityObject, ParityScrubReport, ParityStore, ProtocolRecordRow,
    ReadyVariableObject, RecoveryShardLocator, VariableParityObject,
};
#[cfg(target_os = "linux")]
pub const GUARDED_REVISION_CAPTURE_KIND: &str = "guarded-view-revision-capture-v1";
pub use source::{
    SourceBackendBinding, SourceBackendKind, SourceBlobImportPlan, SourceCapturePlan,
    SourceFileCaptureError, SourceFileCapturePlan, WITHDRAWN_GUARDED_BACKEND,
};

pub const SCHEMA_VERSION: u32 = 9;
