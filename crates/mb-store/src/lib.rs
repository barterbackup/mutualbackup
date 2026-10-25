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
#[cfg(target_os = "linux")]
pub use anchor::{ANCHOR_DISCOVERY_CHECKPOINT_BYTES, AnchorAreaDiscovery, AnchorAreaDiscoveryStep};
pub use anchor::{
    AnchorAreaLocator, AnchorError, AnchorFileLocator, AnchorManifest, CapturedEntry,
    FileAnchorManifest, FileExtent, FilesystemIdentity, GIT_CATALOG_DIRECTORY,
    GIT_CATALOG_MARKER_FILE, ImportedBlobCapturePlan, NativeFileId, PinnedDirectory,
    PinnedEntryKind, PinnedReadDirectory, PreservedFileAnchor, PreservedFileCapture,
    PreservedFileCapturePlan, PreservedRootCapture, ReflinkAnchor, ReflinkCapturePlan,
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
#[cfg(target_os = "linux")]
pub use database::{
    ANCHOR_DISCOVERY_FENCE_KIND, ANCHOR_DISCOVERY_JOURNAL_KIND, AnchorDiscoveryJobPage,
    AnchorDiscoveryJobStatus, DatabaseDirectory, DatabaseOpenGuard, PreservedReadGuard,
};
pub use database::{
    CATALOG_ACQUISITION_WORK_JOBS, CATALOG_BUNDLE_DESCRIPTOR_BYTES, CATALOG_BUNDLE_ROOTS,
    CATALOG_SECTOR_RECIPE_BYTES, CatalogAcquisitionWorkState, CatalogAcquisitionWorkUsage,
    CatalogBundle, CatalogBundleRoot, CatalogBundleState, CatalogCertifiedCodingDirectoriesIndex,
    CatalogCertifiedCodingDirectoryIndex, CatalogCertifiedCodingGroup, CatalogCertifiedCodingIndex,
    CatalogCertifiedPackingDirectoryIndex, CatalogCertifiedPackingIndex,
    CatalogCheckpointAcquisition, CatalogCheckpointAcquisitionState,
    CatalogCheckpointAuthorityContext, CatalogCheckpointAuthorityIndex,
    CatalogCheckpointAuthorityValidation, CatalogCheckpointChunkLocation,
    CatalogCheckpointCodingDirectoriesIndex, CatalogCheckpointCodingDirectoryIndex,
    CatalogCheckpointCodingStateIndex, CatalogCheckpointCodingTrust,
    CatalogCheckpointDirectoriesCodingStateIndex, CatalogCheckpointDirectoriesTransitionIndex,
    CatalogCheckpointLocalCustody, CatalogCheckpointLocalCustodyPhase,
    CatalogCheckpointPackingDirectoryIndex, CatalogCheckpointPackingIndex,
    CatalogCheckpointPayload, CatalogCheckpointPrevious, CatalogCheckpointRecoverySource,
    CatalogCheckpointRecoveryTip, CatalogCheckpointRecoveryWork, CatalogCheckpointRetention,
    CatalogCheckpointRetentionState, CatalogCheckpointTransitionIndex,
    CatalogCheckpointWriterAuthorization, CatalogCodingAuthorization, CatalogCodingCoverage,
    CatalogCodingCoveragePolicy, CatalogCodingRetention, CatalogCodingRetentionState,
    CatalogCodingValidation, CatalogDurableGuildHistory, CatalogDurableGuildHistoryView,
    CatalogGuildEventProposalGuard, CatalogGuildHistoryIndex, CatalogGuildHistoryMutation,
    CatalogGuildHistoryObject, CatalogGuildHistorySnapshot, CatalogGuildHistorySource,
    CatalogGuildHistoryView, CatalogIndexedCodingGroup, CatalogIndexedDirectoryCodingGroup,
    CatalogIntent, CatalogIntentState, CatalogNativeValidation, CatalogNativeValidationState,
    CatalogPackingAuthority, CatalogPackingAuthorityBase, CatalogPackingAuthorizedSource,
    CatalogPackingCodingDirectoriesIndex, CatalogPackingCodingDirectoriesRetention,
    CatalogPackingCodingDirectoriesRetentionState, CatalogPackingCodingDirectoriesValidation,
    CatalogPackingCodingDirectoryIndex, CatalogPackingCodingDirectoryValidation,
    CatalogPackingCodingIndex, CatalogPackingCodingRetention, CatalogPackingCodingRetentionState,
    CatalogPackingCodingValidation, CatalogPackingDirectoryIndex,
    CatalogPackingDirectoryValidation, CatalogPackingIndex, CatalogPackingOperation,
    CatalogPackingOperationState, CatalogPackingOperationView, CatalogPackingOutputAttempt,
    CatalogPackingPayload, CatalogPackingPayloadRetention, CatalogPackingPayloadRetentionState,
    CatalogPackingPayloadView, CatalogPackingPlacement, CatalogPackingSector,
    CatalogPackingSourceRetention, CatalogPackingSourceRetentionState, CatalogPackingSourceView,
    CatalogPackingValidation, CatalogPageReservation, CatalogPagedCheckpointDirectoryRetention,
    CatalogPagedCheckpointRetention, CatalogPagedCheckpointRetentionState,
    CatalogPayloadRetirementView, CatalogProducedPackingDirectory, CatalogPublicCheckpoint,
    CatalogPublicationView, CatalogPublishedRevisionQuota, CatalogPublishedRevisionQuotaScope,
    CatalogPublishedRevisionQuotaState, CatalogPublishedRevisionQuotaUsage,
    CatalogPublishedRevisionQuotas, CatalogQuorumPagedCheckpointDirectoryIndex,
    CatalogQuorumPagedCheckpointIndex, CatalogResourcePolicy, CatalogRetainedSourceQuota,
    CatalogRetainedSourceReservation, CatalogRetainedSourceUsage, CatalogScratchLease,
    CatalogScratchPoolPolicy, CatalogScratchPoolUsage, CatalogSectorSource, CatalogSourceSweep,
    CatalogStorageQuota, CatalogStorageUsage, CatalogStoreError, CatalogTraversalPoolPolicy,
    CatalogValidatedCoding, CatalogValidatedLink, CheckpointRow, ControlStore, DatabaseError,
    DatabaseJournalQuota, DatabaseJournalQuotaUsage, DatabasePageQuota, DatabasePageQuotaUsage,
    DatabaseRecordQuota, DatabaseRecordQuotaState, DatabaseRecordQuotaUsage, DatabaseShellResult,
    KindedProtocolRecordMetadata, KindedProtocolRecordRow, ObjectAttemptState,
    PAGED_DATA_RECIPE_BYTES, PAGED_DATA_SHARED_BINDING_BYTES, PagedCatalogDataSource,
    PagedCatalogPageSource, PagedCatalogSectorSource, PagedCatalogSnapshot, ParityObject,
    ParityScrubReport, ParityStore, ProtocolRecordRow, ReadyVariableObject, RecordScratchStore,
    RecoveryShardLocator, ScratchStorageLimits, VariableParityObject,
};
#[cfg(target_os = "linux")]
pub const GUARDED_REVISION_CAPTURE_KIND: &str = "guarded-view-revision-capture-v1";
pub use source::{
    SourceBackendBinding, SourceBackendKind, SourceBlobImportPlan, SourceCapturePlan,
    SourceFileCaptureError, SourceFileCapturePlan, WITHDRAWN_GUARDED_BACKEND,
};

#[cfg(target_os = "linux")]
pub use database::physical_allocation_domain;

pub const SCHEMA_VERSION: u32 = 10;

#[cfg(target_os = "linux")]
pub use database::{DatabasePhysicalIoLimits, NativeDatabaseInspection, NativeDatabaseOwner};
