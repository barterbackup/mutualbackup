//! Active node state machine and transport-independent protocol services.

mod automation;
mod control;
#[cfg(target_os = "linux")]
mod guarded_metadata;
#[cfg(test)]
mod lab;
#[cfg(target_os = "linux")]
mod legacy_export;
mod native_catalog;
mod network;
mod node;
mod paged_data;
#[cfg(target_os = "linux")]
mod paged_legacy;
mod paged_migration;
#[cfg(target_os = "linux")]
mod paged_restore;
#[cfg(target_os = "linux")]
pub use paged_legacy::PagedPrivateStream;
pub use paged_migration::RetainedLegacyMigration;
mod paged_revision;
pub use paged_data::{PagedAnchorSectorSource, PagedDataSource, PagedLegacyDataAuthority};
mod snapshot;
mod source_policy;
mod volume;
mod watcher;
mod wire;

pub use automation::{run_automatic_backups, run_periodic_audits};
pub use control::{
    GitRepositoryInfo, GitStagedFile, LocalControlConnection, LocalControlListener, LocalRequest,
    LocalResponse, NodeStatus, ProtectedRoot, UnlockSecret, bind_local_control, local_control_call,
    serve_local_control, serve_local_control_on,
};
#[cfg(target_os = "linux")]
pub use guarded_metadata::{GuardedPrivateEntryV6, GuardedPrivateMetadataV6, GuardedPrivateStatV6};
#[cfg(target_os = "linux")]
pub use legacy_export::{
    LegacyAnchorAreaLocation, LegacyCaptureOwnership, LegacyExportPeer, LegacyExportReport,
    LegacyGitAnchorAreaLocation, LegacyGitBlobPin, LegacyGitGraphObject, LegacyGitGraphRef,
    LegacyGitIndexRegistration, LegacyGitMetadataObject, LegacyGitObjectAnchor, LegacyGitReference,
    LegacyGitRegistration, LegacyGitSelectedBranch, LegacyGitWorktreeRegistration,
    LegacyGuardedAnchorPin, LegacyGuardedCapture, LegacyLocalSectorRecipe, LegacyLocalSectorSource,
    LegacyLocalStateInventory, LegacyPeerInventoryCoverage, LegacyPeerSources,
    LegacyPendingCapture, LegacyPendingFilePin, LegacyPendingGitGraph, LegacyPreservedRecord,
    LegacyRetainedAnchor, LegacyRevisionInventory, LegacyRevisionInventoryEntry,
    LegacyRootRegistration, LegacySourceBinding, LegacyStorageVolumeRegistration,
    LegacyVolumeOwnership, export_withdrawn_revision_from_catalog,
    export_withdrawn_revision_from_catalog_over_network,
    export_withdrawn_revision_from_catalog_with_anchor_areas,
    export_withdrawn_revision_from_catalog_with_preserved_sources,
    export_withdrawn_revision_from_files, export_withdrawn_revision_from_source,
    inventory_withdrawn_revisions_from_catalog,
    inventory_withdrawn_revisions_from_catalog_over_network,
};
pub use mb_core::{KeyMaterial, NodeId, Seed};
pub use native_catalog::{NativeCatalogStream, NativeCatalogWriteError};
pub use network::{
    ClaimedTorTransportConfig, DhtRecord, DhtRecoveryResult, ONION_SERVICE_PORT, P2pActiveSession,
    P2pClient, P2pConfig, P2pEventLoop, P2pPath, P2pPathMetrics, P2pPathTransfer, P2pPeerProfile,
    P2pPeerStatus, P2pSessionDirection, P2pSessionHistory, P2pSessionOutcome, P2pStartup,
    P2pStartupReceiver, P2pStatus, PreparedTorTransportConfig, TorMode, TorShutdownHandle,
    TorTransport, TorTransportConfig, audit_guild, build_p2p, build_p2p_with_tor,
    endpoint_record_key, is_onion_address, onion_address_matches_node, onion_address_matches_peer,
    onion_listener_address, recover_from_dht, recovery_bundle_key, recovery_mailbox_key,
    run_coding_holder_cleanup_jobs, run_coordinator_jobs, run_delegated_coding_jobs,
    run_dht_publications, run_peer_exchange, run_port_mapping, run_relay_membership_sync,
    validate_bootstrap_addresses, validate_local_advertised_endpoints,
    validate_port_mapping_listeners, wait_for_onion_service_shutdown,
};
pub use node::{
    AutomaticBackupPolicy, AutomaticBackupStatus, BackupDescriptor, BackupJob, BackupJobState,
    DhtPublicationSet, DhtSequenceFloors, GuildAuditReport, GuildPeer, GuildPhase, GuildSummary,
    LockedDataDir, Node, ProtectionState, RecoveredShards, SnapshotInfo,
};
pub use paged_revision::{
    PAGED_PRIVATE_METADATA_BYTES, PagedCatalogIntents, PagedPrivateMetadata,
    PagedRevisionCatalogSnapshot,
};
pub use snapshot::{
    PrivateDataExtent, PrivateEntry, PrivateMetadata, restore_revision,
    restore_revision_from_source,
};
#[cfg(target_os = "linux")]
pub use volume::{LegacyVolumeOwnershipEvidence, LegacyVolumeReceipt};
pub use volume::{
    PreservedParityVolume, StorageScrubReport, StorageVolumeState, StorageVolumeStatus,
};
pub use watcher::run_root_watcher;
pub use wire::{WireError, WireErrorCode};
