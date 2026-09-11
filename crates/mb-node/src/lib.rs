//! Active node state machine and transport-independent protocol services.

mod control;
#[cfg(test)]
mod lab;
mod network;
mod node;
mod snapshot;
mod watcher;
mod wire;

pub use control::{
    LocalControlConnection, LocalControlListener, LocalRequest, LocalResponse, NodeStatus,
    ProtectedRoot, UnlockSecret, bind_local_control, local_control_call, serve_local_control,
    serve_local_control_on,
};
pub use mb_core::{KeyMaterial, NodeId, Seed};
pub use network::{
    DhtRecord, DhtRecoveryResult, ONION_SERVICE_PORT, P2pActiveSession, P2pClient, P2pConfig,
    P2pEventLoop, P2pPath, P2pPathMetrics, P2pPathTransfer, P2pPeerProfile, P2pPeerStatus,
    P2pSessionDirection, P2pSessionHistory, P2pSessionOutcome, P2pStartup, P2pStartupReceiver,
    P2pStatus, PreparedTorTransportConfig, TorMode, TorShutdownHandle, TorTransport,
    TorTransportConfig, build_p2p, build_p2p_with_tor, endpoint_record_key, is_onion_address,
    onion_address_matches_node, onion_address_matches_peer, onion_listener_address,
    recover_from_dht, recovery_bundle_key, recovery_mailbox_key, run_coordinator_jobs,
    run_dht_publications, run_peer_exchange, run_port_mapping, run_relay_membership_sync,
    validate_port_mapping_listeners, wait_for_onion_service_shutdown,
};
pub use node::{
    BackupDescriptor, BackupJob, BackupJobState, DhtPublicationSet, DhtSequenceFloors, GuildPeer,
    GuildPhase, GuildSummary, LockedDataDir, Node, RecoveredShards, SnapshotInfo,
};
pub use snapshot::{
    PrivateDataExtent, PrivateEntry, PrivateMetadata, restore_revision,
    restore_revision_from_source,
};
pub use watcher::run_root_watcher;
pub use wire::{WireError, WireErrorCode};
