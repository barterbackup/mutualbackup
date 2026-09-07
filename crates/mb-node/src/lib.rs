//! Active node state machine and transport-independent protocol services.

mod control;
#[cfg(test)]
mod lab;
mod network;
mod node;
mod snapshot;
mod watcher;

pub use control::{
    LocalControlConnection, LocalControlListener, LocalRequest, LocalResponse, NodeStatus,
    ProtectedRoot, UnlockSecret, bind_local_control, local_control_call, serve_local_control,
    serve_local_control_on,
};
pub use mb_core::{KeyMaterial, NodeId, Seed};
pub use network::{
    DhtRecord, DhtRecoveryResult, P2pClient, P2pConfig, P2pEventLoop, P2pPath, P2pPeerProfile,
    P2pPeerStatus, P2pStatus, build_p2p, endpoint_record_key, recover_from_dht,
    recovery_bundle_key, recovery_mailbox_key, run_coordinator_jobs, run_dht_publications,
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
