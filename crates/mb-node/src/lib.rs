//! Active node state machine and transport-independent protocol services.

mod control;
mod lab;
mod network;
mod node;
mod snapshot;
mod watcher;

pub use control::{
    LocalRequest, LocalResponse, NodeStatus, ProtectedRoot, local_control_call, serve_local_control,
};
pub use lab::{MemoryDirectory, MemoryNetwork, PrototypeGuild};
pub use mb_core::{KeyMaterial, NodeId, Seed};
pub use network::{
    DhtRecord, DhtRecoveryResult, DirectoryState, NetworkCommitResult, NetworkMemberRecovery,
    NodeServerConfig, P2pClient, P2pConfig, P2pEventLoop, P2pPeerProfile, P2pStatus, build_p2p,
    commit_source_over_network, commit_source_over_network_with_intent, endpoint_record_key,
    recover_from_dht, recover_guild_over_network, recover_member_and_republish_over_network,
    recover_member_over_network, recover_over_network, recovery_bundle_key, recovery_mailbox_key,
    run_coordinator_jobs, run_dht_publications, serve_directory, serve_node,
};
pub use node::{
    BackupDescriptor, BackupJob, BackupJobState, DhtPublicationSet, GuildPeer, GuildPhase,
    GuildSummary, Node, RecoveredShards, SnapshotInfo,
};
pub use snapshot::{
    PrivateDataExtent, PrivateEntry, PrivateMetadata, restore_revision,
    restore_revision_from_source,
};
pub use watcher::run_root_watcher;
