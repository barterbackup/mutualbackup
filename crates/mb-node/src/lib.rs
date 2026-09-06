//! Active node state machine and transport-independent protocol services.

mod control;
mod lab;
mod network;
mod node;
mod snapshot;

pub use control::{
    LocalRequest, LocalResponse, NodeStatus, ProtectedRoot, local_control_call, serve_local_control,
};
pub use lab::{MemoryDirectory, MemoryNetwork, PrototypeGuild};
pub use mb_core::{KeyMaterial, NodeId, Seed};
pub use network::{
    DhtRecord, DirectoryState, NetworkCommitResult, NetworkMemberRecovery, NodeServerConfig,
    P2pClient, P2pConfig, P2pEventLoop, P2pPeerProfile, P2pStatus, build_p2p,
    commit_source_over_network, commit_source_over_network_with_intent, recover_guild_over_network,
    recover_member_and_republish_over_network, recover_member_over_network, recover_over_network,
    serve_directory, serve_node,
};
pub use node::{GuildPeer, GuildPhase, GuildSummary, Node, RecoveredShards};
pub use snapshot::{
    PrivateDataExtent, PrivateEntry, PrivateMetadata, restore_revision,
    restore_revision_from_source,
};
