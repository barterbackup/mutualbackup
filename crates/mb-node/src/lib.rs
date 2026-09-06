//! Active node state machine and transport-independent protocol services.

mod lab;
mod network;
mod node;
mod snapshot;

pub use lab::{MemoryDirectory, MemoryNetwork, PrototypeGuild};
pub use mb_core::{KeyMaterial, NodeId, Seed};
pub use network::{
    DirectoryState, NetworkCommitResult, NodeServerConfig, commit_source_over_network,
    recover_over_network, serve_directory, serve_node,
};
pub use node::{Node, RecoveredShards};
pub use snapshot::{PrivateEntry, PrivateMetadata, restore_revision, restore_revision_from_source};
