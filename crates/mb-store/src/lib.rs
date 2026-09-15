//! SQLCipher persistence and source-anchor backends.
//!
//! APIs in this crate are synchronous by design. Node orchestration calls them
//! through bounded blocking workers rather than holding database state across
//! `.await` points.

mod anchor;
mod database;

pub use anchor::{
    AnchorAreaLocator, AnchorError, AnchorFileLocator, AnchorManifest, CapturedEntry, FileExtent,
    FilesystemIdentity, NativeFileId, PinnedDirectory, ReflinkAnchor, ReflinkCapturePlan,
    StableAnchorAreaLocator, StableAnchorFileLocator, StableAnchorManifest, directory_identity,
    filesystem_identity, probe_reflink, remove_owned_directory_tree,
};
pub use database::{
    CheckpointRow, ControlStore, DatabaseError, DatabaseShellResult, ParityObject,
    ParityScrubReport, ParityStore, ProtocolRecordRow, VariableParityObject,
};

pub const SCHEMA_VERSION: u32 = 8;
