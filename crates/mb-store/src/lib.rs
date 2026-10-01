//! SQLCipher persistence and source-anchor backends.
//!
//! APIs in this crate are synchronous by design. Node orchestration calls them
//! through bounded blocking workers rather than holding database state across
//! `.await` points.

mod anchor;
mod database;
mod source;

pub use anchor::{
    AnchorAreaLocator, AnchorError, AnchorFileLocator, AnchorManifest, CapturedEntry,
    FileAnchorManifest, FileExtent, FilesystemIdentity, NativeFileId, PinnedDirectory,
    ReflinkAnchor, ReflinkCapturePlan, ReflinkFileCapturePlan, StableAnchorAreaLocator,
    StableAnchorFileLocator, StableAnchorManifest, directory_identity, filesystem_identity,
    probe_reflink, remove_owned_directory_tree,
};
pub use database::{
    CheckpointRow, ControlStore, DatabaseError, DatabaseShellResult, ObjectAttemptState,
    ParityObject, ParityScrubReport, ParityStore, ProtocolRecordRow, VariableParityObject,
};
pub use source::{SourceCapturePlan, SourceFileCapturePlan};

pub const SCHEMA_VERSION: u32 = 9;
