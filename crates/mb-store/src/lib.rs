//! SQLCipher persistence and source-anchor backends.
//!
//! APIs in this crate are synchronous by design. Node orchestration calls them
//! through bounded blocking workers rather than holding database state across
//! `.await` points.

mod anchor;
mod database;

pub use anchor::{
    AnchorAreaLocator, AnchorError, AnchorFileLocator, AnchorManifest, CapturedEntry, FileExtent,
    NativeFileId, ReflinkAnchor, ReflinkCapturePlan, StableAnchorAreaLocator,
    StableAnchorFileLocator, StableAnchorManifest, probe_reflink,
};
pub use database::{
    CheckpointRow, ControlStore, DatabaseError, ParityObject, ParityStore, ProtocolRecordRow,
};

pub const SCHEMA_VERSION: u32 = 5;
