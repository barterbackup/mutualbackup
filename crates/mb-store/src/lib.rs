//! SQLCipher persistence and source-anchor backends.
//!
//! APIs in this crate are synchronous by design. Node orchestration calls them
//! through bounded blocking workers rather than holding database state across
//! `.await` points.

mod anchor;
mod database;

pub use anchor::{
    AnchorAreaLocator, AnchorError, AnchorFileLocator, AnchorManifest, CapturedEntry,
    ReflinkAnchor, probe_reflink,
};
pub use database::{CheckpointRow, ControlStore, DatabaseError, ParityObject, ParityStore};

pub const SCHEMA_VERSION: u32 = 3;
