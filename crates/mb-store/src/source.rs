//! Versioned, durable dispatch for local source capture.
//!
//! The node persists a plan before touching source files. Keep existing enum
//! variants stable: a pending capture must remain replayable after an upgrade.
//! Backends return the same stable anchor manifest consumed by sector encoding;
//! no backend identifier enters signed peer records.

use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AnchorError, FileAnchorManifest, ImportedBlobCapturePlan, ReflinkAnchor, ReflinkCapturePlan,
    ReflinkFileCapturePlan, StableAnchorManifest,
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceCapturePlan {
    ReflinkV1(ReflinkCapturePlan),
}

impl SourceCapturePlan {
    pub fn plan_reflink(source_root: impl AsRef<Path>) -> Result<Self, AnchorError> {
        ReflinkAnchor::plan(source_root).map(Self::ReflinkV1)
    }

    pub fn source_root(&self) -> &Path {
        match self {
            Self::ReflinkV1(plan) => plan.source_root(),
        }
    }

    pub fn capture(&self) -> Result<StableAnchorManifest, AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::capture_plan(plan),
        }
    }

    pub fn discard(&self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::discard_capture(plan),
        }
    }

    pub fn reconcile(&self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::reconcile_capture(plan),
        }
    }
}

/// A separate durable operation from whole-root backup capture. Its anchor is
/// pinned by the Git stage/object map, not by a signed source revision.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceFileCapturePlan {
    ReflinkV1(ReflinkFileCapturePlan),
}

impl SourceFileCapturePlan {
    pub fn plan_reflink(
        source_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<Self, AnchorError> {
        ReflinkAnchor::plan_file(source_root, relative_path).map(Self::ReflinkV1)
    }

    pub fn capture(&self) -> Result<FileAnchorManifest, AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::capture_file_plan(plan),
        }
    }

    pub fn source_mode(&self) -> Result<u32, AnchorError> {
        match self {
            Self::ReflinkV1(plan) => plan.source_mode(),
        }
    }

    pub fn source_root(&self) -> &Path {
        match self {
            Self::ReflinkV1(plan) => plan.source_root(),
        }
    }

    pub fn relative_path(&self) -> &Path {
        match self {
            Self::ReflinkV1(plan) => plan.relative_path(),
        }
    }

    pub fn reconcile(&self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::reconcile_file_capture(plan),
        }
    }

    pub fn discard(&self) -> Result<(), AnchorError> {
        match self {
            Self::ReflinkV1(plan) => ReflinkAnchor::discard_file_capture(plan),
        }
    }
}

/// Versioned import of bytes already held by another object store. The
/// producer supplies a bounded stream; the backend writes straight into one
/// immutable native anchor and can replay a completed publication without it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum SourceBlobImportPlan {
    DirectV1(ImportedBlobCapturePlan),
}

impl SourceBlobImportPlan {
    pub fn plan_direct(
        source_root: impl AsRef<Path>,
        logical_len: u64,
    ) -> Result<Self, AnchorError> {
        ImportedBlobCapturePlan::plan(source_root, logical_len).map(Self::DirectV1)
    }

    pub fn source_root(&self) -> &Path {
        match self {
            Self::DirectV1(plan) => plan.source_root(),
        }
    }

    pub fn logical_len(&self) -> u64 {
        match self {
            Self::DirectV1(plan) => plan.logical_len(),
        }
    }

    pub fn anchor_id(&self) -> Uuid {
        match self {
            Self::DirectV1(plan) => plan.anchor_id(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn capture(&self, source: impl Read) -> Result<FileAnchorManifest, AnchorError> {
        match self {
            Self::DirectV1(plan) => plan.capture(source),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn reconcile(&self) -> Result<(), AnchorError> {
        match self {
            Self::DirectV1(plan) => plan.reconcile(),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn discard(&self) -> Result<(), AnchorError> {
        match self {
            Self::DirectV1(plan) => plan.discard(),
        }
    }
}
