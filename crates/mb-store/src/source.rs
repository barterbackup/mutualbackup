//! Versioned, durable dispatch for local source capture.
//!
//! The node persists a plan before touching source files. Keep existing enum
//! variants stable: a pending capture must remain replayable after an upgrade.
//! Backends return the same stable anchor manifest consumed by sector encoding;
//! no backend identifier enters signed peer records.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    AnchorError, FileAnchorManifest, ReflinkAnchor, ReflinkCapturePlan, ReflinkFileCapturePlan,
    StableAnchorManifest,
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
