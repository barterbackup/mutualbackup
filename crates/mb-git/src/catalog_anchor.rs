//! Durable location assistance for native Git reads. Neither a cursor nor a
//! hint changes the serialized manifest or authorizes a Git object identity.
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid};
use mb_store::{AnchorAreaDiscoveryStep, AnchorError, ControlStore, FileAnchorManifest};
use serde::{Deserialize, Serialize};

use crate::GitAnchorError;

const HINT_KIND: &str = "anchor-area-location";
const MAX_PATH: usize = 4_096;
const MAX_HINT: usize = MAX_PATH + 16;

#[derive(Serialize, Deserialize)]
struct RawPath(#[serde(with = "mb_store::raw_path_bytes")] PathBuf);

pub(crate) fn location_record(
    manifest: &FileAnchorManifest,
    path: &Path,
) -> anyhow::Result<(String, Vec<u8>, Vec<u8>)> {
    anyhow::ensure!(
        path.as_os_str().as_encoded_bytes().len() <= MAX_PATH,
        "anchor location exceeds its bound"
    );
    Ok((
        HINT_KIND.to_owned(),
        manifest.area.area_id.as_bytes().to_vec(),
        mb_core::canonical_bytes_bounded(&RawPath(path.to_path_buf()), MAX_HINT)?,
    ))
}

pub(crate) fn hint(
    control: &ControlStore,
    manifest: &FileAnchorManifest,
) -> Result<Option<PathBuf>, GitAnchorError> {
    Ok(control
        .get_record_bounded(HINT_KIND, manifest.area.area_id.as_bytes(), MAX_HINT)?
        .and_then(|bytes| mb_core::decode_canonical::<RawPath>(&bytes).ok())
        .map(|path| path.0)
        .filter(|path| path.as_os_str().as_encoded_bytes().len() <= MAX_PATH))
}

pub(crate) fn open(
    control: &ControlStore,
    manifest: &FileAnchorManifest,
) -> Result<(File, PathBuf), GitAnchorError> {
    // Reject withdrawn ownership before creating any relocation assistance.
    if manifest.guarded_root_file.is_some() {
        return Err(
            AnchorError::UnsupportedSourceOperation(mb_store::WITHDRAWN_GUARDED_BACKEND).into(),
        );
    }
    if manifest.format_version != 1 {
        return Err(AnchorError::InvalidRoot.into());
    }
    let saved = hint(control, manifest)?;
    let resolved = if let Some(path) = manifest.area.known_path(saved.as_deref()) {
        Some(path)
    } else if control.is_read_only()? {
        None
    } else {
        match control.advance_anchor_area_discovery(&manifest.area) {
            Ok(AnchorAreaDiscoveryStep::Found(path)) => Some(path),
            Ok(AnchorAreaDiscoveryStep::Pending) => {
                return Err(AnchorError::AnchorAreaDiscoveryPending.into());
            }
            Ok(AnchorAreaDiscoveryStep::Missing) => {
                return Err(
                    AnchorError::AnchorAreaCollision(manifest.area.path_hint.clone()).into(),
                );
            }
            Err(error) => match error.downcast::<AnchorError>() {
                Ok(AnchorError::UnsupportedSourceOperation(
                    "persistent anchor directory cookies",
                )) => None,
                Ok(error) => return Err(error.into()),
                Err(error) => return Err(GitAnchorError::Discovery(error)),
            },
        }
    };
    Ok(manifest.open_verified_with_area_hint(resolved.as_deref().or(saved.as_deref()))?)
}

pub(crate) fn identify(
    control: &ControlStore,
    manifest: &FileAnchorManifest,
) -> Result<(Oid, PathBuf), GitAnchorError> {
    let (file, path) = open(control, manifest)?;
    let descriptor = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    let oid = Oid::hash_file(ObjectType::Blob, descriptor)?;
    Ok((oid, path))
}

/// Called only after both the manifest content root and the expected Git ID
/// have passed. Complete a leftover job even if its hint was already current.
pub(crate) fn remember(
    control: &ControlStore,
    manifest: &FileAnchorManifest,
    path: &Path,
) -> Result<(), GitAnchorError> {
    if control.is_read_only()? {
        return Ok(());
    }
    if path.as_os_str().as_encoded_bytes().len() > MAX_PATH {
        return Err(AnchorError::AnchorAreaDiscoveryLimit.into());
    }
    if hint(control, manifest)?.as_deref() == Some(path)
        && control
            .get_record_bounded(
                mb_store::ANCHOR_DISCOVERY_JOURNAL_KIND,
                manifest.area.area_id.as_bytes(),
                mb_store::ANCHOR_DISCOVERY_CHECKPOINT_BYTES + 64,
            )?
            .is_none()
    {
        return Ok(());
    }
    let encoded = mb_core::canonical_bytes_bounded(&RawPath(path.to_path_buf()), MAX_HINT)
        .map_err(|error| GitAnchorError::Discovery(error.into()))?;
    control.finish_anchor_area_discovery(manifest.area.area_id, &encoded)?;
    Ok(())
}

/// Keep original cached locations, including unresolved historical relative hints.
pub(crate) fn for_each_preserved_location(
    control: &ControlStore,
    repository_id: uuid::Uuid,
    mut visit: impl FnMut(crate::PreservedGitRecord) -> anyhow::Result<()>,
) -> anyhow::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    control.for_each_record_bounded(HINT_KIND, 16, MAX_HINT, |key, bytes| {
        let area_id = uuid::Uuid::from_slice(key)?;
        let path: RawPath = mb_core::decode_canonical(bytes)?;
        anyhow::ensure!(
            !area_id.is_nil()
                && !path.0.as_os_str().is_empty()
                && path.0.as_os_str().as_bytes().len() <= MAX_PATH
                && !path.0.as_os_str().as_bytes().contains(&0)
                && mb_core::canonical_bytes_bounded(&path, bytes.len())? == bytes,
            "invalid preserved Git anchor area location"
        );
        visit(crate::PreservedGitRecord::AnchorAreaLocation {
            repository_id,
            area_id,
            path: path.0,
        })?;
        Ok(true)
    })?;
    Ok(())
}
