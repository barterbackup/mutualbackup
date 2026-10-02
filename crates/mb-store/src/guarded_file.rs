//! Durable single-file capture into the stable anchor area. Root enrollment
//! remains separate: a backend must also publish a whole-root manifest and
//! recover all its file intents before it can protect a root.

use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    AnchorError, CaptureVersion, FileAnchorManifest, NativeFileId, PinnedDirectory,
    StableAnchorAreaLocator, capture_manifest_name, capture_version, filesystem_identity_for_file,
    open_source_beneath, open_source_root, open_stable_anchor_area, probe_guarded_link_freeze,
    resolve_anchor_area, unix_mode, validate_relative,
};
use crate::{ControlStore, LinkFreezeCaptureIntent, LinkFreezeCapturePhase};

const PLAN_KIND: &str = "guarded-file-plan-v1";
const DIRECTORY_CLAIM_KIND: &str = "guarded-file-directory-v1";
const MANIFEST_CLAIM_KIND: &str = "guarded-file-manifest-v1";
const RETIRE_KIND: &str = "guarded-file-retire-v1";
const MARKER_PREFIX: &str = ".mutualbackup-guarded-file-v1-";
const PAYLOAD_NAME: &str = "blob";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DirectoryClaim {
    format_version: u16,
    anchor_id: Uuid,
    directory_id: NativeFileId,
    plan_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct ManifestClaim {
    format_version: u16,
    anchor_id: Uuid,
    directory_id: NativeFileId,
    plan_hash: [u8; 32],
    manifest_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FileRetirement {
    format_version: u16,
    anchor_id: Uuid,
    plan_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedFileCapturePlan {
    format_version: u16,
    anchor_id: Uuid,
    source_root: PathBuf,
    source_root_id: NativeFileId,
    relative_path: PathBuf,
    source_version: CaptureVersion,
    source_mode: u32,
    area: StableAnchorAreaLocator,
}

impl GuardedFileCapturePlan {
    pub fn plan(
        source_root: impl AsRef<Path>,
        relative_path: impl AsRef<Path>,
    ) -> Result<Self, AnchorError> {
        let relative_path = relative_path.as_ref();
        validate_relative(relative_path)?;
        let source_root = source_root
            .as_ref()
            .canonicalize()
            .map_err(|_| AnchorError::InvalidRoot)?;
        probe_guarded_link_freeze(&source_root)?;
        let root = open_source_root(&source_root)?;
        let root_filesystem = filesystem_identity_for_file(&root)?;
        let root_metadata = root.metadata()?;
        let source = open_source_beneath(&root, relative_path, false)?;
        let source_filesystem = filesystem_identity_for_file(&source)?;
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 || source_filesystem != root_filesystem {
            return Err(AnchorError::SourceChanged(relative_path.to_path_buf()));
        }
        let area = StableAnchorAreaLocator::prepare_for_root(&source_root)?;
        if area.filesystem_id != root_filesystem.stable_id {
            return Err(AnchorError::FilesystemChanged);
        }
        Ok(Self {
            format_version: 1,
            anchor_id: Uuid::new_v4(),
            source_root,
            source_root_id: NativeFileId {
                filesystem_id: root_filesystem.stable_id,
                inode: root_metadata.ino(),
            },
            relative_path: relative_path.to_path_buf(),
            source_version: capture_version(root_filesystem.stable_id, &metadata),
            source_mode: unix_mode(&metadata),
            area,
        })
    }

    pub fn anchor_id(&self) -> Uuid {
        self.anchor_id
    }

    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    pub fn relative_path(&self) -> &Path {
        &self.relative_path
    }

    pub fn source_mode(&self) -> u32 {
        self.source_mode
    }

    /// Persist plan ownership before creating an anchor directory, then use
    /// the per-file freeze journal to make its payload durable. The manifest
    /// appears only after journal replay proves the anchor's exact bytes.
    pub fn capture(&self, control: &ControlStore) -> anyhow::Result<FileAnchorManifest> {
        anyhow::ensure!(self.format_version == 1 && !self.anchor_id.is_nil());
        anyhow::ensure!(
            control
                .get_record(RETIRE_KIND, self.anchor_id.as_bytes())?
                .is_none()
                && !LinkFreezeCaptureIntent::retirement_pending(control, self.anchor_id)?,
            "guarded file anchor is being retired"
        );
        validate_relative(&self.relative_path)?;
        let encoded_plan = mb_core::canonical_bytes(self)?;
        let plan_hash = *blake3::hash(&encoded_plan).as_bytes();
        let new_plan =
            control.put_record_if_absent(PLAN_KIND, self.anchor_id.as_bytes(), &encoded_plan)?;
        if !new_plan {
            anyhow::ensure!(
                control.get_record(PLAN_KIND, self.anchor_id.as_bytes())? == Some(encoded_plan),
                "guarded file anchor belongs to another source plan"
            );
        }
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let anchor_parent = self.prepare_anchor_directory(control, &area, plan_hash, new_plan)?;
        let source_parent = match self.open_source_parent() {
            Ok(parent) => parent,
            Err(error) => {
                let pending = LinkFreezeCaptureIntent::load(control, self.anchor_id)?;
                if pending
                    .as_ref()
                    .is_some_and(|intent| intent.phase() != LinkFreezeCapturePhase::Prepared)
                {
                    anchor_parent.try_clone()?
                } else {
                    return Err(error.into());
                }
            }
        };
        let source_name = self
            .relative_path
            .file_name()
            .ok_or(AnchorError::UnsafePath)?;
        let expected_source = NativeFileId {
            filesystem_id: self.source_version.filesystem_id,
            inode: self.source_version.inode,
        };
        let recorded = LinkFreezeCaptureIntent::load(control, self.anchor_id)?;
        if recorded.is_none() {
            anyhow::ensure!(
                anchor_parent.entry_identity(PAYLOAD_NAME, false)?.is_none()
                    && anchor_parent
                        .entry_identity(capture_manifest_name(self.anchor_id), false)?
                        .is_none(),
                "unowned guarded payload or manifest blocks first freeze"
            );
        }
        let intent = match recorded {
            Some(intent) => intent,
            None => LinkFreezeCaptureIntent::begin_checked(
                control,
                self.anchor_id,
                &source_parent,
                source_name,
                &anchor_parent,
                PAYLOAD_NAME,
                &self.source_version,
            )?,
        };
        anyhow::ensure!(intent.matches_file_plan(
            self.anchor_id,
            expected_source,
            &anchor_parent,
            Path::new(PAYLOAD_NAME),
        )?);
        let verified = intent
            .resume(control, &source_parent, &anchor_parent)?
            .ok_or_else(|| anyhow::anyhow!("planned source changed before guarded freeze"))?;
        anyhow::ensure!(matches!(
            verified.phase(),
            LinkFreezeCapturePhase::Frozen | LinkFreezeCapturePhase::Detached
        ));
        let content = verified.content_proof();
        let manifest = FileAnchorManifest {
            format_version: 1,
            anchor_id: self.anchor_id,
            area: self.area.clone(),
            source_root_hint: self.source_root.clone(),
            source_relative_path: self.relative_path.clone(),
            logical_len: content.logical_len,
            content_hash: content.content_hash,
            source_version: self.source_version.clone(),
        };
        let manifest_name = capture_manifest_name(self.anchor_id);
        let manifest_bytes = mb_core::canonical_bytes(&manifest)?;
        let claim = ManifestClaim {
            format_version: 1,
            anchor_id: self.anchor_id,
            directory_id: anchor_parent.identity()?,
            plan_hash,
            manifest_hash: *blake3::hash(&manifest_bytes).as_bytes(),
        };
        let claim_bytes = mb_core::canonical_bytes(&claim)?;
        let recorded_claim = control.get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?;
        if let Some(bytes) = recorded_claim.as_ref() {
            anyhow::ensure!(bytes == &claim_bytes, "guarded file manifest claim changed");
        }
        match anchor_parent.open_child_file(&manifest_name)? {
            Some(mut file) => {
                let metadata = file.metadata()?;
                let identity = NativeFileId {
                    filesystem_id: self.area.filesystem_id,
                    inode: metadata.ino(),
                };
                anyhow::ensure!(
                    metadata.len() == manifest_bytes.len() as u64
                        && metadata.nlink() == 1
                        && unix_mode(&metadata) & 0o222 == 0,
                    "guarded manifest metadata changed"
                );
                let mut existing_bytes = Vec::new();
                file.read_to_end(&mut existing_bytes)?;
                anyhow::ensure!(
                    existing_bytes == manifest_bytes
                        && anchor_parent.entry_identity(&manifest_name, false)? == Some(identity),
                    "guarded manifest changed"
                );
            }
            None => {
                anyhow::ensure!(
                    recorded_claim.is_none(),
                    "claimed guarded file manifest disappeared"
                );
                anchor_parent.publish_sealed_bytes_child(&manifest_name, &manifest_bytes)?;
            }
        }
        anchor_parent.sync_all()?;
        area.sync_all()?;
        manifest.open_verified()?;
        if recorded_claim.is_none() {
            anyhow::ensure!(control.put_record_if_absent(
                MANIFEST_CLAIM_KIND,
                self.anchor_id.as_bytes(),
                &claim_bytes,
            )?);
        }
        Ok(manifest)
    }

    fn marker_name(&self) -> String {
        format!("{MARKER_PREFIX}{}", self.anchor_id)
    }

    fn marker_bytes(&self, plan_hash: [u8; 32]) -> Vec<u8> {
        format!(
            "mutualbackup-guarded-file-v1\n{}\n{}\n",
            self.anchor_id,
            blake3::Hash::from(plan_hash)
        )
        .into_bytes()
    }

    fn verified_marker(
        &self,
        area: &PinnedDirectory,
        plan_hash: [u8; 32],
    ) -> anyhow::Result<Option<NativeFileId>> {
        let name = self.marker_name();
        let Some(mut marker) = area.open_child_file(&name)? else {
            return Ok(None);
        };
        let expected = self.marker_bytes(plan_hash);
        let metadata = marker.metadata()?;
        let identity = NativeFileId {
            filesystem_id: self.area.filesystem_id,
            inode: metadata.ino(),
        };
        anyhow::ensure!(
            metadata.len() == expected.len() as u64
                && metadata.nlink() == 1
                && unix_mode(&metadata) & 0o222 == 0,
            "guarded file ownership marker changed"
        );
        let mut actual = Vec::new();
        marker.read_to_end(&mut actual)?;
        anyhow::ensure!(
            actual == expected && area.entry_identity(&name, false)? == Some(identity),
            "guarded file ownership marker changed"
        );
        Ok(Some(identity))
    }

    fn prepare_anchor_directory(
        &self,
        control: &ControlStore,
        area: &PinnedDirectory,
        plan_hash: [u8; 32],
        new_plan: bool,
    ) -> anyhow::Result<PinnedDirectory> {
        let name = self.anchor_id.to_string();
        let claim_bytes = control.get_record(DIRECTORY_CLAIM_KIND, self.anchor_id.as_bytes())?;
        if new_plan {
            anyhow::ensure!(
                claim_bytes.is_none()
                    && area.entry_identity(&name, true)?.is_none()
                    && area.entry_identity(self.marker_name(), false)?.is_none(),
                "unowned guarded file anchor namespace collides with a new plan"
            );
        }
        if self.verified_marker(area, plan_hash)?.is_none() {
            anyhow::ensure!(
                claim_bytes.is_none() && area.entry_identity(&name, true)?.is_none(),
                "guarded file directory exists without its ownership marker"
            );
            area.publish_sealed_bytes_child(self.marker_name(), &self.marker_bytes(plan_hash))?;
        }
        if let Some(bytes) = claim_bytes {
            let claim: DirectoryClaim = mb_core::decode_canonical(&bytes)?;
            let directory = area
                .open_child_directory(&name)?
                .ok_or_else(|| anyhow::anyhow!("claimed guarded file directory is missing"))?;
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == self.anchor_id
                    && claim.plan_hash == plan_hash
                    && claim.directory_id.filesystem_id == self.area.filesystem_id
                    && directory.identity()? == claim.directory_id
                    && unix_mode(&directory.as_file().metadata()?) & 0o777 == 0o700,
                "guarded file directory differs from its durable claim"
            );
            return Ok(directory);
        }
        // Publication of a file journal starts only after the claim. An
        // unclaimed directory from a crash may therefore contain no children.
        if let Some(unclaimed) = area.entry_identity(&name, true)? {
            anyhow::ensure!(
                area.remove_empty_child_directory(&name, unclaimed)?,
                "unclaimed guarded file directory contains unknown entries"
            );
        }
        let directory = area.create_child_directory(&name)?;
        area.sync_all()?;
        let claim = DirectoryClaim {
            format_version: 1,
            anchor_id: self.anchor_id,
            directory_id: directory.identity()?,
            plan_hash,
        };
        anyhow::ensure!(control.put_record_if_absent(
            DIRECTORY_CLAIM_KIND,
            self.anchor_id.as_bytes(),
            &mb_core::canonical_bytes(&claim)?,
        )?);
        Ok(directory)
    }

    fn verified_manifest_for_retirement(
        &self,
        directory: Option<&PinnedDirectory>,
        claim: Option<&ManifestClaim>,
        allow_missing: bool,
    ) -> anyhow::Result<Option<NativeFileId>> {
        let name = capture_manifest_name(self.anchor_id);
        let present = directory
            .map(|directory| directory.entry_identity(&name, false))
            .transpose()?
            .flatten();
        let Some(claim) = claim else {
            anyhow::ensure!(
                present.is_none(),
                "unclaimed guarded file manifest blocks retirement"
            );
            return Ok(None);
        };
        let Some(identity) = present else {
            anyhow::ensure!(allow_missing, "claimed guarded file manifest disappeared");
            return Ok(None);
        };
        let directory =
            directory.ok_or_else(|| anyhow::anyhow!("guarded file directory vanished"))?;
        let mut file = directory
            .open_child_file(&name)?
            .ok_or_else(|| anyhow::anyhow!("guarded file manifest vanished"))?;
        let metadata = file.metadata()?;
        anyhow::ensure!(
            metadata.len() <= 64 * 1024
                && metadata.nlink() == 1
                && unix_mode(&metadata) & 0o222 == 0,
            "guarded file manifest metadata changed"
        );
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        anyhow::ensure!(
            *blake3::hash(&bytes).as_bytes() == claim.manifest_hash
                && directory.entry_identity(&name, false)? == Some(identity),
            "guarded file manifest bytes changed"
        );
        let manifest: FileAnchorManifest = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            manifest.format_version == 1
                && manifest.anchor_id == self.anchor_id
                && manifest.area == self.area
                && manifest.source_root_hint == self.source_root
                && manifest.source_relative_path == self.relative_path
                && manifest.source_version == self.source_version,
            "guarded file manifest differs from its source plan"
        );
        Ok(Some(identity))
    }

    /// The owner must prove this anchor is unreferenced before calling this
    /// method. Keep the plan record until source access and namespace cleanup
    /// both finish, so a crash can replay the same retirement.
    pub fn discard_unreferenced(&self, control: &ControlStore) -> anyhow::Result<()> {
        anyhow::ensure!(self.format_version == 1 && !self.anchor_id.is_nil());
        let plan_bytes = mb_core::canonical_bytes(self)?;
        let plan_hash = *blake3::hash(&plan_bytes).as_bytes();
        let recorded_plan = control.get_record(PLAN_KIND, self.anchor_id.as_bytes())?;
        let area_path = resolve_anchor_area(&self.area)?;
        let area_file = open_stable_anchor_area(&area_path, &self.area)?;
        let area = PinnedDirectory {
            file: area_file,
            filesystem_id: self.area.filesystem_id,
        };
        let directory_name = self.anchor_id.to_string();
        let anchor_parent = area.open_child_directory(&directory_name)?;
        let claim_bytes = control.get_record(DIRECTORY_CLAIM_KIND, self.anchor_id.as_bytes())?;
        let manifest_claim_bytes =
            control.get_record(MANIFEST_CLAIM_KIND, self.anchor_id.as_bytes())?;
        let marker_id = self.verified_marker(&area, plan_hash)?;
        let retirement = FileRetirement {
            format_version: 1,
            anchor_id: self.anchor_id,
            plan_hash,
        };
        let retirement_bytes = mb_core::canonical_bytes(&retirement)?;
        let prior_retirement = control.get_record(RETIRE_KIND, self.anchor_id.as_bytes())?;
        anyhow::ensure!(
            prior_retirement
                .as_ref()
                .is_none_or(|bytes| bytes == &retirement_bytes),
            "guarded file retirement belongs to another plan"
        );
        if recorded_plan.is_none() {
            anyhow::ensure!(
                anchor_parent.is_none()
                    && claim_bytes.is_none()
                    && manifest_claim_bytes.is_none()
                    && marker_id.is_none()
                    && LinkFreezeCaptureIntent::load(control, self.anchor_id)?.is_none(),
                "unowned guarded file namespace or capture remains after retirement"
            );
            LinkFreezeCaptureIntent::finish_completed_retirement(control, self.anchor_id)?;
            if prior_retirement.is_some() {
                control.delete_record_if_value(
                    RETIRE_KIND,
                    self.anchor_id.as_bytes(),
                    &retirement_bytes,
                )?;
            }
            return Ok(());
        }
        anyhow::ensure!(recorded_plan.as_ref() == Some(&plan_bytes));
        let claim = claim_bytes
            .as_deref()
            .map(mb_core::decode_canonical::<DirectoryClaim>)
            .transpose()?;
        let manifest_claim = manifest_claim_bytes
            .as_deref()
            .map(mb_core::decode_canonical::<ManifestClaim>)
            .transpose()?;
        let present_id = anchor_parent
            .as_ref()
            .map(PinnedDirectory::identity)
            .transpose()?;
        let directory_mode = anchor_parent
            .as_ref()
            .map(|directory| {
                directory
                    .as_file()
                    .metadata()
                    .map(|metadata| unix_mode(&metadata))
            })
            .transpose()?;
        if let Some(claim) = claim.as_ref() {
            anyhow::ensure!(
                claim.format_version == 1
                    && claim.anchor_id == self.anchor_id
                    && claim.plan_hash == plan_hash
                    && claim.directory_id.filesystem_id == self.area.filesystem_id
                    && present_id.is_none_or(|present| present == claim.directory_id)
                    && directory_mode.is_none_or(|mode| mode & 0o777 == 0o700),
                "guarded file directory differs from its durable claim"
            );
        }
        if let Some(manifest_claim) = manifest_claim.as_ref() {
            anyhow::ensure!(
                manifest_claim.format_version == 1
                    && manifest_claim.anchor_id == self.anchor_id
                    && manifest_claim.plan_hash == plan_hash
                    && claim.as_ref().is_some_and(|directory| {
                        directory.directory_id == manifest_claim.directory_id
                    }),
                "guarded file manifest claim differs from its directory plan"
            );
            anyhow::ensure!(
                LinkFreezeCaptureIntent::load(control, self.anchor_id)?.is_some()
                    || LinkFreezeCaptureIntent::retirement_pending(control, self.anchor_id)?,
                "claimed guarded file manifest lacks its freeze or retirement journal"
            );
        }
        anyhow::ensure!(
            marker_id.is_some() || (anchor_parent.is_none() && claim.is_none()),
            "guarded file ownership marker disappeared before retirement"
        );
        anyhow::ensure!(
            anchor_parent.is_some() || claim.is_none() || prior_retirement.is_some(),
            "claimed guarded file directory disappeared before retirement began"
        );
        anyhow::ensure!(
            claim.is_some() || LinkFreezeCaptureIntent::load(control, self.anchor_id)?.is_none(),
            "unjournaled guarded file directory has a capture"
        );
        self.verified_manifest_for_retirement(
            anchor_parent.as_ref(),
            manifest_claim.as_ref(),
            prior_retirement.is_some(),
        )?;
        if prior_retirement.is_none() {
            anyhow::ensure!(control.put_record_if_absent(
                RETIRE_KIND,
                self.anchor_id.as_bytes(),
                &retirement_bytes,
            )?);
        }
        if let (Some(anchor_parent), Some(_)) = (anchor_parent.as_ref(), claim.as_ref()) {
            let source_parent = self
                .open_source_parent()
                .unwrap_or(anchor_parent.try_clone()?);
            if let Some(capture) = LinkFreezeCaptureIntent::load(control, self.anchor_id)? {
                let capture = if capture.phase() == LinkFreezeCapturePhase::Prepared {
                    capture.resume(control, &source_parent, anchor_parent)?
                } else {
                    Some(capture)
                };
                if let Some(capture) = capture {
                    capture.retire_unreferenced(control, &source_parent, anchor_parent)?;
                }
            }
            anyhow::ensure!(
                LinkFreezeCaptureIntent::retirement_ready_for_cleanup(control, self.anchor_id)?
                    && LinkFreezeCaptureIntent::load(control, self.anchor_id)?.is_none()
                    && anchor_parent.entry_identity(PAYLOAD_NAME, false)?.is_none(),
                "guarded anchor still has a live capture or payload"
            );
            if let Some(manifest_id) = self.verified_manifest_for_retirement(
                Some(anchor_parent),
                manifest_claim.as_ref(),
                true,
            )? {
                anchor_parent.remove_child_file_if_identity(
                    capture_manifest_name(self.anchor_id),
                    manifest_id,
                )?;
            }
            anyhow::ensure!(
                area.remove_empty_child_directory(&directory_name, anchor_parent.identity()?)?,
                "guarded anchor directory has unknown remaining entries"
            );
        } else if let Some(unclaimed) = present_id {
            anyhow::ensure!(
                LinkFreezeCaptureIntent::retirement_ready_for_cleanup(control, self.anchor_id)?,
                "unclaimed guarded file directory has an unfinished retirement"
            );
            anyhow::ensure!(
                area.remove_empty_child_directory(&directory_name, unclaimed)?,
                "unclaimed guarded file directory has unknown entries"
            );
        } else {
            anyhow::ensure!(
                LinkFreezeCaptureIntent::load(control, self.anchor_id)?.is_none(),
                "missing guarded anchor directory has a live capture"
            );
            anyhow::ensure!(
                LinkFreezeCaptureIntent::retirement_ready_for_cleanup(control, self.anchor_id)?,
                "guarded retirement has not restored source access"
            );
        }
        if let Some(bytes) = manifest_claim_bytes {
            control.delete_record_if_value(
                MANIFEST_CLAIM_KIND,
                self.anchor_id.as_bytes(),
                &bytes,
            )?;
        }
        if let Some(bytes) = claim_bytes {
            control.delete_record_if_value(
                DIRECTORY_CLAIM_KIND,
                self.anchor_id.as_bytes(),
                &bytes,
            )?;
        }
        if let Some(marker_id) = marker_id {
            area.remove_child_file_if_identity(self.marker_name(), marker_id)?;
        }
        area.sync_all()?;
        control.delete_record_if_value(PLAN_KIND, self.anchor_id.as_bytes(), &plan_bytes)?;
        LinkFreezeCaptureIntent::finish_completed_retirement(control, self.anchor_id)?;
        control.delete_record_if_value(
            RETIRE_KIND,
            self.anchor_id.as_bytes(),
            &retirement_bytes,
        )?;
        Ok(())
    }

    fn open_source_parent(&self) -> Result<PinnedDirectory, AnchorError> {
        let root = PinnedDirectory::open(&self.source_root)?;
        if root.identity()? != self.source_root_id {
            return Err(AnchorError::SourceChanged(PathBuf::new()));
        }
        let mut parent = root;
        for component in self
            .relative_path
            .parent()
            .ok_or(AnchorError::UnsafePath)?
            .components()
        {
            let Component::Normal(name) = component else {
                return Err(AnchorError::UnsafePath);
            };
            parent = parent
                .open_child_directory(Path::new(name))?
                .ok_or_else(|| AnchorError::SourceChanged(self.relative_path.clone()))?;
        }
        Ok(parent)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use mb_core::{KeyMaterial, Seed};

    use super::*;
    use crate::{ControlStore, LinkFreezeCaptureIntent, LinkFreezeCapturePhase, PinnedDirectory};

    fn planned_without_privileged_probe(root: &Path) -> GuardedFileCapturePlan {
        let root = root.canonicalize().unwrap();
        let root_file = open_source_root(&root).unwrap();
        let filesystem = filesystem_identity_for_file(&root_file).unwrap();
        let file = open_source_beneath(&root_file, Path::new("source"), false).unwrap();
        let metadata = file.metadata().unwrap();
        GuardedFileCapturePlan {
            format_version: 1,
            anchor_id: Uuid::new_v4(),
            source_root: root.clone(),
            source_root_id: NativeFileId {
                filesystem_id: filesystem.stable_id,
                inode: root_file.metadata().unwrap().ino(),
            },
            relative_path: PathBuf::from("source"),
            source_version: capture_version(filesystem.stable_id, &metadata),
            source_mode: unix_mode(&metadata),
            area: StableAnchorAreaLocator::prepare_for_root(&root).unwrap(),
        }
    }

    fn claimed_test_directory(
        plan: &GuardedFileCapturePlan,
        control: &ControlStore,
    ) -> (PinnedDirectory, [u8; 32], NativeFileId) {
        let bytes = mb_core::canonical_bytes(plan).unwrap();
        assert!(
            control
                .put_record_if_absent(PLAN_KIND, plan.anchor_id.as_bytes(), &bytes)
                .unwrap()
        );
        let hash = *blake3::hash(&bytes).as_bytes();
        let area_path = resolve_anchor_area(&plan.area).unwrap();
        let area = PinnedDirectory {
            file: open_stable_anchor_area(&area_path, &plan.area).unwrap(),
            filesystem_id: plan.area.filesystem_id,
        };
        let directory = plan
            .prepare_anchor_directory(control, &area, hash, true)
            .unwrap();
        let identity = directory.identity().unwrap();
        assert_eq!(
            plan.prepare_anchor_directory(control, &area, hash, false)
                .unwrap()
                .identity()
                .unwrap(),
            identity
        );
        (area, hash, identity)
    }

    fn mock_manifest(plan: &GuardedFileCapturePlan) -> FileAnchorManifest {
        FileAnchorManifest {
            format_version: 1,
            anchor_id: plan.anchor_id,
            area: plan.area.clone(),
            source_root_hint: plan.source_root.clone(),
            source_relative_path: plan.relative_path.clone(),
            logical_len: 9,
            content_hash: [42; 32],
            source_version: plan.source_version.clone(),
        }
    }

    #[test]
    fn guarded_file_manifest_claim_detects_replacement_and_loss() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source"), b"raw bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([121; 32]));
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (area, plan_hash, directory_id) = claimed_test_directory(&plan, &control);
        let directory = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        let bytes = mb_core::canonical_bytes(&mock_manifest(&plan)).unwrap();
        let claim = ManifestClaim {
            format_version: 1,
            anchor_id: plan.anchor_id,
            directory_id,
            plan_hash,
            manifest_hash: *blake3::hash(&bytes).as_bytes(),
        };
        let name = capture_manifest_name(plan.anchor_id);
        let first = directory.publish_sealed_bytes_child(&name, &bytes).unwrap();
        assert_eq!(
            plan.verified_manifest_for_retirement(Some(&directory), Some(&claim), false)
                .unwrap(),
            Some(first)
        );
        directory
            .remove_child_file_if_identity(&name, first)
            .unwrap();
        let mut altered = bytes.clone();
        altered[0] ^= 1;
        let changed = directory
            .publish_sealed_bytes_child(&name, &altered)
            .unwrap();
        assert!(
            plan.verified_manifest_for_retirement(Some(&directory), Some(&claim), false)
                .is_err()
        );
        directory
            .remove_child_file_if_identity(&name, changed)
            .unwrap();
        assert!(
            plan.verified_manifest_for_retirement(Some(&directory), Some(&claim), false)
                .is_err()
        );
        assert_eq!(
            plan.verified_manifest_for_retirement(Some(&directory), Some(&claim), true)
                .unwrap(),
            None
        );
    }

    #[test]
    fn unclaimed_guarded_file_manifest_blocks_retirement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source"), b"raw bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([122; 32]));
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (area, _, _) = claimed_test_directory(&plan, &control);
        let directory = area
            .open_child_directory(plan.anchor_id.to_string())
            .unwrap()
            .unwrap();
        let name = capture_manifest_name(plan.anchor_id);
        let bytes = mb_core::canonical_bytes(&mock_manifest(&plan)).unwrap();
        let identity = directory.publish_sealed_bytes_child(&name, &bytes).unwrap();
        assert!(plan.discard_unreferenced(&control).is_err());
        assert!(
            control
                .get_record(RETIRE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            directory.entry_identity(&name, false).unwrap(),
            Some(identity)
        );
        directory
            .remove_child_file_if_identity(&name, identity)
            .unwrap();
        plan.discard_unreferenced(&control).unwrap();
    }

    #[test]
    fn guarded_file_directory_claim_rejects_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source"), b"raw bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([118; 32]));
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (area, hash, identity) = claimed_test_directory(&plan, &control);
        let name = plan.anchor_id.to_string();
        fs::rename(
            plan.area.path_hint.join(&name),
            plan.area.path_hint.join("moved"),
        )
        .unwrap();
        fs::create_dir(plan.area.path_hint.join(&name)).unwrap();
        assert_ne!(area.entry_identity(&name, true).unwrap(), Some(identity));
        assert!(
            plan.prepare_anchor_directory(&control, &area, hash, false)
                .is_err()
        );
        assert!(plan.discard_unreferenced(&control).is_err());
    }

    #[test]
    fn guarded_file_directory_claim_requires_its_marker() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source"), b"raw bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([120; 32]));
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (area, hash, _) = claimed_test_directory(&plan, &control);
        let marker = plan.marker_name();
        let identity = area.entry_identity(&marker, false).unwrap().unwrap();
        area.remove_child_file_if_identity(&marker, identity)
            .unwrap();
        assert!(
            plan.prepare_anchor_directory(&control, &area, hash, false)
                .is_err()
        );
        assert!(plan.discard_unreferenced(&control).is_err());
        assert!(
            area.entry_identity(plan.anchor_id.to_string(), true)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn guarded_file_directory_claim_replays_empty_creation_and_retirement() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("source"), b"raw bytes").unwrap();
        let plan = planned_without_privileged_probe(&root);
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([119; 32]));
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let bytes = mb_core::canonical_bytes(&plan).unwrap();
        assert!(
            control
                .put_record_if_absent(PLAN_KIND, plan.anchor_id.as_bytes(), &bytes)
                .unwrap()
        );
        let hash = *blake3::hash(&bytes).as_bytes();
        let area_path = resolve_anchor_area(&plan.area).unwrap();
        let area = PinnedDirectory {
            file: open_stable_anchor_area(&area_path, &plan.area).unwrap(),
            filesystem_id: plan.area.filesystem_id,
        };
        area.publish_sealed_bytes_child(plan.marker_name(), &plan.marker_bytes(hash))
            .unwrap();
        let unclaimed = area
            .create_child_directory(plan.anchor_id.to_string())
            .unwrap();
        fs::write(
            plan.area
                .path_hint
                .join(plan.anchor_id.to_string())
                .join("alien"),
            b"keep",
        )
        .unwrap();
        assert!(
            plan.prepare_anchor_directory(&control, &area, hash, false)
                .is_err()
        );
        assert_eq!(
            fs::read(
                plan.area
                    .path_hint
                    .join(plan.anchor_id.to_string())
                    .join("alien")
            )
            .unwrap(),
            b"keep"
        );
        fs::remove_file(
            plan.area
                .path_hint
                .join(plan.anchor_id.to_string())
                .join("alien"),
        )
        .unwrap();
        drop(unclaimed);
        let claimed = plan
            .prepare_anchor_directory(&control, &area, hash, false)
            .unwrap();
        let claim_bytes = control
            .get_record(DIRECTORY_CLAIM_KIND, plan.anchor_id.as_bytes())
            .unwrap()
            .unwrap();
        let claim: DirectoryClaim = mb_core::decode_canonical(&claim_bytes).unwrap();
        assert_eq!(claimed.identity().unwrap(), claim.directory_id);
        drop(claimed);
        let retirement = FileRetirement {
            format_version: 1,
            anchor_id: plan.anchor_id,
            plan_hash: hash,
        };
        control
            .put_record(
                RETIRE_KIND,
                plan.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&retirement).unwrap(),
            )
            .unwrap();
        let claimed_id = area
            .entry_identity(plan.anchor_id.to_string(), true)
            .unwrap()
            .unwrap();
        assert!(
            area.remove_empty_child_directory(plan.anchor_id.to_string(), claimed_id)
                .unwrap()
        );
        plan.discard_unreferenced(&control).unwrap();
        assert!(
            control
                .get_record(PLAN_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            control
                .get_record(DIRECTORY_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            control
                .get_record(RETIRE_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            area.entry_identity(plan.marker_name(), false)
                .unwrap()
                .is_none()
        );
        plan.discard_unreferenced(&control).unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn guarded_file_plan_publishes_replayable_native_manifest() {
        let temp = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-file-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let source_root = temp.path().join("protected");
        fs::create_dir(&source_root).unwrap();
        let source_path = source_root.join("source");
        fs::write(&source_path, b"raw\r\nbytes\0").unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([97; 32]));
        let database_path = temp.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let plan = GuardedFileCapturePlan::plan(&source_root, "source").unwrap();
        let manifest = plan.capture(&store).unwrap();
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_some()
        );
        let mut captured = Vec::new();
        manifest
            .open_verified()
            .unwrap()
            .read_to_end(&mut captured)
            .unwrap();
        assert_eq!(captured, b"raw\r\nbytes\0");
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        drop(store);

        let store = ControlStore::open(&database_path, &keys).unwrap();
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        let source_parent = PinnedDirectory::open(&source_root).unwrap();
        let anchor_parent =
            PinnedDirectory::open(plan.area.path_hint.join(plan.anchor_id.to_string())).unwrap();
        let frozen = LinkFreezeCaptureIntent::load(&store, plan.anchor_id)
            .unwrap()
            .unwrap();
        assert_eq!(frozen.phase(), LinkFreezeCapturePhase::Frozen);
        frozen
            .begin_edit(&store, &source_parent, &anchor_parent)
            .unwrap();
        let detached = LinkFreezeCaptureIntent::load(&store, plan.anchor_id)
            .unwrap()
            .unwrap()
            .resume(&store, &source_parent, &anchor_parent)
            .unwrap()
            .unwrap();
        assert_eq!(detached.phase(), LinkFreezeCapturePhase::Detached);
        fs::write(&source_path, b"edited").unwrap();
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        fs::remove_file(&source_path).unwrap();
        assert_eq!(plan.capture(&store).unwrap(), manifest);
        let mut retained = Vec::new();
        manifest
            .open_verified()
            .unwrap()
            .read_to_end(&mut retained)
            .unwrap();
        assert_eq!(retained, b"raw\r\nbytes\0");
        plan.discard_unreferenced(&store).unwrap();
        assert!(manifest.open_verified().is_err());
        assert!(
            store
                .get_record(MANIFEST_CLAIM_KIND, plan.anchor_id.as_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            LinkFreezeCaptureIntent::load(&store, plan.anchor_id)
                .unwrap()
                .is_none()
        );
        assert!(
            !plan
                .area
                .path_hint
                .join(plan.anchor_id.to_string())
                .exists()
        );

        let frozen_path = source_root.join("frozen");
        fs::write(&frozen_path, b"keep source bytes").unwrap();
        let frozen_plan = GuardedFileCapturePlan::plan(&source_root, "frozen").unwrap();
        frozen_plan.capture(&store).unwrap();
        assert_eq!(
            fs::metadata(&frozen_path).unwrap().permissions().mode() & 0o222,
            0
        );
        frozen_plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(&frozen_path).unwrap(), b"keep source bytes");
        assert_ne!(
            fs::metadata(&frozen_path).unwrap().permissions().mode() & 0o200,
            0
        );
        assert!(
            !frozen_plan
                .area
                .path_hint
                .join(frozen_plan.anchor_id.to_string())
                .exists()
        );

        fs::write(source_root.join("changed"), b"first").unwrap();
        let stale = GuardedFileCapturePlan::plan(&source_root, "changed").unwrap();
        fs::write(source_root.join("changed"), b"second").unwrap();
        assert!(stale.capture(&store).is_err());
        assert!(
            LinkFreezeCaptureIntent::load(&store, stale.anchor_id)
                .unwrap()
                .is_none()
        );
        stale.discard_unreferenced(&store).unwrap();
        assert!(
            !stale
                .area
                .path_hint
                .join(stale.anchor_id.to_string())
                .exists()
        );
    }
}
