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
const PAYLOAD_NAME: &str = "blob";

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
        validate_relative(&self.relative_path)?;
        let encoded_plan = mb_core::canonical_bytes(self)?;
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
        let directory_name = self.anchor_id.to_string();
        let existing = area.open_child_directory(&directory_name)?;
        anyhow::ensure!(
            !new_plan || existing.is_none(),
            "unowned anchor directory collides with a new guarded plan"
        );
        let anchor_parent = match existing {
            Some(directory) => directory,
            None => area.create_child_directory(&directory_name)?,
        };
        area.sync_all()?;
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
        match anchor_parent.open_child_file(&manifest_name)? {
            Some(mut file) => {
                let metadata = file.metadata()?;
                anyhow::ensure!(
                    metadata.len() <= 64 * 1024
                        && metadata.nlink() == 1
                        && unix_mode(&metadata) & 0o222 == 0,
                    "guarded manifest metadata changed"
                );
                let mut existing_bytes = Vec::new();
                file.read_to_end(&mut existing_bytes)?;
                anyhow::ensure!(existing_bytes == manifest_bytes, "guarded manifest changed");
            }
            None => {
                anchor_parent.publish_sealed_bytes_child(&manifest_name, &manifest_bytes)?;
            }
        }
        anchor_parent.sync_all()?;
        area.sync_all()?;
        manifest.open_verified()?;
        Ok(manifest)
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

    use mb_core::{KeyMaterial, Seed};

    use super::GuardedFileCapturePlan;
    use crate::{ControlStore, LinkFreezeCaptureIntent, LinkFreezeCapturePhase, PinnedDirectory};

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

        fs::write(source_root.join("changed"), b"first").unwrap();
        let stale = GuardedFileCapturePlan::plan(&source_root, "changed").unwrap();
        fs::write(source_root.join("changed"), b"second").unwrap();
        assert!(stale.capture(&store).is_err());
        assert!(
            LinkFreezeCaptureIntent::load(&store, stale.anchor_id)
                .unwrap()
                .is_none()
        );
    }
}
