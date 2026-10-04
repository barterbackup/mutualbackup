//! Replayable namespace handoff from a restored directory to a guarded view.
//! A caller still has to capture/isolate the private lower tree and claim the
//! FUSE mount before advertising the recovered root as protected.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{AnchorError, ControlStore, NativeFileId, PinnedDirectory};

const HANDOFF_KIND: &str = "guarded-recovery-handoff-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedRecoveryHandoff {
    format_version: u16,
    handoff_id: Uuid,
    #[serde(with = "crate::raw_path_bytes")]
    parent_path: PathBuf,
    parent_id: NativeFileId,
    #[serde(with = "crate::raw_path_bytes")]
    target_name: PathBuf,
    target_id: NativeFileId,
    #[serde(with = "crate::raw_path_bytes")]
    lower_name: PathBuf,
    #[serde(with = "crate::raw_path_bytes")]
    placeholder_name: PathBuf,
    placeholder_id: Option<NativeFileId>,
}

impl GuardedRecoveryHandoff {
    /// Journal every name and the published restore inode before changing its
    /// ownership or moving it. Only one local daemon writer may call this.
    pub fn prepare(
        control: &ControlStore,
        handoff_id: Uuid,
        parent: &PinnedDirectory,
        target_name: impl AsRef<Path>,
        target_id: NativeFileId,
    ) -> Result<Self> {
        ensure!(!handoff_id.is_nil(), "guarded recovery handoff ID is nil");
        let target_name = target_name.as_ref().to_path_buf();
        let parent_path = parent.descriptor_path().canonicalize()?;
        let parent_id = parent.identity()?;
        // The pinned lookup also rejects a multi-component or symlink name.
        let target = parent.entry_identity(&target_name, true)?;
        if let Some(bytes) = control.get_record(HANDOFF_KIND, handoff_id.as_bytes())? {
            let existing: Self = mb_core::decode_canonical(&bytes)?;
            existing.validate(parent, &parent_path)?;
            ensure!(
                existing.target_name == target_name
                    && existing.target_id == target_id
                    && (target == Some(target_id)
                        || target == existing.placeholder_id
                        || target.is_none()),
                "guarded recovery handoff conflicts with its durable target"
            );
            return Ok(existing);
        }
        ensure!(
            target == Some(target_id),
            "guarded recovery target changed before handoff"
        );
        let lower_name = PathBuf::from(format!(".mutualbackup-guarded-lower-{handoff_id}"));
        let placeholder_name = PathBuf::from(format!(
            ".mutualbackup-guarded-placeholder-{}",
            Uuid::new_v4()
        ));
        ensure!(
            target_name != lower_name
                && target_name != placeholder_name
                && parent.entry_identity(&lower_name, true)?.is_none()
                && parent.entry_identity(&placeholder_name, true)?.is_none(),
            "guarded recovery handoff name is occupied"
        );
        for (other_id, bytes) in control.records(HANDOFF_KIND)? {
            let other: Self = mb_core::decode_canonical(&bytes)?;
            ensure!(
                other_id == other.handoff_id.as_bytes() && other.format_version == 1,
                "another guarded recovery handoff record is inconsistent"
            );
            ensure!(
                other.parent_id != parent_id || other.target_name != target_name,
                "another guarded recovery handoff claims this target"
            );
        }
        let handoff = Self {
            format_version: 1,
            handoff_id,
            parent_path,
            parent_id,
            target_name,
            target_id,
            lower_name,
            placeholder_name,
            placeholder_id: None,
        };
        ensure!(
            control.put_record_if_absent(
                HANDOFF_KIND,
                handoff_id.as_bytes(),
                &mb_core::canonical_bytes(&handoff)?,
            )?,
            "guarded recovery handoff changed concurrently"
        );
        Ok(handoff)
    }

    pub fn load(control: &ControlStore, handoff_id: Uuid) -> Result<Option<Self>> {
        control
            .get_record(HANDOFF_KIND, handoff_id.as_bytes())?
            .map(|bytes| {
                let handoff: Self = mb_core::decode_canonical(&bytes)?;
                ensure!(
                    handoff.format_version == 1 && handoff.handoff_id == handoff_id,
                    "guarded recovery handoff record changed"
                );
                Ok(handoff)
            })
            .transpose()
    }

    fn validate(&self, parent: &PinnedDirectory, parent_path: &Path) -> Result<()> {
        let expected_lower = format!(".mutualbackup-guarded-lower-{}", self.handoff_id);
        ensure!(
            self.format_version == 1
                && !self.handoff_id.is_nil()
                && self.parent_id == parent.identity()?
                && self.parent_path == parent_path
                && self.lower_name == Path::new(&expected_lower)
                && self.target_name != self.lower_name
                && self.target_name != self.placeholder_name
                && self
                    .placeholder_name
                    .to_str()
                    .and_then(|name| name.strip_prefix(".mutualbackup-guarded-placeholder-"))
                    .is_some_and(|id| Uuid::parse_str(id).is_ok()),
            "guarded recovery handoff record is inconsistent"
        );
        // Validate every recorded component through the pinned lookup.
        // A claimed FUSE view is a different filesystem, so the pinned
        // no-cross-device lookup rejects it. Replay and mount-claim checks
        // below establish whether that view is ours; still validate the name.
        match parent.entry_identity(&self.target_name, true) {
            Ok(_) => {}
            Err(AnchorError::Io(error)) if error.raw_os_error() == Some(libc::EXDEV) => {}
            Err(error) => return Err(error.into()),
        }
        parent.entry_identity(&self.lower_name, true)?;
        parent.entry_identity(&self.placeholder_name, true)?;
        Ok(())
    }

    pub fn verify_recovery_target(
        &self,
        parent: &PinnedDirectory,
        target_name: &Path,
        target_id: NativeFileId,
    ) -> Result<()> {
        self.validate(parent, &parent.descriptor_path().canonicalize()?)?;
        ensure!(
            self.target_name == target_name && self.target_id == target_id,
            "guarded recovery handoff belongs to another restored target"
        );
        Ok(())
    }

    fn store(&self, control: &ControlStore) -> Result<()> {
        control.put_record(
            HANDOFF_KIND,
            self.handoff_id.as_bytes(),
            &mb_core::canonical_bytes(self)?,
        )?;
        Ok(())
    }

    /// Resume from any rename boundary. An unrecorded placeholder left by a
    /// crash is never adopted; a fresh hidden name is journaled instead.
    pub fn resume(&mut self, control: &ControlStore, parent: &PinnedDirectory) -> Result<()> {
        let parent_path = parent.descriptor_path().canonicalize()?;
        self.validate(parent, &parent_path)?;
        ensure!(
            Self::load(control, self.handoff_id)?.as_ref() == Some(self),
            "guarded recovery handoff changed during replay"
        );
        let lower = parent.entry_identity(&self.lower_name, true)?;
        let target = parent.entry_identity(&self.target_name, true)?;
        let placeholder = parent.entry_identity(&self.placeholder_name, true)?;
        if lower.is_none() {
            ensure!(
                target == Some(self.target_id),
                "guarded recovery target changed before private move"
            );
            let restored = parent
                .open_child_directory(&self.target_name)?
                .context("guarded recovery target disappeared")?;
            ensure!(
                restored.identity()? == self.target_id,
                "guarded recovery target was replaced"
            );
            // Remove the view owner's direct access before the inode becomes
            // reachable at the hidden lower name. Signed visible ownership is
            // retained in portable metadata for the later FUSE view.
            restored
                .as_file()
                .set_permissions(fs::Permissions::from_mode(0o700))?;
            if unsafe { libc::fchown(restored.as_file().as_raw_fd(), 0, 0) } < 0 {
                return Err(std::io::Error::last_os_error()).context("privatize recovered root");
            }
            restored.sync_all()?;
            if self.placeholder_id.is_none() {
                if placeholder.is_some() {
                    self.placeholder_name = PathBuf::from(format!(
                        ".mutualbackup-guarded-placeholder-{}",
                        Uuid::new_v4()
                    ));
                    ensure!(
                        parent
                            .entry_identity(&self.placeholder_name, true)?
                            .is_none(),
                        "replacement guarded placeholder name is occupied"
                    );
                    self.store(control)?;
                }
                let created = parent.create_child_directory(&self.placeholder_name)?;
                created.sync_all()?;
                parent.sync_all()?;
                self.placeholder_id = Some(created.identity()?);
                self.store(control)?;
            } else {
                ensure!(
                    placeholder == self.placeholder_id,
                    "guarded recovery placeholder was replaced"
                );
            }
            parent.move_child_directory_no_replace(
                &self.target_name,
                self.target_id,
                parent,
                &self.lower_name,
            )?;
        }
        ensure!(
            parent.entry_identity(&self.lower_name, true)? == Some(self.target_id),
            "guarded recovery lower tree has another identity"
        );
        let placeholder_id = self
            .placeholder_id
            .context("guarded recovery lower tree lacks a placeholder identity")?;
        match (
            parent.entry_identity(&self.target_name, true)?,
            parent.entry_identity(&self.placeholder_name, true)?,
        ) {
            (None, Some(actual)) if actual == placeholder_id => {
                parent.move_child_directory_no_replace(
                    &self.placeholder_name,
                    placeholder_id,
                    parent,
                    &self.target_name,
                )?;
            }
            (Some(actual), None) if actual == placeholder_id => {}
            _ => anyhow::bail!("guarded recovery placeholder changed during handoff"),
        }
        let lower = parent
            .open_child_directory(&self.lower_name)?
            .context("guarded recovery lower tree disappeared")?;
        let lower_stat = lower.as_file().metadata()?;
        ensure!(
            lower.identity()? == self.target_id
                && lower_stat.uid() == 0
                && lower_stat.mode() & 0o7777 == 0o700
                && parent.child_directory_is_empty(&self.target_name, placeholder_id)?,
            "guarded recovery handoff lost its private lower or empty placeholder"
        );
        Ok(())
    }

    pub fn lower_path(&self) -> PathBuf {
        self.parent_path.join(&self.lower_name)
    }

    pub fn mountpoint(&self) -> PathBuf {
        self.parent_path.join(&self.target_name)
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::PermissionsExt;

    use mb_core::{KeyMaterial, Seed};
    use uuid::Uuid;

    use super::GuardedRecoveryHandoff;
    use crate::{ControlStore, PinnedDirectory};

    #[test]
    #[ignore = "requires root ownership for a guarded lower tree"]
    fn recovery_handoff_replays_both_rename_boundaries() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::tempdir_in(root).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let parent = PinnedDirectory::open(area.path()).unwrap();
        let target_name = OsString::from_vec(b"restored-\xfe".to_vec());
        fs::create_dir(area.path().join(&target_name)).unwrap();
        fs::write(area.path().join(&target_name).join("file"), b"exact bytes").unwrap();
        let target_id = parent.entry_identity(&target_name, true).unwrap().unwrap();
        let control_path = area.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([117; 32]));
        let control = ControlStore::open(&control_path, &keys).unwrap();
        let id = Uuid::new_v4();
        let mut handoff =
            GuardedRecoveryHandoff::prepare(&control, id, &parent, &target_name, target_id)
                .unwrap();
        let placeholder = parent
            .create_child_directory(&handoff.placeholder_name)
            .unwrap();
        handoff.placeholder_id = Some(placeholder.identity().unwrap());
        handoff.store(&control).unwrap();
        fs::set_permissions(
            area.path().join(&target_name),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        parent
            .move_child_directory_no_replace(&target_name, target_id, &parent, &handoff.lower_name)
            .unwrap();
        drop(control);

        let control = ControlStore::open(&control_path, &keys).unwrap();
        let mut replay = GuardedRecoveryHandoff::load(&control, id).unwrap().unwrap();
        replay.resume(&control, &parent).unwrap();
        replay.resume(&control, &parent).unwrap();
        assert_eq!(
            fs::read(replay.lower_path().join("file")).unwrap(),
            b"exact bytes"
        );
        assert!(fs::read_dir(replay.mountpoint()).unwrap().next().is_none());
        assert_eq!(
            parent.entry_identity(&target_name, true).unwrap(),
            replay.placeholder_id
        );
    }

    #[test]
    #[ignore = "requires root ownership for a guarded lower tree"]
    fn recovery_handoff_leaves_unbound_placeholder_and_rejects_foreign_lower() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::tempdir_in(root).unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let parent = PinnedDirectory::open(area.path()).unwrap();
        fs::create_dir(area.path().join("restored")).unwrap();
        fs::write(area.path().join("restored/file"), b"must survive").unwrap();
        let target_id = parent.entry_identity("restored", true).unwrap().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([118; 32]));
        let control = ControlStore::open(area.path().join("control.db"), &keys).unwrap();
        let mut handoff = GuardedRecoveryHandoff::prepare(
            &control,
            Uuid::new_v4(),
            &parent,
            "restored",
            target_id,
        )
        .unwrap();
        let abandoned = handoff.placeholder_name.clone();
        parent.create_child_directory(&abandoned).unwrap();
        handoff.resume(&control, &parent).unwrap();
        assert_ne!(handoff.placeholder_name, abandoned);
        assert!(area.path().join(abandoned).is_dir());
        assert_eq!(
            fs::read(handoff.lower_path().join("file")).unwrap(),
            b"must survive"
        );

        fs::create_dir(area.path().join("other")).unwrap();
        let foreign = area.path().join("other");
        let lower = handoff.lower_path();
        fs::rename(&lower, area.path().join("relocated")).unwrap();
        fs::rename(&foreign, &lower).unwrap();
        assert!(handoff.resume(&control, &parent).is_err());
        assert_eq!(
            fs::read(area.path().join("relocated/file")).unwrap(),
            b"must survive"
        );
    }
}
