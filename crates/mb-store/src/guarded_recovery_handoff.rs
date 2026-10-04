//! Replayable namespace handoff from a restored directory to a guarded view.
//! A caller still has to capture/isolate the private lower tree and claim the
//! FUSE mount before advertising the recovered root as protected.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, FileTimes};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    AnchorError, ControlStore, GuardedViewEntryKind, GuardedViewMetadataEntry,
    GuardedViewMetadataV1, NativeFileId, PinnedDirectory,
};

const HANDOFF_KIND: &str = "guarded-recovery-handoff-v1";
const HANDOFF_RELEASE_KIND: &str = "guarded-recovery-handoff-release-v1";
const HANDOFF_RELEASE_METADATA_KIND: &str = "guarded-recovery-handoff-release-metadata-v1";
const RELEASE_METADATA_MAX_BYTES: usize = mb_core::V1_MAX_CATALOG_BYTES * 2 + 4096;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GuardedReleaseMetadataV1 {
    format_version: u16,
    handoff_id: Uuid,
    anchor_id: Uuid,
    handoff_hash: [u8; 32],
    visible: GuardedViewMetadataV1,
}

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

    fn release_metadata(
        &self,
        control: &ControlStore,
        anchor_id: Uuid,
    ) -> Result<GuardedViewMetadataV1> {
        let bytes = control
            .get_record(HANDOFF_RELEASE_METADATA_KIND, self.handoff_id.as_bytes())?
            .context("guarded release lost its visible metadata")?;
        ensure!(
            bytes.len() <= RELEASE_METADATA_MAX_BYTES,
            "guarded release metadata exceeds its local bound"
        );
        let record: GuardedReleaseMetadataV1 = mb_core::decode_canonical(&bytes)?;
        record.visible.validate_shape()?;
        ensure!(
            record.format_version == 1
                && record.handoff_id == self.handoff_id
                && record.anchor_id == anchor_id
                && record.handoff_hash
                    == *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes()
                && record.visible.anchor_id == anchor_id
                && record.visible.lower_root_id == self.target_id,
            "guarded release metadata differs from its handoff"
        );
        Ok(record.visible)
    }

    /// A retired claim may no longer be used to take a new view snapshot.
    /// Replay must instead find the already durable, handoff-bound snapshot.
    pub fn has_prepared_release(&self, control: &ControlStore, anchor_id: Uuid) -> Result<bool> {
        if control
            .get_record(HANDOFF_RELEASE_METADATA_KIND, self.handoff_id.as_bytes())?
            .is_none()
        {
            return Ok(false);
        }
        self.release_metadata(control, anchor_id)?;
        Ok(true)
    }

    /// Keys to retire atomically with the node's protected-root registration
    /// after the name and visible metadata have been handed back.
    pub fn released_record_keys(
        &self,
        control: &ControlStore,
        anchor_id: Uuid,
    ) -> Result<Vec<(String, Vec<u8>)>> {
        self.release_metadata(control, anchor_id)?;
        let bytes = mb_core::canonical_bytes(self)?;
        ensure!(
            control.get_record(HANDOFF_KIND, self.handoff_id.as_bytes())? == Some(bytes.clone())
                && control.get_record(HANDOFF_RELEASE_KIND, self.handoff_id.as_bytes())?
                    == Some(bytes),
            "guarded release handoff is not complete"
        );
        Ok([
            HANDOFF_KIND,
            HANDOFF_RELEASE_KIND,
            HANDOFF_RELEASE_METADATA_KIND,
        ]
        .into_iter()
        .map(|kind| (kind.to_owned(), self.handoff_id.as_bytes().to_vec()))
        .collect())
    }

    /// Freeze the stopped view's post-detach visible metadata before the
    /// mount claim can retire. A retry must find the same snapshot; it cannot
    /// substitute newer view state for a release already in progress.
    pub fn prepare_release_metadata(
        &self,
        control: Arc<Mutex<ControlStore>>,
        parent: &PinnedDirectory,
        anchor_id: Uuid,
    ) -> Result<GuardedViewMetadataV1> {
        self.validate(parent, &parent.descriptor_path().canonicalize()?)?;
        let placeholder = self
            .placeholder_id
            .context("guarded release has no placeholder")?;
        {
            let store = control
                .lock()
                .map_err(|_| std::io::Error::other("guarded release control lock is poisoned"))?;
            ensure!(
                Self::load(&store, self.handoff_id)?.as_ref() == Some(self),
                "guarded release handoff changed"
            );
            crate::guarded_mount::require_active_claim_for_release(
                &store,
                anchor_id,
                &self.lower_path(),
                self.target_id,
                &self.mountpoint(),
                placeholder,
            )?;
        }
        crate::GuardedViewMount::detach_stopped_files_for_release(anchor_id, Arc::clone(&control))?;
        let visible = crate::GuardedViewMount::snapshot_stopped(anchor_id, Arc::clone(&control))?;
        visible.validate_shape()?;
        ensure!(
            visible.anchor_id == anchor_id && visible.lower_root_id == self.target_id,
            "guarded release view differs from its handoff"
        );
        let record = GuardedReleaseMetadataV1 {
            format_version: 1,
            handoff_id: self.handoff_id,
            anchor_id,
            handoff_hash: *blake3::hash(&mb_core::canonical_bytes(self)?).as_bytes(),
            visible: visible.clone(),
        };
        let bytes = mb_core::canonical_bytes(&record)?;
        ensure!(
            bytes.len() <= RELEASE_METADATA_MAX_BYTES,
            "guarded release metadata exceeds its local bound"
        );
        let store = control
            .lock()
            .map_err(|_| std::io::Error::other("guarded release control lock is poisoned"))?;
        crate::guarded_mount::require_active_claim_for_release(
            &store,
            anchor_id,
            &self.lower_path(),
            self.target_id,
            &self.mountpoint(),
            placeholder,
        )?;
        if !store.put_record_if_absent(
            HANDOFF_RELEASE_METADATA_KIND,
            self.handoff_id.as_bytes(),
            &bytes,
        )? {
            ensure!(
                store.get_record(HANDOFF_RELEASE_METADATA_KIND, self.handoff_id.as_bytes())?
                    == Some(bytes),
                "guarded release visible metadata changed after preparation"
            );
        }
        Ok(visible)
    }

    /// Return the private lower tree to its original name after the guarded
    /// view has stopped, every live file has detached from immutable anchors,
    /// and the mount claim has retired. The durable release marker fences
    /// forward handoff replay. Until the caller restores visible metadata,
    /// the returned root remains private (root-owned and mode 0700).
    pub fn release_names(
        &self,
        control: &ControlStore,
        parent: &PinnedDirectory,
        anchor_id: Uuid,
    ) -> Result<()> {
        ensure!(!anchor_id.is_nil(), "guarded release anchor ID is nil");
        self.validate(parent, &parent.descriptor_path().canonicalize()?)?;
        ensure!(
            Self::load(control, self.handoff_id)?.as_ref() == Some(self),
            "guarded recovery handoff changed before release"
        );
        ensure!(
            self.placeholder_id.is_some(),
            "guarded recovery handoff has no published placeholder"
        );
        // Releasing a still-claimed view would expose its lower tree at the
        // mounted path while the daemon believes the FUSE view is active.
        crate::guarded_mount::require_retired_claim_for_release(
            control,
            anchor_id,
            &self.lower_path(),
            self.target_id,
            &self.mountpoint(),
            self.placeholder_id.unwrap(),
        )?;
        self.release_metadata(control, anchor_id)?;
        if parent.entry_identity(&self.lower_name, true)? == Some(self.target_id) {
            let lower = parent
                .open_child_directory(&self.lower_name)?
                .context("guarded release lower tree disappeared")?;
            let metadata = lower.as_file().metadata()?;
            ensure!(
                lower.identity()? == self.target_id
                    && metadata.uid() == 0
                    && metadata.mode() & 0o7777 == 0o700,
                "guarded release lower tree is not private"
            );
        }
        let marker = mb_core::canonical_bytes(self)?;
        match control.get_record(HANDOFF_RELEASE_KIND, self.handoff_id.as_bytes())? {
            Some(existing) => ensure!(existing == marker, "guarded handoff release changed"),
            None => {
                let lower = parent.entry_identity(&self.lower_name, true)?;
                let target = parent.entry_identity(&self.target_name, true)?;
                ensure!(
                    lower == Some(self.target_id) && target == self.placeholder_id,
                    "guarded release names changed before preparation"
                );
                ensure!(
                    parent.child_directory_is_empty(
                        &self.target_name,
                        self.placeholder_id.unwrap()
                    )?,
                    "guarded release placeholder is not empty"
                );
                ensure!(
                    control.put_record_if_absent(
                        HANDOFF_RELEASE_KIND,
                        self.handoff_id.as_bytes(),
                        &marker,
                    )?,
                    "guarded handoff release changed concurrently"
                );
            }
        }
        ensure!(
            parent
                .entry_identity(&self.placeholder_name, true)?
                .is_none(),
            "guarded release has an unexpected spare placeholder"
        );
        match (
            parent.entry_identity(&self.lower_name, true)?,
            parent.entry_identity(&self.target_name, true)?,
        ) {
            (None, Some(actual)) if actual == self.target_id => return Ok(()),
            (Some(actual), Some(placeholder))
                if actual == self.target_id && Some(placeholder) == self.placeholder_id =>
            {
                ensure!(
                    parent.remove_empty_child_directory(
                        &self.target_name,
                        self.placeholder_id.unwrap()
                    )?,
                    "guarded release placeholder changed before removal"
                );
            }
            (Some(actual), None) if actual == self.target_id => {}
            _ => anyhow::bail!("guarded release lower or placeholder changed"),
        }
        parent.move_child_directory_no_replace(
            &self.lower_name,
            self.target_id,
            parent,
            &self.target_name,
        )?;
        ensure!(
            parent.entry_identity(&self.lower_name, true)?.is_none()
                && parent.entry_identity(&self.target_name, true)? == Some(self.target_id),
            "guarded release failed to return the original directory"
        );
        Ok(())
    }

    /// Apply the durable post-detach stopped-view snapshot to the returned
    /// directory. This operation can replay after any partial ownership or
    /// timestamp change. The root remains inaccessible to its ordinary owner
    /// until all descendants have been restored.
    pub fn restore_released_metadata(
        &self,
        control: &ControlStore,
        parent: &PinnedDirectory,
        anchor_id: Uuid,
    ) -> Result<()> {
        let visible = self.release_metadata(control, anchor_id)?;
        visible.validate_shape()?;
        ensure!(
            visible.anchor_id == anchor_id
                && visible.lower_root_id == self.target_id
                && mb_core::canonical_bytes(&visible)?.len() <= RELEASE_METADATA_MAX_BYTES,
            "guarded release metadata differs from its lower tree"
        );
        self.validate(parent, &parent.descriptor_path().canonicalize()?)?;
        ensure!(
            control.get_record(HANDOFF_RELEASE_KIND, self.handoff_id.as_bytes())?
                == Some(mb_core::canonical_bytes(self)?),
            "guarded release has no durable name handoff"
        );
        crate::guarded_mount::require_retired_claim_for_release(
            control,
            anchor_id,
            &self.lower_path(),
            self.target_id,
            &self.mountpoint(),
            self.placeholder_id
                .context("guarded release lost its placeholder")?,
        )?;
        ensure!(
            parent.entry_identity(&self.lower_name, true)?.is_none()
                && parent.entry_identity(&self.target_name, true)? == Some(self.target_id),
            "guarded lower tree has not returned to its original name"
        );
        let root = parent
            .open_child_directory(&self.target_name)?
            .context("guarded release target disappeared")?;
        restore_visible_release_metadata(&root, &visible)
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
        ensure!(
            control
                .get_record(HANDOFF_RELEASE_KIND, self.handoff_id.as_bytes())?
                .is_none(),
            "guarded recovery handoff is being released"
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

    pub fn target_identity(&self) -> NativeFileId {
        self.target_id
    }

    pub fn mountpoint(&self) -> PathBuf {
        self.parent_path.join(&self.target_name)
    }
}

/// Restore a stopped view's exact visible metadata onto its unmounted lower
/// tree after the caller has fenced the mount and journaled any name handoff.
/// Replaying after the root becomes user-visible leaves later edits untouched.
pub fn restore_visible_release_metadata(
    root: &PinnedDirectory,
    visible: &GuardedViewMetadataV1,
) -> Result<()> {
    visible.validate_shape()?;
    ensure!(
        mb_core::canonical_bytes(visible)?.len() <= RELEASE_METADATA_MAX_BYTES
            && root.identity()? == visible.lower_root_id,
        "guarded release metadata differs from its lower tree"
    );
    let root_stat = root.as_file().metadata()?;
    let root_mode = root_stat.mode() & 0o7777;
    if root_stat.uid() == visible.root_uid && root_mode != 0 {
        ensure!(
            root_mode == u32::from(visible.root_mode),
            "guarded released root mode changed after exposure"
        );
        return Ok(());
    }
    verify_release_namespace(root, visible)?;
    // Descendants first: updating a child must not change a restored parent's
    // recorded modification time.
    let mut entries = visible.entries.iter().collect::<Vec<_>>();
    entries.sort_by_key(|entry| {
        std::cmp::Reverse(entry.path.iter().filter(|byte| **byte == b'/').count())
    });
    for entry in entries {
        let file = open_release_entry(root, entry)?;
        apply_release_metadata(&file, entry)?;
    }
    root.as_file()
        .set_permissions(fs::Permissions::from_mode(0o000))?;
    if unsafe {
        libc::fchown(
            root.as_file().as_raw_fd(),
            visible.root_uid,
            visible.root_gid,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error()).context("restore guarded root owner");
    }
    root.as_file().set_times(release_file_times(
        visible.root_atime_secs,
        visible.root_atime_nanos,
        visible.root_modified_secs,
        visible.root_modified_nanos,
    )?)?;
    root.as_file()
        .set_permissions(fs::Permissions::from_mode(u32::from(visible.root_mode)))?;
    root.sync_all()?;
    Ok(())
}

pub(crate) fn release_prepared_for_anchor(control: &ControlStore, anchor_id: Uuid) -> Result<bool> {
    for (record_id, bytes) in control.records(HANDOFF_RELEASE_METADATA_KIND)? {
        ensure!(
            bytes.len() <= RELEASE_METADATA_MAX_BYTES,
            "guarded release metadata exceeds its local bound"
        );
        let record: GuardedReleaseMetadataV1 = mb_core::decode_canonical(&bytes)?;
        ensure!(
            record.format_version == 1
                && record.handoff_id.as_bytes() == record_id.as_slice()
                && !record.anchor_id.is_nil(),
            "guarded release metadata record is inconsistent"
        );
        if record.anchor_id == anchor_id {
            let handoff = GuardedRecoveryHandoff::load(control, record.handoff_id)?
                .context("guarded release lost its handoff")?;
            handoff.release_metadata(control, anchor_id)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn open_release_entry(root: &PinnedDirectory, entry: &GuardedViewMetadataEntry) -> Result<File> {
    let path = PathBuf::from(OsString::from_vec(entry.path.clone()));
    let file = match entry.kind {
        GuardedViewEntryKind::Directory => root
            .open_descendant_directory(&path)?
            .as_file()
            .try_clone()?,
        GuardedViewEntryKind::File => {
            let parent_path = path
                .parent()
                .context("guarded release entry has no parent")?;
            let parent = if parent_path.as_os_str().is_empty() {
                root.try_clone()?
            } else {
                root.open_descendant_directory(parent_path)?
            };
            parent
                .open_child_file(
                    path.file_name()
                        .context("guarded release entry has no name")?,
                )?
                .context("guarded release file disappeared")?
        }
    };
    let stat = file.metadata()?;
    ensure!(
        NativeFileId {
            filesystem_id: root.identity()?.filesystem_id,
            inode: stat.ino(),
        } == entry.native_id
            && match entry.kind {
                GuardedViewEntryKind::Directory => stat.is_dir(),
                GuardedViewEntryKind::File =>
                    stat.is_file() && stat.len() == entry.logical_len && stat.nlink() == 1,
            },
        "guarded release entry changed before metadata restoration"
    );
    Ok(file)
}

fn verify_release_namespace(root: &PinnedDirectory, visible: &GuardedViewMetadataV1) -> Result<()> {
    let mut children = BTreeMap::<Vec<u8>, BTreeSet<Vec<u8>>>::new();
    children.insert(Vec::new(), BTreeSet::new());
    for entry in &visible.entries {
        let parent_end = entry.path.iter().rposition(|byte| *byte == b'/');
        let (parent, name) = match parent_end {
            Some(index) => (&entry.path[..index], &entry.path[index + 1..]),
            None => (&[][..], entry.path.as_slice()),
        };
        children
            .get_mut(parent)
            .context("guarded release entry has no recorded parent")?
            .insert(name.to_vec());
        if entry.kind == GuardedViewEntryKind::Directory {
            children.insert(entry.path.clone(), BTreeSet::new());
        }
        open_release_entry(root, entry)?;
    }
    for (path, expected) in children {
        let directory = if path.is_empty() {
            root.try_clone()?
        } else {
            root.open_descendant_directory(Path::new(OsStr::from_bytes(&path)))?
        };
        let actual = fs::read_dir(directory.descriptor_path())?
            .map(|entry| Ok(entry?.file_name().as_bytes().to_vec()))
            .collect::<std::io::Result<BTreeSet<_>>>()?;
        ensure!(actual == expected, "guarded release namespace changed");
    }
    Ok(())
}

fn release_system_time(seconds: i64, nanos: u32) -> Result<SystemTime> {
    let value = i128::from(seconds) * 1_000_000_000 + i128::from(nanos);
    let magnitude = value.unsigned_abs();
    let duration = Duration::new(
        u64::try_from(magnitude / 1_000_000_000)?,
        (magnitude % 1_000_000_000) as u32,
    );
    if value >= 0 {
        UNIX_EPOCH.checked_add(duration)
    } else {
        UNIX_EPOCH.checked_sub(duration)
    }
    .context("guarded release timestamp is out of range")
}

fn release_file_times(
    atime_secs: i64,
    atime_nanos: u32,
    mtime_secs: i64,
    mtime_nanos: u32,
) -> Result<FileTimes> {
    Ok(FileTimes::new()
        .set_accessed(release_system_time(atime_secs, atime_nanos)?)
        .set_modified(release_system_time(mtime_secs, mtime_nanos)?))
}

fn apply_release_metadata(file: &File, entry: &GuardedViewMetadataEntry) -> Result<()> {
    if unsafe { libc::fchown(file.as_raw_fd(), entry.uid, entry.gid) } < 0 {
        return Err(std::io::Error::last_os_error()).context("restore guarded entry owner");
    }
    file.set_permissions(fs::Permissions::from_mode(u32::from(entry.mode)))?;
    file.set_times(release_file_times(
        entry.atime_secs,
        entry.atime_nanos,
        entry.modified_secs,
        entry.modified_nanos,
    )?)?;
    file.sync_all()?;
    Ok(())
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
