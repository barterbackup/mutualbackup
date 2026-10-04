//! Durable mount ownership for a guarded FUSE worktree whose private lower
//! root has already been captured. Enrollment still owns the separate,
//! replayable transition from a user's original directory to this layout.

use std::collections::BTreeMap;
use std::ffi::{CString, OsString};
use std::fs;
use std::io::{self, Read};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, ensure};
use fuser::{BackgroundSession, Config, MountOption, SessionACL};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::guarded_view_probe::{GuardedProbeView, GuardedViewEntryKind, GuardedViewMetadataV1};
use crate::{
    CapturedEntry, ControlStore, FileAnchorManifest, FileExtent, GuardedRootCapturePlan,
    NativeFileId, PinnedDirectory, StableAnchorFileLocator, StableAnchorManifest,
    filesystem_identity,
};

const MOUNT_CLAIM_KIND: &str = "guarded-view-mount-v1";
const MOUNT_RETIRE_KIND: &str = "guarded-view-mount-retired-v1";
const STOPPED_CAPTURE_KIND: &str = "guarded-view-stopped-capture-v1";
const STOPPED_CAPTURE_MAX_BYTES: usize = mb_core::V1_MAX_CATALOG_BYTES * 2 + 4096;
const MOUNT_SUBTYPE: &str = "mutualbackup_guarded";
// The daemon is the sole writer for a root. Serialize local mount lifecycle
// operations so a stopped-view snapshot cannot overlap a remount or stop.
static MOUNT_LIFECYCLE: Mutex<()> = Mutex::new(());

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct MountClaim {
    version: u16,
    anchor_id: Uuid,
    lower_root: PathBuf,
    lower_id: NativeFileId,
    mountpoint: PathBuf,
    mountpoint_id: NativeFileId,
    view_uid: u32,
    view_gid: u32,
}

#[derive(Debug)]
struct MountedFilesystem {
    filesystem_type: String,
    source: String,
}

/// A mounted guarded view. Keep this with the daemon's root registration;
/// dropping it unmounts the view, while `stop` propagates unmount errors.
pub struct GuardedViewMount {
    session: Option<BackgroundSession>,
    mountpoint: PathBuf,
    source: String,
}

/// One quiescent view with an immutable anchor for every visible file. This
/// local capture is input to a future signed owner revision, not a revision by
/// itself. The revision owner must pin its file locators until retirement.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedStoppedCaptureV1 {
    pub format_version: u16,
    pub metadata: GuardedViewMetadataV1,
    pub files: Vec<GuardedStoppedFileV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuardedStoppedFileV1 {
    pub path: Vec<u8>,
    pub native_id: NativeFileId,
    pub locator: StableAnchorFileLocator,
    pub logical_len: u64,
    pub content_hash: [u8; 32],
    pub data_extents: Vec<FileExtent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct StoppedCaptureIntent {
    format_version: u16,
    attempt_id: Uuid,
    root_anchor_id: Uuid,
    metadata: GuardedViewMetadataV1,
    published: Option<GuardedStoppedCaptureV1>,
}

type StoppedCaptureRecord = (Vec<u8>, Vec<u8>, StoppedCaptureIntent);

impl StoppedCaptureIntent {
    fn validate(&self, record_id: &[u8]) -> anyhow::Result<()> {
        ensure!(
            self.format_version == 1
                && !self.attempt_id.is_nil()
                && self.attempt_id.as_bytes() == record_id
                && !self.root_anchor_id.is_nil()
                && self.metadata.format_version == 1
                && self.metadata.anchor_id == self.root_anchor_id
                && self
                    .published
                    .as_ref()
                    .is_none_or(|capture| capture.metadata == self.metadata),
            "guarded stopped-capture intent differs from its metadata"
        );
        Ok(())
    }
}

fn stopped_capture_intents(control: &ControlStore) -> anyhow::Result<Vec<StoppedCaptureRecord>> {
    control
        .records(STOPPED_CAPTURE_KIND)?
        .into_iter()
        .map(|(id, bytes)| {
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded stopped-capture intent exceeds its local bound"
            );
            let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
            intent.validate(&id)?;
            Ok((id, bytes, intent))
        })
        .collect()
}

fn pending_stopped_capture_attempts(
    control: &ControlStore,
    root_anchor_id: Uuid,
) -> anyhow::Result<Vec<Uuid>> {
    Ok(stopped_capture_intents(control)?
        .into_iter()
        .filter_map(|(_, _, intent)| {
            (intent.root_anchor_id == root_anchor_id && intent.published.is_none())
                .then_some(intent.attempt_id)
        })
        .collect())
}

pub(crate) fn stopped_capture_intent_pins_anchor(
    control: &ControlStore,
    anchor_id: Uuid,
) -> anyhow::Result<bool> {
    Ok(stopped_capture_intents(control)?
        .into_iter()
        .any(|(_, _, intent)| {
            intent.root_anchor_id == anchor_id
                || intent.published.as_ref().is_some_and(|capture| {
                    capture
                        .files
                        .iter()
                        .any(|file| file.locator.anchor_id == anchor_id)
                })
        }))
}

impl GuardedStoppedCaptureV1 {
    /// Recheck a persisted local capture before building signed sector data.
    /// This proves each locator still supplies the exact captured bytes and
    /// sparse layout, without depending on the mutable lower worktree.
    pub fn verify(&self) -> anyhow::Result<()> {
        ensure!(
            self.format_version == 1
                && self.metadata.format_version == 1
                && !self.metadata.anchor_id.is_nil()
                && mb_core::canonical_bytes(self)?.len() <= mb_core::V1_MAX_CATALOG_BYTES,
            "invalid guarded stopped-capture version or size"
        );
        let mut previous = None::<&[u8]>;
        for entry in &self.metadata.entries {
            let path = PathBuf::from(OsString::from_vec(entry.path.clone()));
            let mut normalized = PathBuf::new();
            for component in path.components() {
                let Component::Normal(name) = component else {
                    anyhow::bail!("guarded stopped capture has an unsafe path")
                };
                normalized.push(name);
            }
            ensure!(
                !entry.path.is_empty()
                    && !entry.path.contains(&0)
                    && normalized.as_os_str().as_bytes() == entry.path
                    && previous.is_none_or(|prior| prior < entry.path.as_slice()),
                "guarded stopped capture has an unsafe or unordered path"
            );
            previous = Some(&entry.path);
        }
        let file_entries: Vec<_> = self
            .metadata
            .entries
            .iter()
            .filter(|entry| entry.kind == GuardedViewEntryKind::File)
            .collect();
        ensure!(
            file_entries.len() == self.files.len(),
            "guarded stopped capture lacks a visible file anchor"
        );
        for (entry, captured) in file_entries.into_iter().zip(&self.files) {
            ensure!(
                captured.path == entry.path
                    && captured.native_id == entry.native_id
                    && captured.logical_len == entry.logical_len
                    && captured.locator.area.filesystem_id
                        == self.metadata.lower_root_id.filesystem_id,
                "guarded stopped file differs from visible metadata"
            );
            let mut file = captured.locator.open()?;
            ensure!(
                file.metadata()?.len() == captured.logical_len,
                "guarded stopped anchor has another length"
            );
            let mut hasher = blake3::Hasher::new();
            let mut read_len = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                read_len += read as u64;
            }
            ensure!(
                read_len == captured.logical_len
                    && hasher.finalize().as_bytes() == &captured.content_hash
                    && crate::anchor::file_data_extents(&file, captured.logical_len)?
                        == captured.data_extents,
                "guarded stopped anchor differs from its captured bytes or extents"
            );
        }
        Ok(())
    }
}

impl GuardedViewMount {
    pub fn has_claims(control: &ControlStore) -> anyhow::Result<bool> {
        Ok(!control.records(MOUNT_CLAIM_KIND)?.is_empty())
    }

    /// Recover every active durable mount claim before the daemon starts
    /// serving requests. A retirement marker wins over an old claim; finish
    /// that retirement instead of remounting a view being released.
    pub fn recover_all_claimed(control: Arc<Mutex<ControlStore>>) -> anyhow::Result<Vec<Self>> {
        let active = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let claims = control.records(MOUNT_CLAIM_KIND)?;
            ensure!(claims.len() <= 256, "too many guarded mount claims");
            let mut active = Vec::with_capacity(claims.len());
            for (record_id, bytes) in claims {
                let anchor_id = Uuid::from_slice(&record_id)?;
                let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
                ensure!(
                    claim.version == 1 && claim.anchor_id == anchor_id,
                    "guarded mount claim record is inconsistent"
                );
                if let Some(retired) =
                    control.get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
                {
                    ensure!(retired == bytes, "guarded mount retirement marker changed");
                    Self::retire_claim(anchor_id, &control)?;
                } else {
                    active.push(anchor_id);
                }
            }
            active
        };
        let mut mounts = Vec::with_capacity(active.len());
        for anchor_id in active {
            let pending = {
                let store = control
                    .lock()
                    .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                pending_stopped_capture_attempts(&store, anchor_id)?
            };
            for attempt_id in pending {
                Self::finish_stopped_capture(anchor_id, attempt_id, Arc::clone(&control))?;
            }
            let mount = Self::recover_claimed(anchor_id, Arc::clone(&control))?;
            mount.check_health()?;
            mounts.push(mount);
        }
        Ok(mounts)
    }

    /// Retire a stopped view before releasing its captured anchors. The caller
    /// must first prove the protected revision and every Git pin are gone.
    /// The retirement marker fences remount even if deletion of the claim is
    /// interrupted; retrying this method finishes that deletion.
    pub fn retire_claim(anchor_id: Uuid, control: &ControlStore) -> anyhow::Result<()> {
        ensure!(
            !stopped_capture_intents(control)?
                .iter()
                .any(|(_, _, intent)| intent.root_anchor_id == anchor_id),
            "guarded mount retains a stopped-capture attempt"
        );
        let id = anchor_id.as_bytes();
        let claim_bytes = control.get_record(MOUNT_CLAIM_KIND, id)?;
        let retired = control.get_record(MOUNT_RETIRE_KIND, id)?;
        let Some(claim_bytes) = claim_bytes else {
            let bytes =
                retired.ok_or_else(|| anyhow::anyhow!("guarded mount has no claim to retire"))?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount retirement marker changed"
            );
            ensure!(
                mounted_filesystem(&claim.mountpoint)?.is_none(),
                "guarded view remains mounted during retirement"
            );
            return Ok(());
        };
        let claim: MountClaim = mb_core::decode_canonical(&claim_bytes)?;
        ensure!(
            claim.version == 1 && claim.anchor_id == anchor_id,
            "guarded mount claim changed before retirement"
        );
        ensure!(
            retired.as_ref().is_none_or(|bytes| bytes == &claim_bytes),
            "guarded mount retirement belongs to another claim"
        );
        ensure!(
            mounted_filesystem(&claim.mountpoint)?.is_none(),
            "guarded view remains mounted during retirement"
        );
        let lower = PinnedDirectory::open(&claim.lower_root)?;
        let placeholder = PinnedDirectory::open(&claim.mountpoint)?;
        ensure!(
            lower.identity()? == claim.lower_id && placeholder.identity()? == claim.mountpoint_id,
            "guarded mount paths changed before retirement"
        );
        if retired.is_none() {
            ensure!(control.put_record_if_absent(MOUNT_RETIRE_KIND, id, &claim_bytes)?);
        }
        control.delete_record_if_value(MOUNT_CLAIM_KIND, id, &claim_bytes)?;
        Ok(())
    }

    /// Reopen a claimed view after process loss using only its durable local
    /// claim, capture plan, and sealed manifest. No caller-held manifest is
    /// needed; `start` still verifies the lower and placeholder identities.
    pub fn recover_claimed(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<Self> {
        let (claim, manifest) = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let bytes = control
                .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
                .ok_or_else(|| anyhow::anyhow!("guarded view has no durable mount claim"))?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount claim changed"
            );
            let manifest = GuardedRootCapturePlan::load_published_manifest(&control, anchor_id)?;
            (claim, manifest)
        };
        Self::start(
            &manifest,
            control,
            claim.mountpoint,
            claim.view_uid,
            claim.view_gid,
        )
    }

    /// Mount an existing private guarded capture. A durable claim binds the
    /// mountpoint and lower inode before FUSE becomes visible. On restart, only
    /// a dead FUSE mount with this exact source may be detached.
    pub fn start(
        manifest: &StableAnchorManifest,
        control: Arc<Mutex<ControlStore>>,
        mountpoint: impl AsRef<Path>,
        view_uid: u32,
        view_gid: u32,
    ) -> anyhow::Result<Self> {
        let _lifecycle = MOUNT_LIFECYCLE
            .lock()
            .map_err(|_| io::Error::other("guarded mount lifecycle lock is poisoned"))?;
        ensure!(view_uid != 0, "guarded view needs an unprivileged owner");
        let mountpoint = canonical_mountpoint(mountpoint.as_ref())?;
        let plan = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            ensure!(
                control
                    .get_record(MOUNT_RETIRE_KIND, manifest.anchor_id.as_bytes())?
                    .is_none(),
                "guarded mount has been retired"
            );
            ensure!(
                pending_stopped_capture_attempts(&control, manifest.anchor_id)?.is_empty(),
                "guarded view has a prepared capture to finish before remount"
            );
            GuardedRootCapturePlan::load_active_for_view(&control, manifest)?
        };
        let lower_root = PinnedDirectory::open(plan.source_root())?;
        ensure!(
            lower_root.identity()? == plan.source_root_identity(),
            "guarded lower root changed after capture"
        );
        let lower_metadata = lower_root.as_file().metadata()?;
        ensure!(
            lower_metadata.uid() != view_uid && lower_metadata.permissions().mode() & 0o077 == 0,
            "guarded lower root is accessible to the view owner"
        );
        let source = mount_source(manifest.anchor_id);
        let existing = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            control
                .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())?
                .map(|bytes| mb_core::decode_canonical::<MountClaim>(&bytes))
                .transpose()?
        };
        if let Some(claim) = &existing {
            ensure!(
                claim.version == 1
                    && claim.anchor_id == manifest.anchor_id
                    && claim.lower_root == plan.source_root()
                    && claim.lower_id == plan.source_root_identity()
                    && claim.mountpoint == mountpoint
                    && claim.view_uid == view_uid
                    && claim.view_gid == view_gid,
                "guarded mount claim differs from the requested view"
            );
        }
        if let Some(mounted) = mounted_filesystem(&mountpoint)? {
            ensure!(
                existing.is_some(),
                "unclaimed filesystem occupies guarded mountpoint"
            );
            ensure!(
                mounted.matches_guarded(&source),
                "another filesystem occupies guarded mountpoint"
            );
            match fs::metadata(&mountpoint) {
                Ok(_) => anyhow::bail!("guarded view is already mounted and live"),
                Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => {}
                Err(error) => return Err(error).context("check existing guarded mount"),
            }
            let path = std::ffi::CString::new(mountpoint.as_os_str().as_encoded_bytes())?;
            // SAFETY: the claim and mountinfo identify this exact dead
            // guarded FUSE mount. The path is NUL-free and stays owned by
            // this process through the following identity check.
            if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } < 0 {
                return Err(io::Error::last_os_error()).context("detach dead guarded FUSE mount");
            }
        }
        let placeholder = PinnedDirectory::open(&mountpoint)?;
        let placeholder_id = placeholder.identity()?;
        let placeholder_metadata = placeholder.as_file().metadata()?;
        ensure!(
            placeholder_metadata.uid() != view_uid
                && placeholder_metadata.permissions().mode() & 0o022 == 0,
            "unmounted guarded placeholder is writable by the view owner"
        );
        ensure!(
            filesystem_identity(&mountpoint)?.stable_id == lower_root.identity()?.filesystem_id,
            "guarded view mountpoint is not on the lower filesystem"
        );
        ensure!(
            fs::read_dir(&mountpoint)?.next().is_none(),
            "guarded view mountpoint is not empty"
        );
        if let Some(claim) = &existing {
            ensure!(
                claim.mountpoint_id == placeholder_id,
                "guarded mountpoint changed after the original mount"
            );
        } else {
            // No FUSE operation has yet changed captured paths. Refuse an
            // accessible child before view reconstruction can replay a
            // pending namespace operation against that lower directory.
            plan.verify_initial_lower_namespace(&lower_root)?;
            plan.verify_initial_private_directories(&lower_root, view_uid)?;
        }
        // Build and validate the complete view before publishing a new mount
        // claim. A user-owned frozen anchor can be changed through a descriptor
        // retained before the private lower path was hidden: fchmod restores
        // write permission, then /proc/self/fd reopens the same inode.
        let view = GuardedProbeView::from_guarded_capture(
            manifest,
            Arc::clone(&control),
            view_uid,
            view_gid,
        )?;
        view.verify_private_lower_ownership()?;
        view.verify_lower_namespace()?;
        if existing.is_none() {
            let claim = MountClaim {
                version: 1,
                anchor_id: manifest.anchor_id,
                lower_root: plan.source_root().to_path_buf(),
                lower_id: plan.source_root_identity(),
                mountpoint: mountpoint.clone(),
                mountpoint_id: placeholder_id,
                view_uid,
                view_gid,
            };
            let encoded = mb_core::canonical_bytes(&claim)?;
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            for (other_id, bytes) in control.records(MOUNT_CLAIM_KIND)? {
                let other: MountClaim = mb_core::decode_canonical(&bytes)?;
                ensure!(
                    other.version == 1
                        && (other.mountpoint != mountpoint
                            || other_id == manifest.anchor_id.as_bytes()),
                    "another guarded capture claims this mountpoint"
                );
            }
            ensure!(
                control.put_record_if_absent(
                    MOUNT_CLAIM_KIND,
                    manifest.anchor_id.as_bytes(),
                    &encoded,
                )?,
                "guarded mount claim changed concurrently"
            );
        }
        let mut config = Config::default();
        config.acl = SessionACL::All;
        config.mount_options = vec![
            MountOption::FSName(source.clone()),
            MountOption::Subtype(MOUNT_SUBTYPE.to_owned()),
            // The view advertises the owner's original modes while the
            // private lower inodes remain frozen. Kernel permission checks
            // must enforce those advertised modes for other local users.
            MountOption::DefaultPermissions,
        ];
        let session = fuser::spawn_mount(view, &mountpoint, &config)
            .context("mount guarded worktree view")?;
        let mounted = mounted_filesystem(&mountpoint)?;
        ensure!(
            mounted
                .as_ref()
                .is_some_and(|mounted| mounted.matches_guarded(&source)),
            "guarded mount did not appear with its claimed identity: {mounted:?}"
        );
        ensure!(
            control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
                .get_record(MOUNT_RETIRE_KIND, manifest.anchor_id.as_bytes())?
                .is_none(),
            "guarded mount was retired while starting"
        );
        Ok(Self {
            session: Some(session),
            mountpoint,
            source,
        })
    }

    pub fn check_health(&self) -> anyhow::Result<()> {
        ensure!(
            !self
                .session
                .as_ref()
                .context("guarded FUSE worker is stopped")?
                .guard
                .is_finished(),
            "guarded FUSE worker exited"
        );
        ensure!(
            mounted_filesystem(&self.mountpoint)?
                .is_some_and(|mounted| mounted.matches_guarded(&self.source)),
            "guarded FUSE mount disappeared or changed"
        );
        fs::metadata(&self.mountpoint).context("guarded FUSE view is not responding")?;
        Ok(())
    }

    /// Reconstruct the current visible namespace after the view has stopped.
    /// This is local, verified input for a future signed owner revision; it
    /// does not itself make the mutable view seed-recoverable.
    pub fn snapshot_stopped(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedViewMetadataV1> {
        Self::with_stopped_view(anchor_id, control, |view, _, _| {
            view.verified_metadata_snapshot(anchor_id)
        })
    }

    /// Capture a visible file from a stopped view into a second guarded
    /// anchor. Remount replays an interrupted capture and keeps the file's
    /// visible mode while the new anchor is frozen. This does not publish a
    /// signed owner revision or release any historical anchor.
    pub fn capture_stopped_file(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
        relative_path: impl AsRef<Path>,
    ) -> anyhow::Result<FileAnchorManifest> {
        let relative_path = relative_path.as_ref().to_path_buf();
        Self::with_stopped_view(anchor_id, control, |view, claim, _| {
            view.capture_stopped_file(&claim.lower_root, &relative_path)
        })
    }

    /// Freeze every visible file under one stopped-mount fence. An unchanged
    /// file may reuse its original root anchor; an edited or newly created
    /// file gets a durable per-inode guard before this method returns.
    pub fn capture_stopped_view(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        let control_for_capture = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, claim, original| {
            Self::capture_stopped_view_inside(view, claim, original, &control_for_capture, None)
        })
    }

    /// Reserve a stopped view's exact visible metadata for a revision attempt.
    /// Remount refuses a prepared attempt until `finish_stopped_capture` has
    /// durably frozen every file, including after a process crash.
    pub fn prepare_stopped_capture(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedViewMetadataV1> {
        ensure!(!attempt_id.is_nil(), "guarded capture attempt ID is nil");
        let control_for_prepare = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, _, _| {
            let metadata = view.verified_metadata_snapshot(anchor_id)?;
            let store = control_for_prepare
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            if let Some(bytes) = store.get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())? {
                let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
                intent.validate(attempt_id.as_bytes())?;
                ensure!(
                    intent.root_anchor_id == anchor_id && intent.metadata == metadata,
                    "guarded capture attempt changed its visible metadata"
                );
                return Ok(metadata);
            }
            ensure!(
                pending_stopped_capture_attempts(&store, anchor_id)?.is_empty(),
                "another guarded capture attempt is still prepared"
            );
            let intent = StoppedCaptureIntent {
                format_version: 1,
                attempt_id,
                root_anchor_id: anchor_id,
                metadata: metadata.clone(),
                published: None,
            };
            let bytes = mb_core::canonical_bytes(&intent)?;
            ensure!(
                bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "guarded capture intent exceeds its catalog bound"
            );
            ensure!(store.put_record_if_absent(
                STOPPED_CAPTURE_KIND,
                attempt_id.as_bytes(),
                &bytes,
            )?);
            Ok(metadata)
        })
    }

    /// Complete a prepared attempt under the same stopped-view fence. A
    /// published retry reads only immutable anchors, so later view edits do
    /// not change the attempt's bytes.
    pub fn finish_stopped_capture(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        let prepared_bytes = {
            let store = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let bytes = store
                .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
                .context("guarded capture attempt was not prepared")?;
            let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
            intent.validate(attempt_id.as_bytes())?;
            ensure!(
                intent.root_anchor_id == anchor_id,
                "guarded capture attempt belongs to another root"
            );
            if let Some(capture) = intent.published {
                capture.verify()?;
                return Ok(capture);
            }
            bytes
        };
        let control_for_capture = Arc::clone(&control);
        Self::with_stopped_view(anchor_id, control, |view, claim, original| {
            let intent: StoppedCaptureIntent = mb_core::decode_canonical(&prepared_bytes)?;
            let capture = Self::capture_stopped_view_inside(
                view,
                claim,
                original,
                &control_for_capture,
                Some(&intent.metadata),
            )?;
            let mut published = intent;
            published.published = Some(capture.clone());
            let published_bytes = mb_core::canonical_bytes(&published)?;
            ensure!(
                published_bytes.len() <= STOPPED_CAPTURE_MAX_BYTES,
                "published guarded capture exceeds its local bound"
            );
            let store = control_for_capture
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            store.replace_record_if_value(
                STOPPED_CAPTURE_KIND,
                attempt_id.as_bytes(),
                &prepared_bytes,
                &published_bytes,
            )?;
            Ok(capture)
        })
    }

    pub fn capture_stopped_view_for_attempt(
        anchor_id: Uuid,
        attempt_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        if control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
            .is_none()
        {
            Self::prepare_stopped_capture(anchor_id, attempt_id, Arc::clone(&control))?;
        }
        Self::finish_stopped_capture(anchor_id, attempt_id, control)
    }

    /// The revision owner calls this only after its signed revision has taken
    /// over every anchor pin, or after proving the attempt is unreferenced.
    pub fn release_stopped_capture_unreferenced(
        attempt_id: Uuid,
        control: &ControlStore,
    ) -> anyhow::Result<()> {
        let bytes = control
            .get_record(STOPPED_CAPTURE_KIND, attempt_id.as_bytes())?
            .context("guarded stopped capture has no durable intent")?;
        let intent: StoppedCaptureIntent = mb_core::decode_canonical(&bytes)?;
        intent.validate(attempt_id.as_bytes())?;
        ensure!(
            intent.published.is_some(),
            "prepared guarded capture must finish before release"
        );
        control.delete_record_if_value(STOPPED_CAPTURE_KIND, attempt_id.as_bytes(), &bytes)?;
        Ok(())
    }

    fn capture_stopped_view_inside(
        view: &GuardedProbeView,
        claim: &MountClaim,
        original: &StableAnchorManifest,
        control_for_capture: &Arc<Mutex<ControlStore>>,
        expected_metadata: Option<&GuardedViewMetadataV1>,
    ) -> anyhow::Result<GuardedStoppedCaptureV1> {
        let before = view.verified_metadata_snapshot(original.anchor_id)?;
        ensure!(
            expected_metadata.is_none_or(|expected| expected == &before),
            "guarded stopped capture metadata changed before replay"
        );
        let root_plan = {
            let store = control_for_capture
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            GuardedRootCapturePlan::load_active_for_view(&store, original)?
        };
        let mut original_files = BTreeMap::new();
        for entry in &original.entries {
            if let CapturedEntry::FileV2 {
                path,
                logical_len,
                native_id,
                ..
            } = entry
            {
                ensure!(
                    original_files
                        .insert(*native_id, (path, *logical_len))
                        .is_none(),
                    "guarded root has duplicate captured file identity"
                );
            }
        }
        let mut files = Vec::new();
        for entry in before
            .entries
            .iter()
            .filter(|entry| entry.kind == GuardedViewEntryKind::File)
        {
            let path = PathBuf::from(OsString::from_vec(entry.path.clone()));
            let reusable_original =
                if let Some((captured_path, captured_len)) = original_files.get(&entry.native_id) {
                    let proof = {
                        let store = control_for_capture
                            .lock()
                            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                        if root_plan.file_has_editable_inode(&store, captured_path)? {
                            None
                        } else {
                            Some(root_plan.captured_file_content_proof(&store, captured_path)?)
                        }
                    };
                    if let Some(proof) = proof {
                        ensure!(
                            *captured_len == entry.logical_len
                                && proof.logical_len == entry.logical_len,
                            "unchanged guarded file has another length"
                        );
                        Some((original.file_locator((*captured_path).clone())?, proof))
                    } else {
                        None
                    }
                } else {
                    None
                };
            let (locator, expected_hash, expected_extents) =
                if let Some((locator, proof)) = reusable_original {
                    (locator, proof.content_hash, Some(proof.data_extents))
                } else {
                    let manifest =
                        view.capture_stopped_file_after_full_check(&claim.lower_root, &path)?;
                    ensure!(
                        manifest.logical_len == entry.logical_len,
                        "recaptured guarded file has another length"
                    );
                    (manifest.file_locator(), manifest.content_hash, None)
                };
            let mut file = locator.open()?;
            ensure!(
                file.metadata()?.len() == entry.logical_len,
                "guarded anchor length changed during stopped capture"
            );
            let mut hasher = blake3::Hasher::new();
            let mut read_len = 0_u64;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
                read_len += read as u64;
            }
            ensure!(
                read_len == entry.logical_len,
                "guarded anchor length changed while reading"
            );
            let content_hash = *hasher.finalize().as_bytes();
            ensure!(
                expected_hash == content_hash,
                "guarded anchor bytes differ from their capture proof"
            );
            let data_extents = crate::anchor::file_data_extents(&file, entry.logical_len)?;
            ensure!(
                expected_extents.is_none_or(|expected| expected == data_extents),
                "guarded anchor extents differ from their capture proof"
            );
            files.push(GuardedStoppedFileV1 {
                path: entry.path.clone(),
                native_id: entry.native_id,
                locator,
                logical_len: entry.logical_len,
                content_hash,
                data_extents,
            });
        }
        let after = view.verified_metadata_snapshot(original.anchor_id)?;
        ensure!(
            after == before,
            "guarded metadata changed while capturing its files"
        );
        let capture = GuardedStoppedCaptureV1 {
            format_version: 1,
            metadata: before,
            files,
        };
        ensure!(
            mb_core::canonical_bytes(&capture)?.len() <= mb_core::V1_MAX_CATALOG_BYTES,
            "guarded stopped capture exceeds its catalog bound"
        );
        Ok(capture)
    }

    fn with_stopped_view<T>(
        anchor_id: Uuid,
        control: Arc<Mutex<ControlStore>>,
        operation: impl FnOnce(
            &GuardedProbeView,
            &MountClaim,
            &StableAnchorManifest,
        ) -> anyhow::Result<T>,
    ) -> anyhow::Result<T> {
        let _lifecycle = MOUNT_LIFECYCLE
            .lock()
            .map_err(|_| io::Error::other("guarded mount lifecycle lock is poisoned"))?;
        let (claim_bytes, claim, manifest) = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            let bytes = control
                .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
                .context("guarded view has no mount claim")?;
            let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
            ensure!(
                claim.version == 1 && claim.anchor_id == anchor_id,
                "guarded mount claim changed"
            );
            ensure!(
                control
                    .get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
                    .is_none(),
                "guarded mount has been retired"
            );
            let manifest = GuardedRootCapturePlan::load_published_manifest(&control, anchor_id)?;
            let plan = GuardedRootCapturePlan::load_active_for_view(&control, &manifest)?;
            ensure!(
                claim.lower_root == plan.source_root()
                    && claim.lower_id == plan.source_root_identity(),
                "guarded mount claim differs from its source plan"
            );
            (bytes, claim, manifest)
        };
        if let Some(mounted) = mounted_filesystem(&claim.mountpoint)? {
            ensure!(
                mounted.matches_guarded(&mount_source(anchor_id)),
                "another filesystem occupies the guarded mountpoint"
            );
            match fs::metadata(&claim.mountpoint) {
                Ok(_) => anyhow::bail!("guarded view must stop before inspecting its source"),
                Err(error) if error.raw_os_error() == Some(libc::ENOTCONN) => {
                    let path = CString::new(claim.mountpoint.as_os_str().as_bytes())?;
                    if unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) } < 0 {
                        return Err(io::Error::last_os_error())
                            .context("detach dead guarded mount before stopped capture");
                    }
                }
                Err(error) => return Err(error).context("check claimed guarded mount"),
            }
        }
        let lower = PinnedDirectory::open(&claim.lower_root)?;
        let placeholder = PinnedDirectory::open(&claim.mountpoint)?;
        ensure!(
            lower.identity()? == claim.lower_id && placeholder.identity()? == claim.mountpoint_id,
            "guarded mount paths changed before inspecting its source"
        );
        let view = GuardedProbeView::from_guarded_capture(
            &manifest,
            Arc::clone(&control),
            claim.view_uid,
            claim.view_gid,
        )?;
        let value = operation(&view, &claim, &manifest)?;
        let control = control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
        ensure!(
            control.get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())? == Some(claim_bytes)
                && control
                    .get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())?
                    .is_none()
                && mounted_filesystem(&claim.mountpoint)?.is_none(),
            "guarded mount claim changed during stopped-view operation"
        );
        Ok(value)
    }

    pub fn stop(mut self) -> io::Result<()> {
        let lifecycle = MOUNT_LIFECYCLE
            .lock()
            .map_err(|_| io::Error::other("guarded mount lifecycle lock is poisoned"))?;
        let session = self
            .session
            .take()
            .ok_or_else(|| io::Error::other("guarded FUSE worker is already stopped"))?;
        let result = session.umount_and_join();
        drop(lifecycle);
        result
    }
}

impl Drop for GuardedViewMount {
    fn drop(&mut self) {
        if self.session.is_none() {
            return;
        }
        let _lifecycle = MOUNT_LIFECYCLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Join the worker as well as unmounting, so a later snapshot cannot
        // observe a lower-tree mutation from an in-flight FUSE request.
        let _ = self.session.take().unwrap().umount_and_join();
    }
}

pub(crate) fn require_mount_claim_retired(
    control: &ControlStore,
    anchor_id: Uuid,
) -> anyhow::Result<()> {
    ensure!(
        control
            .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
            .is_none(),
        "guarded mount claim must be retired before its anchors"
    );
    if let Some(bytes) = control.get_record(MOUNT_RETIRE_KIND, anchor_id.as_bytes())? {
        let claim: MountClaim = mb_core::decode_canonical(&bytes)?;
        ensure!(
            claim.version == 1 && claim.anchor_id == anchor_id,
            "guarded mount retirement marker changed"
        );
        ensure!(
            mounted_filesystem(&claim.mountpoint)?.is_none(),
            "guarded view remains mounted during anchor retirement"
        );
    }
    Ok(())
}

pub(crate) fn mount_claim_exists(control: &ControlStore, anchor_id: Uuid) -> anyhow::Result<bool> {
    Ok(control
        .get_record(MOUNT_CLAIM_KIND, anchor_id.as_bytes())?
        .is_some())
}

fn mount_source(anchor_id: Uuid) -> String {
    format!("mutualbackup-guarded-{anchor_id}")
}

impl MountedFilesystem {
    fn matches_guarded(&self, source: &str) -> bool {
        // The pure FUSE mount path reports `fuse` even when a subtype was
        // requested; fusermount may report `fuse.<subtype>` instead.
        (self.filesystem_type == "fuse" || self.filesystem_type == format!("fuse.{MOUNT_SUBTYPE}"))
            && self.source == source
    }
}

fn canonical_mountpoint(path: &Path) -> anyhow::Result<PathBuf> {
    let name = path.file_name().context("guarded mountpoint has no name")?;
    ensure!(
        path.components().next_back() == Some(Component::Normal(name)),
        "guarded mountpoint must name a directory"
    );
    Ok(path
        .parent()
        .context("guarded mountpoint has no parent")?
        .canonicalize()?
        .join(name))
}

fn mounted_filesystem(mountpoint: &Path) -> anyhow::Result<Option<MountedFilesystem>> {
    let text = fs::read_to_string("/proc/self/mountinfo")?;
    let mut found = None;
    for line in text.lines() {
        let (front, back) = line
            .split_once(" - ")
            .context("invalid Linux mountinfo separator")?;
        let encoded_path = front
            .split_ascii_whitespace()
            .nth(4)
            .context("invalid Linux mountinfo mountpoint")?;
        if decode_mountinfo_path(encoded_path)? != mountpoint {
            continue;
        }
        let mut fields = back.split_ascii_whitespace();
        let filesystem_type = fields.next().context("missing mountinfo filesystem type")?;
        let source = fields.next().context("missing mountinfo source")?;
        ensure!(found.is_none(), "guarded mountpoint has stacked mounts");
        found = Some(MountedFilesystem {
            filesystem_type: filesystem_type.to_owned(),
            source: source.to_owned(),
        });
    }
    Ok(found)
}

fn decode_mountinfo_path(encoded: &str) -> anyhow::Result<PathBuf> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            ensure!(index + 3 < bytes.len(), "truncated mountinfo path escape");
            let digits = &bytes[index + 1..index + 4];
            ensure!(
                digits.iter().all(|digit| (b'0'..=b'7').contains(digit)),
                "invalid mountinfo path escape"
            );
            decoded.push((digits[0] - b'0') * 64 + (digits[1] - b'0') * 8 + (digits[2] - b'0'));
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    Ok(PathBuf::from(OsString::from_vec(decoded)))
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mb_core::{KeyMaterial, Seed};

    use crate::{ControlStore, GuardedRootCapturePlan};

    use super::{
        GuardedStoppedCaptureV1, GuardedViewMount, MOUNT_CLAIM_KIND, MOUNT_RETIRE_KIND,
        decode_mountinfo_path,
    };

    #[test]
    fn mountinfo_paths_decode_spaces_and_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;

        let path = decode_mountinfo_path("/one\\040two/odd\\377").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/one two/odd\xff");
        assert!(decode_mountinfo_path("/broken\\08").is_err());
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and fanotify permission events"]
    fn guarded_mount_refuses_mutable_private_lower_inodes() {
        for unsafe_case in [
            "file-owner",
            "directory-owner",
            "directory-group-write",
            "directory-world-search",
            "unknown-lower-entry",
        ] {
            let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
                Some(root) => tempfile::Builder::new()
                    .prefix("mb-guarded-owner-")
                    .tempdir_in(root)
                    .unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let lower = area.path().join("lower");
            let mountpoint = area.path().join("view");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(&mountpoint).unwrap();
            fs::create_dir(lower.join("nested")).unwrap();
            fs::write(lower.join("sample"), b"frozen bytes").unwrap();
            fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
            if unsafe_case == "directory-group-write" {
                fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o775))
                    .unwrap();
            } else if unsafe_case == "directory-world-search" {
                fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o711))
                    .unwrap();
            } else if unsafe_case != "unknown-lower-entry" {
                let owned = lower.join(if unsafe_case == "file-owner" {
                    "sample"
                } else {
                    "nested"
                });
                let path = CString::new(owned.as_os_str().as_bytes()).unwrap();
                // SAFETY: this test owns the NUL-free disposable lower path.
                assert_eq!(unsafe { libc::chown(path.as_ptr(), 65534, 65534) }, 0);
            }

            let keys = KeyMaterial::from_seed(&Seed::from_bytes([112; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
            ));
            let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
            let manifest = plan.capture(&control.lock().unwrap()).unwrap();
            if unsafe_case == "unknown-lower-entry" {
                fs::write(lower.join("nested/unknown"), b"outside the capture plan").unwrap();
            }
            // A first-mount preflight must reject the unsafe nested directory
            // before it tries to decode or replay any view namespace intent.
            let pending_rename = (unsafe_case == "directory-world-search"
                || unsafe_case == "unknown-lower-entry")
                .then(|| {
                    let mut id = manifest.anchor_id.as_bytes().to_vec();
                    id.extend_from_slice(&2_u64.to_le_bytes());
                    control
                        .lock()
                        .unwrap()
                        .put_record("guarded-view-directory-rename-v1", &id, &[0xff])
                        .unwrap();
                    id
                });
            let error = match GuardedViewMount::start(
                &manifest,
                Arc::clone(&control),
                &mountpoint,
                65534,
                65534,
            ) {
                Ok(mount) => {
                    mount.stop().unwrap();
                    panic!("mutable private lower {unsafe_case} was mounted")
                }
                Err(error) => error,
            };
            let expected = if unsafe_case == "unknown-lower-entry" {
                "unexpected or missing entry"
            } else {
                "view owner"
            };
            assert!(error.to_string().contains(expected), "{error:#}");
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(
                control
                    .lock()
                    .unwrap()
                    .records("guarded-view-namespace-v1")
                    .unwrap()
                    .is_empty(),
                "unsafe lower {unsafe_case} replayed view namespace state"
            );
            if let Some(id) = pending_rename {
                assert_eq!(
                    control
                        .lock()
                        .unwrap()
                        .get_record("guarded-view-directory-rename-v1", &id)
                        .unwrap(),
                    Some(vec![0xff])
                );
                assert!(
                    control
                        .lock()
                        .unwrap()
                        .delete_record("guarded-view-directory-rename-v1", &id)
                        .unwrap()
                );
            }
            if unsafe_case == "unknown-lower-entry" {
                fs::remove_file(lower.join("nested/unknown")).unwrap();
            }
            plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn guarded_mount_isolates_a_preopened_read_only_lower_descriptor() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-held-fd-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        let nested = lower.join("nested");
        fs::create_dir(&nested).unwrap();
        fs::write(nested.join("known"), b"nested bytes").unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let original = b"preopened\r\n\0source";
        let source = lower.join("sample");
        fs::write(&source, original).unwrap();
        let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
        // SAFETY: this test owns the NUL-free disposable source path.
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        fs::set_permissions(&source, fs::Permissions::from_mode(0o644)).unwrap();

        let keys = KeyMaterial::from_seed(&Seed::from_bytes([113; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        assert_eq!(
            fs::metadata(area.path()).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&lower).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(fs::metadata(&source).unwrap().uid(), 65534);
        assert_eq!(
            fs::metadata(&source).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let mut child = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-u")
            .arg("-c")
            .arg(
                r#"import errno, os, sys
fd = os.open(sys.argv[1], os.O_RDONLY)
dirfd = os.open(os.path.dirname(sys.argv[1]), os.O_RDONLY | os.O_DIRECTORY)
nested_fd = os.open(sys.argv[3], os.O_RDONLY | os.O_DIRECTORY)
print('READY', flush=True)
assert sys.stdin.readline() == 'continue\n'
for operation in (
    lambda: os.fchmod(fd, 0o600),
    lambda: os.open('/proc/self/fd/%d' % fd, os.O_WRONLY),
    lambda: os.open(sys.argv[1], os.O_RDONLY),
    lambda: os.fchmod(dirfd, 0o777),
    lambda: os.open('sample', os.O_RDONLY, dir_fd=dirfd),
    lambda: os.open('known', os.O_RDONLY, dir_fd=nested_fd),
):
    try:
        operation()
    except OSError as error:
        assert error.errno in (errno.EACCES, errno.EPERM), error
    else:
        raise AssertionError('private lower inode remained accessible')
view = os.open(sys.argv[2], os.O_RDWR)
os.pwrite(view, b'EDIT', 0)
os.fsync(view)
os.close(view)
os.close(fd)
os.close(dirfd)
os.close(nested_fd)
print('DONE', flush=True)
"#,
            )
            .arg(&source)
            .arg(mountpoint.join("sample"))
            .arg(&nested)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut output = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        if line != "READY\n" {
            let child_output = child.wait_with_output().unwrap();
            panic!(
                "held-descriptor child did not open the lower file: {line:?}, {}",
                String::from_utf8_lossy(&child_output.stderr)
            );
        }

        let manifest = plan.capture(&control.lock().unwrap()).unwrap();
        // This is the isolation state the enrollment transition must reach
        // durably before exposing a view. The test holds an older descriptor
        // across that transition; enrollment itself remains gated.
        assert_eq!(unsafe { libc::chown(source_path.as_ptr(), 0, 0) }, 0);
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(b"continue\n")
            .unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        let status = child.wait().unwrap();
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "held-descriptor child failed: {stderr}");
        assert_eq!(line, "DONE\n");

        let mut changed = original.to_vec();
        changed[..4].copy_from_slice(b"EDIT");
        assert_eq!(fs::read(&source).unwrap(), changed);
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut frozen = Vec::new();
        anchor.read_to_end(&mut frozen).unwrap();
        assert_eq!(frozen, original);
        mount.stop().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &control.lock().unwrap()).unwrap();
        plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn frozen_file_renamed_through_view_retires_at_its_recorded_path() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-renamed-retire-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let public = tempfile::Builder::new()
            .prefix("mb-guarded-renamed-view-")
            .tempdir_in(area.path().parent().unwrap())
            .unwrap();
        fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = public.path().join("view");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let source = lower.join("sample");
        let original = b"frozen\r\n\0bytes";
        fs::write(&source, original).unwrap();
        let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([126; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
            .unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        let rename = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
            .arg(mountpoint.join("sample"))
            .arg(mountpoint.join("renamed"))
            .output()
            .unwrap();
        assert!(rename.status.success(), "{rename:?}");
        assert_eq!(fs::read(lower.join("renamed")).unwrap(), original);
        assert_eq!(fs::metadata(lower.join("renamed")).unwrap().uid(), 0);
        mount.stop().unwrap();
        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(fs::read(mountpoint.join("renamed")).unwrap(), original);
        assert!(!mountpoint.join("sample").exists());
        remounted.stop().unwrap();
        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        let mut namespace_id = manifest.anchor_id.as_bytes().to_vec();
        namespace_id.extend_from_slice(&2_u64.to_le_bytes());
        let namespace = store
            .get_record("guarded-view-namespace-v1", &namespace_id)
            .unwrap()
            .unwrap();
        store
            .put_record("guarded-view-namespace-v1", &namespace_id, &[0xff])
            .unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        store
            .put_record("guarded-view-namespace-v1", &namespace_id, &namespace)
            .unwrap();
        store
            .put_record("guarded-view-create-v1", &namespace_id, &[0xff])
            .unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        store
            .delete_record("guarded-view-create-v1", &namespace_id)
            .unwrap();
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut retained = Vec::new();
        anchor.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(lower.join("renamed")).unwrap(), original);
        let restored = fs::metadata(lower.join("renamed")).unwrap();
        assert_eq!((restored.uid(), restored.gid()), (65534, 65534));
        assert_eq!(restored.permissions().mode() & 0o7777, 0o644);
        assert!(!source.exists());
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn captured_directory_move_restores_nested_owners_at_current_paths() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-directory-retire-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        let public = tempfile::Builder::new()
            .prefix("mb-guarded-directory-view-")
            .tempdir_in(area.path().parent().unwrap())
            .unwrap();
        fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let nested = lower.join("nested");
        let mountpoint = public.path().join("view");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o750)).unwrap();
        let nested_path = CString::new(nested.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(nested_path.as_ptr(), 65533, 65533) },
            0
        );
        let source = nested.join("sample");
        let original = b"nested\r\n\0bytes";
        fs::write(&source, original).unwrap();
        let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([127; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
            .unwrap();
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        let rename = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
            .arg(mountpoint.join("nested"))
            .arg(mountpoint.join("moved"))
            .output()
            .unwrap();
        assert!(rename.status.success(), "{rename:?}");
        assert_eq!(fs::read(lower.join("moved/sample")).unwrap(), original);
        mount.stop().unwrap();
        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(fs::read(mountpoint.join("moved/sample")).unwrap(), original);
        remounted.stop().unwrap();
        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        let mut directory_id = manifest.anchor_id.as_bytes().to_vec();
        directory_id.extend_from_slice(&2_u64.to_le_bytes());
        let directory_record = store
            .get_record("guarded-view-directory-v1", &directory_id)
            .unwrap()
            .unwrap();
        store
            .put_record("guarded-view-directory-v1", &directory_id, &[0xff])
            .unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        store
            .put_record(
                "guarded-view-directory-v1",
                &directory_id,
                &directory_record,
            )
            .unwrap();
        fs::rename(lower.join("moved"), lower.join("held")).unwrap();
        fs::create_dir(lower.join("moved")).unwrap();
        assert!(plan.discard_unreferenced(&store).is_err());
        fs::remove_dir(lower.join("moved")).unwrap();
        fs::rename(lower.join("held"), lower.join("moved")).unwrap();
        let moved_path = CString::new(lower.join("moved").as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(moved_path.as_ptr(), 65533, 65533) }, 0);
        assert_eq!(
            fs::metadata(lower.join("moved"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let mut anchor = manifest
            .file_locator("nested/sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut retained = Vec::new();
        anchor.read_to_end(&mut retained).unwrap();
        assert_eq!(retained, original);
        plan.discard_unreferenced(&store).unwrap();
        assert_eq!(fs::read(lower.join("moved/sample")).unwrap(), original);
        let restored_file = fs::metadata(lower.join("moved/sample")).unwrap();
        assert_eq!((restored_file.uid(), restored_file.gid()), (65534, 65534));
        assert_eq!(restored_file.permissions().mode() & 0o7777, 0o644);
        let restored_directory = fs::metadata(lower.join("moved")).unwrap();
        assert_eq!(
            (restored_directory.uid(), restored_directory.gid()),
            (65533, 65533)
        );
        assert_eq!(restored_directory.permissions().mode() & 0o7777, 0o750);
        assert!(!nested.exists());
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn removed_or_replaced_captured_directory_retires_without_restoring_old_inode() {
        for replace in [false, true] {
            let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
                Some(root) => tempfile::Builder::new()
                    .prefix("mb-guarded-removed-dir-")
                    .tempdir_in(root)
                    .unwrap(),
                None => tempfile::tempdir().unwrap(),
            };
            let public = tempfile::Builder::new()
                .prefix("mb-guarded-removed-view-")
                .tempdir_in(area.path().parent().unwrap())
                .unwrap();
            fs::set_permissions(public.path(), fs::Permissions::from_mode(0o755)).unwrap();
            let lower = area.path().join("lower");
            let mountpoint = public.path().join("view");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(&mountpoint).unwrap();
            fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
            let target = lower.join("target");
            fs::create_dir(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o750)).unwrap();
            let target_path = CString::new(target.as_os_str().as_bytes()).unwrap();
            assert_eq!(
                unsafe { libc::chown(target_path.as_ptr(), 65533, 65533) },
                0
            );
            if replace {
                let source = lower.join("source");
                fs::create_dir(&source).unwrap();
                fs::set_permissions(&source, fs::Permissions::from_mode(0o710)).unwrap();
                let source_path = CString::new(source.as_os_str().as_bytes()).unwrap();
                assert_eq!(
                    unsafe { libc::chown(source_path.as_ptr(), 65532, 65532) },
                    0
                );
            }
            let kept = lower.join("kept");
            let original = b"retained\r\n\0bytes";
            fs::write(&kept, original).unwrap();
            let kept_path = CString::new(kept.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(kept_path.as_ptr(), 65534, 65534) }, 0);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([128; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
            ));
            let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
            let manifest = plan
                .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
                .unwrap();
            plan.isolate_lower_directories(&control.lock().unwrap(), &manifest)
                .unwrap();
            let mount =
                GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                    .unwrap();
            let operation = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg(if replace {
                    "import os,sys; os.rename(sys.argv[1],sys.argv[2])"
                } else {
                    "import os,sys; os.rmdir(sys.argv[2])"
                })
                .arg(mountpoint.join("source"))
                .arg(mountpoint.join("target"))
                .output()
                .unwrap();
            assert!(operation.status.success(), "{operation:?}");
            mount.stop().unwrap();
            let remounted =
                GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control))
                    .unwrap();
            assert_eq!(mountpoint.join("target").exists(), replace);
            remounted.stop().unwrap();
            let store = control.lock().unwrap();
            GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
            plan.discard_unreferenced(&store).unwrap();
            assert_eq!(target.exists(), replace);
            if replace {
                let restored = fs::metadata(&target).unwrap();
                assert_eq!((restored.uid(), restored.gid()), (65532, 65532));
                assert_eq!(restored.permissions().mode() & 0o7777, 0o710);
                assert!(!lower.join("source").exists());
            }
            assert_eq!(fs::read(&kept).unwrap(), original);
            assert_eq!(fs::metadata(&kept).unwrap().uid(), 65534);
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn guarded_mount_claim_survives_remount_and_rejects_replaced_placeholder() {
        const CHILD_ROOT: &str = "MUTUALBACKUP_GUARDED_MOUNT_CHILD_ROOT";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([111; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(root.join("control/control.db"), &keys).unwrap(),
            ));
            let anchor_id: uuid::Uuid = fs::read_to_string(root.join("anchor-id"))
                .unwrap()
                .parse()
                .unwrap();
            let _mount = GuardedViewMount::recover_claimed(anchor_id, control).unwrap();
            fs::write(root.join("ready"), b"mounted").unwrap();
            loop {
                std::thread::sleep(Duration::from_secs(1));
            }
        }

        struct DeadMount {
            child: Child,
            mountpoint: PathBuf,
        }
        impl Drop for DeadMount {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                let path = CString::new(self.mountpoint.as_os_str().as_bytes()).unwrap();
                // SAFETY: this test's private mountpoint has no embedded NUL.
                let _ = unsafe { libc::umount2(path.as_ptr(), libc::MNT_DETACH) };
            }
        }

        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-mount-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        let control_path = control_dir.join("control.db");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let exact_bytes = b"guarded\r\n\0source\n";
        fs::create_dir(lower.join("captured")).unwrap();
        fs::set_permissions(lower.join("captured"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(lower.join("sample"), exact_bytes).unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();

        let keys = KeyMaterial::from_seed(&Seed::from_bytes([111; 32]));
        let control = ControlStore::open(&control_path, &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan
            .capture_private_file_owners(&control, 65534, 0, 0)
            .unwrap();
        plan.isolate_lower_directories(&control, &manifest).unwrap();
        let control = Arc::new(Mutex::new(control));
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        mount.check_health().unwrap();
        assert!(
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).is_err()
        );
        {
            let store = control.lock().unwrap();
            assert!(plan.discard_unreferenced(&store).is_err());
            assert!(GuardedViewMount::retire_claim(manifest.anchor_id, &store).is_err());
        }
        assert!(
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534,)
                .is_err()
        );
        let user_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(user_read.status.success(), "{user_read:?}");
        assert_eq!(user_read.stdout, exact_bytes);
        let unrelated_read = Command::new("cat")
            .uid(65533)
            .gid(65533)
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(!unrelated_read.status.success());
        let private_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(lower.join("sample"))
            .output()
            .unwrap();
        assert!(!private_read.status.success());
        let owner_write = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.pwrite(fd,b'EDIT',0); os.fsync(fd); os.close(fd)")
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(owner_write.status.success(), "{owner_write:?}");
        let mut edited = exact_bytes.to_vec();
        edited[..4].copy_from_slice(b"EDIT");
        assert_eq!(fs::read(lower.join("sample")).unwrap(), edited);
        let mut anchor = manifest
            .file_locator("sample".to_owned())
            .unwrap()
            .open()
            .unwrap();
        let mut frozen = Vec::new();
        anchor.read_to_end(&mut frozen).unwrap();
        assert_eq!(frozen, exact_bytes);
        let public_directory = mountpoint.join("public");
        let user_mkdir = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.mkdir(sys.argv[1],0o777); os.chmod(sys.argv[1],0o777)")
            .arg(&public_directory)
            .output()
            .unwrap();
        assert!(user_mkdir.status.success(), "{user_mkdir:?}");
        assert_eq!(
            fs::metadata(&public_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
        assert_eq!(
            fs::metadata(lower.join("public"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let visible_modes = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.chmod(sys.argv[1],0o751); os.chmod(sys.argv[2],0o711); os.chmod(sys.argv[3],0o640)")
            .arg(&mountpoint)
            .arg(mountpoint.join("captured"))
            .arg(mountpoint.join("sample"))
            .output()
            .unwrap();
        assert!(visible_modes.status.success(), "{visible_modes:?}");
        mount.stop().unwrap();
        let snapshot =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        let encoded = mb_core::canonical_bytes(&snapshot).unwrap();
        assert_eq!(
            mb_core::decode_canonical::<crate::GuardedViewMetadataV1>(&encoded).unwrap(),
            snapshot
        );
        assert_eq!(snapshot.format_version, 1);
        assert_eq!(snapshot.anchor_id, manifest.anchor_id);
        assert_eq!(snapshot.root_mode, 0o751);
        assert_eq!((snapshot.root_uid, snapshot.root_gid), (65534, 65534));
        assert_eq!(
            snapshot.lower_root_id,
            crate::PinnedDirectory::open(&lower)
                .unwrap()
                .identity()
                .unwrap()
        );
        assert_eq!(snapshot.entries.len(), 3);
        assert_eq!(snapshot.entries[0].path, b"captured");
        assert_eq!(
            snapshot.entries[0].kind,
            crate::GuardedViewEntryKind::Directory
        );
        assert_eq!(snapshot.entries[0].mode, 0o711);
        assert_eq!(
            (snapshot.entries[0].uid, snapshot.entries[0].gid),
            (65534, 65534)
        );
        assert_eq!(snapshot.entries[1].path, b"public");
        assert_eq!(
            snapshot.entries[1].kind,
            crate::GuardedViewEntryKind::Directory
        );
        assert_eq!(snapshot.entries[1].mode, 0o777);
        assert_eq!(
            (snapshot.entries[1].uid, snapshot.entries[1].gid),
            (65534, 65534)
        );
        assert_eq!(snapshot.entries[2].path, b"sample");
        assert_eq!(snapshot.entries[2].kind, crate::GuardedViewEntryKind::File);
        assert_eq!(snapshot.entries[2].mode, 0o640);
        assert_eq!(
            (snapshot.entries[2].uid, snapshot.entries[2].gid),
            (65534, 65534)
        );
        assert_eq!(snapshot.entries[2].logical_len, edited.len() as u64);
        assert_eq!(
            snapshot.entries[2].native_id.inode,
            fs::metadata(lower.join("sample")).unwrap().ino()
        );

        for unexpected in [lower.join("public/unknown"), lower.join("unknown")] {
            fs::write(&unexpected, b"outside the guarded view").unwrap();
            assert!(
                GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control))
                    .is_err()
            );
            let error =
                match GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)) {
                    Ok(mount) => {
                        mount.stop().unwrap();
                        panic!("remount admitted an unrecorded lower entry")
                    }
                    Err(error) => error,
                };
            assert!(
                error.to_string().contains("unrecorded inode before replay"),
                "{error:#}"
            );
            assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
            fs::remove_file(unexpected).unwrap();
        }
        fs::rename(lower.join("sample"), lower.join("wrong-recorded-inode")).unwrap();
        let error =
            match GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)) {
                Ok(mount) => {
                    mount.stop().unwrap();
                    panic!("remount admitted a recorded inode at an unrecorded path")
                }
                Err(error) => error,
            };
        assert!(
            error.to_string().contains("ungranted path before replay"),
            "{error:#}"
        );
        assert!(fs::read_dir(&mountpoint).unwrap().next().is_none());
        fs::rename(lower.join("wrong-recorded-inode"), lower.join("sample")).unwrap();

        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let reopened_snapshot =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert_eq!(reopened_snapshot.root_mode, snapshot.root_mode);
        for (before, after) in snapshot.entries.iter().zip(&reopened_snapshot.entries) {
            assert_eq!(before.path, after.path);
            assert_eq!(before.kind, after.kind);
            assert_eq!(before.native_id, after.native_id);
            assert_eq!(before.mode, after.mode);
            assert_eq!(before.logical_len, after.logical_len);
        }
        assert_eq!(reopened_snapshot.entries.len(), snapshot.entries.len());

        let mut recovered_mounts =
            GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(recovered_mounts.len(), 1);
        let remounted = recovered_mounts.pop().unwrap();
        remounted.check_health().unwrap();
        assert_eq!(fs::read(mountpoint.join("sample")).unwrap(), edited);
        assert_eq!(
            fs::metadata(&public_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o777
        );
        assert_eq!(
            fs::metadata(lower.join("public"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o700
        );
        let user_rmdir = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rmdir(sys.argv[1])")
            .arg(&public_directory)
            .output()
            .unwrap();
        assert!(user_rmdir.status.success(), "{user_rmdir:?}");
        remounted.stop().unwrap();

        fs::write(
            area.path().join("anchor-id"),
            manifest.anchor_id.to_string(),
        )
        .unwrap();
        let mut dead = DeadMount {
            child: Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "guarded_mount::tests::guarded_mount_claim_survives_remount_and_rejects_replaced_placeholder",
                    "--nocapture",
                ])
                .env(CHILD_ROOT, area.path())
                .spawn()
                .unwrap(),
            mountpoint: mountpoint.clone(),
        };
        for _ in 0..200 {
            if area.path().join("ready").exists() {
                break;
            }
            assert!(dead.child.try_wait().unwrap().is_none());
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(
            area.path().join("ready").exists(),
            "child mount did not become ready"
        );
        dead.child.kill().unwrap();
        assert!(!dead.child.wait().unwrap().success());
        assert!(fs::read(mountpoint.join("sample")).is_err());
        let after_dead =
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).unwrap();
        assert!(
            after_dead
                .entries
                .iter()
                .any(|entry| entry.path == b"sample")
        );
        let mut recovered_mounts =
            GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(recovered_mounts.len(), 1);
        let recovered = recovered_mounts.pop().unwrap();
        recovered.check_health().unwrap();
        assert_eq!(fs::read(mountpoint.join("sample")).unwrap(), edited);
        recovered.stop().unwrap();
        drop(dead);

        fs::rename(&mountpoint, area.path().join("old-view")).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            GuardedViewMount::snapshot_stopped(manifest.anchor_id, Arc::clone(&control)).is_err()
        );
        assert!(
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .is_err()
        );
        fs::remove_dir(&mountpoint).unwrap();
        fs::rename(area.path().join("old-view"), &mountpoint).unwrap();
        {
            let store = control.lock().unwrap();
            assert!(plan.discard_unreferenced(&store).is_err());
            let claim = store
                .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())
                .unwrap()
                .unwrap();
            assert!(
                store
                    .put_record_if_absent(MOUNT_RETIRE_KIND, manifest.anchor_id.as_bytes(), &claim)
                    .unwrap()
            );
        }
        assert!(
            GuardedViewMount::recover_all_claimed(Arc::clone(&control))
                .unwrap()
                .is_empty()
        );
        {
            let store = control.lock().unwrap();
            assert!(
                store
                    .get_record(MOUNT_CLAIM_KIND, manifest.anchor_id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            GuardedViewMount::retire_claim(manifest.anchor_id, &store).unwrap();
        }
        assert!(
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).is_err()
        );
        plan.discard_unreferenced(&control.lock().unwrap()).unwrap();
        assert!(
            !manifest
                .area
                .path_hint
                .join(manifest.anchor_id.to_string())
                .exists()
        );
        assert_eq!(fs::read(lower.join("sample")).unwrap(), edited);
    }

    #[test]
    #[ignore = "requires root, CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn stopped_view_file_recapture_detaches_new_anchor_after_rename_and_remount() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-recapture-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(lower.join("sample"), b"first revision bytes").unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();
        let source_path = CString::new(lower.join("sample").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(source_path.as_ptr(), 65534, 65534) },
            0
        );
        let untouched_bytes = b"untouched\r\nsource";
        fs::write(lower.join("untouched"), untouched_bytes).unwrap();
        fs::set_permissions(lower.join("untouched"), fs::Permissions::from_mode(0o644)).unwrap();
        let untouched_path = CString::new(lower.join("untouched").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(untouched_path.as_ptr(), 65534, 65534) },
            0
        );
        fs::create_dir(lower.join("nested")).unwrap();
        fs::set_permissions(lower.join("nested"), fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(lower.join("nested/kept"), b"nested unchanged").unwrap();
        let nested_path = CString::new(lower.join("nested/kept").as_os_str().as_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::chown(nested_path.as_ptr(), 65534, 65534) },
            0
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([113; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let root_plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let original = root_plan
            .capture_private_file_owners(&control.lock().unwrap(), 65534, 0, 0)
            .unwrap();
        root_plan
            .isolate_lower_directories(&control.lock().unwrap(), &original)
            .unwrap();
        let first_mount =
            GuardedViewMount::start(&original, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        let edit = |path: &std::path::Path, bytes: &str| {
            let output = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.pwrite(fd,sys.argv[2].encode(),0); os.fsync(fd); os.close(fd)")
                .arg(path)
                .arg(bytes)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        };
        edit(&mountpoint.join("sample"), "EDIT1");
        let first_bytes = fs::read(lower.join("sample")).unwrap();
        first_mount.stop().unwrap();
        let anchor_bytes = |manifest: &crate::FileAnchorManifest| {
            let mut file = manifest.open_verified().unwrap();
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes).unwrap();
            bytes
        };
        let attempt_id = uuid::Uuid::new_v4();
        let prepared = GuardedViewMount::prepare_stopped_capture(
            original.anchor_id,
            attempt_id,
            Arc::clone(&control),
        )
        .unwrap();
        let partial = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "sample",
        )
        .unwrap();
        assert!(
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).is_err()
        );
        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(control_dir.join("control.db"), &keys).unwrap(),
        ));
        let mut recovered = GuardedViewMount::recover_all_claimed(Arc::clone(&control)).unwrap();
        assert_eq!(recovered.len(), 1);
        recovered.pop().unwrap().stop().unwrap();
        let captured_view = GuardedViewMount::finish_stopped_capture(
            original.anchor_id,
            attempt_id,
            Arc::clone(&control),
        )
        .unwrap();
        assert_eq!(captured_view.metadata, prepared);
        assert_eq!(captured_view.format_version, 1);
        assert_eq!(
            mb_core::decode_canonical::<GuardedStoppedCaptureV1>(
                &mb_core::canonical_bytes(&captured_view).unwrap()
            )
            .unwrap(),
            captured_view
        );
        captured_view.verify().unwrap();
        let mut wrong_bytes = captured_view.clone();
        wrong_bytes.files[0].content_hash[0] ^= 1;
        assert!(wrong_bytes.verify().is_err());
        assert_eq!(captured_view.files.len(), 3);
        let sample = captured_view
            .files
            .iter()
            .find(|file| file.path == b"sample")
            .unwrap();
        let untouched = captured_view
            .files
            .iter()
            .find(|file| file.path == b"untouched")
            .unwrap();
        assert_ne!(sample.locator.anchor_id, original.anchor_id);
        assert_eq!(sample.content_hash, *blake3::hash(&first_bytes).as_bytes());
        assert_eq!(untouched.locator.anchor_id, original.anchor_id);
        assert_eq!(
            untouched.content_hash,
            *blake3::hash(untouched_bytes).as_bytes()
        );
        let nested = captured_view
            .files
            .iter()
            .find(|file| file.path == b"nested/kept")
            .unwrap();
        assert_eq!(nested.locator.anchor_id, original.anchor_id);
        assert_eq!(
            nested.content_hash,
            *blake3::hash(b"nested unchanged").as_bytes()
        );

        let first = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "sample",
        )
        .unwrap();
        assert_eq!(first, partial);
        assert_eq!(first.anchor_id, sample.locator.anchor_id);
        assert_eq!(
            GuardedViewMount::capture_stopped_view(original.anchor_id, Arc::clone(&control))
                .unwrap(),
            captured_view
        );
        assert_eq!(anchor_bytes(&first), first_bytes);
        assert_eq!(
            GuardedViewMount::capture_stopped_file(
                original.anchor_id,
                Arc::clone(&control),
                "sample",
            )
            .unwrap(),
            first
        );
        let remounted =
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).unwrap();
        let first_plan = {
            let store = control.lock().unwrap();
            let plan = crate::GuardedFileCapturePlan::load_for_manifest(&store, &first)
                .unwrap()
                .unwrap();
            assert!(plan.discard_unreferenced(&store).is_err());
            plan
        };
        assert_eq!(
            fs::metadata(mountpoint.join("sample"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o666
        );
        let renamed = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
            .arg(mountpoint.join("sample"))
            .arg(mountpoint.join("moved"))
            .output()
            .unwrap();
        assert!(renamed.status.success(), "{renamed:?}");
        edit(&mountpoint.join("moved"), "EDIT2");
        assert_eq!(anchor_bytes(&first), first_bytes);
        assert_eq!(
            GuardedViewMount::finish_stopped_capture(
                original.anchor_id,
                attempt_id,
                Arc::clone(&control),
            )
            .unwrap(),
            captured_view
        );
        let second_bytes = fs::read(lower.join("moved")).unwrap();
        remounted.stop().unwrap();

        let second = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "moved",
        )
        .unwrap();
        assert_ne!(second.anchor_id, first.anchor_id);
        assert_eq!(anchor_bytes(&second), second_bytes);
        assert!(
            first_plan
                .discard_unreferenced(&control.lock().unwrap())
                .is_err()
        );
        assert!(
            GuardedViewMount::retire_claim(original.anchor_id, &control.lock().unwrap()).is_err()
        );
        GuardedViewMount::release_stopped_capture_unreferenced(
            attempt_id,
            &control.lock().unwrap(),
        )
        .unwrap();
        first_plan
            .discard_unreferenced(&control.lock().unwrap())
            .unwrap();
        assert!(first.open_verified().is_err());
        assert!(captured_view.verify().is_err());
        let remounted =
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).unwrap();
        edit(&mountpoint.join("moved"), "EDIT3");
        assert_eq!(anchor_bytes(&second), second_bytes);
        let create = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o644); os.write(fd,b'new view file'); os.fsync(fd); os.close(fd)")
            .arg(mountpoint.join("created"))
            .output()
            .unwrap();
        assert!(create.status.success(), "{create:?}");
        remounted.stop().unwrap();
        let created_bytes = fs::read(lower.join("created")).unwrap();
        let created = GuardedViewMount::capture_stopped_file(
            original.anchor_id,
            Arc::clone(&control),
            "created",
        )
        .unwrap();
        assert_eq!(anchor_bytes(&created), created_bytes);
        let remounted =
            GuardedViewMount::recover_claimed(original.anchor_id, Arc::clone(&control)).unwrap();
        edit(&mountpoint.join("created"), "EDIT4");
        assert_eq!(anchor_bytes(&created), created_bytes);
        remounted.stop().unwrap();

        let store = control.lock().unwrap();
        GuardedViewMount::retire_claim(original.anchor_id, &store).unwrap();
        assert!(root_plan.discard_unreferenced(&store).is_err());
        for anchor in [&second, &created] {
            let plan = crate::GuardedFileCapturePlan::load_for_manifest(&store, anchor)
                .unwrap()
                .unwrap();
            plan.discard_unreferenced(&store).unwrap();
        }
        assert!(
            store
                .records(crate::guarded_view_probe::FILE_GUARD_KIND)
                .unwrap()
                .is_empty()
        );
        root_plan.discard_unreferenced(&store).unwrap();
        assert!(fs::read(lower.join("moved")).unwrap().starts_with(b"EDIT3"));
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and a disposable mounted filesystem of at most 512 MiB"]
    fn real_enospc_writable_open_keeps_guarded_mount_recoverable() {
        let mounted_root = std::env::var_os("MUTUALBACKUP_REAL_ENOSPC_TEST_ROOT")
            .expect("set MUTUALBACKUP_REAL_ENOSPC_TEST_ROOT to a disposable mount");
        let mounted_root = PathBuf::from(mounted_root).canonicalize().unwrap();
        assert_eq!(
            fs::read(mounted_root.join(".mutualbackup-disposable-enospc")).unwrap(),
            b"mutualbackup-disposable-enospc-v1\n"
        );
        assert_ne!(
            fs::metadata(&mounted_root).unwrap().dev(),
            fs::metadata(mounted_root.parent().unwrap()).unwrap().dev()
        );
        let mounted = File::open(&mounted_root).unwrap();
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: the mounted descriptor is open and fstatvfs fills stats on success.
        assert_eq!(
            unsafe { libc::fstatvfs(mounted.as_raw_fd(), stats.as_mut_ptr()) },
            0
        );
        // SAFETY: the preceding fstatvfs call succeeded.
        let stats = unsafe { stats.assume_init() };
        assert!(
            stats.f_blocks > 0
                && stats.f_frsize > 0
                && stats.f_blocks.saturating_mul(stats.f_frsize) <= 512 * 1024 * 1024
        );

        let area = tempfile::Builder::new()
            .prefix("mb-guarded-full-view-")
            .tempdir_in(&mounted_root)
            .unwrap();
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let filler_path = area.path().join("filler");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        let chunk = [0x5a_u8; 1024 * 1024];
        let source_path = lower.join("source");
        let mut source = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        for _ in 0..32 {
            source.write_all(&chunk).unwrap();
        }
        source.sync_all().unwrap();
        source
            .set_permissions(fs::Permissions::from_mode(0o666))
            .unwrap();
        drop(source);
        let original_hash = blake3::hash(&fs::read(&source_path).unwrap());

        let journal_area = tempfile::tempdir().unwrap();
        assert_ne!(
            fs::metadata(journal_area.path()).unwrap().dev(),
            fs::metadata(area.path()).unwrap().dev()
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([112; 32]));
        let control = ControlStore::open(journal_area.path().join("control.db"), &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&control).unwrap();
        let control = Arc::new(Mutex::new(control));
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        mount.check_health().unwrap();

        let mut filler = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filler_path)
            .unwrap();
        let mut full = false;
        for _ in 0..512 {
            let result = filler.write_all(&chunk).and_then(|()| filler.sync_data());
            if let Err(error) = result {
                assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
                full = true;
                break;
            }
        }
        assert!(full, "the disposable filesystem did not become full");
        filler
            .set_len(
                filler
                    .metadata()
                    .unwrap()
                    .len()
                    .saturating_sub(8 * 1024 * 1024),
            )
            .unwrap();
        filler.sync_all().unwrap();

        let attempted_open = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import errno,os,sys\ntry:\n fd=os.open(sys.argv[1],os.O_WRONLY)\n os.close(fd)\n raise AssertionError('writable open unexpectedly succeeded')\nexcept OSError as error:\n assert error.errno==errno.ENOSPC,error")
            .arg(mountpoint.join("source"))
            .output()
            .unwrap();
        assert!(
            attempted_open.status.success(),
            "ordinary-user disk-full open: {}",
            String::from_utf8_lossy(&attempted_open.stderr)
        );
        let attempted_truncate = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import errno,os,sys\ntry:\n os.truncate(sys.argv[1],1)\n raise AssertionError('pathname truncate unexpectedly succeeded')\nexcept OSError as error:\n assert error.errno==errno.ENOSPC,error")
            .arg(mountpoint.join("source"))
            .output()
            .unwrap();
        assert!(
            attempted_truncate.status.success(),
            "ordinary-user disk-full truncate: {}",
            String::from_utf8_lossy(&attempted_truncate.stderr)
        );
        mount.check_health().unwrap();
        let private_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(&source_path)
            .output()
            .unwrap();
        assert!(!private_read.status.success());
        let anchor_path = manifest.file_locator("source".to_owned()).unwrap();
        let anchor = anchor_path.open().unwrap();
        assert_eq!(
            fs::metadata(&source_path).unwrap().ino(),
            anchor.metadata().unwrap().ino()
        );
        assert_eq!(
            blake3::hash(&fs::read(&source_path).unwrap()),
            original_hash
        );
        drop(anchor);

        drop(filler);
        fs::remove_file(&filler_path).unwrap();
        mount.stop().unwrap();
        let recovered =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        recovered.check_health().unwrap();
        let edited = Command::new("python3")
            .uid(65534)
            .gid(65534)
            .arg("-c")
            .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.pwrite(fd,b'EDIT',0); os.fsync(fd); os.close(fd)")
            .arg(mountpoint.join("source"))
            .output()
            .unwrap();
        assert!(
            edited.status.success(),
            "ordinary-user retry: {}",
            String::from_utf8_lossy(&edited.stderr)
        );
        assert!(fs::read(&source_path).unwrap().starts_with(b"EDIT"));
        let mut protected = anchor_path.open().unwrap();
        assert_ne!(
            fs::metadata(&source_path).unwrap().ino(),
            protected.metadata().unwrap().ino()
        );
        let mut anchor_bytes = Vec::new();
        protected.read_to_end(&mut anchor_bytes).unwrap();
        assert_eq!(blake3::hash(&anchor_bytes), original_hash);
        recovered.stop().unwrap();
        let control = control.lock().unwrap();
        GuardedViewMount::retire_claim(manifest.anchor_id, &control).unwrap();
        plan.discard_unreferenced(&control).unwrap();
    }
}
