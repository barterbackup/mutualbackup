//! Durable mount ownership for a guarded FUSE worktree whose private lower
//! root has already been captured. Enrollment still owns the separate,
//! replayable transition from a user's original directory to this layout.

use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, ensure};
use fuser::{BackgroundSession, Config, MountOption, SessionACL};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::guarded_view_probe::GuardedProbeView;
use crate::{
    ControlStore, GuardedRootCapturePlan, NativeFileId, PinnedDirectory, StableAnchorManifest,
    filesystem_identity,
};

const MOUNT_CLAIM_KIND: &str = "guarded-view-mount-v1";
const MOUNT_RETIRE_KIND: &str = "guarded-view-mount-retired-v1";
const MOUNT_SUBTYPE: &str = "mutualbackup_guarded";

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
    session: BackgroundSession,
    mountpoint: PathBuf,
    source: String,
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
            session,
            mountpoint,
            source,
        })
    }

    pub fn check_health(&self) -> anyhow::Result<()> {
        ensure!(
            !self.session.guard.is_finished(),
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

    pub fn stop(self) -> io::Result<()> {
        self.session.umount_and_join()
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

    use super::{GuardedViewMount, MOUNT_CLAIM_KIND, MOUNT_RETIRE_KIND, decode_mountinfo_path};

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
        fs::write(lower.join("sample"), exact_bytes).unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();

        let keys = KeyMaterial::from_seed(&Seed::from_bytes([111; 32]));
        let control = ControlStore::open(&control_path, &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&control).unwrap();
        let control = Arc::new(Mutex::new(control));
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        mount.check_health().unwrap();
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
        mount.stop().unwrap();

        for unexpected in [lower.join("public/unknown"), lower.join("unknown")] {
            fs::write(&unexpected, b"outside the guarded view").unwrap();
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
