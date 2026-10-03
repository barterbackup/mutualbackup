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
        let view = GuardedProbeView::from_guarded_capture(
            manifest,
            Arc::clone(&control),
            view_uid,
            view_gid,
        )?;
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
    use std::fs;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::{Child, Command};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use mb_core::{KeyMaterial, Seed};

    use crate::{ControlStore, GuardedRootCapturePlan};

    use super::{GuardedViewMount, decode_mountinfo_path};

    #[test]
    fn mountinfo_paths_decode_spaces_and_non_utf8_bytes() {
        use std::os::unix::ffi::OsStrExt;

        let path = decode_mountinfo_path("/one\\040two/odd\\377").unwrap();
        assert_eq!(path.as_os_str().as_bytes(), b"/one two/odd\xff");
        assert!(decode_mountinfo_path("/broken\\08").is_err());
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
        let manifest = GuardedRootCapturePlan::plan(&lower)
            .unwrap()
            .capture(&control)
            .unwrap();
        let control = Arc::new(Mutex::new(control));
        let mount =
            GuardedViewMount::start(&manifest, Arc::clone(&control), &mountpoint, 65534, 65534)
                .unwrap();
        mount.check_health().unwrap();
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
        mount.stop().unwrap();

        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));

        let remounted =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        remounted.check_health().unwrap();
        assert_eq!(fs::read(mountpoint.join("sample")).unwrap(), edited);
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
        let recovered =
            GuardedViewMount::recover_claimed(manifest.anchor_id, Arc::clone(&control)).unwrap();
        recovered.check_health().unwrap();
        assert_eq!(fs::read(mountpoint.join("sample")).unwrap(), edited);
        recovered.stop().unwrap();
        drop(dead);

        fs::rename(&mountpoint, area.path().join("old-view")).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::set_permissions(&mountpoint, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(GuardedViewMount::start(&manifest, control, &mountpoint, 65534, 65534).is_err());
    }
}
