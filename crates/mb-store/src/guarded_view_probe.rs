//! Disposable Linux FUSE passthrough probe for the future guarded worktree.
//!
//! This proves that this host can mount a view, pass read-only file access to
//! a lower inode, and finish one captured file's durable detach before a
//! writable open or metadata edit. It also probes rename and unlink through
//! the view. It is not a complete long-lived edit guard and must not be used
//! as an enrollment decision by itself.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, ensure};
use fuser::{
    BackingId, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, InitFlags, KernelConfig, LockOwner, OpenAccMode, OpenFlags, RenameFlags,
    ReplyAttr, ReplyEmpty, ReplyEntry, ReplyOpen, Request, SessionACL, TimeOrNow,
};

const FILE_INODE: INodeNo = INodeNo(2);
const ENTRY_TTL: Duration = Duration::ZERO;
const PROBE_BYTES: &[u8] = b"mutualbackup-guarded-view-probe";
// The kernel supplies O_LARGEFILE in FUSE_OPEN even when libc defines it as
// zero for the native 64-bit ABI.
const KERNEL_O_LARGEFILE: i32 = 0o100000;

struct SingleFileProbeView {
    source: File,
    source_attr: Mutex<FileAttr>,
    name: Arc<Mutex<Option<OsString>>>,
    lower_dir: Option<PathBuf>,
    root_perm: u16,
    next_handle: AtomicU64,
    denied_writable: Arc<AtomicU64>,
    backing: Mutex<HashMap<u64, ActiveBacking>>,
    open_for_write: Option<Arc<dyn Fn(OpenAccMode) -> io::Result<File> + Send + Sync>>,
}

struct ActiveBacking {
    id: BackingId,
    mode: OpenAccMode,
}

impl SingleFileProbeView {
    fn root_attr(&self) -> FileAttr {
        let source_attr = self.source_attr.lock().unwrap();
        FileAttr {
            ino: INodeNo::ROOT,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: self.root_perm,
            nlink: 2,
            uid: source_attr.uid,
            gid: source_attr.gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }

    fn current_file_attr(&self) -> io::Result<FileAttr> {
        let metadata = self.source.metadata()?;
        let mut attr = self.source_attr.lock().unwrap();
        attr.size = metadata.len();
        attr.blocks = metadata.blocks();
        attr.nlink = metadata.nlink() as u32;
        Ok(*attr)
    }
}

fn probe_file_attr(source: &File, advertised_mode: u16) -> io::Result<FileAttr> {
    let metadata = source.metadata()?;
    Ok(FileAttr {
        ino: FILE_INODE,
        size: metadata.len(),
        blocks: metadata.blocks(),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: advertised_mode,
        nlink: 1,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: 0,
        flags: 0,
        blksize: metadata.blksize() as u32,
    })
}

impl Filesystem for SingleFileProbeView {
    fn init(&mut self, _request: &Request, config: &mut KernelConfig) -> io::Result<()> {
        config
            .add_capabilities(InitFlags::FUSE_PASSTHROUGH)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::Unsupported, "FUSE passthrough unavailable")
            })?;
        config
            .set_max_stack_depth(1)
            .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "FUSE stacking unavailable"))?;
        Ok(())
    }

    fn lookup(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        let current = self.name.lock().unwrap();
        if parent == INodeNo::ROOT && current.as_deref() == Some(name) {
            match self.current_file_attr() {
                Ok(attr) => reply.entry(&ENTRY_TTL, &attr, Generation(0)),
                Err(_) => reply.error(Errno::EIO),
            }
        } else {
            reply.error(Errno::ENOENT);
        }
    }

    fn getattr(
        &self,
        _request: &Request,
        inode: INodeNo,
        _handle: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        match inode {
            INodeNo::ROOT => reply.attr(&ENTRY_TTL, &self.root_attr()),
            FILE_INODE => match self.current_file_attr() {
                Ok(attr) => reply.attr(&ENTRY_TTL, &attr),
                Err(_) => reply.error(Errno::EIO),
            },
            _ => reply.error(Errno::ENOENT),
        }
    }

    fn setattr(
        &self,
        _request: &Request,
        inode: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        handle: Option<FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if inode != FILE_INODE {
            reply.error(Errno::ENOENT);
            return;
        }
        if (mode.is_none() && size.is_none())
            || uid.is_some()
            || gid.is_some()
            || atime.is_some()
            || mtime.is_some()
            || ctime.is_some()
            || crtime.is_some()
            || chgtime.is_some()
            || bkuptime.is_some()
            || flags.is_some()
        {
            reply.error(Errno::EINVAL);
            return;
        }
        if let Some(handle) = handle {
            let held = self.backing.lock().unwrap();
            let Some(backing) = held.get(&handle.0) else {
                reply.error(Errno::EIO);
                return;
            };
            if size.is_some() && backing.mode == OpenAccMode::O_RDONLY {
                reply.error(Errno::EACCES);
                return;
            }
        }
        let Some(open_for_write) = &self.open_for_write else {
            reply.error(Errno::EACCES);
            return;
        };
        let result = (|| -> io::Result<FileAttr> {
            // The callback completes the durable sparse detach before this
            // operation can change the inode shared with an anchor.
            let source = open_for_write(OpenAccMode::O_RDWR)?;
            if let Some(size) = size {
                source.set_len(size)?;
            }
            if let Some(mode) = mode {
                source.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
            }
            source.sync_all()?;
            if let Some(mode) = mode {
                self.source_attr.lock().unwrap().perm = (mode & 0o7777) as u16;
            }
            self.current_file_attr()
        })();
        match result {
            Ok(attr) => reply.attr(&ENTRY_TTL, &attr),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn open(&self, _request: &Request, inode: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if inode != FILE_INODE {
            reply.error(Errno::ENOENT);
            return;
        }
        if flags.0 & !(libc::O_ACCMODE | KERNEL_O_LARGEFILE) != 0 {
            reply.error(Errno::EACCES);
            return;
        }
        let writable;
        let source = if flags.acc_mode() == OpenAccMode::O_RDONLY {
            &self.source
        } else if matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        ) {
            let Some(open_for_write) = &self.open_for_write else {
                self.denied_writable.fetch_add(1, Ordering::Relaxed);
                reply.error(Errno::EACCES);
                return;
            };
            writable = match open_for_write(flags.acc_mode()) {
                Ok(file) => file,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            &writable
        } else {
            self.denied_writable.fetch_add(1, Ordering::Relaxed);
            reply.error(Errno::EACCES);
            return;
        };
        let backing = match reply.open_backing(source) {
            Ok(backing) => backing,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let mut held = self.backing.lock().unwrap();
        held.insert(
            handle,
            ActiveBacking {
                id: backing,
                mode: flags.acc_mode(),
            },
        );
        reply.opened_passthrough(FileHandle(handle), FopenFlags::empty(), &held[&handle].id);
    }

    fn release(
        &self,
        _request: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.backing.lock().unwrap().remove(&handle.0);
        reply.ok();
    }

    fn rename(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        let Some(lower_dir) = &self.lower_dir else {
            reply.error(Errno::EACCES);
            return;
        };
        if parent != INodeNo::ROOT || newparent != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        if !flags.is_empty() && flags != RenameFlags::RENAME_NOREPLACE {
            reply.error(Errno::EINVAL);
            return;
        }
        let mut current = self.name.lock().unwrap();
        if current.as_deref() != Some(name) {
            reply.error(Errno::ENOENT);
            return;
        }
        if name == newname {
            reply.ok();
            return;
        }
        let result = (|| -> io::Result<()> {
            let lower = crate::PinnedDirectory::open(lower_dir).map_err(io::Error::other)?;
            lower
                .rename_child_no_replace(name, newname)
                .map_err(io::Error::other)?;
            *current = Some(newname.to_os_string());
            lower.sync_all().map_err(io::Error::other)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn unlink(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        let Some(lower_dir) = &self.lower_dir else {
            reply.error(Errno::EACCES);
            return;
        };
        if parent != INodeNo::ROOT {
            reply.error(Errno::ENOENT);
            return;
        }
        let mut current = self.name.lock().unwrap();
        if current.as_deref() != Some(name) {
            reply.error(Errno::ENOENT);
            return;
        }
        let result = (|| -> io::Result<()> {
            let lower = crate::PinnedDirectory::open(lower_dir).map_err(io::Error::other)?;
            lower.remove_child_file(name).map_err(io::Error::other)?;
            *current = None;
            lower.sync_all().map_err(io::Error::other)
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))),
        }
    }
}

/// Verify read-only FUSE passthrough on a disposable view beside `source_root`.
/// This is a kernel/privilege probe, not a guarded-backend enrollment probe.
pub fn probe_guarded_view_passthrough(source_root: impl AsRef<Path>) -> anyhow::Result<()> {
    let source_root = source_root.as_ref();
    ensure!(
        source_root.is_dir(),
        "guarded view probe needs a source directory"
    );
    let parent = source_root
        .parent()
        .context("guarded view source has no parent")?;
    ensure!(
        crate::filesystem_identity(source_root)? == crate::filesystem_identity(parent)?,
        "guarded view probe needs a same-filesystem parent"
    );
    let area = tempfile::Builder::new()
        .prefix(".mutualbackup-fuse-probe-")
        .tempdir_in(parent)
        .context("create disposable FUSE probe directory")?;
    fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755))?;
    let lower = area.path().join("lower");
    let mountpoint = area.path().join("view");
    fs::create_dir(&lower)?;
    fs::create_dir(&mountpoint)?;
    fs::set_permissions(&lower, fs::Permissions::from_mode(0o700))?;
    let lower_path = lower.join("sample");
    let mut writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lower_path)?;
    io::Write::write_all(&mut writable, PROBE_BYTES)?;
    writable.sync_all()?;
    drop(writable);
    fs::set_permissions(&lower_path, fs::Permissions::from_mode(0o444))?;
    let source = File::open(&lower_path)?;
    let denied_writable = Arc::new(AtomicU64::new(0));
    let view = SingleFileProbeView {
        // Advertise the original editable mode. The lower inode is frozen;
        // the view must still reject writes until detach.
        source_attr: Mutex::new(probe_file_attr(&source, 0o666)?),
        name: Arc::new(Mutex::new(Some(OsString::from("sample")))),
        lower_dir: None,
        root_perm: 0o755,
        source,
        next_handle: AtomicU64::new(1),
        denied_writable: Arc::clone(&denied_writable),
        backing: Mutex::new(HashMap::new()),
        open_for_write: None,
    };
    let mut config = Config::default();
    config.acl = SessionACL::All;
    let session = fuser::spawn_mount(view, &mountpoint, &config)
        .context("mount disposable FUSE passthrough view")?;
    let result = (|| -> anyhow::Result<()> {
        ensure!(
            fs::read(mountpoint.join("sample"))? == PROBE_BYTES,
            "FUSE passthrough changed bytes"
        );
        let ordinary_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(mountpoint.join("sample"))
            .output()
            .context("read guarded view as an ordinary user")?;
        ensure!(
            ordinary_read.status.success() && ordinary_read.stdout == PROBE_BYTES,
            "ordinary user could not read exact bytes through FUSE view"
        );
        let private_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(&lower_path)
            .output()
            .context("check private lower source access")?;
        ensure!(
            !private_read.status.success(),
            "ordinary user can bypass the guarded view through the lower path"
        );
        let visible = File::open(mountpoint.join("sample"))?;
        // SAFETY: the mapping is read-only, shared, and bounded by this
        // immutable probe file. It is unmapped before the descriptor closes.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PROBE_BYTES.len(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                visible.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: mmap returned a readable region of exactly this length.
        let mapped_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(mapping.cast(), PROBE_BYTES.len()) };
        let mapping_matches = mapped_bytes == PROBE_BYTES;
        // SAFETY: this is the original mapping pointer and length.
        if unsafe { libc::munmap(mapping, PROBE_BYTES.len()) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        ensure!(mapping_matches, "FUSE read-only mapping changed bytes");
        // SAFETY: this deliberately attempts a shared writable map through a
        // read-only descriptor; any unexpected mapping is immediately unmapped.
        let writable_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PROBE_BYTES.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                visible.as_raw_fd(),
                0,
            )
        };
        if writable_mapping != libc::MAP_FAILED {
            // SAFETY: release the unexpected successful mapping before error.
            unsafe { libc::munmap(writable_mapping, PROBE_BYTES.len()) };
            anyhow::bail!("FUSE read-only handle accepted a shared writable mapping");
        }
        ensure!(
            OpenOptions::new()
                .write(true)
                .open(mountpoint.join("sample"))
                .is_err(),
            "FUSE read-only view accepted a writable open"
        );
        ensure!(
            denied_writable.load(Ordering::Relaxed) > 0,
            "writable open bypassed the FUSE decision"
        );
        let _ = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_TRUNC)
            .open(mountpoint.join("sample"));
        ensure!(
            fs::read(&lower_path)? == PROBE_BYTES,
            "read-only pathname truncate changed the lower inode"
        );
        let _ = fs::set_permissions(mountpoint.join("sample"), fs::Permissions::from_mode(0o666));
        ensure!(
            fs::metadata(&lower_path)?.permissions().mode() & 0o222 == 0,
            "FUSE chmod changed the frozen lower inode"
        );
        Ok(())
    })();
    session
        .umount_and_join()
        .context("unmount disposable FUSE view")?;
    result
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};

    use fuser::{Config, OpenAccMode, SessionACL};
    use mb_core::{KeyMaterial, Seed};

    use crate::{
        ControlStore, GuardedFileCapturePlan, LinkFreezeCaptureIntent, LinkFreezeCapturePhase,
    };

    use super::{SingleFileProbeView, probe_file_attr};

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and FUSE passthrough"]
    fn read_only_passthrough_mount_preserves_bytes_and_denies_writable_open() {
        let disposable = tempfile::tempdir().unwrap();
        let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| disposable.path().to_path_buf());
        super::probe_guarded_view_passthrough(root).unwrap();
    }

    #[derive(Clone, Copy)]
    enum FirstMutation {
        WritableOpen,
        OwnerChmod,
        PathTruncate,
        OpenTruncate,
        RenameThenWrite,
        Unlink,
    }

    fn guarded_view_mutation_case(first: FirstMutation) {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-view-edit-")
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
        let lower_path = lower.join("sample");
        let original = b"raw\r\nbytes\0guarded";
        fs::write(&lower_path, original).unwrap();
        fs::set_permissions(&lower_path, fs::Permissions::from_mode(0o666)).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let control = ControlStore::open(control_dir.join("control.db"), &keys).unwrap();
        let plan = GuardedFileCapturePlan::plan(&lower, "sample").unwrap();
        let manifest = plan.capture(&control).unwrap();
        let source = File::open(&lower_path).unwrap();
        let original_inode = source.metadata().unwrap().ino();
        let control = Arc::new(Mutex::new(control));
        let control_for_open = Arc::clone(&control);
        let plan_for_open = plan.clone();
        let name = Arc::new(Mutex::new(Some(OsString::from("sample"))));
        let name_for_open = Arc::clone(&name);
        let lower_for_open = lower.clone();
        let open_for_write = Arc::new(move |mode: OpenAccMode| -> io::Result<File> {
            let current = name_for_open
                .lock()
                .map_err(|_| io::Error::other("guarded name lock is poisoned"))?;
            let current = current
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let control = control_for_open
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            plan_for_open
                .prepare_edit_at(&control, current)
                .map_err(io::Error::other)?;
            OpenOptions::new()
                .read(mode == OpenAccMode::O_RDWR)
                .write(true)
                .open(lower_for_open.join(current))
        });
        let mut advertised = probe_file_attr(&source, 0o666).unwrap();
        advertised.uid = 65534;
        let view = SingleFileProbeView {
            source_attr: Mutex::new(advertised),
            source,
            name,
            lower_dir: Some(lower.clone()),
            root_perm: 0o777,
            next_handle: AtomicU64::new(1),
            denied_writable: Arc::new(AtomicU64::new(0)),
            backing: Mutex::default(),
            open_for_write: Some(open_for_write),
        };
        let mut config = Config::default();
        config.acl = SessionACL::All;
        let session = fuser::spawn_mount(view, &mountpoint, &config).unwrap();
        let result = (|| -> anyhow::Result<()> {
            anyhow::ensure!(fs::read(mountpoint.join("sample"))? == original);
            anyhow::ensure!(fs::read(&lower_path)? == original);
            anyhow::ensure!(fs::metadata(&lower_path)?.permissions().mode() & 0o222 == 0);
            let guest_read = Command::new("cat")
                .uid(65534)
                .gid(65534)
                .arg(mountpoint.join("sample"))
                .output()?;
            anyhow::ensure!(
                guest_read.status.success(),
                "ordinary-user read failed: {}",
                String::from_utf8_lossy(&guest_read.stderr)
            );
            anyhow::ensure!(guest_read.stdout == original);
            anyhow::ensure!(
                fs::metadata(mountpoint.join("sample"))?
                    .permissions()
                    .mode()
                    & 0o222
                    != 0
            );
            let script = match first {
                FirstMutation::WritableOpen => {
                    "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)"
                }
                FirstMutation::OwnerChmod => "import os,sys; os.chmod(sys.argv[1],0o600)",
                FirstMutation::PathTruncate => "import os,sys; os.truncate(sys.argv[1],3)",
                FirstMutation::OpenTruncate => {
                    "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC); os.write(fd,b'REPLACED'); os.fsync(fd); os.close(fd)"
                }
                FirstMutation::RenameThenWrite => {
                    "import os,sys; os.rename(sys.argv[1],os.path.join(os.path.dirname(sys.argv[1]),'moved'))"
                }
                FirstMutation::Unlink => "import os,sys; os.unlink(sys.argv[1])",
            };
            let output = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg(script)
                .arg(mountpoint.join("sample"))
                .output()?;
            anyhow::ensure!(
                output.status.success(),
                "ordinary-user guarded mutation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            match first {
                FirstMutation::WritableOpen => {
                    anyhow::ensure!(fs::read(&lower_path)?.starts_with(b"EDIT"));
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))?.starts_with(b"EDIT"));
                    let second_open = Command::new("python3")
                        .uid(65534)
                        .gid(65534)
                        .arg("-c")
                        .arg("import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.lseek(fd,5,os.SEEK_SET); os.write(fd,b'NEXT'); os.fsync(fd); os.close(fd)")
                        .arg(mountpoint.join("sample"))
                        .output()?;
                    anyhow::ensure!(
                        second_open.status.success(),
                        "ordinary-user read/write open failed: {}",
                        String::from_utf8_lossy(&second_open.stderr)
                    );
                    anyhow::ensure!(fs::read(&lower_path)?.starts_with(b"EDIT\nNEXT"));
                }
                FirstMutation::OwnerChmod => {
                    anyhow::ensure!(fs::read(&lower_path)? == original);
                    anyhow::ensure!(
                        fs::metadata(&lower_path)?.permissions().mode() & 0o777 == 0o600
                    );
                    anyhow::ensure!(
                        fs::metadata(mountpoint.join("sample"))?
                            .permissions()
                            .mode()
                            & 0o777
                            == 0o600
                    );
                }
                FirstMutation::PathTruncate => {
                    anyhow::ensure!(fs::read(&lower_path)? == original[..3]);
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))? == original[..3]);
                }
                FirstMutation::OpenTruncate => {
                    anyhow::ensure!(fs::read(&lower_path)? == b"REPLACED");
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))? == b"REPLACED");
                }
                FirstMutation::RenameThenWrite => {
                    anyhow::ensure!(!lower_path.exists());
                    anyhow::ensure!(!mountpoint.join("sample").exists());
                    anyhow::ensure!(fs::read(lower.join("moved"))? == original);
                    anyhow::ensure!(fs::read(mountpoint.join("moved"))? == original);
                    anyhow::ensure!(
                        LinkFreezeCaptureIntent::load(&control.lock().unwrap(), plan.anchor_id())?
                            .is_some_and(|intent| intent.phase() == LinkFreezeCapturePhase::Frozen)
                    );
                    let renamed_write = Command::new("python3")
                        .uid(65534)
                        .gid(65534)
                        .arg("-c")
                        .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)")
                        .arg(mountpoint.join("moved"))
                        .output()?;
                    anyhow::ensure!(
                        renamed_write.status.success(),
                        "ordinary-user write after rename failed: {}",
                        String::from_utf8_lossy(&renamed_write.stderr)
                    );
                    anyhow::ensure!(fs::read(lower.join("moved"))?.starts_with(b"EDIT"));
                }
                FirstMutation::Unlink => {
                    anyhow::ensure!(!lower_path.exists());
                    anyhow::ensure!(!mountpoint.join("sample").exists());
                    let mut anchor = manifest.open_verified()?;
                    anyhow::ensure!(anchor.metadata()?.ino() == original_inode);
                    anyhow::ensure!(anchor.metadata()?.nlink() == 1);
                    let mut bytes = Vec::new();
                    anchor.read_to_end(&mut bytes)?;
                    anyhow::ensure!(bytes == original);
                    anyhow::ensure!(
                        LinkFreezeCaptureIntent::load(&control.lock().unwrap(), plan.anchor_id())?
                            .is_some_and(|intent| intent.phase() == LinkFreezeCapturePhase::Frozen)
                    );
                    return Ok(());
                }
            }
            let current_lower = if matches!(first, FirstMutation::RenameThenWrite) {
                lower.join("moved")
            } else {
                lower_path.clone()
            };
            let source_metadata = fs::metadata(current_lower)?;
            anyhow::ensure!(
                source_metadata.ino() == original_inode && source_metadata.nlink() == 1
            );
            anyhow::ensure!(source_metadata.permissions().mode() & 0o222 != 0);
            let mut anchored = Vec::new();
            let mut anchor = manifest.open_verified()?;
            anyhow::ensure!(anchor.metadata()?.ino() != original_inode);
            anchor.read_to_end(&mut anchored)?;
            anyhow::ensure!(anchored == original);
            anyhow::ensure!(
                LinkFreezeCaptureIntent::load(&control.lock().unwrap(), plan.anchor_id())?
                    .is_some_and(|intent| intent.phase() == LinkFreezeCapturePhase::Detached)
            );
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        result.unwrap();
        unmounted.unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn writable_open_finishes_durable_detach_before_passthrough() {
        guarded_view_mutation_case(FirstMutation::WritableOpen);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn owner_chmod_detaches_before_changing_source_mode() {
        guarded_view_mutation_case(FirstMutation::OwnerChmod);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn pathname_truncate_detaches_before_changing_source_bytes() {
        guarded_view_mutation_case(FirstMutation::PathTruncate);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn truncating_open_detaches_before_changing_source_bytes() {
        guarded_view_mutation_case(FirstMutation::OpenTruncate);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn rename_preserves_anchor_until_later_write_detaches() {
        guarded_view_mutation_case(FirstMutation::RenameThenWrite);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn unlink_preserves_anchor_without_detach() {
        guarded_view_mutation_case(FirstMutation::Unlink);
    }
}
