//! Short-lived Linux write exclusion for the guarded link-freeze backend.
//!
//! A read lease is acquired before changing inode permissions. Linux refuses
//! it while another writable file description (including one held by a shared
//! writable mapping) exists. Fanotify permission events deny new opens and
//! pathname truncation so they cannot break that lease during the transition.
//! This guard is not the durable backend: the caller still has to record and
//! recover the permission and anchor transition.

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::anchor::{AnchorError, FileExtent, file_data_extents};

// Linux UAPI asm-generic/fcntl.h. The libc crate does not expose F_SETSIG.
const F_SETSIG_LINUX: libc::c_int = 10;
// Linux UAPI linux/fanotify.h. Permission events require CAP_SYS_ADMIN.
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_NONBLOCK: libc::c_uint = 0x0000_0002;
const FAN_CLASS_PRE_CONTENT: libc::c_uint = 0x0000_0008;
const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_PRE_ACCESS: u64 = 0x0010_0000;
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
const FAN_DENY: u32 = 0x0000_0002;
const FANOTIFY_METADATA_VERSION: u8 = 3;
const MAX_ACCESS_ACL_BYTES: usize = 64 * 1024;
const ACCESS_ACL_NAME: &std::ffi::CStr = c"system.posix_acl_access";

#[cfg(test)]
thread_local! {
    static AFTER_SPARSE_COPY_START: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
}

fn run_after_sparse_copy_start_hook() {
    #[cfg(test)]
    AFTER_SPARSE_COPY_START.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

/// Exact original access metadata to persist before freezing a shared inode.
/// An unsupported ACL facility is distinct from a supported filesystem with
/// no access ACL, so a later backend does not silently invent ACL semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileAccessSnapshot {
    pub format_version: u16,
    pub mode: u32,
    pub access_acl: AccessAclSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AccessAclSnapshot {
    Unsupported,
    Absent,
    Present(Vec<u8>),
}

/// Verified private inode produced from a frozen hard-link source. Publication
/// and recovery of the copy remain the owning backend's responsibility.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndependentSparseCopy {
    pub logical_len: u64,
    pub content_hash: [u8; 32],
    pub data_extents: Vec<FileExtent>,
}

impl FileAccessSnapshot {
    /// Capture the mode and raw POSIX access ACL through a pinned descriptor.
    /// The caller must durably record this value before changing permissions.
    pub fn capture(file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let before = file.metadata()?;
        if !before.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "access snapshot requires a regular file",
            ));
        }
        let access_acl = read_access_acl(file)?;
        let after = file.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.mode(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mode(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(io::Error::other(
                "file metadata changed during access snapshot",
            ));
        }
        Ok(Self {
            format_version: 1,
            mode: before.mode() & 0o7777,
            access_acl,
        })
    }

    /// Check both mode and ACL after recovery without changing the file.
    pub fn matches(&self, file: &File) -> io::Result<bool> {
        if self.format_version != 1 {
            return Ok(false);
        }
        Ok(*self == Self::capture(file)?)
    }
}

fn read_access_acl(file: &File) -> io::Result<AccessAclSnapshot> {
    let fd = file.as_raw_fd();
    // SAFETY: the pinned descriptor and NUL-terminated xattr name are valid.
    let length = unsafe { libc::fgetxattr(fd, ACCESS_ACL_NAME.as_ptr(), std::ptr::null_mut(), 0) };
    if length < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENODATA) => Ok(AccessAclSnapshot::Absent),
            Some(libc::EOPNOTSUPP) => Ok(AccessAclSnapshot::Unsupported),
            _ => Err(error),
        };
    }
    let length = length as usize;
    if length == 0 || length > MAX_ACCESS_ACL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "POSIX access ACL exceeds its supported bound or is empty",
        ));
    }
    let mut value = vec![0_u8; length];
    // SAFETY: the allocated vector has length bytes and the kernel writes at
    // most that many bytes; a changed ACL returns ERANGE or a different size.
    let read = unsafe {
        libc::fgetxattr(
            fd,
            ACCESS_ACL_NAME.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read as usize != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "POSIX access ACL changed during capture",
        ));
    }
    Ok(AccessAclSnapshot::Present(value))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    version: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

/// Keeps an inode free of open writers during a short permission transition.
#[must_use = "dropping the guard releases its write exclusion"]
pub struct FileWriteExclusion {
    file: File,
    fanotify: File,
    stop: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    active: bool,
}

impl FileWriteExclusion {
    /// The caller must pass a dedicated read-only descriptor for a regular
    /// file. This requires CAP_SYS_ADMIN for fanotify permission events and a
    /// kernel with FAN_PRE_ACCESS (Linux 6.14 or newer). Ownership and
    /// filesystem lease support are checked by the kernel; unsupported hosts
    /// return an error instead of weakening the guard.
    pub fn acquire(file: File) -> io::Result<Self> {
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file leases require a regular file",
            ));
        }
        let fd = file.as_raw_fd();
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read lease needs a read-only descriptor",
            ));
        }
        // A read lease alone is insufficient: a conflicting O_NONBLOCK open
        // or pathname truncate can break it immediately. Install inode-bound
        // permission marks first, then acquire the lease to exclude writers
        // opened earlier. FAN_PRE_ACCESS requires a recent kernel and catches
        // truncate without an open; unsupported kernels fail this probe.
        // SAFETY: fanotify_init receives the documented Linux UAPI flags.
        let fan_fd = unsafe {
            libc::fanotify_init(
                FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_PRE_CONTENT,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
            )
        };
        if fan_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fanotify_init returned sole ownership of this descriptor.
        let fanotify = unsafe { File::from_raw_fd(fan_fd) };
        let stop = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_file = fanotify.try_clone()?;
        let worker_stop = Arc::clone(&stop);
        let worker_healthy = Arc::clone(&healthy);
        let worker = thread::Builder::new()
            .name("mb-link-freeze-deny".to_owned())
            .spawn(move || deny_new_opens(&worker_file, &worker_stop, &worker_healthy))?;
        let mut guard = Self {
            file,
            fanotify,
            stop,
            healthy,
            worker: Some(worker),
            active: false,
        };
        // A NULL path marks the opened inode rather than a potentially
        // replaced pathname. New opens now need an explicit deny response.
        // SAFETY: both descriptors are valid and NULL selects the source fd.
        if unsafe {
            libc::fanotify_mark(
                guard.fanotify.as_raw_fd(),
                FAN_MARK_ADD,
                FAN_OPEN_PERM | FAN_PRE_ACCESS,
                guard.file.as_raw_fd(),
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SIGURG is ignored by default. A competing writer must not send the
        // daemon the default lease-break signal, SIGIO, which could terminate
        // it before the permission transition is made durable.
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        if unsafe { libc::fcntl(fd, F_SETSIG_LINUX, libc::SIGURG) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        if unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        guard.active = true;
        if !guard.is_held()? {
            return Err(io::Error::other(
                "write exclusion was lost during acquisition",
            ));
        }
        Ok(guard)
    }

    /// A lease can be forcibly broken after the kernel's lease-break timeout.
    /// A caller must verify this before committing an anchor transition.
    pub fn is_held(&self) -> io::Result<bool> {
        if !self.healthy.load(Ordering::Acquire) {
            return Ok(false);
        }
        // SAFETY: fcntl only inspects the valid descriptor and command.
        let state = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLEASE) };
        if state < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(state == libc::F_RDLCK)
    }

    /// Copy the pinned, frozen source into a distinct writable inode. The
    /// source descriptor was opened before the fanotify mark, so its reads do
    /// not need a permission exception. New opens and pathname truncates stay
    /// denied, while other preexisting read-only descriptors remain harmless.
    /// The caller must persist its freeze intent first and publish the result
    /// only after the returned copy has been verified and synced.
    pub fn copy_sparse_independent(
        &self,
        destination: &File,
    ) -> Result<IndependentSparseCopy, AnchorError> {
        if !self.is_held()? {
            return Err(io::Error::other("write exclusion is no longer held").into());
        }
        run_after_sparse_copy_start_hook();
        let copy = copy_sparse_independent(&self.file, destination)?;
        if !self.is_held()? {
            return Err(io::Error::other("write exclusion was lost during sparse copy").into());
        }
        Ok(copy)
    }

    /// Release only after the caller has made the permission transition durable
    /// or abandoned it with the original permissions intact.
    pub fn release(mut self) -> io::Result<()> {
        self.unlock()
    }

    fn unlock(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.active = false;
        Ok(())
    }
}

fn copy_sparse_independent(
    source: &File,
    destination: &File,
) -> Result<IndependentSparseCopy, AnchorError> {
    let before = source.metadata()?;
    let target = destination.metadata()?;
    if !before.is_file()
        || !target.is_file()
        || before.dev() != target.dev()
        || before.ino() == target.ino()
        || target.nlink() != 1
        || target.len() != 0
        || before.len() > i64::MAX as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sparse detach needs a new, empty, private inode on the source filesystem",
        )
        .into());
    }
    let logical_len = before.len();
    let data_extents = file_data_extents(source, logical_len)?;
    destination.set_len(logical_len)?;
    let mut buffer = [0_u8; 64 * 1024];
    for extent in &data_extents {
        let end = extent.offset + extent.logical_len;
        let mut position = extent.offset;
        while position < end {
            let take = (end - position).min(buffer.len() as u64) as usize;
            let read = source.read_at(&mut buffer[..take], position)?;
            if read == 0 {
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "source extent shrank").into(),
                );
            }
            let mut written = 0;
            while written < read {
                let count =
                    destination.write_at(&buffer[written..read], position + written as u64)?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sparse copy write stopped",
                    )
                    .into());
                }
                written += count;
            }
            position += read as u64;
        }
    }
    destination.sync_all()?;
    let after = source.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mode(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) || destination.metadata()?.len() != logical_len
    {
        return Err(io::Error::other("source changed during sparse detach copy").into());
    }
    if file_data_extents(destination, logical_len)? != data_extents {
        return Err(io::Error::other("sparse detach copy changed hole layout").into());
    }
    let source_hash = hash_exact(source, logical_len)?;
    if hash_exact(destination, logical_len)? != source_hash {
        return Err(io::Error::other("sparse detach copy changed bytes").into());
    }
    Ok(IndependentSparseCopy {
        logical_len,
        content_hash: source_hash,
        data_extents,
    })
}

fn hash_exact(file: &File, logical_len: u64) -> io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut position = 0;
    while position < logical_len {
        let take = (logical_len - position).min(buffer.len() as u64) as usize;
        let read = file.read_at(&mut buffer[..take], position)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file shrank during hash",
            ));
        }
        hasher.update(&buffer[..read]);
        position += read as u64;
    }
    Ok(*hasher.finalize().as_bytes())
}

impl Drop for FileWriteExclusion {
    fn drop(&mut self) {
        let _ = self.unlock();
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn deny_new_opens(group: &File, stop: &AtomicBool, healthy: &AtomicBool) {
    let mut buffer = [0_u8; 16 * 1024];
    while !stop.load(Ordering::Acquire) {
        // SAFETY: the buffer is writable and the descriptor stays live for
        // this worker's lifetime.
        let count =
            unsafe { libc::read(group.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            match io::Error::last_os_error().kind() {
                io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
                io::ErrorKind::Interrupted => {}
                _ => {
                    healthy.store(false, Ordering::Release);
                    return;
                }
            }
            continue;
        }
        if count == 0 {
            healthy.store(false, Ordering::Release);
            return;
        }
        let mut offset = 0;
        let count = count as usize;
        while offset < count {
            if count - offset < std::mem::size_of::<FanotifyEventMetadata>() {
                healthy.store(false, Ordering::Release);
                return;
            }
            // SAFETY: the size check above covers the metadata, and an
            // unaligned read avoids assuming the kernel buffer's alignment.
            let event = unsafe {
                std::ptr::read_unaligned(
                    buffer.as_ptr().add(offset).cast::<FanotifyEventMetadata>(),
                )
            };
            let event_len = event.event_len as usize;
            if event.version != FANOTIFY_METADATA_VERSION
                || event_len < std::mem::size_of::<FanotifyEventMetadata>()
                || event_len > count - offset
                || (event.metadata_len as usize) < std::mem::size_of::<FanotifyEventMetadata>()
                || (event.metadata_len as usize) > event_len
                || event.mask & FAN_Q_OVERFLOW != 0
                || event.mask & (FAN_OPEN_PERM | FAN_PRE_ACCESS) == 0
                || event.fd < 0
            {
                if event.fd >= 0 {
                    // SAFETY: the kernel supplied an event descriptor and we
                    // are discarding this event without a permission reply.
                    unsafe { libc::close(event.fd) };
                }
                healthy.store(false, Ordering::Release);
                return;
            }
            let response = FanotifyResponse {
                fd: event.fd,
                response: FAN_DENY,
            };
            // SAFETY: the response is a valid Linux fanotify_response and
            // the event descriptor is owned by this worker after read().
            let written = unsafe {
                libc::write(
                    group.as_raw_fd(),
                    (&raw const response).cast(),
                    std::mem::size_of::<FanotifyResponse>(),
                )
            };
            // SAFETY: the event descriptor is no longer needed after the
            // permission decision, including if the write failed.
            unsafe { libc::close(event.fd) };
            if written != std::mem::size_of::<FanotifyResponse>() as isize {
                healthy.store(false, Ordering::Release);
                return;
            }
            offset += event_len;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    use super::{
        ACCESS_ACL_NAME, AFTER_SPARSE_COPY_START, AccessAclSnapshot, FileAccessSnapshot,
        FileWriteExclusion, file_data_extents,
    };

    #[test]
    fn access_snapshot_records_the_acl_mask_changed_by_chmod() {
        let root = test_directory();
        let path = root.path().join("access");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o660))
            .unwrap();
        // Linux POSIX ACL xattr: version 2 and owner, named user, group,
        // mask, and other entries. The named user grants write through mask.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        for (tag, permission, id) in [
            (1_u16, 6_u16, u32::MAX),
            (2, 6, 2000),
            (4, 6, u32::MAX),
            (16, 6, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permission.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        // SAFETY: the descriptor and xattr name are valid and acl owns its
        // full buffer for the duration of this call.
        let set = unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                ACCESS_ACL_NAME.as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        if set < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EOPNOTSUPP) {
            return;
        }
        assert_eq!(set, 0);
        let snapshot = FileAccessSnapshot::capture(&File::open(&path).unwrap()).unwrap();
        assert_eq!(snapshot.mode, 0o660);
        assert!(matches!(
            &snapshot.access_acl,
            AccessAclSnapshot::Present(_)
        ));
        let encoded = mb_core::canonical_bytes(&snapshot).unwrap();
        let decoded: FileAccessSnapshot = mb_core::decode_canonical(&encoded).unwrap();
        assert_eq!(decoded, snapshot);

        file.set_permissions(fs::Permissions::from_mode(0o440))
            .unwrap();
        assert!(!snapshot.matches(&file).unwrap());
        // SAFETY: the same valid descriptor, name, and original ACL buffer
        // are used to model exact restoration after an anchor is detached.
        assert_eq!(
            unsafe {
                libc::fsetxattr(
                    file.as_raw_fd(),
                    ACCESS_ACL_NAME.as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            },
            0
        );
        file.set_permissions(fs::Permissions::from_mode(snapshot.mode))
            .unwrap();
        assert!(snapshot.matches(&file).unwrap());
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn lease_rejects_open_writers_and_writable_mappings() {
        let root = test_directory();
        let path = root.path().join("source");
        fs::write(&path, vec![7_u8; 4096]).unwrap();

        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        let attempted = FileWriteExclusion::acquire(File::open(&path).unwrap());
        assert_eq!(attempted.err().unwrap().raw_os_error(), Some(libc::EAGAIN));
        drop(writer);

        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // SAFETY: the descriptor names a 4096-byte regular file; the mapping
        // is unmapped below before the test directory is removed.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        drop(writer);
        let attempted = FileWriteExclusion::acquire(File::open(&path).unwrap());
        assert_eq!(attempted.err().unwrap().raw_os_error(), Some(libc::EAGAIN));
        // SAFETY: this releases the exact mapping established above.
        assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);

        let guard = FileWriteExclusion::acquire(File::open(&path).unwrap()).unwrap();
        assert!(guard.is_held().unwrap());
        let access = FileAccessSnapshot::capture(&guard.file).unwrap();
        assert!(access.matches(&guard.file).unwrap());
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated path and integer flags are valid.
        let competing = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        assert_eq!(competing, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );

        // A pathname truncate does not need to open a writable descriptor.
        // FAN_PRE_ACCESS must deny it while the transition guard is active.
        // SAFETY: the NUL-terminated path is valid.
        assert_eq!(unsafe { libc::truncate(c_path.as_ptr(), 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 4096);

        let anchor = root.path().join("anchor");
        fs::hard_link(&path, &anchor).unwrap();
        let c_anchor = CString::new(anchor.as_os_str().as_bytes()).unwrap();
        // An inode mark must cover every hard-link alias, including an alias
        // created after acquisition.
        assert_eq!(unsafe { libc::truncate(c_anchor.as_ptr(), 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(fs::metadata(&anchor).unwrap().len(), 4096);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(guard.is_held().unwrap());
        guard.release().unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(OpenOptions::new().write(true).open(&anchor).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn guarded_sparse_copy_detaches_the_anchor_without_changing_bytes_or_holes() {
        let root = test_directory();
        let source_path = root.path().join("source");
        let anchor_path = root.path().join("anchor");
        let staging_path = root.path().join("private-staging");
        let logical_len = 1024 * 1024 + 4096;
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        source.set_len(logical_len).unwrap();
        source.write_at(b"head", 0).unwrap();
        source.write_at(b"tail", logical_len - 4).unwrap();
        source.sync_all().unwrap();
        let original_extents = file_data_extents(&source, logical_len).unwrap();
        assert!(original_extents.len() >= 2);
        drop(source);

        let other_reader = File::open(&source_path).unwrap();
        let guard = FileWriteExclusion::acquire(File::open(&source_path).unwrap()).unwrap();
        let access = FileAccessSnapshot::capture(&guard.file).unwrap();
        fs::hard_link(&source_path, &anchor_path).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
        let shared = guard.file.try_clone().unwrap();
        assert!(guard.copy_sparse_independent(&shared).is_err());
        assert_eq!(fs::metadata(&source_path).unwrap().len(), logical_len);
        let nonempty_path = root.path().join("nonempty");
        fs::write(&nonempty_path, b"keep").unwrap();
        let nonempty = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&nonempty_path)
            .unwrap();
        assert!(guard.copy_sparse_independent(&nonempty).is_err());
        assert_eq!(fs::read(&nonempty_path).unwrap(), b"keep");
        let private = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .unwrap();
        let alias_for_attempt = anchor_path.clone();
        AFTER_SPARSE_COPY_START.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let read = std::thread::spawn(move || {
                    let mut byte = [0];
                    (other_reader.read_at(&mut byte, 0).unwrap(), byte)
                })
                .join()
                .unwrap();
                assert_eq!(read, (1, *b"h"));
                let truncate_error = std::thread::spawn(move || {
                    let path = CString::new(alias_for_attempt.as_os_str().as_bytes()).unwrap();
                    // SAFETY: the pathname is a valid NUL-terminated string.
                    assert_eq!(unsafe { libc::truncate(path.as_ptr(), 0) }, -1);
                    std::io::Error::last_os_error()
                })
                .join()
                .unwrap();
                assert_eq!(truncate_error.raw_os_error(), Some(libc::EPERM));
            }));
        });
        let copied = guard.copy_sparse_independent(&private).unwrap();
        assert_eq!(copied.logical_len, logical_len);
        assert_eq!(copied.data_extents, original_extents);
        assert!(guard.is_held().unwrap());
        guard.release().unwrap();

        fs::rename(&staging_path, &anchor_path).unwrap();
        assert_ne!(
            fs::metadata(&source_path).unwrap().ino(),
            fs::metadata(&anchor_path).unwrap().ino()
        );
        fs::set_permissions(&source_path, fs::Permissions::from_mode(access.mode)).unwrap();
        fs::write(&source_path, b"edited").unwrap();
        assert_eq!(fs::metadata(&anchor_path).unwrap().len(), logical_len);
        assert_eq!(fs::read(&anchor_path).unwrap()[..4], *b"head");
        assert_eq!(
            fs::read(&anchor_path).unwrap()[(logical_len - 4) as usize..],
            *b"tail"
        );
        assert_eq!(
            file_data_extents(&File::open(&anchor_path).unwrap(), logical_len).unwrap(),
            original_extents
        );
    }

    fn test_directory() -> tempfile::TempDir {
        match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-link-freeze-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }
}
