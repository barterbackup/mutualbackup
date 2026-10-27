//! Linux anonymous SQLite file I/O with physical allocation before writes.
//! This VFS accepts only private temporary files. Durable databases continue to
//! use SQLite's ordinary VFS. Owned catalog leases fund one initialized backing
//! file before use; other scratch files allocate on growth. The registered
//! adapter outlives its connection.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::Mutex;

use rusqlite::ffi;
use uuid::Uuid;

use super::DatabaseError;
mod arena;
use arena::{Arena, ArenaFile};

const CHUNK: u64 = 64 * 1024;
// Linux filesystem IDs are 32-bit; glibc and musl expose different f_type types.
const BTRFS_TYPE: u32 = libc::BTRFS_SUPER_MAGIC as u32;

/// Runtime allocation-pool identity. Btrfs subvolumes and bind mounts share
/// their filesystem UUID; ordinary filesystems use their current device ID.
/// This is not a durable source identity or evidence of free physical capacity.
pub fn physical_allocation_domain(path: impl AsRef<Path>) -> Result<[u8; 32], DatabaseError> {
    domain_for_file(&super::directory::open_directory_file(path.as_ref())?)
}

fn domain_for_file(file: &File) -> Result<[u8; 32], DatabaseError> {
    domain_for_descriptor(file.as_fd())
}

/// Inspect only the live borrowed file: do not duplicate, close, or reenter
/// SQLite while this descriptor is borrowed from its main file.
pub(super) fn domain_for_descriptor(file: BorrowedFd<'_>) -> Result<[u8; 32], DatabaseError> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let mut digest =
        blake3::Hasher::new_derive_key("mutualbackup runtime physical allocation domain v1");
    if unsafe { filesystem.assume_init() }.f_type as u32 == BTRFS_TYPE {
        digest.update(b"btrfs");
        digest.update(
            &crate::anchor::btrfs_filesystem_uuid(&file)
                .map_err(|_| DatabaseError::ScratchUnavailable)?,
        );
    } else {
        digest.update(b"device");
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let device = unsafe { info.assume_init() }.st_dev;
        #[allow(
            clippy::unnecessary_cast,
            reason = "Linux stat widths vary by target ABI"
        )]
        digest.update(&(device as u64).to_be_bytes());
    }
    Ok(*digest.finalize().as_bytes())
}

pub(super) fn shared_allocation_lock() -> Result<(File, PathBuf), DatabaseError> {
    // One fixed, private rendezvous for this host user. It deliberately remains
    // present across jobs; unlinking a live advisory-lock inode breaks mutual
    // exclusion. Descriptor/path identity is rechecked after each acquisition.
    let uid = unsafe { libc::geteuid() };
    let path = PathBuf::from(format!("/tmp/.mutualbackup-scratch-allocation-{uid}"));
    // Only the process-isolated lock probe selects its own rendezvous. Holding
    // the production rendezvous in that fixture stalls unrelated parallel tests
    // and lets their allocations starve the child's bounded resume assertion.
    #[cfg(test)]
    let path = std::env::var_os("MB_SCRATCH_ALLOCATION_LOCK_PROBE_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or(path);
    allocation_lock_at(path)
}

fn allocation_lock_at(path: PathBuf) -> Result<(File, PathBuf), DatabaseError> {
    let uid = unsafe { libc::geteuid() };
    match std::fs::DirBuilder::new().mode(0o700).create(&path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let metadata = file.metadata()?;
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(DatabaseError::ScratchUnavailable);
    }
    Ok((file, path))
}

pub(super) struct ScratchVfs {
    vfs: Box<ffi::sqlite3_vfs>,
    name: CString,
    // Files borrow this allocation until SQLite closes the connection.
    _state: Box<State>,
}

// SAFETY: Moving this owner does not move its boxed VFS/State or CString
// allocations, so SQLite's registered pointers stay valid. The original VFS
// is SQLite's process-global native adapter, not a thread-local allocation.
// File descriptors and allocation counters are thread-safe; there are no
// thread-affine fields. RecordScratchStore retains rusqlite's !Sync connection
// and closes it before unregistering this adapter. Shared users must serialize
// the complete connection (as the Git ODB's Mutex does), consistent with
// https://sqlite.org/threadsafe.html for SQLITE_OPEN_NOMUTEX connections.
unsafe impl Send for ScratchVfs {}

struct State {
    original: *mut ffi::sqlite3_vfs,
    directory: File,
    allocation_lock: File,
    lock_path: PathBuf,
    max_physical_bytes: u64,
    headroom_bytes: u64,
    allocated_bytes: Mutex<u64>,
    // Drop the backing before releasing the lease's kernel ownership slot.
    arena: Option<Mutex<Arena>>,
    checkpoints: Vec<(File, std::ffi::OsString)>,
    lease: Option<crate::CatalogScratchLease>,
}

struct DiskFile {
    file: File,
    state: *const State,
    allocated: u64,
    charged: u64,
    physical_bytes: u64,
    headroom_pending: bool,
}

#[repr(C)]
struct SqlFile {
    base: ffi::sqlite3_file,
    disk: Option<Box<DiskFile>>,
    arena: Option<Box<ArenaFile>>,
}

impl ScratchVfs {
    pub(super) fn new(
        directory: &Path,
        max_physical_bytes: u64,
        headroom_bytes: u64,
        checkpoint_paths: &[PathBuf],
    ) -> Result<Self, DatabaseError> {
        Self::new_with_lease(
            directory,
            max_physical_bytes,
            headroom_bytes,
            checkpoint_paths,
            None,
        )
    }

    pub(super) fn new_with_lease(
        directory: &Path,
        max_physical_bytes: u64,
        headroom_bytes: u64,
        checkpoint_paths: &[PathBuf],
        lease: Option<crate::CatalogScratchLease>,
    ) -> Result<Self, DatabaseError> {
        // Initialize through rusqlite before finding SQLite's default VFS.
        drop(rusqlite::Connection::open_in_memory()?);
        let directory = super::directory::open_directory_file(directory)?;
        if checkpoint_paths.len() > 1024 || max_physical_bytes < CHUNK {
            return Err(DatabaseError::ScratchUnavailable);
        }
        let device = domain_for_file(&directory)?;
        if let Some(lease) = &lease {
            lease
                .check_domain(device, max_physical_bytes)
                .map_err(|_| DatabaseError::ScratchUnavailable)?;
        }
        let (allocation_lock, lock_path) = shared_allocation_lock()?;
        let mut checkpoints = Vec::new();
        for path in checkpoint_paths {
            let parent = path
                .parent()
                .filter(|path| !path.as_os_str().is_empty())
                .unwrap_or(Path::new("."));
            let directory = super::directory::open_directory_file(parent)?;
            if domain_for_file(&directory)? != device {
                return Err(DatabaseError::ScratchUnavailable);
            }
            let name = path
                .file_name()
                .ok_or(DatabaseError::ScratchUnavailable)?
                .to_os_string();
            checkpoints.push((directory, name));
        }
        let original = unsafe { ffi::sqlite3_vfs_find(ptr::null()) };
        if original.is_null() {
            return Err(DatabaseError::ScratchUnavailable);
        }
        let name = CString::new(format!("mb-scratch-{}", Uuid::new_v4()))
            .map_err(|_| DatabaseError::ScratchUnavailable)?;
        let mut state = Box::new(State {
            original,
            directory,
            allocation_lock,
            lock_path,
            max_physical_bytes,
            headroom_bytes,
            allocated_bytes: Mutex::new(0),
            arena: None,
            checkpoints,
            lease,
        });
        if let Some(lease) = &state.lease {
            let arena = Arena::new(&state).map_err(|code| {
                if code == ffi::SQLITE_FULL {
                    DatabaseError::CapacityExceeded
                } else {
                    DatabaseError::ScratchUnavailable
                }
            })?;
            lease
                .check(max_physical_bytes)
                .map_err(|_| DatabaseError::ScratchUnavailable)?;
            state.arena = Some(Mutex::new(arena));
        }
        // The callbacks receiving a VFS pointer delegate with the original VFS
        // pointer, preserving its application data. File I/O is entirely ours.
        let mut vfs = Box::new(unsafe { *original });
        vfs.iVersion = 2;
        vfs.szOsFile = std::mem::size_of::<SqlFile>() as c_int;
        vfs.pNext = ptr::null_mut();
        vfs.zName = name.as_ptr();
        vfs.pAppData = (&mut *state as *mut State).cast();
        vfs.xOpen = Some(open);
        vfs.xDelete = Some(delete);
        vfs.xAccess = Some(access);
        vfs.xFullPathname = Some(full_path);
        vfs.xDlOpen = None;
        vfs.xDlError = None;
        vfs.xDlSym = None;
        vfs.xDlClose = None;
        vfs.xRandomness = Some(randomness);
        vfs.xSleep = Some(sleep);
        vfs.xCurrentTime = Some(current_time);
        vfs.xGetLastError = Some(last_error);
        vfs.xCurrentTimeInt64 = Some(current_time_int64);
        vfs.xSetSystemCall = None;
        vfs.xGetSystemCall = None;
        vfs.xNextSystemCall = None;
        let result = unsafe { ffi::sqlite3_vfs_register(&mut *vfs, 0) };
        if result != ffi::SQLITE_OK {
            return Err(DatabaseError::ScratchUnavailable);
        }
        Ok(Self {
            vfs,
            name,
            _state: state,
        })
    }

    pub(super) fn name(&self) -> &str {
        // Constructed solely from an ASCII prefix and UUID.
        self.name.to_str().expect("ASCII scratch VFS name")
    }

    pub(super) fn check_reusable(&self) -> Result<(), DatabaseError> {
        let state = &self._state;
        // Check ownership before locking an allocator inherited across fork.
        state
            .lease
            .as_ref()
            .ok_or(DatabaseError::ScratchUnavailable)?
            .check(state.max_physical_bytes)
            .map_err(|_| DatabaseError::ScratchUnavailable)?;
        let arena = state
            .arena
            .as_ref()
            .ok_or(DatabaseError::ScratchUnavailable)?
            .lock()
            .map_err(|_| DatabaseError::ScratchUnavailable)?;
        if !arena
            .is_idle()
            .map_err(|_| DatabaseError::ScratchUnavailable)?
        {
            return Err(DatabaseError::ScratchUnavailable);
        }
        Ok(())
    }
}

impl Drop for ScratchVfs {
    fn drop(&mut self) {
        // RecordScratchStore declares its connection before this adapter, so
        // SQLite has closed all borrowed DiskFile objects before unregistering.
        unsafe {
            ffi::sqlite3_vfs_unregister(&mut *self.vfs);
        }
    }
}

fn io_code(error: io::Error, fallback: c_int) -> c_int {
    match error.raw_os_error() {
        Some(libc::ENOSPC | libc::EDQUOT) => ffi::SQLITE_FULL,
        _ => fallback,
    }
}

fn protect(operation: impl FnOnce() -> c_int) -> c_int {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(ffi::SQLITE_IOERR)
}

struct AllocationLock<'a>(&'a File);
impl Drop for AllocationLock<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl State {
    fn allocation_guard(&self) -> Result<AllocationLock<'_>, c_int> {
        loop {
            if unsafe { libc::flock(self.allocation_lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(io_code(error, ffi::SQLITE_IOERR_LOCK));
            }
        }
        let lock = AllocationLock(&self.allocation_lock);
        let expected = match self.allocation_lock.metadata() {
            Ok(metadata) => metadata,
            Err(_) => return Err(ffi::SQLITE_IOERR_LOCK),
        };
        let current = match std::fs::symlink_metadata(&self.lock_path) {
            Ok(metadata) => metadata,
            Err(_) => return Err(ffi::SQLITE_IOERR_LOCK),
        };
        if current.dev() != expected.dev() || current.ino() != expected.ino() || !current.is_dir() {
            return Err(ffi::SQLITE_IOERR_LOCK);
        }
        if self
            .allocation_lock
            .set_modified(std::time::SystemTime::now())
            .is_err()
        {
            return Err(ffi::SQLITE_IOERR_LOCK);
        }

        Ok(lock)
    }

    fn available_after_headroom(&self) -> Result<u64, c_int> {
        let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(self.directory.as_raw_fd(), space.as_mut_ptr()) } != 0 {
            return Err(ffi::SQLITE_IOERR_FSTAT);
        }
        let space = unsafe { space.assume_init() };
        let Ok(available) = u64::try_from(u128::from(space.f_bavail) * u128::from(space.f_frsize))
        else {
            return Err(ffi::SQLITE_FULL);
        };
        let mut headroom = self.headroom_bytes;
        for (directory, name) in &self.checkpoints {
            let path = PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name);
            let bytes = match super::wal_checkpoint_reservation_bytes(&path) {
                Ok(bytes) => bytes,
                Err(_) => return Err(ffi::SQLITE_IOERR_FSTAT),
            };
            let Some(updated) = headroom.checked_add(bytes) else {
                return Err(ffi::SQLITE_FULL);
            };
            headroom = updated;
        }
        available.checked_sub(headroom).ok_or(ffi::SQLITE_FULL)
    }
}

impl DiskFile {
    // Keep rounded data reservations and actual extent-tree blocks charged.
    // On refusal, release only unused tail extents: SQL rollback still needs
    // every byte up to the current logical EOF. Cleanup never changes refusal
    // into success, and any retained excess remains charged until close/retry.
    fn reconcile(&mut self, total: &mut u64) -> c_int {
        let state = unsafe { &*self.state };
        let measure = |disk: &mut Self, total: &mut u64| -> Result<u64, c_int> {
            let metadata = disk.file.metadata().map_err(|_| ffi::SQLITE_IOERR_FSTAT)?;
            let blocks = metadata.blocks().checked_mul(512).ok_or(ffi::SQLITE_FULL)?;
            let charged = blocks.max(disk.allocated.div_ceil(CHUNK) * CHUNK);
            *total = total.saturating_sub(disk.charged).saturating_add(charged);
            disk.charged = charged;
            disk.physical_bytes = blocks;
            Ok(metadata.len())
        };
        let previous_physical = self.physical_bytes;
        let length = match measure(self, total) {
            Ok(length) => length,
            Err(code) => return code,
        };
        if self.physical_bytes == 0 {
            self.headroom_pending = false;
        }
        let headroom_exceeded = if self.physical_bytes > previous_physical || self.headroom_pending
        {
            // A failed measurement or refusal must be rechecked on retry,
            // even when the already-written metadata does not grow again.
            self.headroom_pending = true;
            match state.available_after_headroom() {
                Ok(_) => {
                    self.headroom_pending = false;
                    false
                }
                Err(ffi::SQLITE_FULL) => true,
                Err(code) => return code,
            }
        } else {
            false
        };
        if *total <= state.max_physical_bytes && !headroom_exceeded {
            return ffi::SQLITE_OK;
        }
        self.headroom_pending = true;
        let trimmed = self.file.set_len(length);
        if trimmed.is_ok() {
            self.allocated = length;
        }
        let measured = measure(self, total);
        if let Err(error) = trimmed {
            return io_code(error, ffi::SQLITE_IOERR_TRUNCATE);
        }
        if let Err(code) = measured {
            return code;
        }
        ffi::SQLITE_FULL
    }

    fn refresh(&mut self) -> c_int {
        let state = unsafe { &*self.state };
        let Ok(mut total) = state.allocated_bytes.lock() else {
            return ffi::SQLITE_IOERR;
        };
        let _lock = match state.allocation_guard() {
            Ok(lock) => lock,
            Err(code) => return code,
        };
        self.reconcile(&mut total)
    }

    fn allocate(&mut self, end: u64) -> c_int {
        let state = unsafe { &*self.state };
        if state
            .lease
            .as_ref()
            .is_some_and(|lease| lease.check(state.max_physical_bytes).is_err())
        {
            return ffi::SQLITE_IOERR_WRITE;
        }
        let refreshed = self.refresh();
        if refreshed != ffi::SQLITE_OK {
            return refreshed;
        }
        if end <= self.allocated {
            return ffi::SQLITE_OK;
        }
        let Some(new_size) = end
            .checked_add(CHUNK - 1)
            .map(|value| value / CHUNK * CHUNK)
        else {
            return ffi::SQLITE_FULL;
        };
        if new_size > i64::MAX as u64 {
            return ffi::SQLITE_FULL;
        }
        // State is owned by the registered VFS until every file closes.
        let state = unsafe { &*self.state };
        let Ok(mut total) = state.allocated_bytes.lock() else {
            return ffi::SQLITE_IOERR;
        };
        let increase = new_size - self.allocated;
        let Some(new_total) = total.checked_add(new_size.saturating_sub(self.charged)) else {
            return ffi::SQLITE_FULL;
        };
        if new_total > state.max_physical_bytes {
            return ffi::SQLITE_FULL;
        }
        let _lock = match state.allocation_guard() {
            Ok(lock) => lock,
            Err(code) => return code,
        };
        let available = match state.available_after_headroom() {
            Ok(available) => available,
            Err(code) => return code,
        };
        if increase > available {
            return ffi::SQLITE_FULL;
        }
        // Allocate real extents without increasing logical EOF. Concurrent jobs
        // observe these reserved blocks in statvfs before their next admission.
        // Unsupported filesystems fail closed instead of making sparse promises.
        loop {
            if unsafe {
                libc::fallocate(
                    self.file.as_raw_fd(),
                    libc::FALLOC_FL_KEEP_SIZE,
                    self.allocated as i64,
                    increase as i64,
                )
            } == 0
            {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                let refreshed = self.reconcile(&mut total);
                return if refreshed == ffi::SQLITE_OK {
                    io_code(error, ffi::SQLITE_IOERR_WRITE)
                } else {
                    refreshed
                };
            }
        }
        self.allocated = new_size;
        self.reconcile(&mut total)
    }
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    output: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    protect(|| unsafe {
        (*output).pMethods = ptr::null();
        let allowed =
            ffi::SQLITE_OPEN_TEMP_DB | ffi::SQLITE_OPEN_TEMP_JOURNAL | ffi::SQLITE_OPEN_SUBJOURNAL;
        // Reject every named file and every durable database/WAL role.
        if !name.is_null() || flags & allowed == 0 || flags & ffi::SQLITE_OPEN_DELETEONCLOSE == 0 {
            return ffi::SQLITE_CANTOPEN;
        }
        let state = (*vfs).pAppData.cast::<State>();
        if (*state).arena.is_some() {
            ptr::write(
                output.cast::<SqlFile>(),
                SqlFile {
                    base: ffi::sqlite3_file { pMethods: &METHODS },
                    disk: None,
                    arena: Some(Box::new(ArenaFile::new(state))),
                },
            );
            if !out_flags.is_null() {
                *out_flags = flags;
            }
            return ffi::SQLITE_OK;
        }
        let directory = PathBuf::from(format!("/proc/self/fd/{}", (*state).directory.as_raw_fd()));
        let file = match tempfile::tempfile_in(directory) {
            Ok(file) => file,
            Err(error) => return io_code(error, ffi::SQLITE_CANTOPEN),
        };
        // Anonymous files cannot enter filesystem snapshots. Disabling data
        // CoW on empty Btrfs files keeps rewrites inside the reserved extents;
        // SQLCipher still authenticates every encrypted database/journal page.
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if libc::fstatfs(file.as_raw_fd(), filesystem.as_mut_ptr()) != 0 {
            return ffi::SQLITE_IOERR_FSTAT;
        }
        if filesystem.assume_init().f_type as u32 == BTRFS_TYPE {
            let mut attributes: libc::c_long = 0;
            if libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut attributes) != 0 {
                return ffi::SQLITE_IOERR;
            }
            attributes |= 0x0080_0000; // Linux FS_NOCOW_FL.
            if libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &attributes) != 0 {
                return ffi::SQLITE_IOERR;
            }
        }
        ptr::write(
            output.cast::<SqlFile>(),
            SqlFile {
                base: ffi::sqlite3_file { pMethods: &METHODS },
                disk: Some(Box::new(DiskFile {
                    file,
                    state,
                    allocated: 0,
                    charged: 0,
                    physical_bytes: 0,
                    headroom_pending: false,
                })),
                arena: None,
            },
        );
        if !out_flags.is_null() {
            *out_flags = flags;
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    protect(|| unsafe {
        let file = &mut *file.cast::<SqlFile>();
        if let Some(mut arena) = file.arena.take() {
            let result = arena.close();
            file.base.pMethods = ptr::null();
            return result;
        }
        if let Some(disk) = file.disk.take() {
            let state = &*disk.state;
            // Close the descriptor before releasing its accounting.
            let allocated = disk.charged;
            drop(disk);
            let Ok(mut total) = state.allocated_bytes.lock() else {
                return ffi::SQLITE_IOERR_CLOSE;
            };
            *total = total.saturating_sub(allocated);
        }
        file.base.pMethods = ptr::null();
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn read(
    file: *mut ffi::sqlite3_file,
    output: *mut c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    protect(|| unsafe {
        if amount < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_READ;
        }
        if amount == 0 {
            return ffi::SQLITE_OK;
        }
        if let Some(arena) = (&mut *file.cast::<SqlFile>()).arena.as_mut() {
            return arena.read(
                std::slice::from_raw_parts_mut(output.cast::<u8>(), amount as usize),
                offset as u64,
            );
        }
        let Some(disk) = (&*file.cast::<SqlFile>()).disk.as_ref() else {
            return ffi::SQLITE_IOERR_READ;
        };
        let mut bytes = std::slice::from_raw_parts_mut(output.cast::<u8>(), amount as usize);
        let mut position = offset as u64;
        while !bytes.is_empty() {
            match disk.file.read_at(bytes, position) {
                Ok(0) => {
                    bytes.fill(0);
                    return ffi::SQLITE_IOERR_SHORT_READ;
                }
                Ok(count) => {
                    position += count as u64;
                    bytes = &mut bytes[count..];
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return io_code(error, ffi::SQLITE_IOERR_READ),
            }
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    input: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    protect(|| unsafe {
        if amount < 0 || offset < 0 {
            return ffi::SQLITE_IOERR_WRITE;
        }
        if amount == 0 {
            return ffi::SQLITE_OK;
        }
        if let Some(arena) = (&mut *file.cast::<SqlFile>()).arena.as_mut() {
            return arena.write(
                std::slice::from_raw_parts(input.cast::<u8>(), amount as usize),
                offset as u64,
            );
        }
        let Some(disk) = (&mut *file.cast::<SqlFile>()).disk.as_mut() else {
            return ffi::SQLITE_IOERR_WRITE;
        };
        let Some(end) = (offset as u64).checked_add(amount as u64) else {
            return ffi::SQLITE_FULL;
        };
        let result = disk.allocate(end);
        if result != ffi::SQLITE_OK {
            return result;
        }
        let bytes = std::slice::from_raw_parts(input.cast::<u8>(), amount as usize);
        let written = disk.file.write_all_at(bytes, offset as u64);
        let refreshed = disk.refresh();
        if refreshed != ffi::SQLITE_OK {
            return refreshed;
        }
        match written {
            Ok(()) => ffi::SQLITE_OK,
            Err(error) => io_code(error, ffi::SQLITE_IOERR_WRITE),
        }
    })
}

unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, size: i64) -> c_int {
    protect(|| unsafe {
        if size < 0 {
            return ffi::SQLITE_IOERR_TRUNCATE;
        }
        if let Some(arena) = (&mut *file.cast::<SqlFile>()).arena.as_mut() {
            return arena.truncate(size as u64);
        }
        let Some(disk) = (&mut *file.cast::<SqlFile>()).disk.as_mut() else {
            return ffi::SQLITE_IOERR_TRUNCATE;
        };
        if size as u64 > disk.allocated {
            let result = disk.allocate(size as u64);
            if result != ffi::SQLITE_OK {
                return result;
            }
        }
        if let Err(error) = disk.file.set_len(size as u64) {
            return io_code(error, ffi::SQLITE_IOERR_TRUNCATE);
        }
        // Truncation frees tail extents, but extent metadata may remain.
        disk.allocated = size as u64;
        disk.refresh()
    })
}

unsafe extern "C" fn sync(file: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    protect(|| unsafe {
        if let Some(arena) = (&mut *file.cast::<SqlFile>()).arena.as_mut() {
            return arena.sync();
        }
        let Some(disk) = (&mut *file.cast::<SqlFile>()).disk.as_mut() else {
            return ffi::SQLITE_IOERR_FSYNC;
        };
        let synced = disk.file.sync_data();
        let refreshed = disk.refresh();
        if refreshed != ffi::SQLITE_OK {
            return refreshed;
        }
        match synced {
            Ok(()) => ffi::SQLITE_OK,
            Err(error) => io_code(error, ffi::SQLITE_IOERR_FSYNC),
        }
    })
}
unsafe extern "C" fn file_size(file: *mut ffi::sqlite3_file, size: *mut i64) -> c_int {
    protect(|| unsafe {
        if let Some(arena) = (&*file.cast::<SqlFile>()).arena.as_ref() {
            *size = arena.size();
            return ffi::SQLITE_OK;
        }
        let Some(disk) = (&*file.cast::<SqlFile>()).disk.as_ref() else {
            return ffi::SQLITE_IOERR_FSTAT;
        };
        match disk.file.metadata() {
            Ok(metadata) => {
                *size = metadata.len() as i64;
                ffi::SQLITE_OK
            }
            Err(error) => io_code(error, ffi::SQLITE_IOERR_FSTAT),
        }
    })
}
unsafe extern "C" fn lock(_: *mut ffi::sqlite3_file, _: c_int) -> c_int {
    ffi::SQLITE_OK
}
unsafe extern "C" fn reserved(_: *mut ffi::sqlite3_file, result: *mut c_int) -> c_int {
    unsafe {
        *result = 0;
    }
    ffi::SQLITE_OK
}
unsafe extern "C" fn control(_: *mut ffi::sqlite3_file, _: c_int, _: *mut c_void) -> c_int {
    ffi::SQLITE_NOTFOUND
}
unsafe extern "C" fn sector(_: *mut ffi::sqlite3_file) -> c_int {
    4096
}
unsafe extern "C" fn characteristics(_: *mut ffi::sqlite3_file) -> c_int {
    0
}
unsafe extern "C" fn delete(_: *mut ffi::sqlite3_vfs, _: *const c_char, _: c_int) -> c_int {
    ffi::SQLITE_IOERR_DELETE
}
unsafe extern "C" fn access(
    _: *mut ffi::sqlite3_vfs,
    _: *const c_char,
    _: c_int,
    result: *mut c_int,
) -> c_int {
    unsafe {
        *result = 0;
    }
    ffi::SQLITE_OK
}

macro_rules! delegate {
    ($name:ident, $member:ident, ($($arg:ident: $ty:ty),*), $fallback:expr) => {
        unsafe extern "C" fn $name(vfs: *mut ffi::sqlite3_vfs, $($arg: $ty),*) -> c_int {
            protect(|| unsafe {
                let original = (*(*vfs).pAppData.cast::<State>()).original;
                match (*original).$member { Some(callback) => callback(original, $($arg),*), None => $fallback }
            })
        }
    };
}
delegate!(full_path, xFullPathname, (name: *const c_char, length: c_int, output: *mut c_char), ffi::SQLITE_CANTOPEN);
delegate!(randomness, xRandomness, (length: c_int, output: *mut c_char), 0);
delegate!(sleep, xSleep, (micros: c_int), 0);
delegate!(current_time, xCurrentTime, (output: *mut f64), ffi::SQLITE_IOERR);
delegate!(current_time_int64, xCurrentTimeInt64, (output: *mut i64), ffi::SQLITE_IOERR);
delegate!(last_error, xGetLastError, (length: c_int, output: *mut c_char), 0);

static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 1,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(file_size),
    xLock: Some(lock),
    xUnlock: Some(lock),
    xCheckReservedLock: Some(reserved),
    xFileControl: Some(control),
    xSectorSize: Some(sector),
    xDeviceCharacteristics: Some(characteristics),
    xShmMap: None,
    xShmLock: None,
    xShmBarrier: None,
    xShmUnmap: None,
    xFetch: None,
    xUnfetch: None,
};

#[cfg(test)]
mod extent_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anonymous_sqlite_io_preserves_eof_zero_filling_truncation_and_quota() {
        let temp = tempfile::tempdir().unwrap();
        let mut vfs = ScratchVfs::new(temp.path(), CHUNK, 0, &[]).unwrap();
        unsafe {
            let flags = ffi::SQLITE_OPEN_TEMP_DB
                | ffi::SQLITE_OPEN_DELETEONCLOSE
                | ffi::SQLITE_OPEN_READWRITE
                | ffi::SQLITE_OPEN_CREATE;
            let mut output = std::mem::MaybeUninit::<SqlFile>::uninit();
            assert_eq!(
                open(
                    &mut *vfs.vfs,
                    c"named.db".as_ptr(),
                    output.as_mut_ptr().cast(),
                    flags,
                    ptr::null_mut()
                ),
                ffi::SQLITE_CANTOPEN
            );
            assert!((*output.as_ptr()).base.pMethods.is_null());
            assert_eq!(
                open(
                    &mut *vfs.vfs,
                    ptr::null(),
                    output.as_mut_ptr().cast(),
                    flags,
                    ptr::null_mut()
                ),
                ffi::SQLITE_OK
            );
            let mut file = output.assume_init();
            let pointer = (&mut file as *mut SqlFile).cast();
            assert_eq!(write(pointer, b"hi".as_ptr().cast(), 2, 4), ffi::SQLITE_OK);
            let mut size = 0;
            assert_eq!(file_size(pointer, &mut size), ffi::SQLITE_OK);
            assert_eq!(size, 6, "preallocation must not extend logical EOF");
            let mut bytes = [9u8; 16];
            assert_eq!(
                read(pointer, bytes.as_mut_ptr().cast(), 16, 0),
                ffi::SQLITE_IOERR_SHORT_READ
            );
            assert_eq!(&bytes[..6], &[0, 0, 0, 0, b'h', b'i']);
            assert_eq!(&bytes[6..], &[0; 10]);
            assert_eq!(
                write(pointer, b"x".as_ptr().cast(), 1, CHUNK as i64),
                ffi::SQLITE_FULL
            );
            assert_eq!(*vfs._state.allocated_bytes.lock().unwrap(), CHUNK);
            assert_eq!(truncate(pointer, -1), ffi::SQLITE_IOERR_TRUNCATE);
            assert_eq!(truncate(pointer, 0), ffi::SQLITE_OK);
            assert_eq!(*vfs._state.allocated_bytes.lock().unwrap(), 0);
            assert_eq!(write(pointer, b"a".as_ptr().cast(), 1, 0), ffi::SQLITE_OK);
            assert_eq!(close(pointer), ffi::SQLITE_OK);
            assert_eq!(*vfs._state.allocated_bytes.lock().unwrap(), 0);
        }
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }
    #[test]
    fn scratch_allocations_wait_for_other_processes_and_resume_after_unlock() {
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let probe_lock = temp.path().join("allocation-lock");
        let (lock, _) = allocation_lock_at(probe_lock.clone()).unwrap();
        assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
        let guard = AllocationLock(&lock);
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "database::scratch::tests::scratch_lifecycle_child",
                    "--nocapture",
                ])
                .env("MB_SCRATCH_LIFECYCLE_CHILD", temp.path())
                .env("MB_SCRATCH_ALLOCATION_LOCK_PROBE", "1")
                .env("MB_SCRATCH_ALLOCATION_LOCK_PROBE_DIRECTORY", &probe_lock)
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        let task_dir = format!("/proc/{}/task", child.0.id());
        loop {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "allocation probe child exited"
            );
            assert!(Instant::now() < deadline, "child did not block in flock");
            let blocked = std::fs::read_dir(&task_dir)
                .unwrap()
                .filter_map(Result::ok)
                .any(|entry| {
                    let Ok(syscall) = std::fs::read_to_string(entry.path().join("syscall")) else {
                        return false;
                    };
                    syscall
                        .split_whitespace()
                        .next()
                        .and_then(|number| number.parse::<i64>().ok())
                        == Some(libc::SYS_flock)
                });
            if temp.path().join("started").exists() && blocked {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!temp.path().join("ready").exists());
        drop(guard);
        while !temp.path().join("ready").exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "child exited after allocation unlock"
            );
            assert!(Instant::now() < deadline, "allocation did not resume");
            std::thread::sleep(Duration::from_millis(10));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
    }
}
