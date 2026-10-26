//! Runtime extent admission for native SQL files. The VFS retains ordinary
//! SQLite file/lock/SHM operations and borrows their already open descriptors.
//! These ceilings do not enroll older writers or reserve an enclosing job.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};

use super::{DatabaseDirectory, DatabaseError};

pub(super) const CHUNK: u64 = 64 * 1024;

/// Independent native file-family ceilings and free-space headroom. Runtime
/// growth allocates real extents; callers still owe durable policy, operation
/// reservations, checkpoint/rebuild copies and admission of other writers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabasePhysicalIoLimits {
    pub main_bytes: u64,
    pub journal_bytes: u64,
    pub shm_bytes: u64,
    pub temporary_bytes: u64,
    pub total_bytes: u64,
    pub headroom_bytes: u64,
    pub files: u32,
}

impl DatabasePhysicalIoLimits {
    pub(super) fn validate(self) -> Result<(), DatabaseError> {
        let roles = [
            self.main_bytes,
            self.journal_bytes,
            self.shm_bytes,
            self.temporary_bytes,
        ];
        if self.files == 0
            || self.files > 64
            || self.total_bytes > i64::MAX as u64
            || !self.total_bytes.is_multiple_of(CHUNK)
            || roles
                .into_iter()
                .any(|n| n < CHUNK || n % CHUNK != 0 || n > self.total_bytes)
        {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        Ok(())
    }

    fn ceiling(self, role: Role) -> u64 {
        match role {
            Role::Main => self.main_bytes,
            Role::Journal => self.journal_bytes,
            Role::Shm => self.shm_bytes,
            Role::Temporary => self.temporary_bytes,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Role {
    Main,
    Journal,
    Shm,
    Temporary,
}

type Identity = (u64, u64);

// Native connections to one main inode share all file-family credits in this
// process. Weak entries grant no lifetime or persistent ownership by themselves.
// Cross-process enrollment remains the caller's responsibility.
static LIVE_POOLS: Mutex<BTreeMap<Identity, Weak<Pool>>> = Mutex::new(BTreeMap::new());

struct Entry {
    // O_PATH pins preserve identity and closed-but-linked allocation without
    // the main-file POSIX-lock side effect of another I/O descriptor's close.
    pin: File,
    role: Role,
    open: u32,
    bytes: u64,
}

pub(super) struct Pool {
    pub(super) limits: DatabasePhysicalIoLimits,
    pub(super) directory: DatabaseDirectory,
    main_name: OsString,
    pub(super) owner: Option<Arc<super::native_owner::OwnerState>>,
    allocation_lock: File,
    lock_path: PathBuf,
    main: Mutex<Option<File>>,
    files: Mutex<BTreeMap<Identity, Entry>>,
}

struct AllocationGuard<'a>(&'a File);
impl Drop for AllocationGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

impl Pool {
    pub(super) fn new(
        directory: &DatabaseDirectory,
        main_name: &OsStr,
        limits: DatabasePhysicalIoLimits,
    ) -> Result<Arc<Self>, DatabaseError> {
        Self::with_owner(directory, main_name, limits, None)
    }

    pub(super) fn new_owned(
        owner: Arc<super::native_owner::OwnerState>,
    ) -> Result<Arc<Self>, DatabaseError> {
        owner.require_claim()?;
        Self::with_owner(
            &owner.directory,
            &owner.name,
            owner.limits(),
            Some(owner.clone()),
        )
    }

    fn with_owner(
        directory: &DatabaseDirectory,
        main_name: &OsStr,
        limits: DatabasePhysicalIoLimits,
        owner: Option<Arc<super::native_owner::OwnerState>>,
    ) -> Result<Arc<Self>, DatabaseError> {
        limits.validate()?;
        directory.leaf(main_name)?;
        let (allocation_lock, lock_path) = super::scratch_space::shared_allocation_lock()?;
        Ok(Arc::new(Self {
            limits,
            directory: directory.clone(),
            main_name: main_name.to_owned(),
            owner,
            allocation_lock,
            lock_path,
            main: Mutex::new(None),
            files: Mutex::new(BTreeMap::new()),
        }))
    }

    /// Publish/reuse only after pinning the intended main inode, before native
    /// SQLite opens it. Different ceilings or journal namespaces cannot create
    /// a second live allowance for that inode. O_PATH pins prevent inode reuse
    /// while an old pool or any of its native bindings is still alive.
    pub(super) fn share(self: &Arc<Self>) -> Result<Arc<Self>, DatabaseError> {
        let identity = self.main_metadata()?;
        let mut pools = LIVE_POOLS
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        pools.retain(|_, pool| pool.strong_count() != 0);
        let id = (identity.dev(), identity.ino());
        if let Some(existing) = pools.get(&id).and_then(Weak::upgrade) {
            let directory = self.directory.file().metadata()?;
            let original = existing.directory.file().metadata()?;
            if self.limits != existing.limits
                || self.main_name != existing.main_name
                || (directory.dev(), directory.ino()) != (original.dev(), original.ino())
                || self.owner.as_ref().map(|owner| owner.identity())
                    != existing.owner.as_ref().map(|owner| owner.identity())
            {
                return Err(DatabaseError::Conflict);
            }
            return Ok(existing);
        }
        pools.insert(id, Arc::downgrade(self));
        Ok(Arc::clone(self))
    }

    fn main_metadata(&self) -> Result<std::fs::Metadata, DatabaseError> {
        let main = self
            .main
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let metadata = main
            .as_ref()
            .ok_or(DatabaseError::PhysicalIoUnavailable)?
            .metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        Ok(metadata)
    }

    pub(super) fn pin_main_path(&self, path: &Path) -> Result<(), DatabaseError> {
        let pin = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        self.remember_main(pin)
    }

    pub(super) fn pin_created_main(&self, created: &File) -> Result<(), DatabaseError> {
        let pin = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{}", created.as_raw_fd()))?;
        self.remember_main(pin)
    }

    fn remember_main(&self, pin: File) -> Result<(), DatabaseError> {
        if !pin.metadata()?.is_file() {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        if let Some(owner) = &self.owner {
            owner.verify_current()?;
            let m = pin.metadata()?;
            if (m.dev(), m.ino()) != owner.main_identity() {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
        }
        let mut main = self
            .main
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        if main.is_some() {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        *main = Some(pin);
        Ok(())
    }

    fn allocation_guard(&self) -> Result<AllocationGuard<'_>, DatabaseError> {
        loop {
            if unsafe { libc::flock(self.allocation_lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
        let guard = AllocationGuard(&self.allocation_lock);
        if let Some(owner) = &self.owner {
            owner.verify_current()?;
        }
        let expected = self.allocation_lock.metadata()?;
        let current = std::fs::symlink_metadata(&self.lock_path)?;
        if !current.is_dir() || (expected.dev(), expected.ino()) != (current.dev(), current.ino()) {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        self.allocation_lock
            .set_modified(std::time::SystemTime::now())?;
        Ok(guard)
    }

    /// Charge every retained linked SQL-family file before a managed reopen,
    /// including a rollback journal SQLite might not open in WAL mode. O_PATH
    /// never opens/closes an independent native I/O description or its locks.
    pub(super) fn admit_family_paths(&self) -> Result<(), DatabaseError> {
        let mut files = self
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.allocation_guard()?;
        self.refresh(&mut files)?;
        let device = self.directory.file().metadata()?.dev();
        for (suffix, role) in [
            ("", Role::Main),
            ("-wal", Role::Journal),
            ("-journal", Role::Journal),
            ("-shm", Role::Shm),
        ] {
            let mut name = self.main_name.clone();
            name.push(suffix);
            let pin = match OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(self.directory.leaf(name)?)
            {
                Ok(pin) => pin,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            let m = pin.metadata()?;
            if !m.is_file()
                || m.nlink() != 1
                || m.dev() != device
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o077 != 0
            {
                return Err(DatabaseError::PhysicalIoUnavailable);
            }
            let id = (m.dev(), m.ino());
            if let Some(entry) = files.get(&id) {
                if entry.role != role {
                    return Err(DatabaseError::PhysicalIoUnavailable);
                }
            } else {
                if files.len() >= self.limits.files as usize {
                    return Err(DatabaseError::CapacityExceeded);
                }
                files.insert(
                    id,
                    Entry {
                        pin,
                        role,
                        open: 0,
                        bytes: m
                            .blocks()
                            .checked_mul(512)
                            .ok_or(DatabaseError::CapacityExceeded)?,
                    },
                );
            }
        }
        self.refresh(&mut files)?;
        Ok(())
    }

    fn refresh(&self, files: &mut BTreeMap<Identity, Entry>) -> Result<u64, DatabaseError> {
        let mut retired = Vec::new();
        let mut total = 0u64;
        for (&id, entry) in files.iter_mut() {
            let metadata = entry.pin.metadata()?;
            if !metadata.is_file()
                || metadata.nlink() > 1
                || metadata.uid() != unsafe { libc::geteuid() }
                || metadata.mode() & 0o022 != 0
                || (metadata.dev(), metadata.ino()) != id
            {
                return Err(DatabaseError::PhysicalIoUnavailable);
            }
            if metadata.nlink() == 0 && entry.open == 0 {
                retired.push(id);
                continue;
            }
            entry.bytes = metadata
                .blocks()
                .checked_mul(512)
                .ok_or(DatabaseError::CapacityExceeded)?;
            total = total
                .checked_add(entry.bytes)
                .ok_or(DatabaseError::CapacityExceeded)?;
        }
        // Drop the final O_PATH references before granting their former space.
        for id in retired {
            files.remove(&id);
        }
        if total > self.limits.total_bytes {
            return Err(DatabaseError::CapacityExceeded);
        }
        for role in [Role::Main, Role::Journal, Role::Shm, Role::Temporary] {
            let used = files
                .values()
                .filter(|e| e.role == role)
                .try_fold(0u64, |sum, e| sum.checked_add(e.bytes))
                .ok_or(DatabaseError::CapacityExceeded)?;
            if used > self.limits.ceiling(role) {
                return Err(DatabaseError::CapacityExceeded);
            }
        }
        Ok(total)
    }

    pub(super) fn refresh_deleted(&self) -> Result<(), DatabaseError> {
        let mut files = self
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.allocation_guard()?;
        self.refresh(&mut files)?;
        Ok(())
    }

    pub(super) fn usage(&self) -> Result<u64, DatabaseError> {
        let mut files = self
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.allocation_guard()?;
        self.refresh(&mut files)
    }

    /// Conservative additional main/journal allocation for admission hints.
    /// Existing reusable journal space is not a new reservation; the native
    /// writer remains authoritative for each actual allocation.
    pub(super) fn write_available(&self) -> Result<u64, DatabaseError> {
        let mut files = self
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.allocation_guard()?;
        let total = self.refresh(&mut files)?;
        let mut available = self.limits.total_bytes.saturating_sub(total);
        for role in [Role::Main, Role::Journal] {
            let used = files
                .values()
                .filter(|entry| entry.role == role)
                .try_fold(0u64, |sum, entry| sum.checked_add(entry.bytes))
                .ok_or(DatabaseError::CapacityExceeded)?;
            available = available.min(self.limits.ceiling(role).saturating_sub(used));
        }
        Ok(available)
    }

    /// The descriptor is owned by a live native sqlite3_file. It must stay
    /// open until Binding::close is called after that native file closes.
    pub(super) unsafe fn bind(
        self: &Arc<Self>,
        descriptor: RawFd,
        role: Role,
    ) -> Result<Binding, DatabaseError> {
        let pin = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(format!("/proc/self/fd/{descriptor}"))?;
        let metadata = pin.metadata()?;
        let directory = self.directory.file().metadata()?;
        if !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.dev() != directory.dev()
            || (role != Role::Temporary && metadata.nlink() != 1)
            || metadata.nlink() > 1
        {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        let id = (metadata.dev(), metadata.ino());
        if role == Role::Main {
            let main = self
                .main
                .lock()
                .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
            let expected = main
                .as_ref()
                .ok_or(DatabaseError::PhysicalIoUnavailable)?
                .metadata()?;
            if (expected.dev(), expected.ino()) != id {
                return Err(DatabaseError::PhysicalIoUnavailable);
            }
        }
        let mut files = self
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.allocation_guard()?;
        self.refresh(&mut files)?;
        // Reusing a pool must not weaken a new native open's extent checks.
        // In particular a stopped main can have gained shared extents while
        // another connection still retains the original pool.
        if !files.contains_key(&id) && files.len() >= self.limits.files as usize {
            return Err(DatabaseError::CapacityExceeded);
        }
        // The native main descriptor must pass its source-admission guard
        // before NoCow initialization changes its ctime. No main mutation is
        // allowed until connect finishes that initialization after xOpen.
        if role != Role::Main {
            initialize_private_file(descriptor, metadata.len(), metadata.blocks())?;
            validate_private_allocations(descriptor)?;
        }
        if let Some(entry) = files.get_mut(&id) {
            if entry.role != role {
                return Err(DatabaseError::PhysicalIoUnavailable);
            }
            entry.open = entry
                .open
                .checked_add(1)
                .ok_or(DatabaseError::CapacityExceeded)?;
        } else {
            files.insert(
                id,
                Entry {
                    pin,
                    role,
                    open: 1,
                    bytes: metadata
                        .blocks()
                        .checked_mul(512)
                        .ok_or(DatabaseError::CapacityExceeded)?,
                },
            );
            if let Err(error) = self.refresh(&mut files) {
                files.remove(&id);
                return Err(error);
            }
        }
        Ok(Binding {
            pool: Arc::clone(self),
            descriptor,
            id,
            role,
            initialized: role != Role::Main,
            closed: false,
        })
    }
}

pub(super) struct Binding {
    pub(super) pool: Arc<Pool>,
    descriptor: RawFd,
    id: Identity,
    role: Role,
    initialized: bool,
    closed: bool,
}

impl Binding {
    pub(super) fn initialize_main(&mut self) -> Result<(), DatabaseError> {
        if self.role != Role::Main || self.closed {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        let files = self
            .pool
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.pool.allocation_guard()?;
        let metadata = files
            .get(&self.id)
            .ok_or(DatabaseError::PhysicalIoUnavailable)?
            .pin
            .metadata()?;
        initialize_private_file(self.descriptor, metadata.len(), metadata.blocks())?;
        validate_private_allocations(self.descriptor)?;
        self.initialized = true;
        Ok(())
    }

    pub(super) fn require_initialized(&self) -> Result<(), DatabaseError> {
        if !self.initialized || self.closed {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        Ok(())
    }

    pub(super) fn block_size(&self) -> Result<u64, DatabaseError> {
        allocation_block_size(self.descriptor)
    }
    /// Allocate and validate the complete rounded write range before native
    /// data I/O. Known sharing/encoded/delayed/unknown extents grant no backing.
    pub(super) fn fund(&self, offset: u64, end: u64) -> Result<(), DatabaseError> {
        self.require_initialized()?;
        if offset > end || end > self.pool.limits.ceiling(self.role) {
            return Err(DatabaseError::CapacityExceeded);
        }
        if offset == end {
            return Ok(());
        }
        let start = offset / CHUNK * CHUNK;
        let end = end
            .checked_add(CHUNK - 1)
            .ok_or(DatabaseError::CapacityExceeded)?
            / CHUNK
            * CHUNK;
        let mut files = self
            .pool
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.pool.allocation_guard()?;
        let total = self.pool.refresh(&mut files)?;
        let entry = files
            .get(&self.id)
            .ok_or(DatabaseError::PhysicalIoUnavailable)?;
        if entry.open == 0 || entry.role != self.role {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        let missing = private_missing_bytes(self.descriptor, start, end)?;
        let role_used = files
            .values()
            .filter(|e| e.role == self.role)
            .try_fold(0u64, |sum, e| sum.checked_add(e.bytes))
            .ok_or(DatabaseError::CapacityExceeded)?;
        if missing > self.pool.limits.total_bytes.saturating_sub(total)
            || missing
                > self
                    .pool
                    .limits
                    .ceiling(self.role)
                    .saturating_sub(role_used)
        {
            return Err(DatabaseError::CapacityExceeded);
        }
        let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(self.descriptor, space.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        let space = unsafe { space.assume_init() };
        let available = u64::try_from(u128::from(space.f_bavail) * u128::from(space.f_frsize))
            .map_err(|_| DatabaseError::CapacityExceeded)?;
        if available < self.pool.limits.headroom_bytes
            || missing > available - self.pool.limits.headroom_bytes
        {
            return Err(DatabaseError::CapacityExceeded);
        }
        if missing != 0 {
            let result = loop {
                if unsafe {
                    libc::fallocate(
                        self.descriptor,
                        libc::FALLOC_FL_KEEP_SIZE,
                        start as i64,
                        (end - start) as i64,
                    )
                } == 0
                {
                    break Ok(());
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    break Err(DatabaseError::Io(error));
                }
            };
            // A failed allocation may retain a partial reservation. Keep those
            // real blocks charged; never punch live database ranges to undo it.
            self.pool.refresh(&mut files)?;
            result?;
        }
        if private_missing_bytes(self.descriptor, start, end)? != 0 {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        Ok(())
    }

    pub(super) fn refresh_after_io(&self) -> Result<(), DatabaseError> {
        let mut files = self
            .pool
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.pool.allocation_guard()?;
        self.pool.refresh(&mut files)?;
        Ok(())
    }

    /// Call after native xClose/xShmUnmap. Closed linked files remain charged;
    /// unlinked files are released only after the final native description.
    pub(super) fn close(&mut self) -> Result<(), DatabaseError> {
        if self.closed {
            return Ok(());
        }
        let mut files = self
            .pool
            .files
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let _allocation = self.pool.allocation_guard()?;
        let entry = files
            .get_mut(&self.id)
            .ok_or(DatabaseError::PhysicalIoUnavailable)?;
        entry.open = entry
            .open
            .checked_sub(1)
            .ok_or(DatabaseError::PhysicalIoUnavailable)?;
        self.closed = true;
        self.pool.refresh(&mut files)?;
        Ok(())
    }
}

fn initialize_private_file(
    descriptor: RawFd,
    length: u64,
    blocks: u64,
) -> Result<(), DatabaseError> {
    #[cfg(test)]
    if std::env::var_os("MB_PHYSICAL_IO_TRACE").is_some() {
        eprintln!("physical init fd={descriptor} length={length} blocks={blocks}");
    }
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor, filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let kind = unsafe { filesystem.assume_init() }.f_type as u32;
    if ![
        libc::BTRFS_SUPER_MAGIC as u32,
        libc::EXT4_SUPER_MAGIC as u32,
        0x5846_5342,
    ]
    .contains(&kind)
    {
        return Err(DatabaseError::PhysicalIoUnavailable);
    }
    if kind == libc::BTRFS_SUPER_MAGIC as u32 {
        let mut flags: libc::c_long = 0;
        if unsafe { libc::ioctl(descriptor, libc::FS_IOC_GETFLAGS, &mut flags) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        if flags & 0x0080_0000 == 0 {
            #[cfg(test)]
            if std::env::var_os("MB_PHYSICAL_IO_TRACE").is_some() {
                eprintln!(
                    "physical NoCow fd={descriptor} flags={flags:x} length={length} blocks={blocks}"
                );
            }
            // Only an empty inode may enter NoCow. Native SHM initialization
            // calls this after its own reset under the exclusive DMS lock.
            if blocks != 0 || length != 0 {
                return Err(DatabaseError::PhysicalIoUnavailable);
            }
            flags |= 0x0080_0000;
            if unsafe { libc::ioctl(descriptor, libc::FS_IOC_SETFLAGS, &flags) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            flags = 0;
            if unsafe { libc::ioctl(descriptor, libc::FS_IOC_GETFLAGS, &mut flags) } != 0
                || flags & 0x0080_0000 == 0
            {
                #[cfg(test)]
                if std::env::var_os("MB_PHYSICAL_IO_TRACE").is_some() {
                    eprintln!("physical NoCow refused fd={descriptor} flags={flags:x}");
                }
                return Err(DatabaseError::PhysicalIoUnavailable);
            }
        }
    }
    Ok(())
}

fn allocation_block_size(descriptor: RawFd) -> Result<u64, DatabaseError> {
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor, filesystem.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let bytes = unsafe { filesystem.assume_init() }.f_bsize;
    let bytes = u64::try_from(bytes).map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
    if !bytes.is_power_of_two() || !(4096..=CHUNK).contains(&bytes) {
        return Err(DatabaseError::PhysicalIoUnavailable);
    }
    Ok(bytes)
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Extent {
    logical: u64,
    physical: u64,
    length: u64,
    reserved64: [u64; 2],
    flags: u32,
    reserved32: [u32; 3],
}
#[repr(C)]
struct Fiemap {
    start: u64,
    length: u64,
    flags: u32,
    mapped: u32,
    count: u32,
    reserved: u32,
    extents: [Extent; 128],
}

fn read_extents(descriptor: RawFd, start: u64, length: u64) -> Result<Fiemap, DatabaseError> {
    let mut map = Fiemap {
        start,
        length,
        flags: 1,
        mapped: 0,
        count: 128,
        reserved: 0,
        extents: [Extent::default(); 128],
    };
    // glibc and musl expose different request types for the same Linux ioctl
    // bits. Infer the libc argument type without changing the FIEMAP request.
    if unsafe { libc::ioctl(descriptor, 0xC020_660B_u32 as _, &mut map) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    if map.mapped > map.count {
        return Err(DatabaseError::PhysicalIoUnavailable);
    }
    Ok(map)
}

fn validate_extent(descriptor: RawFd, extent: &Extent) -> Result<(), DatabaseError> {
    if extent.flags & !(1 | 0x800 | 0x1000) != 0 || extent.physical == 0 || extent.length == 0 {
        #[cfg(test)]
        if std::env::var_os("MB_PHYSICAL_IO_TRACE").is_some() {
            eprintln!(
                "physical FIEMAP refused fd={descriptor} logical={} physical={} length={} flags={:x}",
                extent.logical, extent.physical, extent.length, extent.flags
            );
        }
        return Err(DatabaseError::PhysicalIoUnavailable);
    }
    // This parameter also identifies diagnostic output in test builds.
    let _ = descriptor;
    Ok(())
}

/// Inspect all existing allocated extents before SQLite can begin a writer.
/// Holes remain unfunded until the corresponding write; known sharing or
/// inline/encoded/delayed allocations refuse open. Pagination bounds memory
/// without imposing an extent-count or catalog-size ceiling.
fn validate_private_allocations(descriptor: RawFd) -> Result<(), DatabaseError> {
    let mut cursor = 0;
    loop {
        let map = read_extents(descriptor, cursor, u64::MAX - cursor)?;
        let previous = cursor;
        for extent in &map.extents[..map.mapped as usize] {
            validate_extent(descriptor, extent)?;
            cursor = cursor.max(
                extent
                    .logical
                    .checked_add(extent.length)
                    .ok_or(DatabaseError::PhysicalIoUnavailable)?,
            );
        }
        if map.mapped == 0 || map.extents[map.mapped as usize - 1].flags & 1 != 0 {
            return Ok(());
        }
        if cursor <= previous || cursor == u64::MAX {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
    }
}

fn private_missing_bytes(descriptor: RawFd, start: u64, end: u64) -> Result<u64, DatabaseError> {
    let map = read_extents(descriptor, start, end - start)?;
    let mut cursor = start;
    let mut missing = 0u64;
    for extent in &map.extents[..map.mapped as usize] {
        validate_extent(descriptor, extent)?;
        let next = extent
            .logical
            .checked_add(extent.length)
            .ok_or(DatabaseError::PhysicalIoUnavailable)?
            .min(end);
        if next <= cursor {
            continue;
        }
        let logical = extent.logical.max(start);
        if logical > cursor {
            missing = missing
                .checked_add(logical - cursor)
                .ok_or(DatabaseError::CapacityExceeded)?;
        }
        cursor = next;
    }
    if cursor < end {
        if map.mapped == map.count && map.extents[(map.mapped - 1) as usize].flags & 1 == 0 {
            return Err(DatabaseError::PhysicalIoUnavailable);
        }
        missing = missing
            .checked_add(end - cursor)
            .ok_or(DatabaseError::CapacityExceeded)?;
    }
    Ok(missing)
}

pub(super) fn sqlite_code(error: DatabaseError, fallback: i32) -> i32 {
    #[cfg(test)]
    if std::env::var_os("MB_PHYSICAL_IO_TRACE").is_some() {
        eprintln!("physical refusal: {error:?}");
    }
    match error {
        DatabaseError::CapacityExceeded | DatabaseError::PhysicalIoUnavailable => {
            rusqlite::ffi::SQLITE_FULL
        }
        DatabaseError::Io(error)
            if matches!(error.raw_os_error(), Some(libc::ENOSPC | libc::EDQUOT)) =>
        {
            rusqlite::ffi::SQLITE_FULL
        }
        _ => fallback,
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod parity_tests;
