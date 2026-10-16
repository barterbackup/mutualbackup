//! Per-connection native physical I/O. The private registered VFS stays alive
//! until its owning ControlStore has closed its connection and native files.
use super::*;
use crate::database::{
    ControlStore, DatabaseDirectory, DatabasePhysicalIoLimits, ParityStore,
    physical_io::{self, Pool, Role},
};
use std::collections::BTreeMap;
use std::ffi::{CString, OsStr};
use std::fs::{File as IoFile, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::{Mutex, Weak};

static POOLS: Mutex<BTreeMap<usize, Weak<Pool>>> = Mutex::new(BTreeMap::new());

pub(in crate::database) struct PhysicalVfs {
    vfs: Box<ffi::sqlite3_vfs>,
    _name: CString,
    pub(in crate::database) pool: Arc<Pool>,
}

// Moving this owner preserves its boxed native table and CString allocation.
// The native callbacks are process-wide; the owning !Sync SQLite connection
// serializes use. Registry/allocation data are mutex protected. The private
// adapter name is never exposed as an independently owned connection API.
unsafe impl Send for PhysicalVfs {}

impl PhysicalVfs {
    fn new(
        directory: &DatabaseDirectory,
        limits: DatabasePhysicalIoLimits,
    ) -> Result<Self, DatabaseError> {
        let pool = Pool::new(directory, limits)?;
        let parent = register()?;
        let name = CString::new(format!("mutualbackup-physical-{}", uuid::Uuid::new_v4()))
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?;
        let mut vfs = Box::new(unsafe { *parent });
        vfs.pNext = ptr::null_mut();
        vfs.zName = name.as_ptr();
        vfs.xFullPathname = Some(crate::database::directory::full_path);
        vfs.xDelete = Some(delete);
        let address = &mut *vfs as *mut ffi::sqlite3_vfs;
        POOLS
            .lock()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?
            .insert(address as usize, Arc::downgrade(&pool));
        let code = unsafe { ffi::sqlite3_vfs_register(address, 0) };
        if code != ffi::SQLITE_OK {
            POOLS
                .lock()
                .map_err(|_| DatabaseError::PhysicalIoUnavailable)?
                .remove(&(address as usize));
            return Err(sql_error(code));
        }
        Ok(Self {
            vfs,
            _name: name,
            pool,
        })
    }
}
impl Drop for PhysicalVfs {
    fn drop(&mut self) {
        unsafe {
            ffi::sqlite3_vfs_unregister(&mut *self.vfs);
        }
        if let Ok(mut pools) = POOLS.lock() {
            pools.remove(&(&mut *self.vfs as *mut ffi::sqlite3_vfs as usize));
        }
    }
}

pub(super) fn pool(vfs: *mut ffi::sqlite3_vfs) -> Result<Option<Arc<Pool>>, DatabaseError> {
    Ok(POOLS
        .lock()
        .map_err(|_| DatabaseError::PhysicalIoUnavailable)?
        .get(&(vfs as usize))
        .and_then(Weak::upgrade))
}

pub(super) fn prepare(
    pool: Option<&Arc<Pool>>,
    name: ffi::sqlite3_filename,
    flags: c_int,
) -> Result<Option<IoFile>, DatabaseError> {
    let Some(pool) = pool else { return Ok(None) };
    if flags & (ffi::SQLITE_OPEN_MAIN_DB | ffi::SQLITE_OPEN_MAIN_JOURNAL | ffi::SQLITE_OPEN_WAL)
        != 0
    {
        return Ok(None);
    }
    if !name.is_null() && flags & ffi::SQLITE_OPEN_DELETEONCLOSE == 0 {
        return Err(DatabaseError::PhysicalIoUnavailable);
    }
    // Hand the anonymous descriptor directly to the native Unix adapter. Its
    // normal O_NOFOLLOW path open deliberately cannot reopen procfs FD links.
    Ok(Some(tempfile::tempfile_in(pool.directory.path())?))
}

pub(super) unsafe fn bind(
    pool: Option<&Arc<Pool>>,
    file: *mut ffi::sqlite3_file,
    flags: c_int,
) -> Result<Option<physical_io::Binding>, DatabaseError> {
    let Some(pool) = pool else { return Ok(None) };
    let role = if flags & ffi::SQLITE_OPEN_MAIN_DB != 0 {
        Role::Main
    } else if flags & (ffi::SQLITE_OPEN_MAIN_JOURNAL | ffi::SQLITE_OPEN_WAL) != 0 {
        Role::Journal
    } else {
        Role::Temporary
    };
    let fd = unsafe {
        crate::database::native_file::descriptor_for(
            file,
            ffi::MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD,
        )?
    }
    .ok_or(DatabaseError::PhysicalIoUnavailable)?;
    Ok(Some(unsafe { pool.bind(fd.as_raw_fd(), role)? }))
}

unsafe extern "C" fn delete(
    vfs: *mut ffi::sqlite3_vfs,
    name: *const std::ffi::c_char,
    sync: c_int,
) -> c_int {
    protect(|| unsafe {
        let parent = *PARENT.get().expect("registered VFS") as *mut ffi::sqlite3_vfs;
        let code = ((*parent).xDelete.expect("native delete"))(parent, name, sync);
        match pool(vfs) {
            Ok(Some(pool)) => {
                if let Err(error) = pool.refresh_deleted() {
                    return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_DELETE);
                }
            }
            Ok(None) => {}
            Err(_) => return ffi::SQLITE_IOERR_DELETE,
        }
        code
    })
}

pub(super) unsafe fn install_shm_init(file: &File) -> c_int {
    let mut init = ffi::MutualBackupShmInit {
        context: file.state.cast(),
        init: initialize_shm,
    };
    unsafe {
        ((*(*file.parent).pMethods)
            .xFileControl
            .expect("native control"))(
            file.parent,
            ffi::MUTUALBACKUP_SQLITE_FCNTL_SHM_INIT,
            (&mut init as *mut ffi::MutualBackupShmInit).cast(),
        )
    }
}

unsafe extern "C" fn initialize_shm(
    context: *mut c_void,
    descriptor: c_int,
    marker: *mut i64,
) -> c_int {
    protect(|| unsafe {
        let state = &mut *context.cast::<State>();
        let Some(main) = &state.physical else {
            return ffi::SQLITE_IOERR_SHMOPEN;
        };
        if state.shm.is_some() {
            return ffi::SQLITE_IOERR_SHMOPEN;
        }
        // Native SQLite has reset its stale index under the exclusive DMS
        // lock. No independent pathname open or external truncation occurs.
        let binding = match main.pool.bind(descriptor, Role::Shm) {
            Ok(binding) => binding,
            Err(error) => return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_SHMOPEN),
        };
        let result = binding
            .block_size()
            .and_then(|bytes| binding.fund(0, bytes).map(|()| bytes));
        state.shm = Some(binding);
        match result {
            Ok(bytes) => {
                *marker = bytes as i64;
                ffi::SQLITE_OK
            }
            Err(error) => physical_io::sqlite_code(error, ffi::SQLITE_IOERR_SHMOPEN),
        }
    })
}

/// Journals may be preextended by a VFS. Keep their initial short header in
/// a complete, admitted filesystem block so Btrfs retains its data extent.
/// The main database's EOF is never padded this way.
pub(super) unsafe fn prepare_header_write(
    file: &File,
    binding: &physical_io::Binding,
    end: u64,
) -> c_int {
    let minimum = match binding.block_size() {
        Ok(bytes) => bytes,
        Err(error) => return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_WRITE),
    };
    if end >= minimum {
        return ffi::SQLITE_OK;
    }
    let methods = unsafe { &*(*file.parent).pMethods };
    let mut old = 0i64;
    let code = unsafe { (methods.xFileSize.expect("native size"))(file.parent, &mut old) };
    if code != ffi::SQLITE_OK || old >= minimum as i64 {
        return code;
    }
    if let Err(error) = binding.fund(0, minimum) {
        return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_WRITE);
    }
    let code =
        unsafe { (methods.xTruncate.expect("native truncate"))(file.parent, minimum as i64) };
    if let Err(error) = binding.refresh_after_io() {
        return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_WRITE);
    }
    code
}

pub(super) unsafe fn shm_map(
    file: &File,
    page: c_int,
    bytes: c_int,
    extend: c_int,
    output: *mut *mut c_void,
) -> c_int {
    unsafe {
        *output = ptr::null_mut();
    }
    if page < 0 || bytes <= 0 {
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    let Some(binding) = (unsafe { &*file.state }).physical.as_ref() else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    let pool = Arc::clone(&binding.pool);
    let Some(end) = (page as u64)
        .checked_add(1)
        .and_then(|n| n.checked_mul(bytes as u64))
    else {
        return ffi::SQLITE_FULL;
    };
    let system_page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if system_page <= 0 {
        return ffi::SQLITE_IOERR_SHMMAP;
    }
    let alignment = (system_page as u64).max(bytes as u64);
    let Some(end) = end
        .checked_add(alignment - 1)
        .map(|n| n / alignment * alignment)
    else {
        return ffi::SQLITE_FULL;
    };
    if end > pool.limits.shm_bytes {
        return ffi::SQLITE_FULL;
    }
    let methods = unsafe { &*(*file.parent).pMethods };
    let Some(map) = methods.xShmMap else {
        return ffi::SQLITE_IOERR_SHMMAP;
    };
    // A non-extending native probe opens the normal SHM node and takes its
    // native locks. Its first-opener callback admits the reset index while
    // holding exclusive DMS. Do not retain a State borrow across that callback.
    let mut probe = ptr::null_mut();
    let code = unsafe { map(file.parent, page, bytes, 0, &mut probe) };
    if code != ffi::SQLITE_OK {
        if let Some(mut binding) = unsafe { &mut *file.state }.shm.take() {
            let _ = binding.close();
        }
        return code;
    }
    let state = unsafe { &mut *file.state };
    let descriptor = match unsafe {
        crate::database::native_file::descriptor_for(
            file.parent,
            ffi::MUTUALBACKUP_SQLITE_FCNTL_SHM_FD,
        )
    } {
        Ok(Some(fd)) => fd,
        _ => return ffi::SQLITE_IOERR_SHMMAP,
    };
    if state.shm.is_none() {
        match unsafe { pool.bind(descriptor.as_raw_fd(), Role::Shm) } {
            Ok(binding) => state.shm = Some(binding),
            Err(error) => return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_SHMMAP),
        }
    }
    let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor.as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return ffi::SQLITE_IOERR_SHMSIZE;
    }
    let old = unsafe { info.assume_init() }.st_size.max(0) as u64;
    let start = (page as u64 * bytes as u64) / alignment * alignment;
    let start = if end > old { start.min(old) } else { start };
    let binding = state.shm.as_ref().expect("bound SHM");
    if (extend != 0 || !probe.is_null())
        && let Err(error) = binding.fund(start, end)
    {
        return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_SHMSIZE);
    }
    let code = unsafe { map(file.parent, page, bytes, extend, output) };
    if let Err(error) = binding.refresh_after_io() {
        unsafe {
            *output = ptr::null_mut();
        }
        return physical_io::sqlite_code(error, ffi::SQLITE_IOERR_SHMSIZE);
    }
    code
}

impl ControlStore {
    /// Create an owned new SQL catalog with runtime physical I/O ceilings.
    /// The caller owns partial creation/restart and still owes persistent
    /// policy, old-writer enrollment and enclosing operation reservations.
    pub fn create_physical_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        key: &[u8; 32],
        limits: DatabasePhysicalIoLimits,
    ) -> Result<Self, DatabaseError> {
        let (vfs, path) = create(directory, name, limits)?;
        Self::connect_physical(directory, path, key, vfs)
    }

    /// Open a caller-owned existing catalog under explicit runtime ceilings.
    /// This does not perform old-writer enrollment or persistent policy
    /// migration. Nonempty Btrfs files must already have NoCow enabled.
    pub fn open_physical_existing_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        key: &[u8; 32],
        limits: DatabasePhysicalIoLimits,
    ) -> Result<Self, DatabaseError> {
        let (vfs, path) = existing(directory, name, limits)?;
        Self::connect_physical(directory, path, key, vfs)
    }

    fn connect_physical(
        directory: &DatabaseDirectory,
        path: std::path::PathBuf,
        key: &[u8; 32],
        vfs: PhysicalVfs,
    ) -> Result<Self, DatabaseError> {
        let mut connection = connect(&path, key, &vfs)?;
        crate::database::initialize_or_validate_control(&mut connection)?;
        Ok(Self {
            connection,
            physical_vfs: Some(vfs),
            path,
            directory: Some(directory.clone()),
        })
    }

    pub fn physical_io_allocated_bytes(&self) -> Result<Option<u64>, DatabaseError> {
        self.physical_vfs
            .as_ref()
            .map(|vfs| vfs.pool.usage())
            .transpose()
    }
}

fn create(
    directory: &DatabaseDirectory,
    name: &OsStr,
    limits: DatabasePhysicalIoLimits,
) -> Result<(PhysicalVfs, std::path::PathBuf), DatabaseError> {
    let path = directory.leaf(name)?;
    for suffix in ["-wal", "-shm", "-journal"] {
        let mut sibling = name.to_os_string();
        sibling.push(suffix);
        match std::fs::symlink_metadata(directory.leaf(sibling)?) {
            Ok(_) => return Err(DatabaseError::Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let vfs = PhysicalVfs::new(directory, limits)?;
    // This is a new empty inode, before any SQLite descriptor or lock can
    // exist. Never truncate a pre-existing catalog to enroll this mode.
    let created = OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(0o600)
        .open(&path)?;
    created.sync_all()?;
    directory.file().sync_all()?;
    vfs.pool.pin_created_main(&created)?;
    drop(created);
    Ok((vfs, path))
}
fn existing(
    directory: &DatabaseDirectory,
    name: &OsStr,
    limits: DatabasePhysicalIoLimits,
) -> Result<(PhysicalVfs, std::path::PathBuf), DatabaseError> {
    let path = directory.leaf(name)?;
    let vfs = PhysicalVfs::new(directory, limits)?;
    vfs.pool.pin_main_path(&path)?;
    Ok((vfs, path))
}
fn connect(
    path: &std::path::Path,
    key: &[u8; 32],
    vfs: &PhysicalVfs,
) -> Result<Connection, DatabaseError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | OpenFlags::SQLITE_OPEN_NOFOLLOW;
    let connection = Connection::open_with_flags_and_vfs(
        path,
        flags,
        vfs._name
            .to_str()
            .map_err(|_| DatabaseError::PhysicalIoUnavailable)?,
    )?;
    crate::database::configure_encrypted(connection, key)
}

impl ParityStore {
    /// Create a new caller-owned parity catalog with runtime native file
    /// admission. Durable volume policy, old writers and enclosing operations
    /// still require independent enrollment and reservations.
    pub fn create_physical_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        key: &[u8; 32],
        limits: DatabasePhysicalIoLimits,
    ) -> Result<Self, DatabaseError> {
        let (vfs, path) = create(directory, name, limits)?;
        Self::connect_physical(directory, path, volume, key, vfs)
    }

    /// Open an existing caller-owned parity catalog under runtime ceilings.
    /// This does not migrate persistent volume policy or enroll old writers.
    pub fn open_physical_existing_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        key: &[u8; 32],
        limits: DatabasePhysicalIoLimits,
    ) -> Result<Self, DatabaseError> {
        let (vfs, path) = existing(directory, name, limits)?;
        Self::connect_physical(directory, path, volume, key, vfs)
    }

    fn connect_physical(
        directory: &DatabaseDirectory,
        path: std::path::PathBuf,
        volume: &[u8; 16],
        key: &[u8; 32],
        vfs: PhysicalVfs,
    ) -> Result<Self, DatabaseError> {
        let mut connection = connect(&path, key, &vfs)?;
        crate::database::initialize_or_validate_parity(&mut connection, volume)?;
        Ok(Self {
            connection,
            physical_vfs: Some(vfs),
            path,
            directory: Some(directory.clone()),
        })
    }

    pub fn physical_io_allocated_bytes(&self) -> Result<Option<u64>, DatabaseError> {
        self.physical_vfs
            .as_ref()
            .map(|vfs| vfs.pool.usage())
            .transpose()
    }
}
