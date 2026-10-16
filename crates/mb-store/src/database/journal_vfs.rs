//! Native file I/O with an explicitly admitted journal byte ceiling. The main
//! file and its WAL/rollback journal share one connection-local limit. SQLite's
//! public filename/file-control interfaces preserve native inode/lock/SHM I/O.

use std::ffi::{CStr, c_int, c_void};
use std::ptr;
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicU64, Ordering},
};

use super::DatabaseError;
use rusqlite::{Connection, OpenFlags, ffi};
#[cfg(target_os = "linux")]
mod physical;
#[cfg(target_os = "linux")]
pub(super) use physical::PhysicalVfs;

pub(super) const NAME: &CStr = c"mutualbackup-journal-quota";
const SET_LIMIT: c_int = 1042;
static PARENT: OnceLock<usize> = OnceLock::new();
static REGISTERED: OnceLock<i32> = OnceLock::new();

#[repr(C)]
struct File {
    base: ffi::sqlite3_file,
    parent: *mut ffi::sqlite3_file,
    state: *mut State,
    // Keep the native file's original allocation alignment after this prefix.
    _padding: [usize; 5],
}

struct State {
    journal: bool,
    limit: Arc<AtomicU64>,
    #[cfg(target_os = "linux")]
    physical: Option<super::physical_io::Binding>,
    #[cfg(target_os = "linux")]
    shm: Option<super::physical_io::Binding>,
}

#[repr(C)]
struct Change {
    next: u64,
    previous: u64,
}

fn protect(f: impl FnOnce() -> i32) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).unwrap_or(ffi::SQLITE_IOERR)
}

pub(super) fn register() -> Result<*mut ffi::sqlite3_vfs, DatabaseError> {
    let code = *REGISTERED.get_or_init(|| unsafe {
        // Built-in native tables have the base-table application context needed
        // by this copied adapter. The table is immutable and never unregistered.
        let code = ffi::sqlite3_initialize();
        if code != ffi::SQLITE_OK {
            return code;
        }
        #[cfg(windows)]
        let native = c"win32";
        #[cfg(not(windows))]
        let native = c"unix";
        let parent = ffi::sqlite3_vfs_find(native.as_ptr());
        if parent.is_null() || (*parent).iVersion < 3 {
            return ffi::SQLITE_NOTFOUND;
        }
        if PARENT.set(parent as usize).is_err() {
            return ffi::SQLITE_MISUSE;
        }
        let Some(bytes) = (*parent)
            .szOsFile
            .checked_add(std::mem::size_of::<File>() as c_int)
        else {
            return ffi::SQLITE_NOMEM;
        };
        let mut vfs = *parent;
        vfs.pNext = ptr::null_mut();
        vfs.zName = NAME.as_ptr();
        vfs.szOsFile = bytes;
        vfs.xOpen = Some(open);
        ffi::sqlite3_vfs_register(Box::into_raw(Box::new(vfs)), 0)
    });
    if code != ffi::SQLITE_OK {
        return Err(sql_error(code));
    }
    // The OnceLock has registered a process-lifetime immutable table.
    Ok(unsafe { ffi::sqlite3_vfs_find(NAME.as_ptr()) })
}

fn sql_error(code: i32) -> DatabaseError {
    rusqlite::Error::SqliteFailure(ffi::Error::new(code), None).into()
}

pub(super) fn connect(
    path: &std::path::Path,
    flags: OpenFlags,
) -> Result<Connection, DatabaseError> {
    register()?;
    Ok(Connection::open_with_flags_and_vfs(
        path,
        flags,
        NAME.to_str().expect("ASCII VFS name"),
    )?)
}

pub(super) fn set_limit(connection: &Connection, next: u64) -> Result<u64, DatabaseError> {
    let mut change = Change { next, previous: 0 };
    // The application opcode belongs only to this adapter. The live connection
    // owns its main file; Change is valid throughout this synchronous call.
    let code = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            SET_LIMIT,
            (&mut change as *mut Change).cast(),
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(sql_error(code));
    }
    Ok(change.previous)
}

pub(super) fn current_limit(connection: &Connection) -> Result<u64, DatabaseError> {
    let mut file: *mut ffi::sqlite3_file = ptr::null_mut();
    let code = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_FILE_POINTER,
            (&mut file as *mut *mut ffi::sqlite3_file).cast(),
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(sql_error(code));
    }
    if file.is_null() || unsafe { !ptr::eq((*file).pMethods, &METHODS) } {
        return Err(DatabaseError::IncompatibleSchema);
    }
    Ok(unsafe {
        (*(*file.cast::<File>()).state)
            .limit
            .load(Ordering::Acquire)
    })
}

pub(super) fn journal_bytes(connection: &Connection) -> Result<u64, DatabaseError> {
    let mut file: *mut ffi::sqlite3_file = ptr::null_mut();
    // SQLite returns its own live journal file, including a WAL inherited from
    // an earlier connection. No pathname or private native-file ABI is used.
    let code = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::SQLITE_FCNTL_JOURNAL_POINTER,
            (&mut file as *mut *mut ffi::sqlite3_file).cast(),
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(sql_error(code));
    }
    // SQLite may return its allocated but unopened rollback-journal object.
    // pMethods is null until xOpen succeeds and again after the file is closed.
    if file.is_null() || unsafe { (*file).pMethods.is_null() } {
        return Ok(0);
    }
    let mut bytes = 0;
    let code = unsafe {
        (*(*file).pMethods)
            .xFileSize
            .ok_or(DatabaseError::Integrity)?(file, &mut bytes)
    };
    if code != ffi::SQLITE_OK {
        return Err(sql_error(code));
    }
    u64::try_from(bytes).map_err(|_| DatabaseError::Integrity)
}

unsafe extern "C" fn open(
    vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    output: *mut ffi::sqlite3_file,
    flags: c_int,
    out_flags: *mut c_int,
) -> c_int {
    protect(|| unsafe {
        // SQLite supplies szOsFile bytes. The prefix and native allocation do
        // not overlap; callbacks receive the untouched native filename pointer.
        (*output).pMethods = ptr::null();
        #[cfg(target_os = "linux")]
        let pool = match physical::pool(vfs) {
            Ok(pool) => pool,
            Err(_) => return ffi::SQLITE_CANTOPEN,
        };
        let parent = *PARENT.get().expect("registered VFS") as *mut ffi::sqlite3_vfs;
        let inner = output
            .cast::<u8>()
            .add(std::mem::size_of::<File>())
            .cast::<ffi::sqlite3_file>();
        let journal = flags & (ffi::SQLITE_OPEN_WAL | ffi::SQLITE_OPEN_MAIN_JOURNAL) != 0;
        let limit = if journal {
            if name.is_null() {
                return ffi::SQLITE_CANTOPEN;
            }
            // This API is defined only for SQLite's original journal xOpen
            // filename with these flags. It returns our live main-file wrapper.
            let main = ffi::sqlite3_database_file_object(name);
            if main.is_null() || !ptr::eq((*main).pMethods, &METHODS) {
                return ffi::SQLITE_CANTOPEN;
            }
            Arc::clone(&(*(*main.cast::<File>()).state).limit)
        } else {
            Arc::new(AtomicU64::new(u64::MAX))
        };
        #[cfg(target_os = "linux")]
        let prepared = match physical::prepare(pool.as_ref(), name, flags) {
            Ok(value) => value,
            Err(error) => return super::physical_io::sqlite_code(error, ffi::SQLITE_CANTOPEN),
        };
        #[cfg(target_os = "linux")]
        let code = if let Some(temporary) = prepared {
            use std::os::fd::{FromRawFd, IntoRawFd};
            let mut descriptor = temporary.into_raw_fd();
            let code = ffi::sqlite3_mutualbackup_open_temp_fd(parent, inner, &mut descriptor);
            if descriptor >= 0 {
                // Rejected before transfer: this is our newly created anonymous
                // temporary inode, never another main-file description.
                drop(std::fs::File::from_raw_fd(descriptor));
            }
            if !out_flags.is_null() {
                *out_flags = flags;
            }
            code
        } else {
            (*parent).xOpen.expect("native xOpen")(parent, name, inner, flags, out_flags)
        };
        #[cfg(not(target_os = "linux"))]
        let code = (*parent).xOpen.expect("native xOpen")(parent, name, inner, flags, out_flags);
        if code != ffi::SQLITE_OK {
            if !(*inner).pMethods.is_null() {
                ((*(*inner).pMethods).xClose.expect("native xClose"))(inner);
            }
            return code;
        }
        #[cfg(target_os = "linux")]
        let binding = match physical::bind(pool.as_ref(), inner, flags) {
            Ok(value) => value,
            Err(error) => {
                ((*(*inner).pMethods).xClose.expect("native xClose"))(inner);
                return super::physical_io::sqlite_code(error, ffi::SQLITE_CANTOPEN);
            }
        };
        ptr::write(
            output.cast::<File>(),
            File {
                base: ffi::sqlite3_file { pMethods: &METHODS },
                parent: inner,
                state: Box::into_raw(Box::new(State {
                    journal,
                    limit,
                    #[cfg(target_os = "linux")]
                    physical: binding,
                    #[cfg(target_os = "linux")]
                    shm: None,
                })),
                _padding: [0; 5],
            },
        );
        if (journal
            && (*(*output.cast::<File>()).state)
                .limit
                .load(Ordering::Acquire)
                != u64::MAX)
            || physical_active(output)
        {
            let mut zero: c_int = 0;
            // Disable existing native rounding as well as later chunk requests.
            ((*(*inner).pMethods)
                .xFileControl
                .expect("native xFileControl"))(
                inner,
                ffi::SQLITE_FCNTL_CHUNK_SIZE,
                (&mut zero as *mut c_int).cast(),
            );
        }
        ffi::SQLITE_OK
    })
}

unsafe extern "C" fn close(file: *mut ffi::sqlite3_file) -> c_int {
    protect(|| unsafe {
        let file = &mut *file.cast::<File>();
        let code = ((*(*file.parent).pMethods).xClose.expect("native xClose"))(file.parent);
        #[cfg(target_os = "linux")]
        {
            let state = &mut *file.state;
            if let Some(binding) = &mut state.shm {
                let _ = binding.close();
            }
            if let Some(binding) = &mut state.physical {
                let _ = binding.close();
            }
        }
        drop(Box::from_raw(file.state));
        file.base.pMethods = ptr::null();
        code
    })
}

unsafe fn physical_active(file: *mut ffi::sqlite3_file) -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { (*(*file.cast::<File>()).state).physical.is_some() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        false
    }
}

unsafe extern "C" fn shm_map(
    file: *mut ffi::sqlite3_file,
    page: c_int,
    bytes: c_int,
    extend: c_int,
    output: *mut *mut c_void,
) -> c_int {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        if (*(*file.parent).pMethods).iVersion < 2 {
            return ffi::SQLITE_IOERR_SHMMAP;
        }
        #[cfg(target_os = "linux")]
        if (*file.state).physical.is_some() {
            return physical::shm_map(file, page, bytes, extend, output);
        }
        match (*(*file.parent).pMethods).xShmMap {
            Some(map) => map(file.parent, page, bytes, extend, output),
            None => ffi::SQLITE_IOERR_SHMMAP,
        }
    })
}

unsafe extern "C" fn shm_unmap(file: *mut ffi::sqlite3_file, delete: c_int) -> c_int {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        if (*(*file.parent).pMethods).iVersion < 2 {
            return ffi::SQLITE_OK;
        }
        let code = match (*(*file.parent).pMethods).xShmUnmap {
            Some(unmap) => unmap(file.parent, delete),
            None => ffi::SQLITE_OK,
        };
        #[cfg(target_os = "linux")]
        if let Some(mut binding) = (*file.state).shm.take()
            && let Err(error) = binding.close()
        {
            return super::physical_io::sqlite_code(error, ffi::SQLITE_IOERR_SHMMAP);
        }
        code
    })
}

unsafe extern "C" fn write(
    file: *mut ffi::sqlite3_file,
    bytes: *const c_void,
    amount: c_int,
    offset: i64,
) -> c_int {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        let state = &*file.state;
        let Some(end) = u64::try_from(offset)
            .ok()
            .zip(u64::try_from(amount).ok())
            .and_then(|(o, n)| o.checked_add(n))
        else {
            return ffi::SQLITE_IOERR_WRITE;
        };
        if state.journal && end > state.limit.load(Ordering::Acquire) {
            return ffi::SQLITE_FULL;
        }
        #[cfg(target_os = "linux")]
        if let Some(binding) = &state.physical
            && let Err(error) = binding.fund(offset as u64, end)
        {
            return super::physical_io::sqlite_code(error, ffi::SQLITE_IOERR_WRITE);
        }
        if state.journal && state.limit.load(Ordering::Acquire) != u64::MAX {
            let mut zero: c_int = 0;
            let code = ((*(*file.parent).pMethods)
                .xFileControl
                .expect("native xFileControl"))(
                file.parent,
                ffi::SQLITE_FCNTL_CHUNK_SIZE,
                (&mut zero as *mut c_int).cast(),
            );
            if !matches!(code, ffi::SQLITE_OK | ffi::SQLITE_NOTFOUND) {
                return code;
            }
        }
        let code = ((*(*file.parent).pMethods).xWrite.expect("native xWrite"))(
            file.parent,
            bytes,
            amount,
            offset,
        );
        #[cfg(target_os = "linux")]
        if let Some(binding) = &state.physical
            && let Err(error) = binding.refresh_after_io()
        {
            return super::physical_io::sqlite_code(error, ffi::SQLITE_IOERR_WRITE);
        }
        code
    })
}

unsafe extern "C" fn truncate(file: *mut ffi::sqlite3_file, bytes: i64) -> c_int {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        let Ok(bytes_u64) = u64::try_from(bytes) else {
            return ffi::SQLITE_IOERR_TRUNCATE;
        };
        if (*file.state).journal && bytes_u64 > (*file.state).limit.load(Ordering::Acquire) {
            return ffi::SQLITE_FULL;
        }
        #[cfg(target_os = "linux")]
        if let Some(binding) = &(*file.state).physical {
            let mut previous = 0i64;
            let code = ((*(*file.parent).pMethods).xFileSize.expect("native size"))(
                file.parent,
                &mut previous,
            );
            if code != ffi::SQLITE_OK {
                return code;
            }
            if bytes > previous
                && let Err(error) = binding.fund(previous.max(0) as u64, bytes_u64)
            {
                return super::physical_io::sqlite_code(error, ffi::SQLITE_IOERR_TRUNCATE);
            }
        }
        if (*file.state).journal && (*file.state).limit.load(Ordering::Acquire) != u64::MAX {
            let mut zero: c_int = 0;
            let code = ((*(*file.parent).pMethods)
                .xFileControl
                .expect("native xFileControl"))(
                file.parent,
                ffi::SQLITE_FCNTL_CHUNK_SIZE,
                (&mut zero as *mut c_int).cast(),
            );
            if !matches!(code, ffi::SQLITE_OK | ffi::SQLITE_NOTFOUND) {
                return code;
            }
        }
        let code = ((*(*file.parent).pMethods)
            .xTruncate
            .expect("native xTruncate"))(file.parent, bytes);
        #[cfg(target_os = "linux")]
        if let Some(binding) = &(*file.state).physical
            && let Err(error) = binding.refresh_after_io()
        {
            return super::physical_io::sqlite_code(error, ffi::SQLITE_IOERR_TRUNCATE);
        }
        code
    })
}

unsafe extern "C" fn control(
    file: *mut ffi::sqlite3_file,
    op: c_int,
    argument: *mut c_void,
) -> c_int {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        let state = &*file.state;
        if op == SET_LIMIT {
            if state.journal || argument.is_null() {
                return ffi::SQLITE_MISUSE;
            }
            let change = &mut *argument.cast::<Change>();
            change.previous = state.limit.swap(change.next, Ordering::AcqRel);
            return ffi::SQLITE_OK;
        }
        if (state.journal && state.limit.load(Ordering::Acquire) != u64::MAX)
            || physical_active(file as *const File as *mut ffi::sqlite3_file)
        {
            // Hints are optional; a rounded preallocation must not exceed the
            // actual admitted writes. Native I/O continues without preallocation.
            if op == ffi::SQLITE_FCNTL_SIZE_HINT {
                return ffi::SQLITE_OK;
            }
            if op == ffi::SQLITE_FCNTL_CHUNK_SIZE {
                let mut zero: c_int = 0;
                return ((*(*file.parent).pMethods)
                    .xFileControl
                    .expect("native xFileControl"))(
                    file.parent,
                    op,
                    (&mut zero as *mut c_int).cast(),
                );
            }
        }
        ((*(*file.parent).pMethods)
            .xFileControl
            .expect("native xFileControl"))(file.parent, op, argument)
    })
}

macro_rules! forward {
    ($name:ident, $method:ident, ($($arg:ident: $type:ty),*), $fallback:expr) => {
        forward!($name, $method, ($($arg: $type),*), $fallback, 1);
    };
    ($name:ident, $method:ident, ($($arg:ident: $type:ty),*), $fallback:expr, $version:expr) => {
        unsafe extern "C" fn $name(file: *mut ffi::sqlite3_file, $($arg:$type),*) -> c_int {
            protect(|| unsafe {
                let file = &*file.cast::<File>();
                if (*(*file.parent).pMethods).iVersion < $version { return $fallback; }
                match (*(*file.parent).pMethods).$method {
                    Some(method) => method(file.parent, $($arg),*), None => $fallback,
                }
            })
        }
    };
}
forward!(read, xRead, (output: *mut c_void, amount: c_int, offset: i64), ffi::SQLITE_IOERR_READ);
forward!(sync, xSync, (flags: c_int), ffi::SQLITE_IOERR_FSYNC);
forward!(size, xFileSize, (bytes: *mut i64), ffi::SQLITE_IOERR_FSTAT);
forward!(lock, xLock, (mode: c_int), ffi::SQLITE_IOERR_LOCK);
forward!(unlock, xUnlock, (mode: c_int), ffi::SQLITE_IOERR_UNLOCK);
forward!(reserved, xCheckReservedLock, (output: *mut c_int), ffi::SQLITE_IOERR_CHECKRESERVEDLOCK);
forward!(sector_size, xSectorSize, (), 4096);
forward!(characteristics, xDeviceCharacteristics, (), 0);
forward!(shm_lock, xShmLock, (offset: c_int, count: c_int, flags: c_int), ffi::SQLITE_IOERR_SHMLOCK, 2);
forward!(unfetch, xUnfetch, (offset: i64, input: *mut c_void), ffi::SQLITE_OK, 3);

unsafe extern "C" fn shm_barrier(file: *mut ffi::sqlite3_file) {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        if (*(*file.parent).pMethods).iVersion >= 2
            && let Some(method) = (*(*file.parent).pMethods).xShmBarrier
        {
            method(file.parent);
        }
        ffi::SQLITE_OK
    });
}

unsafe extern "C" fn fetch(
    file: *mut ffi::sqlite3_file,
    offset: i64,
    amount: c_int,
    output: *mut *mut c_void,
) -> c_int {
    protect(|| unsafe {
        let file = &*file.cast::<File>();
        if (*(*file.parent).pMethods).iVersion >= 3
            && let Some(method) = (*(*file.parent).pMethods).xFetch
        {
            method(file.parent, offset, amount, output)
        } else {
            *output = ptr::null_mut();
            ffi::SQLITE_OK
        }
    })
}

static METHODS: ffi::sqlite3_io_methods = ffi::sqlite3_io_methods {
    iVersion: 3,
    xClose: Some(close),
    xRead: Some(read),
    xWrite: Some(write),
    xTruncate: Some(truncate),
    xSync: Some(sync),
    xFileSize: Some(size),
    xLock: Some(lock),
    xUnlock: Some(unlock),
    xCheckReservedLock: Some(reserved),
    xFileControl: Some(control),
    xSectorSize: Some(sector_size),
    xDeviceCharacteristics: Some(characteristics),
    xShmMap: Some(shm_map),
    xShmLock: Some(shm_lock),
    xShmBarrier: Some(shm_barrier),
    xShmUnmap: Some(shm_unmap),
    xFetch: Some(fetch),
    xUnfetch: Some(unfetch),
};
