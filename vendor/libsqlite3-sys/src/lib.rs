#![expect(non_snake_case, non_camel_case_types)]

// force linking to openssl
#[cfg(feature = "bundled-sqlcipher-vendored-openssl")]
extern crate openssl_sys;

pub use self::error::*;

/// Local bundled Linux Unix-VFS extension. The argument is an `int *`.
/// Returns the existing descriptor borrowed until that sqlite3_file is closed;
/// callers must never close it or alter native locking/file-status flags.
/// Other VFSes and non-Linux targets return SQLITE_NOTFOUND.
pub const MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD: std::ffi::c_int = 1043;
/// Borrow an already open Unix SHM descriptor. The caller must retain its
/// mapped main-file connection; this opcode neither opens nor grows SHM.
pub const MUTUALBACKUP_SQLITE_FCNTL_SHM_FD: std::ffi::c_int = 1044;
/// Before a WAL commit, fund the exact future main size (`sqlite3_int64 *`).
/// Native physical VFS admission is mandatory; unsupported VFSes return
/// SQLITE_NOTFOUND and retain their original behavior.
pub const MUTUALBACKUP_SQLITE_FCNTL_WAL_COMMIT_SIZE: std::ffi::c_int = 1046;

use std::mem;

mod error;

#[must_use]
pub fn SQLITE_STATIC() -> sqlite3_destructor_type {
    None
}

#[must_use]
pub fn SQLITE_TRANSIENT() -> sqlite3_destructor_type {
    Some(unsafe { mem::transmute::<isize, unsafe extern "C" fn(*mut std::ffi::c_void)>(-1_isize) })
}

#[allow(dead_code, clippy::all)]
mod bindings {
    include!(concat!(env!("OUT_DIR"), "/bindgen.rs"));
}
pub use bindings::*;

impl Default for sqlite3_vtab {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

impl Default for sqlite3_vtab_cursor {
    fn default() -> Self {
        unsafe { mem::zeroed() }
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    /// Adopt an anonymous regular temporary descriptor using the bundled Unix
    /// VFS. On acceptance `*descriptor` becomes -1 and native xClose owns it,
    /// including initialization-error cleanup. Rejection leaves it unchanged.
    pub fn sqlite3_mutualbackup_open_temp_fd(
        vfs: *mut sqlite3_vfs,
        file: *mut sqlite3_file,
        descriptor: *mut std::ffi::c_int,
    ) -> std::ffi::c_int;
}

/// Bundled Linux native SHM admission callback, invoked under exclusive DMS.
#[cfg(target_os = "linux")]
#[repr(C)]
pub struct MutualBackupShmInit {
    pub context: *mut std::ffi::c_void,
    pub init: unsafe extern "C" fn(*mut std::ffi::c_void, std::ffi::c_int, *mut i64) -> std::ffi::c_int,
}
#[cfg(target_os = "linux")]
pub const MUTUALBACKUP_SQLITE_FCNTL_SHM_INIT: std::ffi::c_int = MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD + 2;
