//! Read native main-file identity without opening or closing another database
//! descriptor. All private Unix-file layout knowledge stays in the pinned C
//! translation unit. No process-global syscall hook is installed.

use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};

use rusqlite::{Connection, ffi};

use super::DatabaseError;

impl super::ControlStore {
    /// Allocation domain of the actual admitted main file. Borrows SQLite's
    /// descriptor without opening/closing native files or changing its locks.
    pub fn physical_allocation_domain(&self) -> Result<[u8; 32], DatabaseError> {
        super::scratch_space::domain_for_descriptor(main_descriptor(&self.connection)?)
    }
}

impl super::ParityStore {
    /// Allocation domain of the actual admitted main file, retaining SQLite's
    /// original native descriptor and lock ownership throughout inspection.
    pub fn physical_allocation_domain(&self) -> Result<[u8; 32], DatabaseError> {
        super::scratch_space::domain_for_descriptor(main_descriptor(&self.connection)?)
    }
}

pub(super) struct MainFile {
    pub device: u64,
    pub inode: u64,
    pub links: u64,
    pub regular: bool,
    pub filesystem: u32,
}

pub(super) fn main_file(connection: &Connection) -> Result<MainFile, DatabaseError> {
    let descriptor = main_descriptor(connection)?;
    let mut info = MaybeUninit::<libc::stat>::uninit();
    let mut filesystem = MaybeUninit::<libc::statfs>::uninit();
    // The borrowed Connection keeps its native main file open. rusqlite does
    // not allow simultaneous safe use of this Connection on another thread.
    // Do not close/duplicate the descriptor, change its flags, or reenter
    // SQLite while inspecting it. These two calls only inspect that same file.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), info.as_mut_ptr()) } != 0
        || unsafe { libc::fstatfs(descriptor.as_raw_fd(), filesystem.as_mut_ptr()) } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let info = unsafe { info.assume_init() };
    let filesystem = unsafe { filesystem.assume_init() };
    #[allow(
        clippy::unnecessary_cast,
        reason = "Linux stat field widths vary by target ABI"
    )]
    let result = MainFile {
        device: info.st_dev as u64,
        inode: info.st_ino as u64,
        links: info.st_nlink as u64,
        regular: info.st_mode & libc::S_IFMT == libc::S_IFREG,
        filesystem: filesystem.f_type as u32,
    };
    Ok(result)
}

fn main_descriptor(connection: &Connection) -> Result<BorrowedFd<'_>, DatabaseError> {
    let mut descriptor: libc::c_int = -1;
    // This local opcode only borrows an existing open native description.
    // Its out-pointer remains valid for the entire synchronous call.
    let code = unsafe {
        ffi::sqlite3_file_control(
            connection.handle(),
            c"main".as_ptr(),
            ffi::MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD,
            (&mut descriptor as *mut libc::c_int).cast(),
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None).into());
    }
    if descriptor < 0 {
        return Err(DatabaseError::Integrity);
    }
    // The native main file remains owned by this borrowed connection. This
    // module performs only non-reentrant inspection before the borrow ends.
    Ok(unsafe { BorrowedFd::borrow_raw(descriptor) })
}

/// The caller retains the native sqlite3_file and, for SHM, its connection's
/// mapping for the entire borrow. It must not close/reenter SQLite during use.
pub(super) unsafe fn descriptor_for<'a>(
    file: *mut ffi::sqlite3_file,
    opcode: libc::c_int,
) -> Result<Option<BorrowedFd<'a>>, DatabaseError> {
    if file.is_null() || unsafe { (*file).pMethods.is_null() } {
        return Err(DatabaseError::Integrity);
    }
    let mut descriptor: libc::c_int = -1;
    let code = unsafe {
        ((*(*file).pMethods)
            .xFileControl
            .ok_or(DatabaseError::Integrity)?)(
            file,
            opcode,
            (&mut descriptor as *mut libc::c_int).cast(),
        )
    };
    if code == ffi::SQLITE_NOTFOUND {
        return Ok(None);
    }
    if code != ffi::SQLITE_OK {
        return Err(rusqlite::Error::SqliteFailure(ffi::Error::new(code), None).into());
    }
    if descriptor < 0 {
        return Err(DatabaseError::Integrity);
    }
    Ok(Some(unsafe { BorrowedFd::borrow_raw(descriptor) }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ControlStore;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn native_main_identity_uses_the_open_file_after_path_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let saved = temp.path().join("saved.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let original = std::fs::metadata(&path).unwrap();
        let before = main_file(&store.connection).unwrap();
        assert_eq!(
            (before.device, before.inode, before.links),
            (original.dev(), original.ino(), 1)
        );
        assert!(before.regular);
        let domain = store.physical_allocation_domain().unwrap();
        assert_eq!(
            domain,
            super::super::physical_allocation_domain(temp.path()).unwrap()
        );
        std::fs::rename(&path, &saved).unwrap();
        std::fs::write(&path, b"preserve this replacement").unwrap();
        let replacement = std::fs::metadata(&path).unwrap();
        assert_ne!(replacement.ino(), original.ino());
        let after = main_file(&store.connection).unwrap();
        assert_eq!(store.physical_allocation_domain().unwrap(), domain);
        assert_eq!(
            (after.device, after.inode, after.links, after.filesystem),
            (before.device, before.inode, before.links, before.filesystem)
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"preserve this replacement");
    }

    #[test]
    fn native_descriptor_inspection_preserves_an_independent_process_writer_exclusion() {
        const CHILD: &str = "MB_NATIVE_SQL_FILE_LOCK_CHILD";
        const CASE: &str = "database::native_file::tests::native_descriptor_inspection_preserves_an_independent_process_writer_exclusion";
        if let Some(path) = std::env::var_os(CHILD) {
            let connection = Connection::open(path).unwrap();
            connection
                .pragma_update(None, "key", hex::encode([7; 32]))
                .unwrap();
            connection
                .execute_batch("PRAGMA cipher_compatibility=4; PRAGMA cipher_page_size=4096;")
                .unwrap();
            connection
                .query_row("SELECT count(*) FROM sqlite_schema", [], |r| {
                    r.get::<_, u64>(0)
                })
                .unwrap();
            connection.busy_timeout(std::time::Duration::ZERO).unwrap();
            let result = connection.execute_batch("BEGIN IMMEDIATE");
            if std::env::var_os("MB_NATIVE_SQL_FILE_LOCK_RELEASED").is_some() {
                result.unwrap();
                connection.execute_batch("ROLLBACK").unwrap();
            } else {
                assert_eq!(
                    result.unwrap_err().sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
            }
            return;
        }
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let mode: String = store
            .connection
            .query_row("PRAGMA journal_mode=DELETE", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "delete");
        let tx = rusqlite::Transaction::new_unchecked(
            &store.connection,
            rusqlite::TransactionBehavior::Immediate,
        )
        .unwrap();
        let probe = |released: bool| {
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .args([CASE, "--exact", "--nocapture"])
                .env(CHILD, &path);
            if released {
                command.env("MB_NATIVE_SQL_FILE_LOCK_RELEASED", "1");
            }
            let result = command.output().unwrap();
            assert!(
                result.status.success(),
                "independent SQLCipher writer probe failed: {}\n{}",
                String::from_utf8_lossy(&result.stdout),
                String::from_utf8_lossy(&result.stderr)
            );
        };
        probe(false);
        let descriptor = main_descriptor(&store.connection).unwrap().as_raw_fd();
        for _ in 0..128 {
            assert_eq!(
                main_descriptor(&store.connection).unwrap().as_raw_fd(),
                descriptor
            );
            let actual = main_file(&store.connection).unwrap();
            assert_eq!(
                store.physical_allocation_domain().unwrap(),
                super::super::physical_allocation_domain(temp.path()).unwrap()
            );
            let named = std::fs::metadata(&path).unwrap();
            assert_eq!((actual.device, actual.inode), (named.dev(), named.ino()));
        }
        probe(false);
        tx.rollback().unwrap();
        probe(true);
        store
            .put_record("native-descriptor", b"after", b"preserved")
            .unwrap();
        assert_eq!(
            store.get_record("native-descriptor", b"after").unwrap(),
            Some(b"preserved".to_vec())
        );
    }

    #[test]
    fn native_file_control_borrows_live_wal_and_rejects_null_or_memory_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        store.put_record("native-wal", b"key", b"value").unwrap();
        let mut file = std::ptr::null_mut::<ffi::sqlite3_file>();
        let code = unsafe {
            ffi::sqlite3_file_control(
                store.connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_JOURNAL_POINTER,
                (&mut file as *mut *mut ffi::sqlite3_file).cast(),
            )
        };
        assert_eq!(code, ffi::SQLITE_OK);
        assert!(!file.is_null());
        let mut descriptor: libc::c_int = -1;
        let code = unsafe {
            ((*(*file).pMethods).xFileControl.unwrap())(
                file,
                ffi::MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD,
                (&mut descriptor as *mut libc::c_int).cast(),
            )
        };
        assert_eq!(code, ffi::SQLITE_OK);
        let mut info = MaybeUninit::<libc::stat>::uninit();
        assert_eq!(unsafe { libc::fstat(descriptor, info.as_mut_ptr()) }, 0);
        let info = unsafe { info.assume_init() };
        let named = std::fs::metadata(path.with_extension("db-wal")).unwrap();
        assert_eq!((info.st_dev, info.st_ino), (named.dev(), named.ino()));
        let code = unsafe {
            ffi::sqlite3_file_control(
                store.connection.handle(),
                c"main".as_ptr(),
                ffi::MUTUALBACKUP_SQLITE_FCNTL_NATIVE_FD,
                std::ptr::null_mut(),
            )
        };
        assert_eq!(code, ffi::SQLITE_MISUSE);
        let memory = Connection::open_in_memory().unwrap();
        assert!(main_file(&memory).is_err());
        assert_eq!(
            store.get_record("native-wal", b"key").unwrap(),
            Some(b"value".to_vec())
        );
    }
}
