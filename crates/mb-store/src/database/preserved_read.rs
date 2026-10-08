//! Strictly non-creating inspection of a preserved Linux control catalog.
//!
//! SQLite normally opens a WAL with CREATE even for a read-only main database.
//! This VFS forces read-only file opens and rejects deletion. Existing WALs use
//! SQLite's read-only shared-memory path. A journal-free catalog can be read as
//! immutable only while its identity/version and journal absence remain unchanged.

use std::{
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Path, PathBuf},
    sync::OnceLock,
};

use anyhow::{Context, Result, ensure};
use rusqlite::{Connection, OpenFlags, ffi};

use super::{
    ControlStore, DatabaseError, configure_encrypted_connection, meta_value,
    validate_control_schema,
};

const VFS_NAME: &std::ffi::CStr = c"mutualbackup-preserved-read";
static PARENT_VFS: OnceLock<usize> = OnceLock::new();
static REGISTERED_VFS: OnceLock<i32> = OnceLock::new();

unsafe extern "C" fn read_only_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: i32,
    out_flags: *mut i32,
) -> i32 {
    if name.is_null() {
        return ffi::SQLITE_READONLY;
    }
    let Some(parent) = PARENT_VFS.get() else {
        return ffi::SQLITE_IOERR;
    };
    let parent = *parent as *mut ffi::sqlite3_vfs;
    // SAFETY: the native Unix VFS is SQLite-owned and remains registered for the
    // process lifetime. Its callback receives SQLite's original file arguments.
    let Some(open) = (unsafe { (*parent).xOpen }) else {
        return ffi::SQLITE_IOERR;
    };
    let flags = (flags
        & !(ffi::SQLITE_OPEN_READWRITE
            | ffi::SQLITE_OPEN_CREATE
            | ffi::SQLITE_OPEN_DELETEONCLOSE
            | ffi::SQLITE_OPEN_EXCLUSIVE))
        | ffi::SQLITE_OPEN_READONLY;
    unsafe { open(parent, name, file, flags, out_flags) }
}

unsafe extern "C" fn reject_delete(
    _vfs: *mut ffi::sqlite3_vfs,
    _name: *const std::ffi::c_char,
    _sync_dir: i32,
) -> i32 {
    ffi::SQLITE_READONLY
}

fn register_vfs() -> Result<()> {
    let code = *REGISTERED_VFS.get_or_init(|| {
        // SAFETY: SQLite initialization and VFS registration are serialized by
        // this OnceLock; registration is not made the global default. The
        // copied immutable callback table lives until process exit.
        unsafe {
            let code = ffi::sqlite3_initialize();
            if code != ffi::SQLITE_OK {
                return code;
            }
            // Only the built-in Unix VFS has the base-table-only context this
            // copied adapter uses. An arbitrary default VFS can embed private
            // state beyond sqlite3_vfs and must not be copied this way.
            let parent = ffi::sqlite3_vfs_find(c"unix".as_ptr());
            if parent.is_null() {
                return ffi::SQLITE_NOTFOUND;
            }
            // A version-3 VFS guarantees the complete callback-table layout
            // copied below. Never read later fields from an older VFS object.
            if (*parent).iVersion < 3 {
                return ffi::SQLITE_NOTFOUND;
            }
            if PARENT_VFS.set(parent as usize).is_err() {
                return ffi::SQLITE_MISUSE;
            }
            let mut vfs = *parent;
            vfs.iVersion = 3;
            vfs.pNext = std::ptr::null_mut();
            vfs.zName = VFS_NAME.as_ptr();
            vfs.xOpen = Some(read_only_open);
            vfs.xDelete = Some(reject_delete);
            ffi::sqlite3_vfs_register(Box::into_raw(Box::new(vfs)), 0)
        }
    });
    ensure!(
        code == ffi::SQLITE_OK,
        "cannot register preserved-catalog read VFS: {code}"
    );
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
struct FileVersion {
    device: u64,
    inode: u64,
    len: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn version(path: &Path) -> Result<Option<FileVersion>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        metadata.is_file(),
        "preserved catalog or journal is not a regular file"
    );
    Ok(Some(FileVersion {
        device: metadata.dev(),
        inode: metadata.ino(),
        len: metadata.len(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }))
}

fn journal_paths(path: &Path) -> [PathBuf; 3] {
    ["-wal", "-shm", "-journal"].map(|suffix| {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        name.into()
    })
}

fn uri(path: &Path, immutable: bool) -> Result<String> {
    let path = std::path::absolute(path)?;
    let mut uri = String::from("file:");
    for byte in path.as_os_str().as_bytes() {
        ensure!(*byte != 0, "preserved catalog path contains NUL");
        if byte.is_ascii_alphanumeric() || b"/._-".contains(byte) {
            uri.push(char::from(*byte));
        } else {
            use std::fmt::Write;
            write!(uri, "%{byte:02X}")?;
        }
    }
    uri.push_str("?mode=ro&readonly_shm=1");
    if immutable {
        uri.push_str("&immutable=1");
    }
    Ok(uri)
}

pub(super) fn inspect<T>(
    path: &Path,
    database_keys: &[[u8; 32]],
    operation: impl FnOnce(&ControlStore) -> Result<T>,
) -> Result<T> {
    register_vfs()?;
    let before = version(path)?.context("preserved control catalog is unavailable")?;
    ensure!(before.len != 0, "preserved control catalog is empty");
    let journals = journal_paths(path);
    let journal_versions: Vec<_> = journals
        .iter()
        .map(|path| version(path))
        .collect::<Result<_>>()?;
    let immutable = journal_versions.iter().all(Option::is_none);
    ensure!(
        immutable
            || (journal_versions[0].is_some()
                && journal_versions[1].is_some()
                && journal_versions[2].is_none()),
        "preserved catalog has incomplete or rollback journal state; preserve every database/journal file and inspect a separate complete snapshot; see docs/guarded-withdrawal.md"
    );
    let uri = uri(path, immutable)?;
    let mut opened = None;
    let mut last_error = None;
    for key in database_keys {
        let attempt = (|| -> Result<ControlStore> {
            let connection = Connection::open_with_flags_and_vfs(
                &uri,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
                VFS_NAME.to_str()?,
            )?;
            let connection = configure_encrypted_connection(connection, key, true)?;
            if meta_value(&connection, "database_kind")?.as_deref() != Some(b"control") {
                return Err(DatabaseError::IncompatibleSchema.into());
            }
            let schema = meta_value(&connection, "schema_version")?
                .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                .map(u32::from_be_bytes)
                .context("preserved catalog schema is unavailable")?;
            validate_control_schema(&connection, schema)?;
            Ok(ControlStore {
                connection,
                path: path.to_path_buf(),
            })
        })();
        match attempt {
            Ok(control) => {
                opened = Some(control);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let control = match opened {
        Some(control) => control,
        None => {
            return Err(last_error
                .unwrap_or_else(|| anyhow::anyhow!("no database key supplied"))
                .context("preserved control catalog rejected available database keys"));
        }
    };
    let result = control.with_read_only_snapshot(|| operation(&control));
    if immutable {
        ensure!(
            version(path)?.as_ref() == Some(&before)
                && journals
                    .iter()
                    .all(|path| matches!(version(path), Ok(None))),
            "preserved catalog changed during immutable inspection; stop its writer and retry"
        );
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    #[test]
    fn closed_preserved_snapshot_escapes_raw_uri_names_and_creates_no_journals() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp
            .path()
            .join(OsString::from_vec(b"catalog-?mode=rw#%\xff.db".to_vec()));
        let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        writer.put_record("root", b"id", b"preserved").unwrap();
        drop(writer);
        let before = fs::read(&path).unwrap();
        let keys = [[8; 32], [7; 32]];
        inspect(&path, &keys, |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"preserved");
            assert!(reader.put_record("root", b"id", b"changed").is_err());
            assert!(reader.delete_record("root", b"id").is_err());
            Ok(())
        })
        .unwrap();
        assert!(inspect(&path, &[[8; 32]], |_| Ok(())).is_err());
        assert!(fs::read(&path).unwrap() == before);
        assert!(journal_paths(&path).iter().all(|path| !path.exists()));
    }

    #[test]
    fn preserved_live_wal_snapshot_retains_concurrent_writer_visibility_rules() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        writer
            .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
            .unwrap();
        writer.put_record("root", b"id", b"old").unwrap();
        let paths = [path.clone(), journal_paths(&path)[0].clone()];
        let before: Vec<_> = paths.iter().map(|path| fs::read(path).unwrap()).collect();
        inspect(&path, &[[7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"old");
            Ok(())
        })
        .unwrap();
        for (path, bytes) in paths.iter().zip(before) {
            assert!(
                fs::read(path).unwrap() == bytes,
                "{} changed",
                path.display()
            );
        }
        inspect(&path, &[[7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"old");
            writer.put_record("root", b"id", b"new")?;
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"old");
            Ok(())
        })
        .unwrap();
        inspect(&path, &[[7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"new");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn immutable_inspection_rejects_a_changed_catalog_and_incomplete_journals_without_creation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        writer.put_record("root", b"id", b"old").unwrap();
        drop(writer);
        let result = inspect(&path, &[[7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"old");
            let writer = ControlStore::open_with_key(&path, &[7; 32])?;
            writer.put_record("root", b"id", b"new")?;
            drop(writer);
            Ok("must not return this report")
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("changed during immutable inspection")
        );
        let wal = journal_paths(&path)[0].clone();
        fs::write(&wal, b"preserve incomplete journal").unwrap();
        let before = fs::read(&path).unwrap();
        assert!(
            inspect(&path, &[[7; 32]], |_| Ok(()))
                .unwrap_err()
                .to_string()
                .contains("incomplete or rollback journal")
        );
        assert!(fs::read(&path).unwrap() == before);
        assert_eq!(fs::read(&wal).unwrap(), b"preserve incomplete journal");
        assert!(!journal_paths(&path)[1].exists());
    }
}
