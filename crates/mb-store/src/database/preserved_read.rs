//! Strictly non-creating inspection of a preserved Linux control catalog.
//!
//! SQLite normally opens a WAL with CREATE even for a read-only main database.
//! This VFS forces read-only file opens and rejects deletion. Existing WALs use
//! SQLite's read-only shared-memory path. A journal-free catalog can be read as
//! immutable only while its identity/version and journal absence remain unchanged.
//! A WAL without shared memory uses SQLite's private heap index, with the same
//! version guard on both input files instead of shared writer locks.

use std::{
    fs,
    io::Read,
    os::unix::{ffi::OsStrExt, fs::MetadataExt, fs::OpenOptionsExt},
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
const PRIVATE_WAL_VFS_NAME: &std::ffi::CStr = c"mutualbackup-preserved-private-wal";
static PARENT_VFS: OnceLock<usize> = OnceLock::new();
static PRIVATE_WAL_PARENT_VFS: OnceLock<usize> = OnceLock::new();
static REGISTERED_VFS: OnceLock<i32> = OnceLock::new();

unsafe extern "C" fn preserved_full_path(
    vfs: *mut ffi::sqlite3_vfs,
    input: *const std::ffi::c_char,
    capacity: i32,
    output: *mut std::ffi::c_char,
) -> i32 {
    if input.is_null() {
        return ffi::SQLITE_CANTOPEN;
    }
    // Keep a held directory's capability through SQLite's main/WAL opens.
    // The ordinary Unix callback resolves procfs back to a replaceable path.
    if unsafe { std::ffi::CStr::from_ptr(input) }
        .to_bytes()
        .starts_with(b"/proc/self/fd/")
    {
        return unsafe { super::directory::full_path(vfs, input, capacity, output) };
    }
    let Some(parent) = PARENT_VFS.get() else {
        return ffi::SQLITE_CANTOPEN;
    };
    let parent = *parent as *mut ffi::sqlite3_vfs;
    match unsafe { (*parent).xFullPathname } {
        Some(callback) => unsafe { callback(parent, input, capacity, output) },
        None => ffi::SQLITE_CANTOPEN,
    }
}

unsafe extern "C" fn read_only_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: i32,
    out_flags: *mut i32,
) -> i32 {
    unsafe { open_read_only(PARENT_VFS.get(), name, file, flags, out_flags) }
}

unsafe extern "C" fn private_wal_read_only_open(
    _vfs: *mut ffi::sqlite3_vfs,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: i32,
    out_flags: *mut i32,
) -> i32 {
    unsafe { open_read_only(PRIVATE_WAL_PARENT_VFS.get(), name, file, flags, out_flags) }
}

unsafe fn open_read_only(
    parent: Option<&usize>,
    name: ffi::sqlite3_filename,
    file: *mut ffi::sqlite3_file,
    flags: i32,
    out_flags: *mut i32,
) -> i32 {
    if name.is_null() {
        return ffi::SQLITE_READONLY;
    }
    let Some(parent) = parent else {
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
            // Only built-in Unix VFS tables have the base-table-only context
            // these copied adapters use. Arbitrary VFS implementations may
            // embed private state beyond sqlite3_vfs.
            for (parent_name, name, slot, open) in [
                (
                    c"unix",
                    VFS_NAME,
                    &PARENT_VFS,
                    read_only_open as unsafe extern "C" fn(_, _, _, _, _) -> _,
                ),
                (
                    c"unix-none",
                    PRIVATE_WAL_VFS_NAME,
                    &PRIVATE_WAL_PARENT_VFS,
                    private_wal_read_only_open as unsafe extern "C" fn(_, _, _, _, _) -> _,
                ),
            ] {
                let parent = ffi::sqlite3_vfs_find(parent_name.as_ptr());
                // Never read later fields from an older VFS object.
                if parent.is_null() || (*parent).iVersion < 3 {
                    return ffi::SQLITE_NOTFOUND;
                }
                if slot.set(parent as usize).is_err() {
                    return ffi::SQLITE_MISUSE;
                }
                let mut vfs = *parent;
                vfs.iVersion = 3;
                vfs.pNext = std::ptr::null_mut();
                vfs.zName = name.as_ptr();
                vfs.xOpen = Some(open);
                vfs.xDelete = Some(reject_delete);
                vfs.xFullPathname = Some(preserved_full_path);
                let code = ffi::sqlite3_vfs_register(Box::into_raw(Box::new(vfs)), 0);
                if code != ffi::SQLITE_OK {
                    return code;
                }
            }
            ffi::SQLITE_OK
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

fn validate_private_wal_header(path: &Path, length: u64) -> Result<()> {
    // SQLite silently ignores an invalid WAL header. Admission must not treat
    // that as a complete view of retained history. Frame recovery, including
    // interrupted transactions/tails, remains SQLite's responsibility.
    if length == 0 {
        return Ok(());
    }
    let mut header = [0; 32];
    fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?
        .read_exact(&mut header)?;
    let big_word = |bytes: &[u8]| u32::from_be_bytes(bytes.try_into().unwrap());
    let magic = big_word(&header[..4]);
    let word = |bytes: &[u8]| {
        if magic & 1 == 0 {
            u32::from_le_bytes(bytes.try_into().unwrap())
        } else {
            big_word(bytes)
        }
    };
    let mut checksum = [0_u32; 2];
    for pair in header[..24].as_chunks::<8>().0 {
        checksum[0] = checksum[0]
            .wrapping_add(word(&pair[..4]))
            .wrapping_add(checksum[1]);
        checksum[1] = checksum[1]
            .wrapping_add(word(&pair[4..]))
            .wrapping_add(checksum[0]);
    }
    ensure!(
        magic & !1 == 0x377f_0682
            && big_word(&header[4..8]) == 3_007_000
            && big_word(&header[8..12]) == 4096
            && checksum == [big_word(&header[24..28]), big_word(&header[28..32])],
        "preserved catalog WAL header is invalid or incompatible; preserve every database/journal file and inspect a separate complete snapshot; see docs/guarded-withdrawal.md"
    );
    Ok(())
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

/// Versions of preserved database inputs. Long-running recovery must verify
/// these immediately before publishing output; this guard holds no SQLite lock.
pub struct PreservedReadGuard {
    path: PathBuf,
    before: FileVersion,
    journals: [PathBuf; 3],
    journal_versions: Vec<Option<FileVersion>>,
    immutable: bool,
    private_wal: bool,
}

impl PreservedReadGuard {
    fn capture(path: &Path) -> Result<Self> {
        let before = version(path)?.context("preserved database is unavailable")?;
        ensure!(before.len != 0, "preserved database is empty");
        let journals = journal_paths(path);
        let journal_versions: Vec<_> = journals
            .iter()
            .map(|path| version(path))
            .collect::<Result<_>>()?;
        let immutable = journal_versions.iter().all(Option::is_none);
        let private_wal = journal_versions[0]
            .as_ref()
            .is_some_and(|wal| wal.len == 0 || wal.len >= 32)
            && journal_versions[1].is_none()
            && journal_versions[2].is_none();
        ensure!(
            immutable
                || private_wal
                || (journal_versions[0].is_some()
                    && journal_versions[1].is_some()
                    && journal_versions[2].is_none()),
            "preserved database has incomplete or rollback journal state; preserve every database/journal file and inspect a separate complete snapshot; see docs/guarded-withdrawal.md"
        );
        if private_wal {
            validate_private_wal_header(&journals[0], journal_versions[0].as_ref().unwrap().len)?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            before,
            journals,
            journal_versions,
            immutable,
            private_wal,
        })
    }

    /// Reject changed or replaced inputs before publishing a recovered result.
    /// SQLite may update transient read marks in an existing writer's SHM
    /// mapping; its identity and length must remain unchanged instead.
    pub fn verify_unchanged(&self) -> Result<()> {
        ensure!(
            version(&self.path)?.as_ref() == Some(&self.before),
            "preserved database changed during recovery; stop its writer and retry"
        );
        for (index, (path, before)) in self.journals.iter().zip(&self.journal_versions).enumerate()
        {
            let after = version(path)?;
            let unchanged = if index == 1 && !self.immutable && !self.private_wal {
                matches!((before, &after), (Some(before), Some(after)) if before.device == after.device && before.inode == after.inode && before.len == after.len)
            } else {
                before == &after
            };
            ensure!(
                unchanged,
                "preserved database journal changed during recovery; stop its writer and retry"
            );
        }
        Ok(())
    }

    fn verify_snapshot(&self) -> Result<()> {
        if self.immutable || self.private_wal {
            return self.verify_unchanged().with_context(|| {
                format!(
                    "preserved catalog changed during {} inspection; stop its writer and retry",
                    if self.immutable {
                        "immutable"
                    } else {
                        "private WAL"
                    },
                )
            });
        }
        // The enclosing live read snapshot supplies the original inspection
        // contract. Recovery callers require the stronger verify_unchanged()
        // check before publishing their output.
        Ok(())
    }
}

pub(super) fn open<T>(
    path: &Path,
    database_keys: &[[u8; 32]],
    validate: impl Fn(Connection) -> Result<T>,
) -> Result<(T, PreservedReadGuard)> {
    register_vfs()?;
    let guard = PreservedReadGuard::capture(path)?;
    let uri = uri(path, guard.immutable)?;
    let mut opened = None;
    let mut last_error = None;
    for key in database_keys {
        let attempt = (|| -> Result<T> {
            let connection = Connection::open_with_flags_and_vfs(
                &uri,
                OpenFlags::SQLITE_OPEN_READ_ONLY
                    | OpenFlags::SQLITE_OPEN_NO_MUTEX
                    | OpenFlags::SQLITE_OPEN_URI,
                if guard.private_wal {
                    PRIVATE_WAL_VFS_NAME
                } else {
                    VFS_NAME
                }
                .to_str()?,
            )?;
            if guard.private_wal {
                // Unlike URI nolock=1 (which disables WAL), this keeps SQLite's
                // WAL pager enabled and selects its private heap wal-index.
                // A native exclusive lock requires a writable fd. unix-none
                // avoids that lock; version guards must protect both files.
                connection.pragma_update(None, "locking_mode", "EXCLUSIVE")?;
            }
            validate(configure_encrypted_connection(connection, key, true)?)
        })();
        match attempt {
            Ok(store) => {
                opened = Some(store);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    guard.verify_snapshot()?;
    let store = opened
        .ok_or_else(|| last_error.unwrap_or_else(|| anyhow::anyhow!("no database key supplied")))
        .context("preserved database rejected available database keys")?;
    Ok((store, guard))
}

pub(super) fn open_control(
    path: &Path,
    database_keys: &[[u8; 32]],
) -> Result<(ControlStore, PreservedReadGuard)> {
    open(path, database_keys, |connection| {
        control_reader(path, connection)
    })
}

fn control_reader(path: &Path, connection: Connection) -> Result<ControlStore> {
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
        physical_vfs: None,
        path: path.to_path_buf(),
        #[cfg(target_os = "linux")]
        directory: None,
    })
}

impl ControlStore {
    /// Inspect a signed native birth without initializing/migrating SQL. None
    /// means the committed image is still tableless, rather than an unknown or
    /// partially decoded control schema.
    pub fn inspect_native_creation_snapshot(
        path: impl AsRef<Path>,
        key: &[u8; 32],
    ) -> Result<(Option<Self>, PreservedReadGuard)> {
        let path = path.as_ref();
        open(path, &[*key], |connection| {
            if !super::database_has_tables(&connection)? {
                return Ok(None);
            }
            Ok(Some(control_reader(path, connection)?))
        })
    }
}

pub(super) fn inspect<T>(
    path: &Path,
    database_keys: &[[u8; 32]],
    operation: impl FnOnce(&ControlStore) -> Result<T>,
) -> Result<T> {
    let (control, guard) = open_control(path, database_keys)?;
    let result = control.with_read_only_snapshot(|| operation(&control));
    guard.verify_snapshot()?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    #[test]
    fn reusable_preserved_reader_releases_snapshots_and_rejects_later_writer_commits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        writer.put_record("root", b"id", b"old").unwrap();
        let (reader, guard) =
            ControlStore::open_preserved_read_only_with_keys(&path, &[[7; 32]]).unwrap();
        reader
            .with_read_only_snapshot(|| {
                assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"old");
                writer.put_record("root", b"id", b"new")?;
                assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"old");
                Ok(())
            })
            .unwrap();
        assert!(reader.connection.is_autocommit());
        reader
            .with_read_only_snapshot(|| {
                assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"new");
                Ok(())
            })
            .unwrap();
        assert!(
            guard
                .verify_unchanged()
                .unwrap_err()
                .to_string()
                .contains("journal changed")
        );
    }

    #[test]
    fn reusable_private_wal_reader_creates_no_sidecars_across_snapshots_and_key_failures() {
        let (_temp, path) = offline_wal_fixture();
        let journals = journal_paths(&path);
        let before = [fs::read(&path).unwrap(), fs::read(&journals[0]).unwrap()];
        assert!(ControlStore::open_preserved_read_only_with_keys(&path, &[[8; 32]]).is_err());
        let (reader, guard) =
            ControlStore::open_preserved_read_only_with_keys(&path, &[[8; 32], [7; 32]]).unwrap();
        for _ in 0..3 {
            reader
                .with_read_only_snapshot(|| {
                    assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"only in WAL");
                    Ok(())
                })
                .unwrap();
            assert!(reader.connection.is_autocommit());
            guard.verify_unchanged().unwrap();
        }
        drop(reader);
        guard.verify_unchanged().unwrap();
        assert_eq!(
            [fs::read(&path).unwrap(), fs::read(&journals[0]).unwrap()],
            before
        );
        assert!(!journals[1].exists());
        assert!(!journals[2].exists());
        fs::write(&journals[1], b"").unwrap();
        assert!(guard.verify_unchanged().is_err());
    }

    fn offline_wal_fixture() -> (tempfile::TempDir, PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source.db");
        let writer = ControlStore::open_with_key(&source, &[7; 32]).unwrap();
        writer.put_record("root", b"id", b"checkpointed").unwrap();
        writer
            .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
            .unwrap();
        writer.put_record("root", b"id", b"only in WAL").unwrap();
        let path = temp.path().join("preserved.db");
        fs::copy(&source, &path).unwrap();
        fs::copy(&journal_paths(&source)[0], &journal_paths(&path)[0]).unwrap();
        drop(writer);
        (temp, path)
    }

    #[test]
    fn preserved_wal_without_shared_memory_reads_commits_without_creating_files() {
        let (_temp, path) = offline_wal_fixture();
        let wal = journal_paths(&path)[0].clone();
        // A crash may leave a partial final frame after the last commit.
        use std::io::Write;
        fs::OpenOptions::new()
            .append(true)
            .open(&wal)
            .unwrap()
            .write_all(b"interrupted tail")
            .unwrap();
        let before = [fs::read(&path).unwrap(), fs::read(&wal).unwrap()];
        inspect(&path, &[[8; 32], [7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"only in WAL");
            assert!(reader.put_record("root", b"id", b"changed").is_err());
            assert!(!journal_paths(&path)[1].exists());
            assert!(!journal_paths(&path)[2].exists());
            Ok(())
        })
        .unwrap();
        assert!(inspect(&path, &[[8; 32]], |_| Ok(())).is_err());
        assert_eq!([fs::read(&path).unwrap(), fs::read(&wal).unwrap()], before);
        assert!(!journal_paths(&path)[1].exists());
        assert!(!journal_paths(&path)[2].exists());
    }

    #[test]
    fn offline_wal_with_empty_shared_memory_recovers_its_index_without_writing() {
        let (_temp, path) = offline_wal_fixture();
        let journals = journal_paths(&path);
        fs::write(&journals[1], b"").unwrap();
        let before = [fs::read(&path).unwrap(), fs::read(&journals[0]).unwrap()];
        inspect(&path, &[[7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"only in WAL");
            Ok(())
        })
        .unwrap();
        assert_eq!(
            [fs::read(&path).unwrap(), fs::read(&journals[0]).unwrap()],
            before
        );
        assert_eq!(fs::metadata(&journals[1]).unwrap().len(), 0);
        assert!(!journals[2].exists());
    }

    #[test]
    fn private_wal_inspection_rejects_input_changes_and_new_shared_memory() {
        for create_shm in [false, true] {
            let (_temp, path) = offline_wal_fixture();
            let journals = journal_paths(&path);
            let result = inspect(&path, &[[7; 32]], |reader| {
                assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"only in WAL");
                if create_shm {
                    fs::write(&journals[1], b"another writer's shared memory")?;
                } else {
                    fs::write(&journals[0], b"replaced WAL")?;
                }
                Ok("must not return stale inspection")
            });
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("changed during private WAL inspection")
            );
            assert!(!journals[2].exists());
        }
    }

    #[test]
    fn private_wal_inspection_rejects_corrupt_headers_without_ignoring_history() {
        for offset in [0, 4, 8, 16, 24] {
            let (_temp, path) = offline_wal_fixture();
            let journals = journal_paths(&path);
            let mut wal = fs::read(&journals[0]).unwrap();
            wal[offset] ^= 1;
            fs::write(&journals[0], &wal).unwrap();
            let main = fs::read(&path).unwrap();
            let result: Result<()> =
                inspect(&path, &[[7; 32]], |_| panic!("corrupt WAL was ignored"));
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("WAL header is invalid")
            );
            assert_eq!(fs::read(&path).unwrap(), main);
            assert_eq!(fs::read(&journals[0]).unwrap(), wal);
            assert!(!journals[1].exists());
            assert!(!journals[2].exists());
        }
    }

    #[test]
    fn empty_preserved_wal_uses_main_catalog_without_creation() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        writer.put_record("root", b"id", b"checkpointed").unwrap();
        drop(writer);
        let main = fs::read(&path).unwrap();
        let journals = journal_paths(&path);
        fs::write(&journals[0], b"").unwrap();
        inspect(&path, &[[7; 32]], |reader| {
            assert_eq!(reader.get_record("root", b"id")?.unwrap(), b"checkpointed");
            Ok(())
        })
        .unwrap();
        assert_eq!(fs::read(&path).unwrap(), main);
        assert_eq!(fs::metadata(&journals[0]).unwrap().len(), 0);
        assert!(!journals[1].exists());
        assert!(!journals[2].exists());
    }

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
