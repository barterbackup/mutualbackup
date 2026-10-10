//! Linux database names bound to a held directory. SQLite's ordinary Unix
//! full-path callback resolves procfs descriptors back into mutable paths.
//! Keep the capability path through main, WAL, SHM and journal operations.

use std::{
    ffi::{CStr, OsStr},
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock, Weak},
};

use rusqlite::{Connection, OpenFlags, ffi};

use super::{
    ControlStore, DatabaseError, ParityStore, configure_encrypted, initialize_or_validate_control,
    initialize_or_validate_parity,
};

const VFS_NAME: &CStr = c"mutualbackup-directory";
static REGISTERED: OnceLock<i32> = OnceLock::new();
static DIRECTORIES: Mutex<std::collections::BTreeMap<i32, Weak<File>>> =
    Mutex::new(std::collections::BTreeMap::new());

/// A process-local directory capability. Never serialize its procfs path.
/// Connections retain this capability until after SQLite has closed journals.
#[derive(Clone)]
pub struct DatabaseDirectory {
    file: Arc<File>,
}

impl DatabaseDirectory {
    pub fn open(path: &Path) -> Result<Self, DatabaseError> {
        Self::from_file(Arc::new(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(path)?,
        ))
    }

    pub fn from_file(file: Arc<File>) -> Result<Self, DatabaseError> {
        let metadata = file.metadata()?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err(DatabaseError::Conflict);
        }
        let mut directories = DIRECTORIES.lock().map_err(|_| DatabaseError::Conflict)?;
        directories.retain(|_, directory| directory.strong_count() != 0);
        // Native Unix WAL connections share one SHM pathname per database
        // inode. Reuse the directory descriptor so that pathname remains live
        // when the first connection closes before another bound connection.
        for existing in directories.values().filter_map(Weak::upgrade) {
            let current = existing.metadata()?;
            if (current.dev(), current.ino()) == (metadata.dev(), metadata.ino()) {
                return Ok(Self { file: existing });
            }
        }
        directories.insert(file.as_raw_fd(), Arc::downgrade(&file));
        Ok(Self { file })
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
    }

    pub fn leaf(&self, name: impl AsRef<OsStr>) -> Result<PathBuf, DatabaseError> {
        let name = name.as_ref();
        if !valid_leaf(name.as_bytes()) {
            return Err(DatabaseError::Conflict);
        }
        Ok(self.path().join(name))
    }

    pub(super) fn connect(
        &self,
        name: &OsStr,
        key: &[u8; 32],
        existing: bool,
    ) -> Result<(Connection, PathBuf), DatabaseError> {
        let path = self.leaf(name)?;
        register()?;
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if existing {
            let metadata = std::fs::symlink_metadata(&path)?;
            if !metadata.is_file() || metadata.len() == 0 {
                return Err(DatabaseError::IncompatibleSchema);
            }
        } else {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags_and_vfs(
            &path,
            flags,
            VFS_NAME.to_str().expect("ASCII VFS name"),
        )?;
        Ok((configure_encrypted(connection, key)?, path))
    }
}

/// Scratch/checkpoint accounting may receive a capability path from an owned
/// store. Duplicate only a live capability registered by this module; arbitrary
/// procfs paths and ordinary final symlinks retain the no-follow rejection.
pub(super) fn open_directory_file(path: &Path) -> Result<File, DatabaseError> {
    if let Some(tail) = path.as_os_str().as_bytes().strip_prefix(b"/proc/self/fd/")
        && !tail.is_empty()
        && tail.iter().all(u8::is_ascii_digit)
    {
        let descriptor = std::str::from_utf8(tail)
            .ok()
            .and_then(|text| text.parse::<i32>().ok())
            .ok_or(DatabaseError::Conflict)?;
        let file = DIRECTORIES
            .lock()
            .map_err(|_| DatabaseError::Conflict)?
            .get(&descriptor)
            .and_then(Weak::upgrade)
            .ok_or(DatabaseError::Conflict)?;
        return Ok(file.try_clone()?);
    }
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

fn valid_leaf(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name != b"."
        && name != b".."
        && !name.contains(&b'/')
        && !name.contains(&0)
}

unsafe extern "C" fn full_path(
    _vfs: *mut ffi::sqlite3_vfs,
    input: *const std::ffi::c_char,
    capacity: i32,
    output: *mut std::ffi::c_char,
) -> i32 {
    if input.is_null() || output.is_null() || capacity <= 0 {
        return ffi::SQLITE_CANTOPEN;
    }
    // SAFETY: SQLite supplies a terminated input and the stated output buffer.
    let bytes = unsafe { CStr::from_ptr(input) }.to_bytes();
    let Some(tail) = bytes.strip_prefix(b"/proc/self/fd/") else {
        return ffi::SQLITE_CANTOPEN;
    };
    let Some(slash) = tail.iter().position(|byte| *byte == b'/') else {
        return ffi::SQLITE_CANTOPEN;
    };
    if slash == 0
        || !tail[..slash].iter().all(u8::is_ascii_digit)
        || !valid_leaf(&tail[slash + 1..])
        || bytes.len() >= capacity as usize
    {
        return ffi::SQLITE_CANTOPEN;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(input, output, bytes.len() + 1);
    }
    ffi::SQLITE_OK
}

fn register() -> Result<(), DatabaseError> {
    let code = *REGISTERED.get_or_init(|| {
        // SAFETY: OnceLock serializes registration. Only the built-in Unix VFS
        // has a base-table context suitable for this copied immutable adapter.
        // The table is not the default and lives until process exit. Its native
        // open/SHM methods retain O_NOFOLLOW and normal SQLite locking semantics.
        unsafe {
            let code = ffi::sqlite3_initialize();
            if code != ffi::SQLITE_OK {
                return code;
            }
            let parent = ffi::sqlite3_vfs_find(c"unix".as_ptr());
            if parent.is_null() || (*parent).iVersion < 3 {
                return ffi::SQLITE_NOTFOUND;
            }
            let mut vfs = *parent;
            vfs.iVersion = 3;
            vfs.pNext = std::ptr::null_mut();
            vfs.zName = VFS_NAME.as_ptr();
            vfs.xFullPathname = Some(full_path);
            ffi::sqlite3_vfs_register(Box::into_raw(Box::new(vfs)), 0)
        }
    });
    if code != ffi::SQLITE_OK {
        return Err(DatabaseError::Sql(rusqlite::Error::SqliteFailure(
            ffi::Error::new(code),
            Some("cannot register directory-bound database VFS".into()),
        )));
    }
    Ok(())
}

impl ControlStore {
    pub fn open_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        Self::open_directory(directory, name, key, false)
    }

    pub fn open_existing_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        Self::open_directory(directory, name, key, true)
    }

    fn open_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        key: &[u8; 32],
        existing: bool,
    ) -> Result<Self, DatabaseError> {
        let (mut connection, path) = directory.connect(name, key, existing)?;
        initialize_or_validate_control(&mut connection)?;
        Ok(Self {
            connection,
            path,
            directory: Some(directory.clone()),
        })
    }

    pub fn directory(&self) -> Option<&DatabaseDirectory> {
        self.directory.as_ref()
    }
}

impl ParityStore {
    pub fn open_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        Self::open_directory(directory, name, volume, key, false)
    }

    pub fn open_existing_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        Self::open_directory(directory, name, volume, key, true)
    }

    fn open_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        key: &[u8; 32],
        existing: bool,
    ) -> Result<Self, DatabaseError> {
        let (mut connection, path) = directory.connect(name, key, existing)?;
        initialize_or_validate_parity(&mut connection, volume)?;
        Ok(Self {
            connection,
            path,
            directory: Some(directory.clone()),
        })
    }

    pub fn directory(&self) -> Option<&DatabaseDirectory> {
        self.directory.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::{ffi::OsStringExt, fs::symlink};

    #[test]
    fn directory_wal_readers_and_writers_survive_reparenting_without_touching_replacements() {
        let temp = tempfile::tempdir().unwrap();
        let visible = temp.path().join("visible");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&visible).unwrap();
        let directory = DatabaseDirectory::open(&visible).unwrap();
        let first = ControlStore::open_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[7; 32],
        )
        .unwrap();
        first.put_record("fixture", b"id", b"original").unwrap();
        let independently_opened = DatabaseDirectory::open(&visible).unwrap();
        assert_eq!(directory.path(), independently_opened.path());
        let second = ControlStore::open_existing_in_directory_with_key(
            &independently_opened,
            OsStr::new("control.db"),
            &[7; 32],
        )
        .unwrap();
        std::fs::rename(&visible, &moved).unwrap();
        std::fs::create_dir(&visible).unwrap();
        let replacement =
            ControlStore::open_with_key(visible.join("control.db"), &[7; 32]).unwrap();
        replacement
            .put_record("fixture", b"id", b"replacement")
            .unwrap();
        first.put_record("fixture", b"id", b"first update").unwrap();
        assert_eq!(
            second.get_record("fixture", b"id").unwrap(),
            Some(b"first update".to_vec())
        );
        drop(first);
        drop(directory);
        drop(independently_opened);
        second
            .put_record("fixture", b"id", b"second update")
            .unwrap();
        second
            .connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        assert_eq!(
            replacement.get_record("fixture", b"id").unwrap(),
            Some(b"replacement".to_vec())
        );
        drop(second);
        let reopened =
            ControlStore::open_existing_with_key(moved.join("control.db"), &[7; 32]).unwrap();
        assert_eq!(
            reopened.get_record("fixture", b"id").unwrap(),
            Some(b"second update".to_vec())
        );
    }

    #[test]
    fn directory_capability_survives_a_symlink_replacing_its_former_path() {
        let temp = tempfile::tempdir().unwrap();
        let visible = temp.path().join("visible");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&visible).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let directory = DatabaseDirectory::open(&visible).unwrap();
        std::fs::rename(&visible, &moved).unwrap();
        symlink(&outside, &visible).unwrap();
        let store = ControlStore::open_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[8; 32],
        )
        .unwrap();
        store.put_record("fixture", b"id", b"owned").unwrap();
        assert!(moved.join("control.db").is_file());
        assert!(std::fs::read_dir(&outside).unwrap().next().is_none());
        assert!(DatabaseDirectory::open(&visible).is_err());
    }

    #[test]
    fn directory_database_leaf_and_missing_existing_opens_reject_before_creation() {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        for name in [
            "",
            ".",
            "..",
            "nested/control.db",
            "/control.db",
            "bad\0name",
        ] {
            assert!(
                ControlStore::open_in_directory_with_key(&directory, OsStr::new(name), &[9; 32])
                    .is_err()
            );
        }
        assert!(
            ControlStore::open_existing_in_directory_with_key(
                &directory,
                OsStr::new("missing.db"),
                &[9; 32]
            )
            .is_err()
        );
        assert!(std::fs::read_dir(temp.path()).unwrap().next().is_none());
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target");
        std::fs::write(&target, b"outside bytes").unwrap();
        symlink(&target, temp.path().join("control.db")).unwrap();
        assert!(
            ControlStore::open_in_directory_with_key(
                &directory,
                OsStr::new("control.db"),
                &[9; 32]
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&target).unwrap(), b"outside bytes");
    }

    #[test]
    fn directory_raw_names_and_bound_scratch_keep_the_original_physical_domain() {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let name = std::ffi::OsString::from_vec(b"control-\xff.db".to_vec());
        let store = ControlStore::open_in_directory_with_key(&directory, &name, &[10; 32]).unwrap();
        let scratch = super::super::RecordScratchStore::new_in_with_checkpoint_reservations(
            directory.path(),
            super::super::ScratchStorageLimits::for_database(1024 * 1024).unwrap(),
            &[store.path().to_path_buf()],
        )
        .unwrap();
        scratch
            .put_record_if_absent("fixture", b"id", b"scratch bytes")
            .unwrap();
        assert_eq!(
            scratch.get_record_bounded("fixture", b"id", 32).unwrap(),
            Some(b"scratch bytes".to_vec())
        );
        assert_eq!(
            super::super::physical_allocation_domain(directory.path()).unwrap(),
            super::super::physical_allocation_domain(temp.path()).unwrap()
        );
        let unregistered = OpenOptions::new().read(true).open(temp.path()).unwrap();
        assert!(
            open_directory_file(&PathBuf::from(format!(
                "/proc/self/fd/{}",
                unregistered.as_raw_fd()
            )))
            .is_err()
        );
    }

    #[test]
    fn directory_parity_publication_and_reopen_keep_ready_bytes_after_rename() {
        let temp = tempfile::tempdir().unwrap();
        let visible = temp.path().join("visible");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&visible).unwrap();
        let directory = DatabaseDirectory::open(&visible).unwrap();
        let bytes = vec![11; mb_core::V1_SECTOR_SIZE];
        let object = super::super::ParityObject {
            format_version: 1,
            guild_id: [12; 32],
            group_id: [13; 32],
            shard_index: 3,
            root: mb_core::sector_root(&bytes),
            bytes,
        };
        let mut store = ParityStore::open_in_directory_with_key(
            &directory,
            OsStr::new("parity.db"),
            &[14; 16],
            &[15; 32],
        )
        .unwrap();
        std::fs::rename(&visible, &moved).unwrap();
        std::fs::create_dir(&visible).unwrap();
        store.stage_and_publish(&object).unwrap();
        drop(store);
        let reopened = ParityStore::open_existing_in_directory_with_key(
            &directory,
            OsStr::new("parity.db"),
            &[14; 16],
            &[15; 32],
        )
        .unwrap();
        assert_eq!(
            reopened
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert!(std::fs::read_dir(&visible).unwrap().next().is_none());
    }
}
