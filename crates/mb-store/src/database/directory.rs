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

#[derive(Clone, Debug, Eq, PartialEq)]
struct OpenFileVersion {
    device: u64,
    inode: u64,
    size: u64,
    mode: u32,
    owner: u32,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl OpenFileVersion {
    fn capture(path: &Path) -> Result<Option<Self>, DatabaseError> {
        let metadata = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file() {
            return Err(DatabaseError::Conflict);
        }
        Ok(Some(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }))
    }

    fn same_mapping(&self, other: &Self) -> bool {
        (
            self.device,
            self.inode,
            self.size,
            self.mode,
            self.owner,
            self.links,
        ) == (
            other.device,
            other.inode,
            other.size,
            other.mode,
            other.owner,
            other.links,
        )
    }
}

/// Bind a completed read-only admission to the first writable main-file open.
/// Capture before inspection and verify afterwards, then supply this token to
/// the directory opener. No SQLite journal-mode/schema changes precede its check.
#[derive(Clone)]
pub struct DatabaseOpenGuard {
    main: Option<OpenFileVersion>,
    journals: [Option<OpenFileVersion>; 3],
    private_files: Vec<(std::ffi::OsString, Option<OpenFileVersion>)>,
}

impl DatabaseOpenGuard {
    pub fn capture(path: &Path, private_files: &[&OsStr]) -> Result<Self, DatabaseError> {
        Self::capture_inner(path, private_files, false)
    }

    /// Capture fresh/partial native creation, including a bound empty main.
    /// Empty images must have no journals. Ordinary admission still rejects
    /// empty existing catalogs; only explicit creation should use this token.
    pub fn capture_native_creation(
        path: &Path,
        private_files: &[&OsStr],
    ) -> Result<Self, DatabaseError> {
        Self::capture_inner(path, private_files, true)
    }

    fn capture_inner(
        path: &Path,
        private_files: &[&OsStr],
        allow_empty: bool,
    ) -> Result<Self, DatabaseError> {
        if private_files.len() > 16 {
            return Err(DatabaseError::Conflict);
        }
        let parent = path.parent().ok_or(DatabaseError::Conflict)?;
        let main_name = path.file_name().ok_or(DatabaseError::Conflict)?;
        if !valid_leaf(main_name.as_bytes()) {
            return Err(DatabaseError::Conflict);
        }
        let mut extras = Vec::with_capacity(private_files.len());
        for name in private_files {
            if !valid_leaf(name.as_bytes()) || *name == main_name {
                return Err(DatabaseError::Conflict);
            }
            extras.push((
                name.to_os_string(),
                OpenFileVersion::capture(&parent.join(name))?,
            ));
        }
        let journals: [Option<OpenFileVersion>; 3] = Self::journal_paths(path)
            .iter()
            .map(|path| OpenFileVersion::capture(path))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| DatabaseError::Conflict)?;
        let main = OpenFileVersion::capture(path)?;
        if (main.as_ref().is_some_and(|file| file.size == 0)
            && (!allow_empty || journals.iter().any(Option::is_some)))
            || (main.is_none() && journals.iter().any(Option::is_some))
        {
            return Err(DatabaseError::IncompatibleSchema);
        }
        Ok(Self {
            main,
            journals,
            private_files: extras,
        })
    }

    pub fn requires_existing_catalog(&self) -> bool {
        self.main.is_some()
    }

    pub fn refresh_private_files_after_publication(
        &self,
        path: &Path,
    ) -> Result<Self, DatabaseError> {
        let mut refreshed = self.clone();
        refreshed.private_files.clear();
        refreshed.verify_unchanged(path)?;
        for (name, _) in &self.private_files {
            let parent = path.parent().ok_or(DatabaseError::Conflict)?;
            refreshed
                .private_files
                .push((name.clone(), OpenFileVersion::capture(&parent.join(name))?));
        }
        Ok(refreshed)
    }

    fn journal_paths(path: &Path) -> [PathBuf; 3] {
        ["-wal", "-shm", "-journal"].map(|suffix| {
            let mut name = path.as_os_str().to_os_string();
            name.push(suffix);
            PathBuf::from(name)
        })
    }

    pub fn verify_unchanged(&self, path: &Path) -> Result<(), DatabaseError> {
        if OpenFileVersion::capture(path)? != self.main {
            return Err(DatabaseError::Conflict);
        }
        self.verify_other_inputs(path)
    }

    fn verify_other_inputs(&self, path: &Path) -> Result<(), DatabaseError> {
        for (index, (path, expected)) in Self::journal_paths(path)
            .iter()
            .zip(&self.journals)
            .enumerate()
        {
            let actual = OpenFileVersion::capture(path)?;
            // Existing SHM read marks are transient. Its mapping, ownership and
            // permissions must remain the same; main/WAL/journal versions are exact.
            let same = if index == 1 {
                match (expected, &actual) {
                    (Some(expected), Some(actual)) => expected.same_mapping(actual),
                    (None, None) => true,
                    _ => false,
                }
            } else {
                *expected == actual
            };
            if !same {
                return Err(DatabaseError::Conflict);
            }
        }
        let parent = path.parent().ok_or(DatabaseError::Conflict)?;
        for (name, expected) in &self.private_files {
            if OpenFileVersion::capture(&parent.join(name))? != *expected {
                return Err(DatabaseError::Conflict);
            }
        }
        Ok(())
    }

    pub(super) fn verify_native_creation_before_open(
        &self,
        path: &Path,
    ) -> Result<(), DatabaseError> {
        if self.main.is_some() {
            return self.verify_unchanged(path);
        }
        // Native birth may publish the new bound main, but may not initialize
        // SQL or change any previously admitted input before descriptor check.
        if !OpenFileVersion::capture(path)?.is_some_and(|file| file.size == 0) {
            return Err(DatabaseError::Conflict);
        }
        self.verify_other_inputs(path)
    }

    pub(super) fn verify_opened(
        &self,
        path: &Path,
        connection: &Connection,
    ) -> Result<(), DatabaseError> {
        if self.main.is_some() {
            self.verify_unchanged(path)?;
        } else {
            // Opening an admitted absent main file may create only an empty
            // file. An existing catalog cannot silently become a fresh one.
            if !OpenFileVersion::capture(path)?.is_some_and(|file| file.size == 0) {
                return Err(DatabaseError::Conflict);
            }
            self.verify_other_inputs(path)?;
        }
        let mut moved = 1_i32;
        // SAFETY: the live connection owns its native main file; SQLite's public
        // file-control contract writes one int. Unix checks its opened inode
        // against the current directory-bound pathname, without private ABI access.
        let code = unsafe {
            ffi::sqlite3_file_control(
                connection.handle(),
                c"main".as_ptr(),
                ffi::SQLITE_FCNTL_HAS_MOVED,
                (&mut moved as *mut i32).cast(),
            )
        };
        if code != ffi::SQLITE_OK || moved != 0 {
            return Err(DatabaseError::Conflict);
        }
        Ok(())
    }
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
        self.connect_with_guard(name, key, existing, None)
    }

    fn connect_with_guard(
        &self,
        name: &OsStr,
        key: &[u8; 32],
        existing: bool,
        guard: Option<&DatabaseOpenGuard>,
    ) -> Result<(Connection, PathBuf), DatabaseError> {
        let path = self.leaf(name)?;
        super::native_owner::reject_managed_path(&path)?;
        if let Some(guard) = guard {
            guard.verify_unchanged(&path)?;
        }
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
        if let Some(guard) = guard {
            guard.verify_opened(&path, &connection)?;
        }
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

pub(super) unsafe extern "C" fn full_path(
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
            let parent = match super::journal_vfs::register() {
                Ok(parent) => parent,
                Err(_) => return ffi::SQLITE_CANTOPEN,
            };
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
    pub fn verify_open_guard(&self, guard: &DatabaseOpenGuard) -> Result<(), DatabaseError> {
        guard.verify_opened(&self.path, &self.connection)
    }

    pub fn open_admitted_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        key: &[u8; 32],
        guard: &DatabaseOpenGuard,
    ) -> Result<Self, DatabaseError> {
        let (mut connection, path) =
            directory.connect_with_guard(name, key, guard.main.is_some(), Some(guard))?;
        initialize_or_validate_control(&mut connection)?;
        Ok(Self {
            connection,
            physical_vfs: None,
            path,
            directory: Some(directory.clone()),
        })
    }

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
            physical_vfs: None,
            path,
            directory: Some(directory.clone()),
        })
    }

    pub fn directory(&self) -> Option<&DatabaseDirectory> {
        self.directory.as_ref()
    }
}

impl ParityStore {
    pub fn verify_open_guard(&self, guard: &DatabaseOpenGuard) -> Result<(), DatabaseError> {
        guard.verify_opened(&self.path, &self.connection)
    }

    /// Open only the main file and journals admitted by a completed read-only
    /// inspection. Check their versions before journal/schema changes.
    pub fn open_admitted_in_directory_with_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        key: &[u8; 32],
        guard: &DatabaseOpenGuard,
    ) -> Result<Self, DatabaseError> {
        let (mut connection, path) =
            directory.connect_with_guard(name, key, guard.main.is_some(), Some(guard))?;
        initialize_or_validate_parity(&mut connection, volume)?;
        Ok(Self {
            connection,
            physical_vfs: None,
            path,
            directory: Some(directory.clone()),
        })
    }

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
            physical_vfs: None,
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
    fn admitted_parity_open_rejects_replaced_inputs_before_journals_or_schema_writes() {
        for changed in ["main", "wal", "manifest", "absent"] {
            let temp = tempfile::tempdir().unwrap();
            let directory = DatabaseDirectory::open(temp.path()).unwrap();
            let path = directory.leaf("parity.db").unwrap();
            let manifest = directory.leaf("manifest").unwrap();
            std::fs::write(&manifest, b"original").unwrap();
            if changed != "absent" {
                drop(
                    ParityStore::open_in_directory_with_key(
                        &directory,
                        OsStr::new("parity.db"),
                        &[6; 16],
                        &[7; 32],
                    )
                    .unwrap(),
                );
            }
            let guard = DatabaseOpenGuard::capture(&path, &[OsStr::new("manifest")]).unwrap();
            match changed {
                "main" => {
                    std::fs::rename(&path, temp.path().join("original.db")).unwrap();
                    std::fs::write(&path, b"replacement").unwrap();
                }
                "wal" => std::fs::write(temp.path().join("parity.db-wal"), b"new WAL").unwrap(),
                "manifest" => std::fs::write(&manifest, b"changed").unwrap(),
                "absent" => {
                    drop(
                        ParityStore::open_in_directory_with_key(
                            &directory,
                            OsStr::new("parity.db"),
                            &[6; 16],
                            &[7; 32],
                        )
                        .unwrap(),
                    );
                }
                _ => unreachable!(),
            }
            let snapshot = || {
                std::fs::read_dir(temp.path())
                    .unwrap()
                    .map(|entry| {
                        let path = entry.unwrap().path();
                        (
                            path.file_name().unwrap().to_owned(),
                            std::fs::read(path).unwrap(),
                        )
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            let before = snapshot();
            assert!(
                ParityStore::open_admitted_in_directory_with_key(
                    &directory,
                    OsStr::new("parity.db"),
                    &[6; 16],
                    &[7; 32],
                    &guard
                )
                .is_err(),
                "{changed}"
            );
            assert_eq!(snapshot(), before, "{changed}");
        }
    }

    #[test]
    fn preserved_directory_parity_reads_original_wal_after_rename_and_first_connection_close() {
        let temp = tempfile::tempdir().unwrap();
        let visible = temp.path().join("volume");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&visible).unwrap();
        let directory = DatabaseDirectory::open(&visible).unwrap();
        let mut writer = ParityStore::open_in_directory_with_key(
            &directory,
            OsStr::new("parity.db"),
            &[6; 16],
            &[7; 32],
        )
        .unwrap();
        let bytes = vec![42; mb_core::V1_SECTOR_SIZE];
        let original = super::super::ParityObject {
            format_version: 1,
            guild_id: [3; 32],
            group_id: [4; 32],
            shard_index: 3,
            root: mb_core::sector_root(&bytes),
            bytes,
        };
        writer.stage_and_publish(&original).unwrap();
        std::fs::rename(&visible, &moved).unwrap();
        std::fs::create_dir(&visible).unwrap();
        let replacement =
            ParityStore::open_with_key(visible.join("parity.db"), &[6; 16], &[7; 32]).unwrap();
        drop(replacement);
        let snapshot = || {
            std::fs::read_dir(&visible)
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    (
                        path.file_name().unwrap().to_owned(),
                        std::fs::read(path).unwrap(),
                    )
                })
                .collect::<std::collections::BTreeMap<_, _>>()
        };
        let before = snapshot();
        let path = directory.leaf("parity.db").unwrap();
        let (reader, guard) =
            ParityStore::open_preserved_read_only_with_keys(&path, &[6; 16], &[[7; 32]]).unwrap();
        assert_eq!(
            reader
                .load_ready(&original.group_id, original.shard_index)
                .unwrap(),
            original
        );
        guard.verify_unchanged().unwrap();
        drop(reader);
        drop(writer);
        let (reader, guard) =
            ParityStore::open_preserved_read_only_with_keys(&path, &[6; 16], &[[7; 32]]).unwrap();
        assert_eq!(
            reader
                .load_ready(&original.group_id, original.shard_index)
                .unwrap(),
            original
        );
        guard.verify_unchanged().unwrap();
        assert_eq!(snapshot(), before);
    }

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

    #[test]
    fn admitted_directory_open_creates_only_a_fresh_catalog_and_reopens_exact_existing_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let path = directory.leaf("control.db").unwrap();
        let fresh = DatabaseOpenGuard::capture(&path, &[]).unwrap();
        let store = ControlStore::open_admitted_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[31; 32],
            &fresh,
        )
        .unwrap();
        store.put_record("fixture", b"id", b"admitted").unwrap();
        drop(store);
        let existing = DatabaseOpenGuard::capture(&path, &[]).unwrap();
        let store = ControlStore::open_admitted_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[31; 32],
            &existing,
        )
        .unwrap();
        assert_eq!(
            store.get_record("fixture", b"id").unwrap(),
            Some(b"admitted".to_vec())
        );
    }

    #[test]
    fn admitted_directory_open_rejects_changed_main_journal_and_private_inputs_before_writes() {
        for change in ["main", "missing", "wal", "shm", "journal", "key", "new-key"] {
            let temp = tempfile::tempdir().unwrap();
            let directory = DatabaseDirectory::open(temp.path()).unwrap();
            let path = directory.leaf("control.db").unwrap();
            let key = directory.leaf("control.key").unwrap();
            drop(
                ControlStore::open_in_directory_with_key(
                    &directory,
                    OsStr::new("control.db"),
                    &[32; 32],
                )
                .unwrap(),
            );
            if change != "new-key" {
                std::fs::write(&key, b"private key").unwrap();
            }
            let guard = DatabaseOpenGuard::capture(&path, &[OsStr::new("control.key")]).unwrap();
            match change {
                "main" => {
                    let bytes = std::fs::read(&path).unwrap();
                    std::fs::rename(&path, directory.leaf("original.db").unwrap()).unwrap();
                    std::fs::write(&path, bytes).unwrap();
                }
                "missing" => {
                    std::fs::rename(&path, directory.leaf("original.db").unwrap()).unwrap();
                }
                "key" | "new-key" => {
                    std::fs::write(&key, b"different key").unwrap();
                }
                suffix => {
                    std::fs::write(
                        directory.leaf(format!("control.db-{suffix}")).unwrap(),
                        b"journal fixture",
                    )
                    .unwrap();
                }
            }
            let snapshot = || {
                std::fs::read_dir(temp.path())
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (entry.file_name(), std::fs::read(entry.path()).unwrap())
                    })
                    .collect::<std::collections::BTreeMap<_, _>>()
            };
            let before = snapshot();
            assert!(
                ControlStore::open_admitted_in_directory_with_key(
                    &directory,
                    OsStr::new("control.db"),
                    &[32; 32],
                    &guard,
                )
                .is_err(),
                "{change}"
            );
            assert_eq!(snapshot(), before, "{change}");
        }
    }

    #[test]
    fn admitted_open_checks_the_native_main_inode_even_when_path_versions_match() {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let path = directory.leaf("control.db").unwrap();
        let original = directory.leaf("original.db").unwrap();
        let replacement = directory.leaf("replacement.db").unwrap();
        drop(
            ControlStore::open_in_directory_with_key(
                &directory,
                OsStr::new("control.db"),
                &[33; 32],
            )
            .unwrap(),
        );
        std::fs::rename(&path, &original).unwrap();
        drop(
            ControlStore::open_in_directory_with_key(
                &directory,
                OsStr::new("control.db"),
                &[34; 32],
            )
            .unwrap(),
        );
        register().unwrap();
        let connection = Connection::open_with_flags_and_vfs(
            &path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
            VFS_NAME.to_str().unwrap(),
        )
        .unwrap();
        std::fs::rename(&path, &replacement).unwrap();
        std::fs::rename(&original, &path).unwrap();
        let guard = DatabaseOpenGuard::capture(&path, &[]).unwrap();
        guard.verify_unchanged(&path).unwrap();
        assert!(guard.verify_opened(&path, &connection).is_err());
        assert!(!directory.leaf("control.db-wal").unwrap().exists());
        assert!(!directory.leaf("control.db-shm").unwrap().exists());
    }

    #[test]
    fn private_publication_refresh_keeps_the_original_database_and_journal_versions() {
        let temp = tempfile::tempdir().unwrap();
        let directory = DatabaseDirectory::open(temp.path()).unwrap();
        let path = directory.leaf("control.db").unwrap();
        let key = directory.leaf("control.key").unwrap();
        drop(
            ControlStore::open_in_directory_with_key(
                &directory,
                OsStr::new("control.db"),
                &[35; 32],
            )
            .unwrap(),
        );
        let guard = DatabaseOpenGuard::capture(&path, &[OsStr::new("control.key")]).unwrap();
        std::fs::write(&key, b"published key").unwrap();
        assert!(guard.verify_unchanged(&path).is_err());
        let refreshed = guard
            .refresh_private_files_after_publication(&path)
            .unwrap();
        refreshed.verify_unchanged(&path).unwrap();
        std::fs::write(
            directory.leaf("control.db-wal").unwrap(),
            b"unadmitted journal",
        )
        .unwrap();
        assert!(
            guard
                .refresh_private_files_after_publication(&path)
                .is_err()
        );
    }

    #[test]
    fn directory_rekey_and_verification_keep_the_original_root_after_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let visible = temp.path().join("visible");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&visible).unwrap();
        let directory = DatabaseDirectory::open(&visible).unwrap();
        let store = ControlStore::open_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[36; 32],
        )
        .unwrap();
        store.put_record("fixture", b"id", b"original").unwrap();
        std::fs::rename(&visible, &moved).unwrap();
        std::fs::create_dir(&visible).unwrap();
        let replacement =
            ControlStore::open_with_key(visible.join("control.db"), &[37; 32]).unwrap();
        replacement
            .put_record("fixture", b"id", b"replacement")
            .unwrap();
        store.rekey(&[38; 32]).unwrap();
        let reopened = ControlStore::open_existing_in_directory_with_key(
            &directory,
            OsStr::new("control.db"),
            &[38; 32],
        )
        .unwrap();
        assert_eq!(
            reopened.get_record("fixture", b"id").unwrap(),
            Some(b"original".to_vec())
        );
        assert_eq!(
            replacement.get_record("fixture", b"id").unwrap(),
            Some(b"replacement".to_vec())
        );
    }
}
