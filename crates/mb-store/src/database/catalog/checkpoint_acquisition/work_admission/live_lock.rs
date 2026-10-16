//! Kernel ownership of traversal slots. The separate empty file avoids the
//! SQLite POSIX-lock hazard of opening/closing another main-file descriptor.
use super::*;

#[derive(Clone, Copy)]
pub(in crate::database::catalog) struct Class {
    pub(in crate::database::catalog) kinds: [&'static str; 2],
    tag: &'static str,
}
pub(in crate::database::catalog) const TRAVERSAL: Class = Class {
    kinds: [
        "catalog-live-work-domain-v1",
        "catalog-live-work-domain-guard-v1",
    ],
    tag: "work",
};
pub(in crate::database::catalog) const SCRATCH: Class = Class {
    kinds: [
        "catalog-scratch-domain-v1",
        "catalog-scratch-domain-guard-v1",
    ],
    tag: "scratch",
};
pub(in crate::database::catalog) const KINDS: [&str; 2] = TRAVERSAL.kinds;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(in crate::database::catalog) struct Identity {
    pub(in crate::database::catalog) device: u64,
    pub(in crate::database::catalog) inode: u64,
}

impl Identity {
    #[cfg(target_os = "linux")]
    pub(in crate::database::catalog) fn database(
        store: &ControlStore,
    ) -> Result<Self, CatalogStoreError> {
        use std::os::unix::fs::MetadataExt;
        // A different reported identity proves a copy only on a supported
        // local filesystem. Layered/remote views can alias the same database
        // with different device/inode values and independent lock domains.
        let directory = FileLock::directory(store)?;
        FileLock::local_filesystem(directory.file())?;
        let metadata = std::fs::metadata(&store.path).map_err(DatabaseError::from)?;
        if metadata.dev()
            != directory
                .file()
                .metadata()
                .map_err(DatabaseError::from)?
                .dev()
        {
            // A separately mounted file could hide another filesystem type
            // behind the otherwise local parent directory. Do not open an
            // extra main-file descriptor to inspect it (SQLite POSIX locks).
            return Err(CatalogStoreError::UnsupportedTraversalFilesystem);
        }
        let mut moved = 1_i32;
        // SAFETY: SQLite's public file-control API writes one int on the live
        // main connection. No private native file layout is inspected.
        let status = unsafe {
            rusqlite::ffi::sqlite3_file_control(
                store.connection.handle(),
                c"main".as_ptr(),
                rusqlite::ffi::SQLITE_FCNTL_HAS_MOVED,
                (&mut moved as *mut i32).cast(),
            )
        };
        if status != rusqlite::ffi::SQLITE_OK || moved != 0 || !metadata.is_file() {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub(in crate::database::catalog) fn database(
        _: &ControlStore,
    ) -> Result<Self, CatalogStoreError> {
        Err(CatalogStoreError::UnsupportedTraversalOwnership)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(in crate::database::catalog) struct Domain {
    version: u16,
    pub(in crate::database::catalog) id: Uuid,
    pub(in crate::database::catalog) database: Identity,
    file: Identity,
}

impl Domain {
    pub(in crate::database::catalog) fn permits_copy_reclamation(self) -> bool {
        // v1 did not establish a non-layered local filesystem identity.
        self.version == 2
    }
}

pub(in crate::database::catalog) fn read(
    cx: &Connection,
    class: Class,
) -> Result<Option<Domain>, CatalogStoreError> {
    let Some(bytes) = paired(cx, class.kinds[0], class.kinds[1], KEY)? else {
        return Ok(None);
    };
    let domain: Domain = canonical(&bytes)?;
    if !matches!(domain.version, 1 | 2)
        || domain.id.is_nil()
        || domain.database.inode == 0
        || domain.file.inode == 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(domain))
}

fn write(
    cx: &Connection,
    old: Option<Domain>,
    next: Domain,
    class: Class,
) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(&next)?;
    for kind in class.kinds {
        if let Some(old) = old {
            if cx.execute(
                "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
                params![kind, KEY, bytes, canonical_bytes(&old)?],
            )? != 1
            {
                return Err(DatabaseError::Integrity.into());
            }
        } else {
            insert_exact(cx, kind, KEY, &bytes)?;
        }
    }
    if read(cx, class)? != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(in crate::database::catalog) struct FileLock {
    #[cfg(target_os = "linux")]
    database_path: std::path::PathBuf,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(target_os = "linux")]
    directory: crate::database::DatabaseDirectory,
    #[cfg(target_os = "linux")]
    path: std::path::PathBuf,
    pub(in crate::database::catalog) domain: Domain,
    #[cfg(target_os = "linux")]
    creator: (u32, u64, u64),
}

impl FileLock {
    #[cfg(target_os = "linux")]
    fn directory(
        store: &ControlStore,
    ) -> Result<crate::database::DatabaseDirectory, CatalogStoreError> {
        let parent = store
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(std::path::Path::new("."));
        Ok(match &store.directory {
            Some(directory) => directory.clone(),
            None => crate::database::DatabaseDirectory::open(parent)?,
        })
    }

    #[cfg(target_os = "linux")]
    fn process() -> Result<(u32, u64, u64), CatalogStoreError> {
        use std::os::unix::fs::MetadataExt;
        let namespace = std::fs::metadata("/proc/self/ns/pid").map_err(DatabaseError::from)?;
        Ok((std::process::id(), namespace.dev(), namespace.ino()))
    }

    #[cfg(target_os = "linux")]
    fn open(
        store: &ControlStore,
        domain: Option<Domain>,
        rotate: bool,
        class: Class,
    ) -> Result<Self, CatalogStoreError> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let database = Identity::database(store)?;
        let directory = Self::directory(store)?;
        Self::local_filesystem(directory.file())?;
        let path = directory.leaf(format!(
            ".mutualbackup-{}-{:x}-{:x}.lock",
            class.tag, database.device, database.inode
        ))?;
        let options = || {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
                .mode(0o600);
            options
        };
        let file = if rotate {
            match options().create_new(true).open(&path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    options().open(&path).map_err(DatabaseError::from)?
                }
                Err(error) => return Err(DatabaseError::from(error).into()),
            }
        } else {
            options().open(&path).map_err(DatabaseError::from)?
        };
        let metadata = file.metadata().map_err(DatabaseError::from)?;
        let file_id = Identity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let next = match domain {
            Some(domain)
                if domain.database == database
                    && domain.file == file_id
                    && (!rotate || domain.version == 2) =>
            {
                domain
            }
            _ if rotate => Domain {
                version: 2,
                id: Uuid::new_v4(),
                database,
                file: file_id,
            },
            _ => return Err(DatabaseError::Conflict.into()),
        };
        let result = Self {
            database_path: directory
                .leaf(store.path.file_name().ok_or(DatabaseError::Conflict)?)?,
            file,
            directory,
            path,
            domain: next,
            creator: Self::process()?,
        };
        result.check_file()?;
        Self::local_filesystem(&result.file)?;
        if domain != Some(result.domain) {
            // Persist the inode and its directory entry before a committed work
            // declaration can depend on this lock domain after a power loss.
            result.file.sync_all().map_err(DatabaseError::from)?;
            result
                .directory
                .file()
                .sync_all()
                .map_err(DatabaseError::from)?;
        }
        if Identity::database(store)? != database {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(result)
    }

    #[cfg(not(target_os = "linux"))]
    fn open(
        _: &ControlStore,
        _: Option<Domain>,
        _: bool,
        _: Class,
    ) -> Result<Self, CatalogStoreError> {
        Err(CatalogStoreError::UnsupportedTraversalOwnership)
    }

    #[cfg(target_os = "linux")]
    fn check_file(&self) -> Result<(), CatalogStoreError> {
        use std::os::unix::fs::MetadataExt;
        let file = self.file.metadata().map_err(DatabaseError::from)?;
        let named = std::fs::symlink_metadata(&self.path).map_err(DatabaseError::from)?;
        let directory = self
            .directory
            .file()
            .metadata()
            .map_err(DatabaseError::from)?;
        if !file.is_file()
            || !named.is_file()
            || file.len() != 0
            || file.nlink() != 1
            || file.uid() != unsafe { libc::geteuid() }
            || file.mode() & 0o7777 != 0o600
            || (file.dev(), file.ino()) != (self.domain.file.device, self.domain.file.inode)
            || (named.dev(), named.ino()) != (file.dev(), file.ino())
            || directory.uid() != unsafe { libc::geteuid() }
            || directory.mode() & 0o022 != 0
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn local_filesystem(file: &std::fs::File) -> Result<(), CatalogStoreError> {
        use std::os::fd::AsRawFd;
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(file.as_raw_fd(), info.as_mut_ptr()) } != 0 {
            return Err(DatabaseError::from(std::io::Error::last_os_error()).into());
        }
        // OFD ownership must stay local to this kernel. Remote lock recovery
        // after a network partition cannot establish that old work has stopped.
        let local = [
            libc::BTRFS_SUPER_MAGIC as u32,
            libc::EXT4_SUPER_MAGIC as u32,
            0x5846_5342,
            libc::TMPFS_MAGIC as u32,
        ];
        if !local.contains(&(unsafe { info.assume_init() }.f_type as u32)) {
            return Err(CatalogStoreError::UnsupportedTraversalFilesystem);
        }
        Ok(())
    }

    pub(in crate::database::catalog) fn admit(
        cx: &Connection,
        store: &ControlStore,
        has_scopes: bool,
        class: Class,
    ) -> Result<Self, CatalogStoreError> {
        let old = read(cx, class)?;
        let database = Identity::database(store)?;
        if has_scopes && old.is_none_or(|d| d.database != database) {
            return Err(DatabaseError::NotReady.into());
        }
        let file = Self::open(store, old, !has_scopes, class)?;
        if old != Some(file.domain) {
            write(cx, old, file.domain, class)?;
        }
        Ok(file)
    }

    pub(in crate::database::catalog) fn existing(
        store: &ControlStore,
        domain: Domain,
        class: Class,
    ) -> Result<Self, CatalogStoreError> {
        Self::open(store, Some(domain), false, class)
    }

    #[cfg(target_os = "linux")]
    pub(in crate::database::catalog) fn check(
        &self,
        store: &ControlStore,
    ) -> Result<(), CatalogStoreError> {
        if Self::process()? != self.creator || Identity::database(store)? != self.domain.database {
            return Err(DatabaseError::NotReady.into());
        }
        self.check_file()
    }

    #[cfg(not(target_os = "linux"))]
    pub(in crate::database::catalog) fn check(
        &self,
        _: &ControlStore,
    ) -> Result<(), CatalogStoreError> {
        Err(CatalogStoreError::UnsupportedTraversalOwnership)
    }

    pub(in crate::database::catalog) fn allocation_domain(
        &self,
    ) -> Result<[u8; 32], CatalogStoreError> {
        #[cfg(target_os = "linux")]
        {
            Ok(crate::physical_allocation_domain(self.directory.path())?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CatalogStoreError::UnsupportedTraversalOwnership)
        }
    }

    /// Check an owned allocation token without retaining or reopening SQLite.
    /// No main-file descriptor is opened/closed, preserving native POSIX locks.
    pub(in crate::database::catalog) fn check_owned(&self) -> Result<(), CatalogStoreError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(&self.database_path).map_err(DatabaseError::from)?;
            if Self::process()? != self.creator
                || !metadata.is_file()
                || (metadata.dev(), metadata.ino())
                    != (self.domain.database.device, self.domain.database.inode)
            {
                return Err(DatabaseError::NotReady.into());
            }
            self.check_file()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CatalogStoreError::UnsupportedTraversalOwnership)
        }
    }

    #[cfg(target_os = "linux")]
    pub(in crate::database::catalog) fn try_slot(
        &self,
        slot: u8,
    ) -> Result<bool, CatalogStoreError> {
        use std::os::fd::AsRawFd;
        if u32::from(slot) >= CATALOG_ACQUISITION_WORK_JOBS {
            return Err(DatabaseError::Integrity.into());
        }
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        lock.l_start = slot.into();
        lock.l_len = 1;
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_OFD_SETLK, &lock) } == 0 {
            return Ok(true);
        }
        let error = std::io::Error::last_os_error();
        match error.raw_os_error() {
            Some(libc::EACCES | libc::EAGAIN) => Ok(false),
            Some(libc::EINVAL | libc::EOPNOTSUPP) => {
                Err(CatalogStoreError::UnsupportedTraversalOwnership)
            }
            _ => Err(DatabaseError::from(error).into()),
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub(in crate::database::catalog) fn try_slot(&self, _: u8) -> Result<bool, CatalogStoreError> {
        Err(CatalogStoreError::UnsupportedTraversalOwnership)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn separate_work_classes_keep_independent_domains_and_kernel_slots() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let traversal = FileLock::open(&store, None, true, TRAVERSAL).unwrap();
        let scratch = FileLock::open(&store, None, true, SCRATCH).unwrap();
        assert_ne!(traversal.path, scratch.path);
        assert_ne!(traversal.domain.id, scratch.domain.id);
        assert!(traversal.try_slot(0).unwrap());
        assert!(scratch.try_slot(0).unwrap());
        let observer = FileLock::open(&store, Some(scratch.domain), false, SCRATCH).unwrap();
        assert!(!observer.try_slot(0).unwrap());
        drop(traversal);
        assert!(!observer.try_slot(0).unwrap());
        scratch.check_owned().unwrap();
        drop(scratch);
        assert!(observer.try_slot(0).unwrap());
    }

    #[test]
    fn another_loaded_module_cannot_reclaim_a_live_process_scope() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let first = FileLock::open(&store, None, true, TRAVERSAL).unwrap();
        assert!(first.try_slot(7).unwrap());
        let other = FileLock::open(&store, Some(first.domain), false, TRAVERSAL).unwrap();
        assert!(!other.try_slot(7).unwrap());
        assert!(other.try_slot(8).unwrap());
        drop(other);
        let observer = FileLock::open(&store, Some(first.domain), false, TRAVERSAL).unwrap();
        assert!(!observer.try_slot(7).unwrap());
        assert!(observer.try_slot(8).unwrap());
        drop(first);
        assert!(observer.try_slot(7).unwrap());
    }

    #[test]
    fn traversal_slot_lock_keeps_directory_capability_after_rename() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        let directory = crate::database::DatabaseDirectory::open(&original).unwrap();
        let store = ControlStore::open_in_directory_with_key(
            &directory,
            std::ffi::OsStr::new("control.db"),
            &[7; 32],
        )
        .unwrap();
        let first = FileLock::open(&store, None, true, TRAVERSAL).unwrap();
        assert!(first.try_slot(0).unwrap());
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        std::fs::write(original.join("sentinel"), b"preserve").unwrap();
        first.check(&store).unwrap();
        let other = FileLock::open(&store, Some(first.domain), false, TRAVERSAL).unwrap();
        assert!(!other.try_slot(0).unwrap());
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(original.join("sentinel")).unwrap(),
            b"preserve"
        );
    }

    #[test]
    fn replaced_traversal_lock_file_cannot_steal_slots_or_overwrite_the_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let store = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
        let first = FileLock::open(&store, None, true, TRAVERSAL).unwrap();
        assert!(first.try_slot(0).unwrap());
        let saved = temp.path().join("saved");
        std::fs::rename(&first.path, &saved).unwrap();
        std::fs::write(&first.path, b"preserve this replacement").unwrap();
        assert!(first.check(&store).is_err());
        assert!(FileLock::open(&store, Some(first.domain), false, TRAVERSAL).is_err());
        assert_eq!(
            std::fs::read(&first.path).unwrap(),
            b"preserve this replacement"
        );
        std::fs::remove_file(&first.path).unwrap();
        std::fs::rename(&saved, &first.path).unwrap();
        first.check(&store).unwrap();
        assert!(first.try_slot(0).unwrap());
    }
}
