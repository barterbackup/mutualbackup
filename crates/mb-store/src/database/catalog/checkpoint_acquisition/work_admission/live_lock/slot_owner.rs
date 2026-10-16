//! Immutable owner identities for reusable aggregate slots. The directory has
//! at most one empty UUID-named file per slot, including failed-admission debt.
use super::*;

pub(in crate::database::catalog) struct SlotOwner {
    pub(in crate::database::catalog) identity: Identity,
    #[cfg(target_os = "linux")]
    directory: OwnerDirectory,
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    #[cfg(target_os = "linux")]
    name: std::ffi::OsString,
    #[cfg(target_os = "linux")]
    creator: (u32, u64, u64),
}

impl SlotOwner {
    pub(in crate::database::catalog) fn check(&self) -> Result<(), CatalogStoreError> {
        #[cfg(target_os = "linux")]
        {
            if FileLock::process()? != self.creator {
                return Err(DatabaseError::NotReady.into());
            }
            self.directory.check()?;
            let file = self.file.metadata().map_err(DatabaseError::from)?;
            let named = std::fs::symlink_metadata(self.directory.directory.leaf(&self.name)?)
                .map_err(DatabaseError::from)?;
            if file_identity(&file) != self.identity
                || file_identity(&named) != self.identity
                || !private_file(&file)
                || !private_file(&named)
            {
                return Err(DatabaseError::Conflict.into());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(CatalogStoreError::UnsupportedTraversalOwnership)
        }
    }
}

#[cfg(target_os = "linux")]
fn file_identity(metadata: &std::fs::Metadata) -> Identity {
    use std::os::unix::fs::MetadataExt;
    Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
    }
}

#[cfg(target_os = "linux")]
fn private_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.is_file()
        && metadata.len() == 0
        && metadata.nlink() == 1
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.mode() & 0o7777 == 0o600
}

#[cfg(target_os = "linux")]
fn owner_lock(file: &std::fs::File) -> Result<bool, CatalogStoreError> {
    use std::os::fd::AsRawFd;
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    lock.l_len = 1;
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_OFD_SETLK, &lock) } == 0 {
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

#[cfg(target_os = "linux")]
struct OwnerDirectory {
    parent: crate::database::DatabaseDirectory,
    directory: crate::database::DatabaseDirectory,
    name: std::ffi::OsString,
    identity: Identity,
    database: Identity,
}

#[cfg(target_os = "linux")]
impl OwnerDirectory {
    fn check(&self) -> Result<(), CatalogStoreError> {
        use std::os::unix::fs::MetadataExt;
        let held = self
            .directory
            .file()
            .metadata()
            .map_err(DatabaseError::from)?;
        let named = std::fs::symlink_metadata(self.parent.leaf(&self.name)?)
            .map_err(DatabaseError::from)?;
        if !held.is_dir()
            || !named.is_dir()
            || file_identity(&held) != self.identity
            || file_identity(&named) != self.identity
            || held.dev() != self.database.device
            || held.uid() != unsafe { libc::geteuid() }
            || held.mode() & 0o7777 != 0o700
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    fn scan(&self) -> Result<Vec<(u8, Uuid, Identity)>, CatalogStoreError> {
        self.check()?;
        let mut entries = Vec::new();
        let mut used = [false; CATALOG_ACQUISITION_WORK_JOBS as usize];
        for entry in std::fs::read_dir(self.directory.path())
            .map_err(DatabaseError::from)?
            .take(CATALOG_ACQUISITION_WORK_JOBS as usize + 1)
        {
            let entry = entry.map_err(DatabaseError::from)?;
            let name = entry.file_name();
            let text = name.to_str().ok_or(DatabaseError::Integrity)?;
            let (slot, id) = text
                .strip_suffix(".lock")
                .and_then(|name| name.split_once('-'))
                .ok_or(DatabaseError::Integrity)?;
            let slot: u8 = slot.parse().map_err(|_| DatabaseError::Integrity)?;
            let id = Uuid::parse_str(id).map_err(|_| DatabaseError::Integrity)?;
            if u32::from(slot) >= CATALOG_ACQUISITION_WORK_JOBS
                || id.is_nil()
                || text != format!("{slot:02}-{id}.lock")
                || std::mem::replace(&mut used[slot as usize], true)
            {
                return Err(DatabaseError::Integrity.into());
            }
            let metadata = std::fs::symlink_metadata(self.directory.leaf(&name)?)
                .map_err(DatabaseError::from)?;
            if !private_file(&metadata) || file_identity(&metadata).device != self.identity.device {
                return Err(DatabaseError::Conflict.into());
            }
            entries.push((slot, id, file_identity(&metadata)));
        }
        self.check()?;
        Ok(entries)
    }

    /// Pin and inspect before opening for I/O. Closing an accidentally aliased
    /// SQLite main-file I/O descriptor could remove the caller's POSIX locks.
    fn open_file(
        &self,
        slot: u8,
        id: Uuid,
        expected: Identity,
    ) -> Result<Option<std::fs::File>, CatalogStoreError> {
        use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
        self.check()?;
        let path = self.directory.leaf(format!("{slot:02}-{id}.lock"))?;
        let pin = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(DatabaseError::from(error).into()),
        };
        let metadata = pin.metadata().map_err(DatabaseError::from)?;
        if file_identity(&metadata) != expected {
            return Ok(None);
        }
        if expected == self.database || !private_file(&metadata) {
            return Err(DatabaseError::Conflict.into());
        }
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(format!("/proc/self/fd/{}", pin.as_raw_fd()))
            .map_err(DatabaseError::from)?;
        if file_identity(&file.metadata().map_err(DatabaseError::from)?) != expected
            || file_identity(&std::fs::symlink_metadata(&path).map_err(DatabaseError::from)?)
                != expected
        {
            return Err(DatabaseError::Conflict.into());
        }
        self.check()?;
        Ok(Some(file))
    }
}

impl FileLock {
    #[cfg(target_os = "linux")]
    fn owners(&self, create: bool) -> Result<Option<OwnerDirectory>, CatalogStoreError> {
        use std::os::unix::fs::DirBuilderExt;
        self.check_file()?;
        let mut name = self
            .path
            .file_name()
            .ok_or(DatabaseError::Conflict)?
            .to_os_string();
        name.push(".owners");
        let path = self.directory.leaf(&name)?;
        if create {
            match std::fs::DirBuilder::new().mode(0o700).create(&path) {
                Ok(()) => self
                    .directory
                    .file()
                    .sync_all()
                    .map_err(DatabaseError::from)?,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(error) => return Err(DatabaseError::from(error).into()),
            }
        }
        let directory = match crate::database::DatabaseDirectory::open(&path) {
            Ok(directory) => directory,
            Err(DatabaseError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(error) => return Err(error.into()),
        };
        Self::local_filesystem(directory.file())?;
        let identity = file_identity(&directory.file().metadata().map_err(DatabaseError::from)?);
        let result = OwnerDirectory {
            parent: self.directory.clone(),
            directory,
            name,
            identity,
            database: self.domain.database,
        };
        result.check()?;
        Ok(Some(result))
    }

    /// Verify actual owner UUIDs, including files absent from a restored
    /// ledger. Aggregate occupancy by itself does not identify a declaration.
    pub(in crate::database::catalog) fn validate_owners(
        &self,
        expected: &[Option<(Uuid, Identity)>; CATALOG_ACQUISITION_WORK_JOBS as usize],
    ) -> Result<(), CatalogStoreError> {
        #[cfg(target_os = "linux")]
        {
            let directory = self.owners(false)?;
            let mut live = [false; CATALOG_ACQUISITION_WORK_JOBS as usize];
            if let Some(directory) = &directory {
                for (slot, id, identity) in directory.scan()? {
                    let file = directory
                        .open_file(slot, id, identity)?
                        .ok_or(DatabaseError::Conflict)?;
                    if !owner_lock(&file)? {
                        if expected[slot as usize] != Some((id, identity)) {
                            return Err(CatalogStoreError::UnrecordedLiveCatalogWork);
                        }
                        live[slot as usize] = true;
                    }
                }
            }
            for (slot, entry) in expected.iter().enumerate() {
                if entry.is_none() {
                    continue;
                }
                let stopped = self.try_slot(slot as u8)?;
                if stopped {
                    self.unlock_slot(slot as u8)?;
                }
                if stopped == live[slot] {
                    return Err(CatalogStoreError::UnrecordedLiveCatalogWork);
                }
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected;
            Err(CatalogStoreError::UnsupportedTraversalOwnership)
        }
    }

    /// Called only while holding this aggregate slot and the SQLite writer.
    /// A stopped prior file is replaced, so crashes cannot grow the directory
    /// beyond one owner file per slot.
    pub(in crate::database::catalog) fn create_owner(
        &self,
        slot: u8,
        id: Uuid,
    ) -> Result<SlotOwner, CatalogStoreError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::OpenOptionsExt;
            if u32::from(slot) >= CATALOG_ACQUISITION_WORK_JOBS || id.is_nil() {
                return Err(DatabaseError::Integrity.into());
            }
            let directory = self.owners(true)?.ok_or(DatabaseError::Integrity)?;
            for (old_slot, old_id, identity) in directory.scan()? {
                if old_slot != slot {
                    continue;
                }
                let file = directory
                    .open_file(slot, old_id, identity)?
                    .ok_or(DatabaseError::Conflict)?;
                if !owner_lock(&file)? {
                    return Err(CatalogStoreError::UnrecordedLiveCatalogWork);
                }
                std::fs::remove_file(
                    directory
                        .directory
                        .leaf(format!("{slot:02}-{old_id}.lock"))?,
                )
                .map_err(DatabaseError::from)?;
            }
            let name: std::ffi::OsString = format!("{slot:02}-{id}.lock").into();
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .mode(0o600)
                .open(directory.directory.leaf(&name)?)
                .map_err(DatabaseError::from)?;
            if !owner_lock(&file)? {
                return Err(CatalogStoreError::UnrecordedLiveCatalogWork);
            }
            let identity = file_identity(&file.metadata().map_err(DatabaseError::from)?);
            let owner = SlotOwner {
                identity,
                directory,
                file,
                name,
                creator: Self::process()?,
            };
            owner.check()?;
            owner.file.sync_all().map_err(DatabaseError::from)?;
            owner
                .directory
                .directory
                .file()
                .sync_all()
                .map_err(DatabaseError::from)?;
            Ok(owner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (slot, id);
            Err(CatalogStoreError::UnsupportedTraversalOwnership)
        }
    }
}
