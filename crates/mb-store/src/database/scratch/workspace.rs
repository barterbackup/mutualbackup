//! Exclusively checked-out VFS owners. Idle workspaces retain their complete
//! initialized backing and ownership token; each checkout gets a fresh pager.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};

type Process = (u32, u64, u64);
type Slot = Arc<Mutex<Option<ScratchVfs>>>;

fn process() -> Result<Process, DatabaseError> {
    let namespace = std::fs::metadata("/proc/self/ns/pid")?;
    Ok((std::process::id(), namespace.dev(), namespace.ino()))
}

fn valid_database_size(bytes: u64) -> bool {
    (16..=u32::MAX as u64 - 1).contains(&(bytes / 4096))
}

/// One physically prepaid scratch slot, reusable across sequential indexes.
/// Clones refer to the same exclusive slot and do not allocate more backing or
/// credits. A live index keeps its backing/lease after every workspace handle
/// drops. Idle slots retain their complete physical reservation until dropped.
/// This does not make a checkpoint or authorize any source/metadata root.
#[derive(Clone)]
pub struct ScratchWorkspace {
    slot: Slot,
    maximum_database_bytes: u64,
    creator: Process,
}

impl ScratchWorkspace {
    pub fn new_in_with_reserved_checkpoint_space(
        directory: impl AsRef<std::path::Path>,
        limits: ScratchStorageLimits,
        database_paths: &[std::path::PathBuf],
        lease: crate::CatalogScratchLease,
    ) -> Result<Self, DatabaseError> {
        if !valid_database_size(limits.max_database_bytes) {
            return Err(DatabaseError::ScratchUnavailable);
        }
        let creator = process()?;
        let vfs = ScratchVfs::new_with_lease(
            directory.as_ref(),
            limits.max_physical_bytes,
            limits.headroom_bytes,
            database_paths,
            Some(lease),
        )?;
        vfs.check_reusable()?;
        Ok(Self {
            slot: Arc::new(Mutex::new(Some(vfs))),
            maximum_database_bytes: limits.max_database_bytes,
            creator,
        })
    }

    /// Open a fresh empty index, with its own database ceiling and encryption
    /// key, within this slot's prepaid maximum. Only one index may be live per
    /// slot. On an I/O/integrity failure the slot may retire instead of reusing
    /// unsafe allocator state; rebuild the enclosing job in that case.
    pub fn open(&self, max_database_bytes: u64) -> Result<RecordScratchStore, DatabaseError> {
        // A fork child must fail before touching a possibly inherited mutex.
        if process()? != self.creator
            || max_database_bytes > self.maximum_database_bytes
            || !valid_database_size(max_database_bytes)
        {
            return Err(DatabaseError::ScratchUnavailable);
        }
        let vfs = self
            .slot
            .lock()
            .map_err(|_| DatabaseError::ScratchUnavailable)?
            .take()
            .ok_or(DatabaseError::ScratchUnavailable)?;
        let owner = VfsOwner {
            vfs: Some(vfs),
            return_to: Some((self.slot.clone(), self.creator)),
        };
        owner.vfs()?.check_reusable()?;
        RecordScratchStore::open_vfs(owner, max_database_bytes)
    }
}

// Stored after the connection in RecordScratchStore, and passed before the
// connection into its constructor: close every SQLite file before returning
// the adapter. No Sync implementation is added to ScratchVfs; the mutex moves
// its existing Send owner exclusively between successive connections.
pub(super) struct VfsOwner {
    vfs: Option<ScratchVfs>,
    return_to: Option<(Slot, Process)>,
}
impl From<ScratchVfs> for VfsOwner {
    fn from(vfs: ScratchVfs) -> Self {
        Self {
            vfs: Some(vfs),
            return_to: None,
        }
    }
}
impl VfsOwner {
    fn vfs(&self) -> Result<&ScratchVfs, DatabaseError> {
        self.vfs.as_ref().ok_or(DatabaseError::ScratchUnavailable)
    }
}
impl Drop for VfsOwner {
    fn drop(&mut self) {
        let Some((slot, creator)) = &self.return_to else {
            return;
        };
        if process().ok() != Some(*creator) {
            return;
        }
        let Some(vfs) = self.vfs.take() else {
            return;
        };
        if vfs.check_reusable().is_err() {
            return;
        }
        if let Ok(mut slot) = slot.lock()
            && slot.is_none()
        {
            *slot = Some(vfs);
        }
    }
}

impl RecordScratchStore {
    pub(super) fn open_vfs(vfs: VfsOwner, maximum: u64) -> Result<Self, DatabaseError> {
        let connection = Connection::open_with_flags_and_vfs(
            ":memory:",
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs.vfs()?.name(),
        )?;
        Self::open(Some(vfs), maximum, connection)
    }
}
