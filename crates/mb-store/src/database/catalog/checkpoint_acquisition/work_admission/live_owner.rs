//! Process identity for disposable traversal scopes. Never open a second file
//! descriptor on the SQLite main file: closing it can release SQLite's POSIX
//! locks. Metadata and SQLITE_FCNTL_HAS_MOVED bind the current database instead.
use super::*;
#[cfg(target_os = "linux")]
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, Weak};

type ScopeKey = (u64, u64, Uuid);
static LIVE: Mutex<std::collections::BTreeMap<ScopeKey, Weak<()>>> =
    Mutex::new(std::collections::BTreeMap::new());
#[cfg(target_os = "linux")]
static INSTANCE: OnceLock<Uuid> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Owner {
    boot: Uuid,
    pid: u32,
    start: u64,
    instance: Uuid,
    device: u64,
    inode: u64,
}

impl Owner {
    pub(super) fn validate(self) -> Result<(), CatalogStoreError> {
        if self.boot.is_nil() || self.pid == 0 || self.instance.is_nil() || self.inode == 0 {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }

    fn key(self, id: Uuid) -> ScopeKey {
        (self.device, self.inode, id)
    }

    pub(super) fn register(self, id: Uuid) -> Result<Arc<()>, CatalogStoreError> {
        let mut live = LIVE.lock().map_err(|_| DatabaseError::Conflict)?;
        live.retain(|_, token| token.strong_count() != 0);
        let token = Arc::new(());
        match live.entry(self.key(id)) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Arc::downgrade(&token));
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                return Err(DatabaseError::Conflict.into());
            }
        }
        Ok(token)
    }

    pub(super) fn unregister(self, id: Uuid) {
        if let Ok(mut live) = LIVE.lock() {
            live.remove(&self.key(id));
        }
    }

    #[cfg(target_os = "linux")]
    pub(super) fn current(store: &ControlStore) -> Result<Self, CatalogStoreError> {
        let (device, inode) = database_identity(store)?;
        let bytes = bounded_file(std::path::Path::new("/proc/sys/kernel/random/boot_id"), 64)?;
        let boot = std::str::from_utf8(&bytes)
            .ok()
            .and_then(|text| Uuid::parse_str(text.trim()).ok())
            .ok_or(DatabaseError::Integrity)?;
        let pid = std::process::id();
        let (state, start) = process(pid)?.ok_or(DatabaseError::NotReady)?;
        if matches!(state, b'Z' | b'X') {
            return Err(DatabaseError::NotReady.into());
        }
        let owner = Self {
            boot,
            pid,
            start,
            instance: *INSTANCE.get_or_init(Uuid::new_v4),
            device,
            inode,
        };
        owner.validate()?;
        Ok(owner)
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn current(_: &ControlStore) -> Result<Self, CatalogStoreError> {
        Err(CatalogStoreError::UnsupportedTraversalOwnership)
    }

    pub(super) fn require_current(self, store: &ControlStore) -> Result<(), CatalogStoreError> {
        if self != Self::current(store)? {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(super) fn abandoned(self, id: Uuid, current: Self) -> Result<bool, CatalogStoreError> {
        // A copied catalog has independent credits. Its inherited scopes never
        // authorize work in the copy, even if the original process is alive.
        if (self.boot, self.device, self.inode) != (current.boot, current.device, current.inode) {
            return Ok(true);
        }
        if self.pid == current.pid {
            if (self.start, self.instance) != (current.start, current.instance) {
                return Ok(true);
            }
            let live = LIVE.lock().map_err(|_| DatabaseError::Conflict)?;
            return Ok(live
                .get(&self.key(id))
                .is_none_or(|token| token.upgrade().is_none()));
        }
        Ok(process(self.pid)?
            .is_none_or(|(state, start)| matches!(state, b'Z' | b'X') || start != self.start))
    }

    #[cfg(not(target_os = "linux"))]
    pub(super) fn abandoned(self, _: Uuid, _: Self) -> Result<bool, CatalogStoreError> {
        Err(CatalogStoreError::UnsupportedTraversalOwnership)
    }
}

#[cfg(target_os = "linux")]
fn database_identity(store: &ControlStore) -> Result<(u64, u64), CatalogStoreError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(&store.path).map_err(DatabaseError::from)?;
    let mut moved = 1_i32;
    // SAFETY: the public SQLite file-control API writes one int for this live
    // connection. No native file layout or private descriptor is inspected.
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
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(target_os = "linux")]
fn bounded_file(path: &std::path::Path, limit: u64) -> Result<Vec<u8>, DatabaseError> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(DatabaseError::Integrity);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn process(pid: u32) -> Result<Option<(u8, u64)>, CatalogStoreError> {
    let path = std::path::PathBuf::from(format!("/proc/{pid}/stat"));
    let bytes = match bounded_file(&path, 8192) {
        Ok(bytes) => bytes,
        Err(DatabaseError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let fields = bytes
        .rsplit(|byte| *byte == b')')
        .next()
        .ok_or(DatabaseError::Integrity)?;
    let mut fields = fields
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|s| !s.is_empty());
    let state = fields
        .next()
        .filter(|value| value.len() == 1)
        .ok_or(DatabaseError::Integrity)?[0];
    let start = fields
        .nth(18)
        .and_then(|value| std::str::from_utf8(value).ok())
        .and_then(|value| value.parse().ok())
        .ok_or(DatabaseError::Integrity)?;
    Ok(Some((state, start)))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    #[test]
    fn process_scopes_fence_reused_identity_and_copied_database_without_stealing_live_work() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let store = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        let owner = Owner::current(&store).unwrap();
        let id = Uuid::new_v4();
        let token = owner.register(id).unwrap();
        assert!(!owner.abandoned(id, owner).unwrap());
        let mut reused = owner;
        reused.start = owner.start.checked_add(1).unwrap();
        assert!(reused.abandoned(id, owner).unwrap());
        reused = owner;
        reused.instance = Uuid::new_v4();
        assert!(reused.abandoned(id, owner).unwrap());
        reused = owner;
        reused.boot = Uuid::new_v4();
        assert!(reused.abandoned(id, owner).unwrap());
        let copy = ControlStore::open_with_key(temp.path().join("copy.db"), &[7; 32]).unwrap();
        let copied = Owner::current(&copy).unwrap();
        assert!(owner.abandoned(id, copied).unwrap());
        assert!(owner.require_current(&copy).is_err());
        assert!(
            !owner
                .abandoned(id, Owner::current(&store).unwrap())
                .unwrap()
        );
        drop(token);
        assert!(owner.abandoned(id, owner).unwrap());
        owner.unregister(id);
    }
}
