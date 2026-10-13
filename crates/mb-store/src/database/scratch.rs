//! Disposable encrypted record indexes. SQLite opens the unnamed attached
//! database and rollback journals with DELETEONCLOSE; Unix unlinks them while
//! open, so a killed process cannot leave a large index awaiting application GC.

#[cfg(target_os = "linux")]
use super::scratch_space::ScratchVfs;
use rusqlite::{Connection, params};
use uuid::Uuid;

use super::{ControlStore, DatabaseError, DatabaseShellResult, ProtocolRecordRow};

/// Physical bounds for disposable indexes. Linux reserves actual filesystem
/// extents before writes, sharing admission across scratch jobs on the mount.
#[derive(Clone, Copy, Debug)]
pub struct ScratchStorageLimits {
    pub max_database_bytes: u64,
    pub max_physical_bytes: u64,
    pub headroom_bytes: u64,
}

impl ScratchStorageLimits {
    pub fn for_database(max_database_bytes: u64) -> Result<Self, DatabaseError> {
        Ok(Self {
            max_database_bytes,
            // Database, rollback/subjournals and rounded allocation tails.
            max_physical_bytes: max_database_bytes
                .checked_mul(3)
                .and_then(|bytes| bytes.checked_add(3 * 64 * 1024))
                .ok_or(DatabaseError::ScratchUnavailable)?,
            headroom_bytes: 32 * 1024 * 1024,
        })
    }
}

/// A private, nonpersistent record store with a 1 MiB page-cache budget and an
/// explicit database-size limit. This is not a durable catalog and cannot be
/// reopened. Linux additionally admits real database/journal allocations under
/// a shared mount lock and a physical budget, preserving configured headroom.
pub struct RecordScratchStore {
    records: ControlStore,
    // Field order closes the SQLite connection before unregistering its VFS.
    #[cfg(target_os = "linux")]
    _vfs: Option<ScratchVfs>,
}

impl RecordScratchStore {
    pub fn new(max_database_bytes: u64) -> Result<Self, DatabaseError> {
        #[cfg(target_os = "linux")]
        {
            Self::new_in(
                std::env::temp_dir(),
                ScratchStorageLimits::for_database(max_database_bytes)?,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            Self::open(max_database_bytes, Connection::open_in_memory()?)
        }
    }

    /// Pin the chosen workspace directory. Renaming or replacing its pathname
    /// cannot redirect subsequent SQLite files or free-space measurements.
    #[cfg(target_os = "linux")]
    pub fn new_in(
        directory: impl AsRef<std::path::Path>,
        limits: ScratchStorageLimits,
    ) -> Result<Self, DatabaseError> {
        Self::new_in_with_checkpoint_reservations(directory, limits, &[])
    }

    /// Include current checkpoint-copy space on every physical allocation.
    /// Each database parent is pinned so path renames cannot hide its WAL.
    #[cfg(target_os = "linux")]
    pub fn new_in_with_checkpoint_reservations(
        directory: impl AsRef<std::path::Path>,
        limits: ScratchStorageLimits,
        database_paths: &[std::path::PathBuf],
    ) -> Result<Self, DatabaseError> {
        let vfs = ScratchVfs::new(
            directory.as_ref(),
            limits.max_physical_bytes,
            limits.headroom_bytes,
            database_paths,
        )?;
        let connection = Connection::open_with_flags_and_vfs(
            ":memory:",
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
            vfs.name(),
        )?;
        Self::open(Some(vfs), limits.max_database_bytes, connection)
    }

    fn open(
        // Keep the VFS parameter before the connection: early errors drop
        // parameters in reverse order, closing SQLite before its borrowed VFS.
        #[cfg(target_os = "linux")] vfs: Option<ScratchVfs>,
        max_database_bytes: u64,
        connection: Connection,
    ) -> Result<Self, DatabaseError> {
        const PAGE_BYTES: u64 = 4096;
        let pages = max_database_bytes / PAGE_BYTES;
        if !(16..=u32::MAX as u64 - 1).contains(&pages) {
            return Err(DatabaseError::ScratchUnavailable);
        }
        let mut key = [0; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let connection = super::configure_encrypted_connection(connection, &key, false)?;
        let forced_memory: bool = connection.query_row(
            "SELECT sqlite_compileoption_used('TEMP_STORE=3')",
            [],
            |row| row.get(0),
        )?;
        if forced_memory {
            return Err(DatabaseError::ScratchUnavailable);
        }
        // Set this before opening the unnamed database: with TEMP_STORE=2 a
        // blank filename would otherwise silently select an in-memory pager.
        connection.pragma_update(None, "temp_store", "FILE")?;
        connection.execute(
            "ATTACH DATABASE '' AS scratch KEY ?1",
            params![hex::encode(key)],
        )?;
        // The attached pager is now fixed to file storage. Keep other SQLite
        // temporary structures in memory, as on the durable SQLCipher store;
        // bounded record queries use their primary index and need no sorter.
        connection.pragma_update(None, "temp_store", "MEMORY")?;
        let schema = Some("scratch");
        connection.pragma_update(schema, "cache_size", -1024)?;
        connection.pragma_update(schema, "cache_spill", true)?;
        connection.pragma_update(schema, "journal_mode", "DELETE")?;
        connection.pragma_update(schema, "synchronous", "OFF")?;
        connection.pragma_update(schema, "max_page_count", pages)?;
        let journal: String =
            connection.pragma_query_value(schema, "journal_mode", |row| row.get(0))?;
        let actual_pages: u64 =
            connection.pragma_query_value(schema, "max_page_count", |row| row.get(0))?;
        let page_size: String =
            connection.pragma_query_value(schema, "cipher_page_size", |row| row.get(0))?;
        let hmac: String =
            connection.pragma_query_value(schema, "cipher_use_hmac", |row| row.get(0))?;
        if journal != "delete"
            || actual_pages != pages
            || page_size != PAGE_BYTES.to_string()
            || hmac != "1"
        {
            return Err(DatabaseError::ScratchUnavailable);
        }
        connection.execute_batch(
            "CREATE TABLE scratch.protocol_records (
                kind TEXT NOT NULL, record_id BLOB NOT NULL, bytes BLOB NOT NULL,
                PRIMARY KEY(kind, record_id)
             ) STRICT;",
        )?;
        Ok(Self {
            records: ControlStore {
                connection,
                path: Default::default(),
                #[cfg(target_os = "linux")]
                directory: None,
            },
            #[cfg(target_os = "linux")]
            _vfs: vfs,
        })
    }

    /// Roll back a failed batch. An actual temporary-file I/O failure can
    /// invalidate SQLite's pager; discard this store and rebuild on retry.
    pub fn with_record_transaction<T, E: From<DatabaseError>>(
        &self,
        operation: impl FnOnce() -> Result<T, E>,
    ) -> Result<T, E> {
        self.records.with_record_transaction(operation)
    }

    pub fn put_record_if_absent(
        &self,
        kind: &str,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<bool, DatabaseError> {
        self.records.put_record_if_absent(kind, key, bytes)
    }

    pub fn get_record_bounded(
        &self,
        kind: &str,
        key: &[u8],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.records.get_record_bounded(kind, key, limit)
    }

    pub fn record_length(&self, kind: &str, key: &[u8]) -> Result<Option<usize>, DatabaseError> {
        self.records.record_length(kind, key)
    }

    pub fn next_record_metadata_bounded(
        &self,
        kind: &str,
        after: Option<&[u8]>,
        key_limit: usize,
    ) -> Result<Option<(Vec<u8>, usize)>, DatabaseError> {
        self.records
            .next_record_metadata_bounded(kind, after, key_limit)
    }

    pub fn next_record_bounded(
        &self,
        kind: &str,
        after: Option<&[u8]>,
        key_limit: usize,
        payload_limit: usize,
    ) -> Result<Option<ProtocolRecordRow>, DatabaseError> {
        self.records
            .next_record_bounded(kind, after, key_limit, payload_limit)
    }

    pub fn record_at_or_before_bounded(
        &self,
        kind: &str,
        lower: &[u8],
        upper: &[u8],
        key_limit: usize,
        payload_limit: usize,
    ) -> Result<Option<ProtocolRecordRow>, DatabaseError> {
        self.records
            .record_at_or_before_bounded(kind, lower, upper, key_limit, payload_limit)
    }

    pub fn for_each_record_bounded(
        &self,
        kind: &str,
        key_limit: usize,
        payload_limit: usize,
        visit: impl FnMut(&[u8], &[u8]) -> anyhow::Result<bool>,
    ) -> anyhow::Result<()> {
        self.records
            .for_each_record_bounded(kind, key_limit, payload_limit, visit)
    }

    pub fn replace_record_if_value(
        &self,
        kind: &str,
        key: &[u8],
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<(), DatabaseError> {
        self.records
            .replace_record_if_value(kind, key, expected, replacement)
    }

    pub fn delete_record_if_value(
        &self,
        kind: &str,
        key: &[u8],
        expected: &[u8],
    ) -> Result<(), DatabaseError> {
        self.records.delete_record_if_value(kind, key, expected)
    }

    /// Diagnostic/fault-injection access, with the same single-statement policy
    /// as the durable store shell. Ordinary consumers should use bounded APIs.
    pub fn database_shell_statement(
        &self,
        sql: &str,
        query_only: bool,
    ) -> Result<DatabaseShellResult, DatabaseError> {
        self.records.database_shell_statement(sql, query_only)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn scratch_owner_moves_between_threads_with_serialized_sql_and_final_cleanup() {
        use std::sync::{Arc, Mutex};
        let temp = tempfile::tempdir().unwrap();
        let store = RecordScratchStore::new_in(
            temp.path(),
            ScratchStorageLimits::for_database(4 << 20).unwrap(),
        )
        .unwrap();
        let shared = Arc::new(Mutex::new(store));
        for number in 0u32..4 {
            let shared = shared.clone();
            std::thread::spawn(move || {
                let store = shared.lock().unwrap();
                store
                    .put_record_if_absent("moved", &number.to_be_bytes(), &[number as u8; 65536])
                    .unwrap();
                assert_eq!(
                    store
                        .get_record_bounded("moved", &number.to_be_bytes(), 65536)
                        .unwrap()
                        .unwrap(),
                    vec![number as u8; 65536]
                );
            })
            .join()
            .unwrap();
        }
        let shared = Arc::try_unwrap(shared).ok().unwrap().into_inner().unwrap();
        std::thread::spawn(move || {
            let mut after = None;
            let mut count = 0;
            while let Some((key, bytes)) = shared
                .next_record_bounded("moved", after.as_deref(), 4, 65536)
                .unwrap()
            {
                assert_eq!(bytes, vec![count; 65536]);
                after = Some(key);
                count += 1;
            }
            assert_eq!(count, 4);
            drop(shared);
        })
        .join()
        .unwrap();
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[test]
    fn scratch_records_bound_reads_and_roll_back_conflicts_and_exhaustion() {
        assert!(RecordScratchStore::new(4096).is_err());
        assert!(RecordScratchStore::new(u64::MAX).is_err());
        let store = RecordScratchStore::new(128 * 1024).unwrap();
        assert!(
            store
                .put_record_if_absent("rows", b"a", b"original")
                .unwrap()
        );
        assert!(!store.put_record_if_absent("rows", b"a", b"other").unwrap());
        assert!(store.get_record_bounded("rows", b"a", 3).is_err());
        let result: Result<(), DatabaseError> = store.with_record_transaction(|| {
            store.replace_record_if_value("rows", b"a", b"original", b"changed")?;
            for index in 0u32..100 {
                if !store.put_record_if_absent("large", &index.to_be_bytes(), &[7; 8192])? {
                    return Err(DatabaseError::Conflict);
                }
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            store.get_record_bounded("rows", b"a", 8).unwrap().unwrap(),
            b"original"
        );
        assert!(
            store
                .next_record_bounded("large", None, 4, 8192)
                .unwrap()
                .is_none()
        );
        store.database_shell_statement("CREATE TEMP TRIGGER ignore_row BEFORE INSERT ON protocol_records WHEN NEW.kind = 'ignored' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
        let result: Result<(), DatabaseError> = store.with_record_transaction(|| {
            store.delete_record_if_value("rows", b"a", b"original")?;
            if !store.put_record_if_absent("ignored", b"a", b"bad")? {
                return Err(DatabaseError::Conflict);
            }
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(
            store.get_record_bounded("rows", b"a", 8).unwrap().unwrap(),
            b"original"
        );
    }
    #[cfg(target_os = "linux")]
    fn write_payloads(store: &RecordScratchStore, rows: u32) -> Result<(), DatabaseError> {
        store.with_record_transaction(|| {
            for index in 0..rows {
                if !store.put_record_if_absent("large", &index.to_be_bytes(), &[b'z'; 8192])? {
                    return Err(DatabaseError::Conflict);
                }
            }
            Ok(())
        })
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_physical_budget_and_headroom_fail_closed_and_allow_fresh_retry() {
        for fault in 0..2 {
            let temp = tempfile::tempdir().unwrap();
            let mut limits = ScratchStorageLimits::for_database(32 * 1024 * 1024).unwrap();
            if fault == 0 {
                limits.max_physical_bytes = 1024 * 1024;
            } else {
                limits.headroom_bytes = u64::MAX;
            }
            let store = RecordScratchStore::new_in(temp.path(), limits).unwrap();
            store
                .database_shell_statement("PRAGMA scratch.cache_size=-64", false)
                .unwrap();
            assert!(
                store
                    .put_record_if_absent("saved", b"key", b"original")
                    .unwrap()
            );
            let error = write_payloads(&store, 512).unwrap_err();
            assert!(
                matches!(error, DatabaseError::Sql(rusqlite::Error::SqliteFailure(error, _)) if error.code == rusqlite::ErrorCode::DiskFull),
                "fault {fault}: {error}"
            );
            // A failed temporary-file write can poison SQLite's private
            // pager. Discard it; consumers must never publish from this index.
            assert!(!matches!(
                store.next_record_bounded("large", None, 4, 8192),
                Ok(Some(_))
            ));
            drop(store);
            assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
            let retry = RecordScratchStore::new_in(
                temp.path(),
                ScratchStorageLimits::for_database(32 * 1024 * 1024).unwrap(),
            )
            .unwrap();
            write_payloads(&retry, 512).unwrap();
            let mut count = 0;
            retry
                .for_each_record_bounded("large", 4, 8192, |_, _| {
                    count += 1;
                    Ok(true)
                })
                .unwrap();
            assert_eq!(count, 512);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_pins_workspace_and_rechecks_growing_checkpoint_after_parent_rename() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let moved = temp.path().join("moved");
        std::fs::create_dir(&original).unwrap();
        let wal = std::fs::File::create(original.join("control.db-wal")).unwrap();
        let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        use std::os::fd::AsRawFd;
        assert_eq!(
            unsafe { libc::fstatvfs(wal.as_raw_fd(), space.as_mut_ptr()) },
            0
        );
        let space = unsafe { space.assume_init() };
        let available =
            u64::try_from(u128::from(space.f_bavail) * u128::from(space.f_frsize)).unwrap();
        let mut limits = ScratchStorageLimits::for_database(32 * 1024 * 1024).unwrap();
        limits.headroom_bytes = available.saturating_sub(128 * 1024 * 1024);
        let store = RecordScratchStore::new_in_with_checkpoint_reservations(
            &original,
            limits,
            &[original.join("control.db")],
        )
        .unwrap();
        let retry = RecordScratchStore::new_in_with_checkpoint_reservations(
            &original,
            ScratchStorageLimits::for_database(32 * 1024 * 1024).unwrap(),
            &[original.join("control.db")],
        )
        .unwrap();
        store
            .database_shell_statement("PRAGMA scratch.cache_size=-64", false)
            .unwrap();
        store
            .put_record_if_absent("saved", b"key", b"original")
            .unwrap();
        std::fs::rename(&original, &moved).unwrap();
        std::fs::create_dir(&original).unwrap();
        // The reservation grows after constructor admission and under the old
        // parent's new name. An empty replacement parent must not hide it.
        wal.set_len(256 * 1024 * 1024).unwrap();
        assert!(write_payloads(&store, 512).is_err());
        drop(store);
        wal.set_len(0).unwrap();
        write_payloads(&retry, 512).unwrap();
        let mut descriptors = 0;
        for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
            let path = entry.unwrap().path();
            let Ok(name) = std::fs::read_link(path) else {
                continue;
            };
            if name.starts_with(&moved) && name.to_string_lossy().ends_with(" (deleted)") {
                descriptors += 1;
            }
            assert!(
                !name.starts_with(&original),
                "replacement parent acquired a scratch file"
            );
        }
        assert!(descriptors > 0);
        assert_eq!(std::fs::read_dir(&original).unwrap().count(), 0);
        let link = temp.path().join("symlink");
        symlink(&moved, &link).unwrap();
        assert!(
            RecordScratchStore::new_in(
                &link,
                ScratchStorageLimits::for_database(1024 * 1024).unwrap()
            )
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn scratch_spills_encrypted_unlinked_files_and_reclaims_them_after_sigkill() {
        use std::io::{Read, Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        struct ChildGuard(Child);
        impl Drop for ChildGuard {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let mut child = ChildGuard(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "database::scratch::tests::scratch_lifecycle_child",
                    "--nocapture",
                ])
                .env("SQLITE_TMPDIR", temp.path())
                .env("MB_SCRATCH_LIFECYCLE_CHILD", temp.path())
                .stdout(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let ready = temp.path().join("ready");
        let deadline = Instant::now() + Duration::from_secs(30);
        while !ready.exists() {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "scratch child exited before spilling"
            );
            assert!(
                Instant::now() < deadline,
                "scratch child did not become ready"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let descriptor_dir = format!("/proc/{}/fd", child.0.id());
        let mut large_files = 0;
        for descriptor in std::fs::read_dir(&descriptor_dir).unwrap() {
            let descriptor = descriptor.unwrap().path();
            let Ok(name) = std::fs::read_link(&descriptor) else {
                continue;
            };
            if !name.starts_with(temp.path()) || !name.to_string_lossy().ends_with(" (deleted)") {
                continue;
            }
            let mut file = std::fs::File::open(&descriptor).unwrap();
            let metadata = file.metadata().unwrap();
            assert_eq!(metadata.nlink(), 0, "scratch file remains named");
            if metadata.len() < 4 * 1024 * 1024 {
                continue;
            }
            large_files += 1;
            assert!(metadata.blocks() > 0, "scratch did not spill to disk");
            for offset in [0, 4096, (metadata.len() / 2 / 4096) * 4096] {
                file.seek(SeekFrom::Start(offset)).unwrap();
                let mut page = [0; 4096];
                file.read_exact(&mut page).unwrap();
                assert_ne!(&page[..16], b"SQLite format 3\0");
                assert!(
                    !page
                        .windows(64)
                        .any(|bytes| bytes == [b'p'; 64] || bytes == [b'q'; 64]),
                    "scratch plaintext leaked"
                );
            }
        }
        assert!(
            large_files >= 2,
            "both database and rollback journal must spill encrypted pages"
        );
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
        child.0.kill().unwrap();
        assert!(!child.0.wait().unwrap().success());
        assert!(!std::path::Path::new(&descriptor_dir).exists());
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn scratch_btrfs_reserves_rewrite_space_and_reclaims_failed_jobs() {
        let root =
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").expect("provisioned Btrfs root");
        let temp = tempfile::tempdir_in(&root).unwrap();
        let store = RecordScratchStore::new_in(
            temp.path(),
            ScratchStorageLimits::for_database(64 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        write_payloads(&store, 1024).unwrap();
        let result: Result<(), DatabaseError> = store.with_record_transaction(|| {
            for index in 0u32..1024 {
                store.replace_record_if_value(
                    "large",
                    &index.to_be_bytes(),
                    &[b'z'; 8192],
                    &[b'y'; 8192],
                )?;
            }
            Err(DatabaseError::Conflict)
        });
        assert!(result.is_err());
        assert_eq!(
            store
                .get_record_bounded("large", &0u32.to_be_bytes(), 8192)
                .unwrap()
                .unwrap(),
            [b'z'; 8192]
        );
        store
            .with_record_transaction(|| -> Result<(), DatabaseError> {
                for index in 0u32..1024 {
                    store.replace_record_if_value(
                        "large",
                        &index.to_be_bytes(),
                        &[b'z'; 8192],
                        &[b'y'; 8192],
                    )?;
                }
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store
                .get_record_bounded("large", &0u32.to_be_bytes(), 8192)
                .unwrap()
                .unwrap(),
            [b'y'; 8192]
        );
        drop(store);
        let mut limits = ScratchStorageLimits::for_database(64 * 1024 * 1024).unwrap();
        limits.max_physical_bytes = 1024 * 1024;
        let store = RecordScratchStore::new_in(temp.path(), limits).unwrap();
        store
            .database_shell_statement("PRAGMA scratch.cache_size=-64", false)
            .unwrap();
        assert!(write_payloads(&store, 1024).is_err());
        drop(store);
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "invoked only by the scratch process-lifecycle test"]
    fn scratch_lifecycle_child() {
        let root =
            std::env::var_os("MB_SCRATCH_LIFECYCLE_CHILD").expect("parent-owned scratch directory");
        let store = RecordScratchStore::new_in(
            &root,
            ScratchStorageLimits::for_database(64 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        if std::env::var_os("MB_SCRATCH_ALLOCATION_LOCK_PROBE").is_some() {
            std::fs::write(std::path::Path::new(&root).join("started"), b"started").unwrap();
        }
        store
            .with_record_transaction(|| -> Result<(), DatabaseError> {
                for index in 0u32..256 {
                    assert!(store.put_record_if_absent(
                        "spill",
                        &index.to_be_bytes(),
                        &[b'p'; 32768]
                    )?);
                }
                Ok(())
            })
            .unwrap();
        store
            .with_record_transaction(|| -> Result<(), DatabaseError> {
                for index in 0u32..256 {
                    store.replace_record_if_value(
                        "spill",
                        &index.to_be_bytes(),
                        &[b'p'; 32768],
                        &[b'q'; 32768],
                    )?;
                }
                std::fs::write(std::path::Path::new(&root).join("ready"), b"ready")?;
                loop {
                    std::thread::park();
                }
            })
            .unwrap();
    }
}
