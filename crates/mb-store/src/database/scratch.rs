//! Disposable encrypted record indexes. SQLite opens the unnamed attached
//! database and rollback journals with DELETEONCLOSE; Unix unlinks them while
//! open, so a killed process cannot leave a large index awaiting application GC.

use rusqlite::{Connection, params};
use uuid::Uuid;

use super::{ControlStore, DatabaseError, DatabaseShellResult, ProtocolRecordRow};

/// A private, nonpersistent record store with a 1 MiB page-cache budget and an
/// explicit database-size limit. This is not a durable catalog and cannot be
/// reopened. The limit excludes bounded caches and rollback-journal disk space;
/// callers still need aggregate scratch-space admission for concurrent jobs.
pub struct RecordScratchStore {
    records: ControlStore,
}

impl RecordScratchStore {
    pub fn new(max_database_bytes: u64) -> Result<Self, DatabaseError> {
        const PAGE_BYTES: u64 = 4096;
        let pages = max_database_bytes / PAGE_BYTES;
        if !(16..=u32::MAX as u64 - 1).contains(&pages) {
            return Err(DatabaseError::ScratchUnavailable);
        }
        let mut key = [0; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        let connection =
            super::configure_encrypted_connection(Connection::open_in_memory()?, &key, false)?;
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
            },
        })
    }

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
    #[ignore = "invoked only by the scratch process-lifecycle test"]
    fn scratch_lifecycle_child() {
        let root =
            std::env::var_os("MB_SCRATCH_LIFECYCLE_CHILD").expect("parent-owned scratch directory");
        let store = RecordScratchStore::new(64 * 1024 * 1024).unwrap();
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
