use std::fs;
use std::path::{Path, PathBuf};

use mb_core::{KeyMaterial, sector_root};
use rusqlite::{Connection, OptionalExtension, params};
use thiserror::Error;

use crate::SCHEMA_VERSION;

const CONTROL_DATABASE_ID: &[u8] = b"control.db";

#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("database I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("SQLCipher error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("the linked SQLite library is not SQLCipher")]
    SqlCipherUnavailable,
    #[error("SQLCipher page HMAC is disabled")]
    HmacDisabled,
    #[error("stored object failed root or length verification")]
    Integrity,
    #[error("object is not ready")]
    NotReady,
}

pub struct ControlStore {
    connection: Connection,
    path: PathBuf,
}

impl ControlStore {
    pub fn open(path: impl AsRef<Path>, keys: &KeyMaterial) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let connection = open_encrypted(path, &keys.database_key(CONTROL_DATABASE_ID))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value BLOB NOT NULL
             ) STRICT;
             CREATE TABLE IF NOT EXISTS protocol_records (
                kind TEXT NOT NULL,
                record_id BLOB NOT NULL,
                bytes BLOB NOT NULL,
                PRIMARY KEY (kind, record_id)
             ) STRICT;
             CREATE TABLE IF NOT EXISTS operations (
                operation_id BLOB PRIMARY KEY,
                kind TEXT NOT NULL,
                state TEXT NOT NULL,
                body BLOB NOT NULL
             ) STRICT;",
        )?;
        connection.execute(
            "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
             ON CONFLICT(key) DO NOTHING",
            [SCHEMA_VERSION.to_be_bytes().as_slice()],
        )?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn put_record(
        &mut self,
        kind: &str,
        record_id: &[u8],
        bytes: &[u8],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![kind, record_id, bytes],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn put_records(
        &mut self,
        records: &[(String, Vec<u8>, Vec<u8>)],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        {
            let mut statement = transaction.prepare_cached(
                "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
                 ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            )?;
            for (kind, record_id, bytes) in records {
                statement.execute(params![kind, record_id, bytes])?;
            }
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn get_record(
        &self,
        kind: &str,
        record_id: &[u8],
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.connection
            .query_row(
                "SELECT bytes FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![kind, record_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(DatabaseError::from)
    }

    pub fn put_operation_result(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        body: &[u8],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO operations(operation_id, kind, state, body)
             VALUES (?1, ?2, 'COMMITTED', ?3)
             ON CONFLICT(operation_id) DO NOTHING",
            params![operation_id.as_slice(), kind, body],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn operation_result(
        &self,
        operation_id: &[u8; 16],
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        self.connection
            .query_row(
                "SELECT body FROM operations
                 WHERE operation_id = ?1 AND state = 'COMMITTED'",
                [operation_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(DatabaseError::from)
    }

    pub fn cipher_integrity_check(&self) -> Result<(), DatabaseError> {
        cipher_integrity_check(&self.connection)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ParityObject {
    pub group_id: [u8; 32],
    pub shard_index: u8,
    pub root: [u8; 32],
    pub bytes: Vec<u8>,
}

pub struct ParityStore {
    connection: Connection,
    path: PathBuf,
}

impl ParityStore {
    pub fn open(
        path: impl AsRef<Path>,
        volume_id: &[u8; 16],
        keys: &KeyMaterial,
    ) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let mut database_id = b"parity.db/".to_vec();
        database_id.extend_from_slice(volume_id);
        let connection = open_encrypted(path, &keys.database_key(&database_id))?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS parity_objects (
                group_id BLOB NOT NULL CHECK(length(group_id) = 32),
                shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 3 AND 4),
                root BLOB NOT NULL CHECK(length(root) = 32),
                byte_length INTEGER NOT NULL CHECK(byte_length > 0),
                state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
                bytes BLOB NOT NULL,
                PRIMARY KEY(group_id, shard_index)
             ) STRICT;",
        )?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stage_and_publish(&mut self, object: &ParityObject) -> Result<(), DatabaseError> {
        if object.bytes.is_empty() || sector_root(&object.bytes) != object.root {
            return Err(DatabaseError::Integrity);
        }

        {
            let transaction = self.connection.transaction()?;
            transaction.execute(
                "INSERT INTO parity_objects(
                    group_id, shard_index, root, byte_length, state, bytes
                 ) VALUES (?1, ?2, ?3, ?4, 'STAGED', ?5)
                 ON CONFLICT(group_id, shard_index) DO UPDATE SET
                    root = excluded.root,
                    byte_length = excluded.byte_length,
                    state = 'STAGED',
                    bytes = excluded.bytes",
                params![
                    object.group_id.as_slice(),
                    object.shard_index,
                    object.root.as_slice(),
                    object.bytes.len() as i64,
                    object.bytes.as_slice(),
                ],
            )?;
            transaction.commit()?;
        }

        let staged = self.load_with_state(&object.group_id, object.shard_index, "STAGED")?;
        if staged.root != object.root || staged.bytes.len() != object.bytes.len() {
            return Err(DatabaseError::Integrity);
        }
        self.connection.execute(
            "UPDATE parity_objects SET state = 'READY'
             WHERE group_id = ?1 AND shard_index = ?2 AND state = 'STAGED'",
            params![object.group_id.as_slice(), object.shard_index],
        )?;
        Ok(())
    }

    pub fn load_ready(
        &self,
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<ParityObject, DatabaseError> {
        self.load_with_state(group_id, shard_index, "READY")
    }

    fn load_with_state(
        &self,
        group_id: &[u8; 32],
        shard_index: u8,
        state: &str,
    ) -> Result<ParityObject, DatabaseError> {
        let row = self
            .connection
            .query_row(
                "SELECT root, byte_length, bytes FROM parity_objects
                 WHERE group_id = ?1 AND shard_index = ?2 AND state = ?3",
                params![group_id.as_slice(), shard_index, state],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?
            .ok_or(DatabaseError::NotReady)?;
        let (root, byte_length, bytes) = row;
        let root: [u8; 32] = root.try_into().map_err(|_| DatabaseError::Integrity)?;
        if byte_length != bytes.len() as i64 || sector_root(&bytes) != root {
            return Err(DatabaseError::Integrity);
        }
        Ok(ParityObject {
            group_id: *group_id,
            shard_index,
            root,
            bytes,
        })
    }

    pub fn cipher_integrity_check(&self) -> Result<(), DatabaseError> {
        cipher_integrity_check(&self.connection)
    }
}

fn open_encrypted(path: &Path, key: &[u8; 32]) -> Result<Connection, DatabaseError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
        set_private_directory(parent)?;
    }
    let connection = Connection::open(path)?;
    connection.pragma_update(None, "key", hex::encode(key))?;
    connection.execute_batch(
        "PRAGMA cipher_compatibility = 4;
         PRAGMA cipher_use_hmac = ON;
         PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
         PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
         PRAGMA cipher_page_size = 4096;
         PRAGMA cipher_memory_security = ON;
         PRAGMA trusted_schema = OFF;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA secure_delete = ON;
         PRAGMA journal_mode = WAL;
         PRAGMA synchronous = FULL;
         PRAGMA wal_autocheckpoint = 1000;",
    )?;
    let cipher_version: Option<String> = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .optional()?;
    if cipher_version.as_deref().unwrap_or_default().is_empty() {
        return Err(DatabaseError::SqlCipherUnavailable);
    }
    let hmac: String = connection.query_row("PRAGMA cipher_use_hmac", [], |row| row.get(0))?;
    if hmac != "1" {
        return Err(DatabaseError::HmacDisabled);
    }
    connection.query_row("SELECT count(*) FROM sqlite_schema", [], |_| Ok(()))?;
    Ok(connection)
}

fn cipher_integrity_check(connection: &Connection) -> Result<(), DatabaseError> {
    let mut statement = connection.prepare("PRAGMA cipher_integrity_check")?;
    let failures = statement
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(DatabaseError::Integrity)
    }
}

#[cfg(unix)]
fn set_private_directory(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use mb_core::Seed;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn control_database_is_encrypted_and_reopens() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([1; 32]));
        {
            let mut store = ControlStore::open(&path, &keys).unwrap();
            store
                .put_record("test", b"id", b"plaintext-marker-should-not-leak")
                .unwrap();
            assert_eq!(
                store.get_record("test", b"id").unwrap().unwrap(),
                b"plaintext-marker-should-not-leak"
            );
            store.cipher_integrity_check().unwrap();
        }

        let mut raw = Vec::new();
        fs::File::open(&path)
            .unwrap()
            .read_to_end(&mut raw)
            .unwrap();
        assert!(!raw.starts_with(b"SQLite format 3"));
        assert!(
            !raw.windows(b"plaintext-marker-should-not-leak".len())
                .any(|window| window == b"plaintext-marker-should-not-leak")
        );

        let store = ControlStore::open(&path, &keys).unwrap();
        assert!(store.get_record("test", b"id").unwrap().is_some());
        let wrong = KeyMaterial::from_seed(&Seed::from_bytes([2; 32]));
        assert!(ControlStore::open(&path, &wrong).is_err());
    }

    #[test]
    fn parity_publication_verifies_before_ready() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([4; 32]));
        let mut store = ParityStore::open(temp.path().join("parity.db"), &[9; 16], &keys).unwrap();
        let bytes = vec![37; 64 * 1024];
        let object = ParityObject {
            group_id: [8; 32],
            shard_index: 3,
            root: sector_root(&bytes),
            bytes,
        };
        store.stage_and_publish(&object).unwrap();
        assert_eq!(store.load_ready(&[8; 32], 3).unwrap(), object);
        store.cipher_integrity_check().unwrap();

        let mut damaged = object;
        damaged.root[0] ^= 1;
        assert!(matches!(
            store.stage_and_publish(&damaged),
            Err(DatabaseError::Integrity)
        ));
    }
}
