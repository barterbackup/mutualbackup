use std::fs;
use std::path::{Path, PathBuf};

use mb_core::{KeyMaterial, V1_SECTOR_SIZE, sector_root};
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
    #[error("immutable database state conflicts with the requested write")]
    Conflict,
    #[error("database kind or schema version is incompatible")]
    IncompatibleSchema,
}

pub struct ControlStore {
    connection: Connection,
    path: PathBuf,
}

impl ControlStore {
    pub fn open(path: impl AsRef<Path>, keys: &KeyMaterial) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let mut connection = open_encrypted(path, &keys.database_key(CONTROL_DATABASE_ID))?;
        initialize_or_validate_control(&mut connection)?;
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
        caller: &[u8; 32],
        request_hash: &[u8; 32],
        body: &[u8],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT kind, caller, request_hash, body FROM operations
                 WHERE operation_id = ?1 AND state = 'COMMITTED'",
                [operation_id.as_slice()],
                operation_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if !existing.matches(kind, caller, request_hash, body) {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO operations(
                operation_id, kind, caller, request_hash, state, body
             ) VALUES (?1, ?2, ?3, ?4, 'COMMITTED', ?5)",
            params![
                operation_id.as_slice(),
                kind,
                caller.as_slice(),
                request_hash.as_slice(),
                body,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn operation_result(
        &self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: &[u8; 32],
        request_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        let existing = self
            .connection
            .query_row(
                "SELECT kind, caller, request_hash, body FROM operations
                 WHERE operation_id = ?1 AND state = 'COMMITTED'",
                [operation_id.as_slice()],
                operation_row,
            )
            .optional()?;
        match existing {
            Some(existing) if existing.matches_request(kind, caller, request_hash) => {
                Ok(Some(existing.body))
            }
            Some(_) => Err(DatabaseError::Conflict),
            None => Ok(None),
        }
    }

    pub fn locked_checkpoint(
        &self,
        guild_id: &[u8; 32],
    ) -> Result<Option<(u64, [u8; 32], Vec<u8>)>, DatabaseError> {
        checkpoint_row(&self.connection, "checkpoint_signature_locks", guild_id)
    }

    pub fn checkpoint_head(
        &self,
        guild_id: &[u8; 32],
    ) -> Result<Option<(u64, [u8; 32], Vec<u8>)>, DatabaseError> {
        checkpoint_row(&self.connection, "checkpoint_heads", guild_id)
    }

    pub fn lock_checkpoint_signature(
        &mut self,
        guild_id: &[u8; 32],
        generation: u64,
        parent: Option<&[u8; 32]>,
        checkpoint_hash: &[u8; 32],
        checkpoint_bytes: &[u8],
    ) -> Result<(), DatabaseError> {
        let generation_i64 = i64::try_from(generation).map_err(|_| DatabaseError::Integrity)?;
        let transaction = self.connection.transaction()?;
        let locked = checkpoint_row(&transaction, "checkpoint_signature_locks", guild_id)?;
        match locked {
            Some((stored_generation, stored_hash, stored_bytes))
                if stored_generation == generation
                    && stored_hash == *checkpoint_hash
                    && stored_bytes == checkpoint_bytes =>
            {
                transaction.commit()?;
                return Ok(());
            }
            Some((stored_generation, stored_hash, _))
                if stored_generation.checked_add(1) == Some(generation)
                    && parent == Some(&stored_hash) => {}
            Some(_) => return Err(DatabaseError::Conflict),
            None => {
                let head = checkpoint_row(&transaction, "checkpoint_heads", guild_id)?;
                match head {
                    Some((stored_generation, stored_hash, _))
                        if stored_generation.checked_add(1) == Some(generation)
                            && parent == Some(&stored_hash) => {}
                    Some(_) => return Err(DatabaseError::Conflict),
                    None if generation == 1 && parent.is_none() => {}
                    None => return Err(DatabaseError::Conflict),
                }
            }
        }
        transaction.execute(
            "INSERT INTO checkpoint_signature_locks(
                guild_id, generation, checkpoint_hash, checkpoint_bytes
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(guild_id) DO UPDATE SET
                generation = excluded.generation,
                checkpoint_hash = excluded.checkpoint_hash,
                checkpoint_bytes = excluded.checkpoint_bytes",
            params![
                guild_id.as_slice(),
                generation_i64,
                checkpoint_hash.as_slice(),
                checkpoint_bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_checkpoint(
        &mut self,
        guild_id: &[u8; 32],
        generation: u64,
        parent: Option<&[u8; 32]>,
        checkpoint_hash: &[u8; 32],
        checkpoint_body_bytes: &[u8],
        checkpoint_certificate_bytes: &[u8],
        require_signature_lock: bool,
    ) -> Result<(), DatabaseError> {
        let generation_i64 = i64::try_from(generation).map_err(|_| DatabaseError::Integrity)?;
        let transaction = self.connection.transaction()?;
        if require_signature_lock {
            let locked = checkpoint_row(&transaction, "checkpoint_signature_locks", guild_id)?;
            if !matches!(
                locked,
                Some((locked_generation, locked_hash, ref locked_bytes))
                    if locked_generation == generation
                        && locked_hash == *checkpoint_hash
                        && locked_bytes == checkpoint_body_bytes
            ) {
                return Err(DatabaseError::Conflict);
            }
        }
        let current = checkpoint_row(&transaction, "checkpoint_heads", guild_id)?;
        match current {
            Some((stored_generation, stored_hash, stored_bytes))
                if stored_generation == generation
                    && stored_hash == *checkpoint_hash
                    && stored_bytes == checkpoint_certificate_bytes =>
            {
                transaction.commit()?;
                return Ok(());
            }
            Some((stored_generation, stored_hash, _))
                if stored_generation.checked_add(1) == Some(generation)
                    && parent == Some(&stored_hash) => {}
            Some(_) => return Err(DatabaseError::Conflict),
            None if generation == 1 && parent.is_none() => {}
            None => return Err(DatabaseError::Conflict),
        }
        transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes)
             VALUES ('guild-checkpoint', ?1, ?2)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![checkpoint_hash.as_slice(), checkpoint_certificate_bytes],
        )?;
        transaction.execute(
            "INSERT INTO checkpoint_heads(
                guild_id, generation, checkpoint_hash, checkpoint_bytes
             ) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(guild_id) DO UPDATE SET
                generation = excluded.generation,
                checkpoint_hash = excluded.checkpoint_hash,
                checkpoint_bytes = excluded.checkpoint_bytes",
            params![
                guild_id.as_slice(),
                generation_i64,
                checkpoint_hash.as_slice(),
                checkpoint_certificate_bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn cipher_integrity_check(&self) -> Result<(), DatabaseError> {
        cipher_integrity_check(&self.connection)
    }
}

#[derive(Debug)]
struct OperationRow {
    kind: String,
    caller: Vec<u8>,
    request_hash: Vec<u8>,
    body: Vec<u8>,
}

impl OperationRow {
    fn matches_request(&self, kind: &str, caller: &[u8; 32], request_hash: &[u8; 32]) -> bool {
        self.kind == kind
            && self.caller.as_slice() == caller
            && self.request_hash.as_slice() == request_hash
    }

    fn matches(&self, kind: &str, caller: &[u8; 32], request_hash: &[u8; 32], body: &[u8]) -> bool {
        self.matches_request(kind, caller, request_hash) && self.body == body
    }
}

fn operation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRow> {
    Ok(OperationRow {
        kind: row.get(0)?,
        caller: row.get(1)?,
        request_hash: row.get(2)?,
        body: row.get(3)?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ParityObject {
    pub format_version: u16,
    pub guild_id: [u8; 32],
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
        let mut connection = open_encrypted(path, &keys.database_key(&database_id))?;
        initialize_or_validate_parity(&mut connection, volume_id)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn stage_and_publish(&mut self, object: &ParityObject) -> Result<(), DatabaseError> {
        if object.format_version != 1
            || object.bytes.len() != V1_SECTOR_SIZE
            || !(3..=4).contains(&object.shard_index)
            || sector_root(&object.bytes) != object.root
        {
            return Err(DatabaseError::Integrity);
        }

        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT format_version, guild_id, root, byte_length, state, bytes
                 FROM parity_objects WHERE group_id = ?1 AND shard_index = ?2",
                params![object.group_id.as_slice(), object.shard_index],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Vec<u8>>(5)?,
                    ))
                },
            )
            .optional()?;
        if let Some((format_version, guild_id, root, byte_length, state, bytes)) = existing {
            if format_version != i64::from(object.format_version)
                || guild_id.as_slice() != object.guild_id
                || root.as_slice() != object.root
                || byte_length != object.bytes.len() as i64
                || bytes != object.bytes
            {
                return Err(DatabaseError::Conflict);
            }
            if state == "STAGED" {
                transaction.execute(
                    "UPDATE parity_objects SET state = 'READY'
                     WHERE group_id = ?1 AND shard_index = ?2 AND state = 'STAGED'",
                    params![object.group_id.as_slice(), object.shard_index],
                )?;
            } else if state != "READY" {
                return Err(DatabaseError::Integrity);
            }
            transaction.commit()?;
            return Ok(());
        }

        transaction.execute(
            "INSERT INTO parity_objects(
                format_version, guild_id, group_id, shard_index, root,
                byte_length, state, bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'STAGED', ?7)",
            params![
                object.format_version,
                object.guild_id.as_slice(),
                object.group_id.as_slice(),
                object.shard_index,
                object.root.as_slice(),
                object.bytes.len() as i64,
                object.bytes.as_slice(),
            ],
        )?;
        let stored: (Vec<u8>, i64, Vec<u8>) = transaction.query_row(
            "SELECT root, byte_length, bytes FROM parity_objects
             WHERE group_id = ?1 AND shard_index = ?2 AND state = 'STAGED'",
            params![object.group_id.as_slice(), object.shard_index],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if stored.0.as_slice() != object.root
            || stored.1 != object.bytes.len() as i64
            || sector_root(&stored.2) != object.root
        {
            return Err(DatabaseError::Integrity);
        }
        transaction.execute(
            "UPDATE parity_objects SET state = 'READY'
             WHERE group_id = ?1 AND shard_index = ?2 AND state = 'STAGED'",
            params![object.group_id.as_slice(), object.shard_index],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn load_ready(
        &self,
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<ParityObject, DatabaseError> {
        let row = self
            .connection
            .query_row(
                "SELECT format_version, guild_id, root, byte_length, bytes
                 FROM parity_objects
                 WHERE group_id = ?1 AND shard_index = ?2 AND state = 'READY'",
                params![group_id.as_slice(), shard_index],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, Vec<u8>>(4)?,
                    ))
                },
            )
            .optional()?
            .ok_or(DatabaseError::NotReady)?;
        let format_version = u16::try_from(row.0).map_err(|_| DatabaseError::Integrity)?;
        let guild_id: [u8; 32] = row.1.try_into().map_err(|_| DatabaseError::Integrity)?;
        let root: [u8; 32] = row.2.try_into().map_err(|_| DatabaseError::Integrity)?;
        if format_version != 1
            || row.3 != row.4.len() as i64
            || row.4.len() != V1_SECTOR_SIZE
            || sector_root(&row.4) != root
        {
            return Err(DatabaseError::Integrity);
        }
        Ok(ParityObject {
            format_version,
            guild_id,
            group_id: *group_id,
            shard_index,
            root,
            bytes: row.4,
        })
    }

    pub fn cipher_integrity_check(&self) -> Result<(), DatabaseError> {
        cipher_integrity_check(&self.connection)
    }
}

fn initialize_or_validate_control(connection: &mut Connection) -> Result<(), DatabaseError> {
    if database_has_tables(connection)? {
        validate_database_identity(connection, b"control", None)?;
        require_tables(
            connection,
            &[
                "meta",
                "protocol_records",
                "operations",
                "checkpoint_signature_locks",
                "checkpoint_heads",
            ],
        )?;
        return Ok(());
    }
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
         ) STRICT;
         CREATE TABLE protocol_records (
            kind TEXT NOT NULL,
            record_id BLOB NOT NULL,
            bytes BLOB NOT NULL,
            PRIMARY KEY (kind, record_id)
         ) STRICT;
         CREATE TABLE operations (
            operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
            kind TEXT NOT NULL,
            caller BLOB NOT NULL CHECK(length(caller) = 32),
            request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
            state TEXT NOT NULL CHECK(state = 'COMMITTED'),
            body BLOB NOT NULL
         ) STRICT;
         CREATE TABLE checkpoint_signature_locks (
            guild_id BLOB PRIMARY KEY CHECK(length(guild_id) = 32),
            generation INTEGER NOT NULL CHECK(generation > 0),
            checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
            checkpoint_bytes BLOB NOT NULL
         ) STRICT;
         CREATE TABLE checkpoint_heads (
            guild_id BLOB PRIMARY KEY CHECK(length(guild_id) = 32),
            generation INTEGER NOT NULL CHECK(generation > 0),
            checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
            checkpoint_bytes BLOB NOT NULL
         ) STRICT;",
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('database_kind', ?1)",
        [b"control".as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_be_bytes().as_slice()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn initialize_or_validate_parity(
    connection: &mut Connection,
    volume_id: &[u8; 16],
) -> Result<(), DatabaseError> {
    if database_has_tables(connection)? {
        validate_database_identity(connection, b"parity", Some(volume_id))?;
        require_tables(connection, &["meta", "parity_objects"])?;
        return Ok(());
    }
    let transaction = connection.transaction()?;
    transaction.execute_batch(
        "CREATE TABLE meta (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
         ) STRICT;
         CREATE TABLE parity_objects (
            format_version INTEGER NOT NULL CHECK(format_version = 1),
            guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
            group_id BLOB NOT NULL CHECK(length(group_id) = 32),
            shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 3 AND 4),
            root BLOB NOT NULL CHECK(length(root) = 32),
            byte_length INTEGER NOT NULL CHECK(byte_length = 65536),
            state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
            bytes BLOB NOT NULL,
            PRIMARY KEY(group_id, shard_index)
         ) STRICT;",
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('database_kind', ?1)",
        [b"parity".as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
        [SCHEMA_VERSION.to_be_bytes().as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('volume_id', ?1)",
        [volume_id.as_slice()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn database_has_tables(connection: &Connection) -> Result<bool, DatabaseError> {
    Ok(connection.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
         )",
        [],
        |row| row.get(0),
    )?)
}

fn validate_database_identity(
    connection: &Connection,
    kind: &[u8],
    volume_id: Option<&[u8; 16]>,
) -> Result<(), DatabaseError> {
    let stored_kind = meta_value(connection, "database_kind")?;
    let stored_version = meta_value(connection, "schema_version")?;
    if stored_kind.as_deref() != Some(kind)
        || stored_version.as_deref() != Some(SCHEMA_VERSION.to_be_bytes().as_slice())
    {
        return Err(DatabaseError::IncompatibleSchema);
    }
    if let Some(expected) = volume_id
        && meta_value(connection, "volume_id")?.as_deref() != Some(expected.as_slice())
    {
        return Err(DatabaseError::IncompatibleSchema);
    }
    Ok(())
}

fn meta_value(connection: &Connection, key: &str) -> Result<Option<Vec<u8>>, DatabaseError> {
    Ok(connection
        .query_row("SELECT value FROM meta WHERE key = ?1", [key], |row| {
            row.get(0)
        })
        .optional()?)
}

fn require_tables(connection: &Connection, names: &[&str]) -> Result<(), DatabaseError> {
    for name in names {
        let present: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [name],
            |row| row.get(0),
        )?;
        if !present {
            return Err(DatabaseError::IncompatibleSchema);
        }
    }
    Ok(())
}

fn checkpoint_row(
    connection: &Connection,
    table: &'static str,
    guild_id: &[u8; 32],
) -> Result<Option<(u64, [u8; 32], Vec<u8>)>, DatabaseError> {
    let sql = format!(
        "SELECT generation, checkpoint_hash, checkpoint_bytes FROM {table} WHERE guild_id = ?1"
    );
    let row = connection
        .query_row(&sql, [guild_id.as_slice()], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        })
        .optional()?;
    let Some((generation, hash, bytes)) = row else {
        return Ok(None);
    };
    let generation = u64::try_from(generation).map_err(|_| DatabaseError::Integrity)?;
    let hash = hash.try_into().map_err(|_| DatabaseError::Integrity)?;
    Ok(Some((generation, hash, bytes)))
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
    fn parity_publication_is_immutable_and_verified() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([4; 32]));
        let mut store = ParityStore::open(temp.path().join("parity.db"), &[9; 16], &keys).unwrap();
        let bytes = vec![37; V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [7; 32],
            group_id: [8; 32],
            shard_index: 3,
            root: sector_root(&bytes),
            bytes,
        };
        store.stage_and_publish(&object).unwrap();
        store.stage_and_publish(&object).unwrap();
        assert_eq!(store.load_ready(&[8; 32], 3).unwrap(), object);
        store.cipher_integrity_check().unwrap();

        let mut replacement = object;
        replacement.bytes[0] ^= 1;
        replacement.root = sector_root(&replacement.bytes);
        assert!(matches!(
            store.stage_and_publish(&replacement),
            Err(DatabaseError::Conflict)
        ));
    }
}
