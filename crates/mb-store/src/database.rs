use std::fs;
use std::path::{Path, PathBuf};

use mb_core::{
    KeyMaterial, V1_CATALOG_PAGE_BYTES, V1_MAX_CATALOG_BYTES, V1_MAX_CATALOG_PAGES, V1_SECTOR_SIZE,
    sector_root,
};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, OptionalExtension, params};
use thiserror::Error;

use crate::SCHEMA_VERSION;

const CONTROL_DATABASE_ID: &[u8] = b"control.db";
pub type CheckpointRow = (u64, [u8; 32], Vec<u8>);
pub type ProtocolRecordRow = (Vec<u8>, Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DatabaseShellResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
    pub affected_rows: Option<u64>,
}

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
    #[error("parity storage budget is exhausted")]
    CapacityExceeded,
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
        Self::open_with_key(path, &keys.database_key(CONTROL_DATABASE_ID))
    }

    pub fn open_with_key(
        path: impl AsRef<Path>,
        database_key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let mut connection = open_encrypted(path, database_key)?;
        initialize_or_validate_control(&mut connection)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn rekey(self, database_key: &[u8; 32]) -> Result<(), DatabaseError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        self.connection
            .pragma_update(None, "rekey", hex::encode(database_key))?;
        let path = self.path.clone();
        drop(self);
        verify_rekeyed_database(&path, database_key)
    }

    /// Prevent this connection from changing database state. This is useful
    /// for integrity inspection and for exercising genuinely read-only paths.
    pub fn make_query_only(&self) -> Result<(), DatabaseError> {
        self.connection.pragma_update(None, "query_only", true)?;
        Ok(())
    }

    pub fn database_shell_statement(
        &self,
        sql: &str,
        query_only: bool,
    ) -> Result<DatabaseShellResult, DatabaseError> {
        database_shell_statement(&self.connection, sql, query_only)
    }

    pub fn put_record(
        &self,
        kind: &str,
        record_id: &[u8],
        bytes: &[u8],
    ) -> Result<(), DatabaseError> {
        self.connection.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![kind, record_id, bytes],
        )?;
        Ok(())
    }

    pub fn put_record_if_absent(
        &self,
        kind: &str,
        record_id: &[u8],
        bytes: &[u8],
    ) -> Result<bool, DatabaseError> {
        Ok(self.connection.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO NOTHING",
            params![kind, record_id, bytes],
        )? == 1)
    }

    pub fn move_record_if_value(
        &self,
        kind: &str,
        old_record_id: &[u8],
        expected: &[u8],
        new_record_id: &[u8],
        replacement: &[u8],
    ) -> Result<(), DatabaseError> {
        if old_record_id == new_record_id {
            return Err(DatabaseError::Conflict);
        }
        let transaction = self.connection.unchecked_transaction()?;
        let inserted = transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO NOTHING",
            params![kind, new_record_id, replacement],
        )?;
        if inserted != 1 {
            return Err(DatabaseError::Conflict);
        }
        let removed = transaction.execute(
            "DELETE FROM protocol_records
             WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, old_record_id, expected],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn replace_record_if_value(
        &self,
        kind: &str,
        record_id: &[u8],
        expected: &[u8],
        replacement: &[u8],
    ) -> Result<(), DatabaseError> {
        let replaced = self.connection.execute(
            "UPDATE protocol_records SET bytes = ?4
             WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, record_id, expected, replacement],
        )?;
        if replaced != 1 {
            return Err(DatabaseError::Conflict);
        }
        Ok(())
    }

    pub fn replace_records_with_one(
        &self,
        kind: &str,
        old_records: &[(Vec<u8>, Vec<u8>)],
        new_record_id: &[u8],
        replacement: &[u8],
    ) -> Result<(), DatabaseError> {
        if old_records.is_empty()
            || old_records
                .iter()
                .any(|(record_id, _)| record_id.as_slice() == new_record_id)
        {
            return Err(DatabaseError::Conflict);
        }
        let transaction = self.connection.unchecked_transaction()?;
        let inserted = transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO NOTHING",
            params![kind, new_record_id, replacement],
        )?;
        if inserted != 1 {
            return Err(DatabaseError::Conflict);
        }
        for (record_id, expected) in old_records {
            let removed = transaction.execute(
                "DELETE FROM protocol_records
                 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![kind, record_id, expected],
            )?;
            if removed != 1 {
                return Err(DatabaseError::Conflict);
            }
        }
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

    pub fn move_protocol_record(
        &mut self,
        source_kind: &str,
        source_id: &[u8],
        expected: &[u8],
        destination_kind: &str,
        destination_id: &[u8],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![destination_kind, destination_id, expected],
        )?;
        let removed = transaction.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![source_kind, source_id, expected],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn reconcile_records(
        &mut self,
        kind: &str,
        delete_record_ids: &[Vec<u8>],
        replacements: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        {
            let mut delete = transaction.prepare_cached(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            )?;
            for record_id in delete_record_ids {
                delete.execute(params![kind, record_id])?;
            }
        }
        {
            let mut replace = transaction.prepare_cached(
                "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
                 ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            )?;
            for (record_id, bytes) in replacements {
                replace.execute(params![kind, record_id, bytes])?;
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

    pub fn delete_record(&self, kind: &str, record_id: &[u8]) -> Result<bool, DatabaseError> {
        Ok(self.connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            params![kind, record_id],
        )? == 1)
    }

    pub fn delete_record_if_value(
        &self,
        kind: &str,
        record_id: &[u8],
        expected: &[u8],
    ) -> Result<(), DatabaseError> {
        let removed = self.connection.execute(
            "DELETE FROM protocol_records
             WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, record_id, expected],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict);
        }
        Ok(())
    }

    pub fn abandon_capture_intent(
        &self,
        capture_id: &[u8; 16],
        expected_intent: &[u8],
    ) -> Result<(), DatabaseError> {
        let removed = self.connection.execute(
            "DELETE FROM protocol_records
             WHERE kind = 'capture-intent' AND record_id = ?1 AND bytes = ?2",
            params![capture_id.as_slice(), expected_intent],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict);
        }
        Ok(())
    }

    pub fn records(&self, kind: &str) -> Result<Vec<ProtocolRecordRow>, DatabaseError> {
        let mut statement = self.connection.prepare(
            "SELECT record_id, bytes FROM protocol_records WHERE kind = ?1 ORDER BY record_id",
        )?;
        let rows = statement.query_map([kind], |row| Ok((row.get(0)?, row.get(1)?)))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(DatabaseError::from)
    }

    pub fn finalize_capture_records(
        &mut self,
        capture_id: &[u8; 16],
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
        let removed = transaction.execute(
            "DELETE FROM protocol_records WHERE kind = 'capture-intent' AND record_id = ?1",
            [capture_id.as_slice()],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn finalize_recovery_anchor_records(
        &mut self,
        revision_id: &[u8; 16],
        expected_intent: &[u8],
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
        let removed = transaction.execute(
            "DELETE FROM protocol_records
             WHERE kind = 'recovery-anchor-intent' AND record_id = ?1 AND bytes = ?2",
            params![revision_id.as_slice(), expected_intent],
        )?;
        if removed != 1 {
            return Err(DatabaseError::Conflict);
        }
        transaction.commit()?;
        Ok(())
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
                "SELECT kind, caller, request_hash, state, body FROM operations
                 WHERE operation_id = ?1",
                [operation_id.as_slice()],
                operation_row,
            )
            .optional()?;
        if let Some(existing) = existing {
            if !existing.matches_request(kind, caller, request_hash)
                || (existing.state == "COMMITTED" && existing.body != body)
            {
                return Err(DatabaseError::Conflict);
            }
            if existing.state == "IN_PROGRESS" {
                transaction.execute(
                    "UPDATE operations SET state = 'COMMITTED', body = ?2
                     WHERE operation_id = ?1 AND state = 'IN_PROGRESS'",
                    params![operation_id.as_slice(), body],
                )?;
            }
            transaction.commit()?;
            return Ok(());
        }
        Err(DatabaseError::Conflict)
    }

    pub fn begin_operation(
        &mut self,
        operation_id: &[u8; 16],
        kind: &str,
        caller: &[u8; 32],
        request_hash: &[u8; 32],
    ) -> Result<Option<Vec<u8>>, DatabaseError> {
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT kind, caller, request_hash, state, body FROM operations
                 WHERE operation_id = ?1",
                [operation_id.as_slice()],
                operation_row,
            )
            .optional()?;
        let result = match existing {
            Some(existing) if existing.matches_request(kind, caller, request_hash) => {
                if existing.state == "COMMITTED" {
                    Some(existing.body)
                } else if existing.state == "IN_PROGRESS" {
                    None
                } else {
                    return Err(DatabaseError::Integrity);
                }
            }
            Some(_) => return Err(DatabaseError::Conflict),
            None => {
                transaction.execute(
                    "INSERT INTO operations(
                        operation_id, kind, caller, request_hash, state, body
                     ) VALUES (?1, ?2, ?3, ?4, 'IN_PROGRESS', x'')",
                    params![
                        operation_id.as_slice(),
                        kind,
                        caller.as_slice(),
                        request_hash.as_slice(),
                    ],
                )?;
                None
            }
        };
        transaction.commit()?;
        Ok(result)
    }

    pub fn clear_recomputable_operations(&mut self) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM operations WHERE kind = 'ensure-filler'", [])?;
        transaction.commit()?;
        Ok(())
    }

    pub fn locked_checkpoint(
        &self,
        guild_id: &[u8; 32],
    ) -> Result<Option<CheckpointRow>, DatabaseError> {
        checkpoint_row(&self.connection, "checkpoint_signature_locks", guild_id)
    }

    pub fn checkpoint_head(
        &self,
        guild_id: &[u8; 32],
    ) -> Result<Option<CheckpointRow>, DatabaseError> {
        checkpoint_row(&self.connection, "checkpoint_heads", guild_id)
    }

    pub fn checkpoint_head_certificates(&self) -> Result<Vec<Vec<u8>>, DatabaseError> {
        let mut statement = self
            .connection
            .prepare("SELECT checkpoint_bytes FROM checkpoint_heads ORDER BY guild_id")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(DatabaseError::from)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stage_recovery_shard(
        &mut self,
        checkpoint_hash: &[u8; 32],
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
        root: &[u8; 32],
        bytes: &[u8],
    ) -> Result<(), DatabaseError> {
        if shard_index > 4 || bytes.len() != V1_SECTOR_SIZE || sector_root(bytes) != *root {
            return Err(DatabaseError::Integrity);
        }
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT guild_id, root, bytes FROM recovery_shards
                 WHERE checkpoint_hash = ?1 AND group_id = ?2 AND shard_index = ?3",
                params![checkpoint_hash.as_slice(), group_id.as_slice(), shard_index],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, Vec<u8>>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        if let Some((stored_guild, stored_root, stored_bytes)) = existing {
            if stored_guild.as_slice() != guild_id
                || stored_root.as_slice() != root
                || stored_bytes != bytes
            {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO recovery_shards(
                checkpoint_hash, guild_id, group_id, shard_index, root, bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                checkpoint_hash.as_slice(),
                guild_id.as_slice(),
                group_id.as_slice(),
                shard_index,
                root.as_slice(),
                bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn recovery_shard(
        &self,
        checkpoint_hash: &[u8; 32],
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
        root: &[u8; 32],
    ) -> Result<Vec<u8>, DatabaseError> {
        let row = self
            .connection
            .query_row(
                "SELECT bytes FROM recovery_shards
                 WHERE checkpoint_hash = ?1 AND guild_id = ?2
                   AND group_id = ?3 AND shard_index = ?4 AND root = ?5",
                params![
                    checkpoint_hash.as_slice(),
                    guild_id.as_slice(),
                    group_id.as_slice(),
                    shard_index,
                    root.as_slice(),
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(DatabaseError::NotReady)?;
        if row.len() != V1_SECTOR_SIZE || sector_root(&row) != *root {
            return Err(DatabaseError::Integrity);
        }
        Ok(row)
    }

    pub fn clear_recovery_shards(
        &mut self,
        checkpoint_hash: &[u8; 32],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM recovery_shards WHERE checkpoint_hash = ?1",
            [checkpoint_hash.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn pin_recovery_attempt(
        &mut self,
        checkpoint_hash: &[u8; 32],
        attempt: &[u8],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes)
             VALUES ('recovery-attempt', ?1, ?2)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![b"active".as_slice(), attempt],
        )?;
        transaction.execute(
            "DELETE FROM recovery_shards WHERE checkpoint_hash <> ?1",
            [checkpoint_hash.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM protocol_records
             WHERE kind = 'recovery-job' AND record_id <> ?1",
            [checkpoint_hash.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn pin_recovery_attempt_and_reconcile_records(
        &mut self,
        checkpoint_hash: &[u8; 32],
        attempt: &[u8],
        kind: &str,
        delete_record_ids: &[Vec<u8>],
        replacements: &[(Vec<u8>, Vec<u8>)],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        {
            let mut delete = transaction.prepare_cached(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
            )?;
            for record_id in delete_record_ids {
                delete.execute(params![kind, record_id])?;
            }
        }
        {
            let mut replace = transaction.prepare_cached(
                "INSERT INTO protocol_records(kind, record_id, bytes) VALUES (?1, ?2, ?3)
                 ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            )?;
            for (record_id, bytes) in replacements {
                replace.execute(params![kind, record_id, bytes])?;
            }
        }
        transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes)
             VALUES ('recovery-attempt', ?1, ?2)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![b"active".as_slice(), attempt],
        )?;
        transaction.execute(
            "DELETE FROM recovery_shards WHERE checkpoint_hash <> ?1",
            [checkpoint_hash.as_slice()],
        )?;
        transaction.execute(
            "DELETE FROM protocol_records
             WHERE kind = 'recovery-job' AND record_id <> ?1",
            [checkpoint_hash.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn complete_recovery_attempt(
        &mut self,
        checkpoint_hash: &[u8; 32],
        job: &[u8],
    ) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "INSERT INTO protocol_records(kind, record_id, bytes)
             VALUES ('recovery-job', ?1, ?2)
             ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
            params![checkpoint_hash.as_slice(), job],
        )?;
        transaction.execute(
            "DELETE FROM protocol_records
             WHERE kind = 'recovery-attempt' AND record_id = ?1",
            [b"active".as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn stage_checkpoint_page(
        &mut self,
        object_kind: &str,
        guild_id: &[u8; 32],
        object_id: &[u8; 32],
        page_index: u32,
        total_pages: u32,
        page_hash: &[u8; 32],
        bytes: &[u8],
    ) -> Result<(), DatabaseError> {
        if !matches!(object_kind, "body" | "certificate")
            || total_pages == 0
            || total_pages > V1_MAX_CATALOG_PAGES
            || page_index >= total_pages
            || bytes.is_empty()
            || bytes.len() > V1_CATALOG_PAGE_BYTES
            || blake3::hash(bytes).as_bytes() != page_hash
        {
            return Err(DatabaseError::Integrity);
        }
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT guild_id, total_pages, page_hash, bytes
                 FROM checkpoint_pages
                 WHERE object_kind = ?1 AND object_id = ?2 AND page_index = ?3",
                params![object_kind, object_id.as_slice(), page_index],
                |row| {
                    Ok((
                        row.get::<_, Vec<u8>>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, Vec<u8>>(2)?,
                        row.get::<_, Vec<u8>>(3)?,
                    ))
                },
            )
            .optional()?;
        if let Some((stored_guild, stored_total, stored_hash, stored_bytes)) = existing {
            if stored_guild.as_slice() != guild_id
                || stored_total != i64::from(total_pages)
                || stored_hash.as_slice() != page_hash
                || stored_bytes != bytes
            {
                return Err(DatabaseError::Conflict);
            }
            transaction.commit()?;
            return Ok(());
        }
        transaction.execute(
            "INSERT INTO checkpoint_pages(
                object_kind, guild_id, object_id, page_index, total_pages, page_hash, bytes
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                object_kind,
                guild_id.as_slice(),
                object_id.as_slice(),
                page_index,
                total_pages,
                page_hash.as_slice(),
                bytes,
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn assembled_checkpoint_object(
        &self,
        object_kind: &str,
        guild_id: &[u8; 32],
        object_id: &[u8; 32],
    ) -> Result<Vec<u8>, DatabaseError> {
        if !matches!(object_kind, "body" | "certificate") {
            return Err(DatabaseError::Integrity);
        }
        let mut statement = self.connection.prepare(
            "SELECT page_index, total_pages, page_hash, bytes
             FROM checkpoint_pages
             WHERE object_kind = ?1 AND guild_id = ?2 AND object_id = ?3
             ORDER BY page_index",
        )?;
        let mut pages = statement.query_map(
            params![object_kind, guild_id.as_slice(), object_id.as_slice()],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            },
        )?;
        let mut assembled = Vec::new();
        let mut expected_total = None;
        let mut page_count = 0_usize;
        for (expected, page) in pages.by_ref().enumerate() {
            let (index, page_total, hash, bytes) = page?;
            let total = *expected_total.get_or_insert(page_total);
            if index != expected as i64
                || page_total != total
                || total <= 0
                || total > i64::from(V1_MAX_CATALOG_PAGES)
                || hash.len() != 32
                || bytes.is_empty()
                || bytes.len() > V1_CATALOG_PAGE_BYTES
                || blake3::hash(&bytes).as_bytes() != hash.as_slice()
                || assembled.len().saturating_add(bytes.len()) > V1_MAX_CATALOG_BYTES
            {
                return Err(DatabaseError::Integrity);
            }
            assembled.extend_from_slice(&bytes);
            page_count += 1;
        }
        let total = expected_total.ok_or(DatabaseError::NotReady)?;
        if page_count != total as usize {
            return Err(DatabaseError::NotReady);
        }
        Ok(assembled)
    }

    pub fn clear_checkpoint_pages(&mut self, object_id: &[u8; 32]) -> Result<(), DatabaseError> {
        let transaction = self.connection.transaction()?;
        transaction.execute(
            "DELETE FROM checkpoint_pages WHERE object_id = ?1",
            [object_id.as_slice()],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn protocol_record_page(
        &self,
        kind: &str,
        record_id: &[u8],
        page_index: u32,
    ) -> Result<(u32, Vec<u8>), DatabaseError> {
        let byte_length: i64 = self
            .connection
            .query_row(
                "SELECT length(bytes) FROM protocol_records WHERE kind = ?1 AND record_id = ?2",
                params![kind, record_id],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(DatabaseError::NotReady)?;
        let byte_length = usize::try_from(byte_length).map_err(|_| DatabaseError::Integrity)?;
        if byte_length > V1_MAX_CATALOG_BYTES {
            return Err(DatabaseError::Integrity);
        }
        let total_pages = byte_length.div_ceil(V1_CATALOG_PAGE_BYTES);
        if total_pages == 0
            || total_pages > V1_MAX_CATALOG_PAGES as usize
            || page_index as usize >= total_pages
        {
            return Err(DatabaseError::Integrity);
        }
        let offset = (page_index as usize)
            .checked_mul(V1_CATALOG_PAGE_BYTES)
            .ok_or(DatabaseError::Integrity)?;
        let bytes = self.connection.query_row(
            "SELECT substr(bytes, ?3, ?4) FROM protocol_records
             WHERE kind = ?1 AND record_id = ?2",
            params![
                kind,
                record_id,
                i64::try_from(offset + 1).map_err(|_| DatabaseError::Integrity)?,
                V1_CATALOG_PAGE_BYTES as i64,
            ],
            |row| row.get::<_, Vec<u8>>(0),
        )?;
        Ok((total_pages as u32, bytes))
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
        let head = checkpoint_row(&transaction, "checkpoint_heads", guild_id)?;
        match &locked {
            Some((stored_generation, stored_hash, stored_bytes))
                if *stored_generation == generation
                    && *stored_hash == *checkpoint_hash
                    && stored_bytes == checkpoint_bytes =>
            {
                transaction.commit()?;
                return Ok(());
            }
            Some((locked_generation, locked_hash, _))
                if !matches!(
                    &head,
                    Some((head_generation, head_hash, _))
                        if (*head_generation == *locked_generation && *head_hash == *locked_hash)
                            || *head_generation > *locked_generation
                ) =>
            {
                return Err(DatabaseError::Conflict);
            }
            _ => {}
        }
        match head {
            Some((stored_generation, stored_hash, _))
                if stored_generation.checked_add(1) == Some(generation)
                    && parent == Some(&stored_hash) => {}
            Some(_) => return Err(DatabaseError::Conflict),
            None if locked.is_none() && generation == 1 && parent.is_none() => {}
            None => return Err(DatabaseError::Conflict),
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
                if !require_signature_lock {
                    upsert_checkpoint_signature_lock(
                        &transaction,
                        guild_id,
                        generation_i64,
                        checkpoint_hash,
                        checkpoint_body_bytes,
                    )?;
                }
                transaction.commit()?;
                return Ok(());
            }
            Some((stored_generation, stored_hash, _))
                if stored_generation.checked_add(1) == Some(generation)
                    && parent == Some(&stored_hash) => {}
            Some(_) => return Err(DatabaseError::Conflict),
            None if generation == 1 && parent.is_none() => {}
            None if !require_signature_lock => {}
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
        if !require_signature_lock {
            upsert_checkpoint_signature_lock(
                &transaction,
                guild_id,
                generation_i64,
                checkpoint_hash,
                checkpoint_body_bytes,
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn commit_recovered_checkpoint(
        &mut self,
        guild_id: &[u8; 32],
        generation: u64,
        parent: Option<&[u8; 32]>,
        checkpoint_hash: &[u8; 32],
        checkpoint_body_bytes: &[u8],
        checkpoint_certificate_bytes: &[u8],
        local_revision_head: Option<&[u8]>,
        complete_recovery_attempt: bool,
    ) -> Result<(), DatabaseError> {
        let generation_i64 = i64::try_from(generation).map_err(|_| DatabaseError::Integrity)?;
        let transaction = self.connection.transaction()?;
        let current = checkpoint_row(&transaction, "checkpoint_heads", guild_id)?;
        match current {
            Some((stored_generation, stored_hash, stored_bytes))
                if stored_generation == generation
                    && stored_hash == *checkpoint_hash
                    && stored_bytes == checkpoint_certificate_bytes => {}
            Some((stored_generation, stored_hash, _))
                if stored_generation.checked_add(1) == Some(generation)
                    && parent == Some(&stored_hash) => {}
            Some(_) => return Err(DatabaseError::Conflict),
            None if generation == 1 && parent.is_none() => {}
            None => {}
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
        upsert_checkpoint_signature_lock(
            &transaction,
            guild_id,
            generation_i64,
            checkpoint_hash,
            checkpoint_body_bytes,
        )?;
        match local_revision_head {
            Some(revision) => {
                transaction.execute(
                    "INSERT INTO protocol_records(kind, record_id, bytes)
                     VALUES ('user-revision-head', ?1, ?2)
                     ON CONFLICT(kind, record_id) DO UPDATE SET bytes = excluded.bytes",
                    params![guild_id.as_slice(), revision],
                )?;
            }
            None => {
                transaction.execute(
                    "DELETE FROM protocol_records
                     WHERE kind = 'user-revision-head' AND record_id = ?1",
                    [guild_id.as_slice()],
                )?;
            }
        }
        transaction.execute(
            "DELETE FROM recovery_shards WHERE checkpoint_hash = ?1",
            [checkpoint_hash.as_slice()],
        )?;
        if complete_recovery_attempt {
            transaction.execute(
                "DELETE FROM protocol_records
                 WHERE kind = 'recovery-attempt' AND record_id = ?1",
                [b"active".as_slice()],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn cipher_integrity_check(&self) -> Result<(), DatabaseError> {
        cipher_integrity_check(&self.connection)
    }
}

fn upsert_checkpoint_signature_lock(
    transaction: &rusqlite::Transaction<'_>,
    guild_id: &[u8; 32],
    generation: i64,
    checkpoint_hash: &[u8; 32],
    checkpoint_body_bytes: &[u8],
) -> Result<(), rusqlite::Error> {
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
            generation,
            checkpoint_hash.as_slice(),
            checkpoint_body_bytes,
        ],
    )?;
    Ok(())
}

#[derive(Debug)]
struct OperationRow {
    kind: String,
    caller: Vec<u8>,
    request_hash: Vec<u8>,
    state: String,
    body: Vec<u8>,
}

impl OperationRow {
    fn matches_request(&self, kind: &str, caller: &[u8; 32], request_hash: &[u8; 32]) -> bool {
        self.kind == kind
            && self.caller.as_slice() == caller
            && self.request_hash.as_slice() == request_hash
    }
}

fn operation_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<OperationRow> {
    Ok(OperationRow {
        kind: row.get(0)?,
        caller: row.get(1)?,
        request_hash: row.get(2)?,
        state: row.get(3)?,
        body: row.get(4)?,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParityScrubReport {
    pub checked_objects: usize,
    pub checked_bytes: u64,
    pub corrupt_objects: Vec<([u8; 32], u8)>,
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
        Self::open_with_key(path, volume_id, &keys.database_key(&database_id))
    }

    pub fn open_with_key(
        path: impl AsRef<Path>,
        volume_id: &[u8; 16],
        database_key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let mut connection = open_encrypted(path, database_key)?;
        initialize_or_validate_parity(&mut connection, volume_id)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn open_existing_with_key(
        path: impl AsRef<Path>,
        volume_id: &[u8; 16],
        database_key: &[u8; 32],
    ) -> Result<Self, DatabaseError> {
        let path = path.as_ref();
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(DatabaseError::Integrity);
        }
        let mut connection = open_encrypted_existing(path, database_key)?;
        if !database_has_tables(&connection)? {
            return Err(DatabaseError::Integrity);
        }
        initialize_or_validate_parity(&mut connection, volume_id)?;
        Ok(Self {
            connection,
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn rekey(self, database_key: &[u8; 32]) -> Result<(), DatabaseError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        self.connection
            .pragma_update(None, "rekey", hex::encode(database_key))?;
        let path = self.path.clone();
        drop(self);
        verify_rekeyed_database(&path, database_key)
    }

    pub fn database_shell_statement(
        &self,
        sql: &str,
        query_only: bool,
    ) -> Result<DatabaseShellResult, DatabaseError> {
        database_shell_statement(&self.connection, sql, query_only)
    }

    pub fn used_bytes(&self) -> Result<u64, DatabaseError> {
        let used: i64 = self.connection.query_row(
            "SELECT coalesce(sum(byte_length), 0) FROM parity_objects
             WHERE state IN ('STAGED', 'READY')",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(used).map_err(|_| DatabaseError::Integrity)
    }

    pub fn ready_object_count(&self) -> Result<u64, DatabaseError> {
        let count: i64 = self.connection.query_row(
            "SELECT count(*) FROM parity_objects WHERE state = 'READY'",
            [],
            |row| row.get(0),
        )?;
        u64::try_from(count).map_err(|_| DatabaseError::Integrity)
    }

    pub fn first_ready_object(&self) -> Result<Option<ParityObject>, DatabaseError> {
        let identity = self
            .connection
            .query_row(
                "SELECT group_id, shard_index FROM parity_objects
                 WHERE state = 'READY' ORDER BY group_id, shard_index LIMIT 1",
                [],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?;
        let Some((group_id, shard_index)) = identity else {
            return Ok(None);
        };
        let group_id: [u8; 32] = group_id.try_into().map_err(|_| DatabaseError::Integrity)?;
        let shard_index = u8::try_from(shard_index).map_err(|_| DatabaseError::Integrity)?;
        self.load_ready(&group_id, shard_index).map(Some)
    }

    pub fn allocated_bytes(&self) -> Result<u64, DatabaseError> {
        ["", "-wal", "-shm"]
            .into_iter()
            .try_fold(0_u64, |total, suffix| {
                let mut path = self.path.as_os_str().to_os_string();
                path.push(suffix);
                match fs::metadata(PathBuf::from(path)) {
                    Ok(metadata) => total
                        .checked_add(allocated_file_bytes(&metadata))
                        .ok_or(DatabaseError::Integrity),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(total),
                    Err(error) => Err(error.into()),
                }
            })
    }

    pub fn reclaim_space(&self) -> Result<(), DatabaseError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let mode: i64 = self
            .connection
            .pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
        if mode == 2 {
            self.connection
                .execute_batch("PRAGMA incremental_vacuum;")?;
        } else {
            self.connection.execute_batch("VACUUM;")?;
        }
        Ok(())
    }

    fn reclaim_deleted_pages(&self) -> Result<(), DatabaseError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;
        let mode: i64 = self
            .connection
            .pragma_query_value(None, "auto_vacuum", |row| row.get(0))?;
        if mode == 2 {
            self.connection
                .execute_batch("PRAGMA incremental_vacuum;")?;
        }
        Ok(())
    }

    pub fn ready_objects(&self) -> Result<Vec<ParityObject>, DatabaseError> {
        let mut statement = self.connection.prepare(
            "SELECT format_version, guild_id, group_id, shard_index, root,
                    byte_length, bytes
             FROM parity_objects WHERE state = 'READY'
             ORDER BY group_id, shard_index",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, Vec<u8>>(6)?,
            ))
        })?;
        let mut objects = Vec::new();
        for row in rows {
            let (format_version, guild_id, group_id, shard_index, root, byte_length, bytes) = row?;
            let object = ParityObject {
                format_version: u16::try_from(format_version)
                    .map_err(|_| DatabaseError::Integrity)?,
                guild_id: guild_id.try_into().map_err(|_| DatabaseError::Integrity)?,
                group_id: group_id.try_into().map_err(|_| DatabaseError::Integrity)?,
                shard_index: u8::try_from(shard_index).map_err(|_| DatabaseError::Integrity)?,
                root: root.try_into().map_err(|_| DatabaseError::Integrity)?,
                bytes,
            };
            if object.format_version != 1
                || object.shard_index > 4
                || byte_length != object.bytes.len() as i64
                || object.bytes.len() != V1_SECTOR_SIZE
                || sector_root(&object.bytes) != object.root
            {
                return Err(DatabaseError::Integrity);
            }
            objects.push(object);
        }
        Ok(objects)
    }

    pub fn scrub(&self) -> Result<ParityScrubReport, DatabaseError> {
        self.cipher_integrity_check()?;
        let mut statement = self.connection.prepare(
            "SELECT group_id, shard_index, root, byte_length, bytes
             FROM parity_objects WHERE state = 'READY'
             ORDER BY group_id, shard_index",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Vec<u8>>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, Vec<u8>>(4)?,
            ))
        })?;
        let mut report = ParityScrubReport {
            checked_objects: 0,
            checked_bytes: 0,
            corrupt_objects: Vec::new(),
        };
        for row in rows {
            let (group_id, shard_index, root, byte_length, bytes) = row?;
            let group_id: [u8; 32] = group_id.try_into().map_err(|_| DatabaseError::Integrity)?;
            let shard_index = u8::try_from(shard_index).map_err(|_| DatabaseError::Integrity)?;
            let root: [u8; 32] = root.try_into().map_err(|_| DatabaseError::Integrity)?;
            report.checked_objects += 1;
            report.checked_bytes = report
                .checked_bytes
                .checked_add(bytes.len() as u64)
                .ok_or(DatabaseError::Integrity)?;
            if shard_index > 4
                || byte_length != bytes.len() as i64
                || bytes.len() != V1_SECTOR_SIZE
                || sector_root(&bytes) != root
            {
                report.corrupt_objects.push((group_id, shard_index));
            }
        }
        Ok(report)
    }

    pub fn remove_ready(
        &mut self,
        group_id: &[u8; 32],
        shard_index: u8,
        expected_root: &[u8; 32],
    ) -> Result<bool, DatabaseError> {
        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT root, state FROM parity_objects
                 WHERE group_id = ?1 AND shard_index = ?2",
                params![group_id.as_slice(), shard_index],
                |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?)),
            )
            .optional()?;
        let Some((root, state)) = existing else {
            transaction.commit()?;
            return Ok(false);
        };
        if root.as_slice() != expected_root || state != "READY" {
            return Err(DatabaseError::Conflict);
        }
        transaction.execute(
            "DELETE FROM parity_objects WHERE group_id = ?1 AND shard_index = ?2",
            params![group_id.as_slice(), shard_index],
        )?;
        transaction.commit()?;
        self.reclaim_deleted_pages()?;
        Ok(true)
    }

    pub fn stage_and_publish(&mut self, object: &ParityObject) -> Result<(), DatabaseError> {
        self.stage_and_publish_ack(object, &[], u64::MAX)
    }

    pub fn stage_and_publish_ack(
        &mut self,
        object: &ParityObject,
        acknowledgement: &[u8],
        budget_bytes: u64,
    ) -> Result<(), DatabaseError> {
        if object.format_version != 1
            || object.bytes.len() != V1_SECTOR_SIZE
            || object.shard_index > 4
            || sector_root(&object.bytes) != object.root
            || acknowledgement.len() > 4096
        {
            return Err(DatabaseError::Integrity);
        }

        let transaction = self.connection.transaction()?;
        let existing = transaction
            .query_row(
                "SELECT format_version, guild_id, root, byte_length, state, bytes, acknowledgement
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
                        row.get::<_, Vec<u8>>(6)?,
                    ))
                },
            )
            .optional()?;
        if let Some((format_version, guild_id, root, byte_length, state, bytes, stored_ack)) =
            existing
        {
            if format_version != i64::from(object.format_version)
                || guild_id.as_slice() != object.guild_id
                || root.as_slice() != object.root
                || byte_length != object.bytes.len() as i64
                || bytes != object.bytes
                || stored_ack != acknowledgement
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

        let used: i64 = transaction.query_row(
            "SELECT coalesce(sum(byte_length), 0) FROM parity_objects",
            [],
            |row| row.get(0),
        )?;
        let required = u64::try_from(used)
            .map_err(|_| DatabaseError::Integrity)?
            .checked_add(object.bytes.len() as u64)
            .ok_or(DatabaseError::CapacityExceeded)?;
        if required > budget_bytes {
            return Err(DatabaseError::CapacityExceeded);
        }

        transaction.execute(
            "INSERT INTO parity_objects(
                format_version, guild_id, group_id, shard_index, root,
                byte_length, state, bytes, acknowledgement
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'STAGED', ?7, ?8)",
            params![
                object.format_version,
                object.guild_id.as_slice(),
                object.group_id.as_slice(),
                object.shard_index,
                object.root.as_slice(),
                object.bytes.len() as i64,
                object.bytes.as_slice(),
                acknowledgement,
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

    pub fn load_acknowledgement(
        &self,
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>, DatabaseError> {
        let bytes = self.load_stored_acknowledgement(group_id, shard_index)?;
        if bytes.is_empty() {
            return Err(DatabaseError::Integrity);
        }
        Ok(bytes)
    }

    pub fn load_stored_acknowledgement(
        &self,
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Vec<u8>, DatabaseError> {
        let bytes = self
            .connection
            .query_row(
                "SELECT acknowledgement FROM parity_objects
                 WHERE group_id = ?1 AND shard_index = ?2 AND state = 'READY'",
                params![group_id.as_slice(), shard_index],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?
            .ok_or(DatabaseError::NotReady)?;
        if bytes.len() > 4096 {
            return Err(DatabaseError::Integrity);
        }
        Ok(bytes)
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
        migrate_control(connection)?;
        validate_database_identity(connection, b"control", None)?;
        validate_control_schema(connection, SCHEMA_VERSION)?;
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
            state TEXT NOT NULL CHECK(state IN ('IN_PROGRESS', 'COMMITTED')),
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
         ) STRICT;
         CREATE TABLE recovery_shards (
            checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
            guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
            group_id BLOB NOT NULL CHECK(length(group_id) = 32),
            shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 0 AND 4),
            root BLOB NOT NULL CHECK(length(root) = 32),
            bytes BLOB NOT NULL CHECK(length(bytes) = 65536),
            PRIMARY KEY(checkpoint_hash, group_id, shard_index)
         ) STRICT;
         CREATE TABLE checkpoint_pages (
            object_kind TEXT NOT NULL CHECK(object_kind IN ('body', 'certificate')),
            guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
            object_id BLOB NOT NULL CHECK(length(object_id) = 32),
            page_index INTEGER NOT NULL CHECK(page_index >= 0),
            total_pages INTEGER NOT NULL CHECK(total_pages BETWEEN 1 AND 512),
            page_hash BLOB NOT NULL CHECK(length(page_hash) = 32),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 524288),
            PRIMARY KEY(object_kind, object_id, page_index)
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
        migrate_parity(connection, volume_id)?;
        validate_database_identity(connection, b"parity", Some(volume_id))?;
        validate_parity_schema(connection)?;
        return Ok(());
    }
    connection.execute_batch("PRAGMA auto_vacuum = INCREMENTAL; VACUUM;")?;
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
            shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 0 AND 4),
            root BLOB NOT NULL CHECK(length(root) = 32),
            byte_length INTEGER NOT NULL CHECK(byte_length = 65536),
            state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
            bytes BLOB NOT NULL,
            acknowledgement BLOB NOT NULL DEFAULT x'',
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

fn migrate_control(connection: &mut Connection) -> Result<(), DatabaseError> {
    if !table_exists(connection, "meta")? {
        return Err(DatabaseError::IncompatibleSchema);
    }
    let version = stored_schema_version(connection)?;
    if version == SCHEMA_VERSION {
        return validate_control_schema(connection, version);
    }
    if !matches!(version, 1..=3 | 5..=6) {
        return Err(DatabaseError::IncompatibleSchema);
    }
    if version >= 2 && meta_value(connection, "database_kind")?.as_deref() != Some(b"control") {
        return Err(DatabaseError::IncompatibleSchema);
    }
    validate_control_schema(connection, version)?;

    let transaction = connection.transaction()?;
    if version <= 2 {
        transaction.execute_batch(
            "ALTER TABLE operations RENAME TO operations_before_v3;
             CREATE TABLE operations (
                operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
                kind TEXT NOT NULL,
                caller BLOB NOT NULL CHECK(length(caller) = 32),
                request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
                state TEXT NOT NULL CHECK(state IN ('IN_PROGRESS', 'COMMITTED')),
                body BLOB NOT NULL
             ) STRICT;",
        )?;
        if version == 2 {
            transaction.execute_batch(
                "INSERT INTO operations(operation_id, kind, caller, request_hash, state, body)
                 SELECT operation_id, kind, caller, request_hash, 'COMMITTED', body
                 FROM operations_before_v3
                 WHERE length(operation_id) = 16
                   AND length(caller) = 32
                   AND length(request_hash) = 32
                   AND state = 'COMMITTED';",
            )?;
        }
        transaction.execute_batch("DROP TABLE operations_before_v3;")?;
    }
    transaction.execute_batch(
        "CREATE TABLE IF NOT EXISTS checkpoint_signature_locks (
            guild_id BLOB PRIMARY KEY CHECK(length(guild_id) = 32),
            generation INTEGER NOT NULL CHECK(generation > 0),
            checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
            checkpoint_bytes BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS checkpoint_heads (
            guild_id BLOB PRIMARY KEY CHECK(length(guild_id) = 32),
            generation INTEGER NOT NULL CHECK(generation > 0),
            checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
            checkpoint_bytes BLOB NOT NULL
         ) STRICT;
         CREATE TABLE IF NOT EXISTS recovery_shards (
            checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
            guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
            group_id BLOB NOT NULL CHECK(length(group_id) = 32),
            shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 0 AND 4),
            root BLOB NOT NULL CHECK(length(root) = 32),
            bytes BLOB NOT NULL CHECK(length(bytes) = 65536),
            PRIMARY KEY(checkpoint_hash, group_id, shard_index)
         ) STRICT;
         CREATE TABLE IF NOT EXISTS checkpoint_pages (
            object_kind TEXT NOT NULL CHECK(object_kind IN ('body', 'certificate')),
            guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
            object_id BLOB NOT NULL CHECK(length(object_id) = 32),
            page_index INTEGER NOT NULL CHECK(page_index >= 0),
            total_pages INTEGER NOT NULL CHECK(total_pages BETWEEN 1 AND 512),
            page_hash BLOB NOT NULL CHECK(length(page_hash) = 32),
            bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 524288),
            PRIMARY KEY(object_kind, object_id, page_index)
         ) STRICT;",
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('database_kind', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [b"control".as_slice()],
    )?;
    transaction.execute(
        "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        [SCHEMA_VERSION.to_be_bytes().as_slice()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn migrate_parity(connection: &mut Connection, volume_id: &[u8; 16]) -> Result<(), DatabaseError> {
    if !table_exists(connection, "meta")? {
        return Err(DatabaseError::IncompatibleSchema);
    }
    let version = stored_schema_version(connection)?;
    if version == SCHEMA_VERSION {
        return validate_parity_schema(connection);
    }
    if !matches!(version, 2..=3 | 5..=6)
        || meta_value(connection, "database_kind")?.as_deref() != Some(b"parity")
        || meta_value(connection, "volume_id")?.as_deref() != Some(volume_id.as_slice())
    {
        return Err(DatabaseError::IncompatibleSchema);
    }
    let prior_schema = if version == 6 {
        PARITY_OBJECTS_BEFORE_V7_SCHEMA
    } else {
        PARITY_OBJECTS_BEFORE_V6_SCHEMA
    };
    require_exact_tables(
        connection,
        &[("meta", META_SCHEMA), ("parity_objects", prior_schema)],
    )?;
    let transaction = connection.transaction()?;
    if version < 6 {
        transaction.execute_batch(
            "ALTER TABLE parity_objects
             ADD COLUMN acknowledgement BLOB NOT NULL DEFAULT x'';",
        )?;
    }
    transaction.execute_batch(
        "ALTER TABLE parity_objects RENAME TO parity_objects_before_v7;
         CREATE TABLE parity_objects (
            format_version INTEGER NOT NULL CHECK(format_version = 1),
            guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
            group_id BLOB NOT NULL CHECK(length(group_id) = 32),
            shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 0 AND 4),
            root BLOB NOT NULL CHECK(length(root) = 32),
            byte_length INTEGER NOT NULL CHECK(byte_length = 65536),
            state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
            bytes BLOB NOT NULL,
            acknowledgement BLOB NOT NULL DEFAULT x'',
            PRIMARY KEY(group_id, shard_index)
         ) STRICT;
         INSERT INTO parity_objects(
            format_version, guild_id, group_id, shard_index, root,
            byte_length, state, bytes, acknowledgement
         )
         SELECT format_version, guild_id, group_id, shard_index, root,
                byte_length, state, bytes, acknowledgement
         FROM parity_objects_before_v7;
         DROP TABLE parity_objects_before_v7;",
    )?;
    transaction.execute(
        "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
        [SCHEMA_VERSION.to_be_bytes().as_slice()],
    )?;
    transaction.commit()?;
    Ok(())
}

fn stored_schema_version(connection: &Connection) -> Result<u32, DatabaseError> {
    let bytes =
        meta_value(connection, "schema_version")?.ok_or(DatabaseError::IncompatibleSchema)?;
    let bytes: [u8; 4] = bytes
        .try_into()
        .map_err(|_| DatabaseError::IncompatibleSchema)?;
    Ok(u32::from_be_bytes(bytes))
}

fn table_exists(connection: &Connection, name: &str) -> Result<bool, DatabaseError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
        [name],
        |row| row.get(0),
    )?)
}

const META_SCHEMA: &str = "CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT";
const PROTOCOL_RECORDS_SCHEMA: &str = "CREATE TABLE protocol_records (
    kind TEXT NOT NULL,
    record_id BLOB NOT NULL,
    bytes BLOB NOT NULL,
    PRIMARY KEY (kind, record_id)
) STRICT";
const OPERATIONS_V1_SCHEMA: &str = "CREATE TABLE operations (
    operation_id BLOB PRIMARY KEY,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    body BLOB NOT NULL
) STRICT";
const OPERATIONS_V2_SCHEMA: &str = "CREATE TABLE operations (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
    kind TEXT NOT NULL,
    caller BLOB NOT NULL CHECK(length(caller) = 32),
    request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
    state TEXT NOT NULL CHECK(state = 'COMMITTED'),
    body BLOB NOT NULL
) STRICT";
const OPERATIONS_SCHEMA: &str = "CREATE TABLE operations (
    operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
    kind TEXT NOT NULL,
    caller BLOB NOT NULL CHECK(length(caller) = 32),
    request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
    state TEXT NOT NULL CHECK(state IN ('IN_PROGRESS', 'COMMITTED')),
    body BLOB NOT NULL
) STRICT";
const CHECKPOINT_LOCKS_SCHEMA: &str = "CREATE TABLE checkpoint_signature_locks (
    guild_id BLOB PRIMARY KEY CHECK(length(guild_id) = 32),
    generation INTEGER NOT NULL CHECK(generation > 0),
    checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
    checkpoint_bytes BLOB NOT NULL
) STRICT";
const CHECKPOINT_HEADS_SCHEMA: &str = "CREATE TABLE checkpoint_heads (
    guild_id BLOB PRIMARY KEY CHECK(length(guild_id) = 32),
    generation INTEGER NOT NULL CHECK(generation > 0),
    checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
    checkpoint_bytes BLOB NOT NULL
) STRICT";
const RECOVERY_SHARDS_SCHEMA: &str = "CREATE TABLE recovery_shards (
    checkpoint_hash BLOB NOT NULL CHECK(length(checkpoint_hash) = 32),
    guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
    group_id BLOB NOT NULL CHECK(length(group_id) = 32),
    shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 0 AND 4),
    root BLOB NOT NULL CHECK(length(root) = 32),
    bytes BLOB NOT NULL CHECK(length(bytes) = 65536),
    PRIMARY KEY(checkpoint_hash, group_id, shard_index)
) STRICT";
const CHECKPOINT_PAGES_SCHEMA: &str = "CREATE TABLE checkpoint_pages (
    object_kind TEXT NOT NULL CHECK(object_kind IN ('body', 'certificate')),
    guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
    object_id BLOB NOT NULL CHECK(length(object_id) = 32),
    page_index INTEGER NOT NULL CHECK(page_index >= 0),
    total_pages INTEGER NOT NULL CHECK(total_pages BETWEEN 1 AND 512),
    page_hash BLOB NOT NULL CHECK(length(page_hash) = 32),
    bytes BLOB NOT NULL CHECK(length(bytes) BETWEEN 1 AND 524288),
    PRIMARY KEY(object_kind, object_id, page_index)
) STRICT";
const PARITY_OBJECTS_SCHEMA: &str = "CREATE TABLE parity_objects (
    format_version INTEGER NOT NULL CHECK(format_version = 1),
    guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
    group_id BLOB NOT NULL CHECK(length(group_id) = 32),
    shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 0 AND 4),
    root BLOB NOT NULL CHECK(length(root) = 32),
    byte_length INTEGER NOT NULL CHECK(byte_length = 65536),
    state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
    bytes BLOB NOT NULL,
    acknowledgement BLOB NOT NULL DEFAULT x'',
    PRIMARY KEY(group_id, shard_index)
) STRICT";

const PARITY_OBJECTS_BEFORE_V6_SCHEMA: &str = "CREATE TABLE parity_objects (
    format_version INTEGER NOT NULL CHECK(format_version = 1),
    guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
    group_id BLOB NOT NULL CHECK(length(group_id) = 32),
    shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 3 AND 4),
    root BLOB NOT NULL CHECK(length(root) = 32),
    byte_length INTEGER NOT NULL CHECK(byte_length = 65536),
    state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
    bytes BLOB NOT NULL,
    PRIMARY KEY(group_id, shard_index)
) STRICT";

const PARITY_OBJECTS_BEFORE_V7_SCHEMA: &str = "CREATE TABLE parity_objects (
    format_version INTEGER NOT NULL CHECK(format_version = 1),
    guild_id BLOB NOT NULL CHECK(length(guild_id) = 32),
    group_id BLOB NOT NULL CHECK(length(group_id) = 32),
    shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 3 AND 4),
    root BLOB NOT NULL CHECK(length(root) = 32),
    byte_length INTEGER NOT NULL CHECK(byte_length = 65536),
    state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
    bytes BLOB NOT NULL,
    acknowledgement BLOB NOT NULL DEFAULT x'',
    PRIMARY KEY(group_id, shard_index)
) STRICT";

fn validate_control_schema(connection: &Connection, version: u32) -> Result<(), DatabaseError> {
    let expected = match version {
        1 => vec![
            ("meta", META_SCHEMA),
            ("protocol_records", PROTOCOL_RECORDS_SCHEMA),
            ("operations", OPERATIONS_V1_SCHEMA),
        ],
        2 => vec![
            ("meta", META_SCHEMA),
            ("protocol_records", PROTOCOL_RECORDS_SCHEMA),
            ("operations", OPERATIONS_V2_SCHEMA),
            ("checkpoint_signature_locks", CHECKPOINT_LOCKS_SCHEMA),
            ("checkpoint_heads", CHECKPOINT_HEADS_SCHEMA),
        ],
        3 => vec![
            ("meta", META_SCHEMA),
            ("protocol_records", PROTOCOL_RECORDS_SCHEMA),
            ("operations", OPERATIONS_SCHEMA),
            ("checkpoint_signature_locks", CHECKPOINT_LOCKS_SCHEMA),
            ("checkpoint_heads", CHECKPOINT_HEADS_SCHEMA),
        ],
        5 | 6 | SCHEMA_VERSION => vec![
            ("meta", META_SCHEMA),
            ("protocol_records", PROTOCOL_RECORDS_SCHEMA),
            ("operations", OPERATIONS_SCHEMA),
            ("checkpoint_signature_locks", CHECKPOINT_LOCKS_SCHEMA),
            ("checkpoint_heads", CHECKPOINT_HEADS_SCHEMA),
            ("recovery_shards", RECOVERY_SHARDS_SCHEMA),
            ("checkpoint_pages", CHECKPOINT_PAGES_SCHEMA),
        ],
        _ => return Err(DatabaseError::IncompatibleSchema),
    };
    require_exact_tables(connection, &expected)
}

fn validate_parity_schema(connection: &Connection) -> Result<(), DatabaseError> {
    require_exact_tables(
        connection,
        &[
            ("meta", META_SCHEMA),
            ("parity_objects", PARITY_OBJECTS_SCHEMA),
        ],
    )
}

fn require_exact_tables(
    connection: &Connection,
    expected: &[(&str, &str)],
) -> Result<(), DatabaseError> {
    let mut statement = connection.prepare(
        "SELECT type, name, coalesce(sql, '') FROM sqlite_schema
         WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    )?;
    let actual = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(1)?,
                (row.get::<_, String>(0)?, row.get::<_, String>(2)?),
            ))
        })?
        .collect::<Result<std::collections::BTreeMap<_, _>, _>>()?;
    if actual.len() != expected.len() {
        return Err(DatabaseError::IncompatibleSchema);
    }
    for (name, sql) in expected {
        let Some((object_type, actual_sql)) = actual.get(*name) else {
            return Err(DatabaseError::IncompatibleSchema);
        };
        if object_type != "table" || normalize_schema_sql(actual_sql) != normalize_schema_sql(sql) {
            return Err(DatabaseError::IncompatibleSchema);
        }
    }
    Ok(())
}

fn normalize_schema_sql(sql: &str) -> String {
    let mut normalized = String::with_capacity(sql.len());
    let mut outside = String::new();
    let mut characters = sql.chars().peekable();
    let mut quote = None;
    while let Some(character) = characters.next() {
        if let Some(end_quote) = quote {
            normalized.push(character);
            if character == end_quote {
                if characters.peek() == Some(&end_quote) && end_quote != ']' {
                    normalized.push(characters.next().expect("peeked escaped quote"));
                } else {
                    quote = None;
                }
            }
            continue;
        }
        match character {
            '\'' | '"' | '`' => {
                append_normalized_schema_outside(&mut normalized, &outside);
                outside.clear();
                quote = Some(character);
                normalized.push(character);
            }
            '[' => {
                append_normalized_schema_outside(&mut normalized, &outside);
                outside.clear();
                quote = Some(']');
                normalized.push(character);
            }
            character => outside.push(character),
        }
    }
    append_normalized_schema_outside(&mut normalized, &outside);
    normalized
}

fn append_normalized_schema_outside(normalized: &mut String, outside: &str) {
    let outside = outside
        .chars()
        .filter(|character| !character.is_whitespace() && *character != ';')
        .flat_map(char::to_lowercase)
        .collect::<String>()
        .replace("ifnotexists", "");
    normalized.push_str(&outside);
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

fn checkpoint_row(
    connection: &Connection,
    table: &'static str,
    guild_id: &[u8; 32],
) -> Result<Option<CheckpointRow>, DatabaseError> {
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
    configure_encrypted(connection, key)
}

fn open_encrypted_existing(path: &Path, key: &[u8; 32]) -> Result<Connection, DatabaseError> {
    let connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    configure_encrypted(connection, key)
}

fn configure_encrypted(
    connection: Connection,
    key: &[u8; 32],
) -> Result<Connection, DatabaseError> {
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

fn verify_rekeyed_database(path: &Path, key: &[u8; 32]) -> Result<(), DatabaseError> {
    let verification = open_encrypted_existing(path, key)?;
    cipher_integrity_check(&verification)
}

#[cfg(unix)]
fn allocated_file_bytes(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.blocks().saturating_mul(512)
}

#[cfg(not(unix))]
fn allocated_file_bytes(metadata: &fs::Metadata) -> u64 {
    metadata.len()
}

fn database_shell_statement(
    connection: &Connection,
    sql: &str,
    query_only: bool,
) -> Result<DatabaseShellResult, DatabaseError> {
    if query_only {
        connection.pragma_update(None, "query_only", true)?;
    }
    let mut statement = connection.prepare(sql)?;
    let column_count = statement.column_count();
    if column_count == 0 {
        let affected_rows = statement.execute([])?;
        return Ok(DatabaseShellResult {
            columns: Vec::new(),
            rows: Vec::new(),
            affected_rows: Some(affected_rows as u64),
        });
    }
    let columns = statement
        .column_names()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect();
    let mut query = statement.query([])?;
    let mut rows = Vec::new();
    while let Some(row) = query.next()? {
        let mut values = Vec::with_capacity(column_count);
        for index in 0..column_count {
            let value = match row.get_ref(index)? {
                ValueRef::Null => "NULL".to_owned(),
                ValueRef::Integer(value) => value.to_string(),
                ValueRef::Real(value) => value.to_string(),
                ValueRef::Text(value) => String::from_utf8_lossy(value).into_owned(),
                ValueRef::Blob(value) => format!("x'{}'", hex::encode(value)),
            };
            values.push(value);
        }
        rows.push(values);
    }
    Ok(DatabaseShellResult {
        columns,
        rows,
        affected_rows: None,
    })
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
            let store = ControlStore::open(&path, &keys).unwrap();
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
    fn control_rekey_preserves_a_nonempty_database() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let old_key = [3; 32];
        let new_key = [4; 32];
        {
            let store = ControlStore::open_with_key(&path, &old_key).unwrap();
            for index in 0_u8..64 {
                store
                    .put_record("rekey-test", &[index], &vec![index; 1024])
                    .unwrap();
            }
        }
        let store = ControlStore::open_with_key(&path, &old_key).unwrap();
        store.rekey(&new_key).unwrap();

        let store = ControlStore::open_with_key(&path, &new_key).unwrap();
        assert_eq!(store.records("rekey-test").unwrap().len(), 64);
        store.cipher_integrity_check().unwrap();
    }

    #[test]
    fn parity_rekey_preserves_a_nonempty_database() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("parity.db");
        let volume_id = [5; 16];
        let old_key = [6; 32];
        let new_key = [7; 32];
        let bytes = vec![8; V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [9; 32],
            group_id: [10; 32],
            shard_index: 3,
            root: sector_root(&bytes),
            bytes,
        };
        let mut store = ParityStore::open_with_key(&path, &volume_id, &old_key).unwrap();
        store
            .stage_and_publish_ack(&object, b"rekeyed-ack", V1_SECTOR_SIZE as u64)
            .unwrap();
        store.rekey(&new_key).unwrap();

        let store = ParityStore::open_existing_with_key(&path, &volume_id, &new_key).unwrap();
        assert_eq!(
            store
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert_eq!(
            store
                .load_acknowledgement(&object.group_id, object.shard_index)
                .unwrap(),
            b"rekeyed-ack"
        );
        store.cipher_integrity_check().unwrap();
    }

    #[test]
    fn database_shell_is_query_only_unless_explicitly_writable() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([42; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        let result = store
            .database_shell_statement("SELECT value FROM meta WHERE key = 'database_kind'", true)
            .unwrap();
        assert_eq!(result.columns, vec!["value"]);
        assert_eq!(result.rows, vec![vec!["x'636f6e74726f6c'".to_owned()]]);
        assert!(
            store
                .database_shell_statement("CREATE TABLE forbidden(value TEXT)", true)
                .is_err()
        );
        drop(store);

        let store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store
                .database_shell_statement("CREATE TABLE permitted(value TEXT)", false)
                .unwrap()
                .affected_rows,
            Some(0)
        );
        let tables = store
            .database_shell_statement(
                "SELECT name FROM sqlite_schema WHERE name = 'permitted'",
                false,
            )
            .unwrap();
        assert_eq!(tables.rows, vec![vec!["permitted".to_owned()]]);
    }

    #[test]
    fn protocol_record_compare_and_replace_rejects_stale_writers() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([72; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        store.put_record("job", b"one", b"first").unwrap();

        store
            .replace_record_if_value("job", b"one", b"first", b"second")
            .unwrap();
        assert!(matches!(
            store.replace_record_if_value("job", b"one", b"first", b"stale"),
            Err(DatabaseError::Conflict)
        ));
        assert_eq!(store.get_record("job", b"one").unwrap().unwrap(), b"second");
    }

    #[test]
    fn protocol_record_many_to_one_replacement_is_atomic() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        store.put_record("job", b"one", b"first").unwrap();
        store.put_record("job", b"two", b"second").unwrap();

        store
            .replace_records_with_one(
                "job",
                &[
                    (b"one".to_vec(), b"first".to_vec()),
                    (b"two".to_vec(), b"second".to_vec()),
                ],
                b"current",
                b"replacement",
            )
            .unwrap();
        assert_eq!(
            store.records("job").unwrap(),
            vec![(b"current".to_vec(), b"replacement".to_vec())]
        );

        store.put_record("job", b"one", b"changed").unwrap();
        assert!(matches!(
            store.replace_records_with_one(
                "job",
                &[(b"one".to_vec(), b"stale".to_vec())],
                b"new",
                b"must-roll-back",
            ),
            Err(DatabaseError::Conflict)
        ));
        assert!(store.get_record("job", b"new").unwrap().is_none());
        assert_eq!(
            store.get_record("job", b"one").unwrap().unwrap(),
            b"changed"
        );
    }

    #[test]
    fn protocol_records_are_read_in_bounded_pages() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([30; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let bytes = vec![31_u8; V1_CATALOG_PAGE_BYTES + 17];
        store
            .put_record("user-revision", b"revision", &bytes)
            .unwrap();
        let (total, first) = store
            .protocol_record_page("user-revision", b"revision", 0)
            .unwrap();
        let (second_total, second) = store
            .protocol_record_page("user-revision", b"revision", 1)
            .unwrap();
        assert_eq!(total, 2);
        assert_eq!(second_total, total);
        assert_eq!(first.len(), V1_CATALOG_PAGE_BYTES);
        assert_eq!(second.len(), 17);
        assert_eq!([first, second].concat(), bytes);
        assert!(
            store
                .protocol_record_page("user-revision", b"revision", 2)
                .is_err()
        );
    }

    #[test]
    fn pinning_recovery_attempt_atomically_bounds_durable_work() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([61; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let old_checkpoint = [62; 32];
        let active_checkpoint = [63; 32];
        let guild_id = [64; 32];
        let old_bytes = vec![65; V1_SECTOR_SIZE];
        let active_bytes = vec![66; V1_SECTOR_SIZE];
        let old_root = sector_root(&old_bytes);
        let active_root = sector_root(&active_bytes);
        store
            .stage_recovery_shard(
                &old_checkpoint,
                &guild_id,
                &[67; 32],
                0,
                &old_root,
                &old_bytes,
            )
            .unwrap();
        store
            .stage_recovery_shard(
                &active_checkpoint,
                &guild_id,
                &[68; 32],
                0,
                &active_root,
                &active_bytes,
            )
            .unwrap();
        store
            .put_record("recovery-job", &old_checkpoint, b"old-job")
            .unwrap();
        store
            .put_record("recovery-job", &active_checkpoint, b"active-job")
            .unwrap();
        store
            .put_record("dht-observed-recovery", b"stale", b"stale-observation")
            .unwrap();

        store
            .pin_recovery_attempt_and_reconcile_records(
                &active_checkpoint,
                b"active-attempt",
                "dht-observed-recovery",
                &[b"stale".to_vec()],
                &[(b"current".to_vec(), b"current-observation".to_vec())],
            )
            .unwrap();

        assert!(matches!(
            store.recovery_shard(&old_checkpoint, &guild_id, &[67; 32], 0, &old_root),
            Err(DatabaseError::NotReady)
        ));
        assert_eq!(
            store
                .recovery_shard(&active_checkpoint, &guild_id, &[68; 32], 0, &active_root,)
                .unwrap(),
            active_bytes
        );
        assert_eq!(store.records("recovery-job").unwrap().len(), 1);
        assert_eq!(
            store
                .get_record("recovery-attempt", b"active")
                .unwrap()
                .unwrap(),
            b"active-attempt"
        );
        assert!(
            store
                .get_record("dht-observed-recovery", b"stale")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_record("dht-observed-recovery", b"current")
                .unwrap()
                .unwrap(),
            b"current-observation"
        );

        store
            .complete_recovery_attempt(&active_checkpoint, b"complete-job")
            .unwrap();
        assert_eq!(
            store
                .get_record("recovery-job", &active_checkpoint)
                .unwrap()
                .unwrap(),
            b"complete-job"
        );
        assert!(
            store
                .get_record("recovery-attempt", b"active")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn capture_finalization_publishes_records_and_retires_intent_atomically() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([29; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let capture_id = [28; 16];
        store
            .put_record("capture-intent", &capture_id, b"pending")
            .unwrap();
        store
            .finalize_capture_records(
                &capture_id,
                &[(
                    "user-revision".to_owned(),
                    b"revision".to_vec(),
                    b"body".to_vec(),
                )],
            )
            .unwrap();
        assert!(
            store
                .get_record("capture-intent", &capture_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_record("user-revision", b"revision")
                .unwrap()
                .unwrap(),
            b"body"
        );

        assert!(
            store
                .finalize_capture_records(
                    &[27; 16],
                    &[(
                        "user-revision".to_owned(),
                        b"other".to_vec(),
                        b"bad".to_vec(),
                    )],
                )
                .is_err()
        );
        assert!(
            store
                .get_record("user-revision", b"other")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn recovered_anchor_finalization_is_compare_and_atomic() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([32; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let revision_id = [33; 16];
        store
            .put_record("recovery-anchor-intent", &revision_id, b"current")
            .unwrap();

        assert!(matches!(
            store.finalize_recovery_anchor_records(
                &revision_id,
                b"stale",
                &[(
                    "anchor-manifest".to_owned(),
                    revision_id.to_vec(),
                    b"not-committed".to_vec(),
                )],
            ),
            Err(DatabaseError::Conflict)
        ));
        assert!(
            store
                .get_record("anchor-manifest", &revision_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_record("recovery-anchor-intent", &revision_id)
                .unwrap()
                .unwrap(),
            b"current"
        );

        store
            .finalize_recovery_anchor_records(
                &revision_id,
                b"current",
                &[(
                    "anchor-manifest".to_owned(),
                    revision_id.to_vec(),
                    b"committed".to_vec(),
                )],
            )
            .unwrap();
        assert!(
            store
                .get_record("recovery-anchor-intent", &revision_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .get_record("anchor-manifest", &revision_id)
                .unwrap()
                .unwrap(),
            b"committed"
        );
    }

    #[test]
    fn capture_intent_abandon_is_compare_and_delete() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([30; 32]));
        let store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let capture_id = [31; 16];
        store
            .put_record("capture-intent", &capture_id, b"current-intent")
            .unwrap();

        assert!(matches!(
            store.abandon_capture_intent(&capture_id, b"stale-intent"),
            Err(DatabaseError::Conflict)
        ));
        assert_eq!(
            store
                .get_record("capture-intent", &capture_id)
                .unwrap()
                .unwrap(),
            b"current-intent"
        );

        store
            .abandon_capture_intent(&capture_id, b"current-intent")
            .unwrap();
        assert!(
            store
                .get_record("capture-intent", &capture_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn operation_identity_is_durable_and_bound_to_request() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([3; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let operation = [1; 16];
        let caller = [2; 32];
        let request = [3; 32];
        assert_eq!(
            store
                .begin_operation(&operation, "write", &caller, &request)
                .unwrap(),
            None
        );
        assert_eq!(
            store
                .begin_operation(&operation, "write", &caller, &request)
                .unwrap(),
            None
        );
        store
            .put_operation_result(&operation, "write", &caller, &request, b"result")
            .unwrap();
        assert_eq!(
            store
                .begin_operation(&operation, "write", &caller, &request)
                .unwrap()
                .unwrap(),
            b"result"
        );
        assert!(
            store
                .begin_operation(&operation, "other", &caller, &request)
                .is_err()
        );
    }

    #[test]
    fn deterministic_filler_responses_are_removed_from_old_journals() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([4; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let operation = [5; 16];
        let caller = [6; 32];
        let request = [7; 32];
        store
            .begin_operation(&operation, "ensure-filler", &caller, &request)
            .unwrap();
        store
            .put_operation_result(
                &operation,
                "ensure-filler",
                &caller,
                &request,
                &vec![8; V1_SECTOR_SIZE],
            )
            .unwrap();
        store.clear_recomputable_operations().unwrap();
        assert_eq!(
            store
                .begin_operation(&operation, "ensure-filler", &caller, &request)
                .unwrap(),
            None
        );
    }

    #[test]
    fn recovered_checkpoint_control_state_commits_atomically() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([61; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let guild_id = [62; 32];
        let checkpoint_hash = [63; 32];
        let group_id = [64; 32];
        let shard = vec![65; V1_SECTOR_SIZE];
        let shard_root = sector_root(&shard);
        store
            .stage_recovery_shard(
                &checkpoint_hash,
                &guild_id,
                &group_id,
                0,
                &shard_root,
                &shard,
            )
            .unwrap();
        store
            .put_record("recovery-attempt", b"active", b"attempt")
            .unwrap();
        store
            .connection
            .execute_batch(
                "CREATE TEMP TRIGGER fail_recovered_revision
                 BEFORE INSERT ON protocol_records
                 WHEN NEW.kind = 'user-revision-head'
                 BEGIN
                   SELECT RAISE(ABORT, 'fault after checkpoint');
                 END;",
            )
            .unwrap();

        assert!(
            store
                .commit_recovered_checkpoint(
                    &guild_id,
                    1,
                    None,
                    &checkpoint_hash,
                    b"checkpoint-body",
                    b"checkpoint-certificate",
                    Some(b"local-revision"),
                    false,
                )
                .is_err()
        );
        assert!(store.checkpoint_head(&guild_id).unwrap().is_none());
        assert!(
            store
                .get_record("guild-checkpoint", &checkpoint_hash)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .recovery_shard(&checkpoint_hash, &guild_id, &group_id, 0, &shard_root)
                .unwrap(),
            shard
        );
        assert_eq!(
            store.get_record("recovery-attempt", b"active").unwrap(),
            Some(b"attempt".to_vec())
        );

        store
            .connection
            .execute_batch("DROP TRIGGER fail_recovered_revision")
            .unwrap();
        store
            .commit_recovered_checkpoint(
                &guild_id,
                1,
                None,
                &checkpoint_hash,
                b"checkpoint-body",
                b"checkpoint-certificate",
                Some(b"local-revision"),
                false,
            )
            .unwrap();
        assert_eq!(
            store.checkpoint_head(&guild_id).unwrap(),
            Some((1, checkpoint_hash, b"checkpoint-certificate".to_vec()))
        );
        assert_eq!(
            store.get_record("user-revision-head", &guild_id).unwrap(),
            Some(b"local-revision".to_vec())
        );
        assert!(matches!(
            store.recovery_shard(&checkpoint_hash, &guild_id, &group_id, 0, &shard_root),
            Err(DatabaseError::NotReady)
        ));
        assert_eq!(
            store.get_record("recovery-attempt", b"active").unwrap(),
            Some(b"attempt".to_vec())
        );
    }

    #[test]
    fn storage_only_recovered_checkpoint_completes_the_attempt() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([66; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let guild_id = [67; 32];
        let checkpoint_hash = [68; 32];
        store
            .put_record("recovery-attempt", b"active", b"storage-only")
            .unwrap();
        store
            .put_record("user-revision-head", &guild_id, b"stale")
            .unwrap();

        store
            .commit_recovered_checkpoint(
                &guild_id,
                1,
                None,
                &checkpoint_hash,
                b"checkpoint-body",
                b"checkpoint-certificate",
                None,
                true,
            )
            .unwrap();

        assert!(
            store
                .get_record("recovery-attempt", b"active")
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get_record("user-revision-head", &guild_id)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn checkpoint_child_waits_for_parent_finalization() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([13; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let guild_id = [1; 32];
        let first_hash = [2; 32];
        let second_hash = [3; 32];
        store
            .lock_checkpoint_signature(&guild_id, 1, None, &first_hash, b"body-1")
            .unwrap();
        assert!(matches!(
            store.lock_checkpoint_signature(
                &guild_id,
                2,
                Some(&first_hash),
                &second_hash,
                b"body-2"
            ),
            Err(DatabaseError::Conflict)
        ));
        store
            .commit_checkpoint(
                &guild_id,
                1,
                None,
                &first_hash,
                b"body-1",
                b"certificate-1",
                true,
            )
            .unwrap();
        store
            .lock_checkpoint_signature(&guild_id, 2, Some(&first_hash), &second_hash, b"body-2")
            .unwrap();
    }

    #[test]
    fn recovered_checkpoint_restores_its_exact_signature_lock() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([12; 32]));
        let mut store = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let guild_id = [4; 32];
        let checkpoint_hash = [5; 32];
        store
            .commit_checkpoint(
                &guild_id,
                7,
                Some(&[6; 32]),
                &checkpoint_hash,
                b"authenticated-body",
                b"authenticated-certificate",
                false,
            )
            .unwrap();
        assert_eq!(
            store.locked_checkpoint(&guild_id).unwrap().unwrap(),
            (7, checkpoint_hash, b"authenticated-body".to_vec())
        );
        store
            .lock_checkpoint_signature(
                &guild_id,
                7,
                Some(&[6; 32]),
                &checkpoint_hash,
                b"authenticated-body",
            )
            .unwrap();
    }

    #[test]
    fn known_control_schema_migrates_transactionally() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([14; 32]));
        {
            let connection =
                open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
                     CREATE TABLE protocol_records(
                        kind TEXT NOT NULL, record_id BLOB NOT NULL, bytes BLOB NOT NULL,
                        PRIMARY KEY(kind, record_id)
                     ) STRICT;
                     CREATE TABLE operations(
                        operation_id BLOB PRIMARY KEY, kind TEXT NOT NULL,
                        state TEXT NOT NULL, body BLOB NOT NULL
                     ) STRICT;",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                    [1_u32.to_be_bytes().as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO protocol_records(kind, record_id, bytes) VALUES ('test', x'01', x'02')",
                    [],
                )
                .unwrap();
        }
        let mut store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(store.get_record("test", &[1]).unwrap().unwrap(), vec![2]);
        assert!(
            store
                .begin_operation(&[1; 16], "test", &[2; 32], &[3; 32])
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn exact_version_six_control_schema_migrates_without_data_loss() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([33; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        store.put_record("test", b"id", b"preserved").unwrap();
        drop(store);
        let connection = open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
        connection
            .execute(
                "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                [6_u32.to_be_bytes().as_slice()],
            )
            .unwrap();
        drop(connection);

        let store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store.get_record("test", b"id").unwrap().unwrap(),
            b"preserved"
        );
    }

    #[test]
    fn unknown_newer_schema_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([15; 32]));
        {
            let connection =
                open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE meta(key TEXT PRIMARY KEY, value BLOB NOT NULL) STRICT;
                     CREATE TABLE protocol_records(
                        kind TEXT NOT NULL, record_id BLOB NOT NULL, bytes BLOB NOT NULL,
                        PRIMARY KEY(kind, record_id)
                     ) STRICT;
                     CREATE TABLE operations(
                        operation_id BLOB PRIMARY KEY, kind TEXT NOT NULL,
                        caller BLOB NOT NULL, request_hash BLOB NOT NULL,
                        state TEXT NOT NULL, body BLOB NOT NULL
                     ) STRICT;",
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('database_kind', ?1)",
                    [b"control".as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                    [(SCHEMA_VERSION + 1).to_be_bytes().as_slice()],
                )
                .unwrap();
        }
        assert!(matches!(
            ControlStore::open(&path, &keys),
            Err(DatabaseError::IncompatibleSchema)
        ));
    }

    #[test]
    fn malformed_current_schema_is_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([16; 32]));
        drop(ControlStore::open(&path, &keys).unwrap());
        {
            let connection =
                open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
            connection
                .execute_batch(
                    "ALTER TABLE protocol_records RENAME TO protocol_records_valid;
                     CREATE TABLE protocol_records(
                        kind TEXT NOT NULL, record_id BLOB NOT NULL, bytes BLOB NOT NULL
                     ) STRICT;
                     DROP TABLE protocol_records_valid;",
                )
                .unwrap();
        }
        assert!(matches!(
            ControlStore::open(&path, &keys),
            Err(DatabaseError::IncompatibleSchema)
        ));
    }

    #[test]
    fn schema_comparison_preserves_check_literal_case() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([18; 32]));
        drop(ControlStore::open(&path, &keys).unwrap());
        {
            let connection =
                open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
            connection
                .execute_batch(
                    "ALTER TABLE operations RENAME TO operations_valid;
                     CREATE TABLE operations (
                        operation_id BLOB PRIMARY KEY CHECK(length(operation_id) = 16),
                        kind TEXT NOT NULL,
                        caller BLOB NOT NULL CHECK(length(caller) = 32),
                        request_hash BLOB NOT NULL CHECK(length(request_hash) = 32),
                        state TEXT NOT NULL CHECK(state IN ('in_progress', 'committed')),
                        body BLOB NOT NULL
                     ) STRICT;
                     DROP TABLE operations_valid;",
                )
                .unwrap();
        }
        assert!(matches!(
            ControlStore::open(&path, &keys),
            Err(DatabaseError::IncompatibleSchema)
        ));
    }

    #[test]
    fn unexpected_schema_triggers_are_rejected() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([19; 32]));
        drop(ControlStore::open(&path, &keys).unwrap());
        {
            let connection =
                open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
            connection
                .execute_batch(
                    "CREATE TRIGGER reject_protocol_records
                     BEFORE INSERT ON protocol_records
                     BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
                )
                .unwrap();
        }
        assert!(matches!(
            ControlStore::open(&path, &keys),
            Err(DatabaseError::IncompatibleSchema)
        ));
    }

    #[test]
    fn undefined_version_four_is_rejected_without_relabeling() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([17; 32]));
        drop(ControlStore::open(&path, &keys).unwrap());
        {
            let connection =
                open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
            connection
                .execute(
                    "UPDATE meta SET value = ?1 WHERE key = 'schema_version'",
                    [4_u32.to_be_bytes().as_slice()],
                )
                .unwrap();
        }
        assert!(matches!(
            ControlStore::open(&path, &keys),
            Err(DatabaseError::IncompatibleSchema)
        ));
        let connection = open_encrypted(&path, &keys.database_key(CONTROL_DATABASE_ID)).unwrap();
        assert_eq!(stored_schema_version(&connection).unwrap(), 4);
    }

    #[test]
    fn unassigned_legacy_parity_requires_explicit_reconciliation() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("parity.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([18; 32]));
        let volume_id = [19; 16];
        let mut database_id = b"parity.db/".to_vec();
        database_id.extend_from_slice(&volume_id);
        {
            let connection = open_encrypted(&path, &keys.database_key(&database_id)).unwrap();
            connection
                .execute_batch(
                    "CREATE TABLE parity_objects (
                        group_id BLOB NOT NULL CHECK(length(group_id) = 32),
                        shard_index INTEGER NOT NULL CHECK(shard_index BETWEEN 3 AND 4),
                        root BLOB NOT NULL CHECK(length(root) = 32),
                        byte_length INTEGER NOT NULL CHECK(byte_length > 0),
                        state TEXT NOT NULL CHECK(state IN ('STAGED', 'READY')),
                        bytes BLOB NOT NULL,
                        PRIMARY KEY(group_id, shard_index)
                     ) STRICT;",
                )
                .unwrap();
        }
        assert!(matches!(
            ParityStore::open(&path, &volume_id, &keys),
            Err(DatabaseError::IncompatibleSchema)
        ));
        let connection = open_encrypted(&path, &keys.database_key(&database_id)).unwrap();
        assert!(table_exists(&connection, "parity_objects").unwrap());
        assert!(!table_exists(&connection, "meta").unwrap());
        assert!(!table_exists(&connection, "parity_objects_v1_unassigned").unwrap());
    }

    #[test]
    fn exact_version_two_parity_schema_migrates_with_data() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("parity.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([20; 32]));
        let volume_id = [21; 16];
        let mut database_id = b"parity.db/".to_vec();
        database_id.extend_from_slice(&volume_id);
        let bytes = vec![22; V1_SECTOR_SIZE];
        let root = sector_root(&bytes);
        {
            let connection = open_encrypted(&path, &keys.database_key(&database_id)).unwrap();
            connection.execute_batch(META_SCHEMA).unwrap();
            connection
                .execute_batch(PARITY_OBJECTS_BEFORE_V6_SCHEMA)
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('database_kind', ?1)",
                    [b"parity".as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                    [2_u32.to_be_bytes().as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('volume_id', ?1)",
                    [volume_id.as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO parity_objects(
                        format_version, guild_id, group_id, shard_index, root,
                        byte_length, state, bytes
                     ) VALUES (1, ?1, ?2, 3, ?3, 65536, 'READY', ?4)",
                    params![
                        [23_u8; 32].as_slice(),
                        [24_u8; 32].as_slice(),
                        root.as_slice(),
                        bytes
                    ],
                )
                .unwrap();
        }
        let store = ParityStore::open(&path, &volume_id, &keys).unwrap();
        assert_eq!(
            store.load_ready(&[24; 32], 3).unwrap().bytes,
            vec![22; V1_SECTOR_SIZE]
        );
    }

    #[test]
    fn exact_version_six_parity_schema_migrates_with_data_and_acknowledgement() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("parity.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([25; 32]));
        let volume_id = [26; 16];
        let mut database_id = b"parity.db/".to_vec();
        database_id.extend_from_slice(&volume_id);
        let bytes = vec![27; V1_SECTOR_SIZE];
        let root = sector_root(&bytes);
        {
            let connection = open_encrypted(&path, &keys.database_key(&database_id)).unwrap();
            connection.execute_batch(META_SCHEMA).unwrap();
            connection
                .execute_batch(PARITY_OBJECTS_BEFORE_V7_SCHEMA)
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('database_kind', ?1)",
                    [b"parity".as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('schema_version', ?1)",
                    [6_u32.to_be_bytes().as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO meta(key, value) VALUES ('volume_id', ?1)",
                    [volume_id.as_slice()],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO parity_objects(
                        format_version, guild_id, group_id, shard_index, root,
                        byte_length, state, bytes, acknowledgement
                     ) VALUES (1, ?1, ?2, 3, ?3, 65536, 'READY', ?4, ?5)",
                    params![
                        [28_u8; 32].as_slice(),
                        [29_u8; 32].as_slice(),
                        root.as_slice(),
                        bytes,
                        b"version-six-ack"
                    ],
                )
                .unwrap();
        }
        let mut store = ParityStore::open(&path, &volume_id, &keys).unwrap();
        assert_eq!(
            store.load_acknowledgement(&[29; 32], 3).unwrap(),
            b"version-six-ack"
        );
        let emergency_bytes = vec![30; V1_SECTOR_SIZE];
        let emergency = ParityObject {
            format_version: 1,
            guild_id: [31; 32],
            group_id: [32; 32],
            shard_index: 0,
            root: sector_root(&emergency_bytes),
            bytes: emergency_bytes,
        };
        store.stage_and_publish(&emergency).unwrap();
        assert_eq!(store.load_ready(&[32; 32], 0).unwrap(), emergency);
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

    #[test]
    fn existing_parity_open_refuses_missing_and_empty_files() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("parity.db");
        let key = [10; 32];
        assert!(ParityStore::open_existing_with_key(&path, &[11; 16], &key).is_err());
        assert!(!path.exists());

        fs::write(&path, []).unwrap();
        assert!(matches!(
            ParityStore::open_existing_with_key(&path, &[11; 16], &key),
            Err(DatabaseError::Integrity)
        ));
        assert_eq!(fs::metadata(path).unwrap().len(), 0);
    }

    #[test]
    fn parity_metadata_is_bounded_and_deleted_pages_are_reclaimed() {
        let temp = tempdir().unwrap();
        let path = temp.path().join("parity.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([12; 32]));
        let mut store = ParityStore::open(&path, &[13; 16], &keys).unwrap();
        assert_eq!(
            store
                .connection
                .pragma_query_value(None, "auto_vacuum", |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        let mut objects = Vec::new();
        for index in 0_u8..5 {
            let bytes = vec![14 + index; V1_SECTOR_SIZE];
            let object = ParityObject {
                format_version: 1,
                guild_id: [15; 32],
                group_id: [16 + index; 32],
                shard_index: index,
                root: sector_root(&bytes),
                bytes,
            };
            store.stage_and_publish(&object).unwrap();
            objects.push(object);
        }
        assert_eq!(store.ready_object_count().unwrap(), 5);
        assert_eq!(
            store.first_ready_object().unwrap(),
            Some(objects[0].clone())
        );
        let allocated_before = store.allocated_bytes().unwrap();

        for object in &objects {
            assert!(
                store
                    .remove_ready(&object.group_id, object.shard_index, &object.root)
                    .unwrap()
            );
        }
        store.reclaim_space().unwrap();

        assert_eq!(store.ready_object_count().unwrap(), 0);
        assert_eq!(store.first_ready_object().unwrap(), None);
        assert!(store.allocated_bytes().unwrap() < allocated_before);
    }

    #[test]
    fn parity_scrub_reports_logically_corrupt_ready_objects() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([43; 32]));
        let mut store = ParityStore::open(temp.path().join("parity.db"), &[44; 16], &keys).unwrap();
        let bytes = vec![45; V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [46; 32],
            group_id: [47; 32],
            shard_index: 4,
            root: sector_root(&bytes),
            bytes,
        };
        store.stage_and_publish(&object).unwrap();
        let mut corrupt_bytes = object.bytes.clone();
        corrupt_bytes[0] ^= 1;
        store
            .connection
            .execute(
                "UPDATE parity_objects SET bytes = ?1
                 WHERE group_id = ?2 AND shard_index = ?3",
                params![
                    corrupt_bytes,
                    object.group_id.as_slice(),
                    object.shard_index
                ],
            )
            .unwrap();

        let report = store.scrub().unwrap();
        assert_eq!(report.checked_objects, 1);
        assert_eq!(report.checked_bytes, V1_SECTOR_SIZE as u64);
        assert_eq!(
            report.corrupt_objects,
            vec![(object.group_id, object.shard_index)]
        );
        assert!(matches!(
            store.load_ready(&object.group_id, object.shard_index),
            Err(DatabaseError::Integrity)
        ));
    }

    #[test]
    fn parity_budget_and_acknowledgement_commit_atomically() {
        let temp = tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([31; 32]));
        let mut store = ParityStore::open(temp.path().join("parity.db"), &[32; 16], &keys).unwrap();
        let bytes = vec![33; V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [34; 32],
            group_id: [35; 32],
            shard_index: 3,
            root: sector_root(&bytes),
            bytes,
        };
        assert!(matches!(
            store.stage_and_publish_ack(&object, b"signed-ack", V1_SECTOR_SIZE as u64 - 1),
            Err(DatabaseError::CapacityExceeded)
        ));
        assert!(matches!(
            store.load_ready(&object.group_id, object.shard_index),
            Err(DatabaseError::NotReady)
        ));
        store
            .stage_and_publish_ack(&object, b"signed-ack", V1_SECTOR_SIZE as u64)
            .unwrap();
        assert_eq!(
            store
                .load_acknowledgement(&object.group_id, object.shard_index)
                .unwrap(),
            b"signed-ack"
        );
        assert!(matches!(
            store.stage_and_publish_ack(&object, b"other-ack", V1_SECTOR_SIZE as u64),
            Err(DatabaseError::Conflict)
        ));
    }
}
