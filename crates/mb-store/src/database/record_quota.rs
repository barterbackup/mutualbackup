//! An explicitly configured logical quota over every persistent data table.
//!
//! Accounted bytes include stored cells, primary/secondary index keys, a
//! 32-byte charge per data row and a fixed bookkeeping reservation. They are
//! deliberately not a bound on SQLite pages, WAL, scratch or filesystem space.
//! Persistent triggers cover existing connections as well as newly opened
//! writers. Incremental adoption freezes data writes until every table's rowid
//! cursor reaches EOF; each step reads at most 128 lengths, never payloads.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use super::{ControlStore, DatabaseError, ParityStore, meta_value, table_exists};

const BOOKKEEPING_BYTES: u64 = 1024;
const ADOPTION_ROWS: usize = 128;
const QUOTA_TABLE: &str = "database_record_quota";
const GUARD_TABLE: &str = "database_record_quota_guard";
const QUOTA_SCHEMA: &str = "CREATE TABLE database_record_quota (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    format_version INTEGER NOT NULL CHECK(format_version = 1),
    database_kind TEXT NOT NULL CHECK(database_kind IN ('control', 'parity')),
    state TEXT NOT NULL CHECK(state IN ('ADOPTING', 'ACTIVE')),
    max_rows INTEGER NOT NULL CHECK(max_rows > 0),
    max_bytes INTEGER NOT NULL CHECK(max_bytes >= 1024),
    used_rows INTEGER NOT NULL CHECK(used_rows BETWEEN 0 AND max_rows),
    used_bytes INTEGER NOT NULL CHECK(used_bytes BETWEEN 1024 AND max_bytes),
    scan_table INTEGER NOT NULL CHECK(scan_table >= 0),
    last_rowid INTEGER
) STRICT";
const GUARD_SCHEMA: &str = "CREATE TABLE database_record_quota_guard (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    expected_rows INTEGER NOT NULL CHECK(expected_rows >= 0),
    expected_bytes INTEGER NOT NULL CHECK(expected_bytes >= 1024),
    max_rows INTEGER NOT NULL,
    max_bytes INTEGER NOT NULL,
    database_kind TEXT NOT NULL,
    scan_table INTEGER NOT NULL,
    last_rowid INTEGER
) STRICT";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseRecordQuota {
    pub max_rows: u64,
    pub max_accounted_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DatabaseRecordQuotaState {
    Adopting,
    Active,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseRecordQuotaUsage {
    pub quota: DatabaseRecordQuota,
    pub state: DatabaseRecordQuotaState,
    pub rows: u64,
    pub accounted_bytes: u64,
    /// The next table to scan, or the table count after authenticated EOF.
    pub scan_table: usize,
    pub last_rowid: Option<i64>,
}

#[derive(Clone, Copy)]
struct Table {
    name: &'static str,
    blobs: &'static [&'static str],
    texts: &'static [&'static str],
    integers: usize,
    key_blobs: &'static [&'static str],
    key_texts: &'static [&'static str],
    key_integers: usize,
}

const CONTROL: &[Table] = &[
    Table {
        name: "meta",
        blobs: &["value"],
        texts: &["key"],
        integers: 0,
        key_blobs: &[],
        key_texts: &["key"],
        key_integers: 0,
    },
    Table {
        name: "protocol_records",
        blobs: &["record_id", "bytes"],
        texts: &["kind"],
        integers: 0,
        key_blobs: &["record_id"],
        key_texts: &["kind"],
        key_integers: 0,
    },
    Table {
        name: "operations",
        blobs: &["operation_id", "caller", "request_hash", "body"],
        texts: &["kind", "state"],
        integers: 0,
        key_blobs: &["operation_id"],
        key_texts: &[],
        key_integers: 0,
    },
    Table {
        name: "checkpoint_signature_locks",
        blobs: &["guild_id", "checkpoint_hash", "checkpoint_bytes"],
        texts: &[],
        integers: 1,
        key_blobs: &["guild_id"],
        key_texts: &[],
        key_integers: 0,
    },
    Table {
        name: "checkpoint_heads",
        blobs: &["guild_id", "checkpoint_hash", "checkpoint_bytes"],
        texts: &[],
        integers: 1,
        key_blobs: &["guild_id"],
        key_texts: &[],
        key_integers: 0,
    },
    Table {
        name: "recovery_shards",
        blobs: &["checkpoint_hash", "guild_id", "group_id", "root", "bytes"],
        texts: &[],
        integers: 1,
        key_blobs: &["checkpoint_hash", "group_id"],
        key_texts: &[],
        key_integers: 1,
    },
    Table {
        name: "checkpoint_pages",
        blobs: &["guild_id", "object_id", "page_hash", "bytes"],
        texts: &["object_kind"],
        integers: 2,
        key_blobs: &["object_id"],
        key_texts: &["object_kind"],
        key_integers: 1,
    },
];
const PARITY: &[Table] = &[
    CONTROL[0],
    Table {
        name: "parity_objects",
        blobs: &[
            "guild_id",
            "group_id",
            "root",
            "bytes",
            "acknowledgement",
            "attempt_id",
            "verification_hash",
        ],
        texts: &["state"],
        integers: 3,
        key_blobs: &["group_id"],
        key_texts: &[],
        key_integers: 1,
    },
    Table {
        name: "coding_reservations",
        blobs: &["attempt_id", "guild_id", "bytes"],
        texts: &[],
        integers: 3,
        key_blobs: &["attempt_id"],
        key_texts: &[],
        key_integers: 1,
    },
];

fn tables(connection: &Connection) -> Result<&'static [Table], DatabaseError> {
    match meta_value(connection, "database_kind")?.as_deref() {
        Some(b"control") => Ok(CONTROL),
        Some(b"parity") => Ok(PARITY),
        _ => Err(DatabaseError::IncompatibleSchema),
    }
}

impl Table {
    fn charge(self, prefix: &str) -> String {
        // Integer cells and index row locators have a fixed logical charge of
        // eight bytes. NULL optional blobs have no payload charge.
        let mut terms = vec![(32 + 8 * (self.integers + self.key_integers + 1)).to_string()];
        for column in self.blobs.iter().chain(self.key_blobs) {
            terms.push(format!("coalesce(length({prefix}{column}), 0)"));
        }
        for column in self.texts.iter().chain(self.key_texts) {
            // Unlike a CAST or character-count length(), octet_length(column)
            // uses SQLite's header-only OP_Column path for stored text bytes.
            terms.push(format!("octet_length({prefix}{column})"));
        }
        if self.name == "protocol_records" {
            // Reserve the partial index's possible key for every protocol row.
            // Evaluating its GLOB predicate would materialize an arbitrary
            // legacy text key during adoption. This is an explicit logical
            // reservation, independent of the row's current index membership.
            terms.push(format!(
                "length({prefix}record_id) + octet_length({prefix}kind) + 8"
            ));
        }
        terms.join(" + ")
    }

    fn trigger(self, operation: &str) -> (String, String) {
        let name = format!("database_record_quota_{}_{operation}", self.name);
        let (row_delta, byte_delta) = match operation {
            "insert" => ("1", self.charge("NEW.")),
            "delete" => ("-1", format!("-({})", self.charge("OLD."))),
            "update" => (
                "0",
                format!("({}) - ({})", self.charge("NEW."), self.charge("OLD.")),
            ),
            _ => unreachable!(),
        };
        // Guard the expected result outside the counter row: checking changes()
        // alone cannot detect an AFTER UPDATE fault that restores old counters.
        let sql = format!("CREATE TRIGGER {name} AFTER {operation} ON {} BEGIN
            SELECT CASE WHEN (SELECT count(*) FROM database_record_quota) != 1
                OR NOT EXISTS(SELECT 1 FROM database_record_quota WHERE singleton = 1 AND state = 'ACTIVE')
                THEN RAISE(ABORT, 'database record quota adoption incomplete') END;
            SELECT CASE WHEN EXISTS(SELECT 1 FROM database_record_quota_guard)
                THEN RAISE(ABORT, 'database record quota guard conflict') END;
            SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM database_record_quota
                WHERE ({row_delta}) <= max_rows - used_rows AND ({row_delta}) >= -used_rows
                AND ({byte_delta}) <= max_bytes - used_bytes
                AND ({byte_delta}) >= 1024 - used_bytes)
                THEN RAISE(ABORT, 'database record quota exhausted') END;
            INSERT INTO database_record_quota_guard
                SELECT 1, used_rows + ({row_delta}), used_bytes + ({byte_delta}), max_rows, max_bytes, database_kind, scan_table, last_rowid FROM database_record_quota;
            SELECT CASE WHEN changes() != 1 OR (SELECT count(*) FROM database_record_quota_guard) != 1
                OR NOT EXISTS(SELECT 1 FROM database_record_quota q JOIN database_record_quota_guard g USING(singleton)
                    WHERE g.expected_rows = q.used_rows + ({row_delta}) AND g.expected_bytes = q.used_bytes + ({byte_delta})
                    AND g.max_rows = q.max_rows AND g.max_bytes = q.max_bytes
                    AND g.database_kind = q.database_kind AND g.scan_table = q.scan_table AND g.last_rowid IS q.last_rowid)
                THEN RAISE(ABORT, 'database record quota guard was not written') END;
            UPDATE database_record_quota SET
                used_rows = (SELECT expected_rows FROM database_record_quota_guard WHERE singleton = 1),
                used_bytes = (SELECT expected_bytes FROM database_record_quota_guard WHERE singleton = 1)
                WHERE singleton = 1;
            SELECT CASE WHEN changes() != 1 OR NOT EXISTS(
                SELECT 1 FROM database_record_quota q JOIN database_record_quota_guard g USING(singleton)
                WHERE q.used_rows = g.expected_rows AND q.used_bytes = g.expected_bytes AND q.state = 'ACTIVE'
                    AND q.format_version = 1 AND q.max_rows = g.max_rows AND q.max_bytes = g.max_bytes
                    AND q.database_kind = g.database_kind AND q.scan_table = g.scan_table AND q.last_rowid IS g.last_rowid)
                THEN RAISE(ABORT, 'database record quota counter was not written') END;
            DELETE FROM database_record_quota_guard WHERE singleton = 1;
            SELECT CASE WHEN changes() != 1 OR EXISTS(SELECT 1 FROM database_record_quota_guard)
                THEN RAISE(ABORT, 'database record quota guard was not removed') END;
        END", self.name);
        (name, sql)
    }
}

pub(super) fn schema(connection: &Connection) -> Result<Vec<(String, String)>, DatabaseError> {
    if !table_exists(connection, QUOTA_TABLE)? {
        return Ok(Vec::new());
    }
    let mut objects = vec![
        (QUOTA_TABLE.to_owned(), QUOTA_SCHEMA.to_owned()),
        (GUARD_TABLE.to_owned(), GUARD_SCHEMA.to_owned()),
    ];
    for table in tables(connection)? {
        for operation in ["insert", "update", "delete"] {
            objects.push(table.trigger(operation));
        }
    }
    Ok(objects)
}

pub(super) fn validate(connection: &Connection) -> Result<(), DatabaseError> {
    if !table_exists(connection, QUOTA_TABLE)? {
        return Ok(());
    }
    let usage = usage(connection)?.ok_or(DatabaseError::Integrity)?;
    let count = tables(connection)?.len();
    if usage.scan_table > count
        || (usage.state == DatabaseRecordQuotaState::Active
            && (usage.scan_table != count || usage.last_rowid.is_some()))
        || (usage.state == DatabaseRecordQuotaState::Adopting && usage.scan_table == count)
        || connection.query_row(
            "SELECT count(*) FROM database_record_quota_guard",
            [],
            |r| r.get::<_, i64>(0),
        )? != 0
    {
        return Err(DatabaseError::Integrity);
    }
    // Required for delete accounting when an administrator uses REPLACE.
    connection.pragma_update(None, "recursive_triggers", true)?;
    Ok(())
}

fn usage(connection: &Connection) -> Result<Option<DatabaseRecordQuotaUsage>, DatabaseError> {
    if !table_exists(connection, QUOTA_TABLE)? {
        return Ok(None);
    }
    let count: i64 =
        connection.query_row("SELECT count(*) FROM database_record_quota", [], |r| {
            r.get(0)
        })?;
    if count != 1 {
        return Err(DatabaseError::Integrity);
    }
    let (kind, state, rows, bytes, max_rows, max_bytes, scan_table, last_rowid) = connection.query_row(
        "SELECT database_kind, state, used_rows, used_bytes, max_rows, max_bytes, scan_table, last_rowid FROM database_record_quota WHERE singleton = 1 AND format_version = 1", [], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, u64>(2)?, r.get::<_, u64>(3)?, r.get::<_, u64>(4)?, r.get::<_, u64>(5)?, r.get::<_, usize>(6)?, r.get::<_, Option<i64>>(7)?))
        }).optional()?.ok_or(DatabaseError::Integrity)?;
    if meta_value(connection, "database_kind")?.as_deref() != Some(kind.as_bytes())
        || rows > max_rows
        || bytes < BOOKKEEPING_BYTES
        || bytes > max_bytes
    {
        return Err(DatabaseError::Integrity);
    }
    Ok(Some(DatabaseRecordQuotaUsage {
        quota: DatabaseRecordQuota {
            max_rows,
            max_accounted_bytes: max_bytes,
        },
        state: match state.as_str() {
            "ADOPTING" => DatabaseRecordQuotaState::Adopting,
            "ACTIVE" => DatabaseRecordQuotaState::Active,
            _ => return Err(DatabaseError::Integrity),
        },
        rows,
        accounted_bytes: bytes,
        scan_table,
        last_rowid,
    }))
}

fn begin(
    connection: &mut Connection,
    quota: DatabaseRecordQuota,
) -> Result<DatabaseRecordQuotaUsage, DatabaseError> {
    if quota.max_rows == 0
        || quota.max_rows > i64::MAX as u64
        || quota.max_accounted_bytes < BOOKKEEPING_BYTES
        || quota.max_accounted_bytes > i64::MAX as u64
    {
        return Err(DatabaseError::RecordCapacityExceeded);
    }
    connection.pragma_update(None, "recursive_triggers", true)?;
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let expected = if let Some(mut previous) = usage(&transaction)? {
        if previous.rows > quota.max_rows || previous.accounted_bytes > quota.max_accounted_bytes {
            return Err(DatabaseError::RecordCapacityExceeded);
        }
        if transaction.execute(
            "UPDATE database_record_quota SET max_rows = ?1, max_bytes = ?2 WHERE singleton = 1",
            params![quota.max_rows, quota.max_accounted_bytes],
        )? != 1
        {
            return Err(DatabaseError::Conflict);
        }
        previous.quota = quota;
        previous
    } else {
        let kind = meta_value(&transaction, "database_kind")?.ok_or(DatabaseError::Integrity)?;
        let kind = std::str::from_utf8(&kind).map_err(|_| DatabaseError::Integrity)?;
        transaction.execute_batch(QUOTA_SCHEMA)?;
        transaction.execute_batch(GUARD_SCHEMA)?;
        for table in tables(&transaction)? {
            for operation in ["insert", "update", "delete"] {
                transaction.execute_batch(&table.trigger(operation).1)?;
            }
        }
        if transaction.execute("INSERT INTO database_record_quota VALUES (1, 1, ?1, 'ADOPTING', ?2, ?3, 0, 1024, 0, NULL)", params![kind, quota.max_rows, quota.max_accounted_bytes])? != 1 {
            return Err(DatabaseError::Conflict);
        }
        DatabaseRecordQuotaUsage {
            quota,
            state: DatabaseRecordQuotaState::Adopting,
            rows: 0,
            accounted_bytes: BOOKKEEPING_BYTES,
            scan_table: 0,
            last_rowid: None,
        }
    };
    if usage(&transaction)? != Some(expected) {
        return Err(DatabaseError::Conflict);
    }
    transaction.commit()?;
    Ok(expected)
}

fn resume(connection: &mut Connection) -> Result<DatabaseRecordQuotaUsage, DatabaseError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let mut expected = usage(&transaction)?.ok_or(DatabaseError::NotReady)?;
    if expected.state == DatabaseRecordQuotaState::Active {
        return Ok(expected);
    }
    let tables = tables(&transaction)?;
    let table = *tables
        .get(expected.scan_table)
        .ok_or(DatabaseError::Integrity)?;
    let predicate = if expected.last_rowid.is_some() {
        "WHERE rowid > ?1"
    } else {
        ""
    };
    let sql = format!(
        "SELECT rowid, {} FROM {} {predicate} ORDER BY rowid LIMIT {ADOPTION_ROWS}",
        table.charge(""),
        table.name
    );
    let mut statement = transaction.prepare(&sql)?;
    let mut rows = if let Some(cursor) = expected.last_rowid {
        statement.query([cursor])?
    } else {
        statement.query([])?
    };
    let mut scanned = 0;
    while let Some(row) = rows.next()? {
        expected.last_rowid = Some(row.get(0)?);
        expected.rows = expected
            .rows
            .checked_add(1)
            .ok_or(DatabaseError::RecordCapacityExceeded)?;
        expected.accounted_bytes = expected
            .accounted_bytes
            .checked_add(row.get::<_, u64>(1)?)
            .ok_or(DatabaseError::RecordCapacityExceeded)?;
        if expected.rows > expected.quota.max_rows
            || expected.accounted_bytes > expected.quota.max_accounted_bytes
        {
            return Err(DatabaseError::RecordCapacityExceeded);
        }
        scanned += 1;
    }
    drop(rows);
    drop(statement);
    if scanned < ADOPTION_ROWS {
        expected.scan_table += 1;
        expected.last_rowid = None;
        if expected.scan_table == tables.len() {
            expected.state = DatabaseRecordQuotaState::Active;
        }
    }
    let state = match expected.state {
        DatabaseRecordQuotaState::Adopting => "ADOPTING",
        DatabaseRecordQuotaState::Active => "ACTIVE",
    };
    if transaction.execute("UPDATE database_record_quota SET state = ?1, used_rows = ?2, used_bytes = ?3, scan_table = ?4, last_rowid = ?5 WHERE singleton = 1", params![state, expected.rows, expected.accounted_bytes, expected.scan_table, expected.last_rowid])? != 1
        || usage(&transaction)? != Some(expected)
    { return Err(DatabaseError::Conflict); }
    transaction.commit()?;
    Ok(expected)
}

fn abort(connection: &mut Connection) -> Result<(), DatabaseError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let current = usage(&transaction)?.ok_or(DatabaseError::NotReady)?;
    if current.state != DatabaseRecordQuotaState::Adopting {
        return Err(DatabaseError::Conflict);
    }
    for (name, _) in schema(&transaction)?.into_iter().rev() {
        let object = if name == QUOTA_TABLE || name == GUARD_TABLE {
            "TABLE"
        } else {
            "TRIGGER"
        };
        transaction.execute_batch(&format!("DROP {object} {name}"))?;
    }
    transaction.commit()?;
    Ok(())
}

macro_rules! quota_api {
    ($store:ty) => {
        impl $store {
            /// Install or change an explicitly declared quota. A new quota
            /// freezes data writes until bounded adoption has reached EOF.
            pub fn begin_record_quota_adoption(
                &mut self,
                quota: DatabaseRecordQuota,
            ) -> Result<DatabaseRecordQuotaUsage, DatabaseError> {
                begin(&mut self.connection, quota)
            }

            /// Advance at most 128 row-length headers in one writer transaction.
            pub fn resume_record_quota_adoption(
                &mut self,
            ) -> Result<DatabaseRecordQuotaUsage, DatabaseError> {
                resume(&mut self.connection)
            }

            /// Discard incomplete accounting without changing existing data.
            /// An active quota can only be resized, not removed through this API.
            pub fn abort_record_quota_adoption(&mut self) -> Result<(), DatabaseError> {
                abort(&mut self.connection)
            }

            pub fn record_quota_usage(
                &self,
            ) -> Result<Option<DatabaseRecordQuotaUsage>, DatabaseError> {
                usage(&self.connection)
            }
        }
    };
}
quota_api!(ControlStore);
quota_api!(ParityStore);

#[cfg(test)]
mod tests;
