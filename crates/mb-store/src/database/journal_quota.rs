//! Explicit durable WAL/rollback-journal admission. Native VFS writes enforce
//! the persisted byte limit without truncating inherited committed journals.
//! Main pages, scratch and filesystem reservation retain separate budgets.

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, ffi, params};

use super::{ControlStore, DatabaseError, ParityStore, table_exists};

const POLICY: &str = "database_journal_quota";
const GUARD: &str = "database_journal_quota_guard";
const MAX_BYTES: u64 = i64::MAX as u64;
const FUNCTION: &std::ffi::CStr = c"mb_enforce_database_journal_quota";

fn table_schema(name: &str) -> String {
    format!(
        "CREATE TABLE {name} (
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        format_version INTEGER NOT NULL CHECK(format_version = 1),
        database_kind TEXT NOT NULL CHECK(database_kind IN ('control', 'parity')),
        page_bytes INTEGER NOT NULL CHECK(page_bytes = 4096),
        max_bytes INTEGER NOT NULL CHECK(max_bytes BETWEEN 32 AND 9223372036854775807)
        ) STRICT"
    )
}

/// An explicit absolute WAL/rollback-journal byte ceiling. It includes
/// inherited file bytes, rather than treating memory or live rows as a journal
/// budget. Configure enough credits for the intended complete transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseJournalQuota {
    pub max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DatabaseJournalQuotaUsage {
    pub quota: DatabaseJournalQuota,
    pub journal_bytes: u64,
}

fn read(connection: &Connection, table: &str) -> Result<(String, u64), DatabaseError> {
    if connection.query_row(
        &format!("SELECT count(*) FROM (SELECT 1 FROM {table} LIMIT 2)"),
        [],
        |row| row.get::<_, u64>(0),
    )? != 1
    {
        return Err(DatabaseError::Integrity);
    }
    // Bound text before allocating, including deliberately damaged schemas.
    let value: (String, u64) = connection.query_row(
        &format!("SELECT CASE WHEN octet_length(database_kind) <= 28 THEN database_kind END, max_bytes FROM {table} WHERE singleton = 1 AND format_version = 1 AND page_bytes = 4096"),
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).optional()?.ok_or(DatabaseError::Integrity)?;
    if !matches!(value.0.as_str(), "control" | "parity") || !(32..=MAX_BYTES).contains(&value.1) {
        return Err(DatabaseError::Integrity);
    }
    Ok(value)
}

fn kind(connection: &Connection) -> Result<Vec<u8>, DatabaseError> {
    connection.query_row("SELECT CASE WHEN length(value) BETWEEN 6 AND 7 THEN value END FROM meta WHERE key = 'database_kind'", [], |row| row.get::<_, Option<Vec<u8>>>(0))?
        .ok_or(DatabaseError::Integrity)
}

fn validate_policy_tables(connection: &Connection) -> Result<(), DatabaseError> {
    // Check declarations before evaluating policy columns. Altered/generated
    // columns must not execute code or allocate payloads in this write callback.
    for (name, expected) in [
        (POLICY, table_schema(POLICY)),
        (GUARD, table_schema(GUARD)),
        ("meta", super::META_SCHEMA.to_owned()),
    ] {
        let actual: Option<Option<String>> = connection.query_row(
            "SELECT CASE WHEN octet_length(sql) <= 4096 THEN sql END FROM sqlite_schema WHERE type = 'table' AND name = ?1",
            params![name], |row| row.get(0),
        ).optional()?;
        if actual.flatten().as_deref().map(super::normalize_schema_sql)
            != Some(super::normalize_schema_sql(&expected))
        {
            return Err(DatabaseError::Integrity);
        }
    }
    Ok(())
}

pub(super) fn usage(
    connection: &Connection,
) -> Result<Option<DatabaseJournalQuotaUsage>, DatabaseError> {
    match (
        table_exists(connection, POLICY)?,
        table_exists(connection, GUARD)?,
    ) {
        (false, false) => return Ok(None),
        (true, true) => (),
        _ => return Err(DatabaseError::Integrity),
    }
    validate_policy_tables(connection)?;
    let value = read(connection, POLICY)?;
    if read(connection, GUARD)? != value || kind(connection)?.as_slice() != value.0.as_bytes() {
        return Err(DatabaseError::Integrity);
    }
    // SQLCipher intercepts page_size and returns its value as text.
    let page_bytes: String = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
    let journal_bytes = super::journal_vfs::journal_bytes(connection)?;
    if page_bytes != "4096" || journal_bytes > value.1 {
        return Err(DatabaseError::CapacityExceeded);
    }
    Ok(Some(DatabaseJournalQuotaUsage {
        quota: DatabaseJournalQuota { max_bytes: value.1 },
        journal_bytes,
    }))
}

fn limit(connection: &Connection, max_bytes: u64) -> Result<(), DatabaseError> {
    if super::journal_vfs::journal_bytes(connection)? > max_bytes {
        return Err(DatabaseError::CapacityExceeded);
    }
    super::journal_vfs::set_limit(connection, max_bytes)?;
    Ok(())
}

/// Register on every encrypted connection, including connections opened before
/// configuration. Persisted BEFORE triggers refresh journal admission under the actual
/// writer; a stale connection or prepared statement cannot use an old limit.
pub(super) fn register(connection: &Connection) -> Result<(), DatabaseError> {
    // SAFETY: SQLite owns the function for the connection's lifetime. It has
    // no borrowed application data and no destructor. INNOCUOUS is justified:
    // it reads only fixed local policy/size and restricts this database's journal writes.
    let code = unsafe {
        ffi::sqlite3_create_function_v2(
            connection.handle(),
            FUNCTION.as_ptr(),
            0,
            ffi::SQLITE_UTF8 | ffi::SQLITE_INNOCUOUS,
            std::ptr::null_mut(),
            Some(enforce),
            None,
            None,
            None,
        )
    };
    if code != ffi::SQLITE_OK {
        return Err(DatabaseError::Sql(rusqlite::Error::SqliteFailure(
            ffi::Error::new(code),
            None,
        )));
    }
    Ok(())
}

unsafe extern "C" fn enforce(
    context: *mut ffi::sqlite3_context,
    _argc: std::ffi::c_int,
    _argv: *mut *mut ffi::sqlite3_value,
) {
    let result = std::panic::catch_unwind(|| -> Result<(), DatabaseError> {
        // SAFETY: SQLite invokes this on the connection's owning thread and
        // supports reentrant local policy reads. The wrapper borrows the handle;
        // dropping it finalizes only our statements and never closes SQLite.
        let connection =
            unsafe { Connection::from_handle(ffi::sqlite3_context_db_handle(context))? };
        let value = usage(&connection)?.ok_or(DatabaseError::Integrity)?;
        limit(&connection, value.quota.max_bytes)
    });
    // No Rust panic crosses the C boundary; errors abort the caller's statement.
    unsafe {
        match result {
            Ok(Ok(())) => ffi::sqlite3_result_int(context, 1),
            Ok(Err(DatabaseError::CapacityExceeded)) => {
                ffi::sqlite3_result_error_code(context, ffi::SQLITE_FULL)
            }
            _ => ffi::sqlite3_result_error(context, c"invalid database journal quota".as_ptr(), -1),
        }
    }
}

pub(super) fn schema(connection: &Connection) -> Result<Vec<(String, String)>, DatabaseError> {
    if !table_exists(connection, POLICY)? && !table_exists(connection, GUARD)? {
        return Ok(Vec::new());
    }
    let mut result = vec![
        (POLICY.to_owned(), table_schema(POLICY)),
        (GUARD.to_owned(), table_schema(GUARD)),
    ];
    for table in super::record_quota::data_tables(connection)? {
        for operation in ["insert", "update", "delete"] {
            let name = format!("database_journal_quota_{table}_{operation}");
            result.push((name.clone(), format!("CREATE TRIGGER {name} BEFORE {operation} ON {table} BEGIN SELECT mb_enforce_database_journal_quota(); END")));
        }
    }
    Ok(result)
}

pub(super) fn apply(connection: &Connection) -> Result<(), DatabaseError> {
    if let Some(value) = usage(connection)?
        && unsafe { ffi::sqlite3_db_readonly(connection.handle(), c"main".as_ptr()) } == 0
    {
        limit(connection, value.quota.max_bytes)?;
    }
    Ok(())
}

pub(super) fn configured(connection: &Connection) -> Result<bool, DatabaseError> {
    Ok(usage(connection)?.is_some())
}

fn configure(
    connection: &mut Connection,
    quota: DatabaseJournalQuota,
) -> Result<DatabaseJournalQuotaUsage, DatabaseError> {
    if !(32..=MAX_BYTES).contains(&quota.max_bytes) {
        return Err(DatabaseError::CapacityExceeded);
    }
    let previous_limit = super::journal_vfs::current_limit(connection)?;
    let result = (|| {
        let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some(policy) =
            super::catalog::required_resource_policy(&tx).map_err(|_| DatabaseError::Integrity)?
            && quota.max_bytes != policy.control_journal_bytes
        {
            return Err(DatabaseError::Conflict);
        }

        let previous = usage(&tx)?;
        limit(&tx, quota.max_bytes)?;
        let kind = kind(&tx)?;
        let kind = std::str::from_utf8(&kind).map_err(|_| DatabaseError::Integrity)?;
        if previous.is_none() {
            tx.execute_batch(&table_schema(POLICY))?;
            tx.execute_batch(&table_schema(GUARD))?;
        }
        for table in [POLICY, GUARD] {
            let changes = if let Some(previous) = previous {
                tx.execute(
                    &format!(
                        "UPDATE {table} SET max_bytes = ?1 WHERE singleton = 1 AND max_bytes = ?2"
                    ),
                    params![quota.max_bytes, previous.quota.max_bytes],
                )?
            } else {
                tx.execute(
                    &format!("INSERT INTO {table} VALUES (1, 1, ?1, 4096, ?2)"),
                    params![kind, quota.max_bytes],
                )?
            };
            if changes != 1 || read(&tx, table)? != (kind.to_owned(), quota.max_bytes) {
                return Err(DatabaseError::Integrity);
            }
        }
        if previous.is_none() {
            for (_, sql) in schema(&tx)?.into_iter().skip(2) {
                tx.execute_batch(&sql)?;
            }
        }
        let value = usage(&tx)?.ok_or(DatabaseError::Integrity)?;
        if value.quota != quota {
            return Err(DatabaseError::Integrity);
        }
        limit(&tx, quota.max_bytes)?;
        match kind {
            "control" => super::validate_control_schema(&tx, crate::SCHEMA_VERSION)?,
            "parity" => super::validate_parity_schema(&tx)?,
            _ => return Err(DatabaseError::IncompatibleSchema),
        }
        tx.commit()?;
        Ok(value)
    })();
    if result.is_err() {
        // VFS limits are connection settings rather than transactional rows.
        // Restore the old setting after rollback, including failed installation.
        super::journal_vfs::set_limit(connection, previous_limit)?;
    }
    result
}

macro_rules! quota_api {
    ($store:ty) => {
        impl $store {
            /// Configure an explicit journal byte ceiling in one writer.
            /// Refused installation/resize preserves records and inherited WAL.
            pub fn configure_journal_quota(
                &mut self,
                quota: DatabaseJournalQuota,
            ) -> Result<DatabaseJournalQuotaUsage, DatabaseError> {
                configure(&mut self.connection, quota)
            }
            pub fn journal_quota_usage(
                &self,
            ) -> Result<Option<DatabaseJournalQuotaUsage>, DatabaseError> {
                let tx = rusqlite::Transaction::new_unchecked(
                    &self.connection,
                    TransactionBehavior::Deferred,
                )?;
                let value = usage(&tx)?;
                tx.commit()?;
                Ok(value)
            }
        }
    };
}
quota_api!(ControlStore);
quota_api!(ParityStore);

#[cfg(test)]
mod tests;
