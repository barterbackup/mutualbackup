//! Compose catalog reads inside an enclosing read-only snapshot.

use std::ops::Deref;

use rusqlite::{Connection, Transaction};

use super::{ControlStore, DatabaseError};

pub(super) struct ReadSnapshot<'connection> {
    connection: &'connection Connection,
    transaction: Option<Transaction<'connection>>,
}

impl ControlStore {
    pub(super) fn read_snapshot(&self) -> Result<ReadSnapshot<'_>, DatabaseError> {
        let transaction = if !self.connection.is_autocommit() && self.is_read_only()? {
            // Reuse the caller's snapshot without committing or rolling it
            // back. Ordinary writer transactions retain their nesting checks.
            None
        } else {
            Some(self.connection.unchecked_transaction()?)
        };
        Ok(ReadSnapshot {
            connection: &self.connection,
            transaction,
        })
    }
}

impl ReadSnapshot<'_> {
    pub(super) fn commit(self) -> rusqlite::Result<()> {
        if let Some(transaction) = self.transaction {
            transaction.commit()?;
        }
        Ok(())
    }
}

impl Deref for ReadSnapshot<'_> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.connection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_catalog_reads_preserve_the_callers_read_only_snapshot_and_error_unwind() {
        let area = tempfile::tempdir().unwrap();
        let path = area.path().join("control.db");
        let writer = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
        writer.put_record("test", b"id", b"old").unwrap();
        let reader = ControlStore::open_existing_read_only_with_key(&path, &[7; 32]).unwrap();
        reader
            .with_read_only_snapshot(|| {
                assert_eq!(reader.get_record("test", b"id")?.unwrap(), b"old");
                assert!(reader.paged_revision_bootstrap_catalog([8; 32])?.is_none());
                assert!(reader.paged_sector_source([8; 32])?.is_none());
                assert!(reader.catalog_sector_source([8; 32])?.is_none());
                reader.read_snapshot()?.commit()?;
                writer.put_record("test", b"id", b"new")?;
                let abandoned: anyhow::Result<()> = (|| {
                    let _abandoned_nested_read = reader.read_snapshot()?;
                    assert_eq!(reader.get_record("test", b"id")?.unwrap(), b"old");
                    anyhow::bail!("abort nested read")
                })();
                assert!(abandoned.is_err());
                assert!(!reader.connection.is_autocommit());
                assert_eq!(reader.get_record("test", b"id")?.unwrap(), b"old");
                Ok(())
            })
            .unwrap();
        assert!(reader.connection.is_autocommit());
        assert_eq!(reader.get_record("test", b"id").unwrap().unwrap(), b"new");
        assert!(
            writer
                .with_record_transaction(|| -> Result<(), DatabaseError> {
                    let _nested_writer_read = writer.read_snapshot()?;
                    Ok(())
                })
                .is_err()
        );
        assert!(writer.connection.is_autocommit());
    }
}
