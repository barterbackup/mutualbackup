//! Preserve the existing streaming atomic-writer contract when introducing
//! database/WAL admission. Per-record bounds do not bound a whole transaction.

use super::*;

#[test]
#[ignore = "writes a large encrypted batch; qualify explicitly with disk and RSS evidence"]
fn streamed_atomic_batch_above_512_mib_preserves_rollback_reopen_and_reader_snapshots() {
    const RECORDS: u64 = 8193;
    const BYTES: usize = V1_SECTOR_SIZE;
    assert!(RECORDS * BYTES as u64 > 512 * 1024 * 1024);
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("control.db");
    let key = [183; 32];
    let mut writer = ControlStore::open_with_key(&path, &key).unwrap();
    let first = 0_u64.to_be_bytes();
    writer
        .put_record("bulk", &first, b"previously committed")
        .unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    reader.connection.execute_batch("BEGIN").unwrap();
    assert_eq!(
        reader.get_record("bulk", &first).unwrap().unwrap(),
        b"previously committed"
    );

    let produced = std::cell::Cell::new(0_u64);
    let records = |late_failure: bool| {
        let produced = &produced;
        (0..RECORDS + u64::from(late_failure)).map(move |index| -> anyhow::Result<_> {
            if index == RECORDS {
                anyhow::bail!("late bulk producer failure");
            }
            produced.set(produced.get() + 1);
            let mut bytes = vec![index as u8; BYTES];
            bytes[..8].copy_from_slice(&index.to_be_bytes());
            Ok(("bulk", index.to_be_bytes(), bytes))
        })
    };
    let error = writer.put_records_iter(records(true)).unwrap_err();
    assert!(
        error.to_string().contains("late bulk producer failure"),
        "{error}"
    );
    assert_eq!(
        produced.get(),
        RECORDS,
        "SQL admission cut off a supported batch before its producer completed"
    );
    assert!(writer.connection.is_autocommit());
    assert_eq!(
        writer.get_record("bulk", &first).unwrap().unwrap(),
        b"previously committed"
    );
    assert!(
        writer
            .get_record("bulk", &(RECORDS - 1).to_be_bytes())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        reader.get_record("bulk", &first).unwrap().unwrap(),
        b"previously committed"
    );

    produced.set(0);
    writer.put_records_iter(records(false)).unwrap();
    assert_eq!(produced.get(), RECORDS);
    assert_eq!(
        reader.get_record("bulk", &first).unwrap().unwrap(),
        b"previously committed"
    );
    let wal = path.with_file_name("control.db-wal");
    let journal_bytes = fs::metadata(&wal).unwrap().len();
    assert!(journal_bytes > 512 * 1024 * 1024);
    assert!(writer.checkpoint_reservation_bytes().unwrap() >= journal_bytes);
    drop(writer);

    // The held reader prevents checkpointing at close. Preserve the complete
    // inherited committed WAL when reopening; do not truncate it for a quota.
    let reopened = ControlStore::open_existing_with_key(&path, &key).unwrap();
    let mut visited = 0_u64;
    reopened
        .for_each_record_value("bulk", |bytes| {
            anyhow::ensure!(bytes.len() == BYTES);
            anyhow::ensure!(bytes[..8] == visited.to_be_bytes());
            anyhow::ensure!(bytes[8..].iter().all(|byte| *byte == visited as u8));
            visited += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(visited, RECORDS);
    assert!(reopened.checkpoint_reservation_bytes().unwrap() >= journal_bytes);
    reader.connection.execute_batch("COMMIT").unwrap();
    drop(reader);
    let busy: i32 = reopened
        .connection
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .unwrap();
    assert_eq!(busy, 0);
    assert_eq!(fs::metadata(&wal).unwrap().len(), 0);
    drop(reopened);
    let final_store = ControlStore::open_existing_read_only_with_key(&path, &key).unwrap();
    for index in [0, RECORDS / 2, RECORDS - 1] {
        let bytes = final_store
            .get_record("bulk", &index.to_be_bytes())
            .unwrap()
            .unwrap();
        assert_eq!(bytes.len(), BYTES);
        assert_eq!(bytes[..8], index.to_be_bytes());
        assert!(bytes[8..].iter().all(|byte| *byte == index as u8));
    }
    println!(
        "bulk admission qualification: records={RECORDS}, payload_bytes={}, inherited_wal_bytes={journal_bytes}",
        RECORDS * BYTES as u64
    );
}
