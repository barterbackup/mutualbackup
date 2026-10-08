use super::*;

fn legacy(store: &mut ParityStore) -> ReadyVariableObject {
    let bytes = vec![31; 64];
    let object = VariableParityObject {
        format_version: 2,
        guild_id: [32; 32],
        group_id: [33; 32],
        shard_index: 0,
        commitment: merkle_commit(&bytes).unwrap(),
        bytes,
    };
    let attempt_id = [34; 16];
    let verification_hash = [35; 32];
    store
        .reserve_coding_attempt(&attempt_id, &object.guild_id, 0, 64, 1024)
        .unwrap();
    store
        .write_coding_attempt_range(&attempt_id, 0, 0, &object.bytes)
        .unwrap();
    store
        .finish_coding_attempt_upload(&attempt_id, &object.group_id, 0, &object.commitment)
        .unwrap();
    // Exact pre-fix information activation: READY with a verified transcript
    // hash, without a parity receipt. Node tests supply actual signed evidence.
    store
        .activate_attempt_object(
            &attempt_id,
            &object.group_id,
            0,
            &object.commitment,
            &verification_hash,
        )
        .unwrap();
    ReadyVariableObject {
        object,
        attempt_id,
        verification_hash,
        staged_receipt: Vec::new(),
    }
}

#[test]
fn legacy_information_upgrade_is_atomic_guarded_and_survives_transfer_after_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("source.db");
    let mut store = ParityStore::open_with_key(&path, &[36; 16], &[37; 32]).unwrap();
    let original = legacy(&mut store);
    assert!(store.first_ready_variable_object().is_err());
    for boundary in [1, 2] {
        let mut calls = 0;
        assert!(
            store
                .first_ready_variable_object_with_information_upgrade(|ready| {
                    assert_eq!(ready, &original);
                    calls += 1;
                    if calls == boundary {
                        Err(DatabaseError::Integrity)
                    } else {
                        Ok(())
                    }
                })
                .is_err()
        );
        assert_eq!(
            store
                .read_ready_variable_activation(&original.object.group_id, 0)
                .unwrap(),
            original
        );
    }
    for trigger in [
        "CREATE TEMP TRIGGER fault BEFORE UPDATE OF acknowledgement ON parity_objects BEGIN SELECT RAISE(IGNORE); END;",
        "CREATE TEMP TRIGGER fault AFTER UPDATE OF acknowledgement ON parity_objects BEGIN UPDATE parity_objects SET bytes=X'00'; END;",
        "CREATE TEMP TRIGGER fault AFTER UPDATE OF acknowledgement ON parity_objects BEGIN UPDATE parity_objects SET verification_hash=zeroblob(32); END;",
    ] {
        store.connection.execute_batch(trigger).unwrap();
        assert!(
            store
                .first_ready_variable_object_with_information_upgrade(
                    |_| Ok::<_, DatabaseError>(())
                )
                .is_err()
        );
        assert_eq!(
            store
                .read_ready_variable_activation(&original.object.group_id, 0)
                .unwrap(),
            original
        );
        store
            .connection
            .execute_batch("DROP TRIGGER fault")
            .unwrap();
    }
    let other = ParityStore::open_with_key(&path, &[36; 16], &[37; 32]).unwrap();
    other
        .connection
        .busy_timeout(std::time::Duration::ZERO)
        .unwrap();
    let mut calls = 0;
    let ready = store
        .first_ready_variable_object_with_information_upgrade(|observed| {
            calls += 1;
            assert_eq!(observed, &original);
            assert!(
                other
                    .connection
                    .execute("UPDATE parity_objects SET acknowledgement=X'01'", [])
                    .is_err()
            );
            Ok::<_, DatabaseError>(())
        })
        .unwrap()
        .unwrap();
    assert_eq!(calls, 2);
    let mut expected = original;
    expected.staged_receipt = expected.verification_hash.to_vec();
    assert_eq!(ready, expected);
    drop(other);
    drop(store);
    let mut store = ParityStore::open_with_key(&path, &[36; 16], &[37; 32]).unwrap();
    assert_eq!(
        store
            .first_ready_variable_object_with_information_upgrade(
                |_| -> Result<(), DatabaseError> { panic!("already upgraded") }
            )
            .unwrap(),
        Some(expected.clone())
    );
    let mut destination =
        ParityStore::open_with_key(temp.path().join("destination.db"), &[38; 16], &[39; 32])
            .unwrap();
    destination
        .copy_ready_variable_object(&ready, 1024)
        .unwrap();
    assert!(
        store
            .remove_ready_variable_object(
                &ready.object.group_id,
                0,
                &ready.object.commitment.root,
                &ready.attempt_id,
                &ready.verification_hash
            )
            .unwrap()
    );
    assert_eq!(store.first_ready_variable_object().unwrap(), None);
    assert_eq!(
        destination.first_ready_variable_object().unwrap(),
        Some(expected)
    );
}

#[test]
fn legacy_information_upgrade_rejects_damaged_activation_before_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let mut store =
        ParityStore::open_with_key(temp.path().join("source.db"), &[36; 16], &[37; 32]).unwrap();
    let original = legacy(&mut store);
    // Model damaged persisted fields independently of current schema checks.
    store
        .connection
        .execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    for (column, replacement) in [
        ("attempt_id", vec![0; 16]),
        ("attempt_id", vec![1; 17]),
        ("verification_hash", vec![0; 32]),
        ("verification_hash", vec![1; 33]),
        ("acknowledgement", vec![1; 65537]),
        ("bytes", vec![1; 64]),
    ] {
        let saved: Vec<u8> = store
            .connection
            .query_row(&format!("SELECT {column} FROM parity_objects"), [], |row| {
                row.get(0)
            })
            .unwrap();
        store
            .connection
            .execute(
                &format!("UPDATE parity_objects SET {column}=?1"),
                [&replacement],
            )
            .unwrap();
        assert!(
            store
                .first_ready_variable_object_with_information_upgrade(
                    |_| -> Result<(), DatabaseError> {
                        panic!("damaged activation reached authentication")
                    }
                )
                .is_err()
        );
        store
            .connection
            .execute(&format!("UPDATE parity_objects SET {column}=?1"), [&saved])
            .unwrap();
        assert_eq!(
            store
                .read_ready_variable_activation(&original.object.group_id, 0)
                .unwrap(),
            original
        );
    }
    store
        .connection
        .execute_batch("PRAGMA ignore_check_constraints=OFF")
        .unwrap();
}
