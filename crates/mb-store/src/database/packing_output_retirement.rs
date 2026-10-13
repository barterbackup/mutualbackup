//! Exact physical deletion; caller holds the control custody writer. Database
//! compaction and WAL reclamation remain separate admission/maintenance work.
use super::*;

impl ParityStore {
    /// Delete only the bound object/reservation for one original shard. Missing
    /// rows are an idempotent success; different identities fail closed. Pins
    /// are checked before deletion and again before committing physical state.
    pub fn discard_coding_attempt_object_checked(
        &mut self,
        attempt: &[u8; 16],
        guild: &[u8; 32],
        storage: &[u8; 32],
        shard: u16,
        commitment: &MerkleCommitment,
        mut pinned: impl FnMut() -> Result<bool, DatabaseError>,
    ) -> Result<bool, DatabaseError> {
        commitment
            .validate()
            .map_err(|_| DatabaseError::Integrity)?;
        if *attempt == [0; 16]
            || *guild == [0; 32]
            || *storage == [0; 32]
            || shard >= MAX_CODING_SHARDS
            || commitment.byte_len > MAX_PROFILE_SHARD_SIZE
        {
            return Err(DatabaseError::Integrity);
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        if pinned()? {
            return Ok(false);
        }
        let object = tx.query_row("SELECT format_version, CASE WHEN length(guild_id)=32 THEN guild_id END,
            CASE WHEN length(root)=32 THEN root END, byte_length, CASE WHEN length(state)<=6 THEN state END,
            CASE WHEN length(attempt_id)=16 THEN attempt_id END, length(bytes)
            FROM parity_objects WHERE group_id=?1 AND shard_index=?2", params![storage.as_slice(),shard],
            |r| Ok((r.get::<_,i64>(0)?,r.get::<_,Option<Vec<u8>>>(1)?,r.get::<_,Option<Vec<u8>>>(2)?,r.get::<_,i64>(3)?,r.get::<_,Option<String>>(4)?,r.get::<_,Option<Vec<u8>>>(5)?,r.get::<_,i64>(6)?))).optional()?;
        if let Some(row) = &object
            && (row.0 != 2
                || row.1.as_deref() != Some(guild.as_slice())
                || row.2.as_deref() != Some(commitment.root.as_slice())
                || row.3 != i64::from(commitment.byte_len)
                || row.6 != row.3
                || !matches!(row.4.as_deref(), Some("STAGED" | "READY"))
                || row.5.as_deref() != Some(attempt.as_slice()))
        {
            return Err(DatabaseError::Integrity);
        }
        let reservation = tx.query_row("SELECT CASE WHEN length(guild_id)=32 THEN guild_id END, byte_length,
            written_until, length(bytes) FROM coding_reservations WHERE attempt_id=?1 AND shard_index=?2",
            params![attempt.as_slice(),shard],|r|Ok((r.get::<_,Option<Vec<u8>>>(0)?,r.get::<_,i64>(1)?,r.get::<_,i64>(2)?,r.get::<_,i64>(3)?))).optional()?;
        if let Some(row) = &reservation
            && (row.0.as_deref() != Some(guild.as_slice())
                || row.1 != i64::from(commitment.byte_len)
                || row.2 < 0
                || row.2 > row.1
                || row.2 % MERKLE_LEAF_SIZE as i64 != 0
                || row.3 != row.1)
        {
            return Err(DatabaseError::Integrity);
        }
        if object.is_some()
            && tx.execute(
                "DELETE FROM parity_objects WHERE group_id=?1 AND shard_index=?2
            AND format_version=2 AND guild_id=?3 AND root=?4 AND byte_length=?5 AND attempt_id=?6
            AND state IN ('STAGED','READY')",
                params![
                    storage.as_slice(),
                    shard,
                    guild.as_slice(),
                    commitment.root.as_slice(),
                    commitment.byte_len,
                    attempt.as_slice()
                ],
            )? != 1
        {
            return Err(DatabaseError::Integrity);
        }
        if reservation.is_some()
            && tx.execute(
                "DELETE FROM coding_reservations WHERE attempt_id=?1 AND shard_index=?2
            AND guild_id=?3 AND byte_length=?4",
                params![
                    attempt.as_slice(),
                    shard,
                    guild.as_slice(),
                    commitment.byte_len
                ],
            )? != 1
        {
            return Err(DatabaseError::Integrity);
        }
        let remaining: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM parity_objects WHERE group_id=?1 AND shard_index=?2)
            OR EXISTS(SELECT 1 FROM coding_reservations WHERE attempt_id=?3 AND shard_index=?2)",
            params![storage.as_slice(), shard, attempt.as_slice()],
            |r| r.get(0),
        )?;
        if remaining || pinned()? {
            return Err(DatabaseError::Integrity);
        }
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store(path: &Path) -> ParityStore {
        ParityStore::open_with_key(path, &[91; 16], &[92; 32]).unwrap()
    }
    fn staged(s: &mut ParityStore, size: usize, ready: bool) -> MerkleCommitment {
        let bytes = (0..size)
            .map(|n| (n * 13 + n / 4096) as u8)
            .collect::<Vec<_>>();
        let commitment = merkle_commit(&bytes).unwrap();
        s.stage_attempt(
            &[93; 16],
            &VariableParityObject {
                format_version: 2,
                guild_id: [94; 32],
                group_id: [95; 32],
                shard_index: 63,
                commitment: commitment.clone(),
                bytes,
            },
            &[96],
            16 << 20,
        )
        .unwrap();
        if ready {
            s.activate_attempt_object(&[93; 16], &[95; 32], 63, &commitment, &[97; 32])
                .unwrap();
        }
        commitment
    }
    #[test]
    fn exact_output_retirement_preserves_other_roles_and_reopens_at_supported_sizes_and_states() {
        for size in [65536, MAX_PROFILE_SHARD_SIZE as usize] {
            for ready in [false, true] {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("parity.db");
                let mut s = store(&path);
                let c = staged(&mut s, size, ready);
                s.reserve_coding_attempt(&[93; 16], &[94; 32], 62, 65536, 16 << 20)
                    .unwrap();
                assert!(
                    !s.discard_coding_attempt_object_checked(
                        &[93; 16],
                        &[94; 32],
                        &[95; 32],
                        63,
                        &c,
                        || Ok(true)
                    )
                    .unwrap()
                );
                assert_eq!(s.variable_object_count().unwrap(), 2);
                assert!(
                    s.discard_coding_attempt_object_checked(
                        &[93; 16],
                        &[94; 32],
                        &[95; 32],
                        63,
                        &c,
                        || Ok(false)
                    )
                    .unwrap()
                );
                assert_eq!(s.variable_object_count().unwrap(), 1);
                drop(s);
                let mut s = store(&path);
                assert!(
                    s.discard_coding_attempt_object_checked(
                        &[93; 16],
                        &[94; 32],
                        &[95; 32],
                        63,
                        &c,
                        || Ok(false)
                    )
                    .unwrap()
                );
                assert_eq!(
                    s.reserve_coding_attempt(&[93; 16], &[94; 32], 62, 65536, 16 << 20)
                        .unwrap(),
                    0
                );
            }
        }
    }
    #[test]
    fn exact_output_retirement_checks_partial_reservations_and_all_original_identity_fields() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = store(&dir.path().join("parity.db"));
        let c = merkle_commit(&vec![9; 65536]).unwrap();
        s.reserve_coding_attempt(&[93; 16], &[94; 32], 63, 65536, 16 << 20)
            .unwrap();
        s.write_coding_attempt_range(&[93; 16], 63, 0, &[9; 16])
            .unwrap();
        assert!(
            s.discard_coding_attempt_object_checked(
                &[93; 16],
                &[98; 32],
                &[95; 32],
                63,
                &c,
                || Ok(false)
            )
            .is_err()
        );
        assert_eq!(s.variable_object_count().unwrap(), 1);
        assert!(
            s.discard_coding_attempt_object_checked(
                &[93; 16],
                &[94; 32],
                &[95; 32],
                63,
                &c,
                || Ok(false)
            )
            .unwrap()
        );
        let c = staged(&mut s, 65536, false);
        let mut wrong = c.clone();
        wrong.root = [98; 32];
        for (attempt, guild, commitment) in [
            ([98; 16], [94; 32], &c),
            ([93; 16], [98; 32], &c),
            ([93; 16], [94; 32], &wrong),
        ] {
            assert!(
                s.discard_coding_attempt_object_checked(
                    &attempt,
                    &guild,
                    &[95; 32],
                    63,
                    commitment,
                    || Ok(false)
                )
                .is_err()
            );
            assert_eq!(s.variable_object_count().unwrap(), 1);
        }
    }
    #[test]
    fn exact_output_retirement_rolls_back_delete_faults_and_late_pin_changes() {
        for table in ["parity_objects", "coding_reservations"] {
            for action in ["ABORT", "IGNORE"] {
                let dir = tempfile::tempdir().unwrap();
                let mut s = store(&dir.path().join("parity.db"));
                let c = if table == "parity_objects" {
                    staged(&mut s, 65536, false)
                } else {
                    s.reserve_coding_attempt(&[93; 16], &[94; 32], 63, 65536, 16 << 20)
                        .unwrap();
                    merkle_commit(&vec![9; 65536]).unwrap()
                };
                let effect = if action == "ABORT" {
                    "RAISE(ABORT,'injected')"
                } else {
                    "RAISE(IGNORE)"
                };
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER physical_fault BEFORE DELETE ON {table} BEGIN SELECT {effect}; END;")).unwrap();
                assert!(
                    s.discard_coding_attempt_object_checked(
                        &[93; 16],
                        &[94; 32],
                        &[95; 32],
                        63,
                        &c,
                        || Ok(false)
                    )
                    .is_err()
                );
                assert_eq!(s.variable_object_count().unwrap(), 1);
                s.connection
                    .execute_batch("DROP TRIGGER physical_fault")
                    .unwrap();
                let mut calls = 0;
                assert!(
                    s.discard_coding_attempt_object_checked(
                        &[93; 16],
                        &[94; 32],
                        &[95; 32],
                        63,
                        &c,
                        || {
                            calls += 1;
                            Ok(calls == 2)
                        }
                    )
                    .is_err()
                );
                assert_eq!(s.variable_object_count().unwrap(), 1);
                assert!(
                    s.discard_coding_attempt_object_checked(
                        &[93; 16],
                        &[94; 32],
                        &[95; 32],
                        63,
                        &c,
                        || Ok(false)
                    )
                    .unwrap()
                );
            }
        }
    }
}
