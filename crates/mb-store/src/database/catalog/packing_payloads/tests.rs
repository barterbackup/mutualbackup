use super::*;
use std::cell::Cell;

fn retention() -> CatalogPackingPayloadRetention {
    CatalogPackingPayloadRetention {
        id: Uuid::new_v4(),
        base: CatalogPackingAuthorityBase {
            guild_id: [71; 32],
            checkpoint_hash: [72; 32],
            generation: 1,
            membership_epoch: Some(1),
        },
        budget: Work {
            bytes: 8 * 1024 * 1024,
            page_occurrences: 0,
            records: 100,
        },
    }
}
fn payload() -> CatalogPackingPayload {
    CatalogPackingPayload {
        guild_id: [71; 32],
        storage_id: [73; 32],
        shard_index: 63,
        commitment: mb_core::merkle_commit(&[74; 64]).unwrap(),
        attempt_id: [75; 16],
        volume_id: Uuid::from_u128(76),
    }
}
fn begin(s: &ControlStore, r: CatalogPackingPayloadRetention) -> Result<(), CatalogStoreError> {
    s.begin_catalog_packing_payload_retention(r, |_| Ok(()))
}
fn retain(
    s: &ControlStore,
    r: CatalogPackingPayloadRetention,
    p: &CatalogPackingPayload,
) -> Result<(), CatalogStoreError> {
    s.retain_catalog_packing_payload_checked(r, p, (|_| Ok(()), |_| Ok(())))
}
fn pinned(s: &ControlStore, p: &CatalogPackingPayload) -> Result<bool, CatalogStoreError> {
    s.catalog_checkpoint_payload_is_pinned(p.storage_id, p.shard_index, p.commitment.root)
}
fn attempt_pinned(s: &ControlStore, p: &CatalogPackingPayload) -> Result<bool, CatalogStoreError> {
    s.with_catalog_checkpoint_payload_retirement(|view| view.attempt_is_pinned(p.attempt_id))
}
fn rows(s: &ControlStore) -> Vec<crate::ProtocolRecordRow> {
    s.records(JOURNAL).unwrap()
}

#[test]
fn packing_payload_loans_reopen_share_exact_physical_identity_and_release_one_at_a_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let s = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let p = payload();
    let mut q = p.clone();
    q.storage_id = [77; 32];
    let a = retention();
    let b = retention();
    for r in [a, b] {
        begin(&s, r).unwrap();
        retain(&s, r, &p).unwrap();
    }
    retain(&s, a, &q).unwrap();
    let old = rows(&s);
    retain(&s, a, &p).unwrap();
    assert_eq!(rows(&s), old);
    assert!(s.release_catalog_packing_payload(a).is_err());
    drop(s);
    let s = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    for r in [a, b] {
        assert_eq!(
            s.catalog_packing_payload(r, p.storage_id, p.shard_index)
                .unwrap(),
            Some(p.clone())
        );
    }
    assert!(pinned(&s, &p).unwrap() && attempt_pinned(&s, &p).unwrap());
    s.cancel_catalog_packing_payload_retention(a).unwrap();
    assert!(pinned(&s, &p).unwrap());
    assert!(retain(&s, a, &p).is_err() && begin(&s, a).is_err());
    assert!(s.release_catalog_packing_payload(a).unwrap());
    assert!(s.release_catalog_packing_payload(a).unwrap());
    assert!(!s.release_catalog_packing_payload(a).unwrap());
    assert!(pinned(&s, &p).unwrap() && attempt_pinned(&s, &p).unwrap());
    assert!(!pinned(&s, &q).unwrap());
    s.cancel_catalog_packing_payload_retention(b).unwrap();
    assert!(s.release_catalog_packing_payload(b).unwrap());
    assert!(!pinned(&s, &p).unwrap() && !attempt_pinned(&s, &p).unwrap());
    assert_eq!(s.records(COUNTS).unwrap().len(), 2);
    assert_eq!(s.records(ATTEMPT_COUNTS).unwrap().len(), 1);
}

#[test]
fn packing_payload_admission_rejects_each_insufficient_budget_before_verification_and_reauthenticates_retries()
 {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let p = payload();
    let exact = fixed().checked_add(p.work()).unwrap();
    for dimension in 0..2 {
        let mut r = retention();
        r.budget = exact;
        if dimension == 0 {
            r.budget.bytes -= 1;
        } else {
            r.budget.records -= 1;
        }
        begin(&s, r).unwrap();
        assert!(
            s.retain_catalog_packing_payload_checked(
                r,
                &p,
                (
                    |_| Ok::<_, CatalogStoreError>(()),
                    |_| -> Result<(), CatalogStoreError> { panic!("quota before verification") }
                )
            )
            .is_err()
        );
        assert!(
            s.catalog_packing_payload(r, p.storage_id, p.shard_index)
                .unwrap()
                .is_none()
        );
    }
    let mut r = retention();
    r.budget = exact;
    begin(&s, r).unwrap();
    let calls = Cell::new(0);
    for _ in 0..2 {
        s.retain_catalog_packing_payload_checked(
            r,
            &p,
            (
                |_| Ok::<_, CatalogStoreError>(()),
                |_| {
                    calls.set(calls.get() + 1);
                    Ok(())
                },
            ),
        )
        .unwrap();
    }
    assert_eq!(calls.get(), 2);
    assert_eq!(
        journal(&s.connection, r.id)
            .unwrap()
            .unwrap()
            .work()
            .unwrap(),
        exact
    );
}

#[test]
fn packing_payload_substitution_and_invalid_geometry_fail_before_physical_callbacks() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let p = payload();
    let r = retention();
    begin(&s, r).unwrap();
    retain(&s, r, &p).unwrap();
    for field in 0..6 {
        let mut changed = p.clone();
        match field {
            0 => changed.guild_id = [80; 32],
            1 => changed.volume_id = Uuid::new_v4(),
            2 => changed.attempt_id = [81; 16],
            3 => changed.commitment = mb_core::merkle_commit(&[82; 64]).unwrap(),
            4 => changed.shard_index = mb_core::MAX_CODING_SHARDS,
            _ => changed.commitment.byte_len = 1,
        }
        assert!(
            s.retain_catalog_packing_payload_checked(
                r,
                &changed,
                (
                    |_| Ok::<_, CatalogStoreError>(()),
                    |_| -> Result<(), CatalogStoreError> {
                        panic!("substituted identity before physical reads")
                    }
                )
            )
            .is_err()
        );
    }
    let mut wrong = r;
    wrong.base.generation += 1;
    assert!(begin(&s, wrong).is_err());
    wrong = r;
    wrong.budget.bytes += 1;
    assert!(begin(&s, wrong).is_err());
    assert_eq!(
        s.catalog_packing_payload(r, p.storage_id, p.shard_index)
            .unwrap(),
        Some(p)
    );
}

#[test]
fn packing_payload_private_and_late_current_base_failures_roll_back_custody_and_head() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let p = payload();
    let r = retention();
    begin(&s, r).unwrap();
    assert!(
        s.retain_catalog_packing_payload_checked(
            r,
            &p,
            (
                |_| Ok::<_, CatalogStoreError>(()),
                |_| Err(CatalogStoreError::from(DatabaseError::Integrity))
            )
        )
        .is_err()
    );
    s.put_record("actual-base", b"head", &[1]).unwrap();
    let guard = |view: &CatalogPackingPayloadView<'_>| -> Result<(), CatalogStoreError> {
        if view.record("actual-base", b"head", 1)? != Some(vec![1]) {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    };
    let kind = payloads(r.id);
    s.connection.execute_batch(&format!("CREATE TEMP TRIGGER late_payload AFTER INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN UPDATE protocol_records SET bytes = X'02' WHERE kind = 'actual-base'; END;")).unwrap();
    assert!(
        s.retain_catalog_packing_payload_checked(
            r,
            &p,
            (guard, |_| Ok::<_, CatalogStoreError>(()))
        )
        .is_err()
    );
    assert!(!pinned(&s, &p).unwrap());
    assert_eq!(s.get_record("actual-base", b"head").unwrap(), Some(vec![1]));
    s.connection
        .execute_batch("DROP TRIGGER late_payload")
        .unwrap();
    s.retain_catalog_packing_payload_checked(r, &p, (guard, |_| Ok::<_, CatalogStoreError>(())))
        .unwrap();
}

#[test]
fn packing_payload_abort_and_ignore_at_every_acquire_and_release_boundary_roll_back_and_retry() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    for acquiring in [true, false] {
        for fault in ["ABORT", "IGNORE"] {
            for boundary in 0..6 {
                let r = retention();
                let mut p = payload();
                p.storage_id = *Uuid::new_v4()
                    .as_bytes()
                    .repeat(2)
                    .first_chunk::<32>()
                    .unwrap();
                p.attempt_id = *Uuid::new_v4().as_bytes();
                begin(&s, r).unwrap();
                if !acquiring {
                    retain(&s, r, &p).unwrap();
                    s.cancel_catalog_packing_payload_retention(r).unwrap();
                }
                let before = rows(&s);
                let kind = match boundary {
                    0 => payloads(r.id),
                    1 => owners(&p.key()),
                    2 => attempts(p.attempt_id),
                    3 => COUNTS.into(),
                    4 => ATTEMPT_COUNTS.into(),
                    _ => JOURNAL.into(),
                };
                let op = if boundary == 5 {
                    "UPDATE"
                } else if acquiring {
                    "INSERT"
                } else if boundary < 3 {
                    "DELETE"
                } else {
                    "UPDATE"
                };
                let row = if op == "DELETE" { "OLD" } else { "NEW" };
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER output_fault BEFORE {op} ON protocol_records WHEN {row}.kind = '{kind}' BEGIN SELECT RAISE({fault}{}); END;",if fault=="ABORT" {", 'injected'"} else {""})).unwrap();
                let result = if acquiring {
                    retain(&s, r, &p).map(|_| true)
                } else {
                    s.release_catalog_packing_payload(r)
                };
                assert!(result.is_err(), "{acquiring} {fault} {boundary}");
                assert_eq!(rows(&s), before);
                assert_eq!(pinned(&s, &p).unwrap(), !acquiring);
                assert_eq!(attempt_pinned(&s, &p).unwrap(), !acquiring);
                s.connection
                    .execute_batch("DROP TRIGGER output_fault")
                    .unwrap();
                if acquiring {
                    retain(&s, r, &p).unwrap();
                } else {
                    assert!(s.release_catalog_packing_payload(r).unwrap());
                }
            }
        }
    }
}

#[test]
fn packing_payload_damaged_forward_reverse_attempt_counts_and_journals_preserve_pins_fail_closed() {
    for damage in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
        let r = retention();
        let p = payload();
        begin(&s, r).unwrap();
        retain(&s, r, &p).unwrap();
        let (kind, key) = match damage {
            0 => (payloads(r.id), p.key().to_vec()),
            1 => (owners(&p.key()), r.id.as_bytes().to_vec()),
            2 => (attempts(p.attempt_id), reverse(r.id, p.key()).to_vec()),
            3 => (COUNTS.into(), p.key().to_vec()),
            4 => (ATTEMPT_COUNTS.into(), p.attempt_id.to_vec()),
            _ => (JOURNAL.into(), r.id.as_bytes().to_vec()),
        };
        let bytes = s.get_record(&kind, &key).unwrap().unwrap();
        s.delete_record(&kind, &key).unwrap();
        assert!(pinned(&s, &p).is_err(), "{damage}");
        assert!(retain(&s, r, &p).is_err());
        s.put_record(&kind, &key, &bytes).unwrap();
        assert!(pinned(&s, &p).unwrap());
        s.cancel_catalog_packing_payload_retention(r).unwrap();
        assert!(s.release_catalog_packing_payload(r).unwrap());
    }
}

#[test]
fn packing_payload_pin_checks_reject_oversized_owner_keys_before_allocation() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let p = payload();
    let r = retention();
    begin(&s, r).unwrap();
    retain(&s, r, &p).unwrap();
    s.connection
        .execute(
            "UPDATE protocol_records SET record_id = zeroblob(1048576) WHERE kind = ?1",
            [owners(&p.key())],
        )
        .unwrap();
    assert!(pinned(&s, &p).is_err());
    assert!(retain(&s, r, &p).is_err());
}

#[test]
fn packing_payload_attempt_locator_retirement_requires_exact_bound_identity_and_keeps_owned_records()
 {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let r = retention();
    let p = payload();
    begin(&s, r).unwrap();
    retain(&s, r, &p).unwrap();
    let bytes = canonical_bytes(&(1_u16, p.attempt_id, p.volume_id, p.guild_id)).unwrap();
    let kind = "volume-attempt-reservation";
    let key = b"exact-fixture-key";
    s.put_record(kind, key, &bytes).unwrap();
    s.with_catalog_checkpoint_payload_retirement(|view| -> Result<(), CatalogStoreError> {
        assert!(!view.retire_attempt_record(kind, key, p.attempt_id, &bytes)?);
        assert!(
            view.retire_attempt_record(kind, key, [83; 16], &bytes)
                .is_err()
        );
        assert!(
            view.retire_attempt_record(JOURNAL, key, p.attempt_id, &bytes)
                .is_err()
        );
        Ok(())
    })
    .unwrap();
    s.cancel_catalog_packing_payload_retention(r).unwrap();
    s.release_catalog_packing_payload(r).unwrap();
    s.with_catalog_checkpoint_payload_retirement(|view| -> Result<(), CatalogStoreError> {
        assert!(view.retire_attempt_record(kind, key, p.attempt_id, &bytes)?);
        Ok(())
    })
    .unwrap();
    assert!(s.get_record(kind, key).unwrap().is_none());
}
