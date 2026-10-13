use super::super::packing_authority::tests::Fixture;
use super::*;
use mb_core::{CodingProfile, PackingProfile, merkle_commit};
use std::cell::Cell;

fn policy(slot: u32) -> CatalogCapacityPolicy {
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 1,
        legacy_revisions: 1,
        legacy_source_occurrences: 2,
        data_bytes_per_dataset: 8 * 65536,
        data_sources_per_dataset: 8,
        private_work_per_revision: Work {
            bytes: 65536,
            page_occurrences: 4,
            records: 20000,
        },
        source_pages_per_revision: 4,
        authority_control_records: 257,
        packing_profile: PackingProfile {
            format_version: 1,
            sector_size: 65536,
            slot_size: slot,
        },
        coding_profile: CodingProfile::new(3, 2, 65536),
        packed_sectors: 32,
        coding_groups: 11,
        replay_work: Work::default(),
    }
}
fn op(f: &Fixture, slot: u32) -> CatalogPackingOperation {
    CatalogPackingOperation::new(
        Uuid::new_v4(),
        &f.authority(),
        policy(slot),
        Work {
            bytes: 1 << 30,
            page_occurrences: 1_000_000,
            records: 1_000_000,
        },
        Work {
            bytes: 16 << 20,
            page_occurrences: 4096,
            records: 100_000,
        },
        Work {
            bytes: 16 << 20,
            page_occurrences: 0,
            records: 100_000,
        },
    )
    .unwrap()
}
fn setup(s: &ControlStore, f: &Fixture) {
    let quota = CatalogStorageQuota {
        page_bytes: 1 << 30,
        pages: 65536,
        open_reservations: 16,
    };
    s.configure_catalog_storage_quota(quota).unwrap();
    s.configure_catalog_scoped_storage_quotas(quota, quota)
        .unwrap();
    s.put_record(
        "actual-packing-base",
        b"head",
        &f.certificate.hash().unwrap(),
    )
    .unwrap();
}
fn guard(
    view: &CatalogPackingOperationView<'_>,
    op: CatalogPackingOperation,
) -> Result<(), CatalogStoreError> {
    if view.record("actual-packing-base", b"head", 32)? != Some(op.base.checkpoint_hash.to_vec()) {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
fn input(
    f: &Fixture,
    source: &CatalogPackingAuthorizedSource,
    bytes: &mut [u8],
) -> Result<(), CatalogStoreError> {
    let index = f
        .records
        .iter()
        .position(|r| r.sector.id == source.id.object_id)
        .ok_or(DatabaseError::NotReady)?;
    bytes.copy_from_slice(&f.bytes[index]);
    Ok(())
}
fn stage(
    s: &ControlStore,
    op: CatalogPackingOperation,
    sector: &PackedSector,
    planned: &CatalogPackingOutputAttempt,
) -> Result<CatalogPackingPayload, CatalogStoreError> {
    let p = CatalogPackingPayload {
        guild_id: op.base.guild_id,
        storage_id: planned.storage_id,
        shard_index: 0,
        commitment: sector.descriptor.commitment.clone(),
        attempt_id: planned.attempt_id,
        volume_id: Uuid::from_u128(31),
    };
    s.put_record("actual-packing-ciphertext", &p.storage_id, &sector.bytes)?;
    s.retain_catalog_packing_payload_checked(
        op.payloads(),
        &p,
        (|_| Ok::<_, CatalogStoreError>(()), |p| verify(s, p)),
    )?;
    Ok(p)
}
fn verify(s: &ControlStore, p: &CatalogPackingPayload) -> Result<(), CatalogStoreError> {
    let b = s
        .get_record_bounded("actual-packing-ciphertext", &p.storage_id, 65536)?
        .ok_or(DatabaseError::NotReady)?;
    if merkle_commit(&b).map_err(|_| DatabaseError::Integrity)? != p.commitment {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn run(
    s: &ControlStore,
    f: &Fixture,
    op: CatalogPackingOperation,
) -> Result<CatalogCertifiedPackingDirectoryIndex, CatalogStoreError> {
    s.produce_catalog_packing_operation_checked(
        op,
        f.authority(),
        (
            |v| guard(v, op),
            |v, a| {
                guard(v, op)?;
                if a.operation_identity()? != op.source_identity {
                    return Err(DatabaseError::Conflict.into());
                }
                Ok(())
            },
        ),
        (
            |source, b| input(f, source, b),
            |sector, planned| stage(s, op, sector, planned),
        ),
        |p| verify(s, p),
    )
}

#[test]
fn packing_operation_owns_complete_original_directory_and_payloads_through_reopen_retry_and_cancel()
{
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let s = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    let proof = run(&s, &f, op).unwrap();
    let manifest = proof.manifest();
    assert!(manifest.directory.summary.sectors > 0);
    assert_eq!(
        s.catalog_packing_operation(op.id).unwrap(),
        Some((op, CatalogPackingOperationState::PackingComplete(manifest)))
    );
    for close in [
        s.cancel_catalog_packing_source_retention(op.sources()),
        s.cancel_catalog_packing_payload_retention(op.payloads()),
        s.cancel_catalog(op.pages()),
    ] {
        assert!(close.is_err());
    }
    assert!(s.release_catalog_pin(op.pages()).is_err());
    assert!(s.release_catalog_packing_payload(op.payloads()).is_err());
    assert!(s.release_catalog_packing_source(op.sources()).is_err());
    assert!(
        s.publish_catalog(op.pages(), manifest.directory.records.page)
            .is_err()
    );
    drop(proof);
    drop(s);
    let s = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    let replay = s
        .produce_catalog_packing_operation_checked(
            op,
            f.authority(),
            (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
            (
                |_, _| {
                    panic!(
                        "completed retry reads retained output instead of missing original sources"
                    )
                },
                |_, _| panic!("no duplicate output staging"),
            ),
            |p| verify(&s, p),
        )
        .unwrap();
    assert_eq!(replay.manifest(), manifest);
    s.cancel_catalog_packing_operation(op).unwrap();
    s.cancel_catalog_packing_operation(op).unwrap();
    assert!(run(&s, &f, op).is_err());
    while s.release_catalog_packing_payload(op.payloads()).unwrap() {}
    while s.release_catalog_pin(op.pages()).unwrap() {}
    assert!(
        s.catalog_page(
            op.pages().scope,
            CatalogSection::Packing,
            manifest.directory.records.page
        )
        .is_ok()
    );
    while s.collect_catalog_page().unwrap() {}
    assert!(
        s.catalog_page(
            op.pages().scope,
            CatalogSection::Packing,
            manifest.directory.records.page
        )
        .is_err()
    );
}

#[test]
fn packing_operation_failed_prefix_replays_exact_input_and_rejects_policy_base_and_source_substitution()
 {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    let calls = Cell::new(0);
    let result = s.produce_catalog_packing_operation_checked(
        op,
        f.authority(),
        (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
        (
            |src, b| input(&f, src, b),
            |sector, planned| {
                calls.set(calls.get() + 1);
                if calls.get() == 2 {
                    return Err(DatabaseError::Conflict.into());
                }
                stage(&s, op, sector, planned)
            },
        ),
        |p| verify(&s, p),
    );
    assert!(result.is_err());
    assert_eq!(
        s.catalog_packing_operation(op.id).unwrap().unwrap().1,
        CatalogPackingOperationState::Building
    );
    let before = s.records(&outputs(op.id)).unwrap();
    for dimension in 0..3 {
        let mut wrong = op;
        match dimension {
            0 => wrong.policy.packed_sectors += 1,
            1 => wrong.base.checkpoint_hash = [91; 32],
            _ => wrong.source_identity = [92; 32],
        };
        assert!(run(&s, &f, wrong).is_err());
        assert_eq!(s.records(&outputs(op.id)).unwrap(), before);
    }
    run(&s, &f, op).unwrap();
    assert_eq!(calls.get(), 2);
}

#[test]
fn packing_operation_rejects_insufficient_aggregate_admission_before_any_source_or_output_io() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    setup(&s, &f);
    let exact = op(&f, 16384);
    let needed = exact
        .fixed()
        .unwrap()
        .checked_add(exact.authority_work)
        .unwrap()
        .checked_add(exact.policy.plan().unwrap().packing_coding.packing.work)
        .unwrap();
    for dimension in 0..3 {
        let mut bad = exact;
        bad.id = Uuid::new_v4();
        bad.budget = needed;
        match dimension {
            0 => bad.budget.bytes -= 1,
            1 => bad.budget.page_occurrences -= 1,
            _ => bad.budget.records -= 1,
        };
        assert!(
            s.produce_catalog_packing_operation_checked(
                bad,
                f.authority(),
                (
                    |_| Ok::<_, CatalogStoreError>(()),
                    |_, _| panic!("admission before custody callbacks")
                ),
                (
                    |_, _| panic!("admission before source reads"),
                    |_, _| panic!("admission before output writes")
                ),
                |_| Ok(())
            )
            .is_err()
        );
        assert!(s.catalog_packing_operation(bad.id).unwrap().is_none());
    }
}

#[test]
fn packing_operation_requires_every_exact_output_loan_and_original_complete_proof() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    let result = s.produce_catalog_packing_operation_checked(
        op,
        f.authority(),
        (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
        (
            |src, b| input(&f, src, b),
            |sector, planned| {
                Ok(CatalogPackingPayload {
                    guild_id: op.base.guild_id,
                    storage_id: planned.storage_id,
                    shard_index: 0,
                    commitment: sector.descriptor.commitment.clone(),
                    attempt_id: planned.attempt_id,
                    volume_id: Uuid::from_u128(31),
                })
            },
        ),
        |_| Ok(()),
    );
    assert!(result.is_err());
    assert!(s.records(&outputs(op.id)).unwrap().is_empty());
    run(&s, &f, op).unwrap();
}

#[test]
fn packing_operation_late_head_failure_rolls_back_completion_and_keeps_all_children_owned() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    s.connection.execute_batch("CREATE TEMP TRIGGER late_operation AFTER UPDATE ON protocol_records WHEN NEW.kind='catalog-packing-operation-v1' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='actual-packing-base'; END;").unwrap();
    assert!(run(&s, &f, op).is_err());
    assert_eq!(
        s.get_record("actual-packing-base", b"head").unwrap(),
        Some(op.base.checkpoint_hash.to_vec())
    );
    assert!(
        s.cancel_catalog_packing_source_retention(op.sources())
            .is_err()
    );
    s.connection
        .execute_batch("DROP TRIGGER late_operation")
        .unwrap();
    run(&s, &f, op).unwrap();
}

#[test]
fn packing_operation_sql_faults_roll_back_initialization_planning_and_output_joins() {
    for kind in [
        JOURNAL,
        ROLE,
        ROLE_GUARD,
        "catalog-packing-operation-attempt-v1/",
        "catalog-packing-operation-output-v1/",
    ] {
        for action in ["ABORT", "IGNORE"] {
            let dir = tempfile::tempdir().unwrap();
            let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
            let f = Fixture::new(true, false);
            let op = op(&f, 16384);
            setup(&s, &f);
            let effect = if action == "ABORT" {
                "RAISE(ABORT, 'injected')"
            } else {
                "RAISE(IGNORE)"
            };
            s.connection.execute_batch(&format!("CREATE TEMP TRIGGER packing_fault BEFORE INSERT ON protocol_records WHEN NEW.kind LIKE '{kind}%' BEGIN SELECT {effect}; END;")).unwrap();
            assert!(run(&s, &f, op).is_err(), "{kind} {action}");
            if [JOURNAL, ROLE, ROLE_GUARD].contains(&kind) {
                assert!(s.catalog_packing_operation(op.id).unwrap().is_none());
                assert!(s.catalog_intent_state(op.pages()).is_err());
            } else {
                assert_eq!(
                    s.catalog_packing_operation(op.id).unwrap(),
                    Some((op, CatalogPackingOperationState::Building))
                );
                assert!(s.cancel_catalog(op.pages()).is_err());
            }
            s.connection
                .execute_batch("DROP TRIGGER packing_fault")
                .unwrap();
            run(&s, &f, op).unwrap();
        }
    }
}

#[test]
fn packing_operation_cancel_faults_preserve_all_children_and_payloads() {
    for action in ["ABORT", "IGNORE"] {
        let dir = tempfile::tempdir().unwrap();
        let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
        let f = Fixture::new(true, false);
        let op = op(&f, 16384);
        setup(&s, &f);
        run(&s, &f, op).unwrap();
        let before = s.catalog_packing_operation(op.id).unwrap();
        let effect = if action == "ABORT" {
            "RAISE(ABORT, 'injected')"
        } else {
            "RAISE(IGNORE)"
        };
        s.connection.execute_batch(&format!("CREATE TEMP TRIGGER packing_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='{JOURNAL}' BEGIN SELECT {effect}; END;")).unwrap();
        assert!(s.cancel_catalog_packing_operation(op).is_err());
        assert_eq!(s.catalog_packing_operation(op.id).unwrap(), before);
        assert!(s.release_catalog_packing_payload(op.payloads()).is_err());
        assert!(s.release_catalog_pin(op.pages()).is_err());
        s.connection
            .execute_batch("DROP TRIGGER packing_fault")
            .unwrap();
        s.cancel_catalog_packing_operation(op).unwrap();
        assert!(s.release_catalog_packing_payload(op.payloads()).unwrap());
    }
}

#[test]
fn packing_operation_planned_attempts_survive_preloan_failure_and_use_private_storage_ids() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("control.db");
    let s = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    let mut planned = None;
    assert!(
        s.produce_catalog_packing_operation_checked(
            op,
            f.authority(),
            (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
            (
                |source, bytes| input(&f, source, bytes),
                |sector, attempt| {
                    assert_eq!(attempt.sector_id, sector.descriptor.id);
                    assert_ne!(attempt.storage_id, attempt.sector_id);
                    assert_eq!(attempt, &op.output_attempt(sector));
                    planned = Some(attempt.clone());
                    Err(DatabaseError::Conflict.into())
                }
            ),
            |_| Ok(())
        )
        .is_err()
    );
    drop(s);
    let s = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
    let first = s
        .next_catalog_packing_operation_attempt(op, None)
        .unwrap()
        .unwrap();
    assert_eq!(Some(first.clone()), planned);
    assert!(
        s.next_catalog_packing_operation_attempt(op, Some(first.sector_id))
            .unwrap()
            .is_none()
    );
    assert!(s.records(&outputs(op.id)).unwrap().is_empty());
    run(&s, &f, op).unwrap();
    s.cancel_catalog_packing_operation(op).unwrap();
    let mut cursor = None;
    let mut found = false;
    while let Some(value) = s
        .next_catalog_packing_operation_attempt(op, cursor)
        .unwrap()
    {
        found |= value == first;
        cursor = Some(value.sector_id);
    }
    assert!(found);
}

#[test]
fn packing_operation_missing_parent_or_one_sided_role_cannot_unlock_child_cleanup() {
    for kind in [JOURNAL, ROLE, ROLE_GUARD] {
        let dir = tempfile::tempdir().unwrap();
        let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
        let f = Fixture::new(true, false);
        let op = op(&f, 16384);
        setup(&s, &f);
        s.begin_catalog_packing_operation_checked(
            op,
            &f.authority(),
            (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
        )
        .unwrap();
        s.connection
            .execute("DELETE FROM protocol_records WHERE kind=?1", [kind])
            .unwrap();
        assert!(s.catalog_packing_operation(op.id).is_err());
        assert!(
            s.cancel_catalog_packing_source_retention(op.sources())
                .is_err()
        );
        assert!(
            s.cancel_catalog_packing_payload_retention(op.payloads())
                .is_err()
        );
        assert!(s.cancel_catalog(op.pages()).is_err());
        assert!(s.release_catalog_pin(op.pages()).is_err());
    }
}

#[test]
fn packing_operation_keeps_complete_directory_parts_at_supported_slot_boundaries() {
    for slot in [16, 32768] {
        let dir = tempfile::tempdir().unwrap();
        let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
        let f = Fixture::new(true, false);
        let op = op(&f, slot);
        setup(&s, &f);
        let fresh = || {
            CatalogPackingAuthority::from_legacy_checkpoint(
                f.certificate.hash().unwrap(),
                &f.certificate,
                crate::RecordScratchStore::new(128 << 20).unwrap(),
            )
            .unwrap()
        };
        let proof = s
            .produce_catalog_packing_operation_checked(
                op,
                fresh(),
                (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
                (
                    |source, bytes| input(&f, source, bytes),
                    |sector, planned| stage(&s, op, sector, planned),
                ),
                |payload| verify(&s, payload),
            )
            .unwrap();
        let manifest = proof.manifest();
        while s.collect_catalog_page().unwrap() {}
        let replay = fresh()
            .validate_packing_directory(manifest, op.construction_budget().unwrap(), |page| {
                s.catalog_page(manifest.scope, CatalogSection::Packing, page)
            })
            .unwrap();
        replay.require_complete().unwrap();
        assert_eq!(replay.manifest(), manifest);
        s.complete_catalog_packing_operation_checked(
            op,
            &replay,
            |v| guard(v, op),
            |p| verify(&s, p),
        )
        .unwrap();
    }
}

#[test]
fn cancelled_packing_output_retirement_waits_for_loans_and_retires_one_exact_plan() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    run(&s, &f, op).unwrap();
    let plan = s
        .next_catalog_packing_operation_attempt(op, None)
        .unwrap()
        .unwrap();
    let retire = || {
        s.retire_catalog_packing_operation_output_checked(
            op,
            &plan,
            |v| guard(v, op),
            |_, _, _| Ok::<_, CatalogStoreError>(true),
        )
    };
    assert!(retire().is_err());
    s.cancel_catalog_packing_operation(op).unwrap();
    assert!(
        !s.retire_catalog_packing_operation_output_checked(
            op,
            &plan,
            |v| guard(v, op),
            |_, _, _| panic!("owned output cannot reach physical cleanup")
        )
        .unwrap()
    );
    while s.release_catalog_packing_payload(op.payloads()).unwrap() {}
    let before = s.records(&attempts(op.id)).unwrap().len();
    assert!(
        s.retire_catalog_packing_operation_output_checked(
            op,
            &plan,
            |v| guard(v, op),
            |_, p, output| {
                assert_eq!(p, &plan);
                assert_eq!(output.unwrap().storage_id, plan.storage_id);
                Ok::<_, CatalogStoreError>(true)
            }
        )
        .unwrap()
    );
    assert_eq!(s.records(&attempts(op.id)).unwrap().len(), before - 1);
    assert!(
        s.get_record(&outputs(op.id), &plan.sector_id)
            .unwrap()
            .is_none()
    );
    assert!(
        s.retire_catalog_packing_operation_output_checked(
            op,
            &plan,
            |v| guard(v, op),
            |_, _, _| panic!("retired retry does no physical I/O")
        )
        .unwrap()
    );
    assert!(run(&s, &f, op).is_err());
}

#[test]
fn cancelled_packing_output_retirement_preserves_offline_plans_and_rejects_substitution() {
    let dir = tempfile::tempdir().unwrap();
    let s = ControlStore::open_with_key(dir.path().join("control.db"), &[7; 32]).unwrap();
    let f = Fixture::new(true, false);
    let op = op(&f, 16384);
    setup(&s, &f);
    assert!(
        s.produce_catalog_packing_operation_checked(
            op,
            f.authority(),
            (|v| guard(v, op), |_, _| Ok::<_, CatalogStoreError>(())),
            (
                |src, bytes| input(&f, src, bytes),
                |_, _| Err(DatabaseError::Conflict.into())
            ),
            |_| Ok(())
        )
        .is_err()
    );
    s.cancel_catalog_packing_operation(op).unwrap();
    let plan = s
        .next_catalog_packing_operation_attempt(op, None)
        .unwrap()
        .unwrap();
    assert!(
        !s.retire_catalog_packing_operation_output_checked(
            op,
            &plan,
            |v| guard(v, op),
            |_, _, output| {
                assert!(output.is_none());
                Ok::<_, CatalogStoreError>(false)
            }
        )
        .unwrap()
    );
    assert_eq!(
        s.next_catalog_packing_operation_attempt(op, None).unwrap(),
        Some(plan.clone())
    );
    let mut wrong = plan.clone();
    wrong.attempt_id = [94; 16];
    assert!(
        s.retire_catalog_packing_operation_output_checked(
            op,
            &wrong,
            |v| guard(v, op),
            |_, _, _| panic!("substitution before physical cleanup")
        )
        .is_err()
    );
    assert!(
        s.retire_catalog_packing_operation_output_checked(
            op,
            &plan,
            |v| guard(v, op),
            |_, _, _| Ok::<_, CatalogStoreError>(true)
        )
        .unwrap()
    );
    assert!(
        s.next_catalog_packing_operation_attempt(op, None)
            .unwrap()
            .is_none()
    );
}

#[test]
fn cancelled_packing_output_retirement_faults_keep_plans_after_physical_success_and_retry() {
    for kind in [
        "catalog-packing-operation-output-v1/",
        "catalog-packing-operation-attempt-v1/",
        JOURNAL,
    ] {
        for action in ["ABORT", "IGNORE"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("control.db");
            let s = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let f = Fixture::new(true, false);
            let op = op(&f, 16384);
            setup(&s, &f);
            run(&s, &f, op).unwrap();
            s.cancel_catalog_packing_operation(op).unwrap();
            while s.release_catalog_packing_payload(op.payloads()).unwrap() {}
            let plan = s
                .next_catalog_packing_operation_attempt(op, None)
                .unwrap()
                .unwrap();
            let event = if kind == JOURNAL { "UPDATE" } else { "DELETE" };
            let row = if kind == JOURNAL { "NEW" } else { "OLD" };
            let effect = if action == "ABORT" {
                "RAISE(ABORT,'injected')"
            } else {
                "RAISE(IGNORE)"
            };
            s.connection.execute_batch(&format!("CREATE TEMP TRIGGER retirement_fault BEFORE {event} ON protocol_records WHEN {row}.kind LIKE '{kind}%' BEGIN SELECT {effect}; END;")).unwrap();
            let physical = Cell::new(true);
            assert!(
                s.retire_catalog_packing_operation_output_checked(
                    op,
                    &plan,
                    |v| guard(v, op),
                    |_, _, _| {
                        physical.set(false);
                        Ok::<_, CatalogStoreError>(true)
                    }
                )
                .is_err(),
                "{kind} {action}"
            );
            assert!(!physical.get());
            assert_eq!(
                s.next_catalog_packing_operation_attempt(op, None).unwrap(),
                Some(plan.clone())
            );
            assert!(
                s.get_record(&outputs(op.id), &plan.sector_id)
                    .unwrap()
                    .is_some()
            );
            drop(s);
            let s = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert!(
                s.retire_catalog_packing_operation_output_checked(
                    op,
                    &plan,
                    |v| guard(v, op),
                    |_, _, _| {
                        assert!(!physical.get());
                        Ok::<_, CatalogStoreError>(true)
                    }
                )
                .unwrap()
            );
        }
    }
}
