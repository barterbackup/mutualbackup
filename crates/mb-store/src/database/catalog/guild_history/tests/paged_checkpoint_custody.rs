use super::*;
use crate::database::catalog::paged_checkpoint_retention::Proof;
use crate::{ParityStore, VariableParityObject};
use mb_core::ShardRoleV2;

const CURSOR: &str = "catalog-checkpoint-local-custody-v1";

fn step<P: Proof>(
    control: &ControlStore,
    volume: &ParityStore,
    proof: &P,
    trust: &PagedCheckpointTrust,
    id: Uuid,
    holder: mb_core::NodeId,
) -> Result<CatalogCheckpointLocalCustody, CatalogStoreError> {
    control.checkpoint_local_custody_step(
        id,
        proof,
        holder,
        || Ok(trust.clone()),
        |snapshot| {
            if snapshot.state != CatalogBundleState::Published || snapshot.bootstrap.is_none() {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(())
        },
        |payload| {
            let object = volume.load_ready_variable(&payload.storage_id, payload.shard_index)?;
            if object.guild_id != payload.guild_id
                || object.commitment != payload.commitment
                || mb_core::merkle_commit(&object.bytes).unwrap() != payload.commitment
            {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(())
        },
    )
}

macro_rules! complete_cases {
    ($name:ident, $proof:path, $stage:path, $retain:ident, $cancel:ident, $release:ident) => {
        #[test]
        fn $name() {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("control.db");
            let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let mut volume =
                ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32])
                    .unwrap();
            let (mut fixture, history, bundle, bootstrap) =
                super::paged_checkpoint_revision::private_checkpoint(&control);
            super::paged_checkpoint_revision::publish_private(
                &control,
                &fixture,
                &bundle,
                &bootstrap,
                Uuid::from_u128(500),
            );
            let objects: Vec<VariableParityObject> =
                super::paged_checkpoint_payload::objects(&fixture, &history);
            let proof = $proof(&mut fixture, &history);
            let trust = proof.trust().clone();
            let holder = fixture.paged().value.owner;
            let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
            $stage(&control, &fixture, &proof, 1000);
            for id in ids {
                control.$retain(id, &proof, || Ok(trust.clone())).unwrap();
            }
            let revision = step(&control, &volume, &proof, &trust, ids[0], holder).unwrap();
            assert_eq!(
                revision.phase,
                CatalogCheckpointLocalCustodyPhase::Revisions
            );
            assert_eq!((revision.revisions, revision.local_revisions), (1, 1));
            assert_eq!(revision.coding.groups, 0);
            assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
            drop(control);
            let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let coding = step(&control, &volume, &proof, &trust, ids[0], holder).unwrap();
            assert_eq!(coding.phase, CatalogCheckpointLocalCustodyPhase::Coding);
            let group = step(&control, &volume, &proof, &trust, ids[0], holder).unwrap();
            assert_eq!(group.phase, CatalogCheckpointLocalCustodyPhase::Coding);
            assert_eq!(group.coding.groups, 1);
            assert_eq!(group.local_payloads, 0);
            let physical_holder = history
                .entry
                .retained
                .group
                .roles
                .iter()
                .find_map(|role| match role {
                    ShardRoleV2::Information(role) if !role.sector.virtual_zero => Some(role.owner),
                    _ => None,
                })
                .unwrap();
            assert_ne!(physical_holder, holder);
            let physical_id = Uuid::from_u128(3);
            control
                .$retain(physical_id, &proof, || Ok(trust.clone()))
                .unwrap();
            step(
                &control,
                &volume,
                &proof,
                &trust,
                physical_id,
                physical_holder,
            )
            .unwrap();
            step(
                &control,
                &volume,
                &proof,
                &trust,
                physical_id,
                physical_holder,
            )
            .unwrap();
            let before = control.get_record(CURSOR, physical_id.as_bytes()).unwrap();
            assert!(
                step(
                    &control,
                    &volume,
                    &proof,
                    &trust,
                    physical_id,
                    physical_holder
                )
                .is_err()
            );
            assert_eq!(
                control.get_record(CURSOR, physical_id.as_bytes()).unwrap(),
                before
            );
            // Missing physical custody cannot excuse this holder's assignment.
            assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
            super::paged_checkpoint_payload::stage(&mut volume, &objects, &history);
            let physical = step(
                &control,
                &volume,
                &proof,
                &trust,
                physical_id,
                physical_holder,
            )
            .unwrap();
            let assigned = history
                .entry
                .retained
                .group
                .roles
                .iter()
                .filter(|role| match role {
                    ShardRoleV2::Information(role) => {
                        !role.sector.virtual_zero && role.owner == physical_holder
                    }
                    ShardRoleV2::Parity(role) => role.holder == physical_holder,
                })
                .count() as u64;
            assert!(assigned > 0);
            assert_eq!(physical.local_payloads, assigned);
            assert_eq!(
                step(
                    &control,
                    &volume,
                    &proof,
                    &trust,
                    physical_id,
                    physical_holder
                )
                .unwrap()
                .phase,
                CatalogCheckpointLocalCustodyPhase::Complete
            );
            let complete = step(&control, &volume, &proof, &trust, ids[0], holder).unwrap();
            assert_eq!(complete.phase, CatalogCheckpointLocalCustodyPhase::Complete);
            assert_eq!(
                complete.coding,
                proof.certificate().checkpoint.coding.summary.coding
            );
            assert_eq!(
                step(&control, &volume, &proof, &trust, ids[0], holder).unwrap(),
                complete
            );
            assert!(
                control
                    .checkpoint_head_identity(&trust.guild_id)
                    .unwrap()
                    .is_none()
            );
            for _ in 0..4 {
                step(&control, &volume, &proof, &trust, ids[1], holder).unwrap();
            }
            assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
            control.$cancel(ids[0]).unwrap();
            assert!(
                control
                    .get_record(CURSOR, ids[0].as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(step(&control, &volume, &proof, &trust, ids[0], holder).is_err());
            while control.$release(ids[0]).unwrap() {}
            assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
            assert_eq!(
                step(&control, &volume, &proof, &trust, ids[1], holder)
                    .unwrap()
                    .phase,
                CatalogCheckpointLocalCustodyPhase::Complete
            );
            control.$cancel(ids[1]).unwrap();
            while control.$release(ids[1]).unwrap() {}
            control.cancel_paged_revision_catalog(bundle.id).unwrap();
            control.$cancel(physical_id).unwrap();
            while control.$release(physical_id).unwrap() {}
        }
    };
}
complete_cases!(
    enclosing_local_custody_resumes_private_and_ready_joins_and_preserves_shared_owners,
    super::paged_checkpoint_revision::private_proof,
    super::paged_checkpoint_retention::stage_paged_owner,
    retain_catalog_paged_checkpoint,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
complete_cases!(
    enclosing_directory_local_custody_resumes_private_and_ready_joins_and_preserves_shared_owners,
    super::checkpoint_directories::initial,
    super::checkpoint_directory_retention::stage,
    retain_catalog_paged_checkpoint_directory,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);

#[test]
fn enclosing_local_custody_rejects_missing_revision_and_group_eofs_and_legacy_local_owners() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let volume =
        ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32]).unwrap();
    let (mut fixture, history) = real_checkpoint();
    let proof = super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &proof, 1000);
    let trust = proof.trust();
    let id = Uuid::from_u128(1);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(trust.clone()))
        .unwrap();
    let first = proof.index().next_revision(None).unwrap().unwrap();
    let key = first.revision_key().unwrap();
    assert!(step(&control, &volume, &proof, trust, id, key.owner).is_err());
    let original = control.get_record(CURSOR, id.as_bytes()).unwrap().unwrap();
    let saved: CatalogCheckpointLocalCustody = decode_canonical(&original).unwrap();
    assert_eq!(saved.revisions, 0);
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    // Use a different original member with no private revisions. Its absence
    // of local assignments cannot excuse missing global inventory rows.
    let holder = trust
        .members
        .iter()
        .map(|member| member.node_id)
        .find(|owner| *owner != key.owner && *owner != fixture.paged().value.owner)
        .unwrap();
    let id = Uuid::from_u128(2);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(trust.clone()))
        .unwrap();
    let store = &proof.index().index().packing().store;
    let kind = super::super::super::checkpoint_validation::REVISIONS;
    let bytes = store
        .get_record_bounded(
            kind,
            &key.index_key(),
            mb_core::CATALOG_CHECKPOINT_RECORD_BYTES,
        )
        .unwrap()
        .unwrap();
    store
        .delete_record_if_value(kind, &key.index_key(), &bytes)
        .unwrap();
    // It may visit the second row, but EOF cannot certify a missing first row.
    assert!(step(&control, &volume, &proof, trust, id, holder).is_ok());
    assert!(step(&control, &volume, &proof, trust, id, holder).is_err());
    store
        .put_record_if_absent(kind, &key.index_key(), &bytes)
        .unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    let id = Uuid::from_u128(3);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(trust.clone()))
        .unwrap();
    for _ in 0..3 {
        step(&control, &volume, &proof, trust, id, holder).unwrap();
    }
    let row = proof.index().index().next_group(None).unwrap().unwrap();
    let kind = super::super::super::coding_directory_coverage::GROUPS;
    let group = row.group.range.group_id;
    let bytes = store
        .get_record_bounded(kind, &group, 4096)
        .unwrap()
        .unwrap();
    store.delete_record_if_value(kind, &group, &bytes).unwrap();
    let before = control.get_record(CURSOR, id.as_bytes()).unwrap();
    assert!(step(&control, &volume, &proof, trust, id, holder).is_err());
    assert_eq!(control.get_record(CURSOR, id.as_bytes()).unwrap(), before);
    store.put_record_if_absent(kind, &group, &bytes).unwrap();
}

#[test]
fn enclosing_local_custody_debits_cursor_budget_and_rolls_back_current_head_and_cancel_faults() {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let volume =
        ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32]).unwrap();
    let (mut fixture, history, _, _) =
        super::paged_checkpoint_revision::private_checkpoint(&control);
    let proof = super::paged_checkpoint_revision::private_proof(&mut fixture, &history);
    let minimum = proof
        .transition()
        .represented_work()
        .checked_add(proof.certificate().checkpoint.represented_work().unwrap())
        .unwrap();
    let limited = super::paged_checkpoint_revision::private_proof_with_budget(
        &mut fixture,
        &history,
        minimum,
    );
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &limited, 1000);
    let id = Uuid::from_u128(1);
    control
        .retain_catalog_paged_checkpoint(id, &limited, || Ok(limited.trust().clone()))
        .unwrap();
    assert!(
        step(
            &control,
            &volume,
            &limited,
            limited.trust(),
            id,
            fixture.paged().value.owner
        )
        .is_err()
    );
    assert!(control.get_record(CURSOR, id.as_bytes()).unwrap().is_none());
    let id = Uuid::from_u128(2);
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    let holder = proof
        .trust()
        .members
        .iter()
        .map(|m| m.node_id)
        .find(|owner| *owner != fixture.paged().value.owner)
        .unwrap();
    let header = proof.certificate().checkpoint;
    let activate = format!(
        "INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'01');",
        hex::encode(header.guild_id),
        hex::encode(header.hash().unwrap())
    );
    control.connection.execute_batch(&format!("CREATE TEMP TRIGGER custody_head AFTER INSERT ON protocol_records WHEN NEW.kind = '{CURSOR}' BEGIN {activate} END;")).unwrap();
    assert!(step(&control, &volume, &proof, proof.trust(), id, holder).is_err());
    assert!(control.get_record(CURSOR, id.as_bytes()).unwrap().is_none());
    assert!(
        control
            .checkpoint_head_identity(&header.guild_id)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER custody_head")
        .unwrap();
    step(&control, &volume, &proof, proof.trust(), id, holder).unwrap();
    let original = control.get_record(CURSOR, id.as_bytes()).unwrap().unwrap();
    let other_holder = proof
        .trust()
        .members
        .iter()
        .map(|m| m.node_id)
        .find(|owner| *owner != holder)
        .unwrap();
    assert!(step(&control, &volume, &proof, proof.trust(), id, other_holder).is_err());
    control.connection.execute_batch(&format!("CREATE TEMP TRIGGER advance_custody_head AFTER UPDATE ON protocol_records WHEN NEW.kind = '{CURSOR}' BEGIN {activate} END;")).unwrap();
    assert!(step(&control, &volume, &proof, proof.trust(), id, holder).is_err());
    assert_eq!(
        control
            .get_record(CURSOR, id.as_bytes())
            .unwrap()
            .as_deref(),
        Some(original.as_slice())
    );
    assert!(
        control
            .checkpoint_head_identity(&header.guild_id)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER advance_custody_head")
        .unwrap();
    let mut damaged: CatalogCheckpointLocalCustody = decode_canonical(&original).unwrap();
    damaged.trust_hash[0] ^= 1;
    control
        .put_record(CURSOR, id.as_bytes(), &canonical_bytes(&damaged).unwrap())
        .unwrap();
    assert!(step(&control, &volume, &proof, proof.trust(), id, holder).is_err());
    control
        .put_record(CURSOR, id.as_bytes(), &[0; 1025])
        .unwrap();
    assert!(step(&control, &volume, &proof, proof.trust(), id, holder).is_err());
    control
        .put_record(CURSOR, id.as_bytes(), &original)
        .unwrap();
    control.connection.execute_batch(&format!("CREATE TEMP TRIGGER cancel_custody_head AFTER DELETE ON protocol_records WHEN OLD.kind = '{CURSOR}' BEGIN {activate} END;")).unwrap();
    assert!(
        control
            .cancel_catalog_paged_checkpoint_retention(id)
            .is_err()
    );
    assert_eq!(
        control
            .get_record(CURSOR, id.as_bytes())
            .unwrap()
            .as_deref(),
        Some(original.as_slice())
    );
    assert!(
        control
            .checkpoint_head_identity(&header.guild_id)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER cancel_custody_head")
        .unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    assert!(control.get_record(CURSOR, id.as_bytes()).unwrap().is_none());
}
