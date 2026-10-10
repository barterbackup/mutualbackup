use super::*;
use crate::{ParityStore, VariableParityObject};

struct PayloadFixture {
    temp: tempfile::TempDir,
    control: ControlStore,
    volume: ParityStore,
    proof: CatalogQuorumPagedCheckpointIndex,
    objects: Vec<VariableParityObject>,
    attempt: [u8; 16],
}

pub(super) fn objects(
    fixture: &super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
) -> Vec<VariableParityObject> {
    let (_, _, inputs) = fixture.packing_inputs_with_byte_roots();
    let group = &history.entry.retained.group;
    let bytes = mb_core::encode(
        group.profile,
        inputs.bytes[..usize::from(group.profile.data_shards)].to_vec(),
    )
    .unwrap();
    group
        .roles
        .iter()
        .enumerate()
        .map(|(index, role)| {
            let (storage, commitment) = match role {
                mb_core::ShardRoleV2::Information(role) => {
                    (role.sector.id, role.sector.commitment.clone())
                }
                mb_core::ShardRoleV2::Parity(role) => (group.id, role.commitment.clone()),
            };
            VariableParityObject {
                format_version: 2,
                guild_id: group.guild_id,
                group_id: storage,
                shard_index: index as u16,
                commitment,
                bytes: bytes[index].clone(),
            }
        })
        .collect()
}

pub(super) fn stage(volume: &mut ParityStore, objects: &[VariableParityObject], history: &History) {
    let attempt = history.entry.transcript.value.plan.value.attempt_id;
    let hash = *blake3::hash(&canonical_bytes(&history.entry.transcript).unwrap()).as_bytes();
    for object in objects {
        // Store-level evidence tests use one physical codeword database. Node
        // fixtures separately enforce the actual local holder and signed upload.
        volume
            .stage_attempt(&attempt, object, b"store fixture evidence", 16 << 20)
            .unwrap();
        volume
            .activate_attempt_object(
                &attempt,
                &object.group_id,
                object.shard_index,
                &object.commitment,
                &hash,
            )
            .unwrap();
    }
}

fn fixture() -> PayloadFixture {
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let mut volume =
        ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32]).unwrap();
    let (mut authority, history) = real_checkpoint();
    let objects = objects(&authority, &history);
    stage(&mut volume, &objects, &history);
    let proof =
        super::paged_checkpoint_retention::paged_owner_proof(&mut authority, &history, None);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &authority, &proof, 1000);
    for id in [Uuid::from_u128(1), Uuid::from_u128(2)] {
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .unwrap();
    }
    PayloadFixture {
        temp,
        control,
        volume,
        proof,
        objects,
        attempt: history.entry.transcript.value.plan.value.attempt_id,
    }
}

fn retain(
    control: &ControlStore,
    volume: &ParityStore,
    proof: &CatalogQuorumPagedCheckpointIndex,
    id: Uuid,
    group: [u8; 32],
    shard: u16,
) -> Result<CatalogCheckpointPayload, CatalogStoreError> {
    control.retain_catalog_paged_checkpoint_payload_checked(
        id,
        proof,
        group,
        shard,
        || Ok(proof.trust().clone()),
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

fn collect(
    control: &ControlStore,
    volume: &mut ParityStore,
    object: &VariableParityObject,
) -> Result<bool, CatalogStoreError> {
    control.with_catalog_checkpoint_payload_retirement(|view| {
        if view.is_pinned(object.group_id, object.shard_index, object.commitment.root)? {
            return Ok(false);
        }
        Ok(volume.remove_ready(
            &object.group_id,
            object.shard_index as u8,
            &object.commitment.root,
        )?)
    })
}

#[test]
fn checkpoint_payload_custody_reopens_shares_and_survives_attempt_rollback_until_bounded_retirement()
 {
    let PayloadFixture {
        temp,
        control,
        mut volume,
        proof,
        objects,
        attempt,
    } = fixture();
    let group = proof
        .index()
        .index()
        .next_group(None)
        .unwrap()
        .unwrap()
        .group
        .range
        .group_id;
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    let info = retain(&control, &volume, &proof, first, group, 0).unwrap();
    let parity = retain(&control, &volume, &proof, first, group, 3).unwrap();
    assert_eq!(
        retain(&control, &volume, &proof, first, group, 0).unwrap(),
        info
    );
    retain(&control, &volume, &proof, second, group, 0).unwrap();
    assert!(
        info.replay_work.bytes > 0
            && info.replay_work.page_occurrences > 0
            && info.replay_work.records > 0
    );
    drop(control);
    drop(volume);
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    volume = ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32]).unwrap();
    assert_eq!(
        control
            .catalog_paged_checkpoint_payload(first, group, 3)
            .unwrap(),
        Some(parity)
    );
    assert!(!collect(&control, &mut volume, &objects[0]).unwrap());
    assert!(!collect(&control, &mut volume, &objects[3]).unwrap());
    control
        .with_catalog_checkpoint_payload_retirement(|view| -> Result<(), CatalogStoreError> {
            volume.discard_uncommitted_attempt_checked(
                &attempt,
                &Default::default(),
                |id, shard, root| {
                    view.is_pinned(id, shard, root)
                        .map_err(|_| DatabaseError::Integrity)
                },
            )?;
            Ok(())
        })
        .unwrap();
    assert!(volume.load_ready_variable(&objects[0].group_id, 0).is_ok());
    assert!(volume.load_ready_variable(&objects[3].group_id, 3).is_ok());
    assert!(volume.load_ready_variable(&objects[4].group_id, 4).is_err());
    control
        .cancel_catalog_paged_checkpoint_retention(first)
        .unwrap();
    assert!(
        control
            .release_catalog_paged_checkpoint_root(first)
            .unwrap()
    );
    assert!(
        control
            .catalog_paged_checkpoint_payload(first, group, 0)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .catalog_paged_checkpoint_payload(first, group, 3)
            .unwrap()
            .is_some()
    );
    assert!(
        control
            .release_catalog_paged_checkpoint_root(first)
            .unwrap()
    );
    assert!(
        control
            .catalog_paged_checkpoint_certificate(first)
            .unwrap()
            .is_some()
    );
    assert!(collect(&control, &mut volume, &objects[3]).unwrap());
    assert!(!collect(&control, &mut volume, &objects[0]).unwrap());
    while control
        .release_catalog_paged_checkpoint_root(first)
        .unwrap()
    {}
    assert!(retain(&control, &volume, &proof, first, group, 0).is_err());
    control
        .cancel_catalog_paged_checkpoint_retention(second)
        .unwrap();
    while control
        .release_catalog_paged_checkpoint_root(second)
        .unwrap()
    {}
    assert!(collect(&control, &mut volume, &objects[0]).unwrap());
}

#[test]
fn checkpoint_payload_custody_serializes_volume_delete_with_acquisition_and_preserves_live_bytes() {
    let PayloadFixture {
        temp,
        control,
        mut volume,
        proof,
        objects,
        ..
    } = fixture();
    let other = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    other
        .connection
        .busy_timeout(std::time::Duration::ZERO)
        .unwrap();
    let group = proof
        .index()
        .index()
        .next_group(None)
        .unwrap()
        .unwrap()
        .group
        .range
        .group_id;
    control.retain_catalog_paged_checkpoint_payload_checked(Uuid::from_u128(1), &proof, group, 0,
        || Ok(proof.trust().clone()), |payload| -> Result<(), CatalogStoreError> {
            assert!(other.connection.execute("INSERT INTO protocol_records(kind, record_id, bytes) VALUES ('test-writer', X'01', X'01')", []).is_err());
            let ready = volume.load_ready_variable(&payload.storage_id, payload.shard_index)?;
            assert_eq!(ready.bytes, objects[0].bytes);
            Ok(())
        }).unwrap();
    control.with_catalog_checkpoint_payload_retirement(|view| -> Result<(), CatalogStoreError> {
        assert!(other.connection.execute("INSERT INTO protocol_records(kind, record_id, bytes) VALUES ('test-writer', X'01', X'01')", []).is_err());
        assert!(view.is_pinned(objects[0].group_id, 0, objects[0].commitment.root)?);
        Ok(())
    }).unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(Uuid::from_u128(1))
        .unwrap();
    assert!(
        control
            .release_catalog_paged_checkpoint_root(Uuid::from_u128(1))
            .unwrap()
    );
    assert!(collect(&control, &mut volume, &objects[0]).unwrap());
    assert!(retain(&control, &volume, &proof, Uuid::from_u128(2), group, 0).is_err());
    assert!(
        control
            .catalog_paged_checkpoint_payload(Uuid::from_u128(2), group, 0)
            .unwrap()
            .is_none()
    );
}

#[test]
fn checkpoint_payload_custody_rolls_back_pin_counter_and_current_head_faults() {
    let PayloadFixture {
        control,
        mut volume,
        proof,
        objects,
        ..
    } = fixture();
    let id = Uuid::from_u128(1);
    let group = proof
        .index()
        .index()
        .next_group(None)
        .unwrap()
        .unwrap()
        .group
        .range
        .group_id;
    let forward = format!("catalog-checkpoint-payload-v1/{}", id.simple());
    let reverse = format!(
        "catalog-payload-checkpoint-v1/{}/{:04x}",
        hex::encode(objects[0].group_id),
        0
    );
    let totals = "catalog-checkpoint-payload-work-v1";
    for kind in [&forward, &reverse, totals] {
        control.connection.execute_batch(&format!("CREATE TEMP TRIGGER fail_payload_insert BEFORE INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
        assert!(retain(&control, &volume, &proof, id, group, 0).is_err());
        assert!(
            control
                .catalog_paged_checkpoint_payload(id, group, 0)
                .unwrap()
                .is_none()
        );
        assert!(control.get_record(totals, id.as_bytes()).unwrap().is_none());
        control
            .connection
            .execute_batch("DROP TRIGGER fail_payload_insert")
            .unwrap();
    }
    let changed = std::cell::Cell::new(false);
    let mut stale = proof.trust().clone();
    stale.event_head[0] ^= 1;
    assert!(
        control
            .retain_catalog_paged_checkpoint_payload_checked(
                id,
                &proof,
                group,
                0,
                || Ok(if changed.get() {
                    stale.clone()
                } else {
                    proof.trust().clone()
                }),
                |_| {
                    changed.set(true);
                    Ok::<_, CatalogStoreError>(())
                }
            )
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_payload(id, group, 0)
            .unwrap()
            .is_none()
    );
    let checkpoint = proof.certificate().checkpoint;
    let activate = format!(
        "INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'00');",
        hex::encode(checkpoint.guild_id),
        hex::encode(checkpoint.hash().unwrap())
    );
    control.connection.execute_batch(&format!("CREATE TEMP TRIGGER change_payload_acquisition AFTER INSERT ON protocol_records WHEN NEW.kind = '{forward}' BEGIN {activate} END;")).unwrap();
    assert!(retain(&control, &volume, &proof, id, group, 0).is_err());
    assert!(
        control
            .checkpoint_head_identity(&checkpoint.guild_id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .catalog_paged_checkpoint_payload(id, group, 0)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER change_payload_acquisition")
        .unwrap();
    let payload = retain(&control, &volume, &proof, id, group, 0).unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    let mut forward_key = group.to_vec();
    forward_key.extend(0_u16.to_be_bytes());
    let mut reverse_key = id.as_bytes().to_vec();
    reverse_key.extend(&forward_key);
    for (kind, key) in [
        (forward.as_str(), forward_key.as_slice()),
        (reverse.as_str(), reverse_key.as_slice()),
        (totals, id.as_bytes().as_slice()),
    ] {
        let original = control.get_record(kind, key).unwrap().unwrap();
        control.put_record(kind, key, &[0; 513]).unwrap();
        assert!(collect(&control, &mut volume, &objects[0]).is_err());
        assert_eq!(
            volume.load_ready_variable(&objects[0].group_id, 0).unwrap(),
            objects[0]
        );
        control.put_record(kind, key, &original).unwrap();
    }
    let original = control.get_record(&forward, &forward_key).unwrap().unwrap();
    control.delete_record(&forward, &forward_key).unwrap();
    assert!(collect(&control, &mut volume, &objects[0]).is_err());
    assert_eq!(
        volume.load_ready_variable(&objects[0].group_id, 0).unwrap(),
        objects[0]
    );
    control
        .put_record(&forward, &forward_key, &original)
        .unwrap();
    for (operation, kind) in [
        ("DELETE", forward.as_str()),
        ("DELETE", reverse.as_str()),
        ("UPDATE", totals),
    ] {
        control.connection.execute_batch(&format!("CREATE TEMP TRIGGER fail_payload_release BEFORE {operation} ON protocol_records WHEN OLD.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END;")).unwrap();
        assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
        assert_eq!(
            control
                .catalog_paged_checkpoint_payload(id, group, 0)
                .unwrap(),
            Some(payload.clone())
        );
        control
            .connection
            .execute_batch("DROP TRIGGER fail_payload_release")
            .unwrap();
    }
    let checkpoint = proof.certificate().checkpoint;
    let activate = format!(
        "INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'00');",
        hex::encode(checkpoint.guild_id),
        hex::encode(checkpoint.hash().unwrap())
    );
    control.connection.execute_batch(&format!("CREATE TEMP TRIGGER change_payload_head AFTER DELETE ON protocol_records WHEN OLD.kind = '{forward}' BEGIN {activate} END;")).unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    assert!(
        control
            .checkpoint_head_identity(&checkpoint.guild_id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .catalog_checkpoint_payload_is_pinned(payload.storage_id, 0, payload.commitment.root)
            .unwrap()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER change_payload_head")
        .unwrap();
    control.connection.execute_batch(&activate).unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    control
        .connection
        .execute(
            "DELETE FROM checkpoint_heads WHERE guild_id = ?1",
            params![checkpoint.guild_id],
        )
        .unwrap();
    let counter = control.get_record(totals, id.as_bytes()).unwrap().unwrap();
    control
        .put_record(totals, id.as_bytes(), &[0; 513])
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    control.put_record(totals, id.as_bytes(), &counter).unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).unwrap());
}

#[test]
fn checkpoint_payload_custody_shares_one_budget_with_private_revision_dependencies_in_both_orders()
{
    use super::paged_checkpoint_revision as private;
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let mut volume =
        ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32]).unwrap();
    let (mut authority, history, bundle, bootstrap) = private::private_checkpoint(&control);
    private::publish_private(
        &control,
        &authority,
        &bundle,
        &bootstrap,
        Uuid::from_u128(500),
    );
    let objects = objects(&authority, &history);
    stage(&mut volume, &objects, &history);
    let proof = private::private_proof(&mut authority, &history);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &authority, &proof, 1000);
    let group = history.entry.retained.group.id;
    let key = mb_core::CatalogCheckpointRevisionKey::from(&authority.paged().value);
    let id = Uuid::from_u128(1);
    let owner = control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    control
        .retain_catalog_paged_checkpoint_revision_checked(
            id,
            &proof,
            key,
            || Ok(proof.trust().clone()),
            |_| Ok::<_, CatalogStoreError>(()),
        )
        .unwrap();
    retain(&control, &volume, &proof, id, group, 0).unwrap();
    let private_work =
        super::super::super::paged_checkpoint_revision::owned_work(&control.connection, owner)
            .unwrap()
            .unwrap();
    let payload_work =
        super::super::super::paged_checkpoint_payload::owned_work(&control.connection, owner)
            .unwrap()
            .unwrap();
    let one = Work {
        bytes: private_work.bytes.max(payload_work.bytes),
        page_occurrences: private_work
            .page_occurrences
            .max(payload_work.page_occurrences),
        records: private_work.records.max(payload_work.records),
    };
    let public = proof
        .transition()
        .represented_work()
        .checked_add(proof.certificate().checkpoint.represented_work().unwrap())
        .unwrap();
    let limited = private::private_proof_with_budget(
        &mut authority,
        &history,
        public.checked_add(one).unwrap(),
    );
    for (id, private_first) in [(Uuid::from_u128(2), true), (Uuid::from_u128(3), false)] {
        control
            .retain_catalog_paged_checkpoint(id, &limited, || Ok(limited.trust().clone()))
            .unwrap();
        if private_first {
            control
                .retain_catalog_paged_checkpoint_revision_checked(
                    id,
                    &limited,
                    key,
                    || Ok(limited.trust().clone()),
                    |_| Ok::<_, CatalogStoreError>(()),
                )
                .unwrap();
            assert!(retain(&control, &volume, &limited, id, group, 0).is_err());
            assert!(
                control
                    .catalog_paged_checkpoint_payload(id, group, 0)
                    .unwrap()
                    .is_none()
            );
        } else {
            retain(&control, &volume, &limited, id, group, 0).unwrap();
            assert!(
                control
                    .retain_catalog_paged_checkpoint_revision_checked(
                        id,
                        &limited,
                        key,
                        || Ok(limited.trust().clone()),
                        |_| Ok::<_, CatalogStoreError>(())
                    )
                    .is_err()
            );
            assert!(
                control
                    .catalog_paged_checkpoint_revision(id, bundle.id)
                    .unwrap()
                    .is_none()
            );
        }
    }
}
