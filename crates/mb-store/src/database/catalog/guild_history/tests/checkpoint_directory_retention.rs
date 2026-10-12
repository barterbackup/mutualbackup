use super::checkpoint_directories::{body_with_budget, certificate};
use super::paged_checkpoint_retention::{
    assert_owned_public_reads, retire_owner_captures, stage_owner_roots,
};
use super::*;
use crate::database::catalog::paged_checkpoint_retention::Proof;
use crate::database::catalog::retention_journal::{self as journal, Dependency};
use mb_core::{CatalogCheckpointAuthorityRecord as R, CatalogPackingDirectoryRecord};

type Fixture = super::super::super::checkpoint_validation::tests::Fixture;
type Root = (CatalogScope, CatalogSection, CatalogPageRef);

pub(super) fn proof(
    fixture: &mut Fixture,
    history: &History,
    limit: Work,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    successor(fixture, history, None, limit)
}

pub(super) fn successor(
    fixture: &mut Fixture,
    history: &History,
    previous: Option<&CatalogQuorumPagedCheckpointDirectoryIndex>,
    limit: Work,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    let mut trust = history.trust();
    trust.previous = previous.map(|previous| mb_core::PagedCheckpointParent {
        generation: previous.certificate().checkpoint.generation,
        hash: previous.certificate().hash().unwrap(),
    });
    let reader = real_reader(history, &trust);
    let transition = body_with_budget(fixture, history, &reader, &trust, true, limit)
        .validate_certified_history_authority_transition(
            previous.map(CatalogCheckpointPrevious::Directory),
            &reader,
            limit,
            || Ok(trust.clone()),
        )
        .unwrap();
    certificate(transition, history)
}

pub(super) fn stage(
    control: &ControlStore,
    fixture: &Fixture,
    proof: &CatalogQuorumPagedCheckpointDirectoryIndex,
    offset: u128,
) -> (Vec<CatalogIntent>, Vec<Root>) {
    let header = proof.certificate().checkpoint;
    let scope = CatalogScope::Guild {
        guild_id: header.guild_id,
    };
    let mut roots = vec![
        (
            scope,
            CatalogSection::Checkpoint,
            header.authority_root.records.page,
        ),
        (scope, CatalogSection::Packing, header.packing.records.page),
        (scope, CatalogSection::Coding, header.coding.records.page),
    ];
    for record in &fixture.records {
        match record {
            R::LegacyRevision(revision) => {
                roots.push((scope, CatalogSection::Checkpoint, revision.body))
            }
            R::PagedRevision(revision) => roots.push((
                revision.value.scope(),
                CatalogSection::SectorReferences,
                revision.value.sources.records.page,
            )),
            _ => {}
        }
    }
    let mut packing =
        mb_core::CatalogPackingDirectoryReader::new(scope, header.packing, budget()).unwrap();
    let mut fetch =
        |page: CatalogPageRef| Ok::<_, CatalogStoreError>(fixture.pages[&page.hash].clone());
    let mut part = |part| {
        roots.push((
            scope,
            CatalogSection::Packing,
            match part {
                CatalogPackingDirectoryRecord::Sources(part) => part.root.records.page,
                CatalogPackingDirectoryRecord::Sectors(part) => part.root.records.page,
            },
        ));
        Ok::<_, CatalogStoreError>(())
    };
    while packing
        .next_source_with_part(&mut fetch, &mut part)
        .unwrap()
        .is_some()
    {}
    while packing
        .next_sector_with_part(
            &mut fetch,
            &mut |key| proof.index().index().packing().source_id(key),
            &mut part,
        )
        .unwrap()
        .is_some()
    {}
    let mut coding =
        mb_core::CatalogCodingDirectoryReader::new(scope, header.coding, budget()).unwrap();
    while coding
        .next_group_with_forest(&mut fetch, &mut |root: &mb_core::CatalogCodingRoot| {
            roots.extend(
                root.parts
                    .iter()
                    .map(|part| (scope, CatalogSection::Coding, part.page)),
            );
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap()
        .is_some()
    {}
    stage_owner_roots(control, &fixture.pages, &roots, offset)
}

fn retain(
    control: &ControlStore,
    id: Uuid,
    proof: &CatalogQuorumPagedCheckpointDirectoryIndex,
) -> CatalogPagedCheckpointDirectoryRetention {
    control
        .retain_catalog_paged_checkpoint_directory(id, proof, || Ok(proof.trust().clone()))
        .unwrap()
}

fn retire(control: &ControlStore, id: Uuid) {
    control
        .cancel_catalog_paged_checkpoint_directory_retention(id)
        .unwrap();
    while control
        .release_catalog_paged_checkpoint_directory_root(id)
        .unwrap()
    {}
    while control.collect_catalog_page().unwrap() {}
}

#[test]
fn directory_owner_reopens_and_preserves_every_nested_root_after_staging_and_shared_owner_retirement()
 {
    let (mut fixture, history) = real_checkpoint();
    let proof = proof(&mut fixture, &history, budget());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("owner.db");
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let (captures, roots) = stage(&control, &fixture, &proof, 1000);
    assert!(roots.len() > 8);
    let first = retain(&control, Uuid::from_u128(1), &proof);
    let second = retain(&control, Uuid::from_u128(2), &proof);
    assert_eq!(retain(&control, first.id, &proof), first);
    retire_owner_captures(&control, &captures);
    retire(&control, first.id);
    drop(control);
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert_eq!(
        control
            .catalog_paged_checkpoint_directory_retention(second.id)
            .unwrap(),
        Some((second, CatalogPagedCheckpointRetentionState::Published))
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_directory_certificate(second.id)
            .unwrap()
            .as_ref(),
        Some(proof.certificate())
    );
    assert!(
        control
            .checkpoint_head_identity(&history.state.guild_id)
            .unwrap()
            .is_none()
    );
    for (scope, section, root) in &roots {
        control.catalog_page(*scope, *section, *root).unwrap();
    }
    let layout = mb_core::PagedCheckpointLayout::Directory;
    let hash = proof.certificate().hash().unwrap();
    let certificate = canonical_bytes(proof.certificate()).unwrap();
    let reader = ControlStore::open_existing_read_only_with_key(
        &path,
        &history.keys[0].database_key(crate::database::CONTROL_DATABASE_ID),
    )
    .unwrap();
    reader
        .with_read_only_snapshot(|| {
            assert_owned_public_reads(
                &reader,
                layout,
                second.id,
                (history.state.guild_id, hash),
                &certificate,
                &roots,
            );
            Ok(())
        })
        .unwrap();
    drop(reader);
    retire(&control, second.id);
    assert!(
        control
            .catalog_retained_paged_checkpoint_certificate(
                layout,
                history.state.guild_id,
                second.id,
                hash
            )
            .unwrap()
            .is_none()
    );
    let (scope, section, root) = roots[0];
    assert!(
        control
            .catalog_retained_paged_checkpoint_public_page(
                layout,
                second.id,
                hash,
                &mb_core::CatalogPagePath {
                    scope,
                    section,
                    pages: vec![root]
                }
            )
            .unwrap()
            .is_none()
    );
    for (scope, section, root) in roots {
        assert!(control.catalog_page(scope, section, root).is_err());
    }
    assert!(
        control
            .catalog_paged_checkpoint_directory_certificate(second.id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(first.id, &proof, || Ok(proof
                .trust()
                .clone()))
            .is_err()
    );
}

#[test]
fn directory_owner_replays_exact_interrupted_descriptor_and_fences_changed_retry_and_current_successors()
 {
    let (mut fixture, history) = real_checkpoint();
    let previous = proof(&mut fixture, &history, budget());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("owner.db");
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let (captures, roots) = stage(&control, &fixture, &previous, 1000);
    let id = Uuid::from_u128(1);
    let descriptor = previous.retention(id).unwrap();
    control
        .with_record_transaction(|| -> Result<(), CatalogStoreError> {
            journal::begin(&control.connection, descriptor)?;
            super::super::super::insert_exact(
                &control.connection,
                "catalog-directory-checkpoint-certificate-v1",
                id.as_bytes(),
                &canonical_bytes(previous.certificate()).unwrap(),
            )?;
            for (scope, section, root) in roots.iter().take(4) {
                journal::retain(
                    &control.connection,
                    descriptor,
                    Dependency {
                        scope: *scope,
                        section: *section,
                        root: *root,
                    },
                )?;
            }
            Ok(())
        })
        .unwrap();
    drop(control);
    let mut control = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert_eq!(
        control
            .catalog_paged_checkpoint_directory_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Building
    );
    let changed = proof(
        &mut fixture,
        &history,
        Work {
            records: budget().records + 1,
            ..budget()
        },
    );
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(id, &changed, || Ok(changed.trust().clone()))
            .is_err()
    );
    assert_eq!(retain(&control, id, &previous), descriptor);
    let commit = |control: &mut ControlStore,
                  proof: &CatalogQuorumPagedCheckpointDirectoryIndex| {
        let h = proof.certificate().checkpoint;
        control
            .commit_checkpoint(
                &h.guild_id,
                h.generation,
                h.parent.as_ref(),
                &h.hash().unwrap(),
                &canonical_bytes(&h).unwrap(),
                &canonical_bytes(proof.certificate()).unwrap(),
                false,
            )
            .unwrap();
    };
    // Only the existing raw test hook writes the head; custody never activates.
    commit(&mut control, &previous);
    assert!(
        control
            .cancel_catalog_paged_checkpoint_directory_retention(id)
            .is_err()
    );
    let next = successor(&mut fixture, &history, Some(&previous), budget());
    let (next_captures, _) = stage(&control, &fixture, &next, 2000);
    let next_owner = retain(&control, Uuid::from_u128(2), &next);
    commit(&mut control, &next);
    retire_owner_captures(&control, &captures);
    retire_owner_captures(&control, &next_captures);
    retire(&control, id);
    assert!(
        control
            .cancel_catalog_paged_checkpoint_directory_retention(next_owner.id)
            .is_err()
    );
    assert!(
        control
            .release_catalog_paged_checkpoint_directory_root(next_owner.id)
            .is_err()
    );
    for (scope, section, root) in roots {
        control.catalog_page(scope, section, root).unwrap();
    }
}

#[test]
fn directory_owner_rejects_external_only_authority_and_missing_local_part_eof() {
    let (mut fixture, history) = real_checkpoint();
    let trust = history.trust();
    let reader = real_reader(&history, &trust);
    let draft = certificate(
        body_with_budget(&mut fixture, &history, &reader, &trust, false, budget())
            .validate_authority_transition(
                None,
                budget(),
                || Ok(trust.clone()),
                |owner, state| {
                    reader
                        .view(|| Ok(trust.clone()))?
                        .current_writer(owner, state)
                },
            )
            .unwrap(),
        &history,
    );
    assert!(!draft.transition().has_certified_history_transition());
    let full = proof(&mut fixture, &history, budget());
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open(temp.path().join("owner.db"), &history.keys[0]).unwrap();
    let id = Uuid::from_u128(1);
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(id, &draft, || panic!(
                "draft rejected before trust or pins"
            ))
            .is_err()
    );
    let (_, roots) = stage(&control, &fixture, &full, 1000);
    let missing = roots
        .iter()
        .skip(3)
        .find(|(_, section, _)| *section == CatalogSection::Packing)
        .unwrap()
        .2;
    control
        .delete_record("catalog-page-v1", &missing.hash)
        .unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(id, &full, || Ok(full.trust().clone()))
            .is_err()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_directory_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Cancelled
    );
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(id, &full, || Ok(full.trust().clone()))
            .is_err()
    );
}

#[test]
fn directory_owner_rolls_back_initial_nested_pin_and_final_event_head_faults() {
    let (mut fixture, history) = real_checkpoint();
    let proof = proof(&mut fixture, &history, budget());
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open(temp.path().join("owner.db"), &history.keys[0]).unwrap();
    let (_, roots) = stage(&control, &fixture, &proof, 1000);
    for (number, root) in [
        (1, roots[1].2),
        (
            2,
            roots
                .iter()
                .skip(3)
                .find(|(_, section, _)| *section == CatalogSection::Packing)
                .unwrap()
                .2,
        ),
    ] {
        let id = Uuid::from_u128(number);
        control.connection.execute_batch(&format!("CREATE TRIGGER ignore_dependency BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-directory-checkpoint-dependency-v1/{}' AND NEW.record_id = X'{}' BEGIN SELECT RAISE(IGNORE); END;", id.simple(), hex::encode(root.hash))).unwrap();
        assert!(
            control
                .retain_catalog_paged_checkpoint_directory(id, &proof, || Ok(proof.trust().clone()))
                .is_err()
        );
        control
            .connection
            .execute_batch("DROP TRIGGER ignore_dependency")
            .unwrap();
        if number == 1 {
            assert!(
                control
                    .catalog_paged_checkpoint_directory_retention(id)
                    .unwrap()
                    .is_none()
            );
        } else {
            assert_eq!(
                control
                    .catalog_paged_checkpoint_directory_retention(id)
                    .unwrap()
                    .unwrap()
                    .1,
                CatalogPagedCheckpointRetentionState::Cancelled
            );
            while control
                .release_catalog_paged_checkpoint_directory_root(id)
                .unwrap()
            {}
        }
    }
    let id = Uuid::from_u128(3);
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(id, &proof, || {
                let mut trust = proof.trust().clone();
                if control
                    .catalog_paged_checkpoint_directory_retention(id)?
                    .is_some_and(|(_, state)| {
                        state == CatalogPagedCheckpointRetentionState::Published
                    })
                {
                    trust.event_head[0] ^= 1;
                }
                Ok(trust)
            })
            .is_err()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_directory_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Cancelled
    );
    assert!(
        control
            .checkpoint_head_identity(&history.state.guild_id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn directory_owner_certificate_and_release_faults_preserve_the_last_root_atomically() {
    let (mut fixture, history) = real_checkpoint();
    let proof = proof(&mut fixture, &history, budget());
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open(temp.path().join("owner.db"), &history.keys[0]).unwrap();
    stage(&control, &fixture, &proof, 1000);
    let id = Uuid::from_u128(1);
    control.connection.execute_batch("CREATE TRIGGER ignore_certificate BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-directory-checkpoint-certificate-v1' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_directory_retention(id)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER ignore_certificate")
        .unwrap();
    retain(&control, id, &proof);
    control
        .cancel_catalog_paged_checkpoint_directory_retention(id)
        .unwrap();
    while journal::read::<CatalogPagedCheckpointDirectoryRetention>(&control.connection, id)
        .unwrap()
        .unwrap()
        .roots
        > 1
    {
        control
            .release_catalog_paged_checkpoint_directory_root(id)
            .unwrap();
    }
    let before =
        journal::read::<CatalogPagedCheckpointDirectoryRetention>(&control.connection, id).unwrap();
    for corrupt in [vec![0], vec![0; mb_core::PAGED_QUORUM_CHECKPOINT_BYTES + 1]] {
        control
            .put_record(
                "catalog-directory-checkpoint-certificate-v1",
                id.as_bytes(),
                &corrupt,
            )
            .unwrap();
        assert!(
            control
                .catalog_paged_checkpoint_directory_certificate(id)
                .is_err()
        );
        assert!(
            control
                .release_catalog_paged_checkpoint_directory_root(id)
                .is_err()
        );
        assert_eq!(
            journal::read::<CatalogPagedCheckpointDirectoryRetention>(&control.connection, id)
                .unwrap(),
            before
        );
    }
    control
        .put_record(
            "catalog-directory-checkpoint-certificate-v1",
            id.as_bytes(),
            &canonical_bytes(proof.certificate()).unwrap(),
        )
        .unwrap();
    control.connection.execute_batch("CREATE TRIGGER ignore_certificate_delete BEFORE DELETE ON protocol_records WHEN OLD.kind = 'catalog-directory-checkpoint-certificate-v1' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(
        control
            .release_catalog_paged_checkpoint_directory_root(id)
            .is_err()
    );
    assert_eq!(
        journal::read::<CatalogPagedCheckpointDirectoryRetention>(&control.connection, id).unwrap(),
        before
    );
    control
        .connection
        .execute_batch("DROP TRIGGER ignore_certificate_delete")
        .unwrap();
    assert!(
        control
            .release_catalog_paged_checkpoint_directory_root(id)
            .unwrap()
    );
    assert!(
        !control
            .release_catalog_paged_checkpoint_directory_root(id)
            .unwrap()
    );
    assert!(
        control
            .catalog_paged_checkpoint_directory_certificate(id)
            .unwrap()
            .is_none()
    );
}

#[test]
fn directory_and_individual_owners_cannot_alias_private_payload_backlinks_through_the_same_uuid() {
    let (mut fixture, history) = real_checkpoint();
    let directory = proof(&mut fixture, &history, budget());
    let original =
        super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open(temp.path().join("owner.db"), &history.keys[0]).unwrap();
    stage(&control, &fixture, &directory, 1000);
    super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &original, 2000);
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    retain(&control, first, &directory);
    assert!(
        control
            .retain_catalog_paged_checkpoint(first, &original, || Ok(original.trust().clone()))
            .is_err()
    );
    control
        .retain_catalog_paged_checkpoint(second, &original, || Ok(original.trust().clone()))
        .unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint_directory(second, &directory, || Ok(directory
                .trust()
                .clone()))
            .is_err()
    );
    retire(&control, first);
    assert!(
        control
            .retain_catalog_paged_checkpoint(first, &original, || Ok(original.trust().clone()))
            .is_err()
    );
}

fn retain_private(
    control: &ControlStore,
    id: Uuid,
    proof: &CatalogQuorumPagedCheckpointDirectoryIndex,
    fixture: &Fixture,
) -> Result<PagedCatalogSnapshot, CatalogStoreError> {
    control.retain_catalog_paged_checkpoint_directory_revision_checked(
        id,
        proof,
        mb_core::CatalogCheckpointRevisionKey::from(&fixture.paged().value),
        || Ok(proof.trust().clone()),
        |_| Ok(()),
    )
}

fn retain_payload(
    control: &ControlStore,
    volume: &crate::ParityStore,
    id: Uuid,
    proof: &CatalogQuorumPagedCheckpointDirectoryIndex,
    group: [u8; 32],
    shard: u16,
) -> Result<CatalogCheckpointPayload, CatalogStoreError> {
    control.retain_catalog_paged_checkpoint_directory_payload_checked(
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

#[test]
fn directory_private_custody_preserves_original_bootstrap_and_native_anchor_with_individual_owner_sharing()
 {
    use super::paged_checkpoint_revision as private;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    let (mut fixture, history, bundle, bootstrap) = private::private_checkpoint(&control);
    let anchor = Uuid::from_u128(500);
    let data = private::publish_private(&control, &fixture, &bundle, &bootstrap, anchor);
    let directory = proof(&mut fixture, &history, budget());
    let original = private::private_proof(&mut fixture, &history);
    let (captures, _) = stage(&control, &fixture, &directory, 1000);
    let (original_captures, _) =
        super::paged_checkpoint_retention::stage_paged_owner(&control, &fixture, &original, 2000);
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    retain(&control, first, &directory);
    control
        .retain_catalog_paged_checkpoint(second, &original, || Ok(original.trust().clone()))
        .unwrap();
    let snapshot = retain_private(&control, first, &directory, &fixture).unwrap();
    assert_eq!(snapshot.bootstrap.as_deref(), Some(bootstrap.as_slice()));
    control
        .retain_catalog_paged_checkpoint_revision_checked(
            second,
            &original,
            mb_core::CatalogCheckpointRevisionKey::from(&fixture.paged().value),
            || Ok(original.trust().clone()),
            |_| Ok::<_, CatalogStoreError>(()),
        )
        .unwrap();
    retire_owner_captures(&control, &captures);
    retire_owner_captures(&control, &original_captures);
    assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
    retire(&control, first);
    assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
    drop(control);
    let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
    assert_eq!(
        control
            .catalog_paged_checkpoint_revision(second, bundle.id)
            .unwrap(),
        Some(snapshot)
    );
    // These opaque Store fixtures exercise native/source ownership, while
    // actual native byte verification is qualified independently in Node.
    assert!(
        control
            .paged_revision_data_source(bundle.id, data.sector.id)
            .unwrap()
            .is_some()
    );
    control
        .cancel_catalog_paged_checkpoint_retention(second)
        .unwrap();
    while control
        .release_catalog_paged_checkpoint_root(second)
        .unwrap()
    {}
    control.cancel_paged_revision_catalog(bundle.id).unwrap();
    while control
        .release_paged_revision_data_source(bundle.id)
        .unwrap()
    {}
    while control
        .release_paged_revision_page_source(bundle.id)
        .unwrap()
    {}
    assert!(!control.paged_data_anchor_is_pinned(anchor).unwrap());
}

#[test]
fn directory_payload_custody_authenticates_ready_information_and_parity_and_blocks_volume_retirement()
 {
    use super::paged_checkpoint_payload as physical;
    let temp = tempfile::tempdir().unwrap();
    let control_path = temp.path().join("control.db");
    let volume_path = temp.path().join("parity.db");
    let control = ControlStore::open_with_key(&control_path, &[7; 32]).unwrap();
    let mut volume = crate::ParityStore::open_with_key(&volume_path, &[8; 16], &[9; 32]).unwrap();
    let (mut fixture, history) = real_checkpoint();
    let objects = physical::objects(&fixture, &history);
    physical::stage(&mut volume, &objects, &history);
    let proof = proof(&mut fixture, &history, budget());
    stage(&control, &fixture, &proof, 1000);
    let first = Uuid::from_u128(1);
    let second = Uuid::from_u128(2);
    retain(&control, first, &proof);
    retain(&control, second, &proof);
    let group = history.entry.retained.group.id;
    let info = retain_payload(&control, &volume, first, &proof, group, 0).unwrap();
    let parity = retain_payload(&control, &volume, first, &proof, group, 3).unwrap();
    retain_payload(&control, &volume, second, &proof, group, 0).unwrap();
    assert_ne!(info.storage_id, parity.storage_id);
    assert_eq!(parity.storage_id, group);
    assert_eq!(
        retain_payload(&control, &volume, first, &proof, group, 0).unwrap(),
        info
    );
    let attempt = history.entry.transcript.value.plan.value.attempt_id;
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
    drop(control);
    drop(volume);
    let control = ControlStore::open_with_key(&control_path, &[7; 32]).unwrap();
    let mut volume = crate::ParityStore::open_with_key(&volume_path, &[8; 16], &[9; 32]).unwrap();
    assert_eq!(
        control
            .catalog_paged_checkpoint_payload(first, group, 3)
            .unwrap(),
        Some(parity.clone())
    );
    assert!(
        control
            .catalog_checkpoint_payload_is_pinned(info.storage_id, 0, info.commitment.root)
            .unwrap()
    );
    control
        .with_catalog_checkpoint_payload_retirement(|view| {
            assert!(view.is_pinned(info.storage_id, 0, info.commitment.root)?);
            assert!(view.is_pinned(parity.storage_id, 3, parity.commitment.root)?);
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
    retire(&control, first);
    assert!(
        !control
            .catalog_checkpoint_payload_is_pinned(parity.storage_id, 3, parity.commitment.root)
            .unwrap()
    );
    assert!(
        control
            .catalog_checkpoint_payload_is_pinned(info.storage_id, 0, info.commitment.root)
            .unwrap()
    );
    retire(&control, second);
    control
        .with_catalog_checkpoint_payload_retirement(|view| {
            assert!(!view.is_pinned(info.storage_id, 0, info.commitment.root)?);
            assert!(volume.remove_ready(&info.storage_id, 0, &info.commitment.root)?);
            Ok::<_, CatalogStoreError>(())
        })
        .unwrap();
    assert!(volume.load_ready_variable(&info.storage_id, 0).is_err());
}

#[test]
fn directory_private_and_payload_dependencies_share_the_complete_budget_in_both_acquisition_orders()
{
    use super::paged_checkpoint_payload as physical;
    use super::paged_checkpoint_revision as private;
    let temp = tempfile::tempdir().unwrap();
    let control = ControlStore::open_with_key(temp.path().join("control.db"), &[7; 32]).unwrap();
    let mut volume =
        crate::ParityStore::open_with_key(temp.path().join("parity.db"), &[8; 16], &[9; 32])
            .unwrap();
    let (mut fixture, history, bundle, bootstrap) = private::private_checkpoint(&control);
    private::publish_private(
        &control,
        &fixture,
        &bundle,
        &bootstrap,
        Uuid::from_u128(500),
    );
    let objects = physical::objects(&fixture, &history);
    physical::stage(&mut volume, &objects, &history);
    let full = proof(&mut fixture, &history, budget());
    stage(&control, &fixture, &full, 1000);
    let id = Uuid::from_u128(1);
    let owner = retain(&control, id, &full);
    let group = history.entry.retained.group.id;
    retain_private(&control, id, &full, &fixture).unwrap();
    retain_payload(&control, &volume, id, &full, group, 0).unwrap();
    let private_work =
        super::super::super::paged_checkpoint_revision::owned_work(&control.connection, owner)
            .unwrap()
            .unwrap();
    let payload_work =
        super::super::super::paged_checkpoint_payload::owned_work(&control.connection, owner)
            .unwrap()
            .unwrap();
    let public = owner
        .proof_work
        .checked_add(owner.checkpoint.represented_work().unwrap())
        .unwrap();
    let one = Work {
        bytes: private_work.bytes.max(payload_work.bytes),
        page_occurrences: private_work
            .page_occurrences
            .max(payload_work.page_occurrences),
        records: private_work.records.max(payload_work.records),
    };
    let limited = proof(&mut fixture, &history, public.checked_add(one).unwrap());
    for (id, private_first) in [(Uuid::from_u128(2), true), (Uuid::from_u128(3), false)] {
        retain(&control, id, &limited);
        if private_first {
            retain_private(&control, id, &limited, &fixture).unwrap();
            assert!(
                control
                    .retain_catalog_paged_checkpoint_directory_payload_checked(
                        id,
                        &limited,
                        group,
                        0,
                        || Ok(limited.trust().clone()),
                        |_| -> Result<(), CatalogStoreError> {
                            panic!("unadmitted directory payload bytes were read")
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
        } else {
            retain_payload(&control, &volume, id, &limited, group, 0).unwrap();
            assert!(
                control
                    .retain_catalog_paged_checkpoint_directory_revision_checked(
                        id,
                        &limited,
                        mb_core::CatalogCheckpointRevisionKey::from(&fixture.paged().value),
                        || Ok(limited.trust().clone()),
                        |_| -> Result<(), CatalogStoreError> {
                            panic!("unadmitted directory private bytes were read")
                        }
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

    let replay_limited = proof(
        &mut fixture,
        &history,
        public
            .checked_add(private_work)
            .unwrap()
            .checked_add(Work {
                bytes: 3 * 512,
                records: 3,
                page_occurrences: 0,
            })
            .unwrap(),
    );
    let id = Uuid::from_u128(4);
    retain(&control, id, &replay_limited);
    retain_private(&control, id, &replay_limited, &fixture).unwrap();
    let page = full.index().index().next_group(None).unwrap().unwrap().page;
    let saved = control
        .get_record("catalog-page-v1", &page.hash)
        .unwrap()
        .unwrap();
    control
        .put_record("catalog-page-v1", &page.hash, &[0])
        .unwrap();
    assert!(matches!(
        control.retain_catalog_paged_checkpoint_directory_payload_checked(
            id,
            &replay_limited,
            group,
            0,
            || Ok(replay_limited.trust().clone()),
            |_| -> Result<(), CatalogStoreError> {
                panic!("unadmitted directory witness reached payload validation")
            }
        ),
        Err(CatalogStoreError::Page(mb_core::CatalogError::Bounds))
    ));
    control
        .put_record("catalog-page-v1", &page.hash, &saved)
        .unwrap();

    let exact = proof(
        &mut fixture,
        &history,
        public
            .checked_add(private_work)
            .unwrap()
            .checked_add(payload_work)
            .unwrap(),
    );
    for (id, private_first) in [(Uuid::from_u128(5), true), (Uuid::from_u128(6), false)] {
        let owner = retain(&control, id, &exact);
        for _ in 0..2 {
            if !private_first {
                retain_payload(&control, &volume, id, &exact, group, 0).unwrap();
            }
            retain_private(&control, id, &exact, &fixture).unwrap();
            retain_payload(&control, &volume, id, &exact, group, 0).unwrap();
        }
        assert_eq!(
            super::super::super::paged_checkpoint_revision::owned_work(&control.connection, owner)
                .unwrap(),
            Some(private_work)
        );
        assert_eq!(
            super::super::super::paged_checkpoint_payload::owned_work(&control.connection, owner)
                .unwrap(),
            Some(payload_work)
        );
    }
}
