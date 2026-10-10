use super::*;

pub(super) fn paged_owner_proof(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
    previous: Option<&CatalogQuorumPagedCheckpointIndex>,
) -> CatalogQuorumPagedCheckpointIndex {
    let mut trust = history.trust();
    trust.previous = previous.map(|previous| mb_core::PagedCheckpointParent {
        generation: previous.certificate().checkpoint.generation,
        hash: previous.certificate().hash().unwrap(),
    });
    let reader = real_reader(history, &trust);
    let body = real_body(fixture, history, &reader, &trust, true);
    let transition = body
        .validate_certified_history_authority_transition(
            previous.map(CatalogCheckpointPrevious::Paged),
            &reader,
            budget(),
            || Ok(trust.clone()),
        )
        .unwrap();
    real_certificate(transition, history)
}

type OwnerRoot = (CatalogScope, CatalogSection, CatalogPageRef);

fn paged_owner_descriptor(
    id: Uuid,
    proof: &CatalogQuorumPagedCheckpointIndex,
) -> CatalogPagedCheckpointRetention {
    CatalogPagedCheckpointRetention {
        id,
        checkpoint: proof.certificate().checkpoint,
        certificate_hash: mb_core::canonical_hash_bounded(
            proof.certificate(),
            mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
        )
        .unwrap(),
        trust_hash: super::super::super::checkpoint_transition::snapshot_hash(proof.trust())
            .unwrap(),
        proof_work: proof.transition().represented_work(),
        budget: proof.transition().budget(),
    }
}

pub(super) fn stage_paged_owner(
    control: &ControlStore,
    fixture: &super::super::super::checkpoint_validation::tests::Fixture,
    proof: &CatalogQuorumPagedCheckpointIndex,
    offset: u128,
) -> (Vec<CatalogIntent>, Vec<OwnerRoot>) {
    use mb_core::CatalogCheckpointAuthorityRecord as R;
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
        (
            scope,
            CatalogSection::Packing,
            header.packed_sectors.records.page,
        ),
        (
            scope,
            CatalogSection::Packing,
            header.packed_sources.records.page,
        ),
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
    let mut coding =
        mb_core::CatalogCodingDirectoryReader::new(scope, header.coding, budget()).unwrap();
    let mut fetch = |page: CatalogPageRef| {
        fixture
            .pages
            .get(&page.hash)
            .cloned()
            .ok_or_else(|| DatabaseError::NotReady.into())
    };
    let mut forest = |root: &mb_core::CatalogCodingRoot| {
        roots.extend(
            root.parts
                .iter()
                .map(|part| (scope, CatalogSection::Coding, part.page)),
        );
        Ok::<_, CatalogStoreError>(())
    };
    while coding
        .next_group_with_forest(&mut fetch, &mut forest)
        .unwrap()
        .is_some()
    {}
    fn tree(
        control: &ControlStore,
        intent: CatalogIntent,
        root: CatalogPageRef,
        pages: &BTreeMap<[u8; 32], Vec<u8>>,
    ) {
        let bytes = &pages[&root.hash];
        if let mb_core::CatalogPageContents::Index(children) = root
            .verify_page(intent.scope, intent.section, bytes)
            .unwrap()
        {
            for child in children {
                tree(control, intent, child, pages);
            }
        }
        control.stage_catalog_page(intent, root, bytes).unwrap();
    }
    let intents = roots
        .iter()
        .enumerate()
        .map(|(index, (scope, section, root))| {
            let intent = CatalogIntent {
                id: Uuid::from_u128(offset + index as u128),
                scope: *scope,
                section: *section,
            };
            control.begin_catalog(intent).unwrap();
            tree(control, intent, *root, &fixture.pages);
            intent
        })
        .collect();
    (intents, roots)
}

fn retire_owner_captures(control: &ControlStore, intents: &[CatalogIntent]) {
    for intent in intents {
        control.cancel_catalog(*intent).unwrap();
        while control.release_catalog_pin(*intent).unwrap() {}
    }
    while control.collect_catalog_page().unwrap() {}
}

#[test]
fn guarded_checkpoint_owner_keeps_all_public_roots_after_capture_retirement_and_reopen() {
    public_owner_lifecycle(false);
}

#[test]
fn budgeted_checkpoint_owner_keeps_original_history_proof_and_all_roots_through_reopen() {
    public_owner_lifecycle(true);
}

fn public_owner_lifecycle(budgeted: bool) {
    let (mut fixture, history) = real_checkpoint();
    if budgeted {
        fixture.authority_budget = Some(budget());
    }
    let proof = paged_owner_proof(&mut fixture, &history, None);
    assert_eq!(
        proof.certificate().checkpoint.format_version,
        if budgeted { 9 } else { 8 }
    );
    assert_eq!(
        proof.certificate().checkpoint.authority_root.format_version,
        if budgeted { 2 } else { 1 }
    );
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owner.db");
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let (intents, roots) = stage_paged_owner(&control, &fixture, &proof, 100);
    assert!(roots.len() >= 7);
    let id = Uuid::from_u128(1);
    let retention = control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    assert_eq!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .unwrap(),
        retention
    );
    assert!(
        control
            .checkpoint_head_identity(&history.state.guild_id)
            .unwrap()
            .is_none()
    );
    retire_owner_captures(&control, &intents);
    drop(control);
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert_eq!(
        control.catalog_paged_checkpoint_retention(id).unwrap(),
        Some((retention, CatalogPagedCheckpointRetentionState::Published))
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .as_ref(),
        Some(proof.certificate())
    );
    for (scope, section, root) in &roots {
        control.catalog_page(*scope, *section, *root).unwrap();
    }
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    while control.release_catalog_paged_checkpoint_root(id).unwrap() {}
    while control.collect_catalog_page().unwrap() {}
    assert!(
        control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Cancelled
    );
    for (scope, section, root) in roots {
        assert!(control.catalog_page(scope, section, root).is_err());
    }
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
}

#[test]
fn guarded_checkpoint_owner_preserves_shared_successors_and_rejects_current_retirement() {
    let (mut fixture, history) = real_checkpoint();
    let previous = paged_owner_proof(&mut fixture, &history, None);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owner.db");
    let mut control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let (intents, roots) = stage_paged_owner(&control, &fixture, &previous, 100);
    let first = control
        .retain_catalog_paged_checkpoint(Uuid::from_u128(1), &previous, || {
            Ok(previous.trust().clone())
        })
        .unwrap();
    let commit = |control: &mut ControlStore, proof: &CatalogQuorumPagedCheckpointIndex| {
        let header = proof.certificate().checkpoint;
        control
            .commit_checkpoint(
                &header.guild_id,
                header.generation,
                header.parent.as_ref(),
                &header.hash().unwrap(),
                &canonical_bytes(&header).unwrap(),
                &canonical_bytes(proof.certificate()).unwrap(),
                false,
            )
            .unwrap();
    };
    commit(&mut control, &previous);
    assert!(
        control
            .cancel_catalog_paged_checkpoint_retention(first.id)
            .is_err()
    );
    let successor = paged_owner_proof(&mut fixture, &history, Some(&previous));
    let (next_intents, _) = stage_paged_owner(&control, &fixture, &successor, 200);
    let next = control
        .retain_catalog_paged_checkpoint(Uuid::from_u128(2), &successor, || {
            Ok(successor.trust().clone())
        })
        .unwrap();
    commit(&mut control, &successor);
    control
        .cancel_catalog_paged_checkpoint_retention(first.id)
        .unwrap();
    while control
        .release_catalog_paged_checkpoint_root(first.id)
        .unwrap()
    {}
    retire_owner_captures(&control, &intents);
    retire_owner_captures(&control, &next_intents);
    for (scope, section, root) in &roots {
        control.catalog_page(*scope, *section, *root).unwrap();
    }
    drop(control);
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    assert!(
        control
            .cancel_catalog_paged_checkpoint_retention(next.id)
            .is_err()
    );
    assert!(
        control
            .release_catalog_paged_checkpoint_root(next.id)
            .is_err()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_retention(next.id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Published
    );
}

#[test]
fn guarded_checkpoint_owner_rolls_back_publication_if_sql_head_changes_inside_the_writer() {
    let (mut fixture, history) = real_checkpoint();
    let proof = paged_owner_proof(&mut fixture, &history, None);
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("owner.db"), &history.keys[0]).unwrap();
    let (intents, roots) = stage_paged_owner(&control, &fixture, &proof, 100);
    let distinct = roots
        .iter()
        .map(|(_, _, root)| (root.hash, *root))
        .collect::<BTreeMap<_, _>>();
    let published = super::super::super::retention_journal::JournalRecord {
        format_version: 1,
        retention: CatalogPagedCheckpointRetention {
            id: Uuid::from_u128(1),
            checkpoint: proof.certificate().checkpoint,
            certificate_hash: mb_core::canonical_hash_bounded(
                proof.certificate(),
                mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
            )
            .unwrap(),
            trust_hash: super::super::super::checkpoint_transition::snapshot_hash(proof.trust())
                .unwrap(),
            proof_work: proof.transition().represented_work(),
            budget: proof.transition().budget(),
        },
        state: CatalogPagedCheckpointRetentionState::Published,
        roots: distinct.len() as u64,
        bytes: distinct.values().map(|root| root.byte_len).sum(),
        pages: distinct.values().map(|root| root.page_occurrences).sum(),
    };
    let published = canonical_bytes(&published)
        .unwrap()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    control
        .connection
        .execute_batch(&format!(
            "CREATE TRIGGER changed_checkpoint_head AFTER UPDATE OF bytes ON protocol_records
         WHEN NEW.kind = 'catalog-paged-checkpoint-retention-v1' AND NEW.bytes = X'{published}'
         BEGIN INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes)
         VALUES (X'{}', 1, X'{}', X'00'); END;",
            history
                .state
                .guild_id
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
            [99_u8; 32]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        ))
        .unwrap();
    let id = Uuid::from_u128(1);
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    assert!(
        control
            .checkpoint_head_identity(&history.state.guild_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Cancelled
    );
    control
        .connection
        .execute_batch("DROP TRIGGER changed_checkpoint_head")
        .unwrap();
    while control.release_catalog_paged_checkpoint_root(id).unwrap() {}
    retire_owner_captures(&control, &intents);
    for (scope, section, root) in roots {
        assert!(control.catalog_page(scope, section, root).is_err());
    }
}

#[test]
fn guarded_checkpoint_owner_rejects_external_history_stale_trust_and_incomplete_local_eof() {
    let (mut fixture, history) = real_checkpoint();
    let proof = paged_owner_proof(&mut fixture, &history, None);
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("owner.db"), &history.keys[0]).unwrap();
    let mut draft = super::super::super::checkpoint_validation::tests::Fixture::new(true, false);
    let draft = real_certificate(
        draft
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap(),
        &history,
    );
    assert!(
        control
            .retain_catalog_paged_checkpoint(Uuid::from_u128(1), &draft, || panic!(
                "external-only proof must fail before trust/pin work"
            ))
            .is_err()
    );
    let mut stale = proof.trust().clone();
    stale.event_head[0] ^= 1;
    assert!(
        control
            .retain_catalog_paged_checkpoint(Uuid::from_u128(1), &proof, || Ok(stale.clone()))
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_retention(Uuid::from_u128(1))
            .unwrap()
            .is_none()
    );
    let (_intents, roots) = stage_paged_owner(&control, &fixture, &proof, 100);
    let missing = roots[4].2;
    control
        .connection
        .execute(
            "DELETE FROM protocol_records WHERE kind = 'catalog-page-v1' AND record_id = ?1",
            [missing.hash.as_slice()],
        )
        .unwrap();
    let id = Uuid::from_u128(1);
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Cancelled
    );
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
}

#[test]
fn guarded_checkpoint_owner_replays_building_and_rechecks_current_head_before_each_release() {
    use super::super::super::retention_journal::{self as journal, Dependency};
    let (mut fixture, history) = real_checkpoint();
    let proof = paged_owner_proof(&mut fixture, &history, None);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owner.db");
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let (_intents, roots) = stage_paged_owner(&control, &fixture, &proof, 100);
    let id = Uuid::from_u128(1);
    let descriptor = paged_owner_descriptor(id, &proof);
    control
        .with_record_transaction(|| -> Result<(), CatalogStoreError> {
            journal::begin(&control.connection, descriptor)?;
            super::super::super::insert_exact(
                &control.connection,
                "catalog-paged-checkpoint-certificate-v1",
                id.as_bytes(),
                &canonical_bytes(proof.certificate()).unwrap(),
            )?;
            for (scope, section, root) in roots.iter().take(5) {
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
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Building
    );
    assert_eq!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .unwrap(),
        descriptor
    );
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    // Backstop a current-head change after cancellation as well as before it.
    // Future activation must itself reject cancelled metadata owners atomically.
    let header = proof.certificate().checkpoint;
    control
        .commit_checkpoint(
            &header.guild_id,
            header.generation,
            None,
            &header.hash().unwrap(),
            &canonical_bytes(&header).unwrap(),
            &canonical_bytes(proof.certificate()).unwrap(),
            false,
        )
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    for (scope, section, root) in roots {
        control.catalog_page(scope, section, root).unwrap();
    }
}

#[test]
fn guarded_checkpoint_owner_rolls_back_initial_pin_faults_and_changed_final_event_trust() {
    use super::super::super::retention_journal as journal;
    let (mut fixture, history) = real_checkpoint();
    let proof = paged_owner_proof(&mut fixture, &history, None);
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("owner.db"), &history.keys[0]).unwrap();
    let (_intents, _) = stage_paged_owner(&control, &fixture, &proof, 100);
    let id = Uuid::from_u128(1);
    let pin = journal::pin_id::<CatalogPagedCheckpointRetention>(id);
    let packed = proof
        .certificate()
        .checkpoint
        .packed_sectors
        .records
        .page
        .hash
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    control
        .connection
        .execute_batch(&format!(
            "CREATE TRIGGER ignore_owned_root BEFORE INSERT ON protocol_records
         WHEN NEW.kind = 'catalog-paged-checkpoint-dependency-v1/{}' AND NEW.record_id = X'{packed}'
         BEGIN SELECT RAISE(IGNORE); END;",
            id.simple(),
        ))
        .unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .is_none()
    );
    let pins: u64 = control
        .connection
        .query_row(
            "SELECT count(*) FROM protocol_records WHERE record_id = ?1",
            [pin.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pins, 0);
    control
        .connection
        .execute_batch("DROP TRIGGER ignore_owned_root")
        .unwrap();
    let mut tight = paged_owner_descriptor(Uuid::from_u128(3), &proof);
    tight.budget = tight.proof_work;
    assert!(
        control
            .with_record_transaction(|| journal::begin(&control.connection, tight))
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_retention(tight.id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || {
                let mut trust = proof.trust().clone();
                if control
                    .catalog_paged_checkpoint_retention(id)?
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
            .catalog_paged_checkpoint_retention(id)
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
    while control.release_catalog_paged_checkpoint_root(id).unwrap() {}
    control
        .retain_catalog_paged_checkpoint(Uuid::from_u128(2), &proof, || Ok(proof.trust().clone()))
        .unwrap();
}

#[test]
fn guarded_checkpoint_owner_cancel_release_and_certificate_retirement_are_atomic() {
    use super::super::super::retention_journal as journal;
    let (mut fixture, history) = real_checkpoint();
    let proof = paged_owner_proof(&mut fixture, &history, None);
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("owner.db"), &history.keys[0]).unwrap();
    let (_intents, _) = stage_paged_owner(&control, &fixture, &proof, 100);
    let id = Uuid::from_u128(1);
    control.connection.execute_batch("CREATE TRIGGER ignore_certificate_acquisition BEFORE INSERT ON protocol_records WHEN NEW.kind = 'catalog-paged-checkpoint-certificate-v1' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER ignore_certificate_acquisition")
        .unwrap();
    control
        .put_record(
            "catalog-paged-checkpoint-certificate-v1",
            id.as_bytes(),
            &canonical_bytes(proof.certificate()).unwrap(),
        )
        .unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    assert!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .is_none()
    );
    control
        .delete_record("catalog-paged-checkpoint-certificate-v1", id.as_bytes())
        .unwrap();
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    let mut cancelled = journal::read::<CatalogPagedCheckpointRetention>(&control.connection, id)
        .unwrap()
        .unwrap();
    let pin = journal::pin_id::<CatalogPagedCheckpointRetention>(id);
    let root_pins = super::super::super::pins(
        proof
            .certificate()
            .checkpoint
            .authority_root
            .records
            .page
            .hash,
    );
    control.delete_record(&root_pins, &pin).unwrap();
    assert!(
        control
            .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
            .is_err()
    );
    control.put_record(&root_pins, &pin, &[]).unwrap();
    control
        .retain_catalog_paged_checkpoint(id, &proof, || Ok(proof.trust().clone()))
        .unwrap();
    cancelled.state = CatalogPagedCheckpointRetentionState::Cancelled;
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let activate = format!(
        "INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'00');",
        hex(&history.state.guild_id),
        hex(&proof.certificate().hash().unwrap())
    );
    control
        .connection
        .execute_batch(&format!(
            "CREATE TRIGGER activate_on_cancel AFTER UPDATE OF bytes ON protocol_records
         WHEN NEW.kind = 'catalog-paged-checkpoint-retention-v1' AND NEW.bytes = X'{}'
         BEGIN {activate} END;",
            hex(&canonical_bytes(&cancelled).unwrap()),
        ))
        .unwrap();
    assert!(
        control
            .cancel_catalog_paged_checkpoint_retention(id)
            .is_err()
    );
    assert!(
        control
            .checkpoint_head_identity(&history.state.guild_id)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .unwrap()
            .1,
        CatalogPagedCheckpointRetentionState::Published
    );
    control
        .connection
        .execute_batch("DROP TRIGGER activate_on_cancel")
        .unwrap();
    control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    let before = journal::read::<CatalogPagedCheckpointRetention>(&control.connection, id).unwrap();
    control
        .connection
        .execute_batch(&format!(
            "CREATE TRIGGER activate_on_release AFTER DELETE ON protocol_records
         WHEN OLD.kind = 'catalog-paged-checkpoint-dependency-v1/{}'
         BEGIN {activate} END;",
            id.simple(),
        ))
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    assert_eq!(
        journal::read::<CatalogPagedCheckpointRetention>(&control.connection, id).unwrap(),
        before
    );
    assert!(
        control
            .checkpoint_head_identity(&history.state.guild_id)
            .unwrap()
            .is_none()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER activate_on_release")
        .unwrap();
    while journal::read::<CatalogPagedCheckpointRetention>(&control.connection, id)
        .unwrap()
        .unwrap()
        .roots
        > 1
    {
        control.release_catalog_paged_checkpoint_root(id).unwrap();
    }
    let certificate = canonical_bytes(proof.certificate()).unwrap();
    for corrupt in [vec![0], vec![0; mb_core::PAGED_QUORUM_CHECKPOINT_BYTES + 1]] {
        control
            .put_record(
                "catalog-paged-checkpoint-certificate-v1",
                id.as_bytes(),
                &corrupt,
            )
            .unwrap();
        assert!(control.catalog_paged_checkpoint_certificate(id).is_err());
        assert!(control.catalog_paged_checkpoint_retention(id).is_err());
        assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    }
    control
        .delete_record("catalog-paged-checkpoint-certificate-v1", id.as_bytes())
        .unwrap();
    assert!(control.catalog_paged_checkpoint_certificate(id).is_err());
    assert!(control.catalog_paged_checkpoint_retention(id).is_err());
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    control
        .put_record(
            "catalog-paged-checkpoint-certificate-v1",
            id.as_bytes(),
            &certificate,
        )
        .unwrap();
    control.connection.execute_batch("CREATE TRIGGER ignore_certificate_retirement BEFORE DELETE ON protocol_records WHEN OLD.kind = 'catalog-paged-checkpoint-certificate-v1' BEGIN SELECT RAISE(IGNORE); END;").unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).is_err());
    assert_eq!(
        journal::read::<CatalogPagedCheckpointRetention>(&control.connection, id)
            .unwrap()
            .unwrap()
            .roots,
        1
    );
    assert!(
        control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .is_some()
    );
    control
        .connection
        .execute_batch("DROP TRIGGER ignore_certificate_retirement")
        .unwrap();
    assert!(control.release_catalog_paged_checkpoint_root(id).unwrap());
    assert!(
        control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .is_none()
    );
    assert!(!control.release_catalog_paged_checkpoint_root(id).unwrap());
}

#[test]
fn checkpoint_head_identity_reads_fixed_columns_and_rejects_damaged_identities() {
    let history = History::new(false, 4);
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("head.db"), &history.keys[0]).unwrap();
    let guild = history.state.guild_id;
    control.connection.execute("INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (?1, 1, ?2, zeroblob(2097152))", params![guild, [9_u8; 32]]).unwrap();
    assert_eq!(
        control.checkpoint_head_identity(&guild).unwrap(),
        Some((1, [9; 32]))
    );
    control
        .connection
        .execute_batch("PRAGMA ignore_check_constraints = ON")
        .unwrap();
    for generation in [0, -1] {
        control
            .connection
            .execute("UPDATE checkpoint_heads SET generation = ?1", [generation])
            .unwrap();
        assert!(control.checkpoint_head_identity(&guild).is_err());
    }
    control
        .connection
        .execute(
            "UPDATE checkpoint_heads SET generation = 1, checkpoint_hash = ?1",
            [[0_u8; 32]],
        )
        .unwrap();
    assert!(control.checkpoint_head_identity(&guild).is_err());
    control
        .connection
        .execute(
            "UPDATE checkpoint_heads SET checkpoint_hash = ?1",
            [[9_u8; 31]],
        )
        .unwrap();
    assert!(control.checkpoint_head_identity(&guild).is_err());
    control
        .connection
        .execute(
            "UPDATE checkpoint_heads SET checkpoint_hash = zeroblob(2097152)",
            [],
        )
        .unwrap();
    assert!(control.checkpoint_head_identity(&guild).is_err());
}
