use super::*;
use crate::database::catalog::packing_directories_coverage::tests::shard;
use mb_core::{
    CatalogCheckpointAuthorityRecord as R, CatalogCodingDirectoryBuilder,
    QuorumPagedCheckpointDirectory,
};

fn body(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
    reader: &CatalogGuildHistoryIndex,
    trust: &PagedCheckpointTrust,
    concrete: bool,
) -> CatalogCheckpointDirectoriesCodingStateIndex {
    fixture.authority_budget = Some(budget());
    fixture.context.generation = trust.next_generation().unwrap();
    fixture.context.event_sequence = trust.event_sequence;
    fixture.context.event_head = trust.event_head;
    fixture.context.authority = trust.authority;
    fixture
        .records
        .retain(|record| !matches!(record, R::Member(_)));
    fixture
        .records
        .extend(trust.members.iter().cloned().map(R::Member));
    let mut original = history.entry.clone();
    original.retained = history
        .state
        .coding_groups
        .iter()
        .find(|group| group.group.id == original.retained.group.id)
        .unwrap()
        .clone();
    let (packing, pages, _) = fixture.packing_inputs_with_byte_roots();
    let parts = shard(packing, pages.into_iter().collect());
    let mut pages = parts.pages;
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    let mut builder =
        CatalogCodingDirectoryBuilder::new(fixture.scope(), trust.event_sequence, budget())
            .unwrap();
    builder.push_group(&original, &mut sink).unwrap();
    let coding = builder.finish(&mut sink).unwrap();
    let index = fixture
        .build_with_members(budget(), &trust.members)
        .unwrap()
        .validate_packing_directory(parts.manifest, |page| Ok(pages[&page.hash].clone()))
        .unwrap()
        .validate_coding_directory(
            coding,
            CatalogCodingCoveragePolicy::Current,
            |page| Ok(pages[&page.hash].clone()),
            |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
        )
        .unwrap();
    if concrete {
        index
            .validate_certified_history_coding_state(reader, budget(), || Ok(trust.clone()))
            .unwrap()
    } else {
        let view = reader.view(|| Ok(trust.clone())).unwrap();
        index
            .validate_certified_coding_state(
                budget(),
                || Ok(view.coding_trust()),
                |id, trust| view.coding_group(id, trust),
            )
            .unwrap()
    }
}

fn certificate(
    transition: CatalogCheckpointDirectoriesTransitionIndex,
    history: &History,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    let trust = transition.trust().clone();
    let mut checkpoint = None;
    let mut signatures = Vec::new();
    for key in &history.keys {
        if trust
            .members
            .iter()
            .any(|member| member.node_id == key.node_id())
        {
            let (header, signature) = transition
                .sign_paged_checkpoint_header(key, || Ok(trust.clone()))
                .unwrap();
            checkpoint = Some(header);
            signatures.push(signature);
        }
    }
    signatures.sort_by_key(|signature| signature.signer);
    transition
        .bind_paged_checkpoint_header(
            QuorumPagedCheckpointDirectory {
                checkpoint: checkpoint.unwrap(),
                signatures,
            },
            || Ok(trust.clone()),
        )
        .unwrap()
}

fn initial(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    let trust = history.trust();
    let reader = real_reader(history, &trust);
    let transition = body(fixture, history, &reader, &trust, true)
        .validate_certified_history_authority_transition(None, &reader, budget(), || {
            Ok(trust.clone())
        })
        .unwrap();
    assert!(transition.has_certified_history_transition());
    certificate(transition, history)
}

#[test]
fn directory_history_certifies_readded_original_witness_and_complete_successor_quorum() {
    let (mut fixture, mut history) = real_checkpoint();
    let previous = initial(&mut fixture, &history);
    let old_group = previous
        .index()
        .index()
        .next_group_row(None)
        .unwrap()
        .unwrap();
    readd_with_new_witness(&mut history);
    let mut current = history.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: 1,
        hash: previous.certificate().hash().unwrap(),
    });
    let reader = real_reader(&history, &current);
    let index = body(&mut fixture, &history, &reader, &current, true);
    assert_eq!(index.history_work(), reader.represented_work());
    let new_group = index.index().index().next_group_row(None).unwrap().unwrap();
    assert_eq!(
        old_group.group.range.group_id,
        new_group.group.range.group_id
    );
    assert_ne!(
        old_group.group.range.transcript_hash,
        new_group.group.range.transcript_hash
    );
    assert_eq!(old_group.group.added_at_event, 8);
    assert_eq!(new_group.group.added_at_event, 11);
    let transition = index
        .validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Directory(&previous)),
            &reader,
            budget(),
            || Ok(current.clone()),
        )
        .unwrap();
    let work = transition.represented_work();
    assert!(transition.has_certified_history_transition());
    let successor = certificate(transition, &history);
    assert_eq!(
        successor.certificate().checkpoint.parent,
        Some(previous.certificate().hash().unwrap())
    );
    successor.recheck_header(|| Ok(current.clone())).unwrap();
    let index = body(&mut fixture, &history, &reader, &current, false);
    assert_eq!(index.history_work(), Work::default());
    assert_eq!(
        index
            .validate_certified_history_authority_transition(
                Some(CatalogCheckpointPrevious::Directory(&previous)),
                &reader,
                work,
                || Ok(current.clone())
            )
            .unwrap()
            .represented_work(),
        work
    );
}

#[test]
fn directory_history_exhaustion_precedes_lookup_and_missing_old_incarnations_fail_closed() {
    let (mut fixture, mut history) = real_checkpoint();
    let previous = initial(&mut fixture, &history);
    readd_with_new_witness(&mut history);
    let mut current = history.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: 1,
        hash: previous.certificate().hash().unwrap(),
    });
    let reader = real_reader(&history, &current);
    let exact = body(&mut fixture, &history, &reader, &current, true)
        .validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Directory(&previous)),
            &reader,
            budget(),
            || Ok(current.clone()),
        )
        .unwrap()
        .represented_work();
    let old = reader
        .store
        .next_record_bounded(ARCHIVE, None, 40, ROW_BYTES)
        .unwrap()
        .unwrap();
    reader
        .store
        .delete_record_if_value(ARCHIVE, &old.0, &old.1)
        .unwrap();
    for dimension in 0..3 {
        let index = body(&mut fixture, &history, &reader, &current, true);
        let mut short = exact;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(matches!(
            index.validate_certified_history_authority_transition(
                Some(CatalogCheckpointPrevious::Directory(&previous)),
                &reader,
                short,
                || Ok(current.clone())
            ),
            Err(CatalogStoreError::Page(CatalogError::Bounds))
        ));
    }
    assert!(
        body(&mut fixture, &history, &reader, &current, true)
            .validate_certified_history_authority_transition(
                Some(CatalogCheckpointPrevious::Directory(&previous)),
                &reader,
                exact,
                || Ok(current.clone())
            )
            .is_err()
    );
}

#[test]
fn directory_history_rejects_a_later_quorum_certified_event_fork() {
    let (mut fixture, history) = real_checkpoint();
    let previous = initial(&mut fixture, &history);
    let old_trust = history.trust();
    let (mut fixture, mut fork) = real_checkpoint();
    let genesis = GuildAuthoritySnapshot::from_genesis(&fork.genesis).unwrap();
    fork.state = DynamicGuildState::new(
        genesis.guild_id,
        genesis.event_head,
        genesis.quorum,
        genesis.active_members().cloned().collect(),
    )
    .unwrap();
    for bytes in fork.source.events.values().take(7) {
        fork.state
            .apply_event(&QuorumGuildEvent::decode_bounded(bytes).unwrap())
            .unwrap();
    }
    fork.source.events.retain(|sequence, _| *sequence <= 7);
    let mut transcript = fork.entry.transcript.value.clone();
    transcript.verified_at_unix_seconds -= 1;
    fork.entry.transcript = mb_core::SignedRecord::sign(
        mb_core::CODING_TRANSCRIPT_DOMAIN,
        transcript,
        fork.keys.last().unwrap(),
    )
    .unwrap();
    fork.add(false);
    fork.push(GuildEventKind::SetQuorum {
        policy: fork.state.quorum,
    });
    let mut current = fork.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: 1,
        hash: previous.certificate().hash().unwrap(),
    });
    assert_eq!(old_trust.genesis_hash, current.genesis_hash);
    assert_eq!(old_trust.members, current.members);
    assert!(old_trust.event_sequence < current.event_sequence);
    assert!(old_trust.authority.membership_epoch < current.authority.membership_epoch);
    let reader = real_reader(&fork, &current);
    assert!(matches!(
        body(&mut fixture, &fork, &reader, &current, true)
            .validate_certified_history_authority_transition(
                Some(CatalogCheckpointPrevious::Directory(&previous)),
                &reader,
                budget(),
                || Ok(current.clone())
            ),
        Err(CatalogStoreError::Database(DatabaseError::Conflict))
    ));
    previous.recheck_header(|| Ok(old_trust.clone())).unwrap();
}

#[test]
fn directory_history_preserves_original_identity_across_format_nine_and_ten_predecessors() {
    for directory_previous in [false, true] {
        let (mut fixture, mut history) = real_checkpoint();
        fixture.authority_budget = Some(budget());
        let trust = history.trust();
        let reader = real_reader(&history, &trust);
        let (old, directory) = if directory_previous {
            (None, Some(initial(&mut fixture, &history)))
        } else {
            let transition = real_body(&mut fixture, &history, &reader, &trust, true)
                .validate_certified_history_authority_transition(None, &reader, budget(), || {
                    Ok(trust.clone())
                })
                .unwrap();
            (Some(real_certificate(transition, &history)), None)
        };
        let previous_hash = if let Some(old) = &old {
            assert_eq!(old.certificate().checkpoint.format_version, 9);
            old.certificate().hash().unwrap()
        } else {
            directory.as_ref().unwrap().certificate().hash().unwrap()
        };
        readd_with_new_witness(&mut history);
        let mut current = history.trust();
        current.previous = Some(mb_core::PagedCheckpointParent {
            generation: 1,
            hash: previous_hash,
        });
        let reader = real_reader(&history, &current);
        if let Some(old) = &old {
            let successor = body(&mut fixture, &history, &reader, &current, true)
                .validate_certified_history_authority_transition(
                    Some(CatalogCheckpointPrevious::Paged(old)),
                    &reader,
                    budget(),
                    || Ok(current.clone()),
                )
                .unwrap();
            assert!(successor.has_certified_history_transition());
            let successor = certificate(successor, &history);
            assert_eq!(successor.certificate().checkpoint.format_version, 10);
            assert_eq!(
                successor.certificate().checkpoint.parent,
                Some(previous_hash)
            );
            successor.recheck_header(|| Ok(current.clone())).unwrap();
        } else {
            let successor = real_body(&mut fixture, &history, &reader, &current, true)
                .validate_certified_history_authority_transition(
                    Some(CatalogCheckpointPrevious::Directory(
                        directory.as_ref().unwrap(),
                    )),
                    &reader,
                    budget(),
                    || Ok(current.clone()),
                )
                .unwrap();
            assert!(successor.has_certified_history_transition());
            let successor = real_certificate(successor, &history);
            assert_eq!(successor.certificate().checkpoint.format_version, 9);
            assert_eq!(
                successor.certificate().checkpoint.parent,
                Some(previous_hash)
            );
            successor.recheck_header(|| Ok(current.clone())).unwrap();
        }
    }
}
