use super::*;
use crate::node::guild_authority::tests::{event, fixture, relabel};
use crate::node::tests::test_coding_transcript;

fn checkpoint_owner_proof(
    node: &mut Node,
    keys: &[KeyMaterial],
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    use mb_core::{
        CatalogBuilder, CatalogCheckpointAuthorityBuilder, CatalogCheckpointAuthorityRecord as R,
        CatalogCodingDirectoryBuilder, CatalogLegacyRevisionRef, CatalogPackedSectorBuilder,
        CatalogPackedSourceBuilder, CatalogPackedSourceRecord, CatalogScope, CatalogSection,
    };
    use mb_store::{
        CatalogCheckpointAuthorityContext, CatalogCheckpointAuthorityIndex,
        CatalogGuildHistoryIndex, CatalogPackingValidation, RecordScratchStore,
    };
    let work = Work {
        bytes: 64 << 20,
        records: 65536,
        page_occurrences: 65536,
    };
    let guild = node
        .installed_guild()
        .unwrap()
        .unwrap()
        .certificate
        .genesis
        .guild_id;
    let scope = CatalogScope::Guild { guild_id: guild };
    let profile = mb_core::PackingProfile {
        format_version: 1,
        sector_size: mb_core::V1_SECTOR_SIZE as u32,
        slot_size: mb_core::V1_SECTOR_SIZE as u32 / 4,
    };
    let writer = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
    let owner = keys[0].node_id();
    let rotate = event(
        node,
        keys,
        mb_core::GuildEventKind::RotateWriterKey {
            owner,
            epoch: 1,
            public_key: writer.verifying_key().to_bytes(),
        },
    );
    node.install_guild_event(rotate).unwrap();
    let bytes = vec![91; mb_core::V1_SECTOR_SIZE];
    let commitment = mb_core::merkle_commit(&bytes).unwrap();
    let target = SectorRef {
        id: [193; 32],
        root: sector_root(&bytes),
        logical_len: mb_core::V1_SECTOR_SIZE as u32,
    };
    let root_id = Uuid::from_u128(194);
    let mut revision = UserRevision {
        format_version: 4,
        guild_id: guild,
        protected_root_id: root_id,
        cipher_profile: mb_core::V1_CIPHER_PROFILE,
        revision_id: Uuid::from_u128(195),
        owner,
        writer_epoch: 1,
        writer_public_key: writer.verifying_key().to_bytes(),
        writer_signature: Vec::new(),
        sequence: 1,
        parent: None,
        metadata_sectors: vec![target.clone()],
        data_sectors: Vec::new(),
        sector_commitments: Some(vec![commitment.clone()]),
    };
    revision.sign_writer(&writer).unwrap();
    let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, &keys[0]).unwrap();
    let packed = mb_core::pack_incremental(
        profile,
        None,
        vec![mb_core::PackingInput {
            owner,
            protected_root: mb_core::packing_protected_root(root_id),
            object_id: target.id,
            source_commitment: Some(commitment.clone()),
            bytes: bytes.clone(),
        }],
    )
    .unwrap();
    let mut descriptors = packed.catalog.sectors.clone();
    let mut entries = Vec::new();
    for (index, (descriptor, packed_bytes)) in
        descriptors.iter_mut().zip(&packed.sectors).enumerate()
    {
        // Preserve the original version-two byte-root identity before signing.
        descriptor.flat_root = sector_root(&packed_bytes.bytes);
        descriptor.id = descriptor.calculate_id(profile).unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let member = |key: &KeyMaterial| {
            state
                .active_members()
                .find(|member| member.node_id == key.node_id())
                .unwrap()
        };
        let coding_profile = mb_core::CodingProfile::new(1, 1, profile.sector_size);
        let shards = mb_core::encode(coding_profile, vec![packed_bytes.bytes.clone()]).unwrap();
        let plan = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [index as u8 + 196; 16],
            checkpoint_hash: [192; 32],
            membership_epoch: state.membership_epoch,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id: guild,
                profile: coding_profile,
                information: vec![mb_core::InformationRoleV2 {
                    owner,
                    failure_domain: member(&keys[0]).failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: descriptor.id,
                        commitment: descriptor.commitment.clone(),
                        logical_len: profile.sector_size,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: keys[1].node_id(),
                    failure_domain: member(&keys[1]).failure_domain.clone(),
                    row: 0,
                }],
            },
            delegator: keys[2].node_id(),
            coding_coordinator: keys[3].node_id(),
            verification_coordinator: keys[4].node_id(),
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![descriptor.flat_root]),
        };
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, &keys[2]).unwrap();
        let transcript = test_coding_transcript(plan, &shards, keys);
        let add = GuildEvent {
            format_version: 2,
            guild_id: guild,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: transcript.value.manifest.value.group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&transcript).unwrap()).as_bytes(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|key| sign_guild_event(&add, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let add = QuorumGuildEvent {
            event: add,
            signatures,
        };
        node.install_coding_group_event(add, transcript.clone())
            .unwrap();
        let retained = node
            .dynamic_guild_state()
            .unwrap()
            .unwrap()
            .coding_groups
            .iter()
            .find(|retained| retained.group.id == transcript.value.manifest.value.group.id)
            .unwrap()
            .clone();
        entries.push(mb_core::CatalogCodingEntry {
            retained,
            transcript,
        });
    }
    let trust = with_history(&node.control, |reader| reader.paged_checkpoint_trust())
        .unwrap()
        .unwrap();
    let mut pages = std::collections::BTreeMap::new();
    let mut sink = |page: mb_core::CatalogPageRef, bytes| {
        pages.insert(page.hash, (CatalogSection::Checkpoint, page, bytes));
        Ok::<_, mb_store::CatalogStoreError>(())
    };
    let mut legacy = CatalogBuilder::new(scope, CatalogSection::Checkpoint).unwrap();
    legacy
        .push(&canonical_bytes(&revision).unwrap(), &mut sink)
        .unwrap();
    let legacy = legacy.finish(&mut sink).unwrap();
    let reference = CatalogLegacyRevisionRef::from_signed(guild, &revision, legacy).unwrap();
    let mut authority =
        CatalogCheckpointAuthorityBuilder::new(scope, 1, trust.authority.membership_epoch).unwrap();
    for member in &trust.members {
        authority
            .push(&R::Member(member.clone()), &mut sink)
            .unwrap();
    }
    let fence = mb_core::WriterFence {
        owner,
        epoch: 1,
        public_key: writer.verifying_key().to_bytes(),
    };
    authority
        .push(&R::WriterFence(fence.clone()), &mut sink)
        .unwrap();
    authority
        .push(&R::LegacyRevision(reference), &mut sink)
        .unwrap();
    let authority = authority.finish(&mut sink).unwrap();
    let mut sink = |page: mb_core::CatalogPageRef, bytes| {
        pages.insert(page.hash, (CatalogSection::Packing, page, bytes));
        Ok::<_, mb_store::CatalogStoreError>(())
    };
    let mut builder = CatalogPackedSectorBuilder::new_compact(scope, 2, profile).unwrap();
    for descriptor in &descriptors {
        builder.push_sector(descriptor, &mut sink).unwrap();
    }
    let descriptors = builder.finish(&mut sink).unwrap();
    let mut builder = CatalogPackedSourceBuilder::new_compact(scope, profile).unwrap();
    builder
        .push(
            &CatalogPackedSourceRecord::Source {
                format_version: 1,
                id: mb_core::CatalogPackedSourceId {
                    owner,
                    protected_root: mb_core::packing_protected_root(root_id),
                    object_id: target.id,
                },
                commitment,
            },
            &mut sink,
        )
        .unwrap();
    builder
        .push(
            &CatalogPackedSourceRecord::Subtrees {
                first_chunk: 0,
                roots: (0..4)
                    .map(|index| {
                        let leaves = profile.slot_size / mb_core::MERKLE_LEAF_SIZE as u32;
                        mb_core::merkle_open_subtree(&bytes, index * leaves, leaves)
                            .unwrap()
                            .subtree_root
                    })
                    .collect(),
            },
            &mut sink,
        )
        .unwrap();
    let sources = builder.finish(&mut sink).unwrap();
    let mut sink = |page: mb_core::CatalogPageRef, bytes| {
        pages.insert(page.hash, (CatalogSection::Coding, page, bytes));
        Ok::<_, mb_store::CatalogStoreError>(())
    };
    entries.sort_by_key(|entry| entry.retained.group.id);
    let mut builder =
        CatalogCodingDirectoryBuilder::new(scope, trust.event_sequence, work).unwrap();
    for entry in &entries {
        builder.push_group(entry, &mut sink).unwrap();
    }
    let coding = builder.finish(&mut sink).unwrap();
    let fetch = |page: mb_core::CatalogPageRef| {
        pages
            .get(&page.hash)
            .map(|(_, _, bytes)| bytes.clone())
            .ok_or_else(|| mb_store::DatabaseError::NotReady.into())
    };
    let context = CatalogCheckpointAuthorityContext {
        guild_id: trust.guild_id,
        generation: 1,
        event_sequence: trust.event_sequence,
        event_head: trust.event_head,
        authority: trust.authority,
    };
    let body = CatalogCheckpointAuthorityIndex::build(
        context,
        authority,
        &trust.members,
        work,
        RecordScratchStore::new(2 << 20).unwrap(),
        |_, _, page| fetch(page),
        |candidate, _| {
            if candidate == &fence {
                Ok(())
            } else {
                Err(mb_store::DatabaseError::Conflict.into())
            }
        },
    )
    .unwrap()
    .validate_packing(
        CatalogPackingValidation {
            format_version: 1,
            scope,
            descriptors,
            sources,
        },
        fetch,
    )
    .unwrap()
    .validate_coding_directory(
        coding,
        mb_store::CatalogCodingCoveragePolicy::Current,
        fetch,
        |_| Ok(mb_store::CatalogCodingAuthorization::CurrentPlacement),
    )
    .unwrap();
    let installed = node.installed_guild().unwrap().unwrap();
    let mut source = &node.control;
    let history = CatalogGuildHistoryIndex::build(
        RecordScratchStore::new(2 << 20).unwrap(),
        &installed.certificate,
        work,
        Work::default(),
        || Ok(trust.clone()),
        &mut source,
    )
    .unwrap();
    let transition = body
        .validate_certified_history_coding_state(&history, work, || Ok(trust.clone()))
        .unwrap()
        .validate_certified_history_authority_transition(None, &history, work, || Ok(trust.clone()))
        .unwrap();
    let mut header = None;
    let mut signatures = Vec::new();
    for key in keys {
        let (checkpoint, signature) = transition
            .sign_paged_checkpoint_header(key, || Ok(trust.clone()))
            .unwrap();
        header = Some(checkpoint);
        signatures.push(signature);
    }
    signatures.sort_by_key(|signature| signature.signer);
    let proof = transition
        .bind_paged_checkpoint_header(
            mb_core::QuorumPagedCheckpoint {
                checkpoint: header.unwrap(),
                signatures,
            },
            || Ok(trust.clone()),
        )
        .unwrap();
    let mut pages = pages.into_values().collect::<Vec<_>>();
    pages.sort_by_key(|(_, page, _)| page.height);
    let intents = pages
        .iter()
        .enumerate()
        .map(|(index, (section, page, bytes))| {
            let intent = mb_store::CatalogIntent {
                id: Uuid::from_u128(index as u128 + 100),
                scope,
                section: *section,
            };
            node.control.begin_catalog(intent).unwrap();
            node.control
                .stage_catalog_page(intent, *page, bytes)
                .unwrap();
            intent
        })
        .collect();
    (proof, intents)
}

#[test]
fn paged_checkpoint_metadata_node_owner_uses_original_index_and_survives_capture_retirement() {
    let (temp, seed, mut node, keys) = fixture();
    let (proof, intents) = checkpoint_owner_proof(&mut node, &keys);
    let flat = node
        .control
        .get_record("guild-dynamic-state", KEY)
        .unwrap()
        .unwrap();
    node.control
        .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
        .unwrap();
    let id = Uuid::from_u128(1);
    let owner = node.retain_paged_checkpoint_metadata(id, &proof).unwrap();
    assert!(
        node.control
            .checkpoint_head_identity(&proof.trust().guild_id)
            .unwrap()
            .is_none()
    );
    for intent in intents {
        node.control.cancel_catalog(intent).unwrap();
        while node.control.release_catalog_pin(intent).unwrap() {}
    }
    while node.control.collect_catalog_page().unwrap() {}
    let checkpoint = proof.certificate().checkpoint;
    for (section, root) in [
        (
            mb_core::CatalogSection::Checkpoint,
            checkpoint.authority_root.records.page,
        ),
        (
            mb_core::CatalogSection::Packing,
            checkpoint.packed_sources.records.page,
        ),
        (
            mb_core::CatalogSection::Coding,
            checkpoint.coding.records.page,
        ),
    ] {
        node.control
            .catalog_page(
                mb_core::CatalogScope::Guild {
                    guild_id: checkpoint.guild_id,
                },
                section,
                root,
            )
            .unwrap();
    }
    node.control
        .put_record("guild-dynamic-state", KEY, &flat)
        .unwrap();
    drop(node);
    let node = Node::open(temp.path(), seed).unwrap();
    let certificate = node
        .control
        .catalog_paged_checkpoint_certificate(id)
        .unwrap()
        .unwrap();
    assert_eq!(&certificate, proof.certificate());
    certificate
        .verify_header(proof.trust(), proof.transition().budget())
        .unwrap();
    node.control
        .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
        .unwrap();
    assert_eq!(
        node.retain_paged_checkpoint_metadata(id, &proof).unwrap(),
        owner
    );
    assert_eq!(
        node.control.catalog_paged_checkpoint_retention(id).unwrap(),
        Some((
            owner,
            mb_store::CatalogPagedCheckpointRetentionState::Published
        ))
    );
    node.control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    while node
        .control
        .release_catalog_paged_checkpoint_root(id)
        .unwrap()
    {}
}

#[test]
fn paged_checkpoint_metadata_node_owner_rejects_changed_original_authority() {
    let (_temp, _seed, mut node, keys) = fixture();
    let (proof, _intents) = checkpoint_owner_proof(&mut node, &keys);
    let original = node
        .control
        .get_record("guild-installed", KEY)
        .unwrap()
        .unwrap();
    assert!(
        with_history(&node.control, |reader| {
            reader.paged_checkpoint_trust()?;
            node.control.put_record("guild-installed", KEY, &[0])?;
            reader.paged_checkpoint_trust()
        })
        .is_err()
    );
    node.control
        .put_record("guild-installed", KEY, &original)
        .unwrap();
    let changed = relabel(&node, &keys);
    node.install_guild_event(changed).unwrap();
    let id = Uuid::from_u128(1);
    assert!(node.retain_paged_checkpoint_metadata(id, &proof).is_err());
    assert!(
        node.control
            .catalog_paged_checkpoint_retention(id)
            .unwrap()
            .is_none()
    );
}
