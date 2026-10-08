use super::*;
use crate::node::guild_authority::tests::{event, fixture, relabel};
use crate::node::tests::test_coding_transcript;

fn local_private_checkpoint_revision(
    node: &Node,
    writer: &ed25519_dalek::SigningKey,
    guild: [u8; 32],
    root: Uuid,
    parent: [u8; 32],
) -> (
    SignedRecord<mb_core::PagedUserRevision>,
    Vec<(mb_core::CatalogSectorRecord, Vec<u8>)>,
) {
    use mb_core::{CatalogScope, CatalogSection, CatalogSectorRecord};
    let scope = CatalogScope::Dataset {
        guild_id: guild,
        owner: node.keys.node_id(),
        protected_root_id: root,
    };
    let intents = [
        CatalogSection::FileMetadata,
        CatalogSection::FileMetadata,
        CatalogSection::SectorReferences,
    ]
    .map(|section| {
        let intent = mb_store::CatalogIntent {
            id: Uuid::new_v4(),
            scope,
            section,
        };
        node.control.begin_catalog(intent).unwrap();
        intent
    });
    let mut records = std::collections::BTreeMap::new();
    let mut stage =
        |intent: mb_store::CatalogIntent, page: mb_core::CatalogPageRef, bytes: Vec<u8>| {
            node.control.stage_catalog_page(intent, page, &bytes)?;
            let (sector, encrypted) = page.seal_private_page(
                &node.keys.guild_content_id_key(&guild),
                &node.keys.guild_data_key(&guild),
                scope,
                intent.section,
                &bytes,
            )?;
            records.insert(
                sector.id,
                (
                    CatalogSectorRecord {
                        format_version: 1,
                        sector,
                        commitment: mb_core::merkle_commit(&encrypted).unwrap(),
                    },
                    encrypted,
                ),
            );
            Ok::<_, mb_store::CatalogStoreError>(())
        };
    let namespace = mb_core::CatalogFileBuilder::new(
        scope,
        mb_core::CatalogFileStat {
            mode: 0o700,
            modified_secs: 123,
            modified_nanos: 456,
        },
    )
    .unwrap()
    .finish(&mut |page, bytes| stage(intents[0], page, bytes))
    .unwrap();
    let recipes = mb_core::CatalogFileRecipeBuilder::new(scope)
        .unwrap()
        .finish(&mut |page, bytes| stage(intents[1], page, bytes))
        .unwrap();
    let private = crate::PagedPrivateMetadata {
        format_version: mb_core::PAGED_USER_REVISION_VERSION,
        native: mb_core::CatalogNativeFileRoot {
            format_version: 1,
            namespace,
            recipes,
        },
        git: None,
    };
    let (metadata, bootstrap) = private.seal(&node.keys, scope).unwrap();
    records.insert(metadata.sector.id, (metadata.clone(), bootstrap));
    let mut sources = mb_core::CatalogSectorBuilder::new(scope).unwrap();
    let mut sink = |page, bytes: Vec<u8>| node.control.stage_catalog_page(intents[2], page, &bytes);
    for (record, _) in records.values() {
        sources.push(record, &mut sink).unwrap();
    }
    let sources = sources.finish(&mut sink).unwrap();
    let signed = mb_core::PagedUserRevision {
        format_version: mb_core::PAGED_USER_REVISION_VERSION,
        guild_id: guild,
        protected_root_id: root,
        cipher_profile: mb_core::V1_CIPHER_PROFILE,
        revision_id: Uuid::from_u128(240),
        owner: node.keys.node_id(),
        writer_epoch: 1,
        writer_public_key: writer.verifying_key().to_bytes(),
        writer_signature: Vec::new(),
        sequence: 2,
        parent: Some(parent),
        metadata,
        sources,
    }
    .sign(writer, &node.keys)
    .unwrap();
    private
        .publish_local_catalog(
            &node.control,
            &node.keys,
            &signed,
            &mb_core::WriterFence {
                owner: node.keys.node_id(),
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            },
            crate::PagedCatalogIntents {
                native: [intents[0], intents[1]],
                sources: intents[2],
                git: None,
            },
        )
        .unwrap();
    (signed, records.into_values().collect())
}

fn checkpoint_owner_proof(
    node: &mut Node,
    keys: &[KeyMaterial],
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    checkpoint_owner_proof_with_private(node, keys, false)
}

fn checkpoint_owner_proof_with_private(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
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
    let mut inputs = std::collections::BTreeMap::from([(
        target.id,
        (
            mb_core::CatalogSectorRecord {
                format_version: 1,
                sector: target.clone(),
                commitment: commitment.clone(),
            },
            bytes.clone(),
        ),
    )]);
    let paged = private.then(|| {
        let (signed, sources) = local_private_checkpoint_revision(
            node,
            &writer,
            guild,
            root_id,
            revision.value.hash().unwrap(),
        );
        for (record, bytes) in sources {
            inputs.insert(record.sector.id, (record, bytes));
        }
        signed
    });
    let packed = mb_core::pack_incremental(
        profile,
        None,
        inputs
            .values()
            .map(|(record, bytes)| mb_core::PackingInput {
                owner,
                protected_root: mb_core::packing_protected_root(root_id),
                object_id: record.sector.id,
                source_commitment: Some(record.commitment.clone()),
                bytes: bytes.clone(),
            })
            .collect(),
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
    if let Some(signed) = &paged {
        authority
            .push(&R::PagedRevision(signed.clone()), &mut sink)
            .unwrap();
    }
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
    for (record, bytes) in inputs.values() {
        builder
            .push(
                &CatalogPackedSourceRecord::Source {
                    format_version: 1,
                    id: mb_core::CatalogPackedSourceId {
                        owner,
                        protected_root: mb_core::packing_protected_root(root_id),
                        object_id: record.sector.id,
                    },
                    commitment: record.commitment.clone(),
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
                            mb_core::merkle_open_subtree(bytes, index * leaves, leaves)
                                .unwrap()
                                .subtree_root
                        })
                        .collect(),
                },
                &mut sink,
            )
            .unwrap();
    }
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
            .map(|(_, _, bytes)| Ok(bytes.clone()))
            .unwrap_or_else(|| {
                let signed = paged.as_ref().ok_or(mb_store::DatabaseError::NotReady)?;
                node.control.catalog_page(
                    signed.value.scope(),
                    CatalogSection::SectorReferences,
                    page,
                )
            })
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
fn paged_checkpoint_node_private_dependency_authenticates_roots_and_preserves_custody_after_reopen()
{
    let (temp, seed, mut node, mut keys) = fixture();
    let owner = keys
        .iter()
        .position(|keys| keys.node_id() == node.keys.node_id())
        .unwrap();
    keys.swap(0, owner);
    let (proof, intents) = checkpoint_owner_proof_with_private(&mut node, &keys, true);
    let first = proof.index().next_revision(None).unwrap().unwrap();
    let paged = proof
        .index()
        .next_revision(first.revision_key())
        .unwrap()
        .unwrap();
    let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = paged else {
        panic!("expected private paged successor")
    };
    let key = mb_core::CatalogCheckpointRevisionKey::from(&signed.value);
    let flat = node
        .control
        .get_record("guild-dynamic-state", KEY)
        .unwrap()
        .unwrap();
    node.control
        .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
        .unwrap();
    let id = Uuid::from_u128(1);
    node.retain_paged_checkpoint_metadata(id, &proof).unwrap();
    node.retain_paged_checkpoint_local_revision(id, &proof, key)
        .unwrap();
    node.retain_paged_checkpoint_local_revision(id, &proof, key)
        .unwrap();
    let mut other = key;
    other.owner = keys[1].node_id();
    assert!(
        node.retain_paged_checkpoint_local_revision(id, &proof, other)
            .is_err()
    );
    assert!(
        node.retain_paged_checkpoint_local_revision(id, &proof, first.revision_key().unwrap())
            .is_err()
    );
    for intent in intents {
        node.control.cancel_catalog(intent).unwrap();
        while node.control.release_catalog_pin(intent).unwrap() {}
    }
    while node.control.collect_catalog_page().unwrap() {}
    assert!(
        node.control
            .cancel_paged_revision_catalog(signed.value.revision_id)
            .is_err()
    );
    let local = crate::PagedPrivateMetadata::load_local_catalog(
        &node.control,
        &node.keys,
        signed.value.revision_id,
        signed.value.scope(),
    )
    .unwrap()
    .unwrap();
    assert!(local.private.is_some());
    assert_eq!(local.revision, signed);
    node.control
        .put_record("guild-dynamic-state", KEY, &flat)
        .unwrap();
    drop(node);
    let node = Node::open(temp.path(), seed).unwrap();
    node.control
        .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
        .unwrap();
    node.retain_paged_checkpoint_local_revision(id, &proof, key)
        .unwrap();
    let retained = node
        .control
        .catalog_paged_checkpoint_revision(id, signed.value.revision_id)
        .unwrap()
        .unwrap();
    assert_eq!(
        retained.bundle.descriptor,
        canonical_bytes(&signed).unwrap()
    );
    node.control
        .cancel_catalog_paged_checkpoint_retention(id)
        .unwrap();
    assert!(
        node.control
            .release_catalog_paged_checkpoint_root(id)
            .unwrap()
    );
    node.control
        .cancel_paged_revision_catalog(signed.value.revision_id)
        .unwrap();
    assert!(
        node.control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .is_some()
    );
    while node
        .control
        .release_catalog_paged_checkpoint_root(id)
        .unwrap()
    {}
    assert!(
        node.control
            .catalog_paged_checkpoint_certificate(id)
            .unwrap()
            .is_none()
    );
}

fn exercise_checkpoint_payload_custody(information: bool) {
    let (temp, seed, mut node, mut keys) = fixture();
    let local = keys
        .iter()
        .position(|key| key.node_id() == node.keys.node_id())
        .unwrap();
    keys.swap(if information { 0 } else { 1 }, local);
    let (proof, intents) = checkpoint_owner_proof(&mut node, &keys);
    let group = proof
        .index()
        .index()
        .next_group(None)
        .unwrap()
        .unwrap()
        .group
        .range
        .group_id;
    let entry = proof
        .index()
        .index()
        .read_group(group, |page| {
            node.control.catalog_page(
                mb_core::CatalogScope::Guild {
                    guild_id: proof.trust().guild_id,
                },
                mb_core::CatalogSection::Coding,
                page,
            )
        })
        .unwrap()
        .unwrap();
    let plan = &entry.transcript.value.plan;
    let guild = proof.trust().guild_id;
    let original = vec![91; mb_core::V1_SECTOR_SIZE];
    let profile = mb_core::PackingProfile {
        format_version: 1,
        sector_size: mb_core::V1_SECTOR_SIZE as u32,
        slot_size: mb_core::V1_SECTOR_SIZE as u32 / 4,
    };
    let packed = mb_core::pack_incremental(
        profile,
        None,
        vec![mb_core::PackingInput {
            owner: keys[0].node_id(),
            protected_root: mb_core::packing_protected_root(Uuid::from_u128(194)),
            object_id: [193; 32],
            source_commitment: Some(merkle_commit(&original).unwrap()),
            bytes: original,
        }],
    )
    .unwrap();
    let information_id = plan.value.geometry.information[0].sector.id;
    let bytes = packed
        .catalog
        .sectors
        .iter()
        .zip(&packed.sectors)
        .find_map(|(descriptor, sector)| {
            let mut descriptor = descriptor.clone();
            descriptor.flat_root = sector_root(&sector.bytes);
            descriptor.id = descriptor.calculate_id(profile).unwrap();
            (descriptor.id == information_id).then(|| sector.bytes.clone())
        })
        .unwrap();
    let shards = mb_core::encode(entry.retained.group.profile, vec![bytes]).unwrap();
    let shard = if information { 0 } else { 1 };
    let storage = if information { information_id } else { group };
    let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
    for id in ids {
        node.retain_paged_checkpoint_metadata(id, &proof).unwrap();
    }
    assert!(
        node.retain_paged_checkpoint_local_payload(ids[0], &proof, group, shard)
            .is_err()
    );
    if information {
        node.reserve_coding_information(plan, 0).unwrap();
        node.write_coding_information_range(plan, 0, 0, &shards[0])
            .unwrap();
        node.finish_coding_information_upload(plan, 0).unwrap();
    } else {
        let commitment = merkle_commit(&shards[1]).unwrap();
        node.stage_coding_parity(
            plan,
            &entry.transcript.value.manifest,
            &mb_store::VariableParityObject {
                format_version: 2,
                guild_id: guild,
                group_id: group,
                shard_index: 1,
                commitment,
                bytes: shards[1].clone(),
            },
        )
        .unwrap();
    }
    // STAGED bytes are insufficient even when they already match the witness.
    assert!(
        node.retain_paged_checkpoint_local_payload(ids[0], &proof, group, shard)
            .is_err()
    );
    node.activate_coding_attempt(&entry.transcript).unwrap();
    // A damaged locator must fail before a custody pin can be published. Its
    // SQL read is bounded independently of the original authenticated proof.
    let mut locator_key = storage.to_vec();
    locator_key.push(shard as u8);
    let locator = node
        .control
        .get_record("volume-receipt", &locator_key)
        .unwrap()
        .unwrap();
    node.control
        .put_record("volume-receipt", &locator_key, &vec![0; 513])
        .unwrap();
    assert!(
        node.retain_paged_checkpoint_local_payload(ids[0], &proof, group, shard)
            .is_err()
    );
    assert_eq!(
        node.control
            .catalog_paged_checkpoint_payload(ids[0], group, shard)
            .unwrap(),
        None
    );
    node.control
        .put_record("volume-receipt", &locator_key, &locator)
        .unwrap();
    let flat = node
        .control
        .get_record("guild-dynamic-state", KEY)
        .unwrap()
        .unwrap();
    node.control
        .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
        .unwrap();
    let payload = node
        .retain_paged_checkpoint_local_payload(ids[0], &proof, group, shard)
        .unwrap();
    node.retain_paged_checkpoint_local_payload(ids[0], &proof, group, shard)
        .unwrap();
    node.retain_paged_checkpoint_local_payload(ids[1], &proof, group, shard)
        .unwrap();
    assert!(
        node.retain_paged_checkpoint_local_payload(ids[0], &proof, group, 1 - shard)
            .is_err()
    );
    for intent in intents {
        node.control.cancel_catalog(intent).unwrap();
        while node.control.release_catalog_pin(intent).unwrap() {}
    }
    while node.control.collect_catalog_page().unwrap() {}
    node.control
        .put_record("guild-dynamic-state", KEY, &flat)
        .unwrap();
    let state = node.dynamic_guild_state().unwrap().unwrap();
    let retire = event(
        &node,
        &keys,
        mb_core::GuildEventKind::RetireCodingGroup {
            group_id: group,
            retain_through_event: state.event_sequence + 1,
        },
    );
    node.install_guild_event(retire).unwrap();
    let forget = event(
        &node,
        &keys,
        mb_core::GuildEventKind::ForgetCodingGroup { group_id: group },
    );
    node.install_guild_event(forget).unwrap();
    node.discard_coding_attempt(&plan.value.attempt_id).unwrap();
    assert_eq!(
        node.volumes
            .load_ready_variable(&node.control, &storage, shard)
            .unwrap()
            .bytes,
        shards[usize::from(shard)]
    );
    assert!(
        !node
            .volumes
            .remove_unreachable(
                &node.control,
                &storage,
                shard as u8,
                &payload.commitment.root
            )
            .unwrap()
    );
    drop(node);
    let mut node = Node::open(temp.path(), seed.clone()).unwrap();
    assert_eq!(
        node.volumes
            .load_ready_variable(&node.control, &storage, shard)
            .unwrap()
            .bytes,
        shards[usize::from(shard)]
    );
    assert_eq!(
        node.control
            .catalog_paged_checkpoint_payload(ids[0], group, shard)
            .unwrap(),
        Some(payload.clone())
    );
    // Custody follows a verified physical move. Interrupt after the destination
    // is READY, then retry rollback while both copies and the migration exist.
    let source: crate::volume::VolumeReceipt = decode_canonical(&locator).unwrap();
    let source_path = node
        .volumes
        .statuses()
        .unwrap()
        .into_iter()
        .find(|status| status.volume_id == source.volume_id)
        .unwrap()
        .path;
    let destination = tempfile::tempdir().unwrap();
    node.configure_storage_volumes(
        &[source_path, destination.path().to_path_buf()],
        64 << 20,
        0,
    )
    .unwrap();
    node.drain_storage_volume(source.volume_id).unwrap();
    crate::volume::interrupt_next_volume_transition(
        crate::volume::VolumeInterruption::VariableMigrationDestinationReady,
    );
    let interruption = node.migrate_draining_volumes().unwrap_err();
    assert!(
        interruption
            .to_string()
            .contains("VariableMigrationDestinationReady")
    );
    node.discard_coding_attempt(&plan.value.attempt_id).unwrap();
    drop(node);
    let mut node = Node::open(temp.path(), seed.clone()).unwrap();
    node.migrate_draining_volumes().unwrap();
    let moved: crate::volume::VolumeReceipt = decode_canonical(
        &node
            .control
            .get_record("volume-receipt", &locator_key)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_ne!(moved.volume_id, source.volume_id);
    assert_eq!(
        node.volumes
            .load_ready_variable(&node.control, &storage, shard)
            .unwrap()
            .bytes,
        shards[usize::from(shard)]
    );
    assert_eq!(
        node.control
            .catalog_paged_checkpoint_payload(ids[0], group, shard)
            .unwrap(),
        Some(payload.clone())
    );
    // Repair an unavailable copy without dropping its custodied locator before
    // the replacement becomes READY. Restore the old disk and collect both
    // copies only after the last owner retires.
    let object = node
        .volumes
        .load_ready_variable(&node.control, &storage, shard)
        .unwrap();
    drop(node);
    let offline = temp.path().join("offline-custody-volume");
    std::fs::rename(destination.path(), &offline).unwrap();
    let mut node = Node::open(temp.path(), seed.clone()).unwrap();
    let replacement = tempfile::tempdir().unwrap();
    node.configure_storage_volumes(&[replacement.path().to_path_buf()], 64 << 20, 0)
        .unwrap();
    let before = node
        .control
        .get_record("volume-receipt", &locator_key)
        .unwrap();
    assert!(
        !node
            .volumes
            .prepare_variable_repair(&node.control, &object)
            .unwrap()
    );
    assert_eq!(
        node.control
            .get_record("volume-receipt", &locator_key)
            .unwrap(),
        before
    );
    let repair = [225; 16];
    node.volumes
        .reserve_attempt(
            &node.control,
            &repair,
            guild,
            shard,
            object.commitment.byte_len,
        )
        .unwrap();
    node.volumes
        .write_attempt_range(&node.control, &repair, shard, 0, &object.bytes)
        .unwrap();
    node.volumes
        .finish_attempt_upload(&node.control, &repair, storage, shard, &object.commitment)
        .unwrap();
    node.volumes
        .attach_attempt_receipt(
            &node.control,
            &repair,
            &storage,
            shard,
            &payload.transcript_hash,
        )
        .unwrap();
    node.volumes
        .activate_attempt_object(
            &node.control,
            &repair,
            &storage,
            shard,
            &object.commitment,
            &payload.transcript_hash,
        )
        .unwrap();
    node.volumes
        .finalize_attempt(&node.control, &repair)
        .unwrap();
    drop(node);
    std::fs::rename(&offline, destination.path()).unwrap();
    let mut node = Node::open(temp.path(), seed).unwrap();
    node.configure_storage_volumes(
        &[
            destination.path().to_path_buf(),
            replacement.path().to_path_buf(),
        ],
        64 << 20,
        0,
    )
    .unwrap();
    assert_eq!(
        node.volumes
            .load_ready_variable(&node.control, &storage, shard)
            .unwrap(),
        object
    );
    node.control
        .cancel_catalog_paged_checkpoint_retention(ids[0])
        .unwrap();
    assert!(
        node.control
            .release_catalog_paged_checkpoint_root(ids[0])
            .unwrap()
    );
    assert!(
        !node
            .volumes
            .remove_unreachable(
                &node.control,
                &storage,
                shard as u8,
                &payload.commitment.root
            )
            .unwrap()
    );
    while node
        .control
        .release_catalog_paged_checkpoint_root(ids[0])
        .unwrap()
    {}
    node.control
        .cancel_catalog_paged_checkpoint_retention(ids[1])
        .unwrap();
    assert!(
        node.control
            .release_catalog_paged_checkpoint_root(ids[1])
            .unwrap()
    );
    assert!(
        node.volumes
            .remove_unreachable(
                &node.control,
                &storage,
                shard as u8,
                &payload.commitment.root
            )
            .unwrap()
    );
    assert!(
        node.volumes
            .load_ready_variable(&node.control, &storage, shard)
            .is_err()
    );
    while node
        .control
        .release_catalog_paged_checkpoint_root(ids[1])
        .unwrap()
    {}
}

#[test]
fn paged_checkpoint_information_custody_survives_real_forget_rollback_and_reopen() {
    exercise_checkpoint_payload_custody(true);
}

#[test]
fn paged_checkpoint_parity_custody_survives_real_forget_rollback_and_reopen() {
    exercise_checkpoint_payload_custody(false);
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
