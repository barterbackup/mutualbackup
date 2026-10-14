use super::*;
use crate::node::guild_authority::tests::{event, fixture, relabel};
use crate::node::tests::test_coding_transcript;

mod checkpoint_acquisition_tests;
#[cfg(target_os = "linux")]
mod checkpoint_bootstrap_tests;
#[cfg(target_os = "linux")]
mod checkpoint_chain_tests;
#[cfg(target_os = "linux")]
mod checkpoint_peer_restore_tests;
#[cfg(target_os = "linux")]
mod checkpoint_restore_tests;
mod transport;

macro_rules! legacy_custody_cases {
    ($test:ident, $constructor:ident, $metadata:ident, $retain:ident, $step:ident, $cancel:ident, $release:ident, $layout:ident, $lookup:ident) => {
        #[test]
        fn $test() {
            let (temp, seed, mut node, mut keys) = fixture();
            let local = keys
                .iter()
                .position(|key| key.node_id() == node.keys.node_id())
                .unwrap();
            keys.swap(0, local);
            let (proof, _) = $constructor(&mut node, &keys);
            let guild = proof.trust().guild_id;
            let mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(reference) =
                proof.index().next_revision(None).unwrap().unwrap()
            else {
                panic!("original legacy revision")
            };
            let key = mb_core::CatalogCheckpointRevisionKey {
                owner: reference.owner,
                protected_root_id: reference.protected_root_id,
                sequence: reference.sequence,
                revision_id: reference.revision_id,
            };
            let original = reference
                .read_signed(&mut |page| {
                    node.control.catalog_page(
                        mb_core::CatalogScope::Guild { guild_id: guild },
                        mb_core::CatalogSection::Checkpoint,
                        page,
                    )
                })
                .unwrap();
            let original_bytes = canonical_bytes(&original).unwrap();
            node.control.put_record("user-revision", original.value.revision_id.as_bytes(), &original_bytes).unwrap();
            let writer = ed25519_dalek::SigningKey::from_bytes(&[72; 32]);
            let migration_id = Uuid::from_u128(88);
            let migration = crate::RetainedLegacyMigration::new(
                &node.keys,
                guild,
                &original,
                mb_core::WriterFence {
                    owner: node.keys.node_id(),
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                },
                migration_id,
            )
            .unwrap();
            let (_, ciphertext) = mb_core::encrypted_sector(
                &node.keys.guild_data_key(&guild),
                [193; 32],
                &legacy_private_plaintext(),
            )
            .unwrap();
            let converted = migration
                .retain(&node.control, &node.keys, &original, &writer, &mut |id| {
                    anyhow::ensure!(*id == [193; 32]);
                    Ok(ciphertext.clone())
                })
                .unwrap();
            assert_eq!(converted.value.parent, Some(original.value.hash().unwrap()));
            assert_ne!(converted.value.revision_id, original.value.revision_id);
            let ids = [Uuid::from_u128(90), Uuid::from_u128(91)];
            for id in ids {
                node.$metadata(id, &proof).unwrap();
            }
            // No implicit conversion, reference reinterpretation or cursor skip.
            assert!(node.$step(ids[0], &proof).is_err());
            assert_eq!(
                node.control
                    .catalog_paged_checkpoint_legacy_revision(ids[0], key.revision_id)
                    .unwrap(),
                None
            );
            let journal = node
                .control
                .get_record("paged-legacy-migration-v1", migration_id.as_bytes())
                .unwrap()
                .unwrap();
            node.control
                .put_record(
                    "paged-legacy-migration-v1",
                    migration_id.as_bytes(),
                    &vec![0; 513],
                )
                .unwrap();
            assert!(node.$retain(ids[0], &proof, key, migration_id).is_err());
            node.control
                .put_record(
                    "paged-legacy-migration-v1",
                    migration_id.as_bytes(),
                    &journal,
                )
                .unwrap();
            let forward = format!("catalog-checkpoint-legacy-private-v1/{}", ids[0].simple());
            let activate = format!("INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (X'{}', 1, X'{}', X'01');", hex::encode(guild), hex::encode(proof.certificate().checkpoint.hash().unwrap()));
            node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER bridge_head AFTER INSERT ON protocol_records WHEN NEW.kind = '{forward}' BEGIN {activate} END"), false).unwrap();
            assert!(node.$retain(ids[0], &proof, key, migration_id).is_err());
            assert!(node.control.get_record(&forward, key.revision_id.as_bytes()).unwrap().is_none());
            assert!(node.control.checkpoint_head_identity(&guild).unwrap().is_none());
            node.control.database_shell_statement("DROP TRIGGER bridge_head", false).unwrap();
            for id in ids {
                node.$retain(id, &proof, key, migration_id).unwrap();
            }
            node.$lookup(ids[0], &proof).unwrap();
            let snapshot = crate::SnapshotInfo {
                protected_root_id: key.protected_root_id,
                revision_id: key.revision_id,
                sequence: key.sequence,
                checkpoint_generation: proof.certificate().checkpoint.generation,
                checkpoint_hash: proof.certificate().hash().unwrap(),
            };
            let target = temp.path().join("restored-original-legacy");
            node.restore_retained_checkpoint_native_snapshot(
                mb_core::PagedCheckpointLayout::$layout,
                ids[0],
                guild,
                &snapshot,
                &target,
                proof.transition().budget(),
            ).unwrap();
            assert!(target.is_dir());
            assert!(node.control.records("restore-job").unwrap().is_empty());
            assert_eq!(node.control.get_record("user-revision", original.value.revision_id.as_bytes()).unwrap().unwrap(), original_bytes);
            node.$retain(ids[0], &proof, key, migration_id).unwrap();
            let mut other = key;
            other.owner = keys[1].node_id();
            assert!(node.$retain(ids[0], &proof, other, migration_id).is_err());
            let totals_kind = "catalog-checkpoint-legacy-private-work-v1";
            let totals = node.control.get_record(totals_kind, ids[0].as_bytes()).unwrap().unwrap();
            let mut exceeded: Work = decode_canonical(&totals).unwrap();
            exceeded.bytes = proof.transition().budget().bytes;
            node.control.put_record(totals_kind, ids[0].as_bytes(), &canonical_bytes(&exceeded).unwrap()).unwrap();
            assert!(node.$retain(ids[0], &proof, key, migration_id).is_err());
            node.control.put_record(totals_kind, ids[0].as_bytes(), &totals).unwrap();
            assert!(migration.cancel(&node.control).is_err());
            assert_eq!(
                node.control
                    .get_record("paged-legacy-migration-v1", migration_id.as_bytes())
                    .unwrap()
                    .unwrap(),
                journal
            );
            assert!(
                node.control
                    .cancel_paged_revision_catalog(migration_id)
                    .is_err()
            );
            // Paired dependency damage fails without repairing away a lost pin.
            let reverse = format!(
                "catalog-legacy-private-checkpoint-v1/{}",
                migration_id.simple()
            );
            let pin = node
                .control
                .get_record(&reverse, ids[0].as_bytes())
                .unwrap()
                .unwrap();
            node.control
                .delete_record_if_value(&reverse, ids[0].as_bytes(), &pin)
                .unwrap();
            assert!(node.$step(ids[0], &proof).is_err());
            assert!(node.$retain(ids[0], &proof, key, migration_id).is_err());
            assert!(
                node.control
                    .catalog_paged_checkpoint_legacy_revision(ids[0], key.revision_id)
                    .is_err()
            );
            node.control
                .put_record_if_absent(&reverse, ids[0].as_bytes(), &pin)
                .unwrap();
            node.control
                .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
                .unwrap();
            drop(node);
            let mut node = Node::open(temp.path(), seed).unwrap();
            let progress = node.$step(ids[0], &proof).unwrap();
            assert_eq!(
                (
                    progress.revisions,
                    progress.legacy_revisions,
                    progress.local_revisions
                ),
                (1, 1, 1)
            );
            assert_eq!(
                node.$step(ids[0], &proof).unwrap().phase,
                mb_store::CatalogCheckpointLocalCustodyPhase::Coding
            );
            assert!(node.$step(ids[0], &proof).is_err());
            let profile = mb_core::PackingProfile {
                format_version: 1,
                sector_size: mb_core::V1_SECTOR_SIZE as u32,
                slot_size: mb_core::V1_SECTOR_SIZE as u32 / 4,
            };
            let packed = mb_core::pack_incremental(
                profile,
                None,
                vec![mb_core::PackingInput {
                    owner: key.owner,
                    protected_root: mb_core::packing_protected_root(key.protected_root_id),
                    object_id: [193; 32],
                    source_commitment: Some(merkle_commit(&ciphertext).unwrap()),
                    bytes: ciphertext,
                }],
            )
            .unwrap();
            let mut cursor = None;
            while let Some(row) = proof.index().index().next_group(cursor).unwrap() {
                let group = row.group.range.group_id;
                let entry = proof
                    .index()
                    .index()
                    .read_group(group, |page| {
                        node.control.catalog_page(
                            mb_core::CatalogScope::Guild { guild_id: guild },
                            mb_core::CatalogSection::Coding,
                            page,
                        )
                    })
                    .unwrap()
                    .unwrap();
                let plan = &entry.transcript.value.plan;
                let information = &plan.value.geometry.information[0].sector;
                let bytes = packed
                    .catalog
                    .sectors
                    .iter()
                    .zip(&packed.sectors)
                    .find_map(|(descriptor, sector)| {
                        let mut descriptor = descriptor.clone();
                        descriptor.flat_root = sector_root(&sector.bytes);
                        descriptor.id = descriptor.calculate_id(profile).unwrap();
                        (descriptor.id == information.id).then(|| sector.bytes.clone())
                    })
                    .unwrap();
                node.reserve_coding_information(plan, 0).unwrap();
                node.write_coding_information_range(plan, 0, 0, &bytes)
                    .unwrap();
                node.finish_coding_information_upload(plan, 0).unwrap();
                node.activate_coding_attempt(&entry.transcript).unwrap();
                cursor = Some(group);
            }
            for id in ids {
                let mut complete = None;
                for _ in 0..6 {
                    let progress = node.$step(id, &proof).unwrap();
                    if progress.phase == mb_store::CatalogCheckpointLocalCustodyPhase::Complete {
                        complete = Some(progress);
                        break;
                    }
                }
                let complete = complete.expect("complete original legacy inventory");
                assert_eq!(
                    (
                        complete.revisions,
                        complete.legacy_revisions,
                        complete.local_revisions
                    ),
                    (1, 1, 1)
                );
                assert_eq!(
                    complete.coding,
                    proof.certificate().checkpoint.coding.summary.coding
                );
                assert_eq!(complete.local_payloads, complete.coding.information_roles);
            }
            assert_eq!(
                canonical_bytes(
                    &reference
                        .read_signed(&mut |page| node.control.catalog_page(
                            mb_core::CatalogScope::Guild { guild_id: guild },
                            mb_core::CatalogSection::Checkpoint,
                            page
                        ))
                        .unwrap()
                )
                .unwrap(),
                original_bytes
            );
            assert!(
                node.control
                    .checkpoint_head_identity(&guild)
                    .unwrap()
                    .is_none()
            );
            node.control.$cancel(ids[0]).unwrap();
            while node.control.$release(ids[0]).unwrap() {}
            assert!(migration.cancel(&node.control).is_err());
            let last_pin = node.control.get_record(&reverse, ids[1].as_bytes()).unwrap().unwrap();
            node.control.delete_record_if_value(&reverse, ids[1].as_bytes(), &last_pin).unwrap();
            assert!(migration.cancel(&node.control).is_err());
            assert_eq!(node.control.get_record("paged-legacy-migration-v1", migration_id.as_bytes()).unwrap().unwrap(), journal);
            node.control.put_record_if_absent(&reverse, ids[1].as_bytes(), &last_pin).unwrap();
            assert_eq!(
                node.$step(ids[1], &proof).unwrap().phase,
                mb_store::CatalogCheckpointLocalCustodyPhase::Complete
            );
            node.control.$cancel(ids[1]).unwrap();
            node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER bridge_retire_head AFTER DELETE ON protocol_records WHEN OLD.kind = 'catalog-checkpoint-legacy-private-v1/{}' BEGIN {activate} END", ids[1].simple()), false).unwrap();
            // Payload dependencies retire first; the bridge's guarded DELETE must
            // roll back both its pin transfer and an unexpected actual head.
            let mut refused = false;
            for _ in 0..8 {
                match node.control.$release(ids[1]) {
                    Ok(true) => {},
                    Err(_) => { refused = true; break; },
                    Ok(false) => panic!("legacy bridge retired despite head trigger"),
                }
            }
            assert!(refused);
            assert!(node.control.checkpoint_head_identity(&guild).unwrap().is_none());
            assert!(migration.cancel(&node.control).is_err());
            node.control.database_shell_statement("DROP TRIGGER bridge_retire_head", false).unwrap();
            while node.control.$release(ids[1]).unwrap() {}
            assert_eq!(
                node.control
                    .catalog_paged_checkpoint_legacy_revision(ids[1], key.revision_id)
                    .unwrap(),
                None
            );
            migration.cancel(&node.control).unwrap();
            while migration.cleanup_step(&node.control).unwrap() {}
            assert_eq!(node.control.get_record("user-revision", key.revision_id.as_bytes()).unwrap().unwrap(), original_bytes);
        }
    };
}
legacy_custody_cases!(
    paged_checkpoint_legacy_private_custody_preserves_identity_reopens_and_blocks_migration_cancel,
    legacy_private_checkpoint,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_legacy_revision,
    retain_paged_checkpoint_local_custody_step,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root,
    Individual,
    build_retained_paged_checkpoint_lookup
);
legacy_custody_cases!(
    directory_checkpoint_legacy_private_custody_preserves_identity_reopens_and_blocks_migration_cancel,
    legacy_private_directory, retain_paged_checkpoint_directory_metadata, retain_paged_checkpoint_directory_local_legacy_revision,
    retain_paged_checkpoint_directory_local_custody_step, cancel_catalog_paged_checkpoint_directory_retention, release_catalog_paged_checkpoint_directory_root,
    Directory, build_retained_paged_checkpoint_directory_lookup
);

macro_rules! local_custody_cases {
    ($test:ident, $constructor:ident, $metadata:ident, $step:ident, $cancel:ident, $release:ident) => {
        #[test]
        fn $test() {
            let (temp, seed, mut node, mut keys) = fixture();
            let local = keys
                .iter()
                .position(|key| key.node_id() == node.keys.node_id())
                .unwrap();
            keys.swap(1, local);
            let (proof, _) = $constructor(&mut node, &keys, false, unix_seconds() + 600);
            let guild = proof.trust().guild_id;
            let id = Uuid::from_u128(90);
            node.$metadata(id, &proof).unwrap();
            let first = node.$step(id, &proof).unwrap();
            assert_eq!(first.revisions, 1);
            assert_eq!(first.local_revisions, 0);
            assert_eq!(
                first.phase,
                mb_store::CatalogCheckpointLocalCustodyPhase::Revisions
            );
            let coding = node.$step(id, &proof).unwrap();
            assert_eq!(
                coding.phase,
                mb_store::CatalogCheckpointLocalCustodyPhase::Coding
            );
            assert!(node.$step(id, &proof).is_err());
            let saved = node
                .control
                .get_record("catalog-checkpoint-local-custody-v1", id.as_bytes())
                .unwrap();
            let progress: mb_store::CatalogCheckpointLocalCustody =
                decode_canonical(saved.as_ref().unwrap()).unwrap();
            assert_eq!(progress, coding);
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
            let mut cursor = None;
            while let Some(row) = proof.index().index().next_group(cursor).unwrap() {
                let group = row.group.range.group_id;
                let entry = proof
                    .index()
                    .index()
                    .read_group(group, |page| {
                        node.control.catalog_page(
                            mb_core::CatalogScope::Guild { guild_id: guild },
                            mb_core::CatalogSection::Coding,
                            page,
                        )
                    })
                    .unwrap()
                    .unwrap();
                let plan = &entry.transcript.value.plan;
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
                node.activate_coding_attempt(&entry.transcript).unwrap();
                cursor = Some(group);
            }
            node.control
                .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
                .unwrap();
            drop(node);
            let node = Node::open(temp.path(), seed).unwrap();
            let mut completed = None;
            for _ in 0..4 {
                let progress = node.$step(id, &proof).unwrap();
                if progress.phase == mb_store::CatalogCheckpointLocalCustodyPhase::Complete {
                    completed = Some(progress);
                    break;
                }
            }
            let completed = completed.expect("local custody did not reach complete inventory EOF");
            let expected = proof.certificate().checkpoint.coding.summary.coding;
            assert_eq!(completed.coding, expected);
            assert_eq!(completed.local_payloads, expected.parity_roles);
            assert_eq!(node.$step(id, &proof).unwrap(), completed);
            assert!(
                node.control
                    .checkpoint_head_identity(&guild)
                    .unwrap()
                    .is_none()
            );
            node.control.$cancel(id).unwrap();
            assert!(
                node.control
                    .get_record("catalog-checkpoint-local-custody-v1", id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(node.$step(id, &proof).is_err());
            while node.control.$release(id).unwrap() {}
        }
    };
}
local_custody_cases!(
    paged_checkpoint_complete_local_custody_requires_all_ready_assignments_and_resumes_original_history,
    checkpoint_owner_proof_at,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_custody_step,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
local_custody_cases!(
    paged_checkpoint_directory_complete_local_custody_requires_all_ready_assignments_and_resumes_original_history,
    directory_owner_proof_at,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_custody_step,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);

fn directory_owner_proof(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
) -> (
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    Vec<mb_store::CatalogIntent>,
) {
    directory_owner_proof_at(node, keys, private, unix_seconds() + 600)
}

fn directory_owner_proof_at(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
) -> (
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    Vec<mb_store::CatalogIntent>,
) {
    directory_owner_proof_at_with_rooted_sources(node, keys, private, expires, false)
}

fn directory_owner_proof_at_with_rooted_sources(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
    rooted_sources: bool,
) -> (
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    Vec<mb_store::CatalogIntent>,
) {
    let (original, intents) = checkpoint_owner_proof_at_with_rooted_sources(
        node,
        keys,
        private,
        expires,
        true,
        rooted_sources,
    );
    directory_from_original(node, keys, original, intents)
}

fn directory_from_original(
    node: &mut Node,
    keys: &[KeyMaterial],
    original: mb_store::CatalogQuorumPagedCheckpointIndex,
    mut intents: Vec<mb_store::CatalogIntent>,
) -> (
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    Vec<mb_store::CatalogIntent>,
) {
    use mb_core::{
        CatalogPackedSourceReader, CatalogPackedSourceRecord as R, CatalogPackingDirectoryBuilder,
        CatalogPackingDirectoryRecord as Part, CatalogScope, CatalogSection,
    };
    let header = original.certificate().checkpoint;
    let trust = original.trust().clone();
    let scope = CatalogScope::Guild {
        guild_id: header.guild_id,
    };
    let work = original.transition().budget();
    let mut sources = CatalogPackedSourceReader::new(scope, header.packed_sources).unwrap();
    let mut bounds = Vec::new();
    while let Some(record) = sources
        .next_record(&mut |page| {
            node.control
                .catalog_page(scope, CatalogSection::Packing, page)
        })
        .unwrap()
    {
        if let R::Source { id, .. } = record {
            bounds.push(id);
        }
    }
    let mut builder = CatalogPackingDirectoryBuilder::new(
        scope,
        header.packed_sources.format_version,
        header.packed_sources.profile,
        work,
    )
    .unwrap();
    let mut pages = BTreeMap::new();
    let mut sink = |page: mb_core::CatalogPageRef, bytes| {
        pages.insert(page.hash, (page, bytes));
        Ok::<_, ()>(())
    };
    builder
        .push(
            Part::Sources(mb_core::CatalogPackedSourcePart {
                format_version: 1,
                first: bounds[0],
                last: *bounds.last().unwrap(),
                root: header.packed_sources,
            }),
            &mut sink,
        )
        .unwrap();
    builder
        .push(
            Part::Sectors(mb_core::CatalogPackedSectorPart {
                format_version: 1,
                first_sector: 0,
                root: header.packed_sectors,
            }),
            &mut sink,
        )
        .unwrap();
    let directory = builder.finish(&mut sink).unwrap();
    for (page, bytes) in pages.values() {
        let intent = mb_store::CatalogIntent {
            id: Uuid::new_v4(),
            scope,
            section: CatalogSection::Packing,
        };
        node.control.begin_catalog(intent).unwrap();
        node.control
            .stage_catalog_page(intent, *page, bytes)
            .unwrap();
        intents.push(intent);
    }
    let installed = node.installed_guild().unwrap().unwrap();
    let history = mb_store::CatalogGuildHistoryIndex::build(
        mb_store::RecordScratchStore::new(2 << 20).unwrap(),
        &installed.certificate,
        work,
        Work::default(),
        || Ok(trust.clone()),
        &mut &node.control,
    )
    .unwrap();
    let view = history.view(|| Ok(trust.clone())).unwrap();
    let authority = original.index().authority();
    let body = mb_store::CatalogCheckpointAuthorityIndex::build(
        authority.context,
        authority.root,
        &trust.members,
        work,
        mb_store::RecordScratchStore::new(2 << 20).unwrap(),
        |scope, section, page| node.control.catalog_page(scope, section, page),
        |candidate, _| {
            if view.current_writer(candidate.owner, &trust)?.as_ref() == Some(candidate) {
                Ok(())
            } else {
                Err(mb_store::DatabaseError::Conflict.into())
            }
        },
    )
    .unwrap()
    .validate_packing_directory(
        mb_store::CatalogPackingDirectoryValidation {
            format_version: 1,
            scope,
            directory,
        },
        |page| {
            node.control
                .catalog_page(scope, CatalogSection::Packing, page)
        },
    )
    .unwrap()
    .validate_coding_directory(
        header.coding,
        mb_store::CatalogCodingCoveragePolicy::Current,
        |page| {
            node.control
                .catalog_page(scope, CatalogSection::Coding, page)
        },
        |_| Ok(mb_store::CatalogCodingAuthorization::CurrentPlacement),
    )
    .unwrap();
    let transition = body
        .validate_certified_history_coding_state(&history, work, || Ok(trust.clone()))
        .unwrap()
        .validate_certified_history_authority_transition(None, &history, work, || Ok(trust.clone()))
        .unwrap();
    let mut checkpoint = None;
    let mut signatures = Vec::new();
    for key in keys {
        let (header, signature) = transition
            .sign_paged_checkpoint_header(key, || Ok(trust.clone()))
            .unwrap();
        checkpoint = Some(header);
        signatures.push(signature);
    }
    signatures.sort_by_key(|signature| signature.signer);
    let proof = transition
        .bind_paged_checkpoint_header(
            mb_core::QuorumPagedCheckpointDirectory {
                checkpoint: checkpoint.unwrap(),
                signatures,
            },
            || Ok(trust.clone()),
        )
        .unwrap();
    (proof, intents)
}

#[test]
fn paged_checkpoint_directory_node_owner_authenticates_private_custody_and_reopens_without_advancing_heads()
 {
    let (temp, seed, mut node, mut keys) = fixture();
    let owner = keys
        .iter()
        .position(|key| key.node_id() == node.keys.node_id())
        .unwrap();
    keys.swap(0, owner);
    let (proof, captures) = directory_owner_proof(&mut node, &keys, true);
    assert_eq!(proof.certificate().checkpoint.format_version, 10);
    let first = proof.index().next_revision(None).unwrap().unwrap();
    let record = proof
        .index()
        .next_revision(first.revision_key())
        .unwrap()
        .unwrap();
    let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = record else {
        panic!("private successor expected")
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
    let retained = node
        .retain_paged_checkpoint_directory_metadata(id, &proof)
        .unwrap();
    node.build_retained_paged_checkpoint_directory_lookup(id, &proof)
        .unwrap();
    let (first_page, cursor) = node
        .retained_checkpoint_snapshot_page(
            mb_core::PagedCheckpointLayout::Directory,
            id,
            proof.certificate().hash().unwrap(),
            None,
            1,
            proof.transition().budget(),
        )
        .unwrap();
    assert_eq!(first_page.len(), 1);
    let (second_page, _) = node
        .retained_checkpoint_snapshot_page(
            mb_core::PagedCheckpointLayout::Directory,
            id,
            proof.certificate().hash().unwrap(),
            cursor,
            1,
            proof.transition().budget(),
        )
        .unwrap();
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].revision_id, signed.value.revision_id);
    assert!(
        node.retained_checkpoint_snapshot_page(
            mb_core::PagedCheckpointLayout::Directory,
            id,
            [248; 32],
            None,
            1,
            proof.transition().budget()
        )
        .is_err()
    );
    assert!(
        node.retained_checkpoint_snapshot_page(
            mb_core::PagedCheckpointLayout::Directory,
            id,
            proof.certificate().hash().unwrap(),
            None,
            0,
            proof.transition().budget()
        )
        .is_err()
    );
    node.retain_paged_checkpoint_directory_local_revision(id, &proof, key)
        .unwrap();
    let mut wrong = key;
    wrong.owner = keys[1].node_id();
    assert!(
        node.retain_paged_checkpoint_directory_local_revision(id, &proof, wrong)
            .is_err()
    );
    for intent in captures {
        node.control.cancel_catalog(intent).unwrap();
        while node.control.release_catalog_pin(intent).unwrap() {}
    }
    while node.control.collect_catalog_page().unwrap() {}
    assert!(
        node.control
            .cancel_paged_revision_catalog(signed.value.revision_id)
            .is_err()
    );
    assert!(
        node.control
            .checkpoint_head_identity(&proof.trust().guild_id)
            .unwrap()
            .is_none()
    );
    node.control
        .put_record("guild-dynamic-state", KEY, &flat)
        .unwrap();
    drop(node);
    let node = Node::open(temp.path(), seed).unwrap();
    let (snapshots, _) = node
        .retained_checkpoint_snapshot_page(
            mb_core::PagedCheckpointLayout::Directory,
            id,
            proof.certificate().hash().unwrap(),
            None,
            2,
            proof.transition().budget(),
        )
        .unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(
        node.control
            .catalog_paged_checkpoint_directory_retention(id)
            .unwrap(),
        Some((
            retained,
            mb_store::CatalogPagedCheckpointRetentionState::Published
        ))
    );
    assert_eq!(
        node.control
            .catalog_paged_checkpoint_directory_certificate(id)
            .unwrap()
            .as_ref(),
        Some(proof.certificate())
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
    node.control
        .cancel_catalog_paged_checkpoint_directory_retention(id)
        .unwrap();
    while node
        .control
        .release_catalog_paged_checkpoint_directory_root(id)
        .unwrap()
    {}
    assert!(
        node.control
            .catalog_paged_checkpoint_revision(id, signed.value.revision_id)
            .unwrap()
            .is_none()
    );
}

fn local_private_checkpoint_revision_inner<const GIT: bool>(
    node: &Node,
    writer: &ed25519_dalek::SigningKey,
    guild: [u8; 32],
    root: Uuid,
    parent: [u8; 32],
    rooted_sources: bool,
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
    let data = GIT.then(|| {
        let payload = b"retained raw\r\n\0";
        let id = mb_core::make_content_sector_id(
            &node.keys.guild_content_id_key(&guild),
            node.keys.node_id(),
            guild,
            root,
            mb_core::SectorPurpose::Data,
            payload,
        )
        .unwrap();
        let (sector, bytes) =
            mb_core::encrypted_sector(&node.keys.guild_data_key(&guild), id, payload).unwrap();
        records.insert(
            id,
            (
                CatalogSectorRecord {
                    format_version: 1,
                    sector: sector.clone(),
                    commitment: mb_core::merkle_commit(&bytes).unwrap(),
                },
                bytes,
            ),
        );
        (sector, payload.as_slice())
    });
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
    let stat = mb_core::CatalogFileStat {
        mode: if GIT { 0o555 } else { 0o700 },
        modified_secs: 123,
        modified_nanos: 456,
    };
    let mut namespace = mb_core::CatalogFileBuilder::new(scope, stat).unwrap();
    let mut recipes = mb_core::CatalogFileRecipeBuilder::new(scope).unwrap();
    if let Some((reference, payload)) = &data {
        namespace
            .push(
                &mb_core::CatalogFileRecord {
                    format_version: 1,
                    path: b"payload-\xff".to_vec(),
                    stat: mb_core::CatalogFileStat {
                        mode: 0o755,
                        ..stat
                    },
                    kind: mb_core::CatalogFileKind::File {
                        file_key: 0,
                        logical_len: 8192,
                        link_group: None,
                    },
                },
                &mut |page, bytes| stage(intents[0], page, bytes),
            )
            .unwrap();
        recipes
            .push_file(
                0,
                8192,
                std::iter::once(mb_core::CatalogFileExtent {
                    offset: 4096,
                    logical_len: payload.len() as u64,
                    sectors: std::slice::from_ref(reference),
                }),
                &mut |page, bytes| stage(intents[1], page, bytes),
            )
            .unwrap();
    }
    let namespace = namespace
        .finish(&mut |page, bytes| stage(intents[0], page, bytes))
        .unwrap();
    let recipes = recipes
        .finish(&mut |page, bytes| stage(intents[1], page, bytes))
        .unwrap();
    let git_intents = GIT.then(|| {
        std::array::from_fn::<_, 3, _>(|_| {
            let intent = mb_store::CatalogIntent {
                id: Uuid::new_v4(),
                scope,
                section: CatalogSection::GitGraph,
            };
            node.control.begin_catalog(intent).unwrap();
            intent
        })
    });
    let git = git_intents.map(|git_intents| {
        let (reference, payload) = data.as_ref().unwrap();
        let mut blob = vec![0; 8192]; blob[4096..4096 + payload.len()].copy_from_slice(payload);
        let blob_oid = git2::Oid::hash_object(git2::ObjectType::Blob, &blob).unwrap();
        let mut tree = b"100755 payload-\xff\0".to_vec(); tree.extend_from_slice(blob_oid.as_bytes());
        let tree_oid = git2::Oid::hash_object(git2::ObjectType::Tree, &tree).unwrap();
        let mut commit = format!("tree {tree_oid}\nauthor A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\nretained original\n").into_bytes();
        commit.resize(commit.len() + 2 * mb_git::GIT_OBJECT_FRAGMENT_BYTES + 17, b'x');
        let commit_oid = git2::Oid::hash_object(git2::ObjectType::Commit, &commit).unwrap();
        let tag = format!("object {commit_oid}\ntype commit\ntag saved\ntagger A <a@test> 1 +0000\n\noriginal tag\n").into_bytes();
        let tag_oid = git2::Oid::hash_object(git2::ObjectType::Tag, &tag).unwrap();
        let mut objects = [(2, tree_oid, tree), (1, commit_oid, commit), (3, tag_oid, tag)]; objects.sort_by_key(|row| row.1);
        let mut builder = mb_git::GitObjectCatalogBuilder::new(scope).unwrap();
        for (kind, oid, bytes) in &objects { builder.push_object(oid.as_bytes().try_into().unwrap(), *kind, bytes.len() as u64, &mut bytes.as_slice(), &mut |page, bytes| stage(git_intents[1], page, bytes)).unwrap(); }
        let objects = builder.finish(&mut |page, bytes| stage(git_intents[1], page, bytes)).unwrap();
        let mut refs = mb_git::GitRefCatalogBuilder::new(scope, b"main").unwrap();
        for (name, oid) in [(b"refs/heads/main".as_slice(), commit_oid), (b"refs/tags/saved".as_slice(), tag_oid)] { refs.push_ref(&mb_git::GitRefRecord { format_version: 1, name: name.to_vec(), oid: oid.as_bytes().try_into().unwrap() }, &mut |page, bytes| stage(git_intents[0], page, bytes)).unwrap(); }
        let refs = refs.finish(&mut |page, bytes| stage(git_intents[0], page, bytes)).unwrap();
        let mut blobs = mb_git::GitBlobCatalogBuilder::new(scope).unwrap();
        for record in [mb_git::GitBlobRecord::Blob { format_version: 1, oid: blob_oid.as_bytes().try_into().unwrap(), logical_len: 8192, extents: 1, sectors: 1 }, mb_git::GitBlobRecord::Extent { offset: 4096, logical_len: payload.len() as u64, sectors: 1 }, mb_git::GitBlobRecord::Sectors { first_sector: 0, references: vec![reference.clone()] }] { blobs.push_record(&record, &mut |page, bytes| stage(git_intents[2], page, bytes)).unwrap(); }
        mb_git::GitCatalogRoot { format_version: 1, repository_id: root, refs, objects, blobs: blobs.finish(&mut |page, bytes| stage(git_intents[2], page, bytes)).unwrap() }
    });
    let private = crate::PagedPrivateMetadata {
        format_version: mb_core::PAGED_USER_REVISION_VERSION,
        native: mb_core::CatalogNativeFileRoot {
            format_version: 1,
            namespace,
            recipes,
        },
        git,
    };
    let (metadata, bootstrap) = private.seal(&node.keys, scope).unwrap();
    records.insert(metadata.sector.id, (metadata.clone(), bootstrap));
    let mut sources = mb_core::CatalogSectorBuilder::new(scope).unwrap();
    let mut sink = |page, bytes: Vec<u8>| node.control.stage_catalog_page(intents[2], page, &bytes);
    for (record, _) in records.values() {
        sources.push(record, &mut sink).unwrap();
    }
    let sources = sources.finish(&mut sink).unwrap();
    let sources = if rooted_sources {
        transport::wrap_sources(node, intents[2], sources)
    } else {
        sources
    };
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
    let data_source = data.as_ref().map(|(_, payload)| {
        let source_root = node.data_dir.join("retained-git-source");
        std::fs::create_dir(&source_root).unwrap();
        let area = mb_store::StableAnchorAreaLocator::prepare_for_root(&source_root).unwrap();
        let anchor_id = Uuid::new_v4();
        let directory = area.path_hint.join(anchor_id.to_string());
        std::fs::create_dir(&directory).unwrap();
        std::fs::write(directory.join("payload"), payload).unwrap();
        crate::PagedAnchorSectorSource {
            locator: mb_store::StableAnchorFileLocator {
                area,
                anchor_id,
                relative_path: "payload".into(),
            },
            offset: 0,
        }
    });
    private
        .publish_local_catalog_with_data_sources(
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
                git: git_intents,
            },
            |record| {
                Ok(data.as_ref().and_then(|(reference, _)| {
                    (record.sector.id == reference.id)
                        .then(|| data_source.as_ref().unwrap().clone())
                }))
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
    checkpoint_owner_proof_at(node, keys, private, unix_seconds() + 600)
}

fn checkpoint_owner_proof_at(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    checkpoint_owner_proof_at_with_budgeted_authority(node, keys, private, expires, false)
}

fn checkpoint_owner_proof_at_with_budgeted_authority(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
    budgeted: bool,
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    checkpoint_owner_proof_at_with_rooted_sources(node, keys, private, expires, budgeted, false)
}

fn checkpoint_owner_proof_at_with_rooted_sources(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
    budgeted: bool,
    rooted_sources: bool,
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    checkpoint_owner_proof_at_with_legacy_private(
        node,
        keys,
        private,
        expires,
        budgeted,
        rooted_sources,
        false,
    )
}

fn legacy_private_checkpoint(
    node: &mut Node,
    keys: &[KeyMaterial],
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    checkpoint_owner_proof_at_with_legacy_private(
        node,
        keys,
        false,
        unix_seconds() + 600,
        true,
        false,
        true,
    )
}

fn legacy_private_directory(
    node: &mut Node,
    keys: &[KeyMaterial],
) -> (
    mb_store::CatalogQuorumPagedCheckpointDirectoryIndex,
    Vec<mb_store::CatalogIntent>,
) {
    let (proof, intents) = legacy_private_checkpoint(node, keys);
    directory_from_original(node, keys, proof, intents)
}

fn legacy_private_plaintext() -> Vec<u8> {
    canonical_bytes(&crate::PrivateMetadata {
        format_version: 3,
        root_mode: 0o700,
        root_modified_secs: 123,
        root_modified_nanos: 456,
        entries: Vec::new(),
    })
    .unwrap()
}

fn checkpoint_owner_proof_at_with_legacy_private(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
    budgeted: bool,
    rooted_sources: bool,
    legacy_private: bool,
) -> (
    mb_store::CatalogQuorumPagedCheckpointIndex,
    Vec<mb_store::CatalogIntent>,
) {
    checkpoint_owner_proof_with_git_inner::<false>(
        node,
        keys,
        private,
        expires,
        budgeted,
        rooted_sources,
        legacy_private,
    )
}

fn checkpoint_owner_proof_with_git_inner<const GIT: bool>(
    node: &mut Node,
    keys: &[KeyMaterial],
    private: bool,
    expires: u64,
    budgeted: bool,
    rooted_sources: bool,
    legacy_private: bool,
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
    let work = node
        .control
        .catalog_capacity_policy()
        .unwrap()
        .map(|policy| policy.plan().unwrap().job_work)
        .unwrap_or(Work {
            bytes: 64 << 20,
            records: 65536,
            page_occurrences: 65536,
        });
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
    let (target, bytes) = if legacy_private {
        mb_core::encrypted_sector(
            &keys[0].guild_data_key(&guild),
            [193; 32],
            &legacy_private_plaintext(),
        )
        .unwrap()
    } else {
        let bytes = vec![91; mb_core::V1_SECTOR_SIZE];
        (
            SectorRef {
                id: [193; 32],
                root: sector_root(&bytes),
                logical_len: mb_core::V1_SECTOR_SIZE as u32,
            },
            bytes,
        )
    };
    let commitment = mb_core::merkle_commit(&bytes).unwrap();
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
        let (signed, sources) = local_private_checkpoint_revision_inner::<GIT>(
            node,
            &writer,
            guild,
            root_id,
            revision.value.hash().unwrap(),
            rooted_sources,
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
                    owner: keys[usize::from(GIT)].node_id(),
                    failure_domain: member(&keys[usize::from(GIT)]).failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: descriptor.id,
                        commitment: descriptor.commitment.clone(),
                        logical_len: profile.sector_size,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: keys[usize::from(!GIT)].node_id(),
                    failure_domain: member(&keys[usize::from(!GIT)]).failure_domain.clone(),
                    row: 0,
                }],
            },
            delegator: keys[2].node_id(),
            coding_coordinator: keys[3].node_id(),
            verification_coordinator: keys[4].node_id(),
            expires_at_unix_seconds: expires,
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
        if GIT {
            // Only parity is local. Full restore must reconstruct information
            // from retained READY bytes after its original source disappears.
            node.stage_coding_parity(
                &transcript.value.plan,
                &transcript.value.manifest,
                &mb_store::VariableParityObject {
                    format_version: 2,
                    guild_id: guild,
                    group_id: transcript.value.manifest.value.group.id,
                    shard_index: 1,
                    commitment: merkle_commit(&shards[1]).unwrap(),
                    bytes: shards[1].clone(),
                },
            )
            .unwrap();
            node.activate_coding_attempt(&transcript).unwrap();
        }
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
    let mut authority = if budgeted {
        CatalogCheckpointAuthorityBuilder::new_with_budget(
            scope,
            1,
            trust.authority.membership_epoch,
            work,
        )
    } else {
        CatalogCheckpointAuthorityBuilder::new(scope, 1, trust.authority.membership_epoch)
    }
    .unwrap();
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

macro_rules! payload_custody_cases {
    ($exercise:ident, $constructor:ident, $metadata:ident, $payload:ident, $cancel:ident, $release:ident) => {
        fn $exercise(information: bool, legacy: bool) {
            let (temp, seed, mut node, mut keys) = fixture();
            let local = keys
                .iter()
                .position(|key| key.node_id() == node.keys.node_id())
                .unwrap();
            keys.swap(if information { 0 } else { 1 }, local);
            if legacy {
                let source = temp.path().join("legacy-source-volume");
                std::fs::create_dir(&source).unwrap();
                node.configure_storage_volumes(&[source], 64 << 20, 0)
                    .unwrap();
            }
            let (proof, intents) = if legacy {
                $constructor(&mut node, &keys, false, 1)
            } else {
                $constructor(&mut node, &keys, false, unix_seconds() + 600)
            };
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
                node.$metadata(id, &proof).unwrap();
            }
            assert!(node.$payload(ids[0], &proof, group, shard).is_err());
            if legacy {
                // Reproduce the prior normal upload/activation state without inventing
                // a receipt or changing its original expired plan and signed witness.
                node.volumes
                    .reserve_attempt(
                        &node.control,
                        &plan.value.attempt_id,
                        guild,
                        0,
                        shards[0].len() as u32,
                    )
                    .unwrap();
                node.volumes
                    .write_attempt_range(&node.control, &plan.value.attempt_id, 0, 0, &shards[0])
                    .unwrap();
                node.volumes
                    .finish_attempt_upload(
                        &node.control,
                        &plan.value.attempt_id,
                        storage,
                        0,
                        &plan.value.geometry.information[0].sector.commitment,
                    )
                    .unwrap();
            } else if information {
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
            assert!(node.$payload(ids[0], &proof, group, shard).is_err());
            if legacy {
                let commitment = merkle_commit(&shards[0]).unwrap();
                let hash = *blake3::hash(&canonical_bytes(&entry.transcript).unwrap()).as_bytes();
                node.volumes
                    .activate_attempt_object(
                        &node.control,
                        &plan.value.attempt_id,
                        &storage,
                        0,
                        &commitment,
                        &hash,
                    )
                    .unwrap();
                node.persist_coding_group_transcript(&entry.transcript)
                    .unwrap();
            } else {
                node.activate_coding_attempt(&entry.transcript).unwrap();
            }
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
            assert!(node.$payload(ids[0], &proof, group, shard).is_err());
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
            let payload = node.$payload(ids[0], &proof, group, shard).unwrap();
            node.$payload(ids[0], &proof, group, shard).unwrap();
            node.$payload(ids[1], &proof, group, shard).unwrap();
            assert!(node.$payload(ids[0], &proof, group, 1 - shard).is_err());
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
            if legacy {
                let remove = event(
                    &node,
                    &keys,
                    mb_core::GuildEventKind::RemoveMember {
                        node_id: keys[4].node_id(),
                    },
                );
                node.install_guild_event(remove).unwrap();
                assert_ne!(
                    node.dynamic_guild_state()
                        .unwrap()
                        .unwrap()
                        .membership_epoch,
                    plan.value.membership_epoch
                );
            }
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
                &[source_path.clone(), destination.path().to_path_buf()],
                64 << 20,
                0,
            )
            .unwrap();
            node.drain_storage_volume(source.volume_id).unwrap();
            if legacy {
                let witness = node
                    .control
                    .get_record("coding-transcript", &plan.value.attempt_id)
                    .unwrap()
                    .unwrap();
                let flat = node
                    .control
                    .get_record("guild-dynamic-state", KEY)
                    .unwrap()
                    .unwrap();
                node.control
                    .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
                    .unwrap();
                node.control
                    .delete_record("coding-transcript", &plan.value.attempt_id)
                    .unwrap();
                assert!(
                    node.migrate_draining_volumes()
                        .unwrap_err()
                        .to_string()
                        .contains("activation witness is unavailable")
                );
                node.control
                    .put_record(
                        "coding-transcript",
                        &plan.value.attempt_id,
                        &vec![0; mb_core::CATALOG_CODING_TRANSCRIPT_BYTES + 1],
                    )
                    .unwrap();
                assert!(node.migrate_draining_volumes().is_err());
                node.control
                    .put_record("coding-transcript", &plan.value.attempt_id, &witness)
                    .unwrap();
                let other = proof
                    .index()
                    .index()
                    .next_group(Some(group))
                    .unwrap()
                    .unwrap()
                    .group
                    .range
                    .group_id;
                let other = proof
                    .index()
                    .index()
                    .read_group(other, |page| {
                        node.control.catalog_page(
                            mb_core::CatalogScope::Guild { guild_id: guild },
                            mb_core::CatalogSection::Coding,
                            page,
                        )
                    })
                    .unwrap()
                    .unwrap();
                node.control
                    .put_record(
                        "coding-transcript",
                        &plan.value.attempt_id,
                        &canonical_bytes(&other.transcript).unwrap(),
                    )
                    .unwrap();
                assert!(node.migrate_draining_volumes().is_err());
                node.control
                    .put_record("coding-transcript", &plan.value.attempt_id, &witness)
                    .unwrap();
                let indexed = node
                    .control
                    .get_record("guild-original-tip-v1", KEY)
                    .unwrap()
                    .unwrap();
                node.control
                    .delete_record("guild-original-tip-v1", KEY)
                    .unwrap();
                assert!(
                    node.migrate_draining_volumes()
                        .unwrap_err()
                        .to_string()
                        .contains("complete original-history indexing")
                );
                node.control
                    .put_record("guild-original-tip-v1", KEY, &indexed)
                    .unwrap();
                let member_key = plan.value.membership_epoch.to_be_bytes();
                let members = node
                    .control
                    .get_record("guild-original-members", &member_key)
                    .unwrap()
                    .unwrap();
                let mut damaged = members.clone();
                *damaged.last_mut().unwrap() ^= 1;
                node.control
                    .put_record("guild-original-members", &member_key, &damaged)
                    .unwrap();
                assert!(node.migrate_draining_volumes().is_err());
                node.control
                    .put_record("guild-original-members", &member_key, &members)
                    .unwrap();
                assert_eq!(
                    node.volumes
                        .database_shell_statement(
                            source.volume_id,
                            "SELECT length(acknowledgement) FROM parity_objects",
                            false
                        )
                        .unwrap()
                        .rows,
                    vec![vec!["0".to_owned()]]
                );
                assert_eq!(
                    node.control
                        .get_record("volume-receipt", &locator_key)
                        .unwrap(),
                    Some(locator.clone())
                );
                crate::volume::interrupt_next_volume_transition(
                    crate::volume::VolumeInterruption::VariableInformationEvidenceStored,
                );
                let injected = node.migrate_draining_volumes().unwrap_err();
                assert!(
                    injected
                        .to_string()
                        .contains("VariableInformationEvidenceStored"),
                    "{injected:#}"
                );
                assert_eq!(
                    node.volumes
                        .database_shell_statement(
                            source.volume_id,
                            "SELECT lower(hex(acknowledgement)) FROM parity_objects",
                            false
                        )
                        .unwrap()
                        .rows,
                    vec![vec![hex::encode(payload.transcript_hash)]]
                );
                node.control
                    .put_record("guild-dynamic-state", KEY, &flat)
                    .unwrap();
                node.control
                    .delete_record("coding-transcript", &plan.value.attempt_id)
                    .unwrap();
                drop(node);
                node = Node::open(temp.path(), seed.clone()).unwrap();
            } else if !information {
                // Empty parity evidence is damage, even with the exact valid witness.
                let original = node
                    .volumes
                    .database_shell_statement(
                        source.volume_id,
                        "SELECT hex(acknowledgement) FROM parity_objects",
                        false,
                    )
                    .unwrap()
                    .rows[0][0]
                    .clone();
                node.volumes
                    .database_shell_statement(
                        source.volume_id,
                        "UPDATE parity_objects SET acknowledgement=X''",
                        false,
                    )
                    .unwrap();
                assert!(
                    node.migrate_draining_volumes()
                        .unwrap_err()
                        .to_string()
                        .contains("not an information upload")
                );
                node.volumes
                    .database_shell_statement(
                        source.volume_id,
                        &format!("UPDATE parity_objects SET acknowledgement=X'{original}'"),
                        false,
                    )
                    .unwrap();
            }
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
            if legacy {
                assert!(source_path.starts_with(temp.path()));
                assert_ne!(source_path, temp.path());
                std::fs::remove_dir_all(&source_path).unwrap();
            }
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
            node.control.$cancel(ids[0]).unwrap();
            assert!(node.control.$release(ids[0]).unwrap());
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
            while node.control.$release(ids[0]).unwrap() {}
            node.control.$cancel(ids[1]).unwrap();
            assert!(node.control.$release(ids[1]).unwrap());
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
            while node.control.$release(ids[1]).unwrap() {}
        }
    };
}
payload_custody_cases!(
    exercise_checkpoint_payload_custody,
    checkpoint_owner_proof_at,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_payload,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
payload_custody_cases!(
    exercise_directory_checkpoint_payload_custody,
    directory_owner_proof_at,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_payload,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);

#[test]
fn paged_checkpoint_directory_information_custody_survives_real_forget_rollback_and_reopen() {
    exercise_directory_checkpoint_payload_custody(true, false);
}

#[test]
fn paged_checkpoint_directory_parity_custody_survives_real_forget_rollback_and_reopen() {
    exercise_directory_checkpoint_payload_custody(false, false);
}

#[test]
fn paged_checkpoint_information_custody_survives_real_forget_rollback_and_reopen() {
    exercise_checkpoint_payload_custody(true, false);
}

#[test]
fn paged_checkpoint_parity_custody_survives_real_forget_rollback_and_reopen() {
    exercise_checkpoint_payload_custody(false, false);
}

#[test]
fn legacy_information_activation_upgrade_authenticates_history_and_evacuates_shared_custody() {
    exercise_checkpoint_payload_custody(true, true);
}

#[test]
fn paged_checkpoint_metadata_node_owner_uses_original_index_and_survives_capture_retirement() {
    exercise_checkpoint_metadata_owner(false);
}

#[test]
fn paged_checkpoint_budgeted_metadata_node_owner_preserves_original_authority_through_reopen() {
    exercise_checkpoint_metadata_owner(true);
}

#[test]
fn capacity_policy_checkpoint_custody_uses_the_same_enclosing_contract_and_reopens() {
    use mb_core::{CatalogCapacityPolicy, CodingProfile, PackingProfile};
    for (directory, configure_before, replay_allowed) in [
        (false, true, true),
        (true, true, true),
        (false, false, true),
        (true, false, true),
        (false, true, false),
        (true, true, false),
    ] {
        let (temp, seed, mut node, keys) = fixture();
        let quota = mb_store::CatalogPublishedRevisionQuota {
            revisions: 100,
            work: Work {
                bytes: 1 << 30,
                page_occurrences: 1_000_000,
                records: 10_000_000,
            },
        };
        node.configure_published_revision_quotas(mb_store::CatalogPublishedRevisionQuotas {
            global: quota,
            dataset: quota,
            guild: quota,
        })
        .unwrap();
        let data = mb_store::CatalogRetainedSourceQuota {
            logical_bytes: 1 << 30,
            sources: 1_000_000,
            open_reservations: 100,
        };
        node.control
            .configure_catalog_retained_source_quota(data)
            .unwrap();
        node.control
            .configure_catalog_retained_source_guild_quota(data)
            .unwrap();
        let policy = CatalogCapacityPolicy {
            format_version: 1,
            datasets: 1,
            revisions_per_dataset: 1,
            legacy_revisions: 1,
            legacy_source_occurrences: 1,
            data_bytes_per_dataset: 1,
            data_sources_per_dataset: 1,
            private_work_per_revision: Work {
                bytes: 16,
                page_occurrences: 2,
                records: 0,
            },
            source_pages_per_revision: 1,
            authority_control_records: 257,
            packing_profile: PackingProfile {
                format_version: 1,
                sector_size: 65536,
                slot_size: 16384,
            },
            coding_profile: CodingProfile::new(3, 2, 65536),
            packed_sectors: 7,
            coding_groups: 3,
            replay_work: if replay_allowed {
                Work {
                    bytes: 64 << 20,
                    page_occurrences: 65536,
                    records: 65536,
                }
            } else {
                Work::default()
            },
        };
        if configure_before {
            node.configure_catalog_capacity_policy(policy).unwrap();
        }
        let id = Uuid::new_v4();
        let (hash, bytes, guild) = if directory {
            let (proof, _) = directory_owner_proof(&mut node, &keys, false);
            if !configure_before {
                node.configure_catalog_capacity_policy(policy).unwrap();
                assert!(
                    node.retain_paged_checkpoint_directory_metadata(id, &proof)
                        .is_err()
                );
                assert!(
                    node.control
                        .catalog_paged_checkpoint_directory_retention(id)
                        .unwrap()
                        .is_none()
                );
                continue;
            }
            assert_eq!(proof.transition().budget(), policy.plan().unwrap().job_work);
            if !replay_allowed {
                assert!(proof.transition().represented_work().bytes > 0);
                assert!(
                    node.retain_paged_checkpoint_directory_metadata(id, &proof)
                        .is_err()
                );
                assert!(
                    node.control
                        .catalog_paged_checkpoint_directory_retention(id)
                        .unwrap()
                        .is_none()
                );
                continue;
            }
            let owned = node
                .retain_paged_checkpoint_directory_metadata(id, &proof)
                .unwrap();
            let certificate = node
                .control
                .catalog_paged_checkpoint_directory_certificate(id)
                .unwrap()
                .unwrap();
            (
                owned.checkpoint.hash().unwrap(),
                canonical_bytes(&certificate).unwrap(),
                proof.trust().guild_id,
            )
        } else {
            let (proof, _) = checkpoint_owner_proof_at_with_budgeted_authority(
                &mut node,
                &keys,
                false,
                unix_seconds() + 600,
                true,
            );
            if !configure_before {
                node.configure_catalog_capacity_policy(policy).unwrap();
                assert!(node.retain_paged_checkpoint_metadata(id, &proof).is_err());
                assert!(
                    node.control
                        .catalog_paged_checkpoint_retention(id)
                        .unwrap()
                        .is_none()
                );
                continue;
            }
            assert_eq!(proof.transition().budget(), policy.plan().unwrap().job_work);
            if !replay_allowed {
                assert!(proof.transition().represented_work().bytes > 0);
                assert!(node.retain_paged_checkpoint_metadata(id, &proof).is_err());
                assert!(
                    node.control
                        .catalog_paged_checkpoint_retention(id)
                        .unwrap()
                        .is_none()
                );
                continue;
            }
            let owned = node.retain_paged_checkpoint_metadata(id, &proof).unwrap();
            let certificate = node
                .control
                .catalog_paged_checkpoint_certificate(id)
                .unwrap()
                .unwrap();
            (
                owned.checkpoint.hash().unwrap(),
                canonical_bytes(&certificate).unwrap(),
                proof.trust().guild_id,
            )
        };
        assert!(
            node.control
                .checkpoint_head_identity(&guild)
                .unwrap()
                .is_none()
        );
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        let layout = if directory {
            mb_core::PagedCheckpointLayout::Directory
        } else {
            mb_core::PagedCheckpointLayout::Individual
        };
        assert_eq!(
            node.retained_paged_checkpoint_certificate(guild, layout, id, hash)
                .unwrap(),
            bytes
        );
        assert_eq!(
            node.control.catalog_capacity_policy().unwrap(),
            Some(policy)
        );
        assert!(
            node.control
                .checkpoint_head_identity(&guild)
                .unwrap()
                .is_none()
        );
    }
}

fn exercise_checkpoint_metadata_owner(budgeted: bool) {
    let (temp, seed, mut node, keys) = fixture();
    let (proof, intents) = checkpoint_owner_proof_at_with_budgeted_authority(
        &mut node,
        &keys,
        false,
        unix_seconds() + 600,
        budgeted,
    );
    assert_eq!(
        proof.certificate().checkpoint.format_version,
        if budgeted { 9 } else { 8 }
    );
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
