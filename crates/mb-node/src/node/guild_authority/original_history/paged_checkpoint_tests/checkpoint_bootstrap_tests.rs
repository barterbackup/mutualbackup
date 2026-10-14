use super::checkpoint_restore_tests::{git_directory_proof, git_owner_proof, verify_git_restore};
use super::*;
use crate::RetainedSnapshotRestore;

type Root = (
    mb_core::CatalogScope,
    mb_core::CatalogSection,
    mb_core::CatalogPageRef,
);
fn individual_packing_roots(
    _: &Node,
    header: &mb_core::PagedGuildCheckpoint,
    _: Work,
) -> Vec<Root> {
    let scope = mb_core::CatalogScope::Guild {
        guild_id: header.guild_id,
    };
    vec![
        (
            scope,
            mb_core::CatalogSection::Packing,
            header.packed_sources.records.page,
        ),
        (
            scope,
            mb_core::CatalogSection::Packing,
            header.packed_sectors.records.page,
        ),
    ]
}
fn directory_packing_roots(
    node: &Node,
    header: &mb_core::PagedGuildCheckpointDirectory,
    work: Work,
) -> Vec<Root> {
    let scope = mb_core::CatalogScope::Guild {
        guild_id: header.guild_id,
    };
    let mut roots = vec![(
        scope,
        mb_core::CatalogSection::Packing,
        header.packing.records.page,
    )];
    let mut reader =
        mb_core::CatalogPackingDirectoryReader::new(scope, header.packing, work).unwrap();
    let mut fetch = |page| {
        node.control
            .catalog_page(scope, mb_core::CatalogSection::Packing, page)
    };
    let mut parts = |part| {
        roots.push((
            scope,
            mb_core::CatalogSection::Packing,
            match part {
                mb_core::CatalogPackingDirectoryRecord::Sources(part) => part.root.records.page,
                mb_core::CatalogPackingDirectoryRecord::Sectors(part) => part.root.records.page,
            },
        ));
        Ok::<_, mb_store::CatalogStoreError>(())
    };
    let mut sources = std::collections::BTreeMap::new();
    while let Some(record) = reader
        .next_source_with_part(&mut fetch, &mut parts)
        .unwrap()
    {
        if let mb_core::CatalogPackedSourceRecord::Source { id, .. } = record {
            sources.insert(id.key(), id);
        }
    }
    while reader
        .next_sector_with_part(
            &mut fetch,
            &mut |key| {
                sources
                    .get(&key)
                    .copied()
                    .ok_or(mb_store::DatabaseError::Integrity.into())
            },
            &mut parts,
        )
        .unwrap()
        .is_some()
    {}
    roots
}

fn copy_public_tree(
    source: &Node,
    destination: &Node,
    intent: mb_store::CatalogIntent,
    page: mb_core::CatalogPageRef,
) {
    let bytes = source
        .control
        .catalog_page(intent.scope, intent.section, page)
        .unwrap();
    if let mb_core::CatalogPageContents::Index(children) = page
        .verify_page(intent.scope, intent.section, &bytes)
        .unwrap()
    {
        for child in children {
            copy_public_tree(source, destination, intent, child);
        }
    }
    destination
        .control
        .stage_catalog_page(intent, page, &bytes)
        .unwrap();
}

fn fresh_public_node(temp: &Path, seed: Seed, source: &Node) -> Node {
    let (_, certificate, peers) = crate::node::tests::recovery_guild_fixture();
    let mut node = Node::open(temp, seed).unwrap();
    node.adopt_recovered_guild(certificate, peers).unwrap();
    for (_, bytes) in source.control.records("guild-event").unwrap() {
        let event: QuorumGuildEvent = decode_canonical(&bytes).unwrap();
        if let mb_core::GuildEventKind::AddCodingGroupBound { .. } = &event.event.kind {
            let bytes = source
                .control
                .get_record("coding-event-transcript", &event.event.hash().unwrap())
                .unwrap()
                .unwrap();
            node.install_coding_group_event(event, decode_canonical(&bytes).unwrap())
                .unwrap();
        } else {
            node.install_guild_event(event).unwrap();
        }
    }
    node
}

macro_rules! cases {
    ($test:ident,$constructor:ident,$layout:ident,$metadata:ident,$lookup:ident,$chunks:ident,$source_index:ident,$payload:ident,$cancel:ident,$release:ident,$parts:ident) => {
        #[test]
        fn $test() {
            let (temp, seed, mut original, mut keys) = fixture();
            let local = keys
                .iter()
                .position(|key| key.node_id() == original.keys.node_id())
                .unwrap();
            keys.swap(0, local);
            let (proof, _) = $constructor(&mut original, &keys, true);
            let first = proof.index().next_revision(None).unwrap().unwrap();
            let record = proof
                .index()
                .next_revision(first.revision_key())
                .unwrap()
                .unwrap();
            let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = record else {
                panic!("paged revision")
            };
            let key = mb_core::CatalogCheckpointRevisionKey::from(&signed.value);
            let server_owner = Uuid::from_u128(760);
            original.$metadata(server_owner, &proof).unwrap();
            original.$lookup(server_owner, &proof).unwrap();
            let mut after = None;
            while let Some(row) = proof.index().index().next_group(after).unwrap() {
                let group = row.group.range.group_id;
                original.$payload(server_owner, &proof, group, 1).unwrap();
                after = Some(group);
            }
            let fresh = temp.path().join("seed-recovery");
            let node = fresh_public_node(&fresh, seed.clone(), &original);
            // Transfer only public retained pages. No bootstrap, private page,
            // native validation, readable source anchor or READY volume is copied.
            let scope = mb_core::CatalogScope::Guild {
                guild_id: proof.trust().guild_id,
            };
            let header = proof.certificate().checkpoint;
            let mut public = vec![
                (
                    scope,
                    mb_core::CatalogSection::Checkpoint,
                    header.authority_root.records.page,
                ),
                (
                    scope,
                    mb_core::CatalogSection::Coding,
                    header.coding.records.page,
                ),
                (
                    signed.value.scope(),
                    mb_core::CatalogSection::SectorReferences,
                    signed.value.sources.records.page,
                ),
            ];
            public.extend($parts(&original, &header, proof.transition().budget()));
            let mut coding = mb_core::CatalogCodingDirectoryReader::new(
                scope,
                header.coding,
                proof.transition().budget(),
            )
            .unwrap();
            while coding
                .next_group_with_forest(
                    &mut |page| {
                        original
                            .control
                            .catalog_page(scope, mb_core::CatalogSection::Coding, page)
                    },
                    &mut |forest: &mb_core::CatalogCodingRoot| {
                        public.extend(
                            forest
                                .parts
                                .iter()
                                .map(|part| (scope, mb_core::CatalogSection::Coding, part.page)),
                        );
                        Ok::<_, mb_store::CatalogStoreError>(())
                    },
                )
                .unwrap()
                .is_some()
            {}
            let legacy = first;
            if let mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(reference) = legacy {
                public.push((scope, mb_core::CatalogSection::Checkpoint, reference.body));
            }
            for (index, (scope, section, page)) in public.into_iter().enumerate() {
                let intent = mb_store::CatalogIntent {
                    id: Uuid::from_u128(800 + index as u128),
                    scope,
                    section,
                };
                node.control.begin_catalog(intent).unwrap();
                copy_public_tree(&original, &node, intent, page);
            }
            let owner = Uuid::from_u128(761);
            node.$metadata(owner, &proof).expect("fresh public retention");
            node.$lookup(owner, &proof).expect("fresh revision/group lookup");
            node.$chunks(owner, &proof).expect("fresh packing chunk lookup");
            node.$source_index(owner, &proof, key.revision_id).expect("fresh signed source lookup");
            node.control.configure_catalog_storage_quota(mb_store::CatalogStorageQuota {
                page_bytes: 64 * 1024 * 1024,
                pages: 1024,
                open_reservations: 16,
            }).unwrap();
            assert!(
                node.control
                    .paged_revision_catalog(key.revision_id)
                    .unwrap()
                    .is_none()
            );
            assert!(
                node.control
                    .records("paged-revision-bootstrap-v1")
                    .unwrap()
                    .is_empty()
            );
            assert!(
                node.control
                    .records("catalog-native-validation-v1")
                    .unwrap()
                    .is_empty()
            );
            let mut request = RetainedSnapshotRestore {
                layout: mb_core::PagedCheckpointLayout::$layout,
                owner,
                guild_id: proof.trust().guild_id,
                snapshot: SnapshotInfo {
                    protected_root_id: key.protected_root_id,
                    revision_id: key.revision_id,
                    sequence: key.sequence,
                    checkpoint_generation: proof.certificate().checkpoint.generation,
                    checkpoint_hash: proof.certificate().hash().unwrap(),
                },
                budget: proof.transition().budget(),
            };
            let session = node.retained_checkpoint_restore().unwrap();
            let target = fresh.join("restored-from-public-evidence");
            let reader = original.reader_config().open().unwrap();
            let mut fetch = |entry: &mb_core::CatalogCodingEntry, index| {
                if index != 1 { return Ok(None); }
                Ok(Some(reader.retained_checkpoint_shard(
                    request.guild_id, request.layout, server_owner,
                    request.snapshot.checkpoint_hash, entry.retained.group.id, index,
                )?))
            };
            let corrupt = fresh.join("corrupt-bootstrap");
            assert!(session.restore(&request, &corrupt, |entry, index| {
                let mut bytes = fetch(entry, index)?;
                if let Some(bytes) = &mut bytes { bytes[0] ^= 1; }
                Ok(bytes)
            }).is_err());
            assert!(!corrupt.exists());
            let cancelled_owner = Uuid::from_u128(762);
            node.$metadata(cancelled_owner, &proof).unwrap();
            node.$lookup(cancelled_owner, &proof).unwrap();
            node.$chunks(cancelled_owner, &proof).unwrap();
            node.$source_index(cancelled_owner, &proof, key.revision_id).unwrap();
            let mut cancelled_request = request.clone();
            cancelled_request.owner = cancelled_owner;
            let cancelled_target = fresh.join("cancelled-during-bootstrap");
            let mut cancelled = false;
            assert!(session.restore(&cancelled_request, &cancelled_target, |entry, index| {
                let bytes = fetch(entry, index)?;
                if bytes.is_some() && !cancelled {
                    node.control.$cancel(cancelled_owner).unwrap();
                    cancelled = true;
                }
                Ok(bytes)
            }).is_err());
            assert!(cancelled);
            assert!(!cancelled_target.exists());
            while node.control.$release(cancelled_owner).unwrap() {}
            // Retained ownership is part of private publication's writer.
            // Both a throwing trigger and a silently ignored write must leave
            // the bootstrap and private bundle unpublished and allow replay.
            for action in ["ABORT", "IGNORE"] {
                node.control.database_shell_statement(&format!(
                    "CREATE TRIGGER refuse_private_recovery BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-checkpoint-private-revision-v1/{}' BEGIN SELECT RAISE({action}{}); END",
                    owner.simple(), if action == "ABORT" { ",'test'" } else { "" }
                ), false).unwrap();
                let failed = fresh.join(format!("private-publication-{action}"));
                assert!(session.restore(&request, &failed, &mut fetch).is_err());
                assert!(!failed.exists());
                assert!(node.control.paged_revision_catalog(key.revision_id).unwrap().is_none());
                assert!(node.control.native_file_catalog_validation(key.revision_id).unwrap().is_some());
                node.control.database_shell_statement("DROP TRIGGER refuse_private_recovery", false).unwrap();
            }
            let shared_owner = Uuid::from_u128(763);
            node.$metadata(shared_owner, &proof).unwrap();
            node.$lookup(shared_owner, &proof).unwrap();
            node.$chunks(shared_owner, &proof).unwrap();
            node.$source_index(shared_owner, &proof, key.revision_id).unwrap();
            let mut shared_request = request.clone();
            shared_request.owner = shared_owner;
            assert!(session.restore(&shared_request, &fresh.join("pending-shared-bootstrap"), |_, _| Ok(None)).is_err());
            node.control.$cancel(owner).unwrap();
            while node.control.$release(owner).unwrap() {}
            request.owner = shared_owner;
            session
                .restore(&request, &target, |entry, index| {
                    if index != 1 {
                        return Ok(None);
                    }
                    Ok(Some(reader.retained_checkpoint_shard(
                        request.guild_id,
                        request.layout,
                        server_owner,
                        request.snapshot.checkpoint_hash,
                        entry.retained.group.id,
                        index,
                    )?))
                })
                .expect("full restore after shared-owner cancellation");
            verify_git_restore(&node, &target, key.protected_root_id);
            assert!(
                node.control
                    .paged_revision_catalog(key.revision_id)
                    .unwrap()
                    .is_some()
            );
            assert!(
                node.control
                    .checkpoint_head_identity(&request.guild_id)
                    .unwrap()
                    .is_none()
            );
            drop(session);
            drop(node);
            let node = Node::open(&fresh, seed).unwrap();
            let retry = fresh.join("reopened-recovered-private");
            node.retained_checkpoint_restore()
                .unwrap()
                .restore(&request, &retry, |entry, index| {
                    if index != 1 {
                        return Ok(None);
                    }
                    Ok(Some(reader.retained_checkpoint_shard(
                        request.guild_id,
                        request.layout,
                        server_owner,
                        request.snapshot.checkpoint_hash,
                        entry.retained.group.id,
                        index,
                    )?))
                })
                .unwrap();
            verify_git_restore(&node, &retry, key.protected_root_id);
            node.control.$cancel(request.owner).unwrap();
            while node.control.$release(request.owner).unwrap() {}
            assert!(
                node.control
                    .paged_revision_catalog(key.revision_id)
                    .unwrap()
                    .is_some()
            );
            verify_git_restore(&node, &target, key.protected_root_id);
        }
    };
}

cases!(
    individual_private_bootstrap_and_pages_recover_from_public_roots_and_original_ready_parity,
    git_owner_proof,
    Individual,
    retain_paged_checkpoint_metadata,
    build_retained_paged_checkpoint_lookup,
    build_retained_paged_checkpoint_chunk_index,
    build_retained_paged_checkpoint_source_lookup,
    retain_paged_checkpoint_local_payload,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root,
    individual_packing_roots
);
cases!(
    directory_private_bootstrap_and_pages_recover_from_public_roots_and_original_ready_parity,
    git_directory_proof,
    Directory,
    retain_paged_checkpoint_directory_metadata,
    build_retained_paged_checkpoint_directory_lookup,
    build_retained_paged_checkpoint_directory_chunk_index,
    build_retained_paged_checkpoint_directory_source_lookup,
    retain_paged_checkpoint_directory_local_payload,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root,
    directory_packing_roots
);
