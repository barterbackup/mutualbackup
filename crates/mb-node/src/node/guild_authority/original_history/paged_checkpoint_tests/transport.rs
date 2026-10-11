use super::*;
use crate::network::{P2pConfig, TorMode, build_p2p};
use mb_core::{
    CatalogPagePath, CatalogReader, CatalogScope, CatalogSection, PagedCheckpointLayout,
};
use std::sync::{Arc, Mutex};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_paged_checkpoint_individual_transport_streams_original_roots_over_quic() {
    exercise(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retained_paged_checkpoint_directory_transport_streams_original_roots_over_quic() {
    exercise(true).await;
}

async fn exercise(directory: bool) {
    let (temp, seed, mut node, mut keys) = fixture();
    let owner = keys
        .iter()
        .position(|key| key.node_id() == node.keys.node_id())
        .unwrap();
    keys.swap(0, owner);
    let id = Uuid::from_u128(100);
    let (layout, certificate, trust, budget, roots, intents) = if directory {
        let (proof, intents) = directory_owner_proof_at_with_rooted_sources(
            &mut node,
            &keys,
            true,
            unix_seconds() + 600,
            true,
        );
        node.retain_paged_checkpoint_directory_metadata(id, &proof)
            .unwrap();
        let h = proof.certificate().checkpoint;
        let scope = CatalogScope::Guild {
            guild_id: h.guild_id,
        };
        let work = proof.transition().budget();
        let mut roots = vec![
            (
                scope,
                CatalogSection::Checkpoint,
                h.authority_root.records.page,
            ),
            (scope, CatalogSection::Packing, h.packing.records.page),
            (scope, CatalogSection::Coding, h.coding.records.page),
        ];
        revision_roots(&mut roots, scope, |after| {
            proof.index().next_revision(after)
        });
        coding_roots(&node, &mut roots, scope, h.coding, work);
        let mut packing =
            mb_core::CatalogPackingDirectoryReader::new(scope, h.packing, work).unwrap();
        let mut part = |part| {
            roots.push((
                scope,
                CatalogSection::Packing,
                match part {
                    mb_core::CatalogPackingDirectoryRecord::Sources(part) => part.root.records.page,
                    mb_core::CatalogPackingDirectoryRecord::Sectors(part) => part.root.records.page,
                },
            ));
            Ok::<_, mb_store::CatalogStoreError>(())
        };
        let mut fetch = |page| {
            node.control
                .catalog_page(scope, CatalogSection::Packing, page)
        };
        let mut source_ids = BTreeMap::new();
        while let Some(record) = packing
            .next_source_with_part(&mut fetch, &mut part)
            .unwrap()
        {
            if let mb_core::CatalogPackedSourceRecord::Source { id, .. } = record {
                source_ids.insert(id.key(), id);
            }
        }
        while packing
            .next_sector_with_part(
                &mut fetch,
                &mut |key| {
                    source_ids.get(&key).copied().ok_or_else(|| {
                        mb_store::CatalogStoreError::from(mb_store::DatabaseError::NotReady)
                    })
                },
                &mut part,
            )
            .unwrap()
            .is_some()
        {}
        (
            PagedCheckpointLayout::Directory,
            canonical_bytes(proof.certificate()).unwrap(),
            proof.trust().clone(),
            proof.transition().budget(),
            roots,
            intents,
        )
    } else {
        let (proof, intents) = checkpoint_owner_proof_at_with_rooted_sources(
            &mut node,
            &keys,
            true,
            unix_seconds() + 600,
            true,
            true,
        );
        node.retain_paged_checkpoint_metadata(id, &proof).unwrap();
        let h = proof.certificate().checkpoint;
        let scope = CatalogScope::Guild {
            guild_id: h.guild_id,
        };
        let mut roots = vec![
            (
                scope,
                CatalogSection::Checkpoint,
                h.authority_root.records.page,
            ),
            (
                scope,
                CatalogSection::Packing,
                h.packed_sources.records.page,
            ),
            (
                scope,
                CatalogSection::Packing,
                h.packed_sectors.records.page,
            ),
            (scope, CatalogSection::Coding, h.coding.records.page),
        ];
        revision_roots(&mut roots, scope, |after| {
            proof.index().next_revision(after)
        });
        coding_roots(
            &node,
            &mut roots,
            scope,
            h.coding,
            proof.transition().budget(),
        );
        (
            PagedCheckpointLayout::Individual,
            canonical_bytes(proof.certificate()).unwrap(),
            proof.trust().clone(),
            proof.transition().budget(),
            roots,
            intents,
        )
    };
    let hash = if directory {
        decode_canonical::<mb_core::QuorumPagedCheckpointDirectory>(&certificate)
            .unwrap()
            .hash()
            .unwrap()
    } else {
        decode_canonical::<mb_core::QuorumPagedCheckpoint>(&certificate)
            .unwrap()
            .hash()
            .unwrap()
    };
    let scope = CatalogScope::Guild {
        guild_id: trust.guild_id,
    };
    for intent in intents {
        node.control.cancel_catalog(intent).unwrap();
        while node.control.release_catalog_pin(intent).unwrap() {}
    }
    while node.control.collect_catalog_page().unwrap() {}
    let caller_seed = (120..125)
        .map(|n| Seed::from_bytes([n; 32]))
        .find(|seed| KeyMaterial::from_seed(seed).node_id() == keys[1].node_id())
        .unwrap();
    let removed = event(
        &node,
        &keys,
        mb_core::GuildEventKind::RemoveMember {
            node_id: keys[1].node_id(),
        },
    );
    node.install_guild_event(removed).unwrap();
    assert!(
        node.authorize_member(&trust.guild_id, keys[1].node_id())
            .is_err()
    );
    drop(node);
    let node = Node::open(temp.path(), seed).unwrap();
    let reader = node.reader_config().open().unwrap();
    assert!(reader.control.is_read_only().unwrap());
    let root_path = CatalogPagePath {
        scope,
        section: roots[0].1,
        pages: vec![roots[0].2],
    };
    assert!(
        reader
            .retained_paged_checkpoint_public_page([231; 32], layout, id, hash, &root_path)
            .is_err()
    );
    let private_path = CatalogPagePath {
        scope: CatalogScope::Dataset {
            guild_id: trust.guild_id,
            owner: keys[0].node_id(),
            protected_root_id: Uuid::from_u128(99),
        },
        section: CatalogSection::FileMetadata,
        pages: root_path.pages.clone(),
    };
    assert!(
        reader
            .retained_paged_checkpoint_public_page(trust.guild_id, layout, id, hash, &private_path)
            .is_err()
    );
    let mut expected = Vec::new();
    let mut forged_path = None;
    for &(scope, section, root) in &roots {
        let mut stream = CatalogReader::new(scope, section, root).unwrap();
        let mut digest = blake3::Hasher::new();
        while let Some(leaf) = stream
            .next_leaf_with_path(&mut |pages| {
                if pages.len() > 1 && forged_path.is_none() {
                    let mut path = CatalogPagePath {
                        scope,
                        section,
                        pages: pages.to_vec(),
                    };
                    path.pages.last_mut().unwrap().hash = [239; 32];
                    forged_path = Some(path);
                }
                node.control
                    .catalog_page(scope, section, *pages.last().unwrap())
            })
            .unwrap()
        {
            digest.update(&leaf);
        }
        expected.push(*digest.finalize().as_bytes());
    }
    drop(reader);
    let target_id = node.keys.node_id();
    let owner = Arc::new(Mutex::new(node));
    let caller = Node::open(temp.path().join("reader-peer"), caller_seed).unwrap();
    let caller_id = caller.keys.node_id();
    let outsider = Node::open(temp.path().join("outsider"), Seed::from_bytes([230; 32])).unwrap();
    let outsider_id = outsider.keys.node_id();
    let (server, server_loop) = build_p2p(owner.clone(), config(target_id)).unwrap();
    let (client, client_loop) = build_p2p(Arc::new(Mutex::new(caller)), config(caller_id)).unwrap();
    let (untrusted, untrusted_loop) =
        build_p2p(Arc::new(Mutex::new(outsider)), config(outsider_id)).unwrap();
    let server_task = tokio::spawn(server_loop.run());
    let client_task = tokio::spawn(client_loop.run());
    let untrusted_task = tokio::spawn(untrusted_loop.run());
    let address: libp2p::Multiaddr =
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let status = server.status().await.unwrap();
                if let Some(address) = status.listen_addresses.first()
                    && !address.contains("/udp/0/")
                {
                    break address.parse().unwrap();
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    client
        .add_peer_address(target_id, address.clone())
        .await
        .unwrap();
    untrusted
        .add_peer_address(target_id, address)
        .await
        .unwrap();
    let fetch_certificate = |client: crate::network::P2pClient,
                             trust: mb_core::PagedCheckpointTrust| async move {
        if directory {
            canonical_bytes(
                &client
                    .retained_paged_checkpoint_directory_certificate(
                        target_id, id, hash, &trust, budget,
                    )
                    .await?,
            )
        } else {
            canonical_bytes(
                &client
                    .retained_paged_checkpoint_certificate(target_id, id, hash, &trust, budget)
                    .await?,
            )
        }
        .map_err(anyhow::Error::from)
    };
    assert_eq!(
        fetch_certificate(client.clone(), trust.clone())
            .await
            .unwrap(),
        certificate
    );
    assert!(
        fetch_certificate(untrusted.clone(), trust.clone())
            .await
            .is_err()
    );
    let mut bad_trust = trust.clone();
    bad_trust.event_head = [239; 32];
    assert!(fetch_certificate(client.clone(), bad_trust).await.is_err());
    assert!(
        client
            .retained_paged_checkpoint_public_page(
                target_id,
                layout,
                id,
                hash,
                forged_path.unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        untrusted
            .retained_paged_checkpoint_public_page(target_id, layout, id, hash, root_path.clone())
            .await
            .is_err()
    );
    let handle = tokio::runtime::Handle::current();
    let streaming_client = client.clone();
    tokio::task::spawn_blocking(move || {
        let mut descendant_requests = 0;
        for ((scope, section, root), expected) in roots.into_iter().zip(expected) {
            let mut stream = CatalogReader::new(scope, section, root).unwrap();
            let mut digest = blake3::Hasher::new();
            let mut bytes = 0;
            while let Some(leaf) = stream
                .next_leaf_with_path(&mut |pages| {
                    descendant_requests += usize::from(pages.len() > 1);
                    handle.block_on(streaming_client.retained_paged_checkpoint_public_page(
                        target_id,
                        layout,
                        id,
                        hash,
                        CatalogPagePath {
                            scope,
                            section,
                            pages: pages.to_vec(),
                        },
                    ))
                })
                .unwrap()
            {
                bytes += leaf.len() as u64;
                digest.update(&leaf);
            }
            assert_eq!(bytes, root.byte_len);
            assert_eq!(*digest.finalize().as_bytes(), expected);
        }
        assert!(
            descendant_requests > 0,
            "fixture must exercise authenticated child paths over QUIC"
        );
    })
    .await
    .unwrap();
    let corrupt_root = root_path.pages[0];
    let original = owner
        .lock()
        .unwrap()
        .control
        .get_record("catalog-page-v1", &corrupt_root.hash)
        .unwrap()
        .unwrap();
    let mut corrupt = original.clone();
    *corrupt.last_mut().unwrap() ^= 1;
    owner
        .lock()
        .unwrap()
        .control
        .put_record("catalog-page-v1", &corrupt_root.hash, &corrupt)
        .unwrap();
    assert!(
        client
            .retained_paged_checkpoint_public_page(target_id, layout, id, hash, root_path.clone())
            .await
            .is_err()
    );
    owner
        .lock()
        .unwrap()
        .control
        .put_record("catalog-page-v1", &corrupt_root.hash, &original)
        .unwrap();
    client
        .retained_paged_checkpoint_public_page(target_id, layout, id, hash, root_path.clone())
        .await
        .unwrap();
    {
        let node = owner.lock().unwrap();
        assert!(
            node.control
                .checkpoint_head_identity(&trust.guild_id)
                .unwrap()
                .is_none()
        );
        match layout {
            PagedCheckpointLayout::Individual => node
                .control
                .cancel_catalog_paged_checkpoint_retention(id)
                .unwrap(),
            PagedCheckpointLayout::Directory => node
                .control
                .cancel_catalog_paged_checkpoint_directory_retention(id)
                .unwrap(),
        }
    }
    assert!(fetch_certificate(client.clone(), trust).await.is_err());
    assert!(
        client
            .retained_paged_checkpoint_public_page(target_id, layout, id, hash, root_path)
            .await
            .is_err()
    );
    client.shutdown().await.unwrap();
    untrusted.shutdown().await.unwrap();
    server.shutdown().await.unwrap();
    client_task.await.unwrap().unwrap();
    untrusted_task.await.unwrap().unwrap();
    server_task.await.unwrap().unwrap();
}

fn config(node_id: NodeId) -> P2pConfig {
    P2pConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
        external_addresses: Vec::new(),
        bootstrap_addresses: Vec::new(),
        relay_reservation_addresses: Vec::new(),
        enable_dht_maintenance: false,
        enable_relay_server: false,
        enable_hole_punching: false,
        enable_port_mapping: false,
        public_endpoint: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
        failure_domain: node_id.to_string(),
        configure_failure_domain: false,
        max_connections: 8,
        tor_mode: TorMode::DisableTor,
    }
}

type Root = (CatalogScope, CatalogSection, mb_core::CatalogPageRef);

/// Keep the exact source records, with a valid unary index chain reaching the
/// maximum supported path depth. Verify the canonical wire fixture through the
/// production decoder before staging and signing its enclosing revision.
pub(super) fn wrap_sources(
    node: &Node,
    intent: mb_store::CatalogIntent,
    mut sources: mb_core::CatalogSectorRoot,
) -> mb_core::CatalogSectorRoot {
    struct Index(mb_core::CatalogPageRef);
    impl serde::Serialize for Index {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let children = Vec::from([self.0]);
            serializer.serialize_newtype_variant("PageBody", 1, "Index", &children)
        }
    }
    for height in sources.records.page.height + 1..=mb_core::CATALOG_MAX_HEIGHT {
        let child = sources.records.page;
        let bytes =
            canonical_bytes(&(1_u16, intent.scope, intent.section, height, Index(child))).unwrap();
        let mut hash = blake3::Hasher::new_derive_key("mutualbackup catalog page v1");
        hash.update(&bytes);
        let parent = mb_core::CatalogPageRef {
            hash: *hash.finalize().as_bytes(),
            encoded_len: bytes.len() as u32,
            height,
            page_occurrences: child.page_occurrences + 1,
            ..child
        };
        assert_eq!(
            parent
                .verify_page(intent.scope, intent.section, &bytes)
                .unwrap(),
            mb_core::CatalogPageContents::Index(vec![child])
        );
        node.control
            .stage_catalog_page(intent, parent, &bytes)
            .unwrap();
        sources.records.page = parent;
    }
    sources
}

fn revision_roots(
    roots: &mut Vec<Root>,
    scope: CatalogScope,
    mut next: impl FnMut(
        Option<mb_core::CatalogCheckpointRevisionKey>,
    ) -> Result<
        Option<mb_core::CatalogCheckpointAuthorityRecord>,
        mb_store::CatalogStoreError,
    >,
) {
    use mb_core::CatalogCheckpointAuthorityRecord as R;
    let mut after = None;
    while let Some(record) = next(after).unwrap() {
        after = record.revision_key();
        match record {
            R::LegacyRevision(revision) => {
                roots.push((scope, CatalogSection::Checkpoint, revision.body))
            }
            R::PagedRevision(revision) => roots.push((
                revision.value.scope(),
                CatalogSection::SectorReferences,
                revision.value.sources.records.page,
            )),
            _ => panic!("revision cursor returned non-revision"),
        }
    }
}

fn coding_roots(
    node: &Node,
    roots: &mut Vec<Root>,
    scope: CatalogScope,
    coding: mb_core::CatalogCodingDirectoryRoot,
    work: Work,
) {
    let mut coding = mb_core::CatalogCodingDirectoryReader::new(scope, coding, work).unwrap();
    while coding
        .next_group_with_forest(
            &mut |page| {
                node.control
                    .catalog_page(scope, CatalogSection::Coding, page)
            },
            &mut |forest: &mb_core::CatalogCodingRoot| {
                roots.extend(
                    forest
                        .parts
                        .iter()
                        .map(|part| (scope, CatalogSection::Coding, part.page)),
                );
                Ok::<_, mb_store::CatalogStoreError>(())
            },
        )
        .unwrap()
        .is_some()
    {}
}
