use super::checkpoint_restore_tests::{git_directory_proof, git_owner_proof, verify_git_restore};
use super::*;
use crate::network::build_p2p;
use crate::{RetainedCheckpointPeer, RetainedSnapshotRestore};
use std::sync::{Arc, Mutex};
use std::time::Duration;

macro_rules! cases {
    ($test:ident,$proof:ident,$layout:ident,$metadata:ident,$revision:ident,$lookup:ident,$chunks:ident,$payload:ident,$cancel:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $test() {
            let (temp, _, mut node, mut keys) = fixture();
            let local = keys
                .iter()
                .position(|key| key.node_id() == node.keys.node_id())
                .unwrap();
            keys.swap(0, local);
            let (proof, _) = $proof(&mut node, &keys, true);
            let first = proof.index().next_revision(None).unwrap().unwrap();
            let record = proof
                .index()
                .next_revision(first.revision_key())
                .unwrap()
                .unwrap();
            let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = record else {
                panic!("original paged revision")
            };
            let key = mb_core::CatalogCheckpointRevisionKey::from(&signed.value);
            let server_owner = Uuid::from_u128(530);
            let restore_owner = Uuid::from_u128(531);
            let cancelled_owner = Uuid::from_u128(533);
            for owner in [server_owner, restore_owner, cancelled_owner] {
                node.$metadata(owner, &proof).unwrap();
                node.$lookup(owner, &proof).unwrap();
            }
            for owner in [restore_owner, cancelled_owner] {
                node.$revision(owner, &proof, key).unwrap();
                node.$chunks(owner, &proof).unwrap();
            }
            let mut after = None;
            let mut first_entry = None;
            while let Some(row) = proof.index().index().next_group(after).unwrap() {
                let group = row.group.range.group_id;
                node.$payload(server_owner, &proof, group, 1).unwrap();
                if first_entry.is_none() {
                    first_entry = proof
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
                        .unwrap();
                }
                after = Some(group);
            }
            after = None;
            while let Some(row) = proof.index().index().next_group(after).unwrap() {
                let group = row.group.range.group_id;
                // The original retained role must remain readable after the
                // current projection forgets it. No current checkpoint exists.
                let retired = event(
                    &node,
                    &keys,
                    mb_core::GuildEventKind::RetireCodingGroup {
                        group_id: group,
                        retain_through_event: node
                            .dynamic_guild_state()
                            .unwrap()
                            .unwrap()
                            .event_sequence
                            + 1,
                    },
                );
                node.install_guild_event(retired).unwrap();
                let forgotten = event(
                    &node,
                    &keys,
                    mb_core::GuildEventKind::ForgetCodingGroup { group_id: group },
                );
                node.install_guild_event(forgotten).unwrap();
                after = Some(group);
            }
            let entry = first_entry.unwrap();
            let area = mb_store::StableAnchorAreaLocator::prepare_for_root(
                &node.data_dir.join("retained-git-source"),
            )
            .unwrap();
            std::fs::remove_dir_all(area.path_hint).unwrap();
            let request = RetainedSnapshotRestore {
                layout: mb_core::PagedCheckpointLayout::$layout,
                owner: restore_owner,
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
            assert!(
                node.reader_config()
                    .open()
                    .unwrap()
                    .variable_shard_for_guild(&request.guild_id, &entry.retained.group.id, 1,)
                    .is_err()
            );
            let target_id = node.keys.node_id();
            let session = node.retained_checkpoint_restore().unwrap();
            let server_node = Arc::new(Mutex::new(node));
            let caller_seed = (120..125)
                .map(|n| Seed::from_bytes([n; 32]))
                .find(|seed| KeyMaterial::from_seed(seed).node_id() == keys[1].node_id())
                .unwrap();
            let caller = Node::open(temp.path().join("transport-caller"), caller_seed).unwrap();
            let caller_id = caller.keys.node_id();
            let outsider =
                Node::open(temp.path().join("outsider"), Seed::from_bytes([230; 32])).unwrap();
            let outsider_id = outsider.keys.node_id();
            let (server, server_loop) =
                build_p2p(server_node.clone(), super::transport::config(target_id)).unwrap();
            let (client, client_loop) = build_p2p(
                Arc::new(Mutex::new(caller)),
                super::transport::config(caller_id),
            )
            .unwrap();
            let (untrusted, untrusted_loop) = build_p2p(
                Arc::new(Mutex::new(outsider)),
                super::transport::config(outsider_id),
            )
            .unwrap();
            let server_task = tokio::spawn(server_loop.run());
            let client_task = tokio::spawn(client_loop.run());
            let untrusted_task = tokio::spawn(untrusted_loop.run());
            let address: libp2p::Multiaddr = tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if let Some(address) = server.status().await.unwrap().listen_addresses.first()
                        && !address.contains("/udp/0/")
                    {
                        break address.parse().unwrap();
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
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
            let peer = RetainedCheckpointPeer {
                node_id: target_id,
                owner_id: server_owner,
            };
            // Establish transport first, then prove these reads and the
            // independent destination writer do not require the Node mutex.
            client
                .retained_checkpoint_shard(peer, &request, &entry, 1)
                .await
                .unwrap();
            assert!(
                untrusted
                    .retained_checkpoint_shard(peer, &request, &entry, 1)
                    .await
                    .is_err()
            );
            for field in 0..4 {
                let mut wrong = request.clone();
                let mut location = peer;
                match field {
                    0 => location.owner_id = Uuid::from_u128(999),
                    1 => wrong.snapshot.checkpoint_hash[0] ^= 1,
                    2 => {
                        wrong.layout = match request.layout {
                            mb_core::PagedCheckpointLayout::Individual => {
                                mb_core::PagedCheckpointLayout::Directory
                            }
                            _ => mb_core::PagedCheckpointLayout::Individual,
                        }
                    }
                    _ => wrong.guild_id = [249; 32],
                }
                assert!(
                    client
                        .retained_checkpoint_shard(location, &wrong, &entry, 1)
                        .await
                        .is_err()
                );
            }
            let (locked, lock_ready) = tokio::sync::oneshot::channel();
            let (release, released) = std::sync::mpsc::channel();
            let held_node = server_node.clone();
            let held_task = tokio::task::spawn_blocking(move || {
                let _held = held_node.lock().unwrap();
                locked.send(()).unwrap();
                let _ = released.recv();
            });
            lock_ready.await.unwrap();
            let target = temp.path().join("retained-peer-restored");
            tokio::time::timeout(
                Duration::from_secs(60),
                client.restore_retained_checkpoint_snapshot(
                    session,
                    request.clone(),
                    target.clone(),
                    vec![peer],
                ),
            )
            .await
            .unwrap()
            .unwrap();
            release.send(()).unwrap();
            held_task.await.unwrap();
            {
                let held = server_node.lock().unwrap();
                verify_git_restore(&held, &target, key.protected_root_id);
                assert!(held.control.records("restore-job").unwrap().is_empty());
                assert!(
                    held.control
                        .checkpoint_head_identity(&request.guild_id)
                        .unwrap()
                        .is_none()
                );
            }

            let runtime = tokio::runtime::Handle::current();
            let failed_target = temp.path().join("cancelled-during-peer-fetch");
            let mut cancelled_request = request.clone();
            cancelled_request.owner = cancelled_owner;
            let session = server_node
                .lock()
                .unwrap()
                .retained_checkpoint_restore()
                .unwrap();
            let cancelled_node = server_node.clone();
            let fetch_client = client.clone();
            let fetch_runtime = runtime.clone();
            let checked_target = failed_target.clone();
            let failed = tokio::task::spawn_blocking(move || {
                session.restore(&cancelled_request, &failed_target, |entry, index| {
                    if index != 1 {
                        return Ok(None);
                    }
                    let bytes = fetch_runtime.block_on(fetch_client.retained_checkpoint_shard(
                        peer,
                        &cancelled_request,
                        entry,
                        index,
                    ))?;
                    cancelled_node
                        .lock()
                        .unwrap()
                        .control
                        .$cancel(cancelled_owner)?;
                    Ok(Some(bytes))
                })
            })
            .await
            .unwrap();
            assert!(failed.is_err());
            assert!(!checked_target.exists());

            let published_target = temp.path().join("interrupted-peer-publication");
            let session = server_node
                .lock()
                .unwrap()
                .retained_checkpoint_restore()
                .unwrap();
            let fetch_client = client.clone();
            let publish_request = request.clone();
            let publish_target = published_target.clone();
            let interrupted = tokio::task::spawn_blocking(move || {
                let mut injected = false;
                session.restore(&publish_request, &publish_target, |entry, index| {
                    if index != 1 {
                        return Ok(None);
                    }
                    let bytes = runtime.block_on(fetch_client.retained_checkpoint_shard(
                        peer,
                        &publish_request,
                        entry,
                        index,
                    ))?;
                    if !injected {
                        crate::snapshot::interrupt_next_restore_after_rename();
                        injected = true;
                    }
                    Ok(Some(bytes))
                })
            })
            .await
            .unwrap();
            assert!(interrupted.is_err());
            assert!(published_target.is_dir());
            use std::os::unix::fs::MetadataExt;
            let inode = std::fs::metadata(&published_target).unwrap().ino();
            server_node
                .lock()
                .unwrap()
                .control
                .$cancel(restore_owner)
                .unwrap();
            let replay = server_node
                .lock()
                .unwrap()
                .retained_checkpoint_restore()
                .unwrap();
            server_node
                .lock()
                .unwrap()
                .control
                .$cancel(server_owner)
                .unwrap();
            assert!(
                client
                    .retained_checkpoint_shard(peer, &request, &entry, 1)
                    .await
                    .is_err()
            );
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
            untrusted.shutdown().await.unwrap();
            client_task.await.unwrap().unwrap();
            server_task.await.unwrap().unwrap();
            untrusted_task.await.unwrap().unwrap();
            let mut replay_request = request;
            replay_request.budget = mb_core::CatalogCodingTraversalBudget::default();
            client
                .restore_retained_checkpoint_snapshot(
                    replay,
                    replay_request,
                    published_target.clone(),
                    Vec::new(),
                )
                .await
                .unwrap();
            assert_eq!(std::fs::metadata(&published_target).unwrap().ino(), inode);
            verify_git_restore(
                &server_node.lock().unwrap(),
                &published_target,
                key.protected_root_id,
            );
        }
    };
}

cases!(
    retained_individual_peer_restore_uses_original_ready_roles_after_forget_without_mutation_lock,
    git_owner_proof,
    Individual,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_revision,
    build_retained_paged_checkpoint_lookup,
    build_retained_paged_checkpoint_chunk_index,
    retain_paged_checkpoint_local_payload,
    cancel_catalog_paged_checkpoint_retention
);
cases!(
    retained_directory_peer_restore_uses_original_ready_roles_after_forget_without_mutation_lock,
    git_directory_proof,
    Directory,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_revision,
    build_retained_paged_checkpoint_directory_lookup,
    build_retained_paged_checkpoint_directory_chunk_index,
    retain_paged_checkpoint_directory_local_payload,
    cancel_catalog_paged_checkpoint_directory_retention
);

#[test]
fn retained_restore_session_keeps_directory_lease_and_writable_job_after_node_drop() {
    let (temp, seed, mut node, mut keys) = fixture();
    let local = keys
        .iter()
        .position(|key| key.node_id() == node.keys.node_id())
        .unwrap();
    keys.swap(0, local);
    let (proof, _) = checkpoint_owner_proof_with_private(&mut node, &keys, true);
    let first = proof.index().next_revision(None).unwrap().unwrap();
    let record = proof
        .index()
        .next_revision(first.revision_key())
        .unwrap()
        .unwrap();
    let mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed) = record else {
        panic!("original paged revision")
    };
    let key = mb_core::CatalogCheckpointRevisionKey::from(&signed.value);
    let owner = Uuid::from_u128(532);
    node.retain_paged_checkpoint_metadata(owner, &proof)
        .unwrap();
    node.retain_paged_checkpoint_local_revision(owner, &proof, key)
        .unwrap();
    node.build_retained_paged_checkpoint_lookup(owner, &proof)
        .unwrap();
    let request = RetainedSnapshotRestore {
        layout: mb_core::PagedCheckpointLayout::Individual,
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
    drop(node);
    assert!(Node::open(temp.path(), seed.clone()).is_err());
    session
        .restore(
            &request,
            &temp.path().join("owned-after-node-drop"),
            |_, _| panic!("empty native tree fetched a shard"),
        )
        .unwrap();
    drop(session);
    let node = Node::open(temp.path(), seed).unwrap();
    assert!(node.control.records("restore-job").unwrap().is_empty());
}
