use super::checkpoint_bootstrap_tests::fresh_public_node;
use super::checkpoint_restore_tests::{git_directory_proof, git_owner_proof, verify_git_restore};
use super::*;
use crate::network::build_p2p;
use crate::{RetainedCheckpointPeer, RetainedSnapshotRestore};
use mb_store::CatalogPublicCheckpoint;
use std::sync::{Arc, Mutex};
use std::time::Duration;

macro_rules! cases {
    ($test:ident,$constructor:ident,$certificate:ident,$metadata:ident,$payload:ident,$layout:ident) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $test() {
            let (temp, seed, mut original, mut keys) = fixture();
            let local = keys
                .iter()
                .position(|key| key.node_id() == original.keys.node_id())
                .unwrap();
            keys.swap(0, local);
            let (proof, _) = $constructor(&mut original, &keys, true);
            let certificate = CatalogPublicCheckpoint::$certificate(proof.certificate().clone());
            let budget = proof.transition().budget();
            let origin_owner = Uuid::from_u128(860);
            original.$metadata(origin_owner, &proof).unwrap();
            let server_seed = (120..125)
                .map(|n| Seed::from_bytes([n; 32]))
                .find(|seed| KeyMaterial::from_seed(seed).node_id() == keys[1].node_id())
                .unwrap();
            let survivor_temp = tempfile::tempdir().unwrap();
            let mut survivor = fresh_public_node(survivor_temp.path(), server_seed, &original);
            survivor
                .control
                .configure_catalog_storage_quota(mb_store::CatalogStorageQuota {
                    page_bytes: 128 << 20,
                    pages: 2048,
                    open_reservations: 64,
                })
                .unwrap();
            let survivor_owner = Uuid::from_u128(861);
            let session = survivor.retained_checkpoint_restore().unwrap();
            let source = original.reader_config().open().unwrap();
            let staged = session
                .acquire_public_checkpoint(survivor_owner, certificate.clone(), budget, |path| {
                    source.retained_paged_checkpoint_public_page(
                        certificate.guild_id(),
                        certificate.layout(),
                        origin_owner,
                        certificate.hash()?,
                        &path,
                    )
                })
                .expect("survivor public acquisition");
            session
                .promote_acquired_checkpoint(&staged, None)
                .expect("survivor complete public proof");
            drop(session);
            let mut after = None;
            while let Some(row) = proof.index().index().next_group(after).unwrap() {
                let group = row.group.range.group_id;
                let entry = proof
                    .index()
                    .index()
                    .read_group(group, |page| {
                        original.control.catalog_page(
                            mb_core::CatalogScope::Guild {
                                guild_id: proof.trust().guild_id,
                            },
                            mb_core::CatalogSection::Coding,
                            page,
                        )
                    })
                    .unwrap()
                    .unwrap();
                let parity = original
                    .volumes
                    .load_ready_variable(&original.control, &group, 1)
                    .unwrap();
                let mut shards = vec![None, Some(parity.bytes)];
                mb_core::reconstruct(entry.retained.group.profile, &mut shards).unwrap();
                let information = shards[0].take().unwrap();
                let plan = &entry.transcript.value.plan;
                survivor
                    .reserve_coding_information(plan, 0)
                    .expect("surviving holder reserve information");
                survivor
                    .write_coding_information_range(plan, 0, 0, &information)
                    .unwrap();
                survivor.finish_coding_information_upload(plan, 0).unwrap();
                survivor
                    .activate_coding_attempt(&entry.transcript)
                    .expect("surviving holder READY activation");
                survivor
                    .$payload(survivor_owner, &proof, group, 0)
                    .expect("surviving holder original payload custody");
                after = Some(group);
            }
            let receiver_temp = tempfile::tempdir().unwrap();
            let fresh = receiver_temp.path();
            let receiver = fresh_public_node(fresh, seed.clone(), &survivor);
            receiver
                .control
                .configure_catalog_storage_quota(mb_store::CatalogStorageQuota {
                    page_bytes: 128 << 20,
                    pages: 2048,
                    open_reservations: 64,
                })
                .unwrap();
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
            drop(source);
            drop(original);
            std::fs::remove_dir_all(temp.path()).unwrap();
            assert!(!temp.path().exists());
            let server_id = survivor.keys.node_id();
            let server_node = Arc::new(Mutex::new(survivor));
            let (server, server_loop) =
                build_p2p(server_node.clone(), super::transport::config(server_id)).unwrap();
            let session = receiver.retained_checkpoint_restore().unwrap();
            let receiver = Arc::new(Mutex::new(receiver));
            let (client, client_loop) = build_p2p(
                receiver.clone(),
                super::transport::config(keys[0].node_id()),
            )
            .unwrap();
            let server_task = tokio::spawn(server_loop.run());
            let client_task = tokio::spawn(client_loop.run());
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
            client.add_peer_address(server_id, address).await.unwrap();
            let peer = RetainedCheckpointPeer {
                node_id: server_id,
                owner_id: survivor_owner,
            };
            let owner = Uuid::from_u128(862);
            let runtime = tokio::runtime::Handle::current();
            let interrupted_client = client.clone();
            let interrupted_certificate = certificate.clone();
            let interrupted = tokio::task::spawn_blocking(move || {
                let mut calls = 0;
                let result = session.acquire_public_checkpoint(
                    owner,
                    interrupted_certificate.clone(),
                    budget,
                    |path| {
                        calls += 1;
                        if calls == 2 {
                            anyhow::bail!("injected public acquisition interruption")
                        }
                        runtime.block_on(interrupted_client.retained_paged_checkpoint_public_page(
                            peer.node_id,
                            interrupted_certificate.layout(),
                            peer.owner_id,
                            interrupted_certificate.hash()?,
                            path,
                        ))
                    },
                );
                assert_eq!(calls, 2);
                result
            })
            .await
            .unwrap();
            assert!(interrupted.is_err());
            let cancelled_id = Uuid::from_u128(863);
            let cancelled = receiver
                .lock()
                .unwrap()
                .control
                .begin_checkpoint_acquisition(
                    cancelled_id,
                    certificate.clone(),
                    proof.trust().clone(),
                    budget,
                )
                .unwrap();
            let cancel_session = receiver
                .lock()
                .unwrap()
                .retained_checkpoint_restore()
                .unwrap();
            let cancel_node = receiver.clone();
            let runtime = tokio::runtime::Handle::current();
            let cancel_client = client.clone();
            let cancel_certificate = certificate.clone();
            let cancel_job = cancelled.clone();
            let cancelled_result = tokio::task::spawn_blocking(move || {
                let mut checked = false;
                let result = cancel_session.acquire_public_checkpoint(
                    cancelled_id,
                    cancel_certificate.clone(),
                    budget,
                    |path| {
                        let bytes = runtime.block_on(
                            cancel_client.retained_paged_checkpoint_public_page(
                                peer.node_id,
                                cancel_certificate.layout(),
                                peer.owner_id,
                                cancel_certificate.hash()?,
                                path,
                            ),
                        )?;
                        if !checked {
                            cancel_node
                                .lock()
                                .unwrap()
                                .control
                                .cancel_checkpoint_acquisition(&cancel_job)
                                .unwrap();
                            checked = true;
                        }
                        Ok(bytes)
                    },
                );
                assert!(checked);
                result
            })
            .await
            .unwrap();
            assert!(cancelled_result.is_err());
            while receiver
                .lock()
                .unwrap()
                .control
                .release_checkpoint_acquisition_step(&cancelled)
                .unwrap()
            {}
            let session = receiver
                .lock()
                .unwrap()
                .retained_checkpoint_restore()
                .unwrap();
            let (session, job) = client
                .acquire_retained_checkpoint_public_catalog(
                    session,
                    owner,
                    peer,
                    certificate.layout(),
                    certificate.hash().unwrap(),
                    budget,
                )
                .await
                .expect("cold public acquisition over QUIC");
            assert!(
                receiver
                    .lock()
                    .unwrap()
                    .control
                    .paged_revision_catalog(key.revision_id)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                receiver
                    .lock()
                    .unwrap()
                    .control
                    .checkpoint_acquisition_state(&job)
                    .unwrap(),
                mb_store::CatalogCheckpointAcquisitionState::Building
            );
            session
                .promote_acquired_checkpoint(&job, None)
                .expect("cold complete original public proof");
            let request = RetainedSnapshotRestore {
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
                budget,
            };
            let target = fresh.join("restored-from-survivor");
            client
                .restore_retained_checkpoint_snapshot(session, request, target.clone(), vec![peer])
                .await
                .expect("cold full native and Git restore over QUIC");
            verify_git_restore(&receiver.lock().unwrap(), &target, key.protected_root_id);
            receiver
                .lock()
                .unwrap()
                .control
                .cancel_checkpoint_acquisition(&job)
                .unwrap();
            while receiver
                .lock()
                .unwrap()
                .control
                .release_checkpoint_acquisition_step(&job)
                .unwrap()
            {}
            verify_git_restore(&receiver.lock().unwrap(), &target, key.protected_root_id);
            client.shutdown().await.unwrap();
            server.shutdown().await.unwrap();
            client_task.await.unwrap().unwrap();
            server_task.await.unwrap().unwrap();
            drop(client);
            drop(receiver);
            let reopened = Node::open(fresh, seed).unwrap();
            assert_eq!(
                reopened.control.checkpoint_acquisition_state(&job).unwrap(),
                mb_store::CatalogCheckpointAcquisitionState::Cancelled
            );
            verify_git_restore(&reopened, &target, key.protected_root_id);
        }
    };
}
cases!(
    individual_public_acquisition_and_full_seed_owned_restore_use_surviving_holder_over_quic,
    git_owner_proof,
    Individual,
    retain_paged_checkpoint_metadata,
    retain_paged_checkpoint_local_payload,
    Individual
);
cases!(
    directory_public_acquisition_and_full_seed_owned_restore_use_surviving_holder_over_quic,
    git_directory_proof,
    Directory,
    retain_paged_checkpoint_directory_metadata,
    retain_paged_checkpoint_directory_local_payload,
    Directory
);
