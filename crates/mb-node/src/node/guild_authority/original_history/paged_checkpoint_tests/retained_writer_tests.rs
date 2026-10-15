use super::checkpoint_bootstrap_tests::fresh_public_node;
use super::checkpoint_chain_tests::{acquire, quota, successor};
use super::*;
use crate::RecoveredCheckpointProof;
use mb_core::{CatalogCheckpointAuthorityRecord as R, CatalogScope, CatalogSection};
use mb_store::CatalogPublicCheckpoint as Certificate;

#[derive(Clone, Copy, Debug)]
enum Change {
    Rotated,
    Revoked,
    Removed,
}

#[derive(Clone, Copy, Debug)]
enum InvalidRevision {
    NewUnderOldWriter,
    ReauthoredPredecessor,
    UnknownWriter,
}

// Sign hostile proposals directly: the production signing API correctly refuses
// these transitions. All public pages and signatures must otherwise be valid.
fn invalid_successor(
    node: &Node,
    keys: &[KeyMaterial],
    certificate: &Certificate,
    invalid: InvalidRevision,
    budget: Work,
) -> Certificate {
    let scope = CatalogScope::Guild {
        guild_id: certificate.guild_id(),
    };
    let mut reader = mb_core::CatalogCheckpointAuthorityReader::new_with_budget(
        scope,
        certificate.authority(),
        budget,
    )
    .unwrap();
    let mut records = Vec::new();
    while let Some(record) = reader
        .next_record(&mut |page| {
            node.control
                .catalog_page(scope, CatalogSection::Checkpoint, page)
        })
        .unwrap()
    {
        records.push(record);
    }
    let position = records
        .iter()
        .position(|record| matches!(record, R::PagedRevision(_)))
        .unwrap();
    let R::PagedRevision(original) = &records[position] else {
        unreachable!()
    };
    let mut revised = original.value.clone();
    let mut nested_records = 0;
    let writer = match invalid {
        InvalidRevision::NewUnderOldWriter => {
            revised.parent = Some(revised.hash().unwrap());
            revised.sequence += 1;
            revised.revision_id = Uuid::new_v4();
            nested_records = revised.sources.records.records;
            ed25519_dalek::SigningKey::from_bytes(&[72; 32])
        }
        InvalidRevision::ReauthoredPredecessor => {
            revised.writer_epoch = 2;
            ed25519_dalek::SigningKey::from_bytes(&[92; 32])
        }
        InvalidRevision::UnknownWriter => {
            revised.writer_epoch = 3;
            ed25519_dalek::SigningKey::from_bytes(&[93; 32])
        }
    };
    revised.writer_public_key = writer.verifying_key().to_bytes();
    let fence = mb_core::WriterFence {
        owner: revised.owner,
        epoch: revised.writer_epoch,
        public_key: revised.writer_public_key,
    };
    let signed = R::PagedRevision(revised.sign(&writer, &keys[0]).unwrap());
    if matches!(invalid, InvalidRevision::NewUnderOldWriter) {
        records.insert(position + 1, signed);
    } else {
        records[position] = signed;
        let position = records
            .iter()
            .position(|record| !matches!(record, R::Member(_) | R::WriterFence(_)))
            .unwrap();
        records.insert(position, R::WriterFence(fence));
        if matches!(invalid, InvalidRevision::UnknownWriter) {
            // Epochs in the public body are contiguous even when a proposed
            // final key is absent from original certified writer history.
            records.insert(
                position,
                R::WriterFence(mb_core::WriterFence {
                    owner: keys[0].node_id(),
                    epoch: 2,
                    public_key: ed25519_dalek::SigningKey::from_bytes(&[92; 32])
                        .verifying_key()
                        .to_bytes(),
                }),
            );
        }
    }
    let old_root = certificate.authority();
    let mut builder = mb_core::CatalogCheckpointAuthorityBuilder::new_with_budget(
        scope,
        certificate.generation(),
        old_root.membership_epoch,
        budget,
    )
    .unwrap();
    let mut pages = Vec::new();
    let mut sink = |page, bytes| {
        pages.push((page, bytes));
        Ok::<_, mb_store::CatalogStoreError>(())
    };
    for record in &records {
        builder
            .push(record, &mut sink)
            .unwrap_or_else(|error| panic!("{invalid:?}: {error:?}"));
    }
    let root = builder.finish(&mut sink).unwrap();
    pages.sort_by_key(|(page, _)| page.height);
    for (page, bytes) in pages {
        let intent = mb_store::CatalogIntent {
            id: Uuid::new_v4(),
            scope,
            section: CatalogSection::Checkpoint,
        };
        node.control
            .begin_catalog_with_page_reservation(
                intent,
                mb_store::CatalogPageReservation {
                    page_bytes: page.page_occurrences * mb_core::CATALOG_PAGE_BYTES as u64,
                    pages: page.page_occurrences,
                },
            )
            .unwrap();
        node.control
            .stage_catalog_page(intent, page, &bytes)
            .unwrap();
        node.control.publish_catalog(intent, page).unwrap();
    }
    let members = records
        .iter()
        .filter_map(|record| {
            if let R::Member(member) = record {
                Some(member.node_id)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    macro_rules! resign {
        ($c:expr) => {{
            let mut c = $c.clone();
            c.checkpoint.authority_records +=
                root.records.records - old_root.records.records + nested_records;
            c.checkpoint.authority_root = root;
            let bytes = canonical_bytes(&c.checkpoint).unwrap();
            c.signatures = keys
                .iter()
                .filter(|key| members.contains(&key.node_id()))
                .map(|key| mb_core::MemberSignature {
                    signer: key.node_id(),
                    signature: key
                        .sign(mb_core::PAGED_GUILD_CHECKPOINT_DOMAIN, &bytes)
                        .to_vec(),
                })
                .collect();
            c.signatures.sort_by_key(|signature| signature.signer);
            c
        }};
    }
    match certificate {
        Certificate::Individual(c) => Certificate::Individual(resign!(c)),
        Certificate::Directory(c) => Certificate::Directory(resign!(c)),
    }
}

macro_rules! cases {
    ($test:ident, $variant:ident, $convert:expr, $cancel:ident, $release:ident) => {
        #[test]
        fn $test() {
            for change in [Change::Rotated, Change::Revoked, Change::Removed] {
                let (source_temp, seed, mut source, mut keys) = fixture();
                let local = keys
                    .iter()
                    .position(|key| key.node_id() == source.keys.node_id())
                    .unwrap();
                keys.swap(0, local);
                // The revision owner is independent of both current holders.
                // Removing it leaves valid current coding placement unchanged.
                let (first, captures) = checkpoint_owner_proof_with_git_inner::<true, true>(
                    &mut source,
                    &keys,
                    true,
                    unix_seconds() + 600,
                    true,
                    true,
                    false,
                );
                let first = ($convert)(&mut source, &keys, first, captures);
                let first = RecoveredCheckpointProof::$variant(Box::new(first));
                quota(&source);
                let session = source.retained_checkpoint_restore().unwrap();
                let first_job = acquire(&session, 980, &first, None);
                let first = session
                    .promote_acquired_checkpoint_after(&first_job, None)
                    .unwrap();
                drop(session);
                let rotate = event(
                    &source,
                    &keys,
                    mb_core::GuildEventKind::RotateWriterKey {
                        owner: keys[0].node_id(),
                        epoch: 2,
                        public_key: ed25519_dalek::SigningKey::from_bytes(&[92; 32])
                            .verifying_key()
                            .to_bytes(),
                    },
                );
                source.install_guild_event(rotate).unwrap();
                match change {
                    Change::Rotated => {}
                    Change::Revoked => {
                        for epoch in [1, 2] {
                            let revoke = event(
                                &source,
                                &keys,
                                mb_core::GuildEventKind::RevokeWriterKey {
                                    owner: keys[0].node_id(),
                                    epoch,
                                },
                            );
                            source.install_guild_event(revoke).unwrap();
                        }
                    }
                    Change::Removed => {
                        let remove = event(
                            &source,
                            &keys,
                            mb_core::GuildEventKind::RemoveMember {
                                node_id: keys[0].node_id(),
                            },
                        );
                        source.install_guild_event(remove).unwrap();
                    }
                }
                let next = successor(&mut source, &keys, &first, true);
                let certificate = next.certificate();
                let receiver_temp = tempfile::tempdir().unwrap();
                let receiver = fresh_public_node(receiver_temp.path(), seed.clone(), &source);
                quota(&receiver);
                let session = receiver.retained_checkpoint_restore().unwrap();
                let job = session
                    .acquire_public_checkpoint_after(
                        Uuid::from_u128(981),
                        first.certificate(),
                        first_job.budget,
                        None,
                        |path| {
                            Ok(source.control.catalog_page(
                                path.scope,
                                path.section,
                                *path.pages.last().unwrap(),
                            )?)
                        },
                    )
                    .unwrap();
                let previous = session
                    .promote_acquired_checkpoint_after(&job, None)
                    .unwrap();
                let tip = receiver.control.checkpoint_recovery_tip().unwrap();
                for invalid in [
                    InvalidRevision::NewUnderOldWriter,
                    InvalidRevision::ReauthoredPredecessor,
                    InvalidRevision::UnknownWriter,
                ] {
                    let bad =
                        invalid_successor(&source, &keys, &certificate, invalid, first_job.budget);
                    let result = session.acquire_public_checkpoint_after(
                        Uuid::new_v4(),
                        bad,
                        first_job.budget,
                        Some(&previous),
                        |path| {
                            Ok(source.control.catalog_page(
                                path.scope,
                                path.section,
                                *path.pages.last().unwrap(),
                            )?)
                        },
                    );
                    match invalid {
                        InvalidRevision::UnknownWriter => assert!(result.is_err()),
                        _ => {
                            let bad_job = result.unwrap();
                            let error = match session
                                .promote_acquired_checkpoint_after(&bad_job, Some(&previous))
                            {
                                Ok(_) => panic!("unauthorized revision accepted after {change:?}"),
                                Err(error) => error,
                            };
                            assert!(
                                error
                                    .to_string()
                                    .contains("validate original checkpoint transition"),
                                "{error:#}"
                            );
                            if matches!(invalid, InvalidRevision::NewUnderOldWriter)
                                && !matches!(change, Change::Removed)
                            {
                                assert!(format!("{error:#}").contains("writer"), "{error:#}");
                            }
                            assert_eq!(
                                receiver
                                    .control
                                    .checkpoint_acquisition_state(&bad_job)
                                    .unwrap(),
                                mb_store::CatalogCheckpointAcquisitionState::Building
                            );
                        }
                    }
                    assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap(), tip);
                }
                let next_job = session
                    .acquire_public_checkpoint_after(
                        Uuid::from_u128(982),
                        certificate.clone(),
                        first_job.budget,
                        Some(&previous),
                        |path| {
                            Ok(source.control.catalog_page(
                                path.scope,
                                path.section,
                                *path.pages.last().unwrap(),
                            )?)
                        },
                    )
                    .unwrap();
                let received = session
                    .promote_acquired_checkpoint_after(&next_job, Some(&previous))
                    .unwrap();
                assert_eq!(received.certificate(), certificate);
                drop(received);
                drop(previous);
                drop(session);
                receiver
                    .control
                    .cancel_checkpoint_acquisition(&job)
                    .unwrap();
                while receiver
                    .control
                    .release_checkpoint_acquisition_step(&job)
                    .unwrap()
                {}
                receiver.control.$cancel(job.id).unwrap();
                while receiver.control.$release(job.id).unwrap() {}
                drop(receiver);
                let receiver = Node::open(receiver_temp.path(), seed).unwrap();
                let session = receiver.retained_checkpoint_restore().unwrap();
                let rebuilt = session
                    .rebuild_checkpoint_recovery_proof(Work {
                        bytes: 16 << 30,
                        records: 16 << 20,
                        page_occurrences: 16 << 20,
                    })
                    .unwrap();
                assert_eq!(rebuilt.certificate(), certificate);
                rebuilt.verify().unwrap();
                assert_eq!(
                    receiver.control.checkpoint_acquisition_state(&job).unwrap(),
                    mb_store::CatalogCheckpointAcquisitionState::Cancelled
                );
                assert!(
                    receiver
                        .control
                        .checkpoint_head_identity(&certificate.guild_id())
                        .unwrap()
                        .is_none()
                );
                drop(source_temp);
            }
        }
    };
}

cases!(
    individual_retained_writer_recovery_survives_rotation_revocation_and_removal,
    Individual,
    |_: &mut Node, _: &[KeyMaterial], proof, _| proof,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
cases!(
    directory_retained_writer_recovery_survives_rotation_revocation_and_removal,
    Directory,
    |node: &mut Node, keys: &[KeyMaterial], proof, captures| directory_from_original(
        node, keys, proof, captures
    )
    .0,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);
