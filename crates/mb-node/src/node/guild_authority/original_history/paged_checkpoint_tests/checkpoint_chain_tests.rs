use super::checkpoint_bootstrap_tests::fresh_public_node;
use super::checkpoint_restore_tests::{git_directory_proof, git_owner_proof, verify_git_restore};
use super::*;
use crate::{RecoveredCheckpointProof, RetainedSnapshotRestore};
use mb_core::{CatalogCheckpointAuthorityRecord as R, CatalogScope, CatalogSection};
use mb_core::{QuorumPagedCheckpoint, QuorumPagedCheckpointDirectory};
use mb_store::CatalogPublicCheckpoint as Certificate;

fn quota(node: &Node) {
    node.control
        .configure_catalog_storage_quota(mb_store::CatalogStorageQuota {
            page_bytes: 128 << 20,
            pages: 2048,
            open_reservations: 64,
        })
        .unwrap();
}
fn acquire(
    session: &crate::RetainedCheckpointRestore,
    id: u128,
    proof: &RecoveredCheckpointProof,
    previous: Option<&RecoveredCheckpointProof>,
) -> mb_store::CatalogCheckpointAcquisition {
    session
        .acquire_public_checkpoint_after(
            Uuid::from_u128(id),
            proof.certificate(),
            Work {
                bytes: 64 << 20,
                records: 65536,
                page_occurrences: 65536,
            },
            previous,
            |_| anyhow::bail!("fixture public pages should already be local"),
        )
        .unwrap()
}
fn successor(
    node: &mut Node,
    keys: &[KeyMaterial],
    previous: &RecoveredCheckpointProof,
    original_history_checked: bool,
) -> RecoveredCheckpointProof {
    let certified = event(
        node,
        keys,
        mb_core::GuildEventKind::SetQuorum {
            policy: mb_core::QuorumPolicy {
                format_version: 1,
                rule: mb_core::QuorumRule::Majority,
            },
        },
    );
    node.install_guild_event(certified).unwrap();
    let old = previous.certificate();
    let work = Work {
        bytes: 64 << 20,
        records: 65536,
        page_occurrences: 65536,
    };
    let session = node.retained_checkpoint_restore().unwrap();
    let sequence = super::super::super::frozen_original_history(&node.control)
        .unwrap()
        .snapshot()
        .event_sequence;
    let trust = session
        .public_checkpoint_trust_after(sequence, Some(previous))
        .unwrap();
    drop(session);
    let scope = CatalogScope::Guild {
        guild_id: trust.guild_id,
    };
    let mut pages = std::collections::BTreeMap::new();
    let mut authority = mb_core::CatalogCheckpointAuthorityBuilder::new_with_budget(
        scope,
        old.generation() + 1,
        trust.authority.membership_epoch,
        work,
    )
    .unwrap();
    for member in &trust.members {
        authority
            .push(&R::Member(member.clone()), &mut |page, bytes| {
                pages.insert(page.hash, (CatalogSection::Checkpoint, page, bytes));
                Ok::<_, mb_store::CatalogStoreError>(())
            })
            .unwrap();
    }
    let mut reader =
        mb_core::CatalogCheckpointAuthorityReader::new_with_budget(scope, old.authority(), work)
            .unwrap();
    while let Some(record) = reader
        .next_record(&mut |page| {
            node.control
                .catalog_page(scope, CatalogSection::Checkpoint, page)
        })
        .unwrap()
    {
        if !matches!(record, R::Member(_)) {
            authority
                .push(&record, &mut |page, bytes| {
                    pages.insert(page.hash, (CatalogSection::Checkpoint, page, bytes));
                    Ok::<_, mb_store::CatalogStoreError>(())
                })
                .unwrap();
        }
    }
    let authority = authority
        .finish(&mut |page, bytes| {
            pages.insert(page.hash, (CatalogSection::Checkpoint, page, bytes));
            Ok::<_, mb_store::CatalogStoreError>(())
        })
        .unwrap();
    let mut coding =
        mb_core::CatalogCodingDirectoryBuilder::new(scope, trust.event_sequence, work).unwrap();
    let mut entries =
        mb_core::CatalogCodingDirectoryReader::new(scope, old.coding(), work).unwrap();
    while let Some(entry) = entries
        .next_group(&mut |page| {
            node.control
                .catalog_page(scope, CatalogSection::Coding, page)
        })
        .unwrap()
    {
        coding
            .push_group(&entry, &mut |page, bytes| {
                pages.insert(page.hash, (CatalogSection::Coding, page, bytes));
                Ok::<_, mb_store::CatalogStoreError>(())
            })
            .unwrap();
    }
    let coding = coding
        .finish(&mut |page, bytes| {
            pages.insert(page.hash, (CatalogSection::Coding, page, bytes));
            Ok::<_, mb_store::CatalogStoreError>(())
        })
        .unwrap();
    let mut pages = pages.into_values().collect::<Vec<_>>();
    pages.sort_by_key(|(_, page, _)| page.height);
    for (index, (section, page, bytes)) in pages.iter().enumerate() {
        let intent = mb_store::CatalogIntent {
            id: Uuid::from_u128(9000 + trust.event_sequence as u128 * 100 + index as u128),
            scope,
            section: *section,
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
            .stage_catalog_page(intent, *page, bytes)
            .unwrap();
        node.control.publish_catalog(intent, *page).unwrap();
    }
    let installed = node.installed_guild().unwrap().unwrap();
    let mut source = &node.control;
    let history = mb_store::CatalogGuildHistoryIndex::build(
        mb_store::RecordScratchStore::new(4 << 20).unwrap(),
        &installed.certificate,
        work,
        Work::default(),
        || Ok(trust.clone()),
        &mut source,
    )
    .unwrap();
    let view = history.view(|| Ok(trust.clone())).unwrap();
    let body = mb_store::CatalogCheckpointAuthorityIndex::build(
        mb_store::CatalogCheckpointAuthorityContext {
            guild_id: trust.guild_id,
            generation: old.generation() + 1,
            event_sequence: trust.event_sequence,
            event_head: trust.event_head,
            authority: trust.authority,
        },
        authority,
        &trust.members,
        work,
        mb_store::RecordScratchStore::new(4 << 20).unwrap(),
        |scope, section, page| node.control.catalog_page(scope, section, page),
        |fence, kind| {
            if view
                .writer_key(fence.owner, fence.epoch, &trust)?
                .is_none_or(|key| key.public_key != fence.public_key)
                || (kind == mb_store::CatalogCheckpointWriterAuthorization::LatestRetained
                    && view.current_writer(fence.owner, &trust)? != Some(fence.clone()))
            {
                return Err(mb_store::DatabaseError::Conflict.into());
            }
            Ok(())
        },
    )
    .unwrap();
    macro_rules! complete {
        ($body:expr,$sign:ident,$bind:ident,$certificate:ident,$variant:ident) => {{
            let state = $body
                .validate_coding_directory(
                    coding,
                    mb_store::CatalogCodingCoveragePolicy::Current,
                    |page| {
                        node.control
                            .catalog_page(scope, CatalogSection::Coding, page)
                    },
                    |_| Ok(mb_store::CatalogCodingAuthorization::CurrentPlacement),
                )
                .unwrap()
                .validate_certified_history_coding_state(&history, work, || Ok(trust.clone()))
                .unwrap();
            let transition = if original_history_checked {
                state
                    .validate_certified_history_authority_transition(
                        Some(previous.previous()),
                        &history,
                        work,
                        || Ok(trust.clone()),
                    )
                    .unwrap()
            } else {
                state
                    .validate_authority_transition(
                        Some(previous.previous()),
                        work,
                        || Ok(trust.clone()),
                        |owner, trust| view.current_writer(owner, trust),
                    )
                    .unwrap()
            };
            let mut header = None;
            let mut signatures = Vec::new();
            for key in keys {
                let (value, signature) = transition.$sign(key, || Ok(trust.clone())).unwrap();
                header = Some(value);
                signatures.push(signature);
            }
            signatures.sort_by_key(|signature| signature.signer);
            let proof = transition
                .$bind(
                    $certificate {
                        checkpoint: header.unwrap(),
                        signatures,
                    },
                    || Ok(trust.clone()),
                )
                .unwrap();
            RecoveredCheckpointProof::$variant(Box::new(proof))
        }};
    }
    match old {
        Certificate::Individual(c) => complete!(
            body.validate_packing(
                mb_store::CatalogPackingValidation {
                    format_version: 1,
                    scope,
                    descriptors: c.checkpoint.packed_sectors,
                    sources: c.checkpoint.packed_sources
                },
                |page| node
                    .control
                    .catalog_page(scope, CatalogSection::Packing, page)
            )
            .unwrap(),
            sign_paged_checkpoint_header,
            bind_paged_checkpoint_header,
            QuorumPagedCheckpoint,
            Individual
        ),
        Certificate::Directory(c) => complete!(
            body.validate_packing_directory(
                mb_store::CatalogPackingDirectoryValidation {
                    format_version: 1,
                    scope,
                    directory: c.checkpoint.packing
                },
                |page| node
                    .control
                    .catalog_page(scope, CatalogSection::Packing, page)
            )
            .unwrap(),
            sign_paged_checkpoint_header,
            bind_paged_checkpoint_header,
            QuorumPagedCheckpointDirectory,
            Directory
        ),
    }
}

macro_rules! cases {
    ($test:ident,$constructor:ident,$variant:ident,$layout:ident,$cancel:ident)=>{
        #[test]
        fn $test() {
            let (original_temp,seed,mut original,mut keys)=fixture();let local=keys.iter().position(|key|key.node_id()==original.keys.node_id()).unwrap();keys.swap(0,local);
            let (first,_captures)=$constructor(&mut original,&keys,true);let first=RecoveredCheckpointProof::$variant(Box::new(first));quota(&original);
            let session=original.retained_checkpoint_restore().unwrap();let first_job=acquire(&session,970,&first,None);
            for action in ["ABORT","IGNORE"] {
                let fault=if action=="ABORT" {",'test'"} else {""};
                original.control.database_shell_statement(&format!("CREATE TRIGGER tip_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-checkpoint-recovery-tip-guard-v1' BEGIN SELECT RAISE({action}{fault}); END"),false).unwrap();
                assert!(session.promote_acquired_checkpoint_after(&first_job,None).is_err());assert!(original.control.checkpoint_recovery_tip().unwrap().is_none());
                assert_eq!(original.control.checkpoint_acquisition_state(&first_job).unwrap(),mb_store::CatalogCheckpointAcquisitionState::Building);
                original.control.database_shell_statement("DROP TRIGGER tip_fault",false).unwrap();
            }
            let first=session.promote_acquired_checkpoint_after(&first_job,None).unwrap();drop(session);
            assert!(original.control.cancel_checkpoint_acquisition(&first_job).is_err());assert!(original.control.$cancel(first_job.id).is_err());
            let uncertified=successor(&mut original,&keys,&first,false);
            assert!(uncertified.verify().unwrap_err().to_string().contains("certified original history"));
            assert!(original.retained_checkpoint_restore().unwrap().public_checkpoint_trust_after(uncertified.certificate().event_sequence(),Some(&uncertified)).is_err());
            let next=successor(&mut original,&keys,&first,true);let session=original.retained_checkpoint_restore().unwrap();let next_job=acquire(&session,971,&next,Some(&first));
            for action in ["ABORT","IGNORE"] {
                let fault=if action=="ABORT" {",'test'"} else {""};
                original.control.database_shell_statement(&format!("CREATE TRIGGER tip_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-checkpoint-recovery-tip-guard-v1' BEGIN SELECT RAISE({action}{fault}); END"),false).unwrap();
                assert!(session.promote_acquired_checkpoint_after(&next_job,Some(&first)).is_err());
                assert_eq!(original.control.checkpoint_recovery_tip().unwrap().unwrap().owner,first_job.id);
                assert_eq!(original.control.checkpoint_acquisition_state(&next_job).unwrap(),mb_store::CatalogCheckpointAcquisitionState::Building);
                original.control.database_shell_statement("DROP TRIGGER tip_fault",false).unwrap();
            }
            let next=session.promote_acquired_checkpoint_after(&next_job,Some(&first)).unwrap();drop(session);
            let scope=CatalogScope::Guild {guild_id:next.certificate().guild_id()};let mut groups=mb_core::CatalogCodingDirectoryReader::new(scope,next.certificate().coding(),next_job.budget).unwrap();
            while let Some(entry)=groups.next_group(&mut |page|original.control.catalog_page(scope,CatalogSection::Coding,page)).unwrap() {original.retain_recovered_checkpoint_payload(next_job.id,&next,entry.retained.group.id,1).unwrap();}
            let rotate=event(&original,&keys,mb_core::GuildEventKind::RotateWriterKey {owner:keys[0].node_id(),epoch:2,public_key:ed25519_dalek::SigningKey::from_bytes(&[92;32]).verifying_key().to_bytes()});original.install_guild_event(rotate).unwrap();
            let revoke=event(&original,&keys,mb_core::GuildEventKind::RevokeWriterKey {owner:keys[0].node_id(),epoch:2});original.install_guild_event(revoke).unwrap();
            let receiver_temp=tempfile::tempdir().unwrap();let receiver=fresh_public_node(receiver_temp.path(),seed.clone(),&original);quota(&receiver);
            let source=original.reader_config().open().unwrap();let session=receiver.retained_checkpoint_restore().unwrap();
            let first_certificate=first.certificate();let first_remote=session.acquire_public_checkpoint_after(Uuid::from_u128(972),first_certificate.clone(),first_job.budget,None,|path|source.retained_paged_checkpoint_public_page(first_certificate.guild_id(),first_certificate.layout(),first_job.id,first_certificate.hash()?,&path)).unwrap();
            let first_received=session.promote_acquired_checkpoint_after(&first_remote,None).unwrap();
            let next_certificate=next.certificate();assert!(session.acquire_public_checkpoint_after(Uuid::from_u128(973),next_certificate.clone(),next_job.budget,None,|_|anyhow::bail!("must reject before fetch")).is_err());
            let next_remote=session.acquire_public_checkpoint_after(Uuid::from_u128(974),next_certificate.clone(),next_job.budget,Some(&first_received),|path|source.retained_paged_checkpoint_public_page(next_certificate.guild_id(),next_certificate.layout(),next_job.id,next_certificate.hash()?,&path)).unwrap();
            drop(first_received);drop(session);drop(receiver);let receiver=Node::open(receiver_temp.path(),seed).unwrap();
            assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap().unwrap().owner,first_remote.id);
            let session=receiver.retained_checkpoint_restore().unwrap();let first_received=session.promote_acquired_checkpoint_after(&first_remote,None).unwrap();
            let received=session.promote_acquired_checkpoint_after(&next_remote,Some(&first_received)).unwrap();
            assert_eq!(received.certificate(),next_certificate);assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap().unwrap().owner,next_remote.id);
            let mut revisions=mb_core::CatalogCheckpointAuthorityReader::new_with_budget(scope,next_certificate.authority(),next_job.budget).unwrap();let mut selected=None;
            while let Some(record)=revisions.next_record(&mut |page|receiver.control.catalog_page(scope,CatalogSection::Checkpoint,page)).unwrap() {if let R::PagedRevision(signed)=record {selected=Some(signed.value);}}
            let revision=selected.unwrap();let target=receiver_temp.path().join("second-generation-restore");
            let request=RetainedSnapshotRestore {layout:mb_core::PagedCheckpointLayout::$layout,owner:next_remote.id,guild_id:next_certificate.guild_id(),snapshot:SnapshotInfo {protected_root_id:revision.protected_root_id,revision_id:revision.revision_id,sequence:revision.sequence,checkpoint_generation:next_certificate.generation(),checkpoint_hash:next_certificate.hash().unwrap()},budget:next_job.budget};
            session.restore(&request,&target,|entry,role| {
                if role!=1 {return Ok(None)}
                Ok(Some(source.retained_checkpoint_shard(request.guild_id,request.layout,next_job.id,request.snapshot.checkpoint_hash,entry.retained.group.id,role)?))
            }).unwrap();verify_git_restore(&receiver,&target,revision.protected_root_id);
            assert!(receiver.control.checkpoint_head_identity(&request.guild_id).unwrap().is_none());
            receiver.control.cancel_checkpoint_recovery_tip(&next_remote).unwrap();receiver.control.cancel_checkpoint_acquisition(&first_remote).unwrap();
            assert!(receiver.control.checkpoint_recovery_tip().unwrap().is_none());assert!(session.promote_acquired_checkpoint_after(&next_remote,Some(&first_received)).is_err());
            verify_git_restore(&receiver,&target,revision.protected_root_id);drop(original_temp);
        }
    };
}
cases!(
    individual_checkpoint_chain_uses_original_history_prefix_and_resumes_after_tip_faults,
    git_owner_proof,
    Individual,
    Individual,
    cancel_catalog_paged_checkpoint_retention
);
cases!(
    directory_checkpoint_chain_uses_original_history_prefix_and_resumes_after_tip_faults,
    git_directory_proof,
    Directory,
    Directory,
    cancel_catalog_paged_checkpoint_directory_retention
);
