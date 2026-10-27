use super::checkpoint_bootstrap_tests::fresh_public_node;
use super::checkpoint_restore_tests::{git_directory_proof, git_owner_proof, verify_git_restore};
use super::*;
use crate::{RecoveredCheckpointProof, RetainedSnapshotRestore};
use mb_core::{CatalogCheckpointAuthorityRecord as R, CatalogScope, CatalogSection};
use mb_core::{QuorumPagedCheckpoint, QuorumPagedCheckpointDirectory};
use mb_store::CatalogPublicCheckpoint as Certificate;
mod resources;

struct PreservedTemp(Option<tempfile::TempDir>);
impl std::ops::Deref for PreservedTemp {
    type Target = tempfile::TempDir;
    fn deref(&self) -> &Self::Target {
        self.0.as_ref().unwrap()
    }
}
impl Drop for PreservedTemp {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "SCRATCH_PLAN_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

#[test]
fn checkpoint_scratch_batch_refuses_complete_credits_without_partial_debt_and_retries() {
    let (temp, _, mut node, _) = fixture();
    let _temp = PreservedTemp(Some(temp));
    resources::configure(&mut node);
    let limits = mb_store::ScratchStorageLimits::for_database(1 << 20).unwrap();
    let pool = node
        .control
        .catalog_scratch_pool_usage()
        .unwrap()
        .unwrap()
        .policy;
    let blocker = node
        .control
        .reserve_catalog_scratch(pool.physical_bytes - limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let before = node.control.catalog_scratch_pool_usage().unwrap();
    let refused = crate::volume::paged_scratch_stores(&node.control, [1 << 20; 2]);
    let error = refused.err().expect("only one complete declaration fits");
    assert!(matches!(
        error.downcast_ref::<mb_store::CatalogStoreError>(),
        Some(mb_store::CatalogStoreError::ScratchPoolExhausted)
    ));
    assert_eq!(node.control.catalog_scratch_pool_usage().unwrap(), before);
    assert!(!node.reclaim_abandoned_catalog_scratch().unwrap());
    drop(blocker);
    assert!(node.reclaim_abandoned_catalog_scratch().unwrap());
    let [history, body] = crate::volume::paged_scratch_stores(&node.control, [1 << 20; 2]).unwrap();
    assert!(
        history
            .put_record_if_absent("batch", b"history", b"original history")
            .unwrap()
    );
    assert!(
        body.put_record_if_absent("batch", b"body", b"original authority")
            .unwrap()
    );
    assert_eq!(
        node.control
            .catalog_scratch_pool_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        2
    );
    drop(history);
    assert!(node.reclaim_abandoned_catalog_scratch().unwrap());
    assert!(!node.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(
        body.get_record_bounded("batch", b"body", 64).unwrap(),
        Some(b"original authority".to_vec())
    );
    drop(body);
    assert!(node.reclaim_abandoned_catalog_scratch().unwrap());
    let usage = node.control.catalog_scratch_pool_usage().unwrap().unwrap();
    assert_eq!((usage.reserved_physical_bytes, usage.open_jobs), (0, 0));
}

pub(super) fn quota(node: &Node) {
    if node.control.catalog_resource_policy().unwrap().is_some() {
        return;
    }
    node.control
        .configure_catalog_storage_quota(mb_store::CatalogStorageQuota {
            page_bytes: 128 << 20,
            pages: 2048,
            open_reservations: 64,
        })
        .unwrap();
}
pub(super) fn acquire(
    session: &crate::RetainedCheckpointRestore,
    id: u128,
    proof: &RecoveredCheckpointProof,
    previous: Option<&RecoveredCheckpointProof>,
) -> mb_store::CatalogCheckpointAcquisition {
    session
        .acquire_public_checkpoint_after(
            Uuid::from_u128(id),
            proof.certificate(),
            match proof {
                RecoveredCheckpointProof::Individual(proof) => proof.transition().budget(),
                RecoveredCheckpointProof::Directory(proof) => proof.transition().budget(),
            },
            previous,
            |_| anyhow::bail!("fixture public pages should already be local"),
        )
        .unwrap()
}
pub(super) fn successor(
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
        |fence, _kind| {
            if view
                .writer_key(fence.owner, fence.epoch, &trust)?
                .is_none_or(|key| key.public_key != fence.public_key)
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
            for key in keys.iter().filter(|key| {
                trust
                    .members
                    .iter()
                    .any(|member| member.node_id == key.node_id())
            }) {
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
    ($test:ident,$constructor:ident,$variant:ident,$layout:ident,$cancel:ident,$release:ident)=>{
        #[test]
        fn $test() {
            let (original_temp,seed,mut original,mut keys)=fixture();let original_temp=PreservedTemp(Some(original_temp));let local=keys.iter().position(|key|key.node_id()==original.keys.node_id()).unwrap();keys.swap(0,local);
            resources::configure(&mut original);
            let (first,_captures)=$constructor(&mut original,&keys,true);let first=RecoveredCheckpointProof::$variant(Box::new(first));quota(&original);eprintln!("SCRATCH_PLAN_PHASE initial proof built");
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
            let rotate=event(&original,&keys,mb_core::GuildEventKind::RotateWriterKey {owner:keys[0].node_id(),epoch:2,public_key:ed25519_dalek::SigningKey::from_bytes(&[92;32]).verifying_key().to_bytes()});original.install_guild_event(rotate).unwrap();
            let next=successor(&mut original,&keys,&first,true);let session=original.retained_checkpoint_restore().unwrap();let next_job=acquire(&session,971,&next,Some(&first));
            for action in ["ABORT","IGNORE"] {
                let fault=if action=="ABORT" {",'test'"} else {""};
                original.control.database_shell_statement(&format!("CREATE TRIGGER tip_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-checkpoint-recovery-tip-guard-v1' BEGIN SELECT RAISE({action}{fault}); END"),false).unwrap();
                assert!(session.promote_acquired_checkpoint_after(&next_job,Some(&first)).is_err());
                assert_eq!(original.control.checkpoint_recovery_tip().unwrap().unwrap().owner,first_job.id);
                assert_eq!(original.control.checkpoint_acquisition_state(&next_job).unwrap(),mb_store::CatalogCheckpointAcquisitionState::Building);
                original.control.database_shell_statement("DROP TRIGGER tip_fault",false).unwrap();
            }
            for action in ["ABORT","IGNORE"] {
                let fault=if action=="ABORT" {",'test'"} else {""};
                original.control.database_shell_statement(&format!("CREATE TRIGGER ancestry_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-checkpoint-ancestry-link-guard-v1' BEGIN SELECT RAISE({action}{fault}); END"),false).unwrap();
                assert!(session.promote_acquired_checkpoint_after(&next_job,Some(&first)).is_err());
                assert_eq!(original.control.checkpoint_recovery_tip().unwrap().unwrap().owner,first_job.id);
                original.control.database_shell_statement("DROP TRIGGER ancestry_fault",false).unwrap();
            }
            let next=session.promote_acquired_checkpoint_after(&next_job,Some(&first)).unwrap();drop(session);
            for kind in ["catalog-checkpoint-ancestry-link-v1","catalog-checkpoint-ancestry-link-guard-v1"] {original.control.delete_record(kind,next_job.id.as_bytes()).unwrap();}
            assert!(original.control.checkpoint_recovery_tip().is_err());
            assert!(original.control.adopt_checkpoint_recovery_ancestry(Uuid::from_u128(999)).is_err());
            original.control.adopt_checkpoint_recovery_ancestry(first_job.id).unwrap();
            assert_eq!(original.control.checkpoint_recovery_tip().unwrap().unwrap().owner,next_job.id);

            assert_eq!(original.control.checkpoint_ancestry_certificate(first_job.id).unwrap(),Some(first.certificate().clone()));
            assert!(original.control.cancel_checkpoint_ancestry_archive(first_job.id).is_err());
            original.control.cancel_checkpoint_acquisition(&first_job).unwrap();
            while original.control.release_checkpoint_acquisition_step(&first_job).unwrap(){}
            original.control.$cancel(first_job.id).unwrap();
            while original.control.$release(first_job.id).unwrap(){}
            assert_eq!(original.control.checkpoint_ancestry_certificate(first_job.id).unwrap(),Some(first.certificate().clone()));
            assert_eq!(original.control.checkpoint_recovery_tip().unwrap().unwrap().owner,next_job.id);

            let scope=CatalogScope::Guild {guild_id:next.certificate().guild_id()};let mut groups=mb_core::CatalogCodingDirectoryReader::new(scope,next.certificate().coding(),next_job.budget).unwrap();
            while let Some(entry)=groups.next_group(&mut |page|original.control.catalog_page(scope,CatalogSection::Coding,page)).unwrap() {original.retain_recovered_checkpoint_payload(next_job.id,&next,entry.retained.group.id,1).unwrap();}
            let revoke=event(&original,&keys,mb_core::GuildEventKind::RevokeWriterKey {owner:keys[0].node_id(),epoch:1});original.install_guild_event(revoke).unwrap();
            let third=successor(&mut original,&keys,&next,true);let session=original.retained_checkpoint_restore().unwrap();let third_job=acquire(&session,975,&third,Some(&next));let third=session.promote_acquired_checkpoint_after(&third_job,Some(&next)).unwrap();drop(session);
            let mut groups=mb_core::CatalogCodingDirectoryReader::new(scope,third.certificate().coding(),third_job.budget).unwrap();
            while let Some(entry)=groups.next_group(&mut |page|original.control.catalog_page(scope,CatalogSection::Coding,page)).unwrap(){original.retain_recovered_checkpoint_payload(third_job.id,&third,entry.retained.group.id,1).unwrap();}
            original.control.cancel_checkpoint_acquisition(&next_job).unwrap();while original.control.release_checkpoint_acquisition_step(&next_job).unwrap(){}
            original.control.$cancel(next_job.id).unwrap();while original.control.$release(next_job.id).unwrap(){}
            let receiver_temp=PreservedTemp(Some(tempfile::tempdir().unwrap()));let mut receiver=fresh_public_node(receiver_temp.path(),seed.clone(),&original);resources::configure(&mut receiver);quota(&receiver);
            let source=original.reader_config().open().unwrap();let session=receiver.retained_checkpoint_restore().unwrap();
            let certificate=first.certificate();let bytes=source.retained_paged_checkpoint_certificate(certificate.guild_id(),certificate.layout(),first_job.id,certificate.hash().unwrap()).unwrap();
            let expected=match &certificate {Certificate::Individual(c)=>mb_core::canonical_bytes(c).unwrap(),Certificate::Directory(c)=>mb_core::canonical_bytes(c).unwrap()};assert_eq!(bytes,expected);
            assert!(source.retained_paged_checkpoint_certificate(certificate.guild_id(),certificate.layout(),first_job.id,[0;32]).is_err());

            let first_certificate=first.certificate();let first_remote=session.acquire_public_checkpoint_after(Uuid::from_u128(972),first_certificate.clone(),first_job.budget,None,|path|source.retained_paged_checkpoint_public_page(first_certificate.guild_id(),first_certificate.layout(),first_job.id,first_certificate.hash()?,&path)).unwrap();
            let first_received=session.promote_acquired_checkpoint_after(&first_remote,None).unwrap();
            let next_certificate=next.certificate();assert!(session.acquire_public_checkpoint_after(Uuid::from_u128(973),next_certificate.clone(),next_job.budget,None,|_|anyhow::bail!("must reject before fetch")).is_err());
            let next_remote=session.acquire_public_checkpoint_after(Uuid::from_u128(974),next_certificate.clone(),next_job.budget,Some(&first_received),|path|source.retained_paged_checkpoint_public_page(next_certificate.guild_id(),next_certificate.layout(),next_job.id,next_certificate.hash()?,&path)).unwrap();
            drop(first_received);drop(session);drop(receiver);let receiver=Node::open(receiver_temp.path(),seed.clone()).unwrap();
            assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap().unwrap().owner,first_remote.id);
            let session=receiver.retained_checkpoint_restore().unwrap();let first_received=session.promote_acquired_checkpoint_after(&first_remote,None).unwrap();
            let received=session.promote_acquired_checkpoint_after(&next_remote,Some(&first_received)).unwrap();
            assert_eq!(received.certificate(),next_certificate);assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap().unwrap().owner,next_remote.id);
            let third_certificate=third.certificate();let third_remote=session.acquire_public_checkpoint_after(Uuid::from_u128(976),third_certificate.clone(),third_job.budget,Some(&received),|path|source.retained_paged_checkpoint_public_page(third_certificate.guild_id(),third_certificate.layout(),third_job.id,third_certificate.hash()?,&path)).unwrap();
            let third_received=session.promote_acquired_checkpoint_after(&third_remote,Some(&received)).unwrap();assert_eq!(third_received.certificate(),third_certificate);drop(third_received);

            drop(received);drop(first_received);drop(session);
            receiver.control.cancel_checkpoint_acquisition(&first_remote).unwrap();while receiver.control.release_checkpoint_acquisition_step(&first_remote).unwrap(){}
            receiver.control.$cancel(first_remote.id).unwrap();while receiver.control.$release(first_remote.id).unwrap(){}
            receiver.control.cancel_checkpoint_acquisition(&next_remote).unwrap();while receiver.control.release_checkpoint_acquisition_step(&next_remote).unwrap(){}
            receiver.control.$cancel(next_remote.id).unwrap();while receiver.control.$release(next_remote.id).unwrap(){}
            let middle_owner=next_remote.id;
            let next_remote=third_remote;let next_certificate=third_certificate;

            drop(receiver);let receiver=Node::open(receiver_temp.path(),seed).unwrap();let session=receiver.retained_checkpoint_restore().unwrap();
            let selected=receiver.control.checkpoint_recovery_tip().unwrap();
            let rebuild_budget=resources::rebuild_budget(&receiver);resources::released(&receiver);
            assert!(session.rebuild_checkpoint_recovery_proof(Work::default()).is_err());
            assert!(session.rebuild_checkpoint_recovery_proof(Work{bytes:512<<20,..rebuild_budget}).is_err());
            for _ in 0..64 { if !receiver.reclaim_abandoned_catalog_scratch().unwrap() { break; } }
            assert!(!receiver.reclaim_abandoned_catalog_scratch().unwrap());
            let scratch_before=receiver.catalog_scratch_pool_usage().unwrap();
            // Setup and its first guard fit, but complete scratch admission does
            // not. The old single lookup allowance would create a stack lease
            // before later source-budget rejection, leaving new physical debt.
            assert!(session.rebuild_checkpoint_recovery_proof(Work{bytes:128<<20,..rebuild_budget}).is_err());
            assert_eq!(receiver.catalog_scratch_pool_usage().unwrap(),scratch_before);
            resources::released(&receiver);
            assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap(),selected);
            let names=["catalog-checkpoint-ancestry-link-v1","catalog-checkpoint-ancestry-link-guard-v1"];
            let links=names.map(|kind|receiver.control.get_record_bounded(kind,middle_owner.as_bytes(),1024).unwrap().unwrap());
            for kind in names{receiver.control.delete_record(kind,middle_owner.as_bytes()).unwrap();}
            assert!(session.rebuild_checkpoint_recovery_proof(rebuild_budget).is_err());assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap(),selected);
            for (kind,bytes) in names.into_iter().zip(links){receiver.control.put_record(kind,middle_owner.as_bytes(),&bytes).unwrap();}
            resources::released(&receiver);
            eprintln!("SCRATCH_PLAN_PHASE rebuilding complete chain");
            let rebuilt=session.rebuild_checkpoint_proof_with_observer(rebuild_budget,|_| {
                resources::scratch_held(&receiver);
                let usage=receiver.checkpoint_acquisition_work_usage()?.unwrap();
                assert_eq!(usage.reserved,rebuild_budget);assert_eq!(usage.open_jobs,1);
                assert!(!receiver.reclaim_abandoned_checkpoint_recovery_work()?);
                assert!(receiver.control.begin_checkpoint_recovery_work(selected.unwrap(),rebuild_budget).is_err());
                Ok(())
            }).unwrap();resources::released(&receiver);rebuilt.verify().unwrap();assert_eq!(rebuilt.certificate(),next_certificate);
            assert_eq!(receiver.control.checkpoint_recovery_tip().unwrap(),selected);
            assert_eq!(receiver.control.checkpoint_acquisition_state(&first_remote).unwrap(),mb_store::CatalogCheckpointAcquisitionState::Cancelled);

            let mut revisions=mb_core::CatalogCheckpointAuthorityReader::new_with_budget(scope,next_certificate.authority(),next_job.budget).unwrap();let mut selected=None;
            while let Some(record)=revisions.next_record(&mut |page|receiver.control.catalog_page(scope,CatalogSection::Checkpoint,page)).unwrap() {if let R::PagedRevision(signed)=record {selected=Some(signed.value);}}
            eprintln!("SCRATCH_PLAN_PHASE chain rebuilt; restoring selected snapshot");
            let revision=selected.unwrap();let target=receiver_temp.path().join("second-generation-restore");
            let request=RetainedSnapshotRestore {layout:mb_core::PagedCheckpointLayout::$layout,owner:next_remote.id,guild_id:next_certificate.guild_id(),snapshot:SnapshotInfo {protected_root_id:revision.protected_root_id,revision_id:revision.revision_id,sequence:revision.sequence,checkpoint_generation:next_certificate.generation(),checkpoint_hash:next_certificate.hash().unwrap()},budget:next_job.budget};
            session.restore(&request,&target,|entry,role| {
                if role!=1 {return Ok(None)}
                Ok(Some(source.retained_checkpoint_shard(request.guild_id,request.layout,third_job.id,request.snapshot.checkpoint_hash,entry.retained.group.id,role)?))
            }).unwrap();verify_git_restore(&receiver,&target,revision.protected_root_id);
            assert!(receiver.control.checkpoint_head_identity(&request.guild_id).unwrap().is_none());
            let mut cancelled=false;
            assert!(session.rebuild_checkpoint_proof_with_observer(rebuild_budget,|generation|{if generation==1{receiver.control.cancel_checkpoint_recovery_tip(&next_remote)?;cancelled=true;}Ok(())}).is_err());assert!(cancelled);resources::released(&receiver);
            assert!(session.rebuild_checkpoint_recovery_proof(rebuild_budget).is_err());
            assert!(receiver.control.checkpoint_recovery_tip().unwrap().is_none());assert!(session.promote_acquired_checkpoint_after(&next_remote,Some(&rebuilt)).is_err());
            verify_git_restore(&receiver,&target,revision.protected_root_id);drop(original_temp);
        }
    };
}
cases!(
    individual_checkpoint_chain_uses_original_history_prefix_and_resumes_after_tip_faults,
    git_owner_proof,
    Individual,
    Individual,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
cases!(
    directory_checkpoint_chain_uses_original_history_prefix_and_resumes_after_tip_faults,
    git_directory_proof,
    Directory,
    Directory,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);
