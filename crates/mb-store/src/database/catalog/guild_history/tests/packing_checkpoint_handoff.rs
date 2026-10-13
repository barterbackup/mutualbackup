use super::paged_checkpoint_revision::{private_checkpoint, publish_private};
use super::*;
use mb_core::CatalogCheckpointRevisionKey;

fn loan(base: CatalogPackingAuthorityBase) -> CatalogPackingSourceRetention {
    CatalogPackingSourceRetention {
        id: Uuid::new_v4(),
        base,
        budget: budget(),
    }
}

fn borrow(control: &ControlStore, source: CatalogPackingSourceRetention, bundle: &CatalogBundle) {
    control
        .begin_catalog_packing_source_retention(source, |_| Ok::<_, CatalogStoreError>(()))
        .unwrap();
    let signed = mb_core::PagedUserRevision::decode_signed(&bundle.descriptor).unwrap();
    control
        .retain_catalog_packing_source_checked(
            source,
            &signed,
            (|_| Ok::<_, CatalogStoreError>(()), |_, _| Ok(())),
        )
        .unwrap();
}

fn set_parent(
    control: &ControlStore,
    guild: [u8; 32],
    generation: u64,
    hash: [u8; 32],
    bytes: Vec<u8>,
) {
    control.connection.execute("INSERT INTO checkpoint_heads(guild_id, generation, checkpoint_hash, checkpoint_bytes) VALUES (?1, ?2, ?3, ?4)", params![guild, generation, hash, bytes]).unwrap();
}

macro_rules! cases {
    ($success:ident, $negative:ident, $faults:ident, $guards:ident, $proof:path, $stage:path, $retain:ident, $handoff:ident, $cancel:ident, $release:ident) => {
        #[test]
        fn $success() {
            let tmp = tempfile::tempdir().unwrap(); let path = tmp.path().join("control.db");
            let control = ControlStore::open_with_key(&path, &[7; 32]).unwrap();
            let (mut fixture, history, bundle, bootstrap) = private_checkpoint(&control);
            let anchor = Uuid::new_v4(); publish_private(&control, &fixture, &bundle, &bootstrap, anchor);
            let previous = $proof(&mut fixture, &history, None);
            let base = CatalogPackingAuthorityBase { guild_id: previous.trust().guild_id, generation: previous.certificate().checkpoint.generation, checkpoint_hash: previous.certificate().hash().unwrap(), membership_epoch: Some(previous.trust().authority.membership_epoch) };
            let proof = $proof(&mut fixture, &history, Some(&previous));
            set_parent(&control, base.guild_id, base.generation, base.checkpoint_hash, canonical_bytes(previous.certificate()).unwrap());
            $stage(&control, &fixture, &proof, 1000);
            let sources = [loan(base), loan(base)]; let ids = [Uuid::from_u128(1), Uuid::from_u128(2)];
            let key = CatalogCheckpointRevisionKey::from(&fixture.paged().value);
            let snapshot = control.paged_revision_catalog(bundle.id).unwrap().unwrap();
            for (source,id) in sources.into_iter().zip(ids) {
                borrow(&control, source, &bundle);
                control.$retain(id, &proof, || Ok(proof.trust().clone())).unwrap();
                control.cancel_catalog_packing_source_retention(source).unwrap();
                assert_eq!(control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Ok::<_, CatalogStoreError>(())).unwrap(), snapshot);
                assert_eq!(control.catalog_packing_source(source,bundle.id).unwrap(),None);
                assert_eq!(control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Ok::<_, CatalogStoreError>(())).unwrap(), snapshot);
                assert!(!control.release_catalog_packing_source(source).unwrap());
            }
            assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
            drop(control);
            let control = ControlStore::open_existing_with_key(&path, &[7; 32]).unwrap();
            assert_eq!(control.catalog_paged_checkpoint_revision(ids[0],bundle.id).unwrap(),Some(snapshot.clone()));
            assert_eq!(snapshot.bootstrap,Some(bootstrap));
            control.$cancel(ids[0]).unwrap(); assert!(control.$release(ids[0]).unwrap());
            assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
            control.$cancel(ids[1]).unwrap(); assert!(control.$release(ids[1]).unwrap());
            control.cancel_paged_revision_catalog(bundle.id).unwrap();
            assert!(control.release_paged_revision_data_source(bundle.id).unwrap());
            assert!(!control.paged_data_anchor_is_pinned(anchor).unwrap());
        }

        #[test]
        fn $negative() {
            let tmp = tempfile::tempdir().unwrap(); let control = ControlStore::open_with_key(tmp.path().join("control.db"), &[7; 32]).unwrap();
            let (mut fixture,history,bundle,bootstrap)=private_checkpoint(&control); publish_private(&control,&fixture,&bundle,&bootstrap,Uuid::new_v4());
            let previous=$proof(&mut fixture,&history,None);
            let base=CatalogPackingAuthorityBase {guild_id:previous.trust().guild_id,generation:1,checkpoint_hash:previous.certificate().hash().unwrap(),membership_epoch:Some(previous.trust().authority.membership_epoch)};
            let proof=$proof(&mut fixture,&history,Some(&previous));set_parent(&control,base.guild_id,1,base.checkpoint_hash,canonical_bytes(previous.certificate()).unwrap());$stage(&control,&fixture,&proof,1000);
            let id=Uuid::from_u128(1);control.$retain(id,&proof,|| Ok(proof.trust().clone())).unwrap();
            let key=CatalogCheckpointRevisionKey::from(&fixture.paged().value);let source=loan(base);borrow(&control,source,&bundle);
            let no_reads=|_: &PagedCatalogSnapshot| -> Result<(),CatalogStoreError> {panic!("reject an open source owner before private reads")};
            assert!(control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()),no_reads).is_err());
            control.cancel_catalog_packing_source_retention(source).unwrap();
            for dimension in 0..3 {
                let mut wrong=base; match dimension {0=>wrong.guild_id=[201;32],1=>wrong.checkpoint_hash=[202;32],_=>wrong.generation+=1}
                let wrong=loan(wrong);
                if dimension == 0 {
                    control.begin_catalog_packing_source_retention(wrong, |_| Ok::<_,CatalogStoreError>(())).unwrap();
                } else { borrow(&control,wrong,&bundle); }
                control.cancel_catalog_packing_source_retention(wrong).unwrap();
                assert!(control.$handoff(wrong,id,&proof,key,|| Ok(proof.trust().clone()), |_| -> Result<(),CatalogStoreError> {panic!("reject another base before private reads")}).is_err());
            }
            let empty=loan(base);control.begin_catalog_packing_source_retention(empty, |_| Ok::<_,CatalogStoreError>(())).unwrap();control.cancel_catalog_packing_source_retention(empty).unwrap();
            assert!(control.$handoff(empty,id,&proof,key,|| Ok(proof.trust().clone()), |_| -> Result<(),CatalogStoreError> {panic!("absent source is not a new handoff")}).is_err());
            assert!(control.catalog_paged_checkpoint_revision(id,bundle.id).unwrap().is_none());
            assert!(control.catalog_packing_source(source,bundle.id).unwrap().is_some());
        }

        #[test]
        fn $faults() {
            let tmp=tempfile::tempdir().unwrap();let control=ControlStore::open_with_key(tmp.path().join("control.db"), &[7;32]).unwrap();
            let (mut fixture,history,bundle,bootstrap)=private_checkpoint(&control);publish_private(&control,&fixture,&bundle,&bootstrap,Uuid::new_v4());
            let previous=$proof(&mut fixture,&history,None);let base=CatalogPackingAuthorityBase {guild_id:previous.trust().guild_id,generation:1,checkpoint_hash:previous.certificate().hash().unwrap(),membership_epoch:Some(previous.trust().authority.membership_epoch)};
            let proof=$proof(&mut fixture,&history,Some(&previous));set_parent(&control,base.guild_id,1,base.checkpoint_hash,canonical_bytes(previous.certificate()).unwrap());$stage(&control,&fixture,&proof,1000);
            let key=CatalogCheckpointRevisionKey::from(&fixture.paged().value);
            for fault in ["ABORT","IGNORE"] {
                for boundary in 0..7 {
                    let source=loan(base);borrow(&control,source,&bundle);control.cancel_catalog_packing_source_retention(source).unwrap();
                    let id=Uuid::new_v4();control.$retain(id,&proof,|| Ok(proof.trust().clone())).unwrap();
                    let before=control.catalog_packing_source_retention(source.id).unwrap();
                    let (operation,kind)=match boundary {
                        0=>("INSERT",format!("catalog-checkpoint-private-revision-v1/{}",id.simple())),
                        1=>("INSERT",format!("catalog-private-revision-checkpoint-v1/{}",bundle.id.simple())),
                        2=>("INSERT","catalog-checkpoint-private-work-v1".into()),
                        3=>("DELETE",format!("catalog-packing-source-revision-v1/{}",source.id.simple())),
                        4=>("DELETE",format!("catalog-revision-packing-owner-v1/{}",bundle.id.simple())),
                        5=>("UPDATE","catalog-packing-source-owner-count-v1".into()),
                        _=>("UPDATE","catalog-packing-source-retention-v1".into()),
                    };
                    let row=if operation=="DELETE" {"OLD"} else {"NEW"};let expression=if fault=="ABORT" {"RAISE(ABORT, 'injected')"} else {"RAISE(IGNORE)"};
                    control.connection.execute_batch(&format!("CREATE TEMP TRIGGER handoff_fault BEFORE {operation} ON protocol_records WHEN {row}.kind = '{kind}' BEGIN SELECT {expression}; END;")).unwrap();
                    assert!(control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Ok::<_,CatalogStoreError>(())).is_err(),"{boundary} {fault}");
                    assert_eq!(control.catalog_packing_source_retention(source.id).unwrap(),before);
                    assert!(control.catalog_packing_source(source,bundle.id).unwrap().is_some());
                    assert!(control.catalog_paged_checkpoint_revision(id,bundle.id).unwrap().is_none());
                    assert!(control.cancel_paged_revision_catalog(bundle.id).is_err());
                    control.connection.execute_batch("DROP TRIGGER handoff_fault").unwrap();
                    control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Ok::<_,CatalogStoreError>(())).unwrap();
                }
            }
        }

        #[test]
        fn $guards() {
            let tmp=tempfile::tempdir().unwrap();let control=ControlStore::open_with_key(tmp.path().join("control.db"), &[7;32]).unwrap();
            let (mut fixture,history,bundle,bootstrap)=private_checkpoint(&control);publish_private(&control,&fixture,&bundle,&bootstrap,Uuid::new_v4());
            let previous=$proof(&mut fixture,&history,None);let base=CatalogPackingAuthorityBase {guild_id:previous.trust().guild_id,generation:1,checkpoint_hash:previous.certificate().hash().unwrap(),membership_epoch:Some(previous.trust().authority.membership_epoch)};
            let proof=$proof(&mut fixture,&history,Some(&previous));set_parent(&control,base.guild_id,1,base.checkpoint_hash,canonical_bytes(previous.certificate()).unwrap());$stage(&control,&fixture,&proof,1000);
            let source=loan(base);borrow(&control,source,&bundle);control.cancel_catalog_packing_source_retention(source).unwrap();let id=Uuid::from_u128(1);control.$retain(id,&proof,|| Ok(proof.trust().clone())).unwrap();let key=CatalogCheckpointRevisionKey::from(&fixture.paged().value);
            assert!(control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Err::<(),_>(CatalogStoreError::from(DatabaseError::Integrity))).is_err());
            let kind=format!("catalog-checkpoint-private-revision-v1/{}",id.simple());
            control.connection.execute_batch(&format!("CREATE TEMP TRIGGER late_handoff_head AFTER INSERT ON protocol_records WHEN NEW.kind = '{kind}' BEGIN UPDATE checkpoint_heads SET checkpoint_hash = X'{}'; END",hex::encode([203;32]))).unwrap();
            assert!(control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Ok::<_,CatalogStoreError>(())).is_err());
            assert_eq!(control.checkpoint_head_identity(&base.guild_id).unwrap(),Some((1,base.checkpoint_hash)));
            assert!(control.catalog_packing_source(source,bundle.id).unwrap().is_some());assert!(control.catalog_paged_checkpoint_revision(id,bundle.id).unwrap().is_none());
            control.connection.execute_batch("DROP TRIGGER late_handoff_head").unwrap();
            control.$handoff(source,id,&proof,key,|| Ok(proof.trust().clone()), |_| Ok::<_,CatalogStoreError>(())).unwrap();
        }
    };
}

fn directory_proof(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
    previous: Option<&CatalogQuorumPagedCheckpointDirectoryIndex>,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    super::checkpoint_directory_retention::successor(fixture, history, previous, budget())
}

cases!(
    packing_handoff_individual_preserves_shared_custody_and_reopens,
    packing_handoff_individual_rejects_open_missing_and_wrong_base_sources,
    packing_handoff_individual_rolls_back_every_transfer_boundary,
    packing_handoff_individual_rolls_back_private_and_late_head_failures,
    super::paged_checkpoint_retention::paged_owner_proof,
    super::paged_checkpoint_retention::stage_paged_owner,
    retain_catalog_paged_checkpoint,
    handoff_catalog_packing_source_to_paged_checkpoint_checked,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
cases!(
    packing_handoff_directory_preserves_shared_custody_and_reopens,
    packing_handoff_directory_rejects_open_missing_and_wrong_base_sources,
    packing_handoff_directory_rolls_back_every_transfer_boundary,
    packing_handoff_directory_rolls_back_private_and_late_head_failures,
    directory_proof,
    super::checkpoint_directory_retention::stage,
    retain_catalog_paged_checkpoint_directory,
    handoff_catalog_packing_source_to_paged_checkpoint_directory_checked,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);
