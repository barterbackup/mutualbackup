use super::*;
use crate::database::catalog::checkpoint_acquisition::{
    CatalogCheckpointAcquisitionState as State, CatalogPublicCheckpoint as Certificate,
};
fn individual(
    f: &mut super::super::super::checkpoint_validation::tests::Fixture,
    h: &History,
) -> CatalogQuorumPagedCheckpointIndex {
    super::paged_checkpoint_retention::paged_owner_proof(f, h, None)
}
fn directory(
    f: &mut super::super::super::checkpoint_validation::tests::Fixture,
    h: &History,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    super::checkpoint_directory_retention::proof(f, h, budget())
}

fn quota(s: &ControlStore) {
    s.configure_catalog_storage_quota(CatalogStorageQuota {
        page_bytes: 128 << 20,
        pages: 2048,
        open_reservations: 64,
    })
    .unwrap();
}
fn tree(
    s: &ControlStore,
    job: &CatalogCheckpointAcquisition,
    intent: CatalogIntent,
    root: CatalogPageRef,
    page: CatalogPageRef,
) {
    let bytes = s.catalog_page(intent.scope, intent.section, page).unwrap();
    if let mb_core::CatalogPageContents::Index(children) = page
        .verify_page(intent.scope, intent.section, &bytes)
        .unwrap()
    {
        for child in children {
            tree(s, job, intent, root, child);
        }
    }
    s.stage_checkpoint_acquisition_page(job, intent, root, page, &bytes)
        .unwrap();
}

macro_rules! cases{
    ($test:ident,$proof:path,$stage:path,$variant:ident,$retain:ident)=>{
        #[test]
        fn $test(){
            for action in ["ABORT","IGNORE"]{
                let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);
                let temp=tempfile::tempdir().unwrap();let s=ControlStore::open(temp.path().join("control.db"),&history.keys[0]).unwrap();
                $stage(&s,&fixture,&proof,1000);
                let cert=Certificate::$variant(proof.certificate().clone());let id=Uuid::from_u128(880);
                assert!(s.begin_checkpoint_acquisition(id,cert.clone(),proof.trust().clone(),budget()).is_err());quota(&s);
                let job=s.begin_checkpoint_acquisition(id,cert.clone(),proof.trust().clone(),budget()).unwrap();
                assert!(s.finish_checkpoint_acquisition(&job).is_err());
                let (scope,section,root)=cert.initial_roots()[0];
                let original_bytes=s.catalog_page(scope,section,root).unwrap();
                assert!(s.reserve_checkpoint_acquisition_root(&job,scope,CatalogSection::FileMetadata,root).is_err());
                let name=format!("catalog-checkpoint-acquisition-root-v1/{}",id.simple());
                let fault=if action=="ABORT"{",'test'"}else{""};
                for phase in ["root","counter","guard"]{
                    let condition=match phase{"root"=>format!("BEFORE INSERT ON protocol_records WHEN NEW.kind='{name}'"),"counter"=>"BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-checkpoint-acquisition-v1'".into(),_=>"BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-checkpoint-acquisition-guard-v1'".into()};
                    s.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_acquisition {condition} BEGIN SELECT RAISE({action}{fault}); END")).unwrap();
                    assert!(s.reserve_checkpoint_acquisition_root(&job,scope,section,root).is_err());
                    assert!(s.next_record_bounded(&name,None,32,1024).unwrap().is_none());
                    assert_eq!(s.catalog_storage_usage().unwrap().unwrap().open_reservations,0);
                    s.connection.execute_batch("DROP TRIGGER refuse_acquisition").unwrap();
                }
                let intent=s.reserve_checkpoint_acquisition_root(&job,scope,section,root).unwrap();tree(&s,&job,intent,root,root);
                let saved=s.get_record("catalog-checkpoint-acquisition-v1",id.as_bytes()).unwrap().unwrap();
                s.put_record("catalog-checkpoint-acquisition-v1",id.as_bytes(),b"damaged").unwrap();assert!(s.checkpoint_acquisition_state(&job).is_err());
                s.put_record("catalog-checkpoint-acquisition-v1",id.as_bytes(),&saved).unwrap();
                if let Some(mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(reference))=proof.index().next_revision(None).unwrap(){
                    let bytes=s.catalog_page(scope,section,reference.body).unwrap();
                    assert!(s.stage_checkpoint_acquisition_page(&job,intent,root,reference.body,&bytes).is_err());
                    assert_eq!(crate::database::catalog::read_intent(&s.connection,intent).unwrap().owned_pages,root.page_occurrences);
                }
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_root_complete BEFORE UPDATE ON protocol_records WHEN NEW.kind='{name}' BEGIN SELECT RAISE({action}{fault}); END")).unwrap();
                assert!(s.complete_checkpoint_acquisition_root(&job,intent,root).is_err());
                assert_eq!(s.catalog_intent_state(intent).unwrap(),CatalogIntentState::Building);
                s.connection.execute_batch("DROP TRIGGER refuse_root_complete").unwrap();s.complete_checkpoint_acquisition_root(&job,intent,root).unwrap();
                assert_eq!(s.checkpoint_acquisition_state(&job).unwrap(),State::Building);assert!(s.finish_checkpoint_acquisition(&job).is_err());
                s.$retain(id,&proof,||Ok(proof.trust().clone())).unwrap();s.finish_checkpoint_acquisition(&job).unwrap();
                assert_eq!(s.checkpoint_acquisition_state(&job).unwrap(),State::Complete);
                s.cancel_checkpoint_acquisition(&job).unwrap();assert!(s.stage_checkpoint_acquisition_page(&job,intent,root,root,&s.catalog_page(scope,section,root).unwrap()).is_err());
                assert!(s.begin_checkpoint_acquisition(id,cert.clone(),proof.trust().clone(),budget()).is_err());
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER refuse_root_delete BEFORE DELETE ON protocol_records WHEN OLD.kind='{name}' BEGIN SELECT RAISE({action}{fault}); END")).unwrap();
                while s.catalog_intent_state(intent).unwrap()!=CatalogIntentState::Cancelled{s.release_checkpoint_acquisition_step(&job).unwrap();}
                while crate::database::catalog::read_intent(&s.connection,intent).unwrap().owned_pages!=0{s.release_checkpoint_acquisition_step(&job).unwrap();}
                assert!(s.release_checkpoint_acquisition_step(&job).is_err());
                s.connection.execute_batch("DROP TRIGGER refuse_root_delete").unwrap();while s.release_checkpoint_acquisition_step(&job).unwrap(){}
                assert_eq!(s.catalog_page(scope,section,root).unwrap(),original_bytes);
            }
        }
    }
}
cases!(
    individual_public_acquisition_reservations_publication_and_retirement_are_atomic,
    individual,
    super::paged_checkpoint_retention::stage_paged_owner,
    Individual,
    retain_catalog_paged_checkpoint
);
cases!(
    directory_public_acquisition_reservations_publication_and_retirement_are_atomic,
    directory,
    super::checkpoint_directory_retention::stage,
    Directory,
    retain_catalog_paged_checkpoint_directory
);

macro_rules! archive_cases {
    ($test:ident,$proof:path,$stage:path,$variant:ident,$retain:ident,$cancel:ident,$release:ident)=>{
        #[test]
        fn $test(){
            for action in ["ABORT","IGNORE"] {
                let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);
                let temp=tempfile::tempdir().unwrap();let path=temp.path().join("control.db");
                let s=ControlStore::open(&path,&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);
                let cert=Certificate::$variant(proof.certificate().clone());let id=Uuid::from_u128(882);
                assert!(s.begin_checkpoint_ancestry_archive(id).is_err());
                s.$retain(id,&proof,||Ok(proof.trust().clone())).unwrap();
                let fault=if action=="ABORT"{",'test'"}else{""};
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER archive_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='catalog-checkpoint-ancestry-guard-v1' BEGIN SELECT RAISE({action}{fault}); END")).unwrap();
                assert!(s.begin_checkpoint_ancestry_archive(id).is_err());
                assert!(s.get_record("catalog-checkpoint-ancestry-v1",id.as_bytes()).unwrap().is_none());
                s.connection.execute_batch("DROP TRIGGER archive_fault").unwrap();s.begin_checkpoint_ancestry_archive(id).unwrap();
                assert!(s.checkpoint_ancestry_certificate(id).unwrap().is_none());
                for kind in ["catalog-checkpoint-ancestry-guard-v1".to_owned(),format!("catalog-checkpoint-ancestry-dependency-v1/{}",id.simple())] {
                    let verb=if kind.contains("dependency"){"INSERT"}else{"UPDATE"};
                    let before=s.get_record("catalog-checkpoint-ancestry-v1",id.as_bytes()).unwrap();
                    s.connection.execute_batch(&format!("CREATE TEMP TRIGGER archive_fault BEFORE {verb} ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{fault}); END")).unwrap();
                    assert!(s.advance_checkpoint_ancestry_archive(id).is_err());
                    assert_eq!(s.get_record("catalog-checkpoint-ancestry-v1",id.as_bytes()).unwrap(),before);
                    s.connection.execute_batch("DROP TRIGGER archive_fault").unwrap();
                }
                assert!(s.advance_checkpoint_ancestry_archive(id).unwrap());drop(s);
                let s=ControlStore::open(&path,&history.keys[0]).unwrap();s.begin_checkpoint_ancestry_archive(id).unwrap();
                while s.advance_checkpoint_ancestry_archive(id).unwrap(){}
                assert_eq!(s.checkpoint_ancestry_certificate(id).unwrap(),Some(cert.clone()));
                let source=s.checkpoint_recovery_source(id).unwrap().unwrap();assert!(source.archived);assert_eq!(source.certificate,cert);
                s.check_checkpoint_recovery_source(&source,proof.trust()).unwrap();
                s.with_record_transaction::<_,CatalogStoreError>(||{assert_eq!(s.checkpoint_recovery_source(id)?,Some(source.clone()));s.check_checkpoint_recovery_source(&source,proof.trust())}).unwrap();
                let mut wrong=source.clone();wrong.trust_hash[0]^=1;assert!(s.check_checkpoint_recovery_source(&wrong,proof.trust()).is_err());

                let guard=s.get_record("catalog-checkpoint-ancestry-guard-v1",id.as_bytes()).unwrap().unwrap();
                s.delete_record("catalog-checkpoint-ancestry-guard-v1",id.as_bytes()).unwrap();assert!(s.checkpoint_ancestry_certificate(id).is_err());
                s.put_record("catalog-checkpoint-ancestry-guard-v1",id.as_bytes(),&guard).unwrap();
                s.$cancel(id).unwrap();while s.$release(id).unwrap(){}
                drop(s);let s=ControlStore::open(&path,&history.keys[0]).unwrap();
                assert_eq!(s.checkpoint_ancestry_certificate(id).unwrap(),Some(cert));
                assert_eq!(s.checkpoint_recovery_source(id).unwrap(),Some(source.clone()));s.check_checkpoint_recovery_source(&source,proof.trust()).unwrap();
                for (scope,section,root) in Certificate::$variant(proof.certificate().clone()).initial_roots(){
                    let dep=crate::database::catalog::retention_journal::Dependency{scope,section,root};
                    let name=format!("catalog-checkpoint-ancestry-dependency-v1/{}",id.simple());
                    assert_eq!(s.get_record(&name,&root.hash).unwrap(),Some(mb_core::canonical_bytes(&dep).unwrap()));
                    let mut pin=[0;17];pin[0]=7;pin[1..].copy_from_slice(id.as_bytes());
                    assert_eq!(s.get_record(&crate::database::catalog::pins(root.hash),&pin).unwrap(),Some(vec![]));
                    let expected=s.catalog_page(scope,section,root).unwrap();
                    let path=mb_core::CatalogPagePath{scope,section,pages:vec![root]};
                    assert_eq!(s.checkpoint_ancestry_page(id,&path).unwrap(),Some(expected));
                    let mut private=path;private.section=CatalogSection::FileMetadata;assert!(s.checkpoint_ancestry_page(id,&private).is_err());
                }
                s.cancel_checkpoint_ancestry_archive(id).unwrap();
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER archive_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-checkpoint-ancestry-guard-v1' BEGIN SELECT RAISE({action}{fault}); END")).unwrap();
                assert!(s.release_checkpoint_ancestry_archive_step(id).is_err());
                s.connection.execute_batch("DROP TRIGGER archive_fault").unwrap();
                while s.release_checkpoint_ancestry_archive_step(id).unwrap(){}
                assert!(s.checkpoint_ancestry_certificate(id).unwrap().is_none());assert!(s.begin_checkpoint_ancestry_archive(id).is_err());
            }
        }
    }
}
archive_cases!(
    individual_ancestry_archive_resumes_and_outlives_original_owner,
    individual,
    super::paged_checkpoint_retention::stage_paged_owner,
    Individual,
    retain_catalog_paged_checkpoint,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
archive_cases!(
    directory_ancestry_archive_resumes_and_outlives_original_owner,
    directory,
    super::checkpoint_directory_retention::stage,
    Directory,
    retain_catalog_paged_checkpoint_directory,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);
