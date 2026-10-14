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
