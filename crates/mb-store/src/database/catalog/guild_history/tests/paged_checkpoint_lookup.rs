use super::*;
use crate::database::catalog::checkpoint_body::Header;
use crate::database::catalog::paged_checkpoint_lookup as lookup;
use mb_core::CatalogCheckpointAuthorityRecord as R;

fn individual(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
) -> CatalogQuorumPagedCheckpointIndex {
    super::paged_checkpoint_retention::paged_owner_proof(fixture, history, None)
}
fn directory(
    fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
    history: &History,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    super::checkpoint_directory_retention::proof(fixture, history, budget())
}

macro_rules! cases {
    ($roundtrip:ident,$damaged:ident,$faults:ident,$proof:ident,$stage:path,$retain:ident,$build:ident,$point:ident,$next:ident,$group:ident,$cancel:ident,$release:ident)=>{
        #[test]
        fn $roundtrip(){
            let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);
            let tmp=tempfile::tempdir().unwrap();let path=tmp.path().join("control.db");
            let s=ControlStore::open(&path,&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);
            let owner=s.$retain(Uuid::from_u128(1),&proof,||Ok(proof.trust().clone())).unwrap();
            let second=s.$retain(Uuid::from_u128(2),&proof,||Ok(proof.trust().clone())).unwrap();
            let key=fixture.records.iter().find_map(R::revision_key).unwrap();
            assert!(s.$point(owner,key.revision_id,budget()).is_err());
            s.$build(owner.id,&proof,||Ok(proof.trust().clone())).unwrap();
            s.$build(second.id,&proof,||Ok(proof.trust().clone())).unwrap();
            let expected=proof.index().revision(key).unwrap().unwrap();
            assert_eq!(s.$point(owner,key.revision_id,budget()).unwrap(),Some(expected.clone()));
            assert_eq!(s.$point(owner,Uuid::from_u128(999999),budget()).unwrap(),None);
            let mut after=None;let mut observed=0;
            while let Some(record)=s.$next(owner,after,budget()).unwrap(){
                let key=record.revision_key().unwrap();assert!(after.is_none_or(|last|last<key));
                after=Some(key);observed+=1;
            }
            assert_eq!(observed,owner.checkpoint.authority_root.summary.revisions);
            let row=proof.index().index().next_group(None).unwrap().unwrap();let group=row.group.range.group_id;
            let expected_group=proof.index().index().read_group(group,|page|s.catalog_page(CatalogScope::Guild{guild_id:proof.trust().guild_id},CatalogSection::Coding,page)).unwrap().unwrap();
            assert_eq!(s.$group(owner,group,budget()).unwrap(),Some(expected_group.clone()));
            for limit in [Work{bytes:0,..budget()},Work{page_occurrences:0,..budget()},Work{records:0,..budget()}]{
                assert!(s.$point(owner,key.revision_id,limit).is_err());assert!(s.$group(owner,group,limit).is_err());
            }
            assert!(s.checkpoint_head_identity(&proof.trust().guild_id).unwrap().is_none());
            s.$cancel(owner.id).unwrap();assert!(s.$point(owner,key.revision_id,budget()).is_err());
            while s.$release(owner.id).unwrap(){}
            assert_eq!(s.$point(second,key.revision_id,budget()).unwrap(),Some(expected.clone()));
            drop(s);let s=ControlStore::open(&path,&history.keys[0]).unwrap();
            assert_eq!(s.$point(second,key.revision_id,budget()).unwrap(),Some(expected));
            assert_eq!(s.$group(second,group,budget()).unwrap(),Some(expected_group));
            let changes=s.connection.total_changes();let _=s.$next(second,None,budget()).unwrap();assert_eq!(s.connection.total_changes(),changes);
        }
        #[test]
        fn $damaged(){
            let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);
            let tmp=tempfile::tempdir().unwrap();let s=ControlStore::open(tmp.path().join("control.db"),&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);
            let owner=s.$retain(Uuid::from_u128(1),&proof,||Ok(proof.trust().clone())).unwrap();s.$build(owner.id,&proof,||Ok(proof.trust().clone())).unwrap();
            let key=fixture.records.iter().find_map(R::revision_key).unwrap();
            let name=lookup::kind(owner.id,"revision");let bytes=s.get_record(&name,key.revision_id.as_bytes()).unwrap().unwrap();
            let mut row:lookup::Revision=decode_canonical(&bytes).unwrap();row.frame.offset+=1;
            s.put_record(&name,key.revision_id.as_bytes(),&canonical_bytes(&row).unwrap()).unwrap();
            assert!(s.$point(owner,key.revision_id,budget()).is_err());
            s.put_record(&name,key.revision_id.as_bytes(),&bytes).unwrap();
            s.put_record(&name,key.revision_id.as_bytes(),&[0;1025]).unwrap();assert!(s.$next(owner,None,budget()).is_err());
            s.put_record(&name,key.revision_id.as_bytes(),&bytes).unwrap();
            let group=proof.index().index().next_group(None).unwrap().unwrap().group.range.group_id;
            let name=lookup::kind(owner.id,"group");let bytes=s.get_record(&name,&group).unwrap().unwrap();let mut row:lookup::Group=decode_canonical(&bytes).unwrap();
            row.location.page.hash=[241;32];s.put_record(&name,&group,&canonical_bytes(&row).unwrap()).unwrap();assert!(s.$group(owner,group,budget()).is_err());
            s.put_record(&name,&group,&bytes).unwrap();row=decode_canonical(&bytes).unwrap();row.forest.offset+=1;s.put_record(&name,&group,&canonical_bytes(&row).unwrap()).unwrap();assert!(s.$group(owner,group,budget()).is_err());
        }
        #[test]
        fn $faults(){
            for action in ["ABORT","IGNORE"]{
                let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);let tmp=tempfile::tempdir().unwrap();let s=ControlStore::open(tmp.path().join("control.db"),&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);
                let owner=s.$retain(Uuid::from_u128(1),&proof,||Ok(proof.trust().clone())).unwrap();
                let name=lookup::kind(owner.id,"ordered");s.connection.execute_batch(&format!("CREATE TEMP TRIGGER fail_lookup BEFORE INSERT ON protocol_records WHEN NEW.kind='{name}' BEGIN SELECT RAISE({action}{}); END",if action=="ABORT"{",'test'"}else{""})).unwrap();
                assert!(s.$build(owner.id,&proof,||Ok(proof.trust().clone())).is_err());let key=fixture.records.iter().find_map(R::revision_key).unwrap();assert!(s.$point(owner,key.revision_id,budget()).is_err());
                assert!(s.next_record_bounded(&lookup::kind(owner.id,"revision"),None,16,1024).unwrap().is_none());s.connection.execute_batch("DROP TRIGGER fail_lookup").unwrap();s.$build(owner.id,&proof,||Ok(proof.trust().clone())).unwrap();
                let before=s.$point(owner,key.revision_id,budget()).unwrap();s.$cancel(owner.id).unwrap();
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER fail_lookup_delete BEFORE DELETE ON protocol_records WHEN OLD.kind LIKE 'catalog-checkpoint-lookup-%' BEGIN SELECT RAISE({action}{}); END",if action=="ABORT"{",'test'"}else{""})).unwrap();
                assert!(s.$release(owner.id).is_err());s.connection.execute_batch("DROP TRIGGER fail_lookup_delete").unwrap();while s.$release(owner.id).unwrap(){}
                assert!(before.is_some());
            }
            for action in ["ABORT","IGNORE"]{
                let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);let tmp=tempfile::tempdir().unwrap();let s=ControlStore::open(tmp.path().join("control.db"),&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);
                let owner=s.$retain(Uuid::from_u128(1),&proof,||Ok(proof.trust().clone())).unwrap();
                s.connection.execute_batch(&format!("CREATE TEMP TRIGGER fail_lookup_complete BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-checkpoint-lookup-v1' BEGIN SELECT RAISE({action}{}); END",if action=="ABORT"{",'test'"}else{""})).unwrap();
                assert!(s.$build(owner.id,&proof,||Ok(proof.trust().clone())).is_err());
                let key=fixture.records.iter().find_map(R::revision_key).unwrap();
                assert!(s.get_record(&lookup::kind(owner.id,"revision"),key.revision_id.as_bytes()).unwrap().is_some());
                assert!(s.$point(owner,key.revision_id,budget()).is_err());
                drop(s);let s=ControlStore::open(tmp.path().join("control.db"),&history.keys[0]).unwrap();
                assert!(s.$point(owner,key.revision_id,budget()).is_err());
                s.$build(owner.id,&proof,||Ok(proof.trust().clone())).unwrap();
                assert!(s.$point(owner,key.revision_id,budget()).unwrap().is_some());
            }
            let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);let tmp=tempfile::tempdir().unwrap();let s=ControlStore::open(tmp.path().join("control.db"),&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);
            let owner=s.$retain(Uuid::from_u128(1),&proof,||Ok(proof.trust().clone())).unwrap();
            let key=fixture.records.iter().find_map(R::revision_key).unwrap();
            assert!(s.$build(owner.id,&proof,||{
                let mut trust=proof.trust().clone();
                if s.get_record(&lookup::kind(owner.id,"revision"),key.revision_id.as_bytes())?.is_some(){trust.event_head[0]^=1;}
                Ok(trust)
            }).is_err());
            assert!(s.$point(owner,key.revision_id,budget()).is_err());
            assert!(s.get_record(&lookup::kind(owner.id,"revision"),key.revision_id.as_bytes()).unwrap().is_none());
            s.$build(owner.id,&proof,||Ok(proof.trust().clone())).unwrap();
            assert!(s.$point(owner,key.revision_id,budget()).unwrap().is_some());
        }
    };
}

cases!(
    paged_lookup_individual_reopens_and_preserves_original_records_and_shared_owners,
    paged_lookup_individual_rejects_corrupt_ranges_before_returning_records,
    paged_lookup_individual_rolls_back_index_and_retirement_faults,
    individual,
    super::paged_checkpoint_retention::stage_paged_owner,
    retain_catalog_paged_checkpoint,
    build_catalog_paged_checkpoint_lookup,
    catalog_paged_checkpoint_indexed_revision,
    next_catalog_paged_checkpoint_indexed_revision,
    catalog_paged_checkpoint_indexed_group,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
cases!(
    paged_lookup_directory_reopens_and_preserves_original_records_and_shared_owners,
    paged_lookup_directory_rejects_corrupt_ranges_before_returning_records,
    paged_lookup_directory_rolls_back_index_and_retirement_faults,
    directory,
    super::checkpoint_directory_retention::stage,
    retain_catalog_paged_checkpoint_directory,
    build_catalog_paged_checkpoint_directory_lookup,
    catalog_paged_checkpoint_directory_indexed_revision,
    next_catalog_paged_checkpoint_directory_indexed_revision,
    catalog_paged_checkpoint_directory_indexed_group,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);

#[test]
fn paged_lookup_reserves_complete_parent_work_before_reading_pages() {
    macro_rules! check {
        ($proof:expr,$stage:path,$retain:ident,$build:ident) => {{
            let (mut fixture, history) = real_checkpoint();
            let full = $proof(&mut fixture, &history, budget());
            let tmp = tempfile::tempdir().unwrap();
            let s = ControlStore::open(tmp.path().join("control.db"), &history.keys[0]).unwrap();
            $stage(&s, &fixture, &full, 1000);
            let owner = s
                .$retain(Uuid::from_u128(1), &full, || Ok(full.trust().clone()))
                .unwrap();
            let limit = owner
                .proof_work
                .checked_add(owner.checkpoint.work().unwrap())
                .unwrap();
            let limited = $proof(&mut fixture, &history, limit);
            $stage(&s, &fixture, &limited, 2000);
            let owner = s
                .$retain(Uuid::from_u128(2), &limited, || Ok(limited.trust().clone()))
                .unwrap();
            let page = owner.checkpoint.authority_root.records.page;
            s.put_record("catalog-page-v1", &page.hash, &[0]).unwrap();
            assert!(matches!(
                s.$build(owner.id, &limited, || Ok(limited.trust().clone())),
                Err(CatalogStoreError::Page(mb_core::CatalogError::Bounds))
            ));
            assert!(
                s.get_record("catalog-checkpoint-lookup-v1", owner.id.as_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(
                s.next_record_bounded(&lookup::kind(owner.id, "revision"), None, 16, 1024)
                    .unwrap()
                    .is_none()
            );
        }};
    }
    fn individual_limit(
        fixture: &mut super::super::super::checkpoint_validation::tests::Fixture,
        history: &History,
        limit: Work,
    ) -> CatalogQuorumPagedCheckpointIndex {
        let trust = history.trust();
        let reader = real_reader(history, &trust);
        let body = real_body(fixture, history, &reader, &trust, true);
        let transition = body
            .validate_certified_history_authority_transition(None, &reader, limit, || {
                Ok(trust.clone())
            })
            .unwrap();
        real_certificate(transition, history)
    }
    check!(
        individual_limit,
        super::paged_checkpoint_retention::stage_paged_owner,
        retain_catalog_paged_checkpoint,
        build_catalog_paged_checkpoint_lookup
    );
    check!(
        super::checkpoint_directory_retention::proof,
        super::checkpoint_directory_retention::stage,
        retain_catalog_paged_checkpoint_directory,
        build_catalog_paged_checkpoint_directory_lookup
    );
}
