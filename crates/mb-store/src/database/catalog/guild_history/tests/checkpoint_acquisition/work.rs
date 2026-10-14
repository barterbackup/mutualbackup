use super::*;
use crate::database::{
    DatabaseJournalQuota, DatabasePageQuota, DatabaseRecordQuota, DatabaseRecordQuotaState,
};
use mb_core::{CatalogCapacityPolicy, CodingProfile};

fn capacity(cert: &Certificate) -> CatalogCapacityPolicy {
    let profile = match cert {
        Certificate::Individual(c) => c.checkpoint.packed_sources.profile,
        Certificate::Directory(c) => c.checkpoint.packing.profile,
    };
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 16,
        legacy_revisions: 16,
        legacy_source_occurrences: 1024,
        data_bytes_per_dataset: 64 * mb_core::V1_SECTOR_SIZE as u64,
        data_sources_per_dataset: 64,
        private_work_per_revision: Work {
            bytes: 16,
            records: 0,
            page_occurrences: 2,
        },
        source_pages_per_revision: 64,
        authority_control_records: 4096,
        packing_profile: profile,
        coding_profile: CodingProfile::new(3, 2, mb_core::V1_SECTOR_SIZE as u32),
        packed_sectors: 2048,
        coding_groups: 1024,
        replay_work: budget(),
    }
}
fn configure(s: &mut ControlStore, cert: &Certificate, slots: u32) {
    let capacity = capacity(cert);
    let plan = capacity.plan().unwrap();
    let q = CatalogPublishedRevisionQuota {
        revisions: 100,
        work: Work {
            bytes: 1 << 40,
            records: 1 << 30,
            page_occurrences: 1 << 30,
        },
    };
    let mut usage = s
        .begin_catalog_published_revision_quota_adoption(CatalogPublishedRevisionQuotas {
            global: q,
            guild: q,
            dataset: q,
        })
        .unwrap();
    while usage.state == CatalogPublishedRevisionQuotaState::Adopting {
        usage = s
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
    let q = CatalogRetainedSourceQuota {
        logical_bytes: 1 << 40,
        sources: 1 << 30,
        open_reservations: 100,
    };
    s.configure_catalog_retained_source_quota(q).unwrap();
    s.configure_catalog_retained_source_guild_quota(q).unwrap();
    s.configure_catalog_capacity_policy(capacity).unwrap();
    let (rows, bytes) = CatalogResourcePolicy::minimum_control_credits(capacity).unwrap();
    let (pages, journal) = CatalogResourcePolicy::minimum_database_extents(capacity).unwrap();
    s.begin_record_quota_adoption(DatabaseRecordQuota {
        max_rows: rows,
        max_accounted_bytes: bytes,
    })
    .unwrap();
    while s.record_quota_usage().unwrap().unwrap().state == DatabaseRecordQuotaState::Adopting {
        s.resume_record_quota_adoption().unwrap();
    }
    s.configure_page_quota(DatabasePageQuota { max_pages: pages })
        .unwrap();
    s.configure_journal_quota(DatabaseJournalQuota { max_bytes: journal })
        .unwrap();
    s.configure_catalog_storage_quota(CatalogStorageQuota {
        page_bytes: plan.encoded_metadata_page_bytes,
        pages: plan.metadata_work.page_occurrences,
        open_reservations: slots,
    })
    .unwrap();
    s.configure_catalog_resource_policy(CatalogResourcePolicy {
        format_version: 1,
        capacity,
        control_rows: rows,
        control_accounted_bytes: bytes,
        control_pages: pages,
        control_journal_bytes: journal,
        immutable_page_bytes: plan.encoded_metadata_page_bytes,
        immutable_pages: plan.metadata_work.page_occurrences,
        open_page_reservations: slots,
    })
    .unwrap();
}
fn activate(s: &ControlStore) {
    while s.advance_checkpoint_acquisition_work_admission().unwrap() {}
}
fn base(cert: &Certificate) -> Work {
    cert.work()
        .unwrap()
        .checked_add(Work {
            bytes: 1 << 20,
            records: 16,
            page_occurrences: 16,
        })
        .unwrap()
}

#[test]
fn acquisition_work_shared_dimensions_reopen_and_cancellation_fence_other_connections() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    for dimension in 0..3 {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let mut s = ControlStore::open(&path, &history.keys[0]).unwrap();
        let other = ControlStore::open(&path, &history.keys[0]).unwrap();
        configure(&mut s, &cert, 16);
        activate(&s);
        assert!(
            other
                .put_record(
                    "catalog-checkpoint-acquisition-v1",
                    Uuid::from_u128(2099).as_bytes(),
                    b"unfunded older writer"
                )
                .is_err()
        );
        let limit = s
            .checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .limit;
        let mut amount = base(&cert);
        match dimension {
            0 => amount.bytes = limit.bytes / 2 + 1,
            1 => amount.records = limit.records / 2 + 1,
            _ => amount.page_occurrences = limit.page_occurrences / 2 + 1,
        };
        let job = s
            .begin_checkpoint_acquisition(
                Uuid::from_u128(2000),
                cert.clone(),
                proof.trust().clone(),
                amount,
            )
            .unwrap();
        assert!(
            other
                .begin_checkpoint_acquisition(
                    Uuid::from_u128(2001),
                    cert.clone(),
                    proof.trust().clone(),
                    amount
                )
                .is_err()
        );
        assert!(
            other
                .get_record(
                    "catalog-checkpoint-acquisition-v1",
                    Uuid::from_u128(2001).as_bytes()
                )
                .unwrap()
                .is_none()
        );
        assert_eq!(
            other
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            amount
        );
        drop(s);
        let s = ControlStore::open(&path, &history.keys[0]).unwrap();
        assert_eq!(
            s.checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .open_jobs,
            1
        );
        s.cancel_checkpoint_acquisition(&job).unwrap();
        assert_eq!(
            other
                .checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .reserved,
            Work::default()
        );
        let next = other
            .begin_checkpoint_acquisition(
                Uuid::from_u128(2001),
                cert.clone(),
                proof.trust().clone(),
                amount,
            )
            .unwrap();
        assert!(
            s.begin_checkpoint_acquisition(job.id, cert.clone(), proof.trust().clone(), amount)
                .is_err()
        );
        other.cancel_checkpoint_acquisition(&next).unwrap();
        assert_eq!(
            s.checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .open_jobs,
            0
        );
    }
}
#[test]
fn acquisition_work_ignored_or_aborted_reserve_release_and_adoption_are_atomic() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    for action in ["ABORT", "IGNORE"] {
        let temp = tempfile::tempdir().unwrap();
        let mut s = ControlStore::open(temp.path().join("control.db"), &history.keys[0]).unwrap();
        configure(&mut s, &cert, 16);
        let suffix = if action == "ABORT" { ",'test'" } else { "" };
        s.connection.execute_batch(&format!("CREATE TEMP TRIGGER work_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-acquisition-work-guard-v1' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
        assert!(s.advance_checkpoint_acquisition_work_admission().is_err());
        assert_eq!(
            s.checkpoint_acquisition_work_usage()
                .unwrap()
                .unwrap()
                .state,
            CatalogAcquisitionWorkState::Adopting
        );
        s.connection
            .execute_batch("DROP TRIGGER work_fault")
            .unwrap();
        activate(&s);
        for kind in [
            "catalog-acquisition-work-held-guard-v1",
            "catalog-acquisition-work-lease-guard-v1",
        ] {
            s.connection.execute_batch(&format!("CREATE TEMP TRIGGER work_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(
                s.begin_checkpoint_acquisition(
                    Uuid::from_u128(2010),
                    cert.clone(),
                    proof.trust().clone(),
                    base(&cert)
                )
                .is_err()
            );
            assert_eq!(
                s.checkpoint_acquisition_work_usage()
                    .unwrap()
                    .unwrap()
                    .open_jobs,
                0
            );
            assert!(
                s.get_record(
                    "catalog-checkpoint-acquisition-v1",
                    Uuid::from_u128(2010).as_bytes()
                )
                .unwrap()
                .is_none()
            );
            s.connection
                .execute_batch("DROP TRIGGER work_fault")
                .unwrap();
        }
        let job = s
            .begin_checkpoint_acquisition(
                Uuid::from_u128(2010),
                cert.clone(),
                proof.trust().clone(),
                base(&cert),
            )
            .unwrap();
        for event in [
            "BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-acquisition-work-lease-guard-v1'",
            "BEFORE DELETE ON protocol_records WHEN OLD.kind='catalog-acquisition-work-held-guard-v1'",
        ] {
            s.connection.execute_batch(&format!("CREATE TEMP TRIGGER work_fault {event} BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
            assert!(s.cancel_checkpoint_acquisition(&job).is_err());
            assert_eq!(
                s.checkpoint_acquisition_state(&job).unwrap(),
                State::Building
            );
            assert_eq!(
                s.checkpoint_acquisition_work_usage()
                    .unwrap()
                    .unwrap()
                    .open_jobs,
                1
            );
            s.connection
                .execute_batch("DROP TRIGGER work_fault")
                .unwrap();
        }
        s.cancel_checkpoint_acquisition(&job).unwrap();
        let saved = s
            .get_record("catalog-acquisition-work-guard-v1", b"store")
            .unwrap()
            .unwrap();
        s.delete_record("catalog-acquisition-work-guard-v1", b"store")
            .unwrap();
        assert!(s.checkpoint_acquisition_work_usage().is_err());
        s.put_record("catalog-acquisition-work-guard-v1", b"store", &saved)
            .unwrap();
        let next = s
            .begin_checkpoint_acquisition(
                Uuid::from_u128(2011),
                cert.clone(),
                proof.trust().clone(),
                base(&cert),
            )
            .unwrap();
        for kind in [
            "catalog-acquisition-work-held-v1",
            "catalog-acquisition-work-held-guard-v1",
        ] {
            s.delete_record(kind, next.id.as_bytes()).unwrap();
        }
        assert!(s.checkpoint_acquisition_work_usage().is_err());
        assert!(
            s.begin_checkpoint_acquisition(
                Uuid::from_u128(2012),
                cert.clone(),
                proof.trust().clone(),
                base(&cert)
            )
            .is_err()
        );
    }
}
#[test]
fn acquisition_work_adopts_existing_jobs_one_at_a_time_and_keeps_cancelled_history() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut s = ControlStore::open(&path, &history.keys[0]).unwrap();
    quota(&s);
    let a = s
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2020),
            cert.clone(),
            proof.trust().clone(),
            base(&cert),
        )
        .unwrap();
    let b = s
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2021),
            cert.clone(),
            proof.trust().clone(),
            base(&cert),
        )
        .unwrap();
    configure(&mut s, &cert, 16);
    assert_eq!(
        s.checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .state,
        CatalogAcquisitionWorkState::Adopting
    );
    assert!(s.advance_checkpoint_acquisition_work_admission().unwrap());
    let u = s.checkpoint_acquisition_work_usage().unwrap().unwrap();
    assert_eq!((u.scanned_jobs, u.open_jobs), (1, 1));
    s.cancel_checkpoint_acquisition(&a).unwrap();
    s.cancel_checkpoint_acquisition(&b).unwrap();
    drop(s);
    let s = ControlStore::open(&path, &history.keys[0]).unwrap();
    activate(&s);
    let u = s.checkpoint_acquisition_work_usage().unwrap().unwrap();
    assert_eq!((u.scanned_jobs, u.open_jobs), (2, 0));
    assert_eq!(u.reserved, Work::default());
    assert_eq!(
        s.checkpoint_acquisition_state(&a).unwrap(),
        State::Cancelled
    );
    assert_eq!(
        s.checkpoint_acquisition_state(&b).unwrap(),
        State::Cancelled
    );
}

fn individual_limited(
    f: &mut super::super::super::super::checkpoint_validation::tests::Fixture,
    h: &History,
    limit: Work,
) -> CatalogQuorumPagedCheckpointIndex {
    super::super::paged_checkpoint_retention::paged_owner_proof_with_budget(f, h, None, limit)
}
fn directory_limited(
    f: &mut super::super::super::super::checkpoint_validation::tests::Fixture,
    h: &History,
    limit: Work,
) -> CatalogQuorumPagedCheckpointDirectoryIndex {
    super::super::checkpoint_directory_retention::proof(f, h, limit)
}
macro_rules! completion_cases{
    ($name:ident,$proof:path,$limited:path,$stage:path,$variant:ident,$retain:ident)=>{
        #[test]
        fn $name(){
            for action in ["ABORT","IGNORE"]{
                let (mut fixture,history)=real_checkpoint();let proof=$proof(&mut fixture,&history);let cert=Certificate::$variant(proof.certificate().clone());
                let amount=capacity(&cert).plan().unwrap().job_work;let proof=$limited(&mut fixture,&history,amount);let cert=Certificate::$variant(proof.certificate().clone());
                let temp=tempfile::tempdir().unwrap();let path=temp.path().join("control.db");let mut s=ControlStore::open(&path,&history.keys[0]).unwrap();$stage(&s,&fixture,&proof,1000);configure(&mut s,&cert,16);activate(&s);
                let amount=s.checkpoint_acquisition_work_usage().unwrap().unwrap().limit;
                let job=s.begin_checkpoint_acquisition(Uuid::from_u128(2030),cert.clone(),proof.trust().clone(),amount).unwrap();
                for (scope,section,root) in cert.initial_roots(){let intent=s.reserve_checkpoint_acquisition_root(&job,scope,section,root).unwrap();tree(&s,&job,intent,root,root);s.complete_checkpoint_acquisition_root(&job,intent,root).unwrap();}
                s.$retain(job.id,&proof,||Ok(proof.trust().clone())).unwrap();
                let suffix=if action=="ABORT"{",'test'"}else{""};s.connection.execute_batch(&format!("CREATE TEMP TRIGGER work_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='catalog-acquisition-work-guard-v1' BEGIN SELECT RAISE({action}{suffix}); END")).unwrap();
                assert!(s.finish_checkpoint_acquisition(&job).is_err());assert_eq!(s.checkpoint_acquisition_state(&job).unwrap(),State::Building);assert_eq!(s.checkpoint_acquisition_work_usage().unwrap().unwrap().reserved,amount);
                s.connection.execute_batch("DROP TRIGGER work_fault").unwrap();s.finish_checkpoint_acquisition(&job).unwrap();assert_eq!(s.checkpoint_acquisition_work_usage().unwrap().unwrap().reserved,Work::default());
                s.finish_checkpoint_acquisition(&job).unwrap();drop(s);let s=ControlStore::open(&path,&history.keys[0]).unwrap();assert_eq!(s.checkpoint_acquisition_state(&job).unwrap(),State::Complete);assert_eq!(s.checkpoint_acquisition_work_usage().unwrap().unwrap().open_jobs,0);
                let next=s.begin_checkpoint_acquisition(Uuid::from_u128(2031),cert.clone(),proof.trust().clone(),amount).unwrap();s.cancel_checkpoint_acquisition(&next).unwrap();assert_eq!(s.checkpoint_acquisition_work_usage().unwrap().unwrap().open_jobs,0);
            }
        }
    }
}
completion_cases!(
    individual_acquisition_work_completion_releases_only_with_complete_public_owner,
    individual,
    individual_limited,
    super::super::paged_checkpoint_retention::stage_paged_owner,
    Individual,
    retain_catalog_paged_checkpoint
);
completion_cases!(
    directory_acquisition_work_completion_releases_only_with_complete_public_owner,
    directory,
    directory_limited,
    super::super::checkpoint_directory_retention::stage,
    Directory,
    retain_catalog_paged_checkpoint_directory
);

#[test]
fn acquisition_work_job_slot_and_unadoptable_debt_remain_explicit_and_cancellable() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("slots.db");
    let mut s = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut s, &cert, 1);
    activate(&s);
    let amount = base(&cert);
    let limit = s
        .checkpoint_acquisition_work_usage()
        .unwrap()
        .unwrap()
        .limit;
    limit
        .remaining_after(amount.checked_add(amount).unwrap())
        .unwrap();
    let a = s
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2040),
            cert.clone(),
            proof.trust().clone(),
            amount,
        )
        .unwrap();
    assert!(
        s.begin_checkpoint_acquisition(
            Uuid::from_u128(2041),
            cert.clone(),
            proof.trust().clone(),
            amount
        )
        .is_err()
    );
    s.cancel_checkpoint_acquisition(&a).unwrap();
    let mut s = ControlStore::open(temp.path().join("debt.db"), &history.keys[0]).unwrap();
    quota(&s);
    let capacity = capacity(&cert);
    let mut oversized = capacity.plan().unwrap().job_work;
    oversized.bytes += 1;
    let old = s
        .begin_checkpoint_acquisition(
            Uuid::from_u128(2042),
            cert.clone(),
            proof.trust().clone(),
            oversized,
        )
        .unwrap();
    configure(&mut s, &cert, 16);
    assert!(s.advance_checkpoint_acquisition_work_admission().is_err());
    assert_eq!(
        s.checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .scanned_jobs,
        0
    );
    assert_eq!(
        s.checkpoint_acquisition_state(&old).unwrap(),
        State::Building
    );
    s.cancel_checkpoint_acquisition(&old).unwrap();
    activate(&s);
    assert_eq!(
        s.checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .reserved,
        Work::default()
    );
}

#[test]
fn acquisition_work_trigger_and_enrollment_damage_reject_reopen_without_mutation() {
    let (mut fixture, history) = real_checkpoint();
    let proof = individual(&mut fixture, &history);
    let cert = Certificate::Individual(proof.certificate().clone());
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let mut s = ControlStore::open(&path, &history.keys[0]).unwrap();
    configure(&mut s, &cert, 16);
    activate(&s);
    let sql: String = s
        .connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE name='catalog_acquisition_work_insert'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    s.connection
        .execute_batch("DROP TRIGGER catalog_acquisition_work_insert")
        .unwrap();
    assert!(s.checkpoint_acquisition_work_usage().is_err());
    assert!(ControlStore::open(&path, &history.keys[0]).is_err());
    s.connection.execute_batch(&sql).unwrap();
    assert!(ControlStore::open(&path, &history.keys[0]).is_ok());
    s.connection
        .execute(
            "DELETE FROM meta WHERE key='catalog_acquisition_work_ready'",
            [],
        )
        .unwrap();
    assert!(s.checkpoint_acquisition_work_usage().is_err());
    assert!(ControlStore::open(&path, &history.keys[0]).is_err());
    s.connection
        .execute(
            "INSERT INTO meta(key,value) VALUES ('catalog_acquisition_work_ready',?1)",
            [&[1u8][..]],
        )
        .unwrap();
    assert_eq!(
        s.checkpoint_acquisition_work_usage()
            .unwrap()
            .unwrap()
            .open_jobs,
        0
    );
}
