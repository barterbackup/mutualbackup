use super::*;
use mb_core::{
    CatalogCapacityPolicy, CatalogCodingTraversalBudget as Work, CodingProfile, PackingProfile,
};
use mb_store::{
    CatalogPackingAuthority, CatalogPackingOperation, CatalogPackingOperationState,
    CatalogStorageQuota, RecordScratchStore,
};

#[test]
fn retained_packing_node_uses_real_volume_custody_reopens_and_preserves_final_role_zero() {
    retained_case(mb_core::V1_SECTOR_SIZE as u32);
}

fn retained_case(sector_size: u32) {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([218; 32]);
    let mut node = Node::open(temp.path(), seed.clone()).unwrap();
    let revision = crate::node::tests::install_public_restore_fixture(&mut node, &seed);
    let guild = revision.value.guild_id;
    let original = node.installed_guild().unwrap().unwrap().certificate;
    let peers = original
        .genesis
        .members
        .iter()
        .cloned()
        .map(|member| GuildPeer {
            member,
            endpoints: Vec::new(),
        })
        .collect();
    node.adopt_recovered_guild(original, peers).unwrap();
    while node.advance_guild_history_index().unwrap() {}
    let checkpoint = node.current_checkpoint(guild).unwrap().unwrap();
    let trusted = checkpoint.hash().unwrap();
    let reference = &revision.value.metadata_sectors[0];
    let ciphertext = node.sector_for_guild(&guild, &reference.id).unwrap();
    let binding = node
        .sign_legacy_packing_binding(&guild, revision.value.protected_root_id, reference)
        .unwrap();
    let fresh = || {
        CatalogPackingAuthority::from_legacy_checkpoint(
            trusted,
            &checkpoint,
            RecordScratchStore::new(16 << 20).unwrap(),
        )
        .unwrap()
        .with_legacy_binding(&binding)
        .unwrap()
    };
    let policy = CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 1,
        legacy_revisions: 1,
        legacy_source_occurrences: 1,
        data_bytes_per_dataset: 8 * 65536,
        data_sources_per_dataset: 8,
        private_work_per_revision: Work {
            bytes: 65536,
            page_occurrences: 4,
            records: 20000,
        },
        source_pages_per_revision: 4,
        authority_control_records: 257,
        packing_profile: PackingProfile {
            format_version: 1,
            sector_size,
            slot_size: 16384,
        },
        coding_profile: CodingProfile::new(3, 2, sector_size),
        packed_sectors: 32,
        coding_groups: 11,
        replay_work: Work::default(),
    };
    // The existing CAPP fixes newly packed output at 64 KiB. Wider retained
    // coding payloads keep their original independent compatibility path.
    let mut wider = policy;
    wider.packing_profile.sector_size = mb_core::MAX_PROFILE_SHARD_SIZE;
    wider.coding_profile.shard_size = wider.packing_profile.sector_size;
    assert!(wider.packing_profile.validate().is_ok());
    assert!(wider.coding_profile.validate().is_ok());
    assert!(wider.plan().is_err());
    assert!(
        CatalogPackingOperation::new(
            Uuid::new_v4(),
            &fresh(),
            wider,
            Work {
                bytes: u64::MAX,
                page_occurrences: u64::MAX,
                records: u64::MAX
            },
            Work::default(),
            Work::default()
        )
        .is_err()
    );
    let plan = policy.plan().unwrap();
    let revisions = mb_store::CatalogPublishedRevisionQuota {
        revisions: plan.revision_occurrences,
        work: plan.retained_revision_work,
    };
    let mut usage = node
        .control
        .begin_catalog_published_revision_quota_adoption(mb_store::CatalogPublishedRevisionQuotas {
            global: revisions,
            dataset: revisions,
            guild: revisions,
        })
        .unwrap();
    while usage.state == mb_store::CatalogPublishedRevisionQuotaState::Adopting {
        usage = node
            .control
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
    let retained = mb_store::CatalogRetainedSourceQuota {
        logical_bytes: policy.data_bytes_per_dataset,
        sources: policy.data_sources_per_dataset,
        open_reservations: 8,
    };
    node.control
        .configure_catalog_retained_source_quota(retained)
        .unwrap();
    node.control
        .configure_catalog_retained_source_guild_quota(retained)
        .unwrap();
    node.control
        .configure_catalog_capacity_policy(policy)
        .unwrap();
    node.configure_control_record_quota(mb_store::DatabaseRecordQuota {
        max_rows: 100000,
        max_accounted_bytes: 1 << 30,
    })
    .unwrap();
    node.configure_control_page_quota(mb_store::DatabasePageQuota { max_pages: 262144 })
        .unwrap();
    node.configure_control_journal_quota(mb_store::DatabaseJournalQuota { max_bytes: 1 << 30 })
        .unwrap();
    let quota = CatalogStorageQuota {
        page_bytes: 1 << 30,
        pages: 65536,
        open_reservations: 16,
    };
    node.control.configure_catalog_storage_quota(quota).unwrap();
    node.control
        .configure_catalog_scoped_storage_quotas(quota, quota)
        .unwrap();
    let operation = CatalogPackingOperation::new(
        Uuid::new_v4(),
        &fresh(),
        policy,
        plan.job_work
            .checked_add(plan.job_work)
            .unwrap()
            .checked_add(plan.job_work)
            .unwrap()
            .checked_add(plan.job_work)
            .unwrap(),
        policy.plan().unwrap().job_work,
        policy.plan().unwrap().job_work,
    )
    .unwrap();
    // This legacy input remains under the unchanged certified checkpoint and
    // its exact durable Inline recipe; paged/remote custody has separate joins.
    let recipe = node
        .control
        .get_record("local-sector", &reference.id)
        .unwrap()
        .unwrap();
    let proof = node
        .produce_retained_packing_operation(
            operation,
            fresh(),
            |view, source| {
                anyhow::ensure!(
                    view.record(
                        "local-sector",
                        &reference.id,
                        mb_store::CATALOG_SECTOR_RECIPE_BYTES
                    )? == Some(recipe.clone())
                );
                anyhow::ensure!(source.operation_identity()? == operation.source_identity);
                Ok(())
            },
            |source, bytes| {
                assert_eq!(source.id.object_id, reference.id);
                bytes.copy_from_slice(&ciphertext);
                Ok(())
            },
        )
        .unwrap();
    let manifest = proof.manifest();
    let planned = node
        .control
        .next_catalog_packing_operation_attempt(operation, None)
        .unwrap()
        .unwrap();
    assert_ne!(planned.storage_id, planned.sector_id);
    assert!(proof.sector(planned.sector_id).unwrap().is_some());
    let payload = node
        .control
        .catalog_packing_payload(operation.payloads(), planned.storage_id, 0)
        .unwrap()
        .unwrap();
    node.volumes
        .verify_packing_payload(&node.control, &payload)
        .unwrap();
    assert!(
        !node
            .volumes
            .discard_attempt(&node.control, &planned.attempt_id, &BTreeSet::new())
            .unwrap()
    );
    let range = node
        .volumes
        .open_attempt_range(
            &node.control,
            &planned.attempt_id,
            &planned.storage_id,
            0,
            0,
            sector_size / mb_core::MERKLE_LEAF_SIZE as u32,
        )
        .unwrap();
    let bytes = mb_core::merkle_verify_range(&planned.commitment, &range).unwrap();
    // Final information role 0 uses the original public sector identity and
    // coexists on the same physical volume with the retained temporary output.
    let final_attempt = [221; 16];
    node.volumes
        .reserve_attempt(&node.control, &final_attempt, guild, 0, sector_size)
        .unwrap();
    for (index, chunk) in bytes.chunks(mb_core::V1_SECTOR_SIZE).enumerate() {
        node.volumes
            .write_attempt_range(
                &node.control,
                &final_attempt,
                0,
                (index * mb_core::V1_SECTOR_SIZE) as u32,
                chunk,
            )
            .unwrap();
    }
    node.volumes
        .finish_attempt_upload(
            &node.control,
            &final_attempt,
            planned.sector_id,
            0,
            &planned.commitment,
        )
        .unwrap();
    node.volumes
        .verify_packing_payload(&node.control, &payload)
        .unwrap();
    node.forget_local_sector(&reference.id).unwrap();
    drop(proof);
    drop(node);
    let mut node = Node::open(temp.path(), seed).unwrap();
    let replay = node
        .produce_retained_packing_operation(
            operation,
            fresh(),
            |_, _| panic!("completed replay retains all outputs"),
            |_, _| panic!("completed replay does not read deleted original source"),
        )
        .unwrap();
    assert_eq!(replay.manifest(), manifest);
    assert_eq!(
        node.control.checkpoint_head_identity(&guild).unwrap(),
        Some((1, trusted))
    );
    assert!(matches!(
        node.control
            .catalog_packing_operation(operation.id)
            .unwrap(),
        Some((_, CatalogPackingOperationState::PackingComplete(_)))
    ));
    node.cancel_retained_packing_operation(operation).unwrap();
    while node
        .control
        .release_catalog_packing_payload(operation.payloads())
        .unwrap()
    {}
    assert!(
        node.volumes
            .discard_attempt(&node.control, &planned.attempt_id, &BTreeSet::new())
            .unwrap()
    );
    assert!(
        node.volumes
            .open_attempt_range(
                &node.control,
                &final_attempt,
                &planned.sector_id,
                0,
                0,
                sector_size / mb_core::MERKLE_LEAF_SIZE as u32
            )
            .is_ok()
    );
}
