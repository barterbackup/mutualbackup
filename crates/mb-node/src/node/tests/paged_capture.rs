use super::*;
use mb_core::{
    CatalogCapacityPolicy, CatalogCodingTraversalBudget as Work, CodingProfile, PackingProfile,
};
use mb_store::{
    CatalogPublishedRevisionQuota, CatalogPublishedRevisionQuotas, CatalogRetainedSourceQuota,
    CatalogStorageQuota,
};

fn capacity() -> CatalogCapacityPolicy {
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 4,
        legacy_revisions: 0,
        legacy_source_occurrences: 0,
        data_bytes_per_dataset: 512 * 65536,
        data_sources_per_dataset: 512,
        private_work_per_revision: Work {
            bytes: 2 * 1024 * 1024,
            page_occurrences: 64,
            records: 500_000,
        },
        source_pages_per_revision: 64,
        authority_control_records: 257,
        packing_profile: PackingProfile {
            format_version: 1,
            sector_size: 65536,
            slot_size: 16384,
        },
        coding_profile: CodingProfile::new(3, 2, 65536),
        packed_sectors: 1030,
        coding_groups: 344,
        replay_work: Work::default(),
    }
}

fn configure(control: &mb_store::ControlStore, policy: CatalogCapacityPolicy) {
    let plan = policy.plan().unwrap();
    let quota = CatalogPublishedRevisionQuota {
        revisions: plan.revision_occurrences,
        work: plan.retained_revision_work,
    };
    let mut usage = control
        .begin_catalog_published_revision_quota_adoption(CatalogPublishedRevisionQuotas {
            global: quota,
            dataset: quota,
            guild: quota,
        })
        .unwrap();
    while usage.state == mb_store::CatalogPublishedRevisionQuotaState::Adopting {
        usage = control
            .resume_catalog_published_revision_quota_adoption()
            .unwrap();
    }
    let data = CatalogRetainedSourceQuota {
        logical_bytes: policy.data_bytes_per_dataset,
        sources: policy.data_sources_per_dataset,
        open_reservations: 8,
    };
    control
        .configure_catalog_retained_source_quota(data)
        .unwrap();
    control
        .configure_catalog_retained_source_guild_quota(data)
        .unwrap();
    control.configure_catalog_capacity_policy(policy).unwrap();
}

#[test]
fn paged_native_capture_admission_requires_all_database_and_scoped_page_policies() {
    for missing in 0..6 {
        let temp = tempfile::tempdir().unwrap();
        let seed = Seed::from_bytes([215; 32]);
        let mut node = Node::open(temp.path(), seed).unwrap();
        let scope = mb_core::CatalogScope::Dataset {
            guild_id: [216; 32],
            owner: node.keys.node_id(),
            protected_root_id: Uuid::from_u128(217),
        };
        configure(&node.control, capacity());
        if missing != 0 {
            node.configure_control_record_quota(mb_store::DatabaseRecordQuota {
                max_rows: 100_000,
                max_accounted_bytes: 1 << 30,
            })
            .unwrap();
        }
        if missing != 1 {
            node.configure_control_page_quota(mb_store::DatabasePageQuota { max_pages: 262144 })
                .unwrap();
        }
        if missing != 2 {
            node.configure_control_journal_quota(mb_store::DatabaseJournalQuota {
                max_bytes: 1 << 30,
            })
            .unwrap();
        }
        let storage = CatalogStorageQuota {
            page_bytes: 512 * 65536,
            pages: 512,
            open_reservations: 8,
        };
        if missing != 3 {
            node.control
                .configure_catalog_storage_quota(storage)
                .unwrap();
            if missing != 4 {
                node.control
                    .configure_catalog_scoped_storage_quotas(storage, storage)
                    .unwrap();
            }
        }
        let result =
            crate::paged_capture::PagedNativeCapture::admit_configuration(&node.control, scope);
        if missing == 5 {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
        }
        assert!(
            node.control
                .records(crate::paged_capture::JOURNAL)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn native_paged_capture_operation_reopens_rolls_back_late_authority_and_cancels_owned_sources() {
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::MetadataExt;
    let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").expect("provisioned Btrfs root");
    let temp = tempfile::tempdir_in(root).unwrap();
    let seed = Seed::from_bytes([218; 32]);
    let state = temp.path().join("node");
    let mut node = Node::open(&state, seed.clone()).unwrap();
    let certified = install_public_restore_fixture(&mut node, &seed);
    let guild = certified.value.guild_id;
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
    let signing = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    node.control
        .put_record(
            "writer-incarnation",
            &guild,
            &canonical_bytes(&LocalWriterIncarnation {
                format_version: 1,
                epoch: 1,
                public_key: signing.verifying_key().to_bytes(),
                secret_key: signing.to_bytes(),
                base_checkpoint: Some(
                    node.current_checkpoint(guild)
                        .unwrap()
                        .unwrap()
                        .hash()
                        .unwrap(),
                ),
            })
            .unwrap(),
        )
        .unwrap();
    node.configure_control_record_quota(mb_store::DatabaseRecordQuota {
        max_rows: 100_000,
        max_accounted_bytes: 1 << 30,
    })
    .unwrap();
    node.configure_control_page_quota(mb_store::DatabasePageQuota { max_pages: 262144 })
        .unwrap();
    node.configure_control_journal_quota(mb_store::DatabaseJournalQuota { max_bytes: 1 << 30 })
        .unwrap();
    configure(&node.control, capacity());
    let storage = CatalogStorageQuota {
        page_bytes: 512 * 65536,
        pages: 512,
        open_reservations: 16,
    };
    node.control
        .configure_catalog_storage_quota(storage)
        .unwrap();
    node.control
        .configure_catalog_scoped_storage_quotas(storage, storage)
        .unwrap();
    let source = temp.path().join("source");
    std::fs::create_dir_all(source.join("nested")).unwrap();
    let dense: Vec<u8> = (0..145)
        .flat_map(|n| {
            let mut bytes = vec![n as u8; 65536];
            bytes[..8].copy_from_slice(&(n as u64).to_le_bytes());
            bytes
        })
        .collect();
    std::fs::write(source.join("nested/dense"), &dense).unwrap();
    std::fs::hard_link(source.join("nested/dense"), source.join("linked")).unwrap();
    let mut sparse = std::fs::File::create(source.join("nested/sparse")).unwrap();
    sparse.set_len(1 << 40).unwrap();
    sparse.seek(SeekFrom::Start((1 << 40) - 4096)).unwrap();
    sparse.write_all(b"tail\r\n\0").unwrap();
    sparse.sync_all().unwrap();
    drop(sparse);
    let protected = node.add_protected_root(&source).unwrap();
    let first_id = Uuid::new_v4();
    let first = node
        .prepare_paged_native_revision_catalog(guild, protected.root_id, &source, 1, first_id)
        .unwrap();
    let first_bytes = canonical_bytes(&first).unwrap();
    assert!(
        node.control
            .get_record("user-revision", first_id.as_bytes())
            .unwrap()
            .is_none()
    );
    assert!(
        node.control
            .get_record(
                "user-revision-head",
                &crate::snapshot::revision_head_id(guild, protected.root_id)
            )
            .unwrap()
            .is_none()
    );
    let second_id = Uuid::new_v4();
    let before_shared = node
        .control
        .catalog_retained_source_usage(first.value.scope())
        .unwrap()
        .unwrap();
    let second = node
        .prepare_paged_native_revision_catalog(guild, protected.root_id, &source, 1, second_id)
        .unwrap();
    assert_eq!(first.value.scope(), second.value.scope());
    let after_shared = node
        .control
        .catalog_retained_source_usage(first.value.scope())
        .unwrap()
        .unwrap();
    assert!(after_shared.stored_sources < 160 && after_shared.reserved_sources == 0);
    assert_eq!(after_shared.stored_sources, before_shared.stored_sources);
    assert_eq!(
        after_shared.stored_logical_bytes,
        before_shared.stored_logical_bytes
    );
    let checkpoint = node.current_checkpoint(guild).unwrap().unwrap();
    let packing_source = mb_store::CatalogPackingSourceRetention {
        id: Uuid::new_v4(),
        base: mb_store::CatalogPackingAuthorityBase {
            guild_id: guild,
            checkpoint_hash: checkpoint.hash().unwrap(),
            generation: checkpoint.checkpoint.generation,
            membership_epoch: checkpoint
                .checkpoint
                .authority
                .map(|authority| authority.membership_epoch),
        },
        budget: capacity().plan().unwrap().job_work,
    };
    node.retain_paged_packing_source(packing_source, &first)
        .unwrap();
    node.retain_paged_packing_source(packing_source, &first)
        .unwrap();
    assert!(node.cancel_paged_native_revision_catalog(first_id).is_err());
    let packing_output = mb_store::CatalogPackingPayloadRetention {
        id: packing_source.id,
        base: packing_source.base,
        budget: packing_source.budget,
    };
    let output_bytes = vec![79; mb_core::V1_SECTOR_SIZE];
    let output_attempt = *Uuid::new_v4().as_bytes();
    let output_storage = [80; 32];
    let output_commitment = mb_core::merkle_commit(&output_bytes).unwrap();
    node.volumes
        .reserve_attempt(
            &node.control,
            &output_attempt,
            guild,
            63,
            output_commitment.byte_len,
        )
        .unwrap();
    node.volumes
        .write_attempt_range(&node.control, &output_attempt, 63, 0, &output_bytes)
        .unwrap();
    let output_receipt = node
        .volumes
        .finish_attempt_upload(
            &node.control,
            &output_attempt,
            output_storage,
            63,
            &output_commitment,
        )
        .unwrap();
    let output = mb_store::CatalogPackingPayload {
        guild_id: guild,
        storage_id: output_storage,
        shard_index: 63,
        commitment: output_commitment,
        attempt_id: output_attempt,
        volume_id: output_receipt.volume_id,
    };
    let mut wrong_output = output.clone();
    wrong_output.commitment = mb_core::merkle_commit(&vec![81; mb_core::V1_SECTOR_SIZE]).unwrap();
    assert!(
        node.retain_paged_packing_payload(packing_output, &wrong_output)
            .is_err()
    );
    node.retain_paged_packing_payload(packing_output, &output)
        .unwrap();
    assert!(
        !node
            .volumes
            .discard_attempt(&node.control, &output_attempt, &BTreeSet::new())
            .unwrap()
    );
    let failed_id = Uuid::new_v4();
    let before_head = node.control.checkpoint_head(&guild).unwrap();
    let sql = format!(
        "CREATE TEMP TRIGGER native_capture_late_authority AFTER INSERT ON protocol_records WHEN NEW.kind='catalog-paged-publication-v1' AND NEW.record_id=X'{}' BEGIN UPDATE checkpoint_heads SET checkpoint_bytes=X'00' WHERE guild_id=X'{}'; END",
        hex::encode(failed_id.as_bytes()),
        hex::encode(guild)
    );
    node.control.database_shell_statement(&sql, false).unwrap();
    assert!(
        node.prepare_paged_native_revision_catalog(guild, protected.root_id, &source, 1, failed_id)
            .is_err()
    );
    assert_eq!(node.control.checkpoint_head(&guild).unwrap(), before_head);
    assert!(
        node.control
            .paged_revision_catalog(failed_id)
            .unwrap()
            .is_none()
    );
    node.control
        .database_shell_statement("DROP TRIGGER native_capture_late_authority", false)
        .unwrap();
    let inventory = crate::inventory_withdrawn_revisions_from_catalog(&node.keys, &state).unwrap();
    assert_eq!(
        inventory
            .local_state
            .pending_captures
            .iter()
            .filter(|capture| capture.record_kind == crate::paged_capture::JOURNAL)
            .count(),
        3
    );
    std::fs::remove_dir_all(&source).unwrap();
    drop(node);
    let mut node = Node::open(&state, seed.clone()).unwrap();
    assert_eq!(
        canonical_bytes(
            &node
                .prepare_paged_native_revision_catalog(
                    guild,
                    protected.root_id,
                    &source,
                    1,
                    first_id
                )
                .unwrap()
        )
        .unwrap(),
        first_bytes
    );
    // The failed publication resumes its exact completed immutable capture.
    // Its original working root is gone, so retry must not recapture it.
    let resumed = node
        .prepare_paged_native_revision_catalog(guild, protected.root_id, &source, 1, failed_id)
        .unwrap();
    assert_eq!(resumed.value.revision_id, failed_id);
    let target = temp.path().join("restored");
    node.restore_retained_native_catalog(first_id, &target)
        .unwrap();
    assert_eq!(std::fs::read(target.join("nested/dense")).unwrap(), dense);
    assert_eq!(
        std::fs::metadata(target.join("nested/dense"))
            .unwrap()
            .ino(),
        std::fs::metadata(target.join("linked")).unwrap().ino()
    );
    assert_eq!(
        std::fs::metadata(target.join("nested/sparse"))
            .unwrap()
            .len(),
        1 << 40
    );
    let mut sparse = std::fs::File::open(target.join("nested/sparse")).unwrap();
    sparse.seek(SeekFrom::Start((1 << 40) - 4096)).unwrap();
    let mut tail = [0; 7];
    sparse.read_exact(&mut tail).unwrap();
    assert_eq!(&tail, b"tail\r\n\0");
    node.retain_paged_packing_source(packing_source, &first)
        .unwrap();
    assert!(node.cancel_paged_native_revision_catalog(first_id).is_err());
    node.retain_paged_packing_payload(packing_output, &output)
        .unwrap();
    assert!(
        !node
            .volumes
            .discard_attempt(&node.control, &output_attempt, &BTreeSet::new())
            .unwrap()
    );
    node.close_paged_packing_payloads(packing_output).unwrap();
    assert!(
        node.release_paged_packing_payload_step(packing_output)
            .unwrap()
    );
    assert!(
        !node
            .release_paged_packing_payload_step(packing_output)
            .unwrap()
    );
    assert!(
        node.volumes
            .discard_attempt(&node.control, &output_attempt, &BTreeSet::new())
            .unwrap()
    );
    node.close_paged_packing_sources(packing_source).unwrap();
    assert!(
        node.retain_paged_packing_source(packing_source, &first)
            .is_err()
    );
    assert!(
        node.release_paged_packing_source_step(packing_source)
            .unwrap()
    );
    assert!(
        !node
            .release_paged_packing_source_step(packing_source)
            .unwrap()
    );
    for id in [first_id, second_id, failed_id] {
        let kind = format!("paged-native-capture-source-v1/{}", id.simple());
        while node
            .control
            .next_record_bounded(&kind, None, 32, 8704)
            .unwrap()
            .is_some()
        {
            let before = node.control.records(&kind).unwrap().len();
            assert!(node.cleanup_paged_native_revision_catalog_step(id).unwrap());
            assert_eq!(node.control.records(&kind).unwrap().len(), before - 1);
        }
        node.cancel_paged_native_revision_catalog(id).unwrap();
        assert!(
            node.prepare_paged_native_revision_catalog(guild, protected.root_id, &source, 1, id)
                .is_err()
        );
    }
    for _ in 0..2000 {
        let mut progress = false;
        for id in [first_id, second_id, failed_id] {
            match node.cleanup_paged_native_revision_catalog_step(id) {
                Ok(value) => progress |= value,
                Err(error) => assert!(
                    error.to_string().contains("owned by a paged data source"),
                    "{error:#}"
                ),
            }
        }
        if !progress {
            break;
        }
    }
    for id in [first_id, second_id, failed_id] {
        assert!(!node.cleanup_paged_native_revision_catalog_step(id).unwrap());
    }
    assert_eq!(
        node.control
            .catalog_retained_source_usage(first.value.scope())
            .unwrap()
            .unwrap()
            .stored_sources,
        0
    );
    drop(node);
    let mut node = Node::open(&state, seed).unwrap();
    for id in [first_id, second_id, failed_id] {
        assert!(!node.cleanup_paged_native_revision_catalog_step(id).unwrap());
    }
}
