use super::*;
use crate::volume::native_node::tests::{footprint, policy};

#[test]
fn managed_default_volume_resumes_interrupted_record_quota_before_reconciliation() {
    interrupted_native_parity_quota(false);
}

#[test]
fn managed_additional_volume_resumes_interrupted_record_quota_before_reconciliation() {
    interrupted_native_parity_quota(true);
}

fn interrupted_native_parity_quota(additional: bool) {
    let temp = tempfile::tempdir().unwrap();
    if let Err(error) = resume_native_parity_quota(temp.path(), additional) {
        let preserved = temp.keep();
        panic!("native record-quota restart failed: {error:#}; preserved={preserved:?}");
    }
}

fn resume_native_parity_quota(root: &Path, additional: bool) -> Result<()> {
    use mb_store::{DatabaseRecordQuota, DatabaseRecordQuotaState};
    let data = root.join("node");
    let seed = Seed::from_bytes([88; 32]);
    let mut node = Node::create_native(&data, seed.clone(), policy())?;
    let volume_id = if additional {
        let extra = root.join("extra");
        fs::create_dir(&extra)?;
        node.create_native_storage_volume(
            &extra,
            crate::NativeParityVolumePolicy {
                database: mb_core::NativeDatabaseIoPolicy {
                    policy_id: [47; 16],
                    ..policy().default_parity
                },
                parity_budget_bytes: policy().parity_budget_bytes,
            },
        )?
    } else {
        node.volumes.reader_configs()[0].volume_id
    };
    let bytes = vec![36; mb_core::V1_SECTOR_SIZE];
    let object = ParityObject {
        format_version: 1,
        guild_id: [37; 32],
        group_id: [38; 32],
        shard_index: 2,
        root: sector_root(&bytes),
        bytes,
    };
    let quota = DatabaseRecordQuota {
        max_rows: 10_000,
        max_accounted_bytes: 4 << 20,
    };
    let (partial, original_key, wrapped_key, physical_policy) = {
        let config = node
            .volumes
            .reader_configs()
            .into_iter()
            .find(|config| config.volume_id == volume_id)
            .unwrap();
        let mut parity = config.open()?;
        parity.stage_and_publish_ack(&object, b"original ACK", policy().parity_budget_bytes)?;
        // Cross a bounded scan's 128-row limit, retaining a durable row cursor.
        for index in 1..=140_u128 {
            parity.reserve_coding_attempt(
                &index.to_be_bytes(),
                &object.guild_id,
                0,
                64,
                policy().parity_budget_bytes,
            )?;
        }
        parity.begin_record_quota_adoption(quota)?;
        for _ in 0..3 {
            parity.resume_record_quota_adoption()?;
        }
        let partial = parity.record_quota_usage()?.unwrap();
        anyhow::ensure!(
            partial.state == DatabaseRecordQuotaState::Adopting && partial.last_rowid.is_some(),
            "fixture must interrupt a partially scanned table"
        );
        let owner = parity.native_database_owner().unwrap();
        (
            partial,
            config.database_key,
            owner.wrapped_key().clone(),
            owner.policy(),
        )
    };
    drop(node);
    let node = Node::open(&data, seed.clone())?;
    let complete = {
        let config = node
            .volumes
            .reader_configs()
            .into_iter()
            .find(|config| config.volume_id == volume_id)
            .context("managed volume must remain online after restart")?;
        anyhow::ensure!(config.database_key == original_key, "native key changed");
        let mut parity = config.open()?;
        let complete = parity.record_quota_usage()?.unwrap();
        anyhow::ensure!(
            complete.state == DatabaseRecordQuotaState::Active,
            "quota remains Adopting"
        );
        anyhow::ensure!(complete.quota == quota, "original quota changed");
        anyhow::ensure!(
            complete.rows > partial.rows && complete.accounted_bytes > partial.accounted_bytes
        );
        let rows = parity.database_shell_statement(
            "SELECT (SELECT count(*) FROM meta) + (SELECT count(*) FROM parity_objects) + (SELECT count(*) FROM coding_reservations)",
            true,
        )?;
        anyhow::ensure!(
            rows.rows == vec![vec![complete.rows.to_string()]],
            "incomplete row accounting"
        );
        let owner = parity.native_database_owner().unwrap();
        anyhow::ensure!(owner.policy() == physical_policy && owner.wrapped_key() == &wrapped_key);
        owner.verify_current()?;
        anyhow::ensure!(
            parity
                .physical_io_allocated_bytes()?
                .is_some_and(|bytes| bytes > 0 && bytes <= physical_policy.total_bytes)
        );
        anyhow::ensure!(parity.load_ready(&object.group_id, object.shard_index)? == object);
        anyhow::ensure!(parity.publication_is_complete(&object, b"original ACK")?);
        // Ordinary reservations and publication must succeed immediately.
        parity.reserve_coding_attempt(
            &[9; 16],
            &object.guild_id,
            0,
            64,
            policy().parity_budget_bytes,
        )?;
        let next = ParityObject {
            group_id: [39; 32],
            ..object.clone()
        };
        parity.stage_and_publish_ack(&next, b"followup ACK", policy().parity_budget_bytes)?;
        anyhow::ensure!(parity.publication_is_complete(&next, b"followup ACK")?);
        let after = parity.record_quota_usage()?.unwrap();
        anyhow::ensure!(
            after.rows == complete.rows + 2 && after.accounted_bytes > complete.accounted_bytes
        );
        after
    };
    drop(node);
    let node = Node::open(&data, seed)?;
    let config = node
        .volumes
        .reader_configs()
        .into_iter()
        .find(|config| config.volume_id == volume_id)
        .unwrap();
    let parity = config.open()?;
    anyhow::ensure!(
        parity.record_quota_usage()? == Some(complete),
        "reopen changed completed counters"
    );
    anyhow::ensure!(parity.publication_is_complete(&object, b"original ACK")?);
    Ok(())
}

#[test]
fn managed_node_preserves_normal_control_parity_ack_and_reader_lifetimes() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    let mut node = Node::create_native(temp.path(), seed.clone(), policy()).unwrap();
    node.configure_retention(7).unwrap();
    let bytes = vec![36; mb_core::V1_SECTOR_SIZE];
    let object = ParityObject {
        format_version: 1,
        guild_id: [37; 32],
        group_id: [38; 32],
        shard_index: 2,
        root: sector_root(&bytes),
        bytes,
    };
    let receipt = node
        .volumes
        .store(&node.control, &object, b"native acknowledgement")
        .unwrap();
    let config = node.reader_config();
    let reader = config.open().unwrap();
    assert_eq!(
        reader
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
    drop(node);
    assert!(Node::open(temp.path(), seed.clone()).is_err());
    assert_eq!(
        reader
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
    drop((reader, config));
    let node = Node::open(temp.path(), seed).unwrap();
    assert_eq!(node.retention_revisions().unwrap(), 7);
    let parity = node
        .volumes
        .reader_configs()
        .into_iter()
        .find(|config| config.volume_id == receipt.volume_id)
        .unwrap()
        .open()
        .unwrap();
    assert!(
        parity
            .publication_is_complete(&object, b"native acknowledgement")
            .unwrap()
    );
    let reader = node.reader_config().open_for_retained_restore().unwrap();
    assert_eq!(
        reader
            .parity_for_guild(&object.guild_id, &object.group_id, object.shard_index)
            .unwrap(),
        object.bytes
    );
}

#[test]
fn managed_control_handoff_rejects_sql_profile_and_birth_substitution_before_writes() {
    for substitution in ["main", "wal", "profile", "birth"] {
        let temp = tempfile::tempdir().unwrap();
        let data = temp.path().to_path_buf();
        let seed = Seed::from_bytes([88; 32]);
        drop(Node::create_native(&data, seed.clone(), policy()).unwrap());
        let after = std::rc::Rc::new(std::cell::RefCell::new(None));
        let captured = after.clone();
        let visible = data.clone();
        BEFORE_CONTROL_WRITER.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                match substitution {
                    "main" => {
                        fs::rename(visible.join("control.db"), visible.join("original.db"))
                            .unwrap();
                        fs::copy(visible.join("original.db"), visible.join("control.db")).unwrap();
                    }
                    "wal" => {
                        fs::write(visible.join("control.db-wal"), b"unadmitted journal").unwrap()
                    }
                    "profile" => {
                        let file = visible.join("native-storage.profile");
                        fs::rename(&file, visible.join("original-profile")).unwrap();
                        fs::copy(visible.join("original-profile"), file).unwrap();
                    }
                    "birth" => {
                        let name = format!(
                            ".mutualbackup-native-{}",
                            blake3::hash(b"control.db").to_hex()
                        );
                        let file = visible.join(name).join("birth");
                        fs::rename(&file, file.with_file_name("original-birth")).unwrap();
                        fs::copy(file.with_file_name("original-birth"), file).unwrap();
                    }
                    _ => unreachable!(),
                }
                *captured.borrow_mut() = Some(footprint(&visible));
            }))
        });
        assert!(Node::open(&data, seed).is_err(), "{substitution}");
        assert_eq!(
            footprint(&data),
            after.borrow_mut().take().unwrap(),
            "{substitution}"
        );
    }
}

#[test]
fn managed_configuration_cannot_create_legacy_volumes_or_inflate_physical_capacity() {
    let temp = tempfile::tempdir().unwrap();
    let seed = Seed::from_bytes([88; 32]);
    let mut node = Node::create_native(temp.path(), seed.clone(), policy()).unwrap();
    let before = node
        .coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
        .unwrap();
    assert!(before > 0);
    assert!(before <= policy().default_parity.journal_bytes / (mb_core::V1_SECTOR_SIZE as u64 * 3));
    node.configure_parity_budget(u64::MAX).unwrap();
    assert_eq!(
        node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
            .unwrap(),
        before
    );
    let extra = tempfile::tempdir().unwrap();
    let registry = node
        .control
        .get_record("node-config", b"storage-volumes")
        .unwrap();
    let extra_before = footprint(extra.path());
    assert!(
        node.configure_storage_volumes(&[extra.path().to_owned()], 8 << 20, 0)
            .is_err()
    );
    assert_eq!(footprint(extra.path()), extra_before);
    assert_eq!(
        node.control
            .get_record("node-config", b"storage-volumes")
            .unwrap(),
        registry
    );
    drop(node);
    let node = Node::open(temp.path(), seed).unwrap();
    assert_eq!(
        node.control.native_database_owner().unwrap().policy(),
        policy().control
    );
    assert_eq!(
        node.coding_capacity(mb_core::V1_SECTOR_SIZE as u32)
            .unwrap(),
        before
    );
}
