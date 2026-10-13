use super::*;
use mb_store::{CatalogPackingOutputAttempt, CatalogPackingPayload, CatalogPayloadRetirementView};

impl StorageVolumes {
    /// The caller's cancelled-operation writer excludes fresh output custody.
    /// Original READY/migration owners remain independent cleanup obligations.
    pub(crate) fn retire_packing_output(
        &mut self,
        view: &CatalogPayloadRetirementView<'_>,
        guild: [u8; 32],
        planned: &CatalogPackingOutputAttempt,
        payload: Option<&CatalogPackingPayload>,
        cleanup_budget: mb_core::CatalogCodingTraversalBudget,
    ) -> Result<bool> {
        let key = attempt_volume_object_id(&planned.attempt_id, &planned.storage_id, 0);
        let reservation_key = attempt_reservation_id(&planned.attempt_id, 0);
        let active_key = volume_object_id(&planned.storage_id, 0);
        if view.attempt_is_pinned(planned.attempt_id)?
            || view.is_pinned(planned.storage_id, 0, planned.commitment.root)?
        {
            return Ok(false);
        }
        // Active, migrating and copy-cleanup owners cannot be inferred from
        // cancellation of a producer. Their own original lifecycle retires them.
        for kind in [
            "volume-receipt",
            VARIABLE_MIGRATION_KIND,
            "volume-copy-cleanup",
        ] {
            if view.record_exists(kind, &active_key)? {
                return Ok(false);
            }
        }
        let mut volume = payload.map(|p| p.volume_id);
        let mut records = Vec::with_capacity(3);
        for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
            if let Some(bytes) = view.record(kind, &key, MAX_VOLUME_RECEIPT_BYTES)? {
                let r: AttemptVolumeRecord = decode_canonical(&bytes)?;
                validate_attempt_volume_record(&r)?;
                anyhow::ensure!(
                    r.attempt_id == planned.attempt_id
                        && r.receipt.guild_id == guild
                        && r.receipt.group_id == planned.storage_id
                        && r.receipt.shard_index == 0
                        && r.receipt.root == planned.commitment.root
                        && canonical_bytes(&r)? == bytes,
                    "packing cleanup locator conflicts with the original output"
                );
                anyhow::ensure!(
                    volume.is_none_or(|v| v == r.receipt.volume_id),
                    "packing cleanup volumes disagree"
                );
                volume = Some(r.receipt.volume_id);
                records.push((kind, key.clone(), bytes));
            }
        }
        if let Some(bytes) = view.record(
            "volume-attempt-reservation",
            &reservation_key,
            MAX_VOLUME_RECEIPT_BYTES,
        )? {
            let r: AttemptReservationRecord = decode_canonical(&bytes)?;
            validate_attempt_reservation_record(&r)?;
            anyhow::ensure!(
                r.attempt_id == planned.attempt_id
                    && r.guild_id == guild
                    && r.shard_index == 0
                    && r.byte_length == planned.commitment.byte_len
                    && canonical_bytes(&r)? == bytes,
                "packing cleanup reservation conflicts with the original output"
            );
            anyhow::ensure!(
                volume.is_none_or(|v| v == r.volume_id),
                "packing cleanup volumes disagree"
            );
            volume = Some(r.volume_id);
            records.push(("volume-attempt-reservation", reservation_key, bytes));
        }
        let retired = |store: &mut ParityStore| -> Result<bool> {
            Ok(store.discard_coding_attempt_object_checked(
                &planned.attempt_id,
                &guild,
                &planned.storage_id,
                0,
                &planned.commitment,
                || {
                    let pinned = view.attempt_is_pinned(planned.attempt_id).and_then(|a| {
                        Ok(a || view.is_pinned(planned.storage_id, 0, planned.commitment.root)?)
                    });
                    pinned.map_err(|_| DatabaseError::Integrity)
                },
            )?)
        };
        if let Some(volume) = volume {
            let Some(store) = self.volumes.get_mut(&volume).and_then(|v| v.store.as_mut()) else {
                return Ok(false);
            };
            if !retired(store)? {
                return Ok(false);
            }
        } else {
            // Pre-loan failures can precede a locator. Verify exact absence or
            // retire the deterministic attempt across the independently admitted registry;
            // an offline candidate keeps the durable plan for the next pass.
            let visits = u64::try_from(self.volumes.len())?;
            cleanup_budget.remaining_after(mb_core::CatalogCodingTraversalBudget {
                bytes: visits
                    .checked_mul(2 * MAX_VOLUME_RECEIPT_BYTES as u64)
                    .context("packing cleanup traversal overflow")?,
                page_occurrences: 0,
                records: visits
                    .checked_mul(2)
                    .context("packing cleanup traversal overflow")?,
            })?;
            if self.volumes.values().any(|v| v.store.is_none()) {
                return Ok(false);
            }
            for v in self.volumes.values_mut() {
                if !retired(v.store.as_mut().expect("online registry checked"))? {
                    return Ok(false);
                }
            }
        }
        for (kind, key, bytes) in records {
            anyhow::ensure!(
                view.retire_attempt_record(kind, &key, planned.attempt_id, &bytes)?,
                "packing cleanup acquired another owner"
            );
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{CatalogCodingTraversalBudget as Work, Seed, merkle_commit};
    use mb_store::{CatalogPackingAuthorityBase, CatalogPackingPayloadRetention};
    struct Fixture {
        data: tempfile::TempDir,
        keys: Arc<KeyMaterial>,
        control: ControlStore,
        volumes: StorageVolumes,
        plan: CatalogPackingOutputAttempt,
        guild: [u8; 32],
        bytes: Vec<u8>,
    }
    impl Fixture {
        fn new() -> Self {
            let data = tempfile::tempdir().unwrap();
            let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([131; 32])));
            let (control, _) = open_control_store(data.path(), &keys).unwrap();
            let volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
            let bytes = (0..65536)
                .map(|n| (n * 13 + n / 4096) as u8)
                .collect::<Vec<_>>();
            let plan = CatalogPackingOutputAttempt {
                sector_id: [132; 32],
                storage_id: [133; 32],
                sector_index: 0,
                commitment: merkle_commit(&bytes).unwrap(),
                attempt_id: [134; 16],
            };
            Self {
                data,
                keys,
                control,
                volumes,
                plan,
                guild: [135; 32],
                bytes,
            }
        }
        fn reserve(&mut self) {
            self.volumes
                .reserve_attempt(&self.control, &self.plan.attempt_id, self.guild, 0, 65536)
                .unwrap();
        }
        fn upload(&mut self) {
            self.reserve();
            self.volumes
                .write_attempt_range(&self.control, &self.plan.attempt_id, 0, 0, &self.bytes)
                .unwrap();
            self.volumes
                .finish_attempt_upload(
                    &self.control,
                    &self.plan.attempt_id,
                    self.plan.storage_id,
                    0,
                    &self.plan.commitment,
                )
                .unwrap();
        }
        fn retire(&mut self) -> Result<bool> {
            self.retire_with(Work {
                bytes: 1 << 20,
                page_occurrences: 0,
                records: 4096,
            })
        }
        fn retire_with(&mut self, budget: Work) -> Result<bool> {
            let (control, volumes) = (&self.control, &mut self.volumes);
            control.with_catalog_checkpoint_payload_retirement(|view| {
                volumes.retire_packing_output(view, self.guild, &self.plan, None, budget)
            })
        }
        fn volume(&self) -> Uuid {
            if let Some(b) = self
                .control
                .get_record(
                    "volume-attempt-reservation",
                    &attempt_reservation_id(&self.plan.attempt_id, 0),
                )
                .unwrap()
            {
                return decode_canonical::<AttemptReservationRecord>(&b)
                    .unwrap()
                    .volume_id;
            }
            let b = self
                .control
                .get_record(
                    "volume-attempt-receipt",
                    &attempt_volume_object_id(&self.plan.attempt_id, &self.plan.storage_id, 0),
                )
                .unwrap()
                .unwrap();
            decode_canonical::<AttemptVolumeRecord>(&b)
                .unwrap()
                .receipt
                .volume_id
        }
        fn reopen(self) -> Self {
            let Self {
                data,
                keys,
                control,
                volumes,
                plan,
                guild,
                bytes,
            } = self;
            drop(volumes);
            drop(control);
            let (control, _) = open_control_store(data.path(), &keys).unwrap();
            let volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
            Self {
                data,
                keys,
                control,
                volumes,
                plan,
                guild,
                bytes,
            }
        }
    }
    #[test]
    fn exact_volume_cleanup_handles_no_allocation_partial_upload_reopen_and_missing_locators() {
        let mut f = Fixture::new();
        assert!(f.retire_with(Work::default()).is_err());
        assert!(f.retire().unwrap());
        f.reserve();
        f.volumes
            .write_attempt_range(&f.control, &f.plan.attempt_id, 0, 0, &f.bytes[..16])
            .unwrap();
        let mut f = f.reopen();
        assert!(f.retire().unwrap());
        assert!(f.retire().unwrap());
        f.upload();
        let key = attempt_volume_object_id(&f.plan.attempt_id, &f.plan.storage_id, 0);
        f.control
            .delete_record("volume-attempt-receipt", &key)
            .unwrap();
        assert!(f.retire().unwrap());
        assert!(f.retire().unwrap());
    }
    #[test]
    fn exact_volume_cleanup_preserves_offline_and_shared_pending_ownership_until_retry() {
        let mut f = Fixture::new();
        f.upload();
        let volume = f.volume();
        let store = f.volumes.volumes.get_mut(&volume).unwrap().store.take();
        assert!(!f.retire().unwrap());
        assert!(
            f.control
                .get_record(
                    "volume-attempt-receipt",
                    &attempt_volume_object_id(&f.plan.attempt_id, &f.plan.storage_id, 0)
                )
                .unwrap()
                .is_some()
        );
        f.volumes.volumes.get_mut(&volume).unwrap().store = store;
        let loan = CatalogPackingPayloadRetention {
            id: Uuid::new_v4(),
            base: CatalogPackingAuthorityBase {
                guild_id: f.guild,
                checkpoint_hash: [136; 32],
                generation: 1,
                membership_epoch: Some(1),
            },
            budget: Work {
                bytes: 1 << 20,
                page_occurrences: 0,
                records: 100,
            },
        };
        f.control
            .begin_catalog_packing_payload_retention(loan, |_| {
                Ok::<_, mb_store::CatalogStoreError>(())
            })
            .unwrap();
        let payload = CatalogPackingPayload {
            guild_id: f.guild,
            storage_id: f.plan.storage_id,
            shard_index: 0,
            commitment: f.plan.commitment.clone(),
            attempt_id: f.plan.attempt_id,
            volume_id: volume,
        };
        f.control
            .retain_catalog_packing_payload_checked(
                loan,
                &payload,
                (
                    |_| Ok::<_, anyhow::Error>(()),
                    |p| f.volumes.verify_packing_payload(&f.control, p),
                ),
            )
            .unwrap();
        assert!(!f.retire().unwrap());
        f.control
            .cancel_catalog_packing_payload_retention(loan)
            .unwrap();
        assert!(f.control.release_catalog_packing_payload(loan).unwrap());
        let mut f = f.reopen();
        assert!(f.retire().unwrap());
    }
    #[test]
    fn exact_volume_cleanup_keeps_ready_and_migration_owners_and_ignores_unrelated_rows() {
        let mut f = Fixture::new();
        f.upload();
        f.volumes
            .attach_attempt_receipt(
                &f.control,
                &f.plan.attempt_id,
                &f.plan.storage_id,
                0,
                &[137],
            )
            .unwrap();
        f.volumes
            .activate_attempt_object(
                &f.control,
                &f.plan.attempt_id,
                &f.plan.storage_id,
                0,
                &f.plan.commitment,
                &[138; 32],
            )
            .unwrap();
        let active = volume_object_id(&f.plan.storage_id, 0);
        assert!(!f.retire().unwrap());
        f.control.delete_record("volume-receipt", &active).unwrap();
        for kind in [VARIABLE_MIGRATION_KIND, "volume-copy-cleanup"] {
            f.control
                .put_record(
                    kind,
                    &active,
                    b"pending owner; do not classify it as packing garbage",
                )
                .unwrap();
            assert!(!f.retire().unwrap());
            f.control.delete_record(kind, &active).unwrap();
        }
        f.control
            .put_record(
                "volume-attempt-receipt",
                &[139; 49],
                b"unrelated invalid receipt",
            )
            .unwrap();
        assert!(f.retire().unwrap());
        assert!(
            f.control
                .get_record("volume-attempt-receipt", &[139; 49])
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn exact_volume_cleanup_retains_locators_on_control_fault_after_physical_deletion() {
        for action in ["ABORT", "IGNORE"] {
            let mut f = Fixture::new();
            f.upload();
            let volume = f.volume();
            let effect = if action == "ABORT" {
                "RAISE(ABORT,'injected')"
            } else {
                "RAISE(IGNORE)"
            };
            f.control.database_shell_statement(&format!("CREATE TEMP TRIGGER cleanup_fault BEFORE DELETE ON protocol_records WHEN OLD.kind='volume-attempt-receipt' BEGIN SELECT {effect}; END;"),false).unwrap();
            assert!(f.retire().is_err());
            assert_eq!(
                f.volumes
                    .volumes
                    .get(&volume)
                    .unwrap()
                    .store
                    .as_ref()
                    .unwrap()
                    .variable_object_count()
                    .unwrap(),
                0
            );
            assert!(
                f.control
                    .get_record(
                        "volume-attempt-receipt",
                        &attempt_volume_object_id(&f.plan.attempt_id, &f.plan.storage_id, 0)
                    )
                    .unwrap()
                    .is_some()
            );
            let mut f = f.reopen();
            assert!(f.retire().unwrap());
            assert!(f.retire().unwrap());
        }
    }
}
