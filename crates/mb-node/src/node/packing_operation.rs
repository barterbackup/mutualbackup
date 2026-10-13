//! Explicit retained packing construction. Normal backup/coding/activation is
//! still gated on complete shared admission and distributed availability.
use super::*;

impl Node {
    /// Rebuild original trusted authority and independently check complete input
    /// custody before any packing read. This entry point owns emitted pages,
    /// planned physical attempts and exact output loans, but publishes no head.
    pub fn produce_retained_packing_operation(
        &mut self,
        operation: mb_store::CatalogPackingOperation,
        source: mb_store::CatalogPackingAuthority,
        mut source_custody: impl FnMut(
            &mb_store::CatalogPackingOperationView<'_>,
            &mb_store::CatalogPackingAuthority,
        ) -> Result<()>,
        render: impl FnMut(
            &mb_store::CatalogPackingAuthorizedSource,
            &mut [u8],
        ) -> std::result::Result<(), mb_store::CatalogStoreError>,
    ) -> Result<mb_store::CatalogCertifiedPackingDirectoryIndex> {
        let policy = self
            .control
            .catalog_capacity_policy()?
            .context("packing operation requires explicit capacity admission")?;
        anyhow::ensure!(
            operation.policy == policy
                && operation.source_budget == policy.plan()?.job_work
                && operation.payload_budget == policy.plan()?.job_work
                && self
                    .control
                    .record_quota_usage()?
                    .is_some_and(|usage| usage.state == mb_store::DatabaseRecordQuotaState::Active)
                && self.control.page_quota_usage()?.is_some()
                && self.control.journal_quota_usage()?.is_some()
                && self.control.catalog_storage_usage()?.is_some()
                && self
                    .control
                    .catalog_guild_storage_usage(operation.base.guild_id)?
                    .is_some(),
            "packing operation requires active database and guild admission"
        );
        let authority = guild_authority::frozen_original_history(&self.control)?;
        anyhow::ensure!(
            authority.snapshot().guild_id == operation.base.guild_id
                && authority
                    .snapshot()
                    .active_members()
                    .any(|member| member.node_id == self.keys.node_id()),
            "packing producer is not a current guild member"
        );
        let control = &self.control;
        let current = || -> Result<()> {
            authority.check()?;
            control.check_catalog_capacity_policy(policy)?;
            anyhow::ensure!(
                control.checkpoint_head_identity(&operation.base.guild_id)?
                    == Some((operation.base.generation, operation.base.checkpoint_hash)),
                "packing operation checkpoint base changed"
            );
            Ok(())
        };
        let volumes = std::cell::RefCell::new(&mut self.volumes);
        let result = control.produce_catalog_packing_operation_checked(
            operation,
            source,
            (
                |_| current(),
                |view, source| {
                    current()?;
                    source_custody(view, source)
                },
            ),
            (render, |sector, planned| {
                let result = (|| -> Result<mb_store::CatalogPackingPayload> {
                    current()?;
                    let mut volumes = volumes.borrow_mut();
                    // The operation's exact planned row precedes this original
                    // volume reservation, including crashes before output loans.
                    volumes.reserve_attempt(
                        control,
                        &planned.attempt_id,
                        operation.base.guild_id,
                        0,
                        planned.commitment.byte_len,
                    )?;
                    for (index, bytes) in sector.bytes.chunks(mb_core::V1_SECTOR_SIZE).enumerate() {
                        current()?;
                        volumes.write_attempt_range(
                            control,
                            &planned.attempt_id,
                            0,
                            u32::try_from(index * mb_core::V1_SECTOR_SIZE)?,
                            bytes,
                        )?;
                    }
                    let receipt = volumes.finish_attempt_upload(
                        control,
                        &planned.attempt_id,
                        planned.storage_id,
                        0,
                        &planned.commitment,
                    )?;
                    let output = mb_store::CatalogPackingPayload {
                        guild_id: operation.base.guild_id,
                        storage_id: planned.storage_id,
                        shard_index: 0,
                        commitment: planned.commitment.clone(),
                        attempt_id: planned.attempt_id,
                        volume_id: receipt.volume_id,
                    };
                    control.retain_catalog_packing_payload_checked(
                        operation.payloads(),
                        &output,
                        (
                            |_| current(),
                            |payload| volumes.verify_packing_payload(control, payload),
                        ),
                    )?;
                    current()?;
                    Ok(output)
                })();
                result.map_err(|_| {
                    mb_store::CatalogStoreError::Database(mb_store::DatabaseError::Conflict)
                })
            }),
            |payload| {
                current()?;
                volumes.borrow().verify_packing_payload(control, payload)
            },
        )?;
        current()?;
        Ok(result)
    }

    /// Transfer one completed packing output into its original signed coding
    /// information role. Both attempts retain independent physical ownership;
    /// only the existing verified transcript lifecycle can make the role READY.
    pub fn stage_retained_packing_information(
        &mut self,
        operation: mb_store::CatalogPackingOperation,
        proof: &mb_store::CatalogCertifiedPackingDirectoryIndex,
        plan: &SignedRecord<CodingAttemptPlan>,
        shard_index: u16,
    ) -> Result<()> {
        let role = self.validate_local_coding_information(plan, shard_index)?;
        anyhow::ensure!(
            !role.sector.virtual_zero
                && plan.value.checkpoint_hash == operation.base.checkpoint_hash
                && plan.value.geometry.guild_id == operation.base.guild_id
                && plan.value.geometry.profile == operation.policy.coding_profile
                && operation
                    .base
                    .membership_epoch
                    .is_none_or(|epoch| epoch == plan.value.membership_epoch)
                && proof.base() == operation.base
                && proof.operation_identity() == operation.source_identity,
            "coding information does not belong to this packing operation"
        );
        let sector = proof
            .sector(role.sector.id)?
            .context("coding information is absent from the completed packing proof")?;
        let expected_root = match (
            plan.value.format_version,
            proof.manifest().directory.packing_version,
        ) {
            (2, 1..=3) => sector.flat_root,
            (3, 1 | 2) => sector.flat_root,
            _ => anyhow::bail!("new packed information requires an original root-bound plan"),
        };
        anyhow::ensure!(
            role.sector.commitment == sector.commitment
                && role.sector.logical_len == sector.commitment.byte_len
                && plan.value.information_root(usize::from(shard_index)) == Some(expected_root),
            "coding information changed its original packing roots"
        );
        let control = &self.control;
        let authority = guild_authority::frozen_original_history(control)?;
        let check = || -> Result<()> {
            authority.check()?;
            anyhow::ensure!(
                control.catalog_capacity_policy()? == Some(operation.policy)
                    && control.checkpoint_head_identity(&operation.base.guild_id)?
                        == Some((operation.base.generation, operation.base.checkpoint_hash))
                    && control.catalog_packing_operation(operation.id)?
                        == Some((
                            operation,
                            mb_store::CatalogPackingOperationState::PackingComplete(
                                proof.manifest()
                            )
                        )),
                "completed packing authority changed during coding transfer"
            );
            authority
                .snapshot()
                .validate_attempt_authority(&plan.value)?;
            anyhow::ensure!(
                plan.value.expires_at_unix_seconds >= unix_seconds(),
                "coding attempt has expired"
            );
            Ok(())
        };
        check()?;
        let (planned, payload) = control.catalog_completed_packing_output(operation, sector.id)?;
        anyhow::ensure!(
            planned.sector_index == sector.index
                && planned.commitment == sector.commitment
                && payload.commitment.byte_len as usize == mb_core::V1_SECTOR_SIZE,
            "completed packing output changed its original descriptor"
        );
        // CAPP fixes newly packed sectors at 64 KiB. Existing wider coding
        // profiles retain their original upload path and compatibility limits.
        let volumes = &mut self.volumes;
        volumes.verify_packing_payload(control, &payload)?;
        let opening = volumes.open_attempt_range(
            control,
            &payload.attempt_id,
            &payload.storage_id,
            payload.shard_index,
            0,
            (mb_core::V1_SECTOR_SIZE / mb_core::MERKLE_LEAF_SIZE) as u32,
        )?;
        let bytes = mb_core::merkle_verify_range(&sector.commitment, &opening)?;
        if proof.manifest().directory.packing_version < 3 {
            anyhow::ensure!(
                mb_core::sector_root(&bytes) == sector.flat_root,
                "completed packing bytes changed their original flat root"
            );
        }
        check()?;
        if volumes
            .load_ready_variable(control, &sector.id, shard_index)
            .is_ok_and(|ready| {
                ready.guild_id == operation.base.guild_id && ready.commitment == sector.commitment
            })
        {
            check()?;
            return Ok(());
        }
        // A finished STAGED upload also survives reopen. Reauthenticate its
        // exact original bytes before retiring a leftover reservation.
        let output_key = crate::volume::attempt_volume_object_id(
            &plan.value.attempt_id,
            &sector.id,
            u8::try_from(shard_index)?,
        );
        if control
            .record_length("volume-attempt-receipt", &output_key)?
            .is_some()
            || control
                .record_length("volume-attempt-intent", &output_key)?
                .is_some()
        {
            let opening = volumes.open_attempt_range(
                control,
                &plan.value.attempt_id,
                &sector.id,
                shard_index,
                0,
                (mb_core::V1_SECTOR_SIZE / mb_core::MERKLE_LEAF_SIZE) as u32,
            )?;
            anyhow::ensure!(
                mb_core::merkle_verify_range(&sector.commitment, &opening)? == bytes,
                "staged coding information differs from its retained packing output"
            );
        } else {
            volumes.reserve_attempt(
                control,
                &plan.value.attempt_id,
                operation.base.guild_id,
                shard_index,
                sector.commitment.byte_len,
            )?;
            check()?;
            volumes.write_attempt_range(control, &plan.value.attempt_id, shard_index, 0, &bytes)?;
            check()?;
        }
        volumes.finish_attempt_upload(
            control,
            &plan.value.attempt_id,
            sector.id,
            shard_index,
            &sector.commitment,
        )?;
        check()?;
        anyhow::ensure!(
            control.catalog_completed_packing_output(operation, sector.id)? == (planned, payload),
            "packing output ownership changed during coding transfer"
        );
        Ok(())
    }

    /// Retire one indexed temporary output after cancellation and explicit
    /// loan release. False retains offline/shared/READY-migration obligations;
    /// the durable cursor can visit other outputs and revisit this one later.
    pub fn retire_retained_packing_output(
        &mut self,
        operation: mb_store::CatalogPackingOperation,
        planned: &mb_store::CatalogPackingOutputAttempt,
    ) -> Result<bool> {
        let control = &self.control;
        let volumes = &mut self.volumes;
        control.retire_catalog_packing_operation_output_checked(
            operation,
            planned,
            |_| Ok::<_, anyhow::Error>(()),
            |view, planned, payload| {
                volumes.retire_packing_output(
                    view,
                    operation.base.guild_id,
                    planned,
                    payload,
                    operation.construction_budget()?,
                )
            },
        )
    }

    pub fn cancel_retained_packing_operation(
        &self,
        operation: mb_store::CatalogPackingOperation,
    ) -> Result<()> {
        self.control.cancel_catalog_packing_operation(operation)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
