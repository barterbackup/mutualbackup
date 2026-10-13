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
