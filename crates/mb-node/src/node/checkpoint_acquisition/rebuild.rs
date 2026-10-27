//! Rebuild original predecessor authority in generation order without advancing
//! recovery progress or reopening cancelled acquisition/private/payload owners.
use super::*;
use mb_store::{CatalogCheckpointRecoverySource as Source, CatalogCheckpointRecoveryTip as Tip};

const STACK: &str = "checkpoint-recovery-proof-stack";
const SOURCE_BYTES: usize = mb_core::PAGED_QUORUM_CHECKPOINT_BYTES + 32768;
const LOOKUP_WORK: Work = Work {
    // Include the bounded shared-ledger integrity scan (at most 64 slots),
    // paired live scopes and the original recovery-custody metadata reads.
    bytes: 8 * 1024 * 1024,
    records: 1024,
    page_occurrences: 0,
};

fn identity(source: &Source) -> Result<Tip> {
    Ok(Tip {
        owner: source.owner,
        guild_id: source.certificate.guild_id(),
        layout: source.certificate.layout(),
        generation: source.certificate.generation(),
        hash: source.certificate.hash()?,
    })
}
pub(super) struct RecoveryWorkMeter<'a> {
    budget: Work,
    used: std::cell::Cell<Work>,
    admission: mb_store::CatalogCheckpointRecoveryWork<'a>,
}
impl RecoveryWorkMeter<'_> {
    pub(super) fn charge(
        &self,
        extra: Work,
    ) -> std::result::Result<(), mb_store::CatalogStoreError> {
        let next = self.used.get().checked_add(extra)?;
        self.budget.remaining_after(next)?;
        self.used.set(next);
        Ok(())
    }
    pub(super) fn guard(&self) -> std::result::Result<(), mb_store::CatalogStoreError> {
        self.charge(LOOKUP_WORK)?;
        self.admission.check()
    }
}
impl RetainedCheckpointRestore {
    /// Reconstruct the complete selected original checkpoint proof after reopen,
    /// including independently owned predecessors whose original owners retired.
    /// The caller declares the whole chain and resource-backed catalogs reserve
    /// it from the shared traversal pool. No durable recovery/protection state
    /// changes. Only the previous and current disposable proof stay live.
    pub fn rebuild_checkpoint_recovery_proof(
        &self,
        budget: Work,
    ) -> Result<RecoveredCheckpointProof> {
        self.rebuild_checkpoint_proof_with_observer(budget, |_| Ok(()))
    }
    pub(crate) fn rebuild_checkpoint_proof_with_observer(
        &self,
        budget: Work,
        mut after_proof: impl FnMut(u64) -> Result<()>,
    ) -> Result<RecoveredCheckpointProof> {
        let control = &self.reader.control;
        // Prepay the tip lookup, admission scans and short release writer,
        // including Drop's cleanup retry after a failed explicit finish. Eight
        // bounded read batches cover these even with all 64 slots occupied.
        // Reserve before scratch or ancestry; validation holds no SQL writer.
        let mut setup = Work::default();
        for _ in 0..8 {
            setup = setup.checked_add(LOOKUP_WORK)?;
        }
        budget.remaining_after(setup)?;
        let selected = control
            .checkpoint_recovery_tip()?
            .context("no selected checkpoint recovery progress")?;
        let mut meter = RecoveryWorkMeter {
            budget,
            used: std::cell::Cell::new(setup),
            admission: control.begin_checkpoint_recovery_work(selected, budget)?,
        };
        let current = || -> Result<()> {
            meter.guard()?;
            anyhow::ensure!(
                control.checkpoint_recovery_tip()? == Some(selected),
                "selected checkpoint recovery progress changed"
            );
            Ok(())
        };
        current()?;
        // Prepay the complete scratch-pool scans/reclamation and separately
        // bounded volume registry before reserving or creating the stack.
        meter.charge(crate::volume::PAGED_SCRATCH_ADMISSION_WORK)?;
        // An exact predecessor chain inserts and removes one bounded Source
        // row per original generation. Keep the independent database/work caps.
        let stack_limits = mb_store::ScratchStorageLimits::for_record_writes(
            selected.generation.saturating_mul(SOURCE_BYTES as u64),
            selected.generation.saturating_mul(2),
            64,
            budget.bytes.min(mb_core::CATALOG_MAX_STREAM_BYTES * 4),
        )?;
        let stack = crate::volume::paged_scratch_store(control, stack_limits.max_database_bytes)
            .context("fund checkpoint ancestry stack scratch")?;
        #[cfg(target_os = "linux")]
        let mut maxima = [0u64; 4];
        let mut wanted = selected;
        loop {
            meter.guard()?;
            current()?;
            let source = control
                .checkpoint_recovery_source(wanted.owner)?
                .context("checkpoint ancestry source is unavailable")?;
            anyhow::ensure!(
                identity(&source)? == wanted,
                "checkpoint ancestry source changed identity"
            );
            // Each validator uses the source's original enclosing budget. Admit
            // all eight pipeline components before metadata scans or scratch
            // publication, in addition to bounded custody/stack read credits.
            for _ in 0..8 {
                meter.charge(source.budget)?;
            }
            #[cfg(target_os = "linux")]
            {
                // Only the previous/current proofs coexist. Plan alternating
                // slots from complete original descriptors, without replaying
                // history or fetching authority/packing/coding pages yet.
                let lane = wanted
                    .generation
                    .checked_sub(1)
                    .context("checkpoint generation is zero")?
                    % 2;
                let history = mb_store::CatalogGuildHistoryIndex::scratch_storage_limits(
                    source.certificate.event_sequence(),
                    source.budget,
                )?;
                // This exact chain has a root at generation one and all later
                // predecessors are paged proofs, not legacy vector bridges.
                let body = source
                    .certificate
                    .scratch_storage_limits(None, source.budget)?;
                let offset = lane as usize * 2;
                maxima[offset] = maxima[offset].max(history.max_database_bytes);
                maxima[offset + 1] = maxima[offset + 1].max(body.max_database_bytes);
            }
            let bytes = mb_core::canonical_bytes_bounded(&source, SOURCE_BYTES)?;
            let key = wanted.generation.to_be_bytes();
            anyhow::ensure!(
                stack.put_record_if_absent(STACK, &key, &bytes)?,
                "duplicate checkpoint ancestry generation"
            );
            anyhow::ensure!(
                stack
                    .get_record_bounded(STACK, &key, SOURCE_BYTES)?
                    .as_deref()
                    == Some(bytes.as_slice()),
                "checkpoint proof stack write did not persist"
            );
            current()?;
            match source.parent {
                Some(parent) => {
                    anyhow::ensure!(
                        parent.guild_id == selected.guild_id
                            && parent.generation.checked_add(1) == Some(wanted.generation)
                            && Some((parent.generation, parent.hash))
                                == source.certificate.previous_identity(),
                        "checkpoint ancestry is not an exact predecessor"
                    );
                    wanted = parent;
                }
                None => {
                    anyhow::ensure!(
                        wanted.generation == 1 && source.certificate.previous_identity().is_none(),
                        "checkpoint ancestry has no original root"
                    );
                    break;
                }
            }
        }
        #[cfg(target_os = "linux")]
        let prepaid = if control.catalog_resource_policy()?.is_some() {
            let count = if selected.generation == 1 { 2 } else { 4 };
            for _ in 0..count {
                meter.charge(crate::volume::PAGED_SCRATCH_ADMISSION_WORK)?;
            }
            // Fund every live-proof slot before the first history/payload page.
            // Index closure returns its VFS to the prepaid slot; reuse never
            // acquires another credit lease or initializes another backing.
            Some(if count == 2 {
                let pair =
                    crate::volume::paged_scratch_workspaces(control, [maxima[0], maxima[1]])?
                        .context("enrolled checkpoint rebuild lacks scratch ownership")?;
                vec![pair]
            } else {
                let [history0, body0, history1, body1] =
                    crate::volume::paged_scratch_workspaces(control, maxima)?
                        .context("enrolled checkpoint rebuild lacks scratch ownership")?;
                vec![[history0, body0], [history1, body1]]
            })
        } else {
            None
        };
        let mut previous: Option<RecoveredCheckpointProof> = None;
        let mut after: Option<[u8; 8]> = None;
        let mut generation = 0u64;
        while let Some((key, bytes)) = stack.next_record_bounded(
            STACK,
            after.as_ref().map(|k| k.as_slice()),
            8,
            SOURCE_BYTES,
        )? {
            current()?;
            let key: [u8; 8] = key
                .try_into()
                .map_err(|_| mb_store::DatabaseError::Integrity)?;
            let source: Source = decode_canonical(&bytes)?;
            anyhow::ensure!(
                mb_core::canonical_bytes_bounded(&source, SOURCE_BYTES)? == bytes
                    && source.certificate.generation() == u64::from_be_bytes(key)
                    && generation.checked_add(1) == Some(source.certificate.generation()),
                "checkpoint proof stack has a gap or changed record"
            );
            let expected = previous
                .as_ref()
                .map(|p| -> Result<_> {
                    let c = p.certificate();
                    Ok((c.generation(), c.hash()?))
                })
                .transpose()?;
            anyhow::ensure!(
                source.certificate.previous_identity() == expected,
                "checkpoint proof stack changed ancestry"
            );
            let proof = self.promote_public_checkpoint_inner(
                ProofInput::Retained {
                    source: &source,
                    selected,
                    previous: previous.as_ref(),
                    meter: &meter,
                    #[cfg(target_os = "linux")]
                    workspaces: prepaid
                        .as_ref()
                        .map(|pairs| &pairs[((source.certificate.generation() - 1) % 2) as usize]),
                },
                previous.as_ref().map(RecoveredCheckpointProof::previous),
            )?;
            proof.verify()?;
            stack.delete_record_if_value(STACK, &key, &bytes)?;
            generation = source.certificate.generation();
            after_proof(generation)?;
            current()?;
            after = Some(key);
            previous = Some(proof);
        }
        current()?;
        let proof = previous.context("checkpoint proof stack is empty")?;
        anyhow::ensure!(
            generation == selected.generation
                && proof.certificate().hash()? == selected.hash
                && proof.certificate().layout() == selected.layout
                && proof.certificate().guild_id() == selected.guild_id,
            "checkpoint proof stack did not reach selected progress"
        );
        meter.admission.finish()?;
        Ok(proof)
    }
}
