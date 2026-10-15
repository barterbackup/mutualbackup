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
        // The fixed-size tip lookup and reservation's before/after integrity
        // scans are bounded setup work. Reserve before any scratch or ancestry
        // traversal; no SQLite writer stays open across validation.
        let setup = LOOKUP_WORK.checked_add(LOOKUP_WORK)?;
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
        // Scratch admission also enumerates the separately bounded volume
        // registry and its checkpoint/headroom descriptors.
        meter.charge(LOOKUP_WORK)?;
        let stack = crate::volume::paged_scratch_store(
            control,
            budget.bytes.min(mb_core::CATALOG_MAX_STREAM_BYTES * 4),
        )?;
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
                },
                previous.as_ref().map(RecoveredCheckpointProof::previous),
            )?;
            proof.verify()?;
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
