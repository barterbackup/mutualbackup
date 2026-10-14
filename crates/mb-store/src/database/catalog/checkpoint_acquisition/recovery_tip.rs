//! Verified local recovery progress, separate from current protection heads.
use super::*;
const TIP: &str = "catalog-checkpoint-recovery-tip-v1";
const GUARD: &str = "catalog-checkpoint-recovery-tip-guard-v1";
const KEY: &[u8] = b"primary";
const BYTES: usize = 1024;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointRecoveryTip {
    pub owner: Uuid,
    pub guild_id: [u8; 32],
    pub layout: PagedCheckpointLayout,
    pub generation: u64,
    pub hash: [u8; 32],
}
fn for_job(
    spec: &CatalogCheckpointAcquisition,
) -> Result<CatalogCheckpointRecoveryTip, CatalogStoreError> {
    Ok(CatalogCheckpointRecoveryTip {
        owner: spec.id,
        guild_id: spec.certificate.guild_id(),
        layout: spec.certificate.layout(),
        generation: spec.certificate.generation(),
        hash: spec.certificate.hash()?,
    })
}
pub(super) fn read(
    cx: &Connection,
) -> Result<Option<CatalogCheckpointRecoveryTip>, CatalogStoreError> {
    read_inner(cx, true)
}
fn read_inner(
    cx: &Connection,
    check_ancestry: bool,
) -> Result<Option<CatalogCheckpointRecoveryTip>, CatalogStoreError> {
    let bytes = bounded_record(cx, TIP, KEY, BYTES)?;
    let guard = bounded_record(cx, GUARD, KEY, BYTES)?;
    if bytes != guard {
        return Err(DatabaseError::Integrity.into());
    }
    let Some(bytes) = bytes else { return Ok(None) };
    let tip: CatalogCheckpointRecoveryTip = decode_canonical(&bytes)?;
    if canonical_bytes(&tip)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    let job = super::read(cx, tip.owner)?.ok_or(DatabaseError::Integrity)?;
    if job.state != CatalogCheckpointAcquisitionState::Complete || for_job(&job.spec)? != tip {
        return Err(DatabaseError::Integrity.into());
    }
    job.spec
        .budget
        .remaining_after(job.used.checked_add(work())?)?;
    macro_rules! owner {
        ($header:ty,$cert:expr) => {{
            let row =
                retention_journal::read::<CatalogPagedCheckpointRetention<$header>>(cx, tip.owner)?
                    .ok_or(DatabaseError::Integrity)?;
            if row.state != CatalogPagedCheckpointRetentionState::Published
                || row.retention.checkpoint != $cert.checkpoint
                || row.retention.trust_hash != job.spec.trust_hash
                || row.retention.budget != job.spec.budget
                || paged_checkpoint_retention::owned_certificate(cx, row.retention)?
                    != $cert.clone()
            {
                return Err(DatabaseError::Integrity.into());
            }
        }};
    }
    match &job.spec.certificate {
        CatalogPublicCheckpoint::Individual(c) => owner!(mb_core::PagedGuildCheckpoint, c),
        CatalogPublicCheckpoint::Directory(c) => owner!(mb_core::PagedGuildCheckpointDirectory, c),
    }
    if check_ancestry {
        ancestry::check_parent(cx, &job.spec)?;
    }
    Ok(Some(tip))
}
fn work() -> Work {
    Work {
        bytes: (BYTES * 8) as u64,
        records: 8,
        page_occurrences: 0,
    }
}
pub(super) fn allows_candidate(
    cx: &Connection,
    id: Uuid,
    hash: [u8; 32],
    trust_hash: [u8; 32],
    budget: Work,
) -> Result<bool, CatalogStoreError> {
    let Some(job) = super::read(cx, id)? else {
        return Ok(false);
    };
    if job.state == CatalogCheckpointAcquisitionState::Cancelled
        || job.spec.certificate.hash()? != hash
        || job.spec.trust_hash != trust_hash
        || job.spec.budget != budget
        || capacity_policy::read(cx)? != job.spec.capacity
    {
        return Err(DatabaseError::Conflict.into());
    }
    let tip = read(cx)?;
    let actual = tip.map(|tip| (tip.generation, tip.hash));
    Ok(actual == job.spec.certificate.previous_identity()
        || (job.state == CatalogCheckpointAcquisitionState::Complete
            && tip == Some(for_job(&job.spec)?)))
}
pub(super) fn publish(
    cx: &Connection,
    spec: &CatalogCheckpointAcquisition,
) -> Result<(), CatalogStoreError> {
    let job = super::read(cx, spec.id)?.ok_or(DatabaseError::NotReady)?;
    if job.spec != *spec || job.state != CatalogCheckpointAcquisitionState::Complete {
        return Err(DatabaseError::Conflict.into());
    }
    spec.budget.remaining_after(job.used.checked_add(work())?)?;
    let next = for_job(spec)?;
    let old = read(cx)?;
    if old == Some(next) {
        return Ok(());
    }
    if old.map(|tip| (tip.generation, tip.hash)) != spec.certificate.previous_identity() {
        return Err(DatabaseError::Conflict.into());
    }
    if let Some(previous) = old {
        ancestry::link_parent(cx, spec.id, previous)?;
    }
    let bytes = canonical_bytes(&next)?;
    for name in [TIP, GUARD] {
        match old {
            Some(old) => {
                if cx.execute("UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",params![name,KEY,bytes,canonical_bytes(&old)?])?!=1{return Err(DatabaseError::Integrity.into())}
            }
            None => insert_exact(cx, name, KEY, &bytes)?,
        }
    }
    if read(cx)? != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
impl ControlStore {
    /// Adopt a pre-ancestry recovery tip only after its exact predecessor has
    /// acquired independent public custody. No signed identity is synthesized.
    pub fn adopt_checkpoint_recovery_ancestry(
        &self,
        parent_owner: Uuid,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let tip = read_inner(&tx, false)?.ok_or(DatabaseError::NotReady)?;
        let job = super::read(&tx, tip.owner)?.ok_or(DatabaseError::Integrity)?;
        let certificate =
            ancestry::certificate(&tx, parent_owner)?.ok_or(DatabaseError::NotReady)?;
        let parent = CatalogCheckpointRecoveryTip {
            owner: parent_owner,
            guild_id: certificate.guild_id(),
            layout: certificate.layout(),
            generation: certificate.generation(),
            hash: certificate.hash()?,
        };
        if certificate.guild_id() != job.spec.certificate.guild_id()
            || Some((parent.generation, parent.hash)) != job.spec.certificate.previous_identity()
            || parent.owner == tip.owner
        {
            return Err(DatabaseError::Conflict.into());
        }
        ancestry::link_parent(&tx, tip.owner, parent)?;
        if read(&tx)? != Some(tip) {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(())
    }
    pub fn checkpoint_recovery_tip(
        &self,
    ) -> Result<Option<CatalogCheckpointRecoveryTip>, CatalogStoreError> {
        if !self.connection.is_autocommit() {
            read(&self.connection)
        } else {
            let snapshot = self.read_snapshot()?;
            let value = read(&snapshot)?;
            snapshot.commit()?;
            Ok(value)
        }
    }
    /// Cancel exact local recovery progress, preserving retained public owners
    /// and every original head. Its job cancellation fences late completion.
    pub fn cancel_checkpoint_recovery_tip(
        &self,
        spec: &CatalogCheckpointAcquisition,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let old = super::read(&tx, spec.id)?.ok_or(DatabaseError::NotReady)?;
        if old.spec != *spec {
            return Err(DatabaseError::Conflict.into());
        }
        let tip = read(&tx)?;
        if old.state == CatalogCheckpointAcquisitionState::Cancelled && tip.is_none() {
            tx.commit()?;
            return Ok(());
        }
        if tip != Some(for_job(spec)?) {
            return Err(DatabaseError::Conflict.into());
        }
        for name in [TIP, GUARD] {
            if tx.execute(
                "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
                params![name, KEY, canonical_bytes(&tip.unwrap())?],
            )? != 1
                || bounded_record(&tx, name, KEY, BYTES)?.is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        let next = Job {
            state: CatalogCheckpointAcquisitionState::Cancelled,
            ..old.clone()
        };
        super::write(&tx, &old, &next)?;
        if read(&tx)?.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        tx.commit()?;
        Ok(())
    }
}
