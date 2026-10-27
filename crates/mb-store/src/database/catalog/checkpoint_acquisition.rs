//! Durable public-page staging. Complete retained proof publication, rather
//! than a header signature or downloaded prefix, authorizes the final handoff.
use super::*;
use mb_core::{CatalogCodingTraversalBudget as Work, PagedCheckpointLayout, PagedCheckpointTrust};

mod ancestry;
mod recovery_source;
mod recovery_tip;
pub(super) mod work_admission;
pub use recovery_source::CatalogCheckpointRecoverySource;
pub use recovery_tip::CatalogCheckpointRecoveryTip;
pub use work_admission::{
    CATALOG_ACQUISITION_WORK_JOBS, CatalogAcquisitionWorkState, CatalogAcquisitionWorkUsage,
    CatalogCheckpointRecoveryWork, CatalogTraversalPoolPolicy,
};
pub(super) fn recovery_candidate(
    cx: &Connection,
    id: Uuid,
    hash: [u8; 32],
    trust_hash: [u8; 32],
    budget: Work,
) -> Result<bool, CatalogStoreError> {
    recovery_tip::allows_candidate(cx, id, hash, trust_hash, budget)
}
pub(super) fn recovery_owner(cx: &Connection, id: Uuid) -> Result<bool, CatalogStoreError> {
    Ok(recovery_tip::read(cx)?.is_some_and(|tip| tip.owner == id))
}

const JOB: &str = "catalog-checkpoint-acquisition-v1";
const GUARD: &str = "catalog-checkpoint-acquisition-guard-v1";
const BYTES: usize =
    mb_core::PAGED_QUORUM_CHECKPOINT_BYTES + mb_core::GUILD_AUTHORITY_SNAPSHOT_BYTES + 32768;
const ROOT_BYTES: usize = 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPublicCheckpoint {
    Individual(mb_core::QuorumPagedCheckpoint),
    Directory(mb_core::QuorumPagedCheckpointDirectory),
}
impl CatalogPublicCheckpoint {
    pub fn layout(&self) -> PagedCheckpointLayout {
        match self {
            Self::Individual(_) => PagedCheckpointLayout::Individual,
            Self::Directory(_) => PagedCheckpointLayout::Directory,
        }
    }
    pub fn hash(&self) -> Result<[u8; 32], CatalogStoreError> {
        Ok(match self {
            Self::Individual(c) => c.hash()?,
            Self::Directory(c) => c.hash()?,
        })
    }
    pub fn guild_id(&self) -> [u8; 32] {
        match self {
            Self::Individual(c) => c.checkpoint.guild_id,
            Self::Directory(c) => c.checkpoint.guild_id,
        }
    }
    pub fn generation(&self) -> u64 {
        match self {
            Self::Individual(c) => c.checkpoint.generation,
            Self::Directory(c) => c.checkpoint.generation,
        }
    }
    pub fn event_sequence(&self) -> u64 {
        match self {
            Self::Individual(c) => c.checkpoint.event_sequence,
            Self::Directory(c) => c.checkpoint.event_sequence,
        }
    }
    pub fn previous_identity(&self) -> Option<(u64, [u8; 32])> {
        match self {
            Self::Individual(c) => c
                .checkpoint
                .parent
                .map(|hash| (c.checkpoint.generation.saturating_sub(1), hash)),
            Self::Directory(c) => c
                .checkpoint
                .parent
                .map(|hash| (c.checkpoint.generation.saturating_sub(1), hash)),
        }
    }
    pub fn authority(&self) -> mb_core::CatalogCheckpointAuthorityRoot {
        match self {
            Self::Individual(c) => c.checkpoint.authority_root,
            Self::Directory(c) => c.checkpoint.authority_root,
        }
    }
    pub fn coding(&self) -> mb_core::CatalogCodingDirectoryRoot {
        match self {
            Self::Individual(c) => c.checkpoint.coding,
            Self::Directory(c) => c.checkpoint.coding,
        }
    }
    /// Bound the complete authority/packing/coding/transition scratch index
    /// from authenticated complete root declarations, without fetching pages.
    /// This sizing result is not a certificate or an authorization token.
    pub fn scratch_storage_limits(
        &self,
        previous: Option<CatalogCheckpointPrevious<'_>>,
        budget: Work,
    ) -> Result<crate::ScratchStorageLimits, CatalogStoreError> {
        match self {
            Self::Individual(c) => c.checkpoint.validate_header(budget)?,
            Self::Directory(c) => c.checkpoint.validate_header(budget)?,
        }
        let authority = self.authority();
        // Every nested sector occurrence contains a 32-byte SectorId, whether
        // in a legacy envelope or a paged sector frame. There is no run form.
        let source_occurrences = (u128::from(authority.summary.source_bytes)
            + u128::from(authority.summary.legacy_bytes))
            / 32;
        let packing = match self {
            Self::Individual(c) => {
                u128::from(c.checkpoint.packed_sources.sources)
                    + u128::from(c.checkpoint.packed_sources.chunks)
                    + u128::from(c.checkpoint.packed_sectors.sectors)
                    + 2
            }
            Self::Directory(c) => {
                let s = c.checkpoint.packing.summary;
                u128::from(s.sources)
                    + u128::from(s.source_chunks)
                    + u128::from(s.sectors)
                    + u128::from(s.source_parts)
                    + u128::from(s.sector_parts)
            }
        };
        let coding = self.coding().summary;
        let coding_items = u128::from(coding.forests)
            + u128::from(coding.coding.groups)
            + u128::from(coding.coding.information_roles)
            + u128::from(coding.coding.parity_roles)
            + u128::from(coding.coding.fragments);
        let legacy_previous = match previous {
            Some(CatalogCheckpointPrevious::Legacy { certificate, .. }) => {
                let c = &certificate.checkpoint;
                (c.writer_fences.len() as u128
                    + c.revision_tombstones.len() as u128
                    + c.revisions.len() as u128)
                    * 2
            }
            _ => 0,
        };
        // At most eight mutations per declared body/source/packing/coding
        // item cover identities, heads, source/object joins, placements,
        // coverage and transition-used rows. Include all completion markers.
        let mutations = 64
            + 8 * (u128::from(authority.records.records)
                + source_occurrences
                + packing
                + coding_items
                + legacy_previous);
        // Scalar rows are <=512 bytes. Revision records are copied once from
        // the complete authority stream; snapshots/descriptors get separate
        // fixed envelopes, including the largest 256-member snapshot.
        let values = mutations * 512
            + u128::from(authority.records.page.byte_len)
            + 16 * mb_core::PAGED_QUORUM_CHECKPOINT_BYTES as u128
            + 8 * (256 * 512 + 512);
        Ok(crate::ScratchStorageLimits::for_record_writes(
            values.min(u128::from(u64::MAX)) as u64,
            mutations.min(u128::from(u64::MAX)) as u64,
            168,
            mb_core::CATALOG_MAX_STREAM_BYTES * 4,
        )?)
    }
    pub fn work(&self) -> Result<Work, CatalogStoreError> {
        Ok(match self {
            Self::Individual(c) => c.checkpoint.represented_work()?,
            Self::Directory(c) => c.checkpoint.represented_work()?,
        })
    }
    fn verify(&self, trust: &PagedCheckpointTrust, budget: Work) -> Result<(), CatalogStoreError> {
        match self {
            Self::Individual(c) => c.verify_header(trust, budget)?,
            Self::Directory(c) => c.verify_header(trust, budget)?,
        };
        Ok(())
    }
    pub fn initial_roots(&self) -> Vec<(CatalogScope, CatalogSection, CatalogPageRef)> {
        let scope = CatalogScope::Guild {
            guild_id: self.guild_id(),
        };
        match self {
            Self::Individual(c) => vec![
                (
                    scope,
                    CatalogSection::Checkpoint,
                    c.checkpoint.authority_root.records.page,
                ),
                (
                    scope,
                    CatalogSection::Packing,
                    c.checkpoint.packed_sources.records.page,
                ),
                (
                    scope,
                    CatalogSection::Packing,
                    c.checkpoint.packed_sectors.records.page,
                ),
                (
                    scope,
                    CatalogSection::Coding,
                    c.checkpoint.coding.records.page,
                ),
            ],
            Self::Directory(c) => vec![
                (
                    scope,
                    CatalogSection::Checkpoint,
                    c.checkpoint.authority_root.records.page,
                ),
                (
                    scope,
                    CatalogSection::Packing,
                    c.checkpoint.packing.records.page,
                ),
                (
                    scope,
                    CatalogSection::Coding,
                    c.checkpoint.coding.records.page,
                ),
            ],
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogCheckpointAcquisitionState {
    Building,
    Complete,
    Cancelled,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointAcquisition {
    pub id: Uuid,
    pub certificate: CatalogPublicCheckpoint,
    pub trust_hash: [u8; 32],
    pub budget: Work,
    pub capacity: Option<mb_core::CatalogCapacityPolicy>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Job {
    version: u16,
    spec: CatalogCheckpointAcquisition,
    state: CatalogCheckpointAcquisitionState,
    roots: u64,
    used: Work,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Root {
    intent: CatalogIntent,
    root: CatalogPageRef,
    complete: bool,
}
fn roots(id: Uuid) -> String {
    format!("catalog-checkpoint-acquisition-root-v1/{}", id.simple())
}
fn root_intent(
    id: Uuid,
    scope: CatalogScope,
    section: CatalogSection,
    root: CatalogPageRef,
) -> Result<CatalogIntent, CatalogStoreError> {
    let hash = mb_core::canonical_hash_bounded(&(id, scope, section, root), 1024)?;
    let mut key = [0; 16];
    key.copy_from_slice(&hash[..16]);
    Ok(CatalogIntent {
        id: Uuid::from_bytes(key),
        scope,
        section,
    })
}
fn root_work(root: CatalogPageRef) -> Result<Work, CatalogStoreError> {
    Ok(Work {
        bytes: root
            .page_occurrences
            .checked_mul(CATALOG_PAGE_BYTES as u64 + ROOT_BYTES as u64)
            .ok_or(DatabaseError::CapacityExceeded)?,
        page_occurrences: root.page_occurrences,
        records: 1,
    })
}
fn read(cx: &Connection, id: Uuid) -> Result<Option<Job>, CatalogStoreError> {
    let saved = bounded_record(cx, JOB, id.as_bytes(), BYTES)?;
    let guard = bounded_record(cx, GUARD, id.as_bytes(), BYTES)?;
    let Some(bytes) = saved else {
        if guard.is_some()
            || cx.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
                [roots(id)],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    if guard.as_deref() != Some(bytes.as_slice()) {
        return Err(DatabaseError::Integrity.into());
    }
    let job: Job = decode_canonical(&bytes)?;
    if job.version != 1 || job.spec.id != id || id.is_nil() || canonical_bytes(&job)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    job.spec.budget.remaining_after(job.used)?;
    if job.used.records != job.roots.checked_add(2).ok_or(DatabaseError::Integrity)?
        || job.used.bytes
            < (BYTES as u64)
                .checked_mul(2)
                .and_then(|n| n.checked_add(job.roots.checked_mul(ROOT_BYTES as u64)?))
                .ok_or(DatabaseError::Integrity)?
        || job.used.page_occurrences < job.roots
    {
        return Err(DatabaseError::Integrity.into());
    }
    let count: u64 = cx.query_row(
        "SELECT count(*) FROM protocol_records WHERE kind=?1",
        [roots(id)],
        |r| r.get(0),
    )?;
    if count != job.roots || count > job.spec.certificate.work()?.page_occurrences {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(job))
}
fn require(cx: &Connection, spec: &CatalogCheckpointAcquisition) -> Result<Job, CatalogStoreError> {
    let job = read(cx, spec.id)?.ok_or(DatabaseError::NotReady)?;
    if job.spec != *spec
        || job.state != CatalogCheckpointAcquisitionState::Building
        || capacity_policy::read(cx)? != spec.capacity
    {
        return Err(DatabaseError::Conflict.into());
    }
    work_admission::require(cx, spec)?;
    Ok(job)
}
fn write(cx: &Connection, previous: &Job, next: &Job) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes(next)?;
    if bytes.len() > BYTES {
        return Err(DatabaseError::Integrity.into());
    }
    for kind in [JOB, GUARD] {
        if cx.execute(
            "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
            params![
                kind,
                next.spec.id.as_bytes(),
                bytes,
                canonical_bytes(previous)?
            ],
        )? != 1
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    if read(cx, next.spec.id)?.as_ref() != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn read_root(cx: &Connection, id: Uuid, hash: [u8; 32]) -> Result<Option<Root>, CatalogStoreError> {
    bounded_record(cx, &roots(id), &hash, ROOT_BYTES)?
        .map(|bytes| {
            let value: Root = decode_canonical(&bytes)?;
            if value.root.hash != hash
                || value.intent.section.is_private()
                || value.intent
                    != root_intent(id, value.intent.scope, value.intent.section, value.root)?
                || canonical_bytes(&value)? != bytes
            {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(value)
        })
        .transpose()
}

impl ControlStore {
    pub fn check_checkpoint_acquisition_trust(
        &self,
        spec: &CatalogCheckpointAcquisition,
        trust: &PagedCheckpointTrust,
    ) -> Result<(), CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let job = read(&tx, spec.id)?.ok_or(DatabaseError::NotReady)?;
        if job.spec != *spec
            || job.state == CatalogCheckpointAcquisitionState::Cancelled
            || super::checkpoint_transition::snapshot_hash(trust)? != spec.trust_hash
        {
            return Err(DatabaseError::Conflict.into());
        }
        if job.state == CatalogCheckpointAcquisitionState::Building {
            work_admission::require(&tx, spec)?;
        }
        tx.commit()?;
        Ok(())
    }
    pub fn begin_checkpoint_acquisition(
        &self,
        id: Uuid,
        certificate: CatalogPublicCheckpoint,
        trust: PagedCheckpointTrust,
        budget: Work,
    ) -> Result<CatalogCheckpointAcquisition, CatalogStoreError> {
        certificate.verify(&trust, budget)?;
        if self.advance_checkpoint_acquisition_work_admission()? {
            return Err(DatabaseError::NotReady.into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        if storage_quota::usage(&tx)?.is_none() {
            return Err(DatabaseError::NotReady.into());
        }
        let spec = CatalogCheckpointAcquisition {
            id,
            certificate,
            trust_hash: super::checkpoint_transition::snapshot_hash(&trust)?,
            budget,
            capacity: capacity_policy::read(&tx)?,
        };
        if id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        if let Some(policy) = spec.capacity {
            match &spec.certificate {
                CatalogPublicCheckpoint::Individual(c) => {
                    policy.admit_individual_checkpoint(c.checkpoint)?
                }
                CatalogPublicCheckpoint::Directory(c) => policy.admit_checkpoint(c.checkpoint)?,
            }
        }
        if let Some(old) = read(&tx, id)? {
            if old.spec != spec || old.state == CatalogCheckpointAcquisitionState::Cancelled {
                return Err(DatabaseError::Conflict.into());
            }
            if old.state == CatalogCheckpointAcquisitionState::Building {
                work_admission::reserve(&tx, &spec)?;
            }
        } else {
            if tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
                [roots(id)],
                |r| r.get::<_, bool>(0),
            )? {
                return Err(DatabaseError::Integrity.into());
            }
            let used = Work {
                bytes: BYTES as u64 * 2,
                records: 2,
                page_occurrences: 0,
            };
            budget.remaining_after(used)?;
            let job = Job {
                version: 1,
                spec: spec.clone(),
                state: CatalogCheckpointAcquisitionState::Building,
                roots: 0,
                used,
            };
            work_admission::reserve(&tx, &spec)?;
            insert_exact(&tx, JOB, id.as_bytes(), &canonical_bytes(&job)?)?;
            insert_exact(&tx, GUARD, id.as_bytes(), &canonical_bytes(&job)?)?;
            if read(&tx, id)?.as_ref() != Some(&job) {
                return Err(DatabaseError::Integrity.into());
            }
        }
        tx.commit()?;
        Ok(spec)
    }
    pub fn checkpoint_acquisition_state(
        &self,
        spec: &CatalogCheckpointAcquisition,
    ) -> Result<CatalogCheckpointAcquisitionState, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let job = read(&tx, spec.id)?.ok_or(DatabaseError::NotReady)?;
        if job.spec != *spec {
            return Err(DatabaseError::Conflict.into());
        }
        tx.commit()?;
        Ok(job.state)
    }
    pub fn reserve_checkpoint_acquisition_root(
        &self,
        spec: &CatalogCheckpointAcquisition,
        scope: CatalogScope,
        section: CatalogSection,
        root: CatalogPageRef,
    ) -> Result<CatalogIntent, CatalogStoreError> {
        scope.validate(section)?;
        root.validate()?;
        let guild = match scope {
            CatalogScope::Guild { guild_id } | CatalogScope::Dataset { guild_id, .. } => guild_id,
        };
        if guild != spec.certificate.guild_id() || section.is_private() {
            return Err(DatabaseError::Conflict.into());
        }
        let intent = root_intent(spec.id, scope, section, root)?;
        self.with_catalog_page_reservations(
            &[(
                intent,
                CatalogPageReservation {
                    page_bytes: root
                        .page_occurrences
                        .checked_mul(CATALOG_PAGE_BYTES as u64)
                        .ok_or(DatabaseError::CapacityExceeded)?,
                    pages: root.page_occurrences,
                },
            )],
            |_| -> Result<(), CatalogStoreError> {
                let job = require(&self.connection, spec)?;
                let value = Root {
                    intent,
                    root,
                    complete: false,
                };
                if let Some(existing) = read_root(&self.connection, spec.id, root.hash)? {
                    if existing.intent != intent || existing.root != root {
                        return Err(DatabaseError::Integrity.into());
                    }
                } else {
                    let mut next = job.clone();
                    next.roots = next
                        .roots
                        .checked_add(1)
                        .ok_or(DatabaseError::CapacityExceeded)?;
                    next.used = next.used.checked_add(root_work(root)?)?;
                    spec.budget.remaining_after(next.used)?;
                    if next.used.page_occurrences > spec.certificate.work()?.page_occurrences {
                        return Err(DatabaseError::CapacityExceeded.into());
                    }
                    insert_exact(
                        &self.connection,
                        &roots(spec.id),
                        &root.hash,
                        &canonical_bytes(&value)?,
                    )?;
                    write(&self.connection, &job, &next)?;
                }
                Ok(())
            },
        )?;
        Ok(intent)
    }
    pub fn stage_checkpoint_acquisition_page(
        &self,
        spec: &CatalogCheckpointAcquisition,
        intent: CatalogIntent,
        root: CatalogPageRef,
        page: CatalogPageRef,
        bytes: &[u8],
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        require(&tx, spec)?;
        let entry = read_root(&tx, spec.id, root.hash)?.ok_or(DatabaseError::NotReady)?;
        if entry.intent != intent || entry.root != root || entry.complete {
            return Err(DatabaseError::Conflict.into());
        }
        stage_page(&tx, intent, page, bytes)?;
        let staged = read_intent(&tx, intent)?;
        if staged.owned_pages > root.page_occurrences
            || staged.owned_bytes
                > root
                    .page_occurrences
                    .checked_mul(CATALOG_PAGE_BYTES as u64)
                    .ok_or(DatabaseError::CapacityExceeded)?
        {
            return Err(DatabaseError::CapacityExceeded.into());
        }
        require(&tx, spec)?;
        tx.commit()?;
        Ok(())
    }
    pub fn complete_checkpoint_acquisition_root(
        &self,
        spec: &CatalogCheckpointAcquisition,
        intent: CatalogIntent,
        root: CatalogPageRef,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        require(&tx, spec)?;
        let old = read_root(&tx, spec.id, root.hash)?.ok_or(DatabaseError::NotReady)?;
        if old.intent != intent || old.root != root {
            return Err(DatabaseError::Conflict.into());
        }
        publish_root(&tx, intent, root)?;
        let next = Root {
            complete: true,
            ..old
        };
        let bytes = canonical_bytes(&next)?;
        if tx.execute(
            "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
            params![roots(spec.id), root.hash, bytes, canonical_bytes(&old)?],
        )? != 1
            || read_root(&tx, spec.id, root.hash)? != Some(next)
        {
            return Err(DatabaseError::Integrity.into());
        }
        require(&tx, spec)?;
        tx.commit()?;
        Ok(())
    }
    pub fn cancel_checkpoint_acquisition(
        &self,
        spec: &CatalogCheckpointAcquisition,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let job = read(&tx, spec.id)?.ok_or(DatabaseError::NotReady)?;
        if job.spec != *spec {
            return Err(DatabaseError::Conflict.into());
        }
        if recovery_owner(&tx, spec.id)? {
            return Err(DatabaseError::Conflict.into());
        }
        work_admission::release(&tx, spec)?;
        let next = Job {
            state: CatalogCheckpointAcquisitionState::Cancelled,
            ..job.clone()
        };
        write(&tx, &job, &next)?;
        tx.commit()?;
        Ok(())
    }

    /// Completion requires the original certificate's fully validated public
    /// owner to be published already. Staging itself grants no serving authority.
    pub fn finish_checkpoint_acquisition(
        &self,
        spec: &CatalogCheckpointAcquisition,
    ) -> Result<(), CatalogStoreError> {
        self.finish_checkpoint_acquisition_inner(spec, false)
    }
    pub fn finish_checkpoint_recovery_acquisition(
        &self,
        spec: &CatalogCheckpointAcquisition,
    ) -> Result<(), CatalogStoreError> {
        self.finish_checkpoint_acquisition_inner(spec, true)
    }
    fn finish_checkpoint_acquisition_inner(
        &self,
        spec: &CatalogCheckpointAcquisition,
        recovery: bool,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let job = read(&tx, spec.id)?.ok_or(DatabaseError::NotReady)?;
        if job.spec != *spec
            || job.state == CatalogCheckpointAcquisitionState::Cancelled
            || capacity_policy::read(&tx)? != spec.capacity
        {
            return Err(DatabaseError::Conflict.into());
        }
        if job.state == CatalogCheckpointAcquisitionState::Building {
            work_admission::require(&tx, spec)?;
        }
        macro_rules! verify {
            ($header:ty,$certificate:expr)=>{{
                use super::retention_journal as journal;
                let owner=journal::read::<CatalogPagedCheckpointRetention<$header>>(&tx,spec.id)?.ok_or(DatabaseError::NotReady)?;
                if owner.state!=CatalogPagedCheckpointRetentionState::Published || owner.retention.checkpoint!=$certificate.checkpoint
                    || paged_checkpoint_retention::owned_certificate(&tx,owner.retention)?!=$certificate.clone() {return Err(DatabaseError::Conflict.into())}
                let mut after:Option<Vec<u8>>=None;
                loop{
                    let row:Option<(Option<Vec<u8>>,Option<Vec<u8>>)>=tx.query_row(
                        "SELECT CASE WHEN length(record_id)=32 THEN record_id END,CASE WHEN length(bytes)<=?3 THEN bytes END FROM protocol_records WHERE kind=?1 AND (?2 IS NULL OR record_id>?2) ORDER BY record_id LIMIT 1",
                        params![roots(spec.id),after,ROOT_BYTES],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                    let Some((key,bytes))=row else{break};let key=key.ok_or(DatabaseError::Integrity)?;let bytes=bytes.ok_or(DatabaseError::Integrity)?;
                    let hash:[u8;32]=key.as_slice().try_into().map_err(|_|DatabaseError::Integrity)?;
                    let root=read_root(&tx,spec.id,hash)?.ok_or(DatabaseError::Integrity)?;
                    if canonical_bytes(&root)?!=bytes{return Err(DatabaseError::Integrity.into())}
                    if !root.complete || root.root.hash.as_slice()!=key{return Err(DatabaseError::NotReady.into())}
                    let dep=retention_journal::Dependency{scope:root.intent.scope,section:root.intent.section,root:root.root};
                    let name=journal::dependencies::<CatalogPagedCheckpointRetention<$header>>(spec.id);
                    if bounded_record(&tx,&name,&key,RECORD_BYTES)?.as_deref()!=Some(canonical_bytes(&dep)?.as_slice()){return Err(DatabaseError::Integrity.into())}
                    if read_intent(&tx,root.intent)?.state!=CatalogIntentState::Published(root.root){return Err(DatabaseError::Integrity.into())}
                    after=Some(key);
                }
            }};
        }
        match &spec.certificate {
            CatalogPublicCheckpoint::Individual(c) => verify!(mb_core::PagedGuildCheckpoint, c),
            CatalogPublicCheckpoint::Directory(c) => {
                verify!(mb_core::PagedGuildCheckpointDirectory, c)
            }
        }
        work_admission::release(&tx, spec)?;
        let next = Job {
            state: CatalogCheckpointAcquisitionState::Complete,
            ..job.clone()
        };
        write(&tx, &job, &next)?;
        if recovery {
            recovery_tip::publish(&tx, spec)?;
        }
        tx.commit()?;
        Ok(())
    }
    /// Retire one staged pin or root record. The independently promoted public
    /// owner remains live; ordinary cancellation handles that owner separately.
    pub fn release_checkpoint_acquisition_step(
        &self,
        spec: &CatalogCheckpointAcquisition,
    ) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let job = read(&tx, spec.id)?.ok_or(DatabaseError::NotReady)?;
        if job.spec != *spec || job.state != CatalogCheckpointAcquisitionState::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let key:Option<Option<Vec<u8>>>=tx.query_row("SELECT CASE WHEN length(record_id)=32 THEN record_id END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT 1",[roots(spec.id)],|r|r.get(0)).optional()?;
        let Some(key) = key else { return Ok(false) };
        let key = key.ok_or(DatabaseError::Integrity)?;
        let hash: [u8; 32] = key
            .as_slice()
            .try_into()
            .map_err(|_| DatabaseError::Integrity)?;
        let root = read_root(&tx, spec.id, hash)?.ok_or(DatabaseError::Integrity)?;
        let mut intent = read_intent(&tx, root.intent)?;
        bundle::require_unbundled(&tx, root.intent)?;
        if intent.state != CatalogIntentState::Cancelled {
            intent.state = CatalogIntentState::Cancelled;
            write_intent(&tx, &intent)?;
            tx.commit()?;
            return Ok(true);
        }
        let name = owners(root.intent);
        if let Some(hash) = candidate_hash(&tx, &name, &[])? {
            let page = metadata(&tx, hash)?;
            intent.owned_pages = intent
                .owned_pages
                .checked_sub(1)
                .ok_or(DatabaseError::Integrity)?;
            intent.owned_bytes = intent
                .owned_bytes
                .checked_sub(u64::from(page.reference.encoded_len))
                .ok_or(DatabaseError::Integrity)?;
            if tx.execute(
                "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2",
                params![name, hash],
            )? != 1
                || tx.execute(
                    "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2",
                    params![pins(hash), root.intent.id.as_bytes()],
                )? != 1
                || bounded_record(&tx, &name, &hash, 0)?.is_some()
                || bounded_record(&tx, &pins(hash), root.intent.id.as_bytes(), 0)?.is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
            write_intent(&tx, &intent)?;
            queue_unreferenced(&tx, hash)?;
            tx.commit()?;
            return Ok(true);
        }
        if intent.owned_pages != 0 || intent.owned_bytes != 0 {
            return Err(DatabaseError::Integrity.into());
        }
        if tx.execute(
            "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
            params![roots(spec.id), hash, canonical_bytes(&root)?],
        )? != 1
            || read_root(&tx, spec.id, hash)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
        let mut next = job.clone();
        next.roots = next.roots.checked_sub(1).ok_or(DatabaseError::Integrity)?;
        next.used = next.used.remaining_after(root_work(root.root)?)?;
        write(&tx, &job, &next)?;
        tx.commit()?;
        Ok(true)
    }
}
