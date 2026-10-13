//! Durable original-authority packing construction. Local packing completion
//! keeps every staged page and source/payload loan; it is not coding completion,
//! distributed availability or checkpoint activation.

use super::*;
use mb_core::{
    CatalogCapacityPolicy, CatalogCodingTraversalBudget as Work, CatalogPackingDirectoryReader,
    CatalogPackingDirectoryRecord, CatalogStreamError, PackedSector, canonical_bytes_bounded,
};

const JOURNAL: &str = "catalog-packing-operation-v1";
const ROLE: &str = "catalog-packing-operation-role-v1";
const ROLE_GUARD: &str = "catalog-packing-operation-role-guard-v1";
const JOURNAL_BYTES: usize = 8192;
const OUTPUT_BYTES: usize = 512;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingOutputAttempt {
    pub sector_id: [u8; 32],
    pub storage_id: [u8; 32],
    pub sector_index: u32,
    pub commitment: mb_core::MerkleCommitment,
    pub attempt_id: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingOperation {
    pub id: Uuid,
    pub base: CatalogPackingAuthorityBase,
    pub source_identity: [u8; 32],
    pub authority_work: Work,
    pub policy: CatalogCapacityPolicy,
    pub budget: Work,
    pub source_budget: Work,
    pub payload_budget: Work,
}
// One fixed-size directory root stays inline in the bounded journal; Copy
// state permits exact old/new comparisons without heap allocation per record.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackingOperationState {
    Building,
    PackingComplete(CatalogPackingDirectoryValidation),
    Cancelled,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Journal {
    version: u16,
    operation: CatalogPackingOperation,
    state: CatalogPackingOperationState,
    outputs: u64,
    attempts: u64,
}

impl CatalogPackingOperation {
    /// Temporary packed output gets a deterministic attempt; the unchanged
    /// coding protocol assigns every final information/parity role afterwards.
    pub fn output_attempt(self, sector: &PackedSector) -> CatalogPackingOutputAttempt {
        let mut h =
            blake3::Hasher::new_derive_key("mutualbackup durable packing output attempt v1");
        h.update(self.id.as_bytes());
        h.update(&sector.descriptor.id);
        CatalogPackingOutputAttempt {
            sector_id: sector.descriptor.id,
            storage_id: output_storage_id(self.id, sector.descriptor.id),
            sector_index: sector.descriptor.sector_index,
            commitment: sector.descriptor.commitment.clone(),
            attempt_id: h.finalize().as_bytes()[..16]
                .try_into()
                .expect("fixed digest"),
        }
    }
    pub fn new(
        id: Uuid,
        authority: &CatalogPackingAuthority,
        policy: CatalogCapacityPolicy,
        budget: Work,
        source_budget: Work,
        payload_budget: Work,
    ) -> Result<Self, CatalogStoreError> {
        let value = Self {
            id,
            base: authority.base(),
            source_identity: authority.operation_identity()?,
            authority_work: authority.authority_work(),
            policy,
            budget,
            source_budget,
            payload_budget,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn sources(self) -> CatalogPackingSourceRetention {
        CatalogPackingSourceRetention {
            id: self.id,
            base: self.base,
            budget: self.source_budget,
        }
    }
    pub fn payloads(self) -> CatalogPackingPayloadRetention {
        CatalogPackingPayloadRetention {
            id: self.id,
            base: self.base,
            budget: self.payload_budget,
        }
    }
    pub fn pages(self) -> CatalogIntent {
        CatalogIntent {
            id: role_id(self.id),
            scope: CatalogScope::Guild {
                guild_id: self.base.guild_id,
            },
            section: CatalogSection::Packing,
        }
    }
    fn fixed(self) -> Result<Work, CatalogStoreError> {
        Ok(Work {
            bytes: JOURNAL_BYTES as u64,
            page_occurrences: 0,
            records: 4,
        }
        .checked_add(self.source_budget)?
        .checked_add(self.payload_budget)?
        .checked_add(Work {
            bytes: self
                .policy
                .packed_sectors
                .checked_mul(2 * OUTPUT_BYTES as u64)
                .ok_or(DatabaseError::CapacityExceeded)?,
            page_occurrences: 0,
            records: self
                .policy
                .packed_sectors
                .checked_mul(2)
                .ok_or(DatabaseError::CapacityExceeded)?,
        })?)
    }
    pub fn construction_budget(self) -> Result<Work, CatalogStoreError> {
        Ok(self.budget.remaining_after(self.fixed()?)?)
    }
    fn reservation(self) -> Result<CatalogPageReservation, CatalogStoreError> {
        let pages = self
            .policy
            .plan()?
            .packing_coding
            .packing
            .work
            .page_occurrences;
        Ok(CatalogPageReservation {
            pages,
            page_bytes: pages
                .checked_mul(CATALOG_PAGE_BYTES as u64)
                .ok_or(DatabaseError::CapacityExceeded)?,
        })
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil()
            || self.base.guild_id == [0; 32]
            || self.base.checkpoint_hash == [0; 32]
            || self.base.generation == 0
            || self.base.membership_epoch == Some(0)
            || self.source_identity == [0; 32]
        {
            return Err(DatabaseError::Conflict.into());
        }
        let plan = self.policy.plan()?;
        self.construction_budget()?.remaining_after(
            self.authority_work
                .checked_add(plan.packing_coding.packing.work)?,
        )?;
        canonical_bytes_bounded(&self, JOURNAL_BYTES)?;
        Ok(())
    }
    fn check_authority(self, authority: &CatalogPackingAuthority) -> Result<(), CatalogStoreError> {
        self.validate()?;
        if authority.base() != self.base
            || authority.authority_work() != self.authority_work
            || authority.operation_identity()? != self.source_identity
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }
}
fn role_id(operation: Uuid) -> Uuid {
    let mut h = blake3::Hasher::new_derive_key("mutualbackup durable packing page role v1");
    h.update(operation.as_bytes());
    Uuid::from_bytes(
        h.finalize().as_bytes()[..16]
            .try_into()
            .expect("fixed digest"),
    )
}
fn output_storage_id(operation: Uuid, sector: [u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("mutualbackup durable packing output storage v1");
    h.update(operation.as_bytes());
    h.update(&sector);
    *h.finalize().as_bytes()
}
fn outputs(id: Uuid) -> String {
    format!("catalog-packing-operation-output-v1/{}", id.simple())
}
fn attempts(id: Uuid) -> String {
    format!("catalog-packing-operation-attempt-v1/{}", id.simple())
}
fn encode(value: &impl Serialize) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(mb_core::canonical_bytes_bounded(value, JOURNAL_BYTES)?)
}
fn has_outputs(cx: &Connection, id: Uuid) -> Result<bool, CatalogStoreError> {
    Ok(cx.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
        [outputs(id)],
        |r| r.get(0),
    )?)
}
fn journal(cx: &Connection, id: Uuid) -> Result<Option<Journal>, CatalogStoreError> {
    let Some(bytes) = bounded_record(cx, JOURNAL, id.as_bytes(), JOURNAL_BYTES)? else {
        if bounded_record(cx, ROLE, role_id(id).as_bytes(), 16)?.is_some()
            || bounded_record(cx, ROLE_GUARD, role_id(id).as_bytes(), 16)?.is_some()
            || has_outputs(cx, id)?
            || cx.query_row(
                "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
                [attempts(id)],
                |r| r.get::<_, bool>(0),
            )?
        {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let j: Journal = decode_canonical(&bytes)?;
    j.operation.validate()?;
    if j.version != 1
        || j.operation.id != id
        || encode(&j)? != bytes
        || j.outputs > j.operation.policy.packed_sectors
        || j.attempts > j.operation.policy.packed_sectors
        || j.outputs > j.attempts
        || cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
            [attempts(id)],
            |r| r.get::<_, bool>(0),
        )? != (j.attempts != 0)
        || has_outputs(cx, id)? != (j.outputs != 0)
    {
        return Err(DatabaseError::Integrity.into());
    }
    let role = j.operation.pages();
    for kind in [ROLE, ROLE_GUARD] {
        if bounded_record(cx, kind, role.id.as_bytes(), 16)?.as_deref() != Some(id.as_bytes()) {
            return Err(DatabaseError::Integrity.into());
        }
    }
    let intent = read_intent(cx, role)?;
    let (sources, _) = packing_sources::operation_state(cx, j.operation.sources())?;
    let (payloads, _) = packing_payloads::operation_state(cx, j.operation.payloads())?;
    match j.state {
        CatalogPackingOperationState::Building
            if intent.state == CatalogIntentState::Building
                && sources == CatalogPackingSourceRetentionState::Building
                && payloads == CatalogPackingPayloadRetentionState::Building => {}
        CatalogPackingOperationState::PackingComplete(manifest)
            if intent.state == CatalogIntentState::Building
                && sources == CatalogPackingSourceRetentionState::Cancelled
                && payloads == CatalogPackingPayloadRetentionState::Cancelled =>
        {
            manifest.validate(
                j.operation
                    .construction_budget()?
                    .remaining_after(j.operation.authority_work)?,
            )?;
            if manifest.scope != role.scope
                || manifest.directory.profile != j.operation.policy.packing_profile
                || manifest.directory.summary.sectors != j.outputs
                || j.attempts != j.outputs
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        CatalogPackingOperationState::Cancelled
            if intent.state == CatalogIntentState::Cancelled
                && sources == CatalogPackingSourceRetentionState::Cancelled
                && payloads == CatalogPackingPayloadRetentionState::Cancelled => {}
        _ => return Err(DatabaseError::Integrity.into()),
    }
    Ok(Some(j))
}
fn require(cx: &Connection, op: CatalogPackingOperation) -> Result<Journal, CatalogStoreError> {
    let j = journal(cx, op.id)?.ok_or(DatabaseError::NotReady)?;
    if j.operation != op {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(j)
}
fn change(cx: &Connection, old: Journal, next: Journal) -> Result<(), CatalogStoreError> {
    if cx.execute(
        "UPDATE protocol_records SET bytes=?4 WHERE kind=?1 AND record_id=?2 AND bytes=?3",
        params![
            JOURNAL,
            old.operation.id.as_bytes(),
            encode(&old)?,
            encode(&next)?
        ],
    )? != 1
        || journal(cx, next.operation.id)? != Some(next)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
pub(super) fn require_job_building(cx: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    if let Some(j) = journal(cx, id)?
        && j.state != CatalogPackingOperationState::Building
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
pub(super) fn require_job_retired(cx: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    if let Some(j) = journal(cx, id)?
        && j.state != CatalogPackingOperationState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
pub(super) fn require_job_handoff(cx: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    if let Some(j) = journal(cx, id)?
        && j.state == CatalogPackingOperationState::Building
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
fn role_owner(cx: &Connection, role: CatalogIntent) -> Result<Option<Journal>, CatalogStoreError> {
    let link = bounded_record(cx, ROLE, role.id.as_bytes(), 16)?;
    let guard = bounded_record(cx, ROLE_GUARD, role.id.as_bytes(), 16)?;
    if link != guard {
        return Err(DatabaseError::Integrity.into());
    }
    let Some(link) = link else { return Ok(None) };
    let id = Uuid::from_slice(&link).map_err(|_| DatabaseError::Integrity)?;
    let j = journal(cx, id)?.ok_or(DatabaseError::Integrity)?;
    if j.operation.pages() != role {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(Some(j))
}
pub(super) fn require_role_building(
    cx: &Connection,
    role: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    if let Some(j) = role_owner(cx, role)?
        && j.state != CatalogPackingOperationState::Building
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
pub(super) fn require_role_retired(
    cx: &Connection,
    role: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    if let Some(j) = role_owner(cx, role)?
        && j.state != CatalogPackingOperationState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}
pub(super) fn require_role_unattached(
    cx: &Connection,
    role: CatalogIntent,
) -> Result<(), CatalogStoreError> {
    if role_owner(cx, role)?.is_some() {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

/// Current base/events and complete source-custody checks use this writer view.
/// Callbacks may read original loans/pages but may not nest control writers.
pub struct CatalogPackingOperationView<'a> {
    connection: &'a Connection,
}
impl CatalogPackingOperationView<'_> {
    pub fn record(
        &self,
        kind: &str,
        key: &[u8],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        bounded_record(self.connection, kind, key, limit)
    }
    pub fn source(
        &self,
        retention: CatalogPackingSourceRetention,
        revision: Uuid,
    ) -> Result<Option<PagedCatalogSnapshot>, CatalogStoreError> {
        packing_sources::operation_source(self.connection, retention, revision)
    }
    /// Join one original authorised paged input to an exact already-held
    /// catalog loan. Resolve the caller's revision directly so another shared
    /// owner's earlier index entry cannot substitute for the borrowed owner.
    /// Current authority and complete source EOF are checked by the producer.
    pub fn require_retained_paged_source(
        &self,
        operation: CatalogPackingOperation,
        revision: Uuid,
        source: &CatalogPackingAuthorizedSource,
    ) -> Result<PagedCatalogSnapshot, CatalogStoreError> {
        operation.validate()?;
        packing_sources::retained_source(self.connection, operation.sources(), revision, source)
    }

    pub fn payload(
        &self,
        retention: CatalogPackingPayloadRetention,
        storage: [u8; 32],
        shard: u16,
    ) -> Result<Option<CatalogPackingPayload>, CatalogStoreError> {
        packing_payloads::operation_payload(self.connection, retention, storage, shard)
    }
}
fn output_descriptor(
    cx: &Connection,
    op: CatalogPackingOperation,
    id: [u8; 32],
) -> Result<Option<CatalogPackingPayload>, CatalogStoreError> {
    let Some(bytes) = bounded_record(cx, &outputs(op.id), &id, OUTPUT_BYTES)? else {
        return Ok(None);
    };
    let p: CatalogPackingPayload = decode_canonical(&bytes)?;
    p.validate()?;
    let planned = attempt(cx, op, id)?.ok_or(DatabaseError::Integrity)?;
    if mb_core::canonical_bytes_bounded(&p, OUTPUT_BYTES)? != bytes
        || p.storage_id != planned.storage_id
        || p.guild_id != op.base.guild_id
        || p.attempt_id != planned.attempt_id
        || p.commitment != planned.commitment
        || p.shard_index != 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(p))
}
fn output(
    cx: &Connection,
    op: CatalogPackingOperation,
    id: [u8; 32],
) -> Result<Option<CatalogPackingPayload>, CatalogStoreError> {
    let p = output_descriptor(cx, op, id)?;
    if let Some(p) = &p
        && packing_payloads::operation_payload(cx, op.payloads(), p.storage_id, p.shard_index)?
            .as_ref()
            != Some(p)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(p)
}
fn stream<T, E: From<CatalogStoreError>>(value: Result<T, CatalogStreamError<E>>) -> Result<T, E> {
    value.map_err(|e| match e {
        CatalogStreamError::Catalog(e) => CatalogStoreError::from(e).into(),
        CatalogStreamError::Storage(e) => e,
    })
}
fn attempt(
    cx: &Connection,
    op: CatalogPackingOperation,
    id: [u8; 32],
) -> Result<Option<CatalogPackingOutputAttempt>, CatalogStoreError> {
    let Some(bytes) = bounded_record(cx, &attempts(op.id), &id, OUTPUT_BYTES)? else {
        return Ok(None);
    };
    let value: CatalogPackingOutputAttempt = decode_canonical(&bytes)?;
    let mut h = blake3::Hasher::new_derive_key("mutualbackup durable packing output attempt v1");
    h.update(op.id.as_bytes());
    h.update(&id);
    if value.sector_id != id
        || value.storage_id != output_storage_id(op.id, id)
        || value.sector_index as u64 >= op.policy.packed_sectors
        || value.attempt_id != h.finalize().as_bytes()[..16]
        || value.commitment.byte_len != op.policy.packing_profile.sector_size
        || mb_core::canonical_bytes_bounded(&value, OUTPUT_BYTES)? != bytes
    {
        return Err(DatabaseError::Integrity.into());
    }
    value
        .commitment
        .validate()
        .map_err(|_| DatabaseError::Integrity)?;
    Ok(Some(value))
}

impl ControlStore {
    pub fn begin_catalog_packing_operation_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        authority: &CatalogPackingAuthority,
        mut checks: (
            impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
            impl FnMut(&CatalogPackingOperationView<'_>, &CatalogPackingAuthority) -> Result<(), E>,
        ),
    ) -> Result<(), E> {
        op.check_authority(authority)?;
        self.with_catalog_page_reservations(&[(op.pages(), op.reservation()?)], |states| {
            let view = CatalogPackingOperationView {
                connection: &self.connection,
            };
            checks.0(&view)?;
            checks.1(&view, authority)?;
            if states != [CatalogIntentState::Building] {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            if let Some(old) = journal(&self.connection, op.id)? {
                if old.operation != op || old.state != CatalogPackingOperationState::Building {
                    return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
                }
            } else {
                packing_sources::begin_for_operation(&self.connection, op.sources())?;
                packing_payloads::begin_for_operation(&self.connection, op.payloads())?;
                for kind in [ROLE, ROLE_GUARD] {
                    insert_exact(
                        &self.connection,
                        kind,
                        op.pages().id.as_bytes(),
                        op.id.as_bytes(),
                    )?;
                }
                let value = Journal {
                    version: 1,
                    operation: op,
                    state: CatalogPackingOperationState::Building,
                    outputs: 0,
                    attempts: 0,
                };
                insert_exact(
                    &self.connection,
                    JOURNAL,
                    op.id.as_bytes(),
                    &encode(&value)?,
                )?;
                if require(&self.connection, op)? != value {
                    return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
                }
            }
            checks.0(&view)?;
            checks.1(&view, authority)?;
            Ok(())
        })
    }

    pub fn catalog_packing_operation(
        &self,
        id: Uuid,
    ) -> Result<Option<(CatalogPackingOperation, CatalogPackingOperationState)>, CatalogStoreError>
    {
        let tx = self.read_snapshot()?;
        let result = journal(&tx, id)?.map(|j| (j.operation, j.state));
        tx.commit()?;
        Ok(result)
    }

    pub fn stage_catalog_packing_operation_page_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        page: CatalogPageRef,
        bytes: &[u8],
        mut guard: impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingOperationView { connection: &tx };
        guard(&view)?;
        if require(&tx, op)?.state != CatalogPackingOperationState::Building {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        stage_page(&tx, op.pages(), page, bytes)?;
        guard(&view)?;
        require(&tx, op)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    pub fn record_catalog_packing_operation_payload_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        sector_id: [u8; 32],
        payload: &CatalogPackingPayload,
        mut guard: impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingOperationView { connection: &tx };
        guard(&view)?;
        let old = require(&tx, op)?;
        if old.state != CatalogPackingOperationState::Building
            || payload.guild_id != op.base.guild_id
            || packing_payloads::operation_payload(
                &tx,
                op.payloads(),
                payload.storage_id,
                payload.shard_index,
            )?
            .as_ref()
                != Some(payload)
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let planned =
            attempt(&tx, op, sector_id)?.ok_or(CatalogStoreError::from(DatabaseError::NotReady))?;
        if payload.storage_id != planned.storage_id
            || payload.attempt_id != planned.attempt_id
            || payload.commitment != planned.commitment
            || payload.shard_index != 0
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        if let Some(existing) = output(&tx, op, sector_id)? {
            if existing != *payload {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
        } else {
            let next = Journal {
                outputs: old
                    .outputs
                    .checked_add(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                ..old
            };
            if next.outputs > op.policy.packed_sectors {
                return Err(CatalogStoreError::from(DatabaseError::CapacityExceeded).into());
            }
            insert_exact(
                &tx,
                &outputs(op.id),
                &sector_id,
                &mb_core::canonical_bytes_bounded(payload, OUTPUT_BYTES)
                    .map_err(CatalogStoreError::from)?,
            )?;
            change(&tx, old, next)?;
        }
        guard(&view)?;
        require(&tx, op)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    pub fn plan_catalog_packing_operation_output_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        sector: &PackedSector,
        mut guard: impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
    ) -> Result<CatalogPackingOutputAttempt, E> {
        let plan = op.output_attempt(sector);
        if plan.sector_index as u64 >= op.policy.packed_sectors
            || sector
                .descriptor
                .calculate_id(op.policy.packing_profile)
                .map_err(|_| CatalogStoreError::from(DatabaseError::Integrity))?
                != plan.sector_id
            || mb_core::merkle_commit(&sector.bytes)
                .map_err(|_| CatalogStoreError::from(DatabaseError::Integrity))?
                != plan.commitment
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingOperationView { connection: &tx };
        guard(&view)?;
        let old = require(&tx, op)?;
        if old.state != CatalogPackingOperationState::Building {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        if let Some(previous) = attempt(&tx, op, plan.sector_id)? {
            if previous != plan {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
        } else {
            insert_exact(
                &tx,
                &attempts(op.id),
                &plan.sector_id,
                &mb_core::canonical_bytes_bounded(&plan, OUTPUT_BYTES)
                    .map_err(CatalogStoreError::from)?,
            )?;
            change(
                &tx,
                old,
                Journal {
                    attempts: old
                        .attempts
                        .checked_add(1)
                        .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                    ..old
                },
            )?;
        }
        guard(&view)?;
        require(&tx, op)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(plan)
    }

    pub fn next_catalog_packing_operation_attempt(
        &self,
        op: CatalogPackingOperation,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogPackingOutputAttempt>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, op)?;
        let key:Option<Option<Vec<u8>>>=tx.query_row("SELECT CASE WHEN length(record_id)=32 THEN record_id END FROM protocol_records WHERE kind=?1 AND (?2 IS NULL OR record_id>?2) ORDER BY record_id LIMIT 1",params![attempts(op.id),after.as_ref().map(|v|v.as_slice())],|r|r.get(0)).optional()?;
        let result = key
            .map(|k| {
                let id = k
                    .ok_or(DatabaseError::Integrity)?
                    .try_into()
                    .map_err(|_| DatabaseError::Integrity)?;
                attempt(&tx, op, id)?.ok_or(CatalogStoreError::from(DatabaseError::Integrity))
            })
            .transpose()?;
        tx.commit()?;
        Ok(result)
    }

    /// Resolve one original public sector to its exact completed temporary
    /// output and still-held payload loan. This is a local custody lookup;
    /// callers must separately check current authority and physical bytes.
    pub fn catalog_completed_packing_output(
        &self,
        op: CatalogPackingOperation,
        sector_id: [u8; 32],
    ) -> Result<(CatalogPackingOutputAttempt, CatalogPackingPayload), CatalogStoreError> {
        let tx = self.read_snapshot()?;
        if !matches!(
            require(&tx, op)?.state,
            CatalogPackingOperationState::PackingComplete(_)
        ) {
            return Err(DatabaseError::NotReady.into());
        }
        let planned = attempt(&tx, op, sector_id)?.ok_or(DatabaseError::NotReady)?;
        let payload = output(&tx, op, sector_id)?.ok_or(DatabaseError::NotReady)?;
        tx.commit()?;
        Ok((planned, payload))
    }

    /// Retire one exact cancelled output after its loans are released. The
    /// callback holds this control writer across physical deletion and exact
    /// locator retirement. Offline/shared owners return false and retain the
    /// plan. Physical success followed by control rollback remains retryable.
    pub fn retire_catalog_packing_operation_output_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        planned: &CatalogPackingOutputAttempt,
        mut guard: impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
        retire: impl FnOnce(
            &CatalogPayloadRetirementView<'_>,
            &CatalogPackingOutputAttempt,
            Option<&CatalogPackingPayload>,
        ) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingOperationView { connection: &tx };
        guard(&view)?;
        let old = require(&tx, op)?;
        if old.state != CatalogPackingOperationState::Cancelled {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let Some(current) = attempt(&tx, op, planned.sector_id)? else {
            if bounded_record(&tx, &outputs(op.id), &planned.sector_id, OUTPUT_BYTES)?.is_some() {
                return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
            }
            guard(&view)?;
            tx.commit().map_err(CatalogStoreError::from)?;
            return Ok(true);
        };
        if &current != planned {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let output = output_descriptor(&tx, op, planned.sector_id)?;
        let pins = CatalogPayloadRetirementView::new(&tx);
        if packing_payloads::operation_payload(&tx, op.payloads(), planned.storage_id, 0)?.is_some()
            || pins.attempt_is_pinned(planned.attempt_id)?
            || pins.is_pinned(planned.storage_id, 0, planned.commitment.root)?
        {
            tx.commit().map_err(CatalogStoreError::from)?;
            return Ok(false);
        }
        if !retire(&pins, planned, output.as_ref())? {
            guard(&view)?;
            require(&tx, op)?;
            tx.commit().map_err(CatalogStoreError::from)?;
            return Ok(false);
        }
        for (kind, bytes) in [
            (
                outputs(op.id),
                output
                    .as_ref()
                    .map(|p| mb_core::canonical_bytes_bounded(p, OUTPUT_BYTES))
                    .transpose()
                    .map_err(CatalogStoreError::from)?,
            ),
            (
                attempts(op.id),
                Some(
                    mb_core::canonical_bytes_bounded(planned, OUTPUT_BYTES)
                        .map_err(CatalogStoreError::from)?,
                ),
            ),
        ] {
            if let Some(bytes) = bytes
                && (tx
                    .execute(
                        "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
                        params![kind, planned.sector_id.as_slice(), bytes],
                    )
                    .map_err(CatalogStoreError::from)?
                    != 1
                    || bounded_record(&tx, &kind, &planned.sector_id, OUTPUT_BYTES)?.is_some())
            {
                return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
            }
        }
        change(
            &tx,
            old,
            Journal {
                outputs: old
                    .outputs
                    .checked_sub(u64::from(output.is_some()))
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                attempts: old
                    .attempts
                    .checked_sub(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                ..old
            },
        )?;
        guard(&view)?;
        require(&tx, op)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(true)
    }

    /// Full source/candidate and packing EOFs precede the final writer. Exact
    /// local payload loans are joined to every original output descriptor;
    /// physical verification is outside that writer while loans exclude GC.
    pub fn complete_catalog_packing_operation_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        proof: &CatalogCertifiedPackingDirectoryIndex,
        mut guard: impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
        mut verify: impl FnMut(&CatalogPackingPayload) -> Result<(), E>,
    ) -> Result<(), E> {
        proof.require_complete()?;
        if proof.base() != op.base
            || proof.operation_identity() != op.source_identity
            || proof.manifest().directory.profile != op.policy.packing_profile
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let manifest = proof.manifest();
        let mut reader = CatalogPackingDirectoryReader::new(
            manifest.scope,
            manifest.directory,
            op.construction_budget()?
                .remaining_after(op.authority_work)
                .map_err(CatalogStoreError::from)?,
        )
        .map_err(CatalogStoreError::from)?;
        let mut fetch = |page| {
            self.catalog_page(manifest.scope, CatalogSection::Packing, page)
                .map_err(E::from)
        };
        let mut part = |part: CatalogPackingDirectoryRecord| -> Result<(), E> {
            let page = match part {
                CatalogPackingDirectoryRecord::Sources(p) => p.root.records.page,
                CatalogPackingDirectoryRecord::Sectors(p) => p.root.records.page,
            };
            let tx = self.read_snapshot().map_err(CatalogStoreError::from)?;
            let current = require(&tx, op)?;
            let pinned = bounded_record(&tx, &owners(op.pages()), &page.hash, 0)?.is_some();
            tx.commit().map_err(CatalogStoreError::from)?;
            if !pinned {
                if current.state != CatalogPackingOperationState::Building {
                    return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
                }
                let bytes = self.catalog_page(manifest.scope, CatalogSection::Packing, page)?;
                self.stage_catalog_packing_operation_page_checked(op, page, &bytes, &mut guard)?;
            }
            Ok(())
        };
        while stream(reader.next_source_with_part(&mut fetch, &mut part))?.is_some() {}
        let mut count = 0_u64;
        while let Some(record) = stream(reader.next_sector_with_part(
            &mut fetch,
            &mut |key| proof.operation_source_id(key).map_err(E::from),
            &mut part,
        ))? {
            let mb_core::CatalogPackedSectorRecord::Header { id, commitment, .. } = record else {
                continue;
            };
            let tx = self.read_snapshot().map_err(CatalogStoreError::from)?;
            let j = require(&tx, op)?;
            if j.state == CatalogPackingOperationState::Cancelled {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            let payload =
                output(&tx, op, id)?.ok_or(CatalogStoreError::from(DatabaseError::NotReady))?;
            tx.commit().map_err(CatalogStoreError::from)?;
            if payload.commitment != commitment {
                return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
            }
            verify(&payload)?;
            count = count
                .checked_add(1)
                .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?;
        }
        if !reader.is_complete() {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let view = CatalogPackingOperationView { connection: &tx };
        guard(&view)?;
        let old = require(&tx, op)?;
        if old.outputs != count
            || old.attempts != count
            || count != manifest.directory.summary.sectors
            || (packing_payloads::operation_state(&tx, op.payloads())?
                .1
                .records
                - 1)
                / 5
                != count
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        {
            let page = manifest.directory.records.page;
            read_page(
                &tx,
                PageMetadata {
                    format_version: 1,
                    scope: manifest.scope,
                    section: CatalogSection::Packing,
                    reference: page,
                },
            )?;
            if bounded_record(&tx, &owners(op.pages()), &page.hash, 0)?.is_none() {
                return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
            }
        }
        match old.state {
            CatalogPackingOperationState::Building => {
                packing_sources::close_for_operation(&tx, op.sources())?;
                packing_payloads::close_for_operation(&tx, op.payloads())?;
                change(
                    &tx,
                    old,
                    Journal {
                        state: CatalogPackingOperationState::PackingComplete(manifest),
                        ..old
                    },
                )?;
            }
            CatalogPackingOperationState::PackingComplete(previous) if previous == manifest => {}
            _ => return Err(CatalogStoreError::from(DatabaseError::Conflict).into()),
        }
        guard(&view)?;
        require(&tx, op)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    /// Rebuild the original authenticated authority on every retry. Sources are
    /// held before callbacks; output sinks must acquire the exact checked loan
    /// before returning. Prefixes remain owned after interrupted construction.
    pub fn produce_catalog_packing_operation_checked<E: From<CatalogStoreError>>(
        &self,
        op: CatalogPackingOperation,
        authority: CatalogPackingAuthority,
        mut checks: (
            impl FnMut(&CatalogPackingOperationView<'_>) -> Result<(), E>,
            impl FnMut(&CatalogPackingOperationView<'_>, &CatalogPackingAuthority) -> Result<(), E>,
        ),
        callbacks: (
            impl FnMut(&CatalogPackingAuthorizedSource, &mut [u8]) -> Result<(), CatalogStoreError>,
            impl FnMut(
                &PackedSector,
                &CatalogPackingOutputAttempt,
            ) -> Result<CatalogPackingPayload, CatalogStoreError>,
        ),
        mut verify: impl FnMut(&CatalogPackingPayload) -> Result<(), E>,
    ) -> Result<CatalogCertifiedPackingDirectoryIndex, E> {
        op.check_authority(&authority)?;
        let current = self.catalog_packing_operation(op.id)?;
        let proof = match current {
            Some((previous, CatalogPackingOperationState::PackingComplete(manifest)))
                if previous == op =>
            {
                authority.validate_packing_directory(
                    manifest,
                    op.construction_budget()?,
                    |page| self.catalog_page(manifest.scope, CatalogSection::Packing, page),
                )?
            }
            Some((previous, _)) if previous != op => {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            Some((_, CatalogPackingOperationState::Cancelled)) => {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            _ => {
                self.begin_catalog_packing_operation_checked(
                    op,
                    &authority,
                    (&mut checks.0, &mut checks.1),
                )?;
                let (render, mut payload) = callbacks;
                let guard = std::cell::RefCell::new(&mut checks.0);
                let produced = authority.produce_packing_directory(
                    op.policy,
                    op.construction_budget()?,
                    (
                        render,
                        |page, bytes| {
                            self.stage_catalog_packing_operation_page_checked(
                                op,
                                page,
                                &bytes,
                                |view| (*guard.borrow_mut())(view),
                            )
                            .map_err(|_| CatalogStoreError::from(DatabaseError::Conflict))
                        },
                        |sector| {
                            let plan = self
                                .plan_catalog_packing_operation_output_checked(op, sector, |view| {
                                    (*guard.borrow_mut())(view)
                                })
                                .map_err(|_| CatalogStoreError::from(DatabaseError::Conflict))?;
                            let output = payload(sector, &plan)?;
                            if output.storage_id != plan.storage_id
                                || output.commitment != sector.descriptor.commitment
                                || output.guild_id != op.base.guild_id
                            {
                                return Err(DatabaseError::Integrity.into());
                            }
                            self.record_catalog_packing_operation_payload_checked(
                                op,
                                plan.sector_id,
                                &output,
                                |view| (*guard.borrow_mut())(view),
                            )
                            .map_err(|_| CatalogStoreError::from(DatabaseError::Conflict))
                        },
                    ),
                )?;
                produced.validate(|page| {
                    self.catalog_page(op.pages().scope, CatalogSection::Packing, page)
                })?
            }
        };
        self.complete_catalog_packing_operation_checked(op, &proof, &mut checks.0, &mut verify)?;
        Ok(proof)
    }

    /// Fencing, both loan jobs and the page role close in one writer. Every
    /// dependency stays live until separate bounded steps; cancellation alone
    /// removes no source, output, page or physical volume data.
    pub fn cancel_catalog_packing_operation(
        &self,
        op: CatalogPackingOperation,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let old = require(&tx, op)?;
        if old.state != CatalogPackingOperationState::Cancelled {
            packing_sources::close_for_operation(&tx, op.sources())?;
            packing_payloads::close_for_operation(&tx, op.payloads())?;
            let mut intent = read_intent(&tx, op.pages())?;
            intent.state = CatalogIntentState::Cancelled;
            write_intent(&tx, &intent)?;
            change(
                &tx,
                old,
                Journal {
                    state: CatalogPackingOperationState::Cancelled,
                    ..old
                },
            )?;
        }
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
