//! Actual READY payload custody under the enclosing checkpoint owner.
//! Control writers serialize acquisition with destructive volume operations.

use mb_core::{
    CatalogCodingTraversalBudget as Work, MerkleCommitment, NodeId, PagedCheckpointTrust,
    ShardRoleV2,
};

use super::checkpoint_body::Header;
use super::paged_checkpoint_retention::{Layout, Proof, owned_certificate, validate_owner};
use super::retention_journal as journal;
use super::*;

const ROW_BYTES: usize = 512;
const TOTALS: &str = "catalog-checkpoint-payload-work-v1";

fn dependencies(id: Uuid) -> String {
    format!("catalog-checkpoint-payload-v1/{}", id.simple())
}
fn owners(storage: [u8; 32], shard: u16) -> String {
    format!(
        "catalog-payload-checkpoint-v1/{}/{shard:04x}",
        hex::encode(storage)
    )
}
fn key(group: [u8; 32], shard: u16) -> [u8; 34] {
    let mut key = [0; 34];
    key[..32].copy_from_slice(&group);
    key[32..].copy_from_slice(&shard.to_be_bytes());
    key
}
fn owner_key(id: Uuid, group: [u8; 32], shard: u16) -> [u8; 50] {
    let mut key = [0; 50];
    key[..16].copy_from_slice(id.as_bytes());
    key[16..].copy_from_slice(&self::key(group, shard));
    key
}

/// One physical local role from the exact original certified coding witness.
/// Information objects use their sector ID; parity objects use their group ID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointPayload {
    pub guild_id: [u8; 32],
    pub group_id: [u8; 32],
    pub storage_id: [u8; 32],
    pub shard_index: u16,
    pub holder: NodeId,
    pub commitment: MerkleCommitment,
    pub transcript_hash: [u8; 32],
    pub replay_work: Work,
}

impl CatalogCheckpointPayload {
    fn validate(&self) -> Result<(), CatalogStoreError> {
        self.commitment.validate().map_err(ModelError::from)?;
        if self.guild_id == [0; 32]
            || self.group_id == [0; 32]
            || self.storage_id == [0; 32]
            || self.holder.0 == [0; 32]
            || self.transcript_hash == [0; 32]
            || self.shard_index > u8::MAX as u16
            || self.replay_work.bytes == 0
            || self.replay_work.page_occurrences == 0
            || self.replay_work.records == 0
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }
    fn work(&self) -> Result<Work, CatalogStoreError> {
        Ok(Work {
            bytes: u64::from(self.commitment.byte_len) + 3 * ROW_BYTES as u64,
            page_occurrences: 0,
            records: 3,
        }
        .checked_add(self.replay_work)?)
    }
}

fn read(
    connection: &Connection,
    id: Uuid,
    group: [u8; 32],
    shard: u16,
) -> Result<Option<CatalogCheckpointPayload>, CatalogStoreError> {
    let Some(bytes) = bounded_record(connection, &dependencies(id), &key(group, shard), ROW_BYTES)?
    else {
        return Ok(None);
    };
    let payload: CatalogCheckpointPayload = decode_canonical(&bytes)?;
    payload.validate()?;
    if payload.group_id != group
        || payload.shard_index != shard
        || canonical_bytes(&payload)? != bytes
        || bounded_record(
            connection,
            &owners(payload.storage_id, shard),
            &owner_key(id, group, shard),
            ROW_BYTES,
        )?
        .as_deref()
            != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(payload))
}

fn has_dependencies(connection: &Connection, id: Uuid) -> Result<bool, CatalogStoreError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        params![dependencies(id)],
        |row| row.get(0),
    )?)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Totals {
    count: u64,
    work: Work,
}

fn raw_totals<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Totals>, CatalogStoreError> {
    let stored = bounded_record(connection, TOTALS, retention.id.as_bytes(), ROW_BYTES)?;
    let totals: Option<Totals> = stored
        .as_ref()
        .map(|bytes| decode_canonical(bytes))
        .transpose()?;
    if let Some(totals) = totals {
        let summary = retention.checkpoint.coding();
        if canonical_bytes(&totals)? != *stored.as_ref().ok_or(DatabaseError::Integrity)?
            || totals.count
                > summary
                    .information_roles
                    .checked_add(summary.parity_roles)
                    .ok_or(CatalogError::Bounds)?
            || totals.work.records < totals.count.checked_mul(3).ok_or(CatalogError::Bounds)?
            || (totals.count == 0) != (totals.work == Work::default())
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    if has_dependencies(connection, retention.id)? != totals.is_some_and(|totals| totals.count != 0)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(totals)
}

pub(super) fn owned_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Work>, CatalogStoreError> {
    Ok(raw_totals(connection, retention)?.map(|totals| totals.work))
}

pub(super) fn owned_count<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<u64, CatalogStoreError> {
    Ok(raw_totals(connection, retention)?.map_or(0, |totals| totals.count))
}

pub(super) fn admitted_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Work>, CatalogStoreError> {
    let work = owned_work(connection, retention)?;
    check_work(connection, retention, work.unwrap_or_default())?;
    Ok(work)
}

fn check_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    work: Work,
) -> Result<(), CatalogStoreError> {
    retention.budget.remaining_after(
        retention
            .proof_work
            .checked_add(retention.checkpoint.work()?)?
            .checked_add(work)?
            .checked_add(paged_checkpoint_lookup::owned_work(connection, retention)?)?
            .checked_add(
                paged_checkpoint_legacy_revision::owned_work(connection, retention)?
                    .unwrap_or_default(),
            )?
            .checked_add(paged_checkpoint_custody::owned_work(connection, retention)?)?
            .checked_add(
                paged_checkpoint_revision::owned_work(connection, retention)?.unwrap_or_default(),
            )?,
    )?;
    Ok(())
}

pub(super) fn require_unowned(connection: &Connection, id: Uuid) -> Result<(), CatalogStoreError> {
    if has_dependencies(connection, id)?
        || bounded_record(connection, TOTALS, id.as_bytes(), ROW_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn change_work<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
    previous: Option<Totals>,
    next: Work,
    adding: bool,
) -> Result<(), CatalogStoreError> {
    let old = raw_totals_after_mutation(connection, retention)?;
    if old != previous {
        return Err(DatabaseError::Conflict.into());
    }
    let count = old.map_or(0, |totals| totals.count);
    let count = if adding {
        count.checked_add(1)
    } else {
        count.checked_sub(1)
    }
    .ok_or(CatalogError::Bounds)?;
    let totals = Totals { count, work: next };
    let bytes = canonical_bytes(&totals)?;
    if let Some(old) = old {
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![TOTALS, retention.id.as_bytes(), canonical_bytes(&old)?, bytes])? != 1 { return Err(DatabaseError::Conflict.into()); }
    } else {
        insert_exact(connection, TOTALS, retention.id.as_bytes(), &bytes)?;
    }
    if raw_totals(connection, retention)? != Some(totals)
        || admitted_work(connection, retention)? != Some(next)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

// Paired dependencies have already changed in this same writer; the previous
// counter is read without comparing it to the new presence/absence of rows.
fn raw_totals_after_mutation<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Totals>, CatalogStoreError> {
    let stored = bounded_record(connection, TOTALS, retention.id.as_bytes(), ROW_BYTES)?;
    stored
        .map(|bytes| {
            let totals: Totals = decode_canonical(&bytes)?;
            if canonical_bytes(&totals)? != bytes {
                return Err(DatabaseError::Integrity.into());
            }
            Ok(totals)
        })
        .transpose()
}

fn is_pinned(
    connection: &Connection,
    storage: [u8; 32],
    shard: u16,
    root: [u8; 32],
) -> Result<bool, CatalogStoreError> {
    let pending = packing_payloads::is_pinned(connection, storage, shard, root)?;
    let owner: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN length(record_id) = 50 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
        params![owners(storage, shard)], |row| row.get(0)).optional()?;
    let Some(owner) = owner else {
        return Ok(pending);
    };
    let owner = owner.ok_or(DatabaseError::Integrity)?;
    let id = Uuid::from_slice(&owner[..16]).map_err(|_| DatabaseError::Integrity)?;
    let group: [u8; 32] = owner[16..48]
        .try_into()
        .map_err(|_| DatabaseError::Integrity)?;
    if id.is_nil() || owner[48..] != shard.to_be_bytes() {
        return Err(DatabaseError::Integrity.into());
    }
    let payload = read(connection, id, group, shard)?.ok_or(DatabaseError::Integrity)?;
    if payload.storage_id != storage || payload.commitment.root != root {
        return Err(DatabaseError::Conflict.into());
    }
    validate_owner(connection, id)?;
    Ok(true)
}

/// Pin checks and exact locator retirement while the control writer excludes
/// custody acquisition. Callbacks may mutate a volume database, but must not
/// start another control transaction or mutate other control state.
pub struct CatalogPayloadRetirementView<'a> {
    connection: &'a Connection,
}
impl<'a> CatalogPayloadRetirementView<'a> {
    pub(super) fn new(connection: &'a Connection) -> Self {
        Self { connection }
    }

    /// Read one bounded original locator under the held custody writer.
    pub fn record(
        &self,
        kind: &str,
        key: &[u8],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        if kind.len() > 128 || key.len() > 64 || limit > 8192 {
            return Err(DatabaseError::Integrity.into());
        }
        bounded_record(self.connection, kind, key, limit)
    }

    /// Check exact owner evidence without materializing its body.
    pub fn record_exists(&self, kind: &str, key: &[u8]) -> Result<bool, CatalogStoreError> {
        if kind.len() > 128 || key.len() > 64 {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(self.connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1 AND record_id=?2)",
            params![kind, key],
            |r| r.get(0),
        )?)
    }

    /// Pending producers also own incomplete reservations and STAGED objects.
    pub fn attempt_is_pinned(&self, attempt: [u8; 16]) -> Result<bool, CatalogStoreError> {
        packing_payloads::attempt_is_pinned(self.connection, attempt)
    }

    /// Retire only an exact canonical version-1 attempt locator. All three
    /// established records begin with the immutable attempt ID. Pending output
    /// loans keep reservations/receipts live even before a payload is READY.
    pub fn retire_attempt_record(
        &self,
        kind: &str,
        key: &[u8],
        attempt: [u8; 16],
        expected: &[u8],
    ) -> Result<bool, CatalogStoreError> {
        let prefix = canonical_bytes(&(1_u16, attempt))?;
        if !matches!(
            kind,
            "volume-attempt-intent" | "volume-attempt-receipt" | "volume-attempt-reservation"
        ) || key.len() > 64
            || expected.len() > 512
            || !expected.starts_with(&prefix)
        {
            return Err(DatabaseError::Integrity.into());
        }
        if self.attempt_is_pinned(attempt)? {
            return Ok(false);
        }
        if bounded_record(self.connection, kind, key, 512)?.as_deref() != Some(expected) {
            return Err(DatabaseError::Conflict.into());
        }
        if self.connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, key, expected],
        )? != 1
            || bounded_record(self.connection, kind, key, 512)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(true)
    }

    pub fn is_pinned(
        &self,
        storage: [u8; 32],
        shard: u16,
        root: [u8; 32],
    ) -> Result<bool, CatalogStoreError> {
        is_pinned(self.connection, storage, shard, root)
    }

    /// Retire the exact active locator only while physical custody is unpinned.
    /// The fixed namespace/key prevents callbacks from changing custody records.
    pub fn retire_volume_receipt(
        &self,
        storage: [u8; 32],
        shard: u16,
        root: [u8; 32],
        expected: &[u8],
    ) -> Result<bool, CatalogStoreError> {
        if expected.len() > ROW_BYTES || shard > u8::MAX as u16 {
            return Err(DatabaseError::Integrity.into());
        }
        if self.is_pinned(storage, shard, root)? {
            return Ok(false);
        }
        let mut key = storage.to_vec();
        key.push(shard as u8);
        if bounded_record(self.connection, "volume-receipt", &key, ROW_BYTES)?.as_deref()
            != Some(expected)
        {
            return Err(DatabaseError::Conflict.into());
        }
        if self.connection.execute("DELETE FROM protocol_records WHERE kind = 'volume-receipt' AND record_id = ?1 AND bytes = ?2", params![key, expected])? != 1
            || bounded_record(self.connection, "volume-receipt", &key, ROW_BYTES)?.is_some() { return Err(DatabaseError::Integrity.into()); }
        Ok(true)
    }
}

pub(super) fn release<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<bool, CatalogStoreError> {
    if journal::require(connection, retention)?.state
        != CatalogPagedCheckpointRetentionState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    let previous = raw_totals(connection, retention)?;
    admitted_work(connection, retention)?;
    let row: Option<Option<Vec<u8>>> = connection.query_row(
        "SELECT CASE WHEN length(record_id) = 34 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1",
        params![dependencies(retention.id)], |row| row.get(0)).optional()?;
    let Some(row) = row else { return Ok(false) };
    let row = row.ok_or(DatabaseError::Integrity)?;
    let group = row[..32].try_into().map_err(|_| DatabaseError::Integrity)?;
    let shard = u16::from_be_bytes(row[32..].try_into().map_err(|_| DatabaseError::Integrity)?);
    let payload = read(connection, retention.id, group, shard)?.ok_or(DatabaseError::Integrity)?;
    owned_certificate(connection, retention)?;
    let bytes = canonical_bytes(&payload)?;
    for (kind, key) in [
        (dependencies(retention.id), row),
        (
            owners(payload.storage_id, shard),
            owner_key(retention.id, group, shard).to_vec(),
        ),
    ] {
        if connection.execute(
            "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
            params![kind, key, bytes],
        )? != 1
            || bounded_record(connection, &kind, &key, ROW_BYTES)?.is_some()
        {
            return Err(DatabaseError::Integrity.into());
        }
    }
    change_work(
        connection,
        retention,
        previous,
        previous
            .ok_or(DatabaseError::Integrity)?
            .work
            .remaining_after(payload.work()?)?,
        false,
    )?;
    owned_certificate(connection, retention)?;
    if journal::require(connection, retention)?.state
        != CatalogPagedCheckpointRetentionState::Cancelled
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(true)
}

macro_rules! payload_api {
    ($proof:ty, $retain:ident) => {
        impl ControlStore {
            /// Verify actual READY bytes and retain one exact original coding
            /// role in the enclosing checkpoint writer. Distributed readiness
            /// still requires every assigned role.
            pub fn $retain<E: From<CatalogStoreError>>(
                &self,
                id: Uuid,
                proof: &$proof,
                group: [u8; 32],
                shard: u16,
                read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
                check: impl FnOnce(&CatalogCheckpointPayload) -> Result<(), E>,
            ) -> Result<CatalogCheckpointPayload, E> {
                self.retain_checkpoint_payload_checked(id, proof, group, shard, read_trust, check)
            }
        }
    };
}
payload_api!(
    CatalogQuorumPagedCheckpointIndex,
    retain_catalog_paged_checkpoint_payload_checked
);
payload_api!(
    CatalogQuorumPagedCheckpointDirectoryIndex,
    retain_catalog_paged_checkpoint_directory_payload_checked
);

impl ControlStore {
    pub fn catalog_paged_checkpoint_payload(
        &self,
        id: Uuid,
        group: [u8; 32],
        shard: u16,
    ) -> Result<Option<CatalogCheckpointPayload>, CatalogStoreError> {
        if id.is_nil() {
            return Err(DatabaseError::Conflict.into());
        }
        let tx = self.read_snapshot()?;
        let payload = read(&tx, id, group, shard)?;
        if payload.is_some() {
            validate_owner(&tx, id)?;
        }
        tx.commit()?;
        Ok(payload)
    }
    /// Verify actual READY custody and publish one physical role dependency in
    /// the control writer. The callback must authenticate full payload bytes.
    /// This is one local role, not complete distributed checkpoint readiness.
    pub(super) fn retain_checkpoint_payload_checked<P: Proof, E: From<CatalogStoreError>>(
        &self,
        id: Uuid,
        proof: &P,
        group: [u8; 32],
        shard: u16,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
        check: impl FnOnce(&CatalogCheckpointPayload) -> Result<(), E>,
    ) -> Result<CatalogCheckpointPayload, E> {
        proof.recheck(&mut read_trust)?;
        let mut acquire = || -> Result<_, CatalogStoreError> {
            if id.is_nil() {
                return Err(DatabaseError::Conflict.into());
            }
            let retention = proof.retention(id)?;
            // Bound point replay against this owner's complete custody debt.
            // Release the read snapshot before fetching witness pages; the
            // writer below rechecks admission against any intervening changes.
            let tx = self.read_snapshot()?;
            self.guard_paged_candidate(retention, &mut read_trust)?;
            if journal::require(&tx, retention)?.state
                != CatalogPagedCheckpointRetentionState::Published
            {
                return Err(DatabaseError::Conflict.into());
            }
            owned_certificate(&tx, retention)?;
            let work = admitted_work(&tx, retention)?.unwrap_or_default();
            let existing = read(&tx, id, group, shard)?;
            // A retry authenticates its original witness without charging the
            // same role twice. All other roles and private dependencies remain
            // debited, along with this role's rows and known physical bytes.
            let other_payload_work = work.remaining_after(
                existing
                    .as_ref()
                    .map(|payload| payload.work())
                    .transpose()?
                    .unwrap_or_default(),
            )?;
            let replay_budget = retention.budget.remaining_after(
                retention
                    .proof_work
                    .checked_add(retention.checkpoint.work()?)?
                    .checked_add(other_payload_work)?
                    .checked_add(paged_checkpoint_lookup::owned_work(&tx, retention)?)?
                    .checked_add(paged_checkpoint_custody::owned_work(&tx, retention)?)?
                    .checked_add(
                        paged_checkpoint_legacy_revision::owned_work(&tx, retention)?
                            .unwrap_or_default(),
                    )?
                    .checked_add(
                        paged_checkpoint_revision::owned_work(&tx, retention)?.unwrap_or_default(),
                    )?
                    .checked_add(Work {
                        bytes: 3 * ROW_BYTES as u64
                            + existing
                                .as_ref()
                                .map_or(0, |payload| u64::from(payload.commitment.byte_len)),
                        page_occurrences: 0,
                        records: 3,
                    })?,
            )?;
            tx.commit()?;
            let (entry, replay_work) = proof
                .read_group(group, replay_budget, |page| {
                    self.catalog_page(
                        CatalogScope::Guild {
                            guild_id: retention.checkpoint.guild_id(),
                        },
                        CatalogSection::Coding,
                        page,
                    )
                })?
                .ok_or(DatabaseError::NotReady)?;
            let role = entry
                .retained
                .group
                .roles
                .get(usize::from(shard))
                .ok_or(DatabaseError::Conflict)?;
            let (holder, storage_id, commitment) = match role {
                ShardRoleV2::Information(role) if !role.sector.virtual_zero => {
                    (role.owner, role.sector.id, role.sector.commitment.clone())
                }
                ShardRoleV2::Parity(role) => (role.holder, group, role.commitment.clone()),
                _ => return Err(DatabaseError::Conflict.into()),
            };
            let payload = CatalogCheckpointPayload {
                guild_id: retention.checkpoint.guild_id(),
                group_id: group,
                storage_id,
                shard_index: shard,
                holder,
                commitment,
                transcript_hash: *blake3::hash(&canonical_bytes(&entry.transcript)?).as_bytes(),
                replay_work,
            };
            payload.validate()?;
            Ok((retention, payload))
        };
        let (retention, payload) = acquire()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        self.guard_paged_candidate(retention, &mut read_trust)?;
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        owned_certificate(&tx, retention)?;
        let previous = raw_totals(&tx, retention)?;
        admitted_work(&tx, retention)?;
        let row = key(group, shard);
        let reverse = owner_key(id, group, shard);
        let next = if let Some(existing) = read(&tx, id, group, shard)? {
            if existing != payload {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            None
        } else {
            if bounded_record(&tx, &owners(payload.storage_id, shard), &reverse, ROW_BYTES)?
                .is_some()
            {
                return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
            }
            let next = previous
                .map(|totals| totals.work)
                .unwrap_or_default()
                .checked_add(payload.work()?)
                .map_err(CatalogStoreError::from)?;
            check_work(&tx, retention, next)?;
            Some(next)
        };
        check(&payload)?;
        if let Some(next) = next {
            let bytes = canonical_bytes(&payload).map_err(CatalogStoreError::from)?;
            insert_exact(&tx, &dependencies(id), &row, &bytes)?;
            insert_exact(&tx, &owners(payload.storage_id, shard), &reverse, &bytes)?;
            change_work(&tx, retention, previous, next, true)?;
        }
        if read(&tx, id, group, shard)?.as_ref() != Some(&payload) {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        owned_certificate(&tx, retention)?;
        admitted_work(&tx, retention)?;
        if journal::require(&tx, retention)?.state
            != CatalogPagedCheckpointRetentionState::Published
        {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        self.guard_paged_candidate(retention, &mut read_trust)?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(payload)
    }

    pub fn catalog_checkpoint_payload_is_pinned(
        &self,
        storage: [u8; 32],
        shard: u16,
        root: [u8; 32],
    ) -> Result<bool, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        let pinned = is_pinned(&tx, storage, shard, root)?;
        tx.commit()?;
        Ok(pinned)
    }

    /// Hold the control writer across volume deletions and their pin checks.
    /// This serializes with custody acquisition across separate databases.
    pub fn with_catalog_checkpoint_payload_retirement<T, E: From<CatalogStoreError>>(
        &self,
        delete: impl FnOnce(&CatalogPayloadRetirementView<'_>) -> Result<T, E>,
    ) -> Result<T, E> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let result = delete(&CatalogPayloadRetirementView { connection: &tx })?;
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(result)
    }
}
