//! Pending packing/coding output custody, distinct from certified availability.
//! The enclosing producer supplies original source authority, physical admission
//! and current-base guards. These pins never publish a checkpoint or READY data.

use super::*;
use mb_core::{CatalogCodingTraversalBudget as Work, MerkleCommitment};

const JOURNAL: &str = "catalog-packing-payload-retention-v1";
const COUNTS: &str = "catalog-packing-payload-owner-count-v1";
const ATTEMPT_COUNTS: &str = "catalog-packing-attempt-owner-count-v1";
const ROW_BYTES: usize = 512;
const ROWS_PER_PAYLOAD: u64 = 5;

/// Independently admitted immutable operation identity and original base.
/// Work charges each logical payload occurrence plus its bounded custody rows;
/// volume reservations and SQL/page/journal/physical limits remain mandatory.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingPayloadRetention {
    pub id: Uuid,
    pub base: CatalogPackingAuthorityBase,
    pub budget: Work,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackingPayloadRetentionState {
    Building,
    Cancelled,
}

/// Exact original physical locator and attempt. Metadata is frozen before
/// staged bytes may be borrowed; no acknowledgement or activation is invented.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingPayload {
    pub guild_id: [u8; 32],
    pub storage_id: [u8; 32],
    pub shard_index: u16,
    pub commitment: MerkleCommitment,
    pub attempt_id: [u8; 16],
    pub volume_id: Uuid,
}

impl CatalogPackingPayload {
    pub(super) fn validate(&self) -> Result<(), CatalogStoreError> {
        self.commitment
            .validate()
            .map_err(|_| DatabaseError::Integrity)?;
        if self.guild_id == [0; 32]
            || self.storage_id == [0; 32]
            || self.attempt_id == [0; 16]
            || self.volume_id.is_nil()
            || self.shard_index >= mb_core::MAX_CODING_SHARDS
            || self.commitment.byte_len < mb_core::MERKLE_LEAF_SIZE as u32
            || !self.commitment.byte_len.is_power_of_two()
            || self.commitment.byte_len > mb_core::MAX_PROFILE_SHARD_SIZE
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(())
    }
    fn key(&self) -> [u8; 34] {
        key(self.storage_id, self.shard_index)
    }
    fn work(&self) -> Work {
        Work {
            bytes: ROWS_PER_PAYLOAD * ROW_BYTES as u64 + u64::from(self.commitment.byte_len),
            page_occurrences: 0,
            records: ROWS_PER_PAYLOAD,
        }
    }
}

fn key(storage: [u8; 32], shard: u16) -> [u8; 34] {
    let mut key = [0; 34];
    key[..32].copy_from_slice(&storage);
    key[32..].copy_from_slice(&shard.to_be_bytes());
    key
}
fn payloads(id: Uuid) -> String {
    format!("catalog-packing-payload-v1/{}", id.simple())
}
fn owners(key: &[u8]) -> String {
    format!("catalog-payload-packing-owner-v1/{}", hex::encode(key))
}
fn attempts(id: [u8; 16]) -> String {
    format!("catalog-attempt-packing-owner-v1/{}", hex::encode(id))
}
fn reverse(id: Uuid, key: [u8; 34]) -> [u8; 50] {
    let mut result = [0; 50];
    result[..16].copy_from_slice(id.as_bytes());
    result[16..].copy_from_slice(&key);
    result
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(mb_core::canonical_bytes_bounded(v, ROW_BYTES)?)
}
fn decode<T: serde::de::DeserializeOwned + Serialize>(b: &[u8]) -> Result<T, CatalogStoreError> {
    let v = decode_canonical(b)?;
    if encode(&v)? != b {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(v)
}
fn has(connection: &Connection, kind: &str) -> Result<bool, CatalogStoreError> {
    Ok(connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind = ?1)",
        [kind],
        |row| row.get(0),
    )?)
}
fn fixed() -> Work {
    Work {
        bytes: ROW_BYTES as u64,
        page_occurrences: 0,
        records: 1,
    }
}
impl CatalogPackingPayloadRetention {
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil()
            || self.base.guild_id == [0; 32]
            || self.base.checkpoint_hash == [0; 32]
            || self.base.generation == 0
            || self.base.membership_epoch == Some(0)
        {
            return Err(DatabaseError::Conflict.into());
        }
        self.budget.remaining_after(fixed())?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Journal {
    version: u16,
    retention: CatalogPackingPayloadRetention,
    state: CatalogPackingPayloadRetentionState,
    count: u64,
    payload_bytes: u64,
}
impl Journal {
    fn work(self) -> Result<Work, CatalogStoreError> {
        fixed()
            .checked_add(Work {
                bytes: self
                    .count
                    .checked_mul(ROWS_PER_PAYLOAD * ROW_BYTES as u64)
                    .and_then(|v| v.checked_add(self.payload_bytes))
                    .ok_or(DatabaseError::Integrity)?,
                page_occurrences: 0,
                records: self
                    .count
                    .checked_mul(ROWS_PER_PAYLOAD)
                    .ok_or(DatabaseError::Integrity)?,
            })
            .map_err(Into::into)
    }
}
fn journal(connection: &Connection, id: Uuid) -> Result<Option<Journal>, CatalogStoreError> {
    if id.is_nil() {
        return Err(DatabaseError::Conflict.into());
    }
    let Some(bytes) = bounded_record(connection, JOURNAL, id.as_bytes(), ROW_BYTES)? else {
        if has(connection, &payloads(id))? {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let value: Journal = decode(&bytes)?;
    value.retention.validate()?;
    if value.version != 1
        || value.retention.id != id
        || has(connection, &payloads(id))? != (value.count != 0)
        || u128::from(value.payload_bytes)
            < u128::from(value.count) * mb_core::MERKLE_LEAF_SIZE as u128
        || u128::from(value.payload_bytes)
            > u128::from(value.count) * u128::from(mb_core::MAX_PROFILE_SHARD_SIZE)
    {
        return Err(DatabaseError::Integrity.into());
    }
    value.retention.budget.remaining_after(value.work()?)?;
    Ok(Some(value))
}
fn require(
    connection: &Connection,
    retention: CatalogPackingPayloadRetention,
) -> Result<Journal, CatalogStoreError> {
    let value = journal(connection, retention.id)?.ok_or(DatabaseError::NotReady)?;
    if value.retention != retention {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(value)
}

pub(super) fn operation_state(
    connection: &Connection,
    retention: CatalogPackingPayloadRetention,
) -> Result<(CatalogPackingPayloadRetentionState, Work), CatalogStoreError> {
    let value = require(connection, retention)?;
    Ok((value.state, value.work()?))
}
pub(super) fn begin_for_operation(
    connection: &Connection,
    retention: CatalogPackingPayloadRetention,
) -> Result<(), CatalogStoreError> {
    retention.validate()?;
    match journal(connection, retention.id)? {
        Some(old)
            if old.retention != retention
                || old.state != CatalogPackingPayloadRetentionState::Building =>
        {
            return Err(DatabaseError::Conflict.into());
        }
        Some(_) => {}
        None => {
            let value = Journal {
                version: 1,
                retention,
                state: CatalogPackingPayloadRetentionState::Building,
                count: 0,
                payload_bytes: 0,
            };
            insert_exact(
                connection,
                JOURNAL,
                retention.id.as_bytes(),
                &encode(&value)?,
            )?;
            if require(connection, retention)? != value {
                return Err(DatabaseError::Integrity.into());
            }
        }
    }
    Ok(())
}
pub(super) fn close_for_operation(
    connection: &Connection,
    retention: CatalogPackingPayloadRetention,
) -> Result<(), CatalogStoreError> {
    let old = require(connection, retention)?;
    if old.state != CatalogPackingPayloadRetentionState::Cancelled {
        change(
            connection,
            old,
            Journal {
                state: CatalogPackingPayloadRetentionState::Cancelled,
                ..old
            },
        )?;
    }
    Ok(())
}
pub(super) fn operation_payload(
    connection: &Connection,
    retention: CatalogPackingPayloadRetention,
    storage: [u8; 32],
    shard: u16,
) -> Result<Option<CatalogPackingPayload>, CatalogStoreError> {
    require(connection, retention)?;
    read(connection, retention.id, &key(storage, shard))
}
fn change(connection: &Connection, old: Journal, next: Journal) -> Result<(), CatalogStoreError> {
    next.retention.budget.remaining_after(next.work()?)?;
    if connection.execute(
        "UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
        params![
            JOURNAL,
            old.retention.id.as_bytes(),
            encode(&old)?,
            encode(&next)?
        ],
    )? != 1
        || journal(connection, next.retention.id)? != Some(next)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn count(
    connection: &Connection,
    family: &str,
    key: &[u8],
    dependencies: &str,
) -> Result<Option<u64>, CatalogStoreError> {
    let value = bounded_record(connection, family, key, ROW_BYTES)?
        .as_deref()
        .map(decode::<u64>)
        .transpose()?;
    if has(connection, dependencies)? != value.is_some_and(|v| v != 0) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}
fn change_count(
    connection: &Connection,
    family: &str,
    key: &[u8],
    dependencies: &str,
    old: Option<u64>,
    next: u64,
) -> Result<(), CatalogStoreError> {
    let bytes = encode(&next)?;
    if let Some(old) = old {
        if connection.execute("UPDATE protocol_records SET bytes = ?4 WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3", params![family, key, encode(&old)?, bytes])? != 1 { return Err(DatabaseError::Integrity.into()); }
    } else {
        insert_exact(connection, family, key, &bytes)?;
    }
    if count(connection, family, key, dependencies)? != Some(next) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn first(
    connection: &Connection,
    kind: &str,
    length: usize,
) -> Result<Option<Vec<u8>>, CatalogStoreError> {
    let row: Option<Option<Vec<u8>>> = connection.query_row("SELECT CASE WHEN length(record_id) = ?2 THEN record_id END FROM protocol_records WHERE kind = ?1 ORDER BY record_id LIMIT 1", params![kind, length], |r| r.get(0)).optional()?;
    row.map(|v| v.ok_or(DatabaseError::Integrity.into()))
        .transpose()
}
fn read(
    connection: &Connection,
    id: Uuid,
    key: &[u8],
) -> Result<Option<CatalogPackingPayload>, CatalogStoreError> {
    if key.len() != 34 {
        return Err(DatabaseError::Integrity.into());
    }
    let forward = bounded_record(connection, &payloads(id), key, ROW_BYTES)?;
    let backward = bounded_record(connection, &owners(key), id.as_bytes(), ROW_BYTES)?;
    let Some(bytes) = forward else {
        if backward.is_some() {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let payload: CatalogPackingPayload = decode(&bytes)?;
    payload.validate()?;
    let journal = journal(connection, id)?.ok_or(DatabaseError::Integrity)?;
    if payload.key().as_slice() != key
        || payload.guild_id != journal.retention.base.guild_id
        || backward.as_deref() != Some(bytes.as_slice())
        || bounded_record(
            connection,
            &attempts(payload.attempt_id),
            &reverse(id, payload.key()),
            ROW_BYTES,
        )?
        .as_deref()
            != Some(bytes.as_slice())
        || count(connection, COUNTS, key, &owners(key))?.unwrap_or(0) == 0
        || count(
            connection,
            ATTEMPT_COUNTS,
            &payload.attempt_id,
            &attempts(payload.attempt_id),
        )?
        .unwrap_or(0)
            == 0
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(payload))
}

pub(super) fn is_pinned(
    connection: &Connection,
    storage: [u8; 32],
    shard: u16,
    root: [u8; 32],
) -> Result<bool, CatalogStoreError> {
    let key = key(storage, shard);
    let count = count(connection, COUNTS, &key, &owners(&key))?;
    let Some(owner) = first(connection, &owners(&key), 16)? else {
        return Ok(false);
    };
    if count.unwrap_or(0) == 0 {
        return Err(DatabaseError::Integrity.into());
    }
    let owner = Uuid::from_slice(&owner).map_err(|_| DatabaseError::Integrity)?;
    let payload = read(connection, owner, &key)?.ok_or(DatabaseError::Integrity)?;
    if payload.commitment.root != root {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(true)
}
pub(super) fn attempt_is_pinned(
    connection: &Connection,
    attempt: [u8; 16],
) -> Result<bool, CatalogStoreError> {
    let count = count(connection, ATTEMPT_COUNTS, &attempt, &attempts(attempt))?;
    let Some(owner) = first(connection, &attempts(attempt), 50)? else {
        return Ok(false);
    };
    if count.unwrap_or(0) == 0 {
        return Err(DatabaseError::Integrity.into());
    }
    let id = Uuid::from_slice(&owner[..16]).map_err(|_| DatabaseError::Integrity)?;
    if read(connection, id, &owner[16..])?
        .ok_or(DatabaseError::Integrity)?
        .attempt_id
        != attempt
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(true)
}

/// Bounded reads inside the same custody writer. Current base/event guards and
/// physical verification must not open a nested control transaction.
pub struct CatalogPackingPayloadView<'a> {
    connection: &'a Connection,
}
impl CatalogPackingPayloadView<'_> {
    pub fn record(
        &self,
        kind: &str,
        key: &[u8],
        limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        bounded_record(self.connection, kind, key, limit)
    }
}

impl ControlStore {
    pub fn begin_catalog_packing_payload_retention<E: From<CatalogStoreError>>(
        &self,
        retention: CatalogPackingPayloadRetention,
        mut guard: impl FnMut(&CatalogPackingPayloadView<'_>) -> Result<(), E>,
    ) -> Result<(), E> {
        retention.validate()?;
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        packing_operation::require_job_building(&tx, retention.id)?;
        let view = CatalogPackingPayloadView { connection: &tx };
        guard(&view)?;
        match journal(&tx, retention.id)? {
            Some(old)
                if old.retention != retention
                    || old.state != CatalogPackingPayloadRetentionState::Building =>
            {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
            Some(_) => {}
            None => {
                let value = Journal {
                    version: 1,
                    retention,
                    state: CatalogPackingPayloadRetentionState::Building,
                    count: 0,
                    payload_bytes: 0,
                };
                insert_exact(&tx, JOURNAL, retention.id.as_bytes(), &encode(&value)?)?;
                if require(&tx, retention)? != value {
                    return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
                }
            }
        }
        guard(&view)?;
        if require(&tx, retention)?.state != CatalogPackingPayloadRetentionState::Building {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    /// Retain one exact physically verified pending output. Independently
    /// admitted byte/record work precedes verification; exact retries verify
    /// again without another charge. This grants neither source authority nor
    /// public availability. The enclosing producer still owns staging intents.
    pub fn retain_catalog_packing_payload_checked<E: From<CatalogStoreError>>(
        &self,
        retention: CatalogPackingPayloadRetention,
        payload: &CatalogPackingPayload,
        callbacks: (
            impl FnMut(&CatalogPackingPayloadView<'_>) -> Result<(), E>,
            impl FnOnce(&CatalogPackingPayload) -> Result<(), E>,
        ),
    ) -> Result<(), E> {
        payload.validate()?;
        if payload.guild_id != retention.base.guild_id {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)
            .map_err(CatalogStoreError::from)?;
        let (mut guard, check) = callbacks;
        packing_operation::require_job_building(&tx, retention.id)?;
        let view = CatalogPackingPayloadView { connection: &tx };
        guard(&view)?;
        let old = require(&tx, retention)?;
        if old.state != CatalogPackingPayloadRetentionState::Building {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let key = payload.key();
        let bytes = encode(payload)?;
        let existing = read(&tx, retention.id, &key)?;
        if existing.as_ref().is_some_and(|v| v != payload) {
            return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
        }
        let owner_count = count(&tx, COUNTS, &key, &owners(&key))?;
        let attempt_count = count(
            &tx,
            ATTEMPT_COUNTS,
            &payload.attempt_id,
            &attempts(payload.attempt_id),
        )?;
        if let Some(owner) = first(&tx, &owners(&key), 16)? {
            let id = Uuid::from_slice(&owner)
                .map_err(|_| CatalogStoreError::from(DatabaseError::Integrity))?;
            if read(&tx, id, &key)?.as_ref() != Some(payload) {
                return Err(CatalogStoreError::from(DatabaseError::Conflict).into());
            }
        }
        let next = if existing.is_none() {
            let next = Journal {
                count: old
                    .count
                    .checked_add(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                payload_bytes: old
                    .payload_bytes
                    .checked_add(u64::from(payload.commitment.byte_len))
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
                ..old
            };
            retention
                .budget
                .remaining_after(
                    old.work()?
                        .checked_add(payload.work())
                        .map_err(CatalogStoreError::from)?,
                )
                .map_err(CatalogStoreError::from)?;
            Some(next)
        } else {
            None
        };
        check(payload)?;
        if let Some(next) = next {
            insert_exact(&tx, &payloads(retention.id), &key, &bytes)?;
            insert_exact(&tx, &owners(&key), retention.id.as_bytes(), &bytes)?;
            insert_exact(
                &tx,
                &attempts(payload.attempt_id),
                &reverse(retention.id, key),
                &bytes,
            )?;
            change_count(
                &tx,
                COUNTS,
                &key,
                &owners(&key),
                owner_count,
                owner_count
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
            )?;
            change_count(
                &tx,
                ATTEMPT_COUNTS,
                &payload.attempt_id,
                &attempts(payload.attempt_id),
                attempt_count,
                attempt_count
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(CatalogStoreError::from(DatabaseError::Integrity))?,
            )?;
            change(&tx, old, next)?;
        }
        guard(&view)?;
        if require(&tx, retention)?.state != CatalogPackingPayloadRetentionState::Building
            || read(&tx, retention.id, &key)?.as_ref() != Some(payload)
        {
            return Err(CatalogStoreError::from(DatabaseError::Integrity).into());
        }
        tx.commit().map_err(CatalogStoreError::from)?;
        Ok(())
    }

    pub fn catalog_packing_payload_retention(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(
            CatalogPackingPayloadRetention,
            CatalogPackingPayloadRetentionState,
        )>,
        CatalogStoreError,
    > {
        let tx = self.read_snapshot()?;
        let result = journal(&tx, id)?.map(|v| (v.retention, v.state));
        tx.commit()?;
        Ok(result)
    }
    pub fn catalog_packing_payload(
        &self,
        retention: CatalogPackingPayloadRetention,
        storage: [u8; 32],
        shard: u16,
    ) -> Result<Option<CatalogPackingPayload>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        let result = read(&tx, retention.id, &key(storage, shard))?;
        tx.commit()?;
        Ok(result)
    }
    pub fn cancel_catalog_packing_payload_retention(
        &self,
        retention: CatalogPackingPayloadRetention,
    ) -> Result<(), CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        packing_operation::require_job_retired(&tx, retention.id)?;
        close_for_operation(&tx, retention)?;
        tx.commit()?;
        Ok(())
    }
    /// Release at most one output loan. Original volume intent/receipt ownership
    /// remains until physical cleanup; other pending/checkpoint loans still
    /// exclude deletion. Source loans and enclosing job completion are separate.
    pub fn release_catalog_packing_payload(
        &self,
        retention: CatalogPackingPayloadRetention,
    ) -> Result<bool, CatalogStoreError> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        packing_operation::require_job_retired(&tx, retention.id)?;
        let old = require(&tx, retention)?;
        if old.state != CatalogPackingPayloadRetentionState::Cancelled {
            return Err(DatabaseError::Conflict.into());
        }
        let Some(key) = first(&tx, &payloads(retention.id), 34)? else {
            tx.commit()?;
            return Ok(false);
        };
        let payload = read(&tx, retention.id, &key)?.ok_or(DatabaseError::Integrity)?;
        let bytes = encode(&payload)?;
        let owners_count =
            count(&tx, COUNTS, &key, &owners(&key))?.ok_or(DatabaseError::Integrity)?;
        let attempt_count = count(
            &tx,
            ATTEMPT_COUNTS,
            &payload.attempt_id,
            &attempts(payload.attempt_id),
        )?
        .ok_or(DatabaseError::Integrity)?;
        for (kind, key) in [
            (payloads(retention.id), key.clone()),
            (owners(&key), retention.id.as_bytes().to_vec()),
            (
                attempts(payload.attempt_id),
                reverse(retention.id, payload.key()).to_vec(),
            ),
        ] {
            if tx.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![kind, key, bytes],
            )? != 1
                || bounded_record(&tx, &kind, &key, ROW_BYTES)?.is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        change_count(
            &tx,
            COUNTS,
            &key,
            &owners(&key),
            Some(owners_count),
            owners_count
                .checked_sub(1)
                .ok_or(DatabaseError::Integrity)?,
        )?;
        change_count(
            &tx,
            ATTEMPT_COUNTS,
            &payload.attempt_id,
            &attempts(payload.attempt_id),
            Some(attempt_count),
            attempt_count
                .checked_sub(1)
                .ok_or(DatabaseError::Integrity)?,
        )?;
        change(
            &tx,
            old,
            Journal {
                count: old.count.checked_sub(1).ok_or(DatabaseError::Integrity)?,
                payload_bytes: old
                    .payload_bytes
                    .checked_sub(u64::from(payload.commitment.byte_len))
                    .ok_or(DatabaseError::Integrity)?,
                ..old
            },
        )?;
        tx.commit()?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
