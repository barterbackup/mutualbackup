//! Retained recovery locators from the complete original packing/coding proof.
//! These rows select bytes; only original witnesses and full commitments
//! authenticate recovery. Construction and retirement use bounded batches.

use super::*;
use mb_core::{PackingProfile, SourceChunkId, canonical_bytes_bounded};

const JOURNAL: &str = "catalog-checkpoint-chunk-index-v1";
const KEY_BYTES: usize = 104;
const LOCATION_BYTES: usize = 256;
const BATCH: usize = 64;

fn rows(id: Uuid) -> String {
    format!("catalog-checkpoint-chunk-location-v1/{}", id.simple())
}

/// An untrusted lookup hint, never authority for a source or storage role.
/// Consumers must authenticate the original group, recover its exact packed
/// commitment, and verify the complete original source ciphertext commitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointChunkLocation {
    pub sector_id: [u8; 32],
    pub slot_index: u32,
    pub group_id: [u8; 32],
    pub shard_index: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Index {
    version: u16,
    owner: Uuid,
    checkpoint_hash: [u8; 32],
    certificate_hash: [u8; 32],
    trust_hash: [u8; 32],
    count: u64,
    #[serde(deserialize_with = "bounded_cursor")]
    after: Option<Vec<u8>>,
    complete: bool,
    work: Work,
}

fn bounded_cursor<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    struct Cursor;
    impl<'de> serde::de::Visitor<'de> for Cursor {
        type Value = Option<Vec<u8>>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("an optional bounded source key")
        }
        fn visit_none<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_unit<E: serde::de::Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            decoder: D,
        ) -> Result<Self::Value, D::Error> {
            struct Key;
            impl<'de> serde::de::Visitor<'de> for Key {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("at most 104 source key bytes")
                }
                fn visit_seq<A: serde::de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Vec<u8>, A::Error> {
                    if seq.size_hint().is_some_and(|n| n > KEY_BYTES) {
                        return Err(serde::de::Error::custom("oversized source cursor"));
                    }
                    let mut key = Vec::with_capacity(KEY_BYTES);
                    while let Some(byte) = seq.next_element()? {
                        if key.len() == KEY_BYTES {
                            return Err(serde::de::Error::custom("oversized source cursor"));
                        }
                        key.push(byte);
                    }
                    Ok(key)
                }
            }
            decoder.deserialize_seq(Key).map(Some)
        }
    }
    decoder.deserialize_option(Cursor)
}

fn reservation<H: Layout>(
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    let count = retention.checkpoint.packing_geometry().1;
    Ok(Work {
        bytes: count
            .checked_mul((KEY_BYTES + LOCATION_BYTES) as u64)
            .and_then(|n| n.checked_add(ROW_BYTES as u64))
            .ok_or(DatabaseError::CapacityExceeded)?,
        records: count
            .checked_add(1)
            .ok_or(DatabaseError::CapacityExceeded)?,
        page_occurrences: 0,
    })
}

fn read<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Option<Index>, CatalogStoreError> {
    let Some(bytes) = bounded_record(cx, JOURNAL, retention.id.as_bytes(), ROW_BYTES)? else {
        if cx.query_row(
            "SELECT EXISTS(SELECT 1 FROM protocol_records WHERE kind=?1)",
            [rows(retention.id)],
            |r| r.get::<_, bool>(0),
        )? {
            return Err(DatabaseError::Integrity.into());
        }
        return Ok(None);
    };
    let index: Index = decode_row(&bytes)?;
    let chunks = retention.checkpoint.packing_geometry().1;
    if index.version != 1
        || index.owner != retention.id
        || index.checkpoint_hash != retention.checkpoint.hash()?
        || index.certificate_hash != retention.certificate_hash
        || index.trust_hash != retention.trust_hash
        || index.work != reservation(retention)?
        || index.count > chunks
        || index.complete && index.count != chunks
        || (index.count == 0) != index.after.is_none()
        || index
            .after
            .as_ref()
            .is_some_and(|key| key.len() > KEY_BYTES)
    {
        return Err(DatabaseError::Integrity.into());
    }
    if let Some(key) = &index.after {
        let source: SourceChunkId = decode_canonical(key)?;
        if canonical_bytes_bounded(&source, KEY_BYTES)? != *key {
            return Err(DatabaseError::Integrity.into());
        }
    }
    Ok(Some(index))
}

pub(super) fn owned_work<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<Work, CatalogStoreError> {
    Ok(read(cx, retention)?.map_or(Work::default(), |index| index.work))
}

pub(super) fn release<H: Layout>(
    cx: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<bool, CatalogStoreError> {
    let Some(index) = read(cx, retention)? else {
        return Ok(false);
    };
    if journal::require(cx, retention)?.state != CatalogPagedCheckpointRetentionState::Cancelled {
        return Err(DatabaseError::Conflict.into());
    }
    let name = rows(retention.id);
    let row: Option<BoundedRow> = cx.query_row("SELECT CASE WHEN length(record_id)<=?2 THEN record_id END,CASE WHEN length(bytes)<=?3 THEN bytes END FROM protocol_records WHERE kind=?1 ORDER BY record_id LIMIT 1", params![name, KEY_BYTES, LOCATION_BYTES], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
    let (kind, key, bytes) = if let Some((key, bytes)) = row {
        (
            name,
            key.ok_or(DatabaseError::Integrity)?,
            bytes.ok_or(DatabaseError::Integrity)?,
        )
    } else {
        (
            JOURNAL.to_string(),
            retention.id.as_bytes().to_vec(),
            canonical_bytes(&index)?,
        )
    };
    if cx.execute(
        "DELETE FROM protocol_records WHERE kind=?1 AND record_id=?2 AND bytes=?3",
        params![kind, key, bytes],
    )? != 1
        || bounded_record(cx, &kind, &key, ROW_BYTES)?.is_some()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(true)
}

impl ControlStore {
    fn build_checkpoint_chunk_index<P: Proof>(
        &self,
        id: Uuid,
        proof: &P,
        mut trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let retention = proof.retention(id)?;
        proof.recheck(&mut trust)?;
        {
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            guard(self, &tx, retention, &mut trust)?;
            require(&tx, retention)?;
            if read(&tx, retention)?.is_none() {
                put(
                    &tx,
                    JOURNAL,
                    id.as_bytes(),
                    &Index {
                        version: 1,
                        owner: id,
                        checkpoint_hash: retention.checkpoint.hash()?,
                        certificate_hash: retention.certificate_hash,
                        trust_hash: retention.trust_hash,
                        count: 0,
                        after: None,
                        complete: false,
                        work: reservation(retention)?,
                    },
                )?;
            }
            paged_checkpoint_revision::admitted_work(&tx, retention)?;
            guard(self, &tx, retention, &mut trust)?;
            tx.commit()?;
        }
        {
            // Replay the full immutable proof inventory, including complete
            // retries: deletion/substitution must never silently repopulate it.
            let mut after = None;
            let mut observed = 0_u64;
            loop {
                let mut pending = Vec::with_capacity(BATCH);
                for _ in 0..BATCH {
                    let Some((key, source, placement, coverage)) =
                        proof.next_placement(after.as_deref())?
                    else {
                        break;
                    };
                    if after.as_ref().is_some_and(|last| key <= *last) {
                        return Err(DatabaseError::Integrity.into());
                    }
                    let encoded = canonical_bytes_bounded(
                        &CatalogCheckpointChunkLocation {
                            sector_id: placement.sector_id,
                            slot_index: placement.slot_index,
                            group_id: coverage.group_id,
                            shard_index: coverage.shard_index,
                        },
                        LOCATION_BYTES,
                    )?;
                    if canonical_bytes_bounded(&source, KEY_BYTES)? != key {
                        return Err(DatabaseError::Integrity.into());
                    }
                    after = Some(key.clone());
                    pending.push((key, encoded));
                }
                if pending.is_empty() {
                    break;
                }
                let tx =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                guard(self, &tx, retention, &mut trust)?;
                require(&tx, retention)?;
                let current = read(&tx, retention)?.ok_or(DatabaseError::Integrity)?;
                observed = observed
                    .checked_add(pending.len() as u64)
                    .ok_or(DatabaseError::Integrity)?;
                if observed > retention.checkpoint.packing_geometry().1 {
                    return Err(DatabaseError::Integrity.into());
                }
                for (key, bytes) in &pending {
                    match bounded_record(&tx, &rows(id), key, LOCATION_BYTES)? {
                        Some(saved) if saved == *bytes => {}
                        None if !current.complete
                            && current.after.as_ref().is_none_or(|last| key > last) =>
                        {
                            insert_exact(&tx, &rows(id), key, bytes)?;
                        }
                        _ => return Err(DatabaseError::Integrity.into()),
                    }
                    if bounded_record(&tx, &rows(id), key, LOCATION_BYTES)?.as_deref()
                        != Some(bytes.as_slice())
                    {
                        return Err(DatabaseError::Integrity.into());
                    }
                }
                if observed > current.count {
                    let next = Index {
                        count: observed,
                        after: after.clone(),
                        ..current.clone()
                    };
                    replace(&tx, &current, &next)?;
                }
                paged_checkpoint_revision::admitted_work(&tx, retention)?;
                guard(self, &tx, retention, &mut trust)?;
                tx.commit()?;
            }
            proof.recheck(&mut trust)?;
            let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            guard(self, &tx, retention, &mut trust)?;
            require(&tx, retention)?;
            let current = read(&tx, retention)?.ok_or(DatabaseError::Integrity)?;
            let actual: u64 = tx.query_row(
                "SELECT count(*) FROM protocol_records WHERE kind=?1",
                [rows(id)],
                |r| r.get(0),
            )?;
            if actual != observed
                || observed != retention.checkpoint.packing_geometry().1
                || current.count != observed
                || current.after != after
            {
                return Err(DatabaseError::Integrity.into());
            }
            if !current.complete {
                replace(
                    &tx,
                    &current,
                    &Index {
                        complete: true,
                        ..current.clone()
                    },
                )?;
            }
            paged_checkpoint_revision::admitted_work(&tx, retention)?;
            guard(self, &tx, retention, &mut trust)?;
            tx.commit()?;
            Ok(())
        }
    }

    fn checkpoint_chunk_location<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        source: SourceChunkId,
    ) -> Result<Option<(PackingProfile, CatalogCheckpointChunkLocation)>, CatalogStoreError> {
        let tx = self.read_snapshot()?;
        require(&tx, retention)?;
        if !read(&tx, retention)?
            .ok_or(DatabaseError::NotReady)?
            .complete
        {
            return Err(DatabaseError::NotReady.into());
        }
        let profile = retention.checkpoint.packing_geometry().0;
        let key = canonical_bytes_bounded(&source, KEY_BYTES)?;
        let location = bounded_record(&tx, &rows(retention.id), &key, LOCATION_BYTES)?
            .map(|bytes| -> Result<_, CatalogStoreError> {
                let value: CatalogCheckpointChunkLocation = decode_row(&bytes)?;
                if value.sector_id == [0; 32]
                    || value.group_id == [0; 32]
                    || value.slot_index
                        >= profile
                            .slots_per_sector()
                            .map_err(|_| DatabaseError::Integrity)?
                    || source.chunk_index
                        >= profile
                            .slots_per_sector()
                            .map_err(|_| DatabaseError::Integrity)?
                    || value.shard_index > u8::MAX as u16
                {
                    return Err(DatabaseError::Integrity.into());
                }
                Ok(value)
            })
            .transpose()?;
        tx.commit()?;
        Ok(location.map(|value| (profile, value)))
    }
}

fn replace(cx: &Connection, old: &Index, next: &Index) -> Result<(), CatalogStoreError> {
    let bytes = canonical_bytes_bounded(next, ROW_BYTES)?;
    if cx.execute(
        "UPDATE protocol_records SET bytes=?3 WHERE kind=?1 AND record_id=?2 AND bytes=?4",
        params![JOURNAL, old.owner.as_bytes(), bytes, canonical_bytes(old)?],
    )? != 1
        || bounded_record(cx, JOURNAL, old.owner.as_bytes(), ROW_BYTES)?.as_deref()
            != Some(bytes.as_slice())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

macro_rules! api {
    ($header:ty, $proof:ty, $build:ident, $point:ident) => {
        impl ControlStore {
            pub fn $build(
                &self,
                owner: Uuid,
                proof: &$proof,
                trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
            ) -> Result<(), CatalogStoreError> {
                self.build_checkpoint_chunk_index(owner, proof, trust)
            }
            pub fn $point(
                &self,
                retention: CatalogPagedCheckpointRetention<$header>,
                source: SourceChunkId,
            ) -> Result<Option<(PackingProfile, CatalogCheckpointChunkLocation)>, CatalogStoreError>
            {
                self.checkpoint_chunk_location(retention, source)
            }
        }
    };
}
api!(
    mb_core::PagedGuildCheckpoint,
    CatalogQuorumPagedCheckpointIndex,
    build_catalog_paged_checkpoint_chunk_index,
    catalog_paged_checkpoint_chunk_location
);
api!(
    mb_core::PagedGuildCheckpointDirectory,
    CatalogQuorumPagedCheckpointDirectoryIndex,
    build_catalog_paged_checkpoint_directory_chunk_index,
    catalog_paged_checkpoint_directory_chunk_location
);
