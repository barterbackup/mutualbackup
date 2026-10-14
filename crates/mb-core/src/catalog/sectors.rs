//! Fixed-size source references and commitments, streamed in sector-ID order.
//! These primitives do not replace signed revision authority or capacity policy.

use serde::{Deserialize, Serialize};

use super::{
    CatalogError, CatalogRecordBuilder, CatalogRecordReader, CatalogRecordRoot, CatalogScope,
    CatalogSection, CatalogStreamError,
};
use crate::{MerkleCommitment, SectorId, SectorRef, V1_SECTOR_SIZE, decode_canonical};

/// Generously bounds the fixed-size schema, including worst-case varints.
pub const CATALOG_SECTOR_RECORD_BYTES: usize = 128;

/// A unique encrypted source sector and its range-proof commitment. Both roots
/// must be authenticated by the enclosing revision; the flat ciphertext hash
/// and Merkle root are distinct commitments, not interchangeable values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogSectorRecord {
    pub format_version: u16,
    pub sector: SectorRef,
    pub commitment: MerkleCommitment,
}

impl CatalogSectorRecord {
    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.format_version != 1
            || self.sector.logical_len == 0
            || self.sector.logical_len as usize > V1_SECTOR_SIZE
            || self.commitment.byte_len as usize != V1_SECTOR_SIZE
            || self.commitment.validate().is_err()
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    /// Decode only fixed-size fields, then reject noncanonical encodings and
    /// invalid source geometry. No peer-controlled collection is allocated.
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_SECTOR_RECORD_BYTES {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        record.validate()?;
        let mut buffer = [0; CATALOG_SECTOR_RECORD_BYTES];
        let encoded =
            postcard::to_slice(&record, &mut buffer).map_err(crate::ModelError::Encode)?;
        if encoded != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

/// Authenticate this summary and the record root together. Logical bytes count
/// each unique source once; they do not measure retained dataset size, sparse
/// file length, physical quota or the release's admission capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogSectorRoot {
    pub records: CatalogRecordRoot,
    pub logical_bytes: u64,
}

impl CatalogSectorRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        if self.logical_bytes < self.records.records
            || self.logical_bytes > self.records.records * V1_SECTOR_SIZE as u64
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

/// Callers supply records in strictly increasing sector-ID order. This makes
/// duplicate/conflicting sources rejectable with constant memory rather than
/// retaining a dataset-sized map in each signer or recovery consumer.
pub struct CatalogSectorBuilder {
    records: CatalogRecordBuilder,
    previous: Option<SectorId>,
    logical_bytes: u64,
    failed: bool,
}

impl CatalogSectorBuilder {
    pub fn new(scope: CatalogScope) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::SectorReferences)?,
            previous: None,
            logical_bytes: 0,
            failed: false,
        })
    }

    pub fn push<E>(
        &mut self,
        record: &CatalogSectorRecord,
        sink: &mut impl FnMut(super::CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.push_inner(record, sink);
        self.failed = result.is_err();
        result
    }

    fn push_inner<E>(
        &mut self,
        record: &CatalogSectorRecord,
        sink: &mut impl FnMut(super::CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        record.validate()?;
        if self
            .previous
            .is_some_and(|previous| previous >= record.sector.id)
        {
            return Err(CatalogError::InvalidPage.into());
        }
        self.records.push(record, sink)?;
        self.previous = Some(record.sector.id);
        self.logical_bytes += u64::from(record.sector.logical_len);
        Ok(())
    }

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(super::CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogSectorRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let root = CatalogSectorRoot {
            records: self.records.finish(sink)?,
            logical_bytes: self.logical_bytes,
        };
        root.validate()?;
        Ok(root)
    }
}

/// Incrementally validates every typed source and the canonical ordering. A
/// valid prefix is not a complete catalog: callers must reach authenticated EOF
/// before activating its revision, protection claim or accounting summary.
pub struct CatalogSectorReader {
    records: CatalogRecordReader,
    root: CatalogSectorRoot,
    previous: Option<SectorId>,
    logical_bytes: u64,
    consumed: u64,
    failed: bool,
}

impl CatalogSectorReader {
    /// Original framed range under the authenticated source root. This is a
    /// locator for point replay, not independent source authority.
    pub fn last_record_range(&self) -> Option<std::ops::Range<u64>> {
        if self.failed {
            None
        } else {
            self.records.last_record_range()
        }
    }
    pub fn new(scope: CatalogScope, root: CatalogSectorRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(
                scope,
                CatalogSection::SectorReferences,
                root.records,
            )?,
            root,
            previous: None,
            logical_bytes: 0,
            consumed: 0,
            failed: false,
        })
    }

    pub fn next_sector<E>(
        &mut self,
        fetch: &mut impl FnMut(super::CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogSectorRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.next_inner(fetch);
        self.failed = result.is_err();
        result
    }

    fn next_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(super::CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogSectorRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            if self.logical_bytes != self.root.logical_bytes {
                return Err(CatalogError::InvalidPage.into());
            }
            return Ok(None);
        };
        let record = CatalogSectorRecord::decode(&bytes)?;
        if self
            .previous
            .is_some_and(|previous| previous >= record.sector.id)
        {
            return Err(CatalogError::InvalidPage.into());
        }
        self.logical_bytes += u64::from(record.sector.logical_len);
        self.consumed += 1;
        if self.logical_bytes > self.root.logical_bytes
            || self.consumed == self.root.records.records
                && self.logical_bytes != self.root.logical_bytes
        {
            return Err(CatalogError::InvalidPage.into());
        }
        self.previous = Some(record.sector.id);
        Ok(Some(record))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{NodeId, canonical_bytes, merkle_zero_commitment};
    use uuid::Uuid;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn record(index: u64) -> CatalogSectorRecord {
        let mut id = [0; 32];
        id[..8].copy_from_slice(&index.to_be_bytes());
        CatalogSectorRecord {
            format_version: 1,
            sector: SectorRef {
                id,
                root: [4; 32],
                logical_len: V1_SECTOR_SIZE as u32,
            },
            commitment: merkle_zero_commitment(V1_SECTOR_SIZE as u32).unwrap(),
        }
    }

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn raw_records(records: &[Vec<u8>], logical_bytes: u64) -> (CatalogSectorRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: super::super::CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder =
            CatalogRecordBuilder::new(scope(), CatalogSection::SectorReferences).unwrap();
        for bytes in records {
            builder.push_encoded(bytes, &mut sink).unwrap();
        }
        (
            CatalogSectorRoot {
                records: builder.finish(&mut sink).unwrap(),
                logical_bytes,
            },
            pages,
        )
    }

    #[test]
    fn catalog_sector_stream_roundtrips_many_pages_without_a_global_source_map() {
        let mut pages = Pages::new();
        let mut sink = |reference: super::super::CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
        for index in 0..2000 {
            builder.push(&record(index), &mut sink).unwrap();
        }
        let root = builder.finish(&mut sink).unwrap();
        assert!(root.records.page.height > 0);
        assert_eq!(root.records.records, 2000);
        assert_eq!(root.logical_bytes, 2000 * V1_SECTOR_SIZE as u64);
        let mut reader = CatalogSectorReader::new(scope(), root).unwrap();
        let mut fetch = |reference: super::super::CatalogPageRef| {
            Ok::<_, &'static str>(pages[&reference.hash].clone())
        };
        for index in 0..2000 {
            assert_eq!(
                reader.next_sector(&mut fetch).unwrap().unwrap(),
                record(index)
            );
        }
        assert!(reader.next_sector(&mut fetch).unwrap().is_none());
        assert!(reader.next_sector(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn catalog_sector_decoder_rejects_schema_geometry_and_noncanonical_bytes() {
        let original = record(1);
        assert_eq!(
            CatalogSectorRecord::decode(&canonical_bytes(&original).unwrap()).unwrap(),
            original
        );
        let mut invalid = Vec::new();
        let mut changed = original.clone();
        changed.format_version = 2;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.sector.logical_len = 0;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.sector.logical_len += 1;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.commitment.byte_len /= 2;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.commitment.format_version = 2;
        invalid.push(changed);
        let mut changed = original.clone();
        changed.commitment.leaf_size = 32;
        invalid.push(changed);
        for value in invalid {
            assert!(value.validate().is_err());
            assert!(CatalogSectorRecord::decode(&canonical_bytes(&value).unwrap()).is_err());
        }
        let encoded = canonical_bytes(&original).unwrap();
        assert!(encoded.len() < CATALOG_SECTOR_RECORD_BYTES);
        assert!(CatalogSectorRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(CatalogSectorRecord::decode(&trailing).is_err());
        let mut noncanonical = vec![0x81, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(CatalogSectorRecord::decode(&noncanonical).is_err());
        assert!(CatalogSectorRecord::decode(&[0; CATALOG_SECTOR_RECORD_BYTES + 1]).is_err());
        assert!(CatalogSectorRecord::decode(&[]).is_err());
    }

    #[test]
    fn catalog_sector_duplicate_conflict_and_reordering_fence_build_and_read() {
        for second in [record(2), record(1), {
            let mut value = record(2);
            value.sector.root = [9; 32];
            value
        }] {
            let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
            let mut sink = |_, _| Ok::<_, &'static str>(());
            builder.push(&record(2), &mut sink).unwrap();
            assert!(builder.push(&second, &mut sink).is_err());
            assert!(builder.push(&record(3), &mut sink).is_err());
            assert!(builder.finish(&mut sink).is_err());
            let (root, pages) = raw_records(
                &[
                    canonical_bytes(&record(2)).unwrap(),
                    canonical_bytes(&second).unwrap(),
                ],
                2 * V1_SECTOR_SIZE as u64,
            );
            let mut reader = CatalogSectorReader::new(scope(), root).unwrap();
            let mut fetch = |reference: super::super::CatalogPageRef| {
                Ok::<_, &'static str>(pages[&reference.hash].clone())
            };
            assert!(reader.next_sector(&mut fetch).unwrap().is_some());
            assert!(reader.next_sector(&mut fetch).is_err());
            assert!(reader.next_sector(&mut fetch).is_err());
        }
    }

    #[test]
    fn catalog_sector_summary_is_checked_before_returning_the_final_source() {
        let mut value = record(1);
        value.sector.logical_len = 16;
        let bytes = canonical_bytes(&value).unwrap();
        for logical_bytes in [15, 17] {
            let (root, pages) = raw_records(std::slice::from_ref(&bytes), logical_bytes);
            let mut reader = CatalogSectorReader::new(scope(), root).unwrap();
            let mut fetch = |reference: super::super::CatalogPageRef| {
                Ok::<_, &'static str>(pages[&reference.hash].clone())
            };
            assert!(reader.next_sector(&mut fetch).is_err());
            assert!(reader.next_sector(&mut fetch).is_err());
        }
        let (root, pages) = raw_records(&[], 0);
        let mut reader = CatalogSectorReader::new(scope(), root).unwrap();
        assert!(
            reader
                .next_sector(
                    &mut |reference: super::super::CatalogPageRef| Ok::<_, &'static str>(
                        pages[&reference.hash].clone()
                    )
                )
                .unwrap()
                .is_none()
        );
        assert!(
            CatalogSectorRoot {
                logical_bytes: 1,
                ..root
            }
            .validate()
            .is_err()
        );
        let (root, _) = raw_records(&[bytes], 16);
        for logical_bytes in [0, V1_SECTOR_SIZE as u64 + 1] {
            assert!(
                CatalogSectorRoot {
                    logical_bytes,
                    ..root
                }
                .validate()
                .is_err()
            );
        }
        assert!(CatalogSectorReader::new(CatalogScope::Guild { guild_id: [1; 32] }, root).is_err());
    }

    #[test]
    fn catalog_sector_failure_and_authenticated_invalid_schema_are_terminal() {
        let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Err::<(), _>("offline");
        let mut failed = false;
        for index in 0..2000 {
            if builder.push(&record(index), &mut sink).is_err() {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(builder.finish(&mut sink).is_err());
        let (root, pages) = raw_records(&[vec![0; CATALOG_SECTOR_RECORD_BYTES + 1]], 1);
        let mut reader = CatalogSectorReader::new(scope(), root).unwrap();
        let mut fetch = |reference: super::super::CatalogPageRef| {
            Ok::<_, &'static str>(pages[&reference.hash].clone())
        };
        assert!(reader.next_sector(&mut fetch).is_err());
        assert!(reader.next_sector(&mut fetch).is_err());
        let (root, _) = raw_records(
            &[canonical_bytes(&record(1)).unwrap()],
            V1_SECTOR_SIZE as u64,
        );
        let mut reader = CatalogSectorReader::new(scope(), root).unwrap();
        assert!(
            reader
                .next_sector(&mut |_| Err::<Vec<u8>, _>("offline"))
                .is_err()
        );
        assert!(reader.next_sector(&mut fetch).is_err());
    }
}
