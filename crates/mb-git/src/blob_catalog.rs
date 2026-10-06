//! Bounded sparse blob recipes. Sector references preserve occurrence order;
//! signed source authority and plaintext Git OID verification belong to the
//! enclosing descriptor/recovery consumer, not this structural codec.

use mb_core::{
    CATALOG_MAX_RECORDS, CatalogError, CatalogPageRef, CatalogRecordBuilder, CatalogRecordReader,
    CatalogRecordRoot, CatalogScope, CatalogSection, CatalogStreamError, SectorRef, V1_SECTOR_SIZE,
    canonical_bytes, decode_canonical,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const GIT_BLOB_SECTOR_REFS: usize = 128;
const MAX_ENCODED_RECORD: usize = GIT_BLOB_SECTOR_REFS * 80 + 32;

/// Discriminants are append-only within version one. Blob headers declare
/// extent/sector occurrences, including repeated references to shared data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GitBlobRecord {
    Blob {
        format_version: u16,
        oid: [u8; 20],
        logical_len: u64,
        extents: u64,
        sectors: u64,
    },
    Extent {
        offset: u64,
        logical_len: u64,
        sectors: u64,
    },
    Sectors {
        first_sector: u64,
        #[serde(deserialize_with = "decode_sectors")]
        references: Vec<SectorRef>,
    },
}

fn decode_sectors<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<SectorRef>, D::Error> {
    struct Sectors;
    impl<'de> Visitor<'de> for Sectors {
        type Value = Vec<SectorRef>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {GIT_BLOB_SECTOR_REFS} sector references"
            )
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence
                .size_hint()
                .is_some_and(|size| size > GIT_BLOB_SECTOR_REFS)
            {
                return Err(serde::de::Error::custom("oversized blob sector fragment"));
            }
            let mut references =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(GIT_BLOB_SECTOR_REFS));
            while let Some(reference) = sequence.next_element()? {
                if references.len() == GIT_BLOB_SECTOR_REFS {
                    return Err(serde::de::Error::custom("oversized blob sector fragment"));
                }
                references.push(reference);
            }
            Ok(references)
        }
    }
    decoder.deserialize_seq(Sectors)
}

impl GitBlobRecord {
    pub fn validate(&self) -> Result<(), CatalogError> {
        let valid = match self {
            Self::Blob {
                format_version,
                extents,
                sectors,
                ..
            } => {
                *format_version == 1
                    && *extents <= *sectors
                    && *sectors <= CATALOG_MAX_RECORDS
                    && (*extents == 0) == (*sectors == 0)
            }
            Self::Extent {
                logical_len,
                sectors,
                ..
            } => {
                *sectors > 0
                    && *sectors <= CATALOG_MAX_RECORDS
                    && *logical_len >= *sectors
                    && *logical_len <= *sectors * V1_SECTOR_SIZE as u64
            }
            Self::Sectors { references, .. } => {
                !references.is_empty()
                    && references.len() <= GIT_BLOB_SECTOR_REFS
                    && references.iter().all(|reference| {
                        reference.logical_len > 0
                            && reference.logical_len as usize <= V1_SECTOR_SIZE
                    })
            }
        };
        if valid {
            Ok(())
        } else {
            Err(CatalogError::InvalidPage)
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > MAX_ENCODED_RECORD {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        record.validate()?;
        if canonical_bytes(&record)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

/// Authenticate the complete summary inside the owner-encrypted Git root.
/// Logical bytes include holes; data bytes sum extent coverage. Repeated source
/// references count repeatedly here and do not measure physical allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitBlobCatalogRoot {
    pub format_version: u16,
    pub records: CatalogRecordRoot,
    pub blobs: u64,
    pub extents: u64,
    pub sectors: u64,
    pub logical_bytes: u64,
    pub data_bytes: u64,
}

impl GitBlobCatalogRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        if self.format_version != 1
            || self.blobs > self.records.records
            || self.extents > self.sectors
            || self.sectors > CATALOG_MAX_RECORDS
            || (self.extents == 0) != (self.sectors == 0)
            || self.data_bytes < self.sectors
            || self.data_bytes > self.sectors * V1_SECTOR_SIZE as u64
            || self.data_bytes > self.logical_bytes
            || self.blobs == 0
                && (self.records.records != 0 || self.logical_bytes != 0 || self.sectors != 0)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

struct ActiveBlob {
    logical_len: u64,
    expected_extents: u64,
    expected_sectors: u64,
    extents: u64,
    sectors: u64,
    previous_end: u64,
}

struct ActiveExtent {
    logical_len: u64,
    expected_sectors: u64,
    sectors: u64,
    covered: u64,
}

#[derive(Default)]
struct BlobState {
    blob: Option<ActiveBlob>,
    extent: Option<ActiveExtent>,
    previous: Option<[u8; 20]>,
    blobs: u64,
    extents: u64,
    sectors: u64,
    logical_bytes: u64,
    data_bytes: u64,
}

impl BlobState {
    fn finish_blob(&self) -> Result<(), CatalogError> {
        if self.extent.is_some()
            || self.blob.as_ref().is_some_and(|blob| {
                blob.extents != blob.expected_extents || blob.sectors != blob.expected_sectors
            })
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    fn accept(&mut self, record: &GitBlobRecord) -> Result<(), CatalogError> {
        record.validate()?;
        match record {
            GitBlobRecord::Blob {
                oid,
                logical_len,
                extents,
                sectors,
                ..
            } => {
                self.finish_blob()?;
                if self.previous.is_some_and(|previous| previous >= *oid) {
                    return Err(CatalogError::InvalidPage);
                }
                self.logical_bytes = self
                    .logical_bytes
                    .checked_add(*logical_len)
                    .ok_or(CatalogError::Bounds)?;
                self.blobs += 1;
                self.previous = Some(*oid);
                self.blob = Some(ActiveBlob {
                    logical_len: *logical_len,
                    expected_extents: *extents,
                    expected_sectors: *sectors,
                    extents: 0,
                    sectors: 0,
                    previous_end: 0,
                });
            }
            GitBlobRecord::Extent {
                offset,
                logical_len,
                sectors,
            } => {
                let blob = self.blob.as_mut().ok_or(CatalogError::InvalidPage)?;
                let end = offset
                    .checked_add(*logical_len)
                    .ok_or(CatalogError::Bounds)?;
                if self.extent.is_some()
                    || *offset < blob.previous_end
                    || end > blob.logical_len
                    || blob.extents == blob.expected_extents
                    || *sectors > blob.expected_sectors - blob.sectors
                {
                    return Err(CatalogError::InvalidPage);
                }
                blob.previous_end = end;
                blob.extents += 1;
                self.extents += 1;
                self.extent = Some(ActiveExtent {
                    logical_len: *logical_len,
                    expected_sectors: *sectors,
                    sectors: 0,
                    covered: 0,
                });
            }
            GitBlobRecord::Sectors {
                first_sector,
                references,
            } => {
                let extent = self.extent.as_mut().ok_or(CatalogError::InvalidPage)?;
                let expected = (extent.expected_sectors - extent.sectors)
                    .min(GIT_BLOB_SECTOR_REFS as u64) as usize;
                if *first_sector != extent.sectors || references.len() != expected {
                    return Err(CatalogError::InvalidPage);
                }
                let covered: u64 = references
                    .iter()
                    .map(|reference| u64::from(reference.logical_len))
                    .sum();
                extent.covered += covered;
                extent.sectors += references.len() as u64;
                if extent.covered > extent.logical_len {
                    return Err(CatalogError::InvalidPage);
                }
                let blob = self.blob.as_mut().ok_or(CatalogError::InvalidPage)?;
                blob.sectors += references.len() as u64;
                self.sectors += references.len() as u64;
                if self.sectors > CATALOG_MAX_RECORDS {
                    return Err(CatalogError::Bounds);
                }
                self.data_bytes = self
                    .data_bytes
                    .checked_add(covered)
                    .ok_or(CatalogError::Bounds)?;
                if extent.sectors == extent.expected_sectors {
                    if extent.covered != extent.logical_len {
                        return Err(CatalogError::InvalidPage);
                    }
                    self.extent = None;
                }
            }
        }
        Ok(())
    }

    fn matches(&self, root: GitBlobCatalogRoot) -> Result<(), CatalogError> {
        self.finish_blob()?;
        if self.blobs != root.blobs
            || self.extents != root.extents
            || self.sectors != root.sectors
            || self.logical_bytes != root.logical_bytes
            || self.data_bytes != root.data_bytes
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

pub struct GitBlobCatalogBuilder {
    records: CatalogRecordBuilder,
    state: BlobState,
    failed: bool,
}

impl GitBlobCatalogBuilder {
    pub fn new(scope: CatalogScope) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::GitGraph)?,
            state: BlobState::default(),
            failed: false,
        })
    }

    pub fn push_record<E>(
        &mut self,
        record: &GitBlobRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self
            .state
            .accept(record)
            .map_err(CatalogStreamError::from)
            .and_then(|()| self.records.push(record, sink));
        self.failed = result.is_err();
        result
    }

    /// Bridge existing decoded recipes without making another full extent or
    /// sector list. Callers provide blobs in OID order; old signed bytes and
    /// legacy descriptor admission remain unchanged.
    #[cfg(target_os = "linux")]
    pub fn push_blob<E>(
        &mut self,
        blob: &crate::GitBackupBlob,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let sectors = blob.data_extents.iter().try_fold(0_u64, |sum, extent| {
            sum.checked_add(extent.sectors.len() as u64)
        });
        let Some(sectors) = sectors else {
            self.failed = true;
            return Err(CatalogError::Bounds.into());
        };
        self.push_record(
            &GitBlobRecord::Blob {
                format_version: 1,
                oid: blob.oid,
                logical_len: blob.logical_len,
                extents: blob.data_extents.len() as u64,
                sectors,
            },
            sink,
        )?;
        for extent in &blob.data_extents {
            self.push_record(
                &GitBlobRecord::Extent {
                    offset: extent.offset,
                    logical_len: extent.logical_len,
                    sectors: extent.sectors.len() as u64,
                },
                sink,
            )?;
            for (index, references) in extent.sectors.chunks(GIT_BLOB_SECTOR_REFS).enumerate() {
                self.push_record(
                    &GitBlobRecord::Sectors {
                        first_sector: (index * GIT_BLOB_SECTOR_REFS) as u64,
                        references: references.to_vec(),
                    },
                    sink,
                )?;
            }
        }
        Ok(())
    }

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<GitBlobCatalogRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.state.finish_blob()?;
        let root = GitBlobCatalogRoot {
            format_version: 1,
            records: self.records.finish(sink)?,
            blobs: self.state.blobs,
            extents: self.state.extents,
            sectors: self.state.sectors,
            logical_bytes: self.state.logical_bytes,
            data_bytes: self.state.data_bytes,
        };
        root.validate()?;
        Ok(root)
    }
}

/// Stage records as they arrive; activation requires complete verified EOF and
/// a join against authenticated source references plus plaintext blob hashing.
pub struct GitBlobCatalogReader {
    records: CatalogRecordReader,
    root: GitBlobCatalogRoot,
    state: BlobState,
    consumed: u64,
    failed: bool,
}

impl GitBlobCatalogReader {
    pub fn new(scope: CatalogScope, root: GitBlobCatalogRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::GitGraph, root.records)?,
            root,
            state: BlobState::default(),
            consumed: 0,
            failed: false,
        })
    }

    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<GitBlobRecord>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.next_inner(fetch);
        self.failed = result.is_err();
        result
    }

    fn next_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<GitBlobRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            self.state.matches(self.root)?;
            return Ok(None);
        };
        let record = GitBlobRecord::decode(&bytes)?;
        self.state.accept(&record)?;
        self.consumed += 1;
        if self.state.blobs > self.root.blobs
            || self.state.extents > self.root.extents
            || self.state.sectors > self.root.sectors
            || self.state.logical_bytes > self.root.logical_bytes
            || self.state.data_bytes > self.root.data_bytes
        {
            return Err(CatalogError::InvalidPage.into());
        }
        if self.consumed == self.root.records.records {
            self.state.matches(self.root)?;
        }
        Ok(Some(record))
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{GitBackupBlob, GitDataExtent};
    use mb_core::NodeId;
    use uuid::Uuid;

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn sector(logical_len: u32) -> SectorRef {
        SectorRef {
            id: [4; 32],
            root: [5; 32],
            logical_len,
        }
    }

    fn valid_records() -> Vec<GitBlobRecord> {
        vec![
            GitBlobRecord::Blob {
                format_version: 1,
                oid: [1; 20],
                logical_len: 128,
                extents: 1,
                sectors: 1,
            },
            GitBlobRecord::Extent {
                offset: 32,
                logical_len: 64,
                sectors: 1,
            },
            GitBlobRecord::Sectors {
                first_sector: 0,
                references: vec![sector(64)],
            },
        ]
    }

    fn raw(records: &[GitBlobRecord]) -> (GitBlobCatalogRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        (
            GitBlobCatalogRoot {
                format_version: 1,
                records: builder.finish(&mut sink).unwrap(),
                blobs: 1,
                extents: 1,
                sectors: 1,
                logical_bytes: 128,
                data_bytes: 64,
            },
            pages,
        )
    }

    fn reject_read(root: GitBlobCatalogRoot, pages: &Pages) {
        let mut reader = GitBlobCatalogReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        loop {
            match reader.next_record(&mut fetch) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("accepted invalid complete recipe"),
                Err(_) => break,
            }
        }
        assert!(reader.next_record(&mut fetch).is_err());
    }

    #[test]
    fn git_blob_catalog_bridges_exact_legacy_sparse_recipes_across_pages() {
        // A synthetic 1 TiB logical blob with a large hole; not an end-to-end
        // 1 TiB backup/recovery qualification. Repeated references stay ordered.
        let logical_len = 1_u64 << 40;
        let original = GitBackupBlob {
            oid: [1; 20],
            logical_len,
            data_extents: vec![
                GitDataExtent {
                    offset: 128,
                    logical_len: 1025 * V1_SECTOR_SIZE as u64,
                    sectors: vec![sector(V1_SECTOR_SIZE as u32); 1025],
                },
                GitDataExtent {
                    offset: logical_len - 37,
                    logical_len: 37,
                    sectors: vec![sector(37)],
                },
            ],
        };
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
        builder.push_blob(&original, &mut sink).unwrap();
        let root = builder.finish(&mut sink).unwrap();
        assert!(root.records.page.height > 0);
        assert_eq!(root.blobs, 1);
        assert_eq!(root.extents, 2);
        assert_eq!(root.sectors, 1026);
        assert_eq!(root.logical_bytes, logical_len);
        assert_eq!(root.data_bytes, 1025 * V1_SECTOR_SIZE as u64 + 37);
        let mut reader = GitBlobCatalogReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert_eq!(
            reader.next_record(&mut fetch).unwrap().unwrap(),
            GitBlobRecord::Blob {
                format_version: 1,
                oid: original.oid,
                logical_len,
                extents: 2,
                sectors: 1026
            }
        );
        // Reassembly is intentionally confined to the compatibility fixture.
        let mut restored = GitBackupBlob {
            oid: original.oid,
            logical_len,
            data_extents: Vec::new(),
        };
        while let Some(record) = reader.next_record(&mut fetch).unwrap() {
            match record {
                GitBlobRecord::Extent {
                    offset,
                    logical_len,
                    ..
                } => restored.data_extents.push(GitDataExtent {
                    offset,
                    logical_len,
                    sectors: Vec::new(),
                }),
                GitBlobRecord::Sectors {
                    first_sector,
                    references,
                } => {
                    assert!(references.len() <= GIT_BLOB_SECTOR_REFS);
                    let extent = restored.data_extents.last_mut().unwrap();
                    assert_eq!(first_sector, extent.sectors.len() as u64);
                    extent.sectors.extend(references);
                }
                GitBlobRecord::Blob { .. } => panic!("unexpected blob"),
            }
        }
        assert_eq!(restored, original);
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn git_blob_catalog_handles_empty_and_all_hole_blobs_without_data_records() {
        for blobs in [
            Vec::new(),
            vec![
                GitBackupBlob {
                    oid: [1; 20],
                    logical_len: 0,
                    data_extents: Vec::new(),
                },
                GitBackupBlob {
                    oid: [2; 20],
                    logical_len: 1 << 40,
                    data_extents: Vec::new(),
                },
            ],
        ] {
            let mut pages = Pages::new();
            let mut sink = |reference: CatalogPageRef, bytes| {
                pages.insert(reference.hash, bytes);
                Ok::<_, &'static str>(())
            };
            let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
            for blob in &blobs {
                builder.push_blob(blob, &mut sink).unwrap();
            }
            let root = builder.finish(&mut sink).unwrap();
            assert_eq!(root.blobs, blobs.len() as u64);
            assert_eq!(root.data_bytes, 0);
            assert_eq!(root.sectors, 0);
            let mut reader = GitBlobCatalogReader::new(scope(), root).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            for blob in blobs {
                assert_eq!(
                    reader.next_record(&mut fetch).unwrap().unwrap(),
                    GitBlobRecord::Blob {
                        format_version: 1,
                        oid: blob.oid,
                        logical_len: blob.logical_len,
                        extents: 0,
                        sectors: 0
                    }
                );
            }
            assert!(reader.next_record(&mut fetch).unwrap().is_none());
        }
    }

    #[test]
    fn git_blob_catalog_rejects_geometry_order_counts_and_incomplete_recipes() {
        let original = valid_records();
        let mut cases = Vec::new();
        cases.push(original[..2].to_vec());
        cases.push(original[1..].to_vec());
        let mut changed = original.clone();
        changed[1] = GitBlobRecord::Extent {
            offset: 96,
            logical_len: 64,
            sectors: 1,
        };
        cases.push(changed);
        let mut changed = original.clone();
        changed[1] = GitBlobRecord::Extent {
            offset: u64::MAX,
            logical_len: 64,
            sectors: 1,
        };
        cases.push(changed);
        let mut changed = original.clone();
        changed[2] = GitBlobRecord::Sectors {
            first_sector: 1,
            references: vec![sector(64)],
        };
        cases.push(changed);
        let mut changed = original.clone();
        changed[2] = GitBlobRecord::Sectors {
            first_sector: 0,
            references: vec![sector(63)],
        };
        cases.push(changed);
        let mut changed = original.clone();
        changed[2] = GitBlobRecord::Sectors {
            first_sector: 0,
            references: vec![sector(65)],
        };
        cases.push(changed);
        let mut changed = original.clone();
        changed.extend(original.clone());
        cases.push(changed);
        let mut changed = original.clone();
        changed.insert(2, original[1].clone());
        cases.push(changed);
        let mut changed = original.clone();
        changed.push(GitBlobRecord::Extent {
            offset: 0,
            logical_len: 64,
            sectors: 1,
        });
        cases.push(changed);
        for records in cases {
            let (root, pages) = raw(&records);
            reject_read(root, &pages);
            let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
            let mut sink = |_, _| Ok::<_, &'static str>(());
            for record in &records {
                if builder.push_record(record, &mut sink).is_err() {
                    break;
                }
            }
            assert!(builder.finish(&mut sink).is_err());
        }
        // Exercise overlap with otherwise correct declarations, not just an
        // undeclared extra extent or root count mismatch.
        let mut state = BlobState::default();
        state
            .accept(&GitBlobRecord::Blob {
                format_version: 1,
                oid: [1; 20],
                logical_len: 128,
                extents: 2,
                sectors: 2,
            })
            .unwrap();
        state.accept(&original[1]).unwrap();
        state.accept(&original[2]).unwrap();
        assert!(
            state
                .accept(&GitBlobRecord::Extent {
                    offset: 95,
                    logical_len: 1,
                    sectors: 1
                })
                .is_err()
        );
        let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Ok::<_, &'static str>(());
        builder
            .push_record(
                &GitBlobRecord::Blob {
                    format_version: 1,
                    oid: [2; 20],
                    logical_len: 0,
                    extents: 0,
                    sectors: 0,
                },
                &mut sink,
            )
            .unwrap();
        assert!(
            builder
                .push_record(
                    &GitBlobRecord::Blob {
                        format_version: 1,
                        oid: [1; 20],
                        logical_len: 0,
                        extents: 0,
                        sectors: 0
                    },
                    &mut sink
                )
                .is_err()
        );
        assert!(builder.finish(&mut sink).is_err());
    }

    #[test]
    fn git_blob_catalog_checks_canonical_fragment_count_and_summary_before_final_yield() {
        let mut state = BlobState::default();
        state
            .accept(&GitBlobRecord::Blob {
                format_version: 1,
                oid: [1; 20],
                logical_len: 129,
                extents: 1,
                sectors: 129,
            })
            .unwrap();
        state
            .accept(&GitBlobRecord::Extent {
                offset: 0,
                logical_len: 129,
                sectors: 129,
            })
            .unwrap();
        assert!(
            state
                .accept(&GitBlobRecord::Sectors {
                    first_sector: 0,
                    references: vec![sector(1); 127]
                })
                .is_err()
        );
        let (root, pages) = raw(&valid_records());
        for altered in [
            GitBlobCatalogRoot {
                logical_bytes: 129,
                ..root
            },
            GitBlobCatalogRoot {
                data_bytes: 65,
                ..root
            },
            GitBlobCatalogRoot { sectors: 2, ..root },
            GitBlobCatalogRoot {
                extents: 0,
                sectors: 0,
                data_bytes: 0,
                ..root
            },
            GitBlobCatalogRoot { blobs: 2, ..root },
        ] {
            reject_read(altered, &pages);
        }
        let mut reader = GitBlobCatalogReader::new(
            scope(),
            GitBlobCatalogRoot {
                data_bytes: 65,
                ..root
            },
        )
        .unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert!(reader.next_record(&mut fetch).unwrap().is_some());
        assert!(reader.next_record(&mut fetch).unwrap().is_some());
        assert!(reader.next_record(&mut fetch).is_err());
    }

    #[test]
    fn git_blob_catalog_decoder_bounds_nested_declarations_and_schema_geometry() {
        struct Declared;
        impl<'de> SeqAccess<'de> for Declared {
            type Error = serde::de::value::Error;
            fn size_hint(&self) -> Option<usize> {
                Some(usize::MAX)
            }
            fn next_element_seed<T: serde::de::DeserializeSeed<'de>>(
                &mut self,
                _: T,
            ) -> Result<Option<T::Value>, Self::Error> {
                panic!("must reject before element allocation/read")
            }
        }
        assert!(
            decode_sectors(serde::de::value::SeqAccessDeserializer::new(Declared))
                .unwrap_err()
                .to_string()
                .contains("oversized blob sector fragment")
        );
        let encoded = canonical_bytes(&valid_records()[2]).unwrap();
        let mut noncanonical = vec![0x82, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(GitBlobRecord::decode(&noncanonical).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(GitBlobRecord::decode(&trailing).is_err());
        assert!(GitBlobRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(GitBlobRecord::decode(&[0; MAX_ENCODED_RECORD + 1]).is_err());
        let mut huge = vec![2, 0];
        huge.extend([0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert!(GitBlobRecord::decode(&huge).is_err());
        for record in [
            GitBlobRecord::Blob {
                format_version: 2,
                oid: [1; 20],
                logical_len: 0,
                extents: 0,
                sectors: 0,
            },
            GitBlobRecord::Blob {
                format_version: 1,
                oid: [1; 20],
                logical_len: 0,
                extents: 0,
                sectors: 1,
            },
            GitBlobRecord::Extent {
                offset: 0,
                logical_len: 0,
                sectors: 1,
            },
            GitBlobRecord::Sectors {
                first_sector: 0,
                references: vec![sector(0)],
            },
            GitBlobRecord::Sectors {
                first_sector: 0,
                references: vec![sector(V1_SECTOR_SIZE as u32 + 1)],
            },
            GitBlobRecord::Sectors {
                first_sector: 0,
                references: vec![sector(1); GIT_BLOB_SECTOR_REFS + 1],
            },
        ] {
            assert!(record.validate().is_err());
            assert!(GitBlobRecord::decode(&canonical_bytes(&record).unwrap()).is_err());
        }
    }

    #[test]
    fn git_blob_catalog_failures_and_counter_overflow_fence_publication() {
        let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Err::<(), _>("offline");
        builder
            .push_record(
                &GitBlobRecord::Blob {
                    format_version: 1,
                    oid: [1; 20],
                    logical_len: 1024 * V1_SECTOR_SIZE as u64,
                    extents: 1,
                    sectors: 1024,
                },
                &mut sink,
            )
            .unwrap();
        builder
            .push_record(
                &GitBlobRecord::Extent {
                    offset: 0,
                    logical_len: 1024 * V1_SECTOR_SIZE as u64,
                    sectors: 1024,
                },
                &mut sink,
            )
            .unwrap();
        let mut failed = false;
        for index in 0..8 {
            if builder
                .push_record(
                    &GitBlobRecord::Sectors {
                        first_sector: index * GIT_BLOB_SECTOR_REFS as u64,
                        references: vec![sector(V1_SECTOR_SIZE as u32); GIT_BLOB_SECTOR_REFS],
                    },
                    &mut sink,
                )
                .is_err()
            {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(builder.push_record(&valid_records()[0], &mut sink).is_err());
        assert!(builder.finish(&mut sink).is_err());
        let (root, pages) = raw(&valid_records());
        let mut reader = GitBlobCatalogReader::new(scope(), root).unwrap();
        assert!(
            reader
                .next_record(&mut |_| Err::<Vec<u8>, _>("offline"))
                .is_err()
        );
        assert!(
            reader
                .next_record(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                    pages[&reference.hash].clone()
                ))
                .is_err()
        );
        let mut builder = GitBlobCatalogBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Ok::<_, &'static str>(());
        builder
            .push_record(
                &GitBlobRecord::Blob {
                    format_version: 1,
                    oid: [1; 20],
                    logical_len: u64::MAX,
                    extents: 0,
                    sectors: 0,
                },
                &mut sink,
            )
            .unwrap();
        assert!(
            builder
                .push_record(
                    &GitBlobRecord::Blob {
                        format_version: 1,
                        oid: [2; 20],
                        logical_len: 1,
                        extents: 0,
                        sectors: 0
                    },
                    &mut sink
                )
                .is_err()
        );
        assert!(builder.finish(&mut sink).is_err());
    }
}
