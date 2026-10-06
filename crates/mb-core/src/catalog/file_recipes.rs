//! Bounded sparse native file recipes. Sector references preserve occurrence order;
//! signed source authority and file namespace/hard-link joins belong to the
//! enclosing descriptor/recovery consumer, not this structural codec.

use super::{
    CATALOG_MAX_RECORDS, CatalogError, CatalogPageRef, CatalogRecordBuilder, CatalogRecordReader,
    CatalogRecordRoot, CatalogScope, CatalogSection, CatalogStreamError,
};
use crate::{SectorRef, V1_SECTOR_SIZE, canonical_bytes, decode_canonical};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const CATALOG_FILE_SECTOR_REFS: usize = 128;
const MAX_ENCODED_RECORD: usize = CATALOG_FILE_SECTOR_REFS * 80 + 32;

/// Borrowed bridge for already decoded legacy extents. New capture should feed
/// individual bounded records directly rather than assemble a full sector list.
#[derive(Clone, Copy)]
pub struct CatalogFileExtent<'a> {
    pub offset: u64,
    pub logical_len: u64,
    pub sectors: &'a [SectorRef],
}

/// Discriminants are append-only within version one. File headers declare
/// extent/sector occurrences, including repeated references to shared data.
/// File keys bind each recipe to the corresponding namespace record ordinal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogFileRecipeRecord {
    File {
        format_version: u16,
        file_key: u64,
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
                "at most {CATALOG_FILE_SECTOR_REFS} sector references"
            )
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence
                .size_hint()
                .is_some_and(|size| size > CATALOG_FILE_SECTOR_REFS)
            {
                return Err(serde::de::Error::custom("oversized file sector fragment"));
            }
            let mut references = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(CATALOG_FILE_SECTOR_REFS),
            );
            while let Some(reference) = sequence.next_element()? {
                if references.len() == CATALOG_FILE_SECTOR_REFS {
                    return Err(serde::de::Error::custom("oversized file sector fragment"));
                }
                references.push(reference);
            }
            Ok(references)
        }
    }
    decoder.deserialize_seq(Sectors)
}

impl CatalogFileRecipeRecord {
    pub fn validate(&self) -> Result<(), CatalogError> {
        let valid = match self {
            Self::File {
                format_version,
                file_key,
                extents,
                sectors,
                ..
            } => {
                *format_version == 1
                    && *file_key < CATALOG_MAX_RECORDS
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
                    && references.len() <= CATALOG_FILE_SECTOR_REFS
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

/// Authenticate the complete summary inside the owner-encrypted native file root.
/// Logical bytes include holes; data bytes sum extent coverage. Repeated source
/// references count repeatedly here and do not measure physical allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogFileRecipeRoot {
    pub format_version: u16,
    pub records: CatalogRecordRoot,
    pub files: u64,
    pub extents: u64,
    pub sectors: u64,
    pub logical_bytes: u64,
    pub data_bytes: u64,
}

impl CatalogFileRecipeRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        if self.format_version != 1
            || self.files > self.records.records
            || self.extents > self.sectors
            || self.sectors > CATALOG_MAX_RECORDS
            || (self.extents == 0) != (self.sectors == 0)
            || self.data_bytes < self.sectors
            || self.data_bytes > self.sectors * V1_SECTOR_SIZE as u64
            || self.data_bytes > self.logical_bytes
            || self.files == 0
                && (self.records.records != 0 || self.logical_bytes != 0 || self.sectors != 0)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

struct ActiveFile {
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
struct RecipeState {
    file: Option<ActiveFile>,
    extent: Option<ActiveExtent>,
    previous: Option<u64>,
    files: u64,
    extents: u64,
    sectors: u64,
    logical_bytes: u64,
    data_bytes: u64,
}

impl RecipeState {
    fn finish_file(&self) -> Result<(), CatalogError> {
        if self.extent.is_some()
            || self.file.as_ref().is_some_and(|file| {
                file.extents != file.expected_extents || file.sectors != file.expected_sectors
            })
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    fn accept(&mut self, record: &CatalogFileRecipeRecord) -> Result<(), CatalogError> {
        record.validate()?;
        match record {
            CatalogFileRecipeRecord::File {
                file_key,
                logical_len,
                extents,
                sectors,
                ..
            } => {
                self.finish_file()?;
                if self.previous.is_some_and(|previous| previous >= *file_key) {
                    return Err(CatalogError::InvalidPage);
                }
                self.logical_bytes = self
                    .logical_bytes
                    .checked_add(*logical_len)
                    .ok_or(CatalogError::Bounds)?;
                self.files += 1;
                self.previous = Some(*file_key);
                self.file = Some(ActiveFile {
                    logical_len: *logical_len,
                    expected_extents: *extents,
                    expected_sectors: *sectors,
                    extents: 0,
                    sectors: 0,
                    previous_end: 0,
                });
            }
            CatalogFileRecipeRecord::Extent {
                offset,
                logical_len,
                sectors,
            } => {
                let file = self.file.as_mut().ok_or(CatalogError::InvalidPage)?;
                let end = offset
                    .checked_add(*logical_len)
                    .ok_or(CatalogError::Bounds)?;
                if self.extent.is_some()
                    || *offset < file.previous_end
                    || end > file.logical_len
                    || file.extents == file.expected_extents
                    || *sectors > file.expected_sectors - file.sectors
                {
                    return Err(CatalogError::InvalidPage);
                }
                file.previous_end = end;
                file.extents += 1;
                self.extents += 1;
                self.extent = Some(ActiveExtent {
                    logical_len: *logical_len,
                    expected_sectors: *sectors,
                    sectors: 0,
                    covered: 0,
                });
            }
            CatalogFileRecipeRecord::Sectors {
                first_sector,
                references,
            } => {
                let extent = self.extent.as_mut().ok_or(CatalogError::InvalidPage)?;
                let expected = (extent.expected_sectors - extent.sectors)
                    .min(CATALOG_FILE_SECTOR_REFS as u64) as usize;
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
                let file = self.file.as_mut().ok_or(CatalogError::InvalidPage)?;
                file.sectors += references.len() as u64;
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

    fn matches(&self, root: CatalogFileRecipeRoot) -> Result<(), CatalogError> {
        self.finish_file()?;
        if self.files != root.files
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

pub struct CatalogFileRecipeBuilder {
    records: CatalogRecordBuilder,
    state: RecipeState,
    failed: bool,
}

impl CatalogFileRecipeBuilder {
    pub fn new(scope: CatalogScope) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::FileMetadata)?,
            state: RecipeState::default(),
            failed: false,
        })
    }

    pub fn push_record<E>(
        &mut self,
        record: &CatalogFileRecipeRecord,
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

    /// Iterate borrowed legacy extents twice to declare counts and emit records.
    /// Only one bounded sector fragment is copied; original signed bytes remain
    /// unchanged. Input order must match the namespace's file record ordinals.
    pub fn push_file<'a, E>(
        &mut self,
        file_key: u64,
        logical_len: u64,
        extents: impl Iterator<Item = CatalogFileExtent<'a>> + Clone,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let counts = extents
            .clone()
            .try_fold((0_u64, 0_u64), |(count, sectors), extent| {
                Some((
                    count.checked_add(1)?,
                    sectors.checked_add(extent.sectors.len() as u64)?,
                ))
            });
        let Some((count, sectors)) = counts else {
            self.failed = true;
            return Err(CatalogError::Bounds.into());
        };
        self.push_record(
            &CatalogFileRecipeRecord::File {
                format_version: 1,
                file_key,
                logical_len,
                extents: count,
                sectors,
            },
            sink,
        )?;
        for extent in extents {
            self.push_record(
                &CatalogFileRecipeRecord::Extent {
                    offset: extent.offset,
                    logical_len: extent.logical_len,
                    sectors: extent.sectors.len() as u64,
                },
                sink,
            )?;
            for (index, references) in extent.sectors.chunks(CATALOG_FILE_SECTOR_REFS).enumerate() {
                self.push_record(
                    &CatalogFileRecipeRecord::Sectors {
                        first_sector: (index * CATALOG_FILE_SECTOR_REFS) as u64,
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
    ) -> Result<CatalogFileRecipeRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.state.finish_file()?;
        let root = CatalogFileRecipeRoot {
            format_version: 1,
            records: self.records.finish(sink)?,
            files: self.state.files,
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
/// a join against authenticated source references plus namespace and hard-link validation.
pub struct CatalogFileRecipeReader {
    records: CatalogRecordReader,
    root: CatalogFileRecipeRoot,
    state: RecipeState,
    consumed: u64,
    failed: bool,
}

impl CatalogFileRecipeReader {
    pub fn new(scope: CatalogScope, root: CatalogFileRecipeRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::FileMetadata, root.records)?,
            root,
            state: RecipeState::default(),
            consumed: 0,
            failed: false,
        })
    }

    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogFileRecipeRecord>, CatalogStreamError<E>> {
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
    ) -> Result<Option<CatalogFileRecipeRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            self.state.matches(self.root)?;
            return Ok(None);
        };
        let record = CatalogFileRecipeRecord::decode(&bytes)?;
        self.state.accept(&record)?;
        self.consumed += 1;
        if self.state.files > self.root.files
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{NodeId, canonical_bytes};
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
        let mut id = [4; 32];
        id[..4].copy_from_slice(&logical_len.to_be_bytes());
        SectorRef {
            id,
            root: [5; 32],
            logical_len,
        }
    }

    fn header(key: u64, len: u64, extents: u64, sectors: u64) -> CatalogFileRecipeRecord {
        CatalogFileRecipeRecord::File {
            format_version: 1,
            file_key: key,
            logical_len: len,
            extents,
            sectors,
        }
    }

    fn valid() -> Vec<CatalogFileRecipeRecord> {
        vec![
            header(2, 1000, 2, 3),
            CatalogFileRecipeRecord::Extent {
                offset: 5,
                logical_len: 7,
                sectors: 2,
            },
            CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references: vec![sector(3), sector(4)],
            },
            CatalogFileRecipeRecord::Extent {
                offset: 999,
                logical_len: 1,
                sectors: 1,
            },
            CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references: vec![sector(1)],
            },
        ]
    }

    fn raw(records: &[CatalogFileRecipeRecord]) -> (CatalogFileRecipeRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::FileMetadata).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        (
            CatalogFileRecipeRoot {
                format_version: 1,
                records: builder.finish(&mut sink).unwrap(),
                files: 1,
                extents: 2,
                sectors: 3,
                logical_bytes: 1000,
                data_bytes: 8,
            },
            pages,
        )
    }

    fn reject(records: &[CatalogFileRecipeRecord]) {
        let mut builder = CatalogFileRecipeBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Ok::<_, &'static str>(());
        for record in records {
            if builder.push_record(record, &mut sink).is_err() {
                break;
            }
        }
        assert!(builder.finish(&mut sink).is_err());
        let (root, pages) = raw(records);
        let mut reader = CatalogFileRecipeReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        loop {
            match reader.next_record(&mut fetch) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("accepted invalid file recipe"),
                Err(_) => break,
            }
        }
        assert!(reader.next_record(&mut fetch).is_err());
    }

    #[test]
    fn catalog_file_recipe_bridge_preserves_sparse_gaps_and_repeated_sectors_across_pages() {
        let large = vec![sector(V1_SECTOR_SIZE as u32); 2049];
        let tail = [sector(7), sector(9)];
        let extents = [
            CatalogFileExtent {
                offset: 123,
                logical_len: large.len() as u64 * V1_SECTOR_SIZE as u64,
                sectors: &large,
            },
            CatalogFileExtent {
                offset: (1 << 40) - 16,
                logical_len: 16,
                sectors: &tail,
            },
        ];
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogFileRecipeBuilder::new(scope()).unwrap();
        builder
            .push_file(2, 1 << 40, extents.iter().copied(), &mut sink)
            .unwrap();
        // Keys need not be adjacent: intervening directory and alias headers
        // have no recipe. Empty and completely sparse files still have headers.
        builder
            .push_file(5, 0, std::iter::empty(), &mut sink)
            .unwrap();
        builder
            .push_file(9, 100, std::iter::empty(), &mut sink)
            .unwrap();
        let root = builder.finish(&mut sink).unwrap();
        assert!(root.records.page.height > 0);
        assert_eq!((root.files, root.extents, root.sectors), (3, 2, 2051));
        assert_eq!(root.logical_bytes, (1 << 40) + 100);
        assert_eq!(
            root.data_bytes,
            large.len() as u64 * V1_SECTOR_SIZE as u64 + 16
        );
        let mut reader = CatalogFileRecipeReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert_eq!(
            reader.next_record(&mut fetch).unwrap().unwrap(),
            header(2, 1 << 40, 2, 2051)
        );
        let mut restored = Vec::new();
        for expected in extents {
            let extent = reader.next_record(&mut fetch).unwrap().unwrap();
            assert_eq!(
                extent,
                CatalogFileRecipeRecord::Extent {
                    offset: expected.offset,
                    logical_len: expected.logical_len,
                    sectors: expected.sectors.len() as u64
                }
            );
            let mut sectors = Vec::new();
            while sectors.len() < expected.sectors.len() {
                let CatalogFileRecipeRecord::Sectors {
                    first_sector,
                    references,
                } = reader.next_record(&mut fetch).unwrap().unwrap()
                else {
                    panic!("missing sector fragment");
                };
                assert_eq!(first_sector, sectors.len() as u64);
                assert!(references.len() <= CATALOG_FILE_SECTOR_REFS);
                sectors.extend(references);
            }
            restored.push((expected.offset, expected.logical_len, sectors));
        }
        assert_eq!(restored.len(), extents.len());
        for ((offset, logical_len, sectors), expected) in restored.iter().zip(extents) {
            assert_eq!(
                (*offset, *logical_len),
                (expected.offset, expected.logical_len)
            );
            assert_eq!(sectors.as_slice(), expected.sectors);
        }
        assert_eq!(
            reader.next_record(&mut fetch).unwrap().unwrap(),
            header(5, 0, 0, 0)
        );
        assert_eq!(
            reader.next_record(&mut fetch).unwrap().unwrap(),
            header(9, 100, 0, 0)
        );
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn catalog_file_recipe_geometry_counts_offsets_and_key_order_are_enforced() {
        for offset in [0, 10, 1000, u64::MAX] {
            let mut records = valid();
            records[3] = CatalogFileRecipeRecord::Extent {
                offset,
                logical_len: 1,
                sectors: 1,
            };
            reject(&records);
        }
        for first_sector in [1, u64::MAX] {
            let mut records = valid();
            records[2] = CatalogFileRecipeRecord::Sectors {
                first_sector,
                references: vec![sector(3), sector(4)],
            };
            reject(&records);
        }
        for references in [
            vec![],
            vec![sector(7)],
            vec![sector(3), sector(3)],
            vec![sector(4), sector(4)],
            vec![sector(3), sector(4), sector(1)],
        ] {
            let mut records = valid();
            records[2] = CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references,
            };
            reject(&records);
        }
        for replacement in [
            header(2, 1000, 1, 3),
            header(2, 1000, 3, 3),
            header(2, 1000, 2, 2),
            header(2, 1000, 2, 4),
        ] {
            let mut records = valid();
            records[0] = replacement;
            reject(&records);
        }
        for end in 1..valid().len() {
            reject(&valid()[..end]);
        }
        let records = valid();
        reject(&records[1..]);
        let mut records = valid();
        records.insert(2, records[3].clone());
        reject(&records);
        let mut records = valid();
        records.extend(valid());
        reject(&records);
        let mut records = valid();
        records.push(header(1, 0, 0, 0));
        reject(&records);
    }

    #[test]
    fn catalog_file_recipe_decoder_bounds_nested_declarations_and_canonical_schema() {
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
                panic!("must reject before reading elements");
            }
        }
        assert!(decode_sectors(serde::de::value::SeqAccessDeserializer::new(Declared)).is_err());
        for len in [1, CATALOG_FILE_SECTOR_REFS, CATALOG_FILE_SECTOR_REFS + 1] {
            let record = CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references: vec![sector(1); len],
            };
            assert_eq!(
                CatalogFileRecipeRecord::decode(&canonical_bytes(&record).unwrap()).is_ok(),
                len <= CATALOG_FILE_SECTOR_REFS
            );
        }
        let invalid = [
            header(CATALOG_MAX_RECORDS, 0, 0, 0),
            header(0, 0, 1, 0),
            header(0, 0, 0, 1),
            header(0, 0, 1, CATALOG_MAX_RECORDS + 1),
            CatalogFileRecipeRecord::File {
                format_version: 2,
                file_key: 0,
                logical_len: 0,
                extents: 0,
                sectors: 0,
            },
            CatalogFileRecipeRecord::Extent {
                offset: 0,
                logical_len: 0,
                sectors: 1,
            },
            CatalogFileRecipeRecord::Extent {
                offset: 0,
                logical_len: V1_SECTOR_SIZE as u64 + 1,
                sectors: 1,
            },
            CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references: vec![sector(0)],
            },
            CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references: vec![sector(V1_SECTOR_SIZE as u32 + 1)],
            },
        ];
        for record in invalid {
            assert!(CatalogFileRecipeRecord::decode(&canonical_bytes(&record).unwrap()).is_err());
        }
        for record in valid() {
            let encoded = canonical_bytes(&record).unwrap();
            assert_eq!(CatalogFileRecipeRecord::decode(&encoded).unwrap(), record);
            assert!(CatalogFileRecipeRecord::decode(&encoded[..encoded.len() - 1]).is_err());
            let mut trailing = encoded.clone();
            trailing.push(0);
            assert!(CatalogFileRecipeRecord::decode(&trailing).is_err());
            let mut noncanonical = vec![encoded[0] | 0x80, 0];
            noncanonical.extend_from_slice(&encoded[1..]);
            assert!(CatalogFileRecipeRecord::decode(&noncanonical).is_err());
        }
        assert!(CatalogFileRecipeRecord::decode(&[0; MAX_ENCODED_RECORD + 1]).is_err());
        assert!(CatalogFileRecipeRecord::decode(&[]).is_err());
    }

    #[test]
    fn catalog_file_recipe_final_summaries_and_empty_roots_fail_closed() {
        let (root, pages) = raw(&valid());
        for changed in [
            CatalogFileRecipeRoot {
                logical_bytes: 1001,
                ..root
            },
            CatalogFileRecipeRoot {
                logical_bytes: 999,
                ..root
            },
            CatalogFileRecipeRoot {
                data_bytes: 9,
                ..root
            },
            CatalogFileRecipeRoot {
                data_bytes: 7,
                ..root
            },
            CatalogFileRecipeRoot { extents: 3, ..root },
            CatalogFileRecipeRoot { files: 2, ..root },
            CatalogFileRecipeRoot { sectors: 4, ..root },
        ] {
            let mut reader = CatalogFileRecipeReader::new(scope(), changed).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            let mut failed = false;
            for _ in 0..valid().len() {
                if reader.next_record(&mut fetch).is_err() {
                    failed = true;
                    break;
                }
            }
            assert!(failed); // Incorrect totals never yield all records.
            assert!(reader.next_record(&mut fetch).is_err());
        }
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let empty = CatalogFileRecipeBuilder::new(scope())
            .unwrap()
            .finish(&mut sink)
            .unwrap();
        assert_eq!(
            (empty.files, empty.logical_bytes, empty.data_bytes),
            (0, 0, 0)
        );
        let mut reader = CatalogFileRecipeReader::new(scope(), empty).unwrap();
        assert!(
            reader
                .next_record(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                    pages[&reference.hash].clone()
                ))
                .unwrap()
                .is_none()
        );
        for changed in [
            CatalogFileRecipeRoot { files: 1, ..empty },
            CatalogFileRecipeRoot {
                logical_bytes: 1,
                ..empty
            },
            CatalogFileRecipeRoot {
                format_version: 2,
                ..empty
            },
            CatalogFileRecipeRoot {
                sectors: 1,
                ..empty
            },
        ] {
            assert!(changed.validate().is_err());
        }
        assert!(
            CatalogFileRecipeReader::new(CatalogScope::Guild { guild_id: [1; 32] }, root).is_err()
        );
    }

    #[test]
    fn catalog_file_recipe_interruption_overflow_and_fetch_failures_are_terminal() {
        let large = vec![sector(V1_SECTOR_SIZE as u32); 2049];
        let extent = CatalogFileExtent {
            offset: 0,
            logical_len: large.len() as u64 * V1_SECTOR_SIZE as u64,
            sectors: &large,
        };
        let mut builder = CatalogFileRecipeBuilder::new(scope()).unwrap();
        let mut offline = |_, _| Err::<(), _>("offline");
        assert!(
            builder
                .push_file(0, extent.logical_len, std::iter::once(extent), &mut offline)
                .is_err()
        );
        assert!(
            builder
                .push_record(&header(1, 0, 0, 0), &mut offline)
                .is_err()
        );
        assert!(builder.finish(&mut offline).is_err());
        let (root, pages) = raw(&valid());
        let mut reader = CatalogFileRecipeReader::new(scope(), root).unwrap();
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
        let mut builder = CatalogFileRecipeBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Ok::<_, &'static str>(());
        builder
            .push_record(&header(0, u64::MAX, 0, 0), &mut sink)
            .unwrap();
        assert!(builder.push_record(&header(1, 1, 0, 0), &mut sink).is_err());
        assert!(builder.finish(&mut sink).is_err());
    }
}
