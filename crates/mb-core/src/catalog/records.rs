//! Version-one bounded record frames over authenticated catalog byte pages.
//! Schema-specific consumers must also bound collections inside each record.

use serde::{Deserialize, Serialize};

use super::{
    CatalogBuilder, CatalogError, CatalogPageRef, CatalogReader, CatalogScope, CatalogSection,
    CatalogStreamError,
};

const HEADER: &[u8; 8] = b"MBCATR\x01\x00";
pub const CATALOG_RECORD_BYTES: usize = 48 * 1024;
pub const CATALOG_MAX_RECORDS: u64 = 64 * 1024 * 1024;

/// The count and page reference must be authenticated together by the enclosing
/// signed revision/checkpoint or owner-encrypted root descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogRecordRoot {
    pub format_version: u16,
    pub page: CatalogPageRef,
    pub records: u64,
}

impl CatalogRecordRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.page.validate()?;
        if self.format_version != 1
            || self.records > CATALOG_MAX_RECORDS
            || self.page.byte_len < HEADER.len() as u64 + self.records * 5
            || self.page.byte_len
                > HEADER.len() as u64 + self.records * (4 + CATALOG_RECORD_BYTES as u64)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

/// Streams records through one fixed serialization buffer and the bounded page
/// builder. Large trees, extent lists and object payloads require independent
/// bounded record fragments; passing one giant collection is rejected.
pub struct CatalogRecordBuilder {
    pages: CatalogBuilder,
    encoding: Vec<u8>,
    records: u64,
    header_written: bool,
    failed: bool,
}

impl CatalogRecordBuilder {
    pub fn new(scope: CatalogScope, section: CatalogSection) -> Result<Self, CatalogError> {
        Ok(Self {
            pages: CatalogBuilder::new(scope, section)?,
            encoding: vec![0; CATALOG_RECORD_BYTES],
            records: 0,
            header_written: false,
            failed: false,
        })
    }

    pub fn push<T: Serialize, E>(
        &mut self,
        value: &T,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = match postcard::to_slice(value, &mut self.encoding) {
            Ok(encoded) => push_frame(
                &mut self.pages,
                &mut self.records,
                &mut self.header_written,
                encoded,
                sink,
            ),
            Err(postcard::Error::SerializeBufferFull) => Err(CatalogError::Bounds.into()),
            Err(error) => Err(CatalogError::Model(crate::ModelError::Encode(error)).into()),
        };
        self.failed = result.is_err();
        result
    }

    pub fn push_encoded<E>(
        &mut self,
        encoded: &[u8],
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = push_frame(
            &mut self.pages,
            &mut self.records,
            &mut self.header_written,
            encoded,
            sink,
        );
        self.failed = result.is_err();
        result
    }

    pub fn finish<E>(
        mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogRecordRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if !self.header_written {
            self.pages.push(HEADER, sink)?;
        }
        let root = CatalogRecordRoot {
            format_version: 1,
            page: self.pages.finish(sink)?,
            records: self.records,
        };
        root.validate()?;
        Ok(root)
    }
}

fn push_frame<E>(
    pages: &mut CatalogBuilder,
    records: &mut u64,
    header_written: &mut bool,
    encoded: &[u8],
    sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
) -> Result<(), CatalogStreamError<E>> {
    if encoded.is_empty() || encoded.len() > CATALOG_RECORD_BYTES || *records == CATALOG_MAX_RECORDS
    {
        return Err(CatalogError::Bounds.into());
    }
    if !*header_written {
        pages.push(HEADER, sink)?;
        *header_written = true;
    }
    pages.push(&(encoded.len() as u32).to_be_bytes(), sink)?;
    pages.push(encoded, sink)?;
    *records += 1;
    Ok(())
}

/// Returns one raw, bounded record at a time. Typed decoders must validate
/// their own schema, nested collection sizes and canonical encoding. Page
/// authentication alone does not supply those schema-specific guarantees.
pub struct CatalogRecordReader {
    pages: CatalogReader,
    root: CatalogRecordRoot,
    leaf: Vec<u8>,
    position: usize,
    records: u64,
    header_checked: bool,
    failed: bool,
}

impl CatalogRecordReader {
    pub fn new(
        scope: CatalogScope,
        section: CatalogSection,
        root: CatalogRecordRoot,
    ) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            pages: CatalogReader::new(scope, section, root.page)?,
            root,
            leaf: Vec::new(),
            position: 0,
            records: 0,
            header_checked: false,
            failed: false,
        })
    }

    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<Vec<u8>>, CatalogStreamError<E>> {
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
    ) -> Result<Option<Vec<u8>>, CatalogStreamError<E>> {
        if !self.header_checked {
            let mut header = [0; HEADER.len()];
            self.read_exact(&mut header, fetch)?;
            if &header != HEADER {
                return Err(CatalogError::InvalidPage.into());
            }
            self.header_checked = true;
        }
        if self.records == self.root.records {
            if self.ensure_leaf(fetch)? {
                return Err(CatalogError::InvalidPage.into());
            }
            return Ok(None);
        }
        let mut length = [0; 4];
        self.read_exact(&mut length, fetch)?;
        let length = u32::from_be_bytes(length) as usize;
        if length == 0 || length > CATALOG_RECORD_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let mut bytes = vec![0; length];
        self.read_exact(&mut bytes, fetch)?;
        self.records += 1;
        // Check the final trailer/EOF before yielding the final record, so a
        // consumer cannot accept all promised records while ignoring junk.
        if self.records == self.root.records && self.ensure_leaf(fetch)? {
            return Err(CatalogError::InvalidPage.into());
        }
        Ok(Some(bytes))
    }

    fn ensure_leaf<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<bool, CatalogStreamError<E>> {
        while self.position == self.leaf.len() {
            let Some(leaf) = self.pages.next_leaf(fetch)? else {
                return Ok(false);
            };
            self.leaf = leaf;
            self.position = 0;
        }
        Ok(true)
    }

    fn read_exact<E>(
        &mut self,
        mut output: &mut [u8],
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<(), CatalogStreamError<E>> {
        while !output.is_empty() {
            if !self.ensure_leaf(fetch)? {
                return Err(CatalogError::InvalidPage.into());
            }
            let take = output.len().min(self.leaf.len() - self.position);
            output[..take].copy_from_slice(&self.leaf[self.position..self.position + take]);
            self.position += take;
            output = &mut output[take..];
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{CATALOG_LEAF_BYTES, NodeId, canonical_bytes, decode_canonical};
    use uuid::Uuid;

    use super::*;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn frame_bytes(bytes: &[u8], records: u64) -> (CatalogRecordRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, encoded| {
            pages.insert(reference.hash, encoded);
            Ok::<_, &'static str>(())
        };
        let mut tree = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        tree.push(bytes, &mut sink).unwrap();
        let root = CatalogRecordRoot {
            format_version: 1,
            page: tree.finish(&mut sink).unwrap(),
            records,
        };
        (root, pages)
    }

    #[test]
    fn catalog_records_stream_across_every_length_header_boundary_and_payload_boundary() {
        for gap in [0, 1, 2, 3, 4, 7, 41] {
            let values = [
                vec![1; 40 * 1024],
                vec![2; CATALOG_LEAF_BYTES - gap - HEADER.len() - 8 - 40 * 1024],
                vec![3; CATALOG_RECORD_BYTES],
            ];
            let mut pages = Pages::new();
            let mut sink = |reference: CatalogPageRef, encoded| {
                pages.insert(reference.hash, encoded);
                Ok::<_, &'static str>(())
            };
            let mut writer = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
            for value in &values {
                writer.push_encoded(value, &mut sink).unwrap();
            }
            let root = writer.finish(&mut sink).unwrap();
            assert_eq!(root.records, 3);
            let mut reader =
                CatalogRecordReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            for value in values {
                assert_eq!(reader.next_record(&mut fetch).unwrap().unwrap(), value);
                assert!(reader.leaf.len() <= CATALOG_LEAF_BYTES);
            }
            assert!(reader.next_record(&mut fetch).unwrap().is_none());
            assert!(reader.next_record(&mut fetch).unwrap().is_none());
        }
    }

    #[test]
    fn catalog_record_serialization_is_bounded_at_and_above_the_actual_encoded_limit() {
        for length in [CATALOG_RECORD_BYTES - 4, CATALOG_RECORD_BYTES - 3] {
            let value = vec![7_u8; length];
            let mut pages = Pages::new();
            let mut sink = |reference: CatalogPageRef, encoded| {
                pages.insert(reference.hash, encoded);
                Ok::<_, &'static str>(())
            };
            let mut writer = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
            writer.push(&value, &mut sink).unwrap();
            let root = writer.finish(&mut sink).unwrap();
            let mut reader =
                CatalogRecordReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            let encoded = reader.next_record(&mut fetch).unwrap().unwrap();
            assert_eq!(encoded.len(), length + 3);
            assert_eq!(encoded, canonical_bytes(&value).unwrap());
            assert_eq!(decode_canonical::<Vec<u8>>(&encoded).unwrap(), value);
        }
        let mut writer = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        let mut writes = 0;
        let mut sink = |_, _| {
            writes += 1;
            Ok::<_, &'static str>(())
        };
        assert!(matches!(
            writer.push(&vec![7_u8; CATALOG_RECORD_BYTES - 2], &mut sink),
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
        assert!(matches!(
            writer.push(&1_u8, &mut sink),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        assert!(writer.finish(&mut sink).is_err());
        assert_eq!(writes, 0);
    }

    #[test]
    fn catalog_record_empty_stream_and_declared_count_are_authenticated() {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, encoded| {
            pages.insert(reference.hash, encoded);
            Ok::<_, &'static str>(())
        };
        let root = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph)
            .unwrap()
            .finish(&mut sink)
            .unwrap();
        assert_eq!(root.records, 0);
        assert_eq!(root.page.byte_len, HEADER.len() as u64);
        let mut reader = CatalogRecordReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
        let mut false_count = root;
        false_count.records = 1;
        assert!(false_count.validate().is_err());
        false_count.records = CATALOG_MAX_RECORDS + 1;
        assert!(false_count.validate().is_err());
        false_count = root;
        false_count.format_version = 2;
        assert!(false_count.validate().is_err());
    }

    #[test]
    fn catalog_record_rejects_malformed_truncated_oversized_and_trailing_frames() {
        let mut wrong_header = HEADER.to_vec();
        wrong_header[6] = 2;
        let cases = [
            (wrong_header, 0),
            ([HEADER.as_slice(), &0_u32.to_be_bytes(), b"x"].concat(), 1),
            (
                [HEADER.as_slice(), &u32::MAX.to_be_bytes(), b"x"].concat(),
                1,
            ),
            (
                [HEADER.as_slice(), &4_u32.to_be_bytes(), b"abc"].concat(),
                1,
            ),
            (
                [HEADER.as_slice(), &1_u32.to_be_bytes(), b"x", b"junk"].concat(),
                1,
            ),
            (
                [HEADER.as_slice(), &6_u32.to_be_bytes(), b"abcdef"].concat(),
                2,
            ),
        ];
        for (bytes, count) in cases {
            let (root, pages) = frame_bytes(&bytes, count);
            let mut reader =
                CatalogRecordReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            loop {
                match reader.next_record(&mut fetch) {
                    Err(_) => break,
                    Ok(Some(_)) => {}
                    Ok(None) => panic!("malformed record stream accepted"),
                }
            }
            assert!(matches!(
                reader.next_record(&mut fetch),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
    }

    #[test]
    fn catalog_record_storage_and_fetch_failure_prevent_publication_and_continuation() {
        let mut writer = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        let mut fail = |_: CatalogPageRef, _: Vec<u8>| Err("offline");
        // Two records flush a page before finish: no root can escape a failed
        // page write even though the first complete record was accepted.
        writer
            .push_encoded(&vec![1; CATALOG_RECORD_BYTES], &mut fail)
            .unwrap();
        assert!(matches!(
            writer.push_encoded(&vec![2; CATALOG_RECORD_BYTES], &mut fail),
            Err(CatalogStreamError::Storage("offline"))
        ));
        assert!(writer.finish(&mut fail).is_err());
        let (root, pages) =
            frame_bytes(&[HEADER.as_slice(), &1_u32.to_be_bytes(), b"x"].concat(), 1);
        let mut reader = CatalogRecordReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
        let mut offline = |_: CatalogPageRef| Err("offline");
        assert!(matches!(
            reader.next_record(&mut offline),
            Err(CatalogStreamError::Storage("offline"))
        ));
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert!(matches!(
            reader.next_record(&mut fetch),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }
}
