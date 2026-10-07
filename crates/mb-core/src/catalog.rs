//! Bounded, authenticated byte-stream trees. This primitive does not enable
//! larger revision/checkpoint formats; their consumers must migrate together.

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::{ModelError, NodeId, canonical_bytes, decode_canonical};

mod file_recipes;
mod files;
mod native_files;
mod packed_sectors;
mod packed_sources;
mod privacy;
mod range;
mod records;
mod revision;
mod sectors;
mod splice;
pub use file_recipes::{
    CATALOG_FILE_SECTOR_REFS, CatalogFileExtent, CatalogFileRecipeBuilder, CatalogFileRecipeReader,
    CatalogFileRecipeRecord, CatalogFileRecipeRoot,
};
pub use files::{
    CATALOG_FILE_PATH_BYTES, CATALOG_FILE_RECORD_BYTES, CatalogFileBuilder, CatalogFileKind,
    CatalogFileReader, CatalogFileRecord, CatalogFileRoot, CatalogFileStat,
    catalog_file_path_order,
};
pub use native_files::{
    CATALOG_NATIVE_FILE_ROOT_BYTES, CatalogFileEvent, CatalogNativeFileReader,
    CatalogNativeFileRoot,
};
pub use packed_sectors::{
    CATALOG_PACKED_RECORD_BYTES, CATALOG_PACKED_ROOT_BYTES, CATALOG_PACKED_SLOTS,
    CatalogPackedChunkReference, CatalogPackedSectorBuilder, CatalogPackedSectorReader,
    CatalogPackedSectorRecord, CatalogPackedSectorRoot, CatalogPackedSlotReference,
};
pub use packed_sources::{
    CATALOG_PACKED_SOURCE_PROOFS, CATALOG_PACKED_SOURCE_RECORD_BYTES,
    CATALOG_PACKED_SOURCE_ROOT_BYTES, CatalogPackedSourceBuilder, CatalogPackedSourceId,
    CatalogPackedSourceProof, CatalogPackedSourceReader, CatalogPackedSourceRecord,
    CatalogPackedSourceRoot,
};
pub use range::CatalogRangeReader;
pub use records::{
    CATALOG_MAX_RECORDS, CATALOG_RECORD_BYTES, CatalogRecordBuilder, CatalogRecordReader,
    CatalogRecordRoot,
};
pub use revision::{
    PAGED_PRIVATE_METADATA_BYTES, PAGED_USER_REVISION_BYTES, PAGED_USER_REVISION_DOMAIN,
    PAGED_USER_REVISION_VERSION, PagedRevisionSourceReader, PagedUserRevision,
};
pub use sectors::{
    CATALOG_SECTOR_RECORD_BYTES, CatalogSectorBuilder, CatalogSectorReader, CatalogSectorRecord,
    CatalogSectorRoot,
};

pub const CATALOG_PAGE_BYTES: usize = 64 * 1024;
pub const CATALOG_LEAF_BYTES: usize = 60 * 1024;
pub const CATALOG_FANOUT: usize = 128;
pub const CATALOG_MAX_HEIGHT: u8 = 3;
pub const CATALOG_MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024 * 1024;
pub const CATALOG_MAX_PAGE_OCCURRENCES: u64 = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogScope {
    Dataset {
        guild_id: [u8; 32],
        owner: NodeId,
        protected_root_id: Uuid,
    },
    Guild {
        guild_id: [u8; 32],
    },
}

impl CatalogScope {
    pub fn validate(self, section: CatalogSection) -> Result<(), CatalogError> {
        match (self, section) {
            (
                Self::Dataset {
                    protected_root_id, ..
                },
                CatalogSection::FileMetadata
                | CatalogSection::GitGraph
                | CatalogSection::SectorReferences,
            ) if !protected_root_id.is_nil() => Ok(()),
            (Self::Guild { .. }, CatalogSection::Packing | CatalogSection::Coding) => Ok(()),
            _ => Err(CatalogError::InvalidPage),
        }
    }
}

/// Serialized discriminants are append-only within page format one.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogSection {
    FileMetadata,
    GitGraph,
    SectorReferences,
    Packing,
    Coding,
}

impl CatalogSection {
    /// Private page hashes/recipes stay inside owner-encrypted metadata.
    /// Public source references and guild catalogs remain available to their
    /// authorized signers and recovery peers without the owner's data key.
    pub fn is_private(self) -> bool {
        matches!(self, Self::FileMetadata | Self::GitGraph)
    }
}

/// A reference must come from a verified signed root or authenticated parent.
/// Counts include repeated references: deduplication must not change traversal
/// order, represented bytes or work bounds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPageRef {
    pub hash: [u8; 32],
    pub encoded_len: u32,
    pub height: u8,
    pub byte_len: u64,
    pub page_occurrences: u64,
}

/// Contents obtained only after verifying the encoded page against its
/// authenticated reference, scope, version, geometry and canonical encoding.
/// The reference's authority must still come from a signed root or parent.
#[derive(Debug, Eq, PartialEq)]
pub enum CatalogPageContents {
    Leaf(Vec<u8>),
    Index(Vec<CatalogPageRef>),
}

#[derive(Debug, Error)]
pub enum CatalogError {
    #[error("catalog page or tree exceeds its format-one bounds")]
    Bounds,
    #[error("catalog page does not match its authenticated reference or scope")]
    InvalidPage,
    #[error("catalog operation cannot continue after a prior failure")]
    Failed,
    #[error(transparent)]
    Model(#[from] ModelError),
    #[error(transparent)]
    Content(#[from] crate::ContentError),
}

#[derive(Debug, Error)]
pub enum CatalogStreamError<E> {
    #[error(transparent)]
    Catalog(#[from] CatalogError),
    #[error("catalog page storage failed: {0}")]
    Storage(E),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum PageBody {
    Leaf(#[serde(deserialize_with = "decode_leaf")] Vec<u8>),
    Index(#[serde(deserialize_with = "decode_index")] Vec<CatalogPageRef>),
}

fn decode_leaf<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    decode_bounded(decoder, CATALOG_LEAF_BYTES)
}

fn decode_index<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<CatalogPageRef>, D::Error> {
    decode_bounded(decoder, CATALOG_FANOUT)
}

fn decode_bounded<'de, D, T>(decoder: D, limit: usize) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Bounded<T>(usize, std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for Bounded<T> {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {} catalog elements", self.0)
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > self.0) {
                return Err(serde::de::Error::custom(
                    "catalog collection exceeds page bounds",
                ));
            }
            let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.0));
            while let Some(value) = sequence.next_element()? {
                if values.len() == self.0 {
                    return Err(serde::de::Error::custom(
                        "catalog collection exceeds page bounds",
                    ));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    decoder.deserialize_seq(Bounded(limit, std::marker::PhantomData))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Page {
    format_version: u16,
    scope: CatalogScope,
    section: CatalogSection,
    height: u8,
    body: PageBody,
}

impl CatalogPageRef {
    pub fn verify_page(
        self,
        scope: CatalogScope,
        section: CatalogSection,
        bytes: &[u8],
    ) -> Result<CatalogPageContents, CatalogError> {
        Ok(match verify_page(self, scope, section, bytes)?.body {
            PageBody::Leaf(bytes) => CatalogPageContents::Leaf(bytes),
            PageBody::Index(children) => CatalogPageContents::Index(children),
        })
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.encoded_len == 0
            || self.encoded_len as usize > CATALOG_PAGE_BYTES
            || self.height > CATALOG_MAX_HEIGHT
            || self.byte_len > CATALOG_MAX_STREAM_BYTES
            || self.page_occurrences == 0
            || self.page_occurrences > CATALOG_MAX_PAGE_OCCURRENCES
            || (self.height == 0
                && (self.page_occurrences != 1 || self.byte_len > CATALOG_LEAF_BYTES as u64))
            || (self.height > 0 && (self.byte_len == 0 || self.page_occurrences <= 1))
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

impl Page {
    fn counts(&self) -> Result<(u64, u64), CatalogError> {
        self.scope.validate(self.section)?;
        if self.format_version != 1 || self.height > CATALOG_MAX_HEIGHT {
            return Err(CatalogError::InvalidPage);
        }
        match &self.body {
            PageBody::Leaf(bytes) if self.height == 0 && bytes.len() <= CATALOG_LEAF_BYTES => {
                Ok((bytes.len() as u64, 1))
            }
            PageBody::Index(children)
                if self.height > 0 && !children.is_empty() && children.len() <= CATALOG_FANOUT =>
            {
                let mut byte_len = 0_u64;
                let mut pages = 1_u64;
                for child in children {
                    child.validate()?;
                    if child.height + 1 != self.height || child.byte_len == 0 {
                        return Err(CatalogError::InvalidPage);
                    }
                    byte_len = byte_len
                        .checked_add(child.byte_len)
                        .ok_or(CatalogError::Bounds)?;
                    pages = pages
                        .checked_add(child.page_occurrences)
                        .ok_or(CatalogError::Bounds)?;
                }
                if byte_len > CATALOG_MAX_STREAM_BYTES || pages > CATALOG_MAX_PAGE_OCCURRENCES {
                    return Err(CatalogError::Bounds);
                }
                Ok((byte_len, pages))
            }
            _ => Err(CatalogError::InvalidPage),
        }
    }

    fn encode(&self) -> Result<(CatalogPageRef, Vec<u8>), CatalogError> {
        let (byte_len, page_occurrences) = self.counts()?;
        let bytes = canonical_bytes(self)?;
        if bytes.len() > CATALOG_PAGE_BYTES {
            return Err(CatalogError::Bounds);
        }
        Ok((
            CatalogPageRef {
                hash: page_hash(&bytes),
                encoded_len: bytes.len() as u32,
                height: self.height,
                byte_len,
                page_occurrences,
            },
            bytes,
        ))
    }
}

fn page_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_derive_key("mutualbackup catalog page v1");
    hash.update(bytes);
    *hash.finalize().as_bytes()
}

fn verify_page(
    expected: CatalogPageRef,
    scope: CatalogScope,
    section: CatalogSection,
    bytes: &[u8],
) -> Result<Page, CatalogError> {
    expected.validate()?;
    // Authenticate and bound the frame before allocating decoded collections.
    if bytes.len() != expected.encoded_len as usize || page_hash(bytes) != expected.hash {
        return Err(CatalogError::InvalidPage);
    }
    let page: Page = decode_canonical(bytes)?;
    if page.scope != scope || page.section != section {
        return Err(CatalogError::InvalidPage);
    }
    let (reference, canonical) = page.encode()?;
    if reference != expected || canonical != bytes {
        return Err(CatalogError::InvalidPage);
    }
    Ok(page)
}

/// Retains one partial leaf and fewer than `CATALOG_FANOUT` references per
/// height. The sink persists each bounded encoded page before accepting it.
/// Only `finish` emits the publishable root. Uncommitted pages require durable
/// intent ownership in the surrounding storage workflow.
pub struct CatalogBuilder {
    scope: CatalogScope,
    section: CatalogSection,
    leaf: Vec<u8>,
    levels: Vec<Vec<CatalogPageRef>>,
    byte_len: u64,
    failed: bool,
}

impl CatalogBuilder {
    pub fn new(scope: CatalogScope, section: CatalogSection) -> Result<Self, CatalogError> {
        scope.validate(section)?;
        Ok(Self {
            scope,
            section,
            leaf: Vec::with_capacity(CATALOG_LEAF_BYTES),
            levels: (0..=CATALOG_MAX_HEIGHT).map(|_| Vec::new()).collect(),
            byte_len: 0,
            failed: false,
        })
    }

    pub fn push<E>(
        &mut self,
        bytes: &[u8],
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.push_inner(bytes, sink);
        self.failed = result.is_err();
        result
    }

    fn push_inner<E>(
        &mut self,
        mut bytes: &[u8],
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        self.byte_len = self
            .byte_len
            .checked_add(bytes.len() as u64)
            .ok_or(CatalogError::Bounds)?;
        if self.byte_len > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        while !bytes.is_empty() {
            let take = bytes.len().min(CATALOG_LEAF_BYTES - self.leaf.len());
            self.leaf.extend_from_slice(&bytes[..take]);
            bytes = &bytes[take..];
            if self.leaf.len() == CATALOG_LEAF_BYTES {
                self.flush_leaf(sink)?;
            }
        }
        Ok(())
    }

    fn store<E>(
        &self,
        height: u8,
        body: PageBody,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPageRef, CatalogStreamError<E>> {
        let (reference, bytes) = Page {
            format_version: 1,
            scope: self.scope,
            section: self.section,
            height,
            body,
        }
        .encode()?;
        sink(reference, bytes).map_err(CatalogStreamError::Storage)?;
        Ok(reference)
    }

    fn flush_leaf<E>(
        &mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        let bytes = std::mem::take(&mut self.leaf);
        let reference = self.store(0, PageBody::Leaf(bytes), sink)?;
        self.append(reference, sink)
    }

    fn append<E>(
        &mut self,
        mut reference: CatalogPageRef,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        loop {
            let height = reference.height as usize;
            self.levels[height].push(reference);
            if self.levels[height].len() < CATALOG_FANOUT {
                return Ok(());
            }
            if height == CATALOG_MAX_HEIGHT as usize {
                return Err(CatalogError::Bounds.into());
            }
            let children = std::mem::take(&mut self.levels[height]);
            reference = self.store(reference.height + 1, PageBody::Index(children), sink)?;
        }
    }

    pub fn finish<E>(
        mut self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPageRef, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        if !self.leaf.is_empty() || self.byte_len == 0 {
            self.flush_leaf(sink)?;
        }
        for height in 0..=CATALOG_MAX_HEIGHT as usize {
            if self.levels[height].is_empty() {
                continue;
            }
            if self.levels[height].len() == 1 && self.levels[height + 1..].iter().all(Vec::is_empty)
            {
                return Ok(self.levels[height][0]);
            }
            if height == CATALOG_MAX_HEIGHT as usize {
                return Err(CatalogError::Bounds.into());
            }
            let children = std::mem::take(&mut self.levels[height]);
            let reference = self.store(height as u8 + 1, PageBody::Index(children), sink)?;
            self.append(reference, sink)?;
        }
        Err(CatalogError::InvalidPage.into())
    }
}

/// Ordered authenticated traversal with at most `fanout * height + 1` pending
/// references. The fetch callback must bound transport/storage allocation to
/// the reference's encoded length. No complete stream is assembled here.
pub struct CatalogReader {
    scope: CatalogScope,
    section: CatalogSection,
    root: CatalogPageRef,
    pending: Vec<CatalogPageRef>,
    visited: u64,
    byte_len: u64,
    failed: bool,
}

impl CatalogReader {
    pub fn new(
        scope: CatalogScope,
        section: CatalogSection,
        root: CatalogPageRef,
    ) -> Result<Self, CatalogError> {
        root.validate()?;
        scope.validate(section)?;
        Ok(Self {
            scope,
            section,
            root,
            pending: vec![root],
            visited: 0,
            byte_len: 0,
            failed: false,
        })
    }

    pub fn next_leaf<E>(
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
        while let Some(reference) = self.pending.pop() {
            self.visited += 1;
            if self.visited > self.root.page_occurrences {
                return Err(CatalogError::Bounds.into());
            }
            let bytes = fetch(reference).map_err(CatalogStreamError::Storage)?;
            let page = verify_page(reference, self.scope, self.section, &bytes)?;
            match page.body {
                PageBody::Index(children) => self.pending.extend(children.into_iter().rev()),
                PageBody::Leaf(bytes) => {
                    self.byte_len += bytes.len() as u64;
                    if self.byte_len > self.root.byte_len {
                        return Err(CatalogError::Bounds.into());
                    }
                    if self.pending.is_empty() {
                        self.check_finished()?;
                    }
                    return Ok(Some(bytes));
                }
            }
        }
        self.check_finished()?;
        Ok(None)
    }

    fn check_finished(&self) -> Result<(), CatalogError> {
        if self.visited != self.root.page_occurrences || self.byte_len != self.root.byte_len {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn build(bytes: &[u8], chunk_size: usize) -> (CatalogPageRef, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, encoded: Vec<u8>| {
            assert!(encoded.len() <= CATALOG_PAGE_BYTES);
            pages.insert(reference.hash, encoded);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        for chunk in bytes.chunks(chunk_size) {
            builder.push(chunk, &mut sink).unwrap();
            assert!(builder.leaf.len() < CATALOG_LEAF_BYTES);
            assert!(
                builder
                    .levels
                    .iter()
                    .all(|level| level.len() < CATALOG_FANOUT)
            );
        }
        let root = builder.finish(&mut sink).unwrap();
        (root, pages)
    }

    #[test]
    fn catalog_stream_boundaries_are_deterministic_and_round_trip_in_order() {
        for length in [
            0,
            1,
            CATALOG_LEAF_BYTES - 1,
            CATALOG_LEAF_BYTES,
            CATALOG_LEAF_BYTES + 1,
            CATALOG_LEAF_BYTES * CATALOG_FANOUT,
            CATALOG_LEAF_BYTES * CATALOG_FANOUT + 1,
        ] {
            let bytes = (0..length)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let (root, pages) = build(&bytes, 8191);
            assert_eq!(root.byte_len, length as u64);
            assert_eq!(root, build(&bytes, 16384).0);
            let mut reader = CatalogReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
            let mut received = 0;
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            while let Some(leaf) = reader.next_leaf(&mut fetch).unwrap() {
                assert_eq!(leaf, bytes[received..received + leaf.len()]);
                received += leaf.len();
                assert!(reader.pending.len() <= CATALOG_FANOUT * CATALOG_MAX_HEIGHT as usize + 1);
            }
            assert_eq!(received, length);
            assert_eq!(reader.visited, root.page_occurrences);
        }
    }

    #[test]
    fn catalog_rejects_corruption_substitution_and_wrong_authenticated_counts() {
        let (root, pages) = build(&vec![7; CATALOG_LEAF_BYTES + 1], 4096);
        let encoded = &pages[&root.hash];
        let mut corrupt = encoded.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(verify_page(root, scope(), CatalogSection::GitGraph, &corrupt).is_err());
        let wrong_scope = CatalogScope::Dataset {
            protected_root_id: Uuid::from_bytes([4; 16]),
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
        };
        assert!(verify_page(root, wrong_scope, CatalogSection::GitGraph, encoded).is_err());
        assert!(verify_page(root, scope(), CatalogSection::FileMetadata, encoded).is_err());
        for field in 0..4 {
            let mut wrong = root;
            match field {
                0 => wrong.byte_len += 1,
                1 => wrong.page_occurrences += 1,
                2 => wrong.height += 1,
                _ => wrong.encoded_len -= 1,
            }
            assert!(verify_page(wrong, scope(), CatalogSection::GitGraph, encoded).is_err());
        }
        let mut page: Page = decode_canonical(encoded).unwrap();
        let PageBody::Index(children) = &mut page.body else {
            panic!("expected index")
        };
        children.swap(0, 1);
        let (_, reordered) = page.encode().unwrap();
        assert!(verify_page(root, scope(), CatalogSection::GitGraph, &reordered).is_err());
        let mut appended = encoded.clone();
        appended.push(0);
        let mut forged = root;
        forged.encoded_len += 1;
        forged.hash = page_hash(&appended);
        assert!(verify_page(forged, scope(), CatalogSection::GitGraph, &appended).is_err());
    }

    #[test]
    fn catalog_decode_bounds_collections_before_allocation_and_rejects_cycles() {
        let leaf = Page {
            format_version: 1,
            scope: scope(),
            section: CatalogSection::GitGraph,
            height: 0,
            body: PageBody::Leaf(vec![0; CATALOG_LEAF_BYTES + 1]),
        };
        let bytes = canonical_bytes(&leaf).unwrap();
        assert!(bytes.len() < CATALOG_PAGE_BYTES);
        assert!(decode_canonical::<Page>(&bytes).is_err());
        let (child, _) = Page {
            body: PageBody::Leaf(vec![1]),
            ..leaf.clone()
        }
        .encode()
        .unwrap();
        let mut index = Page {
            height: 1,
            body: PageBody::Index(vec![child; CATALOG_FANOUT + 1]),
            ..leaf
        };
        assert!(decode_canonical::<Page>(&canonical_bytes(&index).unwrap()).is_err());
        index.body = PageBody::Index(vec![CatalogPageRef { height: 1, ..child }]);
        assert!(index.encode().is_err());
        index.body = PageBody::Index(Vec::new());
        assert!(index.encode().is_err());
        index.format_version = 2;
        assert!(index.encode().is_err());
        // Postcard's declared sequence length must not trigger a large allocation.
        assert!(
            decode_bounded::<_, u8>(
                &mut postcard::Deserializer::from_bytes(&[0xff, 0xff, 0xff, 0xff, 0x0f]),
                128
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_storage_failure_never_emits_root_or_allows_continuation() {
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        let mut fail = |_: CatalogPageRef, _: Vec<u8>| Err("offline");
        assert!(matches!(
            builder.push(&vec![1; CATALOG_LEAF_BYTES], &mut fail),
            Err(CatalogStreamError::Storage("offline"))
        ));
        assert!(matches!(
            builder.push(&[], &mut fail),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        assert!(matches!(
            builder.finish(&mut fail),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        builder.byte_len = CATALOG_MAX_STREAM_BYTES - 1;
        let mut stores = 0;
        let mut sink = |_: CatalogPageRef, _: Vec<u8>| {
            stores += 1;
            Ok::<_, &'static str>(())
        };
        builder.push(&[1], &mut sink).unwrap();
        assert!(builder.push(&[2], &mut sink).is_err());
        assert!(builder.finish(&mut sink).is_err());
        assert_eq!(stores, 0);
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        builder.push(&[1], &mut fail).unwrap();
        assert!(matches!(
            builder.finish(&mut fail),
            Err(CatalogStreamError::Storage("offline"))
        ));
    }

    #[test]
    fn catalog_reader_failure_is_terminal_and_repeated_pages_count_each_occurrence() {
        let (root, pages) = build(&vec![1; CATALOG_LEAF_BYTES * 2], CATALOG_LEAF_BYTES);
        assert_eq!(pages.len(), 2, "the identical leaves share one stored page");
        assert_eq!(root.page_occurrences, 3);
        let mut reader = CatalogReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert_eq!(
            reader.next_leaf(&mut fetch).unwrap().unwrap().len(),
            CATALOG_LEAF_BYTES
        );
        assert_eq!(
            reader.next_leaf(&mut fetch).unwrap().unwrap().len(),
            CATALOG_LEAF_BYTES
        );
        assert!(reader.next_leaf(&mut fetch).unwrap().is_none());
        assert_eq!(reader.visited, 3);
        let mut reader = CatalogReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
        let mut offline = |_: CatalogPageRef| Err("offline");
        assert!(matches!(
            reader.next_leaf(&mut offline),
            Err(CatalogStreamError::Storage("offline"))
        ));
        assert!(matches!(
            reader.next_leaf(&mut fetch),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }

    #[test]
    fn catalog_structural_limit_has_room_for_the_declared_capacity_geometry() {
        // 1 TiB / 64 KiB = 16,777,216 data refs. Budget 1 KiB per reference
        // for recipes, commitments and bounded record framing. This verifies
        // tree shape only; it is not a data backup or a capacity qualification.
        let mut reference = CatalogPageRef {
            hash: [5; 32],
            encoded_len: CATALOG_PAGE_BYTES as u32,
            height: 0,
            byte_len: CATALOG_LEAF_BYTES as u64,
            page_occurrences: 1,
        };
        reference.validate().unwrap();
        for height in 1..=CATALOG_MAX_HEIGHT {
            let page = Page {
                format_version: 1,
                scope: scope(),
                section: CatalogSection::SectorReferences,
                height,
                body: PageBody::Index(vec![reference; CATALOG_FANOUT]),
            };
            if height < CATALOG_MAX_HEIGHT {
                reference = page.encode().unwrap().0;
            } else {
                assert!(
                    page.encode().is_err(),
                    "stream byte bound precedes maximum tree fanout"
                );
            }
        }
        assert_eq!(CATALOG_MAX_STREAM_BYTES, (1_u64 << 40) / (64 * 1024) * 1024);
        assert!(
            CATALOG_LEAF_BYTES as u64 * (CATALOG_FANOUT as u64).pow(3) > CATALOG_MAX_STREAM_BYTES
        );
        let mut over = reference;
        over.byte_len = CATALOG_MAX_STREAM_BYTES + 1;
        assert!(over.validate().is_err());
        over = reference;
        over.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES + 1;
        assert!(over.validate().is_err());
        over = reference;
        over.height = CATALOG_MAX_HEIGHT + 1;
        assert!(over.validate().is_err());
    }

    #[test]
    fn catalog_exact_stream_limit_authenticates_repeated_subtrees_with_bounded_construction() {
        fn tree(
            length: u64,
            height: u8,
            cache: &mut HashMap<(u64, u8), CatalogPageRef>,
        ) -> CatalogPageRef {
            if let Some(reference) = cache.get(&(length, height)) {
                return *reference;
            }
            let body = if height == 0 {
                PageBody::Leaf(vec![0; length as usize])
            } else {
                let capacity =
                    CATALOG_LEAF_BYTES as u64 * (CATALOG_FANOUT as u64).pow(height as u32 - 1);
                let mut children = Vec::new();
                let mut remaining = length;
                while remaining > 0 {
                    let take = remaining.min(capacity);
                    children.push(tree(take, height - 1, cache));
                    remaining -= take;
                }
                PageBody::Index(children)
            };
            let (reference, encoded) = Page {
                format_version: 1,
                scope: scope(),
                section: CatalogSection::SectorReferences,
                height,
                body,
            }
            .encode()
            .unwrap();
            verify_page(
                reference,
                scope(),
                CatalogSection::SectorReferences,
                &encoded,
            )
            .unwrap();
            cache.insert((length, height), reference);
            reference
        }
        for length in [CATALOG_MAX_STREAM_BYTES - 1, CATALOG_MAX_STREAM_BYTES] {
            let mut cache = HashMap::new();
            let root = tree(length, CATALOG_MAX_HEIGHT, &mut cache);
            assert_eq!(root.byte_len, length);
            assert!(root.page_occurrences <= CATALOG_MAX_PAGE_OCCURRENCES);
            assert!(cache.len() <= 2 * (CATALOG_MAX_HEIGHT as usize + 1));
            let mut over = root;
            over.byte_len = CATALOG_MAX_STREAM_BYTES + 1;
            assert!(over.validate().is_err());
        }
    }

    #[test]
    fn catalog_guild_sections_do_not_require_an_invented_dataset_owner() {
        let guild = CatalogScope::Guild { guild_id: [1; 32] };
        for section in [CatalogSection::Packing, CatalogSection::Coding] {
            let mut builder = CatalogBuilder::new(guild, section).unwrap();
            assert!(CatalogBuilder::new(scope(), section).is_err());
            let mut encoded = Vec::new();
            let mut sink = |_: CatalogPageRef, bytes: Vec<u8>| {
                encoded = bytes;
                Ok::<_, &'static str>(())
            };
            builder.push(&[1, 2, 3], &mut sink).unwrap();
            let root = builder.finish(&mut sink).unwrap();
            verify_page(root, guild, section, &encoded).unwrap();
            assert!(CatalogReader::new(scope(), section, root).is_err());
            assert!(
                verify_page(
                    root,
                    CatalogScope::Guild { guild_id: [4; 32] },
                    section,
                    &encoded
                )
                .is_err()
            );
        }
        for section in [
            CatalogSection::GitGraph,
            CatalogSection::FileMetadata,
            CatalogSection::SectorReferences,
        ] {
            assert!(CatalogBuilder::new(guild, section).is_err());
        }
        assert!(
            CatalogBuilder::new(
                CatalogScope::Dataset {
                    guild_id: [1; 32],
                    owner: NodeId([2; 32]),
                    protected_root_id: Uuid::nil(),
                },
                CatalogSection::GitGraph
            )
            .is_err()
        );
    }
}
