//! Bounded file namespace and attribute records. File recipes, hard-link joins
//! and platform-specific metadata require separate validation before activation.

use std::cmp::Ordering;

use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    CatalogError, CatalogPageRef, CatalogRecordBuilder, CatalogRecordReader, CatalogRecordRoot,
    CatalogScope, CatalogSection, CatalogStreamError,
};
use crate::decode_canonical;

pub const CATALOG_FILE_PATH_BYTES: usize = 8 * 1024;
pub const CATALOG_FILE_RECORD_BYTES: usize = CATALOG_FILE_PATH_BYTES + 128;

/// Components sort before their descendants and before subsequent siblings.
/// Names are raw bytes; interpretation and platform representability are the
/// responsibility of capture/restore, not a lossy Unicode conversion here.
pub fn catalog_file_path_order(left: &[u8], right: &[u8]) -> Ordering {
    left.split(|byte| *byte == b'/')
        .cmp(right.split(|byte| *byte == b'/'))
}

fn decode_path<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    struct Path;
    impl<'de> Visitor<'de> for Path {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {CATALOG_FILE_PATH_BYTES} path bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence
                .size_hint()
                .is_some_and(|size| size > CATALOG_FILE_PATH_BYTES)
            {
                return Err(serde::de::Error::custom("oversized catalog path"));
            }
            let mut bytes = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(CATALOG_FILE_PATH_BYTES),
            );
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == CATALOG_FILE_PATH_BYTES {
                    return Err(serde::de::Error::custom("oversized catalog path"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    decoder.deserialize_seq(Path)
}

/// The attributes currently carried by native private metadata. This is not
/// an ACL/xattr/Windows stream or complete cross-platform metadata schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogFileStat {
    pub mode: u32,
    pub modified_secs: i64,
    pub modified_nanos: u32,
}

impl CatalogFileStat {
    pub fn validate(self) -> Result<(), CatalogError> {
        if self.modified_nanos >= 1_000_000_000 {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

/// Discriminants are append-only. A file key is its zero-based record ordinal,
/// including directories and aliases. A separate recipe stream binds that key
/// to sparse extents and exact sectors. Link groups retain legacy identities;
/// their primary/alias attributes and recipes must be joined before restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogFileKind {
    Directory,
    File {
        file_key: u64,
        logical_len: u64,
        link_group: Option<u64>,
    },
    HardLink {
        logical_len: u64,
        link_group: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogFileRecord {
    pub format_version: u16,
    #[serde(deserialize_with = "decode_path")]
    pub path: Vec<u8>,
    pub stat: CatalogFileStat,
    pub kind: CatalogFileKind,
}

impl CatalogFileRecord {
    pub fn validate(&self) -> Result<(), CatalogError> {
        self.stat.validate()?;
        if self.format_version != 1
            || self.path.is_empty()
            || self.path.len() > CATALOG_FILE_PATH_BYTES
            || self.path.contains(&0)
            || self
                .path
                .split(|byte| *byte == b'/')
                .any(|component| component.is_empty() || component == b"." || component == b"..")
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_FILE_RECORD_BYTES {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        record.validate()?;
        let mut buffer = [0; CATALOG_FILE_RECORD_BYTES];
        let encoded =
            postcard::to_slice(&record, &mut buffer).map_err(crate::ModelError::Encode)?;
        if encoded != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

/// Authenticate all fields together in the enclosing owner-encrypted root.
/// Byte totals count path occurrences, including hard-link aliases, rather
/// than deduplicated payload, physical quota or retained history capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogFileRoot {
    pub format_version: u16,
    pub records: CatalogRecordRoot,
    pub root_stat: CatalogFileStat,
    pub directories: u64,
    pub files: u64,
    pub hard_links: u64,
    pub file_bytes: u64,
    pub hard_link_bytes: u64,
}

impl CatalogFileRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        self.root_stat.validate()?;
        if self.format_version != 1
            || self
                .directories
                .checked_add(self.files)
                .and_then(|count| count.checked_add(self.hard_links))
                != Some(self.records.records)
            || self.files == 0 && self.file_bytes != 0
            || self.hard_links == 0 && self.hard_link_bytes != 0
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

#[derive(Default)]
struct FileState {
    previous: Vec<u8>,
    directory: Vec<u8>,
    consumed: u64,
    directories: u64,
    files: u64,
    hard_links: u64,
    file_bytes: u64,
    hard_link_bytes: u64,
}

impl FileState {
    fn accept(&mut self, record: &CatalogFileRecord) -> Result<(), CatalogError> {
        record.validate()?;
        if !self.previous.is_empty()
            && catalog_file_path_order(&self.previous, &record.path) != Ordering::Less
        {
            return Err(CatalogError::InvalidPage);
        }
        let parent = record
            .path
            .iter()
            .rposition(|byte| *byte == b'/')
            .map_or(&[][..], |end| &record.path[..end]);
        // In component order a directory subtree is contiguous. Its active
        // ancestors are prefixes of one path, so no dataset-sized set or stack
        // is needed to reject missing directories and children of files.
        if !parent.is_empty()
            && self.directory != parent
            && !(self.directory.starts_with(parent)
                && self.directory.get(parent.len()) == Some(&b'/'))
        {
            return Err(CatalogError::InvalidPage);
        }
        self.directory.truncate(parent.len());
        match record.kind {
            CatalogFileKind::Directory => {
                self.directory.clone_from(&record.path);
                self.directories += 1;
            }
            CatalogFileKind::File {
                file_key,
                logical_len,
                ..
            } => {
                if file_key != self.consumed {
                    return Err(CatalogError::InvalidPage);
                }
                self.files += 1;
                self.file_bytes = self
                    .file_bytes
                    .checked_add(logical_len)
                    .ok_or(CatalogError::Bounds)?;
            }
            CatalogFileKind::HardLink { logical_len, .. } => {
                self.hard_links += 1;
                self.hard_link_bytes = self
                    .hard_link_bytes
                    .checked_add(logical_len)
                    .ok_or(CatalogError::Bounds)?;
            }
        }
        self.consumed += 1;
        self.previous.clone_from(&record.path);
        Ok(())
    }

    fn matches(&self, root: CatalogFileRoot) -> bool {
        self.consumed == root.records.records
            && self.directories == root.directories
            && self.files == root.files
            && self.hard_links == root.hard_links
            && self.file_bytes == root.file_bytes
            && self.hard_link_bytes == root.hard_link_bytes
    }
}

pub struct CatalogFileBuilder {
    records: CatalogRecordBuilder,
    root_stat: CatalogFileStat,
    state: FileState,
    failed: bool,
}

impl CatalogFileBuilder {
    pub fn new(scope: CatalogScope, root_stat: CatalogFileStat) -> Result<Self, CatalogError> {
        root_stat.validate()?;
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::FileMetadata)?,
            root_stat,
            state: FileState::default(),
            failed: false,
        })
    }

    pub fn push<E>(
        &mut self,
        record: &CatalogFileRecord,
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

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogFileRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let root = CatalogFileRoot {
            format_version: 1,
            records: self.records.finish(sink)?,
            root_stat: self.root_stat,
            directories: self.state.directories,
            files: self.state.files,
            hard_links: self.state.hard_links,
            file_bytes: self.state.file_bytes,
            hard_link_bytes: self.state.hard_link_bytes,
        };
        root.validate()?;
        Ok(root)
    }
}

/// Namespace validation retains two bounded paths and one record/page buffer.
/// Reach authenticated EOF and validate recipe/link joins before activation;
/// a successfully read prefix or namespace root alone cannot authorize restore.
pub struct CatalogFileReader {
    records: CatalogRecordReader,
    root: CatalogFileRoot,
    state: FileState,
    failed: bool,
}

impl CatalogFileReader {
    pub fn new(scope: CatalogScope, root: CatalogFileRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::FileMetadata, root.records)?,
            root,
            state: FileState::default(),
            failed: false,
        })
    }

    pub fn next_file<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogFileRecord>, CatalogStreamError<E>> {
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
    ) -> Result<Option<CatalogFileRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            if !self.state.matches(self.root) {
                return Err(CatalogError::InvalidPage.into());
            }
            return Ok(None);
        };
        let record = CatalogFileRecord::decode(&bytes)?;
        self.state.accept(&record)?;
        if self.state.directories > self.root.directories
            || self.state.files > self.root.files
            || self.state.hard_links > self.root.hard_links
            || self.state.file_bytes > self.root.file_bytes
            || self.state.hard_link_bytes > self.root.hard_link_bytes
            || self.state.consumed == self.root.records.records && !self.state.matches(self.root)
        {
            return Err(CatalogError::InvalidPage.into());
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
    const STAT: CatalogFileStat = CatalogFileStat {
        mode: 0o100640,
        modified_secs: -5,
        modified_nanos: 999_999_999,
    };

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn record(path: &[u8], kind: CatalogFileKind) -> CatalogFileRecord {
        CatalogFileRecord {
            format_version: 1,
            path: path.to_vec(),
            stat: STAT,
            kind,
        }
    }

    fn file(path: &[u8], file_key: u64, logical_len: u64) -> CatalogFileRecord {
        record(
            path,
            CatalogFileKind::File {
                file_key,
                logical_len,
                link_group: Some(42),
            },
        )
    }

    fn build(records: &[CatalogFileRecord]) -> (CatalogFileRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogFileBuilder::new(scope(), STAT).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        (builder.finish(&mut sink).unwrap(), pages)
    }

    fn raw(records: &[CatalogFileRecord]) -> (CatalogFileRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::FileMetadata).unwrap();
        let (mut directories, mut files, mut hard_links, mut file_bytes, mut hard_link_bytes) =
            (0, 0, 0, 0, 0);
        for record in records {
            builder.push(record, &mut sink).unwrap();
            match record.kind {
                CatalogFileKind::Directory => directories += 1,
                CatalogFileKind::File { logical_len, .. } => {
                    files += 1;
                    file_bytes += logical_len;
                }
                CatalogFileKind::HardLink { logical_len, .. } => {
                    hard_links += 1;
                    hard_link_bytes += logical_len;
                }
            }
        }
        (
            CatalogFileRoot {
                format_version: 1,
                records: builder.finish(&mut sink).unwrap(),
                root_stat: STAT,
                directories,
                files,
                hard_links,
                file_bytes,
                hard_link_bytes,
            },
            pages,
        )
    }

    fn reject(records: &[CatalogFileRecord]) {
        let mut builder = CatalogFileBuilder::new(scope(), STAT).unwrap();
        let mut sink = |_, _| Ok::<_, &'static str>(());
        assert!(
            records
                .iter()
                .any(|record| builder.push(record, &mut sink).is_err())
        );
        assert!(builder.push(&file(b"z", 100, 0), &mut sink).is_err());
        assert!(builder.finish(&mut sink).is_err());
        let (root, pages) = raw(records);
        let mut reader = CatalogFileReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        loop {
            match reader.next_file(&mut fetch) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("accepted invalid namespace"),
                Err(_) => break,
            }
        }
        assert!(reader.next_file(&mut fetch).is_err());
    }

    #[test]
    fn catalog_file_namespace_roundtrips_attributes_links_and_raw_paths_across_pages() {
        let mut records = vec![record(b"a", CatalogFileKind::Directory)];
        records.push(record(b"a/deep", CatalogFileKind::Directory));
        records.push(file(b"a/deep/item", 2, 1 << 40));
        records.push(record(b"a/empty", CatalogFileKind::Directory));
        for index in 0..3000 {
            records.push(file(
                format!("a/file{index:04}").as_bytes(),
                records.len() as u64,
                7,
            ));
        }
        records.push(record(
            b"a/link",
            CatalogFileKind::HardLink {
                logical_len: 1 << 40,
                link_group: 42,
            },
        ));
        records.push(file(b"a/\xff", records.len() as u64, 0));
        records.push(record(b"a-other", CatalogFileKind::Directory));
        records.push(file(b"a-other/item", records.len() as u64, 1));
        records.push(file(b"z", records.len() as u64, 0));
        let (root, pages) = build(&records);
        assert!(root.records.page.height > 0);
        assert_eq!(root.root_stat, STAT);
        assert_eq!(root.directories, 4);
        assert_eq!(root.hard_links, 1);
        assert_eq!(root.file_bytes, (1 << 40) + 3000 * 7 + 1);
        assert_eq!(root.hard_link_bytes, 1 << 40);
        let mut reader = CatalogFileReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        for record in records {
            assert_eq!(reader.next_file(&mut fetch).unwrap().unwrap(), record);
            assert!(reader.state.previous.len() <= CATALOG_FILE_PATH_BYTES);
            assert!(reader.state.directory.len() <= CATALOG_FILE_PATH_BYTES);
        }
        assert!(reader.next_file(&mut fetch).unwrap().is_none());
        assert!(reader.next_file(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn catalog_file_namespace_rejects_missing_parents_file_children_duplicates_and_order() {
        reject(&[file(b"missing/child", 0, 0)]);
        reject(&[file(b"a", 0, 0), file(b"a/child", 1, 0)]);
        reject(&[
            record(b"a", CatalogFileKind::Directory),
            file(b"a/missing/child", 1, 0),
        ]);
        reject(&[
            record(b"a", CatalogFileKind::Directory),
            record(b"a", CatalogFileKind::Directory),
        ]);
        reject(&[file(b"z", 0, 0), file(b"a", 1, 0)]);
        reject(&[
            record(b"a", CatalogFileKind::Directory),
            file(b"a-other", 1, 0),
            file(b"a/child", 2, 0),
        ]);
        reject(&[file(b"a", 1, 0)]);
        reject(&[
            record(
                b"a",
                CatalogFileKind::HardLink {
                    logical_len: 0,
                    link_group: 0,
                },
            ),
            file(b"a/child", 1, 0),
        ]);
        // Backtracking from a nested directory to its declared ancestor is valid.
        build(&[
            record(b"a", CatalogFileKind::Directory),
            record(b"a/b", CatalogFileKind::Directory),
            record(b"a/b/c", CatalogFileKind::Directory),
            file(b"a/b/c/x", 3, 0),
            file(b"a/b/y", 4, 0),
            file(b"a/z", 5, 0),
            file(b"root", 6, 0),
        ]);
    }

    #[test]
    fn catalog_file_decoder_bounds_paths_and_rejects_invalid_schema_before_allocation() {
        for path in [
            b"".as_slice(),
            b"/a",
            b"a/",
            b"a//b",
            b".",
            b"..",
            b"a/../b",
            b"a/./b",
            b"a\0b",
        ] {
            let record = file(path, 0, 0);
            assert!(record.validate().is_err());
            assert!(CatalogFileRecord::decode(&canonical_bytes(&record).unwrap()).is_err());
        }
        let largest = file(&vec![b'a'; CATALOG_FILE_PATH_BYTES], 0, u64::MAX);
        let encoded = canonical_bytes(&largest).unwrap();
        assert!(encoded.len() <= CATALOG_FILE_RECORD_BYTES);
        assert_eq!(CatalogFileRecord::decode(&encoded).unwrap(), largest);
        let too_large = file(&vec![b'a'; CATALOG_FILE_PATH_BYTES + 1], 0, 0);
        assert!(CatalogFileRecord::decode(&canonical_bytes(&too_large).unwrap()).is_err());
        let mut declaration = canonical_bytes(&1_u16).unwrap();
        declaration.extend_from_slice(&canonical_bytes(&usize::MAX).unwrap());
        assert!(CatalogFileRecord::decode(&declaration).is_err());
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
                panic!("oversized path must reject before reading elements")
            }
        }
        assert!(decode_path(serde::de::value::SeqAccessDeserializer::new(Declared)).is_err());
        for nanos in [1_000_000_000, u32::MAX] {
            let mut changed = file(b"valid", 0, 0);
            changed.stat.modified_nanos = nanos;
            assert!(CatalogFileRecord::decode(&canonical_bytes(&changed).unwrap()).is_err());
        }
        let mut changed = file(b"valid", 0, 0);
        changed.format_version = 2;
        assert!(CatalogFileRecord::decode(&canonical_bytes(&changed).unwrap()).is_err());
        let encoded = canonical_bytes(&file(b"valid", 0, 0)).unwrap();
        assert!(CatalogFileRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(CatalogFileRecord::decode(&trailing).is_err());
        let mut noncanonical = vec![0x81, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(CatalogFileRecord::decode(&noncanonical).is_err());
        assert!(CatalogFileRecord::decode(&[0; CATALOG_FILE_RECORD_BYTES + 1]).is_err());
    }

    #[test]
    fn catalog_file_namespace_matches_declared_parent_validation_for_nested_layouts() {
        // Independently compare the bounded path state to a complete directory
        // set over every absent/directory/file assignment of these nested names.
        let mut paths = [
            b"a".as_slice(),
            b"a/b",
            b"a/b/c",
            b"a/b/c/d",
            b"a/b-other",
            b"a/c",
            b"a-other",
            b"a-other/b",
            b"z",
        ];
        paths.sort_by(|left, right| catalog_file_path_order(left, right));
        for assignment in 0..3_u32.pow(paths.len() as u32) {
            let mut choices = assignment;
            let mut declared = std::collections::BTreeSet::new();
            let mut state = FileState::default();
            let mut expected_valid = true;
            let mut actual_valid = true;
            let mut ordinal = 0;
            for path in paths {
                let choice = choices % 3;
                choices /= 3;
                if choice == 0 {
                    continue;
                }
                let parent = path
                    .iter()
                    .rposition(|byte| *byte == b'/')
                    .map_or(&[][..], |end| &path[..end]);
                if !parent.is_empty() && !declared.contains(parent) {
                    expected_valid = false;
                }
                let kind = if choice == 1 {
                    declared.insert(path);
                    CatalogFileKind::Directory
                } else {
                    CatalogFileKind::File {
                        file_key: ordinal,
                        logical_len: 0,
                        link_group: None,
                    }
                };
                if actual_valid && state.accept(&record(path, kind)).is_err() {
                    actual_valid = false;
                }
                ordinal += 1;
            }
            assert_eq!(actual_valid, expected_valid, "assignment {assignment}");
        }
    }

    #[test]
    fn catalog_file_final_summary_and_empty_root_are_verified_before_activation() {
        let (root, pages) = build(&[file(b"a", 0, 9)]);
        for changed in [
            CatalogFileRoot {
                file_bytes: 8,
                ..root
            },
            CatalogFileRoot {
                file_bytes: 10,
                ..root
            },
            CatalogFileRoot {
                files: 0,
                hard_links: 1,
                file_bytes: 0,
                hard_link_bytes: 9,
                ..root
            },
        ] {
            let mut reader = CatalogFileReader::new(scope(), changed).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            assert!(reader.next_file(&mut fetch).is_err());
            assert!(reader.next_file(&mut fetch).is_err());
        }
        let (empty, pages) = build(&[]);
        let mut reader = CatalogFileReader::new(scope(), empty).unwrap();
        assert!(
            reader
                .next_file(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                    pages[&reference.hash].clone()
                ))
                .unwrap()
                .is_none()
        );
        for changed in [
            CatalogFileRoot { files: 1, ..empty },
            CatalogFileRoot {
                file_bytes: 1,
                ..empty
            },
            CatalogFileRoot {
                hard_link_bytes: 1,
                ..empty
            },
            CatalogFileRoot {
                directories: u64::MAX,
                files: 1,
                ..empty
            },
            CatalogFileRoot {
                format_version: 2,
                ..empty
            },
        ] {
            assert!(changed.validate().is_err());
        }
        assert!(CatalogFileReader::new(CatalogScope::Guild { guild_id: [1; 32] }, root).is_err());
        assert!(
            CatalogFileBuilder::new(
                scope(),
                CatalogFileStat {
                    modified_nanos: 1_000_000_000,
                    ..STAT
                }
            )
            .is_err()
        );
    }

    #[test]
    fn catalog_file_byte_overflow_and_storage_fetch_failures_fence_continuation() {
        let mut sink = |_, _| Ok::<_, &'static str>(());
        let mut builder = CatalogFileBuilder::new(scope(), STAT).unwrap();
        builder.push(&file(b"a", 0, u64::MAX), &mut sink).unwrap();
        assert!(builder.push(&file(b"b", 1, 1), &mut sink).is_err());
        assert!(builder.finish(&mut sink).is_err());
        let mut builder = CatalogFileBuilder::new(scope(), STAT).unwrap();
        for (path, len) in [(b"a", u64::MAX), (b"b", 1)] {
            let result = builder.push(
                &record(
                    path,
                    CatalogFileKind::HardLink {
                        logical_len: len,
                        link_group: 42,
                    },
                ),
                &mut sink,
            );
            assert_eq!(result.is_err(), len == 1);
        }
        assert!(builder.finish(&mut sink).is_err());
        let mut builder = CatalogFileBuilder::new(scope(), STAT).unwrap();
        let mut offline = |_, _| Err::<(), _>("offline");
        let mut failed = false;
        for index in 0..3000 {
            if builder
                .push(
                    &file(format!("file{index:04}").as_bytes(), index, 0),
                    &mut offline,
                )
                .is_err()
            {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(builder.finish(&mut offline).is_err());
        let (root, pages) = build(&[file(b"a", 0, 0)]);
        let mut reader = CatalogFileReader::new(scope(), root).unwrap();
        assert!(
            reader
                .next_file(&mut |_| Err::<Vec<u8>, _>("offline"))
                .is_err()
        );
        assert!(
            reader
                .next_file(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                    pages[&reference.hash].clone()
                ))
                .is_err()
        );
    }
}
