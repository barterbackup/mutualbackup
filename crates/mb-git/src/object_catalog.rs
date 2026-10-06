//! Streaming metadata objects for the paged Git graph migration. This object
//! stream does not establish ref reachability, blob availability or DAG validity.

use std::io::Read;

use mb_core::{
    CATALOG_MAX_STREAM_BYTES, CatalogError, CatalogPageRef, CatalogRecordBuilder,
    CatalogRecordReader, CatalogRecordRoot, CatalogScope, CatalogSection, CatalogStreamError,
    canonical_bytes, decode_canonical,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha1::{Digest, Sha1};

pub const GIT_OBJECT_FRAGMENT_BYTES: usize = 32 * 1024;
const MAX_ENCODED_RECORD: usize = GIT_OBJECT_FRAGMENT_BYTES + 32;

/// Discriminants are append-only within version one. Blobs stay in native
/// source anchors; only commit (1), tree (2), and tag (3) objects belong here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GitObjectRecord {
    Header {
        format_version: u16,
        oid: [u8; 20],
        kind: u8,
        byte_len: u64,
    },
    Fragment {
        offset: u64,
        #[serde(deserialize_with = "decode_fragment")]
        bytes: Vec<u8>,
    },
}

fn decode_fragment<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    struct Fragment;
    impl<'de> Visitor<'de> for Fragment {
        type Value = Vec<u8>;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(
                formatter,
                "at most {GIT_OBJECT_FRAGMENT_BYTES} object bytes"
            )
        }

        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence
                .size_hint()
                .is_some_and(|size| size > GIT_OBJECT_FRAGMENT_BYTES)
            {
                return Err(serde::de::Error::custom("oversized Git object fragment"));
            }
            let mut bytes = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(GIT_OBJECT_FRAGMENT_BYTES),
            );
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == GIT_OBJECT_FRAGMENT_BYTES {
                    return Err(serde::de::Error::custom("oversized Git object fragment"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    decoder.deserialize_seq(Fragment)
}

impl GitObjectRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > MAX_ENCODED_RECORD {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        match &record {
            Self::Header {
                format_version,
                kind,
                byte_len,
                ..
            } if *format_version != 1
                || !matches!(kind, 1..=3)
                || *byte_len > CATALOG_MAX_STREAM_BYTES =>
            {
                return Err(CatalogError::InvalidPage);
            }
            Self::Fragment { bytes, .. } if bytes.is_empty() => {
                return Err(CatalogError::InvalidPage);
            }
            _ => {}
        }
        if canonical_bytes(&record)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

/// Authenticate this complete summary inside the owner-encrypted Git root.
/// Counts and bytes do not replace the shared dataset/history admission policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitObjectCatalogRoot {
    pub format_version: u16,
    pub records: CatalogRecordRoot,
    pub objects: u64,
    pub object_bytes: u64,
}

impl GitObjectCatalogRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        if self.format_version != 1
            || self.objects > self.records.records
            || self.object_bytes > CATALOG_MAX_STREAM_BYTES
            || self.object_bytes > self.records.page.byte_len
            || self.objects == 0 && (self.records.records != 0 || self.object_bytes != 0)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

struct ActiveObject {
    oid: [u8; 20],
    byte_len: u64,
    consumed: u64,
    hash: Sha1,
}

#[derive(Default)]
struct ObjectState {
    active: Option<ActiveObject>,
    previous: Option<[u8; 20]>,
    objects: u64,
    object_bytes: u64,
}

impl ObjectState {
    fn accept(&mut self, record: &GitObjectRecord) -> Result<(), CatalogError> {
        match record {
            GitObjectRecord::Header {
                format_version,
                oid,
                kind,
                byte_len,
            } => {
                if *format_version != 1
                    || self.active.is_some()
                    || self.previous.is_some_and(|previous| previous >= *oid)
                    || *byte_len > CATALOG_MAX_STREAM_BYTES
                {
                    return Err(CatalogError::InvalidPage);
                }
                let name = match kind {
                    1 => "commit",
                    2 => "tree",
                    3 => "tag",
                    _ => return Err(CatalogError::InvalidPage),
                };
                let mut hash = Sha1::new();
                hash.update(format!("{name} {byte_len}\0").as_bytes());
                self.object_bytes = self
                    .object_bytes
                    .checked_add(*byte_len)
                    .filter(|total| *total <= CATALOG_MAX_STREAM_BYTES)
                    .ok_or(CatalogError::Bounds)?;
                self.objects += 1;
                self.previous = Some(*oid);
                self.active = Some(ActiveObject {
                    oid: *oid,
                    byte_len: *byte_len,
                    consumed: 0,
                    hash,
                });
            }
            GitObjectRecord::Fragment { offset, bytes } => {
                let active = self.active.as_mut().ok_or(CatalogError::InvalidPage)?;
                let expected = (active.byte_len - active.consumed)
                    .min(GIT_OBJECT_FRAGMENT_BYTES as u64) as usize;
                if *offset != active.consumed || bytes.len() != expected || bytes.is_empty() {
                    return Err(CatalogError::InvalidPage);
                }
                active.hash.update(bytes);
                active.consumed += bytes.len() as u64;
            }
        }
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.consumed == active.byte_len)
        {
            let active = self.active.take().expect("completed object exists");
            if <[u8; 20]>::from(active.hash.finalize()) != active.oid {
                return Err(CatalogError::InvalidPage);
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), CatalogError> {
        if self.active.is_some() {
            Err(CatalogError::InvalidPage)
        } else {
            Ok(())
        }
    }
}

/// Stream one isolated object at a time in increasing OID order. The input
/// must contain exactly its declared bytes. Failed hashing, input or page
/// storage fences publication, including pages already staged by the sink.
pub struct GitObjectCatalogBuilder {
    records: CatalogRecordBuilder,
    state: ObjectState,
    failed: bool,
}

impl GitObjectCatalogBuilder {
    pub fn new(scope: CatalogScope) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::GitGraph)?,
            state: ObjectState::default(),
            failed: false,
        })
    }

    pub fn push_object<E>(
        &mut self,
        oid: [u8; 20],
        kind: u8,
        byte_len: u64,
        input: &mut impl Read,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.push_inner(oid, kind, byte_len, input, sink);
        self.failed = result.is_err();
        result
    }

    fn push_inner<E>(
        &mut self,
        oid: [u8; 20],
        kind: u8,
        byte_len: u64,
        input: &mut impl Read,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        let header = GitObjectRecord::Header {
            format_version: 1,
            oid,
            kind,
            byte_len,
        };
        self.state.accept(&header)?;
        self.records.push(&header, sink)?;
        let mut offset = 0;
        let mut bytes = vec![0; GIT_OBJECT_FRAGMENT_BYTES];
        while offset < byte_len {
            let length = (byte_len - offset).min(GIT_OBJECT_FRAGMENT_BYTES as u64) as usize;
            bytes.resize(length, 0);
            input
                .read_exact(&mut bytes)
                .map_err(|_| CatalogError::InvalidPage)?;
            let fragment = GitObjectRecord::Fragment { offset, bytes };
            self.state.accept(&fragment)?;
            self.records.push(&fragment, sink)?;
            let GitObjectRecord::Fragment {
                bytes: returned, ..
            } = fragment
            else {
                unreachable!()
            };
            bytes = returned;
            offset += length as u64;
        }
        let mut trailing = [0];
        loop {
            match input.read(&mut trailing) {
                Ok(0) => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                _ => return Err(CatalogError::InvalidPage.into()),
            }
        }
        Ok(())
    }

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<GitObjectCatalogRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.state.finish()?;
        let root = GitObjectCatalogRoot {
            format_version: 1,
            records: self.records.finish(sink)?,
            objects: self.state.objects,
            object_bytes: self.state.object_bytes,
        };
        root.validate()?;
        Ok(root)
    }
}

/// Yields bounded records without reassembling an object. A consumer may stage
/// object fragments but must not activate them before full verified EOF. Git
/// import must also retain libgit2's object parsing/collision checks and perform
/// complete ref/blob/reachability validation before activating the graph.
pub struct GitObjectCatalogReader {
    records: CatalogRecordReader,
    root: GitObjectCatalogRoot,
    state: ObjectState,
    consumed: u64,
    failed: bool,
}

impl GitObjectCatalogReader {
    pub fn new(scope: CatalogScope, root: GitObjectCatalogRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::GitGraph, root.records)?,
            root,
            state: ObjectState::default(),
            consumed: 0,
            failed: false,
        })
    }

    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<GitObjectRecord>, CatalogStreamError<E>> {
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
    ) -> Result<Option<GitObjectRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            self.verify_totals()?;
            return Ok(None);
        };
        let record = GitObjectRecord::decode(&bytes)?;
        self.state.accept(&record)?;
        self.consumed += 1;
        if self.state.objects > self.root.objects
            || self.state.object_bytes > self.root.object_bytes
        {
            return Err(CatalogError::InvalidPage.into());
        }
        if self.consumed == self.root.records.records {
            self.verify_totals()?;
        }
        Ok(Some(record))
    }

    fn verify_totals(&self) -> Result<(), CatalogError> {
        self.state.finish()?;
        if self.state.objects != self.root.objects
            || self.state.object_bytes != self.root.object_bytes
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{Cursor, Write};

    use super::*;
    use git2::{ObjectType, Oid, Repository};
    use mb_core::{NodeId, V1_MAX_CATALOG_BYTES};
    use uuid::Uuid;

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn oid(kind: u8, bytes: &[u8]) -> [u8; 20] {
        let kind = match kind {
            1 => ObjectType::Commit,
            2 => ObjectType::Tree,
            3 => ObjectType::Tag,
            _ => panic!("test kind"),
        };
        Oid::hash_object(kind, bytes)
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn header(kind: u8, bytes: &[u8]) -> GitObjectRecord {
        GitObjectRecord::Header {
            format_version: 1,
            oid: oid(kind, bytes),
            kind,
            byte_len: bytes.len() as u64,
        }
    }

    fn raw(
        records: &[GitObjectRecord],
        objects: u64,
        object_bytes: u64,
    ) -> (GitObjectCatalogRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes: Vec<u8>| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        let root = GitObjectCatalogRoot {
            format_version: 1,
            records: builder.finish(&mut sink).unwrap(),
            objects,
            object_bytes,
        };
        (root, pages)
    }

    fn rejects(records: &[GitObjectRecord], objects: u64, object_bytes: u64) {
        let (root, pages) = raw(records, objects, object_bytes);
        let Ok(mut reader) = GitObjectCatalogReader::new(scope(), root) else {
            return; // A malformed root must also reject before any fetch.
        };
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        loop {
            match reader.next_record(&mut fetch) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("accepted invalid complete catalog"),
                Err(_) => break,
            }
        }
        assert!(reader.next_record(&mut fetch).is_err());
    }

    #[test]
    fn git_object_catalog_streams_fragments_and_matches_libgit2_for_every_kind() {
        let mut objects = vec![
            (1, vec![b'c'; GIT_OBJECT_FRAGMENT_BYTES * 2 + 7]),
            (2, Vec::new()),
            (3, vec![b't'; GIT_OBJECT_FRAGMENT_BYTES]),
        ];
        objects.sort_by_key(|(kind, bytes)| oid(*kind, bytes));
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = GitObjectCatalogBuilder::new(scope()).unwrap();
        for (kind, bytes) in &objects {
            builder
                .push_object(
                    oid(*kind, bytes),
                    *kind,
                    bytes.len() as u64,
                    &mut bytes.as_slice(),
                    &mut sink,
                )
                .unwrap();
        }
        let root = builder.finish(&mut sink).unwrap();
        assert_eq!(root.objects, 3);
        assert!(root.records.page.height > 0);
        let mut reader = GitObjectCatalogReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        for (kind, bytes) in objects {
            assert_eq!(
                reader.next_record(&mut fetch).unwrap().unwrap(),
                header(kind, &bytes)
            );
            for (index, chunk) in bytes.chunks(GIT_OBJECT_FRAGMENT_BYTES).enumerate() {
                assert_eq!(
                    reader.next_record(&mut fetch).unwrap().unwrap(),
                    GitObjectRecord::Fragment {
                        offset: (index * GIT_OBJECT_FRAGMENT_BYTES) as u64,
                        bytes: chunk.to_vec()
                    }
                );
            }
            assert!(reader.state.active.is_none());
        }
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
        assert!(reader.next_record(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn git_object_catalog_handles_an_object_above_the_old_descriptor_limit() {
        // Generate a large tag without allocating its entire payload. Libgit2
        // independently computes the expected OID through its native stream.
        const TAG_HEADER: &[u8] = b"object 1111111111111111111111111111111111111111\ntype commit\ntag large\ntagger Example <example@example.test> 1 +0000\n\n";
        let body_len = V1_MAX_CATALOG_BYTES as u64 + 1;
        let byte_len = TAG_HEADER.len() as u64 + body_len;
        let input = || Cursor::new(TAG_HEADER).chain(std::io::repeat(b'x').take(body_len));
        let directory = tempfile::tempdir().unwrap();
        let repository = Repository::init_bare(directory.path()).unwrap();
        let odb = repository.odb().unwrap();
        let mut writer = odb.writer(byte_len as usize, ObjectType::Tag).unwrap();
        std::io::copy(&mut input(), &mut writer).unwrap();
        let expected: [u8; 20] = writer.finalize().unwrap().as_bytes().try_into().unwrap();
        drop(writer);
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes: Vec<u8>| {
            assert!(bytes.len() <= mb_core::CATALOG_PAGE_BYTES);
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = GitObjectCatalogBuilder::new(scope()).unwrap();
        builder
            .push_object(expected, 3, byte_len, &mut input(), &mut sink)
            .unwrap();
        let root = builder.finish(&mut sink).unwrap();
        assert_eq!(root.object_bytes, byte_len);
        assert_eq!(root.objects, 1);
        let mut reader = GitObjectCatalogReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert_eq!(
            reader.next_record(&mut fetch).unwrap().unwrap(),
            GitObjectRecord::Header {
                format_version: 1,
                oid: expected,
                kind: 3,
                byte_len
            }
        );
        let mut regenerated = odb.writer(byte_len as usize, ObjectType::Tag).unwrap();
        let mut consumed = 0;
        while let Some(record) = reader.next_record(&mut fetch).unwrap() {
            let GitObjectRecord::Fragment { offset, bytes } = record else {
                panic!("expected fragment")
            };
            assert_eq!(offset, consumed);
            assert!(bytes.len() <= GIT_OBJECT_FRAGMENT_BYTES);
            regenerated.write_all(&bytes).unwrap();
            consumed += bytes.len() as u64;
        }
        assert_eq!(consumed, byte_len);
        assert_eq!(regenerated.finalize().unwrap().as_bytes(), expected);
        // This codec-only fixture is not a complete above-limit graph backup.
    }

    #[test]
    fn git_object_catalog_rejects_corruption_offsets_lengths_and_incomplete_objects() {
        let bytes = vec![b'x'; GIT_OBJECT_FRAGMENT_BYTES + 3];
        let first = GitObjectRecord::Fragment {
            offset: 0,
            bytes: bytes[..GIT_OBJECT_FRAGMENT_BYTES].to_vec(),
        };
        let last = GitObjectRecord::Fragment {
            offset: GIT_OBJECT_FRAGMENT_BYTES as u64,
            bytes: bytes[GIT_OBJECT_FRAGMENT_BYTES..].to_vec(),
        };
        rejects(&[header(2, &bytes), first.clone()], 1, bytes.len() as u64);
        rejects(std::slice::from_ref(&first), 1, bytes.len() as u64);
        rejects(
            &[header(2, &bytes), header(2, &bytes)],
            2,
            2 * bytes.len() as u64,
        );
        rejects(
            &[
                header(2, &bytes),
                GitObjectRecord::Fragment {
                    offset: 0,
                    bytes: vec![b'x'; GIT_OBJECT_FRAGMENT_BYTES - 1],
                },
            ],
            1,
            bytes.len() as u64,
        );
        rejects(
            &[
                header(2, &bytes),
                first.clone(),
                GitObjectRecord::Fragment {
                    offset: 1,
                    bytes: vec![b'x'; 3],
                },
            ],
            1,
            bytes.len() as u64,
        );
        rejects(
            &[
                header(2, &bytes),
                first.clone(),
                GitObjectRecord::Fragment {
                    offset: GIT_OBJECT_FRAGMENT_BYTES as u64,
                    bytes: vec![b'y'; 3],
                },
            ],
            1,
            bytes.len() as u64,
        );
        let mut wrong_oid = header(2, &bytes);
        if let GitObjectRecord::Header { oid, .. } = &mut wrong_oid {
            *oid = [0; 20];
        }
        rejects(&[wrong_oid, first, last.clone()], 1, bytes.len() as u64);
        rejects(&[header(2, &[]), last], 1, 0);
    }

    #[test]
    fn git_object_catalog_checks_order_schema_version_and_final_summary() {
        let a = b"a";
        let b = b"b";
        let mut objects = [a.as_slice(), b.as_slice()];
        objects.sort_by_key(|bytes| oid(1, bytes));
        let one = |bytes: &[u8]| {
            [
                header(1, bytes),
                GitObjectRecord::Fragment {
                    offset: 0,
                    bytes: bytes.to_vec(),
                },
            ]
        };
        let mut duplicated = one(objects[0]).to_vec();
        duplicated.extend(one(objects[0]));
        rejects(&duplicated, 2, 2);
        let mut reversed = one(objects[1]).to_vec();
        reversed.extend(one(objects[0]));
        rejects(&reversed, 2, 2);
        for kind in [0, 4] {
            rejects(
                &[GitObjectRecord::Header {
                    format_version: 1,
                    oid: [0; 20],
                    kind,
                    byte_len: 1,
                }],
                1,
                1,
            );
        }
        rejects(
            &[GitObjectRecord::Header {
                format_version: 2,
                oid: oid(2, &[]),
                kind: 2,
                byte_len: 0,
            }],
            1,
            0,
        );
        let bytes = b"abc";
        for total in [2, 4] {
            rejects(&one(bytes), 1, total);
        }
        rejects(&one(bytes), 2, bytes.len() as u64);
        let (root, _) = raw(&[], 0, 0);
        assert!(
            GitObjectCatalogRoot {
                format_version: 2,
                ..root
            }
            .validate()
            .is_err()
        );
        assert!(
            GitObjectCatalogRoot { objects: 1, ..root }
                .validate()
                .is_err()
        );
        assert!(
            GitObjectCatalogRoot {
                object_bytes: 1,
                ..root
            }
            .validate()
            .is_err()
        );
        assert!(
            GitObjectCatalogReader::new(CatalogScope::Guild { guild_id: [1; 32] }, root).is_err()
        );
    }

    #[test]
    fn git_object_catalog_input_storage_and_fetch_failures_fence_publication() {
        let bytes = vec![1; GIT_OBJECT_FRAGMENT_BYTES * 3];
        for input in [
            bytes[..bytes.len() - 1].to_vec(),
            {
                let mut extra = bytes.clone();
                extra.push(2);
                extra
            },
            {
                let mut corrupt = bytes.clone();
                corrupt[0] = 2;
                corrupt
            },
        ] {
            let mut builder = GitObjectCatalogBuilder::new(scope()).unwrap();
            let mut sink = |_, _| Ok::<_, &'static str>(());
            assert!(
                builder
                    .push_object(
                        oid(1, &bytes),
                        1,
                        bytes.len() as u64,
                        &mut input.as_slice(),
                        &mut sink
                    )
                    .is_err()
            );
            assert!(
                builder
                    .push_object(oid(2, &[]), 2, 0, &mut &[][..], &mut sink)
                    .is_err()
            );
            assert!(builder.finish(&mut sink).is_err());
        }
        let mut builder = GitObjectCatalogBuilder::new(scope()).unwrap();
        let mut sink = |_, _| Err::<(), _>("offline");
        assert!(
            builder
                .push_object(
                    oid(1, &bytes),
                    1,
                    bytes.len() as u64,
                    &mut bytes.as_slice(),
                    &mut sink
                )
                .is_err()
        );
        assert!(builder.finish(&mut sink).is_err());
        let (root, pages) = raw(&[header(2, &[])], 1, 0);
        let mut reader = GitObjectCatalogReader::new(scope(), root).unwrap();
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
    }

    #[test]
    fn git_object_catalog_decoder_bounds_collection_declarations_before_allocation() {
        let mut oversized = vec![1, 0]; // Fragment discriminant, offset zero.
        // u32::MAX declared collection length, no payload.
        oversized.extend([0xff, 0xff, 0xff, 0xff, 0x0f]);
        assert!(GitObjectRecord::decode(&oversized).is_err());
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
                panic!("oversized declaration must reject before reading or allocating elements")
            }
        }
        let error =
            decode_fragment(serde::de::value::SeqAccessDeserializer::new(Declared)).unwrap_err();
        assert!(error.to_string().contains("oversized Git object fragment"));
        let mut state = ObjectState::default();
        state.accept(&header(2, &[])).unwrap();
        state.finish().unwrap();
        let encoded = canonical_bytes(&header(2, &[])).unwrap();
        let mut noncanonical = vec![0x80, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(GitObjectRecord::decode(&noncanonical).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(GitObjectRecord::decode(&trailing).is_err());
        assert!(GitObjectRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        assert!(GitObjectRecord::decode(&[0; MAX_ENCODED_RECORD + 1]).is_err());
    }
}
