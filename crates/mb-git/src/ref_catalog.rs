//! Bounded Git ref records with component ordering for constant-memory
//! namespace validation. Target reachability belongs to graph validation.

use std::cmp::Ordering;

use mb_core::{
    CatalogError, CatalogPageRef, CatalogRecordBuilder, CatalogRecordReader, CatalogRecordRoot,
    CatalogScope, CatalogSection, CatalogStreamError, canonical_bytes, decode_canonical,
};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

pub const GIT_REF_NAME_BYTES: usize = 8 * 1024;
pub const GIT_HEAD_BRANCH_BYTES: usize = 1024;
const MAX_ENCODED_RECORD: usize = GIT_REF_NAME_BYTES + 32;

pub fn git_ref_name_order(left: &[u8], right: &[u8]) -> Ordering {
    left.split(|byte| *byte == b'/')
        .cmp(right.split(|byte| *byte == b'/'))
}

fn bounded_bytes<'de, D: Deserializer<'de>>(decoder: D, limit: usize) -> Result<Vec<u8>, D::Error> {
    struct Bytes(usize);
    impl<'de> Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(formatter, "at most {} Git name bytes", self.0)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > self.0) {
                return Err(serde::de::Error::custom("oversized Git name"));
            }
            let mut bytes = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.0));
            while let Some(byte) = sequence.next_element()? {
                if bytes.len() == self.0 {
                    return Err(serde::de::Error::custom("oversized Git name"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    decoder.deserialize_seq(Bytes(limit))
}

fn decode_name<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    bounded_bytes(decoder, GIT_REF_NAME_BYTES)
}

fn decode_head<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    bounded_bytes(decoder, GIT_HEAD_BRANCH_BYTES)
}

fn validate_head(branch: &[u8]) -> Result<(), CatalogError> {
    if branch.len() > GIT_HEAD_BRANCH_BYTES
        || !std::str::from_utf8(branch)
            .is_ok_and(|branch| git2::Branch::name_is_valid(branch).is_ok_and(|valid| valid))
    {
        return Err(CatalogError::InvalidPage);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitRefRecord {
    pub format_version: u16,
    #[serde(deserialize_with = "decode_name")]
    pub name: Vec<u8>,
    pub oid: [u8; 20],
}

impl GitRefRecord {
    pub fn validate(&self) -> Result<(), CatalogError> {
        let name = std::str::from_utf8(&self.name).map_err(|_| CatalogError::InvalidPage)?;
        if self.format_version != 1
            || self.name.len() > GIT_REF_NAME_BYTES
            || !name.starts_with("refs/")
            || !git2::Reference::is_valid_name(name)
            || name
                .strip_prefix("refs/heads/")
                .is_some_and(|branch| !git2::Branch::name_is_valid(branch).is_ok_and(|valid| valid))
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
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

/// The enclosing owner-encrypted Git root authenticates every field. None
/// identifies an unborn selected branch; Some must match its exact ref/OID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GitRefCatalogRoot {
    pub format_version: u16,
    pub records: CatalogRecordRoot,
    #[serde(deserialize_with = "decode_head")]
    pub head_branch: Vec<u8>,
    pub selected_head: Option<[u8; 20]>,
}

impl GitRefCatalogRoot {
    pub fn validate(&self) -> Result<(), CatalogError> {
        self.records.validate()?;
        validate_head(&self.head_branch)?;
        if self.format_version != 1 || self.records.records == 0 && self.selected_head.is_some() {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

struct RefState {
    previous: Vec<u8>,
    selected_name: Vec<u8>,
    selected_head: Option<[u8; 20]>,
}

impl RefState {
    fn new(head_branch: &[u8]) -> Result<Self, CatalogError> {
        validate_head(head_branch)?;
        let mut selected_name = b"refs/heads/".to_vec();
        selected_name.extend_from_slice(head_branch);
        Ok(Self {
            previous: Vec::new(),
            selected_name,
            selected_head: None,
        })
    }

    fn accept(&mut self, record: &GitRefRecord) -> Result<(), CatalogError> {
        record.validate()?;
        if !self.previous.is_empty()
            && (git_ref_name_order(&self.previous, &record.name) != Ordering::Less
                || record
                    .name
                    .strip_prefix(self.previous.as_slice())
                    .is_some_and(|suffix| suffix.starts_with(b"/")))
        {
            return Err(CatalogError::InvalidPage);
        }
        if record.name == self.selected_name {
            self.selected_head = Some(record.oid);
        }
        self.previous.clone_from(&record.name);
        Ok(())
    }
}

pub struct GitRefCatalogBuilder {
    records: CatalogRecordBuilder,
    head_branch: Vec<u8>,
    state: RefState,
    failed: bool,
}

impl GitRefCatalogBuilder {
    pub fn new(scope: CatalogScope, head_branch: &[u8]) -> Result<Self, CatalogError> {
        let state = RefState::new(head_branch)?;
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::GitGraph)?,
            head_branch: head_branch.to_vec(),
            state,
            failed: false,
        })
    }

    pub fn push_ref<E>(
        &mut self,
        record: &GitRefRecord,
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
    ) -> Result<GitRefCatalogRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let root = GitRefCatalogRoot {
            format_version: 1,
            records: self.records.finish(sink)?,
            head_branch: self.head_branch,
            selected_head: self.state.selected_head,
        };
        root.validate()?;
        Ok(root)
    }
}

pub struct GitRefCatalogReader {
    records: CatalogRecordReader,
    root: GitRefCatalogRoot,
    state: RefState,
    consumed: u64,
    failed: bool,
}

impl GitRefCatalogReader {
    pub fn new(scope: CatalogScope, root: GitRefCatalogRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::GitGraph, root.records)?,
            state: RefState::new(&root.head_branch)?,
            root,
            consumed: 0,
            failed: false,
        })
    }

    pub fn next_ref<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<GitRefRecord>, CatalogStreamError<E>> {
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
    ) -> Result<Option<GitRefRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            self.verify_head()?;
            return Ok(None);
        };
        let record = GitRefRecord::decode(&bytes)?;
        self.state.accept(&record)?;
        self.consumed += 1;
        if self.consumed == self.root.records.records {
            self.verify_head()?;
        }
        Ok(Some(record))
    }

    fn verify_head(&self) -> Result<(), CatalogError> {
        if self.state.selected_head != self.root.selected_head {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::NodeId;
    use std::collections::HashMap;
    use uuid::Uuid;

    type Pages = HashMap<[u8; 32], Vec<u8>>;
    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }
    fn reference(name: &[u8]) -> GitRefRecord {
        GitRefRecord {
            format_version: 1,
            name: name.to_vec(),
            oid: [4; 20],
        }
    }
    fn raw(
        records: &[GitRefRecord],
        selected_head: Option<[u8; 20]>,
    ) -> (GitRefCatalogRoot, Pages) {
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
            GitRefCatalogRoot {
                format_version: 1,
                records: builder.finish(&mut sink).unwrap(),
                head_branch: b"main".to_vec(),
                selected_head,
            },
            pages,
        )
    }
    fn reject(records: &[GitRefRecord], selected_head: Option<[u8; 20]>) {
        let (root, pages) = raw(records, selected_head);
        let mut reader = GitRefCatalogReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        loop {
            match reader.next_ref(&mut fetch) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("accepted invalid refs"),
                Err(_) => break,
            }
        }
        assert!(reader.next_ref(&mut fetch).is_err());
    }

    #[test]
    fn git_ref_catalog_roundtrips_component_order_and_selected_head_across_pages() {
        let mut records: Vec<_> = (0..2000)
            .map(|index| reference(format!("refs/heads/topic/{index:04}").as_bytes()))
            .collect();
        records.extend([
            reference(b"refs/heads/main"),
            reference(b"refs/heads/topic-other"),
            reference(b"refs/tags/release"),
        ]);
        records.sort_by(|left, right| git_ref_name_order(&left.name, &right.name));
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut builder = GitRefCatalogBuilder::new(scope(), b"main").unwrap();
        for record in &records {
            builder.push_ref(record, &mut sink).unwrap();
        }
        let root = builder.finish(&mut sink).unwrap();
        assert_eq!(root.selected_head, Some([4; 20]));
        assert!(root.records.page.height > 0);
        let mut reader = GitRefCatalogReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        for record in records {
            assert_eq!(reader.next_ref(&mut fetch).unwrap().unwrap(), record);
            assert!(reader.state.previous.len() <= GIT_REF_NAME_BYTES);
        }
        assert!(reader.next_ref(&mut fetch).unwrap().is_none());
        assert!(reader.next_ref(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn git_ref_catalog_namespace_conflicts_cannot_hide_behind_hyphenated_names() {
        let mut records = [
            reference(b"refs/heads/foo"),
            reference(b"refs/heads/foo-bar"),
            reference(b"refs/heads/foo/x"),
        ];
        records.sort_by(|left, right| left.name.cmp(&right.name));
        assert_eq!(records[1].name, b"refs/heads/foo-bar");
        reject(&records, None); // Raw byte order is not canonical component order.
        records.sort_by(|left, right| git_ref_name_order(&left.name, &right.name));
        assert_eq!(records[1].name, b"refs/heads/foo/x");
        reject(&records, None);
        let mut builder = GitRefCatalogBuilder::new(scope(), b"main").unwrap();
        let mut sink = |_, _| Ok::<_, &'static str>(());
        builder.push_ref(&records[0], &mut sink).unwrap();
        assert!(builder.push_ref(&records[1], &mut sink).is_err());
        assert!(
            builder
                .push_ref(&reference(b"refs/tags/later"), &mut sink)
                .is_err()
        );
        assert!(builder.finish(&mut sink).is_err());
        reject(
            &[
                reference(b"refs/tags/release"),
                reference(b"refs/tags/release"),
            ],
            None,
        );
    }

    #[test]
    fn git_ref_catalog_name_and_head_bounds_reject_before_collection_allocation() {
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
                panic!("oversized name must reject before reading elements")
            }
        }
        assert!(decode_name(serde::de::value::SeqAccessDeserializer::new(Declared)).is_err());
        assert!(decode_head(serde::de::value::SeqAccessDeserializer::new(Declared)).is_err());
        for length in [
            GIT_REF_NAME_BYTES - 1,
            GIT_REF_NAME_BYTES,
            GIT_REF_NAME_BYTES + 1,
        ] {
            let mut name = b"refs/tags/".to_vec();
            name.resize(length, b'x');
            let record = reference(&name);
            let encoded = canonical_bytes(&record).unwrap();
            assert_eq!(record.validate().is_ok(), length <= GIT_REF_NAME_BYTES);
            assert_eq!(
                GitRefRecord::decode(&encoded).is_ok(),
                length <= GIT_REF_NAME_BYTES
            );
        }
        assert!(GitRefCatalogBuilder::new(scope(), &[b'x'; GIT_HEAD_BRANCH_BYTES]).is_ok());
        assert!(GitRefCatalogBuilder::new(scope(), &[b'x'; GIT_HEAD_BRANCH_BYTES + 1]).is_err());
        for name in [
            b"HEAD".as_slice(),
            b"refs/heads/HEAD",
            b"refs/heads/a..b",
            b"refs/tags/bad.lock",
            b"refs/heads/a b",
            b"refs/tags/\xff",
        ] {
            assert!(reference(name).validate().is_err());
        }
        let encoded = canonical_bytes(&reference(b"refs/heads/main")).unwrap();
        let mut noncanonical = vec![0x81, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(GitRefRecord::decode(&noncanonical).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(GitRefRecord::decode(&trailing).is_err());
        assert!(GitRefRecord::decode(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn git_ref_catalog_checks_born_and_unborn_head_before_final_ref() {
        reject(&[reference(b"refs/heads/main")], Some([5; 20]));
        reject(&[reference(b"refs/heads/main")], None);
        reject(&[reference(b"refs/tags/release")], Some([4; 20]));
        for records in [Vec::new(), vec![reference(b"refs/tags/release")]] {
            let (root, pages) = raw(&records, None);
            let mut reader = GitRefCatalogReader::new(scope(), root).unwrap();
            let mut fetch =
                |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
            for record in records {
                assert_eq!(reader.next_ref(&mut fetch).unwrap().unwrap(), record);
            }
            assert!(reader.next_ref(&mut fetch).unwrap().is_none());
        }
        let (root, _) = raw(&[], None);
        assert!(
            GitRefCatalogRoot {
                format_version: 2,
                ..root.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            GitRefCatalogRoot {
                selected_head: Some([4; 20]),
                ..root.clone()
            }
            .validate()
            .is_err()
        );
        assert!(GitRefCatalogReader::new(CatalogScope::Guild { guild_id: [1; 32] }, root).is_err());
    }

    #[test]
    fn git_ref_catalog_storage_and_fetch_failures_fence_continuation() {
        let mut builder = GitRefCatalogBuilder::new(scope(), b"main").unwrap();
        let mut sink = |_, _| Err::<(), _>("offline");
        let mut failed = false;
        for index in 0..3000 {
            if builder
                .push_ref(
                    &reference(format!("refs/tags/{index:04}").as_bytes()),
                    &mut sink,
                )
                .is_err()
            {
                failed = true;
                break;
            }
        }
        assert!(failed);
        assert!(builder.finish(&mut sink).is_err());
        let (root, pages) = raw(&[reference(b"refs/heads/main")], Some([4; 20]));
        let mut reader = GitRefCatalogReader::new(scope(), root).unwrap();
        assert!(
            reader
                .next_ref(&mut |_| Err::<Vec<u8>, _>("offline"))
                .is_err()
        );
        assert!(
            reader
                .next_ref(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                    pages[&reference.hash].clone()
                ))
                .is_err()
        );
    }
}
