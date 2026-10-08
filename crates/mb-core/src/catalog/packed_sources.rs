//! Complete, ordered source authentication for paged packing. The enclosing
//! checkpoint still must authenticate source authority and join every proof
//! with exactly one descriptor slot before claiming protection.

use serde::de::DeserializeSeed;
use serde::{Deserialize, Deserializer, Serialize};

use super::{
    CatalogError, CatalogPageRef, CatalogRecordBuilder, CatalogRecordReader, CatalogRecordRoot,
    CatalogScope, CatalogSection, CatalogStreamError,
};
use crate::{
    MERKLE_LEAF_SIZE, MERKLE_SUITE_V1, MerkleCommitment, MerkleSubtreeProof, NodeId, SourceChunkId,
    canonical_bytes_bounded, decode_canonical, merkle_verify_subtree,
};

pub const CATALOG_PACKED_SOURCE_PROOFS: usize = 64;
// Maximum profile: 4 MiB / 16-byte leaves = 18 sibling levels. Each proof
// carries one subtree root, one bounded sibling count and at most 18 siblings.
pub const CATALOG_PACKED_SOURCE_RECORD_BYTES: usize =
    CATALOG_PACKED_SOURCE_PROOFS * (32 + 1 + 18 * 32) + 256;
pub const CATALOG_PACKED_SOURCE_ROOT_BYTES: usize = 512;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct CatalogPackedSourceId {
    pub owner: NodeId,
    pub protected_root: [u8; 32],
    pub object_id: [u8; 32],
}

impl CatalogPackedSourceId {
    /// Stable across insertion/removal of other sources. Compact descriptors
    /// resolve this key against the authenticated source-proof stream.
    pub fn key(self) -> [u8; 32] {
        let mut hash = blake3::Hasher::new_derive_key("mutualbackup packed source identity v1");
        hash.update(&self.owner.0);
        hash.update(&self.protected_root);
        hash.update(&self.object_id);
        *hash.finalize().as_bytes()
    }

    pub fn chunk(self, chunk_index: u32) -> SourceChunkId {
        SourceChunkId {
            owner: self.owner,
            protected_root: self.protected_root,
            object_id: self.object_id,
            chunk_index,
        }
    }

    /// Validate a decoded identity before using it as an authenticated lookup key.
    /// This checks its shape; enclosing signed source authority is still required.
    pub fn validate(self) -> Result<(), CatalogError> {
        if self.owner == NodeId([0; 32])
            || self.protected_root == [0; 32]
            || self.object_id == [0; 32]
        {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

/// Version and geometry come from the record/root. Chunk indices, start leaves
/// and leaf counts are implicit in the exact fragment position and profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackedSourceProof {
    pub subtree_root: [u8; 32],
    #[serde(deserialize_with = "crate::range::decode_siblings")]
    pub siblings: Vec<[u8; 32]>,
}

impl CatalogPackedSourceProof {
    pub fn opening(
        &self,
        chunk_index: u32,
        slot_size: u32,
    ) -> Result<MerkleSubtreeProof, CatalogError> {
        let leaf_count = slot_size / MERKLE_LEAF_SIZE as u32;
        if slot_size < MERKLE_LEAF_SIZE as u32
            || slot_size > crate::MAX_PROFILE_SHARD_SIZE
            || !slot_size.is_power_of_two()
            || self.siblings.len() > 18
        {
            return Err(CatalogError::Bounds);
        }
        Ok(MerkleSubtreeProof {
            format_version: MERKLE_SUITE_V1,
            start_leaf: chunk_index
                .checked_mul(leaf_count)
                .ok_or(CatalogError::Bounds)?,
            leaf_count,
            subtree_root: self.subtree_root,
            siblings: self.siblings.clone(),
        })
    }
}

/// Discriminants are append-only in record format one. Headers are ordered by
/// source ID, followed by every chunk proof in exact-size bounded fragments.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CatalogPackedSourceRecord {
    Source {
        format_version: u16,
        id: CatalogPackedSourceId,
        commitment: MerkleCommitment,
    },
    Proofs {
        first_chunk: u32,
        #[serde(deserialize_with = "decode_proofs")]
        proofs: Vec<CatalogPackedSourceProof>,
    },
    /// Complete coverage allows authentication by recomposing the source root,
    /// without repeating sibling paths for every chunk (root format two).
    Subtrees {
        first_chunk: u32,
        #[serde(deserialize_with = "decode_subtrees")]
        roots: Vec<[u8; 32]>,
    },
}

fn decode_subtrees<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<[u8; 32]>, D::Error> {
    crate::bounded::VecSeed::new(CATALOG_PACKED_SOURCE_PROOFS).deserialize(decoder)
}

fn decode_proofs<'de, D: Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<CatalogPackedSourceProof>, D::Error> {
    crate::bounded::VecSeed::new(CATALOG_PACKED_SOURCE_PROOFS).deserialize(decoder)
}

impl CatalogPackedSourceRecord {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_PACKED_SOURCE_RECORD_BYTES {
            return Err(CatalogError::Bounds);
        }
        let record: Self = decode_canonical(bytes)?;
        match &record {
            Self::Source {
                format_version,
                id,
                commitment,
            } => {
                id.validate()?;
                if *format_version != 1 || commitment.validate().is_err() {
                    return Err(CatalogError::InvalidPage);
                }
            }
            Self::Proofs { proofs, .. } => {
                if proofs.is_empty() || proofs.len() > CATALOG_PACKED_SOURCE_PROOFS {
                    return Err(CatalogError::Bounds);
                }
            }
            Self::Subtrees { roots, .. }
                if roots.is_empty() || roots.len() > CATALOG_PACKED_SOURCE_PROOFS =>
            {
                return Err(CatalogError::Bounds);
            }
            Self::Subtrees { .. } => {}
        }
        if canonical_bytes_bounded(&record, CATALOG_PACKED_SOURCE_RECORD_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(record)
    }
}

/// All fields must be authenticated together by an enclosing packing root.
/// Counts describe unique complete ciphertext sources, not retained plaintext
/// size, quotas, descriptor coverage or authorization by a signed revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackedSourceRoot {
    pub format_version: u16,
    pub profile: crate::PackingProfile,
    pub records: CatalogRecordRoot,
    pub sources: u64,
    pub chunks: u64,
    pub ciphertext_bytes: u64,
}

impl CatalogPackedSourceRoot {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_PACKED_SOURCE_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate()?;
        if canonical_bytes_bounded(&root, CATALOG_PACKED_SOURCE_ROOT_BYTES)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }

    pub fn validate(self) -> Result<(), CatalogError> {
        self.records.validate()?;
        let width = self
            .profile
            .slots_per_sector()
            .map_err(|_| CatalogError::InvalidPage)?;
        let fragments = u64::from(width).div_ceil(CATALOG_PACKED_SOURCE_PROOFS as u64);
        if !matches!(self.format_version, 1 | 2)
            || self.sources.checked_mul(1 + fragments) != Some(self.records.records)
            || self.sources.checked_mul(u64::from(width)) != Some(self.chunks)
            || self
                .sources
                .checked_mul(u64::from(self.profile.sector_size))
                != Some(self.ciphertext_bytes)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

struct ActiveSource {
    commitment: MerkleCommitment,
    consumed: u32,
    accumulator: crate::MerkleSubtreeAccumulator,
}

struct SourceState {
    profile: crate::PackingProfile,
    previous: Option<CatalogPackedSourceId>,
    active: Option<ActiveSource>,
    sources: u64,
    chunks: u64,
}

impl SourceState {
    fn new(profile: crate::PackingProfile) -> Result<Self, CatalogError> {
        profile.validate().map_err(|_| CatalogError::InvalidPage)?;
        Ok(Self {
            profile,
            previous: None,
            active: None,
            sources: 0,
            chunks: 0,
        })
    }

    fn accept(&mut self, record: &CatalogPackedSourceRecord) -> Result<(), CatalogError> {
        let width = self.profile.sector_size / self.profile.slot_size;
        match record {
            CatalogPackedSourceRecord::Source {
                format_version,
                id,
                commitment,
            } => {
                id.validate()?;
                if *format_version != 1
                    || self.active.is_some()
                    || self.previous.is_some_and(|previous| previous >= *id)
                    || commitment.byte_len != self.profile.sector_size
                    || commitment.validate().is_err()
                {
                    return Err(CatalogError::InvalidPage);
                }
                self.previous = Some(*id);
                self.active = Some(ActiveSource {
                    commitment: commitment.clone(),
                    consumed: 0,
                    accumulator: crate::MerkleSubtreeAccumulator::new(
                        self.profile.sector_size,
                        self.profile.slot_size,
                    )
                    .map_err(|_| CatalogError::InvalidPage)?,
                });
                self.sources += 1;
            }
            CatalogPackedSourceRecord::Proofs {
                first_chunk,
                proofs,
            } => {
                let active = self.active.as_mut().ok_or(CatalogError::InvalidPage)?;
                let expected = (width - active.consumed).min(CATALOG_PACKED_SOURCE_PROOFS as u32);
                if *first_chunk != active.consumed
                    || proofs.is_empty()
                    || proofs.len() != expected as usize
                {
                    return Err(CatalogError::InvalidPage);
                }
                for (index, proof) in proofs.iter().enumerate() {
                    let opening =
                        proof.opening(active.consumed + index as u32, self.profile.slot_size)?;
                    merkle_verify_subtree(&active.commitment, &opening)
                        .map_err(|_| CatalogError::InvalidPage)?;
                }
                self.accept_roots(*first_chunk, proofs.iter().map(|proof| proof.subtree_root))?;
            }
            CatalogPackedSourceRecord::Subtrees { first_chunk, roots } => {
                self.accept_roots(*first_chunk, roots.iter().copied())?
            }
        }
        Ok(())
    }

    fn accept_roots(
        &mut self,
        first_chunk: u32,
        roots: impl ExactSizeIterator<Item = [u8; 32]>,
    ) -> Result<(), CatalogError> {
        let width = self.profile.sector_size / self.profile.slot_size;
        let active = self.active.as_mut().ok_or(CatalogError::InvalidPage)?;
        let expected = (width - active.consumed).min(CATALOG_PACKED_SOURCE_PROOFS as u32);
        if first_chunk != active.consumed || roots.len() != expected as usize || roots.len() == 0 {
            return Err(CatalogError::InvalidPage);
        }
        for root in roots {
            active
                .accumulator
                .push(root)
                .map_err(|_| CatalogError::InvalidPage)?;
            active.consumed += 1;
            self.chunks += 1;
        }
        if active.consumed == width {
            let active = self.active.take().expect("completed source");
            if active
                .accumulator
                .finish()
                .map_err(|_| CatalogError::InvalidPage)?
                != active.commitment
            {
                return Err(CatalogError::InvalidPage);
            }
        }
        Ok(())
    }

    fn finish(&self) -> Result<(), CatalogError> {
        if self.active.is_some() {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

/// Accept ordered sources and bounded proof fragments; a failed operation
/// permanently fences the builder. No whole-catalog source map is retained.
pub struct CatalogPackedSourceBuilder {
    records: CatalogRecordBuilder,
    state: SourceState,
    failed: bool,
    format_version: u16,
}

impl CatalogPackedSourceBuilder {
    pub fn new(scope: CatalogScope, profile: crate::PackingProfile) -> Result<Self, CatalogError> {
        Ok(Self {
            records: CatalogRecordBuilder::new(scope, CatalogSection::Packing)?,
            state: SourceState::new(profile)?,
            failed: false,
            format_version: 1,
        })
    }

    /// Complete source subtrees authenticate through exact root composition.
    /// Existing proof fragments may also be supplied and are compacted after
    /// verifying their original openings. No signed legacy bytes are rewritten.
    pub fn new_compact(
        scope: CatalogScope,
        profile: crate::PackingProfile,
    ) -> Result<Self, CatalogError> {
        let mut builder = Self::new(scope, profile)?;
        builder.format_version = 2;
        Ok(builder)
    }

    pub fn push<E>(
        &mut self,
        record: &CatalogPackedSourceRecord,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = (|| {
            if self.format_version == 1
                && matches!(record, CatalogPackedSourceRecord::Subtrees { .. })
            {
                return Err(CatalogError::InvalidPage.into());
            }
            self.state.accept(record)?;
            if self.format_version == 2
                && let CatalogPackedSourceRecord::Proofs {
                    first_chunk,
                    proofs,
                } = record
            {
                self.records.push(
                    &CatalogPackedSourceRecord::Subtrees {
                        first_chunk: *first_chunk,
                        roots: proofs.iter().map(|proof| proof.subtree_root).collect(),
                    },
                    sink,
                )
            } else {
                self.records.push(record, sink)
            }
        })();
        self.failed = result.is_err();
        result
    }

    pub fn finish<E>(
        self,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPackedSourceRoot, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        self.state.finish()?;
        let root = CatalogPackedSourceRoot {
            format_version: self.format_version,
            profile: self.state.profile,
            records: self.records.finish(sink)?,
            sources: self.state.sources,
            chunks: self.state.chunks,
            ciphertext_bytes: self
                .state
                .sources
                .checked_mul(u64::from(self.state.profile.sector_size))
                .ok_or(CatalogError::Bounds)?,
        };
        root.validate()?;
        Ok(root)
    }
}

/// A valid prefix is insufficient. Reach authenticated EOF and complete the
/// descriptor/authority joins before committing validation or protection state.
pub struct CatalogPackedSourceReader {
    records: CatalogRecordReader,
    root: CatalogPackedSourceRoot,
    state: SourceState,
    consumed: u64,
    failed: bool,
}

impl CatalogPackedSourceReader {
    pub fn new(scope: CatalogScope, root: CatalogPackedSourceRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            records: CatalogRecordReader::new(scope, CatalogSection::Packing, root.records)?,
            root,
            state: SourceState::new(root.profile)?,
            consumed: 0,
            failed: false,
        })
    }

    pub fn next_record<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogPackedSourceRecord>, CatalogStreamError<E>> {
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
    ) -> Result<Option<CatalogPackedSourceRecord>, CatalogStreamError<E>> {
        let Some(bytes) = self.records.next_record(fetch)? else {
            self.verify_totals()?;
            return Ok(None);
        };
        let record = CatalogPackedSourceRecord::decode(&bytes)?;
        if matches!(
            (self.root.format_version, &record),
            (1, CatalogPackedSourceRecord::Subtrees { .. })
                | (2, CatalogPackedSourceRecord::Proofs { .. })
        ) {
            return Err(CatalogError::InvalidPage.into());
        }
        self.state.accept(&record)?;
        self.consumed += 1;
        if self.state.sources > self.root.sources || self.state.chunks > self.root.chunks {
            return Err(CatalogError::InvalidPage.into());
        }
        if self.consumed == self.root.records.records {
            self.verify_totals()?;
        }
        Ok(Some(record))
    }

    fn verify_totals(&self) -> Result<(), CatalogError> {
        self.state.finish()?;
        if self.state.sources != self.root.sources || self.state.chunks != self.root.chunks {
            return Err(CatalogError::InvalidPage);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{PackingProfile, canonical_bytes, merkle_commit, merkle_open_subtree};

    type Pages = HashMap<[u8; 32], Vec<u8>>;

    #[test]
    fn complete_subtree_stream_preserves_commitments_without_repeated_sibling_paths() {
        let profile = PackingProfile {
            format_version: 1,
            sector_size: 4096,
            slot_size: 16,
        };
        let original = records(0, profile);
        let (full, _) = build(profile, &original);
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder = CatalogPackedSourceBuilder::new_compact(scope(), profile).unwrap();
        let mut expected = Vec::new();
        for record in &original {
            builder.push(record, &mut sink).unwrap();
            expected.push(match record {
                CatalogPackedSourceRecord::Proofs {
                    first_chunk,
                    proofs,
                } => CatalogPackedSourceRecord::Subtrees {
                    first_chunk: *first_chunk,
                    roots: proofs.iter().map(|proof| proof.subtree_root).collect(),
                },
                header => header.clone(),
            });
        }
        let root = builder.finish(&mut sink).unwrap();
        assert_eq!(root.format_version, 2);
        assert_eq!(root.chunks, full.chunks);
        assert!(root.records.page.byte_len * 4 < full.records.page.byte_len);
        assert_eq!(
            CatalogPackedSourceRoot::decode(&canonical_bytes(&root).unwrap()).unwrap(),
            root
        );
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut fetch = |reference: CatalogPageRef| Ok::<_, ()>(pages[&reference.hash].clone());
        for record in &expected {
            assert_eq!(
                reader.next_record(&mut fetch).unwrap().as_ref(),
                Some(record)
            );
        }
        assert_eq!(reader.next_record(&mut fetch).unwrap(), None);
        // The direct subtree producer yields exactly the same authenticated root.
        let mut builder = CatalogPackedSourceBuilder::new_compact(scope(), profile).unwrap();
        for record in &expected {
            builder.push(record, &mut |_, _| Ok::<_, ()>(())).unwrap();
        }
        assert_eq!(builder.finish(&mut |_, _| Ok::<_, ()>(())).unwrap(), root);
        for bad_index in 1..expected.len() {
            let mut altered = expected.clone();
            let CatalogPackedSourceRecord::Subtrees { roots, .. } = &mut altered[bad_index] else {
                unreachable!()
            };
            roots[0][0] ^= 1;
            let (mut root, pages) = raw(profile, &altered, 1);
            root.format_version = 2;
            assert_rejected(root, &pages);
        }
        let (mut mismatched, pages) = raw(profile, &original, 1);
        mismatched.format_version = 2;
        assert_rejected(mismatched, &pages);
        let (mismatched, pages) = raw(profile, &expected, 1);
        assert_rejected(mismatched, &pages);
        let mut builder = CatalogPackedSourceBuilder::new(scope(), profile).unwrap();
        builder
            .push(&expected[0], &mut |_, _| Ok::<_, ()>(()))
            .unwrap();
        assert!(
            builder
                .push(&expected[1], &mut |_, _| Ok::<_, ()>(()))
                .is_err()
        );
        assert!(builder.finish(&mut |_, _| Ok::<_, ()>(())).is_err());
        let mut oversized = vec![2, 0];
        oversized.extend(canonical_bytes(&65_usize).unwrap());
        assert!(CatalogPackedSourceRecord::decode(&oversized).is_err());
    }

    fn scope() -> CatalogScope {
        CatalogScope::Guild { guild_id: [7; 32] }
    }

    fn profile() -> PackingProfile {
        PackingProfile {
            format_version: 1,
            sector_size: 64,
            slot_size: 16,
        }
    }

    fn records(index: u32, profile: PackingProfile) -> Vec<CatalogPackedSourceRecord> {
        let mut object_id = [0; 32];
        object_id[..4].copy_from_slice(&(index + 1).to_be_bytes());
        let bytes = (0..profile.sector_size)
            .map(|offset| ((offset / MERKLE_LEAF_SIZE as u32 + index) % 251) as u8)
            .collect::<Vec<_>>();
        let mut records = vec![CatalogPackedSourceRecord::Source {
            format_version: 1,
            id: CatalogPackedSourceId {
                owner: NodeId([2; 32]),
                protected_root: [3; 32],
                object_id,
            },
            commitment: merkle_commit(&bytes).unwrap(),
        }];
        let width = profile.slots_per_sector().unwrap();
        for first_chunk in (0..width).step_by(CATALOG_PACKED_SOURCE_PROOFS) {
            let proofs = (first_chunk
                ..width.min(first_chunk + CATALOG_PACKED_SOURCE_PROOFS as u32))
                .map(|chunk_index| {
                    let proof = merkle_open_subtree(
                        &bytes,
                        chunk_index * profile.slot_size / MERKLE_LEAF_SIZE as u32,
                        profile.slot_size / MERKLE_LEAF_SIZE as u32,
                    )
                    .unwrap();
                    CatalogPackedSourceProof {
                        subtree_root: proof.subtree_root,
                        siblings: proof.siblings,
                    }
                })
                .collect();
            records.push(CatalogPackedSourceRecord::Proofs {
                first_chunk,
                proofs,
            });
        }
        records
    }

    fn build(
        profile: PackingProfile,
        records: &[CatalogPackedSourceRecord],
    ) -> (CatalogPackedSourceRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder = CatalogPackedSourceBuilder::new(scope(), profile).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        (builder.finish(&mut sink).unwrap(), pages)
    }

    fn raw(
        profile: PackingProfile,
        records: &[CatalogPackedSourceRecord],
        sources: u64,
    ) -> (CatalogPackedSourceRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder = CatalogRecordBuilder::new(scope(), CatalogSection::Packing).unwrap();
        for record in records {
            builder.push(record, &mut sink).unwrap();
        }
        let root = CatalogPackedSourceRoot {
            format_version: 1,
            profile,
            records: builder.finish(&mut sink).unwrap(),
            sources,
            chunks: sources * u64::from(profile.slots_per_sector().unwrap()),
            ciphertext_bytes: sources * u64::from(profile.sector_size),
        };
        (root, pages)
    }

    fn assert_rejected(root: CatalogPackedSourceRoot, pages: &Pages) {
        let Ok(mut reader) = CatalogPackedSourceReader::new(scope(), root) else {
            return;
        };
        let mut fetch = |reference: CatalogPageRef| Ok::<_, ()>(pages[&reference.hash].clone());
        for _ in 0..=root.records.records {
            match reader.next_record(&mut fetch) {
                Ok(Some(_)) => {}
                Ok(None) => panic!("invalid source stream reached EOF"),
                Err(_) => {
                    assert!(matches!(
                        reader.next_record(&mut fetch),
                        Err(CatalogStreamError::Catalog(CatalogError::Failed))
                    ));
                    return;
                }
            }
        }
        panic!("invalid source stream did not fail");
    }

    #[test]
    fn packed_source_stream_round_trips_unique_complete_sources_across_many_pages() {
        let profile = profile();
        let records: Vec<_> = (0..512).flat_map(|index| records(index, profile)).collect();
        let (root, pages) = build(profile, &records);
        assert!(pages.len() > 2);
        assert_eq!(root.sources, 512);
        assert_eq!(root.chunks, 2048);
        assert_eq!(root.ciphertext_bytes, 512 * 64);
        assert_eq!(
            CatalogPackedSourceRoot::decode(&canonical_bytes(&root).unwrap()).unwrap(),
            root
        );
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut fetch = |reference: CatalogPageRef| Ok::<_, ()>(pages[&reference.hash].clone());
        let mut current = None;
        for expected in &records {
            let record = reader.next_record(&mut fetch).unwrap().unwrap();
            assert_eq!(&record, expected);
            match record {
                CatalogPackedSourceRecord::Source { id, commitment, .. } => {
                    current = Some((id, commitment))
                }
                CatalogPackedSourceRecord::Proofs {
                    first_chunk,
                    proofs,
                } => {
                    let (id, commitment) = current.as_ref().unwrap();
                    for (index, proof) in proofs.iter().enumerate() {
                        let chunk = id.chunk(first_chunk + index as u32);
                        let opening = proof.opening(chunk.chunk_index, profile.slot_size).unwrap();
                        assert_eq!(
                            merkle_verify_subtree(commitment, &opening).unwrap(),
                            proof.subtree_root
                        );
                    }
                }
                CatalogPackedSourceRecord::Subtrees { .. } => {
                    panic!("unexpected compact record in full-proof stream")
                }
            }
        }
        assert_eq!(reader.next_record(&mut fetch).unwrap(), None);
        assert_eq!(reader.next_record(&mut fetch).unwrap(), None);
        let mut wrong_scope =
            CatalogPackedSourceReader::new(CatalogScope::Guild { guild_id: [8; 32] }, root)
                .unwrap();
        assert!(wrong_scope.next_record(&mut fetch).is_err());
    }

    #[test]
    fn packed_source_stream_fragments_one_source_and_rejects_every_incomplete_boundary() {
        let profile = PackingProfile {
            format_version: 1,
            sector_size: 4096,
            slot_size: 16,
        };
        let records = records(0, profile);
        assert_eq!(records.len(), 5);
        let (root, pages) = build(profile, &records);
        assert!(root.records.page.byte_len > crate::CATALOG_LEAF_BYTES as u64);
        assert_eq!(root.chunks, 256);
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut fetch = |reference: CatalogPageRef| Ok::<_, ()>(pages[&reference.hash].clone());
        for expected in &records {
            assert_eq!(
                reader.next_record(&mut fetch).unwrap().as_ref(),
                Some(expected)
            );
        }
        assert_eq!(reader.next_record(&mut fetch).unwrap(), None);
        for stop in 1..records.len() {
            let (root, pages) = raw(profile, &records[..stop], 1);
            assert_rejected(root, &pages);
            let mut builder = CatalogPackedSourceBuilder::new(scope(), profile).unwrap();
            let mut sink = |_, _| Ok::<_, ()>(());
            for record in &records[..stop] {
                builder.push(record, &mut sink).unwrap();
            }
            assert!(builder.finish(&mut sink).is_err());
        }
    }

    #[test]
    fn packed_source_stream_rejects_proof_substitution_reordering_and_duplicate_sources() {
        let profile = profile();
        let original = records(0, profile);
        let mut mutations = Vec::new();
        let mut altered = original.clone();
        let CatalogPackedSourceRecord::Source { commitment, .. } = &mut altered[0] else {
            unreachable!()
        };
        commitment.root[0] ^= 1;
        mutations.push(altered);
        let mut altered = original.clone();
        let CatalogPackedSourceRecord::Proofs { proofs, .. } = &mut altered[1] else {
            unreachable!()
        };
        proofs[0].siblings[0][0] ^= 1;
        mutations.push(altered);
        let mut altered = original.clone();
        let CatalogPackedSourceRecord::Proofs { proofs, .. } = &mut altered[1] else {
            unreachable!()
        };
        proofs.swap(0, 1);
        mutations.push(altered);
        let mut altered = original.clone();
        let CatalogPackedSourceRecord::Proofs { first_chunk, .. } = &mut altered[1] else {
            unreachable!()
        };
        *first_chunk = 1;
        mutations.push(altered);
        let mut altered = original.clone();
        let CatalogPackedSourceRecord::Proofs { proofs, .. } = &mut altered[1] else {
            unreachable!()
        };
        proofs.pop();
        mutations.push(altered);
        let mut altered = original.clone();
        let CatalogPackedSourceRecord::Source { id, .. } = &mut altered[0] else {
            unreachable!()
        };
        id.object_id = [0; 32];
        mutations.push(altered);
        let mut altered = original.clone();
        altered.swap(0, 1);
        mutations.push(altered);
        for altered in mutations {
            let (root, pages) = raw(profile, &altered, 1);
            assert_rejected(root, &pages);
            let mut builder = CatalogPackedSourceBuilder::new(scope(), profile).unwrap();
            let mut sink = |_, _| Ok::<_, ()>(());
            assert!(
                altered
                    .iter()
                    .any(|record| builder.push(record, &mut sink).is_err())
            );
            assert!(matches!(
                builder.push(&original[0], &mut sink),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
        }
        for altered in [
            [original.clone(), original.clone()].concat(),
            [records(1, profile), original.clone()].concat(),
        ] {
            let (root, pages) = raw(profile, &altered, 2);
            assert_rejected(root, &pages);
        }
        let (root, pages) = build(profile, &original);
        for altered in [
            CatalogPackedSourceRoot {
                records: CatalogRecordRoot {
                    records: root.records.records * 2,
                    ..root.records
                },
                sources: root.sources * 2,
                chunks: root.chunks * 2,
                ciphertext_bytes: root.ciphertext_bytes * 2,
                ..root
            },
            CatalogPackedSourceRoot {
                chunks: root.chunks + 1,
                ..root
            },
            CatalogPackedSourceRoot {
                ciphertext_bytes: root.ciphertext_bytes + 1,
                ..root
            },
            CatalogPackedSourceRoot {
                sources: u64::MAX,
                ..root
            },
        ] {
            assert_rejected(altered, &pages);
        }
    }

    #[test]
    fn packed_source_decode_bounds_nested_proofs_siblings_and_noncanonical_encodings() {
        let original = records(0, profile());
        for record in &original {
            let bytes = canonical_bytes(record).unwrap();
            assert_eq!(CatalogPackedSourceRecord::decode(&bytes).unwrap(), *record);
            for end in 0..bytes.len() {
                assert!(CatalogPackedSourceRecord::decode(&bytes[..end]).is_err());
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(CatalogPackedSourceRecord::decode(&trailing).is_err());
        }
        // Proofs discriminant, first_chunk, then nested vector declaration.
        for declared in [65_usize, usize::MAX] {
            let mut bytes = vec![1, 0];
            bytes.extend(canonical_bytes(&declared).unwrap());
            assert!(CatalogPackedSourceRecord::decode(&bytes).is_err());
        }
        let mut bytes = vec![1, 0, 1];
        bytes.extend([1; 32]);
        bytes.push(19);
        assert!(CatalogPackedSourceRecord::decode(&bytes).is_err());
        let mut bytes = canonical_bytes(&original[0]).unwrap();
        bytes.splice(1..2, [0x81, 0]);
        assert!(CatalogPackedSourceRecord::decode(&bytes).is_err());
        let record = CatalogPackedSourceRecord::Proofs {
            first_chunk: u32::MAX,
            proofs: vec![
                CatalogPackedSourceProof {
                    subtree_root: [1; 32],
                    siblings: vec![[2; 32]; 18]
                };
                CATALOG_PACKED_SOURCE_PROOFS
            ],
        };
        let bytes = canonical_bytes(&record).unwrap();
        assert!(bytes.len() <= CATALOG_PACKED_SOURCE_RECORD_BYTES);
        assert!(bytes.len() < crate::CATALOG_RECORD_BYTES);
        assert_eq!(CatalogPackedSourceRecord::decode(&bytes).unwrap(), record);
        let CatalogPackedSourceRecord::Proofs { proofs, .. } = &record else {
            unreachable!()
        };
        assert!(proofs[0].opening(u32::MAX, 32).is_err());
        for slot_size in [0, 8, 17, u32::MAX] {
            assert!(proofs[0].opening(0, slot_size).is_err());
        }
        assert!(
            CatalogPackedSourceRoot::decode(&vec![0; CATALOG_PACKED_SOURCE_ROOT_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn packed_source_stream_handles_empty_roots_and_fences_storage_fetch_failure() {
        let profile = profile();
        let (root, pages) = build(profile, &[]);
        assert_eq!(root.sources, 0);
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut fetch = |reference: CatalogPageRef| Ok::<_, ()>(pages[&reference.hash].clone());
        assert_eq!(reader.next_record(&mut fetch).unwrap(), None);
        let fixture = records(0, profile);
        let (root, pages) = build(profile, &fixture);
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut fetch_failure = |_| Err::<Vec<u8>, _>("fetch failure");
        assert!(matches!(
            reader.next_record(&mut fetch_failure),
            Err(CatalogStreamError::Storage("fetch failure"))
        ));
        assert!(matches!(
            reader.next_record(&mut fetch_failure),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut corrupt = |reference: CatalogPageRef| {
            let mut bytes = pages[&reference.hash].clone();
            bytes[0] ^= 1;
            Ok::<_, ()>(bytes)
        };
        assert!(reader.next_record(&mut corrupt).is_err());
        assert!(matches!(
            reader.next_record(&mut corrupt),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        let mut builder = CatalogPackedSourceBuilder::new(scope(), profile).unwrap();
        let mut fail = |_, _| Err::<(), _>("sink failure");
        // Fill enough records to flush a leaf and reach the sink failure.
        let mut saw_failure = false;
        for index in 0..512 {
            for record in records(index, profile) {
                if builder.push(&record, &mut fail).is_err() {
                    saw_failure = true;
                    break;
                }
            }
            if saw_failure {
                break;
            }
        }
        assert!(saw_failure);
        assert!(matches!(
            builder.finish(&mut fail),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }

    #[test]
    fn packed_source_stream_checks_minimum_and_maximum_supported_proof_geometry() {
        let minimum = PackingProfile {
            format_version: 1,
            sector_size: 16,
            slot_size: 16,
        };
        let records = records(0, minimum);
        let (root, pages) = build(minimum, &records);
        assert_eq!(root.chunks, 1);
        let mut reader = CatalogPackedSourceReader::new(scope(), root).unwrap();
        let mut fetch = |reference: CatalogPageRef| Ok::<_, ()>(pages[&reference.hash].clone());
        for record in records {
            assert_eq!(reader.next_record(&mut fetch).unwrap(), Some(record));
        }
        assert_eq!(reader.next_record(&mut fetch).unwrap(), None);

        let maximum = PackingProfile {
            format_version: 1,
            sector_size: crate::MAX_PROFILE_SHARD_SIZE,
            slot_size: 16,
        };
        let bytes = vec![0; maximum.sector_size as usize];
        let opening = merkle_open_subtree(&bytes, 0, 1).unwrap();
        assert_eq!(opening.siblings.len(), 18);
        let mut builder = CatalogPackedSourceBuilder::new(scope(), maximum).unwrap();
        let mut sink = |_, _| Ok::<_, ()>(());
        builder
            .push(
                &CatalogPackedSourceRecord::Source {
                    format_version: 1,
                    id: CatalogPackedSourceId {
                        owner: NodeId([2; 32]),
                        protected_root: [3; 32],
                        object_id: [4; 32],
                    },
                    commitment: merkle_commit(&bytes).unwrap(),
                },
                &mut sink,
            )
            .unwrap();
        let fragment = CatalogPackedSourceRecord::Proofs {
            first_chunk: 0,
            proofs: vec![
                CatalogPackedSourceProof {
                    subtree_root: opening.subtree_root,
                    siblings: opening.siblings,
                };
                CATALOG_PACKED_SOURCE_PROOFS
            ],
        };
        let encoded = canonical_bytes(&fragment).unwrap();
        assert!(encoded.len() <= CATALOG_PACKED_SOURCE_RECORD_BYTES);
        assert_eq!(
            CatalogPackedSourceRecord::decode(&encoded).unwrap(),
            fragment
        );
        // For an all-zero source these maximum-depth paths are valid for each
        // of the first 64 leaves; the remaining fragments are still mandatory.
        builder.push(&fragment, &mut sink).unwrap();
        assert!(builder.finish(&mut sink).is_err());
        for invalid in [
            PackingProfile {
                format_version: 2,
                ..maximum
            },
            PackingProfile {
                slot_size: 0,
                ..maximum
            },
            PackingProfile {
                sector_size: maximum.sector_size * 2,
                ..maximum
            },
        ] {
            assert!(CatalogPackedSourceBuilder::new(scope(), invalid).is_err());
        }
        assert!(
            CatalogPackedSourceBuilder::new(
                CatalogScope::Dataset {
                    guild_id: [7; 32],
                    owner: NodeId([2; 32]),
                    protected_root_id: uuid::Uuid::new_v4(),
                },
                minimum
            )
            .is_err()
        );
    }
}
