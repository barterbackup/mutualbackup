//! Bounded descriptor/source joins in a disposable encrypted index. Callers
//! authenticate roots and source authority; this is not a signed checkpoint,
//! dataset quota reservation, payload verification or durable page ownership.

use mb_core::{
    CATALOG_MAX_PAGE_OCCURRENCES, CATALOG_MAX_RECORDS, CATALOG_MAX_STREAM_BYTES,
    CatalogCodingTraversalBudget, CatalogPackedSectorReader, CatalogPackedSectorRecord,
    CatalogPackedSectorRoot, CatalogPackedSourceId, CatalogPackedSourceReader,
    CatalogPackedSourceRecord, CatalogPackedSourceRoot, CatalogStreamError, MerkleCommitment,
    MerkleSubtreeAccumulator, PackedSlot, SourceChunkId, canonical_bytes_bounded,
    canonical_size_bounded, merkle_zero_subtree_root,
};

use super::*;
use crate::RecordScratchStore;

const ROOT_BYTES: usize = 2048;
const ROW_BYTES: usize = 256;
const KEY_BYTES: usize = 104;
const HEADERS: &str = "packing-source";
const CHUNKS: &str = "packing-chunk";
pub(super) const SECTORS: &str = "packing-sector";
const COMPLETE: &str = "packing-complete";

/// Local join configuration including both streams and this descriptor. Version
/// one retains the original aggregate ceiling; version two requires a separate
/// trusted enclosing budget. Its source-authority context remains external.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingValidation {
    pub format_version: u16,
    pub scope: CatalogScope,
    pub descriptors: CatalogPackedSectorRoot,
    pub sources: CatalogPackedSourceRoot,
}

impl CatalogPackingValidation {
    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogStoreError> {
        let manifest = Self::decode_with_budget(bytes, Self::original_budget())?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn decode_with_budget(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > ROOT_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate_with_budget(budget)?;
        if canonical_bytes_bounded(&manifest, ROOT_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }

    pub fn validate(self) -> Result<(), CatalogStoreError> {
        if self.format_version != 1 {
            return Err(CatalogError::InvalidPage.into());
        }
        self.validate_with_budget(Self::original_budget())
    }

    pub(super) fn original_budget() -> CatalogCodingTraversalBudget {
        CatalogCodingTraversalBudget {
            bytes: CATALOG_MAX_STREAM_BYTES,
            page_occurrences: CATALOG_MAX_PAGE_OCCURRENCES,
            // Both independently bounded streams may use their full record cap.
            records: 2 * CATALOG_MAX_RECORDS,
        }
    }

    /// Includes both stream occurrences, their framed records and the canonical
    /// descriptor. Callers debit authority and other sections before admission.
    pub fn represented_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        let mut work = CatalogCodingTraversalBudget {
            bytes: canonical_size_bounded(&self, ROOT_BYTES)? as u64,
            ..Default::default()
        };
        for root in [self.descriptors.records, self.sources.records] {
            work = work.checked_add(CatalogCodingTraversalBudget {
                bytes: root.page.byte_len,
                page_occurrences: root.page.page_occurrences,
                records: root.records,
            })?;
        }
        Ok(work)
    }

    pub fn validate_with_budget(
        self,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<(), CatalogStoreError> {
        self.scope.validate(CatalogSection::Packing)?;
        self.descriptors.validate()?;
        self.sources.validate()?;
        if !matches!(self.format_version, 1 | 2)
            || self.descriptors.packing_version < 2
            || self.descriptors.profile != self.sources.profile
            || self.descriptors.source_chunks != self.sources.chunks
            || self.descriptors.source_bytes != self.sources.ciphertext_bytes
        {
            return Err(CatalogError::InvalidPage.into());
        }
        let work = self.represented_work()?;
        if self.format_version == 1 {
            Self::original_budget().remaining_after(work)?;
        }
        budget.remaining_after(work)?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingPlacement {
    pub sector_id: [u8; 32],
    pub sector_index: u32,
    pub slot_index: u32,
    pub content_hash: [u8; 32],
    pub virtual_zero: bool,
}

/// A complete descriptor whose identity and source composition passed both
/// packing EOFs. Available only behind the completed packing index marker.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingSector {
    pub id: [u8; 32],
    pub index: u32,
    pub flat_root: [u8; 32],
    pub commitment: MerkleCommitment,
}

#[derive(Serialize, Deserialize)]
struct SourceHeader {
    id: CatalogPackedSourceId,
    commitment: MerkleCommitment,
}

#[derive(Serialize, Deserialize)]
struct Chunk {
    subtree_root: [u8; 32],
    placement: Option<CatalogPackingPlacement>,
}

struct ActiveSector {
    id: [u8; 32],
    index: u32,
    commitment: MerkleCommitment,
    flat_root: [u8; 32],
    accumulator: MerkleSubtreeAccumulator,
    consumed: u32,
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(canonical_bytes_bounded(value, ROW_BYTES)?)
}

fn put(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
    bytes: &[u8],
) -> Result<(), CatalogStoreError> {
    if !store.put_record_if_absent(kind, key, bytes)?
        || store.get_record_bounded(kind, key, bytes.len())?.as_deref() != Some(bytes)
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn row<T: serde::de::DeserializeOwned + Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
) -> Result<Option<(T, Vec<u8>)>, CatalogStoreError> {
    let Some(bytes) = store.get_record_bounded(kind, key, ROW_BYTES)? else {
        return Ok(None);
    };
    let value = decode_canonical(&bytes)?;
    if encode(&value)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some((value, bytes)))
}

fn resolve_source(
    store: &RecordScratchStore,
    profile: mb_core::PackingProfile,
    key: [u8; 32],
) -> Result<CatalogPackedSourceId, CatalogStoreError> {
    let (header, _) = row::<SourceHeader>(store, HEADERS, &key)?.ok_or(DatabaseError::NotReady)?;
    if header.id.key() != key
        || header.commitment.byte_len != profile.sector_size
        || header.commitment.validate().is_err()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(header.id)
}

pub(super) fn unwrap_stream<T>(
    result: Result<T, CatalogStreamError<CatalogStoreError>>,
) -> Result<T, CatalogStoreError> {
    result.map_err(|error| match error {
        CatalogStreamError::Catalog(error) => error.into(),
        CatalogStreamError::Storage(error) => error,
    })
}

fn zero_content_hash(byte_len: u32) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    let zeros = [0; 4096];
    let mut left = byte_len as usize;
    while left != 0 {
        let count = left.min(zeros.len());
        hash.update(&zeros[..count]);
        left -= count;
    }
    *hash.finalize().as_bytes()
}

/// Only construction can create this index. A failed job drops its anonymous
/// database/journals. The completed index retains one placement per source
/// chunk with bounded reads; callers own its physical limits and headroom.
pub struct CatalogPackingIndex {
    pub(super) manifest: CatalogPackingValidation,
    pub(super) store: RecordScratchStore,
    pub(super) budget: CatalogCodingTraversalBudget,
}

impl CatalogPackingIndex {
    pub(super) fn source_id(
        &self,
        key: [u8; 32],
    ) -> Result<CatalogPackedSourceId, CatalogStoreError> {
        self.require_complete()?;
        resolve_source(&self.store, self.manifest.descriptors.profile, key)
    }
    /// Roots must already be authenticated. The required authorization callback
    /// must bind each exact source commitment to certified revision/member and
    /// writer authority. The caller supplies a private, physically admitted
    /// scratch store; this operation holds no production SQL writer transaction.
    pub fn build(
        manifest: CatalogPackingValidation,
        store: RecordScratchStore,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(CatalogPackedSourceId, &MerkleCommitment) -> Result<(), CatalogStoreError>,
    ) -> Result<Self, CatalogStoreError> {
        manifest.validate()?;
        Self::build_with_budget(
            manifest,
            CatalogPackingValidation::original_budget(),
            store,
            fetch,
            authorize,
        )
    }

    /// Admit all represented packing work against the trusted remaining budget
    /// before fetching pages or authorizing sources. Physical scratch admission
    /// and authenticated source authority are still required independently.
    pub fn build_with_budget(
        manifest: CatalogPackingValidation,
        budget: CatalogCodingTraversalBudget,
        store: RecordScratchStore,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(
            CatalogPackedSourceId,
            &MerkleCommitment,
        ) -> Result<(), CatalogStoreError>,
    ) -> Result<Self, CatalogStoreError> {
        manifest.validate_with_budget(budget)?;
        store.with_record_transaction(|| {
            build_index(manifest, &store, &mut fetch, &mut authorize)
        })?;
        Ok(Self {
            manifest,
            store,
            budget,
        })
    }

    pub fn manifest(&self) -> CatalogPackingValidation {
        self.manifest
    }

    /// Bind exactly the verified descriptor/source roles to existing durable
    /// page intents. Local bundle publication remains separate from signing
    /// and must recheck intent state through the ordinary atomic store API.
    pub fn as_local_bundle(
        &self,
        id: Uuid,
        intents: [CatalogIntent; 2],
    ) -> Result<CatalogBundle, CatalogStoreError> {
        self.require_complete()?;
        for intent in &intents {
            if intent.scope != self.manifest.scope || intent.section != CatalogSection::Packing {
                return Err(DatabaseError::Conflict.into());
            }
        }
        let bundle = CatalogBundle {
            id,
            scope: self.manifest.scope,
            roots: intents
                .into_iter()
                .zip([
                    self.manifest.descriptors.records.page,
                    self.manifest.sources.records.page,
                ])
                .map(|(intent, root)| CatalogBundleRoot { intent, root })
                .collect(),
            descriptor: canonical_bytes_bounded(&self.manifest, ROOT_BYTES)?,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub(super) fn require_complete(&self) -> Result<(), CatalogStoreError> {
        self.manifest.validate_with_budget(self.budget)?;
        let expected = canonical_bytes_bounded(&self.manifest, ROOT_BYTES)?;
        if self
            .store
            .get_record_bounded(COMPLETE, b"root", ROOT_BYTES)?
            .as_deref()
            != Some(expected.as_slice())
        {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }

    pub fn placement(
        &self,
        source: SourceChunkId,
    ) -> Result<Option<CatalogPackingPlacement>, CatalogStoreError> {
        self.require_complete()?;
        let key = canonical_bytes_bounded(&source, KEY_BYTES)?;
        let Some((chunk, _)) = row::<Chunk>(&self.store, CHUNKS, &key)? else {
            return Ok(None);
        };
        let placement = chunk.placement.ok_or(DatabaseError::Integrity)?;
        if chunk.subtree_root == [0; 32]
            || u64::from(placement.sector_index) >= self.manifest.descriptors.sectors
            || placement.slot_index
                >= self
                    .manifest
                    .descriptors
                    .profile
                    .slots_per_sector()
                    .map_err(|_| CatalogError::InvalidPage)?
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(placement))
    }

    pub fn sector(&self, id: [u8; 32]) -> Result<Option<CatalogPackingSector>, CatalogStoreError> {
        self.require_complete()?;
        self.sector_row(id)
    }

    // Internal bounded joins check completion before/after their full scan.
    // Keep all row/geometry checks without rereading the marker per point.
    pub(super) fn sector_row(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogPackingSector>, CatalogStoreError> {
        let Some((sector, _)) = row::<CatalogPackingSector>(&self.store, SECTORS, &id)? else {
            return Ok(None);
        };
        if sector.id != id
            || sector.id == [0; 32]
            || u64::from(sector.index) >= self.manifest.descriptors.sectors
            || sector.flat_root == [0; 32]
            || sector.commitment.byte_len != self.manifest.descriptors.profile.sector_size
            || sector.commitment.validate().is_err()
            || self.manifest.descriptors.packing_version >= 3
                && sector.flat_root != sector.commitment.root
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(sector))
    }
}

pub(super) fn build_index(
    manifest: CatalogPackingValidation,
    store: &RecordScratchStore,
    fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    authorize: &mut impl FnMut(
        CatalogPackedSourceId,
        &MerkleCommitment,
    ) -> Result<(), CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    for kind in [HEADERS, CHUNKS, SECTORS, COMPLETE] {
        if store
            .next_record_bounded(kind, None, KEY_BYTES, ROOT_BYTES)?
            .is_some()
        {
            return Err(DatabaseError::Conflict.into());
        }
    }
    let mut sources = CatalogPackedSourceReader::new(manifest.scope, manifest.sources)?;
    let mut current = None;
    let mut pending = 0_u64;
    while let Some(record) = unwrap_stream(sources.next_record(fetch))? {
        match record {
            CatalogPackedSourceRecord::Source { id, commitment, .. } => {
                authorize(id, &commitment)?;
                put(
                    store,
                    HEADERS,
                    &id.key(),
                    &encode(&SourceHeader { id, commitment })?,
                )?;
                current = Some(id);
            }
            CatalogPackedSourceRecord::Proofs {
                first_chunk,
                proofs,
            } => {
                let id = current.ok_or(DatabaseError::Integrity)?;
                for (offset, proof) in proofs.into_iter().enumerate() {
                    let key =
                        canonical_bytes_bounded(&id.chunk(first_chunk + offset as u32), KEY_BYTES)?;
                    put(
                        store,
                        CHUNKS,
                        &key,
                        &encode(&Chunk {
                            subtree_root: proof.subtree_root,
                            placement: None,
                        })?,
                    )?;
                    pending += 1;
                }
            }
            CatalogPackedSourceRecord::Subtrees { first_chunk, roots } => {
                let id = current.ok_or(DatabaseError::Integrity)?;
                for (offset, root) in roots.into_iter().enumerate() {
                    let key =
                        canonical_bytes_bounded(&id.chunk(first_chunk + offset as u32), KEY_BYTES)?;
                    put(
                        store,
                        CHUNKS,
                        &key,
                        &encode(&Chunk {
                            subtree_root: root,
                            placement: None,
                        })?,
                    )?;
                    pending += 1;
                }
            }
        }
    }
    if pending != manifest.sources.chunks {
        return Err(DatabaseError::Integrity.into());
    }
    let profile = manifest.descriptors.profile;
    let width = profile
        .slots_per_sector()
        .map_err(|_| CatalogError::InvalidPage)?;
    let zero_root =
        merkle_zero_subtree_root(profile.slot_size).map_err(|_| CatalogError::InvalidPage)?;
    let zero_hash = zero_content_hash(profile.slot_size);
    let mut reader = CatalogPackedSectorReader::new(manifest.scope, manifest.descriptors)?;
    let mut resolve = |key| resolve_source(store, profile, key);
    let mut active: Option<ActiveSector> = None;
    while let Some(record) = unwrap_stream(reader.next_record_with_sources(fetch, &mut resolve))? {
        match record {
            CatalogPackedSectorRecord::Header {
                id,
                sector_index,
                commitment,
                flat_root,
                ..
            } => {
                if active.is_some() {
                    return Err(DatabaseError::Integrity.into());
                }
                active = Some(ActiveSector {
                    id,
                    index: sector_index,
                    commitment,
                    flat_root,
                    accumulator: MerkleSubtreeAccumulator::new(
                        profile.sector_size,
                        profile.slot_size,
                    )
                    .map_err(|_| CatalogError::InvalidPage)?,
                    consumed: 0,
                });
            }
            CatalogPackedSectorRecord::Slots { offset, slots } => {
                let sector = active.as_mut().ok_or(DatabaseError::Integrity)?;
                if sector.consumed != offset {
                    return Err(DatabaseError::Integrity.into());
                }
                for slot in slots {
                    let root = if let Some(source) = slot.source() {
                        let key = canonical_bytes_bounded(&source.id, KEY_BYTES)?;
                        let (mut chunk, expected) =
                            row::<Chunk>(store, CHUNKS, &key)?.ok_or(DatabaseError::NotReady)?;
                        if chunk.placement.is_some()
                            || source.logical_len != profile.slot_size
                            || matches!(slot, PackedSlot::VirtualZero { .. })
                                && (chunk.subtree_root != zero_root
                                    || source.content_hash != zero_hash)
                        {
                            return Err(CatalogError::InvalidPage.into());
                        }
                        let root = chunk.subtree_root;
                        chunk.placement = Some(CatalogPackingPlacement {
                            sector_id: sector.id,
                            sector_index: sector.index,
                            slot_index: sector.consumed,
                            content_hash: source.content_hash,
                            virtual_zero: matches!(slot, PackedSlot::VirtualZero { .. }),
                        });
                        let replacement = encode(&chunk)?;
                        store.replace_record_if_value(CHUNKS, &key, &expected, &replacement)?;
                        if store
                            .get_record_bounded(CHUNKS, &key, ROW_BYTES)?
                            .as_deref()
                            != Some(replacement.as_slice())
                        {
                            return Err(DatabaseError::Integrity.into());
                        }
                        pending = pending.checked_sub(1).ok_or(DatabaseError::Integrity)?;
                        root
                    } else {
                        zero_root
                    };
                    sector
                        .accumulator
                        .push(root)
                        .map_err(|_| CatalogError::InvalidPage)?;
                    sector.consumed += 1;
                }
                if sector.consumed == width {
                    let sector = active.take().expect("complete sector");
                    if sector
                        .accumulator
                        .finish()
                        .map_err(|_| CatalogError::InvalidPage)?
                        != sector.commitment
                    {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    put(
                        store,
                        SECTORS,
                        &sector.id,
                        &encode(&CatalogPackingSector {
                            id: sector.id,
                            index: sector.index,
                            flat_root: sector.flat_root,
                            commitment: sector.commitment,
                        })?,
                    )?;
                }
            }
            CatalogPackedSectorRecord::CompactSlots { .. } => {
                return Err(DatabaseError::Integrity.into());
            }
        }
    }
    if active.is_some() || pending != 0 {
        return Err(CatalogError::InvalidPage.into());
    }
    put(
        store,
        COMPLETE,
        b"root",
        &canonical_bytes_bounded(&manifest, ROOT_BYTES)?,
    )?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use mb_core::{
        CatalogPackedSectorBuilder, CatalogPackedSourceBuilder, KeyMaterial,
        PackedSectorDescriptor, PackingInput, PackingProfile, Seed, merkle_zero_commitment,
        pack_incremental,
    };
    use std::collections::{BTreeMap, HashMap};

    pub(crate) struct Fixture {
        pub(crate) manifest: CatalogPackingValidation,
        pub(crate) pages: HashMap<[u8; 32], Vec<u8>>,
        pub(crate) roles: [Vec<(CatalogPageRef, Vec<u8>)>; 2],
        pub(crate) authority: BTreeMap<CatalogPackedSourceId, MerkleCommitment>,
        pub(crate) sectors: Vec<PackedSectorDescriptor>,
        pub(crate) bytes: Vec<Vec<u8>>,
    }

    impl Fixture {
        pub(crate) fn authorize(
            &self,
            id: CatalogPackedSourceId,
            commitment: &MerkleCommitment,
        ) -> Result<(), CatalogStoreError> {
            if self.authority.get(&id) != Some(commitment) {
                return Err(DatabaseError::Conflict.into());
            }
            Ok(())
        }
        pub(crate) fn fetch(
            &self,
            reference: CatalogPageRef,
        ) -> Result<Vec<u8>, CatalogStoreError> {
            self.pages
                .get(&reference.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        }
        pub(crate) fn build(&self, maximum: u64) -> Result<CatalogPackingIndex, CatalogStoreError> {
            CatalogPackingIndex::build(
                self.manifest,
                RecordScratchStore::new(maximum)?,
                |page| self.fetch(page),
                |id, commitment| self.authorize(id, commitment),
            )
        }
        fn replace_sectors(&mut self, mut sectors: Vec<PackedSectorDescriptor>) {
            let mut builder = CatalogPackedSectorBuilder::new_compact(
                self.manifest.scope,
                3,
                self.manifest.descriptors.profile,
            )
            .unwrap();
            let mut role = Vec::new();
            for sector in &mut sectors {
                sector.id = sector
                    .calculate_id(self.manifest.descriptors.profile)
                    .unwrap();
                builder
                    .push_sector(sector, &mut |page, bytes| {
                        role.push((page, bytes));
                        Ok::<_, ()>(())
                    })
                    .unwrap();
            }
            self.manifest.descriptors = builder
                .finish(&mut |page, bytes| {
                    role.push((page, bytes));
                    Ok::<_, ()>(())
                })
                .unwrap();
            for (reference, bytes) in &role {
                self.pages.insert(reference.hash, bytes.clone());
            }
            self.roles[0] = role;
            self.sectors = sectors;
        }
    }

    pub(crate) fn fixture(count: u32, compact: bool) -> Fixture {
        let profile = PackingProfile {
            format_version: 1,
            sector_size: 64,
            slot_size: 16,
        };
        let scope = CatalogScope::Guild { guild_id: [7; 32] };
        let inputs = (0..count)
            .map(|index| {
                let mut object_id = [0; 32];
                object_id[..4].copy_from_slice(&(index + 1).to_be_bytes());
                let bytes = (0..64)
                    .map(|offset| {
                        if index % 7 == 0 {
                            0
                        } else {
                            ((index * 64 + offset) % 251) as u8
                        }
                    })
                    .collect::<Vec<_>>();
                PackingInput {
                    owner: mb_core::NodeId([2 + (index % 3) as u8; 32]),
                    protected_root: [3; 32],
                    object_id,
                    source_commitment: Some(mb_core::merkle_commit(&bytes).unwrap()),
                    bytes,
                }
            })
            .collect();
        let packed = pack_incremental(profile, None, inputs).unwrap();
        packed.validate().unwrap();
        let mut grouped = BTreeMap::<CatalogPackedSourceId, Vec<_>>::new();
        for proof in packed
            .catalog
            .source_authentication
            .as_ref()
            .into_iter()
            .flatten()
        {
            grouped
                .entry(CatalogPackedSourceId {
                    owner: proof.id.owner,
                    protected_root: proof.id.protected_root,
                    object_id: proof.id.object_id,
                })
                .or_default()
                .push(proof);
        }
        let mut authority = BTreeMap::new();
        let mut roles = [Vec::new(), Vec::new()];
        let mut source_builder = if compact {
            CatalogPackedSourceBuilder::new_compact(scope, profile)
        } else {
            CatalogPackedSourceBuilder::new(scope, profile)
        }
        .unwrap();
        for (id, mut proofs) in grouped {
            proofs.sort_by_key(|proof| proof.id.chunk_index);
            let commitment = proofs[0].source_commitment.clone();
            authority.insert(id, commitment.clone());
            source_builder
                .push(
                    &CatalogPackedSourceRecord::Source {
                        format_version: 1,
                        id,
                        commitment,
                    },
                    &mut |page, bytes| {
                        roles[1].push((page, bytes));
                        Ok::<_, ()>(())
                    },
                )
                .unwrap();
            for fragment in proofs.chunks(mb_core::CATALOG_PACKED_SOURCE_PROOFS) {
                source_builder
                    .push(
                        &CatalogPackedSourceRecord::Proofs {
                            first_chunk: fragment[0].id.chunk_index,
                            proofs: fragment
                                .iter()
                                .map(|entry| mb_core::CatalogPackedSourceProof {
                                    subtree_root: entry.proof.subtree_root,
                                    siblings: entry.proof.siblings.clone(),
                                })
                                .collect(),
                        },
                        &mut |page, bytes| {
                            roles[1].push((page, bytes));
                            Ok::<_, ()>(())
                        },
                    )
                    .unwrap();
            }
        }
        let sources = source_builder
            .finish(&mut |page, bytes| {
                roles[1].push((page, bytes));
                Ok::<_, ()>(())
            })
            .unwrap();
        let mut descriptor_builder = if compact {
            CatalogPackedSectorBuilder::new_compact(scope, 3, profile)
        } else {
            CatalogPackedSectorBuilder::new(scope, 3, profile)
        }
        .unwrap();
        for sector in &packed.catalog.sectors {
            descriptor_builder
                .push_sector(sector, &mut |page, bytes| {
                    roles[0].push((page, bytes));
                    Ok::<_, ()>(())
                })
                .unwrap();
        }
        let descriptors = descriptor_builder
            .finish(&mut |page, bytes| {
                roles[0].push((page, bytes));
                Ok::<_, ()>(())
            })
            .unwrap();
        let pages = roles
            .iter()
            .flatten()
            .map(|(reference, bytes)| (reference.hash, bytes.clone()))
            .collect();
        Fixture {
            manifest: CatalogPackingValidation {
                format_version: 1,
                scope,
                descriptors,
                sources,
            },
            pages,
            roles,
            authority,
            bytes: packed
                .sectors
                .iter()
                .map(|sector| sector.bytes.clone())
                .collect(),
            sectors: packed.catalog.sectors,
        }
    }

    #[test]
    fn packing_index_joins_all_unique_chunks_and_spills_with_a_bounded_cache() {
        for (count, compact) in [(32, false), (2048, true)] {
            let fixture = fixture(count, compact);
            let index = fixture.build(16 * 1024 * 1024).unwrap();
            assert_eq!(index.manifest(), fixture.manifest);
            for sector in &fixture.sectors {
                assert_eq!(
                    index.sector(sector.id).unwrap(),
                    Some(CatalogPackingSector {
                        id: sector.id,
                        index: sector.sector_index,
                        flat_root: sector.flat_root,
                        commitment: sector.commitment.clone()
                    })
                );
                for (slot_index, slot) in sector.slots.iter().enumerate() {
                    let source = slot.source().unwrap();
                    assert_eq!(
                        index.placement(source.id).unwrap(),
                        Some(CatalogPackingPlacement {
                            sector_id: sector.id,
                            sector_index: sector.sector_index,
                            slot_index: slot_index as u32,
                            content_hash: source.content_hash,
                            virtual_zero: matches!(slot, PackedSlot::VirtualZero { .. }),
                        })
                    );
                }
            }
            let missing = CatalogPackedSourceId {
                owner: mb_core::NodeId([9; 32]),
                protected_root: [3; 32],
                object_id: [4; 32],
            }
            .chunk(0);
            assert_eq!(index.placement(missing).unwrap(), None);
            assert_eq!(index.sector([255; 32]).unwrap(), None);
            let cache = index
                .store
                .database_shell_statement("PRAGMA scratch.cache_size", false)
                .unwrap();
            assert_eq!(cache.rows[0][0], "-1024");
            if compact {
                let pages = index
                    .store
                    .database_shell_statement("PRAGMA scratch.page_count", false)
                    .unwrap();
                assert!(pages.rows[0][0].parse::<u64>().unwrap() * 4096 > 1024 * 1024);
            }
            let marker = canonical_bytes_bounded(&fixture.manifest, ROOT_BYTES).unwrap();
            index
                .store
                .delete_record_if_value(COMPLETE, b"root", &marker)
                .unwrap();
            assert!(index.placement(missing).is_err());
        }
    }

    #[test]
    fn packing_join_rejects_duplicate_missing_zero_and_merkle_mismatches() {
        for mutation in 0..5 {
            let mut fixture = fixture(16, true);
            let mut sectors = fixture.sectors.clone();
            let data = sectors
                .iter()
                .enumerate()
                .find_map(|(sector_index, sector)| {
                    sector
                        .slots
                        .iter()
                        .position(|slot| matches!(slot, PackedSlot::Data(_)))
                        .map(|slot| (sector_index, slot))
                })
                .unwrap();
            match mutation {
                0 => {
                    sectors[data.0].slots[(data.1 + 1) % 4] = sectors[data.0].slots[data.1].clone();
                }
                1 => {
                    let PackedSlot::Data(source) = &mut sectors[data.0].slots[data.1] else {
                        unreachable!()
                    };
                    source.id.owner = mb_core::NodeId([9; 32]);
                }
                2 => {
                    let source = sectors[data.0].slots[data.1].source().unwrap().clone();
                    sectors[data.0].slots[data.1] = PackedSlot::VirtualZero {
                        source: Some(source),
                    };
                }
                3 => {
                    sectors[data.0].commitment = merkle_zero_commitment(64).unwrap();
                    sectors[data.0].flat_root = sectors[data.0].commitment.root;
                }
                4 => {
                    let source = sectors
                        .iter_mut()
                        .flat_map(|sector| &mut sector.slots)
                        .find_map(|slot| match slot {
                            PackedSlot::VirtualZero {
                                source: Some(source),
                            } => Some(source),
                            _ => None,
                        })
                        .unwrap();
                    source.content_hash[0] ^= 1;
                }
                _ => unreachable!(),
            }
            fixture.replace_sectors(sectors);
            fixture.manifest.validate().unwrap();
            assert!(
                fixture.build(4 * 1024 * 1024).is_err(),
                "accepted mutation {mutation}"
            );
        }
        let fixture = fixture(32, true);
        let denied = CatalogPackingIndex::build(
            fixture.manifest,
            RecordScratchStore::new(4 * 1024 * 1024).unwrap(),
            |page| fixture.fetch(page),
            |_, _| Err(DatabaseError::Conflict.into()),
        );
        assert!(denied.is_err());
        let mut altered = fixture.manifest;
        altered.descriptors.source_chunks += 1;
        assert!(altered.validate().is_err());
    }

    #[test]
    fn packing_join_rolls_back_ignored_writes_cancellation_corruption_and_exhaustion() {
        let fixture = fixture(512, true);
        for trigger in [
            "CREATE TEMP TRIGGER ignored BEFORE INSERT ON protocol_records WHEN NEW.kind='packing-chunk' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER ignored BEFORE UPDATE ON protocol_records WHEN OLD.kind='packing-chunk' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER ignored BEFORE INSERT ON protocol_records WHEN NEW.kind='packing-sector' BEGIN SELECT RAISE(IGNORE); END",
            "CREATE TEMP TRIGGER ignored BEFORE INSERT ON protocol_records WHEN NEW.kind='packing-complete' BEGIN SELECT RAISE(IGNORE); END",
        ] {
            let store = RecordScratchStore::new(4 * 1024 * 1024).unwrap();
            store.database_shell_statement(trigger, false).unwrap();
            let result = store.with_record_transaction(|| {
                build_index(
                    fixture.manifest,
                    &store,
                    &mut |page| fixture.fetch(page),
                    &mut |id, commitment| fixture.authorize(id, commitment),
                )
            });
            assert!(result.is_err());
            for kind in [HEADERS, CHUNKS, SECTORS, COMPLETE] {
                assert!(
                    store
                        .next_record_bounded(kind, None, KEY_BYTES, ROOT_BYTES)
                        .unwrap()
                        .is_none()
                );
            }
        }
        for role in [0, 1] {
            let tail = fixture.roles[role]
                .iter()
                .rfind(|(reference, _)| reference.height == 0)
                .unwrap()
                .0
                .hash;
            let store = RecordScratchStore::new(4 * 1024 * 1024).unwrap();
            let result = store.with_record_transaction(|| {
                build_index(
                    fixture.manifest,
                    &store,
                    &mut |page| {
                        let mut bytes = fixture.fetch(page)?;
                        if page.hash == tail {
                            bytes[0] ^= 1;
                        }
                        Ok(bytes)
                    },
                    &mut |id, commitment| fixture.authorize(id, commitment),
                )
            });
            assert!(result.is_err());
            for kind in [HEADERS, CHUNKS, SECTORS, COMPLETE] {
                assert!(
                    store
                        .next_record_bounded(kind, None, KEY_BYTES, ROOT_BYTES)
                        .unwrap()
                        .is_none()
                );
            }
        }
        let mut visits = 0;
        assert!(
            CatalogPackingIndex::build(
                fixture.manifest,
                RecordScratchStore::new(4 * 1024 * 1024).unwrap(),
                |page| fixture.fetch(page),
                |id, commitment| {
                    visits += 1;
                    if visits == 511 {
                        return Err(DatabaseError::Conflict.into());
                    }
                    fixture.authorize(id, commitment)
                }
            )
            .is_err()
        );
        assert_eq!(visits, 511);
        assert!(fixture.build(64 * 1024).is_err());
        assert!(fixture.build(4 * 1024 * 1024).is_ok());
    }

    #[test]
    fn verified_packing_bundle_reopens_and_cancelled_roles_cannot_republish() {
        let fixture = fixture(512, true);
        let index = fixture.build(4 * 1024 * 1024).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([83; 32]));
        let intents = [
            CatalogIntent {
                id: Uuid::new_v4(),
                scope: fixture.manifest.scope,
                section: CatalogSection::Packing,
            },
            CatalogIntent {
                id: Uuid::new_v4(),
                scope: fixture.manifest.scope,
                section: CatalogSection::Packing,
            },
        ];
        let bundle = index.as_local_bundle(Uuid::new_v4(), intents).unwrap();
        let store = ControlStore::open(&path, &keys).unwrap();
        for intent in intents {
            store.begin_catalog(intent).unwrap();
        }
        for (reference, bytes) in &fixture.roles[0] {
            store
                .stage_catalog_page(intents[0], *reference, bytes)
                .unwrap();
        }
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        assert!(store.catalog_bundle(bundle.id).unwrap().is_none());
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        for (reference, bytes) in &fixture.roles[1] {
            store
                .stage_catalog_page(intents[1], *reference, bytes)
                .unwrap();
        }
        let replayed = CatalogPackingIndex::build(
            fixture.manifest,
            RecordScratchStore::new(4 * 1024 * 1024).unwrap(),
            |page| store.catalog_page(fixture.manifest.scope, CatalogSection::Packing, page),
            |id, commitment| fixture.authorize(id, commitment),
        )
        .unwrap();
        assert_eq!(
            replayed.as_local_bundle(bundle.id, intents).unwrap(),
            bundle
        );
        store.publish_catalog_bundle(&bundle).unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store.catalog_bundle(bundle.id).unwrap(),
            Some((bundle.clone(), CatalogBundleState::Published))
        );
        assert_eq!(
            CatalogPackingValidation::decode(&bundle.descriptor).unwrap(),
            fixture.manifest
        );
        let mut changed = bundle.clone();
        changed.descriptor[0] ^= 1;
        assert!(store.publish_catalog_bundle(&changed).is_err());
        store.cancel_catalog_bundle(bundle.id).unwrap();
        for intent in intents {
            while store.release_catalog_pin(intent).unwrap() {}
        }
        while store.collect_catalog_page().unwrap() {}
        assert!(store.records(PAGE).unwrap().is_empty());
        assert!(store.publish_catalog_bundle(&bundle).is_err());
        let mut wrong = intents;
        wrong[0].section = CatalogSection::Coding;
        assert!(index.as_local_bundle(Uuid::new_v4(), wrong).is_err());
    }

    #[test]
    fn packing_join_bounds_aggregate_roots_and_rejects_unowned_scratch_prefixes() {
        let fixture = fixture(0, true);
        let index = fixture.build(64 * 1024).unwrap();
        assert_eq!(index.manifest(), fixture.manifest);
        let bytes = canonical_bytes_bounded(&fixture.manifest, ROOT_BYTES).unwrap();
        assert_eq!(
            CatalogPackingValidation::decode(&bytes).unwrap(),
            fixture.manifest
        );
        for end in 0..bytes.len() {
            assert!(CatalogPackingValidation::decode(&bytes[..end]).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CatalogPackingValidation::decode(&trailing).is_err());
        assert!(CatalogPackingValidation::decode(&vec![0; ROOT_BYTES + 1]).is_err());
        let store = RecordScratchStore::new(64 * 1024).unwrap();
        put(&store, COMPLETE, b"root", b"unverified").unwrap();
        assert!(
            store
                .with_record_transaction(|| build_index(
                    fixture.manifest,
                    &store,
                    &mut |page| fixture.fetch(page),
                    &mut |_, _| Ok(())
                ))
                .is_err()
        );
        assert_eq!(
            store
                .get_record_bounded(COMPLETE, b"root", ROOT_BYTES)
                .unwrap()
                .unwrap(),
            b"unverified"
        );
        let mut large = fixture.manifest;
        let count = 1_u64 << 24;
        large.descriptors.sectors = count;
        large.descriptors.slots = count * 4;
        large.descriptors.source_chunks = count * 4;
        large.descriptors.source_bytes = count * 64;
        large.descriptors.records.records = count * 2;
        large.sources.sources = count;
        large.sources.chunks = count * 4;
        large.sources.ciphertext_bytes = count * 64;
        large.sources.records.records = count * 2;
        for page in [
            &mut large.descriptors.records.page,
            &mut large.sources.records.page,
        ] {
            page.byte_len = CATALOG_MAX_STREAM_BYTES / 2;
            page.height = 3;
            page.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES / 2;
        }
        large.descriptors.validate().unwrap();
        large.sources.validate().unwrap();
        // The fixed root descriptor also consumes the aggregate budget.
        assert!(large.validate().is_err());
        large.descriptors.records.page.byte_len -= ROOT_BYTES as u64;
        large.sources.records.page.byte_len -= ROOT_BYTES as u64;
        large.validate().unwrap();
        large.sources.records.page.page_occurrences += 1;
        assert!(large.validate().is_err());
    }

    #[test]
    fn budgeted_packing_admits_both_full_streams_without_relaxing_individual_bounds() {
        // Admission geometry only: no large stream or payload is materialized.
        let mut manifest = fixture(0, true).manifest;
        let count = 1_u64 << 24;
        manifest.format_version = 2;
        manifest.descriptors.sectors = count;
        manifest.descriptors.slots = count * 4;
        manifest.descriptors.source_chunks = count * 4;
        manifest.descriptors.source_bytes = count * 64;
        manifest.descriptors.records.records = count * 2;
        manifest.sources.sources = count;
        manifest.sources.chunks = count * 4;
        manifest.sources.ciphertext_bytes = count * 64;
        manifest.sources.records.records = count * 2;
        for page in [
            &mut manifest.descriptors.records.page,
            &mut manifest.sources.records.page,
        ] {
            page.byte_len = CATALOG_MAX_STREAM_BYTES;
            page.height = 3;
            page.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES;
        }
        manifest.descriptors.validate().unwrap();
        manifest.sources.validate().unwrap();
        let work = manifest.represented_work().unwrap();
        assert!(work.bytes > 2 * CATALOG_MAX_STREAM_BYTES);
        assert_eq!(work.page_occurrences, 2 * CATALOG_MAX_PAGE_OCCURRENCES);
        manifest.validate_with_budget(work).unwrap();
        assert!(manifest.validate().is_err());
        let bytes = canonical_bytes_bounded(&manifest, ROOT_BYTES).unwrap();
        assert_eq!(
            CatalogPackingValidation::decode_with_budget(&bytes, work).unwrap(),
            manifest
        );
        assert!(CatalogPackingValidation::decode(&bytes).is_err());
        let mut original = manifest;
        original.format_version = 1;
        assert!(original.validate_with_budget(work).is_err());
        let unlimited = CatalogCodingTraversalBudget {
            bytes: u64::MAX,
            page_occurrences: u64::MAX,
            records: u64::MAX,
        };
        for role in 0..2 {
            for dimension in 0..3 {
                let mut invalid = manifest;
                let root = if role == 0 {
                    &mut invalid.descriptors.records
                } else {
                    &mut invalid.sources.records
                };
                match dimension {
                    0 => root.page.byte_len += 1,
                    1 => root.page.page_occurrences += 1,
                    _ => root.records = CATALOG_MAX_RECORDS + 1,
                }
                assert!(invalid.validate_with_budget(unlimited).is_err());
            }
        }
        manifest.format_version = 3;
        assert!(manifest.validate_with_budget(unlimited).is_err());
    }

    #[test]
    fn budgeted_packing_requires_admission_before_fetch_and_preserves_complete_eofs() {
        let mut fixture = fixture(9, true);
        fixture.manifest.format_version = 2;
        let work = fixture.manifest.represented_work().unwrap();
        assert!(fixture.build(1024 * 1024).is_err());
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                CatalogPackingIndex::build_with_budget(
                    fixture.manifest,
                    limit,
                    RecordScratchStore::new(1024 * 1024).unwrap(),
                    |_| panic!("exhausted budget fetched packing pages"),
                    |_, _| panic!("exhausted budget authorized packing sources"),
                )
                .is_err()
            );
        }
        let bytes = canonical_bytes_bounded(&fixture.manifest, ROOT_BYTES).unwrap();
        for end in 0..bytes.len() {
            assert!(CatalogPackingValidation::decode_with_budget(&bytes[..end], work).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(CatalogPackingValidation::decode_with_budget(&trailing, work).is_err());
        for root in [
            fixture.manifest.descriptors.records.page,
            fixture.manifest.sources.records.page,
        ] {
            assert!(
                CatalogPackingIndex::build_with_budget(
                    fixture.manifest,
                    work,
                    RecordScratchStore::new(1024 * 1024).unwrap(),
                    |page| {
                        let mut bytes = fixture.fetch(page)?;
                        if page == root {
                            bytes.pop();
                        }
                        Ok(bytes)
                    },
                    |id, commitment| fixture.authorize(id, commitment),
                )
                .is_err()
            );
        }
        let mut index = CatalogPackingIndex::build_with_budget(
            fixture.manifest,
            work,
            RecordScratchStore::new(1024 * 1024).unwrap(),
            |page| fixture.fetch(page),
            |id, commitment| fixture.authorize(id, commitment),
        )
        .unwrap();
        for sector in &fixture.sectors {
            assert!(index.sector(sector.id).unwrap().is_some());
            for slot in &sector.slots {
                if let PackedSlot::Data(source) = slot {
                    assert!(index.placement(source.id).unwrap().is_some());
                }
            }
        }
        let intents = std::array::from_fn(|_| CatalogIntent {
            id: Uuid::new_v4(),
            scope: fixture.manifest.scope,
            section: CatalogSection::Packing,
        });
        let bundle = index.as_local_bundle(Uuid::new_v4(), intents).unwrap();
        assert_eq!(
            CatalogPackingValidation::decode_with_budget(&bundle.descriptor, work).unwrap(),
            fixture.manifest
        );
        // The saved trusted budget remains necessary even with a valid marker.
        index.budget.records -= 1;
        assert!(index.sector(fixture.sectors[0].id).is_err());
        assert!(index.as_local_bundle(Uuid::new_v4(), intents).is_err());
    }
}
