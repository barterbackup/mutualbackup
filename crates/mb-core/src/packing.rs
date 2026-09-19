use serde::de::{SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

use crate::{
    MAX_PROFILE_SHARD_SIZE, MERKLE_LEAF_SIZE, MerkleCommitment, MerkleSubtreeProof, NodeId,
    canonical_bytes, merkle_commit, merkle_commit_subtrees, merkle_open_subtree,
    merkle_verify_subtree,
};

const MAX_PACKED_CHUNKS: usize = 1_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackingProfile {
    pub format_version: u16,
    pub sector_size: u32,
    pub slot_size: u32,
}

impl PackingProfile {
    pub fn validate(self) -> Result<(), PackingError> {
        if self.format_version != 1
            || self.sector_size < MERKLE_LEAF_SIZE as u32
            || self.sector_size > MAX_PROFILE_SHARD_SIZE
            || !self.sector_size.is_power_of_two()
            || self.slot_size < MERKLE_LEAF_SIZE as u32
            || self.slot_size > self.sector_size
            || !self.slot_size.is_power_of_two()
            || !self.sector_size.is_multiple_of(self.slot_size)
        {
            return Err(PackingError::InvalidProfile);
        }
        Ok(())
    }

    pub fn slots_per_sector(self) -> Result<u32, PackingError> {
        self.validate()?;
        Ok(self.sector_size / self.slot_size)
    }
}

/// One independently versioned object inside one named protected root. Bytes
/// are already owner-encrypted before cross-user packing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackingInput {
    pub owner: NodeId,
    pub protected_root: [u8; 32],
    pub object_id: [u8; 32],
    pub source_commitment: Option<MerkleCommitment>,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedPackingSource {
    pub owner: NodeId,
    pub protected_root: [u8; 32],
    pub object_id: [u8; 32],
    pub source_commitment: MerkleCommitment,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct SourceChunkId {
    pub owner: NodeId,
    pub protected_root: [u8; 32],
    pub object_id: [u8; 32],
    pub chunk_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackedSourceChunk {
    pub id: SourceChunkId,
    pub source_offset: u64,
    pub logical_len: u32,
    pub content_hash: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PackedSlot {
    Data(PackedSourceChunk),
    /// A zero chunk may retain a logical source mapping, while an empty slot
    /// has no source. Neither requires source payload transfer.
    VirtualZero {
        source: Option<PackedSourceChunk>,
    },
}

impl PackedSlot {
    pub fn source(&self) -> Option<&PackedSourceChunk> {
        match self {
            Self::Data(source)
            | Self::VirtualZero {
                source: Some(source),
            } => Some(source),
            Self::VirtualZero { source: None } => None,
        }
    }
}

pub fn packing_protected_root(root_id: Uuid) -> [u8; 32] {
    let mut protected_root = [0_u8; 32];
    protected_root[..16].copy_from_slice(root_id.as_bytes());
    protected_root
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackedSectorDescriptor {
    pub id: [u8; 32],
    pub sector_index: u32,
    pub flat_root: [u8; 32],
    pub commitment: MerkleCommitment,
    pub slots: Vec<PackedSlot>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackedSourceAuthentication {
    pub id: SourceChunkId,
    pub source_commitment: MerkleCommitment,
    pub proof: MerkleSubtreeProof,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackedCatalog {
    pub id: [u8; 32],
    pub format_version: u16,
    pub revision: u64,
    pub parent: Option<[u8; 32]>,
    pub profile: PackingProfile,
    pub sectors: Vec<PackedSectorDescriptor>,
    /// Compact source-to-slot proofs. Version-one catalogs predate source
    /// authentication and retain their original six-field encoding.
    pub source_authentication: Option<Vec<PackedSourceAuthentication>>,
}

impl Serialize for PackedCatalog {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = match (self.format_version, &self.source_authentication) {
            (1, None) => 6,
            (2, Some(_)) => 7,
            _ => return Err(serde::ser::Error::custom("invalid packed catalog version")),
        };
        let mut tuple = serializer.serialize_tuple(field_count)?;
        tuple.serialize_element(&self.id)?;
        tuple.serialize_element(&self.format_version)?;
        tuple.serialize_element(&self.revision)?;
        tuple.serialize_element(&self.parent)?;
        tuple.serialize_element(&self.profile)?;
        tuple.serialize_element(&self.sectors)?;
        if let Some(authentication) = &self.source_authentication {
            tuple.serialize_element(authentication)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for PackedCatalog {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PackedCatalogVisitor;

        impl<'de> Visitor<'de> for PackedCatalogVisitor {
            type Value = PackedCatalog;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a versioned packed catalog")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let id = next_catalog_field(&mut sequence, "catalog ID")?;
                let format_version = next_catalog_field(&mut sequence, "format version")?;
                let revision = next_catalog_field(&mut sequence, "revision")?;
                let parent = next_catalog_field(&mut sequence, "parent")?;
                let profile = next_catalog_field(&mut sequence, "profile")?;
                let sectors = next_catalog_field(&mut sequence, "sectors")?;
                let source_authentication = match format_version {
                    1 => None,
                    2 => Some(next_catalog_field(&mut sequence, "source authentication")?),
                    _ => {
                        return Err(serde::de::Error::custom("invalid packed catalog version"));
                    }
                };
                Ok(PackedCatalog {
                    id,
                    format_version,
                    revision,
                    parent,
                    profile,
                    sectors,
                    source_authentication,
                })
            }
        }

        deserializer.deserialize_tuple(7, PackedCatalogVisitor)
    }
}

fn next_catalog_field<'de, A, T>(sequence: &mut A, name: &'static str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| serde::de::Error::missing_field(name))
}

impl PackedCatalog {
    pub fn calculate_id(&self) -> Result<[u8; 32], PackingError> {
        catalog_id(
            self.format_version,
            self.revision,
            self.parent,
            self.profile,
            &self.sectors,
            self.source_authentication.as_deref(),
        )
    }

    pub fn validate(&self) -> Result<(), PackingError> {
        self.profile.validate()?;
        if !matches!(
            (self.format_version, &self.source_authentication),
            (1, None) | (2, Some(_))
        ) || self.revision == 0
            || (self.revision == 1) != self.parent.is_none()
            || self.calculate_id()? != self.id
        {
            return Err(PackingError::InvalidCatalog);
        }
        let expected_slots = self.profile.slots_per_sector()? as usize;
        let mut source_ids = std::collections::BTreeSet::new();
        let mut object_chunks =
            std::collections::BTreeMap::<(NodeId, [u8; 32], [u8; 32]), Vec<u32>>::new();
        for (sector_index, sector) in self.sectors.iter().enumerate() {
            if sector.sector_index != sector_index as u32
                || sector.slots.len() != expected_slots
                || sector.flat_root == [0; 32]
                || sector.commitment.byte_len != self.profile.sector_size
                || sector.calculate_id(self.profile)? != sector.id
            {
                return Err(PackingError::InvalidCatalog);
            }
            for slot in &sector.slots {
                let Some(source) = slot.source() else {
                    continue;
                };
                if source.id.owner == NodeId([0; 32])
                    || source.id.protected_root == [0; 32]
                    || source.id.object_id == [0; 32]
                    || source.logical_len == 0
                    || source.logical_len > self.profile.slot_size
                    || source.source_offset
                        != u64::from(source.id.chunk_index) * u64::from(self.profile.slot_size)
                    || !source_ids.insert(source.id)
                {
                    return Err(PackingError::InvalidCatalog);
                }
                object_chunks
                    .entry((
                        source.id.owner,
                        source.id.protected_root,
                        source.id.object_id,
                    ))
                    .or_default()
                    .push(source.id.chunk_index);
            }
        }
        if self
            .sectors
            .last()
            .is_some_and(|sector| sector.slots.iter().all(|slot| slot.source().is_none()))
        {
            return Err(PackingError::InvalidCatalog);
        }
        for chunks in object_chunks.values_mut() {
            chunks.sort_unstable();
            if chunks
                .iter()
                .enumerate()
                .any(|(index, chunk)| *chunk != index as u32)
            {
                return Err(PackingError::InvalidCatalog);
            }
        }
        if self.format_version == 2 {
            self.validate_source_authentication(&source_ids)?;
        }
        Ok(())
    }

    fn validate_source_authentication(
        &self,
        source_ids: &std::collections::BTreeSet<SourceChunkId>,
    ) -> Result<(), PackingError> {
        let authentication = self
            .source_authentication
            .as_ref()
            .ok_or(PackingError::InvalidCatalog)?;
        let expected_leaf_count = self.profile.slot_size / MERKLE_LEAF_SIZE as u32;
        let mut proofs = std::collections::BTreeMap::new();
        for entry in authentication {
            if entry.source_commitment.byte_len != self.profile.sector_size
                || entry.proof.start_leaf
                    != entry
                        .id
                        .chunk_index
                        .checked_mul(expected_leaf_count)
                        .ok_or(PackingError::InvalidCatalog)?
                || entry.proof.leaf_count != expected_leaf_count
                || merkle_verify_subtree(&entry.source_commitment, &entry.proof).is_err()
                || proofs.insert(entry.id, entry).is_some()
            {
                return Err(PackingError::InvalidCatalog);
            }
        }
        if proofs
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            != *source_ids
        {
            return Err(PackingError::InvalidCatalog);
        }

        let zeros = vec![0_u8; self.profile.slot_size as usize];
        let zero_root = merkle_open_subtree(&zeros, 0, expected_leaf_count)
            .map_err(|_| PackingError::InvalidCatalog)?
            .subtree_root;
        for descriptor in &self.sectors {
            let mut roots = Vec::with_capacity(descriptor.slots.len());
            for slot in &descriptor.slots {
                let root = match slot {
                    PackedSlot::Data(source) => {
                        if source.logical_len != self.profile.slot_size {
                            return Err(PackingError::InvalidCatalog);
                        }
                        proofs[&source.id].proof.subtree_root
                    }
                    PackedSlot::VirtualZero {
                        source: Some(source),
                    } => {
                        if source.logical_len != self.profile.slot_size
                            || proofs[&source.id].proof.subtree_root != zero_root
                        {
                            return Err(PackingError::InvalidCatalog);
                        }
                        zero_root
                    }
                    PackedSlot::VirtualZero { source: None } => zero_root,
                };
                roots.push(root);
            }
            if merkle_commit_subtrees(self.profile.sector_size, self.profile.slot_size, &roots)
                .map_err(|_| PackingError::InvalidCatalog)?
                != descriptor.commitment
            {
                return Err(PackingError::InvalidCatalog);
            }
        }
        Ok(())
    }
}

impl PackedSectorDescriptor {
    pub fn calculate_id(&self, profile: PackingProfile) -> Result<[u8; 32], PackingError> {
        let mut hasher = blake3::Hasher::new_derive_key("mutualbackup packed sector v1");
        hasher.update(&canonical_bytes(&(
            profile,
            self.sector_index,
            self.flat_root,
            &self.commitment,
            &self.slots,
        ))?);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PackedSector {
    pub descriptor: PackedSectorDescriptor,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PackingMetrics {
    pub logical_bytes: u64,
    pub source_upload_bytes: u64,
    pub packed_sector_bytes: u64,
    pub virtual_zero_bytes: u64,
    pub reused_slots: u64,
    pub changed_sectors: u64,
    pub peak_materialized_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackingResult {
    pub catalog: PackedCatalog,
    pub sectors: Vec<PackedSector>,
    pub metrics: PackingMetrics,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PackingUpdate {
    pub catalog: PackedCatalog,
    pub changed_sectors: Vec<PackedSector>,
    pub metrics: PackingMetrics,
}

#[derive(Default)]
struct PackingSectorState {
    owners: std::collections::BTreeSet<NodeId>,
    free: std::collections::BTreeSet<usize>,
}

struct StableSlotAllocator {
    slots_per_sector: usize,
    assignments: Vec<Option<SourceChunkId>>,
    sectors: Vec<PackingSectorState>,
    mixed: std::collections::BTreeSet<usize>,
    single: std::collections::BTreeMap<NodeId, std::collections::BTreeSet<usize>>,
    single_fillable: std::collections::BTreeMap<NodeId, std::collections::BTreeSet<usize>>,
    empty: std::collections::BTreeSet<usize>,
}

impl StableSlotAllocator {
    fn new(assignments: Vec<Option<SourceChunkId>>, slots_per_sector: usize) -> Self {
        let mut allocator = Self {
            slots_per_sector,
            assignments,
            sectors: Vec::new(),
            mixed: std::collections::BTreeSet::new(),
            single: std::collections::BTreeMap::new(),
            single_fillable: std::collections::BTreeMap::new(),
            empty: std::collections::BTreeSet::new(),
        };
        for sector_index in 0..allocator.assignments.len() / slots_per_sector {
            let start = sector_index * slots_per_sector;
            let mut state = PackingSectorState::default();
            for (offset, assignment) in allocator.assignments[start..start + slots_per_sector]
                .iter()
                .enumerate()
            {
                if let Some(id) = assignment {
                    state.owners.insert(id.owner);
                } else {
                    state.free.insert(start + offset);
                }
            }
            allocator.sectors.push(state);
            allocator.add_classification(sector_index);
        }
        allocator
    }

    fn insert_index(
        map: &mut std::collections::BTreeMap<NodeId, std::collections::BTreeSet<usize>>,
        owner: NodeId,
        sector_index: usize,
    ) {
        map.entry(owner).or_default().insert(sector_index);
    }

    fn remove_index(
        map: &mut std::collections::BTreeMap<NodeId, std::collections::BTreeSet<usize>>,
        owner: NodeId,
        sector_index: usize,
    ) {
        let remove_owner = map.get_mut(&owner).is_some_and(|sectors| {
            sectors.remove(&sector_index);
            sectors.is_empty()
        });
        if remove_owner {
            map.remove(&owner);
        }
    }

    fn add_classification(&mut self, sector_index: usize) {
        let state = &self.sectors[sector_index];
        if state.free.is_empty() {
            return;
        }
        match state.owners.len() {
            0 => {
                self.empty.insert(sector_index);
            }
            1 => {
                let owner = *state.owners.first().expect("one owner is present");
                Self::insert_index(&mut self.single, owner, sector_index);
                if state.free.len() > 1 {
                    Self::insert_index(&mut self.single_fillable, owner, sector_index);
                }
            }
            _ => {
                self.mixed.insert(sector_index);
            }
        }
    }

    fn remove_classification(&mut self, sector_index: usize) {
        let state = &self.sectors[sector_index];
        if state.free.is_empty() {
            return;
        }
        match state.owners.len() {
            0 => {
                self.empty.remove(&sector_index);
            }
            1 => {
                let owner = *state.owners.first().expect("one owner is present");
                Self::remove_index(&mut self.single, owner, sector_index);
                if state.free.len() > 1 {
                    Self::remove_index(&mut self.single_fillable, owner, sector_index);
                }
            }
            _ => {
                self.mixed.remove(&sector_index);
            }
        }
    }

    fn other_owner_sector(&self, owner: NodeId) -> Option<usize> {
        use std::ops::Bound::{Excluded, Unbounded};

        self.single
            .range(..owner)
            .next()
            .or_else(|| self.single.range((Excluded(owner), Unbounded)).next())
            .and_then(|(_, sectors)| sectors.first().copied())
    }

    fn append_empty_sector(&mut self) -> usize {
        let sector_index = self.sectors.len();
        let start = self.assignments.len();
        self.assignments.resize(start + self.slots_per_sector, None);
        self.sectors.push(PackingSectorState {
            owners: std::collections::BTreeSet::new(),
            free: (start..start + self.slots_per_sector).collect(),
        });
        self.add_classification(sector_index);
        sector_index
    }

    fn assign(&mut self, id: SourceChunkId) {
        let sector_index = self
            .mixed
            .first()
            .copied()
            .or_else(|| self.other_owner_sector(id.owner))
            .or_else(|| {
                self.single_fillable
                    .get(&id.owner)
                    .and_then(|sectors| sectors.first().copied())
            })
            .or_else(|| self.empty.first().copied())
            .unwrap_or_else(|| self.append_empty_sector());
        self.remove_classification(sector_index);
        let flat_index = self.sectors[sector_index]
            .free
            .first()
            .copied()
            .expect("classified sector has a free slot");
        self.sectors[sector_index].free.remove(&flat_index);
        self.sectors[sector_index].owners.insert(id.owner);
        self.assignments[flat_index] = Some(id);
        self.add_classification(sector_index);
    }

    fn into_assignments(self) -> Vec<Option<SourceChunkId>> {
        self.assignments
    }
}

impl PackingResult {
    pub fn validate(&self) -> Result<(), PackingError> {
        self.catalog.validate()?;
        if self.sectors.len() != self.catalog.sectors.len() {
            return Err(PackingError::InvalidCatalog);
        }
        for (packed, descriptor) in self.sectors.iter().zip(&self.catalog.sectors) {
            if &packed.descriptor != descriptor
                || packed.bytes.len() != self.catalog.profile.sector_size as usize
                || *blake3::hash(&packed.bytes).as_bytes() != descriptor.flat_root
                || merkle_commit(&packed.bytes).map_err(|_| PackingError::InvalidCatalog)?
                    != descriptor.commitment
            {
                return Err(PackingError::InvalidCatalog);
            }
            let slot_size = self.catalog.profile.slot_size as usize;
            for (index, slot) in descriptor.slots.iter().enumerate() {
                let bytes = &packed.bytes[index * slot_size..(index + 1) * slot_size];
                match slot {
                    PackedSlot::Data(source) => {
                        if bytes[source.logical_len as usize..]
                            .iter()
                            .any(|byte| *byte != 0)
                            || *blake3::hash(&bytes[..source.logical_len as usize]).as_bytes()
                                != source.content_hash
                        {
                            return Err(PackingError::InvalidCatalog);
                        }
                    }
                    PackedSlot::VirtualZero { source } => {
                        if bytes.iter().any(|byte| *byte != 0) {
                            return Err(PackingError::InvalidCatalog);
                        }
                        if source.as_ref().is_some_and(|source| {
                            *blake3::hash(&bytes[..source.logical_len as usize]).as_bytes()
                                != source.content_hash
                        }) {
                            return Err(PackingError::InvalidCatalog);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// Build a stable-slot catalog. Existing source chunk identities keep their
/// slot across content updates; removed chunks become authenticated zero slots;
/// new chunks enter free slots through a deterministic per-owner round robin.
pub fn pack_incremental(
    profile: PackingProfile,
    previous: Option<&PackedCatalog>,
    inputs: Vec<PackingInput>,
) -> Result<PackingResult, PackingError> {
    profile.validate()?;
    if let Some(previous) = previous {
        previous.validate()?;
        if previous.profile != profile {
            return Err(PackingError::ProfileChanged);
        }
    }
    let chunks = input_chunks(profile, inputs)?;
    let desired = chunks
        .iter()
        .map(|chunk| (chunk.source.id, chunk))
        .collect::<std::collections::BTreeMap<_, _>>();
    let slots_per_sector = profile.slots_per_sector()? as usize;
    let previous_slot_count = previous
        .map(|catalog| catalog.sectors.len() * slots_per_sector)
        .unwrap_or(0);
    let mut assignments = vec![None::<SourceChunkId>; previous_slot_count];
    let mut assigned = std::collections::BTreeSet::new();
    let mut reused_slots = 0_u64;
    if let Some(previous) = previous {
        for (flat_index, slot) in previous
            .sectors
            .iter()
            .flat_map(|sector| &sector.slots)
            .enumerate()
        {
            if let Some(source) = slot.source()
                && desired.contains_key(&source.id)
            {
                assignments[flat_index] = Some(source.id);
                assigned.insert(source.id);
                reused_slots += 1;
            }
        }
    }

    let mut pending_by_owner = std::collections::BTreeMap::<NodeId, Vec<SourceChunkId>>::new();
    for id in desired.keys().filter(|id| !assigned.contains(id)) {
        pending_by_owner.entry(id.owner).or_default().push(*id);
    }
    for pending in pending_by_owner.values_mut() {
        pending.sort();
        pending.reverse();
    }
    let mut allocator = StableSlotAllocator::new(assignments, slots_per_sector);
    loop {
        let mut progress = false;
        let owners = pending_by_owner.keys().copied().collect::<Vec<_>>();
        for owner in owners {
            let Some(id) = pending_by_owner.get_mut(&owner).and_then(Vec::pop) else {
                continue;
            };
            allocator.assign(id);
            progress = true;
        }
        if !progress {
            break;
        }
    }
    let mut assignments = allocator.into_assignments();
    while assignments.last().is_some_and(Option::is_none) {
        assignments.pop();
    }
    if assignments.len() > MAX_PACKED_CHUNKS {
        return Err(PackingError::TooManyChunks);
    }
    let sector_count = assignments.len().div_ceil(slots_per_sector);
    assignments.resize(sector_count * slots_per_sector, None);

    let mut sectors = Vec::with_capacity(sector_count);
    let mut logical_bytes = 0_u64;
    let mut source_upload_bytes = 0_u64;
    let mut virtual_zero_bytes = 0_u64;
    for sector_index in 0..sector_count {
        let mut bytes = vec![0_u8; profile.sector_size as usize];
        let mut slots = Vec::with_capacity(slots_per_sector);
        for slot_index in 0..slots_per_sector {
            let flat_index = sector_index * slots_per_sector + slot_index;
            let Some(id) = assignments[flat_index] else {
                virtual_zero_bytes += u64::from(profile.slot_size);
                slots.push(PackedSlot::VirtualZero { source: None });
                continue;
            };
            let chunk = desired[&id];
            logical_bytes += u64::from(chunk.source.logical_len);
            let slot_start = slot_index * profile.slot_size as usize;
            if chunk.virtual_zero {
                virtual_zero_bytes += u64::from(profile.slot_size);
                slots.push(PackedSlot::VirtualZero {
                    source: Some(chunk.source.clone()),
                });
            } else {
                let end = slot_start + chunk.bytes.len();
                bytes[slot_start..end].copy_from_slice(&chunk.bytes);
                source_upload_bytes += chunk.bytes.len() as u64;
                virtual_zero_bytes += u64::from(profile.slot_size - chunk.source.logical_len);
                slots.push(PackedSlot::Data(chunk.source.clone()));
            }
        }
        let commitment = merkle_commit(&bytes).map_err(|_| PackingError::InvalidCatalog)?;
        let mut descriptor = PackedSectorDescriptor {
            id: [0; 32],
            sector_index: sector_index as u32,
            flat_root: *blake3::hash(&bytes).as_bytes(),
            commitment,
            slots,
        };
        descriptor.id = descriptor.calculate_id(profile)?;
        sectors.push(PackedSector { descriptor, bytes });
    }
    let descriptors = sectors
        .iter()
        .map(|sector| sector.descriptor.clone())
        .collect::<Vec<_>>();
    let authenticated_chunks = chunks
        .iter()
        .filter_map(|chunk| chunk.authentication.clone())
        .collect::<Vec<_>>();
    let source_authentication = if authenticated_chunks.is_empty() {
        None
    } else if authenticated_chunks.len() == chunks.len() {
        Some(authenticated_chunks)
    } else {
        return Err(PackingError::InvalidInput);
    };
    let revision = previous.map_or(1, |catalog| catalog.revision + 1);
    let parent = previous.map(|catalog| catalog.id);
    let mut catalog = PackedCatalog {
        id: [0; 32],
        format_version: if source_authentication.is_some() {
            2
        } else {
            1
        },
        revision,
        parent,
        profile,
        sectors: descriptors,
        source_authentication,
    };
    catalog.id = catalog.calculate_id()?;
    let changed_sectors = sectors
        .iter()
        .filter(|sector| {
            previous
                .and_then(|catalog| catalog.sectors.get(sector.descriptor.sector_index as usize))
                .is_none_or(|old| old.commitment != sector.descriptor.commitment)
        })
        .count() as u64
        + previous
            .map(|catalog| catalog.sectors.len().saturating_sub(sectors.len()) as u64)
            .unwrap_or(0);
    let result = PackingResult {
        metrics: PackingMetrics {
            logical_bytes,
            source_upload_bytes,
            packed_sector_bytes: sector_count as u64 * u64::from(profile.sector_size),
            virtual_zero_bytes,
            reused_slots,
            changed_sectors,
            peak_materialized_bytes: logical_bytes
                .saturating_add(sector_count as u64 * u64::from(profile.sector_size)),
        },
        catalog,
        sectors,
    };
    result.validate()?;
    Ok(result)
}

/// Incrementally update an authenticated catalog. Only source objects absent
/// from the previous catalog need payloads in `new_inputs`; `load_previous`
/// is called only for packed sectors whose slot layout changes.
pub fn pack_incremental_authenticated<F>(
    profile: PackingProfile,
    previous: &PackedCatalog,
    sources: Vec<AuthenticatedPackingSource>,
    new_inputs: Vec<PackingInput>,
    mut load_previous: F,
) -> Result<PackingUpdate, PackingError>
where
    F: FnMut(&PackedSectorDescriptor) -> Result<Vec<u8>, PackingError>,
{
    profile.validate()?;
    previous.validate()?;
    if previous.format_version != 2 || previous.profile != profile {
        return Err(PackingError::ProfileChanged);
    }
    let previous_authentication = previous
        .source_authentication
        .as_ref()
        .ok_or(PackingError::InvalidCatalog)?
        .iter()
        .map(|entry| (entry.id, entry))
        .collect::<std::collections::BTreeMap<_, _>>();
    let previous_chunks = previous
        .sectors
        .iter()
        .flat_map(|sector| sector.slots.iter())
        .filter_map(PackedSlot::source)
        .map(|source| (source.id, source))
        .collect::<std::collections::BTreeMap<_, _>>();
    let previous_virtual = previous
        .sectors
        .iter()
        .flat_map(|sector| &sector.slots)
        .filter_map(|slot| match slot {
            PackedSlot::VirtualZero {
                source: Some(source),
            } => Some(source.id),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let input_count = new_inputs.len();
    let mut inputs = new_inputs
        .into_iter()
        .map(|input| ((input.owner, input.protected_root, input.object_id), input))
        .collect::<std::collections::BTreeMap<_, _>>();
    if inputs.len() != input_count || sources.is_empty() {
        return Err(PackingError::InvalidInput);
    }
    let mut seen_sources = std::collections::BTreeSet::new();
    let mut desired = std::collections::BTreeMap::<SourceChunkId, InputChunk>::new();
    let chunks_per_source = profile.sector_size / profile.slot_size;
    for source in sources {
        let object = (source.owner, source.protected_root, source.object_id);
        if source.owner == NodeId([0; 32])
            || source.protected_root == [0; 32]
            || source.object_id == [0; 32]
            || source.source_commitment.byte_len != profile.sector_size
            || source.source_commitment.validate().is_err()
            || !seen_sources.insert(object)
        {
            return Err(PackingError::InvalidInput);
        }
        if let Some(input) = inputs.remove(&object) {
            if input.source_commitment.as_ref() != Some(&source.source_commitment)
                || input.bytes.len() != profile.sector_size as usize
            {
                return Err(PackingError::InvalidInput);
            }
            for chunk in input_chunks(profile, vec![input])? {
                desired.insert(chunk.source.id, chunk);
            }
            continue;
        }
        for chunk_index in 0..chunks_per_source {
            let id = SourceChunkId {
                owner: source.owner,
                protected_root: source.protected_root,
                object_id: source.object_id,
                chunk_index,
            };
            let prior = previous_chunks
                .get(&id)
                .ok_or(PackingError::MissingObject)?;
            let authentication = previous_authentication
                .get(&id)
                .ok_or(PackingError::InvalidCatalog)?;
            if authentication.source_commitment != source.source_commitment
                || prior.logical_len != profile.slot_size
            {
                return Err(PackingError::InvalidInput);
            }
            let virtual_zero = previous_virtual.contains(&id);
            desired.insert(
                id,
                InputChunk {
                    source: (*prior).clone(),
                    authentication: Some((*authentication).clone()),
                    bytes: Vec::new(),
                    virtual_zero,
                },
            );
        }
    }
    if !inputs.is_empty() || desired.len() > MAX_PACKED_CHUNKS {
        return Err(PackingError::InvalidInput);
    }

    let slots_per_sector = profile.slots_per_sector()? as usize;
    let previous_slot_count = previous.sectors.len() * slots_per_sector;
    let mut assignments = vec![None::<SourceChunkId>; previous_slot_count];
    let mut assigned = std::collections::BTreeSet::new();
    let mut reused_slots = 0_u64;
    for (flat_index, slot) in previous
        .sectors
        .iter()
        .flat_map(|sector| &sector.slots)
        .enumerate()
    {
        if let Some(source) = slot.source()
            && desired.contains_key(&source.id)
        {
            assignments[flat_index] = Some(source.id);
            assigned.insert(source.id);
            reused_slots += 1;
        }
    }
    let mut pending_by_owner = std::collections::BTreeMap::<NodeId, Vec<SourceChunkId>>::new();
    for id in desired.keys().filter(|id| !assigned.contains(id)) {
        pending_by_owner.entry(id.owner).or_default().push(*id);
    }
    for pending in pending_by_owner.values_mut() {
        pending.sort();
        pending.reverse();
    }
    let mut allocator = StableSlotAllocator::new(assignments, slots_per_sector);
    loop {
        let mut progress = false;
        for owner in pending_by_owner.keys().copied().collect::<Vec<_>>() {
            let Some(id) = pending_by_owner.get_mut(&owner).and_then(Vec::pop) else {
                continue;
            };
            allocator.assign(id);
            progress = true;
        }
        if !progress {
            break;
        }
    }
    let mut assignments = allocator.into_assignments();
    while assignments.last().is_some_and(Option::is_none) {
        assignments.pop();
    }
    let sector_count = assignments.len().div_ceil(slots_per_sector);
    assignments.resize(sector_count * slots_per_sector, None);

    let mut descriptors = Vec::with_capacity(sector_count);
    let mut changed_sectors = Vec::new();
    let mut virtual_zero_bytes = 0_u64;
    for sector_index in 0..sector_count {
        let mut slots = Vec::with_capacity(slots_per_sector);
        for slot_index in 0..slots_per_sector {
            let assignment = assignments[sector_index * slots_per_sector + slot_index];
            let slot = match assignment {
                Some(id) => {
                    let chunk = &desired[&id];
                    if chunk.virtual_zero {
                        PackedSlot::VirtualZero {
                            source: Some(chunk.source.clone()),
                        }
                    } else {
                        PackedSlot::Data(chunk.source.clone())
                    }
                }
                None => PackedSlot::VirtualZero { source: None },
            };
            if matches!(slot, PackedSlot::VirtualZero { .. }) {
                virtual_zero_bytes += u64::from(profile.slot_size);
            }
            slots.push(slot);
        }
        if let Some(prior) = previous.sectors.get(sector_index)
            && prior.slots == slots
        {
            descriptors.push(prior.clone());
            continue;
        }

        let mut bytes = if let Some(prior) = previous.sectors.get(sector_index) {
            let bytes = load_previous(prior)?;
            if bytes.len() != profile.sector_size as usize
                || *blake3::hash(&bytes).as_bytes() != prior.flat_root
                || merkle_commit(&bytes).map_err(|_| PackingError::InvalidCatalog)?
                    != prior.commitment
            {
                return Err(PackingError::InvalidCatalog);
            }
            bytes
        } else {
            vec![0; profile.sector_size as usize]
        };
        for (slot_index, slot) in slots.iter().enumerate() {
            let start = slot_index * profile.slot_size as usize;
            let end = start + profile.slot_size as usize;
            match slot {
                PackedSlot::Data(source) => {
                    let chunk = &desired[&source.id];
                    if chunk.bytes.is_empty() {
                        let preserved = previous
                            .sectors
                            .get(sector_index)
                            .and_then(|sector| sector.slots.get(slot_index))
                            .is_some_and(|old| old.source().map(|old| old.id) == Some(source.id));
                        if !preserved {
                            return Err(PackingError::MissingObject);
                        }
                    } else {
                        bytes[start..end].fill(0);
                        bytes[start..start + chunk.bytes.len()].copy_from_slice(&chunk.bytes);
                    }
                }
                PackedSlot::VirtualZero { .. } => bytes[start..end].fill(0),
            }
        }
        let commitment = merkle_commit(&bytes).map_err(|_| PackingError::InvalidCatalog)?;
        let mut descriptor = PackedSectorDescriptor {
            id: [0; 32],
            sector_index: sector_index as u32,
            flat_root: *blake3::hash(&bytes).as_bytes(),
            commitment,
            slots,
        };
        descriptor.id = descriptor.calculate_id(profile)?;
        descriptors.push(descriptor.clone());
        changed_sectors.push(PackedSector { descriptor, bytes });
    }
    let source_authentication = desired
        .values()
        .map(|chunk| {
            chunk
                .authentication
                .clone()
                .ok_or(PackingError::InvalidCatalog)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut catalog = PackedCatalog {
        id: [0; 32],
        format_version: 2,
        revision: previous
            .revision
            .checked_add(1)
            .ok_or(PackingError::InvalidCatalog)?,
        parent: Some(previous.id),
        profile,
        sectors: descriptors,
        source_authentication: Some(source_authentication),
    };
    catalog.id = catalog.calculate_id()?;
    catalog.validate()?;
    let removed_sectors = previous.sectors.len().saturating_sub(catalog.sectors.len()) as u64;
    Ok(PackingUpdate {
        metrics: PackingMetrics {
            logical_bytes: desired.len() as u64 * u64::from(profile.slot_size),
            source_upload_bytes: desired.values().map(|chunk| chunk.bytes.len() as u64).sum(),
            packed_sector_bytes: changed_sectors.len() as u64 * u64::from(profile.sector_size),
            virtual_zero_bytes,
            reused_slots,
            changed_sectors: changed_sectors.len() as u64 + removed_sectors,
            peak_materialized_bytes: desired
                .values()
                .map(|chunk| chunk.bytes.len() as u64)
                .sum::<u64>()
                .saturating_add(changed_sectors.len() as u64 * u64::from(profile.sector_size))
                .saturating_add(u64::from(profile.sector_size)),
        },
        catalog,
        changed_sectors,
    })
}

/// Recover one logical protected-root object from authenticated packed sector
/// bytes. Virtual-zero source chunks are synthesized without stored payload.
pub fn unpack_object(
    packed: &PackingResult,
    owner: NodeId,
    protected_root: [u8; 32],
    object_id: [u8; 32],
) -> Result<Vec<u8>, PackingError> {
    packed.validate()?;
    unpack_object_from_sectors(
        &packed.catalog,
        &packed.sectors,
        owner,
        protected_root,
        object_id,
    )
}

/// Recover one catalog object from the authenticated packed sectors that
/// contain it. Callers need not materialize unrelated catalog sectors.
pub fn unpack_object_from_sectors(
    catalog: &PackedCatalog,
    sectors: &[PackedSector],
    owner: NodeId,
    protected_root: [u8; 32],
    object_id: [u8; 32],
) -> Result<Vec<u8>, PackingError> {
    catalog.validate()?;
    let available = sectors
        .iter()
        .map(|sector| (sector.descriptor.id, sector))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut chunks = Vec::<(u32, Vec<u8>)>::new();
    let slot_size = catalog.profile.slot_size as usize;
    for descriptor in &catalog.sectors {
        if !descriptor.slots.iter().any(|slot| {
            slot.source().is_some_and(|source| {
                (
                    source.id.owner,
                    source.id.protected_root,
                    source.id.object_id,
                ) == (owner, protected_root, object_id)
            })
        }) {
            continue;
        }
        let sector = available
            .get(&descriptor.id)
            .ok_or(PackingError::MissingObject)?;
        if sector.descriptor != *descriptor
            || sector.bytes.len() != catalog.profile.sector_size as usize
            || *blake3::hash(&sector.bytes).as_bytes() != descriptor.flat_root
            || merkle_commit(&sector.bytes).map_err(|_| PackingError::InvalidCatalog)?
                != descriptor.commitment
        {
            return Err(PackingError::InvalidCatalog);
        }
        for (slot_index, slot) in descriptor.slots.iter().enumerate() {
            let Some(source) = slot.source() else {
                continue;
            };
            if (
                source.id.owner,
                source.id.protected_root,
                source.id.object_id,
            ) != (owner, protected_root, object_id)
            {
                continue;
            }
            let bytes = match slot {
                PackedSlot::Data(_) => {
                    let start = slot_index * slot_size;
                    sector.bytes[start..start + source.logical_len as usize].to_vec()
                }
                PackedSlot::VirtualZero { .. } => vec![0; source.logical_len as usize],
            };
            chunks.push((source.id.chunk_index, bytes));
        }
    }
    if chunks.is_empty() {
        return Err(PackingError::MissingObject);
    }
    chunks.sort_by_key(|(index, _)| *index);
    if chunks
        .iter()
        .enumerate()
        .any(|(index, (chunk, _))| *chunk != index as u32)
    {
        return Err(PackingError::InvalidCatalog);
    }
    Ok(chunks.into_iter().flat_map(|(_, bytes)| bytes).collect())
}

#[derive(Debug)]
struct InputChunk {
    source: PackedSourceChunk,
    authentication: Option<PackedSourceAuthentication>,
    bytes: Vec<u8>,
    virtual_zero: bool,
}

fn input_chunks(
    profile: PackingProfile,
    inputs: Vec<PackingInput>,
) -> Result<Vec<InputChunk>, PackingError> {
    let mut seen_objects = std::collections::BTreeSet::new();
    let mut chunks = Vec::new();
    for input in inputs {
        let object = (input.owner, input.protected_root, input.object_id);
        if input.owner == NodeId([0; 32])
            || input.protected_root == [0; 32]
            || input.object_id == [0; 32]
            || input.bytes.is_empty()
            || input.source_commitment.as_ref().is_some_and(|commitment| {
                commitment.byte_len != input.bytes.len() as u32
                    || merkle_commit(&input.bytes).ok().as_ref() != Some(commitment)
            })
            || !seen_objects.insert(object)
        {
            return Err(PackingError::InvalidInput);
        }
        for (index, bytes) in input.bytes.chunks(profile.slot_size as usize).enumerate() {
            if chunks.len() == MAX_PACKED_CHUNKS {
                return Err(PackingError::TooManyChunks);
            }
            let chunk_index = u32::try_from(index).map_err(|_| PackingError::TooManyChunks)?;
            let start_leaf = chunk_index
                .checked_mul(profile.slot_size / MERKLE_LEAF_SIZE as u32)
                .ok_or(PackingError::TooManyChunks)?;
            let id = SourceChunkId {
                owner: input.owner,
                protected_root: input.protected_root,
                object_id: input.object_id,
                chunk_index,
            };
            let authentication = input
                .source_commitment
                .as_ref()
                .map(|commitment| -> Result<_, PackingError> {
                    Ok(PackedSourceAuthentication {
                        id,
                        source_commitment: commitment.clone(),
                        proof: merkle_open_subtree(
                            &input.bytes,
                            start_leaf,
                            profile.slot_size / MERKLE_LEAF_SIZE as u32,
                        )
                        .map_err(|_| PackingError::InvalidInput)?,
                    })
                })
                .transpose()?;
            chunks.push(InputChunk {
                source: PackedSourceChunk {
                    id,
                    source_offset: u64::from(chunk_index) * u64::from(profile.slot_size),
                    logical_len: bytes.len() as u32,
                    content_hash: *blake3::hash(bytes).as_bytes(),
                },
                authentication,
                bytes: bytes.to_vec(),
                virtual_zero: bytes.iter().all(|byte| *byte == 0),
            });
        }
    }
    chunks.sort_by_key(|chunk| chunk.source.id);
    Ok(chunks)
}

fn catalog_id(
    format_version: u16,
    revision: u64,
    parent: Option<[u8; 32]>,
    profile: PackingProfile,
    sectors: &[PackedSectorDescriptor],
    source_authentication: Option<&[PackedSourceAuthentication]>,
) -> Result<[u8; 32], PackingError> {
    let domain = match (format_version, source_authentication) {
        (1, None) => "mutualbackup packed catalog v1",
        (2, Some(_)) => "mutualbackup packed catalog v2",
        _ => return Err(PackingError::InvalidCatalog),
    };
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    let bytes = if let Some(authentication) = source_authentication {
        canonical_bytes(&(
            format_version,
            revision,
            parent,
            profile,
            sectors,
            authentication,
        ))?
    } else {
        canonical_bytes(&(format_version, revision, parent, profile, sectors))?
    };
    hasher.update(&bytes);
    Ok(*hasher.finalize().as_bytes())
}

#[derive(Debug, Error)]
pub enum PackingError {
    #[error("packing profile is invalid")]
    InvalidProfile,
    #[error("packing input is empty, duplicated, or has an invalid identity")]
    InvalidInput,
    #[error("packed catalog is invalid")]
    InvalidCatalog,
    #[error("an incremental update cannot change its packing profile")]
    ProfileChanged,
    #[error("the packing operation exceeds its chunk bound")]
    TooManyChunks,
    #[error("the requested packed object is absent")]
    MissingObject,
    #[error("protocol model failure: {0}")]
    Model(#[from] crate::ModelError),
}

#[cfg(test)]
mod tests {
    use crate::{KeyMaterial, Seed, merkle_open_range, merkle_verify_range};

    use super::*;

    fn owners(count: u8) -> Vec<NodeId> {
        (0..count)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 150; 32])).node_id())
            .collect()
    }

    fn input(owner: NodeId, protected_root: u8, object_id: u8, bytes: Vec<u8>) -> PackingInput {
        PackingInput {
            owner,
            protected_root: [protected_root; 32],
            object_id: [object_id; 32],
            source_commitment: None,
            bytes,
        }
    }

    fn profile() -> PackingProfile {
        PackingProfile {
            format_version: 1,
            sector_size: 64,
            slot_size: 16,
        }
    }

    #[test]
    fn authenticated_catalog_rejects_substituted_packed_content() {
        let owner = owners(1)[0];
        let bytes = (0..64_u8).collect::<Vec<_>>();
        let mut packed = pack_incremental(
            profile(),
            None,
            vec![PackingInput {
                owner,
                protected_root: [1; 32],
                object_id: [2; 32],
                source_commitment: Some(merkle_commit(&bytes).unwrap()),
                bytes,
            }],
        )
        .unwrap();
        assert_eq!(packed.catalog.format_version, 2);
        packed.validate().unwrap();

        packed.sectors[0].bytes[0] ^= 1;
        packed.sectors[0].descriptor.flat_root = *blake3::hash(&packed.sectors[0].bytes).as_bytes();
        packed.sectors[0].descriptor.commitment = merkle_commit(&packed.sectors[0].bytes).unwrap();
        packed.sectors[0].descriptor.id = packed.sectors[0]
            .descriptor
            .calculate_id(packed.catalog.profile)
            .unwrap();
        packed.catalog.sectors[0] = packed.sectors[0].descriptor.clone();
        packed.catalog.id = packed.catalog.calculate_id().unwrap();

        assert!(matches!(
            packed.validate(),
            Err(PackingError::InvalidCatalog)
        ));
    }

    #[test]
    fn authenticated_update_reads_and_writes_only_changed_packed_sectors() {
        let owners = owners(8);
        let mut original_inputs = Vec::new();
        let mut sources = Vec::new();
        for (index, owner) in owners.iter().copied().enumerate() {
            let bytes = vec![index as u8 + 1; 64];
            let commitment = merkle_commit(&bytes).unwrap();
            original_inputs.push(PackingInput {
                owner,
                protected_root: [1; 32],
                object_id: [index as u8 + 1; 32],
                source_commitment: Some(commitment.clone()),
                bytes,
            });
            sources.push(AuthenticatedPackingSource {
                owner,
                protected_root: [1; 32],
                object_id: [index as u8 + 1; 32],
                source_commitment: commitment,
            });
        }
        let previous = pack_incremental(profile(), None, original_inputs).unwrap();
        let changed_bytes = vec![99; 64];
        let changed_commitment = merkle_commit(&changed_bytes).unwrap();
        sources.push(AuthenticatedPackingSource {
            owner: owners[0],
            protected_root: [1; 32],
            object_id: [99; 32],
            source_commitment: changed_commitment.clone(),
        });
        let prior_bytes = previous
            .sectors
            .iter()
            .map(|sector| (sector.descriptor.id, sector.bytes.clone()))
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut reads = 0_u64;
        let update = pack_incremental_authenticated(
            profile(),
            &previous.catalog,
            sources,
            vec![PackingInput {
                owner: owners[0],
                protected_root: [1; 32],
                object_id: [99; 32],
                source_commitment: Some(changed_commitment),
                bytes: changed_bytes,
            }],
            |descriptor| {
                reads += 1;
                prior_bytes
                    .get(&descriptor.id)
                    .cloned()
                    .ok_or(PackingError::MissingObject)
            },
        )
        .unwrap();

        assert_eq!(update.catalog.parent, Some(previous.catalog.id));
        assert_eq!(update.metrics.source_upload_bytes, 64);
        assert!(reads as usize <= update.changed_sectors.len());
        assert!(reads < previous.sectors.len() as u64);
        assert_eq!(
            update.metrics.packed_sector_bytes,
            update.changed_sectors.len() as u64 * u64::from(profile().sector_size)
        );
        assert_eq!(
            update.metrics.changed_sectors,
            update.changed_sectors.len() as u64
        );
        assert!(
            update.metrics.peak_materialized_bytes
                < previous.sectors.len() as u64 * u64::from(profile().sector_size)
        );
        for sector in &update.changed_sectors {
            let descriptor = &update.catalog.sectors[sector.descriptor.sector_index as usize];
            assert_eq!(&sector.descriptor, descriptor);
            assert_eq!(merkle_commit(&sector.bytes).unwrap(), descriptor.commitment);
        }
    }

    #[test]
    fn new_slots_are_fair_and_cross_user_and_cover_multiple_roots() {
        let owners = owners(3);
        let packed = pack_incremental(
            profile(),
            None,
            vec![
                input(owners[0], 1, 10, vec![1; 40]),
                input(owners[0], 2, 11, vec![2; 20]),
                input(owners[1], 3, 12, vec![3; 35]),
                input(owners[2], 4, 13, vec![4; 33]),
            ],
        )
        .unwrap();
        assert_eq!(
            unpack_object(&packed, owners[0], [1; 32], [10; 32]).unwrap(),
            vec![1; 40]
        );
        assert_eq!(
            unpack_object(&packed, owners[1], [3; 32], [12; 32]).unwrap(),
            vec![3; 35]
        );
        let partial = packed
            .sectors
            .iter()
            .filter(|sector| {
                sector.descriptor.slots.iter().any(|slot| {
                    slot.source().is_some_and(|source| {
                        (
                            source.id.owner,
                            source.id.protected_root,
                            source.id.object_id,
                        ) == (owners[1], [3; 32], [12; 32])
                    })
                })
            })
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            unpack_object_from_sectors(&packed.catalog, &partial, owners[1], [3; 32], [12; 32],)
                .unwrap(),
            vec![3; 35]
        );
        let scheduled = packed
            .catalog
            .sectors
            .iter()
            .flat_map(|sector| &sector.slots)
            .filter_map(PackedSlot::source)
            .map(|source| source.id.owner)
            .collect::<Vec<_>>();
        let mut expected_owners = owners.clone();
        expected_owners.sort();
        assert_eq!(scheduled[..3], expected_owners[..]);
        assert!(
            packed.catalog.sectors[0]
                .slots
                .iter()
                .filter_map(PackedSlot::source)
                .map(|source| source.id.owner)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1
        );
        assert_eq!(
            packed
                .catalog
                .sectors
                .iter()
                .flat_map(|sector| &sector.slots)
                .filter_map(PackedSlot::source)
                .filter(|source| source.id.owner == owners[0])
                .map(|source| source.id.protected_root)
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            2
        );
    }

    #[test]
    fn incremental_changes_keep_slots_and_touch_only_affected_sectors() {
        let owners = owners(2);
        let first_inputs = vec![
            input(owners[0], 1, 10, vec![1; 48]),
            input(owners[1], 2, 20, vec![2; 48]),
        ];
        let first = pack_incremental(profile(), None, first_inputs).unwrap();
        let mut changed = vec![1; 48];
        changed[17] = 9;
        let second = pack_incremental(
            profile(),
            Some(&first.catalog),
            vec![
                input(owners[0], 1, 10, changed),
                input(owners[1], 2, 20, vec![2; 48]),
            ],
        )
        .unwrap();
        assert_eq!(second.metrics.reused_slots, 6);
        assert_eq!(second.metrics.changed_sectors, 1);
        let first_locations = source_locations(&first.catalog);
        assert_eq!(source_locations(&second.catalog), first_locations);
    }

    #[test]
    fn later_owner_fills_reserved_cross_user_slot_without_moving_sources() {
        let owners = owners(2);
        let first =
            pack_incremental(profile(), None, vec![input(owners[0], 1, 10, vec![1; 64])]).unwrap();
        let first_locations = source_locations(&first.catalog);
        assert!(
            first
                .catalog
                .sectors
                .iter()
                .any(|sector| { sector.slots.iter().any(|slot| slot.source().is_none()) })
        );

        let second = pack_incremental(
            profile(),
            Some(&first.catalog),
            vec![
                input(owners[0], 1, 10, vec![1; 64]),
                input(owners[1], 2, 20, vec![2; 16]),
            ],
        )
        .unwrap();
        let second_locations = source_locations(&second.catalog);
        assert!(
            first_locations
                .iter()
                .all(|(source, position)| second_locations.get(source) == Some(position))
        );
        assert!(second.catalog.sectors.iter().any(|sector| {
            sector
                .slots
                .iter()
                .filter_map(PackedSlot::source)
                .map(|source| source.id.owner)
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                > 1
        }));
    }

    #[test]
    fn removed_and_sparse_chunks_become_authenticated_virtual_zero() {
        let owners = owners(2);
        let first = pack_incremental(
            profile(),
            None,
            vec![
                input(owners[0], 1, 10, vec![8; 48]),
                input(owners[1], 2, 20, vec![0; 32]),
            ],
        )
        .unwrap();
        assert_eq!(first.metrics.source_upload_bytes, 48);
        assert!(first.catalog.sectors.iter().any(|sector| {
            sector
                .slots
                .iter()
                .any(|slot| matches!(slot, PackedSlot::VirtualZero { source: Some(_) }))
        }));
        assert_eq!(
            unpack_object(&first, owners[1], [2; 32], [20; 32]).unwrap(),
            vec![0; 32]
        );

        let second = pack_incremental(
            profile(),
            Some(&first.catalog),
            vec![input(owners[1], 2, 20, vec![0; 32])],
        )
        .unwrap();
        assert!(second.catalog.sectors.iter().any(|sector| {
            sector
                .slots
                .iter()
                .any(|slot| matches!(slot, PackedSlot::VirtualZero { source: None }))
        }));
        for sector in &second.sectors {
            let proof = merkle_open_range(&sector.bytes, 1, 1).unwrap();
            merkle_verify_range(&sector.descriptor.commitment, &proof).unwrap();
        }
    }

    #[test]
    fn sparse_large_sector_metrics_pin_transfer_and_proof_efficiency() {
        let owners = owners(1);
        let profile = PackingProfile {
            format_version: 1,
            sector_size: 64 * 1024,
            slot_size: 4096,
        };
        let packed =
            pack_incremental(profile, None, vec![input(owners[0], 9, 10, vec![7])]).unwrap();
        assert_eq!(packed.metrics.logical_bytes, 1);
        assert_eq!(packed.metrics.source_upload_bytes, 1);
        assert_eq!(packed.metrics.packed_sector_bytes, 64 * 1024);
        assert_eq!(packed.metrics.virtual_zero_bytes, 64 * 1024 - 1);
        let proof = merkle_open_range(&packed.sectors[0].bytes, 0, 1).unwrap();
        assert_eq!(proof.leaves.len() * MERKLE_LEAF_SIZE, 16);
        assert_eq!(proof.siblings.len(), 12);
    }

    fn source_locations(
        catalog: &PackedCatalog,
    ) -> std::collections::BTreeMap<SourceChunkId, usize> {
        catalog
            .sectors
            .iter()
            .flat_map(|sector| &sector.slots)
            .enumerate()
            .filter_map(|(index, slot)| slot.source().map(|source| (source.id, index)))
            .collect()
    }
}
