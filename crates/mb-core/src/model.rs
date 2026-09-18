use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::de::{DeserializeOwned, SeqAccess, Visitor};
use serde::ser::SerializeTuple;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use uuid::Uuid;

use crate::guild::RecoveryKeyEnvelope;
use crate::keys::{KeyMaterial, NodeId, RecoveryPublicKey, signing_payload};
use crate::packing::{PackedCatalog, packing_protected_root};
use crate::recovery::{RecoveryLocator, SealedRecoveryRecord};
use crate::{
    CodingProfile, MerkleCommitment, MerkleRangeProof, V1_CIPHER_PROFILE, V1_MAX_CODING_GROUPS,
    V1_MAX_ENDPOINT_BYTES, V1_MAX_ENDPOINTS_PER_PEER, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS,
    V1_SECTOR_SIZE, encode as encode_codeword, encode_3_2, merkle_commit, merkle_verify_range,
    merkle_zero_commitment, sector_root, verify_sampled_codeword,
};

pub type SectorId = [u8; 32];
pub type CodingGroupId = [u8; 32];
pub const USER_REVISION_DOMAIN: &[u8] = b"mutualbackup/user-revision/v3";
const WRITER_REVISION_DOMAIN: &[u8] = b"mutualbackup/writer-revision/v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub node_id: NodeId,
    pub recovery_public_key: RecoveryPublicKey,
    pub failure_domain: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildGenesis {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub coordinator: NodeId,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumGuildGenesis {
    pub genesis: GuildGenesis,
    pub signatures: Vec<MemberSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildInvite {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub coordinator: Member,
    pub coordinator_endpoints: Vec<String>,
    pub nonce: [u8; 16],
    pub expires_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageAcknowledgement {
    pub format_version: u16,
    pub operation_id: [u8; 16],
    pub guild_id: [u8; 32],
    pub group_id: CodingGroupId,
    pub shard_index: u8,
    pub row: u16,
    pub root: [u8; 32],
    pub holder: NodeId,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriterFence {
    pub owner: NodeId,
    pub epoch: u64,
    pub public_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RevisionTombstone {
    pub owner: NodeId,
    pub protected_root_id: Uuid,
    pub through_sequence: u64,
    pub last_revision_id: Uuid,
    pub last_revision_hash: [u8; 32],
    pub retired_at_generation: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct EndpointRecord {
    pub format_version: u16,
    pub publisher: NodeId,
    pub sequence: u64,
    pub expires_at_unix_seconds: u64,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryBundle {
    pub format_version: u16,
    pub subject: NodeId,
    pub publisher: NodeId,
    pub sequence: u64,
    pub expires_at_unix_seconds: u64,
    pub key_envelope: Option<RecoveryKeyEnvelope>,
    pub sealed: SealedRecoveryRecord,
}

impl Serialize for RecoveryBundle {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = match (self.format_version, &self.key_envelope) {
            (1, None) => 6,
            (2, Some(_)) => 7,
            _ => return Err(serde::ser::Error::custom("invalid recovery bundle version")),
        };
        let mut tuple = serializer.serialize_tuple(field_count)?;
        tuple.serialize_element(&self.format_version)?;
        tuple.serialize_element(&self.subject)?;
        tuple.serialize_element(&self.publisher)?;
        tuple.serialize_element(&self.sequence)?;
        tuple.serialize_element(&self.expires_at_unix_seconds)?;
        if let Some(envelope) = &self.key_envelope {
            tuple.serialize_element(envelope)?;
        }
        tuple.serialize_element(&self.sealed)?;
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for RecoveryBundle {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct RecoveryBundleVisitor;

        impl<'de> Visitor<'de> for RecoveryBundleVisitor {
            type Value = RecoveryBundle;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a versioned recovery bundle")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let format_version = next_recovery_bundle_field(&mut sequence, "format version")?;
                let subject = next_recovery_bundle_field(&mut sequence, "subject")?;
                let publisher = next_recovery_bundle_field(&mut sequence, "publisher")?;
                let bundle_sequence = next_recovery_bundle_field(&mut sequence, "sequence")?;
                let expires_at_unix_seconds = next_recovery_bundle_field(&mut sequence, "expiry")?;
                let key_envelope = match format_version {
                    1 => None,
                    2 => Some(next_recovery_bundle_field(&mut sequence, "key envelope")?),
                    _ => return Err(serde::de::Error::custom("invalid recovery bundle version")),
                };
                let sealed = next_recovery_bundle_field(&mut sequence, "sealed record")?;
                Ok(RecoveryBundle {
                    format_version,
                    subject,
                    publisher,
                    sequence: bundle_sequence,
                    expires_at_unix_seconds,
                    key_envelope,
                    sealed,
                })
            }
        }

        deserializer.deserialize_tuple(7, RecoveryBundleVisitor)
    }
}

fn next_recovery_bundle_field<'de, A, T>(
    sequence: &mut A,
    name: &'static str,
) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| serde::de::Error::missing_field(name))
}

impl StorageAcknowledgement {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.format_version != 1
            || self.operation_id == [0; 16]
            || self.guild_id == [0; 32]
            || self.group_id == [0; 32]
            || !(3..=4).contains(&self.shard_index)
            || self.row != u16::from(self.shard_index - 3)
            || self.root == [0; 32]
        {
            return Err(ModelError::InvalidStorageAcknowledgement);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SectorRef {
    pub id: SectorId,
    pub root: [u8; 32],
    pub logical_len: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InformationRole {
    pub owner: NodeId,
    pub sector: SectorRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParityRole {
    pub holder: NodeId,
    pub row: u16,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ShardRole {
    Information(InformationRole),
    Parity(ParityRole),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingGroup {
    pub id: CodingGroupId,
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub data_shards: u16,
    pub parity_shards: u16,
    pub shard_size: u32,
    pub roles: [ShardRole; 5],
}

/// Merkle-committed information reference used by variable coding layouts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RangeSectorRef {
    pub id: SectorId,
    pub commitment: MerkleCommitment,
    pub logical_len: u32,
    /// Virtual-zero shards have no payload transfer. Their all-zero RS bytes
    /// remain authenticated by `commitment` and their position by the group ID.
    pub virtual_zero: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct InformationRoleV2 {
    pub owner: NodeId,
    /// The certified hard-domain claim at placement time.
    pub failure_domain: String,
    pub sector: RangeSectorRef,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParityRoleV2 {
    pub holder: NodeId,
    /// The certified hard-domain claim at placement time.
    pub failure_domain: String,
    pub row: u16,
    pub commitment: MerkleCommitment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ShardRoleV2 {
    Information(InformationRoleV2),
    Parity(ParityRoleV2),
}

/// An explicit variable-geometry layout. The descriptor records every coding
/// parameter and placement-domain claim needed to decode it in the future.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingGroupV2 {
    pub id: CodingGroupId,
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub profile: CodingProfile,
    pub roles: Vec<ShardRoleV2>,
}

impl CodingGroupV2 {
    pub fn calculate_id(&self) -> Result<CodingGroupId, ModelError> {
        coding_group_v2_id(
            self.format_version,
            self.guild_id,
            self.profile,
            &self.roles,
        )
    }

    pub fn validate(&self) -> Result<(), ModelError> {
        self.profile.validate()?;
        if self.format_version != 2
            || self.guild_id == [0; 32]
            || self.roles.len() != self.profile.total_shards()?
            || self.calculate_id()? != self.id
        {
            return Err(ModelError::InvalidCheckpoint);
        }
        let mut domains = std::collections::BTreeSet::new();
        for (index, role) in self.roles.iter().enumerate() {
            let domain = match role {
                ShardRoleV2::Information(information)
                    if index < usize::from(self.profile.data_shards) =>
                {
                    information.sector.commitment.validate()?;
                    if information.sector.id == [0; 32]
                        || information.sector.commitment.byte_len != self.profile.shard_size
                        || information.sector.logical_len > self.profile.shard_size
                        || information.failure_domain.is_empty()
                        || information.failure_domain.len() > 256
                    {
                        return Err(ModelError::InvalidCheckpoint);
                    }
                    if information.sector.virtual_zero {
                        if information.sector.logical_len != self.profile.shard_size
                            || information.sector.commitment
                                != merkle_zero_commitment(self.profile.shard_size)?
                        {
                            return Err(ModelError::InvalidCheckpoint);
                        }
                    } else if information.sector.logical_len == 0 {
                        return Err(ModelError::InvalidCheckpoint);
                    }
                    information.failure_domain.as_str()
                }
                ShardRoleV2::Parity(parity)
                    if index >= usize::from(self.profile.data_shards)
                        && parity.row == (index - usize::from(self.profile.data_shards)) as u16 =>
                {
                    parity.commitment.validate()?;
                    if parity.commitment.byte_len != self.profile.shard_size
                        || parity.failure_domain.is_empty()
                        || parity.failure_domain.len() > 256
                    {
                        return Err(ModelError::InvalidCheckpoint);
                    }
                    parity.failure_domain.as_str()
                }
                _ => return Err(ModelError::InvalidCheckpoint),
            };
            if !domains.insert(domain) {
                return Err(ModelError::ReusedFailureDomain(domain.to_owned()));
            }
        }
        Ok(())
    }

    /// Verify a complete parity shard against all committed information bytes.
    pub fn verify_parity_shard(
        &self,
        information: &[Vec<u8>],
        shard_index: usize,
        parity: &[u8],
    ) -> Result<(), ModelError> {
        self.validate()?;
        if information.len() != usize::from(self.profile.data_shards) {
            return Err(ModelError::InvalidCodingRelation);
        }
        for (role, bytes) in self.roles[..information.len()].iter().zip(information) {
            let ShardRoleV2::Information(information_role) = role else {
                return Err(ModelError::InvalidCodingRelation);
            };
            if merkle_commit(bytes)? != information_role.sector.commitment {
                return Err(ModelError::InvalidCodingRelation);
            }
        }
        let Some(ShardRoleV2::Parity(parity_role)) = self.roles.get(shard_index) else {
            return Err(ModelError::InvalidCodingRelation);
        };
        if merkle_commit(parity)? != parity_role.commitment {
            return Err(ModelError::InvalidCodingRelation);
        }
        let encoded = encode_codeword(self.profile, information.to_vec())?;
        if encoded[shard_index].as_slice() != parity {
            return Err(ModelError::InvalidCodingRelation);
        }
        Ok(())
    }

    /// Authenticate the same 16-byte leaf from every shard and verify only
    /// those symbols against the declared Reed--Solomon equation.
    pub fn verify_sampled_openings(
        &self,
        challenged_leaf: u32,
        proofs: &[MerkleRangeProof],
    ) -> Result<(), ModelError> {
        self.validate()?;
        if proofs.len() != self.roles.len() {
            return Err(ModelError::InvalidCodingRelation);
        }
        let mut symbols = Vec::with_capacity(proofs.len());
        for (role, proof) in self.roles.iter().zip(proofs) {
            if proof.start_leaf != challenged_leaf || proof.leaves.len() != 1 {
                return Err(ModelError::InvalidCodingRelation);
            }
            let commitment = match role {
                ShardRoleV2::Information(information) => &information.sector.commitment,
                ShardRoleV2::Parity(parity) => &parity.commitment,
            };
            let bytes = merkle_verify_range(commitment, proof)?;
            symbols.push(
                bytes
                    .try_into()
                    .map_err(|_| ModelError::InvalidCodingRelation)?,
            );
        }
        verify_sampled_codeword(self.profile, &symbols)?;
        Ok(())
    }
}

pub fn coding_group_v2_id(
    format_version: u16,
    guild_id: [u8; 32],
    profile: CodingProfile,
    roles: &[ShardRoleV2],
) -> Result<CodingGroupId, ModelError> {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup coding group v2");
    hasher.update(&canonical_bytes(&(
        format_version,
        guild_id,
        profile,
        roles,
    ))?);
    Ok(*hasher.finalize().as_bytes())
}

impl CodingGroup {
    pub fn calculate_id(&self) -> Result<CodingGroupId, ModelError> {
        coding_group_id(
            self.format_version,
            self.guild_id,
            self.data_shards,
            self.parity_shards,
            self.shard_size,
            &self.roles,
        )
    }

    /// Verify that one parity shard is the declared Reed--Solomon row for the
    /// three root-bound information shards in this descriptor.
    pub fn verify_parity_shard(
        &self,
        information: &[Vec<u8>; 3],
        shard_index: usize,
        parity: &[u8],
    ) -> Result<(), ModelError> {
        validate_group_profile(self)?;
        let ShardRole::Parity(parity_role) = self
            .roles
            .get(shard_index)
            .ok_or(ModelError::InvalidCodingRelation)?
        else {
            return Err(ModelError::InvalidCodingRelation);
        };
        if shard_index < V1_RS_DATA_SHARDS as usize
            || parity_role.row != (shard_index - V1_RS_DATA_SHARDS as usize) as u16
            || parity.len() != self.shard_size as usize
            || sector_root(parity) != parity_role.root
        {
            return Err(ModelError::InvalidCodingRelation);
        }
        for (role, bytes) in self.roles[..V1_RS_DATA_SHARDS as usize]
            .iter()
            .zip(information)
        {
            let ShardRole::Information(information_role) = role else {
                return Err(ModelError::InvalidCodingRelation);
            };
            if bytes.len() != self.shard_size as usize
                || sector_root(bytes) != information_role.sector.root
            {
                return Err(ModelError::InvalidCodingRelation);
            }
        }
        let encoded = encode_3_2(information.clone())?;
        if encoded[shard_index].as_slice() != parity {
            return Err(ModelError::InvalidCodingRelation);
        }
        Ok(())
    }
}

pub fn coding_group_id(
    format_version: u16,
    guild_id: [u8; 32],
    data_shards: u16,
    parity_shards: u16,
    shard_size: u32,
    roles: &[ShardRole; 5],
) -> Result<CodingGroupId, ModelError> {
    Ok(*blake3::hash(&canonical_bytes(&(
        format_version,
        guild_id,
        data_shards,
        parity_shards,
        shard_size,
        roles,
    ))?)
    .as_bytes())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CheckpointAuthority {
    pub format_version: u16,
    pub membership_epoch: u64,
    pub quorum: crate::QuorumPolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuildCheckpoint {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub generation: u64,
    pub parent: Option<[u8; 32]>,
    pub members: Vec<Member>,
    pub writer_fences: Vec<WriterFence>,
    pub revision_tombstones: Vec<RevisionTombstone>,
    pub revisions: Vec<SignedRecord<UserRevision>>,
    pub coding_groups: Vec<CodingGroup>,
    pub authority: Option<CheckpointAuthority>,
    pub packing_catalog: Option<PackedCatalog>,
}

impl Serialize for GuildCheckpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count = match (
            self.format_version,
            self.authority,
            self.packing_catalog.as_ref(),
        ) {
            (3 | 4, None, None) => 10,
            (5 | 6, Some(_), None) => 11,
            (7, Some(_), Some(_)) => 12,
            _ => {
                return Err(serde::ser::Error::custom(
                    "invalid checkpoint extension version",
                ));
            }
        };
        let mut tuple = serializer.serialize_tuple(field_count)?;
        tuple.serialize_element(&self.format_version)?;
        tuple.serialize_element(&self.guild_id)?;
        tuple.serialize_element(&self.genesis_hash)?;
        tuple.serialize_element(&self.generation)?;
        tuple.serialize_element(&self.parent)?;
        tuple.serialize_element(&self.members)?;
        tuple.serialize_element(&self.writer_fences)?;
        tuple.serialize_element(&self.revision_tombstones)?;
        tuple.serialize_element(&self.revisions)?;
        tuple.serialize_element(&self.coding_groups)?;
        if let Some(authority) = self.authority {
            tuple.serialize_element(&authority)?;
        }
        if let Some(catalog) = &self.packing_catalog {
            tuple.serialize_element(catalog)?;
        }
        tuple.end()
    }
}

impl<'de> Deserialize<'de> for GuildCheckpoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct GuildCheckpointVisitor;

        impl<'de> Visitor<'de> for GuildCheckpointVisitor {
            type Value = GuildCheckpoint;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a versioned guild checkpoint")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let format_version = next_checkpoint_field(&mut sequence, "format version")?;
                let guild_id = next_checkpoint_field(&mut sequence, "guild ID")?;
                let genesis_hash = next_checkpoint_field(&mut sequence, "genesis hash")?;
                let generation = next_checkpoint_field(&mut sequence, "generation")?;
                let parent = next_checkpoint_field(&mut sequence, "parent")?;
                let members = next_checkpoint_field(&mut sequence, "members")?;
                let writer_fences = next_checkpoint_field(&mut sequence, "writer fences")?;
                let revision_tombstones =
                    next_checkpoint_field(&mut sequence, "revision tombstones")?;
                let revisions = next_checkpoint_field(&mut sequence, "revisions")?;
                let coding_groups = next_checkpoint_field(&mut sequence, "coding groups")?;
                let authority = match format_version {
                    3 | 4 => None,
                    5..=7 => Some(next_checkpoint_field(&mut sequence, "authority")?),
                    _ => return Err(serde::de::Error::custom("invalid checkpoint version")),
                };
                let packing_catalog = match format_version {
                    3..=6 => None,
                    7 => Some(next_checkpoint_field(&mut sequence, "packing catalog")?),
                    _ => return Err(serde::de::Error::custom("invalid checkpoint version")),
                };
                Ok(GuildCheckpoint {
                    format_version,
                    guild_id,
                    genesis_hash,
                    generation,
                    parent,
                    members,
                    writer_fences,
                    revision_tombstones,
                    revisions,
                    coding_groups,
                    authority,
                    packing_catalog,
                })
            }
        }

        deserializer.deserialize_tuple(12, GuildCheckpointVisitor)
    }
}

fn next_checkpoint_field<'de, A, T>(sequence: &mut A, name: &'static str) -> Result<T, A::Error>
where
    A: SeqAccess<'de>,
    T: Deserialize<'de>,
{
    sequence
        .next_element()?
        .ok_or_else(|| serde::de::Error::missing_field(name))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MemberSignature {
    pub signer: NodeId,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumCheckpoint {
    pub checkpoint: GuildCheckpoint,
    pub signatures: Vec<MemberSignature>,
}

impl GuildCheckpoint {
    pub fn validate(&self) -> Result<(), ModelError> {
        if !matches!(self.format_version, 3..=7)
            || self.genesis_hash == [0; 32]
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || (self.generation == 1) != self.parent.is_none()
            || match self.format_version {
                3 => self.members.len() != 5,
                4..=7 => self.members.is_empty() || self.members.len() > 256,
                _ => true,
            }
            || self.revisions.is_empty()
            || self.revisions.len() > 4096
            || (self.format_version == 3 && self.coding_groups.is_empty())
            || self.coding_groups.len() > V1_MAX_CODING_GROUPS
        {
            return Err(ModelError::InvalidCheckpoint);
        }
        match (
            self.format_version,
            self.authority,
            self.packing_catalog.as_ref(),
        ) {
            (3 | 4, None, None) => {}
            (5 | 6, Some(authority), None)
                if authority.format_version == 1
                    && authority.membership_epoch > 0
                    && authority.quorum.required(self.members.len()).is_ok() => {}
            (7, Some(authority), Some(catalog))
                if authority.format_version == 1
                    && authority.membership_epoch > 0
                    && authority.quorum.required(self.members.len()).is_ok()
                    && catalog.validate().is_ok() => {}
            _ => return Err(ModelError::InvalidCheckpoint),
        }
        let mut member_ids = std::collections::BTreeSet::new();
        let mut failure_domains = std::collections::BTreeMap::new();
        let mut previous_member = None;
        for member in &self.members {
            if previous_member.is_some_and(|previous| previous >= member.node_id)
                || !member_ids.insert(member.node_id)
                || member.failure_domain.is_empty()
                || member.failure_domain.len() > 256
                || !member.recovery_public_key.is_contributory()
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            let key = VerifyingKey::from_bytes(&member.node_id.0)?;
            if key.is_weak() {
                return Err(ModelError::WeakPublicKey);
            }
            failure_domains.insert(member.node_id, member.failure_domain.as_str());
            previous_member = Some(member.node_id);
        }

        let mut revision_ids = std::collections::BTreeSet::new();
        let mut revision_order = None;
        let mut revision_sectors = std::collections::BTreeMap::new();
        let mut scoped_revision_sectors = std::collections::BTreeMap::new();
        let mut revision_heads =
            std::collections::BTreeMap::<(NodeId, Uuid), (u64, [u8; 32], u64)>::new();
        let mut fences = std::collections::BTreeMap::<(NodeId, u64), [u8; 32]>::new();
        let mut latest_fences = std::collections::BTreeMap::<NodeId, u64>::new();
        let mut previous_fence = None;
        for fence in &self.writer_fences {
            let order = (fence.owner, fence.epoch);
            let key = VerifyingKey::from_bytes(&fence.public_key)?;
            if previous_fence.is_some_and(|previous| previous >= order)
                || self.format_version == 3 && !member_ids.contains(&fence.owner)
                || fence.epoch == 0
                || key.is_weak()
                || fences.insert(order, fence.public_key).is_some()
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            match latest_fences.insert(fence.owner, fence.epoch) {
                Some(previous) if previous.checked_add(1) == Some(fence.epoch) => {}
                None if fence.epoch == 1 => {}
                _ => return Err(ModelError::InvalidCheckpoint),
            }
            previous_fence = Some(order);
        }
        let mut tombstones =
            std::collections::BTreeMap::<(NodeId, Uuid), &RevisionTombstone>::new();
        let mut previous_tombstone = None;
        for tombstone in &self.revision_tombstones {
            let order = (tombstone.owner, tombstone.protected_root_id);
            if previous_tombstone.is_some_and(|previous| previous >= order)
                || self.format_version == 3 && !member_ids.contains(&tombstone.owner)
                || tombstone.protected_root_id.is_nil()
                || tombstone.through_sequence == 0
                || tombstone.last_revision_id.is_nil()
                || tombstone.last_revision_hash == [0; 32]
                || tombstone.retired_at_generation < 2
                || tombstone.retired_at_generation > self.generation
                || tombstones.insert(order, tombstone).is_some()
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            previous_tombstone = Some(order);
        }
        for revision in &self.revisions {
            revision.verify(USER_REVISION_DOMAIN)?;
            revision.value.verify_writer()?;
            let order = (
                revision.value.owner,
                revision.value.protected_root_id,
                revision.value.sequence,
                revision.value.revision_id,
            );
            if revision_order.is_some_and(|previous| previous >= order)
                || revision.signer != revision.value.owner
                || self.format_version == 3 && !member_ids.contains(&revision.signer)
                || revision.value.format_version != 3
                || revision.value.guild_id != self.guild_id
                || revision.value.protected_root_id.is_nil()
                || revision.value.cipher_profile != V1_CIPHER_PROFILE
                || revision.value.sequence == 0
                || revision.value.metadata_sectors.is_empty()
                || !revision_ids.insert(revision.value.revision_id)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            if fences.get(&(revision.value.owner, revision.value.writer_epoch))
                != Some(&revision.value.writer_public_key)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            let chain = (revision.value.owner, revision.value.protected_root_id);
            match revision_heads.get(&chain) {
                Some((previous_sequence, previous_hash, previous_writer_epoch))
                    if previous_sequence.checked_add(1) == Some(revision.value.sequence)
                        && revision.value.parent == Some(*previous_hash)
                        && revision.value.writer_epoch >= *previous_writer_epoch => {}
                None => match tombstones.get(&chain) {
                    Some(tombstone)
                        if tombstone.through_sequence.checked_add(1)
                            == Some(revision.value.sequence)
                            && revision.value.parent == Some(tombstone.last_revision_hash) => {}
                    None if revision.value.sequence == 1 && revision.value.parent.is_none() => {}
                    _ => return Err(ModelError::InvalidCheckpoint),
                },
                Some(_) => return Err(ModelError::InvalidCheckpoint),
            }
            for reference in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
            {
                if reference.logical_len == 0 || reference.logical_len as usize > V1_SECTOR_SIZE {
                    return Err(ModelError::InvalidCheckpoint);
                }
                let scoped = (
                    revision.value.owner,
                    revision.value.protected_root_id,
                    reference.clone(),
                );
                if scoped_revision_sectors
                    .insert(reference.id, scoped.clone())
                    .is_some_and(|previous| previous != scoped)
                {
                    return Err(ModelError::InvalidCheckpoint);
                }
                revision_sectors
                    .entry(reference.id)
                    .or_insert((revision.value.owner, reference.clone()));
            }
            revision_heads.insert(
                chain,
                (
                    revision.value.sequence,
                    revision.value.hash()?,
                    revision.value.writer_epoch,
                ),
            );
            revision_order = Some(order);
        }
        for (owner, latest_epoch) in &latest_fences {
            if !revision_heads
                .iter()
                .any(|((head_owner, _), (_, _, epoch))| {
                    head_owner == owner && epoch == latest_epoch
                })
            {
                return Err(ModelError::InvalidCheckpoint);
            }
        }
        if !tombstones
            .keys()
            .all(|chain| revision_heads.contains_key(chain))
        {
            return Err(ModelError::InvalidCheckpoint);
        }
        if let Some(catalog) = &self.packing_catalog {
            let expected = scoped_revision_sectors
                .iter()
                .map(|(sector_id, (owner, protected_root_id, _))| {
                    (
                        *owner,
                        packing_protected_root(*protected_root_id),
                        *sector_id,
                    )
                })
                .collect::<std::collections::BTreeSet<_>>();
            let mut actual = std::collections::BTreeMap::<_, u64>::new();
            for source in catalog
                .sectors
                .iter()
                .flat_map(|sector| &sector.slots)
                .filter_map(|slot| slot.source())
            {
                *actual
                    .entry((
                        source.id.owner,
                        source.id.protected_root,
                        source.id.object_id,
                    ))
                    .or_default() += u64::from(source.logical_len);
            }
            if actual
                .keys()
                .copied()
                .collect::<std::collections::BTreeSet<_>>()
                != expected
                || actual.values().any(|bytes| *bytes != V1_SECTOR_SIZE as u64)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
        }

        let mut group_ids = std::collections::BTreeSet::new();
        let mut previous_group = None;
        let mut information_ids = std::collections::BTreeSet::new();
        let mut covered_revision_sectors = std::collections::BTreeSet::new();
        for group in &self.coding_groups {
            if previous_group.is_some_and(|previous| previous >= group.id)
                || !group_ids.insert(group.id)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            validate_group(
                group,
                self.guild_id,
                &failure_domains,
                &revision_sectors,
                &mut information_ids,
                &mut covered_revision_sectors,
            )?;
            previous_group = Some(group.id);
        }
        if self.format_version == 3
            && (covered_revision_sectors.len() != revision_sectors.len()
                || !revision_sectors
                    .keys()
                    .all(|id| covered_revision_sectors.contains(id)))
        {
            return Err(ModelError::InvalidCheckpoint);
        }
        Ok(())
    }

    pub fn member_signature(&self, keys: &KeyMaterial) -> Result<MemberSignature, ModelError> {
        let signer = keys.node_id();
        if !self.members.iter().any(|member| member.node_id == signer) {
            return Err(ModelError::NonMemberSigner(signer));
        }
        self.validate()?;
        Ok(MemberSignature {
            signer,
            signature: keys
                .sign(b"mutualbackup/guild-checkpoint/v1", &canonical_bytes(self)?)
                .to_vec(),
        })
    }

    pub fn verify_member_signature(
        &self,
        member_signature: &MemberSignature,
    ) -> Result<(), ModelError> {
        self.validate()?;
        if !self
            .members
            .iter()
            .any(|member| member.node_id == member_signature.signer)
        {
            return Err(ModelError::NonMemberSigner(member_signature.signer));
        }
        let key = VerifyingKey::from_bytes(&member_signature.signer.0)?;
        if key.is_weak() {
            return Err(ModelError::WeakPublicKey);
        }
        let signature = Signature::from_slice(&member_signature.signature)?;
        key.verify_strict(
            &signing_payload(b"mutualbackup/guild-checkpoint/v1", &canonical_bytes(self)?),
            &signature,
        )?;
        Ok(())
    }
}

impl GuildGenesis {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.format_version != 1
            || self.guild_id == [0; 32]
            || self.members.len() != 5
            || !self
                .members
                .iter()
                .any(|member| member.node_id == self.coordinator)
        {
            return Err(ModelError::InvalidGenesis);
        }
        validate_members(&self.members).map_err(|_| ModelError::InvalidGenesis)
    }

    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        self.validate()?;
        let mut hasher = blake3::Hasher::new_derive_key("mutualbackup guild genesis v1");
        hasher.update(&canonical_bytes(self)?);
        Ok(*hasher.finalize().as_bytes())
    }

    pub fn member_signature(&self, keys: &KeyMaterial) -> Result<MemberSignature, ModelError> {
        self.validate()?;
        let signer = keys.node_id();
        if !self.members.iter().any(|member| member.node_id == signer) {
            return Err(ModelError::NonMemberSigner(signer));
        }
        Ok(MemberSignature {
            signer,
            signature: keys
                .sign(b"mutualbackup/guild-genesis/v1", &canonical_bytes(self)?)
                .to_vec(),
        })
    }
}

impl QuorumGuildGenesis {
    pub fn verify(&self) -> Result<(), ModelError> {
        self.genesis.validate()?;
        let encoded = canonical_bytes(&self.genesis)?;
        let member_ids = self
            .genesis
            .members
            .iter()
            .map(|member| member.node_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = None;
        let mut signers = std::collections::BTreeSet::new();
        for signature in &self.signatures {
            if !member_ids.contains(&signature.signer)
                || previous.is_some_and(|node_id| node_id >= signature.signer)
                || !signers.insert(signature.signer)
            {
                return Err(ModelError::InvalidGenesis);
            }
            let key = VerifyingKey::from_bytes(&signature.signer.0)?;
            if key.is_weak() {
                return Err(ModelError::WeakPublicKey);
            }
            key.verify_strict(
                &signing_payload(b"mutualbackup/guild-genesis/v1", &encoded),
                &Signature::from_slice(&signature.signature)?,
            )?;
            previous = Some(signature.signer);
        }
        if signers.len() != member_ids.len() {
            return Err(ModelError::InsufficientQuorum {
                actual: signers.len(),
                required: member_ids.len(),
            });
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        self.verify()?;
        self.genesis.hash()
    }
}

impl GuildInvite {
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.format_version != 1
            || self.guild_id == [0; 32]
            || self.coordinator_endpoints.is_empty()
            || self.coordinator_endpoints.len() > V1_MAX_ENDPOINTS_PER_PEER
            || self
                .coordinator_endpoints
                .iter()
                .any(|endpoint| endpoint.is_empty() || endpoint.len() > V1_MAX_ENDPOINT_BYTES)
            || self.nonce == [0; 16]
            || self.expires_at_unix_seconds == 0
            || validate_members(std::slice::from_ref(&self.coordinator)).is_err()
        {
            return Err(ModelError::InvalidInvite);
        }
        Ok(())
    }
}

impl QuorumCheckpoint {
    pub fn add_signature(&mut self, keys: &KeyMaterial) -> Result<(), ModelError> {
        let member_signature = self.checkpoint.member_signature(keys)?;
        let signer = member_signature.signer;
        self.signatures.retain(|entry| entry.signer != signer);
        self.signatures.push(member_signature);
        self.signatures.sort_by_key(|entry| entry.signer);
        Ok(())
    }

    pub fn verify(&self) -> Result<(), ModelError> {
        self.checkpoint.validate()?;
        let member_ids = self
            .checkpoint
            .members
            .iter()
            .map(|member| member.node_id)
            .collect::<std::collections::BTreeSet<_>>();

        let encoded = canonical_bytes(&self.checkpoint)?;
        let mut valid_signers = std::collections::BTreeSet::new();
        let mut previous_signer = None;
        for member_signature in &self.signatures {
            if !member_ids.contains(&member_signature.signer)
                || previous_signer.is_some_and(|previous| previous >= member_signature.signer)
                || !valid_signers.insert(member_signature.signer)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            let key = VerifyingKey::from_bytes(&member_signature.signer.0)?;
            if key.is_weak() {
                return Err(ModelError::WeakPublicKey);
            }
            let signature = Signature::from_slice(&member_signature.signature)?;
            key.verify_strict(
                &signing_payload(b"mutualbackup/guild-checkpoint/v1", &encoded),
                &signature,
            )?;
            previous_signer = Some(member_signature.signer);
        }
        // Legacy certificates used each member signature as both checkpoint
        // authorization and storage attestation. Authority-bearing versions
        // separate those facts: replayable coding transcripts contain signed
        // holder receipts, so the epoch-bound guild policy authorizes the
        // checkpoint itself.
        let quorum = match self.checkpoint.authority {
            Some(authority) if matches!(self.checkpoint.format_version, 5..=7) => authority
                .quorum
                .required(member_ids.len())
                .map_err(|_| ModelError::InvalidCheckpoint)?,
            _ => self.checkpoint.members.len(),
        };
        if valid_signers.len() < quorum {
            return Err(ModelError::InsufficientQuorum {
                actual: valid_signers.len(),
                required: quorum,
            });
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        self.checkpoint.hash()
    }

    pub fn has_signature(&self, signer: NodeId) -> bool {
        self.signatures
            .binary_search_by_key(&signer, |signature| signature.signer)
            .is_ok()
    }

    pub fn authorizes_member_recovery(&self, subject: NodeId) -> bool {
        self.checkpoint
            .members
            .binary_search_by_key(&subject, |member| member.node_id)
            .is_ok()
            && (self.checkpoint.format_version >= 5 || self.has_signature(subject))
    }

    pub fn validate_recovery_authority(
        &self,
        keys: &KeyMaterial,
        locator: &RecoveryLocator,
        directory_publisher: NodeId,
    ) -> Result<(), ModelError> {
        self.verify()?;
        let subject = keys.node_id();
        let member = self
            .checkpoint
            .members
            .iter()
            .find(|member| member.node_id == subject)
            .ok_or(ModelError::InvalidRecoveryAuthority)?;
        if locator.format_version != 1
            || locator.subject != subject
            || locator.publisher != directory_publisher
            || locator.guild_id != self.checkpoint.guild_id
            || locator.checkpoint_generation != self.checkpoint.generation
            || locator.checkpoint_hash != self.hash()?
            || locator.subject_endpoint_sequence_floor == u64::MAX
            || locator.expires_at_unix_seconds == 0
            || locator.endpoints.is_empty()
            || locator.endpoints.len() > V1_MAX_ENDPOINTS_PER_PEER
            || locator
                .endpoints
                .iter()
                .any(|endpoint| endpoint.is_empty() || endpoint.len() > V1_MAX_ENDPOINT_BYTES)
            || member.recovery_public_key != keys.recovery_public_key()
            || !self
                .checkpoint
                .members
                .iter()
                .any(|member| member.node_id == locator.publisher)
            || !self.authorizes_member_recovery(subject)
        {
            return Err(ModelError::InvalidRecoveryAuthority);
        }
        Ok(())
    }
}

impl GuildCheckpoint {
    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        Ok(*blake3::hash(&canonical_bytes(self)?).as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserRevision {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub protected_root_id: Uuid,
    pub cipher_profile: u16,
    pub revision_id: Uuid,
    pub owner: NodeId,
    pub writer_epoch: u64,
    pub writer_public_key: [u8; 32],
    pub writer_signature: Vec<u8>,
    pub sequence: u64,
    pub parent: Option<[u8; 32]>,
    pub metadata_sectors: Vec<SectorRef>,
    pub data_sectors: Vec<SectorRef>,
}

impl UserRevision {
    pub fn sign_writer(&mut self, signing_key: &SigningKey) -> Result<(), ModelError> {
        if signing_key.verifying_key().to_bytes() != self.writer_public_key {
            return Err(ModelError::InvalidWriterFence);
        }
        self.writer_signature.clear();
        self.writer_signature = signing_key
            .sign(&signing_payload(
                WRITER_REVISION_DOMAIN,
                &canonical_bytes(self)?,
            ))
            .to_vec();
        Ok(())
    }

    pub fn verify_writer(&self) -> Result<(), ModelError> {
        if self.writer_epoch == 0 || self.writer_signature.len() != 64 {
            return Err(ModelError::InvalidWriterFence);
        }
        let key = VerifyingKey::from_bytes(&self.writer_public_key)?;
        if key.is_weak() {
            return Err(ModelError::WeakPublicKey);
        }
        let mut unsigned = self.clone();
        unsigned.writer_signature.clear();
        key.verify_strict(
            &signing_payload(WRITER_REVISION_DOMAIN, &canonical_bytes(&unsigned)?),
            &Signature::from_slice(&self.writer_signature)?,
        )?;
        Ok(())
    }

    /// Stable identity used by the next revision's `parent` field.
    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        let mut hasher = blake3::Hasher::new_derive_key("mutualbackup user revision body v3");
        hasher.update(&canonical_bytes(self)?);
        Ok(*hasher.finalize().as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignedRecord<T> {
    pub signer: NodeId,
    pub value: T,
    pub signature: Vec<u8>,
}

impl<T: Serialize> SignedRecord<T> {
    pub fn sign(domain: &'static [u8], value: T, keys: &KeyMaterial) -> Result<Self, ModelError> {
        let encoded = canonical_bytes(&value)?;
        Ok(Self {
            signer: keys.node_id(),
            signature: keys.sign(domain, &encoded).to_vec(),
            value,
        })
    }

    pub fn verify(&self, domain: &'static [u8]) -> Result<(), ModelError> {
        let key = VerifyingKey::from_bytes(&self.signer.0)?;
        if key.is_weak() {
            return Err(ModelError::WeakPublicKey);
        }
        let signature = Signature::from_slice(&self.signature)?;
        key.verify_strict(
            &signing_payload(domain, &canonical_bytes(&self.value)?),
            &signature,
        )?;
        Ok(())
    }
}

pub fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ModelError> {
    postcard::to_stdvec(value).map_err(ModelError::Encode)
}

pub fn decode_canonical<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ModelError> {
    postcard::from_bytes(bytes).map_err(ModelError::Decode)
}

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("canonical encode failed: {0}")]
    Encode(postcard::Error),
    #[error("canonical decode failed: {0}")]
    Decode(postcard::Error),
    #[error("invalid Ed25519 key: {0}")]
    PublicKey(#[from] ed25519_dalek::SignatureError),
    #[error("invalid guild checkpoint")]
    InvalidCheckpoint,
    #[error("invalid guild genesis")]
    InvalidGenesis,
    #[error("invalid guild invite")]
    InvalidInvite,
    #[error("invalid parity storage acknowledgement")]
    InvalidStorageAcknowledgement,
    #[error("revision is not authorized by its writer incarnation")]
    InvalidWriterFence,
    #[error("weak Ed25519 public key is not accepted")]
    WeakPublicKey,
    #[error("checkpoint is not authorized by the recovering seed")]
    InvalidRecoveryAuthority,
    #[error("checkpoint signature is from non-member {0}")]
    NonMemberSigner(NodeId),
    #[error("checkpoint has {actual} valid signatures but requires {required}")]
    InsufficientQuorum { actual: usize, required: usize },
    #[error("coding group assigns more than one shard to failure domain {0}")]
    ReusedFailureDomain(String),
    #[error("parity shard does not encode the declared information shards")]
    InvalidCodingRelation,
    #[error("Reed--Solomon validation failed: {0}")]
    Coding(#[from] crate::CodingError),
    #[error("Merkle range validation failed: {0}")]
    Merkle(#[from] crate::MerkleError),
}

fn validate_members(members: &[Member]) -> Result<(), ModelError> {
    let mut previous = None;
    let mut node_ids = std::collections::BTreeSet::new();
    let mut failure_domains = std::collections::BTreeSet::new();
    for member in members {
        if previous.is_some_and(|node_id| node_id >= member.node_id)
            || !node_ids.insert(member.node_id)
            || !failure_domains.insert(member.failure_domain.as_str())
            || member.failure_domain.is_empty()
            || member.failure_domain.len() > 256
            || !member.recovery_public_key.is_contributory()
        {
            return Err(ModelError::InvalidGenesis);
        }
        let key = VerifyingKey::from_bytes(&member.node_id.0)?;
        if key.is_weak() {
            return Err(ModelError::WeakPublicKey);
        }
        previous = Some(member.node_id);
    }
    Ok(())
}

fn validate_group(
    group: &CodingGroup,
    guild_id: [u8; 32],
    failure_domains: &std::collections::BTreeMap<NodeId, &str>,
    revision_sectors: &std::collections::BTreeMap<SectorId, (NodeId, SectorRef)>,
    information_ids: &mut std::collections::BTreeSet<SectorId>,
    covered_revision_sectors: &mut std::collections::BTreeSet<SectorId>,
) -> Result<(), ModelError> {
    validate_group_profile(group)?;
    if group.guild_id != guild_id {
        return Err(ModelError::InvalidCheckpoint);
    }
    let mut used_domains = std::collections::BTreeSet::new();
    let mut covered_in_group = 0_usize;
    for (index, role) in group.roles.iter().enumerate() {
        let node_id = match role {
            ShardRole::Information(information)
                if index < V1_RS_DATA_SHARDS as usize
                    && information.sector.logical_len as usize <= V1_SECTOR_SIZE =>
            {
                if !information_ids.insert(information.sector.id) {
                    return Err(ModelError::InvalidCheckpoint);
                }
                if let Some((owner, reference)) = revision_sectors.get(&information.sector.id) {
                    if *owner != information.owner
                        || reference != &information.sector
                        || !covered_revision_sectors.insert(information.sector.id)
                    {
                        return Err(ModelError::InvalidCheckpoint);
                    }
                    covered_in_group += 1;
                }
                information.owner
            }
            ShardRole::Parity(parity)
                if index >= V1_RS_DATA_SHARDS as usize
                    && parity.row == (index - V1_RS_DATA_SHARDS as usize) as u16 =>
            {
                parity.holder
            }
            _ => return Err(ModelError::InvalidCheckpoint),
        };
        let domain = failure_domains
            .get(&node_id)
            .ok_or(ModelError::InvalidCheckpoint)?;
        if !used_domains.insert(*domain) {
            return Err(ModelError::ReusedFailureDomain((*domain).to_owned()));
        }
    }
    if covered_in_group == 0 {
        return Err(ModelError::InvalidCheckpoint);
    }
    Ok(())
}

fn validate_group_profile(group: &CodingGroup) -> Result<(), ModelError> {
    if group.format_version != 1
        || group.data_shards != V1_RS_DATA_SHARDS
        || group.parity_shards != V1_RS_PARITY_SHARDS
        || group.shard_size as usize != V1_SECTOR_SIZE
        || group.calculate_id()? != group.id
    {
        return Err(ModelError::InvalidCheckpoint);
    }
    for (index, role) in group.roles.iter().enumerate() {
        match role {
            ShardRole::Information(information)
                if index < V1_RS_DATA_SHARDS as usize
                    && information.sector.logical_len as usize <= V1_SECTOR_SIZE => {}
            ShardRole::Parity(parity)
                if index >= V1_RS_DATA_SHARDS as usize
                    && parity.row == (index - V1_RS_DATA_SHARDS as usize) as u16 => {}
            _ => return Err(ModelError::InvalidCheckpoint),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Seed;

    #[test]
    fn signed_record_rejects_tampering() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([11; 32]));
        let mut record = SignedRecord::sign(b"test/member/v1", 41_u64, &keys).unwrap();
        record.verify(b"test/member/v1").unwrap();
        record.value = 42;
        assert!(record.verify(b"test/member/v1").is_err());

        let weak = SignedRecord {
            signer: NodeId([0; 32]),
            value: 1_u8,
            signature: vec![0; 64],
        };
        assert!(weak.verify(b"test/member/v1").is_err());
    }

    #[test]
    fn recovery_bundle_v1_keeps_its_legacy_canonical_layout() {
        #[derive(Serialize)]
        struct LegacyRecoveryBundle {
            format_version: u16,
            subject: NodeId,
            publisher: NodeId,
            sequence: u64,
            expires_at_unix_seconds: u64,
            sealed: SealedRecoveryRecord,
        }

        let legacy = LegacyRecoveryBundle {
            format_version: 1,
            subject: NodeId([12; 32]),
            publisher: NodeId([13; 32]),
            sequence: 14,
            expires_at_unix_seconds: 15,
            sealed: SealedRecoveryRecord {
                format_version: 1,
                ephemeral_public_key: [16; 32],
                nonce: [17; 24],
                ciphertext: vec![18; 32],
            },
        };
        let legacy_bytes = canonical_bytes(&legacy).unwrap();
        let decoded: RecoveryBundle = decode_canonical(&legacy_bytes).unwrap();
        assert_eq!(decoded.format_version, 1);
        assert!(decoded.key_envelope.is_none());
        assert_eq!(canonical_bytes(&decoded).unwrap(), legacy_bytes);

        let version_two = RecoveryBundle {
            format_version: 2,
            subject: NodeId([21; 32]),
            publisher: NodeId([22; 32]),
            sequence: 23,
            expires_at_unix_seconds: 24,
            key_envelope: Some(RecoveryKeyEnvelope {
                format_version: 1,
                guild_id: [25; 32],
                subject: NodeId([21; 32]),
                epoch: 2,
                public_key: RecoveryPublicKey([26; 32]),
                sealed_private_key: SealedRecoveryRecord {
                    format_version: 1,
                    ephemeral_public_key: [27; 32],
                    nonce: [28; 24],
                    ciphertext: vec![29; 48],
                },
            }),
            sealed: SealedRecoveryRecord {
                format_version: 1,
                ephemeral_public_key: [30; 32],
                nonce: [31; 24],
                ciphertext: vec![32; 64],
            },
        };
        assert_eq!(
            decode_canonical::<RecoveryBundle>(&canonical_bytes(&version_two).unwrap()).unwrap(),
            version_two
        );
        let signer = KeyMaterial::from_seed(&Seed::from_bytes([33; 32]));
        for bundle in [decoded, version_two] {
            let signed =
                SignedRecord::sign(b"mutualbackup/recovery-bundle/v1", bundle, &signer).unwrap();
            let reopened: SignedRecord<RecoveryBundle> =
                decode_canonical(&canonical_bytes(&signed).unwrap()).unwrap();
            reopened.verify(b"mutualbackup/recovery-bundle/v1").unwrap();
            assert_eq!(reopened, signed);
        }
    }

    #[test]
    fn guild_genesis_requires_all_five_member_signatures() {
        let keys = (1_u8..=5)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value; 32])))
            .collect::<Vec<_>>();
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| Member {
                node_id: key.node_id(),
                recovery_public_key: key.recovery_public_key(),
                failure_domain: format!("host-{index}"),
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.node_id);
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: [9; 32],
            coordinator: keys[0].node_id(),
            members,
        };
        genesis.validate().unwrap();

        let mut certificate = QuorumGuildGenesis {
            signatures: keys
                .iter()
                .map(|key| genesis.member_signature(key).unwrap())
                .collect(),
            genesis,
        };
        certificate
            .signatures
            .sort_by_key(|signature| signature.signer);
        certificate.verify().unwrap();
        certificate.signatures.pop();
        assert!(matches!(
            certificate.verify(),
            Err(ModelError::InsufficientQuorum {
                actual: 4,
                required: 5
            })
        ));
    }

    #[test]
    fn guild_invite_is_structurally_bounded() {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([17; 32]));
        let mut invite = GuildInvite {
            format_version: 1,
            guild_id: [3; 32],
            coordinator: Member {
                node_id: keys.node_id(),
                recovery_public_key: keys.recovery_public_key(),
                failure_domain: "coordinator-host".into(),
            },
            coordinator_endpoints: vec!["/ip4/127.0.0.1/udp/4000/quic-v1/p2p/peer-id".into()],
            nonce: [4; 16],
            expires_at_unix_seconds: 1,
        };
        invite.validate().unwrap();
        invite.coordinator_endpoints = vec![String::new()];
        assert!(matches!(invite.validate(), Err(ModelError::InvalidInvite)));
    }

    #[test]
    fn checkpoint_requires_quorum_and_unique_failure_domains() {
        let keys = (0_u8..5)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value; 32])))
            .collect::<Vec<_>>();
        let mut members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| Member {
                node_id: key.node_id(),
                recovery_public_key: key.recovery_public_key(),
                failure_domain: format!("host-{index}"),
            })
            .collect::<Vec<_>>();
        let target = SectorRef {
            id: [1; 32],
            root: [2; 32],
            logical_len: 1,
        };
        let helper_a = SectorRef {
            id: [6; 32],
            root: [7; 32],
            logical_len: 0,
        };
        let helper_b = SectorRef {
            id: [8; 32],
            root: [9; 32],
            logical_len: 0,
        };
        let guild_id = [7; 32];
        let roles = [
            ShardRole::Information(InformationRole {
                owner: members[0].node_id,
                sector: target.clone(),
            }),
            ShardRole::Information(InformationRole {
                owner: members[1].node_id,
                sector: helper_a,
            }),
            ShardRole::Information(InformationRole {
                owner: members[2].node_id,
                sector: helper_b,
            }),
            ShardRole::Parity(ParityRole {
                holder: members[3].node_id,
                row: 0,
                root: [4; 32],
            }),
            ShardRole::Parity(ParityRole {
                holder: members[4].node_id,
                row: 1,
                root: [5; 32],
            }),
        ];
        let mut group = CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id,
            data_shards: V1_RS_DATA_SHARDS,
            parity_shards: V1_RS_PARITY_SHARDS,
            shard_size: 64 * 1024,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let writer = SigningKey::from_bytes(&[77; 32]);
        let mut revision_body = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_u128(99),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: Uuid::from_u128(1),
            owner: keys[0].node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![target],
            data_sectors: Vec::new(),
        };
        revision_body.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision_body, &keys[0]).unwrap();
        members.sort_by_key(|member| member.node_id);
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 3,
                guild_id,
                genesis_hash: [10; 32],
                generation: 1,
                parent: None,
                members,
                writer_fences: vec![WriterFence {
                    owner: keys[0].node_id(),
                    epoch: 1,
                    public_key: writer.verifying_key().to_bytes(),
                }],
                revision_tombstones: Vec::new(),
                revisions: vec![revision],
                coding_groups: vec![group],
                authority: None,
                packing_catalog: None,
            },
            signatures: Vec::new(),
        };
        for key in keys.iter().take(2) {
            checkpoint.add_signature(key).unwrap();
        }
        assert!(matches!(
            checkpoint.verify(),
            Err(ModelError::InsufficientQuorum { .. })
        ));
        for key in keys.iter().skip(2) {
            checkpoint.add_signature(key).unwrap();
        }
        checkpoint.verify().unwrap();

        let mut variable_checkpoint = checkpoint.checkpoint.clone();
        variable_checkpoint.format_version = 4;
        variable_checkpoint.coding_groups.clear();
        variable_checkpoint.validate().unwrap();

        let mut second_root = variable_checkpoint.revisions[0].value.clone();
        second_root.protected_root_id = Uuid::from_u128(100);
        second_root.revision_id = Uuid::from_u128(2);
        second_root.metadata_sectors[0].id = [21; 32];
        second_root.metadata_sectors[0].root = [22; 32];
        second_root.writer_signature.clear();
        second_root.sign_writer(&writer).unwrap();
        variable_checkpoint
            .revisions
            .push(SignedRecord::sign(USER_REVISION_DOMAIN, second_root, &keys[0]).unwrap());
        variable_checkpoint.revisions.sort_by_key(|revision| {
            (
                revision.value.owner,
                revision.value.protected_root_id,
                revision.value.sequence,
                revision.value.revision_id,
            )
        });
        variable_checkpoint.validate().unwrap();
        let mut changed_root = variable_checkpoint.revisions[0].clone();
        changed_root.value.protected_root_id = Uuid::from_u128(101);
        assert!(changed_root.verify(USER_REVISION_DOMAIN).is_err());

        #[derive(Serialize)]
        struct LegacyGuildCheckpoint {
            format_version: u16,
            guild_id: [u8; 32],
            genesis_hash: [u8; 32],
            generation: u64,
            parent: Option<[u8; 32]>,
            members: Vec<Member>,
            writer_fences: Vec<WriterFence>,
            revision_tombstones: Vec<RevisionTombstone>,
            revisions: Vec<SignedRecord<UserRevision>>,
            coding_groups: Vec<CodingGroup>,
        }
        let legacy_bytes = |body: &GuildCheckpoint| {
            canonical_bytes(&LegacyGuildCheckpoint {
                format_version: body.format_version,
                guild_id: body.guild_id,
                genesis_hash: body.genesis_hash,
                generation: body.generation,
                parent: body.parent,
                members: body.members.clone(),
                writer_fences: body.writer_fences.clone(),
                revision_tombstones: body.revision_tombstones.clone(),
                revisions: body.revisions.clone(),
                coding_groups: body.coding_groups.clone(),
            })
            .unwrap()
        };
        for legacy in [&checkpoint.checkpoint, &variable_checkpoint] {
            let encoded = canonical_bytes(legacy).unwrap();
            assert_eq!(encoded, legacy_bytes(legacy));
            assert_eq!(
                decode_canonical::<GuildCheckpoint>(&encoded).unwrap(),
                *legacy
            );
        }
        let legacy_certificate = canonical_bytes(&checkpoint).unwrap();
        assert_eq!(
            decode_canonical::<QuorumCheckpoint>(&legacy_certificate).unwrap(),
            checkpoint
        );

        variable_checkpoint
            .members
            .retain(|member| member.node_id != keys[0].node_id());
        variable_checkpoint.validate().unwrap();
        let mut dynamic_quorum = QuorumCheckpoint {
            checkpoint: variable_checkpoint.clone(),
            signatures: Vec::new(),
        };
        for key in &keys {
            if variable_checkpoint
                .members
                .iter()
                .any(|member| member.node_id == key.node_id())
            {
                dynamic_quorum.add_signature(key).unwrap();
            }
        }
        dynamic_quorum.verify().unwrap();
        let mut insufficient_dynamic = dynamic_quorum.clone();
        insufficient_dynamic.signatures.pop();
        assert!(matches!(
            insufficient_dynamic.verify(),
            Err(ModelError::InsufficientQuorum { .. })
        ));

        let mut policy_checkpoint = variable_checkpoint.clone();
        policy_checkpoint.format_version = 5;
        policy_checkpoint.authority = Some(CheckpointAuthority {
            format_version: 1,
            membership_epoch: 2,
            quorum: crate::QuorumPolicy {
                format_version: 1,
                rule: crate::QuorumRule::Majority,
            },
        });
        let sign_policy_checkpoint = |checkpoint: GuildCheckpoint| {
            let member_ids = checkpoint
                .members
                .iter()
                .map(|member| member.node_id)
                .collect::<std::collections::BTreeSet<_>>();
            let mut quorum = QuorumCheckpoint {
                checkpoint,
                signatures: Vec::new(),
            };
            for key in keys
                .iter()
                .filter(|key| member_ids.contains(&key.node_id()))
            {
                if quorum.signatures.len() == 3 {
                    break;
                }
                quorum.add_signature(key).unwrap();
            }
            quorum
        };
        let mut policy_quorum = sign_policy_checkpoint(policy_checkpoint);
        policy_quorum.verify().unwrap();
        let unsigned_member = policy_quorum
            .checkpoint
            .members
            .iter()
            .find(|member| !policy_quorum.has_signature(member.node_id))
            .unwrap()
            .node_id;
        assert!(policy_quorum.authorizes_member_recovery(unsigned_member));
        let mut root_scoped_checkpoint = policy_quorum.checkpoint.clone();
        root_scoped_checkpoint.format_version = 6;
        let root_scoped_quorum = sign_policy_checkpoint(root_scoped_checkpoint.clone());
        root_scoped_quorum.verify().unwrap();
        assert!(root_scoped_quorum.authorizes_member_recovery(unsigned_member));
        let root_scoped_bytes = canonical_bytes(&root_scoped_checkpoint).unwrap();
        assert_eq!(
            decode_canonical::<GuildCheckpoint>(&root_scoped_bytes).unwrap(),
            root_scoped_checkpoint
        );
        let packing_inputs = root_scoped_checkpoint
            .revisions
            .iter()
            .flat_map(|revision| {
                revision
                    .value
                    .metadata_sectors
                    .iter()
                    .chain(&revision.value.data_sectors)
                    .map(move |reference| crate::PackingInput {
                        owner: revision.value.owner,
                        protected_root: crate::packing_protected_root(
                            revision.value.protected_root_id,
                        ),
                        object_id: reference.id,
                        bytes: vec![reference.id[0]; V1_SECTOR_SIZE],
                    })
            })
            .collect();
        let packing = crate::pack_incremental(
            crate::PackingProfile {
                format_version: 1,
                sector_size: V1_SECTOR_SIZE as u32,
                slot_size: 16 * 1024,
            },
            None,
            packing_inputs,
        )
        .unwrap();
        let mut packed_checkpoint = root_scoped_checkpoint.clone();
        packed_checkpoint.format_version = 7;
        packed_checkpoint.packing_catalog = Some(packing.catalog);
        let packed_quorum = sign_policy_checkpoint(packed_checkpoint.clone());
        packed_quorum.verify().unwrap();
        assert!(packed_quorum.authorizes_member_recovery(unsigned_member));
        let packed_bytes = canonical_bytes(&packed_checkpoint).unwrap();
        assert_eq!(
            decode_canonical::<GuildCheckpoint>(&packed_bytes).unwrap(),
            packed_checkpoint
        );
        let mut invalid_signature = policy_quorum.signatures[0].clone();
        invalid_signature.signature[0] ^= 1;
        assert!(
            policy_quorum
                .checkpoint
                .verify_member_signature(&invalid_signature)
                .is_err()
        );
        policy_quorum.signatures.pop();
        assert!(matches!(
            policy_quorum.verify(),
            Err(ModelError::InsufficientQuorum {
                actual: 2,
                required: 3
            })
        ));

        variable_checkpoint.format_version = 3;
        assert!(matches!(
            variable_checkpoint.validate(),
            Err(ModelError::InvalidCheckpoint)
        ));

        let mut tampered_writer = checkpoint.checkpoint.clone();
        tampered_writer.revisions[0].value.writer_signature[0] ^= 1;
        tampered_writer.revisions[0] = SignedRecord::sign(
            USER_REVISION_DOMAIN,
            tampered_writer.revisions[0].value.clone(),
            &keys[0],
        )
        .unwrap();
        assert!(tampered_writer.validate().is_err());

        let locator = RecoveryLocator {
            format_version: 1,
            subject: keys[4].node_id(),
            publisher: keys[0].node_id(),
            guild_id,
            checkpoint_hash: checkpoint.hash().unwrap(),
            checkpoint_generation: 1,
            subject_endpoint_sequence_floor: 0,
            endpoints: vec!["tcp://127.0.0.1:1".to_owned()],
            expires_at_unix_seconds: u64::MAX,
        };
        checkpoint
            .validate_recovery_authority(&keys[4], &locator, keys[0].node_id())
            .unwrap();
        let mut empty_endpoint = locator.clone();
        empty_endpoint.endpoints = vec![String::new()];
        assert!(
            checkpoint
                .validate_recovery_authority(&keys[4], &empty_endpoint, keys[0].node_id())
                .is_err()
        );

        let mut chained = checkpoint.checkpoint.clone();
        let previous = chained.revisions[0].value.hash().unwrap();
        let next_target = SectorRef {
            id: [10; 32],
            root: [11; 32],
            logical_len: 1,
        };
        let mut next_revision = UserRevision {
            format_version: 3,
            guild_id,
            protected_root_id: Uuid::from_u128(99),
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id: Uuid::from_u128(2),
            owner: keys[0].node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 2,
            parent: Some(previous),
            metadata_sectors: vec![next_target.clone()],
            data_sectors: Vec::new(),
        };
        next_revision.sign_writer(&writer).unwrap();
        chained
            .revisions
            .push(SignedRecord::sign(USER_REVISION_DOMAIN, next_revision, &keys[0]).unwrap());
        let mut next_group = chained.coding_groups[0].clone();
        let ShardRole::Information(next_information) = &mut next_group.roles[0] else {
            unreachable!();
        };
        next_information.sector = next_target;
        let ShardRole::Information(next_helper_a) = &mut next_group.roles[1] else {
            unreachable!();
        };
        next_helper_a.sector.id = [12; 32];
        next_helper_a.sector.root = [13; 32];
        let ShardRole::Information(next_helper_b) = &mut next_group.roles[2] else {
            unreachable!();
        };
        next_helper_b.sector.id = [14; 32];
        next_helper_b.sector.root = [15; 32];
        let ShardRole::Parity(next_parity_a) = &mut next_group.roles[3] else {
            unreachable!();
        };
        next_parity_a.root = [16; 32];
        let ShardRole::Parity(next_parity_b) = &mut next_group.roles[4] else {
            unreachable!();
        };
        next_parity_b.root = [17; 32];
        next_group.id = next_group.calculate_id().unwrap();
        chained.coding_groups.push(next_group);
        chained.coding_groups.sort_by_key(|group| group.id);
        chained.validate().unwrap();

        let mut retained = chained.clone();
        let retired = retained.revisions.remove(0);
        retained.revision_tombstones.push(RevisionTombstone {
            owner: retired.value.owner,
            protected_root_id: retired.value.protected_root_id,
            through_sequence: retired.value.sequence,
            last_revision_id: retired.value.revision_id,
            last_revision_hash: retired.value.hash().unwrap(),
            retired_at_generation: 2,
        });
        let retained_sector = retained.revisions[0].value.metadata_sectors[0].id;
        retained.coding_groups.retain(|group| {
            group.roles.iter().any(|role| {
                matches!(role, ShardRole::Information(information) if information.sector.id == retained_sector)
            })
        });
        retained.generation = 2;
        retained.parent = Some(checkpoint.hash().unwrap());
        retained.validate().unwrap();
        let mut forged_tombstone = retained.clone();
        forged_tombstone.revision_tombstones[0].last_revision_hash = [99; 32];
        assert!(matches!(
            forged_tombstone.validate(),
            Err(ModelError::InvalidCheckpoint)
        ));

        let replacement_writer = SigningKey::from_bytes(&[78; 32]);
        let mut recovered = chained.clone();
        recovered.writer_fences.push(WriterFence {
            owner: keys[0].node_id(),
            epoch: 2,
            public_key: replacement_writer.verifying_key().to_bytes(),
        });
        recovered
            .writer_fences
            .sort_by_key(|fence| (fence.owner, fence.epoch));
        recovered.revisions[1].value.writer_epoch = 2;
        recovered.revisions[1].value.writer_public_key =
            replacement_writer.verifying_key().to_bytes();
        recovered.revisions[1]
            .value
            .sign_writer(&replacement_writer)
            .unwrap();
        recovered.revisions[1] = SignedRecord::sign(
            USER_REVISION_DOMAIN,
            recovered.revisions[1].value.clone(),
            &keys[0],
        )
        .unwrap();
        recovered.validate().unwrap();
        let mut stale_writer = recovered.clone();
        stale_writer.revisions[1].value.writer_epoch = 1;
        stale_writer.revisions[1].value.writer_public_key = writer.verifying_key().to_bytes();
        stale_writer.revisions[1]
            .value
            .sign_writer(&writer)
            .unwrap();
        stale_writer.revisions[1] = SignedRecord::sign(
            USER_REVISION_DOMAIN,
            stale_writer.revisions[1].value.clone(),
            &keys[0],
        )
        .unwrap();
        assert!(matches!(
            stale_writer.validate(),
            Err(ModelError::InvalidCheckpoint)
        ));
        let mut invalid_revision = chained.revisions[1].value.clone();
        invalid_revision.parent = Some([99; 32]);
        invalid_revision.sign_writer(&writer).unwrap();
        chained.revisions[1] =
            SignedRecord::sign(USER_REVISION_DOMAIN, invalid_revision, &keys[0]).unwrap();
        assert!(matches!(
            chained.validate(),
            Err(ModelError::InvalidCheckpoint)
        ));

        let mut eclipse = checkpoint.clone();
        eclipse.checkpoint.generation = u64::MAX;
        eclipse.checkpoint.parent = Some([99; 32]);
        assert!(matches!(
            eclipse.verify(),
            Err(ModelError::InvalidCheckpoint)
        ));

        let mut wrong_owner = checkpoint.checkpoint.clone();
        let group = &mut wrong_owner.coding_groups[0];
        let (left, right) = group.roles.split_at_mut(1);
        let ShardRole::Information(first) = &mut left[0] else {
            unreachable!();
        };
        let ShardRole::Information(second) = &mut right[0] else {
            unreachable!();
        };
        std::mem::swap(&mut first.owner, &mut second.owner);
        group.id = group.calculate_id().unwrap();
        assert!(matches!(
            wrong_owner.validate(),
            Err(ModelError::InvalidCheckpoint)
        ));

        checkpoint.checkpoint.members[4].failure_domain = "host-3".to_owned();
        assert!(matches!(
            checkpoint.verify(),
            Err(ModelError::ReusedFailureDomain(_))
        ));
    }

    #[test]
    fn coding_group_verifies_the_parity_equation() {
        let keys = (0_u8..5)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 20; 32])))
            .collect::<Vec<_>>();
        let information = [
            vec![1; V1_SECTOR_SIZE],
            vec![2; V1_SECTOR_SIZE],
            vec![3; V1_SECTOR_SIZE],
        ];
        let encoded = encode_3_2(information.clone()).unwrap();
        let roles = [
            ShardRole::Information(InformationRole {
                owner: keys[0].node_id(),
                sector: SectorRef {
                    id: [1; 32],
                    root: sector_root(&information[0]),
                    logical_len: 1,
                },
            }),
            ShardRole::Information(InformationRole {
                owner: keys[1].node_id(),
                sector: SectorRef {
                    id: [2; 32],
                    root: sector_root(&information[1]),
                    logical_len: 1,
                },
            }),
            ShardRole::Information(InformationRole {
                owner: keys[2].node_id(),
                sector: SectorRef {
                    id: [3; 32],
                    root: sector_root(&information[2]),
                    logical_len: 1,
                },
            }),
            ShardRole::Parity(ParityRole {
                holder: keys[3].node_id(),
                row: 0,
                root: sector_root(&encoded[3]),
            }),
            ShardRole::Parity(ParityRole {
                holder: keys[4].node_id(),
                row: 1,
                root: sector_root(&encoded[4]),
            }),
        ];
        let mut group = CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id: [9; 32],
            data_shards: V1_RS_DATA_SHARDS,
            parity_shards: V1_RS_PARITY_SHARDS,
            shard_size: V1_SECTOR_SIZE as u32,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        group
            .verify_parity_shard(&information, 3, &encoded[3])
            .unwrap();
        group
            .verify_parity_shard(&information, 4, &encoded[4])
            .unwrap();
        let mut invalid = encoded[3].clone();
        invalid[0] ^= 1;
        let mut invalid_group = group.clone();
        let ShardRole::Parity(invalid_role) = &mut invalid_group.roles[3] else {
            unreachable!();
        };
        invalid_role.root = sector_root(&invalid);
        invalid_group.id = invalid_group.calculate_id().unwrap();
        assert!(matches!(
            invalid_group.verify_parity_shard(&information, 3, &invalid),
            Err(ModelError::InvalidCodingRelation)
        ));
    }

    fn variable_group() -> (CodingGroupV2, Vec<Vec<u8>>) {
        let keys = (0_u8..6)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 40; 32])))
            .collect::<Vec<_>>();
        let profile = CodingProfile::new(4, 2, 64);
        let information = (0_u8..4)
            .map(|value| vec![value.wrapping_mul(37); profile.shard_size as usize])
            .collect::<Vec<_>>();
        let encoded = encode_codeword(profile, information).unwrap();
        let mut roles = encoded[..4]
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                ShardRoleV2::Information(InformationRoleV2 {
                    owner: keys[index].node_id(),
                    failure_domain: format!("domain-{index}"),
                    sector: RangeSectorRef {
                        id: [index as u8 + 1; 32],
                        commitment: merkle_commit(bytes).unwrap(),
                        logical_len: profile.shard_size,
                        virtual_zero: false,
                    },
                })
            })
            .collect::<Vec<_>>();
        roles.extend(encoded[4..].iter().enumerate().map(|(row, bytes)| {
            ShardRoleV2::Parity(ParityRoleV2 {
                holder: keys[row + 4].node_id(),
                failure_domain: format!("domain-{}", row + 4),
                row: row as u16,
                commitment: merkle_commit(bytes).unwrap(),
            })
        }));
        let mut group = CodingGroupV2 {
            id: [0; 32],
            format_version: 2,
            guild_id: [17; 32],
            profile,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        (group, encoded)
    }

    #[test]
    fn variable_group_binds_geometry_domains_and_complete_parity() {
        let (group, encoded) = variable_group();
        group.validate().unwrap();
        group
            .verify_parity_shard(&encoded[..4], 4, &encoded[4])
            .unwrap();
        group
            .verify_parity_shard(&encoded[..4], 5, &encoded[5])
            .unwrap();

        let mut reused_domain = group.clone();
        let ShardRoleV2::Parity(parity) = &mut reused_domain.roles[5] else {
            unreachable!();
        };
        parity.failure_domain = "domain-0".to_owned();
        reused_domain.id = reused_domain.calculate_id().unwrap();
        assert!(matches!(
            reused_domain.validate(),
            Err(ModelError::ReusedFailureDomain(domain)) if domain == "domain-0"
        ));

        let mut changed_profile = group.clone();
        changed_profile.profile = CodingProfile::new(3, 3, 64);
        assert_ne!(changed_profile.calculate_id().unwrap(), group.id);
    }

    #[test]
    fn variable_group_verifies_authenticated_same_leaf_samples() {
        let (group, encoded) = variable_group();
        let proofs = encoded
            .iter()
            .map(|bytes| crate::merkle_open_range(bytes, 2, 1).unwrap())
            .collect::<Vec<_>>();
        group.verify_sampled_openings(2, &proofs).unwrap();

        let mut different_leaf = proofs.clone();
        different_leaf[1] = crate::merkle_open_range(&encoded[1], 1, 1).unwrap();
        assert!(matches!(
            group.verify_sampled_openings(2, &different_leaf),
            Err(ModelError::InvalidCodingRelation)
        ));

        let mut corrupt = encoded.clone();
        corrupt[5][2 * crate::MERKLE_LEAF_SIZE] ^= 1;
        let mut invalid_group = group.clone();
        let ShardRoleV2::Parity(parity) = &mut invalid_group.roles[5] else {
            unreachable!();
        };
        parity.commitment = merkle_commit(&corrupt[5]).unwrap();
        invalid_group.id = invalid_group.calculate_id().unwrap();
        invalid_group.validate().unwrap();
        let corrupt_proofs = corrupt
            .iter()
            .map(|bytes| crate::merkle_open_range(bytes, 2, 1).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            invalid_group.verify_sampled_openings(2, &corrupt_proofs),
            Err(ModelError::Coding(crate::CodingError::InvalidCodeword))
        ));
    }

    #[test]
    fn variable_group_authenticates_virtual_zero_extents() {
        let (mut group, _) = variable_group();
        let ShardRoleV2::Information(information) = &mut group.roles[0] else {
            unreachable!();
        };
        information.sector.commitment = merkle_zero_commitment(group.profile.shard_size).unwrap();
        information.sector.virtual_zero = true;
        information.sector.logical_len = group.profile.shard_size;
        group.id = group.calculate_id().unwrap();
        group.validate().unwrap();

        let mut forged = group.clone();
        let ShardRoleV2::Information(information) = &mut forged.roles[0] else {
            unreachable!();
        };
        information.sector.commitment.root[0] ^= 1;
        forged.id = forged.calculate_id().unwrap();
        assert!(matches!(
            forged.validate(),
            Err(ModelError::InvalidCheckpoint)
        ));
    }
}
