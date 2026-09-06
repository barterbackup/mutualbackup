use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

use crate::keys::{KeyMaterial, NodeId, RecoveryPublicKey, signing_payload};
use crate::recovery::{RecoveryLocator, SealedRecoveryRecord};
use crate::{
    V1_CIPHER_PROFILE, V1_MAX_CODING_GROUPS, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS,
    V1_SECTOR_SIZE, encode_3_2, sector_root,
};

pub type SectorId = [u8; 32];
pub type CodingGroupId = [u8; 32];

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
pub struct EndpointRecord {
    pub format_version: u16,
    pub publisher: NodeId,
    pub sequence: u64,
    pub expires_at_unix_seconds: u64,
    pub endpoints: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryBundle {
    pub format_version: u16,
    pub subject: NodeId,
    pub publisher: NodeId,
    pub sequence: u64,
    pub expires_at_unix_seconds: u64,
    pub sealed: SealedRecoveryRecord,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildCheckpoint {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub generation: u64,
    pub parent: Option<[u8; 32]>,
    pub members: Vec<Member>,
    pub revisions: Vec<SignedRecord<UserRevision>>,
    pub coding_groups: Vec<CodingGroup>,
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
        if self.format_version != 1
            || self.genesis_hash == [0; 32]
            || self.generation == 0
            || self.generation > i64::MAX as u64
            || (self.generation == 1) != self.parent.is_none()
            || self.members.len() != 5
            || self.revisions.is_empty()
            || self.revisions.len() > 4096
            || self.coding_groups.is_empty()
            || self.coding_groups.len() > V1_MAX_CODING_GROUPS
        {
            return Err(ModelError::InvalidCheckpoint);
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
        let mut revision_heads = std::collections::BTreeMap::<NodeId, (u64, [u8; 32])>::new();
        for revision in &self.revisions {
            revision.verify(b"mutualbackup/user-revision/v1")?;
            let order = (
                revision.value.owner,
                revision.value.sequence,
                revision.value.revision_id,
            );
            if revision_order.is_some_and(|previous| previous >= order)
                || revision.signer != revision.value.owner
                || !member_ids.contains(&revision.signer)
                || revision.value.format_version != 1
                || revision.value.guild_id != self.guild_id
                || revision.value.cipher_profile != V1_CIPHER_PROFILE
                || revision.value.sequence == 0
                || revision.value.metadata_sectors.is_empty()
                || !revision_ids.insert(revision.value.revision_id)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            match revision_heads.get(&revision.value.owner) {
                Some((previous_sequence, previous_hash))
                    if previous_sequence.checked_add(1) == Some(revision.value.sequence)
                        && revision.value.parent == Some(*previous_hash) => {}
                None if revision.value.sequence == 1 && revision.value.parent.is_none() => {}
                _ => return Err(ModelError::InvalidCheckpoint),
            }
            for reference in revision
                .value
                .metadata_sectors
                .iter()
                .chain(&revision.value.data_sectors)
            {
                if reference.logical_len == 0
                    || reference.logical_len as usize > V1_SECTOR_SIZE
                    || revision_sectors
                        .insert(reference.id, (revision.value.owner, reference.clone()))
                        .is_some()
                {
                    return Err(ModelError::InvalidCheckpoint);
                }
            }
            revision_heads.insert(
                revision.value.owner,
                (revision.value.sequence, revision.value.hash()?),
            );
            revision_order = Some(order);
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
        if covered_revision_sectors.len() != revision_sectors.len()
            || !revision_sectors
                .keys()
                .all(|id| covered_revision_sectors.contains(id))
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
            || self.coordinator_endpoints.len() > 8
            || self
                .coordinator_endpoints
                .iter()
                .any(|endpoint| endpoint.is_empty() || endpoint.len() > 512)
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
        // The fixed v1 slice relies on each role holder's signature as its
        // durable-storage and coding-validation attestation. A smaller quorum
        // could certify a group without either parity holder participating.
        let quorum = self.checkpoint.members.len();
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
            || locator.expires_at_unix_seconds == 0
            || locator.endpoints.is_empty()
            || locator.endpoints.len() > 8
            || locator
                .endpoints
                .iter()
                .any(|endpoint| endpoint.len() > 512)
            || member.recovery_public_key != keys.recovery_public_key()
            || !self
                .checkpoint
                .members
                .iter()
                .any(|member| member.node_id == locator.publisher)
            || !self.has_signature(subject)
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
    pub cipher_profile: u16,
    pub revision_id: Uuid,
    pub owner: NodeId,
    pub sequence: u64,
    pub parent: Option<[u8; 32]>,
    pub metadata_sectors: Vec<SectorRef>,
    pub data_sectors: Vec<SectorRef>,
}

impl UserRevision {
    /// Stable identity used by the next revision's `parent` field.
    pub fn hash(&self) -> Result<[u8; 32], ModelError> {
        let mut hasher = blake3::Hasher::new_derive_key("mutualbackup user revision body v1");
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
        let revision = SignedRecord::sign(
            b"mutualbackup/user-revision/v1",
            UserRevision {
                format_version: 1,
                guild_id,
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::from_u128(1),
                owner: keys[0].node_id(),
                sequence: 1,
                parent: None,
                metadata_sectors: vec![target],
                data_sectors: Vec::new(),
            },
            &keys[0],
        )
        .unwrap();
        members.sort_by_key(|member| member.node_id);
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 1,
                guild_id,
                genesis_hash: [10; 32],
                generation: 1,
                parent: None,
                members,
                revisions: vec![revision],
                coding_groups: vec![group],
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

        let locator = RecoveryLocator {
            format_version: 1,
            subject: keys[4].node_id(),
            publisher: keys[0].node_id(),
            guild_id,
            checkpoint_hash: checkpoint.hash().unwrap(),
            checkpoint_generation: 1,
            endpoints: vec!["tcp://127.0.0.1:1".to_owned()],
            expires_at_unix_seconds: u64::MAX,
        };
        checkpoint
            .validate_recovery_authority(&keys[4], &locator, keys[0].node_id())
            .unwrap();

        let mut chained = checkpoint.checkpoint.clone();
        let previous = chained.revisions[0].value.hash().unwrap();
        let next_target = SectorRef {
            id: [10; 32],
            root: [11; 32],
            logical_len: 1,
        };
        chained.revisions.push(
            SignedRecord::sign(
                b"mutualbackup/user-revision/v1",
                UserRevision {
                    format_version: 1,
                    guild_id,
                    cipher_profile: V1_CIPHER_PROFILE,
                    revision_id: Uuid::from_u128(2),
                    owner: keys[0].node_id(),
                    sequence: 2,
                    parent: Some(previous),
                    metadata_sectors: vec![next_target.clone()],
                    data_sectors: Vec::new(),
                },
                &keys[0],
            )
            .unwrap(),
        );
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
        let mut invalid_revision = chained.revisions[1].value.clone();
        invalid_revision.parent = Some([99; 32]);
        chained.revisions[1] =
            SignedRecord::sign(b"mutualbackup/user-revision/v1", invalid_revision, &keys[0])
                .unwrap();
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
}
