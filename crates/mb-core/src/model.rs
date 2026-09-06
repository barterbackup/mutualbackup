use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

use crate::keys::{KeyMaterial, NodeId, RecoveryPublicKey, signing_payload};
use crate::recovery::RecoveryLocator;
use crate::{V1_CIPHER_PROFILE, V1_RS_DATA_SHARDS, V1_RS_PARITY_SHARDS, V1_SECTOR_SIZE};

pub type SectorId = [u8; 32];
pub type CodingGroupId = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Member {
    pub node_id: NodeId,
    pub recovery_public_key: RecoveryPublicKey,
    pub failure_domain: String,
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
            || self.generation == 0
            || (self.generation == 1) != self.parent.is_none()
            || self.members.len() < 3
            || self.revisions.is_empty()
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
                || (revision.value.sequence == 1) != revision.value.parent.is_none()
                || revision.value.metadata_sectors.is_empty()
                || !revision_ids.insert(revision.value.revision_id)
            {
                return Err(ModelError::InvalidCheckpoint);
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
                        .insert(reference.id, reference.clone())
                        .is_some()
                {
                    return Err(ModelError::InvalidCheckpoint);
                }
            }
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
        let quorum = self.checkpoint.members.len() / 2 + 1;
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
            || locator.expires_at_unix_seconds != u64::MAX
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
}

fn validate_group(
    group: &CodingGroup,
    guild_id: [u8; 32],
    failure_domains: &std::collections::BTreeMap<NodeId, &str>,
    revision_sectors: &std::collections::BTreeMap<SectorId, SectorRef>,
    information_ids: &mut std::collections::BTreeSet<SectorId>,
    covered_revision_sectors: &mut std::collections::BTreeSet<SectorId>,
) -> Result<(), ModelError> {
    if group.format_version != 1
        || group.guild_id != guild_id
        || group.data_shards != V1_RS_DATA_SHARDS
        || group.parity_shards != V1_RS_PARITY_SHARDS
        || group.shard_size as usize != V1_SECTOR_SIZE
        || group.calculate_id()? != group.id
    {
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
                if let Some(reference) = revision_sectors.get(&information.sector.id) {
                    if reference != &information.sector
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
        checkpoint.add_signature(&keys[2]).unwrap();
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
        assert!(matches!(
            checkpoint.validate_recovery_authority(&keys[4], &locator, keys[0].node_id()),
            Err(ModelError::InvalidRecoveryAuthority)
        ));
        checkpoint.add_signature(&keys[4]).unwrap();
        checkpoint
            .validate_recovery_authority(&keys[4], &locator, keys[0].node_id())
            .unwrap();

        checkpoint.checkpoint.members[4].failure_domain = "host-3".to_owned();
        assert!(matches!(
            checkpoint.verify(),
            Err(ModelError::ReusedFailureDomain(_))
        ));
    }
}
