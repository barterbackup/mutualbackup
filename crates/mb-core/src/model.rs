use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;
use uuid::Uuid;

use crate::keys::{KeyMaterial, NodeId, RecoveryPublicKey, signing_payload};

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
    pub shard_size: u32,
    pub roles: [ShardRole; 5],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildCheckpoint {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub generation: u64,
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
        if self.format_version != 1 || self.members.len() < 3 {
            return Err(ModelError::InvalidCheckpoint);
        }
        let mut member_ids = std::collections::BTreeSet::new();
        let mut failure_domains = std::collections::BTreeMap::new();
        for member in &self.members {
            if !member_ids.insert(member.node_id) || member.failure_domain.is_empty() {
                return Err(ModelError::InvalidCheckpoint);
            }
            failure_domains.insert(member.node_id, member.failure_domain.as_str());
        }
        for revision in &self.revisions {
            revision.verify(b"mutualbackup/user-revision/v1")?;
            if revision.signer != revision.value.owner || !member_ids.contains(&revision.signer) {
                return Err(ModelError::InvalidCheckpoint);
            }
        }
        for group in &self.coding_groups {
            validate_group(group, &failure_domains)?;
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
        for member_signature in &self.signatures {
            if !member_ids.contains(&member_signature.signer)
                || !valid_signers.insert(member_signature.signer)
            {
                return Err(ModelError::InvalidCheckpoint);
            }
            let key = VerifyingKey::from_bytes(&member_signature.signer.0)?;
            let signature = Signature::from_slice(&member_signature.signature)?;
            key.verify(
                &signing_payload(b"mutualbackup/guild-checkpoint/v1", &encoded),
                &signature,
            )?;
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
        Ok(*blake3::hash(&canonical_bytes(self)?).as_bytes())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UserRevision {
    pub format_version: u16,
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
        let signature = Signature::from_slice(&self.signature)?;
        key.verify(
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
    #[error("checkpoint signature is from non-member {0}")]
    NonMemberSigner(NodeId),
    #[error("checkpoint has {actual} valid signatures but requires {required}")]
    InsufficientQuorum { actual: usize, required: usize },
    #[error("coding group assigns more than one shard to failure domain {0}")]
    ReusedFailureDomain(String),
}

fn validate_group(
    group: &CodingGroup,
    failure_domains: &std::collections::BTreeMap<NodeId, &str>,
) -> Result<(), ModelError> {
    if group.shard_size == 0 {
        return Err(ModelError::InvalidCheckpoint);
    }
    let mut used_domains = std::collections::BTreeSet::new();
    for (index, role) in group.roles.iter().enumerate() {
        let node_id = match role {
            ShardRole::Information(information) if index < 3 => information.owner,
            ShardRole::Parity(parity) if index >= 3 && parity.row == (index - 3) as u16 => {
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
        let members = keys
            .iter()
            .enumerate()
            .map(|(index, key)| Member {
                node_id: key.node_id(),
                recovery_public_key: key.recovery_public_key(),
                failure_domain: format!("host-{index}"),
            })
            .collect::<Vec<_>>();
        let placeholder = SectorRef {
            id: [1; 32],
            root: [2; 32],
            logical_len: 1,
        };
        let group = CodingGroup {
            id: [3; 32],
            shard_size: 64 * 1024,
            roles: [
                ShardRole::Information(InformationRole {
                    owner: members[0].node_id,
                    sector: placeholder.clone(),
                }),
                ShardRole::Information(InformationRole {
                    owner: members[1].node_id,
                    sector: placeholder.clone(),
                }),
                ShardRole::Information(InformationRole {
                    owner: members[2].node_id,
                    sector: placeholder,
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
            ],
        };
        let mut checkpoint = QuorumCheckpoint {
            checkpoint: GuildCheckpoint {
                format_version: 1,
                guild_id: [7; 32],
                generation: 1,
                members,
                revisions: Vec::new(),
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

        checkpoint.checkpoint.members[4].failure_domain = "host-3".to_owned();
        assert!(matches!(
            checkpoint.verify(),
            Err(ModelError::ReusedFailureDomain(_))
        ));
    }
}
