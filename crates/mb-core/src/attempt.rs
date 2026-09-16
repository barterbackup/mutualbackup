use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CodingError, CodingGroupV2, CodingProfile, InformationRoleV2, KeyMaterial, MerkleCommitment,
    MerkleRangeProof, ModelError, NodeId, ParityRoleV2, ShardRoleV2, SignedRecord, canonical_bytes,
    challenged_leaf, encode, merkle_commit, merkle_verify_range, merkle_zero_commitment,
    verify_sampled_codeword,
};

pub const CODING_ATTEMPT_PLAN_DOMAIN: &[u8] = b"mutualbackup/coding-attempt-plan/v1";
pub const CODING_ROOT_MANIFEST_DOMAIN: &[u8] = b"mutualbackup/coding-root-manifest/v1";
pub const STAGED_STORAGE_RECEIPT_DOMAIN: &[u8] = b"mutualbackup/staged-storage-receipt/v1";
pub const CODING_CHALLENGE_COMMITMENT_DOMAIN: &[u8] =
    b"mutualbackup/coding-challenge-commitment/v1";
pub const CODING_CHALLENGE_REVEAL_DOMAIN: &[u8] = b"mutualbackup/coding-challenge-reveal/v1";
pub const CODING_SHARD_OPENING_DOMAIN: &[u8] = b"mutualbackup/coding-shard-opening/v1";
pub const CODING_TRANSCRIPT_DOMAIN: &[u8] = b"mutualbackup/coding-transcript/v1";
pub const CODING_FAILURE_REPORT_DOMAIN: &[u8] = b"mutualbackup/coding-failure-report/v1";

/// The immutable, narrow delegation for one complete coding attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ParityPlacementV2 {
    pub holder: NodeId,
    pub failure_domain: String,
    pub row: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingPlanGeometry {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub profile: CodingProfile,
    pub information: Vec<InformationRoleV2>,
    pub parity: Vec<ParityPlacementV2>,
}

impl CodingPlanGeometry {
    pub fn validate(&self) -> Result<(), CodingAttemptError> {
        self.profile
            .validate()
            .map_err(|_| CodingAttemptError::InvalidPlan)?;
        if self.format_version != 1
            || self.guild_id == [0; 32]
            || self.information.len() != usize::from(self.profile.data_shards)
            || self.parity.len() != usize::from(self.profile.parity_shards)
        {
            return Err(CodingAttemptError::InvalidPlan);
        }
        let mut domains = std::collections::BTreeSet::new();
        for information in &self.information {
            information
                .sector
                .commitment
                .validate()
                .map_err(|_| CodingAttemptError::InvalidPlan)?;
            if information.owner == NodeId([0; 32])
                || information.failure_domain.is_empty()
                || information.failure_domain.len() > 256
                || information.sector.id == [0; 32]
                || information.sector.commitment.byte_len != self.profile.shard_size
                || information.sector.logical_len > self.profile.shard_size
                || !domains.insert(information.failure_domain.as_str())
            {
                return Err(CodingAttemptError::InvalidPlan);
            }
            if information.sector.virtual_zero {
                if information.sector.logical_len != self.profile.shard_size
                    || information.sector.commitment
                        != merkle_zero_commitment(self.profile.shard_size)
                            .map_err(|_| CodingAttemptError::InvalidPlan)?
                {
                    return Err(CodingAttemptError::InvalidPlan);
                }
            } else if information.sector.logical_len == 0 {
                return Err(CodingAttemptError::InvalidPlan);
            }
        }
        for (row, parity) in self.parity.iter().enumerate() {
            if parity.holder == NodeId([0; 32])
                || parity.row != row as u16
                || parity.failure_domain.is_empty()
                || parity.failure_domain.len() > 256
                || !domains.insert(parity.failure_domain.as_str())
            {
                return Err(CodingAttemptError::InvalidPlan);
            }
        }
        Ok(())
    }

    pub fn validate_group(&self, group: &CodingGroupV2) -> Result<(), CodingAttemptError> {
        group.validate()?;
        if group.guild_id != self.guild_id
            || group.profile != self.profile
            || group.roles.len() != self.information.len() + self.parity.len()
        {
            return Err(CodingAttemptError::InvalidTranscript);
        }
        for (index, information) in self.information.iter().enumerate() {
            if group.roles[index] != ShardRoleV2::Information(information.clone()) {
                return Err(CodingAttemptError::InvalidTranscript);
            }
        }
        for (offset, placement) in self.parity.iter().enumerate() {
            let Some(ShardRoleV2::Parity(parity)) =
                group.roles.get(self.information.len() + offset)
            else {
                return Err(CodingAttemptError::InvalidTranscript);
            };
            if parity.holder != placement.holder
                || parity.failure_domain != placement.failure_domain
                || parity.row != placement.row
            {
                return Err(CodingAttemptError::InvalidTranscript);
            }
        }
        Ok(())
    }
}

/// The immutable, narrow delegation for one complete coding attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingAttemptPlan {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub checkpoint_hash: [u8; 32],
    pub membership_epoch: u64,
    pub geometry: CodingPlanGeometry,
    pub delegator: NodeId,
    pub coding_coordinator: NodeId,
    pub verification_coordinator: NodeId,
    pub expires_at_unix_seconds: u64,
}

impl CodingAttemptPlan {
    pub fn validate(&self) -> Result<(), CodingAttemptError> {
        self.geometry.validate()?;
        if self.format_version != 1
            || self.attempt_id == [0; 16]
            || self.checkpoint_hash == [0; 32]
            || self.membership_epoch == 0
            || self.delegator == NodeId([0; 32])
            || self.coding_coordinator == NodeId([0; 32])
            || self.verification_coordinator == NodeId([0; 32])
            || self.coding_coordinator == self.verification_coordinator
            || self.expires_at_unix_seconds == 0
        {
            return Err(CodingAttemptError::InvalidPlan);
        }
        Ok(())
    }

    pub fn hash(&self) -> Result<[u8; 32], CodingAttemptError> {
        self.validate()?;
        Ok(hash_canonical("mutualbackup coding attempt plan v1", self)?)
    }
}

/// The coordinator's signed result, binding the delegated inputs and placement
/// geometry to the parity commitments produced by this attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingRootManifest {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub plan_hash: [u8; 32],
    pub group: CodingGroupV2,
}

/// A parity holder's durable fact that one attempt's bytes are present but not
/// yet active protection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StagedStorageReceipt {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub plan_hash: [u8; 32],
    pub guild_id: [u8; 32],
    pub group_id: [u8; 32],
    pub shard_index: u16,
    pub holder: NodeId,
    pub commitment: MerkleCommitment,
}

/// Signed before encoding starts. The nonce remains hidden until every parity
/// holder has produced a staged receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingChallengeCommitment {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub plan_hash: [u8; 32],
    pub commitment: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingChallengeReveal {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub plan_hash: [u8; 32],
    pub nonce: [u8; 32],
    pub evidence_hash: [u8; 32],
}

/// A holder-signed response bound to the complete attempt and verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingShardOpening {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub plan_hash: [u8; 32],
    pub verifier: NodeId,
    pub challenge: [u8; 32],
    pub shard_index: u16,
    pub commitment: MerkleCommitment,
    pub proof: MerkleRangeProof,
}

/// All evidence needed for any checkpoint signer to replay the verifier's
/// decision without receiving complete shards.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingVerificationTranscript {
    pub format_version: u16,
    /// Verifier wall-clock time. It must fall within the delegated attempt
    /// lifetime; holders may replay and activate this evidence afterward.
    pub verified_at_unix_seconds: u64,
    pub plan: SignedRecord<CodingAttemptPlan>,
    pub manifest: SignedRecord<CodingRootManifest>,
    pub challenge_commitment: SignedRecord<CodingChallengeCommitment>,
    pub staged_receipts: Vec<SignedRecord<StagedStorageReceipt>>,
    pub challenge_reveal: SignedRecord<CodingChallengeReveal>,
    pub openings: Vec<SignedRecord<CodingShardOpening>>,
}

/// A coding coordinator's durable notice that an attempt failed before a
/// verifier accepted it. The detailed local error stays out of the protocol;
/// its hash binds diagnostics without making them authorization input.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingFailureReport {
    pub format_version: u16,
    pub failed_at_unix_seconds: u64,
    pub plan: SignedRecord<CodingAttemptPlan>,
    pub error_hash: [u8; 32],
}

impl CodingFailureReport {
    pub fn validate(&self) -> Result<(), CodingAttemptError> {
        self.plan
            .verify(CODING_ATTEMPT_PLAN_DOMAIN)
            .map_err(|_| CodingAttemptError::InvalidPlan)?;
        self.plan.value.validate()?;
        if self.format_version != 1
            || self.failed_at_unix_seconds == 0
            || self.plan.signer != self.plan.value.delegator
            || self.error_hash == [0; 32]
        {
            return Err(CodingAttemptError::InvalidPlan);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodingReplayFinding {
    Verified,
    /// The expected holder signed an opening that does not authenticate the
    /// exact plan-bound shard and challenge.
    InvalidOpening {
        holder: NodeId,
        shard_index: u16,
    },
    /// Every opening is authentic, but the sampled symbols violate the RS
    /// equation accepted in the coding coordinator's signed root manifest.
    InvalidCoding {
        coordinator: NodeId,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CodingTransferEstimate {
    pub information_shard_transfers: u16,
    pub parity_shard_transfers: u16,
    pub bulk_bytes: u64,
}

/// Count the complete-shard-equivalent bulk paths in one immutable plan.
/// Merkle proofs and control messages are deliberately excluded.
pub fn coding_transfer_estimate(
    plan: &CodingAttemptPlan,
) -> Result<CodingTransferEstimate, CodingAttemptError> {
    plan.validate()?;
    let information_shard_transfers = plan
        .geometry
        .information
        .iter()
        .filter(|role| !role.sector.virtual_zero && role.owner != plan.coding_coordinator)
        .count() as u16;
    let parity_shard_transfers = plan
        .geometry
        .parity
        .iter()
        .filter(|role| role.holder != plan.coding_coordinator)
        .count() as u16;
    let total = u64::from(information_shard_transfers)
        .checked_add(u64::from(parity_shard_transfers))
        .and_then(|count| count.checked_mul(u64::from(plan.geometry.profile.shard_size)))
        .ok_or(CodingAttemptError::InvalidPlan)?;
    Ok(CodingTransferEstimate {
        information_shard_transfers,
        parity_shard_transfers,
        bulk_bytes: total,
    })
}

#[derive(Debug, Error)]
pub enum CodingAttemptError {
    #[error("the coding attempt plan is invalid")]
    InvalidPlan,
    #[error("the coding transcript is structurally invalid")]
    InvalidTranscript,
    #[error("the coding transcript is incomplete; this proves only unavailability")]
    Incomplete,
    #[error("coding input does not match the immutable attempt plan")]
    InvalidInformation,
    #[error("Reed-Solomon coding failed: {0}")]
    Coding(#[from] CodingError),
    #[error("canonical coding evidence encoding failed: {0}")]
    Model(#[from] ModelError),
}

/// Verify the delegated information and produce the coordinator-signed output
/// manifest. A `None` input is accepted only for an authenticated virtual-zero
/// extent, so callers can preserve the no-transfer invariant for sparse data.
pub fn encode_coding_attempt(
    signed_plan: &SignedRecord<CodingAttemptPlan>,
    information: Vec<Option<Vec<u8>>>,
    coordinator_keys: &KeyMaterial,
) -> Result<(SignedRecord<CodingRootManifest>, Vec<Vec<u8>>), CodingAttemptError> {
    signed_plan.verify(CODING_ATTEMPT_PLAN_DOMAIN)?;
    let plan = &signed_plan.value;
    plan.validate()?;
    if signed_plan.signer != plan.delegator
        || coordinator_keys.node_id() != plan.coding_coordinator
        || information.len() != plan.geometry.information.len()
    {
        return Err(CodingAttemptError::InvalidPlan);
    }

    let mut input_bytes = Vec::with_capacity(information.len());
    for (role, bytes) in plan.geometry.information.iter().zip(information) {
        let bytes = match (role.sector.virtual_zero, bytes) {
            (true, None) => vec![0_u8; plan.geometry.profile.shard_size as usize],
            (false, Some(bytes)) => bytes,
            _ => return Err(CodingAttemptError::InvalidInformation),
        };
        if merkle_commit(&bytes).map_err(|_| CodingAttemptError::InvalidInformation)?
            != role.sector.commitment
        {
            return Err(CodingAttemptError::InvalidInformation);
        }
        input_bytes.push(bytes);
    }

    let encoded = encode(plan.geometry.profile, input_bytes)?;
    let parity_start = usize::from(plan.geometry.profile.data_shards);
    let parity = encoded[parity_start..].to_vec();
    let mut roles = plan
        .geometry
        .information
        .iter()
        .cloned()
        .map(ShardRoleV2::Information)
        .collect::<Vec<_>>();
    for (placement, bytes) in plan.geometry.parity.iter().zip(&parity) {
        roles.push(ShardRoleV2::Parity(ParityRoleV2 {
            holder: placement.holder,
            failure_domain: placement.failure_domain.clone(),
            row: placement.row,
            commitment: merkle_commit(bytes).map_err(|_| CodingAttemptError::InvalidInformation)?,
        }));
    }
    let mut group = CodingGroupV2 {
        id: [0; 32],
        format_version: 2,
        guild_id: plan.geometry.guild_id,
        profile: plan.geometry.profile,
        roles,
    };
    group.id = group.calculate_id()?;
    group.validate()?;
    let manifest = SignedRecord::sign(
        CODING_ROOT_MANIFEST_DOMAIN,
        CodingRootManifest {
            format_version: 1,
            attempt_id: plan.attempt_id,
            plan_hash: plan.hash()?,
            group,
        },
        coordinator_keys,
    )?;
    Ok((manifest, parity))
}

pub fn coding_challenge_commitment(plan_hash: [u8; 32], nonce: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup coding hidden challenge v1");
    hasher.update(&plan_hash);
    hasher.update(&nonce);
    *hasher.finalize().as_bytes()
}

pub fn coding_evidence_hash(
    manifest: &SignedRecord<CodingRootManifest>,
    receipts: &[SignedRecord<StagedStorageReceipt>],
) -> Result<[u8; 32], CodingAttemptError> {
    Ok(hash_canonical(
        "mutualbackup coding staged evidence v1",
        &(manifest, receipts),
    )?)
}

pub fn coding_challenge(plan_hash: [u8; 32], nonce: [u8; 32], evidence_hash: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup coding sample challenge v1");
    hasher.update(&plan_hash);
    hasher.update(&nonce);
    hasher.update(&evidence_hash);
    *hasher.finalize().as_bytes()
}

/// Verify signatures and replay every proof and sampled RS equation.
///
/// Missing evidence is classified only as unavailability. Attribution is
/// returned only after an expected signer has authenticated the bad evidence.
pub fn replay_coding_transcript(
    signed: &SignedRecord<CodingVerificationTranscript>,
) -> Result<CodingReplayFinding, CodingAttemptError> {
    signed.verify(CODING_TRANSCRIPT_DOMAIN)?;
    let transcript = &signed.value;
    let plan = &transcript.plan.value;
    plan.validate()?;
    if transcript.format_version != 1
        || transcript.verified_at_unix_seconds == 0
        || transcript.verified_at_unix_seconds > plan.expires_at_unix_seconds
        || transcript.plan.signer != plan.delegator
        || signed.signer != plan.verification_coordinator
    {
        return Err(CodingAttemptError::InvalidTranscript);
    }
    transcript.plan.verify(CODING_ATTEMPT_PLAN_DOMAIN)?;
    let plan_hash = plan.hash()?;

    let manifest = &transcript.manifest.value;
    transcript.manifest.verify(CODING_ROOT_MANIFEST_DOMAIN)?;
    if transcript.manifest.signer != plan.coding_coordinator
        || manifest.format_version != 1
        || manifest.attempt_id != plan.attempt_id
        || manifest.plan_hash != plan_hash
    {
        return Err(CodingAttemptError::InvalidTranscript);
    }
    plan.geometry.validate_group(&manifest.group)?;
    let group = &manifest.group;

    let parity_start = usize::from(group.profile.data_shards);
    if transcript.staged_receipts.len() != usize::from(group.profile.parity_shards) {
        return Err(CodingAttemptError::Incomplete);
    }
    for (offset, receipt) in transcript.staged_receipts.iter().enumerate() {
        receipt.verify(STAGED_STORAGE_RECEIPT_DOMAIN)?;
        let index = parity_start + offset;
        let ShardRoleV2::Parity(parity) = &group.roles[index] else {
            return Err(CodingAttemptError::InvalidTranscript);
        };
        let value = &receipt.value;
        if receipt.signer != parity.holder
            || value.format_version != 1
            || value.attempt_id != plan.attempt_id
            || value.plan_hash != plan_hash
            || value.guild_id != group.guild_id
            || value.group_id != group.id
            || usize::from(value.shard_index) != index
            || value.holder != parity.holder
            || value.commitment != parity.commitment
        {
            return Err(CodingAttemptError::InvalidTranscript);
        }
    }

    let commitment = &transcript.challenge_commitment;
    commitment.verify(CODING_CHALLENGE_COMMITMENT_DOMAIN)?;
    let reveal = &transcript.challenge_reveal;
    reveal.verify(CODING_CHALLENGE_REVEAL_DOMAIN)?;
    let evidence_hash = coding_evidence_hash(&transcript.manifest, &transcript.staged_receipts)?;
    if commitment.signer != plan.verification_coordinator
        || reveal.signer != plan.verification_coordinator
        || commitment.value.format_version != 1
        || reveal.value.format_version != 1
        || commitment.value.attempt_id != plan.attempt_id
        || reveal.value.attempt_id != plan.attempt_id
        || commitment.value.plan_hash != plan_hash
        || reveal.value.plan_hash != plan_hash
        || reveal.value.evidence_hash != evidence_hash
        || commitment.value.commitment != coding_challenge_commitment(plan_hash, reveal.value.nonce)
    {
        return Err(CodingAttemptError::InvalidTranscript);
    }
    let challenge = coding_challenge(plan_hash, reveal.value.nonce, evidence_hash);

    if transcript.openings.len() != group.roles.len() {
        return Err(CodingAttemptError::Incomplete);
    }
    let mut symbols = Vec::with_capacity(transcript.openings.len());
    for (index, opening) in transcript.openings.iter().enumerate() {
        let (holder, expected_commitment) = role_holder_and_commitment(&group.roles[index]);
        opening.verify(CODING_SHARD_OPENING_DOMAIN)?;
        if opening.signer != holder {
            return Err(CodingAttemptError::InvalidTranscript);
        }
        let value = &opening.value;
        let expected_leaf = challenged_leaf(&challenge, expected_commitment)
            .map_err(|_| CodingAttemptError::InvalidTranscript)?;
        if value.format_version != 1
            || value.attempt_id != plan.attempt_id
            || value.plan_hash != plan_hash
            || value.verifier != plan.verification_coordinator
            || value.challenge != challenge
            || usize::from(value.shard_index) != index
            || value.commitment != *expected_commitment
            || value.proof.start_leaf != expected_leaf
            || value.proof.leaves.len() != 1
        {
            return Ok(CodingReplayFinding::InvalidOpening {
                holder,
                shard_index: index as u16,
            });
        }
        let Ok(bytes) = merkle_verify_range(expected_commitment, &value.proof) else {
            return Ok(CodingReplayFinding::InvalidOpening {
                holder,
                shard_index: index as u16,
            });
        };
        let Ok(symbol) = bytes.try_into() else {
            return Ok(CodingReplayFinding::InvalidOpening {
                holder,
                shard_index: index as u16,
            });
        };
        symbols.push(symbol);
    }
    if verify_sampled_codeword(group.profile, &symbols).is_err() {
        return Ok(CodingReplayFinding::InvalidCoding {
            coordinator: plan.coding_coordinator,
        });
    }
    Ok(CodingReplayFinding::Verified)
}

fn role_holder_and_commitment(role: &ShardRoleV2) -> (NodeId, &MerkleCommitment) {
    match role {
        ShardRoleV2::Information(information) => {
            (information.owner, &information.sector.commitment)
        }
        ShardRoleV2::Parity(parity) => (parity.holder, &parity.commitment),
    }
}

fn hash_canonical<T: Serialize>(domain: &str, value: &T) -> Result<[u8; 32], ModelError> {
    let mut hasher = blake3::Hasher::new_derive_key(domain);
    hasher.update(&canonical_bytes(value)?);
    Ok(*hasher.finalize().as_bytes())
}

#[cfg(test)]
mod tests {
    use crate::{
        CodingProfile, InformationRoleV2, KeyMaterial, ParityRoleV2, RangeSectorRef, Seed, encode,
        merkle_commit, merkle_open_range,
    };

    use super::*;

    fn signed_transcript() -> (
        SignedRecord<CodingVerificationTranscript>,
        Vec<KeyMaterial>,
        Vec<Vec<u8>>,
    ) {
        let keys = (0_u8..9)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 70; 32])))
            .collect::<Vec<_>>();
        let profile = CodingProfile::new(4, 2, 64);
        let information = (0_u8..4)
            .map(|value| vec![value.wrapping_mul(29); 64])
            .collect::<Vec<_>>();
        let shards = encode(profile, information.clone()).unwrap();
        let mut roles = shards[..4]
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                ShardRoleV2::Information(InformationRoleV2 {
                    owner: keys[index].node_id(),
                    failure_domain: format!("site-{index}"),
                    sector: RangeSectorRef {
                        id: [index as u8 + 1; 32],
                        commitment: merkle_commit(bytes).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                })
            })
            .collect::<Vec<_>>();
        roles.extend(shards[4..].iter().enumerate().map(|(row, bytes)| {
            ShardRoleV2::Parity(ParityRoleV2 {
                holder: keys[4 + row].node_id(),
                failure_domain: format!("site-{}", 4 + row),
                row: row as u16,
                commitment: merkle_commit(bytes).unwrap(),
            })
        }));
        let mut group = CodingGroupV2 {
            id: [0; 32],
            format_version: 2,
            guild_id: [8; 32],
            profile,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        let plan = CodingAttemptPlan {
            format_version: 1,
            attempt_id: [4; 16],
            checkpoint_hash: [5; 32],
            membership_epoch: 3,
            geometry: CodingPlanGeometry {
                format_version: 1,
                guild_id: group.guild_id,
                profile,
                information: group.roles[..4]
                    .iter()
                    .map(|role| match role {
                        ShardRoleV2::Information(information) => information.clone(),
                        ShardRoleV2::Parity(_) => unreachable!(),
                    })
                    .collect(),
                parity: group.roles[4..]
                    .iter()
                    .map(|role| match role {
                        ShardRoleV2::Parity(parity) => ParityPlacementV2 {
                            holder: parity.holder,
                            failure_domain: parity.failure_domain.clone(),
                            row: parity.row,
                        },
                        ShardRoleV2::Information(_) => unreachable!(),
                    })
                    .collect(),
            },
            delegator: keys[6].node_id(),
            coding_coordinator: keys[7].node_id(),
            verification_coordinator: keys[8].node_id(),
            expires_at_unix_seconds: 2_000_000_000,
        };
        assert_eq!(
            coding_transfer_estimate(&plan).unwrap(),
            CodingTransferEstimate {
                information_shard_transfers: 4,
                parity_shard_transfers: 2,
                bulk_bytes: 6 * 64,
            }
        );
        let mut participating_plan = plan.clone();
        participating_plan.coding_coordinator = keys[0].node_id();
        assert_eq!(
            coding_transfer_estimate(&participating_plan).unwrap(),
            CodingTransferEstimate {
                information_shard_transfers: 3,
                parity_shard_transfers: 2,
                bulk_bytes: 5 * 64,
            }
        );
        let plan_hash = plan.hash().unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, &keys[6]).unwrap();
        let (manifest, parity) =
            encode_coding_attempt(&plan, information.into_iter().map(Some).collect(), &keys[7])
                .unwrap();
        assert_eq!(manifest.value.group, group);
        assert_eq!(parity, shards[4..]);
        let staged_receipts = (4_usize..6)
            .map(|index| {
                let ShardRoleV2::Parity(parity) = &manifest.value.group.roles[index] else {
                    unreachable!();
                };
                SignedRecord::sign(
                    STAGED_STORAGE_RECEIPT_DOMAIN,
                    StagedStorageReceipt {
                        format_version: 1,
                        attempt_id: [4; 16],
                        plan_hash,
                        guild_id: [8; 32],
                        group_id: manifest.value.group.id,
                        shard_index: index as u16,
                        holder: parity.holder,
                        commitment: parity.commitment.clone(),
                    },
                    &keys[index],
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let nonce = [22; 32];
        let challenge_commitment = SignedRecord::sign(
            CODING_CHALLENGE_COMMITMENT_DOMAIN,
            CodingChallengeCommitment {
                format_version: 1,
                attempt_id: [4; 16],
                plan_hash,
                commitment: coding_challenge_commitment(plan_hash, nonce),
            },
            &keys[8],
        )
        .unwrap();
        let evidence_hash = coding_evidence_hash(&manifest, &staged_receipts).unwrap();
        let challenge = coding_challenge(plan_hash, nonce, evidence_hash);
        let challenge_reveal = SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            CodingChallengeReveal {
                format_version: 1,
                attempt_id: [4; 16],
                plan_hash,
                nonce,
                evidence_hash,
            },
            &keys[8],
        )
        .unwrap();
        let openings = shards
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                let (holder, commitment) =
                    role_holder_and_commitment(&manifest.value.group.roles[index]);
                let leaf = challenged_leaf(&challenge, commitment).unwrap();
                SignedRecord::sign(
                    CODING_SHARD_OPENING_DOMAIN,
                    CodingShardOpening {
                        format_version: 1,
                        attempt_id: [4; 16],
                        plan_hash,
                        verifier: keys[8].node_id(),
                        challenge,
                        shard_index: index as u16,
                        commitment: commitment.clone(),
                        proof: merkle_open_range(bytes, leaf, 1).unwrap(),
                    },
                    &keys[index],
                )
                .unwrap_or_else(|_| panic!("holder {holder} signs its opening"))
            })
            .collect();
        let transcript = CodingVerificationTranscript {
            format_version: 1,
            verified_at_unix_seconds: 1_900_000_000,
            plan,
            manifest,
            challenge_commitment,
            staged_receipts,
            challenge_reveal,
            openings,
        };
        (
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, transcript, &keys[8]).unwrap(),
            keys,
            shards,
        )
    }

    #[test]
    fn transcript_replays_without_complete_shards() {
        let (transcript, _, _) = signed_transcript();
        assert_eq!(
            replay_coding_transcript(&transcript).unwrap(),
            CodingReplayFinding::Verified
        );
    }

    #[test]
    fn signed_invalid_opening_is_attributed_to_its_holder() {
        let (mut transcript, keys, _) = signed_transcript();
        let holder = transcript.value.openings[2].signer;
        transcript.value.openings[2].value.proof.leaves[0][0] ^= 1;
        transcript.value.openings[2] = SignedRecord::sign(
            CODING_SHARD_OPENING_DOMAIN,
            transcript.value.openings[2].value.clone(),
            &keys[2],
        )
        .unwrap();
        transcript =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, transcript.value, &keys[8]).unwrap();
        assert_eq!(
            replay_coding_transcript(&transcript).unwrap(),
            CodingReplayFinding::InvalidOpening {
                holder,
                shard_index: 2
            }
        );
    }

    #[test]
    fn authenticated_rs_mismatch_is_attributed_to_the_coder() {
        let (mut transcript, keys, mut shards) = signed_transcript();
        let coordinator = transcript.value.plan.value.coding_coordinator;
        for byte in &mut shards[5] {
            *byte ^= 1;
        }
        let commitment = merkle_commit(&shards[5]).unwrap();
        let ShardRoleV2::Parity(parity) = &mut transcript.value.manifest.value.group.roles[5]
        else {
            unreachable!();
        };
        parity.commitment = commitment.clone();
        transcript.value.manifest.value.group.id = transcript
            .value
            .manifest
            .value
            .group
            .calculate_id()
            .unwrap();
        let plan_hash = transcript.value.plan.value.hash().unwrap();
        transcript.value.manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            transcript.value.manifest.value,
            &keys[7],
        )
        .unwrap();
        let ShardRoleV2::Parity(parity) = &transcript.value.manifest.value.group.roles[5] else {
            unreachable!();
        };
        for (offset, receipt) in transcript.value.staged_receipts.iter_mut().enumerate() {
            let index = 4 + offset;
            let ShardRoleV2::Parity(role) = &transcript.value.manifest.value.group.roles[index]
            else {
                unreachable!();
            };
            receipt.value.plan_hash = plan_hash;
            receipt.value.group_id = transcript.value.manifest.value.group.id;
            receipt.value.commitment = role.commitment.clone();
            *receipt = SignedRecord::sign(
                STAGED_STORAGE_RECEIPT_DOMAIN,
                receipt.value.clone(),
                &keys[index],
            )
            .unwrap();
        }
        assert_eq!(parity.commitment, commitment);
        let nonce = transcript.value.challenge_reveal.value.nonce;
        transcript.value.challenge_commitment.value.plan_hash = plan_hash;
        transcript.value.challenge_commitment.value.commitment =
            coding_challenge_commitment(plan_hash, nonce);
        transcript.value.challenge_commitment = SignedRecord::sign(
            CODING_CHALLENGE_COMMITMENT_DOMAIN,
            transcript.value.challenge_commitment.value,
            &keys[8],
        )
        .unwrap();
        let evidence_hash = coding_evidence_hash(
            &transcript.value.manifest,
            &transcript.value.staged_receipts,
        )
        .unwrap();
        let challenge = coding_challenge(plan_hash, nonce, evidence_hash);
        transcript.value.challenge_reveal.value.plan_hash = plan_hash;
        transcript.value.challenge_reveal.value.evidence_hash = evidence_hash;
        transcript.value.challenge_reveal = SignedRecord::sign(
            CODING_CHALLENGE_REVEAL_DOMAIN,
            transcript.value.challenge_reveal.value,
            &keys[8],
        )
        .unwrap();
        for (index, opening) in transcript.value.openings.iter_mut().enumerate() {
            let (_, expected) =
                role_holder_and_commitment(&transcript.value.manifest.value.group.roles[index]);
            let leaf = challenged_leaf(&challenge, expected).unwrap();
            opening.value.plan_hash = plan_hash;
            opening.value.challenge = challenge;
            opening.value.commitment = expected.clone();
            opening.value.proof = merkle_open_range(&shards[index], leaf, 1).unwrap();
            *opening = SignedRecord::sign(
                CODING_SHARD_OPENING_DOMAIN,
                opening.value.clone(),
                &keys[index],
            )
            .unwrap();
        }
        transcript =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, transcript.value, &keys[8]).unwrap();
        assert_eq!(
            replay_coding_transcript(&transcript).unwrap(),
            CodingReplayFinding::InvalidCoding { coordinator }
        );
    }

    #[test]
    fn missing_evidence_proves_only_unavailability() {
        let (mut transcript, keys, _) = signed_transcript();
        transcript.value.openings.pop();
        transcript =
            SignedRecord::sign(CODING_TRANSCRIPT_DOMAIN, transcript.value, &keys[8]).unwrap();
        assert!(matches!(
            replay_coding_transcript(&transcript),
            Err(CodingAttemptError::Incomplete)
        ));
    }
}
