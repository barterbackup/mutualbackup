use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    CodingGroupV2, MerkleCommitment, MerkleRangeProof, ModelError, NodeId, ShardRoleV2,
    SignedRecord, canonical_bytes, challenged_leaf, merkle_verify_range, verify_sampled_codeword,
};

pub const CODING_ATTEMPT_PLAN_DOMAIN: &[u8] = b"mutualbackup/coding-attempt-plan/v1";
pub const CODING_ROOT_MANIFEST_DOMAIN: &[u8] = b"mutualbackup/coding-root-manifest/v1";
pub const STAGED_STORAGE_RECEIPT_DOMAIN: &[u8] = b"mutualbackup/staged-storage-receipt/v1";
pub const CODING_CHALLENGE_COMMITMENT_DOMAIN: &[u8] =
    b"mutualbackup/coding-challenge-commitment/v1";
pub const CODING_CHALLENGE_REVEAL_DOMAIN: &[u8] = b"mutualbackup/coding-challenge-reveal/v1";
pub const CODING_SHARD_OPENING_DOMAIN: &[u8] = b"mutualbackup/coding-shard-opening/v1";
pub const CODING_TRANSCRIPT_DOMAIN: &[u8] = b"mutualbackup/coding-transcript/v1";

/// The immutable, narrow delegation for one complete coding attempt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingAttemptPlan {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub checkpoint_hash: [u8; 32],
    pub membership_epoch: u64,
    pub group: CodingGroupV2,
    pub delegator: NodeId,
    pub coding_coordinator: NodeId,
    pub verification_coordinator: NodeId,
    pub expires_at_unix_seconds: u64,
}

impl CodingAttemptPlan {
    pub fn validate(&self) -> Result<(), CodingAttemptError> {
        self.group.validate()?;
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

/// The coordinator's signed acceptance of the exact ordered input and output
/// commitments in the delegated plan.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingRootManifest {
    pub format_version: u16,
    pub attempt_id: [u8; 16],
    pub plan_hash: [u8; 32],
    pub ordered_commitments: Vec<MerkleCommitment>,
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
    pub plan: SignedRecord<CodingAttemptPlan>,
    pub manifest: SignedRecord<CodingRootManifest>,
    pub challenge_commitment: SignedRecord<CodingChallengeCommitment>,
    pub staged_receipts: Vec<SignedRecord<StagedStorageReceipt>>,
    pub challenge_reveal: SignedRecord<CodingChallengeReveal>,
    pub openings: Vec<SignedRecord<CodingShardOpening>>,
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

#[derive(Debug, Error)]
pub enum CodingAttemptError {
    #[error("the coding attempt plan is invalid")]
    InvalidPlan,
    #[error("the coding transcript is structurally invalid")]
    InvalidTranscript,
    #[error("the coding transcript is incomplete; this proves only unavailability")]
    Incomplete,
    #[error("canonical coding evidence encoding failed: {0}")]
    Model(#[from] ModelError),
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
        || transcript.plan.signer != plan.delegator
        || signed.signer != plan.verification_coordinator
    {
        return Err(CodingAttemptError::InvalidTranscript);
    }
    transcript.plan.verify(CODING_ATTEMPT_PLAN_DOMAIN)?;
    let plan_hash = plan.hash()?;

    let commitments = plan
        .group
        .roles
        .iter()
        .map(role_commitment)
        .cloned()
        .collect::<Vec<_>>();
    let manifest = &transcript.manifest.value;
    transcript.manifest.verify(CODING_ROOT_MANIFEST_DOMAIN)?;
    if transcript.manifest.signer != plan.coding_coordinator
        || manifest.format_version != 1
        || manifest.attempt_id != plan.attempt_id
        || manifest.plan_hash != plan_hash
        || manifest.ordered_commitments != commitments
    {
        return Err(CodingAttemptError::InvalidTranscript);
    }

    let parity_start = usize::from(plan.group.profile.data_shards);
    if transcript.staged_receipts.len() != usize::from(plan.group.profile.parity_shards) {
        return Err(CodingAttemptError::Incomplete);
    }
    for (offset, receipt) in transcript.staged_receipts.iter().enumerate() {
        receipt.verify(STAGED_STORAGE_RECEIPT_DOMAIN)?;
        let index = parity_start + offset;
        let ShardRoleV2::Parity(parity) = &plan.group.roles[index] else {
            return Err(CodingAttemptError::InvalidTranscript);
        };
        let value = &receipt.value;
        if receipt.signer != parity.holder
            || value.format_version != 1
            || value.attempt_id != plan.attempt_id
            || value.plan_hash != plan_hash
            || value.guild_id != plan.group.guild_id
            || value.group_id != plan.group.id
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

    if transcript.openings.len() != plan.group.roles.len() {
        return Err(CodingAttemptError::Incomplete);
    }
    let mut symbols = Vec::with_capacity(transcript.openings.len());
    for (index, opening) in transcript.openings.iter().enumerate() {
        let (holder, expected_commitment) = role_holder_and_commitment(&plan.group.roles[index]);
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
    if verify_sampled_codeword(plan.group.profile, &symbols).is_err() {
        return Ok(CodingReplayFinding::InvalidCoding {
            coordinator: plan.coding_coordinator,
        });
    }
    Ok(CodingReplayFinding::Verified)
}

fn role_commitment(role: &ShardRoleV2) -> &MerkleCommitment {
    match role {
        ShardRoleV2::Information(information) => &information.sector.commitment,
        ShardRoleV2::Parity(parity) => &parity.commitment,
    }
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
        let shards = encode(profile, information).unwrap();
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
            group,
            delegator: keys[6].node_id(),
            coding_coordinator: keys[7].node_id(),
            verification_coordinator: keys[8].node_id(),
            expires_at_unix_seconds: 2_000_000_000,
        };
        let plan_hash = plan.hash().unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, &keys[6]).unwrap();
        let ordered_commitments = plan
            .value
            .group
            .roles
            .iter()
            .map(role_commitment)
            .cloned()
            .collect();
        let manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            CodingRootManifest {
                format_version: 1,
                attempt_id: [4; 16],
                plan_hash,
                ordered_commitments,
            },
            &keys[7],
        )
        .unwrap();
        let staged_receipts = (4_usize..6)
            .map(|index| {
                let ShardRoleV2::Parity(parity) = &plan.value.group.roles[index] else {
                    unreachable!();
                };
                SignedRecord::sign(
                    STAGED_STORAGE_RECEIPT_DOMAIN,
                    StagedStorageReceipt {
                        format_version: 1,
                        attempt_id: [4; 16],
                        plan_hash,
                        guild_id: [8; 32],
                        group_id: plan.value.group.id,
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
                    role_holder_and_commitment(&plan.value.group.roles[index]);
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
        let ShardRoleV2::Parity(parity) = &mut transcript.value.plan.value.group.roles[5] else {
            unreachable!();
        };
        parity.commitment = commitment.clone();
        transcript.value.plan.value.group.id =
            transcript.value.plan.value.group.calculate_id().unwrap();
        let plan_hash = transcript.value.plan.value.hash().unwrap();
        transcript.value.plan = SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            transcript.value.plan.value,
            &keys[6],
        )
        .unwrap();
        transcript.value.manifest.value.plan_hash = plan_hash;
        transcript.value.manifest.value.ordered_commitments[5] = commitment.clone();
        transcript.value.manifest = SignedRecord::sign(
            CODING_ROOT_MANIFEST_DOMAIN,
            transcript.value.manifest.value,
            &keys[7],
        )
        .unwrap();
        let ShardRoleV2::Parity(parity) = &transcript.value.plan.value.group.roles[5] else {
            unreachable!();
        };
        for (offset, receipt) in transcript.value.staged_receipts.iter_mut().enumerate() {
            let index = 4 + offset;
            let ShardRoleV2::Parity(role) = &transcript.value.plan.value.group.roles[index] else {
                unreachable!();
            };
            receipt.value.plan_hash = plan_hash;
            receipt.value.group_id = transcript.value.plan.value.group.id;
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
                role_holder_and_commitment(&transcript.value.plan.value.group.roles[index]);
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
