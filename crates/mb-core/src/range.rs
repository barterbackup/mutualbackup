use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const MERKLE_LEAF_SIZE: usize = 16;
pub const MERKLE_SUITE_V1: u16 = 1;
const MAX_MERKLE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleCommitment {
    pub format_version: u16,
    pub leaf_size: u16,
    pub byte_len: u32,
    pub root: [u8; 32],
}

impl MerkleCommitment {
    pub fn validate(&self) -> Result<(), MerkleError> {
        validate_commitment(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MerkleRangeProof {
    pub format_version: u16,
    pub start_leaf: u32,
    pub leaves: Vec<[u8; MERKLE_LEAF_SIZE]>,
    /// Siblings ordered from the proved subtree toward the root.
    pub siblings: Vec<[u8; 32]>,
}

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("Merkle data length must be a bounded power-of-two multiple of 16 bytes")]
    InvalidDataLength,
    #[error("Merkle range must be a non-empty aligned power-of-two leaf range")]
    InvalidRange,
    #[error("Merkle proof shape or version is invalid")]
    InvalidProof,
    #[error("Merkle proof does not open the committed root")]
    RootMismatch,
}

/// Commit bytes using the version-one 16-byte-leaf Merkle suite.
pub fn merkle_commit(bytes: &[u8]) -> Result<MerkleCommitment, MerkleError> {
    validate_data_len(bytes.len())?;
    let levels = merkle_levels(bytes);
    let tree_root = levels.last().expect("validated tree has a root")[0];
    Ok(MerkleCommitment {
        format_version: MERKLE_SUITE_V1,
        leaf_size: MERKLE_LEAF_SIZE as u16,
        byte_len: bytes.len() as u32,
        root: bind_root(bytes.len() as u32, tree_root),
    })
}

/// Compute the canonical commitment for an authenticated virtual-zero shard
/// without allocating the shard itself.
pub fn merkle_zero_commitment(byte_len: u32) -> Result<MerkleCommitment, MerkleError> {
    validate_data_len(byte_len as usize)?;
    let mut tree_root = hash_leaf(&[0; MERKLE_LEAF_SIZE]);
    let leaf_count = byte_len as usize / MERKLE_LEAF_SIZE;
    for _ in 0..leaf_count.ilog2() {
        tree_root = hash_node(&tree_root, &tree_root);
    }
    Ok(MerkleCommitment {
        format_version: MERKLE_SUITE_V1,
        leaf_size: MERKLE_LEAF_SIZE as u16,
        byte_len,
        root: bind_root(byte_len, tree_root),
    })
}

/// Open one aligned power-of-two range. A single-leaf proof carries exactly
/// the 16 bytes used by the sampled Reed--Solomon verification protocol.
pub fn merkle_open_range(
    bytes: &[u8],
    start_leaf: u32,
    leaf_count: u32,
) -> Result<MerkleRangeProof, MerkleError> {
    validate_data_len(bytes.len())?;
    let total_leaves = bytes.len() / MERKLE_LEAF_SIZE;
    let start = usize::try_from(start_leaf).map_err(|_| MerkleError::InvalidRange)?;
    let count = usize::try_from(leaf_count).map_err(|_| MerkleError::InvalidRange)?;
    if count == 0
        || !count.is_power_of_two()
        || start % count != 0
        || start
            .checked_add(count)
            .is_none_or(|end| end > total_leaves)
    {
        return Err(MerkleError::InvalidRange);
    }

    let levels = merkle_levels(bytes);
    let subtree_level = count.ilog2() as usize;
    let mut node_index = start >> subtree_level;
    let mut siblings = Vec::with_capacity(levels.len() - subtree_level - 1);
    for level in levels.iter().take(levels.len() - 1).skip(subtree_level) {
        siblings.push(level[node_index ^ 1]);
        node_index >>= 1;
    }
    let leaves = bytes[start * MERKLE_LEAF_SIZE..(start + count) * MERKLE_LEAF_SIZE]
        .as_chunks::<MERKLE_LEAF_SIZE>()
        .0
        .to_vec();
    Ok(MerkleRangeProof {
        format_version: MERKLE_SUITE_V1,
        start_leaf,
        leaves,
        siblings,
    })
}

/// Verify and return the exact authenticated range carried by `proof`.
pub fn merkle_verify_range(
    commitment: &MerkleCommitment,
    proof: &MerkleRangeProof,
) -> Result<Vec<u8>, MerkleError> {
    validate_commitment(commitment)?;
    let total_leaves = commitment.byte_len as usize / MERKLE_LEAF_SIZE;
    let start = usize::try_from(proof.start_leaf).map_err(|_| MerkleError::InvalidProof)?;
    let count = proof.leaves.len();
    if proof.format_version != MERKLE_SUITE_V1
        || count == 0
        || !count.is_power_of_two()
        || start % count != 0
        || start
            .checked_add(count)
            .is_none_or(|end| end > total_leaves)
    {
        return Err(MerkleError::InvalidProof);
    }
    let subtree_level = count.ilog2() as usize;
    let tree_height = total_leaves.ilog2() as usize;
    if proof.siblings.len() != tree_height - subtree_level {
        return Err(MerkleError::InvalidProof);
    }

    let mut nodes = proof.leaves.iter().map(hash_leaf).collect::<Vec<_>>();
    while nodes.len() > 1 {
        nodes = nodes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_node(&pair[0], &pair[1]))
            .collect();
    }
    let mut current = nodes[0];
    let mut node_index = start >> subtree_level;
    for sibling in &proof.siblings {
        current = if node_index & 1 == 0 {
            hash_node(&current, sibling)
        } else {
            hash_node(sibling, &current)
        };
        node_index >>= 1;
    }
    if bind_root(commitment.byte_len, current) != commitment.root {
        return Err(MerkleError::RootMismatch);
    }
    Ok(proof.leaves.iter().flatten().copied().collect())
}

/// Derive the uniformly selected leaf for one verifier challenge.
///
/// Every accepted tree has a power-of-two leaf count, so masking introduces
/// no modulo bias.
pub fn challenged_leaf(
    challenge: &[u8; 32],
    commitment: &MerkleCommitment,
) -> Result<u32, MerkleError> {
    validate_commitment(commitment)?;
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup range challenge v1");
    hasher.update(challenge);
    hasher.update(&commitment.byte_len.to_be_bytes());
    let digest = hasher.finalize();
    let value = u64::from_be_bytes(digest.as_bytes()[..8].try_into().expect("fixed digest"));
    let leaf_count = u64::from(commitment.byte_len) / MERKLE_LEAF_SIZE as u64;
    Ok((value & (leaf_count - 1)) as u32)
}

fn validate_commitment(commitment: &MerkleCommitment) -> Result<(), MerkleError> {
    if commitment.format_version != MERKLE_SUITE_V1
        || commitment.leaf_size != MERKLE_LEAF_SIZE as u16
        || commitment.root == [0; 32]
    {
        return Err(MerkleError::InvalidProof);
    }
    validate_data_len(commitment.byte_len as usize)
}

fn validate_data_len(len: usize) -> Result<(), MerkleError> {
    if !(MERKLE_LEAF_SIZE..=MAX_MERKLE_BYTES).contains(&len)
        || !len.is_power_of_two()
        || !len.is_multiple_of(MERKLE_LEAF_SIZE)
    {
        return Err(MerkleError::InvalidDataLength);
    }
    Ok(())
}

fn merkle_levels(bytes: &[u8]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![
        bytes
            .as_chunks::<MERKLE_LEAF_SIZE>()
            .0
            .iter()
            .map(hash_leaf)
            .collect::<Vec<_>>(),
    ];
    while levels.last().expect("leaf level exists").len() > 1 {
        let next = levels
            .last()
            .expect("previous level exists")
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_node(&pair[0], &pair[1]))
            .collect();
        levels.push(next);
    }
    levels
}

fn hash_leaf(leaf: &[u8; MERKLE_LEAF_SIZE]) -> [u8; 32] {
    blake3::derive_key("mutualbackup merkle leaf v1", leaf)
}

fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup merkle node v1");
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

fn bind_root(byte_len: u32, tree_root: [u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup merkle root v1");
    hasher.update(&MERKLE_SUITE_V1.to_be_bytes());
    hasher.update(&(MERKLE_LEAF_SIZE as u16).to_be_bytes());
    hasher.update(&byte_len.to_be_bytes());
    hasher.update(&tree_root);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_aligned_power_of_two_range_opens() {
        let bytes = (0_u32..1024).map(|value| value as u8).collect::<Vec<_>>();
        let commitment = merkle_commit(&bytes).unwrap();
        let total_leaves = bytes.len() / MERKLE_LEAF_SIZE;
        for count in [1_usize, 2, 4, 8, 16, 32, 64] {
            for start in (0..total_leaves).step_by(count) {
                let proof = merkle_open_range(&bytes, start as u32, count as u32).unwrap();
                let opened = merkle_verify_range(&commitment, &proof).unwrap();
                assert_eq!(
                    opened,
                    bytes[start * MERKLE_LEAF_SIZE..(start + count) * MERKLE_LEAF_SIZE]
                );
            }
        }
    }

    #[test]
    fn proof_binds_bytes_position_length_and_shape() {
        let bytes = (0_u32..256).map(|value| value as u8).collect::<Vec<_>>();
        let commitment = merkle_commit(&bytes).unwrap();
        let proof = merkle_open_range(&bytes, 7, 1).unwrap();
        assert_eq!(merkle_verify_range(&commitment, &proof).unwrap().len(), 16);

        let mut corrupt_leaf = proof.clone();
        corrupt_leaf.leaves[0][0] ^= 1;
        assert!(matches!(
            merkle_verify_range(&commitment, &corrupt_leaf),
            Err(MerkleError::RootMismatch)
        ));
        let mut wrong_position = proof.clone();
        wrong_position.start_leaf = 6;
        assert!(matches!(
            merkle_verify_range(&commitment, &wrong_position),
            Err(MerkleError::RootMismatch)
        ));
        let mut wrong_length = commitment.clone();
        wrong_length.byte_len = 128;
        assert!(merkle_verify_range(&wrong_length, &proof).is_err());
        let mut extra_sibling = proof;
        extra_sibling.siblings.push([9; 32]);
        assert!(matches!(
            merkle_verify_range(&commitment, &extra_sibling),
            Err(MerkleError::InvalidProof)
        ));
    }

    #[test]
    fn one_challenge_selects_the_same_leaf_for_every_equal_size_shard() {
        let first = merkle_commit(&vec![3; 64 * 1024]).unwrap();
        let second = merkle_commit(&vec![7; 64 * 1024]).unwrap();
        let challenge = [11; 32];
        assert_eq!(
            challenged_leaf(&challenge, &first).unwrap(),
            challenged_leaf(&challenge, &second).unwrap()
        );
        assert!(challenged_leaf(&challenge, &first).unwrap() < 4096);
    }

    #[test]
    fn virtual_zero_commitment_matches_materialized_bytes() {
        for byte_len in [16_u32, 64, 4096, 64 * 1024] {
            assert_eq!(
                merkle_zero_commitment(byte_len).unwrap(),
                merkle_commit(&vec![0; byte_len as usize]).unwrap()
            );
        }
    }

    #[test]
    fn merkle_range_suite_matches_the_committed_vector() {
        let vector = include_str!("../../../protocol/vectors/merkle-range-v1.txt");
        let vector_value = |name: &str| {
            vector
                .lines()
                .find_map(|line| line.strip_prefix(&format!("{name}=")))
                .unwrap_or_else(|| panic!("missing vector field {name}"))
        };
        let bytes = (0_u8..64).collect::<Vec<_>>();
        let commitment = merkle_commit(&bytes).unwrap();
        let proof = merkle_open_range(&bytes, 2, 1).unwrap();
        assert_eq!(hex::encode(&bytes), vector_value("input"));
        assert_eq!(hex::encode(commitment.root), vector_value("root"));
        assert_eq!(proof.start_leaf.to_string(), vector_value("start_leaf"));
        assert_eq!(hex::encode(proof.leaves[0]), vector_value("leaf"));
        assert_eq!(
            proof
                .siblings
                .iter()
                .map(hex::encode)
                .collect::<Vec<_>>()
                .join(","),
            vector_value("siblings")
        );
        assert_eq!(
            challenged_leaf(&[11; 32], &commitment).unwrap().to_string(),
            vector_value("challenge_leaf")
        );
    }
}
