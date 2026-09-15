use reed_solomon_erasure::galois_8::ReedSolomon;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum geometry accepted by the version-one variable coding profile.
///
/// Galois-8 can represent more shards, but this protocol bound keeps coding
/// memory, catalog size, and per-attempt network fanout predictable.
pub const MAX_CODING_SHARDS: u16 = 64;
pub const MAX_PROFILE_SHARD_SIZE: u32 = 4 * 1024 * 1024;
pub const MIN_PROFILE_SHARD_SIZE: u32 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ReedSolomonConstruction {
    /// The systematic Galois-8 Vandermonde matrix implemented by the pinned
    /// `reed-solomon-erasure` protocol dependency.
    Galois8Vandermonde,
}

/// A complete, versioned description of one Reed--Solomon codeword geometry.
///
/// Committed groups carry this value so recovery never infers a profile from
/// the current guild size or from local defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CodingProfile {
    pub format_version: u16,
    pub construction: ReedSolomonConstruction,
    pub data_shards: u16,
    pub parity_shards: u16,
    pub shard_size: u32,
}

impl CodingProfile {
    pub const fn new(data_shards: u16, parity_shards: u16, shard_size: u32) -> Self {
        Self {
            format_version: 1,
            construction: ReedSolomonConstruction::Galois8Vandermonde,
            data_shards,
            parity_shards,
            shard_size,
        }
    }

    pub fn validate(self) -> Result<(), CodingError> {
        let total = self
            .data_shards
            .checked_add(self.parity_shards)
            .ok_or(CodingError::InvalidProfile)?;
        if self.format_version != 1
            || self.data_shards == 0
            || self.parity_shards == 0
            || total > MAX_CODING_SHARDS
            || self.shard_size < MIN_PROFILE_SHARD_SIZE
            || self.shard_size > MAX_PROFILE_SHARD_SIZE
            || !self.shard_size.is_power_of_two()
        {
            return Err(CodingError::InvalidProfile);
        }
        Ok(())
    }

    pub fn total_shards(self) -> Result<usize, CodingError> {
        self.validate()?;
        Ok(usize::from(self.data_shards + self.parity_shards))
    }
}

#[derive(Debug, Error)]
pub enum CodingError {
    #[error("invalid or unsupported coding profile")]
    InvalidProfile,
    #[error("all shards must have the size declared by the coding profile")]
    InvalidShardLength,
    #[error("the shard count does not match the coding profile")]
    InvalidShardCount,
    #[error("the shards do not form the codeword declared by the coding profile")]
    InvalidCodeword,
    #[error("Reed--Solomon error: {0}")]
    ReedSolomon(#[from] reed_solomon_erasure::Error),
}

/// Encode a systematic codeword for an explicit variable geometry.
pub fn encode(
    profile: CodingProfile,
    mut information: Vec<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, CodingError> {
    profile.validate()?;
    if information.len() != usize::from(profile.data_shards) {
        return Err(CodingError::InvalidShardCount);
    }
    if information
        .iter()
        .any(|shard| shard.len() != profile.shard_size as usize)
    {
        return Err(CodingError::InvalidShardLength);
    }
    information.extend((0..profile.parity_shards).map(|_| vec![0_u8; profile.shard_size as usize]));
    ReedSolomon::new(
        usize::from(profile.data_shards),
        usize::from(profile.parity_shards),
    )?
    .encode(&mut information)?;
    Ok(information)
}

/// Reconstruct a codeword from any `data_shards` valid positions.
pub fn reconstruct(
    profile: CodingProfile,
    shards: &mut [Option<Vec<u8>>],
) -> Result<(), CodingError> {
    if shards.len() != profile.total_shards()? {
        return Err(CodingError::InvalidShardCount);
    }
    if shards
        .iter()
        .flatten()
        .any(|shard| shard.len() != profile.shard_size as usize)
    {
        return Err(CodingError::InvalidShardLength);
    }
    ReedSolomon::new(
        usize::from(profile.data_shards),
        usize::from(profile.parity_shards),
    )?
    .reconstruct(shards)?;
    Ok(())
}

/// Check a complete codeword without modifying it.
pub fn verify_codeword(profile: CodingProfile, shards: &[Vec<u8>]) -> Result<(), CodingError> {
    if shards.len() != profile.total_shards()? {
        return Err(CodingError::InvalidShardCount);
    }
    if shards
        .iter()
        .any(|shard| shard.len() != profile.shard_size as usize)
    {
        return Err(CodingError::InvalidShardLength);
    }
    if !ReedSolomon::new(
        usize::from(profile.data_shards),
        usize::from(profile.parity_shards),
    )?
    .verify(shards)?
    {
        return Err(CodingError::InvalidCodeword);
    }
    Ok(())
}

/// Verify one equal-width Reed--Solomon symbol range from every shard.
///
/// Callers authenticate each range against its committed Merkle root before
/// invoking this function. The verifier therefore checks the coding equation
/// without receiving or recomputing a complete shard.
pub fn verify_sampled_codeword(
    profile: CodingProfile,
    symbols: &[[u8; 16]],
) -> Result<(), CodingError> {
    if symbols.len() != profile.total_shards()? {
        return Err(CodingError::InvalidShardCount);
    }
    if !ReedSolomon::new(
        usize::from(profile.data_shards),
        usize::from(profile.parity_shards),
    )?
    .verify(symbols)?
    {
        return Err(CodingError::InvalidCodeword);
    }
    Ok(())
}

/// Encode three information shards into the fixed prototype 3+2 codeword.
pub fn encode_3_2(information: [Vec<u8>; 3]) -> Result<[Vec<u8>; 5], CodingError> {
    let shard_size =
        u32::try_from(information[0].len()).map_err(|_| CodingError::InvalidShardLength)?;
    let encoded = encode(CodingProfile::new(3, 2, shard_size), information.into())?;
    encoded
        .try_into()
        .map_err(|_| CodingError::InvalidShardCount)
}

/// Reconstruct a fixed prototype 3+2 codeword from any three valid shards.
pub fn reconstruct_3_2(shards: &mut [Option<Vec<u8>>]) -> Result<(), CodingError> {
    let shard_size = shards
        .iter()
        .flatten()
        .next()
        .and_then(|shard| u32::try_from(shard.len()).ok())
        .ok_or(CodingError::InvalidShardLength)?;
    reconstruct(CodingProfile::new(3, 2, shard_size), shards)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_three_shards_reconstruct() {
        let encoded = encode_3_2([vec![1; 4096], vec![2; 4096], vec![3; 4096]]).unwrap();
        for missing_a in 0..5 {
            for missing_b in (missing_a + 1)..5 {
                let mut damaged = encoded.iter().cloned().map(Some).collect::<Vec<_>>();
                damaged[missing_a] = None;
                damaged[missing_b] = None;
                reconstruct_3_2(&mut damaged).unwrap();
                assert_eq!(
                    damaged.into_iter().map(Option::unwrap).collect::<Vec<_>>(),
                    encoded
                );
            }
        }
    }

    #[test]
    fn every_k_subset_reconstructs_variable_profiles() {
        for data_shards in 1_u16..=6 {
            for parity_shards in 1_u16..=3 {
                let profile = CodingProfile::new(data_shards, parity_shards, 32);
                let information = (0..data_shards)
                    .map(|index| {
                        (0..profile.shard_size)
                            .map(|offset| (u32::from(index) * 31 + offset) as u8)
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let encoded = encode(profile, information).unwrap();
                verify_codeword(profile, &encoded).unwrap();
                for survivor_mask in 0_u64..(1_u64 << encoded.len()) {
                    if survivor_mask.count_ones() != u32::from(data_shards) {
                        continue;
                    }
                    let mut damaged = encoded
                        .iter()
                        .enumerate()
                        .map(|(index, shard)| {
                            ((survivor_mask >> index) & 1 == 1).then(|| shard.clone())
                        })
                        .collect::<Vec<_>>();
                    reconstruct(profile, &mut damaged).unwrap();
                    assert_eq!(
                        damaged.into_iter().map(Option::unwrap).collect::<Vec<_>>(),
                        encoded
                    );
                }
            }
        }
    }

    #[test]
    fn profile_and_codeword_bounds_are_enforced() {
        assert!(matches!(
            CodingProfile::new(0, 2, 64).validate(),
            Err(CodingError::InvalidProfile)
        ));
        assert!(matches!(
            CodingProfile::new(32, 33, 64).validate(),
            Err(CodingError::InvalidProfile)
        ));
        assert!(matches!(
            encode(CodingProfile::new(2, 1, 64), vec![vec![0; 64]]),
            Err(CodingError::InvalidShardCount)
        ));
        assert!(matches!(
            encode(CodingProfile::new(2, 1, 64), vec![vec![0; 64], vec![0; 32]]),
            Err(CodingError::InvalidShardLength)
        ));
    }

    #[test]
    fn sampled_symbols_check_the_same_rs_equation() {
        let profile = CodingProfile::new(4, 3, 64);
        let information = (0_u8..4)
            .map(|value| vec![value.wrapping_mul(37); 64])
            .collect();
        let encoded = encode(profile, information).unwrap();
        let symbols = encoded
            .iter()
            .map(|shard| shard[32..48].try_into().unwrap())
            .collect::<Vec<[u8; 16]>>();
        verify_sampled_codeword(profile, &symbols).unwrap();

        let mut corrupt = symbols;
        corrupt[5][7] ^= 1;
        assert!(matches!(
            verify_sampled_codeword(profile, &corrupt),
            Err(CodingError::InvalidCodeword)
        ));
    }
}
