use reed_solomon_erasure::galois_8::ReedSolomon;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CodingError {
    #[error("all information shards must have equal, non-zero length")]
    InvalidShardLength,
    #[error("a 3+2 codeword must contain exactly five shard slots")]
    InvalidShardCount,
    #[error("Reed--Solomon error: {0}")]
    ReedSolomon(#[from] reed_solomon_erasure::Error),
}

/// Encode three information shards into a systematic 3+2 codeword.
pub fn encode_3_2(information: [Vec<u8>; 3]) -> Result<[Vec<u8>; 5], CodingError> {
    let shard_len = information[0].len();
    if shard_len == 0 || information.iter().any(|shard| shard.len() != shard_len) {
        return Err(CodingError::InvalidShardLength);
    }
    let [a, b, c] = information;
    let mut shards = [a, b, c, vec![0; shard_len], vec![0; shard_len]];
    ReedSolomon::new(3, 2)?.encode(&mut shards)?;
    Ok(shards)
}

/// Reconstruct a 3+2 codeword from any three valid shards.
pub fn reconstruct_3_2(shards: &mut [Option<Vec<u8>>]) -> Result<(), CodingError> {
    if shards.len() != 5 {
        return Err(CodingError::InvalidShardCount);
    }
    ReedSolomon::new(3, 2)?.reconstruct(shards)?;
    Ok(())
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
}
