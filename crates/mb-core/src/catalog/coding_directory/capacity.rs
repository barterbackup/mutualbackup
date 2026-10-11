//! Construction bounds for full original witnesses, not compact-only sizing.
//! These are coding-section credits. Other checkpoint sections, SQL copies,
//! indexes, journals, scratch and filesystem allocation need separate credits.

use super::*;

/// A conservative upper bound for a directory containing at most this many
/// original witnesses. Includes every supported 600 KiB transcript, framing,
/// forest descriptors, the directory envelope and page occurrences. Encoded
/// page bytes bound immutable page payloads only; they are not physical space.
/// This derived local value has no wire decoder and grants no authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogCodingDirectoryCapacity {
    pub groups: u64,
    pub forests: u64,
    pub transcript_bytes: u64,
    pub evidence_bytes: u64,
    pub directory_bytes: u64,
    pub work: CatalogCodingTraversalBudget,
    pub encoded_page_bytes: u64,
}

impl CatalogCodingDirectoryCapacity {
    /// Bound the existing directory builder's automatic single-tree forests.
    /// Each nonfinal forest accepts at least `groups_per_forest` groups, even
    /// when all groups use the full supported witness/framing allowance.
    pub fn for_groups(groups: u64) -> Result<Self, CatalogError> {
        Self::with_forest_limit(groups, CATALOG_MAX_STREAM_BYTES)
    }

    pub(super) fn with_forest_limit(groups: u64, forest_limit: u64) -> Result<Self, CatalogError> {
        let group_bytes = CATALOG_CODING_GROUP_BYTES as u64;
        let available = forest_limit
            .checked_sub(8 + CATALOG_CODING_ROOT_BYTES as u64)
            .ok_or(CatalogError::Bounds)?;
        let groups_per_forest = available / group_bytes;
        if groups_per_forest == 0 || forest_limit > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds);
        }
        let forests = groups.div_ceil(groups_per_forest);
        if forests > CATALOG_MAX_RECORDS {
            return Err(CatalogError::Bounds);
        }
        let transcript_bytes = groups
            .checked_mul(CATALOG_CODING_TRANSCRIPT_BYTES as u64)
            .ok_or(CatalogError::Bounds)?;
        let evidence_bytes = groups
            .checked_mul(group_bytes)
            .and_then(|bytes| {
                forests
                    .checked_mul(8)
                    .and_then(|headers| bytes.checked_add(headers))
            })
            .ok_or(CatalogError::Bounds)?;
        let directory_bytes = forests
            .checked_mul(4 + CATALOG_CODING_ROOT_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(8))
            .ok_or(CatalogError::Bounds)?;
        if directory_bytes > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds);
        }
        let directory_pages = dense_pages(directory_bytes)?;
        if directory_pages > CATALOG_MAX_PAGE_OCCURRENCES {
            return Err(CatalogError::Bounds);
        }
        // Trees round separately at every level. Rounding once over the
        // concatenated evidence would under-reserve small/tail forests.
        let evidence_pages = dense_forest_pages(evidence_bytes, forests)?;
        let records = groups
            .checked_mul(
                1 + (CATALOG_CODING_TRANSCRIPT_BYTES as u64)
                    .div_ceil(CATALOG_CODING_FRAGMENT_BYTES as u64),
            )
            .and_then(|records| records.checked_add(forests))
            .ok_or(CatalogError::Bounds)?;
        let page_occurrences = evidence_pages
            .checked_add(directory_pages)
            .ok_or(CatalogError::Bounds)?;
        Ok(Self {
            groups,
            forests,
            transcript_bytes,
            evidence_bytes,
            directory_bytes,
            work: CatalogCodingTraversalBudget {
                bytes: evidence_bytes
                    .checked_add(directory_bytes)
                    .and_then(|bytes| bytes.checked_add(CATALOG_CODING_DIRECTORY_ROOT_BYTES as u64))
                    .ok_or(CatalogError::Bounds)?,
                page_occurrences,
                records,
            },
            encoded_page_bytes: page_occurrences
                .checked_mul(CATALOG_PAGE_BYTES as u64)
                .ok_or(CatalogError::Bounds)?,
        })
    }
}

/// For `n` independently rounded dense trees, sum(ceil(x_i / d)) is at most
/// ceil(sum(x_i) / d) + n - 1. Apply at leaves and each possible index level.
/// Counting all index levels deliberately over-reserves shorter trees; no
/// forest's credit is reused for another forest. The builder limits each tree.
fn dense_forest_pages(bytes: u64, forests: u64) -> Result<u64, CatalogError> {
    if forests == 0 {
        return if bytes == 0 {
            Ok(0)
        } else {
            Err(CatalogError::Bounds)
        };
    }
    let rounding = forests - 1;
    let mut nodes = bytes
        .div_ceil(CATALOG_LEAF_BYTES as u64)
        .max(1)
        .checked_add(rounding)
        .ok_or(CatalogError::Bounds)?;
    let mut pages = nodes;
    for _ in 0..CATALOG_MAX_HEIGHT {
        nodes = nodes
            .div_ceil(CATALOG_FANOUT as u64)
            .checked_add(rounding)
            .ok_or(CatalogError::Bounds)?;
        pages = pages.checked_add(nodes).ok_or(CatalogError::Bounds)?;
    }
    Ok(pages)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separate_forest_rounding_bounds_leaf_and_index_tails() {
        let leaf = CATALOG_LEAF_BYTES as u64;
        for trees in [1_u64, 2, 3, 127, 128, 129, 257] {
            for base in [0, 1, leaf - 1, leaf, leaf + 1, 127 * leaf, 128 * leaf + 1] {
                let sizes = (0..trees).map(|n| base + n % 3).collect::<Vec<_>>();
                let actual = sizes
                    .iter()
                    .map(|bytes| dense_pages(*bytes).unwrap())
                    .sum::<u64>();
                let upper = dense_forest_pages(sizes.iter().sum(), trees).unwrap();
                assert!(
                    upper >= actual,
                    "{trees} trees, {base} bytes: {upper} < {actual}"
                );
            }
        }
        assert_eq!(dense_forest_pages(0, 0).unwrap(), 0);
        assert!(dense_forest_pages(1, 0).is_err());
        assert!(dense_forest_pages(u64::MAX, u64::MAX).is_err());
    }

    #[test]
    fn full_witness_capacity_reserves_frames_forests_and_encoding_separately() {
        let groups_per_forest = (CATALOG_MAX_STREAM_BYTES - 8 - CATALOG_CODING_ROOT_BYTES as u64)
            / CATALOG_CODING_GROUP_BYTES as u64;
        for groups in [0, 1, groups_per_forest, groups_per_forest + 1, 7_456_541] {
            let capacity = CatalogCodingDirectoryCapacity::for_groups(groups).unwrap();
            assert_eq!(capacity.forests, groups.div_ceil(groups_per_forest));
            assert_eq!(capacity.transcript_bytes, groups * 600 * 1024);
            assert_eq!(
                capacity.evidence_bytes,
                groups * CATALOG_CODING_GROUP_BYTES as u64 + 8 * capacity.forests
            );
            assert_eq!(capacity.directory_bytes, 8 + capacity.forests * 516);
            assert_eq!(capacity.work.records, groups * 39 + capacity.forests);
            assert_eq!(
                capacity.encoded_page_bytes,
                capacity.work.page_occurrences * CATALOG_PAGE_BYTES as u64
            );
            assert!(capacity.work.bytes > capacity.transcript_bytes);
        }
        let empty = CatalogCodingDirectoryCapacity::for_groups(0).unwrap();
        assert_eq!(
            empty.work,
            CatalogCodingTraversalBudget {
                bytes: 520,
                page_occurrences: 1,
                records: 0
            }
        );
        // The individually supported original witness bound gives a true
        // coding upper bound, unlike the 62.7 GB compact-only lower bound.
        let dense = CatalogCodingDirectoryCapacity::for_groups(7_456_541).unwrap();
        assert!(dense.transcript_bytes > 4 * (1_u64 << 40));
        assert!(dense.forests > 1 && dense.work.page_occurrences > 1_000_000);
        assert!(dense.encoded_page_bytes > dense.work.bytes);
        assert!(CatalogCodingDirectoryCapacity::for_groups(u64::MAX).is_err());
        assert!(
            CatalogCodingDirectoryCapacity::with_forest_limit(1, CATALOG_CODING_GROUP_BYTES as u64)
                .is_err()
        );
        assert!(
            CatalogCodingDirectoryCapacity::with_forest_limit(1, CATALOG_MAX_STREAM_BYTES + 1)
                .is_err()
        );
    }
}
