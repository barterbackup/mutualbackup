//! Authenticated byte ranges without scanning preceding or unrelated pages.

use std::ops::Range;

use super::*;

/// Reads an exact byte range from an authenticated root. Each returned chunk
/// belongs to one verified leaf and is bounded by `CATALOG_LEAF_BYTES`.
///
/// Only intersecting subtrees are fetched. Skipped child lengths are trusted
/// only after verifying their parent; this is not whole-catalog validation.
/// An empty range performs no fetch. The caller must obtain the root from a
/// signed record or authenticated parent and bound each fetch's allocation to
/// the expected encoded page length, as with `CatalogReader`.
pub struct CatalogRangeReader {
    scope: CatalogScope,
    section: CatalogSection,
    range: Range<u64>,
    pending: Vec<(CatalogPageRef, u64)>,
    remaining: u64,
    failed: bool,
}

impl CatalogRangeReader {
    pub fn new(
        scope: CatalogScope,
        section: CatalogSection,
        root: CatalogPageRef,
        range: Range<u64>,
    ) -> Result<Self, CatalogError> {
        scope.validate(section)?;
        root.validate()?;
        if range.start > range.end || range.end > root.byte_len {
            return Err(CatalogError::Bounds);
        }
        let remaining = range.end - range.start;
        Ok(Self {
            scope,
            section,
            range,
            pending: if remaining == 0 {
                Vec::new()
            } else {
                vec![(root, 0)]
            },
            remaining,
            failed: false,
        })
    }

    /// Fetch the next intersecting leaf and return only the requested bytes.
    /// After any storage or verification failure this reader stays poisoned;
    /// retries must start a new reader from the authenticated root.
    pub fn next_chunk<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<Vec<u8>>, CatalogStreamError<E>> {
        if self.failed {
            return Err(CatalogError::Failed.into());
        }
        let result = self.next_inner(fetch);
        self.failed = result.is_err();
        result
    }

    fn next_inner<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<Vec<u8>>, CatalogStreamError<E>> {
        while let Some((reference, offset)) = self.pending.pop() {
            let encoded = fetch(reference).map_err(CatalogStreamError::Storage)?;
            let page = verify_page(reference, self.scope, self.section, &encoded)?;
            match page.body {
                PageBody::Index(children) => {
                    // Descending heights bound both stack size and traversal.
                    // Reverse insertion preserves stream order, including
                    // distinct occurrences of the same content-addressed page.
                    let mut end = offset
                        .checked_add(reference.byte_len)
                        .ok_or(CatalogError::Bounds)?;
                    for child in children.into_iter().rev() {
                        let start = end
                            .checked_sub(child.byte_len)
                            .ok_or(CatalogError::Bounds)?;
                        if start < self.range.end && end > self.range.start {
                            self.pending.push((child, start));
                        }
                        end = start;
                    }
                    if end != offset {
                        return Err(CatalogError::InvalidPage.into());
                    }
                }
                PageBody::Leaf(mut bytes) => {
                    let start = self.range.start.saturating_sub(offset) as usize;
                    let end = (self.range.end - offset).min(reference.byte_len) as usize;
                    if start >= end || end > bytes.len() {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    let count = end - start;
                    self.remaining = self
                        .remaining
                        .checked_sub(count as u64)
                        .ok_or(CatalogError::Bounds)?;
                    if self.pending.is_empty() && self.remaining != 0 {
                        return Err(CatalogError::InvalidPage.into());
                    }
                    bytes.copy_within(start..end, 0);
                    bytes.truncate(count);
                    return Ok(Some(bytes));
                }
            }
        }
        if self.remaining != 0 {
            return Err(CatalogError::InvalidPage.into());
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn tree(length: u64, height: u8, pages: &mut HashMap<[u8; 32], Vec<u8>>) -> CatalogPageRef {
        let body = if height == 0 {
            PageBody::Leaf((0..length).map(|i| (i % 251) as u8).collect())
        } else {
            let capacity =
                CATALOG_LEAF_BYTES as u64 * (CATALOG_FANOUT as u64).pow(height as u32 - 1);
            let full = tree(capacity, height - 1, pages);
            let mut children = vec![full; (length / capacity) as usize];
            if !length.is_multiple_of(capacity) {
                children.push(tree(length % capacity, height - 1, pages));
            }
            PageBody::Index(children)
        };
        let (reference, bytes) = Page {
            format_version: 1,
            scope: scope(),
            section: CatalogSection::GitGraph,
            height,
            body,
        }
        .encode()
        .unwrap();
        pages.insert(reference.hash, bytes);
        reference
    }

    #[test]
    fn catalog_ranges_skip_unrelated_pages_at_maximum_stream_size() {
        let mut pages = HashMap::new();
        let root = tree(CATALOG_MAX_STREAM_BYTES, CATALOG_MAX_HEIGHT, &mut pages);
        // Repeated subtrees represent the full 16 GiB stream without allocating it.
        assert!(pages.len() <= 2 * (CATALOG_MAX_HEIGHT as usize + 1));
        let leaf = CATALOG_LEAF_BYTES as u64;
        for range in [
            0..1,
            leaf - 1..leaf + 1,
            leaf * 128 - 1..leaf * 128 + 1,
            leaf * 128 * 128 - 1..leaf * 128 * 128 + 1,
            root.byte_len - 1..root.byte_len,
            root.byte_len - 100..root.byte_len,
            0..0,
            root.byte_len..root.byte_len,
        ] {
            let expected: Vec<_> = range.clone().map(|i| ((i % leaf) % 251) as u8).collect();
            let mut reader =
                CatalogRangeReader::new(scope(), CatalogSection::GitGraph, root, range.clone())
                    .unwrap();
            let reads = std::cell::Cell::new(0);
            let mut fetch = |reference: CatalogPageRef| {
                reads.set(reads.get() + 1);
                Ok::<_, &'static str>(pages[&reference.hash].clone())
            };
            let mut actual = Vec::new();
            while let Some(chunk) = reader.next_chunk(&mut fetch).unwrap() {
                actual.extend(chunk);
                assert!(reader.pending.len() <= CATALOG_FANOUT * CATALOG_MAX_HEIGHT as usize + 1);
            }
            assert_eq!(actual, expected);
            assert!(reads.get() <= 2 * (CATALOG_MAX_HEIGHT as usize + 1));
            if range.is_empty() {
                assert_eq!(reads.get(), 0);
            }
            let before = reads.get();
            assert!(reader.next_chunk(&mut fetch).unwrap().is_none());
            assert_eq!(reads.get(), before);
        }
    }

    #[test]
    fn catalog_ranges_match_full_stream_across_partial_leaf_boundaries() {
        let bytes: Vec<_> = (0..CATALOG_LEAF_BYTES * 2 + 7)
            .map(|i| (i % 239) as u8)
            .collect();
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        let mut pages = HashMap::new();
        let mut sink = |reference: CatalogPageRef, encoded| {
            pages.insert(reference.hash, encoded);
            Ok::<_, &'static str>(())
        };
        builder.push(&bytes, &mut sink).unwrap();
        let root = builder.finish(&mut sink).unwrap();
        let edges = [
            0,
            1,
            CATALOG_LEAF_BYTES - 1,
            CATALOG_LEAF_BYTES,
            CATALOG_LEAF_BYTES + 1,
            CATALOG_LEAF_BYTES * 2,
            bytes.len() - 1,
            bytes.len(),
        ];
        for start in edges {
            for end in edges {
                let reader = CatalogRangeReader::new(
                    scope(),
                    CatalogSection::GitGraph,
                    root,
                    start as u64..end as u64,
                );
                if start > end {
                    assert!(reader.is_err());
                    continue;
                }
                let mut reader = reader.unwrap();
                let mut actual = Vec::new();
                while let Some(chunk) = reader
                    .next_chunk(&mut |reference: CatalogPageRef| {
                        Ok::<_, &'static str>(pages[&reference.hash].clone())
                    })
                    .unwrap()
                {
                    actual.extend(chunk);
                }
                assert_eq!(actual, bytes[start..end]);
            }
        }
        for range in [0..root.byte_len + 1, u64::MAX..u64::MAX, 0..u64::MAX] {
            assert!(
                CatalogRangeReader::new(scope(), CatalogSection::GitGraph, root, range).is_err()
            );
        }
    }

    #[test]
    fn catalog_ranges_poison_on_storage_scope_reference_and_page_failures() {
        let mut pages = HashMap::new();
        let root = tree(CATALOG_LEAF_BYTES as u64 * 3, 1, &mut pages);
        for failure in 0..5 {
            let mut expected = root;
            if failure == 3 {
                expected.byte_len -= 1;
            }
            let section = if failure == 4 {
                CatalogSection::FileMetadata
            } else {
                CatalogSection::GitGraph
            };
            let mut reader = CatalogRangeReader::new(scope(), section, expected, 1..2).unwrap();
            let mut reads = 0;
            let mut fetch = |reference: CatalogPageRef| {
                reads += 1;
                if failure == 0 {
                    return Err("offline");
                }
                let mut bytes = pages[&reference.hash].clone();
                if failure == 1 || (failure == 2 && reference.height == 0) {
                    let last = bytes.len() - 1;
                    bytes[last] ^= 1;
                }
                Ok(bytes)
            };
            assert!(reader.next_chunk(&mut fetch).is_err());
            assert!(matches!(
                reader.next_chunk(&mut fetch),
                Err(CatalogStreamError::Catalog(CatalogError::Failed))
            ));
            assert_eq!(reads, if failure == 2 { 2 } else { 1 });
        }
    }
}
