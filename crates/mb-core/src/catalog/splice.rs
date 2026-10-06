//! Path-copying byte edits. Untouched subtrees retain their original addresses.

use std::ops::Range;

use super::*;

impl CatalogPageRef {
    /// Replace an authenticated byte range with at most one leaf of bytes.
    /// Insertions and deletions change length without repaging the suffix.
    /// Only boundary paths are fetched; fully deleted subtrees are skipped.
    /// New pages reach the sink child first, and unchanged pages are not emitted.
    /// Memory and page work are bounded by fanout and height, independent of the
    /// range's length. Repeated page occurrences are edited by stream offset.
    ///
    /// The caller supplies signed/parent root authority and holds the original
    /// closure alive until the successor is durably pinned. Sink writes must
    /// belong to a pending intent: failure may leave staged pages but never
    /// returns a publishable root. No-op empty edits need no page fetch.
    ///
    /// Splices preserve existing subtree heights. A root split may increase
    /// height; exceeding any format-one geometry bound fails. This operation
    /// does not rebalance an arbitrarily fragmented tree or validate skipped
    /// pages, and is a byte edit rather than a typed-record integrity check.
    pub fn splice<E>(
        self,
        scope: CatalogScope,
        section: CatalogSection,
        range: Range<u64>,
        replacement: &[u8],
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<Self, CatalogStreamError<E>> {
        self.validate()?;
        scope.validate(section)?;
        if range.start > range.end
            || range.end > self.byte_len
            || replacement.len() > CATALOG_LEAF_BYTES
        {
            return Err(CatalogError::Bounds.into());
        }
        let length = self.byte_len - (range.end - range.start) + replacement.len() as u64;
        if length > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        if range.is_empty() && replacement.is_empty() {
            return Ok(self);
        }
        let edit = Edit {
            scope,
            section,
            range,
            replacement,
        };
        let mut roots = edit.visit(self, 0, true, fetch, sink)?;
        let root = match roots.len() {
            0 => edit.emit(0, PageBody::Leaf(Vec::new()), None, sink)?,
            1 => roots.pop().unwrap(),
            _ => edit.emit(self.height + 1, PageBody::Index(roots), None, sink)?,
        };
        if root.byte_len != length {
            return Err(CatalogError::InvalidPage.into());
        }
        Ok(root)
    }
}

struct Edit<'a> {
    scope: CatalogScope,
    section: CatalogSection,
    range: Range<u64>,
    replacement: &'a [u8],
}

impl Edit<'_> {
    fn emit<E>(
        &self,
        height: u8,
        body: PageBody,
        original: Option<CatalogPageRef>,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogPageRef, CatalogStreamError<E>> {
        if height > CATALOG_MAX_HEIGHT {
            return Err(CatalogError::Bounds.into());
        }
        let (reference, bytes) = Page {
            format_version: 1,
            scope: self.scope,
            section: self.section,
            height,
            body,
        }
        .encode()?;
        if Some(reference) != original {
            sink(reference, bytes).map_err(CatalogStreamError::Storage)?;
        }
        Ok(reference)
    }

    fn visit<E>(
        &self,
        reference: CatalogPageRef,
        offset: u64,
        inserts: bool,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
        sink: &mut impl FnMut(CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<Vec<CatalogPageRef>, CatalogStreamError<E>> {
        let end = offset
            .checked_add(reference.byte_len)
            .ok_or(CatalogError::Bounds)?;
        if !inserts {
            if offset >= self.range.start && end <= self.range.end {
                return Ok(Vec::new());
            }
            if end <= self.range.start || offset >= self.range.end {
                return Ok(vec![reference]);
            }
        }
        let encoded = fetch(reference).map_err(CatalogStreamError::Storage)?;
        let page = verify_page(reference, self.scope, self.section, &encoded)?;
        match page.body {
            PageBody::Leaf(bytes) => {
                let start = self
                    .range
                    .start
                    .saturating_sub(offset)
                    .min(reference.byte_len) as usize;
                let stop = self
                    .range
                    .end
                    .saturating_sub(offset)
                    .min(reference.byte_len) as usize;
                let inserted = if inserts { self.replacement } else { &[] };
                let mut changed = Vec::with_capacity(start + inserted.len() + bytes.len() - stop);
                changed.extend_from_slice(&bytes[..start]);
                changed.extend_from_slice(inserted);
                changed.extend_from_slice(&bytes[stop..]);
                let mut leaves = Vec::new();
                for chunk in changed.chunks(CATALOG_LEAF_BYTES) {
                    leaves.push(self.emit(
                        0,
                        PageBody::Leaf(chunk.to_vec()),
                        Some(reference),
                        sink,
                    )?);
                }
                Ok(leaves)
            }
            PageBody::Index(children) => {
                let child_count = children.len();
                let mut changed = Vec::with_capacity(CATALOG_FANOUT + 1);
                let mut position = offset;
                let mut inserted = false;
                for (index, child) in children.into_iter().enumerate() {
                    let child_end = position
                        .checked_add(child.byte_len)
                        .ok_or(CatalogError::Bounds)?;
                    // An insertion at a shared boundary belongs to the right
                    // child. EOF belongs to the last child, exactly once.
                    let child_inserts = inserts
                        && !inserted
                        && (self.range.start < child_end || index + 1 == child_count);
                    inserted |= child_inserts;
                    changed.extend(self.visit(child, position, child_inserts, fetch, sink)?);
                    position = child_end;
                }
                if position != end || (inserts && !inserted) {
                    return Err(CatalogError::InvalidPage.into());
                }
                let mut parents = Vec::new();
                for chunk in changed.chunks(CATALOG_FANOUT) {
                    parents.push(self.emit(
                        reference.height,
                        PageBody::Index(chunk.to_vec()),
                        Some(reference),
                        sink,
                    )?);
                }
                Ok(parents)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::HashMap};

    use super::*;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    type Pages = RefCell<HashMap<[u8; 32], Vec<u8>>>;

    fn build(bytes: &[u8]) -> (CatalogPageRef, Pages) {
        let pages = Pages::default();
        let mut sink = |reference: CatalogPageRef, encoded| {
            pages.borrow_mut().insert(reference.hash, encoded);
            Ok::<_, &'static str>(())
        };
        let mut builder = CatalogBuilder::new(scope(), CatalogSection::GitGraph).unwrap();
        builder.push(bytes, &mut sink).unwrap();
        (builder.finish(&mut sink).unwrap(), pages)
    }

    fn read(root: CatalogPageRef, pages: &Pages) -> Vec<u8> {
        let mut reader = CatalogReader::new(scope(), CatalogSection::GitGraph, root).unwrap();
        let mut result = Vec::new();
        while let Some(bytes) = reader
            .next_leaf(&mut |reference: CatalogPageRef| {
                Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
            })
            .unwrap()
        {
            result.extend(bytes);
        }
        result
    }

    #[test]
    fn catalog_splices_insert_delete_replace_and_preserve_original_across_boundaries() {
        let bytes: Vec<_> = (0..CATALOG_LEAF_BYTES * 3 + 7)
            .map(|i| (i % 251) as u8)
            .collect();
        let (root, pages) = build(&bytes);
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
                if start > end {
                    continue;
                }
                for replacement in [&b""[..], &b"new"[..], &vec![9; CATALOG_LEAF_BYTES][..]] {
                    let mut expected = bytes.clone();
                    expected.splice(start..end, replacement.iter().copied());
                    let next = root
                        .splice(
                            scope(),
                            CatalogSection::GitGraph,
                            start as u64..end as u64,
                            replacement,
                            &mut |reference: CatalogPageRef| {
                                Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
                            },
                            &mut |reference: CatalogPageRef, encoded| {
                                pages.borrow_mut().insert(reference.hash, encoded);
                                Ok::<_, &'static str>(())
                            },
                        )
                        .unwrap();
                    assert_eq!(read(next, &pages), expected);
                }
            }
        }
        assert_eq!(read(root, &pages), bytes);
        let (empty, pages) = build(&[]);
        let next = empty
            .splice(
                scope(),
                CatalogSection::GitGraph,
                0..0,
                b"initial",
                &mut |reference: CatalogPageRef| {
                    Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
                },
                &mut |reference: CatalogPageRef, encoded| {
                    pages.borrow_mut().insert(reference.hash, encoded);
                    Ok::<_, &'static str>(())
                },
            )
            .unwrap();
        assert_eq!(read(next, &pages), b"initial");
    }

    #[test]
    fn catalog_splices_split_full_parents_and_edit_repeated_occurrences_independently() {
        let bytes = vec![0; CATALOG_LEAF_BYTES * CATALOG_FANOUT];
        let (root, pages) = build(&bytes);
        assert_eq!(root.height, 1);
        let mut reads = 0;
        let mut writes = 0;
        let next = root
            .splice(
                scope(),
                CatalogSection::GitGraph,
                1..1,
                b"x",
                &mut |reference: CatalogPageRef| {
                    reads += 1;
                    Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
                },
                &mut |reference: CatalogPageRef, encoded| {
                    writes += 1;
                    pages.borrow_mut().insert(reference.hash, encoded);
                    Ok::<_, &'static str>(())
                },
            )
            .unwrap();
        assert_eq!(next.height, 2);
        assert_eq!(reads, 2);
        assert_eq!(writes, 5);
        let mut expected = bytes.clone();
        expected.insert(1, b'x');
        assert_eq!(read(next, &pages), expected);
        assert_eq!(read(root, &pages), bytes);
        for range in [0..0, 1..2] {
            let replacement = if range.is_empty() {
                &b""[..]
            } else {
                &b"\0"[..]
            };
            let mut writes = 0;
            let same = root
                .splice(
                    scope(),
                    CatalogSection::GitGraph,
                    range,
                    replacement,
                    &mut |reference: CatalogPageRef| {
                        Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
                    },
                    &mut |_: CatalogPageRef, _| {
                        writes += 1;
                        Ok::<_, &'static str>(())
                    },
                )
                .unwrap();
            assert_eq!(same, root);
            assert_eq!(writes, 0);
        }
    }

    #[test]
    fn catalog_splices_edit_maximum_stream_with_bounded_page_work() {
        fn tree(length: u64, height: u8, pages: &Pages) -> CatalogPageRef {
            let body = if height == 0 {
                PageBody::Leaf(vec![0; length as usize])
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
            let (reference, encoded) = Page {
                format_version: 1,
                scope: scope(),
                section: CatalogSection::GitGraph,
                height,
                body,
            }
            .encode()
            .unwrap();
            pages.borrow_mut().insert(reference.hash, encoded);
            reference
        }
        let pages = Pages::default();
        let root = tree(CATALOG_MAX_STREAM_BYTES, CATALOG_MAX_HEIGHT, &pages);
        assert!(pages.borrow().len() <= 2 * (CATALOG_MAX_HEIGHT as usize + 1));
        for (range, replacement) in [
            (root.byte_len - 1..root.byte_len, &b"x"[..]),
            (1..root.byte_len - 1, &b"xyz"[..]),
            (0..root.byte_len, &b""[..]),
        ] {
            let mut reads = 0;
            let mut writes = 0;
            let length = root.byte_len - (range.end - range.start) + replacement.len() as u64;
            let next = root
                .splice(
                    scope(),
                    CatalogSection::GitGraph,
                    range.clone(),
                    replacement,
                    &mut |reference: CatalogPageRef| {
                        reads += 1;
                        Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
                    },
                    &mut |reference: CatalogPageRef, encoded| {
                        writes += 1;
                        pages.borrow_mut().insert(reference.hash, encoded);
                        Ok::<_, &'static str>(())
                    },
                )
                .unwrap();
            assert_eq!(next.byte_len, length);
            assert!(reads <= 2 * (CATALOG_MAX_HEIGHT as usize + 1));
            assert!(writes <= 2 * (CATALOG_MAX_HEIGHT as usize + 1));
            if range.start == root.byte_len - 1 {
                for (reference, expected) in [(root, &b"\0"[..]), (next, &b"x"[..])] {
                    let mut reader = super::super::CatalogRangeReader::new(
                        scope(),
                        CatalogSection::GitGraph,
                        reference,
                        reference.byte_len - 1..reference.byte_len,
                    )
                    .unwrap();
                    assert_eq!(
                        reader
                            .next_chunk(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                                pages.borrow()[&reference.hash].clone()
                            ))
                            .unwrap()
                            .unwrap(),
                        expected
                    );
                }
            } else {
                assert_eq!(
                    read(next, &pages),
                    if replacement.is_empty() {
                        &b""[..]
                    } else {
                        &b"\0xyz\0"[..]
                    }
                );
            }
        }
        let result = root.splice(
            scope(),
            CatalogSection::GitGraph,
            0..0,
            b"x",
            &mut |_| -> Result<Vec<u8>, &'static str> { panic!("must reject before fetch") },
            &mut |_, _| -> Result<(), &'static str> { panic!("must reject before stage") },
        );
        assert!(matches!(
            result,
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
    }

    #[test]
    fn catalog_splices_reject_root_height_overflow_and_preserve_original() {
        let pages = Pages::default();
        let emit = |height, body| {
            let (reference, encoded) = Page {
                format_version: 1,
                scope: scope(),
                section: CatalogSection::GitGraph,
                height,
                body,
            }
            .encode()
            .unwrap();
            pages.borrow_mut().insert(reference.hash, encoded);
            reference
        };
        let small = emit(0, PageBody::Leaf(vec![0]));
        let full = emit(0, PageBody::Leaf(vec![0; CATALOG_LEAF_BYTES]));
        let mut children = vec![small; CATALOG_FANOUT];
        children[0] = full;
        let dense_one = emit(1, PageBody::Index(children));
        let dense_two = emit(2, PageBody::Index(vec![dense_one; CATALOG_FANOUT]));
        let sparse_one = emit(1, PageBody::Index(vec![small]));
        let sparse_two = emit(2, PageBody::Index(vec![sparse_one]));
        let mut children = vec![sparse_two; CATALOG_FANOUT];
        children[0] = dense_two;
        let root = emit(3, PageBody::Index(children));
        let original = read(root, &pages);
        let result = root.splice(
            scope(),
            CatalogSection::GitGraph,
            1..1,
            b"x",
            &mut |reference: CatalogPageRef| {
                Ok::<_, &'static str>(pages.borrow()[&reference.hash].clone())
            },
            &mut |reference: CatalogPageRef, encoded| {
                pages.borrow_mut().insert(reference.hash, encoded);
                Ok::<_, &'static str>(())
            },
        );
        assert!(matches!(
            result,
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
        assert_eq!(read(root, &pages), original);
    }

    #[test]
    fn catalog_splices_fail_without_returning_root_for_invalid_input_storage_or_corruption() {
        let bytes = vec![1; CATALOG_LEAF_BYTES * 3];
        let (root, pages) = build(&bytes);
        for failure in 0..7 {
            let range = if failure == 0 {
                root.byte_len..root.byte_len + 1
            } else if failure == 1 {
                u64::MAX..u64::MAX
            } else {
                1..root.byte_len - 1
            };
            let replacement = vec![
                2;
                if failure == 2 {
                    CATALOG_LEAF_BYTES + 1
                } else {
                    1
                }
            ];
            let mut reads = 0;
            let mut writes = 0;
            let result = root.splice(
                scope(),
                CatalogSection::GitGraph,
                range,
                &replacement,
                &mut |reference: CatalogPageRef| {
                    reads += 1;
                    if failure == 3 {
                        return Err("offline");
                    }
                    let mut bytes = pages.borrow()[&reference.hash].clone();
                    if failure == 4 || (failure == 5 && reference.height == 0) {
                        let last = bytes.len() - 1;
                        bytes[last] ^= 1;
                    }
                    Ok(bytes)
                },
                &mut |_: CatalogPageRef, _| {
                    writes += 1;
                    Err("sink failure")
                },
            );
            assert!(result.is_err());
            if failure <= 2 {
                assert_eq!(reads, 0);
            }
            if failure <= 5 {
                assert_eq!(writes, 0);
            }
        }
        assert_eq!(read(root, &pages), bytes);
    }
}
