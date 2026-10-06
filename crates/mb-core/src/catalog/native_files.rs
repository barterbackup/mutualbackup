//! A bounded native namespace/recipe container and streaming key/length join.
//! Hard-link identity and signed source authority are separate activation gates.

use serde::{Deserialize, Serialize};

use super::{
    CATALOG_MAX_PAGE_OCCURRENCES, CATALOG_MAX_STREAM_BYTES, CatalogError, CatalogFileKind,
    CatalogFileReader, CatalogFileRecipeReader, CatalogFileRecipeRecord, CatalogFileRecipeRoot,
    CatalogFileRecord, CatalogFileRoot, CatalogPageRef, CatalogScope, CatalogStreamError,
};
use crate::decode_canonical;

pub const CATALOG_NATIVE_FILE_ROOT_BYTES: usize = 1024;

/// Authenticate this complete container in owner-encrypted revision metadata.
/// Both private roots must be retained together by durable publication. Source
/// records remain separately authenticated by the enclosing signed revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogNativeFileRoot {
    pub format_version: u16,
    pub namespace: CatalogFileRoot,
    pub recipes: CatalogFileRecipeRoot,
}

impl CatalogNativeFileRoot {
    pub fn validate(self) -> Result<(), CatalogError> {
        self.namespace.validate()?;
        self.recipes.validate()?;
        let pages = self.page_roots();
        if self.format_version != 1
            || self.namespace.files != self.recipes.files
            || self.namespace.file_bytes != self.recipes.logical_bytes
        {
            return Err(CatalogError::InvalidPage);
        }
        // Each validated reference is individually bounded, so these two sums
        // cannot overflow. Both streams share one structural metadata budget.
        if pages.iter().map(|page| page.byte_len).sum::<u64>() > CATALOG_MAX_STREAM_BYTES
            || pages.iter().map(|page| page.page_occurrences).sum::<u64>()
                > CATALOG_MAX_PAGE_OCCURRENCES
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, CatalogError> {
        if bytes.is_empty() || bytes.len() > CATALOG_NATIVE_FILE_ROOT_BYTES {
            return Err(CatalogError::Bounds);
        }
        let root: Self = decode_canonical(bytes)?;
        root.validate()?;
        let mut buffer = [0; CATALOG_NATIVE_FILE_ROOT_BYTES];
        if postcard::to_slice(&root, &mut buffer).map_err(crate::ModelError::Encode)? != bytes {
            return Err(CatalogError::InvalidPage);
        }
        Ok(root)
    }

    /// Namespace then recipes. Stream role order must also match the manifest
    /// used for local durable publication; an opaque root leaf cannot retain
    /// its two referenced trees through page-store index edges by itself.
    pub fn page_roots(self) -> [CatalogPageRef; 2] {
        [self.namespace.records.page, self.recipes.records.page]
    }
}

/// Entry events preserve directory/file/alias order. Each file entry is followed
/// by its matched recipe header and extent/sector fragments before the next
/// entry. Directory and hard-link aliases have no standalone payload recipe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CatalogFileEvent {
    Entry(CatalogFileRecord),
    Recipe(CatalogFileRecipeRecord),
}

/// Joins two sorted streams using one pending recipe header and the two bounded
/// typed readers. File recipes must match exact namespace keys and lengths.
/// Missing, extra and substituted recipes fail even when their own totals match.
/// Reach authenticated EOF, then validate hard-link and signed source joins
/// before activating restore, protection or physical accounting.
pub struct CatalogNativeFileReader {
    namespace: CatalogFileReader,
    recipes: CatalogFileRecipeReader,
    expected_entries: u64,
    consumed_entries: u64,
    pending_header: Option<CatalogFileRecipeRecord>,
    in_recipe: bool,
    finished: bool,
    failed: bool,
}

impl CatalogNativeFileReader {
    pub fn new(scope: CatalogScope, root: CatalogNativeFileRoot) -> Result<Self, CatalogError> {
        root.validate()?;
        Ok(Self {
            namespace: CatalogFileReader::new(scope, root.namespace)?,
            recipes: CatalogFileRecipeReader::new(scope, root.recipes)?,
            expected_entries: root.namespace.records.records,
            consumed_entries: 0,
            pending_header: None,
            in_recipe: false,
            finished: false,
            failed: false,
        })
    }

    pub fn next_event<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<Option<CatalogFileEvent>, CatalogStreamError<E>> {
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
    ) -> Result<Option<CatalogFileEvent>, CatalogStreamError<E>> {
        if self.finished {
            return Ok(None);
        }
        let event = if let Some(header) = self.pending_header.take() {
            CatalogFileEvent::Recipe(header)
        } else if self.in_recipe {
            let record = self
                .recipes
                .next_record(fetch)?
                .ok_or(CatalogError::InvalidPage)?;
            if matches!(record, CatalogFileRecipeRecord::File { .. }) {
                return Err(CatalogError::InvalidPage.into());
            }
            self.in_recipe = !self.recipes.file_complete();
            CatalogFileEvent::Recipe(record)
        } else {
            let Some(entry) = self.namespace.next_file(fetch)? else {
                self.verify_eof(fetch)?;
                return Ok(None);
            };
            self.consumed_entries += 1;
            if let CatalogFileKind::File {
                file_key,
                logical_len,
                ..
            } = entry.kind
            {
                let header = self
                    .recipes
                    .next_record(fetch)?
                    .ok_or(CatalogError::InvalidPage)?;
                match header {
                    CatalogFileRecipeRecord::File {
                        file_key: recipe_key,
                        logical_len: recipe_len,
                        ..
                    } if file_key == recipe_key && logical_len == recipe_len => {}
                    _ => return Err(CatalogError::InvalidPage.into()),
                }
                self.in_recipe = !self.recipes.file_complete();
                self.pending_header = Some(header);
            }
            CatalogFileEvent::Entry(entry)
        };
        // Check both authenticated EOFs before yielding the final combined
        // event, including catalogs ending in directories, aliases or empty
        // files. A final file entry is followed by its pending recipe header.
        if self.consumed_entries == self.expected_entries
            && self.pending_header.is_none()
            && !self.in_recipe
        {
            self.verify_eof(fetch)?;
        }
        Ok(Some(event))
    }

    fn verify_eof<E>(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, E>,
    ) -> Result<(), CatalogStreamError<E>> {
        if self.consumed_entries != self.expected_entries
            || self.namespace.next_file(fetch)?.is_some()
            || self.recipes.next_record(fetch)?.is_some()
        {
            return Err(CatalogError::InvalidPage.into());
        }
        self.finished = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::{
        CatalogFileBuilder, CatalogFileRecipeBuilder, CatalogFileStat, CatalogRecordBuilder,
        CatalogSection, NodeId, SectorRef, canonical_bytes,
    };
    use uuid::Uuid;

    type Pages = HashMap<[u8; 32], Vec<u8>>;
    const STAT: CatalogFileStat = CatalogFileStat {
        mode: 0o640,
        modified_secs: -2,
        modified_nanos: 7,
    };

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn entry(path: &[u8], kind: CatalogFileKind) -> CatalogFileRecord {
        CatalogFileRecord {
            format_version: 1,
            path: path.to_vec(),
            stat: STAT,
            kind,
        }
    }

    fn file(path: &[u8], key: u64, len: u64) -> CatalogFileRecord {
        entry(
            path,
            CatalogFileKind::File {
                file_key: key,
                logical_len: len,
                link_group: None,
            },
        )
    }

    fn header(key: u64, len: u64, extents: u64, sectors: u64) -> CatalogFileRecipeRecord {
        CatalogFileRecipeRecord::File {
            format_version: 1,
            file_key: key,
            logical_len: len,
            extents,
            sectors,
        }
    }

    fn build(
        entries: &[CatalogFileRecord],
        recipes: &[CatalogFileRecipeRecord],
    ) -> (CatalogNativeFileRoot, Pages) {
        let mut pages = Pages::new();
        let mut sink = |reference: CatalogPageRef, bytes| {
            pages.insert(reference.hash, bytes);
            Ok::<_, &'static str>(())
        };
        let mut namespace = CatalogFileBuilder::new(scope(), STAT).unwrap();
        for entry in entries {
            namespace.push(entry, &mut sink).unwrap();
        }
        let mut payload = CatalogFileRecipeBuilder::new(scope()).unwrap();
        for record in recipes {
            payload.push_record(record, &mut sink).unwrap();
        }
        (
            CatalogNativeFileRoot {
                format_version: 1,
                namespace: namespace.finish(&mut sink).unwrap(),
                recipes: payload.finish(&mut sink).unwrap(),
            },
            pages,
        )
    }

    fn events(root: CatalogNativeFileRoot, pages: &Pages) -> Vec<CatalogFileEvent> {
        let mut reader = CatalogNativeFileReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        let mut events = Vec::new();
        while let Some(event) = reader.next_event(&mut fetch).unwrap() {
            events.push(event);
        }
        assert!(reader.finished);
        assert!(reader.next_event(&mut fetch).unwrap().is_none());
        events
    }

    fn reject(root: CatalogNativeFileRoot, pages: &Pages) -> Vec<CatalogFileEvent> {
        let mut reader = match CatalogNativeFileReader::new(scope(), root) {
            Ok(reader) => reader,
            Err(_) => {
                assert!(root.validate().is_err());
                return Vec::new();
            }
        };
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        let mut events = Vec::new();
        loop {
            match reader.next_event(&mut fetch) {
                Ok(Some(event)) => events.push(event),
                Ok(None) => panic!("accepted invalid joined catalog"),
                Err(_) => break,
            }
        }
        assert!(reader.next_event(&mut fetch).is_err());
        assert!(!reader.finished);
        events
    }

    #[test]
    fn catalog_native_file_join_roundtrips_interleaved_entries_recipes_and_all_endings() {
        let entries = [
            entry(b"a", CatalogFileKind::Directory),
            entry(
                b"a/data",
                CatalogFileKind::File {
                    file_key: 1,
                    logical_len: 100,
                    link_group: Some(4),
                },
            ),
            entry(
                b"a/link",
                CatalogFileKind::HardLink {
                    logical_len: 100,
                    link_group: 4,
                },
            ),
            file(b"b", 3, 0),
            file(b"c", 4, 1000),
        ];
        let recipes = [
            header(1, 100, 1, 1),
            CatalogFileRecipeRecord::Extent {
                offset: 90,
                logical_len: 10,
                sectors: 1,
            },
            CatalogFileRecipeRecord::Sectors {
                first_sector: 0,
                references: vec![SectorRef {
                    id: [4; 32],
                    root: [5; 32],
                    logical_len: 10,
                }],
            },
            header(3, 0, 0, 0),
            header(4, 1000, 0, 0),
        ];
        let (root, pages) = build(&entries, &recipes);
        assert_eq!(
            CatalogNativeFileRoot::decode(&canonical_bytes(&root).unwrap()).unwrap(),
            root
        );
        assert_eq!(
            root.page_roots(),
            [root.namespace.records.page, root.recipes.records.page]
        );
        assert_eq!(
            events(root, &pages),
            vec![
                CatalogFileEvent::Entry(entries[0].clone()),
                CatalogFileEvent::Entry(entries[1].clone()),
                CatalogFileEvent::Recipe(recipes[0].clone()),
                CatalogFileEvent::Recipe(recipes[1].clone()),
                CatalogFileEvent::Recipe(recipes[2].clone()),
                CatalogFileEvent::Entry(entries[2].clone()),
                CatalogFileEvent::Entry(entries[3].clone()),
                CatalogFileEvent::Recipe(recipes[3].clone()),
                CatalogFileEvent::Entry(entries[4].clone()),
                CatalogFileEvent::Recipe(recipes[4].clone()),
            ]
        );
        // A final directory, alias, dense/sparse file or empty file all verify
        // both EOFs before the final event is exposed.
        for (entries, recipes) in [
            (&entries[..1], &recipes[..0]),
            (&entries[..2], &recipes[..3]),
            (&entries[..3], &recipes[..3]),
            (&entries[..4], &recipes[..4]),
            (&entries[..0], &recipes[..0]),
        ] {
            let (root, pages) = build(entries, recipes);
            events(root, &pages);
        }
    }

    #[test]
    fn catalog_native_file_join_crosses_both_streams_page_boundaries_with_one_pending_header() {
        let mut entries = vec![entry(b"files", CatalogFileKind::Directory)];
        let mut recipes = Vec::new();
        for index in 0..6000 {
            entries.push(file(
                format!("files/{index:04}").as_bytes(),
                index + 1,
                index,
            ));
            recipes.push(header(index + 1, index, 0, 0));
        }
        let (root, pages) = build(&entries, &recipes);
        assert!(root.namespace.records.page.height > 0);
        assert!(root.recipes.records.page.height > 0);
        let mut reader = CatalogNativeFileReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        assert_eq!(
            reader.next_event(&mut fetch).unwrap().unwrap(),
            CatalogFileEvent::Entry(entries[0].clone())
        );
        for (entry, recipe) in entries[1..].iter().zip(&recipes) {
            assert_eq!(
                reader.next_event(&mut fetch).unwrap().unwrap(),
                CatalogFileEvent::Entry(entry.clone())
            );
            assert_eq!(reader.pending_header.as_ref(), Some(recipe));
            assert!(!reader.in_recipe);
            assert_eq!(
                reader.next_event(&mut fetch).unwrap().unwrap(),
                CatalogFileEvent::Recipe(recipe.clone())
            );
            assert!(reader.pending_header.is_none());
        }
        assert!(reader.finished);
        assert!(reader.next_event(&mut fetch).unwrap().is_none());
    }

    #[test]
    fn catalog_native_file_join_rejects_substituted_keys_and_lengths_despite_matching_totals() {
        let entries = [file(b"a", 0, 3), file(b"b", 1, 5)];
        for recipes in [
            [header(1, 3, 0, 0), header(2, 5, 0, 0)],
            [header(0, 5, 0, 0), header(1, 3, 0, 0)],
        ] {
            let (root, pages) = build(&entries, &recipes);
            root.validate().unwrap(); // Same file/byte totals are insufficient.
            assert!(reject(root, &pages).is_empty());
        }
        let (root, pages) = build(&entries, &[header(0, 3, 0, 0), header(2, 5, 0, 0)]);
        assert_eq!(
            reject(root, &pages),
            vec![
                CatalogFileEvent::Entry(entries[0].clone()),
                CatalogFileEvent::Recipe(header(0, 3, 0, 0))
            ]
        );
    }

    #[test]
    fn catalog_native_file_join_rejects_missing_extra_incomplete_and_corrupt_streams() {
        let (mut root, mut pages) = build(
            &[file(b"a", 0, 10), file(b"b", 1, 20)],
            &[header(0, 10, 0, 0), header(1, 20, 0, 0)],
        );
        let original = root;
        // Raw frames create streams with authenticated page bytes but dishonest
        // enclosing summaries, exercising EOF and typed validation together.
        for records in [
            vec![header(0, 10, 0, 0)],
            vec![header(0, 10, 0, 0), header(1, 20, 0, 0), header(2, 0, 0, 0)],
            vec![header(0, 10, 0, 0), header(1, 20, 1, 1)],
        ] {
            let mut sink = |reference: CatalogPageRef, bytes| {
                pages.insert(reference.hash, bytes);
                Ok::<_, &'static str>(())
            };
            let mut builder =
                CatalogRecordBuilder::new(scope(), CatalogSection::FileMetadata).unwrap();
            for record in records {
                builder.push(&record, &mut sink).unwrap();
            }
            root.recipes.records = builder.finish(&mut sink).unwrap();
            reject(root, &pages);
        }
        let mut damaged = pages.clone();
        damaged
            .get_mut(&original.recipes.records.page.hash)
            .unwrap()[0] ^= 1;
        assert!(reject(original, &damaged).is_empty());
        let mut damaged = pages;
        damaged
            .get_mut(&original.namespace.records.page.hash)
            .unwrap()[0] ^= 1;
        assert!(reject(original, &damaged).is_empty());
    }

    #[test]
    fn catalog_native_file_root_bounds_schema_canonical_encoding_and_shared_geometry() {
        let (root, _) = build(&[file(b"a", 0, 3)], &[header(0, 3, 0, 0)]);
        for changed in [
            CatalogNativeFileRoot {
                format_version: 2,
                ..root
            },
            CatalogNativeFileRoot {
                recipes: CatalogFileRecipeRoot {
                    files: 0,
                    logical_bytes: 0,
                    ..root.recipes
                },
                ..root
            },
            CatalogNativeFileRoot {
                recipes: CatalogFileRecipeRoot {
                    logical_bytes: 4,
                    ..root.recipes
                },
                ..root
            },
        ] {
            assert!(changed.validate().is_err());
        }
        let encoded = canonical_bytes(&root).unwrap();
        assert!(encoded.len() < CATALOG_NATIVE_FILE_ROOT_BYTES);
        assert!(CatalogNativeFileRoot::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(CatalogNativeFileRoot::decode(&trailing).is_err());
        let mut noncanonical = vec![0x81, 0];
        noncanonical.extend_from_slice(&encoded[1..]);
        assert!(CatalogNativeFileRoot::decode(&noncanonical).is_err());
        assert!(CatalogNativeFileRoot::decode(&[0; CATALOG_NATIVE_FILE_ROOT_BYTES + 1]).is_err());
        assert!(CatalogNativeFileRoot::decode(&[]).is_err());
        assert!(
            CatalogNativeFileReader::new(CatalogScope::Guild { guild_id: [1; 32] }, root).is_err()
        );
    }

    #[test]
    fn catalog_native_file_root_shares_one_aggregate_metadata_and_page_budget() {
        let (mut boundary, _) = build(&[file(b"a", 0, 3)], &[header(0, 3, 0, 0)]);
        // Synthetic declared references exercise the aggregate root bounds;
        // these are not materialized catalogs or capacity qualification.
        for records in [
            &mut boundary.namespace.records,
            &mut boundary.recipes.records,
        ] {
            records.records = 1_000_000;
            records.page.height = 3;
            records.page.byte_len = CATALOG_MAX_STREAM_BYTES / 2;
            records.page.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES / 2;
        }
        boundary.namespace.files = 1_000_000;
        boundary.recipes.files = 1_000_000;
        boundary.validate().unwrap();
        let mut changed = boundary;
        changed.namespace.records.page.byte_len += 1;
        assert!(matches!(changed.validate(), Err(CatalogError::Bounds)));
        let mut changed = boundary;
        changed.recipes.records.page.page_occurrences += 1;
        assert!(matches!(changed.validate(), Err(CatalogError::Bounds)));
    }

    #[test]
    fn catalog_native_file_join_fetch_failure_fences_a_matched_pending_header() {
        let (root, pages) = build(&[file(b"a", 0, 3)], &[header(0, 3, 0, 0)]);
        let mut reader = CatalogNativeFileReader::new(scope(), root).unwrap();
        let mut reads = Vec::new();
        assert!(
            reader
                .next_event(&mut |reference: CatalogPageRef| {
                    reads.push(reference);
                    if reference == root.recipes.records.page {
                        Err("offline")
                    } else {
                        Ok(pages[&reference.hash].clone())
                    }
                })
                .is_err()
        );
        assert_eq!(reads, root.page_roots());
        assert!(
            reader
                .next_event(&mut |reference: CatalogPageRef| Ok::<_, &'static str>(
                    pages[&reference.hash].clone()
                ))
                .is_err()
        );
        assert!(reader.pending_header.is_none());
        assert!(!reader.finished);
    }
}
