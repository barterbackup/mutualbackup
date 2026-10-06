//! Borrowed conversion of the native portion of bounded legacy private metadata.
//! Runtime formats remain unchanged until all capture/recovery consumers migrate.

use std::collections::BTreeMap;

use anyhow::{Result, bail, ensure};
use mb_core::{
    CATALOG_FILE_PATH_BYTES, CatalogError, CatalogFileBuilder, CatalogFileExtent, CatalogFileKind,
    CatalogFileRecipeBuilder, CatalogFileRecord, CatalogFileStat, CatalogNativeFileRoot,
    CatalogPageRef, CatalogScope, CatalogStreamError, V1_MAX_CATALOG_BYTES, canonical_size_bounded,
    catalog_file_path_order,
};
use thiserror::Error;

use crate::{PrivateEntry, PrivateMetadata};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeCatalogStream {
    Namespace,
    Recipes,
}

impl NativeCatalogStream {
    pub const fn index(self) -> usize {
        match self {
            Self::Namespace => 0,
            Self::Recipes => 1,
        }
    }
}

#[derive(Debug, Error)]
pub enum NativeCatalogWriteError<E> {
    #[error(transparent)]
    Legacy(#[from] anyhow::Error),
    #[error(transparent)]
    Catalog(#[from] CatalogStreamError<E>),
}

fn parts(entry: &PrivateEntry) -> (&str, CatalogFileStat) {
    match entry {
        PrivateEntry::Directory {
            path,
            mode,
            modified_secs,
            modified_nanos,
        }
        | PrivateEntry::File {
            path,
            mode,
            modified_secs,
            modified_nanos,
            ..
        }
        | PrivateEntry::FileV2 {
            path,
            mode,
            modified_secs,
            modified_nanos,
            ..
        }
        | PrivateEntry::HardLinkV3 {
            path,
            mode,
            modified_secs,
            modified_nanos,
            ..
        } => (
            path,
            CatalogFileStat {
                mode: *mode,
                modified_secs: *modified_secs,
                modified_nanos: *modified_nanos,
            },
        ),
    }
}

fn entry_record(entry: &PrivateEntry, ordinal: u64) -> CatalogFileRecord {
    let (path, stat) = parts(entry);
    CatalogFileRecord {
        format_version: 1,
        path: path.as_bytes().to_vec(),
        stat,
        kind: match entry {
            PrivateEntry::Directory { .. } => CatalogFileKind::Directory,
            PrivateEntry::File { logical_len, .. } => CatalogFileKind::File {
                file_key: ordinal,
                logical_len: *logical_len,
                link_group: None,
            },
            PrivateEntry::FileV2 {
                logical_len,
                link_group,
                ..
            } => CatalogFileKind::File {
                file_key: ordinal,
                logical_len: *logical_len,
                link_group: Some(*link_group),
            },
            PrivateEntry::HardLinkV3 {
                logical_len,
                link_group,
                ..
            } => CatalogFileKind::HardLink {
                logical_len: *logical_len,
                link_group: *link_group,
            },
        },
    }
}

fn validate_legacy_links(metadata: &PrivateMetadata) -> Result<()> {
    let mut primaries = BTreeMap::<u64, &PrivateEntry>::new();
    for entry in &metadata.entries {
        match entry {
            PrivateEntry::FileV2 {
                link_group,
                logical_len,
                data_extents,
                ..
            } => {
                if let Some(previous) = primaries.get(link_group) {
                    let PrivateEntry::FileV2 {
                        logical_len: previous_len,
                        data_extents: previous_extents,
                        ..
                    } = previous
                    else {
                        unreachable!();
                    };
                    ensure!(
                        parts(previous).1 == parts(entry).1
                            && previous_len == logical_len
                            && previous_extents == data_extents,
                        "legacy hard-link primaries have conflicting attributes or recipes"
                    );
                } else {
                    primaries.insert(*link_group, entry);
                }
            }
            PrivateEntry::HardLinkV3 {
                link_group,
                logical_len,
                ..
            } => {
                let Some(previous) = primaries.get(link_group) else {
                    bail!("legacy hard-link alias precedes or lacks its primary");
                };
                let PrivateEntry::FileV2 {
                    logical_len: previous_len,
                    ..
                } = previous
                else {
                    unreachable!();
                };
                ensure!(
                    parts(previous).1 == parts(entry).1 && previous_len == logical_len,
                    "legacy hard-link alias has conflicting attributes"
                );
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_legacy_version(metadata: &PrivateMetadata) -> Result<()> {
    ensure!(
        matches!(metadata.format_version, 1..=5),
        "unsupported legacy native metadata version"
    );
    ensure!(
        metadata.format_version != 1
            || metadata.entries.iter().all(|entry| matches!(
                entry,
                PrivateEntry::Directory { .. } | PrivateEntry::File { .. }
            )),
        "version-1 private metadata contains a later entry variant"
    );
    ensure!(
        metadata.format_version != 2
            || metadata
                .entries
                .iter()
                .all(|entry| !matches!(entry, PrivateEntry::HardLinkV3 { .. })),
        "version-2 private metadata contains a later hard-link variant"
    );
    Ok(())
}

fn write_entries<E>(
    metadata: &PrivateMetadata,
    entries: &[&PrivateEntry],
    scope: CatalogScope,
    sink: &mut impl FnMut(NativeCatalogStream, CatalogPageRef, Vec<u8>) -> Result<(), E>,
) -> Result<CatalogNativeFileRoot, CatalogStreamError<E>> {
    let stat = CatalogFileStat {
        mode: metadata.root_mode,
        modified_secs: metadata.root_modified_secs,
        modified_nanos: metadata.root_modified_nanos,
    };
    let mut namespace = CatalogFileBuilder::new(scope, stat)?;
    let mut recipes = CatalogFileRecipeBuilder::new(scope)?;
    for (ordinal, entry) in entries.iter().enumerate() {
        let ordinal = ordinal as u64;
        if parts(entry).0.len() > CATALOG_FILE_PATH_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        namespace.push(&entry_record(entry, ordinal), &mut |reference, bytes| {
            sink(NativeCatalogStream::Namespace, reference, bytes)
        })?;
        let mut recipe_sink =
            |reference, bytes| sink(NativeCatalogStream::Recipes, reference, bytes);
        match entry {
            PrivateEntry::File {
                logical_len,
                sectors,
                ..
            } => {
                if *logical_len == 0 && !sectors.is_empty() {
                    return Err(CatalogError::InvalidPage.into());
                }
                // A zero-length dense legacy file has no extent or sectors.
                let extent = (*logical_len != 0).then_some(CatalogFileExtent {
                    offset: 0,
                    logical_len: *logical_len,
                    sectors,
                });
                recipes.push_file(ordinal, *logical_len, extent.into_iter(), &mut recipe_sink)?;
            }
            PrivateEntry::FileV2 {
                logical_len,
                data_extents,
                ..
            } => {
                recipes.push_file(
                    ordinal,
                    *logical_len,
                    data_extents.iter().map(|extent| CatalogFileExtent {
                        offset: extent.offset,
                        logical_len: extent.logical_len,
                        sectors: &extent.sectors,
                    }),
                    &mut recipe_sink,
                )?;
            }
            _ => {}
        }
    }
    let root = CatalogNativeFileRoot {
        format_version: 1,
        namespace: namespace.finish(&mut |reference, bytes| {
            sink(NativeCatalogStream::Namespace, reference, bytes)
        })?,
        recipes: recipes
            .finish(&mut |reference, bytes| sink(NativeCatalogStream::Recipes, reference, bytes))?,
    };
    root.validate()?;
    Ok(root)
}

impl PrivateMetadata {
    /// Convert supported decoded legacy native entries without rewriting their
    /// original signed bytes. Formats 4/5 represent only the decoded native
    /// portion here: callers must also convert and retain their Git descriptor.
    /// Sources must be joined against the enclosing authenticated revision using
    /// the native validator before typed durable publication or activation.
    /// Oversized/unsupported originals remain on their existing recovery path.
    pub fn write_paged_native_entries<E>(
        &self,
        scope: CatalogScope,
        sink: &mut impl FnMut(NativeCatalogStream, CatalogPageRef, Vec<u8>) -> Result<(), E>,
    ) -> Result<CatalogNativeFileRoot, NativeCatalogWriteError<E>> {
        validate_legacy_version(self)?;
        canonical_size_bounded(self, V1_MAX_CATALOG_BYTES).map_err(|_| {
            anyhow::anyhow!("legacy native metadata exceeds its 32 MiB encoding bound")
        })?;
        // Preserve legacy restore semantics before sorting: aliases require a
        // preceding primary in their original stream. Sorting may then put an
        // alias first; the new durable group join resolves it explicitly.
        validate_legacy_links(self)?;
        let mut entries: Vec<_> = self.entries.iter().collect();
        entries.sort_by(|left, right| {
            catalog_file_path_order(parts(left).0.as_bytes(), parts(right).0.as_bytes())
        });
        let mut discard = |_, _, _| Ok::<_, std::convert::Infallible>(());
        write_entries(self, &entries, scope, &mut discard).map_err(|error| {
            anyhow::anyhow!("legacy native catalog cannot be converted: {error}")
        })?;
        write_entries(self, &entries, scope, sink).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mb_core::{
        CatalogFileEvent, CatalogFileRecipeRecord, CatalogNativeFileReader, CatalogSection,
        CatalogSectorBuilder, CatalogSectorRecord, KeyMaterial, NodeId, SectorRef, Seed,
        V1_SECTOR_SIZE, canonical_bytes, merkle_zero_commitment,
    };
    use mb_store::{CatalogIntent, CatalogNativeValidation, ControlStore};
    use uuid::Uuid;

    use super::*;
    use crate::PrivateDataExtent;

    fn scope() -> CatalogScope {
        CatalogScope::Dataset {
            guild_id: [1; 32],
            owner: NodeId([2; 32]),
            protected_root_id: Uuid::from_bytes([3; 16]),
        }
    }

    fn sector() -> SectorRef {
        SectorRef {
            id: [4; 32],
            root: [5; 32],
            logical_len: 3,
        }
    }

    fn dense(path: &str, len: u64, sectors: Vec<SectorRef>) -> PrivateEntry {
        PrivateEntry::File {
            path: path.to_owned(),
            mode: 0o640,
            logical_len: len,
            modified_secs: -7,
            modified_nanos: 12,
            sectors,
        }
    }

    fn primary(path: &str, references: Vec<SectorRef>) -> PrivateEntry {
        PrivateEntry::FileV2 {
            path: path.to_owned(),
            mode: 0o640,
            logical_len: 20,
            modified_secs: -7,
            modified_nanos: 12,
            link_group: 8,
            data_extents: vec![PrivateDataExtent {
                offset: 4,
                logical_len: references
                    .iter()
                    .map(|sector| u64::from(sector.logical_len))
                    .sum(),
                sectors: references,
            }],
        }
    }

    fn alias(path: &str) -> PrivateEntry {
        PrivateEntry::HardLinkV3 {
            path: path.to_owned(),
            mode: 0o640,
            logical_len: 20,
            modified_secs: -7,
            modified_nanos: 12,
            link_group: 8,
        }
    }

    fn metadata(entries: Vec<PrivateEntry>) -> PrivateMetadata {
        PrivateMetadata {
            format_version: 3,
            root_mode: 0o750,
            root_modified_secs: -9,
            root_modified_nanos: 17,
            entries,
        }
    }

    fn reject(value: &PrivateMetadata) {
        let before = canonical_bytes(value).unwrap();
        let mut writes = 0;
        assert!(
            value
                .write_paged_native_entries(scope(), &mut |_, _, _| {
                    writes += 1;
                    Ok::<_, &'static str>(())
                })
                .is_err()
        );
        assert_eq!(writes, 0);
        assert_eq!(canonical_bytes(value).unwrap(), before);
    }

    #[test]
    fn legacy_native_catalog_adapter_preserves_dense_sparse_alias_and_directory_records() {
        let value = metadata(vec![
            primary("z-primary", vec![sector(), sector()]),
            alias("a-alias"),
            primary("y-primary", vec![sector(), sector()]),
            PrivateEntry::Directory {
                path: "dir".to_owned(),
                mode: 0o710,
                modified_secs: -11,
                modified_nanos: 13,
            },
            dense("dir/dense", 6, vec![sector(), sector()]),
            dense("empty", 0, vec![]),
        ]);
        let before = canonical_bytes(&value).unwrap();
        let mut pages = HashMap::new();
        let root = value
            .write_paged_native_entries(scope(), &mut |stream, reference: CatalogPageRef, bytes| {
                assert!(stream.index() < 2);
                pages.insert(reference.hash, bytes);
                Ok::<_, &'static str>(())
            })
            .unwrap();
        assert_eq!(
            root.namespace.root_stat,
            CatalogFileStat {
                mode: 0o750,
                modified_secs: -9,
                modified_nanos: 17
            }
        );
        assert_eq!(
            (
                root.namespace.directories,
                root.namespace.files,
                root.namespace.hard_links
            ),
            (1, 4, 1)
        );
        let mut reader = CatalogNativeFileReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        let mut events = Vec::new();
        while let Some(event) = reader.next_event(&mut fetch).unwrap() {
            events.push(event);
        }
        let paths: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                CatalogFileEvent::Entry(entry) => Some(entry.path.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(
            paths,
            [
                b"a-alias".as_slice(),
                b"dir",
                b"dir/dense",
                b"empty",
                b"y-primary",
                b"z-primary"
            ]
        );
        let expected_entries = [
            entry_record(&value.entries[1], 0),
            entry_record(&value.entries[3], 1),
            entry_record(&value.entries[4], 2),
            entry_record(&value.entries[5], 3),
            entry_record(&value.entries[2], 4),
            entry_record(&value.entries[0], 5),
        ];
        assert_eq!(
            events
                .iter()
                .filter_map(|event| if let CatalogFileEvent::Entry(entry) = event {
                    Some(entry)
                } else {
                    None
                })
                .collect::<Vec<_>>(),
            expected_entries.iter().collect::<Vec<_>>()
        );
        let offsets: Vec<_> = events
            .iter()
            .filter_map(|event| match event {
                CatalogFileEvent::Recipe(CatalogFileRecipeRecord::Extent {
                    offset,
                    logical_len,
                    sectors,
                }) => Some((*offset, *logical_len, *sectors)),
                _ => None,
            })
            .collect();
        assert_eq!(offsets, [(0, 6, 2), (4, 6, 2), (4, 6, 2)]);
        assert_eq!(canonical_bytes(&value).unwrap(), before);
    }

    #[test]
    fn legacy_native_catalog_adapter_streams_large_borrowed_recipes_across_pages() {
        let references = vec![sector(); 4097];
        let value = metadata(vec![dense(
            "dense",
            references.len() as u64 * 3,
            references,
        )]);
        let before = canonical_bytes(&value).unwrap();
        let mut pages = HashMap::new();
        let root = value
            .write_paged_native_entries(scope(), &mut |_, reference: CatalogPageRef, bytes| {
                pages.insert(reference.hash, bytes);
                Ok::<_, &'static str>(())
            })
            .unwrap();
        assert!(root.recipes.records.page.height > 0);
        let mut reader = CatalogNativeFileReader::new(scope(), root).unwrap();
        let mut fetch =
            |reference: CatalogPageRef| Ok::<_, &'static str>(pages[&reference.hash].clone());
        let mut restored = Vec::new();
        while let Some(event) = reader.next_event(&mut fetch).unwrap() {
            if let CatalogFileEvent::Recipe(CatalogFileRecipeRecord::Sectors {
                references, ..
            }) = event
            {
                assert!(references.len() <= mb_core::CATALOG_FILE_SECTOR_REFS);
                restored.extend(references);
            }
        }
        let PrivateEntry::File { sectors, .. } = &value.entries[0] else {
            unreachable!();
        };
        assert_eq!(&restored, sectors);
        assert_eq!(canonical_bytes(&value).unwrap(), before);
    }

    #[test]
    fn legacy_native_catalog_adapter_rejects_invalid_shapes_before_any_writes() {
        for version in [0, 6, 7, u16::MAX] {
            let mut value = metadata(vec![]);
            value.format_version = version;
            reject(&value);
        }
        let mut value = metadata(vec![primary("a", vec![sector()])]);
        value.format_version = 1;
        reject(&value);
        let mut value = metadata(vec![primary("a", vec![sector()]), alias("b")]);
        value.format_version = 2;
        reject(&value);
        for entries in [
            vec![alias("a"), primary("b", vec![sector()])],
            vec![
                primary("a", vec![sector()]),
                primary("b", vec![sector(), sector()]),
            ],
            vec![dense("a", 0, vec![sector()])],
            vec![dense("a", 4, vec![sector()])],
            vec![dense("missing/a", 3, vec![sector()])],
            vec![dense("a", 3, vec![sector()]), dense("a", 3, vec![sector()])],
            vec![dense("../a", 0, vec![])],
            vec![dense(&"x".repeat(CATALOG_FILE_PATH_BYTES + 1), 0, vec![])],
        ] {
            reject(&metadata(entries));
        }
        let mut value = metadata(vec![]);
        value.root_modified_nanos = 1_000_000_000;
        reject(&value);
        let mut value = metadata(vec![primary("a", vec![sector()]), alias("b")]);
        let PrivateEntry::HardLinkV3 { modified_secs, .. } = &mut value.entries[1] else {
            unreachable!();
        };
        *modified_secs += 1;
        reject(&value);
    }

    #[test]
    fn legacy_native_catalog_adapter_bounds_counting_and_preserves_versions_and_failures() {
        let value = metadata(vec![dense(&"x".repeat(V1_MAX_CATALOG_BYTES), 0, vec![])]);
        let mut writes = 0;
        assert!(
            value
                .write_paged_native_entries(scope(), &mut |_, _, _| {
                    writes += 1;
                    Ok::<_, &'static str>(())
                })
                .is_err()
        );
        assert_eq!(writes, 0);
        let mut value = metadata(vec![dense("a", 3, vec![sector()])]);
        for version in 1..=5 {
            value.format_version = version;
            let before = canonical_bytes(&value).unwrap();
            value
                .write_paged_native_entries(scope(), &mut |_, _, _| Ok::<_, &'static str>(()))
                .unwrap();
            assert_eq!(canonical_bytes(&value).unwrap(), before);
        }
        let before = canonical_bytes(&value).unwrap();
        assert!(
            value
                .write_paged_native_entries(scope(), &mut |_, _, _| Err::<(), _>("offline"))
                .is_err()
        );
        assert_eq!(canonical_bytes(&value).unwrap(), before);
        assert!(
            value
                .write_paged_native_entries(
                    CatalogScope::Guild { guild_id: [1; 32] },
                    &mut |_, _, _| Ok::<_, &'static str>(())
                )
                .is_err()
        );
    }

    #[test]
    fn legacy_native_catalog_adapter_stages_validates_publishes_and_reopens_exact_recipes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([8; 32]));
        let store = ControlStore::open(&path, &keys).unwrap();
        let value = metadata(vec![
            primary("z-primary", vec![sector(), sector()]),
            alias("a-alias"),
        ]);
        let before = canonical_bytes(&value).unwrap();
        let intents = [
            CatalogSection::FileMetadata,
            CatalogSection::FileMetadata,
            CatalogSection::SectorReferences,
        ]
        .map(|section| CatalogIntent {
            id: Uuid::new_v4(),
            scope: scope(),
            section,
        });
        for intent in intents {
            store.begin_catalog(intent).unwrap();
        }
        let files = value
            .write_paged_native_entries(scope(), &mut |stream, reference, bytes: Vec<u8>| {
                store.stage_catalog_page(intents[stream.index()], reference, &bytes)
            })
            .unwrap();
        let mut builder = CatalogSectorBuilder::new(scope()).unwrap();
        let mut sink =
            |reference, bytes: Vec<u8>| store.stage_catalog_page(intents[2], reference, &bytes);
        builder
            .push(
                &CatalogSectorRecord {
                    format_version: 1,
                    sector: sector(),
                    commitment: merkle_zero_commitment(V1_SECTOR_SIZE as u32).unwrap(),
                },
                &mut sink,
            )
            .unwrap();
        let manifest = CatalogNativeValidation {
            id: Uuid::new_v4(),
            scope: scope(),
            files,
            sources: builder.finish(&mut sink).unwrap(),
        };
        store.validate_native_file_catalog(manifest).unwrap();
        store
            .publish_native_file_catalog(manifest, intents)
            .unwrap();
        drop(store);
        let store = ControlStore::open(&path, &keys).unwrap();
        assert_eq!(
            store
                .native_file_catalog(manifest.id, manifest.scope)
                .unwrap()
                .unwrap()
                .0,
            manifest
        );
        assert_eq!(
            store
                .native_file_catalog_link(manifest.id, 8)
                .unwrap()
                .unwrap()
                .primary_file_key,
            Some(1)
        );
        let mut reader = CatalogNativeFileReader::new(scope(), manifest.files).unwrap();
        let mut fetch =
            |reference| store.catalog_page(scope(), CatalogSection::FileMetadata, reference);
        let mut sectors = Vec::new();
        while let Some(event) = reader.next_event(&mut fetch).unwrap() {
            if let CatalogFileEvent::Recipe(CatalogFileRecipeRecord::Sectors {
                references, ..
            }) = event
            {
                sectors.extend(references);
            }
        }
        assert_eq!(sectors, [sector(), sector()]);
        assert_eq!(canonical_bytes(&value).unwrap(), before);
    }
}
