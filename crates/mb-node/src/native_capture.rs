//! Native-anchor production of private paged roots. No legacy revision or
//! dataset-sized sector vector is involved. Durable admission, source ordering,
//! publication and checkpoint activation belong to the enclosing operation.

use std::{
    collections::BTreeMap,
    io::{Read, Seek, SeekFrom},
    os::unix::ffi::OsStrExt,
};

use anyhow::{Context, Result, ensure};
use mb_core::{
    CATALOG_FANOUT, CATALOG_FILE_SECTOR_REFS, CATALOG_LEAF_BYTES, CATALOG_MAX_PAGE_OCCURRENCES,
    CATALOG_MAX_RECORDS, CATALOG_MAX_STREAM_BYTES, CatalogCapacityPolicy,
    CatalogCodingTraversalBudget as Work, CatalogFileBuilder, CatalogFileKind,
    CatalogFileRecipeBuilder, CatalogFileRecipeRecord, CatalogFileRecord, CatalogFileStat,
    CatalogNativeFileRoot, CatalogPageRef, CatalogScope, CatalogSectorRecord, KeyMaterial,
    SectorPurpose, V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, canonical_size_bounded,
    catalog_file_path_order, encrypted_sector, make_content_sector_id, merkle_commit,
};
use mb_store::{CapturedEntry, ControlStore, FileExtent, NativeFileId, StableAnchorManifest};

use crate::{NativeCatalogStream, PagedAnchorSectorSource, PagedPrivateMetadata};

/// Construction credits for the two dense native trees, including all recipe
/// occurrences. Data counts are occurrence upper bounds, not unique retained
/// charges: the enclosing source ledger must deduplicate authenticated IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeCatalogAdmission {
    pub native_work: Work,
    pub data_occurrences: u64,
    pub data_occurrence_bytes: u64,
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b).context("native catalog capacity overflow")
}
fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b).context("native catalog capacity overflow")
}

fn dense_pages(bytes: u64) -> Result<u64> {
    let mut width = bytes.div_ceil(CATALOG_LEAF_BYTES as u64).max(1);
    let mut total = width;
    while width > 1 {
        width = width.div_ceil(CATALOG_FANOUT as u64);
        total = add(total, width)?;
    }
    Ok(total)
}

fn parts(entry: &CapturedEntry) -> (&std::path::Path, CatalogFileStat) {
    match entry {
        CapturedEntry::Directory {
            path,
            mode,
            modified_secs,
            modified_nanos,
        }
        | CapturedEntry::File {
            path,
            mode,
            modified_secs,
            modified_nanos,
            ..
        }
        | CapturedEntry::FileV2 {
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

fn entries(manifest: &StableAnchorManifest) -> Result<Vec<&CapturedEntry>> {
    // The current native anchor format has this independently bounded domain.
    // Sector occurrences are never collected into this namespace-sized index.
    ensure!(
        manifest.entries.len() <= 8192,
        "native anchor namespace exceeds its supported bound"
    );
    ensure!(
        matches!(manifest.format_version, 2 | 3) && !manifest.anchor_id.is_nil(),
        "unsupported native anchor manifest"
    );
    canonical_size_bounded(manifest, V1_MAX_CATALOG_BYTES)?;
    let mut entries: Vec<_> = manifest.entries.iter().collect();
    entries.sort_by(|left, right| {
        catalog_file_path_order(
            parts(left).0.as_os_str().as_bytes(),
            parts(right).0.as_os_str().as_bytes(),
        )
    });
    Ok(entries)
}

fn extents(entry: &CapturedEntry) -> Vec<FileExtent> {
    match entry {
        CapturedEntry::File { logical_len, .. } => {
            if *logical_len == 0 {
                vec![]
            } else {
                vec![FileExtent {
                    offset: 0,
                    logical_len: *logical_len,
                }]
            }
        }
        CapturedEntry::FileV2 { data_extents, .. } => data_extents.clone(),
        CapturedEntry::Directory { .. } => vec![],
    }
}

fn file_len(entry: &CapturedEntry) -> u64 {
    match entry {
        CapturedEntry::File { logical_len, .. } | CapturedEntry::FileV2 { logical_len, .. } => {
            *logical_len
        }
        CapturedEntry::Directory { .. } => 0,
    }
}

fn namespace_record<'a>(
    entry: &'a CapturedEntry,
    ordinal: u64,
    links: &mut BTreeMap<NativeFileId, (u64, &'a CapturedEntry)>,
) -> Result<CatalogFileRecord> {
    let (path, stat) = parts(entry);
    let kind = match entry {
        CapturedEntry::Directory { .. } => CatalogFileKind::Directory,
        CapturedEntry::File { logical_len, .. } => CatalogFileKind::File {
            file_key: ordinal,
            logical_len: *logical_len,
            link_group: None,
        },
        CapturedEntry::FileV2 {
            native_id,
            logical_len,
            data_extents,
            ..
        } => {
            if let Some((group, primary)) = links.get(native_id) {
                ensure!(
                    parts(primary).1 == stat
                        && file_len(primary) == *logical_len
                        && extents(primary) == *data_extents,
                    "native hard-link attributes or extents conflict"
                );
                CatalogFileKind::HardLink {
                    logical_len: *logical_len,
                    link_group: *group,
                }
            } else {
                links.insert(*native_id, (ordinal, entry));
                CatalogFileKind::File {
                    file_key: ordinal,
                    logical_len: *logical_len,
                    link_group: Some(ordinal),
                }
            }
        }
    };
    let record = CatalogFileRecord {
        format_version: 1,
        path: path.as_os_str().as_bytes().to_vec(),
        stat,
        kind,
    };
    record.validate()?;
    Ok(record)
}

impl NativeCatalogAdmission {
    /// Complete read-free geometry admission before a payload open or sink
    /// callback. Extent and sector fragment widths reserve their maximum
    /// supported scalar encodings; holes/aliases produce no data occurrences.
    pub fn for_anchor(
        manifest: &StableAnchorManifest,
        scope: CatalogScope,
        policy: CatalogCapacityPolicy,
    ) -> Result<Self> {
        policy.plan()?;
        ensure!(
            matches!(scope, CatalogScope::Dataset { .. }),
            "native capture requires dataset scope"
        );
        let mut namespace = CatalogFileBuilder::new(
            scope,
            CatalogFileStat {
                mode: manifest.root_mode,
                modified_secs: manifest.root_modified_secs,
                modified_nanos: manifest.root_modified_nanos,
            },
        )?;
        let mut namespace_bytes = 8;
        let mut recipe_bytes = 8;
        let mut recipe_records = 0;
        let mut extent_count = 0;
        let mut data_occurrences = 0;
        let mut data_occurrence_bytes = 0;
        let mut links = BTreeMap::new();
        let mut discard = |_, _| Ok::<_, anyhow::Error>(());
        for (ordinal, entry) in entries(manifest)?.into_iter().enumerate() {
            let record = namespace_record(entry, ordinal as u64, &mut links)?;
            namespace_bytes = add(
                namespace_bytes,
                add(
                    4,
                    canonical_size_bounded(&record, mb_core::CATALOG_FILE_RECORD_BYTES)? as u64,
                )?,
            )?;
            namespace.push(&record, &mut discard)?;
            if !matches!(record.kind, CatalogFileKind::File { .. }) {
                continue;
            }
            recipe_bytes = add(recipe_bytes, 64)?;
            recipe_records = add(recipe_records, 1)?;
            let mut end = 0;
            for extent in extents(entry) {
                let next = add(extent.offset, extent.logical_len)?;
                ensure!(
                    extent.logical_len > 0 && extent.offset >= end && next <= file_len(entry),
                    "invalid native sparse extent"
                );
                end = next;
                extent_count = add(extent_count, 1)?;
                let sectors = extent.logical_len.div_ceil(V1_SECTOR_SIZE as u64);
                data_occurrences = add(data_occurrences, sectors)?;
                data_occurrence_bytes = add(data_occurrence_bytes, extent.logical_len)?;
                let fragments = sectors.div_ceil(CATALOG_FILE_SECTOR_REFS as u64);
                recipe_bytes = add(
                    recipe_bytes,
                    add(64, add(mul(sectors, 80)?, mul(fragments, 36)?)?)?,
                )?;
                recipe_records = add(recipe_records, add(1, fragments)?)?;
            }
        }
        namespace.finish(&mut discard)?;
        ensure!(
            extent_count <= 65536
                && data_occurrences <= CATALOG_MAX_RECORDS
                && recipe_records <= CATALOG_MAX_RECORDS,
            "native recipe exceeds supported geometry"
        );
        let bytes = add(namespace_bytes, recipe_bytes)?;
        let page_occurrences = add(dense_pages(namespace_bytes)?, dense_pages(recipe_bytes)?)?;
        // Match publication's conservative framing-record admission, rather
        // than substituting the smaller exact typed record count.
        let native_work = Work {
            bytes,
            page_occurrences,
            records: add(
                ((namespace_bytes - 8) / 5).min(CATALOG_MAX_RECORDS),
                ((recipe_bytes - 8) / 5).min(CATALOG_MAX_RECORDS),
            )?,
        };
        ensure!(
            bytes <= CATALOG_MAX_STREAM_BYTES && page_occurrences <= CATALOG_MAX_PAGE_OCCURRENCES,
            "native catalog exceeds aggregate geometry"
        );
        policy
            .private_work_per_revision
            .remaining_after(native_work)?;
        Ok(Self {
            native_work,
            data_occurrences,
            data_occurrence_bytes,
        })
    }
}

impl PagedPrivateMetadata {
    /// Encode an immutable native capture directly into private paged trees.
    /// The caller owns/reserves both streams and deduplicates the authenticated
    /// data callbacks into the signed source tree and retained-source ledger.
    /// This encoder does not publish a revision, change a head or claim backup.
    pub fn write_native_anchor_catalog(
        control: &ControlStore,
        keys: &KeyMaterial,
        scope: CatalogScope,
        policy: CatalogCapacityPolicy,
        manifest: &StableAnchorManifest,
        sink: &mut impl FnMut(NativeCatalogStream, CatalogPageRef, Vec<u8>) -> Result<()>,
        source_sink: &mut impl FnMut(CatalogSectorRecord, PagedAnchorSectorSource) -> Result<()>,
    ) -> Result<CatalogNativeFileRoot> {
        let admission = NativeCatalogAdmission::for_anchor(manifest, scope, policy)?;
        let enrolled = control.catalog_capacity_policy()?;
        ensure!(
            enrolled.is_none_or(|existing| existing == policy),
            "native construction differs from the enrolled capacity contract"
        );
        let CatalogScope::Dataset {
            guild_id,
            owner,
            protected_root_id,
        } = scope
        else {
            unreachable!()
        };
        ensure!(
            owner == keys.node_id(),
            "native capture owner differs from local keys"
        );
        let encryption = keys.guild_data_key(&guild_id);
        let content = keys.guild_content_id_key(&guild_id);
        let mut namespace = CatalogFileBuilder::new(
            scope,
            CatalogFileStat {
                mode: manifest.root_mode,
                modified_secs: manifest.root_modified_secs,
                modified_nanos: manifest.root_modified_nanos,
            },
        )?;
        let mut recipes = CatalogFileRecipeBuilder::new(scope)?;
        let mut links = BTreeMap::new();
        let mut emitted_pages = 0;
        let mut emit = |stream, page, bytes| {
            emitted_pages = add(emitted_pages, 1)?;
            ensure!(
                emitted_pages <= admission.native_work.page_occurrences,
                "native page reservation exhausted"
            );
            sink(stream, page, bytes)
        };
        for (ordinal, entry) in entries(manifest)?.into_iter().enumerate() {
            let ordinal = ordinal as u64;
            let record = namespace_record(entry, ordinal, &mut links)?;
            namespace.push(&record, &mut |page, bytes| {
                emit(NativeCatalogStream::Namespace, page, bytes)
            })?;
            if !matches!(record.kind, CatalogFileKind::File { .. }) {
                continue;
            }
            let extents = extents(entry);
            let sectors: u64 = extents
                .iter()
                .map(|e| e.logical_len.div_ceil(V1_SECTOR_SIZE as u64))
                .sum();
            let mut recipe_sink = |page, bytes| emit(NativeCatalogStream::Recipes, page, bytes);
            recipes.push_record(
                &CatalogFileRecipeRecord::File {
                    format_version: 1,
                    file_key: ordinal,
                    logical_len: file_len(entry),
                    extents: extents.len() as u64,
                    sectors,
                },
                &mut recipe_sink,
            )?;
            if extents.is_empty() {
                continue;
            }
            let locator = manifest.file_locator_path(parts(entry).0)?;
            let hint = crate::snapshot::anchor_area_hint(control, locator.area.area_id)?;
            let (mut file, _) = crate::snapshot::open_stable_anchor_with_discovery(
                control,
                &locator,
                hint.as_deref(),
            )?;
            ensure!(
                file.metadata()?.len() == file_len(entry),
                "native anchor file length differs from its manifest"
            );
            for extent in extents {
                let sectors = extent.logical_len.div_ceil(V1_SECTOR_SIZE as u64);
                recipes.push_record(
                    &CatalogFileRecipeRecord::Extent {
                        offset: extent.offset,
                        logical_len: extent.logical_len,
                        sectors,
                    },
                    &mut recipe_sink,
                )?;
                file.seek(SeekFrom::Start(extent.offset))?;
                let mut offset = extent.offset;
                let mut remaining = extent.logical_len;
                let mut ordinal = 0;
                while remaining > 0 {
                    let first_sector = ordinal;
                    let mut references = Vec::with_capacity(CATALOG_FILE_SECTOR_REFS);
                    while remaining > 0 && references.len() < CATALOG_FILE_SECTOR_REFS {
                        let length = remaining.min(V1_SECTOR_SIZE as u64);
                        let mut plaintext = vec![0; length as usize];
                        file.read_exact(&mut plaintext)?;
                        let id = make_content_sector_id(
                            &content,
                            owner,
                            guild_id,
                            protected_root_id,
                            SectorPurpose::Data,
                            &plaintext,
                        )?;
                        let (reference, ciphertext) =
                            encrypted_sector(&encryption, id, &plaintext)?;
                        source_sink(
                            CatalogSectorRecord {
                                format_version: 1,
                                sector: reference.clone(),
                                commitment: merkle_commit(&ciphertext)?,
                            },
                            PagedAnchorSectorSource {
                                locator: locator.clone(),
                                offset,
                            },
                        )?;
                        references.push(reference);
                        offset += length;
                        remaining -= length;
                        ordinal += 1;
                    }
                    recipes.push_record(
                        &CatalogFileRecipeRecord::Sectors {
                            first_sector,
                            references,
                        },
                        &mut recipe_sink,
                    )?;
                }
            }
        }
        let root = CatalogNativeFileRoot {
            format_version: 1,
            namespace: namespace
                .finish(&mut |page, bytes| emit(NativeCatalogStream::Namespace, page, bytes))?,
            recipes: recipes
                .finish(&mut |page, bytes| emit(NativeCatalogStream::Recipes, page, bytes))?,
        };
        root.validate()?;
        policy.private_work_per_revision.remaining_after(Work {
            bytes: root.page_roots().iter().map(|page| page.byte_len).sum(),
            page_occurrences: root
                .page_roots()
                .iter()
                .map(|page| page.page_occurrences)
                .sum(),
            records: root
                .page_roots()
                .iter()
                .map(|page| ((page.byte_len - 8) / 5).min(CATALOG_MAX_RECORDS))
                .sum(),
        })?;
        ensure!(
            control.catalog_capacity_policy()? == enrolled,
            "native capacity contract changed during construction"
        );
        Ok(root)
    }
}

#[cfg(test)]
mod tests;
