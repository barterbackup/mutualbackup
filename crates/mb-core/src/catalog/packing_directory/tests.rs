use super::*;
use crate::{NodeId, PackedSectorDescriptor, PackingInput, pack_incremental};
use std::collections::{BTreeMap, HashMap};

#[test]
fn packing_directory_visits_admitted_parts_before_io_and_fences_failed_ownership() {
    use std::cell::RefCell;
    use std::collections::HashSet;
    let fixture = fixture();
    let visited = RefCell::new(HashSet::from([fixture.root.records.page.hash]));
    let mut reader = CatalogPackingDirectoryReader::new(scope(), fixture.root, budget()).unwrap();
    let mut fetch = |page: CatalogPageRef| {
        assert!(
            visited.borrow().contains(&page.hash),
            "unowned nested root read"
        );
        Ok::<_, &'static str>(fixture.pages[&page.hash].clone())
    };
    let mut visit = |record: CatalogPackingDirectoryRecord| {
        assert!(visited.borrow_mut().insert(record.records().page.hash));
        Ok(())
    };
    let mut ids = HashMap::new();
    while let Some(record) = reader
        .next_source_with_part(&mut fetch, &mut visit)
        .unwrap()
    {
        if let CatalogPackedSourceRecord::Source { id, .. } = record {
            ids.insert(id.key(), id);
        }
    }
    while reader
        .next_sector_with_part(&mut fetch, &mut |key| Ok(ids[&key]), &mut visit)
        .unwrap()
        .is_some()
    {}
    assert!(reader.is_complete());
    assert_eq!(
        visited.borrow().len(),
        1 + fixture.source_parts.len() + fixture.sector_parts.len()
    );
    let mut reader = CatalogPackingDirectoryReader::new(scope(), fixture.root, budget()).unwrap();
    let mut reads = 0;
    let mut fetch = |page: CatalogPageRef| {
        reads += 1;
        Ok(fixture.pages[&page.hash].clone())
    };
    assert!(matches!(
        reader.next_source_with_part(&mut fetch, &mut |_| Err("pin failed")),
        Err(CatalogStreamError::Storage("pin failed"))
    ));
    assert!(matches!(
        reader.next_source(&mut fetch),
        Err(CatalogStreamError::Catalog(CatalogError::Failed))
    ));
    assert_eq!(reads, 1);
    assert!(!reader.is_complete());
}

fn scope() -> CatalogScope {
    CatalogScope::Guild { guild_id: [7; 32] }
}
fn budget() -> CatalogCodingTraversalBudget {
    CatalogCodingTraversalBudget {
        bytes: 128 << 30,
        page_occurrences: 8_000_000,
        records: 1 << 32,
    }
}

struct Fixture {
    root: CatalogPackingDirectoryRoot,
    pages: HashMap<[u8; 32], Vec<u8>>,
    source_parts: Vec<CatalogPackedSourcePart>,
    sector_parts: Vec<CatalogPackedSectorPart>,
    sectors: Vec<PackedSectorDescriptor>,
}

fn directory(
    records: impl IntoIterator<Item = CatalogPackingDirectoryRecord>,
    profile: PackingProfile,
    pages: &mut HashMap<[u8; 32], Vec<u8>>,
) -> CatalogPackingDirectoryRoot {
    let mut builder = CatalogPackingDirectoryBuilder::new(scope(), 3, profile, budget()).unwrap();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    for record in records {
        builder.push(record, &mut sink).unwrap();
    }
    builder.finish(&mut sink).unwrap()
}

fn fixture() -> Fixture {
    let profile = PackingProfile {
        format_version: 1,
        sector_size: 64,
        slot_size: 16,
    };
    let inputs = (1..=4)
        .map(|index| {
            let bytes = vec![index; 64];
            PackingInput {
                owner: NodeId([2; 32]),
                protected_root: [3; 32],
                object_id: [index; 32],
                source_commitment: Some(crate::merkle_commit(&bytes).unwrap()),
                bytes,
            }
        })
        .collect();
    let packed = pack_incremental(profile, None, inputs).unwrap();
    let mut grouped = BTreeMap::<CatalogPackedSourceId, Vec<_>>::new();
    for proof in packed.catalog.source_authentication.as_ref().unwrap() {
        grouped
            .entry(CatalogPackedSourceId {
                owner: proof.id.owner,
                protected_root: proof.id.protected_root,
                object_id: proof.id.object_id,
            })
            .or_default()
            .push(proof);
    }
    let mut pages = HashMap::new();
    let mut source_parts = Vec::new();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    for (id, mut proofs) in grouped {
        proofs.sort_by_key(|proof| proof.id.chunk_index);
        let mut builder = CatalogPackedSourceBuilder::new_compact(scope(), profile).unwrap();
        builder
            .push(
                &CatalogPackedSourceRecord::Source {
                    format_version: 1,
                    id,
                    commitment: proofs[0].source_commitment.clone(),
                },
                &mut sink,
            )
            .unwrap();
        builder
            .push(
                &CatalogPackedSourceRecord::Subtrees {
                    first_chunk: 0,
                    roots: proofs
                        .iter()
                        .map(|proof| proof.proof.subtree_root)
                        .collect(),
                },
                &mut sink,
            )
            .unwrap();
        source_parts.push(builder.finish_part(&mut sink).unwrap());
    }
    let mut sector_parts = Vec::new();
    for sectors in packed.catalog.sectors.chunks(2) {
        let mut builder =
            CatalogPackedSectorBuilder::new_part(scope(), 3, profile, sectors[0].sector_index)
                .unwrap();
        for sector in sectors {
            builder.push_sector(sector, &mut sink).unwrap();
        }
        sector_parts.push(builder.finish_part(&mut sink).unwrap());
    }
    let records = source_parts
        .iter()
        .copied()
        .map(CatalogPackingDirectoryRecord::Sources)
        .chain(
            sector_parts
                .iter()
                .copied()
                .map(CatalogPackingDirectoryRecord::Sectors),
        );
    let root = directory(records, profile, &mut pages);
    Fixture {
        root,
        pages,
        source_parts,
        sector_parts,
        sectors: packed.catalog.sectors,
    }
}

fn read(
    fixture: &Fixture,
) -> Result<Vec<CatalogPackedSectorRecord>, CatalogStreamError<&'static str>> {
    let mut reader =
        CatalogPackingDirectoryReader::new(scope(), fixture.root, fixture.root.work().unwrap())
            .unwrap();
    let mut ids = HashMap::new();
    let mut fetch =
        |page: CatalogPageRef| fixture.pages.get(&page.hash).cloned().ok_or("missing page");
    while let Some(record) = reader.next_source(&mut fetch)? {
        if let CatalogPackedSourceRecord::Source { id, .. } = record {
            ids.insert(id.key(), id);
        }
    }
    assert!(!reader.is_complete());
    let mut result = Vec::new();
    while let Some(record) = reader.next_sector(&mut fetch, &mut |key| {
        ids.get(&key).copied().ok_or("unknown source")
    })? {
        result.push(record);
    }
    assert!(reader.is_complete());
    assert!(reader.next_source(&mut fetch)?.is_none());
    Ok(result)
}

#[test]
fn packing_directory_preserves_global_indices_original_ids_and_both_complete_eofs() {
    let fixture = fixture();
    assert_eq!(fixture.root.summary.sources, 4);
    assert_eq!(fixture.root.summary.source_parts, 4);
    assert!(fixture.root.summary.sector_parts > 1);
    let records = read(&fixture).unwrap();
    let headers: Vec<_> = records
        .iter()
        .filter_map(|record| match record {
            CatalogPackedSectorRecord::Header {
                id, sector_index, ..
            } => Some((*id, *sector_index)),
            _ => None,
        })
        .collect();
    assert_eq!(
        headers,
        fixture
            .sectors
            .iter()
            .map(|sector| (sector.id, sector.sector_index))
            .collect::<Vec<_>>()
    );
    let part = fixture.sector_parts[1];
    let mut old = CatalogPackedSectorReader::new(scope(), part.root).unwrap();
    assert!(
        old.next_record_with_sources(
            &mut |page: CatalogPageRef| Ok::<_, ()>(fixture.pages[&page.hash].clone()),
            &mut |_| unreachable!()
        )
        .is_err()
    );
    let encoded =
        canonical_bytes_bounded(&fixture.root, CATALOG_PACKING_DIRECTORY_ROOT_BYTES).unwrap();
    assert_eq!(
        CatalogPackingDirectoryRoot::decode(&encoded, fixture.root.work().unwrap()).unwrap(),
        fixture.root
    );
    for end in 0..encoded.len() {
        assert!(CatalogPackingDirectoryRoot::decode(&encoded[..end], budget()).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(CatalogPackingDirectoryRoot::decode(&trailing, budget()).is_err());
}

#[test]
fn packing_directory_rejects_gaps_overlaps_reordered_ranges_and_failed_builder_reuse() {
    let fixture = fixture();
    for invalid in [
        CatalogPackingDirectoryRecord::Sources(fixture.source_parts[0]),
        CatalogPackingDirectoryRecord::Sources(fixture.source_parts[1]),
    ] {
        let mut builder =
            CatalogPackingDirectoryBuilder::new(scope(), 3, fixture.root.profile, budget())
                .unwrap();
        builder
            .push(
                CatalogPackingDirectoryRecord::Sources(fixture.source_parts[1]),
                &mut |_, _| Ok::<_, ()>(()),
            )
            .unwrap();
        assert!(builder.push(invalid, &mut |_, _| Ok::<_, ()>(())).is_err());
        assert!(matches!(
            builder.finish(&mut |_, _| Ok::<_, ()>(())),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }
    for first in [1, 3] {
        let mut builder =
            CatalogPackingDirectoryBuilder::new(scope(), 3, fixture.root.profile, budget())
                .unwrap();
        let mut part = fixture.sector_parts[0];
        part.first_sector = first;
        assert!(
            builder
                .push(
                    CatalogPackingDirectoryRecord::Sectors(part),
                    &mut |_, _| Ok::<_, ()>(())
                )
                .is_err()
        );
    }
    let mut builder =
        CatalogPackingDirectoryBuilder::new(scope(), 3, fixture.root.profile, budget()).unwrap();
    builder
        .push(
            CatalogPackingDirectoryRecord::Sectors(fixture.sector_parts[0]),
            &mut |_, _| Ok::<_, ()>(()),
        )
        .unwrap();
    assert!(
        builder
            .push(
                CatalogPackingDirectoryRecord::Sources(fixture.source_parts[0]),
                &mut |_, _| Ok::<_, ()>(())
            )
            .is_err()
    );
    let mut reader = CatalogPackingDirectoryReader::new(scope(), fixture.root, budget()).unwrap();
    assert!(
        reader
            .next_sector(
                &mut |_| -> Result<Vec<u8>, ()> {
                    panic!("descriptors before source EOF fetched pages")
                },
                &mut |_| panic!("resolved before source EOF")
            )
            .is_err()
    );
    assert!(matches!(
        reader.next_source(&mut |_| Ok::<_, ()>(vec![])),
        Err(CatalogStreamError::Catalog(CatalogError::Failed))
    ));
}

#[test]
fn packing_directory_admits_cumulative_dimensions_before_io_and_checks_actual_source_bounds() {
    let mut fixture = fixture();
    let work = fixture.root.work().unwrap();
    for dimension in 0..3 {
        let mut limit = work;
        match dimension {
            0 => limit.bytes -= 1,
            1 => limit.page_occurrences -= 1,
            _ => limit.records -= 1,
        }
        assert!(CatalogPackingDirectoryReader::new(scope(), fixture.root, limit).is_err());
    }
    // A plausible but false source envelope cannot authorize its actual header.
    let mut part = fixture.source_parts[0];
    part.first.object_id = [0; 32];
    part.first.object_id[31] = 1;
    part.last = part.first;
    let records = [CatalogPackingDirectoryRecord::Sources(part)]
        .into_iter()
        .chain(
            fixture.source_parts[1..]
                .iter()
                .copied()
                .map(CatalogPackingDirectoryRecord::Sources),
        )
        .chain(
            fixture
                .sector_parts
                .iter()
                .copied()
                .map(CatalogPackingDirectoryRecord::Sectors),
        );
    fixture.root = directory(records, fixture.root.profile, &mut fixture.pages);
    let mut reader = CatalogPackingDirectoryReader::new(scope(), fixture.root, budget()).unwrap();
    let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(fixture.pages[&page.hash].clone());
    assert!(reader.next_source(&mut fetch).is_err());
    assert!(matches!(
        reader.next_source(&mut fetch),
        Err(CatalogStreamError::Catalog(CatalogError::Failed))
    ));
}

#[test]
fn packing_directory_rejects_corrupt_referenced_tails_and_storage_failures_permanently() {
    let fixture = fixture();
    for corrupted in [
        None,
        Some(fixture.source_parts[3].root.records.page),
        Some(fixture.sector_parts.last().unwrap().root.records.page),
    ] {
        let mut reader =
            CatalogPackingDirectoryReader::new(scope(), fixture.root, budget()).unwrap();
        let mut fetch = |page: CatalogPageRef| {
            if corrupted.is_none() {
                return Err("cancelled");
            }
            let mut bytes = fixture.pages[&page.hash].clone();
            if Some(page) == corrupted {
                bytes.pop();
            }
            Ok(bytes)
        };
        let mut ids = HashMap::new();
        let result = (|| {
            while let Some(record) = reader.next_source(&mut fetch)? {
                if let CatalogPackedSourceRecord::Source { id, .. } = record {
                    ids.insert(id.key(), id);
                }
            }
            while reader
                .next_sector(&mut fetch, &mut |key| {
                    ids.get(&key).copied().ok_or("missing source")
                })?
                .is_some()
            {}
            Ok::<_, CatalogStreamError<_>>(())
        })();
        assert!(result.is_err());
        assert!(!reader.is_complete());
        assert!(matches!(
            reader.next_source(&mut fetch),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
    }
}

#[test]
fn packing_parts_preserve_the_last_u32_global_sector_and_reject_unwrapped_or_empty_ranges() {
    let fixture = fixture();
    let profile = fixture.root.profile;
    let mut sector = fixture.sectors[0].clone();
    sector.sector_index = u32::MAX;
    sector.id = sector.calculate_id(profile).unwrap();
    let mut pages = HashMap::new();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    let mut builder = CatalogPackedSectorBuilder::new_part(scope(), 3, profile, u32::MAX).unwrap();
    builder.push_sector(&sector, &mut sink).unwrap();
    let part = builder.finish_part(&mut sink).unwrap();
    let mut reader = CatalogPackedSectorReader::for_part(scope(), part).unwrap();
    let ids: HashMap<_, _> = fixture
        .source_parts
        .iter()
        .map(|part| (part.first.key(), part.first))
        .collect();
    let mut headers = 0;
    while let Some(record) = reader
        .next_record_with_sources(
            &mut |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone()),
            &mut |key| Ok(ids[&key]),
        )
        .unwrap()
    {
        if let CatalogPackedSectorRecord::Header {
            id, sector_index, ..
        } = record
        {
            assert_eq!((id, sector_index), (sector.id, u32::MAX));
            headers += 1;
        }
    }
    assert_eq!(headers, 1);
    let mut bad = fixture.sector_parts[0];
    bad.first_sector = u32::MAX;
    assert!(bad.validate().is_err());
    let mut builder = CatalogPackedSectorBuilder::new_part(scope(), 3, profile, u32::MAX).unwrap();
    builder
        .push_sector(&sector, &mut |_, _| Ok::<_, ()>(()))
        .unwrap();
    assert!(
        builder
            .finish(&mut |_, _| -> Result<(), ()> {
                panic!("unwrapped nonzero range emitted pages")
            })
            .is_err()
    );
    assert!(
        CatalogPackedSectorBuilder::new_part(scope(), 3, profile, 0)
            .unwrap()
            .finish_part(&mut |_, _| -> Result<(), ()> { panic!("empty part emitted pages") })
            .is_err()
    );
    assert!(
        CatalogPackedSourceBuilder::new_compact(scope(), profile)
            .unwrap()
            .finish_part(&mut |_, _| -> Result<(), ()> { panic!("empty sources emitted pages") })
            .is_err()
    );
}

#[test]
fn packing_directory_admits_declared_retained_single_owner_geometry_across_original_stream_limits()
{
    let fixture = fixture();
    let profile = PackingProfile {
        format_version: 1,
        sector_size: 65536,
        slot_size: 16384,
    };
    let sources =
        (1_u64 << 40) / u64::from(profile.sector_size) + 32 * (CATALOG_MAX_PAGE_OCCURRENCES + 1);
    assert_eq!(sources, 48_777_248);
    let sectors = (sources * 4).div_ceil(3);
    assert_eq!(sectors, 65_036_331);
    let maximum = CATALOG_MAX_RECORDS / 2;
    assert!(sources * 2 > CATALOG_MAX_RECORDS && sectors * 2 > CATALOG_MAX_RECORDS);
    let mut records = Vec::new();
    for (index, count) in [maximum, sources - maximum].into_iter().enumerate() {
        let mut part = fixture.source_parts[0];
        part.first.object_id = [1 + 2 * index as u8; 32];
        part.last.object_id = [2 + 2 * index as u8; 32];
        part.root.profile = profile;
        part.root.sources = count;
        part.root.chunks = count * 4;
        part.root.ciphertext_bytes = count * 65536;
        part.root.records.records = count * 2;
        part.root.records.page.byte_len = 8 << 30;
        part.root.records.page.height = 3;
        part.root.records.page.page_occurrences = 500_000;
        part.validate().unwrap();
        records.push(CatalogPackingDirectoryRecord::Sources(part));
    }
    for (first, count, chunks) in [
        (0, maximum, maximum * 3),
        (maximum, sectors - maximum, sources * 4 - maximum * 3),
    ] {
        let mut part = fixture.sector_parts[0];
        part.first_sector = first as u32;
        part.root.profile = profile;
        part.root.sectors = count;
        part.root.slots = count * 4;
        part.root.source_chunks = chunks;
        part.root.source_bytes = chunks * 16384;
        part.root.records.records = count * 2;
        part.root.records.page.byte_len = 8 << 30;
        part.root.records.page.height = 3;
        part.root.records.page.page_occurrences = 500_000;
        part.validate().unwrap();
        records.push(CatalogPackingDirectoryRecord::Sectors(part));
    }
    // Only four bounded root records are materialized. This proves declared
    // sharding/admission geometry, not dense storage, joins or recovery capacity.
    let mut pages = HashMap::new();
    let root = directory(records, profile, &mut pages);
    assert_eq!(
        (root.summary.source_parts, root.summary.sector_parts),
        (2, 2)
    );
    assert_eq!(root.summary.sources, sources);
    assert_eq!(root.summary.sectors, sectors);
    assert!(root.work().unwrap().records > CATALOG_MAX_RECORDS * 2);
    assert!(root.work().unwrap().page_occurrences > CATALOG_MAX_PAGE_OCCURRENCES);
    root.validate(root.work().unwrap()).unwrap();
}

#[test]
fn packing_directory_preserves_interior_padding_only_parts_and_rejects_global_empty_tail() {
    let mut fixture = fixture();
    let profile = fixture.root.profile;
    let commitment = crate::merkle_zero_commitment(profile.sector_size).unwrap();
    let empty = PackedSectorDescriptor {
        id: [0; 32],
        sector_index: 0,
        flat_root: commitment.root,
        commitment,
        slots: vec![crate::PackedSlot::VirtualZero { source: None }; 4],
    };
    fixture.sectors.insert(2, empty.clone());
    for tail in [false, true] {
        if tail {
            fixture.sectors.push(empty.clone());
        }
        fixture.sector_parts.clear();
        for (index, sector) in fixture.sectors.iter_mut().enumerate() {
            sector.sector_index = index as u32;
            sector.id = sector.calculate_id(profile).unwrap();
            let mut builder =
                CatalogPackedSectorBuilder::new_part(scope(), 3, profile, sector.sector_index)
                    .unwrap();
            let mut sink = |page: CatalogPageRef, bytes| {
                fixture.pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            builder.push_sector(sector, &mut sink).unwrap();
            fixture
                .sector_parts
                .push(builder.finish_part(&mut sink).unwrap());
        }
        assert_eq!(fixture.sector_parts[2].root.source_chunks, 0);
        assert!(fixture.sector_parts[2].root.validate().is_err());
        fixture.sector_parts[2].validate().unwrap();
        fixture.root = directory(
            fixture
                .source_parts
                .iter()
                .copied()
                .map(CatalogPackingDirectoryRecord::Sources)
                .chain(
                    fixture
                        .sector_parts
                        .iter()
                        .copied()
                        .map(CatalogPackingDirectoryRecord::Sectors),
                ),
            profile,
            &mut fixture.pages,
        );
        let result = read(&fixture);
        if tail {
            assert!(result.is_err());
        } else {
            let actual = result
                .unwrap()
                .into_iter()
                .filter_map(|record| match record {
                    CatalogPackedSectorRecord::Header {
                        id, sector_index, ..
                    } => Some((id, sector_index)),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(
                actual,
                fixture
                    .sectors
                    .iter()
                    .map(|sector| (sector.id, sector.sector_index))
                    .collect::<Vec<_>>()
            );
        }
    }
}
