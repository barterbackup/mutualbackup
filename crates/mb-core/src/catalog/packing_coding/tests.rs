use super::*;
use crate::{
    MerkleCommitment, NodeId, PackedSlot, PackingInput, canonical_bytes, merkle_commit,
    merkle_open_subtree, pack_incremental,
};
use std::collections::{BTreeMap, HashMap};

fn scope() -> CatalogScope {
    CatalogScope::Guild { guild_id: [37; 32] }
}
fn profile() -> PackingProfile {
    PackingProfile {
        format_version: 1,
        sector_size: 64,
        slot_size: 16,
    }
}
type Pages = HashMap<[u8; 32], Vec<u8>>;

fn records(
    count: u8,
) -> (
    Vec<CatalogPackedSourceRecord>,
    Vec<CatalogPackedSectorRecord>,
    BTreeMap<[u8; 32], CatalogPackedSourceId>,
) {
    let mut sources = Vec::new();
    let mut inputs = Vec::new();
    let mut ids = BTreeMap::new();
    for index in 1..=count {
        let bytes = vec![index; 64];
        let commitment = merkle_commit(&bytes).unwrap();
        let id = CatalogPackedSourceId {
            owner: NodeId([9; 32]),
            protected_root: [8; 32],
            object_id: [index; 32],
        };
        ids.insert(id.key(), id);
        sources.push(CatalogPackedSourceRecord::Source {
            format_version: 1,
            id,
            commitment: commitment.clone(),
        });
        sources.push(CatalogPackedSourceRecord::Proofs {
            first_chunk: 0,
            proofs: (0..4)
                .map(|chunk| {
                    let proof = merkle_open_subtree(&bytes, chunk, 1).unwrap();
                    CatalogPackedSourceProof {
                        subtree_root: proof.subtree_root,
                        siblings: proof.siblings,
                    }
                })
                .collect(),
        });
        inputs.push(PackingInput {
            owner: id.owner,
            protected_root: id.protected_root,
            object_id: id.object_id,
            source_commitment: Some(commitment),
            bytes,
        });
    }
    let packed = pack_incremental(profile(), None, inputs).unwrap();
    let mut sectors = Vec::new();
    for sector in packed.catalog.sectors {
        sectors.push(CatalogPackedSectorRecord::Header {
            format_version: 1,
            id: sector.id,
            sector_index: sector.sector_index,
            flat_root: sector.flat_root,
            commitment: sector.commitment,
        });
        sectors.push(CatalogPackedSectorRecord::Slots {
            offset: 0,
            slots: sector.slots,
        });
    }
    (sources, sectors, ids)
}

#[test]
fn automatic_packing_parts_preserve_complete_proofs_and_original_sector_identities() {
    let (sources, sectors, ids) = records(3);
    assert_eq!(sectors.len(), 8); // Actual single-owner allocator: three sources, four sectors.
    let capacity = CatalogPackingDirectoryCapacity::with_part_bytes(profile(), 3, 4, 600).unwrap();
    assert_eq!((capacity.source_parts, capacity.sector_parts), (3, 4));
    let mut builder = CatalogPackingDirectoryStreamBuilder::with_part_bytes(
        scope(),
        2,
        profile(),
        3,
        4,
        capacity.work,
        600,
    )
    .unwrap();
    let mut pages = Pages::new();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    for record in &sources {
        builder.push_source(record, &mut sink).unwrap();
    }
    for record in &sectors {
        builder.push_sector(record, &mut sink).unwrap();
    }
    let root = builder.finish(&mut sink).unwrap();
    assert_eq!(
        (root.summary.source_parts, root.summary.sector_parts),
        (3, 4)
    );
    capacity.work.check(root.work().unwrap()).unwrap();
    assert!(
        pages.values().map(|bytes| bytes.len() as u64).sum::<u64>() <= capacity.encoded_page_bytes
    );
    let mut reader = CatalogPackingDirectoryReader::new(scope(), root, capacity.work).unwrap();
    let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone());
    for source in &sources {
        let actual = reader.next_source(&mut fetch).unwrap().unwrap();
        match source {
            CatalogPackedSourceRecord::Proofs {
                first_chunk,
                proofs,
            } => assert_eq!(
                actual,
                CatalogPackedSourceRecord::Subtrees {
                    first_chunk: *first_chunk,
                    roots: proofs.iter().map(|proof| proof.subtree_root).collect()
                }
            ),
            _ => assert_eq!(&actual, source),
        }
    }
    assert!(reader.next_source(&mut fetch).unwrap().is_none());
    for expected in &sectors {
        assert_eq!(
            reader
                .next_sector(&mut fetch, &mut |key| Ok(ids[&key]))
                .unwrap()
                .as_ref(),
            Some(expected)
        );
    }
    assert!(
        reader
            .next_sector(&mut fetch, &mut |key| Ok(ids[&key]))
            .unwrap()
            .is_none()
    );
    assert!(reader.is_complete());
}

#[test]
fn packing_construction_field_bounds_cover_full_scalar_widths_and_fragment_tails() {
    use super::super::packing_directory::capacity::{FRAGMENT_BYTES, HEADER_BYTES, SLOT_BYTES};
    let commitment = MerkleCommitment {
        format_version: u16::MAX,
        leaf_size: u16::MAX,
        byte_len: u32::MAX,
        root: [255; 32],
    };
    let source = CatalogPackedSourceRecord::Source {
        format_version: u16::MAX,
        id: CatalogPackedSourceId {
            owner: NodeId([255; 32]),
            protected_root: [255; 32],
            object_id: [255; 32],
        },
        commitment: commitment.clone(),
    };
    let sector = CatalogPackedSectorRecord::Header {
        format_version: u16::MAX,
        id: [255; 32],
        sector_index: u32::MAX,
        flat_root: [255; 32],
        commitment,
    };
    assert!(canonical_bytes(&source).unwrap().len() as u64 <= HEADER_BYTES);
    assert!(canonical_bytes(&sector).unwrap().len() as u64 <= HEADER_BYTES);
    for count in [1, 2, 63, 64] {
        let record = CatalogPackedSourceRecord::Subtrees {
            first_chunk: u32::MAX,
            roots: vec![[255; 32]; count],
        };
        assert!(
            canonical_bytes(&record).unwrap().len() as u64 <= FRAGMENT_BYTES + count as u64 * 32
        );
    }
    for count in [1, 2, 127, 128] {
        for zero in [false, true] {
            let reference = CatalogPackedChunkReference {
                source_key: [255; 32],
                chunk_index: u32::MAX,
                content_hash: [255; 32],
            };
            let slot = if zero {
                CatalogPackedSlotReference::VirtualZero {
                    source: Some(reference),
                }
            } else {
                CatalogPackedSlotReference::Data(reference)
            };
            let record = CatalogPackedSectorRecord::CompactSlots {
                offset: u32::MAX,
                slots: vec![slot; count],
            };
            assert!(
                canonical_bytes(&record).unwrap().len() as u64
                    <= FRAGMENT_BYTES + count as u64 * SLOT_BYTES
            );
        }
    }
}

#[test]
fn combined_reservation_covers_required_dense_geometry_and_checked_part_rounding() {
    let p = PackingProfile {
        format_version: 1,
        sector_size: 65536,
        slot_size: 16384,
    };
    let sources = (1_u64 << 40) / 65536;
    let sectors = (sources * 4).div_ceil(3);
    let groups = sectors.div_ceil(3);
    let capacity = CatalogPackingCodingCapacity::for_counts(p, sources, sectors, groups).unwrap();
    assert_eq!(
        (sources, sectors, groups),
        (16_777_216, 22_369_622, 7_456_541)
    );
    assert_eq!(
        (capacity.packing.source_parts, capacity.packing.sector_parts),
        (1, 1)
    );
    assert_eq!(capacity.packing.source_bytes, 8 + sources * 408);
    assert_eq!(capacity.packing.sector_bytes, 8 + sectors * 568);
    assert_eq!(
        capacity.work,
        capacity
            .packing
            .work
            .checked_add(capacity.coding.work)
            .unwrap()
    );
    assert!(capacity.work.bytes > 4 * (1_u64 << 40));
    assert!(capacity.packing.work.bytes > 7_046_430_806 + 4_596_957_192);
    eprintln!("single-owner 1 TiB packing/coding construction upper bound: {capacity:?}");
    for sector_size in [16, 64, 65536, crate::MAX_PROFILE_SHARD_SIZE] {
        for slot_size in [16, sector_size] {
            let p = PackingProfile {
                format_version: 1,
                sector_size,
                slot_size,
            };
            let capacity = CatalogPackingDirectoryCapacity::for_counts(p, 1, 1).unwrap();
            assert_eq!(
                capacity.work.records,
                4 + u64::from(sector_size / slot_size).div_ceil(64)
                    + u64::from(sector_size / slot_size).div_ceil(128)
            );
        }
    }
    assert!(CatalogPackingDirectoryCapacity::for_counts(p, u64::MAX, 1).is_err());
    assert!(CatalogPackingDirectoryCapacity::for_counts(p, 1, u64::from(u32::MAX) + 2).is_err());
    assert!(CatalogPackingDirectoryCapacity::with_part_bytes(p, 1, 1, 100).is_err());
    assert!(
        CatalogPackingDirectoryCapacity::with_part_bytes(p, 1, 1, CATALOG_MAX_STREAM_BYTES + 1)
            .is_err()
    );
    let boundary = CatalogPackingDirectoryCapacity::with_part_bytes(p, 2, 2, 1000).unwrap();
    assert_eq!((boundary.source_parts, boundary.sector_parts), (1, 2));
    let after = CatalogPackingDirectoryCapacity::with_part_bytes(p, 3, 3, 1000).unwrap();
    assert_eq!((after.source_parts, after.sector_parts), (2, 3));
}

#[test]
fn combined_capacity_refuses_missing_credits_and_fences_extra_occurrences_before_sink_calls() {
    let (sources, sectors, _) = records(3);
    let capacity = CatalogPackingCodingCapacity::for_counts(profile(), 3, 4, 1).unwrap();
    for dimension in 0..3 {
        let mut budget = capacity.work;
        match dimension {
            0 => budget.bytes -= 1,
            1 => budget.page_occurrences -= 1,
            _ => budget.records -= 1,
        }
        assert!(CatalogPackingCodingBuilder::new(scope(), 2, 1, capacity, budget).is_err());
    }
    let mut changed = capacity;
    changed.work.bytes -= 1;
    assert!(CatalogPackingCodingBuilder::new(scope(), 2, 1, changed, capacity.work).is_err());
    for excessive in [0, 1, 2] {
        let mut builder =
            CatalogPackingCodingBuilder::new(scope(), 2, i64::MAX as u64, capacity, capacity.work)
                .unwrap();
        let calls = std::cell::Cell::new(0);
        let mut sink = |_: CatalogPageRef, _: Vec<u8>| {
            calls.set(calls.get() + 1);
            Ok::<_, ()>(())
        };
        for record in &sources {
            builder.push_source(record, &mut sink).unwrap();
        }
        if excessive != 0 {
            for record in &sectors {
                builder.push_sector(record, &mut sink).unwrap();
            }
        }
        let entry = super::super::coding_evidence::tests::entry(2, 1, 64, 256);
        if excessive == 2 {
            builder.push_group(&entry, &mut sink).unwrap();
        }
        let staged = calls.get();
        let result = match excessive {
            0 => builder.push_source(&sources[0], &mut sink),
            1 => builder.push_sector(&sectors[0], &mut sink),
            _ => builder.push_group(&entry, &mut sink),
        };
        assert!(matches!(
            result,
            Err(CatalogStreamError::Catalog(CatalogError::Bounds))
        ));
        assert_eq!(calls.get(), staged);
        assert!(matches!(
            builder.push_group(&entry, &mut sink),
            Err(CatalogStreamError::Catalog(CatalogError::Failed))
        ));
        assert!(builder.finish(&mut sink).is_err());
        assert_eq!(calls.get(), staged);
    }
    let empty = CatalogPackingCodingCapacity::for_counts(profile(), 0, 0, 0).unwrap();
    let roots = CatalogPackingCodingBuilder::new(scope(), 2, 1, empty, empty.work)
        .unwrap()
        .finish(&mut |_, _| Ok::<_, ()>(()))
        .unwrap();
    assert_eq!(roots.work().unwrap(), empty.work);
}

#[test]
fn automatic_packing_rejects_corrupt_boundary_proofs_and_an_empty_final_sector() {
    let (sources, sectors, _) = records(3);
    let capacity = CatalogPackingDirectoryCapacity::with_part_bytes(profile(), 3, 5, 600).unwrap();
    let mut builder = CatalogPackingDirectoryStreamBuilder::with_part_bytes(
        scope(),
        2,
        profile(),
        3,
        5,
        capacity.work,
        600,
    )
    .unwrap();
    let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
    for record in &sources {
        builder.push_source(record, &mut sink).unwrap();
    }
    for record in &sectors {
        builder.push_sector(record, &mut sink).unwrap();
    }
    let bytes = vec![0; 64];
    let mut sector = crate::PackedSectorDescriptor {
        id: [0; 32],
        sector_index: 4,
        flat_root: crate::sector_root(&bytes),
        commitment: merkle_commit(&bytes).unwrap(),
        slots: vec![PackedSlot::VirtualZero { source: None }; 4],
    };
    sector.id = sector.calculate_id(profile()).unwrap();
    builder
        .push_sector(
            &CatalogPackedSectorRecord::Header {
                format_version: 1,
                id: sector.id,
                sector_index: sector.sector_index,
                flat_root: sector.flat_root,
                commitment: sector.commitment,
            },
            &mut sink,
        )
        .unwrap();
    builder
        .push_sector(
            &CatalogPackedSectorRecord::Slots {
                offset: 0,
                slots: sector.slots,
            },
            &mut sink,
        )
        .unwrap();
    // Coverage counts still match; ordinary directory EOF also requires a
    // nonempty final descriptor. Refuse to emit a root that fails that check.
    assert!(builder.finish(&mut sink).is_err());
    let mut builder = CatalogPackingDirectoryStreamBuilder::with_part_bytes(
        scope(),
        2,
        profile(),
        3,
        5,
        capacity.work,
        600,
    )
    .unwrap();
    for record in &sources[..3] {
        builder.push_source(record, &mut sink).unwrap();
    }
    let mut bad = sources[3].clone();
    if let CatalogPackedSourceRecord::Proofs { proofs, .. } = &mut bad {
        proofs[3].subtree_root[0] ^= 1;
    }
    assert!(builder.push_source(&bad, &mut sink).is_err());
    assert!(matches!(
        builder.push_sector(&sectors[0], &mut sink),
        Err(CatalogStreamError::Catalog(CatalogError::Failed))
    ));
    assert!(builder.finish(&mut sink).is_err());
}

#[test]
fn partial_or_reordered_packing_streams_and_storage_failures_never_finish() {
    let (sources, sectors, _) = records(3);
    let capacity = CatalogPackingCodingCapacity::for_counts(profile(), 3, 4, 0).unwrap();
    for failure in 0..5 {
        let mut builder =
            CatalogPackingCodingBuilder::new(scope(), 2, 1, capacity, capacity.work).unwrap();
        let mut sink = |_: CatalogPageRef, _: Vec<u8>| Ok::<_, ()>(());
        match failure {
            0 => {
                builder.push_source(&sources[0], &mut sink).unwrap();
                assert!(builder.push_sector(&sectors[0], &mut sink).is_err());
            }
            1 => {
                for record in &sources {
                    builder.push_source(record, &mut sink).unwrap();
                }
                assert!(builder.push_sector(&sectors[2], &mut sink).is_err());
            }
            2 => {
                for record in &sources {
                    builder.push_source(record, &mut sink).unwrap();
                }
                builder.push_sector(&sectors[0], &mut sink).unwrap();
                assert!(builder.push_source(&sources[0], &mut sink).is_err());
            }
            3 => {
                for record in &sources {
                    builder.push_source(record, &mut sink).unwrap();
                }
                builder.push_sector(&sectors[0], &mut sink).unwrap();
            }
            _ => {
                builder.push_source(&sources[0], &mut sink).unwrap();
            }
        }
        assert!(builder.finish(&mut sink).is_err());
    }
    let capacity = CatalogPackingDirectoryCapacity::with_part_bytes(profile(), 3, 4, 600).unwrap();
    let mut builder = CatalogPackingDirectoryStreamBuilder::with_part_bytes(
        scope(),
        2,
        profile(),
        3,
        4,
        capacity.work,
        600,
    )
    .unwrap();
    builder
        .push_source(&sources[0], &mut |_, _| Ok::<_, ()>(()))
        .unwrap();
    builder
        .push_source(&sources[1], &mut |_, _| Ok::<_, ()>(()))
        .unwrap();
    assert!(matches!(
        builder.push_source(&sources[2], &mut |_, _| Err("full")),
        Err(CatalogStreamError::Storage("full"))
    ));
    assert!(matches!(
        builder.push_sector(&sectors[0], &mut |_, _| Ok::<_, &str>(())),
        Err(CatalogStreamError::Catalog(CatalogError::Failed))
    ));
    assert!(builder.finish(&mut |_, _| Ok::<_, &str>(())).is_err());
    // An oversized untrusted fragment must be rejected before compaction.
    let mut builder = CatalogPackingDirectoryStreamBuilder::new(
        scope(),
        2,
        profile(),
        3,
        4,
        CatalogPackingDirectoryCapacity::for_counts(profile(), 3, 4)
            .unwrap()
            .work,
    )
    .unwrap();
    let record = CatalogPackedSectorRecord::Slots {
        offset: 0,
        slots: vec![PackedSlot::VirtualZero { source: None }; 129],
    };
    assert!(
        builder
            .push_sector(&record, &mut |_, _| Ok::<_, ()>(()))
            .is_err()
    );
}
