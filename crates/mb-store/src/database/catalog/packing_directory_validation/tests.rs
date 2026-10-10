use super::super::packing_validation::tests::{Fixture, fixture};
use super::*;
use mb_core::{
    CatalogPackedSectorBuilder, CatalogPackedSectorPart, CatalogPackedSourceBuilder,
    CatalogPackedSourcePart, CatalogPackedSourceReader, CatalogPackingDirectoryBuilder,
    CatalogPackingDirectoryRecord, PackedSlot, merkle_zero_commitment,
};

struct DirectoryFixture {
    base: Fixture,
    manifest: CatalogPackingDirectoryValidation,
    sources: Vec<CatalogPackedSourcePart>,
    sectors: Vec<CatalogPackedSectorPart>,
}

impl DirectoryFixture {
    fn new(count: u32, compact: bool) -> Self {
        let mut base = fixture(count, compact);
        let originals = base.pages.clone();
        let mut reader =
            CatalogPackedSourceReader::new(base.manifest.scope, base.manifest.sources).unwrap();
        let mut sources = Vec::new();
        let mut active: Option<CatalogPackedSourceBuilder> = None;
        let mut headers = 0;
        let mut sink = |page: CatalogPageRef, bytes| {
            base.pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        while let Some(record) = reader
            .next_record(&mut |page: CatalogPageRef| Ok::<_, ()>(originals[&page.hash].clone()))
            .unwrap()
        {
            if matches!(record, CatalogPackedSourceRecord::Source { .. }) {
                if headers == 8 {
                    sources.push(active.take().unwrap().finish_part(&mut sink).unwrap());
                    headers = 0;
                }
                headers += 1;
            }
            if active.is_none() {
                active = Some(
                    if compact {
                        CatalogPackedSourceBuilder::new_compact(
                            base.manifest.scope,
                            base.manifest.sources.profile,
                        )
                    } else {
                        CatalogPackedSourceBuilder::new(
                            base.manifest.scope,
                            base.manifest.sources.profile,
                        )
                    }
                    .unwrap(),
                );
            }
            active.as_mut().unwrap().push(&record, &mut sink).unwrap();
        }
        if let Some(builder) = active {
            sources.push(builder.finish_part(&mut sink).unwrap());
        }
        let mut result = Self {
            manifest: CatalogPackingDirectoryValidation {
                format_version: 1,
                scope: base.manifest.scope,
                directory: CatalogPackingDirectoryBuilder::new(
                    base.manifest.scope,
                    3,
                    base.manifest.sources.profile,
                    CatalogCodingTraversalBudget {
                        bytes: 1 << 30,
                        page_occurrences: 1_000_000,
                        records: 1_000_000,
                    },
                )
                .unwrap()
                .finish(&mut |_, _| Ok::<_, ()>(()))
                .unwrap(),
            },
            base,
            sources,
            sectors: Vec::new(),
        };
        result.rebuild();
        result
    }

    fn rebuild(&mut self) {
        self.sectors.clear();
        let scope = self.manifest.scope;
        let profile = self.base.manifest.descriptors.profile;
        let mut sink = |page: CatalogPageRef, bytes| {
            self.base.pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        for sectors in self.base.sectors.chunks_mut(2) {
            let mut builder =
                CatalogPackedSectorBuilder::new_part(scope, 3, profile, sectors[0].sector_index)
                    .unwrap();
            for sector in sectors {
                sector.id = sector.calculate_id(profile).unwrap();
                builder.push_sector(sector, &mut sink).unwrap();
            }
            self.sectors.push(builder.finish_part(&mut sink).unwrap());
        }
        let budget = CatalogCodingTraversalBudget {
            bytes: 1 << 30,
            page_occurrences: 1_000_000,
            records: 1_000_000,
        };
        let mut builder = CatalogPackingDirectoryBuilder::new(scope, 3, profile, budget).unwrap();
        for source in &self.sources {
            builder
                .push(CatalogPackingDirectoryRecord::Sources(*source), &mut sink)
                .unwrap();
        }
        for sector in &self.sectors {
            builder
                .push(CatalogPackingDirectoryRecord::Sectors(*sector), &mut sink)
                .unwrap();
        }
        self.manifest.directory = builder.finish(&mut sink).unwrap();
    }

    fn build(&self, maximum: u64) -> Result<CatalogPackingDirectoryIndex, CatalogStoreError> {
        CatalogPackingDirectoryIndex::build(
            self.manifest,
            self.manifest.represented_work()?,
            RecordScratchStore::new(maximum)?,
            |page| self.base.fetch(page),
            |id, commitment| self.base.authorize(id, commitment),
        )
    }

    fn build_borrowed(&self, store: &RecordScratchStore) -> Result<(), CatalogStoreError> {
        let budget = self.manifest.represented_work()?;
        self.manifest.validate(budget)?;
        let mut streams = CatalogPackingDirectoryReader::new(
            self.manifest.scope,
            self.manifest.directory,
            budget.remaining_after(self.manifest.envelope_work()?)?,
        )?;
        let completion = canonical_bytes_bounded(&self.manifest, ROOT_BYTES)?;
        store.with_record_transaction(|| {
            build_streams(
                &mut streams,
                PackingStreamManifest {
                    profile: self.manifest.directory.profile,
                    chunks: self.manifest.directory.summary.source_chunks,
                    complete_kind: COMPLETE,
                    completion: &completion,
                },
                store,
                &mut |page| self.base.fetch(page),
                &mut |id, commitment| self.base.authorize(id, commitment),
            )
        })
    }
}

#[test]
fn packing_directory_index_joins_cross_part_placements_and_spills_with_a_bounded_cache() {
    for (count, compact) in [(9, false), (2048, true)] {
        let fixture = DirectoryFixture::new(count, compact);
        if compact {
            assert!(fixture.manifest.directory.records.page.height > 0);
        }
        let index = fixture.build(16 << 20).unwrap();
        assert_eq!(index.manifest(), fixture.manifest);
        for sector in &fixture.base.sectors {
            assert_eq!(
                index.sector(sector.id).unwrap(),
                Some(CatalogPackingSector {
                    id: sector.id,
                    index: sector.sector_index,
                    flat_root: sector.flat_root,
                    commitment: sector.commitment.clone(),
                })
            );
            for (slot_index, slot) in sector.slots.iter().enumerate() {
                if let Some(source) = slot.source() {
                    assert_eq!(
                        index.placement(source.id).unwrap(),
                        Some(CatalogPackingPlacement {
                            sector_id: sector.id,
                            sector_index: sector.sector_index,
                            slot_index: slot_index as u32,
                            content_hash: source.content_hash,
                            virtual_zero: matches!(slot, PackedSlot::VirtualZero { .. }),
                        })
                    );
                }
            }
        }
        assert_eq!(index.sector([255; 32]).unwrap(), None);
        if compact {
            let pages = index
                .store
                .database_shell_statement("PRAGMA scratch.page_count", false)
                .unwrap();
            assert!(pages.rows[0][0].parse::<usize>().unwrap() * 4096 > 1 << 20);
        }
        index
            .store
            .replace_record_if_value(
                COMPLETE,
                b"root",
                &canonical_bytes_bounded(&fixture.manifest, ROOT_BYTES).unwrap(),
                b"unverified",
            )
            .unwrap();
        assert!(index.sector(fixture.base.sectors[0].id).is_err());
    }
    let mut fixture = DirectoryFixture::new(9, true);
    let commitment = merkle_zero_commitment(64).unwrap();
    let empty = mb_core::PackedSectorDescriptor {
        id: [0; 32],
        sector_index: 0,
        flat_root: commitment.root,
        commitment,
        slots: vec![PackedSlot::VirtualZero { source: None }; 4],
    };
    fixture.base.sectors.splice(2..2, [empty.clone(), empty]);
    for (index, sector) in fixture.base.sectors.iter_mut().enumerate() {
        sector.sector_index = index as u32;
    }
    fixture.rebuild();
    assert_eq!(fixture.sectors[1].root.source_chunks, 0);
    let index = fixture.build(1 << 20).unwrap();
    for sector in &fixture.base.sectors[2..4] {
        assert_eq!(
            index.sector(sector.id).unwrap().unwrap().index,
            sector.sector_index
        );
    }
}

#[test]
fn packing_directory_index_admits_all_dimensions_before_io_and_rejects_auth_or_damaged_eofs() {
    let fixture = DirectoryFixture::new(17, true);
    let work = fixture.manifest.represented_work().unwrap();
    for dimension in 0..3 {
        let mut limit = work;
        match dimension {
            0 => limit.bytes -= 1,
            1 => limit.page_occurrences -= 1,
            _ => limit.records -= 1,
        }
        assert!(
            CatalogPackingDirectoryIndex::build(
                fixture.manifest,
                limit,
                RecordScratchStore::new(1 << 20).unwrap(),
                |_| panic!("exhausted directory budget fetched pages"),
                |_, _| panic!("exhausted directory budget authorized sources")
            )
            .is_err()
        );
    }
    let encoded = canonical_bytes_bounded(&fixture.manifest, ROOT_BYTES).unwrap();
    assert_eq!(
        CatalogPackingDirectoryValidation::decode(&encoded, work).unwrap(),
        fixture.manifest
    );
    for end in 0..encoded.len() {
        assert!(CatalogPackingDirectoryValidation::decode(&encoded[..end], work).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(CatalogPackingDirectoryValidation::decode(&trailing, work).is_err());
    assert!(
        CatalogPackingDirectoryIndex::build(
            fixture.manifest,
            work,
            RecordScratchStore::new(1 << 20).unwrap(),
            |page| fixture.base.fetch(page),
            |_, _| Err(DatabaseError::Conflict.into())
        )
        .is_err()
    );
    for root in [
        fixture.manifest.directory.records.page,
        fixture.sources.last().unwrap().root.records.page,
        fixture.sectors.last().unwrap().root.records.page,
    ] {
        assert!(
            CatalogPackingDirectoryIndex::build(
                fixture.manifest,
                work,
                RecordScratchStore::new(1 << 20).unwrap(),
                |page| {
                    let mut bytes = fixture.base.fetch(page)?;
                    if page == root {
                        bytes.pop();
                    }
                    Ok(bytes)
                },
                |id, commitment| fixture.base.authorize(id, commitment)
            )
            .is_err()
        );
    }
}

#[test]
fn packing_directory_index_rejects_cross_part_duplicate_chunks_false_zero_and_merkle_substitution()
{
    for mutation in 0..3 {
        let mut fixture = DirectoryFixture::new(17, true);
        let original = fixture.base.sectors[0]
            .slots
            .iter()
            .find(|slot| slot.source().is_some())
            .unwrap()
            .clone();
        let sector = &mut fixture.base.sectors[2];
        match mutation {
            0 => {
                sector.slots[0] = original;
            }
            1 => {
                let source = sector
                    .slots
                    .iter()
                    .find_map(|slot| match slot {
                        PackedSlot::Data(source) => Some(source.clone()),
                        _ => None,
                    })
                    .unwrap();
                sector.slots[0] = PackedSlot::VirtualZero {
                    source: Some(source),
                };
            }
            _ => {
                sector.commitment = merkle_zero_commitment(64).unwrap();
                sector.flat_root = sector.commitment.root;
            }
        }
        fixture.rebuild();
        assert!(fixture.build(1 << 20).is_err());
    }
}

#[test]
fn packing_directory_index_rolls_back_ignored_writes_and_rebuilds_after_scratch_exhaustion() {
    let fixture = DirectoryFixture::new(17, true);
    for (kind, action) in [
        ("packing-source", "INSERT"),
        ("packing-chunk", "INSERT"),
        ("packing-chunk", "UPDATE"),
        ("packing-sector", "INSERT"),
        (COMPLETE, "INSERT"),
    ] {
        let store = RecordScratchStore::new(1 << 20).unwrap();
        store.database_shell_statement(&format!("CREATE TEMP TRIGGER fault BEFORE {action} ON protocol_records WHEN NEW.kind = '{kind}' BEGIN SELECT RAISE(IGNORE); END"),false).unwrap();
        assert!(fixture.build_borrowed(&store).is_err());
        for kind in [
            "packing-source",
            "packing-chunk",
            "packing-sector",
            COMPLETE,
        ] {
            assert!(
                store
                    .next_record_bounded(kind, None, 104, ROOT_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
        store
            .database_shell_statement("DROP TRIGGER fault", false)
            .unwrap();
        fixture.build_borrowed(&store).unwrap();
        assert!(
            store
                .get_record_bounded(COMPLETE, b"root", ROOT_BYTES)
                .unwrap()
                .is_some()
        );
    }
    let large = DirectoryFixture::new(2048, true);
    assert!(large.build(64 << 10).is_err());
    let index = large.build(16 << 20).unwrap();
    assert!(
        index
            .sector(large.base.sectors.last().unwrap().id)
            .unwrap()
            .is_some()
    );
}
