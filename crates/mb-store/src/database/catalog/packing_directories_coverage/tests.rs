use super::*;
use crate::RecordScratchStore;
use mb_core::{
    CatalogPackedSectorBuilder, CatalogPackedSectorPart, CatalogPackedSectorReader,
    CatalogPackedSectorRecord, CatalogPackedSourceBuilder, CatalogPackedSourceId,
    CatalogPackedSourcePart, CatalogPackedSourceReader, CatalogPackedSourceRecord,
    CatalogPackingDirectoryBuilder, CatalogPackingDirectoryRecord,
};
use std::collections::HashMap;

pub(crate) struct PackingParts {
    pub(crate) manifest: CatalogPackingDirectoryValidation,
    pub(crate) pages: HashMap<[u8; 32], Vec<u8>>,
    pub(crate) sources: Vec<CatalogPackedSourcePart>,
    pub(crate) sectors: Vec<CatalogPackedSectorPart>,
}

pub(crate) fn shard(
    original: CatalogPackingValidation,
    originals: HashMap<[u8; 32], Vec<u8>>,
) -> PackingParts {
    let mut pages = originals.clone();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    let mut reader = CatalogPackedSourceReader::new(original.scope, original.sources).unwrap();
    let mut source: Option<CatalogPackedSourceBuilder> = None;
    let mut sources = Vec::new();
    let mut ids = HashMap::<[u8; 32], CatalogPackedSourceId>::new();
    let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(originals[&page.hash].clone());
    while let Some(record) = reader.next_record(&mut fetch).unwrap() {
        if let CatalogPackedSourceRecord::Source { id, .. } = record {
            if let Some(builder) = source.take() {
                sources.push(builder.finish_part(&mut sink).unwrap());
            }
            ids.insert(id.key(), id);
            source = Some(
                CatalogPackedSourceBuilder::new_compact(original.scope, original.sources.profile)
                    .unwrap(),
            );
        }
        source.as_mut().unwrap().push(&record, &mut sink).unwrap();
    }
    if let Some(builder) = source {
        sources.push(builder.finish_part(&mut sink).unwrap());
    }
    let mut reader = CatalogPackedSectorReader::new(original.scope, original.descriptors).unwrap();
    let mut sector: Option<CatalogPackedSectorBuilder> = None;
    let mut sectors = Vec::new();
    while let Some(record) = reader
        .next_record_with_sources(&mut fetch, &mut |key| Ok(ids[&key]))
        .unwrap()
    {
        if let CatalogPackedSectorRecord::Header { sector_index, .. } = record {
            if let Some(builder) = sector.take() {
                sectors.push(builder.finish_part(&mut sink).unwrap());
            }
            sector = Some(
                CatalogPackedSectorBuilder::new_part(
                    original.scope,
                    original.descriptors.packing_version,
                    original.descriptors.profile,
                    sector_index,
                )
                .unwrap(),
            );
        }
        sector.as_mut().unwrap().push(&record, &mut sink).unwrap();
    }
    if let Some(builder) = sector {
        sectors.push(builder.finish_part(&mut sink).unwrap());
    }
    let budget = CatalogCodingTraversalBudget {
        bytes: 1 << 30,
        page_occurrences: 1_000_000,
        records: 1_000_000,
    };
    let mut directory = CatalogPackingDirectoryBuilder::new(
        original.scope,
        original.descriptors.packing_version,
        original.descriptors.profile,
        budget,
    )
    .unwrap();
    for record in sources
        .iter()
        .copied()
        .map(CatalogPackingDirectoryRecord::Sources)
        .chain(
            sectors
                .iter()
                .copied()
                .map(CatalogPackingDirectoryRecord::Sectors),
        )
    {
        directory.push(record, &mut sink).unwrap();
    }
    let manifest = CatalogPackingDirectoryValidation {
        format_version: 1,
        scope: original.scope,
        directory: directory.finish(&mut sink).unwrap(),
    };
    PackingParts {
        manifest,
        pages,
        sources,
        sectors,
    }
}

pub(crate) struct Fixture {
    pub(crate) coding: super::super::coding_directory_coverage::tests::Fixture,
    pub(crate) packing: PackingParts,
}
impl Fixture {
    pub(crate) fn new(count: u32) -> Self {
        let coding = super::super::coding_directory_coverage::tests::Fixture::new(count);
        let packing = shard(coding.packing.manifest, coding.packing.pages.clone());
        Self { coding, packing }
    }
    pub(crate) fn manifest(
        &self,
        prior_work: CatalogCodingTraversalBudget,
    ) -> CatalogPackingCodingDirectoriesValidation {
        CatalogPackingCodingDirectoriesValidation {
            format_version: 1,
            packing: self.packing.manifest,
            coding: self.coding.root,
            policy: CatalogCodingCoveragePolicy::Current,
            prior_work,
        }
    }
    pub(crate) fn packing(&self) -> CatalogPackingDirectoryIndex {
        CatalogPackingDirectoryIndex::build(
            self.packing.manifest,
            self.packing.manifest.represented_work().unwrap(),
            RecordScratchStore::new(16 << 20).unwrap(),
            |page| {
                self.packing
                    .pages
                    .get(&page.hash)
                    .cloned()
                    .ok_or_else(|| DatabaseError::NotReady.into())
            },
            |id, commitment| self.coding.packing.authorize(id, commitment),
        )
        .unwrap()
    }
    pub(crate) fn build(&self) -> CatalogPackingCodingDirectoriesIndex {
        let manifest = self.manifest(Default::default());
        self.packing()
            .validate_coding_directory(
                manifest.coding,
                manifest.policy,
                manifest.represented_work().unwrap(),
                |page| self.coding.fetch(page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap()
    }
}

#[test]
fn packing_directories_complete_coverage_and_witnesses_preserve_prior_authority() {
    let fixture = Fixture::new(12);
    let prior = CatalogCodingTraversalBudget {
        bytes: 5000,
        page_occurrences: 5,
        records: 7,
    };
    let manifest = fixture.manifest(prior);
    let total = manifest.represented_work().unwrap();
    let encoded = canonical_bytes_bounded(&manifest, MANIFEST_BYTES).unwrap();
    assert_eq!(
        CatalogPackingCodingDirectoriesValidation::decode(&encoded, total).unwrap(),
        manifest
    );
    let mut bad = encoded.clone();
    bad.push(0);
    assert!(CatalogPackingCodingDirectoriesValidation::decode(&bad, total).is_err());
    assert!(
        CatalogPackingCodingDirectoriesValidation::decode(&encoded[..encoded.len() - 1], total)
            .is_err()
    );
    let proof = fixture
        .packing()
        .validate_directory_with_prior(
            manifest.coding,
            manifest.policy,
            total,
            prior,
            |page| fixture.coding.fetch(page),
            |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
        )
        .unwrap();
    assert_eq!(proof.manifest(), manifest);
    let mut after = None;
    for expected in &fixture.coding.entries {
        let group = proof.next_group(after).unwrap().unwrap();
        assert_eq!(group.group.range.group_id, expected.retained.group.id);
        let (actual, work) = proof
            .read_group_with_work(group.group.range.group_id, |page| {
                fixture.coding.fetch(page)
            })
            .unwrap()
            .unwrap();
        assert_eq!(&actual, expected);
        assert!(work.bytes > 0 && work.page_occurrences > 0 && work.records > 0);
        after = Some(expected.retained.group.id);
    }
    assert_eq!(proof.next_group(after).unwrap(), None);
    for sector in &fixture.coding.packing.sectors {
        assert_eq!(
            proof.packing().sector(sector.id).unwrap().unwrap().index,
            sector.sector_index
        );
        assert!(proof.coverage(sector.id).unwrap().is_some());
    }
    proof
        .packing
        .store
        .replace_record_if_value(COMPLETE, b"root", &encoded, b"tampered")
        .unwrap();
    assert!(proof.next_group(None).is_err());
    assert!(
        proof
            .coverage(fixture.coding.packing.sectors[0].id)
            .is_err()
    );
    assert!(
        proof
            .read_group(after.unwrap(), |_| -> Result<Vec<u8>, CatalogStoreError> {
                panic!("incomplete proof fetched")
            })
            .is_err()
    );
}

#[test]
fn packing_directories_reject_dimensional_debt_before_io_and_incomplete_coding_authority() {
    let fixture = Fixture::new(9);
    let prior = CatalogCodingTraversalBudget {
        bytes: 5000,
        page_occurrences: 5,
        records: 7,
    };
    let manifest = fixture.manifest(prior);
    for dimension in 0..3 {
        let mut limit = manifest.represented_work().unwrap();
        match dimension {
            0 => limit.bytes -= 1,
            1 => limit.page_occurrences -= 1,
            _ => limit.records -= 1,
        }
        assert!(
            fixture
                .packing()
                .validate_directory_with_prior(
                    manifest.coding,
                    manifest.policy,
                    limit,
                    prior,
                    |_| -> Result<Vec<u8>, CatalogStoreError> { panic!("unadmitted page read") },
                    |_| -> Result<CatalogCodingAuthorization, CatalogStoreError> {
                        panic!("unadmitted coding authorization")
                    }
                )
                .is_err()
        );
    }
    for fail in [0, 1, 2] {
        let packing = fixture.packing();
        let manifest = fixture.manifest(Default::default());
        let tail = fixture.coding.forests.last().unwrap().parts[0].page;
        assert!(
            packing
                .store
                .with_record_transaction(|| build(
                    &packing,
                    manifest,
                    manifest.represented_work().unwrap(),
                    &mut |page| {
                        let mut bytes = fixture.coding.fetch(page)?;
                        if fail == 0 && page == tail {
                            bytes.pop();
                        }
                        Ok(bytes)
                    },
                    &mut |_| if fail == 1 {
                        Err(DatabaseError::Conflict.into())
                    } else if fail == 2 {
                        Ok(CatalogCodingAuthorization::Retained)
                    } else {
                        Ok(CatalogCodingAuthorization::CurrentPlacement)
                    }
                ))
                .is_err()
        );
        packing.require_complete().unwrap();
        for kind in [GROUPS, COVERAGE, COMPLETE] {
            assert!(
                packing
                    .store
                    .next_record_bounded(kind, None, 32, MANIFEST_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[test]
fn packing_directories_sql_rollback_and_missing_coverage_leave_no_completed_prefix() {
    let mut fixture = Fixture::new(9);
    for kind in [GROUPS, COVERAGE, COMPLETE] {
        let packing = fixture.packing();
        packing.store.database_shell_statement(&format!("CREATE TEMP TRIGGER skip_row BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
        let manifest = fixture.manifest(Default::default());
        assert!(
            packing
                .store
                .with_record_transaction(|| build(
                    &packing,
                    manifest,
                    manifest.represented_work().unwrap(),
                    &mut |page| fixture.coding.fetch(page),
                    &mut |_| Ok(CatalogCodingAuthorization::CurrentPlacement)
                ))
                .is_err()
        );
        for kind in [GROUPS, COVERAGE, COMPLETE] {
            assert!(
                packing
                    .store
                    .next_record_bounded(kind, None, 32, MANIFEST_BYTES)
                    .unwrap()
                    .is_none()
            );
        }
        packing.require_complete().unwrap();
        packing
            .store
            .database_shell_statement("DROP TRIGGER skip_row", false)
            .unwrap();
        packing
            .validate_coding_directory(
                manifest.coding,
                manifest.policy,
                manifest.represented_work().unwrap(),
                |page| fixture.coding.fetch(page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap();
    }
    fixture.coding.entries.pop();
    fixture.coding.rebuild();
    let manifest = fixture.manifest(Default::default());
    assert!(
        fixture
            .packing()
            .validate_coding_directory(
                manifest.coding,
                manifest.policy,
                manifest.represented_work().unwrap(),
                |page| fixture.coding.fetch(page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement)
            )
            .is_err()
    );
}
