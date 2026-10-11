use super::*;
use crate::RecordScratchStore;
use mb_core::{
    CatalogPackedSectorPart, CatalogPackedSectorReader, CatalogPackedSourceId,
    CatalogPackedSourcePart, CatalogPackedSourceReader, CatalogPackedSourceRecord,
    CatalogPackingDirectoryRecord,
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
    let budget = mb_core::CatalogPackingDirectoryCapacity::with_part_bytes(
        original.sources.profile,
        original.sources.sources,
        original.descriptors.sectors,
        600,
    )
    .unwrap()
    .work;
    let mut builder = mb_core::CatalogPackingDirectoryStreamBuilder::with_part_bytes(
        original.scope,
        original.descriptors.packing_version,
        original.sources.profile,
        original.sources.sources,
        original.descriptors.sectors,
        budget,
        600,
    )
    .unwrap();
    let mut ids = HashMap::<[u8; 32], CatalogPackedSourceId>::new();
    let mut fetch = |page: CatalogPageRef| Ok::<_, ()>(originals[&page.hash].clone());
    while let Some(record) = reader.next_record(&mut fetch).unwrap() {
        if let CatalogPackedSourceRecord::Source { id, .. } = record {
            ids.insert(id.key(), id);
        }
        builder.push_source(&record, &mut sink).unwrap();
    }
    let mut reader = CatalogPackedSectorReader::new(original.scope, original.descriptors).unwrap();
    while let Some(record) = reader
        .next_record_with_sources(&mut fetch, &mut |key| Ok(ids[&key]))
        .unwrap()
    {
        builder.push_sector(&record, &mut sink).unwrap();
    }
    let manifest = CatalogPackingDirectoryValidation {
        format_version: 1,
        scope: original.scope,
        directory: builder.finish(&mut sink).unwrap(),
    };
    let mut sources = Vec::new();
    let mut sectors = Vec::new();
    let mut directory = mb_core::CatalogRecordReader::new(
        original.scope,
        mb_core::CatalogSection::Packing,
        manifest.directory.records,
    )
    .unwrap();
    while let Some(bytes) = directory
        .next_record(&mut |page: CatalogPageRef| Ok::<_, ()>(pages[&page.hash].clone()))
        .unwrap()
    {
        match CatalogPackingDirectoryRecord::decode(&bytes).unwrap() {
            CatalogPackingDirectoryRecord::Sources(part) => sources.push(part),
            CatalogPackingDirectoryRecord::Sectors(part) => sectors.push(part),
        }
    }
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
fn combined_construction_credits_feed_complete_source_placement_and_original_witness_joins() {
    use mb_core::{CatalogPackingCodingBuilder, CatalogPackingCodingCapacity};
    let fixture = Fixture::new(12);
    let original = fixture.coding.packing.manifest;
    let capacity = CatalogPackingCodingCapacity::with_packing_part_bytes(
        original.sources.profile,
        original.sources.sources,
        original.descriptors.sectors,
        fixture.coding.entries.len() as u64,
        600,
    )
    .unwrap();
    let mut builder = CatalogPackingCodingBuilder::new(
        original.scope,
        original.descriptors.packing_version,
        fixture.coding.root.guild_event_sequence,
        capacity,
        capacity.work,
    )
    .unwrap();
    let mut pages = HashMap::new();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, CatalogStoreError>(())
    };
    let mut ids = HashMap::new();
    let mut sources = CatalogPackedSourceReader::new(original.scope, original.sources).unwrap();
    while let Some(record) = sources
        .next_record(&mut |page| fixture.coding.packing.fetch(page))
        .unwrap()
    {
        if let CatalogPackedSourceRecord::Source { id, .. } = record {
            ids.insert(id.key(), id);
        }
        builder.push_source(&record, &mut sink).unwrap();
    }
    let mut sectors = CatalogPackedSectorReader::new(original.scope, original.descriptors).unwrap();
    while let Some(record) = sectors
        .next_record_with_sources(&mut |page| fixture.coding.packing.fetch(page), &mut |key| {
            Ok(ids[&key])
        })
        .unwrap()
    {
        builder.push_sector(&record, &mut sink).unwrap();
    }
    for entry in &fixture.coding.entries {
        builder.push_group(entry, &mut sink).unwrap();
    }
    let roots = builder.finish(&mut sink).unwrap();
    capacity
        .work
        .remaining_after(roots.work().unwrap())
        .unwrap();
    assert_eq!(roots.packing.summary.sources, original.sources.sources);
    assert_eq!(roots.packing.summary.sectors, original.descriptors.sectors);
    assert_eq!(
        roots.coding.summary.coding.groups,
        fixture.coding.entries.len() as u64
    );
    assert!(
        pages.values().map(|bytes| bytes.len() as u64).sum::<u64>() <= capacity.encoded_page_bytes
    );
    let packing = CatalogPackingDirectoryValidation {
        format_version: 1,
        scope: original.scope,
        directory: roots.packing,
    };
    let manifest = CatalogPackingCodingDirectoriesValidation {
        format_version: 1,
        packing,
        coding: roots.coding,
        policy: CatalogCodingCoveragePolicy::Current,
        prior_work: Default::default(),
    };
    let fetch = |page: CatalogPageRef| {
        pages
            .get(&page.hash)
            .cloned()
            .ok_or_else(|| DatabaseError::NotReady.into())
    };
    let proof = CatalogPackingDirectoryIndex::build(
        packing,
        packing.represented_work().unwrap(),
        RecordScratchStore::new(16 << 20).unwrap(),
        fetch,
        |id, commitment| fixture.coding.packing.authorize(id, commitment),
    )
    .unwrap()
    .validate_coding_directory(
        roots.coding,
        manifest.policy,
        manifest.represented_work().unwrap(),
        fetch,
        |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
    )
    .unwrap();
    assert_eq!(proof.manifest(), manifest);
    for expected in &fixture.coding.entries {
        let (actual, _) = proof
            .read_group_with_work(expected.retained.group.id, fetch)
            .unwrap()
            .unwrap();
        assert_eq!(
            canonical_bytes(&actual.transcript).unwrap(),
            canonical_bytes(&expected.transcript).unwrap()
        );
        assert_eq!(&actual, expected);
    }
    for sector in &fixture.coding.packing.sectors {
        assert!(proof.coverage(sector.id).unwrap().is_some());
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
