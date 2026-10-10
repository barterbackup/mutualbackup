use super::super::tests::Fixture;
use super::*;
use crate::database::catalog::packing_directories_coverage::tests::{PackingParts, shard};
use mb_core::{
    CatalogCodingDirectoryBuilder, CatalogSectorRecord, V1_SECTOR_SIZE, merkle_commit, sector_root,
};

fn fetch(parts: &PackingParts, page: CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError> {
    parts
        .pages
        .get(&page.hash)
        .cloned()
        .ok_or_else(|| DatabaseError::NotReady.into())
}
fn prior(authority: &CatalogPackingAuthority) -> CatalogCodingTraversalBudget {
    CatalogCodingTraversalBudget {
        bytes: authority.bytes,
        page_occurrences: authority.pages,
        records: authority.records,
    }
}

#[test]
fn certified_packing_directories_debit_authority_and_fence_scope_or_missing_commitments_before_io()
{
    let fixture = Fixture::new(true, false);
    let (original, pages) = fixture.packing(&fixture.records, &fixture.bytes);
    let parts = shard(original, pages.into_iter().collect());
    let authority = fixture.authority();
    let total = prior(&authority)
        .checked_add(parts.manifest.represented_work().unwrap())
        .unwrap();
    drop(authority);
    for dimension in 0..3 {
        let mut limit = total;
        match dimension {
            0 => limit.bytes -= 1,
            1 => limit.page_occurrences -= 1,
            _ => limit.records -= 1,
        }
        assert!(
            fixture
                .authority()
                .validate_packing_directory(
                    parts.manifest,
                    limit,
                    |_| -> Result<Vec<u8>, CatalogStoreError> {
                        panic!("unadmitted authority read")
                    }
                )
                .is_err()
        );
    }
    let mut wrong = parts.manifest;
    wrong.scope = CatalogScope::Guild { guild_id: [99; 32] };
    assert!(
        fixture
            .authority()
            .validate_packing_directory(wrong, total, |_| -> Result<Vec<u8>, CatalogStoreError> {
                panic!("wrong guild fetched")
            })
            .is_err()
    );
    let unauthenticated = Fixture::new(false, false).authority();
    let total_unauthenticated = prior(&unauthenticated)
        .checked_add(parts.manifest.represented_work().unwrap())
        .unwrap();
    assert!(
        unauthenticated
            .validate_packing_directory(
                parts.manifest,
                total_unauthenticated,
                |_| -> Result<Vec<u8>, CatalogStoreError> { panic!("unbound source fetched") }
            )
            .is_err()
    );
    let proof = fixture
        .authority()
        .validate_packing_directory(parts.manifest, total, |page| fetch(&parts, page))
        .unwrap();
    assert_eq!(
        proof.base().checkpoint_hash,
        fixture.certificate.hash().unwrap()
    );
    assert_eq!(proof.candidate_count(), 0);
    assert!(proof.next_paged_revision(None).unwrap().is_none());
    for source in &parts.sources {
        for chunk in 0..4 {
            assert!(
                proof
                    .placement(source.first.chunk(chunk))
                    .unwrap()
                    .is_some()
            );
        }
    }
}

#[test]
fn certified_packing_directories_preserve_signed_candidates_and_reject_source_substitution() {
    let fixture = Fixture::new(true, false);
    let extra_bytes = vec![3; V1_SECTOR_SIZE];
    let extra = CatalogSectorRecord {
        format_version: 1,
        sector: mb_core::SectorRef {
            id: [3; 32],
            root: sector_root(&extra_bytes),
            logical_len: 17,
        },
        commitment: merkle_commit(&extra_bytes).unwrap(),
    };
    let (candidate, candidate_pages) =
        fixture.candidate(&[fixture.records[0].clone(), extra.clone()]);
    let mut records = fixture.records.clone();
    records.push(extra);
    let mut payloads = fixture.bytes.clone();
    payloads.push(extra_bytes);
    let (original, pages) = fixture.packing(&records, &payloads);
    let parts = shard(original, pages.into_iter().collect());
    let authority = fixture
        .authority()
        .with_paged_revision(&candidate, |page| {
            candidate_pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    let debt = prior(&authority);
    let total = debt
        .checked_add(parts.manifest.represented_work().unwrap())
        .unwrap();
    let proof = authority
        .validate_packing_directory(parts.manifest, total, |page| fetch(&parts, page))
        .unwrap();
    assert_eq!(proof.candidate_count(), 1);
    assert_eq!(
        proof.next_paged_revision(None).unwrap(),
        Some(candidate.clone())
    );
    assert!(
        proof
            .next_paged_revision(Some(CatalogCheckpointRevisionKey::from(&candidate.value)))
            .unwrap()
            .is_none()
    );
    let mut altered_records = fixture.records.clone();
    let mut altered_payloads = fixture.bytes.clone();
    altered_payloads[0].fill(9);
    altered_records[0].commitment = merkle_commit(&altered_payloads[0]).unwrap();
    altered_records[0].sector.root = sector_root(&altered_payloads[0]);
    let (original, pages) = fixture.packing(&altered_records, &altered_payloads);
    let altered = shard(original, pages.into_iter().collect());
    let authority = fixture.authority();
    let total = prior(&authority)
        .checked_add(altered.manifest.represented_work().unwrap())
        .unwrap();
    assert!(
        authority
            .validate_packing_directory(altered.manifest, total, |page| fetch(&altered, page))
            .is_err()
    );
    let budget = CatalogCodingTraversalBudget {
        bytes: 1 << 30,
        page_occurrences: 1_000_000,
        records: 1_000_000,
    };
    let coding = CatalogCodingDirectoryBuilder::new(parts.manifest.scope, 0, budget)
        .unwrap()
        .finish(&mut |_, _| Ok::<_, ()>(()))
        .unwrap();
    let manifest = CatalogPackingCodingDirectoriesValidation {
        format_version: 1,
        packing: parts.manifest,
        coding,
        policy: CatalogCodingCoveragePolicy::Current,
        prior_work: debt,
    };
    let mut too_small = manifest.represented_work().unwrap();
    too_small.records -= 1;
    assert!(
        proof
            .validate_coding_directory(
                coding,
                manifest.policy,
                too_small,
                |_| -> Result<Vec<u8>, CatalogStoreError> {
                    panic!("authority debt reset at coding boundary")
                },
                |_| -> Result<CatalogCodingAuthorization, CatalogStoreError> {
                    panic!("unadmitted coding authorization")
                }
            )
            .is_err()
    );
}

#[test]
fn certified_packing_directories_complete_coding_preserves_trusted_base_candidates_and_debt() {
    use crate::database::catalog::{
        coding_coverage::tests::entry, packing_validation::tests::Fixture as PackingFixture,
    };
    use mb_core::{PackingInput, pack_incremental, packing_protected_root};
    let fixture = Fixture::new(true, false);
    let (original, original_pages) = fixture.packing(&fixture.records, &fixture.bytes);
    let parts = shard(original, original_pages.into_iter().collect());
    let (candidate, candidate_pages) = fixture.candidate(&fixture.records);
    let authority = fixture
        .authority()
        .with_paged_revision(&candidate, |page| {
            candidate_pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    let debt = prior(&authority);
    let total = debt
        .checked_add(parts.manifest.represented_work().unwrap())
        .unwrap();
    let proof = authority
        .validate_packing_directory(parts.manifest, total, |page| fetch(&parts, page))
        .unwrap();
    let old = &fixture.certificate.checkpoint.revisions[0].value;
    let inputs = fixture
        .records
        .iter()
        .zip(&fixture.bytes)
        .map(|(record, bytes)| PackingInput {
            owner: old.owner,
            protected_root: packing_protected_root(old.protected_root_id),
            object_id: record.sector.id,
            source_commitment: Some(record.commitment.clone()),
            bytes: bytes.clone(),
        })
        .collect();
    let packed = pack_incremental(original.descriptors.profile, None, inputs).unwrap();
    assert_eq!(packed.catalog.sectors.len(), 3);
    let packing_fixture = PackingFixture {
        manifest: original,
        pages: Default::default(),
        roles: Default::default(),
        authority: Default::default(),
        sectors: packed.catalog.sectors,
        bytes: packed
            .sectors
            .into_iter()
            .map(|sector| sector.bytes)
            .collect(),
    };
    let expected = entry(&packing_fixture, [0, 1, 2], 1, 2, None);
    let budget = CatalogCodingTraversalBudget {
        bytes: 1 << 30,
        page_occurrences: 1_000_000,
        records: 1_000_000,
    };
    let mut pages = std::collections::HashMap::new();
    let mut sink = |page: CatalogPageRef, bytes| {
        pages.insert(page.hash, bytes);
        Ok::<_, ()>(())
    };
    let mut coding = CatalogCodingDirectoryBuilder::new(original.scope, 100, budget).unwrap();
    coding.push_group(&expected, &mut sink).unwrap();
    let coding = coding.finish(&mut sink).unwrap();
    let manifest = CatalogPackingCodingDirectoriesValidation {
        format_version: 1,
        packing: parts.manifest,
        coding,
        policy: CatalogCodingCoveragePolicy::Current,
        prior_work: debt,
    };
    let total = manifest.represented_work().unwrap();
    let proof = proof
        .validate_coding_directory(
            coding,
            manifest.policy,
            total,
            |page| {
                pages
                    .get(&page.hash)
                    .cloned()
                    .ok_or_else(|| DatabaseError::NotReady.into())
            },
            |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
        )
        .unwrap();
    assert_eq!(
        proof.base().checkpoint_hash,
        fixture.certificate.hash().unwrap()
    );
    assert_eq!(proof.index().manifest().prior_work, debt);
    assert_eq!(proof.represented_work().unwrap(), total);
    assert_eq!(proof.candidate_count(), 1);
    assert_eq!(
        proof.next_paged_revision(None).unwrap(),
        Some(candidate.clone())
    );
    assert!(
        proof
            .next_paged_revision(Some(CatalogCheckpointRevisionKey::from(&candidate.value)))
            .unwrap()
            .is_none()
    );
    assert_eq!(
        proof
            .index()
            .read_group(expected.retained.group.id, |page| pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into()))
            .unwrap(),
        Some(expected)
    );
    for sector in &packing_fixture.sectors {
        assert!(proof.index().coverage(sector.id).unwrap().is_some());
    }
}
