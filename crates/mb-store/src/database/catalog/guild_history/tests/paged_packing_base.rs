use super::*;
use crate::database::catalog::packing_authority::{self as facts, CatalogPackingAuthority};
use mb_core::{CatalogCapacityPolicy, CodingProfile, PackingProfile, SignedRecord, V1_SECTOR_SIZE};

fn scratch() -> RecordScratchStore {
    RecordScratchStore::new(64 * 1024 * 1024).unwrap()
}

fn successor(
    fixture: &super::super::super::checkpoint_validation::tests::Fixture,
) -> SignedRecord<mb_core::PagedUserRevision> {
    let previous = fixture.paged();
    let mut value = previous.value.clone();
    value.sequence += 1;
    value.parent = Some(previous.value.hash().unwrap());
    value.revision_id = Uuid::from_u128(5000);
    value
        .sign(&fixture.sources.writer, &fixture.sources.keys[0])
        .unwrap()
}

fn produce(
    fixture: &super::super::super::checkpoint_validation::tests::Fixture,
    job: CatalogPackingAuthority,
    next: &SignedRecord<mb_core::PagedUserRevision>,
) {
    let job = job
        .with_paged_revision(next, |page| {
            fixture
                .pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    let profile = PackingProfile {
        format_version: 1,
        sector_size: V1_SECTOR_SIZE as u32,
        slot_size: (V1_SECTOR_SIZE / 4) as u32,
    };
    let policy = CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 3,
        legacy_revisions: 1,
        legacy_source_occurrences: 2,
        data_bytes_per_dataset: 2 * V1_SECTOR_SIZE as u64,
        data_sources_per_dataset: 2,
        private_work_per_revision: Work {
            bytes: 16,
            page_occurrences: 2,
            records: 0,
        },
        source_pages_per_revision: 1,
        authority_control_records: 257,
        packing_profile: profile,
        coding_profile: CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32),
        packed_sectors: 18,
        coding_groups: 6,
        replay_work: Work::default(),
    };
    let base = job.base();
    let mut pages = BTreeMap::new();
    let mut payloads = 0;
    let produced = job
        .produce_packing_directory(
            policy,
            budget(),
            (
                |source, bytes| {
                    let index = fixture
                        .sources
                        .records
                        .iter()
                        .position(|record| record.sector.id == source.id.object_id)
                        .ok_or(DatabaseError::NotReady)?;
                    bytes.copy_from_slice(&fixture.sources.bytes[index]);
                    Ok(())
                },
                |page, bytes| {
                    pages.insert(page.hash, bytes);
                    Ok(())
                },
                |sector| {
                    assert_eq!(sector.bytes.len(), V1_SECTOR_SIZE);
                    payloads += 1;
                    Ok(())
                },
            ),
        )
        .unwrap();
    assert!(payloads > 0);
    let index = produced
        .validate(|page| {
            pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    assert_eq!(index.base(), base);
    assert_eq!(index.candidate_count(), 1);
    assert_eq!(index.next_paged_revision(None).unwrap(), Some(next.clone()));
    assert!(
        index
            .next_paged_revision(Some(mb_core::CatalogCheckpointRevisionKey::from(
                &next.value
            )))
            .unwrap()
            .is_none()
    );
}

#[test]
fn paged_source_authority_both_layouts_preserve_original_sources_and_feed_next_packing() {
    let (mut fixture, history) = real_checkpoint();
    let proof = super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    let job = CatalogPackingAuthority::from_paged_checkpoint(
        proof.certificate().hash().unwrap(),
        &proof,
        scratch(),
        budget(),
    )
    .unwrap();
    let mut after = None;
    let mut original = Vec::new();
    while let Some(source) = job.next_source(after).unwrap() {
        after = Some(source.id);
        original.push(source);
    }
    assert_eq!(original.len(), 2);
    let next = successor(&fixture);
    produce(&fixture, job, &next);
    let directory = super::checkpoint_directory_retention::proof(&mut fixture, &history, budget());
    let job = CatalogPackingAuthority::from_paged_checkpoint_directory(
        directory.certificate().hash().unwrap(),
        &directory,
        scratch(),
        budget(),
    )
    .unwrap();
    let mut after = None;
    let mut imported = Vec::new();
    while let Some(source) = job.next_source(after).unwrap() {
        after = Some(source.id);
        imported.push(source);
    }
    assert_eq!(imported, original);
    assert_eq!(
        job.base().membership_epoch,
        Some(directory.trust().authority.membership_epoch)
    );
    produce(&fixture, job, &next);
}

#[test]
fn paged_source_authority_rejects_wrong_identity_budget_and_occupied_destination() {
    let (mut fixture, history) = real_checkpoint();
    let proof = super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    let hash = proof.certificate().hash().unwrap();
    for wrong in [[0; 32], [99; 32]] {
        assert!(
            CatalogPackingAuthority::from_paged_checkpoint(wrong, &proof, scratch(), budget())
                .is_err()
        );
    }
    let minimum = proof
        .index()
        .index()
        .manifest()
        .prior_work
        .checked_add(Work {
            bytes: mb_core::canonical_size_bounded(
                proof.certificate(),
                mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
            )
            .unwrap() as u64,
            page_occurrences: 0,
            records: 1,
        })
        .unwrap();
    for dimension in 0..3 {
        let mut limit = minimum;
        match dimension {
            0 => limit.bytes -= 1,
            1 => limit.page_occurrences -= 1,
            _ => limit.records -= 1,
        }
        assert!(
            CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, scratch(), limit).is_err()
        );
    }
    let store = scratch();
    store
        .put_record_if_absent(facts::SOURCES, b"occupied", b"old")
        .unwrap();
    assert!(CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, store, budget()).is_err());
    assert!(
        CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, scratch(), budget()).is_ok()
    );
}

#[test]
fn paged_source_authority_preserves_latest_writer_parent_and_global_ids() {
    let (mut fixture, history) = real_checkpoint();
    let proof = super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    let hash = proof.certificate().hash().unwrap();
    let valid = successor(&fixture);
    for fault in 0..3 {
        let mut value = valid.value.clone();
        match fault {
            0 => value.parent = Some([233; 32]),
            1 => value.writer_epoch += 1,
            _ => {
                value.revision_id = fixture.sources.certificate.checkpoint.revisions[0]
                    .value
                    .revision_id
            }
        }
        let signed = value
            .sign(&fixture.sources.writer, &fixture.sources.keys[0])
            .unwrap();
        let job = CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, scratch(), budget())
            .unwrap();
        assert!(
            job.with_paged_revision(&signed, |_| panic!("unadmitted successor fetched"))
                .is_err()
        );
    }
}

#[test]
fn paged_source_authority_rejects_damaged_original_fact_and_ignored_import_mutations() {
    let (mut fixture, history) = real_checkpoint();
    let proof = super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    let hash = proof.certificate().hash().unwrap();
    for kind in [
        facts::MEMBERS,
        facts::FENCES,
        facts::SOURCES,
        facts::HEADS,
        facts::IDS,
    ] {
        let store = scratch();
        store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_import BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"),false).unwrap();
        assert!(
            CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, store, budget()).is_err()
        );
    }
    let original = &proof.index().index().packing().store;
    let (key, bytes) = original
        .next_record_bounded(facts::SOURCES, None, 96, 256)
        .unwrap()
        .unwrap();
    original
        .replace_record_if_value(facts::SOURCES, &key, &bytes, b"bad")
        .unwrap();
    assert!(
        CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, scratch(), budget()).is_err()
    );
    original
        .replace_record_if_value(facts::SOURCES, &key, b"bad", &bytes)
        .unwrap();
    let job =
        CatalogPackingAuthority::from_paged_checkpoint(hash, &proof, scratch(), budget()).unwrap();
    let source = job.next_source(None).unwrap().unwrap();
    assert_eq!(key, facts::source_key(source.id));
    assert_eq!(source.commitment, fixture.sources.records[0].commitment);
}

#[test]
fn paged_source_authority_both_layouts_preserve_pruned_revision_tombstone_and_reserved_id() {
    use mb_core::CatalogCheckpointAuthorityRecord as R;
    let mut initial = super::super::super::checkpoint_validation::tests::Fixture::new(true, false);
    let old = initial.paged().value;
    let sources = initial.sources.records.clone();
    initial.replace_paged(old, &sources);
    let (mut fixture, history) = real_checkpoint_with_fixture(initial);
    let previous =
        super::paged_checkpoint_retention::paged_owner_proof(&mut fixture, &history, None);
    let previous_directory =
        super::checkpoint_directory_retention::proof(&mut fixture, &history, budget());
    let retired = fixture
        .records
        .iter()
        .find_map(|record| {
            if let R::LegacyRevision(reference) = record {
                Some(reference.clone())
            } else {
                None
            }
        })
        .unwrap();
    fixture
        .records
        .retain(|record| !matches!(record, R::LegacyRevision(_)));
    let tombstone = mb_core::RevisionTombstone {
        owner: retired.owner,
        protected_root_id: retired.protected_root_id,
        through_sequence: retired.sequence,
        last_revision_id: retired.revision_id,
        last_revision_hash: retired.revision_hash,
        retired_at_generation: 2,
    };
    fixture.records.push(R::Tombstone(tombstone.clone()));
    let next = super::paged_checkpoint_retention::paged_owner_proof(
        &mut fixture,
        &history,
        Some(&previous),
    );
    let directory = super::checkpoint_directory_retention::successor(
        &mut fixture,
        &history,
        Some(&previous_directory),
        budget(),
    );
    for job in [
        CatalogPackingAuthority::from_paged_checkpoint(
            next.certificate().hash().unwrap(),
            &next,
            scratch(),
            budget(),
        )
        .unwrap(),
        CatalogPackingAuthority::from_paged_checkpoint_directory(
            directory.certificate().hash().unwrap(),
            &directory,
            scratch(),
            budget(),
        )
        .unwrap(),
    ] {
        assert_eq!(job.base().generation, 2);
        assert!(job.next_source(None).unwrap().is_some());
        let mut value = successor(&fixture).value;
        value.revision_id = tombstone.last_revision_id;
        let signed = value
            .sign(&fixture.sources.writer, &fixture.sources.keys[0])
            .unwrap();
        assert!(
            job.with_paged_revision(&signed, |_| panic!(
                "reserved retired UUID fetched source pages"
            ))
            .is_err()
        );
    }
}
