use super::super::tests::Fixture;
use super::*;
use mb_core::{
    CodingProfile, PackingInput, PackingProfile, USER_REVISION_DOMAIN, pack_incremental,
};
use std::{cell::Cell, collections::BTreeMap};

fn policy(profile: PackingProfile) -> CatalogCapacityPolicy {
    let sources = 3 * (8 + 2 + 1) + 6;
    let width = u64::from(profile.slots_per_sector().unwrap());
    let sectors = (sources * width).div_ceil(width - 1);
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 3,
        revisions_per_dataset: 1,
        legacy_revisions: 3,
        legacy_source_occurrences: 6,
        data_bytes_per_dataset: 8 * V1_SECTOR_SIZE as u64,
        data_sources_per_dataset: 8,
        private_work_per_revision: CatalogCodingTraversalBudget {
            bytes: 16,
            page_occurrences: 2,
            records: 0,
        },
        source_pages_per_revision: 1,
        authority_control_records: 257,
        packing_profile: profile,
        coding_profile: CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32),
        packed_sectors: sectors,
        coding_groups: sectors.div_ceil(3),
        replay_work: CatalogCodingTraversalBudget::default(),
    }
}
fn profile(slot_size: u32) -> PackingProfile {
    PackingProfile {
        format_version: 1,
        sector_size: V1_SECTOR_SIZE as u32,
        slot_size,
    }
}
fn budget(
    authority: &CatalogPackingAuthority,
    policy: CatalogCapacityPolicy,
) -> CatalogCodingTraversalBudget {
    CatalogCodingTraversalBudget {
        bytes: authority.bytes,
        page_occurrences: authority.pages,
        records: authority.records,
    }
    .checked_add(policy.plan().unwrap().packing_coding.packing.work)
    .unwrap()
}
fn fill(
    fixture: &Fixture,
    source: &CatalogPackingAuthorizedSource,
    bytes: &mut [u8],
) -> Result<(), CatalogStoreError> {
    let index = fixture
        .records
        .iter()
        .position(|r| r.sector.id == source.id.object_id)
        .ok_or(DatabaseError::NotReady)?;
    bytes.copy_from_slice(&fixture.bytes[index]);
    Ok(())
}
fn compare(fixture: &Fixture, profile: PackingProfile) {
    let value = policy(profile);
    let authority = CatalogPackingAuthority::from_legacy_checkpoint(
        fixture.certificate.hash().unwrap(),
        &fixture.certificate,
        RecordScratchStore::new(32 * 1024 * 1024).unwrap(),
    )
    .unwrap();
    let limit = budget(&authority, value);
    let mut pages = BTreeMap::new();
    let mut sectors = Vec::new();
    let produced = authority
        .produce_packing_directory(
            value,
            limit,
            (
                |source, bytes| fill(fixture, source, bytes),
                |page, bytes| {
                    pages.insert(page.hash, bytes);
                    Ok(())
                },
                |sector| {
                    sectors.push(sector.clone());
                    Ok(())
                },
            ),
        )
        .unwrap();
    let mut inputs = Vec::new();
    for revision in &fixture.certificate.checkpoint.revisions {
        for reference in revision
            .value
            .metadata_sectors
            .iter()
            .chain(&revision.value.data_sectors)
        {
            let index = fixture
                .records
                .iter()
                .position(|r| r.sector.id == reference.id)
                .unwrap();
            inputs.push(PackingInput {
                owner: revision.value.owner,
                protected_root: packing_protected_root(revision.value.protected_root_id),
                object_id: reference.id,
                source_commitment: Some(fixture.records[index].commitment.clone()),
                bytes: fixture.bytes[index].clone(),
            });
        }
    }
    if profile.slot_size > MERKLE_LEAF_SIZE as u32 {
        let expected = pack_incremental(profile, None, inputs).unwrap();
        assert_eq!(
            sectors, expected.sectors,
            "original payload, descriptors and identities"
        );
    } else {
        // Avoid the reference packer's quadratic full-source proof work at
        // this extreme. Independently verify every bounded payload and slot.
        for sector in &sectors {
            assert_eq!(
                sector.descriptor.calculate_id(profile).unwrap(),
                sector.descriptor.id
            );
            assert_eq!(
                merkle_commit(&sector.bytes).unwrap(),
                sector.descriptor.commitment
            );
            for (slot, value) in sector.descriptor.slots.iter().enumerate() {
                if let Some(source) = value.source() {
                    let input = inputs
                        .iter()
                        .find(|input| {
                            input.object_id == source.id.object_id && input.owner == source.id.owner
                        })
                        .unwrap();
                    let offset = source.source_offset as usize;
                    let chunk = &input.bytes[offset..offset + profile.slot_size as usize];
                    assert_eq!(*blake3::hash(chunk).as_bytes(), source.content_hash);
                    let offset = slot * profile.slot_size as usize;
                    assert_eq!(chunk, &sector.bytes[offset..offset + chunk.len()]);
                }
            }
        }
    }
    let manifest = produced.manifest();
    assert_eq!(manifest.directory.summary.sectors, sectors.len() as u64);
    let index = produced
        .validate(|page| {
            pages
                .get(&page.hash)
                .cloned()
                .ok_or_else(|| DatabaseError::NotReady.into())
        })
        .unwrap();
    assert_eq!(
        index.base().checkpoint_hash,
        fixture.certificate.hash().unwrap()
    );
    for sector in &sectors {
        for slot in &sector.descriptor.slots {
            if let Some(source) = slot.source() {
                let placement = index.placement(source.id).unwrap().unwrap();
                assert_eq!(placement.sector_index, sector.descriptor.sector_index);
            }
        }
    }
}

#[test]
fn source_authorized_packing_producer_preserves_single_owner_spares_and_original_bytes() {
    let fixture = Fixture::new(true, false);
    compare(&fixture, profile((V1_SECTOR_SIZE / 4) as u32));
    // Widest supported slots exercise many bounded proof/slot fragments.
    compare(&fixture, profile(MERKLE_LEAF_SIZE as u32));
}

#[test]
fn source_authorized_packing_producer_preserves_multi_owner_rounds_and_virtual_zero_sources() {
    let mut fixture = Fixture::new(true, false);
    fixture.bytes[0].fill(0);
    fixture.records[0].sector.root = sector_root(&fixture.bytes[0]);
    fixture.records[0].commitment = merkle_commit(&fixture.bytes[0]).unwrap();
    let original = fixture.certificate.checkpoint.revisions[0].value.clone();
    fixture.certificate.checkpoint.revisions.clear();
    fixture.certificate.checkpoint.writer_fences.clear();
    for (index, keys) in fixture.keys.iter().enumerate() {
        let mut revision = original.clone();
        revision.owner = keys.node_id();
        revision.revision_id = Uuid::from_u128(300 + index as u128);
        let mut records = fixture.records[..2].to_vec();
        for (part, record) in records.iter_mut().enumerate() {
            record.sector.id = [10 + (index * 2 + part) as u8; 32];
            fixture.records.push(record.clone());
            fixture.bytes.push(fixture.bytes[part].clone());
        }
        revision.metadata_sectors = vec![records[0].sector.clone()];
        revision.data_sectors = if index == 1 {
            Vec::new()
        } else {
            vec![records[1].sector.clone()]
        };
        revision.sector_commitments = Some(if index == 1 {
            vec![records[0].commitment.clone()]
        } else {
            records.iter().map(|r| r.commitment.clone()).collect()
        });
        revision.sign_writer(&fixture.writer).unwrap();
        fixture
            .certificate
            .checkpoint
            .writer_fences
            .push(WriterFence {
                owner: keys.node_id(),
                epoch: 1,
                public_key: fixture.writer.verifying_key().to_bytes(),
            });
        fixture
            .certificate
            .checkpoint
            .revisions
            .push(SignedRecord::sign(USER_REVISION_DOMAIN, revision, keys).unwrap());
    }
    fixture
        .certificate
        .checkpoint
        .revisions
        .sort_by_key(|r| (r.value.owner, r.value.protected_root_id));
    fixture
        .certificate
        .checkpoint
        .writer_fences
        .sort_by_key(|f| f.owner);
    fixture.resign();
    compare(&fixture, profile((V1_SECTOR_SIZE / 4) as u32));
}

#[test]
fn source_authorized_packing_producer_rejects_unadmitted_or_unauthenticated_inputs_before_io() {
    let fixture = Fixture::new(true, false);
    let value = policy(profile((V1_SECTOR_SIZE / 4) as u32));
    for dimension in 0..3 {
        let authority = fixture.authority();
        let mut limit = budget(&authority, value);
        match dimension {
            0 => limit.bytes -= 1,
            1 => limit.page_occurrences -= 1,
            _ => limit.records -= 1,
        }
        assert!(
            authority
                .produce_packing_directory(
                    value,
                    limit,
                    (
                        |_, _| panic!("unadmitted source read"),
                        |_, _| panic!("unadmitted page"),
                        |_| panic!("unadmitted payload")
                    )
                )
                .is_err()
        );
    }
    let authority = Fixture::new(false, false).authority();
    let limit = budget(&authority, value);
    assert!(
        authority
            .produce_packing_directory(
                value,
                limit,
                (
                    |_, _| panic!("unauthenticated source"),
                    |_, _| panic!("unauthenticated page"),
                    |_| panic!("unauthenticated payload")
                )
            )
            .is_err()
    );
}

#[test]
fn source_authorized_packing_producer_keeps_original_paged_candidate_and_requires_page_eofs() {
    let mut fixture = Fixture::new(true, false);
    let bytes = vec![3; V1_SECTOR_SIZE];
    let extra = mb_core::CatalogSectorRecord {
        format_version: 1,
        sector: mb_core::SectorRef {
            id: [3; 32],
            root: sector_root(&bytes),
            logical_len: 17,
        },
        commitment: merkle_commit(&bytes).unwrap(),
    };
    let (candidate, candidate_pages) =
        fixture.candidate(&[fixture.records[0].clone(), extra.clone()]);
    fixture.records.push(extra);
    fixture.bytes.push(bytes);
    let value = policy(profile((V1_SECTOR_SIZE / 4) as u32));
    for missing in [true, false] {
        let authority = fixture
            .authority()
            .with_paged_revision(&candidate, |page| {
                candidate_pages
                    .get(&page.hash)
                    .cloned()
                    .ok_or_else(|| DatabaseError::NotReady.into())
            })
            .unwrap();
        let limit = budget(&authority, value);
        let mut pages = BTreeMap::new();
        let produced = authority
            .produce_packing_directory(
                value,
                limit,
                (
                    |source, bytes| fill(&fixture, source, bytes),
                    |page, bytes| {
                        pages.insert(page.hash, bytes);
                        Ok(())
                    },
                    |_| Ok(()),
                ),
            )
            .unwrap();
        assert_eq!(produced.manifest().directory.summary.sources, 3);
        let index = produced.validate(|page| {
            if missing {
                Err(DatabaseError::NotReady.into())
            } else {
                pages
                    .get(&page.hash)
                    .cloned()
                    .ok_or_else(|| DatabaseError::NotReady.into())
            }
        });
        if missing {
            assert!(index.is_err());
        } else {
            let index = index.unwrap();
            assert_eq!(index.candidate_count(), 1);
            assert_eq!(
                index.next_paged_revision(None).unwrap(),
                Some(candidate.clone())
            );
            assert!(
                index
                    .next_paged_revision(Some(CatalogCheckpointRevisionKey::from(&candidate.value)))
                    .unwrap()
                    .is_none()
            );
        }
    }
}

#[test]
fn source_authorized_packing_producer_fences_changed_payload_and_sink_failure_without_root() {
    let fixture = Fixture::new(true, false);
    let value = policy(profile((V1_SECTOR_SIZE / 4) as u32));
    for fault in 0..4 {
        let authority = fixture.authority();
        let limit = budget(&authority, value);
        let reads = Cell::new(0);
        let pages = Cell::new(0);
        let payloads = Cell::new(0);
        assert!(
            authority
                .produce_packing_directory(
                    value,
                    limit,
                    (
                        |source, bytes| {
                            fill(&fixture, source, bytes)?;
                            reads.set(reads.get() + 1);
                            if fault == 0 || fault == 1 && reads.get() > 2 {
                                bytes[0] ^= 1;
                            }
                            Ok(())
                        },
                        |_, _| {
                            pages.set(pages.get() + 1);
                            if fault == 2 {
                                Err(DatabaseError::Conflict.into())
                            } else {
                                Ok(())
                            }
                        },
                        |_| {
                            payloads.set(payloads.get() + 1);
                            if fault == 3 {
                                Err(DatabaseError::Conflict.into())
                            } else {
                                Ok(())
                            }
                        }
                    )
                )
                .is_err()
        );
        if fault == 0 {
            assert_eq!(pages.get(), 0);
            assert_eq!(payloads.get(), 0);
        }
        if fault == 1 {
            assert_eq!(payloads.get(), 0);
        }
        if fault == 3 {
            assert_eq!(payloads.get(), 1);
        }
    }
}

#[test]
fn disk_slot_allocation_rejects_ignored_mutations_and_rolls_back_the_whole_batch() {
    let id = SourceChunkId {
        owner: NodeId([1; 32]),
        protected_root: [2; 32],
        object_id: [3; 32],
        chunk_index: 0,
    };
    for kind in [
        slots::ASSIGNMENTS,
        slots::STATES,
        slots::SINGLE,
        slots::FILLABLE,
    ] {
        let store = RecordScratchStore::new(4 * 1024 * 1024).unwrap();
        store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignored BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
        let mut allocation = Slots::new(&store, 4, 100);
        assert!(
            store
                .with_record_transaction(|| allocation.assign(id))
                .is_err()
        );
        for kind in [
            slots::ASSIGNMENTS,
            slots::STATES,
            slots::SINGLE,
            slots::FILLABLE,
        ] {
            assert!(
                store
                    .next_record_metadata_bounded(kind, None, 100)
                    .unwrap()
                    .is_none()
            );
        }
        store
            .database_shell_statement("DROP TRIGGER ignored", false)
            .unwrap();
        let mut allocation = Slots::new(&store, 4, 100);
        store
            .with_record_transaction(|| allocation.assign(id))
            .unwrap();
        assert_eq!(allocation.at(0, 0).unwrap(), Some(id));
        assert_eq!(allocation.sectors(), 1);
    }
}

#[test]
fn disk_slot_reads_reject_invalid_source_geometry_before_payload_indexing() {
    let id = SourceChunkId {
        owner: NodeId([1; 32]),
        protected_root: [2; 32],
        object_id: [3; 32],
        chunk_index: 0,
    };
    let store = RecordScratchStore::new(4 * 1024 * 1024).unwrap();
    let mut allocation = Slots::new(&store, 4, 100);
    store
        .with_record_transaction(|| allocation.assign(id))
        .unwrap();
    let valid = encoded(&id, ROW_BYTES).unwrap();
    for fault in 0..5 {
        let mut invalid = id;
        match fault {
            0 => invalid.chunk_index = 4,
            1 => invalid.chunk_index = u32::MAX,
            2 => invalid.owner = NodeId([0; 32]),
            3 => invalid.protected_root = [0; 32],
            _ => invalid.object_id = [0; 32],
        }
        let bytes = encoded(&invalid, ROW_BYTES).unwrap();
        store
            .replace_record_if_value(slots::ASSIGNMENTS, &[0; 8], &valid, &bytes)
            .unwrap();
        assert!(
            allocation.at(0, 0).is_err(),
            "unvalidated source geometry {fault}"
        );
        store
            .replace_record_if_value(slots::ASSIGNMENTS, &[0; 8], &bytes, &valid)
            .unwrap();
        assert_eq!(allocation.at(0, 0).unwrap(), Some(id));
    }
}
