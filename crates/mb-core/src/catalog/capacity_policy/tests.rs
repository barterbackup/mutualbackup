use super::*;

pub(crate) fn policy() -> CatalogCapacityPolicy {
    CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 1,
        legacy_revisions: 0,
        legacy_source_occurrences: 0,
        data_bytes_per_dataset: 1 << 40,
        data_sources_per_dataset: (1 << 40) / V1_SECTOR_SIZE as u64,
        private_work_per_revision: CatalogCodingTraversalBudget {
            bytes: 2 << 30,
            page_occurrences: 40_000,
            records: 5 * CATALOG_MAX_RECORDS,
        },
        source_pages_per_revision: CATALOG_MAX_PAGE_OCCURRENCES - 40_000,
        authority_control_records: 257,
        packing_profile: PackingProfile {
            format_version: 1,
            sector_size: V1_SECTOR_SIZE as u32,
            slot_size: (V1_SECTOR_SIZE / 4) as u32,
        },
        coding_profile: CodingProfile::new(3, 2, V1_SECTOR_SIZE as u32),
        packed_sectors: 22_422_956,
        coding_groups: 7_474_319,
        replay_work: CatalogCodingTraversalBudget::default(),
    }
}

#[test]
fn complete_capacity_includes_metadata_sources_in_the_required_dense_one_tib_geometry() {
    let plan = policy().plan().unwrap();
    assert_eq!(plan.sources_per_revision, 16_817_217);
    assert_eq!(plan.retained_sources, 16_817_217);
    assert_eq!(plan.minimum_dense_sectors, 22_422_956);
    assert_eq!(plan.minimum_dense_groups, 7_474_319);
    assert!(plan.packing_coding.work.bytes > 4_631_391_975_828);
    assert!(plan.metadata_work.bytes > plan.packing_coding.work.bytes);
    assert!(plan.metadata_work.page_occurrences > plan.packing_coding.work.page_occurrences);
    assert!(plan.job_work.bytes > plan.metadata_work.bytes);
    assert_eq!(
        plan.parity_ciphertext_bytes,
        policy().coding_groups
            * u64::from(crate::MAX_CODING_SHARDS - 1)
            * u64::from(crate::MAX_PROFILE_SHARD_SIZE)
    );
    assert!(plan.encoded_metadata_page_bytes >= plan.packing_coding.encoded_page_bytes);
    assert_eq!(
        plan.source_ciphertext_bytes,
        (1 << 40) + 40_001 * V1_SECTOR_SIZE as u64
    );
    let mut incomplete = policy();
    incomplete.packed_sectors = 22_369_622;
    incomplete.coding_groups = 7_456_541;
    assert!(incomplete.plan().is_err());
}

#[test]
fn complete_capacity_retained_history_counts_private_sources_and_source_occurrences_without_sharing()
 {
    let mut value = policy();
    value.revisions_per_dataset = 2;
    let sources =
        value.data_sources_per_dataset + 2 * (value.private_work_per_revision.page_occurrences + 1);
    value.packed_sectors = (sources * 4).div_ceil(3);
    value.coding_groups = value.packed_sectors.div_ceil(3);
    let first = policy().plan().unwrap();
    let second = value.plan().unwrap();
    assert_eq!(second.retained_sources, first.retained_sources + 40_001);
    assert_eq!(
        second.retained_revision_work.bytes,
        first.retained_revision_work.bytes * 2
    );
    assert_eq!(
        second.retained_revision_work.page_occurrences,
        first.retained_revision_work.page_occurrences * 2
    );
    assert_eq!(
        second.retained_revision_work.records,
        first.retained_revision_work.records * 2
    );
    assert_eq!(second.revision_occurrences, 2);
    value.datasets = 2;
    value.packed_sectors *= 2;
    value.coding_groups *= 2;
    let guild = value.plan().unwrap();
    assert_eq!(guild.retained_sources, second.retained_sources * 2);
    assert_eq!(
        guild.retained_revision_work,
        repeated(second.retained_revision_work, 2).unwrap()
    );
}

#[test]
fn complete_capacity_counts_retired_groups_and_independent_replay_in_every_dimension() {
    let first = policy().plan().unwrap();
    let mut value = policy();
    value.coding_groups += 1;
    value.replay_work = CatalogCodingTraversalBudget {
        bytes: 13,
        page_occurrences: 17,
        records: 19,
    };
    let next = value.plan().unwrap();
    assert_eq!(
        next.packing_coding.coding.groups,
        first.packing_coding.coding.groups + 1
    );
    assert!(next.job_work.bytes > first.job_work.bytes + 13);
    assert!(next.job_work.page_occurrences >= first.job_work.page_occurrences + 17);
    assert!(next.job_work.records > first.job_work.records + 19);
}

#[test]
fn complete_capacity_rejects_incomplete_geometry_and_checked_overflow() {
    let edits: &[fn(&mut CatalogCapacityPolicy)] = &[
        |v| v.format_version = 2,
        |v| v.datasets = 0,
        |v| v.revisions_per_dataset = 0,
        |v| v.revisions_per_dataset = u64::MAX,
        |v| v.data_bytes_per_dataset += 1,
        |v| v.data_sources_per_dataset -= 1,
        |v| v.private_work_per_revision.bytes = u64::MAX,
        |v| v.private_work_per_revision.page_occurrences = CATALOG_MAX_PAGE_OCCURRENCES,
        |v| v.private_work_per_revision.bytes = 1024,
        |v| v.source_pages_per_revision = 0,
        |v| v.source_pages_per_revision = 1,
        |v| v.authority_control_records = u64::MAX,
        |v| v.packing_profile.slot_size = v.packing_profile.sector_size,
        |v| v.packed_sectors -= 1,
        |v| v.coding_groups -= 1,
        |v| v.coding_groups = u64::MAX,
        |v| v.replay_work.bytes = u64::MAX,
    ];
    for edit in edits {
        let mut value = policy();
        edit(&mut value);
        assert!(value.plan().is_err());
    }
}

#[test]
fn complete_capacity_matches_actual_single_owner_packing_with_private_and_bootstrap_sources() {
    let mut value = policy();
    value.data_bytes_per_dataset = 3 * V1_SECTOR_SIZE as u64;
    value.data_sources_per_dataset = 3;
    value.private_work_per_revision = CatalogCodingTraversalBudget {
        bytes: 16,
        page_occurrences: 2,
        records: 0,
    };
    value.source_pages_per_revision = 1;
    value.packed_sectors = 8;
    value.coding_groups = 3;
    let plan = value.plan().unwrap();
    assert_eq!(plan.retained_sources, 6);
    let inputs = (1..=6)
        .map(|index| crate::PackingInput {
            owner: crate::NodeId([7; 32]),
            protected_root: [8; 32],
            object_id: [index; 32],
            source_commitment: None,
            bytes: vec![index; V1_SECTOR_SIZE],
        })
        .collect();
    let actual = crate::pack_incremental(value.packing_profile, None, inputs).unwrap();
    assert_eq!(
        actual.catalog.sectors.len() as u64,
        plan.minimum_dense_sectors
    );
    let scope = CatalogScope::Guild { guild_id: [9; 32] };
    let mut too_small = plan.packing_coding.work;
    too_small.records -= 1;
    assert!(
        CatalogPackingCodingBuilder::with_capacity_policy(scope, 2, 1, value, too_small).is_err()
    );
    CatalogPackingCodingBuilder::with_capacity_policy(scope, 2, 1, value, plan.public_work)
        .unwrap();
}

#[test]
fn complete_capacity_preserves_separate_original_legacy_sources_and_body_work() {
    let first = policy().plan().unwrap();
    let mut value = policy();
    value.legacy_revisions = 1;
    value.legacy_source_occurrences = 512;
    value.packed_sectors = ((first.retained_sources + 512) * 4).div_ceil(3);
    value.coding_groups = value.packed_sectors.div_ceil(3);
    let next = value.plan().unwrap();
    assert_eq!(next.retained_sources, first.retained_sources + 512);
    assert!(next.public_work.bytes >= first.public_work.bytes + V1_MAX_CATALOG_BYTES as u64);
    assert!(
        next.public_work.page_occurrences
            >= first.public_work.page_occurrences + CATALOG_MAX_PAGE_OCCURRENCES
    );
    assert!(next.public_work.records >= first.public_work.records + 512);
    value.legacy_source_occurrences = 0;
    assert!(value.plan().is_err());
    value.legacy_revisions = 0;
    value.legacy_source_occurrences = 1;
    assert!(value.plan().is_err());
}
