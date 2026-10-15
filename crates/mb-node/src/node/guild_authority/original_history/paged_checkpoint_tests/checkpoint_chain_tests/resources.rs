use super::*;

const REBUILD_OVERHEAD: Work = Work {
    bytes: 16 << 30,
    records: 16 << 20,
    page_occurrences: 16 << 20,
};

/// A small represented dataset with explicit, separate whole-chain work
/// credits. Raising data geometry to make a recovery declaration fit would hide
/// the difference between per-checkpoint and cumulative traversal admission.
pub(super) fn configure(node: &mut Node) {
    let q = mb_store::CatalogPublishedRevisionQuota {
        revisions: 100,
        work: Work {
            bytes: 1 << 30,
            records: 10_000_000,
            page_occurrences: 1_000_000,
        },
    };
    node.configure_published_revision_quotas(mb_store::CatalogPublishedRevisionQuotas {
        global: q,
        guild: q,
        dataset: q,
    })
    .unwrap();
    let data = mb_store::CatalogRetainedSourceQuota {
        logical_bytes: 1 << 30,
        sources: 1_000_000,
        open_reservations: 100,
    };
    node.control
        .configure_catalog_retained_source_quota(data)
        .unwrap();
    node.control
        .configure_catalog_retained_source_guild_quota(data)
        .unwrap();
    let capacity = mb_core::CatalogCapacityPolicy {
        format_version: 1,
        datasets: 1,
        revisions_per_dataset: 2,
        legacy_revisions: 1,
        legacy_source_occurrences: 1,
        data_bytes_per_dataset: 8192,
        data_sources_per_dataset: 1,
        private_work_per_revision: Work {
            bytes: 128 * 1024,
            records: (128 * 1024 - 16) / 5,
            page_occurrences: 16,
        },
        source_pages_per_revision: 16,
        authority_control_records: 4096,
        packing_profile: mb_core::PackingProfile {
            format_version: 1,
            sector_size: mb_core::V1_SECTOR_SIZE as u32,
            slot_size: mb_core::V1_SECTOR_SIZE as u32 / 4,
        },
        coding_profile: mb_core::CodingProfile::new(3, 2, mb_core::V1_SECTOR_SIZE as u32),
        packed_sectors: 48,
        coding_groups: 16,
        replay_work: Work {
            bytes: 64 << 20,
            records: 65536,
            page_occurrences: 65536,
        },
    };
    node.configure_catalog_capacity_policy(capacity).unwrap();
    let plan = capacity.plan().unwrap();
    let (rows, bytes) = mb_store::CatalogResourcePolicy::minimum_control_credits(capacity).unwrap();
    let (pages, journal) =
        mb_store::CatalogResourcePolicy::minimum_database_extents(capacity).unwrap();
    node.configure_control_record_quota(mb_store::DatabaseRecordQuota {
        max_rows: rows,
        max_accounted_bytes: bytes,
    })
    .unwrap();
    node.configure_control_page_quota(mb_store::DatabasePageQuota { max_pages: pages })
        .unwrap();
    node.configure_control_journal_quota(mb_store::DatabaseJournalQuota { max_bytes: journal })
        .unwrap();
    node.control
        .configure_catalog_storage_quota(mb_store::CatalogStorageQuota {
            page_bytes: plan.encoded_metadata_page_bytes,
            pages: plan.metadata_work.page_occurrences,
            open_reservations: 16,
        })
        .unwrap();
    node.configure_catalog_resource_policy(mb_store::CatalogResourcePolicy {
        format_version: 1,
        capacity,
        control_rows: rows,
        control_accounted_bytes: bytes,
        control_pages: pages,
        control_journal_bytes: journal,
        immutable_page_bytes: plan.encoded_metadata_page_bytes,
        immutable_pages: plan.metadata_work.page_occurrences,
        open_page_reservations: 16,
    })
    .unwrap();
    while node
        .advance_checkpoint_acquisition_work_admission()
        .unwrap()
    {}
    let budget = rebuild_budget(node);
    let limit = budget.checked_add(plan.job_work).unwrap();
    node.configure_catalog_traversal_pool_policy(mb_store::CatalogTraversalPoolPolicy {
        format_version: 1,
        capacity,
        limit,
    })
    .unwrap();
}

pub(super) fn released(node: &Node) {
    let usage = node.checkpoint_acquisition_work_usage().unwrap().unwrap();
    assert_eq!(usage.reserved, Work::default());
    assert_eq!(usage.open_jobs, 0);
}

/// The existing validator conservatively admits eight components per source.
/// Three generations retain their original per-checkpoint declarations, which
/// also include worst-case historical custody roles. Keep that allowance
/// explicit instead of changing the dataset geometry to fit a fixed budget.
pub(super) fn rebuild_budget(node: &Node) -> Work {
    let per_checkpoint = node
        .control
        .catalog_capacity_policy()
        .unwrap()
        .unwrap()
        .plan()
        .unwrap()
        .job_work;
    let mut result = REBUILD_OVERHEAD;
    for _ in 0..3 * 8 {
        result = result.checked_add(per_checkpoint).unwrap();
    }
    result
}
