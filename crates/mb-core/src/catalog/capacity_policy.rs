//! One local contract for retained revisions and the enclosing checkpoint.
//! These are represented-work and immutable-payload bounds. Database pages,
//! journals, scratch, physical blocks and distributed availability are separate.

use super::*;
use crate::{
    CodingProfile, PAGED_QUORUM_CHECKPOINT_BYTES, PackingProfile, V1_MAX_CATALOG_BYTES,
    V1_SECTOR_SIZE,
};
use serde::{Deserialize, Serialize};

/// Independently configured local admission, never authority supplied by a
/// certificate. A dataset's data limit counts unique retained data sources;
/// private page and bootstrap sources are additional to that data allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCapacityPolicy {
    pub format_version: u16,
    /// Aggregate guild allowance in dataset units. Root registration count is
    /// independent; data and revision ledgers enforce these aggregate credits.
    pub datasets: u32,
    pub revisions_per_dataset: u64,
    /// Original legacy bodies/source occurrences retained by the checkpoint.
    /// These credits preserve old metadata sources and do not assume sharing.
    pub legacy_revisions: u64,
    pub legacy_source_occurrences: u64,
    pub data_bytes_per_dataset: u64,
    pub data_sources_per_dataset: u64,
    /// Aggregate native/Git roots, excluding the public source tree.
    pub private_work_per_revision: CatalogCodingTraversalBudget,
    /// Allows existing non-dense source layouts; not inferred from byte length.
    pub source_pages_per_revision: u64,
    /// Members, fences, tombstones and original migration evidence together.
    pub authority_control_records: u64,
    pub packing_profile: PackingProfile,
    pub coding_profile: CodingProfile,
    /// Include retained obsolete placements, not just the new dense allocation.
    pub packed_sectors: u64,
    /// Include every live/candidate/retired original witness.
    pub coding_groups: u64,
    /// Independent credits for the complete proof, including current/previous
    /// public state, original history and repeated work. No payload borrowing.
    pub replay_work: CatalogCodingTraversalBudget,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatalogCapacityPlan {
    pub revision_occurrences: u64,
    pub sources_per_revision: u64,
    pub retained_sources: u64,
    pub minimum_dense_sectors: u64,
    pub minimum_dense_groups: u64,
    pub revision_work: CatalogCodingTraversalBudget,
    pub retained_revision_work: CatalogCodingTraversalBudget,
    pub public_work: CatalogCodingTraversalBudget,
    pub metadata_work: CatalogCodingTraversalBudget,
    pub job_work: CatalogCodingTraversalBudget,
    pub packing_coding: CatalogPackingCodingCapacity,
    pub encoded_metadata_page_bytes: u64,
    pub source_ciphertext_bytes: u64,
    pub packed_ciphertext_bytes: u64,
    pub parity_ciphertext_bytes: u64,
}

fn mul(a: u64, b: u64) -> Result<u64, CatalogError> {
    a.checked_mul(b).ok_or(CatalogError::Bounds)
}
fn add(a: u64, b: u64) -> Result<u64, CatalogError> {
    a.checked_add(b).ok_or(CatalogError::Bounds)
}
fn repeated(
    work: CatalogCodingTraversalBudget,
    count: u64,
) -> Result<CatalogCodingTraversalBudget, CatalogError> {
    Ok(CatalogCodingTraversalBudget {
        bytes: mul(work.bytes, count)?,
        page_occurrences: mul(work.page_occurrences, count)?,
        records: mul(work.records, count)?,
    })
}

impl CatalogCapacityPolicy {
    pub fn plan(self) -> Result<CatalogCapacityPlan, CatalogError> {
        self.packing_profile
            .validate()
            .map_err(|_| CatalogError::InvalidPage)?;
        self.coding_profile
            .validate()
            .map_err(|_| CatalogError::InvalidPage)?;
        let private = self.private_work_per_revision;
        let width = u64::from(
            self.packing_profile
                .slots_per_sector()
                .map_err(|_| CatalogError::InvalidPage)?,
        );
        if self.format_version != 1
            || self.datasets == 0
            || self.revisions_per_dataset == 0
            || self.data_bytes_per_dataset == 0
            || self.data_bytes_per_dataset > 1 << 40
            || self.data_sources_per_dataset
                < self.data_bytes_per_dataset.div_ceil(V1_SECTOR_SIZE as u64)
            || self.data_sources_per_dataset > self.data_bytes_per_dataset
            || private.bytes < 16
            || private.page_occurrences < 2
            || private.records < ((private.bytes - 16) / 5).min(5 * CATALOG_MAX_RECORDS)
            || self.source_pages_per_revision == 0
            || add(private.page_occurrences, self.source_pages_per_revision)?
                > CATALOG_MAX_PAGE_OCCURRENCES
            || width < 2
            || self.packing_profile.sector_size as usize != V1_SECTOR_SIZE
            || self.coding_profile.shard_size != self.packing_profile.sector_size
            || self.authority_control_records < 257
        {
            return Err(CatalogError::Bounds);
        }
        let revisions = mul(u64::from(self.datasets), self.revisions_per_dataset)?;
        if self.legacy_revisions > revisions
            || self.legacy_source_occurrences < self.legacy_revisions
            || self.legacy_source_occurrences
                > mul(self.legacy_revisions, V1_MAX_CATALOG_BYTES as u64 / 65)?
        {
            return Err(CatalogError::Bounds);
        }
        let sources_per_revision = add(
            self.data_sources_per_dataset,
            add(private.page_occurrences, 1)?,
        )?;
        if sources_per_revision > CATALOG_MAX_RECORDS {
            return Err(CatalogError::Bounds);
        }
        // Every sector record has its existing 128-byte codec envelope and a
        // four-byte frame. Page layout/density is admitted independently.
        let source_work = CatalogCodingTraversalBudget {
            bytes: add(
                8,
                mul(sources_per_revision, 4 + CATALOG_SECTOR_RECORD_BYTES as u64)?,
            )?,
            page_occurrences: self.source_pages_per_revision,
            records: sources_per_revision,
        };
        if self.source_pages_per_revision < super::packing_directory::dense_pages(source_work.bytes)
        {
            return Err(CatalogError::Bounds);
        }
        if self.data_bytes_per_dataset == 1 << 40 {
            // Admit at least the required dense native file, including full
            // SectorRef scalar widths, fragment tails and the maximum path.
            // Private caps still bound other namespace/extent/Git workloads.
            let references = self.data_bytes_per_dataset.div_ceil(V1_SECTOR_SIZE as u64);
            let recipe_bytes = add(
                mul(references, 80)?,
                mul(references.div_ceil(CATALOG_FILE_SECTOR_REFS as u64), 4 + 32)?,
            )?;
            let dense_private_bytes = add(
                recipe_bytes,
                16 + 4 + CATALOG_FILE_RECORD_BYTES as u64 + 2 * (4 + 128),
            )?;
            if private.bytes < dense_private_bytes
                || private.page_occurrences
                    < super::coding_directory::dense_forest_pages(dense_private_bytes, 2)?
            {
                return Err(CatalogError::Bounds);
            }
        }
        if add(private.bytes, source_work.bytes)? > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds);
        }
        let revision_work =
            private
                .checked_add(source_work)?
                .checked_add(CatalogCodingTraversalBudget {
                    bytes: (PAGED_USER_REVISION_BYTES
                        + PAGED_PRIVATE_METADATA_BYTES
                        + V1_SECTOR_SIZE) as u64,
                    page_occurrences: 0,
                    records: 1,
                })?;
        let retained_revision_work = repeated(revision_work, revisions)?;
        // Unique data are capped over retained history. Metadata sources may
        // all differ in every revision; no sharing is assumed for that term.
        let retained_sources = add(
            add(
                mul(u64::from(self.datasets), self.data_sources_per_dataset)?,
                mul(revisions, add(private.page_occurrences, 1)?)?,
            )?,
            self.legacy_source_occurrences,
        )?;
        let minimum_dense_sectors = mul(retained_sources, width)?.div_ceil(width - 1);
        let minimum_dense_groups =
            minimum_dense_sectors.div_ceil(u64::from(self.coding_profile.data_shards));
        if self.packed_sectors < minimum_dense_sectors
            || self.coding_groups
                < self
                    .packed_sectors
                    .div_ceil(u64::from(self.coding_profile.data_shards))
        {
            return Err(CatalogError::Bounds);
        }
        let packing_coding = CatalogPackingCodingCapacity::for_counts(
            self.packing_profile,
            retained_sources,
            self.packed_sectors,
            self.coding_groups,
        )?;
        let authority_records = add(self.authority_control_records, revisions)?;
        let authority_bytes = add(
            8,
            mul(
                authority_records,
                4 + CATALOG_CHECKPOINT_RECORD_BYTES as u64,
            )?,
        )?;
        if authority_records > CATALOG_MAX_RECORDS || authority_bytes > CATALOG_MAX_STREAM_BYTES {
            return Err(CatalogError::Bounds);
        }
        // The authority byte tree may be non-dense, as may each preserved
        // legacy body. Retained source/body occurrences are charged separately
        // even when all underlying pages share the same content hash.
        let authority = CatalogCodingTraversalBudget {
            bytes: authority_bytes,
            page_occurrences: CATALOG_MAX_PAGE_OCCURRENCES,
            records: authority_records,
        };
        let mut legacy = repeated(
            CatalogCodingTraversalBudget {
                bytes: V1_MAX_CATALOG_BYTES as u64,
                page_occurrences: CATALOG_MAX_PAGE_OCCURRENCES,
                records: 0,
            },
            self.legacy_revisions,
        )?;
        legacy.records = self.legacy_source_occurrences;
        let public_work = authority
            .checked_add(repeated(source_work, revisions)?)?
            .checked_add(legacy)?
            .checked_add(packing_coding.work)?
            .checked_add(CatalogCodingTraversalBudget {
                bytes: PAGED_QUORUM_CHECKPOINT_BYTES as u64,
                page_occurrences: 0,
                records: 0,
            })?;
        let metadata_work = public_work
            .checked_add(repeated(private, revisions)?)?
            .checked_add(repeated(
                CatalogCodingTraversalBudget {
                    bytes: (PAGED_USER_REVISION_BYTES
                        + PAGED_PRIVATE_METADATA_BYTES
                        + V1_SECTOR_SIZE) as u64,
                    page_occurrences: 0,
                    records: 4,
                },
                revisions,
            )?)?;
        // Local custody can include all supported 64 roles of every original
        // group, including historical profiles, rather than only this profile's
        // current k+m. These are payload/record credits, not allocated blocks.
        let custody = CatalogCodingTraversalBudget {
            bytes: mul(
                self.coding_groups,
                add(
                    CATALOG_CODING_TRANSCRIPT_BYTES as u64 + 4096,
                    mul(64, crate::MAX_PROFILE_SHARD_SIZE as u64 + 3 * 512)?,
                )?,
            )?,
            page_occurrences: 0,
            records: mul(self.coding_groups, 64 * 3 + 1)?,
        };
        let job_work = metadata_work
            .checked_add(custody)?
            .checked_add(self.replay_work)?;
        if [job_work.bytes, job_work.page_occurrences, job_work.records]
            .into_iter()
            .any(|n| n > i64::MAX as u64)
        {
            return Err(CatalogError::Bounds);
        }
        Ok(CatalogCapacityPlan {
            revision_occurrences: revisions,
            sources_per_revision,
            retained_sources,
            minimum_dense_sectors,
            minimum_dense_groups,
            revision_work,
            retained_revision_work,
            public_work,
            metadata_work,
            job_work,
            packing_coding,
            encoded_metadata_page_bytes: mul(
                metadata_work.page_occurrences,
                CATALOG_PAGE_BYTES as u64,
            )?,
            source_ciphertext_bytes: mul(retained_sources, V1_SECTOR_SIZE as u64)?,
            packed_ciphertext_bytes: mul(
                self.packed_sectors,
                u64::from(self.packing_profile.sector_size),
            )?,
            parity_ciphertext_bytes: mul(
                mul(self.coding_groups, u64::from(crate::MAX_CODING_SHARDS - 1))?,
                u64::from(crate::MAX_PROFILE_SHARD_SIZE),
            )?,
        })
    }

    /// Check the fixed public/private root declarations before any page I/O.
    /// Exact EOF, data-purpose joins and unique-history ledgers remain required.
    pub fn admit_revision(
        self,
        revision: &PagedUserRevision,
        private: CatalogCodingTraversalBudget,
    ) -> Result<(), CatalogError> {
        let plan = self.plan()?;
        revision.validate()?;
        self.private_work_per_revision.check(private)?;
        if revision.sources.records.records > plan.sources_per_revision
            || revision.sources.records.page.page_occurrences > self.source_pages_per_revision
            || revision.sources.records.page.byte_len
                > add(8, mul(plan.sources_per_revision, 132)?)?
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }

    /// This bound applies to the complete guild certificate. Independent
    /// history, EOF, private/payload custody and atomic activation still apply.
    pub fn admit_checkpoint(
        self,
        checkpoint: crate::PagedGuildCheckpointDirectory,
    ) -> Result<(), CatalogError> {
        let plan = self.plan()?;
        checkpoint.validate_header(plan.public_work)?;
        self.admit_checkpoint_counts(
            checkpoint.authority_root,
            checkpoint.packing.profile,
            checkpoint.packing.summary.sources,
            checkpoint.packing.summary.sectors,
            checkpoint.coding,
        )
    }

    pub fn admit_individual_checkpoint(
        self,
        checkpoint: crate::PagedGuildCheckpoint,
    ) -> Result<(), CatalogError> {
        checkpoint.validate_header(self.plan()?.public_work)?;
        self.admit_checkpoint_counts(
            checkpoint.authority_root,
            checkpoint.packed_sources.profile,
            checkpoint.packed_sources.sources,
            checkpoint.packed_sectors.sectors,
            checkpoint.coding,
        )
    }

    fn admit_checkpoint_counts(
        self,
        authority: CatalogCheckpointAuthorityRoot,
        profile: PackingProfile,
        sources: u64,
        sectors: u64,
        coding: CatalogCodingDirectoryRoot,
    ) -> Result<(), CatalogError> {
        let plan = self.plan()?;
        let summary = authority.summary;
        let control_records = authority
            .records
            .records
            .checked_sub(summary.revisions)
            .ok_or(CatalogError::Bounds)?;
        if summary.revisions > plan.revision_occurrences
            || summary.legacy_revisions > self.legacy_revisions
            || summary.legacy_bytes > mul(self.legacy_revisions, V1_MAX_CATALOG_BYTES as u64)?
            || summary.legacy_pages > mul(self.legacy_revisions, CATALOG_MAX_PAGE_OCCURRENCES)?
            || control_records > self.authority_control_records
            || profile != self.packing_profile
            || sources > plan.retained_sources
            || sectors > self.packed_sectors
            || coding.summary.coding.groups > self.coding_groups
        {
            return Err(CatalogError::Bounds);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
