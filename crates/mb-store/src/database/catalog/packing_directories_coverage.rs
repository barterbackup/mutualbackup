//! Complete joins between sharded packing and original coding directories.
//! External certified authority and physical admission remain mandatory.

use mb_core::{
    CatalogCodingDirectoryReader, CatalogCodingDirectoryRoot, CatalogCodingEntry,
    CatalogCodingTraversalBudget, canonical_bytes_bounded,
};

use super::coding_coverage::{
    MANIFEST_BYTES, ROW_BYTES, cover_entry_with_sector, ensure_empty_store, put,
};
use super::coding_directory_coverage::{COVERAGE, DirectoryCoverageRows, GROUPS};
use super::packing_validation::unwrap_stream;
use super::*;

const COMPLETE: &str = "packing-coding-directories-complete";
pub(super) const KINDS: [&str; 1] = [COMPLETE];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingCodingDirectoriesValidation {
    pub format_version: u16,
    pub packing: CatalogPackingDirectoryValidation,
    pub coding: CatalogCodingDirectoryRoot,
    pub policy: CatalogCodingCoveragePolicy,
    pub prior_work: CatalogCodingTraversalBudget,
}

impl CatalogPackingCodingDirectoriesValidation {
    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > MANIFEST_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate(budget)?;
        if canonical_bytes_bounded(&manifest, MANIFEST_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }

    pub fn validate(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogStoreError> {
        if self.format_version != 1 {
            return Err(DatabaseError::Conflict.into());
        }
        canonical_bytes_bounded(&self, MANIFEST_BYTES)?;
        self.packing.validate(self.packing_budget(budget)?)?;
        self.coding.validate(self.coding_budget(budget)?)?;
        Ok(())
    }

    fn envelope(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        // Keep a conservative fixed combined envelope in addition to each
        // directory's independent root reservation. Never reset prior debt.
        Ok(self.prior_work.checked_add(CatalogCodingTraversalBudget {
            bytes: MANIFEST_BYTES as u64,
            ..Default::default()
        })?)
    }

    pub fn represented_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(self
            .envelope()?
            .checked_add(self.packing.represented_work()?)?
            .checked_add(self.coding.work()?)?)
    }

    pub fn packing_budget(
        self,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(budget.remaining_after(self.envelope()?.checked_add(self.coding.work()?)?)?)
    }

    pub fn coding_budget(
        self,
        budget: CatalogCodingTraversalBudget,
    ) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(budget.remaining_after(
            self.envelope()?
                .checked_add(self.packing.represented_work()?)?,
        )?)
    }
}

pub struct CatalogPackingCodingDirectoriesIndex {
    packing: CatalogPackingDirectoryIndex,
    manifest: CatalogPackingCodingDirectoriesValidation,
    budget: CatalogCodingTraversalBudget,
}

impl CatalogPackingDirectoryIndex {
    pub fn validate_coding_directory(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        budget: CatalogCodingTraversalBudget,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(
            &CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogPackingCodingDirectoriesIndex, CatalogStoreError> {
        self.validate_directory_with_prior(
            coding,
            policy,
            budget,
            Default::default(),
            fetch,
            authorize,
        )
    }

    pub(super) fn validate_directory_with_prior(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        budget: CatalogCodingTraversalBudget,
        prior_work: CatalogCodingTraversalBudget,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(
            &CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogPackingCodingDirectoriesIndex, CatalogStoreError> {
        let manifest = CatalogPackingCodingDirectoriesValidation {
            format_version: 1,
            packing: self.manifest,
            coding,
            policy,
            prior_work,
        };
        self.store.with_record_transaction(|| {
            build(&self, manifest, budget, &mut fetch, &mut authorize)
        })?;
        Ok(CatalogPackingCodingDirectoriesIndex {
            packing: self,
            manifest,
            budget,
        })
    }
}

pub(super) fn build(
    packing: &CatalogPackingDirectoryIndex,
    manifest: CatalogPackingCodingDirectoriesValidation,
    budget: CatalogCodingTraversalBudget,
    fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    authorize: &mut impl FnMut(
        &CatalogCodingEntry,
    ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    packing.require_complete()?;
    manifest.validate(budget)?;
    if packing.manifest != manifest.packing {
        return Err(DatabaseError::Conflict.into());
    }
    ensure_empty_store(&packing.store)?;
    let mut pending = manifest.packing.directory.summary.sectors;
    let mut reader = CatalogCodingDirectoryReader::new(
        manifest.packing.scope,
        manifest.coding,
        manifest.coding_budget(budget)?,
    )?;
    while let Some(entry) = unwrap_stream(reader.next_group(fetch))? {
        let authority = authorize(&entry)?;
        let group = &entry.retained.group;
        let location = reader
            .last_group_location()
            .ok_or(DatabaseError::Integrity)?;
        put(
            &packing.store,
            GROUPS,
            &group.id,
            &CatalogIndexedDirectoryCodingGroup {
                group: CatalogIndexedCodingGroup {
                    profile: group.profile,
                    range: location.range,
                    added_at_event: entry.retained.added_at_event,
                    retired_at_event: entry.retained.retired_at_event,
                    retain_through_event: entry.retained.retain_through_event,
                },
                page: location.page,
            },
            ROW_BYTES,
        )?;
        cover_entry_with_sector(
            &packing.store,
            &mut |id| packing.sector(id),
            &entry,
            authority,
            manifest.policy,
            COVERAGE,
            &mut pending,
        )?;
    }
    if pending != 0 {
        return Err(DatabaseError::NotReady.into());
    }
    put(&packing.store, COMPLETE, b"root", &manifest, MANIFEST_BYTES)
}

impl CatalogPackingCodingDirectoriesIndex {
    pub fn manifest(&self) -> CatalogPackingCodingDirectoriesValidation {
        self.manifest
    }
    pub fn packing(&self) -> &CatalogPackingDirectoryIndex {
        &self.packing
    }
    pub fn budget(&self) -> CatalogCodingTraversalBudget {
        self.budget
    }

    pub(super) fn require_complete(&self) -> Result<(), CatalogStoreError> {
        self.packing.require_complete()?;
        self.manifest.validate(self.budget)?;
        let expected = canonical_bytes_bounded(&self.manifest, MANIFEST_BYTES)?;
        if self
            .packing
            .store
            .get_record_bounded(COMPLETE, b"root", MANIFEST_BYTES)?
            .as_deref()
            != Some(expected.as_slice())
        {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }

    fn rows(&self) -> Result<DirectoryCoverageRows<'_>, CatalogStoreError> {
        Ok(DirectoryCoverageRows {
            store: &self.packing.store,
            scope: self.manifest.packing.scope,
            root: self.manifest.coding,
            budget: self.manifest.coding_budget(self.budget)?,
            profile: self.manifest.packing.directory.profile,
            version: self.manifest.packing.directory.packing_version,
            sectors: self.manifest.packing.directory.summary.sectors,
        })
    }

    pub fn coverage(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogCodingCoverage>, CatalogStoreError> {
        self.require_complete()?;
        self.rows()?.coverage_row(id)
    }
    pub(super) fn coverage_row(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogCodingCoverage>, CatalogStoreError> {
        self.rows()?.coverage_row(id)
    }
    pub(super) fn next_group_row(
        &self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
        self.rows()?.next_group_row(after)
    }
    pub fn next_group(
        &self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
        self.require_complete()?;
        self.rows()?.next_group_row(after)
    }
    pub fn read_group(
        &self,
        id: [u8; 32],
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<Option<CatalogCodingEntry>, CatalogStoreError> {
        self.read_group_with_work(id, fetch)
            .map(|entry| entry.map(|(entry, _)| entry))
    }
    pub fn read_group_with_work(
        &self,
        id: [u8; 32],
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<Option<(CatalogCodingEntry, CatalogCodingTraversalBudget)>, CatalogStoreError> {
        self.require_complete()?;
        self.rows()?.read_group_with_work(id, fetch)
    }
}

#[cfg(test)]
pub(super) mod tests;
