//! Preserve the certified source bridge through both sharded directories.
use super::*;

impl CatalogPackingAuthority {
    /// Pay the exact imported source-authority debt before fetching any part.
    /// Complete ordered source cardinality binds all retained/candidate facts.
    pub fn validate_packing_directory(
        self,
        manifest: CatalogPackingDirectoryValidation,
        budget: CatalogCodingTraversalBudget,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<CatalogCertifiedPackingDirectoryIndex, CatalogStoreError> {
        let prior_work = CatalogCodingTraversalBudget {
            bytes: self.bytes,
            page_occurrences: self.pages,
            records: self.records,
        };
        let packing_budget = budget.remaining_after(prior_work)?;
        manifest.validate(packing_budget)?;
        if manifest.scope
            != (CatalogScope::Guild {
                guild_id: self.base.guild_id,
            })
            || manifest.directory.summary.sources != self.sources
            || self.authenticated != self.sources
        {
            return Err(DatabaseError::Conflict.into());
        }
        let source_identity = self.operation_identity()?;
        self.store.with_record_transaction(|| {
            super::super::packing_directory_validation::build_index(
                manifest,
                packing_budget,
                &self.store,
                &mut fetch,
                &mut |id, commitment| {
                    let (source, _) = source(&self.store, id)?;
                    if source.commitment.as_ref() != Some(commitment) {
                        return Err(DatabaseError::Conflict.into());
                    }
                    Ok(())
                },
            )
        })?;
        Ok(CatalogCertifiedPackingDirectoryIndex {
            source_identity,
            base: self.base,
            candidates: self.candidates,
            prior_work,
            index: CatalogPackingDirectoryIndex {
                manifest,
                store: self.store,
                budget: packing_budget,
            },
        })
    }
}

pub struct CatalogCertifiedPackingDirectoryIndex {
    source_identity: [u8; 32],
    base: CatalogPackingAuthorityBase,
    candidates: u64,
    prior_work: CatalogCodingTraversalBudget,
    index: CatalogPackingDirectoryIndex,
}

impl CatalogCertifiedPackingDirectoryIndex {
    pub fn operation_identity(&self) -> [u8; 32] {
        self.source_identity
    }
    pub fn require_complete(&self) -> Result<(), CatalogStoreError> {
        self.index.require_complete()
    }
    pub fn sector(&self, id: [u8; 32]) -> Result<Option<CatalogPackingSector>, CatalogStoreError> {
        self.index.sector(id)
    }
    pub(crate) fn operation_source_id(
        &self,
        key: [u8; 32],
    ) -> Result<mb_core::CatalogPackedSourceId, CatalogStoreError> {
        self.index.source_id(key)
    }
    pub fn base(&self) -> CatalogPackingAuthorityBase {
        self.base
    }
    pub fn candidate_count(&self) -> u64 {
        self.candidates
    }
    pub fn manifest(&self) -> CatalogPackingDirectoryValidation {
        self.index.manifest()
    }
    pub fn placement(
        &self,
        source: mb_core::SourceChunkId,
    ) -> Result<Option<CatalogPackingPlacement>, CatalogStoreError> {
        self.index.placement(source)
    }
    pub fn next_paged_revision(
        &self,
        after: Option<CatalogCheckpointRevisionKey>,
    ) -> Result<Option<SignedRecord<PagedUserRevision>>, CatalogStoreError> {
        self.index.require_complete()?;
        next_candidate_from_store(&self.index.store, after)
    }
    pub fn validate_coding_directory(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        budget: CatalogCodingTraversalBudget,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(
            &mb_core::CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogCertifiedCodingDirectoriesIndex, CatalogStoreError> {
        let index = self.index.validate_directory_with_prior(
            coding,
            policy,
            budget,
            self.prior_work,
            fetch,
            authorize,
        )?;
        Ok(CatalogCertifiedCodingDirectoriesIndex {
            base: self.base,
            candidates: self.candidates,
            index,
        })
    }
}

/// Complete source/coding proof with the original certified base and candidates.
/// Current event, full public/private and payload guards still gate activation.
pub struct CatalogCertifiedCodingDirectoriesIndex {
    base: CatalogPackingAuthorityBase,
    candidates: u64,
    index: CatalogPackingCodingDirectoriesIndex,
}

impl CatalogCertifiedCodingDirectoriesIndex {
    pub fn base(&self) -> CatalogPackingAuthorityBase {
        self.base
    }
    pub fn candidate_count(&self) -> u64 {
        self.candidates
    }
    pub fn index(&self) -> &CatalogPackingCodingDirectoriesIndex {
        &self.index
    }
    pub fn represented_work(&self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        self.index.manifest().validate(self.index.budget())?;
        self.index.manifest().represented_work()
    }
    pub fn next_paged_revision(
        &self,
        after: Option<CatalogCheckpointRevisionKey>,
    ) -> Result<Option<SignedRecord<PagedUserRevision>>, CatalogStoreError> {
        self.index.require_complete()?;
        next_candidate_from_store(&self.index.packing().store, after)
    }
}

#[cfg(test)]
mod tests;
