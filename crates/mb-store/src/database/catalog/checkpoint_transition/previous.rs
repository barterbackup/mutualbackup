//! Previous quorum proofs keep their original header and complete public
//! index; directory predecessors are never represented by invented flat roots.
use super::*;

#[derive(Clone, Copy)]
pub(super) enum PagedPrevious<'a> {
    Individual(&'a CatalogQuorumPagedCheckpointIndex),
    Directory(&'a CatalogQuorumPagedCheckpointDirectoryIndex),
}

macro_rules! fact {
    ($value:expr, $index:ident, $expression:expr) => {
        match $value {
            PagedPrevious::Individual($index) => $expression,
            PagedPrevious::Directory($index) => $expression,
        }
    };
}

impl<'a> PagedPrevious<'a> {
    pub(super) fn trust(self) -> &'a PagedCheckpointTrust {
        fact!(self, index, index.trust())
    }
    pub(super) fn store(self) -> &'a RecordScratchStore {
        fact!(self, index, index.index().store())
    }
    pub(super) fn counts(self) -> Counts {
        fact!(self, index, Counts::paged(index.index()))
    }
    pub(super) fn generation(self) -> u64 {
        fact!(self, index, index.certificate().checkpoint.generation)
    }
    pub(super) fn hash(self) -> Result<[u8; 32], CatalogStoreError> {
        Ok(fact!(self, index, index.certificate().checkpoint.hash())?)
    }
    pub(super) fn work(self) -> Result<Work, CatalogStoreError> {
        Ok(fact!(
            self,
            index,
            index.certificate().checkpoint.represented_work()
        )?)
    }
    pub(super) fn coding(self) -> mb_core::CatalogCodingSummary {
        fact!(
            self,
            index,
            index.certificate().checkpoint.coding.summary.coding
        )
    }
    pub(super) fn group(
        self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
        fact!(self, index, index.index().group(after))
    }
    pub(super) fn require_complete(self) -> Result<(), CatalogStoreError> {
        fact!(self, index, index.transition().require_complete())
    }
    pub(super) fn verify_certificate(self) -> Result<(), CatalogStoreError> {
        Ok(fact!(
            self,
            index,
            index
                .certificate()
                .verify_header(index.trust(), index.index().budget())
        )?)
    }
}
