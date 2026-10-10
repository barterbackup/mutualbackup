//! Private adapters for the two completed public checkpoint layouts. These
//! expose bounded indexed rows, never a flattened directory or signing token.

use super::*;
use crate::RecordScratchStore;
use mb_core::{
    CatalogCodingSummary, CatalogCodingTraversalBudget, PagedCheckpointTrust, PagedGuildCheckpoint,
    PagedGuildCheckpointDirectory,
};

pub(super) trait Header: Copy + Eq + Serialize {
    fn hash(self) -> Result<[u8; 32], ModelError>;
    fn work(self) -> Result<CatalogCodingTraversalBudget, CatalogError>;
    fn generation(self) -> u64;
    fn coding(self) -> CatalogCodingSummary;
    fn sectors(self) -> u64;
}

impl Header for PagedGuildCheckpoint {
    fn hash(self) -> Result<[u8; 32], ModelError> {
        self.hash()
    }
    fn work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        self.represented_work()
    }
    fn generation(self) -> u64 {
        self.generation
    }
    fn coding(self) -> CatalogCodingSummary {
        self.coding.summary.coding
    }
    fn sectors(self) -> u64 {
        self.packed_sectors.sectors
    }
}
impl Header for PagedGuildCheckpointDirectory {
    fn hash(self) -> Result<[u8; 32], ModelError> {
        self.hash()
    }
    fn work(self) -> Result<CatalogCodingTraversalBudget, CatalogError> {
        self.represented_work()
    }
    fn generation(self) -> u64 {
        self.generation
    }
    fn coding(self) -> CatalogCodingSummary {
        self.coding.summary.coding
    }
    fn sectors(self) -> u64 {
        self.packing.summary.sectors
    }
}

pub(super) trait Body {
    type Header: Header;
    fn header(&self, trust: &PagedCheckpointTrust) -> Result<Self::Header, CatalogStoreError>;
    fn authority(&self) -> CatalogCheckpointAuthorityValidation;
    fn store(&self) -> &RecordScratchStore;
    fn budget(&self) -> CatalogCodingTraversalBudget;
    fn group(
        &self,
        after: Option<[u8; 32]>,
    ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError>;
    fn sector(&self, id: [u8; 32]) -> Result<Option<CatalogPackingSector>, CatalogStoreError>;
    fn coverage(&self, id: [u8; 32]) -> Result<Option<CatalogCodingCoverage>, CatalogStoreError>;
}

macro_rules! rows {
    () => {
        fn authority(&self) -> CatalogCheckpointAuthorityValidation {
            self.authority()
        }
        fn store(&self) -> &RecordScratchStore {
            &self.index().packing().store
        }
        fn budget(&self) -> CatalogCodingTraversalBudget {
            self.index().budget()
        }
        fn group(
            &self,
            after: Option<[u8; 32]>,
        ) -> Result<Option<CatalogIndexedDirectoryCodingGroup>, CatalogStoreError> {
            self.index().next_group_row(after)
        }
        fn sector(&self, id: [u8; 32]) -> Result<Option<CatalogPackingSector>, CatalogStoreError> {
            self.index().packing().sector_row(id)
        }
        fn coverage(
            &self,
            id: [u8; 32],
        ) -> Result<Option<CatalogCodingCoverage>, CatalogStoreError> {
            self.index().coverage_row(id)
        }
    };
}
impl Body for CatalogCheckpointCodingDirectoryIndex {
    type Header = PagedGuildCheckpoint;
    fn header(&self, trust: &PagedCheckpointTrust) -> Result<Self::Header, CatalogStoreError> {
        self.header(trust)
    }
    rows!();
}
impl Body for CatalogCheckpointCodingDirectoriesIndex {
    type Header = PagedGuildCheckpointDirectory;
    fn header(&self, trust: &PagedCheckpointTrust) -> Result<Self::Header, CatalogStoreError> {
        self.header_candidate(trust)
    }
    rows!();
}
