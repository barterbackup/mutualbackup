//! Complete sharded packing joins in one admitted disposable index. Every part
//! shares source uniqueness/coverage and the enclosing work budget. Durable
//! transitive ownership and checkpoint activation remain separate requirements.

use mb_core::{
    CatalogCodingTraversalBudget, CatalogPackedSectorRecord, CatalogPackedSourceId,
    CatalogPackedSourceRecord, CatalogPackingDirectoryReader, CatalogPackingDirectoryRoot,
    MerkleCommitment, SourceChunkId, canonical_bytes_bounded, canonical_size_bounded,
};

use super::packing_validation::{
    PackingStreamManifest, PackingStreams, ROOT_BYTES, build_streams, read_placement, read_sector,
    resolve_source, unwrap_stream,
};
use super::*;
use crate::RecordScratchStore;

pub(super) const COMPLETE: &str = "packing-directory-complete";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingDirectoryValidation {
    pub format_version: u16,
    pub scope: CatalogScope,
    pub directory: CatalogPackingDirectoryRoot,
}

impl CatalogPackingDirectoryValidation {
    fn envelope_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(CatalogCodingTraversalBudget {
            bytes: canonical_size_bounded(&self, ROOT_BYTES)? as u64,
            ..Default::default()
        })
    }

    pub fn represented_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(self.directory.work()?.checked_add(self.envelope_work()?)?)
    }

    pub fn validate(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogStoreError> {
        self.scope.validate(CatalogSection::Packing)?;
        if self.format_version != 1 {
            return Err(CatalogError::InvalidPage.into());
        }
        self.directory
            .validate(budget.remaining_after(self.envelope_work()?)?)?;
        Ok(())
    }

    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > ROOT_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate(budget)?;
        if canonical_bytes_bounded(&manifest, ROOT_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }
}

impl PackingStreams for CatalogPackingDirectoryReader {
    fn next_source(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<Option<CatalogPackedSourceRecord>, CatalogStoreError> {
        unwrap_stream(CatalogPackingDirectoryReader::next_source(self, fetch))
    }

    fn next_sector(
        &mut self,
        fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        resolve: &mut impl FnMut([u8; 32]) -> Result<CatalogPackedSourceId, CatalogStoreError>,
    ) -> Result<Option<CatalogPackedSectorRecord>, CatalogStoreError> {
        unwrap_stream(CatalogPackingDirectoryReader::next_sector(
            self, fetch, resolve,
        ))
    }

    fn verify_complete(&self) -> Result<(), CatalogStoreError> {
        if !self.is_complete() {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }
}

pub struct CatalogPackingDirectoryIndex {
    pub(super) manifest: CatalogPackingDirectoryValidation,
    pub(super) budget: CatalogCodingTraversalBudget,
    pub(super) store: RecordScratchStore,
}

impl CatalogPackingDirectoryIndex {
    /// Roots and source authority must be independently authenticated. Reserve
    /// all represented work before any page I/O; never reset uniqueness,
    /// missing-chunk accounting, scratch admission or authority at a boundary.
    pub fn build(
        manifest: CatalogPackingDirectoryValidation,
        budget: CatalogCodingTraversalBudget,
        store: RecordScratchStore,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(
            CatalogPackedSourceId,
            &MerkleCommitment,
        ) -> Result<(), CatalogStoreError>,
    ) -> Result<Self, CatalogStoreError> {
        store.with_record_transaction(|| {
            build_index(manifest, budget, &store, &mut fetch, &mut authorize)
        })?;
        Ok(Self {
            manifest,
            budget,
            store,
        })
    }

    pub fn manifest(&self) -> CatalogPackingDirectoryValidation {
        self.manifest
    }

    pub(super) fn require_complete(&self) -> Result<(), CatalogStoreError> {
        self.manifest.validate(self.budget)?;
        let expected = canonical_bytes_bounded(&self.manifest, ROOT_BYTES)?;
        if self
            .store
            .get_record_bounded(COMPLETE, b"root", ROOT_BYTES)?
            .as_deref()
            != Some(expected.as_slice())
        {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }

    pub fn placement(
        &self,
        source: SourceChunkId,
    ) -> Result<Option<CatalogPackingPlacement>, CatalogStoreError> {
        self.require_complete()?;
        read_placement(
            &self.store,
            self.manifest.directory.profile,
            self.manifest.directory.summary.sectors,
            source,
        )
    }

    pub fn sector(&self, id: [u8; 32]) -> Result<Option<CatalogPackingSector>, CatalogStoreError> {
        self.require_complete()?;
        self.sector_row(id)
    }

    pub(super) fn source_id(
        &self,
        key: [u8; 32],
    ) -> Result<CatalogPackedSourceId, CatalogStoreError> {
        self.require_complete()?;
        resolve_source(&self.store, self.manifest.directory.profile, key)
    }

    pub(super) fn sector_row(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogPackingSector>, CatalogStoreError> {
        read_sector(
            &self.store,
            self.manifest.directory.profile,
            self.manifest.directory.packing_version,
            self.manifest.directory.summary.sectors,
            id,
        )
    }
}

pub(super) fn build_index(
    manifest: CatalogPackingDirectoryValidation,
    budget: CatalogCodingTraversalBudget,
    store: &RecordScratchStore,
    fetch: &mut impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    authorize: &mut impl FnMut(
        CatalogPackedSourceId,
        &MerkleCommitment,
    ) -> Result<(), CatalogStoreError>,
) -> Result<(), CatalogStoreError> {
    manifest.validate(budget)?;
    let mut streams = CatalogPackingDirectoryReader::new(
        manifest.scope,
        manifest.directory,
        budget.remaining_after(manifest.envelope_work()?)?,
    )?;
    let completion = canonical_bytes_bounded(&manifest, ROOT_BYTES)?;
    build_streams(
        &mut streams,
        PackingStreamManifest {
            profile: manifest.directory.profile,
            chunks: manifest.directory.summary.source_chunks,
            complete_kind: COMPLETE,
            completion: &completion,
        },
        store,
        fetch,
        authorize,
    )
}

#[cfg(test)]
mod tests;
