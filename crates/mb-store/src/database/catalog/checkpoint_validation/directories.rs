//! Complete public authority, sharded packing and coding-directory joins.
//! These typed proofs do not authorize signing, transition or activation.

use super::*;
use mb_core::{
    PAGED_GUILD_CHECKPOINT_DIRECTORY_VERSION, PagedCheckpointTrust, PagedGuildCheckpointDirectory,
    canonical_bytes_bounded,
};

pub type CatalogCheckpointPackingDirectoryIndex =
    CatalogCheckpointPackingIndex<CatalogPackingDirectoryIndex>;
pub type CatalogCheckpointCodingDirectoriesIndex =
    CatalogCheckpointCodingDirectoryIndex<CatalogPackingCodingDirectoriesIndex>;

impl CatalogCheckpointAuthorityIndex {
    pub fn validate_packing_directory(
        self,
        manifest: CatalogPackingDirectoryValidation,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<CatalogCheckpointPackingDirectoryIndex, CatalogStoreError> {
        self.require_complete()?;
        if self.manifest.format_version != 2 {
            return Err(DatabaseError::Conflict.into());
        }
        let packing_budget = self.budget.remaining_after(self.work)?;
        manifest.validate(packing_budget)?;
        if manifest.scope != self.manifest.scope()
            || manifest.directory.summary.sources != self.source_count
        {
            return Err(DatabaseError::Conflict.into());
        }
        // Reserve the same fixed combined envelope used by the coding join,
        // as well as every represented packing occurrence, before page I/O.
        self.budget.remaining_after(
            self.work
                .checked_add(manifest.represented_work()?)?
                .checked_add(CatalogCodingTraversalBudget {
                    bytes: 4096,
                    ..Default::default()
                })?,
        )?;
        self.store.with_record_transaction(|| {
            super::super::packing_directory_validation::build_index(
                manifest,
                packing_budget,
                &self.store,
                &mut fetch,
                &mut |id, commitment| {
                    if source(&self.store, id)?.0.commitment.as_ref() != Some(commitment) {
                        return Err(DatabaseError::Conflict.into());
                    }
                    Ok(())
                },
            )
        })?;
        Ok(CatalogCheckpointPackingIndex {
            authority: self.manifest,
            authority_work: self.work,
            source_count: self.source_count,
            budget: self.budget,
            index: CatalogPackingDirectoryIndex {
                manifest,
                store: self.store,
                budget: packing_budget,
            },
        })
    }
}

impl CatalogCheckpointPackingDirectoryIndex {
    pub fn authority(&self) -> CatalogCheckpointAuthorityValidation {
        self.authority
    }
    pub fn packing(&self) -> &CatalogPackingDirectoryIndex {
        &self.index
    }
    pub fn validate_coding_directory(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(
            &mb_core::CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogCheckpointCodingDirectoriesIndex, CatalogStoreError> {
        require_authority(
            &self.index.store,
            self.authority,
            self.authority_work,
            self.source_count,
            self.budget,
        )?;
        if coding.guild_event_sequence != self.authority.context.event_sequence {
            return Err(DatabaseError::Conflict.into());
        }
        let index = self.index.validate_directory_with_prior(
            coding,
            policy,
            self.budget,
            self.authority_work,
            fetch,
            authorize,
        )?;
        Ok(CatalogCheckpointCodingDirectoryIndex {
            authority: self.authority,
            source_count: self.source_count,
            index,
        })
    }
}

impl CatalogCheckpointCodingDirectoriesIndex {
    pub fn authority(&self) -> CatalogCheckpointAuthorityValidation {
        self.authority
    }
    pub fn index(&self) -> &CatalogPackingCodingDirectoriesIndex {
        &self.index
    }
    pub(in crate::database::catalog) fn require_complete(&self) -> Result<(), CatalogStoreError> {
        self.index.require_complete()?;
        require_authority(
            &self.index.packing().store,
            self.authority,
            self.index.manifest().prior_work,
            self.source_count,
            self.index.budget(),
        )
    }
    pub fn next_revision(
        &self,
        after: Option<CatalogCheckpointRevisionKey>,
    ) -> Result<Option<CatalogCheckpointAuthorityRecord>, CatalogStoreError> {
        self.require_complete()?;
        next_revision(
            &self.index.packing().store,
            self.authority.context.guild_id,
            after,
        )
    }
    pub fn revision(
        &self,
        key: CatalogCheckpointRevisionKey,
    ) -> Result<Option<CatalogCheckpointAuthorityRecord>, CatalogStoreError> {
        self.require_complete()?;
        revision(
            &self.index.packing().store,
            self.authority.context.guild_id,
            key,
        )
    }

    /// Bind the completed public body to an independently supplied trust
    /// snapshot. This candidate does not prove certified coding state, legal
    /// original-history transition, payload custody or atomic activation.
    pub fn header_candidate(
        &self,
        trust: &PagedCheckpointTrust,
    ) -> Result<PagedGuildCheckpointDirectory, CatalogStoreError> {
        self.require_complete()?;
        trust.validate()?;
        let context = self.authority.context;
        if context.guild_id != trust.guild_id
            || context.generation != trust.next_generation()?
            || context.event_sequence != trust.event_sequence
            || context.event_head != trust.event_head
            || context.authority != trust.authority
            || self.authority.root.summary.members as usize != trust.members.len()
            || self.index.manifest().policy != CatalogCodingCoveragePolicy::Current
        {
            return Err(DatabaseError::Conflict.into());
        }
        require_members(&self.index.packing().store, &trust.members)?;
        let checkpoint = PagedGuildCheckpointDirectory {
            format_version: PAGED_GUILD_CHECKPOINT_DIRECTORY_VERSION,
            guild_id: trust.guild_id,
            genesis_hash: trust.genesis_hash,
            generation: context.generation,
            parent: trust.previous.map(|parent| parent.hash),
            event_sequence: context.event_sequence,
            event_head: context.event_head,
            authority: context.authority,
            authority_root: self.authority.root,
            authority_records: self.index.manifest().prior_work.records,
            packing: self.index.manifest().packing.directory,
            coding: self.index.manifest().coding,
        };
        checkpoint.validate_trust(trust, self.index.budget())?;
        Ok(checkpoint)
    }
}

pub(super) fn require_members(
    store: &RecordScratchStore,
    members: &[Member],
) -> Result<(), CatalogStoreError> {
    for member in members {
        let bytes = store
            .get_record_bounded(MEMBER_RECORDS, &member.node_id.0, MEMBER_BYTES)?
            .ok_or(DatabaseError::NotReady)?;
        let original: Member = decode_canonical(&bytes)?;
        if original != *member || canonical_bytes_bounded(&original, MEMBER_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
