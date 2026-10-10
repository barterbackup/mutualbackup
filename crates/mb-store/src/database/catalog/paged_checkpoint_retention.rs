//! One guarded public metadata owner for an original-history-proven candidate.
//! This stages ownership; it does not publish a protected/current checkpoint.

use mb_core::{
    CatalogCheckpointAuthorityReader, CatalogCheckpointAuthorityRecord as R,
    CatalogCodingDirectoryReader, CatalogCodingTraversalBudget as Work, CatalogPackedSectorReader,
    CatalogPackedSourceReader, PagedCheckpointTrust, PagedGuildCheckpoint,
    PagedRevisionSourceReader, WriterFence,
};

use super::checkpoint_transition::snapshot_hash;
use super::packing_validation::unwrap_stream;
use super::retention_journal::{self as journal, Dependency, Retention};
use super::*;

const CERTIFICATE: &str = "catalog-paged-checkpoint-certificate-v1";

pub(super) fn owned_certificate(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention,
) -> Result<mb_core::QuorumPagedCheckpoint, CatalogStoreError> {
    let bytes = bounded_record(
        connection,
        CERTIFICATE,
        retention.id.as_bytes(),
        mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
    )?
    .ok_or(DatabaseError::Integrity)?;
    // The original envelope was quorum-verified by the required proof at
    // acquisition. Its decoder bounds all nested signatures; this exact local
    // readback is not a substitute for historical-trust checks at activation.
    let certificate: mb_core::QuorumPagedCheckpoint = decode_canonical(&bytes)?;
    certificate.checkpoint.validate_header(retention.budget)?;
    if certificate.checkpoint != retention.checkpoint
        || mb_core::canonical_bytes_bounded(&certificate, mb_core::PAGED_QUORUM_CHECKPOINT_BYTES)?
            != bytes
        || mb_core::canonical_hash_bounded(&certificate, mb_core::PAGED_QUORUM_CHECKPOINT_BYTES)?
            != retention.certificate_hash
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(certificate)
}

fn check_owned_root(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention,
    dependency: Dependency,
) -> Result<(), CatalogStoreError> {
    if journal::require(connection, retention)?.state
        != CatalogPagedCheckpointRetentionState::Published
    {
        return Err(DatabaseError::Conflict.into());
    }
    dependency.validate(retention)?;
    read_page(connection, dependency.page())?;
    let expected = canonical_bytes(&dependency)?;
    if bounded_record(
        connection,
        &journal::dependencies::<CatalogPagedCheckpointRetention>(retention.id),
        &dependency.root.hash,
        RECORD_BYTES,
    )?
    .as_deref()
        != Some(expected.as_slice())
        || bounded_record(
            connection,
            &pins(dependency.root.hash),
            &journal::pin_id::<CatalogPagedCheckpointRetention>(retention.id),
            0,
        )?
        .as_deref()
            != Some(&[])
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

/// All public roots and the exact original certificate/trust of a candidate.
/// The same completed proof is required to resume. Private metadata, native
/// anchors, bootstrap ciphertext and information/parity payloads need their
/// enclosing owners before activation. Cancellation permanently fences IDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPagedCheckpointRetention {
    pub id: Uuid,
    pub checkpoint: PagedGuildCheckpoint,
    pub certificate_hash: [u8; 32],
    pub trust_hash: [u8; 32],
    pub proof_work: Work,
    pub budget: Work,
}

pub use journal::CatalogRetentionState as CatalogPagedCheckpointRetentionState;

impl CatalogPagedCheckpointRetention {
    fn scope(self) -> CatalogScope {
        CatalogScope::Guild {
            guild_id: self.checkpoint.guild_id,
        }
    }
    fn initial(self) -> [Dependency; 4] {
        [
            (
                CatalogSection::Checkpoint,
                self.checkpoint.authority_root.records.page,
            ),
            (
                CatalogSection::Packing,
                self.checkpoint.packed_sectors.records.page,
            ),
            (
                CatalogSection::Packing,
                self.checkpoint.packed_sources.records.page,
            ),
            (CatalogSection::Coding, self.checkpoint.coding.records.page),
        ]
        .map(|(section, root)| Dependency {
            scope: self.scope(),
            section,
            root,
        })
    }
}

impl Retention for CatalogPagedCheckpointRetention {
    const JOURNAL: &'static str = "catalog-paged-checkpoint-retention-v1";
    const JOURNAL_BYTES: usize = 8192;
    const DEPENDENCIES: &'static str = "catalog-paged-checkpoint-dependency-v1";
    const PIN_PREFIX: u8 = 4;

    fn id(self) -> Uuid {
        self.id
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil() || self.certificate_hash == [0; 32] || self.trust_hash == [0; 32] {
            return Err(DatabaseError::Conflict.into());
        }
        self.checkpoint.validate_header(self.budget)?;
        self.budget.remaining_after(
            self.proof_work
                .checked_add(self.checkpoint.represented_work()?)?,
        )?;
        Ok(())
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        let work = self.checkpoint.represented_work()?;
        Ok((work.bytes, work.page_occurrences))
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        matches!((scope, section),
            (CatalogScope::Guild { guild_id }, CatalogSection::Checkpoint | CatalogSection::Packing | CatalogSection::Coding)
            | (CatalogScope::Dataset { guild_id, .. }, CatalogSection::SectorReferences)
            if guild_id == self.checkpoint.guild_id)
    }
}

impl ControlStore {
    // Call only inside the short writer transaction. The independent reader
    // fences original event authority; the actual SQL head fences the base.
    pub(super) fn guard_paged_candidate(
        &self,
        retention: CatalogPagedCheckpointRetention,
        read_trust: &mut impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let trust = read_trust()?;
        if snapshot_hash(&trust)? != retention.trust_hash
            || self.checkpoint_head_identity(&retention.checkpoint.guild_id)?
                != trust
                    .previous
                    .map(|parent| (parent.generation, parent.hash))
        {
            return Err(DatabaseError::Conflict.into());
        }
        retention
            .checkpoint
            .validate_trust(&trust, retention.budget)?;
        Ok(())
    }

    /// Acquire one owner for authority, both packing roots, the coding
    /// directory and every nested logical source/legacy/forest root. Requires
    /// the concrete original-history transition, exact bound quorum and full
    /// local typed EOF. Every pin/publication transaction checks independent
    /// event trust and the actual current predecessor. Traversal holds no writer.
    /// Published means public metadata retained, not checkpoint activation.
    pub fn retain_catalog_paged_checkpoint(
        &self,
        id: Uuid,
        proof: &CatalogQuorumPagedCheckpointIndex,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<CatalogPagedCheckpointRetention, CatalogStoreError> {
        if !proof.transition().has_certified_history_transition() {
            return Err(DatabaseError::NotReady.into());
        }
        proof.recheck_header(&mut read_trust)?;
        let retention = CatalogPagedCheckpointRetention {
            id,
            checkpoint: proof.certificate().checkpoint,
            certificate_hash: mb_core::canonical_hash_bounded(
                proof.certificate(),
                mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
            )?,
            trust_hash: snapshot_hash(proof.trust())?,
            proof_work: proof.transition().represented_work(),
            budget: proof.transition().budget(),
        };
        retention.validate()?;
        let certificate_bytes = mb_core::canonical_bytes_bounded(
            proof.certificate(),
            mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
        )?;
        let published;
        {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            self.guard_paged_candidate(retention, &mut read_trust)?;
            let existed =
                journal::read::<CatalogPagedCheckpointRetention>(&transaction, id)?.is_some();
            if !existed {
                paged_checkpoint_revision::require_unowned(&transaction, id)?;
                paged_checkpoint_payload::require_unowned(&transaction, id)?;
            }
            let state = journal::begin(&transaction, retention)?;
            paged_checkpoint_revision::admitted_work(&transaction, retention)?;
            let stored = bounded_record(
                &transaction,
                CERTIFICATE,
                id.as_bytes(),
                mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
            )?;
            match stored {
                Some(stored) if existed && stored == certificate_bytes => {}
                None if !existed => {
                    insert_exact(&transaction, CERTIFICATE, id.as_bytes(), &certificate_bytes)?;
                    if bounded_record(
                        &transaction,
                        CERTIFICATE,
                        id.as_bytes(),
                        mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
                    )?
                    .as_deref()
                        != Some(certificate_bytes.as_slice())
                    {
                        return Err(DatabaseError::Integrity.into());
                    }
                }
                _ => return Err(DatabaseError::Integrity.into()),
            }
            published = state == CatalogPagedCheckpointRetentionState::Published;
            for dependency in retention.initial() {
                if published {
                    check_owned_root(&transaction, retention, dependency)?;
                } else {
                    journal::retain(&transaction, retention, dependency)?;
                }
            }
            self.guard_paged_candidate(retention, &mut read_trust)?;
            transaction.commit()?;
        }
        let result = (|| {
            let mut pin = |dependency: Dependency| -> Result<(), CatalogStoreError> {
                let transaction =
                    Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
                self.guard_paged_candidate(retention, &mut read_trust)?;
                if published {
                    check_owned_root(&transaction, retention, dependency)?;
                } else {
                    journal::retain(&transaction, retention, dependency)?;
                }
                self.guard_paged_candidate(retention, &mut read_trust)?;
                transaction.commit()?;
                Ok(())
            };
            let mut authority = CatalogCheckpointAuthorityReader::new_with_budget(
                retention.scope(),
                retention.checkpoint.authority_root,
                retention.budget,
            )?;
            let mut fetch_authority =
                |page| self.catalog_page(retention.scope(), CatalogSection::Checkpoint, page);
            while let Some(record) = unwrap_stream(authority.next_record(&mut fetch_authority))? {
                match record {
                    R::LegacyRevision(revision) => {
                        pin(Dependency {
                            scope: retention.scope(),
                            section: CatalogSection::Checkpoint,
                            root: revision.body,
                        })?;
                        revision
                            .read_signed(&mut fetch_authority)
                            .map_err(unwrap_error)?;
                    }
                    R::PagedRevision(revision) => {
                        let body = &revision.value;
                        let scope = body.scope();
                        pin(Dependency {
                            scope,
                            section: CatalogSection::SectorReferences,
                            root: body.sources.records.page,
                        })?;
                        let fence = WriterFence {
                            owner: body.owner,
                            epoch: body.writer_epoch,
                            public_key: body.writer_public_key,
                        };
                        let mut sources = PagedRevisionSourceReader::new(
                            &revision,
                            retention.checkpoint.guild_id,
                            body.owner,
                            &fence,
                        )?;
                        let mut fetch =
                            |page| self.catalog_page(scope, CatalogSection::SectorReferences, page);
                        while unwrap_stream(sources.next_sector(&mut fetch))?.is_some() {}
                    }
                    _ => {}
                }
            }
            let mut fetch_packing =
                |page| self.catalog_page(retention.scope(), CatalogSection::Packing, page);
            let mut sources = CatalogPackedSourceReader::new(
                retention.scope(),
                retention.checkpoint.packed_sources,
            )?;
            while unwrap_stream(sources.next_record(&mut fetch_packing))?.is_some() {}
            let mut sectors = CatalogPackedSectorReader::new(
                retention.scope(),
                retention.checkpoint.packed_sectors,
            )?;
            while unwrap_stream(
                sectors.next_record_with_sources(&mut fetch_packing, &mut |key| {
                    proof.index().index().packing().source_id(key)
                }),
            )?
            .is_some()
            {}
            let mut coding = CatalogCodingDirectoryReader::new(
                retention.scope(),
                retention.checkpoint.coding,
                retention.budget,
            )?;
            let mut fetch_coding =
                |page| self.catalog_page(retention.scope(), CatalogSection::Coding, page);
            let mut forest = |root: &mb_core::CatalogCodingRoot| {
                for part in &root.parts {
                    pin(Dependency {
                        scope: retention.scope(),
                        section: CatalogSection::Coding,
                        root: part.page,
                    })?;
                }
                Ok::<_, CatalogStoreError>(())
            };
            while unwrap_stream(coding.next_group_with_forest(&mut fetch_coding, &mut forest))?
                .is_some()
            {}
            proof.recheck_header(&mut read_trust)?;
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            self.guard_paged_candidate(retention, &mut read_trust)?;
            owned_certificate(&transaction, retention)?;
            paged_checkpoint_revision::admitted_work(&transaction, retention)?;
            if published {
                if journal::require(&transaction, retention)?.state
                    != CatalogPagedCheckpointRetentionState::Published
                {
                    return Err(DatabaseError::Conflict.into());
                }
            } else {
                journal::publish(&transaction, retention)?;
            }
            owned_certificate(&transaction, retention)?;
            self.guard_paged_candidate(retention, &mut read_trust)?;
            transaction.commit()?;
            Ok(retention)
        })();
        if result.is_err() {
            let transaction =
                Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
            journal::cancel_building(&transaction, retention)?;
            transaction.commit()?;
        }
        result
    }

    pub fn catalog_paged_checkpoint_retention(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(
            CatalogPagedCheckpointRetention,
            CatalogPagedCheckpointRetentionState,
        )>,
        CatalogStoreError,
    > {
        let Some(record) = journal::read::<CatalogPagedCheckpointRetention>(&self.connection, id)?
        else {
            return Ok(None);
        };
        paged_checkpoint_revision::admitted_work(&self.connection, record.retention)?;
        if record.state == CatalogPagedCheckpointRetentionState::Cancelled && record.roots == 0 {
            if paged_checkpoint_payload::admitted_work(&self.connection, record.retention)?
                .is_some_and(|work| work.records != 0)
            {
                return Err(DatabaseError::Integrity.into());
            }
            if paged_checkpoint_revision::has_dependencies(&self.connection, id)? {
                return Err(DatabaseError::Integrity.into());
            }
            if self.record_length(CERTIFICATE, id.as_bytes())?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
        } else {
            owned_certificate(&self.connection, record.retention)?;
        }
        Ok(Some((record.retention, record.state)))
    }

    /// Original bounded certificate retained atomically with the owner's roots.
    /// A retired/unknown owner has none; missing/corrupt live evidence fails.
    pub fn catalog_paged_checkpoint_certificate(
        &self,
        id: Uuid,
    ) -> Result<Option<mb_core::QuorumPagedCheckpoint>, CatalogStoreError> {
        let Some(record) = journal::read::<CatalogPagedCheckpointRetention>(&self.connection, id)?
        else {
            return Ok(None);
        };
        paged_checkpoint_revision::admitted_work(&self.connection, record.retention)?;
        if record.state == CatalogPagedCheckpointRetentionState::Cancelled && record.roots == 0 {
            if paged_checkpoint_payload::admitted_work(&self.connection, record.retention)?
                .is_some_and(|work| work.records != 0)
            {
                return Err(DatabaseError::Integrity.into());
            }
            if paged_checkpoint_revision::has_dependencies(&self.connection, id)? {
                return Err(DatabaseError::Integrity.into());
            }
            if self.record_length(CERTIFICATE, id.as_bytes())?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(None);
        }
        owned_certificate(&self.connection, record.retention).map(Some)
    }

    pub(super) fn guard_paged_retirement(
        &self,
        retention: CatalogPagedCheckpointRetention,
    ) -> Result<(), CatalogStoreError> {
        let owned = retention.checkpoint.hash()?;
        if self
            .checkpoint_head_identity(&retention.checkpoint.guild_id)?
            .is_some_and(|(_, hash)| owned == hash)
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    /// Refuse cancellation of the actual current checkpoint. Each successor
    /// must finish its own complete dependency acquisition before activation.
    pub fn cancel_catalog_paged_checkpoint_retention(
        &self,
        id: Uuid,
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = journal::read::<CatalogPagedCheckpointRetention>(&transaction, id)?
            .ok_or(DatabaseError::NotReady)?;
        self.guard_paged_retirement(record.retention)?;
        journal::cancel::<CatalogPagedCheckpointRetention>(&transaction, id)?;
        self.guard_paged_retirement(record.retention)?;
        transaction.commit()?;
        Ok(())
    }

    /// Release at most one cancelled payload, private revision dependency or public
    /// root. Recheck the actual current head inside every writer transaction.
    pub fn release_catalog_paged_checkpoint_root(
        &self,
        id: Uuid,
    ) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = journal::read::<CatalogPagedCheckpointRetention>(&transaction, id)?
            .ok_or(DatabaseError::NotReady)?;
        self.guard_paged_retirement(record.retention)?;
        if paged_checkpoint_payload::release(&transaction, record.retention)? {
            self.guard_paged_retirement(record.retention)?;
            transaction.commit()?;
            return Ok(true);
        }
        if paged_checkpoint_revision::release(&transaction, record.retention)? {
            self.guard_paged_retirement(record.retention)?;
            transaction.commit()?;
            return Ok(true);
        }
        let released = journal::release::<CatalogPagedCheckpointRetention>(&transaction, id)?;
        if released
            && journal::read::<CatalogPagedCheckpointRetention>(&transaction, id)?
                .ok_or(DatabaseError::NotReady)?
                .roots
                == 0
        {
            if paged_checkpoint_revision::admitted_work(&transaction, record.retention)?
                .is_some_and(|work| work.records != 0)
                || paged_checkpoint_payload::admitted_work(&transaction, record.retention)?
                    .is_some_and(|work| work.records != 0)
            {
                return Err(DatabaseError::Integrity.into());
            }
            let certificate = owned_certificate(&transaction, record.retention)?;
            let bytes = mb_core::canonical_bytes_bounded(
                &certificate,
                mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
            )?;
            if transaction.execute(
                "DELETE FROM protocol_records WHERE kind = ?1 AND record_id = ?2 AND bytes = ?3",
                params![CERTIFICATE, id.as_bytes(), bytes],
            )? != 1
                || bounded_record(
                    &transaction,
                    CERTIFICATE,
                    id.as_bytes(),
                    mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
                )?
                .is_some()
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        self.guard_paged_retirement(record.retention)?;
        transaction.commit()?;
        Ok(released)
    }
}

fn unwrap_error(error: mb_core::CatalogStreamError<CatalogStoreError>) -> CatalogStoreError {
    match error {
        mb_core::CatalogStreamError::Catalog(error) => error.into(),
        mb_core::CatalogStreamError::Storage(error) => error,
    }
}
