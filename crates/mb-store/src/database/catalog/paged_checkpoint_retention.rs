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

mod layout;
pub(super) use layout::{Layout, Proof, require_layout, validate_owner};

pub(super) fn owned_certificate<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
) -> Result<H::Certificate, CatalogStoreError> {
    require_layout::<H>(connection, retention.id)?;
    let bytes = bounded_record(
        connection,
        H::CERTIFICATE,
        retention.id.as_bytes(),
        mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
    )?
    .ok_or(DatabaseError::Integrity)?;
    // The original envelope was quorum-verified by the required proof at
    // acquisition. Its decoder bounds all nested signatures; this exact local
    // readback is not a substitute for historical-trust checks at activation.
    let certificate: H::Certificate = decode_canonical(&bytes)?;
    let checkpoint = H::certificate_header(&certificate);
    checkpoint.validate(retention.budget)?;
    if checkpoint != retention.checkpoint
        || mb_core::canonical_bytes_bounded(&certificate, mb_core::PAGED_QUORUM_CHECKPOINT_BYTES)?
            != bytes
        || mb_core::canonical_hash_bounded(&certificate, mb_core::PAGED_QUORUM_CHECKPOINT_BYTES)?
            != retention.certificate_hash
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(certificate)
}

fn check_owned_root<H: Layout>(
    connection: &Connection,
    retention: CatalogPagedCheckpointRetention<H>,
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
        &journal::dependencies::<CatalogPagedCheckpointRetention<H>>(retention.id),
        &dependency.root.hash,
        RECORD_BYTES,
    )?
    .as_deref()
        != Some(expected.as_slice())
        || bounded_record(
            connection,
            &pins(dependency.root.hash),
            &journal::pin_id::<CatalogPagedCheckpointRetention<H>>(retention.id),
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
pub struct CatalogPagedCheckpointRetention<H = PagedGuildCheckpoint> {
    pub id: Uuid,
    pub checkpoint: H,
    pub certificate_hash: [u8; 32],
    pub trust_hash: [u8; 32],
    pub proof_work: Work,
    pub budget: Work,
}

pub use journal::CatalogRetentionState as CatalogPagedCheckpointRetentionState;
/// The same guarded custody operations with an exact format-ten header.
pub type CatalogPagedCheckpointDirectoryRetention =
    CatalogPagedCheckpointRetention<mb_core::PagedGuildCheckpointDirectory>;

fn scope<H: Layout>(retention: CatalogPagedCheckpointRetention<H>) -> CatalogScope {
    CatalogScope::Guild {
        guild_id: retention.checkpoint.guild_id(),
    }
}

impl<H: Layout> Retention for CatalogPagedCheckpointRetention<H> {
    const JOURNAL: &'static str = H::JOURNAL;
    const JOURNAL_BYTES: usize = 8192;
    const DEPENDENCIES: &'static str = H::DEPENDENCIES;
    const PIN_PREFIX: u8 = H::PIN_PREFIX;

    fn id(self) -> Uuid {
        self.id
    }
    fn validate(self) -> Result<(), CatalogStoreError> {
        if self.id.is_nil() || self.certificate_hash == [0; 32] || self.trust_hash == [0; 32] {
            return Err(DatabaseError::Conflict.into());
        }
        self.checkpoint.validate(self.budget)?;
        self.budget
            .remaining_after(self.proof_work.checked_add(self.checkpoint.work()?)?)?;
        Ok(())
    }
    fn work(self) -> Result<(u64, u64), CatalogStoreError> {
        let work = self.checkpoint.work()?;
        Ok((work.bytes, work.page_occurrences))
    }
    fn allows(self, scope: CatalogScope, section: CatalogSection) -> bool {
        matches!((scope, section),
            (CatalogScope::Guild { guild_id }, CatalogSection::Checkpoint | CatalogSection::Packing | CatalogSection::Coding)
            | (CatalogScope::Dataset { guild_id, .. }, CatalogSection::SectorReferences)
            if guild_id == self.checkpoint.guild_id())
    }
}

impl ControlStore {
    // Call only inside the short writer transaction. The independent reader
    // fences original event authority; the actual SQL head fences the base.
    pub(super) fn guard_paged_candidate<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
        read_trust: &mut impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        require_layout::<H>(&self.connection, retention.id)?;
        let trust = read_trust()?;
        if snapshot_hash(&trust)? != retention.trust_hash
            || self.checkpoint_head_identity(&retention.checkpoint.guild_id())?
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
    fn retain_paged_checkpoint<P: Proof>(
        &self,
        id: Uuid,
        proof: &P,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<CatalogPagedCheckpointRetention<P::Header>, CatalogStoreError> {
        let retention = proof.retention(id)?;
        proof.recheck(&mut read_trust)?;
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
                journal::read::<CatalogPagedCheckpointRetention<P::Header>>(&transaction, id)?
                    .is_some();
            if !existed {
                paged_checkpoint_revision::require_unowned(&transaction, id)?;
                paged_checkpoint_payload::require_unowned(&transaction, id)?;
            }
            let state = journal::begin(&transaction, retention)?;
            paged_checkpoint_revision::admitted_work(&transaction, retention)?;
            let stored = bounded_record(
                &transaction,
                <P::Header as Layout>::CERTIFICATE,
                id.as_bytes(),
                mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
            )?;
            match stored {
                Some(stored) if existed && stored == certificate_bytes => {}
                None if !existed => {
                    insert_exact(
                        &transaction,
                        <P::Header as Layout>::CERTIFICATE,
                        id.as_bytes(),
                        &certificate_bytes,
                    )?;
                    if bounded_record(
                        &transaction,
                        <P::Header as Layout>::CERTIFICATE,
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
            for dependency in retention.checkpoint.initial() {
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
                scope(retention),
                retention.checkpoint.authority_root(),
                retention.budget,
            )?;
            let mut fetch_authority =
                |page| self.catalog_page(scope(retention), CatalogSection::Checkpoint, page);
            while let Some(record) = unwrap_stream(authority.next_record(&mut fetch_authority))? {
                match record {
                    R::LegacyRevision(revision) => {
                        pin(Dependency {
                            scope: scope(retention),
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
                            retention.checkpoint.guild_id(),
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
            retention
                .checkpoint
                .walk_packing(self, proof, retention.budget, &mut pin)?;
            let mut coding = CatalogCodingDirectoryReader::new(
                scope(retention),
                retention.checkpoint.coding_root(),
                retention.budget,
            )?;
            let mut fetch_coding =
                |page| self.catalog_page(scope(retention), CatalogSection::Coding, page);
            let mut forest = |root: &mb_core::CatalogCodingRoot| {
                for part in &root.parts {
                    pin(Dependency {
                        scope: scope(retention),
                        section: CatalogSection::Coding,
                        root: part.page,
                    })?;
                }
                Ok::<_, CatalogStoreError>(())
            };
            while unwrap_stream(coding.next_group_with_forest(&mut fetch_coding, &mut forest))?
                .is_some()
            {}
            proof.recheck(&mut read_trust)?;
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

    fn paged_checkpoint_retention<H: Layout>(
        &self,
        id: Uuid,
    ) -> Result<
        Option<(
            CatalogPagedCheckpointRetention<H>,
            CatalogPagedCheckpointRetentionState,
        )>,
        CatalogStoreError,
    > {
        let Some(record) =
            journal::read::<CatalogPagedCheckpointRetention<H>>(&self.connection, id)?
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
            if self.record_length(H::CERTIFICATE, id.as_bytes())?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
        } else {
            owned_certificate(&self.connection, record.retention)?;
        }
        Ok(Some((record.retention, record.state)))
    }

    /// Original bounded certificate retained atomically with the owner's roots.
    /// A retired/unknown owner has none; missing/corrupt live evidence fails.
    fn paged_checkpoint_certificate<H: Layout>(
        &self,
        id: Uuid,
    ) -> Result<Option<H::Certificate>, CatalogStoreError> {
        let Some(record) =
            journal::read::<CatalogPagedCheckpointRetention<H>>(&self.connection, id)?
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
            if self.record_length(H::CERTIFICATE, id.as_bytes())?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(None);
        }
        owned_certificate(&self.connection, record.retention).map(Some)
    }

    pub(super) fn guard_paged_retirement<H: Layout>(
        &self,
        retention: CatalogPagedCheckpointRetention<H>,
    ) -> Result<(), CatalogStoreError> {
        require_layout::<H>(&self.connection, retention.id)?;
        let owned = retention.checkpoint.hash()?;
        if self
            .checkpoint_head_identity(&retention.checkpoint.guild_id())?
            .is_some_and(|(_, hash)| owned == hash)
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }

    /// Refuse cancellation of the actual current checkpoint. Each successor
    /// must finish its own complete dependency acquisition before activation.
    fn cancel_paged_checkpoint_retention<H: Layout>(
        &self,
        id: Uuid,
    ) -> Result<(), CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = journal::read::<CatalogPagedCheckpointRetention<H>>(&transaction, id)?
            .ok_or(DatabaseError::NotReady)?;
        self.guard_paged_retirement(record.retention)?;
        journal::cancel::<CatalogPagedCheckpointRetention<H>>(&transaction, id)?;
        self.guard_paged_retirement(record.retention)?;
        transaction.commit()?;
        Ok(())
    }

    /// Release at most one cancelled payload, private revision dependency or public
    /// root. Recheck the actual current head inside every writer transaction.
    fn release_paged_checkpoint_root<H: Layout>(
        &self,
        id: Uuid,
    ) -> Result<bool, CatalogStoreError> {
        let transaction =
            Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let record = journal::read::<CatalogPagedCheckpointRetention<H>>(&transaction, id)?
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
        let released = journal::release::<CatalogPagedCheckpointRetention<H>>(&transaction, id)?;
        if released
            && journal::read::<CatalogPagedCheckpointRetention<H>>(&transaction, id)?
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
                params![H::CERTIFICATE, id.as_bytes(), bytes],
            )? != 1
                || bounded_record(
                    &transaction,
                    H::CERTIFICATE,
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

macro_rules! custody_api {
    ($header:ty, $proof:ty, $cert:ty, $retain:ident, $read:ident, $certificate:ident, $cancel:ident, $release:ident) => {
        impl ControlStore {
            /// Retain the exact original-history-proven public certificate and
            /// every transitive root. This stages custody; activation still
            /// requires private/native/bootstrap and distributed payload joins.
            pub fn $retain(
                &self,
                id: Uuid,
                proof: &$proof,
                read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
            ) -> Result<CatalogPagedCheckpointRetention<$header>, CatalogStoreError> {
                self.retain_paged_checkpoint(id, proof, read_trust)
            }
            pub fn $read(
                &self,
                id: Uuid,
            ) -> Result<
                Option<(
                    CatalogPagedCheckpointRetention<$header>,
                    CatalogPagedCheckpointRetentionState,
                )>,
                CatalogStoreError,
            > {
                self.paged_checkpoint_retention::<$header>(id)
            }
            pub fn $certificate(&self, id: Uuid) -> Result<Option<$cert>, CatalogStoreError> {
                self.paged_checkpoint_certificate::<$header>(id)
            }
            /// The actual current checkpoint cannot be cancelled.
            pub fn $cancel(&self, id: Uuid) -> Result<(), CatalogStoreError> {
                self.cancel_paged_checkpoint_retention::<$header>(id)
            }
            /// Release at most one cancelled payload, private dependency or
            /// public root, checking the actual head in the same writer.
            pub fn $release(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
                self.release_paged_checkpoint_root::<$header>(id)
            }
        }
    };
}
custody_api!(
    PagedGuildCheckpoint,
    CatalogQuorumPagedCheckpointIndex,
    mb_core::QuorumPagedCheckpoint,
    retain_catalog_paged_checkpoint,
    catalog_paged_checkpoint_retention,
    catalog_paged_checkpoint_certificate,
    cancel_catalog_paged_checkpoint_retention,
    release_catalog_paged_checkpoint_root
);
custody_api!(
    mb_core::PagedGuildCheckpointDirectory,
    CatalogQuorumPagedCheckpointDirectoryIndex,
    mb_core::QuorumPagedCheckpointDirectory,
    retain_catalog_paged_checkpoint_directory,
    catalog_paged_checkpoint_directory_retention,
    catalog_paged_checkpoint_directory_certificate,
    cancel_catalog_paged_checkpoint_directory_retention,
    release_catalog_paged_checkpoint_directory_root
);

fn unwrap_error(error: mb_core::CatalogStreamError<CatalogStoreError>) -> CatalogStoreError {
    match error {
        mb_core::CatalogStreamError::Catalog(error) => error.into(),
        mb_core::CatalogStreamError::Storage(error) => error,
    }
}
