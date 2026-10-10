//! Source authority for a packing proposal based on an already trusted legacy
//! certificate. This is a migration bridge, not a paged checkpoint certificate
//! or revision activation: private joins, retention policy, coding receipts and
//! publication against the unchanged certified base and current guild-event
//! membership/writer fences remain separate gates.

use mb_core::{
    CATALOG_MAX_RECORDS, CATALOG_MAX_STREAM_BYTES, CatalogCheckpointRevisionKey,
    CatalogCodingDirectoryRoot, CatalogCodingTraversalBudget, CatalogPackedSourceId,
    LEGACY_PACKING_ATTESTATION_DOMAIN, LEGACY_PACKING_BINDING_DOMAIN, LegacyPackingAttestation,
    LegacyPackingBinding, MerkleCommitment, NodeId, PAGED_USER_REVISION_BYTES,
    PagedRevisionSourceReader, PagedUserRevision, QuorumCheckpoint, SignedRecord,
    V1_MAX_CATALOG_BYTES, V1_SECTOR_SIZE, WriterFence, canonical_bytes_bounded,
    canonical_size_bounded, packing_protected_root,
};

use super::packing_validation::{build_index, unwrap_stream};
use super::*;
use crate::RecordScratchStore;

pub(super) const ROW_BYTES: usize = 256;
pub(super) const EVIDENCE_BYTES: usize = 512;
pub(super) const MEMBERS: &str = "packing-authority-member";
pub(super) const FENCES: &str = "packing-authority-fence";
pub(super) const HEADS: &str = "packing-authority-head";
pub(super) const IDS: &str = "packing-authority-revision-id";
pub(super) const SOURCES: &str = "packing-authority-source";
const CANDIDATES: &str = "packing-authority-candidate";
pub(super) const BINDINGS: &str = "packing-authority-binding";
pub(super) const ATTESTATIONS: &str = "packing-authority-attestation";
pub(super) const TALLIES: &str = "packing-authority-tally";
pub(super) const KINDS: [&str; 9] = [
    MEMBERS,
    FENCES,
    HEADS,
    IDS,
    SOURCES,
    CANDIDATES,
    BINDINGS,
    ATTESTATIONS,
    TALLIES,
];

/// The expected hash is supplied by the caller's established checkpoint trust
/// chain, never learned from the same untrusted certificate being imported.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogPackingAuthorityBase {
    pub guild_id: [u8; 32],
    pub checkpoint_hash: [u8; 32],
    pub generation: u64,
    pub membership_epoch: Option<u64>,
}

/// One complete source in owner/root/object order, suitable for bounded
/// packing input traversal. Payload verification remains the producer's job.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CatalogPackingAuthorizedSource {
    pub id: CatalogPackedSourceId,
    pub flat_root: [u8; 32],
    pub commitment: MerkleCommitment,
}

pub(super) fn source_key(id: CatalogPackedSourceId) -> [u8; 96] {
    let mut key = [0; 96];
    key[..32].copy_from_slice(&id.owner.0);
    key[32..64].copy_from_slice(&id.protected_root);
    key[64..].copy_from_slice(&id.object_id);
    key
}

#[derive(Serialize, Deserialize)]
pub(super) struct Source {
    pub(super) id: CatalogPackedSourceId,
    pub(super) flat_root: [u8; 32],
    pub(super) commitment: Option<MerkleCommitment>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Head {
    pub(super) sequence: u64,
    pub(super) hash: [u8; 32],
    pub(super) writer_epoch: u64,
}

#[derive(Serialize, Deserialize)]
pub(super) struct Tally {
    pub(super) commitment: MerkleCommitment,
    pub(super) signers: u16,
}

pub(super) fn encoded<T: Serialize>(value: &T, limit: usize) -> Result<Vec<u8>, CatalogStoreError> {
    Ok(canonical_bytes_bounded(value, limit)?)
}

pub(super) fn insert<T: Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
    value: &T,
    limit: usize,
) -> Result<(), CatalogStoreError> {
    let bytes = encoded(value, limit)?;
    if !store.put_record_if_absent(kind, key, &bytes)?
        || store.get_record_bounded(kind, key, limit)?.as_deref() != Some(&bytes)
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

pub(super) fn read<T: serde::de::DeserializeOwned + Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
) -> Result<Option<(T, Vec<u8>)>, CatalogStoreError> {
    let Some(bytes) = store.get_record_bounded(kind, key, ROW_BYTES)? else {
        return Ok(None);
    };
    let value = decode_canonical(&bytes)?;
    if encoded(&value, ROW_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some((value, bytes)))
}

pub(super) fn replace<T: Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
    previous: &[u8],
    value: &T,
) -> Result<(), CatalogStoreError> {
    let bytes = encoded(value, ROW_BYTES)?;
    store.replace_record_if_value(kind, key, previous, &bytes)?;
    if store.get_record_bounded(kind, key, ROW_BYTES)?.as_deref() != Some(&bytes) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn source(
    store: &RecordScratchStore,
    id: CatalogPackedSourceId,
) -> Result<(Source, Vec<u8>), CatalogStoreError> {
    let (source, bytes) =
        read::<Source>(store, SOURCES, &source_key(id))?.ok_or(DatabaseError::NotReady)?;
    if source.id != id {
        return Err(DatabaseError::Integrity.into());
    }
    Ok((source, bytes))
}

pub(super) fn add_source(
    store: &RecordScratchStore,
    id: CatalogPackedSourceId,
    flat_root: [u8; 32],
    commitment: Option<MerkleCommitment>,
) -> Result<(u64, u64), CatalogStoreError> {
    if let Some(commitment) = &commitment
        && (commitment.byte_len as usize != V1_SECTOR_SIZE || commitment.validate().is_err())
    {
        return Err(CatalogError::InvalidPage.into());
    }
    if let Some((previous, bytes)) = read::<Source>(store, SOURCES, &source_key(id))? {
        if previous.id != id
            || previous.flat_root != flat_root
            || previous
                .commitment
                .as_ref()
                .zip(commitment.as_ref())
                .is_some_and(|(a, b)| a != b)
        {
            return Err(DatabaseError::Conflict.into());
        }
        if previous.commitment.is_none() && commitment.is_some() {
            replace(
                store,
                SOURCES,
                &source_key(id),
                &bytes,
                &Source {
                    id,
                    flat_root,
                    commitment,
                },
            )?;
            return Ok((0, 1));
        }
        return Ok((0, 0));
    }
    let authenticated = u64::from(commitment.is_some());
    insert(
        store,
        SOURCES,
        &source_key(id),
        &Source {
            id,
            flat_root,
            commitment,
        },
        ROW_BYTES,
    )?;
    Ok((1, authenticated))
}

pub(super) fn chain(owner: NodeId, root: Uuid) -> [u8; 48] {
    let mut key = [0; 48];
    key[..32].copy_from_slice(&owner.0);
    key[32..].copy_from_slice(root.as_bytes());
    key
}

/// Owns one admitted encrypted scratch store. Mutation methods consume the job:
/// any error discards its private prefix, including partial source traversal.
/// Rebuild from the trusted certificate after cancellation or storage failure.
pub struct CatalogPackingAuthority {
    base: CatalogPackingAuthorityBase,
    store: RecordScratchStore,
    required_signers: usize,
    sources: u64,
    authenticated: u64,
    candidates: u64,
    bytes: u64,
    pages: u64,
    // One record per bounded signed envelope/evidence object, plus every
    // framed paged-source occurrence (including repeated referenced trees).
    records: u64,
}

impl CatalogPackingAuthority {
    /// Legacy certificates are decoded and verified by the existing bounded
    /// legacy path. This constructor intentionally does not make that flat
    /// verifier a scalable paged checkpoint consumer.
    pub fn from_legacy_checkpoint(
        trusted_hash: [u8; 32],
        certificate: &QuorumCheckpoint,
        store: RecordScratchStore,
    ) -> Result<Self, CatalogStoreError> {
        let legacy_bytes = canonical_size_bounded(certificate, V1_MAX_CATALOG_BYTES)? as u64;
        if trusted_hash == [0; 32] || certificate.hash()? != trusted_hash {
            return Err(DatabaseError::Conflict.into());
        }
        certificate.verify()?;
        let checkpoint = &certificate.checkpoint;
        let (membership_epoch, required_signers) = match checkpoint.authority {
            Some(authority) => (
                Some(authority.membership_epoch),
                authority
                    .quorum
                    .required(checkpoint.members.len())
                    .map_err(|_| ModelError::InvalidCheckpoint)?,
            ),
            None => (None, checkpoint.members.len()),
        };
        let mut job = Self {
            base: CatalogPackingAuthorityBase {
                guild_id: checkpoint.guild_id,
                checkpoint_hash: trusted_hash,
                generation: checkpoint.generation,
                membership_epoch,
            },
            store,
            required_signers,
            sources: 0,
            authenticated: 0,
            candidates: 0,
            bytes: legacy_bytes,
            pages: 0,
            records: 1,
        };
        job.store
            .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                for kind in KINDS {
                    if job
                        .store
                        .next_record_bounded(kind, None, 96, PAGED_USER_REVISION_BYTES)?
                        .is_some()
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                }
                for member in &checkpoint.members {
                    insert(&job.store, MEMBERS, &member.node_id.0, &true, ROW_BYTES)?;
                }
                for fence in &checkpoint.writer_fences {
                    if let Some((_, previous)) =
                        read::<WriterFence>(&job.store, FENCES, &fence.owner.0)?
                    {
                        replace(&job.store, FENCES, &fence.owner.0, &previous, fence)?;
                    } else {
                        insert(&job.store, FENCES, &fence.owner.0, fence, ROW_BYTES)?;
                    }
                }
                for revision in &checkpoint.revisions {
                    let body = &revision.value;
                    insert(
                        &job.store,
                        IDS,
                        body.revision_id.as_bytes(),
                        &true,
                        ROW_BYTES,
                    )?;
                    let key = chain(body.owner, body.protected_root_id);
                    let head = Head {
                        sequence: body.sequence,
                        hash: body.hash()?,
                        writer_epoch: body.writer_epoch,
                    };
                    if let Some((_, previous)) = read::<Head>(&job.store, HEADS, &key)? {
                        replace(&job.store, HEADS, &key, &previous, &head)?;
                    } else {
                        insert(&job.store, HEADS, &key, &head, ROW_BYTES)?;
                    }
                    for (index, sector) in body
                        .metadata_sectors
                        .iter()
                        .chain(&body.data_sectors)
                        .enumerate()
                    {
                        let id = CatalogPackedSourceId {
                            owner: body.owner,
                            protected_root: packing_protected_root(body.protected_root_id),
                            object_id: sector.id,
                        };
                        let commitment = body
                            .sector_commitments
                            .as_ref()
                            .map(|values| values[index].clone());
                        let (new, authenticated) =
                            add_source(&job.store, id, sector.root, commitment)?;
                        job.sources += new;
                        job.authenticated += authenticated;
                    }
                }
                // The complete legacy certificate verifier already joins these
                // commitments to signed revision roots or verified migration evidence.
                if let Some(catalog) = &checkpoint.packing_catalog
                    && let Some(authentication) = &catalog.source_authentication
                {
                    for entry in authentication {
                        let id = CatalogPackedSourceId {
                            owner: entry.id.owner,
                            protected_root: entry.id.protected_root,
                            object_id: entry.id.object_id,
                        };
                        let (previous, _) = source(&job.store, id)?;
                        let (new, authenticated) = add_source(
                            &job.store,
                            id,
                            previous.flat_root,
                            Some(entry.source_commitment.clone()),
                        )?;
                        if new != 0 {
                            return Err(DatabaseError::Integrity.into());
                        }
                        job.authenticated += authenticated;
                    }
                }
                Ok(())
            })?;
        job.check_budget(0, 0)?;
        Ok(job)
    }

    pub fn base(&self) -> CatalogPackingAuthorityBase {
        self.base
    }

    pub fn next_source(
        &self,
        after: Option<CatalogPackedSourceId>,
    ) -> Result<Option<CatalogPackingAuthorizedSource>, CatalogStoreError> {
        if self.authenticated != self.sources {
            return Err(DatabaseError::NotReady.into());
        }
        let after = after.map(source_key);
        let Some((key, bytes)) = self.store.next_record_bounded(
            SOURCES,
            after.as_ref().map(|key| key.as_slice()),
            96,
            ROW_BYTES,
        )?
        else {
            return Ok(None);
        };
        let source: Source = decode_canonical(&bytes)?;
        if key != source_key(source.id) || encoded(&source, ROW_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        let commitment = source.commitment.ok_or(DatabaseError::Integrity)?;
        if commitment.byte_len as usize != V1_SECTOR_SIZE || commitment.validate().is_err() {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(CatalogPackingAuthorizedSource {
            id: source.id,
            flat_root: source.flat_root,
            commitment,
        }))
    }

    fn check_budget(&self, extra_bytes: u64, extra_pages: u64) -> Result<(), CatalogStoreError> {
        if self.sources > CATALOG_MAX_RECORDS
            || self.authenticated > self.sources
            || self
                .bytes
                .checked_add(extra_bytes)
                .is_none_or(|bytes| bytes > CATALOG_MAX_STREAM_BYTES)
            || self
                .pages
                .checked_add(extra_pages)
                .is_none_or(|pages| pages > CATALOG_MAX_PAGE_OCCURRENCES)
        {
            return Err(CatalogError::Bounds.into());
        }
        Ok(())
    }

    /// New roots require membership and the latest writer fence in this base,
    /// exact continuation of the retained chain and globally unique revision ID.
    /// This checks source authority only; private namespace/Git joins must also
    /// complete before an enclosing checkpoint or active revision is published.
    /// Signing/publication must recheck the base and current certified guild
    /// events: a concurrent writer rotation/removal can supersede this base.
    pub fn with_paged_revision(
        mut self,
        signed: &SignedRecord<PagedUserRevision>,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<Self, CatalogStoreError> {
        let body = &signed.value;
        if read::<bool>(&self.store, MEMBERS, &body.owner.0)?.map(|row| row.0) != Some(true) {
            return Err(DatabaseError::Conflict.into());
        }
        let (fence, _) = read::<WriterFence>(&self.store, FENCES, &body.owner.0)?
            .ok_or(ModelError::InvalidWriterFence)?;
        let mut reader =
            PagedRevisionSourceReader::new(signed, self.base.guild_id, body.owner, &fence)?;
        let key = chain(body.owner, body.protected_root_id);
        let previous = read::<Head>(&self.store, HEADS, &key)?;
        match &previous {
            Some((head, _))
                if head.sequence.checked_add(1) == Some(body.sequence)
                    && body.parent == Some(head.hash)
                    && body.writer_epoch >= head.writer_epoch => {}
            None if body.sequence == 1 && body.parent.is_none() => {}
            _ => return Err(DatabaseError::Conflict.into()),
        }
        let bytes = encoded(signed, PAGED_USER_REVISION_BYTES)?;
        let extra_bytes = bytes.len() as u64 + body.sources.records.page.byte_len;
        let extra_pages = body.sources.records.page.page_occurrences;
        let records = self
            .records
            .checked_add(1)
            .and_then(|records| records.checked_add(body.sources.records.records))
            .ok_or(CatalogError::Bounds)?;
        self.check_budget(extra_bytes, extra_pages)?;
        let mut new_sources = 0;
        let mut authenticated_sources = 0;
        self.store
            .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                insert(
                    &self.store,
                    IDS,
                    body.revision_id.as_bytes(),
                    &true,
                    ROW_BYTES,
                )?;
                while let Some(record) = unwrap_stream(reader.next_sector(&mut fetch))? {
                    let id = CatalogPackedSourceId {
                        owner: body.owner,
                        protected_root: packing_protected_root(body.protected_root_id),
                        object_id: record.sector.id,
                    };
                    let (new, authenticated) =
                        add_source(&self.store, id, record.sector.root, Some(record.commitment))?;
                    new_sources += new;
                    authenticated_sources += authenticated;
                    if self.sources + new_sources > CATALOG_MAX_RECORDS {
                        return Err(CatalogError::Bounds.into());
                    }
                }
                if !reader.is_complete() {
                    return Err(DatabaseError::Integrity.into());
                }
                insert(
                    &self.store,
                    CANDIDATES,
                    &CatalogCheckpointRevisionKey::from(body).index_key(),
                    signed,
                    PAGED_USER_REVISION_BYTES,
                )?;
                let head = Head {
                    sequence: body.sequence,
                    hash: body.hash()?,
                    writer_epoch: body.writer_epoch,
                };
                if let Some((_, bytes)) = &previous {
                    replace(&self.store, HEADS, &key, bytes, &head)?;
                } else {
                    insert(&self.store, HEADS, &key, &head, ROW_BYTES)?;
                }
                Ok(())
            })?;
        self.sources += new_sources;
        self.authenticated += authenticated_sources;
        self.candidates += 1;
        self.bytes += extra_bytes;
        self.pages += extra_pages;
        self.records = records;
        self.check_budget(0, 0)?;
        Ok(self)
    }

    fn check_evidence(
        &self,
        id: CatalogPackedSourceId,
        flat_root: [u8; 32],
        commitment: MerkleCommitment,
    ) -> Result<(Source, Vec<u8>), CatalogStoreError> {
        let (source, bytes) = source(&self.store, id)?;
        if source.flat_root != flat_root
            || flat_root == [0; 32]
            || commitment.byte_len as usize != V1_SECTOR_SIZE
            || commitment.validate().is_err()
            || source
                .commitment
                .as_ref()
                .is_some_and(|previous| previous != &commitment)
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok((source, bytes))
    }

    pub fn with_legacy_binding(
        mut self,
        signed: &SignedRecord<LegacyPackingBinding>,
    ) -> Result<Self, CatalogStoreError> {
        let bytes = encoded(signed, EVIDENCE_BYTES)?;
        let records = self.records.checked_add(1).ok_or(CatalogError::Bounds)?;
        self.check_budget(bytes.len() as u64, 0)?;
        signed.verify(LEGACY_PACKING_BINDING_DOMAIN)?;
        let value = &signed.value;
        if value.format_version != 1 || signed.signer != value.owner {
            return Err(DatabaseError::Conflict.into());
        }
        let id = CatalogPackedSourceId {
            owner: value.owner,
            protected_root: value.protected_root,
            object_id: value.object_id,
        };
        let (mut source, previous) =
            self.check_evidence(id, value.flat_root, value.source_commitment.clone())?;
        let new = source.commitment.is_none();
        source.commitment = Some(value.source_commitment.clone());
        self.store
            .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                insert(&self.store, BINDINGS, &id.key(), signed, EVIDENCE_BYTES)?;
                replace(&self.store, SOURCES, &source_key(id), &previous, &source)
            })?;
        self.authenticated += u64::from(new);
        self.bytes += bytes.len() as u64;
        self.records = records;
        Ok(self)
    }

    pub fn with_legacy_attestation(
        mut self,
        signed: &SignedRecord<LegacyPackingAttestation>,
    ) -> Result<Self, CatalogStoreError> {
        let bytes = encoded(signed, EVIDENCE_BYTES)?;
        let records = self.records.checked_add(1).ok_or(CatalogError::Bounds)?;
        self.check_budget(bytes.len() as u64, 0)?;
        signed.verify(LEGACY_PACKING_ATTESTATION_DOMAIN)?;
        let value = &signed.value;
        if value.format_version != 1
            || value.guild_id != self.base.guild_id
            || Some(value.membership_epoch) != self.base.membership_epoch
            || read::<bool>(&self.store, MEMBERS, &signed.signer.0)?.map(|row| row.0) != Some(true)
        {
            return Err(DatabaseError::Conflict.into());
        }
        let id = CatalogPackedSourceId {
            owner: value.owner,
            protected_root: value.protected_root,
            object_id: value.object_id,
        };
        let (mut source, previous) =
            self.check_evidence(id, value.flat_root, value.source_commitment.clone())?;
        let mut key = [0; 64];
        key[..32].copy_from_slice(&id.key());
        key[32..].copy_from_slice(&signed.signer.0);
        let tally = read::<Tally>(&self.store, TALLIES, &id.key())?;
        let signers = match &tally {
            Some((tally, _)) if tally.commitment == value.source_commitment => tally
                .signers
                .checked_add(1)
                .ok_or(DatabaseError::Integrity)?,
            None => 1,
            _ => return Err(DatabaseError::Conflict.into()),
        };
        let new = source.commitment.is_none() && usize::from(signers) >= self.required_signers;
        self.store
            .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                insert(&self.store, ATTESTATIONS, &key, signed, EVIDENCE_BYTES)?;
                let replacement = Tally {
                    commitment: value.source_commitment.clone(),
                    signers,
                };
                if let Some((_, previous)) = &tally {
                    replace(&self.store, TALLIES, &id.key(), previous, &replacement)?;
                } else {
                    insert(&self.store, TALLIES, &id.key(), &replacement, ROW_BYTES)?;
                }
                if new {
                    source.commitment = Some(value.source_commitment.clone());
                    replace(&self.store, SOURCES, &source_key(id), &previous, &source)?;
                }
                Ok(())
            })?;
        self.authenticated += u64::from(new);
        self.bytes += bytes.len() as u64;
        self.records = records;
        Ok(self)
    }

    /// Exact source cardinality plus the ordered unique stream establishes a
    /// bijection with all retained and candidate sources. No retirement is
    /// authorized here. Both catalog EOFs must pass before placements are usable.
    pub fn validate_packing(
        self,
        manifest: CatalogPackingValidation,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<CatalogCertifiedPackingIndex, CatalogStoreError> {
        manifest.validate()?;
        let work = manifest.represented_work()?;
        self.check_budget(work.bytes, work.page_occurrences)?;
        let mut budget = CatalogPackingValidation::original_budget();
        budget.records = budget
            .records
            .checked_add(self.records)
            .ok_or(CatalogError::Bounds)?;
        self.validate_packing_with_budget(manifest, budget, fetch)
    }

    /// The trusted total budget includes this job's admitted source authority;
    /// its debt is paid before either packing stream is fetched. The original
    /// unbudgeted API keeps its original aggregate ceiling and version.
    pub fn validate_packing_with_budget(
        self,
        manifest: CatalogPackingValidation,
        budget: CatalogCodingTraversalBudget,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<CatalogCertifiedPackingIndex, CatalogStoreError> {
        let packing_budget = budget.remaining_after(CatalogCodingTraversalBudget {
            bytes: self.bytes,
            page_occurrences: self.pages,
            records: self.records,
        })?;
        manifest.validate_with_budget(packing_budget)?;
        if manifest.scope
            != (CatalogScope::Guild {
                guild_id: self.base.guild_id,
            })
            || manifest.sources.sources != self.sources
            || self.authenticated != self.sources
        {
            return Err(DatabaseError::Conflict.into());
        }
        self.store.with_record_transaction(|| {
            build_index(manifest, &self.store, &mut fetch, &mut |id, commitment| {
                let (source, _) = source(&self.store, id)?;
                if source.commitment.as_ref() != Some(commitment) {
                    return Err(DatabaseError::Conflict.into());
                }
                Ok(())
            })
        })?;
        Ok(CatalogCertifiedPackingIndex {
            base: self.base,
            candidates: self.candidates,
            authority_bytes: self.bytes,
            authority_pages: self.pages,
            authority_records: self.records,
            index: CatalogPackingIndex {
                manifest,
                store: self.store,
                budget: packing_budget,
            },
        })
    }
}

/// Verified placements retain their trusted base and bounded signed candidates.
/// This disposable object does not issue a certificate or protection claim.
pub struct CatalogCertifiedPackingIndex {
    base: CatalogPackingAuthorityBase,
    candidates: u64,
    authority_bytes: u64,
    authority_pages: u64,
    authority_records: u64,
    index: CatalogPackingIndex,
}

impl CatalogCertifiedPackingIndex {
    pub fn base(&self) -> CatalogPackingAuthorityBase {
        self.base
    }
    pub fn candidate_count(&self) -> u64 {
        self.candidates
    }
    pub fn manifest(&self) -> CatalogPackingValidation {
        self.index.manifest()
    }
    pub fn placement(
        &self,
        source: mb_core::SourceChunkId,
    ) -> Result<Option<CatalogPackingPlacement>, CatalogStoreError> {
        self.index.placement(source)
    }

    /// Exclusive owner/root/sequence/UUID order for the checkpoint stream.
    /// Reaching this EOF is necessary before using the full candidate set.
    pub fn next_paged_revision(
        &self,
        after: Option<CatalogCheckpointRevisionKey>,
    ) -> Result<Option<SignedRecord<PagedUserRevision>>, CatalogStoreError> {
        next_candidate(&self.index, after)
    }
}

fn next_candidate(
    index: &CatalogPackingIndex,
    after: Option<CatalogCheckpointRevisionKey>,
) -> Result<Option<SignedRecord<PagedUserRevision>>, CatalogStoreError> {
    index.require_complete()?;
    let after = after.map(CatalogCheckpointRevisionKey::index_key);
    let Some((key, bytes)) = index.store.next_record_bounded(
        CANDIDATES,
        after.as_ref().map(|key| key.as_slice()),
        72,
        PAGED_USER_REVISION_BYTES,
    )?
    else {
        return Ok(None);
    };
    let signed = PagedUserRevision::decode_signed(&bytes)?;
    if key != CatalogCheckpointRevisionKey::from(&signed.value).index_key() {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some(signed))
}

/// The source-authority base/candidates and aggregate admission survive the
/// coding join. This proof still requires live event rechecks and complete
/// enclosing checkpoint/private catalog validation before activation.
pub struct CatalogCertifiedCodingIndex {
    base: CatalogPackingAuthorityBase,
    candidates: u64,
    authority_bytes: u64,
    authority_pages: u64,
    index: CatalogPackingCodingIndex,
}

impl CatalogCertifiedPackingIndex {
    pub fn validate_coding(
        self,
        coding: CatalogCodingValidation,
        policy: CatalogCodingCoveragePolicy,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(
            &mb_core::CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogCertifiedCodingIndex, CatalogStoreError> {
        let manifest = CatalogPackingCodingValidation {
            format_version: 1,
            packing: self.index.manifest,
            coding: coding.clone(),
            policy,
        };
        manifest.validate()?;
        let (bytes, pages) = manifest.represented_work()?;
        check_coding_work(self.authority_bytes, self.authority_pages, bytes, pages)?;
        let index = self
            .index
            .validate_coding(coding, policy, fetch, authorize)?;
        Ok(CatalogCertifiedCodingIndex {
            base: self.base,
            candidates: self.candidates,
            authority_bytes: self.authority_bytes,
            authority_pages: self.authority_pages,
            index,
        })
    }
}

fn check_coding_work(
    authority_bytes: u64,
    authority_pages: u64,
    bytes: u64,
    pages: u64,
) -> Result<(u64, u64), CatalogStoreError> {
    let bytes = authority_bytes
        .checked_add(bytes)
        .ok_or(CatalogError::Bounds)?;
    let pages = authority_pages
        .checked_add(pages)
        .ok_or(CatalogError::Bounds)?;
    if bytes > mb_core::CATALOG_CODING_MAX_BYTES || pages > CATALOG_MAX_PAGE_OCCURRENCES {
        return Err(CatalogError::Bounds.into());
    }
    Ok((bytes, pages))
}

/// The trusted source base, complete candidates and all three dimensions of
/// admitted authority work survive the directory join. Current guild-event
/// authority and complete enclosing checkpoint validation remain mandatory.
pub struct CatalogCertifiedCodingDirectoryIndex {
    base: CatalogPackingAuthorityBase,
    candidates: u64,
    index: CatalogPackingCodingDirectoryIndex,
}

impl CatalogCertifiedPackingIndex {
    pub fn validate_coding_directory(
        self,
        coding: CatalogCodingDirectoryRoot,
        policy: CatalogCodingCoveragePolicy,
        budget: CatalogCodingTraversalBudget,
        fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
        authorize: impl FnMut(
            &mb_core::CatalogCodingEntry,
        ) -> Result<CatalogCodingAuthorization, CatalogStoreError>,
    ) -> Result<CatalogCertifiedCodingDirectoryIndex, CatalogStoreError> {
        let index = self.index.validate_directory_with_prior(
            coding,
            policy,
            budget,
            CatalogCodingTraversalBudget {
                bytes: self.authority_bytes,
                page_occurrences: self.authority_pages,
                records: self.authority_records,
            },
            fetch,
            authorize,
        )?;
        Ok(CatalogCertifiedCodingDirectoryIndex {
            base: self.base,
            candidates: self.candidates,
            index,
        })
    }
}

impl CatalogCertifiedCodingDirectoryIndex {
    pub fn base(&self) -> CatalogPackingAuthorityBase {
        self.base
    }
    pub fn candidate_count(&self) -> u64 {
        self.candidates
    }
    pub fn index(&self) -> &CatalogPackingCodingDirectoryIndex {
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
        next_candidate(self.index.packing(), after)
    }
}

impl CatalogCertifiedCodingIndex {
    pub fn base(&self) -> CatalogPackingAuthorityBase {
        self.base
    }
    pub fn candidate_count(&self) -> u64 {
        self.candidates
    }
    pub fn index(&self) -> &CatalogPackingCodingIndex {
        &self.index
    }
    pub fn represented_work(&self) -> Result<(u64, u64), CatalogStoreError> {
        let (bytes, pages) = self.index.manifest().represented_work()?;
        check_coding_work(self.authority_bytes, self.authority_pages, bytes, pages)
    }
    pub fn next_paged_revision(
        &self,
        after: Option<CatalogCheckpointRevisionKey>,
    ) -> Result<Option<SignedRecord<PagedUserRevision>>, CatalogStoreError> {
        next_candidate(self.index.packing(), after)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mb_core::{
        CatalogPackedSectorBuilder, CatalogPackedSourceBuilder, CatalogPackedSourceRecord,
        CatalogSectorBuilder, CatalogSectorRecord, CheckpointAuthority, GuildCheckpoint,
        KeyMaterial, Member, PackingInput, PackingProfile, QuorumPolicy, QuorumRule, Seed,
        USER_REVISION_DOMAIN, UserRevision, V1_CIPHER_PROFILE, merkle_commit, merkle_open_subtree,
        pack_incremental, sector_root,
    };
    use std::collections::BTreeMap;

    type Pages = BTreeMap<[u8; 32], Vec<u8>>;

    pub(crate) struct Fixture {
        pub(crate) keys: Vec<KeyMaterial>,
        pub(crate) writer: SigningKey,
        pub(crate) certificate: QuorumCheckpoint,
        pub(crate) records: Vec<CatalogSectorRecord>,
        pub(crate) bytes: Vec<Vec<u8>>,
    }

    impl Fixture {
        pub(crate) fn new(authenticated: bool, removed: bool) -> Self {
            let keys = (11..14)
                .map(|seed| KeyMaterial::from_seed(&Seed::from_bytes([seed; 32])))
                .collect::<Vec<_>>();
            let writer = SigningKey::from_bytes(&[20; 32]);
            let bytes = vec![vec![1; V1_SECTOR_SIZE], vec![2; V1_SECTOR_SIZE]];
            let records = bytes
                .iter()
                .enumerate()
                .map(|(index, bytes)| CatalogSectorRecord {
                    format_version: 1,
                    sector: mb_core::SectorRef {
                        id: [index as u8 + 1; 32],
                        root: sector_root(bytes),
                        logical_len: 12,
                    },
                    commitment: merkle_commit(bytes).unwrap(),
                })
                .collect::<Vec<_>>();
            let mut revision = UserRevision {
                format_version: if authenticated { 5 } else { 3 },
                guild_id: [21; 32],
                protected_root_id: Uuid::from_u128(22),
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::from_u128(23),
                owner: keys[0].node_id(),
                writer_epoch: 1,
                writer_public_key: writer.verifying_key().to_bytes(),
                writer_signature: Vec::new(),
                sequence: 1,
                parent: None,
                metadata_sectors: vec![records[0].sector.clone()],
                data_sectors: vec![records[1].sector.clone()],
                sector_commitments: authenticated.then(|| {
                    records
                        .iter()
                        .map(|record| record.commitment.clone())
                        .collect()
                }),
            };
            revision.sign_writer(&writer).unwrap();
            let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, &keys[0]).unwrap();
            let mut members = keys
                .iter()
                .skip(usize::from(removed))
                .enumerate()
                .map(|(index, keys)| Member {
                    node_id: keys.node_id(),
                    recovery_public_key: keys.recovery_public_key(),
                    failure_domain: format!("domain-{index}"),
                })
                .collect::<Vec<_>>();
            members.sort_by_key(|member| member.node_id);
            let certificate = QuorumCheckpoint {
                checkpoint: GuildCheckpoint {
                    format_version: 6,
                    guild_id: [21; 32],
                    genesis_hash: [24; 32],
                    generation: 1,
                    parent: None,
                    members,
                    writer_fences: vec![WriterFence {
                        owner: keys[0].node_id(),
                        epoch: 1,
                        public_key: writer.verifying_key().to_bytes(),
                    }],
                    revision_tombstones: Vec::new(),
                    revisions: vec![revision],
                    coding_groups: Vec::new(),
                    authority: Some(CheckpointAuthority {
                        format_version: 1,
                        membership_epoch: 2,
                        quorum: QuorumPolicy {
                            format_version: 1,
                            rule: QuorumRule::Majority,
                        },
                    }),
                    packing_catalog: None,
                },
                signatures: Vec::new(),
            };
            let mut fixture = Self {
                keys,
                writer,
                certificate,
                records,
                bytes,
            };
            fixture.resign();
            fixture
        }

        pub(crate) fn resign(&mut self) {
            self.certificate.signatures.clear();
            for keys in &self.keys {
                if self
                    .certificate
                    .checkpoint
                    .members
                    .iter()
                    .any(|member| member.node_id == keys.node_id())
                {
                    self.certificate.add_signature(keys).unwrap();
                }
            }
            self.certificate.verify().unwrap();
        }

        fn authority(&self) -> CatalogPackingAuthority {
            CatalogPackingAuthority::from_legacy_checkpoint(
                self.certificate.hash().unwrap(),
                &self.certificate,
                RecordScratchStore::new(4 * 1024 * 1024).unwrap(),
            )
            .unwrap()
        }

        pub(crate) fn candidate(
            &self,
            records: &[CatalogSectorRecord],
        ) -> (SignedRecord<PagedUserRevision>, Pages) {
            let old = &self.certificate.checkpoint.revisions[0].value;
            let scope = CatalogScope::Dataset {
                guild_id: old.guild_id,
                owner: old.owner,
                protected_root_id: old.protected_root_id,
            };
            let mut pages = Pages::new();
            let mut sink = |page: CatalogPageRef, bytes| {
                pages.insert(page.hash, bytes);
                Ok::<_, CatalogStoreError>(())
            };
            let mut builder = CatalogSectorBuilder::new(scope).unwrap();
            for record in records {
                builder.push(record, &mut sink).unwrap();
            }
            let sources = builder.finish(&mut sink).unwrap();
            let signed = PagedUserRevision {
                format_version: 8,
                guild_id: old.guild_id,
                protected_root_id: old.protected_root_id,
                cipher_profile: V1_CIPHER_PROFILE,
                revision_id: Uuid::from_u128(30),
                owner: old.owner,
                writer_epoch: old.writer_epoch,
                writer_public_key: old.writer_public_key,
                writer_signature: Vec::new(),
                sequence: old.sequence + 1,
                parent: Some(old.hash().unwrap()),
                metadata: records[0].clone(),
                sources,
            }
            .sign(&self.writer, &self.keys[0])
            .unwrap();
            (signed, pages)
        }

        pub(crate) fn packing(
            &self,
            records: &[CatalogSectorRecord],
            payloads: &[Vec<u8>],
        ) -> (CatalogPackingValidation, Pages) {
            let old = &self.certificate.checkpoint.revisions[0].value;
            let inputs = records
                .iter()
                .zip(payloads)
                .map(|(record, bytes)| PackingInput {
                    owner: old.owner,
                    protected_root: packing_protected_root(old.protected_root_id),
                    object_id: record.sector.id,
                    source_commitment: Some(record.commitment.clone()),
                    bytes: bytes.clone(),
                })
                .collect();
            let profile = PackingProfile {
                format_version: 1,
                sector_size: V1_SECTOR_SIZE as u32,
                slot_size: 16 * 1024,
            };
            let packed = pack_incremental(profile, None, inputs).unwrap();
            let scope = CatalogScope::Guild {
                guild_id: old.guild_id,
            };
            let mut pages = Pages::new();
            let mut sink = |page: CatalogPageRef, bytes| {
                pages.insert(page.hash, bytes);
                Ok::<_, CatalogStoreError>(())
            };
            let mut descriptors = CatalogPackedSectorBuilder::new_compact(
                scope,
                packed.catalog.format_version,
                profile,
            )
            .unwrap();
            for descriptor in &packed.catalog.sectors {
                descriptors.push_sector(descriptor, &mut sink).unwrap();
            }
            let descriptors = descriptors.finish(&mut sink).unwrap();
            let mut sources = CatalogPackedSourceBuilder::new_compact(scope, profile).unwrap();
            for (record, bytes) in records.iter().zip(payloads) {
                sources
                    .push(
                        &CatalogPackedSourceRecord::Source {
                            format_version: 1,
                            id: CatalogPackedSourceId {
                                owner: old.owner,
                                protected_root: packing_protected_root(old.protected_root_id),
                                object_id: record.sector.id,
                            },
                            commitment: record.commitment.clone(),
                        },
                        &mut sink,
                    )
                    .unwrap();
                let roots = (0..4)
                    .map(|index| {
                        let leaves = profile.slot_size / mb_core::MERKLE_LEAF_SIZE as u32;
                        merkle_open_subtree(bytes, index * leaves, leaves)
                            .unwrap()
                            .subtree_root
                    })
                    .collect();
                sources
                    .push(
                        &CatalogPackedSourceRecord::Subtrees {
                            first_chunk: 0,
                            roots,
                        },
                        &mut sink,
                    )
                    .unwrap();
            }
            let sources = sources.finish(&mut sink).unwrap();
            (
                CatalogPackingValidation {
                    format_version: 1,
                    scope,
                    descriptors,
                    sources,
                },
                pages,
            )
        }

        pub(crate) fn binding(&self, index: usize) -> SignedRecord<LegacyPackingBinding> {
            let old = &self.certificate.checkpoint.revisions[0].value;
            SignedRecord::sign(
                LEGACY_PACKING_BINDING_DOMAIN,
                LegacyPackingBinding {
                    format_version: 1,
                    owner: old.owner,
                    protected_root: packing_protected_root(old.protected_root_id),
                    object_id: self.records[index].sector.id,
                    flat_root: self.records[index].sector.root,
                    source_commitment: self.records[index].commitment.clone(),
                },
                &self.keys[0],
            )
            .unwrap()
        }

        pub(crate) fn attestation(
            &self,
            index: usize,
            signer: usize,
        ) -> SignedRecord<LegacyPackingAttestation> {
            let binding = self.binding(index).value;
            SignedRecord::sign(
                LEGACY_PACKING_ATTESTATION_DOMAIN,
                LegacyPackingAttestation {
                    format_version: 1,
                    guild_id: self.certificate.checkpoint.guild_id,
                    membership_epoch: 2,
                    owner: binding.owner,
                    protected_root: binding.protected_root,
                    object_id: binding.object_id,
                    flat_root: binding.flat_root,
                    source_commitment: binding.source_commitment,
                },
                &self.keys[signer],
            )
            .unwrap()
        }
    }

    fn fetch(pages: &Pages, page: CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError> {
        pages
            .get(&page.hash)
            .cloned()
            .ok_or_else(|| DatabaseError::NotReady.into())
    }

    #[test]
    fn budgeted_certified_packing_debits_source_authority_before_fetching() {
        let fixture = Fixture::new(true, false);
        let (mut manifest, pages) = fixture.packing(&fixture.records, &fixture.bytes);
        manifest.format_version = 2;
        let job = fixture.authority();
        let prior = CatalogCodingTraversalBudget {
            bytes: job.bytes,
            page_occurrences: job.pages,
            records: job.records,
        };
        let work = prior
            .checked_add(manifest.represented_work().unwrap())
            .unwrap();
        drop(job);
        assert!(
            fixture
                .authority()
                .validate_packing(manifest, |_| panic!("unbudgeted version two fetched pages"))
                .is_err()
        );
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                fixture
                    .authority()
                    .validate_packing_with_budget(manifest, limit, |_| panic!(
                        "unpaid authority or packing work fetched pages"
                    ))
                    .is_err()
            );
        }
        assert!(
            fixture
                .authority()
                .validate_packing_with_budget(
                    manifest,
                    manifest.represented_work().unwrap(),
                    |_| panic!("authority debt was omitted")
                )
                .is_err()
        );
        let checked = fixture
            .authority()
            .validate_packing_with_budget(manifest, work, |page| fetch(&pages, page))
            .unwrap();
        assert_eq!(checked.manifest(), manifest);
        assert_eq!(checked.candidate_count(), 0);
        assert_eq!(checked.index.budget, manifest.represented_work().unwrap());
        checked.index.require_complete().unwrap();
        assert!(checked.next_paged_revision(None).unwrap().is_none());
    }

    #[test]
    fn certified_packing_preserves_retained_sources_and_extends_signed_paged_history() {
        let fixture = Fixture::new(true, false);
        let extra_bytes = vec![3; V1_SECTOR_SIZE];
        let extra = CatalogSectorRecord {
            format_version: 1,
            sector: mb_core::SectorRef {
                id: [3; 32],
                root: sector_root(&extra_bytes),
                logical_len: 17,
            },
            commitment: merkle_commit(&extra_bytes).unwrap(),
        };
        let (candidate, candidate_pages) =
            fixture.candidate(&[fixture.records[0].clone(), extra.clone()]);
        let mut records = fixture.records.clone();
        records.push(extra);
        let mut payloads = fixture.bytes.clone();
        payloads.push(extra_bytes);
        let (manifest, pages) = fixture.packing(&records, &payloads);
        let authority = fixture
            .authority()
            .with_paged_revision(&candidate, |page| fetch(&candidate_pages, page))
            .unwrap();
        assert_eq!(authority.sources, 3);
        let mut after = None;
        for record in &records {
            let source = authority.next_source(after).unwrap().unwrap();
            assert_eq!(source.id.object_id, record.sector.id);
            assert_eq!(source.flat_root, record.sector.root);
            assert_eq!(source.commitment, record.commitment);
            after = Some(source.id);
        }
        assert!(authority.next_source(after).unwrap().is_none());
        let mut next = candidate.value.clone();
        next.sequence += 1;
        next.parent = Some(candidate.value.hash().unwrap());
        next.revision_id = Uuid::from_u128(29);
        let next = next.sign(&fixture.writer, &fixture.keys[0]).unwrap();
        let authority = authority
            .with_paged_revision(&next, |page| fetch(&candidate_pages, page))
            .unwrap();
        assert_eq!(
            authority.records,
            1 + 2 * (1 + candidate.value.sources.records.records)
        );
        let checked = authority
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
        assert_eq!(
            checked.base().checkpoint_hash,
            fixture.certificate.hash().unwrap()
        );
        assert_eq!(checked.candidate_count(), 2);
        assert_eq!(
            checked.next_paged_revision(None).unwrap(),
            Some(candidate.clone())
        );
        assert_eq!(
            checked
                .next_paged_revision(Some((&candidate.value).into()))
                .unwrap(),
            Some(next.clone())
        );
        assert!(
            checked
                .next_paged_revision(Some((&next.value).into()))
                .unwrap()
                .is_none()
        );
        // Checkpoint order follows the signed chain even when UUID order is
        // reversed. Feed the cursor directly into the mixed authority codec.
        let scope = manifest.scope;
        let mut control_pages = candidate_pages.clone();
        let mut sink = |page: CatalogPageRef, bytes| {
            control_pages.insert(page.hash, bytes);
            Ok::<_, CatalogStoreError>(())
        };
        let mut body_builder =
            mb_core::CatalogBuilder::new(scope, CatalogSection::Checkpoint).unwrap();
        let legacy = &fixture.certificate.checkpoint.revisions[0];
        body_builder
            .push(
                &canonical_bytes_bounded(legacy, V1_MAX_CATALOG_BYTES).unwrap(),
                &mut sink,
            )
            .unwrap();
        let body = body_builder.finish(&mut sink).unwrap();
        let reference = mb_core::CatalogLegacyRevisionRef::from_signed(
            fixture.certificate.checkpoint.guild_id,
            legacy,
            body,
        )
        .unwrap();
        let mut control = mb_core::CatalogCheckpointAuthorityBuilder::new(scope, 2, 2).unwrap();
        for member in &fixture.certificate.checkpoint.members {
            control
                .push(
                    &mb_core::CatalogCheckpointAuthorityRecord::Member(member.clone()),
                    &mut sink,
                )
                .unwrap();
        }
        for fence in &fixture.certificate.checkpoint.writer_fences {
            control
                .push(
                    &mb_core::CatalogCheckpointAuthorityRecord::WriterFence(fence.clone()),
                    &mut sink,
                )
                .unwrap();
        }
        control
            .push(
                &mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(reference),
                &mut sink,
            )
            .unwrap();
        let mut after = None;
        while let Some(signed) = checked.next_paged_revision(after).unwrap() {
            after = Some((&signed.value).into());
            control
                .push(
                    &mb_core::CatalogCheckpointAuthorityRecord::PagedRevision(signed),
                    &mut sink,
                )
                .unwrap();
        }
        let control = control.finish(&mut sink).unwrap();
        assert_eq!(control.summary.revisions, 3);
        let mut reader = mb_core::CatalogCheckpointAuthorityReader::new(scope, control).unwrap();
        let mut read = 0;
        while let Some(record) = reader
            .next_record(&mut |page| fetch(&control_pages, page))
            .unwrap()
        {
            if let mb_core::CatalogCheckpointAuthorityRecord::LegacyRevision(reference) = record {
                assert_eq!(
                    reference
                        .read_signed(&mut |page| fetch(&control_pages, page))
                        .unwrap(),
                    *legacy
                );
            }
            read += 1;
        }
        assert_eq!(read, control.records.records);
        for record in records {
            for chunk in 0..4 {
                assert!(
                    checked
                        .placement(
                            CatalogPackedSourceId {
                                owner: candidate.value.owner,
                                protected_root: packing_protected_root(
                                    candidate.value.protected_root_id
                                ),
                                object_id: record.sector.id,
                            }
                            .chunk(chunk)
                        )
                        .unwrap()
                        .is_some()
                );
            }
        }
        let (omitted, pages) = fixture.packing(&fixture.records[..1], &fixture.bytes[..1]);
        assert!(
            fixture
                .authority()
                .validate_packing(omitted, |page| fetch(&pages, page))
                .is_err()
        );
        let mut wrong = fixture.records.clone();
        wrong[1].sector.id = [99; 32];
        let (unknown, pages) = fixture.packing(&wrong, &fixture.bytes);
        assert!(
            fixture
                .authority()
                .validate_packing(unknown, |page| fetch(&pages, page))
                .is_err()
        );
        let (manifest, mut pages) = fixture.packing(&fixture.records, &fixture.bytes);
        pages.get_mut(&manifest.sources.records.page.hash).unwrap()[0] ^= 1;
        assert!(
            fixture
                .authority()
                .validate_packing(manifest, |page| fetch(&pages, page))
                .is_err()
        );
    }

    #[test]
    fn certified_packing_requires_the_trusted_hash_valid_quorum_and_exact_current_fence() {
        let mut fixture = Fixture::new(true, false);
        let make = |hash, certificate: &QuorumCheckpoint| {
            CatalogPackingAuthority::from_legacy_checkpoint(
                hash,
                certificate,
                RecordScratchStore::new(4 * 1024 * 1024).unwrap(),
            )
        };
        assert!(make([99; 32], &fixture.certificate).is_err());
        let mut invalid = fixture.certificate.clone();
        invalid.signatures.truncate(1);
        assert!(make(fixture.certificate.hash().unwrap(), &invalid).is_err());
        invalid = fixture.certificate.clone();
        invalid.signatures[0].signature[0] ^= 1;
        assert!(make(fixture.certificate.hash().unwrap(), &invalid).is_err());
        let (candidate, pages) = fixture.candidate(&fixture.records);
        for changed in 0..4 {
            let mut bad = candidate.value.clone();
            match changed {
                0 => bad.parent = Some([99; 32]),
                1 => bad.sequence += 1,
                2 => {
                    bad.revision_id = fixture.certificate.checkpoint.revisions[0]
                        .value
                        .revision_id
                }
                _ => bad.guild_id = [99; 32],
            }
            let bad = bad.sign(&fixture.writer, &fixture.keys[0]).unwrap();
            assert!(
                fixture
                    .authority()
                    .with_paged_revision(&bad, |page| fetch(&pages, page))
                    .is_err()
            );
        }
        let mut bad = candidate.clone();
        bad.signature[0] ^= 1;
        assert!(
            fixture
                .authority()
                .with_paged_revision(&bad, |page| fetch(&pages, page))
                .is_err()
        );
        // The old writer remains a valid historical signer after rotation; it
        // cannot introduce a new candidate merely by supplying its own fence.
        let rotated = SigningKey::from_bytes(&[40; 32]);
        let owner = fixture.keys[0].node_id();
        fixture
            .certificate
            .checkpoint
            .writer_fences
            .push(WriterFence {
                owner,
                epoch: 2,
                public_key: rotated.verifying_key().to_bytes(),
            });
        let mut revision = fixture.certificate.checkpoint.revisions[0].value.clone();
        revision.writer_epoch = 2;
        revision.writer_public_key = rotated.verifying_key().to_bytes();
        revision.sign_writer(&rotated).unwrap();
        fixture.certificate.checkpoint.revisions[0] =
            SignedRecord::sign(USER_REVISION_DOMAIN, revision, &fixture.keys[0]).unwrap();
        fixture.resign();
        let mut stale = candidate.value;
        stale.parent = Some(
            fixture.certificate.checkpoint.revisions[0]
                .value
                .hash()
                .unwrap(),
        );
        let stale = stale.sign(&fixture.writer, &fixture.keys[0]).unwrap();
        assert!(
            fixture
                .authority()
                .with_paged_revision(&stale, |page| fetch(&pages, page))
                .is_err()
        );
    }

    #[test]
    fn certified_packing_imports_all_authenticated_legacy_catalog_evidence_paths() {
        for mode in 0..4 {
            let mut fixture = Fixture::new(mode == 0, false);
            let old = &fixture.certificate.checkpoint.revisions[0].value;
            let profile = PackingProfile {
                format_version: 1,
                sector_size: V1_SECTOR_SIZE as u32,
                slot_size: 16 * 1024,
            };
            let inputs = fixture
                .records
                .iter()
                .zip(&fixture.bytes)
                .map(|(record, bytes)| PackingInput {
                    owner: old.owner,
                    protected_root: packing_protected_root(old.protected_root_id),
                    object_id: record.sector.id,
                    source_commitment: (mode != 3).then(|| record.commitment.clone()),
                    bytes: bytes.clone(),
                })
                .collect();
            let mut catalog = pack_incremental(profile, None, inputs).unwrap().catalog;
            if mode == 1 {
                catalog = mb_core::attach_legacy_packing_bindings(
                    catalog,
                    vec![fixture.binding(0), fixture.binding(1)],
                )
                .unwrap();
            } else if mode == 2 {
                catalog = mb_core::attach_legacy_packing_evidence(
                    catalog,
                    vec![],
                    vec![
                        fixture.attestation(0, 0),
                        fixture.attestation(0, 1),
                        fixture.attestation(1, 0),
                        fixture.attestation(1, 1),
                    ],
                )
                .unwrap();
            }
            fixture.certificate.checkpoint.format_version = 7;
            fixture.certificate.checkpoint.packing_catalog = Some(catalog);
            fixture.resign();
            let mut authority = fixture.authority();
            if mode == 3 {
                assert_eq!(authority.authenticated, 0);
                authority = authority
                    .with_legacy_binding(&fixture.binding(0))
                    .unwrap()
                    .with_legacy_binding(&fixture.binding(1))
                    .unwrap();
            }
            assert_eq!(authority.authenticated, 2);
            let (manifest, pages) = fixture.packing(&fixture.records, &fixture.bytes);
            authority
                .validate_packing(manifest, |page| fetch(&pages, page))
                .unwrap();
        }
    }

    #[test]
    fn certified_packing_retains_removed_owners_but_rejects_their_new_revisions() {
        let fixture = Fixture::new(true, true);
        let (manifest, pages) = fixture.packing(&fixture.records, &fixture.bytes);
        fixture
            .authority()
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
        let (candidate, pages) = fixture.candidate(&fixture.records);
        assert!(
            fixture
                .authority()
                .with_paged_revision(&candidate, |page| fetch(&pages, page))
                .is_err()
        );
    }

    #[test]
    fn certified_packing_flat_history_requires_owner_or_epoch_quorum_evidence() {
        let fixture = Fixture::new(false, false);
        assert!(fixture.authority().next_source(None).is_err());
        let (manifest, pages) = fixture.packing(&fixture.records, &fixture.bytes);
        assert!(
            fixture
                .authority()
                .validate_packing(manifest, |page| fetch(&pages, page))
                .is_err()
        );
        let authority = fixture
            .authority()
            .with_legacy_binding(&fixture.binding(0))
            .unwrap()
            .with_legacy_binding(&fixture.binding(1))
            .unwrap();
        assert_eq!(authority.records, 3);
        authority
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
        let authority = fixture
            .authority()
            .with_legacy_binding(&fixture.binding(0))
            .unwrap()
            .with_legacy_attestation(&fixture.attestation(1, 0))
            .unwrap();
        assert!(
            authority
                .validate_packing(manifest, |page| fetch(&pages, page))
                .is_err()
        );
        let authority = fixture
            .authority()
            .with_legacy_binding(&fixture.binding(0))
            .unwrap()
            .with_legacy_attestation(&fixture.attestation(1, 0))
            .unwrap()
            .with_legacy_attestation(&fixture.attestation(1, 1))
            .unwrap();
        assert_eq!(authority.records, 4);
        authority
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
        let attestation = fixture.attestation(1, 0);
        assert!(
            fixture
                .authority()
                .with_legacy_attestation(&attestation)
                .unwrap()
                .with_legacy_attestation(&attestation)
                .is_err()
        );
        for changed in 0..3 {
            let mut bad = fixture.attestation(0, 0).value;
            match changed {
                0 => bad.membership_epoch += 1,
                1 => bad.flat_root[0] ^= 1,
                _ => bad.guild_id[0] ^= 1,
            }
            let bad = SignedRecord::sign(LEGACY_PACKING_ATTESTATION_DOMAIN, bad, &fixture.keys[0])
                .unwrap();
            assert!(fixture.authority().with_legacy_attestation(&bad).is_err());
        }
        let mut bad = fixture.binding(0).value;
        bad.source_commitment.root[0] ^= 1;
        let bad = SignedRecord::sign(LEGACY_PACKING_BINDING_DOMAIN, bad, &fixture.keys[1]).unwrap();
        assert!(fixture.authority().with_legacy_binding(&bad).is_err());
        let removed = Fixture::new(false, true);
        assert!(
            removed
                .authority()
                .with_legacy_attestation(&removed.attestation(0, 0))
                .is_err()
        );
        let authority = removed
            .authority()
            .with_legacy_binding(&removed.binding(0))
            .unwrap()
            .with_legacy_binding(&removed.binding(1))
            .unwrap();
        let (manifest, pages) = removed.packing(&removed.records, &removed.bytes);
        authority
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
    }

    #[test]
    fn certified_packing_imports_legacy_membership_and_retained_tombstone_continuations() {
        let mut fixture = Fixture::new(false, false);
        fixture.certificate.checkpoint.format_version = 4;
        fixture.certificate.checkpoint.authority = None;
        fixture.resign();
        assert_eq!(fixture.authority().base().membership_epoch, None);
        assert!(
            fixture
                .authority()
                .with_legacy_attestation(&fixture.attestation(0, 0))
                .is_err()
        );
        let authority = fixture
            .authority()
            .with_legacy_binding(&fixture.binding(0))
            .unwrap()
            .with_legacy_binding(&fixture.binding(1))
            .unwrap();
        let (manifest, pages) = fixture.packing(&fixture.records, &fixture.bytes);
        authority
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();

        let mut fixture = Fixture::new(true, false);
        let mut revision = fixture.certificate.checkpoint.revisions[0].value.clone();
        revision.sequence = 3;
        revision.parent = Some([70; 32]);
        revision.sign_writer(&fixture.writer).unwrap();
        fixture
            .certificate
            .checkpoint
            .revision_tombstones
            .push(mb_core::RevisionTombstone {
                owner: revision.owner,
                protected_root_id: revision.protected_root_id,
                through_sequence: 2,
                last_revision_id: Uuid::from_u128(70),
                last_revision_hash: [70; 32],
                retired_at_generation: 2,
            });
        fixture.certificate.checkpoint.revisions[0] =
            SignedRecord::sign(USER_REVISION_DOMAIN, revision, &fixture.keys[0]).unwrap();
        fixture.certificate.checkpoint.generation = 3;
        fixture.certificate.checkpoint.parent = Some([71; 32]);
        fixture.resign();
        let (candidate, pages) = fixture.candidate(&fixture.records);
        assert_eq!(candidate.value.sequence, 4);
        fixture
            .authority()
            .with_paged_revision(&candidate, |page| fetch(&pages, page))
            .unwrap();
        let mut reset = candidate.value;
        reset.sequence = 1;
        reset.parent = None;
        let reset = reset.sign(&fixture.writer, &fixture.keys[0]).unwrap();
        assert!(
            fixture
                .authority()
                .with_paged_revision(&reset, |page| fetch(&pages, page))
                .is_err()
        );
    }

    #[test]
    fn certified_packing_authority_spills_and_rebuilds_after_a_late_source_failure() {
        let fixture = Fixture::new(true, false);
        let mut records = (0..16_000_u32)
            .map(|index| {
                let mut record = fixture.records[0].clone();
                record.sector.id = [0; 32];
                record.sector.id[..4].copy_from_slice(&index.to_be_bytes());
                record.sector.id[31] = 1;
                record
            })
            .collect::<Vec<_>>();
        records.push(fixture.records[0].clone());
        records.sort_by_key(|record| record.sector.id);
        let (candidate, pages) = fixture.candidate(&records);
        let make = || {
            CatalogPackingAuthority::from_legacy_checkpoint(
                fixture.certificate.hash().unwrap(),
                &fixture.certificate,
                RecordScratchStore::new(16 * 1024 * 1024).unwrap(),
            )
            .unwrap()
        };
        let mut fetched = 0;
        assert!(
            make()
                .with_paged_revision(&candidate, |page| {
                    fetched += 1;
                    if fetched == candidate.value.sources.records.page.page_occurrences {
                        return Err(DatabaseError::NotReady.into());
                    }
                    fetch(&pages, page)
                })
                .is_err()
        );
        assert!(fetched > 10);
        let authority = make()
            .with_paged_revision(&candidate, |page| fetch(&pages, page))
            .unwrap();
        assert_eq!(authority.sources, 16_002);
        let cache = authority
            .store
            .database_shell_statement("PRAGMA scratch.cache_size", false)
            .unwrap();
        assert_eq!(cache.rows[0][0], "-1024");
        let pages = authority
            .store
            .database_shell_statement("PRAGMA scratch.page_count", false)
            .unwrap();
        assert!(pages.rows[0][0].parse::<u64>().unwrap() * 4096 > 1024 * 1024);
        let mut after = None;
        let mut count = 0;
        while let Some(source) = authority.next_source(after).unwrap() {
            assert!(after.is_none_or(|previous| previous < source.id));
            after = Some(source.id);
            count += 1;
        }
        assert_eq!(count, 16_002);
    }

    #[test]
    fn certified_packing_fences_incomplete_sources_orphan_rows_ignored_writes_and_aggregate_budget()
    {
        let fixture = Fixture::new(true, false);
        let store = RecordScratchStore::new(4 * 1024 * 1024).unwrap();
        store
            .put_record_if_absent(HEADS, b"orphan", b"unverified")
            .unwrap();
        assert!(
            CatalogPackingAuthority::from_legacy_checkpoint(
                fixture.certificate.hash().unwrap(),
                &fixture.certificate,
                store
            )
            .is_err()
        );
        let (mut missing_bootstrap, good_pages) = fixture.candidate(&fixture.records[..1]);
        missing_bootstrap.value.metadata = fixture.records[1].clone();
        let missing_bootstrap = missing_bootstrap
            .value
            .sign(&fixture.writer, &fixture.keys[0])
            .unwrap();
        assert!(
            fixture
                .authority()
                .with_paged_revision(&missing_bootstrap, |page| fetch(&good_pages, page))
                .is_err()
        );
        let mut conflict = fixture.records[0].clone();
        conflict.sector.root[0] ^= 1;
        let (conflict, pages) = fixture.candidate(&[conflict]);
        assert!(
            fixture
                .authority()
                .with_paged_revision(&conflict, |page| fetch(&pages, page))
                .is_err()
        );
        let (candidate, mut pages) = fixture.candidate(&fixture.records);
        pages
            .get_mut(&candidate.value.sources.records.page.hash)
            .unwrap()[0] ^= 1;
        assert!(
            fixture
                .authority()
                .with_paged_revision(&candidate, |page| fetch(&pages, page))
                .is_err()
        );
        assert!(
            fixture
                .authority()
                .with_paged_revision(&candidate, |_| Err(DatabaseError::NotReady.into()))
                .is_err()
        );
        let (manifest, pages) = fixture.packing(&fixture.records, &fixture.bytes);
        let mut authority = fixture.authority();
        authority.bytes = CATALOG_MAX_STREAM_BYTES;
        assert!(
            authority
                .validate_packing(manifest, |page| fetch(&pages, page))
                .is_err()
        );
        let mut authority = fixture.authority();
        authority.pages = CATALOG_MAX_PAGE_OCCURRENCES;
        assert!(
            authority
                .validate_packing(manifest, |page| fetch(&pages, page))
                .is_err()
        );
        let authority = fixture.authority();
        authority.store.database_shell_statement("CREATE TEMP TRIGGER ignore_authority_candidate BEFORE INSERT ON protocol_records WHEN NEW.kind='packing-authority-candidate' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
        let (candidate, pages) = fixture.candidate(&fixture.records);
        assert!(
            authority
                .with_paged_revision(&candidate, |page| fetch(&pages, page))
                .is_err()
        );
        fixture
            .authority()
            .with_paged_revision(&candidate, |page| fetch(&pages, page))
            .unwrap();
    }
    #[test]
    fn certified_coding_join_preserves_source_base_candidates_and_combined_admission() {
        let fixture = Fixture::new(true, false);
        let extra_bytes = vec![3; V1_SECTOR_SIZE];
        let extra = CatalogSectorRecord {
            format_version: 1,
            sector: mb_core::SectorRef {
                id: [3; 32],
                root: sector_root(&extra_bytes),
                logical_len: 17,
            },
            commitment: merkle_commit(&extra_bytes).unwrap(),
        };
        let (candidate, candidate_pages) =
            fixture.candidate(&[fixture.records[0].clone(), extra.clone()]);
        let mut records = fixture.records.clone();
        records.push(extra);
        let mut payloads = fixture.bytes.clone();
        payloads.push(extra_bytes);
        let (manifest, pages) = fixture.packing(&records, &payloads);
        let old = &fixture.certificate.checkpoint.revisions[0].value;
        let packed = pack_incremental(
            manifest.descriptors.profile,
            None,
            records
                .iter()
                .zip(&payloads)
                .map(|(record, bytes)| PackingInput {
                    owner: old.owner,
                    protected_root: packing_protected_root(old.protected_root_id),
                    object_id: record.sector.id,
                    source_commitment: Some(record.commitment.clone()),
                    bytes: bytes.clone(),
                })
                .collect(),
        )
        .unwrap();
        let packing = super::super::packing_validation::tests::Fixture {
            manifest,
            pages: pages
                .iter()
                .map(|(id, bytes)| (*id, bytes.clone()))
                .collect(),
            roles: [Vec::new(), Vec::new()],
            authority: BTreeMap::new(),
            sectors: packed.catalog.sectors,
            bytes: packed
                .sectors
                .into_iter()
                .map(|sector| sector.bytes)
                .collect(),
        };
        let entry = super::super::coding_coverage::tests::entry(&packing, [0, 1, 2], 400, 2, None);
        let mut coding_pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            coding_pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder = mb_core::CatalogCodingBuilder::new(manifest.scope, 100).unwrap();
        let other = super::super::coding_coverage::tests::entry(&packing, [3, 0, 1], 401, 2, None);
        let mut entries = [&entry, &other];
        entries.sort_by_key(|entry| entry.retained.group.id);
        for entry in entries {
            builder.push_group(entry, &mut sink).unwrap();
        }
        let coding = CatalogCodingValidation {
            format_version: 1,
            scope: manifest.scope,
            root: builder.finish(&mut sink).unwrap(),
        };
        let mut directory = mb_core::CatalogCodingDirectoryBuilder::new(
            manifest.scope,
            100,
            CatalogCodingTraversalBudget {
                bytes: 96 * 1024 * 1024 * 1024,
                page_occurrences: 2_000_000,
                records: 64_000_000,
            },
        )
        .unwrap();
        for entry in entries {
            directory.push_group(entry, &mut sink).unwrap();
        }
        let directory = directory.finish(&mut sink).unwrap();
        let authority = fixture
            .authority()
            .with_paged_revision(&candidate, |page| fetch(&candidate_pages, page))
            .unwrap();
        let (authority_bytes, authority_pages) = (authority.bytes, authority.pages);
        let authority_records = authority.records;
        let checked = authority
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
        assert_eq!(manifest.descriptors.sectors, packing.sectors.len() as u64);
        for sector in &packing.sectors {
            assert!(
                checked.index.sector(sector.id).unwrap().is_some(),
                "input ID absent from packing"
            );
        }
        let base = checked.base();
        let checked = checked
            .validate_coding(
                coding.clone(),
                CatalogCodingCoveragePolicy::Current,
                |page| fetch(&coding_pages, page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap();
        assert_eq!(checked.base(), base);
        assert_eq!(checked.candidate_count(), 1);
        assert_eq!(
            checked.next_paged_revision(None).unwrap(),
            Some(candidate.clone())
        );
        assert!(
            checked
                .next_paged_revision(Some((&candidate.value).into()))
                .unwrap()
                .is_none()
        );
        let (bytes, pages_count) = checked.index().manifest().represented_work().unwrap();
        assert_eq!(
            checked.represented_work().unwrap(),
            (authority_bytes + bytes, authority_pages + pages_count)
        );
        for sector in &packing.sectors {
            assert!(checked.index().coverage(sector.id).unwrap().is_some());
        }
        assert_eq!(
            checked
                .index()
                .read_group(entry.retained.group.id, |page| fetch(&coding_pages, page))
                .unwrap(),
            Some(entry.clone())
        );
        let prior_work = CatalogCodingTraversalBudget {
            bytes: authority_bytes,
            page_occurrences: authority_pages,
            records: authority_records,
        };
        assert_eq!(
            authority_records,
            2 + candidate.value.sources.records.records
        );
        let proposed = CatalogPackingCodingDirectoryValidation {
            format_version: 1,
            packing: manifest,
            coding: directory,
            policy: CatalogCodingCoveragePolicy::Current,
            prior_work,
        };
        let work = proposed.represented_work().unwrap();
        let rebuild = || {
            fixture
                .authority()
                .with_paged_revision(&candidate, |page| fetch(&candidate_pages, page))
                .unwrap()
                .validate_packing(manifest, |page| fetch(&pages, page))
                .unwrap()
        };
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                rebuild()
                    .validate_coding_directory(
                        directory,
                        proposed.policy,
                        limit,
                        |_| panic!("over-budget certified directory fetched pages"),
                        |_| panic!("over-budget certified directory authorized groups")
                    )
                    .is_err()
            );
        }
        let joined = rebuild()
            .validate_coding_directory(
                directory,
                proposed.policy,
                work,
                |page| fetch(&coding_pages, page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap();
        assert_eq!(joined.base(), base);
        assert_eq!(joined.candidate_count(), 1);
        assert_eq!(joined.index().manifest(), proposed);
        assert_eq!(joined.represented_work().unwrap(), work);
        assert_eq!(
            joined.index().manifest().coding_budget(work).unwrap(),
            directory.work().unwrap()
        );
        assert_eq!(
            joined.next_paged_revision(None).unwrap(),
            Some(candidate.clone())
        );
        assert!(
            joined
                .next_paged_revision(Some((&candidate.value).into()))
                .unwrap()
                .is_none()
        );
        for sector in &packing.sectors {
            assert!(joined.index().coverage(sector.id).unwrap().is_some());
        }
        assert_eq!(
            joined
                .index()
                .read_group(entry.retained.group.id, |page| fetch(&coding_pages, page))
                .unwrap(),
            Some(entry)
        );
        let mut checked = fixture
            .authority()
            .with_paged_revision(&candidate, |page| fetch(&candidate_pages, page))
            .unwrap()
            .validate_packing(manifest, |page| fetch(&pages, page))
            .unwrap();
        checked.authority_pages = CATALOG_MAX_PAGE_OCCURRENCES;
        assert!(
            checked
                .validate_coding(
                    coding,
                    CatalogCodingCoveragePolicy::Current,
                    |_| panic!("over-budget authority fetched pages"),
                    |_| panic!("over-budget authority authorized groups")
                )
                .is_err()
        );
        assert_eq!(
            check_coding_work(
                1,
                1,
                mb_core::CATALOG_CODING_MAX_BYTES - 1,
                CATALOG_MAX_PAGE_OCCURRENCES - 1
            )
            .unwrap(),
            (
                mb_core::CATALOG_CODING_MAX_BYTES,
                CATALOG_MAX_PAGE_OCCURRENCES
            )
        );
        assert!(check_coding_work(1, 0, mb_core::CATALOG_CODING_MAX_BYTES, 0).is_err());
        assert!(check_coding_work(u64::MAX, 0, 1, 0).is_err());
        assert!(check_coding_work(0, u64::MAX, 0, 1).is_err());
    }
}
