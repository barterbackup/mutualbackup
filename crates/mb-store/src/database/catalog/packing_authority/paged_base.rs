//! Transfer completed original paged authority into a fresh packing job.
//! No flat checkpoint, revision vector or catalog-wide source list is built.

use super::super::checkpoint_body::{Body, Header};
use super::*;
use mb_core::{CatalogCheckpointAuthorityRecord as R, PagedCheckpointTrust, RevisionTombstone};

macro_rules! constructors {
    ($proof:ty, $name:ident) => {
        impl CatalogPackingAuthority {
            /// Import a completed original-history proof for this independently
            /// trusted checkpoint hash. The original public body/source EOFs,
            /// quorum and legal transition are required; a signed header alone
            /// cannot enter this constructor. Publication must still recheck
            /// the actual current base/event scope and private/payload custody.
            /// The supplied credits include original authority and this bounded
            /// certificate, plus any later candidates and packing construction.
            pub fn $name(
                trusted_hash: [u8; 32],
                proof: &$proof,
                store: RecordScratchStore,
                budget: CatalogCodingTraversalBudget,
            ) -> Result<Self, CatalogStoreError> {
                if trusted_hash == [0; 32]
                    || proof.certificate().hash()? != trusted_hash
                    || !proof.transition().has_certified_history_transition()
                {
                    return Err(DatabaseError::Conflict.into());
                }
                proof.recheck_header(|| Ok(proof.trust().clone()))?;
                let bytes = canonical_size_bounded(
                    proof.certificate(),
                    mb_core::PAGED_QUORUM_CHECKPOINT_BYTES,
                )? as u64;
                let base = CatalogPackingAuthorityBase {
                    guild_id: proof.certificate().checkpoint.guild_id,
                    checkpoint_hash: trusted_hash,
                    generation: proof.certificate().checkpoint.generation,
                    membership_epoch: Some(
                        proof.certificate().checkpoint.authority.membership_epoch,
                    ),
                };
                let job = Self::import_paged_base(
                    base,
                    proof.index(),
                    proof.trust(),
                    store,
                    budget,
                    bytes,
                )?;
                proof.recheck_header(|| Ok(proof.trust().clone()))?;
                Ok(job)
            }
        }
    };
}
constructors!(CatalogQuorumPagedCheckpointIndex, from_paged_checkpoint);
constructors!(
    CatalogQuorumPagedCheckpointDirectoryIndex,
    from_paged_checkpoint_directory
);

fn typed<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T, CatalogStoreError> {
    let value: T = decode_canonical(bytes)?;
    if encoded(&value, EVIDENCE_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

fn validate_fact(
    kind: &str,
    key: &[u8],
    bytes: &[u8],
    base: CatalogPackingAuthorityBase,
    members: usize,
) -> Result<(), CatalogStoreError> {
    let valid = match kind {
        FENCES => {
            let fence: WriterFence = typed(bytes)?;
            let public = ed25519_dalek::VerifyingKey::from_bytes(&fence.public_key)
                .map_err(ModelError::from)?;
            key == fence.owner.0
                && fence.owner != NodeId([0; 32])
                && fence.epoch != 0
                && !public.is_weak()
        }
        SOURCES => {
            let value: Source = typed(bytes)?;
            value.id.validate()?;
            let commitment = value.commitment.ok_or(DatabaseError::Integrity)?;
            key == source_key(value.id)
                && value.flat_root != [0; 32]
                && commitment.byte_len as usize == V1_SECTOR_SIZE
                && commitment.validate().is_ok()
        }
        BINDINGS => {
            let signed: SignedRecord<LegacyPackingBinding> = typed(bytes)?;
            signed.verify(LEGACY_PACKING_BINDING_DOMAIN)?;
            let value = signed.value;
            let id = CatalogPackedSourceId {
                owner: value.owner,
                protected_root: value.protected_root,
                object_id: value.object_id,
            };
            id.validate()?;
            key == id.key()
                && signed.signer == value.owner
                && value.format_version == 1
                && value.flat_root != [0; 32]
                && value.source_commitment.validate().is_ok()
                && value.source_commitment.byte_len as usize == V1_SECTOR_SIZE
        }
        ATTESTATIONS => {
            let signed: SignedRecord<LegacyPackingAttestation> = typed(bytes)?;
            signed.verify(LEGACY_PACKING_ATTESTATION_DOMAIN)?;
            let value = signed.value;
            let id = CatalogPackedSourceId {
                owner: value.owner,
                protected_root: value.protected_root,
                object_id: value.object_id,
            };
            id.validate()?;
            key.len() == 64
                && key[..32] == id.key()
                && key[32..] == signed.signer.0
                && value.format_version == 1
                && value.guild_id == base.guild_id
                && Some(value.membership_epoch) == base.membership_epoch
                && value.flat_root != [0; 32]
                && value.source_commitment.validate().is_ok()
                && value.source_commitment.byte_len as usize == V1_SECTOR_SIZE
        }
        TALLIES => {
            let value: Tally = typed(bytes)?;
            key.len() == 32
                && value.signers != 0
                && usize::from(value.signers) <= members
                && value.commitment.validate().is_ok()
                && value.commitment.byte_len as usize == V1_SECTOR_SIZE
        }
        TOMBSTONES => {
            let value: RevisionTombstone = typed(bytes)?;
            key == chain(value.owner, value.protected_root_id)
                && value.owner != NodeId([0; 32])
                && !value.protected_root_id.is_nil()
                && value.through_sequence != 0
                && !value.last_revision_id.is_nil()
                && value.last_revision_hash != [0; 32]
                && value.retired_at_generation >= 2
                && value.retired_at_generation <= base.generation
        }
        _ => false,
    };
    if !valid {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

impl CatalogPackingAuthority {
    fn import_paged_base<I: Body>(
        base: CatalogPackingAuthorityBase,
        body: &I,
        trust: &PagedCheckpointTrust,
        store: RecordScratchStore,
        budget: CatalogCodingTraversalBudget,
        certificate_bytes: u64,
    ) -> Result<Self, CatalogStoreError> {
        if body.header(trust)?.hash()? != base.checkpoint_hash {
            return Err(DatabaseError::Conflict.into());
        }
        let work = body
            .authority_work()
            .checked_add(CatalogCodingTraversalBudget {
                bytes: certificate_bytes,
                page_occurrences: 0,
                records: 1,
            })?;
        budget.remaining_after(work)?;
        let source_count = body.source_count();
        if source_count > work.records {
            return Err(DatabaseError::Integrity.into());
        }
        let summary = body.authority().root.summary;
        let job = Self {
            base,
            store,
            required_signers: trust
                .authority
                .quorum
                .required(trust.members.len())
                .map_err(|_| DatabaseError::Conflict)?,
            sources: source_count,
            authenticated: source_count,
            candidates: 0,
            bytes: work.bytes,
            pages: work.page_occurrences,
            records: work.records,
            limit: Some(budget),
        };
        job.check_budget(0, 0)?;
        job.store
            .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                for kind in KINDS {
                    if job
                        .store
                        .next_record_metadata_bounded(kind, None, 96)?
                        .is_some()
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                }
                for member in &trust.members {
                    insert(&job.store, MEMBERS, &member.node_id.0, &true, ROW_BYTES)?;
                }
                // Copy only typed authority facts. Existing packing/coding/proposal
                // indexes and candidate rows stay in the original disposable proof.
                for (origin, target, count_limit) in [
                    (FENCES, FENCES, summary.writer_fences),
                    (SOURCES, SOURCES, source_count),
                    (BINDINGS, BINDINGS, summary.bindings),
                    (ATTESTATIONS, ATTESTATIONS, summary.attestations),
                    (TALLIES, TALLIES, source_count),
                    (
                        super::super::checkpoint_validation::TOMBSTONES,
                        TOMBSTONES,
                        summary.tombstones,
                    ),
                ] {
                    let mut after = None;
                    let mut count = 0_u64;
                    while let Some((key, bytes)) = body.store().next_record_bounded(
                        origin,
                        after.as_deref(),
                        96,
                        EVIDENCE_BYTES,
                    )? {
                        count = count.checked_add(1).ok_or(CatalogError::Bounds)?;
                        if count > count_limit {
                            return Err(DatabaseError::Integrity.into());
                        }
                        validate_fact(target, &key, &bytes, base, trust.members.len())?;
                        if !job.store.put_record_if_absent(target, &key, &bytes)?
                            || job
                                .store
                                .get_record_bounded(target, &key, EVIDENCE_BYTES)?
                                .as_deref()
                                != Some(&bytes)
                        {
                            return Err(DatabaseError::Integrity.into());
                        }
                        if target == TOMBSTONES {
                            let tombstone: RevisionTombstone = typed(&bytes)?;
                            insert(
                                &job.store,
                                IDS,
                                tombstone.last_revision_id.as_bytes(),
                                &true,
                                ROW_BYTES,
                            )?;
                        }
                        after = Some(key);
                    }
                    if (target == SOURCES && count != source_count)
                        || (target == TOMBSTONES && count != summary.tombstones)
                    {
                        return Err(DatabaseError::Integrity.into());
                    }
                }
                let mut after = None;
                let mut revisions = 0_u64;
                while let Some(record) = body.next_revision(after)? {
                    let (key, hash, epoch) = match record {
                        R::PagedRevision(signed) => (
                            CatalogCheckpointRevisionKey::from(&signed.value),
                            signed.value.hash()?,
                            signed.value.writer_epoch,
                        ),
                        R::LegacyRevision(reference) => (
                            CatalogCheckpointRevisionKey::from(&reference),
                            reference.revision_hash,
                            reference.writer_epoch,
                        ),
                        _ => return Err(DatabaseError::Integrity.into()),
                    };
                    if after.is_some_and(|previous| previous >= key) {
                        return Err(DatabaseError::Integrity.into());
                    }
                    revisions += 1;
                    if revisions > summary.revisions {
                        return Err(DatabaseError::Integrity.into());
                    }
                    insert(
                        &job.store,
                        IDS,
                        key.revision_id.as_bytes(),
                        &true,
                        ROW_BYTES,
                    )?;
                    let id = chain(key.owner, key.protected_root_id);
                    let head = Head {
                        sequence: key.sequence,
                        hash,
                        writer_epoch: epoch,
                    };
                    if let Some((_, bytes)) = read::<Head>(&job.store, HEADS, &id)? {
                        replace(&job.store, HEADS, &id, &bytes, &head)?;
                    } else {
                        insert(&job.store, HEADS, &id, &head, ROW_BYTES)?;
                    }
                    after = Some(key);
                }
                if revisions != summary.revisions {
                    return Err(DatabaseError::Integrity.into());
                }
                body.header(trust)?;
                job.check_budget(0, 0)
            })?;
        // The constructor owns the new store and discards it on every error.
        // No mutable view of the original completed proof escapes this transfer.
        job.check_budget(0, 0)?;
        Ok(job)
    }
}
