//! Complete public authority joins for an authenticated checkpoint root.
//! Current event trust, certificate publication and private/payload joins remain
//! the enclosing checkpoint's responsibility.

use mb_core::{
    CATALOG_CHECKPOINT_RECORD_BYTES, CatalogCheckpointAuthorityReader,
    CatalogCheckpointAuthorityRecord, CatalogCheckpointAuthorityRoot, CatalogCheckpointRevisionKey,
    CatalogCodingDirectoryRoot, CatalogCodingTraversalBudget, CatalogPackedSourceId,
    CheckpointAuthority, Member, MerkleCommitment, PagedRevisionSourceReader, PagedUserRevision,
    RevisionTombstone, V1_SECTOR_SIZE, WriterFence, packing_protected_root,
};

use super::packing_authority::{
    self as sources, ATTESTATIONS, BINDINGS, EVIDENCE_BYTES, FENCES, HEADS, Head, IDS, MEMBERS,
    ROW_BYTES, SOURCES, TALLIES, Tally, add_source, chain, encoded, insert, read, replace, source,
    source_key,
};
use super::packing_validation::{build_index, unwrap_stream};
use super::*;
use crate::RecordScratchStore;

const MANIFEST_BYTES: usize = 2048;
const COMPLETE: &str = "checkpoint-authority-complete";
pub(super) const HISTORY: &str = "checkpoint-authority-writer-history";
const USED: &str = "checkpoint-authority-latest-writer-used";
pub(super) const TOMBSTONES: &str = "checkpoint-authority-tombstone";
const OBJECTS: &str = "checkpoint-authority-source-object";
pub(super) const REVISIONS: &str = "checkpoint-authority-revision";
pub(super) const IDENTITIES: &str = "checkpoint-authority-revision-identity";
pub(super) const MEMBER_RECORDS: &str = "checkpoint-authority-member";
pub(super) const MEMBER_BYTES: usize = 512;
const KINDS: [&str; 8] = [
    COMPLETE,
    HISTORY,
    USED,
    TOMBSTONES,
    OBJECTS,
    REVISIONS,
    MEMBER_RECORDS,
    IDENTITIES,
];

/// Trusted enclosing event snapshot, not a claim learned from the proposed
/// root. Callers must obtain this and the active members from certified guild
/// history, then recheck the same snapshot before signing/publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointAuthorityContext {
    pub guild_id: [u8; 32],
    pub generation: u64,
    pub event_sequence: u64,
    pub event_head: [u8; 32],
    pub authority: CheckpointAuthority,
}

/// A bounded local descriptor. It is not a certificate or a completion token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CatalogCheckpointAuthorityValidation {
    pub format_version: u16,
    pub context: CatalogCheckpointAuthorityContext,
    pub root: CatalogCheckpointAuthorityRoot,
}

impl CatalogCheckpointAuthorityValidation {
    pub fn decode(
        bytes: &[u8],
        budget: CatalogCodingTraversalBudget,
    ) -> Result<Self, CatalogStoreError> {
        if bytes.is_empty() || bytes.len() > MANIFEST_BYTES {
            return Err(CatalogError::Bounds.into());
        }
        let manifest: Self = decode_canonical(bytes)?;
        manifest.validate(budget)?;
        if encoded(&manifest, MANIFEST_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(manifest)
    }

    fn scope(self) -> CatalogScope {
        CatalogScope::Guild {
            guild_id: self.context.guild_id,
        }
    }

    pub fn minimum_work(self) -> Result<CatalogCodingTraversalBudget, CatalogStoreError> {
        Ok(CatalogCodingTraversalBudget {
            // This descriptor embeds the authority root. Replace its original
            // encoded envelope with this fixed descriptor reservation.
            bytes: self
                .root
                .records
                .page
                .byte_len
                .checked_add(self.root.summary.legacy_bytes)
                .and_then(|bytes| bytes.checked_add(self.root.summary.source_bytes))
                .and_then(|bytes| bytes.checked_add(MANIFEST_BYTES as u64))
                .ok_or(CatalogError::Bounds)?,
            page_occurrences: self.root.page_occurrences()?,
            // Legacy envelopes are bounded objects; their source entries and
            // paged-source frames are charged separately as they are admitted.
            records: self
                .root
                .records
                .records
                .checked_add(self.root.summary.legacy_revisions)
                .ok_or(CatalogError::Bounds)?,
        })
    }

    pub fn validate(self, budget: CatalogCodingTraversalBudget) -> Result<(), CatalogStoreError> {
        self.scope().validate(CatalogSection::Checkpoint)?;
        self.root.validate_with_budget(budget)?;
        if !matches!(
            (self.format_version, self.root.format_version),
            (1, 1) | (2, 2)
        ) || self.context.event_head == [0; 32]
            || self.context.generation != self.root.generation
            || self.context.authority.format_version != 1
            || self.context.authority.membership_epoch != self.root.membership_epoch
            || self
                .context
                .authority
                .quorum
                .required(self.root.summary.members as usize)
                .is_err()
        {
            return Err(DatabaseError::Conflict.into());
        }
        encoded(&self, MANIFEST_BYTES)?;
        budget.remaining_after(self.minimum_work()?)?;
        Ok(())
    }
}

/// Every retained fence must match certified writer history. Its latest epoch
/// must also be the retained owner's authorized checkpoint head. Removed owners
/// may retain historical sources; this callback must enforce that distinction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogCheckpointWriterAuthorization {
    Historical,
    LatestRetained,
}

pub(super) fn fence_key(fence: &WriterFence) -> [u8; 40] {
    let mut key = [0; 40];
    key[..32].copy_from_slice(&fence.owner.0);
    key[32..].copy_from_slice(&fence.epoch.to_be_bytes());
    key
}

fn put_latest(store: &RecordScratchStore, fence: &WriterFence) -> Result<(), CatalogStoreError> {
    if let Some((_, bytes)) = read::<WriterFence>(store, FENCES, &fence.owner.0)? {
        replace(store, FENCES, &fence.owner.0, &bytes, fence)?;
    } else {
        insert(store, FENCES, &fence.owner.0, fence, ROW_BYTES)?;
    }
    Ok(())
}

fn add_checked_source(
    store: &RecordScratchStore,
    id: CatalogPackedSourceId,
    sector: &mb_core::SectorRef,
    commitment: Option<MerkleCommitment>,
) -> Result<(u64, u64), CatalogStoreError> {
    id.validate()?;
    if let Some((previous, _)) =
        read::<(CatalogPackedSourceId, mb_core::SectorRef)>(store, OBJECTS, &id.object_id)?
    {
        if previous != (id, sector.clone()) {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        insert(store, OBJECTS, &id.object_id, &(id, sector), ROW_BYTES)?;
    }
    add_source(store, id, sector.root, commitment)
}

fn admit_records(
    work: &mut CatalogCodingTraversalBudget,
    records: u64,
    budget: CatalogCodingTraversalBudget,
) -> Result<(), CatalogStoreError> {
    *work = work.checked_add(CatalogCodingTraversalBudget {
        records,
        ..Default::default()
    })?;
    budget.remaining_after(*work)?;
    Ok(())
}

fn first_or_next(
    store: &RecordScratchStore,
    key: CatalogCheckpointRevisionKey,
    parent: Option<[u8; 32]>,
    writer_epoch: u64,
) -> Result<(), CatalogStoreError> {
    let id = chain(key.owner, key.protected_root_id);
    if let Some((head, _)) = read::<Head>(store, HEADS, &id)? {
        if head.sequence.checked_add(1) != Some(key.sequence)
            || parent != Some(head.hash)
            || writer_epoch < head.writer_epoch
        {
            return Err(DatabaseError::Conflict.into());
        }
    } else {
        match read::<RevisionTombstone>(store, TOMBSTONES, &id)? {
            Some((tombstone, _))
                if tombstone.through_sequence.checked_add(1) == Some(key.sequence)
                    && parent == Some(tombstone.last_revision_hash) => {}
            None if key.sequence == 1 && parent.is_none() => {}
            _ => return Err(DatabaseError::Conflict.into()),
        }
    }
    insert(store, IDS, key.revision_id.as_bytes(), &true, ROW_BYTES)
}

fn finish_revision(
    store: &RecordScratchStore,
    key: CatalogCheckpointRevisionKey,
    hash: [u8; 32],
    writer_epoch: u64,
) -> Result<(), CatalogStoreError> {
    let id = chain(key.owner, key.protected_root_id);
    let head = Head {
        sequence: key.sequence,
        hash,
        writer_epoch,
    };
    if let Some((_, bytes)) = read::<Head>(store, HEADS, &id)? {
        replace(store, HEADS, &id, &bytes, &head)?;
    } else {
        insert(store, HEADS, &id, &head, ROW_BYTES)?;
    }
    let (latest, _) =
        read::<WriterFence>(store, FENCES, &key.owner.0)?.ok_or(DatabaseError::NotReady)?;
    if latest.epoch == writer_epoch {
        if let Some((_, bytes)) = read::<bool>(store, USED, &key.owner.0)? {
            replace(store, USED, &key.owner.0, &bytes, &true)?;
        } else {
            insert(store, USED, &key.owner.0, &true, ROW_BYTES)?;
        }
    }
    Ok(())
}

fn evidence(
    store: &RecordScratchStore,
    id: CatalogPackedSourceId,
    flat_root: [u8; 32],
    commitment: &MerkleCommitment,
) -> Result<(sources::Source, Vec<u8>), CatalogStoreError> {
    let (source, bytes) = source(store, id)?;
    if source.flat_root != flat_root
        || source
            .commitment
            .as_ref()
            .is_some_and(|previous| previous != commitment)
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok((source, bytes))
}

/// Complete disposable public-authority proof. Construction holds only its
/// admitted scratch transaction, never a production database writer. A failed
/// build rolls back all namespaces; no usable prefix or completion marker exists.
pub struct CatalogCheckpointAuthorityIndex {
    manifest: CatalogCheckpointAuthorityValidation,
    budget: CatalogCodingTraversalBudget,
    work: CatalogCodingTraversalBudget,
    source_count: u64,
    store: RecordScratchStore,
}

impl CatalogCheckpointAuthorityIndex {
    /// Roots are authenticated by the enclosing checkpoint. The context and
    /// exact active member list come from independently certified current events.
    /// Writer callbacks must check that same history, including removed owners.
    /// This does not validate a previous checkpoint transition, private joins,
    /// payload custody, coding lifecycle or a quorum certificate.
    pub fn build(
        context: CatalogCheckpointAuthorityContext,
        root: CatalogCheckpointAuthorityRoot,
        members: &[Member],
        budget: CatalogCodingTraversalBudget,
        store: RecordScratchStore,
        mut fetch: impl FnMut(
            CatalogScope,
            CatalogSection,
            CatalogPageRef,
        ) -> Result<Vec<u8>, CatalogStoreError>,
        mut authorize: impl FnMut(
            &WriterFence,
            CatalogCheckpointWriterAuthorization,
        ) -> Result<(), CatalogStoreError>,
    ) -> Result<Self, CatalogStoreError> {
        let manifest = CatalogCheckpointAuthorityValidation {
            format_version: root.format_version,
            context,
            root,
        };
        manifest.validate(budget)?;
        if members.len() != root.summary.members as usize {
            return Err(DatabaseError::Conflict.into());
        }
        let mut work = manifest.minimum_work()?;
        let mut count = 0_u64;
        let mut authenticated = 0_u64;
        let required = context
            .authority
            .quorum
            .required(members.len())
            .map_err(|_| DatabaseError::Conflict)?;
        store.with_record_transaction(|| -> Result<(), CatalogStoreError> {
            for kind in sources::KINDS.into_iter().chain(KINDS) {
                if store
                    .next_record_bounded(kind, None, 96, CATALOG_CHECKPOINT_RECORD_BYTES)?
                    .is_some()
                {
                    return Err(DatabaseError::Conflict.into());
                }
            }
            let mut reader =
                CatalogCheckpointAuthorityReader::new_with_budget(manifest.scope(), root, budget)?;
            let mut member_index = 0;
            while let Some(record) = unwrap_stream(reader.next_record(&mut |page| {
                fetch(manifest.scope(), CatalogSection::Checkpoint, page)
            }))? {
                use CatalogCheckpointAuthorityRecord as R;
                match &record {
                    R::Member(member) => {
                        if members.get(member_index) != Some(member) {
                            return Err(DatabaseError::Conflict.into());
                        }
                        insert(&store, MEMBERS, &member.node_id.0, &true, ROW_BYTES)?;
                        insert(
                            &store,
                            MEMBER_RECORDS,
                            &member.node_id.0,
                            member,
                            MEMBER_BYTES,
                        )?;
                        member_index += 1;
                    }
                    R::WriterFence(fence) => {
                        authorize(fence, CatalogCheckpointWriterAuthorization::Historical)?;
                        insert(&store, HISTORY, &fence_key(fence), fence, ROW_BYTES)?;
                        put_latest(&store, fence)?;
                    }
                    R::Tombstone(tombstone) => {
                        insert(
                            &store,
                            TOMBSTONES,
                            &chain(tombstone.owner, tombstone.protected_root_id),
                            tombstone,
                            ROW_BYTES,
                        )?;
                        // Retired IDs remain globally reserved too.
                        insert(
                            &store,
                            IDS,
                            tombstone.last_revision_id.as_bytes(),
                            &true,
                            ROW_BYTES,
                        )?;
                    }
                    R::LegacyRevision(reference) => {
                        let key = CatalogCheckpointRevisionKey::from(reference);
                        first_or_next(&store, key, reference.parent, reference.writer_epoch)?;
                        let expected = WriterFence {
                            owner: reference.owner,
                            epoch: reference.writer_epoch,
                            public_key: reference.writer_public_key,
                        };
                        if read::<WriterFence>(&store, HISTORY, &fence_key(&expected))?
                            .map(|row| row.0)
                            != Some(expected)
                        {
                            return Err(ModelError::InvalidWriterFence.into());
                        }
                        let signed = unwrap_stream(reference.read_signed(&mut |page| {
                            fetch(manifest.scope(), CatalogSection::Checkpoint, page)
                        }))?;
                        let identity =
                            super::checkpoint_transition::RevisionIdentity::legacy(&signed)?;
                        insert(
                            &store,
                            IDENTITIES,
                            &key.index_key(),
                            &identity.bind_reference(&record)?,
                            ROW_BYTES,
                        )?;
                        let body = &signed.value;
                        let source_records = body
                            .metadata_sectors
                            .len()
                            .checked_add(body.data_sectors.len())
                            .ok_or(CatalogError::Bounds)?;
                        admit_records(&mut work, source_records as u64, budget)?;
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
                            let (new, auth) = add_checked_source(&store, id, sector, commitment)?;
                            count += new;
                            authenticated += auth;
                        }
                        finish_revision(
                            &store,
                            key,
                            reference.revision_hash,
                            reference.writer_epoch,
                        )?;
                    }
                    R::PagedRevision(signed) => {
                        let body = &signed.value;
                        let key = CatalogCheckpointRevisionKey::from(body);
                        let identity =
                            super::checkpoint_transition::RevisionIdentity::paged(signed)?;
                        insert(
                            &store,
                            IDENTITIES,
                            &key.index_key(),
                            &identity.bind_reference(&record)?,
                            ROW_BYTES,
                        )?;
                        first_or_next(&store, key, body.parent, body.writer_epoch)?;
                        let expected = WriterFence {
                            owner: body.owner,
                            epoch: body.writer_epoch,
                            public_key: body.writer_public_key,
                        };
                        let (fence, _) =
                            read::<WriterFence>(&store, HISTORY, &fence_key(&expected))?
                                .ok_or(ModelError::InvalidWriterFence)?;
                        let mut sources = PagedRevisionSourceReader::new(
                            signed,
                            context.guild_id,
                            body.owner,
                            &fence,
                        )?;
                        // Admit declared nested records before any source-page fetch.
                        admit_records(&mut work, body.sources.records.records, budget)?;
                        while let Some(source) = unwrap_stream(sources.next_sector(&mut |page| {
                            fetch(body.scope(), CatalogSection::SectorReferences, page)
                        }))? {
                            let id = CatalogPackedSourceId {
                                owner: body.owner,
                                protected_root: packing_protected_root(body.protected_root_id),
                                object_id: source.sector.id,
                            };
                            let (new, auth) = add_checked_source(
                                &store,
                                id,
                                &source.sector,
                                Some(source.commitment),
                            )?;
                            count += new;
                            authenticated += auth;
                        }
                        if !sources.is_complete() {
                            return Err(DatabaseError::Integrity.into());
                        }
                        finish_revision(&store, key, body.hash()?, body.writer_epoch)?;
                    }
                    R::LegacyBinding(signed) => {
                        let value = &signed.value;
                        let id = CatalogPackedSourceId {
                            owner: value.owner,
                            protected_root: value.protected_root,
                            object_id: value.object_id,
                        };
                        let (mut source, previous) =
                            evidence(&store, id, value.flat_root, &value.source_commitment)?;
                        if source.commitment.is_some() {
                            return Err(DatabaseError::Conflict.into());
                        }
                        insert(&store, BINDINGS, &id.key(), signed, EVIDENCE_BYTES)?;
                        source.commitment = Some(value.source_commitment.clone());
                        replace(&store, SOURCES, &source_key(id), &previous, &source)?;
                        authenticated += 1;
                    }
                    R::LegacyAttestation(signed) => {
                        let value = &signed.value;
                        let id = CatalogPackedSourceId {
                            owner: value.owner,
                            protected_root: value.protected_root,
                            object_id: value.object_id,
                        };
                        if read::<bool>(&store, MEMBERS, &signed.signer.0)?.map(|row| row.0)
                            != Some(true)
                        {
                            return Err(DatabaseError::Conflict.into());
                        }
                        let (mut source, previous) =
                            evidence(&store, id, value.flat_root, &value.source_commitment)?;
                        let tally = read::<Tally>(&store, TALLIES, &id.key())?;
                        let signers = match &tally {
                            Some((tally, _)) if tally.commitment == value.source_commitment => {
                                tally.signers.checked_add(1).ok_or(CatalogError::Bounds)?
                            }
                            None if source.commitment.is_none() => 1,
                            _ => return Err(DatabaseError::Conflict.into()),
                        };
                        let mut key = [0; 64];
                        key[..32].copy_from_slice(&id.key());
                        key[32..].copy_from_slice(&signed.signer.0);
                        insert(&store, ATTESTATIONS, &key, signed, EVIDENCE_BYTES)?;
                        let next = Tally {
                            commitment: value.source_commitment.clone(),
                            signers,
                        };
                        if let Some((_, previous)) = &tally {
                            replace(&store, TALLIES, &id.key(), previous, &next)?;
                        } else {
                            insert(&store, TALLIES, &id.key(), &next, ROW_BYTES)?;
                        }
                        if source.commitment.is_none() && signers as usize >= required {
                            source.commitment = Some(value.source_commitment.clone());
                            replace(&store, SOURCES, &source_key(id), &previous, &source)?;
                            authenticated += 1;
                        }
                    }
                }
                if let Some(key) = record.revision_key() {
                    insert(
                        &store,
                        REVISIONS,
                        &key.index_key(),
                        &record,
                        CATALOG_CHECKPOINT_RECORD_BYTES,
                    )?;
                }
            }
            if member_index != members.len() || authenticated != count {
                return Err(DatabaseError::Conflict.into());
            }
            let mut after = None;
            while let Some((key, bytes)) =
                store.next_record_bounded(FENCES, after.as_deref(), 32, ROW_BYTES)?
            {
                let fence: WriterFence = super::coding_coverage::decode_row(&bytes)?;
                if key != fence.owner.0
                    || read::<bool>(&store, USED, &key)?.map(|row| row.0) != Some(true)
                {
                    return Err(DatabaseError::Conflict.into());
                }
                authorize(&fence, CatalogCheckpointWriterAuthorization::LatestRetained)?;
                after = Some(key);
            }
            let mut after = None;
            while let Some((key, bytes)) =
                store.next_record_bounded(TOMBSTONES, after.as_deref(), 48, ROW_BYTES)?
            {
                let tombstone: RevisionTombstone = super::coding_coverage::decode_row(&bytes)?;
                if key != chain(tombstone.owner, tombstone.protected_root_id)
                    || read::<Head>(&store, HEADS, &key)?.is_none()
                {
                    return Err(DatabaseError::Conflict.into());
                }
                after = Some(key);
            }
            // Exact source authentication above also rules out incomplete
            // migration tallies and unused/redundant evidence.
            insert(
                &store,
                COMPLETE,
                b"root",
                &(manifest, work, count),
                MANIFEST_BYTES,
            )?;
            Ok(())
        })?;
        Ok(Self {
            manifest,
            budget,
            work,
            source_count: count,
            store,
        })
    }

    pub fn manifest(&self) -> CatalogCheckpointAuthorityValidation {
        self.manifest
    }
    pub fn represented_work(&self) -> CatalogCodingTraversalBudget {
        self.work
    }
    pub fn source_count(&self) -> u64 {
        self.source_count
    }

    fn require_complete(&self) -> Result<(), CatalogStoreError> {
        require_authority(
            &self.store,
            self.manifest,
            self.work,
            self.source_count,
            self.budget,
        )
    }

    pub fn next_revision(
        &self,
        after: Option<CatalogCheckpointRevisionKey>,
    ) -> Result<Option<CatalogCheckpointAuthorityRecord>, CatalogStoreError> {
        self.require_complete()?;
        next_revision(&self.store, self.manifest.context.guild_id, after)
    }

    pub fn next_source(
        &self,
        after: Option<CatalogPackedSourceId>,
    ) -> Result<Option<CatalogPackingAuthorizedSource>, CatalogStoreError> {
        self.require_complete()?;
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
        let value: sources::Source = super::coding_coverage::decode_row(&bytes)?;
        value.id.validate()?;
        let commitment = value.commitment.ok_or(DatabaseError::Integrity)?;
        if key != source_key(value.id)
            || commitment.byte_len as usize != V1_SECTOR_SIZE
            || commitment.validate().is_err()
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(CatalogPackingAuthorizedSource {
            id: value.id,
            flat_root: value.flat_root,
            commitment,
        }))
    }

    pub fn validate_packing(
        self,
        manifest: CatalogPackingValidation,
        mut fetch: impl FnMut(CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError>,
    ) -> Result<CatalogCheckpointPackingIndex, CatalogStoreError> {
        self.require_complete()?;
        let packing_budget = self.budget.remaining_after(self.work)?;
        manifest.validate_with_budget(packing_budget)?;
        if manifest.scope != self.manifest.scope() || manifest.sources.sources != self.source_count
        {
            return Err(DatabaseError::Conflict.into());
        }
        // Reserve the same combined descriptor used by the directory join.
        // This is a trusted shared ceiling, not a reset at a section boundary.
        let mut work = self.work.checked_add(CatalogCodingTraversalBudget {
            bytes: 4096,
            ..Default::default()
        })?;
        for root in [manifest.sources.records, manifest.descriptors.records] {
            work = work.checked_add(CatalogCodingTraversalBudget {
                bytes: root.page.byte_len,
                page_occurrences: root.page.page_occurrences,
                records: root.records,
            })?;
        }
        self.budget.remaining_after(work)?;
        self.store.with_record_transaction(|| {
            build_index(manifest, &self.store, &mut fetch, &mut |id, commitment| {
                if source(&self.store, id)?.0.commitment.as_ref() != Some(commitment) {
                    return Err(DatabaseError::Conflict.into());
                }
                Ok(())
            })
        })?;
        Ok(CatalogCheckpointPackingIndex {
            authority: self.manifest,
            authority_work: self.work,
            source_count: self.source_count,
            budget: self.budget,
            index: CatalogPackingIndex {
                manifest,
                store: self.store,
                budget: packing_budget,
            },
        })
    }
}

fn require_authority(
    store: &RecordScratchStore,
    manifest: CatalogCheckpointAuthorityValidation,
    work: CatalogCodingTraversalBudget,
    count: u64,
    budget: CatalogCodingTraversalBudget,
) -> Result<(), CatalogStoreError> {
    manifest.validate(budget)?;
    let minimum = manifest.minimum_work()?;
    if work.bytes != minimum.bytes
        || work.page_occurrences != minimum.page_occurrences
        || work.records < minimum.records
        || count == 0
        || count > work.records
    {
        return Err(DatabaseError::Integrity.into());
    }
    budget.remaining_after(work)?;
    let expected = encoded(&(manifest, work, count), MANIFEST_BYTES)?;
    if store
        .get_record_bounded(COMPLETE, b"root", MANIFEST_BYTES)?
        .as_deref()
        != Some(expected.as_slice())
    {
        return Err(DatabaseError::NotReady.into());
    }
    Ok(())
}

fn next_revision(
    store: &RecordScratchStore,
    guild_id: [u8; 32],
    after: Option<CatalogCheckpointRevisionKey>,
) -> Result<Option<CatalogCheckpointAuthorityRecord>, CatalogStoreError> {
    let after = after.map(CatalogCheckpointRevisionKey::index_key);
    let Some((key, bytes)) = store.next_record_bounded(
        REVISIONS,
        after.as_ref().map(|key| key.as_slice()),
        72,
        CATALOG_CHECKPOINT_RECORD_BYTES,
    )?
    else {
        return Ok(None);
    };
    decode_revision(&bytes, &key, guild_id).map(Some)
}

fn decode_revision(
    bytes: &[u8],
    key: &[u8],
    guild_id: [u8; 32],
) -> Result<CatalogCheckpointAuthorityRecord, CatalogStoreError> {
    let value: CatalogCheckpointAuthorityRecord = decode_canonical(bytes)?;
    if encoded(&value, CATALOG_CHECKPOINT_RECORD_BYTES)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    match &value {
        CatalogCheckpointAuthorityRecord::LegacyRevision(reference) => {
            reference.validate()?;
            if reference.guild_id != guild_id {
                return Err(DatabaseError::Integrity.into());
            }
        }
        CatalogCheckpointAuthorityRecord::PagedRevision(signed) => {
            PagedUserRevision::verify_signed(signed)?;
            if signed.value.guild_id != guild_id {
                return Err(DatabaseError::Integrity.into());
            }
        }
        _ => return Err(DatabaseError::Integrity.into()),
    }
    if value
        .revision_key()
        .is_none_or(|order| key != order.index_key())
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(value)
}

pub struct CatalogCheckpointPackingIndex {
    authority: CatalogCheckpointAuthorityValidation,
    authority_work: CatalogCodingTraversalBudget,
    source_count: u64,
    budget: CatalogCodingTraversalBudget,
    index: CatalogPackingIndex,
}

impl CatalogCheckpointPackingIndex {
    pub fn authority(&self) -> CatalogCheckpointAuthorityValidation {
        self.authority
    }
    pub fn packing(&self) -> &CatalogPackingIndex {
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
    ) -> Result<CatalogCheckpointCodingDirectoryIndex, CatalogStoreError> {
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

/// Complete public authority/packing/directory joins in one admitted scratch
/// store. Exact certified coding state, authority transition/signatures, event
/// rechecks and private/payload ownership remain mandatory before activation.
pub struct CatalogCheckpointCodingDirectoryIndex {
    authority: CatalogCheckpointAuthorityValidation,
    source_count: u64,
    index: CatalogPackingCodingDirectoryIndex,
}
impl CatalogCheckpointCodingDirectoryIndex {
    /// Read one exact revision from the completed, authenticated authority join.
    /// No retained-history scan or caller-supplied membership assertion is used.
    pub fn revision(
        &self,
        key: CatalogCheckpointRevisionKey,
    ) -> Result<Option<CatalogCheckpointAuthorityRecord>, CatalogStoreError> {
        self.require_complete()?;
        let key = key.index_key();
        let store = &self.index.packing().store;
        let identity =
            read::<super::checkpoint_transition::RevisionIdentity>(store, IDENTITIES, &key)?;
        let Some(bytes) =
            store.get_record_bounded(REVISIONS, &key, CATALOG_CHECKPOINT_RECORD_BYTES)?
        else {
            if identity.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
            return Ok(None);
        };
        let record = decode_revision(&bytes, &key, self.authority.context.guild_id)?;
        let (identity, _) = identity.ok_or(DatabaseError::Integrity)?;
        if !identity.matches_reference(&record)? {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(record))
    }

    pub fn authority(&self) -> CatalogCheckpointAuthorityValidation {
        self.authority
    }
    pub fn index(&self) -> &CatalogPackingCodingDirectoryIndex {
        &self.index
    }
    pub(super) fn require_complete(&self) -> Result<(), CatalogStoreError> {
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
}

#[cfg(test)]
pub(super) mod tests {
    use super::super::packing_authority::tests::Fixture as Sources;
    use super::*;
    use mb_core::{
        CatalogBuilder, CatalogCheckpointAuthorityBuilder, CatalogCodingDirectoryBuilder,
        CatalogSectorBuilder, CatalogSectorRecord, PackingInput, PagedUserRevision, SignedRecord,
        pack_incremental,
    };
    use std::cell::Cell;
    use std::collections::BTreeMap;

    type Pages = BTreeMap<[u8; 32], Vec<u8>>;
    type R = CatalogCheckpointAuthorityRecord;

    pub(crate) struct Fixture {
        pub(crate) sources: Sources,
        pub(crate) context: CatalogCheckpointAuthorityContext,
        pub(crate) records: Vec<R>,
        pub(crate) pages: Pages,
        pub(crate) authority_budget: Option<CatalogCodingTraversalBudget>,
    }

    fn budget() -> CatalogCodingTraversalBudget {
        CatalogCodingTraversalBudget {
            bytes: 96 << 30,
            page_occurrences: 2_000_000,
            records: 128_000_000,
        }
    }
    fn fetch(pages: &Pages, page: CatalogPageRef) -> Result<Vec<u8>, CatalogStoreError> {
        pages
            .get(&page.hash)
            .cloned()
            .ok_or_else(|| DatabaseError::NotReady.into())
    }

    fn order(record: &R) -> (u8, Vec<u8>) {
        match record {
            R::Member(member) => (0, member.node_id.0.to_vec()),
            R::WriterFence(fence) => (1, fence_key(fence).to_vec()),
            R::Tombstone(tombstone) => (
                2,
                chain(tombstone.owner, tombstone.protected_root_id).to_vec(),
            ),
            R::LegacyRevision(_) | R::PagedRevision(_) => {
                (3, record.revision_key().unwrap().index_key().to_vec())
            }
            R::LegacyBinding(signed) => (
                4,
                source_key(CatalogPackedSourceId {
                    owner: signed.value.owner,
                    protected_root: signed.value.protected_root,
                    object_id: signed.value.object_id,
                })
                .to_vec(),
            ),
            R::LegacyAttestation(signed) => {
                let mut key = source_key(CatalogPackedSourceId {
                    owner: signed.value.owner,
                    protected_root: signed.value.protected_root,
                    object_id: signed.value.object_id,
                })
                .to_vec();
                key.extend(signed.signer.0);
                (5, key)
            }
        }
    }

    impl Fixture {
        pub(crate) fn new(authenticated: bool, removed: bool) -> Self {
            let sources = Sources::new(authenticated, removed);
            let checkpoint = &sources.certificate.checkpoint;
            let context = CatalogCheckpointAuthorityContext {
                guild_id: checkpoint.guild_id,
                generation: 2,
                event_sequence: 100,
                event_head: [91; 32],
                authority: checkpoint.authority.unwrap(),
            };
            let scope = CatalogScope::Guild {
                guild_id: context.guild_id,
            };
            let mut pages = Pages::new();
            let mut builder = CatalogBuilder::new(scope, CatalogSection::Checkpoint).unwrap();
            let mut sink = |page: CatalogPageRef, bytes| {
                pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            builder
                .push(
                    &canonical_bytes(&checkpoint.revisions[0]).unwrap(),
                    &mut sink,
                )
                .unwrap();
            let body = builder.finish(&mut sink).unwrap();
            let reference = mb_core::CatalogLegacyRevisionRef::from_signed(
                context.guild_id,
                &checkpoint.revisions[0],
                body,
            )
            .unwrap();
            let mut records = checkpoint
                .members
                .iter()
                .cloned()
                .map(R::Member)
                .collect::<Vec<_>>();
            records.extend(checkpoint.writer_fences.iter().cloned().map(R::WriterFence));
            records.push(R::LegacyRevision(reference));
            let (paged, source_pages) = sources.candidate(&sources.records[..1]);
            pages.extend(source_pages);
            records.push(R::PagedRevision(paged));
            Self {
                sources,
                context,
                records,
                pages,
                authority_budget: None,
            }
        }
        pub(crate) fn scope(&self) -> CatalogScope {
            CatalogScope::Guild {
                guild_id: self.context.guild_id,
            }
        }
        pub(crate) fn paged(&self) -> SignedRecord<PagedUserRevision> {
            self.records
                .iter()
                .find_map(|record| {
                    if let R::PagedRevision(value) = record {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
                .unwrap()
        }
        pub(crate) fn replace_paged(
            &mut self,
            mut value: PagedUserRevision,
            records: &[CatalogSectorRecord],
        ) {
            let mut builder = CatalogSectorBuilder::new(value.scope()).unwrap();
            let mut sink = |page: CatalogPageRef, bytes| {
                self.pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            for record in records {
                builder.push(record, &mut sink).unwrap();
            }
            value.sources = builder.finish(&mut sink).unwrap();
            let signed = value
                .sign(&self.sources.writer, &self.sources.keys[0])
                .unwrap();
            *self
                .records
                .iter_mut()
                .find(|record| matches!(record, R::PagedRevision(_)))
                .unwrap() = R::PagedRevision(signed);
        }
        fn root(&mut self) -> CatalogCheckpointAuthorityRoot {
            self.records.sort_by_key(order);
            let mut builder = match self.authority_budget {
                Some(budget) => CatalogCheckpointAuthorityBuilder::new_with_budget(
                    self.scope(),
                    self.context.generation,
                    self.context.authority.membership_epoch,
                    budget,
                ),
                None => CatalogCheckpointAuthorityBuilder::new(
                    self.scope(),
                    self.context.generation,
                    self.context.authority.membership_epoch,
                ),
            }
            .unwrap();
            let mut sink = |page: CatalogPageRef, bytes| {
                self.pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            for record in &self.records {
                builder.push(record, &mut sink).unwrap();
            }
            builder.finish(&mut sink).unwrap()
        }
        fn members(&self) -> &[Member] {
            &self.sources.certificate.checkpoint.members
        }
        fn build(
            &mut self,
            limit: CatalogCodingTraversalBudget,
        ) -> Result<CatalogCheckpointAuthorityIndex, CatalogStoreError> {
            let members = self.members().to_vec();
            self.build_with_members(limit, &members)
        }
        fn build_with_members(
            &mut self,
            limit: CatalogCodingTraversalBudget,
            members: &[Member],
        ) -> Result<CatalogCheckpointAuthorityIndex, CatalogStoreError> {
            let root = self.root();
            CatalogCheckpointAuthorityIndex::build(
                self.context,
                root,
                members,
                limit,
                RecordScratchStore::new(8 << 20)?,
                |scope, section, page| {
                    assert!(
                        scope == self.scope() && section == CatalogSection::Checkpoint
                            || scope == self.paged().value.scope()
                                && section == CatalogSection::SectorReferences
                    );
                    fetch(&self.pages, page)
                },
                |fence, _| {
                    if self
                        .sources
                        .certificate
                        .checkpoint
                        .writer_fences
                        .contains(fence)
                    {
                        Ok(())
                    } else {
                        Err(DatabaseError::Conflict.into())
                    }
                },
            )
        }
        pub(crate) fn trust(&self) -> mb_core::PagedCheckpointTrust {
            let old = &self.sources.certificate;
            mb_core::PagedCheckpointTrust {
                guild_id: self.context.guild_id,
                genesis_hash: old.checkpoint.genesis_hash,
                event_sequence: self.context.event_sequence,
                event_head: self.context.event_head,
                authority: self.context.authority,
                members: self.members().to_vec(),
                previous: Some(mb_core::PagedCheckpointParent {
                    generation: old.checkpoint.generation,
                    hash: old.hash().unwrap(),
                }),
            }
        }
        pub(crate) fn previous_trust(&self) -> mb_core::PagedCheckpointTrust {
            let mut trust = self.trust();
            let checkpoint = &self.sources.certificate.checkpoint;
            trust.previous = checkpoint
                .parent
                .map(|hash| mb_core::PagedCheckpointParent {
                    generation: checkpoint.generation - 1,
                    hash,
                });
            trust.authority = checkpoint.authority.unwrap_or(self.context.authority);
            trust
        }
        pub(crate) fn transitioned(
            &mut self,
            limit: CatalogCodingTraversalBudget,
            policy: CatalogCodingCoveragePolicy,
        ) -> Result<CatalogCheckpointTransitionIndex, CatalogStoreError> {
            let trust = self.trust();
            let current = self.certified(limit, policy, &trust)?;
            let previous_trust = self.previous_trust();
            current.validate_authority_transition(
                Some(CatalogCheckpointPrevious::Legacy {
                    certificate: &self.sources.certificate,
                    trust: &previous_trust,
                }),
                budget(),
                || Ok(trust.clone()),
                |owner, _| {
                    Ok(self
                        .sources
                        .certificate
                        .checkpoint
                        .writer_fences
                        .iter()
                        .filter(|fence| fence.owner == owner)
                        .max_by_key(|fence| fence.epoch)
                        .cloned())
                },
            )
        }
        pub(crate) fn joined(
            &mut self,
            budget: CatalogCodingTraversalBudget,
            policy: CatalogCodingCoveragePolicy,
        ) -> CatalogCheckpointCodingDirectoryIndex {
            self.joined_with_entry(budget, policy).0
        }
        pub(crate) fn certified(
            &mut self,
            limit: CatalogCodingTraversalBudget,
            policy: CatalogCodingCoveragePolicy,
            trust: &mb_core::PagedCheckpointTrust,
        ) -> Result<CatalogCheckpointCodingStateIndex, CatalogStoreError> {
            let (index, original) = self.joined_with_entry(limit, policy);
            let trust = CatalogCheckpointCodingTrust {
                checkpoint: trust.clone(),
                retained_groups: 1,
                retired_groups: 0,
            };
            let original = CatalogCertifiedCodingGroup::from_retained(
                &original.retained,
                mb_core::canonical_hash_bounded(
                    &original.transcript,
                    mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
                )?,
                CatalogCodingAuthorization::CurrentPlacement,
            )?;
            index.validate_certified_coding_state(
                budget(),
                || Ok(trust.clone()),
                |id, _| Ok((id == original.lifecycle.group_id).then_some(original)),
            )
        }
        pub(crate) fn joined_with_entry(
            &mut self,
            budget: CatalogCodingTraversalBudget,
            policy: CatalogCodingCoveragePolicy,
        ) -> (
            CatalogCheckpointCodingDirectoryIndex,
            mb_core::CatalogCodingEntry,
        ) {
            let (index, mut entries) =
                self.joined_with_groups(budget, policy, |_, entries| entries);
            (index, entries.pop().unwrap())
        }
        pub(crate) fn packing_inputs_with_byte_roots(
            &self,
        ) -> (
            CatalogPackingValidation,
            Pages,
            super::super::packing_validation::tests::Fixture,
        ) {
            self.packing_inputs_mode(true)
        }

        fn packing_inputs_mode(
            &self,
            byte_roots: bool,
        ) -> (
            CatalogPackingValidation,
            Pages,
            super::super::packing_validation::tests::Fixture,
        ) {
            let (mut packing, mut packing_pages) = self
                .sources
                .packing(&self.sources.records, &self.sources.bytes);
            let old = &self.sources.certificate.checkpoint.revisions[0].value;
            let packed = pack_incremental(
                packing.descriptors.profile,
                None,
                self.sources
                    .records
                    .iter()
                    .zip(&self.sources.bytes)
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
            let mut inputs = super::super::packing_validation::tests::Fixture {
                manifest: packing,
                pages: Default::default(),
                roles: [Vec::new(), Vec::new()],
                authority: Default::default(),
                sectors: packed.catalog.sectors,
                bytes: packed
                    .sectors
                    .into_iter()
                    .map(|sector| sector.bytes)
                    .collect(),
            };
            if byte_roots {
                // Build new descriptors with supported version-two byte-root
                // semantics before any group ID or certificate is created.
                // Versions three through five bind the Merkle root instead.
                let mut builder = mb_core::CatalogPackedSectorBuilder::new_compact(
                    packing.scope,
                    2,
                    packing.descriptors.profile,
                )
                .unwrap();
                let mut sink = |page: CatalogPageRef, bytes| {
                    packing_pages.insert(page.hash, bytes);
                    Ok::<_, ()>(())
                };
                for (sector, bytes) in inputs.sectors.iter_mut().zip(&inputs.bytes) {
                    sector.flat_root = mb_core::sector_root(bytes);
                    sector.id = sector.calculate_id(packing.descriptors.profile).unwrap();
                    builder.push_sector(sector, &mut sink).unwrap();
                }
                packing.descriptors = builder.finish(&mut sink).unwrap();
                inputs.manifest = packing;
            }
            (packing, packing_pages, inputs)
        }

        pub(crate) fn joined_with_groups(
            &mut self,
            budget: CatalogCodingTraversalBudget,
            policy: CatalogCodingCoveragePolicy,
            select: impl FnOnce(
                &super::super::packing_validation::tests::Fixture,
                Vec<mb_core::CatalogCodingEntry>,
            ) -> Vec<mb_core::CatalogCodingEntry>,
        ) -> (
            CatalogCheckpointCodingDirectoryIndex,
            Vec<mb_core::CatalogCodingEntry>,
        ) {
            let members = self.members().to_vec();
            self.joined_with_groups_and_members(budget, policy, &members, false, select)
        }

        pub(crate) fn joined_with_groups_and_members(
            &mut self,
            budget: CatalogCodingTraversalBudget,
            policy: CatalogCodingCoveragePolicy,
            members: &[Member],
            byte_roots: bool,
            select: impl FnOnce(
                &super::super::packing_validation::tests::Fixture,
                Vec<mb_core::CatalogCodingEntry>,
            ) -> Vec<mb_core::CatalogCodingEntry>,
        ) -> (
            CatalogCheckpointCodingDirectoryIndex,
            Vec<mb_core::CatalogCodingEntry>,
        ) {
            let (mut packing, packing_pages, inputs) = self.packing_inputs_mode(byte_roots);
            if self.authority_budget.is_some() {
                packing.format_version = 2;
            }
            let entry = super::super::coding_coverage::tests::entry(
                &inputs,
                [0, 1, 2],
                701,
                if byte_roots { 3 } else { 2 },
                None,
            );
            let mut entries = select(&inputs, vec![entry]);
            entries.sort_by_key(|entry| entry.retained.group.id);
            let mut pages = Pages::new();
            let mut sink = |page: CatalogPageRef, bytes| {
                pages.insert(page.hash, bytes);
                Ok::<_, ()>(())
            };
            let mut builder = CatalogCodingDirectoryBuilder::new(
                self.scope(),
                self.context.event_sequence,
                budget,
            )
            .unwrap();
            for entry in &entries {
                builder.push_group(entry, &mut sink).unwrap();
            }
            let coding = builder.finish(&mut sink).unwrap();
            let index = self
                .build_with_members(budget, members)
                .unwrap()
                .validate_packing(packing, |page| fetch(&packing_pages, page))
                .unwrap()
                .validate_coding_directory(
                    coding,
                    policy,
                    |page| fetch(&pages, page),
                    |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
                )
                .unwrap();
            // Keep the original encoded public pages available to enclosing
            // ownership fixtures, not just the disposable joined facts.
            self.pages.extend(packing_pages);
            self.pages.extend(pages);
            (index, entries)
        }
    }

    #[test]
    fn budgeted_authority_index_preserves_complete_source_joins_and_exact_shared_admission() {
        let mut fixture = Fixture::new(true, false);
        fixture.authority_budget = Some(budget());
        let root = fixture.root();
        let index = fixture.build(budget()).unwrap();
        assert_eq!(root.format_version, 2);
        let manifest = index.manifest();
        assert_eq!(manifest.format_version, 2);
        let exact = index.represented_work();
        assert_eq!(fixture.build(exact).unwrap().represented_work(), exact);
        let bytes = canonical_bytes(&manifest).unwrap();
        assert_eq!(
            CatalogCheckpointAuthorityValidation::decode(&bytes, exact).unwrap(),
            manifest
        );
        let mut wrong_version = manifest;
        wrong_version.format_version = 1;
        assert!(wrong_version.validate(budget()).is_err());
        for dimension in 0..3 {
            let mut short = exact;
            match dimension {
                0 => short.bytes -= 1,
                1 => short.page_occurrences -= 1,
                _ => short.records -= 1,
            }
            assert!(fixture.build(short).is_err(), "dimension {dimension}");
        }
        let mut missing = fixture;
        missing
            .pages
            .remove(&missing.paged().value.sources.records.page.hash);
        assert!(missing.build(budget()).is_err());
    }

    #[test]
    fn authority_index_joins_mixed_roots_sources_and_complete_directory_under_one_budget() {
        let mut fixture = Fixture::new(true, false);
        let root = fixture.root();
        let index = fixture.build(budget()).unwrap();
        assert_eq!(index.source_count(), 2);
        assert_eq!(
            index.represented_work().records,
            root.records.records + 1 + 2 + fixture.paged().value.sources.records.records
        );
        let mut after = None;
        for expected in fixture
            .records
            .iter()
            .filter(|record| record.revision_key().is_some())
        {
            assert_eq!(index.next_revision(after).unwrap().as_ref(), Some(expected));
            after = expected.revision_key();
        }
        assert!(index.next_revision(after).unwrap().is_none());
        let mut after = None;
        for expected in &fixture.sources.records {
            let source = index.next_source(after).unwrap().unwrap();
            assert_eq!(source.id.object_id, expected.sector.id);
            assert_eq!(source.commitment, expected.commitment);
            after = Some(source.id);
        }
        assert!(index.next_source(after).unwrap().is_none());
        let (mut packing, packing_pages) = fixture
            .sources
            .packing(&fixture.sources.records, &fixture.sources.bytes);
        packing.format_version = 2;
        let old = &fixture.sources.certificate.checkpoint.revisions[0].value;
        let packed = pack_incremental(
            packing.descriptors.profile,
            None,
            fixture
                .sources
                .records
                .iter()
                .zip(&fixture.sources.bytes)
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
        assert_eq!(packed.sectors.len(), 3);
        let inputs = super::super::packing_validation::tests::Fixture {
            manifest: packing,
            pages: Default::default(),
            roles: [Vec::new(), Vec::new()],
            authority: Default::default(),
            sectors: packed.catalog.sectors,
            bytes: packed
                .sectors
                .into_iter()
                .map(|sector| sector.bytes)
                .collect(),
        };
        let entry = super::super::coding_coverage::tests::entry(&inputs, [0, 1, 2], 701, 2, None);
        let mut coding_pages = Pages::new();
        let mut sink = |page: CatalogPageRef, bytes| {
            coding_pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut builder =
            CatalogCodingDirectoryBuilder::new(fixture.scope(), 100, budget()).unwrap();
        builder.push_group(&entry, &mut sink).unwrap();
        let coding = builder.finish(&mut sink).unwrap();
        let manifest = CatalogPackingCodingDirectoryValidation {
            format_version: 1,
            packing,
            coding,
            policy: CatalogCodingCoveragePolicy::Current,
            prior_work: index.represented_work(),
        };
        let total = manifest.represented_work().unwrap();
        assert_eq!(
            CatalogCheckpointAuthorityValidation::decode(
                &canonical_bytes(&index.manifest()).unwrap(),
                total
            )
            .unwrap(),
            index.manifest()
        );
        drop(index);
        let mut packing_work = manifest
            .prior_work
            .checked_add(CatalogCodingTraversalBudget {
                bytes: 4096,
                ..Default::default()
            })
            .unwrap();
        for root in [packing.sources.records, packing.descriptors.records] {
            packing_work = packing_work
                .checked_add(CatalogCodingTraversalBudget {
                    bytes: root.page.byte_len,
                    page_occurrences: root.page.page_occurrences,
                    records: root.records,
                })
                .unwrap();
        }
        for dimension in 0..3 {
            let mut limit = packing_work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                fixture
                    .build(limit)
                    .unwrap()
                    .validate_packing(packing, |_| panic!(
                        "exhausted shared budget fetched packing"
                    ))
                    .is_err()
            );
        }
        for dimension in 0..3 {
            let mut limit = total;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            let packing = fixture
                .build(limit)
                .unwrap()
                .validate_packing(packing, |page| fetch(&packing_pages, page))
                .unwrap();
            assert!(
                packing
                    .validate_coding_directory(
                        coding,
                        manifest.policy,
                        |_| panic!("exhausted combined budget fetched coding"),
                        |_| panic!("exhausted combined budget authorized coding")
                    )
                    .is_err()
            );
        }
        let joined = fixture
            .build(total)
            .unwrap()
            .validate_packing(packing, |page| fetch(&packing_pages, page))
            .unwrap()
            .validate_coding_directory(
                coding,
                manifest.policy,
                |page| fetch(&coding_pages, page),
                |_| Ok(CatalogCodingAuthorization::CurrentPlacement),
            )
            .unwrap();
        assert_eq!(joined.authority().context, fixture.context);
        assert_eq!(joined.index().manifest(), manifest);
        assert_eq!(joined.index().manifest().represented_work().unwrap(), total);
        assert_eq!(
            joined
                .index()
                .read_group(entry.retained.group.id, |page| fetch(&coding_pages, page))
                .unwrap(),
            Some(entry)
        );
        assert!(joined.next_revision(None).unwrap().is_some());
        let mut wrong_event = coding;
        wrong_event.guild_event_sequence -= 1;
        assert!(
            fixture
                .build(total)
                .unwrap()
                .validate_packing(packing, |page| fetch(&packing_pages, page))
                .unwrap()
                .validate_coding_directory(
                    wrong_event,
                    manifest.policy,
                    |_| panic!("wrong event snapshot fetched coding"),
                    |_| panic!("wrong event snapshot authorized coding")
                )
                .is_err()
        );
        let complete = encoded(
            &(joined.authority, manifest.prior_work, 2_u64),
            MANIFEST_BYTES,
        )
        .unwrap();
        joined
            .index
            .packing()
            .store
            .delete_record_if_value(COMPLETE, b"root", &complete)
            .unwrap();
        assert!(joined.next_revision(None).is_err());
    }

    #[test]
    fn authority_index_requires_tombstone_continuations_and_reserves_retired_ids() {
        for case in 0..5 {
            let mut fixture = Fixture::new(true, false);
            let old = &fixture.sources.certificate.checkpoint.revisions[0].value;
            let mut tombstone = RevisionTombstone {
                owner: old.owner,
                protected_root_id: old.protected_root_id,
                through_sequence: 1,
                last_revision_id: old.revision_id,
                last_revision_hash: old.hash().unwrap(),
                retired_at_generation: 2,
            };
            fixture
                .records
                .retain(|record| !matches!(record, R::LegacyRevision(_)));
            match case {
                0 => {} // A retained suffix without its prefix tombstone.
                1 => fixture.records.push(R::Tombstone(tombstone)),
                2 => {
                    tombstone.last_revision_hash = [92; 32];
                    fixture.records.push(R::Tombstone(tombstone));
                }
                3 => {
                    tombstone.last_revision_id = fixture.paged().value.revision_id;
                    fixture.records.push(R::Tombstone(tombstone));
                }
                _ => {
                    tombstone.protected_root_id = Uuid::from_u128(999);
                    fixture.records.push(R::Tombstone(tombstone));
                }
            }
            assert_eq!(fixture.build(budget()).is_ok(), case == 1);
        }
        let mut fixture = Fixture::new(true, false);
        let mut duplicate = fixture.paged().value.clone();
        duplicate.protected_root_id = Uuid::from_u128(999);
        duplicate.sequence = 1;
        duplicate.parent = None;
        let signed = duplicate
            .sign(&fixture.sources.writer, &fixture.sources.keys[0])
            .unwrap();
        fixture.records.push(R::PagedRevision(signed));
        assert!(fixture.build(budget()).is_err());
    }

    #[test]
    fn authority_index_checks_exact_members_historical_fences_and_latest_head_authorization() {
        let mut fixture = Fixture::new(true, true);
        assert!(
            fixture.build(budget()).is_ok(),
            "removed owners retain already authorized history"
        );
        let root = fixture.root();
        let mut wrong = fixture.members().to_vec();
        wrong[0].failure_domain.push('x');
        assert!(
            CatalogCheckpointAuthorityIndex::build(
                fixture.context,
                root,
                &wrong,
                budget(),
                RecordScratchStore::new(4 << 20).unwrap(),
                |_, _, page| fetch(&fixture.pages, page),
                |_, _| Ok(())
            )
            .is_err()
        );
        for denied in [
            CatalogCheckpointWriterAuthorization::Historical,
            CatalogCheckpointWriterAuthorization::LatestRetained,
        ] {
            let calls = Cell::new(0);
            assert!(
                CatalogCheckpointAuthorityIndex::build(
                    fixture.context,
                    root,
                    fixture.members(),
                    budget(),
                    RecordScratchStore::new(4 << 20).unwrap(),
                    |_, _, page| fetch(&fixture.pages, page),
                    |_, role| {
                        calls.set(calls.get() + 1);
                        if role == denied {
                            Err(DatabaseError::Conflict.into())
                        } else {
                            Ok(())
                        }
                    }
                )
                .is_err()
            );
            assert_eq!(
                calls.get(),
                if denied == CatalogCheckpointWriterAuthorization::Historical {
                    1
                } else {
                    2
                }
            );
        }
        let mut fence = fixture.sources.certificate.checkpoint.writer_fences[0].clone();
        fence.epoch = 2;
        fixture.records.push(R::WriterFence(fence));
        let root = fixture.root();
        assert!(
            CatalogCheckpointAuthorityIndex::build(
                fixture.context,
                root,
                fixture.members(),
                budget(),
                RecordScratchStore::new(4 << 20).unwrap(),
                |_, _, page| fetch(&fixture.pages, page),
                |_, _| Ok(())
            )
            .is_err(),
            "latest listed fence needs a retained head"
        );
    }

    #[test]
    fn authority_index_rejects_source_namespace_and_logical_geometry_conflicts() {
        for case in 0..3 {
            let mut fixture = Fixture::new(true, false);
            let mut value = fixture.paged().value;
            let mut records = fixture.sources.records[..1].to_vec();
            match case {
                0 => {
                    records[0].sector.logical_len += 1;
                    value.metadata = records[0].clone();
                }
                1 => {
                    records[0].sector.root = [93; 32];
                    value.metadata = records[0].clone();
                }
                _ => {
                    value.protected_root_id = Uuid::from_u128(999);
                    value.sequence = 1;
                    value.parent = None;
                }
            }
            fixture.replace_paged(value, &records);
            assert!(fixture.build(budget()).is_err());
        }
    }

    #[test]
    fn authority_index_requires_exact_owner_or_current_quorum_migration_evidence() {
        for mode in 0..6 {
            let mut fixture = Fixture::new(false, false);
            match mode {
                0 => {}
                1 => fixture
                    .records
                    .push(R::LegacyBinding(fixture.sources.binding(1))),
                2 | 3 => {
                    fixture
                        .records
                        .push(R::LegacyAttestation(fixture.sources.attestation(1, 0)));
                    if mode == 3 {
                        fixture
                            .records
                            .push(R::LegacyAttestation(fixture.sources.attestation(1, 1)));
                    }
                }
                4 => {
                    fixture
                        .records
                        .push(R::LegacyBinding(fixture.sources.binding(1)));
                    fixture
                        .records
                        .push(R::LegacyAttestation(fixture.sources.attestation(1, 0)));
                }
                _ => fixture
                    .records
                    .push(R::LegacyBinding(fixture.sources.binding(0))), // Redundant: paged source already authenticates it.
            }
            assert_eq!(fixture.build(budget()).is_ok(), matches!(mode, 1 | 3));
        }
        let mut fixture = Fixture::new(false, true);
        fixture
            .records
            .push(R::LegacyAttestation(fixture.sources.attestation(1, 0)));
        fixture
            .records
            .push(R::LegacyAttestation(fixture.sources.attestation(1, 1)));
        assert!(
            fixture.build(budget()).is_err(),
            "removed members cannot attest current migration"
        );
    }

    #[test]
    fn authority_index_admits_all_dimensions_before_fetch_and_rejects_orphans_and_ignored_writes() {
        let mut fixture = Fixture::new(true, false);
        let root = fixture.root();
        let manifest = CatalogCheckpointAuthorityValidation {
            format_version: 1,
            context: fixture.context,
            root,
        };
        let minimum = manifest.minimum_work().unwrap();
        for dimension in 0..3 {
            let mut limit = minimum;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                CatalogCheckpointAuthorityIndex::build(
                    fixture.context,
                    root,
                    fixture.members(),
                    limit,
                    RecordScratchStore::new(4 << 20).unwrap(),
                    |_, _, _| panic!("inadmissible authority fetched pages"),
                    |_, _| panic!("inadmissible authority authorized fences")
                )
                .is_err()
            );
        }
        let mut limit = minimum;
        limit.records += 2; // Admit legacy entries, exhaust at paged sources.
        let source_fetches = Cell::new(0);
        assert!(
            CatalogCheckpointAuthorityIndex::build(
                fixture.context,
                root,
                fixture.members(),
                limit,
                RecordScratchStore::new(4 << 20).unwrap(),
                |_, section, page| {
                    if section == CatalogSection::SectorReferences {
                        source_fetches.set(source_fetches.get() + 1);
                    }
                    fetch(&fixture.pages, page)
                },
                |_, _| Ok(())
            )
            .is_err()
        );
        assert_eq!(source_fetches.get(), 0);
        for kind in [COMPLETE, SOURCES, MEMBER_RECORDS, IDENTITIES] {
            let store = RecordScratchStore::new(4 << 20).unwrap();
            store.put_record_if_absent(kind, b"orphan", b"").unwrap();
            assert!(
                CatalogCheckpointAuthorityIndex::build(
                    fixture.context,
                    root,
                    fixture.members(),
                    budget(),
                    store,
                    |_, _, _| panic!("orphan authority fetched pages"),
                    |_, _| Ok(())
                )
                .is_err()
            );
        }
        for (operation, kind) in [
            ("INSERT", MEMBER_RECORDS),
            ("INSERT", IDENTITIES),
            ("INSERT", HISTORY),
            ("INSERT", SOURCES),
            ("UPDATE", HEADS),
            ("INSERT", COMPLETE),
        ] {
            let store = RecordScratchStore::new(4 << 20).unwrap();
            let side = if operation == "UPDATE" { "OLD" } else { "NEW" };
            store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_authority BEFORE {operation} ON scratch.protocol_records WHEN {side}.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
            assert!(
                CatalogCheckpointAuthorityIndex::build(
                    fixture.context,
                    root,
                    fixture.members(),
                    budget(),
                    store,
                    |_, _, page| fetch(&fixture.pages, page),
                    |_, _| Ok(())
                )
                .is_err()
            );
        }
        fixture.build(budget()).unwrap();
    }

    #[test]
    fn authority_index_spills_rebuilds_after_exhaustion_and_rejects_corrupt_local_cursors() {
        let mut fixture = Fixture::new(true, false);
        let mut records = (0..4096_u32)
            .map(|index| {
                let mut record = fixture.sources.records[0].clone();
                record.sector.id = [0; 32];
                record.sector.id[..4].copy_from_slice(&(index + 1).to_be_bytes());
                record
            })
            .collect::<Vec<_>>();
        records.push(fixture.sources.records[0].clone());
        fixture.replace_paged(fixture.paged().value, &records);
        let root = fixture.root();
        let fetches = Cell::new(0);
        assert!(
            CatalogCheckpointAuthorityIndex::build(
                fixture.context,
                root,
                fixture.members(),
                budget(),
                RecordScratchStore::new(64 << 10).unwrap(),
                |_, _, page| {
                    fetches.set(fetches.get() + 1);
                    fetch(&fixture.pages, page)
                },
                |_, _| Ok(())
            )
            .is_err()
        );
        assert!(fetches.get() > 0);
        let index = fixture.build(budget()).unwrap();
        let pages = index
            .store
            .database_shell_statement("PRAGMA scratch.page_count", false)
            .unwrap()
            .rows[0][0]
            .parse::<u64>()
            .unwrap();
        assert!(pages * 4096 > 1024 * 1024);
        assert_eq!(index.source_count(), 4098);
        let id = index.next_source(None).unwrap().unwrap().id;
        let (mut source, bytes) = source(&index.store, id).unwrap();
        source.commitment.as_mut().unwrap().byte_len = 1;
        let corrupt = encoded(&source, ROW_BYTES).unwrap();
        index
            .store
            .replace_record_if_value(SOURCES, &source_key(id), &bytes, &corrupt)
            .unwrap();
        assert!(index.next_source(None).is_err());
        index
            .store
            .replace_record_if_value(SOURCES, &source_key(id), &corrupt, &bytes)
            .unwrap();
        let original = fixture.paged();
        let key = CatalogCheckpointRevisionKey::from(&original.value).index_key();
        let bytes = encoded(
            &R::PagedRevision(original.clone()),
            CATALOG_CHECKPOINT_RECORD_BYTES,
        )
        .unwrap();
        let mut corrupt = original;
        corrupt.signature[0] ^= 1;
        let corrupt = encoded(&R::PagedRevision(corrupt), CATALOG_CHECKPOINT_RECORD_BYTES).unwrap();
        index
            .store
            .replace_record_if_value(REVISIONS, &key, &bytes, &corrupt)
            .unwrap();
        let legacy = index.next_revision(None).unwrap().unwrap().revision_key();
        assert!(index.next_revision(legacy).is_err());
        index
            .store
            .replace_record_if_value(REVISIONS, &key, &corrupt, &bytes)
            .unwrap();
        let marker = encoded(
            &(index.manifest, index.work, index.source_count),
            MANIFEST_BYTES,
        )
        .unwrap();
        index
            .store
            .delete_record_if_value(COMPLETE, b"root", &marker)
            .unwrap();
        assert!(index.next_source(None).is_err());
        assert!(index.next_revision(None).is_err());
    }

    fn tail(
        mut page: CatalogPageRef,
        scope: CatalogScope,
        section: CatalogSection,
        pages: &Pages,
    ) -> CatalogPageRef {
        loop {
            match page
                .verify_page(scope, section, &pages[&page.hash])
                .unwrap()
            {
                CatalogPageContents::Leaf(_) => return page,
                CatalogPageContents::Index(children) => page = *children.last().unwrap(),
            }
        }
    }

    #[test]
    fn authority_index_requires_nested_bootstrap_and_replayed_control_eof_without_usable_prefixes()
    {
        let mut fixture = Fixture::new(true, false);
        fixture.replace_paged(fixture.paged().value, &[fixture.sources.records[1].clone()]);
        assert!(
            fixture.build(budget()).is_err(),
            "complete sources must contain the signed bootstrap"
        );
        let mut fixture = Fixture::new(true, false);
        let mut root = fixture.root();
        root.summary.source_bytes -= 1;
        root.validate().unwrap();
        let sources = Cell::new(0);
        assert!(
            CatalogCheckpointAuthorityIndex::build(
                fixture.context,
                root,
                fixture.members(),
                budget(),
                RecordScratchStore::new(4 << 20).unwrap(),
                |_, section, page| {
                    if section == CatalogSection::SectorReferences {
                        sources.set(sources.get() + 1);
                    }
                    fetch(&fixture.pages, page)
                },
                |_, _| Ok(())
            )
            .is_err()
        );
        assert_eq!(sources.get(), 0);

        let mut previous = fixture.paged();
        for index in 0..160_u128 {
            let mut value = previous.value.clone();
            value.sequence += 1;
            value.revision_id = Uuid::from_u128(index + 1000);
            value.parent = Some(previous.value.hash().unwrap());
            previous = value
                .sign(&fixture.sources.writer, &fixture.sources.keys[0])
                .unwrap();
            fixture.records.push(R::PagedRevision(previous.clone()));
        }
        let root = fixture.root();
        assert!(root.records.page.height > 0);
        let last = tail(
            root.records.page,
            fixture.scope(),
            CatalogSection::Checkpoint,
            &fixture.pages,
        );
        let original = fixture.pages[&last.hash].clone();
        fixture.pages.get_mut(&last.hash).unwrap()[0] ^= 1;
        let sources = Cell::new(0);
        assert!(
            CatalogCheckpointAuthorityIndex::build(
                fixture.context,
                root,
                fixture.members(),
                budget(),
                RecordScratchStore::new(4 << 20).unwrap(),
                |_, section, page| {
                    if section == CatalogSection::SectorReferences {
                        sources.set(sources.get() + 1);
                    }
                    fetch(&fixture.pages, page)
                },
                |_, _| Ok(())
            )
            .is_err()
        );
        assert!(
            sources.get() > 0,
            "corruption must follow a validated mixed-revision prefix"
        );
        fixture.pages.insert(last.hash, original);
        let index = fixture.build(budget()).unwrap();
        assert_eq!(index.source_count(), 2);
        assert_eq!(
            index.represented_work().records,
            root.records.records + 1 + 2 + 161 * fixture.paged().value.sources.records.records
        );
    }
}
