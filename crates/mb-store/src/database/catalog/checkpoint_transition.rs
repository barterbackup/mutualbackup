//! Bounded previous-state authority comparison. This proves public revision,
//! tombstone and writer transitions, not coding lifecycle, private joins,
//! payload custody or durable checkpoint publication.

use mb_core::{
    CATALOG_CHECKPOINT_RECORD_BYTES, CatalogCheckpointAuthorityRecord as R,
    CatalogCheckpointRevisionKey as Key, CatalogCodingTraversalBudget as Work, NodeId,
    PAGED_USER_REVISION_BYTES, PagedCheckpointTrust, PagedUserRevision, QuorumCheckpoint,
    RevisionTombstone, SignedRecord, UserRevision, V1_MAX_CATALOG_BYTES, WriterFence,
    canonical_bytes_bounded, canonical_hash_bounded, canonical_size_bounded,
};

use super::checkpoint_validation::{HISTORY, IDENTITIES, REVISIONS, TOMBSTONES, fence_key};
use super::packing_authority::{FENCES, IDS, ROW_BYTES, chain, encoded, insert, read, replace};
use super::*;
use crate::RecordScratchStore;

const COMPLETE: &str = "checkpoint-authority-transition-complete";
const USED: &str = "checkpoint-authority-transition-writer";
const DESCRIPTOR_BYTES: usize = 4096;
const SNAPSHOT_BYTES: usize = 256 * 512 + 512;
const LEGACY: Names = Names {
    history: "checkpoint-transition-legacy-history",
    latest: "checkpoint-transition-legacy-latest",
    tombstones: "checkpoint-transition-legacy-tombstone",
    identities: "checkpoint-transition-legacy-identity",
    ids: "checkpoint-transition-legacy-id",
    references: None,
};
const PAGED: Names = Names {
    history: HISTORY,
    latest: FENCES,
    tombstones: TOMBSTONES,
    identities: IDENTITIES,
    ids: IDS,
    references: Some(REVISIONS),
};
const KINDS: [&str; 7] = [
    COMPLETE,
    USED,
    LEGACY.history,
    LEGACY.latest,
    LEGACY.tombstones,
    LEGACY.identities,
    LEGACY.ids,
];

/// The independent current trust snapshot must name this exact predecessor.
/// Legacy trust is a certified historical event snapshot, including the epoch
/// witness absent from formats 3/4. Paged predecessors require a completed,
/// quorum-bound public transition proof; no raw header can stand in for one.
pub enum CatalogCheckpointPrevious<'a> {
    Legacy {
        certificate: &'a QuorumCheckpoint,
        trust: &'a PagedCheckpointTrust,
    },
    Paged(&'a CatalogQuorumPagedCheckpointIndex),
}

/// Fixed disposable facts retain both body identity and original signed
/// envelope identity. Reference hashes bind scratch rows to their original
/// control record, but are excluded from equality across legacy repagination.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct RevisionIdentity {
    pub(super) key: Key,
    pub(super) format_version: u16,
    pub(super) revision_hash: [u8; 32],
    envelope_hash: [u8; 32],
    parent: Option<[u8; 32]>,
    pub(super) writer_epoch: u64,
    pub(super) writer_public_key: [u8; 32],
    reference_hash: [u8; 32],
}

impl RevisionIdentity {
    pub(super) fn legacy(signed: &SignedRecord<UserRevision>) -> Result<Self, CatalogStoreError> {
        let value = &signed.value;
        Ok(Self {
            key: Key {
                owner: value.owner,
                protected_root_id: value.protected_root_id,
                sequence: value.sequence,
                revision_id: value.revision_id,
            },
            format_version: value.format_version,
            revision_hash: value.hash()?,
            envelope_hash: canonical_hash_bounded(signed, V1_MAX_CATALOG_BYTES)?,
            parent: value.parent,
            writer_epoch: value.writer_epoch,
            writer_public_key: value.writer_public_key,
            reference_hash: [0; 32],
        })
    }
    pub(super) fn paged(
        signed: &SignedRecord<PagedUserRevision>,
    ) -> Result<Self, CatalogStoreError> {
        let value = &signed.value;
        Ok(Self {
            key: value.into(),
            format_version: value.format_version,
            revision_hash: value.hash()?,
            envelope_hash: canonical_hash_bounded(signed, PAGED_USER_REVISION_BYTES)?,
            parent: value.parent,
            writer_epoch: value.writer_epoch,
            writer_public_key: value.writer_public_key,
            reference_hash: [0; 32],
        })
    }
    pub(super) fn bind_reference(mut self, record: &R) -> Result<Self, CatalogStoreError> {
        self.reference_hash = canonical_hash_bounded(record, CATALOG_CHECKPOINT_RECORD_BYTES)?;
        Ok(self)
    }
    fn same_revision(self, other: Self) -> bool {
        Self {
            reference_hash: [0; 32],
            ..self
        } == Self {
            reference_hash: [0; 32],
            ..other
        }
    }
    fn fence(self) -> WriterFence {
        WriterFence {
            owner: self.key.owner,
            epoch: self.writer_epoch,
            public_key: self.writer_public_key,
        }
    }
}

#[derive(Clone, Copy)]
struct Names {
    history: &'static str,
    latest: &'static str,
    tombstones: &'static str,
    identities: &'static str,
    ids: &'static str,
    references: Option<&'static str>,
}
#[derive(Clone, Copy, Default)]
struct Counts {
    fences: u64,
    tombstones: u64,
    revisions: u64,
}
impl Counts {
    fn paged(index: &CatalogCheckpointCodingDirectoryIndex) -> Self {
        let summary = index.authority().root.summary;
        Self {
            fences: summary.writer_fences,
            tombstones: summary.tombstones,
            revisions: summary.revisions,
        }
    }
    fn legacy(certificate: &QuorumCheckpoint) -> Self {
        let body = &certificate.checkpoint;
        Self {
            fences: body.writer_fences.len() as u64,
            tombstones: body.revision_tombstones.len() as u64,
            revisions: body.revisions.len() as u64,
        }
    }
}

struct View<'a> {
    store: &'a RecordScratchStore,
    names: Names,
    counts: Counts,
    guild_id: [u8; 32],
    generation: u64,
}
impl View<'_> {
    fn identity_row(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<RevisionIdentity, CatalogStoreError> {
        let identity: RevisionIdentity = decode_canonical(bytes)?;
        if encoded(&identity, ROW_BYTES)? != bytes
            || key != identity.key.index_key()
            || identity.key.revision_id.is_nil()
            || identity.key.protected_root_id.is_nil()
            || identity.key.sequence == 0
            || identity.writer_epoch == 0
            || !matches!(identity.format_version, 3..=5 | 8)
        {
            return Err(DatabaseError::Integrity.into());
        }
        if let Some(kind) = self.names.references {
            let bytes = self
                .store
                .get_record_bounded(kind, key, CATALOG_CHECKPOINT_RECORD_BYTES)?
                .ok_or(DatabaseError::NotReady)?;
            let record: R = decode_canonical(&bytes)?;
            if canonical_bytes_bounded(&record, CATALOG_CHECKPOINT_RECORD_BYTES)? != bytes
                || record.revision_key() != Some(identity.key)
                || canonical_hash_bounded(&record, CATALOG_CHECKPOINT_RECORD_BYTES)?
                    != identity.reference_hash
            {
                return Err(DatabaseError::Integrity.into());
            }
            match record {
                R::LegacyRevision(reference) => {
                    reference.validate()?;
                    if reference.guild_id != self.guild_id
                        || reference.revision_hash != identity.revision_hash
                        || reference.parent != identity.parent
                        || reference.writer_epoch != identity.writer_epoch
                        || reference.writer_public_key != identity.writer_public_key
                        || !matches!(identity.format_version, 3..=5)
                    {
                        return Err(DatabaseError::Integrity.into());
                    }
                }
                R::PagedRevision(signed) => {
                    PagedUserRevision::verify_signed(&signed)?;
                    if signed.value.guild_id != self.guild_id
                        || !identity.same_revision(RevisionIdentity::paged(&signed)?)
                    {
                        return Err(DatabaseError::Integrity.into());
                    }
                }
                _ => return Err(DatabaseError::Integrity.into()),
            }
        }
        Ok(identity)
    }
    fn identity(&self, key: Key) -> Result<Option<RevisionIdentity>, CatalogStoreError> {
        let key = key.index_key();
        self.store
            .get_record_bounded(self.names.identities, &key, ROW_BYTES)?
            .map(|bytes| self.identity_row(&key, &bytes))
            .transpose()
    }
    fn next_identity(
        &self,
        after: Option<Key>,
    ) -> Result<Option<RevisionIdentity>, CatalogStoreError> {
        let after = after.map(Key::index_key);
        self.store
            .next_record_bounded(
                self.names.identities,
                after.as_ref().map(|key| key.as_slice()),
                72,
                ROW_BYTES,
            )?
            .map(|(key, bytes)| self.identity_row(&key, &bytes))
            .transpose()
    }
    fn at_sequence(
        &self,
        owner: NodeId,
        root: Uuid,
        sequence: u64,
    ) -> Result<Option<RevisionIdentity>, CatalogStoreError> {
        let key = Key {
            owner,
            protected_root_id: root,
            sequence,
            revision_id: Uuid::nil(),
        };
        Ok(self.next_identity(Some(key))?.filter(|value| {
            value.key.owner == owner
                && value.key.protected_root_id == root
                && value.key.sequence == sequence
        }))
    }
    fn used_id(&self, id: Uuid) -> Result<bool, CatalogStoreError> {
        match read::<bool>(self.store, self.names.ids, id.as_bytes())?.map(|row| row.0) {
            Some(true) => Ok(true),
            None => Ok(false),
            _ => Err(DatabaseError::Integrity.into()),
        }
    }
    fn fence_row(
        &self,
        key: &[u8],
        bytes: &[u8],
        latest: bool,
    ) -> Result<WriterFence, CatalogStoreError> {
        let fence: WriterFence = decode_canonical(bytes)?;
        let expected = if latest {
            fence.owner.0.to_vec()
        } else {
            fence_key(&fence).to_vec()
        };
        if encoded(&fence, ROW_BYTES)? != bytes || key != expected || fence.epoch == 0 {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(fence)
    }
    fn historical_fence(
        &self,
        fence: &WriterFence,
    ) -> Result<Option<WriterFence>, CatalogStoreError> {
        let key = fence_key(fence);
        self.store
            .get_record_bounded(self.names.history, &key, ROW_BYTES)?
            .map(|bytes| self.fence_row(&key, &bytes, false))
            .transpose()
    }
    fn latest(&self, owner: NodeId) -> Result<Option<WriterFence>, CatalogStoreError> {
        self.store
            .get_record_bounded(self.names.latest, &owner.0, ROW_BYTES)?
            .map(|bytes| self.fence_row(&owner.0, &bytes, true))
            .transpose()
    }
    fn tombstone_row(
        &self,
        key: &[u8],
        bytes: &[u8],
    ) -> Result<RevisionTombstone, CatalogStoreError> {
        let tombstone: RevisionTombstone = decode_canonical(bytes)?;
        if encoded(&tombstone, ROW_BYTES)? != bytes
            || key != chain(tombstone.owner, tombstone.protected_root_id)
            || tombstone.protected_root_id.is_nil()
            || tombstone.through_sequence == 0
            || tombstone.last_revision_id.is_nil()
            || tombstone.last_revision_hash == [0; 32]
            || tombstone.retired_at_generation < 2
            || tombstone.retired_at_generation > self.generation
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(tombstone)
    }
    fn tombstone(
        &self,
        owner: NodeId,
        root: Uuid,
    ) -> Result<Option<RevisionTombstone>, CatalogStoreError> {
        let key = chain(owner, root);
        self.store
            .get_record_bounded(self.names.tombstones, &key, ROW_BYTES)?
            .map(|bytes| self.tombstone_row(&key, &bytes))
            .transpose()
    }
    fn each_fence(
        &self,
        mut check: impl FnMut(WriterFence) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let mut after = None;
        let mut count = 0;
        while let Some((key, bytes)) =
            self.store
                .next_record_bounded(self.names.history, after.as_deref(), 40, ROW_BYTES)?
        {
            count = increment(count, self.counts.fences)?;
            check(self.fence_row(&key, &bytes, false)?)?;
            after = Some(key);
        }
        exact(count, self.counts.fences)
    }
    fn each_tombstone(
        &self,
        mut check: impl FnMut(RevisionTombstone) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let mut after = None;
        let mut count = 0;
        while let Some((key, bytes)) = self.store.next_record_bounded(
            self.names.tombstones,
            after.as_deref(),
            48,
            ROW_BYTES,
        )? {
            count = increment(count, self.counts.tombstones)?;
            check(self.tombstone_row(&key, &bytes)?)?;
            after = Some(key);
        }
        exact(count, self.counts.tombstones)
    }
    fn each_revision(
        &self,
        mut check: impl FnMut(RevisionIdentity) -> Result<(), CatalogStoreError>,
    ) -> Result<(), CatalogStoreError> {
        let mut after = None;
        let mut count = 0;
        while let Some(identity) = self.next_identity(after)? {
            count = increment(count, self.counts.revisions)?;
            check(identity)?;
            after = Some(identity.key);
        }
        exact(count, self.counts.revisions)
    }
}

fn increment(count: u64, maximum: u64) -> Result<u64, CatalogStoreError> {
    count
        .checked_add(1)
        .filter(|count| *count <= maximum)
        .ok_or_else(|| DatabaseError::Integrity.into())
}
fn exact(count: u64, expected: u64) -> Result<(), CatalogStoreError> {
    if count != expected {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
pub(super) fn snapshot_hash(trust: &PagedCheckpointTrust) -> Result<[u8; 32], CatalogStoreError> {
    trust.validate()?;
    Ok(canonical_hash_bounded(
        &(
            trust.guild_id,
            trust.genesis_hash,
            trust.event_sequence,
            trust.event_head,
            trust.authority,
            &trust.members,
            trust
                .previous
                .map(|parent| (parent.generation, parent.hash)),
        ),
        SNAPSHOT_BYTES,
    )?)
}
fn validate_event_progress(
    previous: &PagedCheckpointTrust,
    current: &PagedCheckpointTrust,
) -> Result<(), CatalogStoreError> {
    if previous.guild_id != current.guild_id
        || previous.genesis_hash != current.genesis_hash
        || previous.event_sequence > current.event_sequence
        || previous.authority.membership_epoch > current.authority.membership_epoch
        || previous.event_sequence == current.event_sequence
            && previous.event_head != current.event_head
        || previous.authority.membership_epoch == current.authority.membership_epoch
            && (previous.members != current.members || previous.authority != current.authority)
        || previous.event_sequence == current.event_sequence
            && previous.authority != current.authority
    {
        return Err(DatabaseError::Conflict.into());
    }
    Ok(())
}

fn scan_reservation(
    current: Counts,
    previous: Counts,
    legacy: bool,
    members: usize,
) -> Result<Work, CatalogStoreError> {
    // Bound indexed row attempts, including original 4 KiB reference reads,
    // point joins, new-writer bookkeeping, EOFs and bounded snapshot rechecks.
    // Legacy initialization additionally charges every temporary indexed write.
    let mut rows = 64_u64
        .checked_add(
            (members as u64)
                .checked_mul(4)
                .ok_or(CatalogError::Bounds)?,
        )
        .ok_or(CatalogError::Bounds)?;
    for (count, multiplier) in [
        (current.fences, 4),
        (current.tombstones, 4),
        (current.revisions, 8),
        (previous.fences, if legacy { 8 } else { 2 }),
        (previous.tombstones, if legacy { 7 } else { 2 }),
        (previous.revisions, if legacy { 9 } else { 4 }),
    ] {
        rows = rows
            .checked_add(count.checked_mul(multiplier).ok_or(CatalogError::Bounds)?)
            .ok_or(CatalogError::Bounds)?;
    }
    Ok(Work {
        bytes: rows
            .checked_mul(CATALOG_CHECKPOINT_RECORD_BYTES as u64)
            .and_then(|bytes| bytes.checked_add(DESCRIPTOR_BYTES as u64))
            .ok_or(CatalogError::Bounds)?,
        records: rows,
        page_occurrences: 0,
    })
}

fn legacy_index(
    store: &RecordScratchStore,
    certificate: &QuorumCheckpoint,
) -> Result<(), CatalogStoreError> {
    let reserve_id = |id: Uuid| -> Result<(), CatalogStoreError> {
        if read::<bool>(store, LEGACY.ids, id.as_bytes())?.is_none() {
            insert(store, LEGACY.ids, id.as_bytes(), &true, ROW_BYTES)?;
        }
        Ok(())
    };
    for fence in &certificate.checkpoint.writer_fences {
        insert(store, LEGACY.history, &fence_key(fence), fence, ROW_BYTES)?;
        if let Some((_, bytes)) = read::<WriterFence>(store, LEGACY.latest, &fence.owner.0)? {
            replace(store, LEGACY.latest, &fence.owner.0, &bytes, fence)?;
        } else {
            insert(store, LEGACY.latest, &fence.owner.0, fence, ROW_BYTES)?;
        }
    }
    for tombstone in &certificate.checkpoint.revision_tombstones {
        insert(
            store,
            LEGACY.tombstones,
            &chain(tombstone.owner, tombstone.protected_root_id),
            tombstone,
            ROW_BYTES,
        )?;
        reserve_id(tombstone.last_revision_id)?;
    }
    for signed in &certificate.checkpoint.revisions {
        let identity = RevisionIdentity::legacy(signed)?;
        insert(
            store,
            LEGACY.identities,
            &identity.key.index_key(),
            &identity,
            ROW_BYTES,
        )?;
        reserve_id(identity.key.revision_id)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Manifest {
    format_version: u16,
    checkpoint_hash: [u8; 32],
    snapshot_hash: [u8; 32],
    previous_snapshot_hash: Option<[u8; 32]>,
    work: Work,
}

impl CatalogCheckpointCodingStateIndex {
    /// Compare a completed proposal with the exact independently trusted prior
    /// state. `budget` admits both complete public inputs and all bounded local
    /// row work without resetting either input's debt. `read_current_writer`
    /// must read the latest nonrevoked writer key from the same certified event
    /// snapshot supplied by `read_trust`; historical retained keys do not grant
    /// new-write authority. Lookups are cached for at most 256 active owners.
    /// No production database writer spans this disposable scratch transaction.
    pub fn validate_authority_transition(
        self,
        previous: Option<CatalogCheckpointPrevious<'_>>,
        budget: Work,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
        mut read_current_writer: impl FnMut(
            NodeId,
            &PagedCheckpointTrust,
        ) -> Result<Option<WriterFence>, CatalogStoreError>,
    ) -> Result<CatalogCheckpointTransitionIndex, CatalogStoreError> {
        let trust = read_trust()?;
        let header = self.header(&trust)?;
        let store = &self.index().index().packing().store;
        let counts = Counts::paged(self.index());
        let mut old_counts = Counts::default();
        let mut old_work = Work::default();
        let mut old_snapshot = None;
        let mut is_legacy = false;
        let mut previous_view = None;
        match &previous {
            None if trust.previous.is_none() => {}
            Some(CatalogCheckpointPrevious::Legacy {
                certificate,
                trust: old,
            }) => {
                old.validate()?;
                let size = canonical_size_bounded(certificate, V1_MAX_CATALOG_BYTES)?;
                let body = &certificate.checkpoint;
                let expected = trust.previous.ok_or(DatabaseError::Conflict)?;
                if body.guild_id != old.guild_id
                    || body.genesis_hash != old.genesis_hash
                    || body.members != old.members
                    || body.generation != old.next_generation()?
                    || body.parent != old.previous.map(|parent| parent.hash)
                    || body
                        .authority
                        .is_some_and(|authority| authority != old.authority)
                    || body.generation != expected.generation
                    || canonical_hash_bounded(body, V1_MAX_CATALOG_BYTES)? != expected.hash
                {
                    return Err(DatabaseError::Conflict.into());
                }
                validate_event_progress(old, &trust)?;
                old_counts = Counts::legacy(certificate);
                old_work = Work {
                    bytes: size as u64,
                    records: 1,
                    page_occurrences: 0,
                };
                old_snapshot = Some(snapshot_hash(old)?);
                is_legacy = true;
                previous_view = Some(View {
                    store,
                    names: LEGACY,
                    counts: old_counts,
                    guild_id: old.guild_id,
                    generation: body.generation,
                });
            }
            Some(CatalogCheckpointPrevious::Paged(previous)) => {
                let old = previous.trust();
                let body = &previous.certificate().checkpoint;
                let expected = trust.previous.ok_or(DatabaseError::Conflict)?;
                if body.generation != expected.generation || body.hash()? != expected.hash {
                    return Err(DatabaseError::Conflict.into());
                }
                validate_event_progress(old, &trust)?;
                old_counts = Counts::paged(previous.index());
                old_work = body.represented_work()?;
                old_snapshot = Some(snapshot_hash(old)?);
                previous_view = Some(View {
                    store: &previous.index().index().packing().store,
                    names: PAGED,
                    counts: old_counts,
                    guild_id: old.guild_id,
                    generation: body.generation,
                });
            }
            _ => return Err(DatabaseError::Conflict.into()),
        }
        let members = trust.members.len()
            + match &previous {
                Some(CatalogCheckpointPrevious::Legacy { trust, .. }) => trust.members.len(),
                Some(CatalogCheckpointPrevious::Paged(previous)) => previous.trust().members.len(),
                None => 0,
            };
        let work = self
            .represented_work()
            .checked_add(old_work)?
            .checked_add(scan_reservation(counts, old_counts, is_legacy, members)?)?;
        budget.remaining_after(work)?;
        let manifest = Manifest {
            format_version: 1,
            checkpoint_hash: header.hash()?,
            snapshot_hash: snapshot_hash(&trust)?,
            previous_snapshot_hash: old_snapshot,
            work,
        };
        encoded(&manifest, DESCRIPTOR_BYTES)?;
        let current = View {
            store,
            names: PAGED,
            counts,
            guild_id: trust.guild_id,
            generation: header.generation,
        };
        store.with_record_transaction(|| -> Result<(), CatalogStoreError> {
            for kind in KINDS {
                if store
                    .next_record_bounded(kind, None, 72, ROW_BYTES)?
                    .is_some()
                {
                    return Err(DatabaseError::Conflict.into());
                }
            }
            match &previous {
                Some(CatalogCheckpointPrevious::Legacy { certificate, .. }) => {
                    certificate.verify()?;
                    legacy_index(store, certificate)?;
                }
                Some(CatalogCheckpointPrevious::Paged(previous)) => {
                    previous.transition().require_complete()?;
                    previous
                        .certificate()
                        .verify_header(previous.trust(), previous.index().index().budget())?;
                }
                None => {}
            }
            if let Some(old) = &previous_view {
                old.each_fence(|fence| {
                    if current.historical_fence(&fence)? != Some(fence) {
                        return Err(DatabaseError::Conflict.into());
                    }
                    Ok(())
                })?;
                old.each_tombstone(|tombstone| {
                    let next = current
                        .tombstone(tombstone.owner, tombstone.protected_root_id)?
                        .ok_or(DatabaseError::Conflict)?;
                    if next.through_sequence < tombstone.through_sequence
                        || next.through_sequence == tombstone.through_sequence && next != tombstone
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                    Ok(())
                })?;
                old.each_revision(|identity| {
                    if let Some(next) = current.identity(identity.key)? {
                        if !identity.same_revision(next) {
                            return Err(DatabaseError::Conflict.into());
                        }
                    } else if current
                        .tombstone(identity.key.owner, identity.key.protected_root_id)?
                        .is_none_or(|tombstone| tombstone.through_sequence < identity.key.sequence)
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                    Ok(())
                })?;
            }
            current.each_tombstone(|tombstone| {
                let old = previous_view.as_ref().ok_or(DatabaseError::Conflict)?;
                let floor = old
                    .tombstone(tombstone.owner, tombstone.protected_root_id)?
                    .map_or(0, |old| old.through_sequence);
                if tombstone.through_sequence > floor {
                    let retired = old
                        .at_sequence(
                            tombstone.owner,
                            tombstone.protected_root_id,
                            tombstone.through_sequence,
                        )?
                        .ok_or(DatabaseError::Conflict)?;
                    if tombstone.retired_at_generation != header.generation
                        || tombstone.last_revision_id != retired.key.revision_id
                        || tombstone.last_revision_hash != retired.revision_hash
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                }
                Ok(())
            })?;
            // This cache is bounded by the independently checked active roster,
            // not by the number of roots, retained revisions or source entries.
            let mut writers: Vec<Option<Option<WriterFence>>> = vec![None; trust.members.len()];
            current.each_revision(|identity| {
                if let Some(old) = &previous_view {
                    if let Some(retained) = old.identity(identity.key)? {
                        if !identity.same_revision(retained) {
                            return Err(DatabaseError::Conflict.into());
                        }
                        return Ok(());
                    }
                    if old.used_id(identity.key.revision_id)? {
                        return Err(DatabaseError::Conflict.into());
                    }
                }
                let member = trust
                    .members
                    .binary_search_by_key(&identity.key.owner, |member| member.node_id)
                    .map_err(|_| DatabaseError::Conflict)?;
                if writers[member].is_none() {
                    writers[member] = Some(read_current_writer(identity.key.owner, &trust)?);
                }
                if writers[member].as_ref().and_then(|value| value.as_ref())
                    != Some(&identity.fence())
                    || current.latest(identity.key.owner)? != Some(identity.fence())
                {
                    return Err(ModelError::InvalidWriterFence.into());
                }
                if let Some((used, _)) = read::<WriterFence>(store, USED, &identity.key.owner.0)? {
                    if used != identity.fence() {
                        return Err(DatabaseError::Conflict.into());
                    }
                } else {
                    insert(
                        store,
                        USED,
                        &identity.key.owner.0,
                        &identity.fence(),
                        ROW_BYTES,
                    )?;
                }
                Ok(())
            })?;
            let mut latest: Option<WriterFence> = None;
            let check_latest = |fence: WriterFence| -> Result<(), CatalogStoreError> {
                if current.latest(fence.owner)? != Some(fence.clone()) {
                    return Err(DatabaseError::Integrity.into());
                }
                let old_epoch = previous_view
                    .as_ref()
                    .map(|old| old.latest(fence.owner))
                    .transpose()?
                    .flatten()
                    .map_or(0, |fence| fence.epoch);
                if fence.epoch < old_epoch {
                    return Err(DatabaseError::Conflict.into());
                }
                if fence.epoch > old_epoch
                    && (previous_view.is_some() && old_epoch.checked_add(1) != Some(fence.epoch)
                        || read::<WriterFence>(store, USED, &fence.owner.0)?.map(|row| row.0)
                            != Some(fence))
                {
                    return Err(ModelError::InvalidWriterFence.into());
                }
                Ok(())
            };
            current.each_fence(|fence| {
                match latest.take() {
                    Some(previous) if previous.owner == fence.owner => {
                        if previous.epoch.checked_add(1) != Some(fence.epoch) {
                            return Err(DatabaseError::Integrity.into());
                        }
                    }
                    Some(previous) => {
                        check_latest(previous)?;
                        if fence.epoch != 1 {
                            return Err(DatabaseError::Integrity.into());
                        }
                    }
                    None if fence.epoch != 1 => return Err(DatabaseError::Integrity.into()),
                    None => {}
                }
                latest = Some(fence);
                Ok(())
            })?;
            if let Some(fence) = latest {
                check_latest(fence)?;
            }
            if read_trust()? != trust {
                return Err(DatabaseError::Conflict.into());
            }
            self.header(&trust)?;
            if let Some(CatalogCheckpointPrevious::Paged(previous)) = &previous {
                previous.transition().require_complete()?;
            }
            insert(store, COMPLETE, b"root", &manifest, DESCRIPTOR_BYTES)
        })?;
        Ok(CatalogCheckpointTransitionIndex {
            index: self,
            trust,
            manifest,
            budget,
        })
    }
}

/// Complete bounded public authority transition under one trusted job budget.
/// Signing/binding requires this proof and its exact certified coding state.
/// Full coding transitions/fixed legacy migration, private/payload joins and
/// atomic durable publication remain separate gates.
pub struct CatalogCheckpointTransitionIndex {
    index: CatalogCheckpointCodingStateIndex,
    trust: PagedCheckpointTrust,
    manifest: Manifest,
    budget: Work,
}
impl CatalogCheckpointTransitionIndex {
    pub fn index(&self) -> &CatalogCheckpointCodingDirectoryIndex {
        self.index.index()
    }
    pub fn coding_state(&self) -> &CatalogCheckpointCodingStateIndex {
        &self.index
    }
    pub fn trust(&self) -> &PagedCheckpointTrust {
        &self.trust
    }
    pub fn represented_work(&self) -> Work {
        self.manifest.work
    }
    pub fn budget(&self) -> Work {
        self.budget
    }
    pub(super) fn require_complete(&self) -> Result<(), CatalogStoreError> {
        let header = self.index.header(&self.trust)?;
        self.budget.remaining_after(self.manifest.work)?;
        if self.manifest.format_version != 1
            || self.manifest.checkpoint_hash != header.hash()?
            || self.manifest.snapshot_hash != snapshot_hash(&self.trust)?
            || self
                .index
                .index()
                .index()
                .packing()
                .store
                .get_record_bounded(COMPLETE, b"root", DESCRIPTOR_BYTES)?
                .as_deref()
                != Some(encoded(&self.manifest, DESCRIPTOR_BYTES)?.as_slice())
        {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(())
    }
    pub(super) fn header(
        &self,
        trust: &PagedCheckpointTrust,
    ) -> Result<mb_core::PagedGuildCheckpoint, CatalogStoreError> {
        if trust != &self.trust {
            return Err(DatabaseError::Conflict.into());
        }
        self.require_complete()?;
        self.index.header(trust)
    }
}

#[cfg(test)]
mod tests {
    use super::super::checkpoint_validation::tests::Fixture;
    use super::*;
    use mb_core::{
        CatalogBuilder, CatalogLegacyRevisionRef, PagedCheckpointParent, QuorumPagedCheckpoint,
    };
    use std::cell::Cell;

    fn budget() -> Work {
        Work {
            bytes: 96 << 30,
            page_occurrences: 2_000_000,
            records: 128_000_000,
        }
    }
    fn writer(fixture: &Fixture, owner: NodeId) -> Option<WriterFence> {
        fixture
            .sources
            .certificate
            .checkpoint
            .writer_fences
            .iter()
            .filter(|fence| fence.owner == owner)
            .max_by_key(|fence| fence.epoch)
            .cloned()
    }
    fn certify(
        fixture: &Fixture,
        index: CatalogCheckpointTransitionIndex,
    ) -> CatalogQuorumPagedCheckpointIndex {
        let trust = index.trust().clone();
        let mut header = None;
        let mut signatures = Vec::new();
        for keys in &fixture.sources.keys {
            if trust
                .members
                .iter()
                .any(|member| member.node_id == keys.node_id())
            {
                let (value, signature) = index
                    .sign_paged_checkpoint_header(keys, || Ok(trust.clone()))
                    .unwrap();
                header = Some(value);
                signatures.push(signature);
            }
        }
        signatures.sort_by_key(|signature| signature.signer);
        index
            .bind_paged_checkpoint_header(
                QuorumPagedCheckpoint {
                    checkpoint: header.unwrap(),
                    signatures,
                },
                || Ok(trust.clone()),
            )
            .unwrap()
    }
    fn previous() -> (Fixture, CatalogQuorumPagedCheckpointIndex) {
        let mut fixture = Fixture::new(true, false);
        let records = fixture.sources.records.clone();
        fixture.replace_paged(fixture.paged().value, &records);
        let index = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let certificate = certify(&fixture, index);
        (fixture, certificate)
    }
    fn successor(
        previous_fixture: &Fixture,
        previous: &CatalogQuorumPagedCheckpointIndex,
    ) -> (Fixture, PagedCheckpointTrust) {
        let mut fixture = Fixture::new(true, false);
        fixture.records = previous_fixture.records.clone();
        fixture.pages = previous_fixture.pages.clone();
        fixture.context = previous_fixture.context;
        fixture.context.generation = previous.certificate().checkpoint.generation + 1;
        let mut trust = fixture.trust();
        trust.previous = Some(PagedCheckpointParent {
            generation: previous.certificate().checkpoint.generation,
            hash: previous.certificate().hash().unwrap(),
        });
        (fixture, trust)
    }
    fn paged(
        fixture: &mut Fixture,
        previous: &CatalogQuorumPagedCheckpointIndex,
        trust: &PagedCheckpointTrust,
    ) -> Result<CatalogCheckpointTransitionIndex, CatalogStoreError> {
        fixture
            .certified(budget(), CatalogCodingCoveragePolicy::Current, trust)
            .unwrap()
            .validate_authority_transition(
                Some(CatalogCheckpointPrevious::Paged(previous)),
                budget(),
                || Ok(trust.clone()),
                |owner, _| Ok(writer(fixture, owner)),
            )
    }
    fn append(fixture: &mut Fixture, count: u64) -> SignedRecord<PagedUserRevision> {
        let mut signed = fixture
            .records
            .iter()
            .filter_map(|record| match record {
                R::PagedRevision(signed) => Some(signed),
                _ => None,
            })
            .max_by_key(|signed| signed.value.sequence)
            .unwrap()
            .clone();
        for _ in 0..count {
            let mut next = signed.value.clone();
            next.sequence += 1;
            next.parent = Some(signed.value.hash().unwrap());
            next.revision_id = Uuid::from_u128(10_000 + u128::from(next.sequence));
            signed = next
                .sign(&fixture.sources.writer, &fixture.sources.keys[0])
                .unwrap();
            fixture.records.push(R::PagedRevision(signed.clone()));
        }
        signed
    }
    fn replace_legacy(fixture: &mut Fixture, signed: &SignedRecord<UserRevision>) {
        let mut sink = |page: CatalogPageRef, bytes| {
            fixture.pages.insert(page.hash, bytes);
            Ok::<_, ()>(())
        };
        let mut body = CatalogBuilder::new(
            CatalogScope::Guild {
                guild_id: signed.value.guild_id,
            },
            CatalogSection::Checkpoint,
        )
        .unwrap();
        body.push(&canonical_bytes(signed).unwrap(), &mut sink)
            .unwrap();
        let reference = CatalogLegacyRevisionRef::from_signed(
            signed.value.guild_id,
            signed,
            body.finish(&mut sink).unwrap(),
        )
        .unwrap();
        *fixture
            .records
            .iter_mut()
            .find(|record| matches!(record, R::LegacyRevision(_)))
            .unwrap() = R::LegacyRevision(reference);
    }
    fn retire(fixture: &mut Fixture, through: u64, retired: &SignedRecord<PagedUserRevision>) {
        let legacy = &fixture.sources.certificate.checkpoint.revisions[0];
        let (id, hash) = if through == 1 {
            (legacy.value.revision_id, legacy.value.hash().unwrap())
        } else {
            (retired.value.revision_id, retired.value.hash().unwrap())
        };
        fixture.records.retain(|record| {
            !matches!(record, R::Tombstone(_))
                && record
                    .revision_key()
                    .is_none_or(|key| key.sequence > through)
        });
        fixture.records.push(R::Tombstone(RevisionTombstone {
            owner: legacy.value.owner,
            protected_root_id: legacy.value.protected_root_id,
            through_sequence: through,
            last_revision_id: id,
            last_revision_hash: hash,
            retired_at_generation: fixture.context.generation,
        }));
    }

    #[test]
    fn authority_transition_accepts_initial_legacy_and_paged_continuations() {
        let mut initial = Fixture::new(true, false);
        initial.context.generation = 1;
        let mut trust = initial.trust();
        trust.previous = None;
        let index = initial
            .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
            .unwrap()
            .validate_authority_transition(
                None,
                budget(),
                || Ok(trust.clone()),
                |owner, _| Ok(writer(&initial, owner)),
            )
            .unwrap();
        assert_eq!(index.trust(), &trust);
        let certified = certify(&initial, index);
        assert_eq!(certified.certificate().checkpoint.generation, 1);
        for version in [3, 4, 5, 6, 7] {
            let mut fixture = Fixture::new(true, false);
            fixture.sources.certificate.checkpoint.format_version = version;
            if version == 3 {
                use mb_core::{
                    CodingGroup, InformationRole, KeyMaterial, Member, ParityRole, SectorRef, Seed,
                    ShardRole,
                };
                for seed in [14, 15] {
                    let keys = KeyMaterial::from_seed(&Seed::from_bytes([seed; 32]));
                    let member = Member {
                        node_id: keys.node_id(),
                        recovery_public_key: keys.recovery_public_key(),
                        failure_domain: format!("domain-{seed}"),
                    };
                    fixture.records.push(R::Member(member.clone()));
                    fixture.sources.certificate.checkpoint.members.push(member);
                    fixture.sources.keys.push(keys);
                }
                fixture
                    .sources
                    .certificate
                    .checkpoint
                    .members
                    .sort_by_key(|member| member.node_id);
                for (index, source) in fixture.sources.records.iter().enumerate() {
                    let keys = &fixture.sources.keys;
                    let mut group = CodingGroup {
                        id: [0; 32],
                        format_version: 1,
                        guild_id: fixture.context.guild_id,
                        data_shards: 3,
                        parity_shards: 2,
                        shard_size: 65536,
                        roles: [
                            ShardRole::Information(InformationRole {
                                owner: keys[0].node_id(),
                                sector: source.sector.clone(),
                            }),
                            ShardRole::Information(InformationRole {
                                owner: keys[1].node_id(),
                                sector: SectorRef {
                                    id: [80 + index as u8; 32],
                                    root: [81; 32],
                                    logical_len: 0,
                                },
                            }),
                            ShardRole::Information(InformationRole {
                                owner: keys[2].node_id(),
                                sector: SectorRef {
                                    id: [84 + index as u8; 32],
                                    root: [85; 32],
                                    logical_len: 0,
                                },
                            }),
                            ShardRole::Parity(ParityRole {
                                holder: keys[3].node_id(),
                                row: 0,
                                root: [86; 32],
                            }),
                            ShardRole::Parity(ParityRole {
                                holder: keys[4].node_id(),
                                row: 1,
                                root: [87; 32],
                            }),
                        ],
                    };
                    group.id = group.calculate_id().unwrap();
                    fixture
                        .sources
                        .certificate
                        .checkpoint
                        .coding_groups
                        .push(group);
                }
                fixture
                    .sources
                    .certificate
                    .checkpoint
                    .coding_groups
                    .sort_by_key(|group| group.id);
            }
            if version == 7 {
                let revision = &fixture.sources.certificate.checkpoint.revisions[0].value;
                fixture.sources.certificate.checkpoint.packing_catalog = Some(
                    mb_core::pack_incremental(
                        mb_core::PackingProfile {
                            format_version: 1,
                            sector_size: 65536,
                            slot_size: 16384,
                        },
                        None,
                        fixture
                            .sources
                            .records
                            .iter()
                            .zip(&fixture.sources.bytes)
                            .map(|(record, bytes)| mb_core::PackingInput {
                                owner: revision.owner,
                                protected_root: mb_core::packing_protected_root(
                                    revision.protected_root_id,
                                ),
                                object_id: record.sector.id,
                                source_commitment: Some(record.commitment.clone()),
                                bytes: bytes.clone(),
                            })
                            .collect(),
                    )
                    .unwrap()
                    .catalog,
                );
            }
            if version < 5 {
                fixture.sources.certificate.checkpoint.authority = None;
            }
            fixture.sources.resign();
            let index = fixture
                .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
                .unwrap();
            assert_eq!(
                index.trust().previous.unwrap().hash,
                fixture.sources.certificate.hash().unwrap()
            );
        }
        let (fixture, previous) = previous();
        let (mut next, trust) = successor(&fixture, &previous);
        let index = next
            .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
            .unwrap()
            .validate_authority_transition(
                Some(CatalogCheckpointPrevious::Paged(&previous)),
                budget(),
                || Ok(trust.clone()),
                |_, _| panic!("unchanged retained history requested a new writer"),
            )
            .unwrap();
        assert!(
            index.represented_work().records
                > previous
                    .certificate()
                    .checkpoint
                    .represented_work()
                    .unwrap()
                    .records
        );
        let current = certify(&next, index);
        assert_eq!(
            current.certificate().checkpoint.parent,
            Some(previous.certificate().hash().unwrap())
        );
        assert!(current.index().next_revision(None).unwrap().is_some());
    }

    #[test]
    fn authority_transition_binds_legacy_signature_original_identity_and_current_writer() {
        for mode in 0..5 {
            let mut fixture = Fixture::new(true, false);
            let mut old = fixture.sources.certificate.clone();
            let mut old_trust = fixture.previous_trust();
            let mut trust = fixture.trust();
            match mode {
                0 => old.signatures[0].signature[0] ^= 1,
                1 => old_trust.event_head[0] ^= 1,
                2 => old_trust.authority.membership_epoch += 1,
                3 => trust.previous.as_mut().unwrap().hash[0] ^= 1,
                _ => old_trust.members[0].failure_domain.push('x'),
            }
            let calls = Cell::new(0);
            let result = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Legacy {
                        certificate: &old,
                        trust: &old_trust,
                    }),
                    budget(),
                    || Ok(trust.clone()),
                    |owner, _| {
                        calls.set(calls.get() + 1);
                        Ok(writer(&fixture, owner))
                    },
                );
            assert!(result.is_err(), "mode {mode}");
            assert_eq!(calls.get(), 0);
        }
        for mode in 0..3 {
            let mut fixture = Fixture::new(true, false);
            let trust = fixture.trust();
            let old_trust = fixture.previous_trust();
            let result = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Legacy {
                        certificate: &fixture.sources.certificate,
                        trust: &old_trust,
                    }),
                    budget(),
                    || Ok(trust.clone()),
                    |owner, _| {
                        let mut fence = writer(&fixture, owner).unwrap();
                        match mode {
                            0 => return Ok(None),
                            1 => fence.epoch += 1,
                            _ => fence.public_key[0] ^= 1,
                        }
                        Ok(Some(fence))
                    },
                );
            assert!(result.is_err());
        }
        let mut fixture = Fixture::new(true, false);
        let trust = fixture.trust();
        let previous_trust = fixture.previous_trust();
        let mut changed = fixture.sources.certificate.checkpoint.revisions[0]
            .value
            .clone();
        changed.revision_id = Uuid::from_u128(99_999);
        changed.sign_writer(&fixture.sources.writer).unwrap();
        let signed = SignedRecord::sign(
            mb_core::USER_REVISION_DOMAIN,
            changed,
            &fixture.sources.keys[0],
        )
        .unwrap();
        replace_legacy(&mut fixture, &signed);
        let mut next = fixture.paged().value;
        next.parent = Some(signed.value.hash().unwrap());
        fixture.replace_paged(next, &fixture.sources.records.clone());
        // The complete proposed body is internally valid; it silently rewrites
        // the trusted first revision and must fail the previous-state join.
        assert!(
            fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Legacy {
                        certificate: &fixture.sources.certificate,
                        trust: &previous_trust
                    }),
                    budget(),
                    || Ok(trust.clone()),
                    |owner, _| Ok(writer(&fixture, owner))
                )
                .is_err()
        );
    }

    #[test]
    fn authority_transition_requires_one_step_writer_advance_with_certified_current_key() {
        use ed25519_dalek::SigningKey;
        for advance in [1, 2] {
            let mut fixture = Fixture::new(true, false);
            let old = fixture.sources.certificate.clone();
            let old_trust = fixture.previous_trust();
            fixture.context.event_sequence += advance;
            fixture.context.event_head = [92; 32];
            for epoch in 2..=1 + advance {
                let key = SigningKey::from_bytes(&[40 + epoch as u8; 32]);
                let fence = WriterFence {
                    owner: fixture.sources.keys[0].node_id(),
                    epoch,
                    public_key: key.verifying_key().to_bytes(),
                };
                fixture
                    .sources
                    .certificate
                    .checkpoint
                    .writer_fences
                    .push(fence.clone());
                fixture.records.push(R::WriterFence(fence));
                fixture.sources.writer = key;
            }
            let mut next = fixture.paged().value;
            next.writer_epoch = 1 + advance;
            next.writer_public_key = fixture.sources.writer.verifying_key().to_bytes();
            fixture.replace_paged(next, &fixture.sources.records.clone());
            let mut trust = fixture.trust();
            trust.previous = Some(PagedCheckpointParent {
                generation: 1,
                hash: old.hash().unwrap(),
            });
            let result = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Legacy {
                        certificate: &old,
                        trust: &old_trust,
                    }),
                    budget(),
                    || Ok(trust.clone()),
                    |owner, _| Ok(writer(&fixture, owner)),
                );
            if advance == 1 {
                result.unwrap();
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn authority_transition_checks_exact_monotone_retirement_and_previous_signed_floor() {
        let (fixture, previous) = previous();
        let (mut retained, trust) = successor(&fixture, &previous);
        retire(&mut retained, 1, &fixture.paged());
        let index = paged(&mut retained, &previous, &trust).unwrap();
        let with_tombstone = certify(&retained, index);
        for mode in 0..2 {
            let (mut next, trust) = successor(&retained, &with_tombstone);
            if mode == 0 {
                next.records
                    .retain(|record| !matches!(record, R::Tombstone(_)));
                next.records.extend(
                    fixture
                        .records
                        .iter()
                        .filter(|record| matches!(record, R::LegacyRevision(_)))
                        .cloned(),
                );
            } else if let R::Tombstone(tombstone) = next
                .records
                .iter_mut()
                .find(|record| matches!(record, R::Tombstone(_)))
                .unwrap()
            {
                tombstone.retired_at_generation = next.context.generation;
            }
            assert!(paged(&mut next, &with_tombstone, &trust).is_err());
        }
        let (mut next, trust) = successor(&retained, &with_tombstone);
        append(&mut next, 1);
        retire(&mut next, 2, &fixture.paged());
        paged(&mut next, &with_tombstone, &trust).unwrap();
        for mode in 0..4 {
            let (mut next, trust) = successor(&fixture, &previous);
            append(&mut next, if mode == 3 { 2 } else { 1 });
            let floor = if mode == 3 { 3 } else { 2 };
            let retired = next
                .records
                .iter()
                .find_map(|record| match record {
                    R::PagedRevision(signed) if signed.value.sequence == floor => {
                        Some(signed.clone())
                    }
                    _ => None,
                })
                .unwrap();
            retire(&mut next, floor, &retired);
            let mut parent = None;
            if let R::Tombstone(tombstone) = next
                .records
                .iter_mut()
                .find(|record| matches!(record, R::Tombstone(_)))
                .unwrap()
            {
                match mode {
                    0 => {
                        tombstone.last_revision_hash = [93; 32];
                        parent = Some(tombstone.last_revision_hash);
                    }
                    1 => tombstone.last_revision_id = Uuid::from_u128(9999),
                    2 => tombstone.retired_at_generation -= 1,
                    _ => {}
                }
            }
            let last = next
                .records
                .iter_mut()
                .find_map(|record| match record {
                    R::PagedRevision(signed) => Some(signed),
                    _ => None,
                })
                .unwrap();
            if let Some(parent) = parent {
                let mut value = last.value.clone();
                value.parent = Some(parent);
                *last = value
                    .sign(&next.sources.writer, &next.sources.keys[0])
                    .unwrap();
            }
            // Retirement cannot invent a signed predecessor or retire a new
            // candidate that was never present in the trusted previous state.
            assert!(paged(&mut next, &previous, &trust).is_err(), "mode {mode}");
        }
    }

    #[test]
    fn authority_transition_preserves_removed_history_and_rejects_new_mutation_or_reused_id() {
        let (fixture, previous) = previous();
        let (mut removed, mut trust) = successor(&fixture, &previous);
        let owner = removed.sources.keys[0].node_id();
        removed
            .sources
            .certificate
            .checkpoint
            .members
            .retain(|member| member.node_id != owner);
        removed
            .records
            .retain(|record| !matches!(record, R::Member(member) if member.node_id == owner));
        removed.context.event_sequence += 1;
        removed.context.event_head = [92; 32];
        removed.context.authority.membership_epoch += 1;
        trust.members.retain(|member| member.node_id != owner);
        trust.event_sequence = removed.context.event_sequence;
        trust.event_head = removed.context.event_head;
        trust.authority = removed.context.authority;
        let index = paged(&mut removed, &previous, &trust).unwrap();
        assert!(
            index
                .sign_paged_checkpoint_header(&removed.sources.keys[0], || Ok(trust.clone()))
                .is_err()
        );
        index
            .sign_paged_checkpoint_header(&removed.sources.keys[1], || Ok(trust.clone()))
            .unwrap();
        append(&mut removed, 1);
        assert!(paged(&mut removed, &previous, &trust).is_err());
        let (mut reused, trust) = successor(&fixture, &previous);
        let mut next = append(&mut reused, 1).value;
        retire(&mut reused, 2, &fixture.paged());
        next.revision_id = fixture.sources.certificate.checkpoint.revisions[0]
            .value
            .revision_id;
        let signed = next
            .sign(&reused.sources.writer, &reused.sources.keys[0])
            .unwrap();
        *reused
            .records
            .iter_mut()
            .find(|record| matches!(record, R::PagedRevision(_)))
            .unwrap() = R::PagedRevision(signed);
        // Current UUIDs are unique: the tombstone names revision two and the
        // new suffix reuses retired revision one's UUID. The old index catches it.
        assert!(paged(&mut reused, &previous, &trust).is_err());
    }

    #[test]
    fn authority_transition_admits_both_inputs_and_scan_before_large_join_or_writer_lookup() {
        let (fixture, previous) = previous();
        let mut widest = RevisionIdentity::paged(&fixture.paged()).unwrap();
        widest.key.sequence = u64::MAX;
        widest.key.revision_id = Uuid::from_u128(u128::MAX);
        widest.writer_epoch = u64::MAX;
        widest.parent = Some([255; 32]);
        let bytes = encoded(&widest, ROW_BYTES).unwrap();
        assert_eq!(
            decode_canonical::<RevisionIdentity>(&bytes).unwrap(),
            widest
        );
        let (mut next, trust) = successor(&fixture, &previous);
        append(&mut next, 1);
        let admitted = paged(&mut next, &previous, &trust).unwrap();
        let work = admitted.represented_work();
        let public = admitted
            .index()
            .header(&trust)
            .unwrap()
            .represented_work()
            .unwrap();
        let coding = admitted.coding_state().represented_work();
        let coding_rows = Work {
            bytes: coding.bytes.checked_sub(public.bytes).unwrap(),
            page_occurrences: coding
                .page_occurrences
                .checked_sub(public.page_occurrences)
                .unwrap(),
            records: coding.records.checked_sub(public.records).unwrap(),
        };
        assert!(coding_rows.bytes > 0 && coding_rows.records > 0);
        let reset = work.remaining_after(coding_rows).unwrap();
        drop(admitted);
        assert!(
            next.certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Paged(&previous)),
                    reset,
                    || Ok(trust.clone()),
                    |_, _| panic!("reset coding debt requested a current writer")
                )
                .is_err()
        );
        let rebuilt = next
            .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
            .unwrap()
            .validate_authority_transition(
                Some(CatalogCheckpointPrevious::Paged(&previous)),
                work,
                || Ok(trust.clone()),
                |owner, _| Ok(writer(&next, owner)),
            )
            .unwrap();
        assert_eq!(rebuilt.budget(), work);
        drop(rebuilt);
        for dimension in 0..3 {
            let mut limit = work;
            match dimension {
                0 => limit.bytes -= 1,
                1 => limit.page_occurrences -= 1,
                _ => limit.records -= 1,
            }
            assert!(
                next.certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                    .unwrap()
                    .validate_authority_transition(
                        Some(CatalogCheckpointPrevious::Paged(&previous)),
                        limit,
                        || Ok(trust.clone()),
                        |_, _| panic!("exhausted joint budget read a current writer")
                    )
                    .is_err()
            );
        }
        let calls = Cell::new(0);
        assert!(
            next.certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Paged(&previous)),
                    budget(),
                    || {
                        calls.set(calls.get() + 1);
                        let mut current = trust.clone();
                        if calls.get() == 2 {
                            current.event_head[0] ^= 1;
                        }
                        Ok(current)
                    },
                    |owner, _| Ok(writer(&next, owner))
                )
                .is_err()
        );
        assert_eq!(calls.get(), 2);
        let mut regressed = trust.clone();
        regressed.event_sequence -= 1;
        next.context.event_sequence = regressed.event_sequence;
        assert!(
            next.certified(budget(), CatalogCodingCoveragePolicy::Current, &regressed)
                .unwrap()
                .validate_authority_transition(
                    Some(CatalogCheckpointPrevious::Paged(&previous)),
                    budget(),
                    || Ok(regressed.clone()),
                    |_, _| panic!("regressed event requested writer")
                )
                .is_err()
        );
    }

    fn legacy_tombstone_fixture() -> Fixture {
        let mut fixture = Fixture::new(true, false);
        let mut value = fixture.sources.certificate.checkpoint.revisions[0]
            .value
            .clone();
        value.sequence = 2;
        value.parent = Some([90; 32]);
        value.sign_writer(&fixture.sources.writer).unwrap();
        let signed = SignedRecord::sign(
            mb_core::USER_REVISION_DOMAIN,
            value,
            &fixture.sources.keys[0],
        )
        .unwrap();
        let tombstone = RevisionTombstone {
            owner: signed.value.owner,
            protected_root_id: signed.value.protected_root_id,
            through_sequence: 1,
            last_revision_id: Uuid::from_u128(9999),
            last_revision_hash: [90; 32],
            retired_at_generation: 2,
        };
        let body = &mut fixture.sources.certificate.checkpoint;
        body.generation = 2;
        body.parent = Some([87; 32]);
        body.revision_tombstones.push(tombstone.clone());
        body.revisions[0] = signed.clone();
        fixture.sources.resign();
        fixture.context.generation = 3;
        replace_legacy(&mut fixture, &signed);
        let mut paged = fixture.paged().value;
        paged.sequence = 3;
        paged.parent = Some(signed.value.hash().unwrap());
        paged.revision_id = Uuid::from_u128(10003);
        fixture.replace_paged(paged, &fixture.sources.records.clone());
        fixture.records.push(R::Tombstone(tombstone));
        fixture
    }

    #[test]
    fn authority_transition_rejects_orphan_ignored_and_missing_rows_without_a_completed_prefix() {
        let mut fixture = legacy_tombstone_fixture();
        let trust = fixture.trust();
        let old_trust = fixture.previous_trust();
        for kind in KINDS {
            let index = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap();
            index
                .index()
                .index()
                .packing()
                .store
                .put_record_if_absent(kind, b"orphan", b"")
                .unwrap();
            assert!(
                index
                    .validate_authority_transition(
                        Some(CatalogCheckpointPrevious::Legacy {
                            certificate: &fixture.sources.certificate,
                            trust: &old_trust,
                        }),
                        budget(),
                        || Ok(trust.clone()),
                        |_, _| panic!("orphan transition requested current writer")
                    )
                    .is_err()
            );
        }
        for kind in KINDS {
            let index = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap();
            index.index().index().packing().store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_transition BEFORE INSERT ON scratch.protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
            assert!(
                index
                    .validate_authority_transition(
                        Some(CatalogCheckpointPrevious::Legacy {
                            certificate: &fixture.sources.certificate,
                            trust: &old_trust,
                        }),
                        budget(),
                        || Ok(trust.clone()),
                        |owner, _| Ok(writer(&fixture, owner))
                    )
                    .is_err(),
                "{kind}"
            );
        }
        for mode in 0..4 {
            let index = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap();
            let store = &index.index().index().packing().store;
            let key: Key = (&fixture.paged().value).into();
            let bytes = store
                .get_record_bounded(IDENTITIES, &key.index_key(), ROW_BYTES)
                .unwrap()
                .unwrap();
            match mode {
                0 => store
                    .delete_record_if_value(IDENTITIES, &key.index_key(), &bytes)
                    .unwrap(),
                1 => {
                    let mut value: RevisionIdentity = decode_canonical(&bytes).unwrap();
                    value.reference_hash[0] ^= 1;
                    store
                        .replace_record_if_value(
                            IDENTITIES,
                            &key.index_key(),
                            &bytes,
                            &encoded(&value, ROW_BYTES).unwrap(),
                        )
                        .unwrap();
                }
                2 => {
                    let bytes = store
                        .get_record_bounded(
                            REVISIONS,
                            &key.index_key(),
                            CATALOG_CHECKPOINT_RECORD_BYTES,
                        )
                        .unwrap()
                        .unwrap();
                    store
                        .delete_record_if_value(REVISIONS, &key.index_key(), &bytes)
                        .unwrap();
                }
                _ => {
                    let fence = writer(&fixture, key.owner).unwrap();
                    let key = fence_key(&fence);
                    let bytes = store
                        .get_record_bounded(HISTORY, &key, ROW_BYTES)
                        .unwrap()
                        .unwrap();
                    store.delete_record_if_value(HISTORY, &key, &bytes).unwrap();
                }
            }
            assert!(
                index
                    .validate_authority_transition(
                        Some(CatalogCheckpointPrevious::Legacy {
                            certificate: &fixture.sources.certificate,
                            trust: &old_trust,
                        }),
                        budget(),
                        || Ok(trust.clone()),
                        |owner, _| Ok(writer(&fixture, owner))
                    )
                    .is_err()
            );
        }
        let index = fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
        let store = &index.index().index().packing().store;
        let bytes = store
            .get_record_bounded(COMPLETE, b"root", DESCRIPTOR_BYTES)
            .unwrap()
            .unwrap();
        store
            .delete_record_if_value(COMPLETE, b"root", &bytes)
            .unwrap();
        assert!(
            index
                .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(trust.clone()))
                .is_err()
        );
        fixture
            .transitioned(budget(), CatalogCodingCoveragePolicy::Current)
            .unwrap();
    }

    #[test]
    fn authority_transition_spills_large_history_rejects_late_corruption_and_rebuilds_after_exhaustion()
     {
        let mut fixture = Fixture::new(true, false);
        fixture.context.event_sequence = 5000;
        let fence = fixture.sources.certificate.checkpoint.writer_fences[0].clone();
        let fences = (1..=4096)
            .map(|epoch| WriterFence {
                epoch,
                ..fence.clone()
            })
            .collect::<Vec<_>>();
        fixture.sources.certificate.checkpoint.writer_fences = fences.clone();
        fixture
            .records
            .retain(|record| !matches!(record, R::WriterFence(_)));
        fixture
            .records
            .extend(fences.into_iter().map(R::WriterFence));
        let mut legacy = fixture.sources.certificate.checkpoint.revisions[0]
            .value
            .clone();
        legacy.writer_epoch = 4096;
        legacy.sign_writer(&fixture.sources.writer).unwrap();
        let signed = SignedRecord::sign(
            mb_core::USER_REVISION_DOMAIN,
            legacy,
            &fixture.sources.keys[0],
        )
        .unwrap();
        fixture.sources.certificate.checkpoint.revisions[0] = signed.clone();
        fixture.sources.resign();
        replace_legacy(&mut fixture, &signed);
        let mut paged = fixture.paged().value;
        paged.writer_epoch = 4096;
        paged.parent = Some(signed.value.hash().unwrap());
        fixture.replace_paged(paged, &fixture.sources.records.clone());
        let trust = fixture.trust();
        let old_trust = fixture.previous_trust();
        for mode in 0..2 {
            let index = fixture
                .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
                .unwrap();
            let store = &index.index().index().packing().store;
            if mode == 0 {
                let pages = store
                    .database_shell_statement("PRAGMA scratch.page_count", false)
                    .unwrap()
                    .rows[0][0]
                    .parse::<u64>()
                    .unwrap();
                store
                    .database_shell_statement(
                        &format!("PRAGMA scratch.max_page_count={}", pages + 16),
                        false,
                    )
                    .unwrap();
            } else {
                let mut last = writer(&fixture, fixture.sources.keys[0].node_id()).unwrap();
                let key = fence_key(&last);
                let bytes = store
                    .get_record_bounded(HISTORY, &key, ROW_BYTES)
                    .unwrap()
                    .unwrap();
                last.public_key[0] ^= 1;
                store
                    .replace_record_if_value(
                        HISTORY,
                        &key,
                        &bytes,
                        &encoded(&last, ROW_BYTES).unwrap(),
                    )
                    .unwrap();
            }
            assert!(
                index
                    .validate_authority_transition(
                        Some(CatalogCheckpointPrevious::Legacy {
                            certificate: &fixture.sources.certificate,
                            trust: &old_trust,
                        }),
                        budget(),
                        || Ok(trust.clone()),
                        |_, _| panic!("failed legacy history prefix requested writer")
                    )
                    .is_err()
            );
        }
        let calls = Cell::new(0);
        let index = fixture
            .certified(budget(), CatalogCodingCoveragePolicy::Current, &trust)
            .unwrap()
            .validate_authority_transition(
                Some(CatalogCheckpointPrevious::Legacy {
                    certificate: &fixture.sources.certificate,
                    trust: &old_trust,
                }),
                budget(),
                || Ok(trust.clone()),
                |owner, _| {
                    calls.set(calls.get() + 1);
                    Ok(writer(&fixture, owner))
                },
            )
            .unwrap();
        let pages = index
            .index()
            .index()
            .packing()
            .store
            .database_shell_statement("PRAGMA scratch.page_count", false)
            .unwrap()
            .rows[0][0]
            .parse::<u64>()
            .unwrap();
        assert!(pages * 4096 > 1 << 20);
        assert_eq!(calls.get(), 1);
        assert!(index.represented_work().records > 4096 * 12);
        index
            .sign_paged_checkpoint_header(&fixture.sources.keys[0], || Ok(trust.clone()))
            .unwrap();
    }
}
