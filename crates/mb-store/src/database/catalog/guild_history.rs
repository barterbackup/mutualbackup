//! Disposable bounded replay of independently anchored original guild history.
//! This is not a durable current-tip publication or a source/payload owner.
use mb_core::{
    CATALOG_CODING_TRANSCRIPT_BYTES, CatalogCodingLifecycle, CatalogCodingTraversalBudget as Work,
    CodingProfile, CodingReplayFinding, GUILD_AUTHORITY_SNAPSHOT_BYTES, GUILD_EVENT_BYTES,
    GuildAuthoritySnapshot, GuildEventKind, LEGACY_CODING_ADD_BINDING_BYTES, NodeId,
    PagedCheckpointTrust, QuorumGuildEvent, QuorumGuildGenesis, QuorumLegacyCodingAddBinding,
    RecoveryKeyEpoch, RetainedCodingGroup, WriterFence, WriterKeyEpoch, canonical_bytes_bounded,
    canonical_size_bounded, decode_coding_transcript_bounded, replay_coding_transcript,
};
use serde::de::DeserializeOwned;

use super::checkpoint_transition::snapshot_hash;
use super::*;
use crate::RecordScratchStore;

const MEMBERS: &str = "guild-history-membership";
const WRITERS: &str = "guild-history-writer";
const LATEST_WRITER: &str = "guild-history-latest-writer";
const RECOVERY: &str = "guild-history-recovery";
const LATEST_RECOVERY: &str = "guild-history-latest-recovery";
const GROUPS: &str = "guild-history-group";
const FACTS: &str = "guild-history-coding-fact";
const COMPLETE: &str = "guild-history-complete";
const KINDS: [&str; 8] = [
    MEMBERS,
    WRITERS,
    LATEST_WRITER,
    RECOVERY,
    LATEST_RECOVERY,
    GROUPS,
    FACTS,
    COMPLETE,
];
const ROW_BYTES: usize = 256;
const RECOVERY_BYTES: usize = 6144;
const GROUP_BYTES: usize = GUILD_EVENT_BYTES;
const MARKER_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CatalogGuildHistoryObject {
    Event(u64),
    /// The exact original signed transcript for this Add event hash.
    Transcript([u8; 32]),
    LegacyBinding([u8; 32]),
}

/// Metadata must precede payload allocation. The final independently trusted
/// tip is reread after exact event EOF; a concurrent append/change rejects the
/// job. Unavailable original evidence rejects rather than recreating identity.
pub trait CatalogGuildHistorySource {
    fn next_event(&mut self, after: Option<u64>)
    -> Result<Option<(u64, usize)>, CatalogStoreError>;
    fn length(
        &mut self,
        object: CatalogGuildHistoryObject,
    ) -> Result<Option<usize>, CatalogStoreError>;
    fn read(
        &mut self,
        object: CatalogGuildHistoryObject,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError>;
}

fn location(object: CatalogGuildHistoryObject) -> (&'static str, Vec<u8>) {
    match object {
        CatalogGuildHistoryObject::Event(sequence) => {
            ("guild-event", sequence.to_be_bytes().to_vec())
        }
        CatalogGuildHistoryObject::Transcript(hash) => ("coding-event-transcript", hash.to_vec()),
        CatalogGuildHistoryObject::LegacyBinding(hash) => {
            ("coding-legacy-add-binding", hash.to_vec())
        }
    }
}

impl CatalogGuildHistorySource for &ControlStore {
    fn next_event(
        &mut self,
        after: Option<u64>,
    ) -> Result<Option<(u64, usize)>, CatalogStoreError> {
        let after = after.map(u64::to_be_bytes);
        self.next_record_metadata_bounded(
            "guild-event",
            after.as_ref().map(|key| key.as_slice()),
            8,
        )?
        .map(|(key, length)| {
            Ok((
                u64::from_be_bytes(key.try_into().map_err(|_| DatabaseError::Integrity)?),
                length,
            ))
        })
        .transpose()
    }
    fn length(
        &mut self,
        object: CatalogGuildHistoryObject,
    ) -> Result<Option<usize>, CatalogStoreError> {
        let (kind, key) = location(object);
        Ok(self.record_length(kind, &key)?)
    }
    fn read(
        &mut self,
        object: CatalogGuildHistoryObject,
        limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        let (kind, key) = location(object);
        Ok(self.get_record_bounded(kind, &key, limit)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Group {
    retained: RetainedCodingGroup,
    transcript_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Fact {
    guild_id: [u8; 32],
    lifecycle: CatalogCodingLifecycle,
    profile: CodingProfile,
    transcript_hash: [u8; 32],
    current: bool,
}
impl Fact {
    fn public(self) -> CatalogCertifiedCodingGroup {
        CatalogCertifiedCodingGroup {
            guild_id: self.guild_id,
            lifecycle: self.lifecycle,
            profile: self.profile,
            transcript_hash: self.transcript_hash,
            authorization: if self.current {
                CatalogCodingAuthorization::CurrentPlacement
            } else {
                CatalogCodingAuthorization::Retained
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Manifest {
    format_version: u16,
    snapshot_hash: [u8; 32],
    retained_groups: u64,
    retired_groups: u64,
    work: Work,
}

struct Meter {
    budget: Work,
    used: Work,
}
impl Meter {
    fn charge(&mut self, bytes: usize, records: u64) -> Result<(), CatalogStoreError> {
        let next = self.used.checked_add(Work {
            bytes: bytes.try_into().map_err(|_| CatalogError::Bounds)?,
            page_occurrences: 0,
            records,
        })?;
        self.budget.remaining_after(next)?;
        self.used = next;
        Ok(())
    }
    fn metadata(&mut self) -> Result<(), CatalogStoreError> {
        self.charge(ROW_BYTES, 1)
    }
}

fn get<T: DeserializeOwned + Serialize>(
    store: &RecordScratchStore,
    meter: &mut Meter,
    kind: &str,
    key: &[u8],
    limit: usize,
) -> Result<Option<(T, Vec<u8>)>, CatalogStoreError> {
    meter.metadata()?;
    let Some(length) = store.record_length(kind, key)? else {
        return Ok(None);
    };
    if length == 0 || length > limit {
        return Err(DatabaseError::Integrity.into());
    }
    meter.charge(length, 1)?;
    let bytes = store
        .get_record_bounded(kind, key, length)?
        .ok_or(DatabaseError::Integrity)?;
    if bytes.len() != length {
        return Err(DatabaseError::Integrity.into());
    }
    let value = decode_canonical(&bytes)?;
    if canonical_bytes_bounded(&value, limit)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some((value, bytes)))
}

fn write<T: Serialize>(
    store: &RecordScratchStore,
    meter: &mut Meter,
    kind: &str,
    key: &[u8],
    value: &T,
    limit: usize,
    old: Option<&[u8]>,
) -> Result<(), CatalogStoreError> {
    let length = canonical_size_bounded(value, limit)?;
    meter.charge(length.checked_mul(2).ok_or(CatalogError::Bounds)?, 2)?;
    let bytes = canonical_bytes_bounded(value, limit)?;
    if let Some(old) = old {
        store.replace_record_if_value(kind, key, old, &bytes)?;
    } else if !store.put_record_if_absent(kind, key, &bytes)? {
        return Err(DatabaseError::Conflict.into());
    }
    if store.get_record_bounded(kind, key, limit)?.as_deref() != Some(bytes.as_slice()) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn fetch(
    source: &mut impl CatalogGuildHistorySource,
    meter: &mut Meter,
    object: CatalogGuildHistoryObject,
    known: Option<usize>,
    limit: usize,
) -> Result<Vec<u8>, CatalogStoreError> {
    let length = if let Some(length) = known {
        length
    } else {
        meter.metadata()?;
        source.length(object)?.ok_or(DatabaseError::NotReady)?
    };
    if length == 0 || length > limit {
        return Err(CatalogError::Bounds.into());
    }
    meter.charge(length, 1)?;
    let bytes = source
        .read(object, length)?
        .ok_or(DatabaseError::NotReady)?;
    if bytes.len() != length {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(bytes)
}

fn epoch_key(owner: NodeId, epoch: u64) -> [u8; 40] {
    let mut key = [0; 40];
    key[..32].copy_from_slice(&owner.0);
    key[32..].copy_from_slice(&epoch.to_be_bytes());
    key
}

fn latest(
    store: &RecordScratchStore,
    meter: &mut Meter,
    kind: &str,
    owner: NodeId,
) -> Result<Option<(u64, Vec<u8>)>, CatalogStoreError> {
    let row = get::<u64>(store, meter, kind, &owner.0, ROW_BYTES)?;
    if row.as_ref().is_some_and(|(epoch, _)| *epoch == 0) {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(row)
}

/// Owns a complete private disposable projection. No public decoder or raw
/// store access can manufacture a completion token. Carry represented_work
/// into the enclosing checkpoint's aggregate admission; this job does not own
/// durable guild-current, checkpoint, private or information/parity payloads.
pub struct CatalogGuildHistoryIndex {
    store: RecordScratchStore,
    trust: CatalogCheckpointCodingTrust,
    manifest: Manifest,
    budget: Work,
}

impl CatalogGuildHistoryIndex {
    pub fn build(
        store: RecordScratchStore,
        genesis: &QuorumGuildGenesis,
        budget: Work,
        prior_work: Work,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
        source: &mut impl CatalogGuildHistorySource,
    ) -> Result<Self, CatalogStoreError> {
        budget.remaining_after(prior_work)?;
        let checkpoint = read_trust()?;
        checkpoint.validate()?;
        let mut meter = Meter {
            budget,
            used: prior_work,
        };
        // Fixed marker write/readback and end/view checks are reserved before
        // deriving its own work field, avoiding a circular encoded-size debt.
        meter.charge(MARKER_BYTES * 3 + GUILD_AUTHORITY_SNAPSHOT_BYTES * 3, 6)?;
        let genesis_bytes = canonical_size_bounded(genesis, GUILD_AUTHORITY_SNAPSHOT_BYTES)?;
        meter.charge(genesis_bytes, 1)?;
        let mut snapshot = GuildAuthoritySnapshot::from_genesis(genesis)?;
        if checkpoint.guild_id != snapshot.guild_id
            || checkpoint.genesis_hash != snapshot.event_head
        {
            return Err(DatabaseError::Conflict.into());
        }
        let hash = snapshot_hash(&checkpoint)?;
        let manifest =
            store.with_record_transaction(|| -> Result<Manifest, CatalogStoreError> {
                for kind in KINDS {
                    meter.metadata()?;
                    if store
                        .next_record_metadata_bounded(kind, None, 40)?
                        .is_some()
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                }
                write(
                    &store,
                    &mut meter,
                    MEMBERS,
                    &1_u64.to_be_bytes(),
                    &snapshot,
                    GUILD_AUTHORITY_SNAPSHOT_BYTES,
                    None,
                )?;
                let mut after = None;
                let mut retained = 0_u64;
                let mut retired = 0_u64;
                loop {
                    meter.metadata()?;
                    let Some((sequence, length)) = source.next_event(after)? else {
                        break;
                    };
                    if Some(sequence) != snapshot.event_sequence.checked_add(1)
                        || sequence > checkpoint.event_sequence
                    {
                        return Err(DatabaseError::Conflict.into());
                    }
                    let bytes = fetch(
                        source,
                        &mut meter,
                        CatalogGuildHistoryObject::Event(sequence),
                        Some(length),
                        GUILD_EVENT_BYTES,
                    )?;
                    let certified = QuorumGuildEvent::decode_bounded(&bytes)?;
                    if certified.event.sequence != sequence {
                        return Err(DatabaseError::Integrity.into());
                    }
                    let epoch = snapshot.membership_epoch;
                    snapshot.advance_indexed(&certified, |before, _| {
                        apply_effect(
                            &store,
                            &mut meter,
                            source,
                            before,
                            &certified,
                            &mut retained,
                            &mut retired,
                        )
                    })?;
                    if snapshot.membership_epoch != epoch {
                        write(
                            &store,
                            &mut meter,
                            MEMBERS,
                            &snapshot.membership_epoch.to_be_bytes(),
                            &snapshot,
                            GUILD_AUTHORITY_SNAPSHOT_BYTES,
                            None,
                        )?;
                    }
                    after = Some(sequence);
                }
                if !matches_tip(&snapshot, &checkpoint) {
                    return Err(DatabaseError::Conflict.into());
                }
                let mut after_group: Option<Vec<u8>> = None;
                let mut count = 0_u64;
                let mut retired_count = 0_u64;
                loop {
                    meter.metadata()?;
                    let Some((key, length)) =
                        store.next_record_metadata_bounded(GROUPS, after_group.as_deref(), 32)?
                    else {
                        break;
                    };
                    if key.len() != 32 || length == 0 || length > GROUP_BYTES {
                        return Err(DatabaseError::Integrity.into());
                    }
                    let (group, _) = get::<Group>(&store, &mut meter, GROUPS, &key, GROUP_BYTES)?
                        .ok_or(DatabaseError::Integrity)?;
                    validate_group(&group, &key, checkpoint.event_sequence)?;
                    count = count
                        .checked_add(1)
                        .filter(|value| *value <= retained)
                        .ok_or(DatabaseError::Integrity)?;
                    retired_count += u64::from(group.retained.retired_at_event.is_some());
                    let public = CatalogCertifiedCodingGroup::from_retained(
                        &group.retained,
                        group.transcript_hash,
                        CatalogCodingAuthorization::Retained,
                    )?;
                    let fact = Fact {
                        guild_id: public.guild_id,
                        lifecycle: public.lifecycle,
                        profile: public.profile,
                        transcript_hash: public.transcript_hash,
                        current: snapshot
                            .validate_current_group_placement(&group.retained.group)
                            .is_ok(),
                    };
                    write(&store, &mut meter, FACTS, &key, &fact, ROW_BYTES, None)?;
                    after_group = Some(key);
                }
                if count != retained || retired_count != retired || read_trust()? != checkpoint {
                    return Err(DatabaseError::Conflict.into());
                }
                let manifest = Manifest {
                    format_version: 1,
                    snapshot_hash: hash,
                    retained_groups: retained,
                    retired_groups: retired,
                    work: meter.used,
                };
                // Already reserved above. Check ignored writes and exact readback.
                super::coding_coverage::put(&store, COMPLETE, b"root", &manifest, MARKER_BYTES)?;
                if read_trust()? != checkpoint {
                    return Err(DatabaseError::Conflict.into());
                }
                Ok(manifest)
            })?;
        Ok(Self {
            store,
            trust: CatalogCheckpointCodingTrust {
                checkpoint,
                retained_groups: manifest.retained_groups,
                retired_groups: manifest.retired_groups,
            },
            manifest,
            budget,
        })
    }

    pub fn represented_work(&self) -> Work {
        self.manifest.work
    }

    /// Recheck the frozen independent tip and private completion once around
    /// each enclosing scan. Point reads through this view have fixed bounds;
    /// they do not reread a large marker or replay a full descriptor per group.
    pub fn view(
        &self,
        mut read_trust: impl FnMut() -> Result<PagedCheckpointTrust, CatalogStoreError>,
    ) -> Result<CatalogGuildHistoryView<'_>, CatalogStoreError> {
        self.budget.remaining_after(self.manifest.work)?;
        if read_trust()? != self.trust.checkpoint
            || snapshot_hash(&self.trust.checkpoint)? != self.manifest.snapshot_hash
            || self
                .store
                .get_record_bounded(COMPLETE, b"root", MARKER_BYTES)?
                .as_deref()
                != Some(canonical_bytes_bounded(&self.manifest, MARKER_BYTES)?.as_slice())
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(CatalogGuildHistoryView { index: self })
    }
}

fn matches_tip(snapshot: &GuildAuthoritySnapshot, trust: &PagedCheckpointTrust) -> bool {
    snapshot.guild_id == trust.guild_id
        && snapshot.event_sequence == trust.event_sequence
        && snapshot.event_head == trust.event_head
        && snapshot.membership_epoch == trust.authority.membership_epoch
        && snapshot.quorum == trust.authority.quorum
        && snapshot.active_members().eq(trust.members.iter())
}

fn validate_group(group: &Group, key: &[u8], sequence: u64) -> Result<(), CatalogStoreError> {
    let retained = &group.retained;
    retained.group.validate()?;
    if retained.group.id.as_slice() != key
        || group.transcript_hash == [0; 32]
        || retained.added_at_event == 0
        || retained.added_at_event > sequence
        || retained.retired_at_event.is_some() != retained.retain_through_event.is_some()
        || retained
            .retired_at_event
            .is_some_and(|event| event < retained.added_at_event || event > sequence)
        || retained
            .retain_through_event
            .is_some_and(|event| event < retained.retired_at_event.unwrap_or(0))
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

fn apply_effect(
    store: &RecordScratchStore,
    meter: &mut Meter,
    source: &mut impl CatalogGuildHistorySource,
    snapshot: &GuildAuthoritySnapshot,
    certified: &QuorumGuildEvent,
    retained: &mut u64,
    retired: &mut u64,
) -> Result<(), CatalogStoreError> {
    let sequence = certified.event.sequence;
    match &certified.event.kind {
        GuildEventKind::AddMember { .. }
        | GuildEventKind::RemoveMember { .. }
        | GuildEventKind::RelabelMember { .. }
        | GuildEventKind::SetQuorum { .. } => {}
        GuildEventKind::RotateWriterKey {
            owner,
            epoch,
            public_key,
        } => {
            if !snapshot
                .active_members()
                .any(|member| member.node_id == *owner)
            {
                return Err(DatabaseError::Conflict.into());
            }
            let key =
                ed25519_dalek::VerifyingKey::from_bytes(public_key).map_err(ModelError::from)?;
            let previous = latest(store, meter, LATEST_WRITER, *owner)?;
            if key.is_weak()
                || Some(*epoch)
                    != previous
                        .as_ref()
                        .map_or(Some(1), |(epoch, _)| epoch.checked_add(1))
            {
                return Err(DatabaseError::Conflict.into());
            }
            write(
                store,
                meter,
                WRITERS,
                &epoch_key(*owner, *epoch),
                &WriterKeyEpoch {
                    owner: *owner,
                    epoch: *epoch,
                    public_key: *public_key,
                    activated_at_event: sequence,
                    revoked_at_event: None,
                },
                ROW_BYTES,
                None,
            )?;
            write(
                store,
                meter,
                LATEST_WRITER,
                &owner.0,
                epoch,
                ROW_BYTES,
                previous.as_ref().map(|(_, bytes)| bytes.as_slice()),
            )?;
        }
        GuildEventKind::RevokeWriterKey { owner, epoch } => {
            let key = epoch_key(*owner, *epoch);
            let (mut entry, old) = get::<WriterKeyEpoch>(store, meter, WRITERS, &key, ROW_BYTES)?
                .ok_or(DatabaseError::Conflict)?;
            validate_writer(&entry, *owner, *epoch, snapshot.event_sequence)?;
            if entry.revoked_at_event.is_some() {
                return Err(DatabaseError::Conflict.into());
            }
            entry.revoked_at_event = Some(sequence);
            write(store, meter, WRITERS, &key, &entry, ROW_BYTES, Some(&old))?;
        }
        GuildEventKind::RotateRecoveryKey { envelope } => {
            if !snapshot
                .active_members()
                .any(|member| member.node_id == envelope.subject)
            {
                return Err(DatabaseError::Conflict.into());
            }
            envelope.validate_for_guild(snapshot.guild_id)?;
            let previous = latest(store, meter, LATEST_RECOVERY, envelope.subject)?;
            if Some(envelope.epoch)
                != previous
                    .as_ref()
                    .map_or(Some(1), |(epoch, _)| epoch.checked_add(1))
            {
                return Err(DatabaseError::Conflict.into());
            }
            write(
                store,
                meter,
                RECOVERY,
                &epoch_key(envelope.subject, envelope.epoch),
                &RecoveryKeyEpoch {
                    envelope: envelope.clone(),
                    activated_at_event: sequence,
                    revoked_at_event: None,
                },
                RECOVERY_BYTES,
                None,
            )?;
            write(
                store,
                meter,
                LATEST_RECOVERY,
                &envelope.subject.0,
                &envelope.epoch,
                ROW_BYTES,
                previous.as_ref().map(|(_, bytes)| bytes.as_slice()),
            )?;
        }
        GuildEventKind::RevokeRecoveryKey { subject, epoch } => {
            let key = epoch_key(*subject, *epoch);
            let (mut entry, old) =
                get::<RecoveryKeyEpoch>(store, meter, RECOVERY, &key, RECOVERY_BYTES)?
                    .ok_or(DatabaseError::Conflict)?;
            validate_recovery(
                &entry,
                *subject,
                *epoch,
                snapshot.guild_id,
                snapshot.event_sequence,
            )?;
            if entry.revoked_at_event.is_some() {
                return Err(DatabaseError::Conflict.into());
            }
            entry.revoked_at_event = Some(sequence);
            write(
                store,
                meter,
                RECOVERY,
                &key,
                &entry,
                RECOVERY_BYTES,
                Some(&old),
            )?;
        }
        GuildEventKind::AddCodingGroup { group }
        | GuildEventKind::AddCodingGroupBound { group, .. } => {
            group.validate()?;
            snapshot.validate_current_group_placement(group)?;
            if group.guild_id != snapshot.guild_id
                || get::<Group>(store, meter, GROUPS, &group.id, GROUP_BYTES)?.is_some()
            {
                return Err(DatabaseError::Conflict.into());
            }
            let event_hash = certified.event.hash()?;
            let expected = if let GuildEventKind::AddCodingGroupBound {
                transcript_hash, ..
            } = &certified.event.kind
            {
                *transcript_hash
            } else {
                let bytes = fetch(
                    source,
                    meter,
                    CatalogGuildHistoryObject::LegacyBinding(event_hash),
                    None,
                    LEGACY_CODING_ADD_BINDING_BYTES,
                )?;
                let binding = QuorumLegacyCodingAddBinding::decode_bounded(&bytes)?;
                snapshot.verify_legacy_coding_add_binding(&binding, certified)?;
                binding.statement.transcript_hash
            };
            let bytes = fetch(
                source,
                meter,
                CatalogGuildHistoryObject::Transcript(event_hash),
                None,
                CATALOG_CODING_TRANSCRIPT_BYTES,
            )?;
            if *blake3::hash(&bytes).as_bytes() != expected {
                return Err(DatabaseError::Conflict.into());
            }
            let transcript = decode_coding_transcript_bounded(&bytes)?;
            if transcript.value.manifest.value.group != *group
                || replay_coding_transcript(&transcript).map_err(|_| DatabaseError::Integrity)?
                    != CodingReplayFinding::Verified
            {
                return Err(DatabaseError::Integrity.into());
            }
            let plan = &transcript.value.plan.value;
            let (historical, bytes) = get::<GuildAuthoritySnapshot>(
                store,
                meter,
                MEMBERS,
                &plan.membership_epoch.to_be_bytes(),
                GUILD_AUTHORITY_SNAPSHOT_BYTES,
            )?
            .ok_or(DatabaseError::Conflict)?;
            GuildAuthoritySnapshot::decode(&bytes)?;
            if historical.membership_epoch != plan.membership_epoch {
                return Err(DatabaseError::Integrity.into());
            }
            historical.validate_attempt_authority(plan)?;
            write(
                store,
                meter,
                GROUPS,
                &group.id,
                &Group {
                    retained: RetainedCodingGroup {
                        group: group.clone(),
                        added_at_event: sequence,
                        retired_at_event: None,
                        retain_through_event: None,
                    },
                    transcript_hash: expected,
                },
                GROUP_BYTES,
                None,
            )?;
            *retained = retained.checked_add(1).ok_or(CatalogError::Bounds)?;
        }
        GuildEventKind::RetireCodingGroup {
            group_id,
            retain_through_event,
        } => {
            let (mut group, old) = get::<Group>(store, meter, GROUPS, group_id, GROUP_BYTES)?
                .ok_or(DatabaseError::Conflict)?;
            validate_group(&group, group_id, snapshot.event_sequence)?;
            if group.retained.retired_at_event.is_some() || *retain_through_event < sequence {
                return Err(DatabaseError::Conflict.into());
            }
            group.retained.retired_at_event = Some(sequence);
            group.retained.retain_through_event = Some(*retain_through_event);
            write(
                store,
                meter,
                GROUPS,
                group_id,
                &group,
                GROUP_BYTES,
                Some(&old),
            )?;
            *retired = retired.checked_add(1).ok_or(CatalogError::Bounds)?;
        }
        GuildEventKind::ForgetCodingGroup { group_id } => {
            let (group, old) = get::<Group>(store, meter, GROUPS, group_id, GROUP_BYTES)?
                .ok_or(DatabaseError::Conflict)?;
            validate_group(&group, group_id, snapshot.event_sequence)?;
            if group
                .retained
                .retain_through_event
                .is_none_or(|through| sequence <= through)
            {
                return Err(DatabaseError::Conflict.into());
            }
            meter.metadata()?;
            store.delete_record_if_value(GROUPS, group_id, &old)?;
            if get::<Group>(store, meter, GROUPS, group_id, GROUP_BYTES)?.is_some() {
                return Err(DatabaseError::Integrity.into());
            }
            *retained = retained.checked_sub(1).ok_or(DatabaseError::Integrity)?;
            *retired = retired.checked_sub(1).ok_or(DatabaseError::Integrity)?;
        }
    }
    Ok(())
}

fn validate_writer(
    entry: &WriterKeyEpoch,
    owner: NodeId,
    epoch: u64,
    sequence: u64,
) -> Result<(), CatalogStoreError> {
    if entry.owner != owner
        || entry.epoch != epoch
        || epoch == 0
        || entry.activated_at_event == 0
        || entry.activated_at_event > sequence
        || entry
            .revoked_at_event
            .is_some_and(|revoked| revoked <= entry.activated_at_event || revoked > sequence)
        || ed25519_dalek::VerifyingKey::from_bytes(&entry.public_key)
            .map_err(ModelError::from)?
            .is_weak()
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}
fn validate_recovery(
    entry: &RecoveryKeyEpoch,
    owner: NodeId,
    epoch: u64,
    guild: [u8; 32],
    sequence: u64,
) -> Result<(), CatalogStoreError> {
    entry.envelope.validate_for_guild(guild)?;
    if entry.envelope.subject != owner
        || entry.envelope.epoch != epoch
        || entry.activated_at_event == 0
        || entry.activated_at_event > sequence
        || entry
            .revoked_at_event
            .is_some_and(|revoked| revoked <= entry.activated_at_event || revoked > sequence)
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

// The enclosing checkpoint scan charges these fixed point rows. The history
// build charges its own full replay separately; no fresh unlimited budget is
// introduced by a point lookup.
fn point<T: DeserializeOwned + Serialize>(
    store: &RecordScratchStore,
    kind: &str,
    key: &[u8],
    limit: usize,
) -> Result<Option<(T, Vec<u8>)>, CatalogStoreError> {
    let Some(bytes) = store.get_record_bounded(kind, key, limit)? else {
        return Ok(None);
    };
    let value = decode_canonical(&bytes)?;
    if canonical_bytes_bounded(&value, limit)? != bytes {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(Some((value, bytes)))
}

pub struct CatalogGuildHistoryView<'a> {
    index: &'a CatalogGuildHistoryIndex,
}
impl CatalogGuildHistoryView<'_> {
    pub fn coding_trust(&self) -> CatalogCheckpointCodingTrust {
        self.index.trust.clone()
    }
    fn check(&self, trust: &PagedCheckpointTrust) -> Result<(), CatalogStoreError> {
        if trust != &self.index.trust.checkpoint {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }
    pub fn coding_group(
        &self,
        group_id: [u8; 32],
        trust: &CatalogCheckpointCodingTrust,
    ) -> Result<Option<CatalogCertifiedCodingGroup>, CatalogStoreError> {
        if trust != &self.index.trust {
            return Err(DatabaseError::Conflict.into());
        }
        let Some((fact, _)) = point::<Fact>(&self.index.store, FACTS, &group_id, ROW_BYTES)? else {
            return Ok(None);
        };
        if fact.guild_id != trust.checkpoint.guild_id
            || fact.lifecycle.group_id != group_id
            || fact.transcript_hash == [0; 32]
            || fact.lifecycle.added_at_event == 0
            || fact.lifecycle.added_at_event > trust.checkpoint.event_sequence
            || fact.lifecycle.retired_at_event.is_some()
                != fact.lifecycle.retain_through_event.is_some()
            || fact.lifecycle.retired_at_event.is_some_and(|event| {
                event < fact.lifecycle.added_at_event || event > trust.checkpoint.event_sequence
            })
            || fact
                .lifecycle
                .retain_through_event
                .is_some_and(|event| event < fact.lifecycle.retired_at_event.unwrap_or(0))
        {
            return Err(DatabaseError::Integrity.into());
        }
        fact.profile
            .validate()
            .map_err(|_| DatabaseError::Integrity)?;
        Ok(Some(fact.public()))
    }
    pub fn writer_key(
        &self,
        owner: NodeId,
        epoch: u64,
        trust: &PagedCheckpointTrust,
    ) -> Result<Option<WriterKeyEpoch>, CatalogStoreError> {
        self.check(trust)?;
        let entry = point::<WriterKeyEpoch>(
            &self.index.store,
            WRITERS,
            &epoch_key(owner, epoch),
            ROW_BYTES,
        )?
        .map(|(entry, _)| entry);
        if let Some(entry) = &entry {
            validate_writer(entry, owner, epoch, trust.event_sequence)?;
        }
        Ok(entry)
    }
    pub fn current_writer(
        &self,
        owner: NodeId,
        trust: &PagedCheckpointTrust,
    ) -> Result<Option<WriterFence>, CatalogStoreError> {
        self.check(trust)?;
        if !trust.members.iter().any(|member| member.node_id == owner) {
            return Ok(None);
        }
        let Some((epoch, _)) = point::<u64>(&self.index.store, LATEST_WRITER, &owner.0, ROW_BYTES)?
        else {
            return Ok(None);
        };
        if epoch == 0 {
            return Err(DatabaseError::Integrity.into());
        }
        let entry = self
            .writer_key(owner, epoch, trust)?
            .ok_or(DatabaseError::Integrity)?;
        // Never fall back to an older unrevoked incarnation.
        Ok(entry.revoked_at_event.is_none().then_some(WriterFence {
            owner,
            epoch,
            public_key: entry.public_key,
        }))
    }
    pub fn recovery_key(
        &self,
        owner: NodeId,
        epoch: u64,
        trust: &PagedCheckpointTrust,
    ) -> Result<Option<RecoveryKeyEpoch>, CatalogStoreError> {
        self.check(trust)?;
        let entry = point::<RecoveryKeyEpoch>(
            &self.index.store,
            RECOVERY,
            &epoch_key(owner, epoch),
            RECOVERY_BYTES,
        )?
        .map(|(entry, _)| entry);
        if let Some(entry) = &entry {
            validate_recovery(entry, owner, epoch, trust.guild_id, trust.event_sequence)?;
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests;
