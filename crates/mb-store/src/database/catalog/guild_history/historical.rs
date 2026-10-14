//! Fixed original event tips and coding incarnations, including forgotten
//! groups. Historical views use the certified prefix, not current placement.
use super::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) struct Tip {
    pub(super) sequence: u64,
    pub(super) head: [u8; 32],
    pub(super) membership_epoch: u64,
    pub(super) retained: u64,
    pub(super) retired: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Archived {
    fact: Fact,
    forgotten_at: Option<u64>,
}

impl Tip {
    pub(super) fn initial(snapshot: &GuildAuthoritySnapshot) -> Self {
        Self {
            sequence: 0,
            head: snapshot.event_head,
            membership_epoch: 1,
            retained: 0,
            retired: 0,
        }
    }
}

pub(super) fn incarnation_key(id: [u8; 32], added: u64) -> [u8; 40] {
    key(id, added)
}

fn key(id: [u8; 32], added: u64) -> [u8; 40] {
    let mut key = [0; 40];
    key[..32].copy_from_slice(&id);
    key[32..].copy_from_slice(&added.to_be_bytes());
    key
}

fn fact(group: &Group) -> Result<Fact, CatalogStoreError> {
    let public = CatalogCertifiedCodingGroup::from_retained(
        &group.retained,
        group.transcript_hash,
        CatalogCodingAuthorization::Retained,
    )?;
    Ok(Fact {
        guild_id: public.guild_id,
        lifecycle: public.lifecycle,
        profile: public.profile,
        transcript_hash: public.transcript_hash,
        current: false,
    })
}

fn validate(
    value: Archived,
    row_key: &[u8],
    sequence: u64,
    guild: [u8; 32],
) -> Result<(), CatalogStoreError> {
    let life = value.fact.lifecycle;
    if row_key != key(life.group_id, life.added_at_event)
        || value.fact.guild_id != guild
        || value.fact.current
        || value.fact.transcript_hash == [0; 32]
        || life.group_id == [0; 32]
        || life.added_at_event == 0
        || life.added_at_event > sequence
        || life.retired_at_event.is_some() != life.retain_through_event.is_some()
        || life
            .retired_at_event
            .is_some_and(|retired| retired < life.added_at_event || retired > sequence)
        || life
            .retain_through_event
            .is_some_and(|through| through < life.retired_at_event.unwrap_or(0))
        || value.forgotten_at.is_some_and(|forgotten| {
            forgotten > sequence
                || life
                    .retain_through_event
                    .is_none_or(|through| forgotten <= through)
        })
    {
        return Err(DatabaseError::Integrity.into());
    }
    value
        .fact
        .profile
        .validate()
        .map_err(|_| DatabaseError::Integrity)?;
    Ok(())
}

pub(super) fn write_tip(
    store: &RecordScratchStore,
    meter: &mut Meter,
    snapshot: &GuildAuthoritySnapshot,
    retained: u64,
    retired: u64,
) -> Result<(), CatalogStoreError> {
    write(
        store,
        meter,
        EVENTS,
        &snapshot.event_sequence.to_be_bytes(),
        &Tip {
            sequence: snapshot.event_sequence,
            head: snapshot.event_head,
            membership_epoch: snapshot.membership_epoch,
            retained,
            retired,
        },
        ROW_BYTES,
        None,
    )
}

pub(super) fn add(
    store: &RecordScratchStore,
    meter: &mut Meter,
    descriptor: &mb_core::CodingGroupV2,
    sequence: u64,
    transcript_hash: [u8; 32],
) -> Result<(), CatalogStoreError> {
    let group = Group {
        retained: RetainedCodingGroup {
            group: descriptor.clone(),
            added_at_event: sequence,
            retired_at_event: None,
            retain_through_event: None,
        },
        transcript_hash,
    };
    let value = Archived {
        fact: fact(&group)?,
        forgotten_at: None,
    };
    write(
        store,
        meter,
        ARCHIVE,
        &key(descriptor.id, sequence),
        &value,
        ROW_BYTES,
        None,
    )
}

pub(super) fn retire(
    store: &RecordScratchStore,
    meter: &mut Meter,
    group: &Group,
    sequence: u64,
) -> Result<(), CatalogStoreError> {
    let row_key = key(group.retained.group.id, group.retained.added_at_event);
    let (mut value, old) = get::<Archived>(store, meter, ARCHIVE, &row_key, ROW_BYTES)?
        .ok_or(DatabaseError::Integrity)?;
    validate(value, &row_key, sequence - 1, group.retained.group.guild_id)?;
    let next = fact(group)?;
    let mut before = next;
    before.lifecycle.retired_at_event = None;
    before.lifecycle.retain_through_event = None;
    if value.fact != before
        || value.forgotten_at.is_some()
        || next.lifecycle.retired_at_event != Some(sequence)
    {
        return Err(DatabaseError::Integrity.into());
    }
    value.fact = next;
    write(
        store,
        meter,
        ARCHIVE,
        &row_key,
        &value,
        ROW_BYTES,
        Some(&old),
    )
}

pub(super) fn forget(
    store: &RecordScratchStore,
    meter: &mut Meter,
    group: &Group,
    sequence: u64,
) -> Result<(), CatalogStoreError> {
    let row_key = key(group.retained.group.id, group.retained.added_at_event);
    let (mut value, old) = get::<Archived>(store, meter, ARCHIVE, &row_key, ROW_BYTES)?
        .ok_or(DatabaseError::Integrity)?;
    validate(value, &row_key, sequence - 1, group.retained.group.guild_id)?;
    if value.fact != fact(group)? || value.forgotten_at.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    value.forgotten_at = Some(sequence);
    validate(value, &row_key, sequence, group.retained.group.guild_id)?;
    write(
        store,
        meter,
        ARCHIVE,
        &row_key,
        &value,
        ROW_BYTES,
        Some(&old),
    )
}

pub(super) fn check_retained(
    store: &RecordScratchStore,
    meter: &mut Meter,
    group: &Group,
    sequence: u64,
) -> Result<(), CatalogStoreError> {
    let row_key = key(group.retained.group.id, group.retained.added_at_event);
    let (value, _) = get::<Archived>(store, meter, ARCHIVE, &row_key, ROW_BYTES)?
        .ok_or(DatabaseError::Integrity)?;
    validate(value, &row_key, sequence, group.retained.group.guild_id)?;
    if value.fact != fact(group)? || value.forgotten_at.is_some() {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

pub(super) fn check_archive(
    store: &RecordScratchStore,
    meter: &mut Meter,
    expected: u64,
    sequence: u64,
    guild: [u8; 32],
) -> Result<(), CatalogStoreError> {
    let mut after: Option<Vec<u8>> = None;
    let mut count = 0_u64;
    loop {
        meter.metadata()?;
        let Some((row_key, length)) =
            store.next_record_metadata_bounded(ARCHIVE, after.as_deref(), 40)?
        else {
            break;
        };
        if length == 0 || length > ROW_BYTES {
            return Err(DatabaseError::Integrity.into());
        }
        let (value, _) = get::<Archived>(store, meter, ARCHIVE, &row_key, ROW_BYTES)?
            .ok_or(DatabaseError::Integrity)?;
        validate(value, &row_key, sequence, guild)?;
        count = count
            .checked_add(1)
            .filter(|count| *count <= expected)
            .ok_or(DatabaseError::Integrity)?;
        after = Some(row_key);
    }
    if count != expected {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(())
}

/// A verified original event prefix of a completed history projection. No
/// public decoder/constructor can substitute a claimed historical snapshot.
/// Fixed coding lookups preserve forgotten and re-added incarnations.
pub struct CatalogGuildHistorySnapshot<'a> {
    index: &'a CatalogGuildHistoryIndex,
    trust: CatalogCheckpointCodingTrust,
}

impl<'a> CatalogGuildHistoryView<'a> {
    /// Reserve the bounded epoch roster and event-tip reads before looking up
    /// a historical snapshot. The enclosing job must carry this work onward.
    pub fn snapshot_lookup_work() -> Work {
        Work {
            bytes: (GUILD_AUTHORITY_SNAPSHOT_BYTES + ROW_BYTES) as u64,
            page_occurrences: 0,
            records: 2,
        }
    }

    pub fn at(
        &self,
        trust: &PagedCheckpointTrust,
        budget: Work,
    ) -> Result<CatalogGuildHistorySnapshot<'a>, CatalogStoreError> {
        budget.remaining_after(Self::snapshot_lookup_work())?;
        trust.validate()?;
        let current = &self.index.trust.checkpoint;
        if trust.guild_id != current.guild_id
            || trust.genesis_hash != current.genesis_hash
            || trust.event_sequence > current.event_sequence
        {
            return Err(DatabaseError::Conflict.into());
        }
        let (tip, _) = point::<Tip>(
            &self.index.store,
            EVENTS,
            &trust.event_sequence.to_be_bytes(),
            ROW_BYTES,
        )?
        .ok_or(DatabaseError::NotReady)?;
        if tip.sequence != trust.event_sequence
            || tip.head != trust.event_head
            || tip.membership_epoch != trust.authority.membership_epoch
            || tip.retired > tip.retained
            || tip.sequence == 0
                && (tip.head != trust.genesis_hash
                    || tip.membership_epoch != 1
                    || tip.retained != 0
                    || tip.retired != 0)
        {
            return Err(DatabaseError::Conflict.into());
        }
        let (_, bytes) = point::<GuildAuthoritySnapshot>(
            &self.index.store,
            MEMBERS,
            &tip.membership_epoch.to_be_bytes(),
            GUILD_AUTHORITY_SNAPSHOT_BYTES,
        )?
        .ok_or(DatabaseError::NotReady)?;
        let roster = GuildAuthoritySnapshot::decode(&bytes)?;
        if roster.guild_id != trust.guild_id
            || roster.membership_epoch != tip.membership_epoch
            || roster.event_sequence > tip.sequence
            || roster.quorum != trust.authority.quorum
            || !roster.active_members().eq(trust.members.iter())
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(CatalogGuildHistorySnapshot {
            index: self.index,
            trust: CatalogCheckpointCodingTrust {
                checkpoint: trust.clone(),
                retained_groups: tip.retained,
                retired_groups: tip.retired,
            },
        })
    }
}

impl CatalogGuildHistorySnapshot<'_> {
    pub fn coding_trust(&self) -> &CatalogCheckpointCodingTrust {
        &self.trust
    }

    /// One bounded indexed range read, not an incarnation scan or a full
    /// descriptor read. The enclosing checkpoint scan charges this fixed row.
    pub fn coding_group(
        &self,
        id: [u8; 32],
    ) -> Result<Option<CatalogCertifiedCodingGroup>, CatalogStoreError> {
        let sequence = self.trust.checkpoint.event_sequence;
        let Some((row_key, bytes)) = self.index.store.record_at_or_before_bounded(
            ARCHIVE,
            &id,
            &key(id, sequence),
            40,
            ROW_BYTES,
        )?
        else {
            return Ok(None);
        };
        let mut value: Archived = decode_canonical(&bytes)?;
        if canonical_bytes_bounded(&value, ROW_BYTES)? != bytes {
            return Err(DatabaseError::Integrity.into());
        }
        validate(
            value,
            &row_key,
            self.index.trust.checkpoint.event_sequence,
            self.trust.checkpoint.guild_id,
        )?;
        if value.fact.lifecycle.group_id != id || value.fact.lifecycle.added_at_event > sequence {
            return Err(DatabaseError::Integrity.into());
        }
        if value
            .forgotten_at
            .is_some_and(|forgotten| forgotten <= sequence)
        {
            return Ok(None);
        }
        if value
            .fact
            .lifecycle
            .retired_at_event
            .is_some_and(|retired| retired > sequence)
        {
            value.fact.lifecycle.retired_at_event = None;
            value.fact.lifecycle.retain_through_event = None;
        }
        Ok(Some(value.fact.public()))
    }

    pub fn writer_key(
        &self,
        owner: NodeId,
        epoch: u64,
    ) -> Result<Option<WriterKeyEpoch>, CatalogStoreError> {
        let view = CatalogGuildHistoryView { index: self.index };
        let Some(mut entry) = view.writer_key(owner, epoch, &self.index.trust.checkpoint)? else {
            return Ok(None);
        };
        let sequence = self.trust.checkpoint.event_sequence;
        if entry.activated_at_event > sequence {
            return Ok(None);
        }
        if entry
            .revoked_at_event
            .is_some_and(|revoked| revoked > sequence)
        {
            entry.revoked_at_event = None;
        }
        Ok(Some(entry))
    }
}
