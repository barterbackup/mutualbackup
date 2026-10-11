//! A bounded membership projection. Writer, recovery and coding state belongs
//! in the caller's indexed history, not in every historical membership epoch.
use super::*;

pub const GUILD_AUTHORITY_SNAPSHOT_BYTES: usize = 128 * 1024;

/// Local replay state, not a certificate. A reader must start at independently
/// trusted genesis, validate every event's non-membership effects, and compare
/// its final tip with an independently trusted certified-current snapshot.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildAuthoritySnapshot {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub event_sequence: u64,
    pub event_head: [u8; 32],
    pub membership_epoch: u64,
    pub quorum: QuorumPolicy,
    #[serde(deserialize_with = "members")]
    pub members: Vec<DynamicMember>,
}

fn members<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Vec<DynamicMember>, D::Error> {
    use serde::de::DeserializeSeed;
    #[derive(Deserialize)]
    struct Entry {
        #[serde(deserialize_with = "super::bounded_event::member")]
        member: Member,
        joined_at_event: u64,
        removed_at_event: Option<u64>,
    }
    Ok(crate::bounded::VecSeed::<Entry>::new(MAX_DYNAMIC_MEMBERS)
        .deserialize(decoder)?
        .into_iter()
        .map(|entry| DynamicMember {
            member: entry.member,
            joined_at_event: entry.joined_at_event,
            removed_at_event: entry.removed_at_event,
        })
        .collect())
}

impl GuildAuthoritySnapshot {
    pub fn from_genesis(genesis: &crate::QuorumGuildGenesis) -> Result<Self, GuildStateError> {
        // Genesis has exactly five members. Bound a typed caller before its
        // legacy validator hashes or copies the original signed envelope.
        crate::canonical_size_bounded(genesis, GUILD_AUTHORITY_SNAPSHOT_BYTES)?;
        genesis.verify()?;
        let state = DynamicGuildState::new(
            genesis.genesis.guild_id,
            genesis.genesis.hash()?,
            QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Unanimous,
            },
            genesis.genesis.members.clone(),
        )?;
        Self::from_state(&state)
    }

    /// Copy only the bounded roster. This does not certify or traverse the
    /// supplied state's writer, recovery or coding histories.
    pub fn from_state(state: &DynamicGuildState) -> Result<Self, GuildStateError> {
        check_members(&state.members)?;
        let snapshot = Self {
            format_version: state.format_version,
            guild_id: state.guild_id,
            event_sequence: state.event_sequence,
            event_head: state.event_head,
            membership_epoch: state.membership_epoch,
            quorum: state.quorum,
            members: state.members.clone(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, GuildStateError> {
        if bytes.is_empty() || bytes.len() > GUILD_AUTHORITY_SNAPSHOT_BYTES {
            return Err(ModelError::EncodingTooLarge {
                limit: GUILD_AUTHORITY_SNAPSHOT_BYTES,
            }
            .into());
        }
        let value: Self = crate::decode_canonical(bytes)?;
        value.validate()?;
        if crate::canonical_bytes_bounded(&value, GUILD_AUTHORITY_SNAPSHOT_BYTES)? != bytes {
            return Err(GuildStateError::InvalidState);
        }
        Ok(value)
    }

    // Existing membership rules are reused on a bounded temporary value. None
    // of the potentially growing history vectors is materialized here.
    fn state(&self) -> Result<DynamicGuildState, GuildStateError> {
        check_members(&self.members)?;
        Ok(DynamicGuildState {
            format_version: self.format_version,
            guild_id: self.guild_id,
            event_sequence: self.event_sequence,
            event_head: self.event_head,
            membership_epoch: self.membership_epoch,
            quorum: self.quorum,
            members: self.members.clone(),
            writer_keys: Vec::new(),
            recovery_keys: Vec::new(),
            coding_groups: Vec::new(),
        })
    }

    pub fn validate(&self) -> Result<(), GuildStateError> {
        self.state()?.validate()
    }

    pub fn active_members(&self) -> impl Iterator<Item = &Member> {
        self.members
            .iter()
            .filter(|entry| entry.is_active())
            .map(|entry| &entry.member)
    }

    pub fn verify_event(&self, certified: &QuorumGuildEvent) -> Result<(), GuildStateError> {
        crate::canonical_size_bounded(certified, GUILD_EVENT_BYTES)?;
        self.state()?.verify_event(certified)
    }

    /// Verify the original certificate and apply membership effects. For every
    /// other event the callback must validate and apply its full indexed state
    /// transition. A failure leaves this snapshot unchanged; the caller must
    /// also roll back callback writes, usually with one disposable transaction.
    /// A successful callback is not inferred from signature verification.
    pub fn advance<F>(
        &mut self,
        certified: &QuorumGuildEvent,
        validate_non_membership: F,
    ) -> Result<(), GuildStateError>
    where
        F: FnOnce(&Self, &GuildEvent) -> Result<(), GuildStateError>,
    {
        self.advance_indexed(certified, validate_non_membership)
    }

    /// Like advance, preserving an indexed caller's database/admission errors
    /// while verifying each original certificate only once. Callback writes
    /// must remain inside the caller's disposable transaction.
    pub fn advance_indexed<E, F>(
        &mut self,
        certified: &QuorumGuildEvent,
        validate_non_membership: F,
    ) -> Result<(), E>
    where
        E: From<GuildStateError>,
        F: FnOnce(&Self, &GuildEvent) -> Result<(), E>,
    {
        self.verify_event(certified)?;
        self.advance_verified_indexed(certified, validate_non_membership)
    }

    /// Check an unsigned next proposal using the same complete indexed effects.
    /// This updates only a disposable local projection and confers no quorum
    /// authority. The caller must discard every effect of this validation.
    pub fn advance_proposal_indexed<E, F>(
        &mut self,
        event: &GuildEvent,
        validate_non_membership: F,
    ) -> Result<(), E>
    where
        E: From<GuildStateError>,
        F: FnOnce(&Self, &GuildEvent) -> Result<(), E>,
    {
        crate::canonical_size_bounded(event, GUILD_EVENT_BYTES).map_err(GuildStateError::from)?;
        self.validate()?;
        if !valid_event_format(event)
            || event.guild_id != self.guild_id
            || Some(event.sequence) != self.event_sequence.checked_add(1)
            || event.parent != self.event_head
        {
            return Err(GuildStateError::InvalidEvent.into());
        }
        self.advance_verified_indexed(
            &QuorumGuildEvent {
                event: event.clone(),
                signatures: Vec::new(),
            },
            validate_non_membership,
        )
    }

    fn advance_verified_indexed<E, F>(
        &mut self,
        certified: &QuorumGuildEvent,
        validate_non_membership: F,
    ) -> Result<(), E>
    where
        E: From<GuildStateError>,
        F: FnOnce(&Self, &GuildEvent) -> Result<(), E>,
    {
        let mut next = self.state()?;
        match &certified.event.kind {
            GuildEventKind::AddMember { .. }
            | GuildEventKind::RemoveMember { .. }
            | GuildEventKind::RelabelMember { .. }
            | GuildEventKind::SetQuorum { .. } => {
                self.membership_epoch
                    .checked_add(1)
                    .ok_or(GuildStateError::InvalidEvent)?;
                next.apply_verified_event(certified)?;
            }
            _ => {
                validate_non_membership(self, &certified.event)?;
                next.event_sequence = certified.event.sequence;
                next.event_head = certified.event.hash()?;
            }
        }
        *self = Self::from_state(&next)?;
        Ok(())
    }

    pub fn verify_legacy_coding_add_binding(
        &self,
        binding: &QuorumLegacyCodingAddBinding,
        certified: &QuorumGuildEvent,
    ) -> Result<(), GuildStateError> {
        crate::canonical_size_bounded(binding, LEGACY_CODING_ADD_BINDING_BYTES)?;
        self.verify_event(certified)?;
        binding.verify(&self.state()?, certified)
    }

    pub fn validate_attempt_authority(
        &self,
        plan: &CodingAttemptPlan,
    ) -> Result<(), GuildStateError> {
        self.validate()?;
        self.state()?.validate_attempt_authority(plan)
    }

    pub fn validate_current_group_placement(
        &self,
        group: &CodingGroupV2,
    ) -> Result<(), GuildStateError> {
        crate::canonical_size_bounded(group, GUILD_EVENT_BYTES)?;
        self.validate()?;
        self.state()?.validate_current_group_placement(group)
    }
}

fn check_members(members: &[DynamicMember]) -> Result<(), GuildStateError> {
    if members.is_empty()
        || members.len() > MAX_DYNAMIC_MEMBERS
        || members
            .iter()
            .any(|entry| entry.member.failure_domain.len() > 256)
    {
        return Err(GuildStateError::InvalidState);
    }
    Ok(())
}
