use ed25519_dalek::{Signature, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod authority;
mod bounded_event;

pub use authority::{GUILD_AUTHORITY_SNAPSHOT_BYTES, GuildAuthoritySnapshot};
pub use bounded_event::{GUILD_EVENT_BYTES, LEGACY_CODING_ADD_BINDING_BYTES};

use crate::keys::signing_payload;
use crate::recovery::open_recovery_record_with_secret;
use crate::{
    CodingAttemptPlan, CodingGroupV2, KeyMaterial, Member, MemberSignature, ModelError, NodeId,
    RecoveryCryptoError, RecoveryPublicKey, SealedRecoveryRecord, ShardRoleV2, canonical_bytes,
    open_recovery_record, seal_recovery_record,
};

pub const GUILD_EVENT_DOMAIN: &[u8] = b"mutualbackup/guild-event/v1";
pub const LEGACY_CODING_ADD_BINDING_DOMAIN: &[u8] = b"mutualbackup/legacy-coding-add-binding/v1";
const MAX_DYNAMIC_MEMBERS: usize = 256;
pub const MAX_GUILD_EVENT_TAIL: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum QuorumRule {
    Unanimous,
    Majority,
    Threshold(u16),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumPolicy {
    pub format_version: u16,
    pub rule: QuorumRule,
}

impl QuorumPolicy {
    pub fn required(self, active_members: usize) -> Result<usize, GuildStateError> {
        if self.format_version != 1 || active_members == 0 {
            return Err(GuildStateError::InvalidState);
        }
        let required = match self.rule {
            QuorumRule::Unanimous => active_members,
            QuorumRule::Majority => active_members / 2 + 1,
            QuorumRule::Threshold(value) => {
                let threshold = usize::from(value);
                if threshold <= active_members / 2 {
                    return Err(GuildStateError::InvalidState);
                }
                threshold
            }
        };
        if required == 0 || required > active_members {
            return Err(GuildStateError::InvalidState);
        }
        Ok(required)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicMember {
    pub member: Member,
    pub joined_at_event: u64,
    pub removed_at_event: Option<u64>,
}

impl DynamicMember {
    pub fn is_active(&self) -> bool {
        self.removed_at_event.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct WriterKeyEpoch {
    pub owner: NodeId,
    pub epoch: u64,
    pub public_key: [u8; 32],
    pub activated_at_event: u64,
    pub revoked_at_event: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryKeyEnvelope {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub subject: NodeId,
    pub epoch: u64,
    pub public_key: RecoveryPublicKey,
    pub sealed_private_key: SealedRecoveryRecord,
}

impl RecoveryKeyEnvelope {
    /// Original envelope shape rules for indexed event replay. Opening the
    /// private recovery key remains the recovering subject's responsibility.
    pub fn validate_for_guild(&self, guild_id: [u8; 32]) -> Result<(), GuildStateError> {
        validate_recovery_envelope(self, guild_id)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RecoveryKeyEpoch {
    pub envelope: RecoveryKeyEnvelope,
    pub activated_at_event: u64,
    pub revoked_at_event: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RetainedCodingGroup {
    pub group: CodingGroupV2,
    pub added_at_event: u64,
    pub retired_at_event: Option<u64>,
    pub retain_through_event: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum GuildEventKind {
    AddMember {
        member: Member,
    },
    RemoveMember {
        node_id: NodeId,
    },
    RelabelMember {
        node_id: NodeId,
        failure_domain: String,
    },
    SetQuorum {
        policy: QuorumPolicy,
    },
    RotateWriterKey {
        owner: NodeId,
        epoch: u64,
        public_key: [u8; 32],
    },
    RevokeWriterKey {
        owner: NodeId,
        epoch: u64,
    },
    RotateRecoveryKey {
        envelope: RecoveryKeyEnvelope,
    },
    RevokeRecoveryKey {
        subject: NodeId,
        epoch: u64,
    },
    AddCodingGroup {
        group: CodingGroupV2,
    },
    RetireCodingGroup {
        group_id: [u8; 32],
        retain_through_event: u64,
    },
    ForgetCodingGroup {
        group_id: [u8; 32],
    },
    /// Appended to preserve the positional Postcard encoding of earlier event kinds.
    AddCodingGroupBound {
        group: CodingGroupV2,
        transcript_hash: [u8; 32],
    },
}

impl GuildEventKind {
    pub fn coding_group_add(&self) -> Option<(&CodingGroupV2, Option<[u8; 32]>)> {
        match self {
            Self::AddCodingGroup { group } => Some((group, None)),
            Self::AddCodingGroupBound {
                group,
                transcript_hash,
            } => Some((group, Some(*transcript_hash))),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildEvent {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub sequence: u64,
    pub parent: [u8; 32],
    pub kind: GuildEventKind,
}

impl GuildEvent {
    pub fn hash(&self) -> Result<[u8; 32], GuildStateError> {
        let mut hasher = blake3::Hasher::new_derive_key("mutualbackup guild event v1");
        crate::canonical::update_canonical_hash(&mut hasher, self)?;
        Ok(*hasher.finalize().as_bytes())
    }
}

fn valid_event_format(event: &GuildEvent) -> bool {
    match &event.kind {
        GuildEventKind::AddCodingGroupBound {
            transcript_hash: hash,
            ..
        } => event.format_version == 2 && *hash != [0; 32],
        _ => event.format_version == 1,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumGuildEvent {
    pub event: GuildEvent,
    pub signatures: Vec<MemberSignature>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyCodingAddStatement {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub event_sequence: u64,
    pub event_hash: [u8; 32],
    pub transcript_hash: [u8; 32],
}

impl LegacyCodingAddStatement {
    pub fn for_event(
        certified: &QuorumGuildEvent,
        transcript_hash: [u8; 32],
    ) -> Result<Self, GuildStateError> {
        if !matches!(certified.event.kind, GuildEventKind::AddCodingGroup { .. })
            || transcript_hash == [0; 32]
        {
            return Err(GuildStateError::InvalidEvent);
        }
        Ok(Self {
            format_version: 1,
            guild_id: certified.event.guild_id,
            event_sequence: certified.event.sequence,
            event_hash: certified.event.hash()?,
            transcript_hash,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct QuorumLegacyCodingAddBinding {
    pub statement: LegacyCodingAddStatement,
    pub signatures: Vec<MemberSignature>,
}

pub fn sign_legacy_coding_add_binding(
    statement: &LegacyCodingAddStatement,
    keys: &KeyMaterial,
) -> Result<MemberSignature, GuildStateError> {
    Ok(MemberSignature {
        signer: keys.node_id(),
        signature: keys
            .sign(
                LEGACY_CODING_ADD_BINDING_DOMAIN,
                &canonical_bytes(statement)?,
            )
            .to_vec(),
    })
}

pub fn verify_legacy_coding_add_signature(
    statement: &LegacyCodingAddStatement,
    signature: &MemberSignature,
) -> Result<(), GuildStateError> {
    let key = VerifyingKey::from_bytes(&signature.signer.0)?;
    if key.is_weak() {
        return Err(GuildStateError::InvalidEvent);
    }
    key.verify_strict(
        &signing_payload(
            LEGACY_CODING_ADD_BINDING_DOMAIN,
            &canonical_bytes(statement)?,
        ),
        &Signature::from_slice(&signature.signature)?,
    )?;
    Ok(())
}

impl QuorumLegacyCodingAddBinding {
    pub fn verify(
        &self,
        state_before: &DynamicGuildState,
        certified: &QuorumGuildEvent,
    ) -> Result<(), GuildStateError> {
        state_before.verify_event(certified)?;
        if !matches!(certified.event.kind, GuildEventKind::AddCodingGroup { .. })
            || self.statement.format_version != 1
            || self.statement.guild_id != certified.event.guild_id
            || self.statement.event_sequence != certified.event.sequence
            || self.statement.event_hash != certified.event.hash()?
            || self.statement.transcript_hash == [0; 32]
        {
            return Err(GuildStateError::InvalidEvent);
        }
        let active = state_before
            .active_members()
            .map(|member| member.node_id)
            .collect::<std::collections::BTreeSet<_>>();
        let original_signers = certified
            .signatures
            .iter()
            .map(|signature| signature.signer)
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = None;
        for signature in &self.signatures {
            if !active.contains(&signature.signer)
                || !original_signers.contains(&signature.signer)
                || previous.is_some_and(|signer| signer >= signature.signer)
            {
                return Err(GuildStateError::InvalidEvent);
            }
            verify_legacy_coding_add_signature(&self.statement, signature)?;
            previous = Some(signature.signer);
        }
        let required = state_before.quorum.required(active.len())?;
        if self.signatures.len() < required {
            return Err(GuildStateError::InsufficientQuorum {
                actual: self.signatures.len(),
                required,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct GuildEventTail {
    pub format_version: u16,
    pub base_sequence: u64,
    pub base_head: [u8; 32],
    pub events: Vec<QuorumGuildEvent>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DynamicGuildState {
    pub format_version: u16,
    pub guild_id: [u8; 32],
    pub event_sequence: u64,
    pub event_head: [u8; 32],
    pub membership_epoch: u64,
    pub quorum: QuorumPolicy,
    pub members: Vec<DynamicMember>,
    pub writer_keys: Vec<WriterKeyEpoch>,
    pub recovery_keys: Vec<RecoveryKeyEpoch>,
    pub coding_groups: Vec<RetainedCodingGroup>,
}

impl DynamicGuildState {
    pub fn new(
        guild_id: [u8; 32],
        genesis_hash: [u8; 32],
        quorum: QuorumPolicy,
        mut members: Vec<Member>,
    ) -> Result<Self, GuildStateError> {
        members.sort_by_key(|member| member.node_id);
        let state = Self {
            format_version: 1,
            guild_id,
            event_sequence: 0,
            event_head: genesis_hash,
            membership_epoch: 1,
            quorum,
            members: members
                .into_iter()
                .map(|member| DynamicMember {
                    member,
                    joined_at_event: 0,
                    removed_at_event: None,
                })
                .collect(),
            writer_keys: Vec::new(),
            recovery_keys: Vec::new(),
            coding_groups: Vec::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn active_members(&self) -> impl Iterator<Item = &Member> {
        self.members
            .iter()
            .filter(|member| member.is_active())
            .map(|member| &member.member)
    }

    pub fn validate(&self) -> Result<(), GuildStateError> {
        if self.format_version != 1
            || self.guild_id == [0; 32]
            || self.event_head == [0; 32]
            || self.membership_epoch == 0
            || self.members.is_empty()
            || self.members.len() > MAX_DYNAMIC_MEMBERS
        {
            return Err(GuildStateError::InvalidState);
        }
        let mut previous = None;
        for member in &self.members {
            if previous.is_some_and(|node_id| node_id >= member.member.node_id)
                || member.member.node_id == NodeId([0; 32])
                || member.member.failure_domain.is_empty()
                || member.member.failure_domain.len() > 256
                || !member.member.recovery_public_key.is_contributory()
                || member.joined_at_event > self.event_sequence
                || member.removed_at_event.is_some_and(|removed| {
                    removed <= member.joined_at_event || removed > self.event_sequence
                })
            {
                return Err(GuildStateError::InvalidState);
            }
            let key = VerifyingKey::from_bytes(&member.member.node_id.0)?;
            if key.is_weak() {
                return Err(GuildStateError::InvalidState);
            }
            previous = Some(member.member.node_id);
        }
        self.quorum.required(self.active_members().count())?;
        validate_writer_keys(self)?;
        validate_recovery_keys(self)?;
        let mut previous_group = None;
        for retained in &self.coding_groups {
            retained.group.validate()?;
            if retained.group.guild_id != self.guild_id
                || previous_group.is_some_and(|id| id >= retained.group.id)
                || retained.added_at_event == 0
                || retained.added_at_event > self.event_sequence
                || retained.retired_at_event.is_some() != retained.retain_through_event.is_some()
                || retained.retired_at_event.is_some_and(|event| {
                    event < retained.added_at_event || event > self.event_sequence
                })
                || retained
                    .retain_through_event
                    .is_some_and(|event| event < retained.retired_at_event.unwrap_or(0))
            {
                return Err(GuildStateError::InvalidState);
            }
            previous_group = Some(retained.group.id);
        }
        Ok(())
    }

    pub fn verify_event(&self, certified: &QuorumGuildEvent) -> Result<(), GuildStateError> {
        self.validate()?;
        let event = &certified.event;
        if !valid_event_format(event)
            || event.guild_id != self.guild_id
            || Some(event.sequence) != self.event_sequence.checked_add(1)
            || event.parent != self.event_head
        {
            return Err(GuildStateError::InvalidEvent);
        }
        let active = self
            .active_members()
            .map(|member| member.node_id)
            .collect::<std::collections::BTreeSet<_>>();
        let mut previous = None;
        let mut valid = 0;
        for signature in &certified.signatures {
            if !active.contains(&signature.signer)
                || previous.is_some_and(|signer| signer >= signature.signer)
            {
                return Err(GuildStateError::InvalidEvent);
            }
            verify_guild_event_signature(event, signature)?;
            valid += 1;
            previous = Some(signature.signer);
        }
        let required = self.quorum.required(active.len())?;
        if valid < required {
            return Err(GuildStateError::InsufficientQuorum {
                actual: valid,
                required,
            });
        }
        let subject_authorization = match &event.kind {
            GuildEventKind::RotateWriterKey { owner, .. } => Some(*owner),
            GuildEventKind::RotateRecoveryKey { envelope } => Some(envelope.subject),
            _ => None,
        };
        if subject_authorization.is_some_and(|subject| {
            !certified
                .signatures
                .iter()
                .any(|signature| signature.signer == subject)
        }) {
            return Err(GuildStateError::InvalidEvent);
        }
        Ok(())
    }

    /// Validate the exact next event and its resulting state before collecting
    /// signatures. Quorum authorization remains a property of `verify_event`.
    pub fn validate_event_proposal(&self, event: &GuildEvent) -> Result<(), GuildStateError> {
        self.validate()?;
        if !valid_event_format(event)
            || event.guild_id != self.guild_id
            || event.sequence != self.event_sequence + 1
            || event.parent != self.event_head
        {
            return Err(GuildStateError::InvalidEvent);
        }
        let mut next = self.clone();
        next.apply_verified_event(&QuorumGuildEvent {
            event: event.clone(),
            signatures: Vec::new(),
        })?;
        Ok(())
    }

    pub fn apply_event(&mut self, certified: &QuorumGuildEvent) -> Result<(), GuildStateError> {
        self.verify_event(certified)?;
        let mut next = self.clone();
        next.apply_verified_event(certified)?;
        *self = next;
        Ok(())
    }

    fn apply_verified_event(
        &mut self,
        certified: &QuorumGuildEvent,
    ) -> Result<(), GuildStateError> {
        let sequence = certified.event.sequence;
        match &certified.event.kind {
            GuildEventKind::AddMember { member } => {
                validate_member(member)?;
                if self
                    .members
                    .binary_search_by_key(&member.node_id, |entry| entry.member.node_id)
                    .is_ok()
                {
                    return Err(GuildStateError::InvalidEvent);
                }
                let index = self
                    .members
                    .partition_point(|entry| entry.member.node_id < member.node_id);
                self.members.insert(
                    index,
                    DynamicMember {
                        member: member.clone(),
                        joined_at_event: sequence,
                        removed_at_event: None,
                    },
                );
                self.membership_epoch += 1;
            }
            GuildEventKind::RemoveMember { node_id } => {
                let member = self.active_member_mut(*node_id)?;
                member.removed_at_event = Some(sequence);
                self.membership_epoch += 1;
                self.quorum.required(self.active_members().count())?;
            }
            GuildEventKind::RelabelMember {
                node_id,
                failure_domain,
            } => {
                if failure_domain.is_empty() || failure_domain.len() > 256 {
                    return Err(GuildStateError::InvalidEvent);
                }
                self.active_member_mut(*node_id)?.member.failure_domain = failure_domain.clone();
                self.membership_epoch += 1;
            }
            GuildEventKind::SetQuorum { policy } => {
                policy.required(self.active_members().count())?;
                self.quorum = *policy;
                self.membership_epoch += 1;
            }
            GuildEventKind::RotateWriterKey {
                owner,
                epoch,
                public_key,
            } => {
                self.require_active_member(*owner)?;
                let key = VerifyingKey::from_bytes(public_key)?;
                let previous_epoch = self
                    .writer_keys
                    .iter()
                    .filter(|entry| entry.owner == *owner)
                    .map(|entry| entry.epoch)
                    .max()
                    .unwrap_or(0);
                if key.is_weak() || *epoch != previous_epoch + 1 {
                    return Err(GuildStateError::InvalidEvent);
                }
                self.writer_keys.push(WriterKeyEpoch {
                    owner: *owner,
                    epoch: *epoch,
                    public_key: *public_key,
                    activated_at_event: sequence,
                    revoked_at_event: None,
                });
                self.writer_keys
                    .sort_by_key(|entry| (entry.owner, entry.epoch));
            }
            GuildEventKind::RevokeWriterKey { owner, epoch } => {
                let entry = self
                    .writer_keys
                    .iter_mut()
                    .find(|entry| entry.owner == *owner && entry.epoch == *epoch)
                    .ok_or(GuildStateError::InvalidEvent)?;
                if entry.revoked_at_event.is_some() {
                    return Err(GuildStateError::InvalidEvent);
                }
                entry.revoked_at_event = Some(sequence);
            }
            GuildEventKind::RotateRecoveryKey { envelope } => {
                self.require_active_member(envelope.subject)?;
                validate_recovery_envelope(envelope, self.guild_id)?;
                let previous_epoch = self
                    .recovery_keys
                    .iter()
                    .filter(|entry| entry.envelope.subject == envelope.subject)
                    .map(|entry| entry.envelope.epoch)
                    .max()
                    .unwrap_or(0);
                if envelope.epoch != previous_epoch + 1 {
                    return Err(GuildStateError::InvalidEvent);
                }
                self.recovery_keys.push(RecoveryKeyEpoch {
                    envelope: envelope.clone(),
                    activated_at_event: sequence,
                    revoked_at_event: None,
                });
                self.recovery_keys
                    .sort_by_key(|entry| (entry.envelope.subject, entry.envelope.epoch));
            }
            GuildEventKind::RevokeRecoveryKey { subject, epoch } => {
                let entry = self
                    .recovery_keys
                    .iter_mut()
                    .find(|entry| {
                        entry.envelope.subject == *subject && entry.envelope.epoch == *epoch
                    })
                    .ok_or(GuildStateError::InvalidEvent)?;
                if entry.revoked_at_event.is_some() {
                    return Err(GuildStateError::InvalidEvent);
                }
                entry.revoked_at_event = Some(sequence);
            }
            GuildEventKind::AddCodingGroup { group }
            | GuildEventKind::AddCodingGroupBound { group, .. } => {
                group.validate()?;
                if group.guild_id != self.guild_id
                    || self
                        .coding_groups
                        .binary_search_by_key(&group.id, |entry| entry.group.id)
                        .is_ok()
                {
                    return Err(GuildStateError::InvalidEvent);
                }
                self.validate_current_group_placement(group)?;
                let index = self
                    .coding_groups
                    .partition_point(|entry| entry.group.id < group.id);
                self.coding_groups.insert(
                    index,
                    RetainedCodingGroup {
                        group: group.clone(),
                        added_at_event: sequence,
                        retired_at_event: None,
                        retain_through_event: None,
                    },
                );
            }
            GuildEventKind::RetireCodingGroup {
                group_id,
                retain_through_event,
            } => {
                let group = self
                    .coding_groups
                    .iter_mut()
                    .find(|group| group.group.id == *group_id)
                    .ok_or(GuildStateError::InvalidEvent)?;
                if group.retired_at_event.is_some() || *retain_through_event < sequence {
                    return Err(GuildStateError::InvalidEvent);
                }
                group.retired_at_event = Some(sequence);
                group.retain_through_event = Some(*retain_through_event);
            }
            GuildEventKind::ForgetCodingGroup { group_id } => {
                let index = self
                    .coding_groups
                    .iter()
                    .position(|group| group.group.id == *group_id)
                    .ok_or(GuildStateError::InvalidEvent)?;
                if self.coding_groups[index]
                    .retain_through_event
                    .is_none_or(|retained| sequence <= retained)
                {
                    return Err(GuildStateError::RetentionActive);
                }
                self.coding_groups.remove(index);
            }
        }
        self.event_sequence = sequence;
        self.event_head = certified.event.hash()?;
        self.validate()?;
        Ok(())
    }

    pub fn apply_tail(&mut self, tail: &GuildEventTail) -> Result<(), GuildStateError> {
        if tail.format_version != 1
            || tail.base_sequence != self.event_sequence
            || tail.base_head != self.event_head
            || tail.events.len() > MAX_GUILD_EVENT_TAIL
        {
            return Err(GuildStateError::InvalidEvent);
        }
        let mut next = self.clone();
        for event in &tail.events {
            next.apply_event(event)?;
        }
        *self = next;
        Ok(())
    }

    /// A membership change fences an attempt even when its immutable group is
    /// otherwise still valid. The coordinator must retry with fresh roles and
    /// a fresh hidden challenge under the current epoch.
    pub fn validate_attempt(
        &self,
        plan: &CodingAttemptPlan,
        now_unix_seconds: u64,
    ) -> Result<(), GuildStateError> {
        self.validate_attempt_authority(plan)?;
        if plan.expires_at_unix_seconds < now_unix_seconds {
            return Err(GuildStateError::InvalidAttempt);
        }
        Ok(())
    }

    /// Validate the membership epoch, active roles, and placement snapshot
    /// without consulting the attempt deadline. This is used only to finish
    /// replay or cleanup work whose authority was established before expiry.
    pub fn validate_attempt_authority(
        &self,
        plan: &CodingAttemptPlan,
    ) -> Result<(), GuildStateError> {
        plan.validate()
            .map_err(|_| GuildStateError::InvalidAttempt)?;
        if plan.geometry.guild_id != self.guild_id || plan.membership_epoch != self.membership_epoch
        {
            return Err(GuildStateError::InvalidAttempt);
        }
        for node in [
            plan.delegator,
            plan.coding_coordinator,
            plan.verification_coordinator,
        ] {
            self.require_active_member(node)
                .map_err(|_| GuildStateError::InvalidAttempt)?;
        }
        for information in &plan.geometry.information {
            let member = self
                .require_active_member(information.owner)
                .map_err(|_| GuildStateError::InvalidAttempt)?;
            if member.member.failure_domain != information.failure_domain {
                return Err(GuildStateError::InvalidAttempt);
            }
        }
        for parity in &plan.geometry.parity {
            let member = self
                .require_active_member(parity.holder)
                .map_err(|_| GuildStateError::InvalidAttempt)?;
            if member.member.failure_domain != parity.failure_domain {
                return Err(GuildStateError::InvalidAttempt);
            }
        }
        Ok(())
    }

    pub fn writer_key_for_retained_revision(&self, owner: NodeId, epoch: u64) -> Option<[u8; 32]> {
        self.writer_keys
            .iter()
            .find(|entry| entry.owner == owner && entry.epoch == epoch)
            .map(|entry| entry.public_key)
    }

    pub fn current_recovery_key(&self, subject: NodeId) -> Option<&RecoveryKeyEpoch> {
        self.recovery_keys
            .iter()
            .filter(|entry| entry.envelope.subject == subject)
            .max_by_key(|entry| entry.envelope.epoch)
            .filter(|entry| entry.revoked_at_event.is_none())
    }

    pub fn writer_epoch_is_current(&self, owner: NodeId, epoch: u64) -> bool {
        self.writer_keys
            .iter()
            .filter(|entry| entry.owner == owner)
            .max_by_key(|entry| entry.epoch)
            .is_some_and(|entry| entry.epoch == epoch && entry.revoked_at_event.is_none())
    }

    fn require_active_member(&self, node_id: NodeId) -> Result<&DynamicMember, GuildStateError> {
        self.members
            .iter()
            .find(|member| member.member.node_id == node_id && member.is_active())
            .ok_or(GuildStateError::InactiveMember(node_id))
    }

    fn active_member_mut(
        &mut self,
        node_id: NodeId,
    ) -> Result<&mut DynamicMember, GuildStateError> {
        self.members
            .iter_mut()
            .find(|member| member.member.node_id == node_id && member.is_active())
            .ok_or(GuildStateError::InactiveMember(node_id))
    }

    pub fn validate_current_group_placement(
        &self,
        group: &CodingGroupV2,
    ) -> Result<(), GuildStateError> {
        for role in &group.roles {
            let (node_id, domain) = match role {
                ShardRoleV2::Information(information) => {
                    (information.owner, information.failure_domain.as_str())
                }
                ShardRoleV2::Parity(parity) => (parity.holder, parity.failure_domain.as_str()),
            };
            let member = self.require_active_member(node_id)?;
            if member.member.failure_domain != domain {
                return Err(GuildStateError::InvalidPlacement);
            }
        }
        Ok(())
    }
}

pub fn sign_guild_event(
    event: &GuildEvent,
    keys: &KeyMaterial,
) -> Result<MemberSignature, GuildStateError> {
    Ok(MemberSignature {
        signer: keys.node_id(),
        signature: keys
            .sign(GUILD_EVENT_DOMAIN, &canonical_bytes(event)?)
            .to_vec(),
    })
}

pub fn verify_guild_event_signature(
    event: &GuildEvent,
    signature: &MemberSignature,
) -> Result<(), GuildStateError> {
    let key = VerifyingKey::from_bytes(&signature.signer.0)?;
    if key.is_weak() {
        return Err(GuildStateError::InvalidEvent);
    }
    key.verify_strict(
        &signing_payload(GUILD_EVENT_DOMAIN, &canonical_bytes(event)?),
        &Signature::from_slice(&signature.signature)?,
    )?;
    Ok(())
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryEpochSecret([u8; 32]);

impl RecoveryEpochSecret {
    pub fn public_key(&self) -> RecoveryPublicKey {
        let secret = StaticSecret::from(self.0);
        RecoveryPublicKey(X25519PublicKey::from(&secret).to_bytes())
    }

    pub fn open_record(
        &self,
        record: &SealedRecoveryRecord,
    ) -> Result<Vec<u8>, RecoveryCryptoError> {
        let secret = StaticSecret::from(self.0);
        open_recovery_record_with_secret(&secret, self.public_key(), record)
    }
}

pub fn create_recovery_key_envelope(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    epoch: u64,
) -> Result<(RecoveryKeyEnvelope, RecoveryEpochSecret), GuildStateError> {
    if guild_id == [0; 32] || epoch == 0 {
        return Err(GuildStateError::InvalidEnvelope);
    }
    let mut secret_bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut secret_bytes);
    let secret = RecoveryEpochSecret(secret_bytes);
    let public_key = secret.public_key();
    let plaintext = Zeroizing::new(canonical_bytes(&(
        1_u16,
        guild_id,
        keys.node_id(),
        epoch,
        public_key,
        secret.0,
    ))?);
    let sealed_private_key = seal_recovery_record(keys.recovery_public_key(), &plaintext)?;
    Ok((
        RecoveryKeyEnvelope {
            format_version: 1,
            guild_id,
            subject: keys.node_id(),
            epoch,
            public_key,
            sealed_private_key,
        },
        secret,
    ))
}

pub fn open_recovery_key_envelope(
    keys: &KeyMaterial,
    envelope: &RecoveryKeyEnvelope,
) -> Result<RecoveryEpochSecret, GuildStateError> {
    validate_recovery_envelope(envelope, envelope.guild_id)?;
    if envelope.subject != keys.node_id() {
        return Err(GuildStateError::InvalidEnvelope);
    }
    let plaintext = Zeroizing::new(open_recovery_record(keys, &envelope.sealed_private_key)?);
    let decoded: (u16, [u8; 32], NodeId, u64, RecoveryPublicKey, [u8; 32]) =
        crate::decode_canonical(&plaintext)?;
    if decoded.0 != 1
        || decoded.1 != envelope.guild_id
        || decoded.2 != envelope.subject
        || decoded.3 != envelope.epoch
        || decoded.4 != envelope.public_key
    {
        return Err(GuildStateError::InvalidEnvelope);
    }
    let secret = RecoveryEpochSecret(decoded.5);
    if secret.public_key() != envelope.public_key {
        return Err(GuildStateError::InvalidEnvelope);
    }
    Ok(secret)
}

fn validate_member(member: &Member) -> Result<(), GuildStateError> {
    if member.node_id == NodeId([0; 32])
        || member.failure_domain.is_empty()
        || member.failure_domain.len() > 256
        || !member.recovery_public_key.is_contributory()
    {
        return Err(GuildStateError::InvalidEvent);
    }
    let key = VerifyingKey::from_bytes(&member.node_id.0)?;
    if key.is_weak() {
        return Err(GuildStateError::InvalidEvent);
    }
    Ok(())
}

fn validate_writer_keys(state: &DynamicGuildState) -> Result<(), GuildStateError> {
    let mut previous = None;
    let mut expected = std::collections::BTreeMap::<NodeId, u64>::new();
    for entry in &state.writer_keys {
        let order = (entry.owner, entry.epoch);
        let key = VerifyingKey::from_bytes(&entry.public_key)?;
        if previous.is_some_and(|value| value >= order)
            || entry.epoch != expected.get(&entry.owner).copied().unwrap_or(0) + 1
            || entry.activated_at_event == 0
            || entry.activated_at_event > state.event_sequence
            || entry.revoked_at_event.is_some_and(|event| {
                event <= entry.activated_at_event || event > state.event_sequence
            })
            || key.is_weak()
        {
            return Err(GuildStateError::InvalidState);
        }
        expected.insert(entry.owner, entry.epoch);
        previous = Some(order);
    }
    Ok(())
}

fn validate_recovery_keys(state: &DynamicGuildState) -> Result<(), GuildStateError> {
    let mut previous = None;
    let mut expected = std::collections::BTreeMap::<NodeId, u64>::new();
    for entry in &state.recovery_keys {
        validate_recovery_envelope(&entry.envelope, state.guild_id)?;
        let order = (entry.envelope.subject, entry.envelope.epoch);
        if previous.is_some_and(|value| value >= order)
            || entry.envelope.epoch
                != expected.get(&entry.envelope.subject).copied().unwrap_or(0) + 1
            || entry.activated_at_event == 0
            || entry.activated_at_event > state.event_sequence
            || entry.revoked_at_event.is_some_and(|event| {
                event <= entry.activated_at_event || event > state.event_sequence
            })
        {
            return Err(GuildStateError::InvalidState);
        }
        expected.insert(entry.envelope.subject, entry.envelope.epoch);
        previous = Some(order);
    }
    Ok(())
}

fn validate_recovery_envelope(
    envelope: &RecoveryKeyEnvelope,
    guild_id: [u8; 32],
) -> Result<(), GuildStateError> {
    if envelope.format_version != 1
        || envelope.guild_id != guild_id
        || envelope.subject == NodeId([0; 32])
        || envelope.epoch == 0
        || !envelope.public_key.is_contributory()
        || envelope.sealed_private_key.ciphertext.len() > 4096
    {
        return Err(GuildStateError::InvalidEnvelope);
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum GuildStateError {
    #[error("dynamic guild state is invalid")]
    InvalidState,
    #[error("guild event is invalid for the current state")]
    InvalidEvent,
    #[error("guild event has {actual} signatures but requires {required}")]
    InsufficientQuorum { actual: usize, required: usize },
    #[error("member is inactive or absent: {0}")]
    InactiveMember(NodeId),
    #[error("coding placement does not match the current certified roster")]
    InvalidPlacement,
    #[error("coding attempt was fenced by membership, authorization, or expiry")]
    InvalidAttempt,
    #[error("the retained coding layout is still inside its retention window")]
    RetentionActive,
    #[error("recovery key envelope is invalid")]
    InvalidEnvelope,
    #[error("protocol model failure: {0}")]
    Model(#[from] ModelError),
    #[error("recovery envelope cryptography failed: {0}")]
    Recovery(#[from] RecoveryCryptoError),
    #[error("signature validation failed: {0}")]
    Signature(#[from] ed25519_dalek::SignatureError),
}

#[cfg(test)]
mod tests {
    use crate::{
        CodingPlanGeometry, CodingProfile, InformationRoleV2, ParityPlacementV2, ParityRoleV2,
        RangeSectorRef, Seed, decode_canonical, encode, merkle_commit,
    };

    use super::*;

    #[test]
    fn bounded_authority_projection_replays_original_membership_and_indexed_effects() {
        let keys = keys(6);
        let mut full = state(&keys);
        let mut projection = GuildAuthoritySnapshot::from_state(&full).unwrap();
        for kind in [
            GuildEventKind::AddMember {
                member: member(&keys[5], "domain-5"),
            },
            GuildEventKind::RelabelMember {
                node_id: keys[5].node_id(),
                failure_domain: "domain-0".into(),
            },
            GuildEventKind::RemoveMember {
                node_id: keys[5].node_id(),
            },
            GuildEventKind::SetQuorum {
                policy: full.quorum,
            },
        ] {
            let certified = certify(&full, kind, &keys[..5]);
            projection
                .advance(&certified, |_, _| panic!("membership callback"))
                .unwrap();
            full.apply_event(&certified).unwrap();
            assert_eq!(
                projection,
                GuildAuthoritySnapshot::from_state(&full).unwrap()
            );
        }
        let roster_bytes = canonical_bytes(&projection).unwrap().len();
        for epoch in 1..=64 {
            let certified = certify(
                &full,
                GuildEventKind::RotateWriterKey {
                    owner: keys[0].node_id(),
                    epoch,
                    public_key: keys[0].node_id().0,
                },
                &keys[..5],
            );
            let bytes = canonical_bytes(&certified).unwrap();
            assert_eq!(QuorumGuildEvent::decode_bounded(&bytes).unwrap(), certified);
            projection
                .advance(&certified, |before, event| {
                    assert_eq!(before, &GuildAuthoritySnapshot::from_state(&full)?);
                    assert_eq!(event, &certified.event);
                    // The indexed implementation must perform these semantics;
                    // this small fixture uses the legacy state as its oracle.
                    full.apply_event(&certified)
                })
                .unwrap();
            assert_eq!(
                projection,
                GuildAuthoritySnapshot::from_state(&full).unwrap()
            );
        }
        assert_eq!(full.writer_keys.len(), 64);
        assert_eq!(canonical_bytes(&projection).unwrap().len(), roster_bytes);
        assert_eq!(
            GuildAuthoritySnapshot::decode(&canonical_bytes(&projection).unwrap()).unwrap(),
            projection
        );
        assert!(canonical_bytes(&full).unwrap().len() > roster_bytes * 3);
    }

    #[test]
    fn bounded_authority_failures_do_not_advance_and_overflow_rejects() {
        let keys = keys(6);
        let full = state(&keys);
        let mut snapshot = GuildAuthoritySnapshot::from_state(&full).unwrap();
        let original = snapshot.clone();
        let certified = certify(
            &full,
            GuildEventKind::RotateWriterKey {
                owner: keys[0].node_id(),
                epoch: 7,
                public_key: keys[0].node_id().0,
            },
            &keys[..3],
        );
        snapshot.verify_event(&certified).unwrap();
        assert!(
            snapshot
                .advance(&certified, |_, _| Err(GuildStateError::InvalidEvent))
                .is_err()
        );
        assert_eq!(snapshot, original);
        for mutate in [0, 1, 2, 3, 4] {
            let mut damaged = certified.clone();
            match mutate {
                0 => damaged.event.parent = [9; 32],
                1 => damaged.event.sequence += 1,
                2 => damaged.event.format_version = 2,
                3 => damaged.signatures[0].signature[0] ^= 1,
                _ => damaged.signatures.reverse(),
            }
            assert!(
                snapshot
                    .advance(&damaged, |_, _| panic!("invalid certificate callback"))
                    .is_err()
            );
            assert_eq!(snapshot, original);
        }
        // A quorum without the rotating subject cannot establish authority.
        let no_subject = certify(&full, certified.event.kind.clone(), &keys[1..4]);
        assert!(snapshot.verify_event(&no_subject).is_err());
        snapshot.event_sequence = u64::MAX;
        let mut wrapped = certified.clone();
        wrapped.event.sequence = 0;
        assert!(snapshot.verify_event(&wrapped).is_err());
        snapshot = original;
        snapshot.membership_epoch = u64::MAX;
        let membership = certify(
            &full,
            GuildEventKind::SetQuorum {
                policy: full.quorum,
            },
            &keys[..3],
        );
        let before = snapshot.clone();
        assert!(
            snapshot
                .advance(&membership, |_, _| panic!("membership callback"))
                .is_err()
        );
        assert_eq!(snapshot, before);
    }

    #[test]
    fn bounded_event_decoders_preserve_every_original_variant_and_reject_nested_excess() {
        let keys = keys(6);
        let full = state(&keys);
        let group = group(&full, &keys);
        let (envelope, _) = create_recovery_key_envelope(&keys[0], full.guild_id, 1).unwrap();
        let kinds = vec![
            GuildEventKind::AddMember {
                member: member(&keys[5], "domain-5"),
            },
            GuildEventKind::RemoveMember {
                node_id: keys[0].node_id(),
            },
            GuildEventKind::RelabelMember {
                node_id: keys[0].node_id(),
                failure_domain: "domain".into(),
            },
            GuildEventKind::SetQuorum {
                policy: full.quorum,
            },
            GuildEventKind::RotateWriterKey {
                owner: keys[0].node_id(),
                epoch: 1,
                public_key: keys[0].node_id().0,
            },
            GuildEventKind::RevokeWriterKey {
                owner: keys[0].node_id(),
                epoch: 1,
            },
            GuildEventKind::RotateRecoveryKey {
                envelope: envelope.clone(),
            },
            GuildEventKind::RevokeRecoveryKey {
                subject: keys[0].node_id(),
                epoch: 1,
            },
            GuildEventKind::AddCodingGroup {
                group: group.clone(),
            },
            GuildEventKind::RetireCodingGroup {
                group_id: group.id,
                retain_through_event: 20,
            },
            GuildEventKind::ForgetCodingGroup { group_id: group.id },
            GuildEventKind::AddCodingGroupBound {
                group,
                transcript_hash: [8; 32],
            },
        ];
        for kind in kinds {
            let mut certified = certify(&full, kind, &keys[..5]);
            if matches!(
                certified.event.kind,
                GuildEventKind::AddCodingGroupBound { .. }
            ) {
                certified.event.format_version = 2;
            }
            let bytes = canonical_bytes(&certified).unwrap();
            assert_eq!(QuorumGuildEvent::decode_bounded(&bytes).unwrap(), certified);
            let expected = blake3::derive_key(
                "mutualbackup guild event v1",
                &canonical_bytes(&certified.event).unwrap(),
            );
            assert_eq!(certified.event.hash().unwrap(), expected);
            let mut trailing = bytes;
            trailing.push(0);
            assert!(QuorumGuildEvent::decode_bounded(&trailing).is_err());
        }
        let valid = certify(
            &full,
            GuildEventKind::SetQuorum {
                policy: full.quorum,
            },
            &keys[..3],
        );
        let mut excessive = valid.clone();
        excessive.signatures[0].signature.resize(65, 0);
        assert!(QuorumGuildEvent::decode_bounded(&canonical_bytes(&excessive).unwrap()).is_err());
        excessive = valid.clone();
        excessive
            .signatures
            .resize(257, valid.signatures[0].clone());
        assert!(QuorumGuildEvent::decode_bounded(&canonical_bytes(&excessive).unwrap()).is_err());
        let mut excessive_envelope = envelope;
        excessive_envelope
            .sealed_private_key
            .ciphertext
            .resize(4097, 0);
        for kind in [
            GuildEventKind::AddMember {
                member: member(&keys[5], &"x".repeat(257)),
            },
            GuildEventKind::RelabelMember {
                node_id: keys[0].node_id(),
                failure_domain: "x".repeat(257),
            },
            GuildEventKind::RotateRecoveryKey {
                envelope: excessive_envelope,
            },
        ] {
            let event = certify(&full, kind, &keys[..5]);
            assert!(QuorumGuildEvent::decode_bounded(&canonical_bytes(&event).unwrap()).is_err());
        }
        assert!(QuorumGuildEvent::decode_bounded(&vec![0; GUILD_EVENT_BYTES + 1]).is_err());
        let mut projection = GuildAuthoritySnapshot::from_state(&full).unwrap();
        projection
            .members
            .resize(257, projection.members[0].clone());
        assert!(GuildAuthoritySnapshot::decode(&canonical_bytes(&projection).unwrap()).is_err());
        assert!(projection.validate().is_err());
        projection.members.truncate(5);
        projection.members[0].member.failure_domain = "x".repeat(257);
        assert!(GuildAuthoritySnapshot::decode(&canonical_bytes(&projection).unwrap()).is_err());
    }

    #[test]
    fn bounded_legacy_add_binding_requires_exact_original_event_and_quorum() {
        let keys = keys(6);
        let full = state(&keys);
        let snapshot = GuildAuthoritySnapshot::from_state(&full).unwrap();
        let certified = certify(
            &full,
            GuildEventKind::AddCodingGroup {
                group: group(&full, &keys),
            },
            &keys[..3],
        );
        let statement = LegacyCodingAddStatement::for_event(&certified, [7; 32]).unwrap();
        let binding_for = |signers: &[KeyMaterial]| {
            let mut signatures = signers
                .iter()
                .map(|key| sign_legacy_coding_add_binding(&statement, key).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            QuorumLegacyCodingAddBinding {
                statement: statement.clone(),
                signatures,
            }
        };
        let binding = binding_for(&keys[..3]);
        let bytes = canonical_bytes(&binding).unwrap();
        assert_eq!(
            QuorumLegacyCodingAddBinding::decode_bounded(&bytes).unwrap(),
            binding
        );
        snapshot
            .verify_legacy_coding_add_binding(&binding, &certified)
            .unwrap();
        assert!(
            snapshot
                .verify_legacy_coding_add_binding(&binding_for(&keys[1..4]), &certified)
                .is_err()
        );
        let mut changed = binding.clone();
        changed.statement.transcript_hash = [9; 32];
        assert!(
            snapshot
                .verify_legacy_coding_add_binding(&changed, &certified)
                .is_err()
        );
        changed = binding.clone();
        changed.signatures[0].signature.resize(65, 0);
        assert!(
            QuorumLegacyCodingAddBinding::decode_bounded(&canonical_bytes(&changed).unwrap())
                .is_err()
        );
        changed = binding;
        changed
            .signatures
            .resize(257, changed.signatures[0].clone());
        assert!(
            QuorumLegacyCodingAddBinding::decode_bounded(&canonical_bytes(&changed).unwrap())
                .is_err()
        );
        let mut trailing = bytes;
        trailing.push(0);
        assert!(QuorumLegacyCodingAddBinding::decode_bounded(&trailing).is_err());
    }

    fn keys(count: u8) -> Vec<KeyMaterial> {
        (0..count)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value + 100; 32])))
            .collect()
    }

    fn member(keys: &KeyMaterial, domain: &str) -> Member {
        Member {
            node_id: keys.node_id(),
            recovery_public_key: keys.recovery_public_key(),
            failure_domain: domain.to_owned(),
        }
    }

    fn state(keys: &[KeyMaterial]) -> DynamicGuildState {
        DynamicGuildState::new(
            [1; 32],
            [2; 32],
            QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Majority,
            },
            keys.iter()
                .take(5)
                .enumerate()
                .map(|(index, key)| member(key, &format!("domain-{index}")))
                .collect(),
        )
        .unwrap()
    }

    fn certify(
        state: &DynamicGuildState,
        kind: GuildEventKind,
        signers: &[KeyMaterial],
    ) -> QuorumGuildEvent {
        let event = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind,
        };
        let mut signatures = signers
            .iter()
            .map(|keys| sign_guild_event(&event, keys).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        QuorumGuildEvent { event, signatures }
    }

    fn group(state: &DynamicGuildState, keys: &[KeyMaterial]) -> CodingGroupV2 {
        let profile = CodingProfile::new(3, 2, 64);
        let information = vec![vec![1; 64], vec![2; 64], vec![3; 64]];
        let encoded = encode(profile, information).unwrap();
        let mut roles = encoded[..3]
            .iter()
            .enumerate()
            .map(|(index, bytes)| {
                ShardRoleV2::Information(InformationRoleV2 {
                    owner: keys[index].node_id(),
                    failure_domain: format!("domain-{index}"),
                    sector: RangeSectorRef {
                        id: [index as u8 + 1; 32],
                        commitment: merkle_commit(bytes).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                })
            })
            .collect::<Vec<_>>();
        roles.extend(encoded[3..].iter().enumerate().map(|(row, bytes)| {
            ShardRoleV2::Parity(ParityRoleV2 {
                holder: keys[3 + row].node_id(),
                failure_domain: format!("domain-{}", 3 + row),
                row: row as u16,
                commitment: merkle_commit(bytes).unwrap(),
            })
        }));
        let mut group = CodingGroupV2 {
            id: [0; 32],
            format_version: 2,
            guild_id: state.guild_id,
            profile,
            roles,
        };
        group.id = group.calculate_id().unwrap();
        group
    }

    #[test]
    fn legacy_add_event_bytes_remain_decodable() {
        #[allow(dead_code)]
        #[derive(Serialize)]
        enum LegacyKind {
            AddMember,
            RemoveMember,
            RelabelMember,
            SetQuorum,
            RotateWriterKey,
            RevokeWriterKey,
            RotateRecoveryKey,
            RevokeRecoveryKey,
            AddCodingGroup { group: CodingGroupV2 },
        }

        #[derive(Serialize)]
        struct LegacyEvent {
            format_version: u16,
            guild_id: [u8; 32],
            sequence: u64,
            parent: [u8; 32],
            kind: LegacyKind,
        }

        let keys = keys(8);
        let state = state(&keys);
        let group = group(&state, &keys);
        let old_bytes = canonical_bytes(&LegacyEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: 1,
            parent: state.event_head,
            kind: LegacyKind::AddCodingGroup {
                group: group.clone(),
            },
        })
        .unwrap();
        let decoded: GuildEvent = decode_canonical(&old_bytes).unwrap();
        assert_eq!(
            decoded.kind,
            GuildEventKind::AddCodingGroup {
                group: group.clone()
            }
        );
        assert_eq!(canonical_bytes(&decoded).unwrap(), old_bytes);

        let bound = GuildEvent {
            format_version: 2,
            guild_id: state.guild_id,
            sequence: 1,
            parent: state.event_head,
            kind: GuildEventKind::AddCodingGroupBound {
                group: group.clone(),
                transcript_hash: [7; 32],
            },
        };
        state.validate_event_proposal(&bound).unwrap();
        assert_eq!(
            decode_canonical::<GuildEvent>(&canonical_bytes(&bound).unwrap()).unwrap(),
            bound
        );
        let mut invalid = bound;
        invalid.format_version = 1;
        assert!(state.validate_event_proposal(&invalid).is_err());
    }

    #[test]
    fn historical_add_binding_requires_the_exact_transcript_and_quorum() {
        let keys = keys(8);
        let state = state(&keys);
        let add = certify(
            &state,
            GuildEventKind::AddCodingGroup {
                group: group(&state, &keys),
            },
            &keys[..5],
        );
        let statement = LegacyCodingAddStatement::for_event(&add, [9; 32]).unwrap();
        let mut signatures = keys[..5]
            .iter()
            .map(|key| sign_legacy_coding_add_binding(&statement, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let binding = QuorumLegacyCodingAddBinding {
            statement,
            signatures,
        };
        binding.verify(&state, &add).unwrap();

        let mut wrong = binding.clone();
        wrong.statement.transcript_hash = [10; 32];
        assert!(wrong.verify(&state, &add).is_err());
        let mut partial = binding.clone();
        partial.signatures.truncate(2);
        assert!(partial.verify(&state, &add).is_err());
        let mut duplicate = binding;
        duplicate
            .signatures
            .insert(1, duplicate.signatures[0].clone());
        assert!(duplicate.verify(&state, &add).is_err());
    }

    #[test]
    fn dynamic_membership_uses_the_pre_event_quorum_and_fences_attempts() {
        let keys = keys(8);
        let mut state = state(&keys);
        let group = group(&state, &keys);
        let geometry = CodingPlanGeometry {
            format_version: 1,
            guild_id: group.guild_id,
            profile: group.profile,
            information: group.roles[..3]
                .iter()
                .map(|role| match role {
                    ShardRoleV2::Information(information) => information.clone(),
                    ShardRoleV2::Parity(_) => unreachable!(),
                })
                .collect(),
            parity: group.roles[3..]
                .iter()
                .map(|role| match role {
                    ShardRoleV2::Parity(parity) => ParityPlacementV2 {
                        holder: parity.holder,
                        failure_domain: parity.failure_domain.clone(),
                        row: parity.row,
                    },
                    ShardRoleV2::Information(_) => unreachable!(),
                })
                .collect(),
        };
        let plan = CodingAttemptPlan {
            format_version: 1,
            attempt_id: [3; 16],
            checkpoint_hash: [4; 32],
            membership_epoch: state.membership_epoch,
            geometry,
            delegator: keys[0].node_id(),
            coding_coordinator: keys[1].node_id(),
            verification_coordinator: keys[2].node_id(),
            expires_at_unix_seconds: 100,
            information_roots: None,
        };
        state.validate_attempt(&plan, 50).unwrap();

        let add = certify(
            &state,
            GuildEventKind::AddMember {
                member: member(&keys[5], "domain-5"),
            },
            &keys[..3],
        );
        state.apply_event(&add).unwrap();
        assert_eq!(state.active_members().count(), 6);
        assert!(matches!(
            state.validate_attempt(&plan, 50),
            Err(GuildStateError::InvalidAttempt)
        ));

        let remove = certify(
            &state,
            GuildEventKind::RemoveMember {
                node_id: keys[4].node_id(),
            },
            &keys[..4],
        );
        state.apply_event(&remove).unwrap();
        assert_eq!(state.active_members().count(), 5);
    }

    #[test]
    fn old_layout_survives_member_removal_relabel_and_retention() {
        let keys = keys(8);
        let mut state = state(&keys);
        let group = group(&state, &keys);
        let group_id = group.id;
        let add = certify(
            &state,
            GuildEventKind::AddCodingGroup {
                group: group.clone(),
            },
            &keys[..3],
        );
        state.apply_event(&add).unwrap();
        let remove = certify(
            &state,
            GuildEventKind::RemoveMember {
                node_id: keys[4].node_id(),
            },
            &keys[..3],
        );
        state.apply_event(&remove).unwrap();
        assert!(matches!(
            state.validate_current_group_placement(&group),
            Err(GuildStateError::InactiveMember(_))
        ));
        let relabel = certify(
            &state,
            GuildEventKind::RelabelMember {
                node_id: keys[0].node_id(),
                failure_domain: "new-domain".to_owned(),
            },
            &keys[..3],
        );
        state.apply_event(&relabel).unwrap();
        assert!(state.validate_current_group_placement(&group).is_err());
        assert_eq!(state.coding_groups[0].group, group);

        let retire = certify(
            &state,
            GuildEventKind::RetireCodingGroup {
                group_id,
                retain_through_event: state.event_sequence + 2,
            },
            &keys[..3],
        );
        state.apply_event(&retire).unwrap();
        let early_forget = certify(
            &state,
            GuildEventKind::ForgetCodingGroup { group_id },
            &keys[..3],
        );
        assert!(matches!(
            state.apply_event(&early_forget),
            Err(GuildStateError::RetentionActive)
        ));
    }

    #[test]
    fn revoking_latest_writer_never_reactivates_older_epoch() {
        let keys = keys(6);
        let mut state = state(&keys);
        let owner = keys[0].node_id();
        let writers = [9, 10, 11].map(|value| {
            ed25519_dalek::SigningKey::from_bytes(&[value; 32])
                .verifying_key()
                .to_bytes()
        });
        for (epoch, public_key) in [(1, writers[0]), (2, writers[1])] {
            let event = certify(
                &state,
                GuildEventKind::RotateWriterKey {
                    owner,
                    epoch,
                    public_key,
                },
                &keys[..3],
            );
            state.apply_event(&event).unwrap();
        }
        assert!(!state.writer_epoch_is_current(owner, 1));
        assert!(state.writer_epoch_is_current(owner, 2));
        let revoke = certify(
            &state,
            GuildEventKind::RevokeWriterKey { owner, epoch: 2 },
            &keys[..3],
        );
        state.apply_event(&revoke).unwrap();
        assert!(!state.writer_epoch_is_current(owner, 1));
        assert!(!state.writer_epoch_is_current(owner, 2));
        for (epoch, public_key) in [(1, writers[0]), (2, writers[1])] {
            assert_eq!(
                state.writer_key_for_retained_revision(owner, epoch),
                Some(public_key)
            );
        }
        let rotate = certify(
            &state,
            GuildEventKind::RotateWriterKey {
                owner,
                epoch: 3,
                public_key: writers[2],
            },
            &keys[..3],
        );
        state.apply_event(&rotate).unwrap();
        assert!(state.writer_epoch_is_current(owner, 3));
        assert!(!state.writer_epoch_is_current(owner, 1));
        assert!(!state.writer_epoch_is_current(owner, 2));
    }

    #[test]
    fn writer_and_recovery_rotation_preserve_old_epoch_material() {
        let keys = keys(6);
        let mut state = state(&keys);
        let writer_one = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let writer_two = ed25519_dalek::SigningKey::from_bytes(&[10; 32]);
        for (epoch, writer) in [(1, &writer_one), (2, &writer_two)] {
            let event = certify(
                &state,
                GuildEventKind::RotateWriterKey {
                    owner: keys[0].node_id(),
                    epoch,
                    public_key: writer.verifying_key().to_bytes(),
                },
                &keys[..3],
            );
            state.apply_event(&event).unwrap();
        }
        assert_eq!(
            state.writer_key_for_retained_revision(keys[0].node_id(), 1),
            Some(writer_one.verifying_key().to_bytes())
        );
        assert!(state.writer_epoch_is_current(keys[0].node_id(), 2));

        let (envelope_one, secret_one) =
            create_recovery_key_envelope(&keys[0], state.guild_id, 1).unwrap();
        let rotate_one = certify(
            &state,
            GuildEventKind::RotateRecoveryKey {
                envelope: envelope_one.clone(),
            },
            &keys[..3],
        );
        state.apply_event(&rotate_one).unwrap();
        assert_eq!(
            state
                .current_recovery_key(keys[0].node_id())
                .unwrap()
                .envelope,
            envelope_one
        );
        let epoch_record = seal_recovery_record(envelope_one.public_key, b"epoch locator").unwrap();
        assert_eq!(
            secret_one.open_record(&epoch_record).unwrap(),
            b"epoch locator"
        );
        let revoke = certify(
            &state,
            GuildEventKind::RevokeRecoveryKey {
                subject: keys[0].node_id(),
                epoch: 1,
            },
            &keys[..3],
        );
        state.apply_event(&revoke).unwrap();
        assert!(state.current_recovery_key(keys[0].node_id()).is_none());
        let (envelope_two, _) = create_recovery_key_envelope(&keys[0], state.guild_id, 2).unwrap();
        let rotate_two = certify(
            &state,
            GuildEventKind::RotateRecoveryKey {
                envelope: envelope_two.clone(),
            },
            &keys[..3],
        );
        state.apply_event(&rotate_two).unwrap();
        assert_eq!(
            state
                .current_recovery_key(keys[0].node_id())
                .unwrap()
                .envelope,
            envelope_two
        );
        assert_eq!(
            open_recovery_key_envelope(&keys[0], &envelope_one)
                .unwrap()
                .public_key(),
            secret_one.public_key()
        );
        assert!(open_recovery_key_envelope(&keys[1], &envelope_one).is_err());
    }

    #[test]
    fn configurable_thresholds_preserve_quorum_intersection() {
        assert_eq!(
            QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Threshold(3),
            }
            .required(5)
            .unwrap(),
            3
        );
        assert!(
            QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Threshold(2),
            }
            .required(5)
            .is_err()
        );
    }
}
