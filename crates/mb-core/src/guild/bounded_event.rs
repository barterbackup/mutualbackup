//! Scoped decoders for original event layouts. Legacy generic decoders and
//! signed encodings are unchanged; nested allocations are bounded here.
use super::*;
use serde::de::DeserializeSeed;

// At most 64 coding roles, each with a 256-byte domain, or one <=4096-byte
// recovery envelope, plus at most 256 original 64-byte member signatures.
pub const GUILD_EVENT_BYTES: usize = 128 * 1024;
pub const LEGACY_CODING_ADD_BINDING_BYTES: usize = 32 * 1024;

pub(super) fn member<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Member, D::Error> {
    #[derive(Deserialize)]
    struct Bounded {
        node_id: NodeId,
        recovery_public_key: RecoveryPublicKey,
        #[serde(deserialize_with = "crate::bounded::failure_domain")]
        failure_domain: String,
    }
    let value = Bounded::deserialize(decoder)?;
    Ok(Member {
        node_id: value.node_id,
        recovery_public_key: value.recovery_public_key,
        failure_domain: value.failure_domain,
    })
}

fn signatures<'de, D: serde::Deserializer<'de>>(
    decoder: D,
) -> Result<Vec<MemberSignature>, D::Error> {
    #[derive(Deserialize)]
    struct Bounded {
        signer: NodeId,
        #[serde(deserialize_with = "crate::bounded::signature")]
        signature: Vec<u8>,
    }
    Ok(crate::bounded::VecSeed::<Bounded>::new(MAX_DYNAMIC_MEMBERS)
        .deserialize(decoder)?
        .into_iter()
        .map(|value| MemberSignature {
            signer: value.signer,
            signature: value.signature,
        })
        .collect())
}

fn ciphertext<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    crate::bounded::VecSeed::new(4096).deserialize(decoder)
}

fn envelope<'de, D: serde::Deserializer<'de>>(decoder: D) -> Result<RecoveryKeyEnvelope, D::Error> {
    #[derive(Deserialize)]
    struct Sealed {
        format_version: u16,
        ephemeral_public_key: [u8; 32],
        nonce: [u8; 24],
        #[serde(deserialize_with = "ciphertext")]
        ciphertext: Vec<u8>,
    }
    #[derive(Deserialize)]
    struct Bounded {
        format_version: u16,
        guild_id: [u8; 32],
        subject: NodeId,
        epoch: u64,
        public_key: RecoveryPublicKey,
        sealed_private_key: Sealed,
    }
    let value = Bounded::deserialize(decoder)?;
    Ok(RecoveryKeyEnvelope {
        format_version: value.format_version,
        guild_id: value.guild_id,
        subject: value.subject,
        epoch: value.epoch,
        public_key: value.public_key,
        sealed_private_key: SealedRecoveryRecord {
            format_version: value.sealed_private_key.format_version,
            ephemeral_public_key: value.sealed_private_key.ephemeral_public_key,
            nonce: value.sealed_private_key.nonce,
            ciphertext: value.sealed_private_key.ciphertext,
        },
    })
}

// Variant order and every field order must remain identical to GuildEventKind.
#[derive(Deserialize)]
enum Kind {
    AddMember {
        #[serde(deserialize_with = "member")]
        member: Member,
    },
    RemoveMember {
        node_id: NodeId,
    },
    RelabelMember {
        node_id: NodeId,
        #[serde(deserialize_with = "crate::bounded::failure_domain")]
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
        #[serde(deserialize_with = "envelope")]
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
    AddCodingGroupBound {
        group: CodingGroupV2,
        transcript_hash: [u8; 32],
    },
}

impl From<Kind> for GuildEventKind {
    fn from(value: Kind) -> Self {
        match value {
            Kind::AddMember { member } => Self::AddMember { member },
            Kind::RemoveMember { node_id } => Self::RemoveMember { node_id },
            Kind::RelabelMember {
                node_id,
                failure_domain,
            } => Self::RelabelMember {
                node_id,
                failure_domain,
            },
            Kind::SetQuorum { policy } => Self::SetQuorum { policy },
            Kind::RotateWriterKey {
                owner,
                epoch,
                public_key,
            } => Self::RotateWriterKey {
                owner,
                epoch,
                public_key,
            },
            Kind::RevokeWriterKey { owner, epoch } => Self::RevokeWriterKey { owner, epoch },
            Kind::RotateRecoveryKey { envelope } => Self::RotateRecoveryKey { envelope },
            Kind::RevokeRecoveryKey { subject, epoch } => {
                Self::RevokeRecoveryKey { subject, epoch }
            }
            Kind::AddCodingGroup { group } => Self::AddCodingGroup { group },
            Kind::RetireCodingGroup {
                group_id,
                retain_through_event,
            } => Self::RetireCodingGroup {
                group_id,
                retain_through_event,
            },
            Kind::ForgetCodingGroup { group_id } => Self::ForgetCodingGroup { group_id },
            Kind::AddCodingGroupBound {
                group,
                transcript_hash,
            } => Self::AddCodingGroupBound {
                group,
                transcript_hash,
            },
        }
    }
}

impl QuorumGuildEvent {
    /// Decode one original signed event with bounded nested allocations and
    /// exact canonical bytes. Certificate and state-transition checks remain
    /// mandatory, including validation of non-membership state effects.
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, GuildStateError> {
        #[derive(Deserialize)]
        struct Event {
            format_version: u16,
            guild_id: [u8; 32],
            sequence: u64,
            parent: [u8; 32],
            kind: Kind,
        }
        #[derive(Deserialize)]
        struct Certificate {
            event: Event,
            #[serde(deserialize_with = "signatures")]
            signatures: Vec<MemberSignature>,
        }
        check_bytes(bytes, GUILD_EVENT_BYTES)?;
        let value: Certificate = crate::decode_canonical(bytes)?;
        let value = Self {
            event: GuildEvent {
                format_version: value.event.format_version,
                guild_id: value.event.guild_id,
                sequence: value.event.sequence,
                parent: value.event.parent,
                kind: value.event.kind.into(),
            },
            signatures: value.signatures,
        };
        if crate::canonical_bytes_bounded(&value, GUILD_EVENT_BYTES)? != bytes {
            return Err(GuildStateError::InvalidEvent);
        }
        Ok(value)
    }
}

impl QuorumLegacyCodingAddBinding {
    pub fn decode_bounded(bytes: &[u8]) -> Result<Self, GuildStateError> {
        #[derive(Deserialize)]
        struct Binding {
            statement: LegacyCodingAddStatement,
            #[serde(deserialize_with = "signatures")]
            signatures: Vec<MemberSignature>,
        }
        check_bytes(bytes, LEGACY_CODING_ADD_BINDING_BYTES)?;
        let value: Binding = crate::decode_canonical(bytes)?;
        let value = Self {
            statement: value.statement,
            signatures: value.signatures,
        };
        if crate::canonical_bytes_bounded(&value, LEGACY_CODING_ADD_BINDING_BYTES)? != bytes {
            return Err(GuildStateError::InvalidEvent);
        }
        Ok(value)
    }
}

fn check_bytes(bytes: &[u8], limit: usize) -> Result<(), GuildStateError> {
    if bytes.is_empty() || bytes.len() > limit {
        return Err(ModelError::EncodingTooLarge { limit }.into());
    }
    Ok(())
}
