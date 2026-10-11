use super::*;
use crate::node::guild_authority::tests::{event, fixture, relabel};

fn poison_cache(node: &Node) -> Vec<u8> {
    let bytes = vec![0; 2 << 20];
    node.control
        .put_record("guild-dynamic-state", KEY, &bytes)
        .unwrap();
    bytes
}

fn admit(node: &mut Node, certified: QuorumGuildEvent) {
    let expected = canonical_bytes(&certified).unwrap();
    let sequence = certified.event.sequence;
    node.sign_guild_event_proposal(&certified.event).unwrap();
    let mut signatures = Vec::new();
    for signature in &certified.signatures {
        signatures = node
            .collect_guild_event_signature(&certified.event, signature.clone())
            .unwrap();
    }
    assert_eq!(signatures, certified.signatures);
    node.install_guild_event(certified.clone()).unwrap();
    assert_eq!(
        node.control
            .get_record("guild-event", &sequence.to_be_bytes())
            .unwrap()
            .unwrap(),
        expected
    );
    let partial = pending_guild_event_signatures_id(&certified.event);
    node.install_guild_event(certified).unwrap();
    assert!(
        node.control
            .get_record("guild-event-partial-signatures", &partial)
            .unwrap()
            .is_none()
    );
}

#[test]
fn indexed_normal_event_admission_rotates_keys_and_membership_without_flat_catalog() {
    let (temp, seed, mut node, keys) = fixture();
    let poison = poison_cache(&node);
    let owner = node.keys.node_id();
    for epoch in 1..=2 {
        let rotate = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner,
                epoch,
                public_key: keys[1].node_id().0,
            },
        );
        admit(&mut node, rotate);
        let revoke = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RevokeWriterKey { owner, epoch },
        );
        admit(&mut node, revoke);
        let duplicate = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RevokeWriterKey { owner, epoch },
        );
        assert!(node.sign_guild_event_proposal(&duplicate.event).is_err());
    }
    let invalid = event(
        &node,
        &keys,
        mb_core::GuildEventKind::RotateWriterKey {
            owner,
            epoch: 4,
            public_key: keys[1].node_id().0,
        },
    );
    assert!(node.sign_guild_event_proposal(&invalid.event).is_err());
    assert!(node.install_guild_event(invalid).is_err());
    for epoch in 1..=2 {
        let guild = complete_index(&node.control)
            .unwrap()
            .unwrap()
            .authority()
            .guild_id;
        let (envelope, _) =
            mb_core::create_recovery_key_envelope(&node.keys, guild, epoch).unwrap();
        let rotate = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateRecoveryKey { envelope },
        );
        admit(&mut node, rotate);
        let revoke = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RevokeRecoveryKey {
                subject: owner,
                epoch,
            },
        );
        admit(&mut node, revoke);
    }
    let changed = relabel(&node, &keys);
    admit(&mut node, changed);
    let removed = keys
        .iter()
        .find(|key| key.node_id() != owner)
        .unwrap()
        .node_id();
    let removal = event(
        &node,
        &keys,
        mb_core::GuildEventKind::RemoveMember { node_id: removed },
    );
    admit(&mut node, removal);
    let invalid = event(
        &node,
        &keys,
        mb_core::GuildEventKind::RotateWriterKey {
            owner: removed,
            epoch: 1,
            public_key: removed.0,
        },
    );
    assert!(node.sign_guild_event_proposal(&invalid.event).is_err());
    assert!(node.install_guild_event(invalid).is_err());
    let expected = node.dynamic_guild_state().unwrap().unwrap();
    assert_eq!(expected.writer_keys.len(), 2);
    assert_eq!(expected.recovery_keys.len(), 2);
    assert_eq!(
        node.control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap(),
        poison
    );
    drop(node);
    let mut node = Node::open(temp.path(), seed).unwrap();
    assert_eq!(node.dynamic_guild_state().unwrap().unwrap(), expected);
    let changed = relabel(&node, &keys);
    admit(&mut node, changed);
    assert_eq!(
        node.control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap(),
        poison
    );
}

#[test]
fn indexed_normal_coding_admission_preserves_evidence_and_full_retirement_lifecycle() {
    let (_temp, _seed, mut node, keys) = fixture();
    let poison = poison_cache(&node);
    let (add, transcript, _) = super::tests::group(&node, &keys);
    let group = transcript.value.manifest.value.group.clone();
    let before = node
        .control
        .get_record("guild-original-tip-v1", KEY)
        .unwrap();
    let mut invalid = add.event.clone();
    if let mb_core::GuildEventKind::AddCodingGroupBound {
        transcript_hash, ..
    } = &mut invalid.kind
    {
        *transcript_hash = [61; 32];
    }
    assert!(
        node.sign_coding_group_event_proposal(&invalid, &transcript)
            .is_err()
    );
    node.sign_coding_group_event_proposal(&add.event, &transcript)
        .unwrap();
    for signature in &add.signatures {
        node.collect_guild_event_signature(&add.event, signature.clone())
            .unwrap();
    }
    // Proposal validation has no durable effects and cannot produce a mutation
    // that installs an unsigned event.
    assert_eq!(
        node.control
            .get_record("guild-original-tip-v1", KEY)
            .unwrap(),
        before
    );
    assert!(
        node.control
            .get_record("guild-event", &add.event.sequence.to_be_bytes())
            .unwrap()
            .is_none()
    );
    let mut unsigned = add.clone();
    unsigned.signatures.clear();
    assert!(
        node.install_coding_group_event(unsigned, transcript.clone())
            .is_err()
    );
    assert_eq!(
        node.control
            .get_record("guild-original-tip-v1", KEY)
            .unwrap(),
        before
    );
    node.install_coding_group_event(add.clone(), transcript.clone())
        .unwrap();
    let bytes = canonical_bytes(&transcript).unwrap();
    assert_eq!(
        node.control
            .get_record("coding-event-transcript", &add.event.hash().unwrap())
            .unwrap()
            .unwrap(),
        bytes
    );
    node.install_coding_group_event(add, transcript).unwrap();
    let sequence = complete_index(&node.control)
        .unwrap()
        .unwrap()
        .authority()
        .event_sequence;
    let retire = event(
        &node,
        &keys,
        mb_core::GuildEventKind::RetireCodingGroup {
            group_id: group.id,
            retain_through_event: sequence + 2,
        },
    );
    admit(&mut node, retire);
    let early = event(
        &node,
        &keys,
        mb_core::GuildEventKind::ForgetCodingGroup { group_id: group.id },
    );
    assert!(node.sign_guild_event_proposal(&early.event).is_err());
    assert!(node.install_guild_event(early).is_err());
    let changed = relabel(&node, &keys);
    admit(&mut node, changed);
    let forget = event(
        &node,
        &keys,
        mb_core::GuildEventKind::ForgetCodingGroup { group_id: group.id },
    );
    admit(&mut node, forget);
    assert!(
        retained_group_if_available(&node.control, group.guild_id, group.id)
            .unwrap()
            .is_none()
    );
    assert!(
        node.dynamic_guild_state()
            .unwrap()
            .unwrap()
            .coding_groups
            .is_empty()
    );
    assert_eq!(
        node.control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap(),
        poison
    );
}

#[test]
fn indexed_event_signature_transactions_fence_original_authority_and_roll_back() {
    for fault in 0..3 {
        let partial = fault == 1;
        let (_temp, _seed, mut node, keys) = fixture();
        let poison = poison_cache(&node);
        let owner = node.keys.node_id();
        if fault == 2 {
            let first = event(
                &node,
                &keys,
                mb_core::GuildEventKind::RotateWriterKey {
                    owner,
                    epoch: 1,
                    public_key: keys[1].node_id().0,
                },
            );
            node.install_guild_event(first).unwrap();
        }
        let next = if fault == 2 {
            event(
                &node,
                &keys,
                mb_core::GuildEventKind::RotateWriterKey {
                    owner,
                    epoch: 2,
                    public_key: keys[1].node_id().0,
                },
            )
        } else {
            relabel(&node, &keys)
        };
        let kind = if partial {
            "guild-event-partial-signatures"
        } else {
            "guild-event-signature-lock"
        };
        if partial {
            node.sign_guild_event_proposal(&next.event).unwrap();
        }
        let compact = node.control.get_record(KIND, KEY).unwrap();
        let target = if fault == 2 {
            "guild-original-latest-writer"
        } else {
            KIND
        };
        let point = node
            .control
            .get_record("guild-original-latest-writer", &owner.0)
            .unwrap();
        node.control.database_shell_statement(&format!(
            "CREATE TEMP TRIGGER event_fault AFTER INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='{target}'; END"
        ), false).unwrap();
        let result = if partial {
            node.collect_guild_event_signature(&next.event, next.signatures[0].clone())
                .map(|_| ())
        } else {
            node.sign_guild_event_proposal(&next.event).map(|_| ())
        };
        assert!(result.is_err());
        assert_eq!(node.control.get_record(KIND, KEY).unwrap(), compact);
        assert_eq!(
            node.control
                .get_record("guild-original-latest-writer", &owner.0)
                .unwrap(),
            point
        );
        let id = if partial {
            pending_guild_event_signatures_id(&next.event).to_vec()
        } else {
            next.event.sequence.to_be_bytes().to_vec()
        };
        assert!(node.control.get_record(kind, &id).unwrap().is_none());
        assert_eq!(
            node.control
                .get_record("guild-dynamic-state", KEY)
                .unwrap()
                .unwrap(),
            poison
        );
        node.control
            .database_shell_statement("DROP TRIGGER event_fault", false)
            .unwrap();
        if partial {
            node.collect_guild_event_signature(&next.event, next.signatures[0].clone())
                .unwrap();
        } else {
            node.sign_guild_event_proposal(&next.event).unwrap();
        }
    }
}
