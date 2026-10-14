use super::super::tests::{event, fixture, relabel};
use super::*;
use crate::{CheckpointHistoryRecoveryState as State, CheckpointHistoryTarget};

fn history() -> (
    Seed,
    Node,
    Vec<QuorumGuildEvent>,
    CheckpointHistoryTarget,
    tempfile::TempDir,
) {
    let (temp, seed, mut node, keys) = fixture();
    let first = relabel(&node, &keys);
    node.install_guild_event(first.clone()).unwrap();
    let second = event(
        &node,
        &keys,
        mb_core::GuildEventKind::SetQuorum {
            policy: QuorumPolicy {
                format_version: 1,
                rule: QuorumRule::Majority,
            },
        },
    );
    node.install_guild_event(second.clone()).unwrap();
    let trust = frozen_original_history(&node.control)
        .unwrap()
        .paged_checkpoint_trust()
        .unwrap();
    let target = CheckpointHistoryTarget {
        guild_id: trust.guild_id,
        genesis_hash: trust.genesis_hash,
        event_sequence: trust.event_sequence,
        event_head: trust.event_head,
    };
    (seed, node, vec![first, second], target, temp)
}
fn fresh(path: &Path, seed: Seed) -> Node {
    let (_, certificate, peers) = crate::node::tests::recovery_guild_fixture();
    let mut node = Node::open(path, seed).unwrap();
    node.adopt_recovered_guild(certificate, peers).unwrap();
    node
}
#[test]
fn history_recovery_admission_atomic_faults_prefix_reopen_and_cancel_preserve_original_authority() {
    for action in ["ABORT", "IGNORE"] {
        let (seed, _source, events, target, _original) = history();
        let temp = tempfile::tempdir().unwrap();
        let node = fresh(temp.path(), seed.clone());
        let id = Uuid::from_u128(890);
        let required = target.required_work().unwrap();
        let mut short = required;
        short.bytes -= 1;
        assert!(
            node.begin_checkpoint_history_recovery(id, target, short)
                .is_err()
        );
        assert!(
            node.control
                .get_record("checkpoint-history-recovery-v1", id.as_bytes())
                .unwrap()
                .is_none()
        );
        let fault = if action == "ABORT" { ",'test'" } else { "" };
        node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER history_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='checkpoint-history-recovery-guard-v1' BEGIN SELECT RAISE({action}{fault}); END"),false).unwrap();
        assert!(
            node.begin_checkpoint_history_recovery(id, target, required)
                .is_err()
        );
        assert!(
            node.control
                .get_record("checkpoint-history-recovery-v1", id.as_bytes())
                .unwrap()
                .is_none()
        );
        node.control
            .database_shell_statement("DROP TRIGGER history_fault", false)
            .unwrap();
        let job = node
            .begin_checkpoint_history_recovery(id, target, required)
            .unwrap();
        let original = node.checkpoint_history_recovery_progress(&job).unwrap();
        let mut changed_budget = required;
        changed_budget.records += 1;
        assert!(
            node.begin_checkpoint_history_recovery(id, target, changed_budget)
                .is_err()
        );
        let mut changed_target = target;
        changed_target.event_head[0] ^= 1;
        assert!(
            node.begin_checkpoint_history_recovery(id, changed_target, required)
                .is_err()
        );
        for kind in [
            "checkpoint-history-recovery-v1",
            "checkpoint-history-recovery-guard-v1",
            "guild-original-tip-v1",
            "guild-authority-tip-v1",
        ] {
            node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER history_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE({action}{fault}); END"),false).unwrap();
            assert!(
                node.install_checkpoint_history_event(&job, events[0].clone(), None, None)
                    .is_err()
            );
            assert_eq!(
                node.checkpoint_history_recovery_progress(&job).unwrap(),
                original
            );
            assert!(
                node.control
                    .get_record("guild-event", &1u64.to_be_bytes())
                    .unwrap()
                    .is_none()
            );
            node.control
                .database_shell_statement("DROP TRIGGER history_fault", false)
                .unwrap();
        }
        let mut corrupt = events[0].clone();
        corrupt.signatures[0].signature[0] ^= 1;
        assert!(
            node.install_checkpoint_history_event(&job, corrupt, None, None)
                .is_err()
        );
        assert_eq!(
            node.checkpoint_history_recovery_progress(&job).unwrap(),
            original
        );
        node.install_checkpoint_history_event(&job, events[0].clone(), None, None)
            .unwrap();
        let bytes = node
            .control
            .get_record("guild-event", &1u64.to_be_bytes())
            .unwrap()
            .unwrap();
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        assert_eq!(
            node.begin_checkpoint_history_recovery(id, target, required)
                .unwrap(),
            job
        );
        assert_eq!(
            node.checkpoint_history_recovery_progress(&job).unwrap().1,
            1
        );
        assert_eq!(
            node.control
                .get_record("guild-event", &1u64.to_be_bytes())
                .unwrap()
                .unwrap(),
            bytes
        );
        node.cancel_checkpoint_history_recovery(&job).unwrap();
        assert_eq!(
            node.checkpoint_history_recovery_progress(&job).unwrap().0,
            State::Cancelled
        );
        assert!(
            node.install_checkpoint_history_event(&job, events[1].clone(), None, None)
                .is_err()
        );
        assert!(
            node.begin_checkpoint_history_recovery(id, target, required)
                .is_err()
        );
        let next = node
            .begin_checkpoint_history_recovery(Uuid::from_u128(891), target, required)
            .unwrap();
        node.install_checkpoint_history_event(&next, events[1].clone(), None, None)
            .unwrap();
        assert_eq!(
            node.checkpoint_history_recovery_progress(&next).unwrap(),
            (State::Complete, target.event_sequence, target.event_head)
        );
        assert_eq!(
            node.control
                .get_record("guild-event", &1u64.to_be_bytes())
                .unwrap()
                .unwrap(),
            bytes
        );
    }
}
#[test]
fn history_recovery_wrong_tip_and_damaged_paired_progress_cannot_publish_completion() {
    let (seed, _source, events, target, _original) = history();
    let temp = tempfile::tempdir().unwrap();
    let node = fresh(temp.path(), seed);
    let mut wrong = target;
    wrong.event_head[0] ^= 1;
    let required = wrong.required_work().unwrap();
    let job = node
        .begin_checkpoint_history_recovery(Uuid::from_u128(892), wrong, required)
        .unwrap();
    node.install_checkpoint_history_event(&job, events[0].clone(), None, None)
        .unwrap();
    assert!(
        node.install_checkpoint_history_event(&job, events[1].clone(), None, None)
            .is_err()
    );
    assert_eq!(
        node.checkpoint_history_recovery_progress(&job).unwrap().1,
        1
    );
    let saved = node
        .control
        .get_record("checkpoint-history-recovery-v1", job.id.as_bytes())
        .unwrap()
        .unwrap();
    node.control
        .put_record(
            "checkpoint-history-recovery-v1",
            job.id.as_bytes(),
            b"damaged",
        )
        .unwrap();
    assert!(node.checkpoint_history_recovery_progress(&job).is_err());
    assert!(node.cancel_checkpoint_history_recovery(&job).is_err());
    node.control
        .put_record("checkpoint-history-recovery-v1", job.id.as_bytes(), &saved)
        .unwrap();
    node.cancel_checkpoint_history_recovery(&job).unwrap();
    let job = node
        .begin_checkpoint_history_recovery(
            Uuid::from_u128(893),
            target,
            target.required_work().unwrap(),
        )
        .unwrap();
    node.install_checkpoint_history_event(&job, events[1].clone(), None, None)
        .unwrap();
    assert_eq!(
        node.checkpoint_history_recovery_progress(&job).unwrap().0,
        State::Complete
    );
    assert!(
        node.control
            .get_record("guild-dynamic-state", b"primary")
            .unwrap()
            .is_some()
    );
    // The retained legacy cache remains at genesis: all new event effects were
    // installed through the bounded original index, not a growing flat state.
    let bytes = node
        .control
        .get_record("guild-dynamic-state", b"primary")
        .unwrap()
        .unwrap();
    let legacy: DynamicGuildState = decode_canonical(&bytes).unwrap();
    assert_eq!(legacy.event_sequence, 0);
}
