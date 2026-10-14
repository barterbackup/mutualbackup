use super::*;
#[test]
fn historical_authority_reads_each_original_tip_across_later_membership_and_quorum_changes() {
    let mut history = History::new(false, 4);
    history.push(GuildEventKind::RelabelMember {
        node_id: history.keys[0].node_id(),
        failure_domain: "historical-domain".into(),
    });
    history.push(GuildEventKind::SetQuorum {
        policy: mb_core::QuorumPolicy {
            format_version: 1,
            rule: mb_core::QuorumRule::Majority,
        },
    });
    history.push(GuildEventKind::RemoveMember {
        node_id: history.keys[0].node_id(),
    });
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("historical.db");
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let initial = GuildAuthoritySnapshot::from_genesis(&history.genesis).unwrap();
    let mut state = DynamicGuildState::new(
        initial.guild_id,
        initial.event_head,
        initial.quorum,
        initial.active_members().cloned().collect(),
    )
    .unwrap();
    let mut expected = vec![initial];
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for bytes in history.source.events.values() {
        let event = QuorumGuildEvent::decode_bounded(bytes).unwrap();
        let mutation = durable(&control)
            .prepare_advance(&control, &event, budget(), &mut history.source.clone())
            .unwrap();
        control
            .with_record_transaction(|| -> Result<(), CatalogStoreError> {
                control.put_record("guild-event", &event.event.sequence.to_be_bytes(), bytes)?;
                mutation.apply_in_transaction(&control)
            })
            .unwrap();
        state.apply_event(&event).unwrap();
        expected.push(GuildAuthoritySnapshot::from_state(&state).unwrap());
    }
    drop(control);
    let control = ControlStore::open(&path, &history.keys[0]).unwrap();
    let current = durable(&control);
    let view = current
        .view(&control, current.genesis_hash(), current.authority())
        .unwrap();
    for snapshot in expected {
        assert_eq!(
            view.authority_at_event(
                snapshot.event_sequence,
                CatalogDurableGuildHistoryView::historical_authority_work()
            )
            .unwrap(),
            snapshot
        );
    }
    assert!(
        view.authority_at_event(current.authority().event_sequence + 1, budget())
            .is_err()
    );
    let mut short = CatalogDurableGuildHistoryView::historical_authority_work();
    short.bytes -= 1;
    assert!(view.authority_at_event(1, short).is_err());
    let saved = control
        .get_record("guild-event", &1u64.to_be_bytes())
        .unwrap()
        .unwrap();
    let mut damaged = QuorumGuildEvent::decode_bounded(&saved).unwrap();
    damaged.signatures[0].signature[0] ^= 1;
    control
        .put_record(
            "guild-event",
            &1u64.to_be_bytes(),
            &canonical_bytes(&damaged).unwrap(),
        )
        .unwrap();
    assert!(view.authority_at_event(1, budget()).is_err());
    control
        .put_record("guild-event", &1u64.to_be_bytes(), &saved)
        .unwrap();
    assert!(view.authority_at_event(1, budget()).is_ok());
}
