mod checkpoint_directories;
mod checkpoint_directory_retention;
mod packing_checkpoint_handoff;
mod paged_checkpoint_custody;
mod paged_checkpoint_payload;
mod paged_checkpoint_retention;
mod paged_checkpoint_revision;
mod paged_packing_base;

use super::*;
use mb_core::{
    CatalogCodingEntry, CheckpointAuthority, DynamicGuildState, GuildEvent, GuildGenesis,
    KeyMaterial, LegacyCodingAddStatement, Member, Seed, canonical_bytes,
    create_recovery_key_envelope, sign_guild_event, sign_legacy_coding_add_binding,
};
use std::collections::BTreeMap;

fn durable(control: &ControlStore) -> CatalogDurableGuildHistory {
    CatalogDurableGuildHistory::read(control).unwrap().unwrap()
}

fn advance_durable(control: &ControlStore, history: &History) {
    let sequence = durable(control).authority().event_sequence + 1;
    let event = QuorumGuildEvent::decode_bounded(&history.source.events[&sequence]).unwrap();
    durable(control)
        .prepare_advance(control, &event, budget(), &mut history.source.clone())
        .unwrap()
        .commit(control)
        .unwrap();
}

#[test]
fn durable_original_history_latest_recovery_preserves_revocation_and_removed_subject_semantics() {
    let mut history = History::new(false, 4);
    let owner = history.keys[0].node_id();
    let (envelope, _) =
        create_recovery_key_envelope(&history.keys[0], history.state.guild_id, 2).unwrap();
    history.push(GuildEventKind::RotateRecoveryKey { envelope });
    history.push(GuildEventKind::RevokeRecoveryKey {
        subject: owner,
        epoch: 2,
    });
    let revoked_sequence = history.state.event_sequence;
    let (envelope, _) =
        create_recovery_key_envelope(&history.keys[0], history.state.guild_id, 3).unwrap();
    history.push(GuildEventKind::RotateRecoveryKey { envelope });
    history.push(GuildEventKind::RemoveMember { node_id: owner });
    let directory = tempfile::tempdir().unwrap();
    let control =
        ControlStore::open(directory.path().join("durable.db"), &history.keys[0]).unwrap();
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for sequence in 1..=history.state.event_sequence {
        advance_durable(&control, &history);
        let current = durable(&control);
        let view = current
            .view(&control, current.genesis_hash(), current.authority())
            .unwrap();
        if sequence == revoked_sequence {
            assert_eq!(
                view.latest_recovery_key(owner)
                    .unwrap()
                    .unwrap()
                    .envelope
                    .epoch,
                2
            );
            assert!(view.current_recovery_key(owner).unwrap().is_none());
            assert!(
                view.recovery_key(owner, 1)
                    .unwrap()
                    .unwrap()
                    .revoked_at_event
                    .is_none()
            );
        }
    }
    let current = durable(&control);
    let view = current
        .view(&control, current.genesis_hash(), current.authority())
        .unwrap();
    assert_eq!(
        view.current_recovery_key(owner).unwrap().as_ref(),
        history.state.current_recovery_key(owner)
    );
    assert_eq!(
        view.latest_recovery_key(owner)
            .unwrap()
            .unwrap()
            .envelope
            .epoch,
        3
    );
    assert!(
        !current
            .authority()
            .active_members()
            .any(|member| member.node_id == owner)
    );
    assert!(
        view.current_recovery_key(history.keys[1].node_id())
            .unwrap()
            .is_none()
    );
}

#[test]
fn durable_original_history_recovery_latest_rows_fail_closed_without_old_epoch_fallback() {
    let history = History::new(false, 4);
    let directory = tempfile::tempdir().unwrap();
    let control =
        ControlStore::open(directory.path().join("durable.db"), &history.keys[0]).unwrap();
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for _ in 0..6 {
        advance_durable(&control, &history);
    }
    let owner = history.keys[0].node_id();
    let current = durable(&control);
    let view = current
        .view(&control, current.genesis_hash(), current.authority())
        .unwrap();
    let pointer = control
        .get_record("guild-original-latest-recovery", &owner.0)
        .unwrap()
        .unwrap();
    for corrupt in [vec![0], vec![0; ROW_BYTES + 65]] {
        control
            .put_record("guild-original-latest-recovery", &owner.0, &corrupt)
            .unwrap();
        assert!(view.current_recovery_key(owner).is_err());
    }
    control
        .delete_record("guild-original-latest-recovery", &owner.0)
        .unwrap();
    assert!(view.current_recovery_key(owner).is_err());
    control
        .put_record("guild-original-latest-recovery", &owner.0, &pointer)
        .unwrap();
    let key = epoch_key(owner, 1);
    let epoch = control
        .get_record("guild-original-recovery", &key)
        .unwrap()
        .unwrap();
    control
        .delete_record("guild-original-recovery", &key)
        .unwrap();
    assert!(view.current_recovery_key(owner).is_err());
    control
        .put_record("guild-original-recovery", &key, &epoch)
        .unwrap();
    assert_eq!(
        view.current_recovery_key(owner).unwrap().as_ref(),
        history.state.current_recovery_key(owner)
    );
}

#[test]
fn durable_original_history_reopens_and_matches_all_original_event_effects() {
    for legacy in [false, true] {
        let mut history = History::new(legacy, 4);
        let owner = history.keys[0].node_id();
        let id = history.entry.retained.group.id;
        history.push(GuildEventKind::RotateWriterKey {
            owner,
            epoch: 2,
            public_key: history.keys[1].node_id().0,
        });
        let (envelope, _) =
            create_recovery_key_envelope(&history.keys[0], history.state.guild_id, 2).unwrap();
        history.push(GuildEventKind::RotateRecoveryKey { envelope });
        history.push(GuildEventKind::RevokeWriterKey { owner, epoch: 2 });
        history.push(GuildEventKind::RevokeRecoveryKey {
            subject: owner,
            epoch: 2,
        });
        history.push(GuildEventKind::RetireCodingGroup {
            group_id: id,
            retain_through_event: history.state.event_sequence + 1,
        });
        history.push(GuildEventKind::ForgetCodingGroup { group_id: id });
        let old_witness_hash =
            *blake3::hash(&canonical_bytes(&history.entry.transcript).unwrap()).as_bytes();
        let mut witness = history.entry.transcript.value.clone();
        witness.verified_at_unix_seconds -= 1;
        history.entry.transcript = mb_core::SignedRecord::sign(
            mb_core::CODING_TRANSCRIPT_DOMAIN,
            witness,
            history.keys.last().unwrap(),
        )
        .unwrap();
        assert_eq!(
            replay_coding_transcript(&history.entry.transcript).unwrap(),
            CodingReplayFinding::Verified
        );
        let new_witness_hash =
            *blake3::hash(&canonical_bytes(&history.entry.transcript).unwrap()).as_bytes();
        assert_ne!(old_witness_hash, new_witness_hash);
        history.add(legacy);
        history.push(GuildEventKind::RelabelMember {
            node_id: owner,
            failure_domain: "original-history-new-domain".to_owned(),
        });
        history.push(GuildEventKind::SetQuorum {
            policy: history.state.quorum,
        });
        history.push(GuildEventKind::RemoveMember { node_id: owner });
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("durable.db");
        let control = ControlStore::open(&path, &history.keys[0]).unwrap();
        let initial = GuildAuthoritySnapshot::from_genesis(&history.genesis).unwrap();
        let mut state = DynamicGuildState::new(
            initial.guild_id,
            initial.event_head,
            initial.quorum,
            initial.active_members().cloned().collect(),
        )
        .unwrap();
        CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
            .unwrap()
            .commit(&control)
            .unwrap();
        drop(control);
        for bytes in history.source.events.values() {
            let control = ControlStore::open(&path, &history.keys[0]).unwrap();
            let old = durable(&control);
            let event = QuorumGuildEvent::decode_bounded(bytes).unwrap();
            let mutation = old
                .prepare_advance(&control, &event, budget(), &mut history.source.clone())
                .unwrap();
            let work = old
                .represented_work()
                .checked_add(mutation.step_work())
                .unwrap();
            mutation.commit(&control).unwrap();
            assert!(
                old.view(&control, old.genesis_hash(), old.authority())
                    .is_err()
            );
            state.apply_event(&event).unwrap();
            let current = durable(&control);
            assert_eq!(current.represented_work(), work);
            assert_eq!(
                current.authority(),
                &GuildAuthoritySnapshot::from_state(&state).unwrap()
            );
            let view = current
                .view(&control, current.genesis_hash(), current.authority())
                .unwrap();
            assert_eq!(
                view.retained_group(id).unwrap().as_ref(),
                state
                    .coding_groups
                    .iter()
                    .find(|group| group.group.id == id)
            );
            for writer in &state.writer_keys {
                assert_eq!(
                    view.writer_key(writer.owner, writer.epoch)
                        .unwrap()
                        .as_ref(),
                    Some(writer)
                );
            }
            for recovery in &state.recovery_keys {
                assert_eq!(
                    view.recovery_key(recovery.envelope.subject, recovery.envelope.epoch)
                        .unwrap()
                        .as_ref(),
                    Some(recovery)
                );
            }
        }
        assert_eq!(state, history.state);
        let control = ControlStore::open(&path, &history.keys[0]).unwrap();
        let encoded = control
            .get_record("guild-original-group", &id)
            .unwrap()
            .unwrap();
        let current_group: Group = decode_canonical(&encoded[64..]).unwrap();
        assert_eq!(current_group.transcript_hash, new_witness_hash);
        // Forgotten incarnations and every original prefix remain indexed.
        assert!(
            control
                .get_record(
                    "guild-original-incarnation",
                    &historical::incarnation_key(id, 6)
                )
                .unwrap()
                .is_some()
        );
        assert!(
            control
                .get_record("guild-original-event", &state.event_sequence.to_be_bytes())
                .unwrap()
                .is_some()
        );
    }
}

#[test]
fn durable_original_history_has_exact_step_budgets_and_rejects_missing_original_witnesses() {
    let history = History::new(true, 4);
    let directory = tempfile::tempdir().unwrap();
    let control =
        ControlStore::open(directory.path().join("durable.db"), &history.keys[0]).unwrap();
    let initial =
        CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget()).unwrap();
    let exact = initial.step_work();
    assert!(
        CatalogDurableGuildHistory::prepare_genesis(
            &control,
            &history.genesis,
            Work {
                bytes: exact.bytes - 1,
                ..exact
            }
        )
        .is_err()
    );
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, exact)
        .unwrap()
        .commit(&control)
        .unwrap();
    for _ in 0..5 {
        advance_durable(&control, &history);
    }
    let old = durable(&control);
    let event = QuorumGuildEvent::decode_bounded(&history.source.events[&6]).unwrap();
    let mutation = old
        .prepare_advance(&control, &event, budget(), &mut history.source.clone())
        .unwrap();
    let exact = mutation.step_work();
    for low in [
        Work {
            bytes: exact.bytes - 1,
            ..exact
        },
        Work {
            records: exact.records - 1,
            ..exact
        },
    ] {
        assert!(
            old.prepare_advance(&control, &event, low, &mut history.source.clone())
                .is_err()
        );
        assert_eq!(durable(&control).authority(), old.authority());
    }
    for object in [
        CatalogGuildHistoryObject::Transcript(event.event.hash().unwrap()),
        CatalogGuildHistoryObject::LegacyBinding(event.event.hash().unwrap()),
    ] {
        let mut source = history.source.clone();
        source.objects.remove(&object);
        assert!(
            old.prepare_advance(&control, &event, budget(), &mut source)
                .is_err()
        );
        assert_eq!(durable(&control).authority(), old.authority());
    }
    let mut forged = event.clone();
    forged.signatures[0].signature[0] ^= 1;
    let mut source = history.source.clone();
    assert!(
        old.prepare_advance(&control, &forged, budget(), &mut source)
            .is_err()
    );
    assert!(
        source.reads.is_empty(),
        "invalid original certificate must precede witness I/O"
    );
    old.prepare_advance(&control, &event, exact, &mut history.source.clone())
        .unwrap()
        .commit(&control)
        .unwrap();
    assert!(
        mutation.commit(&control).is_err(),
        "a prepared original prefix cannot be reused"
    );
}

#[test]
fn durable_original_history_publication_faults_roll_back_and_retry() {
    for fault in 0..6 {
        let history = History::new(false, 4);
        let directory = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open(directory.path().join("durable.db"), &history.keys[0]).unwrap();
        CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
            .unwrap()
            .commit(&control)
            .unwrap();
        let old = durable(&control);
        let event = QuorumGuildEvent::decode_bounded(&history.source.events[&1]).unwrap();
        let mutation = old
            .prepare_advance(&control, &event, budget(), &mut history.source.clone())
            .unwrap();
        assert!(mutation.apply_in_transaction(&control).is_err());
        let sql = match fault {
            0 => {
                "CREATE TEMP TRIGGER original_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='guild-original-members' BEGIN SELECT RAISE(IGNORE); END"
            }
            1 => {
                "CREATE TEMP TRIGGER original_fault AFTER INSERT ON protocol_records WHEN NEW.kind='guild-original-event' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind=NEW.kind AND record_id=NEW.record_id; END"
            }
            2 => {
                "CREATE TEMP TRIGGER original_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN SELECT RAISE(IGNORE); END"
            }
            3 => {
                "CREATE TEMP TRIGGER original_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-original-members'; END"
            }
            4 => {
                "CREATE TEMP TRIGGER original_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind=NEW.kind AND record_id=NEW.record_id; END"
            }
            _ => {
                "CREATE TEMP TRIGGER original_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='guild-original-event' BEGIN SELECT RAISE(IGNORE); END"
            }
        };
        control.database_shell_statement(sql, false).unwrap();
        assert!(mutation.commit(&control).is_err(), "fault {fault}");
        assert_eq!(durable(&control).authority(), old.authority());
        assert!(
            control
                .get_record("guild-original-members", &2_u64.to_be_bytes())
                .unwrap()
                .is_none()
        );
        assert!(
            control
                .get_record("guild-original-event", &1_u64.to_be_bytes())
                .unwrap()
                .is_none()
        );
        control
            .database_shell_statement("DROP TRIGGER original_fault", false)
            .unwrap();
        mutation.commit(&control).unwrap();
        assert_eq!(durable(&control).authority().event_sequence, 1);
    }
}

#[test]
fn durable_original_history_point_rows_fail_closed_on_corruption_and_oversize() {
    let history = History::new(false, 4);
    let directory = tempfile::tempdir().unwrap();
    let control =
        ControlStore::open(directory.path().join("durable.db"), &history.keys[0]).unwrap();
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for _ in 0..6 {
        advance_durable(&control, &history);
    }
    let current = durable(&control);
    let id = history.entry.retained.group.id;
    let bytes = control
        .get_record("guild-original-group", &id)
        .unwrap()
        .unwrap();
    for index in [0, 32, bytes.len() - 1] {
        let mut corrupt = bytes.clone();
        corrupt[index] ^= 1;
        control
            .put_record("guild-original-group", &id, &corrupt)
            .unwrap();
        assert!(
            current
                .view(&control, current.genesis_hash(), current.authority())
                .unwrap()
                .retained_group(id)
                .is_err()
        );
    }
    control
        .put_record(
            "guild-original-group",
            &id,
            &vec![0; GUILD_EVENT_BYTES + 65],
        )
        .unwrap();
    assert!(
        current
            .view(&control, current.genesis_hash(), current.authority())
            .unwrap()
            .retained_group(id)
            .is_err()
    );
    control
        .put_record("guild-original-group", &id, &bytes)
        .unwrap();
    assert_eq!(
        current
            .view(&control, current.genesis_hash(), current.authority())
            .unwrap()
            .retained_group(id)
            .unwrap()
            .unwrap(),
        history.state.coding_groups[0]
    );
}

#[test]
fn durable_original_history_guards_selected_rows_and_rolls_back_forgotten_group_deletion() {
    let mut history = History::new(false, 4);
    let id = history.entry.retained.group.id;
    history.push(GuildEventKind::RetireCodingGroup {
        group_id: id,
        retain_through_event: 7,
    });
    history.push(GuildEventKind::ForgetCodingGroup { group_id: id });
    let directory = tempfile::tempdir().unwrap();
    let control =
        ControlStore::open(directory.path().join("durable.db"), &history.keys[0]).unwrap();
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for _ in 0..6 {
        advance_durable(&control, &history);
    }
    let current = durable(&control);
    let retire = QuorumGuildEvent::decode_bounded(&history.source.events[&7]).unwrap();
    let mutation = current
        .prepare_advance(&control, &retire, budget(), &mut history.source.clone())
        .unwrap();
    let old = control
        .get_record("guild-original-group", &id)
        .unwrap()
        .unwrap();
    control
        .put_record("guild-original-group", &id, &[0])
        .unwrap();
    assert!(
        mutation.commit(&control).is_err(),
        "a prepared transition must guard its original selected row"
    );
    assert_eq!(durable(&control).authority(), current.authority());
    control
        .put_record("guild-original-group", &id, &old)
        .unwrap();
    control.database_shell_statement("CREATE TEMP TRIGGER original_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='guild-original-group' BEGIN SELECT RAISE(IGNORE); END", false).unwrap();
    assert!(mutation.commit(&control).is_err());
    assert_eq!(
        control.get_record("guild-original-group", &id).unwrap(),
        Some(old)
    );
    control
        .database_shell_statement("DROP TRIGGER original_fault", false)
        .unwrap();
    mutation.commit(&control).unwrap();
    let current = durable(&control);
    let forget = QuorumGuildEvent::decode_bounded(&history.source.events[&8]).unwrap();
    let mutation = current
        .prepare_advance(&control, &forget, budget(), &mut history.source.clone())
        .unwrap();
    for sql in [
        "CREATE TEMP TRIGGER original_fault BEFORE DELETE ON protocol_records WHEN OLD.kind='guild-original-group' BEGIN SELECT RAISE(IGNORE); END".to_owned(),
        format!("CREATE TEMP TRIGGER original_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('guild-original-group',X'{}',X'00'); END", blake3::Hash::from_bytes(id).to_hex()),
    ] {
        control.database_shell_statement(&sql, false).unwrap();
        assert!(mutation.commit(&control).is_err());
        assert_eq!(durable(&control).authority(), current.authority());
        assert!(current.view(&control, current.genesis_hash(), current.authority()).unwrap().retained_group(id).unwrap().unwrap().retired_at_event.is_some());
        control.database_shell_statement("DROP TRIGGER original_fault", false).unwrap();
    }
    mutation.commit(&control).unwrap();
    assert!(
        durable(&control)
            .view(&control, current.genesis_hash(), mutation.authority())
            .unwrap()
            .retained_group(id)
            .unwrap()
            .is_none()
    );
    assert!(
        control
            .get_record(
                "guild-original-incarnation",
                &historical::incarnation_key(id, 6)
            )
            .unwrap()
            .is_some()
    );
}

fn budget() -> Work {
    Work {
        bytes: 1 << 30,
        page_occurrences: 100_000,
        records: 10_000_000,
    }
}

#[derive(Clone, Default)]
struct Source {
    events: BTreeMap<u64, Vec<u8>>,
    objects: BTreeMap<CatalogGuildHistoryObject, Vec<u8>>,
    lengths: BTreeMap<CatalogGuildHistoryObject, usize>,
    reads: Vec<CatalogGuildHistoryObject>,
    fail: Option<CatalogGuildHistoryObject>,
}
impl CatalogGuildHistorySource for Source {
    fn next_event(
        &mut self,
        after: Option<u64>,
    ) -> Result<Option<(u64, usize)>, CatalogStoreError> {
        use std::ops::Bound::{Excluded, Unbounded};
        let next = if let Some(after) = after {
            self.events.range((Excluded(after), Unbounded)).next()
        } else {
            self.events.first_key_value()
        };
        Ok(next.map(|(sequence, bytes)| {
            (
                *sequence,
                self.lengths
                    .get(&CatalogGuildHistoryObject::Event(*sequence))
                    .copied()
                    .unwrap_or(bytes.len()),
            )
        }))
    }
    fn length(
        &mut self,
        object: CatalogGuildHistoryObject,
    ) -> Result<Option<usize>, CatalogStoreError> {
        Ok(self
            .lengths
            .get(&object)
            .copied()
            .or_else(|| self.objects.get(&object).map(Vec::len)))
    }
    fn read(
        &mut self,
        object: CatalogGuildHistoryObject,
        _limit: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        self.reads.push(object);
        if self.fail == Some(object) {
            return Err(DatabaseError::NotReady.into());
        }
        Ok(match object {
            CatalogGuildHistoryObject::Event(sequence) => self.events.get(&sequence).cloned(),
            _ => self.objects.get(&object).cloned(),
        })
    }
}

struct History {
    keys: Vec<KeyMaterial>,
    genesis: QuorumGuildGenesis,
    state: DynamicGuildState,
    source: Source,
    entry: CatalogCodingEntry,
}
impl History {
    fn new(legacy: bool, epoch: u64) -> Self {
        let id = 701_u64;
        let keys = (0..8)
            .map(|index| {
                let mut seed = [index as u8 + 38; 32];
                seed[..8].copy_from_slice(&id.to_be_bytes());
                KeyMaterial::from_seed(&Seed::from_bytes(seed))
            })
            .collect::<Vec<_>>();
        let mut members = keys[..5]
            .iter()
            .enumerate()
            .map(|(index, key)| Member {
                node_id: key.node_id(),
                recovery_public_key: key.recovery_public_key(),
                failure_domain: format!("{id}:{index:012}"),
            })
            .collect::<Vec<_>>();
        members.sort_by_key(|member| member.node_id);
        let genesis = GuildGenesis {
            format_version: 1,
            guild_id: [7; 32],
            coordinator: keys[0].node_id(),
            members,
        };
        let mut signatures = keys[..5]
            .iter()
            .map(|key| genesis.member_signature(key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        let genesis = QuorumGuildGenesis {
            genesis,
            signatures,
        };
        let snapshot = GuildAuthoritySnapshot::from_genesis(&genesis).unwrap();
        let state = DynamicGuildState::new(
            snapshot.guild_id,
            snapshot.event_head,
            snapshot.quorum,
            snapshot.active_members().cloned().collect(),
        )
        .unwrap();
        let packing = super::super::packing_validation::tests::fixture(3, true);
        let entry = super::super::coding_coverage::tests::entry_at_epoch(
            &packing,
            [0, 1, 2],
            id,
            3,
            None,
            epoch,
        );
        let mut history = Self {
            keys,
            genesis,
            state,
            source: Source::default(),
            entry,
        };
        for index in 5..8 {
            history.push(GuildEventKind::AddMember {
                member: Member {
                    node_id: history.keys[index].node_id(),
                    recovery_public_key: history.keys[index].recovery_public_key(),
                    failure_domain: format!("{id}:{index:012}"),
                },
            });
        }
        history.push(GuildEventKind::RotateWriterKey {
            owner: history.keys[0].node_id(),
            epoch: 1,
            public_key: history.keys[0].node_id().0,
        });
        let (envelope, _) =
            create_recovery_key_envelope(&history.keys[0], history.state.guild_id, 1).unwrap();
        history.push(GuildEventKind::RotateRecoveryKey { envelope });
        history.add(legacy);
        history
    }
    fn signed(&self, kind: GuildEventKind) -> QuorumGuildEvent {
        let event = GuildEvent {
            format_version: if matches!(kind, GuildEventKind::AddCodingGroupBound { .. }) {
                2
            } else {
                1
            },
            guild_id: self.state.guild_id,
            sequence: self.state.event_sequence + 1,
            parent: self.state.event_head,
            kind,
        };
        let mut signatures = self
            .keys
            .iter()
            .filter(|key| {
                self.state
                    .active_members()
                    .any(|member| member.node_id == key.node_id())
            })
            .map(|key| sign_guild_event(&event, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        QuorumGuildEvent { event, signatures }
    }
    fn push(&mut self, kind: GuildEventKind) -> QuorumGuildEvent {
        let certified = self.signed(kind);
        self.state.apply_event(&certified).unwrap();
        self.source.events.insert(
            certified.event.sequence,
            canonical_bytes(&certified).unwrap(),
        );
        certified
    }
    fn add(&mut self, legacy: bool) {
        let bytes = canonical_bytes(&self.entry.transcript).unwrap();
        let transcript_hash = *blake3::hash(&bytes).as_bytes();
        let group = self.entry.retained.group.clone();
        let certified = self.push(if legacy {
            GuildEventKind::AddCodingGroup { group }
        } else {
            GuildEventKind::AddCodingGroupBound {
                group,
                transcript_hash,
            }
        });
        let hash = certified.event.hash().unwrap();
        self.source
            .objects
            .insert(CatalogGuildHistoryObject::Transcript(hash), bytes);
        if legacy {
            let statement =
                LegacyCodingAddStatement::for_event(&certified, transcript_hash).unwrap();
            let mut signatures = self
                .keys
                .iter()
                .map(|key| sign_legacy_coding_add_binding(&statement, key).unwrap())
                .collect::<Vec<_>>();
            signatures.sort_by_key(|signature| signature.signer);
            self.source.objects.insert(
                CatalogGuildHistoryObject::LegacyBinding(hash),
                canonical_bytes(&QuorumLegacyCodingAddBinding {
                    statement,
                    signatures,
                })
                .unwrap(),
            );
        }
    }
    fn trust(&self) -> PagedCheckpointTrust {
        PagedCheckpointTrust {
            guild_id: self.state.guild_id,
            genesis_hash: self.genesis.genesis.hash().unwrap(),
            event_sequence: self.state.event_sequence,
            event_head: self.state.event_head,
            authority: CheckpointAuthority {
                format_version: 1,
                membership_epoch: self.state.membership_epoch,
                quorum: self.state.quorum,
            },
            members: self.state.active_members().cloned().collect(),
            previous: None,
        }
    }
    fn build(&self) -> CatalogGuildHistoryIndex {
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &self.genesis,
            budget(),
            Work::default(),
            || Ok(self.trust()),
            &mut self.source.clone(),
        )
        .unwrap()
    }
}

#[test]
fn original_history_produces_fixed_coding_writer_and_recovery_facts() {
    for legacy in [false, true] {
        let history = History::new(legacy, 4);
        let index = history.build();
        let trust = history.trust();
        let view = index.view(|| Ok(trust.clone())).unwrap();
        let coding = view.coding_trust();
        assert_eq!((coding.retained_groups, coding.retired_groups), (1, 0));
        let retained = &history.state.coding_groups[0];
        let fact = view
            .coding_group(retained.group.id, &coding)
            .unwrap()
            .unwrap();
        assert_eq!(
            fact,
            CatalogCertifiedCodingGroup::from_retained(
                retained,
                *blake3::hash(&canonical_bytes(&history.entry.transcript).unwrap()).as_bytes(),
                CatalogCodingAuthorization::CurrentPlacement
            )
            .unwrap()
        );
        assert!(view.coding_group([99; 32], &coding).unwrap().is_none());
        for entry in &history.state.writer_keys {
            assert_eq!(
                view.writer_key(entry.owner, entry.epoch, &trust)
                    .unwrap()
                    .as_ref(),
                Some(entry)
            );
            assert_eq!(
                view.current_writer(entry.owner, &trust).unwrap(),
                Some(WriterFence {
                    owner: entry.owner,
                    epoch: entry.epoch,
                    public_key: entry.public_key
                })
            );
        }
        for entry in &history.state.recovery_keys {
            assert_eq!(
                view.recovery_key(entry.envelope.subject, entry.envelope.epoch, &trust)
                    .unwrap()
                    .as_ref(),
                Some(entry)
            );
        }
        let raw = index
            .store
            .get_record_bounded(FACTS, &retained.group.id, ROW_BYTES)
            .unwrap()
            .unwrap();
        assert!(raw.len() <= ROW_BYTES);
        let mut stale = trust.clone();
        stale.event_head = [99; 32];
        assert!(index.view(|| Ok(stale.clone())).is_err());
        assert!(
            view.current_writer(history.keys[0].node_id(), &stale)
                .is_err()
        );
        let mut stale_coding = coding.clone();
        stale_coding.retained_groups += 1;
        assert!(view.coding_group(retained.group.id, &stale_coding).is_err());
        assert!(
            index.represented_work().bytes
                > history
                    .source
                    .events
                    .values()
                    .map(|bytes| bytes.len() as u64)
                    .sum::<u64>()
        );
    }
}

#[test]
fn latest_revocation_and_removed_owners_never_fall_back_to_old_writer_authority() {
    let mut history = History::new(false, 4);
    let owner = history.keys[0].node_id();
    history.push(GuildEventKind::RotateWriterKey {
        owner,
        epoch: 2,
        public_key: history.keys[1].node_id().0,
    });
    history.push(GuildEventKind::RevokeWriterKey { owner, epoch: 2 });
    history.push(GuildEventKind::RevokeRecoveryKey {
        subject: owner,
        epoch: 1,
    });
    let index = history.build();
    let trust = history.trust();
    let view = index.view(|| Ok(trust.clone())).unwrap();
    assert!(view.current_writer(owner, &trust).unwrap().is_none());
    assert_eq!(
        view.writer_key(owner, 1, &trust)
            .unwrap()
            .unwrap()
            .revoked_at_event,
        None
    );
    assert_eq!(
        view.writer_key(owner, 2, &trust)
            .unwrap()
            .unwrap()
            .revoked_at_event,
        Some(8)
    );
    assert_eq!(
        view.recovery_key(owner, 1, &trust)
            .unwrap()
            .unwrap()
            .revoked_at_event,
        Some(9)
    );
    history.push(GuildEventKind::RemoveMember { node_id: owner });
    let index = history.build();
    let trust = history.trust();
    let view = index.view(|| Ok(trust.clone())).unwrap();
    assert!(view.current_writer(owner, &trust).unwrap().is_none());
    assert!(view.writer_key(owner, 1, &trust).unwrap().is_some());
    let coding = view.coding_trust();
    assert_eq!(
        view.coding_group(history.entry.retained.group.id, &coding)
            .unwrap()
            .unwrap()
            .authorization,
        CatalogCodingAuthorization::Retained
    );
}

#[test]
fn retained_lifecycle_and_readd_keep_exact_original_identity_and_event_witnesses() {
    let mut history = History::new(true, 4);
    let id = history.entry.retained.group.id;
    let original_added = history.state.event_sequence;
    let through = original_added + 1;
    history.push(GuildEventKind::RetireCodingGroup {
        group_id: id,
        retain_through_event: through,
    });
    let index = history.build();
    let trust = history.trust();
    let view = index.view(|| Ok(trust.clone())).unwrap();
    let coding = view.coding_trust();
    assert_eq!((coding.retained_groups, coding.retired_groups), (1, 1));
    let fact = view.coding_group(id, &coding).unwrap().unwrap();
    assert_eq!(fact.lifecycle.added_at_event, original_added);
    assert_eq!(fact.lifecycle.retired_at_event, Some(through));
    assert_eq!(fact.lifecycle.retain_through_event, Some(through));
    history.push(GuildEventKind::ForgetCodingGroup { group_id: id });
    let index = history.build();
    let trust = history.trust();
    let view = index.view(|| Ok(trust.clone())).unwrap();
    let coding = view.coding_trust();
    assert_eq!((coding.retained_groups, coding.retired_groups), (0, 0));
    assert!(view.coding_group(id, &coding).unwrap().is_none());
    history.add(false);
    let index = history.build();
    let trust = history.trust();
    let view = index.view(|| Ok(trust.clone())).unwrap();
    let coding = view.coding_trust();
    let fact = view.coding_group(id, &coding).unwrap().unwrap();
    assert_eq!(fact.lifecycle.added_at_event, 9);
    assert_eq!(fact.lifecycle.retired_at_event, None);
    assert_eq!(fact.lifecycle.group_id, id);
    assert_eq!(
        fact.transcript_hash,
        *blake3::hash(&canonical_bytes(&history.entry.transcript).unwrap()).as_bytes()
    );
    assert_eq!(history.source.objects.len(), 3); // Two original Add witnesses and one legacy binding.
}

#[test]
fn exact_event_eof_independent_tip_and_original_authorization_are_required() {
    let history = History::new(false, 4);
    let original = history.source.clone();
    let tip = history.trust();
    for mode in 0..7 {
        let mut source = original.clone();
        match mode {
            0 => {
                source.events.remove(&2);
            }
            1 => {
                source.events.insert(0, source.events[&1].clone());
            }
            2 => {
                source
                    .events
                    .insert(tip.event_sequence + 1, source.events[&1].clone());
            }
            3 => {
                source.events.remove(&tip.event_sequence);
            }
            4 => {
                source.events.get_mut(&tip.event_sequence).unwrap().push(0);
            }
            5 => {
                source.events.get_mut(&tip.event_sequence).unwrap()[4] ^= 1;
            }
            _ => source.fail = Some(CatalogGuildHistoryObject::Event(tip.event_sequence)),
        }
        assert!(
            CatalogGuildHistoryIndex::build(
                RecordScratchStore::new(8 << 20).unwrap(),
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(tip.clone()),
                &mut source
            )
            .is_err(),
            "mode {mode}"
        );
    }
    for mode in 0..5 {
        let mut changed = tip.clone();
        match mode {
            0 => changed.event_head = [99; 32],
            1 => changed.authority.membership_epoch += 1,
            2 => changed.members[0].failure_domain.push('x'),
            3 => changed.genesis_hash = [99; 32],
            _ => {
                changed.members.pop().unwrap();
            }
        }
        assert!(
            CatalogGuildHistoryIndex::build(
                RecordScratchStore::new(8 << 20).unwrap(),
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(changed.clone()),
                &mut original.clone()
            )
            .is_err()
        );
    }
    let mut reads = 0;
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &history.genesis,
            budget(),
            Work::default(),
            || {
                reads += 1;
                if reads == 1 {
                    Ok(tip.clone())
                } else {
                    Err(DatabaseError::NotReady.into())
                }
            },
            &mut original.clone()
        )
        .is_err()
    );
    assert_eq!(reads, 2);
    // A changed independent tip after marker insertion/readback must still
    // abort the disposable transaction and return no completed projection.
    let mut reads = 0;
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &history.genesis,
            budget(),
            Work::default(),
            || {
                reads += 1;
                let mut current = tip.clone();
                if reads == 3 {
                    current.event_head = [99; 32];
                }
                Ok(current)
            },
            &mut original.clone(),
        )
        .is_err()
    );
    assert_eq!(reads, 3);
    // All nested signatures and the RS witness are valid. Epoch 1 lacks the
    // original delegate/coordinators; epoch 99 never existed.
    for epoch in [1, 99] {
        let invalid = History::new(false, epoch);
        assert_eq!(
            replay_coding_transcript(&invalid.entry.transcript).unwrap(),
            CodingReplayFinding::Verified
        );
        assert!(
            CatalogGuildHistoryIndex::build(
                RecordScratchStore::new(8 << 20).unwrap(),
                &invalid.genesis,
                budget(),
                Work::default(),
                || Ok(invalid.trust()),
                &mut invalid.source.clone()
            )
            .is_err()
        );
    }
    history.build();
}

#[test]
fn original_witness_missing_changed_or_legacy_binding_gap_rejects() {
    for legacy in [false, true] {
        let history = History::new(legacy, 4);
        let tip = history.trust();
        let hash = history.state.event_head;
        for mode in 0..if legacy { 5 } else { 3 } {
            let mut source = history.source.clone();
            let object = CatalogGuildHistoryObject::Transcript(hash);
            match mode {
                0 => {
                    source.objects.remove(&object);
                }
                1 => {
                    source.objects.get_mut(&object).unwrap()[10] ^= 1;
                }
                2 => source.fail = Some(object),
                3 => {
                    source
                        .objects
                        .remove(&CatalogGuildHistoryObject::LegacyBinding(hash));
                }
                _ => {
                    let object = CatalogGuildHistoryObject::LegacyBinding(hash);
                    let mut binding =
                        QuorumLegacyCodingAddBinding::decode_bounded(&source.objects[&object])
                            .unwrap();
                    binding.signatures.pop();
                    source
                        .objects
                        .insert(object, canonical_bytes(&binding).unwrap());
                }
            }
            assert!(
                CatalogGuildHistoryIndex::build(
                    RecordScratchStore::new(8 << 20).unwrap(),
                    &history.genesis,
                    budget(),
                    Work::default(),
                    || Ok(tip.clone()),
                    &mut source
                )
                .is_err(),
                "legacy {legacy} mode {mode}"
            );
        }
        history.build();
    }
}

#[test]
fn a_valid_original_quorum_cannot_replace_indexed_state_transition_rules() {
    let history = History::new(false, 4);
    let owner = history.keys[0].node_id();
    let (envelope, _) =
        create_recovery_key_envelope(&history.keys[0], history.state.guild_id, 3).unwrap();
    for kind in [
        GuildEventKind::RotateWriterKey {
            owner,
            epoch: 3,
            public_key: owner.0,
        },
        GuildEventKind::RotateWriterKey {
            owner,
            epoch: 2,
            public_key: [0; 32],
        },
        GuildEventKind::RevokeWriterKey { owner, epoch: 99 },
        GuildEventKind::RotateRecoveryKey { envelope },
        GuildEventKind::RevokeRecoveryKey {
            subject: owner,
            epoch: 99,
        },
        GuildEventKind::RetireCodingGroup {
            group_id: [99; 32],
            retain_through_event: 100,
        },
        GuildEventKind::RetireCodingGroup {
            group_id: history.entry.retained.group.id,
            retain_through_event: 1,
        },
        GuildEventKind::ForgetCodingGroup {
            group_id: history.entry.retained.group.id,
        },
        GuildEventKind::AddCodingGroupBound {
            group: history.entry.retained.group.clone(),
            transcript_hash: [9; 32],
        },
    ] {
        let certified = history.signed(kind);
        history.state.verify_event(&certified).unwrap();
        let mut source = history.source.clone();
        source.events.insert(
            certified.event.sequence,
            canonical_bytes(&certified).unwrap(),
        );
        let mut trust = history.trust();
        trust.event_sequence = certified.event.sequence;
        trust.event_head = certified.event.hash().unwrap();
        assert!(
            CatalogGuildHistoryIndex::build(
                RecordScratchStore::new(8 << 20).unwrap(),
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(trust.clone()),
                &mut source
            )
            .is_err()
        );
    }
    let mut revoked = History::new(false, 4);
    revoked.push(GuildEventKind::RevokeWriterKey { owner, epoch: 1 });
    let certified = revoked.signed(GuildEventKind::RevokeWriterKey { owner, epoch: 1 });
    let mut trust = revoked.trust();
    trust.event_sequence = certified.event.sequence;
    trust.event_head = certified.event.hash().unwrap();
    revoked.source.events.insert(
        certified.event.sequence,
        canonical_bytes(&certified).unwrap(),
    );
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &revoked.genesis,
            budget(),
            Work::default(),
            || Ok(trust.clone()),
            &mut revoked.source
        )
        .is_err()
    );
    history.build();
}

#[test]
fn admission_precedes_payload_fetch_and_preserves_all_prior_work_dimensions() {
    let history = History::new(false, 4);
    let tip = history.trust();
    let prior = Work {
        bytes: 7000,
        page_occurrences: 7,
        records: 11,
    };
    let index = CatalogGuildHistoryIndex::build(
        RecordScratchStore::new(8 << 20).unwrap(),
        &history.genesis,
        budget(),
        prior,
        || Ok(tip.clone()),
        &mut history.source.clone(),
    )
    .unwrap();
    let exact = index.represented_work();
    assert_eq!(exact.page_occurrences, 7);
    CatalogGuildHistoryIndex::build(
        RecordScratchStore::new(8 << 20).unwrap(),
        &history.genesis,
        exact,
        prior,
        || Ok(tip.clone()),
        &mut history.source.clone(),
    )
    .unwrap();
    for dimension in 0..3 {
        let mut short = exact;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(
            CatalogGuildHistoryIndex::build(
                RecordScratchStore::new(8 << 20).unwrap(),
                &history.genesis,
                short,
                prior,
                || Ok(tip.clone()),
                &mut history.source.clone()
            )
            .is_err()
        );
    }
    for object in [
        CatalogGuildHistoryObject::Event(1),
        CatalogGuildHistoryObject::Transcript(tip.event_head),
    ] {
        let mut source = history.source.clone();
        source
            .lengths
            .insert(object, CATALOG_CODING_TRANSCRIPT_BYTES + 1);
        assert!(
            CatalogGuildHistoryIndex::build(
                RecordScratchStore::new(8 << 20).unwrap(),
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(tip.clone()),
                &mut source
            )
            .is_err()
        );
        assert!(!source.reads.contains(&object));
    }
    let mut source = history.source.clone();
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &history.genesis,
            Work::default(),
            Work::default(),
            || Ok(tip.clone()),
            &mut source
        )
        .is_err()
    );
    assert!(source.reads.is_empty());
    history.build();
}

#[test]
fn ignored_writes_orphans_missing_rows_and_real_storage_failure_never_complete() {
    let mut history = History::new(false, 4);
    let owner = history.keys[0].node_id();
    history.push(GuildEventKind::RotateWriterKey {
        owner,
        epoch: 2,
        public_key: owner.0,
    });
    for kind in KINDS {
        let store = RecordScratchStore::new(8 << 20).unwrap();
        store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_history BEFORE INSERT ON scratch.protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
        assert!(
            CatalogGuildHistoryIndex::build(
                store,
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(history.trust()),
                &mut history.source.clone()
            )
            .is_err(),
            "{kind}"
        );
        let store = RecordScratchStore::new(8 << 20).unwrap();
        store
            .put_record_if_absent(kind, b"orphan", b"orphan")
            .unwrap();
        assert!(
            CatalogGuildHistoryIndex::build(
                store,
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(history.trust()),
                &mut history.source.clone()
            )
            .is_err()
        );
    }
    {
        let kind = LATEST_WRITER;
        let store = RecordScratchStore::new(8 << 20).unwrap();
        store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_history_update BEFORE UPDATE ON scratch.protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
        assert!(
            CatalogGuildHistoryIndex::build(
                store,
                &history.genesis,
                budget(),
                Work::default(),
                || Ok(history.trust()),
                &mut history.source.clone()
            )
            .is_err()
        );
    }
    let index = history.build();
    let trust = history.trust();
    let marker = index
        .store
        .get_record_bounded(COMPLETE, b"root", MARKER_BYTES)
        .unwrap()
        .unwrap();
    index
        .store
        .delete_record_if_value(COMPLETE, b"root", &marker)
        .unwrap();
    assert!(index.view(|| Ok(trust.clone())).is_err());
    for epoch in 3..=512 {
        history.push(GuildEventKind::RotateWriterKey {
            owner,
            epoch,
            public_key: owner.0,
        });
    }
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(64 << 10).unwrap(),
            &history.genesis,
            budget(),
            Work::default(),
            || Ok(history.trust()),
            &mut history.source.clone()
        )
        .is_err()
    );
    let rebuilt = history.build();
    let trust = history.trust();
    let view = rebuilt.view(|| Ok(trust.clone())).unwrap();
    assert_eq!(
        view.current_writer(owner, &trust).unwrap().unwrap().epoch,
        512
    );
    assert_eq!(
        view.writer_key(owner, 1, &trust)
            .unwrap()
            .unwrap()
            .activated_at_event,
        4
    );
}

#[test]
fn actual_control_store_source_reads_metadata_before_original_bounded_records() {
    let history = History::new(true, 4);
    let directory = tempfile::tempdir().unwrap();
    let control =
        ControlStore::open(directory.path().join("control.db"), &history.keys[0]).unwrap();
    for (sequence, bytes) in &history.source.events {
        control
            .put_record("guild-event", &sequence.to_be_bytes(), bytes)
            .unwrap();
    }
    for (object, bytes) in &history.source.objects {
        let (kind, key) = location(*object);
        control.put_record(kind, &key, bytes).unwrap();
    }
    let mut source = &control;
    let trust = history.trust();
    let index = CatalogGuildHistoryIndex::build(
        RecordScratchStore::new(8 << 20).unwrap(),
        &history.genesis,
        budget(),
        Work::default(),
        || Ok(trust.clone()),
        &mut source,
    )
    .unwrap();
    assert_eq!(
        index
            .view(|| Ok(trust.clone()))
            .unwrap()
            .coding_trust()
            .retained_groups,
        1
    );
    control.put_record("guild-event", &[0; 9], &[0; 2]).unwrap();
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &history.genesis,
            budget(),
            Work::default(),
            || Ok(trust.clone()),
            &mut source
        )
        .is_err()
    );
    control.delete_record("guild-event", &[0; 9]).unwrap();
    control
        .put_record(
            "guild-event",
            &1_u64.to_be_bytes(),
            &vec![0; GUILD_EVENT_BYTES + 1],
        )
        .unwrap();
    assert_eq!(
        source
            .record_length("guild-event", &1_u64.to_be_bytes())
            .unwrap(),
        Some(GUILD_EVENT_BYTES + 1)
    );
    assert!(
        CatalogGuildHistoryIndex::build(
            RecordScratchStore::new(8 << 20).unwrap(),
            &history.genesis,
            budget(),
            Work::default(),
            || Ok(trust.clone()),
            &mut source
        )
        .is_err()
    );
}

#[test]
fn historical_prefixes_preserve_original_lifecycle_and_writer_incarnations() {
    let mut history = History::new(false, 4);
    let owner = history.keys[0].node_id();
    let group_id = history.entry.retained.group.id;
    history.push(GuildEventKind::RotateWriterKey {
        owner,
        epoch: 2,
        public_key: history.keys[1].node_id().0,
    });
    history.push(GuildEventKind::RevokeWriterKey { owner, epoch: 2 });
    let retired = history.state.event_sequence + 1;
    history.push(GuildEventKind::RetireCodingGroup {
        group_id,
        retain_through_event: retired,
    });
    history.push(GuildEventKind::ForgetCodingGroup { group_id });
    history.add(true);
    history.push(GuildEventKind::RelabelMember {
        node_id: owner,
        failure_domain: "changed-current-domain".into(),
    });
    let index = history.build();
    let current = history.trust();
    let view = index.view(|| Ok(current.clone())).unwrap();
    let first = GuildAuthoritySnapshot::from_genesis(&history.genesis).unwrap();
    let mut replay = DynamicGuildState::new(
        first.guild_id,
        first.event_head,
        first.quorum,
        first.active_members().cloned().collect(),
    )
    .unwrap();
    for sequence in 0..=current.event_sequence {
        if sequence != 0 {
            replay
                .apply_event(
                    &QuorumGuildEvent::decode_bounded(&history.source.events[&sequence]).unwrap(),
                )
                .unwrap();
        }
        let mut trust = current.clone();
        trust.event_sequence = replay.event_sequence;
        trust.event_head = replay.event_head;
        trust.authority.membership_epoch = replay.membership_epoch;
        trust.authority.quorum = replay.quorum;
        trust.members = replay.active_members().cloned().collect();
        let prefix = view
            .at(&trust, CatalogGuildHistoryView::snapshot_lookup_work())
            .unwrap();
        assert_eq!(
            prefix.coding_trust().retained_groups,
            replay.coding_groups.len() as u64
        );
        assert_eq!(
            prefix.coding_trust().retired_groups,
            replay
                .coding_groups
                .iter()
                .filter(|group| group.retired_at_event.is_some())
                .count() as u64
        );
        let expected = replay
            .coding_groups
            .iter()
            .find(|group| group.group.id == group_id)
            .map(|retained| {
                CatalogCertifiedCodingGroup::from_retained(
                    retained,
                    *blake3::hash(&canonical_bytes(&history.entry.transcript).unwrap()).as_bytes(),
                    CatalogCodingAuthorization::Retained,
                )
                .unwrap()
            });
        assert_eq!(
            prefix.coding_group(group_id).unwrap(),
            expected,
            "event {sequence}"
        );
        assert!(prefix.coding_group([0; 32]).unwrap().is_none());
        assert!(prefix.coding_group([255; 32]).unwrap().is_none());
        for epoch in 1..=3 {
            assert_eq!(
                prefix.writer_key(owner, epoch).unwrap().as_ref(),
                replay
                    .writer_keys
                    .iter()
                    .find(|entry| entry.owner == owner && entry.epoch == epoch),
                "writer epoch {epoch} at event {sequence}"
            );
        }
    }
    assert_eq!(index.manifest.incarnations, 2);
    let coding = view.coding_trust();
    assert_eq!(
        view.coding_group(group_id, &coding)
            .unwrap()
            .unwrap()
            .authorization,
        CatalogCodingAuthorization::Retained
    );
    assert_eq!(
        view.coding_group(group_id, &coding)
            .unwrap()
            .unwrap()
            .lifecycle
            .added_at_event,
        11
    );
}

#[test]
fn historical_snapshot_admission_and_exact_event_roster_checks_precede_authority() {
    let history = History::new(false, 4);
    let index = history.build();
    let current = history.trust();
    let view = index.view(|| Ok(current.clone())).unwrap();
    let work = CatalogGuildHistoryView::snapshot_lookup_work();
    for dimension in [0, 1] {
        let mut short = work;
        if dimension == 0 {
            short.bytes -= 1;
        } else {
            short.records -= 1;
        }
        assert!(view.at(&current, short).is_err());
    }
    for mode in 0..6 {
        let mut damaged = current.clone();
        match mode {
            0 => damaged.event_head = [99; 32],
            1 => damaged.authority.membership_epoch -= 1,
            2 => damaged.members[0].failure_domain.push('x'),
            3 => damaged.genesis_hash = [99; 32],
            4 => damaged.event_sequence += 1,
            _ => damaged.authority.quorum.rule = mb_core::QuorumRule::Majority,
        }
        assert!(view.at(&damaged, work).is_err(), "mode {mode}");
    }
    let event_key = current.event_sequence.to_be_bytes();
    let original = index
        .store
        .get_record_bounded(EVENTS, &event_key, ROW_BYTES)
        .unwrap()
        .unwrap();
    index
        .store
        .delete_record_if_value(EVENTS, &event_key, &original)
        .unwrap();
    assert!(view.at(&current, work).is_err());
    index
        .store
        .put_record_if_absent(EVENTS, &event_key, &original)
        .unwrap();
    let mut tip: historical::Tip = decode_canonical(&original).unwrap();
    tip.sequence -= 1;
    let damaged = canonical_bytes(&tip).unwrap();
    index
        .store
        .replace_record_if_value(EVENTS, &event_key, &original, &damaged)
        .unwrap();
    assert!(view.at(&current, work).is_err());
    index
        .store
        .replace_record_if_value(EVENTS, &event_key, &damaged, &original)
        .unwrap();
    let epoch_key = current.authority.membership_epoch.to_be_bytes();
    let roster = index
        .store
        .get_record_bounded(MEMBERS, &epoch_key, GUILD_AUTHORITY_SNAPSHOT_BYTES)
        .unwrap()
        .unwrap();
    index
        .store
        .delete_record_if_value(MEMBERS, &epoch_key, &roster)
        .unwrap();
    assert!(view.at(&current, work).is_err());
}

#[test]
fn historical_archive_updates_and_range_reads_fail_closed() {
    let mut history = History::new(false, 4);
    let id = history.entry.retained.group.id;
    let retired = history.state.event_sequence + 1;
    history.push(GuildEventKind::RetireCodingGroup {
        group_id: id,
        retain_through_event: retired,
    });
    history.push(GuildEventKind::ForgetCodingGroup { group_id: id });
    let store = RecordScratchStore::new(8 << 20).unwrap();
    store.database_shell_statement(&format!("CREATE TEMP TRIGGER ignore_archive_update BEFORE UPDATE ON scratch.protocol_records WHEN NEW.kind='{ARCHIVE}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
    assert!(
        CatalogGuildHistoryIndex::build(
            store,
            &history.genesis,
            budget(),
            Work::default(),
            || Ok(history.trust()),
            &mut history.source.clone()
        )
        .is_err()
    );
    let index = history.build();
    let current = history.trust();
    let view = index.view(|| Ok(current.clone())).unwrap();
    let prefix = view
        .at(&current, CatalogGuildHistoryView::snapshot_lookup_work())
        .unwrap();
    let row = index
        .store
        .next_record_bounded(ARCHIVE, None, 40, ROW_BYTES)
        .unwrap()
        .unwrap();
    index
        .store
        .replace_record_if_value(ARCHIVE, &row.0, &row.1, &vec![0; ROW_BYTES + 1])
        .unwrap();
    assert!(prefix.coding_group(id).is_err());
    let range = RecordScratchStore::new(1 << 20).unwrap();
    for key in [b"a1", b"a2", b"b1"] {
        range.put_record_if_absent("range", key, key).unwrap();
    }
    assert_eq!(
        range
            .record_at_or_before_bounded("range", b"a", b"a9", 2, 2)
            .unwrap(),
        Some((b"a2".to_vec(), b"a2".to_vec()))
    );
    assert!(
        range
            .record_at_or_before_bounded("range", b"c", b"c9", 2, 2)
            .unwrap()
            .is_none()
    );
    assert!(
        range
            .record_at_or_before_bounded("range", b"a", b"a9", 1, 2)
            .is_err()
    );
    assert!(
        range
            .record_at_or_before_bounded("range", b"a", b"a9", 2, 1)
            .is_err()
    );
    assert!(
        range
            .record_at_or_before_bounded("range", b"z", b"a", 2, 2)
            .is_err()
    );
}

fn real_checkpoint() -> (super::super::checkpoint_validation::tests::Fixture, History) {
    real_checkpoint_with_fixture(super::super::checkpoint_validation::tests::Fixture::new(
        true, false,
    ))
}

fn real_checkpoint_with_fixture(
    mut fixture: super::super::checkpoint_validation::tests::Fixture,
) -> (super::super::checkpoint_validation::tests::Fixture, History) {
    use super::super::coding_coverage::tests::entry_at_epoch_with_nonce;
    use mb_core::CatalogCheckpointAuthorityRecord as R;
    let (_, _, packing) = fixture.packing_inputs_with_byte_roots();
    let entries = (0..packing.sectors.len())
        .collect::<Vec<_>>()
        .chunks(3)
        .enumerate()
        .map(|(nonce, indices)| match *indices {
            [a, b, c] => {
                entry_at_epoch_with_nonce(&packing, [a, b, c], 701, 3, None, 7, nonce as u64)
            }
            [a, b] => entry_at_epoch_with_nonce(&packing, [a, b], 701, 3, None, 7, nonce as u64),
            [a] => entry_at_epoch_with_nonce(&packing, [a], 701, 3, None, 7, nonce as u64),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();
    let entry = entries[0].clone();
    let mut keys = (11..14)
        .map(|seed| KeyMaterial::from_seed(&Seed::from_bytes([seed; 32])))
        .collect::<Vec<_>>();
    keys.extend((0..8).map(|index| {
        let mut seed = [index as u8 + 38; 32];
        seed[..8].copy_from_slice(&701_u64.to_be_bytes());
        KeyMaterial::from_seed(&Seed::from_bytes(seed))
    }));
    let mut members = fixture.sources.certificate.checkpoint.members.clone();
    members.extend((0..2).map(|index| Member {
        node_id: keys[index + 3].node_id(),
        recovery_public_key: keys[index + 3].recovery_public_key(),
        failure_domain: format!("701:{index:012}"),
    }));
    members.sort_by_key(|member| member.node_id);
    let genesis = GuildGenesis {
        format_version: 1,
        guild_id: fixture.context.guild_id,
        coordinator: keys[0].node_id(),
        members,
    };
    let mut signatures = keys
        .iter()
        .filter(|key| {
            genesis
                .members
                .iter()
                .any(|member| member.node_id == key.node_id())
        })
        .map(|key| genesis.member_signature(key).unwrap())
        .collect::<Vec<_>>();
    signatures.sort_by_key(|signature| signature.signer);
    let genesis = QuorumGuildGenesis {
        genesis,
        signatures,
    };
    let initial = GuildAuthoritySnapshot::from_genesis(&genesis).unwrap();
    let state = DynamicGuildState::new(
        initial.guild_id,
        initial.event_head,
        initial.quorum,
        initial.active_members().cloned().collect(),
    )
    .unwrap();
    let mut history = History {
        keys,
        genesis,
        state,
        source: Source::default(),
        entry,
    };
    history.push(GuildEventKind::RotateWriterKey {
        owner: history.keys[0].node_id(),
        epoch: 1,
        public_key: fixture.sources.writer.verifying_key().to_bytes(),
    });
    for index in 2..8 {
        history.push(GuildEventKind::AddMember {
            member: Member {
                node_id: history.keys[index + 3].node_id(),
                recovery_public_key: history.keys[index + 3].recovery_public_key(),
                failure_domain: format!("701:{index:012}"),
            },
        });
    }
    history.add(false);
    let first = history.entry.clone();
    for entry in entries.into_iter().skip(1) {
        history.entry = entry;
        history.add(false);
    }
    history.entry = first;
    fixture.context.generation = 1;
    fixture.context.event_sequence = history.state.event_sequence;
    fixture.context.event_head = history.state.event_head;
    fixture.context.authority = history.trust().authority;
    fixture
        .records
        .retain(|record| !matches!(record, R::Member(_)));
    fixture
        .records
        .extend(history.state.active_members().cloned().map(R::Member));
    (fixture, history)
}

fn real_reader(history: &History, trust: &PagedCheckpointTrust) -> CatalogGuildHistoryIndex {
    CatalogGuildHistoryIndex::build(
        RecordScratchStore::new(16 << 20).unwrap(),
        &history.genesis,
        budget(),
        Work::default(),
        || Ok(trust.clone()),
        &mut history.source.clone(),
    )
    .unwrap()
}

fn real_body(
    fixture: &mut super::super::checkpoint_validation::tests::Fixture,
    history: &History,
    reader: &CatalogGuildHistoryIndex,
    trust: &PagedCheckpointTrust,
    concrete: bool,
) -> CatalogCheckpointCodingStateIndex {
    use mb_core::CatalogCheckpointAuthorityRecord as R;
    fixture.context.generation = trust.next_generation().unwrap();
    fixture.context.event_sequence = trust.event_sequence;
    fixture.context.event_head = trust.event_head;
    fixture.context.authority = trust.authority;
    fixture
        .records
        .retain(|record| !matches!(record, R::Member(_)));
    fixture
        .records
        .extend(trust.members.iter().cloned().map(R::Member));
    let mut original = history.entry.clone();
    original.retained = history
        .state
        .coding_groups
        .iter()
        .find(|group| group.group.id == original.retained.group.id)
        .unwrap()
        .clone();
    let (body, _) = fixture.joined_with_groups_and_members(
        budget(),
        CatalogCodingCoveragePolicy::Current,
        &trust.members,
        true,
        |_, _| vec![original],
    );
    if concrete {
        body.validate_certified_history_coding_state(reader, budget(), || Ok(trust.clone()))
            .unwrap()
    } else {
        let view = reader.view(|| Ok(trust.clone())).unwrap();
        body.validate_certified_coding_state(
            budget(),
            || Ok(view.coding_trust()),
            |id, trust| view.coding_group(id, trust),
        )
        .unwrap()
    }
}

fn real_certificate(
    transition: CatalogCheckpointTransitionIndex,
    history: &History,
) -> CatalogQuorumPagedCheckpointIndex {
    let trust = transition.trust().clone();
    let mut checkpoint = None;
    let mut signatures = Vec::new();
    for key in &history.keys {
        if trust
            .members
            .iter()
            .any(|member| member.node_id == key.node_id())
        {
            let (body, signature) = transition
                .sign_paged_checkpoint_header(key, || Ok(trust.clone()))
                .unwrap();
            checkpoint = Some(body);
            signatures.push(signature);
        }
    }
    signatures.sort_by_key(|signature| signature.signer);
    transition
        .bind_paged_checkpoint_header(
            mb_core::QuorumPagedCheckpoint {
                checkpoint: checkpoint.unwrap(),
                signatures,
            },
            || Ok(trust.clone()),
        )
        .unwrap()
}

fn readd_with_new_witness(history: &mut History) {
    let group_id = history.entry.retained.group.id;
    let retired = history.state.event_sequence + 1;
    history.push(GuildEventKind::RetireCodingGroup {
        group_id,
        retain_through_event: retired,
    });
    history.push(GuildEventKind::ForgetCodingGroup { group_id });
    let mut transcript = history.entry.transcript.value.clone();
    transcript.verified_at_unix_seconds -= 1;
    history.entry.transcript = mb_core::SignedRecord::sign(
        mb_core::CODING_TRANSCRIPT_DOMAIN,
        transcript,
        history.keys.last().unwrap(),
    )
    .unwrap();
    assert_eq!(
        replay_coding_transcript(&history.entry.transcript).unwrap(),
        CodingReplayFinding::Verified
    );
    history.add(false);
}

#[test]
fn real_history_certifies_original_public_body_and_paged_successor_after_readd() {
    let (mut fixture, mut history) = real_checkpoint();
    let initial = history.trust();
    let reader = real_reader(&history, &initial);
    let body = real_body(&mut fixture, &history, &reader, &initial, true);
    assert_eq!(body.history_work(), reader.represented_work());
    let transition = body
        .validate_certified_history_authority_transition(None, &reader, budget(), || {
            Ok(initial.clone())
        })
        .unwrap();
    assert!(transition.has_certified_history_transition());
    let previous = real_certificate(transition, &history);
    let old_group = previous
        .index()
        .index()
        .next_group_row(None)
        .unwrap()
        .unwrap();
    readd_with_new_witness(&mut history);
    let mut current = history.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: previous.certificate().checkpoint.generation,
        hash: previous.certificate().hash().unwrap(),
    });
    let reader = real_reader(&history, &current);
    let body = real_body(&mut fixture, &history, &reader, &current, true);
    let new_group = body.index().index().next_group_row(None).unwrap().unwrap();
    assert_eq!(
        old_group.group.range.group_id,
        new_group.group.range.group_id
    );
    assert_ne!(
        old_group.group.range.transcript_hash,
        new_group.group.range.transcript_hash
    );
    assert_eq!(old_group.group.added_at_event, 8);
    assert_eq!(new_group.group.added_at_event, 11);
    let transition = body
        .validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &reader,
            budget(),
            || Ok(current.clone()),
        )
        .unwrap();
    let work = transition.represented_work();
    assert!(transition.has_certified_history_transition());
    let successor = real_certificate(transition, &history);
    assert_eq!(
        successor.certificate().checkpoint.parent,
        Some(previous.certificate().hash().unwrap())
    );
    successor.recheck_header(|| Ok(current.clone())).unwrap();
    // A fixed-fact caller which has not already admitted replay pays exactly
    // the same total; an already admitted history ledger is not charged twice.
    let body = real_body(&mut fixture, &history, &reader, &current, false);
    assert_eq!(body.history_work(), Work::default());
    let transition = body
        .validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &reader,
            work,
            || Ok(current.clone()),
        )
        .unwrap();
    assert_eq!(transition.represented_work(), work);
}

#[test]
fn real_history_transition_admits_all_debt_and_rejects_missing_old_incarnations() {
    let (mut fixture, mut history) = real_checkpoint();
    let initial = history.trust();
    let reader = real_reader(&history, &initial);
    let body = real_body(&mut fixture, &history, &reader, &initial, true);
    let previous = real_certificate(
        body.validate_certified_history_authority_transition(None, &reader, budget(), || {
            Ok(initial.clone())
        })
        .unwrap(),
        &history,
    );
    readd_with_new_witness(&mut history);
    let mut current = history.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: 1,
        hash: previous.certificate().hash().unwrap(),
    });
    let reader = real_reader(&history, &current);
    let body = real_body(&mut fixture, &history, &reader, &current, true);
    let exact = body
        .validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &reader,
            budget(),
            || Ok(current.clone()),
        )
        .unwrap()
        .represented_work();
    let old = reader
        .store
        .next_record_bounded(ARCHIVE, None, 40, ROW_BYTES)
        .unwrap()
        .unwrap();
    reader
        .store
        .delete_record_if_value(ARCHIVE, &old.0, &old.1)
        .unwrap();
    for dimension in 0..3 {
        let body = real_body(&mut fixture, &history, &reader, &current, true);
        let mut short = exact;
        match dimension {
            0 => short.bytes -= 1,
            1 => short.page_occurrences -= 1,
            _ => short.records -= 1,
        }
        assert!(matches!(
            body.validate_certified_history_authority_transition(
                Some(CatalogCheckpointPrevious::Paged(&previous)),
                &reader,
                short,
                || Ok(current.clone())
            ),
            Err(CatalogStoreError::Page(CatalogError::Bounds))
        ));
    }
    let body = real_body(&mut fixture, &history, &reader, &current, true);
    assert!(
        body.validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &reader,
            exact,
            || Ok(current.clone())
        )
        .is_err()
    );
    let rebuilt = real_reader(&history, &current);
    let body = real_body(&mut fixture, &history, &rebuilt, &current, true);
    body.validate_certified_history_authority_transition(
        Some(CatalogCheckpointPrevious::Paged(&previous)),
        &rebuilt,
        exact,
        || Ok(current.clone()),
    )
    .unwrap();
    let body = real_body(&mut fixture, &history, &rebuilt, &current, true);
    let mut reads = 0;
    assert!(
        body.validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &rebuilt,
            budget(),
            || {
                reads += 1;
                let mut snapshot = current.clone();
                if reads == 3 {
                    snapshot.event_head = [99; 32];
                }
                Ok(snapshot)
            }
        )
        .is_err()
    );
    assert_eq!(reads, 3);
    previous.recheck_header(|| Ok(initial.clone())).unwrap();

    // Retained fences must also match original writer history, even when no
    // new revision needs a latest-writer lookup in the successor comparison.
    let row = rebuilt
        .store
        .next_record_bounded(WRITERS, None, 40, ROW_BYTES)
        .unwrap()
        .unwrap();
    let mut writer: WriterKeyEpoch = decode_canonical(&row.1).unwrap();
    writer.public_key = history.keys[1].node_id().0;
    rebuilt
        .store
        .replace_record_if_value(WRITERS, &row.0, &row.1, &canonical_bytes(&writer).unwrap())
        .unwrap();
    let body = real_body(&mut fixture, &history, &rebuilt, &current, true);
    assert!(matches!(
        body.validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &rebuilt,
            budget(),
            || Ok(current.clone())
        ),
        Err(CatalogStoreError::Model(ModelError::InvalidWriterFence))
    ));
}

#[test]
fn real_history_rejects_a_later_quorum_certified_fork_of_the_previous_event_tip() {
    let (mut fixture, history) = real_checkpoint();
    let initial = history.trust();
    let reader = real_reader(&history, &initial);
    let body = real_body(&mut fixture, &history, &reader, &initial, true);
    let previous = real_certificate(
        body.validate_certified_history_authority_transition(None, &reader, budget(), || {
            Ok(initial.clone())
        })
        .unwrap(),
        &history,
    );

    let (mut fixture, mut fork) = real_checkpoint();
    let genesis = GuildAuthoritySnapshot::from_genesis(&fork.genesis).unwrap();
    fork.state = DynamicGuildState::new(
        genesis.guild_id,
        genesis.event_head,
        genesis.quorum,
        genesis.active_members().cloned().collect(),
    )
    .unwrap();
    for bytes in fork.source.events.values().take(7) {
        fork.state
            .apply_event(&QuorumGuildEvent::decode_bounded(bytes).unwrap())
            .unwrap();
    }
    fork.source.events.retain(|sequence, _| *sequence <= 7);
    let mut transcript = fork.entry.transcript.value.clone();
    transcript.verified_at_unix_seconds -= 1;
    fork.entry.transcript = mb_core::SignedRecord::sign(
        mb_core::CODING_TRANSCRIPT_DOMAIN,
        transcript,
        fork.keys.last().unwrap(),
    )
    .unwrap();
    fork.add(false);
    fork.push(GuildEventKind::SetQuorum {
        policy: fork.state.quorum,
    });
    let mut current = fork.trust();
    current.previous = Some(mb_core::PagedCheckpointParent {
        generation: 1,
        hash: previous.certificate().hash().unwrap(),
    });
    assert_eq!(initial.genesis_hash, current.genesis_hash);
    assert_eq!(initial.members, current.members);
    assert!(initial.event_sequence < current.event_sequence);
    assert!(initial.authority.membership_epoch < current.authority.membership_epoch);
    let reader = real_reader(&fork, &current);
    let body = real_body(&mut fixture, &fork, &reader, &current, true);
    assert!(matches!(
        body.validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Paged(&previous)),
            &reader,
            budget(),
            || Ok(current.clone())
        ),
        Err(CatalogStoreError::Database(DatabaseError::Conflict))
    ));
    previous.recheck_header(|| Ok(initial.clone())).unwrap();
}

#[test]
fn real_history_migrates_an_empty_legacy_prefix_and_rejects_omitted_variable_history() {
    for sequence in [7, 8] {
        let (mut fixture, history) = real_checkpoint();
        let mut old = history.trust();
        old.event_sequence = sequence;
        old.event_head = QuorumGuildEvent::decode_bounded(&history.source.events[&sequence])
            .unwrap()
            .event
            .hash()
            .unwrap();
        let mut certificate = fixture.sources.certificate.clone();
        certificate.checkpoint.genesis_hash = old.genesis_hash;
        certificate.checkpoint.members = old.members.clone();
        certificate.checkpoint.authority = Some(old.authority);
        certificate.signatures.clear();
        for key in &history.keys {
            certificate.add_signature(key).unwrap();
        }
        certificate.verify().unwrap();
        assert!(certificate.checkpoint.coding_groups.is_empty());
        let mut current = history.trust();
        current.previous = Some(mb_core::PagedCheckpointParent {
            generation: 1,
            hash: certificate.hash().unwrap(),
        });
        let reader = real_reader(&history, &current);
        let body = real_body(&mut fixture, &history, &reader, &current, true);
        let transition = body.validate_certified_history_authority_transition(
            Some(CatalogCheckpointPrevious::Legacy {
                certificate: &certificate,
                trust: &old,
            }),
            &reader,
            budget(),
            || Ok(current.clone()),
        );
        if sequence == 7 {
            let transition = transition.unwrap();
            assert!(transition.has_certified_history_transition());
            let successor = real_certificate(transition, &history);
            assert_eq!(successor.certificate().checkpoint.generation, 2);
            assert_eq!(
                successor.certificate().checkpoint.parent,
                Some(certificate.hash().unwrap())
            );
        } else {
            assert!(matches!(
                transition,
                Err(CatalogStoreError::Database(DatabaseError::NotReady))
            ));
        }
    }
}

#[test]
fn durable_retained_group_stream_checks_complete_lifecycle_and_eof() {
    let mut history = History::new(false, 4);
    let id = history.entry.retained.group.id;
    history.push(GuildEventKind::RetireCodingGroup {
        group_id: id,
        retain_through_event: 7,
    });
    history.push(GuildEventKind::ForgetCodingGroup { group_id: id });
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("stream.db"), &history.keys[0]).unwrap();
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for sequence in 0..=8 {
        if sequence > 0 {
            advance_durable(&control, &history);
        }
        let current = durable(&control);
        let view = current
            .view(&control, current.genesis_hash(), current.authority())
            .unwrap();
        let mut found = Vec::new();
        view.for_each_retained_group::<CatalogStoreError>(|group| {
            found.push(group);
            Ok(())
        })
        .unwrap();
        assert_eq!(found.len(), usize::from((6..=7).contains(&sequence)));
        if sequence == 7 {
            assert_eq!(found[0].retired_at_event, Some(7));
        }
        if sequence == 6 {
            let row = control
                .get_record("guild-original-group", &id)
                .unwrap()
                .unwrap();
            for damage in [None, Some(vec![0]), Some(vec![0; GROUP_BYTES + 65])] {
                match damage {
                    Some(bytes) => control
                        .put_record("guild-original-group", &id, &bytes)
                        .unwrap(),
                    None => {
                        control.delete_record("guild-original-group", &id).unwrap();
                    }
                }
                assert!(
                    view.for_each_retained_group::<CatalogStoreError>(|_| Ok(()))
                        .is_err()
                );
                control
                    .put_record("guild-original-group", &id, &row)
                    .unwrap();
            }
            let tip = control
                .get_record("guild-original-tip-v1", b"primary")
                .unwrap()
                .unwrap();
            assert!(
                view.for_each_retained_group::<CatalogStoreError>(|_| {
                    control.put_record("guild-original-tip-v1", b"primary", &[0])?;
                    Ok(())
                })
                .is_err()
            );
            control
                .put_record("guild-original-tip-v1", b"primary", &tip)
                .unwrap();
        }
        // Even a caller needing no group must reject rows beyond certified EOF.
        control
            .put_record("guild-original-group", &[255; 33], &[1; 65])
            .unwrap();
        assert!(
            view.for_each_retained_group::<CatalogStoreError>(|_| Ok(()))
                .is_err()
        );
        control
            .delete_record("guild-original-group", &[255; 33])
            .unwrap();
    }
}

#[test]
fn durable_current_writer_never_revives_a_superseded_or_revoked_epoch() {
    let mut history = History::new(false, 4);
    let owner = history.keys[0].node_id();
    history.push(GuildEventKind::RotateWriterKey {
        owner,
        epoch: 2,
        public_key: history.keys[1].node_id().0,
    });
    history.push(GuildEventKind::RevokeWriterKey { owner, epoch: 2 });
    let directory = tempfile::tempdir().unwrap();
    let control = ControlStore::open(directory.path().join("writer.db"), &history.keys[0]).unwrap();
    CatalogDurableGuildHistory::prepare_genesis(&control, &history.genesis, budget())
        .unwrap()
        .commit(&control)
        .unwrap();
    for _ in 0..history.state.event_sequence {
        advance_durable(&control, &history);
    }
    let current = durable(&control);
    let view = current
        .view(&control, current.genesis_hash(), current.authority())
        .unwrap();
    assert!(view.current_writer_key(owner).unwrap().is_none());
    assert!(
        view.writer_key(owner, 1)
            .unwrap()
            .unwrap()
            .revoked_at_event
            .is_none()
    );
    let latest = control
        .get_record("guild-original-latest-writer", &owner.0)
        .unwrap()
        .unwrap();
    control
        .delete_record("guild-original-latest-writer", &owner.0)
        .unwrap();
    assert!(view.current_writer_key(owner).is_err());
    control
        .put_record("guild-original-latest-writer", &owner.0, &latest)
        .unwrap();
    control
        .delete_record("guild-original-writer", &epoch_key(owner, 2))
        .unwrap();
    assert!(view.current_writer_key(owner).is_err());
}
