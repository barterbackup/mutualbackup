use super::*;
use mb_core::{
    CatalogCodingEntry, CheckpointAuthority, DynamicGuildState, GuildEvent, GuildGenesis,
    KeyMaterial, LegacyCodingAddStatement, Member, Seed, canonical_bytes,
    create_recovery_key_envelope, sign_guild_event, sign_legacy_coding_add_binding,
};
use std::collections::BTreeMap;

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
