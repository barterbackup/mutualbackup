//! Normal durable consumers of the shared original-history validator.
use super::*;
use mb_core::CatalogCodingTraversalBudget as Work;
use mb_store::{
    CatalogDurableGuildHistory as History, CatalogGuildHistoryMutation as Mutation,
    CatalogGuildHistoryObject as Object, CatalogGuildHistorySource, CatalogStoreError,
};

// One event and its original evidence/point rows, using existing envelope
// bounds. This is a per-step admission bound, not an unlimited replay job.
fn budget() -> Work {
    Work {
        bytes: (3 * mb_core::CATALOG_CODING_TRANSCRIPT_BYTES
            + 32 * (GUILD_EVENT_BYTES + GUILD_AUTHORITY_SNAPSHOT_BYTES)
            + mb_core::LEGACY_CODING_ADD_BINDING_BYTES) as u64,
        records: 512,
        page_occurrences: 0,
    }
}

struct Source<'a> {
    control: &'a ControlStore,
    records: &'a [ControlRecord],
}
impl Source<'_> {
    fn location(object: Object) -> (&'static str, Vec<u8>) {
        match object {
            Object::Event(sequence) => ("guild-event", sequence.to_be_bytes().to_vec()),
            Object::Transcript(hash) => ("coding-event-transcript", hash.to_vec()),
            Object::LegacyBinding(hash) => ("coding-legacy-add-binding", hash.to_vec()),
        }
    }
    fn pending(&self, object: Object) -> Option<&[u8]> {
        let (name, key) = Self::location(object);
        self.records
            .iter()
            .find(|(kind, id, _)| kind == name && id == &key)
            .map(|(_, _, bytes)| bytes.as_slice())
    }
}
impl CatalogGuildHistorySource for Source<'_> {
    fn next_event(
        &mut self,
        after: Option<u64>,
    ) -> std::result::Result<Option<(u64, usize)>, CatalogStoreError> {
        let mut source = self.control;
        source.next_event(after)
    }
    fn length(&mut self, object: Object) -> std::result::Result<Option<usize>, CatalogStoreError> {
        if let Some(bytes) = self.pending(object) {
            return Ok(Some(bytes.len()));
        }
        let mut source = self.control;
        source.length(object)
    }
    fn read(
        &mut self,
        object: Object,
        cap: usize,
    ) -> std::result::Result<Option<Vec<u8>>, CatalogStoreError> {
        if let Some(bytes) = self.pending(object) {
            if bytes.len() > cap {
                return Err(mb_core::CatalogError::Bounds.into());
            }
            return Ok(Some(bytes.to_vec()));
        }
        let mut source = self.control;
        source.read(object, cap)
    }
}

pub(super) fn owns_kind(kind: &str) -> bool {
    History::owns_record_kind(kind)
}

pub(super) fn prepare(
    control: &ControlStore,
    installed: &InstalledGuild,
    next: &Record,
    before: Option<&Record>,
    records: &[ControlRecord],
) -> Result<Mutation> {
    let Some(history) = History::read(control)? else {
        // A recovered/older history starts at independently verified genesis.
        // Its bounded catch-up remains explicit; no later state invents rows.
        return Ok(History::prepare_genesis(
            control,
            &installed.certificate,
            budget(),
        )?);
    };
    let expected = before.unwrap_or(next);
    if history.genesis_hash() != next.genesis_hash
        || history.authority().guild_id != next.authority.guild_id
        || history.authority().event_sequence > expected.authority.event_sequence
    {
        anyhow::bail!("durable original history conflicts with accepted authority");
    }
    if history.authority().event_sequence < expected.authority.event_sequence {
        check_original_tip(
            control,
            &make(next.genesis_hash, history.authority().clone())?,
        )?;
        return Ok(history.prepare_guard());
    }
    if history.authority() != &expected.authority {
        anyhow::bail!("durable original history has another roster or event head");
    }
    if before.is_none() {
        return Ok(history.prepare_guard());
    }
    let mut source = Source { control, records };
    let event = source
        .read(
            Object::Event(next.authority.event_sequence),
            GUILD_EVENT_BYTES,
        )?
        .context("accepted original event is unavailable for indexed publication")?;
    let event = QuorumGuildEvent::decode_bounded(&event)?;
    let mutation = history.prepare_advance(control, &event, budget(), &mut source)?;
    if mutation.authority() != &next.authority {
        anyhow::bail!("indexed original event produced a different accepted roster or tip");
    }
    Ok(mutation)
}

pub(super) fn advance(control: &ControlStore) -> Result<bool> {
    let Some(current_bytes) = control.get_record_bounded(KIND, KEY, BYTES)? else {
        return Ok(false);
    };
    let current = decode(&current_bytes)?;
    let (installed, _) = check_genesis(control, &current)?;
    check_tail(control, &current)?;
    let history = History::read(control)?;
    let mut original = None;
    let mutation = match history {
        None => History::prepare_genesis(control, &installed.certificate, budget())?,
        Some(history) => {
            if history.genesis_hash() != current.genesis_hash
                || history.authority().guild_id != current.authority.guild_id
                || history.authority().event_sequence > current.authority.event_sequence
            {
                anyhow::bail!("durable original history belongs to another current authority");
            }
            if history.authority().event_sequence == current.authority.event_sequence {
                if history.authority() != &current.authority {
                    anyhow::bail!("durable original history has a conflicting current tip");
                }
                return Ok(false);
            }
            check_original_tip(
                control,
                &make(current.genesis_hash, history.authority().clone())?,
            )?;
            let sequence = history
                .authority()
                .event_sequence
                .checked_add(1)
                .context("original history sequence exhausted")?;
            let key = sequence.to_be_bytes();
            let bytes = control
                .get_record_bounded("guild-event", &key, GUILD_EVENT_BYTES)?
                .context("original history catch-up lacks an event")?;
            let event = QuorumGuildEvent::decode_bounded(&bytes)?;
            let mutation = history.prepare_advance(
                control,
                &event,
                budget(),
                &mut Source {
                    control,
                    records: &[],
                },
            )?;
            original = Some((key, bytes));
            mutation
        }
    };
    control.with_record_transaction(|| -> Result<()> {
        if control.get_record_bounded(KIND, KEY, BYTES)?.as_deref()
            != Some(current_bytes.as_slice())
        {
            anyhow::bail!("accepted authority changed during original history catch-up");
        }
        if let Some((key, bytes)) = &original
            && control
                .get_record_bounded("guild-event", key, GUILD_EVENT_BYTES)?
                .as_deref()
                != Some(bytes.as_slice())
        {
            anyhow::bail!("original event changed during indexed catch-up");
        }
        mutation.apply_in_transaction(control)?;
        check_tail(control, &current)?;
        mutation.verify_published(control)?;
        Ok(())
    })?;
    Ok(true)
}

// The legacy allocation is confined to an explicitly absent/incomplete index.
// Successful indexed batches never materialize the accumulated history vectors.
pub(crate) struct AuthorityReader<'a> {
    control: &'a ControlStore,
    original: Option<Vec<u8>>,
    compact: Option<Record>,
    current: GuildAuthoritySnapshot,
    history: Option<History>,
    legacy: Option<DynamicGuildState>,
    legacy_fence: Option<(usize, [u8; 32])>,
}

impl<'a> AuthorityReader<'a> {
    pub(super) fn open(control: &'a ControlStore) -> Result<Option<Self>> {
        Self::open_inner(control, false)
    }

    pub(super) fn open_complete(control: &'a ControlStore) -> Result<Self> {
        Self::open_inner(control, true)?.context("original guild history is unavailable")
    }

    fn open_inner(control: &'a ControlStore, require_indexed: bool) -> Result<Option<Self>> {
        with_read_snapshot(control, || Self::open_in_snapshot(control, require_indexed))
    }

    fn open_in_snapshot(control: &'a ControlStore, require_indexed: bool) -> Result<Option<Self>> {
        let original =
            control.get_record_bounded("guild-installed", KEY, GUILD_AUTHORITY_SNAPSHOT_BYTES)?;
        let compact = read_record(control)?;
        if require_indexed && compact.is_none() {
            anyhow::bail!("information upgrade requires indexed original guild authority");
        }
        let mut legacy = None;
        let mut legacy_fence = None;
        let current = match &compact {
            Some(record) => record.authority.clone(),
            None => {
                let Some((state, fence)) = read_legacy(control)? else {
                    return Ok(None);
                };
                let current = GuildAuthoritySnapshot::from_state(&state)?;
                legacy = Some(state);
                legacy_fence = Some(fence);
                current
            }
        };
        let mut history = History::read(control)?;
        if let Some(index) = &history {
            let genesis_hash = match &compact {
                Some(record) => record.genesis_hash,
                None => decode_installed_guild(
                    original
                        .as_deref()
                        .context("indexed authority has no original genesis")?,
                )?
                .certificate
                .hash()?,
            };
            if index.genesis_hash() != genesis_hash
                || index.authority().guild_id != current.guild_id
                || index.authority().event_sequence > current.event_sequence
            {
                anyhow::bail!("indexed authority belongs to another original history");
            }
            if index.authority().event_sequence == current.event_sequence {
                index.view(control, genesis_hash, &current)?;
            } else {
                check_original_tip(control, &make(genesis_hash, index.authority().clone())?)?;
                history = None;
            }
        }
        if history.is_none() && legacy.is_none() {
            if require_indexed {
                anyhow::bail!("information upgrade requires complete original-history indexing");
            }
            let (state, fence) =
                read_legacy(control)?.context("legacy guild state is unavailable")?;
            if GuildAuthoritySnapshot::from_state(&state)? != current {
                anyhow::bail!("legacy guild state differs from current authority");
            }
            legacy = Some(state);
            legacy_fence = Some(fence);
        }
        Ok(Some(Self {
            control,
            original,
            compact,
            current,
            history,
            legacy,
            legacy_fence,
        }))
    }

    pub(crate) fn snapshot(&self) -> &GuildAuthoritySnapshot {
        &self.current
    }

    pub(crate) fn validate_information_activation(
        &self,
        ready: &mb_store::ReadyVariableObject,
        transcript: &SignedRecord<CodingVerificationTranscript>,
        holder: NodeId,
    ) -> Result<()> {
        self.check()?;
        let history = self
            .history
            .as_ref()
            .context("original history is not indexed")?;
        history
            .view(self.control, history.genesis_hash(), &self.current)?
            .validate_historical_coding_plan(&transcript.value.plan)?;
        let group = &transcript.value.manifest.value.group;
        let Some(ShardRoleV2::Information(role)) =
            group.roles.get(usize::from(ready.object.shard_index))
        else {
            anyhow::bail!("missing activation receipt is not an information upload");
        };
        if !ready.staged_receipt.is_empty()
            || role.sector.virtual_zero
            || role.owner != holder
            || role.sector.id != ready.object.group_id
            || role.sector.commitment != ready.object.commitment
            || group.guild_id != ready.object.guild_id
            || ready.attempt_id != transcript.value.plan.value.attempt_id
            || ready.verification_hash
                != mb_core::canonical_hash_bounded(
                    transcript,
                    mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
                )?
            || replay_coding_transcript(transcript)? != CodingReplayFinding::Verified
            || merkle_commit(&ready.object.bytes)? != ready.object.commitment
        {
            anyhow::bail!("legacy information activation differs from its original witness");
        }
        self.check()
    }

    pub(crate) fn paged_checkpoint_trust(&self) -> Result<mb_core::PagedCheckpointTrust> {
        self.check()?;
        let genesis_hash = match &self.compact {
            Some(record) => record.genesis_hash,
            None => decode_installed_guild(
                self.original
                    .as_deref()
                    .context("paged checkpoint requires original genesis")?,
            )?
            .certificate
            .hash()?,
        };
        let trust = mb_core::PagedCheckpointTrust {
            guild_id: self.current.guild_id,
            genesis_hash,
            event_sequence: self.current.event_sequence,
            event_head: self.current.event_head,
            authority: mb_core::CheckpointAuthority {
                format_version: 1,
                membership_epoch: self.current.membership_epoch,
                quorum: self.current.quorum,
            },
            members: self.current.active_members().cloned().collect(),
            previous: self
                .control
                .checkpoint_head_identity(&self.current.guild_id)?
                .map(|(generation, hash)| mb_core::PagedCheckpointParent { generation, hash }),
        };
        trust.validate()?;
        self.check()?;
        Ok(trust)
    }

    pub(crate) fn current_recovery_key(
        &self,
        owner: NodeId,
    ) -> Result<Option<mb_core::RecoveryKeyEpoch>> {
        match &self.history {
            Some(history) => Ok(history
                .view(self.control, history.genesis_hash(), &self.current)?
                .current_recovery_key(owner)?),
            None => Ok(self
                .legacy
                .as_ref()
                .context("legacy authority is unavailable")?
                .current_recovery_key(owner)
                .cloned()),
        }
    }

    pub(crate) fn writer_key_for_retained_revision(
        &self,
        owner: NodeId,
        epoch: u64,
    ) -> Result<Option<[u8; 32]>> {
        match &self.history {
            Some(history) => Ok(history
                .view(self.control, history.genesis_hash(), &self.current)?
                .writer_key(owner, epoch)?
                .map(|entry| entry.public_key)),
            None => Ok(self
                .legacy
                .as_ref()
                .context("legacy authority is unavailable")?
                .writer_key_for_retained_revision(owner, epoch)),
        }
    }

    pub(crate) fn retained_group(
        &self,
        id: [u8; 32],
    ) -> Result<Option<mb_core::RetainedCodingGroup>> {
        match &self.history {
            Some(history) => Ok(history
                .view(self.control, history.genesis_hash(), &self.current)?
                .retained_group(id)?),
            None => Ok(self
                .legacy
                .as_ref()
                .context("legacy authority is unavailable")?
                .coding_groups
                .iter()
                .find(|group| group.group.id == id)
                .cloned()),
        }
    }

    pub(crate) fn for_each_retained_group(
        &self,
        mut visit: impl FnMut(mb_core::RetainedCodingGroup) -> Result<()>,
    ) -> Result<()> {
        self.check()?;
        match &self.history {
            Some(history) => history
                .view(self.control, history.genesis_hash(), &self.current)?
                .for_each_retained_group(&mut visit)?,
            None => {
                for group in &self
                    .legacy
                    .as_ref()
                    .context("legacy authority is unavailable")?
                    .coding_groups
                {
                    visit(group.clone())?;
                }
            }
        }
        self.check()
    }

    pub(crate) fn writer_epoch_is_current(&self, owner: NodeId, epoch: u64) -> Result<bool> {
        match &self.history {
            Some(history) => Ok(history
                .view(self.control, history.genesis_hash(), &self.current)?
                .current_writer_key(owner)?
                .is_some_and(|key| key.epoch == epoch)),
            None => Ok(self
                .legacy
                .as_ref()
                .context("legacy authority is unavailable")?
                .writer_epoch_is_current(owner, epoch)),
        }
    }

    pub(crate) fn validate_retained_coding_transcript(
        &self,
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> Result<()> {
        self.check()?;
        match &self.history {
            Some(history) => history
                .view(self.control, history.genesis_hash(), &self.current)?
                .validate_retained_coding_transcript(transcript)?,
            None => {
                let descriptor = &transcript.value.manifest.value.group;
                if self.current.guild_id != descriptor.guild_id
                    || self
                        .retained_group(descriptor.id)?
                        .is_none_or(|group| group.group != *descriptor)
                    || replay_coding_transcript(transcript)? != CodingReplayFinding::Verified
                {
                    anyhow::bail!("recovery transcript is absent from certified guild state");
                }
            }
        }
        self.check()
    }

    pub(crate) fn check(&self) -> Result<()> {
        with_read_snapshot(self.control, || self.check_in_snapshot())
    }

    fn check_in_snapshot(&self) -> Result<()> {
        if self.control.get_record_bounded(
            "guild-installed",
            KEY,
            GUILD_AUTHORITY_SNAPSHOT_BYTES,
        )? != self.original
        {
            anyhow::bail!("original guild genesis changed during lookup");
        }
        match &self.compact {
            Some(record) => {
                if self.control.get_record_bounded(KIND, KEY, BYTES)?
                    != Some(mb_core::canonical_bytes_bounded(record, BYTES)?)
                {
                    anyhow::bail!("guild authority changed during lookup");
                }
                check_tail(self.control, record)?;
            }
            None if self.control.record_length(KIND, KEY)?.is_some() => {
                anyhow::bail!("guild authority appeared during legacy lookup")
            }
            None => {}
        }
        if let Some(history) = &self.history {
            history.view(self.control, history.genesis_hash(), &self.current)?;
        }
        if let Some((length, hash)) = self.legacy_fence {
            let bytes = self
                .control
                .get_record_bounded("guild-dynamic-state", KEY, length)?
                .context("legacy guild state disappeared during lookup")?;
            if bytes.len() != length || *blake3::hash(&bytes).as_bytes() != hash {
                anyhow::bail!("legacy guild state changed during lookup");
            }
        }
        Ok(())
    }
}

type LegacyState = (DynamicGuildState, (usize, [u8; 32]));
fn read_legacy(control: &ControlStore) -> Result<Option<LegacyState>> {
    control
        .get_record("guild-dynamic-state", KEY)?
        .map(|bytes| {
            let state: DynamicGuildState = decode_canonical(&bytes)?;
            state.validate()?;
            Ok((state, (bytes.len(), *blake3::hash(&bytes).as_bytes())))
        })
        .transpose()
}

pub(super) fn retained_group(
    control: &ControlStore,
    guild: [u8; 32],
    id: [u8; 32],
) -> Result<mb_core::RetainedCodingGroup> {
    retained_group_if_available(control, guild, id)?.context("variable coding group is unavailable")
}

pub(super) fn retained_group_if_available(
    control: &ControlStore,
    guild: [u8; 32],
    id: [u8; 32],
) -> Result<Option<mb_core::RetainedCodingGroup>> {
    Ok(with_history(control, |authority| {
        if authority.snapshot().guild_id != guild {
            anyhow::bail!("variable coding group belongs to another guild");
        }
        authority.retained_group(id)
    })?
    .flatten())
}

#[cfg(test)]
mod paged_checkpoint_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::guild_authority::tests::{event, fixture, relabel};
    use crate::node::tests::test_coding_transcript;

    fn recovery(
        node: &mut Node,
        keys: &[KeyMaterial],
        subject: &KeyMaterial,
        epoch: u64,
    ) -> mb_core::RecoveryKeyEnvelope {
        let guild = node.dynamic_guild_state().unwrap().unwrap().guild_id;
        let (envelope, _) = mb_core::create_recovery_key_envelope(subject, guild, epoch).unwrap();
        let certified = event(
            node,
            keys,
            mb_core::GuildEventKind::RotateRecoveryKey {
                envelope: envelope.clone(),
            },
        );
        node.install_guild_event(certified).unwrap();
        envelope
    }

    #[test]
    fn indexed_key_readers_keep_retained_writers_and_never_revive_revoked_recovery_epochs() {
        let (_temp, _seed, mut node, keys) = fixture();
        let owner = keys[0].node_id();
        let writer = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner,
                epoch: 1,
                public_key: keys[1].node_id().0,
            },
        );
        node.install_guild_event(writer).unwrap();
        let revoke = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RevokeWriterKey { owner, epoch: 1 },
        );
        node.install_guild_event(revoke).unwrap();
        recovery(&mut node, &keys, &keys[0], 1);
        recovery(&mut node, &keys, &keys[0], 2);
        let revoke = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RevokeRecoveryKey {
                subject: owner,
                epoch: 2,
            },
        );
        node.install_guild_event(revoke).unwrap();
        let flat = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
            .unwrap();
        assert_eq!(
            node.retained_writer_public_key(owner, 1).unwrap(),
            Some(keys[1].node_id().0)
        );
        assert_eq!(node.retained_writer_public_key(owner, 99).unwrap(), None);
        assert!(
            with_history(&node.control, |reader| reader.current_recovery_key(owner))
                .unwrap()
                .unwrap()
                .is_none()
        );
        node.control
            .put_record("guild-dynamic-state", KEY, &flat)
            .unwrap();
        let envelope = recovery(&mut node, &keys, &keys[0], 3);
        let remove = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RemoveMember { node_id: owner },
        );
        node.install_guild_event(remove).unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            node.retained_writer_public_key(owner, 1).unwrap(),
            Some(keys[1].node_id().0)
        );
        let current = with_history(&node.control, |reader| reader.current_recovery_key(owner))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            current.envelope, envelope,
            "removed subjects retain the original historical-envelope semantics"
        );
    }

    #[test]
    fn indexed_key_readers_reject_damaged_completed_rows_without_flat_fallback() {
        let (_temp, _seed, mut node, keys) = fixture();
        let owner = keys[0].node_id();
        let writer = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner,
                epoch: 1,
                public_key: keys[1].node_id().0,
            },
        );
        node.install_guild_event(writer).unwrap();
        recovery(&mut node, &keys, &keys[0], 1);
        let key = [owner.0.as_slice(), &1_u64.to_be_bytes()].concat();
        for (kind, id, cap) in [
            ("guild-original-recovery", key.clone(), 6144 + 64),
            ("guild-original-latest-recovery", owner.0.to_vec(), 256 + 64),
            ("guild-original-writer", key.clone(), 256 + 64),
        ] {
            let old = node.control.get_record(kind, &id).unwrap().unwrap();
            for bad in [Some(vec![0]), Some(vec![0; cap + 1]), None] {
                match bad {
                    Some(bytes) => node.control.put_record(kind, &id, &bytes).unwrap(),
                    None => {
                        node.control.delete_record(kind, &id).unwrap();
                    }
                }
                let result = if kind == "guild-original-writer" {
                    node.retained_writer_public_key(owner, 1).map(|_| ())
                } else {
                    with_history(&node.control, |reader| reader.current_recovery_key(owner))
                        .map(|_| ())
                };
                assert!(result.is_err(), "damaged completed {kind}");
            }
            node.control.put_record(kind, &id, &old).unwrap();
        }
        assert!(
            node.dynamic_guild_state()
                .unwrap()
                .unwrap()
                .current_recovery_key(owner)
                .is_some()
        );
    }

    #[test]
    fn indexed_key_batches_recheck_genesis_tip_history_and_legacy_source_fences() {
        let (_temp, _seed, mut node, keys) = fixture();
        let owner = keys[0].node_id();
        recovery(&mut node, &keys, &keys[0], 1);
        for kind in ["guild-installed", KIND, "guild-original-tip-v1"] {
            let before = node.control.get_record(kind, KEY).unwrap().unwrap();
            assert!(
                with_history(&node.control, |reader| {
                    assert!(reader.current_recovery_key(owner)?.is_some());
                    node.control.put_record(kind, KEY, &[0])?;
                    Ok(())
                })
                .is_err(),
                "changed batch fence {kind}"
            );
            node.control.put_record(kind, KEY, &before).unwrap();
        }
        node.control
            .database_shell_statement(
                "DELETE FROM protocol_records WHERE kind LIKE 'guild-original-%'",
                false,
            )
            .unwrap();
        let before = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        assert!(
            with_history(&node.control, |reader| {
                assert!(reader.current_recovery_key(owner)?.is_some());
                node.control.put_record("guild-dynamic-state", KEY, &[0])?;
                Ok(())
            })
            .is_err()
        );
        node.control
            .put_record("guild-dynamic-state", KEY, &before)
            .unwrap();
        assert!(
            with_history(&node.control, |reader| reader.current_recovery_key(owner))
                .unwrap()
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn indexed_key_backup_admission_and_idle_registration_avoid_flat_history() {
        let directory = tempfile::tempdir().unwrap();
        let (_, certificate, peers) = crate::node::tests::recovery_guild_fixture();
        let keys = (120..125)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value; 32])))
            .collect::<Vec<_>>();
        let coordinator_seed = (120..125)
            .map(|value| Seed::from_bytes([value; 32]))
            .find(|seed| KeyMaterial::from_seed(seed).node_id() == certificate.genesis.coordinator)
            .unwrap();
        let mut node = Node::open(directory.path(), coordinator_seed).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        for key in &keys {
            recovery(&mut node, &keys, key, 1);
        }
        let state = node.dynamic_guild_state().unwrap().unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
            .unwrap();
        assert!(!node.needs_recovery_key_registration().unwrap());
        let descriptor = BackupDescriptor {
            format_version: 2,
            guild_id: state.guild_id,
            owner: keys[1].node_id(),
            protected_root_id: Uuid::from_bytes([81; 16]),
            revision_id: Uuid::from_bytes([82; 16]),
            total_pages: 1,
            object_hash: [83; 32],
        };
        node.enqueue_backup(descriptor.owner, descriptor.clone())
            .unwrap();
        assert!(
            node.enqueue_backup(keys[2].node_id(), descriptor.clone())
                .is_err()
        );
        assert_eq!(
            node.claim_backup_job().unwrap().unwrap().descriptor,
            descriptor
        );
        node.control
            .put_record(
                "guild-event-signature-lock",
                &(state.event_sequence + 1).to_be_bytes(),
                &vec![0; GUILD_EVENT_BYTES + 257],
            )
            .unwrap();
        assert!(node.needs_recovery_key_registration().is_err());
    }

    fn group(
        node: &Node,
        keys: &[KeyMaterial],
    ) -> (
        QuorumGuildEvent,
        SignedRecord<CodingVerificationTranscript>,
        Vec<Vec<u8>>,
    ) {
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let members = state.active_members().collect::<Vec<_>>();
        let remotes = members
            .iter()
            .filter(|member| member.node_id != node.keys.node_id())
            .collect::<Vec<_>>();
        let local = members
            .iter()
            .find(|member| member.node_id == node.keys.node_id())
            .unwrap();
        let profile = mb_core::CodingProfile::new(1, 1, 64);
        let shards = mb_core::encode(profile, vec![vec![91; 64]]).unwrap();
        let plan = CodingAttemptPlan {
            format_version: 3,
            attempt_id: [191; 16],
            checkpoint_hash: [192; 32],
            membership_epoch: state.membership_epoch,
            geometry: mb_core::CodingPlanGeometry {
                format_version: 1,
                guild_id: state.guild_id,
                profile,
                information: vec![mb_core::InformationRoleV2 {
                    owner: remotes[0].node_id,
                    failure_domain: remotes[0].failure_domain.clone(),
                    sector: mb_core::RangeSectorRef {
                        id: [193; 32],
                        commitment: merkle_commit(&shards[0]).unwrap(),
                        logical_len: 64,
                        virtual_zero: false,
                    },
                }],
                parity: vec![mb_core::ParityPlacementV2 {
                    holder: local.node_id,
                    failure_domain: local.failure_domain.clone(),
                    row: 0,
                }],
            },
            delegator: remotes[1].node_id,
            coding_coordinator: remotes[2].node_id,
            verification_coordinator: remotes[3].node_id,
            expires_at_unix_seconds: unix_seconds() + 600,
            information_roots: Some(vec![sector_root(&shards[0])]),
        };
        let delegator = keys
            .iter()
            .find(|key| key.node_id() == plan.delegator)
            .unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, delegator).unwrap();
        let transcript = test_coding_transcript(plan, &shards, keys);
        let event = GuildEvent {
            format_version: 2,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: transcript.value.manifest.value.group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&transcript).unwrap()).as_bytes(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|key| sign_guild_event(&event, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        (QuorumGuildEvent { event, signatures }, transcript, shards)
    }

    #[test]
    fn durable_history_serves_real_shards_after_reopen_without_flat_state() {
        let (temp, seed, mut node, keys) = fixture();
        let (add, transcript, shards) = group(&node, &keys);
        let descriptor = transcript.value.manifest.value.group.clone();
        let object = VariableParityObject {
            format_version: 2,
            guild_id: descriptor.guild_id,
            group_id: descriptor.id,
            shard_index: 1,
            commitment: merkle_commit(&shards[1]).unwrap(),
            bytes: shards[1].clone(),
        };
        node.stage_coding_parity(&transcript.value.plan, &transcript.value.manifest, &object)
            .unwrap();
        node.activate_coding_attempt(&transcript).unwrap();
        node.install_coding_group_event(add, transcript).unwrap();
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
            .unwrap();
        assert_eq!(
            node.variable_shard_for_guild(&descriptor.guild_id, &descriptor.id, 1)
                .unwrap(),
            shards[1]
        );
        let reader = node.reader_config().open().unwrap();
        assert_eq!(
            reader
                .variable_shard_for_guild(&descriptor.guild_id, &descriptor.id, 1)
                .unwrap(),
            shards[1]
        );
        assert!(
            node.variable_shard_for_guild(&[99; 32], &descriptor.id, 1)
                .is_err()
        );
        assert!(
            node.variable_shard_for_guild(&descriptor.guild_id, &descriptor.id, 0)
                .is_err()
        );
        assert!(node.dynamic_guild_state().is_err());
    }

    #[test]
    fn indexed_recovery_stages_and_activates_live_and_retired_shards_without_flat_state() {
        for retired in [false, true] {
            let (temp, seed, mut node, keys) = fixture();
            let (add, transcript, shards) = group(&node, &keys);
            let descriptor = transcript.value.manifest.value.group.clone();
            node.install_coding_group_event(add, transcript.clone())
                .unwrap();
            if retired {
                let sequence = node.dynamic_guild_state().unwrap().unwrap().event_sequence + 1;
                let retire = event(
                    &node,
                    &keys,
                    mb_core::GuildEventKind::RetireCodingGroup {
                        group_id: descriptor.id,
                        retain_through_event: sequence,
                    },
                );
                node.install_guild_event(retire).unwrap();
            }
            let checkpoint = transcript.value.plan.value.checkpoint_hash;
            node.control
                .put_record(
                    "recovery-attempt",
                    b"active",
                    &canonical_bytes(&RecoveryAttempt {
                        format_version: 1,
                        guild_id: descriptor.guild_id,
                        checkpoint_hash: checkpoint,
                        generation: 1,
                    })
                    .unwrap(),
                )
                .unwrap();
            drop(node);
            let mut node = Node::open(temp.path(), seed).unwrap();
            node.control
                .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
                .unwrap();
            assert!(node.dynamic_guild_state().is_err());
            assert_eq!(
                node.recovery_coding_transcript_for_group(
                    checkpoint,
                    descriptor.guild_id,
                    descriptor.id
                )
                .unwrap(),
                transcript
            );
            assert!(
                node.recovery_coding_transcript_for_group(
                    [99; 32],
                    descriptor.guild_id,
                    descriptor.id
                )
                .is_err()
            );
            assert!(
                node.recovery_coding_transcript_for_group(checkpoint, [99; 32], descriptor.id)
                    .is_err()
            );
            node.stage_recovered_variable_shard(&checkpoint, &transcript, 1, &shards[1])
                .unwrap();
            node.activate_recovered_coding_attempt(checkpoint, &transcript)
                .unwrap();
            assert_eq!(
                node.variable_shard_for_guild(&descriptor.guild_id, &descriptor.id, 1)
                    .unwrap(),
                shards[1]
            );
            let reader = node.reader_config().open().unwrap();
            assert_eq!(
                reader
                    .coding_transcript_for_group(descriptor.guild_id, descriptor.id)
                    .unwrap(),
                transcript
            );
            assert_eq!(
                reader
                    .variable_shard_for_guild(&descriptor.guild_id, &descriptor.id, 1)
                    .unwrap(),
                shards[1]
            );
        }
    }

    #[test]
    fn indexed_recovery_rejects_substituted_aliases_and_damaged_original_rows_before_staging() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (add, transcript, shards) = group(&node, &keys);
        node.install_coding_group_event(add, transcript.clone())
            .unwrap();
        let descriptor = &transcript.value.manifest.value.group;
        let checkpoint = transcript.value.plan.value.checkpoint_hash;
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        let mut changed = transcript.value.clone();
        changed.verified_at_unix_seconds += 1;
        let signer = keys
            .iter()
            .find(|key| key.node_id() == transcript.signer)
            .unwrap();
        let substituted =
            SignedRecord::sign(mb_core::CODING_TRANSCRIPT_DOMAIN, changed, signer).unwrap();
        assert_eq!(
            replay_coding_transcript(&substituted).unwrap(),
            CodingReplayFinding::Verified
        );
        assert_eq!(substituted.value.manifest.value.group, *descriptor);
        let original = canonical_bytes(&transcript).unwrap();
        for (kind, key) in [
            (
                "coding-transcript",
                transcript.value.plan.value.attempt_id.as_slice(),
            ),
            ("coding-group-transcript", descriptor.id.as_slice()),
        ] {
            node.control
                .put_record(kind, key, &canonical_bytes(&substituted).unwrap())
                .unwrap();
        }
        assert!(
            node.recovery_coding_transcript_for_group(
                checkpoint,
                descriptor.guild_id,
                descriptor.id
            )
            .is_err()
        );
        assert!(
            node.stage_recovered_variable_shard(&checkpoint, &substituted, 1, &shards[1])
                .is_err()
        );
        assert!(node.activate_coding_attempt(&substituted).is_err());
        assert!(
            !node
                .volumes
                .has_staged_attempt_object(
                    &node.control,
                    &transcript.value.plan.value.attempt_id,
                    &descriptor.id,
                    1
                )
                .unwrap()
        );
        for (kind, key) in [
            (
                "coding-transcript",
                transcript.value.plan.value.attempt_id.as_slice(),
            ),
            ("coding-group-transcript", descriptor.id.as_slice()),
        ] {
            node.control.put_record(kind, key, &original).unwrap();
        }
        for (kind, key, cap) in [
            (
                "guild-original-group",
                descriptor.id.as_slice(),
                mb_core::GUILD_EVENT_BYTES + 64,
            ),
            (
                "guild-original-tip-v1",
                KEY,
                GUILD_AUTHORITY_SNAPSHOT_BYTES + 256,
            ),
            (
                "coding-transcript",
                transcript.value.plan.value.attempt_id.as_slice(),
                mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
            ),
            (
                "coding-group-transcript",
                descriptor.id.as_slice(),
                mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
            ),
        ] {
            let before = node.control.get_record(kind, key).unwrap().unwrap();
            for bad in [None, Some(vec![0]), Some(vec![0; cap + 1])] {
                match bad {
                    Some(bytes) => node.control.put_record(kind, key, &bytes).unwrap(),
                    None => {
                        node.control.delete_record(kind, key).unwrap();
                    }
                }
                assert!(
                    node.recovery_coding_transcript_for_group(
                        checkpoint,
                        descriptor.guild_id,
                        descriptor.id
                    )
                    .is_err(),
                    "damaged {kind}"
                );
                assert!(
                    node.stage_recovered_variable_shard(&checkpoint, &transcript, 1, &shards[1])
                        .is_err(),
                    "damaged {kind}"
                );
                assert!(
                    !node
                        .volumes
                        .has_staged_attempt_object(
                            &node.control,
                            &transcript.value.plan.value.attempt_id,
                            &descriptor.id,
                            1
                        )
                        .unwrap()
                );
            }
            node.control.put_record(kind, key, &before).unwrap();
        }
        for kind in ["guild-installed", KIND, "guild-original-tip-v1"] {
            let before = node.control.get_record(kind, KEY).unwrap().unwrap();
            assert!(
                with_history(&node.control, |authority| {
                    authority.validate_retained_coding_transcript(&transcript)?;
                    node.control.put_record(kind, KEY, &[0])?;
                    Ok(())
                })
                .is_err(),
                "changed transcript batch fence {kind}"
            );
            node.control.put_record(kind, KEY, &before).unwrap();
        }
        assert_eq!(
            node.recovery_coding_transcript_for_group(
                checkpoint,
                descriptor.guild_id,
                descriptor.id
            )
            .unwrap(),
            transcript
        );
    }

    #[test]
    fn indexed_recovery_follows_retire_forget_and_new_add_without_changing_group_identity() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (add, transcript, shards) = group(&node, &keys);
        let original_event_hash = add.event.hash().unwrap();
        let original_sequence = add.event.sequence;
        node.install_coding_group_event(add, transcript.clone())
            .unwrap();
        let descriptor = transcript.value.manifest.value.group.clone();
        let checkpoint = transcript.value.plan.value.checkpoint_hash;
        let retire = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RetireCodingGroup {
                group_id: descriptor.id,
                retain_through_event: original_sequence + 1,
            },
        );
        node.install_guild_event(retire).unwrap();
        assert_eq!(
            node.recovery_coding_transcript_for_group(
                checkpoint,
                descriptor.guild_id,
                descriptor.id
            )
            .unwrap(),
            transcript
        );
        let forget = event(
            &node,
            &keys,
            mb_core::GuildEventKind::ForgetCodingGroup {
                group_id: descriptor.id,
            },
        );
        node.install_guild_event(forget).unwrap();
        assert!(
            node.recovery_coding_transcript_for_group(
                checkpoint,
                descriptor.guild_id,
                descriptor.id
            )
            .is_err()
        );
        // Historical evidence remains accessible; it does not permit staging.
        assert_eq!(
            node.coding_transcript_for_group(descriptor.guild_id, descriptor.id)
                .unwrap(),
            transcript
        );
        assert_eq!(
            node.coding_transcript_for_event(
                descriptor.guild_id,
                descriptor.id,
                original_sequence,
                original_event_hash
            )
            .unwrap(),
            transcript
        );

        let mut plan = transcript.value.plan.value.clone();
        plan.attempt_id[0] += 1;
        let delegator = keys
            .iter()
            .find(|key| key.node_id() == plan.delegator)
            .unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, plan, delegator).unwrap();
        let successor = test_coding_transcript(plan, &shards, &keys);
        assert_eq!(successor.value.manifest.value.group, descriptor);
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let add = GuildEvent {
            format_version: 2,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind: mb_core::GuildEventKind::AddCodingGroupBound {
                group: descriptor.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(&successor).unwrap()).as_bytes(),
            },
        };
        let mut signatures = keys
            .iter()
            .map(|key| sign_guild_event(&add, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        node.install_coding_group_event(
            QuorumGuildEvent {
                event: add,
                signatures,
            },
            successor.clone(),
        )
        .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            node.recovery_coding_transcript_for_group(
                checkpoint,
                descriptor.guild_id,
                descriptor.id
            )
            .unwrap(),
            successor
        );
        assert!(
            node.stage_recovered_variable_shard(&checkpoint, &transcript, 1, &shards[1])
                .is_err()
        );
        assert_eq!(
            node.coding_transcript_for_event(
                descriptor.guild_id,
                descriptor.id,
                original_sequence,
                original_event_hash
            )
            .unwrap(),
            transcript
        );
    }

    #[test]
    fn coding_event_fallback_uses_original_index_and_preserves_legacy_recovery_access() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (add, transcript, _) = group(&node, &keys);
        let event_sequence = add.event.sequence;
        let event_hash = add.event.hash().unwrap();
        let descriptor = transcript.value.manifest.value.group.clone();
        node.install_coding_group_event(add, transcript.clone())
            .unwrap();
        let flat = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        let event_witness = node
            .control
            .get_record("coding-event-transcript", &event_hash)
            .unwrap()
            .unwrap();
        node.control
            .delete_record("coding-event-transcript", &event_hash)
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            node.coding_transcript_for_event(
                descriptor.guild_id,
                descriptor.id,
                event_sequence,
                event_hash
            )
            .unwrap(),
            transcript
        );
        let reader = node.reader_config().open().unwrap();
        assert_eq!(
            reader
                .coding_transcript_for_event(
                    descriptor.guild_id,
                    descriptor.id,
                    event_sequence,
                    event_hash
                )
                .unwrap(),
            transcript
        );
        node.control
            .put_record(
                "coding-event-transcript",
                &event_hash,
                &vec![0; mb_core::CATALOG_CODING_TRANSCRIPT_BYTES + 1],
            )
            .unwrap();
        assert!(
            node.coding_transcript_for_event(
                descriptor.guild_id,
                descriptor.id,
                event_sequence,
                event_hash
            )
            .is_err()
        );
        assert!(
            reader
                .coding_transcript_for_event(
                    descriptor.guild_id,
                    descriptor.id,
                    event_sequence,
                    event_hash
                )
                .is_err()
        );
        drop(reader);
        node.control
            .put_record("coding-event-transcript", &event_hash, &event_witness)
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &flat)
            .unwrap();
        node.control
            .database_shell_statement(
                "DELETE FROM protocol_records WHERE kind LIKE 'guild-original-%'",
                false,
            )
            .unwrap();
        assert_eq!(
            node.recovery_coding_transcript_for_group(
                transcript.value.plan.value.checkpoint_hash,
                descriptor.guild_id,
                descriptor.id
            )
            .unwrap(),
            transcript
        );
        assert!(node.advance_guild_history_index().unwrap());
        assert_eq!(
            node.recovery_coding_transcript_for_group(
                transcript.value.plan.value.checkpoint_hash,
                descriptor.guild_id,
                descriptor.id
            )
            .unwrap(),
            transcript
        );
        assert!(node.advance_guild_history_index().unwrap());
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            node.recovery_coding_transcript_for_group(
                transcript.value.plan.value.checkpoint_hash,
                descriptor.guild_id,
                descriptor.id
            )
            .unwrap(),
            transcript
        );
    }

    #[test]
    fn durable_history_legacy_catch_up_requires_each_original_event_and_witness() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (add, transcript, _) = group(&node, &keys);
        let hash = add.event.hash().unwrap();
        let descriptor = transcript.value.manifest.value.group.clone();
        node.install_coding_group_event(add, transcript).unwrap();
        let relabel = relabel(&node, &keys);
        node.install_guild_event(relabel).unwrap();
        // Model a store predating this index; preserve all original records.
        node.control
            .database_shell_statement(
                "DELETE FROM protocol_records WHERE kind LIKE 'guild-original-%'",
                false,
            )
            .unwrap();
        assert_eq!(
            retained_group(&node.control, descriptor.guild_id, descriptor.id)
                .unwrap()
                .group,
            descriptor
        );
        assert!(node.advance_guild_history_index().unwrap());
        assert_eq!(
            History::read(&node.control)
                .unwrap()
                .unwrap()
                .authority()
                .event_sequence,
            0
        );
        let witness = node
            .control
            .get_record("coding-event-transcript", &hash)
            .unwrap()
            .unwrap();
        node.control
            .delete_record("coding-event-transcript", &hash)
            .unwrap();
        assert!(
            node.advance_guild_history_index().is_err(),
            "the group-key witness cannot replace missing original Add evidence"
        );
        assert_eq!(
            History::read(&node.control)
                .unwrap()
                .unwrap()
                .authority()
                .event_sequence,
            0
        );
        node.control
            .put_record("coding-event-transcript", &hash, &witness)
            .unwrap();
        assert!(node.advance_guild_history_index().unwrap());
        assert_eq!(
            History::read(&node.control)
                .unwrap()
                .unwrap()
                .authority()
                .event_sequence,
            1
        );
        assert!(node.advance_guild_history_index().unwrap());
        assert!(!node.advance_guild_history_index().unwrap());
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            retained_group(&node.control, descriptor.guild_id, descriptor.id)
                .unwrap()
                .group,
            descriptor
        );
    }

    #[test]
    fn durable_history_completed_corrupt_or_missing_rows_never_use_flat_fallback() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (add, transcript, _) = group(&node, &keys);
        let descriptor = transcript.value.manifest.value.group.clone();
        node.install_coding_group_event(add, transcript).unwrap();
        let bytes = node
            .control
            .get_record("guild-original-group", &descriptor.id)
            .unwrap()
            .unwrap();
        for bad in [vec![0], vec![0; GUILD_EVENT_BYTES + 65]] {
            node.control
                .put_record("guild-original-group", &descriptor.id, &bad)
                .unwrap();
            assert!(retained_group(&node.control, descriptor.guild_id, descriptor.id).is_err());
            assert!(
                node.dynamic_guild_state()
                    .unwrap()
                    .unwrap()
                    .coding_groups
                    .iter()
                    .any(|retained| retained.group == descriptor)
            );
        }
        node.control
            .delete_record("guild-original-group", &descriptor.id)
            .unwrap();
        assert!(retained_group(&node.control, descriptor.guild_id, descriptor.id).is_err());
        node.control
            .put_record("guild-original-group", &descriptor.id, &bytes)
            .unwrap();
        assert_eq!(
            retained_group(&node.control, descriptor.guild_id, descriptor.id)
                .unwrap()
                .group,
            descriptor
        );
    }

    #[test]
    fn durable_history_normal_publication_faults_preserve_original_and_all_authority_records() {
        for fault in 0..6 {
            let (_temp, _seed, mut node, keys) = fixture();
            let certified = event(
                &node,
                &keys,
                mb_core::GuildEventKind::RelabelMember {
                    node_id: node.keys.node_id(),
                    failure_domain: "history-fault-domain".to_owned(),
                },
            );
            let before = ["guild-dynamic-state", KIND, "guild-original-tip-v1"]
                .map(|kind| node.control.get_record(kind, KEY).unwrap());
            let partial = pending_guild_event_signatures_id(&certified.event);
            node.control
                .put_record("guild-event-partial-signatures", &partial, b"preserve")
                .unwrap();
            let sql = match fault {
                0 => {
                    "CREATE TEMP TRIGGER original_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='guild-original-members' BEGIN SELECT RAISE(IGNORE); END"
                }
                1 => {
                    "CREATE TEMP TRIGGER original_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN SELECT RAISE(IGNORE); END"
                }
                2 => {
                    "CREATE TEMP TRIGGER original_fault AFTER INSERT ON protocol_records WHEN NEW.kind='guild-original-event' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-dynamic-state'; END"
                }
                3 => {
                    "CREATE TEMP TRIGGER original_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='guild-authority-tip-v1' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-original-tip-v1'; END"
                }
                4 => {
                    "CREATE TEMP TRIGGER original_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='guild-authority-tip-v1' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-original-members'; END"
                }
                _ => {
                    "CREATE TEMP TRIGGER original_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('guild-event-partial-signatures', X'00', X'00'); UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-event'; END"
                }
            };
            node.control.database_shell_statement(sql, false).unwrap();
            assert!(
                node.install_guild_event(certified.clone()).is_err(),
                "fault {fault}"
            );
            assert_eq!(
                ["guild-dynamic-state", KIND, "guild-original-tip-v1"]
                    .map(|kind| node.control.get_record(kind, KEY).unwrap()),
                before
            );
            assert!(
                node.control
                    .get_record("guild-event", &1_u64.to_be_bytes())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                node.control
                    .get_record("guild-event-partial-signatures", &partial)
                    .unwrap()
                    .as_deref(),
                Some(b"preserve".as_slice())
            );
            node.control
                .database_shell_statement("DROP TRIGGER original_fault", false)
                .unwrap();
            node.install_guild_event(certified).unwrap();
            assert_eq!(
                History::read(&node.control)
                    .unwrap()
                    .unwrap()
                    .authority()
                    .event_sequence,
                1
            );
        }
    }
    fn bound_add(
        node: &Node,
        keys: &[KeyMaterial],
        transcript: &SignedRecord<CodingVerificationTranscript>,
    ) -> QuorumGuildEvent {
        let mut certified = event(
            node,
            keys,
            mb_core::GuildEventKind::AddCodingGroupBound {
                group: transcript.value.manifest.value.group.clone(),
                transcript_hash: *blake3::hash(&canonical_bytes(transcript).unwrap()).as_bytes(),
            },
        );
        certified.event.format_version = 2;
        for signature in &mut certified.signatures {
            let signer = keys
                .iter()
                .find(|key| key.node_id() == signature.signer)
                .unwrap();
            *signature = sign_guild_event(&certified.event, signer).unwrap();
        }
        certified
    }

    #[test]
    fn indexed_coverage_planning_survives_reopen_and_rejects_substituted_witnesses() {
        let (temp, seed, mut node, keys) = fixture();
        let (add, transcript, _) = group(&node, &keys);
        let group_id = transcript.value.manifest.value.group.id;
        let ShardRoleV2::Information(information) = &transcript.value.manifest.value.group.roles[0]
        else {
            unreachable!()
        };
        let descriptor = PackedSectorDescriptor {
            id: information.sector.id,
            sector_index: 0,
            flat_root: transcript.value.plan.value.information_root(0).unwrap(),
            commitment: information.sector.commitment.clone(),
            slots: Vec::new(),
        };
        node.install_coding_group_event(add, transcript.clone())
            .unwrap();
        let flat = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        drop(node);
        let mut node = Node::open(temp.path(), seed).unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
            .unwrap();
        assert!(node.dynamic_guild_state().is_err());
        assert!(
            node.uncovered_packed_sectors(std::slice::from_ref(&descriptor))
                .unwrap()
                .is_empty()
        );
        assert!(
            node.packed_sectors_for_group_replacement(std::slice::from_ref(&descriptor))
                .unwrap()
                .is_empty()
        );
        let mut different = descriptor.clone();
        different.flat_root = [66; 32];
        assert_eq!(
            node.uncovered_packed_sectors(std::slice::from_ref(&different))
                .unwrap(),
            vec![different]
        );
        let indexed = node
            .control
            .get_record("guild-original-group", &group_id)
            .unwrap()
            .unwrap();
        node.control
            .delete_record("guild-original-group", &group_id)
            .unwrap();
        assert!(
            node.uncovered_packed_sectors(&[]).is_err(),
            "EOF must be checked even with no requested sectors"
        );
        node.control
            .put_record("guild-original-group", &group_id, &indexed)
            .unwrap();
        let mut value = transcript.value.plan.value.clone();
        value.attempt_id = [88; 16];
        let delegator = keys
            .iter()
            .find(|key| key.node_id() == value.delegator)
            .unwrap();
        let plan = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, value, delegator).unwrap();
        let shards = mb_core::encode(plan.value.geometry.profile, vec![vec![91; 64]]).unwrap();
        let alternate = test_coding_transcript(plan, &shards, &keys);
        assert_eq!(
            alternate.value.manifest.value.group,
            transcript.value.manifest.value.group
        );
        node.control
            .put_record(
                "coding-group-transcript",
                &group_id,
                &canonical_bytes(&alternate).unwrap(),
            )
            .unwrap();
        assert!(
            node.uncovered_packed_sectors(std::slice::from_ref(&descriptor))
                .is_err()
        );
        node.control
            .put_record(
                "coding-group-transcript",
                &group_id,
                &vec![0; mb_core::CATALOG_CODING_TRANSCRIPT_BYTES + 1],
            )
            .unwrap();
        assert!(
            node.uncovered_packed_sectors(std::slice::from_ref(&descriptor))
                .is_err()
        );
        node.control
            .put_record(
                "coding-group-transcript",
                &group_id,
                &canonical_bytes(&transcript).unwrap(),
            )
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &flat)
            .unwrap();
        let sequence = node.dynamic_guild_state().unwrap().unwrap().event_sequence + 1;
        let retire = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RetireCodingGroup {
                group_id,
                retain_through_event: sequence,
            },
        );
        node.install_guild_event(retire).unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            node.uncovered_packed_sectors(std::slice::from_ref(&descriptor))
                .unwrap(),
            vec![descriptor]
        );
    }

    #[test]
    fn indexed_replacement_keeps_groups_with_expired_inputs_out_of_the_planning_view() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (_, first, _) = group(&node, &keys);
        let mut value = first.value.plan.value.clone();
        value.geometry.profile = mb_core::CodingProfile::new(2, 1, 64);
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let other = state
            .active_members()
            .find(|member| member.node_id == value.delegator)
            .unwrap();
        let shards =
            mb_core::encode(value.geometry.profile, vec![vec![91; 64], vec![92; 64]]).unwrap();
        value.geometry.information.push(mb_core::InformationRoleV2 {
            owner: other.node_id,
            failure_domain: other.failure_domain.clone(),
            sector: mb_core::RangeSectorRef {
                id: [194; 32],
                commitment: merkle_commit(&shards[1]).unwrap(),
                logical_len: 64,
                virtual_zero: false,
            },
        });
        value.information_roots =
            Some(shards[..2].iter().map(|shard| sector_root(shard)).collect());
        let signer = keys
            .iter()
            .find(|key| key.node_id() == value.delegator)
            .unwrap();
        let transcript = test_coding_transcript(
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, value, signer).unwrap(),
            &shards,
            &keys,
        );
        let certified = bound_add(&node, &keys, &transcript);
        node.install_coding_group_event(certified, transcript.clone())
            .unwrap();
        let descriptors = transcript
            .value
            .plan
            .value
            .geometry
            .information
            .iter()
            .enumerate()
            .map(|(index, role)| PackedSectorDescriptor {
                id: role.sector.id,
                sector_index: index as u32,
                flat_root: transcript.value.plan.value.information_root(index).unwrap(),
                commitment: role.sector.commitment.clone(),
                slots: Vec::new(),
            })
            .collect::<Vec<_>>();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert!(
            node.uncovered_packed_sectors(&descriptors[..1])
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            node.packed_sectors_for_group_replacement(&descriptors[..1])
                .unwrap(),
            descriptors[..1]
        );
        assert!(
            node.packed_sectors_for_group_replacement(&descriptors)
                .unwrap()
                .is_empty()
        );
        assert!(
            node.coding_transcript_for_group(
                state.guild_id,
                transcript.value.manifest.value.group.id
            )
            .is_ok(),
            "planning cannot retire actual custody"
        );
    }
    #[test]
    fn indexed_current_checkpoint_coverage_uses_original_writer_and_full_root_binding() {
        let (_temp, _seed, mut node, keys) = fixture();
        let (_, initial, _) = group(&node, &keys);
        let mut value = initial.value.plan.value.clone();
        let owner = value.geometry.information[0].owner;
        let writer = ed25519_dalek::SigningKey::from_bytes(&[224; 32]);
        let register = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            },
        );
        node.install_guild_event(register).unwrap();
        value.geometry.profile = mb_core::CodingProfile::new(1, 1, V1_SECTOR_SIZE as u32);
        let shards =
            mb_core::encode(value.geometry.profile, vec![vec![91; V1_SECTOR_SIZE]]).unwrap();
        value.geometry.information[0].sector.commitment = merkle_commit(&shards[0]).unwrap();
        value.information_roots = Some(vec![sector_root(&shards[0])]);
        let signer = keys
            .iter()
            .find(|key| key.node_id() == value.delegator)
            .unwrap();
        let transcript = test_coding_transcript(
            SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, value, signer).unwrap(),
            &shards,
            &keys,
        );
        let add = bound_add(&node, &keys, &transcript);
        node.install_coding_group_event(add, transcript.clone())
            .unwrap();
        let mut revision = UserRevision {
            format_version: 4,
            guild_id: transcript.value.plan.value.geometry.guild_id,
            protected_root_id: Uuid::from_bytes([225; 16]),
            cipher_profile: mb_core::V1_CIPHER_PROFILE,
            revision_id: Uuid::from_bytes([226; 16]),
            owner,
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors: vec![SectorRef {
                id: [193; 32],
                root: sector_root(&shards[0]),
                logical_len: 64,
            }],
            data_sectors: Vec::new(),
            sector_commitments: Some(vec![merkle_commit(&shards[0]).unwrap()]),
        };
        revision.sign_writer(&writer).unwrap();
        let owner_key = keys.iter().find(|key| key.node_id() == owner).unwrap();
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let checkpoint = GuildCheckpoint {
            format_version: 6,
            guild_id: state.guild_id,
            genesis_hash: node
                .installed_guild()
                .unwrap()
                .unwrap()
                .certificate
                .hash()
                .unwrap(),
            generation: 1,
            parent: None,
            members: state.active_members().cloned().collect(),
            writer_fences: vec![mb_core::WriterFence {
                owner,
                epoch: 1,
                public_key: writer.verifying_key().to_bytes(),
            }],
            revision_tombstones: Vec::new(),
            revisions: vec![SignedRecord::sign(USER_REVISION_DOMAIN, revision, owner_key).unwrap()],
            coding_groups: Vec::new(),
            authority: Some(mb_core::CheckpointAuthority {
                format_version: 1,
                membership_epoch: state.membership_epoch,
                quorum: state.quorum,
            }),
            packing_catalog: None,
        };
        checkpoint.validate().unwrap();
        let flat = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        node.validate_variable_checkpoint_coverage(&checkpoint, false)
            .unwrap();
        let mut wrong = checkpoint.clone();
        wrong.revisions[0].value.metadata_sectors[0].root = [99; 32];
        assert!(
            node.validate_variable_checkpoint_coverage(&wrong, false)
                .is_err()
        );
        let mut wrong = checkpoint.clone();
        wrong.revisions[0]
            .value
            .sector_commitments
            .as_mut()
            .unwrap()[0] = merkle_commit(&vec![92; V1_SECTOR_SIZE]).unwrap();
        assert!(
            node.validate_variable_checkpoint_coverage(&wrong, false)
                .is_err()
        );
        node.control
            .put_record("guild-dynamic-state", KEY, &flat)
            .unwrap();
        let rotate = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner,
                epoch: 2,
                public_key: keys[1].node_id().0,
            },
        );
        node.install_guild_event(rotate).unwrap();
        let revoke = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RevokeWriterKey { owner, epoch: 2 },
        );
        node.install_guild_event(revoke).unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &[0])
            .unwrap();
        assert_eq!(
            node.retained_writer_public_key(owner, 1).unwrap(),
            Some(writer.verifying_key().to_bytes())
        );
        assert!(
            node.validate_variable_checkpoint_coverage(&checkpoint, false)
                .is_err(),
            "an old retained writer cannot sign a new uncommitted head"
        );
    }
}
