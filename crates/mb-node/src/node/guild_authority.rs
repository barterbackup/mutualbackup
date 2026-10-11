//! Durable bounded projections of verified original guild authority.
//! Original records, current/historical rosters and original-history point
//! mutations share the accepted event/state transaction.
use super::*;
use mb_core::{GUILD_AUTHORITY_SNAPSHOT_BYTES, GUILD_EVENT_BYTES, GuildAuthoritySnapshot};

const KIND: &str = "guild-authority-tip-v1";
const KEY: &[u8] = b"primary";
const BYTES: usize = GUILD_AUTHORITY_SNAPSHOT_BYTES + 128;

#[cfg(test)]
thread_local! {
    static AFTER_COMPACT_READ: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

mod membership;
pub(super) mod original_history;

pub(super) fn advance_original_history(control: &ControlStore) -> Result<bool> {
    original_history::advance(control)
}
pub(super) fn retained_group(
    control: &ControlStore,
    guild: [u8; 32],
    group: [u8; 32],
) -> Result<mb_core::RetainedCodingGroup> {
    original_history::retained_group(control, guild, group)
}

pub(super) fn retained_group_if_available(
    control: &ControlStore,
    guild: [u8; 32],
    group: [u8; 32],
) -> Result<Option<mb_core::RetainedCodingGroup>> {
    original_history::retained_group_if_available(control, guild, group)
}

/// Freeze one independently checked current scope around a batch of bounded
/// key/group lookups. A successful result always includes the final fences.
pub(super) fn with_history<T>(
    control: &ControlStore,
    read: impl FnOnce(&original_history::AuthorityReader<'_>) -> Result<T>,
) -> Result<Option<T>> {
    let Some(authority) = original_history::AuthorityReader::open(control)? else {
        return Ok(None);
    };
    let result = read(&authority)?;
    authority.check()?;
    Ok(Some(result))
}

pub(super) fn frozen_original_history(
    control: &ControlStore,
) -> Result<original_history::AuthorityReader<'_>> {
    original_history::AuthorityReader::open_complete(control)
}
pub(super) fn read_membership_epoch(
    control: &ControlStore,
    epoch: u64,
) -> Result<Option<GuildAuthoritySnapshot>> {
    membership::read(control, epoch)
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct Record {
    format_version: u16,
    genesis_hash: [u8; 32],
    authority: GuildAuthoritySnapshot,
    checksum: [u8; 32],
}

fn make(genesis_hash: [u8; 32], authority: GuildAuthoritySnapshot) -> Result<Record> {
    Ok(Record {
        format_version: 1,
        genesis_hash,
        checksum: mb_core::canonical_hash_bounded(&(1_u16, genesis_hash, &authority), BYTES)?,
        authority,
    })
}

fn decode(bytes: &[u8]) -> Result<Record> {
    if bytes.is_empty() || bytes.len() > BYTES {
        anyhow::bail!("compact guild authority exceeds its bound");
    }
    let record: Record = decode_canonical(bytes)?;
    record.authority.validate()?;
    if record.format_version != 1
        || record.genesis_hash == [0; 32]
        || record.checksum
            != mb_core::canonical_hash_bounded(
                &(
                    record.format_version,
                    record.genesis_hash,
                    &record.authority,
                ),
                BYTES,
            )?
        || mb_core::canonical_bytes_bounded(&record, BYTES)? != bytes
    {
        anyhow::bail!("invalid compact guild authority");
    }
    Ok(record)
}

fn check_original_tip(control: &ControlStore, record: &Record) -> Result<()> {
    let snapshot = &record.authority;
    let after = snapshot.event_sequence.to_be_bytes();
    if snapshot.event_sequence == 0 {
        if snapshot.event_head != record.genesis_hash || snapshot.membership_epoch != 1 {
            anyhow::bail!("compact genesis authority has a different tip");
        }
    } else {
        let bytes = control
            .get_record_bounded("guild-event", &after, GUILD_EVENT_BYTES)?
            .context("compact guild authority lacks its original event")?;
        let event = QuorumGuildEvent::decode_bounded(&bytes)?;
        if event.event.guild_id != snapshot.guild_id
            || event.event.sequence != snapshot.event_sequence
            || event.event.hash()? != snapshot.event_head
        {
            anyhow::bail!("compact guild authority conflicts with original event history");
        }
    }
    Ok(())
}

fn check_tail(control: &ControlStore, record: &Record) -> Result<()> {
    let sequence = record.authority.event_sequence;
    let after = sequence.to_be_bytes();
    if control
        .next_record_metadata_bounded(
            "guild-event",
            (sequence != 0).then_some(after.as_slice()),
            8,
        )?
        .is_some()
    {
        anyhow::bail!("compact guild authority is behind original event history");
    }
    check_original_tip(control, record)
}

fn check_genesis(
    control: &ControlStore,
    record: &Record,
) -> Result<(InstalledGuild, GuildAuthoritySnapshot)> {
    let bytes = control
        .get_record_bounded("guild-installed", KEY, GUILD_AUTHORITY_SNAPSHOT_BYTES)?
        .context("compact guild authority has no installed genesis")?;
    let installed = decode_installed_guild(&bytes)?;
    let genesis = GuildAuthoritySnapshot::from_genesis(&installed.certificate)?;
    if record.authority.guild_id != genesis.guild_id
        || record.genesis_hash != genesis.event_head
        || record.authority.event_sequence == 0 && record.authority != genesis
    {
        anyhow::bail!("compact guild authority belongs to another genesis");
    }
    Ok((installed, genesis))
}

/// Fixed reads only. A missing projection permits the existing legacy path;
/// malformed/stale projections never fall back to a different authority.
pub(super) fn read(control: &ControlStore) -> Result<Option<GuildAuthoritySnapshot>> {
    Ok(read_record(control)?.map(|record| record.authority))
}

fn read_record(control: &ControlStore) -> Result<Option<Record>> {
    with_read_snapshot(control, || read_record_in_snapshot(control))
}

// Writable Node operations serialize their connection. Independent read-only
// connections need one local snapshot for related authority/history queries.
fn with_read_snapshot<T>(
    control: &ControlStore,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    if control.is_read_only()? {
        control.with_read_only_snapshot(operation)
    } else {
        operation()
    }
}

fn read_record_in_snapshot(control: &ControlStore) -> Result<Option<Record>> {
    let Some(bytes) = control.get_record_bounded(KIND, KEY, BYTES)? else {
        return Ok(None);
    };
    #[cfg(test)]
    AFTER_COMPACT_READ.with(|hook| {
        let operation = hook.borrow_mut().take();
        if let Some(operation) = operation {
            operation();
        }
    });
    let record = decode(&bytes)?;
    check_genesis(control, &record)?;
    check_tail(control, &record)?;
    if control.get_record_bounded(KIND, KEY, BYTES)?.as_deref() != Some(bytes.as_slice()) {
        anyhow::bail!("compact guild authority changed during lookup");
    }
    Ok(Some(record))
}

pub(super) fn read_or_legacy(control: &ControlStore) -> Result<Option<GuildAuthoritySnapshot>> {
    with_read_snapshot(control, || read_or_legacy_in_snapshot(control))
}

fn read_or_legacy_in_snapshot(control: &ControlStore) -> Result<Option<GuildAuthoritySnapshot>> {
    if let Some(snapshot) = read(control)? {
        return Ok(Some(snapshot));
    }
    // Compatibility until the next independently validated install/recovery
    // or event publishes the projection. Normal projected reads never touch
    // the potentially growing legacy state blob.
    control
        .get_record("guild-dynamic-state", KEY)?
        .map(|bytes| {
            let state: DynamicGuildState = decode_canonical(&bytes)?;
            state.validate()?;
            Ok(GuildAuthoritySnapshot::from_state(&state)?)
        })
        .transpose()
}

pub(super) fn coordinator(
    installed: &InstalledGuild,
    authority: &GuildAuthoritySnapshot,
) -> Result<NodeId> {
    if authority.guild_id != installed.certificate.genesis.guild_id {
        anyhow::bail!("dynamic membership belongs to another guild");
    }
    let original = installed.certificate.genesis.coordinator;
    authority
        .active_members()
        .map(|member| member.node_id)
        .find(|node_id| *node_id == original)
        .or_else(|| {
            authority
                .active_members()
                .next()
                .map(|member| member.node_id)
        })
        .context("dynamic guild has no active coordinator")
}

/// Private to the verified Node ingestion paths. A raw proposed roster is
/// never an input: callers first validate original genesis/events, complete
/// non-membership effects and, for coding Adds, their original evidence.
pub(super) fn publish(
    control: &ControlStore,
    installed: &InstalledGuild,
    state: &DynamicGuildState,
    before: Option<&GuildAuthoritySnapshot>,
    records: &[ControlRecord],
    deletions: &[(String, Vec<u8>)],
) -> Result<()> {
    publish_authority(
        control,
        installed,
        GuildAuthoritySnapshot::from_state(state)?,
        before,
        records,
        deletions,
        None,
    )
}

pub(super) fn publish_indexed_event(
    control: &ControlStore,
    installed: &InstalledGuild,
    history: &mb_store::CatalogDurableGuildHistory,
    event: &QuorumGuildEvent,
    records: &[ControlRecord],
    deletions: &[(String, Vec<u8>)],
) -> Result<()> {
    let mutation = original_history::prepare_event(control, history, event, records)?;
    let next = mutation.authority().clone();
    publish_authority(
        control,
        installed,
        next,
        Some(history.authority()),
        records,
        deletions,
        Some(mutation),
    )
}

fn publish_authority(
    control: &ControlStore,
    installed: &InstalledGuild,
    authority: GuildAuthoritySnapshot,
    before: Option<&GuildAuthoritySnapshot>,
    records: &[ControlRecord],
    deletions: &[(String, Vec<u8>)],
    prepared_history: Option<mb_store::CatalogGuildHistoryMutation>,
) -> Result<()> {
    let initial = GuildAuthoritySnapshot::from_genesis(&installed.certificate)?;
    let next = make(initial.event_head, authority)?;
    if next.authority.guild_id != initial.guild_id
        || next.authority.event_sequence == 0 && next.authority != initial
    {
        anyhow::bail!("accepted guild state belongs to another genesis");
    }
    let encoded = mb_core::canonical_bytes_bounded(&next, BYTES)?;
    let expected = control.get_record_bounded(KIND, KEY, BYTES)?;
    if let Some(bytes) = &expected {
        let previous = decode(bytes)?;
        if previous.genesis_hash != next.genesis_hash
            || previous.authority != *before.unwrap_or(&next.authority)
        {
            anyhow::bail!("accepted event conflicts with compact guild authority");
        }
    }
    let before = before
        .map(|authority| make(next.genesis_hash, authority.clone()))
        .transpose()?;
    let membership = membership::prepare(
        control,
        installed,
        &initial,
        &next,
        before.as_ref(),
        records,
    )?;
    let original_history = match prepared_history {
        Some(mutation) => mutation,
        None => original_history::prepare(control, installed, &next, before.as_ref(), records)?,
    };
    control.with_record_transaction(|| -> Result<()> {
        if control.get_record_bounded(KIND, KEY, BYTES)? != expected {
            anyhow::bail!("compact guild authority changed before publication");
        }
        if let Some(before) = &before {
            check_genesis(control, before)?;
            check_tail(control, before)?;
        }
        for (kind, id, bytes) in records {
            if kind == KIND || membership::owns_kind(kind) || original_history::owns_kind(kind) {
                anyhow::bail!("accepted record batch cannot substitute compact authority");
            }
            control.put_record(kind, id, bytes)?;
        }
        for (kind, id) in deletions {
            if kind == KIND || membership::owns_kind(kind) || original_history::owns_kind(kind) {
                anyhow::bail!("accepted record batch cannot delete compact authority");
            }
            let existed = control.record_length(kind, id)?.is_some();
            if control.delete_record(kind, id)? != existed
                || control.record_length(kind, id)?.is_some()
            {
                anyhow::bail!("accepted guild record deletion did not persist");
            }
        }
        membership.publish(control)?;
        original_history.apply_in_transaction(control)?;
        match &expected {
            Some(old) => control.replace_record_if_value(KIND, KEY, old, &encoded)?,
            None => {
                if !control.put_record_if_absent(KIND, KEY, &encoded)? {
                    anyhow::bail!("compact guild authority publication raced another writer");
                }
            }
        }
        if control.get_record_bounded(KIND, KEY, BYTES)?.as_deref() != Some(encoded.as_slice()) {
            anyhow::bail!("compact guild authority write did not persist exact bytes");
        }
        // Check accepted records after every projection mutation. A later
        // trigger/write must not invalidate an earlier successful readback.
        check_genesis(control, &next)?;
        check_tail(control, &next)?;
        for (kind, id, bytes) in records {
            if control
                .get_record_bounded(kind, id, bytes.len())?
                .as_deref()
                != Some(bytes)
            {
                anyhow::bail!("accepted guild record write did not persist exact bytes");
            }
        }
        for (kind, id) in deletions {
            if control.record_length(kind, id)?.is_some() {
                anyhow::bail!("accepted guild record deletion changed during publication");
            }
        }
        membership.check(control)?;
        original_history.verify_published(control)?;
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::super::tests::recovery_guild_fixture;
    use super::*;

    pub(super) fn fixture() -> (tempfile::TempDir, Seed, Node, Vec<KeyMaterial>) {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path(), seed.clone()).unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        let keys = (120..125)
            .map(|value| KeyMaterial::from_seed(&Seed::from_bytes([value; 32])))
            .collect();
        (temp, seed, node, keys)
    }

    pub(super) fn event(
        node: &Node,
        keys: &[KeyMaterial],
        kind: mb_core::GuildEventKind,
    ) -> QuorumGuildEvent {
        let state = node.dynamic_guild_state().unwrap().unwrap();
        let event = GuildEvent {
            format_version: 1,
            guild_id: state.guild_id,
            sequence: state.event_sequence + 1,
            parent: state.event_head,
            kind,
        };
        let mut signatures = keys
            .iter()
            .filter(|key| {
                state
                    .active_members()
                    .any(|member| member.node_id == key.node_id())
            })
            .map(|key| sign_guild_event(&event, key).unwrap())
            .collect::<Vec<_>>();
        signatures.sort_by_key(|signature| signature.signer);
        QuorumGuildEvent { event, signatures }
    }

    pub(super) fn relabel(node: &Node, keys: &[KeyMaterial]) -> QuorumGuildEvent {
        event(
            node,
            keys,
            mb_core::GuildEventKind::RelabelMember {
                node_id: node.keys.node_id(),
                failure_domain: "compact-new-domain".to_owned(),
            },
        )
    }

    fn publication_during_compact_read() -> (
        tempfile::TempDir,
        ControlStore,
        GuildAuthoritySnapshot,
        GuildAuthoritySnapshot,
    ) {
        let (temp, _seed, node, keys) = fixture();
        let installed = node.installed_guild().unwrap().unwrap();
        let mut next = node.dynamic_guild_state().unwrap().unwrap();
        let before = GuildAuthoritySnapshot::from_state(&next).unwrap();
        let certified = relabel(&node, &keys);
        next.apply_event(&certified).unwrap();
        let after = GuildAuthoritySnapshot::from_state(&next).unwrap();
        let records = vec![
            (
                "guild-event".to_owned(),
                certified.event.sequence.to_be_bytes().to_vec(),
                canonical_bytes(&certified).unwrap(),
            ),
            (
                "guild-dynamic-state".to_owned(),
                KEY.to_vec(),
                canonical_bytes(&next).unwrap(),
            ),
        ];
        let reader = ControlStore::open_existing_read_only_with_key(
            temp.path().join("control.db"),
            &node.control_database_key,
        )
        .unwrap();
        let writer = ControlStore::open_existing_with_key(
            temp.path().join("control.db"),
            &node.control_database_key,
        )
        .unwrap();
        let expected = before.clone();
        AFTER_COMPACT_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                publish(&writer, &installed, &next, Some(&before), &records, &[]).unwrap();
            }));
        });
        (temp, reader, expected, after)
    }

    #[test]
    fn compact_authority_reader_keeps_one_snapshot_across_valid_original_publication() {
        let (_temp, reader, expected, after) = publication_during_compact_read();
        assert_eq!(
            read(&reader).unwrap(),
            Some(expected),
            "the reader must see a coherent original authority snapshot"
        );
        assert_eq!(read(&reader).unwrap(), Some(after));
    }

    #[test]
    fn node_reader_authorization_keeps_one_snapshot_across_valid_original_publication() {
        let (temp, _seed, node, keys) = fixture();
        let reader = node.reader_config().open().unwrap();
        let installed = node.installed_guild().unwrap().unwrap();
        let mut next = node.dynamic_guild_state().unwrap().unwrap();
        let before = GuildAuthoritySnapshot::from_state(&next).unwrap();
        let guild = before.guild_id;
        let caller = node.keys.node_id();
        let certified = relabel(&node, &keys);
        next.apply_event(&certified).unwrap();
        let records = vec![
            (
                "guild-event".to_owned(),
                certified.event.sequence.to_be_bytes().to_vec(),
                canonical_bytes(&certified).unwrap(),
            ),
            (
                "guild-dynamic-state".to_owned(),
                KEY.to_vec(),
                canonical_bytes(&next).unwrap(),
            ),
        ];
        let writer = ControlStore::open_existing_with_key(
            temp.path().join("control.db"),
            &node.control_database_key,
        )
        .unwrap();
        AFTER_COMPACT_READ.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                publish(&writer, &installed, &next, Some(&before), &records, &[]).unwrap();
            }));
        });
        reader.authorize_member(&guild, caller).unwrap();
        reader.authorize_member(&guild, caller).unwrap();
        assert!(reader.control.is_read_only().unwrap());
        assert!(
            reader
                .control
                .put_record("reader-write", b"a", b"b")
                .is_err()
        );
        assert!(
            node.control
                .get_record("reader-write", b"a")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn original_history_reader_opens_coherently_and_still_rejects_later_publication() {
        let (_temp, reader, before, after) = publication_during_compact_read();
        let authority = original_history::AuthorityReader::open(&reader)
            .unwrap()
            .unwrap();
        assert_eq!(authority.snapshot(), &before);
        assert!(authority.check().is_err());
        let current = original_history::AuthorityReader::open(&reader)
            .unwrap()
            .unwrap();
        assert_eq!(current.snapshot(), &after);
        current.check().unwrap();
    }

    #[test]
    fn compact_authority_is_durable_and_ordinary_readers_do_not_decode_flat_history() {
        let (temp, seed, mut node, mut keys) = fixture();
        let initial = read(&node.control).unwrap().unwrap();
        let original = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
            .unwrap();
        node.authorize_member(&initial.guild_id, node.keys.node_id())
            .unwrap();
        node.reader_config()
            .open()
            .unwrap()
            .authorize_historical_member(&initial.guild_id, node.keys.node_id())
            .unwrap();
        assert!(
            decode_canonical::<DynamicGuildState>(
                &node
                    .control
                    .get_record("guild-dynamic-state", KEY)
                    .unwrap()
                    .unwrap()
            )
            .map(|state| state.validate().is_err())
            .unwrap_or(true)
        );
        assert_eq!(
            node.guild_summary().unwrap().unwrap().event_sequence,
            Some(0)
        );
        assert!(node.guild_coordinator(&initial.guild_id).unwrap().is_some());
        node.reader_config()
            .open()
            .unwrap()
            .peer_exchange_endpoints(initial.guild_id)
            .unwrap();
        assert!(node.control.record_length(KIND, KEY).unwrap().unwrap() < 8 << 10);
        node.control
            .put_record("guild-dynamic-state", KEY, &original)
            .unwrap();

        let added = KeyMaterial::from_seed(&Seed::from_bytes([199; 32]));
        let add = event(
            &node,
            &keys,
            mb_core::GuildEventKind::AddMember {
                member: Member {
                    node_id: added.node_id(),
                    recovery_public_key: added.recovery_public_key(),
                    failure_domain: "compact-added-domain".to_owned(),
                },
            },
        );
        node.install_guild_event(add).unwrap();
        keys.push(added);
        let removed = node.guild_summary().unwrap().unwrap().coordinator;
        let remove = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RemoveMember { node_id: removed },
        );
        node.install_guild_event(remove).unwrap();
        let current = read(&node.control).unwrap().unwrap();
        assert_eq!(
            current,
            GuildAuthoritySnapshot::from_state(&node.dynamic_guild_state().unwrap().unwrap())
                .unwrap()
        );
        assert_eq!((current.event_sequence, current.membership_epoch), (2, 3));
        assert!(node.authorize_member(&current.guild_id, removed).is_err());
        node.reader_config()
            .open()
            .unwrap()
            .authorize_historical_member(&current.guild_id, removed)
            .unwrap();
        assert_ne!(
            node.guild_coordinator(&current.guild_id).unwrap(),
            Some(removed)
        );
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        assert_eq!(read(&node.control).unwrap(), Some(current));
    }

    #[test]
    fn compact_authority_event_publication_rolls_back_ignored_and_corrupted_writes() {
        for fault in 0..6 {
            let (_temp, _seed, mut node, keys) = fixture();
            let certified = relabel(&node, &keys);
            let old = node.dynamic_guild_state().unwrap().unwrap();
            let compact = node.control.get_record(KIND, KEY).unwrap().unwrap();
            let partial = pending_guild_event_signatures_id(&certified.event);
            node.control
                .put_record("guild-event-partial-signatures", &partial, b"preserve")
                .unwrap();
            let trigger = match fault {
                0 => format!("CREATE TEMP TRIGGER compact_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='{KIND}' BEGIN SELECT RAISE(IGNORE); END"),
                1 => "CREATE TEMP TRIGGER compact_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='guild-event' BEGIN SELECT RAISE(IGNORE); END".to_owned(),
                2 => "CREATE TEMP TRIGGER compact_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='guild-original-tip-v1' BEGIN SELECT RAISE(IGNORE); END".to_owned(),
                3 => format!("CREATE TEMP TRIGGER compact_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{KIND}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind=NEW.kind AND record_id=NEW.record_id; END"),
                4 => "CREATE TEMP TRIGGER compact_fault AFTER INSERT ON protocol_records WHEN NEW.kind='guild-event' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind=NEW.kind AND record_id=NEW.record_id; END".to_owned(),
                _ => "CREATE TEMP TRIGGER compact_fault BEFORE DELETE ON protocol_records WHEN OLD.kind='guild-event-partial-signatures' BEGIN SELECT RAISE(IGNORE); END".to_owned(),
            };
            node.control
                .database_shell_statement(&trigger, false)
                .unwrap();
            assert!(
                node.install_guild_event(certified.clone()).is_err(),
                "fault {fault}"
            );
            assert_eq!(node.dynamic_guild_state().unwrap(), Some(old));
            assert_eq!(node.control.get_record(KIND, KEY).unwrap(), Some(compact));
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
                .database_shell_statement("DROP TRIGGER compact_fault", false)
                .unwrap();
            node.install_guild_event(certified).unwrap();
            assert_eq!(read(&node.control).unwrap().unwrap().event_sequence, 1);
        }
    }

    #[test]
    fn compact_authority_initial_publication_cannot_leave_a_partial_recovered_guild() {
        let temp = tempfile::tempdir().unwrap();
        let (seed, certificate, peers) = recovery_guild_fixture();
        let mut node = Node::open(temp.path(), seed).unwrap();
        node.control.database_shell_statement(
            &format!("CREATE TEMP TRIGGER compact_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='{KIND}' BEGIN SELECT RAISE(IGNORE); END"),
            false,
        ).unwrap();
        assert!(
            node.adopt_recovered_guild(certificate.clone(), peers.clone())
                .is_err()
        );
        for kind in [
            KIND,
            "guild-installed",
            "guild-dynamic-state",
            "guild-genesis-signature-lock",
        ] {
            assert!(node.control.get_record(kind, KEY).unwrap().is_none());
        }
        assert!(
            node.control
                .get_record("node-config", b"member")
                .unwrap()
                .is_none()
        );
        node.control
            .database_shell_statement("DROP TRIGGER compact_fault", false)
            .unwrap();
        node.adopt_recovered_guild(certificate, peers).unwrap();
        assert_eq!(read(&node.control).unwrap().unwrap().event_sequence, 0);
    }

    #[test]
    fn compact_authority_rejects_bad_bounds_checksum_genesis_and_stale_original_tips() {
        let (_temp, _seed, mut node, keys) = fixture();
        let initial = node.control.get_record(KIND, KEY).unwrap().unwrap();
        let authority = read(&node.control).unwrap().unwrap();
        let mut changed: Record = decode(&initial).unwrap();
        changed.authority.members[0].member.failure_domain.push('x');
        let bad_checksum = canonical_bytes(&changed).unwrap();
        let bad_genesis = canonical_bytes(&make([99; 32], authority.clone()).unwrap()).unwrap();
        for bytes in [bad_checksum, bad_genesis, vec![0; BYTES + 1]] {
            node.control.put_record(KIND, KEY, &bytes).unwrap();
            assert!(read_or_legacy(&node.control).is_err());
            assert!(
                node.authorize_member(&authority.guild_id, node.keys.node_id())
                    .is_err()
            );
        }
        node.control.put_record(KIND, KEY, &initial).unwrap();
        let installed_bytes = node
            .control
            .get_record("guild-installed", KEY)
            .unwrap()
            .unwrap();
        let mut installed: InstalledGuild = decode_canonical(&installed_bytes).unwrap();
        installed.certificate.signatures[0].signature[0] ^= 1;
        node.control
            .put_record(
                "guild-installed",
                KEY,
                &canonical_bytes(&installed).unwrap(),
            )
            .unwrap();
        assert!(read(&node.control).is_err());
        node.control
            .put_record("guild-installed", KEY, &installed_bytes)
            .unwrap();
        let certified = relabel(&node, &keys);
        node.install_guild_event(certified.clone()).unwrap();
        let current = node.control.get_record(KIND, KEY).unwrap().unwrap();
        let rejected = relabel(&node, &keys);
        node.control.put_record(KIND, KEY, &initial).unwrap();
        assert!(read(&node.control).is_err());
        assert!(node.install_guild_event(rejected).is_err());
        node.control.put_record(KIND, KEY, &current).unwrap();
        let event_key = certified.event.sequence.to_be_bytes();
        node.control
            .delete_record("guild-event", &event_key)
            .unwrap();
        assert!(read(&node.control).is_err());
        node.control
            .put_record(
                "guild-event",
                &event_key,
                &canonical_bytes(&certified).unwrap(),
            )
            .unwrap();
        let mut fork = certified;
        fork.event.parent = [88; 32];
        node.control
            .put_record("guild-event", &event_key, &canonical_bytes(&fork).unwrap())
            .unwrap();
        assert!(read(&node.control).is_err());
    }

    #[test]
    fn compact_authority_backfills_legacy_state_only_with_an_accepted_original_event() {
        let (_temp, _seed, mut node, keys) = fixture();
        let initial = read(&node.control).unwrap().unwrap();
        node.control.delete_record(KIND, KEY).unwrap();
        assert_eq!(read(&node.control).unwrap(), None);
        assert_eq!(
            read_or_legacy(&node.control).unwrap(),
            Some(initial.clone())
        );
        let original = node
            .control
            .get_record("guild-dynamic-state", KEY)
            .unwrap()
            .unwrap();
        node.control
            .put_record("guild-dynamic-state", KEY, b"invalid")
            .unwrap();
        assert!(read_or_legacy(&node.control).is_err());
        node.control
            .put_record("guild-dynamic-state", KEY, &original)
            .unwrap();
        let certified = relabel(&node, &keys);
        node.install_guild_event(certified).unwrap();
        assert_eq!(read(&node.control).unwrap().unwrap().event_sequence, 1);
        let rotate = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner: node.keys.node_id(),
                epoch: 1,
                public_key: node.keys.node_id().0,
            },
        );
        node.install_guild_event(rotate).unwrap();
        let current = read(&node.control).unwrap().unwrap();
        assert_eq!((current.event_sequence, current.membership_epoch), (2, 2));
        assert_eq!(
            node.dynamic_guild_state()
                .unwrap()
                .unwrap()
                .writer_keys
                .len(),
            1
        );
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
            .unwrap();
        node.authorize_member(&current.guild_id, node.keys.node_id())
            .unwrap();
        assert_eq!(read(&node.control).unwrap(), Some(current));
    }
}
