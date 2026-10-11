//! Durable bounded historical rosters. Only verified ingestion publishes these
//! local projections; original certificates and identities remain unchanged.
use super::*;

const EPOCHS: &str = "guild-authority-membership-v1";
const MARKER: &str = "guild-authority-membership-tip-v1";
const MARKER_BYTES: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct Epoch {
    record: Record,
    certificate_hash: [u8; 32],
    checksum: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
struct Marker {
    format_version: u16,
    genesis_hash: [u8; 32],
    guild_id: [u8; 32],
    first_epoch: u64,
    membership_epoch: u64,
    event_sequence: u64,
    event_head: [u8; 32],
    checksum: [u8; 32],
}

impl Marker {
    fn new(record: &Record, first_epoch: u64) -> Result<Self> {
        let mut value = Self {
            format_version: 1,
            genesis_hash: record.genesis_hash,
            guild_id: record.authority.guild_id,
            first_epoch,
            membership_epoch: record.authority.membership_epoch,
            event_sequence: record.authority.event_sequence,
            event_head: record.authority.event_head,
            checksum: [0; 32],
        };
        value.checksum = value.hash()?;
        Ok(value)
    }

    fn hash(&self) -> Result<[u8; 32]> {
        Ok(mb_core::canonical_hash_bounded(
            &(
                self.format_version,
                self.genesis_hash,
                self.guild_id,
                self.first_epoch,
                self.membership_epoch,
                self.event_sequence,
                self.event_head,
            ),
            MARKER_BYTES,
        )?)
    }

    fn check(&self, record: &Record) -> Result<()> {
        if self.first_epoch == 0
            || self.first_epoch > self.membership_epoch
            || *self != Self::new(record, self.first_epoch)?
        {
            anyhow::bail!("historical membership index conflicts with compact authority");
        }
        Ok(())
    }
}

pub(super) fn owns_kind(kind: &str) -> bool {
    matches!(kind, EPOCHS | MARKER)
}

fn marker(bytes: &[u8]) -> Result<Marker> {
    let value: Marker = decode_canonical(bytes)?;
    if value.checksum != value.hash()?
        || mb_core::canonical_bytes_bounded(&value, MARKER_BYTES)? != bytes
    {
        anyhow::bail!("historical membership marker is not canonical");
    }
    Ok(value)
}

fn epoch(bytes: &[u8]) -> Result<Epoch> {
    let value: Epoch = decode_canonical(bytes)?;
    // Reuse the compact roster's nested allocation bounds and invariants.
    decode(&mb_core::canonical_bytes_bounded(&value.record, BYTES)?)?;
    if value.certificate_hash == [0; 32]
        || value.checksum
            != mb_core::canonical_hash_bounded(&(&value.record, value.certificate_hash), BYTES)?
        || mb_core::canonical_bytes_bounded(&value, BYTES)? != bytes
    {
        anyhow::bail!("invalid historical membership projection");
    }
    Ok(value)
}

fn same_roster(left: &GuildAuthoritySnapshot, right: &GuildAuthoritySnapshot) -> bool {
    left.format_version == right.format_version
        && left.guild_id == right.guild_id
        && left.membership_epoch == right.membership_epoch
        && left.quorum == right.quorum
        && left.members == right.members
}

fn check_epoch(value: &Epoch, requested: u64, current: &Record) -> Result<()> {
    let authority = &value.record.authority;
    if authority.membership_epoch != requested
        || value.record.genesis_hash != current.genesis_hash
        || authority.guild_id != current.authority.guild_id
        || authority.event_sequence > current.authority.event_sequence
        || requested > current.authority.membership_epoch
        || requested == current.authority.membership_epoch
            && !same_roster(authority, &current.authority)
    {
        anyhow::bail!("historical membership projection has a different epoch or origin");
    }
    Ok(())
}

fn original_certificate(
    control: &ControlStore,
    installed: &InstalledGuild,
    genesis: &GuildAuthoritySnapshot,
    record: &Record,
    records: &[ControlRecord],
) -> Result<[u8; 32]> {
    if record.authority.event_sequence == 0 {
        if record.authority != *genesis || record.genesis_hash != record.authority.event_head {
            anyhow::bail!("historical genesis membership differs from its original certificate");
        }
        return Ok(mb_core::canonical_hash_bounded(
            &installed.certificate,
            GUILD_AUTHORITY_SNAPSHOT_BYTES,
        )?);
    }
    let key = record.authority.event_sequence.to_be_bytes();
    let bytes = match records
        .iter()
        .find(|(kind, id, _)| kind == "guild-event" && id == &key)
    {
        Some((_, _, bytes)) => std::borrow::Cow::Borrowed(bytes.as_slice()),
        None => std::borrow::Cow::Owned(
            control
                .get_record_bounded("guild-event", &key, GUILD_EVENT_BYTES)?
                .context("historical membership projection lacks its original certificate")?,
        ),
    };
    let event = QuorumGuildEvent::decode_bounded(&bytes)?;
    if event.event.sequence != record.authority.event_sequence
        || event.event.guild_id != record.authority.guild_id
        || event.event.hash()? != record.authority.event_head
    {
        anyhow::bail!("historical membership projection conflicts with its original certificate");
    }
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// At most one bounded epoch row and one fixed marker change. Preparation and
/// original certificate decoding happen outside the production writer.
pub(super) struct Prepared {
    expected: Option<Vec<u8>>,
    next: Vec<u8>,
    row: Option<([u8; 8], Vec<u8>)>,
    guards: Vec<([u8; 8], Vec<u8>)>,
}

pub(super) fn prepare(
    control: &ControlStore,
    installed: &InstalledGuild,
    genesis: &GuildAuthoritySnapshot,
    next: &Record,
    before: Option<&Record>,
    records: &[ControlRecord],
) -> Result<Prepared> {
    let expected = control.get_record_bounded(MARKER, KEY, MARKER_BYTES)?;
    let first = match &expected {
        Some(bytes) => {
            let previous = marker(bytes)?;
            previous.check(before.unwrap_or(next))?;
            previous.first_epoch
        }
        // Older stores start an explicit contiguous indexed suffix. Requests
        // preceding it still use original legacy replay, never a guessed row.
        None => next.authority.membership_epoch,
    };
    let changed = expected.is_none()
        || before.is_some_and(|before| {
            before.authority.membership_epoch != next.authority.membership_epoch
        });
    if let Some(before) = before
        && (before.authority.event_sequence.checked_add(1) != Some(next.authority.event_sequence)
            || next.authority.membership_epoch != before.authority.membership_epoch
                && before.authority.membership_epoch.checked_add(1)
                    != Some(next.authority.membership_epoch))
    {
        anyhow::bail!("historical membership publication skips an accepted transition");
    }
    if let Some(before) = before
        && before.authority.membership_epoch == next.authority.membership_epoch
        && !same_roster(&before.authority, &next.authority)
    {
        anyhow::bail!("historical membership changed without advancing its epoch");
    }
    let mut guards = Vec::with_capacity(2);
    if expected.is_some() {
        let previous = before.unwrap_or(next);
        let key = previous.authority.membership_epoch.to_be_bytes();
        let bytes = control
            .get_record_bounded(EPOCHS, &key, BYTES)?
            .context("historical membership index lacks its current epoch")?;
        let value = epoch(&bytes)?;
        check_epoch(&value, previous.authority.membership_epoch, previous)?;
        if original_certificate(control, installed, genesis, &value.record, records)?
            != value.certificate_hash
        {
            anyhow::bail!("historical membership certificate changed before publication");
        }
        guards.push((key, bytes));
    }
    let row = if changed {
        let key = next.authority.membership_epoch.to_be_bytes();
        if let Some(bytes) = control.get_record_bounded(EPOCHS, &key, BYTES)? {
            // A removed marker may leave an exact previously accepted row.
            // Preserve its original tip instead of rewriting its identity.
            let value = epoch(&bytes)?;
            check_epoch(&value, next.authority.membership_epoch, next)?;
            if !same_roster(&value.record.authority, &next.authority) {
                anyhow::bail!("historical membership row conflicts with the accepted roster");
            }
            check_original_tip(control, &value.record)?;
            let hash = original_certificate(control, installed, genesis, &value.record, records)?;
            if hash != value.certificate_hash {
                anyhow::bail!("historical membership certificate changed");
            }
            guards.push((key, bytes));
            None
        } else {
            let hash = original_certificate(control, installed, genesis, next, records)?;
            let value = Epoch {
                record: next.clone(),
                certificate_hash: hash,
                checksum: mb_core::canonical_hash_bounded(&(next, hash), BYTES)?,
            };
            Some((key, mb_core::canonical_bytes_bounded(&value, BYTES)?))
        }
    } else {
        None
    };
    Ok(Prepared {
        expected,
        next: mb_core::canonical_bytes_bounded(&Marker::new(next, first)?, MARKER_BYTES)?,
        row,
        guards,
    })
}

impl Prepared {
    pub(super) fn publish(&self, control: &ControlStore) -> Result<()> {
        if control.get_record_bounded(MARKER, KEY, MARKER_BYTES)? != self.expected {
            anyhow::bail!("historical membership index changed before publication");
        }
        self.check_rows(control)?;
        if let Some((key, bytes)) = &self.row
            && (!control.put_record_if_absent(EPOCHS, key, bytes)?
                || control.get_record_bounded(EPOCHS, key, BYTES)?.as_deref() != Some(bytes))
        {
            anyhow::bail!("historical membership epoch write did not persist exact bytes");
        }
        match &self.expected {
            Some(old) => control.replace_record_if_value(MARKER, KEY, old, &self.next)?,
            None => {
                if !control.put_record_if_absent(MARKER, KEY, &self.next)? {
                    anyhow::bail!("historical membership marker raced another writer");
                }
            }
        }
        if control
            .get_record_bounded(MARKER, KEY, MARKER_BYTES)?
            .as_deref()
            != Some(self.next.as_slice())
        {
            anyhow::bail!("historical membership marker write did not persist exact bytes");
        }
        Ok(())
    }

    fn check_rows(&self, control: &ControlStore) -> Result<()> {
        for (key, bytes) in &self.guards {
            if control.get_record_bounded(EPOCHS, key, BYTES)?.as_deref() != Some(bytes.as_slice())
            {
                anyhow::bail!("historical membership epoch changed before publication");
            }
        }
        Ok(())
    }

    pub(super) fn check(&self, control: &ControlStore) -> Result<()> {
        self.check_rows(control)?;
        if let Some((key, bytes)) = &self.row
            && control.get_record_bounded(EPOCHS, key, BYTES)?.as_deref() != Some(bytes.as_slice())
        {
            anyhow::bail!("historical membership epoch changed during publication");
        }
        if control
            .get_record_bounded(MARKER, KEY, MARKER_BYTES)?
            .as_deref()
            != Some(self.next.as_slice())
        {
            anyhow::bail!("historical membership marker changed during publication");
        }
        Ok(())
    }
}

/// None means this epoch precedes the indexed suffix (or the store predates
/// it). Missing/malformed indexed rows and stale markers always fail closed.
pub(super) fn read(
    control: &ControlStore,
    requested: u64,
) -> Result<Option<GuildAuthoritySnapshot>> {
    let Some(marker_bytes) = control.get_record_bounded(MARKER, KEY, MARKER_BYTES)? else {
        return Ok(None);
    };
    let current_bytes = control
        .get_record_bounded(KIND, KEY, BYTES)?
        .context("historical membership index has no compact authority")?;
    let current = decode(&current_bytes)?;
    let (installed, genesis) = check_genesis(control, &current)?;
    check_tail(control, &current)?;
    let completed = marker(&marker_bytes)?;
    completed.check(&current)?;
    if requested == 0 || requested > completed.membership_epoch {
        anyhow::bail!("coding attempt membership epoch is absent from guild history");
    }
    if requested < completed.first_epoch {
        return Ok(None);
    }
    let bytes = control
        .get_record_bounded(EPOCHS, &requested.to_be_bytes(), BYTES)?
        .context("historical membership index lacks a completed epoch")?;
    let value = epoch(&bytes)?;
    check_epoch(&value, requested, &current)?;
    check_original_tip(control, &value.record)?;
    if original_certificate(control, &installed, &genesis, &value.record, &[])?
        != value.certificate_hash
    {
        anyhow::bail!("historical membership original certificate changed");
    }
    if control
        .get_record_bounded(MARKER, KEY, MARKER_BYTES)?
        .as_deref()
        != Some(marker_bytes.as_slice())
        || control.get_record_bounded(KIND, KEY, BYTES)?.as_deref()
            != Some(current_bytes.as_slice())
        || control
            .get_record_bounded(EPOCHS, &requested.to_be_bytes(), BYTES)?
            .as_deref()
            != Some(bytes.as_slice())
    {
        anyhow::bail!("historical membership changed during lookup");
    }
    check_tail(control, &current)?;
    Ok(Some(value.record.authority))
}

#[cfg(test)]
mod tests {
    use super::super::tests::{event, fixture, relabel};
    use super::*;

    fn plan(node: &Node) -> SignedRecord<CodingAttemptPlan> {
        let authority = super::super::read(&node.control).unwrap().unwrap();
        let local = authority
            .active_members()
            .find(|m| m.node_id == node.keys.node_id())
            .unwrap();
        let others = authority
            .active_members()
            .filter(|m| m.node_id != local.node_id)
            .collect::<Vec<_>>();
        let bytes = vec![7; 64];
        SignedRecord::sign(
            CODING_ATTEMPT_PLAN_DOMAIN,
            CodingAttemptPlan {
                format_version: 3,
                attempt_id: [76; 16],
                checkpoint_hash: [77; 32],
                membership_epoch: authority.membership_epoch,
                geometry: mb_core::CodingPlanGeometry {
                    format_version: 1,
                    guild_id: authority.guild_id,
                    profile: mb_core::CodingProfile::new(1, 1, 64),
                    information: vec![mb_core::InformationRoleV2 {
                        owner: local.node_id,
                        failure_domain: local.failure_domain.clone(),
                        sector: mb_core::RangeSectorRef {
                            id: [78; 32],
                            commitment: merkle_commit(&bytes).unwrap(),
                            logical_len: 64,
                            virtual_zero: false,
                        },
                    }],
                    parity: vec![mb_core::ParityPlacementV2 {
                        holder: others[0].node_id,
                        failure_domain: others[0].failure_domain.clone(),
                        row: 0,
                    }],
                },
                delegator: local.node_id,
                coding_coordinator: others[1].node_id,
                verification_coordinator: others[2].node_id,
                expires_at_unix_seconds: unix_seconds() + 600,
                information_roots: Some(vec![sector_root(&bytes)]),
            },
            node.keys(),
        )
        .unwrap()
    }

    #[test]
    fn indexed_membership_serves_real_coding_authority_without_flat_history_after_reopen() {
        let (temp, seed, mut node, mut keys) = fixture();
        let initial = node.membership_authority_for_epoch(1).unwrap();
        let signed = plan(&node);
        node.validate_coding_attempt_plan(&signed).unwrap();
        let initial_row = node
            .control
            .get_record(EPOCHS, &1_u64.to_be_bytes())
            .unwrap();
        let writer = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner: node.keys.node_id(),
                epoch: 1,
                public_key: node.keys.node_id().0,
            },
        );
        node.install_guild_event(writer).unwrap();
        assert_eq!(
            node.control
                .get_record(EPOCHS, &1_u64.to_be_bytes())
                .unwrap(),
            initial_row
        );
        node.install_guild_event(relabel(&node, &keys)).unwrap();
        let relabeled = node.membership_authority_for_epoch(2).unwrap();
        let quorum = event(
            &node,
            &keys,
            mb_core::GuildEventKind::SetQuorum {
                policy: QuorumPolicy {
                    format_version: 1,
                    rule: QuorumRule::Majority,
                },
            },
        );
        node.install_guild_event(quorum).unwrap();
        let majority = node.membership_authority_for_epoch(3).unwrap();
        let key = KeyMaterial::from_seed(&Seed::from_bytes([199; 32]));
        let add = event(
            &node,
            &keys,
            mb_core::GuildEventKind::AddMember {
                member: Member {
                    node_id: key.node_id(),
                    recovery_public_key: key.recovery_public_key(),
                    failure_domain: "indexed-added-member".to_owned(),
                },
            },
        );
        node.install_guild_event(add).unwrap();
        keys.push(key);
        let added = node.membership_authority_for_epoch(4).unwrap();
        let remove = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RemoveMember {
                node_id: signed.value.geometry.parity[0].holder,
            },
        );
        node.install_guild_event(remove).unwrap();
        let removed = node.membership_authority_for_epoch(5).unwrap();
        assert_eq!(node.control.records(EPOCHS).unwrap().len(), 5);
        assert!(node.membership_history_cache.lock().unwrap().is_none());
        assert_eq!(node.membership_authority_for_epoch(1).unwrap(), initial);
        assert!(node.membership_authority_for_epoch(0).is_err());
        assert!(node.membership_authority_for_epoch(6).is_err());
        // Historical cleanup still has its original placement authority;
        // starting the attempt under the current roster remains fenced.
        node.validate_coding_attempt_authority(&signed).unwrap();
        assert!(node.validate_coding_attempt_plan(&signed).is_err());
        let mut expired = signed.value.clone();
        expired.expires_at_unix_seconds = unix_seconds() - 1;
        let expired = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, expired, node.keys()).unwrap();
        node.validate_coding_attempt_authority(&expired).unwrap();
        let mut wrong = signed.value.clone();
        wrong.geometry.information[0].failure_domain.push('x');
        let wrong = SignedRecord::sign(CODING_ATTEMPT_PLAN_DOMAIN, wrong, node.keys()).unwrap();
        assert!(node.validate_coding_attempt_authority(&wrong).is_err());
        let mut bad_signature = signed.clone();
        bad_signature.signature[0] ^= 1;
        assert!(
            node.validate_coding_attempt_authority(&bad_signature)
                .is_err()
        );
        let fresh = plan(&node);
        node.control
            .put_record("guild-dynamic-state", KEY, &vec![0; 2 << 20])
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
        node.validate_coding_attempt_plan(&fresh).unwrap();
        for expected in [&initial, &relabeled, &majority, &added, &removed] {
            assert_eq!(
                node.membership_authority_for_epoch(expected.membership_epoch)
                    .unwrap(),
                *expected
            );
        }
        drop(node);
        let node = Node::open(temp.path(), seed).unwrap();
        node.validate_coding_attempt_authority(&signed).unwrap();
        assert_eq!(node.membership_authority_for_epoch(1).unwrap(), initial);
        assert_eq!(node.membership_authority_for_epoch(5).unwrap(), removed);
        node.validate_coding_attempt_plan(&fresh).unwrap();
        assert!(node.membership_history_cache.lock().unwrap().is_none());
    }

    #[test]
    fn indexed_membership_publication_rolls_back_ignored_corrupted_and_cross_record_writes() {
        for fault in 0..9 {
            let (_temp, _seed, mut node, keys) = fixture();
            let old = node.dynamic_guild_state().unwrap();
            let compact = node.control.get_record(KIND, KEY).unwrap();
            let marker = node.control.get_record(MARKER, KEY).unwrap();
            let first = node
                .control
                .get_record(EPOCHS, &1_u64.to_be_bytes())
                .unwrap();
            let certified = relabel(&node, &keys);
            let pending = pending_guild_event_signatures_id(&certified.event);
            node.control
                .put_record("guild-event-partial-signatures", &pending, b"pending")
                .unwrap();
            let trigger = match fault {
                0 => format!(
                    "CREATE TEMP TRIGGER membership_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='{EPOCHS}' BEGIN SELECT RAISE(IGNORE); END"
                ),
                1 => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER INSERT ON protocol_records WHEN NEW.kind='{EPOCHS}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind=NEW.kind AND record_id=NEW.record_id; END"
                ),
                2 => format!(
                    "CREATE TEMP TRIGGER membership_fault BEFORE UPDATE ON protocol_records WHEN NEW.kind='{MARKER}' BEGIN SELECT RAISE(IGNORE); END"
                ),
                3 => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{MARKER}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind=NEW.kind AND record_id=NEW.record_id; END"
                ),
                4 => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{KIND}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='{EPOCHS}'; END"
                ),
                5 => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{MARKER}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='{EPOCHS}' AND record_id=X'0000000000000001'; END"
                ),
                6 => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{MARKER}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-event'; END"
                ),
                7 => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{MARKER}' BEGIN UPDATE protocol_records SET bytes=X'00' WHERE kind='guild-original-tip-v1'; END"
                ),
                _ => format!(
                    "CREATE TEMP TRIGGER membership_fault AFTER UPDATE ON protocol_records WHEN NEW.kind='{MARKER}' BEGIN INSERT INTO protocol_records(kind,record_id,bytes) VALUES ('guild-event-partial-signatures', X'{}', X'00'); END",
                    hex::encode(pending),
                ),
            };
            node.control
                .database_shell_statement(&trigger, false)
                .unwrap();
            assert!(
                node.install_guild_event(certified.clone()).is_err(),
                "fault {fault}"
            );
            assert_eq!(node.dynamic_guild_state().unwrap(), old, "fault {fault}");
            assert_eq!(node.control.get_record(KIND, KEY).unwrap(), compact);
            assert_eq!(node.control.get_record(MARKER, KEY).unwrap(), marker);
            assert_eq!(
                node.control
                    .get_record(EPOCHS, &1_u64.to_be_bytes())
                    .unwrap(),
                first
            );
            assert!(
                node.control
                    .get_record(EPOCHS, &2_u64.to_be_bytes())
                    .unwrap()
                    .is_none()
            );
            assert!(
                node.control
                    .get_record("guild-event", &1_u64.to_be_bytes())
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                node.control
                    .get_record("guild-event-partial-signatures", &pending)
                    .unwrap()
                    .as_deref(),
                Some(b"pending".as_slice())
            );
            node.control
                .database_shell_statement("DROP TRIGGER membership_fault", false)
                .unwrap();
            node.install_guild_event(certified).unwrap();
            assert_eq!(
                node.membership_authority_for_epoch(2)
                    .unwrap()
                    .event_sequence,
                1
            );
        }
    }

    #[test]
    fn indexed_membership_initial_publication_is_atomic() {
        for kind in [EPOCHS, MARKER] {
            let temp = tempfile::tempdir().unwrap();
            let (seed, certificate, peers) = crate::node::tests::recovery_guild_fixture();
            let mut node = Node::open(temp.path(), seed).unwrap();
            node.control.database_shell_statement(&format!("CREATE TEMP TRIGGER membership_fault BEFORE INSERT ON protocol_records WHEN NEW.kind='{kind}' BEGIN SELECT RAISE(IGNORE); END"), false).unwrap();
            assert!(
                node.adopt_recovered_guild(certificate.clone(), peers.clone())
                    .is_err()
            );
            for kind in [
                KIND,
                MARKER,
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
            assert!(node.control.records(EPOCHS).unwrap().is_empty());
            node.control
                .database_shell_statement("DROP TRIGGER membership_fault", false)
                .unwrap();
            node.adopt_recovered_guild(certificate, peers).unwrap();
            assert_eq!(
                node.membership_authority_for_epoch(1)
                    .unwrap()
                    .event_sequence,
                0
            );
        }
    }

    #[test]
    fn indexed_membership_rejects_bad_rows_markers_and_changed_original_certificates() {
        let (_temp, _seed, mut node, keys) = fixture();
        let relabel = relabel(&node, &keys);
        node.install_guild_event(relabel.clone()).unwrap();
        let writer = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner: node.keys.node_id(),
                epoch: 1,
                public_key: node.keys.node_id().0,
            },
        );
        node.install_guild_event(writer).unwrap();
        let row = node
            .control
            .get_record(EPOCHS, &2_u64.to_be_bytes())
            .unwrap()
            .unwrap();
        let first = node
            .control
            .get_record(EPOCHS, &1_u64.to_be_bytes())
            .unwrap()
            .unwrap();
        let mut bad = epoch(&row).unwrap();
        bad.record.authority.members[0]
            .member
            .failure_domain
            .push('x');
        for bytes in [vec![0; BYTES + 1], first, canonical_bytes(&bad).unwrap()] {
            node.control
                .put_record(EPOCHS, &2_u64.to_be_bytes(), &bytes)
                .unwrap();
            assert!(node.membership_authority_for_epoch(2).is_err());
        }
        node.control
            .delete_record(EPOCHS, &2_u64.to_be_bytes())
            .unwrap();
        assert!(node.membership_authority_for_epoch(2).is_err());
        node.control
            .put_record(EPOCHS, &2_u64.to_be_bytes(), &row)
            .unwrap();
        let complete = node.control.get_record(MARKER, KEY).unwrap().unwrap();
        let mut bad = marker(&complete).unwrap();
        bad.first_epoch += 1;
        for bytes in [vec![0; MARKER_BYTES + 1], canonical_bytes(&bad).unwrap()] {
            node.control.put_record(MARKER, KEY, &bytes).unwrap();
            assert!(node.membership_authority_for_epoch(2).is_err());
        }
        node.control.put_record(MARKER, KEY, &complete).unwrap();
        // This is an older original event, so the current-tip read alone
        // cannot detect signature corruption in its unchanged event body.
        let original = canonical_bytes(&relabel).unwrap();
        let mut changed = relabel;
        changed.signatures[0].signature[0] ^= 1;
        node.control
            .put_record(
                "guild-event",
                &1_u64.to_be_bytes(),
                &canonical_bytes(&changed).unwrap(),
            )
            .unwrap();
        assert!(node.membership_authority_for_epoch(2).is_err());
        node.control
            .delete_record("guild-event", &1_u64.to_be_bytes())
            .unwrap();
        assert!(node.membership_authority_for_epoch(2).is_err());
        node.control
            .put_record("guild-event", &1_u64.to_be_bytes(), &original)
            .unwrap();
        node.membership_authority_for_epoch(2).unwrap();
        assert!(node.membership_history_cache.lock().unwrap().is_none());
    }

    #[test]
    fn indexed_membership_legacy_backfill_declares_a_suffix_and_keeps_original_replay_for_older_epochs()
     {
        let (_temp, _seed, mut node, keys) = fixture();
        let initial = node.membership_authority_for_epoch(1).unwrap();
        node.install_guild_event(relabel(&node, &keys)).unwrap();
        for (key, _) in node.control.records(EPOCHS).unwrap() {
            node.control.delete_record(EPOCHS, &key).unwrap();
        }
        node.control.delete_record(MARKER, KEY).unwrap();
        assert_eq!(node.membership_authority_for_epoch(1).unwrap(), initial);
        let writer = event(
            &node,
            &keys,
            mb_core::GuildEventKind::RotateWriterKey {
                owner: node.keys.node_id(),
                epoch: 1,
                public_key: node.keys.node_id().0,
            },
        );
        node.install_guild_event(writer).unwrap();
        assert_eq!(
            marker(&node.control.get_record(MARKER, KEY).unwrap().unwrap())
                .unwrap()
                .first_epoch,
            2
        );
        assert!(read(&node.control, 1).unwrap().is_none());
        assert_eq!(node.membership_authority_for_epoch(1).unwrap(), initial);
        let current = node.membership_authority_for_epoch(2).unwrap();
        assert_eq!(current.event_sequence, 2);
        node.control
            .put_record("guild-dynamic-state", KEY, b"unreadable legacy state")
            .unwrap();
        assert_eq!(node.membership_authority_for_epoch(2).unwrap(), current);
        assert_eq!(node.membership_authority_for_epoch(1).unwrap(), initial);
        node.control
            .delete_record(EPOCHS, &2_u64.to_be_bytes())
            .unwrap();
        assert!(node.membership_authority_for_epoch(2).is_err());
    }
}
