//! Incremental original-history authority. Validation runs in a disposable
//! bounded overlay; publication applies only checked fixed point mutations.
use super::*;
use std::collections::BTreeMap;

const TIP: &str = "guild-original-tip-v1";
const KEY: &[u8] = b"primary";
const TIP_BYTES: usize = GUILD_AUTHORITY_SNAPSHOT_BYTES + 256;
const HEADER: usize = 64;
const ROW_KINDS: [&str; 8] = [
    MEMBERS,
    WRITERS,
    LATEST_WRITER,
    RECOVERY,
    LATEST_RECOVERY,
    GROUPS,
    EVENTS,
    ARCHIVE,
];

fn kind(value: &str) -> &'static str {
    match value {
        MEMBERS => "guild-original-members",
        WRITERS => "guild-original-writer",
        LATEST_WRITER => "guild-original-latest-writer",
        RECOVERY => "guild-original-recovery",
        LATEST_RECOVERY => "guild-original-latest-recovery",
        GROUPS => "guild-original-group",
        EVENTS => "guild-original-event",
        ARCHIVE => "guild-original-incarnation",
        _ => unreachable!("private original-history row kind"),
    }
}
fn limit(value: &str) -> usize {
    match value {
        MEMBERS => GUILD_AUTHORITY_SNAPSHOT_BYTES,
        RECOVERY => RECOVERY_BYTES,
        GROUPS => GROUP_BYTES,
        _ => ROW_BYTES,
    }
}
fn row_hash(
    genesis: [u8; 32],
    name: &str,
    key: &[u8],
    body: &[u8],
) -> Result<[u8; 32], CatalogStoreError> {
    Ok(mb_core::canonical_hash_bounded(
        &(
            "mutualbackup original history row v1",
            genesis,
            name,
            key,
            body,
        ),
        limit(name) + 256,
    )?)
}
fn wrap(
    genesis: [u8; 32],
    name: &str,
    key: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, CatalogStoreError> {
    if body.is_empty() || body.len() > limit(name) || key.len() > 40 {
        return Err(CatalogError::Bounds.into());
    }
    let mut bytes = Vec::with_capacity(HEADER + body.len());
    bytes.extend_from_slice(&genesis);
    bytes.extend_from_slice(&row_hash(genesis, name, key, body)?);
    bytes.extend_from_slice(body);
    Ok(bytes)
}
fn unwrap<'a>(
    genesis: [u8; 32],
    name: &str,
    key: &[u8],
    bytes: &'a [u8],
) -> Result<&'a [u8], CatalogStoreError> {
    if bytes.len() <= HEADER
        || bytes.len() > HEADER + limit(name)
        || bytes[..32] != genesis
        || bytes[32..HEADER] != row_hash(genesis, name, key, &bytes[HEADER..])?
    {
        return Err(DatabaseError::Integrity.into());
    }
    Ok(&bytes[HEADER..])
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct DurableManifest {
    format_version: u16,
    genesis_hash: [u8; 32],
    authority: GuildAuthoritySnapshot,
    retained: u64,
    retired: u64,
    incarnations: u64,
    work: Work,
    checksum: [u8; 32],
}
impl DurableManifest {
    fn hash(&self) -> Result<[u8; 32], CatalogStoreError> {
        Ok(mb_core::canonical_hash_bounded(
            &(
                self.format_version,
                self.genesis_hash,
                &self.authority,
                self.retained,
                self.retired,
                self.incarnations,
                self.work,
            ),
            TIP_BYTES,
        )?)
    }
    fn encode(&mut self) -> Result<Vec<u8>, CatalogStoreError> {
        self.checksum = self.hash()?;
        Ok(canonical_bytes_bounded(self, TIP_BYTES)?)
    }
    fn decode(bytes: &[u8]) -> Result<Self, CatalogStoreError> {
        let value: Self = decode_canonical(bytes)?;
        value.authority.validate()?;
        if value.format_version != 1
            || value.genesis_hash == [0; 32]
            || value.retired > value.retained
            || value.retained > value.incarnations
            || value.incarnations > value.authority.event_sequence
            || value.authority.event_sequence == 0
                && (value.authority.event_head != value.genesis_hash
                    || value.authority.membership_epoch != 1)
            || value.checksum != value.hash()?
            || canonical_bytes_bounded(&value, TIP_BYTES)? != bytes
        {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(value)
    }
}

/// Constructed only by original genesis/certificate/transition validation.
pub struct CatalogDurableGuildHistory {
    manifest: DurableManifest,
    encoded: Vec<u8>,
}
struct Patch {
    name: &'static str,
    key: Vec<u8>,
    expected: Option<Vec<u8>>,
    next: Option<Vec<u8>>,
}
/// A private completion token. No decoder or arbitrary point-row constructor.
pub struct CatalogGuildHistoryMutation {
    expected: Option<Vec<u8>>,
    manifest: DurableManifest,
    encoded: Vec<u8>,
    patches: Vec<Patch>,
    step_work: Work,
}

fn seed(
    control: &ControlStore,
    scratch: &RecordScratchStore,
    meter: &mut Meter,
    guards: &mut BTreeMap<(&'static str, Vec<u8>), Option<Vec<u8>>>,
    genesis: [u8; 32],
    name: &'static str,
    key: &[u8],
) -> Result<(), CatalogStoreError> {
    let location = (name, key.to_vec());
    if guards.contains_key(&location) {
        return Ok(());
    }
    meter.metadata()?;
    let bytes = if let Some(length) = control.record_length(kind(name), key)? {
        if length <= HEADER || length > HEADER + limit(name) {
            return Err(DatabaseError::Integrity.into());
        }
        meter.charge(length.checked_mul(4).ok_or(CatalogError::Bounds)?, 4)?;
        let bytes = control
            .get_record_bounded(kind(name), key, length)?
            .ok_or(DatabaseError::Integrity)?;
        let body = unwrap(genesis, name, key, &bytes)?;
        if !scratch.put_record_if_absent(name, key, body)?
            || scratch
                .get_record_bounded(name, key, limit(name))?
                .as_deref()
                != Some(body)
        {
            return Err(DatabaseError::Integrity.into());
        }
        Some(bytes)
    } else {
        None
    };
    guards.insert(location, bytes);
    Ok(())
}

struct CachedSource<'a, S> {
    source: &'a mut S,
    transcript: Option<(CatalogGuildHistoryObject, Vec<u8>)>,
}
impl<S: CatalogGuildHistorySource> CatalogGuildHistorySource for CachedSource<'_, S> {
    fn next_event(
        &mut self,
        after: Option<u64>,
    ) -> Result<Option<(u64, usize)>, CatalogStoreError> {
        self.source.next_event(after)
    }
    fn length(
        &mut self,
        object: CatalogGuildHistoryObject,
    ) -> Result<Option<usize>, CatalogStoreError> {
        if let Some((id, bytes)) = &self.transcript
            && *id == object
        {
            return Ok(Some(bytes.len()));
        }
        self.source.length(object)
    }
    fn read(
        &mut self,
        object: CatalogGuildHistoryObject,
        cap: usize,
    ) -> Result<Option<Vec<u8>>, CatalogStoreError> {
        if let Some((id, bytes)) = &self.transcript
            && *id == object
        {
            if bytes.len() > cap {
                return Err(CatalogError::Bounds.into());
            }
            return Ok(Some(bytes.clone()));
        }
        self.source.read(object, cap)
    }
}

impl CatalogDurableGuildHistory {
    pub fn owns_record_kind(name: &str) -> bool {
        name == TIP || ROW_KINDS.iter().any(|value| kind(value) == name)
    }
    pub fn read(control: &ControlStore) -> Result<Option<Self>, CatalogStoreError> {
        let Some(encoded) = control.get_record_bounded(TIP, KEY, TIP_BYTES)? else {
            return Ok(None);
        };
        let manifest = DurableManifest::decode(&encoded)?;
        Ok(Some(Self { manifest, encoded }))
    }
    pub fn authority(&self) -> &GuildAuthoritySnapshot {
        &self.manifest.authority
    }
    pub fn genesis_hash(&self) -> [u8; 32] {
        self.manifest.genesis_hash
    }
    pub fn represented_work(&self) -> Work {
        self.manifest.work
    }

    pub fn prepare_guard(&self) -> CatalogGuildHistoryMutation {
        CatalogGuildHistoryMutation {
            expected: Some(self.encoded.clone()),
            manifest: self.manifest.clone(),
            encoded: self.encoded.clone(),
            patches: Vec::new(),
            // Expected-tip check and both publication readbacks; no new
            // original evidence is added to the represented history ledger.
            step_work: Work {
                bytes: (TIP_BYTES * 3) as u64,
                records: 3,
                page_occurrences: 0,
            },
        }
    }

    pub fn prepare_genesis(
        control: &ControlStore,
        genesis: &QuorumGuildGenesis,
        budget: Work,
    ) -> Result<CatalogGuildHistoryMutation, CatalogStoreError> {
        let mut meter = Meter {
            budget,
            used: Work::default(),
        };
        // Encode, expected-tip guard, write and both publication readbacks.
        meter.charge(TIP_BYTES * 5 + ROW_BYTES * 4, 9)?;
        meter.charge(
            canonical_size_bounded(genesis, GUILD_AUTHORITY_SNAPSHOT_BYTES)?,
            1,
        )?;
        let authority = GuildAuthoritySnapshot::from_genesis(genesis)?;
        if control.record_length(TIP, KEY)?.is_some() {
            return Err(DatabaseError::Conflict.into());
        }
        for name in ROW_KINDS {
            // Empty-namespace admission is repeated under the durable writer.
            meter.charge(ROW_BYTES * 2, 2)?;
            if control
                .next_record_metadata_bounded(kind(name), None, 40)?
                .is_some()
            {
                return Err(DatabaseError::Conflict.into());
            }
        }
        let roster = canonical_bytes_bounded(&authority, GUILD_AUTHORITY_SNAPSHOT_BYTES)?;
        let tip = canonical_bytes_bounded(&historical::Tip::initial(&authority), ROW_BYTES)?;
        let mut patches = Vec::with_capacity(2);
        for (name, key, body) in [
            (MEMBERS, 1_u64.to_be_bytes(), roster),
            (EVENTS, 0_u64.to_be_bytes(), tip),
        ] {
            meter.charge((HEADER + body.len()) * 3, 3)?;
            patches.push(Patch {
                name,
                key: key.to_vec(),
                expected: None,
                next: Some(wrap(authority.event_head, name, &key, &body)?),
            });
        }
        let mut manifest = DurableManifest {
            format_version: 1,
            genesis_hash: authority.event_head,
            authority,
            retained: 0,
            retired: 0,
            incarnations: 0,
            work: meter.used,
            checksum: [0; 32],
        };
        let encoded = manifest.encode()?;
        Ok(CatalogGuildHistoryMutation {
            expected: None,
            manifest,
            encoded,
            patches,
            step_work: meter.used,
        })
    }

    /// One original event, including full non-membership effects and original
    /// witness replay. No proof or filesystem work holds the durable writer.
    pub fn prepare_advance(
        &self,
        control: &ControlStore,
        event: &QuorumGuildEvent,
        budget: Work,
        source: &mut impl CatalogGuildHistorySource,
    ) -> Result<CatalogGuildHistoryMutation, CatalogStoreError> {
        let mut meter = Meter {
            budget,
            used: Work::default(),
        };
        meter.charge(TIP_BYTES * 5 + ROW_BYTES * 4, 9)?;
        meter.charge(canonical_size_bounded(event, GUILD_EVENT_BYTES)?, 1)?;
        // At most eight bounded point rows, plus indexes/journal rounding.
        let overlay_bytes =
            8 * (GUILD_AUTHORITY_SNAPSHOT_BYTES as u64 + GUILD_EVENT_BYTES as u64) + 8 * 4096;
        #[cfg(target_os = "linux")]
        let scratch = RecordScratchStore::new_in_with_checkpoint_reservations(
            control
                .path
                .parent()
                .ok_or(DatabaseError::ScratchUnavailable)?,
            crate::ScratchStorageLimits::for_database(overlay_bytes)?,
            std::slice::from_ref(&control.path),
        )?;
        #[cfg(not(target_os = "linux"))]
        let scratch = RecordScratchStore::new(overlay_bytes)?;
        let mut guards = BTreeMap::new();
        let mut authority = self.manifest.authority.clone();
        let mut retained = self.manifest.retained;
        let mut retired = self.manifest.retired;
        let genesis = self.manifest.genesis_hash;
        let mut source = CachedSource {
            source,
            transcript: None,
        };
        scratch.with_record_transaction(|| -> Result<(), CatalogStoreError> {
            authority.advance_indexed(
                event,
                |before, original| -> Result<(), CatalogStoreError> {
                    let mut locations = Vec::with_capacity(3);
                    match &original.kind {
                        GuildEventKind::RotateWriterKey { owner, epoch, .. } => {
                            locations.push((LATEST_WRITER, owner.0.to_vec()));
                            locations.push((WRITERS, epoch_key(*owner, *epoch).to_vec()));
                        }
                        GuildEventKind::RevokeWriterKey { owner, epoch } => {
                            locations.push((WRITERS, epoch_key(*owner, *epoch).to_vec()))
                        }
                        GuildEventKind::RotateRecoveryKey { envelope } => {
                            locations.push((LATEST_RECOVERY, envelope.subject.0.to_vec()));
                            locations.push((
                                RECOVERY,
                                epoch_key(envelope.subject, envelope.epoch).to_vec(),
                            ));
                        }
                        GuildEventKind::RevokeRecoveryKey { subject, epoch } => {
                            locations.push((RECOVERY, epoch_key(*subject, *epoch).to_vec()))
                        }
                        GuildEventKind::AddCodingGroup { group }
                        | GuildEventKind::AddCodingGroupBound { group, .. } => {
                            locations.push((GROUPS, group.id.to_vec()));
                            locations.push((
                                ARCHIVE,
                                historical::incarnation_key(group.id, original.sequence).to_vec(),
                            ));
                            let object = CatalogGuildHistoryObject::Transcript(original.hash()?);
                            let bytes = fetch(
                                &mut source,
                                &mut meter,
                                object,
                                None,
                                CATALOG_CODING_TRANSCRIPT_BYTES,
                            )?;
                            let transcript = decode_coding_transcript_bounded(&bytes)?;
                            locations.push((
                                MEMBERS,
                                transcript
                                    .value
                                    .plan
                                    .value
                                    .membership_epoch
                                    .to_be_bytes()
                                    .to_vec(),
                            ));
                            source.transcript = Some((object, bytes));
                        }
                        GuildEventKind::RetireCodingGroup { group_id, .. }
                        | GuildEventKind::ForgetCodingGroup { group_id } => {
                            seed(
                                control,
                                &scratch,
                                &mut meter,
                                &mut guards,
                                genesis,
                                GROUPS,
                                group_id,
                            )?;
                            let (group, _) =
                                get::<Group>(&scratch, &mut meter, GROUPS, group_id, GROUP_BYTES)?
                                    .ok_or(DatabaseError::Conflict)?;
                            validate_group(&group, group_id, before.event_sequence)?;
                            locations.push((
                                ARCHIVE,
                                historical::incarnation_key(
                                    *group_id,
                                    group.retained.added_at_event,
                                )
                                .to_vec(),
                            ));
                        }
                        _ => return Err(DatabaseError::Integrity.into()),
                    }
                    for (name, key) in locations {
                        seed(
                            control,
                            &scratch,
                            &mut meter,
                            &mut guards,
                            genesis,
                            name,
                            &key,
                        )?;
                    }
                    apply_effect(
                        &scratch,
                        &mut meter,
                        &mut source,
                        before,
                        event,
                        &mut retained,
                        &mut retired,
                    )
                },
            )?;
            if authority.membership_epoch != self.manifest.authority.membership_epoch {
                let key = authority.membership_epoch.to_be_bytes();
                seed(
                    control,
                    &scratch,
                    &mut meter,
                    &mut guards,
                    genesis,
                    MEMBERS,
                    &key,
                )?;
                write(
                    &scratch,
                    &mut meter,
                    MEMBERS,
                    &key,
                    &authority,
                    GUILD_AUTHORITY_SNAPSHOT_BYTES,
                    None,
                )?;
            }
            let key = authority.event_sequence.to_be_bytes();
            seed(
                control,
                &scratch,
                &mut meter,
                &mut guards,
                genesis,
                EVENTS,
                &key,
            )?;
            historical::write_tip(&scratch, &mut meter, &authority, retained, retired)?;
            Ok(())
        })?;
        let mut patches = Vec::with_capacity(guards.len());
        for ((name, key), expected) in guards {
            meter.metadata()?;
            let next = match scratch.record_length(name, &key)? {
                Some(length) => {
                    if length > limit(name) {
                        return Err(DatabaseError::Integrity.into());
                    }
                    // Overlay read, durable write and both publication
                    // readbacks. Guard-only point rows reserve the same cap.
                    meter.charge((length + HEADER) * 4, 4)?;
                    let body = scratch
                        .get_record_bounded(name, &key, length)?
                        .ok_or(DatabaseError::Integrity)?;
                    Some(wrap(genesis, name, &key, &body)?)
                }
                None => None,
            };
            patches.push(Patch {
                name,
                key,
                expected,
                next,
            });
        }
        let mut manifest = DurableManifest {
            format_version: 1,
            genesis_hash: genesis,
            authority,
            retained,
            retired,
            incarnations: self
                .manifest
                .incarnations
                .checked_add(u64::from(event.event.kind.coding_group_add().is_some()))
                .ok_or(CatalogError::Bounds)?,
            work: self.manifest.work.checked_add(meter.used)?,
            checksum: [0; 32],
        };
        let encoded = manifest.encode()?;
        Ok(CatalogGuildHistoryMutation {
            expected: Some(self.encoded.clone()),
            manifest,
            encoded,
            patches,
            step_work: meter.used,
        })
    }

    pub fn view<'a>(
        &'a self,
        control: &'a ControlStore,
        genesis: [u8; 32],
        authority: &GuildAuthoritySnapshot,
    ) -> Result<CatalogDurableGuildHistoryView<'a>, CatalogStoreError> {
        if genesis != self.genesis_hash() || authority != self.authority() {
            return Err(DatabaseError::Conflict.into());
        }
        self.check(control)?;
        Ok(CatalogDurableGuildHistoryView {
            history: self,
            control,
        })
    }
    fn check(&self, control: &ControlStore) -> Result<(), CatalogStoreError> {
        if control.get_record_bounded(TIP, KEY, TIP_BYTES)?.as_deref()
            != Some(self.encoded.as_slice())
        {
            return Err(DatabaseError::Conflict.into());
        }
        Ok(())
    }
}

impl CatalogGuildHistoryMutation {
    pub fn authority(&self) -> &GuildAuthoritySnapshot {
        &self.manifest.authority
    }
    pub fn step_work(&self) -> Work {
        self.step_work
    }
    pub fn commit(&self, control: &ControlStore) -> Result<(), CatalogStoreError> {
        control.with_record_transaction(|| self.apply_in_transaction(control))
    }
    /// Join the accepted-original-record transaction. An enclosing transaction
    /// is mandatory, and callers must verify again after their last mutation.
    pub fn apply_in_transaction(&self, control: &ControlStore) -> Result<(), CatalogStoreError> {
        if control.connection.is_autocommit() {
            return Err(DatabaseError::Conflict.into());
        }
        if control.get_record_bounded(TIP, KEY, TIP_BYTES)? != self.expected {
            return Err(DatabaseError::Conflict.into());
        }
        if self.expected.is_none() {
            for name in ROW_KINDS {
                if control
                    .next_record_metadata_bounded(kind(name), None, 40)?
                    .is_some()
                {
                    return Err(DatabaseError::Conflict.into());
                }
            }
        }
        for patch in &self.patches {
            if control.get_record_bounded(
                kind(patch.name),
                &patch.key,
                limit(patch.name) + HEADER,
            )? != patch.expected
            {
                return Err(DatabaseError::Conflict.into());
            }
        }
        for patch in &self.patches {
            if patch.expected == patch.next {
                continue;
            }
            match (&patch.expected, &patch.next) {
                (Some(old), Some(next)) => {
                    control.replace_record_if_value(kind(patch.name), &patch.key, old, next)?
                }
                (None, Some(next)) => {
                    if !control.put_record_if_absent(kind(patch.name), &patch.key, next)? {
                        return Err(DatabaseError::Conflict.into());
                    }
                }
                (Some(old), None) => {
                    control.delete_record_if_value(kind(patch.name), &patch.key, old)?
                }
                (None, None) => {}
            }
        }
        match &self.expected {
            Some(old) if old != &self.encoded => {
                control.replace_record_if_value(TIP, KEY, old, &self.encoded)?;
            }
            Some(_) => {}
            None => {
                if !control.put_record_if_absent(TIP, KEY, &self.encoded)? {
                    return Err(DatabaseError::Conflict.into());
                }
            }
        }
        self.verify_published(control)
    }
    pub fn verify_published(&self, control: &ControlStore) -> Result<(), CatalogStoreError> {
        if control.get_record_bounded(TIP, KEY, TIP_BYTES)?.as_deref()
            != Some(self.encoded.as_slice())
        {
            return Err(DatabaseError::Integrity.into());
        }
        for patch in &self.patches {
            if control.get_record_bounded(
                kind(patch.name),
                &patch.key,
                limit(patch.name) + HEADER,
            )? != patch.next
            {
                return Err(DatabaseError::Integrity.into());
            }
        }
        Ok(())
    }
}

pub struct CatalogDurableGuildHistoryView<'a> {
    history: &'a CatalogDurableGuildHistory,
    control: &'a ControlStore,
}
impl CatalogDurableGuildHistoryView<'_> {
    fn point<T: DeserializeOwned + Serialize>(
        &self,
        name: &str,
        key: &[u8],
    ) -> Result<Option<T>, CatalogStoreError> {
        self.history.check(self.control)?;
        let encoded = self
            .control
            .get_record_bounded(kind(name), key, limit(name) + HEADER)?;
        let value = encoded
            .as_ref()
            .map(|bytes| -> Result<T, CatalogStoreError> {
                let body = unwrap(self.history.genesis_hash(), name, key, bytes)?;
                let value = decode_canonical(body)?;
                if canonical_bytes_bounded(&value, limit(name))? != body {
                    return Err(DatabaseError::Integrity.into());
                }
                Ok(value)
            })
            .transpose()?;
        if self
            .control
            .get_record_bounded(kind(name), key, limit(name) + HEADER)?
            != encoded
        {
            return Err(DatabaseError::Conflict.into());
        }
        self.history.check(self.control)?;
        Ok(value)
    }
    pub fn retained_group(
        &self,
        id: [u8; 32],
    ) -> Result<Option<RetainedCodingGroup>, CatalogStoreError> {
        let Some(group) = self.point::<Group>(GROUPS, &id)? else {
            return Ok(None);
        };
        validate_group(&group, &id, self.history.authority().event_sequence)?;
        if group.retained.group.guild_id != self.history.authority().guild_id {
            return Err(DatabaseError::Integrity.into());
        }
        Ok(Some(group.retained))
    }
    pub fn writer_key(
        &self,
        owner: NodeId,
        epoch: u64,
    ) -> Result<Option<WriterKeyEpoch>, CatalogStoreError> {
        let value = self.point::<WriterKeyEpoch>(WRITERS, &epoch_key(owner, epoch))?;
        if let Some(value) = &value {
            validate_writer(value, owner, epoch, self.history.authority().event_sequence)?;
        }
        Ok(value)
    }
    pub fn recovery_key(
        &self,
        owner: NodeId,
        epoch: u64,
    ) -> Result<Option<RecoveryKeyEpoch>, CatalogStoreError> {
        let value = self.point::<RecoveryKeyEpoch>(RECOVERY, &epoch_key(owner, epoch))?;
        if let Some(value) = &value {
            validate_recovery(
                value,
                owner,
                epoch,
                self.history.authority().guild_id,
                self.history.authority().event_sequence,
            )?;
        }
        Ok(value)
    }
}
