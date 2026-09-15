use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail};
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use mb_core::{
    KeyMaterial, SectorId, SectorPurpose, SectorRef, SignedRecord, USER_REVISION_DOMAIN,
    UserRevision, V1_CIPHER_PROFILE, V1_MAX_CATALOG_BYTES, V1_MAX_CODING_GROUPS, V1_SECTOR_SIZE,
    canonical_bytes, crypt_sector, decode_canonical, encrypted_sector, make_sector_id, sector_root,
};
use mb_store::{
    AnchorFileLocator, CapturedEntry, ControlStore, FileExtent, NativeFileId, PinnedDirectory,
    ReflinkAnchor, ReflinkCapturePlan, StableAnchorFileLocator,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

type RecordWrite = (String, Vec<u8>, Vec<u8>);
const ANCHOR_AREA_LOCATION_KIND: &str = "anchor-area-location";
const RECOVERY_ANCHOR_INTENT_KIND: &str = "recovery-anchor-intent";
const ANCHOR_RETIREMENT_KIND: &str = "anchor-retirement";
const MAX_METADATA_SECTORS: usize = V1_MAX_CATALOG_BYTES.div_ceil(V1_SECTOR_SIZE);
const MAX_DATA_SECTORS: usize = V1_MAX_CODING_GROUPS - MAX_METADATA_SECTORS;
const RESTORE_JOB_KIND: &str = "restore-job";

#[cfg(test)]
type RestoreRenameHook = Box<dyn FnOnce() -> Result<()>>;

#[cfg(test)]
thread_local! {
    static INTERRUPT_RECOVERY_ANCHOR_AFTER_CAPTURE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static INTERRUPT_AFTER_LEGACY_RESTORE_RETIRE: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
    static AFTER_RESTORE_RENAME: std::cell::RefCell<Option<RestoreRenameHook>> =
        std::cell::RefCell::new(None);
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
        data_extents: Vec<PrivateDataExtent>,
    },
    HardLinkV3 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateDataExtent {
    pub offset: u64,
    pub logical_len: u64,
    pub sectors: Vec<SectorRef>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PrivateMetadata {
    pub format_version: u16,
    pub root_mode: u32,
    pub root_modified_secs: i64,
    pub root_modified_nanos: u32,
    pub entries: Vec<PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum RestoreJobState {
    Building,
    Publishing,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RestoreJob {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target: PathBuf,
    parent_identity: NativeFileId,
    staging_name: String,
    staged_identity: Option<NativeFileId>,
    state: RestoreJobState,
}

struct ReservedRestoreJob {
    record_id: [u8; 32],
    bytes: Vec<u8>,
    job: RestoreJob,
}

struct RestoreOperationGuard(File);

// Private metadata version 2 existed briefly with two different positional
// postcard layouts. Keep both wire types immutable: changing PrivateEntry
// cannot make either historical layout disappear from recovery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct NativeV2PrivateMetadata {
    format_version: u16,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<NativeV2PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum NativeV2PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        native_id: NativeFileId,
        data_extents: Vec<PrivateDataExtent>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LinkV2PrivateMetadata {
    format_version: u16,
    root_mode: u32,
    root_modified_secs: i64,
    root_modified_nanos: u32,
    entries: Vec<LinkV2PrivateEntry>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LinkV2PrivateEntry {
    Directory {
        path: String,
        mode: u32,
        modified_secs: i64,
        modified_nanos: u32,
    },
    File {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        sectors: Vec<SectorRef>,
    },
    FileV2 {
        path: String,
        mode: u32,
        logical_len: u64,
        modified_secs: i64,
        modified_nanos: u32,
        link_group: u64,
        data_extents: Vec<PrivateDataExtent>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct LocalSectorRecipe {
    guild_id: [u8; 32],
    reference: SectorRef,
    source: LocalPlaintextSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum LocalPlaintextSource {
    AnchorFile {
        locator: AnchorFileLocator,
        offset: u64,
    },
    Inline(Vec<u8>),
    StableAnchorFile {
        locator: StableAnchorFileLocator,
        offset: u64,
    },
}

struct PendingAnchor {
    manifest: mb_store::StableAnchorManifest,
    committed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CaptureIntent {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    sequence: u64,
    parent: Option<[u8; 32]>,
    captured_change_sequence: Option<u64>,
    requested_source: PathBuf,
    plan: ReflinkCapturePlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyCaptureIntentV1 {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    sequence: u64,
    parent: Option<[u8; 32]>,
    requested_source: PathBuf,
    plan: ReflinkCapturePlan,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RecoveryAnchorIntent {
    format_version: u16,
    guild_id: [u8; 32],
    revision_id: Uuid,
    source_root: PathBuf,
    plan: ReflinkCapturePlan,
    replaced_anchor: Option<mb_store::StableAnchorManifest>,
}

pub(crate) fn reconcile_pending_captures(control: &ControlStore) -> Result<()> {
    for (record_id, bytes) in control.records("capture-intent")? {
        let (intent, migrated) = match decode_canonical::<CaptureIntent>(&bytes) {
            Ok(intent) => (intent, false),
            Err(current_error) => {
                let legacy: LegacyCaptureIntentV1 =
                    decode_canonical(&bytes).with_context(|| {
                        format!("pending source capture is undecodable: {current_error}")
                    })?;
                if legacy.format_version != 1 {
                    bail!("pending source capture has an unsupported version");
                }
                (
                    CaptureIntent {
                        format_version: 2,
                        guild_id: legacy.guild_id,
                        revision_id: legacy.revision_id,
                        sequence: legacy.sequence,
                        parent: legacy.parent,
                        captured_change_sequence: None,
                        requested_source: legacy.requested_source,
                        plan: legacy.plan,
                    },
                    true,
                )
            }
        };
        if intent.format_version != 2 || record_id.as_slice() != intent.revision_id.as_bytes() {
            bail!("pending source capture is inconsistent");
        }
        if migrated {
            control.put_record("capture-intent", &record_id, &canonical_bytes(&intent)?)?;
        }
        // An offline source volume must not prevent unrelated guilds from
        // starting. The exact plan remains durable for a later explicit retry.
        let _ = ReflinkAnchor::reconcile_capture(&intent.plan);
    }
    for (record_id, bytes) in control.records(RECOVERY_ANCHOR_INTENT_KIND)? {
        let intent: RecoveryAnchorIntent = decode_canonical(&bytes)?;
        if intent.format_version != 1 || record_id.as_slice() != intent.revision_id.as_bytes() {
            bail!("pending recovered-anchor capture is inconsistent");
        }
        let _ = ReflinkAnchor::reconcile_capture(&intent.plan);
    }
    reconcile_anchor_retirements(control)?;
    Ok(())
}

fn reconcile_anchor_retirements(control: &ControlStore) -> Result<()> {
    for (record_id, bytes) in control.records(ANCHOR_RETIREMENT_KIND)? {
        let manifest: mb_store::StableAnchorManifest = decode_canonical(&bytes)?;
        if record_id.as_slice() != manifest.anchor_id.as_bytes() {
            bail!("durable anchor retirement is inconsistent");
        }
        if manifest.remove().is_ok() {
            let _ = control.delete_record(ANCHOR_RETIREMENT_KIND, &record_id)?;
        }
    }
    Ok(())
}

pub(crate) fn retire_revision_anchor(control: &mut ControlStore, revision_id: Uuid) -> Result<()> {
    let Some(bytes) = control.get_record("anchor-manifest", revision_id.as_bytes())? else {
        return Ok(());
    };
    let manifest: mb_store::StableAnchorManifest = decode_canonical(&bytes)?;
    control.move_protocol_record(
        "anchor-manifest",
        revision_id.as_bytes(),
        &bytes,
        ANCHOR_RETIREMENT_KIND,
        manifest.anchor_id.as_bytes(),
    )?;
    if manifest.remove().is_ok() {
        let _ = control.delete_record(ANCHOR_RETIREMENT_KIND, manifest.anchor_id.as_bytes())?;
    }
    Ok(())
}

pub(crate) fn abandon_recovered_anchor_capture(
    control: &ControlStore,
    guild_id: [u8; 32],
    revision_id: Uuid,
) -> Result<()> {
    let Some(bytes) = control.get_record(RECOVERY_ANCHOR_INTENT_KIND, revision_id.as_bytes())?
    else {
        return Ok(());
    };
    let intent: RecoveryAnchorIntent = decode_canonical(&bytes)?;
    if intent.format_version != 1
        || intent.guild_id != guild_id
        || intent.revision_id != revision_id
    {
        bail!("pending recovered-anchor capture conflicts with the recovery job");
    }
    ReflinkAnchor::discard_capture(&intent.plan)
        .context("discard recovered-anchor capture whose restored source was lost")?;
    if !control.delete_record(RECOVERY_ANCHOR_INTENT_KIND, revision_id.as_bytes())? {
        bail!("pending recovered-anchor capture disappeared");
    }
    Ok(())
}

impl PendingAnchor {
    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for PendingAnchor {
    fn drop(&mut self) {
        if !self.committed {
            let _ = self.manifest.remove();
        }
    }
}

pub(crate) struct WriterCredentials<'a> {
    pub epoch: u64,
    pub secret: &'a [u8; 32],
    pub captured_change_sequence: Option<u64>,
}

pub(crate) fn prepare_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    source_root: &Path,
    sequence: u64,
    revision_id: Option<Uuid>,
    writer: WriterCredentials<'_>,
) -> Result<SignedRecord<UserRevision>> {
    let writer_epoch = writer.epoch;
    let writer_secret = writer.secret;
    let captured_change_sequence = writer.captured_change_sequence;
    let revision_id = revision_id.unwrap_or_else(Uuid::new_v4);
    if let Some(bytes) = control.get_record("user-revision", revision_id.as_bytes())? {
        let existing: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
        existing.verify(USER_REVISION_DOMAIN)?;
        existing.value.verify_writer()?;
        if existing.value.revision_id != revision_id
            || existing.value.owner != keys.node_id()
            || existing.value.guild_id != guild_id
            || existing.value.sequence != sequence
            || existing.value.writer_epoch != writer_epoch
            || existing.value.writer_public_key
                != SigningKey::from_bytes(writer_secret)
                    .verifying_key()
                    .to_bytes()
        {
            bail!("persisted revision does not match the retried operation");
        }
        return Ok(existing);
    }
    let parent = match control.get_record("user-revision-head", &guild_id)? {
        Some(bytes) => {
            let previous: SignedRecord<UserRevision> = decode_canonical(&bytes)?;
            previous.verify(USER_REVISION_DOMAIN)?;
            previous.value.verify_writer()?;
            if previous.signer != keys.node_id()
                || previous.value.owner != keys.node_id()
                || previous.value.guild_id != guild_id
                || previous.value.format_version != 2
                || previous.value.cipher_profile != V1_CIPHER_PROFILE
                || previous.value.sequence.checked_add(1) != Some(sequence)
            {
                bail!("new revision does not extend the durable local revision head");
            }
            Some(previous.value.hash()?)
        }
        None if sequence == 1 => None,
        None => bail!("the first local revision must have sequence one"),
    };
    let (intent, intent_bytes) =
        match control.get_record("capture-intent", revision_id.as_bytes())? {
            Some(bytes) => {
                let intent: CaptureIntent = decode_canonical(&bytes)?;
                if intent.format_version != 2
                    || intent.guild_id != guild_id
                    || intent.revision_id != revision_id
                    || intent.sequence != sequence
                    || intent.parent != parent
                    || intent.requested_source != source_root
                {
                    bail!("pending source capture conflicts with the retried operation");
                }
                (intent, bytes)
            }
            None => {
                let intent = CaptureIntent {
                    format_version: 2,
                    guild_id,
                    revision_id,
                    sequence,
                    parent,
                    captured_change_sequence,
                    requested_source: source_root.to_path_buf(),
                    plan: ReflinkAnchor::plan(source_root).context("plan reflink source anchor")?,
                };
                let bytes = canonical_bytes(&intent)?;
                control.put_record("capture-intent", revision_id.as_bytes(), &bytes)?;
                (intent, bytes)
            }
        };
    let result = (|| {
        let mut anchor = PendingAnchor {
            manifest: ReflinkAnchor::capture_plan(&intent.plan)
                .context("capture reflink source anchor")?,
            committed: false,
        };
        if canonical_bytes(&anchor.manifest)?.len() > V1_MAX_CATALOG_BYTES / 2 {
            bail!("captured source catalog exceeds the v1 bounded-object limit");
        }
        validate_capture_sector_budget(&anchor.manifest)?;
        let encryption_key = keys.guild_data_key(&guild_id);
        let mut data_references = Vec::new();
        let mut private_entries = Vec::new();
        let mut recipe_records = Vec::with_capacity(256);
        let mut ordinal = 0_u64;
        let mut prepared_links = BTreeMap::<NativeFileId, u64>::new();
        let mut next_link_group = 0_u64;

        for entry in &anchor.manifest.entries {
            match entry {
                CapturedEntry::Directory {
                    path,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => {
                    private_entries.push(PrivateEntry::Directory {
                        path: path.clone(),
                        mode: *mode,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                    });
                }
                CapturedEntry::File {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                } => {
                    let locator = anchor.manifest.file_locator(path.clone())?;
                    let mut file = locator.open().context("open captured anchor file")?;
                    let mut remaining = *logical_len;
                    let mut offset = 0_u64;
                    let mut file_references = Vec::new();
                    while remaining > 0 {
                        let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as usize;
                        let mut plaintext = vec![0_u8; logical_len];
                        file.read_exact(&mut plaintext)?;
                        let id = make_sector_id(
                            keys.node_id(),
                            revision_id,
                            SectorPurpose::Data,
                            ordinal,
                        );
                        ordinal += 1;
                        let (reference, _) = encrypted_sector(&encryption_key, id, &plaintext)?;
                        push_data_reference(&mut data_references, reference.clone())?;
                        file_references.push(reference.clone());
                        queue_recipe(
                            &mut recipe_records,
                            LocalSectorRecipe {
                                guild_id,
                                reference,
                                source: LocalPlaintextSource::StableAnchorFile {
                                    locator: locator.clone(),
                                    offset,
                                },
                            },
                        )?;
                        offset += logical_len as u64;
                        remaining -= logical_len as u64;
                    }
                    private_entries.push(PrivateEntry::File {
                        path: path.clone(),
                        mode: *mode,
                        logical_len: *logical_len,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                        sectors: file_references,
                    });
                }
                CapturedEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    native_id,
                    data_extents,
                } => {
                    if let Some(link_group) = prepared_links.get(native_id) {
                        private_entries.push(PrivateEntry::HardLinkV3 {
                            path: path.clone(),
                            mode: *mode,
                            logical_len: *logical_len,
                            modified_secs: *modified_secs,
                            modified_nanos: *modified_nanos,
                            link_group: *link_group,
                        });
                        continue;
                    }
                    let locator = anchor.manifest.file_locator(path.clone())?;
                    let private_extents = prepare_sparse_file(
                        &mut recipe_records,
                        keys,
                        guild_id,
                        revision_id,
                        &mut ordinal,
                        &locator,
                        *logical_len,
                        data_extents,
                    )?;
                    for reference in private_extents
                        .iter()
                        .flat_map(|extent| extent.sectors.iter())
                    {
                        push_data_reference(&mut data_references, reference.clone())?;
                    }
                    let link_group = next_link_group;
                    next_link_group = next_link_group
                        .checked_add(1)
                        .context("too many hard-link groups in one revision")?;
                    prepared_links.insert(*native_id, link_group);
                    private_entries.push(PrivateEntry::FileV2 {
                        path: path.clone(),
                        mode: *mode,
                        logical_len: *logical_len,
                        modified_secs: *modified_secs,
                        modified_nanos: *modified_nanos,
                        link_group,
                        data_extents: private_extents,
                    });
                }
            }
        }

        let metadata = PrivateMetadata {
            format_version: 3,
            root_mode: anchor.manifest.root_mode,
            root_modified_secs: anchor.manifest.root_modified_secs,
            root_modified_nanos: anchor.manifest.root_modified_nanos,
            entries: private_entries,
        };
        let metadata_bytes = canonical_bytes(&metadata)?;
        if metadata_bytes.is_empty() || metadata_bytes.len() > V1_MAX_CATALOG_BYTES {
            bail!("private metadata exceeds the v1 bounded-object limit");
        }
        let mut metadata_references = Vec::new();
        for (metadata_ordinal, plaintext) in metadata_bytes.chunks(V1_SECTOR_SIZE).enumerate() {
            let id = make_sector_id(
                keys.node_id(),
                revision_id,
                SectorPurpose::Metadata,
                metadata_ordinal as u64,
            );
            let (reference, _) = encrypted_sector(&encryption_key, id, plaintext)?;
            metadata_references.push(reference.clone());
            queue_recipe(
                &mut recipe_records,
                LocalSectorRecipe {
                    guild_id,
                    reference,
                    source: LocalPlaintextSource::Inline(plaintext.to_vec()),
                },
            )?;
        }

        let writer = SigningKey::from_bytes(writer_secret);
        let mut revision = UserRevision {
            format_version: 2,
            guild_id,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            writer_epoch,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence,
            parent,
            metadata_sectors: metadata_references,
            data_sectors: data_references,
        };
        revision.sign_writer(&writer)?;
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision, keys)?;
        if canonical_bytes(&revision)?.len() > V1_MAX_CATALOG_BYTES {
            bail!("revision catalog exceeds the v1 bounded-object limit");
        }
        let mut records = recipe_records;
        records.extend([
            (
                ANCHOR_AREA_LOCATION_KIND.to_owned(),
                anchor.manifest.area.area_id.as_bytes().to_vec(),
                canonical_bytes(&anchor.manifest.area.path_hint)?,
            ),
            (
                "anchor-manifest".to_owned(),
                revision_id.as_bytes().to_vec(),
                canonical_bytes(&anchor.manifest)?,
            ),
            (
                "user-revision".to_owned(),
                revision_id.as_bytes().to_vec(),
                canonical_bytes(&revision)?,
            ),
            (
                "user-revision-head".to_owned(),
                guild_id.to_vec(),
                canonical_bytes(&revision)?,
            ),
        ]);
        if let Some(captured_change_sequence) = intent.captured_change_sequence {
            records.push((
                "revision-root-change".to_owned(),
                revision_id.as_bytes().to_vec(),
                canonical_bytes(&captured_change_sequence)?,
            ));
        }
        control.finalize_capture_records(revision_id.as_bytes(), &records)?;
        anchor.commit();
        Ok(revision)
    })();
    match result {
        Ok(revision) => Ok(revision),
        Err(error) => {
            ReflinkAnchor::discard_capture(&intent.plan)
                .context("discard failed reflink source capture")?;
            control
                .abandon_capture_intent(revision_id.as_bytes(), &intent_bytes)
                .context("retire failed source-capture intent")?;
            Err(error)
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn prepare_sparse_file(
    recipe_records: &mut Vec<RecordWrite>,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision_id: Uuid,
    ordinal: &mut u64,
    locator: &StableAnchorFileLocator,
    logical_len: u64,
    extents: &[FileExtent],
) -> Result<Vec<PrivateDataExtent>> {
    validate_file_extents(
        logical_len,
        extents
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)),
    )?;
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut file = locator.open().context("open captured anchor file")?;
    let mut result = Vec::with_capacity(extents.len());
    for extent in extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        let mut remaining = extent.logical_len;
        let mut offset = extent.offset;
        let mut sectors = Vec::new();
        while remaining > 0 {
            let logical_len = remaining.min(V1_SECTOR_SIZE as u64) as usize;
            let mut plaintext = vec![0_u8; logical_len];
            file.read_exact(&mut plaintext)?;
            let id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, *ordinal);
            *ordinal = ordinal
                .checked_add(1)
                .context("too many sectors in one revision")?;
            let (reference, _) = encrypted_sector(&encryption_key, id, &plaintext)?;
            sectors.push(reference.clone());
            queue_recipe(
                recipe_records,
                LocalSectorRecipe {
                    guild_id,
                    reference,
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                },
            )?;
            offset += logical_len as u64;
            remaining -= logical_len as u64;
        }
        result.push(PrivateDataExtent {
            offset: extent.offset,
            logical_len: extent.logical_len,
            sectors,
        });
    }
    Ok(result)
}

fn validate_file_extents(
    logical_len: u64,
    extents: impl IntoIterator<Item = (u64, u64)>,
) -> Result<()> {
    let mut previous_end = 0_u64;
    for (offset, extent_len) in extents {
        let end = offset
            .checked_add(extent_len)
            .context("file extent overflows its signed range")?;
        if extent_len == 0 || offset < previous_end || end > logical_len {
            bail!("invalid or overlapping file extent");
        }
        previous_end = end;
    }
    Ok(())
}

fn queue_recipe(records: &mut Vec<RecordWrite>, recipe: LocalSectorRecipe) -> Result<()> {
    records.push((
        "local-sector".to_owned(),
        recipe.reference.id.to_vec(),
        canonical_bytes(&recipe)?,
    ));
    Ok(())
}

fn push_data_reference(references: &mut Vec<SectorRef>, reference: SectorRef) -> Result<()> {
    if references.len() >= MAX_DATA_SECTORS {
        bail!("source data exceeds the bounded v1 coding catalog");
    }
    references.push(reference);
    Ok(())
}

fn validate_capture_sector_budget(manifest: &mb_store::StableAnchorManifest) -> Result<()> {
    let mut sectors = 0_usize;
    let mut seen_files = BTreeSet::new();
    for entry in &manifest.entries {
        let additional = match entry {
            CapturedEntry::Directory { .. } => 0,
            CapturedEntry::File { logical_len, .. } => {
                usize::try_from(logical_len.div_ceil(V1_SECTOR_SIZE as u64))
                    .context("captured file is too large for this platform")?
            }
            CapturedEntry::FileV2 {
                native_id,
                data_extents,
                ..
            } if seen_files.insert(*native_id) => {
                data_extents.iter().try_fold(0_usize, |count, extent| {
                    let extent_sectors =
                        usize::try_from(extent.logical_len.div_ceil(V1_SECTOR_SIZE as u64))
                            .context("captured extent is too large for this platform")?;
                    count
                        .checked_add(extent_sectors)
                        .context("captured sector count overflow")
                })?
            }
            CapturedEntry::FileV2 { .. } => 0,
        };
        sectors = sectors
            .checked_add(additional)
            .context("captured sector count overflow")?;
        if sectors > MAX_DATA_SECTORS {
            bail!("source data exceeds the bounded v1 coding catalog");
        }
    }
    Ok(())
}

fn checked_metadata_length(revision: &SignedRecord<UserRevision>) -> Result<usize> {
    if revision.value.metadata_sectors.is_empty()
        || revision.value.metadata_sectors.len() > MAX_METADATA_SECTORS
        || revision
            .value
            .metadata_sectors
            .len()
            .saturating_add(revision.value.data_sectors.len())
            > V1_MAX_CODING_GROUPS
    {
        bail!("revision exceeds the bounded v1 metadata or coding catalog");
    }
    revision
        .value
        .metadata_sectors
        .iter()
        .try_fold(0_usize, |total, reference| {
            let length = usize::try_from(reference.logical_len)
                .context("metadata sector length does not fit memory")?;
            let total = total
                .checked_add(length)
                .context("private metadata length overflow")?;
            if length == 0 || length > V1_SECTOR_SIZE || total > V1_MAX_CATALOG_BYTES {
                bail!("private metadata exceeds the bounded v1 object limit");
            }
            Ok(total)
        })
}

pub(crate) fn install_inline_recipe(
    control: &mut ControlStore,
    guild_id: [u8; 32],
    reference: SectorRef,
    plaintext: Vec<u8>,
) -> Result<()> {
    let recipe = LocalSectorRecipe {
        guild_id,
        reference: reference.clone(),
        source: LocalPlaintextSource::Inline(plaintext),
    };
    control.put_record("local-sector", &reference.id, &canonical_bytes(&recipe)?)?;
    Ok(())
}

pub(crate) fn install_recovered_sector_recipe(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    reference: SectorRef,
    ciphertext: &[u8],
) -> Result<()> {
    if reference.logical_len as usize > V1_SECTOR_SIZE
        || ciphertext.len() != V1_SECTOR_SIZE
        || sector_root(ciphertext) != reference.root
    {
        bail!("recovered information shard does not match its descriptor");
    }
    if render_sector(control, keys, &reference.id, Some(&guild_id))
        .is_ok_and(|existing| existing == ciphertext)
    {
        return Ok(());
    }
    let mut plaintext = ciphertext.to_vec();
    crypt_sector(
        &keys.guild_data_key(&guild_id),
        reference.id,
        &mut plaintext,
    )?;
    plaintext.truncate(reference.logical_len as usize);
    install_inline_recipe(control, guild_id, reference, plaintext)
}

pub(crate) fn reanchor_recovered_revision(
    control: &mut ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &Path,
) -> Result<()> {
    revision.verify(USER_REVISION_DOMAIN)?;
    revision.value.verify_writer()?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
    {
        bail!("recovered revision does not belong to the local seed and guild");
    }
    if revision.value.data_sectors.is_empty() {
        return Ok(());
    }
    reconcile_anchor_retirements(control)?;
    let metadata = load_private_metadata(control, keys, guild_id, revision)?;
    let existing = control.get_record("anchor-manifest", revision.value.revision_id.as_bytes())?;
    let old_manifest = existing
        .as_deref()
        .and_then(|bytes| decode_canonical::<mb_store::StableAnchorManifest>(bytes).ok());
    if let Some(manifest) = old_manifest.as_ref()
        && let Ok(records) = recovered_anchor_records(keys, guild_id, revision, &metadata, manifest)
    {
        if let Some(bytes) = control.get_record(
            RECOVERY_ANCHOR_INTENT_KIND,
            revision.value.revision_id.as_bytes(),
        )? {
            let intent: RecoveryAnchorIntent = decode_canonical(&bytes)?;
            if intent.format_version != 1
                || intent.guild_id != guild_id
                || intent.revision_id != revision.value.revision_id
            {
                bail!("pending recovered-anchor capture conflicts with the revision");
            }
            ReflinkAnchor::discard_capture(&intent.plan)
                .context("discard redundant recovered-anchor capture")?;
            if !control.delete_record(
                RECOVERY_ANCHOR_INTENT_KIND,
                revision.value.revision_id.as_bytes(),
            )? {
                bail!("pending recovered-anchor capture disappeared");
            }
        }
        control.put_records(&records)?;
        return Ok(());
    }

    let canonical_source = restored_root
        .canonicalize()
        .context("resolve recovered source before anchoring")?;
    let (intent, intent_bytes) = match control.get_record(
        RECOVERY_ANCHOR_INTENT_KIND,
        revision.value.revision_id.as_bytes(),
    )? {
        Some(bytes) => {
            let intent: RecoveryAnchorIntent = decode_canonical(&bytes)?;
            if intent.format_version != 1
                || intent.guild_id != guild_id
                || intent.revision_id != revision.value.revision_id
                || intent.source_root != canonical_source
                || intent.replaced_anchor != old_manifest
            {
                bail!("pending recovered-anchor capture conflicts with the revision");
            }
            (intent, bytes)
        }
        None => {
            let plan =
                ReflinkAnchor::plan(&canonical_source).context("plan recovered source anchor")?;
            let intent = RecoveryAnchorIntent {
                format_version: 1,
                guild_id,
                revision_id: revision.value.revision_id,
                source_root: canonical_source,
                plan,
                replaced_anchor: old_manifest.clone(),
            };
            let bytes = canonical_bytes(&intent)?;
            control.put_record(
                RECOVERY_ANCHOR_INTENT_KIND,
                revision.value.revision_id.as_bytes(),
                &bytes,
            )?;
            (intent, bytes)
        }
    };
    let mut anchor = PendingAnchor {
        manifest: ReflinkAnchor::capture_plan(&intent.plan)
            .context("capture recovered source anchor")?,
        committed: false,
    };
    #[cfg(test)]
    if INTERRUPT_RECOVERY_ANCHOR_AFTER_CAPTURE.with(|interrupt| interrupt.replace(false)) {
        anchor.commit();
        bail!("injected interruption after recovered-anchor capture");
    }
    let mut records =
        recovered_anchor_records(keys, guild_id, revision, &metadata, &anchor.manifest)?;
    if let Some(old) = intent.replaced_anchor.as_ref()
        && old.anchor_id != anchor.manifest.anchor_id
    {
        records.push((
            ANCHOR_RETIREMENT_KIND.to_owned(),
            old.anchor_id.as_bytes().to_vec(),
            canonical_bytes(old)?,
        ));
    }
    // The durable intent now owns this completed anchor. Keep it for an exact
    // retry if the following SQL transaction fails or the process stops.
    anchor.commit();
    control.finalize_recovery_anchor_records(
        revision.value.revision_id.as_bytes(),
        &intent_bytes,
        &records,
    )?;
    reconcile_anchor_retirements(control)?;
    Ok(())
}

fn recovered_anchor_records(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<Vec<RecordWrite>> {
    if manifest.format_version != 2 {
        bail!("unsupported recovered anchor manifest version");
    }
    validate_recovered_manifest(metadata, manifest)?;
    let mut records = recovered_anchor_recipes(keys, guild_id, revision, metadata, manifest)?;
    records.push((
        ANCHOR_AREA_LOCATION_KIND.to_owned(),
        manifest.area.area_id.as_bytes().to_vec(),
        canonical_bytes(&manifest.area.path_hint)?,
    ));
    records.push((
        "anchor-manifest".to_owned(),
        revision.value.revision_id.as_bytes().to_vec(),
        canonical_bytes(manifest)?,
    ));
    Ok(records)
}

fn load_private_metadata(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<PrivateMetadata> {
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::with_capacity(checked_metadata_length(revision)?);
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(
            &encryption_key,
            reference,
            &mut |sector_id| render_sector(control, keys, sector_id, Some(&guild_id)),
        )?);
    }
    decode_private_metadata(&metadata_bytes)
}

fn decode_private_metadata(bytes: &[u8]) -> Result<PrivateMetadata> {
    let (format_version, _) =
        postcard::take_from_bytes::<u16>(bytes).context("decode private metadata version")?;
    match format_version {
        1 | 3 => {
            let metadata: PrivateMetadata = decode_canonical(bytes)?;
            if metadata.format_version != format_version {
                bail!("private metadata version changed while decoding");
            }
            if format_version == 1
                && metadata.entries.iter().any(|entry| {
                    matches!(
                        entry,
                        PrivateEntry::FileV2 { .. } | PrivateEntry::HardLinkV3 { .. }
                    )
                })
            {
                bail!("version-1 private metadata contains a later entry variant");
            }
            Ok(metadata)
        }
        2 => decode_v2_private_metadata(bytes),
        _ => bail!("unsupported private metadata version"),
    }
}

fn decode_v2_private_metadata(bytes: &[u8]) -> Result<PrivateMetadata> {
    if let Ok(metadata) = decode_canonical::<LinkV2PrivateMetadata>(bytes)
        && validate_link_v2_layout(&metadata).is_ok()
    {
        return Ok(convert_link_v2(metadata));
    }
    let metadata: NativeV2PrivateMetadata = decode_canonical(bytes)
        .context("private metadata does not match either historical version-2 layout")?;
    convert_native_v2(metadata)
}

fn validate_link_v2_layout(metadata: &LinkV2PrivateMetadata) -> Result<()> {
    if metadata.format_version != 2 {
        bail!("historical link metadata has the wrong version");
    }
    let mut next_group = 0_u64;
    let mut groups = BTreeSet::new();
    for entry in &metadata.entries {
        if let LinkV2PrivateEntry::FileV2 { link_group, .. } = entry
            && groups.insert(*link_group)
        {
            if *link_group != next_group {
                bail!("historical link groups are not in emitted order");
            }
            next_group = next_group
                .checked_add(1)
                .context("too many historical link groups")?;
        }
    }
    Ok(())
}

fn convert_link_v2(metadata: LinkV2PrivateMetadata) -> PrivateMetadata {
    PrivateMetadata {
        format_version: metadata.format_version,
        root_mode: metadata.root_mode,
        root_modified_secs: metadata.root_modified_secs,
        root_modified_nanos: metadata.root_modified_nanos,
        entries: metadata
            .entries
            .into_iter()
            .map(|entry| match entry {
                LinkV2PrivateEntry::Directory {
                    path,
                    mode,
                    modified_secs,
                    modified_nanos,
                } => PrivateEntry::Directory {
                    path,
                    mode,
                    modified_secs,
                    modified_nanos,
                },
                LinkV2PrivateEntry::File {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    sectors,
                } => PrivateEntry::File {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    sectors,
                },
                LinkV2PrivateEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                } => PrivateEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                },
            })
            .collect(),
    }
}

fn convert_native_v2(metadata: NativeV2PrivateMetadata) -> Result<PrivateMetadata> {
    if metadata.format_version != 2 {
        bail!("historical native-ID metadata has the wrong version");
    }
    let mut groups = BTreeMap::<NativeFileId, u64>::new();
    let mut next_group = 0_u64;
    let mut entries = Vec::with_capacity(metadata.entries.len());
    for entry in metadata.entries {
        entries.push(match entry {
            NativeV2PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            } => PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            },
            NativeV2PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            } => PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            },
            NativeV2PrivateEntry::FileV2 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                native_id,
                data_extents,
            } => {
                let link_group = match groups.get(&native_id) {
                    Some(group) => *group,
                    None => {
                        let group = next_group;
                        next_group = next_group
                            .checked_add(1)
                            .context("too many historical native file identities")?;
                        groups.insert(native_id, group);
                        group
                    }
                };
                PrivateEntry::FileV2 {
                    path,
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                }
            }
        });
    }
    Ok(PrivateMetadata {
        format_version: metadata.format_version,
        root_mode: metadata.root_mode,
        root_modified_secs: metadata.root_modified_secs,
        root_modified_nanos: metadata.root_modified_nanos,
        entries,
    })
}

pub(crate) fn restore_signed_root_metadata_at(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    restored_root: &PinnedDirectory,
) -> Result<()> {
    let metadata = load_private_metadata(control, keys, guild_id, revision)?;
    set_metadata_durable(
        restored_root.as_file(),
        metadata.root_mode,
        metadata.root_modified_secs,
        metadata.root_modified_nanos,
    )
}

pub(crate) fn make_restore_root_private_at(restored_root: &PinnedDirectory) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        restored_root
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o700))?;
    }
    restored_root.sync_all()?;
    Ok(())
}

fn validate_recovered_manifest(
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<()> {
    if metadata.root_mode != manifest.root_mode
        || metadata.root_modified_secs != manifest.root_modified_secs
        || metadata.root_modified_nanos != manifest.root_modified_nanos
        || metadata.entries.len() != manifest.entries.len()
    {
        bail!("recovered anchor root does not match signed metadata");
    }
    let captured = manifest
        .entries
        .iter()
        .map(|entry| {
            let path = match entry {
                CapturedEntry::Directory { path, .. }
                | CapturedEntry::File { path, .. }
                | CapturedEntry::FileV2 { path, .. } => path,
            };
            (path.as_str(), entry)
        })
        .collect::<BTreeMap<_, _>>();
    if captured.len() != manifest.entries.len() {
        bail!("recovered anchor contains duplicate paths");
    }
    let mut signed_to_captured = BTreeMap::<u64, NativeFileId>::new();
    let mut captured_to_signed = BTreeMap::<NativeFileId, u64>::new();
    for entry in &metadata.entries {
        let path = private_entry_path(entry);
        let actual = captured
            .get(path)
            .with_context(|| format!("recovered anchor is missing {path}"))?;
        match (entry, *actual) {
            (
                PrivateEntry::Directory {
                    mode,
                    modified_secs,
                    modified_nanos,
                    ..
                },
                CapturedEntry::Directory {
                    mode: actual_mode,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    ..
                },
            ) if mode == actual_mode
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos => {}
            (
                PrivateEntry::File {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos => {}
            (
                PrivateEntry::FileV2 {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    data_extents,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    native_id: actual_native_id,
                    data_extents: actual_extents,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos
                && data_extents
                    .iter()
                    .map(|extent| FileExtent {
                        offset: extent.offset,
                        logical_len: extent.logical_len,
                    })
                    .eq(actual_extents.iter().cloned()) =>
            {
                if signed_to_captured
                    .insert(*link_group, *actual_native_id)
                    .is_some_and(|previous| previous != *actual_native_id)
                    || captured_to_signed
                        .insert(*actual_native_id, *link_group)
                        .is_some_and(|previous| previous != *link_group)
                {
                    bail!("recovered anchor does not preserve signed hard-link groups");
                }
            }
            (
                PrivateEntry::HardLinkV3 {
                    mode,
                    logical_len,
                    modified_secs,
                    modified_nanos,
                    link_group,
                    ..
                },
                CapturedEntry::FileV2 {
                    mode: actual_mode,
                    logical_len: actual_len,
                    modified_secs: actual_secs,
                    modified_nanos: actual_nanos,
                    native_id: actual_native_id,
                    ..
                },
            ) if mode == actual_mode
                && logical_len == actual_len
                && modified_secs == actual_secs
                && modified_nanos == actual_nanos =>
            {
                if signed_to_captured.get(link_group) != Some(actual_native_id)
                    || captured_to_signed.get(actual_native_id) != Some(link_group)
                {
                    bail!("recovered anchor does not preserve signed hard-link aliases");
                }
            }
            _ => bail!("recovered anchor entry {path} does not match signed metadata"),
        }
    }
    Ok(())
}

fn private_entry_path(entry: &PrivateEntry) -> &str {
    match entry {
        PrivateEntry::Directory { path, .. }
        | PrivateEntry::File { path, .. }
        | PrivateEntry::FileV2 { path, .. }
        | PrivateEntry::HardLinkV3 { path, .. } => path,
    }
}

fn recovered_anchor_recipes(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    metadata: &PrivateMetadata,
    manifest: &mb_store::StableAnchorManifest,
) -> Result<Vec<RecordWrite>> {
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut by_id = BTreeMap::<SectorId, LocalSectorRecipe>::new();
    for entry in &metadata.entries {
        let (path, extents) = match entry {
            PrivateEntry::Directory { .. } => continue,
            PrivateEntry::File {
                path,
                logical_len,
                sectors,
                ..
            } => (
                path,
                vec![PrivateDataExtent {
                    offset: 0,
                    logical_len: *logical_len,
                    sectors: sectors.clone(),
                }],
            ),
            PrivateEntry::FileV2 {
                path, data_extents, ..
            } => (path, data_extents.clone()),
            PrivateEntry::HardLinkV3 { .. } => continue,
        };
        let locator = manifest.file_locator(path.clone())?;
        let mut file = locator.open().context("open recovered anchor file")?;
        for extent in extents {
            let mut offset = extent.offset;
            let mut extent_len = 0_u64;
            for reference in extent.sectors {
                file.seek(SeekFrom::Start(offset))?;
                let mut plaintext = vec![0_u8; reference.logical_len as usize];
                file.read_exact(&mut plaintext)?;
                let (actual, _) = encrypted_sector(&encryption_key, reference.id, &plaintext)?;
                if actual != reference {
                    bail!("recovered anchor content does not match a signed sector");
                }
                let recipe = LocalSectorRecipe {
                    guild_id,
                    reference: reference.clone(),
                    source: LocalPlaintextSource::StableAnchorFile {
                        locator: locator.clone(),
                        offset,
                    },
                };
                if by_id
                    .insert(reference.id, recipe.clone())
                    .is_some_and(|previous| previous.reference != recipe.reference)
                {
                    bail!("one sector ID has conflicting signed references");
                }
                offset = offset
                    .checked_add(reference.logical_len as u64)
                    .context("signed sector range overflow")?;
                extent_len = extent_len
                    .checked_add(reference.logical_len as u64)
                    .context("signed extent length overflow")?;
            }
            if extent_len != extent.logical_len {
                bail!("signed extent does not match its sector lengths");
            }
        }
    }
    let expected = revision
        .value
        .data_sectors
        .iter()
        .map(|reference| (reference.id, reference))
        .collect::<BTreeMap<_, _>>();
    if expected.len() != revision.value.data_sectors.len()
        || expected.len() != by_id.len()
        || expected.iter().any(|(id, reference)| {
            by_id.get(id).map(|recipe| &recipe.reference) != Some(*reference)
        })
    {
        bail!("signed data-sector catalog does not match recovered file metadata");
    }
    by_id
        .into_values()
        .map(|recipe| {
            Ok((
                "local-sector".to_owned(),
                recipe.reference.id.to_vec(),
                canonical_bytes(&recipe)?,
            ))
        })
        .collect()
}

pub(crate) fn render_sector(
    control: &ControlStore,
    keys: &KeyMaterial,
    sector_id: &SectorId,
    expected_guild: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    render_sector_with_hint_update(control, keys, sector_id, expected_guild, true)
}

fn render_sector_with_hint_update(
    control: &ControlStore,
    keys: &KeyMaterial,
    sector_id: &SectorId,
    expected_guild: Option<&[u8; 32]>,
    update_area_hint: bool,
) -> Result<Vec<u8>> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    if expected_guild.is_some_and(|guild_id| recipe.guild_id != *guild_id) {
        bail!("local sector does not belong to the requested guild");
    }
    let plaintext = match &recipe.source {
        LocalPlaintextSource::AnchorFile { locator, offset } => {
            let mut file = locator.open().context("open source anchor")?;
            file.seek(SeekFrom::Start(*offset))?;
            let mut plaintext = vec![0_u8; recipe.reference.logical_len as usize];
            file.read_exact(&mut plaintext)?;
            plaintext
        }
        LocalPlaintextSource::StableAnchorFile { locator, offset } => {
            let area_hint = control
                .get_record(ANCHOR_AREA_LOCATION_KIND, locator.area.area_id.as_bytes())?
                .and_then(|bytes| decode_canonical::<PathBuf>(&bytes).ok());
            let (mut file, resolved_area) = locator
                .open_with_area_hint(area_hint.as_deref())
                .context("open stable source anchor")?;
            if update_area_hint && area_hint.as_ref() != Some(&resolved_area) {
                control.put_record(
                    ANCHOR_AREA_LOCATION_KIND,
                    locator.area.area_id.as_bytes(),
                    &canonical_bytes(&resolved_area)?,
                )?;
            }
            file.seek(SeekFrom::Start(*offset))?;
            let mut plaintext = vec![0_u8; recipe.reference.logical_len as usize];
            file.read_exact(&mut plaintext)?;
            plaintext
        }
        LocalPlaintextSource::Inline(bytes) => bytes.clone(),
    };
    let (actual_reference, ciphertext) = encrypted_sector(
        &keys.guild_data_key(&recipe.guild_id),
        recipe.reference.id,
        &plaintext,
    )?;
    if actual_reference != recipe.reference {
        bail!("source anchor no longer matches the committed sector root");
    }
    Ok(ciphertext)
}

#[cfg(test)]
pub(crate) fn local_recipe_is_inline(control: &ControlStore, sector_id: &SectorId) -> Result<bool> {
    let encoded = control
        .get_record("local-sector", sector_id)?
        .context("local sector recipe is unavailable")?;
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    Ok(matches!(recipe.source, LocalPlaintextSource::Inline(_)))
}

pub(crate) fn recovered_recipe_is_stable(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    reference: &SectorRef,
) -> Result<bool> {
    let Some(encoded) = control.get_record("local-sector", &reference.id)? else {
        return Ok(false);
    };
    let recipe: LocalSectorRecipe = decode_canonical(&encoded)?;
    if recipe.guild_id != guild_id || recipe.reference != *reference {
        bail!("local sector recipe conflicts with the recovered revision");
    }
    if !matches!(recipe.source, LocalPlaintextSource::StableAnchorFile { .. }) {
        return Ok(false);
    }
    Ok(
        render_sector_with_hint_update(control, keys, &reference.id, Some(&guild_id), false)
            .is_ok_and(|ciphertext| sector_root(&ciphertext) == reference.root),
    )
}

pub fn restore_revision(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    ciphertexts: &BTreeMap<SectorId, Vec<u8>>,
    target: &Path,
) -> Result<()> {
    restore_revision_from_source(control, keys, guild_id, revision, target, |sector_id| {
        ciphertexts
            .get(sector_id)
            .cloned()
            .with_context(|| format!("missing recovered sector {}", hex_id(sector_id)))
    })
}

pub fn restore_revision_from_source<F>(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    target: &Path,
    mut load_ciphertext: F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    validate_restore_revision(keys, guild_id, revision)?;
    let _operation = lock_restore_operations(control)?;
    let (target, target_name, parent) = pinned_restore_parent(target)?;
    let parent_identity = parent.identity()?;
    let ReservedRestoreJob {
        record_id,
        mut bytes,
        mut job,
    } = loop {
        if let Some(reserved) = reserved_restore_job(
            control,
            &target,
            &parent,
            guild_id,
            revision.value.revision_id,
        )? {
            break reserved;
        }
        if parent.entry_identity(&target_name, true)?.is_some() {
            bail!("restore target already exists: {}", target.display());
        }
        let job = RestoreJob {
            format_version: 2,
            guild_id,
            revision_id: revision.value.revision_id,
            target: target.clone(),
            parent_identity,
            staging_name: format!(".mutualbackup-restore-{}", Uuid::new_v4()),
            staged_identity: None,
            state: RestoreJobState::Building,
        };
        let record_id = restore_job_record_id(&target)?;
        let bytes = canonical_bytes(&job)?;
        if control.put_record_if_absent(RESTORE_JOB_KIND, &record_id, &bytes)? {
            break ReservedRestoreJob {
                record_id,
                bytes,
                job,
            };
        }
        // A non-cooperating writer changed the journal despite the operation
        // lock. Reload the durable owner and fail closed below.
    };
    validate_reserved_restore_job(
        &job,
        guild_id,
        revision.value.revision_id,
        &target,
        parent_identity,
    )?;

    if parent.identity()? != job.parent_identity {
        bail!("restore parent directory changed since the durable job was created");
    }
    if job.state == RestoreJobState::Publishing {
        let staging_identity = parent.entry_identity(&job.staging_name, true)?;
        let target_identity = parent.entry_identity(&target_name, true)?;
        if staging_identity.is_none() && target_identity.is_none() {
            // An older multi-job reconciliation could stop after durably
            // removing this job's staging tree but before retiring its journal
            // row. Nothing remains to publish or adopt, so return the signed
            // revision to Building and reconstruct it under a fresh name.
            job.state = RestoreJobState::Building;
            job.staged_identity = None;
            bytes = replace_restore_job(control, &record_id, &bytes, &job)?;
        } else {
            return finish_durable_restore_publication(
                control,
                &record_id,
                &bytes,
                &job,
                &parent,
                &target_name,
            );
        }
    }

    let prior_staging_identity = parent.entry_identity(&job.staging_name, true)?;
    if parent.entry_identity(&target_name, true)?.is_some() {
        if job.staged_identity.is_none() && prior_staging_identity.is_none() {
            control.delete_record_if_value(RESTORE_JOB_KIND, &record_id, &bytes)?;
        }
        bail!("restore target appeared while rebuilding an unfinished restore");
    }
    if let Some(actual) = prior_staging_identity {
        match job.staged_identity {
            Some(expected) if actual == expected => {
                parent.remove_child_directory(&job.staging_name, actual)?;
                parent.sync_all()?;
            }
            Some(_) => bail!("durable restore staging directory was replaced"),
            None => {
                // The process may have stopped between directory creation and
                // recording its inode. Never delete an unbound name; rotate to
                // a fresh staging name and leave the unknown entry untouched.
            }
        }
    }

    job.staging_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
    job.staged_identity = None;
    bytes = replace_restore_job(control, &record_id, &bytes, &job)?;
    let staging = parent.create_child_directory(&job.staging_name)?;
    parent.sync_all()?;
    let staged_identity = staging.identity()?;
    job.staged_identity = Some(staged_identity);
    match replace_restore_job(control, &record_id, &bytes, &job) {
        Ok(replacement) => bytes = replacement,
        Err(error) => {
            if parent.entry_identity(&job.staging_name, true)? == Some(staged_identity) {
                parent.remove_child_directory(&job.staging_name, staged_identity)?;
                parent.sync_all()?;
            }
            return Err(error);
        }
    }

    build_revision_restore(
        keys,
        guild_id,
        revision,
        &staging,
        &mut load_ciphertext,
        true,
    )?;
    if parent.entry_identity(&job.staging_name, true)? != Some(staged_identity) {
        bail!("restore staging directory changed during construction");
    }
    job.state = RestoreJobState::Publishing;
    bytes = replace_restore_job(control, &record_id, &bytes, &job)?;
    finish_durable_restore_publication(control, &record_id, &bytes, &job, &parent, &target_name)
}

pub(crate) fn resume_restore_publication(
    control: &ControlStore,
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    target: &Path,
) -> Result<bool> {
    validate_restore_revision(keys, guild_id, revision)?;
    let _operation = lock_restore_operations(control)?;
    let (target, target_name, parent) = pinned_restore_parent(target)?;
    let parent_identity = parent.identity()?;
    let Some(ReservedRestoreJob {
        record_id,
        bytes,
        mut job,
    }) = reserved_restore_job(
        control,
        &target,
        &parent,
        guild_id,
        revision.value.revision_id,
    )?
    else {
        return Ok(false);
    };
    validate_reserved_restore_job(
        &job,
        guild_id,
        revision.value.revision_id,
        &target,
        parent_identity,
    )?;
    if job.state != RestoreJobState::Publishing {
        return Ok(false);
    }
    if parent.entry_identity(&job.staging_name, true)?.is_none()
        && parent.entry_identity(&target_name, true)?.is_none()
    {
        job.state = RestoreJobState::Building;
        job.staged_identity = None;
        replace_restore_job(control, &record_id, &bytes, &job)?;
        return Ok(false);
    }
    finish_durable_restore_publication(control, &record_id, &bytes, &job, &parent, &target_name)?;
    Ok(true)
}

fn validate_restore_revision(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
) -> Result<()> {
    revision.verify(USER_REVISION_DOMAIN)?;
    revision.value.verify_writer()?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
        || revision.value.format_version != 2
        || revision.value.cipher_profile != V1_CIPHER_PROFILE
    {
        bail!("revision does not belong to the recovering seed and guild");
    }
    Ok(())
}

fn validate_reserved_restore_job(
    job: &RestoreJob,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target: &Path,
    parent_identity: NativeFileId,
) -> Result<()> {
    if job.guild_id != guild_id
        || job.revision_id != revision_id
        || job.target != target
        || job.parent_identity != parent_identity
    {
        bail!("restore request conflicts with an unfinished durable restore job");
    }
    Ok(())
}

fn lock_restore_operations(control: &ControlStore) -> Result<RestoreOperationGuard> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(control.path())
        .context("open control database for restore serialization")?;
    FileExt::lock_exclusive(&file).context("serialize ordinary restore operations")?;
    Ok(RestoreOperationGuard(file))
}

impl Drop for RestoreOperationGuard {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

fn replace_restore_job(
    control: &ControlStore,
    record_id: &[u8; 32],
    expected: &[u8],
    replacement: &RestoreJob,
) -> Result<Vec<u8>> {
    let replacement = canonical_bytes(replacement)?;
    control.replace_record_if_value(RESTORE_JOB_KIND, record_id, expected, &replacement)?;
    Ok(replacement)
}

fn restore_job_record_id(target: &Path) -> Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new_derive_key("mutualbackup restore target reservation v1");
    hasher.update(&canonical_bytes(&target)?);
    Ok(*hasher.finalize().as_bytes())
}

fn reserved_restore_job(
    control: &ControlStore,
    target: &Path,
    parent: &PinnedDirectory,
    guild_id: [u8; 32],
    revision_id: Uuid,
) -> Result<Option<ReservedRestoreJob>> {
    let target_record_id = restore_job_record_id(target)?;
    for _ in 0..2 {
        let mut matching = Vec::new();
        for (record_id, bytes) in control.records(RESTORE_JOB_KIND)? {
            let job: RestoreJob = decode_canonical(&bytes)?;
            match job.format_version {
                1 if record_id.as_slice() == job.revision_id.as_bytes() => {}
                2 if record_id.as_slice() == restore_job_record_id(&job.target)? => {}
                _ => bail!("unfinished durable restore job is inconsistent"),
            }
            if job.target == target {
                matching.push((record_id, bytes, job));
            }
        }
        if matching.len() > 1 {
            return reconcile_legacy_restore_jobs(
                control,
                target,
                parent,
                guild_id,
                revision_id,
                target_record_id,
                matching,
            );
        }
        let Some((record_id, bytes, mut job)) = matching.pop() else {
            return Ok(None);
        };
        if job.format_version == 2 {
            return Ok(Some(ReservedRestoreJob {
                record_id: target_record_id,
                bytes,
                job,
            }));
        }

        job.format_version = 2;
        let replacement = canonical_bytes(&job)?;
        match control.move_record_if_value(
            RESTORE_JOB_KIND,
            &record_id,
            &bytes,
            &target_record_id,
            &replacement,
        ) {
            Ok(()) => {
                return Ok(Some(ReservedRestoreJob {
                    record_id: target_record_id,
                    bytes: replacement,
                    job,
                }));
            }
            Err(mb_store::DatabaseError::Conflict) => continue,
            Err(error) => return Err(error.into()),
        }
    }
    bail!("unfinished durable restore job changed concurrently")
}

fn reconcile_legacy_restore_jobs(
    control: &ControlStore,
    target: &Path,
    parent: &PinnedDirectory,
    guild_id: [u8; 32],
    revision_id: Uuid,
    target_record_id: [u8; 32],
    matching: Vec<(Vec<u8>, Vec<u8>, RestoreJob)>,
) -> Result<Option<ReservedRestoreJob>> {
    if matching.iter().any(|(_, _, job)| job.format_version != 1) {
        bail!("multiple unfinished durable restore jobs reserve the same target");
    }
    let selected_index = matching
        .iter()
        .position(|(_, _, job)| job.guild_id == guild_id && job.revision_id == revision_id)
        .context("restore request conflicts with multiple legacy jobs for this target")?;
    let parent_identity = parent.identity()?;
    if matching
        .iter()
        .any(|(_, _, job)| job.parent_identity != parent_identity)
    {
        bail!("legacy restore parent directory changed unexpectedly");
    }
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("legacy restore target has no UTF-8 file name")?;
    if let Some(actual_target) = parent.entry_identity(target_name, true)? {
        let owners = matching
            .iter()
            .enumerate()
            .filter(|(_, (_, _, job))| {
                job.state == RestoreJobState::Publishing
                    && job.staged_identity == Some(actual_target)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if owners.as_slice() != [selected_index] {
            bail!("existing restore target belongs to another legacy job or actor");
        }
    }
    let selected_staging = &matching[selected_index].2.staging_name;
    for (index, (_, _, job)) in matching.iter().enumerate() {
        if index == selected_index {
            continue;
        }
        if &job.staging_name == selected_staging {
            bail!("multiple legacy restore jobs share one staging name");
        }
        retire_legacy_restore_staging(parent, job)?;
    }
    let mut selected = matching[selected_index].2.clone();
    selected.format_version = 2;
    let replacement = canonical_bytes(&selected)?;
    let old_records = matching
        .iter()
        .map(|(record_id, bytes, _)| (record_id.clone(), bytes.clone()))
        .collect::<Vec<_>>();
    control.replace_records_with_one(
        RESTORE_JOB_KIND,
        &old_records,
        &target_record_id,
        &replacement,
    )?;
    Ok(Some(ReservedRestoreJob {
        record_id: target_record_id,
        bytes: replacement,
        job: selected,
    }))
}

fn retire_legacy_restore_staging(parent: &PinnedDirectory, job: &RestoreJob) -> Result<()> {
    let Some(actual) = parent.entry_identity(&job.staging_name, true)? else {
        return Ok(());
    };
    match job.staged_identity {
        Some(expected) if expected == actual => {
            parent.remove_child_directory(&job.staging_name, expected)?;
            parent.sync_all()?;
            run_after_legacy_restore_retire_hook()
        }
        Some(_) => bail!("legacy restore staging directory was replaced"),
        None => Ok(()),
    }
}

#[cfg(test)]
fn run_after_legacy_restore_retire_hook() -> Result<()> {
    INTERRUPT_AFTER_LEGACY_RESTORE_RETIRE.with(|interrupt| {
        if interrupt.replace(false) {
            bail!("injected interruption after legacy restore retirement");
        }
        Ok(())
    })
}

#[cfg(not(test))]
fn run_after_legacy_restore_retire_hook() -> Result<()> {
    Ok(())
}

pub(crate) fn build_revision_restore<F>(
    keys: &KeyMaterial,
    guild_id: [u8; 32],
    revision: &SignedRecord<UserRevision>,
    staging: &PinnedDirectory,
    load_ciphertext: &mut F,
    apply_root_metadata: bool,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    revision.verify(USER_REVISION_DOMAIN)?;
    revision.value.verify_writer()?;
    if revision.signer != keys.node_id()
        || revision.value.owner != keys.node_id()
        || revision.value.guild_id != guild_id
        || revision.value.format_version != 2
        || revision.value.cipher_profile != V1_CIPHER_PROFILE
    {
        bail!("revision does not belong to the recovering seed and guild");
    }
    let encryption_key = keys.guild_data_key(&guild_id);
    let mut metadata_bytes = Vec::with_capacity(checked_metadata_length(revision)?);
    for reference in &revision.value.metadata_sectors {
        metadata_bytes.extend(decrypt_reference(
            &encryption_key,
            reference,
            load_ciphertext,
        )?);
    }
    let metadata = decode_private_metadata(&metadata_bytes)?;

    restore_entries(
        staging,
        &metadata,
        &encryption_key,
        load_ciphertext,
        apply_root_metadata,
    )
}

fn pinned_restore_parent(target: &Path) -> Result<(PathBuf, String, PinnedDirectory)> {
    let parent_hint = containing_directory(target);
    fs::create_dir_all(parent_hint)?;
    let parent_path = parent_hint.canonicalize()?;
    let target_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .context("restore target needs one UTF-8 file name")?
        .to_owned();
    let relative = Path::new(&target_name);
    if relative.components().count() != 1
        || !matches!(relative.components().next(), Some(Component::Normal(_)))
    {
        bail!("restore target needs one safe file name");
    }
    let parent = PinnedDirectory::open(&parent_path)?;
    Ok((parent_path.join(&target_name), target_name, parent))
}

fn finish_durable_restore_publication(
    control: &ControlStore,
    record_id: &[u8],
    expected_record: &[u8],
    job: &RestoreJob,
    parent: &PinnedDirectory,
    target_name: &str,
) -> Result<()> {
    let expected = job
        .staged_identity
        .context("publishing restore job has no staged directory identity")?;
    publish_owned_restore(parent, &job.staging_name, target_name, expected)?;
    if parent.descriptor_path().canonicalize()? != containing_directory(&job.target) {
        bail!("restore parent directory was renamed during publication");
    }
    match control.delete_record_if_value(RESTORE_JOB_KIND, record_id, expected_record) {
        Ok(()) => {}
        Err(mb_store::DatabaseError::Conflict)
            if control.get_record(RESTORE_JOB_KIND, record_id)?.is_none()
                && parent.entry_identity(target_name, true)? == Some(expected) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

pub(crate) fn publish_owned_restore(
    parent: &PinnedDirectory,
    staging_name: &str,
    target_name: &str,
    expected: NativeFileId,
) -> Result<()> {
    match (
        parent.entry_identity(staging_name, true)?,
        parent.entry_identity(target_name, true)?,
    ) {
        (Some(actual), None) if actual == expected => {
            parent.rename_child_no_replace(staging_name, target_name)?;
            run_after_restore_rename_hook()?;
            if parent.entry_identity(target_name, true)? != Some(expected) {
                bail!("restore target changed during publication");
            }
        }
        (None, Some(actual)) if actual == expected => {}
        (Some(_), None) => bail!("durable restore staging directory was replaced"),
        (None, Some(_)) => bail!("restore target was created by another actor"),
        (Some(_), Some(_)) => bail!("both restore staging and target names exist"),
        (None, None) => bail!("durable restore staging and published target are both missing"),
    }
    parent.sync_all()?;
    Ok(())
}

#[cfg(test)]
fn run_after_restore_rename_hook() -> Result<()> {
    AFTER_RESTORE_RENAME.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook()?;
        }
        Ok(())
    })
}

#[cfg(test)]
pub(crate) fn interrupt_next_restore_after_rename() {
    AFTER_RESTORE_RENAME.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| anyhow::bail!("injected parent sync failure")));
    });
}

#[cfg(not(test))]
fn run_after_restore_rename_hook() -> Result<()> {
    Ok(())
}

fn containing_directory(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn restore_entries<F>(
    staging: &PinnedDirectory,
    metadata: &PrivateMetadata,
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
    apply_root_metadata: bool,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let mut directory_metadata = BTreeMap::new();
    let mut expected_entries = BTreeMap::<PathBuf, ExpectedRestoreEntry>::new();
    let mut declared_paths = BTreeSet::new();
    let mut restored_links = BTreeMap::<u64, RestoredLink>::new();
    let link_pool_name = loop {
        let candidate = format!(".mutualbackup-restore-links-{}", Uuid::new_v4());
        if !metadata.entries.iter().any(|entry| {
            Path::new(private_entry_path(entry))
                .components()
                .next()
                .is_some_and(|component| component.as_os_str() == candidate.as_str())
        }) {
            break candidate;
        }
    };
    let link_pool = staging.create_child_directory(&link_pool_name)?;
    let link_pool_identity = link_pool.identity()?;
    let mut pooled_links = Vec::new();
    for entry in &metadata.entries {
        match entry {
            PrivateEntry::Directory {
                path,
                mode,
                modified_secs,
                modified_nanos,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                ensure_restore_directory(staging, &destination, &mut expected_entries)?;
                directory_metadata.insert(destination, (*mode, *modified_secs, *modified_nanos));
            }
            PrivateEntry::File {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                sectors,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                let (parent, name) =
                    restore_destination(staging, &destination, &mut expected_entries)?;
                let mut file = parent.create_child_file(&name)?;
                let identity = native_id_for_file(staging, &file)?;
                let mut written = 0_u64;
                for reference in sectors {
                    let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
                    file.write_all(&plaintext)?;
                    written += plaintext.len() as u64;
                }
                if written != *logical_len {
                    bail!("restored file length does not match signed metadata");
                }
                set_metadata_durable(&file, *mode, *modified_secs, *modified_nanos)?;
                expected_entries.insert(
                    destination,
                    ExpectedRestoreEntry {
                        directory: false,
                        identity,
                    },
                );
            }
            PrivateEntry::FileV2 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                link_group,
                data_extents,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                let (parent, name) =
                    restore_destination(staging, &destination, &mut expected_entries)?;
                if let Some(existing) = restored_links.get(link_group) {
                    if existing.mode != *mode
                        || existing.logical_len != *logical_len
                        || existing.modified_secs != *modified_secs
                        || existing.modified_nanos != *modified_nanos
                        || existing.data_extents != *data_extents
                    {
                        bail!("hard-linked aliases have inconsistent signed metadata");
                    }
                    link_pool.hard_link_child_from(&existing.pool_name, &parent, &name)?;
                    expected_entries.insert(
                        destination,
                        ExpectedRestoreEntry {
                            directory: false,
                            identity: existing.identity,
                        },
                    );
                } else {
                    let mut file = parent.create_child_file(&name)?;
                    restore_sparse_file(
                        &mut file,
                        *logical_len,
                        data_extents,
                        encryption_key,
                        load_ciphertext,
                    )?;
                    set_metadata_durable(&file, *mode, *modified_secs, *modified_nanos)?;
                    let identity = native_id_for_file(staging, &file)?;
                    let pool_name = link_group.to_string();
                    parent.hard_link_child_from(&name, &link_pool, &pool_name)?;
                    pooled_links.push(pool_name.clone());
                    expected_entries.insert(
                        destination,
                        ExpectedRestoreEntry {
                            directory: false,
                            identity,
                        },
                    );
                    restored_links.insert(
                        *link_group,
                        RestoredLink {
                            pool_name,
                            identity,
                            mode: *mode,
                            logical_len: *logical_len,
                            modified_secs: *modified_secs,
                            modified_nanos: *modified_nanos,
                            data_extents: data_extents.clone(),
                        },
                    );
                }
            }
            PrivateEntry::HardLinkV3 {
                path,
                mode,
                logical_len,
                modified_secs,
                modified_nanos,
                link_group,
            } => {
                let destination = safe_relative_path(path)?;
                if !declared_paths.insert(destination.clone()) {
                    bail!("duplicate path in recovered metadata");
                }
                let (parent, name) =
                    restore_destination(staging, &destination, &mut expected_entries)?;
                let existing = restored_links
                    .get(link_group)
                    .context("hard-link alias precedes its signed primary file")?;
                if existing.mode != *mode
                    || existing.logical_len != *logical_len
                    || existing.modified_secs != *modified_secs
                    || existing.modified_nanos != *modified_nanos
                {
                    bail!("hard-linked alias has inconsistent signed metadata");
                }
                link_pool.hard_link_child_from(&existing.pool_name, &parent, &name)?;
                expected_entries.insert(
                    destination,
                    ExpectedRestoreEntry {
                        directory: false,
                        identity: existing.identity,
                    },
                );
            }
        }
    }
    for name in pooled_links {
        link_pool.remove_child_file(name)?;
    }
    link_pool.sync_all()?;
    staging.remove_child_directory(&link_pool_name, link_pool_identity)?;

    for (path, expected) in &expected_entries {
        if staging.entry_identity(path, expected.directory)? != Some(expected.identity) {
            bail!(
                "restored entry changed during construction: {}",
                path.display()
            );
        }
    }
    let mut directories = expected_entries
        .iter()
        .filter(|(_, expected)| expected.directory)
        .map(|(path, _)| path.clone())
        .collect::<Vec<_>>();
    directories.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    for path in directories {
        let directory = open_expected_restore_directory(staging, &path, &expected_entries)?;
        if let Some((mode, modified_secs, modified_nanos)) = directory_metadata.remove(&path) {
            set_metadata_durable(directory.as_file(), mode, modified_secs, modified_nanos)?;
        } else {
            directory.sync_all()?;
        }
    }
    if !directory_metadata.is_empty() {
        bail!("restored directory metadata has no matching directory");
    }
    if apply_root_metadata {
        set_metadata_durable(
            staging.as_file(),
            metadata.root_mode,
            metadata.root_modified_secs,
            metadata.root_modified_nanos,
        )?;
    } else {
        staging.sync_all()?;
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct ExpectedRestoreEntry {
    directory: bool,
    identity: NativeFileId,
}

struct RestoredLink {
    pool_name: String,
    identity: NativeFileId,
    mode: u32,
    logical_len: u64,
    modified_secs: i64,
    modified_nanos: u32,
    data_extents: Vec<PrivateDataExtent>,
}

fn ensure_restore_directory(
    root: &PinnedDirectory,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, ExpectedRestoreEntry>,
) -> Result<PinnedDirectory> {
    let mut current = root.try_clone()?;
    let mut traversed = PathBuf::new();
    for component in relative.components() {
        let Component::Normal(name) = component else {
            bail!("unsafe path in recovered metadata");
        };
        traversed.push(name);
        current = match expected.get(&traversed) {
            Some(entry) if entry.directory => {
                let directory = current
                    .open_child_directory(name)?
                    .context("expected restored directory disappeared")?;
                if directory.identity()? != entry.identity {
                    bail!("restored directory was replaced: {}", traversed.display());
                }
                directory
            }
            Some(_) => bail!("restored path is both a file and directory"),
            None => {
                if current.open_child_directory(name)?.is_some() {
                    bail!("unexpected directory appeared in restore staging");
                }
                let directory = current.create_child_directory(name)?;
                expected.insert(
                    traversed.clone(),
                    ExpectedRestoreEntry {
                        directory: true,
                        identity: directory.identity()?,
                    },
                );
                directory
            }
        };
    }
    Ok(current)
}

fn restore_destination(
    root: &PinnedDirectory,
    relative: &Path,
    expected: &mut BTreeMap<PathBuf, ExpectedRestoreEntry>,
) -> Result<(PinnedDirectory, PathBuf)> {
    let name = relative
        .file_name()
        .map(PathBuf::from)
        .context("restored path has no file name")?;
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let directory = if parent.as_os_str().is_empty() {
        root.try_clone()?
    } else {
        ensure_restore_directory(root, parent, expected)?
    };
    if expected.contains_key(relative) {
        bail!("duplicate path in recovered metadata");
    }
    Ok((directory, name))
}

fn open_expected_restore_directory(
    root: &PinnedDirectory,
    relative: &Path,
    expected: &BTreeMap<PathBuf, ExpectedRestoreEntry>,
) -> Result<PinnedDirectory> {
    let entry = expected
        .get(relative)
        .filter(|entry| entry.directory)
        .context("restored directory is not tracked")?;
    let directory = root.open_descendant_directory(relative)?;
    if directory.identity()? != entry.identity {
        bail!("restored directory was replaced: {}", relative.display());
    }
    Ok(directory)
}

fn native_id_for_file(root: &PinnedDirectory, file: &File) -> Result<NativeFileId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        Ok(NativeFileId {
            filesystem_id: root.identity()?.filesystem_id,
            inode: file.metadata()?.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = (root, file);
        bail!("native restore identity is not implemented on this platform")
    }
}

fn restore_sparse_file<F>(
    file: &mut File,
    logical_len: u64,
    data_extents: &[PrivateDataExtent],
    encryption_key: &[u8; 32],
    load_ciphertext: &mut F,
) -> Result<()>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    validate_file_extents(
        logical_len,
        data_extents
            .iter()
            .map(|extent| (extent.offset, extent.logical_len)),
    )?;
    file.set_len(logical_len)?;
    for extent in data_extents {
        file.seek(SeekFrom::Start(extent.offset))?;
        let mut written = 0_u64;
        for reference in &extent.sectors {
            let plaintext = decrypt_reference(encryption_key, reference, load_ciphertext)?;
            file.write_all(&plaintext)?;
            written = written
                .checked_add(plaintext.len() as u64)
                .context("restored extent length overflow")?;
        }
        if written != extent.logical_len {
            bail!("restored extent length does not match signed metadata");
        }
    }
    file.sync_all()?;
    Ok(())
}

fn decrypt_reference<F>(
    encryption_key: &[u8; 32],
    reference: &SectorRef,
    load_ciphertext: &mut F,
) -> Result<Vec<u8>>
where
    F: FnMut(&SectorId) -> Result<Vec<u8>>,
{
    let mut bytes = load_ciphertext(&reference.id)?;
    if bytes.len() != V1_SECTOR_SIZE || sector_root(&bytes) != reference.root {
        bail!("recovered sector failed its signed root");
    }
    crypt_sector(encryption_key, reference.id, &mut bytes)?;
    let logical_len = reference.logical_len as usize;
    if logical_len > bytes.len() {
        bail!("invalid logical sector length");
    }
    bytes.truncate(logical_len);
    Ok(bytes)
}

fn safe_relative_path(relative: &str) -> Result<PathBuf> {
    let relative = Path::new(relative);
    if relative.as_os_str().is_empty()
        || relative.is_absolute()
        || relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe path in recovered metadata");
    }
    Ok(relative.to_path_buf())
}

fn set_metadata_durable(
    file: &File,
    mode: u32,
    modified_secs: i64,
    modified_nanos: u32,
) -> Result<()> {
    if modified_nanos >= 1_000_000_000 {
        bail!("invalid modification timestamp");
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(mode))?;
        let timestamps = [
            libc::timespec {
                tv_sec: 0,
                tv_nsec: libc::UTIME_OMIT,
            },
            libc::timespec {
                tv_sec: modified_secs,
                tv_nsec: i64::from(modified_nanos),
            },
        ];
        if unsafe { libc::futimens(file.as_raw_fd(), timestamps.as_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    #[cfg(not(unix))]
    let _ = (mode, modified_secs, modified_nanos);
    file.sync_all()?;
    Ok(())
}

fn hex_id(id: &[u8; 32]) -> String {
    id.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod metadata_compatibility_tests {
    use super::*;

    fn restore_fixture(
        keys: &KeyMaterial,
        guild_id: [u8; 32],
        entries: Vec<PrivateEntry>,
        data: Vec<(u64, Vec<u8>)>,
    ) -> (SignedRecord<UserRevision>, BTreeMap<SectorId, Vec<u8>>) {
        let revision_id = Uuid::new_v4();
        let encryption_key = keys.guild_data_key(&guild_id);
        let mut ciphertexts = BTreeMap::new();
        let mut data_sectors = Vec::new();
        for (ordinal, plaintext) in data {
            let id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, ordinal);
            let (reference, ciphertext) =
                encrypted_sector(&encryption_key, id, &plaintext).unwrap();
            data_sectors.push(reference);
            ciphertexts.insert(id, ciphertext);
        }
        let metadata = PrivateMetadata {
            format_version: 3,
            root_mode: 0o755,
            root_modified_secs: 1_700_000_000,
            root_modified_nanos: 123,
            entries,
        };
        let encoded = canonical_bytes(&metadata).unwrap();
        let mut metadata_sectors = Vec::new();
        for (ordinal, plaintext) in encoded.chunks(V1_SECTOR_SIZE).enumerate() {
            let id = make_sector_id(
                keys.node_id(),
                revision_id,
                SectorPurpose::Metadata,
                ordinal as u64,
            );
            let (reference, ciphertext) = encrypted_sector(&encryption_key, id, plaintext).unwrap();
            metadata_sectors.push(reference);
            ciphertexts.insert(id, ciphertext);
        }
        let writer = SigningKey::from_bytes(&[75; 32]);
        let mut revision_body = UserRevision {
            format_version: 2,
            guild_id,
            cipher_profile: V1_CIPHER_PROFILE,
            revision_id,
            owner: keys.node_id(),
            writer_epoch: 1,
            writer_public_key: writer.verifying_key().to_bytes(),
            writer_signature: Vec::new(),
            sequence: 1,
            parent: None,
            metadata_sectors,
            data_sectors,
        };
        revision_body.sign_writer(&writer).unwrap();
        let revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision_body, keys).unwrap();
        (revision, ciphertexts)
    }

    fn current_restore_job_record_id(target: &Path) -> [u8; 32] {
        let parent = containing_directory(target).canonicalize().unwrap();
        restore_job_record_id(&parent.join(target.file_name().unwrap())).unwrap()
    }

    #[test]
    fn ordinary_restore_resumes_after_rename_before_parent_sync() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([201; 32]));
        let guild_id = [202; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");

        AFTER_RESTORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(|| anyhow::bail!("injected parent sync failure")));
        });
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert!(target.is_dir());
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_some()
        );

        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ordinary_restore_resumes_from_publishing_before_rename() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([220; 32]));
        let guild_id = [221; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let staging_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let staging = parent.create_child_directory(&staging_name).unwrap();
        parent.sync_all().unwrap();
        let job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: revision.value.revision_id,
            target: temp.path().canonicalize().unwrap().join("restored"),
            parent_identity: parent.identity().unwrap(),
            staging_name,
            staged_identity: Some(staging.identity().unwrap()),
            state: RestoreJobState::Publishing,
        };
        control
            .put_record(
                RESTORE_JOB_KIND,
                revision.value.revision_id.as_bytes(),
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();

        let target = temp.path().join("restored");
        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();
        assert!(target.is_dir());
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn ordinary_restore_rebuilds_a_durably_owned_partial_tree() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([222; 32]));
        let guild_id = [223; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &revision,
                &target,
                |_| anyhow::bail!("injected sector read failure"),
            )
            .is_err()
        );
        let bytes = control
            .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
            .unwrap()
            .unwrap();
        let interrupted: RestoreJob = decode_canonical(&bytes).unwrap();
        assert_eq!(interrupted.state, RestoreJobState::Building);
        assert!(temp.path().join(&interrupted.staging_name).is_dir());

        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();
        assert!(target.is_dir());
        assert!(!temp.path().join(interrupted.staging_name).exists());
    }

    #[test]
    fn ordinary_restore_reserves_a_target_across_revisions() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([224; 32]));
        let guild_id = [225; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (first, first_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (second, second_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &first,
                &target,
                |_| anyhow::bail!("injected first restore interruption"),
            )
            .is_err()
        );
        let error = restore_revision(
            &control,
            &keys,
            guild_id,
            &second,
            &second_ciphertexts,
            &target,
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicts with an unfinished"));

        restore_revision(
            &control,
            &keys,
            guild_id,
            &first,
            &first_ciphertexts,
            &target,
        )
        .unwrap();
        assert!(target.is_dir());
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn concurrent_ordinary_restores_cannot_share_a_target() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([226; 32]));
        let guild_id = [227; 32];
        let database = temp.path().join("control.db");
        let first_control = ControlStore::open(&database, &keys).unwrap();
        let second_control = ControlStore::open(&database, &keys).unwrap();
        let (first, _) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (second, _) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let barrier = Arc::new(Barrier::new(2));

        let run = |control: ControlStore,
                   revision: SignedRecord<UserRevision>,
                   barrier: Arc<Barrier>| {
            let target = target.clone();
            std::thread::spawn(move || {
                let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([226; 32]));
                barrier.wait();
                restore_revision_from_source(&control, &keys, guild_id, &revision, &target, |_| {
                    anyhow::bail!("injected winning restore interruption")
                })
                .unwrap_err()
                .to_string()
            })
        };
        let first_thread = run(first_control, first, barrier.clone());
        let second_thread = run(second_control, second, barrier);
        let errors = [first_thread.join().unwrap(), second_thread.join().unwrap()];

        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("injected winning restore interruption"))
                .count(),
            1
        );
        assert_eq!(
            errors
                .iter()
                .filter(|error| error.contains("conflicts with an unfinished"))
                .count(),
            1
        );
        let control = ControlStore::open(&database, &keys).unwrap();
        assert_eq!(control.records(RESTORE_JOB_KIND).unwrap().len(), 1);
    }

    #[test]
    fn completed_restore_cannot_be_followed_by_a_late_reservation() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([231; 32]));
        let guild_id = [232; 32];
        let database = temp.path().join("control.db");
        let first_control = ControlStore::open(&database, &keys).unwrap();
        let second_control = ControlStore::open(&database, &keys).unwrap();
        let (first, first_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (second, second_ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let barrier = Arc::new(Barrier::new(2));

        let run = |control: ControlStore,
                   revision: SignedRecord<UserRevision>,
                   ciphertexts: BTreeMap<SectorId, Vec<u8>>,
                   barrier: Arc<Barrier>| {
            let target = target.clone();
            std::thread::spawn(move || {
                let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([231; 32]));
                barrier.wait();
                restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target)
            })
        };
        let first_thread = run(first_control, first, first_ciphertexts, barrier.clone());
        let second_thread = run(second_control, second, second_ciphertexts, barrier);
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let control = ControlStore::open(&database, &keys).unwrap();
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
        assert!(target.is_dir());
        assert!(!fs::read_dir(temp.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".mutualbackup-restore-")
        }));
    }

    #[test]
    fn same_revision_restore_callers_cannot_recreate_a_published_job() {
        use std::sync::{Arc, Barrier};

        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([233; 32]));
        let guild_id = [234; 32];
        let database = temp.path().join("control.db");
        let first_control = ControlStore::open(&database, &keys).unwrap();
        let second_control = ControlStore::open(&database, &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let barrier = Arc::new(Barrier::new(2));

        let run = |control: ControlStore, barrier: Arc<Barrier>| {
            let target = target.clone();
            let revision = revision.clone();
            let ciphertexts = ciphertexts.clone();
            std::thread::spawn(move || {
                let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([233; 32]));
                barrier.wait();
                restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target)
            })
        };
        let first_thread = run(first_control, barrier.clone());
        let second_thread = run(second_control, barrier);
        let results = [first_thread.join().unwrap(), second_thread.join().unwrap()];

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
        let control = ControlStore::open(&database, &keys).unwrap();
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
        assert!(target.is_dir());
    }

    #[test]
    fn multiple_legacy_restore_jobs_are_reconciled_without_unbound_deletion() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([235; 32]));
        let guild_id = [236; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (selected_revision, ciphertexts) =
            restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (retired_revision, _) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let selected_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let retired_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let selected_staging = parent.create_child_directory(&selected_name).unwrap();
        let retired_staging = parent.create_child_directory(&retired_name).unwrap();
        fs::write(
            temp.path().join(&retired_name).join("must-survive"),
            b"unbound staging",
        )
        .unwrap();
        parent.sync_all().unwrap();
        let canonical_target = temp.path().canonicalize().unwrap().join("restored");
        let selected_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: selected_revision.value.revision_id,
            target: canonical_target.clone(),
            parent_identity: parent.identity().unwrap(),
            staging_name: selected_name.clone(),
            staged_identity: Some(selected_staging.identity().unwrap()),
            state: RestoreJobState::Building,
        };
        let retired_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: retired_revision.value.revision_id,
            target: canonical_target,
            parent_identity: parent.identity().unwrap(),
            staging_name: retired_name.clone(),
            staged_identity: None,
            state: RestoreJobState::Building,
        };
        drop(retired_staging);
        control
            .put_record(
                RESTORE_JOB_KIND,
                selected_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&selected_job).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                RESTORE_JOB_KIND,
                retired_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&retired_job).unwrap(),
            )
            .unwrap();

        restore_revision(
            &control,
            &keys,
            guild_id,
            &selected_revision,
            &ciphertexts,
            &target,
        )
        .unwrap();

        assert!(target.is_dir());
        assert!(!temp.path().join(selected_name).exists());
        assert_eq!(
            fs::read(temp.path().join(retired_name).join("must-survive")).unwrap(),
            b"unbound staging"
        );
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn retired_legacy_publishing_job_rebuilds_after_reconciliation_crash() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([239; 32]));
        let guild_id = [240; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (first_revision, first_ciphertexts) =
            restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let (retired_revision, retired_ciphertexts) =
            restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let first_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let retired_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        let first_staging = parent.create_child_directory(&first_name).unwrap();
        let retired_staging = parent.create_child_directory(&retired_name).unwrap();
        parent.sync_all().unwrap();
        let canonical_target = temp.path().canonicalize().unwrap().join("restored");
        let first_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: first_revision.value.revision_id,
            target: canonical_target.clone(),
            parent_identity: parent.identity().unwrap(),
            staging_name: first_name.clone(),
            staged_identity: Some(first_staging.identity().unwrap()),
            state: RestoreJobState::Building,
        };
        let retired_job = RestoreJob {
            format_version: 1,
            guild_id,
            revision_id: retired_revision.value.revision_id,
            target: canonical_target,
            parent_identity: parent.identity().unwrap(),
            staging_name: retired_name.clone(),
            staged_identity: Some(retired_staging.identity().unwrap()),
            state: RestoreJobState::Publishing,
        };
        control
            .put_record(
                RESTORE_JOB_KIND,
                first_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&first_job).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                RESTORE_JOB_KIND,
                retired_revision.value.revision_id.as_bytes(),
                &canonical_bytes(&retired_job).unwrap(),
            )
            .unwrap();

        INTERRUPT_AFTER_LEGACY_RESTORE_RETIRE.with(|interrupt| interrupt.set(true));
        assert!(
            restore_revision(
                &control,
                &keys,
                guild_id,
                &first_revision,
                &first_ciphertexts,
                &target,
            )
            .is_err()
        );
        assert!(!temp.path().join(&retired_name).exists());
        assert_eq!(control.records(RESTORE_JOB_KIND).unwrap().len(), 2);
        let resumed =
            resume_restore_publication(&control, &keys, guild_id, &retired_revision, &target)
                .unwrap();
        assert!(!resumed);

        restore_revision(
            &control,
            &keys,
            guild_id,
            &retired_revision,
            &retired_ciphertexts,
            &target,
        )
        .unwrap();

        assert!(target.is_dir());
        assert!(!temp.path().join(first_name).exists());
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn ordinary_restore_never_deletes_an_unbound_staging_name() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([237; 32]));
        let guild_id = [238; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let parent = PinnedDirectory::open(temp.path()).unwrap();
        let unbound_name = format!(".mutualbackup-restore-{}", Uuid::new_v4());
        fs::create_dir(temp.path().join(&unbound_name)).unwrap();
        fs::write(
            temp.path().join(&unbound_name).join("must-survive"),
            b"unverified directory",
        )
        .unwrap();
        let canonical_target = temp.path().canonicalize().unwrap().join("restored");
        let job = RestoreJob {
            format_version: 2,
            guild_id,
            revision_id: revision.value.revision_id,
            target: canonical_target.clone(),
            parent_identity: parent.identity().unwrap(),
            staging_name: unbound_name.clone(),
            staged_identity: None,
            state: RestoreJobState::Building,
        };
        control
            .put_record(
                RESTORE_JOB_KIND,
                &restore_job_record_id(&canonical_target).unwrap(),
                &canonical_bytes(&job).unwrap(),
            )
            .unwrap();

        restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).unwrap();

        assert!(target.is_dir());
        assert_eq!(
            fs::read(temp.path().join(unbound_name).join("must-survive")).unwrap(),
            b"unverified directory"
        );
        assert!(control.records(RESTORE_JOB_KIND).unwrap().is_empty());
    }

    #[test]
    fn ordinary_restore_keeps_renamed_parent_obligation() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let moved = temp.path().join("moved-parent");
        fs::create_dir(&parent).unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([203; 32]));
        let guild_id = [204; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = parent.join("restored");
        let parent_for_hook = parent.clone();
        let moved_for_hook = moved.clone();

        AFTER_RESTORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::rename(&parent_for_hook, &moved_for_hook)?;
                fs::create_dir(&parent_for_hook)?;
                fs::write(parent_for_hook.join("foreign"), b"must survive")?;
                Ok(())
            }));
        });
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert!(moved.join("restored").is_dir());
        assert_eq!(fs::read(parent.join("foreign")).unwrap(), b"must survive");
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_some()
        );
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert_eq!(fs::read(parent.join("foreign")).unwrap(), b"must survive");
    }

    #[test]
    fn ordinary_restore_keeps_obligation_when_target_is_replaced_after_rename() {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([209; 32]));
        let guild_id = [210; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let moved = temp.path().join("moved-restored");
        let target_for_hook = target.clone();
        let moved_for_hook = moved.clone();

        AFTER_RESTORE_RENAME.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                fs::rename(&target_for_hook, &moved_for_hook)?;
                fs::create_dir(&target_for_hook)?;
                fs::write(target_for_hook.join("foreign"), b"must survive")?;
                Ok(())
            }));
        });
        assert!(
            restore_revision(&control, &keys, guild_id, &revision, &ciphertexts, &target).is_err()
        );
        assert!(moved.is_dir());
        assert_eq!(fs::read(target.join("foreign")).unwrap(), b"must survive");
        assert!(
            control
                .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))
                .unwrap()
                .is_some()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_restore_rejects_staging_root_replacement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"must survive").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([205; 32]));
        let guild_id = [206; 32];
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let (revision, ciphertexts) = restore_fixture(&keys, guild_id, Vec::new(), Vec::new());
        let target = temp.path().join("restored");
        let mut replaced = false;

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &revision,
                &target,
                |sector_id| {
                    if !replaced {
                        let bytes = control
                            .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))?
                            .context("restore job missing")?;
                        let job: RestoreJob = decode_canonical(&bytes)?;
                        let moved = temp.path().join("moved-staging");
                        fs::rename(temp.path().join(&job.staging_name), &moved)?;
                        symlink(&external, temp.path().join(&job.staging_name))?;
                        replaced = true;
                    }
                    ciphertexts
                        .get(sector_id)
                        .cloned()
                        .context("missing fixture sector")
                },
            )
            .is_err()
        );
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"must survive"
        );
        assert!(!target.exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ordinary_restore_rejects_descendant_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let external = temp.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("sentinel"), b"must survive").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([207; 32]));
        let guild_id = [208; 32];
        let revision_id = Uuid::new_v4();
        let data_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, 0);
        let plaintext = b"payload".to_vec();
        let (data_reference, data_ciphertext) =
            encrypted_sector(&keys.guild_data_key(&guild_id), data_id, &plaintext).unwrap();
        let entries = vec![
            PrivateEntry::Directory {
                path: "nested".into(),
                mode: 0o755,
                modified_secs: 1,
                modified_nanos: 0,
            },
            PrivateEntry::File {
                path: "nested/payload".into(),
                mode: 0o644,
                logical_len: plaintext.len() as u64,
                modified_secs: 1,
                modified_nanos: 0,
                sectors: vec![data_reference.clone()],
            },
        ];
        let (mut revision, mut ciphertexts) = restore_fixture(&keys, guild_id, entries, Vec::new());
        revision.value.revision_id = revision_id;
        revision.value.data_sectors = vec![data_reference];
        revision
            .value
            .sign_writer(&SigningKey::from_bytes(&[75; 32]))
            .unwrap();
        revision = SignedRecord::sign(USER_REVISION_DOMAIN, revision.value, &keys).unwrap();
        ciphertexts.insert(data_id, data_ciphertext);
        let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
        let target = temp.path().join("restored");
        let mut replaced = false;

        assert!(
            restore_revision_from_source(
                &control,
                &keys,
                guild_id,
                &revision,
                &target,
                |sector_id| {
                    if *sector_id == data_id && !replaced {
                        let bytes = control
                            .get_record(RESTORE_JOB_KIND, &current_restore_job_record_id(&target))?
                            .context("restore job missing")?;
                        let job: RestoreJob = decode_canonical(&bytes)?;
                        let staging = temp.path().join(&job.staging_name);
                        fs::rename(staging.join("nested"), staging.join("moved-nested"))?;
                        symlink(&external, staging.join("nested"))?;
                        replaced = true;
                    }
                    ciphertexts
                        .get(sector_id)
                        .cloned()
                        .context("missing fixture sector")
                },
            )
            .is_err()
        );
        assert_eq!(
            fs::read(external.join("sentinel")).unwrap(),
            b"must survive"
        );
        assert!(!target.exists());
    }

    #[cfg(target_os = "linux")]
    fn bind_mount_for_recovery_test(source: &Path, target: &Path) {
        let output = std::process::Command::new("sudo")
            .args(["-n", "mount", "--bind"])
            .arg(source)
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot create recovery-test bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    fn unmount_for_recovery_test(target: &Path) {
        let output = std::process::Command::new("sudo")
            .args(["-n", "umount"])
            .arg(target)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "cannot remove recovery-test bind mount: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn rejected_capture_can_be_repaired_and_replanned() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("capture-replan-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"recoverable capture").unwrap();
        let fifo = source.join("unsupported");
        let encoded = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);

        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([41; 32]));
        let mut control =
            ControlStore::open(run_root.join("control.db"), &keys).expect("open control store");
        let guild_id = [42; 32];
        let revision_id = Uuid::from_bytes([43; 16]);
        let first = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            &source,
            1,
            Some(revision_id),
            WriterCredentials {
                epoch: 1,
                secret: &[17; 32],
                captured_change_sequence: None,
            },
        );
        assert!(first.is_err());
        assert!(
            control
                .get_record("capture-intent", revision_id.as_bytes())
                .unwrap()
                .is_none()
        );

        fs::remove_file(&fifo).unwrap();
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            &source,
            1,
            Some(revision_id),
            WriterCredentials {
                epoch: 1,
                secret: &[17; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        assert_eq!(revision.value.revision_id, revision_id);
        let manifest: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        manifest.remove().unwrap();
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn version_one_capture_intent_migrates_conservatively() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("capture-intent-v1-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"legacy pending capture").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([51; 32]));
        let control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let revision_id = Uuid::from_bytes([52; 16]);
        let legacy = LegacyCaptureIntentV1 {
            format_version: 1,
            guild_id: [53; 32],
            revision_id,
            sequence: 1,
            parent: None,
            requested_source: source.clone(),
            plan: ReflinkAnchor::plan(&source).unwrap(),
        };
        control
            .put_record(
                "capture-intent",
                revision_id.as_bytes(),
                &canonical_bytes(&legacy).unwrap(),
            )
            .unwrap();

        reconcile_pending_captures(&control).unwrap();

        let migrated: CaptureIntent = decode_canonical(
            &control
                .get_record("capture-intent", revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(migrated.format_version, 2);
        assert_eq!(migrated.revision_id, revision_id);
        assert_eq!(migrated.requested_source, source);
        assert_eq!(migrated.captured_change_sequence, None);
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn recovered_anchor_resumes_after_capture_before_database_commit() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("reanchor-resume-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        let restored = run_root.join("restored");
        fs::create_dir_all(&source).unwrap();
        fs::write(source.join("payload"), b"recovered anchor payload").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([47; 32]));
        let mut control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let guild_id = [48; 32];
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            &source,
            1,
            None,
            WriterCredentials {
                epoch: 1,
                secret: &[18; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        restore_revision_from_source(
            &control,
            &keys,
            guild_id,
            &revision,
            &restored,
            |sector_id| render_sector(&control, &keys, sector_id, Some(&guild_id)),
        )
        .unwrap();
        let old: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        old.remove().unwrap();

        INTERRUPT_RECOVERY_ANCHOR_AFTER_CAPTURE.with(|interrupt| interrupt.set(true));
        assert!(
            reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored)
                .is_err()
        );
        assert!(
            control
                .get_record(
                    RECOVERY_ANCHOR_INTENT_KIND,
                    revision.value.revision_id.as_bytes(),
                )
                .unwrap()
                .is_some()
        );

        reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored).unwrap();
        assert!(
            control
                .get_record(
                    RECOVERY_ANCHOR_INTENT_KIND,
                    revision.value.revision_id.as_bytes(),
                )
                .unwrap()
                .is_none()
        );
        let current: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_ne!(current.anchor_id, old.anchor_id);
        assert!(control.records(ANCHOR_RETIREMENT_KIND).unwrap().is_empty());
        let mut payload = String::new();
        current
            .file_locator("payload".to_owned())
            .unwrap()
            .open()
            .unwrap()
            .read_to_string(&mut payload)
            .unwrap();
        assert_eq!(payload, "recovered anchor payload");

        let reference = revision.value.data_sectors[0].clone();
        let ciphertext = render_sector(&control, &keys, &reference.id, Some(&guild_id)).unwrap();
        assert!(!local_recipe_is_inline(&control, &reference.id).unwrap());
        install_recovered_sector_recipe(
            &mut control,
            &keys,
            guild_id,
            reference.clone(),
            &ciphertext,
        )
        .unwrap();
        assert!(!local_recipe_is_inline(&control, &reference.id).unwrap());

        current.remove().unwrap();
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn failed_old_anchor_removal_remains_a_durable_retirement() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("reanchor-retire-{}", Uuid::new_v4()));
        let source = run_root.join("source");
        let restored = run_root.join("restored");
        let external = run_root.join("external");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir(&external).unwrap();
        fs::write(source.join("payload"), b"retirement payload").unwrap();
        let sentinel = external.join("must-survive");
        fs::write(&sentinel, b"external bytes").unwrap();
        let keys = KeyMaterial::from_seed(&mb_core::Seed::from_bytes([49; 32]));
        let mut control = ControlStore::open(run_root.join("control.db"), &keys).unwrap();
        let guild_id = [50; 32];
        let revision = prepare_revision(
            &mut control,
            &keys,
            guild_id,
            &source,
            1,
            None,
            WriterCredentials {
                epoch: 1,
                secret: &[19; 32],
                captured_change_sequence: None,
            },
        )
        .unwrap();
        restore_revision_from_source(
            &control,
            &keys,
            guild_id,
            &revision,
            &restored,
            |sector_id| render_sector(&control, &keys, sector_id, Some(&guild_id)),
        )
        .unwrap();
        let old: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        let old_root = old.area.path_hint.join(old.anchor_id.to_string());
        bind_mount_for_recovery_test(&external, &old_root);

        reanchor_recovered_revision(&mut control, &keys, guild_id, &revision, &restored).unwrap();
        assert_eq!(control.records(ANCHOR_RETIREMENT_KIND).unwrap().len(), 1);
        unmount_for_recovery_test(&old_root);
        assert_eq!(fs::read(&sentinel).unwrap(), b"external bytes");

        reconcile_pending_captures(&control).unwrap();
        assert!(control.records(ANCHOR_RETIREMENT_KIND).unwrap().is_empty());
        assert!(!old_root.exists());
        let current: mb_store::StableAnchorManifest = decode_canonical(
            &control
                .get_record("anchor-manifest", revision.value.revision_id.as_bytes())
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        current.remove().unwrap();
        drop(control);
        fs::remove_dir_all(run_root).unwrap();
    }

    #[test]
    fn bare_restore_target_uses_the_current_directory() {
        assert_eq!(containing_directory(Path::new("restored")), Path::new("."));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "temporarily lowers the process descriptor limit"]
    fn restore_directory_descriptor_use_is_bounded() {
        struct OpenFileLimitGuard(libc::rlimit);

        impl Drop for OpenFileLimitGuard {
            fn drop(&mut self) {
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &self.0) }, 0);
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let staging = PinnedDirectory::open(temp.path()).unwrap();
        let metadata = PrivateMetadata {
            format_version: 3,
            root_mode: 0o755,
            root_modified_secs: 1_700_000_000,
            root_modified_nanos: 0,
            entries: (0..512)
                .map(|ordinal| PrivateEntry::Directory {
                    path: format!("directory-{ordinal:04}"),
                    mode: 0o755,
                    modified_secs: 1_700_000_000,
                    modified_nanos: 0,
                })
                .collect(),
        };
        let mut original = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, original.as_mut_ptr()) },
            0
        );
        let original = unsafe { original.assume_init() };
        assert!(original.rlim_cur >= 96);
        let limited = libc::rlimit {
            rlim_cur: 96,
            rlim_max: original.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);
        let limit = OpenFileLimitGuard(original);

        restore_entries(
            &staging,
            &metadata,
            &[0; 32],
            &mut |_| unreachable!(),
            false,
        )
        .unwrap();

        drop(limit);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 512);
    }

    #[test]
    fn decodes_immutable_native_id_v2_fixture() {
        const FIXTURE: &[u8] = &[
            2, 237, 3, 1, 123, 2, 2, 1, 97, 164, 3, 0, 3, 200, 3, 7, 9, 0, 2, 1, 98, 164, 3, 0, 3,
            200, 3, 7, 9, 0,
        ];
        assert_v2_hard_link_fixture(decode_private_metadata(FIXTURE).unwrap());
    }

    #[test]
    fn decodes_immutable_link_group_v2_fixture() {
        const FIXTURE: &[u8] = &[
            2, 237, 3, 1, 123, 2, 2, 1, 97, 164, 3, 0, 3, 200, 3, 0, 0, 2, 1, 98, 164, 3, 0, 3,
            200, 3, 0, 0,
        ];
        assert_v2_hard_link_fixture(decode_private_metadata(FIXTURE).unwrap());
    }

    fn assert_v2_hard_link_fixture(metadata: PrivateMetadata) {
        assert_eq!(metadata.format_version, 2);
        assert_eq!(metadata.root_mode, 0o755);
        assert_eq!(metadata.entries.len(), 2);
        for (entry, path) in metadata.entries.iter().zip(["a", "b"]) {
            assert!(matches!(
                entry,
                PrivateEntry::FileV2 {
                    path: actual_path,
                    mode: 0o644,
                    logical_len: 0,
                    modified_secs: -2,
                    modified_nanos: 456,
                    link_group: 0,
                    data_extents,
                } if actual_path == path && data_extents.is_empty()
            ));
        }
    }
}
