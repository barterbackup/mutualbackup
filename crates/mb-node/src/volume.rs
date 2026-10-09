use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mb_core::{
    KeyMaterial, MerkleCommitment, MerkleRangeProof, NodeId, SignedRecord, WrappedDatabaseKey,
    canonical_bytes, decode_canonical,
};
use mb_store::{
    ControlStore, DatabaseError, DatabaseShellResult, ParityObject, ParityStore,
    ReadyVariableObject, VariableParityObject,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const VOLUME_MANIFEST_DOMAIN: &[u8] = b"mutualbackup/local-volume-manifest/v1";
const VOLUME_MANIFEST_FILE: &str = ".mutualbackup-volume";
const CONTROL_KEY_FILE: &str = "control.key";
const MAX_LOCAL_MANIFEST_BYTES: usize = 64 * 1024;
const MAX_VOLUME_RECEIPT_BYTES: usize = 512;
#[cfg(target_os = "linux")]
const MAX_BOUNDED_VOLUME_REGISTRY_BYTES: usize = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_BOUNDED_VOLUME_RECORDS: usize = 1023;
const DATABASE_PAGE_BYTES: u64 = 4096;
const PHYSICAL_WRITE_FIXED_RESERVE: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum VolumeInterruption {
    WriteIntentStored,
    ObjectPublished,
    ReceiptStored,
    WriteIntentRetired,
    MigrationSourceReceiptRetired,
    MigrationDestinationStored,
    MigrationSourceRemoved,
    MigrationReceiptStored,
    MigrationStateStored,
    GarbageObjectRemoved,
    GarbageReceiptRetired,
    AttemptObjectActivated,
    CodingUploadReceiptStored,
    VariableMigrationIntentStored,
    VariableMigrationDestinationReady,
    VariableMigrationReceiptStored,
    VariableMigrationSourceRemoved,
    VariableMigrationIntentRetired,
    VariableInformationEvidenceStored,
}

#[cfg(test)]
thread_local! {
    static NEXT_VOLUME_INTERRUPTION: std::cell::Cell<Option<VolumeInterruption>> =
        const { std::cell::Cell::new(None) };
}

fn volume_interruption(point: VolumeInterruption) -> Result<()> {
    #[cfg(test)]
    NEXT_VOLUME_INTERRUPTION.with(|next| {
        if next.get() == Some(point) {
            next.set(None);
            bail!("injected interruption after {point:?}");
        }
        Ok(())
    })?;
    let _ = point;
    Ok(())
}

#[cfg(test)]
pub(crate) fn interrupt_next_volume_transition(point: VolumeInterruption) {
    NEXT_VOLUME_INTERRUPTION.with(|next| next.set(Some(point)));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageVolumeState {
    Online,
    Offline,
    Draining,
    Retired,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageVolumeStatus {
    pub volume_id: Uuid,
    #[cfg_attr(target_os = "linux", serde(with = "mb_store::raw_path_bytes"))]
    pub path: PathBuf,
    pub state: StorageVolumeState,
    pub budget_bytes: u64,
    pub headroom_bytes: u64,
    pub used_bytes: Option<u64>,
    pub allocated_bytes: Option<u64>,
    pub available_bytes: Option<u64>,
    pub object_count: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StorageScrubReport {
    pub volume_id: Uuid,
    pub checked_objects: u64,
    pub checked_bytes: u64,
    pub corrupt_objects: Vec<([u8; 32], u8)>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct VolumeManifest {
    format_version: u16,
    owner: NodeId,
    volume_id: Uuid,
    database_file: String,
    wrapped_database_key: WrappedDatabaseKey,
}

/// An existing local parity volume opened without registry reconciliation,
/// key publication/rekeying, schema migration or shard retirement.
pub struct PreservedParityVolume {
    volume_id: Uuid,
    store: ParityStore,
    #[cfg(target_os = "linux")]
    guard: mb_store::PreservedReadGuard,
}

impl PreservedParityVolume {
    pub fn open(root: &Path, keys: &KeyMaterial) -> Result<Self> {
        let metadata = fs::symlink_metadata(root)?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            bail!("preserved parity volume must be an existing directory");
        }
        let manifest_path = root.join(VOLUME_MANIFEST_FILE);
        let (volume_id, path, database_key) = match fs::symlink_metadata(&manifest_path) {
            Ok(_) => {
                let signed: SignedRecord<VolumeManifest> = read_private_record(&manifest_path)?;
                signed.verify(VOLUME_MANIFEST_DOMAIN)?;
                validate_manifest(&signed.value, keys.node_id())?;
                if signed.signer != keys.node_id() {
                    bail!("parity volume manifest was not signed by its owner");
                }
                let key = keys.unwrap_database_key(
                    &volume_database_id(signed.value.volume_id),
                    &signed.value.wrapped_database_key,
                )?;
                (
                    signed.value.volume_id,
                    root.join(&signed.value.database_file),
                    key,
                )
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let id = legacy_default_volume_id(keys);
                (
                    id,
                    root.join("parity.db"),
                    keys.database_key(&legacy_volume_database_id(id)),
                )
            }
            Err(error) => return Err(error.into()),
        };
        #[cfg(target_os = "linux")]
        let (store, guard) = ParityStore::open_preserved_read_only_with_keys(
            &path,
            volume_id.as_bytes(),
            &[
                database_key,
                keys.database_key(&legacy_volume_database_id(volume_id)),
            ],
        )?;
        #[cfg(not(target_os = "linux"))]
        let store = ParityStore::open_existing_read_only_with_key(
            &path,
            volume_id.as_bytes(),
            &database_key,
        )
        .or_else(|wrapped_error| {
            ParityStore::open_existing_read_only_with_key(
                &path,
                volume_id.as_bytes(),
                &keys.database_key(&legacy_volume_database_id(volume_id)),
            )
            .map_err(|_| wrapped_error)
        })?;
        Ok(Self {
            volume_id,
            store,
            #[cfg(target_os = "linux")]
            guard,
        })
    }

    /// Verify preserved input versions immediately before publishing recovery.
    #[cfg(target_os = "linux")]
    pub fn verify_unchanged(&self) -> Result<()> {
        self.guard.verify_unchanged()
    }

    pub fn volume_id(&self) -> Uuid {
        self.volume_id
    }

    pub fn load_fixed(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        index: u8,
        root: &[u8; 32],
    ) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        self.verify_unchanged()?;
        let object = self.store.load_ready(group_id, index)?;
        if object.guild_id != *guild_id || object.root != *root {
            bail!("preserved fixed shard differs from its authenticated reference");
        }
        #[cfg(target_os = "linux")]
        self.verify_unchanged()?;
        Ok(object.bytes)
    }

    pub fn load_variable(
        &self,
        guild_id: &[u8; 32],
        group_id: &[u8; 32],
        index: u16,
        commitment: &MerkleCommitment,
    ) -> Result<Vec<u8>> {
        #[cfg(target_os = "linux")]
        self.verify_unchanged()?;
        let object = self.store.load_ready_variable(group_id, index)?;
        if object.guild_id != *guild_id || object.commitment != *commitment {
            bail!("preserved variable shard differs from its authenticated reference");
        }
        #[cfg(target_os = "linux")]
        self.verify_unchanged()?;
        Ok(object.bytes)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct VolumeRecord {
    format_version: u16,
    volume_id: Uuid,
    #[cfg_attr(target_os = "linux", serde(with = "mb_store::raw_path_bytes"))]
    path: PathBuf,
    database_file: String,
    wrapped_database_key: WrappedDatabaseKey,
    state: StorageVolumeState,
    budget_bytes: u64,
    headroom_bytes: u64,
    last_error: Option<String>,
    configured: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
#[cfg_attr(test, derive(Serialize))]
struct VolumeRecordBeforeConfiguredState {
    format_version: u16,
    volume_id: Uuid,
    #[cfg_attr(target_os = "linux", serde(with = "mb_store::raw_path_bytes"))]
    path: PathBuf,
    database_file: String,
    wrapped_database_key: WrappedDatabaseKey,
    state: StorageVolumeState,
    budget_bytes: u64,
    headroom_bytes: u64,
    last_error: Option<String>,
}

impl From<VolumeRecordBeforeConfiguredState> for VolumeRecord {
    fn from(record: VolumeRecordBeforeConfiguredState) -> Self {
        Self {
            format_version: record.format_version,
            volume_id: record.volume_id,
            path: record.path,
            database_file: record.database_file,
            wrapped_database_key: record.wrapped_database_key,
            state: record.state,
            budget_bytes: record.budget_bytes,
            headroom_bytes: record.headroom_bytes,
            last_error: record.last_error,
            configured: true,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct VolumeReceipt {
    pub format_version: u16,
    pub volume_id: Uuid,
    pub guild_id: [u8; 32],
    pub group_id: [u8; 32],
    pub shard_index: u8,
    pub root: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct VolumeWriteIntent {
    format_version: u16,
    receipt: VolumeReceipt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AttemptVolumeRecord {
    format_version: u16,
    attempt_id: [u8; 16],
    receipt: VolumeReceipt,
}

const VARIABLE_MIGRATION_KIND: &str = "volume-variable-migration-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct VariableVolumeMigration {
    format_version: u16,
    source_volume_id: Uuid,
    destination: VolumeReceipt,
    attempt_id: [u8; 16],
    verification_hash: [u8; 32],
    commitment: MerkleCommitment,
    staged_receipt_hash: [u8; 32],
    destination_attempt_id: [u8; 16],
    destination_receipt_hash: [u8; 32],
    cancelled: bool,
}

fn validate_variable_migration(record_id: &[u8], intent: &VariableVolumeMigration) -> Result<()> {
    validate_receipt(&intent.destination)?;
    validate_volume_object_record_id(record_id, &intent.destination)?;
    intent.commitment.validate()?;
    if intent.format_version != 1
        || intent.destination.format_version != 2
        || intent.source_volume_id.is_nil()
        || intent.source_volume_id == intent.destination.volume_id
        || intent.attempt_id == [0; 16]
        || intent.verification_hash == [0; 32]
        || intent.commitment.root != intent.destination.root
        || intent.staged_receipt_hash == [0; 32]
        || intent.destination_attempt_id == [0; 16]
        || intent.destination_receipt_hash == [0; 32]
        || intent.commitment.byte_len > mb_core::MAX_PROFILE_SHARD_SIZE
    {
        bail!("invalid variable volume migration intent");
    }
    Ok(())
}

fn ensure_variable_migration_source(
    intent: &VariableVolumeMigration,
    ready: &ReadyVariableObject,
) -> Result<()> {
    let object = &ready.object;
    if object.format_version != 2
        || object.guild_id != intent.destination.guild_id
        || object.group_id != intent.destination.group_id
        || object.shard_index != u16::from(intent.destination.shard_index)
        || object.commitment != intent.commitment
        || ready.attempt_id != intent.attempt_id
        || ready.verification_hash != intent.verification_hash
        || *blake3::hash(&ready.staged_receipt).as_bytes() != intent.staged_receipt_hash
    {
        bail!("variable migration object conflicts with its durable intent");
    }
    Ok(())
}

fn ensure_variable_migration_destination(
    intent: &VariableVolumeMigration,
    ready: &ReadyVariableObject,
) -> Result<()> {
    let object = &ready.object;
    if object.format_version != 2
        || object.guild_id != intent.destination.guild_id
        || object.group_id != intent.destination.group_id
        || object.shard_index != u16::from(intent.destination.shard_index)
        || object.commitment != intent.commitment
        || ready.attempt_id != intent.destination_attempt_id
        || ready.verification_hash != intent.verification_hash
        || *blake3::hash(&ready.staged_receipt).as_bytes() != intent.destination_receipt_hash
    {
        bail!("variable migration destination conflicts with its durable evidence");
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AttemptRetirement {
    format_version: u16,
    volume_id: Uuid,
    attempt_id: [u8; 16],
    group_id: [u8; 32],
    shard_index: u8,
    cleanup_verification_hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct AttemptReservationRecord {
    format_version: u16,
    attempt_id: [u8; 16],
    volume_id: Uuid,
    guild_id: [u8; 32],
    shard_index: u8,
    byte_length: u32,
}

#[derive(Clone)]
pub(crate) struct VolumeReaderConfig {
    pub volume_id: Uuid,
    pub path: PathBuf,
    pub database_key: [u8; 32],
}

struct StorageVolume {
    record: VolumeRecord,
    database_key: [u8; 32],
    store: Option<ParityStore>,
}

pub(crate) struct StorageVolumes {
    keys: Arc<KeyMaterial>,
    default_path: PathBuf,
    volumes: BTreeMap<Uuid, StorageVolume>,
}

impl StorageVolumes {
    pub(crate) fn open(
        data_dir: &Path,
        keys: Arc<KeyMaterial>,
        control: &ControlStore,
    ) -> Result<Self> {
        let mut records = load_volume_records(control)?;
        if records.is_empty() {
            let record = initialize_volume(data_dir, Some("parity.db"), u64::MAX, 0, &keys)?;
            records.push(record);
            store_volume_records(control, &records)?;
        }

        let mut volumes = BTreeMap::new();
        let mut canonical_paths = BTreeSet::new();
        for mut record in records {
            validate_volume_record(&record)?;
            let database_key = keys
                .unwrap_database_key(
                    &volume_database_id(record.volume_id),
                    &record.wrapped_database_key,
                )
                .context("cannot unwrap parity database key")?;
            let mut store = None;
            if record.path.is_dir() {
                let path = record.path.canonicalize().with_context(|| {
                    format!("cannot resolve parity volume {}", record.path.display())
                })?;
                if !canonical_paths.insert(path.clone()) {
                    bail!(
                        "two configured parity volumes resolve to {}",
                        path.display()
                    );
                }
                record.path = path;
                if record.configured || record.state == StorageVolumeState::Draining {
                    match open_volume_store(&record, &database_key, &keys) {
                        Ok(opened) => {
                            if matches!(
                                record.state,
                                StorageVolumeState::Online | StorageVolumeState::Draining
                            ) {
                                record.last_error = None;
                            }
                            store = Some(opened);
                        }
                        Err(error) => {
                            record.state = StorageVolumeState::Failed;
                            record.last_error = Some(truncated_error(&error));
                        }
                    }
                }
            } else if !matches!(
                record.state,
                StorageVolumeState::Retired | StorageVolumeState::Draining
            ) {
                record.state = StorageVolumeState::Offline;
                record.last_error = Some("configured volume is absent".to_owned());
            } else if record.state == StorageVolumeState::Draining {
                record.last_error = Some("draining volume is absent".to_owned());
            }
            if volumes
                .insert(
                    record.volume_id,
                    StorageVolume {
                        record,
                        database_key,
                        store,
                    },
                )
                .is_some()
            {
                bail!("duplicate parity volume UUID");
            }
        }
        let set = Self {
            keys,
            default_path: data_dir.to_path_buf(),
            volumes,
        };
        set.persist(control)?;
        Ok(set)
    }

    pub(crate) fn configure(
        &mut self,
        control: &ControlStore,
        paths: &[PathBuf],
        budget_bytes: u64,
        headroom_bytes: u64,
    ) -> Result<()> {
        if budget_bytes == 0 || headroom_bytes >= budget_bytes {
            bail!("parity volume budget must exceed its reserved headroom");
        }
        let requested = if paths.is_empty() {
            vec![self.default_path.clone()]
        } else {
            paths.to_vec()
        };
        let mut configured = BTreeSet::new();
        for requested_path in requested {
            let path = match require_online_directory(&requested_path) {
                Ok(path) => path,
                Err(error) => {
                    if !configured.insert(requested_path.clone()) {
                        bail!(
                            "parity volume is configured more than once: {}",
                            requested_path.display()
                        );
                    }
                    let Some(volume) = self
                        .volumes
                        .values_mut()
                        .find(|volume| volume.record.path == requested_path)
                    else {
                        return Err(error);
                    };
                    volume.record.budget_bytes = budget_bytes;
                    volume.record.headroom_bytes = headroom_bytes;
                    if volume.record.state == StorageVolumeState::Retired {
                        volume.record.configured = false;
                        volume.store = None;
                        continue;
                    }
                    volume.record.configured = true;
                    if volume.record.state == StorageVolumeState::Draining {
                        volume.record.last_error = Some("draining volume is absent".to_owned());
                    } else {
                        volume.record.state = StorageVolumeState::Offline;
                        volume.record.last_error = Some("configured volume is absent".to_owned());
                    }
                    volume.store = None;
                    continue;
                }
            };
            if !configured.insert(path.clone()) {
                bail!(
                    "parity volume is configured more than once: {}",
                    path.display()
                );
            }
            if let Some(volume) = self
                .volumes
                .values_mut()
                .find(|volume| volume.record.path == path)
            {
                volume.record.budget_bytes = budget_bytes;
                volume.record.headroom_bytes = headroom_bytes;
                if volume.record.state == StorageVolumeState::Retired {
                    volume.record.configured = false;
                    continue;
                }
                volume.record.configured = true;
                if matches!(
                    volume.record.state,
                    StorageVolumeState::Offline | StorageVolumeState::Draining
                ) && volume.store.is_none()
                {
                    volume.store = Some(open_volume_store(
                        &volume.record,
                        &volume.database_key,
                        &self.keys,
                    )?);
                }
                if volume.record.state == StorageVolumeState::Offline {
                    volume.record.state = StorageVolumeState::Online;
                    volume.record.last_error = None;
                } else if volume.record.state == StorageVolumeState::Draining {
                    volume.record.last_error = None;
                }
                continue;
            }
            if let Some(manifest) = read_volume_manifest(&path, &self.keys)?
                && let Some(volume) = self.volumes.get_mut(&manifest.volume_id)
            {
                if volume.store.is_some() {
                    bail!(
                        "parity volume UUID {} is available at more than one configured path",
                        manifest.volume_id
                    );
                }
                if volume.record.database_file != manifest.database_file
                    || volume.record.wrapped_database_key != manifest.wrapped_database_key
                {
                    bail!("parity volume manifest conflicts with the control registry");
                }
                volume.record.path = path;
                volume.record.budget_bytes = budget_bytes;
                volume.record.headroom_bytes = headroom_bytes;
                if volume.record.state == StorageVolumeState::Retired {
                    volume.record.configured = false;
                    volume.store = None;
                    continue;
                }
                volume.record.configured = true;
                match open_volume_store(&volume.record, &volume.database_key, &self.keys) {
                    Ok(store) => {
                        if volume.record.state != StorageVolumeState::Draining {
                            volume.record.state = StorageVolumeState::Online;
                        }
                        volume.record.last_error = None;
                        volume.store = Some(store);
                    }
                    Err(error) => {
                        volume.record.state = StorageVolumeState::Failed;
                        volume.record.last_error = Some(truncated_error(&error));
                        volume.store = None;
                    }
                }
                continue;
            }
            let record = initialize_volume(&path, None, budget_bytes, headroom_bytes, &self.keys)?;
            if self.volumes.get(&record.volume_id).is_some_and(|existing| {
                existing.store.is_some() || configured.contains(&existing.record.path)
            }) {
                bail!(
                    "parity volume UUID {} is available at more than one configured path",
                    record.volume_id
                );
            }
            let database_key = self.keys.unwrap_database_key(
                &volume_database_id(record.volume_id),
                &record.wrapped_database_key,
            )?;
            let store = open_volume_store(&record, &database_key, &self.keys)?;
            self.volumes.insert(
                record.volume_id,
                StorageVolume {
                    record,
                    database_key,
                    store: Some(store),
                },
            );
        }
        for volume in self.volumes.values_mut() {
            if !configured.contains(&volume.record.path) {
                volume.record.configured = false;
                if volume.record.state == StorageVolumeState::Online {
                    volume.record.state = StorageVolumeState::Offline;
                    volume.record.last_error = Some("volume is no longer configured".to_owned());
                    volume.store = None;
                }
            }
        }
        self.persist(control)
    }

    pub(crate) fn set_uniform_budget(
        &mut self,
        control: &ControlStore,
        budget_bytes: u64,
    ) -> Result<()> {
        if budget_bytes == 0 {
            bail!("parity storage budget must be greater than zero");
        }
        for volume in self.volumes.values_mut() {
            volume.record.budget_bytes = budget_bytes;
            if volume.record.headroom_bytes >= budget_bytes {
                volume.record.headroom_bytes = 0;
            }
        }
        self.persist(control)
    }

    pub(crate) fn statuses(&self) -> Result<Vec<StorageVolumeStatus>> {
        self.volumes
            .values()
            .map(|volume| {
                let mut last_error = volume.record.last_error.clone();
                let measurements = volume.store.as_ref().map(|store| {
                    Ok::<_, anyhow::Error>((
                        store.used_bytes()?,
                        store.allocated_bytes()?,
                        fs2::available_space(&volume.record.path)?,
                        store.ready_object_count()?,
                    ))
                });
                let (used_bytes, allocated_bytes, available_bytes, object_count) =
                    match measurements.transpose() {
                        Ok(Some((used, allocated, available, count))) => {
                            (Some(used), Some(allocated), Some(available), Some(count))
                        }
                        Ok(None) => (None, None, None, None),
                        Err(error) => {
                            last_error.get_or_insert_with(|| truncated_error(&error));
                            (None, None, None, None)
                        }
                    };
                Ok(StorageVolumeStatus {
                    volume_id: volume.record.volume_id,
                    path: volume.record.path.clone(),
                    state: volume.record.state,
                    budget_bytes: volume.record.budget_bytes,
                    headroom_bytes: volume.record.headroom_bytes,
                    used_bytes,
                    allocated_bytes,
                    available_bytes,
                    object_count,
                    last_error,
                })
            })
            .collect()
    }

    pub(crate) fn coding_capacity(&self, control: &ControlStore, shard_size: u32) -> Result<u64> {
        validate_coding_shard_size(shard_size)?;
        let mut devices = BTreeMap::new();
        for volume in self.volumes.values() {
            if volume.record.state != StorageVolumeState::Online {
                continue;
            }
            let Some(store) = volume.store.as_ref() else {
                continue;
            };
            add_volume_coding_capacity(&mut devices, &volume.record, store, shard_size)?;
        }
        device_coding_capacity(control, &devices, shard_size)
    }

    pub(crate) fn reclaim(&mut self, volume_id: Option<Uuid>) -> Result<u64> {
        if let Some(volume_id) = volume_id
            && !self.volumes.contains_key(&volume_id)
        {
            bail!("unknown parity volume");
        }
        let mut reclaimed = 0_u64;
        for (id, volume) in &mut self.volumes {
            if volume_id.is_some_and(|selected| selected != *id) {
                continue;
            }
            let Some(store) = volume.store.as_mut() else {
                if volume_id.is_some() {
                    bail!("parity volume is not available for reclamation");
                }
                continue;
            };
            let before = store.allocated_bytes()?;
            store.reclaim_space()?;
            reclaimed = reclaimed.saturating_add(before.saturating_sub(store.allocated_bytes()?));
        }
        Ok(reclaimed)
    }

    pub(crate) fn reader_configs(&self) -> Vec<VolumeReaderConfig> {
        self.volumes
            .values()
            .filter_map(|volume| {
                volume
                    .store
                    .as_ref()
                    .filter(|_| {
                        matches!(
                            volume.record.state,
                            StorageVolumeState::Online | StorageVolumeState::Draining
                        )
                    })
                    .map(|store| VolumeReaderConfig {
                        volume_id: volume.record.volume_id,
                        path: store.path().to_path_buf(),
                        database_key: volume.database_key,
                    })
            })
            .collect()
    }

    pub(crate) fn protection_degraded(&self, control: &ControlStore) -> Result<bool> {
        if self.volumes.values().any(|volume| {
            volume.record.configured
                && matches!(
                    volume.record.state,
                    StorageVolumeState::Offline | StorageVolumeState::Failed
                )
        }) {
            return Ok(true);
        }
        for (_, bytes) in control.records("volume-receipt")? {
            let receipt: VolumeReceipt = decode_canonical(&bytes)?;
            validate_receipt(&receipt)?;
            let available = self.volumes.get(&receipt.volume_id).is_some_and(|volume| {
                volume.record.configured
                    && matches!(
                        volume.record.state,
                        StorageVolumeState::Online | StorageVolumeState::Draining
                    )
                    && volume.store.is_some()
            });
            if !available {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub(crate) fn load_ready(&self, group_id: &[u8; 32], shard_index: u8) -> Result<ParityObject> {
        let mut first_error = None;
        for volume in self.volumes.values() {
            if !matches!(
                volume.record.state,
                StorageVolumeState::Online | StorageVolumeState::Draining
            ) {
                continue;
            }
            let Some(store) = &volume.store else {
                continue;
            };
            match store.load_ready(group_id, shard_index) {
                Ok(object) => return Ok(object),
                Err(DatabaseError::NotReady) => {}
                Err(error) => {
                    first_error.get_or_insert(error);
                }
            }
        }
        match first_error {
            Some(error) => Err(error.into()),
            None => Err(DatabaseError::NotReady.into()),
        }
    }

    pub(crate) fn remove_unreachable(
        &mut self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u8,
        root: &[u8; 32],
    ) -> Result<bool> {
        self.remove_unreachable_matching_attempt(control, group_id, shard_index, root, None)
    }

    pub(crate) fn remove_unreachable_for_attempt(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        verification_hash: &[u8; 32],
        group_id: &[u8; 32],
        shard_index: u8,
        root: &[u8; 32],
    ) -> Result<bool> {
        self.remove_unreachable_matching_attempt(
            control,
            group_id,
            shard_index,
            root,
            Some((attempt_id, verification_hash)),
        )
    }

    fn remove_unreachable_matching_attempt(
        &mut self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u8,
        root: &[u8; 32],
        attempt: Option<(&[u8; 16], &[u8; 32])>,
    ) -> Result<bool> {
        if control.catalog_checkpoint_payload_is_pinned(*group_id, u16::from(shard_index), *root)? {
            return Ok(false);
        }
        let record_id = volume_object_id(group_id, shard_index);
        self.cancel_variable_migration_for_gc(control, &record_id, root, attempt)?;
        let receipt_volume = self
            .receipt(control, group_id, shard_index)?
            .map(|receipt| receipt.volume_id);
        let mut cleanup_volumes = self.cleanup_volumes(control, group_id, shard_index)?;
        let intent_volume = control
            .get_record("volume-write-intent", &record_id)?
            .map(|bytes| -> Result<Uuid> {
                let intent: VolumeWriteIntent = decode_canonical(&bytes)?;
                validate_receipt(&intent.receipt)?;
                Ok(intent.receipt.volume_id)
            })
            .transpose()?;
        if let Some(volume_id) = intent_volume {
            cleanup_volumes.insert(volume_id);
        }
        let mut complete = receipt_volume
            .into_iter()
            .chain(intent_volume)
            .all(|volume_id| self.volumes.contains_key(&volume_id));
        let mut newer_ready_volumes = BTreeSet::new();
        self.settle_attempt_retirements(control, group_id, shard_index, attempt)?;
        for (volume_id, volume) in &mut self.volumes {
            let required = receipt_volume == Some(*volume_id)
                || intent_volume == Some(*volume_id)
                || cleanup_volumes.contains(volume_id)
                || volume.record.state == StorageVolumeState::Draining;
            let Some(store) = volume.store.as_mut() else {
                if required {
                    complete = false;
                }
                continue;
            };
            if let Some((attempt_id, verification_hash)) = attempt
                && let Some(stored) = store.object_attempt_state(group_id, shard_index)?
            {
                // A repair carries the same verification evidence as its
                // original group, but uses a different operation ID. A
                // successor reusing this group ID carries different evidence.
                let old_object = if stored.ready {
                    stored.verification_hash.as_ref() == Some(verification_hash)
                } else {
                    stored.attempt_id.as_ref() == Some(attempt_id)
                };
                if !old_object {
                    if stored.ready {
                        newer_ready_volumes.insert(*volume_id);
                    }
                    cleanup_volumes.remove(volume_id);
                    continue;
                }
                if let Some(stored_attempt) = stored.attempt_id {
                    let retirement = AttemptRetirement {
                        format_version: 1,
                        volume_id: *volume_id,
                        attempt_id: stored_attempt,
                        group_id: *group_id,
                        shard_index,
                        cleanup_verification_hash: Some(*verification_hash),
                    };
                    let key = attempt_volume_object_id(&stored_attempt, group_id, shard_index);
                    let bytes = canonical_bytes(&retirement)?;
                    // Migration may temporarily hold this attempt on two disks.
                    // Keep one retirement record until every tracked copy is gone.
                    if let Some(existing) = control.get_record("volume-attempt-retirement", &key)? {
                        let existing: AttemptRetirement = decode_canonical(&existing)?;
                        if existing.attempt_id != retirement.attempt_id
                            || existing.group_id != retirement.group_id
                            || existing.shard_index != retirement.shard_index
                            || existing.cleanup_verification_hash.is_some()
                                && retirement.cleanup_verification_hash.is_some()
                                && existing.cleanup_verification_hash
                                    != retirement.cleanup_verification_hash
                        {
                            bail!("attempt retirement conflicts with an earlier cleanup");
                        }
                    } else {
                        control.put_record("volume-attempt-retirement", &key, &bytes)?;
                    }
                }
            } else if attempt.is_none()
                && let Some(stored) = store.object_attempt_state(group_id, shard_index)?
                && let Some(stored_attempt) = stored.attempt_id
            {
                let retirement = AttemptRetirement {
                    format_version: 1,
                    volume_id: *volume_id,
                    attempt_id: stored_attempt,
                    group_id: *group_id,
                    shard_index,
                    cleanup_verification_hash: None,
                };
                let key = attempt_volume_object_id(&stored_attempt, group_id, shard_index);
                let bytes = canonical_bytes(&retirement)?;
                if let Some(existing) = control.get_record("volume-attempt-retirement", &key)? {
                    let existing: AttemptRetirement = decode_canonical(&existing)?;
                    if existing.attempt_id != retirement.attempt_id
                        || existing.group_id != retirement.group_id
                        || existing.shard_index != retirement.shard_index
                    {
                        bail!("attempt retirement conflicts with an earlier cleanup");
                    }
                } else {
                    control.put_record("volume-attempt-retirement", &key, &bytes)?;
                }
            }
            let removed = control.with_catalog_checkpoint_payload_retirement(
                |view| -> Result<Option<bool>> {
                    if view.is_pinned(*group_id, u16::from(shard_index), *root)? {
                        Ok(None)
                    } else {
                        Ok(Some(store.remove_ready(group_id, shard_index, root)?))
                    }
                },
            );
            match removed {
                Ok(None) => {
                    return Ok(false);
                }
                Ok(Some(true)) => {
                    volume_interruption(VolumeInterruption::GarbageObjectRemoved)?;
                    cleanup_volumes.remove(volume_id);
                }
                Ok(Some(false)) => {
                    cleanup_volumes.remove(volume_id);
                }
                Err(error) => {
                    volume.record.state = StorageVolumeState::Failed;
                    volume.record.last_error = Some(truncated_error(&error));
                    cleanup_volumes.insert(*volume_id);
                    complete = false;
                }
            }
        }
        self.persist(control)?;
        self.store_cleanup_volumes(control, &record_id, &cleanup_volumes)?;
        complete &= self.settle_attempt_retirements(control, group_id, shard_index, attempt)?;
        if complete && cleanup_volumes.is_empty() && newer_ready_volumes.is_empty() {
            if let Some(bytes) = control.get_record_bounded(
                "volume-receipt",
                &record_id,
                MAX_VOLUME_RECEIPT_BYTES,
            )? {
                let retired =
                    control.with_catalog_checkpoint_payload_retirement(|view| -> Result<bool> {
                        Ok(view.retire_volume_receipt(
                            *group_id,
                            u16::from(shard_index),
                            *root,
                            &bytes,
                        )?)
                    })?;
                if !retired {
                    return Ok(false);
                }
            }
            control.delete_record("volume-write-intent", &record_id)?;
            volume_interruption(VolumeInterruption::GarbageReceiptRetired)?;
        }
        if complete
            && cleanup_volumes.is_empty()
            && let Some(bytes) = control.get_record(VARIABLE_MIGRATION_KIND, &record_id)?
        {
            let intent: VariableVolumeMigration = decode_canonical(&bytes)?;
            validate_variable_migration(&record_id, &intent)?;
            if intent.cancelled
                && intent.destination.root == *root
                && attempt.is_none_or(|(_, hash)| *hash == intent.verification_hash)
            {
                control.delete_record_if_value(VARIABLE_MIGRATION_KIND, &record_id, &bytes)?;
            }
        }
        // A newer READY copy does not make an old active receipt valid. Keep
        // the holder cleanup obligation until activation publishes that copy's
        // receipt, including after a crash between READY and receipt storage.
        let successor_located = newer_ready_volumes.is_empty()
            || receipt_volume.is_some_and(|id| newer_ready_volumes.contains(&id));
        Ok(complete && cleanup_volumes.is_empty() && successor_located)
    }

    pub(crate) fn store(
        &mut self,
        control: &ControlStore,
        object: &ParityObject,
        acknowledgement: &[u8],
    ) -> Result<VolumeReceipt> {
        self.store_with_headroom(control, object, acknowledgement, true)
    }

    pub(crate) fn stage_attempt(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        object: &VariableParityObject,
        staged_receipt: &[u8],
    ) -> Result<VolumeReceipt> {
        let shard_index = u8::try_from(object.shard_index)
            .context("variable parity shard index exceeds the volume receipt format")?;
        let record_id = attempt_volume_object_id(attempt_id, &object.group_id, shard_index);
        let existing = control
            .get_record("volume-attempt-receipt", &record_id)?
            .or(control.get_record("volume-attempt-intent", &record_id)?)
            .map(|bytes| decode_canonical::<AttemptVolumeRecord>(&bytes))
            .transpose()?;
        let receipt = if let Some(existing) = existing {
            validate_attempt_volume_record(&existing)?;
            if existing.attempt_id != *attempt_id
                || existing.receipt.guild_id != object.guild_id
                || existing.receipt.group_id != object.group_id
                || existing.receipt.shard_index != shard_index
                || existing.receipt.root != object.commitment.root
            {
                bail!("staged parity volume record conflicts with the requested object");
            }
            existing.receipt
        } else {
            let required = object.bytes.len() as u64;
            let required_physical =
                physical_write_reservation(object.bytes.len(), staged_receipt.len());
            let selected = self
                .volumes
                .iter()
                .filter_map(|(id, volume)| {
                    if volume.record.state != StorageVolumeState::Online {
                        return None;
                    }
                    let store = volume.store.as_ref()?;
                    let used = store.used_bytes().ok()?;
                    let writable = volume
                        .record
                        .budget_bytes
                        .saturating_sub(volume.record.headroom_bytes);
                    let available = fs2::available_space(&volume.record.path).ok()?;
                    let physical = required_physical
                        .saturating_add(shared_checkpoint_reservation(control, store).ok()?);
                    (used.saturating_add(required) <= writable
                        && physical <= available.saturating_sub(volume.record.headroom_bytes))
                    .then_some((*id, used))
                })
                .min_by_key(|(id, used)| (*used, *id))
                .map(|(id, _)| id)
                .ok_or(DatabaseError::CapacityExceeded)?;
            let receipt = VolumeReceipt {
                format_version: 2,
                volume_id: selected,
                guild_id: object.guild_id,
                group_id: object.group_id,
                shard_index,
                root: object.commitment.root,
            };
            let intent = AttemptVolumeRecord {
                format_version: 1,
                attempt_id: *attempt_id,
                receipt: receipt.clone(),
            };
            control.put_record(
                "volume-attempt-intent",
                &record_id,
                &canonical_bytes(&intent)?,
            )?;
            receipt
        };
        let volume = self
            .volumes
            .get_mut(&receipt.volume_id)
            .context("staged parity volume is no longer configured")?;
        let store = volume
            .store
            .as_mut()
            .context("staged parity volume is offline")?;
        store.stage_attempt(
            attempt_id,
            object,
            staged_receipt,
            volume.record.budget_bytes,
        )?;
        let durable = AttemptVolumeRecord {
            format_version: 1,
            attempt_id: *attempt_id,
            receipt: receipt.clone(),
        };
        control.put_record(
            "volume-attempt-receipt",
            &record_id,
            &canonical_bytes(&durable)?,
        )?;
        control.delete_record("volume-attempt-intent", &record_id)?;
        Ok(receipt)
    }

    pub(crate) fn reserve_attempt(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        guild_id: [u8; 32],
        shard_index: u16,
        byte_length: u32,
    ) -> Result<u32> {
        let shard = u8::try_from(shard_index)
            .context("variable parity shard index exceeds the volume receipt format")?;
        let record_id = attempt_reservation_id(attempt_id, shard);
        let record =
            if let Some(bytes) = control.get_record("volume-attempt-reservation", &record_id)? {
                let record: AttemptReservationRecord = decode_canonical(&bytes)?;
                validate_attempt_reservation_record(&record)?;
                if record.attempt_id != *attempt_id
                    || record.guild_id != guild_id
                    || record.shard_index != shard
                    || record.byte_length != byte_length
                {
                    bail!("coding reservation conflicts with a prior attempt");
                }
                record
            } else {
                let required = u64::from(byte_length);
                let required_physical = physical_write_reservation(byte_length as usize, 0);
                let selected = self
                    .volumes
                    .iter()
                    .filter_map(|(id, volume)| {
                        if volume.record.state != StorageVolumeState::Online {
                            return None;
                        }
                        let store = volume.store.as_ref()?;
                        let used = store.used_bytes().ok()?;
                        let writable = volume
                            .record
                            .budget_bytes
                            .saturating_sub(volume.record.headroom_bytes);
                        let available = fs2::available_space(&volume.record.path).ok()?;
                        let physical = required_physical
                            .saturating_add(shared_checkpoint_reservation(control, store).ok()?);
                        (used.saturating_add(required) <= writable
                            && physical <= available.saturating_sub(volume.record.headroom_bytes))
                        .then_some((*id, used))
                    })
                    .min_by_key(|(id, used)| (*used, *id))
                    .map(|(id, _)| id)
                    .ok_or(DatabaseError::CapacityExceeded)?;
                let record = AttemptReservationRecord {
                    format_version: 1,
                    attempt_id: *attempt_id,
                    volume_id: selected,
                    guild_id,
                    shard_index: shard,
                    byte_length,
                };
                control.put_record(
                    "volume-attempt-reservation",
                    &record_id,
                    &canonical_bytes(&record)?,
                )?;
                record
            };
        let volume = self
            .volumes
            .get_mut(&record.volume_id)
            .context("reserved coding volume is no longer configured")?;
        let store = volume
            .store
            .as_mut()
            .context("reserved coding volume is offline")?;
        store
            .reserve_coding_attempt(
                attempt_id,
                &guild_id,
                shard_index,
                byte_length,
                volume.record.budget_bytes,
            )
            .map_err(Into::into)
    }

    pub(crate) fn write_attempt_range(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        shard_index: u16,
        offset: u32,
        bytes: &[u8],
    ) -> Result<u32> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let record_id = attempt_reservation_id(attempt_id, shard);
        let record: AttemptReservationRecord = decode_canonical(
            &control
                .get_record("volume-attempt-reservation", &record_id)?
                .context("coding reservation is unavailable")?,
        )?;
        validate_attempt_reservation_record(&record)?;
        self.volumes
            .get_mut(&record.volume_id)
            .and_then(|volume| volume.store.as_mut())
            .context("reserved coding volume is offline")?
            .write_coding_attempt_range(attempt_id, shard_index, offset, bytes)
            .map_err(Into::into)
    }

    pub(crate) fn finish_attempt_upload(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        group_id: [u8; 32],
        shard_index: u16,
        commitment: &MerkleCommitment,
    ) -> Result<VolumeReceipt> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let attempt_object_id = attempt_volume_object_id(attempt_id, &group_id, shard);
        if let Some(bytes) = control.get_record("volume-attempt-receipt", &attempt_object_id)? {
            let existing: AttemptVolumeRecord = decode_canonical(&bytes)?;
            validate_attempt_volume_record(&existing)?;
            if existing.attempt_id != *attempt_id
                || existing.receipt.guild_id == [0; 32]
                || existing.receipt.group_id != group_id
                || existing.receipt.shard_index != shard
                || existing.receipt.root != commitment.root
            {
                bail!("completed coding upload conflicts with its receipt");
            }
            let reservation_id = attempt_reservation_id(attempt_id, shard);
            let reservation_bytes =
                control.get_record("volume-attempt-reservation", &reservation_id)?;
            if let Some(bytes) = &reservation_bytes {
                let reservation: AttemptReservationRecord = decode_canonical(bytes)?;
                validate_attempt_reservation_record(&reservation)?;
                if reservation.attempt_id != *attempt_id
                    || reservation.volume_id != existing.receipt.volume_id
                    || reservation.guild_id != existing.receipt.guild_id
                    || reservation.shard_index != shard
                    || reservation.byte_length != commitment.byte_len
                {
                    bail!("completed coding upload conflicts with its pending reservation");
                }
            }
            // The receipt can precede reservation retirement. Revalidate the
            // physical STAGED/READY bytes before returning it, and finish both
            // database and control cleanup after an interrupted publication.
            self.volumes
                .get_mut(&existing.receipt.volume_id)
                .and_then(|volume| volume.store.as_mut())
                .context("completed coding upload volume is offline")?
                .finish_coding_attempt_upload(attempt_id, &group_id, shard_index, commitment)?;
            if let Some(bytes) = reservation_bytes {
                control.delete_record_if_value(
                    "volume-attempt-reservation",
                    &reservation_id,
                    &bytes,
                )?;
            }
            return Ok(existing.receipt);
        }
        let reservation_id = attempt_reservation_id(attempt_id, shard);
        let record: AttemptReservationRecord = decode_canonical(
            &control
                .get_record("volume-attempt-reservation", &reservation_id)?
                .context("coding reservation is unavailable")?,
        )?;
        validate_attempt_reservation_record(&record)?;
        if record.byte_length != commitment.byte_len {
            bail!("coding upload commitment conflicts with its reservation");
        }
        self.volumes
            .get_mut(&record.volume_id)
            .and_then(|volume| volume.store.as_mut())
            .context("reserved coding volume is offline")?
            .finish_coding_attempt_upload(attempt_id, &group_id, shard_index, commitment)?;
        let receipt = VolumeReceipt {
            format_version: 2,
            volume_id: record.volume_id,
            guild_id: record.guild_id,
            group_id,
            shard_index: shard,
            root: commitment.root,
        };
        let durable = AttemptVolumeRecord {
            format_version: 1,
            attempt_id: *attempt_id,
            receipt: receipt.clone(),
        };
        control.put_record(
            "volume-attempt-receipt",
            &attempt_object_id,
            &canonical_bytes(&durable)?,
        )?;
        volume_interruption(VolumeInterruption::CodingUploadReceiptStored)?;
        control.delete_record("volume-attempt-reservation", &reservation_id)?;
        Ok(receipt)
    }

    pub(crate) fn attach_attempt_receipt(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        group_id: &[u8; 32],
        shard_index: u16,
        receipt: &[u8],
    ) -> Result<()> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let record_id = attempt_volume_object_id(attempt_id, group_id, shard);
        let record: AttemptVolumeRecord = decode_canonical(
            &control
                .get_record("volume-attempt-receipt", &record_id)?
                .context("staged parity volume receipt is unavailable")?,
        )?;
        validate_attempt_volume_record(&record)?;
        self.volumes
            .get_mut(&record.receipt.volume_id)
            .and_then(|volume| volume.store.as_mut())
            .context("staged parity volume is offline")?
            .attach_coding_attempt_receipt(attempt_id, group_id, shard_index, receipt)?;
        Ok(())
    }

    pub(crate) fn open_attempt_range(
        &self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        group_id: &[u8; 32],
        shard_index: u16,
        start_leaf: u32,
        leaf_count: u32,
    ) -> Result<MerkleRangeProof> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let record_id = attempt_volume_object_id(attempt_id, group_id, shard);
        let bytes = control
            .get_record("volume-attempt-receipt", &record_id)?
            .or(control.get_record("volume-attempt-intent", &record_id)?)
            .context("staged parity volume receipt is unavailable")?;
        let record: AttemptVolumeRecord = decode_canonical(&bytes)?;
        validate_attempt_volume_record(&record)?;
        let store = self
            .volumes
            .get(&record.receipt.volume_id)
            .and_then(|volume| volume.store.as_ref())
            .context("staged parity volume is offline")?;
        store
            .open_attempt_range(attempt_id, group_id, shard_index, start_leaf, leaf_count)
            .map_err(Into::into)
    }

    pub(crate) fn has_staged_attempt_object(
        &self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<bool> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let record_id = attempt_volume_object_id(attempt_id, group_id, shard);
        Ok(control
            .get_record("volume-attempt-receipt", &record_id)?
            .is_some()
            || control
                .get_record("volume-attempt-intent", &record_id)?
                .is_some())
    }

    pub(crate) fn activate_attempt_object(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        group_id: &[u8; 32],
        shard_index: u16,
        commitment: &MerkleCommitment,
        verification_hash: &[u8; 32],
    ) -> Result<VolumeReceipt> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let record_id = attempt_volume_object_id(attempt_id, group_id, shard);
        let bytes = control
            .get_record("volume-attempt-receipt", &record_id)?
            .or(control.get_record("volume-attempt-intent", &record_id)?)
            .context("staged parity volume receipt is unavailable")?;
        let record: AttemptVolumeRecord = decode_canonical(&bytes)?;
        validate_attempt_volume_record(&record)?;
        if record.attempt_id != *attempt_id
            || record.receipt.group_id != *group_id
            || record.receipt.shard_index != shard
            || record.receipt.root != commitment.root
        {
            bail!("staged parity activation conflicts with its volume receipt");
        }
        let active_id = volume_object_id(group_id, shard);
        let active = control
            .get_record_bounded("volume-receipt", &active_id, MAX_VOLUME_RECEIPT_BYTES)?
            .map(|bytes| decode_canonical::<VolumeReceipt>(&bytes))
            .transpose()?;
        if let Some(existing) = &active
            && existing != &record.receipt
        {
            validate_receipt(existing)?;
            if existing.guild_id != record.receipt.guild_id
                || existing.group_id != record.receipt.group_id
                || existing.shard_index != record.receipt.shard_index
                || existing.root != record.receipt.root
            {
                bail!("active parity volume receipt conflicts with attempt activation");
            }
        }
        let store = self
            .volumes
            .get_mut(&record.receipt.volume_id)
            .and_then(|volume| volume.store.as_mut())
            .context("staged parity volume is offline")?;
        store.activate_attempt_object(
            attempt_id,
            group_id,
            shard_index,
            commitment,
            verification_hash,
        )?;
        if let Some(existing) = &active
            && existing != &record.receipt
        {
            // The old volume remains a cleanup obligation after the active
            // receipt moves, even when that volume is currently offline.
            self.add_cleanup_volume(control, group_id, shard, existing.volume_id)?;
        }
        volume_interruption(VolumeInterruption::AttemptObjectActivated)?;
        if active.as_ref() != Some(&record.receipt) {
            control.put_record(
                "volume-receipt",
                &active_id,
                &canonical_bytes(&record.receipt)?,
            )?;
        }
        // Keep the attempt receipt until the coding-group event is durable.
        // It is the rollback handle if authority changes after this object
        // becomes READY but before the group enters retained guild history.
        Ok(record.receipt)
    }

    pub(crate) fn finalize_attempt(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
    ) -> Result<()> {
        for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
            for (record_id, bytes) in control.records(kind)? {
                let record: AttemptVolumeRecord = decode_canonical(&bytes)?;
                validate_attempt_volume_record(&record)?;
                if record.attempt_id == *attempt_id {
                    control.delete_record(kind, &record_id)?;
                }
            }
        }
        Ok(())
    }

    fn finalize_attempt_object(
        &self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<()> {
        let record_id = attempt_volume_object_id(attempt_id, group_id, shard_index);
        for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
            if let Some(bytes) = control.get_record(kind, &record_id)? {
                let record: AttemptVolumeRecord = decode_canonical(&bytes)?;
                validate_attempt_volume_record(&record)?;
                if record.attempt_id != *attempt_id
                    || record.receipt.group_id != *group_id
                    || record.receipt.shard_index != shard_index
                {
                    bail!("attempt receipt conflicts with object cleanup");
                }
                control.delete_record(kind, &record_id)?;
            }
        }
        Ok(())
    }

    fn settle_attempt_retirements(
        &self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u8,
        cleanup_attempt: Option<(&[u8; 16], &[u8; 32])>,
    ) -> Result<bool> {
        let mut complete = true;
        for (key, bytes) in control.records("volume-attempt-retirement")? {
            let retirement: AttemptRetirement = decode_canonical(&bytes)?;
            if retirement.format_version != 1
                || retirement.volume_id.is_nil()
                || retirement.attempt_id == [0; 16]
                || key
                    != attempt_volume_object_id(
                        &retirement.attempt_id,
                        &retirement.group_id,
                        retirement.shard_index,
                    )
            {
                bail!("durable attempt retirement is invalid");
            }
            if retirement.group_id != *group_id
                || retirement.shard_index != shard_index
                || cleanup_attempt.is_some_and(|(_, hash)| {
                    retirement
                        .cleanup_verification_hash
                        .is_some_and(|stored| stored != *hash)
                })
            {
                continue;
            }
            let Some(store) = self
                .volumes
                .get(&retirement.volume_id)
                .and_then(|volume| volume.store.as_ref())
            else {
                complete = false;
                continue;
            };
            if store
                .object_attempt_state(group_id, shard_index)?
                .is_some_and(|state| state.attempt_id == Some(retirement.attempt_id))
            {
                complete = false;
                continue;
            }
            let object_id = volume_object_id(group_id, shard_index);
            let migration = control
                .get_record(VARIABLE_MIGRATION_KIND, &object_id)?
                .map(|bytes| -> Result<VariableVolumeMigration> {
                    let intent = decode_canonical(&bytes)?;
                    validate_variable_migration(&object_id, &intent)?;
                    Ok(intent)
                })
                .transpose()?;
            let mut copies_remain = false;
            for (id, volume) in &self.volumes {
                match volume.store.as_ref() {
                    Some(store) => {
                        if store
                            .object_attempt_state(group_id, shard_index)?
                            .is_some_and(|state| state.attempt_id == Some(retirement.attempt_id))
                        {
                            copies_remain = true;
                        }
                    }
                    None if migration.as_ref().is_some_and(|intent| {
                        (*id == intent.source_volume_id
                            && intent.attempt_id == retirement.attempt_id)
                            || (*id == intent.destination.volume_id
                                && intent.destination_attempt_id == retirement.attempt_id)
                    }) =>
                    {
                        copies_remain = true
                    }
                    None => {}
                }
            }
            if copies_remain {
                complete = false;
                continue;
            }
            self.finalize_attempt_object(control, &retirement.attempt_id, group_id, shard_index)?;
            control.delete_record("volume-attempt-retirement", &key)?;
        }
        Ok(complete)
    }

    pub(crate) fn discard_attempt(
        &mut self,
        control: &ControlStore,
        attempt_id: &[u8; 16],
        preserve_ready: &BTreeSet<([u8; 32], u16)>,
    ) -> Result<bool> {
        let mut required_volumes = BTreeSet::new();
        let mut cancelled_migrations = Vec::new();
        for (id, bytes) in control.records(VARIABLE_MIGRATION_KIND)? {
            let mut intent: VariableVolumeMigration = decode_canonical(&bytes)?;
            validate_variable_migration(&id, &intent)?;
            if intent.attempt_id != *attempt_id
                || preserve_ready.contains(&(
                    intent.destination.group_id,
                    u16::from(intent.destination.shard_index),
                ))
            {
                continue;
            }
            if control.catalog_checkpoint_payload_is_pinned(
                intent.destination.group_id,
                u16::from(intent.destination.shard_index),
                intent.destination.root,
            )? {
                continue;
            }
            intent.cancelled = true;
            control.put_record(VARIABLE_MIGRATION_KIND, &id, &canonical_bytes(&intent)?)?;
            required_volumes.insert(intent.source_volume_id);
            required_volumes.insert(intent.destination.volume_id);
            cancelled_migrations.push((id, intent));
        }
        let mut attempt_records = Vec::new();
        for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
            for (record_id, bytes) in control.records(kind)? {
                let record: AttemptVolumeRecord = decode_canonical(&bytes)?;
                validate_attempt_volume_record(&record)?;
                if record.attempt_id == *attempt_id {
                    required_volumes.insert(record.receipt.volume_id);
                    attempt_records.push((kind, record_id, record));
                }
            }
        }
        let mut reservations = Vec::new();
        for (record_id, bytes) in control.records("volume-attempt-reservation")? {
            let record: AttemptReservationRecord = decode_canonical(&bytes)?;
            validate_attempt_reservation_record(&record)?;
            if record.attempt_id == *attempt_id {
                required_volumes.insert(record.volume_id);
                reservations.push((record_id, record));
            }
        }
        let mut complete = true;
        for (volume_id, volume) in &mut self.volumes {
            let Some(store) = volume.store.as_mut() else {
                if required_volumes.contains(volume_id) {
                    complete = false;
                }
                continue;
            };
            control.with_catalog_checkpoint_payload_retirement(|view| -> Result<()> {
                store.discard_uncommitted_attempt_checked(
                    attempt_id,
                    preserve_ready,
                    |storage, shard, root| {
                        view.is_pinned(storage, shard, root)
                            .map_err(|_| DatabaseError::Integrity)
                    },
                )?;
                Ok(())
            })?;
        }
        for (kind, record_id, record) in attempt_records {
            if self
                .volumes
                .get(&record.receipt.volume_id)
                .and_then(|volume| volume.store.as_ref())
                .is_none()
            {
                continue;
            }
            let receipt = record.receipt;
            let active_id = volume_object_id(&receipt.group_id, receipt.shard_index);
            let retained_information = preserve_ready
                .contains(&(receipt.group_id, u16::from(receipt.shard_index)))
                && self
                    .volumes
                    .get(&receipt.volume_id)
                    .and_then(|volume| volume.store.as_ref())
                    .is_some_and(|store| {
                        store
                            .load_ready_variable(&receipt.group_id, u16::from(receipt.shard_index))
                            .is_ok()
                    });
            if !retained_information
                && let Some(bytes) = control.get_record_bounded(
                    "volume-receipt",
                    &active_id,
                    MAX_VOLUME_RECEIPT_BYTES,
                )?
            {
                let active: VolumeReceipt = decode_canonical(&bytes)?;
                if active != receipt {
                    bail!("active volume receipt conflicts with aborted coding attempt");
                }
                control.with_catalog_checkpoint_payload_retirement(|view| -> Result<()> {
                    view.retire_volume_receipt(
                        receipt.group_id,
                        u16::from(receipt.shard_index),
                        receipt.root,
                        &bytes,
                    )?;
                    Ok(())
                })?;
            }
            control.delete_record(kind, &record_id)?;
        }
        for (record_id, record) in reservations {
            if self
                .volumes
                .get(&record.volume_id)
                .and_then(|volume| volume.store.as_ref())
                .is_some()
            {
                control.delete_record("volume-attempt-reservation", &record_id)?;
            }
        }
        if complete {
            for (id, intent) in cancelled_migrations {
                control.delete_record_if_value(
                    VARIABLE_MIGRATION_KIND,
                    &id,
                    &canonical_bytes(&intent)?,
                )?;
                self.remove_cleanup_volume(control, &id, intent.source_volume_id)?;
                self.remove_cleanup_volume(control, &id, intent.destination.volume_id)?;
            }
        }
        Ok(complete)
    }

    pub(crate) fn load_ready_variable(
        &self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u16,
    ) -> Result<VariableParityObject> {
        let shard = u8::try_from(shard_index).context("variable parity shard index is invalid")?;
        let receipt = self
            .receipt(control, group_id, shard)?
            .context("variable parity volume receipt is unavailable")?;
        if receipt.format_version != 2 {
            bail!("parity volume receipt is not a variable-profile object");
        }
        self.volumes
            .get(&receipt.volume_id)
            .and_then(|volume| volume.store.as_ref())
            .context("variable parity volume is offline")?
            .load_ready_variable(group_id, shard_index)
            .map_err(Into::into)
    }

    pub(crate) fn store_repair(
        &mut self,
        control: &ControlStore,
        object: &ParityObject,
    ) -> Result<VolumeReceipt> {
        if let Some(receipt) = self.receipt(control, &object.group_id, object.shard_index)? {
            let reusable = self.volumes.get(&receipt.volume_id).is_some_and(|volume| {
                volume.store.is_some()
                    && matches!(
                        volume.record.state,
                        StorageVolumeState::Online | StorageVolumeState::Draining
                    )
            });
            if !reusable {
                self.add_cleanup_volume(
                    control,
                    &object.group_id,
                    object.shard_index,
                    receipt.volume_id,
                )?;
                control.delete_record(
                    "volume-receipt",
                    &volume_object_id(&object.group_id, object.shard_index),
                )?;
            }
        }
        self.store_with_headroom(control, object, &[], false)
    }

    pub(crate) fn prepare_variable_repair(
        &mut self,
        control: &ControlStore,
        object: &VariableParityObject,
    ) -> Result<bool> {
        let shard_index = u8::try_from(object.shard_index)
            .context("variable repair shard index exceeds the volume receipt format")?;
        let Some(receipt) = self.receipt(control, &object.group_id, shard_index)? else {
            return Ok(false);
        };
        if receipt.format_version != 2
            || receipt.guild_id != object.guild_id
            || receipt.root != object.commitment.root
        {
            bail!("variable repair volume receipt conflicts with the requested object");
        }
        let mut reusable = false;
        let mut failed = false;
        let mut cleanup = true;
        if let Some(volume) = self.volumes.get_mut(&receipt.volume_id)
            && let Some(store) = volume.store.as_mut()
        {
            match store.load_ready_variable(&object.group_id, object.shard_index) {
                Ok(existing) if existing == *object => reusable = true,
                Ok(_) => failed = true,
                Err(DatabaseError::NotReady) => cleanup = false,
                Err(_) => failed = true,
            }
            if failed {
                volume.record.state = StorageVolumeState::Failed;
                volume.record.last_error =
                    Some("variable repair found a corrupt committed object".to_owned());
            }
        }
        if reusable {
            return Ok(true);
        }
        if cleanup {
            self.add_cleanup_volume(control, &object.group_id, shard_index, receipt.volume_id)?;
        }
        // Keep a custodied source locator until repair activation publishes a
        // verified destination. Staging on another volume does not need to
        // erase that original location evidence first.
        let bytes = canonical_bytes(&receipt)?;
        control.with_catalog_checkpoint_payload_retirement(|view| -> Result<()> {
            view.retire_volume_receipt(
                object.group_id,
                u16::from(shard_index),
                receipt.root,
                &bytes,
            )?;
            Ok(())
        })?;
        if failed {
            self.persist(control)?;
        }
        Ok(false)
    }

    fn store_with_headroom(
        &mut self,
        control: &ControlStore,
        object: &ParityObject,
        acknowledgement: &[u8],
        reserve_headroom: bool,
    ) -> Result<VolumeReceipt> {
        if let Some(receipt) = self.receipt(control, &object.group_id, object.shard_index)? {
            if receipt.guild_id != object.guild_id || receipt.root != object.root {
                bail!("parity volume receipt conflicts with the requested object");
            }
            let volume = self
                .volumes
                .get_mut(&receipt.volume_id)
                .context("parity receipt names an unknown volume")?;
            let store = volume
                .store
                .as_mut()
                .context("parity receipt volume is offline")?;
            if store.publication_is_complete(object, acknowledgement)? {
                return Ok(receipt);
            }
            let reserved = if reserve_headroom {
                volume.record.headroom_bytes
            } else {
                0
            };
            let required_physical =
                physical_write_reservation(object.bytes.len(), acknowledgement.len())
                    .saturating_add(shared_checkpoint_reservation(control, store)?);
            let available = fs2::available_space(&volume.record.path)?;
            if required_physical > available.saturating_sub(reserved) {
                return Err(DatabaseError::CapacityExceeded.into());
            }
            store.stage_and_publish_ack(object, acknowledgement, volume.record.budget_bytes)?;
            return Ok(receipt);
        }

        let required = object.bytes.len() as u64;
        let required_physical =
            physical_write_reservation(object.bytes.len(), acknowledgement.len());
        let selected = self
            .volumes
            .iter()
            .filter_map(|(id, volume)| {
                if volume.record.state != StorageVolumeState::Online {
                    return None;
                }
                let store = volume.store.as_ref()?;
                let used = store.used_bytes().ok()?;
                let reserved = if reserve_headroom {
                    volume.record.headroom_bytes
                } else {
                    0
                };
                let writable = volume.record.budget_bytes.saturating_sub(reserved);
                let available = fs2::available_space(&volume.record.path).ok()?;
                let required_physical = required_physical
                    .saturating_add(shared_checkpoint_reservation(control, store).ok()?);
                (used.saturating_add(required) <= writable
                    && required_physical <= available.saturating_sub(reserved))
                .then_some((*id, used))
            })
            .min_by_key(|(id, used)| (*used, *id))
            .map(|(id, _)| id)
            .ok_or(DatabaseError::CapacityExceeded)?;
        let receipt = VolumeReceipt {
            format_version: 1,
            volume_id: selected,
            guild_id: object.guild_id,
            group_id: object.group_id,
            shard_index: object.shard_index,
            root: object.root,
        };
        let record_id = volume_object_id(&object.group_id, object.shard_index);
        if let Some(bytes) = control.get_record("volume-write-intent", &record_id)? {
            let previous: VolumeWriteIntent = decode_canonical(&bytes)?;
            validate_receipt(&previous.receipt)?;
            if previous.receipt.volume_id != selected {
                self.add_cleanup_volume(
                    control,
                    &object.group_id,
                    object.shard_index,
                    previous.receipt.volume_id,
                )?;
            }
        }
        control.put_record(
            "volume-write-intent",
            &record_id,
            &canonical_bytes(&VolumeWriteIntent {
                format_version: 1,
                receipt: receipt.clone(),
            })?,
        )?;
        volume_interruption(VolumeInterruption::WriteIntentStored)?;
        let volume = self
            .volumes
            .get_mut(&selected)
            .expect("selected volume exists");
        volume
            .store
            .as_mut()
            .expect("selected volume is online")
            .stage_and_publish_ack(object, acknowledgement, volume.record.budget_bytes)?;
        volume_interruption(VolumeInterruption::ObjectPublished)?;
        control.put_record("volume-receipt", &record_id, &canonical_bytes(&receipt)?)?;
        volume_interruption(VolumeInterruption::ReceiptStored)?;
        control.delete_record("volume-write-intent", &record_id)?;
        volume_interruption(VolumeInterruption::WriteIntentRetired)?;
        Ok(receipt)
    }

    pub(crate) fn reconcile(&mut self, control: &ControlStore) -> Result<()> {
        for (record_id, bytes) in control.records(VARIABLE_MIGRATION_KIND)? {
            let intent: VariableVolumeMigration = decode_canonical(&bytes)?;
            validate_variable_migration(&record_id, &intent)?;
            if intent.cancelled {
                continue;
            }
            let result = self.resume_variable_migration(control, &record_id, &intent);
            if let Some(source) = self.volumes.get_mut(&intent.source_volume_id) {
                source.record.last_error = match result {
                    Ok(true) => None,
                    Ok(false) => {
                        Some("variable migration is waiting for an unavailable volume".to_owned())
                    }
                    Err(error) => Some(truncated_error(&error)),
                };
            }
        }
        for (record_id, bytes) in control.records("volume-write-intent")? {
            let intent: VolumeWriteIntent = decode_canonical(&bytes)?;
            validate_receipt(&intent.receipt)?;
            validate_volume_object_record_id(&record_id, &intent.receipt)?;
            let Some(volume) = self.volumes.get_mut(&intent.receipt.volume_id) else {
                continue;
            };
            let Some(store) = &volume.store else {
                continue;
            };
            let object =
                match store.load_ready(&intent.receipt.group_id, intent.receipt.shard_index) {
                    Ok(object) => object,
                    Err(DatabaseError::NotReady) => continue,
                    Err(error) => {
                        volume.record.state = StorageVolumeState::Failed;
                        volume.record.last_error = Some(truncated_error(&error));
                        continue;
                    }
                };
            if object.guild_id != intent.receipt.guild_id || object.root != intent.receipt.root {
                volume.record.state = StorageVolumeState::Failed;
                volume.record.last_error =
                    Some("completed parity write conflicts with its durable intent".to_owned());
                continue;
            }
            control.put_record(
                "volume-receipt",
                &record_id,
                &canonical_bytes(&intent.receipt)?,
            )?;
            control.delete_record("volume-write-intent", &record_id)?;
        }
        let retired = self
            .volumes
            .iter()
            .filter(|(_, volume)| volume.record.state == StorageVolumeState::Retired)
            .map(|(volume_id, _)| *volume_id)
            .collect::<Vec<_>>();
        for volume_id in retired {
            self.settle_empty_volume_location_evidence(control, volume_id)?;
        }
        self.persist(control)
    }

    pub(crate) fn scrub(&mut self, control: &ControlStore) -> Result<Vec<StorageScrubReport>> {
        let mut reports = Vec::new();
        for volume in self.volumes.values_mut() {
            let Some(store) = &volume.store else {
                continue;
            };
            match store.scrub() {
                Ok(report) => {
                    if !report.corrupt_objects.is_empty() {
                        volume.record.state = StorageVolumeState::Failed;
                        volume.record.last_error = Some(format!(
                            "{} parity object(s) failed integrity verification",
                            report.corrupt_objects.len()
                        ));
                    }
                    reports.push(StorageScrubReport {
                        volume_id: volume.record.volume_id,
                        checked_objects: report.checked_objects as u64,
                        checked_bytes: report.checked_bytes,
                        corrupt_objects: report.corrupt_objects,
                    });
                }
                Err(error) => {
                    volume.record.state = StorageVolumeState::Failed;
                    volume.record.last_error = Some(truncated_error(&error));
                }
            }
        }
        self.persist(control)?;
        Ok(reports)
    }

    pub(crate) fn database_shell_statement(
        &self,
        volume_id: Uuid,
        sql: &str,
        query_only: bool,
    ) -> Result<DatabaseShellResult> {
        let volume = self
            .volumes
            .get(&volume_id)
            .context("unknown parity volume")?;
        let store = volume
            .store
            .as_ref()
            .context("parity volume is not online")?;
        Ok(store.database_shell_statement(sql, query_only)?)
    }

    pub(crate) fn mark_draining(&mut self, control: &ControlStore, volume_id: Uuid) -> Result<()> {
        let volume = self
            .volumes
            .get_mut(&volume_id)
            .context("unknown parity volume")?;
        if volume.store.is_none() {
            bail!("cannot drain an offline parity volume");
        }
        volume.record.state = StorageVolumeState::Draining;
        self.persist(control)
    }

    #[cfg(test)]
    pub(crate) fn migrate_draining(&mut self, control: &ControlStore) -> Result<u64> {
        self.migrate_draining_with_information_upgrade(control, |_| {
            bail!("legacy information upgrade requires authenticated original authority")
        })
    }

    pub(crate) fn migrate_draining_with_information_upgrade(
        &mut self,
        control: &ControlStore,
        mut check: impl FnMut(&ReadyVariableObject) -> Result<()>,
    ) -> Result<u64> {
        let draining = self
            .volumes
            .iter()
            .filter(|(_, volume)| volume.record.state == StorageVolumeState::Draining)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let mut moved = 0_u64;
        for source_id in draining {
            loop {
                let object = self
                    .volumes
                    .get(&source_id)
                    .and_then(|volume| volume.store.as_ref())
                    .context("draining volume became unavailable")?
                    .first_ready_object()?;
                let Some(object) = object else {
                    break;
                };
                let acknowledgement = self
                    .volumes
                    .get(&source_id)
                    .and_then(|volume| volume.store.as_ref())
                    .expect("source checked above")
                    .load_stored_acknowledgement(&object.group_id, object.shard_index)?;
                let record_id = volume_object_id(&object.group_id, object.shard_index);
                self.add_cleanup_volume(control, &object.group_id, object.shard_index, source_id)?;
                // Remove the source receipt before selecting a destination, while
                // retaining a write intent that makes an interruption recoverable.
                let existing_destination = self
                    .receipt(control, &object.group_id, object.shard_index)?
                    .filter(|receipt| receipt.volume_id != source_id);
                if existing_destination.is_none() {
                    control.delete_record("volume-receipt", &record_id)?;
                    volume_interruption(VolumeInterruption::MigrationSourceReceiptRetired)?;
                }
                let destination = match existing_destination {
                    Some(receipt) => {
                        let stored = self
                            .volumes
                            .get(&receipt.volume_id)
                            .and_then(|volume| volume.store.as_ref())
                            .context("migration destination is unavailable")?
                            .load_ready(&object.group_id, object.shard_index)?;
                        if stored != object {
                            bail!("migration destination conflicts with its source object");
                        }
                        receipt
                    }
                    None => {
                        match self.store_with_headroom(control, &object, &acknowledgement, false) {
                            Ok(receipt) if receipt.volume_id != source_id => receipt,
                            Ok(_) => bail!("draining migration selected its source volume"),
                            Err(error) => return Err(error),
                        }
                    }
                };
                volume_interruption(VolumeInterruption::MigrationDestinationStored)?;
                self.volumes
                    .get_mut(&source_id)
                    .and_then(|volume| volume.store.as_mut())
                    .expect("draining source is online")
                    .remove_ready(&object.group_id, object.shard_index, &object.root)?;
                volume_interruption(VolumeInterruption::MigrationSourceRemoved)?;
                self.remove_cleanup_volume(control, &record_id, source_id)?;
                control.put_record(
                    "volume-receipt",
                    &record_id,
                    &canonical_bytes(&destination)?,
                )?;
                volume_interruption(VolumeInterruption::MigrationReceiptStored)?;
                moved += 1;
            }
            for (id, bytes) in control.records(VARIABLE_MIGRATION_KIND)? {
                let intent: VariableVolumeMigration = decode_canonical(&bytes)?;
                validate_variable_migration(&id, &intent)?;
                if intent.source_volume_id == source_id {
                    if !self.resume_variable_migration(control, &id, &intent)? {
                        bail!(
                            "variable migration is waiting for an unavailable volume; source remains draining"
                        );
                    }
                    moved += 1;
                }
            }
            loop {
                let store = self
                    .volumes
                    .get_mut(&source_id)
                    .and_then(|volume| volume.store.as_mut())
                    .context("draining volume became unavailable")?;
                let mut upgraded = false;
                let object =
                    control.with_catalog_checkpoint_payload_retirement(|_| -> Result<_> {
                        store.first_ready_variable_object_with_information_upgrade(|ready| {
                            check(ready)?;
                            upgraded = true;
                            Ok(())
                        })
                    })?;
                if upgraded {
                    volume_interruption(VolumeInterruption::VariableInformationEvidenceStored)?;
                }
                let Some(object) = object else {
                    break;
                };
                if !self.migrate_variable_object(control, source_id, &object)? {
                    bail!(
                        "variable migration is waiting for an unavailable volume; source remains draining"
                    );
                }
                moved += 1;
            }
            let remaining = self
                .volumes
                .get(&source_id)
                .and_then(|volume| volume.store.as_ref())
                .expect("draining source is online")
                .variable_object_count()?;
            if remaining != 0 {
                bail!(
                    "draining volume still contains {remaining} variable-profile objects or reservations"
                );
            }
            self.ensure_no_attempt_volume_obligations(control, source_id)?;
            self.settle_empty_volume_location_evidence(control, source_id)?;
            let source = self.volumes.get_mut(&source_id).expect("source exists");
            source.record.configured = false;
            source.record.state = StorageVolumeState::Retired;
            source.record.last_error = Some("drain completed; safe to remove volume".to_owned());
            source.store = None;
            self.persist(control)?;
            volume_interruption(VolumeInterruption::MigrationStateStored)?;
        }
        Ok(moved)
    }

    fn migrate_variable_object(
        &mut self,
        control: &ControlStore,
        source_id: Uuid,
        ready: &ReadyVariableObject,
    ) -> Result<bool> {
        let object = &ready.object;
        let shard = u8::try_from(object.shard_index).context("invalid variable shard index")?;
        let record_id = volume_object_id(&object.group_id, shard);
        let intent = if let Some(bytes) = control.get_record(VARIABLE_MIGRATION_KIND, &record_id)? {
            let intent: VariableVolumeMigration = decode_canonical(&bytes)?;
            validate_variable_migration(&record_id, &intent)?;
            ensure_variable_migration_source(&intent, ready)?;
            if intent.source_volume_id != source_id {
                bail!("variable migration is already owned by another source volume");
            }
            intent
        } else {
            let active = self
                .receipt(control, &object.group_id, shard)?
                .context("variable migration requires an active volume receipt")?;
            if active.format_version != 2
                || active.guild_id != object.guild_id
                || active.root != object.commitment.root
            {
                bail!("variable migration source conflicts with its active receipt");
            }
            let destination = if active.volume_id != source_id {
                active.clone()
            } else {
                let physical =
                    physical_write_reservation(object.bytes.len(), ready.staged_receipt.len());
                let destination_id = self
                    .volumes
                    .iter()
                    .filter_map(|(id, volume)| {
                        if *id == source_id || volume.record.state != StorageVolumeState::Online {
                            return None;
                        }
                        let store = volume.store.as_ref()?;
                        let used = store.used_bytes().ok()?;
                        let writable = volume
                            .record
                            .budget_bytes
                            .saturating_sub(volume.record.headroom_bytes);
                        let available = fs2::available_space(&volume.record.path).ok()?;
                        let physical = physical
                            .saturating_add(shared_checkpoint_reservation(control, store).ok()?);
                        (used.saturating_add(object.bytes.len() as u64) <= writable
                            && physical <= available.saturating_sub(volume.record.headroom_bytes))
                        .then_some((*id, used))
                    })
                    .min_by_key(|(id, used)| (*used, *id))
                    .map(|(id, _)| id)
                    .ok_or(DatabaseError::CapacityExceeded)?;
                VolumeReceipt {
                    volume_id: destination_id,
                    ..active.clone()
                }
            };
            let destination_ready = if destination.volume_id != active.volume_id
                || active.volume_id == source_id
            {
                ready.clone()
            } else {
                let repaired = self
                    .volumes
                    .get(&destination.volume_id)
                    .and_then(|volume| volume.store.as_ref())
                    .context("authoritative variable migration destination is offline")?
                    .load_ready_variable_object(&object.group_id, object.shard_index)?;
                if repaired.object != *object
                    || repaired.verification_hash != ready.verification_hash
                {
                    bail!("authoritative variable migration destination conflicts with its source");
                }
                repaired
            };
            if destination_ready.attempt_id != ready.attempt_id {
                let attempt_key =
                    attempt_volume_object_id(&ready.attempt_id, &object.group_id, shard);
                for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
                    if control.get_record(kind, &attempt_key)?.is_some() {
                        bail!(
                            "finalize the original attempt before evacuating to a repaired destination"
                        );
                    }
                }
            }
            let intent = VariableVolumeMigration {
                format_version: 1,
                source_volume_id: source_id,
                destination,
                attempt_id: ready.attempt_id,
                verification_hash: ready.verification_hash,
                commitment: object.commitment.clone(),
                staged_receipt_hash: *blake3::hash(&ready.staged_receipt).as_bytes(),
                destination_attempt_id: destination_ready.attempt_id,
                destination_receipt_hash: *blake3::hash(&destination_ready.staged_receipt)
                    .as_bytes(),
                cancelled: false,
            };
            validate_variable_migration(&record_id, &intent)?;
            let mut cleanup = self.cleanup_volumes(control, &object.group_id, shard)?;
            cleanup.insert(source_id);
            cleanup.insert(intent.destination.volume_id);
            control.put_records_and_delete(
                &[
                    (
                        VARIABLE_MIGRATION_KIND.to_owned(),
                        record_id.clone(),
                        canonical_bytes(&intent)?,
                    ),
                    (
                        "volume-copy-cleanup".to_owned(),
                        record_id.clone(),
                        canonical_bytes(&cleanup.into_iter().collect::<Vec<_>>())?,
                    ),
                ],
                &[],
            )?;
            volume_interruption(VolumeInterruption::VariableMigrationIntentStored)?;
            intent
        };
        self.resume_variable_migration(control, &record_id, &intent)
    }

    fn resume_variable_migration(
        &mut self,
        control: &ControlStore,
        record_id: &[u8],
        intent: &VariableVolumeMigration,
    ) -> Result<bool> {
        validate_variable_migration(record_id, intent)?;
        if intent.cancelled {
            bail!("cancelled variable migration is awaiting garbage or abort cleanup");
        }
        let destination_id = intent.destination.volume_id;
        let group = &intent.destination.group_id;
        let shard = intent.destination.shard_index;
        let active = self
            .receipt(control, group, shard)?
            .context("variable migration active receipt is unavailable")?;
        if active != intent.destination
            && active
                != (VolumeReceipt {
                    volume_id: intent.source_volume_id,
                    ..intent.destination.clone()
                })
        {
            bail!("variable migration conflicts with changed active ownership");
        }
        let Some(destination) = self
            .volumes
            .get(&destination_id)
            .and_then(|volume| volume.store.as_ref())
        else {
            return Ok(false);
        };
        let ready = match destination.load_ready_variable_object(group, shard.into()) {
            Ok(ready) => {
                ensure_variable_migration_destination(intent, &ready)?;
                ready
            }
            Err(DatabaseError::NotReady) => {
                let Some(source) = self
                    .volumes
                    .get(&intent.source_volume_id)
                    .and_then(|volume| volume.store.as_ref())
                else {
                    return Ok(false);
                };
                let ready = source.load_ready_variable_object(group, shard.into())?;
                ensure_variable_migration_source(intent, &ready)?;
                let volume = self
                    .volumes
                    .get_mut(&destination_id)
                    .expect("destination checked");
                if volume.record.state != StorageVolumeState::Online {
                    bail!("variable migration destination is no longer online");
                }
                let store = volume.store.as_mut().expect("destination checked");
                let physical = physical_write_reservation(
                    ready.object.bytes.len(),
                    ready.staged_receipt.len(),
                )
                .saturating_add(shared_checkpoint_reservation(control, store)?);
                let available = fs2::available_space(&volume.record.path)?;
                if physical > available.saturating_sub(volume.record.headroom_bytes) {
                    bail!("variable migration destination has insufficient physical headroom");
                }
                store.copy_ready_variable_object(
                    &ready,
                    volume
                        .record
                        .budget_bytes
                        .saturating_sub(volume.record.headroom_bytes),
                )?;
                let stored = store.load_ready_variable_object(group, shard.into())?;
                if stored != ready {
                    bail!("variable migration destination verification failed");
                }
                ready
            }
            Err(error) => return Err(error.into()),
        };
        ensure_variable_migration_destination(intent, &ready)?;
        volume_interruption(VolumeInterruption::VariableMigrationDestinationReady)?;
        if let Some(source) = self
            .volumes
            .get(&intent.source_volume_id)
            .and_then(|volume| volume.store.as_ref())
            && let Some(state) = source.object_attempt_state(group, shard)?
            && (!state.ready
                || state.attempt_id != Some(intent.attempt_id)
                || state.verification_hash != Some(intent.verification_hash))
        {
            bail!("variable migration source was replaced by another attempt");
        }
        // Pending coding operations must follow the copy before source cleanup.
        let attempt_key = attempt_volume_object_id(&intent.attempt_id, group, shard);
        let mut publish = vec![(
            "volume-receipt".to_owned(),
            record_id.to_vec(),
            canonical_bytes(&intent.destination)?,
        )];
        for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
            if let Some(bytes) = control.get_record(kind, &attempt_key)? {
                let mut record: AttemptVolumeRecord = decode_canonical(&bytes)?;
                validate_attempt_volume_record(&record)?;
                if record.attempt_id != intent.attempt_id
                    || record.receipt.guild_id != intent.destination.guild_id
                    || record.receipt.group_id != *group
                    || record.receipt.shard_index != shard
                    || record.receipt.root != intent.destination.root
                    || ![intent.source_volume_id, destination_id]
                        .contains(&record.receipt.volume_id)
                {
                    bail!("variable migration conflicts with a pending attempt receipt");
                }
                record.receipt = intent.destination.clone();
                publish.push((
                    kind.to_owned(),
                    attempt_key.clone(),
                    canonical_bytes(&record)?,
                ));
            }
        }
        let reservation_key = attempt_reservation_id(&intent.attempt_id, shard);
        let mut retire = Vec::new();
        if let Some(bytes) = control.get_record("volume-attempt-reservation", &reservation_key)? {
            let reservation: AttemptReservationRecord = decode_canonical(&bytes)?;
            validate_attempt_reservation_record(&reservation)?;
            if reservation.attempt_id != intent.attempt_id
                || reservation.volume_id != intent.source_volume_id
                || reservation.guild_id != intent.destination.guild_id
                || reservation.shard_index != shard
                || reservation.byte_length != intent.commitment.byte_len
            {
                bail!("variable migration conflicts with a pending reservation");
            }
            retire.push(("volume-attempt-reservation".to_owned(), reservation_key));
        }
        if let Some(source) = self
            .volumes
            .get_mut(&intent.source_volume_id)
            .and_then(|volume| volume.store.as_mut())
        {
            if source.object_attempt_state(group, shard)?.is_some() {
                source.finish_coding_attempt_upload(
                    &intent.attempt_id,
                    group,
                    shard.into(),
                    &intent.commitment,
                )?;
            }
        } else if !retire.is_empty() {
            return Ok(false);
        }
        control.put_records_and_delete(&publish, &retire)?;
        volume_interruption(VolumeInterruption::VariableMigrationReceiptStored)?;
        let Some(source) = self
            .volumes
            .get_mut(&intent.source_volume_id)
            .and_then(|volume| volume.store.as_mut())
        else {
            return Ok(false);
        };
        source.remove_ready_variable_object(
            group,
            shard.into(),
            &intent.destination.root,
            &intent.attempt_id,
            &intent.verification_hash,
        )?;
        volume_interruption(VolumeInterruption::VariableMigrationSourceRemoved)?;
        let mut cleanup = self.cleanup_volumes(control, group, shard)?;
        cleanup.remove(&intent.source_volume_id);
        cleanup.remove(&destination_id);
        let replacements = if cleanup.is_empty() {
            Vec::new()
        } else {
            vec![(
                "volume-copy-cleanup".to_owned(),
                record_id.to_vec(),
                canonical_bytes(&cleanup.into_iter().collect::<Vec<_>>())?,
            )]
        };
        let deletes = if replacements.is_empty() {
            vec![("volume-copy-cleanup".to_owned(), record_id.to_vec())]
        } else {
            Vec::new()
        };
        control.put_records_and_retire_and_delete_if_value(
            &replacements,
            &deletes,
            VARIABLE_MIGRATION_KIND,
            record_id,
            &canonical_bytes(intent)?,
        )?;
        volume_interruption(VolumeInterruption::VariableMigrationIntentRetired)?;
        Ok(true)
    }

    fn cancel_variable_migration_for_gc(
        &self,
        control: &ControlStore,
        record_id: &[u8],
        root: &[u8; 32],
        attempt: Option<(&[u8; 16], &[u8; 32])>,
    ) -> Result<()> {
        let Some(bytes) = control.get_record(VARIABLE_MIGRATION_KIND, record_id)? else {
            return Ok(());
        };
        let mut intent: VariableVolumeMigration = decode_canonical(&bytes)?;
        validate_variable_migration(record_id, &intent)?;
        if intent.destination.root != *root
            || attempt.is_some_and(|(_, hash)| *hash != intent.verification_hash)
        {
            return Ok(());
        }
        let mut cleanup = self.cleanup_volumes(
            control,
            &intent.destination.group_id,
            intent.destination.shard_index,
        )?;
        cleanup.insert(intent.source_volume_id);
        cleanup.insert(intent.destination.volume_id);
        intent.cancelled = true;
        control.put_records_and_delete(
            &[
                (
                    "volume-copy-cleanup".to_owned(),
                    record_id.to_vec(),
                    canonical_bytes(&cleanup.into_iter().collect::<Vec<_>>())?,
                ),
                (
                    VARIABLE_MIGRATION_KIND.to_owned(),
                    record_id.to_vec(),
                    canonical_bytes(&intent)?,
                ),
            ],
            &[],
        )?;
        Ok(())
    }

    pub(crate) fn reactivate(&mut self, control: &ControlStore, volume_id: Uuid) -> Result<()> {
        let volume = self
            .volumes
            .get_mut(&volume_id)
            .context("unknown parity volume")?;
        if volume.record.state != StorageVolumeState::Retired {
            bail!("only a completed retired volume can be reactivated");
        }
        require_online_directory(&volume.record.path)?;
        let store = open_volume_store(&volume.record, &volume.database_key, &self.keys)?;
        volume.record.configured = true;
        volume.record.state = StorageVolumeState::Online;
        volume.record.last_error = None;
        volume.store = Some(store);
        self.persist(control)
    }

    fn receipt(
        &self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<Option<VolumeReceipt>> {
        control
            .get_record_bounded(
                "volume-receipt",
                &volume_object_id(group_id, shard_index),
                MAX_VOLUME_RECEIPT_BYTES,
            )?
            .map(|bytes| {
                let receipt: VolumeReceipt = decode_canonical(&bytes)?;
                validate_receipt(&receipt)?;
                validate_volume_object_record_id(
                    &volume_object_id(group_id, shard_index),
                    &receipt,
                )?;
                Ok(receipt)
            })
            .transpose()
    }

    fn cleanup_volumes(
        &self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u8,
    ) -> Result<BTreeSet<Uuid>> {
        let Some(bytes) = control.get_record(
            "volume-copy-cleanup",
            &volume_object_id(group_id, shard_index),
        )?
        else {
            return Ok(BTreeSet::new());
        };
        let volumes: Vec<Uuid> = decode_canonical(&bytes)?;
        let set = volumes.into_iter().collect::<BTreeSet<_>>();
        if set.iter().any(Uuid::is_nil) {
            bail!("volume cleanup obligation has an invalid UUID");
        }
        Ok(set)
    }

    fn add_cleanup_volume(
        &self,
        control: &ControlStore,
        group_id: &[u8; 32],
        shard_index: u8,
        volume_id: Uuid,
    ) -> Result<()> {
        let record_id = volume_object_id(group_id, shard_index);
        let mut volumes = self.cleanup_volumes(control, group_id, shard_index)?;
        volumes.insert(volume_id);
        self.store_cleanup_volumes(control, &record_id, &volumes)
    }

    fn remove_cleanup_volume(
        &self,
        control: &ControlStore,
        record_id: &[u8],
        volume_id: Uuid,
    ) -> Result<()> {
        let group_id: [u8; 32] = record_id
            .get(..32)
            .context("volume object key is truncated")?
            .try_into()?;
        let shard_index = *record_id
            .get(32)
            .context("volume object key is truncated")?;
        let mut volumes = self.cleanup_volumes(control, &group_id, shard_index)?;
        volumes.remove(&volume_id);
        self.store_cleanup_volumes(control, record_id, &volumes)
    }

    fn store_cleanup_volumes(
        &self,
        control: &ControlStore,
        record_id: &[u8],
        volumes: &BTreeSet<Uuid>,
    ) -> Result<()> {
        if volumes.is_empty() {
            control.delete_record("volume-copy-cleanup", record_id)?;
        } else {
            control.put_record(
                "volume-copy-cleanup",
                record_id,
                &canonical_bytes(&volumes.iter().copied().collect::<Vec<_>>())?,
            )?;
        }
        Ok(())
    }

    fn ensure_no_attempt_volume_obligations(
        &self,
        control: &ControlStore,
        volume_id: Uuid,
    ) -> Result<()> {
        for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
            for (_, bytes) in control.records(kind)? {
                let record: AttemptVolumeRecord = decode_canonical(&bytes)?;
                validate_attempt_volume_record(&record)?;
                if record.receipt.volume_id == volume_id {
                    bail!("draining volume still owns a pending coding attempt");
                }
            }
        }
        for (_, bytes) in control.records("volume-attempt-reservation")? {
            let record: AttemptReservationRecord = decode_canonical(&bytes)?;
            validate_attempt_reservation_record(&record)?;
            if record.volume_id == volume_id {
                bail!("draining volume still owns a coding reservation");
            }
        }
        for (_, bytes) in control.records("volume-attempt-retirement")? {
            let record: AttemptRetirement = decode_canonical(&bytes)?;
            if record.volume_id == volume_id {
                bail!("draining volume still owns attempt retirement evidence");
            }
        }
        Ok(())
    }

    fn settle_empty_volume_location_evidence(
        &self,
        control: &ControlStore,
        volume_id: Uuid,
    ) -> Result<()> {
        for (record_id, bytes) in control.records("volume-write-intent")? {
            let intent: VolumeWriteIntent = decode_canonical(&bytes)?;
            validate_receipt(&intent.receipt)?;
            validate_volume_object_record_id(&record_id, &intent.receipt)?;
            if intent.receipt.volume_id == volume_id {
                control.delete_record("volume-write-intent", &record_id)?;
            }
        }
        for (record_id, bytes) in control.records("volume-receipt")? {
            let receipt: VolumeReceipt = decode_canonical(&bytes)?;
            validate_receipt(&receipt)?;
            validate_volume_object_record_id(&record_id, &receipt)?;
            if receipt.volume_id == volume_id {
                let retired =
                    control.with_catalog_checkpoint_payload_retirement(|view| -> Result<bool> {
                        Ok(view.retire_volume_receipt(
                            receipt.group_id,
                            u16::from(receipt.shard_index),
                            receipt.root,
                            &bytes,
                        )?)
                    })?;
                if !retired {
                    bail!("checkpoint custody still requires this volume locator");
                }
            }
        }
        for (record_id, bytes) in control.records("volume-copy-cleanup")? {
            let volumes: Vec<Uuid> = decode_canonical(&bytes)?;
            let mut volumes = volumes.into_iter().collect::<BTreeSet<_>>();
            if volumes.iter().any(Uuid::is_nil) {
                bail!("volume cleanup obligation has an invalid UUID");
            }
            if volumes.remove(&volume_id) {
                self.store_cleanup_volumes(control, &record_id, &volumes)?;
            }
        }
        Ok(())
    }

    fn persist(&self, control: &ControlStore) -> Result<()> {
        let records = self
            .volumes
            .values()
            .map(|volume| volume.record.clone())
            .collect::<Vec<_>>();
        store_volume_records(control, &records)
    }
}

pub(crate) fn reader_coding_capacity(
    control: &ControlStore,
    readers: &[VolumeReaderConfig],
    shard_size: u32,
) -> Result<u64> {
    validate_coding_shard_size(shard_size)?;
    let records = load_volume_records(control)?
        .into_iter()
        .map(|record| (record.volume_id, record))
        .collect::<BTreeMap<_, _>>();
    let mut devices = BTreeMap::new();
    for reader in readers {
        let Some(record) = records.get(&reader.volume_id) else {
            continue;
        };
        if record.state != StorageVolumeState::Online {
            continue;
        }
        let store = match ParityStore::open_existing_with_key(
            &reader.path,
            reader.volume_id.as_bytes(),
            &reader.database_key,
        ) {
            Ok(store) => store,
            Err(_) => continue,
        };
        add_volume_coding_capacity(&mut devices, record, &store, shard_size)?;
    }
    device_coding_capacity(control, &devices, shard_size)
}

/// Read-only inspection uses the existing key without publishing an envelope
/// or migrating a legacy key. Callers can reject retired backends first.
#[cfg(any(not(target_os = "linux"), test))]
pub(crate) fn inspect_control_store(
    data_dir: &Path,
    keys: &KeyMaterial,
) -> Result<Option<ControlStore>> {
    let database_path = data_dir.join("control.db");
    match fs::symlink_metadata(&database_path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let envelope_path = data_dir.join(CONTROL_KEY_FILE);
    if envelope_path.exists() {
        let envelope: WrappedDatabaseKey = read_private_record(&envelope_path)?;
        let database_key = keys
            .unwrap_database_key(b"control.db/v2", &envelope)
            .context("cannot unwrap control database key")?;
        match ControlStore::open_existing_read_only_with_key(&database_path, &database_key) {
            Ok(store) => return Ok(Some(store)),
            Err(error) => {
                return ControlStore::open_existing_read_only_with_key(
                    &database_path,
                    &keys.database_key(b"control.db"),
                )
                .map(Some)
                .with_context(|| format!("control database rejected wrapped key: {error}"));
            }
        }
    }
    ControlStore::open_existing_read_only_with_key(
        &database_path,
        &keys.database_key(b"control.db"),
    )
    .map(Some)
    .map_err(Into::into)
}

#[cfg(target_os = "linux")]
pub(crate) fn with_inspected_control_snapshot<T>(
    data_dir: &Path,
    keys: &KeyMaterial,
    operation: impl FnOnce(&ControlStore) -> Result<T>,
) -> Result<T> {
    let database_keys = preserved_control_keys(data_dir, keys)?;
    ControlStore::with_preserved_read_only_snapshot(
        data_dir.join("control.db"),
        &database_keys,
        operation,
    )
}

#[cfg(target_os = "linux")]
pub(crate) fn open_preserved_control_store(
    data_dir: &Path,
    keys: &KeyMaterial,
) -> Result<(ControlStore, mb_store::PreservedReadGuard)> {
    let database_keys = preserved_control_keys(data_dir, keys)?;
    ControlStore::open_preserved_read_only_with_keys(data_dir.join("control.db"), &database_keys)
}

#[cfg(target_os = "linux")]
fn preserved_control_keys(data_dir: &Path, keys: &KeyMaterial) -> Result<Vec<[u8; 32]>> {
    let mut database_keys = Vec::new();
    let envelope_path = data_dir.join(CONTROL_KEY_FILE);
    if envelope_path.exists() {
        let envelope: WrappedDatabaseKey = read_private_record(&envelope_path)?;
        database_keys.push(
            keys.unwrap_database_key(b"control.db/v2", &envelope)
                .context("cannot unwrap preserved control database key")?,
        );
    }
    database_keys.push(keys.database_key(b"control.db"));
    Ok(database_keys)
}

pub(crate) fn open_control_store(
    data_dir: &Path,
    keys: &KeyMaterial,
) -> Result<(ControlStore, [u8; 32])> {
    let database_path = data_dir.join("control.db");
    let envelope_path = data_dir.join(CONTROL_KEY_FILE);
    let database_id = b"control.db/v2";
    if envelope_path.exists() {
        let envelope: WrappedDatabaseKey = read_private_record(&envelope_path)?;
        let database_key = keys
            .unwrap_database_key(database_id, &envelope)
            .context("cannot unwrap control database key")?;
        match ControlStore::open_with_key(&database_path, &database_key) {
            Ok(store) => return Ok((store, database_key)),
            Err(new_key_error) => {
                let legacy_key = keys.database_key(b"control.db");
                let store = ControlStore::open_with_key(&database_path, &legacy_key).with_context(
                    || format!("control database rejected wrapped key: {new_key_error}"),
                )?;
                store.rekey(&database_key)?;
                return Ok((
                    ControlStore::open_with_key(&database_path, &database_key)?,
                    database_key,
                ));
            }
        }
    }

    let mut database_key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut database_key);
    let envelope = keys.wrap_database_key(database_id, &database_key)?;
    write_new_private_record(&envelope_path, &envelope)?;
    if database_path.exists() {
        let legacy_key = keys.database_key(b"control.db");
        let store = ControlStore::open_with_key(&database_path, &legacy_key)?;
        store.rekey(&database_key)?;
        Ok((
            ControlStore::open_with_key(&database_path, &database_key)?,
            database_key,
        ))
    } else {
        Ok((
            ControlStore::open_with_key(&database_path, &database_key)?,
            database_key,
        ))
    }
}

fn initialize_volume(
    root: &Path,
    database_file: Option<&str>,
    budget_bytes: u64,
    headroom_bytes: u64,
    keys: &KeyMaterial,
) -> Result<VolumeRecord> {
    let root = require_online_directory(root)?;
    let manifest_path = root.join(VOLUME_MANIFEST_FILE);
    if let Some(manifest) = read_volume_manifest(&root, keys)? {
        let record = VolumeRecord {
            format_version: 1,
            volume_id: manifest.volume_id,
            path: root,
            database_file: manifest.database_file,
            wrapped_database_key: manifest.wrapped_database_key,
            state: StorageVolumeState::Online,
            configured: true,
            budget_bytes,
            headroom_bytes,
            last_error: None,
        };
        let database_key = keys.unwrap_database_key(
            &volume_database_id(record.volume_id),
            &record.wrapped_database_key,
        )?;
        if database_file.is_some() && record.volume_id == legacy_default_volume_id(keys) {
            open_volume_store(&record, &database_key, keys)?;
        } else {
            let database_path = record.path.join(&record.database_file);
            ParityStore::open_with_key(&database_path, record.volume_id.as_bytes(), &database_key)?;
        }
        return Ok(record);
    }

    let legacy_path = database_file.map(|name| root.join(name));
    let volume_id = if legacy_path.as_ref().is_some_and(|path| path.exists()) {
        legacy_default_volume_id(keys)
    } else {
        Uuid::new_v4()
    };
    let database_file = database_file
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("parity-{volume_id}.db"));
    let mut database_key = [0_u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut database_key);
    let wrapped_database_key =
        keys.wrap_database_key(&volume_database_id(volume_id), &database_key)?;
    let manifest = VolumeManifest {
        format_version: 1,
        owner: keys.node_id(),
        volume_id,
        database_file: database_file.clone(),
        wrapped_database_key: wrapped_database_key.clone(),
    };
    let signed = SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, keys)?;
    write_new_private_record(&manifest_path, &signed)?;
    let record = VolumeRecord {
        format_version: 1,
        volume_id,
        path: root,
        database_file,
        wrapped_database_key,
        state: StorageVolumeState::Online,
        configured: true,
        budget_bytes,
        headroom_bytes,
        last_error: None,
    };
    let database_path = record.path.join(&record.database_file);
    if database_path.exists() {
        let legacy_key = keys.database_key(&legacy_volume_database_id(volume_id));
        let store =
            ParityStore::open(&database_path, volume_id.as_bytes(), keys).or_else(|_| {
                ParityStore::open_with_key(&database_path, volume_id.as_bytes(), &legacy_key)
            })?;
        store.rekey(&database_key)?;
    } else {
        ParityStore::open_with_key(&database_path, volume_id.as_bytes(), &database_key)?;
    }
    Ok(record)
}

fn read_volume_manifest(root: &Path, keys: &KeyMaterial) -> Result<Option<VolumeManifest>> {
    let manifest_path = root.join(VOLUME_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let signed: SignedRecord<VolumeManifest> = read_private_record(&manifest_path)?;
    signed.verify(VOLUME_MANIFEST_DOMAIN)?;
    validate_manifest(&signed.value, keys.node_id())?;
    if signed.signer != keys.node_id() {
        bail!("parity volume manifest was not signed by its owner");
    }
    Ok(Some(signed.value))
}

fn open_volume_store(
    record: &VolumeRecord,
    database_key: &[u8; 32],
    keys: &KeyMaterial,
) -> Result<ParityStore> {
    let manifest_path = record.path.join(VOLUME_MANIFEST_FILE);
    let signed: SignedRecord<VolumeManifest> = read_private_record(&manifest_path)?;
    signed.verify(VOLUME_MANIFEST_DOMAIN)?;
    validate_manifest(&signed.value, keys.node_id())?;
    if signed.signer != keys.node_id() {
        bail!("parity volume manifest was not signed by its owner");
    }
    if signed.value.volume_id != record.volume_id
        || signed.value.database_file != record.database_file
        || signed.value.wrapped_database_key != record.wrapped_database_key
    {
        bail!("parity volume manifest conflicts with the control registry");
    }
    let database_path = record.path.join(&record.database_file);
    match ParityStore::open_existing_with_key(
        &database_path,
        record.volume_id.as_bytes(),
        database_key,
    ) {
        Ok(store) => Ok(store),
        Err(new_key_error) => {
            let legacy_key = keys.database_key(&legacy_volume_database_id(record.volume_id));
            let store = ParityStore::open_existing_with_key(
                &database_path,
                record.volume_id.as_bytes(),
                &legacy_key,
            )
            .with_context(|| format!("parity database rejected wrapped key: {new_key_error}"))?;
            store.rekey(database_key)?;
            Ok(ParityStore::open_existing_with_key(
                &database_path,
                record.volume_id.as_bytes(),
                database_key,
            )?)
        }
    }
}

fn validate_manifest(manifest: &VolumeManifest, owner: NodeId) -> Result<()> {
    if manifest.format_version != 1
        || manifest.owner != owner
        || manifest.volume_id.is_nil()
        || manifest.database_file.is_empty()
        || manifest.database_file.len() > 128
        || Path::new(&manifest.database_file).components().count() != 1
        || manifest.database_file == VOLUME_MANIFEST_FILE
    {
        bail!("invalid parity volume manifest");
    }
    Ok(())
}

fn validate_volume_record(record: &VolumeRecord) -> Result<()> {
    if record.format_version != 1
        || record.volume_id.is_nil()
        || record.budget_bytes == 0
        || record.headroom_bytes >= record.budget_bytes
        || record.database_file.is_empty()
        || Path::new(&record.database_file).components().count() != 1
    {
        bail!("invalid parity volume registry record");
    }
    Ok(())
}

fn validate_receipt(receipt: &VolumeReceipt) -> Result<()> {
    if !matches!(receipt.format_version, 1 | 2)
        || receipt.volume_id.is_nil()
        || receipt.guild_id == [0; 32]
        || receipt.group_id == [0; 32]
        || match receipt.format_version {
            1 => receipt.shard_index > 4,
            2 => receipt.shard_index >= mb_core::MAX_CODING_SHARDS as u8,
            _ => true,
        }
        || receipt.root == [0; 32]
    {
        bail!("invalid parity volume receipt");
    }
    Ok(())
}

fn validate_attempt_volume_record(record: &AttemptVolumeRecord) -> Result<()> {
    validate_receipt(&record.receipt)?;
    if record.format_version != 1
        || record.attempt_id == [0; 16]
        || record.receipt.format_version != 2
    {
        bail!("invalid staged parity volume record");
    }
    Ok(())
}

fn validate_attempt_reservation_record(record: &AttemptReservationRecord) -> Result<()> {
    if record.format_version != 1
        || record.attempt_id == [0; 16]
        || record.volume_id.is_nil()
        || record.guild_id == [0; 32]
        || record.shard_index >= mb_core::MAX_CODING_SHARDS as u8
        || record.byte_length < mb_core::MIN_PROFILE_SHARD_SIZE
        || record.byte_length > mb_core::MAX_PROFILE_SHARD_SIZE
        || !record.byte_length.is_power_of_two()
    {
        bail!("invalid coding volume reservation");
    }
    Ok(())
}

fn validate_volume_object_record_id(record_id: &[u8], receipt: &VolumeReceipt) -> Result<()> {
    if record_id != volume_object_id(&receipt.group_id, receipt.shard_index) {
        bail!("parity volume receipt conflicts with its record key");
    }
    Ok(())
}

/// Keep paged scratch on the catalog filesystem and protect every configured
/// parity headroom on that device plus current database checkpoint-copy space.
pub(crate) fn paged_scratch_store(
    control: &ControlStore,
    max_database_bytes: u64,
) -> Result<mb_store::RecordScratchStore> {
    #[cfg(target_os = "linux")]
    {
        let directory = control
            .path()
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let device = mb_store::physical_allocation_domain(directory)?;
        let mut limits = mb_store::ScratchStorageLimits::for_database(max_database_bytes)?;
        let mut checkpoints = vec![control.path().to_path_buf()];
        let (records, _) = load_bounded_volume_records(control)?;
        for record in records {
            validate_volume_record(&record)?;
            match fs::metadata(&record.path) {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
            if mb_store::physical_allocation_domain(&record.path)? == device {
                limits.headroom_bytes = limits
                    .headroom_bytes
                    .checked_add(record.headroom_bytes)
                    .and_then(|bytes| bytes.checked_add(PHYSICAL_WRITE_FIXED_RESERVE))
                    .context("scratch headroom overflow")?;
                checkpoints.push(record.path.join(&record.database_file));
            }
        }
        Ok(
            mb_store::RecordScratchStore::new_in_with_checkpoint_reservations(
                directory,
                limits,
                &checkpoints,
            )?,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(mb_store::RecordScratchStore::new(max_database_bytes)?)
    }
}

fn decode_volume_records_with_configured_flag(bytes: &[u8]) -> Result<(Vec<VolumeRecord>, bool)> {
    decode_canonical::<Vec<VolumeRecord>>(bytes)
        .map(|records| (records, true))
        .or_else(|_| {
            decode_canonical::<Vec<VolumeRecordBeforeConfiguredState>>(bytes)
                .map(|records| (records.into_iter().map(Into::into).collect(), false))
        })
        .map_err(Into::into)
}

fn decode_volume_records(bytes: &[u8]) -> Result<Vec<VolumeRecord>> {
    decode_volume_records_with_configured_flag(bytes).map(|(records, _)| records)
}

#[cfg(target_os = "linux")]
fn load_bounded_volume_records(control: &ControlStore) -> Result<(Vec<VolumeRecord>, bool)> {
    let records = control
        .get_record_bounded(
            "node-config",
            b"storage-volumes",
            MAX_BOUNDED_VOLUME_REGISTRY_BYTES,
        )?
        .map(|bytes| decode_volume_records_with_configured_flag(&bytes))
        .transpose()?
        .unwrap_or_else(|| (Vec::new(), true));
    if records.0.len() > MAX_BOUNDED_VOLUME_RECORDS {
        bail!("too many volumes for bounded registry inspection");
    }
    Ok(records)
}

/// A decoded registration without wrapped keys or claims about payload custody.
#[cfg(target_os = "linux")]
pub(crate) struct PreservedVolumeRegistration<'a> {
    pub(crate) record_format: u16,
    pub(crate) volume_id: Uuid,
    pub(crate) path: &'a Path,
    pub(crate) database_file: &'a str,
    pub(crate) state: StorageVolumeState,
    pub(crate) configured: bool,
    pub(crate) configured_recorded: bool,
    pub(crate) budget_bytes: u64,
    pub(crate) headroom_bytes: u64,
}

/// Visit every saved volume without opening its manifest or payload.
/// Retired/unconfigured volumes can still hold retained or interrupted data.
#[cfg(target_os = "linux")]
pub(crate) fn for_each_preserved_volume_registration(
    control: &ControlStore,
    mut visit: impl FnMut(PreservedVolumeRegistration<'_>) -> Result<()>,
) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    let (records, configured_recorded) = load_bounded_volume_records(control)?;
    let mut ids = BTreeSet::new();
    for record in &records {
        validate_volume_record(record)?;
        if !ids.insert(record.volume_id) {
            bail!("duplicate preserved parity volume UUID");
        }
        let mut database_path = Path::new(&record.database_file).components();
        if !record.path.is_absolute()
            || record.path.as_os_str().as_bytes().contains(&0)
            || record.database_file.len() > 128
            || record.database_file.as_bytes().contains(&0)
            || record.database_file == VOLUME_MANIFEST_FILE
            || !matches!(database_path.next(), Some(Component::Normal(_)))
            || database_path.next().is_some()
        {
            bail!(
                "preserved parity volume registry has an unresolved path; preserve the registry and use a separate complete snapshot with verified volume locations"
            );
        }
    }
    for record in records {
        visit(PreservedVolumeRegistration {
            record_format: record.format_version,
            volume_id: record.volume_id,
            path: &record.path,
            database_file: &record.database_file,
            state: record.state,
            configured: record.configured,
            configured_recorded,
            budget_bytes: record.budget_bytes,
            headroom_bytes: record.headroom_bytes,
        })?;
    }
    Ok(())
}

/// Saved volume custody metadata; these records do not verify stored payloads.
#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LegacyVolumeReceipt {
    pub format_version: u16,
    pub volume_id: Uuid,
    pub guild_id: String,
    pub group_id: String,
    pub shard_index: u8,
    pub root: String,
}

#[cfg(target_os = "linux")]
impl From<&VolumeReceipt> for LegacyVolumeReceipt {
    fn from(receipt: &VolumeReceipt) -> Self {
        Self {
            format_version: receipt.format_version,
            volume_id: receipt.volume_id,
            guild_id: hex::encode(receipt.guild_id),
            group_id: hex::encode(receipt.group_id),
            shard_index: receipt.shard_index,
            root: hex::encode(receipt.root),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyVolumeOwnershipEvidence {
    Receipt(LegacyVolumeReceipt),
    WriteIntent {
        format_version: u16,
        receipt: LegacyVolumeReceipt,
    },
    Attempt {
        format_version: u16,
        attempt_id: String,
        receipt: LegacyVolumeReceipt,
    },
    Reservation {
        format_version: u16,
        attempt_id: String,
        volume_id: Uuid,
        guild_id: String,
        shard_index: u8,
        byte_length: u32,
    },
    Retirement {
        format_version: u16,
        volume_id: Uuid,
        attempt_id: String,
        group_id: String,
        shard_index: u8,
        cleanup_verification_hash: Option<String>,
    },
    Migration {
        format_version: u16,
        source_volume_id: Uuid,
        destination: LegacyVolumeReceipt,
        attempt_id: String,
        verification_hash: String,
        commitment: MerkleCommitment,
        staged_receipt_hash: String,
        destination_attempt_id: String,
        destination_receipt_hash: String,
        cancelled: bool,
    },
    CopyCleanup {
        group_id: String,
        shard_index: u8,
        volume_ids: Vec<Uuid>,
    },
}

#[cfg(target_os = "linux")]
impl LegacyVolumeOwnershipEvidence {
    pub(crate) fn for_each_volume(&self, mut visit: impl FnMut(Uuid)) {
        match self {
            Self::Receipt(receipt)
            | Self::WriteIntent { receipt, .. }
            | Self::Attempt { receipt, .. } => visit(receipt.volume_id),
            Self::Reservation { volume_id, .. } | Self::Retirement { volume_id, .. } => {
                visit(*volume_id)
            }
            Self::Migration {
                source_volume_id,
                destination,
                ..
            } => {
                visit(*source_volume_id);
                visit(destination.volume_id);
            }
            Self::CopyCleanup { volume_ids, .. } => {
                for id in volume_ids {
                    visit(*id);
                }
            }
        }
    }
}

/// Decode original records with bounded SQL rows; never open a volume or replay work.
#[cfg(target_os = "linux")]
pub(crate) fn for_each_preserved_volume_ownership(
    control: &ControlStore,
    mut visit: impl FnMut(&str, &[u8], &[u8], LegacyVolumeOwnershipEvidence) -> Result<()>,
) -> Result<()> {
    fn decode<T: serde::de::DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
        let record = decode_canonical(bytes)?;
        if mb_core::canonical_bytes_bounded(&record, bytes.len())? != bytes {
            bail!("preserved volume ownership record is not canonical");
        }
        Ok(record)
    }
    for kind in [
        "volume-receipt",
        "volume-write-intent",
        "volume-attempt-intent",
        "volume-attempt-receipt",
        "volume-attempt-reservation",
        "volume-attempt-retirement",
        VARIABLE_MIGRATION_KIND,
        "volume-copy-cleanup",
    ] {
        // Cleanup obligations are historical UUID lists; keep the existing local
        // row budget. All other original record layouts fit the receipt bound.
        let limit = if kind == "volume-copy-cleanup" {
            mb_core::V1_MAX_CATALOG_BYTES
        } else {
            MAX_VOLUME_RECEIPT_BYTES
        };
        control.for_each_record_bounded(kind, 49, limit, |key, bytes| {
            let evidence = match kind {
                "volume-receipt" => {
                    let record: VolumeReceipt = decode(bytes)?;
                    validate_receipt(&record)?;
                    validate_volume_object_record_id(key, &record)?;
                    LegacyVolumeOwnershipEvidence::Receipt((&record).into())
                }
                "volume-write-intent" => {
                    let record: VolumeWriteIntent = decode(bytes)?;
                    validate_receipt(&record.receipt)?;
                    validate_volume_object_record_id(key, &record.receipt)?;
                    if record.format_version != 1 {
                        bail!("invalid preserved volume write intent");
                    }
                    LegacyVolumeOwnershipEvidence::WriteIntent {
                        format_version: record.format_version,
                        receipt: (&record.receipt).into(),
                    }
                }
                "volume-attempt-intent" | "volume-attempt-receipt" => {
                    let record: AttemptVolumeRecord = decode(bytes)?;
                    validate_attempt_volume_record(&record)?;
                    if key
                        != attempt_volume_object_id(
                            &record.attempt_id,
                            &record.receipt.group_id,
                            record.receipt.shard_index,
                        )
                    {
                        bail!("preserved volume attempt conflicts with its record key");
                    }
                    LegacyVolumeOwnershipEvidence::Attempt {
                        format_version: record.format_version,
                        attempt_id: hex::encode(record.attempt_id),
                        receipt: (&record.receipt).into(),
                    }
                }
                "volume-attempt-reservation" => {
                    let record: AttemptReservationRecord = decode(bytes)?;
                    validate_attempt_reservation_record(&record)?;
                    if key != attempt_reservation_id(&record.attempt_id, record.shard_index) {
                        bail!("preserved volume reservation conflicts with its record key");
                    }
                    LegacyVolumeOwnershipEvidence::Reservation {
                        format_version: record.format_version,
                        attempt_id: hex::encode(record.attempt_id),
                        volume_id: record.volume_id,
                        guild_id: hex::encode(record.guild_id),
                        shard_index: record.shard_index,
                        byte_length: record.byte_length,
                    }
                }
                "volume-attempt-retirement" => {
                    let record: AttemptRetirement = decode(bytes)?;
                    if record.format_version != 1
                        || record.volume_id.is_nil()
                        || record.attempt_id == [0; 16]
                        || record.group_id == [0; 32]
                        || record.shard_index >= mb_core::MAX_CODING_SHARDS as u8
                        || key
                            != attempt_volume_object_id(
                                &record.attempt_id,
                                &record.group_id,
                                record.shard_index,
                            )
                        || record.cleanup_verification_hash == Some([0; 32])
                    {
                        bail!("invalid preserved volume attempt retirement");
                    }
                    LegacyVolumeOwnershipEvidence::Retirement {
                        format_version: record.format_version,
                        volume_id: record.volume_id,
                        attempt_id: hex::encode(record.attempt_id),
                        group_id: hex::encode(record.group_id),
                        shard_index: record.shard_index,
                        cleanup_verification_hash: record
                            .cleanup_verification_hash
                            .map(hex::encode),
                    }
                }
                VARIABLE_MIGRATION_KIND => {
                    let record: VariableVolumeMigration = decode(bytes)?;
                    validate_variable_migration(key, &record)?;
                    LegacyVolumeOwnershipEvidence::Migration {
                        format_version: record.format_version,
                        source_volume_id: record.source_volume_id,
                        destination: (&record.destination).into(),
                        attempt_id: hex::encode(record.attempt_id),
                        verification_hash: hex::encode(record.verification_hash),
                        commitment: record.commitment,
                        staged_receipt_hash: hex::encode(record.staged_receipt_hash),
                        destination_attempt_id: hex::encode(record.destination_attempt_id),
                        destination_receipt_hash: hex::encode(record.destination_receipt_hash),
                        cancelled: record.cancelled,
                    }
                }
                "volume-copy-cleanup" => {
                    let volumes: Vec<Uuid> = decode(bytes)?;
                    if key.len() != 33
                        || key[..32] == [0; 32]
                        || key[32] >= mb_core::MAX_CODING_SHARDS as u8
                        || volumes.iter().any(Uuid::is_nil)
                        || volumes.iter().collect::<BTreeSet<_>>().len() != volumes.len()
                    {
                        bail!("invalid preserved volume copy cleanup obligation");
                    }
                    LegacyVolumeOwnershipEvidence::CopyCleanup {
                        group_id: hex::encode(&key[..32]),
                        shard_index: key[32],
                        volume_ids: volumes,
                    }
                }
                _ => unreachable!(),
            };
            visit(kind, key, bytes, evidence)?;
            Ok(true)
        })?;
    }
    Ok(())
}

fn load_volume_records(control: &ControlStore) -> Result<Vec<VolumeRecord>> {
    Ok(control
        .get_record("node-config", b"storage-volumes")?
        .map(|bytes| decode_volume_records(&bytes))
        .transpose()?
        .unwrap_or_default())
}

fn store_volume_records(control: &ControlStore, records: &[VolumeRecord]) -> Result<()> {
    control.put_record(
        "node-config",
        b"storage-volumes",
        &canonical_bytes(&records.to_vec())?,
    )?;
    Ok(())
}

fn volume_object_id(group_id: &[u8; 32], shard_index: u8) -> Vec<u8> {
    let mut id = Vec::with_capacity(33);
    id.extend_from_slice(group_id);
    id.push(shard_index);
    id
}

fn attempt_volume_object_id(
    attempt_id: &[u8; 16],
    group_id: &[u8; 32],
    shard_index: u8,
) -> Vec<u8> {
    let mut id = Vec::with_capacity(49);
    id.extend_from_slice(attempt_id);
    id.extend_from_slice(group_id);
    id.push(shard_index);
    id
}

fn attempt_reservation_id(attempt_id: &[u8; 16], shard_index: u8) -> Vec<u8> {
    let mut id = Vec::with_capacity(17);
    id.extend_from_slice(attempt_id);
    id.push(shard_index);
    id
}

fn validate_coding_shard_size(shard_size: u32) -> Result<()> {
    if !(mb_core::MIN_PROFILE_SHARD_SIZE..=mb_core::MAX_PROFILE_SHARD_SIZE).contains(&shard_size)
        || !shard_size.is_power_of_two()
    {
        bail!("coding capacity shard size is invalid");
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct DeviceCodingCapacity {
    logical_shards: u64,
    available_bytes: Option<u64>,
    reserved_bytes: u64,
}

fn add_volume_coding_capacity(
    devices: &mut BTreeMap<u64, DeviceCodingCapacity>,
    record: &VolumeRecord,
    store: &ParityStore,
    shard_size: u32,
) -> Result<()> {
    let logical = record
        .budget_bytes
        .saturating_sub(record.headroom_bytes)
        .saturating_sub(store.used_bytes()?)
        / u64::from(shard_size);
    let device = fs::metadata(&record.path)?.dev();
    let available = fs2::available_space(&record.path)?;
    let entry = devices.entry(device).or_default();
    entry.logical_shards = entry.logical_shards.saturating_add(logical);
    entry.available_bytes = Some(
        entry
            .available_bytes
            .map_or(available, |prior| prior.min(available)),
    );
    entry.reserved_bytes = entry
        .reserved_bytes
        .saturating_add(record.headroom_bytes)
        .saturating_add(store.checkpoint_reservation_bytes()?);
    Ok(())
}

fn device_coding_capacity(
    control: &ControlStore,
    devices: &BTreeMap<u64, DeviceCodingCapacity>,
    shard_size: u32,
) -> Result<u64> {
    let control_device = fs::metadata(control.path())?.dev();
    let control_checkpoint = control.checkpoint_reservation_bytes()?;
    let required_physical = physical_write_reservation(shard_size as usize, 0);
    Ok(devices
        .iter()
        .map(|(device, capacity)| {
            let control_reserve = if *device == control_device {
                control_checkpoint
            } else {
                0
            };
            let reserved = capacity.reserved_bytes.saturating_add(control_reserve);
            let physical = capacity
                .available_bytes
                .unwrap_or(0)
                .saturating_sub(reserved)
                / required_physical;
            capacity.logical_shards.min(physical)
        })
        .fold(0_u64, u64::saturating_add))
}

fn physical_write_reservation(payload_bytes: usize, acknowledgement_bytes: usize) -> u64 {
    let row_bytes = (payload_bytes as u64)
        .saturating_add(acknowledgement_bytes as u64)
        .saturating_add(DATABASE_PAGE_BYTES * 4);
    let pages = row_bytes.div_ceil(DATABASE_PAGE_BYTES);
    pages
        .saturating_mul(DATABASE_PAGE_BYTES)
        .saturating_mul(3)
        .saturating_add(PHYSICAL_WRITE_FIXED_RESERVE)
}

fn shared_checkpoint_reservation(control: &ControlStore, parity: &ParityStore) -> Result<u64> {
    let mut reservation = parity.checkpoint_reservation_bytes()?;
    if fs::metadata(control.path())?.dev() == fs::metadata(parity.path())?.dev() {
        reservation = reservation.saturating_add(control.checkpoint_reservation_bytes()?);
    }
    Ok(reservation)
}

fn volume_database_id(volume_id: Uuid) -> Vec<u8> {
    let mut id = b"parity.db/v2/".to_vec();
    id.extend_from_slice(volume_id.as_bytes());
    id
}

fn legacy_volume_database_id(volume_id: Uuid) -> Vec<u8> {
    let mut id = b"parity.db/".to_vec();
    id.extend_from_slice(volume_id.as_bytes());
    id
}

fn legacy_default_volume_id(keys: &KeyMaterial) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&blake3::hash(&keys.node_id().0).as_bytes()[..16]);
    Uuid::from_bytes(bytes)
}

fn require_online_directory(path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve parity volume {}", path.display()))?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("parity volume must be an existing directory");
    }
    Ok(path)
}

fn read_private_record<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() as usize > MAX_LOCAL_MANIFEST_BYTES
    {
        bail!("private storage manifest has unsafe ownership, mode, type, or size");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take(MAX_LOCAL_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_LOCAL_MANIFEST_BYTES {
        bail!("private storage manifest is too large");
    }
    Ok(decode_canonical(&bytes)?)
}

fn write_new_private_record<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = canonical_bytes(value)?;
    if bytes.len() > MAX_LOCAL_MANIFEST_BYTES {
        bail!("private storage manifest is too large");
    }
    let parent = path.parent().context("storage manifest has no parent")?;
    let temporary = parent.join(format!(".mutualbackup-manifest-{}.tmp", Uuid::new_v4()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let write_result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn truncated_error(error: &impl std::fmt::Display) -> String {
    let mut value = error.to_string();
    if value.len() > 1024 {
        let mut boundary = 1024;
        while !value.is_char_boundary(boundary) {
            boundary -= 1;
        }
        value.truncate(boundary);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{Seed, V1_SECTOR_SIZE, sector_root};
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    fn preserved_ownership_fixture() -> Vec<(&'static str, Vec<u8>, Vec<u8>)> {
        let volume_id = Uuid::from_u128(1);
        let old = VolumeReceipt {
            format_version: 1,
            volume_id,
            guild_id: [86; 32],
            group_id: [87; 32],
            shard_index: 4,
            root: [88; 32],
        };
        let commitment = mb_core::merkle_zero_commitment(mb_core::MIN_PROFILE_SHARD_SIZE).unwrap();
        let receipt = VolumeReceipt {
            format_version: 2,
            group_id: [89; 32],
            shard_index: 6,
            root: commitment.root,
            ..old.clone()
        };
        let attempt = AttemptVolumeRecord {
            format_version: 1,
            attempt_id: [90; 16],
            receipt: receipt.clone(),
        };
        let reservation = AttemptReservationRecord {
            format_version: 1,
            attempt_id: attempt.attempt_id,
            volume_id,
            guild_id: receipt.guild_id,
            shard_index: receipt.shard_index,
            byte_length: commitment.byte_len,
        };
        let retirement = AttemptRetirement {
            format_version: 1,
            volume_id,
            attempt_id: attempt.attempt_id,
            group_id: receipt.group_id,
            shard_index: receipt.shard_index,
            cleanup_verification_hash: None,
        };
        let migration = VariableVolumeMigration {
            format_version: 1,
            source_volume_id: Uuid::from_u128(2),
            destination: receipt.clone(),
            attempt_id: attempt.attempt_id,
            verification_hash: [91; 32],
            commitment,
            staged_receipt_hash: [92; 32],
            destination_attempt_id: [93; 16],
            destination_receipt_hash: [94; 32],
            cancelled: true,
        };
        let object_key = volume_object_id(&receipt.group_id, receipt.shard_index);
        let attempt_key =
            attempt_volume_object_id(&attempt.attempt_id, &receipt.group_id, receipt.shard_index);
        vec![
            (
                "volume-receipt",
                volume_object_id(&old.group_id, old.shard_index),
                canonical_bytes(&old).unwrap(),
            ),
            (
                "volume-receipt",
                object_key.clone(),
                canonical_bytes(&receipt).unwrap(),
            ),
            (
                "volume-write-intent",
                object_key.clone(),
                canonical_bytes(&VolumeWriteIntent {
                    format_version: 1,
                    receipt: receipt.clone(),
                })
                .unwrap(),
            ),
            (
                "volume-attempt-intent",
                attempt_key.clone(),
                canonical_bytes(&attempt).unwrap(),
            ),
            (
                "volume-attempt-receipt",
                attempt_key.clone(),
                canonical_bytes(&attempt).unwrap(),
            ),
            (
                "volume-attempt-reservation",
                attempt_reservation_id(&attempt.attempt_id, receipt.shard_index),
                canonical_bytes(&reservation).unwrap(),
            ),
            (
                "volume-attempt-retirement",
                attempt_key,
                canonical_bytes(&retirement).unwrap(),
            ),
            (
                VARIABLE_MIGRATION_KIND,
                object_key.clone(),
                canonical_bytes(&migration).unwrap(),
            ),
            (
                "volume-copy-cleanup",
                object_key,
                canonical_bytes(&vec![volume_id, migration.source_volume_id]).unwrap(),
            ),
        ]
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserved_volume_ownership_uses_original_records_without_opening_payloads() {
        for mode in ["closed", "wal-only", "live"] {
            let area = TempDir::new().unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([85; 32]));
            let database = area.path().join("control.db");
            let control = ControlStore::open(&database, &keys).unwrap();
            let records = preserved_ownership_fixture();
            for (kind, key, bytes) in &records {
                control.put_record(kind, key, bytes).unwrap();
            }
            let registry = preserved_registry_record(area.path().join("unavailable-volume"), 1);
            store_volume_records(&control, &[registry]).unwrap();
            let mut writer = Some(control);
            if mode == "closed" {
                drop(writer.take());
            }
            if mode == "wal-only" {
                fs::remove_file(database.with_extension("db-shm")).unwrap();
            }
            let names = || {
                let mut names = fs::read_dir(area.path())
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<Vec<_>>();
                names.sort();
                names
            };
            let before_names = names();
            let before_main = fs::read(&database).unwrap();
            let before_wal = fs::read(database.with_extension("db-wal")).ok();
            let report =
                crate::inventory_withdrawn_revisions_from_catalog(&keys, area.path()).unwrap();
            assert_eq!(report.format_version, 18);
            assert!(!report.retained_history_complete);
            let json = serde_json::to_vec(&report).unwrap();
            assert_eq!(
                serde_json::from_slice::<crate::LegacyRevisionInventory>(&json).unwrap(),
                report
            );
            let entries = &report.local_state.volume_ownership;
            assert_eq!(entries.len(), records.len(), "{mode}");
            for (kind, key, bytes) in &records {
                let entry = entries
                    .iter()
                    .find(|entry| {
                        entry.record_kind == *kind && entry.record_id_hex == hex::encode(key)
                    })
                    .unwrap();
                assert_eq!(entry.record_bytes, bytes.len() as u64);
                assert_eq!(
                    entry.record_hash,
                    hex::encode(blake3::hash(bytes).as_bytes())
                );
                assert!(!entry.payloads_verified);
                assert_eq!(
                    entry.unregistered_volume_ids,
                    if matches!(*kind, VARIABLE_MIGRATION_KIND | "volume-copy-cleanup") {
                        vec![Uuid::from_u128(2)]
                    } else {
                        vec![]
                    }
                );
            }
            assert!(entries.iter().any(|entry| matches!(&entry.evidence, LegacyVolumeOwnershipEvidence::Receipt(receipt) if receipt.format_version == 1 && receipt.shard_index == 4)));
            assert!(entries.iter().any(|entry| matches!(&entry.evidence, LegacyVolumeOwnershipEvidence::Receipt(receipt) if receipt.format_version == 2 && receipt.shard_index == 6)));
            let migration = entries
                .iter()
                .find_map(|entry| match &entry.evidence {
                    LegacyVolumeOwnershipEvidence::Migration {
                        cancelled,
                        verification_hash,
                        destination_attempt_id,
                        commitment,
                        ..
                    } => Some((
                        cancelled,
                        verification_hash,
                        destination_attempt_id,
                        commitment,
                    )),
                    _ => None,
                })
                .unwrap();
            assert!(*migration.0);
            assert_eq!(*migration.1, hex::encode([91; 32]));
            assert_eq!(*migration.2, hex::encode([93; 16]));
            assert_eq!(migration.3.byte_len, mb_core::MIN_PROFILE_SHARD_SIZE);
            assert_eq!(names(), before_names, "{mode}");
            assert_eq!(fs::read(&database).unwrap(), before_main, "{mode}");
            assert_eq!(
                fs::read(database.with_extension("db-wal")).ok(),
                before_wal,
                "{mode}"
            );
            assert!(!area.path().join("unavailable-volume").exists());
            drop(writer);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserved_volume_ownership_rejects_wrong_keys_noncanonical_and_oversized_rows() {
        let area = TempDir::new().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[95; 32]).unwrap();
        for (kind, key, bytes) in preserved_ownership_fixture() {
            let mut wrong = key.clone();
            wrong[0] ^= 1;
            // Cleanup's group key is its only group evidence, so an alternate
            // nonzero group remains valid. Its malformed key is truncated.
            if kind == "volume-copy-cleanup" {
                wrong.pop();
            }
            let invalid_shape = match kind {
                "volume-receipt" => {
                    let mut record: VolumeReceipt = decode_canonical(&bytes).unwrap();
                    record.root = [0; 32];
                    canonical_bytes(&record).unwrap()
                }
                "volume-write-intent" => {
                    let mut record: VolumeWriteIntent = decode_canonical(&bytes).unwrap();
                    record.format_version = 2;
                    canonical_bytes(&record).unwrap()
                }
                "volume-attempt-intent" | "volume-attempt-receipt" => {
                    let mut record: AttemptVolumeRecord = decode_canonical(&bytes).unwrap();
                    record.receipt.format_version = 1;
                    canonical_bytes(&record).unwrap()
                }
                "volume-attempt-reservation" => {
                    let mut record: AttemptReservationRecord = decode_canonical(&bytes).unwrap();
                    record.byte_length = 17;
                    canonical_bytes(&record).unwrap()
                }
                "volume-attempt-retirement" => {
                    let mut record: AttemptRetirement = decode_canonical(&bytes).unwrap();
                    record.cleanup_verification_hash = Some([0; 32]);
                    canonical_bytes(&record).unwrap()
                }
                VARIABLE_MIGRATION_KIND => {
                    let mut record: VariableVolumeMigration = decode_canonical(&bytes).unwrap();
                    record.destination.root = [1; 32];
                    canonical_bytes(&record).unwrap()
                }
                "volume-copy-cleanup" => canonical_bytes(&vec![Uuid::nil()]).unwrap(),
                _ => unreachable!(),
            };
            for (key, bytes) in [
                (wrong, bytes.clone()),
                (vec![1; 50], bytes.clone()),
                (key.clone(), invalid_shape),
                (key.clone(), [bytes.clone(), vec![0]].concat()),
                (key.clone(), vec![0; MAX_VOLUME_RECEIPT_BYTES + 1]),
            ] {
                control.put_record(kind, &key, &bytes).unwrap();
                let mut visits = 0;
                assert!(
                    for_each_preserved_volume_ownership(&control, |_, _, _, _| {
                        visits += 1;
                        Ok(())
                    })
                    .is_err(),
                    "{kind}"
                );
                assert_eq!(visits, 0, "{kind}");
                control.delete_record(kind, &key).unwrap();
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn preserved_registry_record(path: PathBuf, number: u128) -> VolumeRecord {
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([81; 32]));
        let volume_id = Uuid::from_u128(number);
        VolumeRecord {
            format_version: 1,
            volume_id,
            path,
            database_file: "parity.db".to_owned(),
            wrapped_database_key: keys
                .wrap_database_key(&volume_database_id(volume_id), &[82; 32])
                .unwrap(),
            state: StorageVolumeState::Online,
            budget_bytes: 65536,
            headroom_bytes: 0,
            last_error: None,
            configured: true,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserved_volume_paths_cover_all_states_and_historical_raw_paths() {
        use std::os::unix::ffi::OsStringExt;

        let area = TempDir::new().unwrap();
        let database = area.path().join("control.db");
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([83; 32]));
        let writer = ControlStore::open(&database, &keys).unwrap();
        let records = [
            StorageVolumeState::Online,
            StorageVolumeState::Offline,
            StorageVolumeState::Draining,
            StorageVolumeState::Retired,
            StorageVolumeState::Failed,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, state)| {
            let path = area.path().join(std::ffi::OsString::from_vec(vec![
                b'v',
                index as u8 + b'0',
                0xff,
            ]));
            let mut record = preserved_registry_record(path, index as u128 + 1);
            record.state = state;
            record.configured = index % 2 == 0;
            record
        })
        .collect::<Vec<_>>();
        let historical = records
            .iter()
            .map(|record| VolumeRecordBeforeConfiguredState {
                format_version: record.format_version,
                volume_id: record.volume_id,
                path: record.path.clone(),
                database_file: record.database_file.clone(),
                wrapped_database_key: record.wrapped_database_key.clone(),
                state: record.state,
                budget_bytes: record.budget_bytes,
                headroom_bytes: record.headroom_bytes,
                last_error: record.last_error.clone(),
            })
            .collect::<Vec<_>>();
        for (encoded, configured_recorded) in [
            (canonical_bytes(&records).unwrap(), true),
            (canonical_bytes(&historical).unwrap(), false),
        ] {
            writer
                .put_record("node-config", b"storage-volumes", &encoded)
                .unwrap();
            let original = fs::read(&database).unwrap();
            let wal = fs::read(database.with_extension("db-wal")).unwrap();
            let names = || {
                fs::read_dir(area.path())
                    .unwrap()
                    .map(|entry| entry.unwrap().file_name())
                    .collect::<BTreeSet<_>>()
            };
            let before = names();
            let mut paths = Vec::new();
            ControlStore::with_preserved_read_only_snapshot(
                &database,
                &[keys.database_key(b"control.db")],
                |control| {
                    for_each_preserved_volume_registration(control, |volume| {
                        assert_eq!(volume.configured_recorded, configured_recorded);
                        let original = &records[paths.len()];
                        assert_eq!(
                            volume.configured,
                            !configured_recorded || original.configured
                        );
                        paths.push(volume.path.to_path_buf());
                        Ok(())
                    })
                },
            )
            .unwrap();
            assert_eq!(
                paths,
                records
                    .iter()
                    .map(|record| record.path.clone())
                    .collect::<Vec<_>>()
            );
            assert!(paths.iter().all(|path| !path.exists()));
            let inventory =
                crate::inventory_withdrawn_revisions_from_catalog(&keys, area.path()).unwrap();
            assert_eq!(inventory.format_version, 18);
            assert!(!inventory.retained_history_complete);
            let volumes = &inventory.local_state.storage_volumes;
            assert_eq!(volumes.len(), records.len());
            for (volume, original) in volumes.iter().zip(&records) {
                assert_eq!(volume.volume_id, original.volume_id);
                assert_eq!(volume.record_format, original.format_version);
                assert_eq!(
                    volume.path_hex,
                    hex::encode(original.path.as_os_str().as_encoded_bytes())
                );
                assert_eq!(volume.database_file, original.database_file);
                assert_eq!(volume.state, original.state);
                assert_eq!(volume.configured_recorded, configured_recorded);
                assert_eq!(
                    volume.configured,
                    !configured_recorded || original.configured
                );
                assert_eq!(volume.budget_bytes, original.budget_bytes);
                assert_eq!(volume.headroom_bytes, original.headroom_bytes);
                assert!(!volume.payloads_verified);
            }
            assert!(
                !serde_json::to_string(&inventory)
                    .unwrap()
                    .contains("wrapped_database_key")
            );
            assert_eq!(names(), before);
            assert_eq!(fs::read(&database).unwrap(), original);
            assert_eq!(fs::read(database.with_extension("db-wal")).unwrap(), wal);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserved_volume_paths_reject_invalid_or_ambiguous_registry_without_visiting() {
        use std::os::unix::ffi::OsStringExt;

        let area = TempDir::new().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[84; 32]).unwrap();
        let record = preserved_registry_record(area.path().join("absent-volume"), 1);
        let mut invalid = Vec::new();
        for path in [
            PathBuf::new(),
            PathBuf::from("relative"),
            area.path()
                .join(std::ffi::OsString::from_vec(b"volume\0".to_vec())),
        ] {
            let mut changed = record.clone();
            changed.volume_id = Uuid::from_u128(2);
            changed.path = path;
            invalid.push(vec![record.clone(), changed]);
        }
        for name in [
            ".",
            "..",
            "/",
            "../parity.db",
            ".mutualbackup-volume",
            "parity\0.db",
        ] {
            let mut changed = record.clone();
            changed.volume_id = Uuid::from_u128(2);
            changed.database_file = name.to_owned();
            invalid.push(vec![record.clone(), changed]);
        }
        for (format, id, budget, headroom) in [
            (2, Uuid::from_u128(2), 65536, 0),
            (1, Uuid::nil(), 65536, 0),
            (1, Uuid::from_u128(2), 0, 0),
            (1, Uuid::from_u128(2), 65536, 65536),
        ] {
            let mut changed = record.clone();
            changed.format_version = format;
            changed.volume_id = id;
            changed.budget_bytes = budget;
            changed.headroom_bytes = headroom;
            invalid.push(vec![record.clone(), changed]);
        }
        invalid.push(vec![record.clone(), record]);
        for records in invalid {
            store_volume_records(&control, &records).unwrap();
            let mut visits = 0;
            assert!(
                for_each_preserved_volume_registration(&control, |_| {
                    visits += 1;
                    Ok(())
                })
                .is_err()
            );
            assert_eq!(
                visits, 0,
                "validate the full bounded registry before using its locations"
            );
        }
        control
            .put_record("node-config", b"storage-volumes", b"damaged registry")
            .unwrap();
        assert!(
            for_each_preserved_volume_registration(&control, |_| panic!(
                "damaged registry visited"
            ))
            .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preserved_volume_paths_share_scratch_registry_size_and_count_bounds() {
        let area = TempDir::new().unwrap();
        let control =
            ControlStore::open_with_key(area.path().join("control.db"), &[85; 32]).unwrap();
        let record = preserved_registry_record(area.path().join("absent-volume"), 1);
        let mut records = (1..=MAX_BOUNDED_VOLUME_RECORDS)
            .map(|number| {
                let mut next = record.clone();
                next.volume_id = Uuid::from_u128(number as u128);
                next
            })
            .collect::<Vec<_>>();
        store_volume_records(&control, &records).unwrap();
        let mut visits = 0;
        for_each_preserved_volume_registration(&control, |_| {
            visits += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(visits, MAX_BOUNDED_VOLUME_RECORDS);
        records.push(record.clone());
        store_volume_records(&control, &records).unwrap();
        assert!(
            for_each_preserved_volume_registration(&control, |_| panic!(
                "oversized registry visited"
            ))
            .unwrap_err()
            .to_string()
            .contains("too many volumes")
        );
        assert!(
            paged_scratch_store(&control, 64 * 1024 * 1024)
                .err()
                .unwrap()
                .to_string()
                .contains("too many volumes")
        );

        let mut boundary = record;
        boundary.last_error = Some("x".repeat(MAX_BOUNDED_VOLUME_REGISTRY_BYTES));
        loop {
            let length = canonical_bytes(&vec![boundary.clone()]).unwrap().len();
            if length == MAX_BOUNDED_VOLUME_REGISTRY_BYTES {
                break;
            }
            let error = boundary.last_error.as_mut().unwrap();
            error.truncate(error.len() - (length - MAX_BOUNDED_VOLUME_REGISTRY_BYTES));
        }
        store_volume_records(&control, &[boundary]).unwrap();
        for_each_preserved_volume_registration(&control, |_| Ok(())).unwrap();
        control
            .put_record(
                "node-config",
                b"storage-volumes",
                &vec![0; MAX_BOUNDED_VOLUME_REGISTRY_BYTES + 1],
            )
            .unwrap();
        for error in [
            for_each_preserved_volume_registration(&control, |_| panic!("oversized blob visited"))
                .unwrap_err(),
            paged_scratch_store(&control, 64 * 1024 * 1024)
                .err()
                .unwrap(),
        ] {
            assert!(matches!(
                error.downcast_ref::<DatabaseError>(),
                Some(DatabaseError::Integrity)
            ));
        }
    }

    #[test]
    fn preserved_parity_volume_reads_wrapped_legacy_and_interrupted_keys_without_mutation() {
        for mode in 0..3 {
            let journal_states = if cfg!(target_os = "linux") { 3 } else { 1 };
            for journal_state in 0..journal_states {
                let temp = TempDir::new().unwrap();
                let keys = KeyMaterial::from_seed(&Seed::from_bytes([119; 32]));
                let volume_id = if mode == 1 {
                    Uuid::new_v4()
                } else {
                    legacy_default_volume_id(&keys)
                };
                let wrapped_key = [120; 32];
                let database_key = if mode == 1 {
                    wrapped_key
                } else {
                    keys.database_key(&legacy_volume_database_id(volume_id))
                };
                let path = temp.path().join("parity.db");
                let mut writer =
                    ParityStore::open_with_key(&path, volume_id.as_bytes(), &database_key).unwrap();
                writer
                    .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
                    .unwrap();
                let fixed = parity_object(121, 3);
                writer.stage_and_publish(&fixed).unwrap();
                let bytes = vec![122; 4096];
                let variable = VariableParityObject {
                    format_version: 2,
                    guild_id: [123; 32],
                    group_id: [124; 32],
                    shard_index: 7,
                    commitment: mb_core::merkle_commit(&bytes).unwrap(),
                    bytes,
                };
                writer
                    .stage_attempt(&[125; 16], &variable, b"receipt", 2 * 65536)
                    .unwrap();
                writer
                    .activate_attempt_object(
                        &[125; 16],
                        &variable.group_id,
                        variable.shard_index,
                        &variable.commitment,
                        &[126; 32],
                    )
                    .unwrap();
                if mode != 0 {
                    let manifest = VolumeManifest {
                        format_version: 1,
                        owner: keys.node_id(),
                        volume_id,
                        database_file: "parity.db".into(),
                        wrapped_database_key: keys
                            .wrap_database_key(&volume_database_id(volume_id), &wrapped_key)
                            .unwrap(),
                    };
                    write_new_private_record(
                        &temp.path().join(VOLUME_MANIFEST_FILE),
                        &SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, &keys).unwrap(),
                    )
                    .unwrap();
                }
                let root = if journal_state == 1 {
                    let copy = temp.path().join("copy");
                    fs::create_dir(&copy).unwrap();
                    for name in ["parity.db", "parity.db-wal", VOLUME_MANIFEST_FILE] {
                        if temp.path().join(name).exists() {
                            fs::copy(temp.path().join(name), copy.join(name)).unwrap();
                        }
                    }
                    copy
                } else {
                    temp.path().to_path_buf()
                };
                let _writer = if journal_state == 2 {
                    Some(writer)
                } else {
                    drop(writer);
                    None
                };
                let path = root.join("parity.db");
                #[cfg(target_os = "linux")]
                let files = || -> BTreeMap<_, _> {
                    fs::read_dir(&root)
                        .unwrap()
                        .filter_map(|entry| {
                            let entry = entry.unwrap();
                            if !entry.file_type().unwrap().is_file() {
                                return None;
                            }
                            let bytes = fs::read(entry.path()).unwrap();
                            let digest = (entry.file_name() != "parity.db-shm")
                                .then(|| blake3::hash(&bytes));
                            Some((entry.file_name(), (bytes.len(), digest)))
                        })
                        .collect()
                };
                #[cfg(target_os = "linux")]
                let original_files = files();
                let original = fs::read(&path).unwrap();
                let manifest_before = fs::read(root.join(VOLUME_MANIFEST_FILE)).ok();
                let reader = PreservedParityVolume::open(&root, &keys).unwrap();
                assert_eq!(reader.volume_id(), volume_id);
                assert_eq!(
                    reader
                        .load_fixed(
                            &fixed.guild_id,
                            &fixed.group_id,
                            fixed.shard_index,
                            &fixed.root
                        )
                        .unwrap(),
                    fixed.bytes
                );
                assert_eq!(
                    reader
                        .load_variable(
                            &variable.guild_id,
                            &variable.group_id,
                            variable.shard_index,
                            &variable.commitment
                        )
                        .unwrap(),
                    variable.bytes
                );
                assert!(
                    reader
                        .load_fixed(&[127; 32], &fixed.group_id, fixed.shard_index, &fixed.root)
                        .is_err()
                );
                assert!(
                    reader
                        .load_fixed(
                            &fixed.guild_id,
                            &fixed.group_id,
                            fixed.shard_index,
                            &[128; 32]
                        )
                        .is_err()
                );
                let mut changed = variable.commitment.clone();
                changed.root = [129; 32];
                assert!(
                    reader
                        .load_variable(
                            &variable.guild_id,
                            &variable.group_id,
                            variable.shard_index,
                            &changed
                        )
                        .is_err()
                );
                #[cfg(target_os = "linux")]
                reader.verify_unchanged().unwrap();
                drop(reader);
                #[cfg(target_os = "linux")]
                assert_eq!(
                    files(),
                    original_files,
                    "mode {mode}, journal state {journal_state}"
                );
                assert_eq!(fs::read(path).unwrap(), original);
                assert_eq!(
                    fs::read(root.join(VOLUME_MANIFEST_FILE)).ok(),
                    manifest_before
                );
                assert!(!root.join("control.db").exists());
                assert!(!root.join("control.key").exists());
            }
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn preserved_parity_volume_rejects_incomplete_journals_without_repair() {
        for (suffix, bytes) in [
            ("-wal", b"partial".as_slice()),
            ("-shm", b"shared memory without WAL".as_slice()),
            ("-journal", b"unfinished rollback".as_slice()),
            ("-wal", &[0; 32]),
        ] {
            let temp = TempDir::new().unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([119; 32]));
            let volume_id = legacy_default_volume_id(&keys);
            let mut writer =
                ParityStore::open(temp.path().join("parity.db"), volume_id.as_bytes(), &keys)
                    .unwrap();
            writer.stage_and_publish(&parity_object(121, 3)).unwrap();
            drop(writer);
            fs::write(temp.path().join(format!("parity.db{suffix}")), bytes).unwrap();
            let files = || -> BTreeMap<_, _> {
                fs::read_dir(temp.path())
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (entry.file_name(), fs::read(entry.path()).unwrap())
                    })
                    .collect()
            };
            let before = files();
            assert!(PreservedParityVolume::open(temp.path(), &keys).is_err());
            assert_eq!(files(), before);
        }
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn preserved_parity_volume_rejects_input_changes_after_open() {
        use std::io::Write;
        let temp = TempDir::new().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([119; 32]));
        let volume_id = legacy_default_volume_id(&keys);
        let path = temp.path().join("parity.db");
        let mut writer = ParityStore::open(&path, volume_id.as_bytes(), &keys).unwrap();
        let object = parity_object(121, 3);
        writer.stage_and_publish(&object).unwrap();
        drop(writer);
        let reader = PreservedParityVolume::open(temp.path(), &keys).unwrap();
        assert_eq!(
            reader
                .load_fixed(
                    &object.guild_id,
                    &object.group_id,
                    object.shard_index,
                    &object.root
                )
                .unwrap(),
            object.bytes
        );
        fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap()
            .write_all(b"changed input")
            .unwrap();
        assert!(reader.verify_unchanged().is_err());
        assert!(
            reader
                .load_fixed(
                    &object.guild_id,
                    &object.group_id,
                    object.shard_index,
                    &object.root
                )
                .is_err()
        );
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }

    #[test]
    fn preserved_parity_volume_rejects_foreign_manifest_signers_missing_and_symlinked_inputs() {
        use std::os::unix::fs::symlink;
        let temp = TempDir::new().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([119; 32]));
        assert!(PreservedParityVolume::open(temp.path(), &keys).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
        let record = initialize_volume(temp.path(), Some("parity.db"), 65536, 0, &keys).unwrap();
        let manifest = read_volume_manifest(temp.path(), &keys).unwrap().unwrap();
        let original = fs::read(temp.path().join("parity.db")).unwrap();
        let foreign = KeyMaterial::from_seed(&Seed::from_bytes([130; 32]));
        let signed = SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, &foreign).unwrap();
        fs::remove_file(temp.path().join(VOLUME_MANIFEST_FILE)).unwrap();
        write_new_private_record(&temp.path().join(VOLUME_MANIFEST_FILE), &signed).unwrap();
        assert!(PreservedParityVolume::open(temp.path(), &keys).is_err());
        assert!(read_volume_manifest(temp.path(), &keys).is_err());
        let database_key = keys
            .unwrap_database_key(
                &volume_database_id(record.volume_id),
                &record.wrapped_database_key,
            )
            .unwrap();
        assert!(open_volume_store(&record, &database_key, &keys).is_err());
        assert_eq!(fs::read(temp.path().join("parity.db")).unwrap(), original);
        fs::remove_file(temp.path().join(VOLUME_MANIFEST_FILE)).unwrap();
        let actual = temp.path().join("preserved.db");
        fs::rename(temp.path().join("parity.db"), &actual).unwrap();
        symlink(&actual, temp.path().join("parity.db")).unwrap();
        assert!(PreservedParityVolume::open(temp.path(), &keys).is_err());
        assert_eq!(fs::read(actual).unwrap(), original);
    }

    #[test]
    fn coding_capacity_accounts_for_durable_reservations() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([201; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[temp.path().to_path_buf()],
                3 * V1_SECTOR_SIZE as u64,
                0,
            )
            .unwrap();
        assert_eq!(
            volumes
                .coding_capacity(&control, V1_SECTOR_SIZE as u32)
                .unwrap(),
            3
        );
        volumes
            .reserve_attempt(&control, &[202; 16], [203; 32], 3, V1_SECTOR_SIZE as u32)
            .unwrap();
        assert_eq!(
            volumes
                .coding_capacity(&control, V1_SECTOR_SIZE as u32)
                .unwrap(),
            2
        );
        assert_eq!(
            reader_coding_capacity(&control, &volumes.reader_configs(), V1_SECTOR_SIZE as u32,)
                .unwrap(),
            2
        );
    }

    #[test]
    fn coding_capacity_counts_shared_filesystem_space_once() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([204; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let device = fs::metadata(control.path()).unwrap().dev();
        let checkpoint = control.checkpoint_reservation_bytes().unwrap();
        let per_shard = physical_write_reservation(V1_SECTOR_SIZE, 0);
        let devices = BTreeMap::from([(
            device,
            DeviceCodingCapacity {
                logical_shards: 8,
                available_bytes: Some(checkpoint + 8192 + per_shard * 2 + per_shard / 2),
                reserved_bytes: 8192,
            },
        )]);
        assert_eq!(
            device_coding_capacity(&control, &devices, V1_SECTOR_SIZE as u32).unwrap(),
            2
        );
    }

    fn parity_object(marker: u8, shard_index: u8) -> ParityObject {
        let bytes = vec![marker; V1_SECTOR_SIZE];
        ParityObject {
            format_version: 1,
            guild_id: [marker.wrapping_add(1); 32],
            group_id: [marker.wrapping_add(2); 32],
            shard_index,
            root: sector_root(&bytes),
            bytes,
        }
    }

    #[test]
    fn control_and_volume_database_keys_are_random_wrapped_and_reopen() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([61; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        assert_eq!(volumes.statuses().unwrap().len(), 1);
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert_eq!(
            volumes.statuses().unwrap()[0].state,
            StorageVolumeState::Online
        );
    }

    #[test]
    fn legacy_nonempty_control_database_is_rekeyed_and_reopened() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([62; 32])));
        {
            let control = ControlStore::open(temp.path().join("control.db"), &keys).unwrap();
            for index in 0_u8..64 {
                control
                    .put_record("legacy-record", &[index], &vec![index; 1024])
                    .unwrap();
            }
        }

        let (control, database_key) = open_control_store(temp.path(), &keys).unwrap();
        assert_eq!(control.records("legacy-record").unwrap().len(), 64);
        drop(control);
        let (control, reopened_key) = open_control_store(temp.path(), &keys).unwrap();
        assert_eq!(reopened_key, database_key);
        assert_eq!(control.records("legacy-record").unwrap().len(), 64);
    }

    #[test]
    fn manifest_published_before_legacy_volume_rekey_resumes_without_data_loss() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([59; 32])));
        let mut volume_id_bytes = [0_u8; 16];
        volume_id_bytes.copy_from_slice(&blake3::hash(&keys.node_id().0).as_bytes()[..16]);
        let volume_id = Uuid::from_bytes(volume_id_bytes);
        let object = parity_object(58, 3);
        let database_path = temp.path().join("parity.db");
        let mut legacy = ParityStore::open(&database_path, volume_id.as_bytes(), &keys).unwrap();
        legacy.stage_and_publish(&object).unwrap();
        drop(legacy);

        let database_key = [57; 32];
        let manifest = VolumeManifest {
            format_version: 1,
            owner: keys.node_id(),
            volume_id,
            database_file: "parity.db".to_owned(),
            wrapped_database_key: keys
                .wrap_database_key(&volume_database_id(volume_id), &database_key)
                .unwrap(),
        };
        let signed = SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest, &keys).unwrap();
        write_new_private_record(&temp.path().join(VOLUME_MANIFEST_FILE), &signed).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
    }

    #[test]
    fn legacy_volume_registry_defaults_to_configured() {
        #[derive(Serialize)]
        struct LegacyVolumeRecord {
            format_version: u16,
            volume_id: Uuid,
            path: PathBuf,
            database_file: String,
            wrapped_database_key: WrappedDatabaseKey,
            state: StorageVolumeState,
            budget_bytes: u64,
            headroom_bytes: u64,
            last_error: Option<String>,
        }

        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([60; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        let record = volumes.volumes.values().next().unwrap().record.clone();
        control
            .put_record(
                "node-config",
                b"storage-volumes",
                &canonical_bytes(&vec![LegacyVolumeRecord {
                    format_version: record.format_version,
                    volume_id: record.volume_id,
                    path: record.path,
                    database_file: record.database_file,
                    wrapped_database_key: record.wrapped_database_key,
                    state: record.state,
                    budget_bytes: record.budget_bytes,
                    headroom_bytes: record.headroom_bytes,
                    last_error: record.last_error,
                }])
                .unwrap(),
            )
            .unwrap();
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert!(volumes.volumes.values().next().unwrap().record.configured);
    }

    #[test]
    fn absent_registered_volume_is_offline_instead_of_empty() {
        let temp = TempDir::new().unwrap();
        let volume = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([62; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(&control, &[volume.path().to_path_buf()], 1024 * 1024, 4096)
            .unwrap();
        let volume_path = volume.keep();
        fs::rename(&volume_path, volume_path.with_extension("offline")).unwrap();
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                std::slice::from_ref(&volume_path),
                1024 * 1024,
                4096,
            )
            .unwrap();
        assert!(volumes.protection_degraded(&control).unwrap());
        assert!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .any(|status| status.state == StorageVolumeState::Offline)
        );
    }

    #[test]
    fn empty_configuration_reopens_the_data_directory_volume() {
        let temp = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([65; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[external.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap();
        volumes
            .configure(
                &control,
                &[],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap();
        let default_path = temp.path().canonicalize().unwrap();
        let statuses = volumes.statuses().unwrap();
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.path == default_path)
                .unwrap()
                .state,
            StorageVolumeState::Online
        );
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.path == external.path().canonicalize().unwrap())
                .unwrap()
                .state,
            StorageVolumeState::Offline
        );
        let object = parity_object(66, 3);
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.path == default_path)
                .unwrap()
                .volume_id,
            receipt.volume_id
        );
        assert!(!volumes.protection_degraded(&control).unwrap());
    }

    #[test]
    fn duplicate_online_volume_identity_is_rejected() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let duplicate = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([67; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap();
        fs::copy(
            first.path().join(VOLUME_MANIFEST_FILE),
            duplicate.path().join(VOLUME_MANIFEST_FILE),
        )
        .unwrap();
        let error = volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), duplicate.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap_err();
        assert!(error.to_string().contains("more than one configured path"));
    }

    #[test]
    fn draining_migrates_verified_objects_before_withdrawing_the_source() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([63; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap();
        let bytes = vec![39; V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [41; 32],
            group_id: [42; 32],
            shard_index: 3,
            root: sector_root(&bytes),
            bytes,
        };
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        volumes.mark_draining(&control, receipt.volume_id).unwrap();
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 1);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        let statuses = volumes.statuses().unwrap();
        assert_eq!(
            statuses
                .iter()
                .find(|status| status.volume_id == receipt.volume_id)
                .unwrap()
                .state,
            StorageVolumeState::Retired
        );
        assert!(
            volumes
                .volumes
                .get(&receipt.volume_id)
                .unwrap()
                .store
                .is_none()
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| status.state == StorageVolumeState::Online)
                .filter_map(|status| status.object_count)
                .sum::<u64>(),
            1
        );

        drop(volumes);
        drop(control);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert_eq!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .find(|status| status.volume_id == receipt.volume_id)
                .unwrap()
                .state,
            StorageVolumeState::Retired
        );
        assert!(
            volumes
                .volumes
                .get(&receipt.volume_id)
                .unwrap()
                .store
                .is_none()
        );
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap();
        assert_eq!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .find(|status| status.volume_id == receipt.volume_id)
                .unwrap()
                .state,
            StorageVolumeState::Retired
        );
        volumes.reactivate(&control, receipt.volume_id).unwrap();
        assert_eq!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .find(|status| status.volume_id == receipt.volume_id)
                .unwrap()
                .state,
            StorageVolumeState::Online
        );
    }

    #[test]
    fn absent_retired_volume_stays_retired_through_startup_configuration() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([66; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        let configured = vec![first.path().to_path_buf(), second.path().to_path_buf()];
        volumes
            .configure(&control, &configured, (V1_SECTOR_SIZE * 2) as u64, 0)
            .unwrap();
        let object = parity_object(67, 3);
        let source = volumes.store(&control, &object, b"ack").unwrap();
        let source_path = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == source.volume_id)
            .unwrap()
            .path;
        volumes.mark_draining(&control, source.volume_id).unwrap();
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 1);
        drop(volumes);
        drop(control);
        fs::remove_dir_all(&source_path).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == source.volume_id)
            .unwrap();
        assert_eq!(status.state, StorageVolumeState::Retired);
        assert!(!status.path.exists());
        volumes
            .configure(&control, &configured, (V1_SECTOR_SIZE * 2) as u64, 0)
            .unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == source.volume_id)
            .unwrap();
        assert_eq!(status.state, StorageVolumeState::Retired);
        assert!(
            !volumes
                .volumes
                .get(&source.volume_id)
                .unwrap()
                .record
                .configured
        );
        assert!(!source_path.exists());
    }

    #[test]
    fn relocated_retired_volume_requires_explicit_reactivation() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([89; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let object = parity_object(90, 3);
        let source = volumes.store(&control, &object, b"ack").unwrap();
        let source_path = volumes
            .volumes
            .get(&source.volume_id)
            .unwrap()
            .record
            .path
            .clone();
        let active_path = volumes
            .volumes
            .values()
            .find(|volume| volume.record.volume_id != source.volume_id && volume.store.is_some())
            .unwrap()
            .record
            .path
            .clone();
        volumes.mark_draining(&control, source.volume_id).unwrap();
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 1);
        drop(volumes);
        drop(control);
        let relocated = temp.path().join("relocated-retired-volume");
        fs::rename(&source_path, &relocated).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[relocated.clone(), active_path],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let retired = volumes.volumes.get(&source.volume_id).unwrap();
        assert_eq!(retired.record.path, relocated.canonicalize().unwrap());
        assert_eq!(retired.record.state, StorageVolumeState::Retired);
        assert!(!retired.record.configured);
        assert!(retired.store.is_none());
    }

    #[test]
    fn repair_can_consume_reserved_headroom_while_normal_placement_cannot() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([64; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[],
                V1_SECTOR_SIZE as u64,
                V1_SECTOR_SIZE as u64 / 2,
            )
            .unwrap();
        let bytes = vec![45; V1_SECTOR_SIZE];
        let object = ParityObject {
            format_version: 1,
            guild_id: [46; 32],
            group_id: [47; 32],
            shard_index: 4,
            root: sector_root(&bytes),
            bytes,
        };
        assert!(matches!(
            volumes.store(&control, &object, b"ack"),
            Err(error) if matches!(
                error.downcast_ref::<DatabaseError>(),
                Some(DatabaseError::CapacityExceeded)
            )
        ));
        volumes.store_repair(&control, &object).unwrap();
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
    }

    #[test]
    fn corrupt_volume_does_not_mask_a_repaired_copy_or_status() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([68; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let object = parity_object(69, 3);
        let original = volumes.store(&control, &object, b"ack").unwrap();
        volumes
            .volumes
            .get(&original.volume_id)
            .unwrap()
            .store
            .as_ref()
            .unwrap()
            .database_shell_statement("UPDATE parity_objects SET bytes = zeroblob(65536)", false)
            .unwrap();
        let reports = volumes.scrub(&control).unwrap();
        assert_eq!(
            reports
                .iter()
                .find(|report| report.volume_id == original.volume_id)
                .unwrap()
                .corrupt_objects,
            vec![(object.group_id, object.shard_index)]
        );
        let replacement = volumes.store_repair(&control, &object).unwrap();
        assert_ne!(replacement.volume_id, original.volume_id);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert_eq!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .find(|status| status.volume_id == original.volume_id)
                .unwrap()
                .state,
            StorageVolumeState::Failed
        );
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert!(volumes.statuses().is_ok());
    }

    #[test]
    fn corrupt_pending_write_is_quarantined_during_reconciliation() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([80; 32])));
        let object = parity_object(81, 3);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        interrupt_next_volume_transition(VolumeInterruption::ObjectPublished);
        assert!(volumes.store(&control, &object, b"ack").is_err());
        let corrupt_volume = *volumes
            .volumes
            .iter()
            .find(|(_, volume)| {
                volume.store.as_ref().is_some_and(|store| {
                    store
                        .load_ready(&object.group_id, object.shard_index)
                        .is_ok()
                })
            })
            .unwrap()
            .0;
        volumes
            .volumes
            .get(&corrupt_volume)
            .unwrap()
            .store
            .as_ref()
            .unwrap()
            .database_shell_statement("UPDATE parity_objects SET bytes = zeroblob(65536)", false)
            .unwrap();
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes.reconcile(&control).unwrap();
        assert_eq!(
            volumes.volumes.get(&corrupt_volume).unwrap().record.state,
            StorageVolumeState::Failed
        );
        assert_eq!(control.records("volume-write-intent").unwrap().len(), 1);
        let replacement = volumes.store_repair(&control, &object).unwrap();
        assert_ne!(replacement.volume_id, corrupt_volume);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
    }

    #[test]
    fn corrupt_unreachable_object_is_removed_without_reading_its_payload() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([82; 32])));
        let object = parity_object(83, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        volumes
            .volumes
            .get(&receipt.volume_id)
            .unwrap()
            .store
            .as_ref()
            .unwrap()
            .database_shell_statement("UPDATE parity_objects SET bytes = zeroblob(65536)", false)
            .unwrap();
        volumes.scrub(&control).unwrap();

        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert!(control.records("volume-receipt").unwrap().is_empty());
    }

    #[test]
    fn failed_metadata_does_not_hide_storage_status() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([84; 32])));
        let object = parity_object(85, 3);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        let failed = volumes.volumes.get(&receipt.volume_id).unwrap();
        failed
            .store
            .as_ref()
            .unwrap()
            .database_shell_statement("UPDATE parity_objects SET bytes = zeroblob(65536)", false)
            .unwrap();
        volumes.scrub(&control).unwrap();
        volumes
            .volumes
            .get(&receipt.volume_id)
            .unwrap()
            .store
            .as_ref()
            .unwrap()
            .database_shell_statement("DROP TABLE parity_objects", false)
            .unwrap();

        let statuses = volumes.statuses().unwrap();
        let failed = statuses
            .iter()
            .find(|status| status.volume_id == receipt.volume_id)
            .unwrap();
        assert_eq!(failed.state, StorageVolumeState::Failed);
        assert_eq!(failed.used_bytes, None);
        assert!(failed.last_error.is_some());
        assert!(statuses.iter().any(|status| {
            status.volume_id != receipt.volume_id
                && status.state == StorageVolumeState::Online
                && status.used_bytes.is_some()
        }));
    }

    #[test]
    fn missing_established_database_is_failed_without_recreation() {
        let temp = TempDir::new().unwrap();
        let volume = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([70; 32])));
        let object = parity_object(71, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[volume.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        let record = volumes.volumes.get(&receipt.volume_id).unwrap();
        let database_path = record.record.path.join(&record.record.database_file);
        drop(volumes);
        drop(control);
        fs::remove_file(&database_path).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == receipt.volume_id)
            .unwrap();
        assert_eq!(status.state, StorageVolumeState::Failed);
        assert!(status.last_error.unwrap().contains("database I/O error"));
        assert!(volumes.protection_degraded(&control).unwrap());
        assert!(!database_path.exists());
    }

    #[test]
    fn truncated_established_database_is_failed_without_reinitialization() {
        let temp = TempDir::new().unwrap();
        let volume = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([76; 32])));
        let object = parity_object(77, 3);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[volume.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        let record = volumes.volumes.get(&receipt.volume_id).unwrap();
        let database_path = record.record.path.join(&record.record.database_file);
        drop(volumes);
        drop(control);
        File::create(&database_path).unwrap().sync_all().unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == receipt.volume_id)
            .unwrap();
        assert_eq!(status.state, StorageVolumeState::Failed);
        assert!(status.last_error.is_some());
        assert!(volumes.protection_degraded(&control).unwrap());
        assert_eq!(fs::metadata(database_path).unwrap().len(), 0);
    }

    #[test]
    fn relocated_established_volume_does_not_recreate_a_missing_database() {
        let temp = TempDir::new().unwrap();
        let original = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([86; 32])));
        let object = parity_object(87, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[original.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let receipt = volumes.store(&control, &object, b"ack").unwrap();
        let database_file = volumes
            .volumes
            .get(&receipt.volume_id)
            .unwrap()
            .record
            .database_file
            .clone();
        let original_path = original.keep();
        let relocated = temp.path().join("relocated-volume");
        drop(volumes);
        drop(control);
        fs::rename(&original_path, &relocated).unwrap();
        let database_path = relocated.join(database_file);
        fs::remove_file(&database_path).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                std::slice::from_ref(&relocated),
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == receipt.volume_id)
            .unwrap();
        assert_eq!(status.path, relocated.canonicalize().unwrap());
        assert_eq!(status.state, StorageVolumeState::Failed);
        assert!(!database_path.exists());
    }

    #[test]
    fn unknown_manifest_with_an_incomplete_database_resumes_initialization() {
        let temp = TempDir::new().unwrap();
        let external = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([88; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[external.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let external_id = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.path == external.path().canonicalize().unwrap())
            .unwrap()
            .volume_id;
        let external_store = volumes
            .volumes
            .get(&external_id)
            .unwrap()
            .store
            .as_ref()
            .unwrap();
        external_store
            .database_shell_statement("DROP TABLE parity_objects", false)
            .unwrap();
        external_store
            .database_shell_statement("DROP TABLE coding_reservations", false)
            .unwrap();
        external_store
            .database_shell_statement("DROP TABLE meta", false)
            .unwrap();
        let retained = volumes
            .volumes
            .values()
            .filter(|volume| volume.record.volume_id != external_id)
            .map(|volume| volume.record.clone())
            .collect::<Vec<_>>();
        store_volume_records(&control, &retained).unwrap();
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[external.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == external_id)
            .unwrap();
        assert_eq!(status.state, StorageVolumeState::Online);
        assert_eq!(status.object_count, Some(0));
    }

    #[test]
    fn physical_available_space_preserves_repair_headroom() {
        let temp = TempDir::new().unwrap();
        let volume = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([78; 32])));
        let object = parity_object(79, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(&control, &[volume.path().to_path_buf()], u64::MAX, 0)
            .unwrap();
        let available = fs2::available_space(volume.path()).unwrap();
        let required = physical_write_reservation(object.bytes.len(), b"ack".len());
        assert!(required > V1_SECTOR_SIZE as u64);
        assert!(available > required);
        volumes
            .configure(
                &control,
                &[volume.path().to_path_buf()],
                u64::MAX,
                u64::MAX - 1,
            )
            .unwrap();

        assert!(matches!(
            volumes.store(&control, &object, b"ack"),
            Err(error) if matches!(
                error.downcast_ref::<DatabaseError>(),
                Some(DatabaseError::CapacityExceeded)
            )
        ));
        let receipt = volumes.store_repair(&control, &object).unwrap();
        let status = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.volume_id == receipt.volume_id)
            .unwrap();
        assert_eq!(status.used_bytes, Some(V1_SECTOR_SIZE as u64));
        assert!(status.allocated_bytes.is_some());
        assert!(status.available_bytes.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn physical_reservation_preserves_headroom_after_many_shared_filesystem_writes() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = TempDir::new_in(test_root).unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([95; 32])));
        let acknowledgement = b"shared-filesystem-ack";
        let (control, control_database_key) = open_control_store(run_root.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(run_root.path(), keys, &control).unwrap();
        let volume_id = volumes
            .statuses()
            .unwrap()
            .into_iter()
            .find(|status| status.path == run_root.path().canonicalize().unwrap())
            .unwrap()
            .volume_id;
        let (parity_path, parity_database_key) = {
            let volume = volumes.volumes.get(&volume_id).unwrap();
            (
                volume.store.as_ref().unwrap().path().to_path_buf(),
                volume.database_key,
            )
        };
        let control_reader =
            ControlStore::open_with_key(control.path(), &control_database_key).unwrap();
        let parity_reader = ParityStore::open_existing_with_key(
            &parity_path,
            volume_id.as_bytes(),
            &parity_database_key,
        )
        .unwrap();
        control_reader
            .database_shell_statement("BEGIN", false)
            .unwrap();
        control_reader
            .database_shell_statement("SELECT count(*) FROM protocol_records", false)
            .unwrap();
        parity_reader
            .database_shell_statement("BEGIN", false)
            .unwrap();
        parity_reader
            .database_shell_statement("SELECT count(*) FROM parity_objects", false)
            .unwrap();
        for marker in 100_u8..180 {
            volumes
                .store(
                    &control,
                    &parity_object(marker, marker % 5),
                    acknowledgement,
                )
                .unwrap();
        }
        let object = parity_object(180, 4);
        let reservation = physical_write_reservation(object.bytes.len(), acknowledgement.len());
        let checkpoint_reservation = shared_checkpoint_reservation(
            &control,
            volumes
                .volumes
                .get(&volume_id)
                .unwrap()
                .store
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        assert!(checkpoint_reservation > (V1_SECTOR_SIZE * 40) as u64);
        let available_before = fs2::available_space(run_root.path()).unwrap();
        let required = reservation.saturating_add(checkpoint_reservation);
        assert!(available_before > required);
        let volume = volumes.volumes.get_mut(&volume_id).unwrap();
        volume.record.budget_bytes = u64::MAX;
        volume.record.headroom_bytes = available_before - reservation;
        assert!(matches!(
            volumes.store(&control, &object, acknowledgement),
            Err(error) if matches!(
                error.downcast_ref::<DatabaseError>(),
                Some(DatabaseError::CapacityExceeded)
            )
        ));

        let headroom = available_before - required;
        let volume = volumes.volumes.get_mut(&volume_id).unwrap();
        volume.record.headroom_bytes = headroom;
        control_reader
            .database_shell_statement("COMMIT", false)
            .unwrap();
        parity_reader
            .database_shell_statement("COMMIT", false)
            .unwrap();

        let receipt = volumes.store(&control, &object, acknowledgement).unwrap();

        assert_eq!(receipt.volume_id, volume_id);
        let available_after = fs2::available_space(run_root.path()).unwrap();
        assert!(
            available_after >= headroom,
            "physical write consumed {} bytes beyond its {}-byte reservation",
            headroom.saturating_sub(available_after),
            required,
        );
    }

    #[test]
    fn repaired_objects_migrate_without_storage_acknowledgements() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([72; 32])));
        let object = parity_object(73, 2);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let source = volumes.store_repair(&control, &object).unwrap();
        volumes.mark_draining(&control, source.volume_id).unwrap();

        assert_eq!(volumes.migrate_draining(&control).unwrap(), 1);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
    }

    #[test]
    fn returned_source_drains_into_an_existing_repaired_copy() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([91; 32])));
        let object = parity_object(92, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                V1_SECTOR_SIZE as u64,
                0,
            )
            .unwrap();
        let source = volumes.store(&control, &object, b"signed-ack").unwrap();
        let source_volume = volumes.volumes.get_mut(&source.volume_id).unwrap();
        let source_store = source_volume.store.take().unwrap();
        source_volume.record.state = StorageVolumeState::Offline;
        let repaired = volumes.store_repair(&control, &object).unwrap();
        assert_ne!(repaired.volume_id, source.volume_id);

        let source_volume = volumes.volumes.get_mut(&source.volume_id).unwrap();
        source_volume.store = Some(source_store);
        source_volume.record.state = StorageVolumeState::Online;
        source_volume.record.configured = true;
        volumes.mark_draining(&control, source.volume_id).unwrap();

        assert_eq!(volumes.migrate_draining(&control).unwrap(), 1);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert_eq!(
            volumes
                .receipt(&control, &object.group_id, object.shard_index)
                .unwrap()
                .unwrap()
                .volume_id,
            repaired.volume_id
        );
    }

    #[test]
    fn garbage_collection_removes_both_sides_of_interrupted_migration() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([93; 32])));
        let object = parity_object(94, 3);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let source = volumes.store(&control, &object, b"ack").unwrap();
        volumes.mark_draining(&control, source.volume_id).unwrap();
        interrupt_next_volume_transition(VolumeInterruption::MigrationDestinationStored);
        assert!(volumes.migrate_draining(&control).is_err());
        assert_eq!(
            volumes
                .volumes
                .values()
                .filter(|volume| {
                    volume.store.as_ref().is_some_and(|store| {
                        store
                            .load_ready(&object.group_id, object.shard_index)
                            .is_ok()
                    })
                })
                .count(),
            2
        );
        let source_path = volumes
            .volumes
            .get(&source.volume_id)
            .unwrap()
            .record
            .path
            .clone();
        let destination_path = volumes
            .volumes
            .values()
            .find(|volume| volume.record.volume_id != source.volume_id && volume.record.configured)
            .unwrap()
            .record
            .path
            .clone();
        drop(volumes);
        drop(control);
        let absent_source = temp.path().join("absent-draining-source");
        fs::rename(&source_path, &absent_source).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes
            .configure(
                &control,
                &[source_path.clone(), destination_path.clone()],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        let unavailable_source = volumes.volumes.get(&source.volume_id).unwrap();
        assert_eq!(
            unavailable_source.record.state,
            StorageVolumeState::Draining
        );
        assert!(unavailable_source.store.is_none());
        assert!(
            !volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert_eq!(control.records("volume-receipt").unwrap().len(), 1);
        assert_eq!(control.records("volume-copy-cleanup").unwrap().len(), 1);
        fs::rename(&absent_source, &source_path).unwrap();
        volumes
            .configure(
                &control,
                &[source_path, destination_path],
                (V1_SECTOR_SIZE * 2) as u64,
                0,
            )
            .unwrap();
        assert_eq!(
            volumes.volumes.get(&source.volume_id).unwrap().record.state,
            StorageVolumeState::Draining
        );
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert!(control.records("volume-receipt").unwrap().is_empty());
        assert!(control.records("volume-copy-cleanup").unwrap().is_empty());
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 0);
        assert!(matches!(
            volumes.load_ready(&object.group_id, object.shard_index),
            Err(error) if matches!(
                error.downcast_ref::<DatabaseError>(),
                Some(DatabaseError::NotReady)
            )
        ));
    }

    #[test]
    fn garbage_collection_waits_for_an_absent_pending_write_destination() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([53; 32])));
        let object = parity_object(54, 3);
        let configured = vec![first.path().to_path_buf(), second.path().to_path_buf()];
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(&control, &configured, (V1_SECTOR_SIZE * 2) as u64, 0)
            .unwrap();
        interrupt_next_volume_transition(VolumeInterruption::ObjectPublished);
        assert!(volumes.store(&control, &object, b"ack").is_err());
        let intent_bytes = control
            .records("volume-write-intent")
            .unwrap()
            .pop()
            .unwrap()
            .1;
        let intent: VolumeWriteIntent = decode_canonical(&intent_bytes).unwrap();
        let destination_path = volumes
            .volumes
            .get(&intent.receipt.volume_id)
            .unwrap()
            .record
            .path
            .clone();
        drop(volumes);
        drop(control);
        let absent_path = temp.path().join("absent-pending-destination");
        fs::rename(&destination_path, &absent_path).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes.reconcile(&control).unwrap();
        assert!(
            !volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert_eq!(control.records("volume-write-intent").unwrap().len(), 1);
        assert_eq!(control.records("volume-copy-cleanup").unwrap().len(), 1);
        drop(volumes);
        drop(control);

        fs::rename(&absent_path, &destination_path).unwrap();
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes.reconcile(&control).unwrap();
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert!(control.records("volume-write-intent").unwrap().is_empty());
        assert!(control.records("volume-receipt").unwrap().is_empty());
        assert!(control.records("volume-copy-cleanup").unwrap().is_empty());
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
    }

    #[test]
    fn retargeted_pending_write_retains_the_first_destination_for_cleanup() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([55; 32])));
        let object = parity_object(56, 4);
        let configured = vec![first.path().to_path_buf(), second.path().to_path_buf()];
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(&control, &configured, (V1_SECTOR_SIZE * 2) as u64, 0)
            .unwrap();
        interrupt_next_volume_transition(VolumeInterruption::ObjectPublished);
        assert!(volumes.store(&control, &object, b"ack").is_err());
        let intent_bytes = control
            .records("volume-write-intent")
            .unwrap()
            .pop()
            .unwrap()
            .1;
        let first_intent: VolumeWriteIntent = decode_canonical(&intent_bytes).unwrap();
        let first_path = volumes
            .volumes
            .get(&first_intent.receipt.volume_id)
            .unwrap()
            .record
            .path
            .clone();
        drop(volumes);
        drop(control);
        let absent_path = temp.path().join("absent-first-write-destination");
        fs::rename(&first_path, &absent_path).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes.reconcile(&control).unwrap();
        let replacement = volumes.store_repair(&control, &object).unwrap();
        assert_ne!(replacement.volume_id, first_intent.receipt.volume_id);
        let cleanup = volumes
            .cleanup_volumes(&control, &object.group_id, object.shard_index)
            .unwrap();
        assert!(cleanup.contains(&first_intent.receipt.volume_id));
        assert!(
            !volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert!(control.records("volume-copy-cleanup").unwrap().len() == 1);
        drop(volumes);
        drop(control);

        fs::rename(&absent_path, &first_path).unwrap();
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
        assert!(control.records("volume-copy-cleanup").unwrap().is_empty());
        assert!(control.records("volume-receipt").unwrap().is_empty());
    }

    #[test]
    fn migration_reuses_an_exactly_full_committed_destination() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([74; 32])));
        let object = parity_object(75, 3);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                V1_SECTOR_SIZE as u64,
                0,
            )
            .unwrap();
        let source = volumes.store(&control, &object, b"ack").unwrap();
        volumes.mark_draining(&control, source.volume_id).unwrap();
        interrupt_next_volume_transition(VolumeInterruption::MigrationDestinationStored);
        assert!(volumes.migrate_draining(&control).is_err());
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes.reconcile(&control).unwrap();
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 1);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
    }

    #[test]
    fn volume_writes_converge_after_every_cross_database_transition() {
        let points = [
            VolumeInterruption::WriteIntentStored,
            VolumeInterruption::ObjectPublished,
            VolumeInterruption::ReceiptStored,
            VolumeInterruption::WriteIntentRetired,
        ];
        for (index, point) in points.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes(
                [70 + index as u8; 32],
            )));
            let object = parity_object(80 + index as u8, 3);
            let (control, _) = open_control_store(temp.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
            interrupt_next_volume_transition(point);
            assert!(
                volumes
                    .store(&control, &object, b"durable-ack")
                    .unwrap_err()
                    .to_string()
                    .contains("injected interruption")
            );
            drop(volumes);
            drop(control);

            let (control, _) = open_control_store(temp.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
            volumes.reconcile(&control).unwrap();
            volumes.store(&control, &object, b"durable-ack").unwrap();
            assert_eq!(
                volumes
                    .load_ready(&object.group_id, object.shard_index)
                    .unwrap(),
                object
            );
            assert!(control.records("volume-write-intent").unwrap().is_empty());
            assert_eq!(control.records("volume-receipt").unwrap().len(), 1);
        }
    }

    #[test]
    fn draining_migration_converges_after_every_cross_database_transition() {
        let points = [
            VolumeInterruption::MigrationSourceReceiptRetired,
            VolumeInterruption::MigrationDestinationStored,
            VolumeInterruption::MigrationSourceRemoved,
            VolumeInterruption::MigrationReceiptStored,
            VolumeInterruption::MigrationStateStored,
        ];
        for (index, point) in points.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let first = TempDir::new().unwrap();
            let second = TempDir::new().unwrap();
            let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes(
                [90 + index as u8; 32],
            )));
            let object = parity_object(100 + index as u8, 3);
            let (control, _) = open_control_store(temp.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
            volumes
                .configure(
                    &control,
                    &[first.path().to_path_buf(), second.path().to_path_buf()],
                    (V1_SECTOR_SIZE * 2) as u64,
                    V1_SECTOR_SIZE as u64 / 2,
                )
                .unwrap();
            let source = volumes.store(&control, &object, b"migration-ack").unwrap();
            volumes.mark_draining(&control, source.volume_id).unwrap();
            interrupt_next_volume_transition(point);
            assert!(
                volumes
                    .migrate_draining(&control)
                    .unwrap_err()
                    .to_string()
                    .contains("injected interruption")
            );
            drop(volumes);
            drop(control);

            let (control, _) = open_control_store(temp.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
            volumes.reconcile(&control).unwrap();
            volumes.migrate_draining(&control).unwrap();
            assert_eq!(
                volumes
                    .load_ready(&object.group_id, object.shard_index)
                    .unwrap(),
                object
            );
            let receipt = volumes
                .receipt(&control, &object.group_id, object.shard_index)
                .unwrap()
                .unwrap();
            assert_ne!(receipt.volume_id, source.volume_id);
            let statuses = volumes.statuses().unwrap();
            assert_eq!(
                statuses
                    .iter()
                    .find(|status| status.volume_id == source.volume_id)
                    .unwrap()
                    .state,
                StorageVolumeState::Retired
            );
            assert_eq!(
                statuses
                    .iter()
                    .filter(|status| status.state == StorageVolumeState::Online)
                    .filter_map(|status| status.object_count)
                    .sum::<u64>(),
                1
            );
            assert!(control.records("volume-copy-cleanup").unwrap().is_empty());
        }
    }

    #[test]
    fn empty_drain_settles_pending_and_preexisting_retired_location_evidence() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([116; 32])));
        let object = parity_object(117, 3);
        let record_id = volume_object_id(&object.group_id, object.shard_index);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        interrupt_next_volume_transition(VolumeInterruption::WriteIntentStored);
        assert!(volumes.store_repair(&control, &object).is_err());
        let intent_bytes = control
            .get_record("volume-write-intent", &record_id)
            .unwrap()
            .unwrap();
        let intent: VolumeWriteIntent = decode_canonical(&intent_bytes).unwrap();
        let retired_id = intent.receipt.volume_id;
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes.reconcile(&control).unwrap();
        volumes.mark_draining(&control, retired_id).unwrap();
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 0);
        assert!(control.records("volume-write-intent").unwrap().is_empty());
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );

        // Older versions could already have persisted Retired before clearing
        // these records. Reconciliation must converge that durable state too.
        control
            .put_record("volume-write-intent", &record_id, &intent_bytes)
            .unwrap();
        control
            .put_record(
                "volume-receipt",
                &record_id,
                &canonical_bytes(&intent.receipt).unwrap(),
            )
            .unwrap();
        control
            .put_record(
                "volume-copy-cleanup",
                &record_id,
                &canonical_bytes(&vec![retired_id]).unwrap(),
            )
            .unwrap();
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        volumes.reconcile(&control).unwrap();
        for kind in [
            "volume-write-intent",
            "volume-receipt",
            "volume-copy-cleanup",
        ] {
            assert!(control.records(kind).unwrap().is_empty(), "{kind}");
        }
    }

    #[test]
    fn empty_drain_settles_receipt_left_after_garbage_removal() {
        let temp = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([118; 32])));
        let object = parity_object(119, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        let receipt = volumes.store(&control, &object, b"gc-ack").unwrap();
        interrupt_next_volume_transition(VolumeInterruption::GarbageObjectRemoved);
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .is_err()
        );
        assert_eq!(control.records("volume-receipt").unwrap().len(), 1);

        volumes.mark_draining(&control, receipt.volume_id).unwrap();
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 0);
        assert!(control.records("volume-receipt").unwrap().is_empty());
        assert!(
            volumes
                .remove_unreachable(&control, &object.group_id, object.shard_index, &object.root,)
                .unwrap()
        );
    }

    #[test]
    fn garbage_collection_converges_after_every_cross_database_transition() {
        let points = [
            VolumeInterruption::GarbageObjectRemoved,
            VolumeInterruption::GarbageReceiptRetired,
        ];
        for (index, point) in points.into_iter().enumerate() {
            let temp = TempDir::new().unwrap();
            let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes(
                [110 + index as u8; 32],
            )));
            let object = parity_object(120 + index as u8, 4);
            let (control, _) = open_control_store(temp.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
            volumes.store(&control, &object, b"gc-ack").unwrap();
            interrupt_next_volume_transition(point);
            assert!(
                volumes
                    .remove_unreachable(
                        &control,
                        &object.group_id,
                        object.shard_index,
                        &object.root,
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("injected interruption")
            );
            drop(volumes);
            drop(control);

            let (control, _) = open_control_store(temp.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
            volumes.reconcile(&control).unwrap();
            assert!(
                volumes
                    .remove_unreachable(
                        &control,
                        &object.group_id,
                        object.shard_index,
                        &object.root,
                    )
                    .unwrap()
            );
            assert!(matches!(
                volumes.load_ready(&object.group_id, object.shard_index),
                Err(error) if matches!(
                    error.downcast_ref::<DatabaseError>(),
                    Some(DatabaseError::NotReady)
                )
            ));
            assert!(control.records("volume-receipt").unwrap().is_empty());
        }
    }

    #[test]
    fn repaired_attempt_receipt_retires_after_partial_cleanup_and_reopen() {
        let data = TempDir::new().unwrap();
        let original = TempDir::new().unwrap();
        let replacement = TempDir::new().unwrap();
        let original_path = original.path().to_path_buf();
        let offline_path = original_path.with_extension("offline");
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([150; 32])));
        let original_attempt = [151; 16];
        let repair_attempt = [152; 16];
        let verification_hash = [153; 32];
        let bytes = vec![154; 64];
        let object = VariableParityObject {
            format_version: 2,
            guild_id: [155; 32],
            group_id: [156; 32],
            shard_index: 4,
            commitment: mb_core::merkle_commit(&bytes).unwrap(),
            bytes,
        };
        let repair_receipt_id = attempt_volume_object_id(&repair_attempt, &object.group_id, 4);

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                std::slice::from_ref(&original_path),
                1024 * 1024,
                0,
            )
            .unwrap();
        volumes
            .stage_attempt(&control, &original_attempt, &object, b"old")
            .unwrap();
        volumes
            .activate_attempt_object(
                &control,
                &original_attempt,
                &object.group_id,
                4,
                &object.commitment,
                &verification_hash,
            )
            .unwrap();
        volumes
            .finalize_attempt(&control, &original_attempt)
            .unwrap();
        drop(volumes);
        drop(control);
        fs::rename(&original_path, &offline_path).unwrap();

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[replacement.path().to_path_buf()],
                1024 * 1024,
                0,
            )
            .unwrap();
        assert!(!volumes.prepare_variable_repair(&control, &object).unwrap());
        volumes
            .reserve_attempt(&control, &repair_attempt, object.guild_id, 4, 64)
            .unwrap();
        volumes
            .write_attempt_range(&control, &repair_attempt, 4, 0, &object.bytes)
            .unwrap();
        volumes
            .finish_attempt_upload(
                &control,
                &repair_attempt,
                object.group_id,
                4,
                &object.commitment,
            )
            .unwrap();
        volumes
            .attach_attempt_receipt(
                &control,
                &repair_attempt,
                &object.group_id,
                4,
                &verification_hash,
            )
            .unwrap();
        volumes
            .activate_attempt_object(
                &control,
                &repair_attempt,
                &object.group_id,
                4,
                &object.commitment,
                &verification_hash,
            )
            .unwrap();
        interrupt_next_volume_transition(VolumeInterruption::GarbageObjectRemoved);
        assert!(
            volumes
                .remove_unreachable_for_attempt(
                    &control,
                    &original_attempt,
                    &verification_hash,
                    &object.group_id,
                    4,
                    &object.commitment.root,
                )
                .is_err()
        );
        assert!(
            control
                .get_record("volume-attempt-receipt", &repair_receipt_id)
                .unwrap()
                .is_some()
        );
        assert!(
            !control
                .records("volume-attempt-retirement")
                .unwrap()
                .is_empty()
        );
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        assert!(
            !volumes
                .remove_unreachable_for_attempt(
                    &control,
                    &original_attempt,
                    &verification_hash,
                    &object.group_id,
                    4,
                    &object.commitment.root,
                )
                .unwrap()
        );
        assert!(
            control
                .get_record("volume-attempt-receipt", &repair_receipt_id)
                .unwrap()
                .is_none()
        );
        assert!(
            control
                .records("volume-attempt-retirement")
                .unwrap()
                .is_empty()
        );
        drop(volumes);
        drop(control);
        fs::rename(&offline_path, &original_path).unwrap();

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[original_path, replacement.path().to_path_buf()],
                1024 * 1024,
                0,
            )
            .unwrap();
        assert!(
            volumes
                .remove_unreachable_for_attempt(
                    &control,
                    &original_attempt,
                    &verification_hash,
                    &object.group_id,
                    4,
                    &object.commitment.root,
                )
                .unwrap()
        );
        assert!(
            control
                .records("volume-attempt-receipt")
                .unwrap()
                .is_empty()
        );
        assert!(control.records("volume-copy-cleanup").unwrap().is_empty());
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(data.path(), keys, &control).unwrap();
        assert!(
            volumes
                .load_ready_variable(&control, &object.group_id, 4)
                .is_err()
        );
    }

    #[test]
    fn completed_coding_upload_retry_verifies_bytes_and_retires_interrupted_reservation() {
        let data = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([199; 32])));
        let attempt = [200; 16];
        let guild = [201; 32];
        let group = [202; 32];
        let bytes = vec![203; 64];
        let commitment = mb_core::merkle_commit(&bytes).unwrap();
        let shard = 4;
        let reservation_id = attempt_reservation_id(&attempt, shard);
        let object_id = attempt_volume_object_id(&attempt, &group, shard);
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .reserve_attempt(&control, &attempt, guild, shard.into(), 64)
            .unwrap();
        volumes
            .write_attempt_range(&control, &attempt, shard.into(), 0, &bytes)
            .unwrap();
        let reservation_bytes = control
            .get_record("volume-attempt-reservation", &reservation_id)
            .unwrap()
            .unwrap();
        interrupt_next_volume_transition(VolumeInterruption::CodingUploadReceiptStored);
        assert!(
            volumes
                .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
                .is_err()
        );
        assert_eq!(
            control
                .get_record("volume-attempt-reservation", &reservation_id)
                .unwrap(),
            Some(reservation_bytes.clone())
        );
        let receipt_bytes = control
            .get_record("volume-attempt-receipt", &object_id)
            .unwrap()
            .unwrap();
        let stored: AttemptVolumeRecord = decode_canonical(&receipt_bytes).unwrap();
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys, &control).unwrap();
        let receipt = volumes
            .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
            .unwrap();
        assert_eq!(receipt, stored.receipt);
        assert!(
            control
                .get_record("volume-attempt-reservation", &reservation_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            control
                .get_record("volume-attempt-receipt", &object_id)
                .unwrap(),
            Some(receipt_bytes.clone())
        );
        assert_eq!(
            volumes.volumes[&receipt.volume_id]
                .store
                .as_ref()
                .unwrap()
                .used_bytes()
                .unwrap(),
            64
        );
        volumes
            .attach_attempt_receipt(
                &control,
                &attempt,
                &group,
                shard.into(),
                b"signed staged receipt",
            )
            .unwrap();
        volumes
            .activate_attempt_object(
                &control,
                &attempt,
                &group,
                shard.into(),
                &commitment,
                &[204; 32],
            )
            .unwrap();
        assert_eq!(
            volumes
                .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
                .unwrap(),
            receipt
        );
        assert_eq!(
            volumes
                .load_ready_variable(&control, &group, shard.into())
                .unwrap()
                .bytes,
            bytes
        );

        // A completed receipt alone cannot certify missing physical storage.
        // Preserve all control evidence when revalidation fails.
        control
            .put_record(
                "volume-attempt-reservation",
                &reservation_id,
                &reservation_bytes,
            )
            .unwrap();
        volumes
            .volumes
            .get_mut(&receipt.volume_id)
            .unwrap()
            .store
            .as_mut()
            .unwrap()
            .remove_ready(&group, shard, &commitment.root)
            .unwrap();
        assert!(
            volumes
                .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
                .is_err()
        );
        assert_eq!(
            control
                .get_record("volume-attempt-reservation", &reservation_id)
                .unwrap(),
            Some(reservation_bytes)
        );
        assert_eq!(
            control
                .get_record("volume-attempt-receipt", &object_id)
                .unwrap(),
            Some(receipt_bytes)
        );
    }

    #[test]
    fn completed_coding_upload_keeps_conflicting_reservation_and_offline_evidence() {
        let data = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([205; 32])));
        let attempt = [206; 16];
        let guild = [207; 32];
        let group = [208; 32];
        let bytes = vec![209; 64];
        let commitment = mb_core::merkle_commit(&bytes).unwrap();
        let shard = 4;
        let reservation_id = attempt_reservation_id(&attempt, shard);
        let object_id = attempt_volume_object_id(&attempt, &group, shard);
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys, &control).unwrap();
        volumes
            .reserve_attempt(&control, &attempt, guild, shard.into(), 64)
            .unwrap();
        volumes
            .write_attempt_range(&control, &attempt, shard.into(), 0, &bytes)
            .unwrap();
        let reservation_bytes = control
            .get_record("volume-attempt-reservation", &reservation_id)
            .unwrap()
            .unwrap();
        let mut reservation: AttemptReservationRecord =
            decode_canonical(&reservation_bytes).unwrap();
        let receipt = volumes
            .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
            .unwrap();
        let receipt_bytes = control
            .get_record("volume-attempt-receipt", &object_id)
            .unwrap()
            .unwrap();
        reservation.byte_length = 128;
        let conflicting = canonical_bytes(&reservation).unwrap();
        control
            .put_record("volume-attempt-reservation", &reservation_id, &conflicting)
            .unwrap();
        assert!(
            volumes
                .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
                .is_err()
        );
        assert_eq!(
            control
                .get_record("volume-attempt-reservation", &reservation_id)
                .unwrap(),
            Some(conflicting)
        );
        assert_eq!(
            volumes.volumes[&receipt.volume_id]
                .store
                .as_ref()
                .unwrap()
                .used_bytes()
                .unwrap(),
            64
        );
        control
            .put_record(
                "volume-attempt-reservation",
                &reservation_id,
                &reservation_bytes,
            )
            .unwrap();
        volumes.volumes.get_mut(&receipt.volume_id).unwrap().store = None;
        assert!(
            volumes
                .finish_attempt_upload(&control, &attempt, group, shard.into(), &commitment)
                .is_err()
        );
        assert_eq!(
            control
                .get_record("volume-attempt-reservation", &reservation_id)
                .unwrap(),
            Some(reservation_bytes)
        );
        assert_eq!(
            control
                .get_record("volume-attempt-receipt", &object_id)
                .unwrap(),
            Some(receipt_bytes)
        );
    }

    struct VariableDrainFixture {
        data: TempDir,
        source: TempDir,
        destination: TempDir,
        keys: Arc<KeyMaterial>,
        control: ControlStore,
        volumes: StorageVolumes,
        object: VariableParityObject,
        source_receipt: VolumeReceipt,
        attempt: [u8; 16],
        verification: [u8; 32],
    }

    impl VariableDrainFixture {
        fn new(shard: u16) -> Self {
            let data = TempDir::new().unwrap();
            let source = TempDir::new().unwrap();
            let destination = TempDir::new().unwrap();
            let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([211; 32])));
            let attempt = [212; 16];
            let verification = [213; 32];
            let bytes = vec![214; 64];
            let object = VariableParityObject {
                format_version: 2,
                guild_id: [215; 32],
                group_id: [216; 32],
                shard_index: shard,
                commitment: mb_core::merkle_commit(&bytes).unwrap(),
                bytes,
            };
            let (control, _) = open_control_store(data.path(), &keys).unwrap();
            let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
            volumes
                .configure(&control, &[source.path().to_path_buf()], 1024, 0)
                .unwrap();
            let source_receipt = volumes
                .stage_attempt(&control, &attempt, &object, b"signed original receipt")
                .unwrap();
            volumes
                .activate_attempt_object(
                    &control,
                    &attempt,
                    &object.group_id,
                    shard,
                    &object.commitment,
                    &verification,
                )
                .unwrap();
            volumes
                .configure(
                    &control,
                    &[
                        source.path().to_path_buf(),
                        destination.path().to_path_buf(),
                    ],
                    1024,
                    0,
                )
                .unwrap();
            volumes
                .mark_draining(&control, source_receipt.volume_id)
                .unwrap();
            Self {
                data,
                source,
                destination,
                keys,
                control,
                volumes,
                object,
                source_receipt,
                attempt,
                verification,
            }
        }

        fn destination_id(&self) -> Uuid {
            self.volumes
                .volumes
                .values()
                .find(|v| v.record.path == self.destination.path())
                .unwrap()
                .record
                .volume_id
        }

        fn reopen(self) -> Self {
            let Self {
                data,
                source,
                destination,
                keys,
                control,
                volumes,
                object,
                source_receipt,
                attempt,
                verification,
            } = self;
            drop(volumes);
            drop(control);
            let (control, _) = open_control_store(data.path(), &keys).unwrap();
            let volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
            Self {
                data,
                source,
                destination,
                keys,
                control,
                volumes,
                object,
                source_receipt,
                attempt,
                verification,
            }
        }

        fn assert_readable(&self) {
            assert_eq!(
                self.volumes
                    .load_ready_variable(
                        &self.control,
                        &self.object.group_id,
                        self.object.shard_index
                    )
                    .unwrap(),
                self.object
            );
        }
    }

    #[test]
    fn variable_migration_converges_after_every_publication_boundary() {
        for shard in [0, 4] {
            for point in [
                VolumeInterruption::VariableMigrationIntentStored,
                VolumeInterruption::VariableMigrationDestinationReady,
                VolumeInterruption::VariableMigrationReceiptStored,
                VolumeInterruption::VariableMigrationSourceRemoved,
                VolumeInterruption::VariableMigrationIntentRetired,
                VolumeInterruption::MigrationStateStored,
            ] {
                let mut f = VariableDrainFixture::new(shard);
                let original = f.volumes.volumes[&f.source_receipt.volume_id]
                    .store
                    .as_ref()
                    .unwrap()
                    .load_ready_variable_object(&f.object.group_id, shard)
                    .unwrap();
                interrupt_next_volume_transition(point);
                assert!(
                    f.volumes
                        .migrate_draining(&f.control)
                        .unwrap_err()
                        .to_string()
                        .contains("injected interruption"),
                    "{point:?}"
                );
                f.assert_readable();
                f = f.reopen();
                f.volumes.reconcile(&f.control).unwrap();
                f.volumes.migrate_draining(&f.control).unwrap();
                f.assert_readable();
                assert_eq!(
                    f.volumes.volumes[&f.source_receipt.volume_id].record.state,
                    StorageVolumeState::Retired
                );
                let receipt = f
                    .volumes
                    .receipt(&f.control, &f.object.group_id, shard as u8)
                    .unwrap()
                    .unwrap();
                assert_ne!(receipt.volume_id, f.source_receipt.volume_id);
                assert_eq!(
                    f.volumes.volumes[&receipt.volume_id]
                        .store
                        .as_ref()
                        .unwrap()
                        .load_ready_variable_object(&f.object.group_id, shard)
                        .unwrap(),
                    original
                );
                assert!(
                    f.control
                        .records(VARIABLE_MIGRATION_KIND)
                        .unwrap()
                        .is_empty()
                );
                assert!(f.control.records("volume-copy-cleanup").unwrap().is_empty());
                let pending: AttemptVolumeRecord = decode_canonical(
                    &f.control
                        .get_record(
                            "volume-attempt-receipt",
                            &attempt_volume_object_id(&f.attempt, &f.object.group_id, shard as u8),
                        )
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(pending.receipt, receipt);
                f.volumes.finalize_attempt(&f.control, &f.attempt).unwrap();
                fs::remove_dir_all(f.source.path()).unwrap();
                f = f.reopen();
                f.assert_readable();
            }
        }
    }

    #[test]
    fn variable_migration_preserves_source_when_destination_is_full_or_offline() {
        for offline in [false, true] {
            let mut f = VariableDrainFixture::new(4);
            let id = f.destination_id();
            if offline {
                f.volumes.volumes.get_mut(&id).unwrap().store = None;
            } else {
                f.volumes
                    .volumes
                    .get_mut(&id)
                    .unwrap()
                    .store
                    .as_mut()
                    .unwrap()
                    .reserve_coding_attempt(&[217; 16], &f.object.guild_id, 9, 1024, 1024)
                    .unwrap();
            }
            assert!(f.volumes.migrate_draining(&f.control).is_err());
            f.assert_readable();
            assert_eq!(
                f.volumes
                    .receipt(&f.control, &f.object.group_id, 4)
                    .unwrap(),
                Some(f.source_receipt.clone())
            );
            assert!(
                f.control
                    .records(VARIABLE_MIGRATION_KIND)
                    .unwrap()
                    .is_empty()
            );
            if !offline {
                f = f.reopen();
                assert!(f.volumes.migrate_draining(&f.control).is_err());
                f.assert_readable();
                f.volumes
                    .volumes
                    .get_mut(&id)
                    .unwrap()
                    .store
                    .as_mut()
                    .unwrap()
                    .discard_uncommitted_attempt(&[217; 16])
                    .unwrap();
                assert_eq!(f.volumes.migrate_draining(&f.control).unwrap(), 1);
                f.assert_readable();
            }
        }
    }

    #[test]
    fn variable_migration_gc_cancels_each_boundary_without_resurrection() {
        for point in [
            VolumeInterruption::VariableMigrationIntentStored,
            VolumeInterruption::VariableMigrationDestinationReady,
            VolumeInterruption::VariableMigrationReceiptStored,
            VolumeInterruption::VariableMigrationSourceRemoved,
        ] {
            let mut f = VariableDrainFixture::new(4);
            interrupt_next_volume_transition(point);
            assert!(f.volumes.migrate_draining(&f.control).is_err());
            assert!(
                f.volumes
                    .remove_unreachable_for_attempt(
                        &f.control,
                        &f.attempt,
                        &f.verification,
                        &f.object.group_id,
                        4,
                        &f.object.commitment.root
                    )
                    .unwrap(),
                "{point:?}"
            );
            f = f.reopen();
            f.volumes.reconcile(&f.control).unwrap();
            f.volumes.migrate_draining(&f.control).unwrap();
            assert!(
                f.volumes
                    .load_ready_variable(&f.control, &f.object.group_id, 4)
                    .is_err()
            );
            assert!(
                f.control
                    .records(VARIABLE_MIGRATION_KIND)
                    .unwrap()
                    .is_empty()
            );
            assert!(f.control.records("volume-copy-cleanup").unwrap().is_empty());
            assert!(
                f.control
                    .records("volume-attempt-retirement")
                    .unwrap()
                    .is_empty()
            );
            assert!(
                f.control
                    .records("volume-attempt-receipt")
                    .unwrap()
                    .is_empty()
            );
        }
    }

    #[test]
    fn variable_migration_abort_cancels_copies_and_preserves_information() {
        for preserve in [false, true] {
            for point in [
                VolumeInterruption::VariableMigrationIntentStored,
                VolumeInterruption::VariableMigrationDestinationReady,
                VolumeInterruption::VariableMigrationReceiptStored,
                VolumeInterruption::VariableMigrationSourceRemoved,
            ] {
                let mut f = VariableDrainFixture::new(0);
                interrupt_next_volume_transition(point);
                assert!(f.volumes.migrate_draining(&f.control).is_err());
                let retained = if preserve {
                    BTreeSet::from([(f.object.group_id, 0)])
                } else {
                    BTreeSet::new()
                };
                assert!(
                    f.volumes
                        .discard_attempt(&f.control, &f.attempt, &retained)
                        .unwrap()
                );
                f = f.reopen();
                f.volumes.reconcile(&f.control).unwrap();
                f.volumes.migrate_draining(&f.control).unwrap();
                assert!(
                    f.control
                        .records(VARIABLE_MIGRATION_KIND)
                        .unwrap()
                        .is_empty()
                );
                assert!(f.control.records("volume-copy-cleanup").unwrap().is_empty());
                if preserve {
                    f.assert_readable();
                } else {
                    assert!(
                        f.volumes
                            .load_ready_variable(&f.control, &f.object.group_id, 0)
                            .is_err()
                    );
                    assert!(f.control.records("volume-receipt").unwrap().is_empty());
                }
            }
        }
    }

    #[test]
    fn variable_migration_reuses_authoritative_repair_without_replacing_its_evidence() {
        let mut f = VariableDrainFixture::new(4);
        f.volumes.finalize_attempt(&f.control, &f.attempt).unwrap();
        let repair = [218; 16];
        let destination = f
            .volumes
            .stage_attempt(&f.control, &repair, &f.object, b"new repaired receipt")
            .unwrap();
        f.volumes
            .activate_attempt_object(
                &f.control,
                &repair,
                &f.object.group_id,
                4,
                &f.object.commitment,
                &f.verification,
            )
            .unwrap();
        f.volumes.finalize_attempt(&f.control, &repair).unwrap();
        let original = f.volumes.volumes[&destination.volume_id]
            .store
            .as_ref()
            .unwrap()
            .load_ready_variable_object(&f.object.group_id, 4)
            .unwrap();
        f.volumes
            .volumes
            .get_mut(&destination.volume_id)
            .unwrap()
            .record
            .budget_bytes = 64;
        assert_eq!(f.volumes.migrate_draining(&f.control).unwrap(), 1);
        assert_eq!(
            f.volumes
                .receipt(&f.control, &f.object.group_id, 4)
                .unwrap(),
            Some(destination.clone())
        );
        assert_eq!(
            f.volumes.volumes[&destination.volume_id]
                .store
                .as_ref()
                .unwrap()
                .load_ready_variable_object(&f.object.group_id, 4)
                .unwrap(),
            original
        );
        f = f.reopen();
        f.assert_readable();
    }

    #[test]
    fn variable_migration_cancelled_offline_copy_remains_owned_until_reopen_cleanup() {
        for garbage in [false, true] {
            for source_offline in [false, true] {
                let mut f = VariableDrainFixture::new(4);
                interrupt_next_volume_transition(
                    VolumeInterruption::VariableMigrationDestinationReady,
                );
                assert!(f.volumes.migrate_draining(&f.control).is_err());
                let offline = if source_offline {
                    f.source_receipt.volume_id
                } else {
                    f.destination_id()
                };
                f.volumes.volumes.get_mut(&offline).unwrap().store = None;
                if garbage {
                    assert!(
                        !f.volumes
                            .remove_unreachable_for_attempt(
                                &f.control,
                                &f.attempt,
                                &f.verification,
                                &f.object.group_id,
                                4,
                                &f.object.commitment.root
                            )
                            .unwrap()
                    );
                } else {
                    assert!(
                        !f.volumes
                            .discard_attempt(&f.control, &f.attempt, &BTreeSet::new())
                            .unwrap()
                    );
                }
                let record = f
                    .control
                    .records(VARIABLE_MIGRATION_KIND)
                    .unwrap()
                    .pop()
                    .unwrap();
                let intent: VariableVolumeMigration = decode_canonical(&record.1).unwrap();
                assert!(intent.cancelled);
                f = f.reopen();
                f.volumes.reconcile(&f.control).unwrap();
                assert!(f.volumes.migrate_draining(&f.control).is_err());
                if garbage {
                    assert!(
                        f.volumes
                            .remove_unreachable_for_attempt(
                                &f.control,
                                &f.attempt,
                                &f.verification,
                                &f.object.group_id,
                                4,
                                &f.object.commitment.root
                            )
                            .unwrap()
                    );
                } else {
                    assert!(
                        f.volumes
                            .discard_attempt(&f.control, &f.attempt, &BTreeSet::new())
                            .unwrap()
                    );
                }
                f.volumes.migrate_draining(&f.control).unwrap();
                assert!(
                    f.control
                        .records(VARIABLE_MIGRATION_KIND)
                        .unwrap()
                        .is_empty()
                );
                assert!(f.control.records("volume-copy-cleanup").unwrap().is_empty());
                assert!(
                    f.volumes
                        .load_ready_variable(&f.control, &f.object.group_id, 4)
                        .is_err()
                );
            }
        }
    }

    #[test]
    fn variable_migration_rejects_replaced_source_and_old_gc_preserves_successor() {
        let mut f = VariableDrainFixture::new(4);
        interrupt_next_volume_transition(VolumeInterruption::VariableMigrationDestinationReady);
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        let source = f
            .volumes
            .volumes
            .get_mut(&f.source_receipt.volume_id)
            .unwrap()
            .store
            .as_mut()
            .unwrap();
        source
            .remove_ready_variable_object(
                &f.object.group_id,
                4,
                &f.object.commitment.root,
                &f.attempt,
                &f.verification,
            )
            .unwrap();
        source
            .stage_attempt(&[220; 16], &f.object, b"successor signed receipt", 1024)
            .unwrap();
        source
            .activate_attempt_object(
                &[220; 16],
                &f.object.group_id,
                4,
                &f.object.commitment,
                &[221; 32],
            )
            .unwrap();
        let successor = source
            .load_ready_variable_object(&f.object.group_id, 4)
            .unwrap();
        f = f.reopen();
        f.volumes.reconcile(&f.control).unwrap();
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        assert_eq!(
            f.volumes
                .receipt(&f.control, &f.object.group_id, 4)
                .unwrap(),
            Some(f.source_receipt.clone())
        );
        assert_eq!(
            f.volumes.volumes[&f.source_receipt.volume_id]
                .store
                .as_ref()
                .unwrap()
                .load_ready_variable_object(&f.object.group_id, 4)
                .unwrap(),
            successor
        );
        assert!(
            f.volumes
                .remove_unreachable_for_attempt(
                    &f.control,
                    &f.attempt,
                    &f.verification,
                    &f.object.group_id,
                    4,
                    &f.object.commitment.root
                )
                .unwrap()
        );
        assert_eq!(
            f.volumes.volumes[&f.source_receipt.volume_id]
                .store
                .as_ref()
                .unwrap()
                .load_ready_variable_object(&f.object.group_id, 4)
                .unwrap(),
            successor
        );
        assert!(
            f.control
                .records(VARIABLE_MIGRATION_KIND)
                .unwrap()
                .is_empty()
        );
        f.assert_readable();
    }

    #[test]
    fn variable_migration_waits_for_staged_and_control_only_reservations() {
        for staged in [false, true] {
            let mut f = VariableDrainFixture::new(4);
            let pending_attempt = [222; 16];
            let pending_group = [223; 32];
            let pending_object = VariableParityObject {
                group_id: pending_group,
                shard_index: 5,
                ..f.object.clone()
            };
            let source = f
                .volumes
                .volumes
                .get_mut(&f.source_receipt.volume_id)
                .unwrap()
                .store
                .as_mut()
                .unwrap();
            if staged {
                source
                    .stage_attempt(
                        &pending_attempt,
                        &pending_object,
                        b"pending staged receipt",
                        1024,
                    )
                    .unwrap();
                let record = AttemptVolumeRecord {
                    format_version: 1,
                    attempt_id: pending_attempt,
                    receipt: VolumeReceipt {
                        group_id: pending_group,
                        shard_index: 5,
                        ..f.source_receipt.clone()
                    },
                };
                f.control
                    .put_record(
                        "volume-attempt-receipt",
                        &attempt_volume_object_id(&pending_attempt, &pending_group, 5),
                        &canonical_bytes(&record).unwrap(),
                    )
                    .unwrap();
            } else {
                // Physical completion/abort can precede control retirement.
                let record = AttemptReservationRecord {
                    format_version: 1,
                    attempt_id: pending_attempt,
                    volume_id: f.source_receipt.volume_id,
                    guild_id: f.object.guild_id,
                    shard_index: 5,
                    byte_length: 64,
                };
                f.control
                    .put_record(
                        "volume-attempt-reservation",
                        &attempt_reservation_id(&pending_attempt, 5),
                        &canonical_bytes(&record).unwrap(),
                    )
                    .unwrap();
            }
            assert!(f.volumes.migrate_draining(&f.control).is_err());
            assert_eq!(
                f.volumes.volumes[&f.source_receipt.volume_id].record.state,
                StorageVolumeState::Draining
            );
            f.assert_readable();
            f = f.reopen();
            assert!(f.volumes.migrate_draining(&f.control).is_err());
            assert!(
                f.volumes
                    .discard_attempt(&f.control, &pending_attempt, &BTreeSet::new())
                    .unwrap()
            );
            f.volumes.migrate_draining(&f.control).unwrap();
            assert_eq!(
                f.volumes.volumes[&f.source_receipt.volume_id].record.state,
                StorageVolumeState::Retired
            );
            f.assert_readable();
        }
    }
    #[test]
    fn variable_migration_refuses_headroom_and_invalid_intent_before_publication() {
        for physical in [false, true] {
            let mut f = VariableDrainFixture::new(4);
            let id = f.destination_id();
            let volume = f.volumes.volumes.get_mut(&id).unwrap();
            if physical {
                volume.record.budget_bytes = u64::MAX;
                volume.record.headroom_bytes = fs2::available_space(&volume.record.path)
                    .unwrap()
                    .saturating_add(1);
            } else {
                volume.record.budget_bytes = 64;
                volume.record.headroom_bytes = 1;
            }
            assert!(f.volumes.migrate_draining(&f.control).is_err());
            f.assert_readable();
            assert!(
                f.control
                    .records(VARIABLE_MIGRATION_KIND)
                    .unwrap()
                    .is_empty()
            );
        }
        let mut f = VariableDrainFixture::new(4);
        interrupt_next_volume_transition(VolumeInterruption::VariableMigrationIntentStored);
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        let (id, original) = f
            .control
            .records(VARIABLE_MIGRATION_KIND)
            .unwrap()
            .pop()
            .unwrap();
        let mut invalid: VariableVolumeMigration = decode_canonical(&original).unwrap();
        invalid.source_volume_id = invalid.destination.volume_id;
        let bytes = canonical_bytes(&invalid).unwrap();
        f.control
            .put_record(VARIABLE_MIGRATION_KIND, &id, &bytes)
            .unwrap();
        f = f.reopen();
        assert!(f.volumes.reconcile(&f.control).is_err());
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        assert_eq!(
            f.control.get_record(VARIABLE_MIGRATION_KIND, &id).unwrap(),
            Some(bytes)
        );
        assert_eq!(
            f.volumes
                .receipt(&f.control, &f.object.group_id, 4)
                .unwrap(),
            Some(f.source_receipt.clone())
        );
        f.assert_readable();
        assert!(
            f.volumes.volumes[&f.destination_id()]
                .store
                .as_ref()
                .unwrap()
                .first_ready_variable_object()
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn variable_migration_copies_mixed_formats_and_reads_after_source_removal() {
        let mut f = VariableDrainFixture::new(4);
        let fixed = parity_object(224, 3);
        // Add a format-1 shard to the same source, representing a mixed-volume upgrade.
        f.volumes
            .volumes
            .get_mut(&f.source_receipt.volume_id)
            .unwrap()
            .record
            .state = StorageVolumeState::Online;
        let destination = f.destination_id();
        f.volumes
            .volumes
            .get_mut(&destination)
            .unwrap()
            .record
            .state = StorageVolumeState::Failed;
        let source = f
            .volumes
            .volumes
            .get_mut(&f.source_receipt.volume_id)
            .unwrap();
        source.record.budget_bytes = (V1_SECTOR_SIZE * 2) as u64;
        assert_eq!(
            f.volumes
                .store(&f.control, &fixed, b"fixed signed acknowledgement")
                .unwrap()
                .volume_id,
            f.source_receipt.volume_id
        );
        f.volumes
            .volumes
            .get_mut(&destination)
            .unwrap()
            .record
            .state = StorageVolumeState::Online;
        f.volumes
            .volumes
            .get_mut(&destination)
            .unwrap()
            .record
            .budget_bytes = (V1_SECTOR_SIZE * 2) as u64;
        f.volumes
            .mark_draining(&f.control, f.source_receipt.volume_id)
            .unwrap();
        assert_eq!(f.volumes.migrate_draining(&f.control).unwrap(), 2);
        f.assert_readable();
        assert_eq!(
            f.volumes
                .load_ready(&fixed.group_id, fixed.shard_index)
                .unwrap(),
            fixed
        );
        assert_eq!(
            f.volumes.volumes[&destination]
                .store
                .as_ref()
                .unwrap()
                .load_stored_acknowledgement(&fixed.group_id, fixed.shard_index)
                .unwrap(),
            b"fixed signed acknowledgement"
        );
        fs::remove_dir_all(f.source.path()).unwrap();
        f = f.reopen();
        f.assert_readable();
        assert_eq!(
            f.volumes
                .load_ready(&fixed.group_id, fixed.shard_index)
                .unwrap(),
            fixed
        );
        assert_eq!(
            f.volumes.volumes[&f.source_receipt.volume_id].record.state,
            StorageVolumeState::Retired
        );
    }
    #[test]
    fn variable_migration_persists_retirement_before_another_source_fails() {
        let data = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([225; 32])));
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[first.path().to_path_buf(), second.path().to_path_buf()],
                1024,
                0,
            )
            .unwrap();
        let ids = volumes
            .volumes
            .iter()
            .filter(|(_, v)| v.record.configured)
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);
        for id in &ids {
            volumes.mark_draining(&control, *id).unwrap();
        }
        let reservation = AttemptReservationRecord {
            format_version: 1,
            attempt_id: [226; 16],
            volume_id: ids[1],
            guild_id: [227; 32],
            shard_index: 4,
            byte_length: 64,
        };
        control
            .put_record(
                "volume-attempt-reservation",
                &attempt_reservation_id(&reservation.attempt_id, 4),
                &canonical_bytes(&reservation).unwrap(),
            )
            .unwrap();
        assert!(volumes.migrate_draining(&control).is_err());
        assert_eq!(
            volumes.volumes[&ids[0]].record.state,
            StorageVolumeState::Retired
        );
        drop(volumes);
        drop(control);
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(data.path(), keys, &control).unwrap();
        assert_eq!(
            volumes.volumes[&ids[0]].record.state,
            StorageVolumeState::Retired
        );
        assert_eq!(
            volumes.volumes[&ids[1]].record.state,
            StorageVolumeState::Draining
        );
        assert!(
            control
                .get_record(
                    "volume-attempt-reservation",
                    &attempt_reservation_id(&reservation.attempt_id, 4)
                )
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn variable_migration_allows_pending_upload_to_finish_on_draining_source() {
        let mut f = VariableDrainFixture::new(4);
        let attempt = [228; 16];
        let group = [229; 32];
        let shard = 5;
        let bytes = vec![230; 64];
        let commitment = mb_core::merkle_commit(&bytes).unwrap();
        f.volumes
            .volumes
            .get_mut(&f.source_receipt.volume_id)
            .unwrap()
            .store
            .as_mut()
            .unwrap()
            .reserve_coding_attempt(&attempt, &f.object.guild_id, shard.into(), 64, 1024)
            .unwrap();
        let reservation = AttemptReservationRecord {
            format_version: 1,
            attempt_id: attempt,
            volume_id: f.source_receipt.volume_id,
            guild_id: f.object.guild_id,
            shard_index: shard,
            byte_length: 64,
        };
        f.control
            .put_record(
                "volume-attempt-reservation",
                &attempt_reservation_id(&attempt, shard),
                &canonical_bytes(&reservation).unwrap(),
            )
            .unwrap();
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        f = f.reopen();
        f.volumes
            .write_attempt_range(&f.control, &attempt, shard.into(), 0, &bytes)
            .unwrap();
        f.volumes
            .finish_attempt_upload(&f.control, &attempt, group, shard.into(), &commitment)
            .unwrap();
        f.volumes
            .attach_attempt_receipt(
                &f.control,
                &attempt,
                &group,
                shard.into(),
                b"completed pending receipt",
            )
            .unwrap();
        f.volumes
            .activate_attempt_object(
                &f.control,
                &attempt,
                &group,
                shard.into(),
                &commitment,
                &[231; 32],
            )
            .unwrap();
        assert_eq!(f.volumes.migrate_draining(&f.control).unwrap(), 1);
        assert_eq!(
            f.volumes
                .load_ready_variable(&f.control, &group, shard.into())
                .unwrap()
                .bytes,
            bytes
        );
        f.assert_readable();
        assert_eq!(
            f.volumes.volumes[&f.source_receipt.volume_id].record.state,
            StorageVolumeState::Retired
        );
    }

    #[test]
    fn variable_migration_keeps_source_active_until_corrupt_destination_is_repaired() {
        let mut f = VariableDrainFixture::new(4);
        interrupt_next_volume_transition(VolumeInterruption::VariableMigrationDestinationReady);
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        let id = f.destination_id();
        f.volumes
            .database_shell_statement(id, "UPDATE parity_objects SET bytes = zeroblob(64)", false)
            .unwrap();
        f = f.reopen();
        f.volumes.reconcile(&f.control).unwrap();
        assert!(
            f.volumes.volumes[&f.source_receipt.volume_id]
                .record
                .last_error
                .is_some()
        );
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        assert_eq!(
            f.volumes
                .receipt(&f.control, &f.object.group_id, 4)
                .unwrap(),
            Some(f.source_receipt.clone())
        );
        f.assert_readable();
        assert_eq!(f.control.records(VARIABLE_MIGRATION_KIND).unwrap().len(), 1);
        f.volumes
            .database_shell_statement(
                id,
                &format!(
                    "UPDATE parity_objects SET bytes = x'{}'",
                    hex::encode(&f.object.bytes)
                ),
                false,
            )
            .unwrap();
        f.volumes.reconcile(&f.control).unwrap();
        f.volumes.migrate_draining(&f.control).unwrap();
        f.assert_readable();
        assert!(
            f.control
                .records(VARIABLE_MIGRATION_KIND)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn variable_migration_waits_for_offline_source_cleanup_after_publishing_verified_destination() {
        let mut f = VariableDrainFixture::new(4);
        interrupt_next_volume_transition(VolumeInterruption::VariableMigrationDestinationReady);
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        f.volumes
            .volumes
            .get_mut(&f.source_receipt.volume_id)
            .unwrap()
            .store = None;
        f.volumes.reconcile(&f.control).unwrap();
        f.assert_readable();
        assert_eq!(f.control.records(VARIABLE_MIGRATION_KIND).unwrap().len(), 1);
        assert!(f.volumes.migrate_draining(&f.control).is_err());
        assert_eq!(
            f.volumes.volumes[&f.source_receipt.volume_id].record.state,
            StorageVolumeState::Draining
        );
        f = f.reopen();
        f.volumes.reconcile(&f.control).unwrap();
        f.volumes.migrate_draining(&f.control).unwrap();
        f.assert_readable();
        assert!(
            f.control
                .records(VARIABLE_MIGRATION_KIND)
                .unwrap()
                .is_empty()
        );
        assert!(f.control.records("volume-copy-cleanup").unwrap().is_empty());
    }

    #[test]
    fn variable_migration_gc_interruption_reopens_without_recreating_a_removed_copy() {
        for point in [
            VolumeInterruption::GarbageObjectRemoved,
            VolumeInterruption::GarbageReceiptRetired,
        ] {
            let mut f = VariableDrainFixture::new(4);
            interrupt_next_volume_transition(VolumeInterruption::VariableMigrationDestinationReady);
            assert!(f.volumes.migrate_draining(&f.control).is_err());
            interrupt_next_volume_transition(point);
            assert!(
                f.volumes
                    .remove_unreachable_for_attempt(
                        &f.control,
                        &f.attempt,
                        &f.verification,
                        &f.object.group_id,
                        4,
                        &f.object.commitment.root
                    )
                    .unwrap_err()
                    .to_string()
                    .contains("injected interruption")
            );
            let counts = f
                .volumes
                .volumes
                .iter()
                .filter_map(|(id, volume)| {
                    volume
                        .store
                        .as_ref()
                        .map(|store| (*id, store.ready_object_count().unwrap()))
                })
                .collect::<BTreeMap<_, _>>();
            f = f.reopen();
            f.volumes.reconcile(&f.control).unwrap();
            for (id, count) in counts {
                assert_eq!(
                    f.volumes.volumes[&id]
                        .store
                        .as_ref()
                        .unwrap()
                        .ready_object_count()
                        .unwrap(),
                    count
                );
            }
            assert!(
                f.volumes
                    .remove_unreachable_for_attempt(
                        &f.control,
                        &f.attempt,
                        &f.verification,
                        &f.object.group_id,
                        4,
                        &f.object.commitment.root
                    )
                    .unwrap()
            );
            f.volumes.migrate_draining(&f.control).unwrap();
            assert!(
                f.volumes
                    .load_ready_variable(&f.control, &f.object.group_id, 4)
                    .is_err()
            );
            assert!(
                f.control
                    .records(VARIABLE_MIGRATION_KIND)
                    .unwrap()
                    .is_empty()
            );
            assert!(
                f.control
                    .records("volume-attempt-retirement")
                    .unwrap()
                    .is_empty()
            );
            assert!(f.control.records("volume-copy-cleanup").unwrap().is_empty());
        }
    }

    #[test]
    fn draining_variable_shard_with_full_destination_keeps_receipt_and_source() {
        let data = TempDir::new().unwrap();
        let source = TempDir::new().unwrap();
        let destination = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([165; 32])));
        let attempt = [166; 16];
        let verification_hash = [167; 32];
        let bytes = vec![168; 64];
        let object = VariableParityObject {
            format_version: 2,
            guild_id: [169; 32],
            group_id: [170; 32],
            shard_index: 4,
            commitment: mb_core::merkle_commit(&bytes).unwrap(),
            bytes,
        };
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(&control, &[source.path().to_path_buf()], 1024 * 1024, 0)
            .unwrap();
        let receipt = volumes
            .stage_attempt(&control, &attempt, &object, b"staged")
            .unwrap();
        volumes
            .activate_attempt_object(
                &control,
                &attempt,
                &object.group_id,
                object.shard_index,
                &object.commitment,
                &verification_hash,
            )
            .unwrap();
        volumes.finalize_attempt(&control, &attempt).unwrap();
        volumes
            .configure(
                &control,
                &[
                    source.path().to_path_buf(),
                    destination.path().to_path_buf(),
                ],
                1,
                0,
            )
            .unwrap();
        volumes.mark_draining(&control, receipt.volume_id).unwrap();
        assert!(volumes.migrate_draining(&control).is_err());
        assert_eq!(
            volumes
                .volumes
                .get(&receipt.volume_id)
                .unwrap()
                .record
                .state,
            StorageVolumeState::Draining
        );
        assert_eq!(
            volumes
                .receipt(&control, &object.group_id, object.shard_index as u8)
                .unwrap(),
            Some(receipt.clone())
        );
        assert_eq!(
            volumes
                .load_ready_variable(&control, &object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[
                    source.path().to_path_buf(),
                    destination.path().to_path_buf(),
                ],
                1,
                0,
            )
            .unwrap();
        assert!(volumes.migrate_draining(&control).is_err());
        assert_eq!(
            volumes
                .load_ready_variable(&control, &object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert!(
            volumes
                .remove_unreachable_for_attempt(
                    &control,
                    &attempt,
                    &verification_hash,
                    &object.group_id,
                    object.shard_index as u8,
                    &object.commitment.root,
                )
                .unwrap()
        );
        assert_eq!(volumes.migrate_draining(&control).unwrap(), 0);
        assert_eq!(
            volumes
                .volumes
                .get(&receipt.volume_id)
                .unwrap()
                .record
                .state,
            StorageVolumeState::Retired
        );
    }

    #[test]
    fn same_group_successor_moves_receipt_across_volumes_after_interruption() {
        let data = TempDir::new().unwrap();
        let old_volume = TempDir::new().unwrap();
        let new_volume = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([157; 32])));
        let old_attempt = [158; 16];
        let successor_attempt = [159; 16];
        let old_hash = [160; 32];
        let successor_hash = [161; 32];
        let bytes = vec![162; 64];
        let object = VariableParityObject {
            format_version: 2,
            guild_id: [163; 32],
            group_id: [164; 32],
            shard_index: 4,
            commitment: mb_core::merkle_commit(&bytes).unwrap(),
            bytes,
        };
        let active_id = volume_object_id(&object.group_id, 4);
        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(data.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(&control, &[old_volume.path().to_path_buf()], 1024 * 1024, 0)
            .unwrap();
        let old_receipt = volumes
            .stage_attempt(&control, &old_attempt, &object, b"old")
            .unwrap();
        volumes
            .activate_attempt_object(
                &control,
                &old_attempt,
                &object.group_id,
                4,
                &object.commitment,
                &old_hash,
            )
            .unwrap();
        volumes.finalize_attempt(&control, &old_attempt).unwrap();
        volumes
            .configure(
                &control,
                &[
                    old_volume.path().to_path_buf(),
                    new_volume.path().to_path_buf(),
                ],
                1024 * 1024,
                0,
            )
            .unwrap();
        let successor_receipt = volumes
            .stage_attempt(&control, &successor_attempt, &object, b"new")
            .unwrap();
        assert_ne!(successor_receipt.volume_id, old_receipt.volume_id);

        interrupt_next_volume_transition(VolumeInterruption::AttemptObjectActivated);
        assert!(
            volumes
                .activate_attempt_object(
                    &control,
                    &successor_attempt,
                    &object.group_id,
                    4,
                    &object.commitment,
                    &successor_hash,
                )
                .is_err()
        );
        let still_old: VolumeReceipt = decode_canonical(
            &control
                .get_record("volume-receipt", &active_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(still_old.volume_id, old_receipt.volume_id);
        assert!(
            !volumes
                .remove_unreachable_for_attempt(
                    &control,
                    &old_attempt,
                    &old_hash,
                    &object.group_id,
                    4,
                    &object.commitment.root,
                )
                .unwrap()
        );

        volumes
            .activate_attempt_object(
                &control,
                &successor_attempt,
                &object.group_id,
                4,
                &object.commitment,
                &successor_hash,
            )
            .unwrap();
        assert!(
            volumes
                .remove_unreachable_for_attempt(
                    &control,
                    &old_attempt,
                    &old_hash,
                    &object.group_id,
                    4,
                    &object.commitment.root,
                )
                .unwrap()
        );
        let active: VolumeReceipt = decode_canonical(
            &control
                .get_record("volume-receipt", &active_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(active.volume_id, successor_receipt.volume_id);
        assert_eq!(
            volumes
                .load_ready_variable(&control, &object.group_id, 4)
                .unwrap(),
            object
        );
        assert!(control.records("volume-copy-cleanup").unwrap().is_empty());
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(data.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(data.path(), keys, &control).unwrap();
        assert_eq!(
            volumes
                .load_ready_variable(&control, &object.group_id, 4)
                .unwrap(),
            object
        );
    }

    #[test]
    fn lost_volume_is_replaced_with_a_new_identity_during_repair() {
        let temp = TempDir::new().unwrap();
        let original = TempDir::new().unwrap();
        let replacement = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([125; 32])));
        let object = parity_object(126, 4);
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        volumes
            .configure(
                &control,
                &[original.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64,
            )
            .unwrap();
        let original_receipt = volumes.store(&control, &object, b"ack").unwrap();
        let original_path = original.keep();
        drop(volumes);
        drop(control);
        fs::rename(&original_path, original_path.with_extension("lost")).unwrap();

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys.clone(), &control).unwrap();
        assert_eq!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .find(|status| status.volume_id == original_receipt.volume_id)
                .unwrap()
                .state,
            StorageVolumeState::Offline
        );
        volumes
            .configure(
                &control,
                &[replacement.path().to_path_buf()],
                (V1_SECTOR_SIZE * 2) as u64,
                V1_SECTOR_SIZE as u64,
            )
            .unwrap();
        assert!(volumes.protection_degraded(&control).unwrap());
        let replacement_receipt = volumes.store_repair(&control, &object).unwrap();
        assert_ne!(replacement_receipt.volume_id, original_receipt.volume_id);
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
        assert!(!volumes.protection_degraded(&control).unwrap());
        drop(volumes);
        drop(control);

        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert_eq!(
            volumes
                .receipt(&control, &object.group_id, object.shard_index)
                .unwrap()
                .unwrap()
                .volume_id,
            replacement_receipt.volume_id
        );
        assert_eq!(
            volumes
                .load_ready(&object.group_id, object.shard_index)
                .unwrap(),
            object
        );
    }
}
