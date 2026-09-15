use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use mb_core::{
    KeyMaterial, NodeId, SignedRecord, WrappedDatabaseKey, canonical_bytes, decode_canonical,
};
use mb_store::{ControlStore, DatabaseError, DatabaseShellResult, ParityObject, ParityStore};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const VOLUME_MANIFEST_DOMAIN: &[u8] = b"mutualbackup/local-volume-manifest/v1";
const VOLUME_MANIFEST_FILE: &str = ".mutualbackup-volume";
const CONTROL_KEY_FILE: &str = "control.key";
const MAX_LOCAL_MANIFEST_BYTES: usize = 64 * 1024;
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct VolumeRecord {
    format_version: u16,
    volume_id: Uuid,
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
struct VolumeRecordBeforeConfiguredState {
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
        let record_id = volume_object_id(group_id, shard_index);
        let receipt_volume = self
            .receipt(control, group_id, shard_index)?
            .map(|receipt| receipt.volume_id);
        let mut cleanup_volumes = self.cleanup_volumes(control, group_id, shard_index)?;
        let mut complete =
            receipt_volume.is_none_or(|volume_id| self.volumes.contains_key(&volume_id));
        for (volume_id, volume) in &mut self.volumes {
            let required = receipt_volume == Some(*volume_id)
                || cleanup_volumes.contains(volume_id)
                || volume.record.state == StorageVolumeState::Draining;
            let Some(store) = volume.store.as_mut() else {
                if required {
                    complete = false;
                }
                continue;
            };
            match store.remove_ready(group_id, shard_index, root) {
                Ok(true) => {
                    volume_interruption(VolumeInterruption::GarbageObjectRemoved)?;
                    cleanup_volumes.remove(volume_id);
                }
                Ok(false) => {
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
        if complete && cleanup_volumes.is_empty() {
            control.delete_record("volume-receipt", &record_id)?;
            volume_interruption(VolumeInterruption::GarbageReceiptRetired)?;
        }
        Ok(complete && cleanup_volumes.is_empty())
    }

    pub(crate) fn store(
        &mut self,
        control: &ControlStore,
        object: &ParityObject,
        acknowledgement: &[u8],
    ) -> Result<VolumeReceipt> {
        self.store_with_headroom(control, object, acknowledgement, true)
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

    fn store_with_headroom(
        &mut self,
        control: &ControlStore,
        object: &ParityObject,
        acknowledgement: &[u8],
        reserve_headroom: bool,
    ) -> Result<VolumeReceipt> {
        if let Some(receipt) = self.receipt(control, &object.group_id, object.shard_index)? {
            let volume = self
                .volumes
                .get_mut(&receipt.volume_id)
                .context("parity receipt names an unknown volume")?;
            let store = volume
                .store
                .as_mut()
                .context("parity receipt volume is offline")?;
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
                let used = volume.store.as_ref()?.used_bytes().ok()?;
                let reserved = if reserve_headroom {
                    volume.record.headroom_bytes
                } else {
                    0
                };
                let writable = volume.record.budget_bytes.saturating_sub(reserved);
                let available = fs2::available_space(&volume.record.path).ok()?;
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
        for (record_id, bytes) in control.records("volume-write-intent")? {
            let intent: VolumeWriteIntent = decode_canonical(&bytes)?;
            validate_receipt(&intent.receipt)?;
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

    pub(crate) fn migrate_draining(&mut self, control: &ControlStore) -> Result<u64> {
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
            let source = self.volumes.get_mut(&source_id).expect("source exists");
            source.record.configured = false;
            source.record.state = StorageVolumeState::Retired;
            source.record.last_error = Some("drain completed; safe to remove volume".to_owned());
            source.store = None;
        }
        self.persist(control)?;
        volume_interruption(VolumeInterruption::MigrationStateStored)?;
        Ok(moved)
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
            .get_record("volume-receipt", &volume_object_id(group_id, shard_index))?
            .map(|bytes| {
                let receipt: VolumeReceipt = decode_canonical(&bytes)?;
                validate_receipt(&receipt)?;
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

    fn persist(&self, control: &ControlStore) -> Result<()> {
        let records = self
            .volumes
            .values()
            .map(|volume| volume.record.clone())
            .collect::<Vec<_>>();
        store_volume_records(control, &records)
    }
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
        let database_path = record.path.join(&record.database_file);
        let database_key = keys.unwrap_database_key(
            &volume_database_id(record.volume_id),
            &record.wrapped_database_key,
        )?;
        ParityStore::open_with_key(&database_path, record.volume_id.as_bytes(), &database_key)?;
        return Ok(record);
    }

    let legacy_path = database_file.map(|name| root.join(name));
    let volume_id = if legacy_path.as_ref().is_some_and(|path| path.exists()) {
        let mut bytes = [0_u8; 16];
        bytes.copy_from_slice(&blake3::hash(&keys.node_id().0).as_bytes()[..16]);
        Uuid::from_bytes(bytes)
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
    if receipt.format_version != 1
        || receipt.volume_id.is_nil()
        || receipt.guild_id == [0; 32]
        || receipt.group_id == [0; 32]
        || receipt.shard_index > 4
        || receipt.root == [0; 32]
    {
        bail!("invalid parity volume receipt");
    }
    Ok(())
}

fn load_volume_records(control: &ControlStore) -> Result<Vec<VolumeRecord>> {
    control
        .get_record("node-config", b"storage-volumes")?
        .map(|bytes| {
            decode_canonical(&bytes).or_else(|_| {
                decode_canonical::<Vec<VolumeRecordBeforeConfiguredState>>(&bytes)
                    .map(|records| records.into_iter().map(Into::into).collect())
            })
        })
        .transpose()
        .map_err(Into::into)
        .map(|records| records.unwrap_or_default())
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
        let headroom = available - required / 2;
        volumes
            .configure(&control, &[volume.path().to_path_buf()], u64::MAX, headroom)
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
        }
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
