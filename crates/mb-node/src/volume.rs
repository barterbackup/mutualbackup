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
use mb_store::{ControlStore, DatabaseError, ParityObject, ParityStore};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const VOLUME_MANIFEST_DOMAIN: &[u8] = b"mutualbackup/local-volume-manifest/v1";
const VOLUME_MANIFEST_FILE: &str = ".mutualbackup-volume";
const CONTROL_KEY_FILE: &str = "control.key";
const MAX_LOCAL_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageVolumeState {
    Online,
    Offline,
    Draining,
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
                match open_volume_store(&record, &database_key, &keys) {
                    Ok(opened) => {
                        if record.state == StorageVolumeState::Offline {
                            record.state = StorageVolumeState::Online;
                        }
                        record.last_error = None;
                        store = Some(opened);
                    }
                    Err(error) => {
                        record.state = StorageVolumeState::Failed;
                        record.last_error = Some(truncated_error(&error));
                    }
                }
            } else {
                record.state = StorageVolumeState::Offline;
                record.last_error = Some("configured volume is absent".to_owned());
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
        let set = Self { keys, volumes };
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
            self.volumes
                .values()
                .next()
                .map(|volume| vec![volume.record.path.clone()])
                .unwrap_or_default()
        } else {
            paths.to_vec()
        };
        let mut configured = BTreeSet::new();
        for path in requested {
            let path = require_online_directory(&path)?;
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
                if volume.record.state == StorageVolumeState::Offline {
                    volume.record.state = StorageVolumeState::Online;
                }
                continue;
            }
            let record = initialize_volume(&path, None, budget_bytes, headroom_bytes, &self.keys)?;
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
            if !configured.contains(&volume.record.path)
                && volume.record.state == StorageVolumeState::Online
            {
                volume.record.state = StorageVolumeState::Offline;
                volume.record.last_error = Some("volume is no longer configured".to_owned());
                volume.store = None;
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
                let (used_bytes, object_count) = match &volume.store {
                    Some(store) => {
                        let objects = store.ready_objects()?;
                        (Some(store.used_bytes()?), Some(objects.len() as u64))
                    }
                    None => (None, None),
                };
                Ok(StorageVolumeStatus {
                    volume_id: volume.record.volume_id,
                    path: volume.record.path.clone(),
                    state: volume.record.state,
                    budget_bytes: volume.record.budget_bytes,
                    headroom_bytes: volume.record.headroom_bytes,
                    used_bytes,
                    object_count,
                    last_error: volume.record.last_error.clone(),
                })
            })
            .collect()
    }

    pub(crate) fn reader_configs(&self) -> Vec<VolumeReaderConfig> {
        self.volumes
            .values()
            .filter_map(|volume| {
                volume.store.as_ref().map(|store| VolumeReaderConfig {
                    volume_id: volume.record.volume_id,
                    path: store.path().to_path_buf(),
                    database_key: volume.database_key,
                })
            })
            .collect()
    }

    pub(crate) fn load_ready(&self, group_id: &[u8; 32], shard_index: u8) -> Result<ParityObject> {
        for volume in self.volumes.values() {
            let Some(store) = &volume.store else {
                continue;
            };
            match store.load_ready(group_id, shard_index) {
                Ok(object) => return Ok(object),
                Err(DatabaseError::NotReady) => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(DatabaseError::NotReady.into())
    }

    pub(crate) fn store(
        &mut self,
        control: &ControlStore,
        object: &ParityObject,
        acknowledgement: &[u8],
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
        let selected = self
            .volumes
            .iter()
            .filter_map(|(id, volume)| {
                if volume.record.state != StorageVolumeState::Online {
                    return None;
                }
                let used = volume.store.as_ref()?.used_bytes().ok()?;
                let writable = volume
                    .record
                    .budget_bytes
                    .saturating_sub(volume.record.headroom_bytes);
                (used.saturating_add(required) <= writable).then_some((*id, used))
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
        let volume = self
            .volumes
            .get_mut(&selected)
            .expect("selected volume exists");
        volume
            .store
            .as_mut()
            .expect("selected volume is online")
            .stage_and_publish_ack(object, acknowledgement, volume.record.budget_bytes)?;
        control.put_record("volume-receipt", &record_id, &canonical_bytes(&receipt)?)?;
        control.delete_record("volume-write-intent", &record_id)?;
        Ok(receipt)
    }

    pub(crate) fn reconcile(&mut self, control: &ControlStore) -> Result<()> {
        for (record_id, bytes) in control.records("volume-write-intent")? {
            let intent: VolumeWriteIntent = decode_canonical(&bytes)?;
            validate_receipt(&intent.receipt)?;
            let Some(volume) = self.volumes.get(&intent.receipt.volume_id) else {
                continue;
            };
            let Some(store) = &volume.store else {
                continue;
            };
            let object =
                match store.load_ready(&intent.receipt.group_id, intent.receipt.shard_index) {
                    Ok(object) => object,
                    Err(DatabaseError::NotReady) => continue,
                    Err(error) => return Err(error.into()),
                };
            if object.guild_id != intent.receipt.guild_id || object.root != intent.receipt.root {
                bail!("completed parity write conflicts with its durable intent");
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
            let objects = self
                .volumes
                .get(&source_id)
                .and_then(|volume| volume.store.as_ref())
                .context("draining volume became unavailable")?
                .ready_objects()?;
            for object in objects {
                let acknowledgement = self
                    .volumes
                    .get(&source_id)
                    .and_then(|volume| volume.store.as_ref())
                    .expect("source checked above")
                    .load_acknowledgement(&object.group_id, object.shard_index)?;
                let record_id = volume_object_id(&object.group_id, object.shard_index);
                // Remove the source receipt before selecting a destination, while
                // retaining a write intent that makes an interruption recoverable.
                control.delete_record("volume-receipt", &record_id)?;
                let destination = match self.store(control, &object, &acknowledgement) {
                    Ok(receipt) if receipt.volume_id != source_id => receipt,
                    Ok(_) => bail!("draining migration selected its source volume"),
                    Err(error) => return Err(error),
                };
                self.volumes
                    .get_mut(&source_id)
                    .and_then(|volume| volume.store.as_mut())
                    .expect("draining source is online")
                    .remove_ready(&object.group_id, object.shard_index, &object.root)?;
                control.put_record(
                    "volume-receipt",
                    &record_id,
                    &canonical_bytes(&destination)?,
                )?;
                moved += 1;
            }
            let source = self.volumes.get_mut(&source_id).expect("source exists");
            source.record.state = StorageVolumeState::Offline;
            source.record.last_error = Some("drain completed; safe to remove volume".to_owned());
            source.store = None;
        }
        self.persist(control)?;
        Ok(moved)
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
                return Ok((store, database_key));
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
        Ok((store, database_key))
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
    if manifest_path.exists() {
        let signed: SignedRecord<VolumeManifest> = read_private_record(&manifest_path)?;
        signed.verify(VOLUME_MANIFEST_DOMAIN)?;
        validate_manifest(&signed.value, keys.node_id())?;
        return Ok(VolumeRecord {
            format_version: 1,
            volume_id: signed.value.volume_id,
            path: root,
            database_file: signed.value.database_file,
            wrapped_database_key: signed.value.wrapped_database_key,
            state: StorageVolumeState::Online,
            budget_bytes,
            headroom_bytes,
            last_error: None,
        });
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
    }
    Ok(record)
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
    match ParityStore::open_with_key(&database_path, record.volume_id.as_bytes(), database_key) {
        Ok(store) => Ok(store),
        Err(new_key_error) => {
            let legacy_key = keys.database_key(&legacy_volume_database_id(record.volume_id));
            let store = ParityStore::open_with_key(
                &database_path,
                record.volume_id.as_bytes(),
                &legacy_key,
            )
            .with_context(|| format!("parity database rejected wrapped key: {new_key_error}"))?;
            store.rekey(database_key)?;
            Ok(store)
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
        || !(3..=4).contains(&receipt.shard_index)
        || receipt.root == [0; 32]
    {
        bail!("invalid parity volume receipt");
    }
    Ok(())
}

fn load_volume_records(control: &ControlStore) -> Result<Vec<VolumeRecord>> {
    control
        .get_record("node-config", b"storage-volumes")?
        .map(|bytes| decode_canonical(&bytes).map_err(Into::into))
        .transpose()
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
    value.truncate(1024);
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use mb_core::{Seed, V1_SECTOR_SIZE, sector_root};
    use tempfile::TempDir;

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
        let volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
        assert!(
            volumes
                .statuses()
                .unwrap()
                .iter()
                .any(|status| status.state == StorageVolumeState::Offline)
        );
    }

    #[test]
    fn draining_migrates_verified_objects_before_withdrawing_the_source() {
        let temp = TempDir::new().unwrap();
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([63; 32])));
        let (control, _) = open_control_store(temp.path(), &keys).unwrap();
        let mut volumes = StorageVolumes::open(temp.path(), keys, &control).unwrap();
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
            StorageVolumeState::Offline
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
