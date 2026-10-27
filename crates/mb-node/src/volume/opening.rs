//! Linux volume admission, key publication and writable open share one held
//! directory. Existing inputs are authenticated without journal/schema writes.

use super::*;
use mb_store::{DatabaseDirectory, DatabaseOpenGuard};
use std::ffi::OsStr;

#[cfg(test)]
thread_local! {
    static BEFORE_VOLUME_WRITER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    static AFTER_MANIFEST_PUBLICATION: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
    pub(super) static BEFORE_DEFAULT_VOLUME_OPEN: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

fn before_writer() {
    #[cfg(test)]
    BEFORE_VOLUME_WRITER.with(|hook| {
        if let Some(operation) = hook.borrow_mut().take() {
            operation();
        }
    });
}

pub(super) fn require_current_directory(directory: &DatabaseDirectory, path: &Path) -> Result<()> {
    let pinned = directory.file().metadata()?;
    let visible = fs::symlink_metadata(path)?;
    anyhow::ensure!(
        visible.is_dir()
            && (visible.dev(), visible.ino()) == (pinned.dev(), pinned.ino())
            && pinned.uid() == unsafe { libc::geteuid() }
            && pinned.mode() & 0o022 == 0,
        "parity volume directory changed during admission; preserve the original volume and retry"
    );
    Ok(())
}

fn capture_guard(path: &Path) -> Result<DatabaseOpenGuard> {
    DatabaseOpenGuard::capture(path, &[OsStr::new(VOLUME_MANIFEST_FILE)])
        .context("parity catalog admission failed; preserve every database/journal file and the manifest; see docs/guarded-withdrawal.md")
}

/// Find the authenticated existing key without speculative writable opens.
fn admit_key(
    directory: &DatabaseDirectory,
    database_file: &str,
    volume_id: Uuid,
    guard: &DatabaseOpenGuard,
    candidates: &[[u8; 32]],
) -> Result<Option<[u8; 32]>> {
    let path = directory.leaf(database_file)?;
    if !guard.requires_existing_catalog() {
        return Ok(None);
    }
    let mut failure = None;
    for key in candidates {
        match ParityStore::open_preserved_read_only_with_keys(&path, volume_id.as_bytes(), &[*key])
        {
            Ok((store, inputs)) => {
                store.verify_open_guard(guard)?;
                inputs.verify_unchanged()?;
                guard.verify_unchanged(&path)?;
                return Ok(Some(*key));
            }
            Err(error) => failure = Some(error),
        }
    }
    Err(failure.unwrap_or_else(|| anyhow::anyhow!("no parity database keys available")))
        .context("parity catalog admission failed; preserve every database/journal file and the manifest; see docs/guarded-withdrawal.md")
}

fn open_admitted(
    directory: &DatabaseDirectory,
    record: &VolumeRecord,
    database_key: &[u8; 32],
    admitted_key: Option<[u8; 32]>,
    guard: &DatabaseOpenGuard,
) -> Result<ParityStore> {
    let selected = admitted_key.as_ref().unwrap_or(database_key);
    let mut store = ParityStore::open_admitted_in_directory_with_key(
        directory,
        OsStr::new(&record.database_file),
        record.volume_id.as_bytes(),
        selected,
        guard,
    )?;
    if selected != database_key {
        // Both rekey verification and the resulting reader retain this same
        // directory. No retry resolves the public path or creates a new main.
        store.rekey(database_key)?;
        store = ParityStore::open_existing_in_directory_with_key(
            directory,
            OsStr::new(&record.database_file),
            record.volume_id.as_bytes(),
            database_key,
        )?;
    }
    resume_record_quota_adoption(store)
}

fn resume_record_quota_adoption(mut store: ParityStore) -> Result<ParityStore> {
    // Finish interrupted accounting on the admitted connection, retaining its
    // native ownership lease and physical limits before Node reconciliation.
    while store
        .record_quota_usage()?
        .is_some_and(|usage| usage.state == mb_store::DatabaseRecordQuotaState::Adopting)
    {
        store.resume_record_quota_adoption()?;
    }
    Ok(store)
}

pub(super) fn initialize_volume(
    root: &Path,
    database_file: Option<&str>,
    budget_bytes: u64,
    headroom_bytes: u64,
    keys: &KeyMaterial,
) -> Result<VolumeRecord> {
    let root = require_online_directory(root)?;
    let directory = DatabaseDirectory::open(&root)?;
    initialize_volume_in_directory(
        &root,
        &directory,
        database_file,
        budget_bytes,
        headroom_bytes,
        keys,
    )
}

pub(super) fn initialize_volume_in_directory(
    root: &Path,
    directory: &DatabaseDirectory,
    database_file: Option<&str>,
    budget_bytes: u64,
    headroom_bytes: u64,
    keys: &KeyMaterial,
) -> Result<VolumeRecord> {
    require_current_directory(directory, root)?;
    let root = root.to_path_buf();
    let manifest = read_volume_manifest(&directory.path(), keys)?;
    if let Some(manifest) = &manifest
        && manifest.wrapped_database_key.format_version == 2
    {
        let key =
            unwrap_mutable_volume_key(keys, manifest.volume_id, &manifest.wrapped_database_key)?;
        let record = VolumeRecord {
            format_version: 1,
            volume_id: manifest.volume_id,
            path: root.clone(),
            database_file: manifest.database_file.clone(),
            wrapped_database_key: manifest.wrapped_database_key.clone(),
            state: StorageVolumeState::Online,
            budget_bytes,
            headroom_bytes,
            last_error: None,
            configured: true,
        };
        open_volume_store_in_directory(&record, &key, keys, directory)?;
        return Ok(record);
    }
    let (manifest, publish) = match manifest {
        Some(manifest) => (manifest, false),
        None => {
            let legacy_exists = database_file
                .map(|name| directory.leaf(name))
                .transpose()?
                .map(|path| match fs::symlink_metadata(path) {
                    Ok(_) => Ok(true),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                    Err(error) => Err(error),
                })
                .transpose()?
                .unwrap_or(false);
            let volume_id = if legacy_exists {
                legacy_default_volume_id(keys)
            } else {
                Uuid::new_v4()
            };
            let mut key = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            (
                VolumeManifest {
                    format_version: 1,
                    owner: keys.node_id(),
                    volume_id,
                    database_file: database_file
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| format!("parity-{volume_id}.db")),
                    wrapped_database_key: keys
                        .wrap_database_key(&volume_database_id(volume_id), &key)?,
                },
                true,
            )
        }
    };
    validate_manifest(&manifest, keys.node_id())?;
    let path = directory.leaf(&manifest.database_file)?;
    let mut guard = capture_guard(&path)?;
    let current = read_volume_manifest(&directory.path(), keys)?;
    anyhow::ensure!(
        if publish {
            current.is_none()
        } else {
            current.as_ref() == Some(&manifest)
        },
        "parity volume manifest changed during admission"
    );
    let database_key = keys.unwrap_database_key(
        &volume_database_id(manifest.volume_id),
        &manifest.wrapped_database_key,
    )?;
    let legacy_key = keys.database_key(&legacy_volume_database_id(manifest.volume_id));
    let admitted_key = admit_key(
        directory,
        &manifest.database_file,
        manifest.volume_id,
        &guard,
        &[database_key, legacy_key],
    )?;
    before_writer();
    require_current_directory(directory, &root)?;
    guard.verify_unchanged(&path)?;
    if publish {
        let signed = SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest.clone(), keys)?;
        write_new_private_record_at(
            directory.file(),
            c".mutualbackup-volume",
            &canonical_bytes_bounded(&signed, MAX_LOCAL_MANIFEST_BYTES)?,
        )?;
        #[cfg(test)]
        AFTER_MANIFEST_PUBLICATION.with(|hook| {
            if let Some(operation) = hook.borrow_mut().take() {
                operation();
            }
        });
        guard = guard.refresh_private_files_after_publication(&path)?;
        anyhow::ensure!(
            read_volume_manifest(&directory.path(), keys)?.as_ref() == Some(&manifest),
            "published parity volume manifest changed before database creation"
        );
    }
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
    open_admitted(directory, &record, &database_key, admitted_key, &guard)?;
    require_current_directory(directory, &record.path)?;
    Ok(record)
}

pub(super) fn open_volume_store(
    record: &VolumeRecord,
    database_key: &[u8; 32],
    keys: &KeyMaterial,
) -> Result<ParityStore> {
    let directory = DatabaseDirectory::open(&record.path)?;
    open_volume_store_in_directory(record, database_key, keys, &directory)
}

pub(super) fn open_volume_store_in_directory(
    record: &VolumeRecord,
    database_key: &[u8; 32],
    keys: &KeyMaterial,
    directory: &DatabaseDirectory,
) -> Result<ParityStore> {
    require_current_directory(directory, &record.path)?;
    let path = directory.leaf(&record.database_file)?;
    let guard = capture_guard(&path)?;
    anyhow::ensure!(
        guard.requires_existing_catalog(),
        "established parity database is absent"
    );
    let manifest = read_volume_manifest(&directory.path(), keys)?
        .context("established parity manifest is absent")?;
    anyhow::ensure!(
        manifest.volume_id == record.volume_id
            && manifest.database_file == record.database_file
            && manifest.wrapped_database_key == record.wrapped_database_key,
        "parity volume manifest conflicts with the control registry"
    );
    if record.wrapped_database_key.format_version == 2 {
        let inspection = ParityStore::inspect_native_existing_in_directory(
            directory,
            OsStr::new(&record.database_file),
            record.volume_id.as_bytes(),
            keys,
            &volume_database_id(record.volume_id),
        )?;
        anyhow::ensure!(
            inspection.wrapped_key() == &record.wrapped_database_key
                && inspection.database_key() == database_key,
            "native parity policy/key differs from its registry"
        );
        let (reader, inputs) = ParityStore::open_preserved_read_only_with_keys(
            &path,
            record.volume_id.as_bytes(),
            &[*database_key],
        )?;
        reader.verify_open_guard(&guard)?;
        inspection.verify_parity(&reader)?;
        inputs.verify_unchanged()?;
        drop(reader);
        before_writer();
        require_current_directory(directory, &record.path)?;
        return resume_record_quota_adoption(
            inspection.open_parity_admitted(directory, keys, &guard)?,
        );
    }
    let legacy_key = keys.database_key(&legacy_volume_database_id(record.volume_id));
    let selected = admit_key(
        directory,
        &record.database_file,
        record.volume_id,
        &guard,
        &[*database_key, legacy_key],
    )?;
    before_writer();
    require_current_directory(directory, &record.path)?;
    open_admitted(directory, record, database_key, selected, &guard)
}

#[cfg(test)]
mod tests;
