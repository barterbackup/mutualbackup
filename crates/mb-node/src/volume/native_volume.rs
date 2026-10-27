//! Explicit fresh parity-volume birth/resume for an already managed Node.
//! The creation profile fixes the original identity and policy before SQL;
//! only the checked control-registry transaction grants placement authority.
use super::*;
use mb_core::NativeDatabaseIoPolicy;
use mb_store::DatabaseDirectory;
use std::ffi::OsStr;

const PROFILE_FILE: &str = "native-volume.profile";
const PROFILE_DOMAIN: &[u8] = b"mutualbackup/native-parity-volume/v1";
const DATABASE_FILE: &str = "parity.db";

/// Original per-catalog ceilings and logical payload budget for an additional
/// native parity volume. Enclosing dataset/guild reservations remain separate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeParityVolumePolicy {
    pub database: NativeDatabaseIoPolicy,
    pub parity_budget_bytes: u64,
}

impl NativeParityVolumePolicy {
    /// Validate the immutable database ceilings and logical parity budget.
    pub fn validate(self) -> Result<()> {
        self.database.validate()?;
        anyhow::ensure!(
            self.parity_budget_bytes > self.database.headroom_bytes
                && self.parity_budget_bytes <= self.database.main_bytes,
            "native parity budget must fit its declared main-file ceiling and headroom"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Profile {
    version: u16,
    parent: (u64, u64),
    volume_id: Uuid,
    policy: NativeParityVolumePolicy,
}

fn read_profile(directory: &DatabaseDirectory, keys: &KeyMaterial) -> Result<Option<Profile>> {
    let signed: Option<SignedRecord<Profile>> =
        read_private_record_optional(&directory.leaf(PROFILE_FILE)?)?;
    signed
        .map(|signed| {
            signed.verify(PROFILE_DOMAIN)?;
            let held = directory.file().metadata()?;
            anyhow::ensure!(
                signed.signer == keys.node_id()
                    && signed.value.version == 1
                    && signed.value.parent == (held.dev(), held.ino())
                    && !signed.value.volume_id.is_nil(),
                "native parity creation profile is incompatible or copied; preserve it for explicit recovery/adoption"
            );
            signed.value.policy.validate()?;
            Ok(signed.value)
        })
        .transpose()
}

fn require_creation_directory(directory: &DatabaseDirectory) -> Result<()> {
    let lease = format!(
        ".mutualbackup-native-{}",
        blake3::hash(DATABASE_FILE.as_bytes()).to_hex()
    );
    for entry in fs::read_dir(directory.path())? {
        let name = entry?.file_name();
        anyhow::ensure!(
            [
                PROFILE_FILE,
                VOLUME_MANIFEST_FILE,
                DATABASE_FILE,
                "parity.db-wal",
                "parity.db-shm",
                "parity.db-journal",
                &lease
            ]
            .iter()
            .any(|allowed| name == OsStr::new(allowed)),
            "native parity creation found unrelated existing state"
        );
    }
    Ok(())
}

impl StorageVolumes {
    pub(crate) fn create_native_volume(
        &mut self,
        control: &ControlStore,
        requested_path: &Path,
        policy: NativeParityVolumePolicy,
    ) -> Result<Uuid> {
        policy.validate()?;
        anyhow::ensure!(
            control.native_database_owner().is_some(),
            "additional native volume birth requires a managed Node"
        );
        require_control_directory(control, &self.default_path)?;
        let path = require_online_directory(requested_path)?;
        anyhow::ensure!(
            path != self.default_path,
            "use Node creation for the default native volume"
        );
        anyhow::ensure!(
            self.volumes.len() < MAX_BOUNDED_VOLUME_RECORDS
                || self
                    .volumes
                    .values()
                    .any(|volume| volume.record.path == path),
            "too many volumes for bounded registry inspection"
        );
        let directory = DatabaseDirectory::open(&path)?;
        opening::require_current_directory(&directory, &path)?;
        let original = read_profile(&directory, &self.keys)?;
        let profile = match original {
            Some(profile) => {
                anyhow::ensure!(
                    profile.policy == policy,
                    "native parity creation policy differs from its original profile"
                );
                profile
            }
            None => {
                anyhow::ensure!(
                    self.volumes
                        .values()
                        .all(|volume| volume.record.path != path),
                    "registered native volume is missing its original creation profile; preserve the original volume for recovery/adoption"
                );
                anyhow::ensure!(
                    fs::read_dir(directory.path())?.next().is_none(),
                    "native parity birth requires an empty directory; existing inputs need explicit adoption"
                );
                let held = directory.file().metadata()?;
                let profile = Profile {
                    version: 1,
                    parent: (held.dev(), held.ino()),
                    volume_id: Uuid::new_v4(),
                    policy,
                };
                let signed = SignedRecord::sign(PROFILE_DOMAIN, profile.clone(), &self.keys)?;
                write_new_private_record_at(
                    directory.file(),
                    c"native-volume.profile",
                    &canonical_bytes_bounded(&signed, MAX_LOCAL_MANIFEST_BYTES)?,
                )?;
                interruption(Step::Profile)?;
                profile
            }
        };
        require_creation_directory(&directory)?;
        anyhow::ensure!(
            self.volumes
                .values()
                .all(|volume| volume.record.path != path
                    || volume.record.volume_id == profile.volume_id),
            "native parity path is already registered with another identity"
        );
        if let Some(existing) = self.volumes.get(&profile.volume_id) {
            anyhow::ensure!(
                existing.record.path == path && existing.record.database_file == DATABASE_FILE,
                "native parity identity is already registered at another path"
            );
        }
        let previous = control.get_record("node-config", b"storage-volumes")?;
        let admission = mb_store::DatabaseOpenGuard::capture_native_creation(
            &directory.leaf(DATABASE_FILE)?,
            &[OsStr::new(PROFILE_FILE), OsStr::new(VOLUME_MANIFEST_FILE)],
        )?;
        // A manifest is published only after the native Store birth is ready.
        // Authenticate it before opening any existing SQL writable.
        if let Some(manifest) = read_volume_manifest(&directory.path(), &self.keys)? {
            anyhow::ensure!(
                manifest.volume_id == profile.volume_id && manifest.database_file == DATABASE_FILE,
                "native parity manifest conflicts with its creation profile"
            );
            let inspection = ParityStore::inspect_native_existing_in_directory(
                &directory,
                OsStr::new(DATABASE_FILE),
                profile.volume_id.as_bytes(),
                &self.keys,
                &volume_database_id(profile.volume_id),
            )?;
            anyhow::ensure!(
                inspection.wrapped_key() == &manifest.wrapped_database_key
                    && inspection.policy() == policy.database,
                "native parity manifest/policy differs from its original birth"
            );
            let (reader, inputs) = ParityStore::open_preserved_read_only_with_keys(
                &directory.leaf(DATABASE_FILE)?,
                profile.volume_id.as_bytes(),
                &[*inspection.database_key()],
            )?;
            reader.verify_open_guard(&admission)?;
            inspection.verify_parity(&reader)?;
            inputs.verify_unchanged()?;
            inspection.verify_current()?;
        }
        before_writer();
        opening::require_current_directory(&directory, &path)?;
        anyhow::ensure!(
            read_profile(&directory, &self.keys)?.as_ref() == Some(&profile),
            "native parity creation profile changed before SQL"
        );
        require_creation_directory(&directory)?;
        let store = ParityStore::create_native_admitted_in_directory(
            &directory,
            OsStr::new(DATABASE_FILE),
            profile.volume_id.as_bytes(),
            &self.keys,
            &volume_database_id(profile.volume_id),
            policy.database,
            &admission,
        )?;
        interruption(Step::Database)?;
        let manifest = VolumeManifest {
            format_version: 1,
            owner: self.keys.node_id(),
            volume_id: profile.volume_id,
            database_file: DATABASE_FILE.to_owned(),
            wrapped_database_key: store
                .native_database_owner()
                .context("native parity owner is missing")?
                .wrapped_key()
                .clone(),
        };
        match read_volume_manifest(&directory.path(), &self.keys)? {
            Some(existing) => anyhow::ensure!(
                existing == manifest,
                "native parity manifest differs from its original birth"
            ),
            None => {
                let signed =
                    SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest.clone(), &self.keys)?;
                write_new_private_record_at(
                    directory.file(),
                    c".mutualbackup-volume",
                    &canonical_bytes_bounded(&signed, MAX_LOCAL_MANIFEST_BYTES)?,
                )?;
            }
        }
        interruption(Step::Manifest)?;
        opening::require_current_directory(&directory, &path)?;
        require_control_directory(control, &self.default_path)?;
        anyhow::ensure!(
            read_profile(&directory, &self.keys)?.as_ref() == Some(&profile),
            "native parity creation profile changed before registry publication"
        );
        if let Some(existing) = self.volumes.get(&profile.volume_id) {
            anyhow::ensure!(
                existing.record.wrapped_database_key == manifest.wrapped_database_key,
                "registered native parity key differs from its birth"
            );
            // Repeating creation never resets later budgets, configuration,
            // drain/retirement state or the existing reader/owner lifetimes.
            return Ok(profile.volume_id);
        }
        let record = VolumeRecord {
            format_version: 1,
            volume_id: profile.volume_id,
            path,
            database_file: DATABASE_FILE.to_owned(),
            wrapped_database_key: manifest.wrapped_database_key,
            state: StorageVolumeState::Online,
            budget_bytes: policy.parity_budget_bytes,
            headroom_bytes: policy.database.headroom_bytes,
            last_error: None,
            configured: true,
        };
        let mut records = self
            .volumes
            .values()
            .map(|volume| volume.record.clone())
            .collect::<Vec<_>>();
        records.push(record.clone());
        records.sort_by_key(|record| record.volume_id);
        canonical_bytes_bounded(&records, MAX_BOUNDED_VOLUME_REGISTRY_BYTES)?;
        let database_key =
            unwrap_mutable_volume_key(&self.keys, record.volume_id, &record.wrapped_database_key)?;
        publish_volume_configuration(control, previous.as_deref(), &records)?;
        self.volumes.insert(
            record.volume_id,
            StorageVolume {
                record,
                database_key,
                store: Some(store),
            },
        );
        interruption(Step::Registry)?;
        Ok(profile.volume_id)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Profile,
    Database,
    Manifest,
    Registry,
}

#[cfg(test)]
thread_local! {
    static INTERRUPT: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
    static BEFORE_WRITER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

fn before_writer() {
    #[cfg(test)]
    BEFORE_WRITER.with(|hook| {
        if let Some(operation) = hook.borrow_mut().take() {
            operation();
        }
    });
}

fn interruption(step: Step) -> Result<()> {
    #[cfg(test)]
    if INTERRUPT.with(|next| {
        next.get() == Some(step) && {
            next.set(None);
            true
        }
    }) {
        bail!("injected native parity interruption after {step:?}");
    }
    #[cfg(test)]
    if std::env::var("MB_NATIVE_VOLUME_CRASH").ok().as_deref() == Some(format!("{step:?}").as_str())
    {
        unsafe {
            libc::_exit(75);
        }
    }
    let _ = step;
    Ok(())
}

#[cfg(test)]
mod tests;
