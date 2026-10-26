//! Explicit native Node bootstrap and read-only admission. These local records
//! select managed SQL; they do not activate paged producers or adopt old stores.
use super::*;
use mb_core::NativeDatabaseIoPolicy;
use mb_store::{DatabaseDirectory, DatabaseOpenGuard, NativeDatabaseInspection};
use std::ffi::OsStr;

pub(crate) const PROFILE_FILE: &str = "native-storage.profile";
pub(crate) const READY_FILE: &str = "native-storage.ready";
const PROFILE_DOMAIN: &[u8] = b"mutualbackup/native-node-storage/v1";
const READY_DOMAIN: &[u8] = b"mutualbackup/native-node-ready/v1";
const PROFILE_KIND: &str = "native-node-profile";

/// Immutable per-catalog ceilings for explicit Linux Node creation. The
/// signed profile preserves these policies across ordinary opens and process
/// restarts. These ceilings do not supply the enclosing resource reservations
/// required before normal paged production can be enabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NativeNodeStoragePolicy {
    pub control: NativeDatabaseIoPolicy,
    pub default_parity: NativeDatabaseIoPolicy,
    pub parity_budget_bytes: u64,
}

impl NativeNodeStoragePolicy {
    fn validate(&self) -> Result<()> {
        self.control.validate()?;
        self.default_parity.validate()?;
        anyhow::ensure!(
            self.parity_budget_bytes > self.default_parity.headroom_bytes
                && self.parity_budget_bytes <= self.default_parity.main_bytes,
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
    policy: NativeNodeStoragePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Ready {
    version: u16,
    profile: [u8; 32],
    control_key: [u8; 32],
    parity_key: [u8; 32],
}

fn digest<T: Serialize>(value: &T) -> Result<[u8; 32]> {
    Ok(*blake3::hash(&canonical_bytes_bounded(value, MAX_LOCAL_MANIFEST_BYTES)?).as_bytes())
}

fn read_signed<T: Serialize + for<'a> Deserialize<'a>>(
    path: &Path,
    keys: &KeyMaterial,
    domain: &'static [u8],
) -> Result<Option<T>> {
    let Some(record): Option<SignedRecord<T>> = read_private_record_optional(path)? else {
        return Ok(None);
    };
    record.verify(domain)?;
    anyhow::ensure!(
        record.signer == keys.node_id(),
        "native Node profile has another owner"
    );
    Ok(Some(record.value))
}

fn profile(directory: &DatabaseDirectory, keys: &KeyMaterial) -> Result<Option<Profile>> {
    let result = read_signed::<Profile>(&directory.leaf(PROFILE_FILE)?, keys, PROFILE_DOMAIN)?;
    if let Some(profile) = &result {
        let m = directory.file().metadata()?;
        anyhow::ensure!(
            profile.version == 1
                && profile.parent == (m.dev(), m.ino())
                && !profile.volume_id.is_nil(),
            "native Node profile is incompatible or copied; preserve it and use explicit recovery/adoption"
        );
        profile.policy.validate()?;
    } else {
        anyhow::ensure!(
            !directory.leaf(READY_FILE)?.try_exists()?,
            "native Node profile is missing"
        );
    }
    Ok(result)
}

fn ready(
    directory: &DatabaseDirectory,
    keys: &KeyMaterial,
    profile: &Profile,
) -> Result<Option<Ready>> {
    let ready = read_signed::<Ready>(&directory.leaf(READY_FILE)?, keys, READY_DOMAIN)?;
    if let Some(ready) = &ready {
        anyhow::ensure!(
            ready.version == 1 && ready.profile == digest(profile)?,
            "native Node readiness differs from its original profile"
        );
    }
    Ok(ready)
}

fn external_key(
    directory: &DatabaseDirectory,
    inspection: &NativeDatabaseInspection,
) -> Result<()> {
    if let Some(envelope) =
        read_private_record_optional::<WrappedDatabaseKey>(&directory.leaf(CONTROL_KEY_FILE)?)?
    {
        anyhow::ensure!(
            &envelope == inspection.wrapped_key(),
            "native control.key conflicts with its managed birth"
        );
    }
    Ok(())
}

pub(crate) fn control_inspection(
    data_dir: &Path,
    keys: &KeyMaterial,
) -> Result<Option<NativeDatabaseInspection>> {
    if read_signed::<Profile>(&data_dir.join(PROFILE_FILE), keys, PROFILE_DOMAIN)?.is_none() {
        anyhow::ensure!(
            read_signed::<Ready>(&data_dir.join(READY_FILE), keys, READY_DOMAIN)?.is_none(),
            "native Node profile is missing"
        );
        return Ok(None);
    }
    let directory = DatabaseDirectory::open(data_dir)?;
    let Some(profile) = profile(&directory, keys)? else {
        return Ok(None);
    };
    let ready = ready(&directory, keys, &profile)?.context(
        "native Node creation is incomplete; resume create_native with its original storage policy",
    )?;
    let inspection = ControlStore::inspect_native_existing_in_directory(
        &directory,
        OsStr::new("control.db"),
        keys,
        b"control.db/v2",
    )?;
    anyhow::ensure!(
        inspection.policy() == profile.policy.control
            && digest(inspection.wrapped_key())? == ready.control_key,
        "native control birth differs from its Node profile"
    );
    external_key(&directory, &inspection)?;
    Ok(Some(inspection))
}

pub(crate) fn verify_control_profile(
    data_dir: &Path,
    keys: &KeyMaterial,
    control: &ControlStore,
) -> Result<()> {
    let directory = DatabaseDirectory::open(data_dir)?;
    let profile = profile(&directory, keys)?.context("native Node profile is missing")?;
    let ready = ready(&directory, keys, &profile)?.context("native Node creation is incomplete")?;
    anyhow::ensure!(
        control.get_record(PROFILE_KIND, b"ready")?.as_deref() == Some(ready.profile.as_slice()),
        "native Node SQL profile binding is missing or changed"
    );
    let records = load_volume_records(control)?;
    anyhow::ensure!(!records.is_empty(), "native Node volume registry is absent");
    for record in records {
        validate_volume_record(&record)?;
        keys.unwrap_native_database_key(
            &volume_database_id(record.volume_id),
            &record.wrapped_database_key,
        )?;
        if record.volume_id == profile.volume_id {
            anyhow::ensure!(
                digest(&record.wrapped_database_key)? == ready.parity_key,
                "native default parity key changed without managed rekey"
            );
        }
    }
    Ok(())
}

fn fresh(directory: &DatabaseDirectory) -> Result<()> {
    for base in ["control.db", "parity.db"] {
        mb_store::NativeDatabaseOwner::require_unmanaged_path(directory.leaf(base)?)?;
        for suffix in ["", "-wal", "-shm", "-journal"] {
            anyhow::ensure!(
                !directory.leaf(format!("{base}{suffix}"))?.try_exists()?,
                "native Node creation never enrolls an existing database"
            );
        }
    }
    for name in [CONTROL_KEY_FILE, VOLUME_MANIFEST_FILE, READY_FILE] {
        anyhow::ensure!(
            !directory.leaf(name)?.try_exists()?,
            "native Node creation found existing key/volume/readiness state"
        );
    }
    Ok(())
}

fn inspect_creation_control(
    directory: &DatabaseDirectory,
    keys: &KeyMaterial,
    profile: &Profile,
) -> Result<Option<(NativeDatabaseInspection, DatabaseOpenGuard)>> {
    let inspection = ControlStore::inspect_native_creation_in_directory(
        directory,
        OsStr::new("control.db"),
        keys,
        b"control.db/v2",
        profile.policy.control,
    )?;
    let Some(inspection) = inspection else {
        return Ok(None);
    };
    external_key(directory, &inspection)?;
    let path = directory.leaf("control.db")?;
    let guard = creation_guard(&path)?;
    if fs::metadata(&path)?.len() == 0 {
        anyhow::ensure!(
            !inspection.is_ready(),
            "completed native control catalog is empty"
        );
        return Ok(Some((inspection, guard)));
    }
    let (reader, inputs) =
        ControlStore::inspect_native_creation_snapshot(&path, inspection.database_key())?;
    if let Some(reader) = reader {
        reader.with_read_only_snapshot(|| {
            reader.verify_open_guard(&guard)?;
            crate::source_policy::require_native_source_state(&reader, keys)?;
            if inspection.is_ready() {
                inspection.verify_control(&reader)?;
            }
            Ok(())
        })?;
        inputs.verify_unchanged()?;
        inspection.verify_current()?;
        guard.verify_unchanged(&path)?;
        return Ok(Some((inspection, guard)));
    }
    inputs.verify_unchanged()?;
    inspection.verify_current()?;
    guard.verify_unchanged(&path)?;
    anyhow::ensure!(
        !inspection.is_ready(),
        "completed native control catalog has no schema"
    );
    Ok(Some((inspection, guard)))
}

fn creation_guard(path: &Path) -> Result<DatabaseOpenGuard> {
    Ok(DatabaseOpenGuard::capture_native_creation(
        path,
        &[
            OsStr::new(CONTROL_KEY_FILE),
            OsStr::new(PROFILE_FILE),
            OsStr::new(READY_FILE),
        ],
    )?)
}

pub(crate) fn control_guard(path: &Path) -> Result<DatabaseOpenGuard> {
    Ok(DatabaseOpenGuard::capture(
        path,
        &[
            OsStr::new(CONTROL_KEY_FILE),
            OsStr::new(PROFILE_FILE),
            OsStr::new(READY_FILE),
        ],
    )?)
}

pub(crate) fn preflight_create(
    data_dir: &Path,
    keys: &KeyMaterial,
    policy: NativeNodeStoragePolicy,
) -> Result<()> {
    policy.validate()?;
    if !data_dir.try_exists()? {
        return Ok(());
    }
    let directory = DatabaseDirectory::open(data_dir)?;
    match profile(&directory, keys)? {
        None => fresh(&directory),
        Some(profile) => {
            anyhow::ensure!(
                profile.policy == policy,
                "native Node policy is immutable during creation/restart"
            );
            if ready(&directory, keys, &profile)?.is_some() {
                crate::source_policy::require_native_source_state_from_catalog(data_dir, keys)
            } else {
                inspect_creation_control(&directory, keys, &profile)?;
                Ok(())
            }
        }
    }
}

pub(crate) fn prepare(
    directory: &DatabaseDirectory,
    data_dir: &Path,
    keys: &KeyMaterial,
    policy: NativeNodeStoragePolicy,
) -> Result<()> {
    preflight_create(data_dir, keys, policy)?;
    let profile = match profile(directory, keys)? {
        Some(profile) => profile,
        None => {
            let m = directory.file().metadata()?;
            let profile = Profile {
                version: 1,
                parent: (m.dev(), m.ino()),
                volume_id: Uuid::new_v4(),
                policy,
            };
            let signed = SignedRecord::sign(PROFILE_DOMAIN, profile.clone(), keys)?;
            write_new_private_record_at(
                directory.file(),
                c"native-storage.profile",
                &canonical_bytes_bounded(&signed, MAX_LOCAL_MANIFEST_BYTES)?,
            )?;
            interruption(Step::Profile)?;
            profile
        }
    };
    if ready(directory, keys, &profile)?.is_some() {
        return Ok(());
    }
    let creation_admission = creation_guard(&directory.leaf("control.db")?)?;
    let inspected = inspect_creation_control(directory, keys, &profile)?;
    #[cfg(test)]
    BEFORE_CONTROL_CREATION_WRITER.with(|hook| {
        if let Some(operation) = hook.borrow_mut().take() {
            operation();
        }
    });
    let control = match inspected {
        Some((inspection, guard)) => inspection.resume_control_admitted(directory, keys, &guard)?,
        None => ControlStore::create_native_admitted_in_directory(
            directory,
            OsStr::new("control.db"),
            keys,
            b"control.db/v2",
            policy.control,
            &creation_admission,
        )?,
    };
    interruption(Step::Control)?;
    let parity = ParityStore::create_native_in_directory(
        directory,
        OsStr::new("parity.db"),
        profile.volume_id.as_bytes(),
        keys,
        &volume_database_id(profile.volume_id),
        policy.default_parity,
    )?;
    interruption(Step::Parity)?;
    let manifest = VolumeManifest {
        format_version: 1,
        owner: keys.node_id(),
        volume_id: profile.volume_id,
        database_file: "parity.db".to_owned(),
        wrapped_database_key: parity
            .native_database_owner()
            .context("native parity owner is missing")?
            .wrapped_key()
            .clone(),
    };
    match read_volume_manifest(&directory.path(), keys)? {
        Some(existing) => anyhow::ensure!(
            existing == manifest,
            "native parity manifest conflicts with its creation"
        ),
        None => {
            let signed = SignedRecord::sign(VOLUME_MANIFEST_DOMAIN, manifest.clone(), keys)?;
            write_new_private_record_at(
                directory.file(),
                c".mutualbackup-volume",
                &canonical_bytes_bounded(&signed, MAX_LOCAL_MANIFEST_BYTES)?,
            )?;
        }
    }
    interruption(Step::Manifest)?;
    let record = VolumeRecord {
        format_version: 1,
        volume_id: profile.volume_id,
        path: data_dir.to_owned(),
        database_file: "parity.db".to_owned(),
        wrapped_database_key: manifest.wrapped_database_key.clone(),
        state: StorageVolumeState::Online,
        budget_bytes: policy.parity_budget_bytes,
        headroom_bytes: policy.default_parity.headroom_bytes,
        last_error: None,
        configured: true,
    };
    #[cfg(test)]
    BEFORE_REGISTRY_PUBLICATION.with(|hook| {
        if let Some(operation) = hook.borrow_mut().take() {
            operation(&control);
        }
    });
    let records = load_volume_records(&control)?;
    anyhow::ensure!(
        records.is_empty() || records == [record.clone()],
        "unfinished native Node has unexpected volume ownership"
    );
    control.with_record_transaction(|| -> Result<()> {
        store_volume_records_in_transaction(&control, &[record])?;
        let bytes = digest(&profile)?;
        let existing = control.get_record(PROFILE_KIND, b"ready")?;
        anyhow::ensure!(
            existing.as_deref().is_none_or(|prior| prior == bytes),
            "native Node SQL profile differs"
        );
        control.put_record(PROFILE_KIND, b"ready", &bytes)?;
        anyhow::ensure!(
            control.get_record(PROFILE_KIND, b"ready")?.as_deref() == Some(bytes.as_slice()),
            "native Node profile publication was ignored"
        );
        Ok(())
    })?;
    interruption(Step::Registry)?;
    let ready = Ready {
        version: 1,
        profile: digest(&profile)?,
        control_key: digest(
            control
                .native_database_owner()
                .context("native control owner is missing")?
                .wrapped_key(),
        )?,
        parity_key: digest(&manifest.wrapped_database_key)?,
    };
    let signed = SignedRecord::sign(READY_DOMAIN, ready, keys)?;
    write_new_private_record_at(
        directory.file(),
        c"native-storage.ready",
        &canonical_bytes_bounded(&signed, MAX_LOCAL_MANIFEST_BYTES)?,
    )?;
    interruption(Step::Ready)?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Step {
    Profile,
    Control,
    Parity,
    Manifest,
    Registry,
    Ready,
}
#[cfg(test)]
type RegistryPublicationHook = Box<dyn FnOnce(&ControlStore)>;

#[cfg(test)]
thread_local! {
    static INTERRUPT: std::cell::Cell<Option<Step>> = const { std::cell::Cell::new(None) };
    static BEFORE_CONTROL_CREATION_WRITER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static BEFORE_REGISTRY_PUBLICATION: std::cell::RefCell<Option<RegistryPublicationHook>> = const { std::cell::RefCell::new(None) };
}
fn interruption(step: Step) -> Result<()> {
    #[cfg(test)]
    if INTERRUPT.with(|next| {
        next.get() == Some(step) && {
            next.set(None);
            true
        }
    }) {
        bail!("injected native Node interruption after {step:?}");
    }
    #[cfg(test)]
    if std::env::var("MB_NATIVE_NODE_CRASH").ok().as_deref() == Some(format!("{step:?}").as_str()) {
        unsafe {
            libc::_exit(74);
        }
    }
    let _ = step;
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests;
