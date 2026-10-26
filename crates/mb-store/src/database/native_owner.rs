//! Durable ownership for newly born native SQL catalogs. Signed, immutable
//! records bind the policy/key, held parent/lease directories and main inode.
//! This is deliberately not enrollment or automatic adoption of old/copy input.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use mb_core::{
    KeyMaterial, NativeDatabaseIoPolicy, SignedRecord, WrappedDatabaseKey, canonical_bytes_bounded,
    decode_canonical,
};
use rand::RngCore;
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use zeroize::Zeroizing;

use super::{
    ControlStore, DatabaseDirectory, DatabaseError, DatabasePhysicalIoLimits, ParityStore,
};

const BIRTH_DOMAIN: &[u8] = b"mutualbackup/native-database-birth/v1";
const MAIN_DOMAIN: &[u8] = b"mutualbackup/native-database-main/v1";
const READY_DOMAIN: &[u8] = b"mutualbackup/native-database-ready/v1";
const MAX_RECORD: usize = 4096;
const SQL_MARKER: &str = super::NATIVE_IO_SQL_MARKER;
type Identity = (u64, u64);
static OWNERS: Mutex<BTreeMap<Identity, Weak<OwnerState>>> = Mutex::new(BTreeMap::new());

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(super) enum Kind {
    Control,
    Parity([u8; 16]),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn of(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Birth {
    version: u16,
    parent: FileIdentity,
    lease: FileIdentity,
    main_name: Vec<u8>,
    database_id: Vec<u8>,
    kind: Kind,
    envelope: WrappedDatabaseKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Main {
    version: u16,
    birth: [u8; 32],
    identity: FileIdentity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct Ready {
    version: u16,
    birth: [u8; 32],
    main: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Version {
    identity: FileIdentity,
    length: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Version {
    fn of(metadata: &fs::Metadata) -> Result<Self, DatabaseError> {
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.len() > MAX_RECORD as u64
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        Ok(Self {
            identity: FileIdentity::of(metadata),
            length: metadata.len(),
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

struct Record {
    name: &'static CStr,
    pin: File,
    version: Version,
}

/// A live claim retained by native connections and reusable reader handles.
/// It is local filesystem authority, not a dataset/guild or enclosing resource
/// reservation. Existing/copy adoption and managed rekey remain separate work.
#[derive(Clone)]
pub struct NativeDatabaseOwner(pub(super) Arc<OwnerState>);

/// Authenticated, pinned admission evidence. Inspection holds no writable lease
/// or allocation credits; the admitted opener rechecks it before native SQL.
#[derive(Clone)]
pub struct NativeDatabaseInspection(Arc<OwnerState>);

pub(super) struct OwnerState {
    pub(super) directory: DatabaseDirectory,
    pub(super) name: OsString,
    lease_name: OsString,
    lease: DatabaseDirectory,
    claim: Option<File>,
    parent_id: FileIdentity,
    lease_id: FileIdentity,
    main: File,
    main_id: FileIdentity,
    birth: Birth,
    birth_hash: [u8; 32],
    main_hash: [u8; 32],
    key: Zeroizing<[u8; 32]>,
    policy: NativeDatabaseIoPolicy,
    records: Mutex<Vec<Record>>,
    ready: AtomicBool,
    pid: u32,
}

fn invalid<E>(_: E) -> DatabaseError {
    DatabaseError::NativeOwnershipInvalid
}

pub(super) fn lease_name(name: &OsStr) -> OsString {
    format!(
        ".mutualbackup-native-{}",
        blake3::hash(name.as_bytes()).to_hex()
    )
    .into()
}

/// Generic writable constructors must not silently discard a managed policy.
/// Read-only/preserved readers deliberately do not call this check.
pub(super) fn reject_managed_path(path: &Path) -> Result<(), DatabaseError> {
    let parent = path.parent().ok_or(DatabaseError::Conflict)?;
    let name = path.file_name().ok_or(DatabaseError::Conflict)?;
    match fs::symlink_metadata(parent.join(lease_name(name))) {
        Ok(_) => Err(DatabaseError::NativeOwnershipRequired),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn pin(path: &Path) -> Result<File, DatabaseError> {
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, DatabaseError> {
    canonical_bytes_bounded(value, MAX_RECORD).map_err(invalid)
}

fn publish(directory: &DatabaseDirectory, name: &CStr, bytes: &[u8]) -> Result<(), DatabaseError> {
    if bytes.len() > MAX_RECORD {
        return Err(DatabaseError::NativeOwnershipInvalid);
    }
    let descriptor = unsafe {
        libc::openat(
            directory.file().as_raw_fd(),
            c".".as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600 as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let source = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).map_err(invalid)?;
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            source.as_ptr(),
            directory.file().as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    directory.file().sync_all()?;
    Ok(())
}

fn read<T: Serialize + DeserializeOwned>(
    directory: &DatabaseDirectory,
    name: &'static CStr,
    keys: &KeyMaterial,
    domain: &'static [u8],
) -> Result<(T, Vec<u8>, Record), DatabaseError> {
    let path = directory.leaf(OsStr::from_bytes(name.to_bytes()))?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOATIME)
        .open(&path)?;
    let version = Version::of(&file.metadata()?)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(MAX_RECORD as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_RECORD || Version::of(&file.metadata()?)? != version {
        return Err(DatabaseError::NativeOwnershipInvalid);
    }
    let signed: SignedRecord<T> = decode_canonical(&bytes).map_err(invalid)?;
    signed.verify(domain).map_err(invalid)?;
    if signed.signer != keys.node_id() || encode(&signed)? != bytes {
        return Err(DatabaseError::NativeOwnershipInvalid);
    }
    let held = pin(&path)?;
    if Version::of(&held.metadata()?)? != version {
        return Err(DatabaseError::NativeOwnershipInvalid);
    }
    Ok((
        signed.value,
        bytes,
        Record {
            name,
            pin: held,
            version,
        },
    ))
}

fn exists(directory: &DatabaseDirectory, name: &OsStr) -> Result<bool, DatabaseError> {
    match fs::symlink_metadata(directory.leaf(name)?) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn family_absent(directory: &DatabaseDirectory, name: &OsStr) -> Result<(), DatabaseError> {
    for suffix in ["", "-wal", "-shm", "-journal"] {
        let mut leaf = name.to_owned();
        leaf.push(suffix);
        if exists(directory, &leaf)? {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
    }
    Ok(())
}

fn native_filesystem(directory: &DatabaseDirectory) -> Result<(), DatabaseError> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(directory.file().as_raw_fd(), info.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let kind = unsafe { info.assume_init() }.f_type as u32;
    if ![
        libc::BTRFS_SUPER_MAGIC as u32,
        libc::EXT4_SUPER_MAGIC as u32,
        0x5846_5342,
    ]
    .contains(&kind)
    {
        return Err(DatabaseError::PhysicalIoUnavailable);
    }
    Ok(())
}

impl OwnerState {
    fn begin(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
        kind: Kind,
        create: Option<NativeDatabaseIoPolicy>,
    ) -> Result<Arc<Self>, DatabaseError> {
        let path = directory.leaf(name)?;
        native_filesystem(directory)?;
        if database_id.is_empty() || database_id.len() > 256 {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        if let Some(policy) = create {
            policy.validate().map_err(invalid)?;
        }
        let lease_name = lease_name(name);
        let lease_path = directory.leaf(&lease_name)?;
        if !exists(directory, &lease_name)? {
            if create.is_none() {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            family_absent(directory, name)?;
            match fs::DirBuilder::new().mode(0o700).create(&lease_path) {
                Ok(()) => directory.file().sync_all()?,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e.into()),
            }
        }
        let lease = DatabaseDirectory::open(&lease_path)?;
        if lease.file().metadata()?.mode() & 0o077 != 0 {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let parent_id = FileIdentity::of(&directory.file().metadata()?);
        let lease_id = FileIdentity::of(&lease.file().metadata()?);
        let mut owners = OWNERS.lock().map_err(invalid)?;
        owners.retain(|_, state| state.strong_count() != 0);
        if let Some(state) = owners
            .get(&(lease_id.device, lease_id.inode))
            .and_then(Weak::upgrade)
        {
            state.verify_current()?;
            if !state.ready.load(Ordering::Acquire) {
                return Err(DatabaseError::NativeOwnershipBusy);
            }
            if state.birth.database_id != database_id
                || state.birth.kind != kind
                || state.name != name
                || state.parent_id != parent_id
                || create.is_some_and(|policy| policy != state.policy)
            {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            // Authenticate the supplied seed even on a process-local reuse.
            let (key, policy) = keys
                .unwrap_native_database_key(database_id, &state.birth.envelope)
                .map_err(invalid)?;
            let key = Zeroizing::new(key);
            if *key != *state.key || policy != state.policy {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            // This live lease already admitted the catalog. Normal data writes
            // may change main/WAL versions while another connection opens;
            // they do not invalidate the immutable signed ownership records.
            // Each returned connection checks its SQL marker after opening.
            return Ok(state);
        }
        // Keep the claim on its own open description. Read-only directory
        // capabilities may be retained after an inspection; those must neither
        // retain nor unlock a later writer's flock.
        let claim = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&lease_path)?;
        if FileIdentity::of(&claim.metadata()?) != lease_id {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        if unsafe { libc::flock(claim.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            let e = std::io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(libc::EWOULDBLOCK) {
                DatabaseError::NativeOwnershipBusy
            } else {
                e.into()
            });
        }
        // The same open description keeps this lock until the state and every
        // native binding are gone. Never explicitly unlock a shared handle.
        if !exists(&lease, OsStr::new("birth"))? {
            let policy = create.ok_or(DatabaseError::NativeOwnershipInvalid)?;
            family_absent(directory, name)?;
            if fs::read_dir(lease.path())?.next().is_some() {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            rand::rngs::OsRng.fill_bytes(&mut *key);
            let birth = Birth {
                version: 1,
                parent: parent_id,
                lease: lease_id,
                main_name: name.as_bytes().to_vec(),
                database_id: database_id.to_vec(),
                kind,
                envelope: keys
                    .wrap_native_database_key(database_id, &key, &policy)
                    .map_err(invalid)?,
            };
            let signed = SignedRecord::sign(BIRTH_DOMAIN, birth, keys).map_err(invalid)?;
            publish(&lease, c"birth", &encode(&signed)?)?;
            interruption(Interruption::Birth)?;
        }
        let (birth, birth_bytes, _birth_record): (Birth, _, _) =
            read(&lease, c"birth", keys, BIRTH_DOMAIN)?;
        if birth.version != 1
            || birth.parent != parent_id
            || birth.lease != lease_id
            || birth.main_name != name.as_bytes()
            || birth.database_id != database_id
            || birth.kind != kind
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let (key, policy) = keys
            .unwrap_native_database_key(database_id, &birth.envelope)
            .map_err(invalid)?;
        let _key = Zeroizing::new(key);
        if create.is_some_and(|expected| expected != policy) {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let birth_hash = hash(&birth_bytes);
        let ready_exists = exists(&lease, OsStr::new("ready"))?;
        if create.is_none() && !ready_exists {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        if !exists(&lease, OsStr::new("main"))? {
            if create.is_none() || ready_exists {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            // SQL initialization is forbidden before this binding is synced.
            // Only a missing/empty, journal-free initial inode can be resumed.
            if exists(directory, name)? {
                let metadata = fs::symlink_metadata(&path)?;
                if !metadata.is_file() || metadata.len() != 0 || metadata.nlink() != 1 {
                    return Err(DatabaseError::NativeOwnershipInvalid);
                }
                if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
                    return Err(DatabaseError::NativeOwnershipInvalid);
                }
                for suffix in ["-wal", "-shm", "-journal"] {
                    let mut sibling = name.to_owned();
                    sibling.push(suffix);
                    if exists(directory, &sibling)? {
                        return Err(DatabaseError::NativeOwnershipInvalid);
                    }
                }
            } else {
                family_absent(directory, name)?;
                let file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)?;
                file.sync_all()?;
                directory.file().sync_all()?;
                interruption(Interruption::EmptyMain)?;
            }
            let main = Main {
                version: 1,
                birth: birth_hash,
                identity: FileIdentity::of(&fs::symlink_metadata(&path)?),
            };
            let signed = SignedRecord::sign(MAIN_DOMAIN, main, keys).map_err(invalid)?;
            publish(&lease, c"main", &encode(&signed)?)?;
            interruption(Interruption::MainBinding)?;
        }
        let state = Self::read_bound(directory, name, keys, database_id, kind, Some(claim), false)?;
        if state.birth_hash != birth_hash || state.policy != policy {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        state.verify_current()?;
        if state.ready.load(Ordering::Acquire) {
            state.preflight_sql()?;
        }
        // Register partial creation too: a second in-process opener must not
        // acquire the same directory's reused open description and its flock.
        owners.insert((lease_id.device, lease_id.inode), Arc::downgrade(&state));
        Ok(state)
    }

    fn read_bound(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
        kind: Kind,
        claim: Option<File>,
        require_ready: bool,
    ) -> Result<Arc<Self>, DatabaseError> {
        let path = directory.leaf(name)?;
        native_filesystem(directory)?;
        let lease_name = lease_name(name);
        let lease = DatabaseDirectory::open(&directory.leaf(&lease_name)?)?;
        let parent_id = FileIdentity::of(&directory.file().metadata()?);
        let lease_id = FileIdentity::of(&lease.file().metadata()?);
        let (birth, birth_bytes, birth_record): (Birth, _, _) =
            read(&lease, c"birth", keys, BIRTH_DOMAIN)?;
        if birth.version != 1
            || birth.parent != parent_id
            || birth.lease != lease_id
            || birth.main_name != name.as_bytes()
            || birth.database_id != database_id
            || birth.kind != kind
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let (key, policy) = keys
            .unwrap_native_database_key(database_id, &birth.envelope)
            .map_err(invalid)?;
        let key = Zeroizing::new(key);
        let birth_hash = hash(&birth_bytes);
        let ready_exists = exists(&lease, OsStr::new("ready"))?;
        if require_ready && !ready_exists {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let (main, main_bytes, main_record): (Main, _, _) =
            read(&lease, c"main", keys, MAIN_DOMAIN)?;
        if main.version != 1 || main.birth != birth_hash {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let main_pin = pin(&path)?;
        let metadata = main_pin.metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || FileIdentity::of(&metadata) != main.identity
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let main_hash = hash(&main_bytes);
        let mut records = vec![birth_record, main_record];
        if ready_exists {
            let (ready, _, record): (Ready, _, _) = read(&lease, c"ready", keys, READY_DOMAIN)?;
            if ready
                != (Ready {
                    version: 1,
                    birth: birth_hash,
                    main: main_hash,
                })
            {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            records.push(record);
        }
        for entry in fs::read_dir(lease.path())? {
            let name = entry?.file_name();
            if ![b"birth".as_slice(), b"main", b"ready"].contains(&name.as_bytes()) {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
        }
        let state = Arc::new(Self {
            directory: directory.clone(),
            name: name.to_owned(),
            lease_name,
            lease,
            claim,
            parent_id,
            lease_id,
            main: main_pin,
            main_id: main.identity,
            birth,
            birth_hash,
            main_hash,
            key,
            policy,
            records: Mutex::new(records),
            ready: AtomicBool::new(ready_exists),
            pid: std::process::id(),
        });
        state.verify_current()?;
        Ok(state)
    }

    pub(super) fn verify_current(&self) -> Result<(), DatabaseError> {
        if self.pid != std::process::id() {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let parent = self.directory.file().metadata()?;
        let lease = self.lease.file().metadata()?;
        if let Some(claim) = &self.claim
            && FileIdentity::of(&claim.metadata()?) != self.lease_id
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let visible =
            fs::symlink_metadata(self.directory.leaf(&self.lease_name)?).map_err(invalid)?;
        let main = self.main.metadata()?;
        let visible_main =
            fs::symlink_metadata(self.directory.leaf(&self.name)?).map_err(invalid)?;
        if FileIdentity::of(&parent) != self.parent_id
            || parent.nlink() == 0
            || parent.uid() != unsafe { libc::geteuid() }
            || parent.mode() & 0o022 != 0
            || !visible.is_dir()
            || FileIdentity::of(&visible) != self.lease_id
            || FileIdentity::of(&lease) != self.lease_id
            || lease.uid() != parent.uid()
            || lease.mode() & 0o077 != 0
            || !main.is_file()
            || main.nlink() != 1
            || main.uid() != parent.uid()
            || main.mode() & 0o077 != 0
            || FileIdentity::of(&main) != self.main_id
            || !visible_main.is_file()
            || FileIdentity::of(&visible_main) != self.main_id
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        for record in self.records.lock().map_err(invalid)?.iter() {
            let path = self.lease.leaf(OsStr::from_bytes(record.name.to_bytes()))?;
            if Version::of(&record.pin.metadata()?)? != record.version
                || Version::of(&fs::symlink_metadata(path).map_err(invalid)?)? != record.version
            {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
        }
        Ok(())
    }

    pub(super) fn identity(&self) -> Identity {
        (self.lease_id.device, self.lease_id.inode)
    }
    pub(super) fn require_claim(&self) -> Result<(), DatabaseError> {
        if self.claim.is_none() {
            return Err(DatabaseError::NativeOwnershipRequired);
        }
        self.verify_current()
    }
    pub(super) fn main_identity(&self) -> Identity {
        (self.main_id.device, self.main_id.inode)
    }
    pub(super) fn limits(&self) -> DatabasePhysicalIoLimits {
        DatabasePhysicalIoLimits {
            main_bytes: self.policy.main_bytes,
            journal_bytes: self.policy.journal_bytes,
            shm_bytes: self.policy.shm_bytes,
            temporary_bytes: self.policy.temporary_bytes,
            total_bytes: self.policy.total_bytes,
            headroom_bytes: self.policy.headroom_bytes,
            files: self.policy.files,
        }
    }
    pub(super) fn key(&self) -> &[u8; 32] {
        &self.key
    }

    fn marker(&self, connection: &Connection, initialize: bool) -> Result<(), DatabaseError> {
        let current: Option<Option<Vec<u8>>> = connection.query_row(
            "SELECT CASE WHEN typeof(value)='blob' AND length(value)=32 THEN value ELSE NULL END FROM meta WHERE key=?1",
            [SQL_MARKER], |r| r.get(0),
        ).optional()?;
        if current.as_ref().and_then(|v| v.as_deref()) == Some(self.birth_hash.as_slice()) {
            return Ok(());
        }
        if current.is_some() || !initialize || self.ready.load(Ordering::Acquire) {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let tx = Transaction::new_unchecked(connection, TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO meta(key,value) VALUES (?1,?2)",
            rusqlite::params![SQL_MARKER, self.birth_hash.as_slice()],
        )?;
        interruption(Interruption::MarkerWrite)?;
        if super::meta_value(&tx, SQL_MARKER)?.as_deref() != Some(self.birth_hash.as_slice()) {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        tx.commit()?;
        Ok(())
    }

    fn preflight_sql(&self) -> Result<(), DatabaseError> {
        let path = self.directory.leaf(&self.name)?;
        let mut rollback_name = self.name.clone();
        rollback_name.push("-journal");
        if exists(&self.directory, &rollback_name)? {
            // The preserved reader deliberately cannot replay rollback input.
            // Original signed birth/main/ready evidence and the held lease
            // authorize native recovery here, under the unchanged file-family
            // limits. The returned connection must still verify its SQL marker
            // after recovery; no generic/copy enrollment is inferred.
            return self.verify_current();
        }
        match self.birth.kind {
            Kind::Control => {
                let (store, guard) =
                    ControlStore::open_preserved_read_only_with_keys(&path, &[*self.key])
                        .map_err(invalid)?;
                self.marker(&store.connection, false)?;
                guard.verify_unchanged().map_err(invalid)?;
            }
            Kind::Parity(volume) => {
                let (store, guard) =
                    ParityStore::open_preserved_read_only_with_keys(&path, &volume, &[*self.key])
                        .map_err(invalid)?;
                self.marker(&store.connection, false)?;
                guard.verify_unchanged().map_err(invalid)?;
            }
        }
        self.verify_current()
    }

    fn finish(&self, keys: &KeyMaterial) -> Result<(), DatabaseError> {
        if self.ready.load(Ordering::Acquire) {
            return self.verify_current();
        }
        self.verify_current()?;
        let ready = Ready {
            version: 1,
            birth: self.birth_hash,
            main: self.main_hash,
        };
        let signed = SignedRecord::sign(READY_DOMAIN, ready, keys).map_err(invalid)?;
        publish(&self.lease, c"ready", &encode(&signed)?)?;
        let (_, _, record): (Ready, _, _) = read(&self.lease, c"ready", keys, READY_DOMAIN)?;
        self.records.lock().map_err(invalid)?.push(record);
        self.ready.store(true, Ordering::Release);
        interruption(Interruption::Ready)?;
        self.verify_current()
    }
}

impl NativeDatabaseOwner {
    pub fn parity_volume_id(&self) -> Option<[u8; 16]> {
        match self.0.birth.kind {
            Kind::Parity(id) => Some(id),
            Kind::Control => None,
        }
    }
    /// Mutable product preflight must run before key publication, directory
    /// permission changes or lock creation, including a birth with no main yet.
    pub fn require_unmanaged_path(path: impl AsRef<Path>) -> Result<(), DatabaseError> {
        reject_managed_path(path.as_ref())
    }

    /// Recover an authenticated key/policy without taking or inferring writable
    /// ownership. Copies and relocated records remain readable; their signed
    /// physical identities are deliberately not adopted by this operation.
    pub fn recovery_key(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
    ) -> Result<([u8; 32], NativeDatabaseIoPolicy), DatabaseError> {
        let lease = DatabaseDirectory::open(&directory.leaf(lease_name(name))?)?;
        let (birth, _, _): (Birth, _, _) = read(&lease, c"birth", keys, BIRTH_DOMAIN)?;
        if birth.version != 1
            || birth.main_name != name.as_bytes()
            || birth.database_id != database_id
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        keys.unwrap_native_database_key(database_id, &birth.envelope)
            .map_err(invalid)
    }

    pub fn policy(&self) -> NativeDatabaseIoPolicy {
        self.0.policy
    }
    pub fn wrapped_key(&self) -> &WrappedDatabaseKey {
        &self.0.birth.envelope
    }
    pub fn verify_current(&self) -> Result<(), DatabaseError> {
        self.0.verify_current()
    }

    pub fn open_control(&self) -> Result<ControlStore, DatabaseError> {
        if self.0.birth.kind != Kind::Control || !self.0.ready.load(Ordering::Acquire) {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        self.verify_current()?;
        let store = ControlStore::open_owned_native(&self.0)?;
        self.0.marker(&store.connection, false)?;
        Ok(store)
    }

    pub fn open_parity(&self) -> Result<ParityStore, DatabaseError> {
        let Kind::Parity(volume) = self.0.birth.kind else {
            return Err(DatabaseError::NativeOwnershipInvalid);
        };
        if !self.0.ready.load(Ordering::Acquire) {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        self.verify_current()?;
        let store = ParityStore::open_owned_native(&self.0, &volume)?;
        self.0.marker(&store.connection, false)?;
        Ok(store)
    }
}

impl NativeDatabaseInspection {
    pub fn is_ready(&self) -> bool {
        self.0.ready.load(Ordering::Acquire)
    }
    pub fn verify_current(&self) -> Result<(), DatabaseError> {
        self.0.verify_current()
    }
    pub fn policy(&self) -> NativeDatabaseIoPolicy {
        self.0.policy
    }
    pub fn wrapped_key(&self) -> &WrappedDatabaseKey {
        &self.0.birth.envelope
    }
    pub fn database_key(&self) -> &[u8; 32] {
        self.0.key()
    }

    pub fn verify_control(&self, store: &ControlStore) -> Result<(), DatabaseError> {
        if self.0.birth.kind != Kind::Control {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        self.0.marker(&store.connection, false)?;
        self.verify_current()
    }

    pub fn verify_parity(&self, store: &ParityStore) -> Result<(), DatabaseError> {
        if !matches!(self.0.birth.kind, Kind::Parity(_)) {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        self.0.marker(&store.connection, false)?;
        self.verify_current()
    }

    fn claim_admitted(
        &self,
        directory: &DatabaseDirectory,
        keys: &KeyMaterial,
        guard: &super::DatabaseOpenGuard,
        resume: bool,
    ) -> Result<Arc<OwnerState>, DatabaseError> {
        self.verify_current()?;
        if (!resume && !self.is_ready())
            || FileIdentity::of(&directory.file().metadata()?) != self.0.parent_id
            || !guard.requires_existing_catalog()
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let path = directory.leaf(&self.0.name)?;
        guard.verify_unchanged(&path)?;
        let state = OwnerState::begin(
            directory,
            &self.0.name,
            keys,
            &self.0.birth.database_id,
            self.0.birth.kind,
            resume.then_some(self.0.policy),
        )?;
        if state.birth_hash != self.0.birth_hash
            || state.main_hash != self.0.main_hash
            || state.identity() != self.0.identity()
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        self.verify_current()?;
        guard.verify_unchanged(&path)?;
        Ok(state)
    }

    /// Consume a read-only policy/source admission before any native SQL
    /// recovery, journal-mode change or schema migration. Native xOpen checks
    /// the same guard again against its actual opened main descriptor.
    pub fn open_control_admitted(
        &self,
        directory: &DatabaseDirectory,
        keys: &KeyMaterial,
        guard: &super::DatabaseOpenGuard,
    ) -> Result<ControlStore, DatabaseError> {
        if self.0.birth.kind != Kind::Control {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let state = self.claim_admitted(directory, keys, guard, false)?;
        let store = ControlStore::open_owned_native_admitted(&state, guard)?;
        state.marker(&store.connection, false)?;
        self.verify_current()?;
        Ok(store)
    }

    pub fn open_parity_admitted(
        &self,
        directory: &DatabaseDirectory,
        keys: &KeyMaterial,
        guard: &super::DatabaseOpenGuard,
    ) -> Result<ParityStore, DatabaseError> {
        let Kind::Parity(volume) = self.0.birth.kind else {
            return Err(DatabaseError::NativeOwnershipInvalid);
        };
        let state = self.claim_admitted(directory, keys, guard, false)?;
        let store = ParityStore::open_owned_native_admitted(&state, &volume, guard)?;
        state.marker(&store.connection, false)?;
        self.verify_current()?;
        Ok(store)
    }
    /// Resume an already inspected committed schema without dropping the
    /// source-admission guard while finishing the native birth.
    pub fn resume_control_admitted(
        &self,
        directory: &DatabaseDirectory,
        keys: &KeyMaterial,
        guard: &super::DatabaseOpenGuard,
    ) -> Result<ControlStore, DatabaseError> {
        if self.0.birth.kind != Kind::Control {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let state = self.claim_admitted(directory, keys, guard, true)?;
        let store = ControlStore::open_owned_native_admitted(&state, guard)?;
        state.marker(&store.connection, true)?;
        state.finish(keys)?;
        self.verify_current()?;
        Ok(store)
    }
}

impl ControlStore {
    /// Read-only preflight for an explicitly authorized fresh creation/resume.
    /// None means no SQL can yet have been initialized. Bound partial births
    /// return evidence for inspection of any already committed control schema.
    pub fn inspect_native_creation_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
        policy: NativeDatabaseIoPolicy,
    ) -> Result<Option<NativeDatabaseInspection>, DatabaseError> {
        policy.validate().map_err(invalid)?;
        let path = directory.leaf(name)?;
        if !exists(directory, &lease_name(name))? {
            family_absent(directory, name)?;
            return Ok(None);
        }
        let lease = DatabaseDirectory::open(&directory.leaf(lease_name(name))?)?;
        if !exists(&lease, OsStr::new("birth"))? {
            family_absent(directory, name)?;
            if fs::read_dir(lease.path())?.next().is_some() {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            return Ok(None);
        }
        let (birth, _, _): (Birth, _, _) = read(&lease, c"birth", keys, BIRTH_DOMAIN)?;
        if birth.version != 1
            || birth.parent != FileIdentity::of(&directory.file().metadata()?)
            || birth.lease != FileIdentity::of(&lease.file().metadata()?)
            || birth.kind != Kind::Control
            || birth.main_name != name.as_bytes()
            || birth.database_id != database_id
        {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        let (key, declared) = keys
            .unwrap_native_database_key(database_id, &birth.envelope)
            .map_err(invalid)?;
        let _key = Zeroizing::new(key);
        if declared != policy {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        if !exists(&lease, OsStr::new("main"))? {
            if exists(&lease, OsStr::new("ready"))? {
                return Err(DatabaseError::NativeOwnershipInvalid);
            }
            for suffix in ["-wal", "-shm", "-journal"] {
                let mut sibling = name.to_owned();
                sibling.push(suffix);
                if exists(directory, &sibling)? {
                    return Err(DatabaseError::NativeOwnershipInvalid);
                }
            }
            if exists(directory, name)? {
                let m = fs::symlink_metadata(path)?;
                if !m.is_file()
                    || m.len() != 0
                    || m.nlink() != 1
                    || m.uid() != unsafe { libc::geteuid() }
                    || m.mode() & 0o077 != 0
                {
                    return Err(DatabaseError::NativeOwnershipInvalid);
                }
            }
            return Ok(None);
        }
        let state = OwnerState::read_bound(
            directory,
            name,
            keys,
            database_id,
            Kind::Control,
            None,
            false,
        )?;
        if state.policy != policy {
            return Err(DatabaseError::NativeOwnershipInvalid);
        }
        Ok(Some(NativeDatabaseInspection(state)))
    }

    pub fn inspect_native_existing_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
    ) -> Result<NativeDatabaseInspection, DatabaseError> {
        Ok(NativeDatabaseInspection(OwnerState::read_bound(
            directory,
            name,
            keys,
            database_id,
            Kind::Control,
            None,
            true,
        )?))
    }
    /// Fresh/partial creation after read-only source admission. Recheck the
    /// original empty/absent main and private inputs before claiming ownership,
    /// and its actual opened descriptor before SQL initialization or recovery.
    pub fn create_native_admitted_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
        policy: NativeDatabaseIoPolicy,
        guard: &super::DatabaseOpenGuard,
    ) -> Result<Self, DatabaseError> {
        guard.verify_unchanged(&directory.leaf(name)?)?;
        let state = OwnerState::begin(
            directory,
            name,
            keys,
            database_id,
            Kind::Control,
            Some(policy),
        )?;
        let store = Self::open_owned_native_admitted(&state, guard)?;
        state.marker(&store.connection, true)?;
        state.finish(keys)?;
        Ok(store)
    }

    /// Create/resume a fresh native birth. Existing generic catalogs and copies
    /// are never enrolled. A completed birth is reopened with its original key
    /// and immutable limits; supplied policy changes reject before SQL writes.
    pub fn create_native_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
        policy: NativeDatabaseIoPolicy,
    ) -> Result<Self, DatabaseError> {
        let state = OwnerState::begin(
            directory,
            name,
            keys,
            database_id,
            Kind::Control,
            Some(policy),
        )?;
        let store = Self::open_owned_native(&state)?;
        interruption(Interruption::Schema)?;
        state.marker(&store.connection, true)?;
        interruption(Interruption::SqlMarker)?;
        state.finish(keys)?;
        Ok(store)
    }

    pub fn open_native_existing_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        keys: &KeyMaterial,
        database_id: &[u8],
    ) -> Result<Self, DatabaseError> {
        let state = OwnerState::begin(directory, name, keys, database_id, Kind::Control, None)?;
        NativeDatabaseOwner(state).open_control()
    }

    pub fn native_database_owner(&self) -> Option<NativeDatabaseOwner> {
        self.physical_vfs
            .as_ref()?
            .pool
            .owner
            .clone()
            .map(NativeDatabaseOwner)
    }
}

impl ParityStore {
    /// Fresh parity creation/resume while retaining the caller's pinned
    /// private creation/manifest inputs through the actual native descriptor.
    pub fn create_native_admitted_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        keys: &KeyMaterial,
        database_id: &[u8],
        policy: NativeDatabaseIoPolicy,
        guard: &super::DatabaseOpenGuard,
    ) -> Result<Self, DatabaseError> {
        guard.verify_unchanged(&directory.leaf(name)?)?;
        let state = OwnerState::begin(
            directory,
            name,
            keys,
            database_id,
            Kind::Parity(*volume),
            Some(policy),
        )?;
        let store = Self::open_owned_native_admitted(&state, volume, guard)?;
        interruption(Interruption::Schema)?;
        state.marker(&store.connection, true)?;
        interruption(Interruption::SqlMarker)?;
        state.finish(keys)?;
        Ok(store)
    }

    pub fn inspect_native_existing_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        keys: &KeyMaterial,
        database_id: &[u8],
    ) -> Result<NativeDatabaseInspection, DatabaseError> {
        Ok(NativeDatabaseInspection(OwnerState::read_bound(
            directory,
            name,
            keys,
            database_id,
            Kind::Parity(*volume),
            None,
            true,
        )?))
    }
    /// Fresh parity birth/resume under the same immutable native ownership
    /// protocol as control catalogs. No legacy key fallback or automatic copy
    /// adoption is permitted on this path.
    pub fn create_native_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        keys: &KeyMaterial,
        database_id: &[u8],
        policy: NativeDatabaseIoPolicy,
    ) -> Result<Self, DatabaseError> {
        let state = OwnerState::begin(
            directory,
            name,
            keys,
            database_id,
            Kind::Parity(*volume),
            Some(policy),
        )?;
        let store = Self::open_owned_native(&state, volume)?;
        interruption(Interruption::Schema)?;
        state.marker(&store.connection, true)?;
        interruption(Interruption::SqlMarker)?;
        state.finish(keys)?;
        Ok(store)
    }

    pub fn open_native_existing_in_directory(
        directory: &DatabaseDirectory,
        name: &OsStr,
        volume: &[u8; 16],
        keys: &KeyMaterial,
        database_id: &[u8],
    ) -> Result<Self, DatabaseError> {
        let state = OwnerState::begin(
            directory,
            name,
            keys,
            database_id,
            Kind::Parity(*volume),
            None,
        )?;
        NativeDatabaseOwner(state).open_parity()
    }

    pub fn native_database_owner(&self) -> Option<NativeDatabaseOwner> {
        self.physical_vfs
            .as_ref()?
            .pool
            .owner
            .clone()
            .map(NativeDatabaseOwner)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Interruption {
    Birth,
    EmptyMain,
    MainBinding,
    Schema,
    MarkerWrite,
    SqlMarker,
    Ready,
}

#[cfg(test)]
thread_local! {
    static INTERRUPT: std::cell::Cell<Option<Interruption>> = const { std::cell::Cell::new(None) };
}

fn interruption(point: Interruption) -> Result<(), DatabaseError> {
    #[cfg(test)]
    if std::env::var("MB_NATIVE_BIRTH_CRASH").ok().as_deref() == Some(format!("{point:?}").as_str())
    {
        // Actual process death skips Rust/SQLite destructors and preserves hot
        // WAL/rollback input. Only the explicitly selected child fixture sets it.
        unsafe {
            libc::_exit(73);
        }
    }
    #[cfg(test)]
    if INTERRUPT.with(|next| {
        next.get() == Some(point) && {
            next.set(None);
            true
        }
    }) {
        return Err(DatabaseError::Conflict);
    }
    let _ = point;
    Ok(())
}

#[cfg(test)]
mod tests;
