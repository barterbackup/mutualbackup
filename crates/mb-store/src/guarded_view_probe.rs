//! Disposable Linux FUSE passthrough probe for the future guarded worktree.
//!
//! This proves that this host can mount a view, pass read-only file access to
//! lower inodes, and finish each captured file's durable detach before a
//! writable open or metadata edit. It also probes a nested file namespace,
//! file rename, and unlink. It is not a complete long-lived edit guard and
//! must not be used as an enrollment decision by itself.

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, ensure};
use fuser::{
    BackingId, BsdFileFlags, Config, Errno, FileAttr, FileHandle, FileType, Filesystem, FopenFlags,
    Generation, INodeNo, InitFlags, KernelConfig, LockOwner, OpenAccMode, OpenFlags, RenameFlags,
    ReplyAttr, ReplyCreate, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, Request, SessionACL,
    TimeOrNow,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    CapturedEntry, ControlStore, GuardedRootCapturePlan, NativeFileId, PinnedDirectory,
    StableAnchorManifest,
};

const FILE_INODE: INodeNo = INodeNo(2);
const ENTRY_TTL: Duration = Duration::ZERO;
const PROBE_BYTES: &[u8] = b"mutualbackup-guarded-view-probe";
// The kernel supplies O_LARGEFILE in FUSE_OPEN even when libc defines it as
// zero for the native 64-bit ABI.
const KERNEL_O_LARGEFILE: i32 = 0o100000;
const NAMESPACE_KIND: &str = "guarded-view-namespace-v1";
const CREATE_KIND: &str = "guarded-view-create-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NamespaceRecord {
    version: u16,
    captured_path: String,
    expected: NativeFileId,
    current: Option<Vec<u8>>,
    // Some(None) is an unlink; Some(Some(path)) is a rename.
    pending: Option<Option<Vec<u8>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CreateIntent {
    version: u16,
    target: Vec<u8>,
    expected: NativeFileId,
}

struct GuardedNamespace {
    control: Arc<Mutex<ControlStore>>,
    anchor_id: Uuid,
    records: Mutex<HashMap<u64, NamespaceRecord>>,
}

impl GuardedNamespace {
    fn record_id(&self, inode: u64) -> Vec<u8> {
        let mut id = self.anchor_id.as_bytes().to_vec();
        id.extend_from_slice(&inode.to_le_bytes());
        id
    }

    fn store(&self, inode: u64, record: &NamespaceRecord) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(record).map_err(io::Error::other)?;
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record(NAMESPACE_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)
    }

    fn store_create(&self, inode: u64, intent: &CreateIntent) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(intent).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(CREATE_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded create inode already recorded",
            ));
        }
        Ok(())
    }

    fn finish_create(&self, inode: u64, intent: &CreateIntent) -> io::Result<()> {
        let record = NamespaceRecord {
            version: 1,
            captured_path: String::new(),
            expected: intent.expected,
            current: Some(intent.target.clone()),
            pending: None,
        };
        let bytes = mb_core::canonical_bytes(&record).map_err(io::Error::other)?;
        let id = self.record_id(inode);
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_records_and_delete(
                &[(NAMESPACE_KIND.to_owned(), id.clone(), bytes)],
                &[(CREATE_KIND.to_owned(), id)],
            )
            .map_err(io::Error::other)?;
        self.records.lock().unwrap().insert(inode, record);
        Ok(())
    }

    fn owned_records(&self, kind: &str) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
        let rows = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .records(kind)?;
        let mut owned = Vec::new();
        for (id, bytes) in rows {
            if id.starts_with(self.anchor_id.as_bytes()) {
                ensure!(id.len() == 24, "malformed guarded namespace record ID");
                let inode = u64::from_le_bytes(id[16..24].try_into()?);
                owned.push((inode, bytes));
            }
        }
        Ok(owned)
    }

    fn reconcile_creates(
        &self,
        lower_root: &PinnedDirectory,
        directories: &HashMap<PathBuf, INodeNo>,
        first_dynamic_inode: u64,
    ) -> anyhow::Result<()> {
        for (inode, bytes) in self.owned_records(CREATE_KIND)? {
            ensure!(
                inode >= first_dynamic_inode,
                "guarded create aliases captured inode"
            );
            let intent: CreateIntent = mb_core::decode_canonical(&bytes)?;
            ensure!(intent.version == 1, "unsupported guarded create intent");
            ensure!(
                intent.expected.filesystem_id == lower_root.identity()?.filesystem_id,
                "guarded create belongs to another filesystem"
            );
            let (path, _) = namespace_path(&intent.target, directories)?;
            let owned = namespace_parent(lower_root, &path)?;
            let parent = owned.as_ref().unwrap_or(lower_root);
            let id = self.record_id(inode);
            match parent.entry_identity(path.file_name().unwrap(), false)? {
                Some(actual) if actual == intent.expected => {
                    parent.sync_all()?;
                    self.finish_create(inode, &intent)?;
                }
                None => {
                    self.control
                        .lock()
                        .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
                        .delete_record_if_value(CREATE_KIND, &id, &bytes)?;
                }
                _ => anyhow::bail!("guarded create target changed before replay"),
            }
        }
        Ok(())
    }

    fn load_or_replay(
        &self,
        inode: u64,
        captured_path: &str,
        expected: NativeFileId,
        lower_root: &PinnedDirectory,
        directories: &HashMap<PathBuf, INodeNo>,
    ) -> anyhow::Result<Option<ProbeLocation>> {
        let bytes = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .get_record(NAMESPACE_KIND, &self.record_id(inode))?;
        let mut record = match bytes {
            Some(bytes) => mb_core::decode_canonical::<NamespaceRecord>(&bytes)?,
            None => NamespaceRecord {
                version: 1,
                captured_path: captured_path.to_owned(),
                expected,
                current: Some(captured_path.as_bytes().to_vec()),
                pending: None,
            },
        };
        ensure!(
            record.version == 1
                && record.captured_path == captured_path
                && record.expected == expected,
            "guarded namespace record does not match capture"
        );
        if let Some(target) = record.pending.clone() {
            let old = record
                .current
                .as_ref()
                .context("pending guarded namespace operation has no source")?;
            let (old_path, _) = namespace_path(old, directories)?;
            let old_owned = namespace_parent(lower_root, &old_path)?;
            let old_parent = old_owned.as_ref().unwrap_or(lower_root);
            let old_name = old_path.file_name().unwrap();
            let old_identity = old_parent.entry_identity(old_name, false)?;
            if let Some(target) = &target {
                let (new_path, _) = namespace_path(target, directories)?;
                ensure!(new_path != old_path, "guarded rename has identical paths");
                let new_owned = namespace_parent(lower_root, &new_path)?;
                let new_parent = new_owned.as_ref().unwrap_or(lower_root);
                let new_name = new_path.file_name().unwrap();
                let new_identity = new_parent.entry_identity(new_name, false)?;
                match (old_identity, new_identity) {
                    (Some(old_id), None) if old_id == expected => old_parent
                        .move_child_file_no_replace(old_name, expected, new_parent, new_name)?,
                    (None, Some(new_id)) if new_id == expected => {
                        // The syscall may have completed before a directory
                        // fsync failed. Finish both durability barriers before
                        // publishing the settled journal record.
                        old_parent.sync_all()?;
                        new_parent.sync_all()?;
                    }
                    _ => anyhow::bail!("guarded rename cannot be safely replayed"),
                }
            } else {
                match old_identity {
                    Some(old_id) if old_id == expected => {
                        old_parent.remove_child_file_if_identity(old_name, expected)?;
                    }
                    None => old_parent.sync_all()?,
                    _ => anyhow::bail!("guarded unlink cannot be safely replayed"),
                }
            }
            record.current = target;
            record.pending = None;
            self.store(inode, &record)?;
        }
        let location = match &record.current {
            Some(bytes) => {
                let (relative_path, parent) = namespace_path(bytes, directories)?;
                let owned = namespace_parent(lower_root, &relative_path)?;
                let lower = owned.as_ref().unwrap_or(lower_root);
                ensure!(
                    lower.entry_identity(relative_path.file_name().unwrap(), false)?
                        == Some(expected),
                    "guarded view file moved or changed after capture"
                );
                Some(ProbeLocation {
                    parent,
                    relative_path,
                })
            }
            None => None,
        };
        ensure!(
            self.records.lock().unwrap().insert(inode, record).is_none(),
            "duplicate guarded namespace inode"
        );
        Ok(location)
    }

    fn transition(
        &self,
        inode: u64,
        old: &Path,
        new: Option<&Path>,
        mutate: impl FnOnce(NativeFileId) -> io::Result<()>,
    ) -> io::Result<()> {
        let mut records = self.records.lock().unwrap();
        let record = records
            .get_mut(&inode)
            .ok_or_else(|| io::Error::other("missing guarded namespace record"))?;
        let old_bytes = old.as_os_str().as_bytes();
        if record.pending.is_some() || record.current.as_deref() != Some(old_bytes) {
            return Err(io::Error::other("guarded namespace record changed"));
        }
        let new_bytes = new.map(|path| path.as_os_str().as_bytes().to_vec());
        record.pending = Some(new_bytes.clone());
        if let Err(error) = self.store(inode, record) {
            record.pending = None;
            return Err(error);
        }
        mutate(record.expected)?;
        record.current = new_bytes;
        record.pending = None;
        self.store(inode, record)
    }
}

fn namespace_path(
    bytes: &[u8],
    directories: &HashMap<PathBuf, INodeNo>,
) -> anyhow::Result<(PathBuf, INodeNo)> {
    let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    ensure!(
        path.components()
            .all(|part| matches!(part, std::path::Component::Normal(_))),
        "invalid guarded namespace path"
    );
    let parent = path
        .parent()
        .context("guarded namespace path has no parent")?;
    let inode = *directories
        .get(parent)
        .context("guarded namespace parent is not captured")?;
    ensure!(
        path.file_name().is_some(),
        "guarded namespace name is empty"
    );
    Ok((path, inode))
}

fn namespace_parent(
    root: &PinnedDirectory,
    path: &Path,
) -> anyhow::Result<Option<PinnedDirectory>> {
    let parent = path
        .parent()
        .context("guarded namespace path has no parent")?;
    if parent.as_os_str().is_empty() {
        Ok(None)
    } else {
        Ok(Some(root.open_descendant_directory(parent)?))
    }
}

struct GuardedProbeFile {
    source: File,
    source_attr: Mutex<FileAttr>,
    location: Arc<Mutex<Option<ProbeLocation>>>,
    open_for_write: Option<Arc<dyn Fn(OpenAccMode) -> io::Result<File> + Send + Sync>>,
}

struct ProbeLocation {
    parent: INodeNo,
    relative_path: PathBuf,
}

struct GuardedProbeDirectory {
    attr: FileAttr,
    parent: INodeNo,
    name: OsString,
    relative_path: PathBuf,
}

/// Experimental FUSE view for a published guarded capture. Enrollment and
/// mount supervision remain gated until directory mutation coverage and the
/// remaining write paths are complete. The caller must keep the lower source
/// directory inaccessible to ordinary users while this view is mounted.
pub struct GuardedProbeView {
    files: HashMap<u64, Arc<GuardedProbeFile>>,
    dynamic_files: Mutex<HashMap<u64, Arc<GuardedProbeFile>>>,
    directories: HashMap<u64, GuardedProbeDirectory>,
    names: Mutex<HashMap<(u64, OsString), u64>>,
    lower_root: Option<crate::PinnedDirectory>,
    namespace: Option<GuardedNamespace>,
    root_uid: u32,
    root_gid: u32,
    root_perm: u16,
    poisoned: AtomicBool,
    next_handle: AtomicU64,
    next_inode: AtomicU64,
    denied_writable: Arc<AtomicU64>,
    backing: Mutex<HashMap<u64, ActiveBacking>>,
}

struct ActiveBacking {
    id: BackingId,
    mode: OpenAccMode,
    inode: INodeNo,
}

impl GuardedProbeFile {
    fn current_attr(&self) -> io::Result<FileAttr> {
        let metadata = self.source.metadata()?;
        let mut attr = self.source_attr.lock().unwrap();
        attr.size = metadata.len();
        attr.blocks = metadata.blocks();
        attr.nlink = metadata.nlink() as u32;
        Ok(*attr)
    }

    fn new_editable(
        source: File,
        inode: INodeNo,
        location: ProbeLocation,
        lower_root: &Path,
        view_uid: u32,
        view_gid: u32,
    ) -> io::Result<Self> {
        let mode = (source.metadata()?.permissions().mode() & 0o7777) as u16;
        let expected_inode = source.metadata()?.ino();
        let mut attr = probe_file_attr(&source, inode, mode)?;
        attr.uid = view_uid;
        attr.gid = view_gid;
        let location = Arc::new(Mutex::new(Some(location)));
        let location_for_open = Arc::clone(&location);
        let lower_root = lower_root.to_path_buf();
        let open_for_write: Arc<dyn Fn(OpenAccMode) -> io::Result<File> + Send + Sync> =
            Arc::new(move |mode| {
                let location = location_for_open
                    .lock()
                    .map_err(|_| io::Error::other("guarded location lock is poisoned"))?;
                let location = location
                    .as_ref()
                    .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                let opened = OpenOptions::new()
                    .read(mode == OpenAccMode::O_RDWR)
                    .write(true)
                    .open(lower_root.join(&location.relative_path))?;
                if opened.metadata()?.ino() != expected_inode {
                    return Err(io::Error::other(
                        "created guarded file changed after opening",
                    ));
                }
                Ok(opened)
            });
        Ok(Self {
            source,
            source_attr: Mutex::new(attr),
            location,
            open_for_write: Some(open_for_write),
        })
    }
}

impl GuardedProbeView {
    fn file(&self, inode: u64) -> Option<Arc<GuardedProbeFile>> {
        self.files
            .get(&inode)
            .cloned()
            .or_else(|| self.dynamic_files.lock().unwrap().get(&inode).cloned())
    }

    /// Rebuild the captured namespace and finish any interrupted file rename
    /// or unlink before serving the view.
    pub fn from_guarded_capture(
        manifest: &StableAnchorManifest,
        control: Arc<Mutex<ControlStore>>,
        view_uid: u32,
        view_gid: u32,
    ) -> anyhow::Result<Self> {
        let plan = {
            let control = control
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            GuardedRootCapturePlan::load_active_for_view(&control, manifest)?
        };
        let lower_root = PinnedDirectory::open(plan.source_root())?;
        ensure!(
            lower_root.identity()? == plan.source_root_identity(),
            "guarded view source root changed after capture"
        );
        let namespace = GuardedNamespace {
            control: Arc::clone(&control),
            anchor_id: manifest.anchor_id,
            records: Mutex::new(HashMap::new()),
        };
        let mut directory_paths = HashMap::new();
        directory_paths.insert(PathBuf::new(), INodeNo::ROOT);
        for (index, entry) in manifest.entries.iter().enumerate() {
            if let CapturedEntry::Directory { path, .. } = entry {
                let expected = plan
                    .captured_entry_identity(path)
                    .context("guarded directory is absent from source plan")?;
                ensure!(
                    lower_root.open_descendant_directory(path)?.identity()? == expected,
                    "guarded view directory changed after capture"
                );
                ensure!(
                    directory_paths
                        .insert(PathBuf::from(path), INodeNo(u64::try_from(index)? + 2))
                        .is_none(),
                    "duplicate guarded view directory"
                );
            }
        }
        let mut paths = HashMap::new();
        paths.insert(PathBuf::new(), INodeNo::ROOT);
        let mut directories = Vec::new();
        let mut files = Vec::new();
        for (index, entry) in manifest.entries.iter().enumerate() {
            let (path, mode) = match entry {
                CapturedEntry::Directory { path, mode, .. }
                | CapturedEntry::FileV2 { path, mode, .. } => (path, *mode),
                CapturedEntry::File { .. } => {
                    anyhow::bail!("guarded view needs native file identities")
                }
            };
            let relative = Path::new(path);
            let parent_path = relative.parent().context("guarded entry has no parent")?;
            let parent = *paths
                .get(parent_path)
                .context("guarded view entry has no captured parent directory")?;
            let name = relative.file_name().context("guarded entry has no name")?;
            let inode = INodeNo(
                u64::try_from(index)?
                    .checked_add(2)
                    .context("view inode overflow")?,
            );
            let expected = plan
                .captured_entry_identity(path)
                .context("guarded manifest entry is not in its source plan")?;
            match entry {
                CapturedEntry::Directory { .. } => {
                    let lower = lower_root.open_descendant_directory(relative)?;
                    ensure!(
                        lower.identity()? == expected,
                        "guarded view directory changed after capture"
                    );
                    let mut attr =
                        probe_directory_attr(lower.as_file(), inode, (mode & 0o7777) as u16)?;
                    attr.uid = view_uid;
                    attr.gid = view_gid;
                    directories.push(GuardedProbeDirectory {
                        attr,
                        parent,
                        name: name.to_os_string(),
                        relative_path: relative.to_path_buf(),
                    });
                }
                CapturedEntry::FileV2 { native_id, .. } => {
                    ensure!(
                        *native_id == expected,
                        "guarded manifest file identity differs from its plan"
                    );
                    let _anchor = manifest.file_locator(path.clone())?.open()?;
                    let location = namespace.load_or_replay(
                        inode.0,
                        path,
                        expected,
                        &lower_root,
                        &directory_paths,
                    )?;
                    let Some(current) = &location else {
                        paths.insert(relative.to_path_buf(), inode);
                        continue;
                    };
                    let lower_parent = namespace_parent(&lower_root, &current.relative_path)?;
                    let lower_parent = lower_parent.as_ref().unwrap_or(&lower_root);
                    let source = lower_parent
                        .open_child_file(current.relative_path.file_name().unwrap())?
                        .context("guarded view source file disappeared")?;
                    ensure!(
                        source.metadata()?.ino() == expected.inode,
                        "guarded view source file changed while opening"
                    );
                    let mut attr = probe_file_attr(&source, inode, (mode & 0o7777) as u16)?;
                    attr.uid = view_uid;
                    attr.gid = view_gid;
                    let location = Arc::new(Mutex::new(location));
                    let location_for_open = Arc::clone(&location);
                    let control_for_open = Arc::clone(&control);
                    let plan_for_open = plan.clone();
                    let lower_path = plan.source_root().to_path_buf();
                    let captured_path = path.clone();
                    let open_for_write: Arc<dyn Fn(OpenAccMode) -> io::Result<File> + Send + Sync> =
                        Arc::new(move |mode| {
                            let location = location_for_open.lock().map_err(|_| {
                                io::Error::other("guarded location lock is poisoned")
                            })?;
                            let location = location
                                .as_ref()
                                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
                            let control = control_for_open.lock().map_err(|_| {
                                io::Error::other("guarded control lock is poisoned")
                            })?;
                            plan_for_open
                                .prepare_file_edit_at(
                                    &control,
                                    &captured_path,
                                    &location.relative_path,
                                )
                                .map_err(io::Error::other)?;
                            OpenOptions::new()
                                .read(mode == OpenAccMode::O_RDWR)
                                .write(true)
                                .open(lower_path.join(&location.relative_path))
                        });
                    files.push(GuardedProbeFile {
                        source,
                        source_attr: Mutex::new(attr),
                        location,
                        open_for_write: Some(open_for_write),
                    });
                }
                CapturedEntry::File { .. } => unreachable!(),
            }
            ensure!(
                paths.insert(relative.to_path_buf(), inode).is_none(),
                "duplicate guarded view entry"
            );
        }
        let first_dynamic_inode = u64::try_from(manifest.entries.len())?
            .checked_add(2)
            .context("guarded view inode overflow")?;
        namespace.reconcile_creates(&lower_root, &directory_paths, first_dynamic_inode)?;
        let mut highest_inode = first_dynamic_inode - 1;
        for (inode, bytes) in namespace.owned_records(NAMESPACE_KIND)? {
            if inode < first_dynamic_inode {
                ensure!(
                    namespace.records.lock().unwrap().contains_key(&inode),
                    "guarded namespace record aliases a directory"
                );
                continue;
            }
            highest_inode = highest_inode.max(inode);
            let record: NamespaceRecord = mb_core::decode_canonical(&bytes)?;
            ensure!(
                record.captured_path.is_empty()
                    && record.expected.filesystem_id == lower_root.identity()?.filesystem_id,
                "invalid dynamically created guarded file"
            );
            let location = namespace.load_or_replay(
                inode,
                "",
                record.expected,
                &lower_root,
                &directory_paths,
            )?;
            let Some(location) = location else {
                continue;
            };
            let owned = namespace_parent(&lower_root, &location.relative_path)?;
            let parent = owned.as_ref().unwrap_or(&lower_root);
            let source = parent
                .open_child_file(location.relative_path.file_name().unwrap())?
                .context("created guarded file disappeared")?;
            ensure!(
                source.metadata()?.ino() == record.expected.inode,
                "created guarded file changed while opening"
            );
            files.push(GuardedProbeFile::new_editable(
                source,
                INodeNo(inode),
                location,
                plan.source_root(),
                view_uid,
                view_gid,
            )?);
        }
        let mut view = Self::with_directories(
            files,
            directories,
            (manifest.root_mode & 0o7777) as u16,
            Arc::new(AtomicU64::new(0)),
            Some(lower_root),
        );
        view.root_uid = view_uid;
        view.root_gid = view_gid;
        view.next_inode.store(
            highest_inode
                .checked_add(1)
                .context("guarded view inode overflow")?,
            Ordering::Relaxed,
        );
        view.namespace = Some(namespace);
        Ok(view)
    }

    fn new(
        files: Vec<GuardedProbeFile>,
        root_perm: u16,
        denied_writable: Arc<AtomicU64>,
        lower_root: Option<crate::PinnedDirectory>,
    ) -> Self {
        Self::with_directories(files, Vec::new(), root_perm, denied_writable, lower_root)
    }

    fn with_directories(
        files: Vec<GuardedProbeFile>,
        directories: Vec<GuardedProbeDirectory>,
        root_perm: u16,
        denied_writable: Arc<AtomicU64>,
        lower_root: Option<crate::PinnedDirectory>,
    ) -> Self {
        let mut by_inode = HashMap::new();
        let mut names = HashMap::new();
        let mut by_directory = HashMap::new();
        let (root_uid, root_gid) = files
            .first()
            .map(|file| {
                let attr = file.source_attr.lock().unwrap();
                (attr.uid, attr.gid)
            })
            .unwrap_or((0, 0));
        for directory in directories {
            let inode = directory.attr.ino.0;
            assert!(inode != INodeNo::ROOT.0, "duplicate guarded root inode");
            assert!(
                names
                    .insert((directory.parent.0, directory.name.clone()), inode)
                    .is_none(),
                "duplicate guarded view name"
            );
            assert!(
                by_directory.insert(inode, directory).is_none(),
                "duplicate guarded view directory inode"
            );
        }
        for file in files {
            let inode = file.source_attr.lock().unwrap().ino.0;
            if let Some(location) = file.location.lock().unwrap().as_ref() {
                let name = location
                    .relative_path
                    .file_name()
                    .expect("guarded file needs a name");
                assert!(
                    names
                        .insert((location.parent.0, name.to_os_string()), inode)
                        .is_none(),
                    "duplicate guarded view name"
                );
            }
            assert!(
                !by_directory.contains_key(&inode),
                "guarded file aliases a directory inode"
            );
            assert!(
                by_inode.insert(inode, Arc::new(file)).is_none(),
                "duplicate guarded view inode"
            );
        }
        let next_inode = by_inode
            .keys()
            .chain(by_directory.keys())
            .copied()
            .max()
            .unwrap_or(INodeNo::ROOT.0)
            .checked_add(1)
            .expect("guarded view inode overflow");
        Self {
            files: by_inode,
            dynamic_files: Mutex::new(HashMap::new()),
            directories: by_directory,
            names: Mutex::new(names),
            lower_root,
            namespace: None,
            root_uid,
            root_gid,
            root_perm,
            poisoned: AtomicBool::new(false),
            next_handle: AtomicU64::new(1),
            next_inode: AtomicU64::new(next_inode),
            denied_writable,
            backing: Mutex::default(),
        }
    }

    fn root_attr(&self) -> FileAttr {
        FileAttr {
            ino: INodeNo::ROOT,
            size: 0,
            blocks: 0,
            atime: UNIX_EPOCH,
            mtime: UNIX_EPOCH,
            ctime: UNIX_EPOCH,
            crtime: UNIX_EPOCH,
            kind: FileType::Directory,
            perm: self.root_perm,
            nlink: 2,
            uid: self.root_uid,
            gid: self.root_gid,
            rdev: 0,
            flags: 0,
            blksize: 4096,
        }
    }
}

fn probe_file_attr(source: &File, inode: INodeNo, advertised_mode: u16) -> io::Result<FileAttr> {
    let metadata = source.metadata()?;
    Ok(FileAttr {
        ino: inode,
        size: metadata.len(),
        blocks: metadata.blocks(),
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::RegularFile,
        perm: advertised_mode,
        nlink: 1,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: 0,
        flags: 0,
        blksize: metadata.blksize() as u32,
    })
}

fn probe_directory_attr(
    source: &File,
    inode: INodeNo,
    advertised_mode: u16,
) -> io::Result<FileAttr> {
    let metadata = source.metadata()?;
    Ok(FileAttr {
        ino: inode,
        size: 0,
        blocks: 0,
        atime: UNIX_EPOCH,
        mtime: UNIX_EPOCH,
        ctime: UNIX_EPOCH,
        crtime: UNIX_EPOCH,
        kind: FileType::Directory,
        perm: advertised_mode,
        nlink: 2,
        uid: metadata.uid(),
        gid: metadata.gid(),
        rdev: 0,
        flags: 0,
        blksize: metadata.blksize() as u32,
    })
}

impl Filesystem for GuardedProbeView {
    fn init(&mut self, _request: &Request, config: &mut KernelConfig) -> io::Result<()> {
        config
            .add_capabilities(InitFlags::FUSE_PASSTHROUGH)
            .map_err(|_| {
                io::Error::new(io::ErrorKind::Unsupported, "FUSE passthrough unavailable")
            })?;
        config
            .set_max_stack_depth(1)
            .map_err(|_| io::Error::new(io::ErrorKind::Unsupported, "FUSE stacking unavailable"))?;
        Ok(())
    }

    fn lookup(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        let names = self.names.lock().unwrap();
        let Some(&inode) = names.get(&(parent.0, name.to_os_string())) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if let Some(directory) = self.directories.get(&inode) {
            reply.entry(&ENTRY_TTL, &directory.attr, Generation(0));
        } else if let Some(file) = self.file(inode) {
            match file.current_attr() {
                Ok(attr) => reply.entry(&ENTRY_TTL, &attr, Generation(0)),
                Err(_) => reply.error(Errno::EIO),
            }
        } else {
            reply.error(Errno::EIO);
        }
    }

    fn readdir(
        &self,
        _request: &Request,
        inode: INodeNo,
        _handle: FileHandle,
        offset: u64,
        mut reply: ReplyDirectory,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        if inode != INodeNo::ROOT && !self.directories.contains_key(&inode.0) {
            reply.error(Errno::ENOENT);
            return;
        }
        let names = self.names.lock().unwrap();
        let parent = self
            .directories
            .get(&inode.0)
            .map(|directory| directory.parent)
            .unwrap_or(INodeNo::ROOT);
        let mut entries = vec![
            (inode, FileType::Directory, OsString::from(".")),
            (parent, FileType::Directory, OsString::from("..")),
        ];
        let mut children: Vec<_> = names
            .iter()
            .filter(|((child_parent, _), _)| *child_parent == inode.0)
            .collect();
        children.sort_by_key(|((_, name), _)| name);
        entries.extend(children.into_iter().map(|((_, name), child_inode)| {
            let kind = if self.directories.contains_key(child_inode) {
                FileType::Directory
            } else {
                FileType::RegularFile
            };
            (INodeNo(*child_inode), kind, name.clone())
        }));
        let start = usize::try_from(offset).unwrap_or(usize::MAX);
        for (index, (entry_inode, kind, name)) in entries.iter().enumerate().skip(start) {
            if reply.add(*entry_inode, index as u64 + 1, *kind, name) {
                break;
            }
        }
        reply.ok();
    }

    fn getattr(
        &self,
        _request: &Request,
        inode: INodeNo,
        _handle: Option<FileHandle>,
        reply: ReplyAttr,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        match inode {
            INodeNo::ROOT => reply.attr(&ENTRY_TTL, &self.root_attr()),
            _ if self.directories.contains_key(&inode.0) => {
                reply.attr(&ENTRY_TTL, &self.directories[&inode.0].attr)
            }
            _ => match self.file(inode.0) {
                Some(file) => match file.current_attr() {
                    Ok(attr) => reply.attr(&ENTRY_TTL, &attr),
                    Err(_) => reply.error(Errno::EIO),
                },
                None => reply.error(Errno::ENOENT),
            },
        }
    }

    fn setattr(
        &self,
        _request: &Request,
        inode: INodeNo,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        handle: Option<FileHandle>,
        crtime: Option<SystemTime>,
        chgtime: Option<SystemTime>,
        bkuptime: Option<SystemTime>,
        flags: Option<BsdFileFlags>,
        reply: ReplyAttr,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        let Some(file) = self.file(inode.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if (mode.is_none() && size.is_none())
            || uid.is_some()
            || gid.is_some()
            || atime.is_some()
            || mtime.is_some()
            || ctime.is_some()
            || crtime.is_some()
            || chgtime.is_some()
            || bkuptime.is_some()
            || flags.is_some()
        {
            reply.error(Errno::EINVAL);
            return;
        }
        if let Some(handle) = handle {
            let held = self.backing.lock().unwrap();
            let Some(backing) = held.get(&handle.0) else {
                reply.error(Errno::EIO);
                return;
            };
            if backing.inode != inode {
                reply.error(Errno::EIO);
                return;
            }
            if size.is_some() && backing.mode == OpenAccMode::O_RDONLY {
                reply.error(Errno::EACCES);
                return;
            }
        }
        let Some(open_for_write) = &file.open_for_write else {
            reply.error(Errno::EACCES);
            return;
        };
        let result = (|| -> io::Result<FileAttr> {
            // The callback completes the durable sparse detach before this
            // operation can change the inode shared with an anchor.
            let source = open_for_write(OpenAccMode::O_RDWR)?;
            if let Some(size) = size {
                source.set_len(size)?;
            }
            if let Some(mode) = mode {
                source.set_permissions(fs::Permissions::from_mode(mode & 0o7777))?;
            }
            source.sync_all()?;
            if let Some(mode) = mode {
                file.source_attr.lock().unwrap().perm = (mode & 0o7777) as u16;
            }
            file.current_attr()
        })();
        match result {
            Ok(attr) => reply.attr(&ENTRY_TTL, &attr),
            Err(_) => reply.error(Errno::EIO),
        }
    }

    fn open(&self, _request: &Request, inode: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        let Some(file) = self.file(inode.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if flags.0 & !(libc::O_ACCMODE | KERNEL_O_LARGEFILE) != 0 {
            reply.error(Errno::EACCES);
            return;
        }
        let writable;
        let source = if flags.acc_mode() == OpenAccMode::O_RDONLY {
            &file.source
        } else if matches!(
            flags.acc_mode(),
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR
        ) {
            let Some(open_for_write) = &file.open_for_write else {
                self.denied_writable.fetch_add(1, Ordering::Relaxed);
                reply.error(Errno::EACCES);
                return;
            };
            writable = match open_for_write(flags.acc_mode()) {
                Ok(file) => file,
                Err(_) => {
                    reply.error(Errno::EIO);
                    return;
                }
            };
            &writable
        } else {
            self.denied_writable.fetch_add(1, Ordering::Relaxed);
            reply.error(Errno::EACCES);
            return;
        };
        let backing = match reply.open_backing(source) {
            Ok(backing) => backing,
            Err(_) => {
                reply.error(Errno::EIO);
                return;
            }
        };
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let mut held = self.backing.lock().unwrap();
        held.insert(
            handle,
            ActiveBacking {
                id: backing,
                mode: flags.acc_mode(),
                inode,
            },
        );
        reply.opened_passthrough(FileHandle(handle), FopenFlags::empty(), &held[&handle].id);
    }

    fn release(
        &self,
        _request: &Request,
        _inode: INodeNo,
        handle: FileHandle,
        _flags: OpenFlags,
        _lock_owner: Option<LockOwner>,
        _flush: bool,
        reply: ReplyEmpty,
    ) {
        self.backing.lock().unwrap().remove(&handle.0);
        reply.ok();
    }

    fn create(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        flags: i32,
        reply: ReplyCreate,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        let Some(lower_root) = &self.lower_root else {
            reply.error(Errno::EACCES);
            return;
        };
        let Some(namespace) = &self.namespace else {
            reply.error(Errno::EACCES);
            return;
        };
        let allowed = libc::O_ACCMODE
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_TRUNC
            | libc::O_CLOEXEC
            | libc::O_NOCTTY
            | KERNEL_O_LARGEFILE;
        if flags & !allowed != 0
            || !matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
            || (mode & libc::S_IFMT != 0 && mode & libc::S_IFMT != libc::S_IFREG)
        {
            reply.error(Errno::EINVAL);
            return;
        }
        let name_path = Path::new(name);
        if name.as_bytes().contains(&0)
            || !matches!(
                name_path.components().next(),
                Some(std::path::Component::Normal(_))
            )
            || name_path.components().count() != 1
        {
            reply.error(Errno::EINVAL);
            return;
        }
        let mut names = self.names.lock().unwrap();
        let parent_path = if parent == INodeNo::ROOT {
            PathBuf::new()
        } else if let Some(directory) = self.directories.get(&parent.0) {
            directory.relative_path.clone()
        } else {
            reply.error(Errno::ENOENT);
            return;
        };
        let key = (parent.0, name.to_os_string());
        if names.contains_key(&key) {
            reply.error(Errno::EEXIST);
            return;
        }
        let result = (|| -> io::Result<(u64, Arc<GuardedProbeFile>, BackingId, FileAttr)> {
            let owned = if parent_path.as_os_str().is_empty() {
                None
            } else {
                Some(
                    lower_root
                        .open_descendant_directory(&parent_path)
                        .map_err(io::Error::other)?,
                )
            };
            let lower = owned.as_ref().unwrap_or(lower_root);
            let source = lower
                .create_unlinked_child_file()
                .map_err(io::Error::other)?;
            // The private lower inode is daemon-owned; do not publish
            // setuid/setgid bits requested through the remapped FUSE owner.
            source.set_permissions(fs::Permissions::from_mode((mode & !umask) & 0o777))?;
            source.sync_all()?;
            let backing = reply.open_backing(&source)?;
            let inode = self
                .next_inode
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                })
                .map_err(|_| io::Error::other("guarded view inode space is exhausted"))?;
            let relative_path = parent_path.join(name);
            let expected = NativeFileId {
                filesystem_id: lower_root
                    .identity()
                    .map_err(io::Error::other)?
                    .filesystem_id,
                inode: source.metadata()?.ino(),
            };
            let intent = CreateIntent {
                version: 1,
                target: relative_path.as_os_str().as_bytes().to_vec(),
                expected,
            };
            namespace.store_create(inode, &intent)?;
            if let Err(error) = lower.publish_unlinked_child_file(&source, name, expected) {
                self.poisoned.store(true, Ordering::Release);
                return Err(io::Error::other(error));
            }
            if let Err(error) = namespace.finish_create(inode, &intent) {
                self.poisoned.store(true, Ordering::Release);
                return Err(error);
            }
            let file = GuardedProbeFile::new_editable(
                source,
                INodeNo(inode),
                ProbeLocation {
                    parent,
                    relative_path,
                },
                &lower_root.descriptor_path(),
                self.root_uid,
                self.root_gid,
            )
            .inspect_err(|_| self.poisoned.store(true, Ordering::Release))?;
            let attr = file
                .current_attr()
                .inspect_err(|_| self.poisoned.store(true, Ordering::Release))?;
            Ok((inode, Arc::new(file), backing, attr))
        })();
        match result {
            Ok((inode, file, backing, attr)) => {
                names.insert(key, inode);
                self.dynamic_files.lock().unwrap().insert(inode, file);
                let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
                self.backing.lock().unwrap().insert(
                    handle,
                    ActiveBacking {
                        id: backing,
                        mode: if flags & libc::O_ACCMODE == libc::O_RDWR {
                            OpenAccMode::O_RDWR
                        } else {
                            OpenAccMode::O_WRONLY
                        },
                        inode: INodeNo(inode),
                    },
                );
                let held = self.backing.lock().unwrap();
                reply.created_passthrough(
                    &ENTRY_TTL,
                    &attr,
                    Generation(0),
                    FileHandle(handle),
                    FopenFlags::empty(),
                    &held[&handle].id,
                );
            }
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn rename(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        newparent: INodeNo,
        newname: &OsStr,
        flags: RenameFlags,
        reply: ReplyEmpty,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        if (parent != INodeNo::ROOT && !self.directories.contains_key(&parent.0))
            || (newparent != INodeNo::ROOT && !self.directories.contains_key(&newparent.0))
        {
            reply.error(Errno::ENOENT);
            return;
        }
        if !flags.is_empty() && flags != RenameFlags::RENAME_NOREPLACE {
            reply.error(Errno::EINVAL);
            return;
        }
        let mut names = self.names.lock().unwrap();
        let old_key = (parent.0, name.to_os_string());
        let new_key = (newparent.0, newname.to_os_string());
        let Some(&inode) = names.get(&old_key) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(file) = self.file(inode) else {
            reply.error(Errno::EISDIR);
            return;
        };
        let Some(lower_root) = &self.lower_root else {
            reply.error(Errno::EACCES);
            return;
        };
        if parent == newparent && name == newname {
            reply.ok();
            return;
        }
        if names.contains_key(&new_key) {
            reply.error(Errno::EEXIST);
            return;
        }
        let mut current = file.location.lock().unwrap();
        let result = (|| -> io::Result<()> {
            let location = current
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            if location.parent != parent {
                return Err(io::Error::other("guarded namespace parent changed"));
            }
            let source_relative_dir = location
                .relative_path
                .parent()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            let destination_relative_dir = self
                .directories
                .get(&newparent.0)
                .map(|directory| directory.relative_path.as_path())
                .unwrap_or(Path::new(""));
            let new_path = destination_relative_dir.join(newname);
            let source_owned = if source_relative_dir.as_os_str().is_empty() {
                None
            } else {
                Some(
                    lower_root
                        .open_descendant_directory(source_relative_dir)
                        .map_err(io::Error::other)?,
                )
            };
            let destination_owned = if destination_relative_dir.as_os_str().is_empty() {
                None
            } else {
                Some(
                    lower_root
                        .open_descendant_directory(destination_relative_dir)
                        .map_err(io::Error::other)?,
                )
            };
            let source_parent = source_owned.as_ref().unwrap_or(lower_root);
            let destination_parent = destination_owned.as_ref().unwrap_or(lower_root);
            let expected = crate::NativeFileId {
                filesystem_id: lower_root
                    .identity()
                    .map_err(io::Error::other)?
                    .filesystem_id,
                inode: file.source.metadata()?.ino(),
            };
            let move_file = |expected| {
                source_parent
                    .move_child_file_no_replace(name, expected, destination_parent, newname)
                    .map_err(io::Error::other)
            };
            let moved = if let Some(namespace) = &self.namespace {
                namespace.transition(inode, &location.relative_path, Some(&new_path), move_file)
            } else {
                move_file(expected)
            };
            moved.inspect_err(|_| {
                // A directory fsync or final journal write can fail after
                // the move. Rebuild and reconcile before serving more calls.
                self.poisoned.store(true, Ordering::Release);
            })?;
            *current = Some(ProbeLocation {
                parent: newparent,
                relative_path: new_path,
            });
            names.remove(&old_key);
            names.insert(new_key, inode);
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn unlink(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        if parent != INodeNo::ROOT && !self.directories.contains_key(&parent.0) {
            reply.error(Errno::ENOENT);
            return;
        }
        let mut names = self.names.lock().unwrap();
        let key = (parent.0, name.to_os_string());
        let Some(&inode) = names.get(&key) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(file) = self.file(inode) else {
            reply.error(Errno::EISDIR);
            return;
        };
        let Some(lower_root) = &self.lower_root else {
            reply.error(Errno::EACCES);
            return;
        };
        let mut current = file.location.lock().unwrap();
        let result = (|| -> io::Result<()> {
            let location = current
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            if location.parent != parent {
                return Err(io::Error::other("guarded namespace parent changed"));
            }
            let source_relative_dir = location
                .relative_path
                .parent()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            let lower_owned = if source_relative_dir.as_os_str().is_empty() {
                None
            } else {
                Some(
                    lower_root
                        .open_descendant_directory(source_relative_dir)
                        .map_err(io::Error::other)?,
                )
            };
            let lower = lower_owned.as_ref().unwrap_or(lower_root);
            let expected = crate::NativeFileId {
                filesystem_id: lower_root
                    .identity()
                    .map_err(io::Error::other)?
                    .filesystem_id,
                inode: file.source.metadata()?.ino(),
            };
            let remove_file = |expected| {
                lower
                    .remove_child_file_if_identity(name, expected)
                    .map_err(io::Error::other)
            };
            let removed = if let Some(namespace) = &self.namespace {
                namespace.transition(inode, &location.relative_path, None, remove_file)
            } else {
                remove_file(expected)
            };
            removed.inspect_err(|_| {
                self.poisoned.store(true, Ordering::Release);
            })?;
            *current = None;
            names.remove(&key);
            Ok(())
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))),
        }
    }

    fn fallocate(
        &self,
        _request: &Request,
        inode: INodeNo,
        handle: FileHandle,
        offset: u64,
        length: u64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        let Some(file) = self.file(inode.0) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let held = self.backing.lock().unwrap();
        let Some(backing) = held.get(&handle.0) else {
            reply.error(Errno::EIO);
            return;
        };
        if backing.inode != inode {
            reply.error(Errno::EIO);
            return;
        }
        if backing.mode == OpenAccMode::O_RDONLY {
            reply.error(Errno::EACCES);
            return;
        }
        drop(held);
        let Some(open_for_write) = &file.open_for_write else {
            reply.error(Errno::EACCES);
            return;
        };
        let result = (|| -> io::Result<()> {
            let offset =
                i64::try_from(offset).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            let length =
                i64::try_from(length).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
            // The callback completes or verifies the durable detach before an
            // allocation or hole punch can reach the private source inode.
            let source = open_for_write(OpenAccMode::O_RDWR)?;
            // SAFETY: `source` owns a valid descriptor, and the offset and
            // length were checked for the syscall's signed argument width.
            if unsafe { libc::fallocate(source.as_raw_fd(), mode, offset, length) } < 0 {
                return Err(io::Error::last_os_error());
            }
            source.sync_all()
        })();
        match result {
            Ok(()) => reply.ok(),
            Err(error) => reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO))),
        }
    }
}

/// Verify read-only FUSE passthrough on a disposable view beside `source_root`.
/// This is a kernel/privilege probe, not a guarded-backend enrollment probe.
pub fn probe_guarded_view_passthrough(source_root: impl AsRef<Path>) -> anyhow::Result<()> {
    let source_root = source_root.as_ref();
    ensure!(
        source_root.is_dir(),
        "guarded view probe needs a source directory"
    );
    let parent = source_root
        .parent()
        .context("guarded view source has no parent")?;
    ensure!(
        crate::filesystem_identity(source_root)? == crate::filesystem_identity(parent)?,
        "guarded view probe needs a same-filesystem parent"
    );
    let area = tempfile::Builder::new()
        .prefix(".mutualbackup-fuse-probe-")
        .tempdir_in(parent)
        .context("create disposable FUSE probe directory")?;
    fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755))?;
    let lower = area.path().join("lower");
    let mountpoint = area.path().join("view");
    fs::create_dir(&lower)?;
    fs::create_dir(&mountpoint)?;
    fs::set_permissions(&lower, fs::Permissions::from_mode(0o700))?;
    let lower_path = lower.join("sample");
    let mut writable = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lower_path)?;
    io::Write::write_all(&mut writable, PROBE_BYTES)?;
    writable.sync_all()?;
    drop(writable);
    fs::set_permissions(&lower_path, fs::Permissions::from_mode(0o444))?;
    let source = File::open(&lower_path)?;
    let denied_writable = Arc::new(AtomicU64::new(0));
    let file = GuardedProbeFile {
        // Advertise the original editable mode. The lower inode is frozen;
        // the view must still reject writes until detach.
        source_attr: Mutex::new(probe_file_attr(&source, FILE_INODE, 0o666)?),
        location: Arc::new(Mutex::new(Some(ProbeLocation {
            parent: INodeNo::ROOT,
            relative_path: PathBuf::from("sample"),
        }))),
        source,
        open_for_write: None,
    };
    let view = GuardedProbeView::new(vec![file], 0o755, Arc::clone(&denied_writable), None);
    let mut config = Config::default();
    config.acl = SessionACL::All;
    let session = fuser::spawn_mount(view, &mountpoint, &config)
        .context("mount disposable FUSE passthrough view")?;
    let result = (|| -> anyhow::Result<()> {
        ensure!(
            fs::read(mountpoint.join("sample"))? == PROBE_BYTES,
            "FUSE passthrough changed bytes"
        );
        let ordinary_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(mountpoint.join("sample"))
            .output()
            .context("read guarded view as an ordinary user")?;
        ensure!(
            ordinary_read.status.success() && ordinary_read.stdout == PROBE_BYTES,
            "ordinary user could not read exact bytes through FUSE view"
        );
        let private_read = Command::new("cat")
            .uid(65534)
            .gid(65534)
            .arg(&lower_path)
            .output()
            .context("check private lower source access")?;
        ensure!(
            !private_read.status.success(),
            "ordinary user can bypass the guarded view through the lower path"
        );
        let visible = File::open(mountpoint.join("sample"))?;
        // SAFETY: the mapping is read-only, shared, and bounded by this
        // immutable probe file. It is unmapped before the descriptor closes.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PROBE_BYTES.len(),
                libc::PROT_READ,
                libc::MAP_SHARED,
                visible.as_raw_fd(),
                0,
            )
        };
        if mapping == libc::MAP_FAILED {
            return Err(io::Error::last_os_error().into());
        }
        // SAFETY: mmap returned a readable region of exactly this length.
        let mapped_bytes: &[u8] =
            unsafe { std::slice::from_raw_parts(mapping.cast(), PROBE_BYTES.len()) };
        let mapping_matches = mapped_bytes == PROBE_BYTES;
        // SAFETY: this is the original mapping pointer and length.
        if unsafe { libc::munmap(mapping, PROBE_BYTES.len()) } < 0 {
            return Err(io::Error::last_os_error().into());
        }
        ensure!(mapping_matches, "FUSE read-only mapping changed bytes");
        // SAFETY: this deliberately attempts a shared writable map through a
        // read-only descriptor; any unexpected mapping is immediately unmapped.
        let writable_mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PROBE_BYTES.len(),
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                visible.as_raw_fd(),
                0,
            )
        };
        if writable_mapping != libc::MAP_FAILED {
            // SAFETY: release the unexpected successful mapping before error.
            unsafe { libc::munmap(writable_mapping, PROBE_BYTES.len()) };
            anyhow::bail!("FUSE read-only handle accepted a shared writable mapping");
        }
        ensure!(
            OpenOptions::new()
                .write(true)
                .open(mountpoint.join("sample"))
                .is_err(),
            "FUSE read-only view accepted a writable open"
        );
        ensure!(
            denied_writable.load(Ordering::Relaxed) > 0,
            "writable open bypassed the FUSE decision"
        );
        let _ = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_TRUNC)
            .open(mountpoint.join("sample"));
        ensure!(
            fs::read(&lower_path)? == PROBE_BYTES,
            "read-only pathname truncate changed the lower inode"
        );
        let _ = fs::set_permissions(mountpoint.join("sample"), fs::Permissions::from_mode(0o666));
        ensure!(
            fs::metadata(&lower_path)?.permissions().mode() & 0o222 == 0,
            "FUSE chmod changed the frozen lower inode"
        );
        Ok(())
    })();
    session
        .umount_and_join()
        .context("unmount disposable FUSE view")?;
    result
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::{self, File, OpenOptions};
    use std::io::{self, Read};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::os::unix::process::CommandExt;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    use fuser::{Config, INodeNo, OpenAccMode, SessionACL};
    use mb_core::{KeyMaterial, Seed};

    use crate::{
        ControlStore, GuardedFileCapturePlan, GuardedRootCapturePlan, LinkFreezeCaptureIntent,
        LinkFreezeCapturePhase, PinnedDirectory,
    };

    use super::{
        CREATE_KIND, CreateIntent, FILE_INODE, GuardedNamespace, GuardedProbeFile,
        GuardedProbeView, NAMESPACE_KIND, NamespaceRecord, ProbeLocation, probe_file_attr,
    };

    #[test]
    fn create_intent_reconciles_before_and_after_publication() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([91; 32]));
        let control_path = area.path().join("control.db");
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        for (index, published) in [(2, false), (3, true)] {
            let anchor_id = uuid::Uuid::new_v4();
            let name = format!("new-{index}");
            let source = root.create_unlinked_child_file().unwrap();
            source.sync_all().unwrap();
            let expected = crate::NativeFileId {
                filesystem_id: root.identity().unwrap().filesystem_id,
                inode: source.metadata().unwrap().ino(),
            };
            let intent = CreateIntent {
                version: 1,
                target: name.as_bytes().to_vec(),
                expected,
            };
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            journal.store_create(index, &intent).unwrap();
            if published {
                root.publish_unlinked_child_file(&source, &name, expected)
                    .unwrap();
            }
            drop(source);
            drop(journal);
            drop(control);
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            journal.reconcile_creates(&root, &directories, 2).unwrap();
            let control = control.lock().unwrap();
            assert!(
                control
                    .get_record(CREATE_KIND, &journal.record_id(index))
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                control
                    .get_record(NAMESPACE_KIND, &journal.record_id(index))
                    .unwrap()
                    .is_some(),
                published
            );
            assert_eq!(lower.join(name).exists(), published);
        }
    }

    #[test]
    fn create_intent_refuses_foreign_target() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let source = root.create_unlinked_child_file().unwrap();
        let expected = crate::NativeFileId {
            filesystem_id: root.identity().unwrap().filesystem_id,
            inode: source.metadata().unwrap().ino(),
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([92; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control,
            anchor_id: uuid::Uuid::new_v4(),
            records: Mutex::new(HashMap::new()),
        };
        journal
            .store_create(
                2,
                &CreateIntent {
                    version: 1,
                    target: b"target".to_vec(),
                    expected,
                },
            )
            .unwrap();
        fs::write(lower.join("target"), b"foreign").unwrap();
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        assert!(journal.reconcile_creates(&root, &directories, 2).is_err());
        assert_eq!(fs::read(lower.join("target")).unwrap(), b"foreign");
    }

    #[test]
    fn namespace_journal_replays_file_move_and_unlink_on_both_sides_of_mutation() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([89; 32]));
        let control_path = area.path().join("control.db");
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        for (index, unlink, completed) in [
            (0, false, false),
            (1, false, true),
            (2, true, false),
            (3, true, true),
        ] {
            let old = format!("old-{index}");
            let new = format!("new-{index}");
            fs::write(lower.join(&old), b"original bytes").unwrap();
            let expected = root.entry_identity(&old, false).unwrap().unwrap();
            let anchor_id = uuid::Uuid::new_v4();
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let target = (!unlink).then(|| new.as_bytes().to_vec());
            let record = NamespaceRecord {
                version: 1,
                captured_path: old.clone(),
                expected,
                current: Some(old.as_bytes().to_vec()),
                pending: Some(target.clone()),
            };
            journal.store(2, &record).unwrap();
            drop(journal);
            drop(control);
            if completed {
                if unlink {
                    fs::remove_file(lower.join(&old)).unwrap();
                } else {
                    fs::rename(lower.join(&old), lower.join(&new)).unwrap();
                }
            }
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let location = journal
                .load_or_replay(2, &old, expected, &root, &directories)
                .unwrap();
            assert!(!lower.join(&old).exists());
            if unlink {
                assert!(location.is_none());
            } else {
                assert_eq!(location.unwrap().relative_path, PathBuf::from(&new));
                assert_eq!(fs::read(lower.join(&new)).unwrap(), b"original bytes");
            }
            let encoded = control
                .lock()
                .unwrap()
                .get_record(NAMESPACE_KIND, &journal.record_id(2))
                .unwrap()
                .unwrap();
            let settled: NamespaceRecord = mb_core::decode_canonical(&encoded).unwrap();
            assert!(settled.pending.is_none());
            assert_eq!(settled.current, target);
        }
    }

    #[test]
    fn namespace_journal_refuses_replacement_identity() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        fs::write(lower.join("old"), b"original").unwrap();
        let expected = root.entry_identity("old", false).unwrap().unwrap();
        let original = root.open_child_file("old").unwrap().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([90; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control,
            anchor_id: uuid::Uuid::new_v4(),
            records: Mutex::new(HashMap::new()),
        };
        journal
            .store(
                2,
                &NamespaceRecord {
                    version: 1,
                    captured_path: "old".into(),
                    expected,
                    current: Some(b"old".to_vec()),
                    pending: Some(Some(b"new".to_vec())),
                },
            )
            .unwrap();
        root.remove_child_file_if_identity("old", expected).unwrap();
        fs::write(lower.join("old"), b"replacement").unwrap();
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        assert!(
            journal
                .load_or_replay(2, "old", expected, &root, &directories)
                .is_err()
        );
        assert_eq!(fs::read(lower.join("old")).unwrap(), b"replacement");
        assert!(!lower.join("new").exists());
        drop(original);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and FUSE passthrough"]
    fn read_only_passthrough_mount_preserves_bytes_and_denies_writable_open() {
        let disposable = tempfile::tempdir().unwrap();
        let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| disposable.path().to_path_buf());
        super::probe_guarded_view_passthrough(root).unwrap();
    }

    #[derive(Clone, Copy)]
    enum FirstMutation {
        WritableOpen,
        OwnerChmod,
        PathTruncate,
        OpenTruncate,
        Allocate,
        RenameThenWrite,
        Unlink,
    }

    fn guarded_view_mutation_case(first: FirstMutation) {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-view-edit-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        let lower_path = lower.join("sample");
        let original = b"raw\r\nbytes\0guarded";
        fs::write(&lower_path, original).unwrap();
        fs::set_permissions(&lower_path, fs::Permissions::from_mode(0o666)).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([73; 32]));
        let control = ControlStore::open(control_dir.join("control.db"), &keys).unwrap();
        let plan = GuardedFileCapturePlan::plan(&lower, "sample").unwrap();
        let manifest = plan.capture(&control).unwrap();
        let source = File::open(&lower_path).unwrap();
        let original_inode = source.metadata().unwrap().ino();
        let control = Arc::new(Mutex::new(control));
        let control_for_open = Arc::clone(&control);
        let plan_for_open = plan.clone();
        let location = Arc::new(Mutex::new(Some(ProbeLocation {
            parent: INodeNo::ROOT,
            relative_path: PathBuf::from("sample"),
        })));
        let location_for_open = Arc::clone(&location);
        let lower_for_open = lower.clone();
        let open_for_write = Arc::new(move |mode: OpenAccMode| -> io::Result<File> {
            let current = location_for_open
                .lock()
                .map_err(|_| io::Error::other("guarded name lock is poisoned"))?;
            let current = current
                .as_ref()
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
            let control = control_for_open
                .lock()
                .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
            plan_for_open
                .prepare_edit_at(&control, &current.relative_path)
                .map_err(io::Error::other)?;
            OpenOptions::new()
                .read(mode == OpenAccMode::O_RDWR)
                .write(true)
                .open(lower_for_open.join(&current.relative_path))
        });
        let mut advertised = probe_file_attr(&source, FILE_INODE, 0o666).unwrap();
        advertised.uid = 65534;
        let file = GuardedProbeFile {
            source_attr: Mutex::new(advertised),
            source,
            location,
            open_for_write: Some(open_for_write),
        };
        let view = GuardedProbeView::new(
            vec![file],
            0o777,
            Arc::new(Default::default()),
            Some(crate::PinnedDirectory::open(&lower).unwrap()),
        );
        let mut config = Config::default();
        config.acl = SessionACL::All;
        let session = fuser::spawn_mount(view, &mountpoint, &config).unwrap();
        let result = (|| -> anyhow::Result<()> {
            anyhow::ensure!(fs::read(mountpoint.join("sample"))? == original);
            anyhow::ensure!(fs::read(&lower_path)? == original);
            anyhow::ensure!(fs::metadata(&lower_path)?.permissions().mode() & 0o222 == 0);
            let guest_read = Command::new("cat")
                .uid(65534)
                .gid(65534)
                .arg(mountpoint.join("sample"))
                .output()?;
            anyhow::ensure!(
                guest_read.status.success(),
                "ordinary-user read failed: {}",
                String::from_utf8_lossy(&guest_read.stderr)
            );
            anyhow::ensure!(guest_read.stdout == original);
            anyhow::ensure!(
                fs::metadata(mountpoint.join("sample"))?
                    .permissions()
                    .mode()
                    & 0o222
                    != 0
            );
            let script = match first {
                FirstMutation::WritableOpen => {
                    "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)"
                }
                FirstMutation::OwnerChmod => "import os,sys; os.chmod(sys.argv[1],0o600)",
                FirstMutation::PathTruncate => "import os,sys; os.truncate(sys.argv[1],3)",
                FirstMutation::OpenTruncate => {
                    "import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY|os.O_TRUNC); os.write(fd,b'REPLACED'); os.fsync(fd); os.close(fd)"
                }
                FirstMutation::Allocate => {
                    "import ctypes,os,sys; fd=os.open(sys.argv[1],os.O_RDWR); libc=ctypes.CDLL(None,use_errno=True); result=libc.fallocate(fd,0,0,4096); assert result==0,os.strerror(ctypes.get_errno()); os.fsync(fd); os.close(fd)"
                }
                FirstMutation::RenameThenWrite => {
                    "import os,sys; os.rename(sys.argv[1],os.path.join(os.path.dirname(sys.argv[1]),'moved'))"
                }
                FirstMutation::Unlink => "import os,sys; os.unlink(sys.argv[1])",
            };
            let output = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg(script)
                .arg(mountpoint.join("sample"))
                .output()?;
            anyhow::ensure!(
                output.status.success(),
                "ordinary-user guarded mutation failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            match first {
                FirstMutation::WritableOpen => {
                    anyhow::ensure!(fs::read(&lower_path)?.starts_with(b"EDIT"));
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))?.starts_with(b"EDIT"));
                    let second_open = Command::new("python3")
                        .uid(65534)
                        .gid(65534)
                        .arg("-c")
                        .arg("import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.lseek(fd,5,os.SEEK_SET); os.write(fd,b'NEXT'); os.fsync(fd); os.close(fd)")
                        .arg(mountpoint.join("sample"))
                        .output()?;
                    anyhow::ensure!(
                        second_open.status.success(),
                        "ordinary-user read/write open failed: {}",
                        String::from_utf8_lossy(&second_open.stderr)
                    );
                    anyhow::ensure!(fs::read(&lower_path)?.starts_with(b"EDIT\nNEXT"));
                }
                FirstMutation::OwnerChmod => {
                    anyhow::ensure!(fs::read(&lower_path)? == original);
                    anyhow::ensure!(
                        fs::metadata(&lower_path)?.permissions().mode() & 0o777 == 0o600
                    );
                    anyhow::ensure!(
                        fs::metadata(mountpoint.join("sample"))?
                            .permissions()
                            .mode()
                            & 0o777
                            == 0o600
                    );
                }
                FirstMutation::PathTruncate => {
                    anyhow::ensure!(fs::read(&lower_path)? == original[..3]);
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))? == original[..3]);
                }
                FirstMutation::OpenTruncate => {
                    anyhow::ensure!(fs::read(&lower_path)? == b"REPLACED");
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))? == b"REPLACED");
                }
                FirstMutation::Allocate => {
                    let bytes = fs::read(&lower_path)?;
                    anyhow::ensure!(bytes.len() == 4096);
                    anyhow::ensure!(bytes.starts_with(original));
                    anyhow::ensure!(bytes[original.len()..].iter().all(|byte| *byte == 0));
                    anyhow::ensure!(fs::read(mountpoint.join("sample"))? == bytes);
                }
                FirstMutation::RenameThenWrite => {
                    anyhow::ensure!(!lower_path.exists());
                    anyhow::ensure!(!mountpoint.join("sample").exists());
                    anyhow::ensure!(fs::read(lower.join("moved"))? == original);
                    anyhow::ensure!(fs::read(mountpoint.join("moved"))? == original);
                    anyhow::ensure!(
                        LinkFreezeCaptureIntent::load(&control.lock().unwrap(), plan.anchor_id())?
                            .is_some_and(|intent| intent.phase() == LinkFreezeCapturePhase::Frozen)
                    );
                    let renamed_write = Command::new("python3")
                        .uid(65534)
                        .gid(65534)
                        .arg("-c")
                        .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)")
                        .arg(mountpoint.join("moved"))
                        .output()?;
                    anyhow::ensure!(
                        renamed_write.status.success(),
                        "ordinary-user write after rename failed: {}",
                        String::from_utf8_lossy(&renamed_write.stderr)
                    );
                    anyhow::ensure!(fs::read(lower.join("moved"))?.starts_with(b"EDIT"));
                }
                FirstMutation::Unlink => {
                    anyhow::ensure!(!lower_path.exists());
                    anyhow::ensure!(!mountpoint.join("sample").exists());
                    let mut anchor = manifest.open_verified()?;
                    anyhow::ensure!(anchor.metadata()?.ino() == original_inode);
                    anyhow::ensure!(anchor.metadata()?.nlink() == 1);
                    let mut bytes = Vec::new();
                    anchor.read_to_end(&mut bytes)?;
                    anyhow::ensure!(bytes == original);
                    anyhow::ensure!(
                        LinkFreezeCaptureIntent::load(&control.lock().unwrap(), plan.anchor_id())?
                            .is_some_and(|intent| intent.phase() == LinkFreezeCapturePhase::Frozen)
                    );
                    return Ok(());
                }
            }
            let current_lower = if matches!(first, FirstMutation::RenameThenWrite) {
                lower.join("moved")
            } else {
                lower_path.clone()
            };
            let source_metadata = fs::metadata(current_lower)?;
            anyhow::ensure!(
                source_metadata.ino() == original_inode && source_metadata.nlink() == 1
            );
            anyhow::ensure!(source_metadata.permissions().mode() & 0o222 != 0);
            let mut anchored = Vec::new();
            let mut anchor = manifest.open_verified()?;
            anyhow::ensure!(anchor.metadata()?.ino() != original_inode);
            anchor.read_to_end(&mut anchored)?;
            anyhow::ensure!(anchored == original);
            anyhow::ensure!(
                LinkFreezeCaptureIntent::load(&control.lock().unwrap(), plan.anchor_id())?
                    .is_some_and(|intent| intent.phase() == LinkFreezeCapturePhase::Detached)
            );
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        result.unwrap();
        unmounted.unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn writable_open_finishes_durable_detach_before_passthrough() {
        guarded_view_mutation_case(FirstMutation::WritableOpen);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn owner_chmod_detaches_before_changing_source_mode() {
        guarded_view_mutation_case(FirstMutation::OwnerChmod);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn pathname_truncate_detaches_before_changing_source_bytes() {
        guarded_view_mutation_case(FirstMutation::PathTruncate);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn truncating_open_detaches_before_changing_source_bytes() {
        guarded_view_mutation_case(FirstMutation::OpenTruncate);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn allocation_keeps_captured_anchor_immutable() {
        guarded_view_mutation_case(FirstMutation::Allocate);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn rename_preserves_anchor_until_later_write_detaches() {
        guarded_view_mutation_case(FirstMutation::RenameThenWrite);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn unlink_preserves_anchor_without_detach() {
        guarded_view_mutation_case(FirstMutation::Unlink);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn two_file_guarded_root_dispatches_edits_and_renames_by_inode() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-view-root-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        let original_alpha = b"alpha\r\n\0";
        let original_beta = b"beta\nbytes";
        fs::write(lower.join("alpha"), original_alpha).unwrap();
        fs::write(lower.join("beta"), original_beta).unwrap();
        for name in ["alpha", "beta"] {
            fs::set_permissions(lower.join(name), fs::Permissions::from_mode(0o666)).unwrap();
        }
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([74; 32]));
        let control = ControlStore::open(control_dir.join("control.db"), &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&control).unwrap();
        let control = Arc::new(Mutex::new(control));
        let view =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let mut config = Config::default();
        config.acl = SessionACL::All;
        let session = fuser::spawn_mount(view, &mountpoint, &config).unwrap();
        let result = (|| -> anyhow::Result<()> {
            let list = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; print(','.join(sorted(os.listdir(sys.argv[1]))))")
                .arg(&mountpoint)
                .output()?;
            anyhow::ensure!(list.status.success());
            anyhow::ensure!(list.stdout == b"alpha,beta\n");
            anyhow::ensure!(fs::read(mountpoint.join("alpha"))? == original_alpha);
            anyhow::ensure!(fs::read(mountpoint.join("beta"))? == original_beta);
            let create = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_RDWR,0o640); os.write(fd,b'gamma-bytes'); os.fsync(fd); os.close(fd); os.rename(sys.argv[1],sys.argv[2]); fd=os.open(sys.argv[2],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("gamma"))
                .arg(mountpoint.join("delta"))
                .output()?;
            anyhow::ensure!(
                create.status.success(),
                "guarded file creation failed: {}",
                String::from_utf8_lossy(&create.stderr)
            );
            anyhow::ensure!(fs::read(lower.join("delta"))?.starts_with(b"EDIT"));
            let beta_inode = fs::metadata(lower.join("beta"))?.ino();
            let edit = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("alpha"))
                .output()?;
            anyhow::ensure!(
                edit.status.success(),
                "alpha edit failed: {}",
                String::from_utf8_lossy(&edit.stderr)
            );
            anyhow::ensure!(fs::read(lower.join("alpha"))?.starts_with(b"EDIT"));
            anyhow::ensure!(fs::read(lower.join("beta"))? == original_beta);
            let mut alpha_anchor = manifest.file_locator("alpha".to_string())?.open()?;
            let mut alpha_bytes = Vec::new();
            alpha_anchor.read_to_end(&mut alpha_bytes)?;
            anyhow::ensure!(alpha_bytes == original_alpha);
            let mut beta_anchor = manifest.file_locator("beta".to_string())?.open()?;
            anyhow::ensure!(beta_anchor.metadata()?.ino() == beta_inode);
            let mut beta_bytes = Vec::new();
            beta_anchor.read_to_end(&mut beta_bytes)?;
            anyhow::ensure!(beta_bytes == original_beta);
            let rename = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("beta"))
                .arg(mountpoint.join("moved"))
                .output()?;
            anyhow::ensure!(
                rename.status.success(),
                "beta rename failed: {}",
                String::from_utf8_lossy(&rename.stderr)
            );
            anyhow::ensure!(fs::metadata(lower.join("moved"))?.ino() == beta_inode);
            let edit_moved = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'NEXT'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("moved"))
                .output()?;
            anyhow::ensure!(
                edit_moved.status.success(),
                "renamed beta edit failed: {}",
                String::from_utf8_lossy(&edit_moved.stderr)
            );
            anyhow::ensure!(fs::read(lower.join("moved"))?.starts_with(b"NEXT"));
            anyhow::ensure!(fs::metadata(lower.join("moved"))?.ino() == beta_inode);
            drop(beta_anchor);
            let mut beta_anchor = manifest.file_locator("beta".to_string())?.open()?;
            anyhow::ensure!(beta_anchor.metadata()?.ino() != beta_inode);
            beta_bytes.clear();
            beta_anchor.read_to_end(&mut beta_bytes)?;
            anyhow::ensure!(beta_bytes == original_beta);
            anyhow::ensure!(fs::read(mountpoint.join("alpha"))?.starts_with(b"EDIT"));
            let unlink = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.unlink(sys.argv[1])")
                .arg(mountpoint.join("alpha"))
                .output()?;
            anyhow::ensure!(
                unlink.status.success(),
                "alpha unlink failed: {}",
                String::from_utf8_lossy(&unlink.stderr)
            );
            anyhow::ensure!(!lower.join("alpha").exists());
            alpha_bytes.clear();
            manifest
                .file_locator("alpha".to_string())?
                .open()?
                .read_to_end(&mut alpha_bytes)?;
            anyhow::ensure!(alpha_bytes == original_alpha);
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        result.unwrap();
        unmounted.unwrap();
        let rebuilt =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let names = rebuilt.names.lock().unwrap();
        assert!(!names.contains_key(&(INodeNo::ROOT.0, "beta".into())));
        assert!(names.contains_key(&(INodeNo::ROOT.0, "moved".into())));
        assert!(names.contains_key(&(INodeNo::ROOT.0, "delta".into())));
        assert!(!names.contains_key(&(INodeNo::ROOT.0, "alpha".into())));
        drop(names);
        let session = fuser::spawn_mount(rebuilt, &mountpoint, &config).unwrap();
        let replayed = (|| -> anyhow::Result<()> {
            anyhow::ensure!(!mountpoint.join("alpha").exists());
            anyhow::ensure!(!mountpoint.join("beta").exists());
            anyhow::ensure!(fs::read(mountpoint.join("moved"))?.starts_with(b"NEXT"));
            anyhow::ensure!(fs::read(mountpoint.join("delta"))?.starts_with(b"EDIT"));
            let edit_created = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'NEXT'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("delta"))
                .output()?;
            anyhow::ensure!(edit_created.status.success());
            anyhow::ensure!(fs::read(lower.join("delta"))?.starts_with(b"NEXT"));
            let unlink = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.unlink(sys.argv[1])")
                .arg(mountpoint.join("moved"))
                .output()?;
            anyhow::ensure!(unlink.status.success());
            let unlink_created = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.unlink(sys.argv[1])")
                .arg(mountpoint.join("delta"))
                .output()?;
            anyhow::ensure!(unlink_created.status.success());
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        replayed.unwrap();
        unmounted.unwrap();
        let empty =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        assert!(empty.names.lock().unwrap().is_empty());
        assert_eq!(
            (empty.root_attr().uid, empty.root_attr().gid),
            (65534, 65534)
        );
        let session = fuser::spawn_mount(empty, &mountpoint, &config).unwrap();
        let listed = fs::read_dir(&mountpoint).unwrap().count();
        session.umount_and_join().unwrap();
        assert_eq!(listed, 0);
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn nested_guarded_root_file_renames_and_detaches_through_view() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-view-nested-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let nested = lower.join("nested");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(&nested).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&nested, fs::Permissions::from_mode(0o700)).unwrap();
        let top_bytes = b"top\r\n";
        let leaf_bytes = b"nested\0bytes";
        fs::write(lower.join("top"), top_bytes).unwrap();
        fs::write(nested.join("leaf"), leaf_bytes).unwrap();
        for path in [lower.join("top"), nested.join("leaf")] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o666)).unwrap();
        }
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([75; 32]));
        let control = ControlStore::open(control_dir.join("control.db"), &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&control).unwrap();
        let control = Arc::new(Mutex::new(control));
        let view =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let mut config = Config::default();
        config.acl = SessionACL::All;
        let session = fuser::spawn_mount(view, &mountpoint, &config).unwrap();
        let result = (|| -> anyhow::Result<()> {
            let listing = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; print(','.join(sorted(os.listdir(sys.argv[1])))); print(','.join(sorted(os.listdir(sys.argv[2]))))")
                .arg(&mountpoint)
                .arg(mountpoint.join("nested"))
                .output()?;
            anyhow::ensure!(
                listing.status.success(),
                "nested listing failed: {}",
                String::from_utf8_lossy(&listing.stderr)
            );
            anyhow::ensure!(listing.stdout == b"nested,top\nleaf\n");
            let guest_read = Command::new("cat")
                .uid(65534)
                .gid(65534)
                .arg(mountpoint.join("nested/leaf"))
                .output()?;
            anyhow::ensure!(guest_read.status.success());
            anyhow::ensure!(guest_read.stdout == leaf_bytes);
            let unsupported_directory_rename = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("nested"))
                .arg(mountpoint.join("other"))
                .output()?;
            anyhow::ensure!(!unsupported_directory_rename.status.success());
            anyhow::ensure!(fs::read(mountpoint.join("nested/leaf"))? == leaf_bytes);
            let unsupported_replacement = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("nested/leaf"))
                .arg(mountpoint.join("top"))
                .output()?;
            anyhow::ensure!(!unsupported_replacement.status.success());
            anyhow::ensure!(fs::read(lower.join("top"))? == top_bytes);
            anyhow::ensure!(fs::read(nested.join("leaf"))? == leaf_bytes);
            let leaf_inode = fs::metadata(nested.join("leaf"))?.ino();
            let move_to_root = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("nested/leaf"))
                .arg(mountpoint.join("relocated"))
                .output()?;
            anyhow::ensure!(
                move_to_root.status.success(),
                "move from nested directory failed: {}",
                String::from_utf8_lossy(&move_to_root.stderr)
            );
            anyhow::ensure!(!nested.join("leaf").exists());
            anyhow::ensure!(fs::metadata(lower.join("relocated"))?.ino() == leaf_inode);
            anyhow::ensure!(fs::read(mountpoint.join("relocated"))? == leaf_bytes);
            let move_back = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("relocated"))
                .arg(mountpoint.join("nested/moved"))
                .output()?;
            anyhow::ensure!(
                move_back.status.success(),
                "move into nested directory failed: {}",
                String::from_utf8_lossy(&move_back.stderr)
            );
            anyhow::ensure!(!lower.join("relocated").exists());
            anyhow::ensure!(fs::metadata(nested.join("moved"))?.ino() == leaf_inode);
            let anchor_before = manifest.file_locator("nested/leaf".to_string())?.open()?;
            anyhow::ensure!(anchor_before.metadata()?.ino() == leaf_inode);
            drop(anchor_before);
            let edit = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("nested/moved"))
                .output()?;
            anyhow::ensure!(
                edit.status.success(),
                "nested edit failed: {}",
                String::from_utf8_lossy(&edit.stderr)
            );
            anyhow::ensure!(fs::read(nested.join("moved"))?.starts_with(b"EDIT"));
            anyhow::ensure!(fs::metadata(nested.join("moved"))?.ino() == leaf_inode);
            let mut anchor_after = manifest.file_locator("nested/leaf".to_string())?.open()?;
            anyhow::ensure!(anchor_after.metadata()?.ino() != leaf_inode);
            let mut bytes = Vec::new();
            anchor_after.read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes == leaf_bytes);
            anyhow::ensure!(fs::read(lower.join("top"))? == top_bytes);
            let top_anchor = manifest.file_locator("top".to_string())?.open()?;
            anyhow::ensure!(top_anchor.metadata()?.ino() == fs::metadata(lower.join("top"))?.ino());
            let create = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600); os.write(fd,b'new-nested'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("nested/new"))
                .output()?;
            anyhow::ensure!(
                create.status.success(),
                "nested guarded file creation failed: {}",
                String::from_utf8_lossy(&create.stderr)
            );
            anyhow::ensure!(fs::read(nested.join("new"))? == b"new-nested");
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        result.unwrap();
        unmounted.unwrap();
        let rebuilt =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let session = fuser::spawn_mount(rebuilt, &mountpoint, &config).unwrap();
        let replayed = (|| -> anyhow::Result<()> {
            anyhow::ensure!(!mountpoint.join("nested/leaf").exists());
            anyhow::ensure!(fs::read(mountpoint.join("nested/moved"))?.starts_with(b"EDIT"));
            anyhow::ensure!(fs::read(mountpoint.join("nested/new"))? == b"new-nested");
            anyhow::ensure!(fs::read(mountpoint.join("top"))? == top_bytes);
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        replayed.unwrap();
        unmounted.unwrap();
    }
}
