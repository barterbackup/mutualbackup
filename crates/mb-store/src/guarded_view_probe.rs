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
    ReplyAttr, ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, Request, SessionACL, TimeOrNow,
};

use crate::{
    CapturedEntry, ControlStore, GuardedRootCapturePlan, PinnedDirectory, StableAnchorManifest,
};

const FILE_INODE: INodeNo = INodeNo(2);
const ENTRY_TTL: Duration = Duration::ZERO;
const PROBE_BYTES: &[u8] = b"mutualbackup-guarded-view-probe";
// The kernel supplies O_LARGEFILE in FUSE_OPEN even when libc defines it as
// zero for the native 64-bit ABI.
const KERNEL_O_LARGEFILE: i32 = 0o100000;

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
/// mount supervision remain gated until namespace replay and mutation coverage
/// are complete. The caller must keep the lower source directory inaccessible
/// to ordinary users while this view is mounted.
pub struct GuardedProbeView {
    files: HashMap<u64, GuardedProbeFile>,
    directories: HashMap<u64, GuardedProbeDirectory>,
    names: Mutex<HashMap<(u64, OsString), u64>>,
    lower_root: Option<crate::PinnedDirectory>,
    root_uid: u32,
    root_gid: u32,
    root_perm: u16,
    poisoned: AtomicBool,
    next_handle: AtomicU64,
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
}

impl GuardedProbeView {
    /// Rebuild the initial namespace only while every captured source path is
    /// still at its recorded identity. A rename or unlink without a durable
    /// namespace journal fails closed instead of silently losing that change.
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
                    let lower_parent = if parent_path.as_os_str().is_empty() {
                        None
                    } else {
                        Some(lower_root.open_descendant_directory(parent_path)?)
                    };
                    let lower_parent = lower_parent.as_ref().unwrap_or(&lower_root);
                    ensure!(
                        lower_parent.entry_identity(name, false)? == Some(expected),
                        "guarded view file moved or changed after capture"
                    );
                    let source = lower_parent
                        .open_child_file(name)?
                        .context("guarded view source file disappeared")?;
                    let _anchor = manifest.file_locator(path.clone())?.open()?;
                    let mut attr = probe_file_attr(&source, inode, (mode & 0o7777) as u16)?;
                    attr.uid = view_uid;
                    attr.gid = view_gid;
                    let location = Arc::new(Mutex::new(Some(ProbeLocation {
                        parent,
                        relative_path: relative.to_path_buf(),
                    })));
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
        Ok(Self::with_directories(
            files,
            directories,
            (manifest.root_mode & 0o7777) as u16,
            Arc::new(AtomicU64::new(0)),
            Some(lower_root),
        ))
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
                by_inode.insert(inode, file).is_none(),
                "duplicate guarded view inode"
            );
        }
        Self {
            files: by_inode,
            directories: by_directory,
            names: Mutex::new(names),
            lower_root,
            root_uid,
            root_gid,
            root_perm,
            poisoned: AtomicBool::new(false),
            next_handle: AtomicU64::new(1),
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
        } else if let Some(file) = self.files.get(&inode) {
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
            _ => match self.files.get(&inode.0) {
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
        let Some(file) = self.files.get(&inode.0) else {
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
        let Some(file) = self.files.get(&inode.0) else {
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
        let Some(file) = self.files.get(&inode) else {
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
            source_parent
                .move_child_file_no_replace(name, expected, destination_parent, newname)
                .map_err(|error| {
                    // The rename may have happened before a directory fsync
                    // failed. Stop serving this view until it is reconciled.
                    self.poisoned.store(true, Ordering::Release);
                    io::Error::other(error)
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
        let Some(file) = self.files.get(&inode) else {
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
            lower.remove_child_file(name).map_err(io::Error::other)?;
            *current = None;
            names.remove(&key);
            lower.sync_all().map_err(|error| {
                self.poisoned.store(true, Ordering::Release);
                io::Error::other(error)
            })
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
        let Some(file) = self.files.get(&inode.0) else {
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
        LinkFreezeCapturePhase,
    };

    use super::{FILE_INODE, GuardedProbeFile, GuardedProbeView, ProbeLocation, probe_file_attr};

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
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        result.unwrap();
        unmounted.unwrap();
        assert!(
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .is_err(),
            "a moved file was silently adopted after the view was rebuilt"
        );
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
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        result.unwrap();
        unmounted.unwrap();
    }
}
