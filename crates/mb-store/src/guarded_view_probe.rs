//! Disposable Linux FUSE passthrough probe for the future guarded worktree.
//!
//! This proves that this host can mount a view, pass read-only file access to
//! lower inodes, and finish each captured file's durable detach before a
//! writable open or metadata edit. It also probes a nested file namespace,
//! creation, rename, unlink, and atomic replacement. It is not a complete
//! long-lived edit guard and must not be used as an enrollment decision by itself.

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
const REPLACE_KIND: &str = "guarded-view-replace-v1";
const DIRECTORY_KIND: &str = "guarded-view-directory-v1";
const DIRECTORY_CREATE_KIND: &str = "guarded-view-directory-create-v1";
const DIRECTORY_REMOVE_KIND: &str = "guarded-view-directory-remove-v1";
const DIRECTORY_RENAME_KIND: &str = "guarded-view-directory-rename-v1";
const DIRECTORY_REPLACE_KIND: &str = "guarded-view-directory-replace-v1";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirectoryRecord {
    version: u16,
    expected: NativeFileId,
    current: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirectoryCreateIntent {
    version: u16,
    staging_name: String,
    target: Vec<u8>,
    expected: Option<NativeFileId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirectoryRemoveIntent {
    version: u16,
    target: Vec<u8>,
    expected: NativeFileId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirectoryRenameIntent {
    version: u16,
    source: Vec<u8>,
    target: Vec<u8>,
    expected: NativeFileId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DirectoryReplaceIntent {
    version: u16,
    move_intent: DirectoryRenameIntent,
    target_inode: u64,
    target_expected: NativeFileId,
}

// Captured directories keep their capture-time identity and mode even after a
// namespace move. The current path is stored separately in DirectoryRecord.
type CapturedDirectories = HashMap<u64, (Vec<u8>, NativeFileId, u16)>;

struct DirectoryMoveContext<'a> {
    lower_root: &'a PinnedDirectory,
    captured: &'a CapturedDirectories,
    defaults: &'a HashMap<u64, NamespaceRecord>,
    first_dynamic_inode: u64,
}

struct GuardedDirectoryIndex {
    paths: HashMap<PathBuf, INodeNo>,
    captured: Vec<GuardedProbeDirectory>,
    dynamic: Vec<GuardedProbeDirectory>,
    highest_inode: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ReplaceIntent {
    version: u16,
    source_inode: u64,
    target_inode: u64,
    source_before: NamespaceRecord,
    target_before: NamespaceRecord,
}

impl ReplaceIntent {
    fn final_records(&self) -> anyhow::Result<(NamespaceRecord, NamespaceRecord)> {
        let target_path = self
            .target_before
            .current
            .as_ref()
            .context("replacement target has no path")?;
        let mut source = self.source_before.clone();
        source.current = Some(target_path.clone());
        source.pending = None;
        let mut target = self.target_before.clone();
        target.current = None;
        target.pending = None;
        Ok((source, target))
    }
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

    fn replace_id(&self, operation: Uuid) -> Vec<u8> {
        let mut id = self.anchor_id.as_bytes().to_vec();
        id.extend_from_slice(operation.as_bytes());
        id
    }

    fn begin_replace(
        &self,
        source_inode: u64,
        target_inode: u64,
    ) -> io::Result<(Vec<u8>, ReplaceIntent)> {
        let records = self.records.lock().unwrap();
        let source = records
            .get(&source_inode)
            .ok_or_else(|| io::Error::other("missing guarded replacement source"))?;
        let target = records
            .get(&target_inode)
            .ok_or_else(|| io::Error::other("missing guarded replacement target"))?;
        if source_inode == target_inode
            || source.pending.is_some()
            || target.pending.is_some()
            || source.current.is_none()
            || target.current.is_none()
            || source.current == target.current
            || source.expected == target.expected
        {
            return Err(io::Error::other("invalid guarded replacement state"));
        }
        let intent = ReplaceIntent {
            version: 1,
            source_inode,
            target_inode,
            source_before: source.clone(),
            target_before: target.clone(),
        };
        let id = self.replace_id(Uuid::new_v4());
        let bytes = mb_core::canonical_bytes(&intent).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(REPLACE_KIND, &id, &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded replacement ID collided",
            ));
        }
        Ok((id, intent))
    }

    fn publish_replace(&self, intent: &ReplaceIntent) -> io::Result<()> {
        let (source, target) = intent.final_records().map_err(io::Error::other)?;
        let source_bytes = mb_core::canonical_bytes(&source).map_err(io::Error::other)?;
        let target_bytes = mb_core::canonical_bytes(&target).map_err(io::Error::other)?;
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_records(&[
                (
                    NAMESPACE_KIND.to_owned(),
                    self.record_id(intent.source_inode),
                    source_bytes,
                ),
                (
                    NAMESPACE_KIND.to_owned(),
                    self.record_id(intent.target_inode),
                    target_bytes,
                ),
            ])
            .map_err(io::Error::other)?;
        let mut records = self.records.lock().unwrap();
        if records.contains_key(&intent.source_inode) {
            records.insert(intent.source_inode, source);
            records.insert(intent.target_inode, target);
        }
        Ok(())
    }

    fn retire_replace(&self, id: &[u8], intent: &ReplaceIntent) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(intent).map_err(io::Error::other)?;
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .delete_record_if_value(REPLACE_KIND, id, &bytes)
            .map_err(io::Error::other)
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

    fn store_directory_create(&self, inode: u64, intent: &DirectoryCreateIntent) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(intent).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(DIRECTORY_CREATE_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded directory inode already recorded",
            ));
        }
        Ok(())
    }

    fn advance_directory_create(
        &self,
        inode: u64,
        before: &DirectoryCreateIntent,
        after: &DirectoryCreateIntent,
    ) -> io::Result<()> {
        let before = mb_core::canonical_bytes(before).map_err(io::Error::other)?;
        let after = mb_core::canonical_bytes(after).map_err(io::Error::other)?;
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .replace_record_if_value(
                DIRECTORY_CREATE_KIND,
                &self.record_id(inode),
                &before,
                &after,
            )
            .map_err(io::Error::other)
    }

    fn finish_directory_create(
        &self,
        inode: u64,
        intent: &DirectoryCreateIntent,
    ) -> io::Result<()> {
        let expected = intent
            .expected
            .ok_or_else(|| io::Error::other("guarded directory identity was not recorded"))?;
        let record = DirectoryRecord {
            version: 1,
            expected,
            current: Some(intent.target.clone()),
        };
        let bytes = mb_core::canonical_bytes(&record).map_err(io::Error::other)?;
        let id = self.record_id(inode);
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_records_and_delete(
                &[(DIRECTORY_KIND.to_owned(), id.clone(), bytes)],
                &[(DIRECTORY_CREATE_KIND.to_owned(), id)],
            )
            .map_err(io::Error::other)
    }

    fn directory_record_opt(&self, inode: u64) -> io::Result<Option<DirectoryRecord>> {
        let bytes = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .get_record(DIRECTORY_KIND, &self.record_id(inode))
            .map_err(io::Error::other)?;
        bytes
            .map(|bytes| mb_core::decode_canonical(&bytes).map_err(io::Error::other))
            .transpose()
    }

    fn directory_record(&self, inode: u64) -> io::Result<DirectoryRecord> {
        self.directory_record_opt(inode)?
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
    }

    fn store_directory_if_absent(&self, inode: u64, record: &DirectoryRecord) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(record).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(DIRECTORY_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded directory record already exists",
            ));
        }
        Ok(())
    }

    fn store_directory_remove(&self, inode: u64, intent: &DirectoryRemoveIntent) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(intent).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(DIRECTORY_REMOVE_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded directory removal is already pending",
            ));
        }
        Ok(())
    }

    fn finish_directory_remove(
        &self,
        inode: u64,
        intent: &DirectoryRemoveIntent,
    ) -> io::Result<()> {
        let record = DirectoryRecord {
            version: 1,
            expected: intent.expected,
            current: None,
        };
        let bytes = mb_core::canonical_bytes(&record).map_err(io::Error::other)?;
        let id = self.record_id(inode);
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_records_and_delete(
                &[(DIRECTORY_KIND.to_owned(), id.clone(), bytes)],
                &[(DIRECTORY_REMOVE_KIND.to_owned(), id)],
            )
            .map_err(io::Error::other)
    }

    fn store_directory_rename(&self, inode: u64, intent: &DirectoryRenameIntent) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(intent).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(DIRECTORY_RENAME_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded directory rename is already pending",
            ));
        }
        Ok(())
    }

    fn store_directory_replace(
        &self,
        inode: u64,
        intent: &DirectoryReplaceIntent,
    ) -> io::Result<()> {
        let bytes = mb_core::canonical_bytes(intent).map_err(io::Error::other)?;
        let inserted = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_record_if_absent(DIRECTORY_REPLACE_KIND, &self.record_id(inode), &bytes)
            .map_err(io::Error::other)?;
        if !inserted {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "guarded directory replacement is already pending",
            ));
        }
        Ok(())
    }

    fn validate_directory_rename_source(
        &self,
        inode: u64,
        intent: &DirectoryRenameIntent,
        captured: &CapturedDirectories,
        first_dynamic_inode: u64,
    ) -> anyhow::Result<()> {
        if inode < first_dynamic_inode {
            ensure!(
                captured
                    .get(&inode)
                    .is_some_and(|(_, expected, _)| *expected == intent.expected),
                "guarded directory rename aliases captured file or changed identity"
            );
        }
        let record = match self.directory_record_opt(inode)? {
            Some(record) => record,
            None => {
                let (path, expected, _) = captured
                    .get(&inode)
                    .context("guarded directory rename has no source record")?;
                DirectoryRecord {
                    version: 1,
                    expected: *expected,
                    current: Some(path.clone()),
                }
            }
        };
        ensure!(
            record.version == 1
                && record.expected == intent.expected
                && record.current.as_deref() == Some(intent.source.as_slice()),
            "guarded directory rename differs from source record"
        );
        Ok(())
    }

    fn finish_directory_move(
        &self,
        context: DirectoryMoveContext<'_>,
        inode: u64,
        intent: &DirectoryRenameIntent,
        replaced: Option<(u64, NativeFileId)>,
        intent_kind: &str,
        intent_bytes: &[u8],
    ) -> anyhow::Result<Vec<(u64, NamespaceRecord)>> {
        let DirectoryMoveContext {
            lower_root,
            captured,
            defaults,
            first_dynamic_inode,
        } = context;
        ensure!(
            intent.version == 1,
            "unsupported guarded directory rename intent"
        );
        let source = checked_namespace_relative_path(&intent.source)?;
        let target = checked_namespace_relative_path(&intent.target)?;
        ensure!(
            source != target && !target.starts_with(&source),
            "invalid guarded directory rename paths"
        );
        if replaced.is_some() {
            ensure!(
                !source.starts_with(&target),
                "guarded directory replacement target contains its source"
            );
        }
        ensure!(
            intent.expected.filesystem_id == lower_root.identity()?.filesystem_id,
            "guarded directory rename belongs to another filesystem"
        );
        let old_owned = namespace_parent(lower_root, &source)?;
        let new_owned = namespace_parent(lower_root, &target)?;
        let old_parent = old_owned.as_ref().unwrap_or(lower_root);
        let new_parent = new_owned.as_ref().unwrap_or(lower_root);
        ensure!(
            old_parent
                .entry_identity(source.file_name().unwrap(), true)?
                .is_none()
                && new_parent.entry_identity(target.file_name().unwrap(), true)?
                    == Some(intent.expected),
            "guarded directory move has not finished in the lower namespace"
        );
        let mut directories = HashMap::new();
        for (&captured_inode, (path, expected, _)) in captured {
            directories.insert(
                captured_inode,
                DirectoryRecord {
                    version: 1,
                    expected: *expected,
                    current: Some(path.clone()),
                },
            );
        }
        for (stored_inode, bytes) in self.owned_records(DIRECTORY_KIND)? {
            let record: DirectoryRecord = mb_core::decode_canonical(&bytes)?;
            ensure!(record.version == 1, "invalid guarded directory record");
            if stored_inode < first_dynamic_inode {
                ensure!(
                    captured
                        .get(&stored_inode)
                        .is_some_and(|(_, expected, _)| *expected == record.expected),
                    "guarded directory record differs from capture"
                );
            }
            directories.insert(stored_inode, record);
        }
        let root_record = directories
            .get(&inode)
            .context("guarded directory rename has no source record")?;
        ensure!(
            root_record.current.as_deref() == Some(intent.source.as_slice())
                && root_record.expected == intent.expected,
            "guarded directory rename differs from source record"
        );
        if let Some((target_inode, target_expected)) = replaced {
            ensure!(target_inode != inode, "guarded directory replaces itself");
            let record = directories
                .get(&target_inode)
                .context("guarded directory replacement has no target record")?;
            ensure!(
                record.current.as_deref() == Some(intent.target.as_slice())
                    && record.expected == target_expected,
                "guarded directory replacement differs from target record"
            );
        }

        let mut files = defaults.clone();
        for (stored_inode, bytes) in self.owned_records(NAMESPACE_KIND)? {
            let record: NamespaceRecord = mb_core::decode_canonical(&bytes)?;
            ensure!(record.version == 1, "invalid guarded namespace record");
            if stored_inode < first_dynamic_inode {
                ensure!(
                    defaults.get(&stored_inode).is_some_and(|default| {
                        default.captured_path == record.captured_path
                            && default.expected == record.expected
                    }),
                    "guarded namespace record differs from capture"
                );
            } else {
                ensure!(
                    record.captured_path.is_empty()
                        && record.expected.filesystem_id == intent.expected.filesystem_id,
                    "invalid dynamic guarded namespace record"
                );
            }
            files.insert(stored_inode, record);
        }

        let mut occupied = std::collections::HashSet::new();
        let mut writes = Vec::new();
        let mut changed_files = Vec::new();
        for (entry_inode, mut record) in directories {
            let Some(current) = &record.current else {
                continue;
            };
            if replaced.is_some_and(|(target_inode, _)| target_inode == entry_inode) {
                record.current = None;
                writes.push((
                    DIRECTORY_KIND.to_owned(),
                    self.record_id(entry_inode),
                    mb_core::canonical_bytes(&record)?,
                ));
                continue;
            }
            let before = checked_namespace_relative_path(current)?;
            let after = rebased_namespace_path(&before, &source, &target);
            ensure!(
                occupied.insert(after.clone()),
                "duplicate guarded namespace path"
            );
            if after != before {
                let actual = lower_root.open_descendant_directory(&after)?.identity()?;
                ensure!(
                    actual == record.expected,
                    "renamed guarded directory changed identity"
                );
                record.current = Some(after.into_os_string().into_vec());
                writes.push((
                    DIRECTORY_KIND.to_owned(),
                    self.record_id(entry_inode),
                    mb_core::canonical_bytes(&record)?,
                ));
            }
        }
        for (entry_inode, mut record) in files {
            let Some(current) = &record.current else {
                continue;
            };
            let before = checked_namespace_relative_path(current)?;
            let after = rebased_namespace_path(&before, &source, &target);
            ensure!(
                occupied.insert(after.clone()),
                "duplicate guarded namespace path"
            );
            if after != before {
                ensure!(
                    record.pending.is_none(),
                    "guarded rename overlaps file transition"
                );
                let parent = namespace_parent(lower_root, &after)?;
                let parent = parent.as_ref().unwrap_or(lower_root);
                ensure!(
                    parent.entry_identity(after.file_name().unwrap(), false)?
                        == Some(record.expected),
                    "renamed guarded file changed identity"
                );
                record.current = Some(after.into_os_string().into_vec());
                writes.push((
                    NAMESPACE_KIND.to_owned(),
                    self.record_id(entry_inode),
                    mb_core::canonical_bytes(&record)?,
                ));
                changed_files.push((entry_inode, record));
            }
        }
        self.control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .put_records_and_retire_if_value(
                &writes,
                intent_kind,
                &self.record_id(inode),
                intent_bytes,
            )?;
        Ok(changed_files)
    }

    fn finish_directory_rename(
        &self,
        lower_root: &PinnedDirectory,
        captured: &CapturedDirectories,
        defaults: &HashMap<u64, NamespaceRecord>,
        first_dynamic_inode: u64,
        inode: u64,
        intent: &DirectoryRenameIntent,
    ) -> anyhow::Result<Vec<(u64, NamespaceRecord)>> {
        let bytes = mb_core::canonical_bytes(intent)?;
        self.finish_directory_move(
            DirectoryMoveContext {
                lower_root,
                captured,
                defaults,
                first_dynamic_inode,
            },
            inode,
            intent,
            None,
            DIRECTORY_RENAME_KIND,
            &bytes,
        )
    }

    fn finish_directory_replace(
        &self,
        lower_root: &PinnedDirectory,
        captured: &CapturedDirectories,
        defaults: &HashMap<u64, NamespaceRecord>,
        first_dynamic_inode: u64,
        source_inode: u64,
        intent: &DirectoryReplaceIntent,
    ) -> anyhow::Result<Vec<(u64, NamespaceRecord)>> {
        let bytes = mb_core::canonical_bytes(intent)?;
        self.finish_directory_move(
            DirectoryMoveContext {
                lower_root,
                captured,
                defaults,
                first_dynamic_inode,
            },
            source_inode,
            &intent.move_intent,
            Some((intent.target_inode, intent.target_expected)),
            DIRECTORY_REPLACE_KIND,
            &bytes,
        )
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

    fn reconcile_directory_creates(
        &self,
        lower_root: &PinnedDirectory,
        staging_area: &PinnedDirectory,
        directories: &HashMap<PathBuf, INodeNo>,
        first_dynamic_inode: u64,
    ) -> anyhow::Result<()> {
        const PREFIX: &str = ".guarded-mkdir-";
        for (inode, bytes) in self.owned_records(DIRECTORY_CREATE_KIND)? {
            ensure!(
                inode >= first_dynamic_inode,
                "guarded directory create aliases captured inode"
            );
            let intent: DirectoryCreateIntent = mb_core::decode_canonical(&bytes)?;
            ensure!(
                intent.version == 1
                    && intent.staging_name.starts_with(PREFIX)
                    && Uuid::parse_str(&intent.staging_name[PREFIX.len()..]).is_ok(),
                "invalid guarded directory creation intent"
            );
            let (target, _) = namespace_path(&intent.target, directories)?;
            let owned = namespace_parent(lower_root, &target)?;
            let target_parent = owned.as_ref().unwrap_or(lower_root);
            let target_name = target.file_name().unwrap();
            let target_id = target_parent.entry_identity(target_name, true)?;
            let stage_id = staging_area
                .open_child_directory(&intent.staging_name)?
                .map(|directory| directory.identity())
                .transpose()?;
            if let Some(expected) = intent.expected {
                ensure!(
                    expected.filesystem_id == lower_root.identity()?.filesystem_id,
                    "guarded directory belongs to another filesystem"
                );
                match (stage_id, target_id) {
                    (Some(actual), None) if actual == expected => {
                        staging_area.move_child_directory_no_replace(
                            &intent.staging_name,
                            expected,
                            target_parent,
                            target_name,
                        )?;
                    }
                    (None, Some(actual)) if actual == expected => {
                        staging_area.sync_all()?;
                        target_parent.sync_all()?;
                    }
                    _ => anyhow::bail!("guarded directory create cannot be safely replayed"),
                }
                self.finish_directory_create(inode, &intent)?;
            } else {
                ensure!(
                    target_id.is_none(),
                    "unidentified guarded directory was already published"
                );
                if let Some(stage_id) = stage_id {
                    ensure!(
                        staging_area
                            .remove_empty_child_directory(&intent.staging_name, stage_id)?,
                        "unidentified guarded staging directory is not empty"
                    );
                }
                self.control
                    .lock()
                    .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
                    .delete_record_if_value(
                        DIRECTORY_CREATE_KIND,
                        &self.record_id(inode),
                        &bytes,
                    )?;
            }
        }
        Ok(())
    }

    fn reconcile_directory_removes(
        &self,
        lower_root: &PinnedDirectory,
        directories: &HashMap<PathBuf, INodeNo>,
        first_dynamic_inode: u64,
        captured_directories: &CapturedDirectories,
    ) -> anyhow::Result<()> {
        for (inode, bytes) in self.owned_records(DIRECTORY_REMOVE_KIND)? {
            let intent: DirectoryRemoveIntent = mb_core::decode_canonical(&bytes)?;
            ensure!(
                intent.version == 1
                    && intent.expected.filesystem_id == lower_root.identity()?.filesystem_id,
                "invalid guarded directory removal intent"
            );
            if inode < first_dynamic_inode {
                let (_, captured_id, _) = captured_directories
                    .get(&inode)
                    .context("guarded directory removal aliases captured file")?;
                ensure!(
                    *captured_id == intent.expected,
                    "guarded directory removal differs from capture"
                );
            }
            let record = self.directory_record(inode)?;
            ensure!(
                record.version == 1
                    && record.current.as_deref() == Some(intent.target.as_slice())
                    && record.expected == intent.expected,
                "guarded directory removal differs from stored directory"
            );
            let (path, _) = namespace_path(&intent.target, directories)?;
            let owned = namespace_parent(lower_root, &path)?;
            let parent = owned.as_ref().unwrap_or(lower_root);
            let name = path.file_name().unwrap();
            match parent.entry_identity(name, true)? {
                Some(actual) if actual == intent.expected => {
                    ensure!(
                        parent.remove_empty_child_directory(name, intent.expected)?,
                        "guarded directory is not empty during removal replay"
                    );
                }
                None => parent.sync_all()?,
                _ => anyhow::bail!("guarded directory changed before removal replay"),
            }
            self.finish_directory_remove(inode, &intent)?;
        }
        Ok(())
    }

    fn reconcile_directory_renames(
        &self,
        lower_root: &PinnedDirectory,
        captured: &CapturedDirectories,
        defaults: &HashMap<u64, NamespaceRecord>,
        first_dynamic_inode: u64,
    ) -> anyhow::Result<()> {
        let pending = self.owned_records(DIRECTORY_RENAME_KIND)?;
        ensure!(
            pending.len() <= 1,
            "multiple guarded directory renames are pending"
        );
        for (inode, bytes) in pending {
            let intent: DirectoryRenameIntent = mb_core::decode_canonical(&bytes)?;
            ensure!(
                intent.version == 1,
                "unsupported guarded directory rename intent"
            );
            self.validate_directory_rename_source(inode, &intent, captured, first_dynamic_inode)?;
            let source = checked_namespace_relative_path(&intent.source)?;
            let target = checked_namespace_relative_path(&intent.target)?;
            ensure!(
                source != target && !target.starts_with(&source),
                "invalid guarded directory rename paths"
            );
            let old_owned = namespace_parent(lower_root, &source)?;
            let new_owned = namespace_parent(lower_root, &target)?;
            let old_parent = old_owned.as_ref().unwrap_or(lower_root);
            let new_parent = new_owned.as_ref().unwrap_or(lower_root);
            let old_name = source.file_name().unwrap();
            let new_name = target.file_name().unwrap();
            let old_id = old_parent.entry_identity(old_name, true)?;
            let new_id = new_parent.entry_identity(new_name, true)?;
            match (old_id, new_id) {
                (Some(actual), None) if actual == intent.expected => {
                    old_parent.move_child_directory_no_replace(
                        old_name,
                        intent.expected,
                        new_parent,
                        new_name,
                    )?;
                }
                (None, Some(actual)) if actual == intent.expected => {
                    old_parent.sync_all()?;
                    new_parent.sync_all()?;
                }
                _ => anyhow::bail!("guarded directory rename cannot be safely replayed"),
            }
            self.finish_directory_rename(
                lower_root,
                captured,
                defaults,
                first_dynamic_inode,
                inode,
                &intent,
            )?;
        }
        Ok(())
    }

    fn reconcile_directory_replaces(
        &self,
        lower_root: &PinnedDirectory,
        captured: &CapturedDirectories,
        defaults: &HashMap<u64, NamespaceRecord>,
        first_dynamic_inode: u64,
    ) -> anyhow::Result<()> {
        let pending = self.owned_records(DIRECTORY_REPLACE_KIND)?;
        ensure!(
            pending.len() <= 1,
            "multiple guarded directory replacements are pending"
        );
        ensure!(
            pending.is_empty() || self.owned_records(DIRECTORY_RENAME_KIND)?.is_empty(),
            "guarded directory moves overlap"
        );
        for (source_inode, bytes) in pending {
            let intent: DirectoryReplaceIntent = mb_core::decode_canonical(&bytes)?;
            ensure!(
                intent.version == 1
                    && intent.move_intent.version == 1
                    && source_inode != intent.target_inode
                    && intent.move_intent.expected != intent.target_expected
                    && intent.target_expected.filesystem_id == lower_root.identity()?.filesystem_id,
                "invalid guarded directory replacement intent"
            );
            self.validate_directory_rename_source(
                source_inode,
                &intent.move_intent,
                captured,
                first_dynamic_inode,
            )?;
            let target_record = DirectoryRenameIntent {
                version: 1,
                source: intent.move_intent.target.clone(),
                target: intent.move_intent.source.clone(),
                expected: intent.target_expected,
            };
            self.validate_directory_rename_source(
                intent.target_inode,
                &target_record,
                captured,
                first_dynamic_inode,
            )?;
            let source = checked_namespace_relative_path(&intent.move_intent.source)?;
            let target = checked_namespace_relative_path(&intent.move_intent.target)?;
            ensure!(
                source != target && !source.starts_with(&target) && !target.starts_with(&source),
                "invalid guarded directory replacement paths"
            );
            let old_owned = namespace_parent(lower_root, &source)?;
            let new_owned = namespace_parent(lower_root, &target)?;
            let old_parent = old_owned.as_ref().unwrap_or(lower_root);
            let new_parent = new_owned.as_ref().unwrap_or(lower_root);
            let old_name = source.file_name().unwrap();
            let new_name = target.file_name().unwrap();
            let old_id = old_parent.entry_identity(old_name, true)?;
            let new_id = new_parent.entry_identity(new_name, true)?;
            match (old_id, new_id) {
                (Some(old), Some(new))
                    if old == intent.move_intent.expected && new == intent.target_expected =>
                {
                    ensure!(
                        new_parent.child_directory_is_empty(new_name, intent.target_expected)?,
                        "guarded directory replacement target is not empty"
                    );
                    old_parent.exchange_child_directories(
                        old_name,
                        intent.move_intent.expected,
                        new_parent,
                        new_name,
                        intent.target_expected,
                    )?;
                }
                (Some(old), Some(new))
                    if old == intent.target_expected && new == intent.move_intent.expected =>
                {
                    old_parent.sync_all()?;
                    new_parent.sync_all()?;
                }
                (None, Some(new)) if new == intent.move_intent.expected => {
                    old_parent.sync_all()?;
                    new_parent.sync_all()?;
                }
                _ => anyhow::bail!("guarded directory replacement cannot be safely replayed"),
            }
            if old_parent.entry_identity(old_name, true)? == Some(intent.target_expected) {
                ensure!(
                    old_parent.remove_empty_child_directory(old_name, intent.target_expected)?,
                    "displaced guarded directory is not empty"
                );
            }
            self.finish_directory_replace(
                lower_root,
                captured,
                defaults,
                first_dynamic_inode,
                source_inode,
                &intent,
            )?;
        }
        Ok(())
    }

    fn load_directories(
        &self,
        lower_root: &PinnedDirectory,
        captured: &CapturedDirectories,
        first_dynamic_inode: u64,
        view_uid: u32,
        view_gid: u32,
    ) -> anyhow::Result<GuardedDirectoryIndex> {
        let mut stored = HashMap::new();
        let mut highest = first_dynamic_inode - 1;
        let pending_removes: std::collections::HashSet<_> = self
            .owned_records(DIRECTORY_REMOVE_KIND)?
            .into_iter()
            .map(|(inode, _)| inode)
            .collect();
        for (inode, bytes) in self.owned_records(DIRECTORY_KIND)? {
            let record: DirectoryRecord = mb_core::decode_canonical(&bytes)?;
            ensure!(
                record.version == 1
                    && record.expected.filesystem_id == lower_root.identity()?.filesystem_id,
                "invalid guarded directory record"
            );
            if inode < first_dynamic_inode {
                ensure!(
                    captured.contains_key(&inode),
                    "guarded directory aliases captured file"
                );
            } else {
                highest = highest.max(inode);
            }
            ensure!(
                stored.insert(inode, record).is_none(),
                "duplicate directory inode"
            );
        }
        let mut entries = Vec::new();
        for (&inode, (original, expected, mode)) in captured {
            let current = match stored.remove(&inode) {
                Some(record) => {
                    ensure!(
                        record.expected == *expected,
                        "captured directory identity changed"
                    );
                    record.current
                }
                None => Some(original.clone()),
            };
            if let Some(current) = current
                && !pending_removes.contains(&inode)
            {
                entries.push((
                    inode,
                    PathBuf::from(OsString::from_vec(current)),
                    *expected,
                    Some(*mode),
                ));
            }
        }
        for (inode, record) in stored {
            if let Some(current) = record.current
                && !pending_removes.contains(&inode)
            {
                entries.push((
                    inode,
                    PathBuf::from(OsString::from_vec(current)),
                    record.expected,
                    None,
                ));
            }
        }
        entries.sort_by_key(|(_, path, _, _)| path.components().count());
        let mut paths = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        let mut captured_views = Vec::new();
        let mut dynamic_views = Vec::new();
        for (inode, path, expected, captured_mode) in entries {
            let (_, parent) = namespace_path(path.as_os_str().as_bytes(), &paths)?;
            let lower = lower_root.open_descendant_directory(&path)?;
            ensure!(
                lower.identity()? == expected,
                "guarded directory changed after publication"
            );
            let mode = captured_mode
                .unwrap_or((lower.as_file().metadata()?.permissions().mode() & 0o7777) as u16);
            let mut attr = probe_directory_attr(lower.as_file(), INodeNo(inode), mode)?;
            attr.uid = view_uid;
            attr.gid = view_gid;
            let name = path
                .file_name()
                .context("created guarded directory has no name")?
                .to_os_string();
            ensure!(
                paths.insert(path.clone(), INodeNo(inode)).is_none(),
                "duplicate guarded directory path"
            );
            let view = GuardedProbeDirectory {
                attr,
                parent,
                name,
                relative_path: path,
                native_id: expected,
            };
            if captured_mode.is_some() {
                captured_views.push(view);
            } else {
                dynamic_views.push(view);
            }
        }
        Ok(GuardedDirectoryIndex {
            paths,
            captured: captured_views,
            dynamic: dynamic_views,
            highest_inode: highest,
        })
    }

    fn stored_or_default(
        &self,
        inode: u64,
        defaults: &HashMap<u64, NamespaceRecord>,
    ) -> anyhow::Result<NamespaceRecord> {
        let bytes = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .get_record(NAMESPACE_KIND, &self.record_id(inode))?;
        match bytes {
            Some(bytes) => Ok(mb_core::decode_canonical(&bytes)?),
            None => defaults
                .get(&inode)
                .cloned()
                .context("replacement inode has no captured or created record"),
        }
    }

    fn reconcile_replaces(
        &self,
        lower_root: &PinnedDirectory,
        directories: &HashMap<PathBuf, INodeNo>,
        defaults: &HashMap<u64, NamespaceRecord>,
        first_dynamic_inode: u64,
    ) -> anyhow::Result<()> {
        let rows = self
            .control
            .lock()
            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?
            .records(REPLACE_KIND)?;
        for (id, bytes) in rows {
            if !id.starts_with(self.anchor_id.as_bytes()) {
                continue;
            }
            ensure!(id.len() == 32, "malformed guarded replacement ID");
            let intent: ReplaceIntent = mb_core::decode_canonical(&bytes)?;
            ensure!(
                intent.version == 1
                    && intent.source_inode != intent.target_inode
                    && intent.source_before.version == 1
                    && intent.target_before.version == 1
                    && intent.source_before.pending.is_none()
                    && intent.target_before.pending.is_none()
                    && intent.source_before.expected != intent.target_before.expected,
                "invalid guarded replacement intent"
            );
            for (inode, record) in [
                (intent.source_inode, &intent.source_before),
                (intent.target_inode, &intent.target_before),
            ] {
                ensure!(
                    record.expected.filesystem_id == lower_root.identity()?.filesystem_id,
                    "guarded replacement belongs to another filesystem"
                );
                ensure!(
                    inode >= first_dynamic_inode || defaults.contains_key(&inode),
                    "guarded replacement aliases a captured directory"
                );
                if let Some(default) = defaults.get(&inode) {
                    ensure!(
                        default.captured_path == record.captured_path
                            && default.expected == record.expected,
                        "guarded replacement contradicts captured file"
                    );
                } else {
                    ensure!(
                        record.captured_path.is_empty(),
                        "guarded replacement has unknown captured file"
                    );
                }
            }
            let (source_after, target_after) = intent.final_records()?;
            let source_current = self.stored_or_default(intent.source_inode, defaults)?;
            let target_current = self.stored_or_default(intent.target_inode, defaults)?;
            ensure!(
                (source_current == intent.source_before && target_current == intent.target_before)
                    || (source_current == source_after && target_current == target_after),
                "guarded replacement records diverged from intent"
            );
            let source_bytes = intent
                .source_before
                .current
                .as_ref()
                .context("replacement source has no path")?;
            let target_bytes = intent
                .target_before
                .current
                .as_ref()
                .context("replacement target has no path")?;
            let (source_path, _) = namespace_path(source_bytes, directories)?;
            let (target_path, _) = namespace_path(target_bytes, directories)?;
            ensure!(
                source_path != target_path,
                "replacement paths are identical"
            );
            let source_owned = namespace_parent(lower_root, &source_path)?;
            let target_owned = namespace_parent(lower_root, &target_path)?;
            let source_parent = source_owned.as_ref().unwrap_or(lower_root);
            let target_parent = target_owned.as_ref().unwrap_or(lower_root);
            let source_name = source_path.file_name().unwrap();
            let target_name = target_path.file_name().unwrap();
            let source_id = intent.source_before.expected;
            let target_id = intent.target_before.expected;
            let source_at = source_parent.entry_identity(source_name, false)?;
            let target_at = target_parent.entry_identity(target_name, false)?;
            match (source_at, target_at) {
                (Some(from), Some(to)) if from == source_id && to == target_id => {
                    source_parent.exchange_child_files(
                        source_name,
                        source_id,
                        target_parent,
                        target_name,
                        target_id,
                    )?;
                }
                (Some(from), Some(to)) if from == target_id && to == source_id => {
                    source_parent.sync_all()?;
                    target_parent.sync_all()?;
                }
                (None, Some(to)) if to == source_id => {
                    source_parent.sync_all()?;
                    target_parent.sync_all()?;
                }
                _ => anyhow::bail!("guarded replacement cannot be safely replayed"),
            }
            self.publish_replace(&intent)?;
            match source_parent.entry_identity(source_name, false)? {
                Some(actual) if actual == target_id => {
                    source_parent.remove_child_file_if_identity(source_name, target_id)?;
                }
                None => source_parent.sync_all()?,
                _ => anyhow::bail!("old guarded replacement target changed before cleanup"),
            }
            self.retire_replace(&id, &intent)?;
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

fn checked_namespace_relative_path(bytes: &[u8]) -> anyhow::Result<PathBuf> {
    let path = PathBuf::from(OsString::from_vec(bytes.to_vec()));
    ensure!(
        path.components()
            .all(|part| matches!(part, std::path::Component::Normal(_)))
            && path.file_name().is_some(),
        "invalid guarded namespace path"
    );
    Ok(path)
}

fn rebased_namespace_path(path: &Path, source: &Path, target: &Path) -> PathBuf {
    match path.strip_prefix(source) {
        Ok(suffix) => target.join(suffix),
        Err(_) => path.to_path_buf(),
    }
}

fn namespace_path(
    bytes: &[u8],
    directories: &HashMap<PathBuf, INodeNo>,
) -> anyhow::Result<(PathBuf, INodeNo)> {
    let path = checked_namespace_relative_path(bytes)?;
    let parent = path
        .parent()
        .context("guarded namespace path has no parent")?;
    let inode = *directories
        .get(parent)
        .context("guarded namespace parent is not captured")?;
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

#[derive(Clone)]
struct GuardedProbeDirectory {
    attr: FileAttr,
    parent: INodeNo,
    name: OsString,
    relative_path: PathBuf,
    native_id: NativeFileId,
}

/// Experimental FUSE view for a published guarded capture. Enrollment and
/// mount supervision remain gated until directory mutation coverage and the
/// remaining write paths are complete. The caller must keep the lower source
/// directory inaccessible to ordinary users while this view is mounted.
pub struct GuardedProbeView {
    files: HashMap<u64, Arc<GuardedProbeFile>>,
    dynamic_files: Mutex<HashMap<u64, Arc<GuardedProbeFile>>>,
    directories: HashMap<u64, GuardedProbeDirectory>,
    dynamic_directories: Mutex<HashMap<u64, GuardedProbeDirectory>>,
    removed_directories: Mutex<std::collections::HashSet<u64>>,
    captured_directories: CapturedDirectories,
    file_defaults: HashMap<u64, NamespaceRecord>,
    first_dynamic_inode: u64,
    names: Mutex<HashMap<(u64, OsString), u64>>,
    lower_root: Option<crate::PinnedDirectory>,
    staging_area: Option<crate::PinnedDirectory>,
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

    fn directory(&self, inode: u64) -> Option<GuardedProbeDirectory> {
        if self.removed_directories.lock().unwrap().contains(&inode) {
            return None;
        }
        self.dynamic_directories
            .lock()
            .unwrap()
            .get(&inode)
            .cloned()
            .or_else(|| self.directories.get(&inode).cloned())
    }

    fn rename_directory(
        &self,
        inode: u64,
        old_key: &(u64, OsString),
        new_key: &(u64, OsString),
        replaced: Option<(u64, GuardedProbeDirectory)>,
        names: &mut HashMap<(u64, OsString), u64>,
    ) -> io::Result<()> {
        let lower_root = self
            .lower_root
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let namespace = self
            .namespace
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let directory = self
            .directory(inode)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if directory.parent.0 != old_key.0 || directory.name != old_key.1 {
            return Err(io::Error::other("guarded directory location changed"));
        }
        let new_name = Path::new(&new_key.1);
        if new_key.1.as_bytes().contains(&0)
            || new_name.components().count() != 1
            || !matches!(
                new_name.components().next(),
                Some(std::path::Component::Normal(_))
            )
        {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        let new_parent_path = if new_key.0 == INodeNo::ROOT.0 {
            PathBuf::new()
        } else {
            self.directory(new_key.0)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
                .relative_path
        };
        let target = new_parent_path.join(&new_key.1);
        let source = directory.relative_path.clone();
        if target.starts_with(&source) || replaced.is_some() && source.starts_with(&target) {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        checked_namespace_relative_path(target.as_os_str().as_bytes()).map_err(io::Error::other)?;
        let intent = DirectoryRenameIntent {
            version: 1,
            source: source.as_os_str().as_bytes().to_vec(),
            target: target.as_os_str().as_bytes().to_vec(),
            expected: directory.native_id,
        };
        namespace
            .validate_directory_rename_source(
                inode,
                &intent,
                &self.captured_directories,
                self.first_dynamic_inode,
            )
            .map_err(io::Error::other)?;
        if let Some((target_inode, target_directory)) = &replaced {
            if *target_inode == inode
                || target_directory.parent.0 != new_key.0
                || target_directory.name != new_key.1
                || target_directory.relative_path != target
                || target_directory.native_id == directory.native_id
                || names.keys().any(|(parent, _)| *parent == *target_inode)
            {
                return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
            }
            let target_record = DirectoryRenameIntent {
                version: 1,
                source: intent.target.clone(),
                target: intent.source.clone(),
                expected: target_directory.native_id,
            };
            namespace
                .validate_directory_rename_source(
                    *target_inode,
                    &target_record,
                    &self.captured_directories,
                    self.first_dynamic_inode,
                )
                .map_err(io::Error::other)?;
        }
        // Keep writable opens from observing a moved lower path before its
        // durable namespace records and in-memory locations are updated.
        let mut files: Vec<_> = self
            .files
            .iter()
            .map(|(&inode, file)| (inode, Arc::clone(file)))
            .collect();
        files.extend(
            self.dynamic_files
                .lock()
                .unwrap()
                .iter()
                .map(|(&inode, file)| (inode, Arc::clone(file))),
        );
        files.sort_by_key(|(inode, _)| *inode);
        let mut locations: Vec<_> = files
            .iter()
            .map(|(inode, file)| (*inode, file.location.lock().unwrap()))
            .collect();
        let mut directory_inodes: Vec<_> = self.directories.keys().copied().collect();
        directory_inodes.extend(self.dynamic_directories.lock().unwrap().keys().copied());
        directory_inodes.sort_unstable();
        directory_inodes.dedup();
        let mut directory_updates = Vec::new();
        for entry_inode in directory_inodes {
            let Some(mut entry) = self.directory(entry_inode) else {
                continue;
            };
            if entry.relative_path.starts_with(&source) {
                entry.relative_path =
                    rebased_namespace_path(&entry.relative_path, &source, &target);
                if entry_inode == inode {
                    entry.parent = INodeNo(new_key.0);
                    entry.name = new_key.1.clone();
                }
                directory_updates.push((entry_inode, entry));
            }
        }
        let old_owned = namespace_parent(lower_root, &source).map_err(io::Error::other)?;
        let new_owned = namespace_parent(lower_root, &target).map_err(io::Error::other)?;
        let old_parent = old_owned.as_ref().unwrap_or(lower_root);
        let new_parent = new_owned.as_ref().unwrap_or(lower_root);
        let replace_intent =
            replaced
                .as_ref()
                .map(|(target_inode, entry)| DirectoryReplaceIntent {
                    version: 1,
                    move_intent: intent.clone(),
                    target_inode: *target_inode,
                    target_expected: entry.native_id,
                });
        if let Some(replace) = &replace_intent {
            if !new_parent
                .child_directory_is_empty(&new_key.1, replace.target_expected)
                .map_err(io::Error::other)?
            {
                return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
            }
            namespace.store_directory_replace(inode, replace)?;
        } else {
            namespace.store_directory_rename(inode, &intent)?;
        }
        let result = (|| -> io::Result<()> {
            let changed_files = if let Some(replace) = &replace_intent {
                old_parent
                    .exchange_child_directories(
                        &old_key.1,
                        directory.native_id,
                        new_parent,
                        &new_key.1,
                        replace.target_expected,
                    )
                    .map_err(io::Error::other)?;
                if !old_parent
                    .remove_empty_child_directory(&old_key.1, replace.target_expected)
                    .map_err(io::Error::other)?
                {
                    return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
                }
                namespace
                    .finish_directory_replace(
                        lower_root,
                        &self.captured_directories,
                        &self.file_defaults,
                        self.first_dynamic_inode,
                        inode,
                        replace,
                    )
                    .map_err(io::Error::other)?
            } else {
                old_parent
                    .move_child_directory_no_replace(
                        &old_key.1,
                        directory.native_id,
                        new_parent,
                        &new_key.1,
                    )
                    .map_err(io::Error::other)?;
                namespace
                    .finish_directory_rename(
                        lower_root,
                        &self.captured_directories,
                        &self.file_defaults,
                        self.first_dynamic_inode,
                        inode,
                        &intent,
                    )
                    .map_err(io::Error::other)?
            };
            for (file_inode, record) in &changed_files {
                let (_, location) = locations
                    .iter_mut()
                    .find(|(candidate, _)| candidate == file_inode)
                    .ok_or_else(|| io::Error::other("renamed guarded file is absent from view"))?;
                let current = location
                    .as_mut()
                    .ok_or_else(|| io::Error::other("renamed guarded file has no location"))?;
                current.relative_path =
                    PathBuf::from(OsString::from_vec(record.current.clone().unwrap()));
            }
            if let Some((target_inode, _)) = &replaced {
                self.removed_directories
                    .lock()
                    .unwrap()
                    .insert(*target_inode);
                self.dynamic_directories
                    .lock()
                    .unwrap()
                    .remove(target_inode);
            }
            self.dynamic_directories
                .lock()
                .unwrap()
                .extend(directory_updates);
            self.namespace
                .as_ref()
                .unwrap()
                .records
                .lock()
                .unwrap()
                .extend(changed_files);
            names.remove(old_key);
            names.insert(new_key.clone(), inode);
            Ok(())
        })();
        if result.is_err() {
            self.poisoned.store(true, Ordering::Release);
        }
        result
    }

    fn replace_existing_file(
        &self,
        source_inode: u64,
        target_inode: u64,
        source_key: &(u64, OsString),
        target_key: &(u64, OsString),
        names: &mut HashMap<(u64, OsString), u64>,
    ) -> io::Result<()> {
        let source_parent_inode = INodeNo(source_key.0);
        let target_parent_inode = INodeNo(target_key.0);
        let source_name = source_key.1.as_os_str();
        let target_name = target_key.1.as_os_str();
        let lower_root = self
            .lower_root
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let namespace = self
            .namespace
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::PermissionDenied))?;
        let source = self
            .file(source_inode)
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let target = self
            .file(target_inode)
            .ok_or_else(|| io::Error::from(io::ErrorKind::IsADirectory))?;
        let mut source_location = source.location.lock().unwrap();
        let mut target_location = target.location.lock().unwrap();
        let from = source_location
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        let to = target_location
            .as_ref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        if from.parent != source_parent_inode
            || to.parent != target_parent_inode
            || from.relative_path.file_name() != Some(source_name)
            || to.relative_path.file_name() != Some(target_name)
        {
            return Err(io::Error::other("guarded replacement location changed"));
        }
        let source_path = from.relative_path.clone();
        let target_path = to.relative_path.clone();
        let source_owned = namespace_parent(lower_root, &source_path).map_err(io::Error::other)?;
        let target_owned = namespace_parent(lower_root, &target_path).map_err(io::Error::other)?;
        let source_parent = source_owned.as_ref().unwrap_or(lower_root);
        let target_parent = target_owned.as_ref().unwrap_or(lower_root);
        let (id, intent) = namespace.begin_replace(source_inode, target_inode)?;
        let result = (|| -> io::Result<()> {
            if intent.source_before.current.as_deref() != Some(source_path.as_os_str().as_bytes())
                || intent.target_before.current.as_deref()
                    != Some(target_path.as_os_str().as_bytes())
                || source.source.metadata()?.ino() != intent.source_before.expected.inode
                || target.source.metadata()?.ino() != intent.target_before.expected.inode
            {
                return Err(io::Error::other("guarded replacement record changed"));
            }
            source_parent
                .exchange_child_files(
                    source_name,
                    intent.source_before.expected,
                    target_parent,
                    target_name,
                    intent.target_before.expected,
                )
                .map_err(io::Error::other)?;
            namespace.publish_replace(&intent)?;
            source_parent
                .remove_child_file_if_identity(source_name, intent.target_before.expected)
                .map_err(io::Error::other)?;
            namespace.retire_replace(&id, &intent)?;
            *source_location = Some(ProbeLocation {
                parent: target_parent_inode,
                relative_path: target_path,
            });
            *target_location = None;
            names.remove(source_key);
            names.insert(target_key.clone(), source_inode);
            Ok(())
        })();
        if result.is_err() {
            // Once the intent is durable, any error may have happened after
            // the exchange. Only replay can decide which inode owns each name.
            self.poisoned.store(true, Ordering::Release);
        }
        result
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
        let first_dynamic_inode = u64::try_from(manifest.entries.len())?
            .checked_add(2)
            .context("guarded view inode overflow")?;
        let mut captured_directories = HashMap::new();
        let mut defaults = HashMap::new();
        for (index, entry) in manifest.entries.iter().enumerate() {
            match entry {
                CapturedEntry::Directory { path, mode, .. } => {
                    let inode = u64::try_from(index)? + 2;
                    let expected = plan
                        .captured_entry_identity(path)
                        .context("guarded directory is absent from source plan")?;
                    ensure!(
                        captured_directories
                            .insert(
                                inode,
                                (path.as_bytes().to_vec(), expected, (mode & 0o7777) as u16)
                            )
                            .is_none(),
                        "duplicate captured guarded directory inode"
                    );
                }
                CapturedEntry::FileV2 {
                    path, native_id, ..
                } => {
                    let expected = plan
                        .captured_entry_identity(path)
                        .context("guarded file is absent from source plan")?;
                    ensure!(
                        *native_id == expected,
                        "guarded file identity differs from plan"
                    );
                    let _anchor = manifest.file_locator(path.clone())?.open()?;
                    defaults.insert(
                        u64::try_from(index)? + 2,
                        NamespaceRecord {
                            version: 1,
                            captured_path: path.clone(),
                            expected,
                            current: Some(path.as_bytes().to_vec()),
                            pending: None,
                        },
                    );
                }
                CapturedEntry::File { .. } => {
                    anyhow::bail!("guarded view needs native file identities")
                }
            }
        }
        let staging_area = manifest.area.open_guarded_staging_area()?;
        ensure!(
            staging_area.identity()?.filesystem_id == lower_root.identity()?.filesystem_id,
            "guarded staging area is on another filesystem"
        );
        namespace.reconcile_directory_replaces(
            &lower_root,
            &captured_directories,
            &defaults,
            first_dynamic_inode,
        )?;
        namespace.reconcile_directory_renames(
            &lower_root,
            &captured_directories,
            &defaults,
            first_dynamic_inode,
        )?;
        let directory_paths = namespace
            .load_directories(
                &lower_root,
                &captured_directories,
                first_dynamic_inode,
                view_uid,
                view_gid,
            )?
            .paths;
        namespace.reconcile_directory_creates(
            &lower_root,
            &staging_area,
            &directory_paths,
            first_dynamic_inode,
        )?;
        namespace.reconcile_directory_removes(
            &lower_root,
            &directory_paths,
            first_dynamic_inode,
            &captured_directories,
        )?;
        let GuardedDirectoryIndex {
            paths: directory_paths,
            captured: directories,
            dynamic: mut dynamic_directories,
            mut highest_inode,
        } = namespace.load_directories(
            &lower_root,
            &captured_directories,
            first_dynamic_inode,
            view_uid,
            view_gid,
        )?;
        namespace.reconcile_creates(&lower_root, &directory_paths, first_dynamic_inode)?;
        namespace.reconcile_replaces(
            &lower_root,
            &directory_paths,
            &defaults,
            first_dynamic_inode,
        )?;
        let mut files = Vec::new();
        for (index, entry) in manifest.entries.iter().enumerate() {
            let (path, mode) = match entry {
                CapturedEntry::Directory { path, mode, .. }
                | CapturedEntry::FileV2 { path, mode, .. } => (path, *mode),
                CapturedEntry::File { .. } => {
                    anyhow::bail!("guarded view needs native file identities")
                }
            };
            let inode = INodeNo(
                u64::try_from(index)?
                    .checked_add(2)
                    .context("view inode overflow")?,
            );
            let expected = plan
                .captured_entry_identity(path)
                .context("guarded manifest entry is not in its source plan")?;
            match entry {
                CapturedEntry::Directory { .. } => {}
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
                    let editable = {
                        let control = control
                            .lock()
                            .map_err(|_| io::Error::other("guarded control lock is poisoned"))?;
                        plan.file_has_editable_inode(&control, path)?
                    };
                    let visible_mode = if editable {
                        (source.metadata()?.permissions().mode() & 0o7777) as u16
                    } else {
                        (mode & 0o7777) as u16
                    };
                    let mut attr = probe_file_attr(&source, inode, visible_mode)?;
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
        }
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
        for directory in dynamic_directories.drain(..) {
            let inode = directory.attr.ino.0;
            ensure!(
                !view.files.contains_key(&inode) && !view.directories.contains_key(&inode),
                "guarded dynamic directory aliases another inode"
            );
            ensure!(
                view.names
                    .get_mut()
                    .unwrap()
                    .insert((directory.parent.0, directory.name.clone()), inode)
                    .is_none(),
                "guarded dynamic directory aliases another name"
            );
            ensure!(
                view.dynamic_directories
                    .get_mut()
                    .unwrap()
                    .insert(inode, directory)
                    .is_none(),
                "duplicate guarded dynamic directory inode"
            );
        }
        view.root_uid = view_uid;
        view.root_gid = view_gid;
        view.next_inode.store(
            highest_inode
                .checked_add(1)
                .context("guarded view inode overflow")?,
            Ordering::Relaxed,
        );
        view.namespace = Some(namespace);
        view.staging_area = Some(staging_area);
        view.captured_directories = captured_directories;
        view.file_defaults = defaults;
        view.first_dynamic_inode = first_dynamic_inode;
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
            dynamic_directories: Mutex::new(HashMap::new()),
            removed_directories: Mutex::new(std::collections::HashSet::new()),
            captured_directories: HashMap::new(),
            file_defaults: HashMap::new(),
            first_dynamic_inode: 2,
            names: Mutex::new(names),
            lower_root,
            staging_area: None,
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
        if let Some(directory) = self.directory(inode) {
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
        if inode != INodeNo::ROOT && self.directory(inode.0).is_none() {
            reply.error(Errno::ENOENT);
            return;
        }
        let names = self.names.lock().unwrap();
        let parent = self
            .directory(inode.0)
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
            let kind = if self.directory(*child_inode).is_some() {
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
            _ => {
                if let Some(directory) = self.directory(inode.0) {
                    reply.attr(&ENTRY_TTL, &directory.attr);
                    return;
                }
                match self.file(inode.0) {
                    Some(file) => match file.current_attr() {
                        Ok(attr) => reply.attr(&ENTRY_TTL, &attr),
                        Err(_) => reply.error(Errno::EIO),
                    },
                    None => reply.error(Errno::ENOENT),
                }
            }
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

    fn mkdir(
        &self,
        _request: &Request,
        parent: INodeNo,
        name: &OsStr,
        mode: u32,
        umask: u32,
        reply: ReplyEntry,
    ) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        let (Some(lower_root), Some(staging_area), Some(namespace)) =
            (&self.lower_root, &self.staging_area, &self.namespace)
        else {
            reply.error(Errno::EACCES);
            return;
        };
        let name_path = Path::new(name);
        if name.as_bytes().contains(&0)
            || !matches!(
                name_path.components().next(),
                Some(std::path::Component::Normal(_))
            )
            || name_path.components().count() != 1
            || (mode & libc::S_IFMT != 0 && mode & libc::S_IFMT != libc::S_IFDIR)
        {
            reply.error(Errno::EINVAL);
            return;
        }
        let mut names = self.names.lock().unwrap();
        let parent_path = if parent == INodeNo::ROOT {
            PathBuf::new()
        } else if let Some(directory) = self.directory(parent.0) {
            directory.relative_path
        } else {
            reply.error(Errno::ENOENT);
            return;
        };
        let key = (parent.0, name.to_os_string());
        if names.contains_key(&key) {
            reply.error(Errno::EEXIST);
            return;
        }
        let inode =
            match self
                .next_inode
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    value.checked_add(1)
                }) {
                Ok(inode) => inode,
                Err(_) => {
                    reply.error(Errno::EOVERFLOW);
                    return;
                }
            };
        let target = parent_path.join(name);
        let mut intent = DirectoryCreateIntent {
            version: 1,
            staging_name: format!(".guarded-mkdir-{}", Uuid::new_v4()),
            target: target.as_os_str().as_bytes().to_vec(),
            expected: None,
        };
        if let Err(error) = namespace.store_directory_create(inode, &intent) {
            reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO)));
            return;
        }
        let result = (|| -> io::Result<GuardedProbeDirectory> {
            let staged = staging_area
                .create_child_directory(&intent.staging_name)
                .map_err(io::Error::other)?;
            // Staging is daemon-owned, so never install setuid/setgid bits
            // requested through the view's remapped owner.
            staged
                .as_file()
                .set_permissions(fs::Permissions::from_mode((mode & !umask) & 0o777))?;
            staged.sync_all().map_err(io::Error::other)?;
            staging_area.sync_all().map_err(io::Error::other)?;
            let before = intent.clone();
            let expected = staged.identity().map_err(io::Error::other)?;
            intent.expected = Some(expected);
            namespace.advance_directory_create(inode, &before, &intent)?;
            let owned = if parent_path.as_os_str().is_empty() {
                None
            } else {
                Some(
                    lower_root
                        .open_descendant_directory(&parent_path)
                        .map_err(io::Error::other)?,
                )
            };
            let lower_parent = owned.as_ref().unwrap_or(lower_root);
            staging_area
                .move_child_directory_no_replace(&intent.staging_name, expected, lower_parent, name)
                .map_err(io::Error::other)?;
            namespace.finish_directory_create(inode, &intent)?;
            let actual_mode = (staged.as_file().metadata()?.permissions().mode() & 0o7777) as u16;
            let mut attr = probe_directory_attr(staged.as_file(), INodeNo(inode), actual_mode)?;
            attr.uid = self.root_uid;
            attr.gid = self.root_gid;
            Ok(GuardedProbeDirectory {
                attr,
                parent,
                name: name.to_os_string(),
                relative_path: target,
                native_id: expected,
            })
        })();
        match result {
            Ok(directory) => {
                let attr = directory.attr;
                self.dynamic_directories
                    .lock()
                    .unwrap()
                    .insert(inode, directory);
                names.insert(key, inode);
                reply.entry(&ENTRY_TTL, &attr, Generation(0));
            }
            Err(error) => {
                self.poisoned.store(true, Ordering::Release);
                reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO)));
            }
        }
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
        } else if let Some(directory) = self.directory(parent.0) {
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
        if (parent != INodeNo::ROOT && self.directory(parent.0).is_none())
            || (newparent != INodeNo::ROOT && self.directory(newparent.0).is_none())
        {
            reply.error(Errno::ENOENT);
            return;
        }
        if !flags.is_empty() && flags != RenameFlags::RENAME_NOREPLACE {
            reply.error(Errno::EINVAL);
            return;
        }
        let mut names = self.names.lock().unwrap();
        if (parent != INodeNo::ROOT && self.directory(parent.0).is_none())
            || (newparent != INodeNo::ROOT && self.directory(newparent.0).is_none())
        {
            reply.error(Errno::ENOENT);
            return;
        }
        let old_key = (parent.0, name.to_os_string());
        let new_key = (newparent.0, newname.to_os_string());
        let Some(&inode) = names.get(&old_key) else {
            reply.error(Errno::ENOENT);
            return;
        };
        if parent == newparent && name == newname {
            reply.ok();
            return;
        }
        if self.directory(inode).is_some() {
            let replaced = names.get(&new_key).and_then(|&target_inode| {
                self.directory(target_inode)
                    .map(|directory| (target_inode, directory))
            });
            if names.contains_key(&new_key) && flags == RenameFlags::RENAME_NOREPLACE {
                reply.error(Errno::EEXIST);
                return;
            }
            if names.contains_key(&new_key) && replaced.is_none() {
                reply.error(Errno::ENOTDIR);
                return;
            }
            let result = self.rename_directory(inode, &old_key, &new_key, replaced, &mut names);
            match result {
                Ok(()) => reply.ok(),
                Err(error) => {
                    reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO)))
                }
            }
            return;
        }
        let Some(file) = self.file(inode) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(lower_root) = &self.lower_root else {
            reply.error(Errno::EACCES);
            return;
        };
        if let Some(&target_inode) = names.get(&new_key) {
            if flags == RenameFlags::RENAME_NOREPLACE {
                reply.error(Errno::EEXIST);
                return;
            }
            let result =
                self.replace_existing_file(inode, target_inode, &old_key, &new_key, &mut names);
            match result {
                Ok(()) => reply.ok(),
                Err(error) => {
                    reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO)))
                }
            }
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
                .directory(newparent.0)
                .map(|directory| directory.relative_path)
                .unwrap_or_default();
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
                        .open_descendant_directory(&destination_relative_dir)
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
        if parent != INodeNo::ROOT && self.directory(parent.0).is_none() {
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

    fn rmdir(&self, _request: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEmpty) {
        if self.poisoned.load(Ordering::Acquire) {
            reply.error(Errno::EIO);
            return;
        }
        if parent != INodeNo::ROOT && self.directory(parent.0).is_none() {
            reply.error(Errno::ENOENT);
            return;
        }
        let mut names = self.names.lock().unwrap();
        let key = (parent.0, name.to_os_string());
        let Some(&inode) = names.get(&key) else {
            reply.error(Errno::ENOENT);
            return;
        };
        let Some(directory) = self.directory(inode) else {
            reply.error(if self.file(inode).is_some() {
                Errno::ENOTDIR
            } else {
                Errno::ENOENT
            });
            return;
        };
        let captured = self.directories.contains_key(&inode);
        if names.keys().any(|(child_parent, _)| *child_parent == inode) {
            reply.error(Errno::ENOTEMPTY);
            return;
        }
        let (Some(lower_root), Some(namespace)) = (&self.lower_root, &self.namespace) else {
            reply.error(Errno::EACCES);
            return;
        };
        let result = (|| -> io::Result<()> {
            let stored = namespace.directory_record_opt(inode)?;
            let record = match &stored {
                Some(record) => record.clone(),
                None if captured => DirectoryRecord {
                    version: 1,
                    expected: directory.native_id,
                    current: Some(directory.relative_path.as_os_str().as_bytes().to_vec()),
                },
                None => return Err(io::Error::from(io::ErrorKind::NotFound)),
            };
            if record.version != 1
                || record.expected != directory.native_id
                || record.current.as_deref() != Some(directory.relative_path.as_os_str().as_bytes())
            {
                return Err(io::Error::other("guarded directory record changed"));
            }
            let parent_path = directory
                .relative_path
                .parent()
                .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
            let owned = if parent_path.as_os_str().is_empty() {
                None
            } else {
                Some(
                    lower_root
                        .open_descendant_directory(parent_path)
                        .map_err(io::Error::other)?,
                )
            };
            let lower_parent = owned.as_ref().unwrap_or(lower_root);
            if lower_parent
                .entry_identity(name, true)
                .map_err(io::Error::other)?
                != Some(record.expected)
            {
                return Err(io::Error::other("guarded directory identity changed"));
            }
            if stored.is_none() {
                namespace.store_directory_if_absent(inode, &record)?;
            }
            let intent = DirectoryRemoveIntent {
                version: 1,
                target: directory.relative_path.as_os_str().as_bytes().to_vec(),
                expected: record.expected,
            };
            namespace.store_directory_remove(inode, &intent)?;
            if !lower_parent
                .remove_empty_child_directory(name, record.expected)
                .map_err(io::Error::other)?
            {
                return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
            }
            namespace.finish_directory_remove(inode, &intent)?;
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.removed_directories.lock().unwrap().insert(inode);
                self.dynamic_directories.lock().unwrap().remove(&inode);
                names.remove(&key);
                reply.ok();
            }
            Err(error) => {
                self.poisoned.store(true, Ordering::Release);
                reply.error(Errno::from_i32(error.raw_os_error().unwrap_or(libc::EIO)));
            }
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
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Arc, Mutex};

    use fuser::{Config, INodeNo, OpenAccMode, SessionACL};
    use mb_core::{KeyMaterial, Seed};

    use crate::{
        ControlStore, GuardedFileCapturePlan, GuardedRootCapturePlan, LinkFreezeCaptureIntent,
        LinkFreezeCapturePhase, PinnedDirectory, StableAnchorAreaLocator,
    };

    use super::{
        CREATE_KIND, CreateIntent, DIRECTORY_CREATE_KIND, DIRECTORY_KIND, DIRECTORY_REMOVE_KIND,
        DIRECTORY_RENAME_KIND, DIRECTORY_REPLACE_KIND, DirectoryCreateIntent, DirectoryRecord,
        DirectoryRemoveIntent, DirectoryRenameIntent, DirectoryReplaceIntent, FILE_INODE,
        GuardedNamespace, GuardedProbeFile, GuardedProbeView, NAMESPACE_KIND, NamespaceRecord,
        ProbeLocation, REPLACE_KIND, probe_file_attr,
    };

    #[test]
    fn populated_directory_replacement_replays_each_boundary() {
        for phase in 0..4 {
            let area = tempfile::tempdir().unwrap();
            let lower = area.path().join("lower");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(lower.join("source")).unwrap();
            fs::create_dir(lower.join("target")).unwrap();
            fs::write(lower.join("source/file"), b"captured bytes").unwrap();
            let root = PinnedDirectory::open(&lower).unwrap();
            let source_id = root
                .open_child_directory("source")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            let target_id = root
                .open_child_directory("target")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            let file_id = root
                .open_child_directory("source")
                .unwrap()
                .unwrap()
                .entry_identity("file", false)
                .unwrap()
                .unwrap();
            let captured = HashMap::from([
                (2, (b"source".to_vec(), source_id, 0o755)),
                (3, (b"target".to_vec(), target_id, 0o755)),
            ]);
            let defaults = HashMap::from([(
                4,
                NamespaceRecord {
                    version: 1,
                    captured_path: "source/file".to_owned(),
                    expected: file_id,
                    current: Some(b"source/file".to_vec()),
                    pending: None,
                },
            )]);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([108; 32]));
            let control_path = area.path().join("control.db");
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let anchor_id = uuid::Uuid::new_v4();
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let intent = DirectoryReplaceIntent {
                version: 1,
                move_intent: DirectoryRenameIntent {
                    version: 1,
                    source: b"source".to_vec(),
                    target: b"target".to_vec(),
                    expected: source_id,
                },
                target_inode: 3,
                target_expected: target_id,
            };
            journal.store_directory_replace(2, &intent).unwrap();
            if phase >= 1 {
                root.exchange_child_directories("source", source_id, &root, "target", target_id)
                    .unwrap();
            }
            if phase >= 2 {
                assert!(
                    root.remove_empty_child_directory("source", target_id)
                        .unwrap()
                );
            }
            if phase >= 3 {
                journal
                    .finish_directory_replace(&root, &captured, &defaults, 5, 2, &intent)
                    .unwrap();
            }
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
            journal
                .reconcile_directory_replaces(&root, &captured, &defaults, 5)
                .unwrap();
            let index = journal
                .load_directories(&root, &captured, 5, 65534, 65534)
                .unwrap();
            assert_eq!(index.paths[Path::new("target")], INodeNo(2));
            assert!(!index.paths.contains_key(Path::new("source")));
            assert_eq!(journal.directory_record(3).unwrap().current, None);
            assert_eq!(
                journal
                    .load_or_replay(4, "source/file", file_id, &root, &index.paths)
                    .unwrap()
                    .unwrap()
                    .relative_path,
                Path::new("target/file")
            );
            assert_eq!(
                fs::read(lower.join("target/file")).unwrap(),
                b"captured bytes"
            );
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_REPLACE_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn directory_replacement_replay_refuses_nonempty_or_foreign_target() {
        for foreign in [false, true] {
            let area = tempfile::tempdir().unwrap();
            let lower = area.path().join("lower");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(lower.join("source")).unwrap();
            fs::create_dir(lower.join("target")).unwrap();
            let root = PinnedDirectory::open(&lower).unwrap();
            let source_id = root
                .open_child_directory("source")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            let target_id = root
                .open_child_directory("target")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            let captured = HashMap::from([
                (2, (b"source".to_vec(), source_id, 0o755)),
                (3, (b"target".to_vec(), target_id, 0o755)),
            ]);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([109; 32]));
            let control = Arc::new(Mutex::new(
                ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control,
                anchor_id: uuid::Uuid::new_v4(),
                records: Mutex::new(HashMap::new()),
            };
            journal
                .store_directory_replace(
                    2,
                    &DirectoryReplaceIntent {
                        version: 1,
                        move_intent: DirectoryRenameIntent {
                            version: 1,
                            source: b"source".to_vec(),
                            target: b"target".to_vec(),
                            expected: source_id,
                        },
                        target_inode: 3,
                        target_expected: target_id,
                    },
                )
                .unwrap();
            if foreign {
                root.move_child_directory_no_replace("target", target_id, &root, "saved")
                    .unwrap();
                fs::create_dir(lower.join("target")).unwrap();
            } else {
                fs::write(lower.join("target/untracked"), b"cannot discard").unwrap();
            }
            let actual_target = root.entry_identity("target", true).unwrap().unwrap();
            assert!(
                journal
                    .reconcile_directory_replaces(&root, &captured, &HashMap::new(), 4)
                    .is_err()
            );
            assert_eq!(
                root.entry_identity("source", true).unwrap(),
                Some(source_id)
            );
            assert_eq!(
                root.entry_identity("target", true).unwrap(),
                Some(actual_target)
            );
            if !foreign {
                assert_eq!(
                    fs::read(lower.join("target/untracked")).unwrap(),
                    b"cannot discard"
                );
            }
        }
    }

    #[test]
    fn populated_directory_rename_replays_each_boundary() {
        for phase in 0..3 {
            let area = tempfile::tempdir().unwrap();
            let lower = area.path().join("lower");
            fs::create_dir(&lower).unwrap();
            fs::create_dir(lower.join("parent")).unwrap();
            fs::create_dir(lower.join("parent/sub")).unwrap();
            fs::write(lower.join("parent/file"), b"captured bytes").unwrap();
            fs::write(lower.join("parent/sub/new"), b"dynamic bytes").unwrap();
            let root = PinnedDirectory::open(&lower).unwrap();
            let parent_id = root
                .open_descendant_directory("parent")
                .unwrap()
                .identity()
                .unwrap();
            let sub_id = root
                .open_descendant_directory("parent/sub")
                .unwrap()
                .identity()
                .unwrap();
            let file_id = root
                .open_descendant_directory("parent")
                .unwrap()
                .entry_identity("file", false)
                .unwrap()
                .unwrap();
            let new_id = root
                .open_descendant_directory("parent/sub")
                .unwrap()
                .entry_identity("new", false)
                .unwrap()
                .unwrap();
            let captured = HashMap::from([(2, (b"parent".to_vec(), parent_id, 0o755))]);
            let defaults = HashMap::from([(
                3,
                NamespaceRecord {
                    version: 1,
                    captured_path: "parent/file".to_owned(),
                    expected: file_id,
                    current: Some(b"parent/file".to_vec()),
                    pending: None,
                },
            )]);
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([105; 32]));
            let control_path = area.path().join("control.db");
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let anchor_id = uuid::Uuid::new_v4();
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            journal
                .store_directory_if_absent(
                    4,
                    &DirectoryRecord {
                        version: 1,
                        expected: sub_id,
                        current: Some(b"parent/sub".to_vec()),
                    },
                )
                .unwrap();
            journal
                .store(
                    5,
                    &NamespaceRecord {
                        version: 1,
                        captured_path: String::new(),
                        expected: new_id,
                        current: Some(b"parent/sub/new".to_vec()),
                        pending: None,
                    },
                )
                .unwrap();
            let intent = DirectoryRenameIntent {
                version: 1,
                source: b"parent".to_vec(),
                target: b"relocated".to_vec(),
                expected: parent_id,
            };
            journal.store_directory_rename(2, &intent).unwrap();
            if phase >= 1 {
                root.move_child_directory_no_replace("parent", parent_id, &root, "relocated")
                    .unwrap();
            }
            if phase >= 2 {
                journal
                    .finish_directory_rename(&root, &captured, &defaults, 4, 2, &intent)
                    .unwrap();
            }
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
            journal
                .reconcile_directory_renames(&root, &captured, &defaults, 4)
                .unwrap();
            let index = journal
                .load_directories(&root, &captured, 4, 65534, 65534)
                .unwrap();
            assert_eq!(index.paths[Path::new("relocated")], INodeNo(2));
            assert_eq!(index.paths[Path::new("relocated/sub")], INodeNo(4));
            assert_eq!(
                journal
                    .load_or_replay(3, "parent/file", file_id, &root, &index.paths)
                    .unwrap()
                    .unwrap()
                    .relative_path,
                Path::new("relocated/file")
            );
            assert_eq!(
                journal
                    .load_or_replay(5, "", new_id, &root, &index.paths)
                    .unwrap()
                    .unwrap()
                    .relative_path,
                Path::new("relocated/sub/new")
            );
            assert_eq!(
                fs::read(lower.join("relocated/file")).unwrap(),
                b"captured bytes"
            );
            assert_eq!(
                fs::read(lower.join("relocated/sub/new")).unwrap(),
                b"dynamic bytes"
            );
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_RENAME_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn directory_rename_replay_refuses_foreign_target() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(lower.join("source")).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let expected = root
            .open_descendant_directory("source")
            .unwrap()
            .identity()
            .unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([106; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control: Arc::clone(&control),
            anchor_id: uuid::Uuid::new_v4(),
            records: Mutex::new(HashMap::new()),
        };
        let captured = HashMap::from([(2, (b"source".to_vec(), expected, 0o755))]);
        let intent = DirectoryRenameIntent {
            version: 1,
            source: b"source".to_vec(),
            target: b"target".to_vec(),
            expected,
        };
        journal.store_directory_rename(2, &intent).unwrap();
        fs::create_dir(lower.join("target")).unwrap();
        let foreign = root
            .open_descendant_directory("target")
            .unwrap()
            .identity()
            .unwrap();
        assert!(
            journal
                .reconcile_directory_renames(&root, &captured, &HashMap::new(), 3)
                .is_err()
        );
        assert_eq!(
            root.open_descendant_directory("source")
                .unwrap()
                .identity()
                .unwrap(),
            expected
        );
        assert_eq!(
            root.open_descendant_directory("target")
                .unwrap()
                .identity()
                .unwrap(),
            foreign
        );
        assert!(
            control
                .lock()
                .unwrap()
                .get_record(DIRECTORY_RENAME_KIND, &journal.record_id(2))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn directory_creation_replays_each_staging_and_publication_boundary() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let anchor_area = StableAnchorAreaLocator::prepare_for_root(&lower).unwrap();
        let staging = anchor_area.open_guarded_staging_area().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([97; 32]));
        let control_path = area.path().join("control.db");
        for phase in 0..5 {
            let anchor_id = uuid::Uuid::new_v4();
            let name = format!("created-{phase}");
            let stage_name = format!(".guarded-mkdir-{}", uuid::Uuid::new_v4());
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let mut intent = DirectoryCreateIntent {
                version: 1,
                staging_name: stage_name.clone(),
                target: name.as_bytes().to_vec(),
                expected: None,
            };
            journal.store_directory_create(2, &intent).unwrap();
            let mut staged = None;
            if phase >= 1 {
                let directory = staging.create_child_directory(&stage_name).unwrap();
                directory.sync_all().unwrap();
                staging.sync_all().unwrap();
                staged = Some(directory);
            }
            if phase >= 2 {
                let before = intent.clone();
                intent.expected = Some(staged.as_ref().unwrap().identity().unwrap());
                journal
                    .advance_directory_create(2, &before, &intent)
                    .unwrap();
            }
            if phase >= 3 {
                staging
                    .move_child_directory_no_replace(
                        &stage_name,
                        intent.expected.unwrap(),
                        &root,
                        &name,
                    )
                    .unwrap();
            }
            if phase >= 4 {
                journal.finish_directory_create(2, &intent).unwrap();
            }
            drop(staged);
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
            let directory_paths = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
            journal
                .reconcile_directory_creates(&root, &staging, &directory_paths, 2)
                .unwrap();
            let visible = journal
                .load_directories(&root, &HashMap::new(), 2, 65534, 65534)
                .unwrap()
                .dynamic;
            assert!(staging.open_child_directory(&stage_name).unwrap().is_none());
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_CREATE_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_none()
            );
            let published = phase >= 2;
            assert_eq!(lower.join(&name).is_dir(), published);
            assert_eq!(visible.len(), usize::from(published));
            assert_eq!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_some(),
                published
            );
            if published {
                let record: DirectoryRecord = mb_core::decode_canonical(
                    &control
                        .lock()
                        .unwrap()
                        .get_record(DIRECTORY_KIND, &journal.record_id(2))
                        .unwrap()
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(
                    record.expected,
                    root.open_child_directory(&name)
                        .unwrap()
                        .unwrap()
                        .identity()
                        .unwrap()
                );
            }
        }
    }

    #[test]
    fn directory_creation_replay_refuses_a_foreign_target() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let anchor_area = StableAnchorAreaLocator::prepare_for_root(&lower).unwrap();
        let staging = anchor_area.open_guarded_staging_area().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([98; 32]));
        let control_path = area.path().join("control.db");
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        for identity_recorded in [false, true] {
            let anchor_id = uuid::Uuid::new_v4();
            let name = format!("foreign-{identity_recorded}");
            let stage_name = format!(".guarded-mkdir-{}", uuid::Uuid::new_v4());
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let mut intent = DirectoryCreateIntent {
                version: 1,
                staging_name: stage_name.clone(),
                target: name.as_bytes().to_vec(),
                expected: None,
            };
            journal.store_directory_create(2, &intent).unwrap();
            let staged = staging.create_child_directory(&stage_name).unwrap();
            if identity_recorded {
                let before = intent.clone();
                intent.expected = Some(staged.identity().unwrap());
                journal
                    .advance_directory_create(2, &before, &intent)
                    .unwrap();
            }
            fs::create_dir(lower.join(&name)).unwrap();
            let foreign_id = root
                .open_child_directory(&name)
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            assert_ne!(Some(foreign_id), intent.expected);
            drop(staged);
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
            assert!(
                journal
                    .reconcile_directory_creates(&root, &staging, &directories, 2)
                    .is_err()
            );
            assert_eq!(
                root.open_child_directory(&name)
                    .unwrap()
                    .unwrap()
                    .identity()
                    .unwrap(),
                foreign_id
            );
            assert!(staging.open_child_directory(&stage_name).unwrap().is_some());
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_CREATE_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_some()
            );
        }
    }

    #[test]
    fn directory_removal_replays_before_and_after_lower_unlink() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([99; 32]));
        let control_path = area.path().join("control.db");
        for removed_before_replay in [false, true] {
            let anchor_id = uuid::Uuid::new_v4();
            let name = format!("remove-{removed_before_replay}");
            fs::create_dir(lower.join(&name)).unwrap();
            let expected = root
                .open_child_directory(&name)
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let record = DirectoryRecord {
                version: 1,
                expected,
                current: Some(name.as_bytes().to_vec()),
            };
            control
                .lock()
                .unwrap()
                .put_record(
                    DIRECTORY_KIND,
                    &journal.record_id(2),
                    &mb_core::canonical_bytes(&record).unwrap(),
                )
                .unwrap();
            let intent = DirectoryRemoveIntent {
                version: 1,
                target: name.as_bytes().to_vec(),
                expected,
            };
            journal.store_directory_remove(2, &intent).unwrap();
            if removed_before_replay {
                assert!(root.remove_empty_child_directory(&name, expected).unwrap());
            }
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
            let visible = journal
                .load_directories(&root, &HashMap::new(), 2, 65534, 65534)
                .unwrap();
            assert!(visible.dynamic.is_empty());
            journal
                .reconcile_directory_removes(&root, &visible.paths, 2, &HashMap::new())
                .unwrap();
            assert!(!lower.join(&name).exists());
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_REMOVE_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_none()
            );
            let after = journal.directory_record(2).unwrap();
            assert_eq!(after.expected, expected);
            assert!(after.current.is_none());
        }
    }

    #[test]
    fn captured_directory_removal_replays_across_control_reopen() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([101; 32]));
        let control_path = area.path().join("control.db");
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        for removed_before_replay in [false, true] {
            let name = format!("captured-{removed_before_replay}");
            fs::create_dir(lower.join(&name)).unwrap();
            let expected = root
                .open_child_directory(&name)
                .unwrap()
                .unwrap()
                .identity()
                .unwrap();
            let anchor_id = uuid::Uuid::new_v4();
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::new()),
            };
            let intent = DirectoryRemoveIntent {
                version: 1,
                target: name.as_bytes().to_vec(),
                expected,
            };
            journal
                .store_directory_if_absent(
                    2,
                    &DirectoryRecord {
                        version: 1,
                        expected,
                        current: Some(intent.target.clone()),
                    },
                )
                .unwrap();
            journal.store_directory_remove(2, &intent).unwrap();
            if removed_before_replay {
                assert!(root.remove_empty_child_directory(&name, expected).unwrap());
            }
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
            let captured = HashMap::from([(2, (name.as_bytes().to_vec(), expected, 0o755))]);
            journal
                .reconcile_directory_removes(&root, &directories, 3, &captured)
                .unwrap();
            assert!(!lower.join(&name).exists());
            assert!(journal.directory_record(2).unwrap().current.is_none());
            assert!(
                control
                    .lock()
                    .unwrap()
                    .get_record(DIRECTORY_REMOVE_KIND, &journal.record_id(2))
                    .unwrap()
                    .is_none()
            );
        }
    }

    #[test]
    fn rebuilt_directory_index_uses_current_captured_and_dynamic_paths() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(lower.join("original")).unwrap();
        fs::write(lower.join("original/file"), b"captured-bytes").unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let captured = root.open_child_directory("original").unwrap().unwrap();
        let captured_id = captured.identity().unwrap();
        let file_id = captured.entry_identity("file", false).unwrap().unwrap();
        let dynamic = root.create_child_directory("newparent").unwrap();
        let dynamic_id = dynamic.identity().unwrap();
        root.move_child_directory_no_replace("original", captured_id, &dynamic, "relocated")
            .unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([102; 32]));
        let control_path = area.path().join("control.db");
        let anchor_id = uuid::Uuid::new_v4();
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control: Arc::clone(&control),
            anchor_id,
            records: Mutex::new(HashMap::new()),
        };
        journal
            .store_directory_if_absent(
                2,
                &DirectoryRecord {
                    version: 1,
                    expected: captured_id,
                    current: Some(b"newparent/relocated".to_vec()),
                },
            )
            .unwrap();
        journal
            .store_directory_if_absent(
                4,
                &DirectoryRecord {
                    version: 1,
                    expected: dynamic_id,
                    current: Some(b"newparent".to_vec()),
                },
            )
            .unwrap();
        journal
            .store(
                3,
                &NamespaceRecord {
                    version: 1,
                    captured_path: "original/file".to_owned(),
                    expected: file_id,
                    current: Some(b"newparent/relocated/file".to_vec()),
                    pending: None,
                },
            )
            .unwrap();
        drop(journal);
        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control,
            anchor_id,
            records: Mutex::new(HashMap::new()),
        };
        let captured = HashMap::from([(2, (b"original".to_vec(), captured_id, 0o755))]);
        let index = journal
            .load_directories(&root, &captured, 4, 65534, 65534)
            .unwrap();
        assert_eq!(index.highest_inode, 4);
        assert_eq!(index.paths[Path::new("newparent")], INodeNo(4));
        assert_eq!(index.paths[Path::new("newparent/relocated")], INodeNo(2));
        assert_eq!(index.captured[0].parent, INodeNo(4));
        assert_eq!(index.dynamic[0].parent, INodeNo::ROOT);
        let file = journal
            .load_or_replay(3, "original/file", file_id, &root, &index.paths)
            .unwrap()
            .unwrap();
        assert_eq!(file.parent, INodeNo(2));
        assert_eq!(file.relative_path, Path::new("newparent/relocated/file"));
    }

    #[test]
    fn directory_removal_replay_refuses_a_foreign_target() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(lower.join("target")).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let expected = root
            .open_child_directory("target")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([100; 32]));
        let control_path = area.path().join("control.db");
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control: Arc::clone(&control),
            anchor_id: uuid::Uuid::new_v4(),
            records: Mutex::new(HashMap::new()),
        };
        let record = DirectoryRecord {
            version: 1,
            expected,
            current: Some(b"target".to_vec()),
        };
        control
            .lock()
            .unwrap()
            .put_record(
                DIRECTORY_KIND,
                &journal.record_id(2),
                &mb_core::canonical_bytes(&record).unwrap(),
            )
            .unwrap();
        journal
            .store_directory_remove(
                2,
                &DirectoryRemoveIntent {
                    version: 1,
                    target: b"target".to_vec(),
                    expected,
                },
            )
            .unwrap();
        root.move_child_directory_no_replace("target", expected, &root, "saved")
            .unwrap();
        fs::create_dir(lower.join("target")).unwrap();
        let foreign = root
            .open_child_directory("target")
            .unwrap()
            .unwrap()
            .identity()
            .unwrap();
        assert_ne!(foreign, expected);
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        assert!(
            journal
                .reconcile_directory_removes(&root, &directories, 2, &HashMap::new())
                .is_err()
        );
        assert_eq!(
            root.open_child_directory("target")
                .unwrap()
                .unwrap()
                .identity()
                .unwrap(),
            foreign
        );
        assert!(journal.directory_record(2).unwrap().current.is_some());
    }

    #[test]
    fn replacement_replays_each_exchange_publication_and_cleanup_boundary() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([93; 32]));
        let control_path = area.path().join("control.db");
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        for phase in 0..4 {
            let source_name = format!("temp-{phase}");
            let target_name = format!("target-{phase}");
            let anchor_name = format!("anchor-{phase}");
            fs::write(lower.join(&source_name), b"new-bytes").unwrap();
            fs::write(lower.join(&target_name), b"old-bytes").unwrap();
            fs::hard_link(lower.join(&target_name), area.path().join(&anchor_name)).unwrap();
            let source_id = root.entry_identity(&source_name, false).unwrap().unwrap();
            let target_id = root.entry_identity(&target_name, false).unwrap().unwrap();
            let source_record = NamespaceRecord {
                version: 1,
                captured_path: String::new(),
                expected: source_id,
                current: Some(source_name.as_bytes().to_vec()),
                pending: None,
            };
            let target_record = NamespaceRecord {
                version: 1,
                captured_path: target_name.clone(),
                expected: target_id,
                current: Some(target_name.as_bytes().to_vec()),
                pending: None,
            };
            let defaults = HashMap::from([(2, target_record.clone())]);
            let anchor_id = uuid::Uuid::new_v4();
            let control = Arc::new(Mutex::new(
                ControlStore::open(&control_path, &keys).unwrap(),
            ));
            let journal = GuardedNamespace {
                control: Arc::clone(&control),
                anchor_id,
                records: Mutex::new(HashMap::from([
                    (3, source_record.clone()),
                    (2, target_record.clone()),
                ])),
            };
            journal.store(3, &source_record).unwrap();
            let (intent_id, intent) = journal.begin_replace(3, 2).unwrap();
            if phase >= 1 {
                root.exchange_child_files(&source_name, source_id, &root, &target_name, target_id)
                    .unwrap();
            }
            if phase >= 2 {
                journal.publish_replace(&intent).unwrap();
            }
            if phase >= 3 {
                root.remove_child_file_if_identity(&source_name, target_id)
                    .unwrap();
            }
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
            journal
                .reconcile_replaces(&root, &directories, &defaults, 3)
                .unwrap();
            assert!(!lower.join(&source_name).exists());
            assert_eq!(fs::read(lower.join(&target_name)).unwrap(), b"new-bytes");
            assert_eq!(
                fs::read(area.path().join(&anchor_name)).unwrap(),
                b"old-bytes"
            );
            let control = control.lock().unwrap();
            assert!(
                control
                    .get_record(REPLACE_KIND, &intent_id)
                    .unwrap()
                    .is_none()
            );
            let source: NamespaceRecord = mb_core::decode_canonical(
                &control
                    .get_record(NAMESPACE_KIND, &journal.record_id(3))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            let target: NamespaceRecord = mb_core::decode_canonical(
                &control
                    .get_record(NAMESPACE_KIND, &journal.record_id(2))
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(source.current, Some(target_name.as_bytes().to_vec()));
            assert_eq!(target.current, None);
        }
    }

    #[test]
    fn replacement_replay_refuses_a_foreign_target() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        fs::write(lower.join("temp"), b"new").unwrap();
        fs::write(lower.join("target"), b"old").unwrap();
        fs::hard_link(lower.join("target"), area.path().join("anchor")).unwrap();
        let source_id = root.entry_identity("temp", false).unwrap().unwrap();
        let target_id = root.entry_identity("target", false).unwrap().unwrap();
        let source_record = NamespaceRecord {
            version: 1,
            captured_path: String::new(),
            expected: source_id,
            current: Some(b"temp".to_vec()),
            pending: None,
        };
        let target_record = NamespaceRecord {
            version: 1,
            captured_path: "target".into(),
            expected: target_id,
            current: Some(b"target".to_vec()),
            pending: None,
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([95; 32]));
        let control = Arc::new(Mutex::new(
            ControlStore::open(area.path().join("control.db"), &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control,
            anchor_id: uuid::Uuid::new_v4(),
            records: Mutex::new(HashMap::from([
                (3, source_record.clone()),
                (2, target_record.clone()),
            ])),
        };
        journal.store(3, &source_record).unwrap();
        journal.begin_replace(3, 2).unwrap();
        root.remove_child_file_if_identity("target", target_id)
            .unwrap();
        fs::write(lower.join("target"), b"foreign").unwrap();
        let defaults = HashMap::from([(2, target_record)]);
        let directories = HashMap::from([(PathBuf::new(), INodeNo::ROOT)]);
        assert!(
            journal
                .reconcile_replaces(&root, &directories, &defaults, 3)
                .is_err()
        );
        assert_eq!(fs::read(lower.join("temp")).unwrap(), b"new");
        assert_eq!(fs::read(lower.join("target")).unwrap(), b"foreign");
        assert_eq!(fs::read(area.path().join("anchor")).unwrap(), b"old");
    }

    #[test]
    fn cross_directory_replacement_replays_after_exchange() {
        let area = tempfile::tempdir().unwrap();
        let lower = area.path().join("lower");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(lower.join("nested")).unwrap();
        fs::write(lower.join("nested/temp"), b"new").unwrap();
        fs::write(lower.join("target"), b"old").unwrap();
        fs::hard_link(lower.join("target"), area.path().join("anchor")).unwrap();
        let root = PinnedDirectory::open(&lower).unwrap();
        let nested = root.open_child_directory("nested").unwrap().unwrap();
        let source_id = nested.entry_identity("temp", false).unwrap().unwrap();
        let target_id = root.entry_identity("target", false).unwrap().unwrap();
        let source_record = NamespaceRecord {
            version: 1,
            captured_path: String::new(),
            expected: source_id,
            current: Some(b"nested/temp".to_vec()),
            pending: None,
        };
        let target_record = NamespaceRecord {
            version: 1,
            captured_path: "target".into(),
            expected: target_id,
            current: Some(b"target".to_vec()),
            pending: None,
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([96; 32]));
        let control_path = area.path().join("control.db");
        let anchor_id = uuid::Uuid::new_v4();
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control: Arc::clone(&control),
            anchor_id,
            records: Mutex::new(HashMap::from([
                (4, source_record.clone()),
                (3, target_record.clone()),
            ])),
        };
        journal.store(4, &source_record).unwrap();
        journal.begin_replace(4, 3).unwrap();
        nested
            .exchange_child_files("temp", source_id, &root, "target", target_id)
            .unwrap();
        drop(journal);
        drop(control);
        let control = Arc::new(Mutex::new(
            ControlStore::open(&control_path, &keys).unwrap(),
        ));
        let journal = GuardedNamespace {
            control,
            anchor_id,
            records: Mutex::new(HashMap::new()),
        };
        let directories = HashMap::from([
            (PathBuf::new(), INodeNo::ROOT),
            (PathBuf::from("nested"), INodeNo(2)),
        ]);
        let defaults = HashMap::from([(3, target_record)]);
        journal
            .reconcile_replaces(&root, &directories, &defaults, 4)
            .unwrap();
        assert!(!lower.join("nested/temp").exists());
        assert_eq!(fs::read(lower.join("target")).unwrap(), b"new");
        assert_eq!(fs::read(area.path().join("anchor")).unwrap(), b"old");
    }

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
            let replace = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("delta"))
                .arg(mountpoint.join("moved"))
                .output()?;
            anyhow::ensure!(
                replace.status.success(),
                "guarded atomic replacement failed: {}",
                String::from_utf8_lossy(&replace.stderr)
            );
            anyhow::ensure!(!lower.join("delta").exists());
            anyhow::ensure!(fs::read(lower.join("moved"))?.starts_with(b"EDIT"));
            beta_bytes.clear();
            manifest
                .file_locator("beta".to_string())?
                .open()?
                .read_to_end(&mut beta_bytes)?;
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
        assert!(!names.contains_key(&(INodeNo::ROOT.0, "delta".into())));
        assert!(!names.contains_key(&(INodeNo::ROOT.0, "alpha".into())));
        drop(names);
        let session = fuser::spawn_mount(rebuilt, &mountpoint, &config).unwrap();
        let replayed = (|| -> anyhow::Result<()> {
            anyhow::ensure!(!mountpoint.join("alpha").exists());
            anyhow::ensure!(!mountpoint.join("beta").exists());
            anyhow::ensure!(!mountpoint.join("delta").exists());
            anyhow::ensure!(fs::read(mountpoint.join("moved"))?.starts_with(b"EDIT"));
            let edit_created = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_WRONLY); os.write(fd,b'NEXT'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("moved"))
                .output()?;
            anyhow::ensure!(edit_created.status.success());
            anyhow::ensure!(fs::read(lower.join("moved"))?.starts_with(b"NEXT"));
            let unlink = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.unlink(sys.argv[1])")
                .arg(mountpoint.join("moved"))
                .output()?;
            anyhow::ensure!(unlink.status.success());
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
    fn atomic_replace_of_frozen_file_preserves_anchor_across_remount() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-view-replace-")
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
        let old_bytes = b"old\r\nbytes\0";
        let new_bytes = b"new\nbytes\0";
        fs::write(lower.join("sample"), old_bytes).unwrap();
        fs::set_permissions(lower.join("sample"), fs::Permissions::from_mode(0o666)).unwrap();
        let old_inode = fs::metadata(lower.join("sample")).unwrap().ino();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([94; 32]));
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
            let replacement = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_RDWR,0o666); os.write(fd,b'new\\nbytes\\0'); os.fsync(fd); os.close(fd); os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("temporary"))
                .arg(mountpoint.join("sample"))
                .output()?;
            anyhow::ensure!(
                replacement.status.success(),
                "frozen replacement failed: {}",
                String::from_utf8_lossy(&replacement.stderr)
            );
            anyhow::ensure!(!lower.join("temporary").exists());
            anyhow::ensure!(fs::read(lower.join("sample"))? == new_bytes);
            anyhow::ensure!(fs::metadata(lower.join("sample"))?.ino() != old_inode);
            let mut anchor = manifest.file_locator("sample".to_string())?.open()?;
            anyhow::ensure!(anchor.metadata()?.ino() == old_inode);
            let mut bytes = Vec::new();
            anchor.read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes == old_bytes);
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
            anyhow::ensure!(!mountpoint.join("temporary").exists());
            anyhow::ensure!(fs::read(mountpoint.join("sample"))? == new_bytes);
            let mut anchor = manifest.file_locator("sample".to_string())?.open()?;
            let mut bytes = Vec::new();
            anchor.read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes == old_bytes);
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        replayed.unwrap();
        unmounted.unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN, FUSE passthrough, and fanotify permission events"]
    fn populated_guarded_directory_rename_survives_remount() {
        let area = match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-guarded-view-dir-rename-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        };
        fs::set_permissions(area.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let lower = area.path().join("lower");
        let mountpoint = area.path().join("view");
        let control_dir = area.path().join("control");
        fs::create_dir(&lower).unwrap();
        fs::create_dir(lower.join("source")).unwrap();
        fs::create_dir(&mountpoint).unwrap();
        fs::create_dir(&control_dir).unwrap();
        fs::set_permissions(&lower, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(lower.join("source"), fs::Permissions::from_mode(0o755)).unwrap();
        let original = b"directory\r\nanchor\0";
        fs::write(lower.join("source/leaf"), original).unwrap();
        fs::set_permissions(lower.join("source/leaf"), fs::Permissions::from_mode(0o666)).unwrap();
        let source_inode = fs::metadata(lower.join("source")).unwrap().ino();
        let leaf_inode = fs::metadata(lower.join("source/leaf")).unwrap().ino();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([107; 32]));
        let control = ControlStore::open(control_dir.join("control.db"), &keys).unwrap();
        let plan = GuardedRootCapturePlan::plan(&lower).unwrap();
        let manifest = plan.capture(&control).unwrap();
        let control = Arc::new(Mutex::new(control));
        let mut config = Config::default();
        config.acl = SessionACL::All;
        let view =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let session = fuser::spawn_mount(view, &mountpoint, &config).unwrap();
        let result = (|| -> anyhow::Result<()> {
            let operation = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; root=sys.argv[1]; os.mkdir(root+'/destination'); os.mkdir(root+'/source/created'); fd=os.open(root+'/source/created/new',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600); os.write(fd,b'dynamic'); os.close(fd); os.rename(root+'/source',root+'/destination/moved'); fd=os.open(root+'/destination/moved/leaf',os.O_WRONLY); os.write(fd,b'EDIT'); os.fsync(fd); os.close(fd)")
                .arg(&mountpoint)
                .output()?;
            anyhow::ensure!(
                operation.status.success(),
                "directory rename failed: {}",
                String::from_utf8_lossy(&operation.stderr)
            );
            anyhow::ensure!(!lower.join("source").exists());
            anyhow::ensure!(fs::metadata(lower.join("destination/moved"))?.ino() == source_inode);
            anyhow::ensure!(
                fs::metadata(lower.join("destination/moved/leaf"))?.ino() == leaf_inode
            );
            anyhow::ensure!(fs::read(lower.join("destination/moved/leaf"))?.starts_with(b"EDIT"));
            anyhow::ensure!(
                fs::read(mountpoint.join("destination/moved/created/new"))? == b"dynamic"
            );
            let mut anchor = manifest.file_locator("source/leaf".to_string())?.open()?;
            let mut bytes = Vec::new();
            anchor.read_to_end(&mut bytes)?;
            anyhow::ensure!(bytes == original && anchor.metadata()?.ino() != leaf_inode);
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
            anyhow::ensure!(!mountpoint.join("source").exists());
            anyhow::ensure!(
                fs::read(mountpoint.join("destination/moved/leaf"))?.starts_with(b"EDIT")
            );
            anyhow::ensure!(
                fs::read(mountpoint.join("destination/moved/created/new"))? == b"dynamic"
            );
            let rename_again = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2]); os.rename(sys.argv[3],sys.argv[4])")
                .arg(mountpoint.join("destination/moved"))
                .arg(mountpoint.join("final"))
                .arg(mountpoint.join("final/created"))
                .arg(mountpoint.join("dynamic-moved"))
                .output()?;
            anyhow::ensure!(
                rename_again.status.success(),
                "second directory rename failed: {}",
                String::from_utf8_lossy(&rename_again.stderr)
            );
            anyhow::ensure!(fs::read(mountpoint.join("dynamic-moved/new"))? == b"dynamic");
            let nonempty = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import errno,os,sys\nroot=sys.argv[1]\nos.mkdir(root+'/nonempty')\nfd=os.open(root+'/nonempty/file',os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)\nos.close(fd)\ntry:\n os.rename(root+'/final',root+'/nonempty')\nexcept OSError as error:\n assert error.errno in (errno.ENOTEMPTY,errno.EEXIST)\nelse:\n raise AssertionError('replaced nonempty directory')")
                .arg(&mountpoint)
                .output()?;
            anyhow::ensure!(
                nonempty.status.success(),
                "nonempty directory replacement was not refused: {}",
                String::from_utf8_lossy(&nonempty.stderr)
            );
            anyhow::ensure!(fs::read(mountpoint.join("final/leaf"))?.starts_with(b"EDIT"));
            let replace = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.mkdir(sys.argv[2]); os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("final"))
                .arg(mountpoint.join("occupied"))
                .output()?;
            anyhow::ensure!(
                replace.status.success(),
                "empty directory replacement failed: {}",
                String::from_utf8_lossy(&replace.stderr)
            );
            anyhow::ensure!(fs::read(mountpoint.join("occupied/leaf"))?.starts_with(b"EDIT"));
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        replayed.unwrap();
        unmounted.unwrap();
        let rebuilt =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let session = fuser::spawn_mount(rebuilt, &mountpoint, &config).unwrap();
        assert!(
            fs::read(mountpoint.join("occupied/leaf"))
                .unwrap()
                .starts_with(b"EDIT")
        );
        assert_eq!(
            fs::read(mountpoint.join("dynamic-moved/new")).unwrap(),
            b"dynamic"
        );
        session.umount_and_join().unwrap();
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
            anyhow::ensure!(
                fs::metadata(mountpoint.join("nested/leaf"))?
                    .permissions()
                    .mode()
                    & 0o7777
                    == 0o666
            );
            anyhow::ensure!(fs::metadata(nested.join("leaf"))?.permissions().mode() & 0o222 == 0);
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
            let cyclic_directory_rename = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("nested"))
                .arg(mountpoint.join("nested/inside"))
                .output()?;
            anyhow::ensure!(!cyclic_directory_rename.status.success());
            anyhow::ensure!(fs::read(mountpoint.join("nested/leaf"))? == leaf_bytes);
            let no_replace = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import ctypes,os,sys; c=ctypes.CDLL(None,use_errno=True); c.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]; r=c.renameat2(-100,os.fsencode(sys.argv[1]),-100,os.fsencode(sys.argv[2]),1); sys.exit(0 if r==-1 and ctypes.get_errno()==17 else 1)")
                .arg(mountpoint.join("nested/leaf"))
                .arg(mountpoint.join("top"))
                .output()?;
            anyhow::ensure!(no_replace.status.success());
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
            let chmod = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.chmod(sys.argv[1],0o640)")
                .arg(mountpoint.join("nested/moved"))
                .output()?;
            anyhow::ensure!(chmod.status.success());
            anyhow::ensure!(
                fs::metadata(nested.join("moved"))?.permissions().mode() & 0o7777 == 0o640
            );
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
            let replace_top = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rename(sys.argv[1],sys.argv[2])")
                .arg(mountpoint.join("nested/new"))
                .arg(mountpoint.join("top"))
                .output()?;
            anyhow::ensure!(
                replace_top.status.success(),
                "cross-directory guarded replacement failed: {}",
                String::from_utf8_lossy(&replace_top.stderr)
            );
            anyhow::ensure!(!nested.join("new").exists());
            anyhow::ensure!(fs::read(lower.join("top"))? == b"new-nested");
            let mut original_top = manifest.file_locator("top".to_string())?.open()?;
            let mut original_bytes = Vec::new();
            original_top.read_to_end(&mut original_bytes)?;
            anyhow::ensure!(original_bytes == top_bytes);
            let mkdir = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.mkdir(sys.argv[1],0o755); os.mkdir(sys.argv[2],0o700); fd=os.open(sys.argv[3],os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600); os.write(fd,b'dynamic-tree'); os.fsync(fd); os.close(fd)")
                .arg(mountpoint.join("nested/newdir"))
                .arg(mountpoint.join("nested/newdir/child"))
                .arg(mountpoint.join("nested/newdir/child/file"))
                .output()?;
            anyhow::ensure!(
                mkdir.status.success(),
                "guarded dynamic directory creation failed: {}",
                String::from_utf8_lossy(&mkdir.stderr)
            );
            anyhow::ensure!(fs::read(nested.join("newdir/child/file"))? == b"dynamic-tree");
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
            anyhow::ensure!(
                fs::metadata(mountpoint.join("nested/moved"))?
                    .permissions()
                    .mode()
                    & 0o7777
                    == 0o640
            );
            anyhow::ensure!(!mountpoint.join("nested/new").exists());
            anyhow::ensure!(fs::read(mountpoint.join("top"))? == b"new-nested");
            anyhow::ensure!(
                fs::read(mountpoint.join("nested/newdir/child/file"))? == b"dynamic-tree"
            );
            let nonempty = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rmdir(sys.argv[1])")
                .arg(mountpoint.join("nested/newdir/child"))
                .output()?;
            anyhow::ensure!(!nonempty.status.success());
            anyhow::ensure!(
                fs::read(mountpoint.join("nested/newdir/child/file"))? == b"dynamic-tree"
            );
            let remove = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.unlink(sys.argv[1]); os.rmdir(sys.argv[2]); os.rmdir(sys.argv[3])")
                .arg(mountpoint.join("nested/newdir/child/file"))
                .arg(mountpoint.join("nested/newdir/child"))
                .arg(mountpoint.join("nested/newdir"))
                .output()?;
            anyhow::ensure!(
                remove.status.success(),
                "guarded directory removal failed: {}",
                String::from_utf8_lossy(&remove.stderr)
            );
            anyhow::ensure!(!nested.join("newdir").exists());
            Ok(())
        })();
        let unmounted = session.umount_and_join();
        replayed.unwrap();
        unmounted.unwrap();
        let rebuilt =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let session = fuser::spawn_mount(rebuilt, &mountpoint, &config).unwrap();
        let remove_captured = (|| -> anyhow::Result<()> {
            anyhow::ensure!(!mountpoint.join("nested/newdir").exists());
            let nonempty = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.rmdir(sys.argv[1])")
                .arg(mountpoint.join("nested"))
                .output()?;
            anyhow::ensure!(!nonempty.status.success());
            let remove = Command::new("python3")
                .uid(65534)
                .gid(65534)
                .arg("-c")
                .arg("import os,sys; os.unlink(sys.argv[1]); os.rmdir(sys.argv[2])")
                .arg(mountpoint.join("nested/moved"))
                .arg(mountpoint.join("nested"))
                .output()?;
            anyhow::ensure!(
                remove.status.success(),
                "captured directory removal failed: {}",
                String::from_utf8_lossy(&remove.stderr)
            );
            anyhow::ensure!(!nested.exists());
            Ok(())
        })();
        session.umount_and_join().unwrap();
        remove_captured.unwrap();
        let rebuilt =
            GuardedProbeView::from_guarded_capture(&manifest, Arc::clone(&control), 65534, 65534)
                .unwrap();
        let session = fuser::spawn_mount(rebuilt, &mountpoint, &config).unwrap();
        assert!(!mountpoint.join("nested").exists());
        assert_eq!(fs::read(mountpoint.join("top")).unwrap(), b"new-nested");
        session.umount_and_join().unwrap();
    }
}
