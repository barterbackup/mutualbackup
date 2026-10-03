//! Short-lived Linux write exclusion for the guarded link-freeze backend.
//!
//! A read lease is acquired before changing inode permissions. Linux refuses
//! it while another writable file description (including one held by a shared
//! writable mapping) exists. Fanotify permission events deny new opens and
//! pathname truncation so they cannot break that lease during the transition.
//! This guard is not the durable backend: the caller still has to record and
//! recover the permission and anchor transition.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::anchor::{AnchorError, FileExtent, NativeFileId, PinnedDirectory, file_data_extents};
use crate::database::ControlStore;

#[path = "link_freeze_capture.rs"]
mod capture;
pub use capture::{LinkFreezeCaptureIntent, LinkFreezeCapturePhase};

// Linux UAPI asm-generic/fcntl.h. The libc crate does not expose F_SETSIG.
const F_SETSIG_LINUX: libc::c_int = 10;
// Linux UAPI linux/fanotify.h. Permission events require CAP_SYS_ADMIN.
const FAN_CLOEXEC: libc::c_uint = 0x0000_0001;
const FAN_NONBLOCK: libc::c_uint = 0x0000_0002;
const FAN_CLASS_PRE_CONTENT: libc::c_uint = 0x0000_0008;
const FAN_MARK_ADD: libc::c_uint = 0x0000_0001;
const FAN_OPEN_PERM: u64 = 0x0001_0000;
const FAN_PRE_ACCESS: u64 = 0x0010_0000;
const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
const FAN_DENY: u32 = 0x0000_0002;
const FANOTIFY_METADATA_VERSION: u8 = 3;
const MAX_ACCESS_ACL_BYTES: usize = 64 * 1024;
const ACCESS_ACL_NAME: &std::ffi::CStr = c"system.posix_acl_access";
const EDIT_INTENT_KIND: &str = "link-freeze-edit-v1";

#[cfg(test)]
type SparseCopyWriteHook = Box<dyn FnOnce() -> io::Result<()>>;

#[cfg(test)]
thread_local! {
    static AFTER_SPARSE_COPY_START: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        std::cell::RefCell::new(None);
    static AFTER_SPARSE_COPY_WRITE: std::cell::RefCell<Option<SparseCopyWriteHook>> =
        std::cell::RefCell::new(None);
}

fn run_after_sparse_copy_start_hook() {
    #[cfg(test)]
    AFTER_SPARSE_COPY_START.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

#[cfg(test)]
fn run_after_sparse_copy_write_hook() -> io::Result<()> {
    AFTER_SPARSE_COPY_WRITE.with(|slot| match slot.borrow_mut().take() {
        Some(hook) => hook(),
        None => Ok(()),
    })
}

/// Exact original access metadata to persist before freezing a shared inode.
/// An unsupported ACL facility is distinct from a supported filesystem with
/// no access ACL, so a later backend does not silently invent ACL semantics.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FileAccessSnapshot {
    pub format_version: u16,
    pub mode: u32,
    pub access_acl: AccessAclSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum AccessAclSnapshot {
    Unsupported,
    Absent,
    Present(Vec<u8>),
}

/// Verified private inode produced from a frozen hard-link source. Publication
/// and recovery of the copy remain the owning backend's responsibility.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndependentSparseCopy {
    pub logical_len: u64,
    pub content_hash: [u8; 32],
    pub data_extents: Vec<FileExtent>,
}

impl FileAccessSnapshot {
    /// Capture the mode and raw POSIX access ACL through a pinned descriptor.
    /// The caller must durably record this value before changing permissions.
    pub fn capture(file: &File) -> io::Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let before = file.metadata()?;
        if !before.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "access snapshot requires a regular file",
            ));
        }
        let access_acl = read_access_acl(file)?;
        let after = file.metadata()?;
        if (
            before.dev(),
            before.ino(),
            before.mode(),
            before.ctime(),
            before.ctime_nsec(),
        ) != (
            after.dev(),
            after.ino(),
            after.mode(),
            after.ctime(),
            after.ctime_nsec(),
        ) {
            return Err(io::Error::other(
                "file metadata changed during access snapshot",
            ));
        }
        Ok(Self {
            format_version: 1,
            mode: before.mode() & 0o7777,
            access_acl,
        })
    }

    /// Check both mode and ACL after recovery without changing the file.
    pub fn matches(&self, file: &File) -> io::Result<bool> {
        if self.format_version != 1 {
            return Ok(false);
        }
        Ok(*self == Self::capture(file)?)
    }

    /// Recovery can retire an `UNLOCK_PENDING` intent if the detached anchor
    /// still matches its durable copy proof and the working inode already has
    /// its original access metadata. The caller must separately match both
    /// inodes to the identities stored in that intent. The source may already
    /// have been edited, so its current bytes must not be compared to the
    /// immutable anchor here.
    pub fn is_restored_after_detach(
        &self,
        source: &File,
        anchor: &File,
        copy: &IndependentSparseCopy,
    ) -> Result<bool, AnchorError> {
        verify_independent_anchor(source, anchor, copy)?;
        Ok(self.matches(source)?)
    }

    /// Restore exact access metadata only after a verified private anchor has
    /// replaced the last shared link. A durable `UNLOCK_PENDING` intent must
    /// already exist so a crash during this multi-step restore can be retried.
    pub fn restore_after_detach(
        &self,
        source: &File,
        anchor: &File,
        copy: &IndependentSparseCopy,
    ) -> Result<(), AnchorError> {
        self.restore_after_detach_inner(source, anchor, copy, true)
    }

    /// A durable `UNLOCK_PENDING` replay may find that the user edited after
    /// the first restore changed the mode but before the journal advanced.
    /// The immutable anchor proof and pinned source identity remain mandatory.
    fn restore_after_detach_replaying(
        &self,
        source: &File,
        anchor: &File,
        copy: &IndependentSparseCopy,
    ) -> Result<(), AnchorError> {
        self.restore_after_detach_inner(source, anchor, copy, false)
    }

    fn restore_after_detach_inner(
        &self,
        source: &File,
        anchor: &File,
        copy: &IndependentSparseCopy,
        require_unchanged_source: bool,
    ) -> Result<(), AnchorError> {
        verify_independent_anchor(source, anchor, copy)?;
        let source_metadata = source.metadata()?;
        if require_unchanged_source
            && (source_metadata.len() != copy.logical_len
                || hash_exact(source, copy.logical_len)? != copy.content_hash)
        {
            return Err(io::Error::other("private anchor is not independent and verified").into());
        }
        anchor.sync_all()?;
        self.restore_access_metadata(source)
    }

    /// Undo an incomplete freeze only after the owned anchor link is gone and
    /// the source inode has no other aliases. The capture intent must still
    /// identify this pinned source inode before calling this method.
    fn restore_unshared_after_abandon(&self, source: &File) -> Result<(), AnchorError> {
        let metadata = source.metadata()?;
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(io::Error::other("cannot unfreeze a still-shared inode").into());
        }
        self.restore_access_metadata(source)
    }

    fn restore_access_metadata(&self, source: &File) -> Result<(), AnchorError> {
        if self.format_version != 1
            || self.mode & !0o7777 != 0
            || matches!(&self.access_acl, AccessAclSnapshot::Present(value) if value.is_empty() || value.len() > MAX_ACCESS_ACL_BYTES)
        {
            return Err(
                io::Error::new(io::ErrorKind::InvalidInput, "invalid access snapshot").into(),
            );
        }
        if self.matches(source)? {
            return Ok(());
        }
        let source_metadata = source.metadata()?;
        // The lease must already be gone. Add owner write temporarily so the
        // pinned inode can be reopened for fsetxattr; fsetxattr on O_RDONLY
        // descriptors fails even for the file owner. A detached anchor or an
        // abandoned capture means no immutable object shares this inode.
        source.set_permissions(std::fs::Permissions::from_mode(self.mode | 0o200))?;
        let pinned_path = format!("/proc/self/fd/{}", source.as_raw_fd());
        let writable = OpenOptions::new().write(true).open(pinned_path)?;
        let reopened = writable.metadata()?;
        if reopened.dev() != source_metadata.dev() || reopened.ino() != source_metadata.ino() {
            return Err(io::Error::other("source inode changed during access restore").into());
        }
        match &self.access_acl {
            AccessAclSnapshot::Unsupported => {}
            AccessAclSnapshot::Absent => {
                // SAFETY: the pinned writable descriptor and constant xattr
                // name are valid; ENODATA means the desired state is present.
                if unsafe { libc::fremovexattr(writable.as_raw_fd(), ACCESS_ACL_NAME.as_ptr()) } < 0
                {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(libc::ENODATA) {
                        return Err(error.into());
                    }
                }
            }
            AccessAclSnapshot::Present(value) => {
                // SAFETY: value remains allocated for the call and the kernel
                // validates the POSIX ACL encoding before installing it.
                if unsafe {
                    libc::fsetxattr(
                        writable.as_raw_fd(),
                        ACCESS_ACL_NAME.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error().into());
                }
            }
        }
        source.set_permissions(std::fs::Permissions::from_mode(self.mode))?;
        source.sync_all()?;
        if !self.matches(source)? {
            return Err(io::Error::other("original mode or ACL was not restored exactly").into());
        }
        Ok(())
    }
}

fn verify_independent_anchor(
    source: &File,
    anchor: &File,
    copy: &IndependentSparseCopy,
) -> Result<(), AnchorError> {
    let source_metadata = source.metadata()?;
    let anchor_metadata = anchor.metadata()?;
    if !source_metadata.is_file()
        || !anchor_metadata.is_file()
        || source_metadata.dev() != anchor_metadata.dev()
        || source_metadata.ino() == anchor_metadata.ino()
        || source_metadata.nlink() != 1
        || anchor_metadata.nlink() != 1
        || FileAccessSnapshot::capture(anchor)?.mode & 0o222 != 0
        || anchor_metadata.len() != copy.logical_len
        || hash_exact(anchor, copy.logical_len)? != copy.content_hash
        || file_data_extents(anchor, copy.logical_len)? != copy.data_extents
    {
        return Err(io::Error::other("private anchor is not independent and verified").into());
    }
    Ok(())
}

/// The durable ordering for detaching a frozen shared anchor before an edit.
/// A capture journal must already own the `SharedFrozen` state; this edit
/// journal never makes an unrecorded writable inode immutable by itself.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LinkFreezeEditPhase {
    SharedFrozen,
    CopyStaging,
    PrivateCopyReady,
    UnlockPending,
    Editable,
}

/// The expected immutable content and original access metadata supplied by
/// the durable frozen-anchor capture record when an edit begins.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FrozenAnchorProof {
    pub original_access: FileAccessSnapshot,
    pub content: IndependentSparseCopy,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LinkFreezeEditIntent {
    format_version: u16,
    anchor_id: Uuid,
    source_id: NativeFileId,
    staging_name: String,
    original_access: FileAccessSnapshot,
    frozen_content: IndependentSparseCopy,
    phase: LinkFreezeEditPhase,
    copy: Option<IndependentSparseCopy>,
    private_inode: Option<u64>,
}

impl LinkFreezeEditIntent {
    /// Persist the intent before creating a private staging copy. The caller
    /// must have a separately durable capture record for this frozen anchor,
    /// and must identify both paths by pinned directories on recovery.
    pub(crate) fn begin(
        control: &ControlStore,
        anchor_id: Uuid,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
        proof: FrozenAnchorProof,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!anchor_id.is_nil(), "nil frozen anchor ID");
        anyhow::ensure!(
            proof.original_access.format_version == 1,
            "unknown access snapshot"
        );
        let source_name = source_name.as_ref();
        let anchor_name = anchor_name.as_ref();
        anyhow::ensure!(
            source_parent.identity()? != anchor_parent.identity()? || source_name != anchor_name,
            "the editable source cannot be its own anchor"
        );
        let source = source_parent
            .open_child_file(source_name)?
            .ok_or_else(|| anyhow::anyhow!("frozen source name disappeared"))?;
        let shared_anchor = anchor_parent
            .open_child_file(anchor_name)?
            .ok_or_else(|| anyhow::anyhow!("shared anchor name disappeared"))?;
        let source_id = source_parent
            .entry_identity(source_name, false)?
            .ok_or_else(|| anyhow::anyhow!("frozen source name disappeared"))?;
        let anchor_entry = anchor_parent
            .entry_identity(anchor_name, false)?
            .ok_or_else(|| anyhow::anyhow!("shared anchor name disappeared"))?;
        let staging_name = format!(".link-edit-{anchor_id}");
        anyhow::ensure!(
            anchor_parent
                .entry_identity(&staging_name, false)?
                .is_none(),
            "an old private staging name already exists"
        );
        let source_meta = source.metadata()?;
        let anchor_meta = shared_anchor.metadata()?;
        anyhow::ensure!(
            source_meta.is_file()
                && anchor_meta.is_file()
                && source_id == anchor_entry
                && source_id.inode == source_meta.ino()
                && source_meta.dev() == anchor_meta.dev()
                && source_meta.ino() == anchor_meta.ino()
                && source_meta.nlink() == 2
                && source_meta.len() == proof.content.logical_len
                && hash_exact(&source, proof.content.logical_len)? == proof.content.content_hash
                && file_data_extents(&source, proof.content.logical_len)?
                    == proof.content.data_extents
                && FileAccessSnapshot::capture(&source)?.mode & 0o222 == 0,
            "edit intent needs one exactly shared frozen source and anchor"
        );
        let intent = Self {
            format_version: 1,
            anchor_id,
            source_id,
            staging_name,
            original_access: proof.original_access,
            frozen_content: proof.content,
            phase: LinkFreezeEditPhase::SharedFrozen,
            copy: None,
            private_inode: None,
        };
        anyhow::ensure!(
            control.put_record_if_absent(
                EDIT_INTENT_KIND,
                anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&intent)?,
            )?,
            "a different edit intent already owns this anchor"
        );
        Ok(intent)
    }

    pub fn load(control: &ControlStore, anchor_id: Uuid) -> anyhow::Result<Option<Self>> {
        let Some(bytes) = control.get_record(EDIT_INTENT_KIND, anchor_id.as_bytes())? else {
            return Ok(None);
        };
        let intent: Self = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(intent.format_version == 1 && intent.anchor_id == anchor_id);
        anyhow::ensure!(intent.staging_name == format!(".link-edit-{anchor_id}"));
        anyhow::ensure!(
            intent.frozen_content.data_extents.len() <= 65_536,
            "frozen content proof exceeds the extent limit"
        );
        anyhow::ensure!(matches!(
            (
                intent.phase,
                intent.copy.is_some(),
                intent.private_inode.is_some()
            ),
            (
                LinkFreezeEditPhase::SharedFrozen | LinkFreezeEditPhase::CopyStaging,
                false,
                false
            ) | (
                LinkFreezeEditPhase::PrivateCopyReady
                    | LinkFreezeEditPhase::UnlockPending
                    | LinkFreezeEditPhase::Editable,
                true,
                true
            )
        ));
        Ok(Some(intent))
    }

    pub fn phase(&self) -> LinkFreezeEditPhase {
        self.phase
    }

    pub fn copy(&self) -> Option<&IndependentSparseCopy> {
        self.copy.as_ref()
    }

    pub fn private_inode(&self) -> Option<u64> {
        self.private_inode
    }

    pub fn staging_name(&self) -> &str {
        &self.staging_name
    }

    pub fn mark_copy_staging(mut self, control: &ControlStore) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeEditPhase::SharedFrozen);
        self.replace_phase(control, LinkFreezeEditPhase::CopyStaging, None, None)
    }

    /// The copy must have been created through this held guard and synced by
    /// `copy_sparse_independent`. Persist its proof and inode before changing
    /// either anchor name. A failed CAS leaves the source frozen.
    pub fn mark_private_copy_ready(
        mut self,
        control: &ControlStore,
        guard: &FileWriteExclusion,
        staging_parent: &PinnedDirectory,
        private: File,
        copy: IndependentSparseCopy,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeEditPhase::CopyStaging);
        anyhow::ensure!(guard.is_held()?);
        let source_meta = guard.file.metadata()?;
        let private_meta = private.metadata()?;
        let staged_id = staging_parent.entry_identity(&self.staging_name, false)?;
        anyhow::ensure!(
            source_meta.is_file()
                && source_meta.ino() == self.source_id.inode
                && source_meta.nlink() == 2
                && private_meta.is_file()
                && private_meta.dev() == source_meta.dev()
                && private_meta.ino() != source_meta.ino()
                && private_meta.nlink() == 1
                && staged_id.map(|id| id.filesystem_id) == Some(self.source_id.filesystem_id)
                && staged_id.map(|id| id.inode) == Some(private_meta.ino())
                && source_meta.len() == copy.logical_len
                && copy == self.frozen_content
                && private_meta.len() == copy.logical_len
                && hash_exact(&guard.file, copy.logical_len)? == copy.content_hash
                && hash_exact(&private, copy.logical_len)? == copy.content_hash
                && file_data_extents(&private, copy.logical_len)? == copy.data_extents,
            "private staging copy no longer matches the frozen source"
        );
        private.set_permissions(std::fs::Permissions::from_mode(0o400))?;
        private.sync_all()?;
        anyhow::ensure!(FileAccessSnapshot::capture(&private)?.mode & 0o222 == 0);
        staging_parent.sync_all()?;
        self.replace_phase(
            control,
            LinkFreezeEditPhase::PrivateCopyReady,
            Some(copy),
            Some(private_meta.ino()),
        )
    }

    /// Call after the private inode owns the anchor name and the old shared
    /// staging alias is gone. This syncs the pinned parent before the CAS and
    /// also handles replay after a rename completed before the CAS.
    pub fn mark_unlock_pending(
        mut self,
        control: &ControlStore,
        source: &File,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeEditPhase::PrivateCopyReady);
        self.check_source(source, source_parent, source_name)?;
        let private_anchor = anchor_parent
            .open_child_file(anchor_name)?
            .ok_or_else(|| anyhow::anyhow!("private anchor name disappeared"))?;
        anyhow::ensure!(
            private_anchor.metadata()?.ino() == self.private_inode.unwrap(),
            "the expected private inode does not own the anchor name"
        );
        verify_independent_anchor(source, &private_anchor, self.copy.as_ref().unwrap())?;
        private_anchor.sync_all()?;
        anchor_parent.sync_all()?;
        self.replace_phase(control, LinkFreezeEditPhase::UnlockPending, None, None)
    }

    /// A replay may reach this step after permissions were restored and the
    /// user edited the source. Only the private anchor proof remains immutable.
    pub fn mark_editable(
        mut self,
        control: &ControlStore,
        source: &File,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeEditPhase::UnlockPending);
        self.check_source(source, source_parent, source_name)?;
        let private_anchor = anchor_parent
            .open_child_file(anchor_name)?
            .ok_or_else(|| anyhow::anyhow!("private anchor name disappeared"))?;
        anyhow::ensure!(private_anchor.metadata()?.ino() == self.private_inode.unwrap());
        anyhow::ensure!(self.original_access.is_restored_after_detach(
            source,
            &private_anchor,
            self.copy.as_ref().unwrap(),
        )?);
        self.replace_phase(control, LinkFreezeEditPhase::Editable, None, None)
    }

    pub(crate) fn retire(self, control: &ControlStore) -> anyhow::Result<()> {
        anyhow::ensure!(self.phase == LinkFreezeEditPhase::Editable);
        control.delete_record_if_value(
            EDIT_INTENT_KIND,
            self.anchor_id.as_bytes(),
            &mb_core::canonical_bytes(&self)?,
        )?;
        Ok(())
    }

    /// Resume every durable edit phase against pinned source and anchor names.
    /// Missing, replaced, or corrupt objects never cause this replay to grant
    /// write access. The owning capture record must resolve these directories and
    /// names before calling this method; it remains responsible for retaining
    /// the anchor after this edit intent is retired.
    pub fn resume(
        mut self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        let source_name = source_name.as_ref();
        let anchor_name = anchor_name.as_ref();
        anyhow::ensure!(
            control.get_record(EDIT_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?),
            "edit intent changed before replay"
        );
        loop {
            self = match self.phase {
                LinkFreezeEditPhase::SharedFrozen => self.mark_copy_staging(control)?,
                LinkFreezeEditPhase::CopyStaging => {
                    let source = source_parent
                        .open_child_file(source_name)?
                        .ok_or_else(|| anyhow::anyhow!("frozen source name disappeared"))?;
                    self.check_source(&source, source_parent, source_name)?;
                    let guard = FileWriteExclusion::acquire(source)?;
                    self.check_shared_frozen(&guard.file, anchor_parent, anchor_name)?;
                    if let Some(staged_id) =
                        anchor_parent.entry_identity(&self.staging_name, false)?
                    {
                        anyhow::ensure!(
                            staged_id != self.source_id
                                && staged_id.filesystem_id == self.source_id.filesystem_id
                                && anchor_parent
                                    .open_child_file(&self.staging_name)?
                                    .ok_or_else(|| anyhow::anyhow!("staging name disappeared"))?
                                    .metadata()?
                                    .nlink()
                                    == 1,
                            "unverified staging alias blocks edit replay"
                        );
                        anchor_parent
                            .remove_child_file_if_identity(&self.staging_name, staged_id)?;
                    }
                    let private = anchor_parent.create_child_file(&self.staging_name)?;
                    let copy = guard.copy_sparse_independent(&private)?;
                    let ready = self.mark_private_copy_ready(
                        control,
                        &guard,
                        anchor_parent,
                        private,
                        copy,
                    )?;
                    guard.release()?;
                    ready
                }
                LinkFreezeEditPhase::PrivateCopyReady => {
                    let source = source_parent
                        .open_child_file(source_name)?
                        .ok_or_else(|| anyhow::anyhow!("frozen source name disappeared"))?;
                    self.check_source(&source, source_parent, source_name)?;
                    let source_meta = source.metadata()?;
                    let anchor_entry = anchor_parent
                        .entry_identity(anchor_name, false)?
                        .ok_or_else(|| anyhow::anyhow!("anchor name disappeared"))?;
                    let staged_entry = anchor_parent.entry_identity(&self.staging_name, false)?;
                    let private_id = NativeFileId {
                        filesystem_id: self.source_id.filesystem_id,
                        inode: self.private_inode.unwrap(),
                    };
                    if anchor_entry == self.source_id && staged_entry == Some(private_id) {
                        let guard = FileWriteExclusion::acquire(source.try_clone()?)?;
                        self.check_shared_frozen(&guard.file, anchor_parent, anchor_name)?;
                        let staging = anchor_parent
                            .open_child_file(&self.staging_name)?
                            .ok_or_else(|| anyhow::anyhow!("private staging name disappeared"))?;
                        self.check_private_copy(&guard.file, &staging)?;
                        anchor_parent.exchange_child_files(
                            anchor_name,
                            self.source_id,
                            anchor_parent,
                            &self.staging_name,
                            private_id,
                        )?;
                        anchor_parent
                            .remove_child_file_if_identity(&self.staging_name, self.source_id)?;
                        let pending = self.mark_unlock_pending(
                            control,
                            &guard.file,
                            source_parent,
                            source_name,
                            anchor_parent,
                            anchor_name,
                        )?;
                        guard.release()?;
                        pending
                    } else if anchor_entry == private_id && staged_entry == Some(self.source_id) {
                        let guard = FileWriteExclusion::acquire(source.try_clone()?)?;
                        anyhow::ensure!(source_meta.nlink() == 2);
                        let private_anchor = anchor_parent
                            .open_child_file(anchor_name)?
                            .ok_or_else(|| anyhow::anyhow!("private anchor name disappeared"))?;
                        self.check_private_copy(&guard.file, &private_anchor)?;
                        anchor_parent
                            .remove_child_file_if_identity(&self.staging_name, self.source_id)?;
                        let pending = self.mark_unlock_pending(
                            control,
                            &guard.file,
                            source_parent,
                            source_name,
                            anchor_parent,
                            anchor_name,
                        )?;
                        guard.release()?;
                        pending
                    } else if anchor_entry == private_id && staged_entry.is_none() {
                        anyhow::ensure!(source_meta.nlink() == 1);
                        self.mark_unlock_pending(
                            control,
                            &source,
                            source_parent,
                            source_name,
                            anchor_parent,
                            anchor_name,
                        )?
                    } else {
                        anyhow::bail!("anchor and staging names disagree with the edit intent");
                    }
                }
                LinkFreezeEditPhase::UnlockPending => {
                    let source = source_parent
                        .open_child_file(source_name)?
                        .ok_or_else(|| anyhow::anyhow!("detached source name disappeared"))?;
                    self.check_source(&source, source_parent, source_name)?;
                    let anchor = anchor_parent
                        .open_child_file(anchor_name)?
                        .ok_or_else(|| anyhow::anyhow!("private anchor name disappeared"))?;
                    anyhow::ensure!(anchor.metadata()?.ino() == self.private_inode.unwrap());
                    if !self.original_access.is_restored_after_detach(
                        &source,
                        &anchor,
                        self.copy.as_ref().unwrap(),
                    )? {
                        self.original_access.restore_after_detach_replaying(
                            &source,
                            &anchor,
                            self.copy.as_ref().unwrap(),
                        )?;
                    }
                    self.mark_editable(
                        control,
                        &source,
                        source_parent,
                        source_name,
                        anchor_parent,
                        anchor_name,
                    )?
                }
                LinkFreezeEditPhase::Editable => {
                    let source = source_parent
                        .open_child_file(source_name)?
                        .ok_or_else(|| anyhow::anyhow!("editable source name disappeared"))?;
                    self.check_source(&source, source_parent, source_name)?;
                    let anchor = anchor_parent
                        .open_child_file(anchor_name)?
                        .ok_or_else(|| anyhow::anyhow!("private anchor name disappeared"))?;
                    anyhow::ensure!(anchor.metadata()?.ino() == self.private_inode.unwrap());
                    anyhow::ensure!(self.original_access.is_restored_after_detach(
                        &source,
                        &anchor,
                        self.copy.as_ref().unwrap(),
                    )?);
                    return Ok(self);
                }
            };
        }
    }

    fn check_shared_frozen(
        &self,
        source: &File,
        anchor_parent: &PinnedDirectory,
        anchor_name: &Path,
    ) -> anyhow::Result<()> {
        let metadata = source.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.ino() == self.source_id.inode
                && metadata.nlink() == 2
                && metadata.len() == self.frozen_content.logical_len
                && anchor_parent.entry_identity(anchor_name, false)? == Some(self.source_id)
                && FileAccessSnapshot::capture(source)?.mode & 0o222 == 0
                && hash_exact(source, metadata.len())? == self.frozen_content.content_hash
                && file_data_extents(source, metadata.len())? == self.frozen_content.data_extents,
            "frozen source or shared anchor changed during edit replay"
        );
        Ok(())
    }

    fn check_private_copy(&self, source: &File, private: &File) -> anyhow::Result<()> {
        let source_meta = source.metadata()?;
        let private_meta = private.metadata()?;
        let copy = self.copy.as_ref().unwrap();
        anyhow::ensure!(
            source_meta.is_file()
                && source_meta.len() == copy.logical_len
                && hash_exact(source, copy.logical_len)? == copy.content_hash
                && private_meta.is_file()
                && private_meta.dev() == source_meta.dev()
                && private_meta.ino() == self.private_inode.unwrap()
                && private_meta.nlink() == 1
                && FileAccessSnapshot::capture(private)?.mode & 0o222 == 0
                && private_meta.len() == copy.logical_len
                && hash_exact(private, copy.logical_len)? == copy.content_hash
                && file_data_extents(private, copy.logical_len)? == copy.data_extents,
            "private copy proof changed before anchor publication"
        );
        Ok(())
    }

    fn check_source(
        &self,
        source: &File,
        parent: &PinnedDirectory,
        name: impl AsRef<Path>,
    ) -> anyhow::Result<()> {
        let metadata = source.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.ino() == self.source_id.inode
                && parent.entry_identity(name, false)? == Some(self.source_id),
            "edit intent source identity changed"
        );
        Ok(())
    }

    fn replace_phase(
        &mut self,
        control: &ControlStore,
        phase: LinkFreezeEditPhase,
        copy: Option<IndependentSparseCopy>,
        private_inode: Option<u64>,
    ) -> anyhow::Result<Self> {
        let before = mb_core::canonical_bytes(self)?;
        self.phase = phase;
        if let Some(copy) = copy {
            self.copy = Some(copy);
        }
        if let Some(private_inode) = private_inode {
            self.private_inode = Some(private_inode);
        }
        control.replace_record_if_value(
            EDIT_INTENT_KIND,
            self.anchor_id.as_bytes(),
            &before,
            &mb_core::canonical_bytes(self)?,
        )?;
        Ok(self.clone())
    }
}

fn read_access_acl(file: &File) -> io::Result<AccessAclSnapshot> {
    let fd = file.as_raw_fd();
    // SAFETY: the pinned descriptor and NUL-terminated xattr name are valid.
    let length = unsafe { libc::fgetxattr(fd, ACCESS_ACL_NAME.as_ptr(), std::ptr::null_mut(), 0) };
    if length < 0 {
        let error = io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::ENODATA) => Ok(AccessAclSnapshot::Absent),
            Some(libc::EOPNOTSUPP) => Ok(AccessAclSnapshot::Unsupported),
            _ => Err(error),
        };
    }
    let length = length as usize;
    if length == 0 || length > MAX_ACCESS_ACL_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "POSIX access ACL exceeds its supported bound or is empty",
        ));
    }
    let mut value = vec![0_u8; length];
    // SAFETY: the allocated vector has length bytes and the kernel writes at
    // most that many bytes; a changed ACL returns ERANGE or a different size.
    let read = unsafe {
        libc::fgetxattr(
            fd,
            ACCESS_ACL_NAME.as_ptr(),
            value.as_mut_ptr().cast(),
            value.len(),
        )
    };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    if read as usize != length {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "POSIX access ACL changed during capture",
        ));
    }
    Ok(AccessAclSnapshot::Present(value))
}

/// Install a named-user ACL on a disposable probe file when supported, so the
/// freeze/restore lifecycle exercises the ACL mask rather than mode bits only.
pub(crate) fn install_probe_acl(file: &File) -> io::Result<bool> {
    // Linux POSIX ACL xattr: version 2 and owner, named user, group, mask,
    // other entries. The named user grants write only through the mask.
    let mut acl = 2_u32.to_le_bytes().to_vec();
    // SAFETY: geteuid has no pointers and returns this process's effective UID.
    let named_user = if unsafe { libc::geteuid() } == 2000 {
        2001
    } else {
        2000
    };
    for (tag, permission, id) in [
        (1_u16, 6_u16, u32::MAX),
        (2, 6, named_user),
        (4, 6, u32::MAX),
        (16, 6, u32::MAX),
        (32, 0, u32::MAX),
    ] {
        acl.extend_from_slice(&tag.to_le_bytes());
        acl.extend_from_slice(&permission.to_le_bytes());
        acl.extend_from_slice(&id.to_le_bytes());
    }
    // SAFETY: the descriptor, constant name, and allocated ACL buffer remain
    // valid through the call; the kernel validates the encoding.
    if unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            ACCESS_ACL_NAME.as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::EOPNOTSUPP) {
            return Ok(false);
        }
        return Err(error);
    }
    Ok(true)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FanotifyEventMetadata {
    event_len: u32,
    version: u8,
    reserved: u8,
    metadata_len: u16,
    mask: u64,
    fd: i32,
    pid: i32,
}

#[repr(C)]
struct FanotifyResponse {
    fd: i32,
    response: u32,
}

/// Keeps an inode free of open writers during a short permission transition.
#[must_use = "dropping the guard releases its write exclusion"]
pub struct FileWriteExclusion {
    file: File,
    fanotify: File,
    stop: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
    active: bool,
}

impl FileWriteExclusion {
    /// The caller must pass a dedicated read-only descriptor for a regular
    /// file. This requires CAP_SYS_ADMIN for fanotify permission events and a
    /// kernel with FAN_PRE_ACCESS (Linux 6.14 or newer). Ownership and
    /// filesystem lease support are checked by the kernel; unsupported hosts
    /// return an error instead of weakening the guard.
    pub fn acquire(file: File) -> io::Result<Self> {
        if !file.metadata()?.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "file leases require a regular file",
            ));
        }
        let fd = file.as_raw_fd();
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::O_ACCMODE != libc::O_RDONLY {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "read lease needs a read-only descriptor",
            ));
        }
        // A read lease alone is insufficient: a conflicting O_NONBLOCK open
        // or pathname truncate can break it immediately. Install inode-bound
        // permission marks first, then acquire the lease to exclude writers
        // opened earlier. FAN_PRE_ACCESS requires a recent kernel and catches
        // truncate without an open; unsupported kernels fail this probe.
        // SAFETY: fanotify_init receives the documented Linux UAPI flags.
        let fan_fd = unsafe {
            libc::fanotify_init(
                FAN_CLOEXEC | FAN_NONBLOCK | FAN_CLASS_PRE_CONTENT,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
            )
        };
        if fan_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fanotify_init returned sole ownership of this descriptor.
        let fanotify = unsafe { File::from_raw_fd(fan_fd) };
        let stop = Arc::new(AtomicBool::new(false));
        let healthy = Arc::new(AtomicBool::new(true));
        let worker_file = fanotify.try_clone()?;
        let worker_stop = Arc::clone(&stop);
        let worker_healthy = Arc::clone(&healthy);
        let worker = thread::Builder::new()
            .name("mb-link-freeze-deny".to_owned())
            .spawn(move || deny_new_opens(&worker_file, &worker_stop, &worker_healthy))?;
        let mut guard = Self {
            file,
            fanotify,
            stop,
            healthy,
            worker: Some(worker),
            active: false,
        };
        // A NULL path marks the opened inode rather than a potentially
        // replaced pathname. New opens now need an explicit deny response.
        // SAFETY: both descriptors are valid and NULL selects the source fd.
        if unsafe {
            libc::fanotify_mark(
                guard.fanotify.as_raw_fd(),
                FAN_MARK_ADD,
                FAN_OPEN_PERM | FAN_PRE_ACCESS,
                guard.file.as_raw_fd(),
                std::ptr::null(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        // SIGURG is ignored by default. A competing writer must not send the
        // daemon the default lease-break signal, SIGIO, which could terminate
        // it before the permission transition is made durable.
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        if unsafe { libc::fcntl(fd, F_SETSIG_LINUX, libc::SIGURG) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        if unsafe { libc::fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        guard.active = true;
        if !guard.is_held()? {
            return Err(io::Error::other(
                "write exclusion was lost during acquisition",
            ));
        }
        Ok(guard)
    }

    /// A lease can be forcibly broken after the kernel's lease-break timeout.
    /// A caller must verify this before committing an anchor transition.
    pub fn is_held(&self) -> io::Result<bool> {
        if !self.healthy.load(Ordering::Acquire) {
            return Ok(false);
        }
        // SAFETY: fcntl only inspects the valid descriptor and command.
        let state = unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_GETLEASE) };
        if state < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(state == libc::F_RDLCK)
    }

    /// Copy the pinned, frozen source into a distinct writable inode. The
    /// source descriptor was opened before the fanotify mark, so its reads do
    /// not need a permission exception. New opens and pathname truncates stay
    /// denied, while other preexisting read-only descriptors remain harmless.
    /// The caller must persist its freeze intent first and publish the result
    /// only after the returned copy has been verified and synced.
    pub fn copy_sparse_independent(
        &self,
        destination: &File,
    ) -> Result<IndependentSparseCopy, AnchorError> {
        if !self.is_held()? {
            return Err(io::Error::other("write exclusion is no longer held").into());
        }
        run_after_sparse_copy_start_hook();
        let copy = copy_sparse_independent(&self.file, destination)?;
        if !self.is_held()? {
            return Err(io::Error::other("write exclusion was lost during sparse copy").into());
        }
        Ok(copy)
    }

    /// Release only after the caller has made the permission transition durable
    /// or abandoned it with the original permissions intact.
    pub fn release(mut self) -> io::Result<()> {
        self.unlock()
    }

    fn unlock(&mut self) -> io::Result<()> {
        if !self.active {
            return Ok(());
        }
        // SAFETY: fcntl only inspects the valid descriptor and integer args.
        if unsafe { libc::fcntl(self.file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
        self.active = false;
        Ok(())
    }
}

fn copy_sparse_independent(
    source: &File,
    destination: &File,
) -> Result<IndependentSparseCopy, AnchorError> {
    let before = source.metadata()?;
    let target = destination.metadata()?;
    if !before.is_file()
        || !target.is_file()
        || before.dev() != target.dev()
        || before.ino() == target.ino()
        || target.nlink() != 1
        || target.len() != 0
        || before.len() > i64::MAX as u64
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sparse detach needs a new, empty, private inode on the source filesystem",
        )
        .into());
    }
    let logical_len = before.len();
    let data_extents = file_data_extents(source, logical_len)?;
    destination.set_len(logical_len)?;
    let mut buffer = [0_u8; 64 * 1024];
    for extent in &data_extents {
        let end = extent.offset + extent.logical_len;
        let mut position = extent.offset;
        while position < end {
            let take = (end - position).min(buffer.len() as u64) as usize;
            let read = source.read_at(&mut buffer[..take], position)?;
            if read == 0 {
                return Err(
                    io::Error::new(io::ErrorKind::UnexpectedEof, "source extent shrank").into(),
                );
            }
            let mut written = 0;
            while written < read {
                let count =
                    destination.write_at(&buffer[written..read], position + written as u64)?;
                if count == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "sparse copy write stopped",
                    )
                    .into());
                }
                written += count;
                #[cfg(test)]
                run_after_sparse_copy_write_hook()?;
            }
            position += read as u64;
        }
    }
    destination.sync_all()?;
    let after = source.metadata()?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mode(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mode(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) || destination.metadata()?.len() != logical_len
    {
        return Err(io::Error::other("source changed during sparse detach copy").into());
    }
    if file_data_extents(destination, logical_len)? != data_extents {
        return Err(io::Error::other("sparse detach copy changed hole layout").into());
    }
    let source_hash = hash_exact(source, logical_len)?;
    if hash_exact(destination, logical_len)? != source_hash {
        return Err(io::Error::other("sparse detach copy changed bytes").into());
    }
    Ok(IndependentSparseCopy {
        logical_len,
        content_hash: source_hash,
        data_extents,
    })
}

fn hash_exact(file: &File, logical_len: u64) -> io::Result<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut position = 0;
    while position < logical_len {
        let take = (logical_len - position).min(buffer.len() as u64) as usize;
        let read = file.read_at(&mut buffer[..take], position)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "file shrank during hash",
            ));
        }
        hasher.update(&buffer[..read]);
        position += read as u64;
    }
    Ok(*hasher.finalize().as_bytes())
}

impl Drop for FileWriteExclusion {
    fn drop(&mut self) {
        let _ = self.unlock();
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn deny_new_opens(group: &File, stop: &AtomicBool, healthy: &AtomicBool) {
    let mut buffer = [0_u8; 16 * 1024];
    while !stop.load(Ordering::Acquire) {
        // SAFETY: the buffer is writable and the descriptor stays live for
        // this worker's lifetime.
        let count =
            unsafe { libc::read(group.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if count < 0 {
            match io::Error::last_os_error().kind() {
                io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(1)),
                io::ErrorKind::Interrupted => {}
                _ => {
                    healthy.store(false, Ordering::Release);
                    return;
                }
            }
            continue;
        }
        if count == 0 {
            healthy.store(false, Ordering::Release);
            return;
        }
        let mut offset = 0;
        let count = count as usize;
        while offset < count {
            if count - offset < std::mem::size_of::<FanotifyEventMetadata>() {
                healthy.store(false, Ordering::Release);
                return;
            }
            // SAFETY: the size check above covers the metadata, and an
            // unaligned read avoids assuming the kernel buffer's alignment.
            let event = unsafe {
                std::ptr::read_unaligned(
                    buffer.as_ptr().add(offset).cast::<FanotifyEventMetadata>(),
                )
            };
            let event_len = event.event_len as usize;
            if event.version != FANOTIFY_METADATA_VERSION
                || event_len < std::mem::size_of::<FanotifyEventMetadata>()
                || event_len > count - offset
                || (event.metadata_len as usize) < std::mem::size_of::<FanotifyEventMetadata>()
                || (event.metadata_len as usize) > event_len
                || event.mask & FAN_Q_OVERFLOW != 0
                || event.mask & (FAN_OPEN_PERM | FAN_PRE_ACCESS) == 0
                || event.fd < 0
            {
                if event.fd >= 0 {
                    // SAFETY: the kernel supplied an event descriptor and we
                    // are discarding this event without a permission reply.
                    unsafe { libc::close(event.fd) };
                }
                healthy.store(false, Ordering::Release);
                return;
            }
            let response = FanotifyResponse {
                fd: event.fd,
                response: FAN_DENY,
            };
            // SAFETY: the response is a valid Linux fanotify_response and
            // the event descriptor is owned by this worker after read().
            let written = unsafe {
                libc::write(
                    group.as_raw_fd(),
                    (&raw const response).cast(),
                    std::mem::size_of::<FanotifyResponse>(),
                )
            };
            // SAFETY: the event descriptor is no longer needed after the
            // permission decision, including if the write failed.
            unsafe { libc::close(event.fd) };
            if written != std::mem::size_of::<FanotifyResponse>() as isize {
                healthy.store(false, Ordering::Release);
                return;
            }
            offset += event_len;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    use mb_core::{KeyMaterial, Seed};
    use uuid::Uuid;

    use crate::anchor::{PinnedDirectory, probe_guarded_link_freeze};
    use crate::database::ControlStore;

    use super::{
        AFTER_SPARSE_COPY_START, AFTER_SPARSE_COPY_WRITE, AccessAclSnapshot, FileAccessSnapshot,
        FileWriteExclusion, FrozenAnchorProof, IndependentSparseCopy, LinkFreezeEditIntent,
        LinkFreezeEditPhase, copy_sparse_independent, file_data_extents, hash_exact,
        install_probe_acl,
    };

    #[test]
    fn edit_intent_rejects_using_the_anchor_name_as_its_source() {
        let root = test_directory();
        fs::write(root.path().join("source"), b"immutable bytes").unwrap();
        fs::hard_link(root.path().join("source"), root.path().join("anchor")).unwrap();
        let parent = PinnedDirectory::open(root.path()).unwrap();
        let file = File::open(root.path().join("anchor")).unwrap();
        let proof = FrozenAnchorProof {
            original_access: FileAccessSnapshot::capture(&file).unwrap(),
            content: IndependentSparseCopy {
                logical_len: file.metadata().unwrap().len(),
                content_hash: hash_exact(&file, file.metadata().unwrap().len()).unwrap(),
                data_extents: file_data_extents(&file, file.metadata().unwrap().len()).unwrap(),
            },
        };
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([74; 32]));
        let store = ControlStore::open(root.path().join("control.db"), &keys).unwrap();
        let anchor_id = Uuid::new_v4();
        assert!(
            LinkFreezeEditIntent::begin(
                &store, anchor_id, &parent, "anchor", &parent, "anchor", proof,
            )
            .is_err()
        );
        assert!(
            LinkFreezeEditIntent::load(&store, anchor_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(root.path().join("anchor")).unwrap(),
            b"immutable bytes"
        );
    }

    #[test]
    fn access_snapshot_records_the_acl_mask_changed_by_chmod() {
        let root = test_directory();
        let path = root.path().join("access");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_at(b"acl-content", 0).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o660))
            .unwrap();
        if !install_probe_acl(&file).unwrap() {
            return;
        }
        let snapshot = FileAccessSnapshot::capture(&File::open(&path).unwrap()).unwrap();
        assert_eq!(snapshot.mode, 0o660);
        assert!(matches!(
            &snapshot.access_acl,
            AccessAclSnapshot::Present(_)
        ));
        let encoded = mb_core::canonical_bytes(&snapshot).unwrap();
        let decoded: FileAccessSnapshot = mb_core::decode_canonical(&encoded).unwrap();
        assert_eq!(decoded, snapshot);

        let anchor = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(root.path().join("private-anchor"))
            .unwrap();
        let copy = copy_sparse_independent(&file, &anchor).unwrap();
        anchor
            .set_permissions(fs::Permissions::from_mode(0o400))
            .unwrap();
        anchor.sync_all().unwrap();
        let encoded_copy = mb_core::canonical_bytes(&copy).unwrap();
        let recovered_copy: super::IndependentSparseCopy =
            mb_core::decode_canonical(&encoded_copy).unwrap();
        assert_eq!(recovered_copy, copy);

        file.set_permissions(fs::Permissions::from_mode(0o440))
            .unwrap();
        assert!(!snapshot.matches(&file).unwrap());
        assert!(
            !snapshot
                .is_restored_after_detach(&file, &anchor, &recovered_copy)
                .unwrap()
        );
        snapshot
            .restore_after_detach(&file, &anchor, &copy)
            .unwrap();
        assert!(snapshot.matches(&file).unwrap());
        file.write_at(b"edited", 0).unwrap();
        assert!(
            snapshot
                .is_restored_after_detach(&file, &anchor, &recovered_copy)
                .unwrap()
        );
        assert!(
            snapshot
                .restore_after_detach(&file, &anchor, &recovered_copy)
                .is_err()
        );
        anchor.write_at(b"damage", 0).unwrap();
        assert!(
            snapshot
                .is_restored_after_detach(&file, &anchor, &recovered_copy)
                .is_err()
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn lease_rejects_open_writers_and_writable_mappings() {
        let root = test_directory();
        let path = root.path().join("source");
        fs::write(&path, vec![7_u8; 4096]).unwrap();

        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        let attempted = FileWriteExclusion::acquire(File::open(&path).unwrap());
        assert_eq!(attempted.err().unwrap().raw_os_error(), Some(libc::EAGAIN));
        drop(writer);

        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        // SAFETY: the descriptor names a 4096-byte regular file; the mapping
        // is unmapped below before the test directory is removed.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                4096,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                writer.as_raw_fd(),
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        drop(writer);
        let attempted = FileWriteExclusion::acquire(File::open(&path).unwrap());
        assert_eq!(attempted.err().unwrap().raw_os_error(), Some(libc::EAGAIN));
        // SAFETY: this releases the exact mapping established above.
        assert_eq!(unsafe { libc::munmap(mapping, 4096) }, 0);

        let guard = FileWriteExclusion::acquire(File::open(&path).unwrap()).unwrap();
        assert!(guard.is_held().unwrap());
        let access = FileAccessSnapshot::capture(&guard.file).unwrap();
        assert!(access.matches(&guard.file).unwrap());
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated path and integer flags are valid.
        let competing = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        assert_eq!(competing, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );

        // A pathname truncate does not need to open a writable descriptor.
        // FAN_PRE_ACCESS must deny it while the transition guard is active.
        // SAFETY: the NUL-terminated path is valid.
        assert_eq!(unsafe { libc::truncate(c_path.as_ptr(), 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 4096);

        let anchor = root.path().join("anchor");
        fs::hard_link(&path, &anchor).unwrap();
        let c_anchor = CString::new(anchor.as_os_str().as_bytes()).unwrap();
        // An inode mark must cover every hard-link alias, including an alias
        // created after acquisition.
        assert_eq!(unsafe { libc::truncate(c_anchor.as_ptr(), 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EPERM)
        );
        assert_eq!(fs::metadata(&anchor).unwrap().len(), 4096);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).unwrap();
        assert!(guard.is_held().unwrap());
        guard.release().unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert!(OpenOptions::new().write(true).open(&anchor).is_err());
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn guarded_sparse_copy_detaches_the_anchor_without_changing_bytes_or_holes() {
        let root = test_directory();
        let source_path = root.path().join("source");
        let anchor_path = root.path().join("anchor");
        let staging_path = root.path().join("private-staging");
        let logical_len = 1024 * 1024 + 4096;
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        source.set_len(logical_len).unwrap();
        source.write_at(b"head", 0).unwrap();
        source.write_at(b"tail", logical_len - 4).unwrap();
        source.sync_all().unwrap();
        let original_extents = file_data_extents(&source, logical_len).unwrap();
        assert!(original_extents.len() >= 2);
        drop(source);

        let other_reader = File::open(&source_path).unwrap();
        let guard = FileWriteExclusion::acquire(File::open(&source_path).unwrap()).unwrap();
        let access = FileAccessSnapshot::capture(&guard.file).unwrap();
        fs::hard_link(&source_path, &anchor_path).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
        let shared = guard.file.try_clone().unwrap();
        assert!(guard.copy_sparse_independent(&shared).is_err());
        assert_eq!(fs::metadata(&source_path).unwrap().len(), logical_len);
        let nonempty_path = root.path().join("nonempty");
        fs::write(&nonempty_path, b"keep").unwrap();
        let nonempty = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&nonempty_path)
            .unwrap();
        assert!(guard.copy_sparse_independent(&nonempty).is_err());
        assert_eq!(fs::read(&nonempty_path).unwrap(), b"keep");
        let private = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .unwrap();
        let alias_for_attempt = anchor_path.clone();
        AFTER_SPARSE_COPY_START.with(|slot| {
            *slot.borrow_mut() = Some(Box::new(move || {
                let read = std::thread::spawn(move || {
                    let mut byte = [0];
                    (other_reader.read_at(&mut byte, 0).unwrap(), byte)
                })
                .join()
                .unwrap();
                assert_eq!(read, (1, *b"h"));
                let truncate_error = std::thread::spawn(move || {
                    let path = CString::new(alias_for_attempt.as_os_str().as_bytes()).unwrap();
                    // SAFETY: the pathname is a valid NUL-terminated string.
                    assert_eq!(unsafe { libc::truncate(path.as_ptr(), 0) }, -1);
                    std::io::Error::last_os_error()
                })
                .join()
                .unwrap();
                assert_eq!(truncate_error.raw_os_error(), Some(libc::EPERM));
            }));
        });
        let copied = guard.copy_sparse_independent(&private).unwrap();
        private
            .set_permissions(fs::Permissions::from_mode(0o400))
            .unwrap();
        private.sync_all().unwrap();
        assert_eq!(copied.logical_len, logical_len);
        assert_eq!(copied.data_extents, original_extents);
        assert!(guard.is_held().unwrap());
        assert!(
            access
                .restore_after_detach(&guard.file, &shared, &copied)
                .is_err()
        );
        guard.release().unwrap();

        fs::rename(&staging_path, &anchor_path).unwrap();
        assert_ne!(
            fs::metadata(&source_path).unwrap().ino(),
            fs::metadata(&anchor_path).unwrap().ino()
        );
        let source_read = File::open(&source_path).unwrap();
        let anchor_read = File::open(&anchor_path).unwrap();
        access
            .restore_after_detach(&source_read, &anchor_read, &copied)
            .unwrap();
        fs::write(&source_path, b"edited").unwrap();
        assert_eq!(fs::metadata(&anchor_path).unwrap().len(), logical_len);
        assert_eq!(fs::read(&anchor_path).unwrap()[..4], *b"head");
        assert_eq!(
            fs::read(&anchor_path).unwrap()[(logical_len - 4) as usize..],
            *b"tail"
        );
        assert_eq!(
            file_data_extents(&File::open(&anchor_path).unwrap(), logical_len).unwrap(),
            original_extents
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn edit_journal_replays_private_copy_and_retirement_after_source_edit() {
        let root = test_directory();
        let source_path = root.path().join("source");
        let anchor_path = root.path().join("anchor");
        let source = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        source.set_len(1024 * 1024).unwrap();
        source.write_at(b"before-edit", 4096).unwrap();
        source.sync_all().unwrap();
        drop(source);
        fs::hard_link(&source_path, &anchor_path).unwrap();
        let source = File::open(&source_path).unwrap();
        let shared_anchor = File::open(&anchor_path).unwrap();
        assert_eq!(
            source.metadata().unwrap().ino(),
            shared_anchor.metadata().unwrap().ino()
        );
        let guard = FileWriteExclusion::acquire(source.try_clone().unwrap()).unwrap();
        let access = FileAccessSnapshot::capture(&source).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
        source.sync_all().unwrap();
        File::open(root.path()).unwrap().sync_all().unwrap();
        guard.release().unwrap();

        let keys = KeyMaterial::from_seed(&Seed::from_bytes([91; 32]));
        let database_path = root.path().join("control.db");
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let anchor_id = Uuid::new_v4();
        let parent = PinnedDirectory::open(root.path()).unwrap();
        let frozen_content = IndependentSparseCopy {
            logical_len: source.metadata().unwrap().len(),
            content_hash: hash_exact(&source, source.metadata().unwrap().len()).unwrap(),
            data_extents: file_data_extents(&source, source.metadata().unwrap().len()).unwrap(),
        };
        let frozen = LinkFreezeEditIntent::begin(
            &store,
            anchor_id,
            &parent,
            "source",
            &parent,
            "anchor",
            FrozenAnchorProof {
                original_access: access.clone(),
                content: frozen_content.clone(),
            },
        )
        .unwrap();
        assert!(
            LinkFreezeEditIntent::begin(
                &store,
                anchor_id,
                &parent,
                "source",
                &parent,
                "anchor",
                FrozenAnchorProof {
                    original_access: access.clone(),
                    content: frozen_content.clone(),
                },
            )
            .is_err()
        );
        let copying = frozen.clone().mark_copy_staging(&store).unwrap();
        assert!(
            frozen
                .clone()
                .resume(&store, &parent, "source", &parent, "anchor")
                .is_err()
        );
        assert!(!root.path().join(copying.staging_name()).exists());
        assert!(frozen.mark_copy_staging(&store).is_err());
        let guard = FileWriteExclusion::acquire(source.try_clone().unwrap()).unwrap();
        let staging_path = root.path().join(copying.staging_name());
        let private = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&staging_path)
            .unwrap();
        let copy = guard.copy_sparse_independent(&private).unwrap();
        let ready = copying
            .mark_private_copy_ready(&store, &guard, &parent, private, copy.clone())
            .unwrap();
        assert_eq!(ready.phase(), LinkFreezeEditPhase::PrivateCopyReady);
        drop(store);

        // Simulate a restart between the synced copy and anchor publication.
        let store = ControlStore::open(&database_path, &keys).unwrap();
        let ready = LinkFreezeEditIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap();
        assert_eq!(ready.copy(), Some(&copy));
        fs::rename(&staging_path, &anchor_path).unwrap();
        let private_anchor = File::open(&anchor_path).unwrap();
        let pending = ready
            .mark_unlock_pending(&store, &source, &parent, "source", &parent, "anchor")
            .unwrap();
        guard.release().unwrap();
        access
            .restore_after_detach(&source, &private_anchor, &copy)
            .unwrap();
        fs::write(&source_path, b"after-edit").unwrap();
        let editable = pending
            .mark_editable(&store, &source, &parent, "source", &parent, "anchor")
            .unwrap();
        assert_eq!(editable.phase(), LinkFreezeEditPhase::Editable);
        editable.retire(&store).unwrap();
        assert!(
            LinkFreezeEditIntent::load(&store, anchor_id)
                .unwrap()
                .is_none()
        );
        assert_eq!(private_anchor.read_at(&mut [0_u8; 11], 4096).unwrap(), 11);
        assert_eq!(fs::read(&anchor_path).unwrap()[4096..4107], *b"before-edit");
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn edit_replay_recovers_each_detach_interruption() {
        for interruption in 0..=9 {
            let root = test_directory();
            let source_path = root.path().join("source");
            let anchor_path = root.path().join("anchor");
            let writer = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&source_path)
                .unwrap();
            writer.set_len(1024 * 1024).unwrap();
            writer.write_at(b"before-edit", 4096).unwrap();
            writer.sync_all().unwrap();
            drop(writer);
            fs::hard_link(&source_path, &anchor_path).unwrap();
            let source = File::open(&source_path).unwrap();
            let initial_guard = FileWriteExclusion::acquire(source.try_clone().unwrap()).unwrap();
            let access = FileAccessSnapshot::capture(&source).unwrap();
            let length = source.metadata().unwrap().len();
            let frozen_content = IndependentSparseCopy {
                logical_len: length,
                content_hash: hash_exact(&source, length).unwrap(),
                data_extents: file_data_extents(&source, length).unwrap(),
            };
            fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
            source.sync_all().unwrap();
            File::open(root.path()).unwrap().sync_all().unwrap();
            initial_guard.release().unwrap();

            let keys = KeyMaterial::from_seed(&Seed::from_bytes([92; 32]));
            let database_path = root.path().join("control.db");
            let store = ControlStore::open(&database_path, &keys).unwrap();
            let parent = PinnedDirectory::open(root.path()).unwrap();
            let anchor_id = Uuid::new_v4();
            let mut intent = LinkFreezeEditIntent::begin(
                &store,
                anchor_id,
                &parent,
                "source",
                &parent,
                "anchor",
                FrozenAnchorProof {
                    original_access: access.clone(),
                    content: frozen_content.clone(),
                },
            )
            .unwrap();
            let staging_name = intent.staging_name().to_owned();
            if interruption >= 1 {
                intent = intent.mark_copy_staging(&store).unwrap();
            }
            if interruption == 1 {
                let staging = parent.create_child_file(&staging_name).unwrap();
                staging.write_at(b"incomplete", 0).unwrap();
                staging.sync_all().unwrap();
                parent.sync_all().unwrap();
            }
            if (2..=8).contains(&interruption) {
                let guard = FileWriteExclusion::acquire(source.try_clone().unwrap()).unwrap();
                let staging = parent.create_child_file(&staging_name).unwrap();
                let copy = guard.copy_sparse_independent(&staging).unwrap();
                intent = intent
                    .mark_private_copy_ready(&store, &guard, &parent, staging, copy)
                    .unwrap();
                guard.release().unwrap();
            }
            if interruption == 8 {
                let staging_path = root.path().join(&staging_name);
                fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o600)).unwrap();
                fs::write(&staging_path, b"corrupt-copy").unwrap();
            }
            if (3..=7).contains(&interruption) {
                let guard = FileWriteExclusion::acquire(source.try_clone().unwrap()).unwrap();
                let source_id = parent.entry_identity("source", false).unwrap().unwrap();
                let private_id = parent
                    .entry_identity(&staging_name, false)
                    .unwrap()
                    .unwrap();
                parent
                    .exchange_child_files("anchor", source_id, &parent, &staging_name, private_id)
                    .unwrap();
                if interruption >= 4 {
                    parent
                        .remove_child_file_if_identity(&staging_name, source_id)
                        .unwrap();
                }
                if interruption >= 5 {
                    intent = intent
                        .mark_unlock_pending(&store, &source, &parent, "source", &parent, "anchor")
                        .unwrap();
                }
                guard.release().unwrap();
            }
            if interruption == 6 {
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o200)).unwrap();
                fs::write(&source_path, b"edited-before-replay").unwrap();
            }
            if interruption == 7 {
                let anchor = File::open(&anchor_path).unwrap();
                access
                    .restore_after_detach(&source, &anchor, intent.copy().unwrap())
                    .unwrap();
                intent = intent
                    .mark_editable(&store, &source, &parent, "source", &parent, "anchor")
                    .unwrap();
            }
            assert_eq!(
                intent.phase(),
                match interruption {
                    0 => LinkFreezeEditPhase::SharedFrozen,
                    1 | 9 => LinkFreezeEditPhase::CopyStaging,
                    2..=4 | 8 => LinkFreezeEditPhase::PrivateCopyReady,
                    5..=6 => LinkFreezeEditPhase::UnlockPending,
                    _ => LinkFreezeEditPhase::Editable,
                }
            );
            drop(store);
            drop(source);
            drop(parent);

            let store = ControlStore::open(&database_path, &keys).unwrap();
            let parent = PinnedDirectory::open(root.path()).unwrap();
            if interruption == 9 {
                AFTER_SPARSE_COPY_WRITE.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(|| {
                        Err(std::io::Error::from_raw_os_error(libc::ENOSPC))
                    }));
                });
            }
            let mut resumed = LinkFreezeEditIntent::load(&store, anchor_id)
                .unwrap()
                .unwrap()
                .resume(&store, &parent, "source", &parent, "anchor");
            if interruption == 9 {
                let error = resumed.expect_err("injected sparse-copy ENOSPC must stop detach");
                assert!(error.chain().any(|cause| {
                    cause
                        .downcast_ref::<std::io::Error>()
                        .and_then(std::io::Error::raw_os_error)
                        == Some(libc::ENOSPC)
                }));
                assert_eq!(
                    LinkFreezeEditIntent::load(&store, anchor_id)
                        .unwrap()
                        .unwrap()
                        .phase(),
                    LinkFreezeEditPhase::CopyStaging
                );
                assert_eq!(
                    fs::metadata(&source_path).unwrap().ino(),
                    fs::metadata(&anchor_path).unwrap().ino()
                );
                assert_eq!(fs::read(&anchor_path).unwrap()[4096..4107], *b"before-edit");
                assert_eq!(
                    FileAccessSnapshot::capture(&File::open(&source_path).unwrap())
                        .unwrap()
                        .mode
                        & 0o222,
                    0
                );
                resumed = LinkFreezeEditIntent::load(&store, anchor_id)
                    .unwrap()
                    .unwrap()
                    .resume(&store, &parent, "source", &parent, "anchor");
            }
            if interruption == 8 {
                assert!(resumed.is_err());
                assert_eq!(
                    LinkFreezeEditIntent::load(&store, anchor_id)
                        .unwrap()
                        .unwrap()
                        .phase(),
                    LinkFreezeEditPhase::PrivateCopyReady
                );
                assert_eq!(
                    fs::metadata(&source_path).unwrap().ino(),
                    fs::metadata(&anchor_path).unwrap().ino()
                );
                assert_eq!(
                    FileAccessSnapshot::capture(&File::open(&source_path).unwrap())
                        .unwrap()
                        .mode
                        & 0o222,
                    0
                );
                continue;
            }
            resumed
                .unwrap_or_else(|error| panic!("interruption {interruption}: {error:#}"))
                .retire(&store)
                .unwrap();
            assert!(
                LinkFreezeEditIntent::load(&store, anchor_id)
                    .unwrap()
                    .is_none()
            );
            assert!(access.matches(&File::open(&source_path).unwrap()).unwrap());
            assert_eq!(fs::read(&anchor_path).unwrap()[4096..4107], *b"before-edit");
            assert_eq!(
                file_data_extents(&File::open(&anchor_path).unwrap(), length).unwrap(),
                frozen_content.data_extents
            );
            assert!(!root.path().join(staging_name).exists());
            fs::write(&source_path, b"edited-after-replay").unwrap();
            assert_eq!(fs::read(&anchor_path).unwrap()[4096..4107], *b"before-edit");
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN and a disposable mounted filesystem of at most 512 MiB"]
    fn real_enospc_leaves_guarded_source_frozen_and_retries() {
        let mount = std::env::var_os("MUTUALBACKUP_REAL_ENOSPC_TEST_ROOT")
            .expect("set MUTUALBACKUP_REAL_ENOSPC_TEST_ROOT to a disposable mount");
        let mount = std::path::PathBuf::from(mount).canonicalize().unwrap();
        assert_eq!(
            fs::read(mount.join(".mutualbackup-disposable-enospc")).unwrap(),
            b"mutualbackup-disposable-enospc-v1\n"
        );
        assert_ne!(
            fs::metadata(&mount).unwrap().dev(),
            fs::metadata(mount.parent().unwrap()).unwrap().dev(),
            "the disposable test root must be a separate mounted filesystem"
        );
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let mounted = File::open(&mount).unwrap();
        // SAFETY: the descriptor is open and fstatvfs initializes stats on success.
        assert_eq!(
            unsafe { libc::fstatvfs(mounted.as_raw_fd(), stats.as_mut_ptr()) },
            0
        );
        // SAFETY: the preceding fstatvfs call succeeded.
        let stats = unsafe { stats.assume_init() };
        assert!(
            stats.f_blocks > 0
                && stats.f_frsize > 0
                && stats.f_blocks.saturating_mul(stats.f_frsize) <= 512 * 1024 * 1024,
            "the disposable test filesystem exceeds 512 MiB"
        );

        let root = tempfile::Builder::new()
            .prefix("mb-real-enospc-")
            .tempdir_in(&mount)
            .unwrap();
        let source_path = root.path().join("source");
        let anchor_path = root.path().join("anchor");
        let filler_path = root.path().join("filler");
        let mut source_writer = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&source_path)
            .unwrap();
        let chunk = [0x5a_u8; 1024 * 1024];
        for _ in 0..32 {
            source_writer.write_all(&chunk).unwrap();
        }
        source_writer.sync_all().unwrap();
        drop(source_writer);
        fs::hard_link(&source_path, &anchor_path).unwrap();
        let source = File::open(&source_path).unwrap();
        let original_hash = hash_exact(&source, 32 * 1024 * 1024).unwrap();
        let frozen_content = IndependentSparseCopy {
            logical_len: 32 * 1024 * 1024,
            content_hash: original_hash,
            data_extents: file_data_extents(&source, 32 * 1024 * 1024).unwrap(),
        };
        let guard = FileWriteExclusion::acquire(source.try_clone().unwrap()).unwrap();
        let access = FileAccessSnapshot::capture(&source).unwrap();
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o444)).unwrap();
        source.sync_all().unwrap();
        File::open(root.path()).unwrap().sync_all().unwrap();
        guard.release().unwrap();

        // Keep journal writes off the filesystem being filled. The anchor and
        // worktree are on the disposable mount, as they would be in practice.
        let journal_area = tempfile::tempdir().unwrap();
        assert_ne!(
            fs::metadata(journal_area.path()).unwrap().dev(),
            fs::metadata(root.path()).unwrap().dev()
        );
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([93; 32]));
        let store = ControlStore::open(journal_area.path().join("control.db"), &keys).unwrap();
        let parent = PinnedDirectory::open(root.path()).unwrap();
        let anchor_id = Uuid::new_v4();
        LinkFreezeEditIntent::begin(
            &store,
            anchor_id,
            &parent,
            "source",
            &parent,
            "anchor",
            FrozenAnchorProof {
                original_access: access.clone(),
                content: frozen_content,
            },
        )
        .unwrap();

        let mut filler = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&filler_path)
            .unwrap();
        let mut full = false;
        for _ in 0..512 {
            let result = filler.write_all(&chunk).and_then(|()| filler.sync_data());
            if let Err(error) = result {
                assert_eq!(error.raw_os_error(), Some(libc::ENOSPC));
                full = true;
                break;
            }
        }
        assert!(full, "the disposable filesystem did not become full");
        let keep = filler
            .metadata()
            .unwrap()
            .len()
            .saturating_sub(8 * 1024 * 1024);
        filler.set_len(keep).unwrap();
        filler.sync_all().unwrap();

        let error = LinkFreezeEditIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap()
            .resume(&store, &parent, "source", &parent, "anchor")
            .expect_err("a 32 MiB sparse detach must not fit in the remaining space");
        assert!(error.chain().any(|cause| {
            cause
                .downcast_ref::<std::io::Error>()
                .and_then(std::io::Error::raw_os_error)
                == Some(libc::ENOSPC)
        }));
        let pending = LinkFreezeEditIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap();
        assert_eq!(pending.phase(), LinkFreezeEditPhase::CopyStaging);
        let partial = File::open(root.path().join(pending.staging_name())).unwrap();
        assert_eq!(partial.metadata().unwrap().len(), 32 * 1024 * 1024);
        assert!(
            !file_data_extents(&partial, 32 * 1024 * 1024)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            fs::metadata(&source_path).unwrap().ino(),
            fs::metadata(&anchor_path).unwrap().ino()
        );
        assert_eq!(
            FileAccessSnapshot::capture(&File::open(&source_path).unwrap())
                .unwrap()
                .mode
                & 0o222,
            0
        );
        assert_eq!(
            hash_exact(&File::open(&anchor_path).unwrap(), 32 * 1024 * 1024).unwrap(),
            original_hash
        );

        drop(filler);
        fs::remove_file(&filler_path).unwrap();
        parent.sync_all().unwrap();
        let resumed = LinkFreezeEditIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap()
            .resume(&store, &parent, "source", &parent, "anchor")
            .unwrap();
        resumed.retire(&store).unwrap();
        assert!(access.matches(&File::open(&source_path).unwrap()).unwrap());
        fs::write(&source_path, b"edited after disk pressure").unwrap();
        assert_eq!(
            hash_exact(&File::open(&anchor_path).unwrap(), 32 * 1024 * 1024).unwrap(),
            original_hash
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn guarded_root_probe_cleans_up_after_complete_sparse_acl_lifecycle() {
        let parent = test_directory();
        let root = parent.path().join("work");
        fs::create_dir(&root).unwrap();
        probe_guarded_link_freeze(&root).unwrap();
        let children = fs::read_dir(parent.path()).unwrap().count();
        assert_eq!(
            children, 1,
            "the disposable probe directory must be removed"
        );
    }

    fn test_directory() -> tempfile::TempDir {
        match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-link-freeze-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::tempdir().unwrap(),
        }
    }
}
