//! Durable first freeze of one guarded hard-link anchor. The protected-root
//! backend owns discovery of these records and publication of source manifests.

use std::fs::File;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    FileAccessSnapshot, FileWriteExclusion, FrozenAnchorProof, IndependentSparseCopy,
    LinkFreezeEditIntent, LinkFreezeEditPhase, file_data_extents, hash_exact,
};
use crate::anchor::{CaptureVersion, NativeFileId, PinnedDirectory, capture_version};
use crate::database::ControlStore;

const CAPTURE_INTENT_KIND: &str = "link-freeze-capture-v1";
const RETIRE_INTENT_KIND: &str = "link-freeze-retire-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LinkFreezeCapturePhase {
    Prepared,
    Frozen,
    Detached,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LinkFreezeCaptureIntent {
    format_version: u16,
    anchor_id: Uuid,
    source_parent_id: NativeFileId,
    anchor_parent_id: NativeFileId,
    source_id: NativeFileId,
    source_name: PathBuf,
    anchor_name: PathBuf,
    proof: FrozenAnchorProof,
    phase: LinkFreezeCapturePhase,
    private_inode: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct LegacyCaptureIntentV1 {
    format_version: u16,
    anchor_id: Uuid,
    source_parent_id: NativeFileId,
    anchor_parent_id: NativeFileId,
    source_id: NativeFileId,
    source_name: PathBuf,
    anchor_name: PathBuf,
    proof: FrozenAnchorProof,
    phase: LinkFreezeCapturePhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
enum RetirePhase {
    Planned,
    NoSource,
    AnchorRemoved,
    AccessRestored,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct RetireIntent {
    format_version: u16,
    capture: LinkFreezeCaptureIntent,
    phase: RetirePhase,
}

impl RetireIntent {
    fn load(control: &ControlStore, anchor_id: Uuid) -> anyhow::Result<Option<Self>> {
        let Some(bytes) = control.get_record(RETIRE_INTENT_KIND, anchor_id.as_bytes())? else {
            return Ok(None);
        };
        let intent: Self = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            intent.format_version == 1 && intent.capture.anchor_id == anchor_id,
            "invalid frozen-anchor retirement"
        );
        Ok(Some(intent))
    }

    fn advance(&mut self, control: &ControlStore, phase: RetirePhase) -> anyhow::Result<()> {
        let before = mb_core::canonical_bytes(&self)?;
        self.phase = phase;
        control.replace_record_if_value(
            RETIRE_INTENT_KIND,
            self.capture.anchor_id.as_bytes(),
            &before,
            &mb_core::canonical_bytes(&self)?,
        )?;
        Ok(())
    }
}

impl LinkFreezeCaptureIntent {
    /// Record original access metadata and exact sparse bytes before adding a
    /// hard link or changing permissions. A held kernel guard excludes both
    /// already-open writers and new opens during this initial proof.
    pub fn begin(
        control: &ControlStore,
        anchor_id: Uuid,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
    ) -> anyhow::Result<Self> {
        Self::begin_inner(
            control,
            anchor_id,
            source_parent,
            source_name,
            anchor_parent,
            anchor_name,
            None,
        )
    }

    /// A durable source plan can require its exact pre-freeze inode version.
    /// The comparison happens inside the guarded first-capture transition.
    pub(crate) fn begin_checked(
        control: &ControlStore,
        anchor_id: Uuid,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
        expected: &CaptureVersion,
    ) -> anyhow::Result<Self> {
        Self::begin_inner(
            control,
            anchor_id,
            source_parent,
            source_name,
            anchor_parent,
            anchor_name,
            Some(expected),
        )
    }

    fn begin_inner(
        control: &ControlStore,
        anchor_id: Uuid,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
        anchor_name: impl AsRef<Path>,
        expected: Option<&CaptureVersion>,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!anchor_id.is_nil(), "nil frozen anchor ID");
        let source_name = source_name.as_ref();
        let anchor_name = anchor_name.as_ref();
        let source_parent_id = source_parent.identity()?;
        let anchor_parent_id = anchor_parent.identity()?;
        anyhow::ensure!(
            source_parent_id.filesystem_id == anchor_parent_id.filesystem_id,
            "a hard-link anchor must stay on the source filesystem"
        );
        anyhow::ensure!(
            anchor_parent.entry_identity(anchor_name, false)?.is_none(),
            "frozen anchor name already exists"
        );
        let source = source_parent
            .open_child_file(source_name)?
            .ok_or_else(|| anyhow::anyhow!("source name disappeared"))?;
        let source_id = source_parent
            .entry_identity(source_name, false)?
            .ok_or_else(|| anyhow::anyhow!("source name disappeared"))?;
        let before = source.metadata()?;
        anyhow::ensure!(
            before.is_file()
                && before.nlink() == 1
                && before.ino() == source_id.inode
                && source_id.filesystem_id == source_parent_id.filesystem_id
                && expected.is_none_or(|version| {
                    *version == capture_version(source_id.filesystem_id, &before)
                }),
            "capture requires one pinned, unaliased source file"
        );
        let guard = FileWriteExclusion::acquire(source)?;
        let access = FileAccessSnapshot::capture(&guard.file)?;
        let proof = IndependentSparseCopy {
            logical_len: before.len(),
            content_hash: hash_exact(&guard.file, before.len())?,
            data_extents: file_data_extents(&guard.file, before.len())?,
        };
        let after = guard.file.metadata()?;
        anyhow::ensure!(
            same_source_metadata(&before, &after)
                && guard.is_held()?
                && source_parent.entry_identity(source_name, false)? == Some(source_id)
                && anchor_parent.entry_identity(anchor_name, false)?.is_none(),
            "source changed during guarded capture planning"
        );
        let intent = Self {
            format_version: 2,
            anchor_id,
            source_parent_id,
            anchor_parent_id,
            source_id,
            source_name: source_name.to_path_buf(),
            anchor_name: anchor_name.to_path_buf(),
            proof: FrozenAnchorProof {
                original_access: access,
                content: proof,
            },
            phase: LinkFreezeCapturePhase::Prepared,
            private_inode: None,
        };
        anyhow::ensure!(
            control.put_record_if_absent(
                CAPTURE_INTENT_KIND,
                anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&intent)?,
            )?,
            "a different frozen capture already owns this anchor"
        );
        guard.release()?;
        Ok(intent)
    }

    pub fn load(control: &ControlStore, anchor_id: Uuid) -> anyhow::Result<Option<Self>> {
        let Some(bytes) = control.get_record(CAPTURE_INTENT_KIND, anchor_id.as_bytes())? else {
            return Ok(None);
        };
        let intent: Self = match mb_core::decode_canonical::<Self>(&bytes) {
            Ok(intent) if intent.format_version == 2 => intent,
            _ => {
                let legacy: LegacyCaptureIntentV1 = mb_core::decode_canonical(&bytes)?;
                anyhow::ensure!(
                    legacy.format_version == 1
                        && legacy.anchor_id == anchor_id
                        && legacy.phase != LinkFreezeCapturePhase::Detached,
                    "unknown frozen capture intent format"
                );
                let migrated = Self {
                    format_version: 2,
                    anchor_id: legacy.anchor_id,
                    source_parent_id: legacy.source_parent_id,
                    anchor_parent_id: legacy.anchor_parent_id,
                    source_id: legacy.source_id,
                    source_name: legacy.source_name,
                    anchor_name: legacy.anchor_name,
                    proof: legacy.proof,
                    phase: legacy.phase,
                    private_inode: None,
                };
                control.replace_record_if_value(
                    CAPTURE_INTENT_KIND,
                    anchor_id.as_bytes(),
                    &bytes,
                    &mb_core::canonical_bytes(&migrated)?,
                )?;
                migrated
            }
        };
        anyhow::ensure!(
            intent.format_version == 2
                && intent.anchor_id == anchor_id
                && intent.source_id.filesystem_id == intent.source_parent_id.filesystem_id
                && intent.source_id.filesystem_id == intent.anchor_parent_id.filesystem_id
                && intent.proof.original_access.format_version == 1
                && intent.proof.content.data_extents.len() <= 65_536
                && match intent.phase {
                    LinkFreezeCapturePhase::Prepared | LinkFreezeCapturePhase::Frozen =>
                        intent.private_inode.is_none(),
                    LinkFreezeCapturePhase::Detached => intent.private_inode.is_some(),
                },
            "invalid frozen capture intent"
        );
        Ok(Some(intent))
    }

    pub fn phase(&self) -> LinkFreezeCapturePhase {
        self.phase
    }

    pub(crate) fn retirement_pending(
        control: &ControlStore,
        anchor_id: Uuid,
    ) -> anyhow::Result<bool> {
        Ok(RetireIntent::load(control, anchor_id)?.is_some())
    }

    pub(crate) fn retirement_ready_for_cleanup(
        control: &ControlStore,
        anchor_id: Uuid,
    ) -> anyhow::Result<bool> {
        Ok(RetireIntent::load(control, anchor_id)?
            .is_none_or(|intent| intent.phase == RetirePhase::AccessRestored))
    }

    pub(crate) fn finish_completed_retirement(
        control: &ControlStore,
        anchor_id: Uuid,
    ) -> anyhow::Result<bool> {
        let Some(intent) = RetireIntent::load(control, anchor_id)? else {
            return Ok(false);
        };
        anyhow::ensure!(
            intent.phase == RetirePhase::AccessRestored
                && control
                    .get_record(CAPTURE_INTENT_KIND, anchor_id.as_bytes())?
                    .is_none(),
            "frozen-anchor retirement still needs source or anchor recovery"
        );
        control.delete_record_if_value(
            RETIRE_INTENT_KIND,
            anchor_id.as_bytes(),
            &mb_core::canonical_bytes(&intent)?,
        )?;
        Ok(true)
    }

    /// Retire an unreferenced capture without leaving a shared source inode
    /// frozen. The caller must first prove that no protected graph or pending
    /// capture still pins this anchor. A separate durable marker covers the
    /// unlink/access-restore gap across crashes.
    pub(crate) fn retire_unreferenced(
        self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            matches!(
                self.phase,
                LinkFreezeCapturePhase::Frozen | LinkFreezeCapturePhase::Detached
            ) && LinkFreezeEditIntent::load(control, self.anchor_id)?.is_none()
                && anchor_parent.identity()? == self.anchor_parent_id,
            "capture cannot retire during a pending freeze or edit"
        );
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?),
            "capture changed before retirement"
        );
        let mut retire = match RetireIntent::load(control, self.anchor_id)? {
            Some(existing) => {
                anyhow::ensure!(existing.capture == self, "retirement changed capture proof");
                existing
            }
            None => {
                let intent = RetireIntent {
                    format_version: 1,
                    capture: self.clone(),
                    phase: RetirePhase::Planned,
                };
                anyhow::ensure!(control.put_record_if_absent(
                    RETIRE_INTENT_KIND,
                    self.anchor_id.as_bytes(),
                    &mb_core::canonical_bytes(&intent)?,
                )?);
                intent
            }
        };
        if retire.phase == RetirePhase::Planned {
            if self.phase == LinkFreezeCapturePhase::Detached {
                if let Some(private_id) = anchor_parent.entry_identity(&self.anchor_name, false)? {
                    self.check_private_anchor(anchor_parent, self.private_inode.unwrap())?;
                    anchor_parent.remove_child_file_if_identity(&self.anchor_name, private_id)?;
                }
                retire.advance(control, RetirePhase::AccessRestored)?;
            } else {
                let source_entry = if source_parent.identity()? == self.source_parent_id {
                    source_parent.entry_identity(&self.source_name, false)?
                } else {
                    None
                };
                let anchor_entry = anchor_parent.entry_identity(&self.anchor_name, false)?;
                match (source_entry, anchor_entry) {
                    (Some(source_id), Some(anchor_id))
                        if source_id == self.source_id && anchor_id == self.source_id =>
                    {
                        let source = source_parent
                            .open_child_file(&self.source_name)?
                            .ok_or_else(|| anyhow::anyhow!("frozen source disappeared"))?;
                        let guard = FileWriteExclusion::acquire(source)?;
                        anyhow::ensure!(
                            guard.file.metadata()?.nlink() == 2
                                && FileAccessSnapshot::capture(&guard.file)?.mode & 0o222 == 0
                                && self.content_matches(&guard.file)?
                                && guard.is_held()?,
                            "shared anchor changed before retirement"
                        );
                        anchor_parent
                            .remove_child_file_if_identity(&self.anchor_name, self.source_id)?;
                        anyhow::ensure!(guard.file.metadata()?.nlink() == 1 && guard.is_held()?);
                        retire.advance(control, RetirePhase::AnchorRemoved)?;
                        guard.release()?;
                    }
                    (Some(source_id), None) if source_id == self.source_id => {
                        anyhow::ensure!(
                            source_parent
                                .open_child_file(&self.source_name)?
                                .ok_or_else(|| anyhow::anyhow!("retiring source disappeared"))?
                                .metadata()?
                                .nlink()
                                == 1,
                            "retiring source kept another hard-link alias"
                        );
                        retire.advance(control, RetirePhase::AnchorRemoved)?;
                    }
                    (None, Some(anchor_id)) if anchor_id == self.source_id => {
                        let anchor = anchor_parent
                            .open_child_file(&self.anchor_name)?
                            .ok_or_else(|| anyhow::anyhow!("frozen anchor disappeared"))?;
                        let guard = FileWriteExclusion::acquire(anchor)?;
                        anyhow::ensure!(
                            guard.file.metadata()?.nlink() == 1
                                && FileAccessSnapshot::capture(&guard.file)?.mode & 0o222 == 0
                                && self.content_matches(&guard.file)?
                                && guard.is_held()?,
                            "unlinked source left an unverified anchor"
                        );
                        retire.advance(control, RetirePhase::NoSource)?;
                        guard.release()?;
                    }
                    _ => anyhow::bail!("retiring anchor has an unknown source or alias"),
                }
            }
        }
        if retire.phase == RetirePhase::NoSource {
            if let Some(anchor_id) = anchor_parent.entry_identity(&self.anchor_name, false)? {
                anyhow::ensure!(anchor_id == self.source_id);
                let anchor = anchor_parent
                    .open_child_file(&self.anchor_name)?
                    .ok_or_else(|| anyhow::anyhow!("retiring anchor disappeared"))?;
                let guard = FileWriteExclusion::acquire(anchor)?;
                anyhow::ensure!(
                    guard.file.metadata()?.nlink() == 1
                        && self.content_matches(&guard.file)?
                        && guard.is_held()?,
                    "unlinked retiring anchor changed"
                );
                anchor_parent.remove_child_file_if_identity(&self.anchor_name, self.source_id)?;
                guard.release()?;
            }
            retire.advance(control, RetirePhase::AccessRestored)?;
        }
        if retire.phase == RetirePhase::AnchorRemoved {
            anyhow::ensure!(
                source_parent.identity()? == self.source_parent_id
                    && source_parent.entry_identity(&self.source_name, false)?
                        == Some(self.source_id)
                    && anchor_parent
                        .entry_identity(&self.anchor_name, false)?
                        .is_none(),
                "retiring source moved before access restoration"
            );
            let source = source_parent
                .open_child_file(&self.source_name)?
                .ok_or_else(|| anyhow::anyhow!("retiring source disappeared"))?;
            self.proof
                .original_access
                .restore_unshared_after_abandon(&source)?;
            retire.advance(control, RetirePhase::AccessRestored)?;
        }
        anyhow::ensure!(retire.phase == RetirePhase::AccessRestored);
        control.delete_record_if_value(
            CAPTURE_INTENT_KIND,
            self.anchor_id.as_bytes(),
            &mb_core::canonical_bytes(&self)?,
        )?;
        Ok(())
    }

    pub(crate) fn matches_file_plan(
        &self,
        anchor_id: Uuid,
        source_id: NativeFileId,
        anchor_parent: &PinnedDirectory,
        anchor_name: &Path,
    ) -> anyhow::Result<bool> {
        Ok(self.anchor_id == anchor_id
            && self.source_id == source_id
            && self.anchor_parent_id == anchor_parent.identity()?
            && self.anchor_name == anchor_name)
    }

    pub(crate) fn matches_root_file_plan(
        &self,
        anchor_id: Uuid,
        source_parent_id: NativeFileId,
        source_id: NativeFileId,
        anchor_parent: &PinnedDirectory,
        anchor_name: &Path,
    ) -> anyhow::Result<bool> {
        Ok(self.source_parent_id == source_parent_id
            && self.source_name == anchor_name
            && self.matches_file_plan(anchor_id, source_id, anchor_parent, anchor_name)?)
    }

    pub(crate) fn content_proof(&self) -> &IndependentSparseCopy {
        &self.proof.content
    }

    pub fn frozen_proof(&self) -> Option<&FrozenAnchorProof> {
        (self.phase == LinkFreezeCapturePhase::Frozen).then_some(&self.proof)
    }

    /// Start editing only from the exact committed frozen capture record.
    /// Verify its pinned anchor before using the durable proof for the edit.
    pub fn begin_edit(
        self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<LinkFreezeEditIntent> {
        let source_name = self.source_name.clone();
        self.begin_edit_at(control, source_parent, source_name, anchor_parent)
    }

    /// A frozen source may have been renamed before its first edit. Bind the
    /// edit replay to its current pinned name before recording the edit intent.
    /// The anchor's inode and bytes, rather than the old pathname, supply the
    /// immutable capture proof.
    pub fn begin_edit_at(
        self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<LinkFreezeEditIntent> {
        let source_name = source_name.as_ref();
        let rebound =
            self.rebind_frozen_source(control, source_parent, source_name, anchor_parent)?;
        LinkFreezeEditIntent::begin(
            control,
            rebound.anchor_id,
            source_parent,
            source_name,
            anchor_parent,
            &rebound.anchor_name,
            rebound.proof,
        )
    }

    /// Move the journal's source-name hint after a verified rename. The old
    /// pathname may now be absent or hold an unrelated replacement; the
    /// current pinned name must still be the sole link besides the anchor.
    pub fn rebind_frozen_source(
        self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeCapturePhase::Frozen);
        anyhow::ensure!(LinkFreezeEditIntent::load(control, self.anchor_id)?.is_none());
        let source_name = source_name.as_ref();
        anyhow::ensure!(
            source_parent.entry_identity(source_name, false)? == Some(self.source_id),
            "current source name does not match the frozen capture"
        );
        self.verify_frozen_anchor(control, anchor_parent, Some((source_parent, source_name)))?;
        self.replace_source_name(control, source_parent, source_name)
    }

    /// An edit can be interrupted after the source moves. Rebind only when
    /// the proposed name still owns the original inode and the anchor/staging
    /// layout matches the edit's durable phase. No access is restored here.
    pub fn rebind_pending_edit(
        self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        source_name: impl AsRef<Path>,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeCapturePhase::Frozen);
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?),
            "frozen capture changed before edit source rebinding"
        );
        let edit = LinkFreezeEditIntent::load(control, self.anchor_id)?
            .ok_or_else(|| anyhow::anyhow!("frozen capture has no pending edit"))?;
        anyhow::ensure!(
            self.matches_edit(&edit) && edit.phase() != LinkFreezeEditPhase::Editable,
            "pending edit does not match the frozen capture"
        );
        let source_name = source_name.as_ref();
        anyhow::ensure!(
            source_parent.entry_identity(source_name, false)? == Some(self.source_id)
                && anchor_parent.identity()? == self.anchor_parent_id,
            "current edit source or anchor directory changed"
        );
        let source = source_parent
            .open_child_file(source_name)?
            .ok_or_else(|| anyhow::anyhow!("current edit source disappeared"))?;
        let anchor_entry = anchor_parent.entry_identity(&self.anchor_name, false)?;
        match edit.phase() {
            LinkFreezeEditPhase::SharedFrozen | LinkFreezeEditPhase::CopyStaging => {
                self.verify_frozen_anchor(
                    control,
                    anchor_parent,
                    Some((source_parent, source_name)),
                )?;
            }
            LinkFreezeEditPhase::PrivateCopyReady => {
                anyhow::ensure!(edit.copy.as_ref() == Some(&self.proof.content));
                let private_inode = edit.private_inode.unwrap();
                if anchor_entry == Some(self.source_id) {
                    self.verify_frozen_anchor(
                        control,
                        anchor_parent,
                        Some((source_parent, source_name)),
                    )?;
                    let staged_id = anchor_parent
                        .entry_identity(&edit.staging_name, false)?
                        .ok_or_else(|| anyhow::anyhow!("private staging name disappeared"))?;
                    let staged = anchor_parent
                        .open_child_file(&edit.staging_name)?
                        .ok_or_else(|| anyhow::anyhow!("private staging name disappeared"))?;
                    let metadata = staged.metadata()?;
                    anyhow::ensure!(
                        staged_id.filesystem_id == self.source_id.filesystem_id
                            && staged_id.inode == private_inode
                            && metadata.is_file()
                            && metadata.ino() == private_inode
                            && metadata.nlink() == 1
                            && metadata.len() == self.proof.content.logical_len
                            && FileAccessSnapshot::capture(&staged)?.mode & 0o222 == 0
                            && self.content_matches(&staged)?,
                        "private staging copy changed before source rebinding"
                    );
                } else {
                    self.check_private_anchor(anchor_parent, private_inode)?;
                    let staged_id = anchor_parent.entry_identity(&edit.staging_name, false)?;
                    anyhow::ensure!(
                        staged_id.is_none() || staged_id == Some(self.source_id),
                        "unexpected staging alias blocks source rebinding"
                    );
                    let guard = FileWriteExclusion::acquire(source)?;
                    anyhow::ensure!(
                        guard.file.metadata()?.nlink() == if staged_id.is_some() { 2 } else { 1 }
                            && FileAccessSnapshot::capture(&guard.file)?.mode & 0o222 == 0
                            && self.content_matches(&guard.file)?
                            && guard.is_held()?
                            && source_parent.entry_identity(source_name, false)?
                                == Some(self.source_id),
                        "frozen source changed after anchor detachment"
                    );
                    guard.release()?;
                }
            }
            LinkFreezeEditPhase::UnlockPending => {
                anyhow::ensure!(edit.copy.as_ref() == Some(&self.proof.content));
                self.check_private_anchor(anchor_parent, edit.private_inode.unwrap())?;
                anyhow::ensure!(
                    anchor_parent
                        .entry_identity(&edit.staging_name, false)?
                        .is_none()
                        && source.metadata()?.nlink() == 1
                        && source_parent.entry_identity(source_name, false)?
                            == Some(self.source_id),
                    "detached source has an unexpected hard-link alias"
                );
            }
            LinkFreezeEditPhase::Editable => unreachable!(),
        }
        anyhow::ensure!(
            LinkFreezeEditIntent::load(control, self.anchor_id)? == Some(edit),
            "pending edit changed during source rebinding"
        );
        self.replace_source_name(control, source_parent, source_name)
    }

    fn replace_source_name(
        mut self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        source_name: &Path,
    ) -> anyhow::Result<Self> {
        let source_parent_id = source_parent.identity()?;
        if self.source_parent_id != source_parent_id || self.source_name != source_name {
            let before = mb_core::canonical_bytes(&self)?;
            self.source_parent_id = source_parent_id;
            self.source_name = source_name.to_path_buf();
            control.replace_record_if_value(
                CAPTURE_INTENT_KIND,
                self.anchor_id.as_bytes(),
                &before,
                &mb_core::canonical_bytes(&self)?,
            )?;
        }
        Ok(self)
    }

    /// Reconcile a prepared freeze or verify a completed one. Changed source
    /// bytes abandon an uncommitted attempt after removing only its known link
    /// and restoring access metadata on the now-unshared source. A collision
    /// or unknown alias fails closed without touching the source permissions.
    pub fn resume(
        mut self,
        control: &ControlStore,
        source_parent: &PinnedDirectory,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<Option<Self>> {
        anyhow::ensure!(
            !Self::retirement_pending(control, self.anchor_id)?,
            "frozen anchor is being retired"
        );
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?),
            "frozen capture intent changed before replay"
        );
        if self.phase == LinkFreezeCapturePhase::Detached {
            return self
                .verify_detached_anchor(control, anchor_parent)
                .map(Some);
        }
        let edit = LinkFreezeEditIntent::load(control, self.anchor_id)?;
        if let Some(ref edit) = edit {
            anyhow::ensure!(
                self.phase == LinkFreezeCapturePhase::Frozen && self.matches_edit(edit),
                "edit intent does not belong to the frozen capture"
            );
            if edit.phase() == LinkFreezeEditPhase::Editable {
                return self.finish_detached_edit(control, anchor_parent).map(Some);
            }
        }
        if self.phase == LinkFreezeCapturePhase::Frozen && edit.is_none() {
            let original_link = if source_parent.identity()? == self.source_parent_id
                && source_parent.entry_identity(&self.source_name, false)? == Some(self.source_id)
            {
                Some((source_parent, self.source_name.as_path()))
            } else {
                None
            };
            self.verify_frozen_anchor(control, anchor_parent, original_link)?;
            return Ok(Some(self));
        }
        anyhow::ensure!(
            source_parent.identity()? == self.source_parent_id
                && anchor_parent.identity()? == self.anchor_parent_id,
            "frozen capture directory identity changed"
        );
        if let Some(edit) = edit {
            let editable = edit.resume(
                control,
                source_parent,
                &self.source_name,
                anchor_parent,
                &self.anchor_name,
            )?;
            self = self.mark_detached(control, anchor_parent, &editable)?;
            editable.retire(control)?;
            return Ok(Some(self));
        }
        let source = source_parent
            .open_child_file(&self.source_name)?
            .ok_or_else(|| anyhow::anyhow!("frozen source name disappeared"))?;
        anyhow::ensure!(
            source_parent.entry_identity(&self.source_name, false)? == Some(self.source_id)
                && source.metadata()?.ino() == self.source_id.inode,
            "frozen source inode changed"
        );
        let guard = FileWriteExclusion::acquire(source)?;
        let source_metadata = guard.file.metadata()?;
        let anchor_entry = anchor_parent.entry_identity(&self.anchor_name, false)?;
        anyhow::ensure!(
            (anchor_entry.is_none() || anchor_entry == Some(self.source_id))
                && source_metadata.nlink() == if anchor_entry.is_some() { 2 } else { 1 },
            "unknown hard-link alias or anchor-name collision"
        );
        let content_matches = source_metadata.len() == self.proof.content.logical_len
            && hash_exact(&guard.file, source_metadata.len())? == self.proof.content.content_hash
            && file_data_extents(&guard.file, source_metadata.len())?
                == self.proof.content.data_extents;
        if !content_matches {
            if anchor_entry == Some(self.source_id) {
                anchor_parent.remove_child_file_if_identity(&self.anchor_name, self.source_id)?;
            }
            anyhow::ensure!(
                guard.file.metadata()?.nlink() == 1 && guard.is_held()?,
                "changed capture source kept another hard-link alias"
            );
            self.check_access_transition(&guard.file)?;
            let source_after = guard.file.try_clone()?;
            guard.release()?;
            self.proof
                .original_access
                .restore_unshared_after_abandon(&source_after)?;
            control.delete_record_if_value(
                CAPTURE_INTENT_KIND,
                self.anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&self)?,
            )?;
            return Ok(None);
        }
        if anchor_entry.is_none() {
            self.check_access_transition(&guard.file)?;
            source_parent.hard_link_child_from(
                &self.source_name,
                anchor_parent,
                &self.anchor_name,
            )?;
            anchor_parent.sync_all()?;
        }
        anyhow::ensure!(
            anchor_parent.entry_identity(&self.anchor_name, false)? == Some(self.source_id)
                && guard.file.metadata()?.nlink() == 2
                && guard.is_held()?,
            "guarded hard link was not durably installed"
        );
        self.check_access_transition(&guard.file)?;
        guard.file.set_permissions(std::fs::Permissions::from_mode(
            self.proof.original_access.mode & !0o222,
        ))?;
        guard.file.sync_all()?;
        anchor_parent.sync_all()?;
        anyhow::ensure!(
            FileAccessSnapshot::capture(&guard.file)?.mode & 0o222 == 0
                && self.content_matches(&guard.file)?
                && guard.is_held()?,
            "guarded freeze did not preserve its source proof"
        );
        let before = mb_core::canonical_bytes(&self)?;
        self.phase = LinkFreezeCapturePhase::Frozen;
        control.replace_record_if_value(
            CAPTURE_INTENT_KIND,
            self.anchor_id.as_bytes(),
            &before,
            &mb_core::canonical_bytes(&self)?,
        )?;
        guard.release()?;
        Ok(Some(self))
    }

    fn verify_frozen_anchor(
        &self,
        control: &ControlStore,
        anchor_parent: &PinnedDirectory,
        known_source_link: Option<(&PinnedDirectory, &Path)>,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(
            !Self::retirement_pending(control, self.anchor_id)?,
            "frozen anchor is being retired"
        );
        anyhow::ensure!(self.phase == LinkFreezeCapturePhase::Frozen);
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(self)?)
                && anchor_parent.identity()? == self.anchor_parent_id,
            "frozen capture record or anchor directory changed"
        );
        anyhow::ensure!(
            anchor_parent.entry_identity(&self.anchor_name, false)? == Some(self.source_id),
            "frozen anchor inode changed"
        );
        let anchor = anchor_parent
            .open_child_file(&self.anchor_name)?
            .ok_or_else(|| anyhow::anyhow!("frozen anchor name disappeared"))?;
        let guard = FileWriteExclusion::acquire(anchor)?;
        let metadata = guard.file.metadata()?;
        let source_link_matches = match known_source_link {
            Some((parent, name)) => parent.entry_identity(name, false)? == Some(self.source_id),
            None => true,
        };
        anyhow::ensure!(
            metadata.is_file()
                && metadata.ino() == self.source_id.inode
                && metadata.nlink() == if known_source_link.is_some() { 2 } else { 1 }
                && source_link_matches
                && FileAccessSnapshot::capture(&guard.file)?.mode & 0o222 == 0
                && self.content_matches(&guard.file)?
                && guard.is_held()?
                && anchor_parent.entry_identity(&self.anchor_name, false)? == Some(self.source_id),
            "committed frozen anchor no longer matches its durable proof"
        );
        guard.release()?;
        Ok(())
    }

    /// Finish an edit that reached durable `Editable` even if the former
    /// working file was removed before the capture record advanced.
    pub fn finish_detached_edit(
        self,
        control: &ControlStore,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeCapturePhase::Frozen);
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?),
            "frozen capture record changed before edit completion"
        );
        let edit = LinkFreezeEditIntent::load(control, self.anchor_id)?
            .ok_or_else(|| anyhow::anyhow!("editable journal disappeared"))?;
        anyhow::ensure!(
            self.matches_edit(&edit) && edit.phase() == LinkFreezeEditPhase::Editable,
            "edit journal is not ready to detach its capture"
        );
        let detached = self.mark_detached(control, anchor_parent, &edit)?;
        edit.retire(control)?;
        Ok(detached)
    }

    /// A detached anchor remains verifiable even if its former working tree
    /// was edited or removed. A crash after the capture phase advanced but
    /// before the edit intent retired is also resolved here.
    pub fn verify_detached_anchor(
        self,
        control: &ControlStore,
        anchor_parent: &PinnedDirectory,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(self.phase == LinkFreezeCapturePhase::Detached);
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?)
                && anchor_parent.identity()? == self.anchor_parent_id,
            "detached capture record or anchor directory changed"
        );
        self.check_private_anchor(anchor_parent, self.private_inode.unwrap())?;
        if let Some(edit) = LinkFreezeEditIntent::load(control, self.anchor_id)? {
            anyhow::ensure!(
                self.matches_edit(&edit)
                    && edit.phase() == LinkFreezeEditPhase::Editable
                    && edit.private_inode() == self.private_inode,
                "pending edit disagrees with the detached capture"
            );
            edit.retire(control)?;
        }
        Ok(self)
    }

    fn mark_detached(
        mut self,
        control: &ControlStore,
        anchor_parent: &PinnedDirectory,
        edit: &LinkFreezeEditIntent,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            self.phase == LinkFreezeCapturePhase::Frozen
                && edit.phase() == LinkFreezeEditPhase::Editable
                && self.matches_edit(edit)
        );
        let private_inode = edit
            .private_inode()
            .ok_or_else(|| anyhow::anyhow!("editable anchor has no private inode"))?;
        self.check_private_anchor(anchor_parent, private_inode)?;
        let before = mb_core::canonical_bytes(&self)?;
        self.phase = LinkFreezeCapturePhase::Detached;
        self.private_inode = Some(private_inode);
        control.replace_record_if_value(
            CAPTURE_INTENT_KIND,
            self.anchor_id.as_bytes(),
            &before,
            &mb_core::canonical_bytes(&self)?,
        )?;
        Ok(self)
    }

    fn check_private_anchor(
        &self,
        anchor_parent: &PinnedDirectory,
        private_inode: u64,
    ) -> anyhow::Result<()> {
        anyhow::ensure!(anchor_parent.identity()? == self.anchor_parent_id);
        let anchor_id = anchor_parent
            .entry_identity(&self.anchor_name, false)?
            .ok_or_else(|| anyhow::anyhow!("detached anchor name disappeared"))?;
        anyhow::ensure!(
            anchor_id.filesystem_id == self.source_id.filesystem_id
                && anchor_id.inode == private_inode
                && anchor_id.inode != self.source_id.inode,
            "detached anchor inode changed"
        );
        let anchor = anchor_parent
            .open_child_file(&self.anchor_name)?
            .ok_or_else(|| anyhow::anyhow!("detached anchor name disappeared"))?;
        let metadata = anchor.metadata()?;
        anyhow::ensure!(
            metadata.is_file()
                && metadata.ino() == private_inode
                && metadata.nlink() == 1
                && metadata.len() == self.proof.content.logical_len
                && FileAccessSnapshot::capture(&anchor)?.mode & 0o222 == 0
                && hash_exact(&anchor, metadata.len())? == self.proof.content.content_hash
                && file_data_extents(&anchor, metadata.len())? == self.proof.content.data_extents,
            "detached anchor no longer matches its capture proof"
        );
        Ok(())
    }

    fn matches_edit(&self, edit: &LinkFreezeEditIntent) -> bool {
        edit.anchor_id == self.anchor_id
            && edit.source_id == self.source_id
            && edit.original_access == self.proof.original_access
            && edit.frozen_content == self.proof.content
    }

    fn content_matches(&self, source: &File) -> anyhow::Result<bool> {
        let metadata = source.metadata()?;
        Ok(metadata.len() == self.proof.content.logical_len
            && hash_exact(source, metadata.len())? == self.proof.content.content_hash
            && file_data_extents(source, metadata.len())? == self.proof.content.data_extents)
    }

    fn check_access_transition(&self, source: &File) -> anyhow::Result<()> {
        let current = FileAccessSnapshot::capture(source)?;
        let frozen_mode = self.proof.original_access.mode & !0o222;
        anyhow::ensure!(
            current == self.proof.original_access
                || (current.mode == frozen_mode && self.proof.original_access.mode != frozen_mode),
            "source access metadata changed outside the guarded freeze"
        );
        Ok(())
    }
}

fn same_source_metadata(left: &std::fs::Metadata, right: &std::fs::Metadata) -> bool {
    (
        left.dev(),
        left.ino(),
        left.nlink(),
        left.mode(),
        left.len(),
        left.mtime(),
        left.mtime_nsec(),
        left.ctime(),
        left.ctime_nsec(),
    ) == (
        right.dev(),
        right.ino(),
        right.nlink(),
        right.mode(),
        right.len(),
        right.mtime(),
        right.mtime_nsec(),
        right.ctime(),
        right.ctime_nsec(),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, OpenOptions};
    use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};

    use mb_core::{KeyMaterial, Seed};

    use super::{
        CAPTURE_INTENT_KIND, LegacyCaptureIntentV1, LinkFreezeCaptureIntent,
        LinkFreezeCapturePhase, RETIRE_INTENT_KIND, RetireIntent, RetirePhase,
    };
    use crate::anchor::{NativeFileId, PinnedDirectory};
    use crate::link_freeze::{
        AccessAclSnapshot, FileAccessSnapshot, FileWriteExclusion, FrozenAnchorProof,
        IndependentSparseCopy, install_probe_acl,
    };

    #[test]
    fn version_one_frozen_capture_intent_migrates_before_replay() {
        let root = test_directory();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([95; 32]));
        let store =
            crate::database::ControlStore::open(root.path().join("control.db"), &keys).unwrap();
        let anchor_id = uuid::Uuid::new_v4();
        let legacy = LegacyCaptureIntentV1 {
            format_version: 1,
            anchor_id,
            source_parent_id: NativeFileId {
                filesystem_id: 7,
                inode: 11,
            },
            anchor_parent_id: NativeFileId {
                filesystem_id: 7,
                inode: 12,
            },
            source_id: NativeFileId {
                filesystem_id: 7,
                inode: 13,
            },
            source_name: "source".into(),
            anchor_name: "anchor".into(),
            proof: FrozenAnchorProof {
                original_access: FileAccessSnapshot {
                    format_version: 1,
                    mode: 0o644,
                    access_acl: AccessAclSnapshot::Absent,
                },
                content: IndependentSparseCopy {
                    logical_len: 0,
                    content_hash: [0; 32],
                    data_extents: Vec::new(),
                },
            },
            phase: LinkFreezeCapturePhase::Frozen,
        };
        let old = mb_core::canonical_bytes(&legacy).unwrap();
        store
            .put_record(CAPTURE_INTENT_KIND, anchor_id.as_bytes(), &old)
            .unwrap();
        let migrated = LinkFreezeCaptureIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap();
        assert_eq!(migrated.format_version, 2);
        assert_eq!(migrated.phase(), LinkFreezeCapturePhase::Frozen);
        assert_eq!(migrated.private_inode, None);
        assert_eq!(
            store
                .get_record(CAPTURE_INTENT_KIND, anchor_id.as_bytes())
                .unwrap(),
            Some(mb_core::canonical_bytes(&migrated).unwrap())
        );
        let retired = RetireIntent {
            format_version: 1,
            capture: migrated.clone(),
            phase: RetirePhase::AccessRestored,
        };
        store
            .put_record_if_absent(
                RETIRE_INTENT_KIND,
                anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&retired).unwrap(),
            )
            .unwrap();
        assert!(LinkFreezeCaptureIntent::finish_completed_retirement(&store, anchor_id).is_err());
        store
            .delete_record_if_value(
                CAPTURE_INTENT_KIND,
                anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&migrated).unwrap(),
            )
            .unwrap();
        assert!(LinkFreezeCaptureIntent::finish_completed_retirement(&store, anchor_id).unwrap());
        assert!(!LinkFreezeCaptureIntent::retirement_pending(&store, anchor_id).unwrap());
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn capture_replay_closes_every_initial_freeze_interruption() {
        for interruption in 0..=8 {
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
            source.write_at(b"original", 4096).unwrap();
            source
                .set_permissions(fs::Permissions::from_mode(0o660))
                .unwrap();
            let _ = install_probe_acl(&source).unwrap();
            source.sync_all().unwrap();
            drop(source);
            let parent = PinnedDirectory::open(root.path()).unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([93; 32]));
            let database_path = root.path().join("control.db");
            let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
            let anchor_id = uuid::Uuid::new_v4();
            let prepared = LinkFreezeCaptureIntent::begin(
                &store, anchor_id, &parent, "source", &parent, "anchor",
            )
            .unwrap();
            assert_eq!(prepared.phase(), LinkFreezeCapturePhase::Prepared);
            if matches!(interruption, 1 | 2 | 4 | 5 | 6) {
                parent
                    .hard_link_child_from("source", &parent, "anchor")
                    .unwrap();
                parent.sync_all().unwrap();
            }
            if matches!(interruption, 2 | 5) {
                let source = File::open(&source_path).unwrap();
                let guard = FileWriteExclusion::acquire(source).unwrap();
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o440)).unwrap();
                guard.file.sync_all().unwrap();
                guard.release().unwrap();
            }
            if matches!(interruption, 3 | 4) {
                fs::write(&source_path, b"changed-before-freeze").unwrap();
            }
            if interruption == 5 {
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o660)).unwrap();
                fs::write(&source_path, b"changed-after-chmod").unwrap();
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o440)).unwrap();
            }
            if interruption == 6 {
                fs::hard_link(&source_path, root.path().join("unknown-alias")).unwrap();
            }
            if interruption == 7 {
                fs::write(&anchor_path, b"collision").unwrap();
            }
            drop(store);
            let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
            let prepared = LinkFreezeCaptureIntent::load(&store, anchor_id)
                .unwrap()
                .unwrap();
            let original_access = prepared.proof.original_access.clone();
            let outcome = prepared.resume(&store, &parent, &parent);
            if matches!(interruption, 6 | 7) {
                assert!(outcome.is_err(), "case {interruption} must fail closed");
                assert_eq!(
                    LinkFreezeCaptureIntent::load(&store, anchor_id)
                        .unwrap()
                        .unwrap()
                        .phase(),
                    LinkFreezeCapturePhase::Prepared
                );
                assert_eq!(
                    FileAccessSnapshot::capture(&File::open(&source_path).unwrap())
                        .unwrap()
                        .mode
                        & 0o222,
                    0o220
                );
                continue;
            }
            if matches!(interruption, 3..=5) {
                assert!(outcome.unwrap().is_none());
                assert!(
                    LinkFreezeCaptureIntent::load(&store, anchor_id)
                        .unwrap()
                        .is_none()
                );
                assert!(!anchor_path.exists());
                assert!(fs::read(&source_path).unwrap().starts_with(b"changed"));
                assert_eq!(
                    FileAccessSnapshot::capture(&File::open(&source_path).unwrap()).unwrap(),
                    original_access
                );
                continue;
            }
            let frozen = outcome.unwrap().unwrap();
            assert_eq!(frozen.phase(), LinkFreezeCapturePhase::Frozen);
            assert_eq!(
                frozen.frozen_proof().unwrap().content.logical_len,
                1024 * 1024
            );
            assert_eq!(
                fs::metadata(&source_path).unwrap().ino(),
                fs::metadata(&anchor_path).unwrap().ino()
            );
            assert_eq!(fs::metadata(&source_path).unwrap().nlink(), 2);
            assert_eq!(
                FileAccessSnapshot::capture(&File::open(&source_path).unwrap())
                    .unwrap()
                    .mode
                    & 0o222,
                0
            );
            assert_eq!(fs::read(&anchor_path).unwrap()[4096..4104], *b"original");
            assert!(
                LinkFreezeCaptureIntent::load(&store, anchor_id)
                    .unwrap()
                    .unwrap()
                    .resume(&store, &parent, &parent)
                    .unwrap()
                    .is_some()
            );
            if interruption == 8 {
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o660)).unwrap();
                fs::write(&source_path, b"corrupt-after-commit").unwrap();
                fs::set_permissions(&source_path, fs::Permissions::from_mode(0o440)).unwrap();
                assert!(
                    LinkFreezeCaptureIntent::load(&store, anchor_id)
                        .unwrap()
                        .unwrap()
                        .resume(&store, &parent, &parent)
                        .is_err()
                );
            }
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn capture_edit_handoff_survives_each_journal_boundary() {
        for interruption in 0..=3 {
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
            source.write_at(b"anchored", 4096).unwrap();
            source.sync_all().unwrap();
            drop(source);
            let original_inode = fs::metadata(&source_path).unwrap().ino();
            let parent = PinnedDirectory::open(root.path()).unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([94; 32]));
            let database_path = root.path().join("control.db");
            let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
            let anchor_id = uuid::Uuid::new_v4();
            let frozen = LinkFreezeCaptureIntent::begin(
                &store, anchor_id, &parent, "source", &parent, "anchor",
            )
            .unwrap()
            .resume(&store, &parent, &parent)
            .unwrap()
            .unwrap();
            let mut edit = frozen.clone().begin_edit(&store, &parent, &parent).unwrap();
            if interruption >= 1 {
                edit = edit
                    .resume(&store, &parent, "source", &parent, "anchor")
                    .unwrap();
                assert_eq!(
                    edit.phase(),
                    crate::link_freeze::LinkFreezeEditPhase::Editable
                );
            }
            if interruption == 2 {
                let detached = frozen.mark_detached(&store, &parent, &edit).unwrap();
                assert_eq!(detached.phase(), LinkFreezeCapturePhase::Detached);
            }
            drop(store);
            let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
            let capture = LinkFreezeCaptureIntent::load(&store, anchor_id)
                .unwrap()
                .unwrap();
            if interruption >= 2 {
                fs::remove_file(&source_path).unwrap();
            }
            let detached = if interruption == 2 {
                capture.verify_detached_anchor(&store, &parent).unwrap()
            } else if interruption == 3 {
                capture.finish_detached_edit(&store, &parent).unwrap()
            } else {
                capture.resume(&store, &parent, &parent).unwrap().unwrap()
            };
            assert_eq!(detached.phase(), LinkFreezeCapturePhase::Detached);
            assert!(
                crate::link_freeze::LinkFreezeEditIntent::load(&store, anchor_id)
                    .unwrap()
                    .is_none()
            );
            assert_ne!(fs::metadata(&anchor_path).unwrap().ino(), original_inode);
            assert_eq!(fs::metadata(&anchor_path).unwrap().nlink(), 1);
            assert_eq!(
                fs::read(&anchor_path).unwrap()[4096..4112],
                *b"anchored\0\0\0\0\0\0\0\0"
            );
            if interruption < 2 {
                fs::write(&source_path, b"edited").unwrap();
                assert_eq!(
                    fs::read(&anchor_path).unwrap()[4096..4112],
                    *b"anchored\0\0\0\0\0\0\0\0"
                );
            }
            detached.verify_detached_anchor(&store, &parent).unwrap();
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn frozen_capture_survives_source_rename_replacement_and_unlink() {
        let root = test_directory();
        let original = root.path().join("source");
        let moved_dir = root.path().join("moved");
        let moved = moved_dir.join("renamed");
        fs::create_dir(&moved_dir).unwrap();
        fs::write(&original, b"immutable original").unwrap();
        let parent = PinnedDirectory::open(root.path()).unwrap();
        let moved_parent = PinnedDirectory::open(&moved_dir).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([95; 32]));
        let database_path = root.path().join("control.db");
        let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
        let anchor_id = uuid::Uuid::new_v4();
        let frozen =
            LinkFreezeCaptureIntent::begin(&store, anchor_id, &parent, "source", &parent, "anchor")
                .unwrap()
                .resume(&store, &parent, &parent)
                .unwrap()
                .unwrap();
        let unknown = root.path().join("unknown-alias");
        fs::hard_link(&original, &unknown).unwrap();
        assert!(frozen.clone().resume(&store, &parent, &parent).is_err());
        fs::remove_file(&unknown).unwrap();
        fs::rename(&original, &moved).unwrap();
        fs::write(&original, b"replacement").unwrap();
        drop(store);

        let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
        let recovered = LinkFreezeCaptureIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap();
        assert_eq!(recovered, frozen);
        // A second, unaccounted link must not be accepted as a rename merely
        // because the old pathname disappeared. The new pinned name supplies
        // the missing link-group evidence before edit replay is rebound.
        assert!(recovered.clone().resume(&store, &parent, &parent).is_err());
        assert_eq!(
            fs::read(root.path().join("anchor")).unwrap(),
            b"immutable original"
        );
        assert!(
            recovered
                .clone()
                .begin_edit(&store, &parent, &parent)
                .is_err()
        );
        let rebound = recovered
            .rebind_frozen_source(&store, &moved_parent, "renamed", &parent)
            .unwrap();
        assert_eq!(
            rebound
                .clone()
                .resume(&store, &moved_parent, &parent)
                .unwrap(),
            Some(rebound.clone())
        );
        let _edit = rebound
            .begin_edit_at(&store, &moved_parent, "renamed", &parent)
            .unwrap();
        drop(store);

        let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
        let rebound = LinkFreezeCaptureIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap();
        let detached = rebound
            .resume(&store, &moved_parent, &parent)
            .unwrap()
            .unwrap();
        assert_eq!(detached.phase(), LinkFreezeCapturePhase::Detached);
        fs::write(&moved, b"changed later").unwrap();
        assert_eq!(
            fs::read(root.path().join("anchor")).unwrap(),
            b"immutable original"
        );
        assert_eq!(fs::read(&original).unwrap(), b"replacement");
        fs::remove_file(&moved).unwrap();
        detached.verify_detached_anchor(&store, &parent).unwrap();

        let second_id = uuid::Uuid::new_v4();
        fs::write(&original, b"another original").unwrap();
        let second = LinkFreezeCaptureIntent::begin(
            &store,
            second_id,
            &parent,
            "source",
            &parent,
            "second-anchor",
        )
        .unwrap()
        .resume(&store, &parent, &parent)
        .unwrap()
        .unwrap();
        fs::remove_file(&original).unwrap();
        assert_eq!(
            second
                .resume(&store, &parent, &parent)
                .unwrap()
                .unwrap()
                .phase(),
            LinkFreezeCapturePhase::Frozen
        );
        assert_eq!(
            fs::read(root.path().join("second-anchor")).unwrap(),
            b"another original"
        );
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn pending_edit_rebinds_after_rename_at_each_detach_phase() {
        for interruption in 0..=5 {
            let root = test_directory();
            let source_path = root.path().join("source");
            let moved_dir = root.path().join("moved");
            let moved_path = moved_dir.join("renamed");
            fs::create_dir(&moved_dir).unwrap();
            let source = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&source_path)
                .unwrap();
            source.set_len(1024 * 1024).unwrap();
            source.write_at(b"original", 4096).unwrap();
            source.sync_all().unwrap();
            drop(source);
            let parent = PinnedDirectory::open(root.path()).unwrap();
            let moved_parent = PinnedDirectory::open(&moved_dir).unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_bytes([96; 32]));
            let database_path = root.path().join("control.db");
            let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
            let anchor_id = uuid::Uuid::new_v4();
            let capture = LinkFreezeCaptureIntent::begin(
                &store, anchor_id, &parent, "source", &parent, "anchor",
            )
            .unwrap()
            .resume(&store, &parent, &parent)
            .unwrap()
            .unwrap();
            let mut edit = capture
                .clone()
                .begin_edit(&store, &parent, &parent)
                .unwrap();
            if interruption >= 1 {
                edit = edit.mark_copy_staging(&store).unwrap();
            }
            if interruption >= 2 {
                let guard = FileWriteExclusion::acquire(File::open(&source_path).unwrap()).unwrap();
                let private = parent.create_child_file(edit.staging_name()).unwrap();
                let copy = guard.copy_sparse_independent(&private).unwrap();
                edit = edit
                    .mark_private_copy_ready(&store, &guard, &parent, private, copy)
                    .unwrap();
                guard.release().unwrap();
            }
            if interruption >= 3 {
                let private_id = NativeFileId {
                    filesystem_id: capture.source_id.filesystem_id,
                    inode: edit.private_inode().unwrap(),
                };
                parent
                    .exchange_child_files(
                        "anchor",
                        capture.source_id,
                        &parent,
                        edit.staging_name(),
                        private_id,
                    )
                    .unwrap();
            }
            if interruption >= 4 {
                parent
                    .remove_child_file_if_identity(edit.staging_name(), capture.source_id)
                    .unwrap();
            }
            if interruption >= 5 {
                edit = edit
                    .mark_unlock_pending(
                        &store,
                        &File::open(&source_path).unwrap(),
                        &parent,
                        "source",
                        &parent,
                        "anchor",
                    )
                    .unwrap();
            }
            fs::rename(&source_path, &moved_path).unwrap();
            fs::write(&source_path, b"replacement").unwrap();
            drop(store);

            let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
            let capture = LinkFreezeCaptureIntent::load(&store, anchor_id)
                .unwrap()
                .unwrap();
            assert!(capture.clone().resume(&store, &parent, &parent).is_err());
            assert!(
                capture
                    .clone()
                    .rebind_pending_edit(&store, &parent, "source", &parent)
                    .is_err()
            );
            let unknown = root.path().join("unknown-alias");
            fs::hard_link(&moved_path, &unknown).unwrap();
            assert!(
                capture
                    .clone()
                    .rebind_pending_edit(&store, &moved_parent, "renamed", &parent)
                    .is_err(),
                "case {interruption} accepted an unknown alias"
            );
            fs::remove_file(&unknown).unwrap();
            let rebound = capture
                .rebind_pending_edit(&store, &moved_parent, "renamed", &parent)
                .unwrap();
            let detached = rebound
                .resume(&store, &moved_parent, &parent)
                .unwrap()
                .unwrap();
            assert_eq!(detached.phase(), LinkFreezeCapturePhase::Detached);
            assert!(
                crate::link_freeze::LinkFreezeEditIntent::load(&store, anchor_id)
                    .unwrap()
                    .is_none()
            );
            fs::write(&moved_path, b"changed later").unwrap();
            assert_eq!(
                fs::read(root.path().join("anchor")).unwrap()[4096..4104],
                *b"original"
            );
            assert_eq!(fs::read(&source_path).unwrap(), b"replacement");
        }
    }

    #[test]
    #[ignore = "requires CAP_SYS_ADMIN for fanotify permission events"]
    fn retirement_recovers_after_anchor_unlink_before_access_restore() {
        let root = test_directory();
        let source_path = root.path().join("source");
        let anchor_path = root.path().join("anchor");
        fs::write(&source_path, b"keep working bytes").unwrap();
        let original_mode = fs::metadata(&source_path).unwrap().permissions().mode() & 0o7777;
        let parent = PinnedDirectory::open(root.path()).unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([98; 32]));
        let database_path = root.path().join("control.db");
        let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
        let anchor_id = uuid::Uuid::new_v4();
        let frozen =
            LinkFreezeCaptureIntent::begin(&store, anchor_id, &parent, "source", &parent, "anchor")
                .unwrap()
                .resume(&store, &parent, &parent)
                .unwrap()
                .unwrap();
        let planned = RetireIntent {
            format_version: 1,
            capture: frozen.clone(),
            phase: RetirePhase::Planned,
        };
        store
            .put_record_if_absent(
                RETIRE_INTENT_KIND,
                anchor_id.as_bytes(),
                &mb_core::canonical_bytes(&planned).unwrap(),
            )
            .unwrap();
        let guard = FileWriteExclusion::acquire(File::open(&source_path).unwrap()).unwrap();
        parent
            .remove_child_file_if_identity("anchor", frozen.source_id)
            .unwrap();
        guard.release().unwrap();
        assert!(!anchor_path.exists());
        assert_eq!(
            fs::metadata(&source_path).unwrap().permissions().mode() & 0o222,
            0
        );
        drop(store);

        let store = crate::database::ControlStore::open(&database_path, &keys).unwrap();
        let frozen = LinkFreezeCaptureIntent::load(&store, anchor_id)
            .unwrap()
            .unwrap();
        assert!(frozen.clone().resume(&store, &parent, &parent).is_err());
        frozen
            .retire_unreferenced(&store, &parent, &parent)
            .unwrap();
        assert_eq!(fs::read(&source_path).unwrap(), b"keep working bytes");
        assert_eq!(
            fs::metadata(&source_path).unwrap().permissions().mode() & 0o7777,
            original_mode
        );
        assert!(
            LinkFreezeCaptureIntent::load(&store, anchor_id)
                .unwrap()
                .is_none()
        );
        assert!(LinkFreezeCaptureIntent::retirement_pending(&store, anchor_id).unwrap());
        assert!(LinkFreezeCaptureIntent::finish_completed_retirement(&store, anchor_id).unwrap());
        assert!(!LinkFreezeCaptureIntent::retirement_pending(&store, anchor_id).unwrap());
    }

    fn test_directory() -> tempfile::TempDir {
        match std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT") {
            Some(root) => tempfile::Builder::new()
                .prefix("mb-link-capture-")
                .tempdir_in(root)
                .unwrap(),
            None => tempfile::Builder::new()
                .prefix("mb-link-capture-")
                .tempdir()
                .unwrap(),
        }
    }
}
