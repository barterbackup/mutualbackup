//! Durable first freeze of one guarded hard-link anchor. The protected-root
//! backend owns discovery of these records and publication of source manifests.

use std::fs::File;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{
    FileAccessSnapshot, FileWriteExclusion, FrozenAnchorProof, IndependentSparseCopy,
    file_data_extents, hash_exact,
};
use crate::anchor::{NativeFileId, PinnedDirectory};
use crate::database::ControlStore;

const CAPTURE_INTENT_KIND: &str = "link-freeze-capture-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum LinkFreezeCapturePhase {
    Prepared,
    Frozen,
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
                && source_id.filesystem_id == source_parent_id.filesystem_id,
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
            format_version: 1,
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
        let intent: Self = mb_core::decode_canonical(&bytes)?;
        anyhow::ensure!(
            intent.format_version == 1
                && intent.anchor_id == anchor_id
                && intent.source_id.filesystem_id == intent.source_parent_id.filesystem_id
                && intent.source_id.filesystem_id == intent.anchor_parent_id.filesystem_id
                && intent.proof.original_access.format_version == 1
                && intent.proof.content.data_extents.len() <= 65_536,
            "invalid frozen capture intent"
        );
        Ok(Some(intent))
    }

    pub fn phase(&self) -> LinkFreezeCapturePhase {
        self.phase
    }

    pub fn frozen_proof(&self) -> Option<&FrozenAnchorProof> {
        (self.phase == LinkFreezeCapturePhase::Frozen).then_some(&self.proof)
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
            source_parent.identity()? == self.source_parent_id
                && anchor_parent.identity()? == self.anchor_parent_id,
            "frozen capture directory identity changed"
        );
        anyhow::ensure!(
            control.get_record(CAPTURE_INTENT_KIND, self.anchor_id.as_bytes())?
                == Some(mb_core::canonical_bytes(&self)?),
            "frozen capture intent changed before replay"
        );
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
        if self.phase == LinkFreezeCapturePhase::Frozen {
            anyhow::ensure!(
                anchor_entry == Some(self.source_id)
                    && content_matches
                    && FileAccessSnapshot::capture(&guard.file)?.mode & 0o222 == 0
                    && guard.is_held()?,
                "committed frozen anchor no longer matches its durable proof"
            );
            guard.release()?;
            return Ok(Some(self));
        }
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

    use super::{LinkFreezeCaptureIntent, LinkFreezeCapturePhase};
    use crate::anchor::PinnedDirectory;
    use crate::link_freeze::{FileAccessSnapshot, FileWriteExclusion, install_probe_acl};

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
