//! Git object semantics over MutualBackup's immutable source anchors.
//!
//! This crate deliberately has no writable Git object directory. The verified
//! native anchor is the payload store; libgit2 supplies the Git object ID.

#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

use git2::{ObjectType, Oid};
use mb_core::KeyMaterial;
#[cfg(target_os = "linux")]
use mb_store::SourceBackendKind;
use mb_store::{AnchorError, FileAnchorManifest};
use thiserror::Error;

#[cfg(target_os = "linux")]
mod backup;
#[cfg(target_os = "linux")]
mod backup_size;
mod blob_catalog;
#[cfg(target_os = "linux")]
mod catalog_anchor;
#[cfg(target_os = "linux")]
mod checkout;
#[cfg(target_os = "linux")]
mod diff;
#[cfg(target_os = "linux")]
mod fetch;
#[cfg(target_os = "linux")]
mod head;
#[cfg(target_os = "linux")]
mod history;
#[cfg(target_os = "linux")]
mod interop;
#[cfg(target_os = "linux")]
mod merge;
mod object_catalog;
mod odb;
mod paged_catalog;
#[cfg(target_os = "linux")]
mod prune;
mod ref_catalog;
#[cfg(target_os = "linux")]
mod repository;
#[cfg(target_os = "linux")]
mod rm;
mod stage;
#[cfg(target_os = "linux")]
mod status;
#[cfg(target_os = "linux")]
mod stock_git;
#[cfg(target_os = "linux")]
mod worktree;
mod worktree_scope;
#[cfg(target_os = "linux")]
pub use backup::{GitBackupBlob, GitBackupDescriptor, GitBackupError, GitDataExtent};
pub use blob_catalog::{
    GIT_BLOB_SECTOR_REFS, GitBlobCatalogBuilder, GitBlobCatalogReader, GitBlobCatalogRoot,
    GitBlobRecord,
};
#[cfg(target_os = "linux")]
pub use checkout::CheckoutError;
#[cfg(target_os = "linux")]
pub use diff::{DiffError, GitDiff};
#[cfg(target_os = "linux")]
pub use fetch::FetchError;
#[cfg(target_os = "linux")]
pub use head::HeadError;
#[cfg(target_os = "linux")]
pub use history::{
    GitBackupCapacity, GitBranchInfo, GitCommitInfo, GitGraphBlobSource, GitGraphObject,
    GitGraphRef, GitGraphSource, GitLogEntry, GitRemoteBranchInfo, GitTagInfo, HistoryError,
};
#[cfg(target_os = "linux")]
pub use interop::GitInteropError;
#[cfg(target_os = "linux")]
pub use merge::{GitMergeState, MergeBlobError};
pub use object_catalog::{
    GIT_OBJECT_FRAGMENT_BYTES, GitObjectCatalogBuilder, GitObjectCatalogReader,
    GitObjectCatalogRoot, GitObjectRecord,
};
pub use odb::NativeOdb;
pub use paged_catalog::{
    GIT_CATALOG_ROOT_BYTES, GitCatalogRoot, GitCatalogStream, GitCatalogWriteError,
};
#[cfg(target_os = "linux")]
pub use prune::{GitPruneError, GitPruneReport, GitPruneRoots};
pub use ref_catalog::{
    GIT_HEAD_BRANCH_BYTES, GIT_REF_NAME_BYTES, GitRefCatalogBuilder, GitRefCatalogReader,
    GitRefCatalogRoot, GitRefRecord, git_ref_name_order,
};
#[cfg(target_os = "linux")]
pub use repository::{GitRepository, RepositoryError, require_native_catalog_state};
#[cfg(target_os = "linux")]
pub use rm::GitRmError;
pub use stage::{
    GitIndexEntry, StageError, abandon_pending_stage, anchors_for_oid, has_pending_stages,
    pending_stage_paths, remove_cached, resume_pending_stages, stage_file, staged_entries,
    staged_entry,
};
#[cfg(target_os = "linux")]
pub use status::{GitChange, GitStatus, GitStatusChange, StatusError};
#[cfg(target_os = "linux")]
pub use worktree::{GitWorktreeError, GitWorktreeInfo, GitWorktreeState, linked_worktree_marker};
pub use worktree_scope::GitWorktreeScope;

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
pub(crate) struct NativeSource<'a> {
    pub root: &'a Path,
    pub backend: SourceBackendKind,
}

#[derive(Debug, Error)]
pub enum GitAnchorError {
    #[error("anchor discovery catalog error: {0}")]
    Database(#[from] mb_store::DatabaseError),
    #[error("anchor relocation failed: {0}")]
    Discovery(anyhow::Error),
    #[error("native anchor failed verification: {0}")]
    Anchor(#[from] AnchorError),
    #[error("libgit2 could not hash the immutable anchor: {0}")]
    Git(#[from] git2::Error),
    #[error("Git anchor hashing requires a Linux pinned-file descriptor")]
    UnsupportedPlatform,
    #[error("different native content was assigned the same Git object ID")]
    OidCollision,
}

pub fn catalog_key(keys: &KeyMaterial, repository_id: uuid::Uuid) -> [u8; 32] {
    let mut database_id = b"git-catalog-v1/".to_vec();
    database_id.extend_from_slice(repository_id.as_bytes());
    keys.database_key(&database_id)
}

/// Hash exact captured bytes as a SHA-1 Git blob without applying Git filters.
///
/// The `/proc/self/fd` path binds libgit2's streaming `hash_file` call to the
/// file descriptor verified by the native backend. In particular, it does not
/// pass the mutable working-tree path to Git or materialize `.git/objects`.
pub fn blob_oid_from_anchor(manifest: &FileAnchorManifest) -> Result<Oid, GitAnchorError> {
    let pinned = manifest.open_verified()?;
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;

        let descriptor_path = PathBuf::from(format!("/proc/self/fd/{}", pinned.as_raw_fd()));
        let oid = Oid::hash_file(ObjectType::Blob, descriptor_path)?;
        Ok(oid)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pinned;
        Err(GitAnchorError::UnsupportedPlatform)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::{fs, path::PathBuf};

    use mb_store::SourceFileCapturePlan;
    use uuid::Uuid;

    use super::blob_oid_from_anchor;

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn git_blob_oid_hashes_exact_anchor_bytes_after_worktree_edit() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-blob-{}", Uuid::new_v4()));
        fs::create_dir_all(&run_root).unwrap();
        let work_file = run_root.join("tracked");
        fs::write(&work_file, b"staged\r\nbytes\0").unwrap();
        let plan = SourceFileCapturePlan::plan_reflink(&run_root, "tracked").unwrap();
        let manifest = plan.capture().unwrap();
        fs::write(&work_file, b"later\nedit").unwrap();
        let oid = blob_oid_from_anchor(&manifest).unwrap();
        // Independent fixture from `git hash-object --no-filters --stdin`.
        assert_eq!(oid.to_string(), "81b2d75d7f1e1b71438019a1128f25986bebd588");
        manifest.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }
}
