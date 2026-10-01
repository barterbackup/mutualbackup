//! Git object semantics over MutualBackup's immutable source anchors.
//!
//! This crate deliberately has no writable Git object directory. The verified
//! native anchor is the payload store; libgit2 supplies the Git object ID.

#[cfg(target_os = "linux")]
use std::path::PathBuf;

use git2::{ObjectType, Oid};
use mb_store::{AnchorError, FileAnchorManifest};
use thiserror::Error;

mod odb;
#[cfg(target_os = "linux")]
mod repository;
mod stage;
pub use odb::NativeOdb;
#[cfg(target_os = "linux")]
pub use repository::{GitRepository, RepositoryError};
pub use stage::{
    GitIndexEntry, StageError, abandon_pending_stage, anchors_for_oid, resume_pending_stages,
    stage_file, staged_entry,
};

#[derive(Debug, Error)]
pub enum GitAnchorError {
    #[error("native anchor failed verification: {0}")]
    Anchor(#[from] AnchorError),
    #[error("libgit2 could not hash the immutable anchor: {0}")]
    Git(#[from] git2::Error),
    #[error("Git anchor hashing requires a Linux pinned-file descriptor")]
    UnsupportedPlatform,
    #[error("different native content was assigned the same Git object ID")]
    OidCollision,
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
