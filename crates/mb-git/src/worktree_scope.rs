//! Catalog scope for local worktree state. The primary worktree keeps every
//! existing key unchanged; linked worktrees get distinct namespaces while
//! sharing repository refs, Git objects, and native anchors.

use uuid::Uuid;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GitWorktreeScope {
    repository_id: Uuid,
    worktree_id: Uuid,
}

impl GitWorktreeScope {
    pub fn primary(repository_id: Uuid) -> Self {
        Self {
            repository_id,
            worktree_id: repository_id,
        }
    }

    pub fn linked(repository_id: Uuid, worktree_id: Uuid) -> Option<Self> {
        if repository_id.is_nil() || worktree_id.is_nil() || repository_id == worktree_id {
            return None;
        }
        Some(Self {
            repository_id,
            worktree_id,
        })
    }

    pub fn repository_id(self) -> Uuid {
        self.repository_id
    }

    pub fn worktree_id(self) -> Uuid {
        self.worktree_id
    }

    /// Decode the exact original primary/linked namespace without inventing a
    /// registration or accepting another repository's local state.
    #[cfg(target_os = "linux")]
    pub(crate) fn preserved_from_kind(
        kind: &str,
        repository_id: Uuid,
        primary_prefix: &str,
        linked_prefix: &str,
    ) -> anyhow::Result<Self> {
        use anyhow::{Context, ensure};
        ensure!(
            !repository_id.is_nil(),
            "invalid preserved Git repository scope"
        );
        let primary = Self::primary(repository_id);
        if kind == primary.local_kind(primary_prefix, linked_prefix) {
            return Ok(primary);
        }
        let expected = format!("{linked_prefix}{repository_id}/");
        let suffix = kind
            .strip_prefix(&expected)
            .context("preserved Git namespace conflicts with its repository marker")?;
        let worktree_id = Uuid::parse_str(suffix)?;
        let scope = Self::linked(repository_id, worktree_id)
            .context("invalid preserved linked Git scope")?;
        ensure!(
            scope.local_kind(primary_prefix, linked_prefix) == kind,
            "noncanonical preserved linked Git scope"
        );
        Ok(scope)
    }

    pub(crate) fn local_kind(self, primary_prefix: &str, linked_prefix: &str) -> String {
        if self.repository_id == self.worktree_id {
            format!("{primary_prefix}{}", self.repository_id)
        } else {
            format!("{linked_prefix}{}/{}", self.repository_id, self.worktree_id)
        }
    }
}
