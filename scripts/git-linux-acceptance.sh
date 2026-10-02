#!/usr/bin/env bash
set -euo pipefail

# Provisioned Linux Git slice. Milestone 6 also requires platform and guarded
# link-freeze gates; this script does not claim the complete milestone gate.
if [[ -z "${MUTUALBACKUP_REFLINK_TEST_ROOT:-}" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT must name a disposable reflink filesystem" >&2
  exit 2
fi

cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p mb-git --lib --locked -- --ignored --test-threads=1
cargo test -p mb-node node::tests::git_repository_init_and_add_survive_daemon_reopen --locked -- --ignored --exact
cargo test -p mb-node node::tests::git_linked_worktree_registration_survives_daemon_reopen --locked -- --ignored --exact
cargo test -p mb-node node::tests::git_prune_keeps_signed_revision_history_until_its_retirement --locked -- --ignored --exact
cargo test -p mb-node lab::tests::seed_only_recovery_rebuilds_git_branches_and_exact_blobs --locked -- --ignored --exact
cargo test -p mb-node node::tests::source_backend_binding_reprobes_and_migrates --locked -- --ignored --exact
cargo test -p mb-node snapshot::metadata_compatibility_tests::git_history_enters_encrypted_revision_sectors_without_changing_root_restore --locked -- --ignored --exact
cargo test -p mutualbackup --test git_remote_helper --locked -- --ignored --test-threads=1
bash scripts/network-smoke.sh "$MUTUALBACKUP_REFLINK_TEST_ROOT"
