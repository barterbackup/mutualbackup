#!/usr/bin/env bash
set -euo pipefail

# Provisioned native Linux Git slice. Milestone 6 also requires platform,
# upgrade, and release-artifact gates; this is one required slice.
if [[ -z "${MUTUALBACKUP_REFLINK_TEST_ROOT:-}" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT must name a disposable reflink filesystem" >&2
  exit 2
fi
if ! command -v btrfs >/dev/null 2>&1; then
  echo "btrfs-progs is required for Git extent measurements" >&2
  exit 2
fi

cargo clippy --workspace --all-targets --locked -- -D warnings
bash scripts/sqlite-wal-admission-acceptance.sh
TMPDIR="$MUTUALBACKUP_REFLINK_TEST_ROOT" cargo test -p mb-store --lib --locked database::physical_io::wal_commit_tests:: -- --nocapture --test-threads=1
cargo test -p mb-git --lib --locked -- --ignored --test-threads=1
cargo test -p mb-git --test btrfs_space --locked -- --ignored --test-threads=1
cargo test -p mb-node node::tests::git_repository_init_and_add_survive_daemon_reopen --locked -- --ignored --exact
cargo test -p mb-node node::tests::git_linked_worktree_registration_survives_daemon_reopen --locked -- --ignored --exact
cargo test -p mb-node node::tests::git_prune_keeps_signed_revision_history_until_its_retirement --locked -- --ignored --exact
cargo test -p mb-node lab::tests::seed_only_recovery_rebuilds_git_branches_and_exact_blobs --locked -- --ignored --exact
cargo test -p mb-node network::p2p::tests::native_git_graph_recovers_from_format_seven_packed_checkpoint --locked -- --ignored --exact --nocapture
cargo test -p mb-node network::p2p::tests::virtual_zero_routing_tests::fresh_coordinator_routes_virtual_zero_openings_and_commits_backup --locked -- --ignored --exact --nocapture
cargo test -p mb-node node::tests::source_backend_binding_reprobes_and_migrates --locked -- --ignored --exact
cargo test -p mb-node volume::scratch_headroom_tests::paged_scratch_preserves_native_control_headroom_and_retries_after_space_returns --locked -- --ignored --exact --nocapture
cargo test -p mb-node volume::allocation_domain_tests:: --locked -- --ignored --nocapture --test-threads=1
cargo test -p mb-node volume::control_headroom_tests::native_parity_refuses_unfunded_control_headroom_before_intent_and_retries --locked -- --ignored --exact --nocapture
cargo test -p mb-node snapshot::metadata_compatibility_tests::git_history_enters_encrypted_revision_sectors_without_changing_root_restore --locked -- --ignored --exact
cargo test -p mutualbackup --test git_remote_helper --locked -- --ignored --test-threads=1
TMPDIR="$MUTUALBACKUP_REFLINK_TEST_ROOT" cargo test -p mutualbackup --test prototype_acceptance --locked native_enrollment:: -- --nocapture --test-threads=2
cargo test -p mutualbackup --test prototype_acceptance --locked raw_unix_paths_survive_cli_daemon_and_git_checkout -- --ignored --exact
bash scripts/network-smoke.sh "$MUTUALBACKUP_REFLINK_TEST_ROOT"
