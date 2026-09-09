#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MUTUALBACKUP_REFLINK_TEST_ROOT:-}" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT must name a disposable reflink filesystem" >&2
  exit 2
fi

cargo test -p mb-store anchor::tests::stable_locator_survives_parent_rename --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::nested_btrfs_subvolumes_are_rejected_before_and_during_capture --locked -- --ignored --exact
cargo test -p mb-node lab::tests::seed_only_recovery_over_five_active_nodes --locked -- --ignored --exact
cargo test -p mb-node network::tests::signed_network_commit_and_seed_recovery --locked -- --ignored --exact
cargo test -p mb-node network::p2p::tests::repeated_multi_owner_backups_commit_over_quic --locked -- --ignored --exact
cargo test -p mutualbackup --test prototype_acceptance --locked -- --ignored --nocapture
