#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MUTUALBACKUP_REFLINK_TEST_ROOT:-}" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT must name a disposable reflink filesystem" >&2
  exit 2
fi

cargo test -p mb-node lab::tests::seed_only_recovery_over_five_active_nodes -- --ignored --exact
cargo test -p mb-node network::tests::signed_network_commit_and_seed_recovery -- --ignored --exact
cargo test -p mb-store anchor::tests::stable_locator_survives_parent_rename -- --ignored --exact
