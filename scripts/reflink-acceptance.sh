#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${MUTUALBACKUP_REFLINK_TEST_ROOT:-}" ]]; then
  echo "MUTUALBACKUP_REFLINK_TEST_ROOT must name a disposable reflink filesystem" >&2
  exit 2
fi

if ! command -v btrfs >/dev/null 2>&1; then
  echo "btrfs is required (enter the repository's default Nix development shell)" >&2
  exit 2
fi

cargo test -p mb-store anchor::tests::stable_locator_survives_parent_rename --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::nested_btrfs_subvolumes_are_rejected_before_and_during_capture --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::capture_walk_remains_bound_to_the_open_root --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::capture_walk_enumerates_a_descendant_through_its_pinned_descriptor --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::capture_output_remains_bound_to_the_validated_anchor_area --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::anchor_removal_syncs_the_area_descriptor_used_for_unlink --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::descriptor_capture_preserves_hard_links_without_publishing_its_link_pool --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::capture_accepts_the_previous_internal_link_pool_name --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::capture_descriptor_use_is_bounded_by_tree_depth --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::anchor_cleanup_refuses_to_cross_a_child_mount --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::owned_tree_cleanup_refuses_child_mounts_and_handles_read_only_directories --locked -- --ignored --exact
cargo test -p mb-store anchor::tests::anchor_area_initialization_recovers_staged_publication --locked -- --ignored --exact
cargo test -p mb-node snapshot::metadata_compatibility_tests::rejected_capture_can_be_repaired_and_replanned --locked -- --ignored --exact
cargo test -p mb-node snapshot::metadata_compatibility_tests::recovered_anchor_resumes_after_capture_before_database_commit --locked -- --ignored --exact
cargo test -p mb-node snapshot::metadata_compatibility_tests::failed_old_anchor_removal_remains_a_durable_retirement --locked -- --ignored --exact
cargo test -p mb-node snapshot::metadata_compatibility_tests::version_one_capture_intent_migrates_conservatively --locked -- --ignored --exact
cargo test -p mb-node snapshot::metadata_compatibility_tests::restore_directory_descriptor_use_is_bounded --locked -- --ignored --exact
cargo test -p mb-node volume::tests::physical_reservation_preserves_real_shared_filesystem_headroom --locked -- --ignored --exact
cargo test -p mb-node node::tests::complete_recovery_verifies_a_relocated_anchor_without_writing --locked -- --ignored --exact
cargo test -p mb-node lab::tests::seed_only_recovery_over_five_active_nodes --locked -- --ignored --exact
cargo test -p mb-node network::tests::signed_network_commit_and_seed_recovery --locked -- --ignored --exact
cargo test -p mb-node network::p2p::tests::repeated_multi_owner_backups_commit_over_quic --locked -- --ignored --exact
bash scripts/network-smoke.sh "$MUTUALBACKUP_REFLINK_TEST_ROOT"
