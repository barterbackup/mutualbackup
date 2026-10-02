#![cfg(target_os = "linux")]

use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;

use mb_git::{GitPruneRoots, GitRepository};
use uuid::Uuid;

#[derive(Debug)]
struct DiskUsage {
    total: u64,
    exclusive: u64,
    shared: u64,
}

fn sync_filesystem(path: &Path) {
    let directory = File::open(path).unwrap();
    // SAFETY: syncfs only reads the valid directory descriptor.
    assert_eq!(unsafe { libc::syncfs(directory.as_raw_fd()) }, 0);
}

fn disk_usage(path: &Path) -> DiskUsage {
    let output = Command::new("btrfs")
        .args(["filesystem", "du", "--raw", "--summarize"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "btrfs filesystem du failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    let values = text
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .collect::<Vec<_>>();
    assert!(values.len() >= 4, "unexpected btrfs du output: {text}");
    DiskUsage {
        total: values[0].parse().unwrap(),
        exclusive: values[1].parse().unwrap(),
        shared: values[2].parse().unwrap(),
    }
}

fn anchor_path(anchor: &mb_store::FileAnchorManifest) -> PathBuf {
    anchor
        .area
        .path_hint
        .join(anchor.anchor_id.to_string())
        .join(&anchor.file_locator().relative_path)
}

fn unique_extent_bytes(usage: &DiskUsage) -> u64 {
    usage.total.checked_sub(usage.shared).unwrap()
}

fn payload(seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut bytes = vec![0_u8; 4 * 1024 * 1024];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    bytes
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem and btrfs-progs"]
fn stage_checkout_and_prune_measure_shared_and_exclusive_extents() {
    let test_root = PathBuf::from(
        std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the Btrfs acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
    );
    let run_root = test_root.join(format!("git-btrfs-space-{}", Uuid::new_v4()));
    let source = run_root.join("source");
    fs::create_dir_all(&source).unwrap();
    let main_bytes = payload(41);
    let topic_bytes = payload(97);
    let tracked = source.join("tracked");
    fs::write(&tracked, &main_bytes).unwrap();
    sync_filesystem(&source);

    let repository_id = Uuid::new_v4();
    let repository = GitRepository::init(&source, repository_id, &[42_u8; 32]).unwrap();
    let main_staged = repository.stage_file("tracked").unwrap();
    repository
        .commit("Author", "a@example.test", "main")
        .unwrap();
    let main_anchor = repository
        .export_graph_source()
        .unwrap()
        .blobs
        .into_iter()
        .find(|blob| blob.oid == main_staged.oid)
        .unwrap()
        .anchor;
    sync_filesystem(&source);
    let staged_source_usage = disk_usage(&tracked);
    let staged_anchor_usage = disk_usage(&anchor_path(&main_anchor));
    assert_eq!(staged_source_usage.total, main_bytes.len() as u64);
    assert_eq!(staged_anchor_usage.total, main_bytes.len() as u64);
    assert!(staged_source_usage.shared >= 1024 * 1024);
    assert!(staged_anchor_usage.shared >= 1024 * 1024);
    assert_eq!(staged_anchor_usage.exclusive, 0);
    assert!(!source.join(".git").exists());

    repository.create_branch("topic").unwrap();
    repository.switch_branch("topic").unwrap();
    fs::write(&tracked, &topic_bytes).unwrap();
    let topic_staged = repository.stage_file("tracked").unwrap();
    repository
        .commit("Author", "a@example.test", "topic")
        .unwrap();
    let topic_anchor = repository
        .export_graph_source()
        .unwrap()
        .blobs
        .into_iter()
        .find(|blob| blob.oid == topic_staged.oid)
        .unwrap()
        .anchor;
    repository.switch_branch("main").unwrap();
    assert_eq!(fs::read(&tracked).unwrap(), main_bytes);
    sync_filesystem(&source);
    let checked_out_usage = disk_usage(&tracked);
    let retained_usage = disk_usage(&anchor_path(&main_anchor));
    let orphan_usage = disk_usage(&anchor_path(&topic_anchor));
    assert!(checked_out_usage.shared >= 1024 * 1024);
    assert!(retained_usage.shared >= 1024 * 1024);
    assert!(orphan_usage.exclusive >= 1024 * 1024);
    let footprint_before = disk_usage(&run_root);

    repository.delete_branch("topic", true).unwrap();
    let report = repository
        .prune_unreachable(&GitPruneRoots::default())
        .unwrap();
    sync_filesystem(&source);
    let footprint_after = disk_usage(&run_root);
    let unique_bytes_removed = unique_extent_bytes(&footprint_before)
        .checked_sub(unique_extent_bytes(&footprint_after))
        .unwrap();
    assert!(report.native_anchors_removed >= 1);
    assert!(report.logical_anchor_bytes_removed >= topic_bytes.len() as u64);
    assert!(unique_bytes_removed >= 1024 * 1024);
    assert!(topic_anchor.file_locator().open().is_err());
    assert!(main_anchor.open_verified().is_ok());
    assert_eq!(fs::read(&tracked).unwrap(), main_bytes);
    eprintln!(
        "Btrfs Git extents: staged shared={} checkout shared={} orphan exclusive={} unique bytes removed={} logical pruned={}",
        staged_anchor_usage.shared,
        checked_out_usage.shared,
        orphan_usage.exclusive,
        unique_bytes_removed,
        report.logical_anchor_bytes_removed
    );

    drop(repository);
    main_anchor.remove().unwrap();
    fs::remove_dir_all(run_root).unwrap();
}
