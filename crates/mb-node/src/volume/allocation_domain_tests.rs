use super::*;
use mb_core::{Seed, V1_SECTOR_SIZE};
use std::os::fd::AsRawFd;
use std::process::Command;

struct Fixture(Option<tempfile::TempDir>);
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "VOLUME_ALLOCATION_DOMAIN_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

fn subvolume(path: &Path) {
    let output = Command::new("btrfs")
        .args(["subvolume", "create"])
        .arg(path)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn setup() -> (Fixture, ControlStore, StorageVolumes) {
    let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").expect("provisioned filesystem");
    let fixture = Fixture(Some(tempfile::tempdir_in(root).unwrap()));
    let root = fixture.0.as_ref().unwrap().path();
    let control_path = root.join("control");
    let first = root.join("first");
    let second = root.join("second");
    for path in [&control_path, &first, &second] {
        subvolume(path);
    }
    assert_ne!(
        fs::metadata(&first).unwrap().dev(),
        fs::metadata(&second).unwrap().dev()
    );
    let domain = mb_store::physical_allocation_domain(&control_path).unwrap();
    assert_eq!(
        mb_store::physical_allocation_domain(&first).unwrap(),
        domain
    );
    assert_eq!(
        mb_store::physical_allocation_domain(&second).unwrap(),
        domain
    );
    let keys = Arc::new(KeyMaterial::from_seed(&Seed::from_bytes([109; 32])));
    let (control, _) = open_control_store(&control_path, &keys).unwrap();
    control
        .put_record("allocation-original", b"one", b"original data")
        .unwrap();
    let mut volumes = StorageVolumes::open(&control_path, keys, &control).unwrap();
    volumes
        .configure(&control, &[first, second], u64::MAX, 0)
        .unwrap();
    assert_eq!(control.physical_allocation_domain().unwrap(), domain);
    for volume in volumes
        .volumes
        .values()
        .filter(|v| v.record.state == StorageVolumeState::Online)
    {
        assert_eq!(
            volume
                .store
                .as_ref()
                .unwrap()
                .physical_allocation_domain()
                .unwrap(),
            domain
        );
    }
    assert_eq!(
        volumes
            .volumes
            .values()
            .filter(|v| v.record.state == StorageVolumeState::Online)
            .count(),
        2
    );
    (fixture, control, volumes)
}

fn cleanup(fixture: Fixture) {
    let root = fixture.0.as_ref().unwrap().path();
    for name in ["first", "second", "control"] {
        let output = Command::new("btrfs")
            .args(["subvolume", "delete"])
            .arg(root.join(name))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Commit deletion without the privileged B-tree enumeration performed by
    // `btrfs subvolume sync`. All paths belong to this disposable fixture.
    let filesystem = File::open(root).unwrap();
    assert_eq!(unsafe { libc::syncfs(filesystem.as_raw_fd()) }, 0);
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn coding_capacity_counts_btrfs_subvolume_space_once_for_writers_and_readers() {
    let (fixture, control, volumes) = setup();
    let available = fs2::available_space(control.path().parent().unwrap()).unwrap();
    let bound = available / physical_write_reservation(V1_SECTOR_SIZE, 0);
    let writer = volumes
        .coding_capacity(&control, V1_SECTOR_SIZE as u32)
        .unwrap();
    let reader =
        reader_coding_capacity(&control, &volumes.reader_configs(), V1_SECTOR_SIZE as u32).unwrap();
    eprintln!("ALLOCATION_DOMAIN_CAPACITY upper_bound={bound} writer={writer} reader={reader}");
    assert!(writer > 0 && reader > 0);
    assert!(
        writer <= bound && reader <= bound,
        "shared Btrfs capacity counted more than once: bound={bound}, writer={writer}, reader={reader}"
    );
    assert_eq!(
        control.get_record("allocation-original", b"one").unwrap(),
        Some(b"original data".to_vec())
    );
    drop((volumes, control));
    cleanup(fixture);
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn parity_reservations_include_control_checkpoint_across_btrfs_subvolumes() {
    let (fixture, control, volumes) = setup();
    control
        .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
        .unwrap();
    control
        .put_record("allocation-original", b"wal", &vec![7; 1024 * 1024])
        .unwrap();
    let store = volumes
        .volumes
        .values()
        .find(|v| v.record.state == StorageVolumeState::Online)
        .unwrap()
        .store
        .as_ref()
        .unwrap();
    assert_ne!(
        fs::metadata(control.path()).unwrap().dev(),
        fs::metadata(store.path()).unwrap().dev()
    );
    let control_bytes = control.checkpoint_reservation_bytes().unwrap();
    let parity_bytes = store.checkpoint_reservation_bytes().unwrap();
    assert!(control_bytes >= 1024 * 1024);
    assert_eq!(
        shared_checkpoint_reservation(&control, store).unwrap(),
        control_bytes + parity_bytes,
        "shared filesystem checkpoint reserve must include the control WAL"
    );
    assert_eq!(
        control.get_record("allocation-original", b"one").unwrap(),
        Some(b"original data".to_vec())
    );
    drop((volumes, control));
    cleanup(fixture);
}
