use super::*;
use mb_core::{
    NativeDatabaseIoPolicy, STAGED_STORAGE_RECEIPT_DOMAIN, Seed, StagedStorageReceipt,
    V1_SECTOR_SIZE,
};
use mb_store::DatabaseDirectory;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;

struct Fixture(Option<tempfile::TempDir>);
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "CONTROL_HEADROOM_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

fn native_control(root: &Path) -> ControlStore {
    let policy = NativeDatabaseIoPolicy {
        headroom_bytes: 8 << 20,
        ..native_node::tests::policy().control
    };
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([117; 32]));
    ControlStore::create_native_in_directory(
        &DatabaseDirectory::open(root).unwrap(),
        OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
        policy,
    )
    .unwrap()
}

#[test]
fn coding_capacity_charges_native_control_headroom_once_on_its_allocation_domain() {
    let fixture = Fixture(Some(tempfile::tempdir().unwrap()));
    let control = native_control(fixture.0.as_ref().unwrap().path());
    let domain = control_allocation_domain(&control).unwrap();
    let mut other = domain;
    other[0] ^= 1;
    let headroom = control
        .native_database_owner()
        .unwrap()
        .policy()
        .headroom_bytes;
    let checkpoint = control.checkpoint_reservation_bytes().unwrap();
    let per = physical_write_reservation(V1_SECTOR_SIZE, 0);
    let mut devices = BTreeMap::from([
        (
            domain,
            DeviceCodingCapacity {
                logical_shards: 100,
                available_bytes: Some(headroom + checkpoint + 2 * per + per / 2),
                reserved_bytes: 0,
            },
        ),
        (
            other,
            DeviceCodingCapacity {
                logical_shards: 100,
                available_bytes: Some(3 * per + per / 2),
                reserved_bytes: 0,
            },
        ),
    ]);
    assert_eq!(
        device_coding_capacity(&control, &devices, V1_SECTOR_SIZE as u32).unwrap(),
        5
    );
    devices.remove(&other);
    devices.get_mut(&domain).unwrap().available_bytes = Some(headroom - 1);
    assert_eq!(
        device_coding_capacity(&control, &devices, V1_SECTOR_SIZE as u32).unwrap(),
        0
    );
}

#[test]
fn parity_preflight_includes_native_control_headroom_and_both_checkpoints() {
    let fixture = Fixture(Some(tempfile::tempdir().unwrap()));
    let root = fixture.0.as_ref().unwrap().path();
    let control = native_control(root);
    let parity =
        ParityStore::open_with_key(root.join("other-parity.db"), &[118; 16], &[119; 32]).unwrap();
    let expected = control
        .native_database_owner()
        .unwrap()
        .policy()
        .headroom_bytes
        + control.checkpoint_reservation_bytes().unwrap()
        + parity.checkpoint_reservation_bytes().unwrap();
    assert_eq!(
        shared_write_reservation(&control, &parity).unwrap(),
        expected
    );
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn native_parity_refuses_unfunded_control_headroom_before_intent_and_retries() {
    let test_root =
        std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").expect("provisioned filesystem");
    let fixture = Fixture(Some(tempfile::tempdir_in(test_root).unwrap()));
    let root = fixture.0.as_ref().unwrap().path();
    let filesystem = File::open(root).unwrap();
    assert_eq!(unsafe { libc::syncfs(filesystem.as_raw_fd()) }, 0);
    let pressure = root.join("pressure");
    let mut file = File::create(&pressure).unwrap();
    for _ in 0..64 {
        file.write_all(&vec![0; 1024 * 1024]).unwrap();
    }
    file.sync_all().unwrap();
    assert!(file.metadata().unwrap().blocks() * 512 >= 64 << 20);
    assert_eq!(unsafe { libc::syncfs(file.as_raw_fd()) }, 0);
    drop(file);
    let mut policy = native_node::tests::policy();
    policy.control.headroom_bytes = fs2::available_space(root)
        .unwrap()
        .checked_sub(8 << 20)
        .unwrap();
    let seed = Seed::from_bytes([120; 32]);
    let keys = Arc::new(KeyMaterial::from_seed(&seed));
    let data = root.join("node");
    drop(crate::Node::create_native(&data, seed, policy).unwrap());
    let directory = DatabaseDirectory::open(&data).unwrap();
    let control = ControlStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
    )
    .unwrap();
    control
        .put_record("headroom-original", b"one", b"original data")
        .unwrap();
    let mut volumes = StorageVolumes::open(&data, keys.clone(), &control).unwrap();
    let object = VariableParityObject {
        format_version: 2,
        guild_id: [121; 32],
        group_id: [122; 32],
        shard_index: 4,
        bytes: vec![123; 4 << 20],
        commitment: mb_core::merkle_commit(&vec![123; 4 << 20]).unwrap(),
    };
    let attempt = [124; 16];
    let receipt = SignedRecord::sign(
        STAGED_STORAGE_RECEIPT_DOMAIN,
        StagedStorageReceipt {
            format_version: 1,
            attempt_id: attempt,
            plan_hash: [125; 32],
            guild_id: object.guild_id,
            group_id: object.group_id,
            shard_index: object.shard_index,
            holder: keys.node_id(),
            commitment: object.commitment.clone(),
        },
        &keys,
    )
    .unwrap();
    receipt.verify(STAGED_STORAGE_RECEIPT_DOMAIN).unwrap();
    let receipt_bytes = canonical_bytes(&receipt).unwrap();
    let id = attempt_volume_object_id(&attempt, &object.group_id, object.shard_index as u8);
    let result = volumes.stage_attempt(&control, &attempt, &object, &receipt_bytes);
    let used = volumes
        .volumes
        .values()
        .filter_map(|v| v.store.as_ref())
        .map(|s| s.used_bytes().unwrap())
        .sum::<u64>();
    eprintln!("CONTROL_HEADROOM_STAGE result={result:?} staged_bytes={used}");
    assert!(
        matches!(result,Err(ref e) if matches!(e.downcast_ref::<DatabaseError>(),Some(DatabaseError::CapacityExceeded))),
        "unfunded staging must refuse before writing: {result:?}"
    );
    assert_eq!(used, 0, "unfunded preflight left parity payloads");
    for kind in ["volume-attempt-intent", "volume-attempt-receipt"] {
        assert!(control.get_record(kind, &id).unwrap().is_none());
    }
    control
        .put_record(
            "headroom-original",
            b"two",
            b"ordinary retry remains healthy",
        )
        .unwrap();
    fs::remove_file(pressure).unwrap();
    assert_eq!(unsafe { libc::syncfs(filesystem.as_raw_fd()) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while fs2::available_space(root).unwrap() < policy.control.headroom_bytes + (48 << 20) {
        assert!(
            std::time::Instant::now() < deadline,
            "released blocks did not return"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    volumes
        .stage_attempt(&control, &attempt, &object, &receipt_bytes)
        .unwrap();
    drop((volumes, control));
    let control = ControlStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
    )
    .unwrap();
    let volumes = StorageVolumes::open(&data, keys, &control).unwrap();
    let parity = volumes
        .volumes
        .values()
        .find_map(|v| v.store.as_ref())
        .unwrap();
    assert_eq!(
        parity
            .load_attempt_receipt(&attempt, &object.group_id, object.shard_index)
            .unwrap(),
        receipt_bytes
    );
    let proof = parity
        .open_attempt_range(
            &attempt,
            &object.group_id,
            object.shard_index,
            0,
            (object.bytes.len() / mb_core::MERKLE_LEAF_SIZE) as u32,
        )
        .unwrap();
    mb_core::merkle_verify_range(&object.commitment, &proof).unwrap();
    assert_eq!(
        proof.leaves.iter().flatten().copied().collect::<Vec<_>>(),
        object.bytes
    );
    assert_eq!(
        control.native_database_owner().unwrap().policy(),
        policy.control
    );
    assert_eq!(
        control.get_record("headroom-original", b"one").unwrap(),
        Some(b"original data".to_vec())
    );
    assert_eq!(
        control.get_record("headroom-original", b"two").unwrap(),
        Some(b"ordinary retry remains healthy".to_vec())
    );
}
