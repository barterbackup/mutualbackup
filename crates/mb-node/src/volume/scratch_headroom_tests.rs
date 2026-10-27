use super::*;
use mb_core::{NativeDatabaseIoPolicy, Seed};
use mb_store::DatabaseDirectory;
use std::ffi::OsStr;
use std::os::fd::AsRawFd;

struct Fixture(Option<tempfile::TempDir>);
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "NATIVE_SCRATCH_HEADROOM_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

#[test]
#[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
fn paged_scratch_preserves_native_control_headroom_and_retries_after_space_returns() {
    let root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT").expect("provisioned filesystem");
    let fixture = Fixture(Some(tempfile::tempdir_in(root).unwrap()));
    let root = fixture.0.as_ref().unwrap().path();
    let filesystem = File::open(root).unwrap();
    assert_eq!(unsafe { libc::syncfs(filesystem.as_raw_fd()) }, 0);
    let pressure = root.join("space-pressure");
    let mut file = File::create(&pressure).unwrap();
    let block = vec![0; 1024 * 1024];
    for _ in 0..64 {
        file.write_all(&block).unwrap();
    }
    file.sync_all().unwrap();
    assert!(file.metadata().unwrap().blocks() * 512 >= 64 << 20);
    assert_eq!(unsafe { libc::syncfs(file.as_raw_fd()) }, 0);
    drop(file);
    let available = fs2::available_space(root).unwrap();
    let policy = NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [97; 16],
        main_bytes: 16 << 20,
        journal_bytes: 16 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 16 << 20,
        total_bytes: 64 << 20,
        headroom_bytes: available.checked_sub(16 << 20).unwrap(),
        files: 32,
    };
    let keys = KeyMaterial::from_seed(&Seed::from_bytes([97; 32]));
    let directory = DatabaseDirectory::open(root).unwrap();
    let control = ControlStore::create_native_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
        policy,
    )
    .unwrap();
    control
        .put_record("headroom-original", b"one", b"original data")
        .unwrap();
    let scratch = paged_scratch_store(&control, 64 << 20).unwrap();
    let payload = vec![7; 1024 * 1024];
    let populate = |scratch: &mb_store::RecordScratchStore| -> Result<(), DatabaseError> {
        scratch.with_record_transaction(|| {
            for index in 0u8..32 {
                if !scratch.put_record_if_absent("scratch", &[index], &payload)? {
                    return Err(DatabaseError::Conflict);
                }
            }
            Ok(())
        })
    };
    let result = populate(&scratch);
    eprintln!(
        "NATIVE_SCRATCH_HEADROOM declared={} available_after={}",
        policy.headroom_bytes,
        fs2::available_space(root).unwrap()
    );
    assert!(
        // SQLITE_FULL is 13; keep this assertion exact without adding a direct
        // rusqlite dependency to the Node crate for the regression.
        matches!(result, Err(DatabaseError::Sql(ref e)) if e.sqlite_error().is_some_and(|e| e.extended_code == 13)),
        "scratch consumed native control headroom: {result:?}"
    );
    drop(scratch);
    control
        .put_record(
            "headroom-original",
            b"two",
            b"ordinary writer remains healthy",
        )
        .unwrap();
    fs::remove_file(pressure).unwrap();
    // Btrfs frees unlinked extents at transaction commit. Commit the owned
    // fixture filesystem before requiring physical capacity for the retry.
    assert_eq!(unsafe { libc::syncfs(directory.file().as_raw_fd()) }, 0);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    while fs2::available_space(root).unwrap() < policy.headroom_bytes + (48 << 20) {
        assert!(
            std::time::Instant::now() < deadline,
            "released blocks did not return"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let scratch = paged_scratch_store(&control, 64 << 20).unwrap();
    populate(&scratch).unwrap();
    for index in 0u8..32 {
        assert_eq!(
            scratch
                .get_record_bounded("scratch", &[index], payload.len())
                .unwrap()
                .as_deref(),
            Some(payload.as_slice())
        );
    }
    drop(scratch);
    drop(control);
    let control = ControlStore::open_native_existing_in_directory(
        &directory,
        OsStr::new("control.db"),
        &keys,
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(control.native_database_owner().unwrap().policy(), policy);
    assert_eq!(
        control.get_record("headroom-original", b"one").unwrap(),
        Some(b"original data".to_vec())
    );
    assert_eq!(
        control.get_record("headroom-original", b"two").unwrap(),
        Some(b"ordinary writer remains healthy".to_vec())
    );
}
