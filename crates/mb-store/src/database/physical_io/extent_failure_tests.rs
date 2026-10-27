use super::*;
use std::os::unix::fs::FileExt;

struct FailureFixture(Option<tempfile::TempDir>);
impl Drop for FailureFixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "NATIVE_EXTENT_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

fn extent_tree_refusal(role: Role, during_write: bool) {
    let fixture = FailureFixture(Some(tempfile::tempdir().unwrap()));
    let temp = fixture.0.as_ref().unwrap();
    let directory = DatabaseDirectory::open(temp.path()).unwrap();
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    assert_eq!(
        unsafe { libc::fstatfs(directory.file().as_raw_fd(), filesystem.as_mut_ptr()) },
        0
    );
    if unsafe { filesystem.assume_init() }.f_type as u32 != libc::EXT4_SUPER_MAGIC as u32 {
        // The fifth-extent metadata transition exercised here is ext4-specific.
        return;
    }
    let allocated_chunks = if during_write { 8 } else { 7 };
    let mut prepared = None;
    for attempt in 0..32 {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(temp.path().join(format!("extent-{attempt}")))
            .unwrap();
        assert_eq!(
            unsafe {
                libc::fallocate(
                    file.as_raw_fd(),
                    libc::FALLOC_FL_KEEP_SIZE,
                    0,
                    allocated_chunks * CHUNK as i64,
                )
            },
            0
        );
        file.write_all_at(&vec![0x31; CHUNK as usize], CHUNK)
            .unwrap();
        if !during_write {
            file.write_all_at(&vec![0x72; CHUNK as usize], 6 * CHUNK)
                .unwrap();
        }
        file.sync_all().unwrap();
        let map = read_extents(file.as_raw_fd(), 0, u64::MAX).unwrap();
        if map.mapped == (if during_write { 3 } else { 4 })
            && file.metadata().unwrap().blocks() * 512 == allocated_chunks as u64 * CHUNK
        {
            prepared = Some((file, format!("extent-{attempt}")));
            break;
        }
    }
    let (file, name) = prepared.expect("prepare four extents stored in the ext4 inode");
    let mut before = vec![0; file.metadata().unwrap().len() as usize];
    file.read_exact_at(&mut before, 0).unwrap();
    let limits = DatabasePhysicalIoLimits {
        main_bytes: 8 * CHUNK,
        journal_bytes: 8 * CHUNK,
        shm_bytes: CHUNK,
        temporary_bytes: 8 * CHUNK,
        total_bytes: 8 * CHUNK,
        headroom_bytes: 0,
        files: 4,
    };
    let pool = Pool::new(&directory, OsStr::new(&name), limits).unwrap();
    if role == Role::Main {
        pool.pin_created_main(&file).unwrap();
    }
    let mut binding = unsafe { pool.bind(file.as_raw_fd(), role) }.unwrap();
    if role == Role::Main {
        binding.initialize_main().unwrap();
    }
    assert_eq!(pool.usage().unwrap(), allocated_chunks as u64 * CHUNK);
    // The data allocation fits exactly. Its fifth extent also needs a metadata
    // block, so the actual allocation must be refused without poisoning retry.
    let error = if during_write {
        binding.fund(6 * CHUNK, 7 * CHUNK).unwrap();
        file.write_all_at(&vec![0x72; CHUNK as usize], 6 * CHUNK)
            .unwrap();
        file.sync_all().unwrap();
        before.resize((7 * CHUNK) as usize, 0);
        before[(6 * CHUNK) as usize..].fill(0x72);
        binding.refresh_after_io().unwrap_err()
    } else {
        binding.fund(7 * CHUNK, 8 * CHUNK).unwrap_err()
    };
    assert!(
        matches!(error, DatabaseError::CapacityExceeded),
        "{error:?}"
    );
    let metadata = file.metadata().unwrap();
    eprintln!(
        "EXT4_EXTENT_TREE_REFUSAL role={role:?} length={} allocated={}",
        metadata.len(),
        metadata.blocks() * 512
    );
    assert!(pool.usage().unwrap() <= limits.total_bytes);
    assert_eq!(metadata.len(), before.len() as u64);
    let mut after = vec![0; before.len()];
    file.read_exact_at(&mut after, 0).unwrap();
    assert_eq!(after, before);
    binding.fund(CHUNK, CHUNK + 4096).unwrap();
    file.write_all_at(&[0x43; 4096], CHUNK).unwrap();
    binding.refresh_after_io().unwrap();
    file.read_exact_at(&mut after, 0).unwrap();
    before[CHUNK as usize..CHUNK as usize + 4096].fill(0x43);
    assert_eq!(after, before);
    assert!(pool.usage().unwrap() <= limits.total_bytes);
    drop(file);
    binding.close().unwrap();
}

#[test]
fn ext4_main_extent_tree_refusal_reclaims_only_unused_tail() {
    extent_tree_refusal(Role::Main, false);
}

#[test]
fn ext4_journal_extent_tree_refusal_reclaims_only_unused_tail() {
    extent_tree_refusal(Role::Journal, false);
}

#[test]
fn ext4_temporary_extent_tree_refusal_reclaims_only_unused_tail() {
    extent_tree_refusal(Role::Temporary, false);
}

#[test]
fn ext4_main_extent_tree_write_refusal_preserves_written_bytes() {
    extent_tree_refusal(Role::Main, true);
}

#[test]
fn ext4_journal_extent_tree_write_refusal_preserves_written_bytes() {
    extent_tree_refusal(Role::Journal, true);
}

#[test]
fn ext4_temporary_extent_tree_write_refusal_preserves_written_bytes() {
    extent_tree_refusal(Role::Temporary, true);
}
