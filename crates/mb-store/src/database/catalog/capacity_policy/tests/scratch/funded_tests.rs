use super::*;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

struct Fixture {
    directory: Option<tempfile::TempDir>,
    store: Option<ControlStore>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.take();
        if std::thread::panicking() {
            eprintln!(
                "FUNDED_SCRATCH_NEGATIVE_FIXTURE {}",
                self.directory.take().unwrap().keep().display()
            );
        }
    }
}
fn fixture() -> Fixture {
    let (directory, store) = setup();
    Fixture {
        directory: Some(directory),
        store: Some(store),
    }
}
fn anonymous(root: &std::path::Path) -> Vec<(std::path::PathBuf, std::fs::Metadata)> {
    std::fs::read_dir("/proc/self/fd")
        .unwrap()
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let target = std::fs::read_link(&path).ok()?;
            if !target.starts_with(root)
                || !target
                    .as_os_str()
                    .as_encoded_bytes()
                    .ends_with(b" (deleted)")
            {
                return None;
            }
            Some((path.clone(), std::fs::metadata(path).ok()?))
        })
        .collect()
}
fn blocks(root: &std::path::Path) -> u64 {
    anonymous(root).iter().map(|(_, m)| m.blocks() * 512).sum()
}
fn preserve_anonymous(root: &std::path::Path) {
    let entries = anonymous(root);
    let mut inventory = String::new();
    for (index, (fd, metadata)) in entries.iter().enumerate() {
        let path = root.join(format!("anonymous-raw-{index}"));
        let mut source = std::fs::File::open(fd).unwrap();
        let mut copy = std::fs::File::create(&path).unwrap();
        let mut buffer = [0; 65536];
        loop {
            let count = source.read(&mut buffer).unwrap();
            if count == 0 {
                break;
            }
            copy.write_all(&buffer[..count]).unwrap();
        }
        copy.sync_all().unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        inventory.push_str(&format!(
            "{} length={} blocks={}\n",
            path.display(),
            metadata.len(),
            metadata.blocks()
        ));
    }
    std::fs::write(root.join("anonymous-inventory.txt"), inventory).unwrap();
}

#[test]
fn resource_scratch_owns_its_full_backing_before_records_and_keeps_it_through_rollback() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let limits = ScratchStorageLimits::for_database(2 << 20).unwrap();
    control
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = control
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let scratch =
        RecordScratchStore::new_in_with_reserved_checkpoint_space(root, limits, &[], lease)
            .unwrap();
    let _snapshot = SnapshotOnPanic(root);
    let owned = blocks(root);
    assert!(
        owned >= limits.max_physical_bytes - 2 * 65536,
        "backing={owned} declaration={}",
        limits.max_physical_bytes
    );
    assert!(owned <= limits.max_physical_bytes);
    let original = vec![0x31u8; 1 << 20];
    scratch
        .put_record_if_absent("funded", b"original", &original)
        .unwrap();
    let result: Result<(), DatabaseError> = scratch.with_record_transaction(|| {
        scratch.put_record_if_absent("funded", b"new", &vec![0x72u8; 512 << 10])?;
        Err(DatabaseError::Conflict)
    });
    assert!(matches!(result, Err(DatabaseError::Conflict)));
    assert_eq!(
        scratch
            .get_record_bounded("funded", b"original", original.len())
            .unwrap(),
        Some(original)
    );
    assert_eq!(
        scratch
            .get_record_bounded("funded", b"new", 512 << 10)
            .unwrap(),
        None
    );
    assert_eq!(
        blocks(root),
        owned,
        "journals consume the existing backing without releasing it"
    );
    drop(scratch);
    assert_eq!(blocks(root), 0);
    assert!(control.reclaim_abandoned_catalog_scratch().unwrap());
    assert_eq!(usage(control), (0, 0));
}

#[test]
fn resource_scratch_refuses_the_full_declaration_before_returning_a_small_writable_index() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let mut limits = ScratchStorageLimits::for_database(2 << 20).unwrap();
    control
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = control
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let directory = std::fs::File::open(root).unwrap();
    let mut space = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    assert_eq!(
        unsafe { libc::fstatvfs(directory.as_raw_fd(), space.as_mut_ptr()) },
        0
    );
    let space = unsafe { space.assume_init() };
    let available = u64::try_from(u128::from(space.f_bavail) * u128::from(space.f_frsize)).unwrap();
    limits.headroom_bytes = available.checked_sub(1 << 20).unwrap();
    let scratch =
        RecordScratchStore::new_in_with_reserved_checkpoint_space(root, limits, &[], lease);
    let _snapshot = SnapshotOnPanic(root);
    assert!(
        scratch.is_err(),
        "a small initial file must not stand in for the full declaration"
    );
    assert_eq!(blocks(root), 0);
    assert_eq!(usage(control), (limits.max_physical_bytes, 1));
    assert!(control.reclaim_abandoned_catalog_scratch().unwrap());
    limits.headroom_bytes = 0;
    let lease = control
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let scratch =
        RecordScratchStore::new_in_with_reserved_checkpoint_space(root, limits, &[], lease)
            .unwrap();
    scratch
        .put_record_if_absent("retry", b"one", b"exact bytes")
        .unwrap();
    assert_eq!(
        scratch.get_record_bounded("retry", b"one", 11).unwrap(),
        Some(b"exact bytes".to_vec())
    );
}

struct SnapshotOnPanic<'a>(&'a std::path::Path);
impl Drop for SnapshotOnPanic<'_> {
    fn drop(&mut self) {
        if std::thread::panicking()
            && std::panic::catch_unwind(|| preserve_anonymous(self.0)).is_err()
        {
            eprintln!("failed to snapshot live anonymous scratch");
        }
    }
}

#[test]
fn funded_scratch_physical_exhaustion_rolls_back_and_reuses_the_same_backing() {
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let mut limits = ScratchStorageLimits::for_database(16 << 20).unwrap();
    limits.max_physical_bytes = 1 << 20;
    control
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = control
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let scratch =
        RecordScratchStore::new_in_with_reserved_checkpoint_space(root, limits, &[], lease)
            .unwrap();
    let _snapshot = SnapshotOnPanic(root);
    let owned = blocks(root);
    let original = vec![0x31u8; 256 << 10];
    scratch
        .put_record_if_absent("funded", b"original", &original)
        .unwrap();
    let result: Result<(), DatabaseError> = scratch.with_record_transaction(|| {
        scratch.put_record_if_absent("funded", b"too-large", &vec![0x72u8; 2 << 20])?;
        Ok(())
    });
    assert!(
        matches!(&result, Err(DatabaseError::Sql(rusqlite::Error::SqliteFailure(error, _))) if error.extended_code == rusqlite::ffi::SQLITE_FULL),
        "{result:?}"
    );
    assert_eq!(
        scratch
            .get_record_bounded("funded", b"original", original.len())
            .unwrap(),
        Some(original)
    );
    assert_eq!(
        scratch
            .get_record_bounded("funded", b"too-large", 2 << 20)
            .unwrap(),
        None
    );
    scratch
        .put_record_if_absent("funded", b"retry", &vec![0x13u8; 16384])
        .unwrap();
    assert_eq!(
        scratch
            .get_record_bounded("funded", b"retry", 16384)
            .unwrap(),
        Some(vec![0x13; 16384])
    );
    assert_eq!(blocks(root), owned);
    drop(scratch);
    assert_eq!(blocks(root), 0);
}

struct RawFile(Vec<usize>);
impl RawFile {
    fn pointer(&mut self) -> *mut rusqlite::ffi::sqlite3_file {
        self.0.as_mut_ptr().cast()
    }
    fn new(vfs: &crate::database::scratch_space::ScratchVfs) -> Self {
        let name = std::ffi::CString::new(vfs.name()).unwrap();
        let vfs = unsafe { rusqlite::ffi::sqlite3_vfs_find(name.as_ptr()) };
        assert!(!vfs.is_null());
        let words = unsafe { (*vfs).szOsFile as usize }.div_ceil(std::mem::size_of::<usize>());
        let mut file = Self(vec![0; words]);
        let flags = rusqlite::ffi::SQLITE_OPEN_TEMP_DB
            | rusqlite::ffi::SQLITE_OPEN_DELETEONCLOSE
            | rusqlite::ffi::SQLITE_OPEN_CREATE
            | rusqlite::ffi::SQLITE_OPEN_READWRITE;
        assert_eq!(
            unsafe {
                (*vfs).xOpen.unwrap()(
                    vfs,
                    std::ptr::null(),
                    file.pointer(),
                    flags,
                    std::ptr::null_mut(),
                )
            },
            rusqlite::ffi::SQLITE_OK
        );
        file
    }
}
impl Drop for RawFile {
    fn drop(&mut self) {
        unsafe {
            let pointer = self.pointer();
            if !(*pointer).pMethods.is_null() {
                ((*(*pointer).pMethods).xClose.unwrap())(pointer);
            }
        }
    }
}

#[test]
fn inherited_scratch_close_cannot_recycle_its_parents_live_pages() {
    use rusqlite::ffi;
    let fixture = fixture();
    let root = fixture.directory.as_ref().unwrap().path();
    let control = fixture.store.as_ref().unwrap();
    let limits = ScratchStorageLimits::for_database(2 << 20).unwrap();
    control
        .configure_catalog_scratch_pool_policy(pool(limits.max_physical_bytes, 1))
        .unwrap();
    let lease = control
        .reserve_catalog_scratch(limits.max_physical_bytes)
        .unwrap()
        .unwrap();
    let vfs = crate::database::scratch_space::ScratchVfs::new_with_lease(
        root,
        limits.max_physical_bytes,
        0,
        &[],
        Some(lease),
    )
    .unwrap();
    let mut file = RawFile::new(&vfs);
    let _snapshot = SnapshotOnPanic(root);
    let pointer = file.pointer();
    let methods = unsafe { &*(*pointer).pMethods };
    let original = vec![0x31u8; 65536];
    assert_eq!(
        unsafe {
            methods.xWrite.unwrap()(pointer, original.as_ptr().cast(), original.len() as i32, 0)
        },
        ffi::SQLITE_OK
    );
    // The child calls only this VFS method, never SQLite or the inherited
    // connection. It must reject ownership before locking copied allocator RAM.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let result = unsafe { methods.xClose.unwrap()(pointer) };
        unsafe {
            libc::_exit(if result == ffi::SQLITE_IOERR_WRITE {
                0
            } else {
                1
            })
        }
    }
    struct Child(libc::pid_t);
    impl Drop for Child {
        fn drop(&mut self) {
            if self.0 != 0 {
                unsafe {
                    libc::kill(self.0, libc::SIGKILL);
                    libc::waitpid(self.0, std::ptr::null_mut(), 0);
                }
            }
        }
    }
    let mut child = Child(pid);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    let mut status = 0;
    loop {
        let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if result == pid {
            child.0 = 0;
            break;
        }
        assert!(
            result == 0
                || std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
        );
        assert!(
            std::time::Instant::now() < deadline,
            "inherited close did not return"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let mut bytes = vec![0; original.len()];
    let read = unsafe {
        methods.xRead.unwrap()(pointer, bytes.as_mut_ptr().cast(), bytes.len() as i32, 0)
    };
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "child status={status} parent read={read}"
    );
    assert_eq!(read, ffi::SQLITE_OK);
    assert!(
        bytes == original,
        "parent bytes must remain unchanged after inherited close"
    );
    drop(file);
    drop(vfs);
    assert_eq!(blocks(root), 0);
    assert!(control.reclaim_abandoned_catalog_scratch().unwrap());
}
