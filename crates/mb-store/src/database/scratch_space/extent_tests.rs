use super::*;

struct Fixture(Option<tempfile::TempDir>);
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "SCRATCH_EXTENT_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

fn extent_metadata_refusal(during_write: bool, limit_chunks: u64, blocked_headroom: bool) {
    let fixture = Fixture(Some(tempfile::tempdir().unwrap()));
    let directory = fixture.0.as_ref().unwrap().path();
    let mut vfs = ScratchVfs::new(directory, limit_chunks * CHUNK, 0, &[]).unwrap();
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    assert_eq!(
        unsafe { libc::fstatfs(vfs._state.directory.as_raw_fd(), filesystem.as_mut_ptr()) },
        0
    );
    if unsafe { filesystem.assume_init() }.f_type as u32 != libc::EXT4_SUPER_MAGIC as u32 {
        return;
    }
    // Use a linked disposable file so failed-run bytes survive descriptor close.
    // Production scratch uses the same DiskFile methods with anonymous files.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(directory.join("scratch-extents"))
        .unwrap();
    let chunks = if during_write { 8 } else { 7 };
    assert_eq!(
        unsafe {
            libc::fallocate(
                file.as_raw_fd(),
                libc::FALLOC_FL_KEEP_SIZE,
                0,
                (chunks * CHUNK) as i64,
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
    if blocked_headroom {
        // Keep EOF at the full reservation so tail cleanup cannot conceal
        // an unfunded metadata block by freeing unused data extents.
        file.set_len(8 * CHUNK).unwrap();
    }
    file.sync_all().unwrap();
    assert_eq!(file.metadata().unwrap().blocks() * 512, chunks * CHUNK);
    *vfs._state.allocated_bytes.lock().unwrap() = chunks * CHUNK;
    let mut output = SqlFile {
        base: ffi::sqlite3_file { pMethods: &METHODS },
        arena: None,
        disk: Some(Box::new(DiskFile {
            file,
            state: &mut *vfs._state,
            allocated: chunks * CHUNK,
            charged: chunks * CHUNK,
            physical_bytes: chunks * CHUNK,
            headroom_pending: false,
        })),
    };
    let mut expected =
        vec![0; output.disk.as_ref().unwrap().file.metadata().unwrap().len() as usize];
    output
        .disk
        .as_ref()
        .unwrap()
        .file
        .read_exact_at(&mut expected, 0)
        .unwrap();
    let pointer = (&mut output as *mut SqlFile).cast();
    if blocked_headroom {
        // Model a loss of available space after the original data funding.
        // Increasing required headroom has the same admission effect without
        // consuming the host filesystem's free space in an ordinary unit test.
        vfs._state.headroom_bytes = u64::MAX;
    }
    if during_write {
        let bytes = vec![0x72u8; CHUNK as usize];
        let result = unsafe {
            write(
                pointer,
                bytes.as_ptr().cast(),
                CHUNK as c_int,
                (6 * CHUNK) as i64,
            )
        };
        assert!([ffi::SQLITE_OK, ffi::SQLITE_FULL].contains(&result));
        let synced = unsafe { sync(pointer, 0) };
        if limit_chunks == 8 || blocked_headroom {
            assert!(
                result == ffi::SQLITE_FULL || synced == ffi::SQLITE_FULL,
                "extent-tree metadata must not be admitted: write={result} sync={synced}"
            );
        } else {
            assert_eq!((result, synced), (ffi::SQLITE_OK, ffi::SQLITE_OK));
        }
        expected.resize(expected.len().max((7 * CHUNK) as usize), 0);
        expected[(6 * CHUNK) as usize..(7 * CHUNK) as usize].fill(0x72);
    } else {
        assert_eq!(
            output.disk.as_mut().unwrap().allocate(8 * CHUNK),
            if limit_chunks == 8 {
                ffi::SQLITE_FULL
            } else {
                ffi::SQLITE_OK
            },
            "admission must include the fifth extent's metadata block"
        );
    }
    if blocked_headroom {
        let disk = output.disk.as_mut().unwrap();
        assert_eq!(
            disk.refresh(),
            ffi::SQLITE_FULL,
            "retry must retain headroom debt"
        );
        assert_eq!(
            disk.refresh(),
            ffi::SQLITE_FULL,
            "repeated retry must remain refused"
        );
        vfs._state.headroom_bytes = 0;
        assert_eq!(
            disk.refresh(),
            ffi::SQLITE_OK,
            "restored headroom permits retry"
        );
    }
    if limit_chunks > 8 && !blocked_headroom {
        assert!(
            output
                .disk
                .as_ref()
                .unwrap()
                .file
                .metadata()
                .unwrap()
                .blocks()
                * 512
                > 8 * CHUNK
        );
        // Rounded data bytes are now smaller than the actual metadata charge.
        // Regrowth must not subtract those unsigned values in the wrong order.
        assert_eq!(
            unsafe { truncate(pointer, (8 * CHUNK - 1) as i64) },
            ffi::SQLITE_OK
        );
        expected.resize((8 * CHUNK - 1) as usize, 0);
        assert_eq!(
            output.disk.as_mut().unwrap().allocate(8 * CHUNK),
            ffi::SQLITE_OK
        );
        let first_charge = *vfs._state.allocated_bytes.lock().unwrap();
        let mut peer = std::mem::MaybeUninit::<SqlFile>::uninit();
        assert_eq!(
            unsafe {
                open(
                    &mut *vfs.vfs,
                    ptr::null(),
                    peer.as_mut_ptr().cast(),
                    ffi::SQLITE_OPEN_TEMP_DB
                        | ffi::SQLITE_OPEN_DELETEONCLOSE
                        | ffi::SQLITE_OPEN_READWRITE
                        | ffi::SQLITE_OPEN_CREATE,
                    ptr::null_mut(),
                )
            },
            ffi::SQLITE_OK
        );
        let mut peer = unsafe { peer.assume_init() };
        assert_eq!(
            peer.disk.as_mut().unwrap().allocate(2 * CHUNK),
            ffi::SQLITE_FULL
        );
        assert_eq!(
            peer.disk
                .as_ref()
                .unwrap()
                .file
                .metadata()
                .unwrap()
                .blocks(),
            0
        );
        assert_eq!(peer.disk.as_mut().unwrap().allocate(CHUNK), ffi::SQLITE_OK);
        assert_eq!(
            unsafe { close((&mut peer as *mut SqlFile).cast()) },
            ffi::SQLITE_OK
        );
        assert_eq!(*vfs._state.allocated_bytes.lock().unwrap(), first_charge);
    }
    let disk = output.disk.as_ref().unwrap();
    let metadata = disk.file.metadata().unwrap();
    assert_eq!(metadata.len(), expected.len() as u64);
    let actual = metadata.blocks() * 512;
    let charged = *vfs._state.allocated_bytes.lock().unwrap();
    assert!(
        actual <= charged && charged <= limit_chunks * CHUNK,
        "actual={actual} charged={charged}"
    );
    let mut bytes = vec![0; expected.len()];
    disk.file.read_exact_at(&mut bytes, 0).unwrap();
    assert!(bytes == expected, "visible scratch bytes must be preserved");
    assert_eq!(
        unsafe { write(pointer, b"x".as_ptr().cast(), 1, CHUNK as i64) },
        ffi::SQLITE_OK
    );
    expected[CHUNK as usize] = b'x';
    output
        .disk
        .as_ref()
        .unwrap()
        .file
        .read_exact_at(&mut bytes, 0)
        .unwrap();
    assert!(bytes == expected, "visible scratch bytes must be preserved");
    assert_eq!(unsafe { truncate(pointer, 0) }, ffi::SQLITE_OK);
    assert_eq!(*vfs._state.allocated_bytes.lock().unwrap(), 0);
    assert_eq!(
        unsafe { write(pointer, b"retry".as_ptr().cast(), 5, 0) },
        ffi::SQLITE_OK
    );
    assert_eq!(unsafe { close(pointer) }, ffi::SQLITE_OK);
    assert_eq!(*vfs._state.allocated_bytes.lock().unwrap(), 0);
}

#[test]
fn ext4_scratch_allocation_metadata_refuses_and_reclaims_unused_tail() {
    extent_metadata_refusal(false, 8, false);
}

#[test]
fn ext4_scratch_write_metadata_refuses_and_preserves_visible_bytes() {
    extent_metadata_refusal(true, 8, false);
}

#[test]
fn ext4_scratch_extent_metadata_is_charged_across_files_and_partial_truncation() {
    extent_metadata_refusal(false, 10, false);
}

#[test]
fn ext4_scratch_write_metadata_with_room_remains_usable() {
    extent_metadata_refusal(true, 10, false);
}

#[test]
fn ext4_scratch_metadata_headroom_refusal_survives_retry_until_space_returns() {
    extent_metadata_refusal(true, 10, true);
}
