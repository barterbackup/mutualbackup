use super::*;

struct Fixture {
    directory: Option<tempfile::TempDir>,
    file: File,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            // A duplicate keeps the anonymous inode alive through capture even
            // if the failed operation already dropped its Arena owner.
            let root = self.directory.as_ref().unwrap().path();
            let capture = || -> io::Result<()> {
                let output = File::create(root.join("arena-raw"))?;
                let mut offset = 0;
                let mut buffer = [0; 65536];
                loop {
                    let count = self.file.read_at(&mut buffer, offset)?;
                    if count == 0 {
                        break;
                    }
                    output.write_all_at(&buffer[..count], offset)?;
                    offset += count as u64;
                }
                output.sync_all()
            };
            if let Err(error) = capture() {
                eprintln!("arena capture failed: {error}");
            }
            eprintln!(
                "FUNDED_ARENA_NEGATIVE_FIXTURE {}",
                self.directory.take().unwrap().keep().display()
            );
        }
    }
}
fn setup() -> (Arena, Fixture) {
    let directory = tempfile::tempdir().unwrap();
    let vfs = ScratchVfs::new(directory.path(), 2 << 20, 0, &[]).unwrap();
    let arena = Arena::new(&vfs._state).unwrap();
    let file = arena.file.try_clone().unwrap();
    (
        arena,
        Fixture {
            directory: Some(directory),
            file,
        },
    )
}

#[test]
fn radix_pages_cross_node_boundaries_prune_and_reuse_without_stale_bytes() {
    let (mut arena, _fixture) = setup();
    assert_eq!(arena.levels, 2);
    let mut file = ArenaFile::new(ptr::null());
    file.reserve(&mut arena, 300 * PAGE as u64).unwrap();
    for index in [0, 101, 102, 299] {
        file.root = arena
            .replace(file.root, arena.levels, index, &[index as u8; PAGE])
            .unwrap();
    }
    for index in [0, 101, 102, 299] {
        assert_eq!(
            arena
                .read(arena.leaf(file.root, arena.levels, index).unwrap(), 0)
                .unwrap(),
            [index as u8; PAGE]
        );
    }
    file.root = arena.prune(file.root, arena.levels, 103).unwrap();
    file.allocated = 103;
    file.reserve(&mut arena, 300 * PAGE as u64).unwrap();
    assert_eq!(
        arena
            .read(arena.leaf(file.root, arena.levels, 102).unwrap(), 0)
            .unwrap(),
        [102; PAGE]
    );
    assert_eq!(
        arena
            .read(arena.leaf(file.root, arena.levels, 299).unwrap(), 0)
            .unwrap(),
        [0; PAGE]
    );
    let before = (arena.used, file.root.id, file.root.hash);
    let beyond_capacity = (arena.pages + 1) * PAGE as u64;
    assert_eq!(
        file.reserve(&mut arena, beyond_capacity),
        Err(ffi::SQLITE_FULL)
    );
    assert_eq!((arena.used, file.root.id, file.root.hash), before);
    file.root = arena.prune(file.root, arena.levels, 0).unwrap();
    assert_eq!(file.root.id, 0);
    assert_eq!(arena.used, 0);
    arena.check().unwrap();
}

#[test]
fn complete_pool_exhaustion_is_atomic_and_recycled_pages_are_zeroed() {
    let (mut arena, _fixture) = setup();
    let first = arena.allocate(0).unwrap();
    arena.write(first.id, 0, &[0x72; PAGE]).unwrap();
    while arena.used < arena.pages {
        arena.allocate(0).unwrap();
    }
    let before = (
        arena.used,
        arena.frontier,
        arena.recycled.id,
        arena.recycled.hash,
    );
    assert!(matches!(arena.allocate(0), Err(ffi::SQLITE_FULL)));
    assert_eq!(
        (
            arena.used,
            arena.frontier,
            arena.recycled.id,
            arena.recycled.hash
        ),
        before
    );
    arena.release(first.id).unwrap();
    let recycled = arena.allocate(0).unwrap();
    assert_eq!(recycled.id, first.id);
    assert_eq!(arena.read(recycled, 0).unwrap(), [0; PAGE]);
    arena.check().unwrap();
}

#[test]
fn corrupted_mapping_node_is_rejected_before_following_its_pointer() {
    let (mut arena, _fixture) = setup();
    let mut file = ArenaFile::new(ptr::null());
    file.reserve(&mut arena, PAGE as u64).unwrap();
    let before = arena.used;
    arena
        .file
        .write_all_at(&[0xff], arena.offset(file.root.id).unwrap())
        .unwrap();
    assert!(matches!(
        arena.leaf(file.root, arena.levels, 0),
        Err(ffi::SQLITE_IOERR_DATA)
    ));
    assert_eq!(arena.used, before);
}

#[test]
fn corrupted_recycled_chain_is_rejected_without_granting_or_losing_a_page() {
    let (mut arena, _fixture) = setup();
    let first = arena.allocate(0).unwrap();
    let second = arena.allocate(0).unwrap();
    arena.release(first.id).unwrap();
    arena.release(second.id).unwrap();
    let before = (
        arena.used,
        arena.frontier,
        arena.recycled.id,
        arena.recycled.hash,
    );
    arena
        .file
        .write_all_at(&[0xff], arena.offset(arena.recycled.id).unwrap())
        .unwrap();
    assert!(matches!(arena.allocate(0), Err(ffi::SQLITE_IOERR_DATA)));
    assert_eq!(
        (
            arena.used,
            arena.frontier,
            arena.recycled.id,
            arena.recycled.hash
        ),
        before
    );
}

#[test]
fn corrupted_data_is_rejected_by_the_current_mapping_commitment() {
    let (mut arena, _fixture) = setup();
    let root = arena.allocate(0).unwrap();
    arena
        .file
        .write_all_at(&[0xff], arena.offset(root.id).unwrap())
        .unwrap();
    assert!(matches!(arena.read(root, 0), Err(ffi::SQLITE_IOERR_DATA)));
}
