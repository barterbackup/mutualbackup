//! One physically funded anonymous file for an owned scratch job. SQLite files
//! use authenticated on-disk radix maps and a recycled-page chain. RAM holds
//! only their roots, counters and bounded traversal buffers, not a page table.
use super::*;
#[cfg(test)]
mod tests;

const PAGE: usize = 4096;
const ENTRY: usize = 40;
const FANOUT: u64 = (PAGE / ENTRY) as u64;
type Bytes = [u8; PAGE];
type Result<T> = std::result::Result<T, c_int>;

#[derive(Clone, Copy, Default)]
struct Root {
    // Zero is absent; every other value is the physical page number plus one.
    id: u64,
    hash: [u8; 32],
}
impl Root {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let id = u64::from_le_bytes(bytes[..8].try_into().unwrap());
        let hash = bytes[8..ENTRY].try_into().unwrap();
        if id == 0 && hash != [0; 32] {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        Ok(Self { id, hash })
    }
    fn encode(self, bytes: &mut [u8]) {
        bytes[..8].copy_from_slice(&self.id.to_le_bytes());
        bytes[8..ENTRY].copy_from_slice(&self.hash);
    }
}

pub(super) struct Arena {
    file: File,
    pages: u64,
    frontier: u64,
    recycled: Root,
    used: u64,
    levels: u32,
    physical_bytes: u64,
    hash: blake3::Hasher,
    poisoned: bool,
}

impl Arena {
    pub(super) fn is_idle(&self) -> Result<bool> {
        self.check()?;
        Ok(self.used == 0)
    }

    pub(super) fn new(state: &State) -> Result<Self> {
        let file;
        let mut length = state.max_physical_bytes / CHUNK * CHUNK;
        if length == 0 || length > i64::MAX as u64 {
            return Err(ffi::SQLITE_FULL);
        }
        {
            let _allocation = state.allocation_guard()?;
            if state.available_after_headroom()? < length {
                return Err(ffi::SQLITE_FULL);
            }
            let directory = PathBuf::from(format!("/proc/self/fd/{}", state.directory.as_raw_fd()));
            file =
                tempfile::tempfile_in(directory).map_err(|e| io_code(e, ffi::SQLITE_CANTOPEN))?;
            super::super::physical_io::initialize_private_file(file.as_raw_fd(), 0, 0)
                .map_err(|_| ffi::SQLITE_IOERR)?;
            loop {
                if unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, length as i64) } == 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(io_code(error, ffi::SQLITE_IOERR_WRITE));
                }
            }
        }
        // Fully initialize the held extents. Later writes must neither split
        // unwritten extents nor allocate CoW replacements. Do not hold the host
        // allocation lock across this potentially large sequential write.
        let zero = vec![0; 1024 * 1024];
        let mut offset = 0;
        while offset < length {
            let count = (length - offset).min(zero.len() as u64) as usize;
            file.write_all_at(&zero[..count], offset)
                .map_err(|e| io_code(e, ffi::SQLITE_IOERR_WRITE))?;
            offset += count as u64;
        }
        file.sync_all()
            .map_err(|e| io_code(e, ffi::SQLITE_IOERR_FSYNC))?;
        super::super::physical_io::validate_initialized_private_range(file.as_raw_fd(), 0, length)
            .map_err(|_| ffi::SQLITE_IOERR_DATA)?;
        let _allocation = state.allocation_guard()?;
        let physical_bytes = loop {
            let metadata = file.metadata().map_err(|_| ffi::SQLITE_IOERR_FSTAT)?;
            let actual = metadata.blocks().checked_mul(512).ok_or(ffi::SQLITE_FULL)?;
            if actual <= state.max_physical_bytes {
                break actual;
            }
            let release = (actual - state.max_physical_bytes).div_ceil(CHUNK) * CHUNK;
            length = length
                .checked_sub(release)
                .filter(|n| *n != 0)
                .ok_or(ffi::SQLITE_FULL)?;
            file.set_len(length)
                .map_err(|e| io_code(e, ffi::SQLITE_IOERR_TRUNCATE))?;
            file.sync_all()
                .map_err(|e| io_code(e, ffi::SQLITE_IOERR_FSYNC))?;
        };
        state.available_after_headroom()?;
        let pages = length / PAGE as u64;
        let mut coverage = FANOUT;
        let mut levels = 1;
        while coverage < pages {
            coverage = coverage.checked_mul(FANOUT).ok_or(ffi::SQLITE_FULL)?;
            levels += 1;
        }
        let mut hash =
            blake3::Hasher::new_derive_key("mutualbackup funded anonymous scratch blocks v1");
        hash.update(Uuid::new_v4().as_bytes());
        Ok(Self {
            file,
            pages,
            frontier: 0,
            recycled: Root::default(),
            used: 0,
            levels,
            physical_bytes,
            hash,
            poisoned: false,
        })
    }

    fn offset(&self, id: u64) -> Result<u64> {
        if id == 0 || id > self.pages {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        Ok((id - 1) * PAGE as u64)
    }
    fn digest(&self, id: u64, kind: u8, level: u32, bytes: &[u8]) -> [u8; 32] {
        let mut hash = self.hash.clone();
        hash.update(&id.to_le_bytes());
        hash.update(&[kind]);
        hash.update(&level.to_le_bytes());
        hash.update(bytes);
        *hash.finalize().as_bytes()
    }
    fn read(&self, root: Root, level: u32) -> Result<Bytes> {
        let mut bytes = [0; PAGE];
        self.file
            .read_exact_at(&mut bytes, self.offset(root.id)?)
            .map_err(|e| io_code(e, ffi::SQLITE_IOERR_READ))?;
        if self.digest(root.id, 0, level, &bytes) != root.hash {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        Ok(bytes)
    }
    fn write(&mut self, id: u64, level: u32, bytes: &Bytes) -> Result<Root> {
        let offset = self.offset(id)?;
        super::super::physical_io::validate_initialized_private_range(
            self.file.as_raw_fd(),
            offset,
            offset + PAGE as u64,
        )
        .map_err(|_| ffi::SQLITE_IOERR_DATA)?;
        self.file
            .write_all_at(bytes, offset)
            .map_err(|e| io_code(e, ffi::SQLITE_IOERR_WRITE))?;
        Ok(Root {
            id,
            hash: self.digest(id, 0, level, bytes),
        })
    }
    fn allocate(&mut self, level: u32) -> Result<Root> {
        if self.used == self.pages {
            return Err(ffi::SQLITE_FULL);
        }
        let id;
        if self.recycled.id != 0 {
            id = self.recycled.id;
            let mut bytes = [0; ENTRY];
            self.file
                .read_exact_at(&mut bytes, self.offset(id)?)
                .map_err(|e| io_code(e, ffi::SQLITE_IOERR_READ))?;
            if self.digest(id, 1, 0, &bytes) != self.recycled.hash {
                return Err(ffi::SQLITE_IOERR_DATA);
            }
            let next = Root::decode(&bytes)?;
            if next.id > self.frontier {
                return Err(ffi::SQLITE_IOERR_DATA);
            }
            self.recycled = next;
        } else {
            if self.frontier == self.pages {
                return Err(ffi::SQLITE_IOERR_DATA);
            }
            self.frontier += 1;
            id = self.frontier;
        }
        let root = self.write(id, level, &[0; PAGE])?;
        self.used += 1;
        Ok(root)
    }
    fn release(&mut self, id: u64) -> Result<()> {
        if id > self.frontier || self.used == 0 {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        let mut bytes = [0; ENTRY];
        self.recycled.encode(&mut bytes);
        let offset = self.offset(id)?;
        super::super::physical_io::validate_initialized_private_range(
            self.file.as_raw_fd(),
            offset,
            offset + PAGE as u64,
        )
        .map_err(|_| ffi::SQLITE_IOERR_DATA)?;
        self.file
            .write_all_at(&bytes, offset)
            .map_err(|e| io_code(e, ffi::SQLITE_IOERR_WRITE))?;
        self.recycled = Root {
            id,
            hash: self.digest(id, 1, 0, &bytes),
        };
        self.used -= 1;
        Ok(())
    }
    fn stride(level: u32) -> u64 {
        FANOUT.pow(level - 1)
    }
    fn entry(bytes: &Bytes, index: u64) -> Result<Root> {
        let start = index as usize * ENTRY;
        Root::decode(&bytes[start..start + ENTRY])
    }
    fn set(bytes: &mut Bytes, index: u64, root: Root) {
        let start = index as usize * ENTRY;
        root.encode(&mut bytes[start..start + ENTRY]);
    }
    fn ensure(&mut self, mut root: Root, level: u32, index: u64) -> Result<Root> {
        if root.id == 0 {
            root = self.allocate(level)?;
        }
        if level == 0 {
            return Ok(root);
        }
        let mut bytes = self.read(root, level)?;
        let stride = Self::stride(level);
        let slot = index / stride;
        if slot >= FANOUT {
            return Err(ffi::SQLITE_FULL);
        }
        let child = self.ensure(Self::entry(&bytes, slot)?, level - 1, index % stride)?;
        Self::set(&mut bytes, slot, child);
        self.write(root.id, level, &bytes)
    }
    fn leaf(&self, root: Root, level: u32, index: u64) -> Result<Root> {
        if root.id == 0 {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        if level == 0 {
            return Ok(root);
        }
        let bytes = self.read(root, level)?;
        let stride = Self::stride(level);
        let slot = index / stride;
        if slot >= FANOUT {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        self.leaf(Self::entry(&bytes, slot)?, level - 1, index % stride)
    }
    fn replace(&mut self, root: Root, level: u32, index: u64, data: &Bytes) -> Result<Root> {
        if level == 0 {
            return self.write(root.id, 0, data);
        }
        let mut bytes = self.read(root, level)?;
        let stride = Self::stride(level);
        let slot = index / stride;
        let child = self.replace(Self::entry(&bytes, slot)?, level - 1, index % stride, data)?;
        Self::set(&mut bytes, slot, child);
        self.write(root.id, level, &bytes)
    }
    fn prune(&mut self, root: Root, level: u32, keep: u64) -> Result<Root> {
        if root.id == 0 {
            return Ok(root);
        }
        if level == 0 {
            if keep == 0 {
                self.release(root.id)?;
                return Ok(Root::default());
            }
            return Ok(root);
        }
        let mut bytes = self.read(root, level)?;
        let stride = Self::stride(level);
        let mut any = false;
        for slot in 0..FANOUT {
            let child = Self::entry(&bytes, slot)?;
            if child.id == 0 {
                continue;
            }
            let retained = keep.saturating_sub(slot * stride).min(stride);
            let child = if retained < stride {
                self.prune(child, level - 1, retained)?
            } else {
                child
            };
            Self::set(&mut bytes, slot, child);
            any |= child.id != 0;
        }
        if any {
            self.write(root.id, level, &bytes)
        } else {
            self.release(root.id)?;
            Ok(Root::default())
        }
    }
    fn check(&self) -> Result<()> {
        if self.poisoned {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        let metadata = self.file.metadata().map_err(|_| ffi::SQLITE_IOERR_FSTAT)?;
        if metadata.len() != self.pages * PAGE as u64
            || metadata.blocks().checked_mul(512) != Some(self.physical_bytes)
        {
            return Err(ffi::SQLITE_IOERR_DATA);
        }
        Ok(())
    }
    fn metadata_pages(&self, count: u64) -> u64 {
        let mut result = 0;
        let mut count = count;
        for _ in 0..self.levels {
            count = count.div_ceil(FANOUT);
            result += count;
        }
        result
    }
}

pub(super) struct ArenaFile {
    state: *const State,
    root: Root,
    allocated: u64,
    length: u64,
}
impl ArenaFile {
    pub(super) fn new(state: *const State) -> Self {
        Self {
            state,
            root: Root::default(),
            allocated: 0,
            length: 0,
        }
    }
    fn operate<T>(
        &mut self,
        writable: bool,
        operation: impl FnOnce(&mut Self, &mut Arena) -> Result<T>,
    ) -> Result<T> {
        let state = unsafe { &*self.state };
        if writable {
            state
                .lease
                .as_ref()
                .ok_or(ffi::SQLITE_IOERR_WRITE)?
                .check(state.max_physical_bytes)
                .map_err(|_| ffi::SQLITE_IOERR_WRITE)?;
        }
        let mut arena = state
            .arena
            .as_ref()
            .ok_or(ffi::SQLITE_IOERR)?
            .lock()
            .map_err(|_| ffi::SQLITE_IOERR)?;
        arena.check()?;
        let result = operation(self, &mut arena);
        if result.as_ref().is_err_and(|code| *code != ffi::SQLITE_FULL) {
            arena.poisoned = true;
        }
        arena.check()?;
        result
    }
    fn reserve(&mut self, arena: &mut Arena, end: u64) -> Result<()> {
        let target = end.div_ceil(PAGE as u64);
        if target <= self.allocated {
            return Ok(());
        }
        let extra = target
            .checked_sub(self.allocated)
            .and_then(|n| {
                n.checked_add(
                    arena
                        .metadata_pages(target)
                        .checked_sub(arena.metadata_pages(self.allocated))?,
                )
            })
            .ok_or(ffi::SQLITE_FULL)?;
        if extra > arena.pages - arena.used {
            return Err(ffi::SQLITE_FULL);
        }
        for index in self.allocated..target {
            self.root = arena.ensure(self.root, arena.levels, index)?;
            self.allocated = index + 1;
        }
        Ok(())
    }
    pub(super) fn read(&mut self, output: &mut [u8], offset: u64) -> c_int {
        let short = offset.saturating_add(output.len() as u64) > self.length;
        let result = self.operate(false, |this, arena| {
            output.fill(0);
            let mut position = offset;
            let mut written = 0;
            while written < output.len() && position < this.length {
                let index = position / PAGE as u64;
                let start = (position % PAGE as u64) as usize;
                let count = (PAGE - start)
                    .min(output.len() - written)
                    // Bound before conversion on ABIs with a narrower usize.
                    .min((this.length - position).min(PAGE as u64) as usize);
                let bytes = arena.read(arena.leaf(this.root, arena.levels, index)?, 0)?;
                output[written..written + count].copy_from_slice(&bytes[start..start + count]);
                written += count;
                position += count as u64;
            }
            Ok(())
        });
        match result {
            Ok(()) if short => ffi::SQLITE_IOERR_SHORT_READ,
            Ok(()) => ffi::SQLITE_OK,
            Err(code) => code,
        }
    }
    pub(super) fn write(&mut self, input: &[u8], offset: u64) -> c_int {
        self.operate(true, |this, arena| {
            let end = offset
                .checked_add(input.len() as u64)
                .filter(|n| *n <= i64::MAX as u64)
                .ok_or(ffi::SQLITE_FULL)?;
            this.reserve(arena, end)?;
            let mut position = offset;
            let mut consumed = 0;
            while consumed < input.len() {
                let index = position / PAGE as u64;
                let start = (position % PAGE as u64) as usize;
                let count = (PAGE - start).min(input.len() - consumed);
                let mut bytes = arena.read(arena.leaf(this.root, arena.levels, index)?, 0)?;
                bytes[start..start + count].copy_from_slice(&input[consumed..consumed + count]);
                this.root = arena.replace(this.root, arena.levels, index, &bytes)?;
                position += count as u64;
                consumed += count;
                this.length = this.length.max(position);
            }
            Ok(())
        })
        .map_or_else(|code| code, |()| ffi::SQLITE_OK)
    }
    pub(super) fn truncate(&mut self, length: u64) -> c_int {
        self.operate(true, |this, arena| {
            if length > this.length {
                this.reserve(arena, length)?;
            }
            let keep = length.div_ceil(PAGE as u64);
            if length < this.length && !length.is_multiple_of(PAGE as u64) {
                let index = length / PAGE as u64;
                let mut bytes = arena.read(arena.leaf(this.root, arena.levels, index)?, 0)?;
                bytes[(length % PAGE as u64) as usize..].fill(0);
                this.root = arena.replace(this.root, arena.levels, index, &bytes)?;
            }
            this.root = arena.prune(this.root, arena.levels, keep)?;
            this.allocated = keep;
            this.length = length;
            Ok(())
        })
        .map_or_else(|code| code, |()| ffi::SQLITE_OK)
    }
    pub(super) fn close(&mut self) -> c_int {
        // Recycling mutates the shared descriptor. An inherited post-fork
        // connection may close its FD, but must not recycle the parent's pages.
        self.operate(true, |this, arena| {
            this.root = arena.prune(this.root, arena.levels, 0)?;
            this.allocated = 0;
            this.length = 0;
            Ok(())
        })
        .map_or_else(|code| code, |()| ffi::SQLITE_OK)
    }
    pub(super) fn sync(&mut self) -> c_int {
        self.operate(false, |_, arena| {
            arena
                .file
                .sync_all()
                .map_err(|e| io_code(e, ffi::SQLITE_IOERR_FSYNC))
        })
        .map_or_else(|code| code, |()| ffi::SQLITE_OK)
    }
    pub(super) fn size(&self) -> i64 {
        self.length as i64
    }
}
