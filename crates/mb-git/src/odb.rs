//! A libgit2 object backend whose blob payloads are native source anchors.
//!
//! The unsafe surface is confined to the callback table below. The ODB owns
//! `AnchorBackend` after `git_odb_add_backend` succeeds; each read stream owns
//! its pinned file until libgit2 calls `free`. No callback may unwind.

use std::collections::HashMap;
use std::ffi::{c_char, c_int, c_void};
use std::io::{Read, Seek, SeekFrom};
use std::path::PathBuf;

use git2::{Binding, Odb};
use libgit2_sys as raw;
use mb_store::FileAnchorManifest;

use crate::{GitAnchorError, blob_oid_from_anchor};

const MAX_MATERIALIZED_BLOB: u64 = 1024 * 1024;

/// An in-memory libgit2 ODB over verified native anchors.
///
/// This first adapter is read-only. Streaming reads work for arbitrarily large
/// blobs; libgit2's whole-object read is capped at 1 MiB so callers cannot
/// accidentally materialize a large payload in memory.
pub struct NativeOdb {
    odb: Odb<'static>,
}

#[repr(C)]
struct AnchorBackend {
    base: raw::git_odb_backend,
    anchors: HashMap<[u8; 20], LocatedAnchor>,
}

struct LocatedAnchor {
    manifest: FileAnchorManifest,
    area_hint: Option<PathBuf>,
}

impl LocatedAnchor {
    fn open_verified(&self) -> Result<std::fs::File, mb_store::AnchorError> {
        self.manifest
            .open_verified_with_area_hint(self.area_hint.as_deref())
            .map(|(file, _)| file)
    }
}

#[repr(C)]
struct AnchorReadStream {
    base: raw::git_odb_stream,
    file: std::fs::File,
}

impl NativeOdb {
    pub fn from_anchors(
        anchors: impl IntoIterator<Item = FileAnchorManifest>,
    ) -> Result<Self, GitAnchorError> {
        Self::build(anchors, |anchor| Ok((blob_oid_from_anchor(anchor)?, None)))
    }

    /// Preserve each catalog's verified relocation hint for subsequent libgit2
    /// callbacks, without retaining a SQL connection across the C interface.
    #[cfg(target_os = "linux")]
    pub fn from_catalog_anchors(
        control: &mb_store::ControlStore,
        anchors: impl IntoIterator<Item = FileAnchorManifest>,
    ) -> Result<Self, GitAnchorError> {
        Self::build(anchors, |anchor| {
            let (oid, path) = crate::catalog_anchor::identify(control, anchor)?;
            crate::catalog_anchor::remember(control, anchor, &path)?;
            Ok((oid, Some(path)))
        })
    }

    fn build(
        anchors: impl IntoIterator<Item = FileAnchorManifest>,
        mut identify: impl FnMut(
            &FileAnchorManifest,
        ) -> Result<(git2::Oid, Option<PathBuf>), GitAnchorError>,
    ) -> Result<Self, GitAnchorError> {
        let mut indexed = HashMap::<[u8; 20], LocatedAnchor>::new();
        for anchor in anchors {
            let (oid, area_hint) = identify(&anchor)?;
            let key: [u8; 20] = oid.as_bytes().try_into().expect("SHA-1 OID has 20 bytes");
            if let Some(existing) = indexed.get(&key) {
                if existing.manifest.content_hash != anchor.content_hash
                    || existing.manifest.logical_len != anchor.logical_len
                {
                    return Err(GitAnchorError::OidCollision);
                }
            } else {
                indexed.insert(
                    key,
                    LocatedAnchor {
                        manifest: anchor,
                        area_hint,
                    },
                );
            }
        }

        let odb = Odb::new()?;
        // SAFETY: The libgit2 C structure contains only pointers, integers,
        // and optional callbacks; zero is its documented empty state before
        // `git_odb_init_backend` sets the version and owner pointer.
        let base = unsafe { std::mem::zeroed() };
        let mut backend = Box::new(AnchorBackend {
            base,
            anchors: indexed,
        });
        // SAFETY: `backend.base` points to a live, correctly aligned C struct.
        let code =
            unsafe { raw::git_odb_init_backend(&mut backend.base, raw::GIT_ODB_BACKEND_VERSION) };
        if code < 0 {
            return Err(git2::Error::last_error(code).into());
        }
        backend.base.read = Some(read_blob);
        backend.base.read_header = Some(read_header);
        backend.base.readstream = Some(open_read_stream);
        backend.base.exists = Some(exists);
        backend.base.free = Some(free_backend);

        let owned = Box::into_raw(backend);
        // SAFETY: libgit2 takes ownership of `owned` on success. On failure,
        // this function reconstructs the Box exactly once below.
        let code = unsafe { raw::git_odb_add_backend(odb.raw(), &mut (*owned).base, 100) };
        if code < 0 {
            // SAFETY: libgit2 did not take ownership after a failed add.
            unsafe { drop(Box::from_raw(owned)) };
            return Err(git2::Error::last_error(code).into());
        }
        Ok(Self { odb })
    }

    pub fn odb(&self) -> &Odb<'static> {
        &self.odb
    }
}

// SAFETY: libgit2 passes back the pointer to the first field of our `repr(C)`
// allocation. The ODB owns it until `free_backend`, after all callbacks stop.
unsafe fn backend_ref<'a>(base: *mut raw::git_odb_backend) -> &'a AnchorBackend {
    unsafe { &*base.cast::<AnchorBackend>() }
}

fn lookup(backend: &AnchorBackend, oid: *const raw::git_oid) -> Option<&LocatedAnchor> {
    if oid.is_null() {
        return None;
    }
    // SAFETY: libgit2 owns the OID for this callback's duration.
    backend.anchors.get(unsafe { &(*oid).id })
}

extern "C" fn exists(base: *mut raw::git_odb_backend, oid: *const raw::git_oid) -> c_int {
    if base.is_null() {
        return 0;
    }
    // SAFETY: `base` belongs to this ODB backend callback.
    let backend = unsafe { backend_ref(base) };
    c_int::from(lookup(backend, oid).is_some_and(|manifest| manifest.open_verified().is_ok()))
}

extern "C" fn read_header(
    size: *mut usize,
    kind: *mut raw::git_object_t,
    base: *mut raw::git_odb_backend,
    oid: *const raw::git_oid,
) -> c_int {
    if size.is_null() || kind.is_null() || base.is_null() {
        return raw::GIT_ERROR;
    }
    // SAFETY: The ODB guarantees output pointers and backend lifetime here.
    let backend = unsafe { backend_ref(base) };
    let Some(manifest) = lookup(backend, oid) else {
        return raw::GIT_ENOTFOUND;
    };
    if manifest.open_verified().is_err() {
        return raw::GIT_ERROR;
    }
    let Ok(length) = usize::try_from(manifest.manifest.logical_len) else {
        return raw::GIT_ERROR;
    };
    // SAFETY: The checked output pointers belong to libgit2.
    unsafe {
        *size = length;
        *kind = raw::GIT_OBJECT_BLOB;
    }
    raw::GIT_OK
}

extern "C" fn read_blob(
    out: *mut *mut c_void,
    size: *mut usize,
    kind: *mut raw::git_object_t,
    base: *mut raw::git_odb_backend,
    oid: *const raw::git_oid,
) -> c_int {
    if out.is_null() || size.is_null() || kind.is_null() || base.is_null() {
        return raw::GIT_ERROR;
    }
    // SAFETY: The ODB guarantees backend lifetime throughout the callback.
    let backend = unsafe { backend_ref(base) };
    let Some(manifest) = lookup(backend, oid) else {
        return raw::GIT_ENOTFOUND;
    };
    if manifest.manifest.logical_len > MAX_MATERIALIZED_BLOB {
        return raw::GIT_ERROR;
    }
    let Ok(mut file) = manifest.open_verified() else {
        return raw::GIT_ERROR;
    };
    let Ok(length) = usize::try_from(manifest.manifest.logical_len) else {
        return raw::GIT_ERROR;
    };
    // SAFETY: libgit2 allocates and later frees buffers from this allocator.
    let memory = unsafe { raw::git_odb_backend_data_alloc(base, length.max(1)) };
    if memory.is_null() {
        return raw::GIT_ERROR;
    }
    // SAFETY: `memory` is allocated for at least `length` bytes above.
    let output = unsafe { std::slice::from_raw_parts_mut(memory.cast::<u8>(), length) };
    if file.read_exact(output).is_err() {
        // SAFETY: The buffer still belongs to this backend until publication.
        unsafe { raw::git_odb_backend_data_free(base, memory) };
        return raw::GIT_ERROR;
    }
    // SAFETY: The checked output pointers belong to libgit2 and the backend
    // allocator's buffer ownership transfers with `*out`.
    unsafe {
        *out = memory;
        *size = length;
        *kind = raw::GIT_OBJECT_BLOB;
    }
    raw::GIT_OK
}

extern "C" fn open_read_stream(
    out: *mut *mut raw::git_odb_stream,
    size: *mut usize,
    kind: *mut raw::git_object_t,
    base: *mut raw::git_odb_backend,
    oid: *const raw::git_oid,
) -> c_int {
    if out.is_null() || size.is_null() || kind.is_null() || base.is_null() {
        return raw::GIT_ERROR;
    }
    // SAFETY: The ODB guarantees backend lifetime throughout the callback.
    let backend = unsafe { backend_ref(base) };
    let Some(manifest) = lookup(backend, oid) else {
        return raw::GIT_ENOTFOUND;
    };
    let Ok(mut file) = manifest.open_verified() else {
        return raw::GIT_ERROR;
    };
    if file.seek(SeekFrom::Start(0)).is_err() {
        return raw::GIT_ERROR;
    }
    let Ok(length) = usize::try_from(manifest.manifest.logical_len) else {
        return raw::GIT_ERROR;
    };
    // SAFETY: The C stream is initialized field-by-field before publication.
    let mut c_stream: raw::git_odb_stream = unsafe { std::mem::zeroed() };
    c_stream.backend = base;
    c_stream.mode = raw::GIT_STREAM_RDONLY;
    c_stream.declared_size = manifest.manifest.logical_len;
    c_stream.read = Some(read_stream_chunk);
    c_stream.free = Some(free_read_stream);
    let stream = Box::new(AnchorReadStream {
        base: c_stream,
        file,
    });
    // SAFETY: libgit2 owns this stream from publication through `free`.
    unsafe {
        *out = Box::into_raw(stream).cast::<raw::git_odb_stream>();
        *size = length;
        *kind = raw::GIT_OBJECT_BLOB;
    }
    raw::GIT_OK
}

extern "C" fn read_stream_chunk(
    stream: *mut raw::git_odb_stream,
    buffer: *mut c_char,
    length: usize,
) -> c_int {
    if stream.is_null() || (buffer.is_null() && length != 0) {
        return raw::GIT_ERROR;
    }
    if length == 0 {
        return 0;
    }
    // SAFETY: `stream` was allocated as `AnchorReadStream` and `buffer` is a
    // libgit2-owned output region of at least `length` bytes.
    let stream = unsafe { &mut *stream.cast::<AnchorReadStream>() };
    let output = unsafe {
        std::slice::from_raw_parts_mut(buffer.cast::<u8>(), length.min(c_int::MAX as usize))
    };
    match stream.file.read(output) {
        Ok(read) => c_int::try_from(read).unwrap_or(raw::GIT_ERROR),
        Err(_) => raw::GIT_ERROR,
    }
}

extern "C" fn free_read_stream(stream: *mut raw::git_odb_stream) {
    if !stream.is_null() {
        // SAFETY: `stream` is still owned by libgit2 and was allocated once
        // as an `AnchorReadStream` by `open_read_stream`.
        unsafe { drop(Box::from_raw(stream.cast::<AnchorReadStream>())) };
    }
}

extern "C" fn free_backend(base: *mut raw::git_odb_backend) {
    if !base.is_null() {
        // SAFETY: The ODB owns this allocation after a successful add.
        unsafe { drop(Box::from_raw(base.cast::<AnchorBackend>())) };
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::fs;
    use std::io::{Cursor, Read};
    use std::path::PathBuf;

    use mb_store::{SourceBlobImportPlan, SourceFileCapturePlan};
    use uuid::Uuid;

    use super::NativeOdb;

    #[test]
    fn native_odb_reads_raw_imports_without_a_reflink_filesystem() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("protected");
        fs::create_dir(&root).unwrap();
        let small_bytes = b"raw\r\nbytes\0";
        let large_bytes = vec![0x5a; 2 * 1024 * 1024];
        let small_plan =
            SourceBlobImportPlan::plan_direct(&root, small_bytes.len() as u64).unwrap();
        let large_plan =
            SourceBlobImportPlan::plan_direct(&root, large_bytes.len() as u64).unwrap();
        let small = small_plan.capture(Cursor::new(small_bytes)).unwrap();
        let large = large_plan.capture(Cursor::new(&large_bytes)).unwrap();
        let small_oid = crate::blob_oid_from_anchor(&small).unwrap();
        let large_oid = crate::blob_oid_from_anchor(&large).unwrap();
        assert_eq!(
            small_oid,
            git2::Oid::hash_object(git2::ObjectType::Blob, small_bytes).unwrap()
        );
        let odb = NativeOdb::from_anchors([small, large]).unwrap();
        assert!(odb.odb().exists(small_oid));
        assert_eq!(odb.odb().read(small_oid).unwrap().data(), small_bytes);
        assert_eq!(
            odb.odb().read_header(large_oid).unwrap().0,
            large_bytes.len()
        );
        assert!(odb.odb().read(large_oid).is_err());
        let (mut stream, length, kind) = odb.odb().reader(large_oid).unwrap();
        assert_eq!(length, large_bytes.len());
        assert_eq!(kind, git2::ObjectType::Blob);
        let mut actual = Vec::new();
        stream.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, large_bytes);
        drop(stream);
        drop(odb);
        small_plan.discard().unwrap();
        large_plan.discard().unwrap();
    }

    #[test]
    #[ignore = "requires an explicitly provisioned Btrfs test filesystem"]
    fn native_odb_reads_small_and_large_git_blobs_from_anchors() {
        let test_root = PathBuf::from(
            std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
                .expect("the reflink acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
        );
        let run_root = test_root.join(format!("git-odb-{}", Uuid::new_v4()));
        fs::create_dir_all(&run_root).unwrap();
        let payload = b"staged\r\nbytes\0";
        fs::write(run_root.join("small"), payload).unwrap();
        let large = vec![0x5a; 2 * 1024 * 1024];
        fs::write(run_root.join("large"), &large).unwrap();
        let small = SourceFileCapturePlan::plan_reflink(&run_root, "small")
            .unwrap()
            .capture()
            .unwrap();
        let large_anchor = SourceFileCapturePlan::plan_reflink(&run_root, "large")
            .unwrap()
            .capture()
            .unwrap();
        let small_oid = crate::blob_oid_from_anchor(&small).unwrap();
        let large_oid = crate::blob_oid_from_anchor(&large_anchor).unwrap();
        fs::write(run_root.join("small"), b"edited").unwrap();
        let odb = NativeOdb::from_anchors([small.clone(), large_anchor.clone()]).unwrap();
        assert!(odb.odb().exists(small_oid));
        assert_eq!(odb.odb().read_header(large_oid).unwrap().0, large.len());
        assert_eq!(odb.odb().read(small_oid).unwrap().data(), payload);
        let (mut reader, length, kind) = odb.odb().reader(large_oid).unwrap();
        assert_eq!(length, large.len());
        assert_eq!(kind, git2::ObjectType::Blob);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, large);
        drop(reader);
        drop(odb);
        small.remove().unwrap();
        large_anchor.remove().unwrap();
        fs::remove_dir_all(run_root).unwrap();
    }
}
