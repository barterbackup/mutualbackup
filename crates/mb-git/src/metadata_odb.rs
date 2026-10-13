//! Verified legacy metadata in an encrypted disposable index. libgit2 reads
//! objects on demand; existing object identities and codecs remain unchanged.

use std::collections::HashSet;
use std::ffi::{c_int, c_void};
use std::sync::{Arc, Mutex};

use git2::{Binding, Odb, Oid};
use libgit2_sys as raw;
use mb_core::{canonical_bytes, decode_canonical};
use mb_store::{ControlStore, RecordScratchStore};
use serde::de::{SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use uuid::Uuid;

use crate::history::{
    HistoryError, MAX_GRAPH_METADATA_BYTES, MAX_GRAPH_OBJECTS, MetadataObject, metadata_kind,
    object_type,
};

const BODY: &str = "git-metadata-body";
const HEADER: &str = "git-metadata-header";
const ROW_BYTES: usize = MAX_GRAPH_METADATA_BYTES + 32;
type Records = Arc<Mutex<RecordScratchStore>>;

pub(crate) fn decode_bytes<'de, D: Deserializer<'de>>(decoder: D) -> Result<Vec<u8>, D::Error> {
    struct Bytes;
    impl<'de> Visitor<'de> for Bytes {
        type Value = Vec<u8>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "at most {MAX_GRAPH_METADATA_BYTES} metadata bytes")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<u8>, A::Error> {
            if seq
                .size_hint()
                .is_some_and(|n| n > MAX_GRAPH_METADATA_BYTES)
            {
                return Err(serde::de::Error::custom("oversized Git metadata object"));
            }
            let mut bytes =
                Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX_GRAPH_METADATA_BYTES));
            while let Some(byte) = seq.next_element()? {
                if bytes.len() == MAX_GRAPH_METADATA_BYTES {
                    return Err(serde::de::Error::custom("oversized Git metadata object"));
                }
                bytes.push(byte);
            }
            Ok(bytes)
        }
    }
    decoder.deserialize_seq(Bytes)
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
struct Header {
    kind: u8,
    byte_len: u64,
    encoded_len: u64,
}

fn decode(oid: Oid, bytes: &[u8]) -> Result<MetadataObject, HistoryError> {
    let object: MetadataObject = decode_canonical(bytes)?;
    let kind = object_type(object.kind).ok_or(HistoryError::IncompatibleRecord)?;
    if bytes.len() > ROW_BYTES
        || object.format_version != 1
        || object.bytes.len() > MAX_GRAPH_METADATA_BYTES
        || Oid::hash_object(kind, &object.bytes)? != oid
        || canonical_bytes(&object)? != bytes
    {
        return Err(HistoryError::IncompatibleRecord);
    }
    Ok(object)
}

fn header(store: &RecordScratchStore, oid: Oid) -> Result<Option<Header>, HistoryError> {
    let Some(bytes) = store.get_record_bounded(HEADER, oid.as_bytes(), 32)? else {
        if store.record_length(BODY, oid.as_bytes())?.is_some() {
            return Err(HistoryError::IncompatibleRecord);
        }
        return Ok(None);
    };
    let value: Header = decode_canonical(&bytes)?;
    if object_type(value.kind).is_none()
        || value.byte_len > MAX_GRAPH_METADATA_BYTES as u64
        || value.encoded_len > ROW_BYTES as u64
        || canonical_bytes(&value)? != bytes
        || store.record_length(BODY, oid.as_bytes())?.map(|n| n as u64) != Some(value.encoded_len)
    {
        return Err(HistoryError::IncompatibleRecord);
    }
    Ok(Some(value))
}

fn get(store: &RecordScratchStore, oid: Oid) -> Result<Option<MetadataObject>, HistoryError> {
    let Some(expected) = header(store, oid)? else {
        return Ok(None);
    };
    let bytes = store
        .get_record_bounded(BODY, oid.as_bytes(), ROW_BYTES)?
        .ok_or(HistoryError::IncompatibleRecord)?;
    let object = decode(oid, &bytes)?;
    if object.kind != expected.kind || object.bytes.len() as u64 != expected.byte_len {
        return Err(HistoryError::IncompatibleRecord);
    }
    Ok(Some(object))
}

fn put(store: &RecordScratchStore, oid: Oid, bytes: &[u8]) -> Result<bool, HistoryError> {
    let object = decode(oid, bytes)?;
    let expected = Header {
        kind: object.kind,
        byte_len: object.bytes.len() as u64,
        encoded_len: bytes.len() as u64,
    };
    let fresh = store.put_record_if_absent(BODY, oid.as_bytes(), bytes)?;
    if store
        .get_record_bounded(BODY, oid.as_bytes(), ROW_BYTES)?
        .as_deref()
        != Some(bytes)
    {
        return Err(HistoryError::IncompatibleRecord);
    }
    let bytes = canonical_bytes(&expected)?;
    store.put_record_if_absent(HEADER, oid.as_bytes(), &bytes)?;
    if header(store, oid)? != Some(expected) {
        return Err(HistoryError::IncompatibleRecord);
    }
    Ok(fresh)
}

pub(crate) struct MetadataIndex {
    records: Records,
    count: usize,
}

impl MetadataIndex {
    pub(crate) fn load(
        control: &ControlStore,
        id: Uuid,
        odb: &Odb<'_>,
    ) -> Result<Self, HistoryError> {
        // Preserve every historically supported per-object/count bound. Actual
        // scratch allocations remain guarded by the shared filesystem budget.
        let maximum = (MAX_GRAPH_OBJECTS as u64)
            .checked_mul(ROW_BYTES as u64 + 128)
            .and_then(|n| n.checked_mul(2))
            .ok_or(HistoryError::GraphTooLarge)?;
        let store = RecordScratchStore::new(maximum)?;
        let mut count = 0;
        store.with_record_transaction(|| -> Result<(), HistoryError> {
            control
                .for_each_record_bounded(&metadata_kind(id), 20, ROW_BYTES, |key, bytes| {
                    if count >= MAX_GRAPH_OBJECTS {
                        return Err(HistoryError::GraphTooLarge.into());
                    }
                    if key.len() != 20 || !put(&store, Oid::from_bytes(key)?, bytes)? {
                        return Err(HistoryError::IncompatibleRecord.into());
                    }
                    count += 1;
                    Ok(true)
                })
                .map_err(|error| {
                    error
                        .downcast::<HistoryError>()
                        .unwrap_or(HistoryError::IncompatibleRecord)
                })?;
            Ok(())
        })?;
        let records = Arc::new(Mutex::new(store));
        attach(odb, records.clone())?;
        Ok(Self { records, count })
    }

    pub(crate) fn get(&self, oid: Oid) -> Result<Option<MetadataObject>, HistoryError> {
        let records = self
            .records
            .lock()
            .map_err(|_| HistoryError::IncompatibleRecord)?;
        get(&records, oid)
    }

    pub(crate) fn insert(&mut self, oid: Oid, bytes: &[u8]) -> Result<(), HistoryError> {
        let store = self
            .records
            .lock()
            .map_err(|_| HistoryError::IncompatibleRecord)?;
        let exists = header(&store, oid)?.is_some();
        if !exists && self.count >= MAX_GRAPH_OBJECTS {
            return Err(HistoryError::GraphTooLarge);
        }
        let fresh = store.with_record_transaction(|| put(&store, oid, bytes))?;
        if fresh {
            self.count += 1
        }
        Ok(())
    }

    pub(crate) fn ids(&self) -> Result<HashSet<Oid>, HistoryError> {
        let store = self
            .records
            .lock()
            .map_err(|_| HistoryError::IncompatibleRecord)?;
        let mut ids = HashSet::new();
        let mut after = None;
        while let Some((key, _)) = store.next_record_bounded(HEADER, after.as_deref(), 20, 32)? {
            let oid = Oid::from_bytes(&key)?;
            header(&store, oid)?.ok_or(HistoryError::IncompatibleRecord)?;
            if !ids.insert(oid) || ids.len() > self.count {
                return Err(HistoryError::IncompatibleRecord);
            }
            after = Some(key);
        }
        if ids.len() != self.count {
            return Err(HistoryError::IncompatibleRecord);
        }
        Ok(ids)
    }
}

#[repr(C)]
struct Backend {
    base: raw::git_odb_backend,
    records: Records,
}

fn attach(odb: &Odb<'_>, records: Records) -> Result<(), HistoryError> {
    // SAFETY: libgit2 initializes the zeroed C callback table's version/owner.
    let mut backend = Box::new(Backend {
        base: unsafe { std::mem::zeroed() },
        records,
    });
    // SAFETY: The table is live and correctly aligned through initialization.
    let code =
        unsafe { raw::git_odb_init_backend(&mut backend.base, raw::GIT_ODB_BACKEND_VERSION) };
    if code < 0 {
        return Err(git2::Error::last_error(code).into());
    }
    backend.base.read = Some(read);
    backend.base.read_header = Some(read_header);
    backend.base.exists = Some(exists);
    backend.base.free = Some(free);
    let owned = Box::into_raw(backend);
    // SAFETY: libgit2 takes ownership only after a successful backend add. Its
    // Arc keeps the encrypted index alive after the Rust loader is dropped.
    let code = unsafe { raw::git_odb_add_backend(odb.raw(), &mut (*owned).base, 200) };
    if code < 0 {
        // SAFETY: Ownership did not transfer on failure.
        unsafe { drop(Box::from_raw(owned)) };
        return Err(git2::Error::last_error(code).into());
    }
    Ok(())
}

fn lookup<T>(
    base: *mut raw::git_odb_backend,
    oid: *const raw::git_oid,
    read: impl FnOnce(&RecordScratchStore, Oid) -> Result<Option<T>, HistoryError>,
) -> Result<Option<T>, ()> {
    if base.is_null() || oid.is_null() {
        return Err(());
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: libgit2 passes its live backend and 20-byte SHA-1 OID.
        let backend = unsafe { &*base.cast::<Backend>() };
        let oid = Oid::from_bytes(unsafe { &(*oid).id }).map_err(|_| ())?;
        let records = backend.records.lock().map_err(|_| ())?;
        read(&records, oid).map_err(|_| ())
    }))
    .map_err(|_| ())?
}

fn raw_kind(kind: u8) -> raw::git_object_t {
    match kind {
        1 => raw::GIT_OBJECT_COMMIT,
        2 => raw::GIT_OBJECT_TREE,
        3 => raw::GIT_OBJECT_TAG,
        _ => raw::GIT_OBJECT_INVALID,
    }
}

extern "C" fn exists(base: *mut raw::git_odb_backend, oid: *const raw::git_oid) -> c_int {
    match lookup(base, oid, header) {
        Ok(Some(_)) => 1,
        Ok(None) => 0,
        Err(_) => 0,
    }
}

extern "C" fn read_header(
    size: *mut usize,
    kind: *mut raw::git_object_t,
    base: *mut raw::git_odb_backend,
    oid: *const raw::git_oid,
) -> c_int {
    if size.is_null() || kind.is_null() {
        return raw::GIT_ERROR;
    }
    match lookup(base, oid, header) {
        Ok(Some(value)) => {
            // SAFETY: libgit2 provides writable outputs; the bounded length fits usize.
            unsafe {
                *size = value.byte_len as usize;
                *kind = raw_kind(value.kind)
            };
            raw::GIT_OK
        }
        Ok(None) => raw::GIT_ENOTFOUND,
        Err(_) => raw::GIT_ERROR,
    }
}

extern "C" fn read(
    out: *mut *mut c_void,
    size: *mut usize,
    kind: *mut raw::git_object_t,
    base: *mut raw::git_odb_backend,
    oid: *const raw::git_oid,
) -> c_int {
    if out.is_null() || size.is_null() || kind.is_null() {
        return raw::GIT_ERROR;
    }
    let object = match lookup(base, oid, get) {
        Ok(Some(value)) => value,
        Ok(None) => return raw::GIT_ENOTFOUND,
        Err(_) => return raw::GIT_ERROR,
    };
    // SAFETY: libgit2 owns allocations from this allocator after publication.
    let memory = unsafe { raw::git_odb_backend_data_alloc(base, object.bytes.len().max(1)) };
    if memory.is_null() {
        return raw::GIT_ERROR;
    }
    // SAFETY: The allocation has at least the checked object's byte length and
    // outputs belong to libgit2. No fallible operations follow publication.
    unsafe {
        std::ptr::copy_nonoverlapping(
            object.bytes.as_ptr(),
            memory.cast::<u8>(),
            object.bytes.len(),
        );
        *out = memory;
        *size = object.bytes.len();
        *kind = raw_kind(object.kind);
    }
    raw::GIT_OK
}

extern "C" fn free(base: *mut raw::git_odb_backend) {
    if !base.is_null() {
        // SAFETY: libgit2 releases its uniquely owned backend allocation once.
        unsafe { drop(Box::from_raw(base.cast::<Backend>())) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use git2::{ObjectType, Repository};

    fn object(control: &ControlStore, id: Uuid, kind: ObjectType, bytes: &[u8]) -> Oid {
        let oid = Oid::hash_object(kind, bytes).unwrap();
        control
            .put_record(
                &metadata_kind(id),
                oid.as_bytes(),
                &crate::history::object_record(kind, bytes.to_vec()).unwrap(),
            )
            .unwrap();
        oid
    }

    #[test]
    fn metadata_index_original_objects_and_proposals_survive_source_and_loader_drop() {
        fn shared<T: Send + Sync>() {}
        shared::<Records>();
        let temp = tempfile::tempdir().unwrap();
        let control =
            ControlStore::open_with_key(temp.path().join("control.db"), &[219; 32]).unwrap();
        let id = Uuid::from_u128(219);
        let tree = object(&control, id, ObjectType::Tree, &[]);
        let bytes = format!("tree {tree}\nauthor A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\noriginal message\n").into_bytes();
        let commit = object(&control, id, ObjectType::Commit, &bytes);
        let tag_bytes = format!(
            "object {commit}\ntype commit\ntag saved\ntagger A <a@test> 1 +0000\n\noriginal tag\n"
        )
        .into_bytes();
        let tag = object(&control, id, ObjectType::Tag, &tag_bytes);
        let odb = Odb::new().unwrap();
        let _pack = odb.add_new_mempack_backend(1000).unwrap();
        let mut index = MetadataIndex::load(&control, id, &odb).unwrap();
        assert_eq!(index.ids().unwrap(), HashSet::from([tree, commit, tag]));
        assert_eq!(
            odb.read_header(commit).unwrap(),
            (bytes.len(), ObjectType::Commit)
        );
        let proposal_bytes = format!("tree {tree}\nparent {commit}\nauthor B <b@test> 2 +0000\ncommitter B <b@test> 2 +0000\n\nproposal\n").into_bytes();
        let proposal = Oid::hash_object(ObjectType::Commit, &proposal_bytes).unwrap();
        let encoded =
            crate::history::object_record(ObjectType::Commit, proposal_bytes.clone()).unwrap();
        index.insert(proposal, &encoded).unwrap();
        index.insert(proposal, &encoded).unwrap();
        assert_eq!(index.ids().unwrap().len(), 4);
        assert!(index.insert(commit, &encoded).is_err());
        assert_eq!(control.records(&metadata_kind(id)).unwrap().len(), 3);
        drop(index);
        drop(control);
        assert_eq!(odb.read(commit).unwrap().data(), bytes);
        assert_eq!(odb.read(proposal).unwrap().data(), proposal_bytes);
        let repository = Repository::from_odb(odb).unwrap();
        assert_eq!(repository.find_tag(tag).unwrap().target_id(), commit);
        assert_eq!(
            repository
                .find_commit(proposal)
                .unwrap()
                .parent_id(0)
                .unwrap(),
            commit
        );
    }

    #[test]
    fn metadata_index_rejects_invalid_keys_lengths_identity_and_nested_bounds() {
        for damage in 0..5 {
            let temp = tempfile::tempdir().unwrap();
            let control =
                ControlStore::open_with_key(temp.path().join("control.db"), &[219; 32]).unwrap();
            let id = Uuid::from_u128(219);
            let oid = object(&control, id, ObjectType::Tree, &[]);
            match damage {
                0 => control
                    .put_record(&metadata_kind(id), &[0; 21], &[0])
                    .unwrap(),
                1 => control
                    .put_record(
                        &metadata_kind(id),
                        oid.as_bytes(),
                        &crate::history::object_record(ObjectType::Tree, b"wrong oid".to_vec())
                            .unwrap(),
                    )
                    .unwrap(),
                2 => control
                    .put_record(
                        &metadata_kind(id),
                        oid.as_bytes(),
                        &[1, 2, 255, 255, 255, 255, 255, 255, 255, 255, 255, 1],
                    )
                    .unwrap(),
                3 => {
                    control
                        .database_shell_statement(
                            &format!(
                                "UPDATE protocol_records SET bytes=zeroblob({}) WHERE kind='{}'",
                                ROW_BYTES + 1,
                                metadata_kind(id)
                            ),
                            false,
                        )
                        .unwrap();
                }
                _ => control
                    .put_record(&metadata_kind(id), oid.as_bytes(), &[1, 9, 0])
                    .unwrap(),
            }
            let odb = Odb::new().unwrap();
            assert!(MetadataIndex::load(&control, id, &odb).is_err());
            assert!(!odb.exists(oid));
        }
    }

    #[test]
    fn metadata_index_sql_faults_keep_unpublished_prefixes_and_damaged_owned_rows_closed() {
        for action in ["ABORT", "IGNORE"] {
            let temp = tempfile::tempdir().unwrap();
            let control =
                ControlStore::open_with_key(temp.path().join("control.db"), &[219; 32]).unwrap();
            let id = Uuid::from_u128(219);
            let mut tree_bytes = b"100644 file\0".to_vec();
            tree_bytes.extend_from_slice(
                Oid::hash_object(ObjectType::Blob, b"original")
                    .unwrap()
                    .as_bytes(),
            );
            let tree = object(&control, id, ObjectType::Tree, &tree_bytes);
            let odb = Odb::new().unwrap();
            let mut index = MetadataIndex::load(&control, id, &odb).unwrap();
            let bytes =
                crate::history::object_record(ObjectType::Tag, b"new object".to_vec()).unwrap();
            let oid = Oid::hash_object(ObjectType::Tag, b"new object").unwrap();
            index.records.lock().unwrap().database_shell_statement(&format!("CREATE TEMP TRIGGER fail_header BEFORE INSERT ON protocol_records WHEN NEW.kind='{HEADER}' BEGIN SELECT RAISE({action}{}); END", if action == "ABORT" { ",'test'" } else { "" }), false).unwrap();
            assert!(index.insert(oid, &bytes).is_err());
            assert!(!odb.exists(oid));
            assert_eq!(index.ids().unwrap(), HashSet::from([tree]));
            index
                .records
                .lock()
                .unwrap()
                .database_shell_statement("DROP TRIGGER fail_header", false)
                .unwrap();
            index.insert(oid, &bytes).unwrap();
            assert_eq!(odb.read(oid).unwrap().data(), b"new object");
            let records = index.records.lock().unwrap();
            let saved = records
                .get_record_bounded(BODY, tree.as_bytes(), ROW_BYTES)
                .unwrap()
                .unwrap();
            records
                .delete_record_if_value(BODY, tree.as_bytes(), &saved)
                .unwrap();
            drop(records);
            assert!(index.get(tree).is_err());
            assert!(odb.read(tree).is_err());
        }
    }

    #[test]
    #[ignore = "explicit Linux >512 MiB metadata memory qualification"]
    fn metadata_history_above_512_mib_keeps_point_history_and_status_bounded() {
        const OBJECTS: u64 = 1025;
        const MESSAGE_BYTES: usize = 512 * 1024;
        let temp = tempfile::tempdir().unwrap();
        let mut control =
            ControlStore::open_with_key(temp.path().join("control.db"), &[219; 32]).unwrap();
        control
            .begin_record_quota_adoption(mb_store::DatabaseRecordQuota {
                max_rows: OBJECTS + 1024,
                max_accounted_bytes: 1 << 30,
            })
            .unwrap();
        while control.resume_record_quota_adoption().unwrap().state
            != mb_store::DatabaseRecordQuotaState::Active
        {}
        control
            .configure_page_quota(mb_store::DatabasePageQuota {
                max_pages: 256 * 1024,
            })
            .unwrap();
        control
            .configure_journal_quota(mb_store::DatabaseJournalQuota { max_bytes: 1 << 30 })
            .unwrap();
        let id = Uuid::from_u128(219);
        let tree = object(&control, id, ObjectType::Tree, &[]);
        let current = format!(
            "tree {tree}\nauthor A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\ncurrent\n"
        )
        .into_bytes();
        let head = object(&control, id, ObjectType::Commit, &current);
        control
            .put_record(
                &crate::history::ref_kind(id),
                b"refs/heads/main",
                &crate::history::fetched_ref_record(head.as_bytes().try_into().unwrap()).unwrap(),
            )
            .unwrap();
        control.with_record_transaction(|| -> Result<(), HistoryError> {
            for number in 0..OBJECTS {
                let mut bytes = format!("tree {tree}\nauthor A <a@test> 1 +0000\ncommitter A <a@test> 1 +0000\n\nretained-{number}\n").into_bytes();
                bytes.resize(bytes.len() + MESSAGE_BYTES, b'x');
                object(&control, id, ObjectType::Commit, &bytes);
            }
            Ok(())
        }).unwrap();
        let rows = control
            .next_record_metadata_bounded(&metadata_kind(id), None, 20)
            .unwrap()
            .unwrap();
        assert_eq!(rows.0.len(), 20);
        let log = crate::history::log_history(&control, id, 1).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].oid, head.as_bytes());
        assert_eq!(log[0].message, b"current\n");
        assert!(
            crate::status::files_for_commit(&control, id, Some(head))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            crate::history::verified_metadata_ids(&control, id)
                .unwrap()
                .len() as u64,
            OBJECTS + 2
        );
        assert!(OBJECTS * MESSAGE_BYTES as u64 > 512 * 1024 * 1024);
        println!(
            "metadata ODB qualification: objects={}, payload_bytes={}",
            OBJECTS + 2,
            OBJECTS * MESSAGE_BYTES as u64
        );
    }
}
