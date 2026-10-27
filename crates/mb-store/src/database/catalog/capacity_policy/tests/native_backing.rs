use super::*;
use crate::database::DatabaseDirectory;
use mb_core::NativeDatabaseIoPolicy;
use std::ffi::OsStr;

const CHUNK: u64 = 65536;

struct Fixture {
    directory: Option<tempfile::TempDir>,
    store: Option<ControlStore>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.take();
        if std::thread::panicking() {
            let path = self.directory.take().unwrap().keep();
            eprintln!(
                "NATIVE_RESOURCE_BACKING_NEGATIVE_FIXTURE {}",
                path.display()
            );
        }
    }
}

fn required(p: CatalogResourcePolicy) -> (u64, u64) {
    (
        p.control_pages.checked_mul(4096).unwrap().div_ceil(CHUNK) * CHUNK,
        p.control_journal_bytes.div_ceil(CHUNK) * CHUNK,
    )
}

fn io(main_bytes: u64, journal_bytes: u64, total_bytes: u64) -> NativeDatabaseIoPolicy {
    NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [81; 16],
        main_bytes,
        journal_bytes,
        shm_bytes: CHUNK,
        temporary_bytes: CHUNK,
        total_bytes,
        headroom_bytes: 0,
        files: 32,
    }
}

fn setup(io: NativeDatabaseIoPolicy, p: CatalogResourcePolicy) -> Fixture {
    let mut fixture = Fixture {
        directory: Some(tempfile::tempdir().unwrap()),
        store: None,
    };
    let dir = DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap();
    fixture.store = Some(
        ControlStore::create_native_in_directory(
            &dir,
            OsStr::new("control.db"),
            &keys(),
            b"control.db/v2",
            io,
        )
        .unwrap(),
    );
    let store = fixture.store.as_mut().unwrap();
    store
        .put_record("native-resource-original", b"one", b"original data")
        .unwrap();
    backing(store);
    store.configure_catalog_capacity_policy(p.capacity).unwrap();
    resource_backing(store, p);
    fixture
}

fn refuses(io: NativeDatabaseIoPolicy, p: CatalogResourcePolicy) {
    let mut fixture = setup(io, p);
    let store = fixture.store.as_ref().unwrap();
    let before = store.record_quota_usage().unwrap();
    assert!(store.catalog_resource_policy().unwrap().is_none());
    let refused = store.configure_catalog_resource_policy(p);
    assert!(
        refused.is_err(),
        "resource policy granted credits beyond native limits: io={io:?} resource={p:?}"
    );
    assert_eq!(store.record_quota_usage().unwrap(), before);
    assert!(store.catalog_resource_policy().unwrap().is_none());
    assert_eq!(
        store
            .get_record("native-resource-original", b"one")
            .unwrap(),
        Some(b"original data".to_vec())
    );
    store
        .put_record(
            "native-resource-original",
            b"two",
            b"ordinary retry remains writable",
        )
        .unwrap();
    fixture.store.take();
    let dir = DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap();
    let reopened = ControlStore::open_native_existing_in_directory(
        &dir,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(reopened.native_database_owner().unwrap().policy(), io);
    assert!(reopened.catalog_resource_policy().unwrap().is_none());
    assert_eq!(
        reopened
            .get_record("native-resource-original", b"one")
            .unwrap(),
        Some(b"original data".to_vec())
    );
    assert_eq!(
        reopened
            .get_record("native-resource-original", b"two")
            .unwrap(),
        Some(b"ordinary retry remains writable".to_vec())
    );
}

#[test]
fn resource_policy_refuses_main_credits_beyond_native_ceiling() {
    let p = resource_policy();
    let (main, journal) = required(p);
    refuses(io(main - CHUNK, journal, main + journal + 2 * CHUNK), p);
}

#[test]
fn resource_policy_refuses_journal_credits_beyond_native_ceiling() {
    let p = resource_policy();
    let (main, journal) = required(p);
    refuses(io(main, journal - CHUNK, main + journal + 2 * CHUNK), p);
}

#[test]
fn resource_policy_refuses_combined_credits_beyond_shared_native_pool() {
    let p = resource_policy();
    let (main, journal) = required(p);
    refuses(io(main, journal, main + journal - CHUNK), p);
}

#[test]
fn resource_policy_accounts_for_separately_rounded_native_extents() {
    let mut p = resource_policy();
    p.control_pages = p.control_pages.div_ceil(CHUNK / 4096) * (CHUNK / 4096) + 1;
    p.control_journal_bytes = p.control_journal_bytes.div_ceil(CHUNK) * CHUNK + 1;
    let (main, journal) = required(p);
    let total = main + journal - CHUNK;
    assert!(p.control_pages * 4096 + p.control_journal_bytes <= total);
    refuses(io(main, journal, total), p);
}

#[test]
fn resource_policy_keeps_fitting_native_backing_across_reopen() {
    let p = resource_policy();
    let (main, journal) = required(p);
    let policy = io(main, journal, main + journal + 2 * CHUNK);
    let mut fixture = setup(policy, p);
    fixture
        .store
        .as_ref()
        .unwrap()
        .configure_catalog_resource_policy(p)
        .unwrap();
    fixture.store.take();
    let dir = DatabaseDirectory::open(fixture.directory.as_ref().unwrap().path()).unwrap();
    let reopened = ControlStore::open_native_existing_in_directory(
        &dir,
        OsStr::new("control.db"),
        &keys(),
        b"control.db/v2",
    )
    .unwrap();
    assert_eq!(reopened.catalog_resource_policy().unwrap(), Some(p));
    assert_eq!(reopened.native_database_owner().unwrap().policy(), policy);
    assert_eq!(
        reopened
            .get_record("native-resource-original", b"one")
            .unwrap(),
        Some(b"original data".to_vec())
    );
}
