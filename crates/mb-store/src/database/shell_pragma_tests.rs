//! Query-only shell statements must not mutate cipher state while preparing.
use super::*;
use mb_core::Seed;

#[derive(Clone, Copy, Debug)]
enum Kind {
    Control,
    Parity,
}

enum Store {
    Control(ControlStore),
    Parity(ParityStore),
}

impl Store {
    fn connection(&self) -> &Connection {
        match self {
            Self::Control(store) => &store.connection,
            Self::Parity(store) => &store.connection,
        }
    }

    fn statement(&self, sql: &str) -> Result<DatabaseShellResult, DatabaseError> {
        match self {
            Self::Control(store) => store.database_shell_statement(sql, true),
            Self::Parity(store) => store.database_shell_statement(sql, true),
        }
    }

    fn original_is_present(&self) -> bool {
        match self {
            Self::Control(store) => {
                store
                    .get_record("shell-pragma-original", b"one")
                    .ok()
                    .flatten()
                    .as_deref()
                    == Some(b"original encrypted record".as_slice())
            }
            Self::Parity(store) => store
                .publication_is_complete(&object(71), ORIGINAL_ACK)
                .unwrap_or(false),
        }
    }

    fn normal_write(&mut self) -> bool {
        match self {
            Self::Control(store) => {
                store
                    .put_record(
                        "shell-pragma-followup",
                        b"two",
                        b"normal writer after inspection",
                    )
                    .is_ok()
                    && store
                        .get_record("shell-pragma-followup", b"two")
                        .ok()
                        .flatten()
                        .as_deref()
                        == Some(b"normal writer after inspection".as_slice())
            }
            Self::Parity(store) => {
                store
                    .stage_and_publish_ack(&object(73), b"followup acknowledgement", 4 << 20)
                    .is_ok()
                    && store
                        .publication_is_complete(&object(73), b"followup acknowledgement")
                        .unwrap_or(false)
            }
        }
    }
}

const VOLUME: [u8; 16] = [70; 16];
const ORIGINAL_ACK: &[u8] = b"original acknowledged parity before inspection";

fn object(marker: u8) -> ParityObject {
    let bytes = vec![marker; V1_SECTOR_SIZE];
    ParityObject {
        format_version: 1,
        guild_id: [72; 32],
        group_id: [marker; 32],
        shard_index: 3,
        root: sector_root(&bytes),
        bytes,
    }
}

fn layouts() -> &'static [bool] {
    #[cfg(target_os = "linux")]
    {
        &[false, true]
    }
    #[cfg(not(target_os = "linux"))]
    {
        &[false]
    }
}

#[cfg(target_os = "linux")]
fn policy() -> mb_core::NativeDatabaseIoPolicy {
    mb_core::NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [74; 16],
        main_bytes: 8 << 20,
        journal_bytes: 8 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 8 << 20,
        total_bytes: 32 << 20,
        headroom_bytes: 0,
        files: 32,
    }
}

struct Fixture {
    directory: Option<tempfile::TempDir>,
    store: Option<Store>,
    path: PathBuf,
    original_key: [u8; 32],
    preserve: bool,
}

impl Fixture {
    fn create(kind: Kind, native: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let keys = KeyMaterial::from_seed(&Seed::from_bytes([75; 32]));
        let path = temp.path().join(match kind {
            Kind::Control => "control.db",
            Kind::Parity => "parity.db",
        });
        #[cfg(target_os = "linux")]
        let mut original_key = [76; 32];
        #[cfg(not(target_os = "linux"))]
        let original_key = [76; 32];
        #[cfg(target_os = "linux")]
        let mut store = if native {
            let directory = DatabaseDirectory::open(temp.path()).unwrap();
            match kind {
                Kind::Control => {
                    let store = ControlStore::create_native_in_directory(
                        &directory,
                        std::ffi::OsStr::new("control.db"),
                        &keys,
                        b"shell-pragma/control",
                        policy(),
                    )
                    .unwrap();
                    let inspection = ControlStore::inspect_native_existing_in_directory(
                        &directory,
                        std::ffi::OsStr::new("control.db"),
                        &keys,
                        b"shell-pragma/control",
                    )
                    .unwrap();
                    original_key = *inspection.database_key();
                    Store::Control(store)
                }
                Kind::Parity => {
                    let store = ParityStore::create_native_in_directory(
                        &directory,
                        std::ffi::OsStr::new("parity.db"),
                        &VOLUME,
                        &keys,
                        b"shell-pragma/parity",
                        policy(),
                    )
                    .unwrap();
                    let inspection = ParityStore::inspect_native_existing_in_directory(
                        &directory,
                        std::ffi::OsStr::new("parity.db"),
                        &VOLUME,
                        &keys,
                        b"shell-pragma/parity",
                    )
                    .unwrap();
                    original_key = *inspection.database_key();
                    Store::Parity(store)
                }
            }
        } else {
            match kind {
                Kind::Control => {
                    Store::Control(ControlStore::open_with_key(&path, &original_key).unwrap())
                }
                Kind::Parity => Store::Parity(
                    ParityStore::open_with_key(&path, &VOLUME, &original_key).unwrap(),
                ),
            }
        };
        #[cfg(not(target_os = "linux"))]
        let mut store = match kind {
            Kind::Control => {
                Store::Control(ControlStore::open_with_key(&path, &original_key).unwrap())
            }
            Kind::Parity => {
                Store::Parity(ParityStore::open_with_key(&path, &VOLUME, &original_key).unwrap())
            }
        };
        match &mut store {
            Store::Control(store) => store
                .put_record(
                    "shell-pragma-original",
                    b"one",
                    b"original encrypted record",
                )
                .unwrap(),
            Store::Parity(store) => {
                store
                    .stage_and_publish_ack(&object(71), ORIGINAL_ACK, 4 << 20)
                    .unwrap();
            }
        }
        store
            .connection()
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        assert!(store.original_is_present());
        // Keys stay in memory and the authenticated native birth, never logs.
        let _ = (native, keys);
        Self {
            directory: Some(temp),
            store: Some(store),
            path,
            original_key,
            preserve: false,
        }
    }

    fn payload_files(&self) -> Vec<(String, Option<Vec<u8>>)> {
        ["", "-wal", "-journal"]
            .into_iter()
            .map(|suffix| {
                let mut path = self.path.as_os_str().to_os_string();
                path.push(suffix);
                let bytes = match fs::read(PathBuf::from(path)) {
                    Ok(bytes) => Some(bytes),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => panic!("inspect fixture: {error}"),
                };
                (suffix.to_owned(), bytes)
            })
            .collect()
    }

    fn reopen_original_read_only(&self, kind: Kind) -> bool {
        match kind {
            Kind::Control => {
                ControlStore::open_existing_read_only_with_key(&self.path, &self.original_key)
                    .map(Store::Control)
            }
            Kind::Parity => ParityStore::open_existing_read_only_with_key(
                &self.path,
                &VOLUME,
                &self.original_key,
            )
            .map(Store::Parity),
        }
        .is_ok_and(|store| store.original_is_present())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.store.take();
        if self.preserve || std::thread::panicking() {
            let path = self.directory.take().unwrap().keep();
            eprintln!("SQLCIPHER_SHELL_NEGATIVE_FIXTURE {}", path.display());
        }
    }
}

fn refused_cipher_pragmas(kind: Kind, names: &[&str]) {
    let mut failures = Vec::new();
    for &native in layouts() {
        for (spelling, name) in names.iter().enumerate() {
            let mut fixture = Fixture::create(kind, native);
            let value = if name.to_ascii_lowercase().starts_with("hex") {
                "89".repeat(32)
            } else {
                "read-only inspection must never replace the original cipher key".to_owned()
            };
            let sql = match spelling % 3 {
                0 => format!("PRAGMA {name} = '{value}'"),
                1 => format!("/* inspector */ PRAGMA \"main\".\"{name}\" = '{value}'"),
                _ => format!("PRAGMA main.{name}('{value}')"),
            };
            let before = fixture.payload_files();
            let denied = fixture.store.as_ref().unwrap().statement(&sql).is_err();
            let unchanged = fixture.payload_files() == before;
            let original_live = fixture.store.as_ref().unwrap().original_is_present();
            let next_write = fixture.store.as_mut().unwrap().normal_write();
            fixture.store.take();
            let original_reopens = fixture.reopen_original_read_only(kind);
            let passed = denied && unchanged && original_live && next_write && original_reopens;
            if !passed {
                fixture.preserve = true;
                failures.push(format!("{kind:?} native={native} {name}: denied={denied} bytes_unchanged={unchanged} original_live={original_live} normal_write={next_write} original_key_reopens={original_reopens}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "read-only cipher mutation: {failures:?}"
    );
}

#[test]
fn control_read_only_shell_refuses_key_changes_before_prepare_side_effects() {
    refused_cipher_pragmas(Kind::Control, &["key", "HEXKEY", "textKEY"]);
}

#[test]
fn control_read_only_shell_refuses_rekey_before_prepare_side_effects() {
    refused_cipher_pragmas(Kind::Control, &["rekey", "HexRekey", "TEXTREKEY"]);
}

#[test]
fn parity_read_only_shell_refuses_key_changes_before_prepare_side_effects() {
    refused_cipher_pragmas(Kind::Parity, &["key", "HEXKEY", "textKEY"]);
}

#[test]
fn parity_read_only_shell_refuses_rekey_before_prepare_side_effects() {
    refused_cipher_pragmas(Kind::Parity, &["rekey", "HexRekey", "TEXTREKEY"]);
}

#[test]
fn read_only_shell_allows_cipher_inspection_and_key_named_columns() {
    for kind in [Kind::Control, Kind::Parity] {
        for &native in layouts() {
            let fixture = Fixture::create(kind, native);
            let store = fixture.store.as_ref().unwrap();
            assert!(
                !store
                    .statement("PRAGMA cipher_version")
                    .unwrap()
                    .rows
                    .is_empty()
            );
            assert_eq!(
                store.statement("SELECT 'rekey' AS key").unwrap().rows,
                vec![vec!["rekey".to_owned()]]
            );
        }
    }
}

#[test]
fn explicitly_writable_shell_can_still_rekey_legacy_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("control.db");
    let store = ControlStore::open_with_key(&path, &[77; 32]).unwrap();
    store.put_record("original", b"one", b"retained").unwrap();
    store
        .database_shell_statement(
            &format!("PRAGMA rekey = '{}'", hex::encode([78; 32])),
            false,
        )
        .unwrap();
    drop(store);
    let reopened = ControlStore::open_existing_read_only_with_key(&path, &[78; 32]).unwrap();
    assert_eq!(
        reopened.get_record("original", b"one").unwrap().unwrap(),
        b"retained"
    );
}
