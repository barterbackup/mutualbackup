use super::*;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;

struct Fixture(Option<tempfile::TempDir>);
impl Drop for Fixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let root = self.0.as_ref().unwrap().path();
            // Preserve live anonymous bytes before the connection closes.
            for entry in std::fs::read_dir("/proc/self/fd").unwrap().flatten() {
                let fd = entry.path();
                let Ok(target) = std::fs::read_link(&fd) else {
                    continue;
                };
                if target.starts_with(root)
                    && target
                        .as_os_str()
                        .as_encoded_bytes()
                        .ends_with(b" (deleted)")
                {
                    let capture = || -> std::io::Result<()> {
                        let mut source = std::fs::File::open(&fd)?;
                        let mut copy = std::fs::File::create(
                            root.join(format!("raw-{}", entry.file_name().to_string_lossy())),
                        )?;
                        let mut buffer = [0; 65536];
                        loop {
                            let n = source.read(&mut buffer)?;
                            if n == 0 {
                                break;
                            }
                            copy.write_all(&buffer[..n])?;
                        }
                        copy.sync_all()?;
                        let m = source.metadata()?;
                        std::fs::write(
                            root.join(format!("metadata-{}", entry.file_name().to_string_lossy())),
                            format!("length={} blocks={}\n", m.len(), m.blocks()),
                        )
                    };
                    if let Err(error) = capture() {
                        eprintln!("scratch capture failed: {error}");
                    }
                }
            }
            eprintln!(
                "SCRATCH_GEOMETRY_NEGATIVE_FIXTURE {}",
                self.0.take().unwrap().keep().display()
            );
        }
    }
}

#[test]
fn record_geometry_preserves_wide_keys_overflow_payloads_and_replacement_high_water() {
    let directory = tempfile::tempdir().unwrap();
    let mutations = 64 * 4;
    let value_bytes = (0..64)
        .map(|i| [0u64, 1, 512, 4096, 8192, 131072][i % 6])
        .sum::<u64>()
        * 4;
    let limits =
        ScratchStorageLimits::for_record_writes(value_bytes, mutations, 4160, 64 << 30).unwrap();
    let store = RecordScratchStore::new_in(directory.path(), limits).unwrap();
    let _fixture = Fixture(Some(directory));
    for round in 0..4u8 {
        store
            .with_record_transaction(|| -> Result<(), DatabaseError> {
                for index in 0..64usize {
                    let mut key = vec![0x31; 4096];
                    key[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    let length = [0usize, 1, 512, 4096, 8192, 131072][index % 6];
                    let value = vec![round; length];
                    if round == 0 {
                        assert!(store.put_record_if_absent("wide", &key, &value)?);
                    } else {
                        store.replace_record_if_value(
                            "wide",
                            &key,
                            &vec![round - 1; length],
                            &value,
                        )?;
                    }
                }
                Ok(())
            })
            .unwrap();
        let pages: u64 = store
            .records
            .connection
            .pragma_query_value(Some("scratch"), "page_count", |row| row.get(0))
            .unwrap();
        assert!(pages * 4096 <= limits.max_database_bytes);
    }
    let mut key = vec![0x31; 4096];
    key[..8].copy_from_slice(&63u64.to_be_bytes());
    assert_eq!(
        store.get_record_bounded("wide", &key, 4096).unwrap(),
        Some(vec![3; 4096])
    );
}

#[test]
fn record_geometry_keeps_the_original_ceiling_and_checks_unrepresentable_database_sizes() {
    let ceiling = 64 << 30;
    let small = ScratchStorageLimits::for_record_writes(0, 0, 0, ceiling).unwrap();
    assert!(small.max_database_bytes >= 16 * 4096 && small.max_database_bytes < ceiling);
    let huge =
        ScratchStorageLimits::for_record_writes(u64::MAX, u64::MAX, u32::MAX, ceiling).unwrap();
    assert_eq!(huge.max_database_bytes, ceiling);
    assert_eq!(
        huge.max_physical_bytes,
        ScratchStorageLimits::for_database(ceiling)
            .unwrap()
            .max_physical_bytes
    );
    assert!(ScratchStorageLimits::for_record_writes(1, 1, 1, 4096).is_err());
    assert!(
        ScratchStorageLimits::for_record_writes(u64::MAX, u64::MAX, u32::MAX, u64::MAX).is_err()
    );
}

#[test]
fn aggregate_key_geometry_preserves_mixed_keys_across_delete_and_reinsert() {
    let directory = tempfile::tempdir().unwrap();
    let keys = (0..65u64)
        .map(|index| {
            let mut key = index.to_be_bytes().to_vec();
            if index == 0 {
                key.resize(4096, 0x42);
            }
            key
        })
        .collect::<Vec<_>>();
    let key_bytes = keys.iter().map(|key| key.len() as u64 + 5).sum::<u64>() * 3;
    let limits = ScratchStorageLimits::for_record_writes_with_key_bytes(
        2 * 65 * 8192,
        3 * 65,
        key_bytes,
        64 << 30,
    )
    .unwrap();
    let store = RecordScratchStore::new_in(directory.path(), limits).unwrap();
    let _fixture = Fixture(Some(directory));
    for round in 0..3 {
        store
            .with_record_transaction(|| -> Result<(), DatabaseError> {
                for key in &keys {
                    if round == 1 {
                        store.delete_record_if_value("mixed", key, &[7; 8192])?;
                        assert!(store.get_record_bounded("mixed", key, 8192)?.is_none());
                    } else {
                        assert!(store.put_record_if_absent("mixed", key, &[7; 8192])?);
                    }
                }
                Ok(())
            })
            .unwrap();
    }
    for key in &keys {
        assert_eq!(
            store.get_record_bounded("mixed", key, 8192).unwrap(),
            Some(vec![7; 8192])
        );
    }
}

#[test]
fn record_geometry_assumptions_match_both_pinned_btree_engines() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../vendor/libsqlite3-sys");
    for file in ["sqlite3/sqlite3.c", "sqlcipher/sqlite3.c"] {
        let source = std::fs::read_to_string(root.join(file)).unwrap();
        assert!(source.contains("#define BTCURSOR_MAX_DEPTH 20"));
        assert!(source.contains("#define NB 3"));
        assert!(source.contains("MemPage *apNew[NB+2]"));
    }
}

#[test]
fn live_record_versions_bound_repeated_freelist_and_overflow_reuse() {
    let directory = tempfile::tempdir().unwrap();
    let limits =
        ScratchStorageLimits::for_live_record_versions(16 * 32768, 16, 4160, 64 << 30).unwrap();
    let store = RecordScratchStore::new_in(directory.path(), limits).unwrap();
    let _fixture = Fixture(Some(directory));
    for round in 0..200u64 {
        store
            .with_record_transaction(|| -> Result<(), DatabaseError> {
                for index in 0..8u64 {
                    let mut key = vec![0x61; 4096];
                    key[..8].copy_from_slice(&index.to_be_bytes());
                    if round != 0 {
                        store.delete_record_if_value(
                            "reuse",
                            &key,
                            &vec![(round - 1) as u8; 32768],
                        )?;
                    }
                    assert!(store.put_record_if_absent(
                        "reuse",
                        &key,
                        &vec![round as u8; 32768]
                    )?);
                }
                Ok(())
            })
            .unwrap();
        let pages: u64 = store
            .records
            .connection
            .pragma_query_value(Some("scratch"), "page_count", |row| row.get(0))
            .unwrap();
        assert!(pages * 4096 <= limits.max_database_bytes);
    }
}
