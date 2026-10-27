use super::*;
use mb_core::NativeDatabaseIoPolicy;
use mb_node::{LocalRequest, NativeNodeStoragePolicy, NativeParityVolumePolicy};
use std::collections::BTreeMap;

struct PreservedFixture(Option<tempfile::TempDir>);

impl Drop for PreservedFixture {
    fn drop(&mut self) {
        if std::thread::panicking() {
            let path = self.0.take().unwrap().keep();
            eprintln!("NATIVE_ENROLLMENT_NEGATIVE_FIXTURE {}", path.display());
        }
    }
}

fn database_policy(id: u8) -> NativeDatabaseIoPolicy {
    NativeDatabaseIoPolicy {
        format_version: 1,
        policy_id: [id; 16],
        main_bytes: 16 << 20,
        journal_bytes: 8 << 20,
        shm_bytes: 1 << 20,
        temporary_bytes: 8 << 20,
        total_bytes: 64 << 20,
        headroom_bytes: 65536,
        files: 32,
    }
}

fn immutable(directory: &Path) -> BTreeMap<PathBuf, (blake3::Hash, u32)> {
    let mut result = BTreeMap::new();
    let mut pending = vec![directory.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if [
                "identity.toml",
                "native-storage.profile",
                "native-storage.ready",
                "native-volume.profile",
                ".mutualbackup-volume",
                "birth",
                "ready",
            ]
            .iter()
            .any(|name| path.file_name() == Some(OsStr::new(name)))
            {
                result.insert(
                    path.clone(),
                    (
                        blake3::hash(&fs::read(&path).unwrap()),
                        fs::metadata(&path).unwrap().permissions().mode(),
                    ),
                );
            }
        }
    }
    result
}

fn initialize(data: &Path, seed: &Path, policy: &Path) -> Vec<OsString> {
    vec![
        os("init-native"),
        os("--data-dir"),
        os(data),
        os("--seed-file"),
        os(seed),
        os("--policy"),
        os(policy),
    ]
}

fn create(socket: &Path, path: &Path, policy: &Path) -> Vec<OsString> {
    vec![
        os("--socket"),
        os(socket),
        os("storage"),
        os("create-native"),
        os(path),
        os("--policy"),
        os(policy),
    ]
}

fn all_files(directory: &Path) -> BTreeMap<PathBuf, (blake3::Hash, u32)> {
    let mut result = BTreeMap::new();
    let mut pending = vec![directory.to_owned()];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                result.insert(
                    path.clone(),
                    (
                        blake3::hash(&fs::read(&path).unwrap()),
                        fs::metadata(&path).unwrap().permissions().mode(),
                    ),
                );
            }
        }
    }
    result
}

#[test]
fn native_cli_rejects_legacy_catalog_and_wrong_identity_without_changing_files() {
    let fixture = PreservedFixture(Some(tempfile::tempdir().unwrap()));
    let root = fixture.0.as_ref().unwrap().path();
    set_private(root);
    let data = root.join("state");
    let seed_file = root.join("recovery.seed");
    let recovery = "native-cli-legacy-and-identity-refusal-fixture-2027!";
    run_cli_with_input(
        &[
            os("init"),
            os("--data-dir"),
            os(&data),
            os("--seed-file"),
            os(&seed_file),
            os("--seed-stdin"),
        ],
        recovery.as_bytes(),
        CLI_TIMEOUT,
    )
    .unwrap();
    let policy_file = root.join("node-policy.json");
    fs::write(
        &policy_file,
        include_bytes!("../../../../docs/examples/native-node-policy.json"),
    )
    .unwrap();
    let before = all_files(&data);
    assert!(
        run_cli_with_input(
            &[
                os("init-native"),
                os("--data-dir"),
                os(&data),
                os("--seed-stdin"),
                os("--policy"),
                os(&policy_file),
            ],
            b"another-native-cli-original-identity-refusal-fixture-2027!",
            CLI_TIMEOUT
        )
        .is_err()
    );
    assert_eq!(all_files(&data), before);
    let seed = Seed::from_recovery_string(recovery).unwrap();
    drop(Node::open(&data, seed.clone()).unwrap());
    run_cli(&[
        os("db-shell"), os("--data-dir"), os(&data), os("--seed-file"), os(&seed_file),
        os("--write"), os("--execute"), os("INSERT INTO protocol_records(kind,record_id,bytes) VALUES('native-cli-legacy',X'01',X'000d0aff')"),
    ], CLI_TIMEOUT).unwrap();
    let before = all_files(&data);
    let refused = run_cli(&initialize(&data, &seed_file, &policy_file), CLI_TIMEOUT);
    assert!(refused.is_err());
    assert_eq!(all_files(&data), before);
    let node = Node::open(&data, seed).unwrap();
    let record = node
        .database_shell_statement(
            None,
            "SELECT hex(bytes) FROM protocol_records WHERE kind='native-cli-legacy'",
            false,
        )
        .unwrap();
    assert_eq!(record.rows, vec![vec!["000D0AFF"]]);
}

#[test]
fn native_cli_enrollment_preserves_policy_identity_and_raw_volume_through_restart() {
    let fixture = PreservedFixture(Some(tempfile::tempdir().unwrap()));
    let root = fixture.0.as_ref().unwrap().path();
    set_private(root);
    let ipc = tempfile::tempdir_in("/tmp").unwrap();
    set_private(ipc.path());
    let socket = ipc.path().join("control.sock");
    let data = root.join("state");
    let seed_file = root.join("recovery.seed");
    let recovery = "native-cli-enrollment-original-identity-fixture-2027!";
    run_cli_with_input(
        &[
            os("init"),
            os("--data-dir"),
            os(&data),
            os("--seed-file"),
            os(&seed_file),
            os("--seed-stdin"),
        ],
        recovery.as_bytes(),
        CLI_TIMEOUT,
    )
    .unwrap();
    let policy = NativeNodeStoragePolicy {
        control: database_policy(17),
        default_parity: database_policy(18),
        parity_budget_bytes: 8 << 20,
    };
    let policy_file = root.join("node-policy.json");
    fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
    let initial = run_cli(&initialize(&data, &seed_file, &policy_file), CLI_TIMEOUT).unwrap();
    let default_id = value_after(&initial, "native default storage volume:");
    let original = immutable(&data);
    assert_eq!(original.len(), 8);
    assert_eq!(
        run_cli(&initialize(&data, &seed_file, &policy_file), CLI_TIMEOUT).unwrap(),
        initial
    );
    assert_eq!(immutable(&data), original);
    let wrong_policy_file = root.join("wrong-node-policy.json");
    fs::write(
        &wrong_policy_file,
        serde_json::to_vec(&NativeNodeStoragePolicy {
            control: database_policy(27),
            ..policy
        })
        .unwrap(),
    )
    .unwrap();
    assert!(
        run_cli(
            &initialize(&data, &seed_file, &wrong_policy_file),
            CLI_TIMEOUT
        )
        .is_err()
    );
    assert_eq!(immutable(&data), original);
    run_cli(&[
        os("db-shell"), os("--data-dir"), os(&data), os("--seed-file"), os(&seed_file),
        os("--write"), os("--execute"), os("INSERT INTO protocol_records(kind,record_id,bytes) VALUES('native-cli-marker',X'01',X'000d0aff')"),
    ], CLI_TIMEOUT).unwrap();
    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            os(&data),
            os("--seed-file"),
            os(&seed_file),
            os("--control-socket"),
            os(&socket),
            os("--failure-domain"),
            os("native-cli-test"),
            os("--parity-budget-bytes"),
            os("8388608"),
            os("--parity-headroom-bytes"),
            os("65536"),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
            os("--tor-mode"),
            os("disable-tor"),
        ],
        root.join("daemon.log"),
    );
    daemon.start();
    wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    assert!(
        cli(&socket, ["storage", "list"], CLI_TIMEOUT).contains(&format!("{default_id} Online"))
    );
    assert!(run_cli(&initialize(&data, &seed_file, &policy_file), CLI_TIMEOUT).is_err());
    let extra = root.join(OsString::from_vec(b"extra-\xff".to_vec()));
    fs::create_dir(&extra).unwrap();
    let extra_policy = NativeParityVolumePolicy {
        database: database_policy(19),
        parity_budget_bytes: 8 << 20,
    };
    let extra_file = root.join("extra-policy.json");
    fs::write(&extra_file, serde_json::to_vec(&extra_policy).unwrap()).unwrap();
    let mut invalid = extra_policy;
    invalid.database.format_version = 0;
    let runtime = tokio::runtime::Runtime::new().unwrap();
    assert!(
        runtime
            .block_on(mb_node::local_control_call(
                &socket,
                &LocalRequest::StorageCreateNative {
                    path: extra.clone(),
                    policy: invalid
                }
            ))
            .is_err()
    );
    assert_eq!(fs::read_dir(&extra).unwrap().count(), 0);
    let created = run_cli(&create(&socket, &extra, &extra_file), CLI_TIMEOUT).unwrap();
    let extra_id = value_after(&created, "native storage volume:");
    let extra_original = immutable(&extra);
    assert_eq!(extra_original.len(), 4);
    assert_eq!(
        run_cli(&create(&socket, &extra, &extra_file), CLI_TIMEOUT).unwrap(),
        created
    );
    let wrong_file = root.join("wrong-extra-policy.json");
    fs::write(
        &wrong_file,
        serde_json::to_vec(&NativeParityVolumePolicy {
            database: database_policy(29),
            ..extra_policy
        })
        .unwrap(),
    )
    .unwrap();
    assert!(run_cli(&create(&socket, &extra, &wrong_file), CLI_TIMEOUT).is_err());
    assert_eq!(immutable(&extra), extra_original);
    assert_eq!(immutable(&data), original);
    daemon.stop_gracefully();
    daemon.args.extend([
        os("--parity-volume"),
        os(&data),
        os("--parity-volume"),
        os(&extra),
    ]);
    daemon.start();
    wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    assert!(cli(&socket, ["storage", "list"], CLI_TIMEOUT).contains(&format!("{extra_id} Online")));
    assert_eq!(
        run_cli(&create(&socket, &extra, &extra_file), CLI_TIMEOUT).unwrap(),
        created
    );
    cli(&socket, ["storage", "drain", &extra_id], CLI_TIMEOUT);
    cli(&socket, ["storage", "migrate"], CLI_TIMEOUT);
    assert!(
        cli(&socket, ["storage", "list"], CLI_TIMEOUT).contains(&format!("{extra_id} Retired"))
    );
    assert_eq!(
        run_cli(&create(&socket, &extra, &extra_file), CLI_TIMEOUT).unwrap(),
        created
    );
    assert!(
        cli(&socket, ["storage", "list"], CLI_TIMEOUT).contains(&format!("{extra_id} Retired"))
    );
    daemon.stop_gracefully();
    let marker = run_cli(&[
        os("db-shell"), os("--data-dir"), os(&data), os("--seed-file"), os(&seed_file), os("--execute"),
        os("SELECT hex(bytes) AS original FROM protocol_records WHERE kind='native-cli-marker'"),
    ], CLI_TIMEOUT).unwrap();
    assert_eq!(marker.lines().collect::<Vec<_>>(), ["original", "000D0AFF"]);
    assert_eq!(immutable(&data), original);
    assert_eq!(immutable(&extra), extra_original);
}
