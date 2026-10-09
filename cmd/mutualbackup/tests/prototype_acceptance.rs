#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use mb_core::{
    EndpointRecord, KeyMaterial, NodeId, RecoveryBundle, SealedRecoveryRecord, Seed, SignedRecord,
    canonical_bytes,
};
use mb_node::{
    Node, P2pConfig, build_p2p, endpoint_record_key, onion_listener_address, recovery_bundle_key,
    recovery_mailbox_key,
};
use mutualbackup::{
    DaemonOptions, InitializationIntent, read_daemon_options, read_identity_manifest,
};
use uuid::Uuid;

#[path = "support/binaries.rs"]
mod binaries;
use binaries::program;

#[path = "support/peer_logs.rs"]
mod peer_logs;
use peer_logs::PeerLogArchive;

fn uses_cargo_debug_programs() -> bool {
    cfg!(debug_assertions) && std::env::var_os("MUTUALBACKUP_TEST_BIN_DIR").is_none()
}

const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_BULK_TRANSFER_BYTES: u64 = 64 * 1024;
const PROCESS_SMALL_BACKUP_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const PROCESS_LARGE_BACKUP_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const PROCESS_TOPOLOGY_BACKUP_TIMEOUT: Duration = Duration::from_secs(90 * 60);
// Retain request/connection correlation and durable signature-lock evidence in
// archived topology logs without enabling verbose transport-library logging.
const TOPOLOGY_LOG_FILTER: &str = "warn,mb_node::network::p2p=info,mb_node::node=debug";

fn process_topology_backup_timeout() -> Duration {
    match std::env::var("MUTUALBACKUP_TEST_TOPOLOGY_BACKUP_TIMEOUT_SECONDS") {
        Ok(value) => {
            let seconds: u64 = value
                .parse()
                .expect("topology backup timeout override must be whole seconds");
            assert!(seconds > 0, "topology backup timeout must be positive");
            Duration::from_secs(seconds)
        }
        Err(std::env::VarError::NotPresent) => PROCESS_TOPOLOGY_BACKUP_TIMEOUT,
        Err(error) => panic!("invalid topology backup timeout override: {error}"),
    }
}

struct Daemon {
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    log: PathBuf,
    network_namespace: Option<NetworkNamespace>,
    child: Option<Child>,
}

#[derive(Clone)]
struct NetworkNamespace {
    name: OsString,
    sudo: PathBuf,
    ip: PathBuf,
    setpriv: PathBuf,
    env: PathBuf,
    uid: u32,
    gid: u32,
}

impl NetworkNamespace {
    fn new(name: impl AsRef<OsStr>) -> Self {
        Self {
            name: os(name),
            sudo: required_test_program("MUTUALBACKUP_TEST_SUDO"),
            ip: required_test_program("MUTUALBACKUP_TEST_IP"),
            setpriv: required_test_program("MUTUALBACKUP_TEST_SETPRIV"),
            env: required_test_program("MUTUALBACKUP_TEST_ENV"),
            // SAFETY: these accessors have no preconditions and only return the
            // invoking test process's real identity.
            uid: unsafe { libc::getuid() },
            // SAFETY: see the `getuid` call above.
            gid: unsafe { libc::getgid() },
        }
    }

    fn command(&self, environment: &[(OsString, OsString)]) -> Command {
        let mut command = Command::new(&self.sudo);
        command
            .arg("-n")
            .arg(&self.ip)
            .args([OsStr::new("netns"), OsStr::new("exec")])
            .arg(&self.name)
            .arg(&self.setpriv)
            .arg(format!("--reuid={}", self.uid))
            .arg(format!("--regid={}", self.gid))
            .arg("--clear-groups")
            .arg("--inh-caps=-all")
            .arg("--bounding-set=-all")
            .arg("--no-new-privs")
            .arg(&self.env);
        for (key, value) in environment {
            let mut assignment = key.clone();
            assignment.push("=");
            assignment.push(value);
            command.arg(assignment);
        }
        command.arg(program("mutualbackupd"));
        command
    }

    fn signal_processes(&self, signal: libc::c_int) {
        let output = Command::new(&self.sudo)
            .arg("-n")
            .arg(&self.ip)
            .args([OsStr::new("netns"), OsStr::new("pids")])
            .arg(&self.name)
            .output();
        let Ok(output) = output else {
            return;
        };
        for pid in String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .filter_map(|value| value.parse::<libc::pid_t>().ok())
        {
            // SAFETY: `pid` came from `ip netns pids`; sending a signal is the
            // intended best-effort cleanup and the return value is immaterial.
            let _ = unsafe { libc::kill(pid, signal) };
        }
    }
}

impl Daemon {
    fn new(config: PathBuf, log: PathBuf) -> Self {
        Self::with_args(vec![os("--config"), config.into_os_string()], log)
    }

    fn with_args(args: Vec<OsString>, log: PathBuf) -> Self {
        Self {
            args,
            environment: Vec::new(),
            log,
            network_namespace: None,
            child: None,
        }
    }

    fn set_env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
        let key = os(key);
        self.environment.retain(|(candidate, _)| candidate != &key);
        self.environment.push((key, os(value)));
    }

    fn set_network_namespace(&mut self, namespace: impl AsRef<OsStr>) {
        assert!(self.child.is_none());
        self.network_namespace = Some(NetworkNamespace::new(namespace));
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let stderr = log.try_clone().unwrap();
        let mut command = if let Some(namespace) = &self.network_namespace {
            namespace.command(&self.environment)
        } else {
            let mut command = Command::new(program("mutualbackupd"));
            command.envs(self.environment.iter().cloned());
            command
        };
        let child = command
            .args(&self.args)
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    fn stop(&mut self) {
        self.stop_inner(false);
    }

    fn stop_gracefully(&mut self) {
        self.stop_inner(true);
    }

    fn stop_inner(&mut self, require_graceful: bool) {
        if let Some(mut child) = self.child.take() {
            if let Some(namespace) = &self.network_namespace {
                namespace.signal_processes(libc::SIGTERM);
            } else {
                #[cfg(unix)]
                unsafe {
                    libc::kill(child.id() as libc::pid_t, libc::SIGTERM);
                }
            }
            let deadline = Instant::now() + Duration::from_secs(30);
            while Instant::now() < deadline {
                if child.try_wait().ok().flatten().is_some() {
                    return;
                }
                thread::sleep(Duration::from_millis(10));
            }
            if let Some(namespace) = &self.network_namespace {
                namespace.signal_processes(libc::SIGKILL);
            }
            let _ = child.kill();
            let _ = child.wait();
            if require_graceful && !thread::panicking() {
                panic!(
                    "daemon did not exit cleanly after SIGTERM:\n{}",
                    fs::read_to_string(&self.log).unwrap_or_default()
                );
            }
        }
    }

    fn assert_running(&mut self) {
        if let Some(child) = &mut self.child
            && let Some(status) = child.try_wait().unwrap()
        {
            panic!(
                "daemon exited unexpectedly with {status}:\n{}",
                fs::read_to_string(&self.log).unwrap_or_default()
            );
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop();
    }
}

struct ProcessNetworkTopology {
    coordinator_namespace: OsString,
    punched_namespace: OsString,
    fallback_namespace: OsString,
    relay_namespace: OsString,
    coordinator_ip: String,
    punched_ip: String,
    relay_ip: String,
    host_ip: String,
}

impl ProcessNetworkTopology {
    fn from_environment() -> Self {
        Self {
            coordinator_namespace: required_test_value("MUTUALBACKUP_TEST_NETNS_COORDINATOR"),
            punched_namespace: required_test_value("MUTUALBACKUP_TEST_NETNS_PUNCHED"),
            fallback_namespace: required_test_value("MUTUALBACKUP_TEST_NETNS_FALLBACK"),
            relay_namespace: required_test_value("MUTUALBACKUP_TEST_NETNS_RELAY"),
            coordinator_ip: required_test_utf8("MUTUALBACKUP_TEST_COORDINATOR_IP"),
            punched_ip: required_test_utf8("MUTUALBACKUP_TEST_PUNCHED_IP"),
            relay_ip: required_test_utf8("MUTUALBACKUP_TEST_RELAY_IP"),
            host_ip: required_test_utf8("MUTUALBACKUP_TEST_HOST_IP"),
        }
    }

    fn transport(&self, loopback_transport: &str, ip: &str) -> String {
        let suffix = loopback_transport
            .strip_prefix("/ip4/127.0.0.1/")
            .expect("acceptance transport must be an IPv4 loopback multiaddress");
        format!("/ip4/{ip}/{suffix}")
    }
}

#[cfg(target_os = "linux")]
#[test]
fn source_scan_cli_resets_unreadable_progress_through_daemon_and_restart() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let seed_file = temp.path().join("recovery.seed");
    let socket = temp.path().join("control.sock");
    let recovery = "source-scan-operational-recovery-fixture-2027!";
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            os(&data_dir),
            os("--seed-file"),
            os(&seed_file),
        ],
        recovery.as_bytes(),
        CLI_TIMEOUT,
    )
    .unwrap();
    drop(Node::open(&data_dir, Seed::from_recovery_string(recovery).unwrap()).unwrap());
    run_cli(&[
        os("db-shell"), os("--data-dir"), os(&data_dir), os("--seed-file"), os(&seed_file), os("--write"), os("--execute"),
        os("INSERT INTO protocol_records(kind, record_id, bytes) VALUES ('anchor-area-discovery-v1', X'00000000000000000000000000000001', X'756e7265616461626c65')"),
    ], CLI_TIMEOUT).unwrap();
    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            os(&data_dir),
            os("--seed-file"),
            os(&seed_file),
            os("--control-socket"),
            os(&socket),
            os("--failure-domain"),
            os("source-scan-test"),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
            os("--tor-mode"),
            os("disable-tor"),
        ],
        temp.path().join("daemon.log"),
    );
    daemon.start();
    wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    let area = "00000000-0000-0000-0000-000000000001";
    let listed = cli(&socket, ["source-scan", "list"], CLI_TIMEOUT);
    assert!(listed.contains(area));
    assert!(listed.contains("unreadable journal (10 bytes)"));
    assert!(
        run_cli(
            &[
                os("--socket"),
                os(&socket),
                os("source-scan"),
                os("--repository"),
                os(area),
                os("list")
            ],
            CLI_TIMEOUT
        )
        .is_err()
    );
    assert!(cli(&socket, ["source-scan", "list"], CLI_TIMEOUT).contains(area));
    assert!(
        cli(&socket, ["source-scan", "reset", area], CLI_TIMEOUT)
            .contains("retry the blocked operation")
    );
    assert!(
        cli(&socket, ["source-scan", "list"], CLI_TIMEOUT).contains("no unfinished source scans")
    );
    daemon.stop_gracefully();
    daemon.start();
    wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    assert!(
        cli(&socket, ["source-scan", "list"], CLI_TIMEOUT).contains("no unfinished source scans")
    );
    assert!(
        cli(&socket, ["source-scan", "reset", area], CLI_TIMEOUT).contains("no stored source scan")
    );
    daemon.stop_gracefully();
}

#[test]
fn daemon_requires_an_initialized_identity_without_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("missing-state");
    let output = Command::new(program("mutualbackupd"))
        .args([
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--failure-domain"),
            os("missing-manifest-test"),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!data_dir.exists());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("identity manifest"),
        "unexpected daemon error:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn init_rejection_does_not_mutate_an_existing_directory() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("existing-state");
    fs::create_dir(&data_dir).unwrap();
    fs::write(data_dir.join("user-file"), b"must survive").unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o750)).unwrap();
    let result = run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        b"non-mutating-initialization-recovery-string-2027!",
        CLI_TIMEOUT,
    );
    assert!(result.is_err());
    assert_eq!(
        fs::metadata(&data_dir).unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert_eq!(
        fs::read(data_dir.join("user-file")).unwrap(),
        b"must survive"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn automatic_unlock_rejects_withdrawn_catalog_before_lock_or_socket_mutation() {
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt;

    for journal_state in 0..3 {
        let temp = tempfile::tempdir().unwrap();
        set_private(temp.path());
        let data = temp.path().join("state");
        let seed_file = temp.path().join("node.seed");
        let recovery = "correct-horse-battery-staple-2026!";
        run_cli_with_input(
            &[
                os("init"),
                os("--seed-stdin"),
                os("--data-dir"),
                os(&data),
                os("--seed-file"),
                os(&seed_file),
            ],
            recovery.as_bytes(),
            CLI_TIMEOUT,
        )
        .unwrap();
        let seed = Seed::from_recovery_string(recovery).unwrap();
        let keys = KeyMaterial::from_seed(&seed);
        let control = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
        control
            .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
            .unwrap();
        control
            .put_record("guarded-view-mount-v1", b"legacy", b"preserve")
            .unwrap();
        let data = if journal_state == 1 {
            let copy = temp.path().join("preserved");
            fs::create_dir(&copy).unwrap();
            for entry in fs::read_dir(&data).unwrap() {
                let entry = entry.unwrap();
                if entry.file_name() != "control.db-shm" {
                    fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
                }
            }
            copy
        } else {
            data
        };
        let _writer = if journal_state == 2 {
            Some(control)
        } else {
            drop(control);
            None
        };
        fs::set_permissions(&data, fs::Permissions::from_mode(0o750)).unwrap();
        let wrong_seed_file = temp.path().join("wrong.seed");
        mutualbackup::write_seed(
            &wrong_seed_file,
            "another-long-recovery-string-for-testing-2027!",
        )
        .unwrap();
        let snapshot = || {
            let metadata = fs::metadata(&data).unwrap();
            let version = (
                metadata.dev(),
                metadata.ino(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
                metadata.ctime(),
                metadata.ctime_nsec(),
            );
            let files = fs::read_dir(&data)
                .unwrap()
                .map(|entry| {
                    let entry = entry.unwrap();
                    (entry.file_name(), fs::read(entry.path()).unwrap())
                })
                .collect::<BTreeMap<_, _>>();
            (version, files)
        };
        for (selected_seed, expected_error) in [
            (&seed_file, mb_store::WITHDRAWN_GUARDED_BACKEND),
            (&wrong_seed_file, "expected"),
        ] {
            let before = snapshot();
            let output = run_output(
                program("mutualbackupd"),
                &[
                    os("--data-dir"),
                    os(&data),
                    os("--seed-file"),
                    os(selected_seed),
                    os("--control-socket"),
                    os(data.join("control.sock")),
                    os("--failure-domain"),
                    os("withdrawn-admission-test"),
                    os("--listen"),
                    os("/ip4/127.0.0.1/udp/0/quic-v1"),
                    os("--tor-mode"),
                    os("disable-tor"),
                ],
                CLI_TIMEOUT,
            )
            .unwrap();
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains(expected_error), "{stderr}");
            let after = snapshot();
            assert_eq!(before.0, after.0);
            assert_eq!(
                before.1.keys().collect::<Vec<_>>(),
                after.1.keys().collect::<Vec<_>>()
            );
            for (name, bytes) in before.1 {
                if name == "control.db-shm" {
                    assert_eq!(bytes.len(), after.1[&name].len());
                } else {
                    assert_eq!(bytes, after.1[&name], "{name:?}");
                }
            }
            assert!(!data.join(".node.lock").exists());
            assert!(!data.join("control.sock").exists());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn manual_unlock_preserves_withdrawn_catalog_before_and_after_rejected_secrets() {
    use std::{collections::BTreeMap, os::unix::fs::MetadataExt};
    for journal in 0..3 {
        for socket_state in ["absent", "file", "missing-parent"] {
            let temp = tempfile::tempdir().unwrap();
            set_private(temp.path());
            let data = temp.path().join("state");
            let recovery = "correct-horse-battery-staple-2026!";
            run_cli_with_input(
                &[os("init"), os("--seed-stdin"), os("--data-dir"), os(&data)],
                recovery.as_bytes(),
                CLI_TIMEOUT,
            )
            .unwrap();
            let keys = KeyMaterial::from_seed(&Seed::from_recovery_string(recovery).unwrap());
            let control = mb_store::ControlStore::open(data.join("control.db"), &keys).unwrap();
            control
                .database_shell_statement("PRAGMA wal_autocheckpoint=0", false)
                .unwrap();
            control
                .put_record("guarded-view-mount-v1", b"legacy", b"preserve")
                .unwrap();
            let data = if journal == 1 {
                let copy = temp.path().join("preserved");
                fs::create_dir(&copy).unwrap();
                for entry in fs::read_dir(&data).unwrap() {
                    let entry = entry.unwrap();
                    if entry.file_name() != "control.db-shm" {
                        fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
                    }
                }
                copy
            } else {
                data
            };
            let _writer = if journal == 2 {
                Some(control)
            } else {
                drop(control);
                None
            };
            let socket = if socket_state == "missing-parent" {
                data.join("absent/control.sock")
            } else {
                data.join("control.sock")
            };
            if socket_state == "file" {
                fs::write(&socket, b"preserved socket-path file").unwrap();
            }
            fs::set_permissions(&data, fs::Permissions::from_mode(0o750)).unwrap();
            let snapshot = || {
                let metadata = fs::metadata(&data).unwrap();
                let version = (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.mode(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                );
                let files = fs::read_dir(&data)
                    .unwrap()
                    .map(|entry| {
                        let entry = entry.unwrap();
                        (entry.file_name(), fs::read(entry.path()).unwrap())
                    })
                    .collect::<BTreeMap<_, _>>();
                (version, files)
            };
            let before = snapshot();
            let mut daemon = Daemon::with_args(
                vec![
                    os("--data-dir"),
                    os(&data),
                    os("--control-socket"),
                    os(&socket),
                    os("--failure-domain"),
                    os("manual-withdrawal-admission"),
                    os("--listen"),
                    os("/ip4/127.0.0.1/udp/0/quic-v1"),
                    os("--tor-mode"),
                    os("disable-tor"),
                ],
                temp.path().join("daemon.log"),
            );
            daemon.start();
            assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));
            for (secret, expected) in [
                ("another-long-recovery-string-for-testing-2027!", "expected"),
                (recovery, mb_store::WITHDRAWN_GUARDED_BACKEND),
                (recovery, mb_store::WITHDRAWN_GUARDED_BACKEND),
            ] {
                let error = run_cli_with_input(
                    &[
                        os("--socket"),
                        os(&socket),
                        os("unlock"),
                        os("--seed-stdin"),
                    ],
                    secret.as_bytes(),
                    CLI_TIMEOUT,
                )
                .unwrap_err();
                assert!(
                    error.contains(expected),
                    "{journal}/{socket_state}: {error}"
                );
                assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));
            }
            daemon.stop_gracefully();
            let after = snapshot();
            assert_eq!(before.0, after.0, "{journal}/{socket_state}");
            assert_eq!(
                before.1.keys().collect::<Vec<_>>(),
                after.1.keys().collect::<Vec<_>>()
            );
            for (name, bytes) in before.1 {
                if name == "control.db-shm" {
                    assert_eq!(bytes.len(), after.1[&name].len());
                } else {
                    assert_eq!(bytes, after.1[&name], "{journal}/{socket_state}/{name:?}");
                }
            }
            assert!(!data.join(".node.lock").exists());
            if socket_state == "file" {
                assert_eq!(fs::read(&socket).unwrap(), b"preserved socket-path file");
            } else {
                assert!(!socket.exists());
            }
            assert!(!data.join("absent").exists());
        }
    }
}

#[test]
fn init_resumes_after_seed_install_without_replacing_outputs() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let seed_file = temp.path().join("node.seed");
    let args = [
        os("init"),
        os("--seed-file"),
        seed_file.as_os_str().to_owned(),
        os("--data-dir"),
        data_dir.as_os_str().to_owned(),
    ];

    if uses_cargo_debug_programs() {
        let interrupted = Command::new(program("mutualbackup"))
            .args(&args)
            .env("MUTUALBACKUP_TEST_FAIL_AFTER_SEED_INSTALL", "1")
            .output()
            .unwrap();
        assert!(!interrupted.status.success());
    } else {
        // Installed release programs omit debug failpoints. Recreate the
        // durable interrupted state and exercise their real resume path.
        mutualbackup::write_seed(
            &seed_file,
            "release-resumable-initialization-recovery-string-2027!",
        )
        .unwrap();
    }
    assert!(seed_file.is_file());
    assert!(!data_dir.exists());

    run_cli(&args, CLI_TIMEOUT).unwrap();
    let installed = read_identity_manifest(&data_dir).unwrap();
    let seed_before = fs::read(&seed_file).unwrap();
    let manifest_before = fs::read(data_dir.join("identity.toml")).unwrap();

    run_cli(&args, CLI_TIMEOUT).unwrap();
    assert_eq!(fs::read(&seed_file).unwrap(), seed_before);
    assert_eq!(
        fs::read(data_dir.join("identity.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        installed.expected_node_id,
        KeyMaterial::from_seed(&mutualbackup::read_seed(&seed_file).unwrap()).node_id()
    );

    let conflict = run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--seed-file"),
            seed_file.as_os_str().to_owned(),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        b"different-strong-recovery-string-for-no-replace-2027!",
        CLI_TIMEOUT,
    );
    assert!(conflict.is_err());
    assert_eq!(fs::read(&seed_file).unwrap(), seed_before);
    assert_eq!(
        fs::read(data_dir.join("identity.toml")).unwrap(),
        manifest_before
    );
    assert_eq!(
        fs::read_dir(temp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
            .count(),
        0
    );
}

#[test]
fn init_preflights_an_existing_manifest_before_installing_a_seed() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let matching_recovery = "matching-existing-manifest-recovery-string-2027!";

    let matching_data = temp.path().join("matching-state");
    let matching_seed_file = temp.path().join("matching.seed");
    let matching_seed = Seed::from_recovery_string(matching_recovery).unwrap();
    mutualbackup::initialize_identity(&matching_data, &matching_seed, InitializationIntent::New)
        .unwrap();
    let matching_manifest = fs::read(matching_data.join("identity.toml")).unwrap();
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--seed-file"),
            matching_seed_file.as_os_str().to_owned(),
            os("--data-dir"),
            matching_data.as_os_str().to_owned(),
        ],
        matching_recovery.as_bytes(),
        CLI_TIMEOUT,
    )
    .unwrap();
    assert!(matching_seed_file.is_file());
    assert_eq!(
        fs::read(matching_data.join("identity.toml")).unwrap(),
        matching_manifest
    );

    let conflicting_data = temp.path().join("conflicting-state");
    let conflicting_seed_file = temp.path().join("conflicting.seed");
    mutualbackup::initialize_identity(&conflicting_data, &matching_seed, InitializationIntent::New)
        .unwrap();
    let conflicting_manifest = fs::read(conflicting_data.join("identity.toml")).unwrap();
    let conflict = run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--seed-file"),
            conflicting_seed_file.as_os_str().to_owned(),
            os("--data-dir"),
            conflicting_data.as_os_str().to_owned(),
        ],
        b"different-existing-manifest-recovery-string-2027!",
        CLI_TIMEOUT,
    );
    assert!(conflict.is_err());
    assert!(!conflicting_seed_file.exists());
    assert_eq!(
        fs::read(conflicting_data.join("identity.toml")).unwrap(),
        conflicting_manifest
    );

    let generated_seed_file = temp.path().join("generated.seed");
    let generated = run_cli(
        &[
            os("init"),
            os("--seed-file"),
            generated_seed_file.as_os_str().to_owned(),
            os("--data-dir"),
            conflicting_data.as_os_str().to_owned(),
        ],
        CLI_TIMEOUT,
    );
    assert!(generated.is_err());
    assert!(!generated_seed_file.exists());
    assert_eq!(
        fs::read(conflicting_data.join("identity.toml")).unwrap(),
        conflicting_manifest
    );
}

#[test]
fn init_rejects_overlapping_output_paths_without_mutation() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let recovery = b"overlapping-initialization-output-recovery-string-2027!";

    let equal_output = temp.path().join("equal-output");
    assert!(
        run_cli_with_input(
            &[
                os("init"),
                os("--seed-stdin"),
                os("--seed-file"),
                equal_output.as_os_str().to_owned(),
                os("--data-dir"),
                equal_output.as_os_str().to_owned(),
            ],
            recovery,
            CLI_TIMEOUT,
        )
        .is_err()
    );
    assert!(!equal_output.exists());

    let containing_data = temp.path().join("containing-state");
    fs::create_dir(&containing_data).unwrap();
    let contained_seed = containing_data.join("node.seed");
    assert!(
        run_cli_with_input(
            &[
                os("init"),
                os("--seed-stdin"),
                os("--seed-file"),
                contained_seed.as_os_str().to_owned(),
                os("--data-dir"),
                containing_data.as_os_str().to_owned(),
            ],
            recovery,
            CLI_TIMEOUT,
        )
        .is_err()
    );
    assert!(fs::read_dir(&containing_data).unwrap().next().is_none());

    let ancestor_seed = temp.path().join("seed-as-parent");
    let nested_data = ancestor_seed.join("state");
    assert!(
        run_cli_with_input(
            &[
                os("init"),
                os("--seed-stdin"),
                os("--seed-file"),
                ancestor_seed.as_os_str().to_owned(),
                os("--data-dir"),
                nested_data.as_os_str().to_owned(),
            ],
            recovery,
            CLI_TIMEOUT,
        )
        .is_err()
    );
    assert!(!ancestor_seed.exists());

    let real_data = temp.path().join("real-state");
    fs::create_dir(&real_data).unwrap();
    let data_alias = temp.path().join("state-alias");
    symlink(&real_data, &data_alias).unwrap();
    let aliased_seed = data_alias.join("node.seed");
    assert!(
        run_cli_with_input(
            &[
                os("init"),
                os("--seed-stdin"),
                os("--seed-file"),
                aliased_seed.as_os_str().to_owned(),
                os("--data-dir"),
                real_data.as_os_str().to_owned(),
            ],
            recovery,
            CLI_TIMEOUT,
        )
        .is_err()
    );
    assert!(fs::read_dir(&real_data).unwrap().next().is_none());

    let dotdot_parent = temp.path().join("dotdot-parent");
    fs::create_dir(&dotdot_parent).unwrap();
    let dotdot_seed = dotdot_parent.join("../real-state/node.seed");
    assert!(
        run_cli_with_input(
            &[
                os("init"),
                os("--seed-stdin"),
                os("--seed-file"),
                dotdot_seed.as_os_str().to_owned(),
                os("--data-dir"),
                real_data.as_os_str().to_owned(),
            ],
            recovery,
            CLI_TIMEOUT,
        )
        .is_err()
    );
    assert!(fs::read_dir(&real_data).unwrap().next().is_none());
}

#[test]
fn init_accepts_bare_relative_seed_and_data_paths() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let mut child = Command::new(program("mutualbackup"))
        .current_dir(temp.path())
        .args([
            "init",
            "--seed-stdin",
            "--seed-file",
            "node.seed",
            "--data-dir",
            "state",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"bare-relative-initialization-recovery-string-2027!")
        .unwrap();
    let output = wait_for_output(child, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "relative init failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(temp.path().join("node.seed").is_file());
    assert!(temp.path().join("state/identity.toml").is_file());
}

#[test]
fn daemon_never_reports_ready_when_its_only_listener_cannot_start() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let seed_file = temp.path().join("node.seed");
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--seed-file"),
            seed_file.as_os_str().to_owned(),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        b"listener-readiness-recovery-string-2027!",
        CLI_TIMEOUT,
    )
    .unwrap();
    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1",
        occupied.local_addr().unwrap().port()
    );
    let output = run_output(
        program("mutualbackupd"),
        &[
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--seed-file"),
            seed_file.as_os_str().to_owned(),
            os("--control-socket"),
            temp.path().join("control.sock").into_os_string(),
            os("--failure-domain"),
            os("listener-readiness-test"),
            os("--tor-mode"),
            os("disable-tor"),
            os("--listen"),
            os(address),
        ],
        Duration::from_secs(40),
    )
    .unwrap();
    assert!(!output.status.success());
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains(" ready"),
        "daemon falsely reported readiness:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("libp2p") || stderr.contains("cannot listen on"),
        "unexpected daemon error:\n{stderr}"
    );
}

#[test]
fn manual_unlock_returns_to_locked_after_network_startup_failure() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let socket = temp.path().join("control.sock");
    let recovery = "manual-network-retry-recovery-string-2027!";
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        recovery.as_bytes(),
        CLI_TIMEOUT,
    )
    .unwrap();

    let occupied = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = format!(
        "/ip4/127.0.0.1/udp/{}/quic-v1",
        occupied.local_addr().unwrap().port()
    );
    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--control-socket"),
            socket.as_os_str().to_owned(),
            os("--failure-domain"),
            os("manual-network-retry-test"),
            os("--tor-mode"),
            os("disable-tor"),
            os("--listen"),
            os(address.clone()),
        ],
        temp.path().join("daemon.log"),
    );
    daemon.start();
    assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));

    let first_unlock = run_cli_with_input(
        &[
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("unlock"),
            os("--seed-stdin"),
        ],
        recovery.as_bytes(),
        Duration::from_secs(40),
    );
    assert!(first_unlock.is_err());
    daemon.assert_running();
    assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));

    drop(occupied);
    run_cli_with_input(
        &[
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("unlock"),
            os("--seed-stdin"),
        ],
        recovery.as_bytes(),
        Duration::from_secs(40),
    )
    .unwrap();
    daemon.assert_running();
    let status = wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    assert!(
        !status.contains("Locked"),
        "daemon stayed locked:\n{status}"
    );
}

#[test]
fn manual_unlock_returns_to_locked_when_tor_state_is_already_in_use() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let socket = temp.path().join("control.sock");
    let tor_state = temp.path().join("tor-state");
    let tor_cache = temp.path().join("tor-cache");
    let recovery = "manual-tor-lock-recovery-string-2027!";
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        recovery.as_bytes(),
        CLI_TIMEOUT,
    )
    .unwrap();

    fs::create_dir(&tor_state).unwrap();
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(tor_state.join("mutualbackup.lock"))
        .unwrap();
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );

    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--control-socket"),
            socket.as_os_str().to_owned(),
            os("--failure-domain"),
            os("manual-tor-lock-test"),
            os("--tor-state-dir"),
            tor_state.as_os_str().to_owned(),
            os("--tor-cache-dir"),
            tor_cache.as_os_str().to_owned(),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
        ],
        temp.path().join("daemon.log"),
    );
    daemon.start();
    assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));

    let error = run_cli_with_input(
        &[
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("unlock"),
            os("--seed-stdin"),
        ],
        recovery.as_bytes(),
        Duration::from_secs(10),
    )
    .unwrap_err();
    assert!(
        error.contains("already in use"),
        "unexpected error: {error}"
    );
    daemon.assert_running();
    assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));
}

#[test]
fn daemon_accepts_config_only_and_flag_overrides() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        b"config-precedence-recovery-string-2027!",
        CLI_TIMEOUT,
    )
    .unwrap();
    let config_socket = temp.path().join("from-config.sock");
    let override_socket = temp.path().join("from-flag.sock");
    let config_path = temp.path().join("node.toml");
    write_test_config(
        &config_path,
        &DaemonOptions {
            config_file: None,
            data_dir,
            seed_file: None,
            start_locked: false,
            control_socket: config_socket.clone(),
            failure_domain: Some("config-precedence-test".to_owned()),
            parity_budget_bytes: 10 * 1024 * 1024 * 1024,
            parity_volumes: Vec::new(),
            parity_headroom_bytes: None,
            retention_revisions: 30,
            automatic_backup: false,
            backup_quiet_seconds: 300,
            backup_minimum_interval_seconds: 3_600,
            full_reconcile_interval_seconds: 86_400,
            daily_backup_limit: 24,
            daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
            audit_interval_seconds: 21_600,
            clear_parity_volumes: false,
            p2p_listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".to_owned()],
            clear_p2p_listen_addresses: false,
            p2p_external_addresses: Vec::new(),
            clear_p2p_external_addresses: false,
            p2p_bootstrap_addresses: Vec::new(),
            clear_p2p_bootstrap_addresses: false,
            p2p_relay_addresses: Vec::new(),
            clear_p2p_relay_addresses: false,
            enable_relay_server: false,
            enable_hole_punching: true,
            enable_port_mapping: false,
            enable_dht_maintenance: true,
            tor_mode: mb_node::TorMode::DisableTor,
            tor_state_dir: None,
            tor_cache_dir: None,
            arti_config_file: None,
            max_connections: 32,
        },
    );

    let mut config_daemon = Daemon::new(config_path.clone(), temp.path().join("config.log"));
    config_daemon.start();
    assert!(wait_for_status(&config_socket, &mut config_daemon, CLI_TIMEOUT).contains("Locked"));
    config_daemon.stop();

    let mut override_daemon = Daemon::with_args(
        vec![
            os("--config"),
            config_path.into_os_string(),
            os("--control-socket"),
            override_socket.as_os_str().to_owned(),
        ],
        temp.path().join("override.log"),
    );
    override_daemon.start();
    assert!(
        wait_for_status(&override_socket, &mut override_daemon, CLI_TIMEOUT).contains("Locked")
    );
}

#[test]
fn daemon_starts_locked_and_rejects_the_wrong_identity_before_opening_storage() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let run_dir = temp.path().join("run");
    fs::create_dir(&run_dir).unwrap();
    set_private(&run_dir);
    let socket = run_dir.join("control.sock");
    let recovery = "correct-horse-battery-staple-2026!";
    let initialized = run_cli_with_input(
        &[
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        recovery.as_bytes(),
        Duration::from_secs(30),
    )
    .unwrap();
    let expected_node_id = value_after(&initialized, "node id:       ");
    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--control-socket"),
            socket.as_os_str().to_owned(),
            os("--failure-domain"),
            os("locked-daemon-test"),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
            os("--tor-mode"),
            os("disable-tor"),
        ],
        temp.path().join("daemon.log"),
    );
    daemon.start();
    let locked = wait_for_status(&socket, &mut daemon, Duration::from_secs(30));
    assert!(locked.contains("state:         Locked"));
    assert!(!data_dir.join("control.db").exists());

    let wrong = run_cli_with_input(
        &[
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("unlock"),
            os("--seed-stdin"),
        ],
        b"another-long-recovery-string-for-testing-2027!",
        Duration::from_secs(30),
    )
    .unwrap_err();
    assert!(wrong.contains("expected"));
    assert!(!data_dir.join("control.db").exists());
    assert!(wait_for_status(&socket, &mut daemon, Duration::from_secs(10)).contains("Locked"));

    run_cli_with_input(
        &[
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("unlock"),
            os("--seed-stdin"),
        ],
        recovery.as_bytes(),
        Duration::from_secs(30),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let status = wait_for_status(&socket, &mut daemon, Duration::from_secs(5));
        if status.contains(&expected_node_id) && !status.contains("Locked") {
            break;
        }
        assert!(Instant::now() < deadline, "daemon did not finish unlocking");
    }
    assert!(data_dir.join("control.db").exists());
}

#[cfg(unix)]
#[test]
fn locked_daemon_exits_cleanly_on_sigterm() {
    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let socket = temp.path().join("control.sock");
    run_cli_with_input(
        &[
            os("init"),
            os("--seed-stdin"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
        ],
        b"locked-signal-clean-shutdown-recovery-string-2027!",
        CLI_TIMEOUT,
    )
    .unwrap();

    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--control-socket"),
            socket.as_os_str().to_owned(),
            os("--failure-domain"),
            os("locked-signal-test"),
            os("--tor-mode"),
            os("disable-tor"),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
        ],
        temp.path().join("daemon.log"),
    );
    daemon.start();
    assert!(wait_for_status(&socket, &mut daemon, CLI_TIMEOUT).contains("Locked"));
    daemon.stop_gracefully();
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an explicitly provisioned reflink test filesystem"]
fn raw_unix_paths_survive_cli_daemon_and_git_checkout() {
    let test_root = PathBuf::from(
        std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
            .expect("the acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT"),
    );
    let source_area = tempfile::tempdir_in(test_root).unwrap();
    let source = source_area
        .path()
        .join(OsString::from_vec(b"source-\xfe".to_vec()));
    fs::create_dir(&source).unwrap();
    let relative = PathBuf::from(OsString::from_vec(b"file-\xff".to_vec()));
    let link_relative = PathBuf::from(OsString::from_vec(b"link-\xfc".to_vec()));
    fs::write(source.join(&relative), b"exact bytes").unwrap();
    std::os::unix::fs::symlink(&relative, source.join(&link_relative)).unwrap();

    let temp = tempfile::tempdir().unwrap();
    set_private(temp.path());
    let data_dir = temp.path().join("state");
    let seed_file = temp.path().join("seed");
    let socket = temp.path().join("control.sock");
    run_cli(
        &[
            os("init"),
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--seed-file"),
            seed_file.as_os_str().to_owned(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    let mut daemon = Daemon::with_args(
        vec![
            os("--data-dir"),
            data_dir.into_os_string(),
            os("--seed-file"),
            seed_file.into_os_string(),
            os("--control-socket"),
            socket.as_os_str().to_owned(),
            os("--failure-domain"),
            os("raw-path-test"),
            os("--tor-mode"),
            os("disable-tor"),
            os("--listen"),
            os("/ip4/127.0.0.1/udp/0/quic-v1"),
        ],
        temp.path().join("daemon.log"),
    );
    daemon.start();
    wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    cli_path(&socket, ["root", "add"], &source);
    let response = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(mb_node::local_control_call(
            &socket,
            &mb_node::LocalRequest::Status,
        ))
        .unwrap();
    let mb_node::LocalResponse::Status(status) = response else {
        panic!("daemon returned the wrong status response");
    };
    assert!(
        status
            .protected_roots
            .iter()
            .any(|root| root.path == source)
    );
    git_cli(&socket, &source, ["init"]);
    let mut git_args = vec![
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("-C"),
        source.as_os_str().to_owned(),
        os("add"),
        relative.as_os_str().to_owned(),
    ];
    let output = run_output(program("mutualgit"), &git_args, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "raw Git add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    git_args[5] = link_relative.as_os_str().to_owned();
    let output = run_output(program("mutualgit"), &git_args, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "raw Git symlink add failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    daemon.stop_gracefully();
    daemon.start();
    wait_for_status(&socket, &mut daemon, CLI_TIMEOUT);
    git_cli(
        &socket,
        &source,
        [
            "commit",
            "-m",
            "raw path",
            "--author-name",
            "Raw Path",
            "--author-email",
            "raw@example.test",
        ],
    );
    let bare = temp.path().join("stock.git");
    let output = Command::new("git")
        .arg("init")
        .arg("--bare")
        .arg(&bare)
        .output()
        .unwrap();
    assert!(output.status.success());
    let bare_arg = bare.to_str().unwrap();
    git_cli(&socket, &source, ["push", bare_arg]);
    git_cli(&socket, &source, ["fetch", bare_arg]);
    let status = git_cli(&socket, &source, ["status"]);
    assert!(status.contains("Git backup descriptor:"), "{status}");
    assert!(status.contains("enclosing revision and source verification still required"));
    let source_oid = git2::Repository::open_bare(&bare)
        .unwrap()
        .find_reference("refs/heads/main")
        .unwrap()
        .target()
        .unwrap();
    git_cli(&socket, &source, ["tag", "retained"]);
    git_cli(&socket, &source, ["pin", &source_oid.to_string()]);
    let full_export = source_area
        .path()
        .join(OsString::from_vec(b"history-\xfd.git".to_vec()));
    assert!(
        Command::new("git")
            .args(["init", "--bare"])
            .arg(&full_export)
            .output()
            .unwrap()
            .status
            .success()
    );
    let export_args = vec![
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("-C"),
        source.as_os_str().to_owned(),
        os("export"),
        full_export.as_os_str().to_owned(),
    ];
    let output = run_output(program("mutualgit"), &export_args, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "full export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let exported = git2::Repository::open_bare(&full_export).unwrap();
    for reference in [
        "refs/heads/main".to_owned(),
        "refs/remotes/origin/main".to_owned(),
        "refs/tags/retained".to_owned(),
        format!("refs/mutualbackup/pins/{source_oid}"),
    ] {
        assert_eq!(
            exported.find_reference(&reference).unwrap().target(),
            Some(source_oid)
        );
    }
    let exported_tree = exported.find_commit(source_oid).unwrap().tree().unwrap();
    let exported_file = exported_tree
        .iter()
        .find(|entry| entry.name_bytes() == relative.as_os_str().as_bytes())
        .unwrap();
    assert_eq!(
        exported.find_blob(exported_file.id()).unwrap().content(),
        b"exact bytes"
    );
    let exported_link = exported_tree
        .iter()
        .find(|entry| entry.name_bytes() == link_relative.as_os_str().as_bytes())
        .unwrap();
    assert_eq!(
        exported.find_blob(exported_link.id()).unwrap().content(),
        relative.as_os_str().as_bytes()
    );
    assert!(
        Command::new("git")
            .arg("--git-dir")
            .arg(&full_export)
            .args(["fsck", "--full", "--strict"])
            .output()
            .unwrap()
            .status
            .success()
    );
    fs::write(source.join(&relative), b"edited bytes").unwrap();
    fs::remove_file(source.join(&link_relative)).unwrap();
    git_args[4] = os("restore");
    git_args[5] = relative.as_os_str().to_owned();
    git_args.push(link_relative.as_os_str().to_owned());
    let output = run_output(program("mutualgit"), &git_args, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "raw Git restore failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read(source.join(&relative)).unwrap(), b"exact bytes");
    assert_eq!(fs::read_link(source.join(link_relative)).unwrap(), relative);
    daemon.stop_gracefully();
}

#[test]
#[ignore = "requires an explicitly provisioned reflink test filesystem"]
fn five_daemons_recover_latest_snapshot_from_seed_and_dht() {
    let topology = ProcessNetworkTopology::from_environment();
    // The Btrfs source path can be long; recovery adds still longer state
    // directory names. Keep every control socket in a short private IPC area.
    let control_directory = tempfile::Builder::new()
        .prefix("mb-net-ctl-")
        .tempdir()
        .unwrap();
    set_private(control_directory.path());
    let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
        .expect("the acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
    let run_root = PathBuf::from(test_root).join(format!("process-{}", Uuid::new_v4()));
    fs::create_dir_all(&run_root).unwrap();
    let mut peer_log_archive = PeerLogArchive::from_environment(&run_root).unwrap();
    let seed_dir = run_root.join("offline");
    fs::create_dir(&seed_dir).unwrap();
    set_private(&seed_dir);

    let reserved_ports = (0..10)
        .map(|_| UdpSocket::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let ports = reserved_ports
        .iter()
        .map(|socket| socket.local_addr().unwrap().port())
        .collect::<Vec<_>>();
    let transports = ports
        .iter()
        .map(|port| format!("/ip4/127.0.0.1/udp/{port}/quic-v1"))
        .collect::<Vec<_>>();

    let mut peer_ids = Vec::new();
    let mut node_ids = Vec::new();
    let mut sockets = Vec::new();
    let mut configs = Vec::new();
    for index in 0..5 {
        let peer_dir = run_root.join(format!("p{index}"));
        fs::create_dir(&peer_dir).unwrap();
        set_private(&peer_dir);
        let seed = seed_dir.join(format!("p{index}.seed"));
        let config = peer_dir.join("node.toml");
        let socket = control_directory.path().join(format!("p{index}"));
        let args = vec![
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("init"),
            os("--seed-file"),
            seed.as_os_str().to_owned(),
            os("--data-dir"),
            peer_dir.join("state").into_os_string(),
        ];
        let output = run_cli(&args, CLI_TIMEOUT).unwrap();
        let recovery_string = fs::read_to_string(&seed).unwrap();
        assert_eq!(recovery_string.split_whitespace().count(), 24);
        peer_ids.push(value_after(&output, "libp2p peer id: "));
        node_ids.push(
            value_after(&output, "node id:       ")
                .parse::<NodeId>()
                .unwrap(),
        );
        let bootstrap_addresses = if index == 0 {
            Vec::new()
        } else {
            vec![format!("{}/p2p/{}", transports[0], peer_ids[0])]
        };
        write_test_config(
            &config,
            &DaemonOptions {
                config_file: None,
                data_dir: peer_dir.join("state"),
                seed_file: Some(seed),
                start_locked: false,
                control_socket: socket.clone(),
                failure_domain: Some(format!("disk-{index}")),
                parity_budget_bytes: 10 * 1024 * 1024 * 1024,
                parity_volumes: Vec::new(),
                parity_headroom_bytes: None,
                retention_revisions: 30,
                automatic_backup: false,
                backup_quiet_seconds: 300,
                backup_minimum_interval_seconds: 3_600,
                full_reconcile_interval_seconds: 86_400,
                daily_backup_limit: 24,
                daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
                audit_interval_seconds: 21_600,
                clear_parity_volumes: false,
                p2p_listen_addresses: vec![transports[index].clone()],
                clear_p2p_listen_addresses: false,
                p2p_external_addresses: vec![transports[index].clone()],
                clear_p2p_external_addresses: false,
                p2p_bootstrap_addresses: bootstrap_addresses,
                clear_p2p_bootstrap_addresses: false,
                p2p_relay_addresses: Vec::new(),
                clear_p2p_relay_addresses: false,
                enable_relay_server: index == 0,
                enable_hole_punching: true,
                enable_port_mapping: false,
                enable_dht_maintenance: true,
                tor_mode: mb_node::TorMode::DisableTor,
                tor_state_dir: None,
                tor_cache_dir: None,
                arti_config_file: None,
                max_connections: 32,
            },
        );
        sockets.push(socket);
        configs.push(config);
    }
    drop(reserved_ports);

    let mut daemons = configs
        .iter()
        .enumerate()
        .map(|(index, config)| {
            let mut daemon = Daemon::new(config.clone(), run_root.join(format!("p{index}.log")));
            daemon.set_env("RUST_LOG", TOPOLOGY_LOG_FILTER);
            if index == 0 && uses_cargo_debug_programs() {
                daemon.set_env("MUTUALBACKUP_TEST_FAIL_BEFORE_LOCAL_GUILD_INSTALL", "1");
            }
            daemon.start();
            daemon
        })
        .collect::<Vec<_>>();
    for index in 0..5 {
        wait_for_status(
            &sockets[index],
            &mut daemons[index],
            Duration::from_secs(30),
        );
    }

    exercise_local_control_limit(&sockets[0], &mut daemons[0]);

    cli(&sockets[0], ["guild", "create"], CLI_TIMEOUT);
    let invite = cli(&sockets[0], ["guild", "invite"], CLI_TIMEOUT);
    let token = value_after(&invite, "invitation: ");
    daemons[0].stop();
    let failed_join = run_cli(
        &[
            os("--socket"),
            sockets[1].as_os_str().to_owned(),
            os("guild"),
            os("join"),
            os(&token),
        ],
        CLI_TIMEOUT,
    )
    .unwrap_err();
    assert!(
        cli(&sockets[1], ["guild", "status"], CLI_TIMEOUT).contains("Joining"),
        "failed join did not persist a resumable state: {failed_join}"
    );
    daemons[0].start();
    wait_for_status(&sockets[0], &mut daemons[0], Duration::from_secs(30));
    for index in 1..5 {
        wait_for_status_text(
            &sockets[index],
            &mut daemons[index],
            &peer_ids[0],
            Duration::from_secs(45),
        );
    }
    assert!(retry_pending_guild_join(&sockets[1], Duration::from_secs(90)).contains("Joining"));
    for index in 2..5 {
        let invite = cli(&sockets[0], ["guild", "invite"], CLI_TIMEOUT);
        let token = value_after(&invite, "invitation: ");
        join_guild_with_retry(&sockets[index], token.as_str(), Duration::from_secs(90));
    }
    if uses_cargo_debug_programs() {
        // Debug source qualification separately exercises the interruption
        // after remote installation. Production binaries have no such hook.
        let interrupted_finalize = run_cli(
            &[
                os("--socket"),
                sockets[0].as_os_str().to_owned(),
                os("guild"),
                os("finalize"),
            ],
            Duration::from_secs(60),
        )
        .unwrap_err();
        assert!(
            interrupted_finalize.contains("test interruption"),
            "unexpected interrupted-finalize result: {interrupted_finalize}"
        );
        assert!(cli(&sockets[0], ["guild", "status"], CLI_TIMEOUT).contains("Draft"));
        for socket in &sockets[1..] {
            assert!(cli(socket, ["guild", "status"], CLI_TIMEOUT).contains("Active"));
        }
    }
    let finalized = cli(&sockets[0], ["guild", "finalize"], Duration::from_secs(60));
    assert!(finalized.lines().any(|line| line == "members:     5"));

    let owner_one_source = run_root.join("p1/source");
    let owner_two_source = run_root.join("p2/source");
    fs::create_dir_all(owner_one_source.join("documents")).unwrap();
    fs::create_dir_all(owner_two_source.join("documents")).unwrap();
    fs::write(
        owner_one_source.join("documents/data.bin"),
        deterministic_bytes(180_000, 17),
    )
    .unwrap();
    fs::write(
        owner_two_source.join("documents/data.bin"),
        deterministic_bytes(190_000, 29),
    )
    .unwrap();
    let owner_one_initial = deterministic_bytes(180_000, 17);
    let topic_bytes = b"topic\r\n\0\xffbyte-exact\n";
    git_cli(&sockets[1], &owner_one_source, ["init"]);
    git_cli(
        &sockets[1],
        &owner_one_source,
        ["add", "documents/data.bin"],
    );
    git_cli(
        &sockets[1],
        &owner_one_source,
        [
            "commit",
            "--author-name",
            "Owner",
            "--author-email",
            "owner@example.test",
            "-m",
            "main",
        ],
    );
    git_cli(&sockets[1], &owner_one_source, ["branch", "topic"]);
    git_cli(&sockets[1], &owner_one_source, ["switch", "topic"]);
    fs::write(owner_one_source.join("documents/data.bin"), topic_bytes).unwrap();
    git_cli(
        &sockets[1],
        &owner_one_source,
        ["add", "documents/data.bin"],
    );
    git_cli(
        &sockets[1],
        &owner_one_source,
        [
            "commit",
            "--author-name",
            "Owner",
            "--author-email",
            "owner@example.test",
            "-m",
            "topic",
        ],
    );
    git_cli(&sockets[1], &owner_one_source, ["switch", "main"]);
    assert_eq!(
        fs::read(owner_one_source.join("documents/data.bin")).unwrap(),
        owner_one_initial
    );
    cli_path(&sockets[2], ["root", "add"], &owner_two_source);

    let first = cli(
        &sockets[1],
        ["backup", "--wait"],
        PROCESS_SMALL_BACKUP_TIMEOUT,
    );
    assert!(first.contains("state:      Committed"));
    assert!(
        git_cli(&sockets[1], &owner_one_source, ["status"])
            .contains("Commit graph and refs are protected by a signed backup")
    );
    let second = cli(
        &sockets[2],
        ["backup", "--wait"],
        PROCESS_SMALL_BACKUP_TIMEOUT,
    );
    assert!(second.contains("state:      Committed"));

    let expected_latest = deterministic_bytes(1024 * 1024 + 31, 41);
    fs::write(
        owner_one_source.join("documents/data.bin"),
        &expected_latest,
    )
    .unwrap();
    let interrupted = cli(&sockets[1], ["backup"], Duration::from_secs(120));
    let interrupted_revision = value_after(&interrupted, "revision:   ");
    thread::sleep(Duration::from_millis(100));
    daemons[0].stop();
    daemons[0].start();
    wait_for_status(&sockets[0], &mut daemons[0], Duration::from_secs(30));
    wait_for_backup(
        &sockets[1],
        &interrupted_revision,
        PROCESS_LARGE_BACKUP_TIMEOUT,
    );

    let snapshots = cli(&sockets[1], ["snapshot", "list"], CLI_TIMEOUT);
    assert_eq!(snapshots.lines().count(), 2);
    remove_anchor_areas(&run_root.join("p1"));
    let unavailable_source = run_root.join("p2/source-unavailable");
    fs::rename(&owner_two_source, &unavailable_source).unwrap();
    wait_for_status_text(
        &sockets[2],
        &mut daemons[2],
        "root dirty:     true",
        Duration::from_secs(30),
    );
    daemons[3].stop();
    let healthy_restore = run_root.join("healthy");
    cli_path(&sockets[1], ["snapshot", "restore"], &healthy_restore);
    assert_eq!(
        fs::read(healthy_restore.join("documents/data.bin")).unwrap(),
        expected_latest
    );
    daemons[3].start();
    wait_for_status(&sockets[3], &mut daemons[3], Duration::from_secs(30));
    fs::rename(&unavailable_source, &owner_two_source).unwrap();

    for daemon in &mut daemons {
        daemon.stop();
    }
    for daemon in &mut daemons {
        daemon.start();
    }
    for index in 0..5 {
        wait_for_status(
            &sockets[index],
            &mut daemons[index],
            Duration::from_secs(30),
        );
    }
    for index in 0..5 {
        wait_for_recovery_ready(
            &sockets[index],
            &mut daemons[index],
            Duration::from_secs(90),
        );
    }

    daemons[1].stop();
    daemons[4].stop();
    fs::remove_dir_all(run_root.join("p1")).unwrap();
    fs::remove_dir_all(run_root.join("p4")).unwrap();
    daemons[0].stop();

    let recovered_dir = run_root.join("recovered");
    fs::create_dir(&recovered_dir).unwrap();
    set_private(&recovered_dir);
    let recovered_socket = control_directory.path().join("recovered");
    let recovered_config = recovered_dir.join("node.toml");
    let bootstrap = format!("{}/p2p/{}", transports[0], peer_ids[0]);
    run_cli(
        &[
            os("--socket"),
            recovered_socket.as_os_str().to_owned(),
            os("recover-init"),
            os("--seed-file"),
            seed_dir.join("p1.seed").into_os_string(),
            os("--data-dir"),
            recovered_dir.join("state").into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    write_test_config(
        &recovered_config,
        &DaemonOptions {
            config_file: None,
            data_dir: recovered_dir.join("state"),
            seed_file: Some(seed_dir.join("p1.seed")),
            start_locked: false,
            control_socket: recovered_socket.clone(),
            failure_domain: None,
            parity_budget_bytes: 10 * 1024 * 1024 * 1024,
            parity_volumes: Vec::new(),
            parity_headroom_bytes: None,
            retention_revisions: 30,
            automatic_backup: false,
            backup_quiet_seconds: 300,
            backup_minimum_interval_seconds: 3_600,
            full_reconcile_interval_seconds: 86_400,
            daily_backup_limit: 24,
            daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
            audit_interval_seconds: 21_600,
            clear_parity_volumes: false,
            p2p_listen_addresses: vec![transports[5].clone()],
            clear_p2p_listen_addresses: false,
            p2p_external_addresses: vec![transports[5].clone()],
            clear_p2p_external_addresses: false,
            p2p_bootstrap_addresses: vec![bootstrap.clone()],
            clear_p2p_bootstrap_addresses: false,
            p2p_relay_addresses: Vec::new(),
            clear_p2p_relay_addresses: false,
            enable_relay_server: false,
            enable_hole_punching: true,
            enable_port_mapping: false,
            enable_dht_maintenance: true,
            tor_mode: mb_node::TorMode::DisableTor,
            tor_state_dir: None,
            tor_cache_dir: None,
            arti_config_file: None,
            max_connections: 32,
        },
    );
    let mut recovered_daemon =
        Daemon::new(recovered_config.clone(), run_root.join("recovered.log"));
    recovered_daemon.set_env("RUST_LOG", TOPOLOGY_LOG_FILTER);
    recovered_daemon.start();
    wait_for_status(
        &recovered_socket,
        &mut recovered_daemon,
        Duration::from_secs(30),
    );
    let isolated_status = cli(&recovered_socket, ["status"], CLI_TIMEOUT);
    assert!(!isolated_status.contains("peer connection:"));
    daemons[0].start();
    wait_for_status(&sockets[0], &mut daemons[0], Duration::from_secs(30));
    wait_for_status_text(
        &recovered_socket,
        &mut recovered_daemon,
        &peer_ids[0],
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &sockets[0],
        &mut daemons[0],
        &peer_ids[2],
        Duration::from_secs(45),
    );
    let mut dht_noise = DhtNoise::start(
        run_root.join("dht-noise"),
        bootstrap.clone(),
        node_ids[1],
        peer_ids[2].clone(),
    );
    let restored = run_root.join("restored-from-seed");
    let recovery_output = cli_path_with_timeout(
        &recovered_socket,
        ["restore"],
        &restored,
        Duration::from_secs(180),
    );
    assert!(recovery_output.contains("restore succeeded:"));
    assert_eq!(
        fs::read(restored.join("documents/data.bin")).unwrap(),
        expected_latest
    );
    dht_noise.stop();
    wait_for_recovery_ready(
        &recovered_socket,
        &mut recovered_daemon,
        Duration::from_secs(90),
    );
    assert!(
        git_cli(&recovered_socket, &restored, ["status"])
            .contains("Commit graph and refs are protected by a signed backup")
    );
    assert!(git_cli(&recovered_socket, &restored, ["branch"]).contains("topic"));
    git_cli(
        &recovered_socket,
        &restored,
        ["restore", "documents/data.bin"],
    );
    git_cli(&recovered_socket, &restored, ["switch", "topic"]);
    assert_eq!(
        fs::read(restored.join("documents/data.bin")).unwrap(),
        topic_bytes
    );

    let storage_recovered_dir = run_root.join("storage-recovered");
    fs::create_dir(&storage_recovered_dir).unwrap();
    set_private(&storage_recovered_dir);
    let storage_recovered_socket = control_directory.path().join("storage-recovered");
    let storage_recovered_config = storage_recovered_dir.join("node.toml");
    run_cli(
        &[
            os("--socket"),
            storage_recovered_socket.as_os_str().to_owned(),
            os("recover-init"),
            os("--seed-file"),
            seed_dir.join("p4.seed").into_os_string(),
            os("--data-dir"),
            storage_recovered_dir.join("state").into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    write_test_config(
        &storage_recovered_config,
        &DaemonOptions {
            config_file: None,
            data_dir: storage_recovered_dir.join("state"),
            seed_file: Some(seed_dir.join("p4.seed")),
            start_locked: false,
            control_socket: storage_recovered_socket.clone(),
            failure_domain: None,
            parity_budget_bytes: 10 * 1024 * 1024 * 1024,
            parity_volumes: Vec::new(),
            parity_headroom_bytes: None,
            retention_revisions: 30,
            automatic_backup: false,
            backup_quiet_seconds: 300,
            backup_minimum_interval_seconds: 3_600,
            full_reconcile_interval_seconds: 86_400,
            daily_backup_limit: 24,
            daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
            audit_interval_seconds: 21_600,
            clear_parity_volumes: false,
            p2p_listen_addresses: vec![transports[7].clone()],
            clear_p2p_listen_addresses: false,
            p2p_external_addresses: vec![transports[7].clone()],
            clear_p2p_external_addresses: false,
            p2p_bootstrap_addresses: vec![bootstrap.clone()],
            clear_p2p_bootstrap_addresses: false,
            p2p_relay_addresses: Vec::new(),
            clear_p2p_relay_addresses: false,
            enable_relay_server: false,
            enable_hole_punching: true,
            enable_port_mapping: false,
            enable_dht_maintenance: true,
            tor_mode: mb_node::TorMode::DisableTor,
            tor_state_dir: None,
            tor_cache_dir: None,
            arti_config_file: None,
            max_connections: 32,
        },
    );
    let mut storage_recovered_daemon = Daemon::new(
        storage_recovered_config.clone(),
        run_root.join("storage-recovered.log"),
    );
    storage_recovered_daemon.set_env("RUST_LOG", TOPOLOGY_LOG_FILTER);
    storage_recovered_daemon.start();
    wait_for_status(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        Duration::from_secs(30),
    );
    let storage_restore_target = run_root.join("storage-only-restore-target");
    let storage_recovery = cli_path_with_timeout(
        &storage_recovered_socket,
        ["restore"],
        &storage_restore_target,
        Duration::from_secs(180),
    );
    assert!(storage_recovery.contains("guild state and assigned shards restored"));
    assert!(!storage_restore_target.exists());

    daemons[0].stop();
    daemons[2].stop();
    daemons[3].stop();
    recovered_daemon.stop();
    storage_recovered_daemon.stop();

    daemons[0].set_network_namespace(&topology.coordinator_namespace);
    daemons[3].set_network_namespace(&topology.punched_namespace);
    recovered_daemon.set_network_namespace(&topology.relay_namespace);
    storage_recovered_daemon.set_network_namespace(&topology.fallback_namespace);
    let coordinator_transport = topology.transport(&transports[0], &topology.coordinator_ip);
    let punched_transport = topology.transport(&transports[6], &topology.punched_ip);
    let relay_transport = topology.transport(&transports[5], &topology.relay_ip);
    let owner_transport = topology.transport(&transports[2], &topology.host_ip);
    let relay = format!("{relay_transport}/p2p/{}", peer_ids[1]);
    let coordinator_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[0]);
    let punched_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[3]);
    let fallback_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[4]);
    update_config(&recovered_config, |config| {
        config.p2p_listen_addresses = vec![relay_transport.clone()];
        config.p2p_external_addresses = vec![relay_transport.clone()];
        config.enable_relay_server = true;
    });
    update_config(&configs[0], |config| {
        // Keep production endpoint exchange and Identify active. The live
        // relay reservation publishes the circuit endpoint; the harness makes
        // private listener addresses unroutable across the two NATs, so only
        // the observed public address exchanged by DCUtR can establish the
        // upgraded QUIC connection.
        config.p2p_listen_addresses = vec![coordinator_transport.clone()];
        config.p2p_external_addresses.clear();
        config.p2p_bootstrap_addresses = vec![punched_circuit.clone(), fallback_circuit.clone()];
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_dht_maintenance = false;
    });
    update_config(&configs[3], |config| {
        config.p2p_listen_addresses = vec![punched_transport.clone()];
        config.p2p_external_addresses.clear();
        config.p2p_bootstrap_addresses.clear();
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_hole_punching = true;
        config.enable_dht_maintenance = false;
    });
    update_config(&storage_recovered_config, |config| {
        config.p2p_listen_addresses.clear();
        config.p2p_external_addresses.clear();
        config.p2p_bootstrap_addresses = vec![relay.clone()];
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_hole_punching = false;
        config.enable_dht_maintenance = false;
    });
    update_config(&configs[2], |config| {
        config.p2p_listen_addresses = vec![owner_transport.clone()];
        config.p2p_external_addresses = vec![owner_transport.clone()];
        config.p2p_bootstrap_addresses = vec![coordinator_circuit.clone()];
        config.enable_dht_maintenance = false;
    });

    // Bring the relay up first, then let the dialing peer obtain its own
    // reservation before the remote circuit endpoints appear. DCUtR requires
    // both peers to have a live reservation; dialing all five daemons at once
    // turns that protocol precondition into a startup race.
    recovered_daemon.start();
    wait_for_status(
        &recovered_socket,
        &mut recovered_daemon,
        Duration::from_secs(30),
    );
    daemons[0].start();
    wait_for_status_text(
        &sockets[0],
        &mut daemons[0],
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    daemons[2].start();
    wait_for_status_text(
        &sockets[2],
        &mut daemons[2],
        &peer_ids[0],
        Duration::from_secs(45),
    );
    daemons[3].start();
    storage_recovered_daemon.start();
    wait_for_status(&sockets[3], &mut daemons[3], Duration::from_secs(30));
    wait_for_status(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        Duration::from_secs(30),
    );
    wait_for_status_text(
        &sockets[3],
        &mut daemons[3],
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &sockets[0],
        &mut daemons[0],
        "HolePunched",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &sockets[0],
        &mut daemons[0],
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    // The backup needs every member's signature. A reservation on p4 only
    // proves its connection to the relay; it does not prove that p0's circuit
    // dial to p4 has completed. Check that route before entering the long
    // backup wait so a missing signer is reported at the topology boundary.
    wait_for_active_peer(
        &sockets[0],
        &mut daemons[0],
        &peer_ids[4],
        Duration::from_secs(45),
    );

    let direct_before = peer_path_transfer(&sockets[0], &mut daemons[0], &peer_ids[1], "Direct");
    let punched_before_on_coordinator =
        peer_path_transfer(&sockets[0], &mut daemons[0], &peer_ids[3], "HolePunched");
    let punched_before_on_peer =
        peer_path_transfer(&sockets[3], &mut daemons[3], &peer_ids[0], "HolePunched");
    let final_owner_two = deterministic_bytes(512_031, 83);
    fs::write(
        owner_two_source.join("documents/data.bin"),
        &final_owner_two,
    )
    .unwrap();
    let topology_backup = topology_backup_cli(
        &sockets[2],
        process_topology_backup_timeout(),
        &[
            &daemons[0].log,
            &daemons[2].log,
            &recovered_daemon.log,
            &storage_recovered_daemon.log,
        ],
    );
    assert!(topology_backup.contains("state:      Committed"));
    wait_for_peer_transfer(
        &sockets[0],
        &mut daemons[0],
        &peer_ids[1],
        "Direct",
        direct_before,
        Duration::from_secs(30),
    );
    let (coordinator, remaining) = daemons.split_at_mut(1);
    wait_for_peer_transfer_on_either_endpoint(
        (
            &sockets[0],
            &mut coordinator[0],
            &peer_ids[3],
            punched_before_on_coordinator,
        ),
        (
            &sockets[3],
            &mut remaining[2],
            &peer_ids[0],
            punched_before_on_peer,
        ),
        "HolePunched",
        Duration::from_secs(30),
    );

    // A no-listener node can still establish a direct outbound QUIC session.
    // Restart both ends without direct listeners to make the retained circuit
    // the only viable transport for the relay-fallback assertion. Restart the
    // relay and its clients between coordinator sessions so old reservations
    // cannot race replacement connections from the same peer identities.
    daemons[0].stop();
    daemons[3].stop();
    storage_recovered_daemon.stop();
    recovered_daemon.stop();
    let relay_transport = topology.transport(&transports[9], &topology.relay_ip);
    let relay = format!("{relay_transport}/p2p/{}", peer_ids[1]);
    let coordinator_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[0]);
    let punched_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[3]);
    let fallback_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[4]);
    update_config(&recovered_config, |config| {
        config.p2p_listen_addresses = vec![relay_transport.clone()];
        config.p2p_external_addresses = vec![relay_transport.clone()];
    });
    update_config(&configs[3], |config| {
        config.p2p_relay_addresses = vec![relay.clone()];
    });
    update_config(&storage_recovered_config, |config| {
        config.p2p_bootstrap_addresses = vec![relay.clone()];
        config.p2p_relay_addresses = vec![relay.clone()];
    });
    recovered_daemon.start();
    wait_for_status(
        &recovered_socket,
        &mut recovered_daemon,
        Duration::from_secs(30),
    );
    update_config(&configs[0], |config| {
        config.p2p_listen_addresses.clear();
        config.p2p_external_addresses.clear();
        config.p2p_bootstrap_addresses = vec![punched_circuit.clone(), fallback_circuit.clone()];
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_hole_punching = false;
    });
    daemons[0].start();
    wait_for_status_text(
        &sockets[0],
        &mut daemons[0],
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    daemons[3].start();
    storage_recovered_daemon.start();
    wait_for_status_text(
        &sockets[3],
        &mut daemons[3],
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        "relay reservations: 1/1",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        &peer_ids[0],
        Duration::from_secs(45),
    );
    // The owner learned the coordinator's old direct endpoint before this
    // topology change. Restart it with the coordinator's circuit address so
    // job submission itself does not fail before the parity route is tested.
    daemons[2].stop();
    update_config(&configs[2], |config| {
        config.p2p_bootstrap_addresses = vec![coordinator_circuit];
        config.enable_dht_maintenance = false;
    });
    daemons[2].start();
    wait_for_status_text(
        &sockets[2],
        &mut daemons[2],
        &peer_ids[0],
        Duration::from_secs(45),
    );
    let relay_before =
        peer_path_transfer(&sockets[0], &mut daemons[0], &peer_ids[4], "RelayFallback");
    fs::write(
        owner_two_source.join("documents/data.bin"),
        deterministic_bytes(512_047, 89),
    )
    .unwrap();
    let relay_backup = topology_backup_cli(
        &sockets[2],
        process_topology_backup_timeout(),
        &[
            &daemons[0].log,
            &daemons[2].log,
            &recovered_daemon.log,
            &storage_recovered_daemon.log,
        ],
    );
    assert!(relay_backup.contains("state:      Committed"));
    wait_for_peer_transfer(
        &sockets[0],
        &mut daemons[0],
        &peer_ids[4],
        "RelayFallback",
        relay_before,
        Duration::from_secs(30),
    );

    let outsider_dir = run_root.join("outsider");
    fs::create_dir(&outsider_dir).unwrap();
    set_private(&outsider_dir);
    let outsider_socket = control_directory.path().join("outsider");
    let outsider_config = outsider_dir.join("node.toml");
    let outsider_transport = topology.transport(&transports[8], &topology.host_ip);
    run_cli(
        &[
            os("--socket"),
            outsider_socket.as_os_str().to_owned(),
            os("init"),
            os("--seed-file"),
            seed_dir.join("outsider.seed").into_os_string(),
            os("--data-dir"),
            outsider_dir.join("state").into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    write_test_config(
        &outsider_config,
        &DaemonOptions {
            config_file: None,
            data_dir: outsider_dir.join("state"),
            seed_file: Some(seed_dir.join("outsider.seed")),
            start_locked: false,
            control_socket: outsider_socket.clone(),
            failure_domain: Some("outsider".to_owned()),
            parity_budget_bytes: 10 * 1024 * 1024 * 1024,
            parity_volumes: Vec::new(),
            parity_headroom_bytes: None,
            retention_revisions: 30,
            automatic_backup: false,
            backup_quiet_seconds: 300,
            backup_minimum_interval_seconds: 3_600,
            full_reconcile_interval_seconds: 86_400,
            daily_backup_limit: 24,
            daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
            audit_interval_seconds: 21_600,
            clear_parity_volumes: false,
            p2p_listen_addresses: vec![outsider_transport.clone()],
            clear_p2p_listen_addresses: false,
            p2p_external_addresses: vec![outsider_transport],
            clear_p2p_external_addresses: false,
            p2p_bootstrap_addresses: vec![bootstrap],
            clear_p2p_bootstrap_addresses: false,
            p2p_relay_addresses: vec![relay],
            clear_p2p_relay_addresses: false,
            enable_relay_server: false,
            enable_hole_punching: true,
            enable_port_mapping: false,
            enable_dht_maintenance: true,
            tor_mode: mb_node::TorMode::DisableTor,
            tor_state_dir: None,
            tor_cache_dir: None,
            arti_config_file: None,
            max_connections: 32,
        },
    );
    let mut outsider_daemon = Daemon::new(outsider_config, run_root.join("outsider.log"));
    outsider_daemon.start();
    wait_for_status(
        &outsider_socket,
        &mut outsider_daemon,
        Duration::from_secs(30),
    );
    thread::sleep(Duration::from_secs(7));
    let outsider_status = cli(&outsider_socket, ["status"], CLI_TIMEOUT);
    assert!(
        !outsider_status.contains("/p2p-circuit"),
        "nonmember obtained a guild-only relay reservation:\n{outsider_status}"
    );
    outsider_daemon.stop();
    storage_recovered_daemon.stop();
    recovered_daemon.stop();
    daemons[0].stop();
    daemons[2].stop();
    daemons[3].stop();
    peer_log_archive
        .finish()
        .expect("archive peer diagnostics before fixture cleanup");
    fs::remove_dir_all(&run_root).unwrap();
}

#[test]
#[ignore = "requires a provisioned reflink filesystem and private Chutney Tor network"]
fn five_daemons_recover_from_seed_over_onion_only_libp2p() {
    let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
        .expect("the acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
    let arti_config = PathBuf::from(
        std::env::var_os("MUTUALBACKUP_PRIVATE_TOR_CONFIG")
            .expect("the private-Tor harness must set MUTUALBACKUP_PRIVATE_TOR_CONFIG"),
    );
    assert!(arti_config.is_file());
    let run_root = PathBuf::from(test_root).join(format!("private-tor-{}", Uuid::new_v4()));
    fs::create_dir_all(&run_root).unwrap();
    let mut peer_log_archive = PeerLogArchive::from_environment(&run_root).unwrap();
    // Keep local-control endpoints independent of the potentially long Btrfs
    // acceptance path. Linux Unix-domain sockets have a small fixed pathname
    // limit, while only the captured data and databases need reflink storage.
    let socket_root = tempfile::Builder::new()
        .prefix("mbtor-sockets.")
        .tempdir()
        .unwrap();
    set_private(socket_root.path());
    let seed_dir = run_root.join("offline");
    fs::create_dir(&seed_dir).unwrap();
    set_private(&seed_dir);

    let mut node_ids = Vec::new();
    let mut peer_ids = Vec::new();
    let mut onion_endpoints = Vec::new();
    let mut sockets = Vec::new();
    let mut configs = Vec::new();
    for index in 0..5 {
        let peer_dir = run_root.join(format!("p{index}"));
        fs::create_dir(&peer_dir).unwrap();
        set_private(&peer_dir);
        let seed_file = seed_dir.join(format!("p{index}.seed"));
        let socket = socket_root.path().join(format!("p{index}.sock"));
        let output = run_cli(
            &[
                os("--socket"),
                socket.as_os_str().to_owned(),
                os("init"),
                os("--seed-file"),
                seed_file.as_os_str().to_owned(),
                os("--data-dir"),
                peer_dir.join("state").into_os_string(),
            ],
            CLI_TIMEOUT,
        )
        .unwrap();
        let node_id = value_after(&output, "node id:       ")
            .parse::<NodeId>()
            .unwrap();
        let peer_id = value_after(&output, "libp2p peer id: ");
        let onion = onion_listener_address(node_id).unwrap().to_string();
        node_ids.push(node_id);
        peer_ids.push(peer_id);
        onion_endpoints.push(onion);
        sockets.push(socket);
    }

    let bootstrap = format!("{}/p2p/{}", onion_endpoints[0], peer_ids[0]);
    for (index, socket) in sockets.iter().enumerate() {
        let peer_dir = run_root.join(format!("p{index}"));
        let config = peer_dir.join("node.toml");
        let node_arti_config = peer_dir.join("arti.toml");
        let mut node_arti = fs::read_to_string(&arti_config).unwrap();
        node_arti.push_str(&format!(
            "\n[storage]\nstate_dir = {:?}\ncache_dir = {:?}\n",
            peer_dir.join("operator-tor-state"),
            peer_dir.join("operator-tor-cache")
        ));
        fs::write(&node_arti_config, node_arti).unwrap();
        write_test_config(
            &config,
            &DaemonOptions {
                config_file: None,
                data_dir: peer_dir.join("state"),
                seed_file: Some(seed_dir.join(format!("p{index}.seed"))),
                start_locked: false,
                control_socket: socket.clone(),
                failure_domain: Some(format!("tor-disk-{index}")),
                parity_budget_bytes: 10 * 1024 * 1024 * 1024,
                parity_volumes: Vec::new(),
                parity_headroom_bytes: None,
                retention_revisions: 30,
                automatic_backup: false,
                backup_quiet_seconds: 300,
                backup_minimum_interval_seconds: 3_600,
                full_reconcile_interval_seconds: 86_400,
                daily_backup_limit: 24,
                daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
                audit_interval_seconds: 21_600,
                clear_parity_volumes: false,
                p2p_listen_addresses: Vec::new(),
                clear_p2p_listen_addresses: false,
                p2p_external_addresses: Vec::new(),
                clear_p2p_external_addresses: false,
                p2p_bootstrap_addresses: if index == 0 {
                    Vec::new()
                } else {
                    vec![bootstrap.clone()]
                },
                clear_p2p_bootstrap_addresses: false,
                p2p_relay_addresses: Vec::new(),
                clear_p2p_relay_addresses: false,
                enable_relay_server: false,
                enable_hole_punching: false,
                enable_port_mapping: false,
                enable_dht_maintenance: true,
                tor_mode: mb_node::TorMode::RequireTor,
                tor_state_dir: Some(peer_dir.join("ignored-tor-state")),
                tor_cache_dir: Some(peer_dir.join("ignored-tor-cache")),
                arti_config_file: Some(node_arti_config),
                max_connections: 32,
            },
        );
        configs.push(config);
    }

    // A private test consensus has a deliberately small circuit pool. Stagger
    // service publication so this gate exercises five live services without
    // creating an artificial all-at-once introduction-circuit stampede.
    let mut daemons = Vec::with_capacity(5);
    for index in 0..5 {
        let startup_lock = if index == 0 {
            let state = run_root.join("p0/operator-tor-state");
            fs::create_dir_all(&state).unwrap();
            set_private(&state);
            let lock = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(state.join("mutualbackup.lock"))
                .unwrap();
            assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
            Some(lock)
        } else {
            None
        };
        let mut daemon = Daemon::new(
            configs[index].clone(),
            run_root.join(format!("p{index}.log")),
        );
        if index == 0 {
            daemon.args.push(os("--locked"));
        }
        daemon.set_env("RUST_LOG", TOPOLOGY_LOG_FILTER);
        daemon.start();
        if let Some(lock) = startup_lock {
            assert!(
                wait_for_status(&sockets[index], &mut daemon, Duration::from_secs(30))
                    .contains("Locked")
            );
            assert!(
                run_cli(
                    &[
                        os("--socket"),
                        sockets[index].as_os_str().to_owned(),
                        os("unlock"),
                        os("--seed-file"),
                        seed_dir.join("p0.seed").into_os_string(),
                    ],
                    Duration::from_secs(30),
                )
                .is_err()
            );
            assert!(
                wait_for_status(&sockets[index], &mut daemon, Duration::from_secs(30))
                    .contains("Locked")
            );
            assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_UN) }, 0);
            drop(lock);
            run_cli(
                &[
                    os("--socket"),
                    sockets[index].as_os_str().to_owned(),
                    os("unlock"),
                    os("--seed-file"),
                    seed_dir.join("p0.seed").into_os_string(),
                ],
                Duration::from_secs(240),
            )
            .unwrap();
            daemon
                .args
                .retain(|argument| argument != OsStr::new("--locked"));
        }
        let status = wait_for_status_text(
            &sockets[index],
            &mut daemon,
            "configured=true reachable=true",
            Duration::from_secs(240),
        );
        assert_onion_only_status(&status);
        assert_stable_onion_is_advertised(&status, &onion_endpoints[index]);
        let peer_dir = run_root.join(format!("p{index}"));
        assert!(peer_dir.join("operator-tor-state").is_dir());
        assert!(!peer_dir.join("ignored-tor-state").exists());
        daemons.push(daemon);
    }

    cli(&sockets[0], ["guild", "create"], Duration::from_secs(60));
    for index in 1..5 {
        let invite = cli(&sockets[0], ["guild", "invite"], Duration::from_secs(60));
        let token = value_after(&invite, "invitation: ");
        join_guild_with_retry(&sockets[index], &token, Duration::from_secs(240));
    }
    let finalized = cli(&sockets[0], ["guild", "finalize"], Duration::from_secs(300));
    assert!(finalized.lines().any(|line| line == "members:     5"));

    let source = run_root.join("p1/source");
    fs::create_dir_all(source.join("documents")).unwrap();
    let expected = deterministic_bytes(192_017, 83);
    fs::write(source.join("documents/onion.bin"), &expected).unwrap();
    cli_path(&sockets[1], ["root", "add"], &source);
    let backup = cli(&sockets[1], ["backup", "--wait"], Duration::from_secs(300));
    assert!(backup.contains("state:      Committed"));
    let owner_status = wait_for_status(&sockets[1], &mut daemons[1], Duration::from_secs(30));
    assert_onion_only_status(&owner_status);
    assert_tor_bulk_transfer(&owner_status);

    for index in 0..5 {
        wait_for_recovery_ready(
            &sockets[index],
            &mut daemons[index],
            Duration::from_secs(180),
        );
    }

    for daemon in &mut daemons {
        daemon.stop_gracefully();
    }
    for index in 0..5 {
        daemons[index].start();
        let status = wait_for_status_text(
            &sockets[index],
            &mut daemons[index],
            "configured=true reachable=true",
            Duration::from_secs(240),
        );
        assert_onion_only_status(&status);
        assert_stable_onion_is_advertised(&status, &onion_endpoints[index]);
    }

    daemons[1].stop();
    daemons[4].stop();
    fs::remove_dir_all(run_root.join("p1")).unwrap();
    fs::remove_dir_all(run_root.join("p4")).unwrap();

    let recovered_dir = run_root.join("recovered-p1");
    fs::create_dir(&recovered_dir).unwrap();
    set_private(&recovered_dir);
    let recovered_socket = socket_root.path().join("recovered-p1.sock");
    run_cli(
        &[
            os("--socket"),
            recovered_socket.as_os_str().to_owned(),
            os("recover-init"),
            os("--seed-file"),
            seed_dir.join("p1.seed").into_os_string(),
            os("--data-dir"),
            recovered_dir.join("state").into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    let recovered_config = recovered_dir.join("node.toml");
    let recovered_arti_config = recovered_dir.join("arti.toml");
    let mut recovered_arti = fs::read_to_string(&arti_config).unwrap();
    recovered_arti.push_str(&format!(
        "\n[storage]\nstate_dir = {:?}\ncache_dir = {:?}\n",
        recovered_dir.join("operator-tor-state"),
        recovered_dir.join("operator-tor-cache")
    ));
    fs::write(&recovered_arti_config, recovered_arti).unwrap();
    write_test_config(
        &recovered_config,
        &DaemonOptions {
            config_file: None,
            data_dir: recovered_dir.join("state"),
            seed_file: Some(seed_dir.join("p1.seed")),
            start_locked: false,
            control_socket: recovered_socket.clone(),
            failure_domain: None,
            parity_budget_bytes: 10 * 1024 * 1024 * 1024,
            parity_volumes: Vec::new(),
            parity_headroom_bytes: None,
            retention_revisions: 30,
            automatic_backup: false,
            backup_quiet_seconds: 300,
            backup_minimum_interval_seconds: 3_600,
            full_reconcile_interval_seconds: 86_400,
            daily_backup_limit: 24,
            daily_backup_byte_limit: 100 * 1024 * 1024 * 1024,
            audit_interval_seconds: 21_600,
            clear_parity_volumes: false,
            p2p_listen_addresses: Vec::new(),
            clear_p2p_listen_addresses: false,
            p2p_external_addresses: Vec::new(),
            clear_p2p_external_addresses: false,
            p2p_bootstrap_addresses: vec![bootstrap],
            clear_p2p_bootstrap_addresses: false,
            p2p_relay_addresses: Vec::new(),
            clear_p2p_relay_addresses: false,
            enable_relay_server: false,
            enable_hole_punching: false,
            enable_port_mapping: false,
            enable_dht_maintenance: true,
            tor_mode: mb_node::TorMode::RequireTor,
            tor_state_dir: Some(recovered_dir.join("ignored-tor-state")),
            tor_cache_dir: Some(recovered_dir.join("ignored-tor-cache")),
            arti_config_file: Some(recovered_arti_config),
            max_connections: 32,
        },
    );
    let mut recovered = Daemon::new(recovered_config, run_root.join("recovered-p1.log"));
    recovered.set_env("RUST_LOG", TOPOLOGY_LOG_FILTER);
    recovered.start();
    let status = wait_for_status_text(
        &recovered_socket,
        &mut recovered,
        "configured=true reachable=true",
        Duration::from_secs(240),
    );
    assert_onion_only_status(&status);
    assert_stable_onion_is_advertised(&status, &onion_endpoints[1]);
    assert!(recovered_dir.join("operator-tor-state").is_dir());
    assert!(!recovered_dir.join("ignored-tor-state").exists());
    let bootstrap_session = format!("peer connection: {} active=[Tor]", peer_ids[0]);
    let status = wait_for_status_text(
        &recovered_socket,
        &mut recovered,
        &bootstrap_session,
        Duration::from_secs(240),
    );
    assert_onion_only_status(&status);

    let restored = run_root.join("restored-from-onion");
    let output = cli_path_with_timeout(
        &recovered_socket,
        ["restore"],
        &restored,
        Duration::from_secs(600),
    );
    assert!(output.contains("restore succeeded:"));
    assert_eq!(
        fs::read(restored.join("documents/onion.bin")).unwrap(),
        expected
    );
    let recovered_status =
        wait_for_status(&recovered_socket, &mut recovered, Duration::from_secs(30));
    assert_tor_bulk_transfer(&recovered_status);
    assert_onion_only_status(&recovered_status);

    assert_eq!(
        node_ids[1],
        read_identity_manifest(&recovered_dir.join("state"))
            .unwrap()
            .expected_node_id
    );
    recovered.stop();
    for daemon in &mut daemons {
        daemon.stop();
    }
    peer_log_archive
        .finish()
        .expect("archive peer diagnostics before fixture cleanup");
    fs::remove_dir_all(&run_root).unwrap();
}

struct DhtNoise {
    shutdown: Option<mpsc::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}

impl DhtNoise {
    fn start(
        data_dir: PathBuf,
        bootstrap: String,
        recovery_subject: NodeId,
        poisoned_endpoint_peer: String,
    ) -> Self {
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let (shutdown_sender, shutdown_receiver) = mpsc::channel();
        let worker = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let seed = Seed::from_bytes([211; 32]);
                let keys = KeyMaterial::from_seed(&seed);
                let publisher = keys.node_id();
                let node = Arc::new(Mutex::new(Node::open(data_dir, seed).unwrap()));
                let (client, event_loop) = build_p2p(
                    node,
                    P2pConfig {
                        listen_addresses: vec!["/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap()],
                        external_addresses: Vec::new(),
                        bootstrap_addresses: vec![bootstrap.parse().unwrap()],
                        relay_reservation_addresses: Vec::new(),
                        enable_dht_maintenance: true,
                        enable_relay_server: false,
                        enable_hole_punching: true,
                        enable_port_mapping: false,
                        public_endpoint: "/ip4/127.0.0.1/udp/0/quic-v1".into(),
                        failure_domain: "malicious-dht-publisher".into(),
                        configure_failure_domain: true,
                        max_connections: 4,
                        tor_mode: mb_node::TorMode::DisableTor,
                    },
                )
                .unwrap();
                let event_task = tokio::spawn(event_loop.run());
                let outcome = async {
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
                    let status = loop {
                        let status = client.status().await?;
                        if !status.peers.is_empty() {
                            break status;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            anyhow::bail!("malicious DHT publisher did not reach bootstrap");
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    };
                    let peer_id = client.local_peer_id();
                    let expired_bundle = SignedRecord::sign(
                        b"mutualbackup/recovery-bundle/v1",
                        RecoveryBundle {
                            format_version: 1,
                            subject: recovery_subject,
                            publisher,
                            sequence: u64::MAX,
                            expires_at_unix_seconds: unix_seconds().saturating_sub(1),
                            key_envelope: None,
                            sealed: SealedRecoveryRecord {
                                format_version: 1,
                                ephemeral_public_key: [1; 32],
                                nonce: [2; 24],
                                ciphertext: vec![3],
                            },
                        },
                        &keys,
                    )?;
                    client
                        .put_record(
                            recovery_bundle_key(recovery_subject, &peer_id),
                            canonical_bytes(&expired_bundle)?,
                        )
                        .await?;
                    client
                        .start_providing(recovery_mailbox_key(recovery_subject))
                        .await?;

                    let endpoint = status
                        .advertised_addresses
                        .first()
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("noise node has no endpoint"))?;
                    let poisoned_endpoint = SignedRecord::sign(
                        b"mutualbackup/endpoint-record/v1",
                        EndpointRecord {
                            format_version: 1,
                            publisher,
                            sequence: u64::MAX,
                            expires_at_unix_seconds: unix_seconds() + 300,
                            endpoints: vec![format!("{endpoint}/p2p/{peer_id}")],
                        },
                        &keys,
                    )?;
                    client
                        .put_record(
                            endpoint_record_key(&poisoned_endpoint_peer),
                            canonical_bytes(&poisoned_endpoint)?,
                        )
                        .await?;
                    Ok::<(), anyhow::Error>(())
                }
                .await;
                ready_sender
                    .send(outcome.map_err(|error| format!("{error:#}")))
                    .unwrap();
                loop {
                    match shutdown_receiver.try_recv() {
                        Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                        Err(mpsc::TryRecvError::Empty) => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
                client.shutdown().await.unwrap();
                event_task.await.unwrap().unwrap();
            });
        });
        ready_receiver
            .recv_timeout(Duration::from_secs(45))
            .expect("malicious DHT publisher did not report readiness")
            .unwrap();
        Self {
            shutdown: Some(shutdown_sender),
            worker: Some(worker),
        }
    }

    fn stop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

impl Drop for DhtNoise {
    fn drop(&mut self) {
        self.stop();
    }
}

fn exercise_local_control_limit(socket: &Path, daemon: &mut Daemon) {
    let held = (0..17)
        .map(|_| UnixStream::connect(socket).unwrap())
        .collect::<Vec<_>>();
    thread::sleep(Duration::from_millis(250));
    let saturated = run_cli(
        &[os("--socket"), socket.as_os_str().to_owned(), os("status")],
        Duration::from_millis(750),
    );
    assert!(
        saturated.is_err(),
        "control connection N+1 was not backpressured"
    );
    drop(held);
    wait_for_status(socket, daemon, Duration::from_secs(10));
}

fn join_guild_with_retry(socket: &Path, token: &str, timeout: Duration) {
    let initial = [
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("guild"),
        os("join"),
        os(token),
    ];
    if run_cli(&initial, CLI_TIMEOUT).is_ok() {
        return;
    }
    retry_pending_guild_join(socket, timeout);
}

fn retry_pending_guild_join(socket: &Path, timeout: Duration) -> String {
    let retry = [
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("guild"),
        os("retry"),
    ];
    let deadline = Instant::now() + timeout;
    loop {
        match run_cli(&retry, CLI_TIMEOUT) {
            Ok(output) => return output,
            Err(error) => {
                assert!(
                    Instant::now() < deadline,
                    "pending guild join never resumed: {error}"
                );
                thread::sleep(Duration::from_millis(250));
            }
        }
    }
}

fn remove_anchor_areas(node_dir: &Path) {
    let areas = fs::read_dir(node_dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with(".mutualbackup-anchors-"))
        })
        .collect::<Vec<_>>();
    assert!(!areas.is_empty(), "no local source-anchor area was created");
    for area in areas {
        fs::remove_dir_all(area).unwrap();
    }
}

fn write_test_config(path: &Path, config: &DaemonOptions) {
    let identity = read_identity_manifest(&config.data_dir).unwrap();
    config.validate(&identity).unwrap();
    fs::write(path, toml::to_string_pretty(config).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    OpenOptions::new()
        .read(true)
        .open(path)
        .unwrap()
        .sync_all()
        .unwrap();
}

fn update_config(path: &Path, update: impl FnOnce(&mut DaemonOptions)) {
    let mut config = read_daemon_options([
        OsString::from("mutualbackupd"),
        OsString::from("--config"),
        path.as_os_str().to_owned(),
    ])
    .unwrap();
    update(&mut config);
    config.config_file = None;
    write_test_config(path, &config);
}

fn wait_for_status_text(
    socket: &Path,
    daemon: &mut Daemon,
    expected: &str,
    timeout: Duration,
) -> String {
    let deadline = Instant::now() + timeout;
    let mut status = wait_for_status(socket, daemon, timeout);
    loop {
        if status.contains(expected) {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "status never contained {expected:?}:\n{status}"
        );
        thread::sleep(Duration::from_millis(100));
        status = wait_for_status(
            socket,
            daemon,
            deadline.saturating_duration_since(Instant::now()),
        );
    }
}

fn wait_for_active_peer(socket: &Path, daemon: &mut Daemon, peer_id: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = wait_for_status(
            socket,
            daemon,
            deadline.saturating_duration_since(Instant::now()),
        );
        let prefix = format!("peer connection: {peer_id} active=[");
        if status.lines().any(|line| {
            line.strip_prefix(&prefix)
                .is_some_and(|paths| !paths.starts_with(']'))
        }) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "peer {peer_id} had no active connection:\n{status}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_peer_transfer(
    socket: &Path,
    daemon: &mut Daemon,
    peer_id: &str,
    path: &str,
    baseline: (u64, u64),
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = wait_for_status(socket, daemon, Duration::from_secs(5));
        if let Some(line) = path_transfer_line(&status, peer_id, path) {
            let sent = numeric_status_field(line, "sent=");
            let received = numeric_status_field(line, "received=");
            if let (Some(sent), Some(received)) = (sent, received) {
                let sent_delta = sent.saturating_sub(baseline.0);
                let received_delta = received.saturating_sub(baseline.1);
                if sent > baseline.0
                    && received > baseline.1
                    && sent_delta.max(received_delta) >= MIN_BULK_TRANSFER_BYTES
                {
                    return;
                }
            }
        }
        assert!(
            Instant::now() < deadline,
            "peer {peer_id} never transferred over {path}:\n{status}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

type TransferEndpoint<'a> = (&'a Path, &'a mut Daemon, &'a str, (u64, u64));

fn wait_for_peer_transfer_on_either_endpoint(
    left: TransferEndpoint<'_>,
    right: TransferEndpoint<'_>,
    path: &str,
    timeout: Duration,
) {
    let (left_socket, left_daemon, left_peer, left_baseline) = left;
    let (right_socket, right_daemon, right_peer, right_baseline) = right;
    let deadline = Instant::now() + timeout;
    loop {
        let left_status = wait_for_status(left_socket, left_daemon, Duration::from_secs(5));
        if status_has_bulk_transfer(&left_status, left_peer, path, left_baseline) {
            return;
        }
        let right_status = wait_for_status(right_socket, right_daemon, Duration::from_secs(5));
        if status_has_bulk_transfer(&right_status, right_peer, path, right_baseline) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "transfer was not attributed to {path} at either endpoint:\nleft:\n{left_status}\nright:\n{right_status}"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn status_has_bulk_transfer(status: &str, peer_id: &str, path: &str, baseline: (u64, u64)) -> bool {
    let Some(line) = path_transfer_line(status, peer_id, path) else {
        return false;
    };
    let (Some(sent), Some(received)) = (
        numeric_status_field(line, "sent="),
        numeric_status_field(line, "received="),
    ) else {
        return false;
    };
    let sent_delta = sent.saturating_sub(baseline.0);
    let received_delta = received.saturating_sub(baseline.1);
    sent > baseline.0
        && received > baseline.1
        && sent_delta.max(received_delta) >= MIN_BULK_TRANSFER_BYTES
}

fn peer_path_transfer(socket: &Path, daemon: &mut Daemon, peer_id: &str, path: &str) -> (u64, u64) {
    let status = wait_for_status(socket, daemon, Duration::from_secs(5));
    path_transfer_line(&status, peer_id, path).map_or((0, 0), |line| {
        (
            numeric_status_field(line, "sent=").unwrap(),
            numeric_status_field(line, "received=").unwrap(),
        )
    })
}

fn path_transfer_line<'a>(status: &'a str, peer_id: &str, path: &str) -> Option<&'a str> {
    status.lines().find(|line| {
        line.strip_prefix("peer path transfer: ")
            .is_some_and(|tail| {
                tail.starts_with(peer_id)
                    && tail
                        .strip_prefix(peer_id)
                        .is_some_and(|fields| fields.starts_with(&format!(" path={path} ")))
            })
    })
}

fn numeric_status_field(line: &str, prefix: &str) -> Option<u64> {
    line.split_ascii_whitespace()
        .find_map(|field| field.strip_prefix(prefix))?
        .parse()
        .ok()
}

fn assert_onion_only_status(status: &str) {
    assert!(
        status.contains("direct listeners: 0/0"),
        "onion-only node exposed a direct listener:\n{status}"
    );
    let addresses = status.lines().filter(|line| {
        line.starts_with("listen address: ") || line.starts_with("advertised address: ")
    });
    for line in addresses {
        assert!(
            line.contains("/onion3/"),
            "onion-only node exposed a non-onion endpoint:\n{status}"
        );
    }
    for forbidden in ["Direct", "Relayed", "HolePunched", "RelayFallback"] {
        assert!(
            !status.lines().any(|line| {
                line.starts_with("peer path transfer: ")
                    && line.contains(&format!(" path={forbidden} "))
            }),
            "onion-only node transferred application data through {forbidden}:\n{status}"
        );
    }
}

fn assert_stable_onion_is_advertised(status: &str, expected_onion: &str) {
    assert!(
        status
            .lines()
            .any(|line| line.strip_prefix("advertised address: ") == Some(expected_onion)),
        "expected stable onion endpoint {expected_onion} was not advertised:\n{status}"
    );
}

fn assert_tor_bulk_transfer(status: &str) {
    let metrics = status
        .lines()
        .find(|line| line.starts_with("path metrics: Tor "))
        .unwrap_or_else(|| panic!("status has no Tor path metrics:\n{status}"));
    let sent = numeric_status_field(metrics, "sent=").unwrap();
    let received = numeric_status_field(metrics, "received=").unwrap();
    assert!(
        sent.max(received) >= MIN_BULK_TRANSFER_BYTES,
        "Tor path did not carry a complete sector: sent={sent} received={received}\n{status}"
    );
}

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_owned()
}

fn required_test_value(name: &str) -> OsString {
    std::env::var_os(name).unwrap_or_else(|| panic!("the acceptance harness must set {name}"))
}

fn required_test_utf8(name: &str) -> String {
    required_test_value(name)
        .into_string()
        .unwrap_or_else(|_| panic!("the acceptance harness must set {name} to UTF-8"))
}

fn required_test_program(name: &str) -> PathBuf {
    let path = PathBuf::from(required_test_value(name));
    assert!(
        path.is_absolute() && path.is_file(),
        "the acceptance harness must set {name} to an absolute executable path"
    );
    path
}

fn cli<const N: usize>(socket: &Path, args: [&str; N], timeout: Duration) -> String {
    let mut owned = vec![os("--socket"), socket.as_os_str().to_owned()];
    owned.extend(args.into_iter().map(os));
    run_cli(&owned, timeout).unwrap()
}

fn topology_backup_cli(socket: &Path, timeout: Duration, logs: &[&Path]) -> String {
    let args = vec![
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("backup"),
        os("--wait"),
    ];
    run_cli(&args, timeout).unwrap_or_else(|error| {
        let diagnostics = logs
            .iter()
            .map(|path| match fs::read_to_string(path) {
                Ok(log) => {
                    let relevant = log
                        .lines()
                        .rev()
                        .filter(|line| {
                            line.contains("guild member did not sign")
                                || line.contains("coding activation deferred")
                                || line.contains("coordinator backup attempt deferred")
                        })
                        .take(20)
                        .collect::<Vec<_>>();
                    let tail = log.lines().rev().take(12).collect::<Vec<_>>();
                    format!(
                        "{}:\nrelevant warnings:\n{}\nrecent log:\n{}",
                        path.display(),
                        relevant.into_iter().rev().collect::<Vec<_>>().join("\n"),
                        tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                    )
                }
                Err(read_error) => format!("{}: {read_error}", path.display()),
            })
            .collect::<Vec<_>>()
            .join("\n");
        panic!("topology backup failed: {error}\n{diagnostics}");
    })
}

fn git_cli<const N: usize>(socket: &Path, directory: &Path, args: [&str; N]) -> String {
    let mut owned = vec![
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("-C"),
        directory.as_os_str().to_owned(),
    ];
    owned.extend(args.into_iter().map(os));
    let output = run_output(program("mutualgit"), &owned, PROCESS_SMALL_BACKUP_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "mutualgit {:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
        owned,
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn cli_path<const N: usize>(socket: &Path, args: [&str; N], path: &Path) -> String {
    cli_path_with_timeout(socket, args, path, Duration::from_secs(120))
}

fn cli_path_with_timeout<const N: usize>(
    socket: &Path,
    args: [&str; N],
    path: &Path,
    timeout: Duration,
) -> String {
    let mut owned = vec![os("--socket"), socket.as_os_str().to_owned()];
    owned.extend(args.into_iter().map(os));
    owned.push(path.as_os_str().to_owned());
    run_cli(&owned, timeout).unwrap()
}

fn run_cli(args: &[OsString], timeout: Duration) -> Result<String, String> {
    let output = run_output(program("mutualbackup"), args, timeout)?;
    if !output.status.success() {
        return Err(format!(
            "mutualbackup {:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn run_cli_with_input(
    args: &[OsString],
    input: &[u8],
    timeout: Duration,
) -> Result<String, String> {
    let mut child = Command::new(program("mutualbackup"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input)
        .map_err(|error| error.to_string())?;
    let output = wait_for_output(child, timeout)?;
    if !output.status.success() {
        return Err(format!(
            "mutualbackup {:?} failed with {}\nstdout:\n{}\nstderr:\n{}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn run_output(
    program: impl AsRef<OsStr>,
    args: &[OsString],
    timeout: Duration,
) -> Result<Output, String> {
    let child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
    wait_for_output(child, timeout)
}

fn wait_for_output(mut child: Child, timeout: Duration) -> Result<Output, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().map_err(|error| error.to_string())? {
            Some(_) => return child.wait_with_output().map_err(|error| error.to_string()),
            None if Instant::now() < deadline => thread::sleep(Duration::from_millis(25)),
            None => {
                let _ = child.kill();
                let output = child
                    .wait_with_output()
                    .map_err(|error| error.to_string())?;
                return Err(format!(
                    "command timed out after {timeout:?}\nstdout:\n{}\nstderr:\n{}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
        }
    }
}

fn wait_for_status(socket: &Path, daemon: &mut Daemon, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        daemon.assert_running();
        let args = [os("--socket"), socket.as_os_str().to_owned(), os("status")];
        if let Ok(output) = run_cli(&args, Duration::from_secs(3)) {
            return output;
        }
        assert!(Instant::now() < deadline, "daemon did not become ready");
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_backup(socket: &Path, revision: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let args = [
        os("--socket"),
        socket.as_os_str().to_owned(),
        os("backup-status"),
        os(revision),
    ];
    loop {
        let last_result = match run_cli(&args, Duration::from_secs(10)) {
            Ok(output) => {
                if output.contains("state:      Committed") {
                    return;
                }
                assert!(
                    !output.contains("state:      Failed"),
                    "interrupted backup failed:\n{output}"
                );
                output
            }
            Err(error) => error,
        };
        assert!(
            Instant::now() < deadline,
            "interrupted backup did not resume; last result:\n{last_result}"
        );
        thread::sleep(Duration::from_millis(250));
    }
}

fn wait_for_recovery_ready(socket: &Path, daemon: &mut Daemon, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let status = wait_for_status(socket, daemon, Duration::from_secs(5));
        if status.contains("recovery ready: true") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "checkpoint never became seed-recovery discoverable:\n{status}"
        );
        thread::sleep(Duration::from_millis(250));
    }
}

fn value_after(output: &str, prefix: &str) -> String {
    output
        .lines()
        .find_map(|line| line.strip_prefix(prefix))
        .unwrap_or_else(|| panic!("missing {prefix:?} in output:\n{output}"))
        .trim()
        .to_owned()
}

fn deterministic_bytes(length: usize, salt: usize) -> Vec<u8> {
    (0..length)
        .map(|offset| ((offset * 17 + salt) % 251) as u8)
        .collect()
}

fn set_private(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_export_cli_runs_offline_and_preserves_original_inputs() {
    use mb_core::{
        SectorPurpose, USER_REVISION_DOMAIN, UserRevision, V1_CIPHER_PROFILE, encrypted_sector,
        make_sector_id, merkle_commit,
    };
    use mb_node::{
        GuardedPrivateEntryV6, GuardedPrivateMetadataV6, GuardedPrivateStatV6, PrivateDataExtent,
    };
    use std::os::unix::fs::MetadataExt;

    let temp = tempfile::tempdir().unwrap();
    let inputs = temp.path().join("original");
    fs::create_dir(&inputs).unwrap();
    let sectors = inputs.join("ciphertexts");
    fs::create_dir(&sectors).unwrap();
    let recovery = Seed::generate_recovery_string().unwrap();
    let seed = Seed::from_recovery_string(&recovery).unwrap();
    let keys = KeyMaterial::from_seed(&seed);
    let seed_file = inputs.join("recovery.txt");
    mutualbackup::write_seed(&seed_file, &recovery).unwrap();
    let revision_id = Uuid::new_v4();
    let guild = [78; 32];
    let encryption = keys.guild_data_key(&guild);
    let data_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Data, 0);
    let (data, data_bytes) = encrypted_sector(&encryption, data_id, b"offline payload").unwrap();
    let stat = GuardedPrivateStatV6 {
        mode: 0o700,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        atime_secs: 1_700_000_000,
        atime_nanos: 0,
        modified_secs: 1_700_000_001,
        modified_nanos: 0,
    };
    let metadata = GuardedPrivateMetadataV6 {
        format_version: 6,
        root: stat.clone(),
        entries: vec![GuardedPrivateEntryV6::File {
            path: b"payload-\xff".to_vec(),
            stat,
            logical_len: 15,
            link_group: 0,
            data_extents: vec![PrivateDataExtent {
                offset: 0,
                logical_len: 15,
                sectors: vec![data.clone()],
            }],
        }],
    };
    let metadata_id = make_sector_id(keys.node_id(), revision_id, SectorPurpose::Metadata, 0);
    let (metadata_sector, metadata_bytes) = encrypted_sector(
        &encryption,
        metadata_id,
        &canonical_bytes(&metadata).unwrap(),
    )
    .unwrap();
    let mut body = UserRevision {
        format_version: 5,
        guild_id: guild,
        protected_root_id: Uuid::new_v4(),
        cipher_profile: V1_CIPHER_PROFILE,
        revision_id,
        owner: keys.node_id(),
        writer_epoch: 1,
        writer_public_key: keys.node_id().0,
        writer_signature: Vec::new(),
        sequence: 1,
        parent: None,
        metadata_sectors: vec![metadata_sector],
        data_sectors: vec![data],
        sector_commitments: Some(vec![
            merkle_commit(&metadata_bytes).unwrap(),
            merkle_commit(&data_bytes).unwrap(),
        ]),
    };
    body.writer_signature = keys
        .sign(
            b"mutualbackup/writer-revision/v1",
            &canonical_bytes(&body).unwrap(),
        )
        .to_vec();
    let revision = SignedRecord::sign(USER_REVISION_DOMAIN, body, &keys).unwrap();
    let signed = canonical_bytes(&revision).unwrap();
    let revision_file = inputs.join("revision.postcard");
    fs::write(&revision_file, &signed).unwrap();
    let data_file = sectors.join(format!("{}.bin", hex::encode(data_id)));
    let metadata_file = sectors.join(format!("{}.bin", hex::encode(metadata_id)));
    fs::write(&data_file, &data_bytes).unwrap();
    fs::write(&metadata_file, &metadata_bytes).unwrap();
    let target = temp
        .path()
        .join(OsString::from_vec(b"export-\xfe".to_vec()));
    let args = vec![
        os("--socket"),
        temp.path().join("absent-daemon.sock").into_os_string(),
        os("legacy-export"),
        os("--revision-file"),
        revision_file.clone().into_os_string(),
        os("--sectors-dir"),
        sectors.clone().into_os_string(),
        os("--destination"),
        target.clone().into_os_string(),
        os("--seed-file"),
        seed_file.clone().into_os_string(),
    ];
    let output = run_output(program("mutualbackup"), &args, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("exported revision"));
    assert_eq!(
        fs::read(
            target
                .join("namespace")
                .join(OsString::from_vec(b"payload-\xff".to_vec()))
        )
        .unwrap(),
        b"offline payload"
    );
    assert_eq!(
        fs::read(target.join("signed-revision.postcard")).unwrap(),
        signed
    );
    assert_eq!(fs::read(&revision_file).unwrap(), signed);
    assert_eq!(fs::read(&metadata_file).unwrap(), metadata_bytes);
    assert_eq!(fs::read(&data_file).unwrap(), data_bytes);
    assert_eq!(
        fs::read_to_string(&seed_file).unwrap().trim(),
        recovery.as_str()
    );
    let retry = run_output(program("mutualbackup"), &args, CLI_TIMEOUT).unwrap();
    assert!(!retry.status.success());
    assert_eq!(
        fs::read(target.join("signed-revision.postcard")).unwrap(),
        signed
    );
    assert!(!inputs.join("control.db").exists());
    let catalog = temp.path().join("catalog");
    fs::create_dir(&catalog).unwrap();
    let volume = temp
        .path()
        .join(OsString::from_vec(b"saved-volume-\xfd".to_vec()));
    fs::create_dir(&volume).unwrap();
    fs::create_dir(volume.join("nested")).unwrap();
    let mut registry_node = Node::open(temp.path().join("registry-state"), seed).unwrap();
    registry_node
        .configure_storage_volumes(std::slice::from_ref(&volume), 65536, 0)
        .unwrap();
    let (filler, _) = registry_node
        .ensure_filler(guild, Uuid::new_v4(), 0)
        .unwrap();
    let registry = registry_node.database_shell_statement(
        None,
        "SELECT hex(bytes) FROM protocol_records WHERE kind='node-config' AND record_id=X'73746f726167652d766f6c756d6573'",
        false,
    ).unwrap();
    let registry_bytes = hex::decode(&registry.rows[0][0]).unwrap();
    let filler_rows = registry_node.database_shell_statement(None, &format!(
        "SELECT hex(bytes) FROM protocol_records WHERE kind='local-sector' AND record_id=X'{}'", hex::encode(filler.id)), false).unwrap();
    let filler_bytes = hex::decode(&filler_rows.rows[0][0]).unwrap();
    drop(registry_node);
    let mut store = mb_store::ControlStore::open(catalog.join("control.db"), &keys).unwrap();
    store
        .put_record("node-config", b"storage-volumes", &registry_bytes)
        .unwrap();
    store
        .put_record("local-sector", &filler.id, &filler_bytes)
        .unwrap();
    store
        .put_record("user-revision", revision_id.as_bytes(), &signed)
        .unwrap();
    store
        .put_record("guarded-view-mount-v1", b"legacy", b"preserve")
        .unwrap();
    let registered_source = temp.path().join("preserved-source");
    let history_only = temp
        .path()
        .join(OsString::from_vec(b"history-only-\xff".to_vec()));
    for path in [&registered_source, &history_only] {
        fs::create_dir_all(path.join("nested")).unwrap();
        fs::write(path.join("original"), b"preserve source/history").unwrap();
    }
    let root_id = Uuid::new_v4();
    store
        .put_record(
            "protected-root",
            root_id.as_bytes(),
            &canonical_bytes(&mb_node::ProtectedRoot {
                format_version: 4,
                root_id,
                path: registered_source.clone(),
                filesystem_id: 7,
                root_inode: 10,
            })
            .unwrap(),
        )
        .unwrap();
    let repository_id = Uuid::new_v4();
    let external_catalog = history_only.join(mb_store::GIT_CATALOG_DIRECTORY);
    fs::create_dir(&external_catalog).unwrap();
    set_private(&external_catalog);
    let marker = external_catalog.join(mb_store::GIT_CATALOG_MARKER_FILE);
    fs::write(&marker, mb_store::git_catalog_marker_bytes(repository_id)).unwrap();
    fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
    let worktree = temp
        .path()
        .join(OsString::from_vec(b"linked-worktree-\xfc".to_vec()));
    fs::create_dir_all(worktree.join("nested")).unwrap();
    fs::write(worktree.join("original"), b"preserve linked worktree").unwrap();
    let worktree_alias = temp.path().join("worktree-alias");
    std::os::unix::fs::symlink(&worktree, &worktree_alias).unwrap();
    let worktree_metadata = fs::metadata(&worktree).unwrap();
    let worktree_id = Uuid::new_v4();
    let worktree_info = mb_git::GitWorktreeInfo {
        format_version: 1,
        repository_id,
        worktree_id,
        path: worktree.clone(),
        root_id: mb_store::NativeFileId {
            filesystem_id: worktree_metadata.dev(),
            inode: worktree_metadata.ino(),
        },
        target_branch: "main".into(),
        state: mb_git::GitWorktreeState::Preparing,
    };
    let external_store = mb_store::ControlStore::open_with_key(
        external_catalog.join("catalog.db"),
        &mb_git::catalog_key(&keys, repository_id),
    )
    .unwrap();
    external_store
        .put_record(
            "git-source-backend-v1",
            repository_id.as_bytes(),
            &canonical_bytes(&(
                1_u16,
                repository_id,
                mb_store::SourceBackendKind::GuardedLinkFreezeV1,
            ))
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-linked-worktree-v1/{repository_id}"),
            worktree_id.as_bytes(),
            &canonical_bytes(&worktree_info).unwrap(),
        )
        .unwrap();
    let object_source = temp.path().join("preserved-git-object-source");
    let object_area = temp.path().join("preserved-git-object-area");
    let cached_area = temp.path().join("preserved-git-cached-area");
    let stage_source = temp.path().join("preserved-git-stage-source");
    let stage_area = temp.path().join("preserved-git-stage-area");
    let symlink_source = temp.path().join("preserved-git-symlink-source");
    let symlink_catalog = temp.path().join("preserved-git-symlink-catalog");
    let symlink_area = temp.path().join("preserved-git-symlink-area");
    let prune_source = temp.path().join("preserved-git-prune-source");
    let prune_area = temp.path().join("preserved-git-prune-area");
    let removal_root = temp.path().join("preserved-git-removal-root");
    let worktree_removal_root = temp.path().join("preserved-worktree-removal-root");
    let worktree_removal_marker = temp.path().join("preserved-worktree-removal-marker");
    let worktree_removal_child = temp.path().join("preserved-worktree-removal-child");
    let fetch_source = temp.path().join("preserved-fetch-stock-source");
    let fetch_target = temp.path().join("preserved-fetch-target");
    let import_source = temp.path().join("preserved-blob-import-source");
    let import_area = temp.path().join("preserved-blob-import-area");
    let merge_source = temp.path().join("preserved-merge-blob-source");
    let merge_area = temp.path().join("preserved-merge-blob-area");
    let checkout_root = temp.path().join("preserved-checkout-root");
    let checkout_stage = temp.path().join("preserved-checkout-stage");
    let checkout_child = temp.path().join("preserved-checkout-child");
    let checkout_removed = temp.path().join("preserved-checkout-removed");
    for path in [
        &object_source,
        &object_area,
        &cached_area,
        &stage_source,
        &stage_area,
        &symlink_source,
        &symlink_catalog,
        &symlink_area,
        &prune_source,
        &prune_area,
        &removal_root,
        &worktree_removal_root,
        &worktree_removal_marker,
        &worktree_removal_child,
        &fetch_source,
        &fetch_target,
        &import_source,
        &import_area,
        &merge_source,
        &merge_area,
        &checkout_root,
        &checkout_stage,
        &checkout_child,
        &checkout_removed,
    ] {
        fs::create_dir(path).unwrap();
        fs::create_dir(path.join("nested")).unwrap();
        fs::write(path.join("original"), b"preserve Git ownership").unwrap();
    }
    let object_alias = temp.path().join("object-area-alias");
    std::os::unix::fs::symlink(&object_area, &object_alias).unwrap();
    let stage_alias = temp.path().join("stage-source-alias");
    std::os::unix::fs::symlink(&stage_source, &stage_alias).unwrap();
    let import_alias = temp.path().join("blob-import-source-alias");
    std::os::unix::fs::symlink(&import_source, &import_alias).unwrap();
    let merge_alias = temp.path().join("merge-blob-source-alias");
    std::os::unix::fs::symlink(&merge_source, &merge_alias).unwrap();
    let checkout_alias = temp.path().join("checkout-child-alias");
    std::os::unix::fs::symlink(&checkout_child, &checkout_alias).unwrap();
    let stage_root_id = mb_store::PinnedDirectory::open(&stage_source)
        .unwrap()
        .identity()
        .unwrap();
    let stage_capture_id = Uuid::new_v4();
    let stage_area_id = Uuid::new_v4();
    let stage_plan = mb_store::SourceFileCapturePlan::GuardedLinkFreezeV1(
        mb_core::decode_canonical(
            &canonical_bytes(&(
                1_u16,
                stage_capture_id,
                stage_source.as_os_str().as_bytes().to_vec(),
                stage_root_id,
                b"unfinished-\xfa".to_vec(),
                (
                    stage_root_id.filesystem_id,
                    51_u64,
                    7_u64,
                    0_i64,
                    0_i64,
                    0_i64,
                    0_i64,
                ),
                0o100644_u32,
                mb_store::StableAnchorAreaLocator {
                    area_id: stage_area_id,
                    path_hint: stage_area.clone(),
                    filesystem_id: stage_root_id.filesystem_id,
                    volume_root_hint: temp.path().to_path_buf(),
                },
            ))
            .unwrap(),
        )
        .unwrap(),
    );
    external_store
        .put_record(
            &format!("git-worktree-stage-intent-v1/{repository_id}/{worktree_id}"),
            b"unfinished-\xfa",
            &canonical_bytes(&(
                1_u16,
                repository_id,
                b"unfinished-\xfa".to_vec(),
                0o100755_u32,
                stage_plan,
            ))
            .unwrap(),
        )
        .unwrap();
    let symlink_root_id = mb_store::PinnedDirectory::open(&symlink_source)
        .unwrap()
        .identity()
        .unwrap();
    let symlink_catalog_root_id = mb_store::PinnedDirectory::open(&symlink_catalog)
        .unwrap()
        .identity()
        .unwrap();
    let symlink_temp_name = format!("symlink-input-{}", Uuid::new_v4());
    let symlink_temp_path =
        std::path::Path::new(mb_store::GIT_CATALOG_DIRECTORY).join(&symlink_temp_name);
    let symlink_target = b"private-symlink-target-\xf9".to_vec();
    let symlink_temp_id = mb_store::NativeFileId {
        filesystem_id: symlink_catalog_root_id.filesystem_id,
        inode: 53,
    };
    let symlink_plan = mb_store::SourceFileCapturePlan::GuardedLinkFreezeV1(
        mb_core::decode_canonical(
            &canonical_bytes(&(
                1_u16,
                Uuid::new_v4(),
                symlink_catalog.as_os_str().as_bytes().to_vec(),
                symlink_catalog_root_id,
                symlink_temp_path.as_os_str().as_bytes().to_vec(),
                (
                    symlink_temp_id.filesystem_id,
                    symlink_temp_id.inode,
                    symlink_target.len() as u64,
                    0_i64,
                    0_i64,
                    0_i64,
                    0_i64,
                ),
                0o100600_u32,
                mb_store::StableAnchorAreaLocator {
                    area_id: Uuid::new_v4(),
                    path_hint: symlink_area.clone(),
                    filesystem_id: symlink_temp_id.filesystem_id,
                    volume_root_hint: temp.path().to_path_buf(),
                },
            ))
            .unwrap(),
        )
        .unwrap(),
    );
    external_store
        .put_record(
            &format!("git-worktree-symlink-stage-intent-v1/{repository_id}/{worktree_id}"),
            b"link-\xf8",
            &canonical_bytes(&(
                2_u16,
                repository_id,
                symlink_source.as_os_str().as_bytes().to_vec(),
                symlink_root_id,
                mb_store::NativeFileId {
                    filesystem_id: symlink_catalog_root_id.filesystem_id,
                    inode: 52,
                },
                b"link-\xf8".to_vec(),
                mb_store::NativeFileId {
                    filesystem_id: symlink_root_id.filesystem_id,
                    inode: 54,
                },
                &symlink_target,
                &symlink_temp_name,
                Some(symlink_temp_id),
                Some(symlink_plan),
                Some(symlink_catalog.as_os_str().as_bytes().to_vec()),
            ))
            .unwrap(),
        )
        .unwrap();
    let anchor_id = Uuid::new_v4();
    let area_id = Uuid::new_v4();
    let object_oid = *git2::Oid::hash_object(git2::ObjectType::Blob, b"native!")
        .unwrap()
        .as_bytes()
        .first_chunk::<20>()
        .unwrap();
    let manifest: mb_store::FileAnchorManifest = mb_core::decode_canonical(
        &canonical_bytes(&(
            1_u16,
            anchor_id,
            mb_store::StableAnchorAreaLocator {
                area_id,
                path_hint: object_area.clone(),
                filesystem_id: 7,
                volume_root_hint: "/".into(),
            },
            object_source.as_os_str().as_bytes().to_vec(),
            b"file-\xfb".to_vec(),
            7_u64,
            *blake3::hash(b"native!").as_bytes(),
            (7_u64, 31_u64, 7_u64, 0_i64, 0_i64, 0_i64, 0_i64),
        ))
        .unwrap(),
    )
    .unwrap();
    let prune_anchor_id = Uuid::new_v4();
    let prune_manifest: mb_store::FileAnchorManifest = mb_core::decode_canonical(
        &canonical_bytes(&(
            1_u16,
            prune_anchor_id,
            mb_store::StableAnchorAreaLocator {
                area_id: Uuid::new_v4(),
                path_hint: prune_area.clone(),
                filesystem_id: 7,
                volume_root_hint: temp.path().to_path_buf(),
            },
            prune_source.as_os_str().as_bytes().to_vec(),
            b"retired-\xf7".to_vec(),
            7_u64,
            *blake3::hash(b"native!").as_bytes(),
            (7_u64, 61_u64, 7_u64, 0_i64, 0_i64, 0_i64, 0_i64),
        ))
        .unwrap(),
    )
    .unwrap();
    external_store
        .put_record(
            &format!("git-prune-intent-v1/{repository_id}"),
            b"active",
            &canonical_bytes(&(1_u16, repository_id, vec![prune_manifest])).unwrap(),
        )
        .unwrap();
    let removal_worktree_id = Uuid::new_v4();
    let removal_root_id = mb_store::PinnedDirectory::open(&removal_root)
        .unwrap()
        .identity()
        .unwrap();
    let removal_entry = mb_git::GitIndexEntry {
        format_version: 1,
        oid: [35; 20],
        mode: 0o100644,
        anchor_id: Uuid::new_v4(),
    };
    let removing_worktree_id = Uuid::new_v4();
    let directory_id = |path: &Path| {
        mb_store::PinnedDirectory::open(path)
            .unwrap()
            .identity()
            .unwrap()
    };
    let removing_root_id = directory_id(&worktree_removal_root);
    let removing_marker_id = directory_id(&worktree_removal_marker);
    let removing_child_id = directory_id(&worktree_removal_child);
    external_store
        .put_record(
            &format!("git-worktree-remove-intent-v1/{repository_id}"),
            removing_worktree_id.as_bytes(),
            &canonical_bytes(&(
                1_u16,
                repository_id,
                removing_worktree_id,
                removing_root_id,
                directory_id(temp.path()),
                removing_marker_id,
                mb_store::NativeFileId {
                    filesystem_id: removing_root_id.filesystem_id,
                    inode: 63,
                },
                vec![(
                    b"nested/file-\xf5".to_vec(),
                    [36_u8; 20],
                    0o100755_u32,
                    mb_store::NativeFileId {
                        filesystem_id: removing_root_id.filesystem_id,
                        inode: 64,
                    },
                )],
                vec![(b"nested".to_vec(), removing_child_id)],
            ))
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-worktree-rm-intent-v1/{repository_id}/{removal_worktree_id}"),
            b"remove-\xf6",
            &canonical_bytes(&(
                1_u16,
                repository_id,
                removal_worktree_id,
                removal_root_id,
                b"remove-\xf6".to_vec(),
                &removal_entry,
                mb_store::NativeFileId {
                    filesystem_id: removal_root_id.filesystem_id,
                    inode: 62,
                },
            ))
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!(
                "git-object-anchor-v1/{repository_id}/{}",
                hex::encode(object_oid)
            ),
            anchor_id.as_bytes(),
            &canonical_bytes(&manifest).unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-worktree-index-entry-v1/{repository_id}/{worktree_id}"),
            b"file-\xfb",
            &canonical_bytes(&mb_git::GitIndexEntry {
                format_version: 1,
                oid: object_oid,
                mode: 0o100644,
                anchor_id,
            })
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            "anchor-area-location",
            area_id.as_bytes(),
            &canonical_bytes(&cached_area.as_os_str().as_bytes().to_vec()).unwrap(),
        )
        .unwrap();
    let tree_bytes = [b"100644 file-\xfb\0".as_slice(), object_oid.as_slice()].concat();
    let tree_oid = git2::Oid::hash_object(git2::ObjectType::Tree, &tree_bytes).unwrap();
    let commit_bytes = format!("tree {tree_oid}\nauthor A <a@example.test> 1 +0000\ncommitter A <a@example.test> 1 +0000\n\nretained commit\n").into_bytes();
    let commit_oid = git2::Oid::hash_object(git2::ObjectType::Commit, &commit_bytes).unwrap();
    let tag_bytes = format!("object {commit_oid}\ntype commit\ntag release\ntagger A <a@example.test> 1 +0000\n\nretained tag\n").into_bytes();
    let tag_oid = git2::Oid::hash_object(git2::ObjectType::Tag, &tag_bytes).unwrap();
    let fetch_id = Uuid::new_v4();
    let push_import_id = Uuid::new_v4();
    let metadata = vec![
        (
            2_u8,
            <[u8; 20]>::try_from(tree_oid.as_bytes()).unwrap(),
            tree_bytes.clone(),
        ),
        (
            1_u8,
            <[u8; 20]>::try_from(commit_oid.as_bytes()).unwrap(),
            commit_bytes.clone(),
        ),
        (
            3_u8,
            <[u8; 20]>::try_from(tag_oid.as_bytes()).unwrap(),
            tag_bytes.clone(),
        ),
    ];
    let commit_sha1: [u8; 20] = commit_oid.as_bytes().try_into().unwrap();
    let tag_sha1: [u8; 20] = tag_oid.as_bytes().try_into().unwrap();
    external_store
        .put_record(
            &format!("git-bare-fetch-intent-v1/{repository_id}"),
            b"active",
            &canonical_bytes(&(
                6_u16,
                fetch_id,
                repository_id,
                fetch_source.as_os_str().as_bytes().to_vec(),
                fetch_target.as_os_str().as_bytes().to_vec(),
                vec![
                    (b"refs/remotes/origin/main".to_vec(), commit_sha1),
                    (b"refs/tags/release".to_vec(), tag_sha1),
                ],
                metadata.clone(),
                vec![(object_oid, manifest.logical_len, false)],
            ))
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-stock-push-intent-v1/{repository_id}"),
            b"active",
            &canonical_bytes(&(
                2_u16,
                "release",
                Some(tag_sha1),
                (
                    4_u16,
                    push_import_id,
                    repository_id,
                    fetch_source.as_os_str().as_bytes().to_vec(),
                    fetch_target.as_os_str().as_bytes().to_vec(),
                    vec![(b"refs/tags/release".to_vec(), tag_sha1)],
                    metadata,
                    vec![(object_oid, manifest.logical_len, false)],
                ),
            ))
            .unwrap(),
        )
        .unwrap();
    let import_root_id = directory_id(&import_source);
    let merge_root_id = directory_id(&merge_source);
    let merge_anchor_id = Uuid::new_v4();
    let merge_area_id = Uuid::new_v4();
    let checkout_root_id = directory_id(&checkout_root);
    let checkout_stage_id = directory_id(&checkout_stage);
    let checkout_child_id = directory_id(&checkout_child);
    let checkout_removed_id = directory_id(&checkout_removed);
    let checkout_path = b"child/restored-\xf2".to_vec();
    let checkout_index = mb_git::GitIndexEntry {
        format_version: 1,
        oid: object_oid,
        mode: 0o100644,
        anchor_id,
    };
    // These original identities survive independent directory relocation.
    external_store
        .put_record(
            &format!("git-worktree-checkout-intent-v1/{repository_id}/{worktree_id}"),
            b"active",
            &canonical_bytes(&(
                3_u16,
                worktree_id,
                checkout_root_id,
                (
                    11_u16,
                    (
                        11_u16,
                        false,
                        None::<Vec<u8>>,
                        repository_id,
                        "topic",
                        commit_sha1,
                        "topic",
                        commit_sha1,
                        format!("checkout-{}", Uuid::new_v4()),
                        Some(checkout_stage_id),
                        1_u8,
                        vec![(
                            checkout_path.clone(),
                            Some(([46_u8; 20], 0o100644_u32, Uuid::nil())),
                            Some(mb_store::NativeFileId {
                                filesystem_id: checkout_root_id.filesystem_id,
                                inode: 65,
                            }),
                            Some((object_oid, 0o100644_u32, anchor_id)),
                            Some(mb_store::NativeFileId {
                                filesystem_id: checkout_root_id.filesystem_id,
                                inode: 66,
                            }),
                        )],
                        vec![(b"child".to_vec(), Some(checkout_child_id))],
                        vec![(b"removed".to_vec(), checkout_removed_id)],
                        vec![(checkout_path.clone(), (17_u64, [45_u8; 32]))],
                    ),
                    vec![checkout_path.clone()],
                    vec![(checkout_path.clone(), &checkout_index)],
                    [47_u8; 32],
                ),
            ))
            .unwrap(),
        )
        .unwrap();
    let fetch_anchor_id = Uuid::new_v4();
    let import_area_id = Uuid::new_v4();
    let import_root_plan: mb_store::ReflinkCapturePlan = mb_core::decode_canonical(
        &canonical_bytes(&(
            1_u16,
            fetch_anchor_id,
            import_source.as_os_str().as_bytes().to_vec(),
            mb_store::StableAnchorAreaLocator {
                area_id: import_area_id,
                filesystem_id: import_root_id.filesystem_id,
                path_hint: import_area.clone(),
                volume_root_hint: import_area.clone(),
            },
            (
                import_root_id.filesystem_id,
                import_root_id.inode,
                0_u64,
                0_i64,
                0_i64,
                0_i64,
                0_i64,
            ),
            libc::S_IFDIR | 0o700,
            0_i64,
            0_u32,
        ))
        .unwrap(),
    )
    .unwrap();
    #[derive(serde::Serialize)]
    enum OriginalFetchBlobPlan {
        DirectV1((u16, mb_store::ReflinkCapturePlan, u64)),
    }
    let merge_root_plan: mb_store::ReflinkCapturePlan = mb_core::decode_canonical(
        &canonical_bytes(&(
            1_u16,
            merge_anchor_id,
            merge_source.as_os_str().as_bytes().to_vec(),
            mb_store::StableAnchorAreaLocator {
                area_id: merge_area_id,
                filesystem_id: merge_root_id.filesystem_id,
                path_hint: merge_area.clone(),
                volume_root_hint: merge_area.clone(),
            },
            (
                merge_root_id.filesystem_id,
                merge_root_id.inode,
                0_u64,
                0_i64,
                0_i64,
                0_i64,
                0_i64,
            ),
            libc::S_IFDIR | 0o700,
            0_i64,
            0_u32,
        ))
        .unwrap(),
    )
    .unwrap();
    let merge_session = (
        1_u16,
        repository_id,
        "topic",
        commit_sha1,
        [40_u8; 20],
        b"refs/heads/source".to_vec(),
        "private cli author",
        "private-cli@example.test",
        "private merge cli message",
        vec![b"conflict-\xf4".to_vec(), b"resolved".to_vec()],
        vec![b"resolved".to_vec()],
    );
    external_store
        .put_record(
            &format!("git-merge-session-v1/{repository_id}"),
            b"active",
            &canonical_bytes(&merge_session).unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-worktree-merge-session-v1/{repository_id}/{worktree_id}"),
            b"active",
            &canonical_bytes(&(1_u16, worktree_id, &merge_session)).unwrap(),
        )
        .unwrap();
    let merge_input = |oid| (oid, 0o100755_u32);
    external_store
        .put_record(
            &format!("git-worktree-merge-blob-intent-v1/{repository_id}/{worktree_id}"),
            b"active",
            &canonical_bytes(&(
                1_u16,
                worktree_id,
                (
                    1_u16,
                    repository_id,
                    b"generated-\xf3".to_vec(),
                    (
                        merge_input([41_u8; 20]),
                        merge_input([42_u8; 20]),
                        merge_input([43_u8; 20]),
                    ),
                    [39_u8; 20],
                    0o100755_u32,
                    OriginalFetchBlobPlan::DirectV1((1, merge_root_plan, 17)),
                ),
            ))
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-bare-fetch-blob-intent-v1/{repository_id}"),
            &object_oid,
            &canonical_bytes(&(
                1_u16,
                repository_id,
                object_oid,
                manifest.logical_len,
                OriginalFetchBlobPlan::DirectV1((1, import_root_plan, manifest.logical_len)),
            ))
            .unwrap(),
        )
        .unwrap();
    external_store
        .put_record(
            &format!("git-bare-fetch-verified-v1/{repository_id}/{fetch_id}"),
            &object_oid,
            &canonical_bytes(&(1_u16, object_oid, vec![(fetch_anchor_id, [38_u8; 32])])).unwrap(),
        )
        .unwrap();
    for (oid, kind, bytes) in [
        (tree_oid, 2_u8, tree_bytes),
        (commit_oid, 1, commit_bytes),
        (tag_oid, 3, tag_bytes),
    ] {
        external_store
            .put_record(
                &format!("git-metadata-object-v1/{repository_id}"),
                oid.as_bytes(),
                &canonical_bytes(&(1_u16, kind, bytes)).unwrap(),
            )
            .unwrap();
    }
    for (name, oid) in [
        ("refs/heads/main".to_owned(), commit_oid),
        ("refs/tags/release".to_owned(), tag_oid),
        ("refs/remotes/origin/main".to_owned(), commit_oid),
        (format!("refs/mutualbackup/pins/{commit_oid}"), commit_oid),
        ("refs/mutualbackup/pins/retained".to_owned(), commit_oid),
    ] {
        let oid: [u8; 20] = oid.as_bytes().try_into().unwrap();
        external_store
            .put_record(
                &format!("git-ref-v1/{repository_id}"),
                name.as_bytes(),
                &canonical_bytes(&(1_u16, oid)).unwrap(),
            )
            .unwrap();
    }
    for (kind, branch) in [
        (format!("git-head-v1/{repository_id}"), "main"),
        (
            format!("git-worktree-head-v1/{repository_id}/{worktree_id}"),
            "topic",
        ),
    ] {
        external_store
            .put_record(
                &kind,
                b"branch",
                &canonical_bytes(&(1_u16, branch)).unwrap(),
            )
            .unwrap();
    }
    drop(external_store);
    let external_files = || -> std::collections::BTreeMap<_, _> {
        fs::read_dir(&external_catalog)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect()
    };
    let original_external = external_files();
    store
        .put_record(
            "git-repository",
            repository_id.as_bytes(),
            &canonical_bytes(&mb_node::GitRepositoryInfo {
                format_version: 1,
                repository_id,
                path: history_only.clone(),
            })
            .unwrap(),
        )
        .unwrap();
    for (index, reference) in revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .enumerate()
    {
        let bytes = if reference.id == metadata_id {
            &metadata_bytes
        } else {
            &data_bytes
        };
        store
            .stage_recovery_shard(
                &[80; 32],
                &guild,
                &[index as u8; 32],
                0,
                &reference.root,
                bytes,
            )
            .unwrap();
    }
    drop(store);
    let original = fs::read(catalog.join("control.db")).unwrap();
    let list_args = vec![
        os("legacy-list"),
        os("--data-dir"),
        catalog.clone().into_os_string(),
        os("--seed-file"),
        seed_file.clone().into_os_string(),
    ];
    let listed = run_output(program("mutualbackup"), &list_args, CLI_TIMEOUT).unwrap();
    assert!(
        listed.status.success(),
        "{}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let inventory: mb_node::LegacyRevisionInventory =
        serde_json::from_slice(&listed.stdout).unwrap();
    assert_eq!(inventory.format_version, 18);
    assert!(!inventory.retained_history_complete);
    assert_eq!(inventory.revisions.len(), 1);
    assert_eq!(inventory.revisions[0].revision_id, revision_id);
    assert_eq!(inventory.local_state.unclassified_guarded_records.len(), 1);
    assert_eq!(inventory.local_state.protected_roots.len(), 1);
    assert_eq!(inventory.local_state.git_repositories.len(), 1);
    assert_eq!(inventory.local_state.storage_volumes.len(), 2);
    let saved_volume = inventory
        .local_state
        .storage_volumes
        .iter()
        .find(|record| record.path_hex == hex::encode(volume.as_os_str().as_bytes()))
        .unwrap();
    assert!(saved_volume.configured && saved_volume.configured_recorded);
    assert_eq!(saved_volume.budget_bytes, 65536);
    assert!(!saved_volume.payloads_verified);
    assert_eq!(inventory.local_state.local_sectors.len(), 1);
    let filler_entry = &inventory.local_state.local_sectors[0];
    assert_eq!(filler_entry.sector_id, hex::encode(filler.id));
    assert_eq!(filler_entry.logical_len, 0);
    assert!(matches!(
        &filler_entry.source,
        mb_node::LegacyLocalSectorSource::Inline { byte_length: 0 }
    ));
    assert!(!filler_entry.payloads_verified);
    assert!(!inventory.local_state.git_repositories[0].registered_root);
    let git_registration = &inventory.local_state.git_repositories[0];
    assert!(
        git_registration.source_backend_binding_inventoried
            && git_registration.unclassified_records_inventoried
    );
    assert_eq!(
        git_registration.saved_source_backend,
        Some(mb_node::LegacySavedGitBackend {
            record_format: 1,
            backend: mb_store::SourceBackendKind::GuardedLinkFreezeV1
        })
    );
    assert!(inventory.local_state.unclassified_git_records.is_empty());
    assert!(git_registration.external_catalog_available);
    assert!(git_registration.linked_worktrees_inventoried);
    assert!(git_registration.object_anchors_inventoried);
    assert!(git_registration.worktree_indexes_inventoried);
    assert!(git_registration.anchor_area_locations_inventoried);
    assert!(git_registration.references_inventoried);
    assert!(git_registration.metadata_objects_inventoried);
    assert!(git_registration.selected_branches_inventoried);
    assert!(git_registration.regular_stage_intents_inventoried);
    assert!(git_registration.symlink_stage_intents_inventoried);
    assert!(
        git_registration.prune_intents_inventoried && git_registration.removal_intents_inventoried
    );
    assert_eq!(inventory.local_state.pending_git_prunes.len(), 1);
    let saved_prune = &inventory.local_state.pending_git_prunes[0];
    assert_eq!(saved_prune.repository_id, repository_id);
    assert_eq!(saved_prune.record_format, 1);
    assert_eq!(saved_prune.anchors.len(), 1);
    assert_eq!(saved_prune.anchors[0].anchor_id, prune_anchor_id);
    assert!(!saved_prune.payloads_verified);
    assert_eq!(inventory.local_state.pending_git_removals.len(), 1);
    let saved_removal = &inventory.local_state.pending_git_removals[0];
    assert_eq!(saved_removal.repository_id, repository_id);
    assert_eq!(saved_removal.worktree_id, removal_worktree_id);
    assert_eq!(saved_removal.recorded_root_identity, removal_root_id);
    assert_eq!(saved_removal.relative_path_hex, hex::encode(b"remove-\xf6"));
    assert_eq!(saved_removal.entry, removal_entry);
    assert!(!saved_removal.payloads_verified);
    assert!(git_registration.worktree_removal_intents_inventoried);
    assert_eq!(inventory.local_state.pending_git_worktree_removals.len(), 1);
    let saved_worktree_removal = &inventory.local_state.pending_git_worktree_removals[0];
    assert_eq!(saved_worktree_removal.repository_id, repository_id);
    assert_eq!(saved_worktree_removal.worktree_id, removing_worktree_id);
    assert_eq!(saved_worktree_removal.record_format, 1);
    assert_eq!(
        saved_worktree_removal.recorded_root_identity,
        removing_root_id
    );
    assert_eq!(
        saved_worktree_removal.recorded_marker_directory_identity,
        removing_marker_id
    );
    assert_eq!(
        saved_worktree_removal.files[0].relative_path_hex,
        hex::encode(b"nested/file-\xf5")
    );
    assert_eq!(saved_worktree_removal.files[0].oid, hex::encode([36; 20]));
    assert_eq!(
        saved_worktree_removal.directories[0].recorded_identity,
        removing_child_id
    );
    assert!(!saved_worktree_removal.payloads_verified);
    assert!(
        git_registration.fetch_intents_inventoried
            && git_registration.push_intents_inventoried
            && git_registration.blob_import_intents_inventoried
            && git_registration.fetch_verification_records_inventoried
    );
    assert_eq!(inventory.local_state.pending_git_fetches.len(), 2);
    for entry in &inventory.local_state.pending_git_fetches {
        assert_eq!(
            entry.source_path_hint_hex,
            hex::encode(fetch_source.as_os_str().as_bytes())
        );
        assert_eq!(
            entry.source_root_hint_hex,
            hex::encode(fetch_target.as_os_str().as_bytes())
        );
        assert!(!entry.graph_metadata_validated && !entry.payloads_verified);
        assert_eq!(entry.objects.len(), 3);
        assert_eq!(entry.blobs[0].oid, hex::encode(object_oid));
        if entry.fetch_id == push_import_id {
            let push = entry.push.as_ref().unwrap();
            assert_eq!(entry.record_format, 4);
            assert_eq!(push.record_format, 2);
            assert_eq!(push.target_name, "release");
            assert_eq!(push.expected_old, Some(hex::encode(tag_sha1)));
        } else {
            assert_eq!(entry.fetch_id, fetch_id);
            assert_eq!(entry.record_format, 6);
            assert!(entry.push.is_none());
        }
    }
    assert_eq!(inventory.local_state.pending_git_blob_imports.len(), 1);
    let import = &inventory.local_state.pending_git_blob_imports[0];
    assert_eq!(import.oid, hex::encode(object_oid));
    assert_eq!(import.plan.anchor_id, fetch_anchor_id);
    assert_eq!(import.plan.area_id, import_area_id);
    assert_eq!(import.plan.recorded_root_identity, import_root_id);
    assert_eq!(import.plan.stable_root_identity, None);
    assert_eq!(import.plan.logical_len, manifest.logical_len);
    assert!(!import.payloads_verified);
    assert_eq!(inventory.local_state.verified_git_fetch_blobs.len(), 1);
    let verified = &inventory.local_state.verified_git_fetch_blobs[0];
    assert_eq!(verified.fetch_id, fetch_id);
    assert_eq!(verified.anchors[0].anchor_id, fetch_anchor_id);
    assert_eq!(verified.anchors[0].content_hash, hex::encode([38; 32]));
    assert!(!verified.payloads_verified);
    assert!(
        git_registration.merge_sessions_inventoried
            && git_registration.merge_blob_intents_inventoried
    );
    assert_eq!(inventory.local_state.pending_git_merge_sessions.len(), 2);
    for session in &inventory.local_state.pending_git_merge_sessions {
        assert_eq!(session.record_format, 1);
        assert!([repository_id, worktree_id].contains(&session.worktree_id));
        assert_eq!(
            session.envelope_format,
            (session.worktree_id == worktree_id).then_some(1)
        );
        assert_eq!(
            session.conflict_paths_hex,
            vec![hex::encode(b"conflict-\xf4"), hex::encode(b"resolved")]
        );
        assert_eq!(session.resolved_paths_hex, vec![hex::encode(b"resolved")]);
        assert_eq!(
            session.message.bytes,
            b"private merge cli message".len() as u64
        );
        assert_eq!(
            session.message.hash,
            hex::encode(blake3::hash(b"private merge cli message").as_bytes())
        );
        assert!(!session.payloads_verified);
    }
    assert_eq!(inventory.local_state.pending_git_merge_blobs.len(), 1);
    let merge = &inventory.local_state.pending_git_merge_blobs[0];
    assert_eq!(merge.worktree_id, worktree_id);
    assert_eq!(merge.record_format, 1);
    assert_eq!(merge.envelope_format, Some(1));
    assert_eq!(merge.relative_path_hex, hex::encode(b"generated-\xf3"));
    assert_eq!(merge.plan.anchor_id, merge_anchor_id);
    assert_eq!(merge.plan.area_id, merge_area_id);
    assert_eq!(merge.plan.recorded_root_identity, merge_root_id);
    assert_eq!(merge.result_oid, hex::encode([39; 20]));
    assert_eq!(merge.result_mode, 0o100755);
    assert_eq!(merge.plan.logical_len, 17);
    assert!(!merge.payloads_verified);
    assert!(git_registration.checkout_intents_inventoried);
    assert_eq!(inventory.local_state.pending_git_checkouts.len(), 1);
    let checkout = &inventory.local_state.pending_git_checkouts[0];
    assert_eq!(checkout.worktree_id, worktree_id);
    assert_eq!(checkout.record_format, 11);
    assert_eq!(checkout.envelope_format, Some(3));
    assert_eq!(checkout.recorded_root_identity, Some(checkout_root_id));
    assert_eq!(checkout.recorded_staging_identity, Some(checkout_stage_id));
    assert_eq!(checkout.phase, mb_node::LegacyGitCheckoutPhase::Applying);
    assert_eq!(
        checkout.entries[0].relative_path_hex,
        hex::encode(&checkout_path)
    );
    assert_eq!(
        checkout.entries[0].old.as_ref().unwrap().native_root,
        Some(mb_node::LegacyGitNativeContentRoot {
            logical_len: 17,
            content_hash: hex::encode([45; 32])
        })
    );
    assert_eq!(
        checkout.entries[0].new.as_ref().unwrap().anchor_id,
        anchor_id
    );
    assert_eq!(
        checkout.directories[0].recorded_staged_identity,
        Some(checkout_child_id)
    );
    assert_eq!(
        checkout.removed_directories[0].recorded_old_identity,
        checkout_removed_id
    );
    assert_eq!(
        checkout.selected_paths_hex,
        vec![hex::encode(&checkout_path)]
    );
    assert_eq!(checkout.target_index[0].entry, checkout_index);
    assert_eq!(checkout.old_index_hash, Some(hex::encode([47; 32])));
    assert!(!checkout.payloads_verified);
    for private in [
        "private cli author",
        "private-cli@example.test",
        "private merge cli message",
    ] {
        assert!(!String::from_utf8_lossy(&listed.stdout).contains(private));
        assert!(!String::from_utf8_lossy(&listed.stdout).contains(&hex::encode(private)));
    }
    assert_eq!(inventory.local_state.pending_git_symlinks.len(), 1);
    let saved_symlink = &inventory.local_state.pending_git_symlinks[0];
    assert_eq!(saved_symlink.repository_id, repository_id);
    assert_eq!(saved_symlink.worktree_id, worktree_id);
    assert_eq!(saved_symlink.record_format, 2);
    assert_eq!(saved_symlink.relative_path_hex, hex::encode(b"link-\xf8"));
    assert_eq!(saved_symlink.recorded_root_identity, symlink_root_id);
    assert_eq!(
        saved_symlink.catalog_root_hint_hex,
        Some(hex::encode(symlink_catalog.as_os_str().as_bytes()))
    );
    assert_eq!(saved_symlink.recorded_temp_identity, Some(symlink_temp_id));
    assert_eq!(saved_symlink.temp_name, symlink_temp_name);
    assert_eq!(saved_symlink.target_bytes, symlink_target.len() as u64);
    assert_eq!(
        saved_symlink.target_hash,
        hex::encode(blake3::hash(&symlink_target).as_bytes())
    );
    assert_eq!(
        saved_symlink.plan.as_ref().unwrap().backend,
        mb_store::SourceBackendKind::GuardedLinkFreezeV1
    );
    assert!(!saved_symlink.payloads_verified);
    assert!(!String::from_utf8_lossy(&listed.stdout).contains("private-symlink-target"));
    assert!(!String::from_utf8_lossy(&listed.stdout).contains(&hex::encode(&symlink_target)));
    assert_eq!(inventory.local_state.pending_git_stages.len(), 1);
    let saved_stage = &inventory.local_state.pending_git_stages[0];
    assert_eq!(saved_stage.repository_id, repository_id);
    assert_eq!(saved_stage.worktree_id, worktree_id);
    assert_eq!(saved_stage.record_format, 1);
    assert_eq!(
        saved_stage.relative_path_hex,
        hex::encode(b"unfinished-\xfa")
    );
    assert_eq!(saved_stage.git_mode, 0o100755);
    assert_eq!(
        saved_stage.plan.backend,
        mb_store::SourceBackendKind::GuardedLinkFreezeV1
    );
    assert_eq!(saved_stage.plan.capture_id, stage_capture_id);
    assert_eq!(saved_stage.plan.area_id, stage_area_id);
    assert_eq!(saved_stage.plan.logical_len, 7);
    assert_eq!(saved_stage.plan.stable_root_identity, Some(stage_root_id));
    assert!(!saved_stage.payloads_verified);
    assert_eq!(inventory.local_state.git_references.len(), 5);
    assert!(
        inventory
            .local_state
            .git_references
            .iter()
            .any(|saved| saved.pin_namespace && saved.pin_name_matches_target == Some(true))
    );
    assert!(
        inventory
            .local_state
            .git_references
            .iter()
            .any(|saved| saved.pin_namespace && saved.pin_name_matches_target == Some(false))
    );
    assert!(
        inventory
            .local_state
            .git_references
            .iter()
            .all(|saved| !saved.target_graph_reconciled)
    );
    assert_eq!(inventory.local_state.git_metadata_objects.len(), 3);
    assert!(
        inventory
            .local_state
            .git_metadata_objects
            .iter()
            .all(|saved| saved.content_address_verified && !saved.graph_metadata_validated)
    );
    assert_eq!(inventory.local_state.git_selected_branches.len(), 2);
    assert!(
        inventory
            .local_state
            .git_selected_branches
            .iter()
            .any(|saved| saved.worktree_id == worktree_id && saved.branch == "topic")
    );
    assert_eq!(inventory.local_state.git_object_anchors.len(), 1);
    let object = &inventory.local_state.git_object_anchors[0];
    assert_eq!(object.repository_id, repository_id);
    assert_eq!(object.pin.anchor_id, anchor_id);
    assert_eq!(object.pin.oid, hex::encode(object_oid));
    assert!(!object.payloads_verified);
    assert_eq!(inventory.local_state.git_indexes.len(), 1);
    let index = &inventory.local_state.git_indexes[0];
    assert_eq!(index.worktree_id, worktree_id);
    assert_eq!(index.anchor_id, anchor_id);
    assert_eq!(index.relative_path_hex, hex::encode(b"file-\xfb"));
    assert!(!index.payloads_verified);
    assert_eq!(inventory.local_state.git_anchor_area_locations.len(), 1);
    assert_eq!(
        inventory.local_state.git_anchor_area_locations[0].path_hex,
        hex::encode(cached_area.as_os_str().as_bytes())
    );
    assert!(!git_registration.catalog_inventoried);
    assert_eq!(inventory.local_state.git_worktrees.len(), 1);
    let saved_worktree = &inventory.local_state.git_worktrees[0];
    assert_eq!(saved_worktree.repository_id, repository_id);
    assert_eq!(saved_worktree.worktree_id, worktree_id);
    assert_eq!(
        saved_worktree.path_hex,
        hex::encode(worktree.as_os_str().as_bytes())
    );
    assert_eq!(saved_worktree.state, mb_git::GitWorktreeState::Preparing);
    assert!(!saved_worktree.payloads_verified);
    assert_eq!(external_files(), original_external);
    let preserved = &inventory.local_state.unclassified_guarded_records[0];
    assert_eq!(preserved.kind, "guarded-view-mount-v1");
    assert_eq!(preserved.record_id_hex, hex::encode(b"legacy"));
    assert_eq!(preserved.payload_bytes, 8);
    assert_eq!(
        preserved.payload_hash,
        hex::encode(blake3::hash(b"preserve").as_bytes())
    );
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    assert!(!catalog.join("control.key").exists());
    let history_alias = temp.path().join("history-alias");
    std::os::unix::fs::symlink(&history_only, &history_alias).unwrap();
    let catalog_files = || -> std::collections::BTreeMap<_, _> {
        fs::read_dir(&catalog)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), fs::read(entry.path()).unwrap())
            })
            .collect()
    };
    let before_destination_checks = catalog_files();
    for parent in [
        registered_source.clone(),
        registered_source.join("nested"),
        history_only.clone(),
        history_alias.join("nested"),
        volume.clone(),
        volume.join("nested"),
        worktree.clone(),
        worktree.join("nested"),
        worktree_alias.join("nested"),
        object_source.join("nested"),
        object_area.join("nested"),
        object_alias.join("nested"),
        cached_area.join("nested"),
        stage_source.join("nested"),
        stage_area.join("nested"),
        stage_alias.join("nested"),
        symlink_source.join("nested"),
        symlink_catalog.join("nested"),
        symlink_area.join("nested"),
        prune_source.join("nested"),
        prune_area.join("nested"),
        removal_root.join("nested"),
        worktree_removal_root.join("nested"),
        worktree_removal_marker.join("nested"),
        worktree_removal_child.join("nested"),
        fetch_source.join("nested"),
        fetch_target.join("nested"),
        import_source.join("nested"),
        import_area.join("nested"),
        import_alias.join("nested"),
        merge_source.join("nested"),
        merge_area.join("nested"),
        merge_alias.join("nested"),
        checkout_root.join("nested"),
        checkout_stage.join("nested"),
        checkout_child.join("nested"),
        checkout_removed.join("nested"),
        checkout_alias.join("nested"),
    ] {
        let destination = parent.join("rejected-export");
        let rejected = run_output(
            program("mutualbackup"),
            &[
                os("legacy-export"),
                os("--data-dir"),
                catalog.clone().into_os_string(),
                os("--revision-id"),
                os(revision_id.to_string()),
                os("--destination"),
                destination.clone().into_os_string(),
                os("--seed-file"),
                seed_file.clone().into_os_string(),
            ],
            CLI_TIMEOUT,
        )
        .unwrap();
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
        assert!(
            String::from_utf8_lossy(&rejected.stderr)
                .contains("export destination must be outside preserved inputs")
        );
        assert!(!destination.exists());
        assert!(
            catalog_files() == before_destination_checks,
            "preserved catalog changed during destination rejection"
        );
        assert_eq!(external_files(), original_external);
    }
    for path in [&registered_source, &history_only] {
        assert_eq!(
            fs::read(path.join("original")).unwrap(),
            b"preserve source/history"
        );
        assert_eq!(
            fs::read_dir(path).unwrap().count(),
            if path == &history_only { 3 } else { 2 }
        );
        assert_eq!(fs::read_dir(path.join("nested")).unwrap().count(), 0);
    }
    let catalog_target = temp.path().join("catalog-export");
    let extra_peer = KeyMaterial::from_seed(&Seed::from_bytes([71; 32])).node_id();
    let extra_endpoint = format!(
        "{extra_peer}=/ip4/127.0.0.1/udp/9/quic-v1/p2p/{}",
        extra_peer.libp2p_peer_id().unwrap()
    );
    let mut peer_list_args = list_args.clone();
    peer_list_args.extend([os("--peer"), os(&extra_endpoint)]);
    let refused = run_output(program("mutualbackup"), &peer_list_args, CLI_TIMEOUT).unwrap();
    assert!(!refused.status.success());
    assert!(refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&refused.stderr)
            .contains("peer inventory requires the preserved signed guild certificate")
    );
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    let mut discovery_args = list_args.clone();
    discovery_args.extend([os("--bootstrap-peer"), os(&extra_endpoint)]);
    let discovery_refused =
        run_output(program("mutualbackup"), &discovery_args, CLI_TIMEOUT).unwrap();
    assert!(!discovery_refused.status.success());
    assert!(discovery_refused.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&discovery_refused.stderr)
            .contains("directory discovery requires the preserved signed guild certificate")
    );
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    let catalog_args = vec![
        os("legacy-export"),
        os("--peer"),
        os(extra_endpoint),
        os("--data-dir"),
        catalog.clone().into_os_string(),
        os("--revision-id"),
        os(revision_id.to_string()),
        os("--destination"),
        catalog_target.clone().into_os_string(),
        os("--seed-file"),
        seed_file.clone().into_os_string(),
    ];
    let output = run_output(program("mutualbackup"), &catalog_args, CLI_TIMEOUT).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(
            catalog_target
                .join("namespace")
                .join(OsString::from_vec(b"payload-\xff".to_vec()))
        )
        .unwrap(),
        b"offline payload"
    );
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    assert!(!catalog.join("control.key").exists());
    let mut confined_args = catalog_args.clone();
    let destination_index = confined_args
        .iter()
        .position(|argument| argument == "--destination")
        .unwrap()
        + 1;
    let confined_target = temp.path().join("rejected-tmpdir-export");
    confined_args[destination_index] = confined_target.clone().into_os_string();
    let entries_before = fs::read_dir(&catalog).unwrap().count();
    for confined in [
        &catalog,
        &registered_source.join("nested"),
        &history_only,
        &history_alias.join("nested"),
        &worktree,
        &worktree_alias.join("nested"),
        &object_source.join("nested"),
        &object_alias.join("nested"),
        &cached_area.join("nested"),
        &stage_source.join("nested"),
        &stage_area.join("nested"),
        &stage_alias.join("nested"),
        &symlink_source.join("nested"),
        &symlink_catalog.join("nested"),
        &symlink_area.join("nested"),
        &prune_source.join("nested"),
        &prune_area.join("nested"),
        &removal_root.join("nested"),
        &worktree_removal_root.join("nested"),
        &worktree_removal_marker.join("nested"),
        &worktree_removal_child.join("nested"),
        &fetch_source.join("nested"),
        &fetch_target.join("nested"),
        &import_source.join("nested"),
        &import_area.join("nested"),
        &import_alias.join("nested"),
        &merge_source.join("nested"),
        &merge_area.join("nested"),
        &merge_alias.join("nested"),
        &checkout_root.join("nested"),
        &checkout_stage.join("nested"),
        &checkout_child.join("nested"),
        &checkout_removed.join("nested"),
        &checkout_alias.join("nested"),
    ] {
        for args in [&confined_args, &peer_list_args] {
            let child = Command::new(program("mutualbackup"))
                .args(args)
                .env("TMPDIR", confined)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let rejected = wait_for_output(child, CLI_TIMEOUT).unwrap();
            assert!(!rejected.status.success());
            assert!(
                String::from_utf8_lossy(&rejected.stderr)
                    .contains("temporary client directory must be outside preserved inputs")
            );
        }
    }
    assert!(!confined_target.exists());
    for path in [&registered_source, &history_only] {
        assert_eq!(
            fs::read(path.join("original")).unwrap(),
            b"preserve source/history"
        );
        assert_eq!(
            fs::read_dir(path).unwrap().count(),
            if path == &history_only { 3 } else { 2 }
        );
        assert_eq!(fs::read_dir(path.join("nested")).unwrap().count(), 0);
    }
    assert_eq!(external_files(), original_external);
    assert_eq!(
        fs::read(worktree.join("original")).unwrap(),
        b"preserve linked worktree"
    );
    assert_eq!(fs::read_dir(&worktree).unwrap().count(), 2);
    assert_eq!(fs::read_dir(worktree.join("nested")).unwrap().count(), 0);
    for path in [
        &object_source,
        &object_area,
        &cached_area,
        &stage_source,
        &stage_area,
        &symlink_source,
        &symlink_catalog,
        &symlink_area,
        &prune_source,
        &prune_area,
        &removal_root,
        &worktree_removal_root,
        &worktree_removal_marker,
        &worktree_removal_child,
        &fetch_source,
        &fetch_target,
        &import_source,
        &import_area,
        &merge_source,
        &merge_area,
        &checkout_root,
        &checkout_stage,
        &checkout_child,
        &checkout_removed,
    ] {
        assert_eq!(
            fs::read(path.join("original")).unwrap(),
            b"preserve Git ownership"
        );
        assert_eq!(fs::read_dir(path).unwrap().count(), 2);
        assert_eq!(fs::read_dir(path.join("nested")).unwrap().count(), 0);
    }
    assert_eq!(fs::read_dir(&catalog).unwrap().count(), entries_before);
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    let area_id = Uuid::new_v4();
    let anchor_id = Uuid::new_v4();
    let area = temp.path().join("preserved-area");
    let anchor = area.join(anchor_id.to_string());
    fs::create_dir_all(&anchor).unwrap();
    fs::write(
        area.join(".mutualbackup-anchor-area-v1"),
        format!("mutualbackup-anchor-area-v1\n{area_id}\n"),
    )
    .unwrap();
    let payload = anchor.join("payload");
    fs::write(&payload, b"prefixoffline payload").unwrap();
    let mut store = mb_store::ControlStore::open(catalog.join("control.db"), &keys).unwrap();
    store.clear_recovery_shards(&[80; 32]).unwrap();
    store
        .stage_recovery_shard(
            &[80; 32],
            &guild,
            &[0; 32],
            0,
            &revision.value.metadata_sectors[0].root,
            &metadata_bytes,
        )
        .unwrap();
    let locator = mb_store::AnchorFileLocator {
        area: mb_store::AnchorAreaLocator {
            area_id,
            path_hint: temp.path().join("missing-old-view"),
        },
        anchor_id,
        relative_path: "payload".into(),
    };
    // Historical AnchorFile discriminant 0, followed by its locator and offset.
    let recipe =
        canonical_bytes(&(guild, &revision.value.data_sectors[0], 0_u8, locator, 6_u64)).unwrap();
    store.put_record("local-sector", &data_id, &recipe).unwrap();
    drop(store);
    let original = fs::read(catalog.join("control.db")).unwrap();
    let anchor_target = temp.path().join("anchor-export");
    let output = run_output(
        program("mutualbackup"),
        &[
            os("legacy-export"),
            os("--data-dir"),
            catalog.clone().into_os_string(),
            os("--revision-id"),
            os(revision_id.to_string()),
            os("--anchor-area"),
            area.into_os_string(),
            os("--destination"),
            anchor_target.clone().into_os_string(),
            os("--seed-file"),
            seed_file.clone().into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(
            anchor_target
                .join("namespace")
                .join(OsString::from_vec(b"payload-\xff".to_vec()))
        )
        .unwrap(),
        b"offline payload"
    );
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    assert_eq!(fs::read(payload).unwrap(), b"prefixoffline payload");
    assert!(!catalog.join("control.key").exists());
    let helpers: Vec<_> = [111, 112, 113, 114]
        .into_iter()
        .map(|byte| KeyMaterial::from_seed(&Seed::from_bytes([byte; 32])))
        .collect();
    let members = [&keys, &helpers[0], &helpers[1], &helpers[2], &helpers[3]];
    let mut roster: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(index, key)| mb_core::Member {
            node_id: key.node_id(),
            recovery_public_key: key.recovery_public_key(),
            failure_domain: format!("domain-{index}"),
        })
        .collect();
    roster.sort_by_key(|member| member.node_id);
    let mut groups = Vec::new();
    for (index, reference) in revision
        .value
        .metadata_sectors
        .iter()
        .chain(&revision.value.data_sectors)
        .enumerate()
    {
        let bytes = if reference.id == metadata_id {
            metadata_bytes.clone()
        } else {
            data_bytes.clone()
        };
        let shards = mb_core::encode_3_2([
            bytes,
            vec![1; mb_core::V1_SECTOR_SIZE],
            vec![2; mb_core::V1_SECTOR_SIZE],
        ])
        .unwrap();
        let mut group = mb_core::CodingGroup {
            id: [0; 32],
            format_version: 1,
            guild_id: guild,
            data_shards: 3,
            parity_shards: 2,
            shard_size: mb_core::V1_SECTOR_SIZE as u32,
            roles: [
                mb_core::ShardRole::Information(mb_core::InformationRole {
                    owner: keys.node_id(),
                    sector: reference.clone(),
                }),
                mb_core::ShardRole::Information(mb_core::InformationRole {
                    owner: members[1].node_id(),
                    sector: mb_core::SectorRef {
                        id: [200 + index as u8; 32],
                        root: mb_core::sector_root(&shards[1]),
                        logical_len: 0,
                    },
                }),
                mb_core::ShardRole::Information(mb_core::InformationRole {
                    owner: members[2].node_id(),
                    sector: mb_core::SectorRef {
                        id: [210 + index as u8; 32],
                        root: mb_core::sector_root(&shards[2]),
                        logical_len: 0,
                    },
                }),
                mb_core::ShardRole::Parity(mb_core::ParityRole {
                    holder: members[3].node_id(),
                    row: 0,
                    root: mb_core::sector_root(&shards[3]),
                }),
                mb_core::ShardRole::Parity(mb_core::ParityRole {
                    holder: members[4].node_id(),
                    row: 1,
                    root: mb_core::sector_root(&shards[4]),
                }),
            ],
        };
        group.id = group.calculate_id().unwrap();
        groups.push((group, shards));
    }
    groups.sort_by_key(|(group, _)| group.id);
    let mut checkpoint = mb_core::QuorumCheckpoint {
        checkpoint: mb_core::GuildCheckpoint {
            format_version: 3,
            guild_id: guild,
            genesis_hash: [99; 32],
            generation: 1,
            parent: None,
            members: roster,
            writer_fences: vec![mb_core::WriterFence {
                owner: keys.node_id(),
                epoch: 1,
                public_key: revision.value.writer_public_key,
            }],
            revision_tombstones: vec![],
            revisions: vec![revision.clone()],
            coding_groups: groups.iter().map(|(group, _)| group.clone()).collect(),
            authority: None,
            packing_catalog: None,
        },
        signatures: vec![],
    };
    for member in members {
        checkpoint.add_signature(member).unwrap();
    }
    checkpoint.verify().unwrap();
    let hash = checkpoint.hash().unwrap();
    let mut store = mb_store::ControlStore::open(catalog.join("control.db"), &keys).unwrap();
    store.clear_recovery_shards(&[80; 32]).unwrap();
    store.delete_record("local-sector", &data_id).unwrap();
    store
        .put_record(
            "guild-checkpoint",
            &hash,
            &canonical_bytes(&checkpoint).unwrap(),
        )
        .unwrap();
    let parity_volume = temp.path().join("preserved-parity");
    fs::create_dir(&parity_volume).unwrap();
    let volume_id = Uuid::from_bytes(
        blake3::hash(&keys.node_id().0).as_bytes()[..16]
            .try_into()
            .unwrap(),
    );
    let mut parity_store =
        mb_store::ParityStore::open(parity_volume.join("parity.db"), volume_id.as_bytes(), &keys)
            .unwrap();
    for (group, shards) in groups {
        for index in [2, 3, 4] {
            if index >= 3 {
                parity_store
                    .stage_and_publish(&mb_store::ParityObject {
                        format_version: 1,
                        guild_id: guild,
                        group_id: group.id,
                        shard_index: index as u8,
                        root: mb_core::sector_root(&shards[index]),
                        bytes: shards[index].clone(),
                    })
                    .unwrap();
                continue;
            }
            store
                .stage_recovery_shard(
                    &hash,
                    &guild,
                    &group.id,
                    index as u8,
                    &mb_core::sector_root(&shards[index]),
                    &shards[index],
                )
                .unwrap();
        }
    }
    drop(parity_store);
    let original_parity = fs::read(parity_volume.join("parity.db")).unwrap();
    drop(store);
    let original = fs::read(catalog.join("control.db")).unwrap();
    let coded_target = temp.path().join("coded-export");
    let output = run_output(
        program("mutualbackup"),
        &[
            os("legacy-export"),
            os("--data-dir"),
            catalog.clone().into_os_string(),
            os("--revision-id"),
            os(revision_id.to_string()),
            os("--parity-volume"),
            parity_volume.clone().into_os_string(),
            os("--destination"),
            coded_target.clone().into_os_string(),
            os("--seed-file"),
            seed_file.into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(
            coded_target
                .join("namespace")
                .join(OsString::from_vec(b"payload-\xff".to_vec()))
        )
        .unwrap(),
        b"offline payload"
    );
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    assert_eq!(
        fs::read(parity_volume.join("parity.db")).unwrap(),
        original_parity
    );
    assert!(!parity_volume.join(".mutualbackup-volume").exists());
    assert!(!catalog.join("control.key").exists());
    let external = mb_store::ControlStore::open_with_key(
        external_catalog.join("catalog.db"),
        &mb_git::catalog_key(&keys, repository_id),
    )
    .unwrap();
    let opaque_key = b"private opaque CLI key";
    let opaque_body = b"private opaque CLI payload";
    external
        .put_record("future-ownership-record-v2", opaque_key, opaque_body)
        .unwrap();
    drop(external);
    let opaque_external = external_files();
    let listed_opaque = run_output(program("mutualbackup"), &list_args, CLI_TIMEOUT).unwrap();
    assert!(
        listed_opaque.status.success(),
        "{}",
        String::from_utf8_lossy(&listed_opaque.stderr)
    );
    let opaque_inventory: mb_node::LegacyRevisionInventory =
        serde_json::from_slice(&listed_opaque.stdout).unwrap();
    assert_eq!(opaque_inventory.format_version, 18);
    assert!(!opaque_inventory.retained_history_complete);
    assert_eq!(
        opaque_inventory.local_state.unclassified_git_records.len(),
        1
    );
    let opaque = &opaque_inventory.local_state.unclassified_git_records[0];
    assert_eq!(opaque.repository_id, repository_id);
    assert_eq!(opaque.kind, "future-ownership-record-v2");
    assert_eq!(
        opaque.record_key_hash,
        hex::encode(blake3::hash(opaque_key).as_bytes())
    );
    assert_eq!(
        opaque.record_hash,
        hex::encode(blake3::hash(opaque_body).as_bytes())
    );
    assert!(!opaque.ownership_verified);
    for private in [opaque_key.as_slice(), opaque_body.as_slice()] {
        assert!(
            !String::from_utf8_lossy(&listed_opaque.stdout)
                .contains(std::str::from_utf8(private).unwrap())
        );
        assert!(!String::from_utf8_lossy(&listed_opaque.stdout).contains(&hex::encode(private)));
    }
    let opaque_destination = temp.path().join("opaque-rejected-export");
    let mut opaque_export = catalog_args.clone();
    opaque_export[destination_index] = opaque_destination.clone().into_os_string();
    for args in [&opaque_export, &peer_list_args] {
        let rejected = run_output(program("mutualbackup"), args, CLI_TIMEOUT).unwrap();
        assert!(!rejected.status.success());
        assert!(rejected.stdout.is_empty());
        assert!(String::from_utf8_lossy(&rejected.stderr).contains("unclassified Git ownership"));
    }
    assert!(!opaque_destination.exists());
    assert_eq!(external_files(), opaque_external);
    assert_eq!(fs::read(catalog.join("control.db")).unwrap(), original);
    assert!(!catalog.join("control.key").exists());
    let invalid = run_output(
        program("mutualbackup"),
        &[
            os("legacy-export"),
            os("--data-dir"),
            catalog.into_os_string(),
            os("--destination"),
            temp.path().join("invalid").into_os_string(),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("--revision-id"));
}
