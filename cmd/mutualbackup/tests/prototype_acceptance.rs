#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::UdpSocket;
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
    Node, P2pConfig, build_p2p, endpoint_record_key, recovery_bundle_key, recovery_mailbox_key,
};
use mutualbackup::{
    DaemonOptions, InitializationIntent, read_daemon_options, read_identity_manifest,
};
use uuid::Uuid;

const CLI_TIMEOUT: Duration = Duration::from_secs(30);
const MIN_BULK_TRANSFER_BYTES: u64 = 64 * 1024;

struct Daemon {
    args: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    log: PathBuf,
    child: Option<Child>,
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
            child: None,
        }
    }

    fn set_env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
        let key = os(key);
        self.environment.retain(|(candidate, _)| candidate != &key);
        self.environment.push((key, os(value)));
    }

    fn start(&mut self) {
        assert!(self.child.is_none());
        let log = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .unwrap();
        let stderr = log.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_mutualbackupd"))
            .args(&self.args)
            .envs(self.environment.iter().cloned())
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap();
        self.child = Some(child);
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
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

#[test]
fn daemon_requires_an_initialized_identity_without_creating_state() {
    let temp = tempfile::tempdir().unwrap();
    let data_dir = temp.path().join("missing-state");
    let output = Command::new(env!("CARGO_BIN_EXE_mutualbackupd"))
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

    #[cfg(debug_assertions)]
    {
        let interrupted = Command::new(env!("CARGO_BIN_EXE_mutualbackup"))
            .args(&args)
            .env("MUTUALBACKUP_TEST_FAIL_AFTER_SEED_INSTALL", "1")
            .output()
            .unwrap();
        assert!(!interrupted.status.success());
    }
    #[cfg(not(debug_assertions))]
    mutualbackup::write_seed(
        &seed_file,
        "release-resumable-initialization-recovery-string-2027!",
    )
    .unwrap();
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_mutualbackup"))
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
        env!("CARGO_BIN_EXE_mutualbackupd"),
        &[
            os("--data-dir"),
            data_dir.as_os_str().to_owned(),
            os("--seed-file"),
            seed_file.as_os_str().to_owned(),
            os("--control-socket"),
            temp.path().join("control.sock").into_os_string(),
            os("--failure-domain"),
            os("listener-readiness-test"),
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

#[test]
#[ignore = "requires an explicitly provisioned reflink test filesystem"]
fn five_daemons_recover_latest_snapshot_from_seed_and_dht() {
    let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
        .expect("the acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
    let run_root = PathBuf::from(test_root).join(format!("process-{}", Uuid::new_v4()));
    fs::create_dir_all(&run_root).unwrap();
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
        let socket = peer_dir.join("c");
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
            daemon.set_env("RUST_LOG", "warn");
            if index == 0 {
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
    let finalized = cli(&sockets[0], ["guild", "finalize"], Duration::from_secs(60));
    assert!(finalized.contains("members:     5 of 5"));

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
    cli_path(&sockets[1], ["root", "add"], &owner_one_source);
    cli_path(&sockets[2], ["root", "add"], &owner_two_source);

    let first = cli(&sockets[1], ["backup", "--wait"], Duration::from_secs(120));
    assert!(first.contains("state:      Committed"));
    let second = cli(&sockets[2], ["backup", "--wait"], Duration::from_secs(120));
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
    wait_for_backup(&sockets[1], &interrupted_revision, Duration::from_secs(180));

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
    let recovered_socket = recovered_dir.join("c");
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

    let storage_recovered_dir = run_root.join("storage-recovered");
    fs::create_dir(&storage_recovered_dir).unwrap();
    set_private(&storage_recovered_dir);
    let storage_recovered_socket = storage_recovered_dir.join("c");
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

    let relay = format!("{}/p2p/{}", transports[5], peer_ids[1]);
    let punched_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[3]);
    let fallback_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[4]);
    update_config(&recovered_config, |config| {
        config.enable_relay_server = true
    });
    update_config(&configs[0], |config| {
        config.p2p_bootstrap_addresses = vec![punched_circuit.clone(), fallback_circuit.clone()];
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_dht_maintenance = false;
    });
    update_config(&configs[3], |config| {
        config.p2p_listen_addresses = vec![transports[6].clone()];
        config.p2p_external_addresses.clear();
        config.p2p_bootstrap_addresses.clear();
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_hole_punching = true;
        config.enable_dht_maintenance = false;
    });
    update_config(&storage_recovered_config, |config| {
        config.p2p_listen_addresses.clear();
        config.p2p_external_addresses.clear();
        config.p2p_bootstrap_addresses.clear();
        config.p2p_relay_addresses = vec![relay.clone()];
        config.enable_hole_punching = false;
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
        "/p2p-circuit",
        Duration::from_secs(45),
    );
    daemons[2].start();
    daemons[3].start();
    storage_recovered_daemon.start();
    wait_for_status(&sockets[2], &mut daemons[2], Duration::from_secs(30));
    wait_for_status(&sockets[3], &mut daemons[3], Duration::from_secs(30));
    wait_for_status(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        Duration::from_secs(30),
    );
    wait_for_status_text(
        &sockets[3],
        &mut daemons[3],
        "/p2p-circuit",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        "/p2p-circuit",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &sockets[0],
        &mut daemons[0],
        "HolePunched",
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
    let topology_backup = cli(&sockets[2], ["backup", "--wait"], Duration::from_secs(180));
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
    let relay = format!("{}/p2p/{}", transports[9], peer_ids[1]);
    let coordinator_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[0]);
    let punched_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[3]);
    let fallback_circuit = format!("{relay}/p2p-circuit/p2p/{}", peer_ids[4]);
    update_config(&recovered_config, |config| {
        config.p2p_listen_addresses = vec![transports[9].clone()];
        config.p2p_external_addresses = vec![transports[9].clone()];
    });
    update_config(&configs[3], |config| {
        config.p2p_relay_addresses = vec![relay.clone()];
    });
    update_config(&storage_recovered_config, |config| {
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
        "/p2p-circuit",
        Duration::from_secs(45),
    );
    daemons[3].start();
    storage_recovered_daemon.start();
    wait_for_status_text(
        &sockets[3],
        &mut daemons[3],
        "/p2p-circuit",
        Duration::from_secs(45),
    );
    wait_for_status_text(
        &storage_recovered_socket,
        &mut storage_recovered_daemon,
        "/p2p-circuit",
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
    let relay_backup = cli(&sockets[2], ["backup", "--wait"], Duration::from_secs(180));
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
    let outsider_socket = outsider_dir.join("c");
    let outsider_config = outsider_dir.join("node.toml");
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
            p2p_listen_addresses: vec![transports[8].clone()],
            clear_p2p_listen_addresses: false,
            p2p_external_addresses: vec![transports[8].clone()],
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

fn unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn os(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_owned()
}

fn cli<const N: usize>(socket: &Path, args: [&str; N], timeout: Duration) -> String {
    let mut owned = vec![os("--socket"), socket.as_os_str().to_owned()];
    owned.extend(args.into_iter().map(os));
    run_cli(&owned, timeout).unwrap()
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
    let output = run_output(env!("CARGO_BIN_EXE_mutualbackup"), args, timeout)?;
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
    let mut child = Command::new(env!("CARGO_BIN_EXE_mutualbackup"))
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

fn run_output(program: &str, args: &[OsString], timeout: Duration) -> Result<Output, String> {
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
