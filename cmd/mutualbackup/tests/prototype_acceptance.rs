#![cfg(unix)]

use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::net::UdpSocket;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use uuid::Uuid;

const CLI_TIMEOUT: Duration = Duration::from_secs(30);

struct Daemon {
    config: PathBuf,
    log: PathBuf,
    child: Option<Child>,
}

impl Daemon {
    fn new(config: PathBuf, log: PathBuf) -> Self {
        Self {
            config,
            log,
            child: None,
        }
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
            .arg("--config")
            .arg(&self.config)
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
#[ignore = "requires an explicitly provisioned reflink test filesystem"]
fn five_daemons_recover_latest_snapshot_from_seed_and_dht() {
    let test_root = std::env::var_os("MUTUALBACKUP_REFLINK_TEST_ROOT")
        .expect("the acceptance harness must set MUTUALBACKUP_REFLINK_TEST_ROOT");
    let run_root = PathBuf::from(test_root).join(format!("process-{}", Uuid::new_v4()));
    fs::create_dir_all(&run_root).unwrap();
    let seed_dir = run_root.join("offline");
    fs::create_dir(&seed_dir).unwrap();
    set_private(&seed_dir);

    let reserved_ports = (0..6)
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
    let mut sockets = Vec::new();
    let mut configs = Vec::new();
    for index in 0..5 {
        let peer_dir = run_root.join(format!("p{index}"));
        fs::create_dir(&peer_dir).unwrap();
        set_private(&peer_dir);
        let seed = seed_dir.join(format!("p{index}.seed"));
        let config = peer_dir.join("node.toml");
        let socket = peer_dir.join("control.sock");
        let mut args = vec![
            os("--socket"),
            socket.as_os_str().to_owned(),
            os("init"),
            os("--seed-file"),
            seed.as_os_str().to_owned(),
            os("--config"),
            config.as_os_str().to_owned(),
            os("--data-dir"),
            peer_dir.join("state").into_os_string(),
            os("--failure-domain"),
            os(format!("disk-{index}")),
            os("--listen"),
            os(&transports[index]),
            os("--external-address"),
            os(&transports[index]),
        ];
        if index == 0 {
            args.push(os("--enable-relay-server"));
        } else {
            let bootstrap = format!("{}/p2p/{}", transports[0], peer_ids[0]);
            args.extend([
                os("--bootstrap"),
                os(&bootstrap),
                os("--relay"),
                os(&bootstrap),
            ]);
        }
        let output = run_cli(&args, CLI_TIMEOUT).unwrap();
        peer_ids.push(value_after(&output, "libp2p peer id: "));
        sockets.push(socket);
        configs.push(config);
    }
    drop(reserved_ports);

    let mut daemons = configs
        .iter()
        .enumerate()
        .map(|(index, config)| {
            let mut daemon = Daemon::new(config.clone(), run_root.join(format!("p{index}.log")));
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

    cli(&sockets[0], ["guild", "create"], CLI_TIMEOUT);
    for index in 1..5 {
        let invite = cli(&sockets[0], ["guild", "invite"], CLI_TIMEOUT);
        let token = value_after(&invite, "invitation: ");
        cli(
            &sockets[index],
            ["guild", "join", token.as_str()],
            CLI_TIMEOUT,
        );
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

    let expected_latest = deterministic_bytes(4 * 1024 * 1024 + 31, 41);
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
    let healthy_restore = run_root.join("healthy");
    cli_path(&sockets[1], ["snapshot", "restore"], &healthy_restore);
    assert_eq!(
        fs::read(healthy_restore.join("documents/data.bin")).unwrap(),
        expected_latest
    );

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

    let recovered_dir = run_root.join("recovered");
    fs::create_dir(&recovered_dir).unwrap();
    set_private(&recovered_dir);
    let recovered_socket = recovered_dir.join("control.sock");
    let recovered_config = recovered_dir.join("node.toml");
    let bootstrap = format!("{}/p2p/{}", transports[0], peer_ids[0]);
    run_cli(
        &[
            os("--socket"),
            recovered_socket.as_os_str().to_owned(),
            os("recover-init"),
            os("--seed-file"),
            seed_dir.join("p1.seed").into_os_string(),
            os("--config"),
            recovered_config.as_os_str().to_owned(),
            os("--data-dir"),
            recovered_dir.join("state").into_os_string(),
            os("--listen"),
            os(&transports[5]),
            os("--external-address"),
            os(&transports[5]),
            os("--bootstrap"),
            os(&bootstrap),
        ],
        CLI_TIMEOUT,
    )
    .unwrap();
    let mut recovered_daemon = Daemon::new(recovered_config, run_root.join("recovered.log"));
    recovered_daemon.start();
    wait_for_status(
        &recovered_socket,
        &mut recovered_daemon,
        Duration::from_secs(30),
    );
    let restored = run_root.join("restored-from-seed");
    cli_path_with_timeout(
        &recovered_socket,
        ["restore"],
        &restored,
        Duration::from_secs(180),
    );
    assert_eq!(
        fs::read(restored.join("documents/data.bin")).unwrap(),
        expected_latest
    );
    wait_for_recovery_ready(
        &recovered_socket,
        &mut recovered_daemon,
        Duration::from_secs(90),
    );

    recovered_daemon.stop();
    for daemon in &mut daemons {
        daemon.stop();
    }
    fs::remove_dir_all(&run_root).unwrap();
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

fn run_output(program: &str, args: &[OsString], timeout: Duration) -> Result<Output, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| error.to_string())?;
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
