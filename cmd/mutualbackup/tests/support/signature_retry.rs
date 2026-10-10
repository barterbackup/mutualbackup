//! Release-build network fault coverage. No daemon interruption hooks are used.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use mb_core::{
    CodingReplayFinding, GuildEvent, KeyMaterial, MemberSignature, NodeId, QuorumGuildEvent,
    WrappedDatabaseKey, decode_canonical, decode_coding_transcript_bounded,
    replay_coding_transcript, verify_guild_event_signature,
};
use mb_store::ControlStore;

use super::{
    Daemon, NetworkNamespace, os, program, required_test_program, run_output, topology_backup_cli,
    wait_for_status,
};

struct LogCursor {
    path: PathBuf,
    offset: u64,
    pending: Vec<u8>,
}

impl LogCursor {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_owned(),
            offset: path.metadata().unwrap().len(),
            pending: Vec::new(),
        }
    }

    fn lines(&mut self) -> Vec<String> {
        let mut file = File::open(&self.path).unwrap();
        assert!(file.metadata().unwrap().len() >= self.offset);
        file.seek(SeekFrom::Start(self.offset)).unwrap();
        let start = self.pending.len();
        file.take(256 * 1024)
            .read_to_end(&mut self.pending)
            .unwrap();
        self.offset += (self.pending.len() - start) as u64;
        let complete = self.pending.iter().rposition(|byte| *byte == b'\n');
        let lines = complete.map_or_else(Vec::new, |end| {
            self.pending
                .drain(..=end)
                .collect::<Vec<_>>()
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .map(|line| plain_log_line(&String::from_utf8_lossy(line)))
                .collect()
        });
        assert!(self.pending.len() <= 64 * 1024, "unbounded daemon log line");
        lines
    }
}

fn plain_log_line(line: &str) -> String {
    let mut escaped = false;
    let mut csi = false;
    line.chars()
        .filter(|character| {
            if escaped {
                escaped = false;
                csi = *character == '[';
                return false;
            }
            if csi {
                if ('@'..='~').contains(character) {
                    csi = false;
                }
                return false;
            }
            if *character == '\u{1b}' {
                escaped = true;
                return false;
            }
            true
        })
        .collect()
}

fn field<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let prefix = format!("{name}=");
    let start = line.find(&prefix)? + prefix.len();
    let token = line[start..].split_whitespace().next()?;
    let token = token.trim_end_matches(['}', ':']);
    Some(
        token
            .strip_prefix("Some(\"")
            .and_then(|value| value.strip_suffix("\")"))
            .unwrap_or_else(|| token.trim_matches('"')),
    )
}

#[derive(Debug)]
struct SignatureAttempt {
    request_id: String,
    guild_id: String,
    sequence: u64,
    event_hash: String,
    group_id: String,
    attempt_id: String,
    signer: NodeId,
    dispatched_line: String,
}

impl SignatureAttempt {
    fn dispatched(line: String, signer: NodeId) -> Option<Self> {
        if !line.contains("guild signature request progress")
            || field(&line, "kind") != Some("coding-add")
            || field(&line, "stage") != Some("dispatched")
            || field(&line, "signer") != Some(signer.to_string().as_str())
            || !line.contains("RelayFallback")
        {
            return None;
        }
        let hex_field = |name, length| {
            let value = field(&line, name)?;
            (value.len() == length && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
                .then(|| value.to_owned())
        };
        Some(Self {
            request_id: hex_field("request_id", 32)?,
            guild_id: hex_field("guild_id", 64)?,
            sequence: field(&line, "sequence")?.parse().ok()?,
            event_hash: hex_field("event_hash", 64)?,
            group_id: hex_field("group_id", 64)?,
            attempt_id: hex_field("attempt_id", 32)?,
            signer,
            dispatched_line: line,
        })
    }

    fn matches(&self, line: &str) -> bool {
        field(line, "guild_id") == Some(self.guild_id.as_str())
            && field(line, "event_hash") == Some(self.event_hash.as_str())
            && field(line, "sequence").and_then(|value| value.parse().ok()) == Some(self.sequence)
    }
}

/// The disposable namespace belongs to this fixture. Every failure restores
/// its link and removes only the netem root installed by this guard.
struct SignerPartition {
    namespace: NetworkNamespace,
    tc: PathBuf,
    default_gateway: String,
    original_routes: serde_json::Value,
    delayed: bool,
    down: bool,
}

impl SignerPartition {
    fn new(namespace: NetworkNamespace) -> Self {
        let mut guard = Self {
            namespace,
            tc: required_test_program("MUTUALBACKUP_TEST_TC"),
            default_gateway: String::new(),
            original_routes: serde_json::Value::Null,
            delayed: false,
            down: false,
        };
        let output = guard.tc(&["-j", "qdisc", "show", "dev", "eth0"]).unwrap();
        let qdiscs: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            qdiscs
                .as_array()
                .unwrap()
                .iter()
                .all(|record| { record["kind"] == "noqueue" || record["root"] != true })
        );
        guard.original_routes = guard.routes();
        let defaults = guard
            .original_routes
            .as_array()
            .unwrap()
            .iter()
            .filter(|route| route["dst"] == "default")
            .collect::<Vec<_>>();
        assert_eq!(defaults.len(), 1);
        let gateway = defaults[0]["gateway"].as_str().unwrap();
        gateway.parse::<std::net::Ipv4Addr>().unwrap();
        guard.default_gateway = gateway.to_owned();
        // Delayed egress gives the monitor time to observe the real dispatch
        // before a response can escape. Link-down below flushes that queue.
        guard.delayed = true;
        guard
            .tc(&[
                "qdisc", "add", "dev", "eth0", "root", "netem", "delay", "2s",
            ])
            .unwrap();
        guard
    }

    fn command(&self, program: &Path, arguments: &[&str]) -> Result<std::process::Output, String> {
        let mut args = vec![
            os("-n"),
            self.namespace.ip.as_os_str().to_owned(),
            os("netns"),
            os("exec"),
            self.namespace.name.clone(),
            program.as_os_str().to_owned(),
        ];
        args.extend(arguments.iter().map(os));
        let output = run_output(&self.namespace.sudo, &args, Duration::from_secs(10))?;
        if !output.status.success() {
            return Err(format!(
                "namespace fault command {arguments:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(output)
    }

    fn tc(&self, arguments: &[&str]) -> Result<std::process::Output, String> {
        self.command(&self.tc, arguments)
    }

    fn routes(&self) -> serde_json::Value {
        let output = self
            .command(
                &self.namespace.ip,
                &["-j", "-4", "route", "show", "dev", "eth0"],
            )
            .unwrap();
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn restore_link(&self) -> Result<(), String> {
        self.command(&self.namespace.ip, &["link", "set", "eth0", "up"])?;
        // Linux removes the static default route when the link goes down.
        // Link-up recreates the connected route, but cannot restore this one.
        self.command(
            &self.namespace.ip,
            &[
                "route",
                "replace",
                "default",
                "via",
                &self.default_gateway,
                "dev",
                "eth0",
            ],
        )?;
        Ok(())
    }

    fn partition(&mut self) {
        self.down = true;
        self.command(&self.namespace.ip, &["link", "set", "eth0", "down"])
            .unwrap();
        self.tc(&["qdisc", "del", "dev", "eth0", "root"]).unwrap();
        self.delayed = false;
    }

    fn heal(&mut self) {
        if self.delayed {
            self.tc(&["qdisc", "del", "dev", "eth0", "root"]).unwrap();
            self.delayed = false;
        }
        if self.down {
            self.restore_link().unwrap();
            self.down = false;
        }
        assert_eq!(
            self.routes(),
            self.original_routes,
            "the signer must regain its original IPv4 routes"
        );
    }
}

impl Drop for SignerPartition {
    fn drop(&mut self) {
        if self.delayed {
            let _ = self.tc(&["qdisc", "del", "dev", "eth0", "root"]);
        }
        if self.down {
            let _ = self.restore_link();
        }
    }
}

struct PendingBackup(Option<Child>);

impl Drop for PendingBackup {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(super) fn backup_after_relay_signature_interruption(
    sockets: (&Path, &Path),
    coordinator: &mut Daemon,
    signer: &mut Daemon,
    signer_id: NodeId,
    members: &[NodeId],
    timeout: Duration,
    run_root: &Path,
) -> String {
    let (owner_socket, coordinator_socket) = sockets;
    let mut partition = SignerPartition::new(
        signer
            .network_namespace
            .clone()
            .expect("signature interruption requires the isolated network harness"),
    );
    let mut cursor = LogCursor::new(&coordinator.log);
    let stdout = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(run_root.join("interrupted-backup.stdout"))
        .unwrap();
    let stderr = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(run_root.join("interrupted-backup.stderr"))
        .unwrap();
    let mut pending = PendingBackup(Some(
        Command::new(program("mutualbackup"))
            .args([os("--socket"), os(owner_socket), os("backup"), os("--wait")])
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .unwrap(),
    ));
    let deadline = Instant::now() + timeout;
    let (attempt, mut backlog) = loop {
        coordinator.assert_running();
        signer.assert_running();
        let lines = cursor.lines();
        if let Some(attempt) = lines
            .iter()
            .find_map(|line| SignatureAttempt::dispatched(line.clone(), signer_id))
        {
            break (attempt, lines);
        }
        assert!(
            Instant::now() < deadline,
            "no relay coding signature was dispatched"
        );
        assert!(pending.0.as_mut().unwrap().try_wait().unwrap().is_none());
        thread::sleep(Duration::from_millis(5));
    };
    partition.partition();
    let partial = loop {
        coordinator.assert_running();
        let lines = std::mem::take(&mut backlog)
            .into_iter()
            .chain(cursor.lines())
            .collect::<Vec<_>>();
        assert!(
            !lines.iter().any(|line| {
                attempt.matches(line)
                    && line.contains("persisted verified partial guild signatures")
                    && field(line, "signatures") == Some("5")
            }),
            "the signer replied before the partition took effect"
        );
        let found = lines.into_iter().find(|line| {
            attempt.matches(line)
                && line.contains("persisted verified partial guild signatures")
                && field(line, "signatures") == Some("4")
        });
        if let Some(line) = found {
            assert!(line.contains(&format!("{:?}", signer_id)));
            break line;
        }
        assert!(
            Instant::now() < deadline,
            "partition never produced four durable signatures"
        );
        thread::sleep(Duration::from_millis(10));
    };
    drop(pending);
    // Abrupt retirement exercises the durable retry, including the SQL WAL.
    let mut child = coordinator.child.take().unwrap();
    coordinator
        .network_namespace
        .as_ref()
        .unwrap()
        .signal_processes(libc::SIGKILL);
    let _ = child.kill();
    child.wait().unwrap();
    let (database_key, event, activation_was_completed) =
        verify_stopped_partial_catalog(run_root, &attempt, members);
    let mut resumed = LogCursor::new(&coordinator.log);
    coordinator.start();
    wait_for_status(coordinator_socket, coordinator, Duration::from_secs(45));
    partition.heal();
    let result = topology_backup_cli(owner_socket, timeout, &[&coordinator.log, &signer.log]);
    assert!(result.contains("state:      Committed"));
    verify_installed_event(run_root, &database_key, &event, members);
    let mut reused = false;
    let mut retried = false;
    let end = resumed.path.metadata().unwrap().len();
    while resumed.offset < end {
        for line in resumed.lines() {
            if !attempt.matches(&line) {
                continue;
            }
            reused |= line.contains("reusing durable guild event signature");
            if line.contains("guild signature request progress")
                && field(&line, "stage") == Some("dispatched")
            {
                assert_eq!(field(&line, "signer"), Some(signer_id.to_string().as_str()));
                assert_eq!(
                    field(&line, "attempt_id"),
                    Some(attempt.attempt_id.as_str())
                );
                retried = true;
            }
        }
    }
    assert!(
        reused && retried,
        "the exact interrupted event did not resume after restart"
    );
    println!(
        "SIGNATURE_RETRY_EVIDENCE {}",
        serde_json::json!({
            "request_id": attempt.request_id,
            "guild_id": attempt.guild_id,
            "sequence": attempt.sequence,
            "event_hash": attempt.event_hash,
            "group_id": attempt.group_id,
            "attempt_id": attempt.attempt_id,
            "missing_signer": attempt.signer.to_string(),
            "dispatch": attempt.dispatched_line,
            "durable_partial": partial,
            "coordinator_crashed": true,
            "network_routes_restored": true,
            "four_original_signatures_verified_from_stopped_catalog": true,
            "original_transcript_verified": true,
            "activation_was_completed_before_crash": activation_was_completed,
            "exact_event_installed_with_all_five_original_signers": true,
            "stopped_inputs_unchanged": true,
            "proof_uses_separate_complete_db_wal_copy": true,
            "same_event_resumed": true,
            "committed": true,
        })
    );
    result
}

// Original private record layouts, intentionally decoded independently of Node
// startup so validation cannot replay, recover, or rewrite the stopped catalog.
#[derive(serde::Deserialize)]
struct OriginalPartialSignatures {
    format_version: u16,
    event: GuildEvent,
    signatures: Vec<MemberSignature>,
}

#[derive(serde::Deserialize)]
struct OriginalSignatureLock {
    format_version: u16,
    event_hash: [u8; 32],
    event: GuildEvent,
    signature: MemberSignature,
}

#[derive(serde::Deserialize)]
struct OriginalActivationJob {
    format_version: u16,
    transcript: mb_core::SignedRecord<mb_core::CodingVerificationTranscript>,
    complete: bool,
    error: Option<String>,
}

fn verify_stopped_partial_catalog(
    root: &Path,
    attempt: &SignatureAttempt,
    members: &[NodeId],
) -> ([u8; 32], GuildEvent, bool) {
    let mut expected = members.to_vec();
    expected.sort();
    expected.dedup();
    assert_eq!(expected.len(), 5);
    assert!(expected.contains(&attempt.signer));
    expected.retain(|id| id != &attempt.signer);
    let seed = mutualbackup::read_seed(&root.join("offline/p0.seed")).unwrap();
    let keys = KeyMaterial::from_seed(&seed);
    let data = root.join("p0/state");
    let mut bytes = Vec::new();
    File::open(data.join("control.key"))
        .unwrap()
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= 64 * 1024);
    let envelope: WrappedDatabaseKey = decode_canonical(&bytes).unwrap();
    let wrapped = keys
        .unwrap_database_key(b"control.db/v2", &envelope)
        .unwrap();
    let mut record_id = [0_u8; 40];
    record_id[..32].copy_from_slice(&hex::decode(&attempt.guild_id).unwrap());
    record_id[32..].copy_from_slice(&attempt.sequence.to_be_bytes());
    // A crashed writer leaves SHM without its dead-man lock. Inspect a
    // complete, separately copied DB/WAL pair with the private WAL reader;
    // never initialize or remove the original shared-memory file.
    let proof = root.join("signature-catalog-proof");
    fs::create_dir(&proof).unwrap();
    fs::set_permissions(&proof, fs::Permissions::from_mode(0o700)).unwrap();
    let original = [
        "control.db",
        "control.db-wal",
        "control.db-shm",
        "control.key",
    ]
    .into_iter()
    .filter_map(|name| {
        let path = data.join(name);
        path.exists().then(|| {
            let version = file_fingerprint(&path);
            (path, version)
        })
    })
    .collect::<Vec<_>>();
    for name in ["control.db", "control.db-wal"] {
        let source = data.join(name);
        if source.exists() {
            fs::copy(source, proof.join(name)).unwrap();
        }
    }
    assert!(!data.join("control.db-journal").exists());
    let (event, activation_was_completed) = ControlStore::with_preserved_read_only_snapshot(
        proof.join("control.db"),
        &[wrapped, keys.database_key(b"control.db")],
        |control| {
            let bytes = control
                .get_record_bounded(
                    "guild-event-partial-signatures",
                    &record_id,
                    mb_core::GUILD_EVENT_BYTES + 4096,
                )?
                .expect("the interrupted event must retain durable partial signatures");
            let partial: OriginalPartialSignatures = decode_canonical(&bytes)?;
            assert_eq!(partial.format_version, 1);
            assert_eq!(partial.event.sequence, attempt.sequence);
            assert_eq!(hex::encode(partial.event.guild_id), attempt.guild_id);
            assert_eq!(hex::encode(partial.event.hash()?), attempt.event_hash);
            assert_eq!(partial.signatures.len(), 4);
            assert_eq!(
                partial
                    .signatures
                    .iter()
                    .map(|signature| signature.signer)
                    .collect::<Vec<_>>(),
                expected,
            );
            let (group, bound_hash) = partial
                .event
                .kind
                .coding_group_add()
                .expect("the interrupted event must add its original coding group");
            assert_eq!(hex::encode(group.id), attempt.group_id);
            let bytes = control
                .get_record_bounded(
                    "coding-group-transcript",
                    &group.id,
                    mb_core::CATALOG_CODING_TRANSCRIPT_BYTES,
                )?
                .expect("the original coding witness must survive interruption");
            let transcript = decode_coding_transcript_bounded(&bytes)?;
            assert_eq!(transcript.value.manifest.value.group, *group);
            assert_eq!(
                hex::encode(transcript.value.plan.value.attempt_id),
                attempt.attempt_id
            );
            assert_eq!(bound_hash, Some(*blake3::hash(&bytes).as_bytes()));
            assert_eq!(
                replay_coding_transcript(&transcript)?,
                CodingReplayFinding::Verified
            );
            let bytes = control
                .get_record_bounded(
                    "coding-activation-job",
                    &transcript.value.plan.value.attempt_id,
                    mb_core::CATALOG_CODING_TRANSCRIPT_BYTES + 8192,
                )?
                .expect("the original activation owner must survive interruption");
            let activation: OriginalActivationJob = decode_canonical(&bytes)?;
            assert_eq!(activation.format_version, 1);
            assert_eq!(activation.transcript, transcript);
            assert!(
                activation
                    .error
                    .as_ref()
                    .is_none_or(|error| error.len() <= 4096)
            );
            let mut previous = None;
            for signature in &partial.signatures {
                assert_ne!(signature.signer, attempt.signer);
                assert!(previous.is_none_or(|signer| signer < signature.signer));
                verify_guild_event_signature(&partial.event, signature)?;
                previous = Some(signature.signer);
            }
            let bytes = control
                .get_record_bounded(
                    "guild-event-signature-lock",
                    &attempt.sequence.to_be_bytes(),
                    mb_core::GUILD_EVENT_BYTES + 256,
                )?
                .expect("the coordinator must retain the original proposal lock");
            let lock: OriginalSignatureLock = decode_canonical(&bytes)?;
            assert_eq!(lock.format_version, 1);
            assert_eq!(lock.event, partial.event);
            assert_eq!(hex::encode(lock.event_hash), attempt.event_hash);
            assert_eq!(lock.signature.signer, keys.node_id());
            assert!(partial.signatures.contains(&lock.signature));
            verify_guild_event_signature(&lock.event, &lock.signature)?;
            Ok((partial.event, activation.complete))
        },
    )
    .unwrap();
    for (path, before) in original {
        assert_eq!(file_fingerprint(&path), before, "stopped input changed");
    }
    fs::remove_dir_all(proof).unwrap();
    (wrapped, event, activation_was_completed)
}

fn verify_installed_event(root: &Path, key: &[u8; 32], event: &GuildEvent, members: &[NodeId]) {
    let control =
        ControlStore::open_existing_read_only_with_key(root.join("p0/state/control.db"), key)
            .unwrap();
    control
        .with_read_only_snapshot(|| {
            let bytes = control
                .get_record_bounded(
                    "guild-event",
                    &event.sequence.to_be_bytes(),
                    mb_core::GUILD_EVENT_BYTES,
                )?
                .expect("the exact interrupted event must be installed after restart");
            let certificate = QuorumGuildEvent::decode_bounded(&bytes)?;
            assert_eq!(certificate.event, *event);
            let mut expected = members.to_vec();
            expected.sort();
            assert_eq!(
                certificate
                    .signatures
                    .iter()
                    .map(|signature| signature.signer)
                    .collect::<Vec<_>>(),
                expected
            );
            for signature in &certificate.signatures {
                verify_guild_event_signature(event, signature)?;
            }
            Ok(())
        })
        .unwrap();
}

fn file_fingerprint(path: &Path) -> (u64, u64, u64, u32, i64, i64, i64, i64, [u8; 32]) {
    let mut file = File::open(path).unwrap();
    let metadata = file.metadata().unwrap();
    assert!(metadata.is_file());
    let mut hash = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    (
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        *hash.finalize().as_bytes(),
    )
}
