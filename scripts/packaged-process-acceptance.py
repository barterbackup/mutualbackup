#!/usr/bin/env python3
"""Run process/recovery fixtures against one installed release candidate.

The caller provisions and removes the disposable Btrfs filesystem. Cargo builds
the workspace test configuration; application processes use MUTUALBACKUP_TEST_BIN_DIR.
The manifest records source, wrappers, underlying payloads and driver hashes,
checks they stay unchanged, and never reports an omitted scenario as passing.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import time

PROGRAMS = ("mutualbackup", "mutualbackupd", "mutualgit", "git-remote-mutualbackup")
WORKSPACE = Path(__file__).resolve().parent.parent
SIGNATURE_RETRY_CASE = (
    "five_daemons_resume_relay_signature_after_partition_and_coordinator_crash"
)
SIGNATURE_RETRY_CHECKS = (
    "four_original_signatures_verified_from_stopped_catalog",
    "coordinator_crashed",
    "same_event_resumed",
    "committed",
    "stopped_inputs_unchanged",
    "proof_uses_separate_complete_db_wal_copy",
    "original_transcript_verified",
    "exact_event_installed_with_all_five_original_signers",
    "network_routes_restored",
)


def executable(path):
    if not path.is_file() or not os.access(path, os.X_OK):
        raise RuntimeError(f"required executable is unavailable: {path}")
    return path


def candidate_programs(directory):
    if not directory.is_absolute() or not directory.is_dir():
        raise RuntimeError("--bin-dir must name an absolute installed bin directory")
    programs = [executable(directory / name) for name in PROGRAMS]
    # Nix runtime wrappers execute these separate static payloads. Hash both.
    programs.extend(
        executable(directory / f".{name}-wrapped")
        for name in PROGRAMS
        if (directory / f".{name}-wrapped").exists()
        or (directory / f".{name}-wrapped").is_symlink()
    )
    return programs


def hashes(paths):
    result = {}
    for path in paths:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        result[str(path)] = {
            "resolved": str(path.resolve()),
            "sha256": digest.hexdigest(),
            "mode": path.stat().st_mode & 0o7777,
        }
    return result


def git(*arguments):
    return subprocess.check_output(["git", *arguments], cwd=WORKSPACE)


def clean_source():
    if git("status", "--porcelain", "--untracked-files=no").strip():
        raise RuntimeError(
            "artifact qualification requires a committed clean source tree"
        )
    for raw in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if not raw:
            continue
        path = WORKSPACE / os.fsdecode(raw)
        if not (
            path.parent == WORKSPACE
            and path.name.startswith("result-")
            and path.is_symlink()
            and path.resolve().is_relative_to("/nix/store")
        ):
            raise RuntimeError(f"untracked input prevents source qualification: {path}")
    return [
        WORKSPACE / os.fsdecode(path)
        for path in git("ls-files", "-z").split(b"\0")
        if path
    ]


def run(command, log, environment, timeout):
    """Bound a whole process group, including children of a timed-out driver."""
    with log.open("wb") as output:
        process = subprocess.Popen(
            [str(part) for part in command],
            cwd=WORKSPACE,
            env=environment,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout)
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                pass
            # The leader may have exited while one of its children ignored
            # SIGTERM. Retire the remaining group as well.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
            raise


def test_drivers(log):
    drivers = {}
    with log.open() as messages:
        for line in messages:
            try:
                message = json.loads(line)
            except json.JSONDecodeError:
                continue
            target = message.get("target", {})
            if (
                message.get("reason") == "compiler-artifact"
                and "test" in target.get("kind", [])
                and target.get("name") in ("prototype_acceptance", "git_remote_helper")
                and message.get("profile", {}).get("test")
            ):
                name = target["name"]
                path = executable(Path(message["executable"]).resolve())
                if name in drivers and drivers[name] != path:
                    raise RuntimeError(f"ambiguous test driver: {name}")
                drivers[name] = path
    if set(drivers) != {"prototype_acceptance", "git_remote_helper"}:
        raise RuntimeError("Cargo did not provide both required process test drivers")
    return drivers


def topology_resources():
    iptables_save = shutil.which("iptables-save")
    ip = shutil.which("ip")
    if iptables_save is None or ip is None:
        raise RuntimeError(
            "iptables-save and ip are required for topology cleanup verification"
        )
    rules = subprocess.check_output(["sudo", "-n", iptables_save], text=True)
    return {
        "namespaces": sorted(
            subprocess.check_output(
                ["sudo", "-n", ip, "netns", "list"], text=True
            ).splitlines()
        ),
        "fixture_firewall_rules": [
            line
            for line in rules.splitlines()
            if re.search(r"\bMB[FRP][0-9a-f]{7}\b", line)
        ],
        "forwarding": Path("/proc/sys/net/ipv4/ip_forward").read_text(),
    }


def driver_tests(driver, ignored=False):
    arguments = [str(driver), "--list"]
    if ignored:
        arguments.append("--ignored")
    output = subprocess.check_output(arguments, text=True, timeout=30)
    return {
        line.removesuffix(": test")
        for line in output.splitlines()
        if line.endswith(": test")
    }


def test_counts(log):
    with log.open() as output:
        matches = [
            match.groups()
            for line in output
            if (
                match := re.fullmatch(
                    r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;.*\n?",
                    line,
                )
            )
        ]
    if len(matches) != 1:
        raise RuntimeError(f"expected one positive libtest result in {log}")
    return tuple(int(count) for count in matches[0])


def require_test_counts(log, expected):
    counts = test_counts(log)
    if counts != expected or counts[0] == 0:
        raise RuntimeError(f"required tests were omitted or ignored: {log}")
    return counts


def require_signature_retry(log, previous_requests):
    """Require the real fixture's original-signature proof for a fresh attempt."""
    require_test_counts(log, (1, 0, 0))

    def unique_object(pairs):
        record = {}
        for key, value in pairs:
            if key in record:
                raise RuntimeError(f"duplicate signature-retry proof field in {log}")
            record[key] = value
        return record

    rows = []
    with log.open() as output:
        while line := output.readline(64 * 1024 + 1):
            if len(line) > 64 * 1024:
                raise RuntimeError(f"oversized signature-retry diagnostic in {log}")
            if line.startswith("SIGNATURE_RETRY_EVIDENCE "):
                try:
                    rows.append(
                        json.loads(
                            line.removeprefix("SIGNATURE_RETRY_EVIDENCE "),
                            object_pairs_hook=unique_object,
                        )
                    )
                except (ValueError, RecursionError) as error:
                    raise RuntimeError(
                        f"invalid signature-retry proof in {log}"
                    ) from error
    if len(rows) != 1 or not isinstance(rows[0], dict):
        raise RuntimeError(f"expected one signature-retry proof in {log}")
    proof = rows[0]
    if any(proof.get(check) is not True for check in SIGNATURE_RETRY_CHECKS):
        raise RuntimeError(f"incomplete signature-retry proof in {log}")
    if type(proof.get("activation_was_completed_before_crash")) is not bool:
        raise RuntimeError(f"missing stopped activation status in {log}")
    for key, length in {
        "request_id": 32,
        "guild_id": 64,
        "event_hash": 64,
        "group_id": 64,
        "attempt_id": 32,
        "missing_signer": 64,
    }.items():
        value = proof.get(key)
        if (
            not isinstance(value, str)
            or re.fullmatch(f"[0-9a-f]{{{length}}}", value) is None
        ):
            raise RuntimeError(f"invalid signature-retry {key} in {log}")
    sequence = proof.get("sequence")
    if type(sequence) is not int or not 0 < sequence < 2**64:
        raise RuntimeError(f"invalid signature-retry sequence in {log}")
    if proof["request_id"] in previous_requests:
        raise RuntimeError(f"repeated signature-retry request in {log}")
    dispatch = proof.get("dispatch")
    partial = proof.get("durable_partial")
    if not isinstance(dispatch, str) or not isinstance(partial, str):
        raise RuntimeError(f"missing correlated signature-retry traces in {log}")

    def field(trace, name, value):
        pattern = r"\b" + name + "=" + re.escape(value) + r"(?=$|[ ,}])"
        if re.search(pattern, trace) is None:
            raise RuntimeError(f"uncorrelated signature-retry {name} in {log}")

    field(dispatch, "request_id", proof["request_id"])
    field(dispatch, "guild_id", proof["guild_id"])
    field(dispatch, "sequence", str(sequence))
    for key in ("event_hash", "group_id", "attempt_id"):
        field(dispatch, key, "Some(" + json.dumps(proof[key]) + ")")
    field(dispatch, "signer", "Some(" + json.dumps(proof["missing_signer"]) + ")")
    field(dispatch, "kind", '"coding-add"')
    field(dispatch, "stage", '"dispatched"')
    field(dispatch, "path", "Some(RelayFallback)")
    field(partial, "guild_id", proof["guild_id"])
    field(partial, "sequence", str(sequence))
    field(partial, "event_hash", proof["event_hash"])
    field(partial, "signatures", "4")
    missing = re.search(r"\bmissing_signers=\[NodeId\(\[([0-9, ]+)\]\)\]", partial)
    expected = list(bytes.fromhex(proof["missing_signer"]))
    try:
        actual = [] if missing is None else [int(value.strip()) for value in missing[1].split(",")]
    except ValueError as error:
        raise RuntimeError(f"invalid missing signature in {log}") from error
    if actual != expected:
        raise RuntimeError(f"uncorrelated missing signature in {log}")
    return proof


def qualify_signature_retries(step, output_dir, reflink_root, before_resources, save):
    proofs = {}
    for number in (1, 2):
        name = f"relay-signature-retry-{number}"
        record = step(
            name,
            [
                "bash",
                WORKSPACE / "scripts/network-smoke.sh",
                reflink_root,
                SIGNATURE_RETRY_CASE,
            ],
            3000,
            (1, 0, 0),
        )
        record["signature_retry"] = require_signature_retry(
            output_dir / f"{name}.log", {proof["request_id"] for proof in proofs.values()}
        )
        record["topology_cleanup_verified"] = topology_resources() == before_resources
        save()
        if not record["topology_cleanup_verified"]:
            raise RuntimeError(f"{name} did not restore network resources")
        proofs[name] = record["signature_retry"]
    return proofs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--reflink-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    programs = candidate_programs(args.bin_dir)
    if not args.output_dir.is_absolute() or args.output_dir.resolve().is_relative_to(
        WORKSPACE
    ):
        raise RuntimeError(
            "--output-dir must name a new absolute artifact directory outside the source tree"
        )
    sources = clean_source()
    if not args.reflink_root.is_absolute() or not args.reflink_root.is_dir():
        raise RuntimeError(
            "--reflink-root must name a provisioned absolute Btrfs directory"
        )
    filesystem = subprocess.check_output(
        ["findmnt", "-n", "-T", str(args.reflink_root), "-o", "FSTYPE"], text=True
    ).strip()
    if filesystem != "btrfs":
        raise RuntimeError(f"Btrfs qualification cannot use filesystem {filesystem!r}")
    before_resources = topology_resources()
    os.umask(0o077)
    args.output_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    environment = os.environ.copy()
    environment.update(
        {
            "MUTUALBACKUP_TEST_BIN_DIR": str(args.bin_dir),
            "MUTUALBACKUP_REFLINK_TEST_ROOT": str(args.reflink_root),
            "MUTUALBACKUP_TEST_LOG_ROOT": str(args.output_dir / "peer-logs"),
            "MUTUALBACKUP_TEST_TOPOLOGY_BACKUP_TIMEOUT_SECONDS": "900",
        }
    )
    evidence = {
        "commit": git("rev-parse", "HEAD").decode().strip(),
        "scope": [
            "ordinary-linux-process",
            "raw-unix-paths",
            "stock-git-bridge",
            "five-daemon-topology-seed-recovery",
            "repeated-relay-signer-partition-coordinator-crash",
        ],
        "filesystem_cleanup": "verified separately by the provisioning caller",
        "debug_only_failpoints": "not exercised by installed programs; source debug fixtures qualify them separately",
        "source": hashes(sources),
        "candidate": hashes(programs),
        "drivers": {},
        "steps": [],
        "qualified": False,
    }
    manifest = args.output_dir / "qualification.json"

    def save():
        manifest.write_text(json.dumps(evidence, indent=2) + "\n")

    def step(name, command, timeout, expected_counts=None):
        record = {"name": name, "command": [str(part) for part in command]}
        if expected_counts is not None:
            record["expected_test_counts"] = expected_counts
        evidence["steps"].append(record)
        save()
        started = time.monotonic()
        try:
            record["return_code"] = run(
                command, args.output_dir / f"{name}.log", environment, timeout
            )
            if record["return_code"] == 0 and expected_counts is not None:
                record["test_counts"] = require_test_counts(
                    args.output_dir / f"{name}.log", expected_counts
                )
        finally:
            record["seconds"] = time.monotonic() - started
            save()
        if record["return_code"]:
            raise RuntimeError(
                f"{name} failed; see {args.output_dir / (name + '.log')}"
            )
        return record

    save()
    try:
        step(
            "build-drivers",
            [
                "cargo",
                "test",
                "--locked",
                "--workspace",
                "--all-targets",
                "--no-run",
                "--message-format=json",
            ],
            3600,
        )
        drivers = test_drivers(args.output_dir / "build-drivers.log")
        evidence["drivers"] = hashes(drivers.values())
        all_process = driver_tests(drivers["prototype_acceptance"])
        ignored_process = driver_tests(drivers["prototype_acceptance"], ignored=True)
        ordinary_process = all_process - ignored_process
        required_process = {
            "raw_unix_paths_survive_cli_daemon_and_git_checkout",
            "five_daemons_recover_latest_snapshot_from_seed_and_dht",
            SIGNATURE_RETRY_CASE,
        }
        bridge = "stock_git_fetches_and_pushes_through_native_anchors"
        if (
            not ordinary_process
            or not required_process.issubset(ignored_process)
            or bridge not in driver_tests(drivers["git_remote_helper"], ignored=True)
        ):
            raise RuntimeError(
                "required process/recovery cases are missing from the compiled drivers"
            )
        evidence["ordinary_process_tests"] = sorted(ordinary_process)
        evidence["required_provisioned_tests"] = sorted(required_process | {bridge})
        save()
        environment["MUTUALBACKUP_TEST_PROCESS_BINARY"] = str(
            drivers["prototype_acceptance"]
        )
        step(
            "ordinary-process",
            [drivers["prototype_acceptance"], "--test-threads=4"],
            1800,
            (len(ordinary_process), 0, len(ignored_process)),
        )
        step(
            "raw-paths",
            [
                drivers["prototype_acceptance"],
                "raw_unix_paths_survive_cli_daemon_and_git_checkout",
                "--ignored",
                "--exact",
                "--nocapture",
            ],
            600,
            (1, 0, 0),
        )
        step(
            "stock-git-bridge",
            [
                drivers["git_remote_helper"],
                bridge,
                "--ignored",
                "--exact",
                "--nocapture",
            ],
            600,
            (1, 0, 0),
        )
        step(
            "topology-seed-recovery",
            ["bash", WORKSPACE / "scripts/network-smoke.sh", args.reflink_root],
            5400,
            (1, 0, 0),
        )
        evidence["signature_retry_proofs"] = qualify_signature_retries(
            step, args.output_dir, args.reflink_root, before_resources, save
        )
        evidence["qualified"] = True
    finally:
        verifications = {
            "source_unchanged": lambda: hashes(clean_source()) == evidence["source"]
            and git("rev-parse", "HEAD").decode().strip() == evidence["commit"],
            "candidate_unchanged": lambda: hashes(candidate_programs(args.bin_dir))
            == evidence["candidate"],
            "drivers_unchanged": lambda: hashes(
                Path(path) for path in evidence["drivers"]
            )
            == evidence["drivers"],
            "topology_cleanup_verified": lambda: topology_resources()
            == before_resources,
        }
        for name, verify in verifications.items():
            try:
                evidence[name] = verify()
            except Exception as error:
                evidence[name] = False
                evidence.setdefault("verification_errors", {})[name] = str(error)
        checks = (
            "source_unchanged",
            "candidate_unchanged",
            "drivers_unchanged",
            "topology_cleanup_verified",
        )
        evidence["qualified"] = evidence["qualified"] and all(
            evidence[name] for name in checks
        )
        save()
        if not all(evidence[name] for name in checks):
            raise RuntimeError(
                f"qualification identity or topology cleanup failed; see {manifest}"
            )
    print(
        f"Installed process, raw-path, stock-Git, topology/seed-recovery and repeated signature-retry qualification passed: {manifest}"
    )


if __name__ == "__main__":
    main()
