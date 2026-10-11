#!/usr/bin/env python3
"""Negative checks for the installed-artifact qualification boundary."""

import importlib.util
import json
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location(
    "qualification", Path(__file__).with_name("packaged-process-acceptance.py")
)
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)


class QualificationTests(unittest.TestCase):
    @staticmethod
    def signature_proof(request_id="11" * 16):
        proof = dict.fromkeys(QUALIFICATION.SIGNATURE_RETRY_CHECKS, True)
        proof.update(
            request_id=request_id,
            guild_id="22" * 32,
            event_hash="33" * 32,
            group_id="44" * 32,
            attempt_id="55" * 16,
            missing_signer="66" * 32,
            sequence=7,
            activation_was_completed_before_crash=False,
        )
        proof["dispatch"] = (
            f'guild_signature_request{{request_id={request_id} guild_id={proof["guild_id"]} '
            f'sequence=7 event_hash=Some("{proof["event_hash"]}") kind="coding-add" '
            f'group_id=Some("{proof["group_id"]}") attempt_id=Some("{proof["attempt_id"]}") '
            f'signer=Some("{proof["missing_signer"]}")}} '
            'guild signature request progress stage="dispatched" path=Some(RelayFallback)'
        )
        proof["durable_partial"] = (
            f'persisted verified partial guild signatures guild_id={proof["guild_id"]} '
            f'sequence=7 event_hash={proof["event_hash"]} signatures=4 '
            f'missing_signers=[NodeId({list(bytes.fromhex(proof["missing_signer"]))})]'
        )
        return proof

    @staticmethod
    def write_retry_log(log, proof):
        log.write_text(
            "SIGNATURE_RETRY_EVIDENCE " + json.dumps(proof) + "\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n"
        )

    def test_signature_retry_requires_original_proof_and_exact_positive_case(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "retry.log"
            proof = self.signature_proof()
            self.write_retry_log(log, proof)
            self.assertEqual(QUALIFICATION.require_signature_retry(log, set()), proof)
            for key in QUALIFICATION.SIGNATURE_RETRY_CHECKS:
                for invalid in (None, False, 1):
                    with self.subTest(key=key, value=invalid):
                        changed = {**proof, key: invalid}
                        self.write_retry_log(log, changed)
                        with self.assertRaisesRegex(RuntimeError, "incomplete"):
                            QUALIFICATION.require_signature_retry(log, set())
            self.write_retry_log(log, proof)
            log.write_text(log.read_text().replace("1 passed", "0 passed"))
            with self.assertRaisesRegex(RuntimeError, "omitted or ignored"):
                QUALIFICATION.require_signature_retry(log, set())

    def test_signature_retry_rejects_malformed_duplicate_missing_or_oversized_proofs(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "retry.log"
            proof = self.signature_proof()
            positive = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n"
            encoded = json.dumps(proof)
            for text in (
                positive,
                "SIGNATURE_RETRY_EVIDENCE {\n" + positive,
                "SIGNATURE_RETRY_EVIDENCE []\n" + positive,
                "SIGNATURE_RETRY_EVIDENCE " + encoded + "\n"
                "SIGNATURE_RETRY_EVIDENCE " + encoded + "\n" + positive,
                "SIGNATURE_RETRY_EVIDENCE " + encoded[:-1]
                + ', "committed": true}\n' + positive,
                "SIGNATURE_RETRY_EVIDENCE " + " " * (64 * 1024) + encoded + "\n" + positive,
            ):
                with self.subTest(text=text[:80]):
                    log.write_text(text)
                    with self.assertRaises(RuntimeError):
                        QUALIFICATION.require_signature_retry(log, set())

    def test_signature_retry_rejects_invalid_identity_sequence_and_reused_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "retry.log"
            proof = self.signature_proof()
            for key, value in (
                ("request_id", "0" * 31),
                ("event_hash", "0" * 65),
                ("guild_id", "G" * 64),
                ("missing_signer", None),
                ("attempt_id", 1),
                ("sequence", True),
                ("sequence", 0),
                ("sequence", 2**64),
                ("activation_was_completed_before_crash", 1),
            ):
                with self.subTest(key=key, value=value):
                    self.write_retry_log(log, {**proof, key: value})
                    with self.assertRaises(RuntimeError):
                        QUALIFICATION.require_signature_retry(log, set())
            self.write_retry_log(log, proof)
            with self.assertRaisesRegex(RuntimeError, "repeated"):
                QUALIFICATION.require_signature_retry(log, {proof["request_id"]})

    def test_signature_retry_correlates_original_event_missing_signer_and_relay_dispatch(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "retry.log"
            proof = self.signature_proof()
            for key, before, after in (
                ("dispatch", proof["request_id"], "77" * 16),
                ("dispatch", proof["event_hash"], "77" * 32),
                ("dispatch", proof["attempt_id"], "77" * 16),
                ("dispatch", proof["group_id"], "77" * 32),
                ("dispatch", 'stage="dispatched"', 'stage="finished"'),
                ("dispatch", "RelayFallback", "Direct"),
                ("durable_partial", proof["guild_id"], "77" * 32),
                ("durable_partial", "sequence=7", "sequence=70"),
                ("durable_partial", "signatures=4", "signatures=5"),
                ("durable_partial", "102, 102", "102, 101"),
                ("durable_partial", "102, 102", "102,,102"),
            ):
                with self.subTest(key=key, before=before):
                    changed = {**proof, key: proof[key].replace(before, after)}
                    self.write_retry_log(log, changed)
                    with self.assertRaises(RuntimeError):
                        QUALIFICATION.require_signature_retry(log, set())

    def test_retry_gate_requires_two_fresh_runs_and_rejects_a_repeated_positive_proof(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            before = {"namespaces": [], "fixture_firewall_rules": [], "forwarding": "0\n"}
            for repeated in (False, True):
                calls = []

                def step(name, command, timeout, counts):
                    calls.append((name, command, timeout, counts))
                    request = "11" * 16 if repeated or len(calls) == 1 else "77" * 16
                    self.write_retry_log(root / f"{name}.log", self.signature_proof(request))
                    return {}

                with mock.patch.object(QUALIFICATION, "topology_resources", return_value=before):
                    if repeated:
                        with self.assertRaisesRegex(RuntimeError, "repeated"):
                            QUALIFICATION.qualify_signature_retries(step, root, root, before, lambda: None)
                    else:
                        proofs = QUALIFICATION.qualify_signature_retries(step, root, root, before, lambda: None)
                        self.assertEqual(len(proofs), 2)
                self.assertEqual(len(calls), 2)
                self.assertTrue(all(call[1][-1] == QUALIFICATION.SIGNATURE_RETRY_CASE for call in calls))
                self.assertTrue(all(call[3] == (1, 0, 0) for call in calls))

    def test_retry_gate_stops_before_second_run_when_first_leaves_network_resources(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            calls = []
            before = {"namespaces": [], "fixture_firewall_rules": [], "forwarding": "0\n"}

            def step(name, command, timeout, counts):
                calls.append(name)
                self.write_retry_log(root / f"{name}.log", self.signature_proof())
                return {}

            with mock.patch.object(QUALIFICATION, "topology_resources", return_value={**before, "namespaces": ["leaked"]}):
                with self.assertRaisesRegex(RuntimeError, "did not restore"):
                    QUALIFICATION.qualify_signature_retries(step, root, root, before, lambda: None)
            self.assertEqual(calls, ["relay-signature-retry-1"])

    def test_missing_candidate_never_uses_a_cargo_program(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in QUALIFICATION.PROGRAMS[:-1]:
                path = root / name
                path.write_text("#!/bin/sh\nexit 0\n")
                path.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "git-remote-mutualbackup"):
                QUALIFICATION.candidate_programs(root)
            with self.assertRaisesRegex(RuntimeError, "absolute"):
                QUALIFICATION.candidate_programs(Path("relative/bin"))

    def test_changed_underlying_nix_payload_changes_the_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in QUALIFICATION.PROGRAMS:
                payload = root / f".{name}-wrapped"
                payload.write_text("#!/bin/sh\nexit 0\n")
                payload.chmod(0o755)
                wrapper = root / name
                wrapper.write_text("#!/bin/sh\nexit 0\n")
                wrapper.chmod(0o755)
            before = QUALIFICATION.hashes(QUALIFICATION.candidate_programs(root))
            (root / ".mutualbackupd-wrapped").write_text("#!/bin/sh\nexit 42\n")
            after = QUALIFICATION.hashes(QUALIFICATION.candidate_programs(root))
            self.assertEqual(
                before[str(root / "mutualbackupd")], after[str(root / "mutualbackupd")]
            )
            self.assertNotEqual(before, after)

    def test_successful_zero_test_or_ignored_results_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "driver.log"
            for counts in (
                "0 passed; 0 failed; 0 ignored",
                "0 passed; 0 failed; 1 ignored",
                "1 passed; 0 failed; 1 ignored",
            ):
                log.write_text(f"test result: ok. {counts}; 0 measured\n")
                with self.assertRaises(RuntimeError):
                    QUALIFICATION.require_test_counts(log, (1, 0, 0))
            log.write_text(
                "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured\n"
            )
            self.assertEqual(
                QUALIFICATION.require_test_counts(log, (1, 0, 0)), (1, 0, 0)
            )

    def test_timeout_retires_a_child_that_ignores_sigterm_after_its_parent_exits(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pid_file = root / "child.pid"
            child = (
                "import os,signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path("
                + repr(str(pid_file))
                + ").write_text(str(os.getpid())); time.sleep(60)"
            )
            parent = (
                "import subprocess,sys,time; subprocess.Popen([sys.executable,'-c',"
                + repr(child)
                + "]); time.sleep(60)"
            )
            with self.assertRaises(subprocess.TimeoutExpired):
                QUALIFICATION.run(
                    [sys.executable, "-c", parent],
                    root / "driver.log",
                    os.environ.copy(),
                    3,
                )
            pid = int(pid_file.read_text())
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                return
            try:
                poller = select.poll()
                poller.register(descriptor, select.POLLIN)
                self.assertTrue(
                    poller.poll(3000), "timed-out driver's child is still running"
                )
            finally:
                os.close(descriptor)

    def test_invalid_frozen_driver_fails_before_any_privileged_command(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = root / "privileged-command"
            sudo = root / "sudo"
            sudo.write_text(
                "#!/bin/sh\n: > " + shlex.quote(str(marker)) + "\nexit 42\n"
            )
            sudo.chmod(0o755)
            environment = os.environ.copy()
            environment["PATH"] = str(root) + os.pathsep + environment["PATH"]
            for invalid in ("", "relative", str(root / "missing")):
                environment["MUTUALBACKUP_TEST_PROCESS_BINARY"] = invalid
                result = subprocess.run(
                    [
                        shutil.which("bash"),
                        QUALIFICATION.WORKSPACE / "scripts/network-smoke.sh",
                        root,
                    ],
                    env=environment,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("MUTUALBACKUP_TEST_PROCESS_BINARY", result.stderr)
                self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
