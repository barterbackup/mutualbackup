#!/usr/bin/env python3
"""Negative checks for the installed-artifact qualification boundary."""

import importlib.util
import os
from pathlib import Path
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "qualification", Path(__file__).with_name("packaged-process-acceptance.py")
)
QUALIFICATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(QUALIFICATION)


class QualificationTests(unittest.TestCase):
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
