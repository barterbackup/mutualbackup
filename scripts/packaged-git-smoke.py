#!/usr/bin/env python3
"""Exercise installed programs with only the package and optional alias on PATH."""

import argparse
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import time


def run(command, environment, *, data=None, timeout=60):
    result = subprocess.run(
        [str(item) for item in command],
        input=data,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    if result.returncode:
        raise RuntimeError(
            f"{command[0]} {command[1:]} failed ({result.returncode}):\n"
            + result.stderr.decode(errors="replace")
        )
    return result.stdout


def scenario(bin_dir, alias_dir, stock_git, root, *, missing_git=False):
    area = Path(tempfile.mkdtemp(prefix="mb-package-git-", dir=root))
    daemon = None
    success = False
    log_path = area / "daemon.log"
    try:
        source = area / "native"
        source.mkdir()
        socket = area / "control.sock"
        path = str(bin_dir)
        if alias_dir:
            path = str(alias_dir) + os.pathsep + path
        environment = {
            "PATH": path,
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "MUTUALBACKUP_CONTROL_SOCKET": str(socket),
        }
        visible_git = shutil.which("git", path=path)
        if alias_dir:
            assert visible_git == str(alias_dir / "git"), visible_git
            assert run([visible_git, "--version"], environment).startswith(b"mutualgit ")
        else:
            assert visible_git is None, "ambient ordinary Git leaked onto test PATH"

        def program(name):
            # The raw static programs also ship as standalone lab artifacts.
            return bin_dir / ("." + name + "-wrapped" if missing_git else name)

        cli = program("mutualbackup")
        git_cli = program("mutualgit")
        seed = secrets.token_urlsafe(48).encode()
        run(
            [cli, "init", "--data-dir", area / "state", "--seed-file", area / "seed", "--seed-stdin"],
            environment,
            data=seed,
        )
        with log_path.open("wb") as log:
            daemon = subprocess.Popen(
                [
                    str(program("mutualbackupd")),
                    "--data-dir", str(area / "state"),
                    "--seed-file", str(area / "seed"),
                    "--control-socket", str(socket),
                    "--failure-domain", "packaged-git-smoke",
                    "--listen", "/ip4/127.0.0.1/udp/0/quic-v1",
                    "--tor-mode", "disable-tor",
                    "--enable-dht-maintenance", "false",
                ],
                env=environment,
                stdout=log,
                stderr=log,
            )
        deadline = time.monotonic() + 60
        while True:
            if daemon.poll() is not None:
                raise RuntimeError("packaged daemon exited during startup")
            try:
                status = run([cli, "--socket", socket, "status"], environment, timeout=5)
                if b"node id:" in status:
                    break
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError("packaged daemon did not unlock within 60 seconds")
            time.sleep(0.1)

        def native(*arguments):
            return run([git_cli, "--socket", socket, "-C", source, *arguments], environment)

        def stock(directory, *arguments):
            return run([stock_git, "-C", directory, *arguments], environment)

        native("init")
        (source / "original").write_bytes(b"native\r\n\0bytes\xff")
        native("add", "original")
        native("commit", "-m", "native", "--author-name", "Smoke", "--author-email", "smoke@example.test")

        fixture = area / "stock-fixture"
        fixture.mkdir()
        stock(fixture, "init", "-q", "--initial-branch=incoming")
        stock(fixture, "config", "user.name", "Smoke")
        stock(fixture, "config", "user.email", "smoke@example.test")
        payloads = {"small": b"stock\r\n\0bytes\xff", "large": bytes(range(256)) * 4096}
        for name, payload in payloads.items():
            (fixture / name).write_bytes(payload)
        stock(fixture, "add", ".")
        stock(fixture, "commit", "-qm", "packed import")
        expected = stock(fixture, "rev-parse", "HEAD").strip()
        stock(fixture, "gc", "--prune=now")
        assert list((fixture / ".git/objects/pack").glob("*.pack"))

        if missing_git:
            prior_branches = native("branch", "-a")
            prior_log = native("log")
            try:
                native("fetch", fixture)
            except RuntimeError as error:
                assert "stock Git is required" in str(error), error
                assert "daemon's PATH" in str(error), error
            else:
                raise AssertionError("standalone import succeeded without ordinary Git")
            assert native("branch", "-a") == prior_branches, "failed import published refs"
            assert native("log") == prior_log, "failed import changed visible history"
            assert (source / "original").read_bytes() == b"native\r\n\0bytes\xff"
            assert not (source / "large").exists()
            daemon.terminate()
            assert daemon.wait(timeout=30) == 0
            success = True
            print("Standalone missing-Git error passed without publishing refs/history")
            return

        native("fetch", fixture)
        native("branch", "imported", "origin/incoming")
        native("checkout", "imported")
        for name, payload in payloads.items():
            assert (source / name).read_bytes() == payload, name

        received = area / "stock-received"
        received.mkdir()
        stock(received, "init", "-q")
        remote = "mutualbackup::" + str(source)
        stock(received, "fetch", remote, "refs/heads/imported:refs/heads/received")
        assert stock(received, "rev-parse", "refs/heads/received").strip() == expected
        for name, payload in payloads.items():
            assert stock(received, "cat-file", "blob", "received:" + name) == payload

        stock(received, "checkout", "-qb", "pushed", "received")
        stock(received, "config", "user.name", "Smoke")
        stock(received, "config", "user.email", "smoke@example.test")
        pushed = b"pushed\r\n\0bytes\xfe"
        (received / "small").write_bytes(pushed)
        stock(received, "add", "small")
        stock(received, "commit", "-qm", "bridge push")
        pushed_oid = stock(received, "rev-parse", "HEAD").strip()
        stock(received, "push", remote, "refs/heads/pushed:refs/heads/pushed")
        native("checkout", "pushed")
        assert (source / "small").read_bytes() == pushed
        assert (source / "large").read_bytes() == payloads["large"]
        stock(received, "fetch", remote, "refs/heads/pushed:refs/heads/native-pushed")
        assert stock(received, "rev-parse", "native-pushed").strip() == pushed_oid
        assert not (source / ".git").exists(), "native repository created a Git payload mirror"

        daemon.terminate()
        assert daemon.wait(timeout=30) == 0, "packaged daemon did not exit cleanly"
        success = True
        print("Packaged Git import/fetch/push passed" + (" with alias first" if alias_dir else " without host Git"))
    except BaseException:
        print(f"Failure diagnostics preserved at {area}")
        if log_path.exists():
            print(log_path.read_bytes()[-16384:].decode(errors="replace"))
        raise
    finally:
        if daemon and daemon.poll() is None:
            daemon.terminate()
            try:
                daemon.wait(timeout=30)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=10)
        if success:
            shutil.rmtree(area)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", required=True, type=Path)
    parser.add_argument("--alias-dir", required=True, type=Path)
    parser.add_argument("--stock-git", required=True, type=Path)
    parser.add_argument("--reflink-root", required=True, type=Path)
    arguments = parser.parse_args()
    bin_dir = arguments.bin_dir.absolute()
    alias_dir = arguments.alias_dir.absolute()
    stock_git = arguments.stock_git.absolute()
    root = arguments.reflink_root.resolve(strict=True)
    for program in ["mutualbackup", "mutualbackupd", "mutualgit", "git-remote-mutualbackup"]:
        assert os.access(bin_dir / program, os.X_OK), program
    assert os.access(stock_git, os.X_OK), "stock Git fixture executable is unavailable"
    assert os.access(alias_dir / "git", os.X_OK), "optional alias package is unavailable"
    scenario(bin_dir, None, stock_git, root)
    scenario(bin_dir, alias_dir, stock_git, root)
    scenario(bin_dir, None, stock_git, root, missing_git=True)


if __name__ == "__main__":
    main()
