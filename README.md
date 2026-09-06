# MutualBackup prototype

This repository contains the first runnable vertical slice of the design in
[`plan.md`](plan.md). It protects a directory with reflink snapshots, encrypts
the owner's fixed-size sectors, forms real Reed–Solomon `3+2` coding groups
across five independent identities and failure domains, stores control/parity
state in HMAC-protected SQLCipher databases, and recovers a lost node from its
offline seed.

The prototype is deliberately narrow. It currently supports Linux reflinks and
signed direct TCP on a trusted network. The recovery directory is an in-memory
stand-in for the future DHT. QUIC, NAT traversal, guild relays, Arti onion
fallback, link-freeze, writer-incarnation fencing, membership changes, audits,
repair, and garbage collection remain later slices. Direct TCP authenticates
protocol messages but does not encrypt the transport; owner data and private
metadata are encrypted before they leave the owner.

Do not entrust unique data to this prototype.

## Fast hand test

On an x86-64 Linux system with Btrfs, XFS, or another filesystem that passes
the full reflink COW probe:

```sh
./dist/mutualbackup-x86_64-linux reflink-probe /path/on/reflink/filesystem
./scripts/network-smoke.sh \
  ./dist/mutualbackup-x86_64-linux \
  /path/on/reflink/filesystem
```

The smoke test starts a recovery directory and five complete node processes,
each with its own seed, identity, SQLCipher databases, failure domain, and
protocol endpoint. It commits a small sparse source tree, stops the owner and
one helper, deletes those two node directories and the plaintext source, and
recovers into a clean directory using only the separately held owner seed. It
then compares every restored file hash. All test material is placed in a new
`mutualbackup-network-smoke.*` directory and is left there for inspection.

## Commands

```text
mutualbackup init --seed-file PATH
mutualbackup identity --seed-file PATH
mutualbackup reflink-probe PATH
mutualbackup serve-directory --listen IP:PORT
mutualbackup serve-node --seed-file PATH --data-dir PATH \
  --listen IP:PORT --public-endpoint tcp://IP:PORT \
  --failure-domain LABEL --trusted-coordinator NODE_ID
mutualbackup commit --seed-file PATH --source PATH --directory IP:PORT \
  --peer IP:PORT --peer IP:PORT --peer IP:PORT --peer IP:PORT --peer IP:PORT
mutualbackup recover --seed-file PATH --data-dir NEW_PATH \
  --restore NEW_PATH --directory IP:PORT
```

`init` creates the seed file exclusively with mode `0600` and refuses to
overwrite it. Keep an offline copy: recovery intentionally does not need the
old `data-dir`, source tree, anchors, guild ID, checkpoint hash, or peer list.
The current fixed network profile requires exactly five distinct peer
identities and five distinct failure-domain labels. The coordinator must be one
of those peers and must be the owner of the protected source.

`demo-seed-recovery --work-dir PATH` is a shorter, single-process version of
the same destructive-loss demonstration. It creates and deletes data only
inside a uniquely named demonstration directory.

## Build and test

The pinned Nix development shell supplies Rust and the native build tools for
the bundled SQLCipher/OpenSSL build:

```sh
nix develop -c cargo test --workspace --all-targets
nix build
```

`nix build` produces a statically linked Linux binary at
`result/bin/mutualbackup`. The prebuilt file under `dist/` is produced by this
same expression.

Set `MUTUALBACKUP_REFLINK_TEST_ROOT` to an existing reflink-capable directory
to enable the end-to-end loss/recovery unit test. Without it, that filesystem
test skips rather than pretending the host supports reflinks.

The SQLCipher tests verify an encrypted header, reject a wrong key through page
HMAC failure, run `cipher_integrity_check`, and reject parity whose committed
root no longer matches. The coding tests reconstruct from every possible pair
of missing shards.
