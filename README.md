# MutualBackup prototype

This repository contains the first usable vertical slice of the design in
[`plan.md`](plan.md). Five persistent daemons form a static guild, capture
reflink snapshots, encrypt owner sectors, build real Reed–Solomon `3+2`
codewords, store parity in HMAC-protected SQLCipher databases, publish recovery
state through Kademlia, and recover a lost member from its offline seed.

Peer traffic uses authenticated QUIC with Identify, circuit relay v2,
AutoNAT/DCUtR hole punching, and one seed-derived identity. Tor/Arti is
deliberately outside this milestone, as are non-reflink source backends,
membership changes, audits, repair, and garbage collection. Do not entrust
unique data to this prototype.

## Programs

- `mutualbackupd --config NODE.toml` owns one node's databases, source anchors,
  peer network, DHT publication, watcher, and durable jobs.
- `mutualbackup` is the local control and offline bootstrap CLI. Run
  `mutualbackup --help` and its subcommand help for the complete interface.

A new node starts with `mutualbackup init --seed-file SEED --config NODE.toml
--data-dir DATA --failure-domain LABEL`. Keep the generated seed offline: a
fresh recovery-mode daemon can be initialized with `mutualbackup recover-init`
using only that seed and generic bootstrap multiaddresses.

Routine operations go through the daemon:

```text
mutualbackup status
mutualbackup root add PATH
mutualbackup guild create|invite|join|finalize|status
mutualbackup backup --wait
mutualbackup snapshot list
mutualbackup snapshot restore TARGET [--revision UUID]
mutualbackup restore TARGET
```

The CLI and daemon use a same-user Unix control socket. Pass `--socket` when a
configuration does not use the default location below `XDG_RUNTIME_DIR`.

## Build and acceptance

The pinned Nix development shell supplies Rust and the native build tools for
the bundled SQLCipher/OpenSSL build:

```sh
nix develop -c cargo test --workspace
nix build
```

The destructive acceptance tests need a disposable directory on a filesystem
that supports reflinks. They start real daemons and use real QUIC, relay,
Kademlia, SQLCipher, process restarts, and seed-only recovery:

```sh
MUTUALBACKUP_REFLINK_TEST_ROOT=/mnt/disposable-btrfs \
  nix develop -c bash scripts/reflink-acceptance.sh
```

For only the five-daemon product acceptance scenario:

```sh
nix develop -c bash scripts/network-smoke.sh /mnt/disposable-btrfs
```

The product test creates three checkpoint generations for two owners, kills
and restarts the coordinator during work, restarts every daemon, then destroys
one owner's complete local state plus another peer. A fresh daemon derives the
same identity from the offline seed, discovers recovery records from a generic
bootstrap peer, restores the latest 4 MiB file byte-for-byte, and republishes a
new reachable endpoint.

The SQLCipher tests verify encrypted pages and HMAC rejection with a wrong key.
Coding tests reconstruct every supported pair of missing shards.
