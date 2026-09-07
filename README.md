# MutualBackup prototype

This repository contains the first usable vertical slice of the design in
[`plan.md`](plan.md). Five persistent daemons form a static guild, capture
reflink snapshots, encrypt owner sectors, build real Reed–Solomon `3+2`
codewords, store parity in HMAC-protected SQLCipher databases, publish recovery
state through Kademlia, and recover a lost member from its offline seed.

Peer traffic uses authenticated QUIC with Identify, circuit relay v2,
AutoNAT/DCUtR hole punching, and one recovery-string-derived identity. Tor/Arti is
deliberately outside this milestone, as are non-reflink source backends,
membership changes, audits, repair, and garbage collection. Do not entrust
unique data to this prototype.

## Programs

- `mutualbackupd --config NODE.toml` owns one node's databases, source anchors,
  peer network, DHT publication, watcher, and durable jobs.
- `mutualbackup` is the local control and offline bootstrap CLI. Run
  `mutualbackup --help` and its subcommand help for the complete interface.

For a no-build, step-by-step walkthrough using the packaged Linux binaries,
including a five-daemon lab and recovery-string-only recovery, see
[`docs/getting-started.md`](docs/getting-started.md). A commented daemon config
is available as [`mutualbackup.example.toml`](mutualbackup.example.toml).

For an isolated five-container environment with one disposable loop-backed
Btrfs filesystem per node, automatic seed/config management, host-visible file
exchange directories, and node reinitialization from its recovery string, see the
[`Docker lab guide`](docs/docker-lab.md). Enter its pinned tool environment
with `nix develop .#docker-lab`; this supplies the host-side commands without
building MutualBackup.

A new node starts with `mutualbackup init --config NODE.toml --data-dir DATA
--failure-domain LABEL`. Its generated printable recovery string is shown once;
retain an offline copy. The daemon starts locked and is unlocked through the
same-user CLI prompt. For unattended labs, `--seed-file FILE` stores the string
in a strictly private auto-unlock file. A fresh recovery-mode daemon can be
initialized with `mutualbackup recover-init` using only that string and generic
bootstrap multiaddresses.

Routine operations go through the daemon:

```text
mutualbackup status
mutualbackup unlock [--seed-stdin|--seed-file FILE]
mutualbackup root add PATH
mutualbackup guild create|invite|join|finalize|status
mutualbackup backup --wait
mutualbackup snapshot list
mutualbackup snapshot restore TARGET [--revision UUID]
mutualbackup restore TARGET
```

The CLI and daemon use a same-user Unix control socket. Pass `--socket` when a
configuration does not use the default location below `XDG_RUNTIME_DIR`.
Several daemons can run under one account when every config has a distinct
recovery string, data directory, control socket, and UDP listen address.
The current draft JSON/CBOR schemas, signed-record field tables, and golden
fixtures are documented in the [`protocol/` directory](protocol/README.md).

## Build and acceptance

The pinned Nix development shell supplies Rust and the native build tools for
the bundled SQLCipher/OpenSSL build:

```sh
nix develop -c cargo test --workspace
nix build
```

The destructive acceptance tests need a disposable directory on a filesystem
that supports reflinks. They start real daemons and use real QUIC, relay,
Kademlia, SQLCipher, process restarts, and recovery-string-only recovery:

```sh
MUTUALBACKUP_REFLINK_TEST_ROOT=/mnt/disposable-btrfs \
  nix develop -c bash scripts/reflink-acceptance.sh
```

For only the five-daemon product acceptance scenario:

```sh
nix develop -c bash scripts/network-smoke.sh /mnt/disposable-btrfs
```

The product test creates checkpoint generations for two owners, resumes a
failed join and an interrupted backup, repairs deleted local anchors while a
source and shard holder are unavailable, and rejects poisoned DHT hints. It
then destroys an owner's complete local state plus another peer, starts the
owner while its bootstrap is offline, recovers both that owner and the
storage-only peer from their recovery strings, changes endpoints, restarts the
guild, and commits another backup. Relay reservations, guild-only admission,
selected paths, and transferred application bytes are asserted along the way.

The SQLCipher tests verify encrypted pages and HMAC rejection with a wrong key.
Coding tests reconstruct every supported pair of missing shards.
