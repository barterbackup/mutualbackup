# MutualBackup prototype

This repository contains the first usable vertical slice of the design in
[`plan.md`](plan.md). Five persistent daemons form a static guild, capture
reflink snapshots, encrypt owner sectors, build real Reed–Solomon `3+2`
codewords, store parity in HMAC-protected SQLCipher databases, publish recovery
state through Kademlia, and recover a lost member from its offline seed.

Peer traffic uses authenticated QUIC with Identify, circuit relay v2,
AutoNAT/DCUtR hole punching, optional gateway port mapping, and embedded Arti
onion services. Every path authenticates the same recovery-string-derived
identity. Non-reflink source backends, membership changes, and cross-user
packing remain later work. Do not entrust unique data to this prototype.

## Programs

- `mutualbackupd [--config NODE.toml] [OPTIONS]` owns one node's databases,
  source anchors, peer network, DHT publication, watcher, and durable jobs.
- `mutualbackup` is the local control and offline bootstrap CLI. Run
  `mutualbackup --help` and its subcommand help for the complete interface.

For a no-build, step-by-step walkthrough using the packaged Linux binaries,
including a five-daemon lab and recovery-string-only recovery, see
[`docs/getting-started.md`](docs/getting-started.md). A commented daemon config
is available as [`mutualbackup.example.toml`](mutualbackup.example.toml).
The [Tor and onion guide](docs/tor.md) covers operating modes, bootstrap
addresses, state, status, and the reproducible private-network acceptance gate.
The accepted [Tor transport ADR](docs/adr/0001-tor-libp2p-transport.md) records
the underlying identity, transport, and discovery decisions.

For an isolated five-container environment with one disposable loop-backed
Btrfs filesystem per node, automatic seed/config management, host-visible file
exchange directories, and node reinitialization from its recovery string, see the
[`Docker lab guide`](docs/docker-lab.md). Enter its pinned tool environment
with `nix develop .#docker-lab`; this supplies the host-side commands without
building MutualBackup.

A new identity starts with `mutualbackup init --data-dir DATA`. Its generated
printable recovery string is shown once; retain an offline copy. The command
creates an application-owned public identity manifest but never edits daemon
configuration. Supply daemon options through human-owned TOML, equivalent
flags, or both with flags taking precedence. Without a configured `seed_file`,
the daemon starts locked and is unlocked through the same-user CLI prompt. For
unattended labs, `init --seed-file FILE` stores the string in a strictly private
auto-unlock file. `mutualbackup recover-init` recreates blank identity state
from only that string; generic network options are still supplied to the daemon.

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
mutualbackup storage list|scrub|reclaim|drain|migrate|reactivate|reconcile
mutualbackup audit [--repair]
mutualbackup db-shell --data-dir STATE [--volume UUID] [--write]
```

Parity may span several configured filesystems. Each volume has a signed UUID,
an independently wrapped SQLCipher key, a byte budget and repair headroom.
`storage drain` stops new placement; `storage migrate` copies and verifies each
object before retiring its source. A retired volume remains retired across
daemon restarts even if its path stays configured; `storage reactivate UUID`
explicitly returns an attached retired volume to service. Interrupted writes
and moves are reconciled from durable control receipts, while an absent disk
remains visibly offline. `storage list` reports logical use, physical database
allocation, and filesystem availability; `storage reclaim [--volume UUID]`
returns unused database and WAL allocation to the filesystem.
`retention_revisions` keeps a signed suffix of each member's history. Retired
prefixes remain represented by checkpoint tombstones, and local anchors and
shards are collected only after a later checkpoint confirms they stayed
unreachable.

Automatic backup is disabled by default. When enabled, watcher events coalesce
behind a quiet period, startup and periodic deadlines force full reconciliation,
and minimum-interval plus daily count/byte limits are durable across restarts.
`status` keeps the root visibly dirty and prints the blocking reason when a
limit or storage capacity prevents publication.

The daemon periodically scrubs every online parity database and audits the
current guild layout. Missing assigned shards are reconstructed from any three
valid shards; when the assigned peer is unavailable, a verified emergency copy
uses reserved repair headroom on another member. `status` reports the last
durable result as healthy, degraded, emergency, or unrecoverable.

`db-shell` uses the application's SQLCipher connection and wrapped keys. It is
query-only unless `--write` is supplied, and opening it requires the node data
directory lock so a writable shell cannot race the daemon.

The CLI and daemon use a same-user Unix control socket. Pass `--socket` when a
configuration does not use the default location below `XDG_RUNTIME_DIR`.
Several daemons can run under one account when every config has a distinct
recovery string, data directory, control socket, and UDP listen address.
`status` reports process-lifetime application byte counters separately for
each observed direct, hole-punched, and relay-fallback path; compare a baseline
before and after an operation when diagnosing the route that operation used.
The current draft JSON/CBOR schemas, signed-record field tables, and golden
fixtures are documented in the [`protocol/` directory](protocol/README.md).

## Build and acceptance

The pinned Nix development shell supplies Rust and the native build tools for
the bundled SQLCipher/OpenSSL build:

```sh
nix develop -c cargo test --workspace
nix build
nix build .#lab-artifacts -o dist
```

The `lab-artifacts` output gives the CLI and daemon the exact static x86-64
filenames consumed by the no-build guides and Docker lab. Building that output
is a release-machine or CI step; the lab itself never builds the programs.

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

This Linux-only gate uses disposable network namespaces, veth interfaces,
port-preserving NAT, and firewall rules to make direct, successful-DCUtR, and
relay-only paths real rather than inferred. It requires passwordless `sudo` for
that network plumbing; daemons are dropped back to the invoking UID/GID, and an
exit trap removes the namespaces and rules and restores the forwarding setting.

The separate gateway-mapping gate runs a real stateful NAT-PMP exchange in an
isolated namespace and verifies acquisition, replacement, loss, reacquisition,
and orderly deletion:

```sh
nix develop -c bash scripts/port-mapping-acceptance.sh
```

It also requires passwordless `sudo`; its namespace and veth pair are removed
by an exit trap.

The onion-only recovery gate starts a pinned private Tor network and uses no
peer IP listener, relay, or hole-punch path:

```sh
MUTUALBACKUP_REFLINK_TEST_ROOT=/mnt/disposable-btrfs \
  nix develop .#private-tor -c bash scripts/private-tor-acceptance.sh
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
