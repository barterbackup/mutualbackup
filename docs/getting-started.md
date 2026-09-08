# Running the prototype with the prebuilt binaries

This guide uses the packaged x86-64 Linux programs in `dist/`; it does not
build anything locally.

The prototype has no implicit daemon configuration file. `mutualbackupd` accepts
an optional human-written `--config PATH`, equivalent command-line flags, or a
mixture in which flags override file values. `mutualbackup init` and
`recover-init` create only application-owned identity state and never edit
operator configuration. [`mutualbackup.example.toml`](../mutualbackup.example.toml)
is a commented starting point.

## Before starting

Set paths to the two programs from the repository root:

```sh
REPO=$PWD
CLI="$REPO/dist/mutualbackup-x86_64-linux"
DAEMON="$REPO/dist/mutualbackupd-x86_64-linux"
```

Both files should report version 0.1.0:

```sh
"$CLI" --version
"$DAEMON" --version
```

The current prototype has these practical constraints:

- It runs on Linux, and the supplied binaries require an x86-64 machine.
- A working guild has exactly five nodes. One daemon is enough to inspect the
  interface, but not to commit a guild backup.
- Protected data must be on a filesystem that passes the complete reflink COW
  probe. Btrfs and appropriately configured XFS are usual choices. Filesystem
  type alone is not proof; always run the probe.
- Five daemons on one machine are useful as a functional lab, but they are not
  five independent failure domains and provide no real disaster resilience.
- This remains a prototype. Do not entrust unique data to it.

Choose a fresh lab directory on a reflink-capable filesystem. Do not put it
under a directory containing valuable files:

```sh
LAB=/mnt/reflink/mutualbackup-demo
mkdir -p "$LAB"
"$CLI" reflink-probe "$LAB"
```

Stop if the probe fails. All paths below stay inside `$LAB` except the packaged
binaries.

## What is in a configuration

Paths may be absolute or relative to the TOML file containing them.

| Field | Meaning |
| --- | --- |
| `data_dir` | Private node state, including the generated public identity manifest and encrypted `control.db` and `parity.db`. One running daemon owns it exclusively. |
| `seed_file` | Optional unattended auto-unlock file. Omit it for the normal locked-daemon workflow. If present, it must be a same-owner regular file with no group/other permissions and must not be a symlink. |
| `control_socket` | Same-user Unix socket used by the CLI. It must be unique for every daemon on one host. |
| `failure_domain` | Stable physical failure-domain label advertised to the guild. Five real peers should not claim the same disk or host as independent domains. |
| `parity_budget_bytes` | Maximum parity bytes accepted into this node's local parity store. |
| `p2p_listen_addresses` | Local libp2p QUIC listeners. Use distinct UDP ports when running multiple daemons. |
| `p2p_external_addresses` | Concrete addresses advertised to peers. Do not advertise `0.0.0.0` or port `0`. |
| `p2p_bootstrap_addresses` | Known peers used to enter the Kademlia network, including `/p2p/PEER_ID`. |
| `p2p_relay_addresses` | Relay nodes on which this node should reserve a circuit, also including `/p2p/PEER_ID`. |
| `enable_relay_server` | Whether this node accepts rate-, byte-, and connection-limited circuit-relay reservations from active guild members. |
| `enable_hole_punching` | Whether DCUtR should try to upgrade a relay circuit to direct QUIC. Disabling it does not prohibit independent direct connections. |
| `enable_dht_maintenance` | Whether the daemon performs outbound Kademlia bootstrap, publication, and refresh work. Keep this enabled normally; static/server-only peers may disable it while still serving DHT, application, and relayed requests. |
| `max_connections` | Bound for established libp2p sessions and concurrent peer workers; defaults to 32. |

Every field is also a daemon flag; repeat `--listen`, `--external-address`,
`--bootstrap`, and `--relay` for lists, and pass an explicit `true` or `false`
to boolean flags. Paths from TOML are relative to the config file, while paths
from flags are relative to the current directory. Unknown TOML fields are
rejected. The config is not a CLI profile: routine CLI commands still select a
daemon with `--socket`, permitting several daemons under one Unix account.

When mixing a file with flags, `--locked` suppresses its `seed_file` for this
run. `--clear-listen`, `--clear-external-addresses`, `--clear-bootstrap`, and
`--clear-relay` similarly replace the corresponding configured list with an
empty list. A clear flag wins if the same invocation also supplies values for
that list. Relative paths stay relative to the pathname the operator supplied,
including when that pathname is a symbolic link to a packaged configuration.

## Recovery strings and locked startup

The recovery string is the sole root secret. By default `init` generates 24
English words, shows them once, and asks you to re-enter them without terminal
echo. It does not store them:

```sh
mkdir -p "$LAB/single/run"
chmod 700 "$LAB/single" "$LAB/single/run"
"$CLI" init --data-dir "$LAB/single/state"

cat >"$LAB/single/node.toml" <<'EOF'
data_dir = "state"
control_socket = "run/control.sock"
failure_domain = "single-test-disk"
p2p_listen_addresses = ["/ip4/0.0.0.0/udp/44000/quic-v1"]
p2p_external_addresses = ["/ip4/127.0.0.1/udp/44000/quic-v1"]
EOF
chmod 600 "$LAB/single/node.toml"
```

You can instead provide your own strong printable string using
`--prompt-recovery`, or pipe it with `--seed-stdin`. Whitespace of every Unicode
class is removed before validation and derivation; every remaining character
must be printable ASCII, the compacted length must be 8–1024 characters, and
the strength estimate must be at least 64 bits. There is intentionally no
prefix, version marker, or checksum.

Start the daemon. Without `seed_file` in its config it binds the control socket
but remains locked and does not open its databases or start networking:

```sh
"$DAEMON" --config "$LAB/single/node.toml"
```

In a second terminal, inspect and unlock it. The prompt has no echo, and only
the derived 32-byte root crosses the same-user local socket:

```sh
"$CLI" --socket "$LAB/single/run/control.sock" status
"$CLI" --socket "$LAB/single/run/control.sock" unlock
"$CLI" --socket "$LAB/single/run/control.sock" status
```

Use Ctrl-C in the first terminal to stop it. The remaining sections instead
create protected auto-unlock files for a complete unattended five-node lab.
[`mutualbackup.example.toml`](../mutualbackup.example.toml) documents every
field. The generated `$LAB/single/state/identity.toml` is public but
application-owned: do not edit or replace it.

## Create five nodes on one box

Create private per-node directories and an offline recovery-string directory:

```sh
mkdir -p "$LAB/offline"
chmod 700 "$LAB/offline"
for i in 0 1 2 3 4; do
  mkdir -p "$LAB/p$i"
  chmod 700 "$LAB/p$i"
done
```

Create five identities and protected unattended recovery-string files:

```sh
for i in 0 1 2 3 4; do
  "$CLI" init \
    --seed-file "$LAB/offline/p$i.seed" \
    --data-dir "$LAB/p$i/state"
done

P0_PEER=$("$CLI" identity --seed-file "$LAB/offline/p0.seed" |
  sed -n 's/^libp2p peer id: *//p')
P0_ENDPOINT="/ip4/127.0.0.1/udp/44000/quic-v1/p2p/$P0_PEER"
```

`init --seed-file` is restartable: it creates the seed without replacement and,
if interrupted before installing `identity.toml`, the identical command reads
that protected seed and completes the same identity. Repeating a completed
command is also safe; different existing seed or identity contents are rejected.

Write the human-owned daemon configs. Node 0 is the initial Kademlia bootstrap
and relay; every node gets its own UDP port, socket, and failure-domain label:

```sh
for i in 0 1 2 3 4; do
  port=$((44000 + i))
  if [ "$i" -eq 0 ]; then
    bootstrap='[]'
    relay='[]'
    relay_server=true
  else
    bootstrap="[\"$P0_ENDPOINT\"]"
    relay="$bootstrap"
    relay_server=false
  fi
  cat >"$LAB/p$i/node.toml" <<EOF
data_dir = "state"
seed_file = "../offline/p$i.seed"
control_socket = "control.sock"
failure_domain = "lab-disk-$i"
p2p_listen_addresses = ["/ip4/127.0.0.1/udp/$port/quic-v1"]
p2p_external_addresses = ["/ip4/127.0.0.1/udp/$port/quic-v1"]
p2p_bootstrap_addresses = $bootstrap
p2p_relay_addresses = $relay
enable_relay_server = $relay_server
EOF
  chmod 600 "$LAB/p$i/node.toml"
done
```

Keep a genuinely offline copy of every `.seed` file. Despite the historical
extension, each is an ordinary printable recovery string. It is the persistent
node identity and recovery root; losing it makes that node unrecoverable. The
daemon accepts this file only as an explicit unattended auto-unlock convenience.
The configs are human-owned; rerunning `init` never changes them.

## Start and address the daemons

Start all five in the background and retain their process IDs and logs:

```sh
for i in 0 1 2 3 4; do
  nohup env RUST_LOG=info "$DAEMON" --config "$LAB/p$i/node.toml" \
    >"$LAB/p$i/daemon.log" 2>&1 &
  printf '%s\n' "$!" >"$LAB/p$i/daemon.pid"
done
```

Define a small shell helper that sends a command to a particular node:

```sh
mb() {
  node=$1
  shift
  "$CLI" --socket "$LAB/p$node/control.sock" "$@"
}
```

After a few seconds, every status command should succeed:

```sh
for i in 0 1 2 3 4; do
  mb "$i" status
done
```

If one fails, inspect its `daemon.log`. Common causes are a reused UDP port, a
second process using the same `data_dir`, or a non-private control-socket
directory.

## Form the five-member guild

Create the draft on node 0, issue one single-use invitation per member, and
join the other four nodes:

```sh
mb 0 guild create

for i in 1 2 3 4; do
  INVITE=$(mb 0 guild invite | sed -n 's/^invitation: //p')
  mb "$i" guild join "$INVITE"
done

mb 0 guild finalize
```

Confirm that every node reports the active guild and five members:

```sh
for i in 0 1 2 3 4; do
  mb "$i" guild status
done
```

## Protect data, back it up, and restore a snapshot

Give node 1 a source directory. Its state and source may be siblings, but must
not overlap:

```sh
mkdir -p "$LAB/p1/source/documents"
printf 'first version\n' >"$LAB/p1/source/documents/example.txt"
mb 1 root add "$LAB/p1/source"
mb 1 backup --wait
```

`state: Committed` means the real `3+2` Reed-Solomon guild checkpoint was
committed. Modify the live file and make another revision:

```sh
printf 'second version\n' >"$LAB/p1/source/documents/example.txt"
mb 1 backup --wait
mb 1 snapshot list
```

Restore the latest locally retained snapshot to a new path:

```sh
mb 1 snapshot restore "$LAB/local-restore"
cat "$LAB/local-restore/documents/example.txt"
```

The protected root's parent also contains a private hidden
`.mutualbackup-anchors-*` directory. It holds reflink snapshots and is part of
the node's live local state; do not edit or delete it.

## Exercise recovery-string-only network recovery

First wait until node 1 reports that its recovery records are present in the
DHT:

```sh
until mb 1 status | grep -q 'recovery ready: true'; do
  sleep 2
done
```

Stop node 1, then make its entire local directory—including its protected
source and reflink anchors—inaccessible. This is a reversible lab simulation;
do not run it on real data:

```sh
P1_PID=$(cat "$LAB/p1/daemon.pid")
kill "$P1_PID"
while kill -0 "$P1_PID" 2>/dev/null; do sleep 0.1; done
mv "$LAB/p1" "$LAB/p1.unavailable"
chmod -R u-rwx "$LAB/p1.unavailable"
```

Create a blank recovery identity from node 1's retained recovery string, then
write independent daemon options containing the generic node-0 bootstrap:

```sh
mkdir -p "$LAB/recovered-p1"
chmod 700 "$LAB/recovered-p1"

"$CLI" recover-init \
  --seed-file "$LAB/offline/p1.seed" \
  --data-dir "$LAB/recovered-p1/state"

cat >"$LAB/recovered-p1/node.toml" <<EOF
data_dir = "state"
seed_file = "../offline/p1.seed"
control_socket = "control.sock"
p2p_listen_addresses = ["/ip4/127.0.0.1/udp/44005/quic-v1"]
p2p_external_addresses = ["/ip4/127.0.0.1/udp/44005/quic-v1"]
p2p_bootstrap_addresses = ["$P0_ENDPOINT"]
EOF
chmod 600 "$LAB/recovered-p1/node.toml"

nohup env RUST_LOG=info "$DAEMON" --config "$LAB/recovered-p1/node.toml" \
  >"$LAB/recovered-p1/daemon.log" 2>&1 &
printf '%s\n' "$!" >"$LAB/recovered-p1/daemon.pid"
```

Address the recovery daemon through its own socket and restore the latest
revision:

```sh
until "$CLI" --socket "$LAB/recovered-p1/control.sock" status; do
  sleep 1
done
"$CLI" --socket "$LAB/recovered-p1/control.sock" \
  restore "$LAB/restored-from-seed"
cat "$LAB/restored-from-seed/documents/example.txt"
```

Recovery discovers the guild through Kademlia, fetches real sectors from the
remaining peers, reconstructs missing data, validates it, restores the tree,
and republishes the recovered identity's endpoint.

## Stop the lab

Stop the recovery daemon and the four original daemons still running:

```sh
kill "$(cat "$LAB/recovered-p1/daemon.pid")"
for i in 0 2 3 4; do
  kill "$(cat "$LAB/p$i/daemon.pid")"
done
```

To regain access to the preserved node-1 lab directory:

```sh
chmod -R u+rwX "$LAB/p1.unavailable"
```

Inspect the logs and restored data before removing the lab directory yourself.

## Moving from one box to real peers

Run one config per host, keep each node's paths local and private, and replace
the loopback `p2p_external_addresses` with addresses reachable by the other
peers. At least one reachable peer should be listed as a bootstrap node; a
publicly reachable peer can also enable relay service. Keep the `/p2p/PEER_ID`
suffix on bootstrap and relay addresses. Direct QUIC, circuit relay, AutoNAT,
and DCUtR hole punching are active; Tor fallback is deliberately not part of
this prototype milestone.
