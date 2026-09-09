# Five-node Docker lab

`scripts/docker-lab.sh` deploys a complete local MutualBackup guild without
compiling MutualBackup or building a Docker image. It runs each of the five
seed identities in a separate container and gives each container a separate,
loop-backed Btrfs filesystem.

The lab is intended for interactive prototype testing: copying files into a
node, taking real backups, stopping peers, inspecting encrypted stores, and
destroying and recovering a node from its seed. Five containers on one host do
not provide real failure-domain independence.

## What the controller creates

By default, all retained lab material lives below `.docker-lab/`:

| Host object | Purpose |
| --- | --- |
| `images/nodeN.btrfs` | One sparse 1 GiB Btrfs image per node. |
| `mounts/nodeN/` | Host mount point for that node's Btrfs image. |
| `mounts/nodeN/exchange/` | Host-visible directory also available as `/node/exchange` inside node N. |
| `seeds/nodeN.seed` | Automatically generated printable recovery string, outside disposable node storage. |
| `seeds/nodeN.identity` | Cached public Node ID/libp2p identity used to render configs without repeating Argon2. |
| `configs/nodeN.toml` | Lab-managed daemon configuration using container-internal paths. |
| One Docker container per node | Runs only the prebuilt `mutualbackupd`. |
| One Docker bridge | Gives nodes stable addresses `172.30.77.10` through `.14`. |

The CLI and daemon release files are bind-mounted read-only at `/opt` in every
container. The daemon reads its seed from a separate read-only bind mount and
uses it to derive its identity and unlock its SQLCipher databases. There is no
password prompt or manual seed copying during normal lab lifecycle commands.

The containers run as the invoking host UID/GID, with a read-only container
root, all Linux capabilities dropped, and `no-new-privileges`. The controller
still needs host root access through `sudo` to attach, format, mount, unmount,
and detach loop devices.

## Requirements

The host must be x86-64 Linux with:

- a running Docker daemon;
- `sudo` or a root shell;
- kernel loop-device and Btrfs support;
- the two prebuilt static MutualBackup binaries.

Enter the pinned runtime-tools shell before using the controller:

```sh
nix develop .#docker-lab
```

That shell supplies the Docker CLI, `btrfs-progs`, `util-linux` loop/mount
commands, and the ordinary shell utilities used by the controller. It does not
depend on the MutualBackup Nix package and therefore does not compile the
project. A development shell cannot provide privileged host services: the
Docker daemon, `sudo`/root authorization, and kernel loop-device and Btrfs
support must already exist on the host.

The default binary paths are:

```text
dist/mutualbackup-x86_64-linux
dist/mutualbackupd-x86_64-linux
```

They are the direct output contract of the source-defined Nix release target.
On a build machine or in CI, create the handoff directory with:

```sh
nix build .#lab-artifacts -o dist
```

Copy that output to the lab host with symlinks dereferenced (or use your normal
Nix artifact transfer). Starting the lab still performs no build.

`up` exits with a useful error if either artifact is absent. It never invokes
Cargo, Nix, a compiler, `docker build`, or a Dockerfile. On its first run it may
download the configured `debian:bookworm-slim` base image. If Nix artifacts are
elsewhere, supply absolute paths:

```sh
MUTUALBACKUP_CLI_BIN=/artifacts/mutualbackup \
MUTUALBACKUP_DAEMON_BIN=/artifacts/mutualbackupd \
  ./scripts/docker-lab.sh up
```

## Start the complete environment

From the repository root:

```sh
./scripts/docker-lab.sh up
```

The first run performs the complete deployment:

1. checks prerequisites and obtains one `sudo` authorization;
2. pulls the base container image if necessary;
3. creates the private Docker bridge;
4. creates five sparse image files and attaches five loop devices;
5. formats and mounts a distinct Btrfs filesystem for each node;
6. generates five distinct seeds, initializes each application-owned identity
   manifest, and writes five lab-managed configs;
7. creates and starts five daemon containers;
8. creates, joins, and finalizes the real fixed five-member guild; and
9. prints container state, IP addresses, ports, loop devices, and host paths.

`up` is resumable. Running it after `down` reattaches and mounts the existing
images, recreates containers, and resumes the same identities and guild. It
does not regenerate an existing recovery string or identity manifest. If a
first-time `up` stopped after writing a seed but before writing its manifest,
the next `up` resumes ordinary new-node initialization. `reinit` records its
recovery intent, original guild, bootstrap member, restore target, and current
phase before removing state. A later `up` or the same `reinit` command resumes
that transaction without another wipe and does not clear it until restore has
succeeded and the node has rejoined the original active guild. Guild formation
likewise resumes when some members installed the final certificate before the
coordinator. The controller rewrites its own lab configs from the selected
environment settings; do not hand-edit them.

New filesystem images are formatted under a `.creating` name and published
only after formatting and device sync complete. A later `up` safely restarts an
interrupted staged creation; it rejects an ambiguous completed-plus-staged pair
or an existing image that is not Btrfs. Every node `start`, `restart`, `up`, and
`down` verifies that the mount is a loop device attached to that node's exact
image.

If retained identity state exists but its corresponding file under `seeds/` is
missing, `up` refuses to invent a replacement. Restore that recovery string
from its offline copy before continuing.

## Run CLI commands

Use `cli NODE` instead of dealing with container names or control-socket paths:

```sh
./scripts/docker-lab.sh cli 0 status
./scripts/docker-lab.sh cli 0 guild status
./scripts/docker-lab.sh cli 1 snapshot list
./scripts/docker-lab.sh cli 2 --help
```

The controller runs the packaged CLI inside the selected container with the
correct `/node/run/control.sock`. Local peer credentials therefore match the
daemon even when the host account runs several nodes.

To inspect every node at once:

```sh
./scripts/docker-lab.sh status
```

To see deployment details without the longer MutualBackup status output:

```sh
./scripts/docker-lab.sh info
```

## Exchange files with each node

All five exchange directories are mounted automatically by `up` and unmounted
by `down`:

```sh
./scripts/docker-lab.sh mounts
```

For a machine-readable path to one node:

```sh
NODE1_EXCHANGE=$(./scripts/docker-lab.sh path 1)
printf '%s\n' "$NODE1_EXCHANGE"
```

The following two paths name the same Btrfs-backed directory:

```text
host:      .docker-lab/mounts/node1/exchange/
container: /node/exchange/
```

Copy and inspect files from the host normally. Pass the container path to
MutualBackup CLI operations:

```sh
mkdir -p "$NODE1_EXCHANGE/source/documents"
cp /path/to/a/test-file "$NODE1_EXCHANGE/source/documents/"

./scripts/docker-lab.sh cli 1 root add /node/exchange/source
./scripts/docker-lab.sh cli 1 backup --wait
```

The root-add operation executes the real reflink safety probe. Because the
exchange and node storage live in that node's Btrfs image, reflink capture is
available even when the Docker host's main filesystem is ext4.

Modify files and create another revision:

```sh
printf 'new contents\n' >"$NODE1_EXCHANGE/source/documents/example.txt"
./scripts/docker-lab.sh cli 1 backup --wait
./scripts/docker-lab.sh cli 1 snapshot list
```

Restore a local snapshot into another host-visible directory:

```sh
./scripts/docker-lab.sh cli 1 snapshot restore /node/exchange/snapshot-restore
find "$NODE1_EXCHANGE/snapshot-restore" -maxdepth 3 -type f
```

Do not alter `.mutualbackup-anchors-*` directories seen below a node mount.
They contain live reflink snapshot anchors managed by MutualBackup.

## Stop, start, and restart one node

These operations leave its Btrfs mount and container definition in place:

```sh
./scripts/docker-lab.sh stop 3
./scripts/docker-lab.sh status 3
./scripts/docker-lab.sh start 3
./scripts/docker-lab.sh restart 3
```

Use Docker logs without finding the generated container name:

```sh
./scripts/docker-lab.sh logs 3 --tail 100
./scripts/docker-lab.sh logs 3 --follow
```

An interactive container shell is also available:

```sh
./scripts/docker-lab.sh shell 3
```

The shell's root filesystem is deliberately read-only. Use `/node/exchange`
for test files.

## Erase and recover a node from its seed

`reinit` is the destructive failure/recovery exercise. It:

1. verifies that the node has published seed-recovery material to the DHT;
2. verifies that at least three responsive survivors report the same active
   guild;
3. removes the old container;
4. unmounts, detaches, and permanently deletes that node's Btrfs image;
5. creates and mounts a new empty Btrfs image;
6. retains the original seed, creates a new recovery identity manifest, and
   archives the previous config;
7. writes daemon options bootstrapping through a surviving peer;
8. creates a new container at the node's old IP with the same recovery-string identity;
9. recovers guild state and the latest owned revision over the real DHT/QUIC
   data path; and
10. restores it to `/node/exchange/recovered` by default.

The node must have at least one committed owned backup. Wait until its recovery
publication is ready:

```sh
until ./scripts/docker-lab.sh status 1 | grep -q '^recovery ready: true$'; do
  sleep 2
done
```

Because `reinit` erases the entire node image, it also erases that node's
exchange directory and original source. Copy any comparison checksum or test
oracle somewhere outside the node mount before continuing.

Run interactively and type the requested node name to confirm:

```sh
./scripts/docker-lab.sh reinit 1
```

For automation, bypass the prompt explicitly:

```sh
./scripts/docker-lab.sh reinit 1 recovered --yes
```

After success, inspect the recovered files directly on the host:

```sh
NODE1_EXCHANGE=$(./scripts/docker-lab.sh path 1)
find "$NODE1_EXCHANGE/recovered" -maxdepth 3 -type f
./scripts/docker-lab.sh status 1
```

The recovered directory is not automatically selected as a new protected root.
To continue backing it up, register it explicitly:

```sh
./scripts/docker-lab.sh cli 1 root add /node/exchange/recovered
```

If network recovery fails, `reinit` returns an error but deliberately retains
the recovery transaction and recovery identity's container. Inspect its logs,
restore enough same-guild survivors, and resume without another wipe using
either command:

```sh
./scripts/docker-lab.sh logs 1 --tail 200
./scripts/docker-lab.sh reinit 1 recovered --yes
# or simply:
./scripts/docker-lab.sh up
```

While a recovery transaction is pending, keep using its original restore name;
the controller rejects a different name instead of changing the durable target.

## Shut down and resume

Shut down the whole environment with:

```sh
./scripts/docker-lab.sh down
```

The controller first stops and removes its containers and bridge. It then
unmounts all five Btrfs filesystems and detaches every loop device associated
with the five image files. It never uses a lazy or forced unmount; if a host
shell or process is holding a mount busy, it tells you to close it and retry.
Before reusing or unmounting a mount point, it verifies that the mounted Btrfs
source is a loop device attached to that node's exact retained image. A foreign
mount at a lab path is rejected and left untouched.

The controller also marks and validates its `images`, `mounts`, `loops`,
`seeds`, and `configs` namespaces. It refuses every mutating command if one of
those directories, or a per-node mount path, has been replaced by a symlink or
foreign mount. Do not remove the `.mutualbackup-docker-lab-directory-v1`
marker files; an existing safe pre-marker lab is adopted on its first mutating
command.

`down` retains image files, configs, and seeds under `.docker-lab/`, so a later
`up` resumes the same data and identities. While down, the host mount-point
directories are present but the Btrfs contents are not mounted.

To discard the lab completely, first run `down`, verify the printed lab root,
and then remove that exact directory yourself. Remember that this also deletes
all five retained test seeds and all Btrfs images.

## Configuration knobs

Set these environment variables consistently for every command in a lab:

| Variable | Default | Effect |
| --- | --- | --- |
| `MUTUALBACKUP_DOCKER_LAB_ROOT` | `.docker-lab` in the repository | Retained images, mounts, configs, and seeds. Use a different path for an independent lab. |
| `MUTUALBACKUP_CLI_BIN` | `dist/mutualbackup-x86_64-linux` | Absolute path to the prebuilt CLI artifact. |
| `MUTUALBACKUP_DAEMON_BIN` | `dist/mutualbackupd-x86_64-linux` | Absolute path to the prebuilt daemon artifact. |
| `MUTUALBACKUP_LAB_IMAGE` | `debian:bookworm-slim` | Pulled runtime container image; it is never built by the controller. |
| `MUTUALBACKUP_LAB_DISK_SIZE` | `1G` | Size of each newly created sparse Btrfs image. Existing images are not resized. |
| `MUTUALBACKUP_LAB_PARITY_BUDGET_BYTES` | `536870912` | Per-node parity-store budget written into new configs. |
| `MUTUALBACKUP_LAB_IP_PREFIX` | `172.30.77` | First three octets of the private `/24` Docker bridge. Change it if the subnet overlaps another Docker network. |
| `MUTUALBACKUP_LAB_P2P_BASE_PORT` | `44000` | First internal UDP/QUIC port; node N uses this value plus N. |

The lab name is derived from its absolute lab-root path, allowing independent
lab roots to use distinct container and bridge names. Their IP subnets must
also be distinct.

## Troubleshooting

- **A binary is missing:** copy the Nix-produced release artifacts into `dist/`
  or set the two binary path variables. `up` will not build them for you.
- **Docker subnet overlap:** choose an unused three-octet private prefix and use
  it consistently for `up`, interaction commands, and `down`.
- **A node will not start:** inspect `logs NODE`. Common causes are a manually
  modified config, missing recovery string, or stale foreign container with the same name.
- **Btrfs will not mount:** ensure both `loop` and `btrfs` kernel modules are
  available and that `btrfs-progs` is installed.
- **Unmount says busy:** leave any shell whose current directory is inside a
  node mount and close programs holding files there; then run `down` again.
- **Recovery readiness remains false:** keep all nodes running after a committed
  backup and allow time for DHT publication. Inspect peer connections and logs.
- **Recovery has insufficient peers:** start at least three other guild nodes;
  keeping all four survivors running is recommended.
