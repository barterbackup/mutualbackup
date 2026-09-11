# Tor and onion connectivity

MutualBackup embeds Arti in `mutualbackupd`; a normal deployment does not need
an external `arti` or `tor` program. Onion sessions carry the same Noise,
yamux, libp2p, DHT, and MutualBackup request protocols as IP sessions. The
recovery string derives both the existing node identity and its deterministic
v3 onion identity, so restarting or recovering a node preserves both its Node
ID and onion hostname.

This remains beta software. Keep an offline recovery string and do not entrust
unique data to it.

## Choose a policy

Set `tor_mode` in the daemon TOML, or pass the equivalent `--tor-mode` option:

| Mode | Behavior |
| --- | --- |
| `auto` | Prefer direct, hole-punched, or relayed IP; use Tor as fallback |
| `prefer-tor` | Prefer Tor and retain IP as fallback |
| `require-tor` | Advertise, discover, accept, and dial only over Tor |
| `disable-tor` | Do not start Arti or accept onion addresses |

`auto` is the default. In `require-tor` mode, IP listen and external addresses
may be empty. At least one IP listener or relay is required when Tor is
disabled.

For a public Tor deployment, the minimal additions to the normal node config
are:

```toml
tor_mode = "auto"

# Full bootstrap addresses always include the peer identity.
p2p_bootstrap_addresses = [
  "/onion3/EXAMPLE56CHARACTERHOST:443/p2p/EXAMPLE_PEER_ID",
]
```

Obtain a peer's exact advertised address from `mutualbackup status`; do not
construct or edit the hostname by hand. Bootstrap entries are replaceable
discovery paths rather than protocol authorities. Signed endpoint records and
sealed recovery locators allow the node to learn other guild onion addresses
after the first authenticated connection.

## State and identity

Arti uses `data_dir/tor/state` and `data_dir/tor/cache` by default. Override
them with `tor_state_dir` and `tor_cache_dir` only when the directories are
private, owned by the daemon user, distinct, and not shared with another
daemon. Directory data, guards, and other client state persist across
restarts. The onion-service secret is injected into an ephemeral Arti keystore
after unlock and is not stored as a second identity secret.

`arti_config_file` is optional on the public Tor network. It is intended for
custom authorities, bridges, pluggable transports, and test networks. A
persistent primary keystore in that file is rejected or replaced with the
ephemeral policy.

## Observe connectivity

Run:

```sh
mutualbackup --socket /path/to/control.sock status
```

The output reports the configured Tor policy, onion-service reachability,
advertised addresses, active session paths, degradation reasons, dial failures,
request latency, and application bytes. `require-tor` does not declare the
network ready until its onion service is reachable. `auto` and `prefer-tor`
can remain ready through IP while reporting Tor degradation.

Tor is slower and transient circuit or descriptor failures are normal. The
daemon supervises bootstrap and publication, retries connections, withdraws an
onion advertisement while the service is unreachable, and republishes it after
recovery.

## Run the private-Tor gate

The repository pins Chutney and a compatible Tor/Arti toolset in a Nix shell.
The gate creates a fresh private consensus, starts five real MutualBackup
daemons with no IP application path, transfers coded data, restarts their onion
services, erases two nodes, and restores one from only its recovery string and
an onion bootstrap address.

Provide a disposable mounted Btrfs filesystem, then run:

```sh
MUTUALBACKUP_REFLINK_TEST_ROOT=/mnt/disposable-btrfs \
  nix develop .#private-tor -c bash scripts/private-tor-acceptance.sh
```

The shell supplies the fixture dependencies but entering it does not build the
MutualBackup binaries. The test itself compiles its Rust test target, starts and
stops Chutney, and removes successful fixture state. On failure it prints the
preserved private-Tor directory; MutualBackup daemon logs remain under the
disposable Btrfs root for diagnosis. Initial private-consensus bootstrap and
the onion recovery scenario each take several minutes.

The detailed security and transport rationale is in
[ADR 0001](adr/0001-tor-libp2p-transport.md).
