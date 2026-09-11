# ADR 0001: Arti as a libp2p onion transport

- Status: accepted for Milestone 3
- Date: 2026-09-11

## Decision

MutualBackup carries its existing libp2p stack over Tor rather than defining a
second peer protocol. An onion connection has this stack:

```text
signed MutualBackup CBOR + Kademlia + Identify
                    yamux
                    Noise
      Arti DataStream to a v3 onion service
```

QUIC, relay, and DCUtR remain alternative transports in the same libp2p
`Swarm`. Noise authenticates the same seed-derived Ed25519 key on every path,
so an onion session has the same Node ID and libp2p Peer ID as an IP session.
The same Ed25519 secret is expanded into Arti's `HsIdKeypair`; consequently the
v3 onion hostname encodes the Node ID public key rather than introducing a
second durable identity.

Onion endpoints use the standard multiaddress form
`/onion3/HOST:443/p2p/PEER_ID`. They are signed in the existing
`EndpointRecord`, published in Kademlia, included in sealed recovery locators,
and shared as signed records by peer exchange. Receiving an endpoint from any
of those channels never makes it authoritative: its signature, publisher,
sequence, expiry, onion/Node-ID binding, and terminal Peer ID are checked before
use.

The connection policy is one of:

- `auto` (default): prefer direct, hole-punched, or relayed IP connectivity and
  use onion connectivity after those paths fail.
- `prefer-tor`: prefer onion connectivity and retain IP as fallback.
- `require-tor`: advertise, accept, discover, and dial peers only through Tor;
  daemon readiness requires a reachable onion service.
- `disable-tor`: do not construct Arti or accept onion addresses.

When two transports connect the same Peer ID, keep the policy-preferred session
and close the redundant one once in-flight application work permits. This
prevents duplicate sessions from making request routing and accounting
arbitrary. Tor is reported as a distinct application path with bounded session,
byte, failure, and latency counters.

## Arti version and API boundary

Pin the mutually compatible Arti crates to exactly `0.46.0` (Arti application
release 2.6.0, published 2026-09-02) and raise the workspace MSRV to Rust 1.91,
which that release requires. Use only crates from the Tor Project release, not
BarterBackup's old custom fork.

The reviewed integration boundary is deliberately small:

- `arti-client`: one shared Tokio `TorClient`, outbound `.onion` streams,
  bootstrap status, and onion-service launch;
- `tor-hsservice`: service configuration, reachability status, bounded
  rendezvous/stream acceptance, and `BEGIN` port validation;
- `tor-hscrypto` and `tor-llcrypto`: conversion of the existing Ed25519 secret
  into `HsIdKeypair`;
- `tor-keymgr`: an ephemeral primary keystore;
- `tor-config` and `tor-config-path`: optional operator-supplied network,
  authority, bridge, and pluggable-transport configuration;
- `tor-cell`, `tor-proto`, and `tor-rtcompat`: the accepted stream and Tokio
  adapter types needed at the transport boundary.

Arti 0.46 still marks supplied-HSID launch, ephemeral keystores, and stop
supervision as experimental APIs. Exact pins prevent accidental API drift;
every Arti upgrade therefore requires a source review, private-network gate,
and explicit pin update. Arti also documents that obsolete versions may
terminate their embedding process when instructed by consensus, so prompt
upgrades are an operational requirement.

## State and supervision

By default, Arti owns `data_dir/tor/cache` and `data_dir/tor/state`, both under
the daemon's private data directory. Public directory data, guards, and other
non-identity client state survive restarts. The primary keystore is forced to
ephemeral operation, and the derived onion identity is injected after unlock;
it is never written to an Arti keystore. Only stale state belonging to
MutualBackup's one onion-service nickname may be pruned when an ephemeral-key
restart requires it. Shared cache/state and other service namespaces must not
be deleted.

Bootstrap and onion-service reachability are supervised independently. The
transport advertises its onion listener only while Arti reports it reachable,
withdraws it on an unreachable transition, and keeps retrying. `auto` and
`prefer-tor` may become ready through IP while reporting Tor degradation;
`require-tor` may not. Dropping the daemon cancels acceptance and supervision
tasks and drops the running onion service.

An operator Arti TOML file may describe private authorities, fallback caches,
bridges, or pluggable transports. Relative daemon option paths follow the
daemon-config path rule. MutualBackup supplies default state/cache directories
when absent and rejects or overrides any persistent primary keystore so the
identity lifecycle cannot be weakened by configuration.

## Discovery and acceptance gate

Configured bootstrap addresses are replaceable entry points, not authorities,
and may themselves be onion multiaddresses. A recovering node must be able to
enter Kademlia through such an onion bootstrap, obtain signed onion endpoints
and recovery records, validate guild state, fetch enough shards, and restore
without any working peer IP path. Peer exchange provides a bounded alternate
source of signed endpoint records after the first authenticated session; it
does not replace seed-only recovery or signature validation.

The Milestone 3 gate uses a private Tor network, blocks every peer IP path,
restarts onion-serving peers to prove hostname stability, erases one node's
state and source, and performs seed-only recovery through onion bootstrap and
onion shard transfer. It must assert Tor path attribution rather than infer it
from configuration.

## Rejected alternatives

- A separate Tor RPC/TLS protocol would duplicate authorization, framing,
  bounds, recovery, and observability, and could diverge from the IP protocol.
- SOCKS-only outbound support would not make peers or bootstrap infrastructure
  always reachable.
- A separately derived onion key would create another identity and recovery
  invariant.
- Persisting the onion key in Arti would duplicate the seed-derived secret on
  disk and make seed rotation/recovery semantics ambiguous.

