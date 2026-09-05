# Mutual P2P Backup — implementation plan

Working plan based on `mutual-p2p-backup-design.md` and the older Rust code in
`/home/user/barterbackup/rust`. Protocol choices below are provisional: record
them as ADRs and test vectors before promising wire compatibility.

## 1. Direction and first decisions

- Start a new layered Rust workspace; transplant small proven utilities rather
  than extending BarterBackup's whole-blob core. Keep one user-facing binary.
- Protect an ordinary folder using scanning and reflink/copy snapshots—no FUSE,
  custom filesystem, or kernel component.
- Use one stable seed-derived Ed25519 **peer identity** across direct, relayed,
  and Tor sessions. Use that same key as the Arti Tor v3 hidden-service
  identity, so the Node ID deterministically maps to its `.onion` address, as
  in BarterBackup. Keep revision, mailbox, metadata, and `(user, guild)` data
  keys domain-separated. Treat one live node as the writer for that identity
  in v1; separately certified multi-device identities remain a later ADR.
- Assume social trust but verify all data and transitions; tolerate buggy or
  dishonest peers, replay, corruption, crashes, and partitions.
- Use a fixed test profile first (for example 4 KiB minimum sectors and RS
  `3+2`), then benchmark sector size, `k/m`, and extensible parity. Never place
  two shards of one group in the same physical failure domain.
- Begin with ordinary quorum signatures for important guild changes. Leave a
  compatible authorization interface for FROST once membership and recovery
  policy are stable.

## 2. State ownership

| Item | Who keeps it |
| --- | --- |
| Plaintext and recovery seed | Plaintext stays in the user's selected folder/devices; the seed has offline backup and never enters the DHT |
| Active source snapshot | The owner retains a reflink or safe copy until all referencing layouts are retired |
| Information sectors | Guild-specific encrypted form normally comes from its owner; after owner-disk loss it is reconstructed from the coding group |
| Private file metadata | Encrypted as user-owned information sectors and protected by the same coding machinery |
| Parity sectors | Assigned peer or storage-only node, according to the explicit guild layout |
| User revisions | Signed by an identity-authorized revision key and replicated with recoverable guild state |
| Guild state | Members retain the latest authenticated state/checkpoint and recent signed events; old history is compacted |
| Coordinator state | Temporary encrypted inputs/staging only; the coordinator is never authoritative |
| DHT and relay | DHT stores short-lived encrypted endpoint hints, including the stable onion address when available; relay stores no data and forwards opaque encrypted traffic |

Proposed simplification: a `UserRevision` describes only that user's logical
data. Membership, revision heads, coding groups, parity assignments, and
tombstones belong to guild state. Both must be recoverable from peers; a DHT
record is only a pointer toward them. This avoids the feedback loop in the old
system where peer inventory changed the owner's content revision.

A local database may cache paths, Merkle nodes, inventories, reachability, and
jobs, but must be disposable. Each guild has independent ciphertext, layout,
quota, and state even when local scanning work is shared.

## 3. Formats to specify first

Use a canonical encoding for hashed/signed records; protobuf can frame RPCs,
but arbitrary protobuf serialization must not be signed. Every durable record
carries format and algorithm versions, scope, type, and lengths. Publish golden
vectors for hashes, signatures, encryption, Merkle trees, and RS.

- **Sector/Merkle object:** power-of-two logical size, encoding and key epoch,
  nonce/salt material, ciphertext hash/root, and domain-separated leaf/parent
  hashes. Define canonical split/coalesce, tails, padding, sparse ranges, and
  AEAD overhead. Code the exact ciphertext representation and make unchanged
  committed sectors reproducible.
- **Private metadata:** safe relative paths, file/directory/symlink type,
  ordered sector references, logical size, sparse extents, timestamps, and a
  portable attribute subset. Restore symlinks only under an explicit safe
  policy that prevents path escape.
- **UserRevision:** owner, monotonic revision, optional parent, metadata root,
  compact information-sector forest, suite versions, and signature.
- **CodingGroup:** stable ID, shard size, versioned RS construction and row IDs,
  `k/m`, canonical ordered roles, sector roots, nodes, and failure domains.
- **Guild state:** signed membership/revocation events plus authenticated state
  commits and periodic checkpoints containing explicit current/temporary
  groups and tombstones. A normal update must not wait for a periodic
  checkpoint; the checkpoint later compacts committed state.
- **Storage and discovery records:** quota reservation, durable shard receipt,
  retention promise, operation ID, and a signed/encrypted/expiring DHT provider
  record. The provider record carries the peer identity plus current IP/QUIC,
  relay, and onion endpoints. Keep one record per publisher so writers cannot
  overwrite each other, and verify that an onion address matches its identity.
  Metadata acceptance never counts as proof that bytes are stored.

## 4. Protocol and data lifecycle

1. **Join/sync:** exchange an out-of-band guild invite, authorize membership,
   authenticate the peer identity, negotiate capabilities, then gossip signed
   events and checkpoints. Current layouts are explicit; never recreate them by
   rerunning an old placement algorithm.
2. **Protect/commit:** scan a stable snapshot, build encrypted sectors and a
   draft revision, select equal-size sectors from different users, reserve
   quota, and stream them to a temporary coordinator. Destinations durably
   stage and verify parity, then return signed receipts. An authenticated state
   commit activates the revision/groups; old protection remains active.
3. **Transfer/concurrency:** stream immutable objects and ranges with Merkle
   proofs. Mutations carry an idempotency key and expected state hash; repeats
   return the previous result, while ambiguous results cause read/refresh rather
   than blind overwrite.
4. **Audit/repair:** use unpredictable range challenges, Merkle verification,
   and RS checks, with occasional full scrubs. Repair, emergency parity, and
   migration reuse the same stage/verify/receipt/commit flow.
5. **Recover:** seed → identity → deterministic DHT lookup → authenticated guild
   peers over the best working IP, relay, or onion path → valid current guild
   state and revision → any `k` valid shards →
   verify/reconstruct/decrypt → restore into a safe staging tree → rebuild local
   caches. Recovery mode blocks mutation/publication until explicitly finished.

Object lifecycle:

`staged → uploaded → verified/receipted → committed/active → superseded → grace period → GC`

Edits and deletions expand only affected Merkle branches, replace their groups,
commit new state, and later re-coalesce compatible survivors. GC removes only
objects unreachable from all active/retained revisions and layouts after the
grace period. Remote secure erasure cannot be proved; deletion ends the storage
obligation and requests best-effort removal.

During outages, keep the old layout while adding temporary protection among
reachable domains. Remove it when peers return or migrate safely if the outage
persists. Guild growth supplies new placement, parity, repair, and gradual
migration; it must not force rewriting old groups. Schedule all work with
weighted fairness plus aging, bounded concurrency, and per-guild disk/network
quotas, so cleanup and audits cannot starve forever.

## 5. Networking and hole punching

- Hide paths behind a common authenticated stream/session interface keyed by
  the stable Node ID. Maintain a small torrent-like peer-exchange/gossip
  overlay, remember several endpoints per peer, fetch independent shards in
  parallel, resume interrupted ranges, and open bulk streams only when needed.
- In the default automatic mode, race or try paths with bounded time budgets in
  this order: existing/direct IPv6, LAN, or mapped public connection (including
  PCP/NAT-PMP/UPnP mappings when enabled); rendezvous-assisted
  UDP hole punching; a bandwidth-limited relay through a reachable guild peer;
  then the peer's Tor onion service. Cache successful paths and periodically
  retry a faster direct path without disrupting a working relay/onion session.
- For hole punching, a guild rendezvous peer exchanges signed, expiring
  candidates plus a nonce/deadline, and both endpoints send simultaneous probes
  from the intended QUIC socket. Canonically collapse simultaneous sessions.
  Relay and Tor paths still run the same end-to-end peer authentication and
  application protocol; intermediaries gain no storage authority.
- Also support an explicit per-node or per-operation policy to prefer Tor or
  require Tor even when an IP path works, plus a policy to disable it. When
  automatic Tor fallback is enabled, bootstrap Arti and publish the onion
  service in the background at unlock rather than waiting for other paths to
  fail, so the slow fallback is ready and advertised when needed.
- Embed Arti for both outbound onion dials and the inbound onion service. Keep
  its directory/cache state persistent, inject the deterministic identity key
  into an ephemeral keystore, supervise/restart the runtime, and expose Tor
  readiness separately from general node readiness. Multiplex logical streams
  over long-lived onion connections to amortize Tor setup cost.
- DHT records and guild gossip advertise a signed endpoint set with priorities,
  expiry, capabilities, and the `.onion` derived from the same peer public key.
  A recovering node tries ordinary endpoints/relays and falls back to the onion
  address when they fail, or uses Tor immediately when requested. The DHT is
  discovery only, never authority or bulk storage.
- Ensure discovery itself has a Tor path: DHT/provider queries must work over
  the common stream abstraction, or records must be mirrored by onion-reachable
  rendezvous nodes. Ship several replaceable IP and onion bootstrap endpoints;
  otherwise a DHT containing onion addresses would not help an IP-blocked
  recovery. Document the remaining condition that some discovery route and
  enough shard holders must be reachable. Onion services avoid inbound NAT
  requirements but still depend on the Tor network being available.

## 6. What to reuse from BarterBackup

| Treatment | Older Rust material |
| --- | --- |
| Reuse/extract | `crates/clock` and `ManualClock`; the small filesystem abstraction and temp-file + fsync + rename atomic-write pattern from `crates/storage`; data-dir locking/permissions; Nix, protobuf build, property/fuzz, and Docker harness patterns |
| Adapt | Transport trait, retry budgets, duplicate-session tie-breaking, bounded sessions, and `netmock`; `crates/nettor`'s embedded Arti client, deterministic onion service, stream adapter, cache/ephemeral-key split, and runtime supervision; CAS read-refresh-retry; recovery-before-publication; latest-known vs actually-stored state; quota admission, receipts, audit, and failure injection |
| Replace | `crates/content`, most of `storage::Store`, old peer/stored schemas, monolithic `crates/node`, wall-clock lineage recovery, 4 MiB whole-blob RPC model, the Tor-only/onion-string connector, and peer scoring as the placement core |

Keep the domain-separated KDF and test-vector principles from `crates/keys`,
including the test that the Node ID-derived onion hostname equals Arti's hidden
service ID. Adapt `nettor`'s conversion of the Ed25519 secret to `HsIdKeypair`
and its shared inbound/outbound `TorClient`, but use a maintained Arti release
and revalidate its state handling rather than copying the custom fork and
hard-coded cleanup paths blindly. Redesign the recovery-secret format, KDF
parameters, and non-identity keys. Do not copy `crates/tlsutil`: its custom
rustls callbacks accept TLS handshake signatures without verifying them. Use a
reviewed authenticated handshake and authorize the identity as a guild member.
Copied code must retain the older repository's MIT notice.

## 7. Delivery phases

1. **ADRs and risk spikes:** identity/membership/threat model, canonical format
   vectors, Merkle/encryption/RS benchmark, and direct/punch/relay/onion
   prototype.
2. **Offline vertical slice:** ordinary-folder snapshot → encrypted hierarchy
   and metadata → signed revision → RS encode → lose a shard → restore; include
   atomic storage, reference tracking, and crash-point tests.
3. **Five-node simulation:** invite/join, `3+2` groups, signed state commits,
   coordinator failure, duplicate calls, edits/deletes, corruption, partitions,
   emergency repair, migration, and GC using `ManualClock` and expanded
   `netmock`.
4. **Real network:** DHT endpoint records, peer exchange, resumable transfers,
   direct QUIC, hole punching, guild relay, and embedded Arti onion service.
   Test automatic fallback, explicit Tor preference/requirement, restart with a
   stable onion identity, and DHT-seeded onion recovery in Docker/network
   namespaces across common and symmetric NAT cases.
5. **Recovery MVP and hardening:** erase a member's whole local state and
   restore with only the seed plus any `k` surviving shards. Then fuzz parsers,
   property-test split/coalesce and any-`k` recovery, test cross-platform
   metadata, soak large trees/small edits, and add rotation/revocation limits.

Before freezing v1, decide the remaining compatibility gates: sector and
encryption regeneration rules; RS matrix/extensible rows and availability-based
`k/m`; multi-device identity/forks; membership/removal/quorum; retention,
quota, and deletion policy; DHT privacy/bootstrap/TTL and endpoint freshness;
connection racing/fallback policy; Tor configuration and resource limits;
relay abuse controls; audit cadence; coordinator failover; and the portable
restore metadata set.
