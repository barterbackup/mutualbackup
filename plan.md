# Mutual P2P Backup — implementation plan

Working plan based on `mutual-p2p-backup-design.md` and the older Rust code in
`/home/user/barterbackup/rust`. Protocol choices below are provisional: record
them as ADRs and test vectors before promising wire compatibility.

## 1. Direction and first decisions

- Start a new layered Rust workspace; transplant small proven utilities rather
  than extending BarterBackup's whole-blob core. Keep one user-facing binary.
- Protect an ordinary folder using scanning and reflink/copy snapshots—no FUSE,
  custom filesystem, or kernel component.
- Prototype separate seed-derived **user identity** and replaceable **device
  identities**. For v1, consider one revision writer per user and preserve any
  detected forks. This needs an ADR before implementation.
- Derive versioned keys for identity, mailbox encryption, metadata, and each
  `(user, guild)` data context. Peers and coordinators only handle ciphertext.
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
| User revisions | Signed by the user/device and replicated with recoverable guild state |
| Guild state | Members retain the latest authenticated state/checkpoint and recent signed events; old history is compacted |
| Coordinator state | Temporary encrypted inputs/staging only; the coordinator is never authoritative |
| DHT and relay | DHT stores short-lived encrypted discovery hints; relay stores no data and forwards opaque encrypted traffic |

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
  record. Keep one DHT record per publisher so writers cannot overwrite each
  other. Metadata acceptance never counts as proof that bytes are stored.

## 4. Protocol and data lifecycle

1. **Join/sync:** exchange an out-of-band guild invite, authorize membership,
   authenticate a device, negotiate capabilities, then gossip signed events and
   checkpoints. Current layouts are explicit; never recreate them by rerunning
   an old placement algorithm.
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
   peers → valid current guild state and revision → any `k` valid shards →
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

- Hide paths behind a transport/session interface keyed by stable Node ID.
  Maintain a small gossip overlay; open bulk streams only when needed.
- As a provisional spike, try authenticated QUIC over direct IPv6/LAN/public
  candidates. A reachable guild rendezvous peer exchanges signed, expiring
  candidates and a nonce/deadline; both endpoints then send simultaneous UDP
  probes from the intended socket (ICE-style hole punching).
- Canonically collapse simultaneous connections, cache good paths, and retry
  changed mappings with bounded backoff. When punching fails, use a
  bandwidth-limited guild relay carrying an end-to-end authenticated/encrypted
  session, then periodically retry direct connectivity.
- The DHT is discovery only, never authority or bulk storage. Ship replaceable
  bootstrap sources and document the real recovery condition: a usable DHT
  path, at least one live discovery publisher, and enough live shard holders.
  Tor can later be an optional transport/privacy fallback.

## 6. What to reuse from BarterBackup

| Treatment | Older Rust material |
| --- | --- |
| Reuse/extract | `crates/clock` and `ManualClock`; the small filesystem abstraction and temp-file + fsync + rename atomic-write pattern from `crates/storage`; data-dir locking/permissions; Nix, protobuf build, property/fuzz, and Docker harness patterns |
| Adapt | Transport trait, retry budgets, duplicate-session tie-breaking, bounded sessions, and `netmock`; daemon supervision/cancellation; CAS read-refresh-retry; recovery-before-publication; latest-known vs actually-stored state; quota admission, receipts, audit, failure injection, and significant-event logging |
| Replace | `crates/content`, most of `storage::Store`, old peer/stored schemas, monolithic `crates/node`, wall-clock lineage recovery, 4 MiB whole-blob RPC model, Tor/onion identity assumptions, and peer scoring as the placement core |

Keep the domain-separated KDF and test-vector principles from `crates/keys`,
but redesign the recovery-secret format, KDF parameters, key hierarchy, and key
types. Do not copy `crates/tlsutil`: its custom rustls callbacks accept TLS
handshake signatures without verifying them. Use a reviewed authenticated
handshake and separately authorize the device as a guild member. Copied code
must retain the older repository's MIT notice.

## 7. Delivery phases

1. **ADRs and risk spikes:** identity/membership/threat model, canonical format
   vectors, Merkle/encryption/RS benchmark, and direct/punch/relay prototype.
2. **Offline vertical slice:** ordinary-folder snapshot → encrypted hierarchy
   and metadata → signed revision → RS encode → lose a shard → restore; include
   atomic storage, reference tracking, and crash-point tests.
3. **Five-node simulation:** invite/join, `3+2` groups, signed state commits,
   coordinator failure, duplicate calls, edits/deletes, corruption, partitions,
   emergency repair, migration, and GC using `ManualClock` and expanded
   `netmock`.
4. **Real network:** DHT provider records, gossip, streaming transfers, direct
   QUIC, hole punching, and relay, tested in Docker/network namespaces across
   common and symmetric NAT cases.
5. **Recovery MVP and hardening:** erase a member's whole local state and
   restore with only the seed plus any `k` surviving shards. Then fuzz parsers,
   property-test split/coalesce and any-`k` recovery, test cross-platform
   metadata, soak large trees/small edits, and add rotation/revocation limits.

Before freezing v1, decide the remaining compatibility gates: sector and
encryption regeneration rules; RS matrix/extensible rows and availability-based
`k/m`; user/device forks; membership/removal/quorum; retention, quota, and
deletion policy; DHT privacy/bootstrap/TTL; relay abuse controls; audit cadence;
coordinator failover; and the portable restore metadata set.
