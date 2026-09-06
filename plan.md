# Mutual P2P Backup — implementation plan

Working plan based on `mutual-p2p-backup-design.md` and the older Rust code in
`/home/user/barterbackup/rust`. Protocol choices below are provisional: record
them as ADRs and test vectors before promising wire compatibility.

## 1. Direction and first decisions

- Start a new layered Rust workspace; transplant small proven utilities rather
  than extending BarterBackup's whole-blob core. Keep one user-facing binary.
- Protect an ordinary folder with two source-anchor backends: COW through a
  runtime-probed reflink/clone, or guarded link-freeze through a same-filesystem
  hard link plus user-reversible write protection. Probe the complete lifecycle
  when a root is added and reject it if neither backend works. Never make an
  eager full copy merely to protect a file; no FUSE, custom filesystem, or
  kernel component is required for v1.
- Use a pinned SQLCipher/SQLite build as the common local storage engine, with
  per-page HMAC enabled. Keep control state separate from per-volume parity
  databases so independent local filesystems can be added, drained, or lost.
- Use one stable seed-derived Ed25519 **peer identity** across direct, relayed,
  and Tor sessions. Use that same key as the Arti Tor v3 hidden-service
  identity, so the Node ID deterministically maps to its `.onion` address, as
  in BarterBackup. Keep revision, mailbox, metadata, and `(user, guild)` data
  keys domain-separated. Treat one live node as the writer for that identity
  in v1; separately certified multi-device identities remain a later ADR.
- Make **seed-only recovery** a v1 invariant and the acceptance test for the
  first complete vertical slice. Starting with the seed, an empty data
  directory, and only generic software bootstrap configuration, a node must
  derive its identity, find its guild peers without a cached guild ID or peer
  list, rebuild its authenticated state and keys, retrieve any sufficient set
  of shards, and restore its data. No indispensable recovery material may live
  only in `control.db` or the source folder.
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
| Plaintext and recovery seed | Plaintext stays on the owner's selected filesystem, in the working folder or restricted source-anchor area; the seed has offline backup and never enters the DHT. The seed alone derives the stable identity and recovery-decryption roots |
| Active source anchor | The owner retains a COW clone/snapshot, a write-protected hard link to the working inode, or a sparse private copy made when that inode is unlocked, until all referencing layouts are retired |
| Information sectors | Guild-specific encrypted form normally comes from its owner; after owner-disk loss it is reconstructed from the coding group |
| Private file metadata | Encrypted as user-owned information sectors and protected by the same coding machinery |
| Parity sectors | Assigned peer or storage-only node; that host stores the exact RS-level bytes as locally SQLCipher-encrypted chunks on a selected volume |
| Virtual zero extents | Nobody stores payload or earns storage credit; peers synthesize them from the authenticated layout |
| User revisions | Signed by an identity-authorized revision key and replicated with recoverable guild state |
| Guild state | Members retain the latest authenticated state/checkpoint, recent signed events, per-member recovery key envelopes/catalogs, and enough layout/revision metadata to rebuild a lost member; old history is compacted |
| Coordinator state | Temporary encrypted inputs/staging only; the coordinator is never authoritative |
| DHT and relay | DHT stores independently published, short-lived encrypted endpoint and per-member recovery-rendezvous hints, including stable onion addresses; relay stores no data and forwards opaque encrypted traffic |

Proposed simplification: a `UserRevision` describes only that user's logical
data. Membership, revision heads, coding groups, parity assignments, and
tombstones belong to guild state. Both must be recoverable from peers; a DHT
record is only a pointer toward them. This avoids the feedback loop in the old
system where peer inventory changed the owner's content revision.

The local `control.db` keeps the working file catalog, source-root and anchor
registry, native volume/file IDs and known paths, desired file properties,
size/change hints, watcher cursors, jobs/outbox, volume registry, inventories,
reachability, byte-exact signed guild records, and normalized query views.
Signed records—not reconstructed SQL rows—remain protocol authority. Derived
caches are disposable, and no recovery seed, indispensable key, current
private metadata, or guild state may exist only in this database. Each guild
has independent ciphertext, layout, quota, and state even when local scanning
work is shared.

Define a versioned, checksummed seed format before storing real data. Rotatable
user/guild keys and historical epochs are kept in encrypted envelopes to a
seed-derived recovery public key, committed by signed guild state, and
replicated by peers; recovery must not depend on a salt, counter, key version,
or manifest found only on the lost machine.

## 3. Formats to specify first

Use a canonical encoding for hashed/signed records; protobuf can frame RPCs,
but arbitrary protobuf serialization must not be signed. Every durable record
carries format and algorithm versions, scope, type, and lengths. Publish golden
vectors for hashes, signatures, encryption, Merkle trees, and RS.

The protocol byte flow is owner plaintext → owner encryption → RS over the
encrypted information sectors → Merkle-committed information/parity sectors.
A storage host then adds transparent local SQLCipher encryption. Peers exchange
only the exact RS-level bytes, never SQLCipher pages. Protocol encryption need
not add its own authentication tag if every range is verified against a Merkle
root authenticated by the signed revision/coding-group state before use.

- **Sector/Merkle object:** power-of-two logical size, encoding and key epoch,
  nonce/salt material, ciphertext hash/root, and domain-separated leaf/parent
  hashes. Define canonical split/coalesce, tails, padding, sparse ranges, and
  encryption framing. Code the exact ciphertext representation and make
  unchanged committed sectors reproducible.
- **Virtual zero extent:** provisionally model an aligned `Zero(length)` at the
  exact byte representation consumed by RS, not as encrypted plaintext zeros.
  Bind its position and length into a new immutable layout/object generation
  and define canonical, precomputable Merkle roots. Benchmark this protocol
  feature before v1; a fully unreachable sector should simply be deleted.
- **Private metadata:** safe relative paths, file/directory/symlink type,
  ordered sector references, logical size, sparse extents, timestamps, and a
  portable attribute subset. Restore symlinks only under an explicit safe
  policy that prevents path escape. Native file IDs, anchor paths, enforcement
  permissions, and watcher cursors are local catalog state, never portable
  signed recovery fields.
- **UserRevision:** owner, monotonic revision, optional parent, metadata root,
  compact information-sector forest, suite versions, and signature.
- **CodingGroup:** stable ID, shard size, versioned RS construction and row IDs,
  `k/m`, canonical ordered roles, sector roots, nodes, and failure domains.
- **Guild state:** signed membership/revocation events bind each stable Node ID
  to its recovery public key. Authenticated commits and periodic checkpoints
  contain explicit current/temporary groups, tombstones, and the quorum-bound
  active `(writer epoch, incarnation public key)` for each identity. A normal
  update must not wait for a periodic checkpoint; the checkpoint later compacts
  committed state.
- **Recovery capsule:** a content-addressed, per-member bundle binds the member
  identity to checkpoint/event-tail heads, private revision-catalog and layout
  roots, and encrypted envelopes for every required historical key epoch. It is
  quorum-committed and replicated by peers; it tells a blank node what signed
  objects to fetch and verify but is not itself a substitute for those objects.
- **Storage and discovery records:** quota reservation, durable shard receipt,
  retention promise, operation ID, and a signed/encrypted/expiring DHT provider
  record. The provider record carries the peer identity plus current IP/QUIC,
  relay, and onion endpoints. Keep one record per publisher so writers cannot
  overwrite each other, and verify that an onion address matches its identity.
  In addition, every guild peer independently refreshes an opaque recovery
  rendezvous record under a key deterministically derived from the subject's
  public Node ID. It is encrypted to that member's seed-derived recovery key
  and contains the publisher's endpoints plus an opaque locator for the
  subject's replicated recovery capsule/checkpoint, without exposing a guild ID
  in cleartext. Thus lookup needs no remembered guild ID. Metadata acceptance
  never counts as proof that bytes are stored, and DHT contents never become
  authority.

## 4. Local source snapshots, persistence, and storage volumes

### Source capture

Each active information-shard role needs a stable **regeneration anchor** that
reproduces its committed RS-level bytes using the recorded format and key
parameters. Only file content and length need anchoring: directory structure,
names, and desired file properties live in authenticated metadata. If an anchor
is missing, changed, or corrupt, declare that local shard unavailable and
repair it; never silently encode new bytes under an old root.

- Support two v1 anchor backends. **COW** uses a native per-file reflink/clone,
  leaving the working inode editable. **Guarded link-freeze** creates a private
  same-filesystem hard link to the working inode, records its exact original
  mode/ACL, uses a short platform guard to exclude pre-opened writers and
  writable mappings, then removes normal write/append/truncate permission. A
  hard link alone is not a snapshot. The write protection is deliberately
  user-reversible and defends against ordinary accidental modification, not a
  malicious process running with the user's authority.
- When adding a root, run a quick disposable sparse-file probe on every allowed
  root/filesystem pair: try the native clone API first; if unavailable, test the
  complete hard-link → guard/freeze → reject in-place mutation → allow
  rename/unlink/atomic replacement while the anchor survives → sparse detach
  → exact permission restore/edit cycle. Use only allowlisted platform
  mechanisms, clean up the probe, and reject the root if neither backend passes;
  never fall back silently to an eager full copy. Re-probe after a filesystem or
  mount-identity change, and reject or separately probe nested filesystems.
- Give each protected root/filesystem pair an app-owned, restricted anchor area
  on that filesystem, keyed by stable root/volume IDs. Prefer it outside the
  scanned subtree; otherwise reserve and hard-exclude it from scans/watchers,
  reject symlink traversal, and prevent recursive protection. Self-identifying
  anchor names let startup reconcile files with `control.db`.
- Link-freeze protects the shared file record, not its user-visible directory
  entry. Renames and unlinks need no copy; an atomic-replace editor naturally
  creates a new working file ID while the old anchored inode remains intact.
  Track all known paths per native file ID. If an inode already has unaccounted
  hard-link aliases, enroll the whole link group explicitly or reject that file
  rather than unexpectedly changing permissions on unknown paths.
- For an in-place edit, use the recoverable local sequence
  `SHARED_FROZEN → COPY_STAGING → PRIVATE_COPY_READY → UNLOCK_PENDING → EDITABLE`.
  Under the transition guard, copy the anchored inode to an independent
  temporary anchor while preserving holes, verify it against the committed
  root, fsync it and the anchor directory, atomically install/register it, and
  detach the old hard link before restoring the working inode's exact original
  permissions. Failure or `ENOSPC` leaves the working inode frozen. This local
  representation change does not create a protocol revision.
- Store local-only `(stable volume UUID, native file ID)`, all known paths,
  working and anchor IDs, link count, desired properties, size, modification
  and change-time hints, last verified root, watcher cursor, and transition
  state in `control.db`. File IDs can be reused and do not survive cross-volume
  moves, so confirm associations with the anchor and content root rather than
  treating IDs or timestamps as authority.
- Watch roots with inotify or the native Windows/macOS analogue, but treat
  events only as latency hints. At startup, after watcher overflow, and
  periodically, enumerate roots and anchor areas; reconcile native IDs and
  paths, expected protection, missing/orphan anchors, and incomplete edit/GC
  intents. Same-volume ID movement is a rename; a new ID at a path is a
  replacement; missing names are deletion candidates; size/time changes mark
  content dirty and require root verification before use.
- Support per-root `immediate`, quiet-period, and manual publication policies.
  Quiet time reduces churn but is not a consistency boundary; live databases
  and other multi-file applications require native snapshots, quiesce/export
  hooks, or an explicit warning. A persistent NTFS VSS snapshot is a possible
  volume-level COW implementation, but enable it only after testing service
  authorization, publication batching, diff-area headroom, eviction, and
  missing-snapshot reconciliation.
- Keep private edit copies sparse and byte-addressable in v1. A compressed or
  locally encrypted source-object store is a later backend because guild
  contexts differ and whole-file transforms hurt range access. Keep the
  abstraction open for independently chunked packing or optional
  userspace-COW/FUSE later.

### Databases and volumes

- Put `control.db` on stable system storage. It contains local owner metadata,
  byte-exact signed guild events/checkpoints, derived membership/group/layout
  views, reservations, object locations, quotas, receipts, durable operations
  and outbox, endpoint caches, and schema migrations.
- Put one `parity-<volume-uuid>.db` on each configured local filesystem, even
  when there is initially only one. It contains immutable parity chunks plus
  enough self-describing state to reconcile it independently: volume/object and
  operation IDs, root, generation, exact length, chunk index, lifecycle state,
  and local accounting. An OS RAID/LVM/ZFS/Btrfs pool appears as one volume;
  SQLite itself does not stripe one database across filesystems.
- Identify a volume by a persistent random UUID and authenticated manifest, not
  by mount path or device name. Never create a fresh database merely because an
  expected mount is absent, and reject two online copies with the same UUID.
  Track `online`, `offline`, `draining`, and `failed` states.
- Give `control.db` and every parity database independent random DEKs wrapped
  by a node-local storage key held outside those databases. Normal master-key
  rotation rewraps DEKs; reserve full SQLCipher `rekey` for DEK compromise or
  cipher migration. Pin the SQLCipher format/settings, retain page HMAC, disable
  extension loading and file-backed temporary storage, and enable defensive,
  untrusted-schema, memory-wiping, and resource-limit hardening.
  The page HMAC protects the local container before SQLite parses it;
  authenticated Merkle roots independently verify protocol-level sector bytes.
- Use separate WAL connections/workers for control and each online volume, so
  an absent disk cannot stop control work and different disks can write in
  parallel. Do not depend on `ATTACH` or cross-database foreign keys in normal
  operation; reserve attachment for inspection and controlled migration.
- Store parity in fixed, bounded, preferably Merkle-aligned BLOB chunks, using
  `zeroblob`/incremental BLOB I/O where useful. Never retain a write transaction
  or BLOB handle while awaiting the network: buffer one bounded chunk, write it
  in a short transaction, and verify the complete object before publication.

WAL does not make a transaction across several database files crash-atomic, so
publication uses an idempotent, recoverable sequence:

`control reservation → parity STAGED → verify root/length → parity READY → control STORED/RECEIPTED + quota + receipt + outbox → send receipt`

On restart, resume or expire reservations, adopt or collect unreferenced
`READY` objects, mark references on offline volumes unavailable, and resend
committed outbox entries. Migrate with copy → verify destination → atomically
switch the control location → collect the source. A disappeared volume is
offline rather than deleted; drain a healthy volume before removal. Multiple
disks in one machine remain one protocol failure domain and must not be counted
as independent shard hosts.

SQLite reuses deleted BLOB pages from its freelist; do not hole-punch or reflink
ranges of a live database. Track logical quota separately from file allocation,
reserve space for control/GC work, and use incremental vacuum, evacuation, or a
controlled rebuild only when physical space must be returned to the host.

Provide `mutualbackup db-shell`, opening `control.db` by default and accepting
`--volume <uuid>` for a parity database. It uses the application's exact
SQLCipher build, settings, and normal key-unwrapping path, never exposes keys in
arguments/logs, and defaults to query-only; writes require the daemon to be
stopped or exclusively locked. Ordinary `sqlite3` cannot decrypt these files,
but the schema and SQL remain inspectable with compatible SQLCipher tooling.
Do not provide a plaintext debug-export command.

### Execution and local test model

- Use an **asynchronous shell around a synchronous deterministic core**, not
  `async` everywhere. Tokio owns network/DHT/Tor RPC, timers, retries,
  cancellation, watchers, and orchestration. Canonical encoding, signature and
  Merkle checks, placement, authorization, and guild-state transitions remain
  ordinary synchronous functions that are easy to test deterministically.
- Put blocking SQLCipher work behind one bounded worker/actor per database,
  filesystem calls such as sparse copy/reflink/fsync in a bounded blocking
  pool, and encryption, hashing, Merkle, and RS work in a bounded CPU pool.
  Bound queues and buffers to provide backpressure. Never block a Tokio worker
  or hold a database transaction, incremental-BLOB handle, mutex/state guard,
  or source transition guard across a network `.await`.
- Give background tasks explicit ownership, cancellation, and shutdown/join
  rules. Use one Tokio runtime per process; several simulated nodes may share
  that runtime but not node state.
- A local simulated peer is a complete active `Node`, not a directory standing
  in for one. Each has its own seed/identity, `control.db`, parity databases,
  guild-log replica, scheduler, protocol workers, and transport endpoint; it
  gossips/checkpoints state and performs reservation, RS coordination, storage,
  receipts, audits, repair, and GC. The deterministic in-process harness may
  replace only transport, time, and failure sources. A local multi-process mode
  then runs the same binary and protocol over loopback with separate data
  directories; neither mode may share a database, guild log, peer registry, or
  hidden source of authority.

## 5. Protocol and data lifecycle

1. **Join/sync:** a new membership starts with an out-of-band guild invite and
   authorization; cold recovery of an existing member follows step 5 and never
   needs a new invite. Authenticate peer identity, negotiate capabilities, then
   gossip signed events and checkpoints. Current layouts are explicit; never
   recreate them by rerunning an old placement algorithm.
2. **Protect/commit:** apply the root's publication policy, capture and register
   a durable regeneration anchor, then build encrypted sectors and a draft
   revision. Select equal-size sectors from different users, reserve quota, and
   stream them to a temporary coordinator. Destinations durably stage and
   verify parity using the local publication sequence above, commit their
   receipt/outbox before sending the signed receipt, and later observe an
   authenticated guild-state commit activating the revision/groups. Old
   protection remains active throughout.
3. **Transfer/concurrency:** stream immutable objects and ranges with Merkle
   proofs. Mutations also carry the guild-certified writer epoch and a signature
   by its bound incarnation key, plus an idempotency key and expected state
   hash. Repeats return the previous result, while ambiguous results cause
   read/refresh rather than blind overwrite.
4. **Audit/repair:** use unpredictable range challenges, Merkle verification,
   and RS checks, with occasional full scrubs. Repair, emergency parity, and
   migration reuse the same stage/verify/receipt/commit flow.
5. **Recover:** seed → identity and recovery keys → generic IP and/or Tor
   bootstrap → deterministic per-identity DHT rendezvous lookup → authenticated
   guild peers over the best working direct, relay, or onion path → quorum-valid
   checkpoint and event tail plus key envelopes, private revision catalog, and
   explicit layouts → any `k` valid shards → verify/reconstruct/decrypt → safe
   staged restore → rebuild `control.db` and disposable caches. Test this after
   deleting every owner-local artifact other than the offline seed, including
   its data directory, source tree, anchors, keyring, endpoint cache, and
   remembered peer/guild configuration. Recovery begins read-only; it generates
   a fresh incarnation signing key, and before it can publish or mutate the
   guild quorum must advance the writer epoch and bind that key. Peers reject
   older epochs and other keys, fencing an accidentally stale copy even though
   it still possesses the seed. Two actors that both control the seed can still
   request a later takeover, so quorum policy remains the final arbiter.

Protocol object lifecycle:

`staged → uploaded → verified/receipted → committed/active → superseded → grace period → GC`

Content edits and deletions expand only affected Merkle branches, replace their
groups, commit new state, and later re-coalesce compatible survivors. A
same-volume rename changes private metadata but reuses unchanged content
sectors; unlink or atomic replacement of a working name leaves its link-freeze
anchor intact. GC removes only objects and source anchors unreachable from all
active/retained revisions and layouts after the grace period and after in-flight
transitions finish. When collecting the last shared hard-link anchor, journal
restoration of the desired permissions on any still-visible working inode so a
crash cannot strand it frozen. Removal is idempotent and crash-reconciled, not
an immediate reaction to the last apparent reference. Secure physical erasure
cannot be proved on remote hosts, CoW filesystems, or SSDs; deletion ends the
obligation and requests best-effort removal.

After replacement protection is committed and the grace period ends, a range
of an old group may become `Zero` only when all `k` information roles there are
retired; linear RS then makes every parity role zero there too. Storage may
omit its payload only from authenticated state and synthesize the exact zeros
in software. A SQLCipher parity database deletes obsolete chunk rows and reuses
their pages; it must never be externally hole-punched. Never mutate an object
still addressed by its old Merkle root.

During outages, keep the old layout while adding temporary protection among
reachable domains. Remove it when peers return or migrate safely if the outage
persists. Guild growth supplies new placement, parity, repair, and gradual
migration; it must not force rewriting old groups. Schedule all work with
weighted fairness plus aging, bounded concurrency, and per-guild disk/network
quotas, so cleanup and audits cannot starve forever.

## 6. Networking and hole punching

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
- Peers also publish the encrypted per-member recovery rendezvous under the
  deterministic key derived from that member's Node ID. Each publisher writes
  its own expiring record, preventing one peer from erasing all alternatives;
  the recovered node decrypts candidate records and accepts only pointers that
  lead to valid signed guild state.
- Ensure discovery itself has a Tor path: DHT/provider queries must work over
  the common stream abstraction, or records must be mirrored by onion-reachable
  rendezvous nodes. Ship several replaceable IP and onion bootstrap endpoints;
  otherwise a DHT containing onion addresses would not help an IP-blocked
  recovery. Document the remaining condition that some discovery route and
  enough shard holders must be reachable. Onion services avoid inbound NAT
  requirements but still depend on the Tor network being available.

## 7. What to reuse from BarterBackup

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

## 8. Delivery phases

1. **ADRs and risk spikes:** identity/membership/threat and writer-fencing
   model; seed/recovery-envelope and rendezvous formats; canonical vectors;
   Merkle/encryption/RS and SQLCipher chunk/range/page-reuse benchmarks;
   virtual-zero storage benchmark; COW/link-freeze and VSS probes;
   multi-volume crash-state spike; bounded async/DB/FS/CPU worker skeleton; and
   direct/punch/relay/onion prototype. These are disposable learning steps, not
   a substitute for the multi-node acceptance test.
2. **First working vertical slice:** run five independent active nodes through
   the real state machines over deterministic in-memory transport; invite/join,
   capture one ordinary folder with an admitted anchor backend, build owner-
   encrypted metadata/sectors, form a `3+2` group, store parity through the real
   databases, exchange receipts, and commit signed guild state. Stop the owner,
   delete its data directory, source tree, anchors, keyring, endpoint cache, and
   all node-specific configuration; then create a clean node from only its seed
   and generic bootstrap configuration. Without the harness injecting a guild
   ID, peer list, checkpoint, or receipt, discover peers, rebuild state, restore
   byte-exact data from any three valid shards, and prove an old writer session
   is fenced. Keep this scenario passing from this milestone onward.
3. **Lifecycle and failure coverage:** add edits/deletes, every source mutation
   path, add-root rejection, reflink/link-freeze detachment and exact permission
   restoration, hard-link aliases, watcher reconciliation, `ENOSPC`, disk
   unplug/remount/path change, cross-volume migration, full-volume headroom,
   coordinator failure, duplicate calls, corruption, partitions, emergency
   repair, GC, and crashes at every capture/unlock/publication boundary using
   `ManualClock` and expanded `netmock`. Also run the same nodes as isolated
   local processes to catch accidental shared-state assumptions.
4. **Real network:** DHT endpoint records, peer exchange, resumable transfers,
   direct QUIC, hole punching, guild relay, and embedded Arti onion service.
   Test automatic fallback, explicit Tor preference/requirement, restart with a
   stable onion identity, and DHT-seeded onion recovery in Docker/network
   namespaces across common and symmetric NAT cases.
5. **Hardening:** fuzz parsers; property-test split/coalesce and any-`k`/seed-only
   recovery; test cross-platform metadata and damaged SQLCipher pages; bound
   queue, buffer, task, RSS, and WAL growth; test volume/source-anchor and
   watcher reconciliation, native-ID reuse and cross-volume movement, remount
   capability changes, incomplete freeze/edit/GC intents, anchor corruption,
   freed-page reuse, large trees/small edits, and rotation/revocation limits.

Before freezing v1, decide the remaining compatibility gates: sector and
encryption regeneration rules; RS matrix/extensible rows and availability-based
`k/m`; multi-device identity/forks; membership/removal/quorum; retention,
quota, and deletion policy; DHT privacy/bootstrap/TTL and endpoint freshness;
connection racing/fallback policy; Tor configuration and resource limits;
relay abuse controls; audit cadence; coordinator failover; and the portable
restore metadata set; zero-extent alignment and whether virtual zeros belong in
v1 wire formats or remain a local storage optimization; protocol
encryption/authenticated-Merkle semantics; physical chunk size; SQLCipher
profile/base version; schema/volume-manifest versions; COW/link-freeze/VSS
support matrix, native-file-ID semantics, and source-anchor state machine;
application-consistent capture; journal/durability/checkpoint policy; and
storage headroom.
