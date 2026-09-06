# Mutual P2P Backup — implementation plan

Working plan based on `mutual-p2p-backup-design.md` and the older Rust code in
`/home/user/barterbackup/rust`. Protocol choices below are provisional: record
them as ADRs and test vectors before promising wire compatibility.

## 1. Direction and first decisions

- Continue the layered Rust workspace; transplant small proven utilities rather
  than extending BarterBackup's whole-blob core. Ship two binaries:
  `mutualbackupd` is the sole owner of the live node, databases, peer network,
  and background jobs; `mutualbackup` is a thin local control and offline
  bootstrap CLI. A bootstrap, DHT, or relay role is a daemon configuration, not
  a third program.
- The first usable prototype is Linux and **reflink-only**. Probe the complete
  COW lifecycle when a root is added and reject the root if reflinks are not
  safe there. Never silently fall back to an eager full copy. Guarded
  link-freeze, VSS, FUSE, and other source backends come after the prototype.
- Use a pinned SQLCipher/SQLite build as the common local storage engine, with
  per-page HMAC enabled. Keep control state separate from parity storage. The
  prototype instantiates one parity database; later, one database per configured
  filesystem lets volumes be added, drained, or lost independently.
- Use one stable seed-derived Ed25519 **peer identity** across direct QUIC,
  hole-punched, relayed, and Kademlia sessions, with a deterministic verified
  mapping between the Node ID and libp2p Peer ID. Keep revision, mailbox,
  metadata, and `(user, guild)` data keys domain-separated. Reserve the same
  identity mapping for a later Arti onion transport, but do not implement or
  require Tor in the first usable prototype. Treat one live node as the writer
  for that identity until writer fencing is added later.
- Make **seed-only recovery** a permanent invariant and the acceptance test for the
  first usable prototype. Starting with the seed, an empty data directory, and
  only generic Kademlia bootstrap multiaddresses, a node must derive its
  identity, find its guild peers without a cached guild ID or peer list, rebuild
  its authenticated state and keys, retrieve any sufficient set of shards, and
  restore its data. No indispensable recovery material may live only in
  `control.db` or the source folder.
- Assume social trust but verify signatures, identities, roots, and state
  transitions. The prototype rejects corrupt/replayed/forked inputs and resumes
  local jobs after crashes or ordinary connection loss; Byzantine availability,
  recovery takeover during a partition, and full abuse resistance come later.
- Keep the implemented prototype profile fixed at five members, 64 KiB sectors,
  and RS `3+2`. Never place two shards of one group in the same physical failure
  domain. Variable membership, sector sizes, `k/m`, and extensible parity are
  later protocol work.
- Require unanimous five-of-five signatures for prototype genesis and
  checkpoints. Leave a compatible authorization interface for later quorum
  policies and FROST once membership and recovery policy are stable.

### First usable prototype milestone

The existing reflink/encryption/RS/SQLCipher/signed-TCP recovery path is useful
foundation, but it is a laboratory harness rather than this milestone. The
prototype is complete only when all of the following use the real runtime path:

- Five persistent `mutualbackupd` processes form one static guild through an
  explicit create/invite/join flow. Routine CLI commands never take five peer
  addresses, a coordinator identity, or a seed file. The prototype supports one
  guild and one protected root per member; both cardinalities can expand later.
- `mutualbackup root add` performs the full reflink probe and persists the root;
  `backup --wait`, durable job status, snapshot listing, and restore all operate
  through the daemon. Every guild member can protect its own root.
- The same guild supports revision and checkpoint generations 2 and later.
  A full rescan and full new revision are acceptable; all old revisions,
  anchors, and parity remain retained until post-prototype GC exists.
- A basic Linux inotify watcher marks roots dirty. Manual publication is the
  default; an opt-in quiet-period policy may start at most one backup per a
  configured minimum interval and stops visibly when the storage budget is
  exhausted. Startup and watcher overflow trigger a full reconciliation, so
  filesystem events are never treated as authority.
- Peers use real authenticated/encrypted QUIC, Identify, Kademlia discovery,
  circuit relay v2, and AutoNAT/DCUtR hole punching. Direct, successful-punch,
  and failed-punch relay paths exercise the same application protocol.
- Kademlia replaces the in-memory directory. Signed, expiring recovery and
  endpoint records are refreshed by the daemons, and backup/recovery no longer
  depends on manually supplied guild or peer addresses. Durable publication
  jobs distinguish a committed checkpoint from one confirmed seed-recovery
  discoverable through records from at least three independent publishers.
- A fresh daemon recovers from the seed plus generic IP bootstrap configuration,
  restores the latest revision from any three valid shards, and rejoins at its
  new endpoint after losing its old state, source, anchors, and endpoint cache.
- Each daemon uses one SQLCipher parity database and an explicit storage budget.
  Parity is acknowledged only after the host verifies the input roots and its
  assigned RS row and durably stores it. A minimal signed acknowledgement stored
  atomically with the parity object is enough for this milestone.
- The acceptance test runs five isolated daemon processes, drives them only via
  `mutualbackup`, survives process restarts, loses the owner and one other shard
  holder, and restores byte-for-byte. No in-memory directory, fake peer, mock
  transport, or injected recovery state is allowed in this acceptance path.

Every prototype owner sector is grouped with two deterministic synthetic
information fillers. This is an explicitly inefficient but real committed
`3+2` codeword, not a transport or storage mock. Cross-user sector packing is a
post-prototype replacement for that rule.

The milestone intentionally excludes Tor/Arti/onion services, guarded
link-freeze and non-Linux platforms, dynamic membership, writer-incarnation
fencing, multiple parity volumes, variable RS, range-level Merkle proofs,
cross-user packing, retention/GC, audits, repair, migration/rebalancing, and
production-grade abuse/resource hardening. Later sections preserve their design
direction, but none of them blocks this prototype unless stated explicitly.

## 2. State ownership

| Item | Who keeps it |
| --- | --- |
| Plaintext and recovery seed | Plaintext stays on the owner's selected filesystem, in the working folder or restricted source-anchor area; the seed has offline backup and never enters the DHT. The seed alone derives the stable identity and recovery-decryption roots |
| Active source anchor | The prototype owner retains a COW reflink until every referencing revision is retired. A write-protected hard link and its sparse private copy are later backends |
| Information sectors | Guild-specific encrypted form normally comes from its owner; after owner-disk loss it is reconstructed from the coding group |
| Private file metadata | Encrypted as user-owned information sectors and protected by the same coding machinery |
| Parity sectors | Assigned peer or storage-only node; that host stores the exact RS-level bytes as locally SQLCipher-encrypted chunks on a selected volume |
| Virtual zero extents | Post-prototype only: nobody stores payload or earns storage credit; peers synthesize them from the authenticated layout |
| User revisions | Signed by an identity-authorized revision key and replicated with recoverable guild state |
| Guild state | Prototype members retain the signed genesis, every authenticated checkpoint/revision, and enough explicit layout and recovery-locator metadata to rebuild a lost member. Later event tails and recovery-key envelopes support rotation, and old history may be safely compacted |
| Coordinator state | The genesis records which member serializes prototype proposals, but five signatures authorize a checkpoint. Its work inputs/staging are temporary and never authoritative |
| DHT and relay | Kademlia stores independently published, short-lived provider advertisements, public signed endpoint records, and signed recovery bundles sealed to their subjects. The relay function retains no forwarded payload or authority, though the same daemon may separately hold assigned parity. Onion endpoints are added only by the later Tor milestone |

Proposed simplification: a `UserRevision` describes only that user's logical
data. Membership, revision heads, coding groups, and parity assignments belong
to guild state; later retention adds tombstones there too. Both must be
recoverable from peers; a DHT record is only a pointer toward them. This avoids
the feedback loop in the old system where peer inventory changed the owner's
content revision.

For the prototype, local `control.db` keeps the root and reflink-anchor catalog,
native volume/file IDs and known paths, size/change hints, watcher cursors,
durable backup and DHT-publication jobs, the static guild roster,
endpoint/bootstrap caches, and byte-exact signed revisions and checkpoints.
Signed records—not reconstructed SQL rows—remain protocol authority. Derived
caches are disposable, and no recovery seed, indispensable key, current private
metadata, or guild state may exist only in this database. Each guild has
independent ciphertext and state.
Post-prototype schemas add multiple-volume inventory, full quota/receipt/outbox
accounting, retention, repair, and migration state.

Keep the seed format versioned and checksummed. The prototype's fixed key suite
must derive every recovery-critical key or recover its authenticated material
from peers; recovery must not depend on a salt, counter, key version, or manifest
found only on the lost machine. Rotatable user/guild keys and historical key
envelopes are post-prototype protocol work.

## 3. Formats and protocol objects

Keep canonical postcard encoding for hashed/signed peer and durable records;
transport and local-control framing is separate and is never itself signed.
Every durable record carries format and algorithm versions, scope, type, and
lengths. Publish golden vectors for hashes, signatures, encryption, sector
roots, RS, identity mapping, and DHT keys. The prototype freezes only the fixed
profile needed for its real multi-process acceptance test; the advanced objects
identified below remain post-prototype work.

The protocol byte flow is owner plaintext → owner encryption → RS over the
encrypted information sectors → root-committed information/parity sectors.
A storage host then adds transparent local SQLCipher encryption. Peers exchange
only the exact RS-level bytes, never SQLCipher pages. Protocol encryption need
not add its own authentication tag when every complete prototype sector is
verified against a root authenticated by signed revision/coding-group state.
Later partial-range transfer must supply proofs to that same authority.

- **Prototype sector object:** fixed 64 KiB RS-level bytes, logical tail length,
  encoding/key-suite version, nonce material, and a full-sector BLAKE3 root.
  Define canonical tails, padding, sparse-file mapping, and encryption framing,
  and regenerate any committed sector byte-for-byte from its anchor and recorded
  parameters. Hierarchical Merkle range proofs, range transfer, and
  split/coalesce formats come later.
- **Later virtual zero extent:** provisionally model an aligned `Zero(length)`
  at the exact byte representation consumed by RS, not as encrypted plaintext zeros.
  Bind its position and length into a new immutable layout/object generation
  and define canonical, precomputable roots. Benchmark this protocol feature
  after the prototype; a fully unreachable sector should simply be deleted.
- **Prototype private metadata:** safe relative paths, file/directory type,
  ordered sector references, logical size, sparse extents, timestamps, and a
  minimal Linux attribute subset. Native file IDs, anchor paths, and watcher
  cursors are local catalog state, never portable signed recovery fields.
  Symlink restore and broader portable attributes come later and require an
  explicit policy that prevents path escape.
- **Prototype UserRevision:** guild, owner, monotonic revision, optional parent,
  explicit metadata/data `SectorRef` lists, suite versions, and owner signature.
  It represents the member's single protected root; multiple named/root-ID
  revision chains come later.
- **CodingGroup:** stable ID, shard size, versioned RS construction and row IDs,
  `k/m`, canonical ordered roles, sector roots, nodes, and failure domains.
- **Prototype GuildGenesis:** guild ID, exactly five Node IDs/recovery keys and
  immutable logical failure-domain slots, fixed format profile, and one
  coordinator Node ID that
  serializes proposals but cannot authorize them alone. All five members sign
  the genesis after accepting their invites.
- **Prototype GuildCheckpoint:** genesis hash, monotonic generation and parent,
  active heads, and the complete retained signed revision and explicit coding-
  group catalog. A checkpoint certificate requires five-of-five member
  signatures. This deliberately grows until GC exists, ensuring historical
  snapshots remain seed-recoverable. Membership events, tombstone compaction,
  writer epochs/incarnation keys, and dynamic membership come later.
- **Prototype storage acknowledgement:** operation ID, canonical complete
  `CodingGroup` ID/algorithm, assigned row and root, holder, and signature. The
  parity holder first verifies all three information roots and recomputes its
  assigned RS row. Its parity-database transaction then checks the configured
  budget and atomically stores the verified READY object plus acknowledgement
  before replying. Pre-activation acknowledgements therefore survive either
  daemon's restart; retain them with the object for the prototype. Rich
  reservations, retention promises, quota ledgers, and repair/audit receipts
  come later.
- **Prototype Kademlia discovery:** every guild publisher announces itself as a
  provider of `mailbox(subject)`. Recovery obtains several provider Peer IDs;
  each publisher owns `recovery-bundle(subject,publisher)`, a bounded sealed set
  of locators for every guild the pair shares, and a public signed
  `endpoint(publisher)` record containing direct QUIC and relay circuit
  multiaddresses. Both record types carry a durable per-kind publisher sequence
  and expiry. The highest valid sequence wins; differing values at the same
  sequence are a fork and are rejected/reported. Before publishing after
  local-state recovery, query all returned values and advance beyond the
  greatest valid sequence. This avoids shared last-writer-wins values, permits
  future multiple guilds without changing keys, and lets publishers refresh independently.
  Validate the Node ID/Peer ID binding and accept only sealed locators that lead
  to quorum-valid signed state. Persistent daemon jobs republish before TTL. A
  checkpoint becomes `seed-recovery-ready` only after a nonlocal lookup returns
  its current bundles from at least three independent guild publishers. DHT
  metadata never proves that bytes are stored and never becomes protocol
  authority. A formal recovery capsule/event tail and onion endpoints are later extensions.

## 4. Local source snapshots, persistence, and storage volumes

### Prototype source capture

Each active owner-data information role needs a stable **regeneration anchor**
that reproduces its committed RS-level bytes using the recorded format and key
parameters; deterministic filler roles carry their own recipe. Only file content
and length need anchoring: directory structure, names, and desired properties
live in authenticated metadata. If an anchor is missing, changed, or corrupt,
refuse to serve/sign for that shard and report that recovery is needed; never
encode new bytes under an old root. Automatic repair comes later.

- Use the native Linux per-file reflink/clone, leaving the working inode editable.
  `root add` performs a disposable sparse-file lifecycle probe: create and clone,
  mutate both sides independently, verify content and holes, rename/unlink while
  the anchor survives, and clean up. Reject the root if any step fails; never
  fall back to a full copy or hard-link freeze. Re-probe after a filesystem or
  mount-identity change, and reject or separately probe nested filesystems.
- Give each protected root/filesystem pair an app-owned, restricted anchor area
  on that filesystem, keyed by stable root/volume IDs. Prefer it outside the
  scanned subtree; otherwise reserve and hard-exclude it from scans/watchers,
  reject symlink traversal, and prevent recursive protection. Self-identifying
  anchor names let startup reconcile files with `control.db`.
- Store local-only `(stable volume UUID, native file ID)`, all known paths,
  working and anchor IDs, size, modification/change-time hints, last verified
  root, and watcher cursor in `control.db`. File IDs and timestamps are scan
  accelerators, not authority; confirm reuse or movement against the anchor and
  content root.
- Linux inotify events mark a root dirty; manual publication is the default.
  An opt-in quiet-period policy coalesces events and enforces a minimum interval,
  but stops with the root visibly dirty if capacity is exhausted. Startup,
  overflow, and periodic reconciliation enumerate the root and anchor area. A
  full rescan and full immutable revision are acceptable; incremental diffing is
  not required. Quiet time is not an application-consistency boundary, so warn
  about live databases and other coordinated multi-file applications.
- Preserve sparse files and hard-link relationships when capturing and
  restoring them. Retain every committed reflink anchor indefinitely until the
  later retention/GC milestone can prove it unreachable.

### Deferred source backends and platform work

- **Guarded link-freeze** creates a private same-filesystem hard link to the
  working inode, records its exact original mode/ACL, uses a short platform
  guard to exclude pre-opened writers and writable mappings, then removes normal
  write/append/truncate permission. A hard link alone is not a snapshot. The
  protection is user-reversible and defends against ordinary accidental
  modification, not a malicious process with the user's authority.
- Before enabling that backend, extend the root probe through hard-link →
  guard/freeze → reject in-place mutation → allow rename/unlink/atomic
  replacement while the anchor survives → sparse detach → exact permission
  restore/edit. If an inode has unaccounted aliases, enroll the whole link group
  explicitly or reject it rather than changing permissions on unknown paths.
- For an in-place edit, use the recoverable local sequence
  `SHARED_FROZEN → COPY_STAGING → PRIVATE_COPY_READY → UNLOCK_PENDING → EDITABLE`.
  Under the guard, make and verify a sparse independent anchor, fsync and install
  it, detach the old hard link, and only then restore the working inode's exact
  permissions. Failure or `ENOSPC` leaves the working inode frozen.
- Evaluate persistent NTFS VSS only after testing service authorization,
  batching, diff-area headroom and eviction, and missing-snapshot reconciliation.
  Native macOS support, portable ACL/xattr handling, independently chunked local
  packing, and optional userspace-COW/FUSE are also post-prototype work.

### Prototype databases

- Put `control.db` on stable system storage and one `parity.db` on the configured
  storage location. Control owns local metadata, durable jobs, signed protocol
  records, endpoint caches, and parity-location views; parity owns immutable
  locally encrypted RS-level bytes, the authoritative byte budget/accounting,
  operation IDs, roots, and stored acknowledgements.
- Pin the SQLCipher format/settings, retain page HMAC, disable extension loading
  and file-backed temporary storage, and enable the practical defensive and
  memory-wiping options. SQLCipher protects the local container; authenticated
  sector roots independently verify protocol bytes.
- Keep blocking SQLite work behind its bounded daemon worker. Store bounded
  full-sector BLOBs and never hold a transaction, BLOB handle, or state lock
  across a network await.
- For each bounded request, verify the three information roots and assigned RS
  row as above, then use one parity-DB transaction to check the configured budget
  and atomically store the READY parity bytes plus signed acknowledgement before
  replying. Checkpoint activation consumes only those acknowledgements.
  Idempotent restart/retry adopts the same operation or rejects a conflict
  without cross-database atomicity.
- Retain every active/historical object and committed anchor, but idempotently
  remove abandoned temporary files, uncommitted capture anchors, and incomplete
  staging rows after a failed or cancelled job. Cancellation succeeds
  only after this cleanup is durable or the resumable job has been safely marked
  abandoned.
- SQLite reuses deleted BLOB pages from its freelist. Never externally punch
  holes in or reflink ranges of a live database.

### Post-prototype volumes and database operations

- Put one `parity-<volume-uuid>.db` on each configured local filesystem. Identify
  it by a persistent random UUID and authenticated manifest, not mount path or
  device name; track `online`, `offline`, `draining`, and `failed`, and reject
  duplicate online UUIDs. An OS RAID/LVM/ZFS/Btrfs pool remains one failure
  domain; SQLite itself does not stripe a database across filesystems.
- Give `control.db` and each parity database an independent random DEK wrapped by
  a node-local storage key. Master-key rotation rewraps DEKs; reserve SQLCipher
  `rekey` for DEK compromise or cipher migration.
- Use separate WAL workers for control and each volume. Do not depend on
  `ATTACH` or cross-database foreign keys. Because WAL cannot make several files
  crash-atomic, extend publication with durable control receipts/outbox and
  restart reconciliation. Migrate with copy → verify destination → switch the
  control location → collect the source; an absent volume is offline, not empty.
- Track logical quota separately from physical allocation. Return space with
  incremental vacuum, evacuation, or a controlled rebuild—not external hole
  punching—and reserve headroom for control, recovery, and GC.
- Provide `mutualbackup db-shell`, opening `control.db` by default and accepting
  `--volume <uuid>`. It uses the application's exact SQLCipher build and normal
  key-unwrapping path, never exposes keys in arguments/logs, defaults to
  query-only, and requires an exclusive lock for writes. Ordinary `sqlite3`
  cannot decrypt these files, though compatible SQLCipher tooling can inspect
  their ordinary SQL schema. Do not provide a plaintext debug-export command.

### Execution and local test model

- Use an **asynchronous shell around a synchronous deterministic core**, not
  `async` everywhere. Tokio owns daemon IPC, the libp2p swarm, Kademlia, timers,
  retries, cancellation, watchers, and orchestration. Canonical encoding,
  signature and root checks, RS, authorization, and guild-state transitions
  remain ordinary synchronous functions that are easy to test deterministically.
- Run one Tokio runtime in `mutualbackupd`. The daemon alone opens the seed,
  `Node`, and databases and runs the peer listener and background jobs.
  `mutualbackup` uses a versioned, length-framed local API over a mode-`0600`
  Unix socket with peer-credential checks. Long operations return durable job
  IDs with status/follow/cancel; only offline bootstrap and maintenance commands
  such as `init`, `recover-init`, reflink probe, and later `db-shell` bypass it.
- `mutualbackup init --data-dir DIR` creates a versioned nonsecret TOML config,
  a mode-`0600` runtime seed, and the default socket location; the user keeps a
  separate offline seed copy. Config names the QUIC listen multiaddresses,
  failure-domain label for a new node, parity path/budget, Kademlia bootstrap and
  optional relay multiaddresses, and root publication defaults.
  `mutualbackupd --data-dir DIR` selects it. The CLI uses the default per-user
  socket or explicit `--socket` for tests/multiple local daemons. `recover-init`
  imports the offline seed into a new data directory without importing guild or
  peer configuration and leaves the failure-domain label unset until signed
  genesis is recovered.
- Put blocking SQLCipher work behind one bounded worker/actor per database,
  filesystem calls such as sparse copy/reflink/fsync in a bounded blocking
  pool, and encryption, hashing, roots, and RS work in a bounded CPU pool.
  Bound queues and buffers to provide backpressure. Never block a Tokio worker
  or hold a database transaction, incremental-BLOB handle, mutex/state guard,
  or source transition guard across a network `.await`.
- Give background tasks explicit ownership, cancellation, and shutdown/join
  rules. Deterministic in-process nodes may replace transport, time, and failure
  sources for focused tests, but are not the prototype milestone. Acceptance
  runs five real `mutualbackupd` processes, each with its own seed, databases,
  guild replica, jobs, and network endpoint, controlled through `mutualbackup`.
  No nodes may share a database, peer registry, or hidden authority.

## 5. Protocol and data lifecycle

### Prototype lifecycle

1. **Create/join:** one member creates a fixed five-member guild and issues
   signed out-of-band invites. All members explicitly accept, authenticate each
   other's Node ID/libp2p Peer ID, and sign/persist `GuildGenesis`. Its named
   coordinator serializes checkpoint proposals but all five signatures authorize
   them. This replaces any runtime-global trusted coordinator. Cold recovery of
   an existing member never requires a new invite.
2. **Protect:** `root add` probes and registers the member's one reflink-capable
   root. A manual request or enabled bounded quiet-period job performs a full
   scan, captures durable COW anchors, creates owner-encrypted fixed sectors and
   private metadata, and signs a monotonic `UserRevision` with its parent.
3. **Code/store:** form explicit `3+2` groups across five failure domains, using
   the owner sector plus two deterministic fillers. Transactionally admit each
   parity object against its host's fixed budget, transfer the complete immutable
   information sectors, verify all three roots, recompute and verify the assigned
   RS row, store that parity through SQLCipher, and return an acknowledgement
   bound to the complete group and row. A retry uses the same operation ID.
4. **Activate/publish:** the genesis coordinator assembles checkpoint generation
   `N+1` only after all required acknowledgements exist. Before signing, every
   member confirms its assigned information recipe/anchor or verified READY
   parity and coding proof is durable; all five members then sign. The latest
   checkpoint contains the entire retained revision/group catalog.
   Replicate it and enqueue durable Kademlia recovery-bundle/endpoint publication
   on every member. Status distinguishes `committed` from `seed-recovery-ready`;
   the latter requires confirmed current records from at least three independent
   publishers. Startup resumes publication before TTL. Old revisions, anchors,
   shards, and acknowledgements remain retained; the prototype performs no GC.
5. **Restore:** a healthy daemon lists signed revisions and restores the selected
   one from verified local/remote sectors. Fetch independent shards concurrently
   and retry at the 64 KiB sector boundary; range proofs and partial-sector
   resume are not needed yet.
6. **Cold recover:** seed → Node ID/libp2p Peer ID and recovery key → generic
   Kademlia bootstrap → `mailbox(subject)` providers → publisher endpoint and
   sealed recovery bundles → authenticated direct, DCUtR-punched, or relay
   sessions → quorum-valid checkpoint and explicit layouts → any three valid
   shards → verify/reconstruct/decrypt → staged restore → rebuild `control.db`
   and rejoin at the new endpoint after reading the greatest valid prior
   publisher sequence and advancing it. The test supplies no guild ID, peer
   list, checkpoint, endpoint cache, or old node configuration.

During prototype recovery, the daemon adopts its immutable logical
failure-domain slot from the recovered signed genesis. The operator must place
the replacement on a physical domain independent of the other four members; the
software cannot infer this from the seed. Re-labeling a member through an
authorized guild transition comes with later dynamic membership work.

The prototype assumes only one live writer for a seed-derived identity. Recovery
can restore and rejoin, but operators must not run the lost node concurrently;
cryptographic writer-incarnation fencing is a later milestone.

### Later lifecycle

Add dynamic membership and event tails, writer epochs/incarnation keys, key
rotation envelopes, cross-user packing, incremental Merkle/range updates,
retention and tombstones, audits/scrubs, repair and emergency parity, outage
layouts, migration/rebalancing, and weighted fair scheduling. The eventual
object lifecycle is:

`staged → uploaded → verified/receipted → committed/active → superseded → grace period → GC`

GC removes only objects and anchors unreachable from every retained revision
after in-flight transitions finish. Link-freeze permission restoration must be
journaled before collecting its last anchor. Virtual-zero ranges may be omitted
only when authenticated state proves that all `k` information roles, and thus
all linear parity roles, are exactly zero. Secure physical erasure cannot be
proved on remote hosts, COW filesystems, or SSDs; deletion ends the obligation
and requests best-effort removal.

## 6. Networking and hole punching

### First usable prototype: real IP connectivity

- Use rust-libp2p rather than extending the temporary TCP stack: QUIC, Identify,
  Kademlia, request/response or stream protocols, circuit relay v2, AutoNAT, and
  DCUtR. Derive its peer identity from the stable Ed25519 key. QUIC authenticates
  and encrypts the live session; existing canonical application signatures stay
  authoritative for stored, relayed, or later replayed protocol records.
- Hide paths behind one authenticated session interface keyed by Node ID. Keep a
  small guild peer-exchange overlay and a signed, expiring endpoint set per peer.
  Reuse sessions, fetch independent shards in parallel, and retry complete
  64 KiB sectors. Range resume and a second custom hole-punch protocol are not
  part of the prototype.
- Try paths with bounded budgets in this order: an existing or direct QUIC
  session over IPv6, LAN, or a known public address; a relay-v2 circuit followed
  by a DCUtR simultaneous QUIC punch; then retain the authenticated relay circuit
  if the punch fails. Cache the working path and deterministically collapse
  duplicate simultaneous sessions. PCP, NAT-PMP, and UPnP mapping come later.
- Reachable guild daemons may opt into a bounded relay role and admit
  reservations/circuits for authenticated guild members. Configured community
  bootstrap relays may provide the initial circuit. The relay function forwards
  opaque bytes without retaining the payload or gaining storage authority, and
  enforces connection, time, and byte limits; the daemon may separately store
  its assigned parity.
- Implement the Kademlia mailbox/provider/bundle/endpoint scheme from section 3.
  Daemons refresh records before their finite TTL and gossip fresher signed
  endpoints inside the guild. Ship several replaceable generic IP bootstrap
  multiaddresses. DHT routing/cache state is disposable; the DHT is discovery,
  never authority or bulk storage.
- Seed-only recovery still requires at least one working bootstrap/routing path
  and enough reachable shard holders. Test topology must make alternatives
  impossible and assert the daemon-reported selected path: direct QUIC; no
  initial direct route followed by successful DCUtR; and forced punch failure
  with the complete transfer carried over the relay circuit.
- Tor/Arti and onion endpoints are not built, advertised, or required by this
  prototype. Keep endpoint and session enums extensible so adding them later
  does not alter the application protocol.

### Later Tor/onion connectivity milestone

- Embed maintained Arti for outbound onion dials and an inbound Tor v3 onion
  service. Use the same seed-derived Ed25519 identity, verify that its onion
  hostname maps to the Node ID, keep Arti directory/cache state persistent, and
  inject the service identity through an ephemeral keystore at startup.
- Add the onion multiaddress to signed DHT/gossip endpoint sets and implement
  `auto`, `prefer-tor`, `require-tor`, and `disable-tor` policies. Start Arti in
  the background so automatic fallback is ready before IP paths fail; expose Tor
  readiness independently and reuse long-lived authenticated sessions.
- Make discovery itself onion-reachable, either by running Kademlia through an
  Arti-backed libp2p transport or through several onion-reachable DHT gateways.
  A DHT that merely contains onion addresses is insufficient when IP bootstrap
  is blocked.
- Gate this separate milestone with a private Tor test: block all peer IP paths,
  bootstrap from only replaceable onion endpoints, recover from the seed, and
  verify the stable onion identity across daemon restarts.

## 7. What to reuse from BarterBackup

| Treatment | Older Rust material |
| --- | --- |
| Reuse/extract | `crates/clock` and `ManualClock`; the small filesystem abstraction and temp-file + fsync + rename atomic-write pattern from `crates/storage`; data-dir locking/permissions; Nix, protobuf build, property/fuzz, and Docker harness patterns |
| Adapt for prototype | The `bbd`/`bbcli` process split and local-control shape; runtime supervision/readiness; transport boundaries, retry budgets, duplicate-session tie-breaking, bounded sessions, CAS read-refresh-retry, recovery-before-publication, durable storage acknowledgement, and failure injection; use `netmock` only for focused tests, never the acceptance path |
| Defer | `crates/nettor`'s Arti client, deterministic onion service, stream adapter, cache/ephemeral-key split, runtime supervision, and Chutney test lane; revisit these only for the separate Tor milestone |
| Replace | `crates/content`, most of `storage::Store`, old peer/stored schemas, monolithic `crates/node`, wall-clock lineage recovery, 4 MiB whole-blob RPC model, the Tor-only/onion-string connector, and peer scoring as the placement core |

Keep the domain-separated KDF and test-vector principles from `crates/keys`, but
redesign recovery-secret formats and non-identity keys where this protocol needs
different domains. Do not copy `crates/tlsutil`: its custom rustls callbacks
accept TLS handshake signatures without verifying them. Use libp2p's reviewed
authenticated transport and retain signed application records. BarterBackup has
no DHT, QUIC, DCUtR, or relay implementation to transplant. Copied code must
retain the older repository's MIT notice.

When the Tor milestone begins, adapt only `nettor`'s conversion to `HsIdKeypair`,
shared inbound/outbound `TorClient`, persistent-cache/ephemeral-key split, and
runtime supervision. Use a maintained Arti release and revalidate state handling
instead of copying its custom fork or hard-coded cleanup paths blindly.

## 8. Delivery phases

Each phase must extend the same runnable workflow. Do not build a replacement
subsystem beside the product and integrate it later.

0. **Existing foundation — keep green:** retain the real reflink capture, owner
   encryption, fixed `3+2`, SQLCipher parity, canonical signed records, durable
   retry work, and five-process direct-TCP seed-recovery smoke test. This is the
   protocol/storage kernel, not the usable prototype.
1. **Daemon and control spine:** create `mutualbackupd` and turn `mutualbackup`
   into its Unix-socket client. The daemon exclusively owns keys, `Node`, stores,
   peer service, and durable jobs. Move the current backup/recovery workflow
   behind this boundary first, make source capture a direct local-daemon action
   so source paths leave the peer protocol, and keep the smoke test passing. Do
   not redesign the data path at the same time.
2. **Final IP network and guild substrate:** define `GuildGenesis` and its local
   validation, then replace the request path's TCP/`SocketAddr` coupling with
   libp2p QUIC before enabling create/invite/join across peers. The final path
   adds Identify, Kademlia provider/bundle/endpoint records, peer exchange,
   relay v2, AutoNAT/DCUtR, and bounded path management, while genesis persists
   peer identity, roster, failure domains, and coordinator policy. Remove
   `serve-directory`, global trusted-coordinator flags, and five-peer CLI
   arguments. Extend the real-process smoke after each replacement, then delete
   the obsolete runtime path rather than maintaining two stacks. No new remote
   behavior is built on TCP.
3. **Persistent usable backup lifecycle on that network:** add one persistent
   root per member, atomic parity budget admission and acknowledgement,
   revisions/checkpoints `N+1`, manual backup, opt-in bounded inotify scheduling
   and startup reconciliation, durable DHT publication/readiness, snapshot
   listing, restore, and visible status/jobs. Test two revisions from at least
   two different members. All five signatures and all five online members are
   required to commit.
4. **First usable prototype acceptance:** install five isolated daemons with
   separate seeds and databases; form the guild through CLI invites; enroll
   reflink roots; make and list repeated backups; restart daemons and interrupt a
   job by killing its daemon mid-backup, then restart and idempotently finish
   without activating partial state. Restore normally. Force three network
   topologies and assert daemon-reported path plus transferred bytes: direct
   QUIC, successful DCUtR, and failed-punch relay fallback. Wait until status is
   `seed-recovery-ready`; then delete one owner's state/source/anchors and one
   additional holder, start a blank daemon with only that owner's seed and
   generic Kademlia bootstrap configuration, discover and rejoin without an
   injected guild ID or peer list, and restore the latest revision byte-for-byte
   from any three valid shards. Keep this gate passing thereafter.

After that milestone:

5. **Tor/onion connectivity:** adapt the narrow BarterBackup `nettor` ideas to a
   maintained Arti release; add the deterministic onion service and dialer,
   onion endpoint publication, Tor routing policy, onion-reachable discovery,
   and a real private-Tor seed-recovery acceptance lane. This is explicitly not
   part of the first usable prototype.
6. **Operational lifecycle and storage:** add writer fencing, dynamic membership,
   cross-user sector packing, retention/GC, audits and repair, outage layouts,
   richer quota/receipt/outbox handling, multiple parity volumes and migration,
   incremental updates/range proofs, virtual zeros, and deeper crash/failure
   coverage.
7. **Additional source backends and platforms:** implement and validate guarded
   link-freeze, then evaluate NTFS/VSS, macOS cloning, non-Linux native watchers,
   portable metadata, ACLs, and application-consistent capture hooks.
8. **Production hardening and compatibility freeze:** fuzz parsers and state
   machines; property-test any-`k` and seed-only recovery; bound queue, task,
   memory, WAL, disk, relay, and DHT resource growth; test corruption, partitions,
   remounts, large trees, key rotation/revocation, and all incomplete lifecycle
   transitions before promising stable wire/storage compatibility.

The prototype freezes only the choices needed for its fixed profile: Node ID ↔
libp2p Peer ID mapping, canonical sector/encryption/root representation, the
`3+2` matrix, static-guild revision/checkpoint format, peer protocol IDs,
Kademlia mailbox/provider/bundle keys and TTL/sequence behavior, relay admission,
and DCUtR path semantics. Before a production v1 freeze, separately decide
variable `k/m`, dynamic membership/quorum and multi-device forks, key epochs, retention
and deletion, audit/repair policy, Tor configuration, endpoint privacy, relay
abuse controls, portable restore metadata, virtual zeros, multiple-volume
manifests, source-backend support, application-consistent capture, and final
resource/headroom limits.
