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
- The implemented first usable prototype baseline is Linux and
  **reflink-only**. Probe the complete COW lifecycle when a root is added and
  reject the root if reflinks are not safe there. Never silently fall back to
  an eager full copy. Guarded
  link-freeze, VSS, FUSE, and other source backends come after the prototype.
- Use a pinned SQLCipher/SQLite build as the common local storage engine, with
  per-page HMAC enabled. Keep control state separate from parity storage. The
  prototype instantiates one parity database; later, one database per configured
  filesystem lets volumes be added, drained, or lost independently.
- Use one stable seed-derived Ed25519 **peer identity** across direct QUIC,
  hole-punched, relayed, onion, and Kademlia sessions, with a deterministic
  verified mapping among the Node ID, libp2p Peer ID, and v3 onion identity.
  Keep revision, mailbox, metadata, and `(user, guild)` data keys
  domain-separated. The embedded Arti transport injects the seed-derived onion
  identity into an ephemeral keystore while retaining non-identity Tor state.
  Treat one live node as the writer for that identity until writer fencing is
  added later.
- Treat one normalized printable recovery string as the sole root secret. Generate
  the recommended form as 24 English words with the maintained Rust `bip39`
  crate and the OS CSPRNG, but use the words only as a high-entropy printable
  string: do not parse BIP-39 entropy, require its checksum, or apply BIP-39's
  wallet KDF. Accept a user-supplied string under the same validation policy.
  The seed string has no prefix, embedded version, checksum, or draft-compatibility
  parser.
- Make **seed-only recovery** a permanent invariant. Starting with the recovery
  string, an empty data directory, and only generic Kademlia bootstrap
  multiaddresses, a node must derive its identity, find its guild peers without
  a cached guild ID or peer list, rebuild its authenticated state and keys,
  retrieve any sufficient set of shards, and restore its data. No indispensable
  recovery material may live only in `control.db` or the source folder. The
  implemented IP alpha demonstrates this from the normalized recovery string,
  including a fresh data directory with no cached guild ID or peer list.
- Assume social trust but verify signatures, identities, roots, and state
  transitions. The fixed-profile product must reject corrupt/replayed/forked
  inputs and resume local jobs after crashes or ordinary connection loss;
  Byzantine availability and recovery takeover during a partition come later.
- Keep the implemented prototype profile fixed at five members, 64 KiB sectors,
  and RS `3+2`. Never place two shards of one group in the same physical failure
  domain. Variable membership, sector sizes, `k/m`, and extensible parity are
  later protocol work.
- Require unanimous five-of-five signatures for prototype genesis and
  checkpoints. Leave a compatible authorization interface for later quorum
  policies and FROST once membership and recovery policy are stable.

### Implemented baseline — first usable product and Tor connectivity beta

The first usable architectural prototype and the Milestone 2
operator-configuration and identity-state slice have passed their review gates.
The Milestone 3 robust-connectivity implementation and its acceptance machinery
previously passed their review and acceptance gates, but a repeat source-only
review at `77db5b1` reopened Milestone 3 for the focused corrective work
recorded in `TODO.md`. Milestone 4 remains blocked until that review gate closes
again.
The repository connects two real binaries and persistent local control to
static five-member guild onboarding,
reflink capture, owner encryption, actual `3+2` RS, remote SQLCipher
parity, unanimous revisions/checkpoints, QUIC, Kademlia discovery, relay/DCUtR
transport support, repeated backups, and DHT-assisted cold recovery. The
five-process acceptance path launches real daemons and CLIs, removes an owner's
state/source plus another holder, and restores bytes. It also exercises locked
startup, generated and supplied recovery strings, failed-start recovery,
endpoint changes, restart convergence, and relay authorization. Focused
real-libp2p topology tests exercise direct, relay/DCUtR, and retained-relay
application sessions without transport mocks.

Call this a runnable product slice, not a claim of production quality. Repeated
source-only reviews found initialization, startup rollback, recovery resumption,
address-lifetime, path-attribution, capture, quota, and Docker crash-safety
defects that the original suite did not expose. Repeated corrective reviews
closed the descriptor-traversal, crash-resumption, Docker-namespace,
build-source, and bounded-resource gaps then known in this draft. The closing
corrective pass also makes a legacy `Publishing` restore whose staging and
target were both lost safely rebuildable through both local and peer restore
paths; cancels abandoned shard-request state and permits while avoiding the
same unhealthy holder across later coding groups; rotates Docker recovery away
from a live but unusable bootstrap without erasing the recovered image; and
makes destructive restore-name validation ASCII and byte-exact. Focused
regressions and the locked workspace, Btrfs/reflink and real-network acceptance,
static Nix artifact, and real Docker/Btrfs erase-and-seed-recovery paths have
passed in earlier gates. The missing `btrfs` executable in the documented
default development shell is fixed and preflighted. The closing process gate
places the coordinator, punched peer, relay, and relay-only fallback in
distinct Linux network namespaces with real routing and port-preserving NAT
while retaining production Identify and endpoint exchange. It proves
application bytes over direct, successful-DCUtR, and failed-punch relay paths
and removes its privileged state on exit. The complete locked,
disposable-Btrfs, static-package, no-build Docker, and private-Tor gates passed
after that repair.
Application-transfer acceptance attributes post-baseline bulk bytes to the
exact direct, DCUtR, or relay-fallback connection used.

Milestone 3 adds an embedded, seed-bound Arti v3 onion transport to the same
libp2p swarm, signed onion discovery and peer exchange, explicit transport
policy, supervised Tor readiness, automatic request fallback across transport
tiers, and optional gateway port mapping. Its private-Tor gate performs a real
five-daemon, onion-only, seed-only recovery with no peer IP application path.

The baseline deliberately remains one guild and one reflink root per member,
one parity database, Linux only, fixed 64 KiB sectors and `3+2`, unanimous
five-of-five checkpoints, full rescans, and indefinite retention. Each owner
sector is grouped with two deterministic synthetic information fillers. This is
inefficient but is a real committed codeword, not a storage or transport mock.

### Milestone 1 stabilization work and regression contract

The implementation addresses the targets below. Every target remains part of
the regression contract.

1. **Restore the reproducible build gate.** Reconcile every workspace manifest
   with the committed `Cargo.lock`; the current CI unit job stops at
   `cargo clippy --locked` because `cmd/mutualbackup` gained its `libc`
   dependency without the corresponding lockfile update, and therefore never
   compiles or tests the product. Keep locked dependency resolution,
   formatting, warning-free clippy, unit tests, and the acceptance lanes green
   for every following change.
2. **Make DHT recovery authoritative only after validation.** Treat mailbox,
   bundle, endpoint, and claimed-head data solely as untrusted hints. Isolate bad
   or unreachable providers, validate guild membership and checkpoint
   certificates before ranking heads, and fall back to the highest *certified*
   recoverable checkpoint rather than letting three self-signed junk locators
   suppress it. Bound candidates and surface rejected/forked evidence.
3. **Make recovery readiness a renewable fact.** Replace the permanent
   `seed_recovery_ready` checkpoint latch with current, expiring confirmations
   from at least three independent valid publishers. Clear/degrade readiness
   when refresh or lookup quorum lapses; destructive lab workflows must never
   rely on stale DHT evidence.
4. **Unify normal restore, repair, and cold recovery.** A healthy daemon that
   loses a local anchor must fetch verified guild shards instead of failing
   locally. Retry/resume each 64 KiB sector across endpoints and holders, retain
   good shards across transient failures, and let a storage-only member recover
   authenticated node/guild state and rejoin without requiring an owner
   revision or plaintext restore.
5. **Converge live endpoints after address changes and recovery.** Continuously
   consume signed DHT/gossip endpoint records into a bounded disposable dial
   cache; do not use the genesis-time endpoint list as permanent routing state.
   Retry configured bootstrap peers with bounded backoff after startup failure
   or routing-table loss, without requiring a daemon restart.
   Prove that a recovered member at a new address remains usable after every
   daemon restarts and a later backup begins.
6. **Keep the peer service alive when source capture is degraded.** A missing,
   renamed, unmounted, or temporarily unwatchable protected root must mark that
   root unavailable/dirty and retry with backoff, not terminate the daemon and
   its parity, relay, and DHT duties. Coalesce watcher events and make overflow
   trigger bounded reconciliation.
7. **Bound and authorize network-facing work.** Put hard limits and backpressure
   ahead of peer requests, blocking CPU/SQL work, database connections, control
   clients, watcher queues, DHT candidates, and response sizes. Until relay
   reservations and circuits can be admitted only for certified guild peers
   under explicit time/byte/connection caps, do not enable a publicly reachable
   relay server by default. Every cap must be a named constant or configuration;
   tests set deliberately small limits and prove item `N+1` is rejected or
   backpressured without exceeding the bound or wedging later valid work.
8. **Make onboarding and the lab resumable.** A failed join must have a durable
   retry or cancel/restart transition instead of remaining wedged in `Joining`.
   Reinitializing any Docker-lab node must preserve the intended relay/bootstrap
   role. Acceptance must force and report real direct, successful-DCUtR, and
   failed-punch relay data paths rather than infer them from enabled behaviours.

## 2. State ownership

| Item | Who keeps it |
| --- | --- |
| Plaintext and recovery seed | Plaintext stays on the owner's selected filesystem, in the working folder or restricted source-anchor area. The printable recovery string is normally retained offline, entered through the CLI, never stored by the daemon, and never enters the DHT. An explicitly configured seed file is a convenience auto-unlock source. The string alone deterministically derives the stable identity and recovery-decryption roots |
| Active source anchor | The prototype owner retains a COW reflink until every referencing revision is retired. A write-protected hard link and its sparse private copy are later backends |
| Information sectors | Guild-specific encrypted form normally comes from its owner; after owner-disk loss it is reconstructed from the coding group |
| Private file metadata | Encrypted as user-owned information sectors and protected by the same coding machinery |
| Parity sectors | Assigned peer or storage-only node; that host stores the exact RS-level bytes as locally SQLCipher-encrypted chunks on a selected volume |
| Virtual zero extents | Post-prototype only: nobody stores payload or earns storage credit; peers synthesize them from the authenticated layout |
| User revisions | Signed by an identity-authorized revision key and replicated with recoverable guild state |
| Guild state | Prototype members retain the signed genesis, every authenticated checkpoint/revision, and enough explicit layout and recovery-locator metadata to rebuild a lost member. Later event tails and recovery-key envelopes support rotation, and old history may be safely compacted |
| Coordinator state | The genesis records which member serializes prototype proposals, but five signatures authorize a checkpoint. Its work inputs/staging are temporary and never authoritative |
| DHT, relay, and Tor | Kademlia stores independently published, short-lived provider advertisements, public signed direct/relay/onion endpoint records, and signed recovery bundles sealed to their subjects. The relay function retains no forwarded payload or authority, though the same daemon may separately hold assigned parity. Arti retains directory, guard, and cache state locally, while the seed-derived onion secret is injected only after unlock and is not persisted as a second identity |

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

Define recovery-string handling as one strict deterministic pipeline. Decode
valid UTF-8, remove every Unicode whitespace character (including spaces, tabs,
line endings, and non-breaking spaces), then require every remaining character
to be an ASCII graphic character in `!` through `~`. This objective allowlist
rejects controls, zero-width/bidirectional characters, combining marks, emoji,
homoglyph-heavy scripts, and normalization ambiguity. Require 8 to 1024
characters after stripping whitespace.

Use a pinned `zxcvbn` 3.1 release to reject any recovery string whose estimated
guessing work is below 64 bits. Compute the gate from its unsaturated estimate as
`guesses_log10 * log2(10) >= 64`, not from its saturating `u64` guess count.
Its source matches ranked dictionaries and user terms, reversed and l33t words,
keyboard walks, repetitions, sequences, regex/year/date patterns, then finds the
least-cost segmentation. It intentionally examines only the first 100
characters, so characters after that limit receive no entropy credit. Keep the
minimum-length check as an independent usability guard and describe this result
as an estimate, not measured entropy. Its manifest calls the project passively
maintained despite current 3.1.1/2026 maintenance, so pin its exact checksum,
hide it behind a small estimator interface, and keep a regression corpus that
makes replacement straightforward if maintenance or quality declines.

After validation, derive a deterministic 16-byte Argon2 salt/tweak with a
domain-separated BLAKE3 hash of the normalized UTF-8 bytes, then derive the
32-byte root with Argon2id v1.3 and fixed, benchmarked memory/time/parallelism
parameters. The RFC 9106 constrained profile (64 MiB, three passes, four lanes)
is the starting candidate. The deterministic tweak and fixed parameters ensure
that the printable string is sufficient for recovery; no salt or KDF metadata
may exist only on the lost machine. The string has no format marker or checksum,
but normalization, the hash domain, and Argon2 parameters are necessarily an
identity contract: changing them changes the node. Rotatable user/guild keys and
historical key envelopes are post-prototype protocol work.
Publish recovery-string/KDF vectors and boundary tests covering all whitespace
classes, invalid UTF-8, disallowed Unicode/control characters, the 8-character
minimum, the 64-bit estimate boundary, Argon parameter stability, generated
phrases, user input, wrong-seed identity rejection, and zeroization/redaction.

## 3. Formats and protocol objects

Keep canonical postcard encoding for hashed/signed peer and durable records;
transport and local-control framing is separate and is never itself signed.
Every durable record carries format and algorithm versions, scope, type, and
lengths. Publish golden vectors for hashes, signatures, encryption, sector
roots, RS, identity mapping, and DHT keys. The implemented baseline uses only its
fixed profile; the advanced objects identified below remain later work and none
of these draft encodings is a compatibility promise yet.

Do not add gRPC, HTTP/2, or Protobuf merely to obtain an interface definition.
Keep the libp2p request/response protocol encoded as CBOR and the local
length-framed Unix-socket API encoded as JSON. Move both APIs out of daemon
implementation modules into dedicated wire-only Rust types with explicit
operation tags, field meanings, bounds, error forms, and request/response
correlation. Commit normative CDDL schemas for the CBOR peer API and the JSON
control API; CDDL describes both data models. CI validates golden valid/invalid
messages against those schemas and checks that schema fixtures round-trip
through the Rust wire types. Keep domain conversions separate so changing an
internal `Node` type cannot silently change the wire. For signed Postcard
records, commit field tables plus byte-exact signing and decoding vectors because
CDDL describes their data model but not the Postcard binary representation.

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
- **Current storage acknowledgement:** operation ID, canonical complete
  `CodingGroup` ID/algorithm, assigned row and root, holder, and signature. The
  fixed prototype makes each parity holder recompute its row before atomically
  storing a READY object. Replace that traffic-heavy draft with the Milestone 5
  coding attempt below: parity holders persist only root-bound `STAGED` output,
  and a distinct verifier checks one hidden random 16-byte RS sample from every
  information and parity shard using canonical Merkle openings before activation.
- **Prototype Kademlia discovery:** every guild publisher announces itself as a
  provider of `mailbox(subject)`. Recovery obtains several provider Peer IDs;
  each publisher owns `recovery-bundle(subject,publisher)`, a bounded sealed set
  of locators for every guild the pair shares, and a public signed
  `endpoint(publisher)` record containing direct QUIC, relay circuit, and onion
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
  authority. A formal recovery capsule/event tail remains a later extension.

## 4. Local source snapshots, persistence, and storage volumes

### Prototype source capture

Each active owner-data information role needs a stable **regeneration anchor**
that reproduces its committed RS-level bytes using the recorded format and key
parameters; deterministic filler roles carry their own recipe. Only file content
and length need anchoring: directory structure, names, and desired properties
live in authenticated metadata. If an anchor is missing, changed, or corrupt,
refuse to serve/sign from it, mark it unavailable, and use verified guild shards
for restore or explicit repair; never encode new bytes under an old root.
Proactive background repair comes later.

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
- For the current fixed prototype request, verify the three information roots
  and assigned RS row as above, then use one parity-DB transaction to check the
  configured budget and atomically store the READY parity bytes plus signed
  acknowledgement before replying. Milestone 5 replaces this with `STAGED`
  writes plus the distinct sampled-verifier transcript before activation.
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

The asynchronous daemon/process split, locked startup, recovery-string input,
expected-identity check, bounded worker ownership, and formal wire-contract
machinery are implemented and synchronized. Human configuration and
application-owned identity state are also separate. A strictly checked
recovery-string file remains an explicit unattended auto-unlock option rather
than a daemon prerequisite. Milestone 2 has passed. Milestone 3 is reopened for
its narrow connectivity corrections, and Milestone 4 is blocked until those
corrections pass review. Later wire or durable-state changes require the review
and gate of the milestone that owns them.

- Use an **asynchronous shell around a synchronous deterministic core**, not
  `async` everywhere. Tokio owns daemon IPC, the libp2p swarm, Kademlia, timers,
  retries, cancellation, watchers, and orchestration. Canonical encoding,
  signature and root checks, RS, authorization, and guild-state transitions
  remain ordinary synchronous functions that are easy to test deterministically.
- Run one Tokio runtime in `mutualbackupd`. It first reads only nonsecret config,
  takes the data-directory lock, binds the mode-`0600` Unix control socket, and
  enters `Locked`. Only bounded status and unlock requests are accepted there.
  A successful unlock transitions through `Unlocking` while the daemon derives
  and verifies its public identity, opens SQLCipher stores, constructs `Node`,
  and starts the libp2p swarm and background jobs; failure returns cleanly to
  `Locked`. The normal way to clear secrets from memory is an orderly daemon
  shutdown rather than a partially torn-down live relock.
- `mutualbackup` uses the explicitly specified, length-framed local wire API with
  Unix peer-credential checks. It obtains recovery strings from a no-echo TTY
  prompt or `--seed-stdin`, never argv or an environment variable; generated
  strings are shown once and confirmed. It strips/validates/strength-checks the
  string, performs the BLAKE3/Argon2id derivation off the Tokio worker threads,
  sends only the 32-byte unlock value in a secret-specific type whose diagnostic
  formatting is redacted, and zeroizes text, KDF work buffers, and frames. Long
  operations return durable job IDs with status/follow/cancel; offline
  configuration, reflink probe, and later `db-shell` remain local.
- Keep one resolved daemon-options model for human TOML and command-line flags;
  the config file is optional, flags override it, and neither form contains
  generated identity state. Paths written in TOML are relative to that file;
  paths passed as flags are relative to the working directory. The sample
  configuration documents network policy, storage paths/budgets, and the
  operator's initial failure-domain claim. The CLI never edits either source.
- `mutualbackup init --data-dir DIR` and `recover-init` atomically create, without
  replacement, a versioned **nonsecret** application-owned identity manifest
  under `data_dir`. It records the expected Node ID and new-versus-recovery
  intent, but no deployment options or secret. `init` uses either a newly
  generated 24-word string or a securely prompted user string; interactive mode
  does not persist it. `recover-init` needs only that string, an empty data
  directory, and separately supplied generic bootstrap options; it imports no
  cached guild or peer state.
- Require the identity manifest before unlock and reject a wrong unlock value
  before opening existing databases. The CLI uses the default
  per-user socket or explicit `--socket` for tests and multiple local daemons.
  The unlock request gets a secret-specific wire wrapper with redacted `Debug`,
  bounded allocation, and zeroization rather than an ordinary logged JSON
  `String` field.
- Put blocking SQLCipher work behind one bounded worker/actor per database,
  filesystem calls such as sparse copy/reflink/fsync in a bounded blocking
  pool, and encryption, hashing, roots, and RS work in a bounded CPU pool.
  Bound queues and buffers to provide backpressure. Never block a Tokio worker
  or hold a database transaction, incremental-BLOB handle, mutex/state guard,
  or source transition guard across a network `.await`.
- Give background tasks explicit ownership, cancellation, and shutdown/join
  rules. Deterministic in-process nodes may replace transport, time, and failure
  sources for focused tests, but never replace real-process acceptance.
  Acceptance runs five real `mutualbackupd` processes, each with its own seed, databases,
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
   sealed recovery bundles → authenticated direct, DCUtR-punched, relay, or
   onion sessions → quorum-valid checkpoint and explicit layouts → any three
   valid shards → verify/reconstruct/decrypt → staged restore → rebuild `control.db`
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

### Implemented robust connectivity profile

- Use rust-libp2p rather than extending the temporary TCP stack: QUIC, Identify,
  Kademlia, request/response or stream protocols, circuit relay v2, AutoNAT, and
  DCUtR. Derive its peer identity from the stable Ed25519 key. QUIC authenticates
  and encrypts the live session; existing canonical application signatures stay
  authoritative for stored, relayed, or later replayed protocol records.
- Hide paths behind one authenticated session interface keyed by Node ID. Keep a
  bounded guild peer-exchange overlay and a signed, expiring endpoint set per
  peer. Reuse sessions, fetch independent shards in parallel, and retry the same
  signed idempotent request when transport policy advances to a fallback tier.
  Range resume and a second custom hole-punch protocol are not part of the
  prototype.
- Under the default `auto` policy, try paths with bounded budgets in this order:
  an existing or direct QUIC session over IPv6, LAN, or a known public address;
  a relay-v2 circuit followed by a DCUtR simultaneous QUIC punch; retain the
  authenticated relay circuit if the punch fails; then use onion connectivity.
  `prefer-tor` reverses the transport-tier preference, `require-tor` excludes IP
  paths, and `disable-tor` does not start Arti. Cache the working path,
  deterministically collapse duplicate simultaneous sessions, and optionally
  request PCP, NAT-PMP, or UPnP gateway mappings without making them a readiness
  prerequisite.
- Reachable guild daemons may opt into a bounded relay role and admit
  reservations/circuits for authenticated guild members. Configured community
  bootstrap relays may provide the initial circuit. The relay function forwards
  opaque bytes without retaining the payload or gaining storage authority, and
  enforces connection, time, and byte limits; the daemon may separately store
  its assigned parity.
- Keep and complete the Kademlia mailbox/provider/bundle/endpoint scheme from
  section 3. Daemons refresh records before their finite TTL and gossip fresher
  signed endpoints inside the guild. Configured replaceable bootstrap addresses
  may be IP or onion multiaddresses; DHT routing/cache state is disposable, and
  the DHT is discovery, never authority or bulk storage.
- Seed-only recovery still requires at least one working bootstrap/routing path
  and enough reachable shard holders. Test topology must make alternatives
  impossible and assert the daemon-reported selected path: direct QUIC; no
  initial direct route followed by successful DCUtR; and forced punch failure
  with the complete transfer carried over the relay circuit.
- Embed maintained Arti for outbound onion dials and an inbound Tor v3 onion
  service. Onion streams carry Noise, yamux, Kademlia, Identify, and the same
  bounded request/response protocol as IP sessions. Verify that the deterministic
  onion hostname maps to the Node ID, retain Arti directory/cache state, and
  inject the service identity through an ephemeral keystore after unlock.
- Advertise onion multiaddresses only while the service is reachable. Signed
  endpoint records, sealed recovery locators, and peer exchange carry onion
  paths under the same sequence, expiry, signature, and identity checks as IP
  paths. Tor bootstrap and service reachability are supervised independently;
  policy and degradation are visible through daemon status.
- The reproducible private-Tor gate pins Chutney, Tor, and Arti, removes every
  peer IP application path, restarts onion-serving peers, and recovers an erased
  node from its seed and one replaceable onion bootstrap address. It verifies
  the stable onion identity, Tor path attribution, RS recovery after another
  shard-holder loss, and byte-exact restore.

## 7. What to reuse from BarterBackup

| Treatment | Older Rust material |
| --- | --- |
| Reuse/extract | `crates/clock` and `ManualClock`; the small filesystem abstraction and temp-file + fsync + rename atomic-write pattern from `crates/storage`; data-dir locking/permissions; Nix, protobuf build, property/fuzz, and Docker harness patterns |
| Adapt for prototype | The `bbd`/`bbcli` process split and local-control shape; runtime supervision/readiness; transport boundaries, retry budgets, duplicate-session tie-breaking, bounded sessions, CAS read-refresh-retry, recovery-before-publication, durable storage acknowledgement, and failure injection; use `netmock` only for focused tests, never the acceptance path |
| Adapted for Milestone 3 | `crates/nettor`'s narrow principles for one shared Arti client, deterministic onion service, stream adaptation, persistent-cache/ephemeral-key split, runtime supervision, and a private-Tor test lane; the product uses a maintained exact Arti pin and its own libp2p transport boundary rather than copying the old fork |
| Replace | `crates/content`, most of `storage::Store`, old peer/stored schemas, monolithic `crates/node`, wall-clock lineage recovery, 4 MiB whole-blob RPC model, the Tor-only/onion-string connector, and peer scoring as the placement core |

Keep the domain-separated KDF and test-vector principles from `crates/keys`, but
redesign recovery-secret formats and non-identity keys where this protocol needs
different domains. Do not copy `crates/tlsutil`: its custom rustls callbacks
accept TLS handshake signatures without verifying them. Use libp2p's reviewed
authenticated transport and retain signed application records. BarterBackup has
no DHT, QUIC, DCUtR, or relay implementation to transplant. Copied code must
retain the older repository's MIT notice.

The Tor integration adapted only `nettor`'s conversion to `HsIdKeypair`, shared
inbound/outbound `TorClient`, persistent-cache/ephemeral-key split, and runtime
supervision. It uses a maintained exact Arti release and revalidated state
handling instead of copying the custom fork or hard-coded cleanup paths.

## 8. Delivery milestones and review gates

Each milestone extends the same runnable product. Preserve the two-binary
architecture and real data/network path; do not build a parallel replacement to
integrate later. Pause for a focused source, runtime, security, and usability
review at every gate before committing the next milestone's detailed scope.

**Current position:** Milestones 0 through 2 are passed. Milestone 3 is
implemented but its gate is reopened; the next implementation slice is its
corrective follow-up, not Milestone 4. Milestone 3 puts policy at the composed
transport boundary, provides Arti onion service and dialing, DHT endpoint
exchange, direct/relay/DCUtR/onion telemetry, optional gateway mapping, and
real acceptance environments. Its final corrective pass binds logical requests
to the selected transport attempts, preserves exact closed-path provenance,
makes preferred-path promotion tentative and recoverable, supervises complete
Arti/P2P construction and cleanup, gives gateway mappings one acknowledged
cleanup path, and adds local endpoint preflight and publication bounds. The
final source-only audit additionally closed a fallback-close race when a
preferred probe was already established and a mapper-cleanup race when its
command queue was full. The repeat audit at `77db5b1` found a distinct
equal-tier duplicate-retirement close race, stale transport-tier state after
ephemeral peer expiry, and incomplete validation of the final signed local endpoint.
Fix those three items with focused event-order, expiry, startup, and publication
regressions, then repeat the Milestone 3 source review and complete acceptance
contract before opening Milestone 4.

The locked workspace, disposable-Btrfs/reflink and isolated IP/NAT gates, mixed
DHT policy and three-tier fallback regressions, custom Arti-state restart, real
NAT-PMP lifecycle, static Nix artifact, no-build Docker erase-and-seed recovery,
and five-daemon private-Tor seed-recovery gate form the Milestone 3 regression
contract. Focused regressions cover its reviewed event orders and failure
schedules. Guild geometry and coding-protocol changes remain Milestone 5.

### Milestone 0 — first usable IP prototype architecture (passed)

Keep the baseline described in section 1: real reflink capture, owner
encryption, fixed `3+2`, remote SQLCipher parity, static guilds and unanimous
checkpoints, daemon/CLI control, QUIC/Kademlia/relay/DCUtR primitives, repeated
backup, and five-process DHT seed recovery. Milestone 1 replaced its legacy
seed-file format; there is no compatibility promise for that draft format.

### Milestone 1 — stabilized, unlockable IP product (implemented)

This was the implementation scope, in order:

1. Fix every item in **Milestone 1 stabilization work and regression contract**.
   Start by restoring the locked
   CI build, then address recovery authority/readiness and restore correctness
   before usability or feature work. Add regression tests with each fix.
2. Implement the recovery-string lifecycle exactly as specified above: 24-word
   `bip39` generation or a user string; Unicode-whitespace stripping plus the
   ASCII/length/`zxcvbn` gate; domain-separated BLAKE3 tweak and fixed Argon2id;
   stable vectors; redaction and zeroization. Deliberately provide no parser or
   migration promise for the legacy draft seed format.
3. Start the daemon locked from nonsecret configuration, and make no-echo prompt
   or `--seed-stdin` through the CLI the primary unlock path. Send only the
   derived root over the same-UID local socket, verify the expected Node ID, and
   retain a strictly checked, no-symlink, owner/mode-safe seed-file auto-unlock
   option for unattended nodes and the Docker lab.
4. Formalize rather than replace the existing interfaces: dedicated bounded
   wire types, correlation and structured errors for local JSON and peer CBOR;
   normative CDDL schemas; field tables and byte-exact vectors for signed
   Postcard records. Do not add gRPC.
5. Extend real-process acceptance to cover generated, user-supplied, stdin, and
   file auto-unlock; healthy restore after local-anchor loss; transient shard
   failure; storage-only seed recovery; malicious/stale DHT hints and expiring
   readiness; join resumption; endpoint change followed by full restart and
   backup; bootstrap absent at startup and later restored without a daemon
   restart; source-root loss without peer-service loss; enforced load bounds and
   nonmember relay rejection. Add the minimum status needed to name the selected
   path and transferred bytes, then force and assert end-to-end direct QUIC,
   successful DCUtR, and failed-punch relay transfer topologies.

The Milestone 2 gate included inherited stabilization regressions that the first
acceptance pass did not expose; they remain part of the mandatory regression
contract.

### Milestone 2 — operator configuration and identity-state separation (passed)

- Replace duplicated daemon parsing with one typed options model consumed by
  optional TOML and equivalent nonsecret command-line flags. Test flag-over-file
  precedence, unknown fields, repeatable multiaddresses, explicit booleans, and
  config-relative versus working-directory-relative paths.
- Remove generated `expected_node_id` and initialization intent from operator
  configuration. Have `init` and `recover-init` create the application-owned
  public identity manifest under `data_dir` without replacing an existing one;
  neither command edits a config file.
- Require and expose that manifest while locked, reject a mismatched recovery
  string before SQLCipher opens, and adapt unattended unlock, documentation,
  sample configuration, the Docker lab, and process acceptance.
- Gate with source-only review and the full locked remote suite, including new,
  recovery, missing-manifest, no-replace, wrong-seed, config-only, flag-only, and
  mixed-precedence process cases. Pause here before beginning Tor or changing
  guild geometry.

The implementation has one derived `DaemonOptions` model, a separate
no-replace public identity manifest, explicit command-line clear/unset behavior,
the documented symlink path policy, a bounded learned-endpoint cache, and
observable network startup. The previous corrective slice also made private
initialization durable and resumable without secret-derived temporary
filenames; distinguishes Docker new-node and recovery intent; rejects missing
seeds and foreign mounts; resumes partial guild finalization; bounds retained
telemetry on its intended paths; attributes operation bytes per connection
path; and defines the exact Nix artifact handoff used by the no-build lab. It
also:

1. Preflights the seed/identity pair without mutation and makes failed manual
   network startup return to the locked control loop.
2. Makes cold recovery reuse staged shards and resume its owned published target
   across command and daemon interruption.
3. Replaces permanent accumulation of discovered/recovery addresses with bounded
   attempt-scoped or expiring replacement state while retaining only genuine
   operator bootstrap/relay configuration as permanent.
4. Adds provenance checks to Docker image creation and start, then turns
   destructive `reinit` into a durable state machine that verifies same-guild
   survivors and resumes through restore completion.
5. Adds fault-injection and process regressions for the affected boundaries,
   including recovery progress across alternating shard availability and a
   daemon restart.

The implemented corrective work makes capture and retirement keep one validated
anchor-area descriptor through mutation and durability sync. Ordinary restore
and seed recovery journal exact staging/publication state, retain the first
native identity, construct trees without following symlinks or child mounts,
and distinguish both sides of rename and parent-sync failures. Restore
directory descriptors are bounded by traversal depth rather than entry count.
Docker-lab namespace enumeration fails closed and loop records accept exactly
one newline-terminated device token. Focused crash, replacement,
descriptor-limit, and malformed-state regressions cover these boundaries. The
follow-up source review at `d52b193` exposed five additional current-path
defects. Their direct cases were fixed with focused regressions, including
legacy restore-job migration, concurrent target ownership, query-only completed
recovery, and pre-erase Docker identity rejection. A further review exposed six
uncovered restore, recovery, and Docker schedules. Those are now fixed with
exclusive compare-and-transition restore state, atomic legacy reconciliation,
data-independent publication retry, non-mutating completed-recovery
verification, safe restoring-phase bootstrap replacement, and destructive-name
preflight. The complete locked, Btrfs, network, packaging, and real Docker lab
gates were rerun successfully. The last re-audit then found four more defects.
The final corrective pass makes missing legacy publication state rebuildable in
both local and peer restore entry points, releases abandoned P2P request state
and outbound permits while carrying unhealthy-holder knowledge across a large
repair, advances Docker recovery past a control-responsive but P2P-unusable
bootstrap without replacing its recovered Btrfs image, and validates destructive
restore names as ASCII bytes before mutation. Focused regressions and the prior
full gate passed. The missing `btrfs` acceptance dependency found by the next
review is fixed and preflighted. The invalid same-loopback DCUtR assertion is
replaced by isolated network namespaces and port-preserving NAT without
disabling production discovery. The final source-only review found no new
high-confidence Milestone 2 defect, and the full remote gate passed.

### Milestone 3 — Tor and robust connectivity beta (corrective follow-up required)

- ADR 0001 pins and source-reviews Arti 0.46.0 and defines the transport,
  identity-key, onion-service-key, discovery, policy, and cache lifecycle
  boundary. Closure requires outbound onion dialing, an inbound v3 onion
  service, persistent non-identity Tor state, ephemeral service-key injection,
  supervised readiness, and clean shutdown.
- Bind the onion service to the same seed-derived identity. Flow strictly
  validated signed onion endpoints through DHT recovery records and bounded
  peer exchange under `auto`, `prefer-tor`, `require-tor`, and `disable-tor`;
  bootstrap/discovery must remain onion-only when every peer IP path is
  unavailable or policy forbids it.
- Collapse redundant sessions, record consistent bounded path, byte, latency,
  and failure telemetry, retry an in-flight idempotent request when its actual
  transport attempt fails, and optionally request PCP, NAT-PMP, or UPnP gateway
  mappings with a verified listener and lifecycle.
- The gate starts a pinned private Tor network and five real daemons, excludes
  peer IP application paths, restarts onion services, erases the owner and a
  shard holder, and proves byte-exact seed-only recovery through one onion
  bootstrap address. The recovered node begins without its old guild, endpoint,
  source, database, or Tor cache state.

The implemented work covers behaviour-originated policy bypass,
unhealthy and duplicate established sessions, sequential fallback advancement,
request-to-transport binding, exact closed-path provenance, tentative preferred
promotion and rollback, custom Arti state paths, supervised
locked/startup/runtime process shutdown, initial endpoint canonicalization and
bounds, and a real gateway mapper with acknowledged cleanup on every exit.
The earlier source-only audit also closed the
established-preferred/fallback-close race and the saturated
mapper-command-queue cleanup race, and its focused regressions and remote
acceptance contract passed. A later source-only pass found the three current
defects recorded in `TODO.md`; Milestone 3 remains open until they are fixed and
the gate is repeated.

### Milestone 4 — durable operations and multi-volume storage beta

Blocked until Milestone 3 re-closes.

- Add writer-incarnation fencing before supporting concurrent loss/recovery;
  then add retention and tombstones, safe GC, audits/scrubs, repair and emergency
  parity, outage layouts, and explicit degraded/emergency states.
- Add quiet-period automatic backup with rate/budget limits, startup and
  periodic full reconciliation, durable scheduling, and clear dirty/blocked
  status; filesystem events remain hints rather than backup authority.
- Add one independently encrypted SQLCipher parity database per physical volume,
  DEK wrapping, volume identity/state, budgets and headroom, durable receipts and
  outboxes instead of cross-database transactions, drain/migrate/reconcile, and
  the restricted `mutualbackup db-shell`.
- Gate with crash injection at every durable transition, corruption and partial
  DHT/network failure, parity-volume loss and replacement, repair followed by a
  second loss, safe retention/GC, and recovery while a source volume is absent.

### Milestone 5 — efficient and flexible data/guild protocol

- Replace deterministic fillers with cross-user sector packing and fair
  scheduling. Add incremental updates, hierarchical Merkle range proofs and
  range resume, authenticated virtual-zero extents, multiple protected roots,
  and measured sparse/large-tree efficiency.
- Delegate each deterministic geometry lane to a directly reachable coding
  coordinator, preferably one of its participants, so every information range
  is uploaded once and only parity rows travel onward: `k+m` bulk shard
  transfers, or `k+m-1` for a participating coordinator, instead of `k*m`
  holder-side input transfers. Use a separate reachable verifier that is never
  that attempt's coding coordinator. It precommits a
  hidden random challenge, then after all parity is durably `STAGED` requests the
  same aligned 16-byte leaf and canonical Merkle proof from every information
  and parity holder. It checks only those RS symbols and publishes a signed,
  replayable transcript; it never recomputes a full parity sector. Any failure
  to confirm deletes all parity staged by that attempt and restarts the complete
  upload with fresh coordinators and challenge. Signed invalid openings and a
  valid-proof RS mismatch are attributable; timeouts prove only unavailability.
- Add versioned variable `k/m` and sector profiles, dynamic membership and event
  tails, quorum policy, writer/key epochs, recovery-key envelopes, rotation and
  revocation. Keep old committed layouts decodable until their retention ends.
- Gate with property tests for any-`k` recovery and packing/layout invariants,
  member add/remove/replacement during interrupted work, key rotation across
  retained revisions, and bounded storage/network amplification.

### Milestone 6 — additional source backends and platforms

- Implement the guarded link-freeze backend, including its atomic sparse private
  copy transition when the user needs to edit the original inode. Preserve file
  IDs, paths and metadata without freezing directory names or removal.
- Then validate native Windows NTFS capture, including VSS where appropriate,
  macOS cloning, platform watchers, portable metadata/ACL policy, and explicit
  application-consistent capture hooks. Each enrolled root must pass its complete
  capture/edit/restore probe; never fall back silently to an eager full copy.

### Milestone 7 — release candidate and compatibility freeze

- Fuzz every parser and state machine; property-test recovery and authorization;
  test partitions, malicious peers, corruption, remounts, clock changes, huge
  trees, disk/WAL exhaustion, interrupted upgrades, and every incomplete object
  transition. Measure and cap tasks, queues, memory, CPU, connections, relay/DHT
  work, bandwidth, and storage amplification.
- Finish migrations, observability and actionable status, install/service and
  upgrade/rollback paths, backup/restore operator documentation, and independent
  cryptographic/protocol/security review. Freeze wire and storage compatibility
  only after this gate passes.

Until the release-candidate gate, deterministic vectors protect the draft from
accidental drift but do not promise backward compatibility; an intentional
contract change may require recreating early nodes. Before the production v1
freeze, explicitly settle Node ID/transport bindings, recovery KDF parameters,
sector/encryption/root representation, variable coding profiles, membership and
fork policy, key epochs, retention/deletion, audit/repair, endpoint privacy and
Tor policy, relay abuse controls, portable metadata, volume manifests, source
backends, application consistency, and final resource/headroom limits.
