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

### Implemented baseline — durable operations beta passed

The first usable architectural prototype and the Milestone 2
operator-configuration and identity-state slice have passed their review gates.
The Milestone 3 robust-connectivity beta and Milestone 4 durable-operations beta
have passed their closure gates. Milestone 4 implements automatic backup,
writer fencing, retention/GC, independently encrypted volume databases, audits,
repair, emergency copies, and protection status. Corrections `27cb1b2`,
`a265cc1`, and `04875a9` passed the recorded local gate on 2026-09-15. Follow-up
corrections `9081266`, `7c58281`, and `89c6569` addressed M4-34 through M4-36 from
the source review of `668324f..d12f5fb`; the locked workspace and complete
local disposable-Btrfs/reflink/network gate passed on 2026-09-15. Source review
of `fb73787..546a1b9` then found M4-37 and M4-38: concurrent audit probes can
overload reachable holders and persist incorrect protection status, and
physical admission can reject matching READY publication retries. Commits
`736bf20` and `fea97b1` were recorded as resolving those findings, and the
complete local correction gate passed on 2026-09-15. Source review of
`197c6b0..1b9f99e` found M4-39: a completed response can reach the audit before
its holder releases the request worker, so even sequential probes can receive
Busy and persist incorrect protection status. No remaining blocker was found
in the matching READY retry correction. Commit `193f67e` transfers worker
capacity with the queued result and releases it before the response becomes
observable. Its deterministic handoff regression and the complete local
correction gate passed on 2026-09-15. Milestone 5's first closure record was
reopened by follow-up source review. Root-scoped signed revision chains,
checkpoint-authenticated production stable-slot packing, and authenticated
candidate-to-lane path ranking are now implemented. The corrected source and
complete local provisioned gate passed on 2026-09-18. Follow-up source review
of `8135e0b..da8974a` found the M5-36 through M5-44 blockers in `TODO.md`.
Milestones 0 through 4 remain closed; Milestone 5 is reopened and must pass its
correction gate before Milestone 6 starts.

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
An earlier Milestone 3 corrective pass revives usable retiring duplicates before
request fallback selection, coalesces all configured addresses for one relay
peer into one reservation lifecycle while retaining each address for dialing
and publication, and releases an active gateway lease before bounded settlement
of a stalled renewal. The final pass makes fallback advancement conditional on
the failed tier still being selected, so an already recovered preferred
connection carries the same logical request. It also removes detached mapping
cleanup: successful deactivation now waits for every in-flight acquisition and
releases its result, while the daemon's outer deadline reports incomplete
cleanup instead of acknowledging work that runtime teardown would cancel.
The closing corrective pass also recovers queued logical requests through an
already established preferred connection when their final fallback dial fails,
and retains cleanup responsibility for every distinct lease replaced during
gateway renewal. The final follow-up supervises that cleanup alongside lease
timers and commands, bounds each attempt, and carries failure into acknowledged
deactivation.

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
- **UserRevision:** guild, owner, protected-root ID, root-scoped monotonic
  revision, optional parent in that root's chain, explicit metadata/data
  `SectorRef` lists, suite versions, and owner signature. Milestone 5 keeps
  independent heads, retention tombstones, dirty state, and restore selection
  for each named root.
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
than a daemon prerequisite. Milestones 0 through 4 have passed; Milestone 5 is
reopened for the open items in M5-36 through M5-44 and the M5-45 correction gate. Later wire or
durable-state changes require the review and gate of the milestone that owns
them. Build and run all subsequent validation locally; do not use a remote
compilation server.

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

**Current position:** Milestones 0 through 4 are passed. Milestone 5 is reopened
after source review of `8135e0b..da8974a`; the open items in M5-36 through
M5-44 and the M5-45 correction gate block completion. Milestone 6 remains
subsequent work.
Milestone 5 replaces filler-based protection with fair incremental cross-user
variable-profile coding. It adds authenticated resumable Merkle ranges and
virtual zero extents, delegated coding with separate sampled verification and
two-phase activation, live capacity-aware bounded placement, dynamic guild
membership/quorum and writer/recovery key epochs, retained historical layouts,
variable recovery/audit/repair, and event-driven group retention. Coding work
is fenced across authority changes; stale attempts clean both staged and
uncommitted ready data without deleting committed protection.

The Milestone 5 source gate covers every-`k` variable-profile reconstruction,
packing/layout stability and multiple roots, the exact `1/4096` sparse-error
detection limit of one 16-byte sample in a 64 KiB shard, `k+m`/`k+m-1` transfer
bounds, member changes during durable attempts, key rotation with retained
history, production cross-user placement, live storage capacity including
shared filesystems, retry/cleanup, activation replay, variable recovery, and
group retention. On 2026-09-16 the exact tree passed locked all-target workspace
tests and warning-free locked all-target workspace Clippy locally. Tests that
explicitly require a provisioned Btrfs filesystem or private Chutney network
remained ignored; no remote compilation server was used. Follow-up review found
that this evidence did not exercise a production caller for the stable-slot
packer, distinct protected-root revision chains, or candidate-to-lane path
selection. Root-scoped signed chains, scheduling, retention, restore selection,
and recovered-chain continuation now close the protected-root gap. Checkpoint
format 7 now binds the production packed catalog to variable coding, lifecycle,
recovery, restore, and delayed collection, while preserving stable source slots
across owner/root updates. Peer protocol 2 obtains fresh signed observations
from each candidate for every real information and parity participant; coding
selection minimizes the complete bulk-lane path cost, saves a transfer for a
participating candidate, and keeps relay and Tor fallbacks eligible. The full
node suite and warning-free all-target node Clippy pass for this change. The
first fresh production-gate run then found that the plan-selected coder was
still denied its plan-scoped information-range reads by the static coordinator
authorization fallback, causing an unbounded sequence of otherwise durable
retries. Those reads now admit only the active guild member named as coding
coordinator by the signed attempt plan, matching its parity-write authority.
The next gate completed all four checkpoints and then showed that stable slots
alone did not ensure incremental cross-user sectors: an initial owner could
consume every slot before another owner arrived. Single-owner sectors now keep
one deterministic vacancy, later owners fill those vacancies first, and mixed
sectors remain densely packed. This preserves old source positions while making
incremental cross-user packing attainable. That corrected catalog and both
local restores passed on the next gate, which then showed that the test runtime
had omitted the daemon's peer-exchange worker. Format-7 recovery publication
requires every active subject's certified recovery-key epoch, so the production
test now runs peer exchange on all five nodes and waits for those epochs before
backing up. Running that real task set then exposed a lifecycle race: the
coordinator retired groups for a running checkpoint draft because they were not
yet referenced by the prior current checkpoint. A durable `Running` backup job
now fences group retirement until checkpoint construction commits or defers,
while recovery-key and endpoint exchange continue. A fresh provisioned
production run then completed all four checkpoints, the packed-catalog checks,
and both local restores, but its DHT readiness probe found no publishers. The
test had cold-started provider announcements only after the long workload and
allowed about three seconds for convergence. It now runs the daemon's real DHT
publication/readiness worker on every node throughout the workload and waits
under a bounded deadline for final-checkpoint readiness. That worker completed
repeated passes across checkpoints 1 and 2 but still retained zero publishers.
Replaying each exact stored bundle through the production validator found that
publication correctly emitted format-2 current-epoch bundles for checkpoint 7,
while validation admitted that format only for checkpoint 4. Dynamic recovery
key validation now covers every supported dynamic checkpoint format, 4 through
7, with a focused range regression. The next production run completed all four
checkpoints, final DHT readiness, packed-catalog checks, and local restores, but
large recovery with three live holders timed out. Cold-recovery head
certification had a separate copy of the recovery-key rule that still admitted
format-2 current-epoch bundles only for checkpoint format 4. Certification now
uses the same supported dynamic range, 4 through 7, with a focused regression.
The following production run completed all coding transcripts, then found the
watched node dirty before the deliberate post-restore edit. Its durable record
showed capture had saved dirty generation 1 before the asynchronously started
watcher wrote generation 2 for startup reconciliation. The watcher now installs
all filesystem watches before advancing the reconciliation generation and
offers an explicit readiness signal; the production path waits for that signal
instead of a fixed delay. The next production run completed all 51 coding
transcripts and reached cold recovery, then failed while pinning the recovery
attempt because that pre-adoption step tried to load dynamic guild state from
the fresh node. Recovery pinning now validates observed bundles against the
already certified downloaded state, while ordinary readiness continues to use
installed local state; a focused regression covers a fresh node with no dynamic
state. The next production run passed that transition, installed the recovered
dynamic guild and all 51 coding transcripts, then exhausted its recovery bound
before staging the first assigned shard. Recovery-head validation had fetched
all transcript evidence serially from every candidate. Those requests now run
with bounded concurrency under the existing global outbound semaphore, and a
focused regression proves both concurrency and its cap. The following run
completed all four checkpoints and 51 transcripts but timed out before the
fresh node adopted guild state: every candidate had started its own eight-way
transcript fetch, so redundant work and stopped publishers could consume the
complete global eight-request budget. Candidate genesis, checkpoint, and event
history are now certified before transcript retrieval; only a publisher whose
state has enough independent current locators fetches the evidence, with a
later certified publisher used if that fetch fails. The next run passed that
phase, installed the complete recovered state and began rebuilding 21 local
variable shards, but timed out after activating two. Variable recovery always
issued `needed + 1` requests, allowing the absent local assignment to displace
the useful initial spare and continuing to retry a known-offline holder after
exactly `k` healthy holders were known. The fresh local assignment is now
deferred before the first fetch; the first probe uses every remote candidate,
and later groups use only the `k` preferred holders once enough are known. This
matches the existing legacy recovery rule and prevents abandoned calls from
consuming the global request budget. The following run installed all 51
recovered transcripts but again activated only two of 21 local variable shards
before the integration deadline. Those independent group reconstructions were
still serialized. Recovery now probes one group to seed shared holder health,
then reconstructs and activates the remaining groups with bounded two-group
concurrency under the unchanged global outbound semaphore. The next production
run completed all four checkpoints, installed all 59 guild events and all 51
transcripts on the fresh node, and no longer retried dead holders, but two-group
concurrency activated only five of 21 local shards before the same recovery
deadline. Recovery now keeps up to eight independent group workflows in flight
so shard transfer, Reed-Solomon reconstruction, commitment checks, and durable
activation overlap; the P2P client's global outbound semaphore continues to
enforce the configured network-request bound. A durable-state resume probe then
showed that the remaining dominant cost was redundant trust work: even with all
assigned shards present, planning and activation spent about 50 seconds
replaying 21 coding transcripts and the 59-event authority history. Remote
transcripts are now fully replayed once on bounded blocking workers and carried
through adoption as typed verified values. Atomic adoption stores the evidence
in both transcript indexes with certified guild state; recovery staging and
activation subsequently require the active checkpoint pin, the exact retained
group, and byte-identical durable evidence instead of replaying the same proofs
and authority history. Reed-Solomon reconstruction runs on blocking workers,
and recovery fetches a live assigned target directly before using any-`k`
fallback reconstruction. The already staged durable resume path fell from
53.27 seconds to 11.91 seconds. The next production run completed cold recovery
within 60 seconds, installed all 59 events and 51 transcripts, and restored the
selected root, but its required one-second offline local resume timed out after
the original peers stopped. That resume had replayed the complete certified
event history through ordinary membership validation. Installed recovery now
uses its already verified, atomically committed durable state as the trust
boundary while still validating checkpoint structure and binding the installed
guild/genesis, local identity and recovery key, legacy local signature, current
active member, and completed recovery target. The preserved production state
resumed in 325 ms without a live peer or DHT path. A fresh provisioned
production run then verified its recovery head and pinned all four observations
but exceeded 60 seconds before adopting guild state. The durable boundary and
source path identified four optional DHT endpoint-record lookups between those
transitions. Accepted recovery locators already carry signed, unexpired
endpoints, and head validation already requires enough independent current
locators. Recovery now installs those endpoints directly and adopts the
certified state without a redundant DHT round; ordinary peer exchange refreshes
them afterward. The next clean run passed bounded cold recovery,
post-recovery publication, and the one-second offline local resume, then could
not reopen the recovered data directory after P2P shutdown. Inbound request
handlers were detached blocking tasks, allowing the event loop to return while
a handler retained `Arc<Node>` and its directory lock. The event loop now
tracks and reaps those workers during service and joins every remaining worker
after closing its result receiver during shutdown. A focused paused-worker
regression proves that shutdown does not return until the node can be reopened.
The next clean run stopped at initial recovery-key readiness with all five
nodes at exactly event sequence 2 and two current recovery keys. Event-tail
synchronization had waited for every peer request before accepting any result,
so one delayed request with a 90-second logical deadline blocked the following
recovery-key reconciliation beyond the test's 60-second bound. Each accepted
tail is independently quorum-certified and replay-validated; synchronization
now advances on the first valid tail and retries other peers on its next
periodic pass. Coding-group evidence is obtained from that selected event
source before its event is installed.
The corrected multi-owner QUIC scenario then passed from a fresh Btrfs image in
2,521 seconds, including cold recovery, offline resume, publication, shutdown,
and recovered-directory reopen. The following five-daemon CLI test stopped
after a successful finalize because it still expected the pre-Milestone-5
fixed-size `members: 5 of 5` display. Dynamic membership intentionally removed
that hard-coded denominator; the preserved coordinator reopened as an active
epoch-1 guild with all five authenticated members. Both direct and onion
process tests now assert the current exact `members: 5` status line.
Continuing the direct process test then timed out on its first backup. Recovery
registration and coding activation had concurrently proposed different events
at sequence 2, dividing the unanimous signatures two-to-three and leaving both
below quorum. A retry also regenerated randomized recovery-envelope bytes and
therefore could not reuse its durable anti-equivocation locks. Coordinator
backup claims now remain pending until every active member has a current
recovery-key epoch, preserving the registration sequence before coding starts.
A subject whose registration attempt lacks quorum reloads and resubmits the
exact event already held by its durable signature lock.
The next direct process run committed its first backup and timed out while the
second job remained healthy and continued producing verified coding groups.
That preserved 190 KiB job resumed immediately and committed after another 212
seconds, exceeding 332 seconds of useful work across the interruption. The old
120-second process bound predated sampled delegated coding. The gate now allows
ten minutes for its small backups and thirty minutes for its interrupted 1 MiB
backup, with durable failure states still rejected immediately.
The large interrupted job then remained `Running` through that bound, but
durable inspection found it fixed at event sequence 22. A retirement proposal
signed between backups held the next sequence while the running-job fence
prevented lifecycle replay; activation chose other groups ahead of the locked
event; and restart planning resurrected an initial deterministic launch whose
completed fresh retry was already durable. Backup claims now wait behind an
unrelated locally signed next event. Lifecycle replay may finish an exact locked
retire/forget event across a running job, activation selects the transcript
named by a locked group event, and durable retry or verifier evidence prevents
the original launch from being reissued. The preserved run advanced through
sequence 42 and committed in 1,138 seconds without another conflict. The large
process allowance is sixty minutes for its measured coding and event-activation
workload.
The next fresh process run revealed one necessary exception to that claim
fence. Its first backup signed a writer-key rotation, collected four of five
signatures, and deferred; the blanket fence then prevented the same pending job
from resuming the exact event it owned. Backup claiming now admits a locked
`RotateWriterKey` only when its owner matches the job, while every unrelated
event still blocks it. A regression pins both branches. The preserved run
resumed immediately with the corrected binary and committed checkpoint
`882eca8d785f5952bae322a50b16a331e4a278b51f87dc9445ee4f813c678ad1`
in about two minutes.
That fresh run then passed both small backups, the interrupted large-backup
restart, DHT renewal, and cold-recovery setup before its 512,031-byte topology
backup exceeded a legacy three-minute CLI bound. Durable inspection found 51
activation jobs, 41 completed transcripts, 27 launch jobs, and only that fourth
revision still running. Resuming the exact databases advanced the guild from
event sequence 52 through 80 and committed checkpoint
`3a1abf9e4163b2ca4a81f971f9737687a9c4a3fb0f9ddb9cbd340b7e15a35f24`
after about fifty additional minutes, for more than fifty-three minutes of
useful work across the interruption. The constrained-topology backup now has a
separate ninety-minute allowance, with durable failure states still rejected
immediately.
The next clean gate passed the repeated multi-owner production scenario in
2,699 seconds and reached the final isolated-topology backup. The coordinator
had durably accepted that fourth job, but the owner's `backup --wait` returned
when an acknowledgement or status request exhausted its transport tiers amid
the concurrent relay and coding load. P2P delivery deadlines, transport-attempt
exhaustion, terminal outbound failures, and explicitly retryable peer responses
now retain a retryable type through contextual errors. A waited backup retries
both idempotent descriptor submission and status polling across those failures;
non-waiting calls and permanent authorization, identity, and protocol errors
retain their immediate result.
The following fresh gate completed all four production backups and entered
three-holder cold recovery, but its 60-second integration allowance expired
after 3,068 seconds of total test work. Preserved-state inspection showed a
healthy, pinned generation-4 recovery: its dynamic state exactly matched the
live peers at event sequence 60 with 50 active groups, and all 50 required
transcripts were present in both durable indexes. It had not yet staged a shard
or committed the checkpoint. Replaying that exact variable-shard phase over
fresh local QUIC sessions took 12.75 seconds. Recovery-head validation already
fetches and replays the selected publisher's complete certified event history,
so the recovery path no longer blocks shard work on a redundant post-adoption
tail request. The integration allowance is two minutes to cover the measured
evidence and reconstruction work; focused tests continue to enforce request
and abandoned-request bounds.
A fresh gate then passed the complete repeated multi-owner production scenario,
including three-holder cold recovery, in 3,281.88 seconds. The direct process
test passed both small backups, interruption and restart of the large backup,
owner seed recovery, and storage-only seed recovery before reaching the
isolated topology backup. Relay load caused the connection-limits behaviour to
reject replacement connections after the earlier request-response behaviour
had preloaded them. When the Swarm later closed its last counted connection,
the vendored request-response behaviour still held an uncounted entry and its
debug assertion killed both the coordinator and hole-punched daemon. Connection
closure now treats the Swarm's zero remaining count as authoritative: it drains
all retained entries, emits `ConnectionClosed` failures for every pending
request using the owning connection ID, and safely ignores a later close for
already reconciled state. A focused vendor regression covers stale inbound and
outbound work plus the duplicate-close case.
A corrected gate passed the repeated multi-owner scenario in 3,244.68 seconds.
The fresh process test then passed onboarding, both small backups, interrupted
large-backup resume, both seed-recovery roles, and the connection-rejection
trigger with all five topology daemons still alive. Its 512,031-byte topology
backup committed after about 70 minutes. The following 512,047-byte
relay-fallback backup began healthy durable work but still inherited a legacy
180-second CLI allowance. Both isolated-topology backups now use the measured
ninety-minute bound; durable failure states continue to terminate immediately.
A fresh process run then passed the complete recovery path and committed its
first constrained-topology backup in about 76 minutes 50 seconds. The
relay-fallback backup consumed its full ninety-minute allowance while all five
daemons remained alive: its coordinator repeatedly received relay resource-limit
failures while activating the same group. Relay service still used the fixed
five-node beta limits of five reservations, eight total circuits, and two
circuits touching one peer. Reservation and circuit capacity now follows the
operator's `max_connections` resource budget, while membership admission and
per-circuit byte and duration bounds remain. The vendored relay enforces these
limits at equality rather than admitting one extra resource. Focused relay
regressions, the complete locked all-target workspace tests, and warning-free
locked all-target Clippy pass locally.
A subsequent fresh process run completed all earlier phases and its first
isolated-topology backup in about 44 minutes 45 seconds, then kept the
relay-fallback route active for its complete ninety-minute allowance without
committing. The relay configuration still inherited libp2p's public-service
time windows: one circuit per source peer every two minutes and one per source
IP every minute. Their generic `resource limit exceeded` denials throttled
authenticated guild coding and cleanup retries despite available configured
capacity. Guild membership is now the sole reservation and circuit-source
admission limiter. Total and per-peer capacity plus circuit byte and duration
bounds remain in force, while repeated requests from one admitted member are
not time-throttled. A focused regression exercises 64 immediate admitted
requests and verifies that a nonmember remains denied.

The corrected tree at `3d0bdbf` passed the complete local gate on 2026-09-18.
The fresh five-daemon process scenario passed in 9,288.94 seconds, including
both small backups, interrupted large-backup resume, both seed-recovery roles,
and both isolated topologies. The first 512,031-byte topology backup committed
in about 75 minutes 9 seconds. The decisive 512,047-byte relay-fallback backup
then committed in about 40 minutes with three simultaneous relayed peers and no
resource-limit denials. On a second fresh Btrfs image, all 19 provisioned
filesystem, metadata, headroom, and recovery tests passed; five-active-node
seed recovery passed in 51.95 seconds; signed network commit and recovery passed
in 94.76 seconds; and repeated multi-owner QUIC backup and recovery passed in
2,796.81 seconds. Formatting, the complete locked all-target workspace suite,
and warning-free locked all-target Clippy also pass. All compilation and
execution were local; no remote compilation server was used. These are
historical gate results; follow-up source review reopens Milestone 5.

The source-only review of `8135e0b..da8974a` on 2026-09-18 found nine remaining
blockers (details, source locations, and regression scenarios are in `TODO.md`):

- **M5-36:** Checkpoint approval does not authenticate packed contents against
  the source roots in owner-signed revisions. Correct RS over substituted
  ciphertext can pass signing and fail only at restore.
- **M5-37 (resolved):** Authority-bearing versions 5–7 now apply the configured
  checkpoint quorum consistently. Recovery locator validation, DHT publication,
  state adoption, installation, and resume share the rule that any certified
  member may recover without having personally signed the checkpoint; legacy
  formats remain unanimous.
- **M5-38 (resolved):** Explicit recovery-key rotation and periodic
  reconciliation now resume the exact signature-locked proposal. Focused
  coverage exercises CLI retry, automatic completion, and durable reuse after
  restart without weakening event anti-equivocation.
- **M5-39 (resolved):** Event synchronization gives empty tails a bounded grace
  for an advancing response, and coding-event evidence falls back concurrently
  across eligible peers until a valid transcript installs. Focused tests cover
  the former fast-empty race and both failed and invalid evidence sources.
- **M5-40 (resolved):** Automatic selection and retry state are root-scoped and
  submission carries the selected root UUID. Watch attachment, health checks,
  and exponential retry are isolated per root. Focused scheduling and live
  filesystem-event tests keep a healthy root active beside a missing sibling.
- **M5-41 (resolved):** Provisional relay reservations are rolled back when
  their acceptance response fails, while failed renewals preserve an existing
  reservation. Renewals bypass new-slot capacity checks. Focused relay tests
  cover per-peer cap 1 and full global capacity.
- **M5-42 (resolved):** Request-response reconciles the exact tentative
  connection on both outbound and inbound composite rejection, completes its
  preloaded work with terminal failures, and preserves accepted siblings.
  Focused tests cover repeated fresh-peer denials and sibling isolation.
- **M5-43:** Unchanged snapshot data gets new IDs/ciphertext, and packing
  refetches and materializes the retained corpus on every update.
- **M5-44:** All packed information stays at the checkpoint coordinator;
  production lanes use one real input plus zeros and lack the planned fair
  information placement and reusable geometry.

Fix the source-authentication and authority/retry/convergence defects first,
then complete root and transport failure isolation and incremental, bounded
information placement. M5-45 requires focused regressions for each finding
and the complete applicable local gate on the corrected tree. Preserve
anti-equivocation, seed-only recovery, retained-layout readability, failure-
domain separation, and storage/transfer bounds throughout the corrections.
This review ran no compilation, tests, daemons, or remote commands.

Milestone 4 implements quiet-period
automatic backup with durable limits and full reconciliation, recovered-writer
fencing, certified retention/tombstones
and delayed GC, independently keyed multi-volume parity storage, drain and
migration, scrubs, assigned repair, emergency shard copies, and durable
healthy/degraded/emergency/unrecoverable status. Milestone 3 put policy at the
composed transport boundary and provided Arti onion
service and dialing, DHT endpoint exchange, direct/relay/DCUtR/onion telemetry,
optional gateway mapping, and real acceptance environments. An earlier
corrective pass serializes request-scoped relay reservation lifecycles, binds
application requests to the selected connection while retaining reservation
fallbacks, reconciles every redundant session in the surviving duplicate set,
and acknowledges settlement and release of gateway leases granted during
acquisition. A later corrective pass revives retiring duplicates before
request fallback selection, gives multiple addresses for one relay a single
reservation lifecycle with complete dial and publication alternatives, and
withdraws an active gateway lease before a bounded wait on renewal. The
follow-up source review of `7d3946e..baee214` found two remaining blockers:
terminal request failure can reverse an already recovered preferred selection,
and detached gateway cleanup can be cancelled by daemon runtime shutdown.
The follow-up in `4fcdaa9` and `ae82816` closes both schedules with
deterministic regressions for both request-failure event orders and for a
granted lease retained across a bounded wait and runtime teardown.
The closing follow-up in `1b08b03` and `8fe9eb4` adopts a healthy established
preferred connection before final-tier dial exhaustion rejects queued callers,
and distinguishes same-lease renewal from replacement so every distinct
superseded gateway lease is released and cleanup errors reach deactivation.
Source review of `44287d8..0f36708` confirmed the dial-recovery correction and
found that `8fe9eb4` awaited superseded UPnP deletion inside the mapper event
loop. The follow-up in `8c835d2` and `cfcdb13` keeps each deletion as an owned,
bounded task polled alongside active-lease timers and commands. Deactivation
releases the active replacement first, settles superseded cleanup, and reports
its first failure. Running-service regressions hold the old deletion response
open and prove that replacement expiry/withdrawal and active cleanup continue.

The locked workspace, disposable-Btrfs/reflink and isolated IP/NAT gates, mixed
DHT policy and three-tier fallback regressions, custom Arti-state restart, real
NAT-PMP lifecycle, static Nix artifact, no-build Docker erase-and-seed recovery,
and five-daemon private-Tor seed-recovery gate form the Milestone 3 regression
contract. Focused regressions cover its reviewed event orders and failure
schedules. Guild geometry and coding-protocol changes remain Milestone 5.

Source review of `7b1114a..b8ffc90` on 2026-09-14 reopened Milestone 4 with the
M4-01 through M4-14 findings recorded in `TODO.md`. Commits `d1857b5` through
`83ebf83` addressed the reviewed paths across seed recovery and GC, writer
fencing, automatic-scan durability, capture generations, emergency-copy use and cleanup,
corruption isolation, live volume readers, established-database loss, repair
migration, exact-capacity resume, durable retirement, bounded metadata access,
physical headroom/reclaim, and verified SQLCipher rekey.

The corrected source tree passed locked workspace tests, warning-free
workspace Clippy, and the complete local disposable-Btrfs/reflink gate on
2026-09-14. That gate exercised capture interruptions, generation-2 seed
recovery over QUIC, close/reopen and GC, and real five-daemon seed-and-DHT
recovery after source loss. That pass included focused storage failure tests,
and the correction series also passed Docker-controller safety and real NAT-PMP
lifecycle gates. No remote compilation server was used.

The follow-up source review of `e663c49..8411f7d` on 2026-09-15 found remaining
completion blockers. Unrelated checkpoint progress permanently fences pending
writers, and version-1 capture intents cannot be reopened after the encoding
change. Corrupt pending writes and corrupt retired shards can prevent startup.
Discovering a known volume UUID at a new path bypasses established-database
loss detection and retirement. Long Unicode scan errors can panic the daemon.
Emergency classification can be lost between commits; GC forgets migration
duplicates; and a returned original volume cannot drain into its repaired copy
when acknowledgement forms differ. Failed-volume status still propagates
metadata errors. Physical admission undercounts database/WAL growth, incremental
vacuum is not stepped to completion, and fresh initialization cannot resume
after committing an empty database before its schema.

`TODO.md` records M4-15 through M4-27 with source locations, failure schedules,
and required regressions. The review itself performed no builds, tests, or
runtime probes. Commits `8162ffc`, `99d8ad5`, and `21486e4` addressed those
findings and were recorded as complete before the further review below.
On 2026-09-15 the corrected tree passed locked workspace tests, warning-free
workspace Clippy, and the complete disposable-Btrfs/reflink/network gate. The
gate covered the legacy capture upgrade, real shared-filesystem headroom,
generation-2 recovery, repeated multi-owner QUIC backup, and five-daemon
seed/DHT recovery after source and holder loss. Docker-controller safety and
the real NAT-PMP lifecycle gate also passed. All compilation and execution were
local; no remote compilation server was used.

Source review of `8411f7d..2da3e82` on 2026-09-15 reopened Milestone 4 with
M4-28 through M4-33 in `TODO.md`. Manifest-first legacy rekey can now prevent
startup after interruption. Cleanup ignores pending write destinations, retries
can discard their location evidence, and a drain interrupted after source
deletion can retire the disk with unresolved cleanup obligations. Physical
admission does not reserve the accumulated main-database growth of a WAL
checkpoint. The existing emergency placement also puts several missing shards
on the same surviving host, so the reported repair can fail to restore a safety
margin against another host loss. The latter is part of Milestone 4's fixed
profile outage requirement; it does not require Milestone 5's variable geometry.

The earlier gates remain historical evidence for the cases they exercised.
This review ran no builds, tests, or runtime probes. Commits `27cb1b2`,
`a265cc1`, and `04875a9` were subsequently recorded as closing the six findings.
On 2026-09-15, the corrected tree passed locked all-target workspace tests, warning-free
locked all-target workspace Clippy, Docker-controller safety, and the complete
local disposable-Btrfs/reflink/network gate. The gate covered the accumulated
WAL headroom boundary, two-holder emergency placement with reconstruction after
each remaining-host loss, generation-2 seed recovery, repeated QUIC backup,
and five-daemon seed/DHT recovery. No remote compilation server was used.

Source review of `668324f..d12f5fb` on 2026-09-15 reopened Milestone 4 with
M4-34 through M4-36 in `TODO.md`. Automatic PASSIVE checkpointing can still
accumulate unreserved main-file growth behind a reader or retain a WAL from
the previous version. Empty drain retirement clears copy-cleanup records but
can leave pending intents or stale receipts requiring a permanently closed
store. Repeated emergency repairs create valid copies that a later audit's
first-copy discovery misses, causing a safe layout to be reported as Emergency.
The earlier gate did not exercise these schedules. The review itself ran no
builds, tests, or runtime probes. Commits `9081266`, `7c58281`, and `89c6569`
were subsequently recorded as closing the three findings with focused
regressions. On 2026-09-15, the corrected tree passed formatting, locked
all-target workspace tests, warning-free locked all-target workspace Clippy,
Docker-controller safety, and the complete local disposable 2 GiB
Btrfs/reflink/network gate. The gate covered
held-reader parity/control WAL headroom, capture and recovery reconciliation,
repeated multi-owner QUIC backup, five-daemon seed/DHT recovery after source and
holder loss, and isolated direct/DCUtR/relay paths. No remote compilation server
was used.

Source review of `fb73787..546a1b9` on 2026-09-15 reopens Milestone 4 for
M4-37 and M4-38 in `TODO.md`. Parallel emergency-copy discovery can overload a
reachable holder's supported worker limit and silently omit copies when it
receives retryable Busy responses, persisting Emergency for a Degraded layout.
The receipt-backed publication path now reserves another sector before
recognizing a matching READY object, so interrupted publications can fail to
complete near capacity despite their payload already being durable. No
remaining blocker was identified in the retired-volume evidence correction.
Add focused regressions for low-capacity audit holders and interrupted
publication retries at the physical boundary, then rerun the local correction
gate before closing Milestone 4. Earlier gate results remain historical
evidence for their exercised cases; this review ran no builds, tests, or
runtime probes.

Commits `736bf20` and `fea97b1` were subsequently recorded as closing M4-37
and M4-38. Emergency inventory remains concurrent across holders but
serializes probes to each holder to remove the explicit request burst.
Receipt-backed publication validates an exact
READY row before physical admission, while conflicts and writes retain their
normal validation and capacity checks. The focused regressions exercise the
low-capacity audit schedule through durable status and reopen, and interrupted
peer publication through reopen and constrained-headroom replay without parity
growth. On 2026-09-15, the corrected tree passed formatting, locked all-target
workspace tests, warning-free locked all-target workspace Clippy, Docker
controller safety, and the complete local disposable 2 GiB
Btrfs/reflink/network gate. All compilation and execution were local; no remote
compilation server was used. These results preceded the source review below.

Source review of `197c6b0..1b9f99e` on 2026-09-15 reopens Milestone 4 for
M4-39 in `TODO.md`. The inbound worker enqueues its response while still
holding its capacity permit. The event loop can transmit that response before
the worker releases the permit, allowing the next sequential inventory probe
to receive Busy from a holder with one available worker. Inventory drops that
error without retry and can persist Emergency for a Degraded layout. The
constrained-permit regression does not force this handoff schedule. Order
capacity release before response visibility while retaining bounded handling,
or handle retryable capacity outcomes with a bounded policy. Cover the
handoff deterministically through complete discovery, durable status, and
reopen, then rerun the local correction gate before closing Milestone 4.
No remaining blocker was identified in the READY publication retry correction.
This review ran no builds, tests, or runtime probes; earlier gate results remain
historical evidence for their exercised cases.

Commit `193f67e` closes M4-39 by carrying the inbound permit with the bounded
result queue and dropping it in the event loop before response transmission.
The deterministic regression holds the completed workers after queueing their
results while leaving one permit available on each reachable remote holder;
the read-only audit still discovers the complete layout and persists Degraded
through reopen. On 2026-09-15, the corrected tree passed formatting, locked
all-target workspace tests, warning-free locked all-target workspace Clippy,
Docker controller safety, and the complete local disposable 2 GiB
Btrfs/reflink/network gate. All compilation and execution were local; no remote
compilation server was used. Milestone 4 is closed and Milestone 5 is next.

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

### Milestone 3 — Tor and robust connectivity beta (passed)

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

The implemented work covers behaviour-originated policy bypass, unhealthy and
duplicate established sessions, sequential fallback advancement,
request-to-transport binding, exact closed-path provenance, tentative preferred
promotion and rollback, custom Arti state paths, supervised
locked/startup/runtime process shutdown, initial endpoint canonicalization and
bounds, and a real gateway mapper that waits for its active lease and an
in-flight acquisition, releases distinct superseded leases without blocking
the active lease lifecycle, and reports cleanup errors on deactivation.
Corrective passes also closed the established-preferred/fallback-close and
equal-tier duplicate-retirement races, the saturated mapper-command-queue
cleanup race, stale transport-tier state after ephemeral endpoint expiry or
final disconnect, and incomplete validation of canonical signed local
endpoints. An earlier pass vendors pinned patches that serialize request-scoped
relay reservations, dispatch application requests on an exact selected
connection while preserving relay fallbacks, reconcile the whole surviving
duplicate-session set, and settle and release in-flight or completed gateway
mapping acquisitions before deactivation. Deterministic regressions cover the
previously reviewed event orders and failure schedules. A later pass also
revives a usable retiring duplicate before timeout fallback selection,
coalesces every configured endpoint for one relay peer under one reservation
while publishing all alternatives, and withdraws an active gateway lease before
waiting on renewal settlement. The final follow-up retains that renewal task
until it settles instead of transferring unresolved cleanup to a detached task.

The latest corrective follow-up preserves a healthier transport selected while
a fallback request is in flight; both close-before-failure and
timeout-before-close regressions prove that the original signed request is
retried on that connection. Gateway deactivation now retains the acquisition
task, releases any mapping it returns, and cannot report success while that
acquisition remains unresolved. Its regression models a granted mapping across
the daemon's bounded wait and actual Tokio runtime teardown.

The latest corrective follow-up handles the previously reported dial and renewal
schedules. A final-tier `OutgoingConnectionError` now adopts the best healthy
preferred connection before deciding that transports are exhausted; its
regression preserves the signed logical request, dispatches it on that exact
connection, and completes the caller. The mapper compares gateway lease
identity when renewal completes. It drops only a redundant handle for the same
lease, schedules owned cleanup for a distinct superseded lease, and carries a
release failure into acknowledged deactivation. Local UPnP regressions cover a
failed preferred-port renewal that replaces A with B, same-port renewal, and
cleanup-error propagation after the active replacement is released.

The final gateway lifecycle correction moves distinct superseded-lease cleanup
into owned tasks that the mapper polls alongside commands and the active lease.
Each task has a five-second deadline, preventing an unresponsive gateway from
growing cleanup state indefinitely. Active deactivation runs before settlement
of those tasks, and any timeout, protocol error, or task failure remains part of
the acknowledged result. Running-service UPnP regressions keep A's deletion
response open after replacement B is published: one proves B still reaches
expiry and withdrawal, and the other proves deactivation deletes B promptly
then reports A's timeout. Same-lease renewal and completed/acquiring mapping
cleanup retain their earlier coverage.

The locked workspace tests and clippy, forced-local static Nix build, Docker
controller safety suite, disposable-Btrfs and multi-process recovery suites,
isolated network and gateway-mapping tests, private-Tor onion-only five-daemon
recovery, and no-build Docker/Btrfs erase-and-seed recovery all passed locally
on 2026-09-14 after these corrections. The final stalled-response follow-up
then passed the locked workspace tests, warning-free workspace clippy, the real
NAT-PMP lifecycle gate, and a fresh forced-local Nix static build and lab
artifact check. The unchanged disposable-Btrfs, isolated-network, private-Tor,
and Docker gates had passed against its immediate precursor. No remote
compilation server was used.

### Milestone 4 — durable operations and multi-volume storage beta (passed)

Implemented after the Milestone 3 gate. Corrections `d1857b5` through `83ebf83`
addressed the initial review and passed the recorded local gate on 2026-09-14.
Source review of `e663c49..8411f7d` on 2026-09-15 reopened completion with
M4-15 through M4-27. Corrections `8162ffc`, `99d8ad5`, and `21486e4` addressed
those findings and passed the new local correction gate on 2026-09-15.
The further source review of `8411f7d..2da3e82` found M4-28 through M4-33.
Commits `27cb1b2`, `a265cc1`, and `04875a9` were recorded as resolving their
key-migration, emergency-placement, cleanup, and physical-reserve schedules. The
locked workspace and complete local disposable-Btrfs/reflink/network correction
gate passed on 2026-09-15. Source review of `668324f..d12f5fb` then found the
remaining WAL headroom, empty-drain cleanup, and protection-reporting schedules
recorded as M4-34 through M4-36. Commits `9081266`, `7c58281`, and `89c6569`
settle retired-volume location evidence, audit every valid emergency-copy
location, and reserve stalled or inherited WAL growth. Focused regressions and
the complete local correction gate passed on 2026-09-15.

The source review of `fb73787..546a1b9` reopened completion for M4-37 and M4-38:
respect holder capacity during emergency-copy inventory, and allow exact READY
publication retries without reserving a second payload. Commits `736bf20` and
`fea97b1` were recorded as correcting both schedules. Their focused regressions
and the complete local correction gate passed on 2026-09-15. Source review of
`197c6b0..1b9f99e` then reopened completion for M4-39: response delivery can
precede worker-permit release, causing sequential audit probes to miss valid
copies under the supported holder capacity limit. The READY publication retry
correction had no remaining blocker identified in this review. The correction
required a deterministic response/permit handoff regression and a new local
gate. Commit `193f67e` releases capacity before response visibility while
preserving the bounded result queue. Its regression and the complete local
correction gate passed on 2026-09-15, closing Milestone 4. See `TODO.md` for
source locations, failure cases, and recorded gate evidence.

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

### Milestone 5 — efficient and flexible data/guild protocol (reopened)

Completion is blocked by the open items in M5-36 through M5-44 in `TODO.md`,
followed by the M5-45 correction gate. The recorded 2026-09-18 production run
passed its scenarios but did not establish all requirements below.

- Replace deterministic fillers with cross-user sector packing and fair
  scheduling. Add incremental updates, hierarchical Merkle range proofs and
  range resume, authenticated virtual-zero extents, multiple protected roots,
  and measured sparse/large-tree efficiency.
- Delegate each deterministic geometry lane to a reachable coding coordinator
  selected from fresh signed observations of every source and destination path,
  preferring one of its participants when total path cost ties, so every
  information range is uploaded once and only parity rows travel onward: `k+m` bulk shard
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
